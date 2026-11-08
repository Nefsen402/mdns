//! A socket that speaks the line protocol of avahi-daemon's, so that what
//! asks Avahi for the address of a name (`nss-mdns`, which has no other way
//! to) can ask this daemon instead.
//!
//! One request per connection, a line, and one line back:
//!
//! ```text
//! RESOLVE-HOSTNAME-IPV4 router.local   ->  + 3 0 router.local 10.0.0.1
//! RESOLVE-HOSTNAME-IPV6 router.local   ->  + 3 1 router.local fd00::1
//! RESOLVE-ADDRESS fe80::1              ->  + 3 1 router.local
//! anything that is not found           ->  -15 Timeout reached
//! ```
//!
//! The first field after the `+` is the index of the interface it is at, the
//! second the protocol (0 for IPv4, 1 for IPv6). `RESOLVE-HOSTNAME`, with no
//! family, is answered with either. One address is told, not a list, as Avahi
//! does: a routable one before a link-local one.
//!
//! A name is looked up in what is known of every segment, and in the names
//! this host advertises, at its own addresses. One not known is asked for, on
//! every interface, and waited for a little: a device that is quiet says
//! nothing until it is asked. An address is only looked up in what is known,
//! as `nss-mdns` only asks for link-local ones, and nothing is asked for it.
//!
//! The socket is made for anyone to connect to, as Avahi's is: what is told
//! is only what any host on the links hears.

use core::net::IpAddr;
use core::time::Duration;

use rustix::fd::{AsRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::net::SocketFlags;

use crate::time::Instant;

use anyhow::Result;

use crate::config::AdvertiseConfig;
use crate::device::is_link_local;
use crate::ipc::links_of;
use crate::codec::{rtype, Question};
use crate::poll;
use crate::runtime::Why;
use crate::socket::{self, Family};
use crate::Group;

use crate::prelude::*;

/// The longest request line taken: Avahi's command is 63 characters and its
/// argument 1013.
const MAX_LINE: usize = 1100;

/// Connections that send nothing for this long are closed.
const IDLE: Duration = Duration::from_millis(if cfg!(test) { 300 } else { 5_000 });

/// How long a name that is not known is waited for, and when it is asked for
/// again within that.
const WAIT: Duration = Duration::from_millis(if cfg!(test) { 600 } else { 2_000 });
/// How long an address of a family is waited for of a name that is known, by
/// another: it is asked for, and a device that has one says so at once.
/// `getent` asks for IPv6 first, of what has only IPv4.
const KNOWN_WAIT: Duration = Duration::from_millis(if cfg!(test) { 100 } else { 300 });
const ASK_AGAIN: Duration = Duration::from_millis(if cfg!(test) { 200 } else { 700 });

/// How many connections at once: past it, one is let wait to be accepted.
const MAX_CLIENTS: usize = 64;

/// The socket and its clients, served from the event loop: nothing here
/// waits, and a client waiting for a name is answered when it is known.
pub struct Server {
    listener: OwnedFd,
    clients: Vec<Client>,
    /// The names this host advertises, which it answers for at its own
    /// addresses, and the families it listens over.
    own: Vec<AdvertiseConfig>,
    families: Vec<Family>,
    /// The addresses this host has on an interface, of the families: read from
    /// the system, or, in a test, made up.
    addresses: Addresses,
}

/// How the addresses of this host on an interface are had.
type Addresses = fn(&str, &[Family]) -> Vec<IpAddr>;

fn system_addresses(interface: &str, families: &[Family]) -> Vec<IpAddr> {
    socket::addresses(interface, families).unwrap_or_default()
}

struct Client {
    stream: OwnedFd,
    input: Vec<u8>,
    output: Vec<u8>,
    /// What it asked, once it has asked, and when it was asked and asked for.
    asked: Option<Asked>,
    since: Instant,
    /// It is closed once its output is written.
    closing: bool,
    gone: bool,
}

struct Asked {
    request: Request,
    at: Instant,
    /// When it is given up on: [`WAIT`] after it was asked, or [`KNOWN_WAIT`]
    /// once the name is known.
    deadline: Instant,
    /// When the name is to be asked for next, if at all.
    next_ask: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// The address of a name, of a family, or of either.
    Host { name: String, family: Option<Family> },
    /// The name of an address.
    Address(IpAddr),
}

/// An address of a host, and the interface it is on.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    interface: String,
    ip: IpAddr,
}

impl Server {
    /// Listen at `path`, for anyone, before anything else happens, so that a
    /// bad path, or an Avahi that has it, is reported at startup.
    pub fn bind(path: &str, own: &[AdvertiseConfig], families: &[Family]) -> Result<Server> {
        let listener = crate::ipc::bind(path, 0o666)?;
        eprintln!("avahi: listening on {path}");
        Ok(Server { listener, clients: Vec::new(), own: own.to_vec(), families: families.to_vec(), addresses: system_addresses })
    }

    /// The descriptors to wait on: the listener, and every client, readable
    /// when it sends or hangs up, and writable when it can take its answer.
    pub fn fds(&self) -> Vec<libc::pollfd> {
        let mut fds = vec![poll::readable(self.listener.as_raw_fd())];
        for c in &self.clients {
            let mut fd = poll::readable(c.stream.as_raw_fd());
            if !c.output.is_empty() {
                fd.events |= libc::POLLOUT;
            }
            fds.push(fd);
        }
        fds
    }

    /// Accept, read and write what `fds` (as [`Server::fds`] gave them, after
    /// waiting) say can be.
    pub fn ready(&mut self, fds: &[libc::pollfd]) {
        if fds.first().is_some_and(poll::ready) {
            self.accept();
        }
        for (c, fd) in self.clients.iter_mut().zip(&fds[1..]) {
            if poll::ready(fd) {
                c.read();
            }
            if fd.revents & libc::POLLOUT != 0 {
                c.flush();
            }
        }
    }

    fn accept(&mut self) {
        while self.clients.len() < MAX_CLIENTS {
            match rustix::net::accept_with(&self.listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                Ok(stream) => {
                    let client = Client { stream, input: Vec::new(), output: Vec::new(), asked: None, since: Instant::now(), closing: false, gone: false };
                    self.clients.push(client);
                }
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => {}
                Err(e) => {
                    eprintln!("avahi: accept failed: {}", Why(e));
                    return;
                }
            }
        }
    }

    /// Take what has been asked, answer what can be, ask for the names that
    /// are not known, give up on those that are not found in time, and let
    /// go of what is done.
    pub fn tick(&mut self, groups: &[Group], now: Instant) {
        let Server { clients, own, families, addresses, .. } = self;
        let host = Host { own, families, addresses: *addresses };
        for c in clients.iter_mut() {
            if c.asked.is_none() && !c.closing {
                c.take_request(now);
            }
            if let Some(asked) = &mut c.asked {
                let (known, host_known) = answer(groups, &host, &asked.request);
                if host_known {
                    asked.deadline = asked.deadline.min(asked.at + KNOWN_WAIT);
                }
                let late = now >= asked.deadline;
                if let Some(line) = known.or_else(|| late.then(|| "-15 Timeout reached".to_string())) {
                    push_line(&mut c.output, &line);
                    c.closing = true;
                    c.asked = None;
                } else if asked.next_ask.is_some_and(|at| now >= at) {
                    // Again, if there is time to hear of it.
                    asked.next_ask = Some(now + ASK_AGAIN).filter(|&at| at < asked.deadline);
                    if let Request::Host { name, family } = &asked.request {
                        ask_for(groups, name, *family);
                    }
                }
            }
            c.flush();
            if c.asked.is_none() && !c.closing && now >= c.since + IDLE {
                c.gone = true;
            }
        }
        clients.retain(|c| !c.gone && !(c.closing && c.output.is_empty()));
    }

    /// When [`Server::tick`] next has something to do of its own accord.
    pub fn next_due(&self) -> Option<Instant> {
        self.clients
            .iter()
            .filter_map(|c| match &c.asked {
                Some(asked) => [Some(asked.deadline), asked.next_ask].into_iter().flatten().min(),
                None => Some(c.since + IDLE),
            })
            .min()
    }
}

impl Client {
    /// Take what it has sent. One that hangs up is gone.
    fn read(&mut self) {
        let mut buf = [0u8; 512];
        loop {
            match rustix::io::read(&self.stream, &mut buf) {
                Ok(0) => return self.gone = true,
                Ok(n) => {
                    // What is sent after the request is not read.
                    if self.input.len() < MAX_LINE {
                        self.input.extend_from_slice(&buf[..n]);
                    }
                }
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => {}
                Err(_) => return self.gone = true,
            }
        }
    }

    /// Write what it can take of its output.
    fn flush(&mut self) {
        let mut wrote = 0;
        while wrote < self.output.len() {
            match rustix::io::write(&self.stream, &self.output[wrote..]) {
                Ok(0) => break,
                Ok(n) => wrote += n,
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => {}
                Err(_) => {
                    self.gone = true;
                    break;
                }
            }
        }
        self.output.drain(..wrote);
    }

    /// Parse the line it has sent, if it has sent one, and start on what it
    /// asks, asking for the name at once if it is not known.
    fn take_request(&mut self, now: Instant) {
        let Some(end) = self.input.iter().position(|&b| b == b'\n') else {
            if self.input.len() >= MAX_LINE {
                push_line(&mut self.output, "-21 Invalid operation: request too long");
                self.closing = true;
            }
            return;
        };
        let line: Vec<u8> = self.input.drain(..=end).collect();
        match parse(&String::from_utf8_lossy(&line)) {
            Ok(request) => self.asked = Some(Asked { request, at: now, deadline: now + WAIT, next_ask: Some(now) }),
            Err(reply) => {
                push_line(&mut self.output, &reply);
                self.closing = true;
            }
        }
    }
}

fn push_line(output: &mut Vec<u8>, line: &str) {
    output.extend_from_slice(line.as_bytes());
    output.push(b'\n');
}

/// What a line asks for, or the line to answer it with if it asks for what
/// is not served.
fn parse(line: &str) -> Result<Request, String> {
    let mut words = line.split_whitespace();
    let (Some(command), Some(arg), None) = (words.next(), words.next(), words.next()) else {
        return Err("-21 Invalid operation: failed to parse command".to_string());
    };
    let host = |family| {
        // As a name is written, with or without its last dot.
        let name = arg.strip_suffix('.').unwrap_or(arg).to_ascii_lowercase();
        if name.ends_with(".local") && name.len() > ".local".len() {
            Ok(Request::Host { name, family })
        } else {
            // Not under .local, the only domain multicast DNS answers for.
            Err(format!("-3 Invalid host name {arg:?}: not under .local"))
        }
    };
    match command {
        "RESOLVE-HOSTNAME" => host(None),
        "RESOLVE-HOSTNAME-IPV4" => host(Some(Family::V4)),
        "RESOLVE-HOSTNAME-IPV6" => host(Some(Family::V6)),
        "RESOLVE-ADDRESS" => arg.parse().map(Request::Address).map_err(|_| format!("-14 Failed to parse address {arg:?}.")),
        _ => Err(format!("-21 Invalid operation: invalid command {command:?}")),
    }
}

/// This host, as it answers for itself: the names it advertises, and the
/// addresses it has.
struct Host<'a> {
    own: &'a [AdvertiseConfig],
    families: &'a [Family],
    addresses: Addresses,
}

impl Host<'_> {
    /// Its addresses on `interface`, if it advertises a name there.
    fn on(&self, interface: &str) -> Vec<IpAddr> {
        (self.addresses)(interface, self.families)
    }
}

/// The line that answers `request`, if it is known now, and whether the name
/// is known at all: at some address, or as one this host advertises, which
/// is of nothing if it has no address of the family asked for.
fn answer(groups: &[Group], host: &Host, request: &Request) -> (Option<String>, bool) {
    match request {
        Request::Host { name, family } => {
            let (found, advertised) = hosts(groups, host, name);
            let line = choose(&found, *family).map(|f| format!("+ {} {} {name} {}", socket::ifindex(&f.interface).unwrap_or(0), protocol(f.ip), f.ip));
            (line, advertised || !found.is_empty())
        }
        // What is known is told, and nothing waits for the rest.
        Request::Address(addr) => {
            let line = match name_of(groups, host, *addr) {
                Some((interface, name)) => format!("+ {} {} {name}", socket::ifindex(&interface).unwrap_or(0), protocol(*addr)),
                None => "-30 Not found".to_string(),
            };
            (Some(line), true)
        }
    }
}

/// Avahi's number for the family of `ip`.
fn protocol(ip: IpAddr) -> u8 {
    u8::from(ip.is_ipv6())
}

/// Every address `name` (lowercase) is known at, and the interface of each:
/// those of this host, if it advertises it, and those of devices heard of;
/// and whether this host advertises it on any interface.
fn hosts(groups: &[Group], host: &Host, name: &str) -> (Vec<Found>, bool) {
    let mut found = Vec::new();
    let mut advertised = false;
    for seg in links_of(groups, "") {
        if host.own.iter().any(|b| b.name.eq_ignore_ascii_case(name) && advertised_on(b, seg.interface())) {
            advertised = true;
            for ip in host.on(seg.interface()) {
                found.push(Found { interface: seg.interface().to_string(), ip });
            }
        }
        for device in seg.devices().iter().filter(|d| d.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(name))) {
            found.extend(device.addrs().map(|ip| Found { interface: seg.interface().to_string(), ip }));
        }
    }
    (found, advertised)
}

/// Whether the advertised `block` is advertised on `interface`.
fn advertised_on(block: &AdvertiseConfig, interface: &str) -> bool {
    block.interfaces.is_empty() || block.interfaces.iter().any(|i| crate::config::glob(i, interface))
}

/// The name `addr` is of, and the interface it is on: of this host, or of a
/// device heard of.
fn name_of(groups: &[Group], host: &Host, addr: IpAddr) -> Option<(String, String)> {
    for seg in links_of(groups, "") {
        let ours = host.own.iter().find(|b| advertised_on(b, seg.interface()) && host.on(seg.interface()).contains(&addr));
        if let Some(block) = ours {
            return Some((seg.interface().to_string(), block.name.clone()));
        }
        for device in seg.devices() {
            if let (Some(host), true) = (&device.hostname, device.addrs().any(|a| a == addr)) {
                return Some((seg.interface().to_string(), host.clone()));
            }
        }
    }
    None
}

/// The address to tell of `found`, of `family` if one is wanted: a routable
/// one before a link-local one, and IPv4 before IPv6.
fn choose(found: &[Found], family: Option<Family>) -> Option<&Found> {
    found
        .iter()
        .filter(|f| match family {
            Some(Family::V4) => f.ip.is_ipv4(),
            Some(Family::V6) => f.ip.is_ipv6(),
            None => true,
        })
        .min_by_key(|f| (is_link_local(&f.ip), f.ip.is_ipv6()))
}

/// Ask for `name` on every interface, of `family` or of both.
fn ask_for(groups: &[Group], name: &str, family: Option<Family>) {
    let wanted = |f: Family| family.is_none_or(|w| w == f);
    let questions: Vec<Question> = [(Family::V4, rtype::A), (Family::V6, rtype::AAAA)]
        .into_iter()
        .filter(|&(f, _)| wanted(f))
        .map(|(_, qtype)| Question { name: name.to_string(), qtype, class: 1, unicast_response: false })
        .collect();
    for seg in links_of(groups, "") {
        // Failing to send is no matter: it is asked for again, or it is not found.
        let _ = seg.query_question(&questions);
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, UdpSocket};
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::codec::{Header, Message, RData, Record};
    use crate::reflector::Reflector;
    use crate::segment::Segment;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn found(interface: &str, addr: &str) -> Found {
        Found { interface: interface.into(), ip: ip(addr) }
    }

    #[test]
    fn what_is_asked_is_a_command_and_one_argument() {
        let host = |name: &str, family| Ok(Request::Host { name: name.into(), family });
        assert_eq!(parse("RESOLVE-HOSTNAME-IPV4 router.local\n"), host("router.local", Some(Family::V4)));
        assert_eq!(parse("RESOLVE-HOSTNAME-IPV6 Router.LOCAL.\r\n"), host("router.local", Some(Family::V6)), "case and the last dot do not matter");
        assert_eq!(parse("RESOLVE-HOSTNAME router.local"), host("router.local", None));
        assert_eq!(parse("RESOLVE-ADDRESS fe80::1\n"), Ok(Request::Address(ip("fe80::1"))));
        for bad in ["", "\n", "RESOLVE-HOSTNAME\n", "RESOLVE-HOSTNAME a.local b.local\n", "HELP x\n", "resolve-hostname a.local\n"] {
            assert!(parse(bad).unwrap_err().starts_with("-21"), "{bad:?}");
        }
        // Only .local is answered for.
        for bad in ["RESOLVE-HOSTNAME-IPV4 example.com", "RESOLVE-HOSTNAME-IPV4 local", "RESOLVE-HOSTNAME-IPV4 .local"] {
            assert!(parse(bad).unwrap_err().starts_with("-3"), "{bad:?}");
        }
        assert!(parse("RESOLVE-ADDRESS nonsense").unwrap_err().starts_with("-14"));
    }

    #[test]
    fn one_address_is_told_routable_before_link_local_and_v4_before_v6() {
        let all = [found("br0", "fe80::1"), found("br0", "fd00::2"), found("br0", "169.254.1.1"), found("br0", "10.0.0.9")];
        assert_eq!(choose(&all, None), Some(&all[3]));
        assert_eq!(choose(&all, Some(Family::V4)), Some(&all[3]));
        assert_eq!(choose(&all, Some(Family::V6)), Some(&all[1]));
        assert_eq!(choose(&all[..1], Some(Family::V6)), Some(&all[0]), "a link-local one if that is all");
        assert_eq!(choose(&all[..2], Some(Family::V4)), None);
        assert_eq!(choose(&[], None), None);
        // IPv4 link-local does not come before a routable IPv6 one.
        assert_eq!(choose(&all[1..3], None), Some(&all[1]));
    }

    /// `socket` as the daemon takes a socket.
    fn fd(socket: impl std::os::fd::IntoRawFd) -> OwnedFd {
        // SAFETY: a descriptor just given up by its owner.
        unsafe { rustix::fd::FromRawFd::from_raw_fd(socket.into_raw_fd()) }
    }

    /// A group of one segment on `lo`, which can send, and where its questions go.
    fn group_on_lo() -> (Vec<Group>, Segment, UdpSocket) {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let seg = Segment::new(socket::LOOPBACK, &[Family::V4, Family::V6]);
        seg.attach(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap());
        let reflector = Reflector::new(0, vec![seg.clone()]).unwrap();
        (vec![Group { name: "lan".into(), reflector }], seg, rx)
    }

    fn hear(seg: &Segment, from: &str, host: &str, addrs: &[&str]) {
        let answers = addrs
            .iter()
            .map(|a| {
                let data = match ip(a) {
                    IpAddr::V4(a) => RData::A(a),
                    IpAddr::V6(a) => RData::Aaaa(a),
                };
                Record { name: host.into(), class: 1, cache_flush: false, ttl: 120, data }
            })
            .collect();
        let header = Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 };
        let msg = Message { header, questions: vec![], answers, authorities: vec![], additionals: vec![] };
        seg.handle(SocketAddr::new(ip(from), 5353), &msg.encode().unwrap()).unwrap();
    }

    /// The server at a socket of its own, turned a step at a time, as the
    /// event loop turns it.
    struct Harness {
        server: Server,
        groups: Vec<Group>,
    }

    impl Harness {
        fn new(tag: &str, groups: Vec<Group>) -> (Harness, String) {
            Harness::advertising(tag, groups, &[], |_, _| Vec::new())
        }

        /// With this host advertising `own`, and having the addresses `addresses`
        /// says on an interface.
        fn advertising(tag: &str, groups: Vec<Group>, own: &[AdvertiseConfig], addresses: Addresses) -> (Harness, String) {
            std::fs::create_dir_all("target").unwrap();
            let path = format!("target/avahi-test-{}-{tag}.sock", std::process::id());
            let _ = std::fs::remove_file(&path);
            let mut server = Server::bind(&path, own, &[Family::V4, Family::V6]).unwrap();
            server.addresses = addresses;
            (Harness { server, groups }, path)
        }

        fn pump(&mut self) {
            let mut fds = self.server.fds();
            poll::wait(&mut fds, Some(Duration::from_millis(1))).unwrap();
            self.server.ready(&fds);
            self.server.tick(&self.groups, Instant::now());
        }

        /// What the server tells a client that sends `request`: all that it says
        /// before it closes the connection.
        fn ask(&mut self, path: &str, request: &str) -> String {
            let mut stream = UnixStream::connect(path).unwrap();
            stream.set_nonblocking(true).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut reply = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut buf = [0u8; 256];
                match stream.read(&mut buf) {
                    Ok(0) => return String::from_utf8(reply).unwrap(),
                    Ok(n) => reply.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("{e}"),
                }
                assert!(Instant::now() < deadline, "not closed; so far {reply:?}");
                self.pump();
            }
        }
    }

    #[test]
    fn a_name_that_is_known_is_answered_at_once_and_the_connection_closed() {
        let (groups, seg, _rx) = group_on_lo();
        hear(&seg, "10.0.0.7", "tv.local", &["10.0.0.7", "fe80::7", "fd00::7"]);
        let (mut h, path) = Harness::new("known", groups);
        let index = socket::ifindex(socket::LOOPBACK).unwrap();
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV4 tv.local\n"), format!("+ {index} 0 tv.local 10.0.0.7\n"));
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV6 TV.local\n"), format!("+ {index} 1 tv.local fd00::7\n"));
        assert_eq!(h.ask(&path, "RESOLVE-ADDRESS fe80::7\n"), format!("+ {index} 1 tv.local\n"));
        assert_eq!(h.ask(&path, "RESOLVE-ADDRESS 10.9.9.9\n"), "-30 Not found\n");
        assert!(h.ask(&path, "NONSENSE\n").starts_with("-21"));
        assert!(h.ask(&path, "RESOLVE-HOSTNAME-IPV4 example.com\n").starts_with("-3"));
        // The socket is for anyone.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o666);
    }

    #[test]
    fn a_name_that_is_not_known_is_asked_for_and_answered_once_it_is_heard() {
        let (groups, seg, rx) = group_on_lo();
        let (mut h, path) = Harness::new("asked", groups);
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(b"RESOLVE-HOSTNAME-IPV4 sleepy.local\n").unwrap();
        for _ in 0..50 {
            h.pump();
        }
        // It is asked for, over the interface, for IPv4 only.
        let mut buf = [0u8; 1500];
        let (n, _) = rx.recv_from(&mut buf).expect("a question was sent");
        let question = Message::parse(&buf[..n]).unwrap();
        assert_eq!((question.questions[0].name.as_str(), question.questions[0].qtype), ("sleepy.local", rtype::A));
        assert_eq!(question.questions.len(), 1);
        // It answers.
        hear(&seg, "10.0.0.8", "sleepy.local", &["10.0.0.8"]);
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        stream.set_nonblocking(true).unwrap();
        let mut line = String::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !line.ends_with('\n') {
            match reader.read_line(&mut line) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => h.pump(),
                Err(e) => panic!("{e}"),
            }
            assert!(Instant::now() < deadline);
        }
        assert_eq!(line, format!("+ {} 0 sleepy.local 10.0.0.8\n", socket::ifindex(socket::LOOPBACK).unwrap()));
    }

    #[test]
    fn a_name_that_never_answers_times_out_and_a_client_that_asks_nothing_is_let_go() {
        let (groups, _seg, _rx) = group_on_lo();
        let (mut h, path) = Harness::new("timeout", groups);
        let started = Instant::now();
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV6 nobody.local\n"), "-15 Timeout reached\n");
        assert!(started.elapsed() >= WAIT && started.elapsed() < WAIT * 4);

        let mut idle = UnixStream::connect(&path).unwrap();
        idle.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 8];
        loop {
            h.pump();
            match idle.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => panic!("told something"),
                Err(_) => {}
            }
            assert!(Instant::now() < deadline, "an idle client is not let go");
        }
        assert!(h.server.clients.is_empty());
    }

    #[test]
    fn an_address_of_a_family_a_known_name_has_none_of_is_not_waited_long_for() {
        let (groups, seg, _rx) = group_on_lo();
        hear(&seg, "10.0.0.7", "tv.local", &["10.0.0.7"]);
        let (mut h, path) = Harness::new("family", groups);
        let started = Instant::now();
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV6 tv.local\n"), "-15 Timeout reached\n");
        assert!(started.elapsed() >= KNOWN_WAIT && started.elapsed() < WAIT, "{:?}", started.elapsed());
    }

    fn advertise(name: &str, interfaces: &[&str]) -> AdvertiseConfig {
        AdvertiseConfig { name: name.into(), interfaces: interfaces.iter().map(|s| s.to_string()).collect(), ..AdvertiseConfig::default() }
    }

    /// This host has an IPv4 address and a global and a link-local IPv6 address.
    fn dual_stack(_: &str, _: &[Family]) -> Vec<IpAddr> {
        vec![ip("10.0.0.1"), ip("2001:db8::1"), ip("fe80::1")]
    }

    fn v4_only(_: &str, _: &[Family]) -> Vec<IpAddr> {
        vec![ip("10.0.0.1")]
    }

    #[test]
    fn a_name_this_host_advertises_is_answered_at_its_own_addresses() {
        let (groups, _seg, _rx) = group_on_lo();
        let (mut h, path) = Harness::advertising("own", groups, &[advertise("Pc.local", &[])], dual_stack);
        let index = socket::ifindex(socket::LOOPBACK).unwrap();
        // Without asking the network: it is not waited for.
        let started = Instant::now();
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV4 pc.local\n"), format!("+ {index} 0 pc.local 10.0.0.1\n"));
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV6 PC.local.\n"), format!("+ {index} 1 pc.local 2001:db8::1\n"), "a routable address before the link-local one");
        assert_eq!(h.ask(&path, "RESOLVE-ADDRESS 2001:db8::1\n"), format!("+ {index} 1 Pc.local\n"));
        assert_eq!(h.ask(&path, "RESOLVE-ADDRESS 10.5.5.5\n"), "-30 Not found\n");
        assert!(started.elapsed() < KNOWN_WAIT);
    }

    #[test]
    fn a_name_is_only_answered_for_on_the_interfaces_it_is_advertised_on() {
        let (groups, _seg, _rx) = group_on_lo();
        let (mut h, path) = Harness::advertising("where", groups, &[advertise("pc.local", &[socket::LOOPBACK]), advertise("away.local", &["eth9"])], dual_stack);
        assert!(h.ask(&path, "RESOLVE-HOSTNAME-IPV4 pc.local\n").starts_with("+ "));
        // Of an interface the segment does not have, nothing: it is asked for, and not found.
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV4 away.local\n"), "-15 Timeout reached\n");
    }

    #[test]
    fn an_advertised_name_with_no_address_of_a_family_is_not_waited_long_for() {
        let (groups, _seg, _rx) = group_on_lo();
        let (mut h, path) = Harness::advertising("advfamily", groups, &[advertise("pc.local", &[])], v4_only);
        let started = Instant::now();
        assert!(h.ask(&path, "RESOLVE-HOSTNAME-IPV4 pc.local\n").starts_with("+ "));
        assert_eq!(h.ask(&path, "RESOLVE-HOSTNAME-IPV6 pc.local\n"), "-15 Timeout reached\n");
        assert!(started.elapsed() < WAIT, "{:?}", started.elapsed());
    }

    #[test]
    fn a_request_that_is_too_long_is_refused() {
        let (groups, _seg, _rx) = group_on_lo();
        let (mut h, path) = Harness::new("long", groups);
        let reply = h.ask(&path, &format!("RESOLVE-HOSTNAME-IPV4 {}", "a".repeat(2000)));
        assert!(reply.starts_with("-21") && reply.contains("too long"), "{reply}");
    }

    #[test]
    fn a_name_is_advertised_on_all_interfaces_unless_it_says_which() {
        let block = |name: &str, interfaces: &[&str]| AdvertiseConfig { name: name.into(), interfaces: interfaces.iter().map(|s| s.to_string()).collect(), ..AdvertiseConfig::default() };
        assert!(advertised_on(&block("pc.local", &[]), "br0"));
        assert!(advertised_on(&block("pc.local", &["br0"]), "br0"));
        assert!(!advertised_on(&block("pc.local", &["media"]), "br0"));
    }
}
