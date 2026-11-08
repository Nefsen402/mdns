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
#[path = "../tests/unit/avahi-compat.rs"]
mod tests;
