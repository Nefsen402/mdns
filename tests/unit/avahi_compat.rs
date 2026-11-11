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
    let reflector = Reflector::new(vec![seg.clone()]).unwrap();
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
