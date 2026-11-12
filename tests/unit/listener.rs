use super::*;
use crate::addr::prefix;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The interface a datagram came in on is read from what the system says, in
/// the form each has: the two families', and Linux's and the BSDs' for IPv4.
#[test]
fn the_interface_a_datagram_came_in_on_is_read_from_each_systems_control_message() {
    // IPv6, the same everywhere: the address it was sent to, then the interface.
    let mut in6 = [0u8; 20];
    in6[..16].copy_from_slice(&"ff02::fb".parse::<Ipv6Addr>().unwrap().octets());
    in6[16..].copy_from_slice(&7u32.to_ne_bytes());
    assert_eq!(arrival::from_in6_pktinfo(&in6), Some(7));
    assert_eq!(arrival::from_in6_pktinfo(&in6[..19]), None, "too short");
    assert_eq!(arrival::from_in6_pktinfo(&[0u8; 20]), None, "no interface is not one");

    // Linux's IPv4: the interface, the address it was sent to, the one it was sent from.
    let mut in4 = [0u8; 12];
    in4[..4].copy_from_slice(&5u32.to_ne_bytes());
    in4[4..8].copy_from_slice(&[224, 0, 0, 251]);
    assert_eq!(arrival::from_in_pktinfo(&in4), Some(5));
    assert_eq!(arrival::from_in_pktinfo(&in4[..3]), None);

    // The BSDs' IPv4: a link-level address of a length, a family (AF_LINK is 18 on all of
    // them) and the interface's index, then its name and the rest.
    let mut dl = [0u8; 20];
    dl[0] = 20;
    dl[1] = 18;
    dl[2..4].copy_from_slice(&300u16.to_ne_bytes());
    dl[4] = 3;
    assert_eq!(arrival::from_sockaddr_dl(&dl), Some(300), "an index too big for a byte");
    assert_eq!(arrival::from_sockaddr_dl(&dl[..3]), None);
    assert_eq!(arrival::from_sockaddr_dl(&[0u8; 20]), None);

    // The address it was sent to, in the form of each: IPv6's, Linux's and the BSDs'.
    let group = "224.0.0.251".parse::<Ipv4Addr>().unwrap();
    in4[8..12].copy_from_slice(&group.octets());
    assert_eq!(arrival::addr_from_in_pktinfo(&in4), Some(IpAddr::V4(group)));
    assert_eq!(arrival::addr_from_in_pktinfo(&in4[..11]), None);
    assert_eq!(arrival::addr_from_in_addr(&group.octets()), Some(IpAddr::V4(group)));
    assert_eq!(arrival::addr_from_in_addr(&[224, 0, 0]), None);
    assert_eq!(arrival::destination_of(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6), Some("ff02::fb".parse().unwrap()));
    assert_eq!(arrival::destination_of(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6[..15]), None);
    assert_eq!(arrival::destination_of(libc::IPPROTO_IPV6, -1, &in6), None);

    // Told apart by level and kind: what is not about the interface is not read.
    assert_eq!(arrival::index_of(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6), Some(7));
    assert_eq!(arrival::index_of(libc::IPPROTO_IPV6, -1, &in6), None);
    assert_eq!(arrival::index_of(libc::SOL_SOCKET, libc::IPV6_PKTINFO, &in6), None);
}

use super::LOOPBACK;

#[test]
fn the_addresses_to_advertise_are_all_of_the_wanted_families_routable_first() {
    let found = [ip("fe80::1"), ip("fd00::2"), ip("10.0.0.9"), ip("127.0.0.1"), ip("169.254.1.1"), ip("10.0.0.5"), ip("2001:db8::3"), ip("10.0.0.9"), ip("fe80:2::7")];
    assert_eq!(
        ordered(&found, &[Family::V4, Family::V6]),
        [ip("10.0.0.5"), ip("10.0.0.9"), ip("2001:db8::3"), ip("fd00::2"), ip("169.254.1.1"), ip("fe80::1"), ip("fe80::7")],
        "each once, routable first, the scope of a link-local taken out, no loopback"
    );
    assert_eq!(ordered(&found, &[Family::V4]), [ip("10.0.0.5"), ip("10.0.0.9"), ip("169.254.1.1")]);
    assert_eq!(ordered(&found, &[]), Vec::<IpAddr>::new());
}

#[test]
fn a_loopback_interface_says_so() {
    assert!(is_loopback(LOOPBACK));
    assert!(!is_loopback("no-such-if0"));
}

#[test]
fn an_interfaces_mtu_is_read() {
    assert!(mtu(LOOPBACK).unwrap() >= 1280, "every network namespace has a loopback");
    assert!(mtu("no-such-if0").is_err());
    assert!(mtu("a-name-far-too-long-for-one").is_err());
    assert!(mtu("nul\0").is_err());
}

#[test]
fn the_loopback_interface_is_on_its_network() {
    let nets = prefixes(LOOPBACK).unwrap();
    assert!(nets.contains(&prefix("127.0.0.1/8")), "{nets:?}");
    assert!(prefixes("no-such-interface").unwrap().is_empty());
}

/// A std socket as the crate's own descriptor type holds it.
fn owned(socket: impl std::os::fd::IntoRawFd) -> OwnedFd {
    // SAFETY: a descriptor just given up by its owner.
    unsafe { rustix::fd::FromRawFd::from_raw_fd(socket.into_raw_fd()) }
}

/// Who sent a datagram is read of either family, off a real one.
#[test]
fn the_sender_of_a_datagram_is_read_of_either_family() {
    use std::net::UdpSocket;
    for (bind, v6) in [("127.0.0.1:0", false), ("[::1]:0", true)] {
        let Ok(rx) = UdpSocket::bind(bind) else {
            assert!(v6, "IPv4 on the loopback interface");
            continue; // no IPv6 here
        };
        let tx = UdpSocket::bind(bind).unwrap();
        tx.send_to(b"hi", rx.local_addr().unwrap()).unwrap();
        let from = tx.local_addr().unwrap();
        let rx = owned(rx);
        let mut buf = [0u8; 16];
        let got = recv(&rx, &mut buf).expect("a datagram");
        assert_eq!((got.from, &buf[..got.len]), (Some(from), &b"hi"[..]));
    }
}

/// A datagram from something that has no IP address is read, and not given:
/// there is nobody it can be said to be from.
#[test]
fn a_datagram_from_no_ip_address_is_read_and_not_given() {
    use std::os::unix::net::UnixDatagram;
    let (tx, rx) = UnixDatagram::pair().unwrap();
    rx.set_nonblocking(true).unwrap();
    tx.send(b"hi").unwrap();
    let rx = owned(rx);
    let mut buf = [0u8; 16];
    let got = recv(&rx, &mut buf).unwrap();
    assert_eq!((got.len, got.from), (2, None));
    tx.send(b"again").unwrap();
    let mut heard = 0;
    drain(&rx, "lo", |_, _, _| heard += 1);
    assert_eq!(heard, 0, "and it is not waited for either");
}

/// Where the socket is not pinned to an interface that has an IPv4 address,
/// what is sent to an IPv4 destination is sent, with nothing said of the
/// interface to send it out of.
#[test]
fn a_sender_with_no_ipv4_address_for_its_interface_still_sends_to_an_ipv4_destination() {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = Sender { fd: owned(UdpSocket::bind("127.0.0.1:0").unwrap()), out: Some((1, None)) };
    tx.send_to(b"hi", rx.local_addr().unwrap()).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(rx.recv(&mut buf).unwrap(), 2);
}

/// Everything is read until there is no more; and what the system reports
/// instead of a datagram (an ICMP error, say) is said once, and ends it.
#[test]
fn what_a_socket_reports_in_place_of_a_datagram_is_said_once_and_ends_the_reading() {
    use std::net::UdpSocket;
    let gone = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = gone.local_addr().unwrap();
    drop(gone);
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.set_nonblocking(true).unwrap();
    tx.connect(to).unwrap();
    // Nothing listens there, so the system tells this socket so, on the loopback
    // interface, at once.
    tx.send(b"anyone?").unwrap();
    let tx = owned(tx);
    let mut heard = 0;
    drain(&tx, "lo", |_, _, _| heard += 1);
    assert_eq!(heard, 0);
    // And it is cleared: there is nothing more to read.
    drain(&tx, "lo", |_, _, _| heard += 1);
    assert_eq!(heard, 0);
}

/// A socket cannot be pinned to an interface that is not there.
#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
#[test]
fn a_socket_is_not_pinned_to_an_interface_that_is_not_there() {
    let socket = owned(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
    let err = pinned::bind_device(&socket, "nosuchif0").unwrap_err();
    assert!(format!("{err:#}").contains("binding to nosuchif0"), "{err:#}");
    // Where sockets are pinned, there is nothing shared to read.
    let hub = Hub::new(&[Family::V4], &[]).unwrap();
    assert_eq!(hub.fds().count(), 0);
    hub.receive(3, |_, _, _, _| panic!("nothing to give"));
}

/// What a link says goes to everyone on it over every family, an answer goes
/// to the asker's side alone, a legacy resolver is answered by itself, and a
/// host is asked directly over its own family.
#[test]
fn a_link_says_to_everyone_answers_the_askers_side_and_asks_hosts_directly() {
    use std::net::UdpSocket;
    let (group4, group6) = (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap());
    for socket in [&group4, &group6] {
        socket.set_read_timeout(Some(core::time::Duration::from_millis(100))).unwrap();
    }
    let sender = || -> OwnedFd {
        // SAFETY: a descriptor just given up by its owner.
        unsafe { rustix::fd::FromRawFd::from_raw_fd(std::os::fd::IntoRawFd::into_raw_fd(UdpSocket::bind("127.0.0.1:0").unwrap())) }
    };
    // Both go to a local socket, as the groups do in tests: the family is only what they are told.
    let link = Link::to(Family::V4, sender(), group4.local_addr().unwrap()).and(Family::V6, sender(), group6.local_addr().unwrap());
    assert_eq!(link.families().len(), 2);
    let heard = |socket: &UdpSocket| {
        let mut buf = [0u8; 16];
        socket.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    };

    link.send(b"all").unwrap();
    assert_eq!((heard(&group4), heard(&group6)), (Some(b"all".to_vec()), Some(b"all".to_vec())));

    link.reply(Family::V6, None, b"six").unwrap();
    assert_eq!((heard(&group4), heard(&group6)), (None, Some(b"six".to_vec())), "to the asker's side");
    let alone = UdpSocket::bind("127.0.0.1:0").unwrap();
    alone.set_read_timeout(Some(core::time::Duration::from_millis(100))).unwrap();
    link.reply(Family::V4, Some(alone.local_addr().unwrap()), b"alone").unwrap();
    assert_eq!((heard(&group4), heard(&alone)), (None, Some(b"alone".to_vec())), "a legacy resolver by itself");

    assert!(link.reaches(ip("10.0.1.3")) && link.reaches(ip("fd00::3")));
    assert!(!Link::default().reaches(ip("10.0.1.3")));
    assert!(link.ask(ip("127.0.0.1"), b"direct"), "sent to its port, which nothing listens on");
    assert!(!Link::to(Family::V4, sender(), group4.local_addr().unwrap()).ask(ip("fd00::3"), b"x"), "no way to its family");

    // A link used over nothing says nothing, and is not an error.
    assert!(Link::default().is_empty());
    Link::default().send(b"nobody").unwrap();
    Link::default().reply(Family::V4, None, b"nobody").unwrap();
}

/// An interface takes what is sent to the group, and what is sent to the
/// daemon itself only over the families it says it hears that over.
#[test]
fn an_interface_takes_what_is_sent_to_the_daemon_over_the_families_it_hears_that_over() {
    let interface = |config: &str| {
        crate::config::Config::parse(&format!("{config}[Segment]\nName=a\nInterfaces=x\n")).unwrap().interface("x")
    };
    let (group4, group6, own4, own6) = (Some(ip("224.0.0.251")), Some(ip("ff02::fb")), Some(ip("10.0.0.1")), Some(ip("fd00::1")));
    let all = interface("");
    assert!([group4, group6, own4, own6, None].into_iter().all(|to| hears(&all, to)));
    let group_only = interface("[Interface]\nIPv4=multicast\n");
    assert!(hears(&group_only, group4) && hears(&group_only, group6) && hears(&group_only, None));
    assert!(!hears(&group_only, own4), "not over the family that is to hear the group alone");
    assert!(hears(&group_only, own6), "but over the other");
    let neither = interface("[Interface]\nIPv4=multicast\nIPv6=multicast\n");
    assert!(!hears(&neither, own4) && !hears(&neither, own6));
    assert!(hears(&neither, group4) && hears(&neither, group6));
}
