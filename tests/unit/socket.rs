use super::*;

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
fn a_prefix_holds_the_addresses_of_its_network() {
    for (net, inside, outside) in [
        ("10.0.2.1/24", "10.0.2.255", "10.0.3.0"),
        ("10.0.2.1/32", "10.0.2.1", "10.0.2.2"),
        ("10.0.2.1/0", "192.0.2.1", "::1"),
        ("2001:db8:2::1/64", "2001:db8:2::ffff:1", "2001:db8:3::1"),
        ("2001:db8:2::1/128", "2001:db8:2::1", "2001:db8:2::2"),
        ("::/0", "2001:db8::1", "10.0.2.1"),
        ("::a00:201/96", "::a00:2ff", "10.0.2.1"), // the families are not mixed
    ] {
        assert!(prefix(net).contains(&ip(inside)), "{net} holds {inside}");
        assert!(!prefix(net).contains(&ip(outside)), "{net} does not hold {outside}");
    }
}

#[test]
fn the_loopback_interface_is_on_its_network() {
    let nets = prefixes(LOOPBACK).unwrap();
    assert!(nets.contains(&prefix("127.0.0.1/8")), "{nets:?}");
    assert!(prefixes("no-such-interface").unwrap().is_empty());
}
