use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
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
