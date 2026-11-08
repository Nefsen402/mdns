use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn addresses_are_found_by_their_link_layer_address_as_they_change() {
    let mut table = NeighbourTable::default();
    let (a, b, c) = (vec![1; 6], vec![2; 6], vec![3; 6]);
    assert_eq!(table.insert(ip("10.0.0.1"), a.clone()), None);
    table.insert(ip("fd00::1"), a.clone());
    table.insert(ip("10.0.0.2"), b.clone());
    table.check();
    let mut with_a: Vec<IpAddr> = table.with_mac(&a).collect();
    with_a.sort();
    assert_eq!(with_a, [ip("10.0.0.1"), ip("fd00::1")]);

    // One that moves to another link-layer address is no longer found under the first.
    assert_eq!(table.insert(ip("10.0.0.1"), b.clone()), Some(a.clone()));
    assert_eq!(table.insert(ip("10.0.0.2"), b.clone()), Some(b.clone()), "set again to what it is");
    table.check();
    assert_eq!(table.with_mac(&a).collect::<Vec<_>>(), [ip("fd00::1")]);
    assert_eq!(table.with_mac(&b).count(), 2);

    assert_eq!(table.remove(&ip("fd00::1")), Some(a.clone()));
    assert_eq!(table.remove(&ip("fd00::1")), None);
    table.check();
    assert_eq!(table.with_mac(&a).count(), 0);
    assert_eq!(table.with_mac(&c).count(), 0);
    assert!(table.contains_key(&ip("10.0.0.2")) && !table.contains_key(&ip("fd00::1")));
}
