use super::*;

/// A message of `kind` with `body`, as the kernel lays it out.
fn message(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + body.len();
    let mut out = Vec::new();
    out.extend((len as u32).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend([0u8; 10]);
    out.extend(body);
    out.resize(align(out.len()), 0);
    out
}

fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(((RTA_HDRLEN + data.len()) as u16).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(data);
    out.resize(align(out.len()), 0);
    out
}

fn link(kind: u16, index: u32, flags: u32, name: &str) -> Vec<u8> {
    let mut body = vec![0u8; 4];
    body.extend(index.to_ne_bytes());
    body.extend(flags.to_ne_bytes());
    body.extend(0u32.to_ne_bytes());
    // The MTU first, as the kernel sends many before the name.
    body.extend(attr(IFLA_MTU, &1500u32.to_ne_bytes()));
    body.extend(attr(IFLA_IFNAME, format!("{name}\0").as_bytes()));
    message(kind, &body)
}

fn address(kind: u16, index: u32) -> Vec<u8> {
    let mut body = vec![10, 24, 0, 0];
    body.extend(index.to_ne_bytes());
    message(kind, &body)
}

#[test]
fn reads_links_coming_going_and_their_addresses() {
    let mut buf = link(RTM_NEWLINK, 7, IFF_UP | IFF_RUNNING, "mdns-a");
    buf.extend(link(RTM_NEWLINK, 8, IFF_UP, "wifi"));
    buf.extend(address(RTM_NEWADDR, 7));
    buf.extend(address(RTM_DELADDR, 8));
    buf.extend(link(RTM_DELLINK, 7, 0, "mdns-a"));
    assert_eq!(parse(&buf), [
        Change::Link { index: 7, name: "mdns-a".into(), up: true, mtu: Some(1500) },
        Change::Link { index: 8, name: "wifi".into(), up: false, mtu: Some(1500) },
        Change::Address { index: 7 },
        Change::Address { index: 8 },
        Change::Gone { index: 7 },
    ]);
}

/// A link message without an MTU, or with one too short to read, says
/// nothing of it.
#[test]
fn a_link_without_an_mtu_says_none() {
    let named = |extra: Vec<u8>| {
        let mut body = vec![0u8; 4];
        body.extend(9u32.to_ne_bytes());
        body.extend((IFF_UP | IFF_RUNNING).to_ne_bytes());
        body.extend(0u32.to_ne_bytes());
        body.extend(extra);
        body.extend(attr(IFLA_IFNAME, b"wifi\0"));
        parse(&message(RTM_NEWLINK, &body))
    };
    assert_eq!(named(vec![]), [Change::Link { index: 9, name: "wifi".into(), up: true, mtu: None }]);
    assert_eq!(named(attr(IFLA_MTU, &[1, 2])), [Change::Link { index: 9, name: "wifi".into(), up: true, mtu: None }]);
    assert_eq!(named(attr(IFLA_MTU, &9000u32.to_ne_bytes())), [Change::Link { index: 9, name: "wifi".into(), up: true, mtu: Some(9000) }]);
}

fn neighbour(kind: u16, index: u32, state: u16, ip: &[u8], mac: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![if ip.len() == 4 { 2 } else { 10 }, 0, 0, 0];
    body.extend(index.to_ne_bytes());
    body.extend(state.to_ne_bytes());
    body.extend([0u8, 1]); // flags, type
    body.extend(attr(NDA_DST, ip));
    if let Some(mac) = mac {
        body.extend(attr(NDA_LLADDR, mac));
    }
    message(kind, &body)
}

/// A neighbour entry that can be used gives its link-layer address; one
/// that went, failed or is still being resolved, none.
#[test]
fn reads_neighbour_entries() {
    let mac = [0x04, 0x09, 0x86, 0x43, 0xe3, 0xf6];
    let v6: IpAddr = "fd00:0:2::73".parse().unwrap();
    let v6_octets = match v6 { IpAddr::V6(a) => a.octets(), _ => unreachable!() };
    let mut buf = neighbour(RTM_NEWNEIGH, 5, 0x02, &v6_octets, Some(&mac)); // reachable
    buf.extend(neighbour(RTM_NEWNEIGH, 5, 0x04, &[10, 0, 2, 73], Some(&mac))); // stale
    buf.extend(neighbour(RTM_NEWNEIGH, 5, 0x20, &[10, 0, 2, 74], Some(&mac))); // failed
    buf.extend(neighbour(RTM_NEWNEIGH, 5, 0x01, &[10, 0, 2, 75], None)); // incomplete
    buf.extend(neighbour(RTM_DELNEIGH, 5, 0x04, &v6_octets, Some(&mac)));
    let mac = Some(mac.to_vec());
    assert_eq!(parse(&buf), [
        Change::Neighbour { index: 5, ip: v6, mac: mac.clone() },
        Change::Neighbour { index: 5, ip: "10.0.2.73".parse().unwrap(), mac },
        Change::Neighbour { index: 5, ip: "10.0.2.74".parse().unwrap(), mac: None },
        Change::Neighbour { index: 5, ip: "10.0.2.75".parse().unwrap(), mac: None },
        Change::Neighbour { index: 5, ip: v6, mac: None },
    ]);
    // Without an address, or with one of another length, it says nothing.
    assert!(parse(&neighbour(RTM_NEWNEIGH, 5, 0x02, &[1, 2, 3], None)).is_empty());
}

#[test]
fn what_cannot_be_read_is_skipped() {
    assert!(parse(&[]).is_empty());
    assert!(parse(&[1, 2, 3]).is_empty());
    // A length past the end stops the reading, and what came before stands.
    let mut buf = address(RTM_NEWADDR, 3);
    let mut broken = link(RTM_NEWLINK, 4, 0, "x");
    broken[0] = 0xff;
    buf.extend(broken);
    assert_eq!(parse(&buf), [Change::Address { index: 3 }]);
    // A link without a name, or with an attribute running over, is skipped.
    let mut nameless = vec![0u8; 4];
    nameless.extend(5u32.to_ne_bytes());
    nameless.extend([0u8; 8]);
    nameless.extend([0xff, 0x00, 0x03, 0x00]);
    assert!(parse(&message(RTM_NEWLINK, &nameless)).is_empty());
    // Other kinds of message are none of its business.
    assert!(parse(&message(2, &[0u8; 20])).is_empty());
}

/// What the kernel says, as a [`Tracker`] turns it into what is new.
fn said(tracker: &mut Tracker, changes: Vec<Change>) -> Vec<Event> {
    let mut events = Vec::new();
    for change in changes {
        tracker.apply(change, &mut events);
    }
    events
}

fn link_change(index: u32, name: &str, up: bool, mtu: u32) -> Change {
    Change::Link { index, name: name.into(), up, mtu: Some(mtu) }
}

fn up(name: &str, index: u32, mtu: u32, back: bool) -> Event {
    Event::Up { name: name.into(), index, mtu: Some(mtu), back }
}

fn down(name: &str, index: u32) -> Event {
    Event::Down { name: name.into(), index }
}

#[test]
fn an_interface_is_up_once_however_often_it_is_said_so() {
    let mut t = Tracker::default();
    assert_eq!(said(&mut t, vec![link_change(3, "ra", false, 1500)]), [], "not up yet");
    assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1500)]), [up("ra", 3, 1500, false)]);
    assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1500), link_change(3, "ra", true, 1500)]), []);
    assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1400)]), [Event::Mtu { name: "ra".into(), mtu: 1400 }]);
}

#[test]
fn an_interface_down_and_up_again_is_back() {
    let mut t = Tracker::default();
    said(&mut t, vec![link_change(3, "ra", true, 1500)]);
    assert_eq!(said(&mut t, vec![link_change(3, "ra", false, 1500)]), [down("ra", 3)]);
    // Its addresses going with it are not news.
    assert_eq!(said(&mut t, vec![Change::Address { index: 3 }]), []);
    assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1500)]), [up("ra", 3, 1500, true)]);
    assert_eq!(said(&mut t, vec![Change::Address { index: 3 }]), [Event::Addresses { name: "ra".into(), index: 3 }]);
}

#[test]
fn an_interface_made_again_is_down_and_up() {
    let mut t = Tracker::default();
    said(&mut t, vec![link_change(3, "ra", true, 1500)]);
    // Deleted, and made again; or made again before the deletion was said.
    assert_eq!(said(&mut t, vec![Change::Gone { index: 3 }, link_change(5, "ra", true, 1500)]), [down("ra", 3), up("ra", 5, 1500, true)]);
    assert_eq!(said(&mut t, vec![link_change(6, "ra", true, 1500)]), [down("ra", 5), up("ra", 6, 1500, true)]);
    // Renamed.
    assert_eq!(said(&mut t, vec![link_change(6, "rb", true, 1500)]), [down("ra", 6), up("rb", 6, 1500, false)]);
    // One that was down is not down again.
    said(&mut t, vec![link_change(6, "rb", false, 1500)]);
    assert_eq!(said(&mut t, vec![Change::Gone { index: 6 }]), []);
}

#[test]
fn asking_again_finds_what_was_lost() {
    let mut t = Tracker::default();
    said(&mut t, vec![link_change(3, "ra", true, 1500), link_change(4, "rb", true, 1500)]);
    t.dumping = Some(HashSet::new());
    // Of the two, one is said again, unchanged, and one not at all; a third is new.
    let events = said(&mut t, vec![link_change(3, "ra", true, 1500), link_change(7, "rc", true, 1500), Change::Done { seq: LINK_DUMP }]);
    assert_eq!(events, [up("rc", 7, 1500, false), down("rb", 4)]);
    // The dump of neighbours ending says nothing.
    assert_eq!(said(&mut t, vec![Change::Done { seq: NEIGHBOUR_DUMP }]), []);
}

#[test]
fn neighbours_are_those_of_interfaces_known() {
    let mut t = Tracker::default();
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    let entry = |index| Change::Neighbour { index, ip, mac: None };
    assert_eq!(said(&mut t, vec![entry(3)]), []);
    said(&mut t, vec![link_change(3, "ra", true, 1500)]);
    assert_eq!(said(&mut t, vec![entry(3)]), [Event::Neighbour { index: 3, ip, mac: None }]);
}

/// Manual check against the real kernel: needs nothing but a network
/// namespace to change, `unshare -rn cargo test netlink_live -- --ignored`.
#[test]
#[ignore]
fn netlink_live() {
    let mut netlink = Netlink::open().unwrap();
    std::process::Command::new("ip").args(["link", "add", "nl-test", "type", "dummy"]).status().unwrap();
    std::process::Command::new("ip").args(["link", "set", "nl-test", "up"]).status().unwrap();
    let events = netlink.events().unwrap();
    assert!(events.iter().any(|e| matches!(e, Event::Up { name, .. } if name == "nl-test")), "{events:?}");
}
