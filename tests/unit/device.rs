use super::*;
use crate::codec::Header;
use crate::message::record;

fn parts() -> ServiceParts {
    ServiceParts {
        instance: "Living Room\\. TV._http._tcp.local".into(),
        kind: "_http._tcp.local".into(),
        port: 8080,
        target: Some("tv.local".into()),
        txt: vec![b"a=b".to_vec(), vec![0xff, 0x00, 0x80], b"flag".to_vec()],
        subtypes: vec!["_a._sub._http._tcp.local".into(), "_b._sub._http._tcp.local".into()],
        ttl: 4500,
    }
}

/// A service is made of what it is given and gives it back, with nothing
/// between but the block: no room to spare, whatever its parts.
#[test]
fn a_service_gives_back_what_it_was_made_of_in_a_block_with_no_room_to_spare() {
    let service = Service::from(parts());
    assert_eq!(service.parts(), parts());
    assert_eq!(
        (service.instance(), service.kind(), service.port(), service.target(), service.ttl()),
        ("Living Room\\. TV._http._tcp.local", "_http._tcp.local", 8080, Some("tv.local"), 4500)
    );
    assert_eq!(service.subtypes().collect::<Vec<_>>(), ["_a._sub._http._tcp.local", "_b._sub._http._tcp.local"]);
    // A TXT value may be any bytes, a NUL among them.
    assert_eq!(service.txt().collect::<Vec<_>>(), [&b"a=b"[..], &[0xff, 0x00, 0x80], b"flag"]);
    // The port and TTL, three names and the subtypes with their ends, and the TXT data.
    let names = ["Living Room\\. TV._http._tcp.local", "_http._tcp.local", "tv.local"].map(str::len);
    let size = 6 + names.iter().sum::<usize>() + 3 + (25 + 25) + 1 + (3 + 1 + 3 + 1 + 4 + 1);
    assert_eq!(service.block.len(), size);
}

/// What is not known is empty, and none of it is told apart from what is
/// not there: no host, no subtypes, no TXT.
#[test]
fn a_service_with_little_known_of_it_says_so() {
    for service in [Service::default(), ServiceParts { instance: "x._a._tcp.local".into(), ..Default::default() }.into()] {
        assert_eq!((service.port(), service.ttl(), service.target()), (0, 0, None));
        assert!(service.subtypes().next().is_none() && service.txt().next().is_none());
        assert!(!service.is_resolved());
    }
    assert_eq!(Service::default().parts(), ServiceParts::default());
    // Only a host and a port say where it is.
    let mut service = Service::default();
    service.edit(|p| p.port = 80);
    assert!(!service.is_resolved());
    service.edit(|p| p.target = Some("tv.local".into()));
    assert!(service.is_resolved());
}

/// A string of TXT data is as long as the wire says it can be, and one
/// that is empty, as a subtype is, is not said.
#[test]
fn txt_is_what_a_string_can_be_and_what_is_empty_is_not_said() {
    let service: Service = ServiceParts {
        instance: "a._x._tcp.local".into(),
        kind: "_x._tcp.local".into(),
        subtypes: vec!["_s._sub._x._tcp.local".into(), String::new()],
        txt: vec![vec![b'x'; 255], Vec::new(), b"k=v".to_vec()],
        ..Default::default()
    }
    .into();
    assert_eq!(service.subtypes().collect::<Vec<_>>(), ["_s._sub._x._tcp.local"]);
    assert_eq!(service.txt().map(<[u8]>::len).collect::<Vec<_>>(), [255, 3]);
}

#[test]
#[should_panic(expected = "a name has no NUL")]
fn a_name_with_a_nul_in_it_is_a_mistake() {
    let _ = Service::from(ServiceParts { instance: "a\0b._x._tcp.local".into(), ..Default::default() });
}

#[test]
#[should_panic(expected = "a name has no NUL")]
fn a_subtype_with_a_nul_in_it_is_a_mistake() {
    let _ = Service::from(ServiceParts { subtypes: vec!["_s\0_sub._x._tcp.local".into()], ..Default::default() });
}

#[test]
#[should_panic(expected = "at most 255 bytes, not 256")]
fn a_string_of_txt_data_over_255_bytes_is_a_mistake() {
    let _ = Service::from(ServiceParts { txt: vec![vec![b'x'; 256]], ..Default::default() });
}

/// An edit that changes nothing leaves the block as it is, and one that
/// does makes it again with nothing to spare.
#[test]
fn editing_a_service_makes_the_block_again_only_if_something_is_not_as_it_was() {
    let mut service = Service::from(parts());
    let at = service.block.as_ptr();
    assert!(!service.edit(|p| p.port = 8080));
    assert!(!service.edit(|p| p.txt = vec![b"a=b".to_vec(), vec![0xff, 0x00, 0x80], b"flag".to_vec()]));
    assert_eq!(service.block.as_ptr(), at, "the same block");

    assert!(service.edit(|p| p.subtypes.retain(|s| s.starts_with("_a."))));
    assert_eq!(service.subtypes().collect::<Vec<_>>(), ["_a._sub._http._tcp.local"]);
    assert!(service.edit(|p| p.txt.clear()));
    assert!(service.txt().next().is_none());
    assert_eq!(service.parts().port, 8080, "the rest is as it was");
    assert_eq!(Service::from(service.parts()), service);
}


/// Its first routable IPv4 or IPv6 address, and link-local one.
fn v4(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv4())
}

fn v6(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv6())
}

pub(crate) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(crate) fn a_record(host: &str, addr: &str) -> Record {
    record(host.into(), true, 120, RData::A(addr.parse().unwrap()))
}

pub(crate) fn aaaa(host: &str, addr: &str) -> Record {
    record(host.into(), true, 120, RData::Aaaa(addr.parse().unwrap()))
}

pub(crate) fn srv(instance: &str, port: u16, target: &str) -> Record {
    record(instance.into(), true, 120, RData::Srv { priority: 0, weight: 0, port, target: target.into() })
}

pub(crate) fn ptr(kind: &str, instance: &str) -> Record {
    record(kind.into(), false, 4500, RData::Ptr(instance.into()))
}

pub(crate) fn nsec(name: &str, types: &[u16]) -> Record {
    record(name.into(), true, 120, RData::Nsec { next: name.into(), types: types.to_vec() })
}

pub(crate) fn reverse(addr: &str, host: &str) -> Record {
    record(codec::reverse_name(ip(addr)), true, 120, RData::Ptr(host.into()))
}

pub(crate) fn response(records: Vec<Record>) -> Message {
    Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: records,
        authorities: vec![],
        additionals: vec![],
    }
}

/// Make `device` hear `records`, as an interface puts them to the one device
/// they are about: the report on it, and what ties to no host.
fn hear(device: &mut Device, records: Vec<Record>) {
    let msg = response(records);
    let (reports, rest) = Report::all(&msg);
    for report in &reports {
        device.learn(report, &report.addrs, DEFAULT_MAX_ADDRS, DEFAULT_MAX_SERVICES);
    }
    device.learn_records(rest.into_iter(), DEFAULT_MAX_SERVICES);
}

pub(crate) fn heard(records: Vec<Record>) -> Device {
    let mut device = Device::default();
    hear(&mut device, records);
    device
}

pub(crate) fn tv(addr: &str, instances: &[&str]) -> Device {
    let mut device = Device {
        hostname: Some("tv.local".into()),
        services: instances
            .iter()
            .map(|i| {
                ServiceParts {
                    instance: format!("{i}._http._tcp.local"),
                    kind: "_http._tcp.local".into(),
                    port: 8080,
                    txt: vec![b"a=b".to_vec()],
                    ..ServiceParts::default()
                }
                .into()
            })
            .collect(),
        ..Device::default()
    };
    device.add_addrs(&[ip(addr)]);
    device
}

pub(crate) fn only(mut msgs: Vec<Message>) -> Message {
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    msgs.remove(0)
}

/// `n` devices `dev0.local`, `dev1.local`, ... each with a service of
/// `_http._tcp` with a TXT record of `txt` bytes.
pub(crate) fn many(n: usize, txt: usize) -> Vec<Device> {
    (0..n)
        .map(|i| {
            let mut d = tv(&format!("10.0.1.{}", i + 1), &[&format!("Device {i}")]);
            d.hostname = Some(format!("dev{i}.local"));
            d.services[0].edit(|p| p.target = d.hostname.clone());
            d.services[0].edit(|p| p.txt = vec![format!("k={}", "v".repeat(txt)).into_bytes()]);
            d
        })
        .collect()
}

/// Narrowed to some types, a device keeps only its services of them, and
/// is nothing without one.
#[test]
fn a_device_narrowed_to_types_keeps_only_those_services() {
    let mut device = tv("10.0.1.9", &["TV", "Cast"]);
    device.services[1].edit(|p| p.kind = "_googlecast._tcp.local".into());
    let narrow = device.only_kinds(&["_GoogleCast._tcp.local".to_string()]).unwrap();
    assert_eq!(narrow.services.len(), 1);
    assert_eq!(narrow.services[0].kind(), "_googlecast._tcp.local");
    assert_eq!((narrow.hostname, narrow.addresses), (device.hostname.clone(), device.addresses.clone()));
    assert!(device.only_kinds(&["_ipp._tcp.local".to_string()]).is_none());
}

fn origins(d: &Device) -> Vec<(IpAddr, Origin)> {
    d.addresses.iter().map(|a| (a.ip, a.origin)).collect()
}

/// The neighbour table fills in a family the device announced no
/// routable address of, and only that; what it announces itself wins.
#[test]
fn neighbours_fill_in_what_a_device_did_not_announce() {
    use Origin::{Announced, Neighbour};
    let mut d = Device { hostname: Some("tv.local".into()), ..Device::default() };
    d.take_addrs(&[ip("10.0.1.9"), ip("fe80::9")], &[], &[], DEFAULT_MAX_ADDRS);
    assert_eq!(d.link_local().collect::<Vec<_>>(), [ip("fe80::9")]);

    // Of IPv6, it announced only its link-local address: the routable
    // ones listed under its link-layer address are taken; of IPv4 it
    // announced one, so the neighbour's is not.
    assert!(d.take_neighbours(&[ip("fd00::9"), ip("2001:db8::9"), ip("10.0.1.99"), ip("fe80::99")], DEFAULT_MAX_ADDRS));
    assert_eq!(origins(&d), [
        (ip("10.0.1.9"), Announced),
        (ip("2001:db8::9"), Neighbour),
        (ip("fd00::9"), Neighbour),
        (ip("fe80::9"), Announced),
    ]);
    assert!(!d.take_neighbours(&[ip("fd00::9"), ip("2001:db8::9")], DEFAULT_MAX_ADDRS), "nothing new");

    // Its announcements of IPv6 replace what it announced, not what was learned.
    d.take_addrs(&[ip("fe80::9")], &[Family::V6], &[], DEFAULT_MAX_ADDRS);
    assert!(d.has_addr(&ip("fd00::9")) && d.has_addr(&ip("2001:db8::9")));

    // A neighbour entry that goes takes its address with it.
    assert!(d.take_neighbours(&[ip("fd00::9")], DEFAULT_MAX_ADDRS));
    assert!(!d.has_addr(&ip("2001:db8::9")));

    // Announced after all, it is announced...
    d.take_addrs(&[ip("fd00::9")], &[], &[], DEFAULT_MAX_ADDRS);
    assert_eq!(d.addresses.iter().find(|a| a.ip == ip("fd00::9")).unwrap().origin, Announced);
    // ...and with a routable IPv6 address announced, none is learned of IPv6.
    d.take_neighbours(&[ip("fd00::9"), ip("2001:db8::77")], DEFAULT_MAX_ADDRS);
    assert!(!d.has_addr(&ip("2001:db8::77")));
    assert!(d.addresses.iter().all(|a| a.origin == Announced));
}

/// Of the learned addresses, only those of a family the device announced
/// a link-local address of are kept, for reflecting by default.
#[test]
fn learned_addresses_can_be_kept_to_families_with_a_link_local_address() {
    let mut d = Device::default();
    d.take_addrs(&[ip("fe80::9")], &[], &[], DEFAULT_MAX_ADDRS);
    d.take_neighbours(&[ip("fd00::9"), ip("10.0.1.9")], DEFAULT_MAX_ADDRS);
    assert_eq!(d.addrs().collect::<Vec<_>>(), [ip("10.0.1.9"), ip("fd00::9"), ip("fe80::9")]);
    let advertised = |neighbours, link_local| {
        let mut how = Advertise::default();
        (how.neighbours, how.link_local) = (neighbours, link_local);
        d.advertised(&how).map(|a| a.ip).collect::<Vec<_>>()
    };
    assert_eq!(advertised(Neighbours::LinkLocal, true), [ip("fd00::9"), ip("fe80::9")], "no IPv4 link-local was announced");
    assert_eq!(advertised(Neighbours::Never, true), [ip("fe80::9")]);
    assert_eq!(advertised(Neighbours::LinkLocal, false), [ip("fd00::9")], "link-local ones mean nothing off the link");
    assert_eq!(advertised(Neighbours::Always, true), d.addrs().collect::<Vec<_>>());
    assert_eq!(d.addresses.len(), 3, "none is dropped, only not advertised");
}

/// A service is held once by a device and its copies: changing it as it is
/// does nothing, and changing it gives the changed one a copy of its own, while
/// the others keep what they had.
#[test]
fn a_service_is_held_once_and_copied_only_when_it_is_changed() {
    let mut device = tv("10.0.1.9", &["TV"]);
    let copy = device.clone();
    assert!(Rc::ptr_eq(&device.services[0], &copy.services[0]), "a copy of the device holds the same service");

    assert!(!device.services[0].edit(|p| p.port = 8080), "not changed");
    assert!(Rc::ptr_eq(&device.services[0], &copy.services[0]), "and not copied");

    assert!(device.services[0].edit(|p| p.port = 81));
    assert_eq!((device.services[0].port(), copy.services[0].port()), (81, 8080), "the copy has what it had");
    assert!(!Rc::ptr_eq(&device.services[0], &copy.services[0]));

    // Held by one, it is changed where it is.
    let at = Rc::as_ptr(&device.services[0]);
    assert!(device.services[0].edit(|p| p.port = 82));
    assert_eq!(Rc::as_ptr(&device.services[0]), at);
}

/// Learned addresses count towards how many of a family are kept.
#[test]
fn neighbours_count_towards_the_limit() {
    let mut d = Device::default();
    d.take_addrs(&[ip("fe80::9")], &[], &[], 2);
    d.take_neighbours(&[ip("fd00::1"), ip("fd00::2"), ip("fd00::3")], 2);
    assert_eq!(d.addrs().filter(|a| a.is_ipv6()).count(), 2);
}

/// What a device announces itself comes before what the neighbour table
/// says of it: a full set of learned addresses must not turn it away.
#[test]
fn announced_addresses_are_not_turned_away_by_learned_ones() {
    let mut d = Device::default();
    d.take_neighbours(&[ip("2001:db8::1"), ip("2001:db8::2")], 2);
    d.take_addrs(&[ip("2001:db8::99")], &[], &[], 2);
    assert_eq!(d.addrs().collect::<Vec<_>>(), [ip("2001:db8::99")]);
}

#[test]
fn only_names_a_device_can_have_are_taken() {
    for ok in ["tv.local", "TV-2.LOCAL", "a.b.local", "fernseh-küche.local"] {
        assert!(is_hostname(ok), "{ok}");
    }
    for bad in ["tv", "tv.com", "local", "tv.local.evil", "bad\\.dot.local", "sp ace.local", "nul\0.local", "bad\u{FFFD}.local", ".local", ""] {
        assert!(!is_hostname(bad), "{bad:?}");
    }
    for ok in ["_http._tcp.local", "_androidtvremote2._tcp.local", "_x._udp.LOCAL", "_home-sharing._tcp.local"] {
        assert!(is_type(ok), "{ok}");
    }
    for bad in ["http._tcp.local", "_._tcp.local", "_http._xyz.local", "_http.local", "_http._tcp.com", "_ht tp._tcp.local", "a._http._tcp.local"] {
        assert!(!is_type(bad), "{bad}");
    }
    for ok in ["My TV._http._tcp.local", "Dots\\.in\\.it._http._tcp.local", "Wohnzimmer Ü._ipp._tcp.local"] {
        assert!(is_instance_name(ok), "{ok}");
    }
    for bad in ["._http._tcp.local", "Bell\u{7}._http._tcp.local", "X._http._tcp.com", "X.tv.local", "\u{FFFD}._http._tcp.local"] {
        assert!(!is_instance_name(bad), "{bad:?}");
    }
}

#[test]
fn only_addresses_a_device_can_be_reached_at_are_taken() {
    for ok in ["10.0.1.5", "192.168.1.1", "169.254.1.2", "fd00::1", "2001:db8::1", "fe80::1"] {
        assert!(is_usable(ip(ok)), "{ok}");
    }
    for bad in [
        "0.0.0.0", "0.1.2.3", "127.0.0.1", "224.0.0.251", "239.1.2.3", "240.0.0.1", "255.255.255.255",
        "::", "::1", "ff02::fb", "::ffff:10.0.1.5", "::10.0.1.5",
    ] {
        assert!(!is_usable(ip(bad)), "{bad}");
    }
}

/// Records no device could have announced are left out of a report, as
/// if they were not there.
#[test]
fn records_no_device_could_have_announced_are_left_out() {
    let msg = response(vec![
        a_record("tv.local", "10.0.1.7"),
        a_record("tv.com", "10.0.1.8"),
        Record { class: 3, ..a_record("tv.local", "10.0.1.9") },
        srv("Port Zero._http._tcp.local", 0, "tv.local"),
        ptr("_http._tcp.local", "Other Type._ipp._tcp.local"),
        srv("TV._http._tcp.local", 80, "tv.local"),
    ]);
    let (reports, rest) = Report::all(&msg);
    let [report] = &reports[..] else { panic!("{} reports", reports.len()) };
    assert_eq!((report.host.as_str(), report.addrs.clone()), ("tv.local", vec![ip("10.0.1.7")]));
    let kept: Vec<&str> = report.records.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(kept, ["TV._http._tcp.local"]);
    assert!(rest.is_empty(), "{rest:?}");
}

/// What a report says of TTLs comes from each address's, and each other
/// record's, own: the longest address TTL, and the longest of all, which
/// the host is kept for at least.
#[test]
fn a_reports_ttls_come_from_each_records_own() {
    let msg = response(vec![
        Record { ttl: 120, ..a_record("tv.local", "10.0.1.7") },
        Record { ttl: 300, ..aaaa("tv.local", "fd00::7") },
        Record { ttl: 86400, ..a_record("tv.local", "0.0.0.0") },
        Record { ttl: 4500, ..srv("TV._http._tcp.local", 80, "tv.local") },
    ]);
    let (reports, _) = Report::all(&msg);
    let r = &reports[0];
    assert_eq!(r.ttls, HashMap::from([(ip("10.0.1.7"), 120), (ip("fd00::7"), 300)]));
    assert_eq!(r.addr_ttl(), Some(300), "an unusable address's does not count");
    assert_eq!(r.longest_ttl(), 4500);

    let only_service = response(vec![Record { ttl: 4500, ..srv("TV._http._tcp.local", 80, "tv.local") }]);
    let (reports, _) = Report::all(&only_service);
    assert_eq!((reports[0].addr_ttl(), reports[0].longest_ttl()), (None, 4500));
}

#[test]
fn a_host_that_announced_only_unusable_addresses_is_refused() {
    let refused = |records| {
        let msg = response(records);
        let (reports, _) = Report::all(&msg);
        (reports[0].addrs.clone(), reports[0].refused.clone())
    };
    assert_eq!(refused(vec![a_record("tv.local", "0.0.0.0")]), (vec![], vec![ip("0.0.0.0")]));
    assert_eq!(
        refused(vec![a_record("tv.local", "0.0.0.0"), a_record("tv.local", "10.0.1.7")]),
        (vec![ip("10.0.1.7")], vec![ip("0.0.0.0")])
    );
    assert_eq!(refused(vec![srv("TV._http._tcp.local", 80, "tv.local")]), (vec![], vec![]), "it said nothing");
    // Of either family, whatever the packet came over.
    assert_eq!(
        refused(vec![aaaa("tv.local", "::1"), aaaa("tv.local", "fd00::7")]),
        (vec![ip("fd00::7")], vec![ip("::1")])
    );
}

#[test]
fn a_device_holds_only_so_much() {
    let mut device = Device { hostname: Some("tv.local".into()), addresses: vec![ip("10.0.1.7").into()].into(), ..Device::default() };
    let services: Vec<Record> = (0..DEFAULT_MAX_SERVICES + 10).map(|i| srv(&format!("S{i}._http._tcp.local"), 80, "tv.local")).collect();
    device.learn_records(services.iter(), DEFAULT_MAX_SERVICES);
    assert_eq!(device.services.len(), DEFAULT_MAX_SERVICES);

    let subtypes: Vec<Record> =
        (0..MAX_SUBTYPES + 5).map(|i| ptr(&format!("_s{i}._sub._http._tcp.local"), "S0._http._tcp.local")).collect();
    device.learn_records(subtypes.iter(), DEFAULT_MAX_SERVICES);
    assert_eq!(device.service("S0._http._tcp.local").unwrap().subtypes().count(), MAX_SUBTYPES);

    let mappings: Vec<Record> = (0..MAX_REVERSE + 5).map(|i| reverse(&format!("10.0.2.{i}"), "tv.local")).collect();
    device.learn_records(mappings.iter(), DEFAULT_MAX_SERVICES);
    assert_eq!(device.reverse.len(), MAX_REVERSE);
}

#[test]
fn a_device_has_the_addresses_of_both_families_whatever_it_was_heard_over() {
    // It sends from its IPv6 link-local address and announces that, a
    // ULA, and its IPv4 address, all in one packet.
    let device = heard(vec![
        aaaa("tv.local", "fd00:0:1::7"),
        aaaa("tv.local", "fe80::7"),
        a_record("tv.local", "10.0.1.7"),
    ]);
    assert_eq!(device.hostname.as_deref(), Some("tv.local"));
    assert_eq!(device.addrs().collect::<Vec<_>>(), [ip("10.0.1.7"), ip("fd00:0:1::7"), ip("fe80::7")]);

    // One family heard later leaves the other as it was.
    let mut device = heard(vec![a_record("nas.local", "10.0.1.8")]);
    hear(&mut device, vec![aaaa("nas.local", "fd00::8")]);
    assert_eq!((v4(&device), v6(&device)), (Some(ip("10.0.1.8")), Some(ip("fd00::8"))));
}

/// Addresses announced with the cache-flush bit are all a device has of
/// their family: they replace those it had, and leave the other family
/// alone. Without it, they are added. A goodbye drops just its address.
#[test]
fn a_family_announced_with_cache_flush_is_replaced_and_otherwise_added_to() {
    let mut device = heard(vec![a_record("tv.local", "10.0.1.7"), aaaa("tv.local", "2001:db8::7"), aaaa("tv.local", "fd00::7")]);

    // A new temporary address in place of the old, with the ULA kept.
    hear(&mut device, vec![aaaa("tv.local", "2001:db8::99"), aaaa("tv.local", "fd00::7")]);
    assert_eq!(device.addrs().collect::<Vec<_>>(), [ip("10.0.1.7"), ip("2001:db8::99"), ip("fd00::7")]);

    let without_flush = |addr: &str| Record { cache_flush: false, ..aaaa("tv.local", addr) };
    hear(&mut device, vec![without_flush("2001:db8::100")]);
    assert_eq!(device.addrs().collect::<Vec<_>>(), [ip("10.0.1.7"), ip("2001:db8::99"), ip("2001:db8::100"), ip("fd00::7")]);

    hear(&mut device, vec![Record { ttl: 0, ..aaaa("tv.local", "2001:db8::99") }]);
    assert_eq!(device.addrs().collect::<Vec<_>>(), [ip("10.0.1.7"), ip("2001:db8::100"), ip("fd00::7")]);

    // However many it announces, only so many of a family are kept.
    let many: Vec<Record> = (0..DEFAULT_MAX_ADDRS + 10).map(|i| without_flush(&format!("2001:db8::{:x}", 0x200 + i))).collect();
    hear(&mut device, many);
    assert_eq!(device.addrs().filter(|a| a.is_ipv6()).count(), DEFAULT_MAX_ADDRS);
    assert_eq!(device.addrs().filter(|a| a.is_ipv4()).count(), 1);
}

/// DNS compares names without regard to case, and devices are not
/// consistent about it, not even within one packet.
#[test]
fn names_that_differ_only_in_case_are_one_and_the_same() {
    let mut device = heard(vec![
        a_record("tv.local", "10.0.1.7"),
        ptr("_HTTP._TCP.LOCAL", "TV._http._tcp.local"),
        srv("tv._HTTP._tcp.local", 80, "tv.local"),
    ]);
    assert_eq!(device.services.len(), 1, "{:?}", device.services);
    let svc = &device.services[0];
    assert_eq!((svc.instance(), svc.kind(), svc.port()), ("TV._http._tcp.local", "_HTTP._TCP.LOCAL", 80));

    // A goodbye in yet another spelling still says goodbye to it.
    let bye = Record { ttl: 0, ..srv("Tv._Http._Tcp.Local", 80, "tv.local") };
    hear(&mut device, vec![a_record("tv.local", "10.0.1.7"), bye]);
    assert!(device.services.is_empty());
}

#[test]
fn the_ttls_a_device_announces_are_kept_and_the_address_ones_do_not_get_the_services() {
    let device = heard(vec![
        a_record("d.local", "10.0.1.30"),
        record("D._x._tcp.local".into(), true, 4500, RData::Srv { priority: 0, weight: 0, port: 1, target: "d.local".into() }),
        record("_x._tcp.local".into(), false, 100, RData::Ptr("D._x._tcp.local".into())),
    ]);
    assert_eq!(device.ttl, Some(120));
    // The SRV record's TTL counts, not the PTR's.
    assert_eq!(device.services[0].ttl(), 4500);
}

/// A printer says it is an AirPrint one with a subtype PTR next to its
/// usual one. That is kept with the service, and a goodbye for it drops
/// the subtype, not the service.
#[test]
fn subtypes_are_kept_with_their_service() {
    let printer = |sub_ttl| {
        vec![
            a_record("printer.local", "10.0.1.8"),
            ptr("_ipp._tcp.local", "Office._ipp._tcp.local"),
            Record { ttl: sub_ttl, ..ptr("_universal._sub._ipp._tcp.local", "Office._ipp._tcp.local") },
            srv("Office._ipp._tcp.local", 631, "printer.local"),
        ]
    };

    let mut device = heard(printer(4500));
    assert_eq!(device.services.len(), 1);
    assert_eq!(device.services[0].subtypes().collect::<Vec<_>>(), ["_universal._sub._ipp._tcp.local"]);
    assert_eq!(device.services[0].kind(), "_ipp._tcp.local", "the type is not the subtype's");

    // Heard again, in another case and on its own: still one.
    hear(&mut device, vec![ptr("_UNIVERSAL._sub._ipp._tcp.local", "Office._ipp._tcp.local")]);
    assert_eq!(device.services[0].subtypes().count(), 1);

    hear(&mut device, printer(0));
    assert!(device.services[0].subtypes().next().is_none());
    assert_eq!(device.services[0].port(), 631);
}

/// A device says which types its hostname has with an NSEC record, in
/// its announcements or on its own as a negative answer. That of its
/// service instances is not kept, nor taken for a host.
#[test]
fn what_a_device_says_its_hostname_has_is_kept() {
    let records = vec![
        a_record("tv.local", "10.0.1.7"),
        nsec("tv.local", &[rtype::A]),
        srv("TV._http._tcp.local", 80, "tv.local"),
        nsec("TV._http._tcp.local", &[rtype::TXT, rtype::SRV]),
    ];
    assert_eq!(Report::all(&response(records.clone())).0.len(), 1);
    let mut device = heard(records);
    assert_eq!(device.nsec, Some(vec![rtype::A].into()));

    // On its own, it is still about the host it names.
    hear(&mut device, vec![nsec("TV.local", &[rtype::A, rtype::AAAA])]);
    assert_eq!(device.nsec, Some(vec![rtype::A, rtype::AAAA].into()));
    hear(&mut device, vec![Record { ttl: 0, ..nsec("tv.local", &[rtype::A]) }]);
    assert_eq!(device.nsec, None);
}

/// A device announces a reverse-mapping PTR for its address. That is kept
/// with the host it names, not taken for a service or a host of its own.
#[test]
fn reverse_mappings_are_kept_with_the_host_they_name() {
    let records = vec![a_record("tv.local", "10.0.1.7"), reverse("10.0.1.7", "tv.local")];
    assert_eq!(Report::all(&response(records.clone())).0.len(), 1);
    let mut device = heard(records);
    assert_eq!(&*device.reverse, [ip("10.0.1.7")]);
    assert!(device.services.is_empty());

    // On its own, as an answer to a reverse lookup: still the same.
    hear(&mut device, vec![reverse("10.0.1.7", "TV.local")]);
    assert_eq!(&*device.reverse, [ip("10.0.1.7")]);
    hear(&mut device, vec![Record { ttl: 0, ..reverse("10.0.1.7", "tv.local") }]);
    assert!(device.reverse.is_empty());
}

/// A sleep proxy or Thread border router announces a host's records from
/// its own address. Its NSEC and reverse mapping go to that host, as its
/// address does, and nothing is left over for the proxy.
#[test]
fn what_a_proxy_says_of_a_host_goes_to_that_host() {
    let msg = response(vec![
        a_record("tv.local", "10.0.1.7"),
        nsec("tv.local", &[rtype::A]),
        reverse("10.0.1.7", "tv.local"),
    ]);
    let (reports, rest) = Report::all(&msg);
    assert!(rest.is_empty());
    let [report] = &reports[..] else { panic!("{} reports", reports.len()) };
    assert_eq!(report.host, "tv.local");

    let mut device = Device::default();
    device.learn(report, &report.addrs, DEFAULT_MAX_ADDRS, DEFAULT_MAX_SERVICES);
    assert_eq!(v4(&device), Some(ip("10.0.1.7")), "the proxy's address is not the host's");
    assert_eq!((device.nsec, device.reverse), (Some(vec![rtype::A].into()), vec![ip("10.0.1.7")].into()));
}
