use super::*;

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
use crate::codec::Question;

/// Its first routable IPv4 or IPv6 address, and link-local one.
fn v4(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv4())
}
fn v6(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv6())
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn a_record(host: &str, addr: &str) -> Record {
    record(host.into(), true, 120, RData::A(addr.parse().unwrap()))
}

fn aaaa(host: &str, addr: &str) -> Record {
    record(host.into(), true, 120, RData::Aaaa(addr.parse().unwrap()))
}

fn srv(instance: &str, port: u16, target: &str) -> Record {
    record(instance.into(), true, 120, RData::Srv { priority: 0, weight: 0, port, target: target.into() })
}

fn ptr(kind: &str, instance: &str) -> Record {
    record(kind.into(), false, 4500, RData::Ptr(instance.into()))
}

fn nsec(name: &str, types: &[u16]) -> Record {
    record(name.into(), true, 120, RData::Nsec { next: name.into(), types: types.to_vec() })
}

fn reverse(addr: &str, host: &str) -> Record {
    record(codec::reverse_name(ip(addr)), true, 120, RData::Ptr(host.into()))
}

fn response(records: Vec<Record>) -> Message {
    Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: records,
        authorities: vec![],
        additionals: vec![],
    }
}

fn query(name: &str, qtype: u16) -> Message {
    Message {
        header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
        questions: vec![Question { name: name.into(), qtype, class: 1, unicast_response: false }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

/// Make `device` hear `records`, as a segment puts them to the one device
/// they are about: the report on it, and what ties to no host.
fn hear(device: &mut Device, records: Vec<Record>) {
    let msg = response(records);
    let (reports, rest) = Report::all(&msg);
    for report in &reports {
        device.learn(report, &report.addrs, DEFAULT_MAX_ADDRS, DEFAULT_MAX_SERVICES);
    }
    device.learn_records(rest.into_iter(), DEFAULT_MAX_SERVICES);
}

fn heard(records: Vec<Record>) -> Device {
    let mut device = Device::default();
    hear(&mut device, records);
    device
}

fn tv(addr: &str, instances: &[&str]) -> Device {
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

/// Two devices with a service of one type, and one with another type.
fn three_devices() -> Vec<Device> {
    let mut television = tv("10.0.1.9", &["TV"]);
    television.ttl = Some(300);
    let nas = Device { hostname: Some("nas.local".into()), ..tv("10.0.1.20", &["NAS"]) };
    let mut printer = Device { hostname: Some("printer.local".into()), ..tv("10.0.1.30", &["Printer"]) };
    printer.services[0].edit(|p| p.kind = "_ipp._tcp.local".into());
    printer.services[0].edit(|p| p.instance = "Printer._ipp._tcp.local".into());
    vec![television, nas, printer]
}

/// The one packet of a reply that fits in one.
/// The devices as they were heard, with all their addresses.
fn as_heard(devices: &[Device]) -> Vec<Advertised<'_>> {
    devices.iter().map(Into::into).collect()
}

fn only(mut msgs: Vec<Message>) -> Message {
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    msgs.remove(0)
}

#[test]
fn a_query_response_has_what_each_device_answers_once() {
    let devices = three_devices();
    let (msgs, answered) = Device::query_response(&as_heard(&devices), &query("_http._tcp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).unwrap();
    let msg = only(msgs);
    assert_eq!(answered, [0, 1], "the printer has nothing of that type");
    let browsed: Vec<&RData> = msg.answers.iter().map(|r| &r.data).collect();
    assert_eq!(browsed, [
        &RData::Ptr("TV._http._tcp.local".into()),
        &RData::Ptr("NAS._http._tcp.local".into()),
    ]);
    // Each comes with what it takes to resolve it, its address with the
    // TTL it is announced with, or the usual one.
    let addr_ttl = |host: &str| msg.additionals.iter().find(|r| r.name == host && matches!(r.data, RData::A(_))).map(|r| r.ttl);
    assert_eq!((addr_ttl("tv.local"), addr_ttl("nas.local")), (Some(300), Some(HOST_TTL)));
    assert_eq!(msg.additionals.iter().filter(|r| matches!(r.data, RData::Srv { .. })).count(), 2);
    assert!(msg.header.response && msg.header.authoritative && msg.questions.is_empty());

    // A record two of them have is given once.
    let (msgs, answered) =
        Device::query_response(&as_heard(&devices), &query("_services._dns-sd._udp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).unwrap();
    let msg = only(msgs);
    assert_eq!(answered, [0, 1, 2]);
    assert_eq!(msg.answers.len(), 2, "_http and _ipp: {:?}", msg.answers);

    // Nothing to say is no reply at all.
    assert!(Device::query_response(&as_heard(&devices), &query("_airplay._tcp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).is_none());
    assert!(Device::query_response(&as_heard(&[]), &query("_http._tcp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).is_none());
}

/// `n` devices `dev0.local`, `dev1.local`, ... each with a service of
/// `_http._tcp` with a TXT record of `txt` bytes.
fn many(n: usize, txt: usize) -> Vec<Device> {
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

fn sizes(msgs: &[Message]) -> Vec<usize> {
    msgs.iter().map(|m| m.encode().unwrap().len()).collect()
}

/// Records are put in as few packets as keep within the limit, in order,
/// answers before additional ones, each name and type's records together.
#[test]
fn records_are_split_into_packets_that_fit() {
    let records: Vec<Record> = many(30, 40).iter().flat_map(|d| d.announcement(&Advertise::ALL, 120, 4500)).collect();
    let packets = responses(&records, &[], 600);
    assert!(packets.len() > 1, "they do not fit in one");
    assert!(sizes(&packets).iter().all(|&s| s <= 600), "{:?}", sizes(&packets));
    let sent: Vec<Record> = packets.iter().flat_map(|m| m.answers.clone()).collect();
    assert_eq!(sent.len(), records.len(), "no record lost or doubled");
    // Each name and type in one packet: here, every device's addresses.
    for host in (0..30).map(|i| format!("dev{i}.local")) {
        let with = packets.iter().filter(|m| m.answers.iter().any(|r| r.name == host && r.rtype() == rtype::A)).count();
        assert_eq!(with, 1, "{host}");
    }
    // What fits in one stays in one.
    assert_eq!(responses(&records[..3], &[], 600).len(), 1);
    assert!(responses(&[], &[], 600).is_empty());

    // Additional records fill the room the answers leave, then packets of
    // their own, after the answers.
    let (answers, additionals) = records.split_at(10);
    let packets = responses(answers, additionals, 600);
    assert!(sizes(&packets).iter().all(|&s| s <= 600));
    assert_eq!(packets.iter().map(|m| m.answers.len()).sum::<usize>(), 10);
    assert_eq!(packets.iter().map(|m| m.additionals.len()).sum::<usize>(), additionals.len());
    let first_additional = packets.iter().position(|m| !m.additionals.is_empty()).unwrap();
    assert!(packets[first_additional + 1..].iter().all(|m| m.answers.is_empty()));
}

/// A record too big for any packet still goes out, alone; what comes
/// after it does not share its packet.
#[test]
fn a_record_too_big_for_a_packet_goes_alone() {
    let big = record("big._http._tcp.local".into(), true, 4500, RData::Txt(vec![vec![b'x'; 250]; 4]));
    let small = |i: u8| record(format!("dev{i}.local"), true, 120, RData::A([10, 0, 0, i].into()));
    let packets = responses(&[small(1), big.clone(), small(2)], &[], 512);
    assert_eq!(packets.len(), 3, "{packets:?}");
    assert_eq!(packets[1].answers, [big]);
    assert!(sizes(&packets)[1] > 512);
    assert!(sizes(&[packets[0].clone(), packets[2].clone()]).iter().all(|&s| s <= 512));
}

/// A browse many devices answer is split over as many packets as it
/// takes, none bigger than the limit, with every device's answer in one.
#[test]
fn a_large_reply_is_split_over_packets() {
    let devices = many(40, 100);
    let (packets, answered) = Device::query_response(&as_heard(&devices), &query("_http._tcp.local", rtype::PTR), false, 1452).unwrap();
    assert_eq!(answered.len(), 40);
    assert!(packets.len() > 1);
    assert!(sizes(&packets).iter().all(|&s| s <= 1452), "{:?}", sizes(&packets));
    let browsed = packets.iter().flat_map(|m| &m.answers).filter(|r| r.rtype() == rtype::PTR).count();
    assert_eq!(browsed, 40);
    assert!(packets.iter().all(|m| m.header.response && m.questions.is_empty()));
}

/// A legacy resolver gets one reply of at most 512 bytes, or of what its
/// query says it takes (and the interface allows). Answers left out mark
/// it truncated; additional records left out do not.
#[test]
fn a_legacy_reply_fits_what_the_resolver_takes() {
    let devices = many(40, 100);
    let browse = query("_http._tcp.local", rtype::PTR);
    let (packets, _) = Device::query_response(&as_heard(&devices), &browse, true, 1452).unwrap();
    let reply = only(packets);
    assert!(reply.encode().unwrap().len() <= 512);
    assert!(reply.header.truncated, "not every answer fits");
    assert!(!reply.answers.is_empty());

    // With EDNS0 saying 4096, as much as the interface allows.
    let mut edns = browse.clone();
    edns.additionals.push(Record { name: String::new(), class: 4096, cache_flush: false, ttl: 0, data: RData::Other { rtype: OPT, data: vec![] } });
    let reply = only(Device::query_response(&as_heard(&devices), &edns, true, 1452).unwrap().0);
    let size = reply.encode().unwrap().len();
    assert!(size > 512 && size <= 1452, "{size}");

    // One device: its answer fits, but not all its additional records
    // (its TXT record is too big), and leaving those out is no truncation.
    let mut one = many(1, 0);
    one[0].services[0].edit(|p| p.txt = vec![format!("a={}", "x".repeat(240)).into_bytes(), format!("b={}", "x".repeat(240)).into_bytes()]);
    let whole = only(Device::query_response(&as_heard(&one), &browse, false, 1452).unwrap().0);
    let reply = only(Device::query_response(&as_heard(&one), &browse, true, 1452).unwrap().0);
    assert_eq!(reply.answers.len(), 1);
    assert!(reply.additionals.len() < whole.additionals.len(), "the TXT record does not fit");
    assert!(!reply.header.truncated);
    assert!(reply.encode().unwrap().len() <= 512);
}

/// Questions are put fewer to a packet when they are long.
#[test]
fn long_questions_are_put_fewer_to_a_packet() {
    let mut devices = many(16, 1);
    for (i, d) in devices.iter_mut().enumerate() {
        d.services[0].edit(|p| p.instance = format!("{}{i}._http._tcp.local", "n".repeat(60)));
        d.services[0].edit(|p| p.target = None);
    }
    let queries = Device::refresh_queries(&devices, 512);
    assert!(queries.len() > 2, "{}", queries.len());
    assert!(sizes(&queries).iter().all(|&s| s <= 512), "{:?}", sizes(&queries));
    assert_eq!(queries.iter().map(|q| q.questions.len()).sum::<usize>(), 16 * 2 + 16, "SRV, TXT and the address of each");
}

#[test]
fn a_legacy_resolver_gets_its_question_back_and_short_ttls_without_cache_flush() {
    let devices = three_devices();
    let mut asked = query("tv.local", rtype::ANY);
    asked.header.id = 0x4242;

    let (msgs, _) = Device::query_response(&as_heard(&devices), &asked, true, DEFAULT_MAX_PACKET).unwrap();
    let msg = only(msgs);
    assert_eq!((msg.header.id, msg.questions.clone()), (0x4242, asked.questions.clone()));
    assert!(msg.answers.iter().chain(&msg.additionals).all(|r| r.ttl <= LEGACY_TTL_CAP && !r.cache_flush));

    // To the group, none of that.
    let (msgs, _) = Device::query_response(&as_heard(&devices), &asked, false, DEFAULT_MAX_PACKET).unwrap();
    let msg = only(msgs);
    assert_eq!(msg.header.id, 0);
    assert!(msg.questions.is_empty());
    assert!(msg.answers.iter().any(|r| r.ttl == 300 && r.cache_flush));
}

/// Every question the `queries` ask, as (name, type), in order.
fn asked(queries: &[Message]) -> Vec<(String, u16)> {
    assert!(queries.iter().all(|q| !q.header.response && q.questions.len() <= QUESTIONS_PER_PACKET));
    queries.iter().flat_map(|q| &q.questions).map(|q| (q.name.clone(), q.qtype)).collect()
}

fn q(name: &str, qtype: u16) -> (String, u16) {
    (name.to_string(), qtype)
}

#[test]
fn a_probe_asks_for_types_instances_subtypes_and_whatever_is_missing() {
    // Resolved and with a routable address: only its type is browsed.
    let mut resolved = tv("10.0.1.9", &["TV"]);
    resolved.services[0].edit(|p| p.target = Some("tv.local".into()));
    // Of the same type, with a subtype heard of, but not yet resolved.
    let mut unresolved = tv("10.0.1.10", &["Den"]);
    unresolved.hostname = None;
    unresolved.services[0].edit(|p| p.subtypes = vec!["_scanner._sub._http._tcp.local".into()]);
    // Known by name, but only by a link-local address.
    let named = Device { hostname: Some("nas.local".into()), addresses: vec![ip("169.254.1.1").into()].into(), ..Device::default() };
    let types = BTreeSet::from(["_ipp._tcp.local".to_string()]);

    let questions = asked(&Device::probe_queries(&[resolved, unresolved, named], &types, DEFAULT_MAX_PACKET));
    for wanted in [
        q(META_QUERY, rtype::PTR),
        q("_http._tcp.local", rtype::PTR),
        q("_ipp._tcp.local", rtype::PTR),
        q("_printer._sub._http._tcp.local", rtype::PTR),
        q("_universal._sub._ipp._tcp.local", rtype::PTR),
        q("_scanner._sub._http._tcp.local", rtype::PTR),
        q("Den._http._tcp.local", rtype::SRV),
        q("Den._http._tcp.local", rtype::TXT),
        q("nas.local", rtype::A),
    ] {
        assert!(questions.contains(&wanted), "{wanted:?} in {questions:?}");
    }
    assert_eq!(questions.iter().filter(|w| **w == q("_http._tcp.local", rtype::PTR)).count(), 1, "asked once");
    assert!(!questions.contains(&q("TV._http._tcp.local", rtype::SRV)), "already resolved");
    assert!(!questions.contains(&q("tv.local", rtype::A)), "already has a routable address");
    assert!(!questions.contains(&q("_universal._sub._ipps._tcp.local", rtype::PTR)), "no _ipps around");

    // However many types there are, a packet has only so many questions.
    let types: BTreeSet<String> = (0..40).map(|i| format!("_t{i}._tcp.local")).collect();
    let queries = Device::probe_queries(&[], &types, DEFAULT_MAX_PACKET);
    assert_eq!(asked(&queries).len(), 41);
    assert_eq!(queries.len(), 3);
}

/// Asking for types by name browses each, and finishes what is missing
/// of their devices only: instances to resolve, hosts to find an address
/// for. What is known goes along as known answers.
#[test]
fn asking_for_types_browses_them_and_resolves_their_devices_only() {
    // Of the type, unresolved, known only by a link-local address.
    let mut plug = tv("169.254.1.5", &["Plug"]);
    plug.hostname = Some("plug.local".into());
    plug.services[0].edit(|p| p.kind = "_shelly._tcp.local".into());
    plug.services[0].edit(|p| p.instance = "Plug._shelly._tcp.local".into());
    // Of another type, as unfinished: none of its business.
    let mut other = tv("169.254.1.6", &["TV"]);
    other.hostname = Some("other.local".into());
    let kinds = ["_Shelly._tcp.local".to_string()];
    let ptr = Record {
        name: "_shelly._tcp.local".into(),
        class: 1,
        cache_flush: false,
        ttl: 60,
        data: RData::Ptr("Plug._shelly._tcp.local".into()),
    };
    let known = |q: &Question| if q.qtype == rtype::PTR { vec![ptr.clone()] } else { Vec::new() };

    let queries = Device::type_queries(&[plug.clone(), other], &kinds, known, DEFAULT_MAX_PACKET);
    assert_eq!(asked(&queries), [
        q("_Shelly._tcp.local", rtype::PTR),
        q("Plug._shelly._tcp.local", rtype::SRV),
        q("Plug._shelly._tcp.local", rtype::TXT),
        q("plug.local", rtype::A),
        q("plug.local", rtype::AAAA),
    ]);
    assert_eq!(queries[0].answers, [ptr]);

    // Resolved and reachable, only the type is asked for.
    plug.services[0].edit(|p| p.target = Some("plug.local".into()));
    plug.add_addrs(&[ip("10.0.1.5")]);
    assert_eq!(asked(&Device::type_queries(&[plug], &kinds, |_| Vec::new(), DEFAULT_MAX_PACKET)), [q("_Shelly._tcp.local", rtype::PTR)]);
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

#[test]
fn a_refresh_asks_each_device_for_what_it_announced_and_no_more() {
    let devices = [tv("fd00::9", &["TV", "Cast"]), tv("fd00::9", &["TV"])];
    let questions = asked(&Device::refresh_queries(&devices, DEFAULT_MAX_PACKET));
    assert_eq!(questions, [
        q("tv.local", rtype::AAAA),
        q("TV._http._tcp.local", rtype::SRV),
        q("TV._http._tcp.local", rtype::TXT),
        q("Cast._http._tcp.local", rtype::SRV),
        q("Cast._http._tcp.local", rtype::TXT),
    ]);
    assert!(Device::refresh_queries(&[], DEFAULT_MAX_PACKET).is_empty());
}

#[test]
fn a_transition_announces_the_new_and_takes_back_only_what_is_ours() {
    let none = |_: &str| false;
    let mut old = tv("10.0.1.9", &["Kitchen", "Den"]);
    old.ttl = Some(300);
    old.nsec = Some(vec![rtype::A].into());
    let goodbyes = |records: &[Record]| records.iter().filter(|r| r.ttl == 0).cloned().collect::<Vec<_>>();

    assert!(Device::transition(Some((&old).into()), Some((&old).into()), &none, false).is_empty(), "nothing changed");
    assert!(Device::transition(None, None, &none, false).is_empty());

    let shown = Device::transition(None, Some((&old).into()), &none, false);
    assert!(shown.iter().any(|r| r.data == RData::A("10.0.1.9".parse().unwrap()) && r.ttl == 300 && r.cache_flush));
    assert!(goodbyes(&shown).is_empty());

    // Moved: the new address, and a goodbye for the old one that does not
    // flush the new.
    let moved = Device { addresses: vec![ip("10.0.1.10").into()].into(), ..old.clone() };
    let bye = goodbyes(&Device::transition(Some((&old).into()), Some((&moved).into()), &none, false));
    assert_eq!(bye.len(), 1);
    assert_eq!((&bye[0].data, bye[0].cache_flush), (&RData::A("10.0.1.9".parse().unwrap()), false));

    // Withdrawn: everything, none of it flushing.
    let bye = goodbyes(&Device::transition(Some((&old).into()), None, &none, false));
    assert_eq!(bye.len(), old.announcement(&Advertise::ALL, 0, 0).len());
    assert!(bye.iter().all(|r| !r.cache_flush));

    // But not what a device on the segment has: a service of the same
    // instance name, or, if one has the hostname, the NSEC.
    let local = |name: &str| name.eq_ignore_ascii_case("kitchen._http._tcp.local");
    let bye = goodbyes(&Device::transition(Some((&old).into()), None, &local, true));
    assert!(!bye.iter().any(|r| r.name.starts_with("Kitchen.") || r.data == RData::Ptr("Kitchen._http._tcp.local".into())));
    assert!(!bye.iter().any(|r| matches!(r.data, RData::Nsec { .. })));
    assert!(bye.iter().any(|r| r.name.starts_with("Den.")), "{bye:?}");
}

/// A device is asked again for the address records of the families it
/// has, or of both if it has none yet.
#[test]
fn a_device_is_asked_for_the_addresses_of_its_families() {
    let named = |addrs: &[&str]| {
        let mut d = Device { hostname: Some("tv.local".into()), ..Device::default() };
        d.add_addrs(&addrs.iter().map(|a| ip(a)).collect::<Vec<_>>());
        d
    };
    assert_eq!(named(&["10.0.1.9"]).address_types(), [rtype::A]);
    assert_eq!(named(&["fd00::9"]).address_types(), [rtype::AAAA]);
    assert_eq!(named(&["10.0.1.9", "fd00::9"]).address_types(), [rtype::A, rtype::AAAA]);
    assert_eq!(named(&[]).address_types(), [rtype::A, rtype::AAAA]);
    assert_eq!(asked(&Device::refresh_queries(&[named(&[])], DEFAULT_MAX_PACKET)), [
        q("tv.local", rtype::A),
        q("tv.local", rtype::AAAA),
    ]);
}

/// A copy's NSEC names the address types it is announced with, IPv6 as
/// well as IPv4, along with what the device said it has.
#[test]
fn a_copys_nsec_names_its_ipv6_addresses_too() {
    let mut d = tv("fd00::9", &[]);
    d.nsec = Some(vec![].into());
    let types = |d: &Device| match d.nsec_record(&Advertise::ALL, 120).map(|r| r.data) {
        Some(RData::Nsec { types, .. }) => types,
        other => panic!("{other:?}"),
    };
    assert_eq!(types(&d), [rtype::AAAA]);
    d.add_addrs(&[ip("10.0.1.9")]);
    assert_eq!(types(&d), [rtype::A, rtype::AAAA]);
}

/// Only questions of class IN, or any class, are answered: mDNS records
/// are of IN alone.
#[test]
fn only_questions_of_class_in_or_any_are_answered() {
    let d = tv("10.0.1.9", &["TV"]);
    let of_class = |class: u16| {
        let mut msg = query("tv.local", rtype::A);
        msg.questions[0].class = class;
        d.answers(&Advertise::ALL, &msg, 120, 4500).0
    };
    assert_eq!(of_class(1).len(), 1);
    assert_eq!(of_class(255).len(), 1);
    assert!(of_class(3).is_empty(), "CHAOS");
    assert!(of_class(4).is_empty(), "Hesiod");
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

/// Which services a device is announced with is for whoever shows it to say,
/// as the records are made: one of a type kept out, or not yet resolved, is in
/// none of them, nor its name in the names it answers to, and a segment that
/// stops showing it says goodbye to it.
#[test]
fn services_are_announced_as_they_are_advertised() {
    let service = |instance: &str, kind: &str, target: Option<&str>| -> Rc<Service> {
        ServiceParts {
            instance: format!("{instance}.{kind}.local"),
            kind: format!("{kind}.local"),
            port: 631,
            target: target.map(String::from),
            ..ServiceParts::default()
        }
        .into()
    };
    let mut d = tv("10.0.1.9", &[]);
    d.services = vec![
        service("Office", "_ipp._tcp", Some("tv.local")),
        service("Shell", "_ssh._tcp", Some("tv.local")),
        service("Bare", "_ipp._tcp", None),
    ]
    .into();
    d.services.sort_by_key(|s| s.instance().to_ascii_lowercase());
    let how = crate::config::Config::parse("[Segment]\nName=a\nInterfaces=x,y\nReflectedServices=!_ssh._tcp")
        .unwrap()
        .segments[0]
        .advertise
        .clone();
    let srv = |records: Vec<Record>, ttl: u32| -> Vec<String> {
        let mut named: Vec<String> =
            records.into_iter().filter(|r| matches!(r.data, RData::Srv { .. }) && r.ttl == ttl).map(|r| r.name).collect();
        named.sort();
        named
    };
    assert_eq!(srv(d.announcement(&Advertise::ALL, 120, 4500), 4500), ["Bare._ipp._tcp.local", "Office._ipp._tcp.local", "Shell._ssh._tcp.local"]);
    assert_eq!(srv(d.announcement(&how, 120, 4500), 4500), ["Office._ipp._tcp.local"]);
    assert!(d.has_name(&Advertise::ALL, "shell._ssh._tcp.local") && !d.has_name(&how, "shell._ssh._tcp.local"));
    assert!(d.has_name(&Advertise::ALL, "_ssh._tcp.local") && !d.has_name(&how, "_ssh._tcp.local"));
    let goodbyes = d.replacement(&Advertise::ALL, Advertised { device: &d, how: &how, host_ttl: 120 }, 120, 4500);
    assert_eq!(srv(goodbyes, 0), ["Bare._ipp._tcp.local", "Shell._ssh._tcp.local"]);
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
fn a_device_knows_what_it_has_and_what_its_nsec_says_it_has_not() {
    let mut device = tv("10.0.1.9", &["TV"]);
    let knows = |d: &Device, name: &str, qtype: u16| {
        d.knows(&Advertise::ALL, &Question { name: name.into(), qtype, class: 1, unicast_response: false })
    };
    assert!(knows(&device, "TV.local", rtype::A));
    assert!(knows(&device, "tv.local", rtype::ANY));
    assert!(knows(&device, "_http._tcp.local", rtype::PTR));
    assert!(knows(&device, "TV._http._tcp.local", rtype::SRV));
    assert!(!knows(&device, "tv.local", rtype::AAAA), "it has not said");
    assert!(!knows(&device, "printer.local", rtype::A));
    device.nsec = Some(vec![rtype::A].into());
    assert!(knows(&device, "tv.local", rtype::AAAA), "it said it has none");
}

/// The names a device is indexed by are those its announcement has records
/// under, no more and no fewer: a device is asked about nothing else.
#[test]
fn a_device_has_the_names_of_the_records_it_announces() {
    use std::collections::BTreeSet;
    let lower = |names: &mut BTreeSet<String>, name: &str| {
        names.insert(name.to_ascii_lowercase());
    };
    let mut device = tv("10.0.1.9", &["TV", "Other"]);
    device.add_addrs(&[ip("fd00::9")]);
    device.reverse = vec![ip("10.0.1.9"), ip("fd00::9")].into();
    device.services[0].edit(|p| p.subtypes = vec!["_printer._sub._http._tcp.local".into()]);
    device.nsec = Some(vec![rtype::A].into());
    device.services[1].edit(|p| p.kind = "_Other._tcp.local".into());
    for device in [device.clone(), Device { services: Box::default(), ..device.clone() }, Device { hostname: None, ..device }] {
        let (mut own, mut announced) = (BTreeSet::new(), BTreeSet::new());
        device.for_each_name(&Advertise::ALL, |name| lower(&mut own, name));
        if device.hostname.is_some() {
            for rec in device.announcement(&Advertise::ALL, 120, 120) {
                lower(&mut announced, &rec.name);
            }
        }
        assert_eq!(own, announced);
        assert!(own.iter().all(|name| device.has_name(&Advertise::ALL, &name.to_ascii_uppercase())));
        assert!(!device.has_name(&Advertise::ALL, "nothing.local"));
    }
}

#[test]
fn forwarded_queries_ask_each_question_once_for_a_multicast_answer() {
    let ask = |name: &str, qtype: u16, unicast_response: bool| Question { name: name.into(), qtype, class: 255, unicast_response };
    let questions = [ask("printer.local", rtype::A, true), ask("Printer.local", rtype::A, false), ask("_ipp._tcp.local", rtype::PTR, false)];
    let none = |_: &Question| Vec::new();
    let queries = Device::forward_queries(&questions, none, DEFAULT_MAX_PACKET);
    assert_eq!(asked(&queries), [q("printer.local", rtype::A), q("_ipp._tcp.local", rtype::PTR)]);
    assert!(queries.iter().flat_map(|m| &m.questions).all(|q| !q.unicast_response && q.class == 1));
    assert!(queries.iter().all(|m| m.answers.is_empty()));
    assert!(Device::forward_queries(&[], none, DEFAULT_MAX_PACKET).is_empty());

    // A name that cannot be encoded again (a label past 63 bytes) is
    // skipped, not the whole query failed.
    let long = format!("{}.local", "x".repeat(64));
    let queries = Device::forward_queries(&[ask(&long, rtype::A, false), ask("ok.local", rtype::A, false)], none, DEFAULT_MAX_PACKET);
    assert_eq!(asked(&queries), [q("ok.local", rtype::A)]);
}

/// The records a device has for a question, as known answers: not the
/// additional ones an answer brings, nor the NSEC saying it has none.
#[test]
fn records_for_a_question_are_only_the_records_it_has() {
    let ask = |name: &str, qtype: u16| Question { name: name.into(), qtype, class: 1, unicast_response: false };
    let mut device = tv("10.0.1.9", &["TV"]);
    device.nsec = Some(vec![rtype::A].into());
    let records = device.records_for(&Advertise::ALL, &ask("_http._tcp.local", rtype::PTR), 120, 4500);
    let kinds: Vec<u16> = records.iter().map(Record::rtype).collect();
    assert_eq!(kinds, [rtype::PTR]);
    assert!(device.knows(&Advertise::ALL, &ask("tv.local", rtype::AAAA)), "its NSEC says it has none");
    assert!(device.records_for(&Advertise::ALL, &ask("tv.local", rtype::AAAA), 120, 4500).is_empty());
}

/// The known answers to each question go along with it, once each, and
/// only as many as fit in a frame: the rest of the devices just answer.
#[test]
fn forwarded_queries_carry_what_fits_of_the_known_answers() {
    let browse = |name: &str| Question { name: name.into(), qtype: rtype::PTR, class: 1, unicast_response: false };
    let ptr = |kind: &str, i: usize| Record {
        name: kind.into(),
        class: 1,
        cache_flush: false,
        ttl: 4500,
        data: RData::Ptr(format!("Device {i}.{kind}")),
    };
    let known = |q: &Question| (0..3).map(|i| ptr(&q.name, i)).collect::<Vec<_>>();
    let questions = [browse("_http._tcp.local"), browse("_ipp._tcp.local"), browse("_http._tcp.local")];
    let queries = Device::forward_queries(&questions, known, DEFAULT_MAX_PACKET);
    assert_eq!(queries.len(), 1);
    let mut expected = known(&questions[0]);
    expected.extend(known(&questions[1]));
    assert_eq!(queries[0].answers, expected);

    let many = |q: &Question| (0..200).map(|i| ptr(&q.name, i)).collect::<Vec<_>>();
    let queries = Device::forward_queries(&questions[..1], many, DEFAULT_MAX_PACKET);
    let size = queries[0].encode().unwrap().len();
    assert!(size <= DEFAULT_MAX_PACKET && size > DEFAULT_MAX_PACKET - 100, "{size}");
    assert!(queries[0].answers.len() < 200 && !queries[0].answers.is_empty());
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

/// A device on a network with a global and a ULA prefix has an address
/// of each, and more: all are kept.
#[test]
fn a_device_keeps_every_address_it_announces() {
    let device = heard(vec![
        aaaa("tv.local", "fd00::7"),
        aaaa("tv.local", "fe80::7"),
        aaaa("tv.local", "2001:db8::7"),
        a_record("tv.local", "10.0.1.7"),
    ]);
    assert_eq!(device.addrs().collect::<Vec<_>>(), [ip("10.0.1.7"), ip("2001:db8::7"), ip("fd00::7"), ip("fe80::7")]);
    let sent: Vec<RData> = device.announcement(&Advertise::ALL, 120, 4500).into_iter().filter(|r| r.name == "tv.local").map(|r| r.data).collect();
    assert_eq!(sent.len(), 4, "{sent:?}");
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

/// Asked for one family's address, a device answers with the other's too
/// (RFC 6762 section 6.2): a client asking over IPv4 learns of IPv6.
#[test]
fn an_address_answer_brings_the_other_familys() {
    let mut device = tv("10.0.1.9", &["TV"]);
    device.add_addrs(&[ip("fd00::9")]);
    for (asked, other) in [(rtype::A, RData::Aaaa("fd00::9".parse().unwrap())), (rtype::AAAA, RData::A("10.0.1.9".parse().unwrap()))] {
        let (answers, extra) = device.answers(&Advertise::ALL, &query("tv.local", asked), 120, 4500);
        assert_eq!(answers.len(), 1);
        assert!(extra.iter().any(|r| r.data == other), "{other:?} in {extra:?}");
    }
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

#[test]
fn subtypes_are_announced_answered_and_withdrawn() {
    let name = "_printer._sub._http._tcp.local";
    let mut printer = tv("10.0.1.9", &["Office"]);
    printer.services[0].edit(|p| p.subtypes = vec![name.into()]);
    let subtype = |records: &[Record]| records.iter().find(|r| r.name == name).cloned();

    let r = subtype(&printer.announcement(&Advertise::ALL, 120, 4500)).expect("announced");
    assert_eq!((r.data, r.cache_flush), (RData::Ptr("Office._http._tcp.local".into()), false));

    // Browsing by the subtype finds it, with what it takes to resolve it.
    let (answers, extra) = printer.answers(&Advertise::ALL, &query(name, rtype::PTR), 120, 4500);
    assert_eq!(answers.len(), 1);
    assert!(subtype(&answers).is_some());
    assert!(extra.iter().any(|r| matches!(r.data, RData::Srv { .. })));
    assert!(extra.iter().any(|r| matches!(r.data, RData::A(_))));

    // No longer of the subtype: that alone is withdrawn.
    let mut plain = printer.clone();
    plain.services[0].edit(|p| p.subtypes.clear());
    let records = printer.replacement(&Advertise::ALL, (&plain).into(), 120, 4500);
    assert_eq!(subtype(&records).map(|r| r.ttl), Some(0));
    assert_eq!(records.iter().filter(|r| r.ttl == 0).count(), 1);
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

#[test]
fn a_reflected_device_denies_only_what_it_denied_itself() {
    let mut v4_only = tv("10.0.1.9", &["TV"]);
    v4_only.nsec = Some(vec![rtype::A].into());
    let nsec_of = |records: &[Record]| records.iter().find(|r| matches!(r.data, RData::Nsec { .. })).cloned();
    let r = nsec_of(&v4_only.announcement(&Advertise::ALL, 120, 4500)).expect("announced");
    assert_eq!((r.name.as_str(), r.cache_flush, r.ttl), ("tv.local", true, 120));
    assert_eq!(r.data, RData::Nsec { next: "tv.local".into(), types: vec![rtype::A] });

    // Asked for an address it has not got, it says so...
    let (answers, _) = v4_only.answers(&Advertise::ALL, &query("tv.local", rtype::AAAA), 120, 4500);
    assert_eq!(answers.len(), 1);
    assert!(nsec_of(&answers).is_some());

    // ...and its address comes with it.
    let (answers, extra) = v4_only.answers(&Advertise::ALL, &query("tv.local", rtype::A), 120, 4500);
    assert!(matches!(answers[..], [Record { data: RData::A(_), .. }]));
    assert!(nsec_of(&extra).is_some());

    // It is not among what the name has.
    let (answers, _) = v4_only.answers(&Advertise::ALL, &query("tv.local", rtype::ANY), 120, 4500);
    assert!(nsec_of(&answers).is_none());

    // What it announces is never denied, and NSEC itself is not listed.
    let mut said_less = v4_only.clone();
    said_less.nsec = Some(vec![rtype::AAAA, rtype::NSEC, 300].into());
    match said_less.nsec_record(&Advertise::ALL, 120).map(|r| r.data) {
        Some(RData::Nsec { types, .. }) => assert_eq!(types, [rtype::A, rtype::AAAA]),
        other => panic!("{other:?}"),
    }

    // A device that said nothing is denied nothing.
    let mut silent = v4_only;
    silent.nsec = None;
    assert!(silent.nsec_record(&Advertise::ALL, 120).is_none());
    assert!(silent.answers(&Advertise::ALL, &query("tv.local", rtype::AAAA), 120, 4500).0.is_empty());
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

#[test]
fn reverse_mappings_are_announced_answered_and_withdrawn() {
    let name = "9.1.0.10.in-addr.arpa";
    let mut mapped = tv("10.0.1.9", &["TV"]);
    mapped.reverse = vec![ip("10.0.1.9")].into();
    let of = |records: &[Record]| records.iter().find(|r| r.name == name).cloned();

    // Only for an address the device announced one for.
    assert!(of(&tv("10.0.1.9", &["TV"]).announcement(&Advertise::ALL, 120, 4500)).is_none());
    let r = of(&mapped.announcement(&Advertise::ALL, 120, 4500)).expect("announced");
    assert_eq!((r.data, r.cache_flush), (RData::Ptr("tv.local".into()), true));

    let (answers, _) = mapped.answers(&Advertise::ALL, &query(name, rtype::PTR), 120, 4500);
    assert_eq!(answers.len(), 1);
    assert!(of(&answers).is_some());

    // Moved: the old mapping is withdrawn along with the old address.
    let mut moved = tv("10.0.1.10", &["TV"]);
    moved.reverse = vec![ip("10.0.1.10")].into();
    let records = mapped.replacement(&Advertise::ALL, (&moved).into(), 120, 4500);
    assert_eq!(of(&records).map(|r| r.ttl), Some(0));
    assert!(records.iter().any(|r| r.name == "10.1.0.10.in-addr.arpa" && r.ttl > 0));
}
