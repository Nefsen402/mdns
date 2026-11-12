use std::cell::RefCell;
use std::net::UdpSocket;
use std::collections::VecDeque;
use std::net::Ipv4Addr;

use super::*;
use crate::device::EditService;
use crate::config::{DEFAULT_MAX_DEVICES, DEFAULT_MIN_LIFETIME};
use crate::device::{addr_of, edit, Origin, META_QUERY};
use std::collections::BTreeSet;
use crate::codec::RData;

/// `socket` as the segment takes a socket.
fn fd(socket: std::net::UdpSocket) -> rustix::fd::OwnedFd {
    use std::os::fd::IntoRawFd;
    // SAFETY: a descriptor just given up by its owner.
    unsafe { rustix::fd::FromRawFd::from_raw_fd(socket.into_raw_fd()) }
}
const FLOOR: Duration = Duration::from_secs(300);

/// A segment that keeps a device at least five minutes, as most of these
/// tests are of timings that go by a lifetime that long; the default keeps
/// a device for exactly its TTL.
fn segment(name: &str) -> Segment {
    let seg = Segment::new(name);
    seg.set_min_lifetime(FLOOR);
    seg
}

use crate::device::{record, LEGACY_TTL_CAP, QUESTIONS_PER_PACKET};
use crate::codec::{self, rtype, Header};
use crate::listener::{prefix, Link};

/// Its first routable IPv4 or IPv6 address, and link-local one.
fn v4(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv4())
}
fn v6(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv6())
}
fn ll4(d: &Device) -> Option<IpAddr> {
    d.addrs().find(|a| a.is_ipv4() && crate::device::is_link_local(a))
}
fn ll6(d: &Device) -> Option<IpAddr> {
    d.addrs().find(|a| a.is_ipv6() && crate::device::is_link_local(a))
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Which device has this hostname.
fn host_id(state: &State, host: &str) -> Id {
    state.tracker.discovered.find_host(host).expect("no such device")
}

fn sa(s: &str) -> SocketAddr {
    SocketAddr::new(ip(s), MDNS_PORT)
}

fn labels(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.push(p.len() as u8);
        out.extend(p.as_bytes());
    }
    out.push(0);
    out
}

fn rr(p: &mut Vec<u8>, name: &[&str], rtype: u16, ttl: u32, rdata: &[u8]) {
    p.extend(labels(name));
    p.extend(rtype.to_be_bytes());
    p.extend(1u16.to_be_bytes());
    p.extend(ttl.to_be_bytes());
    p.extend((rdata.len() as u16).to_be_bytes());
    p.extend(rdata);
}

fn response(records: usize) -> Vec<u8> {
    let mut p = Vec::new();
    for v in [0, 0x8400, 0, records as u16, 0, 0] {
        p.extend(u16::to_be_bytes(v));
    }
    p
}

/// "Printer._http._tcp.local" on host "printer.local" at 10.0.1.7.
fn announcement(ttl: u32) -> Vec<u8> {
    let mut p = response(4);
    let mut ptr = vec![7];
    ptr.extend(b"Printer");
    ptr.extend(labels(&["_http", "_tcp", "local"]));
    rr(&mut p, &["_http", "_tcp", "local"], 12, ttl, &ptr);

    let mut srv = vec![0, 0, 0, 0, 0x02, 0x77];
    srv.extend(labels(&["printer", "local"]));
    rr(&mut p, &["Printer", "_http", "_tcp", "local"], 33, ttl, &srv);
    rr(&mut p, &["Printer", "_http", "_tcp", "local"], 16, ttl, b"\x05ty=hp");
    rr(&mut p, &["printer", "local"], 1, ttl, &[10, 0, 1, 7]);
    p
}

/// A device heard only by address, as `observe` records it.
fn unnamed(addr: &str) -> Device {
    let mut device = Device::default();
    device.add_addrs(&[ip(addr)]);
    device
}

#[test]
fn observe_adds_once_and_notifies() {
    let seg = segment("test");
    let rx = seg.subscribe();
    seg.observe(ip("10.0.1.5"));
    seg.observe(ip("10.0.1.5"));
    assert_eq!(seg.devices().len(), 1);
    assert_eq!(rx.try_recv(), Ok(Event::Added(unnamed("10.0.1.5").into())));
    assert!(rx.try_recv().is_err());
}

#[test]
fn expire_removes_and_notifies() {
    let seg = segment("test");
    seg.observe(ip("10.0.1.5"));
    let rx = seg.subscribe();
    seg.expire(Instant::now());
    assert_eq!(seg.devices().len(), 1);
    seg.expire(Instant::now() + FLOOR + Duration::from_secs(1));
    assert!(seg.devices().is_empty());
    assert_eq!(rx.try_recv(), Ok(Event::Removed(unnamed("10.0.1.5").into())));
}

/// A v4 segment whose "multicast group" is a local socket we can read.
fn wired() -> (Segment, UdpSocket) {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let seg = segment("test");
    seg.attach(Link::to(Family::V4, fd(tx), rx.local_addr().unwrap()));
    (seg, rx)
}

fn recv(rx: &UdpSocket) -> Option<Message> {
    let mut buf = [0u8; 9000];
    let (n, _) = rx.recv_from(&mut buf).ok()?;
    Some(Message::parse(&buf[..n]).unwrap())
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
                    target: None,
                    txt: vec![b"a=b".to_vec()],
                    ttl: 0,
                    ..ServiceParts::default()
                }
                .into()
            })
            .collect(),
        ttl: None,
        nsec: None,
        reverse: Box::default(),
        ..Device::default()
    };
    device.add_addrs(&[ip(addr)]);
    device
}

#[test]
fn reflected_list_is_separate() {
    let seg = segment("test");
    let rx = seg.subscribe();
    let device = Shared::new(tv("10.0.1.9", &["TV"]));
    assert!(seg.add_reflected(OWN, &device).unwrap());
    assert!(!seg.add_reflected(OWN, &device).unwrap(), "said again as it is");
    assert!(seg.devices().is_empty());
    assert!(rx.try_recv().is_err());
    assert_eq!(seg.reflected_devices().len(), 1);
    assert!(seg.remove_reflected(&seg.own(), &device).unwrap());
    assert!(!seg.remove_reflected(&seg.own(), &device).unwrap());
}

#[test]
fn add_announces_and_remove_says_goodbye() {
    let (seg, rx) = wired();
    let device = Shared::new(tv("10.0.1.9", &["TV"]));
    seg.add_reflected(OWN, &device).unwrap();

    let m = recv(&rx).expect("announcement");
    assert!(m.header.response && m.header.authoritative);
    let by_name = |n: &str| m.answers.iter().find(|r| r.name == n).unwrap();
    assert_eq!(by_name("tv.local").data, RData::A("10.0.1.9".parse().unwrap()));
    assert!(by_name("tv.local").cache_flush);
    assert_eq!(by_name("tv.local").ttl, HOST_TTL);
    assert_eq!(by_name("_http._tcp.local").data, RData::Ptr("TV._http._tcp.local".into()));
    assert!(!by_name("_http._tcp.local").cache_flush);
    assert_eq!(
        by_name("TV._http._tcp.local").ttl,
        OTHER_TTL,
    );
    assert_eq!(
        by_name("_services._dns-sd._udp.local").data,
        RData::Ptr("_http._tcp.local".into())
    );
    assert!(m.answers.iter().any(|r| matches!(
        &r.data,
        RData::Srv { port: 8080, target, .. } if target == "tv.local"
    )));
    assert!(m.answers.iter().any(|r| r.data == RData::Txt(vec![b"a=b".to_vec()])));

    // Saying it again as it is is a no-op on the wire.
    assert!(!seg.add_reflected(OWN, &device).unwrap());
    assert!(recv(&rx).is_none());

    seg.remove_reflected(&seg.own(), &device).unwrap();
    let bye = recv(&rx).expect("goodbye");
    assert_eq!(bye.answers.len(), m.answers.len());
    assert!(bye.answers.iter().all(|r| r.ttl == 0));
    assert!(seg.reflected_devices().is_empty());
}

#[test]
fn replacing_sends_goodbye_for_dropped_services() {
    let (seg, rx) = wired();
    let device = Shared::new(tv("10.0.1.9", &["A", "B"]));
    seg.add_reflected(OWN, &device).unwrap();
    recv(&rx).unwrap();

    *device.borrow_mut() = tv("10.0.1.9", &["A"]);
    seg.add_reflected(OWN, &device).unwrap();
    let m = recv(&rx).unwrap();
    let gone: Vec<_> = m.answers.iter().filter(|r| r.ttl == 0).collect();
    assert_eq!(gone.len(), 3); // PTR, SRV, TXT of "B"
    assert!(gone.iter().any(|r| r.data == RData::Ptr("B._http._tcp.local".into())));
    assert!(m.answers.iter().filter(|r| r.ttl != 0).count() >= 5);
}

#[test]
fn a_hostname_two_owners_want_goes_to_the_lower_and_passes_to_the_next() {
    let (seg, rx) = wired();
    let (first, second) = (FIRST, SECOND);
    let has = |m: &Message, data: RData, live: bool| m.answers.iter().any(|r| r.data == data && (r.ttl > 0) == live);
    let a = |s: &str| RData::A(s.parse().unwrap());
    let b_ptr = || RData::Ptr("B._http._tcp.local".into());

    let (high, low) = (Shared::new(tv("10.0.1.9", &["A", "B"])), Shared::new(tv("10.0.2.9", &["A"])));
    assert!(seg.add_reflected(second, &high).unwrap());
    recv(&rx).unwrap();

    // The lower priority takes over, and what it does not have is withdrawn.
    assert!(seg.add_reflected(first, &low).unwrap());
    let m = recv(&rx).unwrap();
    assert!(has(&m, a("10.0.2.9"), true) && has(&m, a("10.0.1.9"), false) && has(&m, b_ptr(), false));
    assert_eq!(seg.reflected_devices(), [tv("10.0.2.9", &["A"])]);

    // The outranked one changing is remembered, not sent.
    *high.borrow_mut() = tv("10.0.1.10", &["A", "B"]);
    assert!(!seg.add_reflected(second, &high).unwrap());
    assert!(recv(&rx).is_none());

    // When the winner goes, the next one is announced in its place.
    assert!(seg.remove_reflected(&seg.own(), &low).unwrap());
    let m = recv(&rx).unwrap();
    assert!(has(&m, a("10.0.1.10"), true) && has(&m, a("10.0.2.9"), false) && has(&m, b_ptr(), true));
    assert_eq!(seg.reflected_devices(), [tv("10.0.1.10", &["A", "B"])]);

    // What is not there removes nothing; the last one says goodbye.
    assert!(!seg.remove_reflected(&seg.own(), &low).unwrap());
    assert!(seg.remove_reflected(&seg.own(), &high).unwrap());
    assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 0));
    assert!(seg.reflected_devices().is_empty());
}

/// A device here offering a service of the same instance name as one of
/// a reflected device's: the copy leaves it out while that device is here.
#[test]
fn a_service_named_like_one_here_is_left_out_of_the_copy() {
    let (seg, rx) = wired();
    let kitchen = || {
        vec![
            a_record("nas.local", "10.0.1.20"),
            ptr("_http._tcp.local", "Kitchen._http._tcp.local"),
            srv("Kitchen._http._tcp.local", 80, "nas.local"),
        ]
    };
    let mentions_kitchen = |m: &Message| {
        m.answers.iter().any(|r| r.name.starts_with("Kitchen.") || r.data == RData::Ptr("Kitchen._http._tcp.local".into()))
    };
    hear(&seg, "10.0.1.20", kitchen());

    seg.add_reflected(FIRST, &Shared::new(tv("10.0.2.9", &["Kitchen", "Den"]))).unwrap();
    assert!(!mentions_kitchen(&recv(&rx).unwrap()));
    assert_eq!(seg.reflected_devices(), [tv("10.0.2.9", &["Den"])]);

    // Shown once the device here goes...
    seg.expire(Instant::now() + Duration::from_secs(36000));
    let m = recv(&rx).unwrap();
    assert!(m.answers.iter().any(|r| r.name == "Kitchen._http._tcp.local" && r.ttl > 0));
    assert_eq!(seg.reflected_devices(), [tv("10.0.2.9", &["Kitchen", "Den"])]);

    // ...and left out again, without a goodbye, when it is back: that
    // would take back its records too.
    hear(&seg, "10.0.1.20", kitchen());
    assert!(!mentions_kitchen(&recv(&rx).unwrap()));
    assert_eq!(seg.reflected_devices(), [tv("10.0.2.9", &["Den"])]);
}

/// A query with proposed records in its authority section is a device
/// probing for a name: a reflected copy does not answer it, the
/// advertised name does.
#[test]
fn a_device_probing_for_a_name_is_not_answered_with_a_copy() {
    let (seg, rx) = wired();
    let router = Device { hostname: Some("router.local".into()), addresses: vec![ip("10.0.1.1").into()].into(), ..Device::default() };
    seg.add_reflected(OWN, &Shared::new(router)).unwrap();
    seg.add_reflected(FIRST, &Shared::new(tv("10.0.2.9", &["TV"]))).unwrap();
    while recv(&rx).is_some() {}
    age(&seg, 2);
    let probe = |name: &str| {
        Message {
            header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
            questions: vec![codec::Question { name: name.into(), qtype: rtype::ANY, class: 1, unicast_response: false }],
            answers: vec![],
            authorities: vec![a_record(name, "10.0.1.5")],
            additionals: vec![],
        }
        .encode()
        .unwrap()
    };

    seg.handle(sa("10.0.1.5"), &probe("tv.local")).unwrap();
    assert!(recv(&rx).is_none());
    seg.handle(sa("10.0.1.5"), &probe("router.local")).unwrap();
    assert_eq!(recv(&rx).unwrap().answers[0].data, RData::A("10.0.1.1".parse().unwrap()));

    // An ordinary query is answered as ever.
    seg.handle(sa("10.0.1.50"), &query("tv.local", rtype::ANY, vec![])).unwrap();
    assert!(recv(&rx).is_some());

    // The name went out just now, answering the probe: within a second
    // of that a query waits, and another probe is answered all the same,
    // or the prober would take the name.
    seg.handle(sa("10.0.1.50"), &query("router.local", rtype::A, vec![])).unwrap();
    assert!(recv(&rx).is_none(), "multicast less than a second ago");
    seg.handle(sa("10.0.1.5"), &probe("router.local")).unwrap();
    assert_eq!(recv(&rx).expect("defended").answers[0].data, RData::A("10.0.1.1".parse().unwrap()));
}

/// A question is passed on for the reflector to ask elsewhere, marked
/// with whether something announced here answers it; one that a device
/// here owns the name of, or that a device asks while probing, is not.
#[test]
fn a_question_is_passed_on_marked_with_whether_it_is_answered_here() {
    let (seg, rx) = wired();
    let events = seg.subscribe();
    let mut copy = tv("10.0.2.9", &["TV"]);
    copy.nsec = Some(vec![rtype::A].into());
    seg.add_reflected(FIRST, &Shared::new(copy)).unwrap();
    recv(&rx).unwrap();
    hear(&seg, "10.0.1.20", vec![
        a_record("nas.local", "10.0.1.20"),
        srv("Files._smb._tcp.local", 445, "nas.local"),
    ]);
    let client = sa("10.0.1.50");

    seg.handle(client, &asking(&[question("printer.local", rtype::A)], vec![])).unwrap();
    assert_eq!(passed_on(&events), [vec![passed("printer.local", rtype::A, false)]]);

    // The copy's address, and even what its NSEC says it has not got,
    // are answered here; the browse for a type it has not got is not.
    let mixed = [question("tv.local", rtype::A), question("tv.local", rtype::AAAA), question("_ipp._tcp.local", rtype::PTR)];
    seg.handle(client, &asking(&mixed, vec![])).unwrap();
    assert_eq!(passed_on(&events), [vec![
        passed("tv.local", rtype::A, true),
        passed("tv.local", rtype::AAAA, true),
        passed("_ipp._tcp.local", rtype::PTR, false),
    ]]);

    // A copy that may not answer again just yet still knows the answer.
    seg.handle(client, &asking(&[question("tv.local", rtype::A)], vec![])).unwrap();
    assert_eq!(passed_on(&events), [vec![passed("tv.local", rtype::A, true)]]);

    // Names a device here owns, it answers for itself, whatever the case.
    let owned = [question("NAS.local", rtype::A), question("files._smb._tcp.local", rtype::TXT)];
    seg.handle(client, &asking(&owned, vec![])).unwrap();
    assert!(passed_on(&events).is_empty());

    // A probe is the prober's own business, and a response asks nothing.
    seg.handle(client, &asking(&[question("printer.local", rtype::ANY)], vec![a_record("printer.local", "10.0.1.50")])).unwrap();
    hear(&seg, "10.0.1.20", vec![a_record("nas.local", "10.0.1.20")]);
    assert!(passed_on(&events).is_empty());
}

#[test]
fn a_question_from_elsewhere_is_asked_once_a_second_without_the_askers_wishes() {
    let (seg, rx) = wired();
    let wants_unicast = Question { unicast_response: true, ..question("printer.local", rtype::A) };
    let questions = [wants_unicast, question("_ipp._tcp.local", rtype::PTR)];

    assert_eq!(seg.query_question(&questions).unwrap(), 2);
    let m = recv(&rx).unwrap();
    assert_eq!(asked(&m), BTreeSet::from([q("printer.local", rtype::A), q("_ipp._tcp.local", rtype::PTR)]));
    assert!(m.answers.is_empty() && m.authorities.is_empty());

    // Again right away, in another case: not asked again.
    assert_eq!(seg.query_question(&[question("PRINTER.local", rtype::A)]).unwrap(), 0);
    assert!(recv(&rx).is_none());

    // A second on, it is.
    for at in seg.state.borrow_mut().forwarded.values_mut() {
        *at -= FORWARD_GAP;
    }
    assert_eq!(seg.query_question(&questions[..1]).unwrap(), 1);
    recv(&rx).unwrap();

    // However many made-up names are asked, only so many are waited out.
    let flood: Vec<Question> = (0..MAX_FORWARDED + 10).map(|i| question(&format!("x{i}.local"), rtype::A)).collect();
    assert_eq!(seg.query_question(&flood).unwrap(), MAX_FORWARDED - 1);
    assert!(seg.state.borrow_mut().forwarded.len() <= MAX_FORWARDED);
    while recv(&rx).is_some() {}

    // Without a sender, nothing.
    assert_eq!(segment("quiet").query_question(&questions).unwrap(), 0);
}

/// A question asked on another's behalf carries what is known here of
/// the answer, each record with the time it has left: an address by its
/// own, a service by the device's. One with none left is not known.
#[test]
fn a_question_from_elsewhere_carries_the_known_answers_with_their_time_left() {
    let (seg, rx) = wired();
    hear(&seg, "10.0.1.7", vec![a_record("tv.local", "10.0.1.7"), srv("TV._http._tcp.local", 80, "tv.local")]);
    hear(&seg, "10.0.1.8", vec![a_record("nas.local", "10.0.1.8"), srv("NAS._http._tcp.local", 80, "nas.local")]);
    // Known only by its address, and by a bare browse answer: no records
    // of its own to give.
    seg.observe(ip("10.0.1.9"));
    hear(&seg, "10.0.1.10", vec![ptr("_http._tcp.local", "Bare._http._tcp.local")]);
    let now = Instant::now();
    {
        let mut state = seg.state.borrow_mut();
        let (tv, nas) = (host_id(&state, "tv.local"), host_id(&state, "nas.local"));
        state.tracker.discovered.edit(tv, |tv| {
            tv.addr_expires.insert(ip("10.0.1.7"), now + Duration::from_secs(50));
            tv.expires = now + Duration::from_secs(70);
        });
        state.tracker.discovered.edit(nas, |nas| nas.expires = now);
    }

    let questions = [question("_http._tcp.local", rtype::PTR), question("tv.local", rtype::A)];
    assert_eq!(seg.query_question(&questions).unwrap(), 2);
    let m = recv(&rx).unwrap();
    let known: Vec<(&RData, u32)> = m.answers.iter().map(|r| (&r.data, r.ttl)).collect();
    assert_eq!(known.len(), 2, "{known:?}");
    let ttl_of = |data: &RData| known.iter().find(|(d, _)| *d == data).map(|&(_, ttl)| ttl);
    assert!(ttl_of(&RData::Ptr("TV._http._tcp.local".into())).is_some_and(|t| (69..=70).contains(&t)), "{known:?}");
    assert!(ttl_of(&RData::A("10.0.1.7".parse().unwrap())).is_some_and(|t| (49..=50).contains(&t)), "{known:?}");
}

/// Types asked for by name are asked for in each round, with what is
/// known of them, and from then on in every probe; what is not a type is
/// asked for but not remembered.
#[test]
fn types_asked_for_by_name_are_asked_with_what_is_known_and_remembered() {
    let (seg, rx) = wired();
    hear(&seg, "10.0.1.5", vec![a_record("plug.local", "10.0.1.5"), srv("Plug._shelly._tcp.local", 80, "plug.local")]);
    let kinds = ["_shelly._tcp.local".to_string(), "_Hue._tcp.local".to_string(), "bogus".to_string()];

    assert_eq!(run_probe(&seg, Some(&kinds)).0, Ok(9));
    for _ in 0..3 {
        let m = recv(&rx).unwrap();
        let questions: Vec<(String, u16)> = m.questions.iter().map(|q| (q.name.clone(), q.qtype)).collect();
        assert_eq!(questions, [q("_shelly._tcp.local", rtype::PTR), q("_Hue._tcp.local", rtype::PTR), q("bogus", rtype::PTR)]);
        assert_eq!(m.answers.len(), 1, "{:?}", m.answers);
        assert_eq!(m.answers[0].data, RData::Ptr("Plug._shelly._tcp.local".into()));
    }
    assert!(recv(&rx).is_none());
    let types = seg.state.borrow_mut().tracker.types.clone();
    assert!(types.contains("_hue._tcp.local") && types.contains("_shelly._tcp.local") && !types.contains("bogus"));

    seg.probe_round().unwrap();
    let probed: Vec<String> = std::iter::from_fn(|| recv(&rx)).flat_map(|m| m.questions).map(|q| q.name).collect();
    assert!(probed.iter().any(|n| n == "_hue._tcp.local"), "{probed:?}");

    // Without a sender, nothing.
    assert_eq!(run_probe(&segment("quiet"), Some(&kinds)).0, Ok(0));
}

/// A way to send over IPv4 that always fails: its group is an IPv6
/// address, which an IPv4 socket refuses at once.
fn broken() -> (UdpSocket, SocketAddr) {
    (UdpSocket::bind("127.0.0.1:0").unwrap(), "[::1]:5353".parse().unwrap())
}

/// Give `seg` a working way to send again, to `rx`.
fn repair(seg: &Segment, rx: &UdpSocket) {
    seg.attach(Link::to(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap()));
}

fn retry_of(seg: &Segment, host: &str) -> Option<Instant> {
    seg.state.borrow_mut().hosts[host].retry
}

/// A device that cannot be announced is not recorded, so that it is
/// offered again and announced once sending works; one that cannot be
/// replaced stays as it was announced.
#[test]
fn a_device_that_cannot_be_announced_is_not_recorded() {
    let (seg, rx) = wired();
    let (socket, dest) = broken();
    seg.attach(Link::to(Family::V4, fd(socket), dest));
    let device = Shared::new(tv("10.0.2.9", &["TV"]));
    let err = seg.add_reflected(FIRST, &device).unwrap_err();
    assert!(format!("{err:#}").contains("sending to [::1]:5353"), "{err:#}");
    assert!(seg.reflected_devices().is_empty());
    assert!(seg.state.borrow_mut().hosts.is_empty(), "nothing left behind");

    repair(&seg, &rx);
    assert!(seg.add_reflected(FIRST, &device).unwrap());
    recv(&rx).unwrap();

    let (socket, dest) = broken();
    seg.attach(Link::to(Family::V4, fd(socket), dest));
    *device.borrow_mut() = tv("10.0.2.9", &["TV", "Cast"]);
    assert!(seg.add_reflected(FIRST, &device).is_err());
    let shown: Vec<String> = seg.reflected_devices()[0].services.iter().map(|s| s.instance().to_string()).collect();
    assert_eq!(shown, ["TV._http._tcp.local"], "still what was announced");
    // And it is what is recorded: saying it as it was again changes nothing.
    *device.borrow_mut() = tv("10.0.2.9", &["TV"]);
    assert!(!seg.add_reflected(FIRST, &device).unwrap());
}

/// A device whose goodbye cannot be sent is kept, so that withdrawing it
/// is tried again, and goes out once sending works.
#[test]
fn a_device_that_cannot_be_withdrawn_is_kept() {
    let (seg, rx) = wired();
    let device = Shared::new(tv("10.0.2.9", &["TV"]));
    seg.add_reflected(FIRST, &device).unwrap();
    recv(&rx).unwrap();

    let (socket, dest) = broken();
    seg.attach(Link::to(Family::V4, fd(socket), dest));
    assert!(seg.remove_reflected(&seg.own(), &device).is_err());
    assert_eq!(seg.reflected_devices().len(), 1, "kept");

    repair(&seg, &rx);
    assert!(seg.remove_reflected(&seg.own(), &device).unwrap());
    let goodbye = recv(&rx).unwrap();
    assert!(!goodbye.answers.is_empty() && goodbye.answers.iter().all(|r| r.ttl == 0));
    assert!(seg.reflected_devices().is_empty());
}

/// An announcement that fails is tried again after [`ANNOUNCE_RETRY`],
/// and again after that while it still fails; once it goes out, the
/// device is back on its usual schedule.
#[test]
fn an_announcement_that_fails_is_tried_again() {
    let (seg, rx) = wired();
    seg.add_reflected(FIRST, &Shared::new(tv("10.0.2.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();

    let (socket, dest) = broken();
    seg.attach(Link::to(Family::V4, fd(socket), dest));
    let before = Instant::now();
    assert!(seg.announce_all().is_err());
    let retry = retry_of(&seg, "tv.local").expect("to be tried again");
    assert!(retry >= before + ANNOUNCE_RETRY && retry <= Instant::now() + ANNOUNCE_RETRY);

    // Not before then.
    seg.reannounce(before).unwrap();
    assert_eq!(retry_of(&seg, "tv.local"), Some(retry));
    // Then, still failing: put off again.
    assert!(seg.reannounce(retry).is_err());
    let again = retry_of(&seg, "tv.local").expect("to be tried again");
    assert_eq!(again, retry + ANNOUNCE_RETRY);

    repair(&seg, &rx);
    seg.reannounce(again).unwrap();
    let announced = recv(&rx).expect("announced once it can be");
    assert!(announced.answers.iter().any(|r| r.data == RData::A("10.0.2.9".parse().unwrap()) && r.ttl > 0));
    assert_eq!(retry_of(&seg, "tv.local"), None, "on its usual schedule again");
}

/// A copy that has to give way to a device here, but whose goodbye
/// cannot be sent, stays shown and is tried again; once sending works the
/// goodbye goes out and the copy is no longer shown.
#[test]
fn a_copy_that_cannot_give_way_is_withdrawn_once_it_can() {
    let (seg, rx) = wired();
    seg.add_reflected(FIRST, &Shared::new(tv("10.0.2.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();

    let (socket, dest) = broken();
    seg.attach(Link::to(Family::V4, fd(socket), dest));
    hear(&seg, "10.0.1.50", vec![a_record("tv.local", "10.0.1.50"), srv("Den._http._tcp.local", 80, "tv.local")]);
    let retry = retry_of(&seg, "tv.local").expect("to be tried again");
    assert_eq!(seg.reflected_devices().len(), 1, "still shown: the goodbye did not go out");

    repair(&seg, &rx);
    seg.reannounce(retry).unwrap();
    let goodbye = recv(&rx).unwrap();
    assert!(goodbye.answers.iter().any(|r| r.data == RData::A("10.0.2.9".parse().unwrap()) && r.ttl == 0));
    assert!(seg.reflected_devices().is_empty(), "given way");
    assert_eq!(retry_of(&seg, "tv.local"), None);
}

/// Every family is tried, whichever fails: the announcement goes out over
/// the one that works, and the failure of the other is reported.
#[test]
fn every_family_is_tried_when_one_fails() {
    // The one that fails comes first, so the other is only tried if
    // sending goes on past a failure.
    let (_, rx) = wired();
    let seg = segment("test");
    let (socket, dest) = broken();
    seg.attach(Link::to(Family::V4, fd(socket), dest).and(Family::V6, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap()));
    let err = seg.add_reflected(FIRST, &Shared::new(tv("10.0.2.9", &["TV"]))).unwrap_err();
    assert!(format!("{err:#}").contains("[::1]:5353"), "{err:#}");
    let sent = recv(&rx).expect("sent over the other family all the same");
    assert!(sent.answers.iter().any(|r| r.data == RData::A("10.0.2.9".parse().unwrap())));
}

/// A packet may hold what the MTU leaves once the IPv6 and UDP headers
/// are added, but never less than plain DNS takes, nor more than mDNS
/// allows.
#[test]
fn the_mtu_sets_what_a_packet_may_hold() {
    let seg = segment("test");
    assert_eq!(seg.state.borrow_mut().max_packet, DEFAULT_MAX_PACKET, "a standard frame until told");
    assert_eq!(seg.set_mtu(1500), 1452);
    assert_eq!(seg.set_mtu(1492), 1444, "PPPoE");
    assert_eq!(seg.set_mtu(9000), 8952, "jumbo frames");
    assert_eq!(seg.set_mtu(65536), 9000, "loopback: mDNS's own limit");
    assert_eq!(seg.set_mtu(300), 512);
    assert_eq!(seg.set_mtu(0), 512);
    assert_eq!(seg.state.borrow_mut().max_packet, 512);
}

/// An announcement bigger than the interface allows goes out in packets
/// that each fit, together all of it.
#[test]
fn an_announcement_too_big_for_the_mtu_goes_in_packets_that_fit() {
    let (seg, rx) = wired();
    let max_packet = seg.set_mtu(576);
    let instances: Vec<String> = (0..20).map(|i| format!("Service {i}")).collect();
    let names: Vec<&str> = instances.iter().map(String::as_str).collect();
    let mut device = tv("10.0.2.9", &names);
    for svc in &mut device.services {
        svc.edit(|p| p.txt = vec![format!("k={}", "v".repeat(60)).into_bytes()]);
    }
    let expected = device.announcement(&Advertise::ALL, HOST_TTL, OTHER_TTL).len();
    seg.add_reflected_ttl(FIRST, &Shared::new(device), Duration::from_secs(HOST_TTL.into())).unwrap();

    let mut buf = [0u8; 9000];
    let mut records = 0;
    let mut packets = 0;
    while let Ok(n) = rx.recv(&mut buf) {
        assert!(n <= max_packet, "a packet of {n} bytes, over {max_packet}");
        records += Message::parse(&buf[..n]).unwrap().answers.len();
        packets += 1;
    }
    assert!(packets > 1, "{packets}");
    assert_eq!(records, expected, "all of it, once");
}

/// Whatever the segment sends, it keeps within its interface's MTU:
/// replies, probes, refreshes and questions asked on another's behalf.
#[test]
fn everything_sent_keeps_within_the_mtu() {
    let (seg, rx) = wired();
    let max_packet = seg.set_mtu(576);
    let packets = || {
        let mut buf = [0u8; 9000];
        let mut sizes = Vec::new();
        while let Ok(n) = rx.recv(&mut buf) {
            sizes.push(n);
        }
        sizes
    };
    let within = |what: &str, sizes: Vec<usize>| {
        assert!(sizes.len() > 1, "{what}: {sizes:?}");
        assert!(sizes.iter().all(|&n| n <= max_packet), "{what}: {sizes:?}");
    };
    // Twenty devices of one type, heard here, with names long enough to
    // need several packets for anything about all of them.
    for i in 0..20 {
        let host = format!("a-device-with-a-rather-long-name-{i}.local");
        let addr = format!("10.0.1.{}", i + 1);
        hear(&seg, &addr, vec![
            a_record(&host, &addr),
            srv(&format!("A service with a long name {i}._http._tcp.local"), 80, &host),
        ]);
    }
    // Copies of as many, to answer for.
    for i in 0..20 {
        let mut copy = tv(&format!("10.0.2.{}", i + 1), &[&format!("A copied service with a long name {i}")]);
        copy.hostname = Some(format!("a-copy-with-a-rather-long-name-{i}.local"));
        seg.add_reflected(FIRST, &Shared::new(copy)).unwrap();
    }
    packets();
    age(&seg, 2);

    seg.handle(sa("10.0.1.200"), &query("_http._tcp.local", rtype::PTR, vec![])).unwrap();
    within("a reply", packets());
    // Types with long names, so that size, not the count, splits a probe.
    seg.state.borrow_mut().tracker.types.extend((0..20).map(|i| format!("_{}{i}._tcp.local", "t".repeat(40))));
    seg.probe_round().unwrap();
    within("a probe", packets());
    // Every device due: a margin longer than any lifetime.
    seg.refresh(Instant::now() + FLOOR * 3 / 4 + Duration::from_secs(1), Duration::from_secs(1_000_000)).unwrap();
    within("a refresh", packets());
    let questions: Vec<Question> = (0..16).map(|i| question(&format!("{}{i}._http._tcp.local", "q".repeat(50)), rtype::SRV)).collect();
    seg.query_question(&questions).unwrap();
    within("questions asked on another's behalf", packets());
    seg.query_question(&[question("_http._tcp.local", rtype::PTR)]).unwrap();
    let known = packets();
    assert!(known.len() == 1 && known[0] <= max_packet, "known answers left out to fit: {known:?}");
}

/// A device without an IPv4 address sends IPv4 from 0.0.0.0: that is no
/// address to credit it with, nor one to know a device by.
#[test]
fn a_packet_from_an_unusable_address_vouches_for_none() {
    let seg = segment("test");
    hear(&seg, "0.0.0.0", vec![aaaa("tv.local", "fe80::9"), srv("TV._http._tcp.local", 80, "tv.local")]);
    let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).expect("still heard of");
    assert_eq!(tv.addrs().collect::<Vec<_>>(), [ip("fe80::9")]);
    assert_eq!(tv.services.len(), 1);

    // A mere query from it makes no device of it.
    seg.handle(sa("0.0.0.0"), &query("tv.local", rtype::A, vec![])).unwrap();
    assert_eq!(seg.devices().len(), 1);
    assert!(!seg.state.borrow_mut().tracker.discovered.holder_of(&ip("0.0.0.0")).is_some());
}

const MAC: [u8; 6] = [0x04, 0x09, 0x86, 0x43, 0xe3, 0xf6];

/// A device that announced only a link-local IPv6 address is given the
/// routable ones the neighbour table lists under its link-layer address,
/// whichever comes first, and loses them with their entries.
#[test]
fn a_device_is_given_the_addresses_the_neighbour_table_has_for_it() {
    let seg = segment("test");
    let events = seg.subscribe();
    let learned = |seg: &Segment| -> Vec<IpAddr> {
        let d = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        d.addresses.iter().filter(|a| a.origin == Origin::Neighbour).map(|a| a.ip).collect()
    };
    seg.set_prefixes(vec![prefix("10.0.2.0/24"), prefix("fd00:0:2::/64"), prefix("2001:db8:2::/64")]);
    // The table first: the router has talked to it.
    seg.neighbour(ip("fd00:0:2::73"), Some(MAC.to_vec()));
    seg.neighbour(ip("fe80::609:86ff:fe43:e3f6"), Some(MAC.to_vec()));
    seg.neighbour(ip("fd00:0:2::99"), Some(vec![1, 2, 3, 4, 5, 6])); // someone else
    hear(&seg, "10.0.2.73", vec![
        a_record("speakers.local", "10.0.2.73"),
        aaaa("speakers.local", "fe80::609:86ff:fe43:e3f6"),
        srv("Speakers._airplay._tcp.local", 7000, "speakers.local"),
    ]);
    assert_eq!(learned(&seg), [ip("fd00:0:2::73")]);
    events.try_iter().count();

    // Then more of it: added, and told.
    seg.neighbour(ip("2001:db8:2::73"), Some(MAC.to_vec()));
    assert_eq!(learned(&seg), [ip("2001:db8:2::73"), ip("fd00:0:2::73")]);
    assert!(matches!(events.try_recv(), Ok(Event::Updated(d)) if d.borrow().has_addr(&ip("2001:db8:2::73"))));
    // A packet from a learned address is the device's.
    let state = seg.state.borrow();
    let holder = state.tracker.discovered.holder_of(&ip("2001:db8:2::73")).map(|id| state.tracker.discovered.get(id).device.borrow().hostname.clone());
    assert_eq!(holder, Some(Some("speakers.local".to_string())));
    drop(state);

    // An entry that goes takes its address with it.
    seg.neighbour(ip("2001:db8:2::73"), None);
    assert_eq!(learned(&seg), [ip("fd00:0:2::73")]);
    assert!(!seg.state.borrow_mut().tracker.discovered.holder_of(&ip("2001:db8:2::73")).is_some());
    assert!(matches!(events.try_recv(), Ok(Event::Updated { .. })));
    // The same entry again changes nothing, and says nothing.
    seg.neighbour(ip("fd00:0:2::73"), Some(MAC.to_vec()));
    assert!(events.try_recv().is_err());
}

/// A device that announced only IPv4 is found in the table by that, and
/// given its IPv6 addresses: which of them are reflected is for each
/// segment to say.
#[test]
fn a_device_is_found_in_the_neighbour_table_by_any_address_it_announced() {
    let seg = segment("test");
    seg.set_prefixes(vec![prefix("10.0.1.0/24"), prefix("fd00::/64")]);
    seg.neighbour(ip("10.0.1.9"), Some(MAC.to_vec()));
    seg.neighbour(ip("fd00::9"), Some(MAC.to_vec()));
    hear(&seg, "10.0.1.9", vec![a_record("printer.local", "10.0.1.9"), srv("Printer._ipp._tcp.local", 631, "printer.local")]);
    let printer = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
    assert_eq!(printer.addrs().collect::<Vec<_>>(), [ip("10.0.1.9"), ip("fd00::9")]);
    assert_eq!(printer.addresses[1].origin, Origin::Neighbour);
}

/// Only addresses in a network the interface is on are learned: an entry
/// left from an old prefix is not, and a device follows the interface's
/// networks as they change.
/// A router that answers for devices behind it, with the service records
/// of one of them and no address, says nothing of itself by it: the
/// address it sends from is not the device's, nor is what it says of its
/// own, in the same packet, the device's.
#[test]
fn a_device_known_at_the_address_is_not_taken_for_the_sender_of_a_packet_about_another() {
    let seg = segment("test");
    // The router, heard of by what it announces.
    hear(&seg, "10.0.0.1", vec![a_record("router.local", "10.0.0.1"), ptr("_ssh._tcp.local", "router._ssh._tcp.local"), srv("router._ssh._tcp.local", 22, "router.local")]);
    // Then, from it, the browse answer: one device's services, and a service of its own, no addresses.
    hear(&seg, "10.0.0.1", vec![
        ptr("_raop._tcp.local", "Speakers._raop._tcp.local"),
        srv("Speakers._raop._tcp.local", 7000, "speakers.local"),
        ptr("_ssh._tcp.local", "router._ssh._tcp.local"),
    ]);
    let devices = seg.devices();
    let device = |host: &str| devices.iter().find(|d| d.hostname.as_deref() == Some(host)).unwrap_or_else(|| panic!("{host}: {devices:?}"));
    assert_eq!(device("speakers.local").addrs().collect::<Vec<_>>(), Vec::<IpAddr>::new(), "no address of the router's");
    assert!(device("speakers.local").services.iter().all(|s| s.kind() == "_raop._tcp.local"), "{:?}", device("speakers.local").services);
    assert_eq!(device("router.local").addrs().collect::<Vec<_>>(), [ip("10.0.0.1")]);
    assert!(device("router.local").service("router._ssh._tcp.local").is_some_and(|s| s.is_resolved()));

    // Nor is any other device given the address it sent from, if it announced none.
    hear(&seg, "10.0.0.9", vec![ptr("_http._tcp.local", "Cam._http._tcp.local"), srv("Cam._http._tcp.local", 80, "cam.local")]);
    let devices = seg.devices();
    let cam = devices.iter().find(|d| d.hostname.as_deref() == Some("cam.local")).unwrap();
    assert_eq!(cam.addrs().collect::<Vec<_>>(), Vec::<IpAddr>::new());
}

/// What a router says of its own services, with no host to say whose they
/// are, is not the device's it was guessed to be the sender of: nothing is
/// added to a device by a guess.
#[test]
fn a_service_without_a_host_is_not_given_to_a_device_whose_address_was_guessed() {
    let seg = segment("test");
    hear(&seg, "10.0.0.1", vec![
        ptr("_raop._tcp.local", "Speakers._raop._tcp.local"),
        srv("Speakers._raop._tcp.local", 7000, "speakers.local"),
        ptr("_ssh._tcp.local", "router._ssh._tcp.local"),
    ]);
    let speakers = |seg: &Segment| seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("speakers.local")).unwrap();
    assert!(speakers(&seg).services.iter().all(|s| s.kind() == "_raop._tcp.local"), "{:?}", speakers(&seg).services);
    // Held where it was heard from, by address, until it says whose it is.
    let by_address = seg.devices().into_iter().find(|d| d.hostname.is_none() && d.service("router._ssh._tcp.local").is_some());
    assert!(by_address.is_some(), "{:?}", seg.devices());

    // The router says whose: its own, with its address.
    hear(&seg, "10.0.0.1", vec![a_record("router.local", "10.0.0.1"), srv("router._ssh._tcp.local", 22, "router.local")]);
    let devices = seg.devices();
    let router = devices.iter().find(|d| d.hostname.as_deref() == Some("router.local")).unwrap();
    assert!(router.service("router._ssh._tcp.local").is_some_and(|s| s.is_resolved()));
    assert!(speakers(&seg).services.iter().all(|s| s.kind() == "_raop._tcp.local"));
}

#[test]
fn only_neighbour_addresses_on_the_interfaces_networks_are_learned() {
    let seg = segment("test");
    let learned = |seg: &Segment| -> Vec<IpAddr> {
        let d = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        d.addresses.iter().filter(|a| a.origin == Origin::Neighbour).map(|a| a.ip).collect()
    };
    seg.set_prefixes(vec![prefix("10.0.2.0/24"), prefix("2001:db8:2::/64")]);
    seg.neighbour(ip("fe80::73"), Some(MAC.to_vec()));
    seg.neighbour(ip("2001:db8:2::73"), Some(MAC.to_vec()));
    seg.neighbour(ip("2001:db8:1::73"), Some(MAC.to_vec())); // the old prefix
    hear(&seg, "10.0.2.73", vec![a_record("tv.local", "10.0.2.73"), aaaa("tv.local", "fe80::73")]);
    assert_eq!(learned(&seg), [ip("2001:db8:2::73")]);
    assert!(!seg.state.borrow_mut().tracker.discovered.holder_of(&ip("2001:db8:1::73")).is_some());

    // The interface moves to the other prefix: so do its devices.
    seg.set_prefixes(vec![prefix("10.0.2.0/24"), prefix("2001:db8:1::/64")]);
    assert_eq!(learned(&seg), [ip("2001:db8:1::73")]);
    assert!(!seg.state.borrow_mut().tracker.discovered.holder_of(&ip("2001:db8:2::73")).is_some());
    // With no network known, nothing is.
    seg.set_prefixes(vec![]);
    assert_eq!(learned(&seg), Vec::<IpAddr>::new());
}

/// What is sent to the group is heard of anyone; what is sent to the
/// daemon itself, only of a host on the interface's networks or link-local.
#[test]
fn what_is_sent_to_the_daemon_is_only_heard_of_a_host_on_the_interface() {
    let seg = segment("test");
    seg.set_prefixes(vec![prefix("10.0.1.0/24"), prefix("fd00::/64")]);
    let group = Some(ip("224.0.0.251"));
    let group6 = Some(ip("ff02::fb"));
    let me = Some(ip("10.0.1.1"));
    let me6 = Some(ip("fd00::1"));
    // To the group, or where it is not known: of anyone.
    assert!(seg.accepts(ip("192.168.9.9"), group));
    assert!(seg.accepts(ip("2001:db8::9"), group6));
    assert!(seg.accepts(ip("192.168.9.9"), None));
    // To the daemon: of the networks it is on.
    assert!(seg.accepts(ip("10.0.1.77"), me));
    assert!(seg.accepts(ip("fd00::77"), me6));
    assert!(seg.accepts(ip("169.254.3.3"), me));
    assert!(seg.accepts(ip("fe80::7"), me6));
    // Not of any other.
    assert!(!seg.accepts(ip("10.0.2.77"), me));
    assert!(!seg.accepts(ip("192.168.9.9"), me));
    assert!(!seg.accepts(ip("2001:db8::9"), me6));
    // With no network known, only link-local.
    seg.set_prefixes(vec![]);
    assert!(!seg.accepts(ip("10.0.1.77"), me));
    assert!(seg.accepts(ip("fe80::7"), me6));
}

/// A device whose link-local address the table has not got, and that has
/// no routable IPv6 address, is asked on it once, for the kernel to look
/// up its link-layer address, and not again within NUDGE_GAP.
#[test]
fn a_device_unknown_to_the_neighbour_table_is_nudged_once() {
    let rx = UdpSocket::bind("[::1]:0").unwrap();
    let seg = segment("test");
    seg.attach(Link::to(Family::V6, fd(UdpSocket::bind("[::1]:0").unwrap()), rx.local_addr().unwrap()));
    let nudged = |seg: &Segment| {
        let state = seg.state.borrow();
        state.tracker.discovered.get(host_id(&state, "speakers.local")).nudged
    };
    hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9")]);
    let first = nudged(&seg).expect("nudged");
    hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9")]);
    assert_eq!(nudged(&seg), Some(first), "not again so soon");

    // One with a routable IPv6 address is not.
    let seg = segment("test");
    seg.attach(Link::to(Family::V6, fd(UdpSocket::bind("[::1]:0").unwrap()), rx.local_addr().unwrap()));
    hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9"), aaaa("speakers.local", "fd00::9")]);
    assert_eq!(nudged(&seg), None);
}

/// One sender may describe only so many hosts: a sleep proxy speaks for
/// several, but not for thousands. Others are not held back, and the
/// hosts it described are still kept up to date.
/// However many addresses a device announces, a segment keeps no more
/// of a family than it is set to.
#[test]
fn a_segment_keeps_as_many_addresses_as_it_is_set_to() {
    let seg = segment("test");
    seg.set_max_addrs(2);
    let many: Vec<Record> = (1..=5).map(|i| aaaa("tv.local", &format!("2001:db8::{i}"))).collect();
    hear(&seg, "fe80::5", many);
    let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
    assert_eq!(tv.addrs().collect::<Vec<_>>(), [ip("2001:db8::1"), ip("2001:db8::2")]);
}

/// An address that is not heard of again runs out on its own, its TTL
/// (at least the minimum lifetime) after it was last heard, while the
/// device, with services that live longer, stays.
#[test]
fn an_address_not_heard_of_again_runs_out_on_its_own() {
    let seg = segment("test");
    let events = seg.subscribe();
    let t0 = Instant::now();
    hear(&seg, "10.0.1.7", vec![
        a_record("tv.local", "10.0.1.7"),
        Record { ttl: 4500, ..aaaa("tv.local", "fd00::7") },
        Record { ttl: 4500, ..srv("TV._http._tcp.local", 80, "tv.local") },
    ]);
    events.try_iter().count();

    // The timer is set for it.
    let pending = seg.pending();
    let address = pending.iter().find(|p| p.who == "tv.local 10.0.1.7").expect("pending");
    assert_eq!(address.what, "expire");
    assert!(address.at > t0 + Duration::from_secs(299) && address.at < t0 + Duration::from_secs(302));

    seg.expire(t0 + Duration::from_secs(200));
    assert!(events.try_recv().is_err(), "not yet");

    seg.expire(t0 + Duration::from_secs(400));
    let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).expect("still there");
    assert_eq!(tv.addrs().collect::<Vec<_>>(), [ip("fd00::7")]);
    assert!(matches!(events.try_recv(), Ok(Event::Updated(d)) if d.borrow().addrs().eq([ip("fd00::7")])));
    assert!(!seg.state.borrow_mut().tracker.discovered.holder_of(&ip("10.0.1.7")).is_some(), "nor found by it");
}

/// A device whose services live long is still asked again before its
/// address runs out, as a cache renews a record before its TTL is up.
#[test]
fn a_device_is_asked_again_before_its_address_runs_out() {
    let (seg, rx) = wired();
    let t0 = Instant::now();
    hear(&seg, "10.0.1.7", vec![
        a_record("tv.local", "10.0.1.7"),
        Record { ttl: 4500, ..srv("TV._http._tcp.local", 80, "tv.local") },
    ]);
    let before = Duration::from_secs(60);
    assert_eq!(seg.refresh(t0 + Duration::from_secs(100), before).unwrap(), 0);
    assert!(seg.refresh(t0 + Duration::from_secs(250), before).unwrap() > 0);
    assert!(asked(&recv(&rx).unwrap()).contains(&q("tv.local", rtype::A)));
}

#[test]
fn a_host_that_is_described_again_is_kept_up_to_date() {
    let seg = segment("test");
    hear(&seg, "10.0.1.1", vec![a_record("h0.local", "10.0.2.1")]);
    hear(&seg, "10.0.1.1", vec![a_record("h0.local", "10.0.3.3")]);
    let h0 = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("h0.local")).unwrap();
    assert_eq!(v4(&h0), Some(ip("10.0.3.3")), "what it described is kept up to date");
}

#[test]
fn a_segment_remembers_only_so_many_devices() {
    let seg = segment("test");
    for i in 0..DEFAULT_MAX_DEVICES + 20 {
        seg.observe(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32 + 1)));
    }
    assert_eq!(seg.devices().len(), DEFAULT_MAX_DEVICES);
}

#[test]
fn the_number_of_services_a_device_is_kept_with_can_be_set() {
    let seg = segment("test");
    seg.set_max_services(3);
    let services: Vec<Record> = (0..10).map(|i| srv(&format!("S{i}._http._tcp.local"), 80, "tv.local")).collect();
    hear(&seg, "10.0.1.7", [vec![a_record("tv.local", "10.0.1.7")], services.clone()].concat());
    assert_eq!(seg.devices()[0].services.len(), 3);

    // Raised, the rest are taken the next time they are heard, and one it has stays up to date.
    seg.set_max_services(8);
    hear(&seg, "10.0.1.7", services);
    assert_eq!(seg.devices()[0].services.len(), 8);
}

#[test]
fn the_number_of_devices_a_segment_remembers_can_be_set() {
    let seg = segment("test");
    seg.set_max_devices(10);
    let host = |i: usize| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32 + 1));
    for i in 0..30 {
        seg.observe(host(i));
    }
    assert_eq!(seg.devices().len(), 10);

    // One it has is kept up to date, and room made by one that is gone is taken.
    seg.observe(host(0));
    assert_eq!(seg.devices().len(), 10);
    seg.set_max_devices(20);
    for i in 0..30 {
        seg.observe(host(i));
    }
    assert_eq!(seg.devices().len(), 20, "raised while running");
}

/// A host that announced only an address no one can be reached at is not
/// given the address the packet came from instead, nor is one that
/// announced none at all.
#[test]
fn a_host_with_only_unusable_addresses_is_not_given_the_senders() {
    let seg = segment("test");
    hear(&seg, "10.0.1.7", vec![a_record("tv.local", "0.0.0.0"), srv("TV._http._tcp.local", 80, "tv.local")]);
    let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
    assert_eq!((v4(&tv), ll4(&tv)), (None, None));

    hear(&seg, "10.0.1.8", vec![srv("NAS._smb._tcp.local", 445, "nas.local")]);
    let nas = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("nas.local")).unwrap();
    assert_eq!(v4(&nas), None);
}

/// The sender is not credited with the address it sent from, in the
/// family it sent over or any: a host has the addresses it announced.
#[test]
fn the_sender_is_not_credited_with_an_address_it_did_not_announce() {
    let seg = segment("test");
    hear(&seg, "fe80::7", vec![a_record("tv.local", "10.0.1.7"), srv("TV._http._tcp.local", 80, "tv.local")]);
    let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
    assert_eq!(v4(&tv), Some(ip("10.0.1.7")));
    assert_eq!(ll6(&tv), None, "not the sender's, over IPv6");

    let seg = segment("test");
    hear(&seg, "10.0.1.8", vec![a_record("nas.local", "0.0.0.0"), aaaa("nas.local", "fd00::8")]);
    let nas = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
    assert_eq!((v4(&nas), v6(&nas)), (None, Some(ip("fd00::8"))));
}

/// A device that says goodbye to the temporary address it sends from,
/// announcing the next in the same packet, is not leaving: it only gives
/// up the one. Saying goodbye with nothing in its place, it is.
#[test]
fn giving_up_a_temporary_address_is_not_leaving() {
    let seg = segment("test");
    hear(&seg, "2001:db8::5", vec![
        aaaa("tv.local", "2001:db8::5"),
        aaaa("tv.local", "fd00::5"),
        srv("TV._http._tcp.local", 80, "tv.local"),
    ]);
    let bye = |addr: &str| Record { ttl: 0, ..aaaa("tv.local", addr) };
    hear(&seg, "2001:db8::5", vec![bye("2001:db8::5"), aaaa("tv.local", "2001:db8::6"), aaaa("tv.local", "fd00::5")]);
    let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).expect("still there");
    assert_eq!(tv.addrs().collect::<Vec<_>>(), [ip("2001:db8::6"), ip("fd00::5")]);
    assert_eq!(tv.services.len(), 1);

    hear(&seg, "2001:db8::6", vec![bye("2001:db8::6"), bye("fd00::5")]);
    assert!(seg.devices().iter().all(|d| d.hostname.is_none()), "gone");
}

/// A device saying goodbye once over each family, the same records each
/// time, leaves in whichever order the two arrive. The IPv6 one comes from
/// a link-local address it never announced: it is not to be credited with
/// that, nor brought back by it once the IPv4 one has seen it off.
#[test]
fn goodbyes_over_both_families_leave_in_either_order() {
    let records = |ttl| {
        vec![
            Record { ttl, ..a_record("test.local", "10.0.2.160") },
            Record { ttl, ..aaaa("test.local", "fd00:2::160") },
            Record { ttl, ..aaaa("test.local", "2001:db8:2::160") },
            Record { ttl, ..srv("Test._http._tcp.local", 8080, "test.local") },
        ]
    };
    for (first, second) in [("10.0.2.160", "fe80::160"), ("fe80::160", "10.0.2.160")] {
        let seg = segment("test");
        hear(&seg, "10.0.2.160", records(120));
        hear(&seg, first, records(0));
        assert!(
            seg.devices().iter().all(|d| !d.has_addr(&ip("fe80::160"))),
            "goodbye from {first}: {:?}",
            seg.devices()
        );
        hear(&seg, second, records(0));
        assert!(seg.devices().is_empty(), "goodbyes from {first} then {second}: {:?}", seg.devices());
    }
}

/// When the interface goes, the segment lets go of its sockets and of the
/// devices on it, and keeps what it announces; when it is back, that is
/// announced again.
#[test]
fn an_interface_that_goes_and_comes_back() {
    let (seg, rx) = wired();
    let events = seg.subscribe();
    hear(&seg, "10.0.1.7", vec![a_record("nas.local", "10.0.1.7"), srv("NAS._smb._tcp.local", 445, "nas.local")]);
    seg.add_reflected(FIRST, &Shared::new(tv("10.0.2.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();
    repeat(&seg, &rx);
    events.try_iter().count();

    // Gone: the devices heard on it are forgotten, what it announces kept.
    seg.detach_all();
    seg.forget_discovered();
    assert!(seg.devices().is_empty());
    assert!(matches!(events.try_recv(), Ok(Event::Removed(d)) if d.borrow().hostname.as_deref() == Some("nas.local")));
    assert_eq!(seg.reflected_devices().len(), 1);
    seg.announce_all().unwrap();
    assert!(recv(&rx).is_none(), "nothing goes out without a socket");

    // Back: a new socket, and everything announced again.
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    seg.attach(Link::to(Family::V4, fd(tx), rx.local_addr().unwrap()));
    seg.announce_all().unwrap();
    let m = recv(&rx).expect("announced again");
    assert!(m.answers.iter().any(|r| r.name == "tv.local" && r.ttl > 0));
    // As anything announced anew: twice.
    assert!(repeat(&seg, &rx).answers.iter().any(|r| r.name == "tv.local" && r.ttl > 0));
}

#[test]
fn add_rejects_unannounceable_devices() {
    let (seg, rx) = wired();
    let mut nameless = tv("10.0.1.9", &["TV"]);
    nameless.hostname = None;
    assert!(seg.add_reflected(OWN, &Shared::new(nameless)).is_err());
    assert!(seg.reflected_devices().is_empty());
    assert!(recv(&rx).is_none());
}


fn query(name: &str, qtype: u16, known: Vec<Record>) -> Vec<u8> {
    Message {
        header: Header { id: 0x4242, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
        questions: vec![codec::Question { name: name.into(), qtype, class: 1, unicast_response: false }],
        answers: known,
        authorities: vec![],
        additionals: vec![],
    }
    .encode()
    .unwrap()
}

fn question(name: &str, qtype: u16) -> Question {
    Question { name: name.into(), qtype, class: 1, unicast_response: false }
}

fn passed(name: &str, qtype: u16, answered: bool) -> Asked {
    Asked { question: question(name, qtype), answered }
}

/// A query asking `questions`, with `proposed` records if it is a probe.
fn asking(questions: &[Question], proposed: Vec<Record>) -> Vec<u8> {
    Message {
        header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
        questions: questions.to_vec(),
        answers: vec![],
        authorities: proposed,
        additionals: vec![],
    }
    .encode()
    .unwrap()
}

/// The events of a segment, taken as a test asks for them, the way a
/// channel's receiver gives them.
struct Events<'a> {
    seg: &'a Segment,
    taken: RefCell<VecDeque<Event>>,
}

impl Segment {
    fn subscribe(&self) -> Events<'_> {
        self.take_events();
        Events { seg: self, taken: RefCell::default() }
    }
}

impl Events<'_> {
    fn try_recv(&self) -> Result<Event, ()> {
        let mut taken = self.taken.borrow_mut();
        taken.extend(self.seg.take_events());
        taken.pop_front().ok_or(())
    }

    fn try_iter(&self) -> impl Iterator<Item = Event> + '_ {
        std::iter::from_fn(|| self.try_recv().ok())
    }
}

/// The questions passed on so far, one list per query.
fn passed_on(events: &Events) -> Vec<Vec<Asked>> {
    events
        .try_iter()
        .filter_map(|e| match e {
            Event::Question(qs) => Some(qs),
            _ => None,
        })
        .collect()
}

/// Pretend the last multicast of every reflected device was `secs` ago.
fn age(seg: &Segment, secs: u64) {
    let mut state = seg.state.borrow_mut();
    for host in state.hosts.hosts_all() {
        state.hosts.edit(&host, |m| {
            m.announced -= Duration::from_secs(secs);
            m.last_sent -= Duration::from_secs(secs);
        });
    }
}

#[test]
fn answers_ptr_query_with_additionals() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();
    age(&seg, 2);

    seg.handle(sa("10.0.0.50"), &query("_http._tcp.local", rtype::PTR, vec![])).unwrap();
    let m = recv(&rx).expect("response");
    assert!(m.header.response && m.header.id == 0 && m.questions.is_empty());
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].data, RData::Ptr("TV._http._tcp.local".into()));
    assert_eq!(m.answers[0].ttl, OTHER_TTL);
    let kinds: Vec<_> = m.additionals.iter().map(|r| r.rtype()).collect();
    assert_eq!(kinds.len(), 3);
    for t in [rtype::SRV, rtype::TXT, rtype::A] {
        assert!(kinds.contains(&t));
    }
}

#[test]
fn matches_names_case_insensitively_and_any_type() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();
    age(&seg, 2);

    seg.handle(sa("10.0.0.50"), &query("TV.Local", rtype::ANY, vec![])).unwrap();
    assert_eq!(recv(&rx).unwrap().answers[0].data, RData::A("10.0.1.9".parse().unwrap()));

    age(&seg, 2);
    seg.handle(sa("10.0.0.50"), &query("nobody.local", rtype::ANY, vec![])).unwrap();
    assert!(recv(&rx).is_none());
    seg.handle(sa("10.0.0.50"), &query("tv.local", rtype::AAAA, vec![])).unwrap();
    assert!(recv(&rx).is_none());
}

#[test]
fn multicast_replies_are_rate_limited() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();

    // Just announced: a query within the second gets nothing.
    let q = query("tv.local", rtype::A, vec![]);
    seg.handle(sa("10.0.0.50"), &q).unwrap();
    assert!(recv(&rx).is_none());

    age(&seg, 2);
    seg.handle(sa("10.0.0.50"), &q).unwrap();
    assert!(recv(&rx).is_some());
    seg.handle(sa("10.0.0.50"), &q).unwrap();
    assert!(recv(&rx).is_none());
}

#[test]
fn known_answers_suppress_replies() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();
    age(&seg, 2);

    let known = |ttl| {
        vec![record("_http._tcp.local".into(), false, ttl, RData::Ptr("TV._http._tcp.local".into()))]
    };
    seg.handle(sa("10.0.0.50"), &query("_http._tcp.local", rtype::PTR, known(OTHER_TTL))).unwrap();
    assert!(recv(&rx).is_none());

    // Under half the TTL left: the asker needs a refresh.
    seg.handle(sa("10.0.0.50"), &query("_http._tcp.local", rtype::PTR, known(OTHER_TTL / 2 - 1))).unwrap();
    assert!(recv(&rx).is_some());
}

#[test]
fn legacy_resolvers_get_unicast_replies() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();

    // Rate limit does not apply to unicast replies.
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let from = client.local_addr().unwrap();
    assert_ne!(from.port(), MDNS_PORT);

    seg.handle(from, &query("tv.local", rtype::A, vec![])).unwrap();
    let m = recv(&client).expect("unicast reply");
    assert_eq!(m.header.id, 0x4242);
    assert_eq!(m.questions[0].name, "tv.local");
    assert!(m.answers.iter().all(|r| r.ttl <= LEGACY_TTL_CAP && !r.cache_flush));
    assert!(recv(&rx).is_none(), "nothing multicast");
}

#[test]
fn ignores_responses_and_odd_queries() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    recv(&rx).unwrap();
    age(&seg, 2);

    let mut resp = query("tv.local", rtype::A, vec![]);
    resp[2] |= 0x80; // QR: a response, not a query
    seg.handle(sa("10.0.0.50"), &resp).unwrap();
    let mut op = query("tv.local", rtype::A, vec![]);
    op[2] |= 0x08; // opcode 1
    seg.handle(sa("10.0.0.50"), &op).unwrap();
    assert!(recv(&rx).is_none());
}

#[test]
fn what_is_announced_anew_is_announced_again_a_second_later_and_then_left_alone() {
    let (seg, rx) = wired();
    let device = Shared::new(tv("10.0.1.9", &["TV"]));
    seg.add_reflected(OWN, &device).unwrap();
    let first = recv(&rx).unwrap();
    seg.reannounce(Instant::now()).unwrap();
    assert!(recv(&rx).is_none(), "not within the second");

    let again = repeat(&seg, &rx);
    assert_eq!(again.answers.len(), first.answers.len());
    assert!(again.answers.iter().all(|r| r.ttl > 0));

    // Unchanged, it is not announced again, however long it waits.
    assert_eq!(seg.state.borrow_mut().hosts["tv.local"].reannounce_at(false), None);
    seg.reannounce(Instant::now() + Duration::from_secs(100_000)).unwrap();
    assert!(recv(&rx).is_none());
    assert!(seg.pending().iter().all(|p| p.what != "re-announce"));

    // A change is, twice again.
    *device.borrow_mut() = tv("10.0.1.9", &["TV", "Other TV"]);
    seg.add_reflected(OWN, &device).unwrap();
    assert!(recv(&rx).is_some());
    repeat(&seg, &rx);
    seg.reannounce(Instant::now() + Duration::from_secs(100_000)).unwrap();
    assert!(recv(&rx).is_none());
}

#[test]
fn a_segment_that_reannounces_keeps_unchanged_devices_up_at_80_percent_of_their_ttl() {
    let (seg, rx) = wired();
    seg.set_reannounce(true);
    seg.add_reflected(OWN, &Shared::new(tv("10.0.1.9", &["TV"]))).unwrap();
    let first = recv(&rx).unwrap();
    repeat(&seg, &rx);

    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    let due = seg.pending().into_iter().find(|p| p.what == "re-announce").expect("waited for");
    assert_eq!(due.at, announced + reannounce_after(HOST_TTL));
    seg.reannounce(announced + reannounce_after(HOST_TTL) - Duration::from_secs(1)).unwrap();
    assert!(recv(&rx).is_none());
    let later = announced + reannounce_after(HOST_TTL);
    seg.reannounce(later).unwrap();
    let again = recv(&rx).expect("re-announcement");
    assert_eq!(again.answers.len(), first.answers.len());

    seg.reannounce(later).unwrap();
    assert!(recv(&rx).is_none());
}

/// Send the second announcement of what `seg` last announced anew, a
/// second after, as heard on `rx`.
fn repeat(seg: &Segment, rx: &UdpSocket) -> Message {
    let at = seg.state.borrow_mut().hosts["tv.local"].announced + ANNOUNCE_REPEAT;
    seg.reannounce(at).unwrap();
    recv(rx).expect("announced a second time")
}

/// Make `seg` hear a response carrying `records` from `from`.
fn hear(seg: &Segment, from: &str, records: Vec<Record>) {
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: records,
        authorities: vec![],
        additionals: vec![],
    };
    seg.handle(sa(from), &msg.encode().unwrap()).unwrap();
}

/// What the questions of one received query ask, as (name, type).
fn asked(m: &Message) -> BTreeSet<(String, u16)> {
    assert!(!m.header.response);
    assert!(m.questions.iter().all(|q| q.class == 1 && !q.unicast_response));
    m.questions.iter().map(|q| (q.name.clone(), q.qtype)).collect()
}

fn q(name: &str, qtype: u16) -> (String, u16) {
    (name.to_string(), qtype)
}

#[test]
fn probe_browses_then_resolves() {
    let (seg, rx) = wired();

    // Nothing known yet: just ask what types exist.
    assert_eq!(seg.probe_round().unwrap(), 1);
    assert_eq!(asked(&recv(&rx).unwrap()), BTreeSet::from([q(META_QUERY, rtype::PTR)]));

    // A device names a type, and an instance of it with no location yet.
    hear(&seg, "10.0.2.73", vec![
        record(META_QUERY.into(), false, 4500, RData::Ptr("_airplay._tcp.local".into())),
        record("_airplay._tcp.local".into(), false, 4500, RData::Ptr("Speaker._airplay._tcp.local".into())),
    ]);
    seg.probe_round().unwrap();
    assert_eq!(
        asked(&recv(&rx).unwrap()),
        BTreeSet::from([
            q(META_QUERY, rtype::PTR),
            q("_airplay._tcp.local", rtype::PTR),
            q("Speaker._airplay._tcp.local", rtype::SRV),
            q("Speaker._airplay._tcp.local", rtype::TXT),
        ])
    );

    // Once the instance says where it is, it is no longer asked about; its
    // host is, for the address it did not say, and the sender's is not taken.
    hear(&seg, "10.0.2.73", vec![record(
        "Speaker._airplay._tcp.local".into(),
        true,
        120,
        RData::Srv { priority: 0, weight: 0, port: 7000, target: "speaker.local".into() },
    )]);
    seg.probe_round().unwrap();
    assert_eq!(
        asked(&recv(&rx).unwrap()),
        BTreeSet::from([
            q(META_QUERY, rtype::PTR),
            q("_airplay._tcp.local", rtype::PTR),
            q("speaker.local", rtype::A),
            q("speaker.local", rtype::AAAA),
        ])
    );
    let speaker = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("speaker.local")).unwrap();
    assert_eq!(v4(&speaker), None);
    // Once it says where it is, it is reflectable, and no longer asked for it.
    hear(&seg, "10.0.2.73", vec![a_record("speaker.local", "10.0.2.73")]);
    seg.probe_round().unwrap();
    assert_eq!(
        asked(&recv(&rx).unwrap()),
        BTreeSet::from([q(META_QUERY, rtype::PTR), q("_airplay._tcp.local", rtype::PTR)])
    );
    let speaker = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("speaker.local")).unwrap();
    assert_eq!(v4(&speaker), Some(ip("10.0.2.73")));
}

/// Run a probe (`kinds` `None`) or a query for types to its end, as the
/// event loop would: the upkeep at each time it says it is due. How it
/// went, and when each round, and its end, came due.
fn run_probe(seg: &Segment, kinds: Option<&[String]>) -> (Probed, Vec<Instant>) {
    let id = seg.begin(kinds.map(<[String]>::to_vec), "asked for", true);
    let mut rounds = Vec::new();
    loop {
        if let Some(result) = seg.probed(id) {
            return (result, rounds);
        }
        let at = seg.next_due().expect("a round or its end is due");
        rounds.push(at);
        seg.upkeep(at);
    }
}

#[test]
fn probe_runs_every_round_and_counts_questions() {
    let (seg, rx) = wired();
    let (result, rounds) = run_probe(&seg, None);
    assert_eq!(result, Ok(3));
    assert_eq!(drain_queries(&rx), 3);
    // A round at once, then after each gap; done once the last has passed.
    let gaps: Vec<Duration> = rounds.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(gaps, PROBE_GAPS);
}

#[test]
fn a_probe_asked_for_while_one_runs_is_that_one() {
    let (seg, _rx) = wired();
    seg.start_probe("startup");
    let joined = seg.probe();
    assert_eq!(seg.state.borrow_mut().probing.len(), 1);
    assert_eq!(seg.probed(joined), None, "not done yet");
    let (result, _) = run_probe(&seg, None);
    assert!(seg.state.borrow_mut().probing.is_empty());
    assert_eq!(seg.probed(joined), None, "the same one: taken already");
    assert_eq!(result, Ok(3));
}

#[test]
fn a_segment_probes_on_its_own_as_often_as_it_is_told() {
    let (seg, rx) = wired();
    seg.set_probe_interval(Some(Duration::from_secs(240)));
    let at = seg.next_due().expect("a routine probe");
    assert!(at > Instant::now() + Duration::from_secs(239), "not at once: startup does that");
    seg.upkeep(at);
    assert_eq!(drain_queries(&rx), 1, "its first round");
    let next = seg.state.borrow_mut().next_routine.unwrap();
    assert_eq!(next, at + Duration::from_secs(240));
    seg.set_probe_interval(None);
    assert_eq!(seg.state.borrow_mut().next_routine, None);
}

fn drain_queries(rx: &UdpSocket) -> usize {
    std::iter::from_fn(|| recv(rx)).count()
}

#[test]
fn probe_splits_big_rounds_into_several_packets() {
    let (seg, rx) = wired();
    let ptrs = (0..40)
        .map(|i| record(META_QUERY.into(), false, 4500, RData::Ptr(format!("_t{i}._tcp.local"))))
        .collect();
    hear(&seg, "10.0.2.73", ptrs);
    assert_eq!(seg.probe_round().unwrap(), 41);
    let packets: Vec<_> = std::iter::from_fn(|| recv(&rx)).collect();
    assert_eq!(packets.len(), 3);
    assert!(packets.iter().all(|p| p.questions.len() <= QUESTIONS_PER_PACKET));
}

#[test]
fn a_name_that_is_not_valid_utf8_is_never_learned_or_asked_about() {
    let (seg, rx) = wired();
    // An instance whose label is 60 invalid UTF-8 bytes: decoded, it would
    // not even fit in a label again.
    let mut p = response(1);
    let mut instance = vec![60];
    instance.extend([0xff; 60]);
    instance.extend(labels(&["_x", "_tcp", "local"]));
    rr(&mut p, &["_x", "_tcp", "local"], 12, 4500, &instance);
    seg.handle(sa("10.0.2.73"), &p).unwrap();

    assert!(seg.devices().iter().all(|d| d.services.is_empty()));
    assert!(seg.probe_round().is_ok());
    assert_eq!(asked(&recv(&rx).unwrap()), BTreeSet::from([q(META_QUERY, rtype::PTR)]));
}

#[test]
fn probe_without_a_sender_does_nothing() {
    let seg = segment("test");
    let id = seg.probe();
    assert_eq!(seg.probed(id), Some(Ok(0)), "done at once");
    assert_eq!(seg.probed(id), None, "taken");
}

#[test]
fn learned_types_are_capped() {
    let seg = segment("test");
    let ptrs = (0..MAX_TYPES + 50)
        .map(|i| record(META_QUERY.into(), false, 4500, RData::Ptr(format!("_t{i}._tcp.local"))))
        .collect();
    hear(&seg, "10.0.2.73", ptrs);
    assert_eq!(seg.state.borrow_mut().tracker.types.len(), MAX_TYPES);
}

/// `router.local` is advertised as a reflected device that has a hostname
/// and an address but no services.
#[test]
fn a_device_without_services_can_be_advertised() {
    let (seg, rx) = wired();
    let router = Device {
        hostname: Some("router.local".into()),
        addresses: vec![ip("10.0.1.1").into()].into(),
        ..Device::default()
    };
    let router = Shared::new(router);
    seg.add_reflected(OWN, &router).unwrap();

    let m = recv(&rx).expect("announcement");
    assert_eq!(m.answers.len(), 1, "just the address record: {:?}", m.answers);
    assert_eq!(m.answers[0].name, "router.local");
    assert_eq!(m.answers[0].data, RData::A("10.0.1.1".parse().unwrap()));
    assert!(m.answers[0].cache_flush);

    // It answers for its name like any reflected device...
    age(&seg, 2);
    seg.handle(sa("10.0.1.50"), &query("Router.LOCAL", rtype::A, vec![])).unwrap();
    assert_eq!(recv(&rx).unwrap().answers[0].data, RData::A("10.0.1.1".parse().unwrap()));

    // ...is re-announced, and says goodbye when removed.
    seg.reannounce(Instant::now() + reannounce_after(HOST_TTL) + Duration::from_secs(1)).unwrap();
    assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == HOST_TTL));
    seg.remove_reflected(&seg.own(), &router).unwrap();
    assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 0));
}

/// A segment over both families, each with a local socket for a group.
fn wired_both() -> (Segment, UdpSocket, UdpSocket) {
    let (_, rx4) = wired();
    let (_, rx6) = wired_family(Family::V6);
    let seg = segment("test");
    seg.attach(
        Link::to(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx4.local_addr().unwrap())
            .and(Family::V6, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx6.local_addr().unwrap()),
    );
    (seg, rx4, rx6)
}

/// A device heard over IPv4 and over IPv6 is one device, with the
/// addresses of both.
#[test]
fn a_segment_over_both_families_keeps_one_list() {
    let seg = segment("test");
    hear(&seg, "10.0.1.7", vec![a_record("tv.local", "10.0.1.7"), srv("TV._http._tcp.local", 80, "tv.local")]);
    hear(&seg, "fe80::7", vec![aaaa("tv.local", "fd00::7")]);
    let named: Vec<Device> = seg.devices().into_iter().filter(|d| d.hostname.is_some()).collect();
    assert_eq!(named.len(), 1, "{named:?}");
    assert_eq!((v4(&named[0]), v6(&named[0])), (Some(ip("10.0.1.7")), Some(ip("fd00::7"))));
}

/// Announcements go out over every family; a reply goes out over the
/// family it was asked over, with the addresses of both, and the once a
/// second is counted per family.
#[test]
fn announcements_go_out_over_both_families_and_replies_over_the_askers() {
    let (seg, rx4, rx6) = wired_both();
    let mut both = tv("10.0.1.9", &["TV"]);
    both.add_addrs(&[ip("fd00::9")]);
    seg.add_reflected(OWN, &Shared::new(both)).unwrap();
    assert!(recv(&rx4).is_some() && recv(&rx6).is_some(), "announced over both");

    age(&seg, 2);
    seg.handle(sa("10.0.1.50"), &query("tv.local", rtype::A, vec![])).unwrap();
    let m = recv(&rx4).expect("answered over IPv4");
    assert!(recv(&rx6).is_none(), "and over IPv4 only");
    assert!(m.additionals.iter().any(|r| r.data == RData::Aaaa("fd00::9".parse().unwrap())), "{:?}", m.additionals);

    // Just answered, it is not answered again within the second, over either
    // family: the limit is the interface's.
    seg.handle(sa("fe80::50"), &query("tv.local", rtype::AAAA, vec![])).unwrap();
    assert!(recv(&rx6).is_none() && recv(&rx4).is_none(), "not again yet");
    seg.handle(sa("10.0.1.51"), &query("tv.local", rtype::A, vec![])).unwrap();
    assert!(recv(&rx4).is_none());

    // A second on, over the family it was asked over.
    age(&seg, 2);
    seg.handle(sa("fe80::50"), &query("tv.local", rtype::AAAA, vec![])).unwrap();
    assert!(recv(&rx6).is_some(), "answered over IPv6");
    assert!(recv(&rx4).is_none());
}

#[test]
fn a_probe_goes_out_over_both_families() {
    let (seg, rx4, rx6) = wired_both();
    seg.probe_round().unwrap();
    for rx in [&rx4, &rx6] {
        assert_eq!(asked(&recv(rx).unwrap()), BTreeSet::from([q(META_QUERY, rtype::PTR)]));
    }
}

/// A segment of `family` whose "multicast group" is a local socket.
fn wired_family(family: Family) -> (Segment, UdpSocket) {
    let (_, rx) = wired();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let seg = segment("test");
    seg.attach(Link::to(family, fd(tx), rx.local_addr().unwrap()));
    (seg, rx)
}

fn aaaa(host: &str, addr: &str) -> Record {
    record(host.into(), true, 120, RData::Aaaa(addr.parse().unwrap()))
}

fn a_record(host: &str, addr: &str) -> Record {
    record(host.into(), true, 120, RData::A(addr.parse().unwrap()))
}

fn srv(instance: &str, port: u16, target: &str) -> Record {
    record(instance.into(), true, 120, RData::Srv { priority: 0, weight: 0, port, target: target.into() })
}

fn ptr(kind: &str, instance: &str) -> Record {
    record(kind.into(), false, 4500, RData::Ptr(instance.into()))
}

#[test]
fn a_device_first_heard_by_address_becomes_the_named_device() {
    let seg = segment("test");
    let rx = seg.subscribe();

    // A browse answer: an instance, but not yet who or where it is.
    hear(&seg, "10.0.2.73", vec![ptr("_airplay._tcp.local", "Speaker._airplay._tcp.local")]);
    assert_eq!(seg.devices().len(), 1);
    assert!(seg.devices()[0].hostname.is_none());

    // The resolve answer names it.
    hear(&seg, "10.0.2.73", vec![
        srv("Speaker._airplay._tcp.local", 7000, "speaker.local"),
        a_record("speaker.local", "10.0.2.73"),
    ]);
    let devices = seg.devices();
    assert_eq!(devices.len(), 1, "one device, not an unnamed one and a named one");
    assert_eq!(devices[0].hostname.as_deref(), Some("speaker.local"));
    assert_eq!(v4(&devices[0]), Some(ip("10.0.2.73")));
    assert_eq!(devices[0].services.len(), 1, "the service learned before the name is kept");
    assert_eq!((devices[0].services[0].port(), devices[0].services[0].target().as_deref()), (7000, Some("speaker.local")));

    let kinds: Vec<&str> = rx
        .try_iter()
        .map(|e| match e {
            Event::Added(d) if d.borrow().hostname.is_none() => "added unnamed",
            Event::Removed(d) if d.borrow().hostname.is_none() => "removed unnamed",
            Event::Added(_) => "added named",
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(kinds, ["added unnamed", "removed unnamed", "added named"]);
}

/// A reflector announces other devices from its own address. Each is
/// its own device, at the address it announces, and the reflector itself
/// is not mistaken for any of them.
#[test]
fn a_reflector_announcing_other_devices_is_not_mistaken_for_them() {
    let seg = segment("test");
    hear(&seg, "10.0.0.1", vec![
        a_record("speaker.local", "10.0.2.73"),
        ptr("_airplay._tcp.local", "Speaker._airplay._tcp.local"),
        srv("Speaker._airplay._tcp.local", 7000, "speaker.local"),
    ]);
    hear(&seg, "10.0.0.1", vec![
        a_record("tv.local", "10.0.2.179"),
        ptr("_airplay._tcp.local", "TV._airplay._tcp.local"),
        srv("TV._airplay._tcp.local", 7000, "tv.local"),
    ]);

    let mut devices = seg.devices();
    devices.sort_by_key(|d| d.hostname.clone());
    let found: Vec<_> = devices.iter().map(|d| (d.hostname.as_deref().unwrap(), v4(d).unwrap(), d.services.len())).collect();
    assert_eq!(found, [("speaker.local", ip("10.0.2.73"), 1), ("tv.local", ip("10.0.2.179"), 1)]);
}

#[test]
fn packets_that_do_not_name_their_sender_belong_to_the_device_it_is() {
    let seg = segment("test");
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    assert_eq!(seg.devices().len(), 1);

    // A query from the same address names nobody, but is that device.
    seg.handle(sa("10.0.1.7"), &query("other.local", rtype::A, vec![])).unwrap();
    assert_eq!(seg.devices().len(), 1, "no second, unnamed device");
    // A different address is a different device.
    seg.handle(sa("10.0.1.8"), &query("other.local", rtype::A, vec![])).unwrap();
    assert_eq!(seg.devices().len(), 2);
}

#[test]
fn goodbye_and_expiry_also_forget_the_addresses() {
    for goodbye in [true, false] {
        let seg = segment("test");
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        if goodbye {
            seg.handle(sa("10.0.1.7"), &announcement(0)).unwrap();
        } else {
            seg.expire(Instant::now() + Duration::from_secs(36000));
        }
        assert!(seg.devices().is_empty());

        // The address no longer points at the old device.
        seg.handle(sa("10.0.1.7"), &query("x.local", rtype::A, vec![])).unwrap();
        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].hostname.is_none() && devices[0].services.is_empty(), "goodbye={goodbye}");
    }
}

#[test]
fn a_link_local_only_device_can_be_advertised_on_its_own_link() {
    let (seg, rx) = wired_family(Family::V6);
    let router = Device {
        hostname: Some("router.local".into()),
        addresses: vec![ip("fe80::1").into()].into(),
        ..Device::default()
    };
    seg.add_reflected(OWN, &Shared::new(router)).unwrap();
    let m = recv(&rx).unwrap();
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].data, RData::Aaaa("fe80::1".parse().unwrap()));
}

#[test]
fn replacing_a_device_withdraws_the_addresses_it_no_longer_has() {
    let (seg, rx) = wired();
    let device = Shared::new(tv("10.0.1.9", &["TV"]));
    seg.add_reflected(OWN, &device).unwrap();
    recv(&rx).unwrap();

    *device.borrow_mut() = tv("10.0.1.10", &["TV"]);
    seg.add_reflected(OWN, &device).unwrap();
    let m = recv(&rx).unwrap();
    let ttl_of = |a: &str| m.answers.iter().find(|r| r.data == RData::A(a.parse().unwrap())).map(|r| r.ttl);
    assert_eq!((ttl_of("10.0.1.9"), ttl_of("10.0.1.10")), (Some(0), Some(HOST_TTL)));
    assert_eq!(seg.reflected_devices().len(), 1, "same device, so it is what is announced");
}

/// Whether a device with no address is worth announcing is for whoever
/// adds it to say: its services are announced, with no address record.
#[test]
fn a_device_with_no_addresses_is_announced_by_its_services() {
    let (seg, rx) = wired();
    let mut none = tv("10.0.1.9", &["TV"]);
    edit(&mut none.addresses).clear();
    seg.add_reflected(OWN, &Shared::new(none)).unwrap();
    assert_eq!(seg.reflected_devices().len(), 1);
    let m = recv(&rx).unwrap();
    assert!(m.answers.iter().all(|r| addr_of(&r.data).is_none()));
    assert!(m.answers.iter().any(|r| matches!(r.data, RData::Srv { .. })));
}

/// Records do not belong to the transport they go out on: an IPv4
/// segment announces a device's IPv6 addresses too, in the same packet.
#[test]
fn a_device_is_announced_with_the_addresses_of_both_families() {
    let (seg, rx) = wired();
    let mut both = tv("10.0.1.9", &["TV"]);
    both.add_addrs(&[ip("fd00::9"), ip("fe80::9")]);
    seg.add_reflected(OWN, &Shared::new(both)).unwrap();
    let addrs: Vec<RData> = recv(&rx).unwrap().answers.into_iter().filter(|r| r.name == "tv.local").map(|r| r.data).collect();
    for want in [RData::A("10.0.1.9".parse().unwrap()), RData::Aaaa("fd00::9".parse().unwrap()), RData::Aaaa("fe80::9".parse().unwrap())] {
        assert!(addrs.contains(&want), "{want:?} in {addrs:?}");
    }
}

fn txt(instance: &str, entry: &str) -> Record {
    record(instance.into(), true, 4500, RData::Txt(vec![entry.as_bytes().to_vec()]))
}

fn find<'a>(devices: &'a [Device], host: &str) -> &'a Device {
    devices.iter().find(|d| d.hostname.as_deref() == Some(host)).unwrap_or_else(|| panic!("no {host} in {devices:?}"))
}

/// The shape of a real reflector's answer to a browse query, captured from
/// the router: two PTRs, an SRV and TXT for each instance, and an address
/// for only one of the two hosts. Every record belongs to the device it
/// names, not to whichever host the packet happened to mention first.
#[test]
fn a_packet_describing_two_devices_attributes_each_record_to_its_own_device() {
    let seg = segment("test");
    let rx = seg.subscribe();
    hear(&seg, "10.0.0.1", vec![
        ptr("_airplay._tcp.local", "OZAL TV._airplay._tcp.local"),
        ptr("_airplay._tcp.local", "OZAL Speakers._airplay._tcp.local"),
        srv("OZAL TV._airplay._tcp.local", 7000, "LGwebOSTV.local"),
        txt("OZAL TV._airplay._tcp.local", "model=TV"),
        srv("OZAL Speakers._airplay._tcp.local", 7000, "OZAL-Speakers.local"),
        txt("OZAL Speakers._airplay._tcp.local", "model=RX"),
        a_record("OZAL-Speakers.local", "10.0.2.73"),
    ]);

    let devices = seg.devices();
    assert_eq!(devices.len(), 2, "the sender is not made a device of its own: {devices:?}");

    let tv = find(&devices, "LGwebOSTV.local");
    let names: Vec<&str> = tv.services.iter().map(|s| s.instance()).collect();
    assert_eq!(names, ["OZAL TV._airplay._tcp.local"]);
    assert_eq!(tv.services[0].txt().collect::<Vec<_>>(), vec![b"model=TV".to_vec()]);
    assert_eq!(v4(tv), None, "no address was announced, and the sender is not credited with one");

    let speaker = find(&devices, "OZAL-Speakers.local");
    let names: Vec<&str> = speaker.services.iter().map(|s| s.instance()).collect();
    assert_eq!(names, ["OZAL Speakers._airplay._tcp.local"]);
    assert_eq!(speaker.services[0].txt().collect::<Vec<_>>(), vec![b"model=RX".to_vec()]);
    assert_eq!(v4(speaker), Some(ip("10.0.2.73")));

    assert_eq!(rx.try_iter().filter(|e| matches!(e, Event::Added(d) if d.borrow().hostname.is_some())).count(), 2);
}

#[test]
fn the_only_host_a_packet_describes_is_not_given_the_senders_address_when_it_announces_none() {
    let seg = segment("test");
    hear(&seg, "10.0.1.9", vec![srv("Dev._http._tcp.local", 80, "dev.local")]);
    let devices = seg.devices();
    assert_eq!(devices.len(), 1);
    assert_eq!((devices[0].hostname.as_deref(), v4(&devices[0])), (Some("dev.local"), None));
}

/// A bare browse answer leaves unresolved instances on the sender. Once a
/// later packet resolves them to their hosts they are not kept twice.
#[test]
fn resolved_instances_leave_the_unresolved_copy_behind() {
    let seg = segment("test");
    hear(&seg, "10.0.0.1", vec![
        ptr("_x._tcp.local", "A._x._tcp.local"),
        ptr("_x._tcp.local", "B._x._tcp.local"),
    ]);
    assert_eq!(seg.devices()[0].services.len(), 2);

    hear(&seg, "10.0.0.1", vec![
        srv("A._x._tcp.local", 1, "a.local"),
        srv("B._x._tcp.local", 2, "b.local"),
        a_record("a.local", "10.0.2.1"),
        a_record("b.local", "10.0.2.2"),
    ]);
    let devices = seg.devices();
    assert_eq!(devices.len(), 3);
    assert_eq!(find(&devices, "a.local").services.len(), 1);
    assert_eq!(find(&devices, "b.local").services.len(), 1);
    let sender = devices.iter().find(|d| d.hostname.is_none()).unwrap();
    assert!(sender.services.is_empty(), "the sender no longer carries them: {sender:?}");
}

/// The copy is found on another device than the one that resolves it, and
/// the list of devices that may hold one follows them coming and going.
#[test]
fn an_unresolved_copy_on_another_device_is_found_and_the_list_of_them_is_kept_clean() {
    let seg = segment("test");
    hear(&seg, "10.0.0.1", vec![ptr("_x._tcp.local", "A._x._tcp.local")]);
    hear(&seg, "10.0.0.5", vec![ptr("_x._tcp.local", "C._x._tcp.local")]);
    assert_eq!(seg.state.borrow().tracker.discovered.with_unresolved().count(), 2);

    // The host announces itself, and the first sender's copy goes; the other's stays.
    hear(&seg, "10.0.0.2", vec![srv("A._x._tcp.local", 1, "a.local"), a_record("a.local", "10.0.0.2")]);
    let devices = seg.devices();
    assert_eq!(find(&devices, "a.local").services.len(), 1);
    let by_addr = |addr: &str| devices.iter().find(|d| d.hostname.is_none() && v4(d) == Some(ip(addr))).unwrap().clone();
    assert!(by_addr("10.0.0.1").services.is_empty(), "{:?}", by_addr("10.0.0.1"));
    assert_eq!(by_addr("10.0.0.5").services.len(), 1);
    assert_eq!(seg.state.borrow().tracker.discovered.with_unresolved().count(), 1, "the one that has none is no longer listed");

    // One that goes is not kept listed.
    seg.expire(Instant::now() + Duration::from_secs(2 * 3600));
    assert!(seg.devices().is_empty());
    assert_eq!(seg.state.borrow().tracker.discovered.with_unresolved().count(), 0);
    hear(&seg, "10.0.0.5", vec![ptr("_x._tcp.local", "C._x._tcp.local")]);
    seg.forget_discovered();
    assert!(seg.state.borrow().tracker.discovered.with_unresolved().count() == 0 && seg.state.borrow().tracker.discovered.addrs_held() == 0);
    seg.state.borrow().tracker.discovered.check();
}

/// Many devices running out together are all dropped, with what pointed
/// at them, and the ones that do not run out are left alone.
#[test]
fn devices_that_run_out_together_are_dropped_and_the_others_kept() {
    let seg = segment("test");
    seg.set_max_devices(500);
    for i in 0..200 {
        let (host, from) = (format!("h{i}.local"), format!("10.1.0.{}", i + 1));
        hear(&seg, &from, vec![a_record(&host, &from), srv(&format!("S{i}._x._tcp.local"), 1, &host)]);
    }
    let keep = "h7.local";
    let longer = Instant::now() + Duration::from_secs(10_000);
    {
        let mut state = seg.state.borrow_mut();
        let kept = host_id(&state, keep);
        state.tracker.discovered.edit(kept, |entry| {
            entry.expires = longer;
            entry.addr_expires.values_mut().for_each(|at| *at = longer);
        });
    }
    seg.expire(Instant::now() + Duration::from_secs(2 * 3600));
    let left = seg.devices();
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].hostname.as_deref(), Some(keep));
    assert!(matches!(seg.take_events().last(), Some(Event::Updated { .. } | Event::Removed(_))));
    assert_eq!(seg.state.borrow().tracker.discovered.addrs_held(), 1, "only the survivor's address is still attributed");
    seg.state.borrow().tracker.discovered.check();
}

#[test]
fn probe_asks_for_the_addresses_of_named_devices_that_have_no_routable_one() {
    let (seg, rx) = wired_family(Family::V6);
    // It sends from, and announces, only its link-local address.
    hear(&seg, "fe80::9", vec![srv("T._x._tcp.local", 1, "t.local"), aaaa("t.local", "fe80::9")]);
    assert_eq!(v4(&seg.devices()[0]), None);

    seg.probe_round().unwrap();
    assert!(asked(&recv(&rx).unwrap()).contains(&q("t.local", rtype::AAAA)));

    // It answers with a ULA as well, so there is nothing left to ask.
    hear(&seg, "fe80::9", vec![aaaa("t.local", "fd00::9")]);
    assert_eq!(v6(&seg.devices()[0]), Some(ip("fd00::9")));
    seg.probe_round().unwrap();
    assert!(!asked(&recv(&rx).unwrap()).contains(&q("t.local", rtype::AAAA)));
}

/// Pretend the device called `host` was heard from so that it now expires at `at`.
/// Pretend `host` and its addresses run out at `at`, as hearing from it
/// would make them.
fn set_expiry(seg: &Segment, host: &str, at: Instant) {
    let mut state = seg.state.borrow_mut();
    let id = host_id(&state, host);
    state
        .tracker
        .discovered
        .edit(id, |entry| {
            entry.expires = at;
            for expiry in entry.addr_expires.values_mut() {
                *expiry = at;
            }
        })
        .expect("no such device");
}

/// printer.local lives only for the 5 minute floor (all its TTLs are 120);
/// other.local announces its address and a PTR for 4500 seconds, so it and
/// its address live 75 minutes.
fn hear_a_short_and_a_long_lived_device(seg: &Segment) {
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    hear(seg, "10.0.1.8", vec![
        Record { ttl: 4500, ..a_record("other.local", "10.0.1.8") },
        ptr("_x._tcp.local", "O._x._tcp.local"),
        srv("O._x._tcp.local", 1, "other.local"),
    ]);
}

#[test]
fn refresh_asks_only_the_devices_about_to_expire_and_only_about_what_they_announced() {
    let (seg, rx) = wired();
    hear_a_short_and_a_long_lived_device(&seg);
    let t0 = Instant::now();
    let before = Duration::from_secs(60);

    // 100 s in, nothing is near its expiry.
    assert_eq!(seg.refresh(t0 + Duration::from_secs(100), before).unwrap(), 0);
    assert!(recv(&rx).is_none());

    // 250 s in, printer.local (expires after 300 s) is within 60 s of it; other.local is not.
    let sent = seg.refresh(t0 + Duration::from_secs(250), before).unwrap();
    assert_eq!(sent, 3);
    assert_eq!(
        asked(&recv(&rx).unwrap()),
        BTreeSet::from([
            q("printer.local", rtype::A),
            q("Printer._http._tcp.local", rtype::SRV),
            q("Printer._http._tcp.local", rtype::TXT),
        ])
    );
    assert!(recv(&rx).is_none());
}

/// A device is asked to refresh at its own address: a routable one, IPv4
/// first, else a link-local one, and where it has none, on the group.
#[test]
fn a_refresh_is_asked_at_a_routable_address_of_the_device_before_a_link_local() {
    let device = |addrs: &[&str]| {
        let mut d = Device { hostname: Some("pc.local".into()), ..Device::default() };
        d.add_addrs(&addrs.iter().map(|a| ip(a)).collect::<Vec<_>>());
        d
    };
    let to = "127.0.0.1:9".parse().unwrap();
    let link = |families: &[Family]| {
        let socket = || fd(UdpSocket::bind("127.0.0.1:0").unwrap());
        families.iter().fold(Link::default(), |link, &family| link.and(family, socket(), to))
    };
    let both = link(&[Family::V4, Family::V6]);
    assert_eq!(direct_address(&device(&["fe80::1", "fd00::2", "10.0.1.3"]), &both), Some(ip("10.0.1.3")));
    assert_eq!(direct_address(&device(&["fe80::1", "fd00::2"]), &both), Some(ip("fd00::2")));
    assert_eq!(direct_address(&device(&["fe80::1"]), &both), Some(ip("fe80::1")));
    assert_eq!(direct_address(&device(&[]), &both), None);
    // Only over a family that hears what is sent to the daemon.
    assert_eq!(direct_address(&device(&["fe80::1", "fd00::2", "10.0.1.3"]), &link(&[Family::V6])), Some(ip("fd00::2")));
    assert_eq!(direct_address(&device(&["fe80::1", "10.0.1.3"]), &link(&[Family::V4])), Some(ip("10.0.1.3")));
    assert_eq!(direct_address(&device(&["fe80::1", "fd00::2"]), &link(&[Family::V4])), None);
    assert_eq!(direct_address(&device(&["10.0.1.3"]), &link(&[])), None);
}

/// Where the device cannot be sent to, the question goes to the group.
#[test]
fn a_refresh_that_cannot_be_sent_to_the_device_goes_to_the_group() {
    let (seg, rx) = wired();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    // 10.0.1.7 is not reachable from the socket the test sends from.
    assert_eq!(seg.refresh(Instant::now() + Duration::from_secs(250), Duration::from_secs(60)).unwrap(), 3);
    assert!(recv(&rx).is_some());
}

#[test]
fn refresh_retries_after_a_gap_and_stops_once_the_device_has_answered() {
    let (seg, rx) = wired();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let t = Instant::now() + Duration::from_secs(250);
    let before = Duration::from_secs(60); // so the retry gap is 15 s

    assert_eq!(seg.refresh(t, before).unwrap(), 3);
    recv(&rx).unwrap();
    // Too soon to ask again.
    assert_eq!(seg.refresh(t + Duration::from_secs(5), before).unwrap(), 0);
    assert!(recv(&rx).is_none());
    // No answer after the gap: ask again.
    assert_eq!(seg.refresh(t + Duration::from_secs(15), before).unwrap(), 3);
    recv(&rx).unwrap();

    // It answers, which moves its expiry out: no more questions.
    set_expiry(&seg, "printer.local", t + Duration::from_secs(4500));
    assert_eq!(seg.refresh(t + Duration::from_secs(40), before).unwrap(), 0);
    assert!(recv(&rx).is_none());
}

#[test]
fn refresh_leaves_devices_known_only_by_address_alone() {
    let (seg, rx) = wired();
    // A phone that only sends queries: no hostname, no services, nothing to ask it.
    seg.handle(sa("10.0.1.9"), &query("x.local", rtype::A, vec![])).unwrap();
    assert_eq!(seg.devices().len(), 1);
    let far = Instant::now() + Duration::from_secs(280);
    assert_eq!(seg.refresh(far, Duration::from_secs(60)).unwrap(), 0);
    assert!(recv(&rx).is_none());
}

#[test]
fn refresh_asks_an_ipv6_device_for_its_aaaa_record() {
    let (seg, rx) = wired_family(Family::V6);
    hear(&seg, "fe80::9", vec![srv("T._x._tcp.local", 1, "t.local"), aaaa("t.local", "fe80::9")]);
    assert_eq!(seg.refresh(Instant::now() + Duration::from_secs(250), Duration::from_secs(60)).unwrap(), 3);
    let asked = asked(&recv(&rx).unwrap());
    assert!(asked.contains(&q("t.local", rtype::AAAA)) && !asked.contains(&q("t.local", rtype::A)), "{asked:?}");
}

#[test]
fn refresh_without_a_sender_does_nothing_and_remembers_nothing() {
    let seg = segment("test");
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    assert_eq!(seg.refresh(Instant::now() + Duration::from_secs(250), Duration::from_secs(60)).unwrap(), 0);
    // Once there is a sender it still asks, because the earlier call asked nobody.
    let (wired_seg, rx) = wired();
    wired_seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    assert_eq!(wired_seg.refresh(Instant::now() + Duration::from_secs(250), Duration::from_secs(60)).unwrap(), 3);
    assert!(recv(&rx).is_some());
}

/// A device whose records all have a TTL shorter than the margin. Its
/// lifetime is never less than the 5 minute floor, so it is not "due" the
/// moment it is heard: it is asked 30 s before that floor runs out.
#[test]
fn a_ttl_shorter_than_the_margin_does_not_make_a_device_due_early() {
    let (seg, rx) = wired();
    // Every record has a 10 second TTL: shorter than the 30 s margin.
    hear(&seg, "10.0.1.20", vec![
        record("short.local".into(), true, 10, RData::A("10.0.1.20".parse().unwrap())),
        record("S._x._tcp.local".into(), true, 10, RData::Srv { priority: 0, weight: 0, port: 1, target: "short.local".into() }),
        record("_x._tcp.local".into(), false, 10, RData::Ptr("S._x._tcp.local".into())),
    ]);
    let t0 = Instant::now();
    let before = Duration::from_secs(30);

    // Heard just now, a 10 s TTL would already be "inside" the margin if the
    // TTL were used as the lifetime. It is not: the floor applies.
    assert_eq!(seg.refresh(t0, before).unwrap(), 0);
    assert_eq!(seg.refresh(t0 + Duration::from_secs(10), before).unwrap(), 0);
    assert_eq!(seg.refresh(t0 + Duration::from_secs(200), before).unwrap(), 0);
    assert!(recv(&rx).is_none());

    // 30 s before the 5 minute floor ends, it is asked.
    assert_eq!(seg.refresh(t0 + FLOOR - before + Duration::from_secs(1), before).unwrap(), 3);
    assert!(recv(&rx).is_some());

    // And without an answer it is dropped when the floor ends, not before.
    seg.expire(t0 + Duration::from_secs(250));
    assert_eq!(seg.devices().len(), 1);
    seg.expire(t0 + FLOOR + Duration::from_secs(1));
    assert!(seg.devices().is_empty());
}

/// With no floor, a device whose TTL is shorter than the margin is asked
/// three quarters of the way through its TTL, and only once in a gap, not
/// over and over.
#[test]
fn a_ttl_shorter_than_the_margin_is_asked_three_quarters_in_where_there_is_no_floor() {
    let (seg, rx) = wired();
    seg.set_min_lifetime(Duration::ZERO);
    hear(&seg, "10.0.1.20", vec![
        record("short.local".into(), true, 20, RData::A("10.0.1.20".parse().unwrap())),
        record("S._x._tcp.local".into(), true, 20, RData::Srv { priority: 0, weight: 0, port: 1, target: "short.local".into() }),
        record("_x._tcp.local".into(), false, 20, RData::Ptr("S._x._tcp.local".into())),
    ]);
    let t0 = Instant::now();
    let before = Duration::from_secs(30); // more than the 20 s it lives

    assert_eq!(seg.refresh(t0, before).unwrap(), 0, "not the moment it is heard");
    assert_eq!(seg.refresh(t0 + Duration::from_secs(14), before).unwrap(), 0);
    assert!(recv(&rx).is_none());
    assert_eq!(seg.refresh(t0 + Duration::from_secs(16), before).unwrap(), 3, "three quarters in, at 15 s");
    assert!(recv(&rx).is_some());
    assert_eq!(seg.refresh(t0 + Duration::from_secs(17), before).unwrap(), 0, "not again at once");
    assert!(recv(&rx).is_none());

    // One that lives longer than the margin is asked the margin before: a
    // quarter of its TTL is more than that.
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let long = Instant::now();
    assert_eq!(seg.refresh(long + Duration::from_secs(89), before).unwrap(), 0);
    assert_eq!(seg.refresh(long + Duration::from_secs(91), before).unwrap(), 3);
}

/// A device that announces a TTL of a second, as a buggy one may, is kept for
/// the default minimum and asked once in it: it is not asked every few seconds.
#[test]
fn a_device_that_announces_a_tiny_ttl_is_asked_once_and_kept_the_default_minimum() {
    let (seg, rx) = wired();
    seg.set_min_lifetime(DEFAULT_MIN_LIFETIME);
    hear_a_device_with_ttl(&seg, 1);
    let t0 = Instant::now();
    let before = Duration::from_secs(30);

    for secs in [0, 1, 5, 30, 44] {
        assert_eq!(seg.refresh(t0 + Duration::from_secs(secs), before).unwrap(), 0, "{secs}s");
    }
    assert!(recv(&rx).is_none());
    assert_eq!(seg.refresh(t0 + Duration::from_secs(46), before).unwrap(), 3, "three quarters of the minute in");
    assert!(recv(&rx).is_some());
    for secs in [47, 50, 52] {
        assert_eq!(seg.refresh(t0 + Duration::from_secs(secs), before).unwrap(), 0, "not again at {secs}s");
    }
    seg.expire(t0 + Duration::from_secs(59));
    assert_eq!(seg.devices().len(), 1, "kept for the minute");
    seg.expire(t0 + Duration::from_secs(61));
    assert!(seg.devices().is_empty());
}

/// The other extreme: a margin longer than any lifetime has every device
/// asked three quarters of the way through its life, once. It must not turn
/// into a flood.
#[test]
fn a_margin_longer_than_the_lifetime_asks_at_a_steady_rate_not_constantly() {
    let (seg, rx) = wired();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let t0 = Instant::now();
    let before = Duration::from_secs(600); // longer than the 300 s floor; the retry gap is 150 s

    assert_eq!(seg.refresh(t0, before).unwrap(), 0, "not from the start");
    assert_eq!(seg.refresh(t0 + Duration::from_secs(224), before).unwrap(), 0);
    assert_eq!(seg.refresh(t0 + Duration::from_secs(226), before).unwrap(), 3, "three quarters in");
    recv(&rx).unwrap();
    for secs in [227, 250, 299] {
        assert_eq!(seg.refresh(t0 + Duration::from_secs(secs), before).unwrap(), 0, "{secs}s");
    }
    assert!(recv(&rx).is_none());
}

#[test]
fn refresh_does_not_ask_a_device_whose_time_has_already_run_out() {
    let (seg, rx) = wired();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let t0 = Instant::now();
    let before = Duration::from_secs(30);

    // Still alive just before the end: asked. Past the end, but not yet
    // dropped (the next expiry pass has not run): not asked.
    assert_eq!(seg.refresh(t0 + FLOOR - Duration::from_secs(5), before).unwrap(), 3);
    recv(&rx).unwrap();
    assert_eq!(seg.refresh(t0 + FLOOR + Duration::from_secs(10), before).unwrap(), 0);
    assert!(recv(&rx).is_none());
}

/// A device that moves on to a new address without saying goodbye to the
/// last is known by its newest once it is at the limit: the address that
/// runs out first makes room.
#[test]
fn a_new_address_takes_the_place_of_the_stalest_at_the_limit() {
    let seg = segment("test");
    seg.set_max_addrs(2);
    let aaaa = |a: &str| record("phone.local".into(), false, 120, RData::Aaaa(a.parse().unwrap()));
    for a in ["2001:db8::1", "2001:db8::2", "2001:db8::3"] {
        hear(&seg, a, vec![aaaa(a)]);
        std::thread::sleep(Duration::from_millis(5));
    }
    let addrs: Vec<IpAddr> = seg.devices()[0].addrs().collect();
    assert_eq!(addrs, [ip("2001:db8::2"), ip("2001:db8::3")]);
}

/// The addresses a packet repeats are not the ones to make room.
#[test]
fn making_room_leaves_the_addresses_a_packet_repeats() {
    let seg = segment("test");
    seg.set_max_addrs(2);
    let aaaa = |a: &str| record("phone.local".into(), false, 120, RData::Aaaa(a.parse().unwrap()));
    hear(&seg, "2001:db8::1", vec![aaaa("2001:db8::1")]);
    std::thread::sleep(Duration::from_millis(5));
    hear(&seg, "2001:db8::2", vec![aaaa("2001:db8::2")]);
    std::thread::sleep(Duration::from_millis(5));
    hear(&seg, "2001:db8::1", vec![aaaa("2001:db8::1")]);
    let addrs: Vec<IpAddr> = seg.devices()[0].addrs().collect();
    assert_eq!(addrs, [ip("2001:db8::1"), ip("2001:db8::2")]);
}

/// A device whose records all have this TTL, heard on `seg`.
fn hear_a_device_with_ttl(seg: &Segment, ttl: u32) {
    hear(seg, "10.0.1.30", vec![
        record("d.local".into(), true, ttl, RData::A("10.0.1.30".parse().unwrap())),
        record("D._x._tcp.local".into(), true, ttl, RData::Srv { priority: 0, weight: 0, port: 1, target: "d.local".into() }),
        record("_x._tcp.local".into(), false, ttl, RData::Ptr("D._x._tcp.local".into())),
    ]);
}

/// Is the device still known `secs` after it was heard, once expired as of then?
fn alive_after(seg: &Segment, secs: u64) -> bool {
    seg.expire(Instant::now() + Duration::from_secs(secs));
    !seg.devices().is_empty()
}

#[test]
fn the_minimum_lifetime_is_a_floor_under_a_devices_ttl_and_can_be_changed() {
    // Default: the 5 minute floor holds a 10 second TTL up to 300 s.
    let seg = segment("test");
    hear_a_device_with_ttl(&seg, 10);
    assert!(alive_after(&seg, 290));
    assert!(!alive_after(&seg, 301));

    // A shorter floor lets that device go sooner...
    let seg = segment("test");
    seg.set_min_lifetime(Duration::from_secs(60));
    hear_a_device_with_ttl(&seg, 10);
    assert!(alive_after(&seg, 50));
    assert!(!alive_after(&seg, 61));

    // ...a longer one keeps it longer...
    let seg = segment("test");
    seg.set_min_lifetime(Duration::from_secs(900));
    hear_a_device_with_ttl(&seg, 10);
    assert!(alive_after(&seg, 890));
    assert!(!alive_after(&seg, 901));

    // ...and zero means no floor: it lives for exactly its TTL.
    let seg = segment("test");
    seg.set_min_lifetime(Duration::ZERO);
    hear_a_device_with_ttl(&seg, 10);
    assert!(alive_after(&seg, 8));
    assert!(!alive_after(&seg, 11));
}

#[test]
fn a_ttl_longer_than_the_floor_still_wins() {
    let seg = segment("test");
    seg.set_min_lifetime(Duration::from_secs(60));
    hear_a_device_with_ttl(&seg, 4500);
    assert!(alive_after(&seg, 4490));
    assert!(!alive_after(&seg, 4501));
}

#[test]
fn refresh_follows_the_configured_floor() {
    let (seg, rx) = wired();
    seg.set_min_lifetime(Duration::from_secs(100));
    hear_a_device_with_ttl(&seg, 10); // lives 100 s
    let t0 = Instant::now();
    let before = Duration::from_secs(30);

    assert_eq!(seg.refresh(t0 + Duration::from_secs(60), before).unwrap(), 0, "not yet within 30 s of 100 s");
    assert!(recv(&rx).is_none());
    assert_eq!(seg.refresh(t0 + Duration::from_secs(70), before).unwrap(), 0, "a quarter of 100 s is less than 30 s: asked at 75");
    assert_eq!(seg.refresh(t0 + Duration::from_secs(76), before).unwrap(), 3, "within a quarter of it");
    assert!(recv(&rx).is_some());
}

// A device of another segment, announced by a handle to it.

/// `tv.local` with a service, heard on a segment.
fn tv_on(seg: &Segment) {
    hear(seg, "10.0.1.5", vec![a_record("tv.local", "10.0.1.5"), srv("TV._http._tcp.local", 80, "tv.local")]);
}

/// The longest name and service the configuration takes can be announced:
/// what it takes is what the codec can write.
#[test]
fn the_longest_name_and_services_the_configuration_takes_are_announced() {
    let label = |n: usize| "a".repeat(n);
    let host = format!("{}.{}.{}.{}.local", label(63), label(63), label(63), label(55));
    let services: String = (0..6).map(|i| format!("_{}{i}._tcp:{}", label(14), 1000 + i)).collect::<Vec<_>>().join(",");
    let config = crate::config::Config::parse(&format!(
        "[Advertise]\nHostname={host}\nServices={services}\n[Segment]\nName=s\nInterfaces=a"
    ))
    .unwrap();
    let (seg, rx) = wired();
    seg.advertise(&config.advertise[0], &[ip("10.0.0.5")]);
    assert_eq!(seg.reflected_devices().len(), 1);
    let announced = recv(&rx).expect("announced");
    assert!(announced.answers.iter().any(|r| r.name == host), "{announced:?}");
    assert!(announced.encode().is_ok());
}

/// `tv.local` saying goodbye to its address.
fn tv_leaves(seg: &Segment) {
    hear(seg, "10.0.1.5", vec![record("tv.local".into(), true, 0, RData::A(ip("10.0.1.5").to_string().parse().unwrap()))]);
}

/// Priorities of what is made for a segment, that rank behind the devices of
/// the segments there are.
const FIRST: u32 = 1_000_000;
const SECOND: u32 = FIRST + 1;

/// The way the `n`th reflector of the test shows a device, which is the same
/// every time: it is what tells one reflector's wish from another's.
fn reflector(n: usize) -> Rc<Advertise> {
    thread_local! {
        static HOWS: [Rc<Advertise>; 2] = [Rc::new(Advertise::ALL), Rc::new(Advertise::ALL)];
    }
    HOWS.with(|hows| Rc::clone(&hows[n]))
}

/// The device of `seg` called `host`, as a reflector is given it.
fn shown(seg: &Segment, host: &str) -> Shared {
    let named = |d: &Shared| d.borrow().hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host));
    seg.shared_devices().into_iter().find(named).expect("it is there")
}

/// `target` is shown the device of `origin` called `host` as it is now, by
/// the first reflector.
fn reflect_of(target: &Segment, origin: &Segment, host: &str) -> Result<bool> {
    target.reflect(origin.priority(), &shown(origin, host), &reflector(0), None)
}

#[test]
fn a_device_of_another_segment_is_announced_as_it_was_last_shown() {
    let (a, _arx) = wired();
    let (b, rx) = wired();
    tv_on(&a);
    assert_eq!(shown(&a, "TV.LOCAL").borrow().services.len(), 1);

    assert!(reflect_of(&b, &a, "tv.local").unwrap());
    assert_eq!(b.reflected_devices().len(), 1);
    let m = recv(&rx).expect("announced");
    assert!(m.answers.iter().any(|r| r.name == "tv.local" && r.ttl > 0));

    // It changes where it is; what is announced changes when the reflector says.
    hear(&a, "10.0.1.5", vec![srv("Web._http._tcp.local", 81, "tv.local")]);
    assert_eq!(b.reflected_devices()[0].services.len(), 1, "announced as last shown");
    assert!(reflect_of(&b, &a, "tv.local").unwrap());
    assert_eq!(b.reflected_devices()[0].services.len(), 2);
    assert!(recv(&rx).is_some(), "the change is announced");
    b.state.borrow().hosts.check();

    // Shown again with nothing changed, it says nothing more.
    age(&b, 2);
    reflect_of(&b, &a, "tv.local").unwrap();
    assert!(recv(&rx).is_none() || recv(&rx).is_none());
}

/// What is shown stays until it is withdrawn: the segment does not look at
/// where it came from, which the reflector does.
#[test]
fn a_reflected_device_is_withdrawn_with_goodbyes_when_the_reflector_says() {
    let (a, _arx) = wired();
    let (b, rx) = wired();
    tv_on(&a);
    reflect_of(&b, &a, "tv.local").unwrap();
    recv(&rx).unwrap();

    let tv = shown(&a, "tv.local");
    tv_leaves(&a);
    assert_eq!(b.reflected_devices().len(), 1, "still shown: nobody has said");
    assert!(b.remove_reflected(&reflector(0), &tv).unwrap());
    assert!(b.reflected_devices().is_empty());
    let bye = recv(&rx).expect("goodbyes");
    assert!(bye.answers.iter().all(|r| r.ttl == 0), "{bye:?}");
    assert!(b.state.borrow().hosts.is_empty());
    assert!(!b.remove_reflected(&reflector(0), &tv).unwrap(), "nothing left");
}

/// Several reflectors may show a device of the same segment, each as it is
/// to be shown by it: what is announced is what they show together,
/// whichever came first, and each is taken back on its own.
#[test]
fn what_two_reflectors_show_of_a_device_of_one_segment_is_announced_together() {
    let one = Shared::new(tv("10.0.1.1", &["One"]));
    let two = Shared::new(tv("10.0.1.1", &["Two"]));
    for (first, second) in [(&one, &two), (&two, &one)] {
        let (b, _rx) = wired();
        b.reflect(1, first, &reflector(0), None).unwrap();
        b.reflect(1, second, &reflector(1), None).unwrap();
        let shown = b.reflected_devices();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].services.len(), 2, "{shown:?}");
        assert_eq!(shown[0].addrs().count(), 1);

        b.remove_reflected(&reflector(0), first).unwrap();
        assert_eq!(b.reflected_devices()[0].services.len(), 1, "the other's is left");
        b.remove_reflected(&reflector(1), second).unwrap();
        assert!(b.reflected_devices().is_empty());
    }
}

/// A segment taken down withdraws what is announced on it, copies and its own
/// alike, with goodbyes, and says that its devices are gone, so that whoever
/// shows copies of them elsewhere withdraws them.
#[test]
fn a_segment_taken_down_withdraws_what_it_announced_and_says_its_devices_are_gone() {
    let (a, _arx) = wired();
    let (b, rx) = wired();
    tv_on(&a);
    reflect_of(&b, &a, "tv.local").unwrap();
    let router = Device { hostname: Some("router.local".into()), addresses: vec![ip("10.0.2.1").into()].into(), ..Device::default() };
    b.add_reflected(OWN, &Shared::new(router)).unwrap();
    assert_eq!(b.reflected_devices().len(), 2);
    while recv(&rx).is_some() {}
    a.take_events();

    a.destroy().unwrap();
    let events = a.take_events();
    assert!(matches!(&events[..], [Event::Removed(d)] if d.borrow().hostname.as_deref() == Some("tv.local")), "{events:?}");
    assert!(a.devices().is_empty());

    b.destroy().unwrap();
    let said: Vec<Record> = std::iter::from_fn(|| recv(&rx)).flat_map(|m| m.answers).collect();
    let bye = |name: &str| said.iter().any(|r| r.name == name && matches!(r.data, RData::A(_)) && r.ttl == 0);
    assert!(bye("tv.local") && bye("router.local"), "{said:?}");
    assert!(b.reflected_devices().is_empty());
    assert!(b.state.borrow().hosts.is_empty());
}

/// A segment that talks to a peer hears it alone, and takes its questions for
/// mDNS from whatever port it asks.
#[test]
fn a_segment_that_talks_to_a_peer_hears_it_alone() {
    let (rx, tx) = (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap());
    rx.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let seg = segment("tun");
    seg.attach(Link::to_peer(Family::V4, fd(tx), rx.local_addr().unwrap()));
    let peer = ip("127.0.0.1");

    // What the peer sends to the daemon is heard, whatever it is sent to; what anyone else sends is not,
    // even to the group.
    for to in [None, Some(ip("10.8.0.1")), Some(ip("224.0.0.251"))] {
        assert!(seg.accepts(peer, to), "{to:?}");
        assert!(!seg.accepts(ip("10.8.0.9"), to), "{to:?}");
        assert!(!seg.accepts(ip("fe80::9"), to), "{to:?}");
    }

    // A question from its port, whichever it is, is answered as mDNS is: to the peer, as to the group.
    seg.add_reflected(OWN, &Shared::new(tv("10.0.2.9", &["TV"]))).unwrap();
    while recv(&rx).is_some() {}
    age(&seg, 2);
    seg.handle(SocketAddr::new(peer, 5399), &query("tv.local", rtype::A, vec![])).unwrap();
    assert!(recv(&rx).is_some_and(|m| m.answers.iter().any(|r| r.name == "tv.local")), "answered to the peer");
    // From another port and no peer, it is a legacy resolver, answered by itself and not to the peer.
    // 127.0.0.2 is an address of the host on Linux; FreeBSD's loopback has to be given it (see the CI
    // job that runs the unit tests there).
    age(&seg, 2);
    seg.handle(SocketAddr::new(ip("127.0.0.2"), 5399), &query("tv.local", rtype::A, vec![])).unwrap();
    assert!(recv(&rx).is_none());
}

/// A device is the same one when it is renamed: it is withdrawn under the name
/// it had, and shown under the one it has.
#[test]
fn a_device_that_is_renamed_is_withdrawn_under_its_old_name_and_shown_under_the_new() {
    let (b, rx) = wired();
    let device = Shared::new(tv("10.0.1.1", &["TV"]));
    let how = reflector(0);
    b.reflect(1, &device, &how, None).unwrap();
    recv(&rx).unwrap();

    device.borrow_mut().hostname = Some("lounge.local".into());
    b.reflect(1, &device, &how, None).unwrap();
    let said: Vec<Record> = std::iter::from_fn(|| recv(&rx)).flat_map(|m| m.answers).collect();
    let a = |name: &str, live: bool| said.iter().any(|r| r.name == name && matches!(r.data, RData::A(_)) && (r.ttl > 0) == live);
    assert!(a("tv.local", false) && a("lounge.local", true), "{said:?}");
    assert_eq!(b.reflected_devices()[0].hostname.as_deref(), Some("lounge.local"));
    b.state.borrow().hosts.check();

    assert!(b.remove_reflected(&how, &device).unwrap(), "found by the device, under its new name");
    assert!(b.reflected_devices().is_empty());
    assert!(b.state.borrow().hosts.is_empty());
}

/// Of devices of one name from different segments, the lowest segment's is
/// announced, whoever shows them, and the next takes over when it goes.
#[test]
fn of_one_name_from_two_segments_the_lowest_is_announced_and_the_next_takes_over() {
    let (b, _rx) = wired();
    let (low, high) = (Shared::new(tv("10.0.1.1", &["Low"])), Shared::new(tv("10.0.2.2", &["High"])));
    // Shown in the order that is not the segments'.
    b.reflect(2, &high, &reflector(1), None).unwrap();
    b.reflect(1, &low, &reflector(0), None).unwrap();
    let shown = b.reflected_devices();
    assert_eq!(shown.len(), 1);
    assert!(shown[0].addrs().eq([ip("10.0.1.1")]), "{shown:?}");

    b.remove_reflected(&reflector(0), &low).unwrap();
    assert!(b.reflected_devices()[0].addrs().eq([ip("10.0.2.2")]), "the other takes over");

    b.reflect(1, &low, &reflector(0), None).unwrap();
    assert!(b.reflected_devices()[0].addrs().eq([ip("10.0.1.1")]), "back, and first");
    b.withdraw_all(&reflector(0)).unwrap();
    assert!(b.reflected_devices()[0].addrs().eq([ip("10.0.2.2")]));
    b.remove_reflected(&reflector(1), &high).unwrap();
    assert!(b.reflected_devices().is_empty());
}

#[test]
fn what_an_owner_wanted_is_withdrawn_all_at_once_and_the_others_kept() {
    let (a, _arx) = wired();
    let (b, _brx) = wired();
    tv_on(&a);
    hear(&a, "10.0.1.6", vec![a_record("nas.local", "10.0.1.6"), srv("NAS._smb._tcp.local", 445, "nas.local")]);
    for host in ["tv.local", "nas.local"] {
        reflect_of(&b, &a, host).unwrap();
    }
    b.add_reflected(SECOND, &Shared::new(tv("10.0.9.9", &["Other"]))).unwrap();
    assert_eq!(b.reflected_devices().len(), 2, "tv.local has two who want it, the first one's is announced");

    b.withdraw_all(&reflector(0)).unwrap();
    let left = b.reflected_devices();
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].hostname.as_deref(), Some("tv.local"), "the other owner's is announced instead");
    assert!(left[0].addrs().any(|addr| addr == ip("10.0.9.9")));
    b.state.borrow().hosts.check();
}

#[test]
fn a_device_without_a_hostname_or_a_ttl_of_zero_is_not_reflected() {
    let (a, _arx) = wired();
    let (b, _brx) = wired();
    hear(&a, "10.0.1.5", vec![ptr("_http._tcp.local", "Bare._http._tcp.local")]);
    tv_on(&a);
    let bare = a.state.borrow().tracker.discovered.find_nameless(&ip("10.0.1.5"));
    assert!(bare.is_none(), "heard from the address of a named device");
    let named = shown(&a, "tv.local");
    let err = b.reflect(a.priority(), &named, &reflector(0), Some(Duration::ZERO)).unwrap_err();
    assert!(format!("{err}").contains("zero"));
    assert!(b.reflected_devices().is_empty());
    // The TTL it is given is the one its address is announced with.
    b.reflect(a.priority(), &named, &reflector(0), Some(Duration::from_secs(900))).unwrap();
    assert_eq!(b.state.borrow().hosts["tv.local"].host_ttl(), 900);
}

// What a full segment costs. Not a test: run it with
// `cargo test --release scale -- --ignored --nocapture`.

/// Counts the heap the tests hold, for what a device costs in memory.
struct Counting;

static LIVE_BYTES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LIVE_BLOCKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

// SAFETY: everything is the system allocator's; only counts are kept.
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        use core::sync::atomic::Ordering::Relaxed;
        let p = unsafe { std::alloc::System.alloc(layout) };
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Relaxed);
            LIVE_BLOCKS.fetch_add(1, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        use core::sync::atomic::Ordering::Relaxed;
        unsafe { std::alloc::System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Relaxed);
        LIVE_BLOCKS.fetch_sub(1, Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        use core::sync::atomic::Ordering::Relaxed;
        let p = unsafe { std::alloc::System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE_BYTES.fetch_add(new_size, Relaxed);
            LIVE_BYTES.fetch_sub(layout.size(), Relaxed);
        }
        p
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The heap held now, in bytes and in blocks.
fn heap() -> (usize, usize) {
    use core::sync::atomic::Ordering::Relaxed;
    (LIVE_BYTES.load(Relaxed), LIVE_BLOCKS.load(Relaxed))
}

/// A segment that has heard `n` devices, each from an address of its own
/// (a sender may describe only so many), with an address that runs out
/// before the device does, as a host's address does against its services.
fn crowded(n: usize) -> Segment {
    crowded_named(n, "host", 1)
}

/// Like [`crowded`], with hosts called `{prefix}{i}.local`, on 10.`net`.x.y.
fn crowded_named(n: usize, prefix: &str, net: usize) -> Segment {
    let (seg, _rx) = wired();
    seg.set_refresh_before(Some(Duration::from_secs(30)));
    seg.set_max_devices(n + 1);
    for i in 0..n {
        let (host, instance) = (format!("{prefix}{i}.local"), format!("Dev{i}._http._tcp.local"));
        let from = format!("10.{net}.{}.{}", i / 250, i % 250 + 1);
        hear(&seg, &from, vec![
            ptr("_http._tcp.local", &instance),
            srv(&instance, 80, &host),
            txt(&instance, "ty=x"),
            a_record(&host, &from),
        ]);
    }
    // What the event loop would have taken.
    seg.take_events();
    assert_eq!(seg.devices().len(), n);
    seg
}

/// The time `f` takes, on average over `runs`, in microseconds.
fn micros(runs: u32, mut f: impl FnMut()) -> f64 {
    let start = std::time::Instant::now();
    for _ in 0..runs {
        f();
    }
    start.elapsed().as_secs_f64() * 1e6 / f64::from(runs)
}

#[test]
#[ignore = "a measurement, not a check"]
fn scale_of_what_a_full_segment_costs() {
    CHECKING.with(|checking| checking.set(false));
    println!(
        "{:>7} {:>9} {:>9} {:>8} {:>11} {:>10} {:>10} {:>11} {:>12} {:>9}",
        "devices", "heap MiB", "bytes/dev", "blocks/d", "next_due us", "upkeep us", "handle us", "forward us", "neighbour us", "expire ms"
    );
    for n in [1, 128, DEFAULT_MAX_DEVICES - 1, 4096, 10_000] {
        let (bytes, blocks) = heap();
        let seg = crowded(n);
        let (b, k) = heap();
        let (held, blocks_held) = (b - bytes, k - blocks);

        let next_due = micros(500, || {
            std::hint::black_box(seg.next_due());
        });
        let upkeep = micros(50, || seg.upkeep(Instant::now()));
        // A device that is already known announcing itself again: what a
        // packet costs from a device that has been heard before.
        let again = announcement(120);
        seg.handle(sa("10.0.1.7"), &again).unwrap();
        let handle = micros(500, || seg.handle(sa("10.0.1.7"), &again).unwrap());

        // A question asked on another segment, put to this one with what is known
        // of it as known answers; a different one each time, as it is asked at most
        // once a second.
        let mut asked = 0;
        let forward = micros(200, || {
            asked += 1;
            seg.query_question(&[question(&format!("_t{asked}._tcp.local"), rtype::PTR)]).unwrap();
        });
        // The one question that every device with a service answers: which types
        // there are. Once, as it is asked at most once a second.
        let start = std::time::Instant::now();
        seg.query_question(&[question("_services._dns-sd._udp.local", rtype::PTR)]).unwrap();
        let enumeration = start.elapsed().as_secs_f64() * 1e6;
        println!("   asking for the types there are: {enumeration:.0} us");
        // The kernel's neighbour table changing: an address at another link-layer address.
        let mut moved = 0u8;
        let neighbour = micros(200, || {
            moved = moved.wrapping_add(1);
            seg.neighbour(ip("10.1.0.1"), Some(vec![moved; 6]));
        });

        // Every device running out at once, as when all go quiet together.
        let start = std::time::Instant::now();
        seg.expire(Instant::now() + Duration::from_secs(2 * 3600));
        let expire = start.elapsed().as_secs_f64() * 1e3;
        assert!(seg.devices().is_empty());
        seg.take_events();
        drop(seg);
        let (b, _) = heap();

        println!(
            "{n:>7} {:>9.2} {:>9} {:>8.1} {next_due:>11.1} {upkeep:>10.1} {handle:>10.1} {forward:>11.1} {neighbour:>12.1} {expire:>9.1}  (heap after: {} B)",
            held as f64 / 1_048_576.0,
            held / n,
            blocks_held as f64 / n as f64,
            b.saturating_sub(bytes),
        );
    }
}

/// What reflecting costs: a segment that has heard `n` devices and is
/// made to announce `n` more, from other segments, answering queries and
/// hearing new devices. Run it like the other.
#[test]
#[ignore = "a measurement, not a check"]
fn scale_of_what_a_full_segment_costs_to_reflect_with() {
    CHECKING.with(|checking| checking.set(false));
    println!(
        "{:>7} {:>10} {:>12} {:>12} {:>13} {:>14} {:>10}",
        "devices", "heap MiB", "query us", "new host us", "add reflected us", "reannounce us", "next_due us"
    );
    for n in [1, 128, DEFAULT_MAX_DEVICES - 1, 4096] {
        let (bytes, _) = heap();
        let seg = crowded(n);
        seg.set_max_devices(n + 1000);
        seg.set_reannounce(true);
        // The devices of another segment, which this one announces by handles
        // to them.
        let other = crowded_named(n, "m", 2);
        let (reflected_from, _) = heap();
        for i in 0..n {
            reflect_of(&seg, &other, &format!("m{i}.local")).unwrap();
        }
        seg.take_events();
        let (b, _) = heap();
        println!("   reflected by a handle: {} B/dev", (b - reflected_from) / n.max(1));

        // A client asking for the name of one of them, each time another.
        let mut asked = 0;
        let query_us = micros(100, || {
            asked += 1;
            seg.handle(sa("10.0.0.50"), &query(&format!("m{}.local", asked % n.max(1)), rtype::A, vec![])).unwrap();
        });
        seg.take_events();

        // A device heard for the first time.
        let mut heard = 0;
        let new_host = micros(100, || {
            heard += 1;
            let (host, from) = (format!("new{heard}.local"), format!("10.3.0.{}", heard % 250 + 1));
            hear(&seg, &from, vec![a_record(&host, &from)]);
        });
        seg.take_events();

        // Another to announce.
        let mut added = 0;
        let add = micros(100, || {
            added += 1;
            let mut device = tv("10.4.0.1", &["X"]);
            device.hostname = Some(format!("x{added}.local"));
            device.services[0].edit(|p| p.instance = format!("X{added}._http._tcp.local"));
            seg.add_reflected(FIRST, &Shared::new(device)).unwrap();
        });

        // The upkeep when nothing is due.
        let upkeep = micros(50, || seg.upkeep(Instant::now()));
        let next_due = micros(200, || {
            std::hint::black_box(seg.next_due());
        });
        println!(
            "{n:>7} {:>10.2} {query_us:>12.1} {new_host:>12.1} {add:>13.1} {upkeep:>14.1} {next_due:>10.1}",
            (b - bytes) as f64 / 1_048_576.0,
        );
    }
}

// The timer-driven upkeep.

fn expiry_of(seg: &Segment, host: &str) -> Instant {
    let state = seg.state.borrow();
    state.tracker.discovered.get(host_id(&state, host)).expires
}

fn next_due(seg: &Segment) -> Option<Instant> {
    seg.state.borrow_mut().next_due(Instant::now())
}

#[test]
fn the_next_deadline_is_the_earliest_of_expiry_refresh_and_reannounce() {
    let (seg, _rx) = wired();
    assert_eq!(next_due(&seg), None, "nothing known, nothing due");

    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let expires = expiry_of(&seg, "printer.local");
    assert_eq!(next_due(&seg), Some(expires));

    // Asking ahead of expiry makes it earlier...
    seg.set_refresh_before(Some(Duration::from_secs(60)));
    assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(60)));

    // ...until it was asked: then the gap (a quarter of the margin) has to pass.
    seg.refresh(expires - Duration::from_secs(60), Duration::from_secs(60)).unwrap();
    assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)));

    // A reflected device is due for re-announcement, and a failed one not before its retry.
    seg.add_reflected(OWN, &Shared::new(tv("10.0.9.9", &["TV"]))).unwrap();
    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)).min(Some(announced + ANNOUNCE_REPEAT)));
    seg.state.borrow_mut().hosts.edit("tv.local", |m| m.retry = Some(announced + Duration::from_secs(500)));
    assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)));
}

#[test]
fn pending_lists_everything_the_upkeep_waits_for_soonest_first() {
    let (seg, _rx) = wired();
    seg.set_refresh_before(Some(Duration::from_secs(60)));
    assert!(seg.pending().is_empty());

    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    seg.observe(ip("10.0.1.99")); // heard, but never named
    seg.add_reflected(OWN, &Shared::new(tv("10.0.9.9", &["TV"]))).unwrap();

    let expires = expiry_of(&seg, "printer.local");
    let pending = seg.pending();
    let rows: Vec<(&str, &str)> = pending.iter().map(|p| (p.what, p.who.as_str())).collect();
    // The unnamed one is by address and only expires: there is nothing to ask it.
    assert_eq!(rows.iter().filter(|(_, who)| *who == "10.0.1.99").collect::<Vec<_>>(), [&("expire", "10.0.1.99")]);
    assert!(rows.contains(&("expire", "printer.local")) && rows.contains(&("refresh", "printer.local")));
    assert!(rows.contains(&("re-announce", "tv.local")));
    assert_eq!(rows.len(), 4);
    // A name is shown as it is announced, not as it is filed, lowercase.
    let mut mixed = tv("10.0.9.10", &[]);
    mixed.hostname = Some("Living-Room-TV.local".into());
    seg.add_reflected(FIRST, &Shared::new(mixed)).unwrap();
    assert!(seg.pending().iter().any(|p| p.what == "re-announce" && p.who == "Living-Room-TV.local"), "{:?}", seg.pending());
    assert!(pending.windows(2).all(|w| w[0].at <= w[1].at), "soonest first");
    // The upkeep is due at the first of them.
    assert_eq!(next_due(&seg), Some(pending[0].at));
    let refresh = pending.iter().find(|p| p.what == "refresh").unwrap();
    assert_eq!(refresh.at, expires - Duration::from_secs(60));
    // Without a refresh margin nothing is asked.
    seg.set_refresh_before(None);
    assert!(seg.pending().iter().all(|p| p.what != "refresh"));
}

#[test]
fn a_name_can_be_announced_with_its_own_ttl_and_is_kept_up_at_80_percent_of_it() {
    let (seg, rx) = wired();
    seg.set_reannounce(true);
    seg.add_reflected_ttl(OWN, &Shared::new(tv("10.0.1.1", &[])), Duration::from_secs(1000)).unwrap();
    let first = recv(&rx).unwrap();
    assert!(first.answers.iter().all(|r| r.ttl == 1000));
    assert!(repeat(&seg, &rx).answers.iter().all(|r| r.ttl == 1000));
    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    assert_eq!(seg.state.borrow_mut().hosts["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(800)));

    // Queries are answered with it too.
    age(&seg, 2);
    seg.handle(sa("10.0.1.50"), &query("tv.local", rtype::A, vec![])).unwrap();
    assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 1000));

    // Not yet at 799 s; again at 800, with the same TTL.
    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    seg.reannounce(announced + Duration::from_secs(799)).unwrap();
    assert!(recv(&rx).is_none());
    seg.reannounce(announced + Duration::from_secs(800)).unwrap();
    assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 1000));

    // The usual way is unchanged, and a TTL of zero (a goodbye) is refused.
    let (usual, rx) = wired();
    usual.add_reflected(OWN, &Shared::new(tv("10.0.1.1", &[]))).unwrap();
    assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == HOST_TTL || r.ttl == OTHER_TTL));
    assert!(usual.add_reflected_ttl(OWN, &Shared::new(tv("10.0.1.2", &[])), Duration::from_millis(900)).is_err());
}

/// `tv.local` as it announced itself: an address with `addr` seconds, and a
/// service with `svc` (0: not known).
fn tv_with_ttls(addr: Option<u32>, svc: u32) -> Device {
    let mut device = tv("10.0.1.1", &["TV"]);
    device.ttl = addr;
    device.services[0].edit(|p| p.ttl = svc);
    device
}

/// (is an address record, ttl) of what was announced, without the type
/// enumeration, which is the daemon's.
fn announced_ttls(rx: &UdpSocket) -> Vec<(bool, u32)> {
    let sent = recv(rx).unwrap();
    sent.answers
        .iter()
        .filter(|r| !r.name.starts_with("_services."))
        .map(|r| (matches!(r.data, RData::A(_)), r.ttl))
        .collect()
}

#[test]
fn a_device_is_announced_with_the_ttls_it_announced_itself_with() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv_with_ttls(Some(300), 600))).unwrap();
    let ttls = announced_ttls(&rx);
    assert!(ttls.contains(&(true, 300)), "{ttls:?}");
    assert!(ttls.iter().filter(|(is_addr, _)| !is_addr).all(|(_, ttl)| *ttl == 600), "{ttls:?}");

    // It is announced again before the shortest of them runs out: 80% of 300.
    repeat(&seg, &rx);
    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    assert_eq!(seg.state.borrow_mut().hosts["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(240)));
}

#[test]
fn a_short_service_ttl_brings_the_reannouncement_forward() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv_with_ttls(Some(300), 50))).unwrap();
    assert!(announced_ttls(&rx).contains(&(false, 50)));
    repeat(&seg, &rx);
    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    assert_eq!(seg.state.borrow_mut().hosts["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(40)));
}

#[test]
fn what_a_device_did_not_say_gets_the_usual_ttl_and_tiny_ones_are_raised() {
    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv_with_ttls(None, 0))).unwrap();
    let ttls = announced_ttls(&rx);
    assert!(ttls.contains(&(true, HOST_TTL)) && ttls.contains(&(false, OTHER_TTL)), "{ttls:?}");

    let (seg, rx) = wired();
    seg.add_reflected(OWN, &Shared::new(tv_with_ttls(Some(2), 3))).unwrap();
    let ttls = announced_ttls(&rx);
    assert!(ttls.iter().all(|(_, ttl)| *ttl == MIN_REFLECT_TTL), "{ttls:?}");
}

#[test]
fn a_given_address_ttl_wins_for_the_address_only() {
    let (seg, rx) = wired();
    seg.add_reflected_ttl(OWN, &Shared::new(tv_with_ttls(Some(300), 600)), Duration::from_secs(900)).unwrap();
    let ttls = announced_ttls(&rx);
    assert!(ttls.contains(&(true, 900)), "{ttls:?}");
    assert!(ttls.iter().filter(|(is_addr, _)| !is_addr).all(|(_, ttl)| *ttl == 600), "{ttls:?}");
    // The services run out first, and it is announced again before that.
    repeat(&seg, &rx);
    let announced = seg.state.borrow_mut().hosts["tv.local"].announced;
    assert_eq!(seg.state.borrow_mut().hosts["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(480)));
}

#[test]
fn a_device_known_only_by_address_has_announced_no_ttls() {
    let seg = segment("test");
    seg.observe(ip("10.0.1.99"));
    let bare = seg.devices().remove(0);
    assert_eq!((bare.ttl, bare.services.len()), (None, 0));
}

#[test]
fn a_segment_that_cannot_send_has_nothing_to_refresh() {
    let seg = segment("test");
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    seg.set_refresh_before(Some(Duration::from_secs(60)));
    // Only the expiry: refresh would return at once without asking, and
    // being due, it would spin.
    assert_eq!(next_due(&seg), Some(expiry_of(&seg, "printer.local")));
}

#[test]
fn a_margin_too_big_for_the_clock_neither_panics_nor_spins() {
    let (seg, rx) = wired();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    seg.set_refresh_before(Some(Duration::MAX));
    // Everything is within that margin of its expiry, so it is asked, three
    // quarters of the way in...
    let asked_at = Instant::now() + FLOOR * 3 / 4;
    assert!(next_due(&seg).unwrap() <= asked_at + Duration::from_millis(50));
    assert!(seg.refresh(asked_at + Duration::from_secs(1), Duration::MAX).unwrap() > 0);
    assert!(recv(&rx).is_some());
    // ...once, and then not again until it has expired.
    assert_eq!(next_due(&seg), Some(expiry_of(&seg, "printer.local")));
}

#[test]
fn a_device_is_dropped_the_moment_it_expires() {
    let (seg, _rx) = wired();
    let events = seg.subscribe();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

    // Not on a tick: due in 150 ms, it is due then, and the upkeep then
    // drops it.
    let at = Instant::now() + Duration::from_millis(150);
    set_expiry(&seg, "printer.local", at);
    assert_eq!(seg.next_due(), Some(at));
    seg.upkeep(at);
    assert!(matches!(events.try_iter().last(), Some(Event::Removed(_))));
    assert!(seg.devices().is_empty());
    assert_eq!(seg.upkeep_info().runs, 1);
}

#[test]
fn a_device_heard_is_due_when_it_runs_out() {
    let (seg, _rx) = wired();
    seg.set_min_lifetime(Duration::ZERO);
    assert_eq!(seg.next_due(), None, "nothing known: never");
    let before = Instant::now();
    hear_a_device_with_ttl(&seg, 1);
    let due = seg.next_due().expect("due");
    assert!(due >= before + Duration::from_secs(1) && due <= Instant::now() + Duration::from_secs(1));
}

#[test]
fn a_device_is_asked_the_margin_before_it_expires() {
    let (seg, rx) = wired();
    seg.set_refresh_before(Some(Duration::from_millis(100)));
    let events = seg.subscribe();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

    let start = Instant::now();
    let expires = start + Duration::from_millis(500);
    set_expiry(&seg, "printer.local", expires);
    assert_eq!(seg.next_due(), Some(start + Duration::from_millis(400)));
    seg.upkeep(start + Duration::from_millis(400));
    let query = recv(&rx).expect("asked");
    assert!(asked(&query).contains(&q("printer.local", rtype::A)));
    // It does not answer, so it goes.
    seg.upkeep(expires);
    assert!(matches!(events.try_iter().last(), Some(Event::Removed(_))));
}

#[test]
fn lifetime_left_is_what_the_daemon_will_keep_a_device() {
    let (seg, _rx) = wired();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let device = seg.devices().remove(0);
    // Its records say 120 seconds, but it is kept for at least the floor.
    assert_eq!(seg.lifetime_left(&device), FLOOR);

    // Where there is no floor, the default, it is kept for its TTL.
    let (seg, _rx) = wired();
    seg.set_min_lifetime(Duration::ZERO);
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let device = seg.devices().remove(0);
    assert_eq!(seg.lifetime_left(&device), Duration::from_secs(120));

    // One that is gone has no time left, and neither has a stranger.
    seg.expire(Instant::now() + Duration::from_secs(3600));
    assert_eq!(seg.lifetime_left(&device), Duration::ZERO);
    assert_eq!(seg.lifetime_left(&unnamed("10.9.9.9")), Duration::ZERO);
}

#[test]
fn events_wait_to_be_taken() {
    let seg = segment("test");
    seg.observe(ip("10.0.1.5"));
    seg.observe(ip("10.0.1.6"));
    assert_eq!(seg.take_events().len(), 2);
    assert!(seg.take_events().is_empty(), "taken");
    assert!(seg.is(&seg.clone()) && !seg.is(&segment("test")));
}

/// Service types learned from the enumeration are one per type, whatever
/// their case.
#[test]
fn service_types_are_learned_once_whatever_their_case() {
    let seg = segment("test");
    let meta = |kind: &str| ptr("_services._dns-sd._udp.local", kind);
    hear(&seg, "10.0.1.7", vec![meta("_http._tcp.local"), meta("_HTTP._tcp.LOCAL")]);
    assert_eq!(seg.state.borrow_mut().tracker.types.len(), 1);
}

/// Subtypes are not sent in answers to a browse of their type, so a probe
/// asks for the well-known ones of the types around, and for those heard.
#[test]
fn probe_asks_for_the_subtypes_clients_browse_by_and_those_heard_of() {
    let (seg, rx) = wired();
    hear(&seg, "10.0.1.8", vec![
        a_record("printer.local", "10.0.1.8"),
        ptr("_ipp._tcp.local", "Office._ipp._tcp.local"),
        ptr("_scanner._sub._http._tcp.local", "Office._http._tcp.local"),
        srv("Office._ipp._tcp.local", 631, "printer.local"),
        srv("Office._http._tcp.local", 80, "printer.local"),
    ]);
    seg.probe_round().unwrap();
    let mut all = BTreeSet::new();
    while let Some(m) = recv(&rx) {
        all.extend(asked(&m));
    }
    assert!(all.contains(&q("_universal._sub._ipp._tcp.local", rtype::PTR)));
    assert!(all.contains(&q("_printer._sub._http._tcp.local", rtype::PTR)));
    assert!(all.contains(&q("_scanner._sub._http._tcp.local", rtype::PTR)), "heard of here");
    assert!(!all.contains(&q("_universal._sub._ipps._tcp.local", rtype::PTR)), "no _ipps here");
    assert!(!all.iter().any(|(name, _)| name.contains("_matterc")));
}

fn nsec(name: &str, types: &[u16]) -> Record {
    record(name.into(), true, 120, RData::Nsec { next: name.into(), types: types.to_vec() })
}

/// A copy giving way to a device here of the same name takes back its
/// address, but not its NSEC, which may be just what the device's says.
#[test]
fn a_copy_giving_way_leaves_the_nsec_of_the_device_here_alone() {
    let (seg, rx) = wired();
    let mut copy = tv("10.0.2.9", &[]);
    copy.nsec = Some(vec![rtype::A].into());
    seg.add_reflected(FIRST, &Shared::new(copy)).unwrap();
    recv(&rx).unwrap();

    hear(&seg, "10.0.1.5", vec![a_record("tv.local", "10.0.1.5"), nsec("tv.local", &[rtype::A])]);
    let bye = recv(&rx).unwrap();
    assert_eq!(bye.answers.len(), 1, "{:?}", bye.answers);
    assert_eq!((&bye.answers[0].data, bye.answers[0].ttl), (&RData::A("10.0.2.9".parse().unwrap()), 0));
}

#[test]
fn ingest_fills_in_hostname_and_services() {
    let seg = segment("test");
    let rx = seg.subscribe();
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

    let devices = seg.devices();
    assert_eq!(devices.len(), 1);
    let d = &devices[0];
    assert_eq!(d.hostname.as_deref(), Some("printer.local"));
    assert_eq!(d.services.len(), 1);
    let s = &d.services[0];
    assert_eq!(s.instance(), "Printer._http._tcp.local");
    assert_eq!(s.kind(), "_http._tcp.local");
    assert_eq!((s.port(), s.target().as_deref()), (631, Some("printer.local")));
    assert_eq!(s.txt().collect::<Vec<_>>(), vec![b"ty=hp".to_vec()]);

    assert!(matches!(rx.try_recv(), Ok(Event::Added(_))));
    assert!(rx.try_recv().is_err());

    // Same data again is not a change.
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    assert!(rx.try_recv().is_err());
}

#[test]
fn later_packet_updates_and_ttl0_removes_service() {
    let seg = segment("test");
    seg.observe(ip("10.0.1.7"));
    let rx = seg.subscribe();

    // The device heard only by address now says who it is.
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    assert!(matches!(rx.try_recv(), Ok(Event::Removed(d)) if d.borrow().hostname.is_none()));
    assert!(matches!(rx.try_recv(), Ok(Event::Added(d)) if d.borrow().hostname.is_some() && d.borrow().services.len() == 1));

    // Goodbye for the service records only (no address record).
    let mut p = response(1);
    let mut ptr = vec![7];
    ptr.extend(b"Printer");
    ptr.extend(labels(&["_http", "_tcp", "local"]));
    rr(&mut p, &["_http", "_tcp", "local"], 12, 0, &ptr);
    seg.handle(sa("10.0.1.7"), &p).unwrap();
    assert!(matches!(rx.try_recv(), Ok(Event::Updated(d)) if d.borrow().services.is_empty()));
    assert_eq!(seg.devices().len(), 1);
}

#[test]
fn address_goodbye_removes_device() {
    let seg = segment("test");
    seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
    let rx = seg.subscribe();
    seg.handle(sa("10.0.1.7"), &announcement(0)).unwrap();
    assert!(seg.devices().is_empty());
    assert!(matches!(rx.try_recv(), Ok(Event::Removed(_))));
}

#[test]
fn long_ttl_extends_lifetime() {
    let seg = segment("test");
    seg.handle(sa("10.0.1.7"), &announcement(4500)).unwrap();
    seg.expire(Instant::now() + FLOOR + Duration::from_secs(1));
    assert_eq!(seg.devices().len(), 1);
    seg.expire(Instant::now() + Duration::from_secs(4501));
    assert!(seg.devices().is_empty());
}

#[test]
fn garbage_still_counts_as_alive() {
    let seg = segment("test");
    seg.handle(sa("10.0.1.5"), b"\xff\xff not dns").unwrap();
    assert_eq!(seg.devices().len(), 1);
}

#[test]
fn query_records_are_ignored() {
    let seg = segment("test");
    let mut p = announcement(120);
    p[2] = 0x00; // clear QR: a query carrying known answers
    seg.handle(sa("10.0.1.8"), &p).unwrap();
    let d = &seg.devices()[0];
    assert!(d.hostname.is_none() && d.services.is_empty());
}

/// Manual check of the real send path: `MDNS_TEST_IFACE=br cargo test
/// live_announce -- --ignored --nocapture`, with a listener on the group.
#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
#[test]
#[ignore]
fn live_announce() {
    let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
    for family in [Family::V4, Family::V6] {
        // Let a listener on this same host hear it.
        let (_socket, link) = crate::listener::looped(&iface, family);
        let seg = segment(&iface);
        seg.attach(link);
        let addr = match family {
            Family::V4 => ip("10.9.9.9"),
            Family::V6 => ip("fd00::9"),
        };
        let device = Shared::new(tv(&addr.to_string(), &["LiveTV"]));
        seg.add_reflected(OWN, &device).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        seg.remove_reflected(&seg.own(), &device).unwrap();
    }
}

/// Manual check of query handling over the real network: announces a
/// device on `MDNS_TEST_IFACE` (IPv4), then answers queries for 4s.
#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
#[test]
#[ignore]
fn live_respond() {
    let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
    let (socket, link) = crate::listener::looped(&iface, Family::V4);
    let seg = segment(&iface);
    seg.attach(link);
    seg.add_reflected(OWN, &Shared::new(tv("10.9.9.9", &["LiveTV"]))).unwrap();
    age(&seg, 2);

    // SAFETY: a descriptor given up by its owner.
    let udp: UdpSocket = unsafe { std::os::fd::FromRawFd::from_raw_fd(rustix::fd::IntoRawFd::into_raw_fd(socket)) };
    udp.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let end = Instant::now() + Duration::from_secs(4);
    let mut buf = [0u8; 9000];
    while Instant::now() < end {
        if let Ok((n, from)) = udp.recv_from(&mut buf) {
            seg.handle(from, &buf[..n]).unwrap();
        }
    }
}
