use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use super::*;
use crate::config::{Advertise, Neighbours};
use crate::device::Device;
use crate::segment::OWN;

/// `socket` as the segment takes a socket.
fn fd(socket: std::net::UdpSocket) -> rustix::fd::OwnedFd {
    use std::os::fd::IntoRawFd;
    // SAFETY: a descriptor just given up by its owner.
    unsafe { rustix::fd::FromRawFd::from_raw_fd(socket.into_raw_fd()) }
}
use crate::codec::{rtype, Header, Message, Question, RData, Record};
use crate::socket::{prefix, Family};

/// Its first routable IPv4 or IPv6 address, and link-local one.
fn v4(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv4())
}
fn v6(d: &Device) -> Option<IpAddr> {
    d.routable().find(|a| a.is_ipv6())
}
fn ll6(d: &Device) -> Option<IpAddr> {
    d.addrs().find(|a| a.is_ipv6() && crate::device::is_link_local(a))
}

/// A segment whose "multicast group" is a local socket we can read.
fn wired(name: &str) -> (Segment, UdpSocket) {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let seg = Segment::new(name, &[Family::V4]);
    seg.attach(Family::V4, fd(tx), rx.local_addr().unwrap());
    (seg, rx)
}

/// Like [`wired`], for an IPv6 segment.
fn wired_v6(name: &str) -> (Segment, UdpSocket) {
    let (_, rx) = wired(name);
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let seg = Segment::new(name, &[Family::V6]);
    seg.attach(Family::V6, fd(tx), rx.local_addr().unwrap());
    (seg, rx)
}

#[test]
fn notices_follow_every_segment_it_spans() {
    let (a, _ra) = wired("a");
    let (b, _rb) = wired("b");
    let reflector = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let next = || {
        deliver_made();
        let mut notices = reflector.take_notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        notices.remove(0)
    };

    a.observe("10.0.1.1".parse().unwrap());
    let first = next();
    assert_eq!(first.interface, "a");
    assert!(matches!(first.event, Event::Added(_)));
    // Kept for at least the floor, whatever its records said.
    assert_eq!(first.ttl, crate::config::DEFAULT_MIN_LIFETIME);

    b.observe("10.0.2.2".parse().unwrap());
    assert_eq!(next().interface, "b");

    // Gone is ttl 0.
    a.expire(Instant::now() + Duration::from_secs(3600));
    let gone = next();
    assert!(matches!(gone.event, Event::Removed(_)));
    assert_eq!((gone.interface.as_str(), gone.ttl), ("a", Duration::ZERO));
    assert!(reflector.take_notices().is_empty(), "taken");
}

fn drain(rx: &UdpSocket) -> Vec<Message> {
    let mut buf = [0u8; 9000];
    let mut out = Vec::new();
    while let Ok((n, _)) = rx.recv_from(&mut buf) {
        out.push(Message::parse(&buf[..n]).unwrap());
    }
    out
}

/// Deliver what has changed, as the event loop would, and check `cond`
/// holds then.
fn wait_for(cond: impl Fn() -> bool) {
    deliver_made();
    assert!(cond(), "not so once delivered");
}

fn rec(name: &str, data: RData) -> Record {
    rec_ttl(name, data, 120)
}

fn rec_ttl(name: &str, data: RData, ttl: u32) -> Record {
    Record { name: name.into(), class: 1, cache_flush: false, ttl, data }
}

/// Make `seg` hear `host` at `from` announcing one service per instance.
/// What reflecting one more device, and withdrawing it, costs as more are
/// reflected already. Not a test: run it with
/// `cargo test --release reflecting_one_more -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn reflecting_one_more_device_costs() {
    crate::segment::set_checking(false);
    println!("{:>8} {:>14} {:>16}", "devices", "one more us", "its goodbye us");
    for n in [10usize, 100, 400, 1000, 4000] {
        let (a, _arx) = wired("a");
        let (b, _brx) = wired("b");
        a.set_max_devices(n + 100);
        let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
        for i in 0..n {
            announce(&a, &format!("10.1.{}.{}", i / 250, i % 250 + 1), &format!("h{i}.local"), &[&format!("S{i}")]);
            deliver_made();
        }
        assert_eq!(b.manual_devices().len(), n);
        let runs = 20;
        let start = std::time::Instant::now();
        for i in 0..runs {
            announce(&a, &format!("10.9.0.{}", i + 1), &format!("x{i}.local"), &[&format!("X{i}")]);
            deliver_made();
        }
        let add = start.elapsed().as_secs_f64() * 1e6 / runs as f64;
        let start = std::time::Instant::now();
        for i in 0..runs {
            announce_ttl(&a, &format!("10.9.0.{}", i + 1), &format!("x{i}.local"), &[&format!("X{i}")], 0, 0);
            deliver_made();
        }
        let del = start.elapsed().as_secs_f64() * 1e6 / runs as f64;
        println!("{n:>8} {add:>14.0} {del:>16.0}");
    }
}

fn announce(seg: &Segment, from: &str, host: &str, instances: &[&str]) {
    announce_ttl(seg, from, host, instances, 120, 120);
}

/// Like [`announce`], with the TTLs of the address and of the services.
fn announce_ttl(seg: &Segment, from: &str, host: &str, instances: &[&str], addr_ttl: u32, svc_ttl: u32) {
    let addr: Ipv4Addr = from.parse().unwrap();
    let mut answers = vec![rec_ttl(host, RData::A(addr), addr_ttl)];
    for i in instances {
        answers.push(rec_ttl("_http._tcp.local", RData::Ptr(format!("{i}._http._tcp.local")), svc_ttl));
        answers.push(rec_ttl(
            &format!("{i}._http._tcp.local"),
            RData::Srv { priority: 0, weight: 0, port: 80, target: host.into() },
            svc_ttl,
        ));
    }
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers,
        authorities: vec![],
        additionals: vec![],
    };
    let from = SocketAddr::new(IpAddr::V4(addr), 5353);
    seg.handle(from, &msg.encode().unwrap()).unwrap();
}

/// Make an IPv6 `seg` hear `host` announcing `addrs` (AAAA records) and one
/// service, from the link-local address `from`.
fn announce6(seg: &Segment, from: &str, host: &str, addrs: &[&str], instance: &str) {
    let mut answers: Vec<Record> =
        addrs.iter().map(|a| rec(host, RData::Aaaa(a.parse::<Ipv6Addr>().unwrap()))).collect();
    answers.push(rec("_http._tcp.local", RData::Ptr(format!("{instance}._http._tcp.local"))));
    answers.push(rec(
        &format!("{instance}._http._tcp.local"),
        RData::Srv { priority: 0, weight: 0, port: 80, target: host.into() },
    ));
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers,
        authorities: vec![],
        additionals: vec![],
    };
    seg.handle(SocketAddr::new(ip(from), 5353), &msg.encode().unwrap()).unwrap();
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn reflects_to_other_segments_only() {
    let (a, arx) = wired("a");
    let (b, brx) = wired("b");
    let (c, _crx) = wired("c");
    let _r = Reflector::new(vec![a.clone(), b.clone(), c.clone()]).unwrap();

    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    wait_for(|| b.manual_devices().len() == 1 && c.manual_devices().len() == 1);

    assert!(a.manual_devices().is_empty());
    assert!(b.devices().is_empty(), "reflected copies are not discovered");
    let sent = drain(&brx);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].answers.iter().any(|r| r.data == RData::A("10.0.1.5".parse().unwrap()) && r.ttl > 0));
    assert!(drain(&arx).is_empty());
}

#[test]
fn reflects_devices_already_discovered() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);

    let _r = Reflector::new(vec![a, b.clone()]).unwrap();
    assert_eq!(b.manual_devices().len(), 1);
    assert_eq!(drain(&brx).len(), 1);
}

#[test]
fn removal_withdraws_with_goodbye() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    wait_for(|| b.manual_devices().len() == 1);
    drain(&brx);

    a.expire(Instant::now() + Duration::from_secs(36000));
    wait_for(|| b.manual_devices().is_empty());
    let bye = drain(&brx);
    assert_eq!(bye.len(), 1);
    assert!(bye[0].answers.iter().all(|r| r.ttl == 0));
}

#[test]
fn updates_follow_the_source() {
    let (a, _arx) = wired("a");
    let (b, _brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    wait_for(|| b.manual_devices().len() == 1);

    announce(&a, "10.0.1.5", "tv.local", &["TV", "Cast"]);
    wait_for(|| b.manual_devices()[0].services.len() == 2);
}

#[test]
fn skips_devices_that_cannot_be_announced() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

    a.observe(ip("10.0.1.5")); // no hostname, no services
    announce(&a, "10.0.1.6", "bare.local", &[]); // hostname only
    deliver_made();
    assert!(b.manual_devices().is_empty());
    assert!(drain(&brx).is_empty());
}

/// A device with a hostname and a routable address is reflected without a
/// service only if `ReflectedWhen=` leaves it out: it is then found by
/// name, though browsing finds nothing of it.
#[test]
fn a_device_without_services_is_reflected_only_if_asked_to() {
    for service in [true, false] {
        let (a, _arx) = wired("a");
        let (b, _brx) = wired("b");
        let when = ReflectedWhen { service, ..ReflectedWhen::default() };
        let _r =
            Reflector::with_options(vec![a.clone(), b.clone()], &[], Forward::default(), Advertise::default(), when, None)
                .unwrap();

        announce(&a, "10.0.1.6", "bare.local", &[]);
        deliver_made();
        let reflected = b.manual_devices();
        assert_eq!(reflected.len(), usize::from(!service));
        if !service {
            assert_eq!(reflected[0].hostname.as_deref(), Some("bare.local"));
            assert!(reflected[0].services.is_empty());
        }
    }
}

/// Make `seg` hear `host` at `from` announce a service of each of `services`
/// (an instance name and a type, such as `_ipp._tcp`).
fn announce_kinds(seg: &Segment, from: &str, host: &str, services: &[(&str, &str)]) {
    let addr: Ipv4Addr = from.parse().unwrap();
    let mut answers = vec![rec_ttl(host, RData::A(addr), 120)];
    for (instance, kind) in services {
        answers.push(rec_ttl(&format!("{kind}.local"), RData::Ptr(format!("{instance}.{kind}.local")), 120));
        answers.push(rec_ttl(
            &format!("{instance}.{kind}.local"),
            RData::Srv { priority: 0, weight: 0, port: 631, target: host.into() },
            120,
        ));
    }
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers,
        authorities: vec![],
        additionals: vec![],
    };
    seg.handle(SocketAddr::new(IpAddr::V4(addr), 5353), &msg.encode().unwrap()).unwrap();
}

/// `ReflectedServices=` keeps services of some types from other networks:
/// a device is reflected with the others, and not at all (`service` is
/// asked for) if none is left.
#[test]
fn only_the_services_of_the_types_asked_for_are_reflected() {
    let kinds_of = |kinds: &str, service: bool| {
        // The config refuses this; the reflector does what it is told.
        let (a, _arx) = wired("a");
        let (b, _brx) = wired("b");
        let when = ReflectedWhen { service, ..ReflectedWhen::default() };
        let advertise = crate::config::Config::parse(&format!("[Segment]\nName=s\nInterfaces=a,b\nReflectedServices={kinds}"))
            .unwrap()
            .segments[0]
            .advertise
            .clone();
        let _r =
            Reflector::with_options(vec![a.clone(), b.clone()], &[], Forward::default(), advertise, when, None)
                .unwrap();
        announce_kinds(&a, "10.0.1.7", "mixed.local", &[("Office", "_ipp._tcp"), ("Shell", "_ssh._tcp")]);
        announce_kinds(&a, "10.0.1.8", "shell.local", &[("Box", "_ssh._tcp")]);
        deliver_made();
        let mut seen: Vec<(String, Vec<String>)> = b
            .manual_devices()
            .into_iter()
            .map(|d| (d.hostname.clone().unwrap(), d.services.iter().map(|s| s.kind().to_string()).collect()))
            .collect();
        seen.sort();
        seen
    };
    let (mixed, shell) = ("mixed.local".to_string(), "shell.local".to_string());
    let ipp = vec!["_ipp._tcp.local".to_string()];
    let ssh = vec!["_ssh._tcp.local".to_string()];
    assert_eq!(kinds_of("", true), vec![(mixed.clone(), vec![ipp[0].clone(), ssh[0].clone()]), (shell.clone(), ssh.clone())]);
    assert_eq!(kinds_of("_ipp._tcp", true), vec![(mixed.clone(), ipp.clone())]);
    assert_eq!(kinds_of("!_ipp._tcp", true), vec![(mixed.clone(), ssh.clone()), (shell.clone(), ssh.clone())]);
    assert_eq!(kinds_of("_ipp._tcp,_ssh._tcp,!_ssh._tcp", true), vec![(mixed.clone(), ipp.clone())]);
    // Found by name alone, if that is enough.
    assert_eq!(kinds_of("_ipp._tcp", false), vec![(mixed, ipp), (shell, vec![])]);
}

/// A device known only by a link-local address is reflected, if
/// `ReflectedWhen=` does not ask for an address, by its services alone:
/// its link-local address means nothing on another link.
#[test]
fn a_device_without_a_routable_address_is_reflected_only_if_asked_to() {
    for address in [true, false] {
        let (a, _arx) = wired_v6("a");
        let (b, _brx) = wired_v6("b");
        let when = ReflectedWhen { address, ..ReflectedWhen::default() };
        let _r =
            Reflector::with_options(vec![a.clone(), b.clone()], &[], Forward::default(), Advertise::default(), when, None)
                .unwrap();

        announce6(&a, "fe80::6", "mute.local", &["fe80::6"], "Mute");
        wait_for(|| !a.devices().is_empty());
        deliver_made();
        let reflected = b.manual_devices();
        assert_eq!(reflected.len(), usize::from(!address), "{reflected:?}");
        if !address {
            assert_eq!(reflected[0].addrs().count(), 0);
            assert_eq!(reflected[0].services.len(), 1);
        }
    }
}

#[test]
fn drop_withdraws_everything() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    wait_for(|| b.manual_devices().len() == 1);
    drain(&brx);

    drop(r);
    assert!(b.manual_devices().is_empty());
    let bye = drain(&brx);
    assert_eq!(bye.len(), 1);
    assert!(bye[0].answers.iter().all(|r| r.ttl == 0));
}

#[test]
fn hostname_clash_goes_to_lowest_segment_then_fails_over() {
    let (a, _arx) = wired("a");
    let (b, _brx) = wired("b");
    let (c, _crx) = wired("c");
    let _r = Reflector::new(vec![a.clone(), b.clone(), c.clone()]).unwrap();

    announce(&b, "10.0.2.5", "tv.local", &["TV"]);
    announce(&a, "10.0.1.5", "TV.local", &["TV"]);
    wait_for(|| {
        let d = c.manual_devices();
        d.len() == 1 && v4(&d[0]) == Some(ip("10.0.1.5"))
    });

    a.expire(Instant::now() + Duration::from_secs(36000));
    wait_for(|| {
        let d = c.manual_devices();
        d.len() == 1 && v4(&d[0]) == Some(ip("10.0.2.5"))
    });
}

/// What each segment announces, by hostname.
fn announced_on(seg: &Segment) -> Vec<String> {
    let mut names: Vec<String> = seg.manual_devices().into_iter().filter_map(|d| d.hostname).collect();
    names.sort();
    names
}

#[test]
fn an_untrusted_segment_announces_but_is_announced_nothing() {
    let (br0, br0_rx) = wired("br0");
    let (media, media_rx) = wired("media");
    let (wifi, wifi_rx) = wired("wifi");
    let r = Reflector::with_untrusted(
        vec![br0.clone(), media.clone(), wifi.clone()],
        &["media".to_string(), "wifi".to_string()],
    )
    .unwrap();
    assert_eq!(r.untrusted(), ["media", "wifi"]);

    announce(&media, "10.0.2.5", "speaker.local", &["Speaker"]);
    announce(&wifi, "10.0.3.5", "plug.local", &["Plug"]);
    announce(&br0, "10.0.0.5", "desktop.local", &["Desktop"]);
    wait_for(|| announced_on(&br0).len() == 2);

    // br0 hears of both; the untrusted ones hear of nothing, not even of
    // each other.
    assert_eq!(announced_on(&br0), ["plug.local", "speaker.local"]);
    assert!(announced_on(&media).is_empty() && announced_on(&wifi).is_empty());
    deliver_made();
    assert!(drain(&media_rx).is_empty() && drain(&wifi_rx).is_empty(), "nothing was sent to them");
    assert!(!drain(&br0_rx).is_empty());

    // They are still tracked, and withdrawn from br0 when they go.
    assert_eq!(media.devices().len(), 1);
    media.expire(Instant::now() + Duration::from_secs(3600));
    wait_for(|| announced_on(&br0) == ["plug.local"]);
}

#[test]
fn a_segment_added_is_told_of_what_is_known_and_one_removed_is_forgotten() {
    let (a, _ra) = wired("a");
    let (b, _rb) = wired("b");
    let r = Reflector::new(vec![a.clone()]).unwrap();
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    r.add(b.clone()).unwrap();
    wait_for(|| announced_on(&b) == ["tv.local"]);
    assert!(r.add(b.clone()).is_err(), "an interface once");

    // What it finds is told to the other, and withdrawn when it is removed.
    announce(&b, "10.0.2.5", "nas.local", &["NAS"]);
    wait_for(|| announced_on(&a) == ["nas.local"]);
    b.forget_discovered();
    deliver_made();
    r.remove("b");
    wait_for(|| announced_on(&a).is_empty());
    assert_eq!(r.segments().len(), 1);
    r.remove("b");
}

#[test]
fn trusted_is_the_default() {
    let (a, _ra) = wired("a");
    let (b, _rb) = wired("b");
    let r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    assert!(r.untrusted().is_empty());

    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    announce(&b, "10.0.2.5", "nas.local", &["NAS"]);
    wait_for(|| announced_on(&a).len() == 1 && announced_on(&b).len() == 1);
}

/// The TTLs of the address and of the other records a reflected device is
/// announced with, as `(address, others)`.
fn announced_ttls(rx: &UdpSocket) -> (Vec<u32>, Vec<u32>) {
    let records: Vec<Record> = drain(rx).into_iter().flat_map(|m| m.answers).collect();
    let (addrs, others): (Vec<_>, Vec<_>) = records.iter().partition(|r| matches!(r.data, RData::A(_)));
    // The type enumeration is the daemon's own, not the device's.
    let others = others.iter().filter(|r| !r.name.starts_with("_services.")).map(|r| r.ttl).collect();
    (addrs.iter().map(|r| r.ttl).collect(), others)
}

#[test]
fn reflected_devices_are_announced_with_the_ttls_they_announced_themselves_with() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

    announce_ttl(&a, "10.0.1.5", "tv.local", &["TV"], 300, 600);
    wait_for(|| b.manual_devices().len() == 1);
    assert_eq!(announced_ttls(&brx), (vec![300], vec![600, 600, 600]));
    // What the device said is on record, too.
    assert_eq!(a.devices()[0].ttl, Some(300));
    assert_eq!(a.devices()[0].services[0].ttl(), 600);
}

#[test]
fn a_configured_reflect_ttl_wins_for_the_address_and_leaves_the_services_alone() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let ttl = Some(Duration::from_secs(900));
    let _r = Reflector::with_options(vec![a.clone(), b.clone()], &[], Forward::default(), Advertise::default(), ReflectedWhen::default(), ttl).unwrap();

    announce_ttl(&a, "10.0.1.5", "tv.local", &["TV"], 300, 600);
    wait_for(|| b.manual_devices().len() == 1);
    assert_eq!(announced_ttls(&brx), (vec![900], vec![600, 600, 600]));
}

/// An interface in two segments shows what each reflects onto it with
/// that segment's TTL: it belongs to what is reflected, not to where.
#[test]
fn segments_sharing_an_interface_each_reflect_with_their_own_ttl() {
    let (br0, brx) = wired("br0");
    let (media, _mrx) = wired("media");
    let (wifi, _wrx) = wired("wifi");
    let ttl = Some(Duration::from_secs(900));
    let _media = Reflector::with_options(vec![br0.clone(), media.clone()], &[], Forward::default(), Advertise::default(), ReflectedWhen::default(), ttl);
    let _wifi = Reflector::new(vec![br0.clone(), wifi.clone()]).unwrap();

    announce_ttl(&media, "10.0.2.5", "tv.local", &["TV"], 300, 600);
    wait_for(|| br0.manual_devices().len() == 1);
    assert_eq!(announced_ttls(&brx).0, vec![900]);
    announce_ttl(&wifi, "10.0.3.5", "plug.local", &["Plug"], 300, 600);
    wait_for(|| br0.manual_devices().len() == 2);
    assert_eq!(announced_ttls(&brx).0, vec![300]);
}

/// One device with two hostnames on one address (an LG TV announces
/// `LGwebOSTV.local` and `LGwebOSTV-nsAs-1.local`, each with its own
/// services). That is not a clash: both names are reflected.
#[test]
fn a_device_with_two_hostnames_on_one_address_has_both_reflected() {
    let (a, _arx) = wired("a");
    let (b, _brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

    announce(&a, "10.0.1.5", "tv.local", &["Airplay"]);
    announce(&a, "10.0.1.5", "tv-nsas-1.local", &["Display"]);
    wait_for(|| a.devices().len() == 2);
    deliver_made();

    let mut names: Vec<_> = b.manual_devices().iter().map(|d| d.hostname.clone().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["tv-nsas-1.local", "tv.local"]);
    assert!(b.manual_devices().iter().all(|d| v4(d) == Some(ip("10.0.1.5"))));
}

/// The configured topology: a<->b and b<->c, but never a<->c, even
/// though both reflectors share b.
#[test]
fn overlapping_reflectors_do_not_leak_through_the_shared_segment() {
    let (a, _arx) = wired("a");
    let (b, _brx) = wired("b");
    let (c, _crx) = wired("c");
    let r_ab = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let _r_bc = Reflector::new(vec![b.clone(), c.clone()]).unwrap();

    announce(&a, "10.0.1.5", "tv-a.local", &["A"]);
    announce(&c, "10.0.3.5", "tv-c.local", &["C"]);
    wait_for(|| b.manual_devices().len() == 2);
    deliver_made();

    // b learned both, but a and c each only learned about b's side.
    assert_eq!(a.manual_devices().len(), 0);
    assert_eq!(c.manual_devices().len(), 0);

    announce(&b, "10.0.2.5", "tv-b.local", &["B"]);
    wait_for(|| a.manual_devices().len() == 1 && c.manual_devices().len() == 1);
    assert_eq!(v4(&a.manual_devices()[0]), Some(ip("10.0.2.5")));
    assert_eq!(v4(&c.manual_devices()[0]), Some(ip("10.0.2.5")));

    // Dropping one reflector withdraws only what it announced.
    drop(r_ab);
    assert!(a.manual_devices().is_empty());
    let on_b: Vec<_> = b.manual_devices().iter().map(|d| v4(d).unwrap()).collect();
    assert_eq!(on_b, [ip("10.0.3.5")]);
    assert_eq!(c.manual_devices().len(), 1);
}

/// Two segments that share br0, with a `tv.local` on each of the others.
/// br0 is told about the one from the segment listed first, and about the
/// other once that one goes; the loser going takes nothing with it.
#[test]
fn segments_sharing_an_interface_keep_both_and_the_first_segment_wins() {
    let (br0, br0_rx) = wired("br0");
    let (media, _media_rx) = wired("media");
    let (wifi, _wifi_rx) = wired("wifi");
    let _first = Reflector::new(vec![br0.clone(), media.clone()]).unwrap();
    let _second = Reflector::new(vec![br0.clone(), wifi.clone()]).unwrap();
    let on_br0 = || br0.manual_devices().iter().map(v4).collect::<Vec<_>>();
    let gone = || Instant::now() + Duration::from_secs(3600);

    // Media's wins, and is not displaced by the one heard after it.
    announce(&media, "10.0.2.5", "TV.local", &["Media TV"]);
    wait_for(|| on_br0() == [Some(ip("10.0.2.5"))]);
    announce(&wifi, "10.0.3.5", "tv.local", &["Wifi TV"]);
    wait_for(|| wifi.devices().len() == 1);
    deliver_made();
    assert_eq!(on_br0(), [Some(ip("10.0.2.5"))]);

    wifi.expire(gone());
    deliver_made();
    assert_eq!(on_br0(), [Some(ip("10.0.2.5"))]);

    // The winner going hands the name over instead of withdrawing it.
    announce(&wifi, "10.0.3.5", "tv.local", &["Wifi TV"]);
    deliver_made();
    drain(&br0_rx);
    media.expire(gone());
    wait_for(|| on_br0() == [Some(ip("10.0.3.5"))]);
    assert!(drain(&br0_rx).iter().all(|m| m.answers.iter().any(|r| r.ttl > 0)), "handed over, not withdrawn");

    wifi.expire(gone());
    wait_for(|| on_br0().is_empty());
}

/// A device on br0 and one on media both called `tv.local`. Neither is
/// told about the other, which it would take for a conflict and rename
/// itself over; each network is told about the other's once its own goes.
#[test]
fn a_device_here_keeps_its_name_and_the_copy_gives_way() {
    let (br0, br0_rx) = wired("br0");
    let (media, _media_rx) = wired("media");
    let _r = Reflector::new(vec![br0.clone(), media.clone()]).unwrap();
    let on_br0 = || br0.manual_devices().iter().map(v4).collect::<Vec<_>>();
    let tv_records = |msgs: Vec<Message>| -> Vec<Record> {
        msgs.into_iter().flat_map(|m| m.answers).filter(|r| r.name.eq_ignore_ascii_case("tv.local")).collect()
    };

    announce(&br0, "10.0.0.5", "tv.local", &["Living Room"]);
    announce(&media, "10.0.2.5", "TV.local", &["Living Room"]);
    wait_for(|| br0.devices().len() == 1 && media.devices().len() == 1);
    deliver_made();
    assert!(on_br0().is_empty() && media.manual_devices().is_empty());
    assert!(tv_records(drain(&br0_rx)).is_empty(), "nothing about tv.local was sent onto br0");

    // The one on br0 goes: media's is shown in its place.
    br0.expire(Instant::now() + Duration::from_secs(3600));
    wait_for(|| on_br0() == [Some(ip("10.0.2.5"))]);
    drain(&br0_rx);

    // It is back: the copy is withdrawn, without flushing what it says.
    announce(&br0, "10.0.0.5", "tv.local", &["Living Room"]);
    wait_for(|| on_br0().is_empty());
    let bye = tv_records(drain(&br0_rx));
    assert_eq!(bye.len(), 1);
    assert_eq!((bye[0].ttl, bye[0].cache_flush), (0, false));
    assert_eq!(bye[0].data, RData::A("10.0.2.5".parse().unwrap()));
}

/// A device elsewhere that calls itself like the router's own name
/// neither displaces it nor, when it goes, withdraws it.
#[test]
fn a_device_named_like_the_advertised_name_leaves_it_alone() {
    let (br0, br0_rx) = wired("br0");
    let (media, _media_rx) = wired("media");
    let router = Device { hostname: Some("router.local".into()), addresses: vec![ip("10.0.0.1").into()].into(), ..Device::default() };
    br0.add_manual_ttl(OWN, &Shared::new(router.clone()), Duration::from_secs(120)).unwrap();
    let _r = Reflector::new(vec![br0.clone(), media.clone()]).unwrap();
    drain(&br0_rx);

    announce(&media, "10.0.2.5", "Router.local", &["Admin"]);
    wait_for(|| media.devices().len() == 1);
    deliver_made();
    assert_eq!(br0.manual_devices(), std::slice::from_ref(&router));

    media.expire(Instant::now() + Duration::from_secs(3600));
    wait_for(|| media.devices().is_empty());
    deliver_made();
    assert_eq!(br0.manual_devices(), [router]);
    assert!(drain(&br0_rx).is_empty(), "nothing about it was sent, or withdrawn");
}

/// A service known only by its text (Apple's `_device-info` has no SRV)
/// is not reflected: a copy would have to make up its port and host.
#[test]
fn only_services_known_where_they_are_are_reflected() {
    let (a, _arx) = wired("a");
    let (b, _brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: vec![
            rec("tv.local", RData::A("10.0.1.5".parse().unwrap())),
            rec("TV._device-info._tcp.local", RData::Txt(vec![b"model=X".to_vec()])),
        ],
        authorities: vec![],
        additionals: vec![],
    };
    a.handle(SocketAddr::new(ip("10.0.1.5"), 5353), &msg.encode().unwrap()).unwrap();
    wait_for(|| a.devices().iter().any(|d| !d.services.is_empty()));
    deliver_made();
    assert!(b.manual_devices().is_empty(), "nothing resolved to reflect");

    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    wait_for(|| b.manual_devices().len() == 1);
    let names: Vec<String> = b.manual_devices()[0].services.iter().map(|s| s.instance().to_string()).collect();
    assert_eq!(names, ["TV._http._tcp.local"]);
}

/// A client on `seg` asks `name` (type A), from port 5353.
fn ask(seg: &Segment, client: &str, name: &str) {
    ask_type(seg, client, name, rtype::A);
}

/// Like [`ask`], for records of `qtype`.
fn ask_type(seg: &Segment, client: &str, name: &str, qtype: u16) {
    let msg = Message {
        header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
        questions: vec![Question { name: name.into(), qtype, class: 1, unicast_response: false }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };
    seg.handle(SocketAddr::new(ip(client), 5353), &msg.encode().unwrap()).unwrap();
}

/// What `msgs` ask, by name.
fn asked_names(msgs: &[Message]) -> Vec<String> {
    msgs.iter().filter(|m| !m.header.response).flat_map(|m| &m.questions).map(|q| q.name.clone()).collect()
}

/// A question br0 has no answer to is asked, by the daemon, on the
/// segments whose devices br0 is told about, untrusted ones included.
/// Their answer is reflected, and the client asking again is answered,
/// and, forwarding only what is unknown, not asked about elsewhere. An
/// untrusted segment's questions go nowhere: nothing would come back.
#[test]
fn a_question_nothing_answers_is_asked_where_the_answer_could_come_from() {
    let (br0, br0_rx) = wired("br0");
    let (media, media_rx) = wired("media");
    let (wifi, wifi_rx) = wired("wifi");
    let segments = vec![br0.clone(), media.clone(), wifi.clone()];
    let _r =
        Reflector::with_options(segments, &["wifi".to_string()], Forward::Unknown, Advertise::default(), ReflectedWhen::default(), None).unwrap();

    ask(&br0, "10.0.0.50", "printer.local");
    deliver_made();
    assert_eq!(asked_names(&drain(&media_rx)), ["printer.local"]);
    assert_eq!(asked_names(&drain(&wifi_rx)), ["printer.local"]);
    assert!(drain(&br0_rx).is_empty(), "nothing to answer, and nothing asked there");

    // The printer on media answers the daemon, and br0 is told of it.
    announce(&media, "10.0.2.7", "printer.local", &["Printer"]);
    wait_for(|| br0.manual_devices().len() == 1);
    let told: Vec<Record> = drain(&br0_rx).into_iter().flat_map(|m| m.answers).collect();
    assert!(told.iter().any(|r| r.data == RData::A("10.0.2.7".parse().unwrap())), "{told:?}");

    // The client asking again is answered on br0 (once the copy may be
    // multicast again), and nothing more is asked elsewhere.
    ask(&br0, "10.0.0.50", "printer.local");
    deliver_made();
    assert!(asked_names(&drain(&media_rx)).is_empty() && asked_names(&drain(&wifi_rx)).is_empty());

    // The untrusted one asks: nothing is asked on its behalf.
    ask(&wifi, "10.0.3.50", "nas.local");
    deliver_made();
    assert!(asked_names(&drain(&br0_rx)).is_empty() && asked_names(&drain(&media_rx)).is_empty());
}

/// A browse that a copy answers may have other answers still, from
/// devices that only answer when asked: it is asked elsewhere unless the
/// segment forwards only what it has no answer to, or nothing. What is
/// known there goes along as known answers, so that only the others
/// answer.
#[test]
fn a_browse_a_copy_answers_is_asked_elsewhere_as_configured() {
    for forward in [Forward::Always, Forward::Unknown, Forward::Never] {
        let (br0, _br0_rx) = wired("br0");
        let (media, media_rx) = wired("media");
        let _r = Reflector::with_options(vec![br0.clone(), media.clone()], &[], forward, Advertise::default(), ReflectedWhen::default(), None).unwrap();
        announce(&media, "10.0.2.7", "tv.local", &["TV"]);
        wait_for(|| br0.manual_devices().len() == 1);
        drain(&media_rx);

        ask_type(&br0, "10.0.0.50", "_http._tcp.local", rtype::PTR);
        deliver_made();
        let queries: Vec<Message> = drain(&media_rx).into_iter().filter(|m| !m.header.response).collect();
        if forward == Forward::Always {
            assert_eq!(asked_names(&queries), ["_http._tcp.local"]);
            let known = &queries[0].answers;
            assert_eq!(known.len(), 1, "{known:?}");
            assert_eq!(known[0].data, RData::Ptr("TV._http._tcp.local".into()));
            assert!(known[0].ttl > 0 && known[0].ttl <= 120, "the time it has left: {}", known[0].ttl);
        } else {
            assert!(queries.is_empty(), "{forward:?}: {queries:?}");
        }

        // Never forwarding, not even what nothing answers is asked.
        ask(&br0, "10.0.0.50", "printer.local");
        deliver_made();
        let asked = asked_names(&drain(&media_rx));
        assert_eq!(asked.is_empty(), forward == Forward::Never, "{forward:?}: {asked:?}");
    }
}

/// A copy that cannot be announced is tried again until it can be, and
/// one whose device is gone stays until its goodbye can go out: none is
/// missing for good, and none outlives its source.
#[test]
fn failed_sends_are_retried_until_they_go_through() {
    let (a, _a_rx) = wired("a");
    let (b, b_rx) = wired("b");
    let broken = || (UdpSocket::bind("127.0.0.1:0").unwrap(), "[::1]:5353".parse::<SocketAddr>().unwrap());
    let repair = || b.attach(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), b_rx.local_addr().unwrap());
    let (socket, dest) = broken();
    b.attach(Family::V4, fd(socket), dest);
    let r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    deliver_made();
    assert!(b.manual_devices().is_empty(), "it could not be announced");
    let retry = r.next_retry().expect("to be tried again");
    assert!(retry > Instant::now() + RETRY - Duration::from_secs(1));
    retry_made(retry);
    assert!(b.manual_devices().is_empty(), "still not");
    repair();
    assert!(r.next_retry().is_some_and(|at| at > retry), "put off");
    retry_made(r.next_retry().unwrap());
    assert_eq!(b.manual_devices().len(), 1);
    assert_eq!(r.next_retry(), None, "nothing left to try");
    let told: Vec<Record> = drain(&b_rx).into_iter().flat_map(|m| m.answers).collect();
    assert!(told.iter().any(|r| r.data == RData::A("10.0.1.5".parse().unwrap()) && r.ttl > 0), "{told:?}");

    // Gone from a while b cannot send: the copy stays until its goodbye goes out.
    let (socket, dest) = broken();
    b.attach(Family::V4, fd(socket), dest);
    a.expire(Instant::now() + Duration::from_secs(100_000));
    deliver_made();
    assert_eq!(b.manual_devices().len(), 1, "kept: its goodbye did not go out");
    repair();
    retry_made(r.next_retry().unwrap());
    assert!(b.manual_devices().is_empty());
    let told: Vec<Record> = drain(&b_rx).into_iter().flat_map(|m| m.answers).collect();
    assert!(told.iter().any(|r| r.data == RData::A("10.0.1.5".parse().unwrap()) && r.ttl == 0), "{told:?}");
}

/// A copy whose goodbye could not go out when its device went is not left
/// behind when its segment goes: it is withdrawn, tried again until it is.
#[test]
fn a_copy_whose_goodbye_failed_is_withdrawn_when_its_segment_goes() {
    let (a, _a_rx) = wired("a");
    let (b, b_rx) = wired("b");
    let r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    deliver_made();
    assert_eq!(b.manual_devices().len(), 1);

    let (socket, dest) = (UdpSocket::bind("127.0.0.1:0").unwrap(), "[::1]:5353".parse::<SocketAddr>().unwrap());
    b.attach(Family::V4, fd(socket), dest);
    a.forget_discovered();
    deliver_made();
    assert_eq!(b.manual_devices().len(), 1, "kept: its goodbye did not go out");

    // The device is not a's any more, only a copy of it is left, and a goes.
    r.remove("a");
    assert_eq!(b.manual_devices().len(), 1, "still: b cannot send");
    let retry = r.next_retry().expect("to be tried again");
    b.attach(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), b_rx.local_addr().unwrap());
    retry_made(retry);
    assert!(b.manual_devices().is_empty());
    assert_eq!(r.next_retry(), None);
}

/// A device that announces only a link-local IPv6 address, and no IPv4
/// one, cannot be reflected; once the neighbour table lists a routable
/// address under its link-layer address, it is, with that address, and
/// withdrawn again when the entry goes.
#[test]
fn a_device_known_only_by_link_local_is_reflected_with_its_neighbour_addresses() {
    let (a, _arx) = wired_v6("a");
    let (b, _brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let mac = vec![2, 0, 0, 0, 0, 9];
    a.set_prefixes(vec![prefix("fd00::/64")]);
    a.neighbour(ip("fe80::9"), Some(mac.clone()));
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: vec![
            rec("tv.local", RData::Aaaa("fe80::9".parse().unwrap())),
            rec("_http._tcp.local", RData::Ptr("TV._http._tcp.local".into())),
            rec("TV._http._tcp.local", RData::Srv { priority: 0, weight: 0, port: 80, target: "tv.local".into() }),
        ],
        authorities: vec![],
        additionals: vec![],
    };
    a.handle(SocketAddr::new(ip("fe80::9"), 5353), &msg.encode().unwrap()).unwrap();
    deliver_made();
    assert!(b.manual_devices().is_empty(), "nowhere to reach it at");

    a.neighbour(ip("fd00::9"), Some(mac));
    wait_for(|| b.manual_devices().first().is_some_and(|d| d.addrs().eq([ip("fd00::9")])));
    a.neighbour(ip("fd00::9"), None);
    wait_for(|| b.manual_devices().is_empty());
}

/// What a segment reflects of the addresses from the neighbour table:
/// all of them; those of a family a device announced a link-local address
/// of (the default); or none. One device announced only IPv4, the other
/// only a link-local IPv6 address; the table has an IPv6 address of each.
#[test]
fn a_segment_chooses_which_neighbour_addresses_to_reflect() {
    for (mode, printer, tv) in [
        (Neighbours::Always, vec![ip("10.0.1.9"), ip("fd00::9")], Some(vec![ip("fd00::8")])),
        (Neighbours::LinkLocal, vec![ip("10.0.1.9")], Some(vec![ip("fd00::8")])),
        (Neighbours::Never, vec![ip("10.0.1.9")], None),
    ] {
        let (a, _arx) = wired("a");
        let (b, _brx) = wired("b");
        let mut advertise = Advertise::default();
        advertise.neighbours = mode;
        let _r = Reflector::with_options(vec![a.clone(), b.clone()], &[], Forward::default(), advertise, ReflectedWhen::default(), None).unwrap();
        a.set_prefixes(vec![prefix("10.0.1.0/24"), prefix("fd00::/64")]);
        for (addr, mac) in [("10.0.1.9", 9), ("fd00::9", 9), ("fe80::8", 8), ("fd00::8", 8)] {
            a.neighbour(ip(addr), Some(vec![2, 0, 0, 0, 0, mac]));
        }
        let heard = |from: &str, host: &str, addr: RData| {
            let msg = Message {
                header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
                questions: vec![],
                answers: {
                    let instance = format!("{}._http._tcp.local", host.split('.').next().unwrap());
                    vec![
                        rec(host, addr),
                        rec("_http._tcp.local", RData::Ptr(instance.clone())),
                        rec(&instance, RData::Srv { priority: 0, weight: 0, port: 80, target: host.into() }),
                    ]
                },
                authorities: vec![],
                additionals: vec![],
            };
            a.handle(SocketAddr::new(ip(from), 5353), &msg.encode().unwrap()).unwrap();
        };
        heard("10.0.1.9", "printer.local", RData::A("10.0.1.9".parse().unwrap()));
        heard("fe80::8", "tv.local", RData::Aaaa("fe80::8".parse().unwrap()));
        let copy = |host: &str| b.manual_devices().into_iter().find(|d| d.hostname.as_deref() == Some(host));
        wait_for(|| copy("printer.local").is_some_and(|d| d.addrs().eq(printer.iter().copied())));
        match &tv {
            Some(addrs) => wait_for(|| copy("tv.local").is_some_and(|d| d.addrs().eq(addrs.iter().copied()))),
            None => {
                deliver_made();
                assert!(copy("tv.local").is_none(), "{mode:?}: nowhere to reach it at");
            }
        }
        // Learned all the same, whichever the mode.
        let printer_here = a.devices().into_iter().find(|d| d.hostname.as_deref() == Some("printer.local")).unwrap();
        assert!(printer_here.has_addr(&ip("fd00::9")), "{mode:?}");
    }
}

/// A device's IPv6 address heard over IPv4 is reflected with it, for
/// clients that ask over IPv4; its link-local ones, of either family, are
/// not.
#[test]
fn a_copy_carries_both_families_but_no_link_local_address() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: vec![
            rec("tv.local", RData::A("10.0.1.5".parse().unwrap())),
            rec("tv.local", RData::A("169.254.1.5".parse().unwrap())),
            rec("tv.local", RData::Aaaa("fd00::5".parse().unwrap())),
            rec("tv.local", RData::Aaaa("fe80::5".parse().unwrap())),
            rec("_http._tcp.local", RData::Ptr("TV._http._tcp.local".into())),
            rec("TV._http._tcp.local", RData::Srv { priority: 0, weight: 0, port: 80, target: "tv.local".into() }),
        ],
        authorities: vec![],
        additionals: vec![],
    };
    a.handle(SocketAddr::new(ip("10.0.1.5"), 5353), &msg.encode().unwrap()).unwrap();
    wait_for(|| b.manual_devices().len() == 1);

    let there = b.manual_devices().remove(0);
    assert_eq!(there.addrs().collect::<Vec<_>>(), [ip("10.0.1.5"), ip("fd00::5")]);
    let sent: Vec<RData> = drain(&brx).into_iter().flat_map(|m| m.answers).filter(|r| r.name == "tv.local").map(|r| r.data).collect();
    assert_eq!(sent, [RData::A("10.0.1.5".parse().unwrap()), RData::Aaaa("fd00::5".parse().unwrap())]);
}

/// On a network with a global and a ULA prefix, a device's copy carries
/// both: which one a client can use depends on where it is.
#[test]
fn a_copy_carries_a_global_and_a_ula_address() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: vec![
            rec("tv.local", RData::Aaaa("2001:db8::5".parse().unwrap())),
            rec("tv.local", RData::Aaaa("fd00::5".parse().unwrap())),
            rec("tv.local", RData::Aaaa("fe80::5".parse().unwrap())),
            rec("TV._http._tcp.local", RData::Srv { priority: 0, weight: 0, port: 80, target: "tv.local".into() }),
        ],
        authorities: vec![],
        additionals: vec![],
    };
    a.handle(SocketAddr::new(ip("fe80::5"), 5353), &msg.encode().unwrap()).unwrap();
    wait_for(|| b.manual_devices().len() == 1);
    assert_eq!(b.manual_devices()[0].addrs().collect::<Vec<_>>(), [ip("2001:db8::5"), ip("fd00::5")]);
    let sent: Vec<RData> = drain(&brx).into_iter().flat_map(|m| m.answers).filter(|r| r.name == "tv.local").map(|r| r.data).collect();
    assert_eq!(sent, [RData::Aaaa("2001:db8::5".parse().unwrap()), RData::Aaaa("fd00::5".parse().unwrap())]);
}

/// An address the device stops announcing runs out on its own, and the
/// copy is told to drop just that one.
#[test]
fn a_copy_drops_an_address_that_ran_out() {
    let (a, _arx) = wired("a");
    let (b, brx) = wired("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
    let msg = Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: vec![],
        answers: vec![
            rec_ttl("tv.local", RData::A("10.0.1.5".parse().unwrap()), 120),
            rec_ttl("tv.local", RData::Aaaa("fd00::5".parse().unwrap()), 4500),
            rec_ttl("TV._http._tcp.local", RData::Srv { priority: 0, weight: 0, port: 80, target: "tv.local".into() }, 4500),
        ],
        authorities: vec![],
        additionals: vec![],
    };
    a.handle(SocketAddr::new(ip("10.0.1.5"), 5353), &msg.encode().unwrap()).unwrap();
    wait_for(|| b.manual_devices().len() == 1);
    drain(&brx);

    a.expire(Instant::now() + Duration::from_secs(400));
    wait_for(|| b.manual_devices().first().is_some_and(|d| d.addrs().eq([ip("fd00::5")])));
    let bye: Vec<Record> = drain(&brx).into_iter().flat_map(|m| m.answers).filter(|r| r.ttl == 0).collect();
    assert_eq!(bye.len(), 1, "{bye:?}");
    assert_eq!(bye[0].data, RData::A("10.0.1.5".parse().unwrap()));
}

/// The bug this guards against: a device on one network announced to
/// another with its link-local address, which only exists on its own link.
#[test]
fn link_local_addresses_never_leave_their_link() {
    let (a, _arx) = wired_v6("a");
    let (b, brx) = wired_v6("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

    // It sends from its link-local address and announces that and a ULA.
    announce6(&a, "fe80::5", "tv.local", &["fd00:0:1::5", "fe80::5"], "TV");
    wait_for(|| b.manual_devices().len() == 1);

    // Where it lives, both addresses are known...
    let home = &a.devices()[0];
    assert_eq!((v6(home), ll6(home)), (Some(ip("fd00:0:1::5")), Some(ip("fe80::5"))));
    // ...but the other network is told only the routable one.
    let there = &b.manual_devices()[0];
    assert_eq!((v6(there), ll6(there)), (Some(ip("fd00:0:1::5")), None));
    let on_the_wire: Vec<Ipv6Addr> = drain(&brx)
        .iter()
        .flat_map(|m| &m.answers)
        .filter_map(|r| match &r.data {
            RData::Aaaa(a) => Some(*a),
            _ => None,
        })
        .collect();
    assert_eq!(on_the_wire, ["fd00:0:1::5".parse::<Ipv6Addr>().unwrap()]);
}

#[test]
fn a_device_known_only_by_a_link_local_address_is_not_reflected() {
    let (a, _arx) = wired_v6("a");
    let (b, brx) = wired_v6("b");
    let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

    announce6(&a, "fe80::6", "mute.local", &["fe80::6"], "Mute");
    wait_for(|| !a.devices().is_empty());
    deliver_made();
    assert_eq!(v4(&a.devices()[0]), None);
    assert!(b.manual_devices().is_empty());
    assert!(drain(&brx).is_empty());
}

#[test]
fn single_segment_reflects_nothing() {
    let (a, arx) = wired("a");
    let _r = Reflector::new(vec![a.clone()]).unwrap();
    announce(&a, "10.0.1.5", "tv.local", &["TV"]);
    deliver_made();
    assert!(a.manual_devices().is_empty());
    assert!(drain(&arx).is_empty());
}

#[test]
fn rejects_bad_construction() {
    let (a, _) = wired("a");
    assert!(Reflector::new(vec![a.clone(), a.clone()]).is_err());
}
