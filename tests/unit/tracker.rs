use core::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::codec::Header;

fn record(name: &str, ttl: u32, data: RData) -> Record {
    Record { name: name.into(), class: 1, cache_flush: true, ttl, data }
}

fn a(name: &str, addr: &str, ttl: u32) -> Record {
    record(name, ttl, RData::A(addr.parse::<Ipv4Addr>().unwrap()))
}

fn aaaa(name: &str, addr: &str, ttl: u32) -> Record {
    record(name, ttl, RData::Aaaa(addr.parse::<Ipv6Addr>().unwrap()))
}

fn message(response: bool, answers: Vec<Record>) -> Message {
    let header = Header { id: 0, response, opcode: 0, authoritative: response, truncated: false, rcode: 0 };
    Message { header, questions: vec![], answers, authorities: vec![], additionals: vec![] }
}

/// A tracker that has been told what `msg` said, sent from `src`.
fn told(tracker: &mut Tracker, src: &str, msg: &Message) {
    tracker.track(src.parse().unwrap(), Instant::now(), Some(msg));
}

fn knows(tracker: &Tracker, host: &str) -> bool {
    tracker.discovered.find_host(host).is_some()
}

/// What is not a message, or a query, says nothing: the records of a
/// query are other devices' known answers.
#[test]
fn a_query_and_what_is_not_a_message_say_nothing() {
    let mut tracker = Tracker::default();
    let known = message(false, vec![a("tv.local", "10.0.1.5", 120), a("gone.local", "10.0.1.5", 0)]);
    told(&mut tracker, "10.0.1.5", &known);
    tracker.track("10.0.1.5".parse().unwrap(), Instant::now(), None);
    assert!(!knows(&tracker, "tv.local") && !knows(&tracker, "gone.local"));
}

/// A host leaves by saying goodbye to the address the packet came from; to
/// another's, it is only saying the other left.
#[test]
fn a_host_leaves_by_saying_goodbye_to_the_address_it_came_from() {
    let mut tracker = Tracker::default();
    told(&mut tracker, "10.0.1.5", &message(true, vec![a("tv.local", "10.0.1.5", 120)]));
    assert!(knows(&tracker, "tv.local"));
    let goodbye = message(true, vec![a("tv.local", "10.0.1.5", 0)]);
    told(&mut tracker, "10.0.1.9", &goodbye);
    assert!(knows(&tracker, "tv.local"), "a router saying so of another");
    told(&mut tracker, "10.0.1.5", &goodbye);
    assert!(!knows(&tracker, "tv.local"));
}

/// One that announces another address in its place is not leaving: it only
/// loses the one, as a temporary IPv6 address gives way to the next.
#[test]
fn a_host_that_announces_another_address_in_its_place_is_not_leaving() {
    let mut tracker = Tracker::default();
    told(&mut tracker, "fd00::1", &message(true, vec![aaaa("tv.local", "fd00::1", 120)]));
    told(&mut tracker, "fd00::1", &message(true, vec![aaaa("tv.local", "fd00::1", 0), aaaa("tv.local", "fd00::2", 120)]));
    assert!(knows(&tracker, "tv.local"));
    // And not in another's name.
    told(&mut tracker, "fd00::2", &message(true, vec![aaaa("tv.local", "fd00::2", 0), aaaa("other.local", "fd00::3", 120)]));
    assert!(!knows(&tracker, "tv.local"));
}

/// The types it names are those of live answers to the question of what
/// types there are, in lowercase, and well formed.
#[test]
fn the_service_types_are_the_live_answers_to_the_question_of_what_there_are() {
    let ptr = |owner: &str, ttl: u32, class: u16, target: &str| Record {
        class,
        ..record(owner, ttl, RData::Ptr(target.into()))
    };
    let mut tracker = Tracker::default();
    let msg = message(
        true,
        vec![
            ptr(META_QUERY, 4500, 1, "_IPP._tcp.local"),
            ptr("_Services._dns-sd._udp.local", 4500, 1, "_http._tcp.local"),
            ptr(META_QUERY, 0, 1, "_gone._tcp.local"),
            ptr(META_QUERY, 4500, 3, "_other._tcp.local"),
            ptr(META_QUERY, 4500, 1, "not a type"),
            ptr("_ipp._tcp.local", 4500, 1, "Printer._ipp._tcp.local"),
        ],
    );
    told(&mut tracker, "10.0.1.5", &msg);
    let types: Vec<&str> = tracker.types.iter().map(String::as_str).collect();
    assert_eq!(types, ["_http._tcp.local", "_ipp._tcp.local"]);
}

/// What it says is told by the host it concerns: a response may describe
/// several, and what ties to none is the sender's.
#[test]
fn what_it_says_is_told_by_host_and_what_ties_to_none_is_the_senders() {
    let mut tracker = Tracker::default();
    let msg = message(
        true,
        vec![
            a("tv.local", "10.0.1.5", 120),
            a("nas.local", "10.0.1.6", 120),
            record("_ipp._tcp.local", 4500, RData::Ptr("Printer._ipp._tcp.local".into())),
        ],
    );
    told(&mut tracker, "10.0.1.5", &msg);
    assert!(knows(&tracker, "tv.local") && knows(&tracker, "nas.local"));
    assert_eq!(tracker.discovered.len(), 2, "one device for each, and none for the leftover");
}

/// A TXT value is any bytes, and is kept, and announced again, as it came:
/// these are not text, and would be changed, and grow past what a string
/// may be, if they were made into it.
#[test]
fn a_txt_value_that_is_not_text_is_kept_as_it_came() {
    let mut tracker = Tracker::default();
    let binary = vec![vec![0xff; 100], b"k=\x80\x81v".to_vec()];
    let txt = record("Dev._x._tcp.local", 120, RData::Txt(binary.clone()));
    let srv = record("Dev._x._tcp.local", 120, RData::Srv { priority: 0, weight: 0, port: 1, target: "d.local".into() });
    told(&mut tracker, "10.0.1.5", &message(true, vec![a("d.local", "10.0.1.5", 120), srv, txt]));
    let id = tracker.discovered.find_host("d.local").unwrap();
    let device = &tracker.discovered.get(id).device;
    assert_eq!(device.services[0].txt().collect::<Vec<_>>(), binary.clone());

    // And said again as it was, over the wire and back.
    let announced = message(true, device.announcement(&Advertise::ALL, 120, 120)).encode().expect("it can be announced");
    let again = Message::parse(&announced).unwrap();
    let said: Vec<&RData> = again.answers.iter().map(|r| &r.data).filter(|d| matches!(d, RData::Txt(_))).collect();
    assert_eq!(said, [&RData::Txt(binary)]);
}

/// What happened to a device is one event of it: that it came, what it was
/// before it changed and what it is, and that it went as it was.
#[test]
fn an_event_says_what_a_device_was_and_what_it_is() {
    let mut tracker = Tracker::default();
    let hear = |tracker: &mut Tracker, src: &str, msg: &Message| {
        let touched = tracker.track(src.parse().unwrap(), Instant::now(), Some(msg));
        touched.events(&tracker.discovered)
    };
    let events = hear(&mut tracker, "10.0.1.5", &message(true, vec![a("tv.local", "10.0.1.5", 120)]));
    let [Event::Added(came)] = &events[..] else { panic!("{events:?}") };
    assert_eq!(came.addrs().count(), 1);

    let events = hear(&mut tracker, "10.0.1.5", &message(true, vec![a("tv.local", "10.0.1.5", 120)]));
    assert!(events.is_empty(), "heard again just as it was: {events:?}");

    let both = message(true, vec![a("tv.local", "10.0.1.5", 120), a("tv.local", "10.0.1.6", 120)]);
    let events = hear(&mut tracker, "10.0.1.5", &both);
    let [Event::Updated { before, after }] = &events[..] else { panic!("{events:?}") };
    assert_eq!((before.addrs().count(), after.addrs().count()), (1, 2));

    let events = hear(&mut tracker, "10.0.1.5", &message(true, vec![a("tv.local", "10.0.1.5", 0)]));
    let [Event::Removed(went)] = &events[..] else { panic!("{events:?}") };
    assert_eq!(went.addrs().count(), 2, "gone as it was");
}
