//! Reflects devices between segments of one address family.
//!
//! Every device discovered on a segment is announced on all the *other*
//! segments, and withdrawn again when it goes away. The reflector owns the
//! reflected copies: it works out what each segment should be announcing and
//! reconciles toward that, so a failed send is simply retried and no copy
//! can outlive its source. Dropping the reflector withdraws everything.
//!
//! Every segment reflects to every other one in the same reflector; which
//! interfaces share a reflector is the caller's policy. A reflector with a
//! single segment only tracks and reflects nothing.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::socket::{Device, Event, Family, Segment};

/// How often a worker checks for shutdown while waiting for events.
const TICK: Duration = Duration::from_millis(250);

/// How often a worker reconciles even without events, to retry failed sends.
const RETRY: Duration = Duration::from_secs(5);

/// A change to a device discovered on one of a reflector's segments, as
/// [`Reflector::watch`] delivers it.
#[derive(Clone, Debug)]
pub struct Notice {
    /// The segment the device was discovered on.
    pub interface: String,
    pub family: Family,
    pub event: Event,
    /// How much longer the daemon keeps the device if it is not heard from
    /// again, to the second; zero if it was removed.
    pub ttl: Duration,
}

pub struct Reflector {
    inner: Arc<Inner>,
    threads: Vec<JoinHandle<()>>,
}

struct Inner {
    segments: Vec<Segment>,
    /// Whether each segment is untrusted: it is not announced anything.
    untrusted: Vec<bool>,
    book: Mutex<Book>,
    stop: AtomicBool,
    subscribers: Mutex<Vec<Sender<Notice>>>,
}

#[derive(Default)]
struct Book {
    /// Reflectable devices currently discovered on each source segment,
    /// keyed by (segment index, lowercase hostname).
    sources: BTreeMap<(usize, String), Device>,
    /// What each target segment has been told, as last sent successfully,
    /// keyed by (segment index, lowercase hostname).
    pushed: HashMap<(usize, String), Device>,
}

impl Reflector {
    /// Start reflecting between `segments`, which must all be the same
    /// address family and on different interfaces. Devices already
    /// discovered are reflected before this returns.
    pub fn new(segments: Vec<Segment>) -> Result<Reflector> {
        Self::with_untrusted(segments, &[])
    }

    /// Like [`new`](Reflector::new), but the segments on the interfaces named
    /// in `untrusted` are announced nothing: their devices are still
    /// announced to the others, but they do not learn about the devices of the
    /// others, so a network that is not to see the rest can still be seen
    /// from it.
    pub fn with_untrusted(segments: Vec<Segment>, untrusted: &[String]) -> Result<Reflector> {
        if segments.is_empty() {
            bail!("a reflector needs at least one segment");
        }
        for (i, seg) in segments.iter().enumerate() {
            if seg.family() != segments[0].family() {
                bail!(
                    "{} is {:?} but {} is {:?}",
                    seg.interface(),
                    seg.family(),
                    segments[0].interface(),
                    segments[0].family()
                );
            }
            if segments[..i].iter().any(|o| o.interface() == seg.interface()) {
                bail!("more than one segment for interface {}", seg.interface());
            }
        }

        if let Some(unknown) = untrusted.iter().find(|name| !segments.iter().any(|s| s.interface() == name.as_str())) {
            bail!("{unknown} is untrusted but not one of the segments");
        }
        let untrusted = segments.iter().map(|s| untrusted.iter().any(|name| name == s.interface())).collect();

        let inner = Arc::new(Inner {
            segments,
            untrusted,
            book: Mutex::default(),
            stop: AtomicBool::new(false),
            subscribers: Mutex::default(),
        });

        // Subscribe before taking the snapshot so no change is missed. A
        // device seen both ways is harmless: tracking is idempotent.
        let receivers: Vec<_> = inner.segments.iter().map(Segment::subscribe).collect();
        {
            let mut book = inner.book();
            for (src, seg) in inner.segments.iter().enumerate() {
                for device in seg.devices() {
                    track(&mut book, src, device);
                }
            }
            inner.reconcile(&mut book);
        }

        let threads = receivers
            .into_iter()
            .enumerate()
            .map(|(src, events)| {
                let inner = Arc::clone(&inner);
                thread::spawn(move || inner.run(src, events))
            })
            .collect();
        Ok(Reflector { inner, threads })
    }
}

impl Reflector {
    /// The segments this reflector spans, in the order they were given.
    pub fn segments(&self) -> &[Segment] {
        &self.inner.segments
    }

    /// The interfaces whose segments are announced nothing.
    pub fn untrusted(&self) -> Vec<&str> {
        let segments = &self.inner.segments;
        (0..segments.len()).filter(|&i| self.inner.untrusted[i]).map(|i| segments[i].interface()).collect()
    }

    /// Send a [`Notice`] to `tx` for every device that appears, changes or goes
    /// on the segments this reflector spans, from now on. Stops when the
    /// receiver is dropped.
    pub fn watch(&self, tx: Sender<Notice>) {
        self.inner.subscribers.lock().unwrap_or_else(|e| e.into_inner()).push(tx);
    }
}

impl Drop for Reflector {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        // Nothing is wanted any more, so reconciling sends the goodbyes.
        let mut book = self.inner.book();
        book.sources.clear();
        self.inner.reconcile(&mut book);
    }
}

impl Inner {
    fn book(&self) -> MutexGuard<'_, Book> {
        // The book is rebuilt by reconciling, so a poisoned lock is usable.
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One worker per source segment: apply its events, and reconcile every
    /// [`RETRY`] to repair failed sends.
    fn run(&self, src: usize, events: Receiver<Event>) {
        let mut last_retry = Instant::now();
        while !self.stop.load(Ordering::SeqCst) {
            match events.recv_timeout(TICK) {
                Ok(event) => self.apply(src, event),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if last_retry.elapsed() >= RETRY {
                self.reconcile(&mut self.book());
                last_retry = Instant::now();
            }
        }
    }

    /// Tell the subscribers, before the reflecting, which can take a while.
    fn notify(&self, src: usize, event: &Event) {
        let mut subscribers = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        if subscribers.is_empty() {
            return;
        }
        let seg = &self.segments[src];
        let ttl = match event {
            Event::Removed(_) => Duration::ZERO,
            Event::Added(device) | Event::Updated(device) => seg.lifetime_left(device),
        };
        let notice = Notice { interface: seg.interface().to_string(), family: seg.family(), event: event.clone(), ttl };
        subscribers.retain(|tx| tx.send(notice.clone()).is_ok());
    }

    fn apply(&self, src: usize, event: Event) {
        self.notify(src, &event);
        let mut book = self.book();
        match event {
            Event::Added(device) | Event::Updated(device) => track(&mut book, src, device),
            Event::Removed(device) => {
                // A device that never had a name was never tracked.
                if let Some(key) = device.key() {
                    book.sources.remove(&(src, key));
                }
            }
        }
        self.reconcile(&mut book);
    }

    /// What `target` should be announcing: every reflectable device from the
    /// other segments (nothing, if it is untrusted), by hostname. If two devices announce the same hostname
    /// (the cache-flush bit would make them overwrite each other), the one from
    /// the lowest-numbered segment wins; the other takes over when it goes.
    /// Different hostnames never clash, even on one address: a device may have
    /// several names, each with services of its own.
    ///
    /// A device's link-local address is dropped: it only means something on
    /// the link the device is on, and on any other it names nobody.
    fn desired(&self, book: &Book, target: usize) -> HashMap<String, Device> {
        let mut out: HashMap<String, Device> = HashMap::new();
        if self.untrusted[target] {
            return out;
        }
        for ((src, key), device) in &book.sources {
            if *src == target || out.contains_key(key) {
                continue;
            }
            out.insert(key.clone(), Device { link_local: None, ..device.clone() });
        }
        out
    }

    /// Bring every target in line with [`Inner::desired`]. Failures are
    /// logged and left as a difference, so the next call retries them.
    fn reconcile(&self, book: &mut Book) {
        for (target, seg) in self.segments.iter().enumerate() {
            let desired = self.desired(book, target);

            let stale: Vec<String> = book
                .pushed
                .keys()
                .filter(|(t, key)| *t == target && !desired.contains_key(key))
                .map(|(_, key)| key.clone())
                .collect();
            for key in stale {
                match seg.remove_manual(&key) {
                    Ok(_) => {
                        book.pushed.remove(&(target, key));
                    }
                    Err(e) => eprintln!("{}/{:?}: withdrawing {key} failed: {e:#}", seg.interface(), seg.family()),
                }
            }

            for (key, device) in desired {
                if book.pushed.get(&(target, key.clone())) == Some(&device) {
                    continue;
                }
                match seg.add_manual(device.clone()) {
                    Ok(_) => {
                        book.pushed.insert((target, key), device);
                    }
                    Err(e) => eprintln!("{}/{:?}: announcing {key} failed: {e:#}", seg.interface(), seg.family()),
                }
            }
        }
    }
}

/// Only devices that can actually be announced elsewhere are reflected: that
/// takes a hostname for the address record and a routable address to put in it
/// (a device known only by a link-local address cannot be reached from another
/// network), and services give clients a reason to care (bare chatty clients
/// such as phones are skipped).
fn reflectable(device: &Device) -> bool {
    device.hostname.is_some() && device.routable.is_some() && !device.services.is_empty()
}

fn track(book: &mut Book, src: usize, device: Device) {
    // Without a name there is nothing to key it by, and it is not reflectable.
    let Some(key) = device.key() else { return };
    let key = (src, key);
    if reflectable(&device) {
        book.sources.insert(key, device);
    } else {
        book.sources.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

    use super::*;
    use crate::parser::{Header, Message, RData, Record};
    use crate::socket::Family;

    /// A segment whose "multicast group" is a local socket we can read.
    fn wired(name: &str) -> (Segment, UdpSocket) {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seg = Segment::new(name, Family::V4);
        seg.attach(tx, rx.local_addr().unwrap());
        (seg, rx)
    }

    /// Like [`wired`], for an IPv6 segment.
    fn wired_v6(name: &str) -> (Segment, UdpSocket) {
        let (_, rx) = wired(name);
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seg = Segment::new(name, Family::V6);
        seg.attach(tx, rx.local_addr().unwrap());
        (seg, rx)
    }

    #[test]
    fn watching_a_reflector_follows_every_segment_it_spans() {
        let (a, _ra) = wired("a");
        let (b, _rb) = wired("b");
        let reflector = Reflector::new(vec![a.clone(), b.clone()]).unwrap();
        let (tx, notices) = std::sync::mpsc::channel();
        reflector.watch(tx);
        let next = || notices.recv_timeout(Duration::from_secs(2)).unwrap();

        a.observe("10.0.1.1".parse().unwrap());
        let first = next();
        assert_eq!((first.interface.as_str(), first.family), ("a", Family::V4));
        assert!(matches!(first.event, Event::Added(_)));
        // Kept for at least the floor, whatever its records said.
        assert_eq!(first.ttl, crate::socket::DEFAULT_MIN_LIFETIME);

        b.observe("10.0.2.2".parse().unwrap());
        assert_eq!(next().interface, "b");

        // Gone is ttl 0.
        a.expire(Instant::now() + Duration::from_secs(3600));
        let gone = next();
        assert!(matches!(gone.event, Event::Removed(_)));
        assert_eq!((gone.interface.as_str(), gone.ttl), ("a", Duration::ZERO));
    }

    #[test]
    fn a_watcher_that_is_dropped_is_forgotten_and_reflecting_goes_on() {
        let (a, _ra) = wired("a");
        let (b, rb) = wired("b");
        let reflector = Reflector::new(vec![a.clone(), b]).unwrap();
        let (tx, notices) = std::sync::mpsc::channel();
        reflector.watch(tx);
        drop(notices);
        // The first event finds the receiver gone; reflecting is unaffected.
        a.observe("10.0.1.1".parse().unwrap());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !reflector.inner.subscribers.lock().unwrap().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(reflector.inner.subscribers.lock().unwrap().is_empty());
        let _ = rb;
    }

    fn drain(rx: &UdpSocket) -> Vec<Message> {
        let mut buf = [0u8; 9000];
        let mut out = Vec::new();
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            out.push(Message::parse(&buf[..n]).unwrap());
        }
        out
    }

    fn wait_for(cond: impl Fn() -> bool) {
        for _ in 0..300 {
            if cond() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for condition");
    }

    fn rec(name: &str, data: RData) -> Record {
        rec_ttl(name, data, 120)
    }

    fn rec_ttl(name: &str, data: RData, ttl: u32) -> Record {
        Record { name: name.into(), class: 1, cache_flush: false, ttl, data }
    }

    /// Make `seg` hear `host` at `from` announcing one service per instance.
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
        thread::sleep(Duration::from_millis(100));
        assert!(b.manual_devices().is_empty());
        assert!(drain(&brx).is_empty());
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
            d.len() == 1 && d[0].routable == Some(ip("10.0.1.5"))
        });

        a.expire(Instant::now() + Duration::from_secs(36000));
        wait_for(|| {
            let d = c.manual_devices();
            d.len() == 1 && d[0].routable == Some(ip("10.0.2.5"))
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
        thread::sleep(Duration::from_millis(100));
        assert!(drain(&media_rx).is_empty() && drain(&wifi_rx).is_empty(), "nothing was sent to them");
        assert!(!drain(&br0_rx).is_empty());

        // They are still tracked, and withdrawn from br0 when they go.
        assert_eq!(media.devices().len(), 1);
        media.expire(Instant::now() + Duration::from_secs(3600));
        wait_for(|| announced_on(&br0) == ["plug.local"]);
    }

    #[test]
    fn untrusted_must_name_a_segment_of_the_reflector_and_trusted_is_the_default() {
        let (a, _ra) = wired("a");
        let (b, _rb) = wired("b");
        assert!(Reflector::with_untrusted(vec![a.clone(), b.clone()], &["c".to_string()]).is_err());
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
        assert_eq!(a.devices()[0].services[0].ttl, 600);
    }

    #[test]
    fn a_configured_reflect_ttl_wins_for_the_address_and_leaves_the_services_alone() {
        let (a, _arx) = wired("a");
        let (b, brx) = wired("b");
        b.set_reflect_ttl(Some(Duration::from_secs(900)));
        let _r = Reflector::new(vec![a.clone(), b.clone()]).unwrap();

        announce_ttl(&a, "10.0.1.5", "tv.local", &["TV"], 300, 600);
        wait_for(|| b.manual_devices().len() == 1);
        assert_eq!(announced_ttls(&brx), (vec![900], vec![600, 600, 600]));
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
        thread::sleep(Duration::from_millis(100));

        let mut names: Vec<_> = b.manual_devices().iter().map(|d| d.hostname.clone().unwrap()).collect();
        names.sort();
        assert_eq!(names, ["tv-nsas-1.local", "tv.local"]);
        assert!(b.manual_devices().iter().all(|d| d.routable == Some(ip("10.0.1.5"))));
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
        thread::sleep(Duration::from_millis(100));

        // b learned both, but a and c each only learned about b's side.
        assert_eq!(a.manual_devices().len(), 0);
        assert_eq!(c.manual_devices().len(), 0);

        announce(&b, "10.0.2.5", "tv-b.local", &["B"]);
        wait_for(|| a.manual_devices().len() == 1 && c.manual_devices().len() == 1);
        assert_eq!(a.manual_devices()[0].routable, Some(ip("10.0.2.5")));
        assert_eq!(c.manual_devices()[0].routable, Some(ip("10.0.2.5")));

        // Dropping one reflector withdraws only what it announced.
        drop(r_ab);
        assert!(a.manual_devices().is_empty());
        let on_b: Vec<_> = b.manual_devices().iter().map(|d| d.routable.unwrap()).collect();
        assert_eq!(on_b, [ip("10.0.3.5")]);
        assert_eq!(c.manual_devices().len(), 1);
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
        assert_eq!((home.routable, home.link_local), (Some(ip("fd00:0:1::5")), Some(ip("fe80::5"))));
        // ...but the other network is told only the routable one.
        let there = &b.manual_devices()[0];
        assert_eq!((there.routable, there.link_local), (Some(ip("fd00:0:1::5")), None));
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
        thread::sleep(Duration::from_millis(100));
        assert_eq!(a.devices()[0].routable, None);
        assert!(b.manual_devices().is_empty());
        assert!(drain(&brx).is_empty());
    }

    #[test]
    fn single_segment_reflects_nothing() {
        let (a, arx) = wired("a");
        let _r = Reflector::new(vec![a.clone()]).unwrap();
        announce(&a, "10.0.1.5", "tv.local", &["TV"]);
        thread::sleep(Duration::from_millis(100));
        assert!(a.manual_devices().is_empty());
        assert!(drain(&arx).is_empty());
    }

    #[test]
    fn rejects_bad_construction() {
        let (a, _) = wired("a");
        let (b, _) = wired("b");
        assert!(Reflector::new(vec![]).is_err());
        assert!(Reflector::new(vec![a.clone(), a.clone()]).is_err());
        let v6 = Segment::new("c", Family::V6);
        assert!(Reflector::new(vec![a, b, v6]).is_err());
    }
}
