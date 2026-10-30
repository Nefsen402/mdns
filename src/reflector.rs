//! Reflects devices between segments, over every address family they serve.
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

use crate::device::{Device, Service};
use crate::socket::{Asked, Event, Owner, Segment};

/// How often a worker checks for shutdown while waiting for events.
const TICK: Duration = Duration::from_millis(250);

/// How often a worker reconciles even without events, to retry failed sends.
const RETRY: Duration = Duration::from_secs(5);

/// Which of the questions asked on one of a reflector's segments it puts to
/// the others (`ForwardQuestions=`). Never a probe, nor one about a name a
/// device on the asking segment owns: it answers for itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Forward {
    /// Every one. A browse for a type that one device was heard to have can
    /// have other answers still, from devices that only answer when asked.
    #[default]
    Always,
    /// Those that nothing announced on the asking segment has an answer to.
    Unknown,
    /// None: only what devices announce, or answer a probe with, is reflected.
    Never,
}

/// A change to a device discovered on one of a reflector's segments, as
/// [`Reflector::watch`] delivers it.
#[derive(Clone, Debug)]
pub struct Notice {
    /// The segment the device was discovered on.
    pub interface: String,
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
    /// Whose the devices it announces are, on segments it shares with other
    /// reflectors.
    owner: Owner,
    segments: Vec<Segment>,
    /// Whether each segment is untrusted: it is not announced anything.
    untrusted: Vec<bool>,
    forward: Forward,
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
    ///
    /// `rank` settles clashes with other reflectors that share an interface:
    /// if both want a hostname announced there, the lower rank's device is,
    /// and the other's takes over when it goes. The daemon ranks reflectors
    /// by the order of their segments in the config.
    pub fn new(rank: u32, segments: Vec<Segment>) -> Result<Reflector> {
        Self::with_untrusted(rank, segments, &[])
    }

    /// Like [`new`](Reflector::new), but the segments on the interfaces named
    /// in `untrusted` are announced nothing: their devices are still
    /// announced to the others, but they do not learn about the devices of the
    /// others, so a network that is not to see the rest can still be seen
    /// from it.
    pub fn with_untrusted(rank: u32, segments: Vec<Segment>, untrusted: &[String]) -> Result<Reflector> {
        Self::with_options(rank, segments, untrusted, Forward::default())
    }

    /// Like [`with_untrusted`](Reflector::with_untrusted), putting the
    /// questions asked on each segment to the others as `forward` says.
    pub fn with_options(rank: u32, segments: Vec<Segment>, untrusted: &[String], forward: Forward) -> Result<Reflector> {
        if segments.is_empty() {
            bail!("a reflector needs at least one segment");
        }
        for (i, seg) in segments.iter().enumerate() {
            if segments[..i].iter().any(|o| o.interface() == seg.interface()) {
                bail!("more than one segment for interface {}", seg.interface());
            }
        }

        if let Some(unknown) = untrusted.iter().find(|name| !segments.iter().any(|s| s.interface() == name.as_str())) {
            bail!("{unknown} is untrusted but not one of the segments");
        }
        let untrusted = segments.iter().map(|s| untrusted.iter().any(|name| name == s.interface())).collect();

        let inner = Arc::new(Inner {
            owner: Owner::Reflector(rank),
            segments,
            untrusted,
            forward,
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
            Event::Removed(_) | Event::Question(_) => Duration::ZERO,
            Event::Added(device) | Event::Updated(device) => seg.lifetime_left(device),
        };
        let notice = Notice { interface: seg.interface().to_string(), event: event.clone(), ttl };
        subscribers.retain(|tx| tx.send(notice.clone()).is_ok());
    }

    fn apply(&self, src: usize, event: Event) {
        if let Event::Question(questions) = &event {
            return self.forward(src, questions);
        }
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
            // Forwarded above.
            Event::Question(_) => {}
        }
        self.reconcile(&mut book);
    }

    /// Put the questions asked on `src`, those [`Forward`] lets through, to
    /// the other segments: those whose devices are announced on it, so whose
    /// answers will be. An untrusted segment is announced nothing, so its
    /// questions are put nowhere.
    fn forward(&self, src: usize, asked: &[Asked]) {
        if self.untrusted[src] {
            return;
        }
        let questions: Vec<_> = asked
            .iter()
            .filter(|a| match self.forward {
                Forward::Always => true,
                Forward::Unknown => !a.answered,
                Forward::Never => false,
            })
            .map(|a| a.question.clone())
            .collect();
        if questions.is_empty() {
            return;
        }
        for (target, seg) in self.segments.iter().enumerate() {
            if target == src {
                continue;
            }
            if let Err(e) = seg.query_question(&questions) {
                eprintln!("{}: asking on behalf of {} failed: {e:#}", seg.interface(), self.segments[src].interface());
            }
        }
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
            let services = device.services.iter().filter(|s| resolved(s)).cloned().collect();
            out.insert(key.clone(), Device { services, ..device.without_link_local() });
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
                match seg.remove_manual(self.owner, &key) {
                    Ok(_) => {
                        book.pushed.remove(&(target, key));
                    }
                    Err(e) => eprintln!("{}: withdrawing {key} failed: {e:#}", seg.interface()),
                }
            }

            for (key, device) in desired {
                if book.pushed.get(&(target, key.clone())) == Some(&device) {
                    continue;
                }
                match seg.add_manual(self.owner, device.clone()) {
                    Ok(_) => {
                        book.pushed.insert((target, key), device);
                    }
                    Err(e) => eprintln!("{}: announcing {key} failed: {e:#}", seg.interface()),
                }
            }
        }
    }
}

/// Only devices that can actually be announced elsewhere are reflected: that
/// takes a hostname for the address record and a routable address to put in it
/// (a device known only by a link-local address cannot be reached from another
/// network), and a resolved service to give clients a reason to care (bare
/// chatty clients such as phones are skipped).
fn reflectable(device: &Device) -> bool {
    device.hostname.is_some() && device.routable().next().is_some() && device.services.iter().any(resolved)
}

/// Whether it is known where `svc` is, by its SRV record: a host and a port.
/// One known only by name from a browse answer or a TXT record is not
/// reflected, since a copy would have to make up the rest.
fn resolved(svc: &Service) -> bool {
    svc.target.is_some() && svc.port != 0
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
    use crate::parser::{rtype, Header, Message, Question, RData, Record};
    use crate::socket::Family;

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
        seg.attach(Family::V4, tx, rx.local_addr().unwrap());
        (seg, rx)
    }

    /// Like [`wired`], for an IPv6 segment.
    fn wired_v6(name: &str) -> (Segment, UdpSocket) {
        let (_, rx) = wired(name);
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seg = Segment::new(name, &[Family::V6]);
        seg.attach(Family::V6, tx, rx.local_addr().unwrap());
        (seg, rx)
    }

    #[test]
    fn watching_a_reflector_follows_every_segment_it_spans() {
        let (a, _ra) = wired("a");
        let (b, _rb) = wired("b");
        let reflector = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
        let (tx, notices) = std::sync::mpsc::channel();
        reflector.watch(tx);
        let next = || notices.recv_timeout(Duration::from_secs(2)).unwrap();

        a.observe("10.0.1.1".parse().unwrap());
        let first = next();
        assert_eq!(first.interface, "a");
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
        let reflector = Reflector::new(0, vec![a.clone(), b]).unwrap();
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
        let _r = Reflector::new(0, vec![a.clone(), b.clone(), c.clone()]).unwrap();

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

        let _r = Reflector::new(0, vec![a, b.clone()]).unwrap();
        assert_eq!(b.manual_devices().len(), 1);
        assert_eq!(drain(&brx).len(), 1);
    }

    #[test]
    fn removal_withdraws_with_goodbye() {
        let (a, _arx) = wired("a");
        let (b, brx) = wired("b");
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
        announce(&a, "10.0.1.5", "tv.local", &["TV"]);
        wait_for(|| b.manual_devices().len() == 1);

        announce(&a, "10.0.1.5", "tv.local", &["TV", "Cast"]);
        wait_for(|| b.manual_devices()[0].services.len() == 2);
    }

    #[test]
    fn skips_devices_that_cannot_be_announced() {
        let (a, _arx) = wired("a");
        let (b, brx) = wired("b");
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();

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
        let r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        let _r = Reflector::new(0, vec![a.clone(), b.clone(), c.clone()]).unwrap();

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
            0,
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
        assert!(Reflector::with_untrusted(0, vec![a.clone(), b.clone()], &["c".to_string()]).is_err());
        let r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();

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
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();

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
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();

        announce(&a, "10.0.1.5", "tv.local", &["Airplay"]);
        announce(&a, "10.0.1.5", "tv-nsas-1.local", &["Display"]);
        wait_for(|| a.devices().len() == 2);
        thread::sleep(Duration::from_millis(100));

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
        let r_ab = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
        let _r_bc = Reflector::new(1, vec![b.clone(), c.clone()]).unwrap();

        announce(&a, "10.0.1.5", "tv-a.local", &["A"]);
        announce(&c, "10.0.3.5", "tv-c.local", &["C"]);
        wait_for(|| b.manual_devices().len() == 2);
        thread::sleep(Duration::from_millis(100));

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
        let _first = Reflector::new(0, vec![br0.clone(), media.clone()]).unwrap();
        let _second = Reflector::new(1, vec![br0.clone(), wifi.clone()]).unwrap();
        let on_br0 = || br0.manual_devices().iter().map(v4).collect::<Vec<_>>();
        let gone = || Instant::now() + Duration::from_secs(3600);

        // Media's wins, and is not displaced by the one heard after it.
        announce(&media, "10.0.2.5", "TV.local", &["Media TV"]);
        wait_for(|| on_br0() == [Some(ip("10.0.2.5"))]);
        announce(&wifi, "10.0.3.5", "tv.local", &["Wifi TV"]);
        wait_for(|| wifi.devices().len() == 1);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(on_br0(), [Some(ip("10.0.2.5"))]);

        wifi.expire(gone());
        thread::sleep(Duration::from_millis(100));
        assert_eq!(on_br0(), [Some(ip("10.0.2.5"))]);

        // The winner going hands the name over instead of withdrawing it.
        announce(&wifi, "10.0.3.5", "tv.local", &["Wifi TV"]);
        thread::sleep(Duration::from_millis(100));
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
        let _r = Reflector::new(0, vec![br0.clone(), media.clone()]).unwrap();
        let on_br0 = || br0.manual_devices().iter().map(v4).collect::<Vec<_>>();
        let tv_records = |msgs: Vec<Message>| -> Vec<Record> {
            msgs.into_iter().flat_map(|m| m.answers).filter(|r| r.name.eq_ignore_ascii_case("tv.local")).collect()
        };

        announce(&br0, "10.0.0.5", "tv.local", &["Living Room"]);
        announce(&media, "10.0.2.5", "TV.local", &["Living Room"]);
        wait_for(|| br0.devices().len() == 1 && media.devices().len() == 1);
        thread::sleep(Duration::from_millis(100));
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
        let router = Device { hostname: Some("router.local".into()), addresses: vec![ip("10.0.0.1")], ..Device::default() };
        br0.add_manual_ttl(Owner::Own, router.clone(), Duration::from_secs(120)).unwrap();
        let _r = Reflector::new(0, vec![br0.clone(), media.clone()]).unwrap();
        drain(&br0_rx);

        announce(&media, "10.0.2.5", "Router.local", &["Admin"]);
        wait_for(|| media.devices().len() == 1);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(br0.manual_devices(), std::slice::from_ref(&router));

        media.expire(Instant::now() + Duration::from_secs(3600));
        wait_for(|| media.devices().is_empty());
        thread::sleep(Duration::from_millis(100));
        assert_eq!(br0.manual_devices(), [router]);
        assert!(drain(&br0_rx).is_empty(), "nothing about it was sent, or withdrawn");
    }

    /// A service known only by its text (Apple's `_device-info` has no SRV)
    /// is not reflected: a copy would have to make up its port and host.
    #[test]
    fn only_services_known_where_they_are_are_reflected() {
        let (a, _arx) = wired("a");
        let (b, _brx) = wired("b");
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        thread::sleep(Duration::from_millis(100));
        assert!(b.manual_devices().is_empty(), "nothing resolved to reflect");

        announce(&a, "10.0.1.5", "tv.local", &["TV"]);
        wait_for(|| b.manual_devices().len() == 1);
        let names: Vec<String> = b.manual_devices()[0].services.iter().map(|s| s.instance.clone()).collect();
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
        let _r = Reflector::with_options(0, segments, &["wifi".to_string()], Forward::Unknown).unwrap();

        ask(&br0, "10.0.0.50", "printer.local");
        thread::sleep(Duration::from_millis(100));
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
        thread::sleep(Duration::from_millis(100));
        assert!(asked_names(&drain(&media_rx)).is_empty() && asked_names(&drain(&wifi_rx)).is_empty());

        // The untrusted one asks: nothing is asked on its behalf.
        ask(&wifi, "10.0.3.50", "nas.local");
        thread::sleep(Duration::from_millis(100));
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
            let _r = Reflector::with_options(0, vec![br0.clone(), media.clone()], &[], forward).unwrap();
            announce(&media, "10.0.2.7", "tv.local", &["TV"]);
            wait_for(|| br0.manual_devices().len() == 1);
            drain(&media_rx);

            ask_type(&br0, "10.0.0.50", "_http._tcp.local", rtype::PTR);
            thread::sleep(Duration::from_millis(100));
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
            thread::sleep(Duration::from_millis(100));
            let asked = asked_names(&drain(&media_rx));
            assert_eq!(asked.is_empty(), forward == Forward::Never, "{forward:?}: {asked:?}");
        }
    }

    /// A device's IPv6 address heard over IPv4 is reflected with it, for
    /// clients that ask over IPv4; its link-local ones, of either family, are
    /// not.
    #[test]
    fn a_copy_carries_both_families_but_no_link_local_address() {
        let (a, _arx) = wired("a");
        let (b, brx) = wired("b");
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        assert_eq!(there.addresses, [ip("10.0.1.5"), ip("fd00::5")]);
        let sent: Vec<RData> = drain(&brx).into_iter().flat_map(|m| m.answers).filter(|r| r.name == "tv.local").map(|r| r.data).collect();
        assert_eq!(sent, [RData::A("10.0.1.5".parse().unwrap()), RData::Aaaa("fd00::5".parse().unwrap())]);
    }

    /// On a network with a global and a ULA prefix, a device's copy carries
    /// both: which one a client can use depends on where it is.
    #[test]
    fn a_copy_carries_a_global_and_a_ula_address() {
        let (a, _arx) = wired("a");
        let (b, brx) = wired("b");
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        assert_eq!(b.manual_devices()[0].addresses, [ip("2001:db8::5"), ip("fd00::5")]);
        let sent: Vec<RData> = drain(&brx).into_iter().flat_map(|m| m.answers).filter(|r| r.name == "tv.local").map(|r| r.data).collect();
        assert_eq!(sent, [RData::Aaaa("2001:db8::5".parse().unwrap()), RData::Aaaa("fd00::5".parse().unwrap())]);
    }

    /// An address the device stops announcing runs out on its own, and the
    /// copy is told to drop just that one.
    #[test]
    fn a_copy_drops_an_address_that_ran_out() {
        let (a, _arx) = wired("a");
        let (b, brx) = wired("b");
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();
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
        wait_for(|| b.manual_devices().first().is_some_and(|d| d.addresses == [ip("fd00::5")]));
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
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();

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
        let _r = Reflector::new(0, vec![a.clone(), b.clone()]).unwrap();

        announce6(&a, "fe80::6", "mute.local", &["fe80::6"], "Mute");
        wait_for(|| !a.devices().is_empty());
        thread::sleep(Duration::from_millis(100));
        assert_eq!(v4(&a.devices()[0]), None);
        assert!(b.manual_devices().is_empty());
        assert!(drain(&brx).is_empty());
    }

    #[test]
    fn single_segment_reflects_nothing() {
        let (a, arx) = wired("a");
        let _r = Reflector::new(0, vec![a.clone()]).unwrap();
        announce(&a, "10.0.1.5", "tv.local", &["TV"]);
        thread::sleep(Duration::from_millis(100));
        assert!(a.manual_devices().is_empty());
        assert!(drain(&arx).is_empty());
    }

    #[test]
    fn rejects_bad_construction() {
        let (a, _) = wired("a");
        assert!(Reflector::new(0, vec![]).is_err());
        assert!(Reflector::new(0, vec![a.clone(), a.clone()]).is_err());
    }
}
