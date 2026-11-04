//! The devices heard on a segment: what a packet said ([`Heard`]), read once
//! and apart from what is known, and the devices it brings up to date.

use core::net::IpAddr;
use core::time::Duration;

use alloc::collections::BTreeSet;

use hashbrown::HashMap;

use crate::device::{addr_of, family_of, is_link_local, is_type, is_usable, Device, Origin, Report, HOST_TTL, META_QUERY, OTHER_TTL};
use alloc::rc::Rc;

use crate::segment::Asked;
use crate::parser::{Message, Question, RData, Record};
use crate::prelude::*;
use crate::config::{DEFAULT_MAX_ADDRS, DEFAULT_MAX_DEVICES, DEFAULT_MAX_SERVICES, DEFAULT_MIN_LIFETIME};
use crate::socket::{Family, Prefix};
use crate::time::Instant;

mod devices;
mod neighbours;
pub(crate) use devices::{Devices, Id, Indexed};
pub(crate) use neighbours::NeighbourTable;

/// Service types remembered per segment, so a hostile device cannot grow it
/// without bound by announcing endless made-up types.
pub const MAX_TYPES: usize = 256;

/// Hosts first described by any one sender, so that one inventing endless
/// devices (or many forged ones) cannot fill the segment, which has room for
/// [`DEFAULT_MAX_DEVICES`] unless set otherwise. A sleep proxy or Thread
/// border router speaks for several hosts, but not for this many.
pub const MAX_PER_SENDER: usize = 64;

/// How long after asking a device on its link-local address, so that the
/// kernel looks up its link-layer address, it is not asked so again.
const NUDGE_GAP: Duration = Duration::from_secs(60);

/// What is known of the devices heard on a segment.
pub struct Tracker {
    pub discovered: Devices,
    /// Service types devices on this segment have said they offer, learned
    /// from answers to the type enumeration query.
    pub types: BTreeSet<String>,
    /// The least a device is kept after it was last heard from.
    pub min_lifetime: Duration,
    /// How many addresses of a family a discovered device is kept with.
    pub max_addrs: usize,
    /// How many devices it remembers, at most.
    pub max_devices: usize,
    /// How many services a device is kept with, at most.
    pub max_services: usize,
    /// The kernel's neighbour table for the interface: each address it has a
    /// link-layer address for, and that link-layer address.
    pub neighbours: NeighbourTable,
    /// The networks the interface is on: of the neighbour table, only
    /// addresses in one of them are learned.
    pub prefixes: Vec<Prefix>,
}

impl Default for Tracker {
    fn default() -> Tracker {
        Tracker {
            discovered: Devices::default(),
            types: BTreeSet::new(),
            min_lifetime: DEFAULT_MIN_LIFETIME,
            max_addrs: DEFAULT_MAX_ADDRS,
            max_devices: DEFAULT_MAX_DEVICES,
            max_services: DEFAULT_MAX_SERVICES,
            neighbours: NeighbourTable::default(),
            prefixes: Vec::new(),
        }
    }
}

impl Tracker {
    /// Whether a new host may be learned of from `src`: the segment has
    /// fewer than it is set to remember, and `src` first described fewer than
    /// [`MAX_PER_SENDER`] of them.
    pub fn room_for(&self, src: IpAddr) -> bool {
        self.discovered.len() < self.max_devices && self.discovered.described_by(&src) < MAX_PER_SENDER
    }

    /// Bring the addresses learned from the neighbour table up to date for
    /// the devices of `keys`, noting in `touched` those that change: the
    /// routable addresses listed under the link-layer address of one it
    /// announced, in a network the interface is on (an entry left over from
    /// one it is no longer on is not the device's to be reached at), of a
    /// family it announced no routable address of
    /// ([`Device::take_neighbours`]). A device with a link-local IPv6 address
    /// the table has not got yet, and no routable one, is asked a question on
    /// it, for the kernel to look up its link-layer address.
    pub fn learn_neighbours(&mut self, ids: &[Id], touched: &mut Touched, now: Instant) {
        for &id in ids {
            let Some(entry) = self.discovered.try_get(id) else { continue };
            // Its link-layer address, by any address it announced.
            let announced = entry.device.addresses.iter().filter(|a| a.origin == Origin::Announced);
            let mut macs: Vec<&Vec<u8>> = announced.filter_map(|a| self.neighbours.get(&a.ip)).collect();
            macs.sort_unstable();
            macs.dedup();
            let on_link = |ip: &IpAddr| self.prefixes.iter().any(|p| p.contains(ip));
            let learned: Vec<IpAddr> = macs
                .iter()
                .flat_map(|mac| self.neighbours.with_mac(mac))
                .filter(|ip| !is_link_local(ip) && on_link(ip))
                .collect();

            let unresolved = entry.device.link_local().find(|ll| ll.is_ipv6() && !self.neighbours.contains_key(ll));
            let has_v6 = entry.device.routable().any(|a| a.is_ipv6());
            let due = entry.nudged.is_none_or(|t| now.saturating_duration_since(t) >= NUDGE_GAP);
            if let Some(ll) = unresolved.filter(|_| !has_v6 && due) {
                touched.nudges.push((ll, entry.device.clone()));
                self.discovered.get_mut(id).nudged = Some(now);
            }

            let mut device = self.discovered.get(id).device.clone();
            if device.take_neighbours(&learned, self.max_addrs) {
                touched.note(&self.discovered, id);
                self.discovered.get_mut(id).device = device;
            }
        }
    }

    /// Bring the learned addresses of the devices of `ids` up to date, noting
    /// in what is returned those that changed.
    pub fn relearn(&mut self, ids: &[Id], now: Instant) -> Touched {
        let mut touched = Touched::default();
        self.learn_neighbours(ids, &mut touched, now);
        touched.sync(&mut self.discovered);
        touched
    }

    /// Bring the devices up to date with what `msg`, a packet from `src` at
    /// `now`, said, noting what changed in what is returned, for it to be told
    /// of. Nothing is said by one that could not be read (`None`), but that
    /// `src` is there, nor by a query: the records in it are other devices'
    /// known answers.
    pub fn track(&mut self, src: IpAddr, now: Instant, msg: Option<&Message>) -> Touched {
        let msg = msg.filter(|m| m.header.response);
        let records = || msg.into_iter().flat_map(|m| m.records());
        let (floor, max_addrs, max_services) = (self.min_lifetime, self.max_addrs, self.max_services);
        let mut touched = Touched::default();

        // A response saying goodbye (TTL 0) to the address it came from, and
        // announcing none for that name still, is a device leaving: the device
        // that owns the name, and anything the sender was only known by. One
        // that announces others in its place (a temporary IPv6 address giving
        // way to the next) is not; it only loses the one.
        let still = |name: &str| records().any(|r| r.ttl > 0 && addr_of(&r.data).is_some() && r.name.eq_ignore_ascii_case(name));
        let leaving: Vec<&str> = records()
            .filter(|r| r.ttl == 0 && addr_of(&r.data) == Some(src) && !still(&r.name))
            .map(|r| r.name.as_str())
            .collect();
        if !leaving.is_empty() {
            let mut gone: Vec<Id> = leaving.iter().filter_map(|name| self.discovered.find_host(name)).collect();
            gone.extend(self.discovered.find_nameless(&src));
            gone.dedup();
            for id in gone {
                touched.note(&self.discovered, id);
                self.discovered.remove(id);
            }
            return touched;
        }

        // The service types it said exist: the answers to the question of what
        // types there are.
        for rec in records() {
            if let RData::Ptr(kind) = &rec.data
                && rec.ttl > 0
                && rec.name.eq_ignore_ascii_case(META_QUERY)
                && rec.class == 1
                && is_type(kind)
                && self.types.len() < MAX_TYPES
            {
                self.types.insert(kind.to_ascii_lowercase());
            }
        }

        // A response may describe several devices (a reflector answering a
        // browse query does), so attribute each record to the device it names
        // instead of the whole packet to one.
        let (reports, rest) = match msg {
            Some(m) => Report::all(m),
            None => (Vec::new(), Vec::new()),
        };

        // The host that turns out to be the sender, if any: the one that
        // announced the address the packet came from, or the only one
        // described when it announced no address at all.
        let mut sender: Option<Id> = None;
        let mut resolved: Vec<(Id, String)> = Vec::new();

        for report in &reports {
            let known = self.discovered.find_host(&report.host);
            if known.is_none() && !self.room_for(src) {
                continue;
            }
            // Goodbyes alone for a device not known here (one that already
            // left by its other family's goodbye) leave nothing to forget, and
            // are not to bring it back.
            if report.addrs.is_empty() && !report.gone.is_empty() && known.is_none() {
                continue;
            }
            // The sender, if it announced the address the packet came from. A
            // device has the addresses it announced and no other: that a packet
            // about it came from one is not its saying so (a router answers for
            // what is behind it).
            let announced_src = report.addrs.contains(&src);
            let addrs = report.addrs.clone();

            // A device first heard only by address becomes the named device, if
            // it announced the address.
            let nameless = self.discovered.find_nameless(&src).filter(|_| announced_src);
            let earlier = nameless.and_then(|id| {
                touched.note(&self.discovered, id);
                self.discovered.remove(id)
            });

            let id = match known {
                Some(id) => {
                    touched.note(&self.discovered, id);
                    id
                }
                None => {
                    let id = self.discovered.create(Entry::new(now, src, Some(&report.host)));
                    touched.note_new(id);
                    id
                }
            };
            let entry = self.discovered.get_mut(id);
            if let Some(earlier) = earlier {
                entry.absorb(earlier, max_services);
            }
            let was = entry.soonest();
            let ttl = Duration::from_secs(report.longest_ttl().into());
            entry.expires = entry.expires.max(now + ttl.max(floor));
            entry.make_room(&addrs, &report.flushed, &report.gone, max_addrs);
            entry.device.learn(report, &addrs, max_addrs, max_services);
            entry.renew_addrs(&addrs, &report.ttls, now, floor);
            if entry.soonest() != was {
                entry.began = now;
            }

            resolved.extend(report.resolved().map(|instance| (id, instance.to_string())));
            if announced_src && sender.is_none() {
                sender = Some(id);
            }
        }

        // What is left is about the sender itself: records tied to no host (a
        // bare browse answer, text records), or just a sign of life such as a
        // query. A packet that only describes other devices says nothing about
        // its sender, which is then not recorded at all.
        // One known only by an address no device can be reached at is not
        // known at all.
        let usable = is_usable(src);
        touched.sync(&mut self.discovered);
        let known = sender
            .or_else(|| self.discovered.holder_of(&src))
            .or_else(|| self.discovered.find_nameless(&src).filter(|_| usable));
        // One heard by its address if it is not known at all, and there is room.
        let room = known.is_some() || (usable && self.discovered.len() < self.max_devices);
        if (known.is_some() || usable) && room && (reports.is_empty() || !rest.is_empty()) {
            let id = match known {
                Some(id) => {
                    touched.note(&self.discovered, id);
                    id
                }
                None => {
                    let id = self.discovered.create(Entry::new(now, src, None));
                    touched.note_new(id);
                    id
                }
            };
            let entry = self.discovered.get_mut(id);
            let was = entry.soonest();
            let ttl = rest.iter().map(|r| r.ttl).max().unwrap_or(0);
            let ttl = Duration::from_secs(ttl as u64);
            entry.expires = entry.expires.max(now + ttl.max(floor));
            if usable {
                entry.make_room(&[src], &[], &[], max_addrs);
                entry.device.take_addrs(&[src], &[], &[], max_addrs);
                entry.renew_addrs(&[src], &HashMap::new(), now, floor);
            }
            if entry.soonest() != was {
                entry.began = now;
            }
            entry.device.learn_records(rest.iter().copied(), max_services);
        }

        // An instance that has now been resolved to its host no longer needs
        // the unresolved copy learned from a bare browse answer.
        touched.sync(&mut self.discovered);
        for (owner, instance) in resolved {
            let others: Vec<Id> = self
                .discovered
                .with_unresolved()
                .filter(|&(id, e)| id != owner && e.device.service(&instance).is_some_and(|s| s.target.is_none()))
                .map(|(id, _)| id)
                .collect();
            for id in others {
                touched.note(&self.discovered, id);
                self.discovered.get_mut(id).device.forget_service(&instance);
            }
            touched.sync(&mut self.discovered);
        }

        // What the neighbour table knows of the devices just heard of.
        let heard = touched.order.clone();
        self.learn_neighbours(&heard, &mut touched, now);

        touched.sync(&mut self.discovered);
        touched
    }
}

/// The discovered devices an `apply` touched, as they were before, so that
/// what changed can be reported once, however many devices a packet affects.
#[derive(Default)]
pub struct Touched {
    pub order: Vec<Id>,
    before: HashMap<Id, Option<Device>>,
    /// What the tables that find devices hold of each, as of when they were
    /// last made to follow it: what it was before, until then.
    indexed: HashMap<Id, Indexed>,
    /// The devices to ask on their link-local addresses, for the kernel to
    /// look up their link-layer addresses, with the device each is of.
    pub nudges: Vec<(IpAddr, Device)>,
}

impl Touched {
    /// A device is about to be changed, or to go: say so before it is, once.
    pub fn note(&mut self, discovered: &Devices, id: Id) {
        if !self.before.contains_key(&id) {
            self.order.push(id);
            self.before.insert(id, discovered.try_get(id).map(|e| e.device.clone()));
            self.indexed.insert(id, discovered.indexed_of(id));
        }
    }

    /// A device was just made.
    pub fn note_new(&mut self, id: Id) {
        self.order.push(id);
        self.before.insert(id, None);
        self.indexed.insert(id, Indexed::default());
    }

    /// Have the tables that find devices follow the changes made so far.
    pub fn sync(&mut self, discovered: &mut Devices) {
        for id in &self.order {
            let was = self.indexed.get(id).cloned().unwrap_or_default();
            self.indexed.insert(*id, discovered.reindex(*id, &was));
        }
    }

    /// What was done to each device noted, in the order they were: the
    /// devices that came, are not as they were, or went.
    pub fn events(&self, discovered: &Devices) -> Vec<Event> {
        let mut events = Vec::new();
        for id in &self.order {
            let before = self.before[id].clone().map(Rc::new);
            let after = discovered.try_get(*id).map(|e| Rc::new(e.device.clone()));
            match (before, after) {
                (None, Some(after)) => events.push(Event::Added(after)),
                (Some(before), Some(after)) if before != after => events.push(Event::Updated { before, after }),
                (Some(before), None) => events.push(Event::Removed(before)),
                _ => {}
            }
        }
        events
    }

    /// The hostnames and instance names, in lowercase, of the devices as they
    /// were and as they are: those that whoever is announcing the same may
    /// have to give way to.
    pub fn names(&self, discovered: &Devices) -> Vec<String> {
        let mut names = Vec::new();
        for id in &self.order {
            let now = discovered.try_get(*id).map(|e| &e.device);
            for device in self.before[id].iter().chain(now) {
                names.extend(device.hostname.iter().map(|host| host.to_ascii_lowercase()));
                names.extend(device.services.iter().map(|svc| svc.instance.to_ascii_lowercase()));
            }
        }
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// A change to the devices of a segment, or a question asked on it: what
/// the tracker has to say of what it heard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A device came.
    Added(Rc<Device>),
    /// A device is not as it was: its hostname, addresses or services.
    Updated { before: Rc<Device>, after: Rc<Device> },
    /// A device went, as it was.
    Removed(Rc<Device>),
    /// The questions of a query that no device here owns the name of: for
    /// the reflector to put to the segments whose devices it announces here
    /// ([`Segment::query_question`](crate::segment::Segment::query_question)),
    /// as it is configured to.
    Question(Vec<Asked>),
}

impl Event {
    /// The device it is of: as it is, or as it was if it went. None for a
    /// question.
    pub fn device(&self) -> Option<&Device> {
        match self {
            Event::Added(device) | Event::Updated { after: device, .. } | Event::Removed(device) => Some(device),
            Event::Question(_) => None,
        }
    }
}

/// A discovered device, and when to drop it or ask it again.
#[derive(Debug)]
pub struct Entry {
    pub device: Device,
    /// The address of the packet it was first heard of in.
    pub from: IpAddr,
    pub expires: Instant,
    /// When each of its addresses runs out if it is not heard of again: its
    /// own TTL after it was last heard, but not before the minimum lifetime,
    /// as for the device. One that stops being announced, without a goodbye,
    /// is so dropped on its own.
    pub addr_expires: HashMap<IpAddr, Instant>,
    /// When what runs out first ([`Entry::soonest`]) began its life: how long
    /// the device said that would be is what is left of it from here.
    pub began: Instant,
    /// When it was last asked to answer again because it was about to expire.
    pub refreshed: Option<Instant>,
    /// When it was last asked on its link-local address, for the kernel to
    /// find its link-layer address ([`NUDGE_GAP`]).
    pub nudged: Option<Instant>,
}

impl Entry {
    /// A device first heard from `from`, with the hostname it has, if it has
    /// one.
    pub fn new(now: Instant, from: IpAddr, hostname: Option<&str>) -> Entry {
        let device = Device { hostname: hostname.map(String::from), ..Device::default() };
        Entry { device, from, expires: now, addr_expires: HashMap::new(), began: now, refreshed: None, nudged: None }
    }

    /// Its records that answer `q`, each with the time it has left here as
    /// its TTL, as known answers to a query asking `q` (RFC 6762 section 7.1).
    /// None of one without a hostname, which has no records of its own.
    pub fn known_answers(&self, q: &Question, now: Instant) -> Vec<Record> {
        if self.device.hostname.is_none() {
            return Vec::new();
        }
        let host_ttl = self.device.ttl.unwrap_or(HOST_TTL);
        let mut records = self.device.records_for(q, host_ttl, OTHER_TTL);
        for rec in &mut records {
            let until = addr_of(&rec.data).and_then(|a| self.addr_expires.get(&a)).unwrap_or(&self.expires);
            let left = until.saturating_duration_since(now).as_secs();
            rec.ttl = rec.ttl.min(u32::try_from(left).unwrap_or(u32::MAX));
        }
        records.retain(|r| r.ttl > 0);
        records
    }

    /// The soonest it, or one of its addresses, runs out.
    pub fn soonest(&self) -> Instant {
        self.addr_expires.values().copied().fold(self.expires, Instant::min)
    }

    /// How long before what runs out first it is asked to answer again: `before`,
    /// or a quarter of what the device gave it to live if that is shorter, so
    /// that one with a short TTL is asked three quarters of the way in and not
    /// over and over.
    pub fn lead(&self, before: Duration) -> Duration {
        before.min(self.soonest().saturating_duration_since(self.began) / 4)
    }

    /// When it is next due to be asked to answer again, if it is: `lead`
    /// before the soonest it or one of its addresses runs out, and not again
    /// until the gap has passed since it was last asked. Not if it is to be
    /// dropped by then, nor if there is nothing to ask it.
    pub fn refresh_due(&self, before: Duration) -> Option<Instant> {
        if !self.askable() {
            return None;
        }
        let soonest = self.soonest();
        let at = soonest.checked_sub(self.lead(before)).unwrap_or(Instant::START);
        let at = match self.refreshed.map(|t| t.checked_add(refresh_gap(before))) {
            Some(Some(again)) => at.max(again),
            Some(None) => return None, // never again
            None => at,
        };
        (at < soonest).then_some(at)
    }

    /// Renew those of `addrs` it has, each for its TTL in `ttls` (none if it
    /// did not say) but at least `floor` from `now`, and forget when the
    /// addresses it no longer has run out.
    pub fn renew_addrs(&mut self, addrs: &[IpAddr], ttls: &HashMap<IpAddr, u32>, now: Instant, floor: Duration) {
        for addr in addrs.iter().filter(|a| self.device.has_addr(a)) {
            let ttl = Duration::from_secs(ttls.get(addr).copied().unwrap_or(0).into());
            self.addr_expires.insert(*addr, now + ttl.max(floor));
        }
        let device = &self.device;
        self.addr_expires.retain(|addr, _| device.has_addr(addr));
    }

    /// Before `incoming` are taken in, drop the announced addresses of a
    /// family that would keep them out at `max_addrs`, the one that runs out
    /// first at a time: a device that moves on to a new temporary address
    /// without saying goodbye to the last is known by its newest. Not those
    /// `incoming` repeats, those in `gone` or of a family in `flushed`, which
    /// go as it is taken in.
    pub fn make_room(&mut self, incoming: &[IpAddr], flushed: &[Family], gone: &[IpAddr], max_addrs: usize) {
        for family in [Family::V4, Family::V6] {
            if flushed.contains(&family) {
                continue;
            }
            let new = incoming
                .iter()
                .filter(|a| family_of(**a) == family && !gone.contains(a) && !self.device.has_addr(a))
                .count();
            let mut held: Vec<IpAddr> = self
                .device
                .addresses
                .iter()
                .filter(|a| a.origin == Origin::Announced)
                .map(|a| a.ip)
                .filter(|a| family_of(*a) == family && !gone.contains(a))
                .collect();
            let excess = (held.len() + new).saturating_sub(max_addrs);
            // Oldest first, and those it did not repeat before those it did.
            held.sort_by_key(|a| (incoming.contains(a), self.addr_expires.get(a).copied()));
            for addr in held.into_iter().filter(|a| !incoming.contains(a)).take(excess) {
                self.device.addresses.retain(|a| a.ip != addr);
                self.addr_expires.remove(&addr);
            }
        }
    }

    /// Drop the addresses that have run out by `now`. Returns whether any had.
    pub fn expire_addrs(&mut self, now: Instant) -> bool {
        let gone: Vec<IpAddr> = self.addr_expires.iter().filter(|&(_, at)| *at <= now).map(|(a, _)| *a).collect();
        for addr in &gone {
            self.addr_expires.remove(addr);
        }
        self.device.addresses.retain(|a| !gone.contains(&a.ip));
        !gone.is_empty()
    }

    /// Whether there is anything to ask it about: a name or a service.
    pub fn askable(&self) -> bool {
        self.device.hostname.is_some() || !self.device.services.is_empty()
    }

    /// Take over what was learned about this device before its name was known.
    pub fn absorb(&mut self, earlier: Entry, max_services: usize) {
        self.device.absorb(earlier.device, max_services);
        self.expires = self.expires.max(earlier.expires);
        self.began = self.began.min(earlier.began);
        for (addr, at) in earlier.addr_expires {
            let mine = self.addr_expires.entry(addr).or_insert(at);
            *mine = (*mine).max(at);
        }
    }
}

/// How long to wait before asking a device again that has not answered.
pub fn refresh_gap(before: Duration) -> Duration {
    (before / 4).max(Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::parser::Header;

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
}
