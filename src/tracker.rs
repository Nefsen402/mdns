//! The devices heard on a segment, and what a packet or the kernel says of
//! them: [`Tracker`] brings them up to date and says what changed.

use core::hash::{BuildHasher, Hasher};
use core::net::IpAddr;
use core::ops::Bound;
use core::time::Duration;

use alloc::collections::BTreeSet;

use hashbrown::{DefaultHashBuilder, HashMap, HashSet, HashTable};

use crate::device::{addr_of, edit, Shared, family_of, is_link_local, is_type, is_usable, Device, Origin, Report, HOST_TTL, META_QUERY, OTHER_TTL};

use crate::segment::Asked;
use crate::codec::{Message, Question, RData, Record};
use crate::prelude::*;
use crate::config::{Advertise, DEFAULT_MAX_ADDRS, DEFAULT_MAX_DEVICES, DEFAULT_MAX_SERVICES, DEFAULT_MIN_LIFETIME};
use crate::interface::{Family, Prefix};
use crate::table::{hash_addr, hash_name, Id, Multi, Table};
use crate::time::Instant;

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
            let (learned, nudge) = {
                let device = entry.device.borrow();
                let announced = device.addresses.iter().filter(|a| a.origin == Origin::Announced);
                let mut macs: Vec<&Vec<u8>> = announced.filter_map(|a| self.neighbours.get(&a.ip)).collect();
                macs.sort_unstable();
                macs.dedup();
                let on_link = |ip: &IpAddr| self.prefixes.iter().any(|p| p.contains(ip));
                let learned: Vec<IpAddr> = macs
                    .iter()
                    .flat_map(|mac| self.neighbours.with_mac(mac))
                    .filter(|ip| !is_link_local(ip) && on_link(ip))
                    .collect();

                let unresolved = device.link_local().find(|ll| ll.is_ipv6() && !self.neighbours.contains_key(ll));
                let has_v6 = device.routable().any(|a| a.is_ipv6());
                let due = entry.nudged.is_none_or(|t| now.saturating_duration_since(t) >= NUDGE_GAP);
                (learned, unresolved.filter(|_| !has_v6 && due).map(|ll| (ll, device.clone())))
            };
            if let Some(nudge) = nudge {
                touched.nudges.push(nudge);
                self.discovered.get_mut(id).nudged = Some(now);
            }

            let mut device = self.discovered.get(id).device.snapshot();
            if device.take_neighbours(&learned, self.max_addrs) {
                touched.note(&self.discovered, id);
                *self.discovered.get(id).device.borrow_mut() = device;
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

    /// Take the networks the interface is on, as its addresses change: of the
    /// neighbour table, only addresses in one of them are learned, and those
    /// learned of one it is no longer on are dropped. Noted in what is
    /// returned are the devices that changed.
    pub fn set_prefixes(&mut self, prefixes: Vec<Prefix>, now: Instant) -> Touched {
        if self.prefixes == prefixes {
            return Touched::default();
        }
        self.prefixes = prefixes;
        let ids: Vec<Id> = self.discovered.ids().filter(|&id| !self.discovered.get(id).device.borrow().addresses.is_empty()).collect();
        self.relearn(&ids, now)
    }

    /// Take in an entry of the interface's neighbour table, as the kernel
    /// reports it: `ip` is at link-layer address `mac`, or with `None`, no
    /// longer (it went, or could not be reached). The devices it may concern,
    /// those with any address, have their learned addresses brought up to
    /// date, and those that changed are noted in what is returned.
    pub fn neighbour(&mut self, ip: IpAddr, mac: Option<Vec<u8>>, now: Instant) -> Touched {
        let was = self.neighbours.get(&ip).cloned();
        let changed = match &mac {
            Some(mac) => self.neighbours.insert(ip, mac.clone()).as_ref() != Some(mac),
            None => self.neighbours.remove(&ip).is_some(),
        };
        if !changed {
            return Touched::default();
        }
        // What it learns of a device follows the addresses that share a
        // link-layer address with one it announced: the devices to bring up
        // to date are those with the address, or with one at the link-layer
        // address it was at, or is at now.
        let mut ips = vec![ip];
        for mac in was.iter().chain(&mac) {
            ips.extend(self.neighbours.with_mac(mac));
        }
        let mut seen = HashSet::new();
        let ids: Vec<Id> = ips.iter().flat_map(|ip| self.discovered.ids_with_addr(ip)).filter(|id| seen.insert(*id)).collect();
        self.relearn(&ids, now)
    }

    /// Forget every device, as when the interface is gone: they cannot be
    /// reached through it. They are found again once it is back.
    pub fn forget(&mut self) -> Touched {
        let mut touched = Touched::default();
        let ids: Vec<Id> = self.discovered.ids().collect();
        for &id in &ids {
            touched.note(&self.discovered, id);
        }
        for id in ids {
            self.discovered.remove(id);
        }
        touched
    }

    /// Drop the devices that have run out by `now`, and the addresses of the
    /// others that have, noting them in what is returned.
    pub fn expire(&mut self, now: Instant) -> Touched {
        let mut touched = Touched::default();
        // Those of which something has run out: the devices themselves, and
        // of the others, the addresses that ran out on their own.
        let (stale, running): (Vec<Id>, Vec<Id>) =
            self.discovered.running_out(now).into_iter().partition(|&id| self.discovered.get(id).expires <= now);
        for &id in &stale {
            touched.note(&self.discovered, id);
        }
        for id in running {
            touched.note(&self.discovered, id);
            self.discovered.edit(id, |entry| entry.expire_addrs(now));
        }
        for id in stale {
            self.discovered.remove(id);
        }
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
            entry.device.borrow_mut().learn(report, &addrs, max_addrs, max_services);
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
                entry.device.borrow_mut().take_addrs(&[src], &[], &[], max_addrs);
                entry.renew_addrs(&[src], &HashMap::new(), now, floor);
            }
            if entry.soonest() != was {
                entry.began = now;
            }
            entry.device.borrow_mut().learn_records(rest.iter().copied(), max_services);
        }

        // An instance that has now been resolved to its host no longer needs
        // the unresolved copy learned from a bare browse answer.
        touched.sync(&mut self.discovered);
        for (owner, instance) in resolved {
            let others: Vec<Id> = self
                .discovered
                .with_unresolved()
                .filter(|&(id, e)| id != owner && e.device.borrow().service(&instance).is_some_and(|s| s.target().is_none()))
                .map(|(id, _)| id)
                .collect();
            for id in others {
                touched.note(&self.discovered, id);
                self.discovered.get_mut(id).device.borrow_mut().forget_service(&instance);
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
    /// The device, which goes on to be what it is, and what it held.
    before: HashMap<Id, Option<(Shared, Device)>>,
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
            self.before.insert(id, discovered.try_get(id).map(|e| (e.device.clone(), e.device.snapshot())));
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
            let now = discovered.try_get(*id).map(|e| e.device.clone());
            match (&self.before[id], now) {
                (None, Some(now)) => events.push(Event::Added(now)),
                // A device that went, and another that came in its place.
                (Some((old, _)), Some(now)) if !old.is(&now) => {
                    events.push(Event::Removed(old.clone()));
                    events.push(Event::Added(now));
                }
                (Some((_, before)), Some(now)) if *before != *now.borrow() => events.push(Event::Updated(now)),
                (Some((old, _)), None) => events.push(Event::Removed(old.clone())),
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
            let mut add = |device: &Device| {
                names.extend(device.hostname.iter().map(|host| host.to_ascii_lowercase()));
                names.extend(device.services.iter().map(|svc| svc.instance().to_ascii_lowercase()));
            };
            if let Some((_, before)) = &self.before[id] {
                add(before);
            }
            if let Some(entry) = discovered.try_get(*id) {
                add(&entry.device.borrow());
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
    Added(Shared),
    /// A device is not as it was: its hostname, addresses or services. It is
    /// the same device, which is what it is now, not what it was.
    Updated(Shared),
    /// A device went, as it was last.
    Removed(Shared),
    /// The questions of a query that no device here owns the name of: for
    /// the reflector to put to the segments whose devices it announces here
    /// ([`Segment::query_question`](crate::segment::Segment::query_question)),
    /// as it is configured to.
    Question(Vec<Asked>),
}

impl Event {
    /// The device it is of: as it is, or as it was last if it went. None for a
    /// question.
    pub fn device(&self) -> Option<&Shared> {
        match self {
            Event::Added(device) | Event::Updated(device) | Event::Removed(device) => Some(device),
            Event::Question(_) => None,
        }
    }
}

/// A discovered device, and when to drop it or ask it again.
#[derive(Debug)]
pub struct Entry {
    pub device: Shared,
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
        let device = Shared::new(Device { hostname: hostname.map(String::from), ..Device::default() });
        Entry { device, from, expires: now, addr_expires: HashMap::new(), began: now, refreshed: None, nudged: None }
    }

    /// Its records that answer `q`, each with the time it has left here as
    /// its TTL, as known answers to a query asking `q` (RFC 6762 section 7.1).
    /// None of one without a hostname, which has no records of its own.
    pub fn known_answers(&self, q: &Question, now: Instant) -> Vec<Record> {
        if self.device.borrow().hostname.is_none() {
            return Vec::new();
        }
        let host_ttl = self.device.borrow().ttl.unwrap_or(HOST_TTL);
        let mut records = self.device.borrow().records_for(&Advertise::ALL, q, host_ttl, OTHER_TTL);
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
        for addr in addrs.iter().filter(|a| self.device.borrow().has_addr(a)) {
            let ttl = Duration::from_secs(ttls.get(addr).copied().unwrap_or(0).into());
            self.addr_expires.insert(*addr, now + ttl.max(floor));
        }
        let device = self.device.borrow();
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
                .filter(|a| family_of(**a) == family && !gone.contains(a) && !self.device.borrow().has_addr(a))
                .count();
            let mut held: Vec<IpAddr> = self
                .device
                .borrow()
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
                edit(&mut self.device.borrow_mut().addresses).retain(|a| a.ip != addr);
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
        edit(&mut self.device.borrow_mut().addresses).retain(|a| !gone.contains(&a.ip));
        !gone.is_empty()
    }

    /// Whether there is anything to ask it about: a name or a service.
    pub fn askable(&self) -> bool {
        self.device.borrow().hostname.is_some() || !self.device.borrow().services.is_empty()
    }

    /// Take over what was learned about this device before its name was known.
    pub fn absorb(&mut self, earlier: Entry, max_services: usize) {
        self.device.borrow_mut().absorb(earlier.device.snapshot(), max_services);
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

// The discovered devices of a segment, each held in one place, and how they
// are found.
//
// A device is [kept](Table) and called by its [`Id`]; nothing about it tells
// it apart from another. It is found by its hostname, or if it has none by
// the address it was first heard from, and by the addresses it has, the
// names it answers for, whether it has a service whose host is not known,
// and when it next needs something done: when something of it runs out, and
// when it is to be asked again. There is at most one device to a hostname:
// those that look for one find it before they make one.
//
// The tables hold a hash or a time and an id, and confirm by looking into
// the device, so they can be made again from the devices alone
// ([`Devices::check`] does, and compares). A table follows a device when it
// is told that it changed ([`Devices::reindex`]), given what the tables held
// of it before ([`Indexed`]), or when it is changed by [`Devices::edit`],
// and when it goes.

/// What the tables hold of a device: the hashes of its addresses and of the
/// names it answers for, each once, in order, and the times it is held under.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(crate) struct Indexed {
    addrs: Vec<u64>,
    names: Vec<u64>,
    soonest: Option<Instant>,
    refresh_at: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Devices {
    table: Table<Entry>,
    /// Each address a device has, and the device, by the hash of the address.
    by_addr: Multi,
    /// Each name a device answers for, and the device, by the hash of the name:
    /// its hostname among them.
    by_name: Multi,
    /// Every device, by the hash of the address that first described it: what
    /// finds one with no hostname, and what a sender may describe only so
    /// many of.
    by_from: Multi,
    /// The devices with a service whose host is not known yet (a bare browse
    /// answer): the ones to look at when it is, rather than all of them.
    unresolved: HashSet<Id>,
    /// The devices by the soonest that they, or one of their addresses, runs
    /// out.
    by_soonest: BTreeSet<(Instant, Id)>,
    /// The devices by when they are due to be asked to answer again, if
    /// [`Devices::refresh`] says they are.
    by_refresh: BTreeSet<(Instant, Id)>,
    /// How long before one would run out they are asked to answer again; none
    /// if they are not.
    refresh: Option<Duration>,
    hasher: DefaultHashBuilder,
}

impl Devices {
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn try_get(&self, id: Id) -> Option<&Entry> {
        self.table.try_get(id)
    }

    pub fn get(&self, id: Id) -> &Entry {
        self.table.get(id)
    }

    /// The device, to be changed but not in when it runs out or is asked
    /// again, nor in what it has, unless its changes are then
    /// [indexed](Devices::reindex).
    pub fn get_mut(&mut self, id: Id) -> &mut Entry {
        self.table.get_mut(id)
    }

    /// Change the device with `f`, and have the tables follow. Nothing if it
    /// is gone.
    pub fn edit<R>(&mut self, id: Id, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
        let was = self.indexed(self.table.try_get(id)?);
        let out = f(self.table.get_mut(id));
        self.reindex_id(id, &was);
        Some(out)
    }

    /// The device with the hostname `host`, ignoring case.
    pub fn find_host(&self, host: &str) -> Option<Id> {
        let hash = hash_name(&self.hasher, host);
        let named = |id: &Id| self.table.get(*id).device.borrow().hostname.as_deref().is_some_and(|own| own.eq_ignore_ascii_case(host));
        self.by_name.under(hash).find(named)
    }

    pub fn contains_host(&self, host: &str) -> bool {
        self.find_host(host).is_some()
    }

    /// The device with no hostname that was first heard from `from`.
    pub fn find_nameless(&self, from: &IpAddr) -> Option<Id> {
        let hash = hash_addr(&self.hasher, from);
        let first = |id: &Id| {
            let entry = self.table.get(*id);
            entry.device.borrow().hostname.is_none() && entry.from == *from
        };
        self.by_from.under(hash).find(first)
    }

    /// Keep a device that is not here yet, and no other with its hostname if
    /// it has one. It is found by its hostname at once, and by the rest of
    /// what the tables hold when it is [indexed](Devices::reindex), with
    /// nothing for what they held.
    pub fn create(&mut self, entry: Entry) -> Id {
        debug_assert!(entry.device.borrow().hostname.as_deref().is_none_or(|host| !self.contains_host(host)), "a hostname is had once");
        let from = hash_addr(&self.hasher, &entry.from);
        let host = entry.device.borrow().hostname.as_deref().map(|host| hash_name(&self.hasher, host));
        let id = self.table.insert(entry);
        self.by_from.add(from, id);
        if let Some(host) = host {
            self.by_name.add(host, id);
        }
        id
    }

    pub fn remove(&mut self, id: Id) -> Option<Entry> {
        // From the other tables, by what it was given to them as: what the
        // tables hold is what it was when it was last indexed, the device
        // as it is now, unless it was changed and not reindexed.
        let held = self.indexed(self.table.try_get(id)?);
        let entry = self.table.remove(id);
        self.by_addr.move_between(id, &held.addrs, &[]);
        self.by_name.move_between(id, &held.names, &[]);
        self.by_from.remove(hash_addr(&self.hasher, &entry.from), id);
        self.unresolved.remove(&id);
        self.by_soonest.remove(&(entry.soonest(), id));
        if let Some(at) = held.refresh_at {
            self.by_refresh.remove(&(at, id));
        }
        Some(entry)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.table.iter()
    }

    pub fn ids(&self) -> impl Iterator<Item = Id> + '_ {
        self.table.ids()
    }

    /// When `entry` is next due to be asked to answer again, if it is: before
    /// the soonest it or one of its addresses runs out, and not again until
    /// the gap has passed since it was last asked. Not if it is to be
    /// dropped by then, nor if there is nothing to ask it.
    fn refresh_at(&self, entry: &Entry) -> Option<Instant> {
        entry.refresh_due(self.refresh?)
    }

    /// What the tables would hold of `entry`.
    pub fn indexed(&self, entry: &Entry) -> Indexed {
        let mut addrs: Vec<u64> = entry.device.borrow().addrs().map(|addr| hash_addr(&self.hasher, &addr)).collect();
        let mut names = Vec::new();
        entry.device.borrow().for_each_name(&Advertise::ALL, |name| names.push(hash_name(&self.hasher, name)));
        for hashes in [&mut addrs, &mut names] {
            hashes.sort_unstable();
            hashes.dedup();
        }
        Indexed { addrs, names, soonest: Some(entry.soonest()), refresh_at: self.refresh_at(entry) }
    }

    /// What the tables hold of the device, as of now; nothing if it is gone.
    pub fn indexed_of(&self, id: Id) -> Indexed {
        self.table.try_get(id).map(|entry| self.indexed(entry)).unwrap_or_default()
    }

    /// The device was changed from what the tables held of it, `was`: have
    /// them follow. Returns what they hold now, which is what to give the
    /// next time. Nothing if it is gone: they were told when it went.
    pub fn reindex(&mut self, id: Id, was: &Indexed) -> Indexed {
        if self.table.has(id) { self.reindex_id(id, was) } else { Indexed::default() }
    }

    fn reindex_id(&mut self, id: Id, was: &Indexed) -> Indexed {
        let entry = self.table.get(id);
        let now = self.indexed(entry);
        self.by_addr.move_between(id, &was.addrs, &now.addrs);
        self.by_name.move_between(id, &was.names, &now.names);
        if entry.device.borrow().services.iter().any(|s| s.target().is_none()) {
            self.unresolved.insert(id);
        } else {
            self.unresolved.remove(&id);
        }
        for (table, was, now) in [
            (&mut self.by_soonest, was.soonest, now.soonest),
            (&mut self.by_refresh, was.refresh_at, now.refresh_at),
        ] {
            if was != now {
                if let Some(at) = was {
                    table.remove(&(at, id));
                }
                if let Some(at) = now {
                    table.insert((at, id));
                }
            }
        }
        now
    }

    /// Set how long before they run out devices are asked to answer again, or
    /// that they are not. It is what [`Devices::refresh_at`] goes by, so the
    /// times they are held under are made again.
    pub fn set_refresh(&mut self, before: Option<Duration>) {
        if self.refresh == before {
            return;
        }
        self.refresh = before;
        self.by_refresh.clear();
        for id in self.table.ids().collect::<Vec<_>>() {
            if let Some(at) = self.refresh_at(self.table.get(id)) {
                self.by_refresh.insert((at, id));
            }
        }
    }

    /// The devices that have `addr`.
    pub fn ids_with_addr<'a>(&'a self, addr: &'a IpAddr) -> impl Iterator<Item = Id> + 'a {
        let hash = hash_addr(&self.hasher, addr);
        self.by_addr.under(hash).filter(move |&id| self.table.get(id).device.borrow().has_addr(addr))
    }

    /// The device that has `addr` and was heard of last, if any does.
    pub fn holder_of(&self, addr: &IpAddr) -> Option<Id> {
        self.ids_with_addr(addr).max_by_key(|&id| (self.table.get(id).expires, id))
    }

    /// The devices that answer for `name`, ignoring case.
    pub fn with_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Entry> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name.under(hash).map(|id| self.table.get(id)).filter(move |entry| entry.device.borrow().has_name(&Advertise::ALL, name))
    }

    /// The devices with a service whose host is not known yet.
    pub fn with_unresolved(&self) -> impl Iterator<Item = (Id, &Entry)> {
        self.unresolved.iter().map(|&id| (id, self.table.get(id)))
    }

    /// How many devices with a hostname `sender` first described.
    pub fn described_by(&self, sender: &IpAddr) -> usize {
        let hash = hash_addr(&self.hasher, sender);
        let first = |id: &Id| {
            let entry = self.table.get(*id);
            entry.from == *sender && entry.device.borrow().hostname.is_some()
        };
        self.by_from.under(hash).filter(first).count()
    }

    /// The soonest anything of a device is due: when something of one runs
    /// out, or one is to be asked again. Never if none is.
    pub fn next_due(&self) -> Option<Instant> {
        let soonest = self.by_soonest.first().map(|&(at, _)| at);
        let refresh = self.by_refresh.first().map(|&(at, _)| at);
        soonest.into_iter().chain(refresh).min()
    }

    /// The devices of which something has run out as of `now`.
    pub fn running_out(&self, now: Instant) -> Vec<Id> {
        self.by_soonest.range(..=(now, Id::LAST)).map(|&(_, id)| id).collect()
    }

    /// The devices that run out after `now`, and no later than `before`
    /// after it: those to ask to answer again.
    pub fn about_to_run_out(&self, now: Instant, before: Duration) -> Vec<Id> {
        let to = now.checked_add(before).map_or(Bound::Unbounded, |limit| Bound::Included((limit, Id::LAST)));
        self.by_soonest.range((Bound::Excluded((now, Id::LAST)), to)).map(|&(_, id)| id).collect()
    }

    /// Whether the tables hold what the devices have, and nothing else: for
    /// tests, which change things without the segment's own care.
    #[cfg(test)]
    pub fn check(&self) {
        self.table.check();
        let (mut addrs, mut names, mut unresolved, mut froms, mut refreshed) = (0, 0, 0, 0, 0);
        for id in self.table.ids() {
            let entry = self.table.get(id);
            let indexed = self.indexed(entry);
            addrs += indexed.addrs.len();
            names += indexed.names.len();
            assert!(indexed.addrs.iter().all(|&h| self.by_addr.holds(h, id)), "an address is indexed: {entry:?}");
            assert!(indexed.names.iter().all(|&h| self.by_name.holds(h, id)), "a name is indexed: {entry:?}");
            let unresolved_here = entry.device.borrow().services.iter().any(|s| s.target().is_none());
            assert_eq!(self.unresolved.contains(&id), unresolved_here, "unresolved: {entry:?}");
            unresolved += usize::from(unresolved_here);
            for addr in entry.device.borrow().addrs() {
                assert!(self.ids_with_addr(&addr).any(|found| found == id), "{addr} finds it");
            }
            froms += 1;
            assert!(self.by_from.holds(hash_addr(&self.hasher, &entry.from), id), "by where from: {entry:?}");
            match entry.device.borrow().hostname.as_deref() {
                Some(host) => assert_eq!(self.find_host(host), Some(id), "a hostname is had once: {entry:?}"),
                None => assert_eq!(self.find_nameless(&entry.from), Some(id), "one with no hostname per address: {entry:?}"),
            }
            assert!(self.by_soonest.contains(&(entry.soonest(), id)), "by when it runs out: {entry:?}");
            if let Some(at) = self.refresh_at(entry) {
                refreshed += 1;
                assert!(self.by_refresh.contains(&(at, id)), "by when it is asked again: {entry:?}");
            }
        }
        assert_eq!((self.by_addr.pairs, self.by_name.pairs, self.unresolved.len()), (addrs, names, unresolved));
        assert_eq!((self.by_from.pairs, self.by_soonest.len(), self.by_refresh.len()), (froms, self.len(), refreshed));
    }

    /// How many (address, device) pairs the tables hold.
    #[cfg(test)]
    pub fn addrs_held(&self) -> usize {
        self.by_addr.pairs
    }
}

// The kernel's neighbour table for an interface, and what finds addresses by
// their link-layer address.
//
// The table of addresses by link-layer address holds the addresses, as ids,
// and confirms by looking each up in the table itself: it is made of the
// table and nothing else.

#[derive(Default)]
pub(crate) struct NeighbourTable {
    /// Each address it has a link-layer address for, and that address.
    macs: HashMap<IpAddr, Vec<u8>>,
    /// The addresses, by the hash of their link-layer address.
    by_mac: HashTable<IpAddr>,
    hasher: DefaultHashBuilder,
}

fn hash_of(hasher: &DefaultHashBuilder, mac: &[u8]) -> u64 {
    let mut h = hasher.build_hasher();
    h.write(mac);
    h.finish()
}

impl NeighbourTable {
    pub fn get(&self, ip: &IpAddr) -> Option<&Vec<u8>> {
        self.macs.get(ip)
    }

    pub fn contains_key(&self, ip: &IpAddr) -> bool {
        self.macs.contains_key(ip)
    }

    /// Set the link-layer address of `ip`. Returns the one it had.
    pub fn insert(&mut self, ip: IpAddr, mac: Vec<u8>) -> Option<Vec<u8>> {
        let hash = hash_of(&self.hasher, &mac);
        let was = self.macs.insert(ip, mac);
        if let Some(was) = &was {
            self.unlink(ip, hash_of(&self.hasher, was));
        }
        let (macs, hasher) = (&self.macs, &self.hasher);
        self.by_mac.insert_unique(hash, ip, |ip| hash_of(hasher, &macs[ip]));
        was
    }

    /// Forget `ip`. Returns the link-layer address it had.
    pub fn remove(&mut self, ip: &IpAddr) -> Option<Vec<u8>> {
        let was = self.macs.remove(ip)?;
        self.unlink(*ip, hash_of(&self.hasher, &was));
        Some(was)
    }

    fn unlink(&mut self, ip: IpAddr, hash: u64) {
        if let Ok(found) = self.by_mac.find_entry(hash, |other| *other == ip) {
            found.remove();
        }
    }

    /// The addresses that have the link-layer address `mac`.
    pub fn with_mac<'a>(&'a self, mac: &'a [u8]) -> impl Iterator<Item = IpAddr> + 'a {
        self.by_mac
            .iter_hash(hash_of(&self.hasher, mac))
            .copied()
            .filter(move |ip| self.macs.get(ip).is_some_and(|own| own == mac))
    }

    /// Whether the table by link-layer address is what the table says.
    #[cfg(test)]
    pub fn check(&self) {
        assert_eq!(self.by_mac.len(), self.macs.len());
        for (ip, mac) in &self.macs {
            assert!(self.with_mac(mac).any(|found| found == *ip), "{ip} is found by {mac:?}");
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/tracker.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/tracker_device_table_tests.rs"]
mod device_table_tests;

#[cfg(test)]
#[path = "../tests/unit/tracker_neighbour_table_tests.rs"]
mod neighbour_table_tests;
