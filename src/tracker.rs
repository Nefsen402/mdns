//! The devices heard on a segment: what a packet said ([`Heard`]), read once
//! and apart from what is known, and the devices it brings up to date.

use core::net::IpAddr;
use core::time::Duration;

use alloc::collections::BTreeSet;

use hashbrown::HashMap;

use crate::device::{addr_of, family_of, is_type, Device, Origin, Report, HOST_TTL, META_QUERY, OTHER_TTL};
use crate::parser::{Message, Question, RData, Record};
use crate::prelude::*;
use crate::config::{DEFAULT_MAX_ADDRS, DEFAULT_MAX_DEVICES, DEFAULT_MAX_SERVICES, DEFAULT_MIN_LIFETIME};
use crate::socket::{Family, Prefix};
use crate::time::Instant;

mod devices;
mod neighbours;
pub(crate) use devices::{Devices, Id, Indexed};
pub(crate) use neighbours::NeighbourTable;

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

/// What one packet said. A query says nothing of its sender's: the records in
/// it are other devices' known answers.
pub struct Heard<'a> {
    /// The hosts that left: a response saying goodbye (TTL 0) to the address
    /// it came from, and announcing none for that name still, is a device
    /// leaving, whatever else is known by that name or by the sender's
    /// address. One that announces others in its place (a temporary IPv6
    /// address giving way to the next) is not; it only loses the one.
    pub leaving: Vec<&'a str>,
    /// The service types it said exist, in lowercase: the answers to the
    /// question of what types there are.
    pub types: Vec<String>,
    /// What it said of each host it describes, and the records that tie to
    /// none ([`Report::all`]), which are the sender's own, if any.
    pub reports: Vec<Report<'a>>,
    pub rest: Vec<&'a Record>,
}

impl<'a> Heard<'a> {
    /// Read `msg`, from `src`, if it was a message at all: nothing is said by
    /// one that could not be read.
    pub fn of(src: IpAddr, msg: Option<&'a Message>) -> Heard<'a> {
        let msg = msg.filter(|m| m.header.response);
        let records = || msg.into_iter().flat_map(|m| m.records());

        let still = |name: &str| records().any(|r| r.ttl > 0 && addr_of(&r.data).is_some() && r.name.eq_ignore_ascii_case(name));
        let leaving = records()
            .filter(|r| r.ttl == 0 && addr_of(&r.data) == Some(src) && !still(&r.name))
            .map(|r| r.name.as_str())
            .collect();

        let types = records()
            .filter_map(|rec| match &rec.data {
                RData::Ptr(kind)
                    if rec.ttl > 0 && rec.name.eq_ignore_ascii_case(META_QUERY) && rec.class == 1 && is_type(kind) =>
                {
                    Some(kind.to_ascii_lowercase())
                }
                _ => None,
            })
            .collect();

        let (reports, rest) = match msg {
            Some(m) => Report::all(m),
            None => (Vec::new(), Vec::new()),
        };
        Heard { leaving, types, reports, rest }
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

    fn heard<'a>(src: &str, msg: &'a Message) -> Heard<'a> {
        Heard::of(src.parse().unwrap(), Some(msg))
    }

    /// What is not a message, or a query, says nothing: the records of a
    /// query are other devices' known answers.
    #[test]
    fn a_query_and_what_is_not_a_message_say_nothing() {
        let known = message(false, vec![a("tv.local", "10.0.1.5", 120), a("gone.local", "10.0.1.5", 0)]);
        for heard in [heard("10.0.1.5", &known), Heard::of("10.0.1.5".parse().unwrap(), None)] {
            assert!(heard.leaving.is_empty() && heard.types.is_empty() && heard.reports.is_empty() && heard.rest.is_empty());
        }
    }

    /// A host leaves when it says goodbye to the address the packet came
    /// from; to another's, it is only saying the other left.
    #[test]
    fn a_host_leaves_by_saying_goodbye_to_the_address_it_came_from() {
        let msg = message(true, vec![a("tv.local", "10.0.1.5", 0)]);
        assert_eq!(heard("10.0.1.5", &msg).leaving, ["tv.local"]);
        assert!(heard("10.0.1.9", &msg).leaving.is_empty(), "a router saying so of another");
        let alive = message(true, vec![a("tv.local", "10.0.1.5", 120)]);
        assert!(heard("10.0.1.5", &alive).leaving.is_empty());
    }

    /// One that announces another address in its place is not leaving: it only
    /// loses the one, as a temporary IPv6 address gives way to the next.
    #[test]
    fn a_host_that_announces_another_address_in_its_place_is_not_leaving() {
        let msg = message(true, vec![aaaa("tv.local", "fd00::1", 0), aaaa("tv.local", "fd00::2", 120)]);
        assert!(heard("fd00::1", &msg).leaving.is_empty());
        // And not in another's name.
        let msg = message(true, vec![aaaa("tv.local", "fd00::1", 0), aaaa("other.local", "fd00::2", 120)]);
        assert_eq!(heard("fd00::1", &msg).leaving, ["tv.local"]);
    }

    /// The types it names are those of live answers to the question of what
    /// types there are, in lowercase, and well formed.
    #[test]
    fn the_service_types_are_the_live_answers_to_the_question_of_what_there_are() {
        let ptr = |owner: &str, ttl: u32, class: u16, target: &str| Record {
            class,
            ..record(owner, ttl, RData::Ptr(target.into()))
        };
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
        assert_eq!(heard("10.0.1.5", &msg).types, ["_ipp._tcp.local", "_http._tcp.local"]);
    }

    /// What it says of hosts is told by the host it concerns, and what ties to
    /// none is left over: a bare browse answer.
    #[test]
    fn what_it_says_is_told_by_host_and_the_rest_is_left_over() {
        let msg = message(
            true,
            vec![
                a("tv.local", "10.0.1.5", 120),
                a("nas.local", "10.0.1.6", 120),
                record("_ipp._tcp.local", 4500, RData::Ptr("Printer._ipp._tcp.local".into())),
            ],
        );
        let heard = heard("10.0.1.5", &msg);
        let hosts: Vec<&str> = heard.reports.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, ["tv.local", "nas.local"]);
        assert_eq!(heard.rest.len(), 1);
    }
}
