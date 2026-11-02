//! The devices on one interface, and what the daemon says and asks there.
//!
//! A [`Segment`] keeps a model of the link rather than its packets: the
//! devices heard on it, with their addresses and services, the ones put there
//! by hand or reflected from elsewhere, and the claims on their names. It
//! answers for them, announces, probes and refreshes them, and forgets them
//! as they expire, sending through the [`socket`](crate::socket)s attached to
//! it.

use std::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr, SocketAddrV6, UdpSocket};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::device::{
    addr_of, family_of, is_link_local, is_type, is_usable, responses, service_ttl, Device, Origin, Report, DEFAULT_MAX_ADDRS,
    DEFAULT_MAX_PACKET, HOST_TTL, META_QUERY, MIN_REFLECT_TTL, OTHER_TTL,
};
use crate::socket::{Family, Prefix, MDNS_PORT};
use crate::parser::{Message, Question, RData, Record};

/// Re-announce a reflected device at 80% of the shortest TTL it advertises,
/// on a segment that re-announces what has not changed.
fn reannounce_after(host_ttl: u32) -> Duration {
    Duration::from_secs(u64::from(host_ttl) * 4 / 5)
}
/// What is announced anew is announced again this long after, in case the
/// first was lost: at least twice, a second apart (RFC 6762 sections 8.3 and
/// 8.4).
const ANNOUNCE_REPEAT: Duration = Duration::from_secs(1);
/// How long to wait before trying again after a re-announcement failed to send.
const ANNOUNCE_RETRY: Duration = Duration::from_secs(10);

/// Pause after each round of a probe. A probe is three rounds, because the
/// answers to one round (service types, then instances) decide what the next
/// one asks; the last pause lets the final answers arrive before returning.
const PROBE_GAPS: [Duration; 3] = if cfg!(test) {
    [Duration::from_millis(5); 3]
} else {
    [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(1)]
};

/// How many probes' results are kept until whoever asked for them takes them.
const MAX_PROBED: usize = 64;

/// Service types remembered per segment, so a hostile device cannot grow it
/// without bound by announcing endless made-up types.
const MAX_TYPES: usize = 256;

/// Devices remembered per segment, and of them, hosts first described by any
/// one sender: one sender inventing endless devices (or many forged ones)
/// must neither fill the other segments nor grow the list without bound. A
/// sleep proxy or Thread border router speaks for several hosts, but not
/// for this many.
const MAX_DEVICES: usize = 1024;
const MAX_PER_SENDER: usize = 64;

/// A record may not be multicast more than once a second (RFC 6762 section 6).
const MIN_MULTICAST_GAP: Duration = Duration::from_secs(1);

/// A question put to a segment on another's behalf is not put to it again
/// within this long: clients ask again after a second, and several ask alike.
const FORWARD_GAP: Duration = Duration::from_secs(1);

/// How long after asking a device on its link-local address, so that the
/// kernel looks up its link-layer address, it is not asked so again.
const NUDGE_GAP: Duration = Duration::from_secs(60);

/// Questions remembered per segment as just put to it, so that a client
/// asking endless made-up names cannot grow the list without bound.
const MAX_FORWARDED: usize = 1024;

/// The default for how long a device is kept at least after it was last heard
/// from, whatever TTLs it announced. See [`Segment::set_min_lifetime`].
pub const DEFAULT_MIN_LIFETIME: Duration = Duration::from_secs(300);

/// The headers around an mDNS packet: those of IPv6, the larger of the two
/// families, and of UDP. What an interface's MTU leaves for the packet is its
/// MTU less these.
const IP_UDP_HEADERS: u32 = 40 + 8;

/// The least a packet may be let grow to, whatever an interface says: what
/// any DNS resolver takes (RFC 1035 section 4.2.1).
const MIN_MAX_PACKET: usize = 512;

/// The most a packet may be let grow to, however large an interface's MTU:
/// mDNS's own limit (RFC 6762 section 17).
const MAX_MAX_PACKET: usize = 9000;

/// A change to the *discovered* list (manual devices never produce events),
/// or questions asked on the segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Added(Device),
    /// Hostname or services changed.
    Updated(Device),
    Removed(Device),
    /// The questions of a query that no device here owns the name of: for
    /// the reflector to put to the segments whose devices it announces here
    /// ([`Segment::query_question`]), as it is configured to.
    Question(Vec<Asked>),
}

/// A question asked on a segment, as passed on to the reflector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub question: Question,
    /// Whether something announced here has an answer to it already. For a
    /// browse, that is one answer, not necessarily all of them.
    pub answered: bool,
}

/// Something a segment's timer is waiting to do: see [`Segment::pending`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// `expire`, `refresh` or `re-announce`.
    pub what: &'static str,
    /// The device it is about: its hostname, or the address it was heard from.
    pub who: String,
    pub at: Instant,
}

/// How a discovered device is told apart: by hostname once it has one,
/// otherwise by the address it was heard from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    Host(String),
    Source(IpAddr),
}

/// A discovered device, and when to drop it or ask it again.
struct Entry {
    device: Device,
    /// The address of the packet it was first heard of in.
    from: IpAddr,
    expires: Instant,
    /// When each of its addresses runs out if it is not heard of again: its
    /// own TTL after it was last heard, but not before the minimum lifetime,
    /// as for the device. One that stops being announced, without a goodbye,
    /// is so dropped on its own.
    addr_expires: HashMap<IpAddr, Instant>,
    /// When it was last asked to answer again because it was about to expire.
    refreshed: Option<Instant>,
    /// When it was last asked on its link-local address, for the kernel to
    /// find its link-layer address ([`NUDGE_GAP`]).
    nudged: Option<Instant>,
}

impl Entry {
    fn new(now: Instant, from: IpAddr) -> Entry {
        Entry { device: Device::default(), from, expires: now, addr_expires: HashMap::new(), refreshed: None, nudged: None }
    }

    /// Its records that answer `q`, each with the time it has left here as
    /// its TTL, as known answers to a query asking `q` (RFC 6762 section 7.1).
    /// None of one without a hostname, which has no records of its own.
    fn known_answers(&self, q: &Question, now: Instant) -> Vec<Record> {
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
    fn soonest(&self) -> Instant {
        self.addr_expires.values().copied().fold(self.expires, Instant::min)
    }

    /// Renew those of `addrs` it has, each for its TTL in `ttls` (none if it
    /// did not say) but at least `floor` from `now`, and forget when the
    /// addresses it no longer has run out.
    fn renew_addrs(&mut self, addrs: &[IpAddr], ttls: &HashMap<IpAddr, u32>, now: Instant, floor: Duration) {
        for addr in addrs.iter().filter(|a| self.device.has_addr(a)) {
            let ttl = Duration::from_secs(ttls.get(addr).copied().unwrap_or(0).into());
            self.addr_expires.insert(*addr, now + ttl.max(floor));
        }
        let device = &self.device;
        self.addr_expires.retain(|addr, _| device.has_addr(addr));
    }

    /// Drop the addresses that have run out by `now`. Returns whether any had.
    fn expire_addrs(&mut self, now: Instant) -> bool {
        let gone: Vec<IpAddr> = self.addr_expires.iter().filter(|&(_, at)| *at <= now).map(|(a, _)| *a).collect();
        for addr in &gone {
            self.addr_expires.remove(addr);
        }
        self.device.addresses.retain(|a| !gone.contains(&a.ip));
        !gone.is_empty()
    }

    /// Whether there is anything to ask it about: a name or a service.
    fn askable(&self) -> bool {
        self.device.hostname.is_some() || !self.device.services.is_empty()
    }

    /// Take over what was learned about this device before its name was known.
    fn absorb(&mut self, earlier: Entry) {
        self.device.absorb(earlier.device);
        self.expires = self.expires.max(earlier.expires);
        for (addr, at) in earlier.addr_expires {
            let mine = self.addr_expires.entry(addr).or_insert(at);
            *mine = (*mine).max(at);
        }
    }
}

/// A way to send over one family: a socket, and the group to send to.
struct Outbound {
    family: Family,
    socket: UdpSocket,
    dest: SocketAddr,
}

/// When a device's records were last multicast, over each family: the rate
/// limit is per group, and each family has its own.
#[derive(Clone, Copy)]
struct Sent {
    v4: Instant,
    v6: Instant,
}

impl Sent {
    /// Over both, at `now`: what announcing does.
    fn both(now: Instant) -> Sent {
        Sent { v4: now, v6: now }
    }

    fn over(&self, family: Family) -> Instant {
        match family {
            Family::V4 => self.v4,
            Family::V6 => self.v6,
        }
    }

    fn set(&mut self, family: Family, now: Instant) {
        match family {
            Family::V4 => self.v4 = now,
            Family::V6 => self.v6 = now,
        }
    }
}



/// Who wants a device announced on a segment. Several may want the same
/// hostname announced there: two reflectors that share the interface, or a
/// reflected device named like the advertised one. The lowest owner's device
/// is announced, and the next one's takes over when it goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    /// The daemon's own name (`[Advertise]`), which always wins.
    Own,
    /// A reflector, ranked by where its segment is in the config: the first
    /// segment wins.
    Reflector(u32),
}

/// One owner's wish to have a device announced, with the TTL of its address.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Claim {
    device: Device,
    host_ttl: u32,
}

/// A hostname announced on behalf of somewhere else, plus the timing needed
/// to keep it announced.
struct Manual {
    /// Everyone who wants this hostname announced. The first one wins; empty
    /// only while what was shown is still to be withdrawn.
    claims: BTreeMap<Owner, Claim>,
    /// What is announced: the winning claim, less what devices on this
    /// segment have themselves (see [`State::wanted`]). `None` while a device
    /// here has the hostname.
    shown: Option<Device>,
    /// When the full record set was last multicast; drives re-announcement.
    announced: Instant,
    /// Whether that was what changed, still to be announced a second time
    /// ([`ANNOUNCE_REPEAT`]).
    repeat: bool,
    /// When any of its records was last multicast, over each family; drives
    /// the rate limit.
    last_sent: Sent,
    /// Not before this, after sending failed.
    retry: Option<Instant>,
    /// The TTLs it is announced with: of its address records, and of the rest.
    host_ttl: u32,
    other_ttl: u32,
}

impl Manual {
    fn new(now: Instant) -> Manual {
        Manual {
            claims: BTreeMap::new(),
            shown: None,
            announced: now,
            repeat: false,
            last_sent: Sent::both(now),
            retry: None,
            host_ttl: HOST_TTL,
            other_ttl: OTHER_TTL,
        }
    }

    /// The shortest TTL anything of it is announced with: it has to be
    /// announced again before that runs out.
    fn shortest_ttl(&self) -> u32 {
        let services = self.shown.iter().flat_map(|d| &d.services).map(|svc| service_ttl(svc, self.other_ttl));
        services.chain([self.host_ttl]).min().unwrap_or(self.host_ttl)
    }

    /// When it is next due for re-announcing, or for another try after
    /// sending failed; `None` if nothing is shown and nothing is pending.
    /// What changed is announced a second time; what has not, only if the
    /// segment re-announces `unchanged` ones.
    fn reannounce_at(&self, unchanged: bool) -> Option<Instant> {
        let after = |gap: Duration| self.announced.checked_add(gap).unwrap_or(self.announced);
        let due = |_: &Device| match (self.repeat, unchanged) {
            (true, _) => Some(after(ANNOUNCE_REPEAT)),
            (false, true) => Some(after(reannounce_after(self.shortest_ttl()))),
            (false, false) => None,
        };
        self.retry.or_else(|| self.shown.as_ref().and_then(due))
    }
}

/// The segment's upkeep (expiry, refreshing and re-announcing): when the
/// event loop is to run it, and how it has run.
#[derive(Default)]
struct Upkeep {
    /// How long before expiry devices are asked to answer again, if at all.
    before: Option<Duration>,
    running: bool,
    runs: u64,
    last_run: Option<Instant>,
    last_took: Option<Duration>,
}

/// What a probe tells whoever asked for it: how many questions it sent.
pub type Probed = std::result::Result<usize, String>;

/// A probe, or a query for types by name, under way: which round comes next,
/// and when.
struct Probing {
    /// The types asked for by name; `None` for a probe of everything.
    kinds: Option<Vec<String>>,
    /// Why it runs, for the journal: at startup it says how it went, and
    /// otherwise only if it failed.
    why: &'static str,
    /// Its number, under which how it went is kept for whoever asked for it
    /// ([`Segment::probed`]), if anyone did.
    id: u64,
    asked: bool,
    /// The next round, or [`PROBE_GAPS`]'s length when only the wait for the
    /// last answers is left.
    round: usize,
    next: Instant,
    sent: usize,
}

/// How a segment's upkeep has run, for `timers`.
pub struct UpkeepInfo {
    pub due: Option<Instant>,
    pub running: bool,
    pub runs: u64,
    pub last_run: Option<Instant>,
    pub last_took: Option<Duration>,
}

/// How long to wait before asking a device again that has not answered.
fn refresh_gap(before: Duration) -> Duration {
    (before / 4).max(Duration::from_secs(5))
}

#[derive(Default)]
struct State {
    discovered: HashMap<Key, Entry>,
    /// Which discovered device each address belongs to, so a packet that does
    /// not name its sender can still be attributed.
    by_addr: HashMap<IpAddr, Key>,
    /// Devices we announce on this segment on behalf of somewhere else, by
    /// lowercase hostname.
    manual: HashMap<String, Manual>,
    /// Changes not yet taken by the event loop ([`Segment::take_events`]).
    outbox: Vec<Event>,
    /// The probes and queries for types under way, the number of the last
    /// one started, and how those asked for went, by number, until taken.
    probing: Vec<Probing>,
    probes_started: u64,
    probed: VecDeque<(u64, Probed)>,
    /// How often to probe on its own, if at all, and when next.
    probe_interval: Option<Duration>,
    next_routine: Option<Instant>,
    /// How to send, over each family the segment has a socket of.
    outbound: Vec<Outbound>,
    /// Service types devices on this segment have said they offer, learned
    /// from answers to the type enumeration query.
    types: BTreeSet<String>,
    /// The least a device is kept after it was last heard from.
    min_lifetime: Duration,
    /// Whether what is announced here is announced again before its TTL runs
    /// out though it has not changed. It need not be: whoever still wants it
    /// asks again (RFC 6762 section 5.2), and is answered.
    reannounce: bool,
    /// How many addresses of a family a discovered device is kept with.
    max_addrs: usize,
    /// The most a packet sent here may hold: what the interface's MTU leaves.
    max_packet: usize,
    upkeep: Upkeep,
    /// The questions put to this segment on another's behalf, in lowercase,
    /// and when, for [`FORWARD_GAP`].
    forwarded: HashMap<(String, u16), Instant>,
    /// The kernel's neighbour table for the interface: each address it has a
    /// link-layer address for, and that link-layer address.
    neighbours: HashMap<IpAddr, Vec<u8>>,
    /// The networks the interface is on: of the neighbour table, only
    /// addresses in one of them are learned.
    prefixes: Vec<Prefix>,
}

impl State {
    /// Bring the addresses learned from the neighbour table up to date for
    /// the devices of `keys`, noting in `touched` those that change: the
    /// routable addresses listed under the link-layer address of one it
    /// announced, in a network the interface is on (an entry left over from
    /// one it is no longer on is not the device's to be reached at), of a
    /// family it announced no routable address of
    /// ([`Device::take_neighbours`]). A device with a link-local IPv6 address
    /// the table has not got yet, and no routable one, is asked a question on
    /// it, for the kernel to look up its link-layer address.
    fn learn_neighbours(&mut self, keys: &[Key], touched: &mut Touched, now: Instant) {
        for key in keys {
            let Some(entry) = self.discovered.get(key) else { continue };
            // Its link-layer address, by any address it announced.
            let announced = entry.device.addresses.iter().filter(|a| a.origin == Origin::Announced);
            let macs: Vec<&Vec<u8>> = announced.filter_map(|a| self.neighbours.get(&a.ip)).collect();
            let on_link = |ip: &IpAddr| self.prefixes.iter().any(|p| p.contains(ip));
            let learned: Vec<IpAddr> = self
                .neighbours
                .iter()
                .filter(|(ip, mac)| !is_link_local(ip) && on_link(ip) && macs.contains(mac))
                .map(|(ip, _)| *ip)
                .collect();

            let unresolved = entry.device.link_local().find(|ll| ll.is_ipv6() && !self.neighbours.contains_key(ll));
            let has_v6 = entry.device.routable().any(|a| a.is_ipv6());
            let due = entry.nudged.is_none_or(|t| now.saturating_duration_since(t) >= NUDGE_GAP);
            if let Some(ll) = unresolved.filter(|_| !has_v6 && due) {
                nudge(&self.outbound, ll, &Device::refresh_queries(std::slice::from_ref(&entry.device), self.max_packet));
                self.discovered.get_mut(key).expect("looked up above").nudged = Some(now);
            }

            let mut device = self.discovered[key].device.clone();
            if device.take_neighbours(&learned, self.max_addrs) {
                touched.note(&self.discovered, key);
                // A packet from an address it no longer has is not its.
                self.by_addr.retain(|ip, k| k != key || device.has_addr(ip));
                for ip in device.addresses.iter().filter(|a| a.origin == Origin::Neighbour).map(|a| a.ip) {
                    self.by_addr.entry(ip).or_insert_with(|| key.clone());
                }
                self.discovered.get_mut(key).expect("looked up above").device = device;
            }
        }
    }

    /// Bring the learned addresses of every device with an address up to
    /// date, as the neighbour table or the interface's networks changed, and
    /// tell of those that changed.
    fn relearn_neighbours(&mut self, now: Instant) {
        let keys: Vec<Key> =
            self.discovered.iter().filter(|(_, e)| !e.device.addresses.is_empty()).map(|(k, _)| k.clone()).collect();
        let mut touched = Touched::default();
        self.learn_neighbours(&keys, &mut touched, now);
        let events = touched.events(&self.discovered);
        if !events.is_empty() {
            self.settle_all(now);
        }
        for event in events {
            self.notify(event);
        }
    }

    fn notify(&mut self, event: Event) {
        self.outbox.push(event);
    }

    /// The next time [`Segment::expire`], [`Segment::refresh`] or
    /// [`Segment::reannounce`] has something to do, or `None` if never. A time
    /// in the past means it is due now. Every time returned is one at which
    /// one of them acts, so that running them moves it on.
    fn next_due(&self, now: Instant) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        self.for_each_deadline(now, &mut |_, _, at| next = Some(next.map_or(at, |n| n.min(at))));
        next
    }

    /// Every time something is due, as what is to be done (`expire`,
    /// `refresh` or `re-announce`), to whom, and when. What
    /// [`State::next_due`] and [`Segment::pending`] are made of.
    fn for_each_deadline(&self, now: Instant, f: &mut dyn FnMut(&'static str, &dyn fmt::Display, Instant)) {
        let before = self.upkeep.before;
        for (key, e) in &self.discovered {
            let who: &dyn fmt::Display = match (&e.device.hostname, key) {
                (Some(host), _) | (None, Key::Host(host)) => host,
                (None, Key::Source(addr)) => addr,
            };
            f("expire", who, e.expires);
            // Its addresses that run out before it does, each on its own.
            for (addr, &at) in e.addr_expires.iter().filter(|&(_, at)| *at < e.expires) {
                f("expire", &format!("{who} {addr}"), at);
            }
            let Some(before) = before.filter(|_| !self.outbound.is_empty() && e.askable()) else {
                continue;
            };
            // Due `before` ahead of it or one of its addresses running out,
            // and not again until the gap has passed since it was last asked.
            let soonest = e.soonest();
            let mut at = soonest.checked_sub(before).unwrap_or(now);
            match e.refreshed.map(|t| t.checked_add(refresh_gap(before))) {
                Some(Some(again)) => at = at.max(again),
                Some(None) => continue, // never again
                None => {}
            }
            // What runs out first is dropped, not asked about.
            if at < soonest {
                f("refresh", who, at);
            }
        }
        for p in &self.probing {
            let kinds = p.kinds.as_ref().map(|k| k.join(", "));
            f("probe", &kinds.as_deref().unwrap_or("every type"), p.next);
        }
        if let Some(at) = self.next_routine {
            f("probe", &"every type, as configured", at);
        }
        for (key, m) in &self.manual {
            if let Some(at) = m.reannounce_at(self.reannounce) {
                // By the name as announced, not the key, which is lowercase.
                let device = m.shown.as_ref().or_else(|| m.claims.values().next().map(|c| &c.device));
                let name = device.and_then(|d| d.hostname.as_deref()).unwrap_or(key);
                f("re-announce", &name, at);
            }
        }
    }

    /// How much longer the daemon keeps `device` if it is not heard from, to
    /// the second.
    fn lifetime_left(&self, device: &Device) -> Duration {
        let key = match (&device.hostname, device.addrs().next()) {
            (Some(host), _) => host_key(host),
            (None, Some(addr)) => Key::Source(addr),
            (None, None) => return Duration::ZERO,
        };
        self.discovered.get(&key).map_or(Duration::ZERO, |entry| {
            let left = entry.expires.saturating_duration_since(Instant::now());
            Duration::from_secs(left.as_secs_f64().round() as u64)
        })
    }

    /// Drop a discovered device and the addresses that pointed at it.
    fn forget(&mut self, key: &Key) -> Option<Entry> {
        self.by_addr.retain(|_, k| k != key);
        self.discovered.remove(key)
    }

    /// Whether a new host may be learned of from `src`: the segment has
    /// fewer than [`MAX_DEVICES`], and `src` first described fewer than
    /// [`MAX_PER_SENDER`] of them.
    fn room_for(&self, src: IpAddr) -> bool {
        let named = |e: &&Entry| e.from == src && e.device.hostname.is_some();
        self.discovered.len() < MAX_DEVICES && self.discovered.values().filter(named).count() < MAX_PER_SENDER
    }

    /// The instance names, in lowercase, of the services that devices on this
    /// segment offer themselves.
    fn local_instances(&self) -> HashSet<String> {
        self.discovered.values().flat_map(|e| &e.device.services).map(|s| s.instance.to_ascii_lowercase()).collect()
    }

    /// What should be announced as `key`: the winning claim, less the
    /// services whose instance names devices here have (`local`), or nothing
    /// if a device here has the hostname. Announced on top of a device here,
    /// a copy would be a conflict, and the device would rename itself. The
    /// advertised name is ours, and announced whatever is here.
    fn wanted(&self, key: &str, m: &Manual, local: &HashSet<String>) -> Option<Claim> {
        let (owner, claim) = m.claims.iter().next()?;
        if *owner == Owner::Own {
            return Some(claim.clone());
        }
        if self.discovered.contains_key(&Key::Host(key.to_string())) {
            return None;
        }
        Some(Claim { device: claim.device.without(local), host_ttl: claim.host_ttl })
    }

    /// Bring what is announced as `key` in line with [`State::wanted`], with
    /// goodbyes for what is no longer to be, and forget it once nobody wants
    /// it and nothing of it is shown. Returns whether anything was sent. If
    /// sending fails, nothing changes.
    fn settle(&mut self, key: &str, local: &HashSet<String>, now: Instant) -> Result<bool> {
        let Some(m) = self.manual.get(key) else {
            return Ok(false);
        };
        let want = self.wanted(key, m, local);
        // Each with the TTL its address is announced with.
        let old = m.shown.as_ref().map(|d| Device { ttl: Some(m.host_ttl), ..d.clone() });
        let new = want.as_ref().map(|c| Device { ttl: Some(c.host_ttl), ..c.device.clone() });
        let host_here = self.discovered.contains_key(&Key::Host(key.to_string()));
        let records = Device::transition(old.as_ref(), new.as_ref(), local, host_here);
        let sent = !records.is_empty();
        if sent {
            send(&self.outbound, self.max_packet, &records)?;
        }

        let m = self.manual.get_mut(key).expect("looked up above");
        if sent {
            m.announced = now;
            m.repeat = true;
            m.last_sent = Sent::both(now);
            m.retry = None;
        }
        match want {
            Some(claim) => {
                m.shown = Some(claim.device);
                m.host_ttl = claim.host_ttl;
            }
            None => m.shown = None,
        }
        if m.claims.is_empty() && m.shown.is_none() {
            self.manual.remove(key);
        }
        Ok(sent)
    }

    /// The questions of `query` that are not about a name a device here owns
    /// (it answers for itself), each with whether something announced here
    /// has an answer to it: those the other segments might be asked. None
    /// from a device probing for names it is about to take: they are its own.
    fn asked(&self, query: &Message) -> Vec<Asked> {
        if !query.authorities.is_empty() {
            return Vec::new();
        }
        let local = self.local_instances();
        let shown: Vec<&Device> = self.manual.values().filter_map(|m| m.shown.as_ref()).collect();
        query
            .questions
            .iter()
            .filter(|q| {
                let name = q.name.to_ascii_lowercase();
                !(local.contains(&name) || self.discovered.contains_key(&Key::Host(name)))
            })
            .map(|q| Asked { question: q.clone(), answered: shown.iter().any(|d| d.knows(q)) })
            .collect()
    }

    /// The devices this segment answers queries for, by hostname: what is
    /// shown of each, with the TTL its address is announced with. Left out
    /// are those multicast less than a second ago (RFC 6762 section 6), unless
    /// the reply is to go to a `legacy` resolver alone, and, for a device
    /// `probing` for names it is about to take, the reflected copies: it would
    /// take them for a conflict, and once it announces, the copy gives way.
    fn answering(&self, now: Instant, legacy: bool, probing: bool, family: Family) -> Vec<(String, Device)> {
        let mut out = Vec::new();
        for (key, m) in &self.manual {
            let Some(device) = &m.shown else { continue };
            if probing && m.claims.keys().next() != Some(&Owner::Own) {
                continue;
            }
            if !legacy && now.saturating_duration_since(m.last_sent.over(family)) < MIN_MULTICAST_GAP {
                continue;
            }
            out.push((key.clone(), Device { ttl: Some(m.host_ttl), ..device.clone() }));
        }
        out
    }

    /// [Settle](State::settle) every announced hostname, after the devices
    /// on this segment changed. One that fails to send is tried again by
    /// [`Segment::reannounce`], which reports it if it fails again.
    fn settle_all(&mut self, now: Instant) {
        let local = self.local_instances();
        let keys: Vec<String> = self.manual.keys().cloned().collect();
        for key in keys {
            if self.settle(&key, &local, now).is_err()
                && let Some(m) = self.manual.get_mut(&key)
            {
                m.retry = Some(now + ANNOUNCE_RETRY);
            }
        }
    }
}

/// One mDNS segment (interface) and the two device lists kept for it:
/// devices discovered on the wire, and devices added by hand, over every
/// family it serves: one list, whichever family a device was heard over.
/// Cheap to clone; clones share state, so its link, the reflectors spanning
/// it and the control socket can each hold one.
#[derive(Clone)]
pub struct Segment {
    interface: Rc<str>,
    families: Rc<[Family]>,
    state: Rc<RefCell<State>>,
}

impl Segment {
    /// A segment for `interface`, over `families`, each to be given a socket
    /// with [`attach`](Segment::attach).
    pub fn new(interface: &str, families: &[Family]) -> Segment {
        Segment {
            interface: interface.into(),
            families: families.into(),
            state: Rc::new(RefCell::new(State {
                min_lifetime: DEFAULT_MIN_LIFETIME,
                max_addrs: DEFAULT_MAX_ADDRS,
                max_packet: DEFAULT_MAX_PACKET,
                ..State::default()
            })),
        }
    }

    /// How long a device is kept, at least, after it was last heard from. A
    /// device lives for the longest TTL it announced, but never for less than
    /// this, so that a device that announces tiny TTLs is not dropped between
    /// two of the daemon's checks. The default is [`DEFAULT_MIN_LIFETIME`].
    /// Applies to what is heard from now on.
    pub fn set_min_lifetime(&self, min_lifetime: Duration) {
        self.state.borrow_mut().min_lifetime = min_lifetime;
    }

    /// How many addresses of a family a discovered device is kept with, at
    /// most: more are not taken. The default is [`DEFAULT_MAX_ADDRS`].
    /// Applies to what is heard from now on.
    pub fn set_max_addrs(&self, max_addrs: usize) {
        self.state.borrow_mut().max_addrs = max_addrs.max(1);
    }

    /// Take the interface's MTU: no packet sent here is bigger than it leaves
    /// once the IP and UDP headers are added, so that none has to go out in
    /// fragments. Until it is told, a segment assumes a standard Ethernet
    /// frame ([`DEFAULT_MAX_PACKET`]). Returns what a packet may now hold.
    pub fn set_mtu(&self, mtu: u32) -> usize {
        let room = usize::try_from(mtu.saturating_sub(IP_UDP_HEADERS)).unwrap_or(usize::MAX);
        let max_packet = room.clamp(MIN_MAX_PACKET, MAX_MAX_PACKET);
        self.state.borrow_mut().max_packet = max_packet;
        max_packet
    }

    /// Whether what is announced here is announced again, at 80% of its TTL,
    /// though it has not changed; by default it is not. What changes is
    /// announced twice, a second apart, either way.
    pub fn set_reannounce(&self, unchanged: bool) {
        self.state.borrow_mut().reannounce = unchanged;
    }

    /// Ask devices to answer again `before` ahead of expiring, from now on;
    /// `None` (the default) does not.
    pub fn set_refresh_before(&self, before: Option<Duration>) {
        self.state.borrow_mut().upkeep.before = before;
    }

    /// When [`Segment::upkeep`] next has something to do, or `None` if never;
    /// a time in the past means it is due now.
    pub fn next_due(&self) -> Option<Instant> {
        self.state.borrow_mut().next_due(Instant::now())
    }

    /// Do what is due at `now`: drop what has run out, ask the devices about
    /// to expire to answer again, and re-announce. Run by the event loop when
    /// [`Segment::next_due`] says.
    pub fn upkeep(&self, now: Instant) {
        let started = Instant::now();
        let before = {
            let mut state = self.state.borrow_mut();
            state.upkeep.running = true;
            state.upkeep.last_run = Some(started);
            state.upkeep.before
        };
        // Drop what has run out first, so that nothing is asked that is being
        // dropped, then ask the devices about to expire to answer again.
        // Routine refreshes are not worth a journal line each.
        self.expire(now);
        if let Some(before) = before
            && let Err(e) = self.refresh(now, before)
        {
            eprintln!("{}: refresh failed: {e:#}", self.interface);
        }
        if let Err(e) = self.reannounce(now) {
            eprintln!("{}: re-announce failed: {e:#}", self.interface);
        }
        self.run_probes(now);
        let mut state = self.state.borrow_mut();
        state.upkeep.running = false;
        state.upkeep.runs += 1;
        state.upkeep.last_took = Some(started.elapsed());
    }

    /// How its upkeep has run, and when it is next due.
    pub fn upkeep_info(&self) -> UpkeepInfo {
        let state = self.state.borrow_mut();
        let u = &state.upkeep;
        UpkeepInfo { due: state.next_due(Instant::now()), running: u.running, runs: u.runs, last_run: u.last_run, last_took: u.last_took }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The families it serves.
    pub fn families(&self) -> &[Family] {
        &self.families
    }

    /// Give the segment a way to send over `family`: `socket`, to the group
    /// at `dest`. Replaces an earlier one of the family. Without any (as in
    /// unit tests), manual changes are recorded but nothing goes on the wire.
    pub fn attach(&self, family: Family, socket: UdpSocket, dest: SocketAddr) {
        let mut state = self.state.borrow_mut();
        state.outbound.retain(|o| o.family != family);
        state.outbound.push(Outbound { family, socket, dest });
    }

    // 1. Discovered devices.

    /// Devices currently active on this segment (excludes manual ones).
    pub fn devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.discovered.values().map(|e| e.device.clone()).collect()
    }

    // 2. Change notifications for the discovered list.

    /// The changes to its devices since last asked, oldest first, for the
    /// event loop to hand on.
    pub fn take_events(&self) -> Vec<Event> {
        std::mem::take(&mut self.state.borrow_mut().outbox)
    }

    /// Whether `other` is this very segment, not just one of the same name.
    pub fn is(&self, other: &Segment) -> bool {
        Rc::ptr_eq(&self.state, &other.state)
    }

    /// Everything this segment's timer is waiting for, soonest first: devices
    /// to expire, to ask again, and to re-announce. The timer's own time is the
    /// first of these.
    pub fn pending(&self) -> Vec<Pending> {
        let state = self.state.borrow_mut();
        let mut all = Vec::new();
        state.for_each_deadline(Instant::now(), &mut |what, who, at| {
            all.push(Pending { what, who: who.to_string(), at });
        });
        all.sort_by_key(|p| p.at);
        all
    }

    /// How much longer the daemon keeps `device`, a device of this segment, if
    /// it is not heard from again, to the second; zero if it is not (or no
    /// longer) known.
    pub fn lifetime_left(&self, device: &Device) -> Duration {
        self.state.borrow_mut().lifetime_left(device)
    }

    // 3. Reflected devices, invisible to 1 and 2.

    /// Announce `device` on this segment for `owner` and remember it, under
    /// its hostname. It needs a hostname and at least one address, all of
    /// this segment's family, and announces exactly the addresses it has: a
    /// reflected device should arrive with only its routable one, since a
    /// link-local address is no use on another link. Its address records are
    /// announced with the TTL it announced itself with (at least ten seconds,
    /// and two minutes if it did not say), and those of its services with
    /// theirs.
    ///
    /// If another owner wants the same hostname announced, the lower
    /// [`Owner`] wins: an outranked device is only remembered, and announced
    /// once the ones ahead of it are removed. Replacing what is announced
    /// also sends goodbyes for services and addresses that are no longer
    /// there. A device on this segment comes first of all: while one has the
    /// hostname, a reflected device of that name is not announced, and
    /// services whose instance names one has are left out (the advertised
    /// name is announced regardless).
    ///
    /// Returns false (and sends nothing) if `owner` already has an identical
    /// device here. If sending fails nothing is recorded.
    pub fn add_manual(&self, owner: Owner, device: Device) -> Result<bool> {
        let ttl = device.ttl.map(|t| t.max(MIN_REFLECT_TTL)).unwrap_or(HOST_TTL);
        self.add_manual_ttl(owner, device, Duration::from_secs(ttl.into()))
    }

    /// Like [`add_manual`](Segment::add_manual), with the address records
    /// announced for `host_ttl` (whole seconds, at least one) whatever the
    /// device says, and, if the segment re-announces, re-announced at 80% of
    /// it.
    pub fn add_manual_ttl(&self, owner: Owner, device: Device, host_ttl: Duration) -> Result<bool> {
        let host_ttl = u32::try_from(host_ttl.as_secs()).unwrap_or(u32::MAX);
        if host_ttl == 0 {
            bail!("a TTL of zero would withdraw the device");
        }
        let Some(key) = device.key() else {
            return Err(anyhow!("a reflected device needs a hostname to announce"));
        };
        if device.addrs().next().is_none() {
            bail!("{key} has no address to announce");
        }

        let claim = Claim { device, host_ttl };
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let m = state.manual.entry(key.clone()).or_insert_with(|| Manual::new(now));
        if m.claims.get(&owner) == Some(&claim) {
            return Ok(false);
        }
        let previous = m.claims.insert(owner, claim);
        let local = state.local_instances();
        if let Err(e) = state.settle(&key, &local, now) {
            // Nothing is recorded: put back what was there.
            if let Some(m) = state.manual.get_mut(&key) {
                match previous {
                    Some(previous) => m.claims.insert(owner, previous),
                    None => m.claims.remove(&owner),
                };
                if m.claims.is_empty() && m.shown.is_none() {
                    state.manual.remove(&key);
                }
            }
            return Err(e);
        }
        drop(guard);
        Ok(true)
    }

    /// Forget what `owner` wanted announced as `hostname`. If that is what is
    /// announced, the next owner's device takes its place, or, if there is
    /// none, goodbyes are sent for it. Returns false if `owner` had no such
    /// device. If sending fails it is kept.
    pub fn remove_manual(&self, owner: Owner, hostname: &str) -> Result<bool> {
        let key = hostname.to_ascii_lowercase();
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let Some(previous) = state.manual.get_mut(&key).and_then(|m| m.claims.remove(&owner)) else {
            return Ok(false);
        };
        let local = state.local_instances();
        if let Err(e) = state.settle(&key, &local, Instant::now()) {
            if let Some(m) = state.manual.get_mut(&key) {
                m.claims.insert(owner, previous);
            }
            return Err(e);
        }
        drop(guard);
        Ok(true)
    }

    /// Let go of every way to send, as when the interface is gone: what is
    /// announced here is kept, to announce again once it is back.
    pub fn detach_all(&self) {
        self.state.borrow_mut().outbound.clear();
    }

    /// Announce again everything announced here, as when the interface has
    /// come back: whoever is on it now may never have heard it. A failed send
    /// is retried by [`Segment::reannounce`].
    pub fn announce_all(&self) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let State { manual, outbound, max_packet, .. } = &mut *guard;
        let mut first_err = None;
        for m in manual.values_mut() {
            let Some(device) = &m.shown else { continue };
            match send(outbound, *max_packet, &device.announcement(m.host_ttl, m.other_ttl)) {
                Ok(()) => {
                    m.announced = now;
                    m.repeat = true;
                    m.last_sent = Sent::both(now);
                    m.retry = None;
                }
                Err(e) => {
                    m.retry = Some(now + ANNOUNCE_RETRY);
                    first_err.get_or_insert(e);
                }
            }
        }
        drop(guard);
        first_err.map_or(Ok(()), Err)
    }

    /// Forget every device discovered here, as when the interface is gone:
    /// they cannot be reached through it, and their copies elsewhere are
    /// withdrawn. They are found again once it is back.
    pub fn forget_discovered(&self) {
        let mut state = self.state.borrow_mut();
        let keys: Vec<Key> = state.discovered.keys().cloned().collect();
        for key in keys {
            if let Some(entry) = state.forget(&key) {
                state.notify(Event::Removed(entry.device));
            }
        }
        state.settle_all(Instant::now());
    }

    /// The devices announced on this segment: for each hostname, what is
    /// shown of the one that won.
    pub fn manual_devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.manual.values().filter_map(|m| m.shown.clone()).collect()
    }

    /// Announce a second time what changed a second ago ([`ANNOUNCE_REPEAT`]),
    /// and, if the segment re-announces ([`Segment::set_reannounce`]), what
    /// has not had a full announcement for 80% of its TTL; and try again
    /// what failed to send. A failed send
    /// is retried after [`ANNOUNCE_RETRY`]; the first error is returned after
    /// every device was tried. Run by [`Segment::schedule`] when due.
    pub fn reannounce(&self, now: Instant) -> Result<()> {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let local = state.local_instances();
        let due: Vec<String> = state
            .manual
            .iter()
            .filter(|(_, m)| m.reannounce_at(state.reannounce).is_some_and(|at| at <= now))
            .map(|(key, _)| key.clone())
            .collect();
        let mut first_err = None;
        for key in due {
            // What is out of line is settled first, which announces it.
            let result = state.settle(&key, &local, now).and_then(|sent| {
                let Some(m) = state.manual.get_mut(&key).filter(|_| !sent) else {
                    return Ok(());
                };
                if let Some(device) = &m.shown {
                    send(&state.outbound, state.max_packet, &device.announcement(m.host_ttl, m.other_ttl))?;
                    m.announced = now;
                    m.repeat = false;
                    m.last_sent = Sent::both(now);
                }
                m.retry = None;
                Ok(())
            });
            if let Err(e) = result {
                if let Some(m) = state.manual.get_mut(&key) {
                    m.retry = Some(now + ANNOUNCE_RETRY);
                }
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Answer a query from `from` with whatever reflected devices match it.
    ///
    /// Replies are multicast, except to legacy resolvers (source port other
    /// than 5353), which get a unicast reply that echoes the question. Known
    /// answers in the query suppress our answer, and a device's records are
    /// not multicast more than once a second. A device probing for names it
    /// is about to take is not answered with reflected copies: it would take
    /// them for a conflict, and once it announces, the copy gives way.
    ///
    /// What it has no answer to is passed on as an [`Event::Question`], for
    /// the reflector to ask elsewhere.
    fn respond(&self, from: SocketAddr, query: &Message) -> Result<()> {
        let h = &query.header;
        if h.response || h.opcode != 0 || h.rcode != 0 || query.questions.is_empty() {
            return Ok(());
        }
        let legacy = from.port() != MDNS_PORT;
        // Answered over the family it was asked over, with everything of
        // both: an A answer brings the AAAA records along.
        let family = family_of(from.ip());
        let now = Instant::now();

        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let asked = state.asked(query);
        if !asked.is_empty() {
            state.notify(Event::Question(asked));
        }
        let probing = !query.authorities.is_empty();
        let (keys, devices): (Vec<String>, Vec<Device>) = state.answering(now, legacy, probing, family).into_iter().unzip();
        let Some((msgs, answered)) = Device::query_response(&devices, query, legacy, state.max_packet) else {
            return Ok(());
        };
        for msg in &msgs {
            transmit(&state.outbound, family, msg, legacy.then_some(from))?;
        }

        if !legacy {
            for i in answered {
                if let Some(m) = state.manual.get_mut(&keys[i]) {
                    m.last_sent.set(family, now);
                }
            }
        }
        Ok(())
    }

    /// Ask the devices on this segment `questions` asked on another segment,
    /// in a query of the daemon's own: nothing of the asker's packet comes
    /// here, not its address, not its known answers, not its wish for a
    /// unicast reply. Their answers are heard like any, and so reflected;
    /// the asker, asking again, is answered from that. What is known here
    /// already goes along as known answers, with the time it has left, so
    /// that only devices not yet heard of, or about to run out, answer.
    ///
    /// A question asked here within [`FORWARD_GAP`] is not asked again, nor
    /// any once [`MAX_FORWARDED`] are waiting it out. Returns how many were
    /// asked. A no-op when the segment has no sender attached.
    pub fn query_question(&self, questions: &[Question]) -> Result<usize> {
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        if state.outbound.is_empty() {
            return Ok(0);
        }
        state.forwarded.retain(|_, at| now.saturating_duration_since(*at) < FORWARD_GAP);
        let mut fresh = Vec::new();
        for q in questions {
            let key = (q.name.to_ascii_lowercase(), q.qtype);
            if !state.forwarded.contains_key(&key) && state.forwarded.len() < MAX_FORWARDED {
                state.forwarded.insert(key, now);
                fresh.push(q);
            }
        }
        let known = |q: &Question| state.discovered.values().flat_map(|e| e.known_answers(q, now)).collect();
        ask(&state.outbound, &Device::forward_queries(fresh, known, state.max_packet))
    }

    // Fed by the receive loops and the timer.

    /// Handle a received datagram: record the sender (still counted as alive
    /// if the packet does not parse) and answer it if it is a query we can
    /// answer. The error, if any, is from sending the answer.
    pub fn handle(&self, from: SocketAddr, packet: &[u8]) -> Result<()> {
        match Message::parse(packet) {
            Ok(msg) => {
                self.apply(from.ip(), Instant::now(), Some(&msg));
                        self.respond(from, &msg)
            }
            Err(_) => {
                self.observe(from.ip());
                Ok(())
            }
        }
    }

    /// Record that `addr` was heard on this segment, without any record data.
    pub fn observe(&self, addr: IpAddr) {
        self.apply(addr, Instant::now(), None);
    }

    fn apply(&self, src: IpAddr, now: Instant, msg: Option<&Message>) {
        // Records in a query are other devices' known answers, not the
        // sender's own data.
        let msg = msg.filter(|m| m.header.response);
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let (floor, max_addrs) = (state.min_lifetime, state.max_addrs);
        let mut touched = Touched::default();

        // A response saying goodbye (TTL 0) to the address it came from, and
        // announcing none for that name still, is a device leaving: the
        // device that owns that name, and anything the sender was only known
        // by. One that announces others in its place (a temporary IPv6
        // address giving way to the next) is not; it only loses the one.
        let records = || msg.into_iter().flat_map(|m| m.records());
        let still = |name: &str| records().any(|r| r.ttl > 0 && addr_of(&r.data).is_some() && r.name.eq_ignore_ascii_case(name));
        let leaving: Vec<Key> = records()
            .filter(|r| r.ttl == 0 && addr_of(&r.data) == Some(src) && !still(&r.name))
            .map(|r| host_key(&r.name))
            .collect();
        if !leaving.is_empty() {
            for key in leaving.iter().chain([&Key::Source(src)]) {
                touched.note(&state.discovered, key);
                state.forget(key);
            }
            let events = touched.events(&state.discovered);
            if !events.is_empty() {
                state.settle_all(now);
            }
            for event in events {
                state.notify(event);
            }
            return;
        }

        for rec in msg.into_iter().flat_map(|m| m.records()) {
            if let RData::Ptr(kind) = &rec.data
                && rec.ttl > 0
                && rec.name.eq_ignore_ascii_case(META_QUERY)
                && rec.class == 1
                && is_type(kind)
                && state.types.len() < MAX_TYPES
            {
                state.types.insert(kind.to_ascii_lowercase());
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
        let mut sender: Option<Key> = None;
        let mut resolved: Vec<(Key, String)> = Vec::new();

        for report in &reports {
            let key = host_key(&report.host);
            if !state.discovered.contains_key(&key) && !state.room_for(src) {
                continue;
            }
            // Goodbyes alone for a device not known here (one that already
            // left by its other family's goodbye) leave nothing to forget, and
            // are not to bring it back.
            if report.addrs.is_empty() && !report.gone.is_empty() && !state.discovered.contains_key(&key) {
                continue;
            }
            // The sender, if it announced the address the packet came from, or
            // is the only host described and announced no address of that
            // family: not even one no one can be reached at, or one it says
            // goodbye to, which are not to be made good with the sender's.
            let same_family = |a: &IpAddr| a.is_ipv4() == src.is_ipv4();
            let is_sender = report.addrs.contains(&src)
                || (!report.addrs.iter().chain(&report.refused).chain(&report.gone).any(same_family)
                    && reports.len() == 1);
            // A packet sent from an address no device can be reached at
            // (a device without an IPv4 address sends from 0.0.0.0) vouches
            // for no address.
            let mut addrs = report.addrs.clone();
            if is_sender && !addrs.contains(&src) && is_usable(src) {
                addrs.push(src);
            }

            // A device first heard only by address becomes the named device.
            let earlier = if is_sender {
                touched.note(&state.discovered, &Key::Source(src));
                state.discovered.remove(&Key::Source(src))
            } else {
                None
            };

            touched.note(&state.discovered, &key);
            let entry = state.discovered.entry(key.clone()).or_insert_with(|| Entry::new(now, src));
            if let Some(earlier) = earlier {
                entry.absorb(earlier);
            }
            let ttl = Duration::from_secs(report.longest_ttl().into());
            entry.expires = entry.expires.max(now + ttl.max(floor));
            entry.device.learn(report, &addrs, max_addrs);
            entry.renew_addrs(&addrs, &report.ttls, now, floor);

            for addr in addrs {
                state.by_addr.insert(addr, key.clone());
            }
            resolved.extend(report.resolved().map(|instance| (key.clone(), instance.to_string())));
            if is_sender && sender.is_none() {
                sender = Some(key);
            }
        }

        // What is left is about the sender itself: records tied to no host (a
        // bare browse answer, text records), or just a sign of life such as a
        // query. A packet that only describes other devices says nothing about
        // its sender, which is then not recorded at all.
        // One known only by an address no device can be reached at is not
        // known at all.
        let usable = is_usable(src);
        let key = sender.or_else(|| state.by_addr.get(&src).cloned()).or_else(|| usable.then_some(Key::Source(src)));
        let room = key.as_ref().is_some_and(|k| state.discovered.contains_key(k)) || state.discovered.len() < MAX_DEVICES;
        if let Some(key) = key.filter(|_| (reports.is_empty() || !rest.is_empty()) && room) {
            touched.note(&state.discovered, &key);
            let entry = state.discovered.entry(key.clone()).or_insert_with(|| Entry::new(now, src));
            let ttl = rest.iter().map(|r| r.ttl).max().unwrap_or(0);
            let ttl = Duration::from_secs(ttl as u64);
            entry.expires = entry.expires.max(now + ttl.max(floor));
            if usable {
                entry.device.take_addrs(&[src], &[], &[], max_addrs);
                entry.renew_addrs(&[src], &HashMap::new(), now, floor);
            }
            entry.device.learn_records(rest.iter().copied());
            if usable {
                state.by_addr.insert(src, key);
            }
        }

        // An instance that has now been resolved to its host no longer needs
        // the unresolved copy learned from a bare browse answer.
        for (owner, instance) in resolved {
            let others: Vec<Key> = state
                .discovered
                .iter()
                .filter(|(k, e)| {
                    **k != owner && e.device.service(&instance).is_some_and(|s| s.target.is_none())
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in others {
                touched.note(&state.discovered, &k);
                if let Some(e) = state.discovered.get_mut(&k) {
                    e.device.forget_service(&instance);
                }
            }
        }

        // What the neighbour table knows of the devices just heard of.
        let heard = touched.order.clone();
        state.learn_neighbours(&heard, &mut touched, now);

        let events = touched.events(&state.discovered);
        if !events.is_empty() {
            state.settle_all(now);
        }
        for event in events {
            state.notify(event);
        }
    }

    /// Take the networks the interface is on, as its addresses change: of the
    /// neighbour table, only addresses in one of them are learned, and those
    /// learned of one it is no longer on are dropped.
    pub fn set_prefixes(&self, prefixes: Vec<Prefix>) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        if state.prefixes == prefixes {
            return;
        }
        state.prefixes = prefixes;
        state.relearn_neighbours(Instant::now());
    }

    /// Take in an entry of the interface's neighbour table, as the kernel
    /// reports it: `ip` is at link-layer address `mac`, or with `None`, no
    /// longer (it went, or could not be reached). The devices it may concern,
    /// those with any address, have their learned addresses brought up to
    /// date, and are reflected so.
    pub fn neighbour(&self, ip: IpAddr, mac: Option<Vec<u8>>) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let changed = match mac {
            Some(mac) => state.neighbours.insert(ip, mac.clone()).as_ref() != Some(&mac),
            None => state.neighbours.remove(&ip).is_some(),
        };
        if changed {
            state.relearn_neighbours(Instant::now());
        }
    }

    /// Actively look for devices: ask what service types exist, browse each
    /// type for instances, and resolve every instance that has not yet said
    /// where it is (target and port). Three rounds, a few seconds in all,
    /// because each round's answers decide the next one's questions; the
    /// upkeep runs them as they come due, and the answers are handled as they
    /// arrive. How many questions it sent is kept under the number returned,
    /// once it is done ([`Segment::probed`]). One asked for while another is
    /// under way is that one.
    pub fn probe(&self) -> u64 {
        self.begin(None, "asked for", true)
    }

    /// How the probe numbered `id` went, if it is done, and has not been
    /// asked about before.
    pub fn probed(&self, id: u64) -> Option<Probed> {
        let mut state = self.state.borrow_mut();
        let at = state.probed.iter().position(|&(done, _)| done == id)?;
        state.probed.remove(at).map(|(_, result)| result)
    }

    /// Like [`Segment::probe`], with no one to tell but the journal: `why`
    /// says what it is for there.
    pub fn start_probe(&self, why: &'static str) {
        self.begin(None, why, false);
    }

    /// Probe on its own every `every`, the first one that long from now, as
    /// well as when asked; `None` (the default) does not.
    pub fn set_probe_interval(&self, every: Option<Duration>) {
        let mut state = self.state.borrow_mut();
        state.probe_interval = every;
        state.next_routine = every.and_then(|every| Instant::now().checked_add(every));
        drop(state);
    }

    /// Ask for the service types `kinds` by name, in three rounds like a
    /// [probe](Segment::probe): devices that only answer when asked for
    /// their type, and do not say what types they have, are found this way.
    /// The types are remembered, so that every later probe asks for them too.
    /// What is known here already goes along as known answers, so only what
    /// is new, or about to run out, answers.
    pub fn query_types(&self, kinds: &[String]) {
        self.begin(Some(kinds.to_vec()), "query for types", false);
    }

    /// Start a probe (`kinds` `None`) or a query for types, unless the same
    /// is under way already, which it then is; its number. How it went is
    /// kept if it was `asked` for. A segment that cannot send has nothing to
    /// do, and is done at once.
    fn begin(&self, kinds: Option<Vec<String>>, why: &'static str, asked: bool) -> u64 {
        let mut state = self.state.borrow_mut();
        if let Some(p) = state.probing.iter_mut().find(|p| p.kinds == kinds) {
            p.asked |= asked;
            return p.id;
        }
        state.probes_started += 1;
        let probing = Probing { kinds, why, id: state.probes_started, asked, round: 0, next: Instant::now(), sent: 0 };
        let id = probing.id;
        if state.outbound.is_empty() {
            drop(state);
            self.finish(probing, Ok(0));
        } else {
            state.probing.push(probing);
        }
        id
    }

    /// Run the rounds of the probes and queries that are due at `now`, and
    /// finish those whose last answers have had their time; start a routine
    /// probe if one is due.
    fn run_probes(&self, now: Instant) {
        let routine = {
            let mut state = self.state.borrow_mut();
            let due = state.next_routine.is_some_and(|at| at <= now);
            if due {
                state.next_routine = state.probe_interval.and_then(|every| now.checked_add(every));
            }
            due
        };
        if routine {
            self.begin(None, "periodic", false);
        }
        let due: Vec<(Option<Vec<String>>, usize)> = {
            let state = self.state.borrow_mut();
            state.probing.iter().filter(|p| p.next <= now).map(|p| (p.kinds.clone(), p.round)).collect()
        };
        for (kinds, round) in due {
            let ran = match (round < PROBE_GAPS.len(), &kinds) {
                (false, _) => None,
                (true, None) => Some(self.probe_round()),
                (true, Some(kinds)) => Some(self.query_types_round(kinds)),
            };
            let mut state = self.state.borrow_mut();
            let Some(at) = state.probing.iter().position(|p| p.kinds == kinds) else { continue };
            let p = &mut state.probing[at];
            let result = match ran {
                Some(Ok(sent)) => {
                    p.sent += sent;
                    p.next = now + PROBE_GAPS[round];
                    p.round += 1;
                    continue;
                }
                Some(Err(e)) => Err(format!("{e:#}")),
                None => Ok(p.sent),
            };
            let p = state.probing.remove(at);
            drop(state);
            self.finish(p, result);
        }
    }

    /// Keep how `probing` went for whoever asked for it, and tell the
    /// journal if it is worth a line. Only so many are kept: one never asked
    /// about, its asker gone, does not stay for ever.
    fn finish(&self, probing: Probing, result: Probed) {
        match (&result, probing.why) {
            (Ok(sent), "startup") => eprintln!("{}: startup probe sent {sent} queries", self.interface),
            (Ok(_), _) => {}
            (Err(e), why) => eprintln!("{}: {why} probe failed: {e}", self.interface),
        }
        if probing.asked {
            let mut state = self.state.borrow_mut();
            if state.probed.len() >= MAX_PROBED {
                state.probed.pop_front();
            }
            state.probed.push_back((probing.id, result));
        }
    }

    /// One round of queries, built from what is known right now. A no-op
    /// when the segment has no sender attached.
    fn probe_round(&self) -> Result<usize> {
        let state = self.state.borrow_mut();
        if state.outbound.is_empty() {
            return Ok(0);
        }

        let devices: Vec<Device> = state.discovered.values().map(|e| e.device.clone()).collect();
        ask(&state.outbound, &Device::probe_queries(&devices, &state.types, state.max_packet))
    }

    fn query_types_round(&self, kinds: &[String]) -> Result<usize> {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        if state.outbound.is_empty() {
            return Ok(0);
        }
        for kind in kinds.iter().filter(|k| is_type(k)) {
            if state.types.len() < MAX_TYPES {
                state.types.insert(kind.to_ascii_lowercase());
            }
        }
        let now = Instant::now();
        let devices: Vec<Device> = state.discovered.values().map(|e| e.device.clone()).collect();
        let known = |q: &Question| state.discovered.values().flat_map(|e| e.known_answers(q, now)).collect();
        ask(&state.outbound, &Device::type_queries(&devices, kinds, known, state.max_packet))
    }

    /// Ask the devices that are about to expire to answer again, so that a
    /// quiet one (most speakers only answer when asked) is renewed just before
    /// it would be dropped, instead of being found again later.
    ///
    /// A device is due once it would expire within `before` of `now`: its
    /// lifetime is the longest TTL it announced, at least the minimum lifetime
    /// ([`Segment::set_min_lifetime`]).
    /// It is asked for what it announced (its address, and the service and text
    /// records of each instance) and not for whole service types, so only it
    /// answers. A device that does not answer is asked again after a quarter of
    /// `before` (at least five seconds) until it expires. Devices known only by
    /// the address they were heard from have nothing to ask for and are left
    /// alone, and so is one whose time has already run out. Run by
    /// [`Segment::schedule`] when due, after [`Segment::expire`]; returns how
    /// many questions were sent.
    pub fn refresh(&self, now: Instant, before: Duration) -> Result<usize> {
        let mut guard = self.state.borrow_mut();
        let State { discovered, outbound, max_packet, .. } = &mut *guard;
        if outbound.is_empty() {
            return Ok(0);
        }
        let gap = refresh_gap(before);

        let mut asking = Vec::new();
        for entry in discovered.values_mut() {
            // Due when it, or one of its addresses, is about to run out. Not
            // what has already run out: it is about to be dropped. A margin
            // too long to add to a time reaches past every expiry.
            let soonest = entry.soonest();
            let due = soonest > now && now.checked_add(before).is_none_or(|limit| soonest <= limit);
            let recent = entry.refreshed.is_some_and(|t| now.saturating_duration_since(t) < gap);
            if !entry.askable() || !due || recent {
                continue;
            }
            entry.refreshed = Some(now);
            asking.push(entry.device.clone());
        }
        ask(outbound, &Device::refresh_queries(&asking, *max_packet))
    }

    /// Drop devices whose lifetime has run out as of `now`.
    pub fn expire(&self, now: Instant) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let stale: Vec<Key> = state
            .discovered
            .iter()
            .filter(|&(_, e)| e.expires <= now)
            .map(|(key, _)| key.clone())
            .collect();
        // Of the others, the addresses that ran out on their own.
        let mut lost = Vec::new();
        for (key, entry) in state.discovered.iter_mut().filter(|(key, _)| !stale.contains(key)) {
            if entry.expire_addrs(now) {
                lost.push(key.clone());
            }
        }
        if stale.is_empty() && lost.is_empty() {
            return;
        }
        for key in stale {
            if let Some(entry) = state.forget(&key) {
                state.notify(Event::Removed(entry.device));
            }
        }
        let discovered = &state.discovered;
        state.by_addr.retain(|addr, key| matches!(key, Key::Source(_)) || discovered.get(key).is_some_and(|e| e.device.has_addr(addr)));
        for key in lost {
            if let Some(device) = state.discovered.get(&key).map(|e| e.device.clone()) {
                state.notify(Event::Updated(device));
            }
        }
        // What they had here may be shown again. `now` may be ahead of the
        // clock, but what is announced is announced now.
        state.settle_all(Instant::now());
    }
}

fn host_key(name: &str) -> Key {
    Key::Host(name.to_ascii_lowercase())
}

/// The discovered devices an `apply` touched, as they were before, so that
/// what changed can be reported once, however many devices a packet affects.
#[derive(Default)]
struct Touched {
    order: Vec<Key>,
    before: HashMap<Key, Option<Device>>,
}

impl Touched {
    fn note(&mut self, discovered: &HashMap<Key, Entry>, key: &Key) {
        if !self.before.contains_key(key) {
            self.order.push(key.clone());
            self.before.insert(key.clone(), discovered.get(key).map(|e| e.device.clone()));
        }
    }

    fn events(self, discovered: &HashMap<Key, Entry>) -> Vec<Event> {
        let Touched { order, mut before } = self;
        let mut events = Vec::new();
        for key in order {
            let was = before.remove(&key).flatten();
            let now = discovered.get(&key).map(|e| e.device.clone());
            match (was, now) {
                (None, Some(now)) => events.push(Event::Added(now)),
                (Some(was), Some(now)) if was != now => events.push(Event::Updated(now)),
                (Some(was), None) => events.push(Event::Removed(was)),
                _ => {}
            }
        }
        events
    }
}

/// Ask `queries` of the device at link-local address `ll`, by unicast to its
/// port 5353 (RFC 6762 section 5.5), over the socket of its family: to send
/// it, the kernel has to look up its link-layer address, which is what this
/// is for. Failing to send is no matter: the next time will do.
fn nudge(outbound: &[Outbound], ll: IpAddr, queries: &[Message]) {
    let Some(out) = outbound.iter().find(|o| o.family == family_of(ll)) else { return };
    let dest = match (ll, out.dest) {
        (IpAddr::V6(ll), SocketAddr::V6(group)) => SocketAddr::V6(SocketAddrV6::new(ll, MDNS_PORT, 0, group.scope_id())),
        (ll, _) => SocketAddr::new(ll, MDNS_PORT),
    };
    for query in queries {
        if let Ok(bytes) = query.encode() {
            let _ = out.socket.send_to(&bytes, dest);
        }
    }
}

/// Multicast `queries`, over every family. Returns how many questions they
/// asked.
fn ask(outbound: &[Outbound], queries: &[Message]) -> Result<usize> {
    for q in queries {
        multicast(outbound, q)?;
    }
    Ok(queries.iter().map(|q| q.questions.len()).sum())
}

/// Announce `records`, over every family, in as many packets as it takes to
/// keep each within `limit`. Every packet is tried; the first error is
/// returned.
fn send(outbound: &[Outbound], limit: usize, records: &[Record]) -> Result<()> {
    let mut first_err = None;
    for msg in responses(records, &[], limit) {
        if let Err(e) = multicast(outbound, &msg) {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Send `msg` to the group of every family. Every family is tried; the
/// first error is returned. A no-op when the segment has no sender attached.
fn multicast(outbound: &[Outbound], msg: &Message) -> Result<()> {
    let bytes = msg.encode()?;
    let mut first_err = None;
    for out in outbound {
        if let Err(e) = out.socket.send_to(&bytes, out.dest) {
            first_err.get_or_insert(anyhow!(e).context(format!("sending to {}", out.dest)));
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Send `msg` over `family`: to its group, or to `dest` alone for a unicast
/// reply. Over another family's socket if there is none of `family` (a
/// segment is given one of each it serves, but tests may give it fewer). A
/// no-op when the segment has no sender attached.
fn transmit(outbound: &[Outbound], family: Family, msg: &Message, dest: Option<SocketAddr>) -> Result<()> {
    let Some(out) = outbound.iter().find(|o| o.family == family).or(outbound.first()) else {
        return Ok(());
    };
    let dest = dest.unwrap_or(out.dest);
    out.socket.send_to(&msg.encode()?, dest).with_context(|| format!("sending to {dest}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::device::{record, Service, LEGACY_TTL_CAP, QUESTIONS_PER_PACKET};
    use crate::parser::{self, rtype, Header};
    use crate::socket::{open, prefix};

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
        let seg = Segment::new("test", &[Family::V4]);
        let rx = seg.subscribe();
        seg.observe(ip("10.0.1.5"));
        seg.observe(ip("10.0.1.5"));
        assert_eq!(seg.devices().len(), 1);
        assert_eq!(rx.try_recv(), Ok(Event::Added(unnamed("10.0.1.5"))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expire_removes_and_notifies() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.observe(ip("10.0.1.5"));
        let rx = seg.subscribe();
        seg.expire(Instant::now());
        assert_eq!(seg.devices().len(), 1);
        seg.expire(Instant::now() + DEFAULT_MIN_LIFETIME + Duration::from_secs(1));
        assert!(seg.devices().is_empty());
        assert_eq!(rx.try_recv(), Ok(Event::Removed(unnamed("10.0.1.5"))));
    }

    /// A v4 segment whose "multicast group" is a local socket we can read.
    fn wired() -> (Segment, UdpSocket) {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seg = Segment::new("test", &[Family::V4]);
        seg.attach(Family::V4, tx, rx.local_addr().unwrap());
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
                .map(|i| Service {
                    instance: format!("{i}._http._tcp.local"),
                    kind: "_http._tcp.local".into(),
                    port: 8080,
                    target: None,
                    txt: vec!["a=b".into()],
                    ttl: 0,
                    ..Service::default()
                })
                .collect(),
            ttl: None,
            nsec: None,
            reverse: Vec::new(),
            ..Device::default()
        };
        device.add_addrs(&[ip(addr)]);
        device
    }

    #[test]
    fn manual_list_is_separate() {
        let seg = Segment::new("test", &[Family::V4]);
        let rx = seg.subscribe();
        assert!(seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap());
        assert!(!seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap());
        assert!(seg.devices().is_empty());
        assert!(rx.try_recv().is_err());
        assert_eq!(seg.manual_devices().len(), 1);
        assert!(seg.remove_manual(Owner::Own, "TV.local").unwrap(), "by hostname, ignoring case");
        assert!(!seg.remove_manual(Owner::Own, "tv.local").unwrap());
    }

    #[test]
    fn add_announces_and_remove_says_goodbye() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();

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

        // Identical re-add is a no-op on the wire.
        assert!(!seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap());
        assert!(recv(&rx).is_none());

        seg.remove_manual(Owner::Own, "tv.local").unwrap();
        let bye = recv(&rx).expect("goodbye");
        assert_eq!(bye.answers.len(), m.answers.len());
        assert!(bye.answers.iter().all(|r| r.ttl == 0));
        assert!(seg.manual_devices().is_empty());
    }

    #[test]
    fn replacing_sends_goodbye_for_dropped_services() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["A", "B"])).unwrap();
        recv(&rx).unwrap();

        seg.add_manual(Owner::Own, tv("10.0.1.9", &["A"])).unwrap();
        let m = recv(&rx).unwrap();
        let gone: Vec<_> = m.answers.iter().filter(|r| r.ttl == 0).collect();
        assert_eq!(gone.len(), 3); // PTR, SRV, TXT of "B"
        assert!(gone.iter().any(|r| r.data == RData::Ptr("B._http._tcp.local".into())));
        assert!(m.answers.iter().filter(|r| r.ttl != 0).count() >= 5);
    }

    #[test]
    fn a_hostname_two_owners_want_goes_to_the_lower_and_passes_to_the_next() {
        let (seg, rx) = wired();
        let (first, second) = (Owner::Reflector(0), Owner::Reflector(1));
        let has = |m: &Message, data: RData, live: bool| m.answers.iter().any(|r| r.data == data && (r.ttl > 0) == live);
        let a = |s: &str| RData::A(s.parse().unwrap());
        let b_ptr = || RData::Ptr("B._http._tcp.local".into());

        assert!(seg.add_manual(second, tv("10.0.1.9", &["A", "B"])).unwrap());
        recv(&rx).unwrap();

        // The lower owner takes over, and what it does not have is withdrawn.
        assert!(seg.add_manual(first, tv("10.0.2.9", &["A"])).unwrap());
        let m = recv(&rx).unwrap();
        assert!(has(&m, a("10.0.2.9"), true) && has(&m, a("10.0.1.9"), false) && has(&m, b_ptr(), false));
        assert_eq!(seg.manual_devices(), [tv("10.0.2.9", &["A"])]);

        // The outranked one changing is remembered, not sent.
        assert!(seg.add_manual(second, tv("10.0.1.10", &["A", "B"])).unwrap());
        assert!(recv(&rx).is_none());

        // When the winner goes, the next one is announced in its place.
        assert!(seg.remove_manual(first, "tv.local").unwrap());
        let m = recv(&rx).unwrap();
        assert!(has(&m, a("10.0.1.10"), true) && has(&m, a("10.0.2.9"), false) && has(&m, b_ptr(), true));
        assert_eq!(seg.manual_devices(), [tv("10.0.1.10", &["A", "B"])]);

        // An owner without a claim removes nothing; the last one says goodbye.
        assert!(!seg.remove_manual(first, "tv.local").unwrap());
        assert!(seg.remove_manual(second, "tv.local").unwrap());
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 0));
        assert!(seg.manual_devices().is_empty());
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

        seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["Kitchen", "Den"])).unwrap();
        assert!(!mentions_kitchen(&recv(&rx).unwrap()));
        assert_eq!(seg.manual_devices(), [tv("10.0.2.9", &["Den"])]);

        // Shown once the device here goes...
        seg.expire(Instant::now() + Duration::from_secs(36000));
        let m = recv(&rx).unwrap();
        assert!(m.answers.iter().any(|r| r.name == "Kitchen._http._tcp.local" && r.ttl > 0));
        assert_eq!(seg.manual_devices(), [tv("10.0.2.9", &["Kitchen", "Den"])]);

        // ...and left out again, without a goodbye, when it is back: that
        // would take back its records too.
        hear(&seg, "10.0.1.20", kitchen());
        assert!(!mentions_kitchen(&recv(&rx).unwrap()));
        assert_eq!(seg.manual_devices(), [tv("10.0.2.9", &["Den"])]);
    }

    /// A query with proposed records in its authority section is a device
    /// probing for a name: a reflected copy does not answer it, the
    /// advertised name does.
    #[test]
    fn a_device_probing_for_a_name_is_not_answered_with_a_copy() {
        let (seg, rx) = wired();
        let router = Device { hostname: Some("router.local".into()), addresses: vec![ip("10.0.1.1").into()], ..Device::default() };
        seg.add_manual(Owner::Own, router).unwrap();
        seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap();
        while recv(&rx).is_some() {}
        age(&seg, 2);
        let probe = |name: &str| {
            Message {
                header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
                questions: vec![parser::Question { name: name.into(), qtype: rtype::ANY, class: 1, unicast_response: false }],
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
    }

    /// A question is passed on for the reflector to ask elsewhere, marked
    /// with whether something announced here answers it; one that a device
    /// here owns the name of, or that a device asks while probing, is not.
    #[test]
    fn a_question_is_passed_on_marked_with_whether_it_is_answered_here() {
        let (seg, rx) = wired();
        let events = seg.subscribe();
        let mut copy = tv("10.0.2.9", &["TV"]);
        copy.nsec = Some(vec![rtype::A]);
        seg.add_manual(Owner::Reflector(0), copy).unwrap();
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
        assert_eq!(Segment::new("quiet", &[Family::V4]).query_question(&questions).unwrap(), 0);
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
            let tv = state.discovered.get_mut(&host_key("tv.local")).unwrap();
            tv.addr_expires.insert(ip("10.0.1.7"), now + Duration::from_secs(50));
            tv.expires = now + Duration::from_secs(70);
            let nas = state.discovered.get_mut(&host_key("nas.local")).unwrap();
            nas.expires = now;
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
        let types = seg.state.borrow_mut().types.clone();
        assert!(types.contains("_hue._tcp.local") && types.contains("_shelly._tcp.local") && !types.contains("bogus"));

        seg.probe_round().unwrap();
        let probed: Vec<String> = std::iter::from_fn(|| recv(&rx)).flat_map(|m| m.questions).map(|q| q.name).collect();
        assert!(probed.iter().any(|n| n == "_hue._tcp.local"), "{probed:?}");

        // Without a sender, nothing.
        assert_eq!(run_probe(&Segment::new("quiet", &[Family::V4]), Some(&kinds)).0, Ok(0));
    }

    /// A way to send over IPv4 that always fails: its group is an IPv6
    /// address, which an IPv4 socket refuses at once.
    fn broken() -> (UdpSocket, SocketAddr) {
        (UdpSocket::bind("127.0.0.1:0").unwrap(), "[::1]:5353".parse().unwrap())
    }

    /// Give `seg` a working way to send again, to `rx`.
    fn repair(seg: &Segment, rx: &UdpSocket) {
        seg.attach(Family::V4, UdpSocket::bind("127.0.0.1:0").unwrap(), rx.local_addr().unwrap());
    }

    fn retry_of(seg: &Segment, host: &str) -> Option<Instant> {
        seg.state.borrow_mut().manual[host].retry
    }

    /// A device that cannot be announced is not recorded, so that it is
    /// offered again and announced once sending works; one that cannot be
    /// replaced stays as it was announced.
    #[test]
    fn a_device_that_cannot_be_announced_is_not_recorded() {
        let (seg, rx) = wired();
        let (socket, dest) = broken();
        seg.attach(Family::V4, socket, dest);
        let err = seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap_err();
        assert!(format!("{err:#}").contains("sending to [::1]:5353"), "{err:#}");
        assert!(seg.manual_devices().is_empty());
        assert!(seg.state.borrow_mut().manual.is_empty(), "nothing left behind");

        repair(&seg, &rx);
        assert!(seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap());
        recv(&rx).unwrap();

        let (socket, dest) = broken();
        seg.attach(Family::V4, socket, dest);
        assert!(seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV", "Cast"])).is_err());
        let shown: Vec<String> = seg.manual_devices()[0].services.iter().map(|s| s.instance.clone()).collect();
        assert_eq!(shown, ["TV._http._tcp.local"], "still what was announced");
        // And it is what is recorded: offering it again changes nothing.
        assert!(!seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap());
    }

    /// A device whose goodbye cannot be sent is kept, so that withdrawing it
    /// is tried again, and goes out once sending works.
    #[test]
    fn a_device_that_cannot_be_withdrawn_is_kept() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap();
        recv(&rx).unwrap();

        let (socket, dest) = broken();
        seg.attach(Family::V4, socket, dest);
        assert!(seg.remove_manual(Owner::Reflector(0), "tv.local").is_err());
        assert_eq!(seg.manual_devices().len(), 1, "kept");

        repair(&seg, &rx);
        assert!(seg.remove_manual(Owner::Reflector(0), "tv.local").unwrap());
        let goodbye = recv(&rx).unwrap();
        assert!(!goodbye.answers.is_empty() && goodbye.answers.iter().all(|r| r.ttl == 0));
        assert!(seg.manual_devices().is_empty());
    }

    /// An announcement that fails is tried again after [`ANNOUNCE_RETRY`],
    /// and again after that while it still fails; once it goes out, the
    /// device is back on its usual schedule.
    #[test]
    fn an_announcement_that_fails_is_tried_again() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap();
        recv(&rx).unwrap();

        let (socket, dest) = broken();
        seg.attach(Family::V4, socket, dest);
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
        seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap();
        recv(&rx).unwrap();

        let (socket, dest) = broken();
        seg.attach(Family::V4, socket, dest);
        hear(&seg, "10.0.1.50", vec![a_record("tv.local", "10.0.1.50"), srv("Den._http._tcp.local", 80, "tv.local")]);
        let retry = retry_of(&seg, "tv.local").expect("to be tried again");
        assert_eq!(seg.manual_devices().len(), 1, "still shown: the goodbye did not go out");

        repair(&seg, &rx);
        seg.reannounce(retry).unwrap();
        let goodbye = recv(&rx).unwrap();
        assert!(goodbye.answers.iter().any(|r| r.data == RData::A("10.0.2.9".parse().unwrap()) && r.ttl == 0));
        assert!(seg.manual_devices().is_empty(), "given way");
        assert_eq!(retry_of(&seg, "tv.local"), None);
    }

    /// Every family is tried, whichever fails: the announcement goes out over
    /// the one that works, and the failure of the other is reported.
    #[test]
    fn every_family_is_tried_when_one_fails() {
        // The one that fails comes first, so the other is only tried if
        // sending goes on past a failure.
        let (_, rx) = wired();
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
        let (socket, dest) = broken();
        seg.attach(Family::V4, socket, dest);
        seg.attach(Family::V6, UdpSocket::bind("127.0.0.1:0").unwrap(), rx.local_addr().unwrap());
        let err = seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap_err();
        assert!(format!("{err:#}").contains("[::1]:5353"), "{err:#}");
        let sent = recv(&rx).expect("sent over the other family all the same");
        assert!(sent.answers.iter().any(|r| r.data == RData::A("10.0.2.9".parse().unwrap())));
    }

    /// A packet may hold what the MTU leaves once the IPv6 and UDP headers
    /// are added, but never less than plain DNS takes, nor more than mDNS
    /// allows.
    #[test]
    fn the_mtu_sets_what_a_packet_may_hold() {
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
            svc.txt = vec!["k=".to_string() + &"v".repeat(60)];
        }
        let expected = device.announcement(HOST_TTL, OTHER_TTL).len();
        seg.add_manual_ttl(Owner::Reflector(0), device, Duration::from_secs(HOST_TTL.into())).unwrap();

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
            seg.add_manual(Owner::Reflector(0), copy).unwrap();
        }
        packets();
        age(&seg, 2);

        seg.handle(sa("10.0.1.200"), &query("_http._tcp.local", rtype::PTR, vec![])).unwrap();
        within("a reply", packets());
        // Types with long names, so that size, not the count, splits a probe.
        seg.state.borrow_mut().types.extend((0..20).map(|i| format!("_{}{i}._tcp.local", "t".repeat(40))));
        seg.probe_round().unwrap();
        within("a probe", packets());
        // Every device due: a margin longer than any lifetime.
        seg.refresh(Instant::now(), Duration::from_secs(1_000_000)).unwrap();
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
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
        hear(&seg, "0.0.0.0", vec![aaaa("tv.local", "fe80::9"), srv("TV._http._tcp.local", 80, "tv.local")]);
        let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).expect("still heard of");
        assert_eq!(tv.addrs().collect::<Vec<_>>(), [ip("fe80::9")]);
        assert_eq!(tv.services.len(), 1);

        // A mere query from it makes no device of it.
        seg.handle(sa("0.0.0.0"), &query("tv.local", rtype::A, vec![])).unwrap();
        assert_eq!(seg.devices().len(), 1);
        assert!(!seg.state.borrow_mut().by_addr.contains_key(&ip("0.0.0.0")));
    }

    const MAC: [u8; 6] = [0x04, 0x09, 0x86, 0x43, 0xe3, 0xf6];

    /// A device that announced only a link-local IPv6 address is given the
    /// routable ones the neighbour table lists under its link-layer address,
    /// whichever comes first, and loses them with their entries.
    #[test]
    fn a_device_is_given_the_addresses_the_neighbour_table_has_for_it() {
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
        assert!(matches!(events.try_recv(), Ok(Event::Updated(d)) if d.has_addr(&ip("2001:db8:2::73"))));
        // A packet from a learned address is the device's.
        assert_eq!(seg.state.borrow_mut().by_addr.get(&ip("2001:db8:2::73")), Some(&host_key("speakers.local")));

        // An entry that goes takes its address with it.
        seg.neighbour(ip("2001:db8:2::73"), None);
        assert_eq!(learned(&seg), [ip("fd00:0:2::73")]);
        assert!(!seg.state.borrow_mut().by_addr.contains_key(&ip("2001:db8:2::73")));
        assert!(matches!(events.try_recv(), Ok(Event::Updated(_))));
        // The same entry again changes nothing, and says nothing.
        seg.neighbour(ip("fd00:0:2::73"), Some(MAC.to_vec()));
        assert!(events.try_recv().is_err());
    }

    /// A device that announced only IPv4 is found in the table by that, and
    /// given its IPv6 addresses: which of them are reflected is for each
    /// segment to say.
    #[test]
    fn a_device_is_found_in_the_neighbour_table_by_any_address_it_announced() {
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
    #[test]
    fn only_neighbour_addresses_on_the_interfaces_networks_are_learned() {
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
        assert!(!seg.state.borrow_mut().by_addr.contains_key(&ip("2001:db8:1::73")));

        // The interface moves to the other prefix: so do its devices.
        seg.set_prefixes(vec![prefix("10.0.2.0/24"), prefix("2001:db8:1::/64")]);
        assert_eq!(learned(&seg), [ip("2001:db8:1::73")]);
        assert!(!seg.state.borrow_mut().by_addr.contains_key(&ip("2001:db8:2::73")));
        // With no network known, nothing is.
        seg.set_prefixes(vec![]);
        assert_eq!(learned(&seg), Vec::<IpAddr>::new());
    }

    /// A device whose link-local address the table has not got, and that has
    /// no routable IPv6 address, is asked on it once, for the kernel to look
    /// up its link-layer address, and not again within NUDGE_GAP.
    #[test]
    fn a_device_unknown_to_the_neighbour_table_is_nudged_once() {
        let rx = UdpSocket::bind("[::1]:0").unwrap();
        let seg = Segment::new("test", &[Family::V6]);
        seg.attach(Family::V6, UdpSocket::bind("[::1]:0").unwrap(), rx.local_addr().unwrap());
        let nudged = |seg: &Segment| seg.state.borrow_mut().discovered[&host_key("speakers.local")].nudged;
        hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9")]);
        let first = nudged(&seg).expect("nudged");
        hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9")]);
        assert_eq!(nudged(&seg), Some(first), "not again so soon");

        // One with a routable IPv6 address is not.
        let seg = Segment::new("test", &[Family::V6]);
        seg.attach(Family::V6, UdpSocket::bind("[::1]:0").unwrap(), rx.local_addr().unwrap());
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
        let seg = Segment::new("test", &[Family::V6]);
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
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
        assert!(matches!(events.try_recv(), Ok(Event::Updated(d)) if d.addrs().eq([ip("fd00::7")])));
        assert!(!seg.state.borrow_mut().by_addr.contains_key(&ip("10.0.1.7")), "nor found by it");
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
    fn one_sender_may_describe_only_so_many_hosts() {
        let seg = Segment::new("test", &[Family::V4]);
        for i in 0..MAX_PER_SENDER + 10 {
            hear(&seg, "10.0.1.1", vec![a_record(&format!("h{i}.local"), &format!("10.0.2.{}", i % 250 + 1))]);
        }
        let named = |seg: &Segment| seg.devices().iter().filter(|d| d.hostname.is_some()).count();
        assert_eq!(named(&seg), MAX_PER_SENDER);

        hear(&seg, "10.0.1.2", vec![a_record("other.local", "10.0.1.2")]);
        assert_eq!(named(&seg), MAX_PER_SENDER + 1, "another sender is not held back");

        hear(&seg, "10.0.1.1", vec![a_record("h0.local", "10.0.3.3")]);
        let h0 = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("h0.local")).unwrap();
        assert_eq!(v4(&h0), Some(ip("10.0.3.3")), "what it described is kept up to date");
    }

    #[test]
    fn a_segment_remembers_only_so_many_devices() {
        let seg = Segment::new("test", &[Family::V4]);
        for i in 0..MAX_DEVICES + 20 {
            seg.observe(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32 + 1)));
        }
        assert_eq!(seg.devices().len(), MAX_DEVICES);
    }

    /// A host that announced only an address no one can be reached at is not
    /// given the address the packet came from instead.
    #[test]
    fn a_host_with_only_unusable_addresses_is_not_given_the_senders() {
        let seg = Segment::new("test", &[Family::V4]);
        hear(&seg, "10.0.1.7", vec![a_record("tv.local", "0.0.0.0"), srv("TV._http._tcp.local", 80, "tv.local")]);
        let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        assert_eq!((v4(&tv), ll4(&tv)), (None, None));

        // One that announced none at all still is: it is the sender.
        hear(&seg, "10.0.1.8", vec![srv("NAS._smb._tcp.local", 445, "nas.local")]);
        let nas = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("nas.local")).unwrap();
        assert_eq!(v4(&nas), Some(ip("10.0.1.8")));
    }

    /// The sender is credited with its address in the family it sent over:
    /// a host that announced only IPv4 addresses is still the sender of a
    /// packet over IPv6, but one that announced an unusable address of the
    /// family is not made good with the sender's.
    #[test]
    fn the_sender_is_credited_in_the_family_it_sent_over() {
        let seg = Segment::new("test", &[Family::V6]);
        hear(&seg, "fe80::7", vec![a_record("tv.local", "10.0.1.7"), srv("TV._http._tcp.local", 80, "tv.local")]);
        let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        assert_eq!(v4(&tv), Some(ip("10.0.1.7")));
        assert_eq!(ll6(&tv), Some(ip("fe80::7")), "the sender, over IPv6");

        let seg = Segment::new("test", &[Family::V4]);
        hear(&seg, "10.0.1.8", vec![a_record("nas.local", "0.0.0.0"), aaaa("nas.local", "fd00::8")]);
        let nas = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        assert_eq!((v4(&nas), v6(&nas)), (None, Some(ip("fd00::8"))));
    }

    /// A device that says goodbye to the temporary address it sends from,
    /// announcing the next in the same packet, is not leaving: it only gives
    /// up the one. Saying goodbye with nothing in its place, it is.
    #[test]
    fn giving_up_a_temporary_address_is_not_leaving() {
        let seg = Segment::new("test", &[Family::V6]);
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
            let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
        seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap();
        recv(&rx).unwrap();
        repeat(&seg, &rx);
        events.try_iter().count();

        // Gone: the devices heard on it are forgotten, what it announces kept.
        seg.detach_all();
        seg.forget_discovered();
        assert!(seg.devices().is_empty());
        assert!(matches!(events.try_recv(), Ok(Event::Removed(d)) if d.hostname.as_deref() == Some("nas.local")));
        assert_eq!(seg.manual_devices().len(), 1);
        seg.announce_all().unwrap();
        assert!(recv(&rx).is_none(), "nothing goes out without a socket");

        // Back: a new socket, and everything announced again.
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        seg.attach(Family::V4, tx, rx.local_addr().unwrap());
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
        assert!(seg.add_manual(Owner::Own, nameless).is_err());
        assert!(seg.manual_devices().is_empty());
        assert!(recv(&rx).is_none());
    }


    fn query(name: &str, qtype: u16, known: Vec<Record>) -> Vec<u8> {
        Message {
            header: Header { id: 0x4242, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
            questions: vec![parser::Question { name: name.into(), qtype, class: 1, unicast_response: false }],
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
        for m in state.manual.values_mut() {
            m.announced -= Duration::from_secs(secs);
            m.last_sent.v4 -= Duration::from_secs(secs);
            m.last_sent.v6 -= Duration::from_secs(secs);
        }
    }

    #[test]
    fn answers_ptr_query_with_additionals() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
        let first = recv(&rx).unwrap();
        seg.reannounce(Instant::now()).unwrap();
        assert!(recv(&rx).is_none(), "not within the second");

        let again = repeat(&seg, &rx);
        assert_eq!(again.answers.len(), first.answers.len());
        assert!(again.answers.iter().all(|r| r.ttl > 0));

        // Unchanged, it is not announced again, however long it waits.
        assert_eq!(seg.state.borrow_mut().manual["tv.local"].reannounce_at(false), None);
        seg.reannounce(Instant::now() + Duration::from_secs(100_000)).unwrap();
        assert!(recv(&rx).is_none());
        assert!(seg.pending().iter().all(|p| p.what != "re-announce"));

        // A change is, twice again.
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV", "Other TV"])).unwrap();
        assert!(recv(&rx).is_some());
        repeat(&seg, &rx);
        seg.reannounce(Instant::now() + Duration::from_secs(100_000)).unwrap();
        assert!(recv(&rx).is_none());
    }

    #[test]
    fn a_segment_that_reannounces_keeps_unchanged_devices_up_at_80_percent_of_their_ttl() {
        let (seg, rx) = wired();
        seg.set_reannounce(true);
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
        let first = recv(&rx).unwrap();
        repeat(&seg, &rx);

        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
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
        let at = seg.state.borrow_mut().manual["tv.local"].announced + ANNOUNCE_REPEAT;
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

        // Once the instance says where it is, it is no longer asked about.
        hear(&seg, "10.0.2.73", vec![record(
            "Speaker._airplay._tcp.local".into(),
            true,
            120,
            RData::Srv { priority: 0, weight: 0, port: 7000, target: "speaker.local".into() },
        )]);
        seg.probe_round().unwrap();
        assert_eq!(
            asked(&recv(&rx).unwrap()),
            BTreeSet::from([q(META_QUERY, rtype::PTR), q("_airplay._tcp.local", rtype::PTR)])
        );
        // ...and that is what makes it reflectable.
        assert_eq!(seg.devices()[0].hostname.as_deref(), Some("speaker.local"));
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
        let seg = Segment::new("test", &[Family::V4]);
        let id = seg.probe();
        assert_eq!(seg.probed(id), Some(Ok(0)), "done at once");
        assert_eq!(seg.probed(id), None, "taken");
    }

    #[test]
    fn learned_types_are_capped() {
        let seg = Segment::new("test", &[Family::V4]);
        let ptrs = (0..MAX_TYPES + 50)
            .map(|i| record(META_QUERY.into(), false, 4500, RData::Ptr(format!("_t{i}._tcp.local"))))
            .collect();
        hear(&seg, "10.0.2.73", ptrs);
        assert_eq!(seg.state.borrow_mut().types.len(), MAX_TYPES);
    }

    /// `router.local` is advertised as a reflected device that has a hostname
    /// and an address but no services.
    #[test]
    fn a_device_without_services_can_be_advertised() {
        let (seg, rx) = wired();
        let router = Device {
            hostname: Some("router.local".into()),
            addresses: vec![ip("10.0.1.1").into()],
            ..Device::default()
        };
        seg.add_manual(Owner::Own, router).unwrap();

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
        seg.remove_manual(Owner::Own, "router.local").unwrap();
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 0));
    }

    /// A segment over both families, each with a local socket for a group.
    fn wired_both() -> (Segment, UdpSocket, UdpSocket) {
        let (_, rx4) = wired();
        let (_, rx6) = wired_family(Family::V6);
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
        seg.attach(Family::V4, UdpSocket::bind("127.0.0.1:0").unwrap(), rx4.local_addr().unwrap());
        seg.attach(Family::V6, UdpSocket::bind("127.0.0.1:0").unwrap(), rx6.local_addr().unwrap());
        (seg, rx4, rx6)
    }

    /// A device heard over IPv4 and over IPv6 is one device, with the
    /// addresses of both.
    #[test]
    fn a_segment_over_both_families_keeps_one_list() {
        let seg = Segment::new("test", &[Family::V4, Family::V6]);
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
        seg.add_manual(Owner::Own, both).unwrap();
        assert!(recv(&rx4).is_some() && recv(&rx6).is_some(), "announced over both");

        age(&seg, 2);
        seg.handle(sa("10.0.1.50"), &query("tv.local", rtype::A, vec![])).unwrap();
        let m = recv(&rx4).expect("answered over IPv4");
        assert!(recv(&rx6).is_none(), "and over IPv4 only");
        assert!(m.additionals.iter().any(|r| r.data == RData::Aaaa("fd00::9".parse().unwrap())), "{:?}", m.additionals);

        // Just answered over IPv4, it may still answer over IPv6.
        seg.handle(sa("fe80::50"), &query("tv.local", rtype::AAAA, vec![])).unwrap();
        assert!(recv(&rx6).is_some(), "answered over IPv6");
        assert!(recv(&rx4).is_none());
        // But not over IPv4 again just yet.
        seg.handle(sa("10.0.1.51"), &query("tv.local", rtype::A, vec![])).unwrap();
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
        let seg = Segment::new("test", &[family]);
        seg.attach(family, tx, rx.local_addr().unwrap());
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
        let seg = Segment::new("test", &[Family::V4]);
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
        assert_eq!((devices[0].services[0].port, devices[0].services[0].target.as_deref()), (7000, Some("speaker.local")));

        let kinds: Vec<&str> = rx
            .try_iter()
            .map(|e| match e {
                Event::Added(d) if d.hostname.is_none() => "added unnamed",
                Event::Removed(d) if d.hostname.is_none() => "removed unnamed",
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
        let seg = Segment::new("test", &[Family::V4]);
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
        let seg = Segment::new("test", &[Family::V4]);
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
            let seg = Segment::new("test", &[Family::V4]);
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
            addresses: vec![ip("fe80::1").into()],
            ..Device::default()
        };
        seg.add_manual(Owner::Own, router).unwrap();
        let m = recv(&rx).unwrap();
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].data, RData::Aaaa("fe80::1".parse().unwrap()));
    }

    #[test]
    fn replacing_a_device_withdraws_the_addresses_it_no_longer_has() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
        recv(&rx).unwrap();

        seg.add_manual(Owner::Own, tv("10.0.1.10", &["TV"])).unwrap();
        let m = recv(&rx).unwrap();
        let ttl_of = |a: &str| m.answers.iter().find(|r| r.data == RData::A(a.parse().unwrap())).map(|r| r.ttl);
        assert_eq!((ttl_of("10.0.1.9"), ttl_of("10.0.1.10")), (Some(0), Some(HOST_TTL)));
        assert_eq!(seg.manual_devices().len(), 1, "same hostname, so it replaced the device");
    }

    #[test]
    fn add_rejects_a_device_with_no_addresses() {
        let (seg, rx) = wired();
        let mut none = tv("10.0.1.9", &["TV"]);
        none.addresses.clear();
        assert!(seg.add_manual(Owner::Own, none).is_err());
        assert!(seg.manual_devices().is_empty());
        assert!(recv(&rx).is_none());
    }

    /// Records do not belong to the transport they go out on: an IPv4
    /// segment announces a device's IPv6 addresses too, in the same packet.
    #[test]
    fn a_device_is_announced_with_the_addresses_of_both_families() {
        let (seg, rx) = wired();
        let mut both = tv("10.0.1.9", &["TV"]);
        both.add_addrs(&[ip("fd00::9"), ip("fe80::9")]);
        seg.add_manual(Owner::Own, both).unwrap();
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
        let seg = Segment::new("test", &[Family::V4]);
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
        let names: Vec<&str> = tv.services.iter().map(|s| s.instance.as_str()).collect();
        assert_eq!(names, ["OZAL TV._airplay._tcp.local"]);
        assert_eq!(tv.services[0].txt, ["model=TV"]);
        assert_eq!(v4(tv), None, "no address was announced, and the sender is not credited with one");

        let speaker = find(&devices, "OZAL-Speakers.local");
        let names: Vec<&str> = speaker.services.iter().map(|s| s.instance.as_str()).collect();
        assert_eq!(names, ["OZAL Speakers._airplay._tcp.local"]);
        assert_eq!(speaker.services[0].txt, ["model=RX"]);
        assert_eq!(v4(speaker), Some(ip("10.0.2.73")));

        assert_eq!(rx.try_iter().filter(|e| matches!(e, Event::Added(d) if d.hostname.is_some())).count(), 2);
    }

    #[test]
    fn the_only_host_a_packet_describes_is_the_sender_when_it_announces_no_address() {
        let seg = Segment::new("test", &[Family::V4]);
        hear(&seg, "10.0.1.9", vec![srv("Dev._http._tcp.local", 80, "dev.local")]);
        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!((devices[0].hostname.as_deref(), v4(&devices[0])), (Some("dev.local"), Some(ip("10.0.1.9"))));
    }

    /// A bare browse answer leaves unresolved instances on the sender. Once a
    /// later packet resolves them to their hosts they are not kept twice.
    #[test]
    fn resolved_instances_leave_the_unresolved_copy_behind() {
        let seg = Segment::new("test", &[Family::V4]);
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
        let entry = state.discovered.get_mut(&host_key(host)).expect("no such device");
        entry.expires = at;
        for expiry in entry.addr_expires.values_mut() {
            *expiry = at;
        }
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
        let seg = Segment::new("test", &[Family::V4]);
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
        assert_eq!(seg.refresh(t0 + DEFAULT_MIN_LIFETIME - before + Duration::from_secs(1), before).unwrap(), 3);
        assert!(recv(&rx).is_some());

        // And without an answer it is dropped when the floor ends, not before.
        seg.expire(t0 + Duration::from_secs(250));
        assert_eq!(seg.devices().len(), 1);
        seg.expire(t0 + DEFAULT_MIN_LIFETIME + Duration::from_secs(1));
        assert!(seg.devices().is_empty());
    }

    /// The other extreme: a margin longer than any lifetime makes every device
    /// due all the time. It must not turn into a flood.
    #[test]
    fn a_margin_longer_than_the_lifetime_asks_at_a_steady_rate_not_constantly() {
        let (seg, rx) = wired();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        let t0 = Instant::now();
        let before = Duration::from_secs(600); // longer than the 300 s floor; the retry gap is 150 s

        assert_eq!(seg.refresh(t0, before).unwrap(), 3, "due from the start");
        recv(&rx).unwrap();
        for secs in [1, 10, 100, 149] {
            assert_eq!(seg.refresh(t0 + Duration::from_secs(secs), before).unwrap(), 0, "{secs}s");
        }
        assert!(recv(&rx).is_none());
        assert_eq!(seg.refresh(t0 + Duration::from_secs(150), before).unwrap(), 3, "then once per gap");
    }

    #[test]
    fn refresh_does_not_ask_a_device_whose_time_has_already_run_out() {
        let (seg, rx) = wired();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        let t0 = Instant::now();
        let before = Duration::from_secs(30);

        // Still alive just before the end: asked. Past the end, but not yet
        // dropped (the next expiry pass has not run): not asked.
        assert_eq!(seg.refresh(t0 + DEFAULT_MIN_LIFETIME - Duration::from_secs(5), before).unwrap(), 3);
        recv(&rx).unwrap();
        assert_eq!(seg.refresh(t0 + DEFAULT_MIN_LIFETIME + Duration::from_secs(10), before).unwrap(), 0);
        assert!(recv(&rx).is_none());
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
        let seg = Segment::new("test", &[Family::V4]);
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 290));
        assert!(!alive_after(&seg, 301));

        // A shorter floor lets that device go sooner...
        let seg = Segment::new("test", &[Family::V4]);
        seg.set_min_lifetime(Duration::from_secs(60));
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 50));
        assert!(!alive_after(&seg, 61));

        // ...a longer one keeps it longer...
        let seg = Segment::new("test", &[Family::V4]);
        seg.set_min_lifetime(Duration::from_secs(900));
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 890));
        assert!(!alive_after(&seg, 901));

        // ...and zero means no floor: it lives for exactly its TTL.
        let seg = Segment::new("test", &[Family::V4]);
        seg.set_min_lifetime(Duration::ZERO);
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 8));
        assert!(!alive_after(&seg, 11));
    }

    #[test]
    fn a_ttl_longer_than_the_floor_still_wins() {
        let seg = Segment::new("test", &[Family::V4]);
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
        assert_eq!(seg.refresh(t0 + Duration::from_secs(72), before).unwrap(), 3, "within 30 s of it");
        assert!(recv(&rx).is_some());
    }

    // The timer-driven upkeep.

    fn expiry_of(seg: &Segment, host: &str) -> Instant {
        seg.state.borrow_mut().discovered[&host_key(host)].expires
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
        seg.add_manual(Owner::Own, tv("10.0.9.9", &["TV"])).unwrap();
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)).min(Some(announced + ANNOUNCE_REPEAT)));
        seg.state.borrow_mut().manual.get_mut("tv.local").unwrap().retry = Some(announced + Duration::from_secs(500));
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)));
    }

    #[test]
    fn pending_lists_everything_the_upkeep_waits_for_soonest_first() {
        let (seg, _rx) = wired();
        seg.set_refresh_before(Some(Duration::from_secs(60)));
        assert!(seg.pending().is_empty());

        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        seg.observe(ip("10.0.1.99")); // heard, but never named
        seg.add_manual(Owner::Own, tv("10.0.9.9", &["TV"])).unwrap();

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
        seg.add_manual(Owner::Reflector(0), mixed).unwrap();
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
        seg.add_manual_ttl(Owner::Own, tv("10.0.1.1", &[]), Duration::from_secs(1000)).unwrap();
        let first = recv(&rx).unwrap();
        assert!(first.answers.iter().all(|r| r.ttl == 1000));
        assert!(repeat(&seg, &rx).answers.iter().all(|r| r.ttl == 1000));
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        assert_eq!(seg.state.borrow_mut().manual["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(800)));

        // Queries are answered with it too.
        age(&seg, 2);
        seg.handle(sa("10.0.1.50"), &query("tv.local", rtype::A, vec![])).unwrap();
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 1000));

        // Not yet at 799 s; again at 800, with the same TTL.
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        seg.reannounce(announced + Duration::from_secs(799)).unwrap();
        assert!(recv(&rx).is_none());
        seg.reannounce(announced + Duration::from_secs(800)).unwrap();
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 1000));

        // The usual way is unchanged, and a TTL of zero (a goodbye) is refused.
        let (usual, rx) = wired();
        usual.add_manual(Owner::Own, tv("10.0.1.1", &[])).unwrap();
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == HOST_TTL || r.ttl == OTHER_TTL));
        assert!(usual.add_manual_ttl(Owner::Own, tv("10.0.1.2", &[]), Duration::from_millis(900)).is_err());
    }

    /// `tv.local` as it announced itself: an address with `addr` seconds, and a
    /// service with `svc` (0: not known).
    fn tv_with_ttls(addr: Option<u32>, svc: u32) -> Device {
        let mut device = tv("10.0.1.1", &["TV"]);
        device.ttl = addr;
        device.services[0].ttl = svc;
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
        seg.add_manual(Owner::Own, tv_with_ttls(Some(300), 600)).unwrap();
        let ttls = announced_ttls(&rx);
        assert!(ttls.contains(&(true, 300)), "{ttls:?}");
        assert!(ttls.iter().filter(|(is_addr, _)| !is_addr).all(|(_, ttl)| *ttl == 600), "{ttls:?}");

        // It is announced again before the shortest of them runs out: 80% of 300.
        repeat(&seg, &rx);
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        assert_eq!(seg.state.borrow_mut().manual["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(240)));
    }

    #[test]
    fn a_short_service_ttl_brings_the_reannouncement_forward() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv_with_ttls(Some(300), 50)).unwrap();
        assert!(announced_ttls(&rx).contains(&(false, 50)));
        repeat(&seg, &rx);
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        assert_eq!(seg.state.borrow_mut().manual["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(40)));
    }

    #[test]
    fn what_a_device_did_not_say_gets_the_usual_ttl_and_tiny_ones_are_raised() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv_with_ttls(None, 0)).unwrap();
        let ttls = announced_ttls(&rx);
        assert!(ttls.contains(&(true, HOST_TTL)) && ttls.contains(&(false, OTHER_TTL)), "{ttls:?}");

        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv_with_ttls(Some(2), 3)).unwrap();
        let ttls = announced_ttls(&rx);
        assert!(ttls.iter().all(|(_, ttl)| *ttl == MIN_REFLECT_TTL), "{ttls:?}");
    }

    #[test]
    fn a_given_address_ttl_wins_for_the_address_only() {
        let (seg, rx) = wired();
        seg.add_manual_ttl(Owner::Own, tv_with_ttls(Some(300), 600), Duration::from_secs(900)).unwrap();
        let ttls = announced_ttls(&rx);
        assert!(ttls.contains(&(true, 900)), "{ttls:?}");
        assert!(ttls.iter().filter(|(is_addr, _)| !is_addr).all(|(_, ttl)| *ttl == 600), "{ttls:?}");
        // The services run out first, and it is announced again before that.
        repeat(&seg, &rx);
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        assert_eq!(seg.state.borrow_mut().manual["tv.local"].reannounce_at(true), Some(announced + Duration::from_secs(480)));
    }

    #[test]
    fn a_device_known_only_by_address_has_announced_no_ttls() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.observe(ip("10.0.1.99"));
        let bare = seg.devices().remove(0);
        assert_eq!((bare.ttl, bare.services.len()), (None, 0));
    }

    #[test]
    fn a_segment_that_cannot_send_has_nothing_to_refresh() {
        let seg = Segment::new("test", &[Family::V4]);
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
        // Everything is within that margin of its expiry, so it is asked...
        assert!(next_due(&seg).unwrap() <= Instant::now() + Duration::from_millis(50));
        assert!(seg.refresh(Instant::now(), Duration::MAX).unwrap() > 0);
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
        seg.set_refresh_before(Some(Duration::from_millis(300)));
        let events = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

        let start = Instant::now();
        let expires = start + Duration::from_millis(500);
        set_expiry(&seg, "printer.local", expires);
        assert_eq!(seg.next_due(), Some(start + Duration::from_millis(200)));
        seg.upkeep(start + Duration::from_millis(200));
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
        assert_eq!(seg.lifetime_left(&device), DEFAULT_MIN_LIFETIME);

        // One that is gone has no time left, and neither has a stranger.
        seg.expire(Instant::now() + Duration::from_secs(3600));
        assert_eq!(seg.lifetime_left(&device), Duration::ZERO);
        assert_eq!(seg.lifetime_left(&unnamed("10.9.9.9")), Duration::ZERO);
    }

    #[test]
    fn events_wait_to_be_taken() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.observe(ip("10.0.1.5"));
        seg.observe(ip("10.0.1.6"));
        assert_eq!(seg.take_events().len(), 2);
        assert!(seg.take_events().is_empty(), "taken");
        assert!(seg.is(&seg.clone()) && !seg.is(&Segment::new("test", &[Family::V4])));
    }

    /// Service types learned from the enumeration are one per type, whatever
    /// their case.
    #[test]
    fn service_types_are_learned_once_whatever_their_case() {
        let seg = Segment::new("test", &[Family::V4]);
        let meta = |kind: &str| ptr("_services._dns-sd._udp.local", kind);
        hear(&seg, "10.0.1.7", vec![meta("_http._tcp.local"), meta("_HTTP._tcp.LOCAL")]);
        assert_eq!(seg.state.borrow_mut().types.len(), 1);
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
        copy.nsec = Some(vec![rtype::A]);
        seg.add_manual(Owner::Reflector(0), copy).unwrap();
        recv(&rx).unwrap();

        hear(&seg, "10.0.1.5", vec![a_record("tv.local", "10.0.1.5"), nsec("tv.local", &[rtype::A])]);
        let bye = recv(&rx).unwrap();
        assert_eq!(bye.answers.len(), 1, "{:?}", bye.answers);
        assert_eq!((&bye.answers[0].data, bye.answers[0].ttl), (&RData::A("10.0.2.9".parse().unwrap()), 0));
    }

    #[test]
    fn ingest_fills_in_hostname_and_services() {
        let seg = Segment::new("test", &[Family::V4]);
        let rx = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        let d = &devices[0];
        assert_eq!(d.hostname.as_deref(), Some("printer.local"));
        assert_eq!(d.services.len(), 1);
        let s = &d.services[0];
        assert_eq!(s.instance, "Printer._http._tcp.local");
        assert_eq!(s.kind, "_http._tcp.local");
        assert_eq!((s.port, s.target.as_deref()), (631, Some("printer.local")));
        assert_eq!(s.txt, ["ty=hp"]);

        assert!(matches!(rx.try_recv(), Ok(Event::Added(_))));
        assert!(rx.try_recv().is_err());

        // Same data again is not a change.
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn later_packet_updates_and_ttl0_removes_service() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.observe(ip("10.0.1.7"));
        let rx = seg.subscribe();

        // The device heard only by address now says who it is.
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Event::Removed(d)) if d.hostname.is_none()));
        assert!(matches!(rx.try_recv(), Ok(Event::Added(d)) if d.hostname.is_some() && d.services.len() == 1));

        // Goodbye for the service records only (no address record).
        let mut p = response(1);
        let mut ptr = vec![7];
        ptr.extend(b"Printer");
        ptr.extend(labels(&["_http", "_tcp", "local"]));
        rr(&mut p, &["_http", "_tcp", "local"], 12, 0, &ptr);
        seg.handle(sa("10.0.1.7"), &p).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Event::Updated(d)) if d.services.is_empty()));
        assert_eq!(seg.devices().len(), 1);
    }

    #[test]
    fn address_goodbye_removes_device() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        let rx = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(0)).unwrap();
        assert!(seg.devices().is_empty());
        assert!(matches!(rx.try_recv(), Ok(Event::Removed(_))));
    }

    #[test]
    fn long_ttl_extends_lifetime() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.handle(sa("10.0.1.7"), &announcement(4500)).unwrap();
        seg.expire(Instant::now() + DEFAULT_MIN_LIFETIME + Duration::from_secs(1));
        assert_eq!(seg.devices().len(), 1);
        seg.expire(Instant::now() + Duration::from_secs(4501));
        assert!(seg.devices().is_empty());
    }

    #[test]
    fn garbage_still_counts_as_alive() {
        let seg = Segment::new("test", &[Family::V4]);
        seg.handle(sa("10.0.1.5"), b"\xff\xff not dns").unwrap();
        assert_eq!(seg.devices().len(), 1);
    }

    #[test]
    fn query_records_are_ignored() {
        let seg = Segment::new("test", &[Family::V4]);
        let mut p = announcement(120);
        p[2] = 0x00; // clear QR: a query carrying known answers
        seg.handle(sa("10.0.1.8"), &p).unwrap();
        let d = &seg.devices()[0];
        assert!(d.hostname.is_none() && d.services.is_empty());
    }

    /// Manual check of the real send path: `MDNS_TEST_IFACE=br cargo test
    /// live_announce -- --ignored --nocapture`, with a listener on the group.
    #[test]
    #[ignore]
    fn live_announce() {
        let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
        for family in [Family::V4, Family::V6] {
            let sock = open(&iface, family).unwrap();
            // Let a listener on this same host hear it.
            match family {
                Family::V4 => sock.socket.set_multicast_loop_v4(true).unwrap(),
                Family::V6 => sock.socket.set_multicast_loop_v6(true).unwrap(),
            }
            let seg = Segment::new(&iface, &[family]);
            let (tx, dest) = sock.sender().unwrap();
            seg.attach(family, tx, dest);
            let addr = match family {
                Family::V4 => ip("10.9.9.9"),
                Family::V6 => ip("fd00::9"),
            };
            seg.add_manual(Owner::Own, tv(&addr.to_string(), &["LiveTV"])).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            seg.remove_manual(Owner::Own, "tv.local").unwrap();
        }
    }

    /// Manual check of query handling over the real network: announces a
    /// device on `MDNS_TEST_IFACE` (IPv4), then answers queries for 4s.
    #[test]
    #[ignore]
    fn live_respond() {
        let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
        let sock = open(&iface, Family::V4).unwrap();
        sock.socket.set_multicast_loop_v4(true).unwrap();
        let seg = Segment::new(&iface, &[Family::V4]);
        let (tx, dest) = sock.sender().unwrap();
        seg.attach(Family::V4, tx, dest);
        seg.add_manual(Owner::Own, tv("10.9.9.9", &["LiveTV"])).unwrap();
        age(&seg, 2);

        let udp: UdpSocket = sock.socket.try_clone().unwrap().into();
        udp.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let end = Instant::now() + Duration::from_secs(4);
        let mut buf = [0u8; 9000];
        while Instant::now() < end {
            if let Ok((n, from)) = udp.recv_from(&mut buf) {
                seg.handle(from, &buf[..n]).unwrap();
            }
        }
    }
}
