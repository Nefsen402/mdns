//! The devices on one interface, and what the daemon says and asks there.
//!
//! A [`Segment`] keeps a model of the link rather than its packets: the
//! devices heard on it, with their addresses and services, the ones put there
//! by hand or reflected from elsewhere, and the claims on their names. It
//! answers for them, announces, probes and refreshes them, and forgets them
//! as they expire, sending through the [`socket`](crate::socket)s attached to
//! it.

use core::fmt;
use alloc::collections::{BTreeSet, VecDeque};

use hashbrown::{DefaultHashBuilder, HashMap};
use core::net::{IpAddr, SocketAddr, SocketAddrV6};

use core::cell::RefCell;
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::time::Duration;

use crate::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

use crate::config::AdvertiseConfig;
use crate::runtime::Why;
use crate::device::{
    family_of, is_link_local, is_type, responses, service_ttl, Device, Service,
    DEFAULT_MAX_PACKET, HOST_TTL, MIN_REFLECT_TTL, OTHER_TTL,
};
use crate::socket::{Family, Prefix, Sender, MDNS_PORT};
use crate::parser::{Message, Question, Record};

use crate::prelude::*;

use crate::table::{hash_name, Id, Multi, Table};
use crate::tracker::{refresh_gap, Touched, Tracker, MAX_TYPES};

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

/// A record may not be multicast more than once a second (RFC 6762 section 6).
const MIN_MULTICAST_GAP: Duration = Duration::from_secs(1);

/// A question put to a segment on another's behalf is not put to it again
/// within this long: clients ask again after a second, and several ask alike.
const FORWARD_GAP: Duration = Duration::from_secs(1);

/// Questions remembered per segment as just put to it, so that a client
/// asking endless made-up names cannot grow the list without bound.
const MAX_FORWARDED: usize = 1024;

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

pub use crate::tracker::Event;

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

/// "`who` `addr`", written only when it is shown: the deadlines are walked
/// every time the loop wakes, and almost none of them is ever printed.
struct Labelled<'a>(&'a dyn fmt::Display, &'a IpAddr);

impl fmt::Display for Labelled<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.1)
    }
}

/// A way to send over one family: a socket, and the group to send to.
struct Outbound {
    family: Family,
    socket: Sender,
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
/// hostname announced there: reflectors that share the interface, which show
/// it together if it is of the same segment, and a reflected device named like
/// the advertised one, which loses to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    /// The daemon's own name (`[Advertise]`), which always wins.
    Own,
    /// A reflector, by where its segment is in the config.
    Reflector(u32),
}

/// One owner's wish to have a device announced.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Claim {
    /// A device made for it, announced as it is, with the TTL of its address.
    Owned { device: Box<Device>, host_ttl: u32 },
    /// A device of another segment, as it is to be shown here, with the TTL
    /// of its address `host_ttl` if given, or else its own.
    Reflected { device: Rc<Device>, host_ttl: Option<u32> },
}

impl Claim {
    /// The device as it is to be announced, and the TTL of its address.
    fn resolve(&self) -> (Device, u32) {
        match self {
            Claim::Owned { device, host_ttl } => ((**device).clone(), *host_ttl),
            Claim::Reflected { device, host_ttl } => {
                let ttl = host_ttl.unwrap_or_else(|| device.ttl.map_or(HOST_TTL, |ttl| ttl.max(MIN_REFLECT_TTL)));
                ((**device).clone(), ttl)
            }
        }
    }
}

/// What a claim is of: whose it is, and, if it is a device of another
/// segment, which segment, by its interface. Those of one segment's device are
/// one device however many reflectors show it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClaimKey {
    owner: Owner,
    origin: Option<Rc<str>>,
}

impl ClaimKey {
    fn owned(owner: Owner) -> ClaimKey {
        ClaimKey { owner, origin: None }
    }

    fn reflected(owner: Owner, origin: &str) -> ClaimKey {
        ClaimKey { owner, origin: Some(origin.into()) }
    }
}

/// Who wants a hostname announced, and what: sorted by owner, then by the
/// segment the device is of, so that the first wins. A few at most, so a list
/// with room for just those, not a tree, which takes room for eleven for one.
#[derive(Default)]
struct Claims(Vec<(ClaimKey, Claim)>);

impl Claims {
    fn position(&self, key: &ClaimKey) -> Result<usize, usize> {
        self.0.binary_search_by(|(other, _)| other.cmp(key))
    }

    fn get(&self, key: &ClaimKey) -> Option<&Claim> {
        self.position(key).ok().map(|at| &self.0[at].1)
    }

    /// Whether `owner` has any claim, of whichever segment's device.
    fn has_owner(&self, owner: &Owner) -> bool {
        self.0.iter().any(|(key, _)| key.owner == *owner)
    }

    /// Put `claim` for `key`, in place of the one it had. Returns that one.
    fn insert(&mut self, key: ClaimKey, claim: Claim) -> Option<Claim> {
        match self.position(&key) {
            Ok(at) => Some(core::mem::replace(&mut self.0[at].1, claim)),
            Err(at) => {
                self.0.reserve_exact(1);
                self.0.insert(at, (key, claim));
                None
            }
        }
    }

    fn remove(&mut self, key: &ClaimKey) -> Option<Claim> {
        let at = self.position(key).ok()?;
        let (_, claim) = self.0.remove(at);
        self.shrink();
        Some(claim)
    }

    /// Take every claim of `owner`.
    fn remove_owner(&mut self, owner: &Owner) -> Vec<(ClaimKey, Claim)> {
        let (taken, kept): (Vec<_>, Vec<_>) = core::mem::take(&mut self.0).into_iter().partition(|(key, _)| key.owner == *owner);
        self.0 = kept;
        self.shrink();
        taken
    }

    fn shrink(&mut self) {
        if self.0.is_empty() {
            self.0 = Vec::new();
        } else {
            self.0.shrink_to_fit();
        }
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// By owner, the first first.
    fn iter(&self) -> impl Iterator<Item = (&ClaimKey, &Claim)> {
        self.0.iter().map(|(key, claim)| (key, claim))
    }

    fn keys(&self) -> impl Iterator<Item = &ClaimKey> {
        self.0.iter().map(|(key, _)| key)
    }

    fn values(&self) -> impl Iterator<Item = &Claim> {
        self.0.iter().map(|(_, claim)| claim)
    }
}

/// A hostname announced on behalf of somewhere else, plus the timing needed
/// to keep it announced.
struct Manual {
    /// The hostname, in lowercase: what it is told apart by.
    host: Box<str>,
    /// Everyone who wants this hostname announced; empty only while what was
    /// shown is still to be withdrawn. See [`State::wanted`] for what is.
    claims: Claims,
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
    /// What the tables that find it hold of it.
    held: Held,
}

impl Manual {
    fn new(host: &str, now: Instant) -> Manual {
        Manual {
            host: host.to_ascii_lowercase().into(),
            claims: Claims::default(),
            shown: None,
            announced: now,
            repeat: false,
            last_sent: Sent::both(now),
            retry: None,
            host_ttl: HOST_TTL,
            other_ttl: OTHER_TTL,
            held: Held::default(),
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
pub type Probed = core::result::Result<usize, String>;

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

// The devices a segment announces, each held in one place, and how they are
// found.
//
// A device is kept (in a [`Table`]) and called by its [`Id`]. It is found by
// its hostname, which is among the names it, or anyone who wants it announced,
// has records under, and by when it is next due to be announced again. Like
// those of the discovered devices ([`Devices`](crate::tracker::Devices)) the
// tables hold hashes, times and ids, and follow a device when it is changed by
// [`Manuals::edit`], or goes. A device that nobody wants announced and that is
// not shown is gone, as it has nothing to be found by.

impl Manual {
    /// Whether nothing of it is wanted or shown.
    fn gone(&self) -> bool {
        self.claims.is_empty() && self.shown.is_none()
    }
}

/// What the tables hold of one: the hashes of the names it, or any claim on
/// it, has records under, and when it is held as due. It is kept with the
/// device, not worked out again, as a claim on a device of another segment has
/// the names of that device, which can change without this being told, until
/// the reflector says to look again.
#[derive(Default, Debug, PartialEq, Eq)]
struct Held {
    names: Vec<u64>,
    due: Option<Instant>,
}

#[derive(Default)]
struct Manuals {
    table: Table<Manual>,
    /// Each name an announced device, or a claim on it, has records under,
    /// and the device, by the hash of the name.
    by_name: Multi,
    /// The devices by when they are next due to be announced again.
    by_due: BTreeSet<(Instant, Id)>,
    /// Whether devices that have not changed are announced again, which is
    /// what when they are due goes by.
    unchanged: bool,
    hasher: DefaultHashBuilder,
}

impl Manuals {
    fn find(&self, host: &str) -> Option<Id> {
        let hash = hash_name(&self.hasher, host);
        let named = |id: &Id| self.table.get(*id).host.eq_ignore_ascii_case(host);
        self.by_name.under(hash).find(named)
    }

    /// The device announced as `host`, ignoring case.
    fn get(&self, host: &str) -> Option<&Manual> {
        self.find(host).map(|id| self.table.get(id))
    }

    fn contains_key(&self, host: &str) -> bool {
        self.find(host).is_some()
    }

    fn iter(&self) -> impl Iterator<Item = &Manual> {
        self.table.iter()
    }

    /// What the tables would hold of `manual`.
    fn held_now(&self, manual: &Manual) -> Held {
        let mut names = vec![hash_name(&self.hasher, &manual.host)];
        let hasher = &self.hasher;
        let mut add = |device: &Device| device.for_each_name(|name| names.push(hash_name(hasher, name)));
        manual.shown.iter().for_each(&mut add);
        // What is wanted, by everyone who wants it.
        for claim in manual.claims.values() {
            add(&claim.resolve().0);
        }
        names.sort_unstable();
        names.dedup();
        Held { names, due: manual.reannounce_at(self.unchanged) }
    }

    /// Have the tables follow a device that was changed from what they held of
    /// it, `was`.
    fn follow(&mut self, id: Id, was: &Held) {
        let now = self.held_now(self.table.get(id));
        self.by_name.move_between(id, &was.names, &now.names);
        if was.due != now.due {
            if let Some(at) = was.due {
                self.by_due.remove(&(at, id));
            }
            if let Some(at) = now.due {
                self.by_due.insert((at, id));
            }
        }
        self.table.get_mut(id).held = now;
    }

    /// Keep a device that is not announced yet, and wanted by someone. Not if
    /// one is announced as its hostname.
    fn insert(&mut self, manual: Manual) {
        debug_assert!(!self.contains_key(&manual.host), "a hostname is announced once");
        debug_assert!(!manual.gone(), "a device is wanted");
        let id = self.table.insert(manual);
        self.follow(id, &Held::default());
    }

    /// Change the device announced as `host` with `f`, and have the tables
    /// follow. It is gone when nothing of it is wanted or shown any more.
    fn edit<R>(&mut self, host: &str, f: impl FnOnce(&mut Manual) -> R) -> Option<R> {
        let id = self.find(host)?;
        let out = f(self.table.get_mut(id));
        let was = core::mem::take(&mut self.table.get_mut(id).held);
        if self.table.get(id).gone() {
            self.drop(id, &was);
        } else {
            self.follow(id, &was);
        }
        Some(out)
    }

    /// Let go of a device, which the tables hold as `held`.
    fn drop(&mut self, id: Id, held: &Held) -> Manual {
        self.by_name.move_between(id, &held.names, &[]);
        if let Some(at) = held.due {
            self.by_due.remove(&(at, id));
        }
        self.table.remove(id)
    }

    /// The devices that have, or that someone wants to have, records under
    /// `name`, ignoring case.
    fn with_claimed_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Manual> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name.under(hash).map(|id| self.table.get(id)).filter(move |manual| {
            manual.claims.values().any(|claim| claim.resolve().0.has_name(name))
                || manual.shown.as_ref().is_some_and(|shown| shown.has_name(name))
        })
    }

    /// The devices that are announced with records under `name`, ignoring case.
    fn with_shown_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Manual> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name
            .under(hash)
            .map(|id| self.table.get(id))
            .filter(move |manual| manual.shown.as_ref().is_some_and(|shown| shown.has_name(name)))
    }

    /// The hostnames, in lowercase, of all the devices.
    fn hosts_all(&self) -> Vec<String> {
        self.hosts(self.iter())
    }

    /// The hostnames, in lowercase, of the devices that someone wants to have
    /// records under `name`, ignoring case, each once.
    fn hosts_claiming(&self, name: &str) -> Vec<String> {
        self.hosts(self.with_claimed_name(name))
    }

    /// The hostnames, in lowercase, of the devices announced with records
    /// under `name`, ignoring case, each once.
    fn hosts_showing(&self, name: &str) -> Vec<String> {
        self.hosts(self.with_shown_name(name))
    }

    fn hosts<'a>(&self, manuals: impl Iterator<Item = &'a Manual>) -> Vec<String> {
        let mut hosts: Vec<String> = manuals.map(|m| m.host.to_string()).collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }

    /// Set whether devices that have not changed are announced again. It is
    /// what when they are due goes by, so those times are made again.
    fn set_unchanged(&mut self, unchanged: bool) {
        if self.unchanged == unchanged {
            return;
        }
        self.unchanged = unchanged;
        self.by_due.clear();
        for id in self.table.ids().collect::<Vec<_>>() {
            if let Some(at) = self.table.get(id).reannounce_at(unchanged) {
                self.by_due.insert((at, id));
            }
        }
    }

    /// When a device is next due to be announced again.
    fn next_due(&self) -> Option<Instant> {
        self.by_due.first().map(|&(at, _)| at)
    }

    /// The hostnames, in lowercase, of the devices due to be announced again
    /// as of `now`.
    fn due(&self, now: Instant) -> Vec<String> {
        self.by_due.range(..=(now, Id::LAST)).map(|&(_, id)| self.table.get(id).host.to_string()).collect()
    }

    /// Whether the tables find each device by what it says and hold what it
    /// has, and nothing else.
    #[cfg(test)]
    fn check(&self) {
        self.table.check();
        let (mut names, mut due) = (0, 0);
        for id in self.table.ids() {
            let manual = self.table.get(id);
            let host = &*manual.host;
            assert!(!manual.gone(), "a device is wanted or shown: {host}");
            assert_eq!(self.find(host), Some(id), "a hostname is announced once: {host}");
            let held = &manual.held;
            names += held.names.len();
            assert!(held.names.iter().all(|&h| self.by_name.holds(h, id)), "a name is held: {host}");
            if let Some(at) = held.due {
                due += 1;
                assert!(self.by_due.contains(&(at, id)), "it is held as due: {host}");
            }
            // What was held is what it would be now, but for a device of another
            // segment that changed since.
            let now = self.held_now(manual);
            assert_eq!(held.due, now.due, "it is held as due as it is: {host}");
            if manual.claims.values().all(|claim| matches!(claim, Claim::Owned { .. })) {
                assert_eq!(held.names, now.names, "its names are held as they are: {host}");
            }
        }
        assert_eq!((self.by_name.pairs, self.by_due.len()), (names, due));
    }
}

#[cfg(test)]
impl Manuals {
    fn is_empty(&self) -> bool {
        self.table.len() == 0
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Manuals {
    type Output = Manual;

    fn index(&self, host: &str) -> &Manual {
        self.get(host).expect("no such device")
    }
}

#[derive(Default)]
struct State {
    /// What is known of the devices heard here.
    tracker: Tracker,
    /// Devices we announce on this segment on behalf of somewhere else, by
    /// lowercase hostname.
    manual: Manuals,
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
    /// Whether what is announced here is announced again before its TTL runs
    /// out though it has not changed. It need not be: whoever still wants it
    /// asks again (RFC 6762 section 5.2), and is answered.
    reannounce: bool,
    /// The families a device is asked directly over, to refresh it: those that
    /// hear what is sent to the daemon.
    direct: Vec<Family>,
    /// The most a packet sent here may hold: what the interface's MTU leaves.
    max_packet: usize,
    upkeep: Upkeep,
    /// The questions put to this segment on another's behalf, in lowercase,
    /// and when, for [`FORWARD_GAP`].
    forwarded: HashMap<(String, u16), Instant>,
}

impl State {
    /// Whether the tables that find things are what the devices and the
    /// neighbour table are, for tests to ask after anything that changes them.
    #[cfg(test)]
    fn check(&self) {
        if CHECKING.with(|checking| checking.get()) && self.tracker.discovered.len() <= 1100 {
            self.tracker.discovered.check();
            self.manual.check();
            self.tracker.neighbours.check();
            // What is due next is what a look at every device says.
            let mut scan: Option<Instant> = None;
            self.for_each_deadline(&mut |_, _, at| scan = Some(scan.map_or(at, |n| n.min(at))));
            assert_eq!(self.next_due(Instant::now()), scan);
        }
    }


    /// Tell of what a change to the devices made, once: ask on the link-local
    /// addresses it noted, let the announced devices that have to give way do,
    /// and put the events out.
    fn report(&mut self, mut touched: Touched, now: Instant) {
        for (ll, device) in core::mem::take(&mut touched.nudges) {
            nudge(&self.outbound, ll, &Device::refresh_queries(core::slice::from_ref(&device), self.max_packet));
        }
        let names = touched.names(&self.tracker.discovered);
        let events = touched.events(&self.tracker.discovered);
        if !events.is_empty() {
            self.settle_for(&names, now);
        }
        for event in events {
            self.notify(event);
        }
        #[cfg(test)]
        self.check();
    }

    fn notify(&mut self, event: Event) {
        self.outbox.push(event);
    }

    /// The next time [`Segment::expire`], [`Segment::refresh`] or
    /// [`Segment::reannounce`] has something to do, or `None` if never. A time
    /// in the past means it is due now. Every time returned is one at which
    /// one of them acts, so that running them moves it on.
    fn next_due(&self, _now: Instant) -> Option<Instant> {
        let mut next = self.tracker.discovered.next_due();
        let mut see = |at: Instant| next = Some(next.map_or(at, |n| n.min(at)));
        for p in &self.probing {
            see(p.next);
        }
        if let Some(at) = self.next_routine {
            see(at);
        }
        if let Some(at) = self.manual.next_due() {
            see(at);
        }
        next
    }

    /// Have the devices go by how long before they run out they are asked to
    /// answer again, when that, or whether there is a way to ask, changed.
    fn sync_refresh(&mut self) {
        let before = self.upkeep.before.filter(|_| !self.outbound.is_empty());
        self.tracker.discovered.set_refresh(before);
    }

    /// Every time something is due, as what is to be done (`expire`,
    /// `refresh` or `re-announce`), to whom, and when. What
    /// [`State::next_due`] and [`Segment::pending`] are made of.
    fn for_each_deadline(&self, f: &mut dyn FnMut(&'static str, &dyn fmt::Display, Instant)) {
        let before = self.upkeep.before;
        for e in self.tracker.discovered.iter() {
            let who: &dyn fmt::Display = match &e.device.hostname {
                Some(host) => host,
                None => &e.from,
            };
            f("expire", who, e.expires);
            // Its addresses that run out before it does, each on its own.
            for (addr, &at) in e.addr_expires.iter().filter(|&(_, at)| *at < e.expires) {
                f("expire", &Labelled(who, addr), at);
            }
            if let Some(at) = before.filter(|_| !self.outbound.is_empty()).and_then(|before| e.refresh_due(before)) {
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
        for m in self.manual.iter() {
            if let Some(at) = m.reannounce_at(self.reannounce) {
                // By the name as announced.
                f("re-announce", &m.shown.as_ref().and_then(|d| d.hostname.as_deref()).unwrap_or(&m.host), at);
            }
        }
    }

    /// How much longer the daemon keeps `device` if it is not heard from, to
    /// the second.
    fn lifetime_left(&self, device: &Device) -> Duration {
        let id = match (&device.hostname, device.addrs().next()) {
            (Some(host), _) => self.tracker.discovered.find_host(host),
            (None, Some(addr)) => self.tracker.discovered.find_nameless(&addr),
            (None, None) => return Duration::ZERO,
        };
        id.map(|id| self.tracker.discovered.get(id)).map_or(Duration::ZERO, |entry| {
            let left = entry.expires.saturating_duration_since(Instant::now());
            // To the nearest second, a half up.
            Duration::from_secs(left.saturating_add(Duration::from_millis(500)).as_secs())
        })
    }


    /// Whether a device on this segment offers a service called `instance`,
    /// ignoring case.
    fn is_local(&self, instance: &str) -> bool {
        self.tracker.discovered.with_name(instance).any(|e| e.device.service(instance).is_some())
    }

    /// What should be announced as `key`: the winning claim, less the
    /// services whose instance names devices here have, or nothing if a device
    /// here has the hostname. Announced on top of a device here, a copy would
    /// be a conflict, and the device would rename itself. The advertised name
    /// is ours, and announced whatever is here.
    fn wanted(&self, key: &str, m: &Manual) -> Option<(Device, u32)> {
        let (first, (device, host_ttl)) = m.claims.iter().next().map(|(k, claim)| (k, claim.resolve()))?;
        if first.owner == Owner::Own {
            return Some((device, host_ttl));
        }
        // What other segments' devices of the name there are: the lowest
        // segment's is announced, as everyone who reflects it shows it.
        let (device, host_ttl) = match &first.origin {
            None => (device, host_ttl),
            Some(_) => {
                let reflected = || m.claims.iter().filter_map(|(k, claim)| Some((k.origin.as_ref()?, claim.resolve())));
                let lowest = reflected().map(|(origin, _)| origin).min()?;
                reflected()
                    .filter(|(origin, _)| *origin == lowest)
                    .map(|(_, wanted)| wanted)
                    .reduce(|(device, ttl), (other, other_ttl)| (device.union(&other), ttl.max(other_ttl)))?
            }
        };
        if self.tracker.discovered.contains_host(key) {
            return None;
        }
        Some((device.without(&|instance| self.is_local(instance)), host_ttl))
    }

    /// Bring what is announced as `key` in line with [`State::wanted`], with
    /// goodbyes for what is no longer to be, and forget it once nobody wants
    /// it and nothing of it is shown. Returns whether anything was sent. If
    /// sending fails, nothing changes.
    fn settle(&mut self, key: &str, now: Instant) -> Result<bool> {
        let Some(m) = self.manual.get(key) else {
            return Ok(false);
        };
        let want = self.wanted(key, m);
        // Each with the TTL its address is announced with.
        let old = m.shown.as_ref().map(|d| Device { ttl: Some(m.host_ttl), ..d.clone() });
        let new = want.as_ref().map(|(device, host_ttl)| Device { ttl: Some(*host_ttl), ..device.clone() });
        let host_here = self.tracker.discovered.contains_host(key);
        let records = Device::transition(old.as_ref(), new.as_ref(), &|instance| self.is_local(instance), host_here);
        let sent = !records.is_empty();
        if sent {
            send(&self.outbound, self.max_packet, &records)?;
        }

        // Gone, if nobody wants it and nothing of it is shown.
        self.manual.edit(key, |m| {
            if sent {
                m.announced = now;
                m.repeat = true;
                m.last_sent = Sent::both(now);
                m.retry = None;
            }
            match want {
                Some((device, host_ttl)) => {
                    m.shown = Some(device);
                    m.host_ttl = host_ttl;
                }
                None => m.shown = None,
            }
        });
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
        query
            .questions
            .iter()
            .filter(|q| !(self.is_local(&q.name) || self.tracker.discovered.contains_host(&q.name)))
            .map(|q| {
                let answered = self.manual.with_shown_name(&q.name).any(|m| m.shown.as_ref().is_some_and(|d| d.knows(q)));
                Asked { question: q.clone(), answered }
            })
            .collect()
    }

    /// The devices this segment answers queries for, by hostname: what is
    /// shown of each, with the TTL its address is announced with. Left out
    /// are those multicast less than a second ago (RFC 6762 section 6), unless
    /// the reply is to go to a `legacy` resolver alone, and, for a device
    /// `probing` for names it is about to take, the reflected copies: it would
    /// take them for a conflict, and once it announces, the copy gives way.
    /// The daemon's own name answers a probe however recently it went out:
    /// that answer defends it, which section 6 exempts from the wait.
    fn answering(&self, query: &Message, now: Instant, legacy: bool, probing: bool, family: Family) -> Vec<(String, Device)> {
        // Only those with records under a name asked for can answer.
        let mut keys: Vec<String> = query.questions.iter().flat_map(|q| self.manual.hosts_showing(&q.name)).collect();
        keys.sort_unstable();
        keys.dedup();
        let mut out = Vec::new();
        for key in keys {
            let Some(m) = self.manual.get(&key) else { continue };
            let Some(device) = &m.shown else { continue };
            if probing && m.claims.keys().next().map(|k| k.owner) != Some(Owner::Own) {
                continue;
            }
            if !legacy && !probing && now.saturating_duration_since(m.last_sent.over(family)) < MIN_MULTICAST_GAP {
                continue;
            }
            out.push((key, Device { ttl: Some(m.host_ttl), ..device.clone() }));
        }
        out
    }

    /// [Settle](State::settle) the announced hostnames that someone wants
    /// records under one of `names` for, after the devices on this segment
    /// that had them changed: the others are as they were. One that fails to
    /// send is tried again by [`Segment::reannounce`], which reports it if it
    /// fails again.
    fn settle_for(&mut self, names: &[String], now: Instant) {
        let mut keys: Vec<String> = names.iter().flat_map(|name| self.manual.hosts_claiming(name)).collect();
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            if self.settle(&key, now).is_err() {
                self.manual.edit(&key, |m| m.retry = Some(now + ANNOUNCE_RETRY));
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
                direct: vec![Family::V4, Family::V6],
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
        self.state.borrow_mut().tracker.min_lifetime = min_lifetime;
    }

    /// The families a device is asked directly over, to refresh it, rather than
    /// on the group: those the daemon hears what is sent to it over, which is
    /// where the answer comes if the device sends it to the daemon. The
    /// default is both.
    pub fn set_direct(&self, families: &[Family]) {
        self.state.borrow_mut().direct = families.to_vec();
    }

    /// How many addresses of a family a discovered device is kept with, at
    /// most: more are not taken. The default is [`DEFAULT_MAX_ADDRS`].
    /// Applies to what is heard from now on.
    pub fn set_max_addrs(&self, max_addrs: usize) {
        self.state.borrow_mut().tracker.max_addrs = max_addrs.max(1);
    }

    /// How many devices it remembers, at most: a host beyond that is not
    /// learned of. The default is [`DEFAULT_MAX_DEVICES`].
    pub fn set_max_devices(&self, max_devices: usize) {
        self.state.borrow_mut().tracker.max_devices = max_devices.max(1);
    }

    /// How many services a device is kept with, at most: more are not taken.
    /// The default is [`DEFAULT_MAX_SERVICES`].
    pub fn set_max_services(&self, max_services: usize) {
        self.state.borrow_mut().tracker.max_services = max_services.max(1);
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
        let mut state = self.state.borrow_mut();
        state.reannounce = unchanged;
        state.manual.set_unchanged(unchanged);
    }

    /// Ask devices to answer again `before` ahead of expiring, from now on;
    /// `None` (the default) does not.
    pub fn set_refresh_before(&self, before: Option<Duration>) {
        let mut state = self.state.borrow_mut();
        state.upkeep.before = before;
        state.sync_refresh();
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
    pub fn attach(&self, family: Family, socket: impl Into<Sender>, dest: SocketAddr) {
        let mut state = self.state.borrow_mut();
        state.outbound.retain(|o| o.family != family);
        state.outbound.push(Outbound { family, socket: socket.into(), dest });
        state.sync_refresh();
    }

    // 1. Discovered devices.

    /// Devices currently active on this segment (excludes manual ones).
    pub fn devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.tracker.discovered.iter().map(|e| e.device.clone()).collect()
    }

    // 2. Change notifications for the discovered list.

    /// The changes to its devices since last asked, oldest first, for the
    /// event loop to hand on.
    pub fn take_events(&self) -> Vec<Event> {
        core::mem::take(&mut self.state.borrow_mut().outbox)
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
        state.for_each_deadline(&mut |what, who, at| {
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
        self.claim(ClaimKey::owned(owner), &key, Claim::Owned { device: Box::new(device), host_ttl })
    }

    /// Announce `device`, one that is on the segment of `origin` (an
    /// interface) and is to be shown here as it is given, for `owner`, with
    /// the TTL `host_ttl` for its address records, if given, or else its own.
    /// It is the reflector's to say again when the device changes, or to
    /// withdraw it with [`unreflect`](Segment::unreflect). A device of the same
    /// name from the same segment that more than one owner shows is announced
    /// as what they show of it together; from another segment, the lowest
    /// segment's is, and the other takes over when it goes.
    pub fn reflect(&self, owner: Owner, origin: &str, device: Rc<Device>, host_ttl: Option<Duration>) -> Result<bool> {
        let Some(host) = device.key() else {
            return Err(anyhow!("a reflected device needs a hostname to announce"));
        };
        let host_ttl = host_ttl.map(|ttl| u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX));
        if host_ttl == Some(0) {
            bail!("a TTL of zero would withdraw the device");
        }
        self.claim(ClaimKey::reflected(owner, origin), &host, Claim::Reflected { device, host_ttl })
    }

    /// Put `claim` among what is wanted announced as `host` (lowercase), and
    /// settle what is announced. One of a device made for it that the same key
    /// has already is left as it is.
    fn claim(&self, key: ClaimKey, host: &str, claim: Claim) -> Result<bool> {
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let previous = match state.manual.get(host) {
            Some(m) if matches!(claim, Claim::Owned { .. }) && m.claims.get(&key) == Some(&claim) => return Ok(false),
            Some(_) => state.manual.edit(host, |m| m.claims.insert(key.clone(), claim)).flatten(),
            None => {
                let mut m = Manual::new(host, now);
                m.claims.insert(key.clone(), claim);
                state.manual.insert(m);
                None
            }
        };
        if let Err(e) = state.settle(host, now) {
            // Nothing is recorded: put back what was there, which leaves
            // nothing if nothing was.
            state.manual.edit(host, |m| match previous {
                Some(previous) => m.claims.insert(key, previous),
                None => m.claims.remove(&key),
            });
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
        self.unclaim(&ClaimKey::owned(owner), hostname)
    }

    /// Forget the device of the segment of `origin` that `owner` wanted
    /// announced as `hostname`, as [`remove_manual`](Segment::remove_manual)
    /// forgets one made for it.
    pub fn unreflect(&self, owner: Owner, origin: &str, hostname: &str) -> Result<bool> {
        self.unclaim(&ClaimKey::reflected(owner, origin), hostname)
    }

    fn unclaim(&self, key: &ClaimKey, hostname: &str) -> Result<bool> {
        let host = hostname.to_ascii_lowercase();
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let Some(previous) = state.manual.edit(&host, |m| m.claims.remove(key)).flatten() else {
            return Ok(false);
        };
        if let Err(e) = state.settle(&host, Instant::now()) {
            state.manual.edit(&host, |m| m.claims.insert(key.clone(), previous));
            return Err(e);
        }
        drop(guard);
        Ok(true)
    }

    /// Forget every device of the segment of `origin` that `owner` wanted
    /// announced, as it is gone. Every one is tried; the first error is
    /// returned.
    pub fn drop_origin(&self, owner: Owner, origin: &str) -> Result<()> {
        let key = ClaimKey::reflected(owner, origin);
        let hosts: Vec<String> = {
            let state = self.state.borrow();
            state.manual.iter().filter(|m| m.claims.get(&key).is_some()).map(|m| m.host.to_string()).collect()
        };
        let mut first_err = None;
        for host in hosts {
            if let Err(e) = self.unclaim(&key, &host) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Forget everything `owner` wanted announced, with goodbyes for what is
    /// then no longer announced. Every one is tried; the first error is
    /// returned.
    pub fn withdraw_all(&self, owner: Owner) -> Result<()> {
        let hosts: Vec<String> = {
            let state = self.state.borrow();
            state.manual.iter().filter(|m| m.claims.has_owner(&owner)).map(|m| m.host.to_string()).collect()
        };
        let mut first_err = None;
        for host in hosts {
            let mut guard = self.state.borrow_mut();
            let state = &mut *guard;
            let taken = state.manual.edit(&host, |m| m.claims.remove_owner(&owner)).unwrap_or_default();
            if let Err(e) = state.settle(&host, Instant::now()) {
                state.manual.edit(&host, |m| {
                    for (key, claim) in taken {
                        m.claims.insert(key, claim);
                    }
                });
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Let go of every way to send, as when the interface is gone: what is
    /// announced here is kept, to announce again once it is back.
    pub fn detach_all(&self) {
        let mut state = self.state.borrow_mut();
        state.outbound.clear();
        state.sync_refresh();
    }

    /// Announce again everything announced here, as when the interface has
    /// come back: whoever is on it now may never have heard it. A failed send
    /// is retried by [`Segment::reannounce`].
    pub fn announce_all(&self) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let State { manual, outbound, max_packet, .. } = &mut *guard;
        let mut first_err = None;
        for key in manual.hosts_all() {
            let Some(m) = manual.get(&key) else { continue };
            let Some(device) = &m.shown else { continue };
            match send(outbound, *max_packet, &device.announcement(m.host_ttl, m.other_ttl)) {
                Ok(()) => {
                    manual.edit(&key, |m| {
                        m.announced = now;
                        m.repeat = true;
                        m.last_sent = Sent::both(now);
                        m.retry = None;
                    });
                }
                Err(e) => {
                    manual.edit(&key, |m| m.retry = Some(now + ANNOUNCE_RETRY));
                    first_err.get_or_insert(e);
                }
            }
        }
        drop(guard);
        first_err.map_or(Ok(()), Err)
    }

    /// Handle a datagram that came in on this interface, if it is of a host
    /// it hears.
    pub fn hear(&self, from: SocketAddr, to: Option<IpAddr>, datagram: &[u8]) {
        if !self.accepts(from.ip(), to) {
            return;
        }
        if let Err(e) = self.handle(from, datagram) {
            eprintln!("{}: reply failed: {e:#}", self.interface);
        }
    }

    /// Announce `advertise` with `addrs`, this host's addresses on the
    /// interface, or withdraw it if there are none.
    pub fn advertise(&self, advertise: &AdvertiseConfig, addrs: &[IpAddr]) {
        let AdvertiseConfig { name, ttl, services, .. } = advertise;
        if addrs.is_empty() {
            eprintln!("{}: no address to advertise {name} with", self.interface);
            if let Err(e) = self.remove_manual(Owner::Own, name) {
                eprintln!("{}: withdrawing {name} failed: {e:#}", self.interface);
            }
            return;
        }
        let mut device = Device { hostname: Some(name.clone()), ..Device::default() };
        device.add_addrs(addrs);
        // Each is of an instance named for the host, as Avahi's %h is.
        let label = name.split('.').next().unwrap_or(name);
        device.services = services
            .iter()
            .map(|(kind, port)| Service {
                instance: format!("{label}.{kind}.local"),
                kind: format!("{kind}.local"),
                port: *port,
                target: Some(name.clone()),
                ..Service::default()
            })
            .collect();
        match self.add_manual_ttl(Owner::Own, device, *ttl) {
            Ok(true) => {
                let shown: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
                eprintln!("{}: advertising {name} as {} (TTL {}s)", self.interface, shown.join(", "), ttl.as_secs());
            }
            Ok(false) => {}
            Err(e) => eprintln!("{}: not advertising {name}: {e:#}", self.interface),
        }
    }

    /// Forget every device discovered here, as when the interface is gone:
    /// they cannot be reached through it, and their copies elsewhere are
    /// withdrawn. They are found again once it is back.
    pub fn forget_discovered(&self) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let touched = state.tracker.forget();
        state.report(touched, Instant::now());
    }

    /// The devices this daemon advertises as its own here (`[Advertise]`), as
    /// they are announced: the host itself, which it never hears of from the
    /// network, each with the TTL of its address records.
    pub fn own_devices(&self) -> Vec<(Device, Duration)> {
        let state = self.state.borrow();
        state
            .manual
            .iter()
            .filter_map(|m| match m.claims.get(&ClaimKey::owned(Owner::Own)) {
                Some(Claim::Owned { device, host_ttl }) => Some(((**device).clone(), Duration::from_secs(u64::from(*host_ttl)))),
                _ => None,
            })
            .collect()
    }

    /// The devices announced on this segment: for each hostname, what is
    /// shown of the one that won.
    pub fn manual_devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.manual.iter().filter_map(|m| m.shown.clone()).collect()
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
        let mut first_err = None;
        for key in state.manual.due(now) {
            // What is out of line is settled first, which announces it.
            let result = state.settle(&key, now).and_then(|sent| {
                let Some(m) = state.manual.get(&key).filter(|_| !sent) else {
                    return Ok(());
                };
                let announced = match &m.shown {
                    Some(device) => {
                        send(&state.outbound, state.max_packet, &device.announcement(m.host_ttl, m.other_ttl))?;
                        true
                    }
                    None => false,
                };
                state.manual.edit(&key, |m| {
                    if announced {
                        m.announced = now;
                        m.repeat = false;
                        m.last_sent = Sent::both(now);
                    }
                    m.retry = None;
                });
                Ok(())
            });
            if let Err(e) = result {
                state.manual.edit(&key, |m| m.retry = Some(now + ANNOUNCE_RETRY));
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
        let (keys, devices): (Vec<String>, Vec<Device>) = state.answering(query, now, legacy, probing, family).into_iter().unzip();
        let Some((msgs, answered)) = Device::query_response(&devices, query, legacy, state.max_packet) else {
            return Ok(());
        };
        for msg in &msgs {
            transmit(&state.outbound, family, msg, legacy.then_some(from))?;
        }

        if !legacy {
            for i in answered {
                state.manual.edit(&keys[i], |m| m.last_sent.set(family, now));
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
        let known = |q: &Question| state.tracker.discovered.with_name(&q.name).flat_map(|e| e.known_answers(q, now)).collect();
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
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let touched = state.tracker.track(src, now, msg);
        state.report(touched, now);
    }

    /// Take the networks the interface is on, as its addresses change: of the
    /// neighbour table, only addresses in one of them are learned, and those
    /// learned of one it is no longer on are dropped.
    pub fn set_prefixes(&self, prefixes: Vec<Prefix>) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let now = Instant::now();
        let touched = state.tracker.set_prefixes(prefixes, now);
        state.report(touched, now);
    }

    /// Whether a datagram from `from`, sent to `to` if that is known, is to be
    /// heard. What is sent to the group is, whoever sends it. What is sent to the
    /// daemon itself is only from a host on a network the interface is on, or
    /// link-local: one of any other address came through some router, and an
    /// interface is not where it is to be believed of devices.
    pub fn accepts(&self, from: IpAddr, to: Option<IpAddr>) -> bool {
        match to {
            None => true,
            Some(to) if to.is_multicast() => true,
            Some(_) => is_link_local(&from) || self.state.borrow().tracker.prefixes.iter().any(|p| p.contains(&from)),
        }
    }

    /// Take in an entry of the interface's neighbour table, as the kernel
    /// reports it: `ip` is at link-layer address `mac`, or with `None`, no
    /// longer (it went, or could not be reached). The devices it may concern,
    /// those with any address, have their learned addresses brought up to
    /// date, and are reflected so.
    pub fn neighbour(&self, ip: IpAddr, mac: Option<Vec<u8>>) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let now = Instant::now();
        let touched = state.tracker.neighbour(ip, mac, now);
        state.report(touched, now);
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

        let devices: Vec<Device> = state.tracker.discovered.iter().map(|e| e.device.clone()).collect();
        ask(&state.outbound, &Device::probe_queries(&devices, &state.tracker.types, state.max_packet))
    }

    fn query_types_round(&self, kinds: &[String]) -> Result<usize> {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        if state.outbound.is_empty() {
            return Ok(0);
        }
        for kind in kinds.iter().filter(|k| is_type(k)) {
            if state.tracker.types.len() < MAX_TYPES {
                state.tracker.types.insert(kind.to_ascii_lowercase());
            }
        }
        let now = Instant::now();
        let devices: Vec<Device> = state.tracker.discovered.iter().map(|e| e.device.clone()).collect();
        let known = |q: &Question| state.tracker.discovered.with_name(&q.name).flat_map(|e| e.known_answers(q, now)).collect();
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
        let State { tracker: Tracker { discovered, .. }, outbound, max_packet, direct, .. } = &mut *guard;
        if outbound.is_empty() {
            return Ok(0);
        }
        let gap = refresh_gap(before);

        // Due when it, or one of its addresses, is about to run out. Not what
        // has already run out: it is about to be dropped. A margin too long to
        // add to a time reaches past every expiry.
        let (mut asking, mut asked) = (Vec::new(), 0);
        for id in discovered.about_to_run_out(now, before) {
            let entry = discovered.get(id);
            let recent = entry.refreshed.is_some_and(|t| now.saturating_duration_since(t) < gap);
            // Its own time to be asked, which is later than `before` ahead of
            // it for one with a short TTL.
            if !entry.askable() || recent || entry.refresh_due(before).is_none_or(|at| at > now) {
                continue;
            }
            // A device that sleeps may ignore the group, and still answers what
            // is sent to it. If it did not answer that (a retry, as it was asked
            // already in this window), the group is tried, in case it ignores
            // what is sent to it instead.
            let retry = entry.refreshed.is_some_and(|t| entry.soonest().checked_sub(entry.lead(before)).is_none_or(|from| t >= from));
            let device = entry.device.clone();
            discovered.edit(id, |entry| entry.refreshed = Some(now));
            let direct = direct_address(&device, direct).filter(|_| !retry);
            let queries = Device::refresh_queries(core::slice::from_ref(&device), *max_packet);
            match direct {
                Some(addr) if ask_at(outbound, addr, &queries) => asked += queries.iter().map(|q| q.questions.len()).sum::<usize>(),
                _ => asking.push(device),
            }
        }
        Ok(asked + ask(outbound, &Device::refresh_queries(&asking, *max_packet))?)
    }

    /// Drop devices whose lifetime has run out as of `now`.
    pub fn expire(&self, now: Instant) {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let touched = state.tracker.expire(now);
        // What they had here may be shown again. `now` may be ahead of the
        // clock, but what is announced is announced now.
        state.report(touched, Instant::now());
    }
}

// Whether tests check the tables that find things after each change; the
// measurement of what a full segment costs turns it off.
#[cfg(test)]
thread_local! {
    static CHECKING: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
}

/// Have tests check the tables that find things after each change, or not.
#[cfg(test)]
pub fn set_checking(on: bool) {
    CHECKING.with(|checking| checking.set(on));
}

/// Ask `queries` of the device at `addr`, by unicast to its port 5353 (RFC
/// 6762 section 5.5), over the socket of its family. Whether all were sent.
/// To a link-local address, the kernel has to look up its link-layer address,
/// which is what [`nudge`] is for.
fn ask_at(outbound: &[Outbound], addr: IpAddr, queries: &[Message]) -> bool {
    let Some(out) = outbound.iter().find(|o| o.family == family_of(addr)) else { return false };
    let dest = match (addr, out.dest) {
        (IpAddr::V6(addr), SocketAddr::V6(group)) => SocketAddr::V6(SocketAddrV6::new(addr, MDNS_PORT, 0, group.scope_id())),
        (addr, _) => SocketAddr::new(addr, MDNS_PORT),
    };
    queries.iter().all(|query| query.encode().is_ok_and(|bytes| send_to(&out.socket, &bytes, dest).is_ok()))
}

/// Ask `queries` of the device at link-local address `ll`, for the kernel to
/// look up its link-layer address. Failing to send is no matter: the next
/// time will do.
fn nudge(outbound: &[Outbound], ll: IpAddr, queries: &[Message]) {
    ask_at(outbound, ll, queries);
}

/// Where to ask `device` directly, over one of `families`: a routable
/// address, IPv4 first, else a link-local one.
fn direct_address(device: &Device, families: &[Family]) -> Option<IpAddr> {
    let allowed = |a: &IpAddr| families.contains(&family_of(*a));
    let routable = || device.routable().filter(allowed);
    routable().find(IpAddr::is_ipv4).or_else(|| routable().next()).or_else(|| device.link_local().find(allowed))
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
        if let Err(e) = send_to(&out.socket, &bytes, out.dest) {
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
    send_to(&out.socket, &msg.encode()?, dest).with_context(|| format!("sending to {dest}"))?;
    Ok(())
}

/// Send the datagram `bytes` to `dest` on `socket`.
fn send_to(socket: &Sender, bytes: &[u8], dest: SocketAddr) -> Result<(), Why> {
    socket.send_to(bytes, dest).map_err(Why)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::net::UdpSocket;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::config::{DEFAULT_MAX_DEVICES, DEFAULT_MIN_LIFETIME};
    use crate::device::{addr_of, Origin, META_QUERY};
    use crate::tracker::MAX_PER_SENDER;
    use std::collections::BTreeSet;
    use crate::parser::RData;

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
    fn segment(name: &str, families: &[Family]) -> Segment {
        let seg = Segment::new(name, families);
        seg.set_min_lifetime(FLOOR);
        seg
    }

    use crate::device::{record, Service, LEGACY_TTL_CAP, QUESTIONS_PER_PACKET};
    use crate::parser::{self, rtype, Header};
    use crate::socket::prefix;
    #[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
    use crate::socket::open;

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
        let seg = segment("test", &[Family::V4]);
        let rx = seg.subscribe();
        seg.observe(ip("10.0.1.5"));
        seg.observe(ip("10.0.1.5"));
        assert_eq!(seg.devices().len(), 1);
        assert_eq!(rx.try_recv(), Ok(Event::Added(Rc::new(unnamed("10.0.1.5")))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expire_removes_and_notifies() {
        let seg = segment("test", &[Family::V4]);
        seg.observe(ip("10.0.1.5"));
        let rx = seg.subscribe();
        seg.expire(Instant::now());
        assert_eq!(seg.devices().len(), 1);
        seg.expire(Instant::now() + FLOOR + Duration::from_secs(1));
        assert!(seg.devices().is_empty());
        assert_eq!(rx.try_recv(), Ok(Event::Removed(Rc::new(unnamed("10.0.1.5")))));
    }

    /// A v4 segment whose "multicast group" is a local socket we can read.
    fn wired() -> (Segment, UdpSocket) {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seg = segment("test", &[Family::V4]);
        seg.attach(Family::V4, fd(tx), rx.local_addr().unwrap());
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
        let seg = segment("test", &[Family::V4]);
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
        assert_eq!(segment("quiet", &[Family::V4]).query_question(&questions).unwrap(), 0);
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
        assert_eq!(run_probe(&segment("quiet", &[Family::V4]), Some(&kinds)).0, Ok(0));
    }

    /// A way to send over IPv4 that always fails: its group is an IPv6
    /// address, which an IPv4 socket refuses at once.
    fn broken() -> (UdpSocket, SocketAddr) {
        (UdpSocket::bind("127.0.0.1:0").unwrap(), "[::1]:5353".parse().unwrap())
    }

    /// Give `seg` a working way to send again, to `rx`.
    fn repair(seg: &Segment, rx: &UdpSocket) {
        seg.attach(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap());
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
        seg.attach(Family::V4, fd(socket), dest);
        let err = seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap_err();
        assert!(format!("{err:#}").contains("sending to [::1]:5353"), "{err:#}");
        assert!(seg.manual_devices().is_empty());
        assert!(seg.state.borrow_mut().manual.is_empty(), "nothing left behind");

        repair(&seg, &rx);
        assert!(seg.add_manual(Owner::Reflector(0), tv("10.0.2.9", &["TV"])).unwrap());
        recv(&rx).unwrap();

        let (socket, dest) = broken();
        seg.attach(Family::V4, fd(socket), dest);
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
        seg.attach(Family::V4, fd(socket), dest);
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
        seg.attach(Family::V4, fd(socket), dest);
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
        seg.attach(Family::V4, fd(socket), dest);
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
        let seg = segment("test", &[Family::V4, Family::V6]);
        let (socket, dest) = broken();
        seg.attach(Family::V4, fd(socket), dest);
        seg.attach(Family::V6, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap());
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
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        assert!(matches!(events.try_recv(), Ok(Event::Updated { after: d, .. }) if d.has_addr(&ip("2001:db8:2::73"))));
        // A packet from a learned address is the device's.
        let state = seg.state.borrow();
        let holder = state.tracker.discovered.holder_of(&ip("2001:db8:2::73")).map(|id| state.tracker.discovered.get(id).device.hostname.clone());
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
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        let seg = segment("test", &[Family::V4]);
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
        assert!(device("speakers.local").services.iter().all(|s| s.kind == "_raop._tcp.local"), "{:?}", device("speakers.local").services);
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
        let seg = segment("test", &[Family::V4]);
        hear(&seg, "10.0.0.1", vec![
            ptr("_raop._tcp.local", "Speakers._raop._tcp.local"),
            srv("Speakers._raop._tcp.local", 7000, "speakers.local"),
            ptr("_ssh._tcp.local", "router._ssh._tcp.local"),
        ]);
        let speakers = |seg: &Segment| seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("speakers.local")).unwrap();
        assert!(speakers(&seg).services.iter().all(|s| s.kind == "_raop._tcp.local"), "{:?}", speakers(&seg).services);
        // Held where it was heard from, by address, until it says whose it is.
        let by_address = seg.devices().into_iter().find(|d| d.hostname.is_none() && d.service("router._ssh._tcp.local").is_some());
        assert!(by_address.is_some(), "{:?}", seg.devices());

        // The router says whose: its own, with its address.
        hear(&seg, "10.0.0.1", vec![a_record("router.local", "10.0.0.1"), srv("router._ssh._tcp.local", 22, "router.local")]);
        let devices = seg.devices();
        let router = devices.iter().find(|d| d.hostname.as_deref() == Some("router.local")).unwrap();
        assert!(router.service("router._ssh._tcp.local").is_some_and(|s| s.is_resolved()));
        assert!(speakers(&seg).services.iter().all(|s| s.kind == "_raop._tcp.local"));
    }

    #[test]
    fn only_neighbour_addresses_on_the_interfaces_networks_are_learned() {
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        let seg = segment("test", &[Family::V6]);
        seg.attach(Family::V6, fd(UdpSocket::bind("[::1]:0").unwrap()), rx.local_addr().unwrap());
        let nudged = |seg: &Segment| {
            let state = seg.state.borrow();
            state.tracker.discovered.get(host_id(&state, "speakers.local")).nudged
        };
        hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9")]);
        let first = nudged(&seg).expect("nudged");
        hear(&seg, "fe80::9", vec![aaaa("speakers.local", "fe80::9")]);
        assert_eq!(nudged(&seg), Some(first), "not again so soon");

        // One with a routable IPv6 address is not.
        let seg = segment("test", &[Family::V6]);
        seg.attach(Family::V6, fd(UdpSocket::bind("[::1]:0").unwrap()), rx.local_addr().unwrap());
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
        let seg = segment("test", &[Family::V6]);
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
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        assert!(matches!(events.try_recv(), Ok(Event::Updated { after: d, .. }) if d.addrs().eq([ip("fd00::7")])));
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
    fn one_sender_may_describe_only_so_many_hosts() {
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
        for i in 0..DEFAULT_MAX_DEVICES + 20 {
            seg.observe(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i as u32 + 1)));
        }
        assert_eq!(seg.devices().len(), DEFAULT_MAX_DEVICES);
    }

    #[test]
    fn the_number_of_services_a_device_is_kept_with_can_be_set() {
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V6]);
        hear(&seg, "fe80::7", vec![a_record("tv.local", "10.0.1.7"), srv("TV._http._tcp.local", 80, "tv.local")]);
        let tv = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        assert_eq!(v4(&tv), Some(ip("10.0.1.7")));
        assert_eq!(ll6(&tv), None, "not the sender's, over IPv6");

        let seg = segment("test", &[Family::V4]);
        hear(&seg, "10.0.1.8", vec![a_record("nas.local", "0.0.0.0"), aaaa("nas.local", "fd00::8")]);
        let nas = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        assert_eq!((v4(&nas), v6(&nas)), (None, Some(ip("fd00::8"))));
    }

    /// A device that says goodbye to the temporary address it sends from,
    /// announcing the next in the same packet, is not leaving: it only gives
    /// up the one. Saying goodbye with nothing in its place, it is.
    #[test]
    fn giving_up_a_temporary_address_is_not_leaving() {
        let seg = segment("test", &[Family::V6]);
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
            let seg = segment("test", &[Family::V4, Family::V6]);
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
        seg.attach(Family::V4, fd(tx), rx.local_addr().unwrap());
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
        for host in state.manual.hosts_all() {
            state.manual.edit(&host, |m| {
                m.announced -= Duration::from_secs(secs);
                m.last_sent.v4 -= Duration::from_secs(secs);
                m.last_sent.v6 -= Duration::from_secs(secs);
            });
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
        let seg = segment("test", &[Family::V4]);
        let id = seg.probe();
        assert_eq!(seg.probed(id), Some(Ok(0)), "done at once");
        assert_eq!(seg.probed(id), None, "taken");
    }

    #[test]
    fn learned_types_are_capped() {
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4, Family::V6]);
        seg.attach(Family::V4, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx4.local_addr().unwrap());
        seg.attach(Family::V6, fd(UdpSocket::bind("127.0.0.1:0").unwrap()), rx6.local_addr().unwrap());
        (seg, rx4, rx6)
    }

    /// A device heard over IPv4 and over IPv6 is one device, with the
    /// addresses of both.
    #[test]
    fn a_segment_over_both_families_keeps_one_list() {
        let seg = segment("test", &[Family::V4, Family::V6]);
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
        let seg = segment("test", &[family]);
        seg.attach(family, fd(tx), rx.local_addr().unwrap());
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
            let seg = segment("test", &[Family::V4]);
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

    /// Whether a device with no address is worth announcing is for whoever
    /// adds it to say: its services are announced, with no address record.
    #[test]
    fn a_device_with_no_addresses_is_announced_by_its_services() {
        let (seg, rx) = wired();
        let mut none = tv("10.0.1.9", &["TV"]);
        none.addresses.clear();
        seg.add_manual(Owner::Own, none).unwrap();
        assert_eq!(seg.manual_devices().len(), 1);
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
        let seg = segment("test", &[Family::V4]);
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
    fn the_only_host_a_packet_describes_is_not_given_the_senders_address_when_it_announces_none() {
        let seg = segment("test", &[Family::V4]);
        hear(&seg, "10.0.1.9", vec![srv("Dev._http._tcp.local", 80, "dev.local")]);
        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!((devices[0].hostname.as_deref(), v4(&devices[0])), (Some("dev.local"), None));
    }

    /// A bare browse answer leaves unresolved instances on the sender. Once a
    /// later packet resolves them to their hosts they are not kept twice.
    #[test]
    fn resolved_instances_leave_the_unresolved_copy_behind() {
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        let both = [Family::V4, Family::V6];
        assert_eq!(direct_address(&device(&["fe80::1", "fd00::2", "10.0.1.3"]), &both), Some(ip("10.0.1.3")));
        assert_eq!(direct_address(&device(&["fe80::1", "fd00::2"]), &both), Some(ip("fd00::2")));
        assert_eq!(direct_address(&device(&["fe80::1"]), &both), Some(ip("fe80::1")));
        assert_eq!(direct_address(&device(&[]), &both), None);
        // Only over a family that hears what is sent to the daemon.
        assert_eq!(direct_address(&device(&["fe80::1", "fd00::2", "10.0.1.3"]), &[Family::V6]), Some(ip("fd00::2")));
        assert_eq!(direct_address(&device(&["fe80::1", "10.0.1.3"]), &[Family::V4]), Some(ip("10.0.1.3")));
        assert_eq!(direct_address(&device(&["fe80::1", "fd00::2"]), &[Family::V4]), None);
        assert_eq!(direct_address(&device(&["10.0.1.3"]), &[]), None);
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V6]);
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
        let seg = segment("test", &[Family::V6]);
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
        let seg = segment("test", &[Family::V4]);
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 290));
        assert!(!alive_after(&seg, 301));

        // A shorter floor lets that device go sooner...
        let seg = segment("test", &[Family::V4]);
        seg.set_min_lifetime(Duration::from_secs(60));
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 50));
        assert!(!alive_after(&seg, 61));

        // ...a longer one keeps it longer...
        let seg = segment("test", &[Family::V4]);
        seg.set_min_lifetime(Duration::from_secs(900));
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 890));
        assert!(!alive_after(&seg, 901));

        // ...and zero means no floor: it lives for exactly its TTL.
        let seg = segment("test", &[Family::V4]);
        seg.set_min_lifetime(Duration::ZERO);
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 8));
        assert!(!alive_after(&seg, 11));
    }

    #[test]
    fn a_ttl_longer_than_the_floor_still_wins() {
        let seg = segment("test", &[Family::V4]);
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

    /// `tv.local` saying goodbye to its address.
    fn tv_leaves(seg: &Segment) {
        hear(seg, "10.0.1.5", vec![record("tv.local".into(), true, 0, RData::A(ip("10.0.1.5").to_string().parse().unwrap()))]);
    }

    /// The device of `seg` called `host`, as a reflector is given it.
    fn shown(seg: &Segment, host: &str) -> Rc<Device> {
        let device = seg.devices().into_iter().find(|d| d.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host)));
        Rc::new(device.expect("it is there"))
    }

    /// `target` is shown the device of `origin` called `host` as it is now, by
    /// the first reflector.
    fn reflect_of(target: &Segment, origin: &Segment, host: &str) -> Result<bool> {
        target.reflect(Owner::Reflector(0), origin.interface(), shown(origin, host), None)
    }

    #[test]
    fn a_device_of_another_segment_is_announced_as_it_was_last_shown() {
        let (a, _arx) = wired();
        let (b, rx) = wired();
        tv_on(&a);
        assert_eq!(shown(&a, "TV.LOCAL").services.len(), 1);

        assert!(reflect_of(&b, &a, "tv.local").unwrap());
        assert_eq!(b.manual_devices().len(), 1);
        let m = recv(&rx).expect("announced");
        assert!(m.answers.iter().any(|r| r.name == "tv.local" && r.ttl > 0));

        // It changes where it is; what is announced changes when the reflector says.
        hear(&a, "10.0.1.5", vec![srv("Web._http._tcp.local", 81, "tv.local")]);
        assert_eq!(b.manual_devices()[0].services.len(), 1, "announced as last shown");
        assert!(reflect_of(&b, &a, "tv.local").unwrap());
        assert_eq!(b.manual_devices()[0].services.len(), 2);
        assert!(recv(&rx).is_some(), "the change is announced");
        b.state.borrow().manual.check();

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

        tv_leaves(&a);
        assert_eq!(b.manual_devices().len(), 1, "still shown: nobody has said");
        assert!(b.unreflect(Owner::Reflector(0), a.interface(), "TV.local").unwrap());
        assert!(b.manual_devices().is_empty());
        let bye = recv(&rx).expect("goodbyes");
        assert!(bye.answers.iter().all(|r| r.ttl == 0), "{bye:?}");
        assert!(b.state.borrow().manual.is_empty());
        assert!(!b.unreflect(Owner::Reflector(0), a.interface(), "tv.local").unwrap(), "nothing left");
    }

    /// Several reflectors may show a device of the same segment, each as it is
    /// to be shown by it: what is announced is what they show together,
    /// whichever came first, and each is taken back on its own.
    #[test]
    fn what_two_reflectors_show_of_a_device_of_one_segment_is_announced_together() {
        let one = Rc::new(tv("10.0.1.1", &["One"]));
        let two = Rc::new(tv("10.0.1.1", &["Two"]));
        for (first, second) in [(&one, &two), (&two, &one)] {
            let (b, _rx) = wired();
            b.reflect(Owner::Reflector(0), "ra", Rc::clone(first), None).unwrap();
            b.reflect(Owner::Reflector(1), "ra", Rc::clone(second), None).unwrap();
            let shown = b.manual_devices();
            assert_eq!(shown.len(), 1);
            assert_eq!(shown[0].services.len(), 2, "{shown:?}");
            assert_eq!(shown[0].addrs().count(), 1);

            b.unreflect(Owner::Reflector(0), "ra", "tv.local").unwrap();
            assert_eq!(b.manual_devices()[0].services.len(), 1, "the other's is left");
            b.unreflect(Owner::Reflector(1), "ra", "tv.local").unwrap();
            assert!(b.manual_devices().is_empty());
        }
    }

    /// Of devices of one name from different segments, the lowest segment's is
    /// announced, whoever shows them, and the next takes over when it goes.
    #[test]
    fn of_one_name_from_two_segments_the_lowest_is_announced_and_the_next_takes_over() {
        let (b, _rx) = wired();
        let (low, high) = (Rc::new(tv("10.0.1.1", &["Low"])), Rc::new(tv("10.0.2.2", &["High"])));
        // Shown in the order that is not the segments'.
        b.reflect(Owner::Reflector(1), "rz", Rc::clone(&high), None).unwrap();
        b.reflect(Owner::Reflector(0), "ra", Rc::clone(&low), None).unwrap();
        let shown = b.manual_devices();
        assert_eq!(shown.len(), 1);
        assert!(shown[0].addrs().eq([ip("10.0.1.1")]), "{shown:?}");

        b.unreflect(Owner::Reflector(0), "ra", "tv.local").unwrap();
        assert!(b.manual_devices()[0].addrs().eq([ip("10.0.2.2")]), "the other takes over");

        b.reflect(Owner::Reflector(0), "ra", low, None).unwrap();
        b.drop_origin(Owner::Reflector(0), "ra").unwrap();
        assert!(b.manual_devices()[0].addrs().eq([ip("10.0.2.2")]));
        b.drop_origin(Owner::Reflector(1), "rz").unwrap();
        assert!(b.manual_devices().is_empty());
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
        b.add_manual(Owner::Reflector(1), tv("10.0.9.9", &["Other"])).unwrap();
        assert_eq!(b.manual_devices().len(), 2, "tv.local has two who want it, the first one's is announced");

        b.withdraw_all(Owner::Reflector(0)).unwrap();
        let left = b.manual_devices();
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].hostname.as_deref(), Some("tv.local"), "the other owner's is announced instead");
        assert!(left[0].addrs().any(|addr| addr == ip("10.0.9.9")));
        b.state.borrow().manual.check();
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
        let err = b.reflect(Owner::Reflector(0), a.interface(), Rc::clone(&named), Some(Duration::ZERO)).unwrap_err();
        assert!(format!("{err}").contains("zero"));
        assert!(b.manual_devices().is_empty());
        // The TTL it is given is the one its address is announced with.
        b.reflect(Owner::Reflector(0), a.interface(), named, Some(Duration::from_secs(900))).unwrap();
        assert_eq!(b.state.borrow().manual["tv.local"].host_ttl, 900);
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
            "devices", "heap MiB", "query us", "new host us", "add manual us", "reannounce us", "next_due us"
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
                device.services[0].instance = format!("X{added}._http._tcp.local");
                seg.add_manual(Owner::Reflector(0), device).unwrap();
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
        seg.add_manual(Owner::Own, tv("10.0.9.9", &["TV"])).unwrap();
        let announced = seg.state.borrow_mut().manual["tv.local"].announced;
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)).min(Some(announced + ANNOUNCE_REPEAT)));
        seg.state.borrow_mut().manual.edit("tv.local", |m| m.retry = Some(announced + Duration::from_secs(500)));
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
        let seg = segment("test", &[Family::V4]);
        seg.observe(ip("10.0.1.99"));
        let bare = seg.devices().remove(0);
        assert_eq!((bare.ttl, bare.services.len()), (None, 0));
    }

    #[test]
    fn a_segment_that_cannot_send_has_nothing_to_refresh() {
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
        seg.observe(ip("10.0.1.5"));
        seg.observe(ip("10.0.1.6"));
        assert_eq!(seg.take_events().len(), 2);
        assert!(seg.take_events().is_empty(), "taken");
        assert!(seg.is(&seg.clone()) && !seg.is(&segment("test", &[Family::V4])));
    }

    /// Service types learned from the enumeration are one per type, whatever
    /// their case.
    #[test]
    fn service_types_are_learned_once_whatever_their_case() {
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        let seg = segment("test", &[Family::V4]);
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
        assert!(matches!(rx.try_recv(), Ok(Event::Updated { after: d, .. }) if d.services.is_empty()));
        assert_eq!(seg.devices().len(), 1);
    }

    #[test]
    fn address_goodbye_removes_device() {
        let seg = segment("test", &[Family::V4]);
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        let rx = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(0)).unwrap();
        assert!(seg.devices().is_empty());
        assert!(matches!(rx.try_recv(), Ok(Event::Removed(_))));
    }

    #[test]
    fn long_ttl_extends_lifetime() {
        let seg = segment("test", &[Family::V4]);
        seg.handle(sa("10.0.1.7"), &announcement(4500)).unwrap();
        seg.expire(Instant::now() + FLOOR + Duration::from_secs(1));
        assert_eq!(seg.devices().len(), 1);
        seg.expire(Instant::now() + Duration::from_secs(4501));
        assert!(seg.devices().is_empty());
    }

    #[test]
    fn garbage_still_counts_as_alive() {
        let seg = segment("test", &[Family::V4]);
        seg.handle(sa("10.0.1.5"), b"\xff\xff not dns").unwrap();
        assert_eq!(seg.devices().len(), 1);
    }

    #[test]
    fn query_records_are_ignored() {
        let seg = segment("test", &[Family::V4]);
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
            let sock = open(&iface, family, false).unwrap();
            // Let a listener on this same host hear it.
            match family {
                Family::V4 => rustix::net::sockopt::set_ip_multicast_loop(&sock.socket, true).unwrap(),
                Family::V6 => rustix::net::sockopt::set_ipv6_multicast_loop(&sock.socket, true).unwrap(),
            }
            let seg = segment(&iface, &[family]);
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
    #[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
    #[test]
    #[ignore]
    fn live_respond() {
        let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
        let sock = open(&iface, Family::V4, false).unwrap();
        rustix::net::sockopt::set_ip_multicast_loop(&sock.socket, true).unwrap();
        let seg = segment(&iface, &[Family::V4]);
        let (tx, dest) = sock.sender().unwrap();
        seg.attach(Family::V4, tx, dest);
        seg.add_manual(Owner::Own, tv("10.9.9.9", &["LiveTV"])).unwrap();
        age(&seg, 2);

        // SAFETY: a descriptor given up by its owner.
        let udp: UdpSocket = unsafe { std::os::fd::FromRawFd::from_raw_fd(rustix::fd::IntoRawFd::into_raw_fd(sock.socket)) };
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
