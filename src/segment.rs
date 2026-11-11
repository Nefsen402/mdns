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
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::time::Duration;

use crate::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

use crate::config::{Advertise, AdvertiseConfig};
use crate::runtime::Why;
use crate::device::{
    family_of, is_link_local, is_type, responses, service_ttl, Advertised, Device, ServiceParts,
    DEFAULT_MAX_PACKET, HOST_TTL, MIN_REFLECT_TTL, OTHER_TTL,
};
use crate::socket::{Family, Prefix, Sender, MDNS_PORT};
use crate::codec::{Message, Question, Record};

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
    /// A device made for it, announced as it is (`how` is [`Advertise::ALL`]),
    /// with the TTL of its address.
    Owned { device: Rc<Device>, how: Rc<Advertise>, host_ttl: u32 },
    /// A device of another segment, as it is to be shown here, with the
    /// addresses and services `how` says, and the TTL of its address `host_ttl` if given,
    /// or else its own.
    Reflected { device: Rc<Device>, how: Rc<Advertise>, host_ttl: Option<u32> },
}

impl Claim {
    /// The device as it is to be announced, and the TTL of its address.
    fn resolve(&self) -> (Shown, u32) {
        match self {
            Claim::Owned { device, how, host_ttl } => (Shown { device: Rc::clone(device), how: Rc::clone(how) }, *host_ttl),
            Claim::Reflected { device, how, host_ttl } => {
                let ttl = host_ttl.unwrap_or_else(|| device.ttl.map_or(HOST_TTL, |ttl| ttl.max(MIN_REFLECT_TTL)));
                (Shown { device: Rc::clone(device), how: Rc::clone(how) }, ttl)
            }
        }
    }
}

/// A device as it is shown on a segment: all of it is kept, and `how` says
/// which of its addresses and services are put in the records it is
/// announced with. The
/// device is the claim's: what is shown is not a copy of it with other
/// addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Shown {
    device: Rc<Device>,
    how: Rc<Advertise>,
}

impl Shown {
    fn has_name(&self, name: &str) -> bool {
        self.device.has_name(&self.how, name)
    }

    fn for_each_name(&self, f: impl FnMut(&str)) {
        self.device.for_each_name(&self.how, f);
    }

    /// The device with only the addresses and services it is shown with: for
    /// what is reported of it, not for what is announced.
    fn made(&self) -> Device {
        Device {
            addresses: self.device.advertised(&self.how).copied().collect(),
            services: self.device.advertised_services(&self.how).cloned().collect(),
            ..(*self.device).clone()
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
    shown: Option<Shown>,
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
        let services = self.shown.iter().flat_map(|d| d.device.advertised_services(&d.how)).map(|svc| service_ttl(svc, self.other_ttl));
        services.chain([self.host_ttl]).min().unwrap_or(self.host_ttl)
    }

    /// When it is next due for re-announcing, or for another try after
    /// sending failed; `None` if nothing is shown and nothing is pending.
    /// What changed is announced a second time; what has not, only if the
    /// segment re-announces `unchanged` ones.
    fn reannounce_at(&self, unchanged: bool) -> Option<Instant> {
        let after = |gap: Duration| self.announced.checked_add(gap).unwrap_or(self.announced);
        let due = |_: &Shown| match (self.repeat, unchanged) {
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
        let mut add = |shown: &Shown| shown.for_each_name(|name| names.push(hash_name(hasher, name)));
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
                f("re-announce", &m.shown.as_ref().and_then(|d| d.device.hostname.as_deref()).unwrap_or(&m.host), at);
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
    fn wanted(&self, key: &str, m: &Manual) -> Option<(Shown, u32)> {
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
                    .reduce(|(shown, ttl), (other, other_ttl)| {
                        let both = shown.device.union(&shown.how, &other.device, &other.how);
                        (Shown { device: Rc::new(both), how: Rc::new(Advertise::ALL) }, ttl.max(other_ttl))
                    })?
            }
        };
        if self.tracker.discovered.contains_host(key) {
            return None;
        }
        let local = |instance: &str| self.is_local(instance);
        let without = match device.device.without(&local) {
            Cow::Owned(without) => Some(Rc::new(without)),
            Cow::Borrowed(_) => None,
        };
        Some((Shown { device: without.unwrap_or(device.device), how: device.how }, host_ttl))
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
        let old = m.shown.as_ref().map(|d| Device { ttl: Some(m.host_ttl), ..(*d.device).clone() });
        let new = want.as_ref().map(|(shown, host_ttl)| Device { ttl: Some(*host_ttl), ..(*shown.device).clone() });
        let host_here = self.tracker.discovered.contains_host(key);
        let old = old.as_ref().zip(m.shown.as_ref()).map(|(device, shown)| Advertised { device, how: &shown.how });
        let new = new.as_ref().zip(want.as_ref()).map(|(device, (shown, _))| Advertised { device, how: &shown.how });
        let records = Device::transition(old, new, &|instance| self.is_local(instance), host_here);
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
                Some((shown, host_ttl)) => {
                    m.shown = Some(shown);
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
                let answered = self.manual.with_shown_name(&q.name).any(|m| m.shown.as_ref().is_some_and(|d| d.device.knows(&d.how, q)));
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
    fn answering(&self, query: &Message, now: Instant, legacy: bool, probing: bool, family: Family) -> Vec<(String, Device, Rc<Advertise>)> {
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
            out.push((key, Device { ttl: Some(m.host_ttl), ..(*device.device).clone() }, Rc::clone(&device.how)));
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
        self.claim(ClaimKey::owned(owner), &key, Claim::Owned { device: Rc::new(device), how: Rc::new(Advertise::ALL), host_ttl })
    }

    /// Announce `device`, one that is on the segment of `origin` (an
    /// interface) and is to be shown here as it is given, for `owner`, with
    /// the TTL `host_ttl` for its address records, if given, or else its own,
    /// with the addresses `how` says: it keeps them all. It is the reflector's to say again when the device changes, or to
    /// withdraw it with [`unreflect`](Segment::unreflect). A device of the same
    /// name from the same segment that more than one owner shows is announced
    /// as what they show of it together; from another segment, the lowest
    /// segment's is, and the other takes over when it goes.
    pub fn reflect(&self, owner: Owner, origin: &str, device: Rc<Device>, how: Rc<Advertise>, host_ttl: Option<Duration>) -> Result<bool> {
        let Some(host) = device.key() else {
            return Err(anyhow!("a reflected device needs a hostname to announce"));
        };
        let host_ttl = host_ttl.map(|ttl| u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX));
        if host_ttl == Some(0) {
            bail!("a TTL of zero would withdraw the device");
        }
        self.claim(ClaimKey::reflected(owner, origin), &host, Claim::Reflected { device, how, host_ttl })
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
            match send(outbound, *max_packet, &device.device.announcement(&device.how, m.host_ttl, m.other_ttl)) {
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
            .map(|(kind, port)| {
                ServiceParts {
                    instance: format!("{label}.{kind}.local"),
                    kind: format!("{kind}.local"),
                    port: *port,
                    target: Some(name.clone()),
                    ..ServiceParts::default()
                }
                .into()
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
                Some(Claim::Owned { device, host_ttl, .. }) => Some(((**device).clone(), Duration::from_secs(u64::from(*host_ttl)))),
                _ => None,
            })
            .collect()
    }

    /// The devices announced on this segment: for each hostname, what is
    /// shown of the one that won.
    pub fn manual_devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.manual.iter().filter_map(|m| m.shown.as_ref().map(Shown::made)).collect()
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
                        send(&state.outbound, state.max_packet, &device.device.announcement(&device.how, m.host_ttl, m.other_ttl))?;
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
        let answering = state.answering(query, now, legacy, probing, family);
        let keys: Vec<&String> = answering.iter().map(|(key, ..)| key).collect();
        let devices: Vec<Advertised> = answering.iter().map(|(_, device, how)| Advertised { device, how }).collect();
        let Some((msgs, answered)) = Device::query_response(&devices, query, legacy, state.max_packet) else {
            return Ok(());
        };
        for msg in &msgs {
            transmit(&state.outbound, family, msg, legacy.then_some(from))?;
        }

        if !legacy {
            for i in answered {
                state.manual.edit(keys[i], |m| m.last_sent.set(family, now));
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
#[path = "../tests/unit/segment.rs"]
mod tests;
