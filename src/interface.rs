//! The devices on one interface, and what the daemon says and asks there.
//!
//! An [`Interface`] keeps a model of the link rather than its packets: the
//! devices heard on it, with their addresses and services, the ones reflected
//! onto it from elsewhere, and what is wanted announced under their names. It
//! answers for them, announces, probes and refreshes them, and forgets them
//! as they expire, sending through the [`Link`](crate::listener::Link) attached
//! to it. Which interfaces reflect to each other is for the
//! [`Segment`](crate::segment::Segment).

use core::fmt;
use alloc::collections::{BTreeSet, VecDeque};

use hashbrown::{DefaultHashBuilder, HashMap};
use core::net::{IpAddr, SocketAddr};

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::time::Duration;

use crate::time::Instant;

use anyhow::{anyhow, bail, Result};

use crate::config::{Advertise, AdvertiseConfig};
use crate::device::{
    family_of, is_link_local, is_type, responses, service_ttl, Advertised, Device, ServiceParts, Shared,
    DEFAULT_MAX_PACKET, HOST_TTL, MIN_REFLECT_TTL, OTHER_TTL,
};
use crate::listener::{Family, Link, Prefix, MDNS_PORT};
use crate::codec::{Message, Question, Record};

use crate::prelude::*;

use crate::table::{hash_name, Id, Multi, Table};
use crate::tracker::{refresh_gap, Touched, Tracker, MAX_TYPES};

/// Re-announce a reflected device at 80% of the shortest TTL it advertises,
/// on an interface that re-announces what has not changed.
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

/// A question put to an interface on another's behalf is not put to it again
/// within this long: clients ask again after a second, and several ask alike.
const FORWARD_GAP: Duration = Duration::from_secs(1);

/// Questions remembered per interface as just put to it, so that a client
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

/// A question asked on an interface, as passed on to the segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub question: Question,
    /// Whether something announced here has an answer to it already. For a
    /// browse, that is one answer, not necessarily all of them.
    pub answered: bool,
}

/// Something an interface's timer is waiting to do: see [`Interface::pending`].
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

/// The priority of what is made for an interface, such as the daemon's own name
/// (`[Advertise]`): it comes first of all, ahead of any device of another
/// interface, which has that interface's priority, above this.
pub const OWN: u32 = 0;

/// What a [`Reflected`] is told apart by: where its device and its [`Advertise`] are.
type ReflectedKey = (usize, usize);

/// A device reflected here, which is a wish to have it announced: the device
/// itself, held where it is heard and so as it is now, and how much of it to
/// show. It is told apart by the device, which is the same device however it
/// changes, and by how it is to be shown, which is a segment's own (another
/// may show the same device otherwise); the segment says when to look at it
/// again. What a host last announced ([`Host::shown`]) is one too, of a copy of
/// the device, which [`Reflected::frozen`] makes.
#[derive(Clone)]
struct Reflected {
    /// Which wins where the same hostname is wanted announced by more than
    /// one: the lowest. What is made for the interface comes first of all, with
    /// [`OWN`]; a copy of a device of another interface has that interface's
    /// priority, which is above. Copies of the same interface's device (the same
    /// priority) are shown together.
    priority: u32,
    device: Shared,
    /// The addresses and services to show of it.
    how: Rc<Advertise>,
    /// The TTL of its address records, if given, or else its own.
    host_ttl: Option<u32>,
}

impl Reflected {
    /// What it is, for finding it again: where its device and its way of
    /// being shown are, which is unique while it holds them.
    fn key(&self) -> ReflectedKey {
        (self.device.addr(), Rc::as_ptr(&self.how) as usize)
    }

    /// Where it sorts: the first of those reflected under a hostname wins.
    fn order(&self) -> (u32, ReflectedKey) {
        (self.priority, self.key())
    }

    /// The TTL its address records are announced with.
    fn host_ttl(&self) -> u32 {
        self.host_ttl.unwrap_or_else(|| self.device.borrow().ttl.map_or(HOST_TTL, |ttl| ttl.max(MIN_REFLECT_TTL)))
    }

    /// The hostname it is announced under, in lowercase.
    fn host(&self) -> Option<String> {
        self.device.borrow().key()
    }

    /// A device as it was when it was announced, so that what is no longer
    /// so can be said goodbye to: of `device`, a copy that nothing else holds,
    /// shown as `how` says with `host_ttl`, of the `priority` it won with.
    fn frozen(device: Shared, priority: u32, how: Rc<Advertise>, host_ttl: u32) -> Reflected {
        Reflected { priority, device, how, host_ttl: Some(host_ttl) }
    }

    fn has_name(&self, name: &str) -> bool {
        self.device.borrow().has_name(&self.how, name)
    }

    fn for_each_name(&self, f: impl FnMut(&str)) {
        self.device.borrow().for_each_name(&self.how, f);
    }

    /// The device with only the addresses and services it is shown with: for
    /// what is reported of it, not for what is announced.
    fn made(&self) -> Device {
        let device = self.device.borrow();
        Device {
            addresses: device.advertised(&self.how).copied().collect(),
            services: device.advertised_services(&self.how).cloned().collect(),
            ..device.clone()
        }
    }
}

/// The priority of the next interface made, if it is not set.
static NEXT_PRIORITY: AtomicU32 = AtomicU32::new(1);

/// A hostname announced on behalf of somewhere else, plus the timing needed
/// to keep it announced.
struct Host {
    /// The hostname, in lowercase: what it is told apart by.
    host: Box<str>,
    /// What is reflected under this hostname, the winner first; empty
    /// only while what was shown is still to be withdrawn. See
    /// [`State::wanted`] for what is.
    reflected: Vec<Reflected>,
    /// What is announced: what the winner was, less what devices on this
    /// interface have themselves (see [`State::wanted`]). `None` while a device
    /// here has the hostname.
    shown: Option<Reflected>,
    /// When the full record set was last multicast; drives re-announcement.
    announced: Instant,
    /// Whether that was what changed, still to be announced a second time
    /// ([`ANNOUNCE_REPEAT`]).
    repeat: bool,
    /// When any of its records was last multicast; drives the rate limit.
    last_sent: Instant,
    /// Not before this, after sending failed.
    retry: Option<Instant>,
    /// The TTL it is announced with, of the records that are not its address.
    other_ttl: u32,
    /// What the tables that find it hold of it.
    held: Held,
}

impl Host {
    fn new(host: &str, now: Instant) -> Host {
        Host {
            host: host.to_ascii_lowercase().into(),
            reflected: Vec::new(),
            shown: None,
            announced: now,
            repeat: false,
            last_sent: now,
            retry: None,
            other_ttl: OTHER_TTL,
            held: Held::default(),
        }
    }

    /// The shortest TTL anything of it is announced with: it has to be
    /// announced again before that runs out.
    fn shortest_ttl(&self) -> u32 {
        let mut shortest = self.host_ttl();
        if let Some(shown) = &self.shown {
            for svc in shown.device.borrow().advertised_services(&shown.how) {
                shortest = shortest.min(service_ttl(svc, self.other_ttl));
            }
        }
        shortest
    }

    /// The TTL its address records are announced with.
    fn host_ttl(&self) -> u32 {
        self.shown.as_ref().map_or(HOST_TTL, Reflected::host_ttl)
    }

    /// When it is next due for re-announcing, or for another try after
    /// sending failed; `None` if nothing is shown and nothing is pending.
    /// What changed is announced a second time; what has not, only if the
    /// interface re-announces `unchanged` ones.
    fn reannounce_at(&self, unchanged: bool) -> Option<Instant> {
        let after = |gap: Duration| self.announced.checked_add(gap).unwrap_or(self.announced);
        let due = |_: &Reflected| match (self.repeat, unchanged) {
            (true, _) => Some(after(ANNOUNCE_REPEAT)),
            (false, true) => Some(after(reannounce_after(self.shortest_ttl()))),
            (false, false) => None,
        };
        self.retry.or_else(|| self.shown.as_ref().and_then(due))
    }
}

/// The interface's upkeep (expiry, refreshing and re-announcing): when the
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
    /// ([`Interface::probed`]), if anyone did.
    id: u64,
    asked: bool,
    /// The next round, or [`PROBE_GAPS`]'s length when only the wait for the
    /// last answers is left.
    round: usize,
    next: Instant,
    sent: usize,
}

/// How an interface's upkeep has run, for `timers`.
pub struct UpkeepInfo {
    pub due: Option<Instant>,
    pub running: bool,
    pub runs: u64,
    pub last_run: Option<Instant>,
    pub last_took: Option<Duration>,
}

// The devices an interface announces, each held in one place, and how they are
// found.
//
// A device is kept (in a [`Table`]) and called by its [`Id`]. It is found by
// its hostname, which is among the names it, or anyone who wants it announced,
// has records under, and by when it is next due to be announced again. Like
// those of the discovered devices ([`Devices`](crate::tracker::Devices)) the
// tables hold hashes, times and ids, and follow a device when it is changed by
// [`Hosts::edit`], or goes. A device that nobody wants announced and that is
// not shown is gone, as it has nothing to be found by.

impl Host {
    /// Put `reflected` where it sorts, in place of the one of its key, which is
    /// returned. A few at most, so a list with room for just
    /// those.
    fn put(&mut self, reflected: Reflected) -> Option<Reflected> {
        let replaced = self.take(reflected.key());
        let at = self.reflected.binary_search_by_key(&reflected.order(), Reflected::order).unwrap_or_else(|at| at);
        self.reflected.reserve_exact(1);
        self.reflected.insert(at, reflected);
        replaced
    }

    fn take(&mut self, key: ReflectedKey) -> Option<Reflected> {
        let at = self.reflected.iter().position(|m| m.key() == key)?;
        let reflected = self.reflected.remove(at);
        if self.reflected.is_empty() {
            self.reflected = Vec::new();
        } else {
            self.reflected.shrink_to_fit();
        }
        Some(reflected)
    }

    /// Whether nothing of it is wanted or shown.
    fn gone(&self) -> bool {
        self.reflected.is_empty() && self.shown.is_none()
    }
}

/// What the tables hold of one: the hashes of the names it, or any claim on
/// it, has records under, and when it is held as due. It is kept with the
/// device, not worked out again, as a claim on a device of another interface has
/// the names of that device, which can change without this being told, until
/// the segment says to look again.
#[derive(Default, Debug, PartialEq, Eq)]
struct Held {
    names: Vec<u64>,
    due: Option<Instant>,
}

#[derive(Default)]
struct Hosts {
    table: Table<Host>,
    /// Each name an announced device, or a claim on it, has records under,
    /// and the device, by the hash of the name.
    by_name: Multi,
    /// The devices by when they are next due to be announced again.
    by_due: BTreeSet<(Instant, Id)>,
    /// Whether devices that have not changed are announced again, which is
    /// what when they are due goes by.
    unchanged: bool,
    /// The host each reflected device is under, by its key.
    by_reflected: HashMap<ReflectedKey, Id>,
    hasher: DefaultHashBuilder,
}

impl Hosts {
    fn find(&self, host: &str) -> Option<Id> {
        let hash = hash_name(&self.hasher, host);
        let named = |id: &Id| self.table.get(*id).host.eq_ignore_ascii_case(host);
        self.by_name.under(hash).find(named)
    }

    /// The device announced as `host`, ignoring case.
    fn get(&self, host: &str) -> Option<&Host> {
        self.find(host).map(|id| self.table.get(id))
    }

    fn contains_key(&self, host: &str) -> bool {
        self.find(host).is_some()
    }

    fn iter(&self) -> impl Iterator<Item = &Host> {
        self.table.iter()
    }

    /// What the tables would hold of `host`.
    fn held_now(&self, host: &Host) -> Held {
        let mut names = vec![hash_name(&self.hasher, &host.host)];
        let hasher = &self.hasher;
        if let Some(shown) = &host.shown {
            shown.for_each_name(|name| names.push(hash_name(hasher, name)));
        }
        // What is wanted, by everyone who wants it.
        for reflected in &host.reflected {
            reflected.for_each_name(|name| names.push(hash_name(hasher, name)));
        }
        names.sort_unstable();
        names.dedup();
        Held { names, due: host.reannounce_at(self.unchanged) }
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
    fn insert(&mut self, host: Host) {
        debug_assert!(!self.contains_key(&host.host), "a hostname is announced once");
        debug_assert!(!host.gone(), "a device is wanted");
        let id = self.table.insert(host);
        self.follow(id, &Held::default());
    }

    /// Change the device announced as `host` with `f`, and have the tables
    /// follow. It is gone when nothing of it is wanted or shown any more.
    fn edit<R>(&mut self, host: &str, f: impl FnOnce(&mut Host) -> R) -> Option<R> {
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
    fn drop(&mut self, id: Id, held: &Held) -> Host {
        self.by_name.move_between(id, &held.names, &[]);
        if let Some(at) = held.due {
            self.by_due.remove(&(at, id));
        }
        self.table.remove(id)
    }

    /// Put `reflected` among those wanted announced as `host` (lowercase), in
    /// place of one of the same key under the same name. Returns
    /// that one. A device that was under another name is not taken from there:
    /// [`take`](Hosts::take) it first.
    fn put(&mut self, host: &str, reflected: Reflected, now: Instant) -> Option<Reflected> {
        let key = reflected.key();
        let replaced = match self.find(host) {
            Some(_) => self.edit(host, |h| h.put(reflected)).flatten(),
            None => {
                let mut h = Host::new(host, now);
                h.put(reflected);
                self.insert(h);
                None
            }
        };
        let id = self.find(host).expect("it was just put");
        self.by_reflected.insert(key, id);
        replaced
    }

    /// Where the device reflected with `key` is: the hostname it was put under.
    fn locate(&self, key: ReflectedKey) -> Option<String> {
        self.by_reflected.get(&key).map(|&id| self.table.get(id).host.to_string())
    }

    /// Take back the device reflected with `key` from the host it is under. The host
    /// goes if nothing of it is shown.
    fn take(&mut self, key: ReflectedKey) -> Option<(String, Reflected)> {
        let host = self.locate(key)?;
        self.by_reflected.remove(&key);
        let reflected = self.edit(&host, |h| h.take(key)).flatten()?;
        Some((host, reflected))
    }

    /// Take back the devices reflected under `host` that `taken` says.
    fn take_where(&mut self, host: &str, taken: impl Fn(&Reflected) -> bool) -> Vec<Reflected> {
        let keys: Vec<ReflectedKey> = self.get(host).map(|h| h.reflected.iter().filter(|m| taken(m)).map(Reflected::key).collect()).unwrap_or_default();
        keys.into_iter().filter_map(|key| self.take(key)).map(|(_, reflected)| reflected).collect()
    }

    /// The devices that have, or that someone wants to have, records under
    /// `name`, ignoring case.
    fn with_claimed_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Host> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name.under(hash).map(|id| self.table.get(id)).filter(move |host| {
            host.reflected.iter().any(|m| m.has_name(name))
                || host.shown.as_ref().is_some_and(|shown| shown.has_name(name))
        })
    }

    /// The devices that are announced with records under `name`, ignoring case.
    fn with_shown_name<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Host> + 'a {
        let hash = hash_name(&self.hasher, name);
        self.by_name
            .under(hash)
            .map(|id| self.table.get(id))
            .filter(move |host| host.shown.as_ref().is_some_and(|shown| shown.has_name(name)))
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

    fn hosts<'a>(&self, found: impl Iterator<Item = &'a Host>) -> Vec<String> {
        let mut hosts: Vec<String> = found.map(|h| h.host.to_string()).collect();
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
            let entry = self.table.get(id);
            let host = &*entry.host;
            assert!(!entry.gone(), "a device is wanted or shown: {host}");
            assert_eq!(self.find(host), Some(id), "a hostname is announced once: {host}");
            let held = &entry.held;
            names += held.names.len();
            assert!(held.names.iter().all(|&h| self.by_name.holds(h, id)), "a name is held: {host}");
            if let Some(at) = held.due {
                due += 1;
                assert!(self.by_due.contains(&(at, id)), "it is held as due: {host}");
            }
            // What was held is what it would be now, but for a device of another
            // interface that changed since.
            let now = self.held_now(entry);
            assert_eq!(held.due, now.due, "it is held as due as it is: {host}");
            if entry.reflected.iter().all(|m| m.priority == 0) {
                assert_eq!(held.names, now.names, "its names are held as they are: {host}");
            }
        }
        assert_eq!((self.by_name.pairs, self.by_due.len()), (names, due));
    }
}

#[cfg(test)]
impl Hosts {
    fn is_empty(&self) -> bool {
        self.table.len() == 0
    }
}

#[cfg(test)]
impl core::ops::Index<&str> for Hosts {
    type Output = Host;

    fn index(&self, host: &str) -> &Host {
        self.get(host).expect("no such device")
    }
}

#[derive(Default)]
struct State {
    /// What is known of the devices heard here.
    tracker: Tracker,
    /// Devices we announce on this interface on behalf of somewhere else, by
    /// lowercase hostname.
    hosts: Hosts,
    /// Changes not yet taken by the event loop ([`Interface::take_events`]).
    outbox: Vec<Event>,
    /// See [`Interface::priority`].
    priority: u32,
    /// How what is made for the interface is shown: all of it.
    own: Rc<Advertise>,
    /// The probes and queries for types under way, the number of the last
    /// one started, and how those asked for went, by number, until taken.
    probing: Vec<Probing>,
    probes_started: u64,
    probed: VecDeque<(u64, Probed)>,
    /// How often to probe on its own, if at all, and when next.
    probe_interval: Option<Duration>,
    /// The service types every probe asks for besides those learned: the ones
    /// the configuration names, which no device can add to.
    probe_types: Vec<String>,
    next_routine: Option<Instant>,
    /// What it hears and says with: all that it knows of how it is reached.
    /// Until it has one it says nothing and hears nothing.
    link: Rc<Link>,
    /// Whether what is announced here is announced again before its TTL runs
    /// out though it has not changed. It need not be: whoever still wants it
    /// asks again (RFC 6762 section 5.2), and is answered.
    reannounce: bool,
    /// The most a packet sent here may hold: what the interface's MTU leaves.
    max_packet: usize,
    upkeep: Upkeep,
    /// The questions put to this interface on another's behalf, in lowercase,
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
            self.hosts.check();
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
            nudge(&self.link, ll, &Device::refresh_queries(core::slice::from_ref(&device), self.max_packet));
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

    /// The next time [`Interface::expire`], [`Interface::refresh`] or
    /// [`Interface::reannounce`] has something to do, or `None` if never. A time
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
        if let Some(at) = self.hosts.next_due() {
            see(at);
        }
        next
    }

    /// Have the devices go by how long before they run out they are asked to
    /// answer again, when that, or whether there is a way to ask, changed.
    fn sync_refresh(&mut self) {
        let before = self.upkeep.before.filter(|_| !self.link.is_empty());
        self.tracker.discovered.set_refresh(before);
    }

    /// Every time something is due, as what is to be done (`expire`,
    /// `refresh` or `re-announce`), to whom, and when. What
    /// [`State::next_due`] and [`Interface::pending`] are made of.
    fn for_each_deadline(&self, f: &mut dyn FnMut(&'static str, &dyn fmt::Display, Instant)) {
        let before = self.upkeep.before;
        for e in self.tracker.discovered.iter() {
            let hostname = e.device.borrow().hostname.clone();
            let who: &dyn fmt::Display = match &hostname {
                Some(host) => host,
                None => &e.from,
            };
            f("expire", who, e.expires);
            // Its addresses that run out before it does, each on its own.
            for (addr, &at) in e.addr_expires.iter().filter(|&(_, at)| *at < e.expires) {
                f("expire", &Labelled(who, addr), at);
            }
            if let Some(at) = before.filter(|_| !self.link.is_empty()).and_then(|before| e.refresh_due(before)) {
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
        for m in self.hosts.iter() {
            if let Some(at) = m.reannounce_at(self.reannounce) {
                // By the name as announced.
                let name = m.shown.as_ref().and_then(|d| d.device.borrow().hostname.clone());
                f("re-announce", &name.as_deref().unwrap_or(&m.host), at);
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


    /// Whether a device on this interface offers a service called `instance`,
    /// ignoring case.
    fn is_local(&self, instance: &str) -> bool {
        self.tracker.discovered.with_name(instance).any(|e| e.device.borrow().service(instance).is_some())
    }

    /// What should be announced as `key`: the winning device, less the
    /// services whose instance names devices here have, or nothing if a device
    /// here has the hostname. Announced on top of a device here, a copy would
    /// be a conflict, and the device would rename itself. The advertised name
    /// is ours, and announced whatever is here.
    fn wanted(&self, key: &str, host: &Host) -> Option<Reflected> {
        let first = host.reflected.first()?;
        // What other interfaces' devices of the name there are: the lowest
        // interface's is announced, as everyone who reflects it shows it, and
        // those who show the same interface's device show it together. One made
        // for it is shown alone.
        let group: Vec<&Reflected> = match first.priority {
            OWN => vec![first],
            priority => host.reflected.iter().take_while(|m| m.priority == priority).collect(),
        };
        let host_ttl = group.iter().map(|m| m.host_ttl()).max()?;
        let shown = match group[..] {
            [only] => {
                // What was shown stays if it is what it would be, not a copy of it again.
                let live = only.device.borrow();
                let same = host.shown.as_ref().filter(|s| s.how == only.how && s.device.borrow().same_but_ttl(&live));
                let device = same.map_or_else(|| Shared::new(live.clone()), |s| s.device.clone());
                Reflected::frozen(device, only.priority, Rc::clone(&only.how), host_ttl)
            }
            [first, ref rest @ ..] => {
                let mut device = first.device.borrow().clone();
                let mut how = Rc::clone(&first.how);
                for next in rest {
                    device = device.union(&how, &next.device.borrow(), &next.how);
                    how = Rc::new(Advertise::ALL);
                }
                Reflected::frozen(Shared::new(device), first.priority, how, host_ttl)
            }
            [] => return None,
        };
        if first.priority == OWN {
            return Some(shown);
        }
        if self.tracker.discovered.contains_host(key) {
            return None;
        }
        let local = |instance: &str| self.is_local(instance);
        let without = match shown.device.borrow().without(&local) {
            Cow::Owned(without) => Some(without),
            Cow::Borrowed(_) => None,
        };
        Some(Reflected { device: without.map_or(shown.device, Shared::new), ..shown })
    }

    /// Put `reflected` among what is wanted announced, and settle what is
    /// announced. Returns whether anything was sent. If sending fails nothing
    /// is recorded.
    fn put(&mut self, reflected: Reflected, now: Instant) -> Result<bool> {
        let key = reflected.key();
        let Some(host) = reflected.host() else {
            bail!("a reflected device needs a hostname to announce");
        };
        // A device that was renamed is taken from under the name it had, and
        // that is settled on its own.
        let renamed = self.hosts.locate(key).is_some_and(|old| old != host);
        if renamed {
            let (old, taken) = self.hosts.take(key).expect("it was found");
            self.settled(&old, vec![taken])?;
        }
        let replaced = self.hosts.put(&host, reflected, now);
        match self.settle(&host, now) {
            Ok(sent) => Ok(sent || renamed),
            Err(e) => {
                // Put back what was there, which leaves nothing if nothing was.
                self.hosts.take(key);
                if let Some(replaced) = replaced {
                    self.hosts.put(&host, replaced, now);
                }
                Err(e)
            }
        }
    }

    /// Settle what is announced as `host` after `taken` were taken from it,
    /// and put them back if sending fails. Returns whether there were any.
    fn settled(&mut self, host: &str, taken: Vec<Reflected>) -> Result<bool> {
        if taken.is_empty() {
            return Ok(false);
        }
        let now = Instant::now();
        if let Err(e) = self.settle(host, now) {
            for reflected in taken {
                self.hosts.put(host, reflected, now);
            }
            return Err(e);
        }
        Ok(true)
    }

    /// Bring what is announced as `key` in line with [`State::wanted`], with
    /// goodbyes for what is no longer to be, and forget it once nobody wants
    /// it and nothing of it is shown. Returns whether anything was sent. If
    /// sending fails, nothing changes.
    fn settle(&mut self, key: &str, now: Instant) -> Result<bool> {
        let Some(m) = self.hosts.get(key) else {
            return Ok(false);
        };
        let want = self.wanted(key, m);
        // Each with the TTL its address is announced with.
        let (old_device, new_device) = (m.shown.as_ref().map(|s| s.device.borrow()), want.as_ref().map(|s| s.device.borrow()));
        let old = m.shown.as_ref().zip(old_device.as_deref()).map(|(s, device)| Advertised { device, how: &s.how, host_ttl: s.host_ttl() });
        let new = want.as_ref().zip(new_device.as_deref()).map(|(s, device)| Advertised { device, how: &s.how, host_ttl: s.host_ttl() });
        let host_here = self.tracker.discovered.contains_host(key);
        let records = Device::transition(old, new, &|instance| self.is_local(instance), host_here);
        drop((old_device, new_device));
        let sent = !records.is_empty();
        if sent {
            send(&self.link, self.max_packet, &records)?;
        }

        // Gone, if nobody wants it and nothing of it is shown.
        self.hosts.edit(key, |m| {
            if sent {
                m.announced = now;
                m.repeat = true;
                m.last_sent = now;
                m.retry = None;
            }
            m.shown = want;
        });
        Ok(sent)
    }

    /// The questions of `query` that are not about a name a device here owns
    /// (it answers for itself), each with whether something announced here
    /// has an answer to it: those the other interfaces might be asked. None
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
                let answered = self.hosts.with_shown_name(&q.name).any(|m| m.shown.as_ref().is_some_and(|d| d.device.borrow().knows(&d.how, q)));
                Asked { question: q.clone(), answered }
            })
            .collect()
    }

    /// The devices this interface answers queries for, by hostname: what is
    /// shown of each, with the TTL its address is announced with. Left out
    /// are those multicast less than a second ago (RFC 6762 section 6), unless
    /// the reply is to go to a `legacy` resolver alone, and, for a device
    /// `probing` for names it is about to take, the reflected copies: it would
    /// take them for a conflict, and once it announces, the copy gives way.
    /// The daemon's own name answers a probe however recently it went out:
    /// that answer defends it, which section 6 exempts from the wait.
    fn answering(&self, query: &Message, now: Instant, legacy: bool, probing: bool) -> Vec<(String, Reflected)> {
        // Only those with records under a name asked for can answer.
        let mut keys: Vec<String> = query.questions.iter().flat_map(|q| self.hosts.hosts_showing(&q.name)).collect();
        keys.sort_unstable();
        keys.dedup();
        let mut out = Vec::new();
        for key in keys {
            let Some(m) = self.hosts.get(&key) else { continue };
            let Some(device) = &m.shown else { continue };
            if probing && m.reflected.first().map(|m| m.priority) != Some(OWN) {
                continue;
            }
            if !legacy && !probing && now.saturating_duration_since(m.last_sent) < MIN_MULTICAST_GAP {
                continue;
            }
            out.push((key, device.clone()));
        }
        out
    }

    /// [Settle](State::settle) the announced hostnames that someone wants
    /// records under one of `names` for, after the devices on this interface
    /// that had them changed: the others are as they were. One that fails to
    /// send is tried again by [`Interface::reannounce`], which reports it if it
    /// fails again.
    fn settle_for(&mut self, names: &[String], now: Instant) {
        let mut keys: Vec<String> = names.iter().flat_map(|name| self.hosts.hosts_claiming(name)).collect();
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            if self.settle(&key, now).is_err() {
                self.hosts.edit(&key, |m| m.retry = Some(now + ANNOUNCE_RETRY));
            }
        }
    }
}

/// One interface, and the two device lists kept for it: devices discovered on
/// the wire, and devices reflected onto it, over every
/// family it serves: one list, whichever family a device was heard over.
/// Cheap to clone; clones share state, so its link, the segments spanning
/// it and the control socket can each hold one.
#[derive(Clone)]
pub struct Interface {
    interface: Rc<str>,
    state: Rc<RefCell<State>>,
}

impl Interface {
    /// The state of the interface called `interface`, to be given a link with
    /// [`attach`](Interface::attach).
    pub fn new(interface: &str) -> Interface {
        Interface {
            interface: interface.into(),
            state: Rc::new(RefCell::new(State {
                max_packet: DEFAULT_MAX_PACKET,
                own: Rc::new(Advertise::ALL),
                // Those made first win, unless told otherwise.
                priority: NEXT_PRIORITY.fetch_add(1, Ordering::Relaxed),
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
    /// fragments. Until it is told, an interface assumes a standard Ethernet
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
        state.hosts.set_unchanged(unchanged);
    }

    /// Ask devices to answer again `before` ahead of expiring, from now on;
    /// `None` (the default) does not.
    pub fn set_refresh_before(&self, before: Option<Duration>) {
        let mut state = self.state.borrow_mut();
        state.upkeep.before = before;
        state.sync_refresh();
    }

    /// When [`Interface::upkeep`] next has something to do, or `None` if never;
    /// a time in the past means it is due now.
    pub fn next_due(&self) -> Option<Instant> {
        self.state.borrow_mut().next_due(Instant::now())
    }

    /// Do what is due at `now`: drop what has run out, ask the devices about
    /// to expire to answer again, and re-announce. Run by the event loop when
    /// [`Interface::next_due`] says.
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

    /// The families it is used over: those of its link.
    pub fn families(&self) -> Vec<Family> {
        self.state.borrow().link.families()
    }

    /// Give the interface its link, replacing an earlier one. Without any (as in
    /// unit tests), what is reflected is recorded but nothing goes on the wire.
    pub fn attach(&self, link: impl Into<Rc<Link>>) {
        let mut state = self.state.borrow_mut();
        state.link = link.into();
        state.sync_refresh();
    }

    // 1. Discovered devices.

    /// Devices currently active on this interface (excludes those announced
    /// for others), as they are now.
    pub fn devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.tracker.discovered.iter().map(|e| e.device.snapshot()).collect()
    }

    /// The devices themselves, to be shown on other interfaces: each is the
    /// one this interface holds, and changes as it does.
    pub fn shared_devices(&self) -> Vec<Shared> {
        let state = self.state.borrow();
        state.tracker.discovered.iter().map(|e| e.device.clone()).collect()
    }

    /// Which interface's device wins where more than one wants the same
    /// hostname announced: the lowest. Not the same as another's.
    pub fn priority(&self) -> u32 {
        self.state.borrow().priority
    }

    /// Set [`priority`](Interface::priority). Above 0: that is a device made
    /// for an interface, which comes first of all.
    pub fn set_priority(&self, priority: u32) {
        assert!(priority > 0, "0 is for what is made for an interface");
        self.state.borrow_mut().priority = priority;
    }

    // 2. Change notifications for the discovered list.

    /// The changes to its devices since last asked, oldest first, for the
    /// event loop to hand on.
    pub fn take_events(&self) -> Vec<Event> {
        core::mem::take(&mut self.state.borrow_mut().outbox)
    }

    /// Whether `other` is this very interface, not just one of the same name.
    pub fn is(&self, other: &Interface) -> bool {
        Rc::ptr_eq(&self.state, &other.state)
    }

    /// Everything this interface's timer is waiting for, soonest first: devices
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

    /// How much longer the daemon keeps `device`, a device of this interface, if
    /// it is not heard from again, to the second; zero if it is not (or no
    /// longer) known.
    pub fn lifetime_left(&self, device: &Device) -> Duration {
        self.state.borrow_mut().lifetime_left(device)
    }

    // 3. Reflected devices, invisible to 1 and 2.

    /// Announce `device` on this interface, made for it, with `priority` (such
    /// as [`OWN`]), under its hostname. It needs a hostname and at least one
    /// address, all of this interface's family, and announces exactly the
    /// addresses it has. Its address records are announced with the TTL it
    /// announced itself with (at least ten seconds, and two minutes if it did
    /// not say), and those of its services with theirs.
    ///
    /// It is the caller's to say again when it has changed, with another
    /// call, and to withdraw with [`remove_reflected`](Interface::remove_reflected).
    ///
    /// If another wants the same hostname announced, the lower priority
    /// wins: an outranked device is only remembered, and announced once the
    /// ones ahead of it are removed. Replacing what is announced also sends
    /// goodbyes for services and addresses that are no longer there. A device
    /// on this interface comes first of all: while one has the hostname, a
    /// reflected device of that name is not announced, and services whose
    /// instance names one has are left out (the advertised name is announced
    /// regardless).
    ///
    /// Returns whether anything was sent: not if it is as it was announced.
    /// If sending fails nothing is recorded.
    pub fn add_reflected(&self, priority: u32, device: &Shared) -> Result<bool> {
        let ttl = device.borrow().ttl.map(|t| t.max(MIN_REFLECT_TTL)).unwrap_or(HOST_TTL);
        self.add_reflected_ttl(priority, device, Duration::from_secs(ttl.into()))
    }

    /// Like [`add_reflected`](Interface::add_reflected), with the address records
    /// announced for `host_ttl` (whole seconds, at least one) whatever the
    /// device says, and, if the interface re-announces, re-announced at 80% of
    /// it.
    pub fn add_reflected_ttl(&self, priority: u32, device: &Shared, host_ttl: Duration) -> Result<bool> {
        let own = Rc::clone(&self.state.borrow().own);
        self.reflect(priority, device, &own, Some(host_ttl))
    }

    /// Announce `device`, one of another interface, whose `priority` is that
    /// interface's, and is to be shown here as `how` says, with the TTL
    /// `host_ttl` for its address records, if given, or else its own. The
    /// device is held where it is heard, and so is shown as it is now:
    /// whoever shows it says again when it has changed, and withdraws it with
    /// [`remove_reflected`](Interface::remove_reflected) when it has gone. A device of the
    /// same name from the same interface that more than one shows (each with its
    /// own `how`) is announced as what they show of it together; from another
    /// interface, the lowest priority's is, and the other takes over when it
    /// goes. Returns whether anything was sent.
    pub fn reflect(&self, priority: u32, device: &Shared, how: &Rc<Advertise>, host_ttl: Option<Duration>) -> Result<bool> {
        let host_ttl = host_ttl.map(|ttl| u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX));
        if host_ttl == Some(0) {
            bail!("a TTL of zero would withdraw the device");
        }
        let reflected = Reflected { priority, device: device.clone(), how: Rc::clone(how), host_ttl };
        if reflected.host().is_none() {
            return Err(anyhow!("a reflected device needs a hostname to announce"));
        }
        self.state.borrow_mut().put(reflected, Instant::now())
    }

    /// How what is made for this interface ([`add_reflected`](Interface::add_reflected))
    /// is shown, for [`remove_reflected`](Interface::remove_reflected).
    pub fn own(&self) -> Rc<Advertise> {
        Rc::clone(&self.state.borrow().own)
    }

    /// Forget `device`, to be shown as `how` says: made for this interface (see
    /// [`own`](Interface::own)) or reflected. If that is what is announced, the
    /// next one's device takes its place, or, if there is none, goodbyes are
    /// sent for it. Returns false if there was no such device. If sending
    /// fails it is kept.
    pub fn remove_reflected(&self, how: &Rc<Advertise>, device: &Shared) -> Result<bool> {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let Some((host, reflected)) = state.hosts.take((device.addr(), Rc::as_ptr(how) as usize)) else {
            return Ok(false);
        };
        state.settled(&host, vec![reflected])
    }

    /// Forget everything that was to be shown as `how` says, with goodbyes
    /// for what is then no longer announced. Every one is tried; the first
    /// error is returned.
    pub fn withdraw_all(&self, how: &Rc<Advertise>) -> Result<()> {
        self.withdraw_where(|m| Rc::ptr_eq(&m.how, how))
    }

    /// Take the interface down: everything announced on it is withdrawn, with
    /// goodbyes, and every device found on it is forgotten, which is said by
    /// an [event](Interface::take_events) of each going, for whoever shows
    /// copies of them elsewhere to withdraw them. Once every interface is down
    /// nothing is announced of any. Every one is tried; the first error is
    /// returned.
    pub fn destroy(&self) -> Result<()> {
        self.forget_discovered();
        self.withdraw_where(|_| true)
    }

    fn withdraw_where(&self, taken: impl Fn(&Reflected) -> bool) -> Result<()> {
        let hosts: Vec<String> = {
            let state = self.state.borrow();
            state.hosts.iter().filter(|h| h.reflected.iter().any(&taken)).map(|h| h.host.to_string()).collect()
        };
        let mut first_err = None;
        for host in hosts {
            let mut guard = self.state.borrow_mut();
            let state = &mut *guard;
            let reflected = state.hosts.take_where(&host, &taken);
            if let Err(e) = state.settled(&host, reflected) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Let go of every way to send, as when the interface is gone: what is
    /// announced here is kept, to announce again once it is back.
    pub fn detach_all(&self) {
        let mut state = self.state.borrow_mut();
        state.link = Rc::default();
        state.sync_refresh();
    }

    /// Announce again everything announced here, as when the interface has
    /// come back: whoever is on it now may never have heard it. A failed send
    /// is retried by [`Interface::reannounce`].
    pub fn announce_all(&self) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let State { hosts, link, max_packet, .. } = &mut *guard;
        let mut first_err = None;
        for key in hosts.hosts_all() {
            let Some(m) = hosts.get(&key) else { continue };
            let Some(device) = &m.shown else { continue };
            let records = device.device.borrow().announcement(&device.how, device.host_ttl(), m.other_ttl);
            match send(link, *max_packet, &records) {
                Ok(()) => {
                    hosts.edit(&key, |m| {
                        m.announced = now;
                        m.repeat = true;
                        m.last_sent = now;
                        m.retry = None;
                    });
                }
                Err(e) => {
                    hosts.edit(&key, |m| m.retry = Some(now + ANNOUNCE_RETRY));
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
        // What is advertised under the name already, which is changed in place.
        let existing = self.own_device(name);
        if addrs.is_empty() {
            eprintln!("{}: no address to advertise {name} with", self.interface);
            if let Some(Err(e)) = existing.map(|existing| self.remove_reflected(&self.own(), &existing)) {
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
        let shared = existing.unwrap_or_default();
        let was = core::mem::replace(&mut *shared.borrow_mut(), device);
        match self.add_reflected_ttl(OWN, &shared, *ttl) {
            Ok(true) => {
                let shown: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
                eprintln!("{}: advertising {name} as {} (TTL {}s)", self.interface, shown.join(", "), ttl.as_secs());
            }
            Ok(false) => {}
            Err(e) => {
                // Nothing is recorded: what it was is put back.
                *shared.borrow_mut() = was;
                eprintln!("{}: not advertising {name}: {e:#}", self.interface);
            }
        }
    }

    /// The device this daemon advertises under `name` here, if it does.
    fn own_device(&self, name: &str) -> Option<Shared> {
        let state = self.state.borrow();
        let host = state.hosts.get(&name.to_ascii_lowercase())?;
        host.reflected.iter().find(|m| m.priority == OWN).map(|m| m.device.clone())
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
    pub fn own_devices(&self) -> Vec<(Shared, Duration)> {
        let state = self.state.borrow();
        state
            .hosts
            .iter()
            .filter_map(|h| h.reflected.iter().find(|m| m.priority == OWN))
            .map(|m| (m.device.clone(), Duration::from_secs(u64::from(m.host_ttl()))))
            .collect()
    }

    /// The devices announced on this interface: for each hostname, what is
    /// shown of the one that won.
    pub fn reflected_devices(&self) -> Vec<Device> {
        let state = self.state.borrow_mut();
        state.hosts.iter().filter_map(|m| m.shown.as_ref().map(Reflected::made)).collect()
    }

    /// Announce a second time what changed a second ago ([`ANNOUNCE_REPEAT`]),
    /// and, if the interface re-announces ([`Interface::set_reannounce`]), what
    /// has not had a full announcement for 80% of its TTL; and try again
    /// what failed to send. A failed send
    /// is retried after [`ANNOUNCE_RETRY`]; the first error is returned after
    /// every device was tried. Run by [`Interface::schedule`] when due.
    pub fn reannounce(&self, now: Instant) -> Result<()> {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        let mut first_err = None;
        for key in state.hosts.due(now) {
            // What is out of line is settled first, which announces it.
            let result = state.settle(&key, now).and_then(|sent| {
                let Some(m) = state.hosts.get(&key).filter(|_| !sent) else {
                    return Ok(());
                };
                let announced = match &m.shown {
                    Some(device) => {
                        send(&state.link, state.max_packet, &device.device.borrow().announcement(&device.how, device.host_ttl(), m.other_ttl))?;
                        true
                    }
                    None => false,
                };
                state.hosts.edit(&key, |m| {
                    if announced {
                        m.announced = now;
                        m.repeat = false;
                        m.last_sent = now;
                    }
                    m.retry = None;
                });
                Ok(())
            });
            if let Err(e) = result {
                state.hosts.edit(&key, |m| m.retry = Some(now + ANNOUNCE_RETRY));
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
    /// the segment to ask elsewhere.
    fn respond(&self, from: SocketAddr, query: &Message) -> Result<()> {
        let h = &query.header;
        if h.response || h.opcode != 0 || h.rcode != 0 || query.questions.is_empty() {
            return Ok(());
        }
        // Answered over the family it was asked over, with everything of
        // both: an A answer brings the AAAA records along.
        let family = family_of(from.ip());
        let now = Instant::now();

        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        // A peer asks from the port it is at, as mDNS does, whichever that is.
        let legacy = from.port() != MDNS_PORT && !state.link.is_peer(from.ip());
        let asked = state.asked(query);
        if !asked.is_empty() {
            state.notify(Event::Question(asked));
        }
        let probing = !query.authorities.is_empty();
        let answering = state.answering(query, now, legacy, probing);
        let keys: Vec<&String> = answering.iter().map(|(key, ..)| key).collect();
        let borrowed: Vec<_> = answering.iter().map(|(_, shown)| shown.device.borrow()).collect();
        let devices: Vec<Advertised> = answering
            .iter()
            .zip(&borrowed)
            .map(|((_, shown), device)| Advertised { device, how: &shown.how, host_ttl: shown.host_ttl() })
            .collect();
        let Some((msgs, answered)) = Device::query_response(&devices, query, legacy, state.max_packet) else {
            return Ok(());
        };
        for msg in &msgs {
            transmit(&state.link, family, msg, legacy.then_some(from))?;
        }

        if !legacy {
            for i in answered {
                state.hosts.edit(keys[i], |m| m.last_sent = now);
            }
        }
        Ok(())
    }

    /// Ask the devices on this interface `questions` asked on another interface,
    /// in a query of the daemon's own: nothing of the asker's packet comes
    /// here, not its address, not its known answers, not its wish for a
    /// unicast reply. Their answers are heard like any, and so reflected;
    /// the asker, asking again, is answered from that. What is known here
    /// already goes along as known answers, with the time it has left, so
    /// that only devices not yet heard of, or about to run out, answer.
    ///
    /// A question asked here within [`FORWARD_GAP`] is not asked again, nor
    /// any once [`MAX_FORWARDED`] are waiting it out. Returns how many were
    /// asked. A no-op when the interface has no sender attached.
    pub fn query_question(&self, questions: &[Question]) -> Result<usize> {
        let now = Instant::now();
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        if state.link.is_empty() {
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
        ask(&state.link, &Device::forward_queries(fresh, known, state.max_packet))
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

    /// Record that `addr` was heard on this interface, without any record data.
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
    /// heard. On a link to peers, a peer's is, and no one else's. What is sent
    /// to the group is, whoever sends it. What is sent to the
    /// daemon itself is only from a host on a network the interface is on, or
    /// link-local: one of any other address came through some router, and an
    /// interface is not where it is to be believed of devices.
    pub fn accepts(&self, from: IpAddr, to: Option<IpAddr>) -> bool {
        // On a link to peers, what they send, and nothing else: it is who it
        // is by the tunnel it came through.
        let state = self.state.borrow();
        if state.link.peered() {
            return state.link.is_peer(from);
        }
        drop(state);
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
    /// once it is done ([`Interface::probed`]). One asked for while another is
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

    /// Like [`Interface::probe`], with no one to tell but the journal: `why`
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

    /// Have every probe browse for the service types `kinds` too, from the
    /// first: those of `ProbeServices=`, for devices that never say their type.
    pub fn set_probe_types(&self, kinds: &[String]) {
        self.state.borrow_mut().probe_types = kinds.to_vec();
    }

    /// Ask for the service types `kinds` by name, in three rounds like a
    /// [probe](Interface::probe): devices that only answer when asked for
    /// their type, and do not say what types they have, are found this way.
    /// The types are remembered, so that every later probe asks for them too.
    /// What is known here already goes along as known answers, so only what
    /// is new, or about to run out, answers.
    pub fn query_types(&self, kinds: &[String]) {
        self.begin(Some(kinds.to_vec()), "query for types", false);
    }

    /// Start a probe (`kinds` `None`) or a query for types, unless the same
    /// is under way already, which it then is; its number. How it went is
    /// kept if it was `asked` for. An interface that cannot send has nothing to
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
        if state.link.is_empty() {
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
    /// when the interface has no sender attached.
    fn probe_round(&self) -> Result<usize> {
        let state = self.state.borrow_mut();
        if state.link.is_empty() {
            return Ok(0);
        }

        let devices: Vec<Device> = state.tracker.discovered.iter().map(|e| e.device.snapshot()).collect();
        let types = state.tracker.types.iter().chain(&state.probe_types).cloned().collect();
        ask(&state.link, &Device::probe_queries(&devices, &types, state.max_packet))
    }

    fn query_types_round(&self, kinds: &[String]) -> Result<usize> {
        let mut guard = self.state.borrow_mut();
        let state = &mut *guard;
        if state.link.is_empty() {
            return Ok(0);
        }
        for kind in kinds.iter().filter(|k| is_type(k)) {
            if state.tracker.types.len() < MAX_TYPES {
                state.tracker.types.insert(kind.to_ascii_lowercase());
            }
        }
        let now = Instant::now();
        let devices: Vec<Device> = state.tracker.discovered.iter().map(|e| e.device.snapshot()).collect();
        let known = |q: &Question| state.tracker.discovered.with_name(&q.name).flat_map(|e| e.known_answers(q, now)).collect();
        ask(&state.link, &Device::type_queries(&devices, kinds, known, state.max_packet))
    }

    /// Ask the devices that are about to expire to answer again, so that a
    /// quiet one (most speakers only answer when asked) is renewed just before
    /// it would be dropped, instead of being found again later.
    ///
    /// A device is due once it would expire within `before` of `now`: its
    /// lifetime is the longest TTL it announced, at least the minimum lifetime
    /// ([`Interface::set_min_lifetime`]).
    /// It is asked for what it announced (its address, and the service and text
    /// records of each instance) and not for whole service types, so only it
    /// answers. A device that does not answer is asked again after a quarter of
    /// `before` (at least five seconds) until it expires. Devices known only by
    /// the address they were heard from have nothing to ask for and are left
    /// alone, and so is one whose time has already run out. Run by
    /// [`Interface::schedule`] when due, after [`Interface::expire`]; returns how
    /// many questions were sent.
    pub fn refresh(&self, now: Instant, before: Duration) -> Result<usize> {
        let mut guard = self.state.borrow_mut();
        let State { tracker: Tracker { discovered, .. }, link, max_packet, .. } = &mut *guard;
        if link.is_empty() {
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
            let device = entry.device.snapshot();
            discovered.edit(id, |entry| entry.refreshed = Some(now));
            let direct = direct_address(&device, link).filter(|_| !retry);
            let queries = Device::refresh_queries(core::slice::from_ref(&device), *max_packet);
            match direct {
                Some(addr) if ask_at(link, addr, &queries) => asked += queries.iter().map(|q| q.questions.len()).sum::<usize>(),
                _ => asking.push(device),
            }
        }
        Ok(asked + ask(link, &Device::refresh_queries(&asking, *max_packet))?)
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
// measurement of what a full interface costs turns it off.
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
/// 6762 section 5.5), over its family. Whether all were sent. To a link-local
/// address, the kernel has to look up its link-layer address, which is what
/// [`nudge`] is for.
fn ask_at(link: &Link, addr: IpAddr, queries: &[Message]) -> bool {
    queries.iter().all(|query| query.encode().is_ok_and(|bytes| link.ask(addr, &bytes)))
}

/// Ask `queries` of the device at link-local address `ll`, for the kernel to
/// look up its link-layer address. Failing to send is no matter: the next
/// time will do.
fn nudge(link: &Link, ll: IpAddr, queries: &[Message]) {
    ask_at(link, ll, queries);
}

/// Where to ask `device` directly: a routable address the link hears the
/// answer at, IPv4 first, else a link-local one.
fn direct_address(device: &Device, link: &Link) -> Option<IpAddr> {
    let allowed = |a: &IpAddr| link.reaches(*a);
    let routable = || device.routable().filter(allowed);
    routable().find(IpAddr::is_ipv4).or_else(|| routable().next()).or_else(|| device.link_local().find(allowed))
}

/// Multicast `queries`, to everyone on the link. Returns how many questions
/// they asked.
fn ask(link: &Link, queries: &[Message]) -> Result<usize> {
    for q in queries {
        multicast(link, q)?;
    }
    Ok(queries.iter().map(|q| q.questions.len()).sum())
}

/// Announce `records`, to everyone on the link, in as many packets as it takes
/// to keep each within `limit`. Every packet is tried; the first error is
/// returned.
fn send(link: &Link, limit: usize, records: &[Record]) -> Result<()> {
    let mut first_err = None;
    for msg in responses(records, &[], limit) {
        if let Err(e) = multicast(link, &msg) {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Send `msg` to everyone on the link. A no-op when the interface has no link
/// attached.
fn multicast(link: &Link, msg: &Message) -> Result<()> {
    link.send(&msg.encode()?)
}

/// Answer over `family`: to everyone on the link, or to `dest` alone for a
/// unicast reply.
fn transmit(link: &Link, family: Family, msg: &Message, dest: Option<SocketAddr>) -> Result<()> {
    link.reply(family, dest, &msg.encode()?)
}

#[cfg(test)]
#[path = "../tests/unit/interface.rs"]
mod tests;
