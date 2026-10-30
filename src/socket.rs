//! Per-interface mDNS sockets.
//!
//! Each socket is pinned to a single interface and bound to the mDNS
//! multicast group address rather than the wildcard, so it shows up in
//! `ss` as `224.0.0.251%wifi:5353` and only ever sees that link's traffic.

use std::ffi::CString;
use std::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};

use crate::device::{addr_of, is_type, service_ttl, Device, Report, HOST_TTL, META_QUERY, MIN_REFLECT_TTL, OTHER_TTL};
use crate::parser::{Header, Message, Question, RData, Record};
use crate::timer::{self, Next, Timer};

pub const MDNS_PORT: u16 = 5353;
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

// Not exported by the libc crate on all versions (Linux >= 4.20).
const IPV6_MULTICAST_ALL: libc::c_int = 29;

/// Re-announce a reflected device at 80% of the shortest TTL it advertises.
fn reannounce_after(host_ttl: u32) -> Duration {
    Duration::from_secs(u64::from(host_ttl) * 4 / 5)
}
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

/// Questions remembered per segment as just put to it, so that a client
/// asking endless made-up names cannot grow the list without bound.
const MAX_FORWARDED: usize = 1024;

/// The default for how long a device is kept at least after it was last heard
/// from, whatever TTLs it announced. See [`Segment::set_min_lifetime`].
pub const DEFAULT_MIN_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

pub struct MdnsSocket {
    pub interface: String,
    pub index: u32,
    pub family: Family,
    pub socket: Socket,
}

impl MdnsSocket {
    /// A second handle on this socket for sending, plus the group address
    /// (scoped to this interface for IPv6) to send to. It keeps the source
    /// port at 5353 and the socket's interface binding.
    pub fn sender(&self) -> Result<(UdpSocket, SocketAddr)> {
        let dest = match self.family {
            Family::V4 => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
            Family::V6 => SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, self.index)),
        };
        Ok((self.socket.try_clone()?.into(), dest))
    }

    /// The address this host uses on this interface: the source address the
    /// kernel picks for traffic to the mDNS group there, which is the primary
    /// IPv4 address and, for IPv6, the link-local address. Nothing is sent.
    pub fn local_addr(&self) -> Result<IpAddr> {
        let (domain, group) = match self.family {
            Family::V4 => (Domain::IPV4, SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT))),
            Family::V6 => (
                Domain::IPV6,
                SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, self.index)),
            ),
        };
        // A throwaway socket: connecting UDP only makes the kernel choose a
        // source address, which `local_addr` then reveals.
        let probe = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        probe.bind_device(Some(self.interface.as_bytes()))?;
        probe
            .connect(&group.into())
            .with_context(|| format!("finding the address used on {}", self.interface))?;
        probe
            .local_addr()?
            .as_socket()
            .map(|a| a.ip())
            .ok_or_else(|| anyhow!("no local address on {}", self.interface))
    }
}

pub fn ifindex(name: &str) -> Result<u32> {
    let cname = CString::new(name).context("interface name contains NUL")?;
    // SAFETY: cname is a valid NUL-terminated string.
    match unsafe { libc::if_nametoindex(cname.as_ptr()) } {
        0 => bail!("no such interface: {name}"),
        idx => Ok(idx),
    }
}

pub fn open(interface: &str, family: Family) -> Result<MdnsSocket> {
    let index = ifindex(interface)?;
    let domain = match family {
        Family::V4 => Domain::IPV4,
        Family::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Share port 5353 with avahi (and anything else) during migration.
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind_device(Some(interface.as_bytes()))?;

    // Without this, the kernel delivers group traffic from *any* interface
    // joined by *any* socket on the host, defeating the per-link isolation.
    match family {
        Family::V4 => set_int(&socket, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL, 0)?,
        Family::V6 => {
            socket.set_only_v6(true)?;
            set_int(&socket, libc::IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)?;
        }
    }

    match family {
        Family::V4 => {
            socket.set_multicast_loop_v4(false)?;
            socket.set_multicast_ttl_v4(255)?;
            socket.bind(&SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)).into())?;
            socket.join_multicast_v4_n(&GROUP_V4, &InterfaceIndexOrAddress::Index(index))?;
        }
        Family::V6 => {
            socket.set_multicast_loop_v6(false)?;
            socket.set_multicast_hops_v6(255)?;
            socket.bind(
                &SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, index)).into(),
            )?;
            socket.join_multicast_v6(&GROUP_V6, index)?;
        }
    }

    Ok(MdnsSocket {
        interface: interface.to_string(),
        index,
        family,
        socket,
    })
}

fn set_int(socket: &Socket, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> Result<()> {
    // SAFETY: the fd is valid for the lifetime of `socket`, and we pass a
    // pointer to a c_int along with its exact size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// A change to the *discovered* list (manual devices never produce events),
/// or questions asked on the segment that it could not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Added(Device),
    /// Hostname or services changed.
    Updated(Device),
    Removed(Device),
    /// The questions of a query that nothing announced here has an answer
    /// to, and that no device here owns the name of: for the reflector to
    /// put to the segments whose devices it announces here
    /// ([`Segment::query_question`]).
    Question(Vec<Question>),
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
    /// When it was last asked to answer again because it was about to expire.
    refreshed: Option<Instant>,
}

impl Entry {
    fn new(now: Instant, from: IpAddr) -> Entry {
        Entry { device: Device::default(), from, expires: now, refreshed: None }
    }

    /// Whether there is anything to ask it about: a name or a service.
    fn askable(&self) -> bool {
        self.device.hostname.is_some() || !self.device.services.is_empty()
    }

    /// Take over what was learned about this device before its name was known.
    fn absorb(&mut self, earlier: Entry) {
        self.device.absorb(earlier.device);
        self.expires = self.expires.max(earlier.expires);
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

/// The family of `addr`.
fn family_of(addr: IpAddr) -> Family {
    if addr.is_ipv4() { Family::V4 } else { Family::V6 }
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
    fn reannounce_at(&self) -> Option<Instant> {
        let due = |_: &Device| self.announced.checked_add(reannounce_after(self.shortest_ttl())).unwrap_or(self.announced);
        self.retry.or_else(|| self.shown.as_ref().map(due))
    }
}

/// The entry that wakes the segment's upkeep: expiry, refreshing and
/// re-announcing.
struct Wake {
    entry: timer::Entry,
    /// How long before expiry devices are asked to answer again, if at all.
    before: Option<Duration>,
    /// When the entry was last set to wake up; `None` if it is parked.
    at: Option<Instant>,
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
    subscribers: Vec<Sender<Event>>,
    /// How to send, over each family the segment has a socket of.
    outbound: Vec<Outbound>,
    /// Service types devices on this segment have said they offer, learned
    /// from answers to the type enumeration query.
    types: BTreeSet<String>,
    /// The least a device is kept after it was last heard from.
    min_lifetime: Duration,
    /// The TTL, in seconds, of the address records of the devices
    /// [`Segment::add_manual`] announces; `None` follows each device's own.
    reflect_ttl: Option<u32>,
    wake: Option<Wake>,
    /// The questions put to this segment on another's behalf, in lowercase,
    /// and when, for [`FORWARD_GAP`].
    forwarded: HashMap<(String, u16), Instant>,
}

impl State {
    fn notify(&mut self, event: Event) {
        // A dropped receiver is an unsubscribe.
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
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
        let before = self.wake.as_ref().and_then(|w| w.before);
        for (key, e) in &self.discovered {
            let who: &dyn fmt::Display = match (&e.device.hostname, key) {
                (Some(host), _) | (None, Key::Host(host)) => host,
                (None, Key::Source(addr)) => addr,
            };
            f("expire", who, e.expires);
            let Some(before) = before.filter(|_| !self.outbound.is_empty() && e.askable()) else {
                continue;
            };
            // Due `before` ahead of expiry, and not again until the gap has
            // passed since it was last asked.
            let mut at = e.expires.checked_sub(before).unwrap_or(now);
            match e.refreshed.map(|t| t.checked_add(refresh_gap(before))) {
                Some(Some(again)) => at = at.max(again),
                Some(None) => continue, // never again
                None => {}
            }
            // A device that runs out first is dropped, not asked.
            if at < e.expires {
                f("refresh", who, at);
            }
        }
        for (name, m) in &self.manual {
            if let Some(at) = m.reannounce_at() {
                f("re-announce", name, at);
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
            send(&self.outbound, &records)?;
        }

        let m = self.manual.get_mut(key).expect("looked up above");
        if sent {
            m.announced = now;
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

    /// The questions of `query` that nothing announced here has an answer to,
    /// and that are not about a name a device here owns (it answers for
    /// itself): those to put to the other segments. None from a device
    /// probing for names it is about to take: they are its own.
    fn unknown(&self, query: &Message) -> Vec<Question> {
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
                let here = local.contains(&name) || self.discovered.contains_key(&Key::Host(name));
                !here && !shown.iter().any(|d| d.knows(q))
            })
            .cloned()
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
            if self.settle(&key, &local, now).is_err() {
                if let Some(m) = self.manual.get_mut(&key) {
                    m.retry = Some(now + ANNOUNCE_RETRY);
                }
            }
        }
    }
}

/// One mDNS segment (interface) and the two device lists kept for it:
/// devices discovered on the wire, and devices added by hand, over every
/// family it serves: one list, whichever family a device was heard over.
/// Cheap to clone; clones share state, so the receive threads and API
/// callers can each hold one.
#[derive(Clone)]
pub struct Segment {
    interface: Arc<str>,
    families: Arc<[Family]>,
    state: Arc<Mutex<State>>,
}

impl Segment {
    /// A segment for `interface`, over `families`, each to be given a socket
    /// with [`attach`](Segment::attach).
    pub fn new(interface: &str, families: &[Family]) -> Segment {
        Segment {
            interface: interface.into(),
            families: families.into(),
            state: Arc::new(Mutex::new(State {
                min_lifetime: DEFAULT_MIN_LIFETIME,
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
        self.state.lock().unwrap().min_lifetime = min_lifetime;
    }

    /// The TTL, to the second, of the address records of the devices
    /// [`add_manual`](Segment::add_manual) announces from now on: how long
    /// others keep them, and so, at 80% of it, how often they are announced
    /// again. `None`, the default, announces each device with the TTL it
    /// announced itself with (at least ten seconds, and two minutes if it did
    /// not say). The records of a device's services keep their own TTL either
    /// way.
    pub fn set_reflect_ttl(&self, ttl: Option<Duration>) {
        let secs = ttl.map(|t| u32::try_from(t.as_secs()).unwrap_or(u32::MAX).max(MIN_REFLECT_TTL));
        self.state.lock().unwrap().reflect_ttl = secs;
    }

    /// Have `timer` run this segment's upkeep from now on: drop devices when
    /// they expire, ask devices to answer again `refresh_before` ahead of that
    /// (if given), and re-announce reflected devices. Each happens when it is
    /// due, not on a tick, and the wake-up follows whatever is heard or added.
    /// Replaces an earlier call. Stops with the timer or the last clone of
    /// the segment.
    pub fn schedule(&self, timer: &Timer, refresh_before: Option<Duration>) {
        let state = Arc::downgrade(&self.state);
        let (interface, families) = (self.interface.clone(), self.families.clone());
        // Parked until `rearm` finds something due. The timer holds only a
        // weak reference, so it does not keep the segment alive.
        let entry = timer.schedule(format!("upkeep {}", self.interface), Duration::MAX, move || match state.upgrade() {
            Some(state) => Segment { interface: interface.clone(), families: families.clone(), state }.run_timers(),
            None => Next::Stop,
        });
        self.state.lock().unwrap().wake = Some(Wake { entry, before: refresh_before, at: None });
        self.rearm();
    }

    /// Point the wake-up at whatever is due next. Call after anything that
    /// can make something due sooner: a device heard or added.
    fn rearm(&self) {
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let at = state.next_due(Instant::now());
        let Some(wake) = state.wake.as_mut().filter(|w| w.at != at) else {
            return;
        };
        wake.at = at;
        match at {
            Some(at) => wake.entry.reschedule_at(at),
            None => wake.entry.reschedule(Duration::MAX),
        };
    }

    /// The timer's callback: do what is due, and say when to run next.
    fn run_timers(&self) -> Next {
        let before = self.state.lock().unwrap().wake.as_ref().and_then(|w| w.before);
        let now = Instant::now();
        // Drop what has run out first, so that nothing is asked that is being
        // dropped, then ask the devices about to expire to answer again.
        // Routine refreshes are not worth a journal line each.
        self.expire(now);
        if let Some(before) = before {
            if let Err(e) = self.refresh(now, before) {
                eprintln!("{}: refresh failed: {e:#}", self.interface);
            }
        }
        if let Err(e) = self.reannounce(now) {
            eprintln!("{}: re-announce failed: {e:#}", self.interface);
        }

        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let at = state.next_due(Instant::now());
        if let Some(wake) = &mut state.wake {
            wake.at = at;
        }
        at.map_or(Next::After(Duration::MAX), Next::At)
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
        let mut state = self.state.lock().unwrap();
        state.outbound.retain(|o| o.family != family);
        state.outbound.push(Outbound { family, socket, dest });
    }

    // 1. Discovered devices.

    /// Devices currently active on this segment (excludes manual ones).
    pub fn devices(&self) -> Vec<Device> {
        let state = self.state.lock().unwrap();
        state.discovered.values().map(|e| e.device.clone()).collect()
    }

    // 2. Change notifications for the discovered list.

    /// Receive an [`Event`] whenever a device appears, changes or disappears
    /// from the discovered list. Drop the receiver to unsubscribe.
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = mpsc::channel();
        self.state.lock().unwrap().subscribers.push(tx);
        rx
    }

    /// Everything this segment's timer is waiting for, soonest first: devices
    /// to expire, to ask again, and to re-announce. The timer's own time is the
    /// first of these.
    pub fn pending(&self) -> Vec<Pending> {
        let state = self.state.lock().unwrap();
        let mut all = Vec::new();
        state.for_each_deadline(Instant::now(), &mut |what, who, at| {
            all.push(Pending { what, who: who.to_string(), at });
        });
        all.sort_by_key(|p| p.at);
        all
    }

    /// The id of this segment's entry in the timer ([`timer::Entry::id`]), if
    /// it has been scheduled.
    pub fn timer_id(&self) -> Option<u64> {
        self.state.lock().unwrap().wake.as_ref().map(|w| w.entry.id())
    }

    /// How much longer the daemon keeps `device`, a device of this segment, if
    /// it is not heard from again, to the second; zero if it is not (or no
    /// longer) known.
    pub fn lifetime_left(&self, device: &Device) -> Duration {
        self.state.lock().unwrap().lifetime_left(device)
    }

    // 3. Reflected devices, invisible to 1 and 2.

    /// Announce `device` on this segment for `owner` and remember it, under
    /// its hostname. It needs a hostname and at least one address, all of
    /// this segment's family, and announces exactly the addresses it has: a
    /// reflected device should arrive with only its routable one, since a
    /// link-local address is no use on another link.
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
        let ttl = {
            let state = self.state.lock().unwrap();
            state.reflect_ttl.or(device.ttl.map(|t| t.max(MIN_REFLECT_TTL))).unwrap_or(HOST_TTL)
        };
        self.add_manual_ttl(owner, device, Duration::from_secs(ttl.into()))
    }

    /// Like [`add_manual`](Segment::add_manual), with the address records
    /// announced for `host_ttl` (whole seconds, at least one) whatever the
    /// device or the segment's [reflect TTL](Segment::set_reflect_ttl) say,
    /// and re-announced at 80% of it.
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
        let mut guard = self.state.lock().unwrap();
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
        self.rearm();
        Ok(true)
    }

    /// Forget what `owner` wanted announced as `hostname`. If that is what is
    /// announced, the next owner's device takes its place, or, if there is
    /// none, goodbyes are sent for it. Returns false if `owner` had no such
    /// device. If sending fails it is kept.
    pub fn remove_manual(&self, owner: Owner, hostname: &str) -> Result<bool> {
        let key = hostname.to_ascii_lowercase();
        let mut guard = self.state.lock().unwrap();
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
        self.rearm();
        Ok(true)
    }

    /// The devices announced on this segment: for each hostname, what is
    /// shown of the one that won.
    pub fn manual_devices(&self) -> Vec<Device> {
        let state = self.state.lock().unwrap();
        state.manual.values().filter_map(|m| m.shown.clone()).collect()
    }

    /// Re-announce reflected devices that have not had a full announcement
    /// for 80% of their TTL, and try again what failed to send. A failed send
    /// is retried after [`ANNOUNCE_RETRY`]; the first error is returned after
    /// every device was tried. Run by [`Segment::schedule`] when due.
    pub fn reannounce(&self, now: Instant) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let local = state.local_instances();
        let due: Vec<String> = state
            .manual
            .iter()
            .filter(|(_, m)| m.reannounce_at().is_some_and(|at| at <= now))
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
                    send(&state.outbound, &device.announcement(m.host_ttl, m.other_ttl))?;
                    m.announced = now;
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
    /// What it has no answer to is passed on to the subscribers as an
    /// [`Event::Question`], for the reflector to ask elsewhere.
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

        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let unknown = state.unknown(query);
        if !unknown.is_empty() {
            state.notify(Event::Question(unknown));
        }
        let probing = !query.authorities.is_empty();
        let (keys, devices): (Vec<String>, Vec<Device>) = state.answering(now, legacy, probing, family).into_iter().unzip();
        let Some((msg, answered)) = Device::query_response(&devices, query, legacy) else {
            return Ok(());
        };
        transmit(&state.outbound, family, &msg, legacy.then_some(from))?;

        if !legacy {
            for i in answered {
                if let Some(m) = state.manual.get_mut(&keys[i]) {
                    m.last_sent.set(family, now);
                }
            }
        }
        Ok(())
    }

    /// Ask the devices on this segment `questions` that another segment had
    /// no answer to, in a query of the daemon's own: nothing of the asker's
    /// packet comes here, not its address, not its known answers, not its
    /// wish for a unicast reply. Their answers are heard like any, and so
    /// reflected; the asker, asking again, is answered from that.
    ///
    /// A question asked here within [`FORWARD_GAP`] is not asked again, nor
    /// any once [`MAX_FORWARDED`] are waiting it out. Returns how many were
    /// asked. A no-op when the segment has no sender attached.
    pub fn query_question(&self, questions: &[Question]) -> Result<usize> {
        let now = Instant::now();
        let mut guard = self.state.lock().unwrap();
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
        ask(&state.outbound, &Device::forward_queries(fresh))
    }

    // Fed by the receive loops and the timer.

    /// Handle a received datagram: record the sender (still counted as alive
    /// if the packet does not parse) and answer it if it is a query we can
    /// answer. The error, if any, is from sending the answer.
    pub fn handle(&self, from: SocketAddr, packet: &[u8]) -> Result<()> {
        match Message::parse(packet) {
            Ok(msg) => {
                self.apply(from.ip(), Instant::now(), Some(&msg));
                self.rearm();
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
        self.rearm();
    }

    fn apply(&self, src: IpAddr, now: Instant, msg: Option<&Message>) {
        // Records in a query are other devices' known answers, not the
        // sender's own data.
        let msg = msg.filter(|m| m.header.response);
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let floor = state.min_lifetime;
        let mut touched = Touched::default();

        // A response saying one of the sender's addresses is gone (TTL 0) is a
        // device leaving: the device that owns that name, and anything the
        // sender was only known by.
        let leaving: Vec<Key> = msg
            .into_iter()
            .flat_map(|m| m.records())
            .filter(|r| r.ttl == 0 && addr_of(&r.data) == Some(src))
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
            if let RData::Ptr(kind) = &rec.data {
                if rec.ttl > 0
                    && rec.name.eq_ignore_ascii_case(META_QUERY)
                    && rec.class == 1
                    && is_type(kind)
                    && state.types.len() < MAX_TYPES
                {
                    state.types.insert(kind.to_ascii_lowercase());
                }
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
            // The sender, if it announced the address the packet came from, or
            // is the only host described and announced no address of that
            // family: not even one no one can be reached at, which is not to be
            // made good with the sender's.
            let same_family = |a: &IpAddr| a.is_ipv4() == src.is_ipv4();
            let is_sender = report.addrs.contains(&src)
                || (!report.addrs.iter().chain(&report.refused).any(same_family) && reports.len() == 1);
            let mut addrs = report.addrs.clone();
            if is_sender && !addrs.contains(&src) {
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
            let ttl = Duration::from_secs(report.max_ttl as u64);
            entry.expires = entry.expires.max(now + ttl.max(floor));
            entry.device.learn(report, &addrs, src);

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
        let key = sender.unwrap_or_else(|| state.by_addr.get(&src).cloned().unwrap_or(Key::Source(src)));
        let room = state.discovered.contains_key(&key) || state.discovered.len() < MAX_DEVICES;
        if (reports.is_empty() || !rest.is_empty()) && room {
            touched.note(&state.discovered, &key);
            let entry = state.discovered.entry(key.clone()).or_insert_with(|| Entry::new(now, src));
            let ttl = rest.iter().map(|r| r.ttl).max().unwrap_or(0);
            let ttl = Duration::from_secs(ttl as u64);
            entry.expires = entry.expires.max(now + ttl.max(floor));
            entry.device.set_addrs(&[src], src);
            entry.device.learn_records(rest.iter().copied());
            state.by_addr.insert(src, key);
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

        let events = touched.events(&state.discovered);
        if !events.is_empty() {
            state.settle_all(now);
        }
        for event in events {
            state.notify(event);
        }
    }

    /// Actively look for devices: ask what service types exist, browse each
    /// type for instances, and resolve every instance that has not yet said
    /// where it is (target and port). Three rounds, a few seconds in all,
    /// because each round's answers decide the next one's questions. Blocks
    /// until done and returns how many questions were sent; answers are
    /// processed by the receive loop as they arrive.
    pub fn probe(&self) -> Result<usize> {
        self.probe_with(&PROBE_GAPS)
    }

    fn probe_with(&self, gaps: &[Duration]) -> Result<usize> {
        let mut sent = 0;
        for gap in gaps {
            sent += self.probe_round()?;
            thread::sleep(*gap);
        }
        Ok(sent)
    }

    /// One round of queries, built from what is known right now. A no-op
    /// when the segment has no sender attached.
    fn probe_round(&self) -> Result<usize> {
        let state = self.state.lock().unwrap();
        if state.outbound.is_empty() {
            return Ok(0);
        }

        let devices: Vec<Device> = state.discovered.values().map(|e| e.device.clone()).collect();
        ask(&state.outbound, &Device::probe_queries(&devices, &state.types))
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
        let mut guard = self.state.lock().unwrap();
        let State { discovered, outbound, .. } = &mut *guard;
        if outbound.is_empty() {
            return Ok(0);
        }
        let gap = refresh_gap(before);

        let mut asking = Vec::new();
        for entry in discovered.values_mut() {
            // Not one that has already run out: it is about to be dropped. A
            // margin too long to add to a time reaches past every expiry.
            let due = entry.expires > now && now.checked_add(before).is_none_or(|limit| entry.expires <= limit);
            let recent = entry.refreshed.is_some_and(|t| now.saturating_duration_since(t) < gap);
            if !entry.askable() || !due || recent {
                continue;
            }
            entry.refreshed = Some(now);
            asking.push(entry.device.clone());
        }
        ask(outbound, &Device::refresh_queries(&asking))
    }

    /// Drop devices whose lifetime has run out as of `now`.
    pub fn expire(&self, now: Instant) {
        let mut state = self.state.lock().unwrap();
        let stale: Vec<Key> = state
            .discovered
            .iter()
            .filter(|&(_, e)| e.expires <= now)
            .map(|(key, _)| key.clone())
            .collect();
        if stale.is_empty() {
            return;
        }
        for key in stale {
            if let Some(entry) = state.forget(&key) {
                state.notify(Event::Removed(entry.device));
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

/// Multicast `queries`, over every family. Returns how many questions they
/// asked.
fn ask(outbound: &[Outbound], queries: &[Message]) -> Result<usize> {
    for q in queries {
        multicast(outbound, q)?;
    }
    Ok(queries.iter().map(|q| q.questions.len()).sum())
}

/// Announce `records`, over every family.
fn send(outbound: &[Outbound], records: &[Record]) -> Result<()> {
    let msg = Message {
        header: Header {
            id: 0,
            response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            rcode: 0,
        },
        questions: Vec::new(),
        answers: records.to_vec(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    multicast(outbound, &msg)
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
    use super::*;
    use crate::device::{record, Addrs, Service, LEGACY_TTL_CAP, QUESTIONS_PER_PACKET};
    use crate::parser::{self, rtype};

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
        device.set_addrs(&[ip(addr)], ip(addr));
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
        device.set_addrs(&[ip(addr)], ip(addr));
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
        let router = Device { hostname: Some("router.local".into()), ipv4: Addrs { routable: Some(ip("10.0.1.1")), ..Addrs::default() }, ..Device::default() };
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

    /// A question nothing announced here answers is passed on for the
    /// reflector to ask elsewhere; one something does, or that a device here
    /// owns the name of, or that a device asks while probing, is not.
    #[test]
    fn a_question_nothing_here_answers_is_passed_on() {
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
        assert_eq!(passed_on(&events), [vec![question("printer.local", rtype::A)]]);

        // Only what is not known: the copy's address, and even what its NSEC
        // says it has not got, are answered here.
        let mixed = [question("tv.local", rtype::A), question("tv.local", rtype::AAAA), question("_ipp._tcp.local", rtype::PTR)];
        seg.handle(client, &asking(&mixed, vec![])).unwrap();
        assert_eq!(passed_on(&events), [vec![question("_ipp._tcp.local", rtype::PTR)]]);

        // A copy that may not answer again just yet still knows the answer.
        seg.handle(client, &asking(&[question("tv.local", rtype::A)], vec![])).unwrap();
        assert!(passed_on(&events).is_empty());

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
        for at in seg.state.lock().unwrap().forwarded.values_mut() {
            *at -= FORWARD_GAP;
        }
        assert_eq!(seg.query_question(&questions[..1]).unwrap(), 1);
        recv(&rx).unwrap();

        // However many made-up names are asked, only so many are waited out.
        let flood: Vec<Question> = (0..MAX_FORWARDED + 10).map(|i| question(&format!("x{i}.local"), rtype::A)).collect();
        assert_eq!(seg.query_question(&flood).unwrap(), MAX_FORWARDED - 1);
        assert!(seg.state.lock().unwrap().forwarded.len() <= MAX_FORWARDED);
        while recv(&rx).is_some() {}

        // Without a sender, nothing.
        assert_eq!(Segment::new("quiet", &[Family::V4]).query_question(&questions).unwrap(), 0);
    }

    /// One sender may describe only so many hosts: a sleep proxy speaks for
    /// several, but not for thousands. Others are not held back, and the
    /// hosts it described are still kept up to date.
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
        assert_eq!(h0.ipv4.routable, Some(ip("10.0.3.3")), "what it described is kept up to date");
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
        assert_eq!((tv.ipv4.routable, tv.ipv4.link_local), (None, None));

        // One that announced none at all still is: it is the sender.
        hear(&seg, "10.0.1.8", vec![srv("NAS._smb._tcp.local", 445, "nas.local")]);
        let nas = seg.devices().into_iter().find(|d| d.hostname.as_deref() == Some("nas.local")).unwrap();
        assert_eq!(nas.ipv4.routable, Some(ip("10.0.1.8")));
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
        assert_eq!(tv.ipv4.routable, Some(ip("10.0.1.7")));
        assert_eq!(tv.ipv6.link_local, Some(ip("fe80::7")), "the sender, over IPv6");

        let seg = Segment::new("test", &[Family::V4]);
        hear(&seg, "10.0.1.8", vec![a_record("nas.local", "0.0.0.0"), aaaa("nas.local", "fd00::8")]);
        let nas = seg.devices().into_iter().find(|d| d.hostname.is_some()).unwrap();
        assert_eq!((nas.ipv4.routable, nas.ipv6.routable), (None, Some(ip("fd00::8"))));
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

    /// The questions passed on so far, one list per query.
    fn passed_on(events: &Receiver<Event>) -> Vec<Vec<Question>> {
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
        let mut state = seg.state.lock().unwrap();
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
    fn reannounces_after_eighty_percent_of_ttl() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv("10.0.1.9", &["TV"])).unwrap();
        let first = recv(&rx).unwrap();

        seg.reannounce(Instant::now()).unwrap();
        assert!(recv(&rx).is_none());

        let later = Instant::now() + reannounce_after(HOST_TTL) + Duration::from_secs(1);
        seg.reannounce(later).unwrap();
        let again = recv(&rx).expect("re-announcement");
        assert_eq!(again.answers.len(), first.answers.len());
        assert!(again.answers.iter().all(|r| r.ttl > 0));

        seg.reannounce(later).unwrap();
        assert!(recv(&rx).is_none());
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

    #[test]
    fn probe_runs_every_round_and_counts_questions() {
        let (seg, rx) = wired();
        assert_eq!(seg.probe().unwrap(), 3);
        assert_eq!(drain_queries(&rx), 3);
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
        assert_eq!(seg.probe().unwrap(), 0);
    }

    #[test]
    fn learned_types_are_capped() {
        let seg = Segment::new("test", &[Family::V4]);
        let ptrs = (0..MAX_TYPES + 50)
            .map(|i| record(META_QUERY.into(), false, 4500, RData::Ptr(format!("_t{i}._tcp.local"))))
            .collect();
        hear(&seg, "10.0.2.73", ptrs);
        assert_eq!(seg.state.lock().unwrap().types.len(), MAX_TYPES);
    }

    /// `router.local` is advertised as a reflected device that has a hostname
    /// and an address but no services.
    #[test]
    fn a_device_without_services_can_be_advertised() {
        let (seg, rx) = wired();
        let router = Device {
            hostname: Some("router.local".into()),
            ipv4: Addrs { routable: Some(ip("10.0.1.1")), ..Addrs::default() },
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

    /// Manual check against a real interface: `MDNS_TEST_IFACE=br cargo test
    /// live_local_addr -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_local_addr() {
        let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
        for family in [Family::V4, Family::V6] {
            let addr = open(&iface, family).unwrap().local_addr().unwrap();
            println!("{iface} {family:?}: {addr}");
            assert!(!addr.is_loopback() && !addr.is_unspecified());
            assert_eq!(addr.is_ipv4(), family == Family::V4);
        }
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
        assert_eq!((named[0].ipv4.routable, named[0].ipv6.routable), (Some(ip("10.0.1.7")), Some(ip("fd00::7"))));
    }

    /// Announcements go out over every family; a reply goes out over the
    /// family it was asked over, with the addresses of both, and the once a
    /// second is counted per family.
    #[test]
    fn announcements_go_out_over_both_families_and_replies_over_the_askers() {
        let (seg, rx4, rx6) = wired_both();
        let mut both = tv("10.0.1.9", &["TV"]);
        both.set_addrs(&[ip("fd00::9")], ip("fd00::9"));
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
        assert_eq!(devices[0].ipv4.routable, Some(ip("10.0.2.73")));
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
        let found: Vec<_> = devices.iter().map(|d| (d.hostname.as_deref().unwrap(), d.ipv4.routable.unwrap(), d.services.len())).collect();
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
            ipv6: Addrs { link_local: Some(ip("fe80::1")), ..Addrs::default() },
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
        none.ipv4.routable = None;
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
        both.set_addrs(&[ip("fd00::9"), ip("fe80::9")], ip("fd00::9"));
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
        assert_eq!(tv.ipv4.routable, None, "no address was announced, and the sender is not credited with one");

        let speaker = find(&devices, "OZAL-Speakers.local");
        let names: Vec<&str> = speaker.services.iter().map(|s| s.instance.as_str()).collect();
        assert_eq!(names, ["OZAL Speakers._airplay._tcp.local"]);
        assert_eq!(speaker.services[0].txt, ["model=RX"]);
        assert_eq!(speaker.ipv4.routable, Some(ip("10.0.2.73")));

        assert_eq!(rx.try_iter().filter(|e| matches!(e, Event::Added(d) if d.hostname.is_some())).count(), 2);
    }

    #[test]
    fn the_only_host_a_packet_describes_is_the_sender_when_it_announces_no_address() {
        let seg = Segment::new("test", &[Family::V4]);
        hear(&seg, "10.0.1.9", vec![srv("Dev._http._tcp.local", 80, "dev.local")]);
        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!((devices[0].hostname.as_deref(), devices[0].ipv4.routable), (Some("dev.local"), Some(ip("10.0.1.9"))));
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
        assert_eq!(seg.devices()[0].ipv4.routable, None);

        seg.probe_round().unwrap();
        assert!(asked(&recv(&rx).unwrap()).contains(&q("t.local", rtype::AAAA)));

        // It answers with a ULA as well, so there is nothing left to ask.
        hear(&seg, "fe80::9", vec![aaaa("t.local", "fd00::9")]);
        assert_eq!(seg.devices()[0].ipv6.routable, Some(ip("fd00::9")));
        seg.probe_round().unwrap();
        assert!(!asked(&recv(&rx).unwrap()).contains(&q("t.local", rtype::AAAA)));
    }

    /// Pretend the device called `host` was heard from so that it now expires at `at`.
    fn set_expiry(seg: &Segment, host: &str, at: Instant) {
        let mut state = seg.state.lock().unwrap();
        state.discovered.get_mut(&host_key(host)).expect("no such device").expires = at;
    }

    /// printer.local lives only for the 5 minute floor (all its TTLs are 120);
    /// other.local announces a 4500 second PTR, so it lives 75 minutes.
    fn hear_a_short_and_a_long_lived_device(seg: &Segment) {
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        hear(seg, "10.0.1.8", vec![
            a_record("other.local", "10.0.1.8"),
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
        seg.state.lock().unwrap().discovered[&host_key(host)].expires
    }

    fn next_due(seg: &Segment) -> Option<Instant> {
        seg.state.lock().unwrap().next_due(Instant::now())
    }

    /// Wait for the next event of this kind, as long as it takes up to `within`.
    fn wait_for_removed(events: &Receiver<Event>, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match events.recv_timeout(left) {
                Ok(Event::Removed(_)) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
        false
    }

    #[test]
    fn the_next_deadline_is_the_earliest_of_expiry_refresh_and_reannounce() {
        let timer = Timer::new().unwrap();
        let (seg, _rx) = wired();
        assert_eq!(next_due(&seg), None, "nothing known, nothing due");

        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        let expires = expiry_of(&seg, "printer.local");
        assert_eq!(next_due(&seg), Some(expires));

        // Asking ahead of expiry makes it earlier...
        seg.schedule(&timer, Some(Duration::from_secs(60)));
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(60)));

        // ...until it was asked: then the gap (a quarter of the margin) has to pass.
        seg.refresh(expires - Duration::from_secs(60), Duration::from_secs(60)).unwrap();
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)));

        // A reflected device is due for re-announcement, and a failed one not before its retry.
        seg.add_manual(Owner::Own, tv("10.0.9.9", &["TV"])).unwrap();
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)).min(Some(announced + reannounce_after(HOST_TTL))));
        seg.state.lock().unwrap().manual.get_mut("tv.local").unwrap().retry = Some(announced + Duration::from_secs(500));
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)));
    }

    #[test]
    fn pending_lists_everything_the_timer_waits_for_soonest_first() {
        let timer = Timer::new().unwrap();
        let (seg, _rx) = wired();
        seg.schedule(&timer, Some(Duration::from_secs(60)));
        assert!(seg.pending().is_empty());
        assert!(seg.timer_id().is_some());

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
        assert!(pending.windows(2).all(|w| w[0].at <= w[1].at), "soonest first");
        // The timer is set for the first of them.
        assert_eq!(next_due(&seg), Some(pending[0].at));
        let refresh = pending.iter().find(|p| p.what == "refresh").unwrap();
        assert_eq!(refresh.at, expires - Duration::from_secs(60));
        // Without a refresh margin nothing is asked.
        seg.schedule(&timer, None);
        assert!(seg.pending().iter().all(|p| p.what != "refresh"));
    }

    #[test]
    fn a_name_can_be_announced_with_its_own_ttl_and_is_kept_up_at_80_percent_of_it() {
        let (seg, rx) = wired();
        seg.add_manual_ttl(Owner::Own, tv("10.0.1.1", &[]), Duration::from_secs(1000)).unwrap();
        let first = recv(&rx).unwrap();
        assert!(first.answers.iter().all(|r| r.ttl == 1000));
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
        assert_eq!(seg.state.lock().unwrap().manual["tv.local"].reannounce_at(), Some(announced + Duration::from_secs(800)));

        // Queries are answered with it too.
        age(&seg, 2);
        seg.handle(sa("10.0.1.50"), &query("tv.local", rtype::A, vec![])).unwrap();
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == 1000));

        // Not yet at 799 s; again at 800, with the same TTL.
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
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
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
        assert_eq!(seg.state.lock().unwrap().manual["tv.local"].reannounce_at(), Some(announced + Duration::from_secs(240)));
    }

    #[test]
    fn a_short_service_ttl_brings_the_reannouncement_forward() {
        let (seg, rx) = wired();
        seg.add_manual(Owner::Own, tv_with_ttls(Some(300), 50)).unwrap();
        assert!(announced_ttls(&rx).contains(&(false, 50)));
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
        assert_eq!(seg.state.lock().unwrap().manual["tv.local"].reannounce_at(), Some(announced + Duration::from_secs(40)));
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
    fn a_configured_reflect_ttl_wins_for_the_address_only() {
        let (seg, rx) = wired();
        seg.set_reflect_ttl(Some(Duration::from_secs(900)));
        seg.add_manual(Owner::Own, tv_with_ttls(Some(300), 600)).unwrap();
        let ttls = announced_ttls(&rx);
        assert!(ttls.contains(&(true, 900)), "{ttls:?}");
        assert!(ttls.iter().filter(|(is_addr, _)| !is_addr).all(|(_, ttl)| *ttl == 600), "{ttls:?}");
        // The services run out first, and it is announced again before that.
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
        assert_eq!(seg.state.lock().unwrap().manual["tv.local"].reannounce_at(), Some(announced + Duration::from_secs(480)));

        // Even a tiny setting is kept to the floor.
        seg.set_reflect_ttl(Some(Duration::from_secs(1)));
        assert_eq!(seg.state.lock().unwrap().reflect_ttl, Some(MIN_REFLECT_TTL));
        seg.set_reflect_ttl(None);
        assert_eq!(seg.state.lock().unwrap().reflect_ttl, None);
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
        let timer = Timer::new().unwrap();
        let seg = Segment::new("test", &[Family::V4]);
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        seg.schedule(&timer, Some(Duration::from_secs(60)));
        // Only the expiry: refresh would return at once without asking, and
        // being due, it would spin.
        assert_eq!(next_due(&seg), Some(expiry_of(&seg, "printer.local")));
    }

    #[test]
    fn a_margin_too_big_for_the_clock_neither_panics_nor_spins() {
        let timer = Timer::new().unwrap();
        let (seg, rx) = wired();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        seg.schedule(&timer, Some(Duration::MAX));
        // Everything is within that margin of its expiry, so it is asked...
        assert!(next_due(&seg).unwrap() <= Instant::now() + Duration::from_millis(50));
        assert!(seg.refresh(Instant::now(), Duration::MAX).unwrap() > 0);
        assert!(recv(&rx).is_some());
        // ...once, and then not again until it has expired.
        assert_eq!(next_due(&seg), Some(expiry_of(&seg, "printer.local")));
    }

    #[test]
    fn a_device_is_dropped_the_moment_it_expires() {
        let timer = Timer::new().unwrap();
        let (seg, _rx) = wired();
        seg.schedule(&timer, None);
        let events = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

        // Not on a tick: 150 ms from now, even though the wake-up was parked
        // for five minutes when it was heard.
        set_expiry(&seg, "printer.local", Instant::now() + Duration::from_millis(150));
        seg.rearm();
        assert!(wait_for_removed(&events, Duration::from_secs(2)));
        assert!(seg.devices().is_empty());
    }

    #[test]
    fn a_device_heard_after_the_wakeup_was_set_can_be_due_sooner() {
        let timer = Timer::new().unwrap();
        let (seg, _rx) = wired();
        seg.set_min_lifetime(Duration::ZERO);
        seg.schedule(&timer, None); // nothing known: parked
        let events = seg.subscribe();
        hear_a_device_with_ttl(&seg, 1);
        assert!(wait_for_removed(&events, Duration::from_secs(4)));
    }

    #[test]
    fn a_device_is_asked_the_margin_before_it_expires() {
        let timer = Timer::new().unwrap();
        let (seg, rx) = wired();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        seg.schedule(&timer, Some(Duration::from_millis(300)));
        let events = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();

        let start = Instant::now();
        set_expiry(&seg, "printer.local", start + Duration::from_millis(500));
        seg.rearm();
        let query = recv(&rx).expect("never asked");
        let waited = start.elapsed();
        assert!(asked(&query).contains(&q("printer.local", rtype::A)));
        assert!(waited >= Duration::from_millis(150), "asked too early: {waited:?}");
        assert!(waited < Duration::from_millis(450), "asked too late: {waited:?}");
        // It does not answer, so it goes.
        assert!(wait_for_removed(&events, Duration::from_secs(2)));
    }

    #[test]
    fn the_timer_does_not_keep_a_dropped_segment_alive() {
        let timer = Timer::new().unwrap();
        let seg = Segment::new("test", &[Family::V4]);
        seg.schedule(&timer, None);
        let state = Arc::downgrade(&seg.state);
        drop(seg);
        assert!(state.upgrade().is_none());
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
    fn dropped_subscriber_is_pruned() {
        let seg = Segment::new("test", &[Family::V4]);
        drop(seg.subscribe());
        seg.observe(ip("10.0.1.5"));
        assert!(seg.state.lock().unwrap().subscribers.is_empty());
    }

    /// Service types learned from the enumeration are one per type, whatever
    /// their case.
    #[test]
    fn service_types_are_learned_once_whatever_their_case() {
        let seg = Segment::new("test", &[Family::V4]);
        let meta = |kind: &str| ptr("_services._dns-sd._udp.local", kind);
        hear(&seg, "10.0.1.7", vec![meta("_http._tcp.local"), meta("_HTTP._tcp.LOCAL")]);
        assert_eq!(seg.state.lock().unwrap().types.len(), 1);
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
