//! Per-interface mDNS sockets.
//!
//! Each socket is pinned to a single interface and bound to the mDNS
//! multicast group address rather than the wildcard, so it shows up in
//! `ss` as `224.0.0.251%wifi:5353` and only ever sees that link's traffic.

use std::ffi::CString;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};

use crate::parser::{self, rtype, Header, Message, Question, RData, Record};
use crate::timer::{self, Next, Timer};

pub const MDNS_PORT: u16 = 5353;
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

// Not exported by the libc crate on all versions (Linux >= 4.20).
const IPV6_MULTICAST_ALL: libc::c_int = 29;

/// Minimum time a discovered device may stay silent before it is dropped.
/// Record TTLs can extend this but never shorten it: without actively
/// querying, a quiet device is indistinguishable from a departed one.
/// TTLs for announced records (RFC 6762 section 10): host records are short
/// lived, everything else long lived.
const HOST_TTL: u32 = 120;
const OTHER_TTL: u32 = 4500;

/// Re-announce a reflected device at 80% of the shortest TTL it advertises.
const REANNOUNCE: Duration = Duration::from_secs(HOST_TTL as u64 * 4 / 5);
/// How long to wait before trying again after a re-announcement failed to send.
const ANNOUNCE_RETRY: Duration = Duration::from_secs(10);

/// DNS-SD service type enumeration (RFC 6763 section 9).
const META_QUERY: &str = "_services._dns-sd._udp.local";

/// Pause after each round of a probe. A probe is three rounds, because the
/// answers to one round (service types, then instances) decide what the next
/// one asks; the last pause lets the final answers arrive before returning.
const PROBE_GAPS: [Duration; 3] = if cfg!(test) {
    [Duration::from_millis(5); 3]
} else {
    [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(1)]
};

/// Questions per query packet, to stay well inside one Ethernet frame.
const QUESTIONS_PER_PACKET: usize = 16;

/// Service types remembered per segment, so a hostile device cannot grow it
/// without bound by announcing endless made-up types.
const MAX_TYPES: usize = 256;

/// A record may not be multicast more than once a second (RFC 6762 section 6).
const MIN_MULTICAST_GAP: Duration = Duration::from_secs(1);

/// TTL cap for replies to legacy unicast resolvers (RFC 6762 section 6.7).
const LEGACY_TTL_CAP: u32 = 10;

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

/// A DNS-SD service advertised by a device.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Service {
    /// Full instance name, e.g. `Printer._http._tcp.local`.
    pub instance: String,
    /// Service type, e.g. `_http._tcp.local`.
    pub kind: String,
    pub port: u16,
    pub target: Option<String>,
    /// TXT strings, usually `key=value`.
    pub txt: Vec<String>,
}

/// A device on a segment. Once it has announced a hostname it is known by
/// that; until then only by the address it was heard from.
///
/// It has up to two addresses, of the segment's family: a link-local one,
/// which only means something on the link it was heard on, and a routable one
/// that other networks can reach it at (IPv4, or global/ULA IPv6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub hostname: Option<String>,
    pub link_local: Option<IpAddr>,
    pub routable: Option<IpAddr>,
    pub services: Vec<Service>,
}

impl Device {
    /// Its addresses, the routable one first.
    pub fn addrs(&self) -> impl Iterator<Item = IpAddr> {
        self.routable.into_iter().chain(self.link_local)
    }

    /// What identifies it in the manual list and to the reflector: its
    /// hostname, case-insensitively.
    pub fn key(&self) -> Option<String> {
        self.hostname.as_ref().map(|h| h.to_ascii_lowercase())
    }
}

/// Link-local: IPv6 `fe80::/10` and IPv4 `169.254.0.0/16`. Valid on one link
/// only, so never to be handed to another network.
pub fn is_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// A change to the *discovered* list. Manual devices never produce events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Added(Device),
    /// Hostname or services changed.
    Updated(Device),
    Removed(Device),
}

/// How a discovered device is told apart: by hostname once it has one,
/// otherwise by the address it was heard from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key {
    Host(String),
    Source(IpAddr),
}

struct Entry {
    expires: Instant,
    /// When it was last asked to answer again because it was about to expire.
    refreshed: Option<Instant>,
    hostname: Option<String>,
    link_local: Option<IpAddr>,
    routable: Option<IpAddr>,
    services: BTreeMap<String, Service>,
}

impl Entry {
    fn new(now: Instant) -> Entry {
        Entry {
            expires: now,
            refreshed: None,
            hostname: None,
            link_local: None,
            routable: None,
            services: BTreeMap::new(),
        }
    }

    /// Whether there is anything to ask it about: a name or a service.
    fn askable(&self) -> bool {
        self.hostname.is_some() || !self.services.is_empty()
    }

    fn device(&self) -> Device {
        Device {
            hostname: self.hostname.clone(),
            link_local: self.link_local,
            routable: self.routable,
            services: self.services.values().cloned().collect(),
        }
    }

    /// Take over what was learned about this device before its name was known.
    fn absorb(&mut self, earlier: Entry) {
        for (instance, svc) in earlier.services {
            self.services.entry(instance).or_insert(svc);
        }
        self.expires = self.expires.max(earlier.expires);
    }

    /// Record the addresses a packet vouches for. When there are several of a
    /// kind, the one the packet came from wins, else the lowest.
    fn set_addrs(&mut self, addrs: &[IpAddr], src: IpAddr) {
        let pick = |wanted: bool| {
            let found: Vec<IpAddr> = addrs.iter().copied().filter(|a| is_link_local(a) == wanted).collect();
            found.contains(&src).then_some(src).or_else(|| found.iter().min().copied())
        };
        if let Some(a) = pick(false) {
            self.routable = Some(a);
        }
        if let Some(a) = pick(true) {
            self.link_local = Some(a);
        }
    }
}

struct Outbound {
    socket: UdpSocket,
    dest: SocketAddr,
}

/// A reflected device plus the timing needed to keep it announced.
struct Manual {
    device: Device,
    /// When the full record set was last multicast; drives re-announcement.
    announced: Instant,
    /// When any of its records was last multicast; drives the rate limit.
    last_sent: Instant,
    /// Not before this, after a re-announcement failed to send.
    retry: Option<Instant>,
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
    outbound: Option<Outbound>,
    /// Service types devices on this segment have said they offer, learned
    /// from answers to the type enumeration query.
    types: BTreeSet<String>,
    /// The least a device is kept after it was last heard from.
    min_lifetime: Duration,
    wake: Option<Wake>,
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
        let before = self.wake.as_ref().and_then(|w| w.before);
        let mut next: Option<Instant> = None;
        let mut soon = |t: Instant| next = Some(next.map_or(t, |n| n.min(t)));
        for e in self.discovered.values() {
            soon(e.expires);
            let Some(before) = before.filter(|_| self.outbound.is_some() && e.askable()) else {
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
                soon(at);
            }
        }
        for m in self.manual.values() {
            let at = m.announced.checked_add(REANNOUNCE).unwrap_or(m.announced);
            soon(m.retry.map_or(at, |r| at.max(r)));
        }
        next
    }

    /// Drop a discovered device and the addresses that pointed at it.
    fn forget(&mut self, key: &Key) -> Option<Entry> {
        self.by_addr.retain(|_, k| k != key);
        self.discovered.remove(key)
    }
}

/// One mDNS segment (interface) and the two device lists kept for it:
/// devices discovered on the wire, and devices added by hand. Cheap to
/// clone; clones share state, so the receive threads and API callers can
/// each hold one.
#[derive(Clone)]
pub struct Segment {
    interface: Arc<str>,
    family: Family,
    state: Arc<Mutex<State>>,
}

impl Segment {
    pub fn new(interface: &str, family: Family) -> Segment {
        Segment {
            interface: interface.into(),
            family,
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

    /// Have `timer` run this segment's upkeep from now on: drop devices when
    /// they expire, ask devices to answer again `refresh_before` ahead of that
    /// (if given), and re-announce reflected devices. Each happens when it is
    /// due, not on a tick, and the wake-up follows whatever is heard or added.
    /// Replaces an earlier call. Stops with the timer or the last clone of
    /// the segment.
    pub fn schedule(&self, timer: &Timer, refresh_before: Option<Duration>) {
        let state = Arc::downgrade(&self.state);
        let (interface, family) = (self.interface.clone(), self.family);
        // Parked until `rearm` finds something due. The timer holds only a
        // weak reference, so it does not keep the segment alive.
        let entry = timer.schedule(format!("upkeep {}/{:?}", self.interface, self.family), Duration::MAX, move || match state.upgrade() {
            Some(state) => Segment { interface: interface.clone(), family, state }.run_timers(),
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
                eprintln!("{}/{:?}: refresh failed: {e:#}", self.interface, self.family);
            }
        }
        if let Err(e) = self.reannounce(now) {
            eprintln!("{}/{:?}: re-announce failed: {e:#}", self.interface, self.family);
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

    pub fn family(&self) -> Family {
        self.family
    }

    /// Give the segment a way to send. Without one (as in unit tests),
    /// manual changes are recorded but nothing goes on the wire.
    pub fn attach(&self, socket: UdpSocket, dest: SocketAddr) {
        self.state.lock().unwrap().outbound = Some(Outbound { socket, dest });
    }

    // 1. Discovered devices.

    /// Devices currently active on this segment (excludes manual ones).
    pub fn devices(&self) -> Vec<Device> {
        let state = self.state.lock().unwrap();
        state.discovered.values().map(Entry::device).collect()
    }

    // 2. Change notifications for the discovered list.

    /// Receive an [`Event`] whenever a device appears, changes or disappears
    /// from the discovered list. Drop the receiver to unsubscribe.
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = mpsc::channel();
        self.state.lock().unwrap().subscribers.push(tx);
        rx
    }

    // 3. Reflected devices, invisible to 1 and 2.

    /// Announce `device` on this segment and remember it, under its
    /// hostname. It needs a hostname and at least one address, all of this
    /// segment's family, and announces exactly the addresses it has: a
    /// reflected device should arrive with only its routable one, since a
    /// link-local address is no use on another link.
    ///
    /// Returns false (and sends nothing) if an identical device is already
    /// present. Replacing a device also sends goodbyes for services and
    /// addresses it no longer has. If sending fails nothing is recorded.
    pub fn add_manual(&self, device: Device) -> Result<bool> {
        let Some(key) = device.key() else {
            return Err(anyhow!("a reflected device needs a hostname to announce"));
        };
        if device.addrs().next().is_none() {
            bail!("{key} has no address to announce");
        }
        let family = self.family;
        if let Some(bad) = device.addrs().find(|a| !matches!((family, a), (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)))) {
            bail!("{bad} is not an {family:?} address");
        }

        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let old = state.manual.get(&key).map(|m| &m.device);
        if old == Some(&device) {
            return Ok(false);
        }

        let mut records = announcement(&device, HOST_TTL, OTHER_TTL);
        if let Some(old) = old {
            let kept: BTreeSet<_> = device.services.iter().map(|s| &s.instance).collect();
            for svc in old.services.iter().filter(|s| !kept.contains(&s.instance)) {
                records.extend(service_records(old, svc, 0));
            }
            let host = old.hostname.clone().unwrap_or_default();
            for gone in old.addrs().filter(|a| !device.addrs().any(|n| n == *a)) {
                records.push(record(host.clone(), true, 0, address_data(gone)));
            }
        }
        send(&state.outbound, &records)?;
        let now = Instant::now();
        state.manual.insert(key, Manual { device, announced: now, last_sent: now, retry: None });
        drop(guard);
        self.rearm();
        Ok(true)
    }

    /// Send goodbyes for the device called `hostname` and forget it. Returns
    /// false if there was no such device. If sending fails it is kept.
    pub fn remove_manual(&self, hostname: &str) -> Result<bool> {
        let key = hostname.to_ascii_lowercase();
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let Some(manual) = state.manual.get(&key) else {
            return Ok(false);
        };
        send(&state.outbound, &announcement(&manual.device, 0, 0))?;
        state.manual.remove(&key);
        Ok(true)
    }

    pub fn manual_devices(&self) -> Vec<Device> {
        let state = self.state.lock().unwrap();
        state.manual.values().map(|m| m.device.clone()).collect()
    }

    /// Re-announce reflected devices that have not had a full announcement
    /// for [`REANNOUNCE`]. A failed send is retried after [`ANNOUNCE_RETRY`]; the
    /// first error is returned after every device was tried. Run by
    /// [`Segment::schedule`] when due.
    pub fn reannounce(&self, now: Instant) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        let State { manual, outbound, .. } = &mut *guard;
        let mut first_err = None;
        for m in manual.values_mut() {
            if now.saturating_duration_since(m.announced) < REANNOUNCE || m.retry.is_some_and(|r| now < r) {
                continue;
            }
            match send(outbound, &announcement(&m.device, HOST_TTL, OTHER_TTL)) {
                Ok(()) => {
                    m.announced = now;
                    m.last_sent = now;
                    m.retry = None;
                }
                Err(e) => {
                    m.retry = Some(now + ANNOUNCE_RETRY);
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Answer a query from `from` with whatever reflected devices match it.
    ///
    /// Replies are multicast, except to legacy resolvers (source port other
    /// than 5353), which get a unicast reply that echoes the question. Known
    /// answers in the query suppress our answer, and a device's records are
    /// not multicast more than once a second.
    fn respond(&self, from: SocketAddr, query: &Message) -> Result<()> {
        let h = &query.header;
        if h.response || h.opcode != 0 || h.rcode != 0 || query.questions.is_empty() {
            return Ok(());
        }
        let legacy = from.port() != MDNS_PORT;
        let now = Instant::now();

        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let mut answers: Vec<Record> = Vec::new();
        let mut additionals: Vec<Record> = Vec::new();
        let mut used = Vec::new();
        for (key, m) in &state.manual {
            let (a, x) = answers_for(query, &m.device);
            if a.is_empty() {
                continue;
            }
            if !legacy && now.saturating_duration_since(m.last_sent) < MIN_MULTICAST_GAP {
                continue;
            }
            for r in a {
                if !answers.contains(&r) {
                    answers.push(r);
                }
            }
            for r in x {
                if !additionals.contains(&r) {
                    additionals.push(r);
                }
            }
            used.push(key.clone());
        }
        if answers.is_empty() {
            return Ok(());
        }

        let mut msg = Message {
            header: Header {
                id: 0,
                response: true,
                opcode: 0,
                authoritative: true,
                truncated: false,
                rcode: 0,
            },
            questions: Vec::new(),
            answers,
            authorities: Vec::new(),
            additionals,
        };
        let dest = if legacy {
            msg.header.id = h.id;
            msg.questions = query.questions.clone();
            for r in msg.answers.iter_mut().chain(&mut msg.additionals) {
                r.ttl = r.ttl.min(LEGACY_TTL_CAP);
                r.cache_flush = false;
            }
            Some(from)
        } else {
            None
        };
        transmit(&state.outbound, &msg, dest)?;

        if !legacy {
            for key in used {
                if let Some(m) = state.manual.get_mut(&key) {
                    m.last_sent = now;
                }
            }
        }
        Ok(())
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
            for event in events {
                state.notify(event);
            }
            return;
        }

        for rec in msg.into_iter().flat_map(|m| m.records()) {
            if let RData::Ptr(kind) = &rec.data {
                if rec.ttl > 0
                    && rec.name.eq_ignore_ascii_case(META_QUERY)
                    && is_service_type(kind)
                    && state.types.len() < MAX_TYPES
                {
                    state.types.insert(kind.clone());
                }
            }
        }

        // A response may describe several devices (a reflector answering a
        // browse query does), so attribute each record to the device it names
        // instead of the whole packet to one.
        let (groups, rest) = match msg {
            Some(m) => partition(m, self.family),
            None => (Vec::new(), Vec::new()),
        };

        // The host that turns out to be the sender, if any: the one that
        // announced the address the packet came from, or the only one
        // described when it announced no address at all.
        let mut sender: Option<Key> = None;
        let mut resolved: Vec<(Key, String)> = Vec::new();

        for g in &groups {
            let key = host_key(&g.host);
            let is_sender = g.addrs.contains(&src) || (g.addrs.is_empty() && groups.len() == 1);
            let mut addrs = g.addrs.clone();
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
            let entry = state.discovered.entry(key.clone()).or_insert_with(|| Entry::new(now));
            if let Some(earlier) = earlier {
                entry.absorb(earlier);
            }
            let ttl = Duration::from_secs(g.max_ttl as u64);
            entry.expires = entry.expires.max(now + ttl.max(floor));
            entry.hostname = Some(g.host.clone());
            entry.set_addrs(&addrs, src);
            merge_records(entry, g.records.iter().copied());

            for addr in addrs {
                state.by_addr.insert(addr, key.clone());
            }
            for rec in &g.records {
                if matches!(rec.data, RData::Srv { .. }) {
                    resolved.push((key.clone(), rec.name.clone()));
                }
            }
            if is_sender && sender.is_none() {
                sender = Some(key);
            }
        }

        // What is left is about the sender itself: records tied to no host (a
        // bare browse answer, text records), or just a sign of life such as a
        // query. A packet that only describes other devices says nothing about
        // its sender, which is then not recorded at all.
        if groups.is_empty() || !rest.is_empty() {
            let key = sender
                .unwrap_or_else(|| state.by_addr.get(&src).cloned().unwrap_or(Key::Source(src)));
            touched.note(&state.discovered, &key);
            let entry = state.discovered.entry(key.clone()).or_insert_with(|| Entry::new(now));
            let ttl = rest.iter().map(|r| r.ttl).max().unwrap_or(0);
            let ttl = Duration::from_secs(ttl as u64);
            entry.expires = entry.expires.max(now + ttl.max(floor));
            entry.set_addrs(&[src], src);
            merge_records(entry, rest.iter().copied());
            state.by_addr.insert(src, key);
        }

        // An instance that has now been resolved to its host no longer needs
        // the unresolved copy learned from a bare browse answer.
        for (owner, instance) in resolved {
            let others: Vec<Key> = state
                .discovered
                .iter()
                .filter(|(k, e)| {
                    **k != owner && e.services.get(&instance).is_some_and(|s| s.target.is_none())
                })
                .map(|(k, _)| k.clone())
                .collect();
            for k in others {
                touched.note(&state.discovered, &k);
                if let Some(e) = state.discovered.get_mut(&k) {
                    e.services.remove(&instance);
                }
            }
        }

        let events = touched.events(&state.discovered);
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
        if state.outbound.is_none() {
            return Ok(0);
        }

        let mut qs = Questions::default();
        qs.ask(META_QUERY, rtype::PTR);

        let mut kinds: BTreeSet<&str> = state.types.iter().map(String::as_str).collect();
        let services = || state.discovered.values().flat_map(|e| e.services.values());
        kinds.extend(services().map(|s| s.kind.as_str()).filter(|k| !k.is_empty()));
        for kind in kinds {
            qs.ask(kind, rtype::PTR);
        }
        for svc in services().filter(|s| s.target.is_none()) {
            qs.ask(&svc.instance, rtype::SRV);
            qs.ask(&svc.instance, rtype::TXT);
        }
        // A device known by name but without a routable address (it only ever
        // showed a link-local one) is asked for all of its addresses.
        let address_type = if self.family == Family::V4 { rtype::A } else { rtype::AAAA };
        for host in state.discovered.values().filter(|e| e.routable.is_none()).filter_map(|e| e.hostname.as_deref()) {
            qs.ask(host, address_type);
        }

        qs.send(&state.outbound)
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
        if outbound.is_none() {
            return Ok(0);
        }
        let gap = refresh_gap(before);
        let address_type = if self.family == Family::V4 { rtype::A } else { rtype::AAAA };

        let mut qs = Questions::default();
        for entry in discovered.values_mut() {
            // Not one that has already run out: it is about to be dropped. A
            // margin too long to add to a time reaches past every expiry.
            let due = entry.expires > now && now.checked_add(before).is_none_or(|limit| entry.expires <= limit);
            let recent = entry.refreshed.is_some_and(|t| now.saturating_duration_since(t) < gap);
            if !entry.askable() || !due || recent {
                continue;
            }
            entry.refreshed = Some(now);
            if let Some(host) = &entry.hostname {
                qs.ask(host, address_type);
            }
            for svc in entry.services.values() {
                qs.ask(&svc.instance, rtype::SRV);
                qs.ask(&svc.instance, rtype::TXT);
            }
        }
        qs.send(outbound)
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
        for key in stale {
            if let Some(entry) = state.forget(&key) {
                state.notify(Event::Removed(entry.device()));
            }
        }
    }
}

fn addr_of(data: &RData) -> Option<IpAddr> {
    match data {
        RData::A(a) => Some(IpAddr::V4(*a)),
        RData::Aaaa(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

fn host_key(name: &str) -> Key {
    Key::Host(name.to_ascii_lowercase())
}

/// One host a response describes: its addresses, and the service records
/// that name it (by the SRV target of their instance).
struct Group<'a> {
    host: String,
    addrs: Vec<IpAddr>,
    records: Vec<&'a Record>,
    max_ttl: u32,
}

fn group_index(groups: &mut Vec<Group<'_>>, host: &str) -> usize {
    if let Some(i) = groups.iter().position(|g| g.host.eq_ignore_ascii_case(host)) {
        return i;
    }
    groups.push(Group { host: host.to_string(), addrs: Vec::new(), records: Vec::new(), max_ttl: 0 });
    groups.len() - 1
}

/// Split a response into the hosts it describes and the records that tie to
/// no host. A host is any name owning an address record or targeted by an SRV
/// record. A service instance belongs to the host its SRV points at, and its
/// PTR and TXT records follow it; those whose instance has no SRV in the
/// packet, and the type enumeration, are left over.
fn partition<'a>(msg: &'a Message, family: Family) -> (Vec<Group<'a>>, Vec<&'a Record>) {
    let mut groups: Vec<Group<'a>> = Vec::new();
    let mut instance_host: HashMap<String, usize> = HashMap::new();
    for rec in msg.records() {
        match &rec.data {
            RData::A(_) | RData::Aaaa(_) => {
                group_index(&mut groups, &rec.name);
            }
            RData::Srv { target, .. } => {
                let i = group_index(&mut groups, target);
                instance_host.insert(rec.name.to_ascii_lowercase(), i);
            }
            _ => {}
        }
    }

    let mut rest: Vec<&'a Record> = Vec::new();
    for rec in msg.records() {
        let instance = match &rec.data {
            RData::A(_) | RData::Aaaa(_) => {
                let i = group_index(&mut groups, &rec.name);
                groups[i].max_ttl = groups[i].max_ttl.max(rec.ttl);
                continue;
            }
            RData::Srv { .. } | RData::Txt(_) => &rec.name,
            RData::Ptr(instance) => instance,
            _ => continue,
        };
        match instance_host.get(&instance.to_ascii_lowercase()) {
            Some(&i) => {
                groups[i].records.push(rec);
                groups[i].max_ttl = groups[i].max_ttl.max(rec.ttl);
            }
            None => rest.push(rec),
        }
    }

    for g in &mut groups {
        g.addrs = announced_addrs(msg, &g.host, family);
    }
    (groups, rest)
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
            self.before.insert(key.clone(), discovered.get(key).map(Entry::device));
        }
    }

    fn events(self, discovered: &HashMap<Key, Entry>) -> Vec<Event> {
        let Touched { order, mut before } = self;
        let mut events = Vec::new();
        for key in order {
            let was = before.remove(&key).flatten();
            let now = discovered.get(&key).map(Entry::device);
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

/// The usable addresses of `family` that `msg` announces for `host`.
fn announced_addrs(msg: &Message, host: &str, family: Family) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = Vec::new();
    for rec in msg.records().filter(|r| r.ttl > 0 && r.name.eq_ignore_ascii_case(host)) {
        let Some(addr) = addr_of(&rec.data) else { continue };
        let family_ok = matches!((family, addr), (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)));
        if family_ok && !addr.is_loopback() && !addr.is_unspecified() && !addr.is_multicast() && !found.contains(&addr) {
            found.push(addr);
        }
    }
    found
}

fn merge_records<'a>(entry: &mut Entry, records: impl Iterator<Item = &'a Record>) {
    for rec in records {
        match &rec.data {
            RData::Ptr(instance) => {
                // Only service-instance PTRs; skip the `_services._dns-sd`
                // meta-enumeration, reverse lookups and subtype duplicates.
                let is_service = rec.name.ends_with("._tcp.local") || rec.name.ends_with("._udp.local");
                if !is_service || rec.name.starts_with("_services.") || rec.name.contains("._sub.") {
                    continue;
                }
                if rec.ttl == 0 {
                    entry.services.remove(instance);
                } else {
                    service(entry, instance).kind = rec.name.clone();
                }
            }
            RData::Srv { port, target, .. } => {
                if rec.ttl == 0 {
                    entry.services.remove(&rec.name);
                } else {
                    let svc = service(entry, &rec.name);
                    svc.port = *port;
                    svc.target = Some(target.clone());
                }
            }
            RData::Txt(strings) => {
                if rec.ttl != 0 {
                    service(entry, &rec.name).txt = strings
                        .iter()
                        .filter(|s| !s.is_empty())
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .collect();
                }
            }
            _ => {}
        }
    }
}

/// Get or create a service, deriving its type from the instance name until a
/// PTR record states it explicitly.
fn service<'a>(entry: &'a mut Entry, instance: &str) -> &'a mut Service {
    entry
        .services
        .entry(instance.to_string())
        .or_insert_with(|| Service {
            instance: instance.to_string(),
            kind: parser::split_instance(instance)
                .map(|(_, kind)| kind.to_string())
                .unwrap_or_default(),
            ..Service::default()
        })
}

/// The records that announce `device`. A TTL of 0 turns them into goodbyes.
/// Callers must have checked that the device has a hostname.
fn announcement(device: &Device, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
    let host = device.hostname.clone().expect("hostname checked on add");
    let mut records: Vec<Record> = device
        .addrs()
        .map(|addr| record(host.clone(), true, host_ttl, address_data(addr)))
        .collect();

    for svc in &device.services {
        records.extend(service_records(device, svc, other_ttl));
    }
    // DNS-SD service type enumeration, once per distinct type.
    let kinds: BTreeSet<_> = device.services.iter().map(|s| &s.kind).collect();
    for kind in kinds {
        records.push(record(
            "_services._dns-sd._udp.local".into(),
            false,
            other_ttl,
            RData::Ptr(kind.clone()),
        ));
    }
    records
}

fn service_records(device: &Device, svc: &Service, ttl: u32) -> Vec<Record> {
    let target = svc.target.clone().or_else(|| device.hostname.clone()).unwrap_or_default();
    vec![
        record(svc.kind.clone(), false, ttl, RData::Ptr(svc.instance.clone())),
        record(
            svc.instance.clone(),
            true,
            ttl,
            RData::Srv { priority: 0, weight: 0, port: svc.port, target },
        ),
        record(
            svc.instance.clone(),
            true,
            ttl,
            RData::Txt(svc.txt.iter().map(|t| t.as_bytes().to_vec()).collect()),
        ),
    ]
}

fn address_data(addr: IpAddr) -> RData {
    match addr {
        IpAddr::V4(a) => RData::A(a),
        IpAddr::V6(a) => RData::Aaaa(a),
    }
}

fn record(name: String, cache_flush: bool, ttl: u32, data: RData) -> Record {
    Record { name, class: 1, cache_flush, ttl, data }
}

/// Records that match `query` for one device, with known-answer suppression
/// applied, plus the additional records a client will want next (RFC 6763
/// section 12): a PTR brings its SRV and TXT, and an SRV brings its address.
fn answers_for(query: &Message, device: &Device) -> (Vec<Record>, Vec<Record>) {
    let all = announcement(device, HOST_TTL, OTHER_TTL);

    let mut answers: Vec<Record> = Vec::new();
    for q in &query.questions {
        if q.class != 1 && q.class != 255 {
            continue;
        }
        for rec in &all {
            let type_ok = q.qtype == rtype::ANY || q.qtype == rec.rtype();
            if type_ok && rec.name.eq_ignore_ascii_case(&q.name) && !answers.contains(rec) {
                answers.push(rec.clone());
            }
        }
    }

    // The asker already holds this record with at least half its life left.
    let known = |r: &Record| {
        query.answers.iter().any(|k| {
            k.name.eq_ignore_ascii_case(&r.name) && k.data == r.data && k.ttl >= r.ttl / 2
        })
    };
    answers.retain(|r| !known(r));
    if answers.is_empty() {
        return (answers, Vec::new());
    }

    let mut extra: Vec<Record> = Vec::new();
    let instances: Vec<&String> = answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::Ptr(instance) => Some(instance),
            _ => None,
        })
        .collect();
    for rec in &all {
        let wanted = matches!(rec.data, RData::Srv { .. } | RData::Txt(_))
            && instances.iter().any(|i| rec.name.eq_ignore_ascii_case(i));
        if wanted && !answers.contains(rec) {
            extra.push(rec.clone());
        }
    }
    let targets: Vec<String> = answers
        .iter()
        .chain(&extra)
        .filter_map(|r| match &r.data {
            RData::Srv { target, .. } => Some(target.clone()),
            _ => None,
        })
        .collect();
    for rec in &all {
        let wanted = matches!(rec.data, RData::A(_) | RData::Aaaa(_))
            && targets.iter().any(|t| rec.name.eq_ignore_ascii_case(t));
        if wanted && !answers.contains(rec) && !extra.contains(rec) {
            extra.push(rec.clone());
        }
    }
    (answers, extra)
}

/// Questions for one query, each asked once however many devices want it.
#[derive(Default)]
struct Questions {
    list: Vec<Question>,
    seen: BTreeSet<(String, u16)>,
}

impl Questions {
    fn ask(&mut self, name: &str, qtype: u16) {
        if !self.seen.insert((name.to_ascii_lowercase(), qtype)) {
            return;
        }
        let q = Question { name: name.into(), qtype, class: 1, unicast_response: false };
        // Names come off the network; one that cannot be re-encoded (lossy
        // UTF-8 can stretch a label past 63 bytes) is skipped rather than
        // failing the whole query.
        if query(std::slice::from_ref(&q)).encode().is_ok() {
            self.list.push(q);
        }
    }

    /// Multicast the questions, a few to a packet. Returns how many there were.
    fn send(&self, outbound: &Option<Outbound>) -> Result<usize> {
        for chunk in self.list.chunks(QUESTIONS_PER_PACKET) {
            transmit(outbound, &query(chunk), None)?;
        }
        Ok(self.list.len())
    }
}

/// A multicast query for `questions` (no known answers, so every device
/// that has a match replies).
fn query(questions: &[Question]) -> Message {
    Message {
        header: Header {
            id: 0,
            response: false,
            opcode: 0,
            authoritative: false,
            truncated: false,
            rcode: 0,
        },
        questions: questions.to_vec(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn is_service_type(name: &str) -> bool {
    name.ends_with("._tcp.local") || name.ends_with("._udp.local")
}

fn send(outbound: &Option<Outbound>, records: &[Record]) -> Result<()> {
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
    transmit(outbound, &msg, None)
}

/// Send to the group, or to `dest` for a unicast reply. A no-op when the
/// segment has no sender attached.
fn transmit(outbound: &Option<Outbound>, msg: &Message, dest: Option<SocketAddr>) -> Result<()> {
    let Some(out) = outbound else {
        return Ok(());
    };
    let dest = dest.unwrap_or(out.dest);
    out.socket
        .send_to(&msg.encode()?, dest)
        .with_context(|| format!("sending to {dest}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let a = ip(addr);
        let (link_local, routable) = if is_link_local(&a) { (Some(a), None) } else { (None, Some(a)) };
        Device { hostname: None, link_local, routable, services: vec![] }
    }

    #[test]
    fn observe_adds_once_and_notifies() {
        let seg = Segment::new("test", Family::V4);
        let rx = seg.subscribe();
        seg.observe(ip("10.0.1.5"));
        seg.observe(ip("10.0.1.5"));
        assert_eq!(seg.devices().len(), 1);
        assert_eq!(rx.try_recv(), Ok(Event::Added(unnamed("10.0.1.5"))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expire_removes_and_notifies() {
        let seg = Segment::new("test", Family::V4);
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
        let seg = Segment::new("test", Family::V4);
        seg.attach(tx, rx.local_addr().unwrap());
        (seg, rx)
    }

    fn recv(rx: &UdpSocket) -> Option<Message> {
        let mut buf = [0u8; 9000];
        let (n, _) = rx.recv_from(&mut buf).ok()?;
        Some(Message::parse(&buf[..n]).unwrap())
    }

    fn tv(addr: &str, instances: &[&str]) -> Device {
        Device {
            hostname: Some("tv.local".into()),
            link_local: None,
            routable: Some(ip(addr)),
            services: instances
                .iter()
                .map(|i| Service {
                    instance: format!("{i}._http._tcp.local"),
                    kind: "_http._tcp.local".into(),
                    port: 8080,
                    target: None,
                    txt: vec!["a=b".into()],
                })
                .collect(),
        }
    }

    #[test]
    fn manual_list_is_separate() {
        let seg = Segment::new("test", Family::V4);
        let rx = seg.subscribe();
        assert!(seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap());
        assert!(!seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap());
        assert!(seg.devices().is_empty());
        assert!(rx.try_recv().is_err());
        assert_eq!(seg.manual_devices().len(), 1);
        assert!(seg.remove_manual("TV.local").unwrap(), "by hostname, ignoring case");
        assert!(!seg.remove_manual("tv.local").unwrap());
    }

    #[test]
    fn add_announces_and_remove_says_goodbye() {
        let (seg, rx) = wired();
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();

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
        assert!(!seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap());
        assert!(recv(&rx).is_none());

        seg.remove_manual("tv.local").unwrap();
        let bye = recv(&rx).expect("goodbye");
        assert_eq!(bye.answers.len(), m.answers.len());
        assert!(bye.answers.iter().all(|r| r.ttl == 0));
        assert!(seg.manual_devices().is_empty());
    }

    #[test]
    fn replacing_sends_goodbye_for_dropped_services() {
        let (seg, rx) = wired();
        seg.add_manual(tv("10.0.1.9", &["A", "B"])).unwrap();
        recv(&rx).unwrap();

        seg.add_manual(tv("10.0.1.9", &["A"])).unwrap();
        let m = recv(&rx).unwrap();
        let gone: Vec<_> = m.answers.iter().filter(|r| r.ttl == 0).collect();
        assert_eq!(gone.len(), 3); // PTR, SRV, TXT of "B"
        assert!(gone.iter().any(|r| r.data == RData::Ptr("B._http._tcp.local".into())));
        assert!(m.answers.iter().filter(|r| r.ttl != 0).count() >= 5);
    }

    #[test]
    fn add_rejects_unannounceable_devices() {
        let (seg, rx) = wired();
        assert!(seg.add_manual(tv("fd00::9", &["TV"])).is_err());
        let mut nameless = tv("10.0.1.9", &["TV"]);
        nameless.hostname = None;
        assert!(seg.add_manual(nameless).is_err());
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

    /// Pretend the last multicast of every reflected device was `secs` ago.
    fn age(seg: &Segment, secs: u64) {
        let mut state = seg.state.lock().unwrap();
        for m in state.manual.values_mut() {
            m.announced -= Duration::from_secs(secs);
            m.last_sent -= Duration::from_secs(secs);
        }
    }

    #[test]
    fn answers_ptr_query_with_additionals() {
        let (seg, rx) = wired();
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
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
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
        let first = recv(&rx).unwrap();

        seg.reannounce(Instant::now()).unwrap();
        assert!(recv(&rx).is_none());

        let later = Instant::now() + REANNOUNCE + Duration::from_secs(1);
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
    fn probe_skips_names_it_cannot_encode() {
        let (seg, rx) = wired();
        // An instance whose label is 60 invalid UTF-8 bytes: decoding turns
        // each into U+FFFD, so the name no longer fits in a 63-byte label.
        let mut p = response(1);
        let mut instance = vec![60];
        instance.extend([0xff; 60]);
        instance.extend(labels(&["_x", "_tcp", "local"]));
        rr(&mut p, &["_x", "_tcp", "local"], 12, 4500, &instance);
        seg.handle(sa("10.0.2.73"), &p).unwrap();

        assert!(seg.probe_round().is_ok());
        let asked = asked(&recv(&rx).unwrap());
        assert!(asked.contains(&q("_x._tcp.local", rtype::PTR)));
        assert_eq!(asked.len(), 2, "the unencodable instance is skipped: {asked:?}");
    }

    #[test]
    fn probe_without_a_sender_does_nothing() {
        let seg = Segment::new("test", Family::V4);
        assert_eq!(seg.probe().unwrap(), 0);
    }

    #[test]
    fn learned_types_are_capped() {
        let seg = Segment::new("test", Family::V4);
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
            link_local: None,
            routable: Some(ip("10.0.1.1")),
            services: vec![],
        };
        seg.add_manual(router).unwrap();

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
        seg.reannounce(Instant::now() + REANNOUNCE + Duration::from_secs(1)).unwrap();
        assert!(recv(&rx).unwrap().answers.iter().all(|r| r.ttl == HOST_TTL));
        seg.remove_manual("router.local").unwrap();
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

    /// A segment of `family` whose "multicast group" is a local socket.
    fn wired_family(family: Family) -> (Segment, UdpSocket) {
        let (_, rx) = wired();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let seg = Segment::new("test", family);
        seg.attach(tx, rx.local_addr().unwrap());
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
    fn an_ipv6_device_has_a_link_local_and_a_routable_address() {
        let seg = Segment::new("test", Family::V6);
        // It sends from its link-local address and announces that, a ULA, and
        // (wrongly for this segment) an IPv4 address, which is ignored.
        hear(&seg, "fe80::7", vec![
            aaaa("tv.local", "fd00:0:1::7"),
            aaaa("tv.local", "fe80::7"),
            a_record("tv.local", "10.0.1.7"),
        ]);
        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].hostname.as_deref(), Some("tv.local"));
        assert_eq!(devices[0].routable, Some(ip("fd00:0:1::7")));
        assert_eq!(devices[0].link_local, Some(ip("fe80::7")));
    }

    #[test]
    fn a_device_first_heard_by_address_becomes_the_named_device() {
        let seg = Segment::new("test", Family::V4);
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
        assert_eq!(devices[0].routable, Some(ip("10.0.2.73")));
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
        let seg = Segment::new("test", Family::V4);
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
        let found: Vec<_> = devices.iter().map(|d| (d.hostname.as_deref().unwrap(), d.routable.unwrap(), d.services.len())).collect();
        assert_eq!(found, [("speaker.local", ip("10.0.2.73"), 1), ("tv.local", ip("10.0.2.179"), 1)]);
    }

    #[test]
    fn packets_that_do_not_name_their_sender_belong_to_the_device_it_is() {
        let seg = Segment::new("test", Family::V4);
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
            let seg = Segment::new("test", Family::V4);
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
            link_local: Some(ip("fe80::1")),
            routable: None,
            services: vec![],
        };
        seg.add_manual(router).unwrap();
        let m = recv(&rx).unwrap();
        assert_eq!(m.answers.len(), 1);
        assert_eq!(m.answers[0].data, RData::Aaaa("fe80::1".parse().unwrap()));
    }

    #[test]
    fn replacing_a_device_withdraws_the_addresses_it_no_longer_has() {
        let (seg, rx) = wired();
        seg.add_manual(tv("10.0.1.9", &["TV"])).unwrap();
        recv(&rx).unwrap();

        seg.add_manual(tv("10.0.1.10", &["TV"])).unwrap();
        let m = recv(&rx).unwrap();
        let ttl_of = |a: &str| m.answers.iter().find(|r| r.data == RData::A(a.parse().unwrap())).map(|r| r.ttl);
        assert_eq!((ttl_of("10.0.1.9"), ttl_of("10.0.1.10")), (Some(0), Some(HOST_TTL)));
        assert_eq!(seg.manual_devices().len(), 1, "same hostname, so it replaced the device");
    }

    #[test]
    fn add_rejects_a_device_with_no_addresses_or_the_wrong_family() {
        let (seg, rx) = wired();
        let mut none = tv("10.0.1.9", &["TV"]);
        none.routable = None;
        assert!(seg.add_manual(none).is_err());
        let mut v6 = tv("10.0.1.9", &["TV"]);
        v6.link_local = Some(ip("fe80::1"));
        assert!(seg.add_manual(v6).is_err(), "a v4 segment cannot announce an IPv6 address");
        assert!(seg.manual_devices().is_empty());
        assert!(recv(&rx).is_none());
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
        let seg = Segment::new("test", Family::V4);
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
        assert_eq!(tv.routable, None, "no address was announced, and the sender is not credited with one");

        let speaker = find(&devices, "OZAL-Speakers.local");
        let names: Vec<&str> = speaker.services.iter().map(|s| s.instance.as_str()).collect();
        assert_eq!(names, ["OZAL Speakers._airplay._tcp.local"]);
        assert_eq!(speaker.services[0].txt, ["model=RX"]);
        assert_eq!(speaker.routable, Some(ip("10.0.2.73")));

        assert_eq!(rx.try_iter().filter(|e| matches!(e, Event::Added(d) if d.hostname.is_some())).count(), 2);
    }

    #[test]
    fn the_only_host_a_packet_describes_is_the_sender_when_it_announces_no_address() {
        let seg = Segment::new("test", Family::V4);
        hear(&seg, "10.0.1.9", vec![srv("Dev._http._tcp.local", 80, "dev.local")]);
        let devices = seg.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!((devices[0].hostname.as_deref(), devices[0].routable), (Some("dev.local"), Some(ip("10.0.1.9"))));
    }

    /// A bare browse answer leaves unresolved instances on the sender. Once a
    /// later packet resolves them to their hosts they are not kept twice.
    #[test]
    fn resolved_instances_leave_the_unresolved_copy_behind() {
        let seg = Segment::new("test", Family::V4);
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
        assert_eq!(seg.devices()[0].routable, None);

        seg.probe_round().unwrap();
        assert!(asked(&recv(&rx).unwrap()).contains(&q("t.local", rtype::AAAA)));

        // It answers with a ULA as well, so there is nothing left to ask.
        hear(&seg, "fe80::9", vec![aaaa("t.local", "fd00::9")]);
        assert_eq!(seg.devices()[0].routable, Some(ip("fd00::9")));
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
        let seg = Segment::new("test", Family::V4);
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
        let seg = Segment::new("test", Family::V4);
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 290));
        assert!(!alive_after(&seg, 301));

        // A shorter floor lets that device go sooner...
        let seg = Segment::new("test", Family::V4);
        seg.set_min_lifetime(Duration::from_secs(60));
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 50));
        assert!(!alive_after(&seg, 61));

        // ...a longer one keeps it longer...
        let seg = Segment::new("test", Family::V4);
        seg.set_min_lifetime(Duration::from_secs(900));
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 890));
        assert!(!alive_after(&seg, 901));

        // ...and zero means no floor: it lives for exactly its TTL.
        let seg = Segment::new("test", Family::V4);
        seg.set_min_lifetime(Duration::ZERO);
        hear_a_device_with_ttl(&seg, 10);
        assert!(alive_after(&seg, 8));
        assert!(!alive_after(&seg, 11));
    }

    #[test]
    fn a_ttl_longer_than_the_floor_still_wins() {
        let seg = Segment::new("test", Family::V4);
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
        seg.add_manual(tv("10.0.9.9", &["TV"])).unwrap();
        let announced = seg.state.lock().unwrap().manual["tv.local"].announced;
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)).min(Some(announced + REANNOUNCE)));
        seg.state.lock().unwrap().manual.get_mut("tv.local").unwrap().retry = Some(announced + Duration::from_secs(500));
        assert_eq!(next_due(&seg), Some(expires - Duration::from_secs(45)));
    }

    #[test]
    fn a_segment_that_cannot_send_has_nothing_to_refresh() {
        let timer = Timer::new().unwrap();
        let seg = Segment::new("test", Family::V4);
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
        let seg = Segment::new("test", Family::V4);
        seg.schedule(&timer, None);
        let state = Arc::downgrade(&seg.state);
        drop(seg);
        assert!(state.upgrade().is_none());
    }

    #[test]
    fn dropped_subscriber_is_pruned() {
        let seg = Segment::new("test", Family::V4);
        drop(seg.subscribe());
        seg.observe(ip("10.0.1.5"));
        assert!(seg.state.lock().unwrap().subscribers.is_empty());
    }

    #[test]
    fn ingest_fills_in_hostname_and_services() {
        let seg = Segment::new("test", Family::V4);
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
        let seg = Segment::new("test", Family::V4);
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
        let seg = Segment::new("test", Family::V4);
        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        let rx = seg.subscribe();
        seg.handle(sa("10.0.1.7"), &announcement(0)).unwrap();
        assert!(seg.devices().is_empty());
        assert!(matches!(rx.try_recv(), Ok(Event::Removed(_))));
    }

    #[test]
    fn long_ttl_extends_lifetime() {
        let seg = Segment::new("test", Family::V4);
        seg.handle(sa("10.0.1.7"), &announcement(4500)).unwrap();
        seg.expire(Instant::now() + DEFAULT_MIN_LIFETIME + Duration::from_secs(1));
        assert_eq!(seg.devices().len(), 1);
        seg.expire(Instant::now() + Duration::from_secs(4501));
        assert!(seg.devices().is_empty());
    }

    #[test]
    fn garbage_still_counts_as_alive() {
        let seg = Segment::new("test", Family::V4);
        seg.handle(sa("10.0.1.5"), b"\xff\xff not dns").unwrap();
        assert_eq!(seg.devices().len(), 1);
    }

    #[test]
    fn query_records_are_ignored() {
        let seg = Segment::new("test", Family::V4);
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
            let seg = Segment::new(&iface, family);
            let (tx, dest) = sock.sender().unwrap();
            seg.attach(tx, dest);
            let addr = match family {
                Family::V4 => ip("10.9.9.9"),
                Family::V6 => ip("fd00::9"),
            };
            seg.add_manual(tv(&addr.to_string(), &["LiveTV"])).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            seg.remove_manual("tv.local").unwrap();
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
        let seg = Segment::new(&iface, Family::V4);
        let (tx, dest) = sock.sender().unwrap();
        seg.attach(tx, dest);
        seg.add_manual(tv("10.9.9.9", &["LiveTV"])).unwrap();
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
