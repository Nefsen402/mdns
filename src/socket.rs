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

pub const DEVICE_TIMEOUT: Duration = Duration::from_secs(300);

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

/// A device on a segment, identified by its address (scope id dropped,
/// since the segment already pins the link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub addr: IpAddr,
    pub hostname: Option<String>,
    pub services: Vec<Service>,
}

impl Device {
    fn bare(addr: IpAddr) -> Device {
        Device {
            addr,
            hostname: None,
            services: Vec::new(),
        }
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

struct Entry {
    expires: Instant,
    hostname: Option<String>,
    services: BTreeMap<String, Service>,
}

impl Entry {
    fn device(&self, addr: IpAddr) -> Device {
        Device {
            addr,
            hostname: self.hostname.clone(),
            services: self.services.values().cloned().collect(),
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
}

#[derive(Default)]
struct State {
    discovered: HashMap<IpAddr, Entry>,
    /// Devices we announce on this segment on behalf of somewhere else.
    manual: HashMap<IpAddr, Manual>,
    subscribers: Vec<Sender<Event>>,
    outbound: Option<Outbound>,
    /// Service types devices on this segment have said they offer, learned
    /// from answers to the type enumeration query.
    types: BTreeSet<String>,
}

impl State {
    fn notify(&mut self, event: Event) {
        // A dropped receiver is an unsubscribe.
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
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
            state: Arc::default(),
        }
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
        state.discovered.iter().map(|(&a, e)| e.device(a)).collect()
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

    /// Announce `device` on this segment and remember it. The device needs a
    /// hostname and an address of this segment's family; the address is
    /// advertised as-is, so it must be reachable by this segment's clients.
    ///
    /// Returns false (and sends nothing) if an identical device is already
    /// present. Replacing a device also sends goodbyes for services it no
    /// longer has. If sending fails nothing is recorded.
    pub fn add_manual(&self, device: Device) -> Result<bool> {
        let family_ok = matches!(
            (self.family, device.addr),
            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_))
        );
        if !family_ok {
            bail!("{} is not an {:?} address", device.addr, self.family);
        }
        if device.hostname.is_none() {
            return Err(anyhow!("a reflected device needs a hostname to announce"));
        }

        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let old = state.manual.get(&device.addr).map(|m| &m.device);
        if old == Some(&device) {
            return Ok(false);
        }

        let mut records = announcement(&device, HOST_TTL, OTHER_TTL);
        if let Some(old) = old {
            let kept: BTreeSet<_> = device.services.iter().map(|s| &s.instance).collect();
            for svc in old.services.iter().filter(|s| !kept.contains(&s.instance)) {
                records.extend(service_records(old, svc, 0));
            }
        }
        send(&state.outbound, &records)?;
        let now = Instant::now();
        state.manual.insert(
            device.addr,
            Manual { device, announced: now, last_sent: now },
        );
        Ok(true)
    }

    /// Send goodbyes for the device at `addr` and forget it. Returns false
    /// if there was no such device. If sending fails it is kept.
    pub fn remove_manual(&self, addr: IpAddr) -> Result<bool> {
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let Some(manual) = state.manual.get(&addr) else {
            return Ok(false);
        };
        send(&state.outbound, &announcement(&manual.device, 0, 0))?;
        state.manual.remove(&addr);
        Ok(true)
    }

    pub fn manual_devices(&self) -> Vec<Device> {
        let state = self.state.lock().unwrap();
        state.manual.values().map(|m| m.device.clone()).collect()
    }

    /// Re-announce reflected devices that have not had a full announcement
    /// for [`REANNOUNCE`]. Call periodically. A failed send is retried on the
    /// next call; the first error is returned after every device was tried.
    pub fn reannounce(&self, now: Instant) -> Result<()> {
        let mut guard = self.state.lock().unwrap();
        let State { manual, outbound, .. } = &mut *guard;
        let mut first_err = None;
        for m in manual.values_mut() {
            if now.saturating_duration_since(m.announced) < REANNOUNCE {
                continue;
            }
            match send(outbound, &announcement(&m.device, HOST_TTL, OTHER_TTL)) {
                Ok(()) => {
                    m.announced = now;
                    m.last_sent = now;
                }
                Err(e) => {
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
        for (addr, m) in &state.manual {
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
            used.push(*addr);
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
            for addr in used {
                if let Some(m) = state.manual.get_mut(&addr) {
                    m.last_sent = now;
                }
            }
        }
        Ok(())
    }

    // Fed by the receive loops and a periodic reaper.

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
        let mut state = self.state.lock().unwrap();

        if let Some(msg) = msg {
            if is_goodbye(msg, src) {
                if let Some(entry) = state.discovered.remove(&src) {
                    state.notify(Event::Removed(entry.device(src)));
                }
                return;
            }
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

        let before = state.discovered.get(&src).map(|e| e.device(src));
        let entry = state.discovered.entry(src).or_insert_with(|| Entry {
            expires: now,
            hostname: None,
            services: BTreeMap::new(),
        });

        let max_ttl = msg
            .into_iter()
            .flat_map(|m| m.records())
            .map(|r| Duration::from_secs(r.ttl as u64))
            .max()
            .unwrap_or_default();
        entry.expires = entry.expires.max(now + max_ttl.max(DEVICE_TIMEOUT));

        if let Some(msg) = msg {
            merge_records(entry, src, msg);
        }

        let after = entry.device(src);
        match before {
            None => state.notify(Event::Added(after)),
            Some(before) if before != after => state.notify(Event::Updated(after)),
            Some(_) => {}
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

        let mut questions: Vec<Question> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut ask = |name: &str, qtype: u16| {
            if !seen.insert((name.to_ascii_lowercase(), qtype)) {
                return;
            }
            let q = Question { name: name.into(), qtype, class: 1, unicast_response: false };
            // Names come off the network; one that cannot be re-encoded
            // (lossy UTF-8 can stretch a label past 63 bytes) is skipped
            // rather than failing the whole round.
            if query(std::slice::from_ref(&q)).encode().is_ok() {
                questions.push(q);
            }
        };

        ask(META_QUERY, rtype::PTR);

        let mut kinds: BTreeSet<&str> = state.types.iter().map(String::as_str).collect();
        let services = || state.discovered.values().flat_map(|e| e.services.values());
        kinds.extend(services().map(|s| s.kind.as_str()).filter(|k| !k.is_empty()));
        for kind in kinds {
            ask(kind, rtype::PTR);
        }
        for svc in services().filter(|s| s.target.is_none()) {
            ask(&svc.instance, rtype::SRV);
            ask(&svc.instance, rtype::TXT);
        }

        for chunk in questions.chunks(QUESTIONS_PER_PACKET) {
            transmit(&state.outbound, &query(chunk), None)?;
        }
        Ok(questions.len())
    }

    /// Drop devices whose lifetime has run out as of `now`.
    pub fn expire(&self, now: Instant) {
        let mut state = self.state.lock().unwrap();
        let stale: Vec<IpAddr> = state
            .discovered
            .iter()
            .filter(|&(_, e)| e.expires <= now)
            .map(|(&addr, _)| addr)
            .collect();
        for addr in stale {
            if let Some(entry) = state.discovered.remove(&addr) {
                state.notify(Event::Removed(entry.device(addr)));
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

/// A response whose only claim is that the sender's own address record is
/// gone (TTL 0) means the device is leaving.
fn is_goodbye(msg: &Message, src: IpAddr) -> bool {
    msg.records()
        .any(|r| r.ttl == 0 && addr_of(&r.data) == Some(src))
}

fn merge_records(entry: &mut Entry, src: IpAddr, msg: &Message) {
    let mut own_name = None;
    let mut srv_target = None;

    for rec in msg.records() {
        match &rec.data {
            data @ (RData::A(_) | RData::Aaaa(_)) => {
                if addr_of(data) == Some(src) {
                    own_name.get_or_insert(&rec.name);
                }
            }
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
                    srv_target.get_or_insert(target);
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

    if let Some(name) = own_name.or(srv_target) {
        entry.hostname = Some(name.clone());
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
    let data = match device.addr {
        IpAddr::V4(a) => RData::A(a),
        IpAddr::V6(a) => RData::Aaaa(a),
    };
    let mut records = vec![record(host, true, host_ttl, data)];

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

    #[test]
    fn observe_adds_once_and_notifies() {
        let seg = Segment::new("test", Family::V4);
        let rx = seg.subscribe();
        seg.observe(ip("10.0.1.5"));
        seg.observe(ip("10.0.1.5"));
        assert_eq!(seg.devices().len(), 1);
        assert_eq!(rx.try_recv(), Ok(Event::Added(Device::bare(ip("10.0.1.5")))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expire_removes_and_notifies() {
        let seg = Segment::new("test", Family::V4);
        seg.observe(ip("10.0.1.5"));
        let rx = seg.subscribe();
        seg.expire(Instant::now());
        assert_eq!(seg.devices().len(), 1);
        seg.expire(Instant::now() + DEVICE_TIMEOUT + Duration::from_secs(1));
        assert!(seg.devices().is_empty());
        assert_eq!(rx.try_recv(), Ok(Event::Removed(Device::bare(ip("10.0.1.5")))));
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
            addr: ip(addr),
            hostname: Some("tv.local".into()),
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
        assert!(seg.remove_manual(ip("10.0.1.9")).unwrap());
        assert!(!seg.remove_manual(ip("10.0.1.9")).unwrap());
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

        seg.remove_manual(ip("10.0.1.9")).unwrap();
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
        let router = Device { addr: ip("10.0.1.1"), hostname: Some("router.local".into()), services: vec![] };
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
        seg.remove_manual(ip("10.0.1.1")).unwrap();
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

        seg.handle(sa("10.0.1.7"), &announcement(120)).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Event::Updated(d)) if d.services.len() == 1));

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
        seg.expire(Instant::now() + DEVICE_TIMEOUT + Duration::from_secs(1));
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
            seg.remove_manual(addr).unwrap();
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
