//! What is known about a device on an interface: its hostname, addresses and
//! services. Kept by [`Interface`](crate::interface::Interface), and announced on
//! other interfaces by the [`Segment`](crate::segment::Segment).
//!
//! A response is read into one [`Report`] per host it describes, which a
//! [`Device`] then takes in with [`Device::learn`]. A device is turned back
//! into records, and asked about, by [`message`](crate::message).

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::{Ref, RefCell, RefMut};

use hashbrown::HashMap;
use core::net::IpAddr;

use crate::config::{Advertise, Neighbours, ReflectedWhen, DEFAULT_MAX_ADDRS};
#[cfg(test)]
use crate::config::DEFAULT_MAX_SERVICES;
use crate::codec::{self, rtype, Message, RData, Record};
use crate::addr::{family_of, is_link_local, Family};

use crate::prelude::*;

/// TTLs for announced records (RFC 6762 section 10): host records are short
/// lived, everything else long lived. They are what a device that did not say
/// is announced with.
pub const HOST_TTL: u32 = 120;
pub const OTHER_TTL: u32 = 4500;

/// DNS-SD service type enumeration (RFC 6763 section 9).
pub const META_QUERY: &str = "_services._dns-sd._udp.local";

/// What one device may have, however much it announces: more would be a
/// flood, not a device. (Its services are limited by `MaxServices=`.)
const MAX_SUBTYPES: usize = 16;

/// The name that DNS-SD service type enumeration asks for (RFC 6763 section 9).
pub const SERVICE_ENUMERATION: &str = "_services._dns-sd._udp.local";
const MAX_REVERSE: usize = 8;

/// A DNS-SD service advertised by a device, held in one block of bytes with
/// nothing to spare, and not to be changed in place: [`Service::edit`] makes
/// the block again if what it is made of is not as it was.
///
/// The block is its port and TTL, then its names, each ended by a NUL (which
/// no name can hold: see `proper`, and [`ServiceParts::encode`]): the instance, the type, the host it is on (empty if it is not
/// known), and the subtypes, which an empty name ends; and then its TXT data,
/// as it is on the wire, each string after its length, to the end of the
/// block.
#[derive(Clone, PartialEq, Eq)]
pub struct Service {
    block: Box<[u8]>,
}

/// What a [`Service`] is made of, as a plain value, for making one and for
/// changing one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceParts {
    /// Full instance name, e.g. `Printer._http._tcp.local`.
    pub instance: String,
    /// Service type, e.g. `_http._tcp.local`.
    pub kind: String,
    pub port: u16,
    pub target: Option<String>,
    /// TXT strings, usually `key=value`, as they came: a value is any bytes,
    /// only often text.
    pub txt: Vec<Vec<u8>>,
    /// The subtypes it said it is of, by the name of their PTR record, such as
    /// `_universal._sub._ipp._tcp.local` (an AirPrint printer).
    pub subtypes: Vec<String>,
    /// The TTL its records were last announced with, in seconds: that of the
    /// SRV record, or else of the PTR or TXT; 0 if not known.
    pub ttl: u32,
}

/// The port and the TTL, which come first in a block.
const SERVICE_HEADER: usize = 6;

impl ServiceParts {
    /// The block they make.
    ///
    /// # Panics
    ///
    /// If a name has a NUL, which the block ends a name with, or a string of
    /// TXT data is over 255 bytes, which is as long as the wire says one is.
    /// Neither is from the network, which is checked first (`proper`, and
    /// a string's length is a byte), nor from the configuration, which does
    /// not take them (`local_name`, `parse_service`): it is a mistake to make
    /// one.
    fn encode(&self) -> Vec<u8> {
        let name = |s: &str| {
            assert!(!s.contains('\0'), "a name has no NUL in it: {s:?}");
            s.len() + 1
        };
        let target = self.target.as_deref().unwrap_or("");
        // A subtype and a string of TXT data that is empty would not be said.
        let subtypes = || self.subtypes.iter().map(String::as_str).filter(|s| !s.is_empty());
        let txt = || {
            self.txt.iter().map(Vec::as_slice).filter(|s| !s.is_empty()).inspect(|s| {
                assert!(s.len() <= 255, "a string of TXT data is at most 255 bytes, not {}", s.len());
            })
        };
        let size = SERVICE_HEADER
            + [&self.instance, &self.kind].into_iter().map(|n| name(n)).sum::<usize>()
            + name(target)
            + subtypes().map(name).sum::<usize>()
            + 1
            + txt().map(|s| s.len() + 1).sum::<usize>();
        let mut out = Vec::with_capacity(size);
        out.extend(self.port.to_le_bytes());
        out.extend(self.ttl.to_le_bytes());
        for n in [self.instance.as_str(), self.kind.as_str(), target].into_iter().chain(subtypes()) {
            out.extend(n.as_bytes());
            out.push(0);
        }
        out.push(0);
        for string in txt() {
            out.push(string.len() as u8);
            out.extend(string);
        }
        debug_assert_eq!(out.len(), size);
        out
    }
}

impl From<ServiceParts> for Service {
    fn from(parts: ServiceParts) -> Service {
        Service { block: parts.encode().into_boxed_slice() }
    }
}

impl From<ServiceParts> for Rc<Service> {
    fn from(parts: ServiceParts) -> Rc<Service> {
        Rc::new(parts.into())
    }
}

/// Changing a service that a device holds in an `Rc`, as [`Service::edit`]
/// does one that is held alone: it is made again only if it is not as it was,
/// and then a copy, if it is held by a copy of the device too, so that theirs
/// stays as it was.
pub trait EditService {
    fn edit(&mut self, f: impl FnOnce(&mut ServiceParts)) -> bool;
}

impl EditService for Rc<Service> {
    fn edit(&mut self, f: impl FnOnce(&mut ServiceParts)) -> bool {
        let mut parts = self.parts();
        f(&mut parts);
        let block = parts.encode().into_boxed_slice();
        if *block == *self.block {
            return false;
        }
        match Rc::get_mut(self) {
            Some(service) => service.block = block,
            None => *self = Rc::new(Service { block }),
        }
        true
    }
}

impl Default for Service {
    fn default() -> Service {
        ServiceParts::default().into()
    }
}

impl core::fmt::Debug for Service {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Service")
            .field("instance", &self.instance())
            .field("kind", &self.kind())
            .field("port", &self.port())
            .field("target", &self.target())
            .field("txt", &self.txt().collect::<Vec<_>>())
            .field("subtypes", &self.subtypes().collect::<Vec<_>>())
            .field("ttl", &self.ttl())
            .finish()
    }
}

/// The bytes up to a NUL, and those after it.
fn until_nul(bytes: &[u8]) -> (&[u8], &[u8]) {
    let at = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    (&bytes[..at], bytes.get(at + 1..).unwrap_or_default())
}

/// A name from the block it was written into, which holds only what was text.
fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or_default()
}

impl Service {
    /// Its instance, the type, the host, the subtypes and the TXT data,
    /// each as the bytes it is in the block.
    fn fields(&self) -> [&[u8]; 5] {
        let (instance, rest) = until_nul(&self.block[SERVICE_HEADER.min(self.block.len())..]);
        let (kind, rest) = until_nul(rest);
        let (target, rest) = until_nul(rest);
        // The subtypes are the names up to the empty one.
        let mut after = rest;
        let mut len = 0;
        loop {
            let (name, next) = until_nul(after);
            after = next;
            if name.is_empty() {
                break;
            }
            len += name.len() + 1;
        }
        [instance, kind, target, &rest[..len.min(rest.len())], after]
    }

    /// Its port, 0 if it is not known.
    pub fn port(&self) -> u16 {
        self.block.get(0..2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
    }

    /// The TTL its records were last announced with, in seconds, or 0.
    pub fn ttl(&self) -> u32 {
        self.block.get(2..SERVICE_HEADER).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Full instance name, e.g. `Printer._http._tcp.local`.
    pub fn instance(&self) -> &str {
        text(self.fields()[0])
    }

    /// Service type, e.g. `_http._tcp.local`.
    pub fn kind(&self) -> &str {
        text(self.fields()[1])
    }

    /// The host it is on, if that is known.
    pub fn target(&self) -> Option<&str> {
        Some(text(self.fields()[2])).filter(|t| !t.is_empty())
    }

    /// The subtypes it said it is of, by the name of their PTR record, such as
    /// `_universal._sub._ipp._tcp.local` (an AirPrint printer).
    pub fn subtypes(&self) -> impl Iterator<Item = &str> {
        let mut rest = self.fields()[3];
        core::iter::from_fn(move || {
            let (name, next) = until_nul(rest);
            rest = next;
            (!name.is_empty()).then(|| text(name))
        })
    }

    /// Its TXT strings, usually `key=value`, as they came: a value is any
    /// bytes, only often text.
    pub fn txt(&self) -> impl Iterator<Item = &[u8]> {
        let mut rest = self.fields()[4];
        core::iter::from_fn(move || {
            let (&len, tail) = rest.split_first()?;
            let (string, tail) = tail.split_at(usize::from(len).min(tail.len()));
            rest = tail;
            Some(string)
        })
    }

    /// What it is made of.
    pub fn parts(&self) -> ServiceParts {
        ServiceParts {
            instance: self.instance().to_string(),
            kind: self.kind().to_string(),
            port: self.port(),
            target: self.target().map(String::from),
            txt: self.txt().map(<[u8]>::to_vec).collect(),
            subtypes: self.subtypes().map(String::from).collect(),
            ttl: self.ttl(),
        }
    }

    /// Change what it is made of with `f`; the block is made again only if
    /// that is not as it was. Returns whether it was changed.
    pub fn edit(&mut self, f: impl FnOnce(&mut ServiceParts)) -> bool {
        let mut parts = self.parts();
        f(&mut parts);
        let block = parts.encode();
        if *block == *self.block {
            return false;
        }
        self.block = block.into_boxed_slice();
        true
    }

    /// Whether it is known where it is, by its SRV record: a host and a port.
    /// One known only by name from a browse answer or a TXT record is not,
    /// and a copy of it would have to make up the rest.
    pub fn is_resolved(&self) -> bool {
        self.target().is_some() && self.port() != 0
    }
}

/// A device on an interface. Once it has announced a hostname it is known by
/// that; until then only by the address it was heard from.
///
/// Its addresses are of both families, whichever it was heard over: mDNS
/// records do not belong to the transport they came in, and an IPv4 packet
/// may well carry a device's IPv6 addresses.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Device {
    pub hostname: Option<String>,
    /// Its addresses: routable ones, which other networks can reach it at
    /// (IPv4, or global or ULA IPv6: a device often has both), then
    /// link-local ones, which only mean something on the link it was heard
    /// on; IPv4 before IPv6. At most [`DEFAULT_MAX_ADDRS`] of a family, unless
    /// the interface keeps more. [`Device::addrs`] has them as plain IPs.
    pub addresses: Box<[Address]>,
    /// Those it learned of are in order of their instance names, ignoring
    /// case: names that differ only in case are one and the same.
    pub services: Box<[Rc<Service>]>,
    /// The TTL its address records were last announced with, in seconds;
    /// `None` if it has not announced any (it was only heard from).
    pub ttl: Option<u32>,
    /// The record types it said its hostname has, by an NSEC record (such as
    /// A but no AAAA); `None` if it has not said.
    pub nsec: Option<Box<[u16]>>,
    /// The addresses it announced a reverse-mapping PTR for, naming its
    /// hostname (`9.1.0.10.in-addr.arpa PTR tv.local`).
    pub reverse: Box<[IpAddr]>,
}

/// A device as it is shown: with the addresses and services `how` says, and
/// the TTL its address records are announced with.
#[derive(Clone, Copy, Debug)]
pub struct Advertised<'a> {
    pub device: &'a Device,
    pub how: &'a Advertise,
    pub host_ttl: u32,
}

impl<'a> From<&'a Device> for Advertised<'a> {
    /// As it was heard, with everything it has and its own TTL.
    fn from(device: &'a Device) -> Advertised<'a> {
        static ALL: Advertise = Advertise::ALL;
        Advertised { device, how: &ALL, host_ttl: device.ttl.unwrap_or(HOST_TTL) }
    }
}

impl PartialEq for Advertised<'_> {
    /// Shown the same: the TTL that counts is the one it is shown with, not
    /// the device's own.
    fn eq(&self, other: &Advertised<'_>) -> bool {
        self.how == other.how && self.host_ttl == other.host_ttl && self.device.same_but_ttl(other.device)
    }
}

impl Eq for Advertised<'_> {}

/// A device held once, however many interfaces show it: it is changed where it
/// is heard, and those that show it see the change without being told. They
/// are told of what changed (an [`Event`](crate::tracker::Event)) when it is
/// time to do something about it. Two are the same device if they are the same
/// allocation ([`Shared::is`]), whatever they hold.
#[derive(Clone, Default)]
pub struct Shared(Rc<RefCell<Device>>);

impl Shared {
    pub fn new(device: Device) -> Shared {
        Shared(Rc::new(RefCell::new(device)))
    }

    pub fn borrow(&self) -> Ref<'_, Device> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<'_, Device> {
        self.0.borrow_mut()
    }

    /// Whether `other` is this very device, not just one that holds the same.
    pub fn is(&self, other: &Shared) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    /// Where it is, to tell devices apart by without holding them: valid for
    /// as long as it is held.
    pub fn addr(&self) -> usize {
        Rc::as_ptr(&self.0) as usize
    }

    /// What it holds now, for what is to be kept as it is.
    pub fn snapshot(&self) -> Device {
        self.0.borrow().clone()
    }
}

impl PartialEq for Shared {
    fn eq(&self, other: &Shared) -> bool {
        *self.0.borrow() == *other.0.borrow()
    }
}

impl Eq for Shared {}

impl core::fmt::Debug for Shared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.borrow().fmt(f)
    }
}

impl From<Device> for Shared {
    fn from(device: Device) -> Shared {
        Shared::new(device)
    }
}

/// A list a device holds, to be made longer or shorter: it is a `Vec` while it
/// is, and a boxed slice again when this is dropped, so that what it holds is
/// all it has room for. A device keeps its lists as boxed slices, which have no
/// room to spare, and this is the way to change how many they hold.
pub struct Listed<'a, T> {
    list: &'a mut Box<[T]>,
    items: Vec<T>,
}

/// Change how many `list` holds: use the result as the `Vec` it is for the
/// time it takes, as in `edit(&mut device.addresses).push(address)`.
pub fn edit<T>(list: &mut Box<[T]>) -> Listed<'_, T> {
    let items = core::mem::take(list).into_vec();
    Listed { list, items }
}

impl<T> core::ops::Deref for Listed<'_, T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Vec<T> {
        &self.items
    }
}

impl<T> core::ops::DerefMut for Listed<'_, T> {
    fn deref_mut(&mut self) -> &mut Vec<T> {
        &mut self.items
    }
}

impl<T> Drop for Listed<'_, T> {
    fn drop(&mut self) {
        *self.list = core::mem::take(&mut self.items).into_boxed_slice();
    }
}

/// An address of a device, with what is known of it besides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub origin: Origin,
}

/// Where an address of a device was learned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Origin {
    /// The device announced it, in an A or AAAA record, or sent from it.
    #[default]
    Announced,
    /// The kernel's neighbour table has it under the link-layer address of
    /// one of the device's link-local ones: the device did not say it, but
    /// it is the device's. Learned only of a family the device announced no
    /// routable address of, it lasts as long as the neighbour entry.
    Neighbour,
}

impl From<IpAddr> for Address {
    /// An announced address.
    fn from(ip: IpAddr) -> Address {
        Address { ip, origin: Origin::Announced }
    }
}

/// Put addresses in the order a device keeps them: routable before
/// link-local, IPv4 before IPv6, then by address.
fn sort_addrs(addrs: &mut [IpAddr]) {
    addrs.sort_by_key(addr_order);
}

/// Where `addr` comes among a device's addresses: routable before
/// link-local, IPv4 before IPv6.
fn addr_order(addr: &IpAddr) -> (bool, bool, IpAddr) {
    (is_link_local(addr), addr.is_ipv6(), *addr)
}

/// What one response says about one host: the addresses it announced for it,
/// and the records that are about it.
pub struct Report<'a> {
    pub host: String,
    /// Its usable addresses, of either family, as announced.
    pub addrs: Vec<IpAddr>,
    /// The records about it other than its addresses: those of the services
    /// whose SRV points at it, its NSEC, and its reverse mappings, each with its
    /// own TTL.
    pub records: Vec<&'a Record>,
    /// The addresses it announced that no device can be reached at. Having
    /// announced addresses of a family, it is not one to credit with the
    /// address of that family the packet came from instead.
    pub refused: Vec<IpAddr>,
    /// The families it announced addresses of with the cache-flush bit: those
    /// are all it has of the family (RFC 6762 section 10.2).
    pub flushed: Vec<Family>,
    /// The addresses it said goodbye to (TTL 0).
    pub gone: Vec<IpAddr>,
    /// The TTL each of its usable addresses was announced with: each runs
    /// out on its own. The only record of its addresses' TTLs; the others
    /// are worked out from it.
    pub ttls: HashMap<IpAddr, u32>,
}

impl<'a> Report<'a> {
    /// Read a response: the hosts it describes, and the records that tie to
    /// no host. A host is any name owning an address record or NSEC, targeted
    /// by an SRV record, or named by a reverse mapping. A service instance
    /// belongs to the host its SRV points at, and its PTR and TXT records
    /// follow it; those whose instance has no SRV in the packet, and the type
    /// enumeration, are left over.
    ///
    /// A response may describe several devices (a reflector answering a
    /// browse query does), so each record goes to the device it names
    /// instead of the whole packet to one.
    ///
    /// A record that is not [well formed](well_formed) is left out, as if it
    /// were not there.
    pub fn all(msg: &'a Message) -> (Vec<Report<'a>>, Vec<&'a Record>) {
        let records: Vec<&'a Record> = msg.records().filter(|r| well_formed(r)).collect();
        let mut reports: Vec<Report<'a>> = Vec::new();
        let mut instance_host: HashMap<String, usize> = HashMap::new();
        for &rec in &records {
            match &rec.data {
                RData::A(_) | RData::Aaaa(_) => {
                    report_index(&mut reports, &rec.name);
                }
                RData::Srv { target, .. } => {
                    let i = report_index(&mut reports, target);
                    instance_host.insert(rec.name.to_ascii_lowercase(), i);
                }
                RData::Nsec { .. } if !is_instance(&rec.name) => {
                    report_index(&mut reports, &rec.name);
                }
                RData::Ptr(host) if codec::reverse_addr(&rec.name).is_some() => {
                    report_index(&mut reports, host);
                }
                _ => {}
            }
        }

        let mut rest: Vec<&'a Record> = Vec::new();
        for &rec in &records {
            let instance = match &rec.data {
                RData::A(_) | RData::Aaaa(_) => {
                    report_index(&mut reports, &rec.name);
                    continue;
                }
                // What types a host has; those of service instances are not kept.
                RData::Nsec { .. } if !is_instance(&rec.name) => {
                    let i = report_index(&mut reports, &rec.name);
                    reports[i].records.push(rec);
                    continue;
                }
                // `9.1.0.10.in-addr.arpa PTR tv.local` is about the host it names.
                RData::Ptr(host) if codec::reverse_addr(&rec.name).is_some() => {
                    let i = report_index(&mut reports, host);
                    reports[i].records.push(rec);
                    continue;
                }
                RData::Srv { .. } | RData::Txt(_) => &rec.name,
                RData::Ptr(instance) => instance,
                _ => continue,
            };
            match instance_host.get(&instance.to_ascii_lowercase()) {
                Some(&i) => reports[i].records.push(rec),
                None => rest.push(rec),
            }
        }

        for r in &mut reports {
            (r.addrs, r.refused, r.ttls) = announced_addrs(&records, &r.host);
            for rec in records.iter().filter(|rec| rec.name.eq_ignore_ascii_case(&r.host)) {
                let Some(addr) = addr_of(&rec.data) else { continue };
                if rec.ttl == 0 {
                    r.gone.push(addr);
                } else if rec.cache_flush && !r.flushed.contains(&family_of(addr)) {
                    r.flushed.push(family_of(addr));
                }
            }
        }
        (reports, rest)
    }

    /// The longest TTL its addresses were announced with, if it announced
    /// any.
    pub fn addr_ttl(&self) -> Option<u32> {
        self.ttls.values().copied().max()
    }

    /// The longest TTL of anything it says about the host, its addresses and
    /// its other records: how long, at least, the host is to be kept.
    pub fn longest_ttl(&self) -> u32 {
        self.records.iter().map(|r| r.ttl).chain(self.addr_ttl()).max().unwrap_or(0)
    }

    /// The service instances it says where they are, by an SRV record.
    pub fn resolved(&self) -> impl Iterator<Item = &str> {
        self.records.iter().filter(|r| matches!(r.data, RData::Srv { .. })).map(|r| r.name.as_str())
    }
}

fn report_index(reports: &mut Vec<Report<'_>>, host: &str) -> usize {
    if let Some(i) = reports.iter().position(|r| r.host.eq_ignore_ascii_case(host)) {
        return i;
    }
    reports.push(Report {
        host: host.to_string(),
        addrs: Vec::new(),
        records: Vec::new(),
        refused: Vec::new(),
        flushed: Vec::new(),
        gone: Vec::new(),
        ttls: HashMap::new(),
    });
    reports.len() - 1
}

/// The usable addresses that `records` announce for `host`, of either
/// family, those they announced that are not, and the TTL each usable one
/// was announced with.
fn announced_addrs(records: &[&Record], host: &str) -> (Vec<IpAddr>, Vec<IpAddr>, HashMap<IpAddr, u32>) {
    let (mut found, mut refused, mut ttls) = (Vec::new(), Vec::new(), HashMap::new());
    for rec in records.iter().filter(|r| r.ttl > 0 && r.name.eq_ignore_ascii_case(host)) {
        let Some(addr) = addr_of(&rec.data) else { continue };
        if is_usable(addr) {
            let ttl = ttls.entry(addr).or_insert(0);
            *ttl = (*ttl).max(rec.ttl);
        }
        let list = if is_usable(addr) { &mut found } else { &mut refused };
        if !list.contains(&addr) {
            list.push(addr);
        }
    }
    (found, refused, ttls)
}

/// Whether a device could be reached at `addr`. Not at an unspecified,
/// loopback, multicast or broadcast address, nor in `0.0.0.0/8` or the
/// reserved `240.0.0.0/4`, nor at an IPv4 address dressed as IPv6 (mapped or
/// compatible), which no IPv6 network routes to. A link-local address is
/// usable, on its own link.
pub fn is_usable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let first = a.octets()[0];
            !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || first == 0 || first >= 240)
        }
        IpAddr::V6(a) => {
            let ipv4 = a.to_ipv4_mapped().is_some() || a.segments()[..6] == [0; 6];
            !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || ipv4)
        }
    }
}

/// Whether `rec` is one a device could have announced, as far as it alone
/// tells: of class IN, about a [host](is_hostname) or a service
/// [instance](is_instance_name), pointing at ones that can be, and a
/// service on a port. Records of other types are none the daemon keeps.
fn well_formed(rec: &Record) -> bool {
    if rec.class != 1 {
        return false;
    }
    match &rec.data {
        RData::A(_) | RData::Aaaa(_) => is_hostname(&rec.name),
        RData::Nsec { .. } => is_hostname(&rec.name) || is_instance_name(&rec.name),
        RData::Srv { port, target, .. } => *port != 0 && is_instance_name(&rec.name) && is_hostname(target),
        RData::Txt(_) => is_instance_name(&rec.name),
        RData::Ptr(target) if codec::reverse_addr(&rec.name).is_some() => is_hostname(target),
        RData::Ptr(target) if rec.name.eq_ignore_ascii_case(META_QUERY) => is_type(target),
        // A browse answer: an instance of the type, or the subtype's type.
        RData::Ptr(target) => {
            let kind = match browsed_type(&rec.name) {
                Some(kind) => kind,
                None => return false,
            };
            is_instance_name(target) && codec::split_instance(target).is_some_and(|(_, k)| k.eq_ignore_ascii_case(kind))
        }
        RData::Other { .. } => false,
    }
}

/// The type a browse PTR's name is of: itself, if a [type](is_type), or the
/// type of a subtype, `_universal._sub._ipp._tcp.local`.
fn browsed_type(name: &str) -> Option<&str> {
    if is_type(name) {
        return Some(name);
    }
    let (sub, rest) = codec::split_instance(name)?;
    let kind = rest.get(5..).filter(|_| starts_with_ci(rest, "_sub."))?;
    (proper(&unescape(sub)) && is_type(kind)).then_some(kind)
}

/// Whether `name` can be a host's: under `.local`, and each of its labels
/// [proper](proper), with no dot, backslash or space in it.
pub fn is_hostname(name: &str) -> bool {
    if name.contains('\\') {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.last().is_some_and(|l| l.eq_ignore_ascii_case("local"))
        && labels.iter().all(|l| proper(l) && !l.contains(' '))
}

/// Whether `name` is a service type: `_name._tcp.local` or `_name._udp.local`,
/// the name of letters, digits, hyphens and underscores.
pub fn is_type(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    let [service, proto, local] = labels[..] else { return false };
    let ok = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    service.len() >= 2
        && service.starts_with('_')
        && service.chars().all(ok)
        && (proto.eq_ignore_ascii_case("_tcp") || proto.eq_ignore_ascii_case("_udp"))
        && local.eq_ignore_ascii_case("local")
}

/// Whether `name` is a service instance's: a [proper](proper) label (which
/// may hold spaces and dots), of a [type](is_type).
pub fn is_instance_name(name: &str) -> bool {
    codec::split_instance(name).is_some_and(|(label, kind)| proper(&unescape(label)) && is_type(kind))
}

/// A label that can be in a name: not empty, at most 63 bytes, without
/// control characters, and of valid UTF-8 (which the parser turns invalid
/// bytes from).
fn proper(label: &str) -> bool {
    !label.is_empty() && label.len() <= 63 && !label.chars().any(|c| c.is_control() || c == char::REPLACEMENT_CHARACTER)
}

/// A label as it was on the wire, without the parser's escapes.
fn unescape(label: &str) -> String {
    let mut out = String::new();
    let mut escaped = false;
    for c in label.chars() {
        if c == '\\' && !escaped {
            escaped = true;
        } else {
            escaped = false;
            out.push(c);
        }
    }
    out
}

impl Device {
    /// Whether it is the same as `other` but for its TTL.
    pub fn same_but_ttl(&self, other: &Device) -> bool {
        self.hostname == other.hostname
            && self.addresses == other.addresses
            && self.services == other.services
            && self.nsec == other.nsec
            && self.reverse == other.reverse
    }

    /// Its addresses, the routable ones first, IPv4 before IPv6.
    pub fn addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addresses.iter().map(|a| a.ip)
    }

    /// Whether `ip` is one of its addresses.
    pub fn has_addr(&self, ip: &IpAddr) -> bool {
        self.addresses.iter().any(|a| a.ip == *ip)
    }

    /// The IPs of [its addresses as `how` would advertise them](Device::advertised).
    pub fn advertised_addrs<'a>(&'a self, how: &'a Advertise) -> impl Iterator<Item = IpAddr> + 'a {
        self.advertised(how).map(|a| a.ip)
    }

    /// Its services as `how` would advertise them.
    pub fn advertised_services<'a>(&'a self, how: &'a Advertise) -> impl Iterator<Item = &'a Rc<Service>> + 'a {
        self.services.iter().filter(move |s| (!how.resolved_only || s.is_resolved()) && how.allows(s.kind()))
    }

    /// Its addresses as `how` would advertise them, with where each was
    /// learned.
    pub fn advertised<'a>(&'a self, how: &'a Advertise) -> impl Iterator<Item = &'a Address> + 'a {
        // A family it announced a link-local address of: it speaks it, if
        // only on its own link.
        let speaks = |v4: bool| {
            self.addresses.iter().any(|a| a.origin == Origin::Announced && a.ip.is_ipv4() == v4 && is_link_local(&a.ip))
        };
        let (v4, v6) = if how.neighbours == Neighbours::LinkLocal { (speaks(true), speaks(false)) } else { (false, false) };
        self.addresses.iter().filter(move |a| {
            (how.link_local || !is_link_local(&a.ip))
                && (a.origin == Origin::Announced
                    || match how.neighbours {
                        Neighbours::Always => true,
                        Neighbours::LinkLocal => if a.ip.is_ipv4() { v4 } else { v6 },
                        Neighbours::Never => false,
                    })
        })
    }

    /// Its routable addresses, IPv4 before IPv6.
    pub fn routable(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addrs().filter(|a| !is_link_local(a))
    }

    /// The address record types to ask it for: of the families it has an
    /// address of, or both if it has none.
    pub fn address_types(&self) -> Vec<u16> {
        match (self.addrs().any(|a| a.is_ipv4()), self.addrs().any(|a| a.is_ipv6())) {
            (true, false) => vec![rtype::A],
            (false, true) => vec![rtype::AAAA],
            _ => vec![rtype::A, rtype::AAAA],
        }
    }

    /// Whether this device is to be announced on another network, as `how`
    /// says: only if it has what `when` asks for: a hostname for the address
    /// record, a routable address to put in it among those `how` advertises (a
    /// device known only by a link-local one cannot be reached from another
    /// network), and a service to give clients a reason to care (bare chatty
    /// clients such as phones are skipped).
    pub fn reflectable(&self, how: &Advertise, when: &ReflectedWhen) -> bool {
        (!when.hostname || self.hostname.is_some())
            && (!when.address || self.advertised(how).next().is_some())
            && (!when.service || self.advertised_services(how).next().is_some())
    }

    /// This device together with `other`, of the same host: what either has,
    /// whichever is which. It is what is announced of a device that more than
    /// one segment reflects from the same interface, each as it is to show it
    /// (`how`, and `other_how` for `other`). The addresses it has are those
    /// advertised of either, which is all there is of the two.
    pub fn union(&self, how: &Advertise, other: &Device, other_how: &Advertise) -> Device {
        let mut device = Device {
            addresses: self.advertised(how).copied().collect(),
            services: self.advertised_services(how).cloned().collect(),
            ..self.clone()
        };
        for address in other.advertised(other_how) {
            match device.addresses.iter_mut().find(|a| a.ip == address.ip) {
                Some(mine) => {
                    if address.origin == Origin::Announced {
                        mine.origin = Origin::Announced;
                    }
                }
                None => edit(&mut device.addresses).push(*address),
            }
        }
        device.addresses.sort_by_key(|a| addr_order(&a.ip));
        for service in other.advertised_services(other_how) {
            if device.service(&service.instance()).is_none() {
                device.insert_service(service.clone());
            }
        }
        device.ttl = device.ttl.max(other.ttl);
        device.nsec = match (device.nsec.take(), &other.nsec) {
            (None, None) => None,
            (mine, theirs) => {
                let mut types: Vec<u16> = mine.into_iter().chain(theirs.clone()).flatten().collect();
                types.sort_unstable();
                types.dedup();
                Some(types.into_boxed_slice())
            }
        };
        edit(&mut device.reverse).extend(other.reverse.iter().copied());
        device.reverse.sort_unstable();
        edit(&mut device.reverse).dedup();
        device
    }

    /// What identifies it among the reflected devices and to the segment: its
    /// hostname, case-insensitively.
    pub fn key(&self) -> Option<String> {
        self.hostname.as_ref().map(|h| h.to_ascii_lowercase())
    }

    /// Its service called `instance`, ignoring case.
    pub fn service(&self, instance: &str) -> Option<&Service> {
        self.services.iter().map(|s| &**s).find(|s| s.instance().eq_ignore_ascii_case(instance))
    }

    /// Forget its service called `instance`, ignoring case.
    pub fn forget_service(&mut self, instance: &str) {
        edit(&mut self.services).retain(|s| !s.instance().eq_ignore_ascii_case(instance));
    }

    /// Take in what `report` says about it, with the addresses that vouch for
    /// it: those announced, and the one the packet came from if it sent it,
    /// keeping at most `max_addrs` of a family and `max_services` services.
    pub fn learn(&mut self, report: &Report<'_>, addrs: &[IpAddr], max_addrs: usize, max_services: usize) {
        self.hostname = Some(report.host.clone());
        self.take_addrs(addrs, &report.flushed, &report.gone, max_addrs);
        self.ttl = report.addr_ttl().or(self.ttl);
        self.learn_records(report.records.iter().copied(), max_services);
    }

    /// Take in the addresses a packet vouches for, of either family. Of a
    /// family in `flushed`, announced with the cache-flush bit, they are all
    /// it has announced, and replace those it had announced (RFC 6762 section
    /// 10.2); of another, they are added. Those in `gone`, said goodbye to,
    /// are dropped. Beyond `max_addrs` of a family, more are not taken. One
    /// learned from the neighbour table that it now announces is announced;
    /// once it announces a routable address of a family, none of that family
    /// learned so is kept.
    pub fn take_addrs(&mut self, addrs: &[IpAddr], flushed: &[Family], gone: &[IpAddr], max_addrs: usize) {
        edit(&mut self.addresses).retain(|a| {
            let flushed = a.origin == Origin::Announced && flushed.contains(&family_of(a.ip));
            !flushed && !gone.contains(&a.ip)
        });
        let mut fresh: Vec<IpAddr> = addrs.iter().copied().filter(|a| !gone.contains(a)).collect();
        sort_addrs(&mut fresh);
        for addr in fresh {
            if let Some(known) = self.addresses.iter_mut().find(|a| a.ip == addr) {
                known.origin = Origin::Announced;
                continue;
            }
            // Only what it announced counts: what the neighbour table said of
            // it gives way to that, below.
            let announced = |a: &&Address| a.origin == Origin::Announced && a.ip.is_ipv4() == addr.is_ipv4();
            if self.addresses.iter().filter(announced).count() < max_addrs {
                edit(&mut self.addresses).push(addr.into());
            }
        }
        self.drop_neighbours_of_announced_families();
        // One it announced only link-local leaves the learned ones of its
        // family, which must still fit with it.
        for v4 in [true, false] {
            let mut room = max_addrs;
            edit(&mut self.addresses).retain(|a| {
                if a.ip.is_ipv4() != v4 {
                    return true;
                }
                let keep = room > 0 || a.origin == Origin::Announced;
                room = room.saturating_sub(1);
                keep
            });
        }
        self.addresses.sort_by_key(|a| addr_order(&a.ip));
    }

    /// Take in what the neighbour table says of it: `learned`, the routable
    /// addresses listed under the link-layer address of one of its link-local
    /// ones. Of a family it announced no routable address of, they replace
    /// those it had learned so (up to `max_addrs` of a family in all); of
    /// another, none are kept, as what it announces is what it has. Returns
    /// whether its addresses changed.
    pub fn take_neighbours(&mut self, learned: &[IpAddr], max_addrs: usize) -> bool {
        let before = self.addresses.clone();
        edit(&mut self.addresses).retain(|a| a.origin != Origin::Neighbour || learned.contains(&a.ip));
        let mut learned: Vec<IpAddr> = learned.iter().copied().filter(|a| !is_link_local(a)).collect();
        sort_addrs(&mut learned);
        for ip in learned {
            let of_family = self.addresses.iter().filter(|a| a.ip.is_ipv4() == ip.is_ipv4()).count();
            if !self.has_addr(&ip) && of_family < max_addrs {
                edit(&mut self.addresses).push(Address { ip, origin: Origin::Neighbour });
            }
        }
        self.drop_neighbours_of_announced_families();
        self.addresses.sort_by_key(|a| addr_order(&a.ip));
        self.addresses != before
    }

    /// Drop the addresses learned from the neighbour table of a family it
    /// announced a routable address of itself.
    fn drop_neighbours_of_announced_families(&mut self) {
        let announced = |v4: bool| {
            self.addresses.iter().any(|a| a.origin == Origin::Announced && a.ip.is_ipv4() == v4 && !is_link_local(&a.ip))
        };
        let (v4, v6) = (announced(true), announced(false));
        edit(&mut self.addresses).retain(|a| a.origin != Origin::Neighbour || !(if a.ip.is_ipv4() { v4 } else { v6 }));
    }

    /// Its link-local addresses, whose link-layer address finds the others in
    /// the neighbour table.
    pub fn link_local(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addrs().filter(is_link_local)
    }

    /// Add `addrs` to those it has, up to [`DEFAULT_MAX_ADDRS`] of a family:
    /// for a device made rather than heard of.
    pub fn add_addrs(&mut self, addrs: &[IpAddr]) {
        self.take_addrs(addrs, &[], &[], DEFAULT_MAX_ADDRS);
    }

    /// Take in the service records, NSEC and reverse mappings in `records`, up
    /// to `max_services` services. A TTL of 0 is a goodbye for what the
    /// record says.
    pub fn learn_records<'a>(&mut self, records: impl Iterator<Item = &'a Record>, max_services: usize) {
        for rec in records {
            match &rec.data {
                RData::Ptr(host) if codec::reverse_addr(&rec.name).is_some() => {
                    let addr = codec::reverse_addr(&rec.name).expect("checked above");
                    if self.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host)) {
                        edit(&mut self.reverse).retain(|a| *a != addr);
                        if rec.ttl != 0 && self.reverse.len() < MAX_REVERSE {
                            edit(&mut self.reverse).push(addr);
                        }
                    }
                }
                RData::Ptr(instance) => {
                    // Only service-instance PTRs and their subtypes; skip the
                    // `_services._dns-sd` meta-enumeration.
                    if !is_service_type(&rec.name) || starts_with_ci(&rec.name, "_services.") {
                        continue;
                    }
                    // `_universal._sub._ipp._tcp.local`: the instance is also of a subtype.
                    if rec.name.to_ascii_lowercase().contains("._sub.") {
                        let same = |sub: &String| sub.eq_ignore_ascii_case(&rec.name);
                        if rec.ttl == 0 {
                            if let Some(svc) = self.services.iter_mut().find(|s| s.instance().eq_ignore_ascii_case(instance)) {
                                svc.edit(|p| p.subtypes.retain(|sub| !same(sub)));
                            }
                        } else if let Some(svc) = self.service_mut(instance, max_services)
                            && !svc.subtypes().any(|sub| rec.name.eq_ignore_ascii_case(sub))
                            && svc.subtypes().count() < MAX_SUBTYPES
                        {
                            svc.edit(|p| p.subtypes.push(rec.name.clone()));
                        }
                        continue;
                    }
                    if rec.ttl == 0 {
                        self.forget_service(instance);
                    } else if let Some(svc) = self.service_mut(instance, max_services)
                        && (svc.kind() != rec.name || svc.ttl() == 0)
                    {
                        svc.edit(|p| {
                            p.kind = rec.name.clone();
                            // The SRV record's TTL is the one that counts, if known.
                            if p.ttl == 0 {
                                p.ttl = rec.ttl;
                            }
                        });
                    }
                }
                RData::Srv { port, target, .. } => {
                    if rec.ttl == 0 {
                        self.forget_service(&rec.name);
                    } else if let Some(svc) = self.service_mut(&rec.name, max_services)
                        && (svc.port() != *port || svc.target() != Some(target.as_str()) || svc.ttl() != rec.ttl)
                    {
                        svc.edit(|p| {
                            p.port = *port;
                            p.target = Some(target.clone());
                            p.ttl = rec.ttl;
                        });
                    }
                }
                RData::Nsec { types, .. } => {
                    if self.hostname.as_deref().is_some_and(|host| host.eq_ignore_ascii_case(&rec.name)) {
                        self.nsec = (rec.ttl != 0).then(|| Box::from(&types[..]));
                    }
                }
                RData::Txt(strings) => {
                    if rec.ttl != 0
                        && let Some(svc) = self.service_mut(&rec.name, max_services)
                        && (svc.ttl() == 0 || !svc.txt().eq(strings.iter().filter(|s| !s.is_empty()).map(Vec::as_slice)))
                    {
                        svc.edit(|p| {
                            p.txt = strings.iter().filter(|s| !s.is_empty()).cloned().collect();
                            if p.ttl == 0 {
                                p.ttl = rec.ttl;
                            }
                        });
                    }
                }
                _ => {}
            }
        }
    }

    /// Take over the services learned about it before its name was known, up
    /// to `max_services`.
    pub fn absorb(&mut self, earlier: Device, max_services: usize) {
        for svc in earlier.services {
            if self.service(&svc.instance()).is_none() && self.services.len() < max_services {
                self.insert_service(svc);
            }
        }
    }

    /// Get or create a service, deriving its type from the instance name
    /// until a PTR record states it explicitly. It keeps the spelling it was
    /// first heard with, whatever the case of later records. `None` if it is
    /// new and the device has `max_services` already.
    fn service_mut(&mut self, instance: &str, max_services: usize) -> Option<&mut Rc<Service>> {
        let at = match self.services.iter().position(|s| s.instance().eq_ignore_ascii_case(instance)) {
            Some(at) => at,
            None if self.services.len() >= max_services => return None,
            None => self.insert_service(
                ServiceParts {
                    instance: instance.to_string(),
                    kind: codec::split_instance(instance).map(|(_, kind)| kind.to_string()).unwrap_or_default(),
                    ..ServiceParts::default()
                }
                .into(),
            ),
        };
        Some(&mut self.services[at])
    }

    /// Add `svc` in its place among the services, and return where that is.
    fn insert_service(&mut self, svc: Rc<Service>) -> usize {
        let key = svc.instance().to_ascii_lowercase();
        let at = self.services.partition_point(|s| s.instance().to_ascii_lowercase() < key);
        edit(&mut self.services).insert(at, svc);
        at
    }

    /// This device without the services whose instance names `taken` says
    /// are taken: itself, if it has none.
    pub fn without(&self, taken: &dyn Fn(&str) -> bool) -> Cow<'_, Device> {
        if !self.services.iter().any(|s| taken(&s.instance())) {
            return Cow::Borrowed(self);
        }
        let mut device = self.clone();
        edit(&mut device.services).retain(|s| !taken(&s.instance()));
        Cow::Owned(device)
    }

    /// The names its [announcement](Device::announcement) has records under,
    /// in the case it has them: the hostname, the reverse names it announced,
    /// and for each service its type, its instance and its subtypes, and the
    /// type enumeration if it has any. None if it has no hostname, and so no
    /// records. A name may come twice.
    pub fn for_each_name(&self, how: &Advertise, mut f: impl FnMut(&str)) {
        let Some(host) = &self.hostname else { return };
        f(host);
        for addr in self.advertised_addrs(how).filter(|addr| self.reverse.contains(addr)) {
            f(&codec::reverse_name(addr));
        }
        let mut any = false;
        for svc in self.advertised_services(how) {
            any = true;
            f(&svc.kind());
            f(&svc.instance());
            for sub in svc.subtypes() {
                f(sub);
            }
        }
        if any {
            f(SERVICE_ENUMERATION);
        }
    }

    /// Whether its announcement has records under `name`, ignoring case:
    /// whether it can answer a question asking for that name.
    pub fn has_name(&self, how: &Advertise, name: &str) -> bool {
        let mut found = false;
        self.for_each_name(how, |own| found |= own.eq_ignore_ascii_case(name));
        found
    }

    /// The device as far as the service types `kinds` go: its services of
    /// one of them, or `None` if it has none.
    pub fn only_kinds(&self, kinds: &[String]) -> Option<Device> {
        let services: Vec<Rc<Service>> =
            self.services.iter().filter(|s| kinds.iter().any(|k| s.kind().eq_ignore_ascii_case(k))).cloned().collect();
        (!services.is_empty()).then(|| Device { services: services.into(), ..self.clone() })
    }

}



/// The address an A or AAAA record holds.
pub fn addr_of(data: &RData) -> Option<IpAddr> {
    match data {
        RData::A(a) => Some(IpAddr::V4(*a)),
        RData::Aaaa(a) => Some(IpAddr::V6(*a)),
        _ => None,
    }
}

/// Whether `name` is that of a service instance, such as
/// `Office._ipp._tcp.local`, rather than of a host.
fn is_instance(name: &str) -> bool {
    codec::split_instance(name).is_some_and(|(_, kind)| is_service_type(kind))
}

pub fn is_service_type(name: &str) -> bool {
    ends_with_ci(name, "._tcp.local") || ends_with_ci(name, "._udp.local")
}

/// Whether `name` starts with `prefix`, ignoring case as DNS does.
fn starts_with_ci(name: &str, prefix: &str) -> bool {
    name.as_bytes().get(..prefix.len()).is_some_and(|b| b.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Whether `name` ends with `suffix`, ignoring case as DNS does.
fn ends_with_ci(name: &str, suffix: &str) -> bool {
    let at = name.len().wrapping_sub(suffix.len());
    name.as_bytes().get(at..).is_some_and(|b| b.eq_ignore_ascii_case(suffix.as_bytes()))
}

#[cfg(test)]
#[path = "../tests/unit/device.rs"]
pub(crate) mod tests;
