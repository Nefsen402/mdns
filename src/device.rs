//! What is known about a device on a segment: its hostname, addresses and
//! services. Kept by [`Segment`](crate::segment::Segment), and announced on
//! other segments by the [`Reflector`](crate::reflector::Reflector).
//!
//! A response is read into one [`Report`] per host it describes, which a
//! [`Device`] then takes in with [`Device::learn`]; a device is turned back
//! into records with [`Device::announcement`] and [`Device::answers`].

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::{Ref, RefCell, RefMut};
use alloc::collections::{BTreeMap, BTreeSet};

use hashbrown::{HashMap, HashSet};
use core::net::IpAddr;

use crate::config::{Advertise, Neighbours, ReflectedWhen, DEFAULT_MAX_ADDRS};
#[cfg(test)]
use crate::config::DEFAULT_MAX_SERVICES;
use crate::codec::{self, rtype, Header, Message, Question, RData, Record};
use crate::listener::Family;

use crate::prelude::*;

/// TTLs for announced records (RFC 6762 section 10): host records are short
/// lived, everything else long lived. They are what a device that did not say
/// is announced with.
pub const HOST_TTL: u32 = 120;
pub const OTHER_TTL: u32 = 4500;

/// TTL cap for replies to legacy unicast resolvers (RFC 6762 section 6.7).
pub const LEGACY_TTL_CAP: u32 = 10;

/// DNS-SD service type enumeration (RFC 6763 section 9).
pub const META_QUERY: &str = "_services._dns-sd._udp.local";

/// Questions per query packet, at most; fewer if they are long and would
/// not fit in one packet.
pub const QUESTIONS_PER_PACKET: usize = 16;

/// The most a packet may hold until the interface's MTU is known: a 1500-byte
/// Ethernet frame less the IPv6 and UDP headers. Every packet the daemon
/// sends is kept within its interface's limit, as one that is not goes out in
/// IP fragments, which many devices and access points drop.
pub const DEFAULT_MAX_PACKET: usize = 1452;

/// What a legacy resolver takes unless its query says it takes more, with
/// EDNS0 (RFC 1035 section 4.2.1, RFC 6891).
const LEGACY_PACKET: usize = 512;

/// The type of the EDNS0 pseudo-record, whose class is the size of reply
/// the asker takes.
const OPT: u16 = 41;

/// Subtypes a probe asks for when their type is around. A device sends its
/// subtypes only when it announces itself and when asked for one by name,
/// not when its type is browsed, yet some clients browse by subtype alone:
/// iOS finds AirPrint printers by `_universal`, and Matter controllers find
/// devices that are ready to be added by `_CM`.
const KNOWN_SUBTYPES: [&str; 4] = [
    "_universal._sub._ipp._tcp.local",
    "_universal._sub._ipps._tcp.local",
    "_printer._sub._http._tcp.local",
    "_CM._sub._matterc._udp.local",
];

/// What one device may have, however much it announces: more would be a
/// flood, not a device. (Its services are limited by `MaxServices=`.)
const MAX_SUBTYPES: usize = 16;

/// The name that DNS-SD service type enumeration asks for (RFC 6763 section 9).
const SERVICE_ENUMERATION: &str = "_services._dns-sd._udp.local";
const MAX_REVERSE: usize = 8;

/// A reflected device is never announced for less than this, however short a
/// TTL it announced itself with: where a segment announces again, it is at 80%
/// of its TTL, and a few seconds would be a flood.
pub const MIN_REFLECT_TTL: u32 = 10;

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

/// A device on a segment. Once it has announced a hostname it is known by
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
    /// the segment keeps more. [`Device::addrs`] has them as plain IPs.
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

/// A device held once, however many segments show it: it is changed where it
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

/// The family of `addr`.
pub fn family_of(addr: IpAddr) -> Family {
    if addr.is_ipv4() { Family::V4 } else { Family::V6 }
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

/// Link-local: IPv6 `fe80::/10` and IPv4 `169.254.0.0/16`. Valid on one link
/// only, so never to be handed to another network.
pub fn is_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
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
    /// one reflector reflects from the same segment, each as it is to show it
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

    /// What identifies it among the reflected devices and to the reflector: its
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

    /// The records that announce it. A TTL of 0 turns them into goodbyes.
    /// Callers must have checked that it has a hostname.
    pub fn announcement(&self, how: &Advertise, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let host = self.hostname.clone().expect("hostname checked on add");
        let mut records: Vec<Record> =
            self.advertised_addrs(how).map(|addr| record(host.clone(), true, host_ttl, address_data(addr))).collect();
        records.extend(self.nsec_record(how, host_ttl));
        records.extend(self.reverse_records(how, host_ttl));

        for svc in self.advertised_services(how) {
            records.extend(self.service_records(svc, service_ttl(svc, other_ttl)));
        }
        // DNS-SD service type enumeration, once per distinct type.
        let kinds: BTreeMap<String, &str> =
            self.advertised_services(how).map(|s| (s.kind().to_ascii_lowercase(), s.kind())).collect();
        for kind in kinds.into_values() {
            records.push(record(SERVICE_ENUMERATION.into(), false, other_ttl, RData::Ptr(kind.to_string())));
        }
        records
    }

    /// The records that take a segment from announcing this device to
    /// announcing `new` under the same hostname: all of `new`, and goodbyes
    /// for the services and addresses of this one that `new` does not have.
    pub fn replacement(&self, how: &Advertise, new: Advertised, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let Advertised { device: new, how: new_how, .. } = new;
        let mut records = new.announcement(new_how, host_ttl, other_ttl);
        let kept: HashMap<String, &Service> =
            new.advertised_services(new_how).map(|s| (s.instance().to_ascii_lowercase(), &**s)).collect();
        for svc in self.advertised_services(how) {
            match kept.get(&svc.instance().to_ascii_lowercase()) {
                None => records.extend(self.service_records(svc, 0)),
                Some(now) => {
                    let gone =
                        svc.subtypes().filter(|sub| !now.subtypes().any(|n| n.eq_ignore_ascii_case(sub)));
                    records.extend(gone.map(|sub| record(sub.to_string(), false, 0, RData::Ptr(svc.instance().to_string()))));
                }
            }
        }
        let host = self.hostname.clone().unwrap_or_default();
        for gone in self.advertised_addrs(how).filter(|a| !new.advertised_addrs(new_how).any(|n| n == *a)) {
            records.push(record(host.clone(), true, 0, address_data(gone)));
        }
        let still = new.reverse_records(new_how, 1);
        for gone in self.reverse_records(how, 0) {
            if !still.iter().any(|r| r.name == gone.name && r.data == gone.data) {
                records.push(gone);
            }
        }
        records
    }

    /// The reverse-mapping PTRs of its addresses, for those it announced one
    /// for itself: a device with several hostnames names one of them, and two
    /// copies saying different things would flush each other.
    fn reverse_records(&self, how: &Advertise, ttl: u32) -> Vec<Record> {
        let Some(host) = &self.hostname else { return Vec::new() };
        self.advertised_addrs(how)
            .filter(|addr| self.reverse.contains(addr))
            .map(|addr| record(codec::reverse_name(addr), true, ttl, RData::Ptr(host.clone())))
            .collect()
    }

    /// The NSEC record that says which types its hostname has, if it said so
    /// itself: never more than it denied, so whatever it has that is announced
    /// is listed too. A responder may only deny what it owns (RFC 6762 section
    /// 6.1), so a device that said nothing gets none.
    pub fn nsec_record(&self, how: &Advertise, ttl: u32) -> Option<Record> {
        let host = self.hostname.clone()?;
        let said = self.nsec.as_ref()?;
        let ours = self.advertised_addrs(how).map(|addr| match addr {
            IpAddr::V4(_) => rtype::A,
            IpAddr::V6(_) => rtype::AAAA,
        });
        // The restricted form mDNS uses: block 0 only, without NSEC itself.
        let types: BTreeSet<u16> =
            said.iter().copied().chain(ours).filter(|&t| t < 256 && t != rtype::NSEC).collect();
        let data = RData::Nsec { next: host.clone(), types: types.into_iter().collect() };
        Some(record(host, true, ttl, data))
    }

    fn service_records(&self, svc: &Service, ttl: u32) -> Vec<Record> {
        let target = svc.target().map(String::from).or_else(|| self.hostname.clone()).unwrap_or_default();
        let subtypes =
            svc.subtypes().map(|sub| record(sub.to_string(), false, ttl, RData::Ptr(svc.instance().to_string())));
        let mut records = vec![
            record(svc.kind().to_string(), false, ttl, RData::Ptr(svc.instance().to_string())),
            record(svc.instance().to_string(), true, ttl, RData::Srv { priority: 0, weight: 0, port: svc.port(), target }),
            record(
                svc.instance().to_string(),
                true,
                ttl,
                RData::Txt(svc.txt().map(|t| t.to_vec()).collect()),
            ),
        ];
        records.extend(subtypes);
        records
    }

    /// The queries that look for devices on a segment where `devices` are
    /// known and `types` were said to be offered: what types there are, the
    /// instances of each, the subtypes clients browse by (they are not sent
    /// when their type is browsed), where each instance not yet resolved is,
    /// and the addresses of a device known by name but without a routable
    /// address (it only ever showed a link-local one), of both families.
    pub fn probe_queries(devices: &[Device], types: &BTreeSet<String>, limit: usize) -> Vec<Message> {
        let mut qs = Questions::default();
        qs.ask(META_QUERY, rtype::PTR);

        let services = || devices.iter().flat_map(|d| &d.services);
        let mut kinds: BTreeSet<&str> = types.iter().map(String::as_str).collect();
        kinds.extend(services().map(|s| s.kind()).filter(|k| !k.is_empty()));
        let known: HashSet<String> = kinds.iter().map(|k| k.to_ascii_lowercase()).collect();
        for kind in kinds {
            qs.ask(kind, rtype::PTR);
        }
        // The subtypes clients browse by, and the ones heard of, to keep them up.
        let wanted = KNOWN_SUBTYPES.into_iter().filter(|sub| {
            sub.split_once("._sub.").is_some_and(|(_, kind)| known.contains(&kind.to_ascii_lowercase()))
        });
        for sub in wanted.chain(services().flat_map(|s| s.subtypes())) {
            qs.ask(sub, rtype::PTR);
        }
        for svc in services().filter(|s| s.target().is_none()) {
            qs.ask(&svc.instance(), rtype::SRV);
            qs.ask(&svc.instance(), rtype::TXT);
        }
        for host in devices.iter().filter(|d| d.routable().next().is_none()).filter_map(|d| d.hostname.as_deref()) {
            qs.ask(host, rtype::A);
            qs.ask(host, rtype::AAAA);
        }
        qs.into_queries(limit)
    }

    /// Queries that ask `questions`, put on another segment, as this
    /// daemon's own: each once, a few to a packet, and for a multicast answer
    /// whatever the asker wanted, so that it is heard and can be reflected.
    /// Each packet carries the `known` answers to its questions, as many as
    /// fit, so that devices already heard of need not answer. No packet is
    /// bigger than `limit`.
    pub fn forward_queries<'a>(
        questions: impl IntoIterator<Item = &'a Question>,
        known: impl Fn(&Question) -> Vec<Record>,
        limit: usize,
    ) -> Vec<Message> {
        let mut qs = Questions::default();
        for q in questions {
            qs.ask(&q.name, q.qtype);
        }
        with_known(qs.into_queries(limit), known, limit)
    }

    /// Queries for the service types `kinds`, as asked for by name: each
    /// type, and, of the devices that have one, the instances not yet
    /// resolved and the hostnames without a routable address. Each packet
    /// carries the `known` answers to its questions, as many as fit.
    pub fn type_queries(
        devices: &[Device],
        kinds: &[String],
        known: impl Fn(&Question) -> Vec<Record>,
        limit: usize,
    ) -> Vec<Message> {
        let mut qs = Questions::default();
        for kind in kinds {
            qs.ask(kind, rtype::PTR);
        }
        let of_kind = |s: &&Rc<Service>| kinds.iter().any(|k| s.kind().eq_ignore_ascii_case(k));
        for svc in devices.iter().flat_map(|d| &d.services).filter(of_kind).filter(|s| s.target().is_none()) {
            qs.ask(&svc.instance(), rtype::SRV);
            qs.ask(&svc.instance(), rtype::TXT);
        }
        let unreachable = devices.iter().filter(|d| d.services.iter().any(|s| of_kind(&s)) && d.routable().next().is_none());
        for host in unreachable.filter_map(|d| d.hostname.as_deref()) {
            qs.ask(host, rtype::A);
            qs.ask(host, rtype::AAAA);
        }
        with_known(qs.into_queries(limit), known, limit)
    }

    /// The device as far as the service types `kinds` go: its services of
    /// one of them, or `None` if it has none.
    pub fn only_kinds(&self, kinds: &[String]) -> Option<Device> {
        let services: Vec<Rc<Service>> =
            self.services.iter().filter(|s| kinds.iter().any(|k| s.kind().eq_ignore_ascii_case(k))).cloned().collect();
        (!services.is_empty()).then(|| Device { services: services.into(), ..self.clone() })
    }

    /// Its records that answer `q`, with these TTLs, without the additional
    /// records an answer brings, nor an NSEC saying it has none.
    pub fn records_for(&self, how: &Advertise, q: &Question, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let (mut records, _) = self.answers(how, &query(core::slice::from_ref(q)), host_ttl, other_ttl);
        records.retain(|r| r.rtype() != rtype::NSEC);
        records
    }

    /// Whether it has an answer to `q`: a record, or, by its NSEC, the word
    /// that there is none.
    pub fn knows(&self, how: &Advertise, q: &Question) -> bool {
        !self.answers(how, &query(core::slice::from_ref(q)), 1, 1).0.is_empty()
    }

    /// The queries that ask `devices` to answer again: each for what it
    /// announced (its addresses, of the families it has, or both if it has
    /// none yet, and the service and text records of each of its instances),
    /// and not for whole service types, so that only they answer.
    pub fn refresh_queries(devices: &[Device], limit: usize) -> Vec<Message> {
        let mut qs = Questions::default();
        for device in devices {
            if let Some(host) = &device.hostname {
                for qtype in device.address_types() {
                    qs.ask(host, qtype);
                }
            }
            for svc in &device.services {
                qs.ask(&svc.instance(), rtype::SRV);
                qs.ask(&svc.instance(), rtype::TXT);
            }
        }
        qs.into_queries(limit)
    }

    /// The records that take a segment from announcing `old` to announcing
    /// `new` under one hostname, either of them nothing, each announced with
    /// the TTL of its address in its `ttl`: all of `new`, and goodbyes for
    /// what of `old` it does not have.
    ///
    /// What devices on the segment have themselves is theirs. No goodbye is
    /// sent for a service whose instance name one has (`local` says),
    /// nor, if one has the hostname (`host_here`), for the NSEC, which may say
    /// just what theirs does. And no goodbye carries the cache-flush bit,
    /// which would flush their records of the name too.
    pub fn transition(old: Option<Advertised>, new: Option<Advertised>, local: &dyn Fn(&str) -> bool, host_here: bool) -> Vec<Record> {
        let mut records = match (old, new) {
            (Some(old), Some(new)) if old == new => Vec::new(),
            (None, None) => Vec::new(),
            (None, Some(new)) => new.device.announcement(new.how, new.host_ttl, OTHER_TTL),
            (Some(old), Some(new)) => old.device.without(local).replacement(old.how, new, new.host_ttl, OTHER_TTL),
            (Some(old), None) => old.device.without(local).announcement(old.how, 0, 0),
        };
        for r in records.iter_mut().filter(|r| r.ttl == 0) {
            r.cache_flush = false;
        }
        if host_here {
            records.retain(|r| r.ttl != 0 || !matches!(r.data, RData::Nsec { .. }));
        }
        records
    }

    /// The reply to `query` from a responder that has `devices`: what each of
    /// them answers, once each, each with the TTL of its address
    /// ([`HOST_TTL`] if it has none) and of its services, in as many packets
    /// of at most `limit` bytes as it takes ([`responses`]). Returns them with
    /// the indices of the devices that answered, or `None` if none did.
    ///
    /// A `legacy` resolver, asking from a port other than 5353, gets one reply
    /// it can take (RFC 6762 section 6.7): its question and id echoed, no TTL
    /// over ten seconds, no cache-flush bits, and no bigger than it says it
    /// takes (512 bytes, unless its query says more with EDNS0), nor than
    /// `limit`. Answers that
    /// do not fit are left out and the reply marked truncated; additional
    /// records that do not fit are only left out.
    pub fn query_response(
        devices: &[Advertised],
        query: &Message,
        legacy: bool,
        limit: usize,
    ) -> Option<(Vec<Message>, Vec<usize>)> {
        let mut answers: Vec<Record> = Vec::new();
        let mut additionals: Vec<Record> = Vec::new();
        let mut answered = Vec::new();
        for (i, Advertised { device, how, host_ttl }) in devices.iter().enumerate() {
            let (a, x) = device.answers(how, query, *host_ttl, OTHER_TTL);
            if a.is_empty() {
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
            answered.push(i);
        }
        if answers.is_empty() {
            return None;
        }

        if !legacy {
            return Some((responses(&answers, &additionals, limit), answered));
        }

        let limit = query
            .additionals
            .iter()
            .find(|r| r.rtype() == OPT)
            .map_or(LEGACY_PACKET, |opt| usize::from(opt.class | u16::from(opt.cache_flush) << 15))
            .max(LEGACY_PACKET)
            .min(limit);
        let legacy = |r: &Record| Record { ttl: r.ttl.min(LEGACY_TTL_CAP), cache_flush: false, ..r.clone() };
        let mut msg = response();
        msg.header.id = query.header.id;
        msg.questions = query.questions.clone();
        for (additional, records) in [(false, &answers), (true, &additionals)] {
            for rec in records {
                section(&mut msg, additional).push(legacy(rec));
                if size(&msg) > limit {
                    section(&mut msg, additional).pop();
                    msg.header.truncated |= !additional;
                }
            }
        }
        Some((vec![msg], answered))
    }

    /// Its records that match `query`, with known-answer suppression
    /// applied, plus the additional records a client will want next (RFC 6763
    /// section 12): a PTR brings its SRV and TXT, and an SRV brings its address.
    pub fn answers(&self, how: &Advertise, query: &Message, host_ttl: u32, other_ttl: u32) -> (Vec<Record>, Vec<Record>) {
        let all = self.announcement(how, host_ttl, other_ttl);

        let mut answers: Vec<Record> = Vec::new();
        for q in &query.questions {
            if q.class != 1 && q.class != 255 {
                continue;
            }
            let mut found = false;
            for rec in &all {
                // An NSEC is not one of the records a name has.
                let type_ok = (q.qtype == rtype::ANY && rec.rtype() != rtype::NSEC) || q.qtype == rec.rtype();
                if type_ok && rec.name.eq_ignore_ascii_case(&q.name) {
                    found = true;
                    if !answers.contains(rec) {
                        answers.push(rec.clone());
                    }
                }
            }
            // A type the name has not got, by its NSEC: say so (RFC 6762
            // section 6.1), so the asker need not wait for an answer.
            let denies = |r: &&Record| {
                r.name.eq_ignore_ascii_case(&q.name)
                    && matches!(&r.data, RData::Nsec { types, .. } if !types.contains(&q.qtype))
            };
            if !found
                && q.qtype != rtype::ANY
                && let Some(nsec) = all.iter().find(denies).filter(|r| !answers.contains(r))
            {
                answers.push(nsec.clone());
            }
        }

        // The asker already holds this record with at least half its life left.
        let known = |r: &Record| {
            query.answers.iter().any(|k| k.name.eq_ignore_ascii_case(&r.name) && k.data == r.data && k.ttl >= r.ttl / 2)
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
        // An address comes with the name's addresses of the other family, and
        // the NSEC that says which kinds of address there are (RFC 6762
        // section 6.2): so a client asking over IPv4 learns of IPv6 too.
        let hosts: Vec<String> = answers
            .iter()
            .chain(&extra)
            .filter(|r| matches!(r.data, RData::A(_) | RData::Aaaa(_)))
            .map(|r| r.name.clone())
            .collect();
        for rec in &all {
            let wanted = matches!(rec.data, RData::A(_) | RData::Aaaa(_) | RData::Nsec { .. })
                && hosts.iter().any(|h| rec.name.eq_ignore_ascii_case(h));
            if wanted && !answers.contains(rec) && !extra.contains(rec) {
                extra.push(rec.clone());
            }
        }
        (answers, extra)
    }
}



/// Questions for queries, each asked once however many devices want it.
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
        if query(core::slice::from_ref(&q)).encode().is_ok() {
            self.list.push(q);
        }
    }

    /// The questions as multicast queries: up to [`QUESTIONS_PER_PACKET`] to
    /// a packet, and fewer if they would make it bigger than `limit`.
    fn into_queries(self, limit: usize) -> Vec<Message> {
        let mut out: Vec<Message> = Vec::new();
        for q in self.list {
            match out.last_mut() {
                Some(msg) if msg.questions.len() < QUESTIONS_PER_PACKET => {
                    msg.questions.push(q);
                    if size(msg) > limit {
                        let q = msg.questions.pop().expect("just pushed");
                        out.push(query(&[q]));
                    }
                }
                _ => out.push(query(&[q])),
            }
        }
        out
    }
}

/// `queries` with the `known` answers to the questions of each, as many as
/// keep it within `limit`, so that the devices already heard of need not
/// answer. Those that do not fit are left out: those devices answer, which is
/// only more traffic.
fn with_known(mut queries: Vec<Message>, known: impl Fn(&Question) -> Vec<Record>, limit: usize) -> Vec<Message> {
    for msg in &mut queries {
        let records: Vec<Record> = msg.questions.iter().flat_map(&known).collect();
        for rec in records {
            if msg.answers.contains(&rec) {
                continue;
            }
            msg.answers.push(rec);
            if size(msg) > limit {
                msg.answers.pop();
                break;
            }
        }
    }
    queries
}

/// `answers`, then `additionals`, as responses of at most `limit` bytes each,
/// in as many as it takes. The records of a name and type go in one packet
/// where they fit, so that its cache-flush bit replaces the set whole; a set
/// too big for one is split, and a record too big for any goes alone.
/// Additional records fill what room the answers leave, then packets of
/// their own.
pub fn responses(answers: &[Record], additionals: &[Record], limit: usize) -> Vec<Message> {
    let mut out = vec![response()];
    for (additional, records) in [(false, answers), (true, additionals)] {
        for set in rrsets(records) {
            if !place(&mut out, additional, &set, limit) {
                for rec in set {
                    place(&mut out, additional, &[rec], limit);
                }
            }
        }
    }
    out.retain(|m| !m.answers.is_empty() || !m.additionals.is_empty());
    out
}

/// `records` grouped by name and type, in the order each set first appears.
fn rrsets(records: &[Record]) -> Vec<Vec<&Record>> {
    let mut sets: Vec<Vec<&Record>> = Vec::new();
    for rec in records {
        let same = |set: &&mut Vec<&Record>| set[0].rtype() == rec.rtype() && set[0].name.eq_ignore_ascii_case(&rec.name);
        match sets.iter_mut().find(same) {
            Some(set) => set.push(rec),
            None => sets.push(vec![rec]),
        }
    }
    sets
}

/// Put `records` together in the last of `out`, or in a new one if they do
/// not fit there, keeping each within `limit`. A single record too big even
/// for a packet of its own goes in one anyway. Returns whether they were
/// put; if not, they are too many to go together.
fn place(out: &mut Vec<Message>, additional: bool, records: &[&Record], limit: usize) -> bool {
    let is_empty = |msg: &Message| msg.answers.is_empty() && msg.additionals.is_empty();
    for fresh in [false, true] {
        if fresh {
            if out.last().is_some_and(is_empty) {
                break;
            }
            out.push(response());
        }
        let msg = out.last_mut().expect("never empty");
        section(msg, additional).extend(records.iter().map(|&r| r.clone()));
        if size(msg) <= limit {
            return true;
        }
        let keep = section(msg, additional).len() - records.len();
        section(msg, additional).truncate(keep);
    }
    let [record] = records else { return false };
    let msg = out.last_mut().expect("never empty");
    section(msg, additional).push((*record).clone());
    out.push(response());
    true
}

/// The answer or additional section of `msg`.
fn section(msg: &mut Message, additional: bool) -> &mut Vec<Record> {
    if additional { &mut msg.additionals } else { &mut msg.answers }
}

/// The size of `msg` on the wire; one that cannot be encoded is too big for
/// anything.
fn size(msg: &Message) -> usize {
    msg.encode().map_or(usize::MAX, |bytes| bytes.len())
}

/// An empty multicast response.
fn response() -> Message {
    Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// A multicast query for `questions` (no known answers, so every device
/// that has a match replies).
fn query(questions: &[Question]) -> Message {
    Message {
        header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
        questions: questions.to_vec(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// The TTL to announce `svc` with: the one it announced itself with (at least
/// [`MIN_REFLECT_TTL`]) or, if that is not known, `other_ttl`. Zero stays zero:
/// that is a goodbye.
pub fn service_ttl(svc: &Service, other_ttl: u32) -> u32 {
    match (other_ttl, svc.ttl()) {
        (0, _) => 0,
        (_, 0) => other_ttl,
        (_, ttl) => ttl.max(MIN_REFLECT_TTL),
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

fn address_data(addr: IpAddr) -> RData {
    match addr {
        IpAddr::V4(a) => RData::A(a),
        IpAddr::V6(a) => RData::Aaaa(a),
    }
}

pub fn record(name: String, cache_flush: bool, ttl: u32, data: RData) -> Record {
    Record { name, class: 1, cache_flush, ttl, data }
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
mod tests;
