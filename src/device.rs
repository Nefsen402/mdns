//! What is known about a device on a segment: its hostname, addresses and
//! services. Kept by [`Segment`](crate::socket::Segment), and announced on
//! other segments by the [`Reflector`](crate::reflector::Reflector).
//!
//! A response is read into one [`Report`] per host it describes, which a
//! [`Device`] then takes in with [`Device::learn`]; a device is turned back
//! into records with [`Device::announcement`] and [`Device::answers`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use crate::parser::{self, rtype, Header, Message, Question, RData, Record};
use crate::socket::Family;

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
/// flood, not a device.
const MAX_SERVICES: usize = 64;
const MAX_SUBTYPES: usize = 16;
const MAX_REVERSE: usize = 8;

/// The default for how many addresses of a family a device is kept with:
/// enough for a global and a ULA address, a few temporary ones, and a
/// link-local one. See `[Devices] MaxAddresses=`.
pub const DEFAULT_MAX_ADDRS: usize = 8;

/// A reflected device is never announced for less than this, however short a
/// TTL it announced itself with: it is announced again at 80% of its TTL, and
/// a few seconds would be a flood.
pub const MIN_REFLECT_TTL: u32 = 10;

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
    /// The subtypes it said it is of, by the name of their PTR record, such as
    /// `_universal._sub._ipp._tcp.local` (an AirPrint printer).
    pub subtypes: Vec<String>,
    /// The TTL its records were last announced with, in seconds: that of the
    /// SRV record, or else of the PTR or TXT; 0 if not known.
    pub ttl: u32,
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
    /// on; IPv4 before IPv6. At most [`MAX_ADDRS`] of a family.
    pub addresses: Vec<IpAddr>,
    /// Those it learned of are in order of their instance names, ignoring
    /// case: names that differ only in case are one and the same.
    pub services: Vec<Service>,
    /// The TTL its address records were last announced with, in seconds;
    /// `None` if it has not announced any (it was only heard from).
    pub ttl: Option<u32>,
    /// The record types it said its hostname has, by an NSEC record (such as
    /// A but no AAAA); `None` if it has not said.
    pub nsec: Option<Vec<u16>>,
    /// The addresses it announced a reverse-mapping PTR for, naming its
    /// hostname (`9.1.0.10.in-addr.arpa PTR tv.local`).
    pub reverse: Vec<IpAddr>,
}

/// The family of `addr`.
pub fn family_of(addr: IpAddr) -> Family {
    if addr.is_ipv4() { Family::V4 } else { Family::V6 }
}

/// Put addresses in the order a device keeps them: routable before
/// link-local, IPv4 before IPv6, then by address.
fn sort_addrs(addrs: &mut [IpAddr]) {
    addrs.sort_by_key(|a| (is_link_local(a), a.is_ipv6(), *a));
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
                RData::Ptr(host) if parser::reverse_addr(&rec.name).is_some() => {
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
                RData::Ptr(host) if parser::reverse_addr(&rec.name).is_some() => {
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
        RData::Ptr(target) if parser::reverse_addr(&rec.name).is_some() => is_hostname(target),
        RData::Ptr(target) if rec.name.eq_ignore_ascii_case(META_QUERY) => is_type(target),
        // A browse answer: an instance of the type, or the subtype's type.
        RData::Ptr(target) => {
            let kind = match browsed_type(&rec.name) {
                Some(kind) => kind,
                None => return false,
            };
            is_instance_name(target) && parser::split_instance(target).is_some_and(|(_, k)| k.eq_ignore_ascii_case(kind))
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
    let (sub, rest) = parser::split_instance(name)?;
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
    parser::split_instance(name).is_some_and(|(label, kind)| proper(&unescape(label)) && is_type(kind))
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
    /// Its addresses, the routable ones first, IPv4 before IPv6.
    pub fn addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addresses.iter().copied()
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

    /// This device without its link-local addresses, which mean nothing off
    /// its own link.
    pub fn without_link_local(&self) -> Device {
        let mut device = self.clone();
        device.addresses.retain(|a| !is_link_local(a));
        device
    }

    /// What identifies it in the manual list and to the reflector: its
    /// hostname, case-insensitively.
    pub fn key(&self) -> Option<String> {
        self.hostname.as_ref().map(|h| h.to_ascii_lowercase())
    }

    /// Its service called `instance`, ignoring case.
    pub fn service(&self, instance: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.instance.eq_ignore_ascii_case(instance))
    }

    /// Forget its service called `instance`, ignoring case.
    pub fn forget_service(&mut self, instance: &str) {
        self.services.retain(|s| !s.instance.eq_ignore_ascii_case(instance));
    }

    /// Take in what `report` says about it, with the addresses that vouch for
    /// it: those announced, and the one the packet came from if it sent it,
    /// keeping at most `max_addrs` of a family.
    pub fn learn(&mut self, report: &Report<'_>, addrs: &[IpAddr], max_addrs: usize) {
        self.hostname = Some(report.host.clone());
        self.take_addrs(addrs, &report.flushed, &report.gone, max_addrs);
        self.ttl = report.addr_ttl().or(self.ttl);
        self.learn_records(report.records.iter().copied());
    }

    /// Take in the addresses a packet vouches for, of either family. Of a
    /// family in `flushed`, announced with the cache-flush bit, they are all
    /// it has, and replace those it had (RFC 6762 section 10.2); of another,
    /// they are added. Those in `gone`, said goodbye to, are dropped. Beyond
    /// `max_addrs` of a family, more are not taken.
    pub fn take_addrs(&mut self, addrs: &[IpAddr], flushed: &[Family], gone: &[IpAddr], max_addrs: usize) {
        self.addresses.retain(|a| !flushed.contains(&family_of(*a)) && !gone.contains(a));
        let mut fresh: Vec<IpAddr> = addrs.iter().copied().filter(|a| !gone.contains(a)).collect();
        sort_addrs(&mut fresh);
        for addr in fresh {
            let of_family = self.addresses.iter().filter(|a| a.is_ipv4() == addr.is_ipv4()).count();
            if !self.addresses.contains(&addr) && of_family < max_addrs {
                self.addresses.push(addr);
            }
        }
        sort_addrs(&mut self.addresses);
    }

    /// Add `addrs` to those it has, up to [`DEFAULT_MAX_ADDRS`] of a family:
    /// for a device made rather than heard of.
    pub fn add_addrs(&mut self, addrs: &[IpAddr]) {
        self.take_addrs(addrs, &[], &[], DEFAULT_MAX_ADDRS);
    }

    /// Take in the service records, NSEC and reverse mappings in `records`. A
    /// TTL of 0 is a goodbye for what the record says.
    pub fn learn_records<'a>(&mut self, records: impl Iterator<Item = &'a Record>) {
        for rec in records {
            match &rec.data {
                RData::Ptr(host) if parser::reverse_addr(&rec.name).is_some() => {
                    let addr = parser::reverse_addr(&rec.name).expect("checked above");
                    if self.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host)) {
                        self.reverse.retain(|a| *a != addr);
                        if rec.ttl != 0 && self.reverse.len() < MAX_REVERSE {
                            self.reverse.push(addr);
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
                            if let Some(svc) = self.services.iter_mut().find(|s| s.instance.eq_ignore_ascii_case(instance)) {
                                svc.subtypes.retain(|sub| !same(sub));
                            }
                        } else if let Some(svc) = self.service_mut(instance)
                            && !svc.subtypes.iter().any(same)
                            && svc.subtypes.len() < MAX_SUBTYPES
                        {
                            svc.subtypes.push(rec.name.clone());
                        }
                        continue;
                    }
                    if rec.ttl == 0 {
                        self.forget_service(instance);
                    } else if let Some(svc) = self.service_mut(instance) {
                        svc.kind = rec.name.clone();
                        // The SRV record's TTL is the one that counts, if known.
                        if svc.ttl == 0 {
                            svc.ttl = rec.ttl;
                        }
                    }
                }
                RData::Srv { port, target, .. } => {
                    if rec.ttl == 0 {
                        self.forget_service(&rec.name);
                    } else if let Some(svc) = self.service_mut(&rec.name) {
                        svc.port = *port;
                        svc.target = Some(target.clone());
                        svc.ttl = rec.ttl;
                    }
                }
                RData::Nsec { types, .. } => {
                    if self.hostname.as_deref().is_some_and(|host| host.eq_ignore_ascii_case(&rec.name)) {
                        self.nsec = (rec.ttl != 0).then(|| types.clone());
                    }
                }
                RData::Txt(strings) => {
                    if rec.ttl != 0
                        && let Some(svc) = self.service_mut(&rec.name)
                    {
                        svc.txt = strings
                            .iter()
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).into_owned())
                            .collect();
                        if svc.ttl == 0 {
                            svc.ttl = rec.ttl;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Take over the services learned about it before its name was known.
    pub fn absorb(&mut self, earlier: Device) {
        for svc in earlier.services {
            if self.service(&svc.instance).is_none() && self.services.len() < MAX_SERVICES {
                self.insert_service(svc);
            }
        }
    }

    /// Get or create a service, deriving its type from the instance name
    /// until a PTR record states it explicitly. It keeps the spelling it was
    /// first heard with, whatever the case of later records. `None` if it is
    /// new and the device has [`MAX_SERVICES`] already.
    fn service_mut(&mut self, instance: &str) -> Option<&mut Service> {
        let at = match self.services.iter().position(|s| s.instance.eq_ignore_ascii_case(instance)) {
            Some(at) => at,
            None if self.services.len() >= MAX_SERVICES => return None,
            None => self.insert_service(Service {
                instance: instance.to_string(),
                kind: parser::split_instance(instance).map(|(_, kind)| kind.to_string()).unwrap_or_default(),
                ..Service::default()
            }),
        };
        Some(&mut self.services[at])
    }

    /// Add `svc` in its place among the services, and return where that is.
    fn insert_service(&mut self, svc: Service) -> usize {
        let key = svc.instance.to_ascii_lowercase();
        let at = self.services.partition_point(|s| s.instance.to_ascii_lowercase() < key);
        self.services.insert(at, svc);
        at
    }

    /// This device without the services whose instance names are in `taken`
    /// (lowercase).
    pub fn without(&self, taken: &HashSet<String>) -> Device {
        let mut device = self.clone();
        device.services.retain(|s| !taken.contains(&s.instance.to_ascii_lowercase()));
        device
    }

    /// The records that announce it. A TTL of 0 turns them into goodbyes.
    /// Callers must have checked that it has a hostname.
    pub fn announcement(&self, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let host = self.hostname.clone().expect("hostname checked on add");
        let mut records: Vec<Record> =
            self.addrs().map(|addr| record(host.clone(), true, host_ttl, address_data(addr))).collect();
        records.extend(self.nsec_record(host_ttl));
        records.extend(self.reverse_records(host_ttl));

        for svc in &self.services {
            records.extend(self.service_records(svc, service_ttl(svc, other_ttl)));
        }
        // DNS-SD service type enumeration, once per distinct type.
        let kinds: BTreeMap<String, &String> =
            self.services.iter().map(|s| (s.kind.to_ascii_lowercase(), &s.kind)).collect();
        for kind in kinds.into_values() {
            records.push(record("_services._dns-sd._udp.local".into(), false, other_ttl, RData::Ptr(kind.clone())));
        }
        records
    }

    /// The records that take a segment from announcing this device to
    /// announcing `new` under the same hostname: all of `new`, and goodbyes
    /// for the services and addresses of this one that `new` does not have.
    pub fn replacement(&self, new: &Device, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let mut records = new.announcement(host_ttl, other_ttl);
        let kept: HashMap<String, &Service> =
            new.services.iter().map(|s| (s.instance.to_ascii_lowercase(), s)).collect();
        for svc in &self.services {
            match kept.get(&svc.instance.to_ascii_lowercase()) {
                None => records.extend(self.service_records(svc, 0)),
                Some(now) => {
                    let gone =
                        svc.subtypes.iter().filter(|sub| !now.subtypes.iter().any(|n| n.eq_ignore_ascii_case(sub)));
                    records.extend(gone.map(|sub| record(sub.clone(), false, 0, RData::Ptr(svc.instance.clone()))));
                }
            }
        }
        let host = self.hostname.clone().unwrap_or_default();
        for gone in self.addrs().filter(|a| !new.addrs().any(|n| n == *a)) {
            records.push(record(host.clone(), true, 0, address_data(gone)));
        }
        let still = new.reverse_records(1);
        for gone in self.reverse_records(0) {
            if !still.iter().any(|r| r.name == gone.name && r.data == gone.data) {
                records.push(gone);
            }
        }
        records
    }

    /// The reverse-mapping PTRs of its addresses, for those it announced one
    /// for itself: a device with several hostnames names one of them, and two
    /// copies saying different things would flush each other.
    fn reverse_records(&self, ttl: u32) -> Vec<Record> {
        let Some(host) = &self.hostname else { return Vec::new() };
        self.addrs()
            .filter(|addr| self.reverse.contains(addr))
            .map(|addr| record(parser::reverse_name(addr), true, ttl, RData::Ptr(host.clone())))
            .collect()
    }

    /// The NSEC record that says which types its hostname has, if it said so
    /// itself: never more than it denied, so whatever it has that is announced
    /// is listed too. A responder may only deny what it owns (RFC 6762 section
    /// 6.1), so a device that said nothing gets none.
    pub fn nsec_record(&self, ttl: u32) -> Option<Record> {
        let host = self.hostname.clone()?;
        let said = self.nsec.as_ref()?;
        let ours = self.addrs().map(|addr| match addr {
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
        let target = svc.target.clone().or_else(|| self.hostname.clone()).unwrap_or_default();
        let subtypes =
            svc.subtypes.iter().map(|sub| record(sub.clone(), false, ttl, RData::Ptr(svc.instance.clone())));
        let mut records = vec![
            record(svc.kind.clone(), false, ttl, RData::Ptr(svc.instance.clone())),
            record(svc.instance.clone(), true, ttl, RData::Srv { priority: 0, weight: 0, port: svc.port, target }),
            record(
                svc.instance.clone(),
                true,
                ttl,
                RData::Txt(svc.txt.iter().map(|t| t.as_bytes().to_vec()).collect()),
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
        kinds.extend(services().map(|s| s.kind.as_str()).filter(|k| !k.is_empty()));
        let known: HashSet<String> = kinds.iter().map(|k| k.to_ascii_lowercase()).collect();
        for kind in kinds {
            qs.ask(kind, rtype::PTR);
        }
        // The subtypes clients browse by, and the ones heard of, to keep them up.
        let wanted = KNOWN_SUBTYPES.into_iter().filter(|sub| {
            sub.split_once("._sub.").is_some_and(|(_, kind)| known.contains(&kind.to_ascii_lowercase()))
        });
        for sub in wanted.chain(services().flat_map(|s| &s.subtypes).map(String::as_str)) {
            qs.ask(sub, rtype::PTR);
        }
        for svc in services().filter(|s| s.target.is_none()) {
            qs.ask(&svc.instance, rtype::SRV);
            qs.ask(&svc.instance, rtype::TXT);
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
        let of_kind = |s: &&Service| kinds.iter().any(|k| s.kind.eq_ignore_ascii_case(k));
        for svc in devices.iter().flat_map(|d| &d.services).filter(of_kind).filter(|s| s.target.is_none()) {
            qs.ask(&svc.instance, rtype::SRV);
            qs.ask(&svc.instance, rtype::TXT);
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
        let services: Vec<Service> =
            self.services.iter().filter(|s| kinds.iter().any(|k| s.kind.eq_ignore_ascii_case(k))).cloned().collect();
        (!services.is_empty()).then(|| Device { services, ..self.clone() })
    }

    /// Its records that answer `q`, with these TTLs, without the additional
    /// records an answer brings, nor an NSEC saying it has none.
    pub fn records_for(&self, q: &Question, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let (mut records, _) = self.answers(&query(std::slice::from_ref(q)), host_ttl, other_ttl);
        records.retain(|r| r.rtype() != rtype::NSEC);
        records
    }

    /// Whether it has an answer to `q`: a record, or, by its NSEC, the word
    /// that there is none.
    pub fn knows(&self, q: &Question) -> bool {
        !self.answers(&query(std::slice::from_ref(q)), 1, 1).0.is_empty()
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
                qs.ask(&svc.instance, rtype::SRV);
                qs.ask(&svc.instance, rtype::TXT);
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
    /// sent for a service whose instance name one has (`local`, lowercase),
    /// nor, if one has the hostname (`host_here`), for the NSEC, which may say
    /// just what theirs does. And no goodbye carries the cache-flush bit,
    /// which would flush their records of the name too.
    pub fn transition(old: Option<&Device>, new: Option<&Device>, local: &HashSet<String>, host_here: bool) -> Vec<Record> {
        let ttl = |d: &Device| d.ttl.unwrap_or(HOST_TTL);
        let mut records = match (old, new) {
            (Some(old), Some(new)) if old == new => Vec::new(),
            (None, None) => Vec::new(),
            (None, Some(new)) => new.announcement(ttl(new), OTHER_TTL),
            (Some(old), Some(new)) => old.without(local).replacement(new, ttl(new), OTHER_TTL),
            (Some(old), None) => old.without(local).announcement(0, 0),
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
        devices: &[Device],
        query: &Message,
        legacy: bool,
        limit: usize,
    ) -> Option<(Vec<Message>, Vec<usize>)> {
        let mut answers: Vec<Record> = Vec::new();
        let mut additionals: Vec<Record> = Vec::new();
        let mut answered = Vec::new();
        for (i, device) in devices.iter().enumerate() {
            let (a, x) = device.answers(query, device.ttl.unwrap_or(HOST_TTL), OTHER_TTL);
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
    pub fn answers(&self, query: &Message, host_ttl: u32, other_ttl: u32) -> (Vec<Record>, Vec<Record>) {
        let all = self.announcement(host_ttl, other_ttl);

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
        if query(std::slice::from_ref(&q)).encode().is_ok() {
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
    match (other_ttl, svc.ttl) {
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
    parser::split_instance(name).is_some_and(|(_, kind)| is_service_type(kind))
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
mod tests {
    use super::*;
    use crate::parser::Question;

    /// Its first routable IPv4 or IPv6 address, and link-local one.
    fn v4(d: &Device) -> Option<IpAddr> {
        d.routable().find(|a| a.is_ipv4())
    }
    fn v6(d: &Device) -> Option<IpAddr> {
        d.routable().find(|a| a.is_ipv6())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn a_record(host: &str, addr: &str) -> Record {
        record(host.into(), true, 120, RData::A(addr.parse().unwrap()))
    }

    fn aaaa(host: &str, addr: &str) -> Record {
        record(host.into(), true, 120, RData::Aaaa(addr.parse().unwrap()))
    }

    fn srv(instance: &str, port: u16, target: &str) -> Record {
        record(instance.into(), true, 120, RData::Srv { priority: 0, weight: 0, port, target: target.into() })
    }

    fn ptr(kind: &str, instance: &str) -> Record {
        record(kind.into(), false, 4500, RData::Ptr(instance.into()))
    }

    fn nsec(name: &str, types: &[u16]) -> Record {
        record(name.into(), true, 120, RData::Nsec { next: name.into(), types: types.to_vec() })
    }

    fn reverse(addr: &str, host: &str) -> Record {
        record(parser::reverse_name(ip(addr)), true, 120, RData::Ptr(host.into()))
    }

    fn response(records: Vec<Record>) -> Message {
        Message {
            header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
            questions: vec![],
            answers: records,
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn query(name: &str, qtype: u16) -> Message {
        Message {
            header: Header { id: 0, response: false, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
            questions: vec![Question { name: name.into(), qtype, class: 1, unicast_response: false }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    /// Make `device` hear `records`, as a segment puts them to the one device
    /// they are about: the report on it, and what ties to no host.
    fn hear(device: &mut Device, records: Vec<Record>) {
        let msg = response(records);
        let (reports, rest) = Report::all(&msg);
        for report in &reports {
            device.learn(report, &report.addrs, DEFAULT_MAX_ADDRS);
        }
        device.learn_records(rest.into_iter());
    }

    fn heard(records: Vec<Record>) -> Device {
        let mut device = Device::default();
        hear(&mut device, records);
        device
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
                    txt: vec!["a=b".into()],
                    ..Service::default()
                })
                .collect(),
            ..Device::default()
        };
        device.add_addrs(&[ip(addr)]);
        device
    }

    /// Two devices with a service of one type, and one with another type.
    fn three_devices() -> Vec<Device> {
        let mut television = tv("10.0.1.9", &["TV"]);
        television.ttl = Some(300);
        let nas = Device { hostname: Some("nas.local".into()), ..tv("10.0.1.20", &["NAS"]) };
        let mut printer = Device { hostname: Some("printer.local".into()), ..tv("10.0.1.30", &["Printer"]) };
        printer.services[0].kind = "_ipp._tcp.local".into();
        printer.services[0].instance = "Printer._ipp._tcp.local".into();
        vec![television, nas, printer]
    }

    /// The one packet of a reply that fits in one.
    fn only(mut msgs: Vec<Message>) -> Message {
        assert_eq!(msgs.len(), 1, "{msgs:?}");
        msgs.remove(0)
    }

    #[test]
    fn a_query_response_has_what_each_device_answers_once() {
        let devices = three_devices();
        let (msgs, answered) = Device::query_response(&devices, &query("_http._tcp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).unwrap();
        let msg = only(msgs);
        assert_eq!(answered, [0, 1], "the printer has nothing of that type");
        let browsed: Vec<&RData> = msg.answers.iter().map(|r| &r.data).collect();
        assert_eq!(browsed, [
            &RData::Ptr("TV._http._tcp.local".into()),
            &RData::Ptr("NAS._http._tcp.local".into()),
        ]);
        // Each comes with what it takes to resolve it, its address with the
        // TTL it is announced with, or the usual one.
        let addr_ttl = |host: &str| msg.additionals.iter().find(|r| r.name == host && matches!(r.data, RData::A(_))).map(|r| r.ttl);
        assert_eq!((addr_ttl("tv.local"), addr_ttl("nas.local")), (Some(300), Some(HOST_TTL)));
        assert_eq!(msg.additionals.iter().filter(|r| matches!(r.data, RData::Srv { .. })).count(), 2);
        assert!(msg.header.response && msg.header.authoritative && msg.questions.is_empty());

        // A record two of them have is given once.
        let (msgs, answered) =
            Device::query_response(&devices, &query("_services._dns-sd._udp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).unwrap();
        let msg = only(msgs);
        assert_eq!(answered, [0, 1, 2]);
        assert_eq!(msg.answers.len(), 2, "_http and _ipp: {:?}", msg.answers);

        // Nothing to say is no reply at all.
        assert!(Device::query_response(&devices, &query("_airplay._tcp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).is_none());
        assert!(Device::query_response(&[], &query("_http._tcp.local", rtype::PTR), false, DEFAULT_MAX_PACKET).is_none());
    }

    /// `n` devices `dev0.local`, `dev1.local`, ... each with a service of
    /// `_http._tcp` with a TXT record of `txt` bytes.
    fn many(n: usize, txt: usize) -> Vec<Device> {
        (0..n)
            .map(|i| {
                let mut d = tv(&format!("10.0.1.{}", i + 1), &[&format!("Device {i}")]);
                d.hostname = Some(format!("dev{i}.local"));
                d.services[0].target = d.hostname.clone();
                d.services[0].txt = vec!["k=".to_string() + &"v".repeat(txt)];
                d
            })
            .collect()
    }

    fn sizes(msgs: &[Message]) -> Vec<usize> {
        msgs.iter().map(|m| m.encode().unwrap().len()).collect()
    }

    /// Records are put in as few packets as keep within the limit, in order,
    /// answers before additional ones, each name and type's records together.
    #[test]
    fn records_are_split_into_packets_that_fit() {
        let records: Vec<Record> = many(30, 40).iter().flat_map(|d| d.announcement(120, 4500)).collect();
        let packets = responses(&records, &[], 600);
        assert!(packets.len() > 1, "they do not fit in one");
        assert!(sizes(&packets).iter().all(|&s| s <= 600), "{:?}", sizes(&packets));
        let sent: Vec<Record> = packets.iter().flat_map(|m| m.answers.clone()).collect();
        assert_eq!(sent.len(), records.len(), "no record lost or doubled");
        // Each name and type in one packet: here, every device's addresses.
        for host in (0..30).map(|i| format!("dev{i}.local")) {
            let with = packets.iter().filter(|m| m.answers.iter().any(|r| r.name == host && r.rtype() == rtype::A)).count();
            assert_eq!(with, 1, "{host}");
        }
        // What fits in one stays in one.
        assert_eq!(responses(&records[..3], &[], 600).len(), 1);
        assert!(responses(&[], &[], 600).is_empty());

        // Additional records fill the room the answers leave, then packets of
        // their own, after the answers.
        let (answers, additionals) = records.split_at(10);
        let packets = responses(answers, additionals, 600);
        assert!(sizes(&packets).iter().all(|&s| s <= 600));
        assert_eq!(packets.iter().map(|m| m.answers.len()).sum::<usize>(), 10);
        assert_eq!(packets.iter().map(|m| m.additionals.len()).sum::<usize>(), additionals.len());
        let first_additional = packets.iter().position(|m| !m.additionals.is_empty()).unwrap();
        assert!(packets[first_additional + 1..].iter().all(|m| m.answers.is_empty()));
    }

    /// A record too big for any packet still goes out, alone; what comes
    /// after it does not share its packet.
    #[test]
    fn a_record_too_big_for_a_packet_goes_alone() {
        let big = record("big._http._tcp.local".into(), true, 4500, RData::Txt(vec![vec![b'x'; 250]; 4]));
        let small = |i: u8| record(format!("dev{i}.local"), true, 120, RData::A([10, 0, 0, i].into()));
        let packets = responses(&[small(1), big.clone(), small(2)], &[], 512);
        assert_eq!(packets.len(), 3, "{packets:?}");
        assert_eq!(packets[1].answers, [big]);
        assert!(sizes(&packets)[1] > 512);
        assert!(sizes(&[packets[0].clone(), packets[2].clone()]).iter().all(|&s| s <= 512));
    }

    /// A browse many devices answer is split over as many packets as it
    /// takes, none bigger than the limit, with every device's answer in one.
    #[test]
    fn a_large_reply_is_split_over_packets() {
        let devices = many(40, 100);
        let (packets, answered) = Device::query_response(&devices, &query("_http._tcp.local", rtype::PTR), false, 1452).unwrap();
        assert_eq!(answered.len(), 40);
        assert!(packets.len() > 1);
        assert!(sizes(&packets).iter().all(|&s| s <= 1452), "{:?}", sizes(&packets));
        let browsed = packets.iter().flat_map(|m| &m.answers).filter(|r| r.rtype() == rtype::PTR).count();
        assert_eq!(browsed, 40);
        assert!(packets.iter().all(|m| m.header.response && m.questions.is_empty()));
    }

    /// A legacy resolver gets one reply of at most 512 bytes, or of what its
    /// query says it takes (and the interface allows). Answers left out mark
    /// it truncated; additional records left out do not.
    #[test]
    fn a_legacy_reply_fits_what_the_resolver_takes() {
        let devices = many(40, 100);
        let browse = query("_http._tcp.local", rtype::PTR);
        let (packets, _) = Device::query_response(&devices, &browse, true, 1452).unwrap();
        let reply = only(packets);
        assert!(reply.encode().unwrap().len() <= 512);
        assert!(reply.header.truncated, "not every answer fits");
        assert!(!reply.answers.is_empty());

        // With EDNS0 saying 4096, as much as the interface allows.
        let mut edns = browse.clone();
        edns.additionals.push(Record { name: String::new(), class: 4096, cache_flush: false, ttl: 0, data: RData::Other { rtype: OPT, data: vec![] } });
        let reply = only(Device::query_response(&devices, &edns, true, 1452).unwrap().0);
        let size = reply.encode().unwrap().len();
        assert!(size > 512 && size <= 1452, "{size}");

        // One device: its answer fits, but not all its additional records
        // (its TXT record is too big), and leaving those out is no truncation.
        let mut one = many(1, 0);
        one[0].services[0].txt = vec!["a=".to_string() + &"x".repeat(240), "b=".to_string() + &"x".repeat(240)];
        let whole = only(Device::query_response(&one, &browse, false, 1452).unwrap().0);
        let reply = only(Device::query_response(&one, &browse, true, 1452).unwrap().0);
        assert_eq!(reply.answers.len(), 1);
        assert!(reply.additionals.len() < whole.additionals.len(), "the TXT record does not fit");
        assert!(!reply.header.truncated);
        assert!(reply.encode().unwrap().len() <= 512);
    }

    /// Questions are put fewer to a packet when they are long.
    #[test]
    fn long_questions_are_put_fewer_to_a_packet() {
        let mut devices = many(16, 1);
        for (i, d) in devices.iter_mut().enumerate() {
            d.services[0].instance = format!("{}{i}._http._tcp.local", "n".repeat(60));
            d.services[0].target = None;
        }
        let queries = Device::refresh_queries(&devices, 512);
        assert!(queries.len() > 2, "{}", queries.len());
        assert!(sizes(&queries).iter().all(|&s| s <= 512), "{:?}", sizes(&queries));
        assert_eq!(queries.iter().map(|q| q.questions.len()).sum::<usize>(), 16 * 2 + 16, "SRV, TXT and the address of each");
    }

    #[test]
    fn a_legacy_resolver_gets_its_question_back_and_short_ttls_without_cache_flush() {
        let devices = three_devices();
        let mut asked = query("tv.local", rtype::ANY);
        asked.header.id = 0x4242;

        let (msgs, _) = Device::query_response(&devices, &asked, true, DEFAULT_MAX_PACKET).unwrap();
        let msg = only(msgs);
        assert_eq!((msg.header.id, msg.questions.clone()), (0x4242, asked.questions.clone()));
        assert!(msg.answers.iter().chain(&msg.additionals).all(|r| r.ttl <= LEGACY_TTL_CAP && !r.cache_flush));

        // To the group, none of that.
        let (msgs, _) = Device::query_response(&devices, &asked, false, DEFAULT_MAX_PACKET).unwrap();
        let msg = only(msgs);
        assert_eq!(msg.header.id, 0);
        assert!(msg.questions.is_empty());
        assert!(msg.answers.iter().any(|r| r.ttl == 300 && r.cache_flush));
    }

    /// Every question the `queries` ask, as (name, type), in order.
    fn asked(queries: &[Message]) -> Vec<(String, u16)> {
        assert!(queries.iter().all(|q| !q.header.response && q.questions.len() <= QUESTIONS_PER_PACKET));
        queries.iter().flat_map(|q| &q.questions).map(|q| (q.name.clone(), q.qtype)).collect()
    }

    fn q(name: &str, qtype: u16) -> (String, u16) {
        (name.to_string(), qtype)
    }

    #[test]
    fn a_probe_asks_for_types_instances_subtypes_and_whatever_is_missing() {
        // Resolved and with a routable address: only its type is browsed.
        let mut resolved = tv("10.0.1.9", &["TV"]);
        resolved.services[0].target = Some("tv.local".into());
        // Of the same type, with a subtype heard of, but not yet resolved.
        let mut unresolved = tv("10.0.1.10", &["Den"]);
        unresolved.hostname = None;
        unresolved.services[0].subtypes = vec!["_scanner._sub._http._tcp.local".into()];
        // Known by name, but only by a link-local address.
        let named = Device { hostname: Some("nas.local".into()), addresses: vec![ip("169.254.1.1")], ..Device::default() };
        let types = BTreeSet::from(["_ipp._tcp.local".to_string()]);

        let questions = asked(&Device::probe_queries(&[resolved, unresolved, named], &types, DEFAULT_MAX_PACKET));
        for wanted in [
            q(META_QUERY, rtype::PTR),
            q("_http._tcp.local", rtype::PTR),
            q("_ipp._tcp.local", rtype::PTR),
            q("_printer._sub._http._tcp.local", rtype::PTR),
            q("_universal._sub._ipp._tcp.local", rtype::PTR),
            q("_scanner._sub._http._tcp.local", rtype::PTR),
            q("Den._http._tcp.local", rtype::SRV),
            q("Den._http._tcp.local", rtype::TXT),
            q("nas.local", rtype::A),
        ] {
            assert!(questions.contains(&wanted), "{wanted:?} in {questions:?}");
        }
        assert_eq!(questions.iter().filter(|w| **w == q("_http._tcp.local", rtype::PTR)).count(), 1, "asked once");
        assert!(!questions.contains(&q("TV._http._tcp.local", rtype::SRV)), "already resolved");
        assert!(!questions.contains(&q("tv.local", rtype::A)), "already has a routable address");
        assert!(!questions.contains(&q("_universal._sub._ipps._tcp.local", rtype::PTR)), "no _ipps around");

        // However many types there are, a packet has only so many questions.
        let types: BTreeSet<String> = (0..40).map(|i| format!("_t{i}._tcp.local")).collect();
        let queries = Device::probe_queries(&[], &types, DEFAULT_MAX_PACKET);
        assert_eq!(asked(&queries).len(), 41);
        assert_eq!(queries.len(), 3);
    }

    /// Asking for types by name browses each, and finishes what is missing
    /// of their devices only: instances to resolve, hosts to find an address
    /// for. What is known goes along as known answers.
    #[test]
    fn asking_for_types_browses_them_and_resolves_their_devices_only() {
        // Of the type, unresolved, known only by a link-local address.
        let mut plug = tv("169.254.1.5", &["Plug"]);
        plug.hostname = Some("plug.local".into());
        plug.services[0].kind = "_shelly._tcp.local".into();
        plug.services[0].instance = "Plug._shelly._tcp.local".into();
        // Of another type, as unfinished: none of its business.
        let mut other = tv("169.254.1.6", &["TV"]);
        other.hostname = Some("other.local".into());
        let kinds = ["_Shelly._tcp.local".to_string()];
        let ptr = Record {
            name: "_shelly._tcp.local".into(),
            class: 1,
            cache_flush: false,
            ttl: 60,
            data: RData::Ptr("Plug._shelly._tcp.local".into()),
        };
        let known = |q: &Question| if q.qtype == rtype::PTR { vec![ptr.clone()] } else { Vec::new() };

        let queries = Device::type_queries(&[plug.clone(), other], &kinds, known, DEFAULT_MAX_PACKET);
        assert_eq!(asked(&queries), [
            q("_Shelly._tcp.local", rtype::PTR),
            q("Plug._shelly._tcp.local", rtype::SRV),
            q("Plug._shelly._tcp.local", rtype::TXT),
            q("plug.local", rtype::A),
            q("plug.local", rtype::AAAA),
        ]);
        assert_eq!(queries[0].answers, [ptr]);

        // Resolved and reachable, only the type is asked for.
        plug.services[0].target = Some("plug.local".into());
        plug.add_addrs(&[ip("10.0.1.5")]);
        assert_eq!(asked(&Device::type_queries(&[plug], &kinds, |_| Vec::new(), DEFAULT_MAX_PACKET)), [q("_Shelly._tcp.local", rtype::PTR)]);
    }

    /// Narrowed to some types, a device keeps only its services of them, and
    /// is nothing without one.
    #[test]
    fn a_device_narrowed_to_types_keeps_only_those_services() {
        let mut device = tv("10.0.1.9", &["TV", "Cast"]);
        device.services[1].kind = "_googlecast._tcp.local".into();
        let narrow = device.only_kinds(&["_GoogleCast._tcp.local".to_string()]).unwrap();
        assert_eq!(narrow.services.len(), 1);
        assert_eq!(narrow.services[0].kind, "_googlecast._tcp.local");
        assert_eq!((narrow.hostname, narrow.addresses), (device.hostname.clone(), device.addresses.clone()));
        assert!(device.only_kinds(&["_ipp._tcp.local".to_string()]).is_none());
    }

    #[test]
    fn a_refresh_asks_each_device_for_what_it_announced_and_no_more() {
        let devices = [tv("fd00::9", &["TV", "Cast"]), tv("fd00::9", &["TV"])];
        let questions = asked(&Device::refresh_queries(&devices, DEFAULT_MAX_PACKET));
        assert_eq!(questions, [
            q("tv.local", rtype::AAAA),
            q("TV._http._tcp.local", rtype::SRV),
            q("TV._http._tcp.local", rtype::TXT),
            q("Cast._http._tcp.local", rtype::SRV),
            q("Cast._http._tcp.local", rtype::TXT),
        ]);
        assert!(Device::refresh_queries(&[], DEFAULT_MAX_PACKET).is_empty());
    }

    #[test]
    fn a_transition_announces_the_new_and_takes_back_only_what_is_ours() {
        let none = HashSet::new();
        let mut old = tv("10.0.1.9", &["Kitchen", "Den"]);
        old.ttl = Some(300);
        old.nsec = Some(vec![rtype::A]);
        let goodbyes = |records: &[Record]| records.iter().filter(|r| r.ttl == 0).cloned().collect::<Vec<_>>();

        assert!(Device::transition(Some(&old), Some(&old), &none, false).is_empty(), "nothing changed");
        assert!(Device::transition(None, None, &none, false).is_empty());

        let shown = Device::transition(None, Some(&old), &none, false);
        assert!(shown.iter().any(|r| r.data == RData::A("10.0.1.9".parse().unwrap()) && r.ttl == 300 && r.cache_flush));
        assert!(goodbyes(&shown).is_empty());

        // Moved: the new address, and a goodbye for the old one that does not
        // flush the new.
        let moved = Device { addresses: vec![ip("10.0.1.10")], ..old.clone() };
        let bye = goodbyes(&Device::transition(Some(&old), Some(&moved), &none, false));
        assert_eq!(bye.len(), 1);
        assert_eq!((&bye[0].data, bye[0].cache_flush), (&RData::A("10.0.1.9".parse().unwrap()), false));

        // Withdrawn: everything, none of it flushing.
        let bye = goodbyes(&Device::transition(Some(&old), None, &none, false));
        assert_eq!(bye.len(), old.announcement(0, 0).len());
        assert!(bye.iter().all(|r| !r.cache_flush));

        // But not what a device on the segment has: a service of the same
        // instance name, or, if one has the hostname, the NSEC.
        let local = HashSet::from(["kitchen._http._tcp.local".to_string()]);
        let bye = goodbyes(&Device::transition(Some(&old), None, &local, true));
        assert!(!bye.iter().any(|r| r.name.starts_with("Kitchen.") || r.data == RData::Ptr("Kitchen._http._tcp.local".into())));
        assert!(!bye.iter().any(|r| matches!(r.data, RData::Nsec { .. })));
        assert!(bye.iter().any(|r| r.name.starts_with("Den.")), "{bye:?}");
    }

    /// A device is asked again for the address records of the families it
    /// has, or of both if it has none yet.
    #[test]
    fn a_device_is_asked_for_the_addresses_of_its_families() {
        let named = |addrs: &[&str]| {
            let mut d = Device { hostname: Some("tv.local".into()), ..Device::default() };
            d.add_addrs(&addrs.iter().map(|a| ip(a)).collect::<Vec<_>>());
            d
        };
        assert_eq!(named(&["10.0.1.9"]).address_types(), [rtype::A]);
        assert_eq!(named(&["fd00::9"]).address_types(), [rtype::AAAA]);
        assert_eq!(named(&["10.0.1.9", "fd00::9"]).address_types(), [rtype::A, rtype::AAAA]);
        assert_eq!(named(&[]).address_types(), [rtype::A, rtype::AAAA]);
        assert_eq!(asked(&Device::refresh_queries(&[named(&[])], DEFAULT_MAX_PACKET)), [
            q("tv.local", rtype::A),
            q("tv.local", rtype::AAAA),
        ]);
    }

    /// A copy's NSEC names the address types it is announced with, IPv6 as
    /// well as IPv4, along with what the device said it has.
    #[test]
    fn a_copys_nsec_names_its_ipv6_addresses_too() {
        let mut d = tv("fd00::9", &[]);
        d.nsec = Some(vec![]);
        let types = |d: &Device| match d.nsec_record(120).map(|r| r.data) {
            Some(RData::Nsec { types, .. }) => types,
            other => panic!("{other:?}"),
        };
        assert_eq!(types(&d), [rtype::AAAA]);
        d.add_addrs(&[ip("10.0.1.9")]);
        assert_eq!(types(&d), [rtype::A, rtype::AAAA]);
    }

    /// Only questions of class IN, or any class, are answered: mDNS records
    /// are of IN alone.
    #[test]
    fn only_questions_of_class_in_or_any_are_answered() {
        let d = tv("10.0.1.9", &["TV"]);
        let of_class = |class: u16| {
            let mut msg = query("tv.local", rtype::A);
            msg.questions[0].class = class;
            d.answers(&msg, 120, 4500).0
        };
        assert_eq!(of_class(1).len(), 1);
        assert_eq!(of_class(255).len(), 1);
        assert!(of_class(3).is_empty(), "CHAOS");
        assert!(of_class(4).is_empty(), "Hesiod");
    }

    #[test]
    fn a_device_knows_what_it_has_and_what_its_nsec_says_it_has_not() {
        let mut device = tv("10.0.1.9", &["TV"]);
        let knows = |d: &Device, name: &str, qtype: u16| {
            d.knows(&Question { name: name.into(), qtype, class: 1, unicast_response: false })
        };
        assert!(knows(&device, "TV.local", rtype::A));
        assert!(knows(&device, "tv.local", rtype::ANY));
        assert!(knows(&device, "_http._tcp.local", rtype::PTR));
        assert!(knows(&device, "TV._http._tcp.local", rtype::SRV));
        assert!(!knows(&device, "tv.local", rtype::AAAA), "it has not said");
        assert!(!knows(&device, "printer.local", rtype::A));
        device.nsec = Some(vec![rtype::A]);
        assert!(knows(&device, "tv.local", rtype::AAAA), "it said it has none");
    }

    #[test]
    fn forwarded_queries_ask_each_question_once_for_a_multicast_answer() {
        let ask = |name: &str, qtype: u16, unicast_response: bool| Question { name: name.into(), qtype, class: 255, unicast_response };
        let questions = [ask("printer.local", rtype::A, true), ask("Printer.local", rtype::A, false), ask("_ipp._tcp.local", rtype::PTR, false)];
        let none = |_: &Question| Vec::new();
        let queries = Device::forward_queries(&questions, none, DEFAULT_MAX_PACKET);
        assert_eq!(asked(&queries), [q("printer.local", rtype::A), q("_ipp._tcp.local", rtype::PTR)]);
        assert!(queries.iter().flat_map(|m| &m.questions).all(|q| !q.unicast_response && q.class == 1));
        assert!(queries.iter().all(|m| m.answers.is_empty()));
        assert!(Device::forward_queries(&[], none, DEFAULT_MAX_PACKET).is_empty());

        // A name that cannot be encoded again (a label past 63 bytes) is
        // skipped, not the whole query failed.
        let long = format!("{}.local", "x".repeat(64));
        let queries = Device::forward_queries(&[ask(&long, rtype::A, false), ask("ok.local", rtype::A, false)], none, DEFAULT_MAX_PACKET);
        assert_eq!(asked(&queries), [q("ok.local", rtype::A)]);
    }

    /// The records a device has for a question, as known answers: not the
    /// additional ones an answer brings, nor the NSEC saying it has none.
    #[test]
    fn records_for_a_question_are_only_the_records_it_has() {
        let ask = |name: &str, qtype: u16| Question { name: name.into(), qtype, class: 1, unicast_response: false };
        let mut device = tv("10.0.1.9", &["TV"]);
        device.nsec = Some(vec![rtype::A]);
        let records = device.records_for(&ask("_http._tcp.local", rtype::PTR), 120, 4500);
        let kinds: Vec<u16> = records.iter().map(Record::rtype).collect();
        assert_eq!(kinds, [rtype::PTR]);
        assert!(device.knows(&ask("tv.local", rtype::AAAA)), "its NSEC says it has none");
        assert!(device.records_for(&ask("tv.local", rtype::AAAA), 120, 4500).is_empty());
    }

    /// The known answers to each question go along with it, once each, and
    /// only as many as fit in a frame: the rest of the devices just answer.
    #[test]
    fn forwarded_queries_carry_what_fits_of_the_known_answers() {
        let browse = |name: &str| Question { name: name.into(), qtype: rtype::PTR, class: 1, unicast_response: false };
        let ptr = |kind: &str, i: usize| Record {
            name: kind.into(),
            class: 1,
            cache_flush: false,
            ttl: 4500,
            data: RData::Ptr(format!("Device {i}.{kind}")),
        };
        let known = |q: &Question| (0..3).map(|i| ptr(&q.name, i)).collect::<Vec<_>>();
        let questions = [browse("_http._tcp.local"), browse("_ipp._tcp.local"), browse("_http._tcp.local")];
        let queries = Device::forward_queries(&questions, known, DEFAULT_MAX_PACKET);
        assert_eq!(queries.len(), 1);
        let mut expected = known(&questions[0]);
        expected.extend(known(&questions[1]));
        assert_eq!(queries[0].answers, expected);

        let many = |q: &Question| (0..200).map(|i| ptr(&q.name, i)).collect::<Vec<_>>();
        let queries = Device::forward_queries(&questions[..1], many, DEFAULT_MAX_PACKET);
        let size = queries[0].encode().unwrap().len();
        assert!(size <= DEFAULT_MAX_PACKET && size > DEFAULT_MAX_PACKET - 100, "{size}");
        assert!(queries[0].answers.len() < 200 && !queries[0].answers.is_empty());
    }

    #[test]
    fn only_names_a_device_can_have_are_taken() {
        for ok in ["tv.local", "TV-2.LOCAL", "a.b.local", "fernseh-küche.local"] {
            assert!(is_hostname(ok), "{ok}");
        }
        for bad in ["tv", "tv.com", "local", "tv.local.evil", "bad\\.dot.local", "sp ace.local", "nul\0.local", "bad\u{FFFD}.local", ".local", ""] {
            assert!(!is_hostname(bad), "{bad:?}");
        }
        for ok in ["_http._tcp.local", "_androidtvremote2._tcp.local", "_x._udp.LOCAL", "_home-sharing._tcp.local"] {
            assert!(is_type(ok), "{ok}");
        }
        for bad in ["http._tcp.local", "_._tcp.local", "_http._xyz.local", "_http.local", "_http._tcp.com", "_ht tp._tcp.local", "a._http._tcp.local"] {
            assert!(!is_type(bad), "{bad}");
        }
        for ok in ["My TV._http._tcp.local", "Dots\\.in\\.it._http._tcp.local", "Wohnzimmer Ü._ipp._tcp.local"] {
            assert!(is_instance_name(ok), "{ok}");
        }
        for bad in ["._http._tcp.local", "Bell\u{7}._http._tcp.local", "X._http._tcp.com", "X.tv.local", "\u{FFFD}._http._tcp.local"] {
            assert!(!is_instance_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn only_addresses_a_device_can_be_reached_at_are_taken() {
        for ok in ["10.0.1.5", "192.168.1.1", "169.254.1.2", "fd00::1", "2001:db8::1", "fe80::1"] {
            assert!(is_usable(ip(ok)), "{ok}");
        }
        for bad in [
            "0.0.0.0", "0.1.2.3", "127.0.0.1", "224.0.0.251", "239.1.2.3", "240.0.0.1", "255.255.255.255",
            "::", "::1", "ff02::fb", "::ffff:10.0.1.5", "::10.0.1.5",
        ] {
            assert!(!is_usable(ip(bad)), "{bad}");
        }
    }

    /// Records no device could have announced are left out of a report, as
    /// if they were not there.
    #[test]
    fn records_no_device_could_have_announced_are_left_out() {
        let msg = response(vec![
            a_record("tv.local", "10.0.1.7"),
            a_record("tv.com", "10.0.1.8"),
            Record { class: 3, ..a_record("tv.local", "10.0.1.9") },
            srv("Port Zero._http._tcp.local", 0, "tv.local"),
            ptr("_http._tcp.local", "Other Type._ipp._tcp.local"),
            srv("TV._http._tcp.local", 80, "tv.local"),
        ]);
        let (reports, rest) = Report::all(&msg);
        let [report] = &reports[..] else { panic!("{} reports", reports.len()) };
        assert_eq!((report.host.as_str(), report.addrs.clone()), ("tv.local", vec![ip("10.0.1.7")]));
        let kept: Vec<&str> = report.records.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(kept, ["TV._http._tcp.local"]);
        assert!(rest.is_empty(), "{rest:?}");
    }

    /// What a report says of TTLs comes from each address's, and each other
    /// record's, own: the longest address TTL, and the longest of all, which
    /// the host is kept for at least.
    #[test]
    fn a_reports_ttls_come_from_each_records_own() {
        let msg = response(vec![
            Record { ttl: 120, ..a_record("tv.local", "10.0.1.7") },
            Record { ttl: 300, ..aaaa("tv.local", "fd00::7") },
            Record { ttl: 86400, ..a_record("tv.local", "0.0.0.0") },
            Record { ttl: 4500, ..srv("TV._http._tcp.local", 80, "tv.local") },
        ]);
        let (reports, _) = Report::all(&msg);
        let r = &reports[0];
        assert_eq!(r.ttls, HashMap::from([(ip("10.0.1.7"), 120), (ip("fd00::7"), 300)]));
        assert_eq!(r.addr_ttl(), Some(300), "an unusable address's does not count");
        assert_eq!(r.longest_ttl(), 4500);

        let only_service = response(vec![Record { ttl: 4500, ..srv("TV._http._tcp.local", 80, "tv.local") }]);
        let (reports, _) = Report::all(&only_service);
        assert_eq!((reports[0].addr_ttl(), reports[0].longest_ttl()), (None, 4500));
    }

    #[test]
    fn a_host_that_announced_only_unusable_addresses_is_refused() {
        let refused = |records| {
            let msg = response(records);
            let (reports, _) = Report::all(&msg);
            (reports[0].addrs.clone(), reports[0].refused.clone())
        };
        assert_eq!(refused(vec![a_record("tv.local", "0.0.0.0")]), (vec![], vec![ip("0.0.0.0")]));
        assert_eq!(
            refused(vec![a_record("tv.local", "0.0.0.0"), a_record("tv.local", "10.0.1.7")]),
            (vec![ip("10.0.1.7")], vec![ip("0.0.0.0")])
        );
        assert_eq!(refused(vec![srv("TV._http._tcp.local", 80, "tv.local")]), (vec![], vec![]), "it said nothing");
        // Of either family, whatever the packet came over.
        assert_eq!(
            refused(vec![aaaa("tv.local", "::1"), aaaa("tv.local", "fd00::7")]),
            (vec![ip("fd00::7")], vec![ip("::1")])
        );
    }

    #[test]
    fn a_device_holds_only_so_much() {
        let mut device = Device { hostname: Some("tv.local".into()), addresses: vec![ip("10.0.1.7")], ..Device::default() };
        let services: Vec<Record> = (0..MAX_SERVICES + 10).map(|i| srv(&format!("S{i}._http._tcp.local"), 80, "tv.local")).collect();
        device.learn_records(services.iter());
        assert_eq!(device.services.len(), MAX_SERVICES);

        let subtypes: Vec<Record> =
            (0..MAX_SUBTYPES + 5).map(|i| ptr(&format!("_s{i}._sub._http._tcp.local"), "S0._http._tcp.local")).collect();
        device.learn_records(subtypes.iter());
        assert_eq!(device.service("S0._http._tcp.local").unwrap().subtypes.len(), MAX_SUBTYPES);

        let mappings: Vec<Record> = (0..MAX_REVERSE + 5).map(|i| reverse(&format!("10.0.2.{i}"), "tv.local")).collect();
        device.learn_records(mappings.iter());
        assert_eq!(device.reverse.len(), MAX_REVERSE);
    }

    #[test]
    fn a_device_has_the_addresses_of_both_families_whatever_it_was_heard_over() {
        // It sends from its IPv6 link-local address and announces that, a
        // ULA, and its IPv4 address, all in one packet.
        let device = heard(vec![
            aaaa("tv.local", "fd00:0:1::7"),
            aaaa("tv.local", "fe80::7"),
            a_record("tv.local", "10.0.1.7"),
        ]);
        assert_eq!(device.hostname.as_deref(), Some("tv.local"));
        assert_eq!(device.addresses, [ip("10.0.1.7"), ip("fd00:0:1::7"), ip("fe80::7")]);

        // One family heard later leaves the other as it was.
        let mut device = heard(vec![a_record("nas.local", "10.0.1.8")]);
        hear(&mut device, vec![aaaa("nas.local", "fd00::8")]);
        assert_eq!((v4(&device), v6(&device)), (Some(ip("10.0.1.8")), Some(ip("fd00::8"))));
    }

    /// A device on a network with a global and a ULA prefix has an address
    /// of each, and more: all are kept.
    #[test]
    fn a_device_keeps_every_address_it_announces() {
        let device = heard(vec![
            aaaa("tv.local", "fd00::7"),
            aaaa("tv.local", "fe80::7"),
            aaaa("tv.local", "2001:db8::7"),
            a_record("tv.local", "10.0.1.7"),
        ]);
        assert_eq!(device.addresses, [ip("10.0.1.7"), ip("2001:db8::7"), ip("fd00::7"), ip("fe80::7")]);
        let sent: Vec<RData> = device.announcement(120, 4500).into_iter().filter(|r| r.name == "tv.local").map(|r| r.data).collect();
        assert_eq!(sent.len(), 4, "{sent:?}");
    }

    /// Addresses announced with the cache-flush bit are all a device has of
    /// their family: they replace those it had, and leave the other family
    /// alone. Without it, they are added. A goodbye drops just its address.
    #[test]
    fn a_family_announced_with_cache_flush_is_replaced_and_otherwise_added_to() {
        let mut device = heard(vec![a_record("tv.local", "10.0.1.7"), aaaa("tv.local", "2001:db8::7"), aaaa("tv.local", "fd00::7")]);

        // A new temporary address in place of the old, with the ULA kept.
        hear(&mut device, vec![aaaa("tv.local", "2001:db8::99"), aaaa("tv.local", "fd00::7")]);
        assert_eq!(device.addresses, [ip("10.0.1.7"), ip("2001:db8::99"), ip("fd00::7")]);

        let without_flush = |addr: &str| Record { cache_flush: false, ..aaaa("tv.local", addr) };
        hear(&mut device, vec![without_flush("2001:db8::100")]);
        assert_eq!(device.addresses, [ip("10.0.1.7"), ip("2001:db8::99"), ip("2001:db8::100"), ip("fd00::7")]);

        hear(&mut device, vec![Record { ttl: 0, ..aaaa("tv.local", "2001:db8::99") }]);
        assert_eq!(device.addresses, [ip("10.0.1.7"), ip("2001:db8::100"), ip("fd00::7")]);

        // However many it announces, only so many of a family are kept.
        let many: Vec<Record> = (0..DEFAULT_MAX_ADDRS + 10).map(|i| without_flush(&format!("2001:db8::{:x}", 0x200 + i))).collect();
        hear(&mut device, many);
        assert_eq!(device.addrs().filter(|a| a.is_ipv6()).count(), DEFAULT_MAX_ADDRS);
        assert_eq!(device.addrs().filter(|a| a.is_ipv4()).count(), 1);
    }

    /// Asked for one family's address, a device answers with the other's too
    /// (RFC 6762 section 6.2): a client asking over IPv4 learns of IPv6.
    #[test]
    fn an_address_answer_brings_the_other_familys() {
        let mut device = tv("10.0.1.9", &["TV"]);
        device.add_addrs(&[ip("fd00::9")]);
        for (asked, other) in [(rtype::A, RData::Aaaa("fd00::9".parse().unwrap())), (rtype::AAAA, RData::A("10.0.1.9".parse().unwrap()))] {
            let (answers, extra) = device.answers(&query("tv.local", asked), 120, 4500);
            assert_eq!(answers.len(), 1);
            assert!(extra.iter().any(|r| r.data == other), "{other:?} in {extra:?}");
        }
    }


    /// DNS compares names without regard to case, and devices are not
    /// consistent about it, not even within one packet.
    #[test]
    fn names_that_differ_only_in_case_are_one_and_the_same() {
        let mut device = heard(vec![
            a_record("tv.local", "10.0.1.7"),
            ptr("_HTTP._TCP.LOCAL", "TV._http._tcp.local"),
            srv("tv._HTTP._tcp.local", 80, "tv.local"),
        ]);
        assert_eq!(device.services.len(), 1, "{:?}", device.services);
        let svc = &device.services[0];
        assert_eq!((svc.instance.as_str(), svc.kind.as_str(), svc.port), ("TV._http._tcp.local", "_HTTP._TCP.LOCAL", 80));

        // A goodbye in yet another spelling still says goodbye to it.
        let bye = Record { ttl: 0, ..srv("Tv._Http._Tcp.Local", 80, "tv.local") };
        hear(&mut device, vec![a_record("tv.local", "10.0.1.7"), bye]);
        assert!(device.services.is_empty());
    }

    #[test]
    fn the_ttls_a_device_announces_are_kept_and_the_address_ones_do_not_get_the_services() {
        let device = heard(vec![
            a_record("d.local", "10.0.1.30"),
            record("D._x._tcp.local".into(), true, 4500, RData::Srv { priority: 0, weight: 0, port: 1, target: "d.local".into() }),
            record("_x._tcp.local".into(), false, 100, RData::Ptr("D._x._tcp.local".into())),
        ]);
        assert_eq!(device.ttl, Some(120));
        // The SRV record's TTL counts, not the PTR's.
        assert_eq!(device.services[0].ttl, 4500);
    }

    /// A printer says it is an AirPrint one with a subtype PTR next to its
    /// usual one. That is kept with the service, and a goodbye for it drops
    /// the subtype, not the service.
    #[test]
    fn subtypes_are_kept_with_their_service() {
        let printer = |sub_ttl| {
            vec![
                a_record("printer.local", "10.0.1.8"),
                ptr("_ipp._tcp.local", "Office._ipp._tcp.local"),
                Record { ttl: sub_ttl, ..ptr("_universal._sub._ipp._tcp.local", "Office._ipp._tcp.local") },
                srv("Office._ipp._tcp.local", 631, "printer.local"),
            ]
        };

        let mut device = heard(printer(4500));
        assert_eq!(device.services.len(), 1);
        assert_eq!(device.services[0].subtypes, ["_universal._sub._ipp._tcp.local"]);
        assert_eq!(device.services[0].kind, "_ipp._tcp.local", "the type is not the subtype's");

        // Heard again, in another case and on its own: still one.
        hear(&mut device, vec![ptr("_UNIVERSAL._sub._ipp._tcp.local", "Office._ipp._tcp.local")]);
        assert_eq!(device.services[0].subtypes.len(), 1);

        hear(&mut device, printer(0));
        assert!(device.services[0].subtypes.is_empty());
        assert_eq!(device.services[0].port, 631);
    }

    #[test]
    fn subtypes_are_announced_answered_and_withdrawn() {
        let name = "_printer._sub._http._tcp.local";
        let mut printer = tv("10.0.1.9", &["Office"]);
        printer.services[0].subtypes = vec![name.into()];
        let subtype = |records: &[Record]| records.iter().find(|r| r.name == name).cloned();

        let r = subtype(&printer.announcement(120, 4500)).expect("announced");
        assert_eq!((r.data, r.cache_flush), (RData::Ptr("Office._http._tcp.local".into()), false));

        // Browsing by the subtype finds it, with what it takes to resolve it.
        let (answers, extra) = printer.answers(&query(name, rtype::PTR), 120, 4500);
        assert_eq!(answers.len(), 1);
        assert!(subtype(&answers).is_some());
        assert!(extra.iter().any(|r| matches!(r.data, RData::Srv { .. })));
        assert!(extra.iter().any(|r| matches!(r.data, RData::A(_))));

        // No longer of the subtype: that alone is withdrawn.
        let mut plain = printer.clone();
        plain.services[0].subtypes.clear();
        let records = printer.replacement(&plain, 120, 4500);
        assert_eq!(subtype(&records).map(|r| r.ttl), Some(0));
        assert_eq!(records.iter().filter(|r| r.ttl == 0).count(), 1);
    }

    /// A device says which types its hostname has with an NSEC record, in
    /// its announcements or on its own as a negative answer. That of its
    /// service instances is not kept, nor taken for a host.
    #[test]
    fn what_a_device_says_its_hostname_has_is_kept() {
        let records = vec![
            a_record("tv.local", "10.0.1.7"),
            nsec("tv.local", &[rtype::A]),
            srv("TV._http._tcp.local", 80, "tv.local"),
            nsec("TV._http._tcp.local", &[rtype::TXT, rtype::SRV]),
        ];
        assert_eq!(Report::all(&response(records.clone())).0.len(), 1);
        let mut device = heard(records);
        assert_eq!(device.nsec, Some(vec![rtype::A]));

        // On its own, it is still about the host it names.
        hear(&mut device, vec![nsec("TV.local", &[rtype::A, rtype::AAAA])]);
        assert_eq!(device.nsec, Some(vec![rtype::A, rtype::AAAA]));
        hear(&mut device, vec![Record { ttl: 0, ..nsec("tv.local", &[rtype::A]) }]);
        assert_eq!(device.nsec, None);
    }

    #[test]
    fn a_reflected_device_denies_only_what_it_denied_itself() {
        let mut v4_only = tv("10.0.1.9", &["TV"]);
        v4_only.nsec = Some(vec![rtype::A]);
        let nsec_of = |records: &[Record]| records.iter().find(|r| matches!(r.data, RData::Nsec { .. })).cloned();
        let r = nsec_of(&v4_only.announcement(120, 4500)).expect("announced");
        assert_eq!((r.name.as_str(), r.cache_flush, r.ttl), ("tv.local", true, 120));
        assert_eq!(r.data, RData::Nsec { next: "tv.local".into(), types: vec![rtype::A] });

        // Asked for an address it has not got, it says so...
        let (answers, _) = v4_only.answers(&query("tv.local", rtype::AAAA), 120, 4500);
        assert_eq!(answers.len(), 1);
        assert!(nsec_of(&answers).is_some());

        // ...and its address comes with it.
        let (answers, extra) = v4_only.answers(&query("tv.local", rtype::A), 120, 4500);
        assert!(matches!(answers[..], [Record { data: RData::A(_), .. }]));
        assert!(nsec_of(&extra).is_some());

        // It is not among what the name has.
        let (answers, _) = v4_only.answers(&query("tv.local", rtype::ANY), 120, 4500);
        assert!(nsec_of(&answers).is_none());

        // What it announces is never denied, and NSEC itself is not listed.
        let mut said_less = v4_only.clone();
        said_less.nsec = Some(vec![rtype::AAAA, rtype::NSEC, 300]);
        match said_less.nsec_record(120).map(|r| r.data) {
            Some(RData::Nsec { types, .. }) => assert_eq!(types, [rtype::A, rtype::AAAA]),
            other => panic!("{other:?}"),
        }

        // A device that said nothing is denied nothing.
        let mut silent = v4_only;
        silent.nsec = None;
        assert!(silent.nsec_record(120).is_none());
        assert!(silent.answers(&query("tv.local", rtype::AAAA), 120, 4500).0.is_empty());
    }

    /// A device announces a reverse-mapping PTR for its address. That is kept
    /// with the host it names, not taken for a service or a host of its own.
    #[test]
    fn reverse_mappings_are_kept_with_the_host_they_name() {
        let records = vec![a_record("tv.local", "10.0.1.7"), reverse("10.0.1.7", "tv.local")];
        assert_eq!(Report::all(&response(records.clone())).0.len(), 1);
        let mut device = heard(records);
        assert_eq!(device.reverse, [ip("10.0.1.7")]);
        assert!(device.services.is_empty());

        // On its own, as an answer to a reverse lookup: still the same.
        hear(&mut device, vec![reverse("10.0.1.7", "TV.local")]);
        assert_eq!(device.reverse, [ip("10.0.1.7")]);
        hear(&mut device, vec![Record { ttl: 0, ..reverse("10.0.1.7", "tv.local") }]);
        assert!(device.reverse.is_empty());
    }

    /// A sleep proxy or Thread border router announces a host's records from
    /// its own address. Its NSEC and reverse mapping go to that host, as its
    /// address does, and nothing is left over for the proxy.
    #[test]
    fn what_a_proxy_says_of_a_host_goes_to_that_host() {
        let msg = response(vec![
            a_record("tv.local", "10.0.1.7"),
            nsec("tv.local", &[rtype::A]),
            reverse("10.0.1.7", "tv.local"),
        ]);
        let (reports, rest) = Report::all(&msg);
        assert!(rest.is_empty());
        let [report] = &reports[..] else { panic!("{} reports", reports.len()) };
        assert_eq!(report.host, "tv.local");

        let mut device = Device::default();
        device.learn(report, &report.addrs, DEFAULT_MAX_ADDRS);
        assert_eq!(v4(&device), Some(ip("10.0.1.7")), "the proxy's address is not the host's");
        assert_eq!((device.nsec, device.reverse), (Some(vec![rtype::A]), vec![ip("10.0.1.7")]));
    }

    #[test]
    fn reverse_mappings_are_announced_answered_and_withdrawn() {
        let name = "9.1.0.10.in-addr.arpa";
        let mut mapped = tv("10.0.1.9", &["TV"]);
        mapped.reverse = vec![ip("10.0.1.9")];
        let of = |records: &[Record]| records.iter().find(|r| r.name == name).cloned();

        // Only for an address the device announced one for.
        assert!(of(&tv("10.0.1.9", &["TV"]).announcement(120, 4500)).is_none());
        let r = of(&mapped.announcement(120, 4500)).expect("announced");
        assert_eq!((r.data, r.cache_flush), (RData::Ptr("tv.local".into()), true));

        let (answers, _) = mapped.answers(&query(name, rtype::PTR), 120, 4500);
        assert_eq!(answers.len(), 1);
        assert!(of(&answers).is_some());

        // Moved: the old mapping is withdrawn along with the old address.
        let mut moved = tv("10.0.1.10", &["TV"]);
        moved.reverse = vec![ip("10.0.1.10")];
        let records = mapped.replacement(&moved, 120, 4500);
        assert_eq!(of(&records).map(|r| r.ttl), Some(0));
        assert!(records.iter().any(|r| r.name == "10.1.0.10.in-addr.arpa" && r.ttl > 0));
    }
}
