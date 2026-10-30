//! What is known about a device on a segment: its hostname, addresses and
//! services. Kept by [`Segment`](crate::socket::Segment), and announced on
//! other segments by the [`Reflector`](crate::reflector::Reflector).
//!
//! A response is read into one [`Report`] per host it describes, which a
//! [`Device`] then takes in with [`Device::learn`]; a device is turned back
//! into records with [`Device::announcement`] and [`Device::answers`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use crate::parser::{self, rtype, Message, RData, Record};
use crate::socket::Family;

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
/// It has up to two addresses, of the segment's family: a link-local one,
/// which only means something on the link it was heard on, and a routable one
/// that other networks can reach it at (IPv4, or global/ULA IPv6).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Device {
    pub hostname: Option<String>,
    pub link_local: Option<IpAddr>,
    pub routable: Option<IpAddr>,
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
    /// Its usable addresses of the segment's family, as announced.
    pub addrs: Vec<IpAddr>,
    /// The records about it other than its addresses: those of the services
    /// whose SRV points at it, its NSEC, and its reverse mappings.
    pub records: Vec<&'a Record>,
    /// The longest TTL of its addresses and services.
    pub max_ttl: u32,
    /// The TTL its address records announced, if it has any of this family.
    pub addr_ttl: Option<u32>,
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
    pub fn all(msg: &'a Message, family: Family) -> (Vec<Report<'a>>, Vec<&'a Record>) {
        let mut reports: Vec<Report<'a>> = Vec::new();
        let mut instance_host: HashMap<String, usize> = HashMap::new();
        for rec in msg.records() {
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
        for rec in msg.records() {
            let instance = match &rec.data {
                RData::A(_) | RData::Aaaa(_) => {
                    let i = report_index(&mut reports, &rec.name);
                    reports[i].max_ttl = reports[i].max_ttl.max(rec.ttl);
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
                Some(&i) => {
                    reports[i].records.push(rec);
                    reports[i].max_ttl = reports[i].max_ttl.max(rec.ttl);
                }
                None => rest.push(rec),
            }
        }

        for r in &mut reports {
            r.addrs = announced_addrs(msg, &r.host, family);
            r.addr_ttl = msg
                .records()
                .filter(|rec| rec.name.eq_ignore_ascii_case(&r.host))
                .filter(|rec| addr_of(&rec.data).is_some_and(|a| r.addrs.contains(&a)))
                .map(|rec| rec.ttl)
                .max();
        }
        (reports, rest)
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
    reports.push(Report { host: host.to_string(), addrs: Vec::new(), records: Vec::new(), max_ttl: 0, addr_ttl: None });
    reports.len() - 1
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

    /// Its service called `instance`, ignoring case.
    pub fn service(&self, instance: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.instance.eq_ignore_ascii_case(instance))
    }

    /// Forget its service called `instance`, ignoring case.
    pub fn forget_service(&mut self, instance: &str) {
        self.services.retain(|s| !s.instance.eq_ignore_ascii_case(instance));
    }

    /// Take in what `report` says about it, with the addresses that vouch for
    /// it: those announced, and the one the packet came from if it sent it.
    pub fn learn(&mut self, report: &Report<'_>, addrs: &[IpAddr], src: IpAddr) {
        self.hostname = Some(report.host.clone());
        self.set_addrs(addrs, src);
        self.ttl = report.addr_ttl.or(self.ttl);
        self.learn_records(report.records.iter().copied());
    }

    /// Record the addresses a packet vouches for. When there are several of a
    /// kind, the one the packet came from wins, else the lowest.
    pub fn set_addrs(&mut self, addrs: &[IpAddr], src: IpAddr) {
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

    /// Take in the service records, NSEC and reverse mappings in `records`. A
    /// TTL of 0 is a goodbye for what the record says.
    pub fn learn_records<'a>(&mut self, records: impl Iterator<Item = &'a Record>) {
        for rec in records {
            match &rec.data {
                RData::Ptr(host) if parser::reverse_addr(&rec.name).is_some() => {
                    let addr = parser::reverse_addr(&rec.name).expect("checked above");
                    if self.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(host)) {
                        self.reverse.retain(|a| *a != addr);
                        if rec.ttl != 0 {
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
                        } else {
                            let svc = self.service_mut(instance);
                            if !svc.subtypes.iter().any(same) {
                                svc.subtypes.push(rec.name.clone());
                            }
                        }
                        continue;
                    }
                    if rec.ttl == 0 {
                        self.forget_service(instance);
                    } else {
                        let svc = self.service_mut(instance);
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
                    } else {
                        let svc = self.service_mut(&rec.name);
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
                    if rec.ttl != 0 {
                        let svc = self.service_mut(&rec.name);
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
            if self.service(&svc.instance).is_none() {
                self.insert_service(svc);
            }
        }
    }

    /// Get or create a service, deriving its type from the instance name
    /// until a PTR record states it explicitly. It keeps the spelling it was
    /// first heard with, whatever the case of later records.
    fn service_mut(&mut self, instance: &str) -> &mut Service {
        let at = match self.services.iter().position(|s| s.instance.eq_ignore_ascii_case(instance)) {
            Some(at) => at,
            None => self.insert_service(Service {
                instance: instance.to_string(),
                kind: parser::split_instance(instance).map(|(_, kind)| kind.to_string()).unwrap_or_default(),
                ..Service::default()
            }),
        };
        &mut self.services[at]
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
            if !found && q.qtype != rtype::ANY {
                if let Some(nsec) = all.iter().find(denies).filter(|r| !answers.contains(r)) {
                    answers.push(nsec.clone());
                }
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
        // An address comes with the NSEC that says which kinds of address
        // there are (RFC 6762 section 6.2).
        let hosts: Vec<String> = answers
            .iter()
            .chain(&extra)
            .filter(|r| matches!(r.data, RData::A(_) | RData::Aaaa(_)))
            .map(|r| r.name.clone())
            .collect();
        for rec in &all {
            let wanted =
                matches!(rec.data, RData::Nsec { .. }) && hosts.iter().any(|h| rec.name.eq_ignore_ascii_case(h));
            if wanted && !answers.contains(rec) && !extra.contains(rec) {
                extra.push(rec.clone());
            }
        }
        (answers, extra)
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
