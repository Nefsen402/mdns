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

/// Questions per query packet, to stay well inside one Ethernet frame.
pub const QUESTIONS_PER_PACKET: usize = 16;

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

    /// The queries that look for devices on a segment of `family` where
    /// `devices` are known and `types` were said to be offered: what types
    /// there are, the instances of each, the subtypes clients browse by (they
    /// are not sent when their type is browsed), where each instance not yet
    /// resolved is, and the addresses of a device known by name but without a
    /// routable address (it only ever showed a link-local one).
    pub fn probe_queries(devices: &[Device], types: &BTreeSet<String>, family: Family) -> Vec<Message> {
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
        for host in devices.iter().filter(|d| d.routable.is_none()).filter_map(|d| d.hostname.as_deref()) {
            qs.ask(host, address_type(family));
        }
        qs.into_queries()
    }

    /// Queries that ask `questions`, put on another segment, as this
    /// daemon's own: each once, a few to a packet, and for a multicast answer
    /// whatever the asker wanted, so that it is heard and can be reflected.
    pub fn forward_queries<'a>(questions: impl IntoIterator<Item = &'a Question>) -> Vec<Message> {
        let mut qs = Questions::default();
        for q in questions {
            qs.ask(&q.name, q.qtype);
        }
        qs.into_queries()
    }

    /// Whether it has an answer to `q`: a record, or, by its NSEC, the word
    /// that there is none.
    pub fn knows(&self, q: &Question) -> bool {
        !self.answers(&query(std::slice::from_ref(q)), 1, 1).0.is_empty()
    }

    /// The queries that ask `devices`, on a segment of `family`, to answer
    /// again: each for what it announced (its address, and the service and
    /// text records of each of its instances), and not for whole service
    /// types, so that only they answer.
    pub fn refresh_queries(devices: &[Device], family: Family) -> Vec<Message> {
        let mut qs = Questions::default();
        for device in devices {
            if let Some(host) = &device.hostname {
                qs.ask(host, address_type(family));
            }
            for svc in &device.services {
                qs.ask(&svc.instance, rtype::SRV);
                qs.ask(&svc.instance, rtype::TXT);
            }
        }
        qs.into_queries()
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
    /// them answers, once each, in one message, each with the TTL of its
    /// address ([`HOST_TTL`] if it has none) and of its services. Returns it
    /// with the indices of the devices that answered, or `None` if none did.
    ///
    /// A `legacy` resolver, asking from a port other than 5353, gets a reply
    /// it can take (RFC 6762 section 6.7): its question and id echoed, no TTL
    /// over ten seconds, and no cache-flush bits.
    pub fn query_response(devices: &[Device], query: &Message, legacy: bool) -> Option<(Message, Vec<usize>)> {
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

        let mut msg = Message {
            header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
            questions: Vec::new(),
            answers,
            authorities: Vec::new(),
            additionals,
        };
        if legacy {
            msg.header.id = query.header.id;
            msg.questions = query.questions.clone();
            for r in msg.answers.iter_mut().chain(&mut msg.additionals) {
                r.ttl = r.ttl.min(LEGACY_TTL_CAP);
                r.cache_flush = false;
            }
        }
        Some((msg, answered))
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

/// The address record type of `family`.
fn address_type(family: Family) -> u16 {
    match family {
        Family::V4 => rtype::A,
        Family::V6 => rtype::AAAA,
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

    /// The questions as multicast queries, a few to a packet.
    fn into_queries(self) -> Vec<Message> {
        self.list.chunks(QUESTIONS_PER_PACKET).map(query).collect()
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

    /// Make `device` hear `records` from `src`, as a segment puts them to the
    /// one device they are about: the report on it, and what ties to no host.
    fn hear(device: &mut Device, family: Family, src: &str, records: Vec<Record>) {
        let msg = response(records);
        let (reports, rest) = Report::all(&msg, family);
        for report in &reports {
            device.learn(report, &report.addrs, ip(src));
        }
        device.learn_records(rest.into_iter());
    }

    fn heard(family: Family, src: &str, records: Vec<Record>) -> Device {
        let mut device = Device::default();
        hear(&mut device, family, src, records);
        device
    }

    fn tv(addr: &str, instances: &[&str]) -> Device {
        Device {
            hostname: Some("tv.local".into()),
            routable: Some(ip(addr)),
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
        }
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

    #[test]
    fn a_query_response_has_what_each_device_answers_once() {
        let devices = three_devices();
        let (msg, answered) = Device::query_response(&devices, &query("_http._tcp.local", rtype::PTR), false).unwrap();
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
        let (msg, answered) =
            Device::query_response(&devices, &query("_services._dns-sd._udp.local", rtype::PTR), false).unwrap();
        assert_eq!(answered, [0, 1, 2]);
        assert_eq!(msg.answers.len(), 2, "_http and _ipp: {:?}", msg.answers);

        // Nothing to say is no reply at all.
        assert!(Device::query_response(&devices, &query("_airplay._tcp.local", rtype::PTR), false).is_none());
        assert!(Device::query_response(&[], &query("_http._tcp.local", rtype::PTR), false).is_none());
    }

    #[test]
    fn a_legacy_resolver_gets_its_question_back_and_short_ttls_without_cache_flush() {
        let devices = three_devices();
        let mut asked = query("tv.local", rtype::ANY);
        asked.header.id = 0x4242;

        let (msg, _) = Device::query_response(&devices, &asked, true).unwrap();
        assert_eq!((msg.header.id, msg.questions.clone()), (0x4242, asked.questions.clone()));
        assert!(msg.answers.iter().chain(&msg.additionals).all(|r| r.ttl <= LEGACY_TTL_CAP && !r.cache_flush));

        // To the group, none of that.
        let (msg, _) = Device::query_response(&devices, &asked, false).unwrap();
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
        let named = Device { hostname: Some("nas.local".into()), link_local: Some(ip("169.254.1.1")), ..Device::default() };
        let types = BTreeSet::from(["_ipp._tcp.local".to_string()]);

        let questions = asked(&Device::probe_queries(&[resolved, unresolved, named], &types, Family::V4));
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
        let queries = Device::probe_queries(&[], &types, Family::V4);
        assert_eq!(asked(&queries).len(), 41);
        assert_eq!(queries.len(), 3);
    }

    #[test]
    fn a_refresh_asks_each_device_for_what_it_announced_and_no_more() {
        let devices = [tv("fd00::9", &["TV", "Cast"]), tv("fd00::9", &["TV"])];
        let questions = asked(&Device::refresh_queries(&devices, Family::V6));
        assert_eq!(questions, [
            q("tv.local", rtype::AAAA),
            q("TV._http._tcp.local", rtype::SRV),
            q("TV._http._tcp.local", rtype::TXT),
            q("Cast._http._tcp.local", rtype::SRV),
            q("Cast._http._tcp.local", rtype::TXT),
        ]);
        assert!(Device::refresh_queries(&[], Family::V6).is_empty());
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
        let moved = Device { routable: Some(ip("10.0.1.10")), ..old.clone() };
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
        let queries = Device::forward_queries(&questions);
        assert_eq!(asked(&queries), [q("printer.local", rtype::A), q("_ipp._tcp.local", rtype::PTR)]);
        assert!(queries.iter().flat_map(|m| &m.questions).all(|q| !q.unicast_response && q.class == 1));
        assert!(Device::forward_queries(&[]).is_empty());
    }

    #[test]
    fn an_ipv6_device_has_a_link_local_and_a_routable_address() {
        // It sends from its link-local address and announces that, a ULA, and
        // (wrongly for an IPv6 segment) an IPv4 address, which is ignored.
        let device = heard(Family::V6, "fe80::7", vec![
            aaaa("tv.local", "fd00:0:1::7"),
            aaaa("tv.local", "fe80::7"),
            a_record("tv.local", "10.0.1.7"),
        ]);
        assert_eq!(device.hostname.as_deref(), Some("tv.local"));
        assert_eq!(device.routable, Some(ip("fd00:0:1::7")));
        assert_eq!(device.link_local, Some(ip("fe80::7")));
    }

    /// DNS compares names without regard to case, and devices are not
    /// consistent about it, not even within one packet.
    #[test]
    fn names_that_differ_only_in_case_are_one_and_the_same() {
        let mut device = heard(Family::V4, "10.0.1.7", vec![
            a_record("tv.local", "10.0.1.7"),
            ptr("_HTTP._TCP.LOCAL", "TV._http._tcp.local"),
            srv("tv._HTTP._tcp.local", 80, "tv.local"),
        ]);
        assert_eq!(device.services.len(), 1, "{:?}", device.services);
        let svc = &device.services[0];
        assert_eq!((svc.instance.as_str(), svc.kind.as_str(), svc.port), ("TV._http._tcp.local", "_HTTP._TCP.LOCAL", 80));

        // A goodbye in yet another spelling still says goodbye to it.
        let bye = Record { ttl: 0, ..srv("Tv._Http._Tcp.Local", 80, "tv.local") };
        hear(&mut device, Family::V4, "10.0.1.7", vec![a_record("tv.local", "10.0.1.7"), bye]);
        assert!(device.services.is_empty());
    }

    #[test]
    fn the_ttls_a_device_announces_are_kept_and_the_address_ones_do_not_get_the_services() {
        let device = heard(Family::V4, "10.0.1.30", vec![
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

        let mut device = heard(Family::V4, "10.0.1.8", printer(4500));
        assert_eq!(device.services.len(), 1);
        assert_eq!(device.services[0].subtypes, ["_universal._sub._ipp._tcp.local"]);
        assert_eq!(device.services[0].kind, "_ipp._tcp.local", "the type is not the subtype's");

        // Heard again, in another case and on its own: still one.
        hear(&mut device, Family::V4, "10.0.1.8", vec![ptr("_UNIVERSAL._sub._ipp._tcp.local", "Office._ipp._tcp.local")]);
        assert_eq!(device.services[0].subtypes.len(), 1);

        hear(&mut device, Family::V4, "10.0.1.8", printer(0));
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
        assert_eq!(Report::all(&response(records.clone()), Family::V4).0.len(), 1);
        let mut device = heard(Family::V4, "10.0.1.7", records);
        assert_eq!(device.nsec, Some(vec![rtype::A]));

        // On its own, it is still about the host it names.
        hear(&mut device, Family::V4, "10.0.1.7", vec![nsec("TV.local", &[rtype::A, rtype::AAAA])]);
        assert_eq!(device.nsec, Some(vec![rtype::A, rtype::AAAA]));
        hear(&mut device, Family::V4, "10.0.1.7", vec![Record { ttl: 0, ..nsec("tv.local", &[rtype::A]) }]);
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
        assert_eq!(Report::all(&response(records.clone()), Family::V4).0.len(), 1);
        let mut device = heard(Family::V4, "10.0.1.7", records);
        assert_eq!(device.reverse, [ip("10.0.1.7")]);
        assert!(device.services.is_empty());

        // On its own, as an answer to a reverse lookup: still the same.
        hear(&mut device, Family::V4, "10.0.1.7", vec![reverse("10.0.1.7", "TV.local")]);
        assert_eq!(device.reverse, [ip("10.0.1.7")]);
        hear(&mut device, Family::V4, "10.0.1.7", vec![Record { ttl: 0, ..reverse("10.0.1.7", "tv.local") }]);
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
        let (reports, rest) = Report::all(&msg, Family::V4);
        assert!(rest.is_empty());
        let [report] = &reports[..] else { panic!("{} reports", reports.len()) };
        assert_eq!(report.host, "tv.local");

        let mut device = Device::default();
        device.learn(report, &report.addrs, ip("10.0.1.1"));
        assert_eq!(device.routable, Some(ip("10.0.1.7")), "the proxy's address is not the host's");
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
