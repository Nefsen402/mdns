//! The messages the daemon says: the records that announce a device, take it
//! back, or answer a question about it, and the queries that look for devices,
//! each packed into as few packets as the interface's MTU leaves room for.
//!
//! What a device is, and what is heard of one, is for [`device`](crate::device);
//! here it is only read, to make what goes out. Which addresses and services of
//! it are shown is decided here, as the records are made, by the
//! [`Advertise`] it is shown with.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::net::IpAddr;

use hashbrown::{HashMap, HashSet};

use crate::codec::{self, rtype, Header, Message, Question, RData, Record};
use crate::config::Advertise;
use crate::device::{Advertised, Device, Service, META_QUERY, OTHER_TTL, SERVICE_ENUMERATION};

use crate::prelude::*;

/// TTL cap for replies to legacy unicast resolvers (RFC 6762 section 6.7).
pub const LEGACY_TTL_CAP: u32 = 10;

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

/// A reflected device is never announced for less than this, however short a
/// TTL it announced itself with: where an interface announces again, it is at 80%
/// of its TTL, and a few seconds would be a flood.
pub const MIN_REFLECT_TTL: u32 = 10;

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
    let mut at: HashMap<(u16, String), usize> = HashMap::new();
    let mut sets: Vec<Vec<&Record>> = Vec::new();
    for rec in records {
        match at.get(&(rec.rtype(), rec.name.to_ascii_lowercase())) {
            Some(&i) => sets[i].push(rec),
            None => {
                at.insert((rec.rtype(), rec.name.to_ascii_lowercase()), sets.len());
                sets.push(vec![rec]);
            }
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

fn address_data(addr: IpAddr) -> RData {
    match addr {
        IpAddr::V4(a) => RData::A(a),
        IpAddr::V6(a) => RData::Aaaa(a),
    }
}

pub fn record(name: String, cache_flush: bool, ttl: u32, data: RData) -> Record {
    Record { name, class: 1, cache_flush, ttl, data }
}

/// The queries that look for devices on an interface where `devices` are
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

/// Queries that ask `questions`, put on another interface, as this
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

/// The records that take an interface from announcing `old` to announcing
/// `new` under one hostname, either of them nothing, each announced with
/// the TTL of its address in its `ttl`: all of `new`, and goodbyes for
/// what of `old` it does not have.
///
/// What devices on the interface have themselves is theirs. No goodbye is
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

/// A query, read once for answering it: the names it asks about, each once
/// whatever the types and the number of times asked, and the answers it
/// already has, found by name and data. So no answer is looked for among all
/// the questions or all the known answers, and what a packet repeats costs
/// nothing.
pub struct Request<'a> {
    pub message: &'a Message,
    /// The names asked about, in lowercase, in the order they were first asked,
    /// with what is asked of each.
    names: Vec<(String, Asking)>,
    /// The longest TTL the asker holds each record it already has with.
    known: HashMap<(String, &'a RData), u32>,
}

/// The types asked of one name.
#[derive(Default)]
struct Asking {
    /// ANY was asked.
    any: bool,
    types: HashSet<u16>,
    /// The types in the order they were first asked.
    order: Vec<u16>,
}

impl<'a> Request<'a> {
    pub fn new(message: &'a Message) -> Request<'a> {
        let mut at: HashMap<String, usize> = HashMap::new();
        let mut names: Vec<(String, Asking)> = Vec::new();
        for q in &message.questions {
            // Only the Internet class is answered, and any.
            if q.class != 1 && q.class != 255 {
                continue;
            }
            let lower = q.name.to_ascii_lowercase();
            let i = match at.get(&lower) {
                Some(&i) => i,
                None => {
                    names.push((lower.clone(), Asking::default()));
                    at.insert(lower, names.len() - 1);
                    names.len() - 1
                }
            };
            let asking = &mut names[i].1;
            asking.any |= q.qtype == rtype::ANY;
            if asking.types.insert(q.qtype) {
                asking.order.push(q.qtype);
            }
        }
        let mut known: HashMap<(String, &RData), u32> = HashMap::new();
        for k in &message.answers {
            let ttl = known.entry((k.name.to_ascii_lowercase(), &k.data)).or_insert(0);
            *ttl = (*ttl).max(k.ttl);
        }
        Request { message, names, known }
    }

    /// The names asked about, in lowercase, once each: what the indices of
    /// [`query_response`] are of.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|(name, _)| name.as_str())
    }

    /// Whether the asker already holds `record`, with at least half its life
    /// left (RFC 6762 section 7.1).
    fn holds(&self, record: &Record) -> bool {
        self.known.get(&(record.name.to_ascii_lowercase(), &record.data)).is_some_and(|&ttl| ttl >= record.ttl / 2)
    }
}

/// The reply to `request` from a responder that has `devices`: what each of
/// them answers, once each, each with the TTL of its address
/// ([`HOST_TTL`](crate::device::HOST_TTL) if it has none) and of its services, in as many packets
/// of at most `limit` bytes as it takes ([`responses`]). Of each device, only
/// the names of the request that `asked` says (by index, see
/// [`Request::names`]) are looked into. Returns the packets with the indices
/// of the devices that answered, or `None` if none did.
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
    asked: &[Vec<usize>],
    request: &Request,
    legacy: bool,
    limit: usize,
) -> Option<(Vec<Message>, Vec<usize>)> {
    let query = request.message;
    let mut answers: Vec<Record> = Vec::new();
    let mut additionals: Vec<Record> = Vec::new();
    let (mut in_answers, mut in_additionals): (HashSet<Record>, HashSet<Record>) = (HashSet::new(), HashSet::new());
    let mut answered = Vec::new();
    for (i, (Advertised { device, how, host_ttl }, names)) in devices.iter().zip(asked).enumerate() {
        let (a, x) = device.answers_to(how, request, names, *host_ttl, OTHER_TTL);
        if a.is_empty() {
            continue;
        }
        for r in a {
            if !in_answers.contains(&r) {
                in_answers.insert(r.clone());
                answers.push(r);
            }
        }
        for r in x {
            if !in_additionals.contains(&r) {
                in_additionals.insert(r.clone());
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
    // A section is full at the first record that does not fit: what is left
    // is not tried, which would cost the size of the reply for each.
    for (additional, records) in [(false, &answers), (true, &additionals)] {
        for rec in records {
            section(&mut msg, additional).push(legacy(rec));
            if size(&msg) > limit {
                section(&mut msg, additional).pop();
                msg.header.truncated |= !additional;
                break;
            }
        }
    }
    Some((vec![msg], answered))
}

impl Device {
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

    /// The records that take an interface from announcing this device to
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

    /// Its records that answer `q`, with these TTLs, without the additional
    /// records an answer brings, nor an NSEC saying it has none.
    pub fn records_for(&self, how: &Advertise, q: &Question, host_ttl: u32, other_ttl: u32) -> Vec<Record> {
        let (mut records, _) = self.answers(how, &query(core::slice::from_ref(q)), host_ttl, other_ttl);
        records.retain(|r| r.rtype() != rtype::NSEC);
        records
    }

    /// Whether it has an answer to `q`: a record, or, by its NSEC, the word
    /// that there is none.
    #[cfg(test)]
    pub fn knows(&self, how: &Advertise, q: &Question) -> bool {
        let mut coverage = Coverage::default();
        coverage.add(self, how, &q.name);
        (q.class == 1 || q.class == 255) && coverage.knows(q.qtype)
    }

    /// Its records that match `query`, with known-answer suppression
    /// applied, plus the additional records a client will want next (RFC 6763
    /// section 12): a PTR brings its SRV and TXT, and an SRV brings its address.
    pub fn answers(&self, how: &Advertise, query: &Message, host_ttl: u32, other_ttl: u32) -> (Vec<Record>, Vec<Record>) {
        let request = Request::new(query);
        let names: Vec<usize> = (0..request.names.len()).collect();
        self.answers_to(how, &request, &names, host_ttl, other_ttl)
    }

    /// Like [`Device::answers`], of the names of `request` that `names` says
    /// (by index) and no others: for a device that is asked only about some of
    /// the names of a query, which is all most of them are. Its records are made
    /// once, and found by name, and nothing is looked for twice.
    pub fn answers_to(
        &self,
        how: &Advertise,
        request: &Request,
        names: &[usize],
        host_ttl: u32,
        other_ttl: u32,
    ) -> (Vec<Record>, Vec<Record>) {
        let all = self.announcement(how, host_ttl, other_ttl);
        let mut under: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, rec) in all.iter().enumerate() {
            under.entry(rec.name.to_ascii_lowercase()).or_default().push(i);
        }

        let mut seen: HashSet<&Record> = HashSet::new();
        let mut answers: Vec<&Record> = Vec::new();
        for &n in names {
            let (name, asking) = &request.names[n];
            let Some(here) = under.get(name) else { continue };
            let mut types: HashSet<u16> = HashSet::new();
            let mut nsecs: Vec<&Record> = Vec::new();
            for &i in here {
                let rec = &all[i];
                types.insert(rec.rtype());
                if matches!(rec.data, RData::Nsec { .. }) {
                    nsecs.push(rec);
                }
                // An NSEC is not one of the records a name has.
                let type_ok = (asking.any && rec.rtype() != rtype::NSEC) || asking.types.contains(&rec.rtype());
                if type_ok && seen.insert(rec) {
                    answers.push(rec);
                }
            }
            // A type the name has not got, by its NSEC: say so (RFC 6762
            // section 6.1), so the asker need not wait for an answer.
            if nsecs.is_empty() {
                continue;
            }
            for &qtype in &asking.order {
                if qtype == rtype::ANY || types.contains(&qtype) {
                    continue;
                }
                let denies = |r: &&&Record| matches!(&r.data, RData::Nsec { types, .. } if !types.contains(&qtype));
                if let Some(&nsec) = nsecs.iter().find(denies)
                    && seen.insert(nsec)
                {
                    answers.push(nsec);
                }
            }
        }

        // The asker already holds this record with at least half its life left.
        answers.retain(|r| !request.holds(r));
        if answers.is_empty() {
            return (Vec::new(), Vec::new());
        }

        // What each next group of records is of, in the order the device has
        // them, and not what is in `seen` already.
        let pick = |of: Vec<String>, ok: fn(&RData) -> bool, seen: &HashSet<&Record>| -> Vec<&Record> {
            let mut at: Vec<usize> =
                of.iter().filter_map(|name| under.get(name)).flatten().copied().filter(|&i| ok(&all[i].data) && !seen.contains(&all[i])).collect();
            at.sort_unstable();
            at.dedup();
            at.into_iter().map(|i| &all[i]).collect()
        };
        fn lower(records: &[&Record], of: fn(&RData) -> Option<&String>) -> Vec<String> {
            records.iter().filter_map(|r| of(&r.data)).map(|name| name.to_ascii_lowercase()).collect()
        }

        seen = answers.iter().copied().collect();
        let mut extra: Vec<&Record> = Vec::new();
        fn target(data: &RData) -> Option<&String> {
            match data {
                RData::Srv { target, .. } => Some(target),
                _ => None,
            }
        }
        fn instance(data: &RData) -> Option<&String> {
            match data {
                RData::Ptr(instance) => Some(instance),
                _ => None,
            }
        }
        // A PTR brings the SRV and TXT of its instance.
        for rec in pick(lower(&answers, instance), |d| matches!(d, RData::Srv { .. } | RData::Txt(_)), &seen) {
            seen.insert(rec);
            extra.push(rec);
        }
        // An SRV brings the addresses of its target.
        let both: Vec<&Record> = answers.iter().chain(&extra).copied().collect();
        for rec in pick(lower(&both, target), |d| matches!(d, RData::A(_) | RData::Aaaa(_)), &seen) {
            seen.insert(rec);
            extra.push(rec);
        }
        // An address comes with the name's addresses of the other family, and
        // the NSEC that says which kinds of address there are (RFC 6762
        // section 6.2): so a client asking over IPv4 learns of IPv6 too.
        let both: Vec<&Record> = answers.iter().chain(&extra).copied().collect();
        let hosts: Vec<String> = both
            .iter()
            .filter(|r| matches!(r.data, RData::A(_) | RData::Aaaa(_)))
            .map(|r| r.name.to_ascii_lowercase())
            .collect();
        for rec in pick(hosts, |d| matches!(d, RData::A(_) | RData::Aaaa(_) | RData::Nsec { .. }), &seen) {
            seen.insert(rec);
            extra.push(rec);
        }
        (answers.into_iter().cloned().collect(), extra.into_iter().cloned().collect())
    }
}

/// What the devices announced under one name between them answer of each
/// type that might be asked of it: a record of it, or, by an NSEC, the word
/// that there is none. Built once for a name, whatever types are asked.
#[derive(Default)]
pub struct Coverage {
    /// The types of the records under the name.
    types: HashSet<u16>,
    /// What each NSEC under the name says it has.
    nsecs: Vec<Vec<u16>>,
}

impl Coverage {
    /// Count what `device`, shown as `how`, has under `name`.
    pub fn add(&mut self, device: &Device, how: &Advertise, name: &str) {
        if device.hostname.is_none() {
            return;
        }
        for rec in device.announcement(how, 1, 1).iter().filter(|r| r.name.eq_ignore_ascii_case(name)) {
            self.types.insert(rec.rtype());
            if let RData::Nsec { types, .. } = &rec.data
                && !self.nsecs.contains(types)
            {
                self.nsecs.push(types.clone());
            }
        }
    }

    /// Whether a question of `qtype` of the name has an answer: any record
    /// for ANY (an NSEC is not one of the records a name has), else one of
    /// the type, or an NSEC that says there is none.
    pub fn knows(&self, qtype: u16) -> bool {
        if qtype == rtype::ANY {
            return self.types.iter().any(|&t| t != rtype::NSEC);
        }
        self.types.contains(&qtype) || self.nsecs.iter().any(|types| !types.contains(&qtype))
    }
}

#[cfg(test)]
#[path = "../tests/unit/message.rs"]
mod tests;
