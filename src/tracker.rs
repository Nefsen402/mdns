//! What a packet said, read once and apart from what is known: the changes
//! it makes to the devices of a segment, for them to be brought up to date by.

use core::net::IpAddr;

use crate::device::{addr_of, is_type, Report, META_QUERY};
use crate::parser::{Message, RData, Record};
use crate::prelude::*;

/// What one packet said. A query says nothing of its sender's: the records in
/// it are other devices' known answers.
pub struct Heard<'a> {
    /// The hosts that left: a response saying goodbye (TTL 0) to the address
    /// it came from, and announcing none for that name still, is a device
    /// leaving, whatever else is known by that name or by the sender's
    /// address. One that announces others in its place (a temporary IPv6
    /// address giving way to the next) is not; it only loses the one.
    pub leaving: Vec<&'a str>,
    /// The service types it said exist, in lowercase: the answers to the
    /// question of what types there are.
    pub types: Vec<String>,
    /// What it said of each host it describes, and the records that tie to
    /// none ([`Report::all`]), which are the sender's own, if any.
    pub reports: Vec<Report<'a>>,
    pub rest: Vec<&'a Record>,
}

impl<'a> Heard<'a> {
    /// Read `msg`, from `src`, if it was a message at all: nothing is said by
    /// one that could not be read.
    pub fn of(src: IpAddr, msg: Option<&'a Message>) -> Heard<'a> {
        let msg = msg.filter(|m| m.header.response);
        let records = || msg.into_iter().flat_map(|m| m.records());

        let still = |name: &str| records().any(|r| r.ttl > 0 && addr_of(&r.data).is_some() && r.name.eq_ignore_ascii_case(name));
        let leaving = records()
            .filter(|r| r.ttl == 0 && addr_of(&r.data) == Some(src) && !still(&r.name))
            .map(|r| r.name.as_str())
            .collect();

        let types = records()
            .filter_map(|rec| match &rec.data {
                RData::Ptr(kind)
                    if rec.ttl > 0 && rec.name.eq_ignore_ascii_case(META_QUERY) && rec.class == 1 && is_type(kind) =>
                {
                    Some(kind.to_ascii_lowercase())
                }
                _ => None,
            })
            .collect();

        let (reports, rest) = match msg {
            Some(m) => Report::all(m),
            None => (Vec::new(), Vec::new()),
        };
        Heard { leaving, types, reports, rest }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::parser::Header;

    fn record(name: &str, ttl: u32, data: RData) -> Record {
        Record { name: name.into(), class: 1, cache_flush: true, ttl, data }
    }

    fn a(name: &str, addr: &str, ttl: u32) -> Record {
        record(name, ttl, RData::A(addr.parse::<Ipv4Addr>().unwrap()))
    }

    fn aaaa(name: &str, addr: &str, ttl: u32) -> Record {
        record(name, ttl, RData::Aaaa(addr.parse::<Ipv6Addr>().unwrap()))
    }

    fn message(response: bool, answers: Vec<Record>) -> Message {
        let header = Header { id: 0, response, opcode: 0, authoritative: response, truncated: false, rcode: 0 };
        Message { header, questions: vec![], answers, authorities: vec![], additionals: vec![] }
    }

    fn heard<'a>(src: &str, msg: &'a Message) -> Heard<'a> {
        Heard::of(src.parse().unwrap(), Some(msg))
    }

    /// What is not a message, or a query, says nothing: the records of a
    /// query are other devices' known answers.
    #[test]
    fn a_query_and_what_is_not_a_message_say_nothing() {
        let known = message(false, vec![a("tv.local", "10.0.1.5", 120), a("gone.local", "10.0.1.5", 0)]);
        for heard in [heard("10.0.1.5", &known), Heard::of("10.0.1.5".parse().unwrap(), None)] {
            assert!(heard.leaving.is_empty() && heard.types.is_empty() && heard.reports.is_empty() && heard.rest.is_empty());
        }
    }

    /// A host leaves when it says goodbye to the address the packet came
    /// from; to another's, it is only saying the other left.
    #[test]
    fn a_host_leaves_by_saying_goodbye_to_the_address_it_came_from() {
        let msg = message(true, vec![a("tv.local", "10.0.1.5", 0)]);
        assert_eq!(heard("10.0.1.5", &msg).leaving, ["tv.local"]);
        assert!(heard("10.0.1.9", &msg).leaving.is_empty(), "a router saying so of another");
        let alive = message(true, vec![a("tv.local", "10.0.1.5", 120)]);
        assert!(heard("10.0.1.5", &alive).leaving.is_empty());
    }

    /// One that announces another address in its place is not leaving: it only
    /// loses the one, as a temporary IPv6 address gives way to the next.
    #[test]
    fn a_host_that_announces_another_address_in_its_place_is_not_leaving() {
        let msg = message(true, vec![aaaa("tv.local", "fd00::1", 0), aaaa("tv.local", "fd00::2", 120)]);
        assert!(heard("fd00::1", &msg).leaving.is_empty());
        // And not in another's name.
        let msg = message(true, vec![aaaa("tv.local", "fd00::1", 0), aaaa("other.local", "fd00::2", 120)]);
        assert_eq!(heard("fd00::1", &msg).leaving, ["tv.local"]);
    }

    /// The types it names are those of live answers to the question of what
    /// types there are, in lowercase, and well formed.
    #[test]
    fn the_service_types_are_the_live_answers_to_the_question_of_what_there_are() {
        let ptr = |owner: &str, ttl: u32, class: u16, target: &str| Record {
            class,
            ..record(owner, ttl, RData::Ptr(target.into()))
        };
        let msg = message(
            true,
            vec![
                ptr(META_QUERY, 4500, 1, "_IPP._tcp.local"),
                ptr("_Services._dns-sd._udp.local", 4500, 1, "_http._tcp.local"),
                ptr(META_QUERY, 0, 1, "_gone._tcp.local"),
                ptr(META_QUERY, 4500, 3, "_other._tcp.local"),
                ptr(META_QUERY, 4500, 1, "not a type"),
                ptr("_ipp._tcp.local", 4500, 1, "Printer._ipp._tcp.local"),
            ],
        );
        assert_eq!(heard("10.0.1.5", &msg).types, ["_ipp._tcp.local", "_http._tcp.local"]);
    }

    /// What it says of hosts is told by the host it concerns, and what ties to
    /// none is left over: a bare browse answer.
    #[test]
    fn what_it_says_is_told_by_host_and_the_rest_is_left_over() {
        let msg = message(
            true,
            vec![
                a("tv.local", "10.0.1.5", 120),
                a("nas.local", "10.0.1.6", 120),
                record("_ipp._tcp.local", 4500, RData::Ptr("Printer._ipp._tcp.local".into())),
            ],
        );
        let heard = heard("10.0.1.5", &msg);
        let hosts: Vec<&str> = heard.reports.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, ["tv.local", "nas.local"]);
        assert_eq!(heard.rest.len(), 1);
    }
}
