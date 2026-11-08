use super::*;

fn labels(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.push(p.len() as u8);
        out.extend(p.as_bytes());
    }
    out.push(0);
    out
}

fn pointer(offset: usize) -> [u8; 2] {
    [0xc0 | (offset >> 8) as u8, offset as u8]
}

fn header(flags: u16, qd: u16, an: u16) -> Vec<u8> {
    let mut h = Vec::new();
    for v in [0x1234, flags, qd, an, 0, 0] {
        h.extend(v.to_be_bytes());
    }
    h
}

/// Appends a record and returns the offset of its rdata.
fn rr(p: &mut Vec<u8>, name: &[u8], rtype: u16, class: u16, ttl: u32, rdata: &[u8]) -> usize {
    p.extend(name);
    p.extend(rtype.to_be_bytes());
    p.extend(class.to_be_bytes());
    p.extend(ttl.to_be_bytes());
    p.extend((rdata.len() as u16).to_be_bytes());
    let off = p.len();
    p.extend(rdata);
    off
}

/// A DNS-SD announcement for "Printer._http._tcp.local" using compression.
fn announcement() -> Vec<u8> {
    let mut p = header(0x8400, 0, 4);

    let svc_off = p.len();
    let mut ptr_data = vec![7];
    ptr_data.extend(b"Printer");
    ptr_data.extend(pointer(svc_off));
    let inst_off = rr(&mut p, &labels(&["_http", "_tcp", "local"]), rtype::PTR, 1, 4500, &ptr_data);

    let mut srv = vec![0, 0, 0, 0, 0x02, 0x77]; // priority 0, weight 0, port 631
    srv.extend(labels(&["printer", "local"]));
    let host_off = rr(&mut p, &pointer(inst_off), rtype::SRV, 0x8001, 120, &srv) + 6;

    rr(&mut p, &pointer(inst_off), rtype::TXT, 0x8001, 4500, b"\x08rp=ipp/p\x05ty=hp");
    rr(&mut p, &pointer(host_off), rtype::A, 0x8001, 120, &[10, 0, 1, 7]);
    p
}

#[test]
fn parses_announcement() {
    let m = Message::parse(&announcement()).unwrap();
    assert!(m.header.response && m.header.authoritative);
    assert_eq!(m.answers.len(), 4);

    assert_eq!(m.answers[0].name, "_http._tcp.local");
    assert_eq!(m.answers[0].data, RData::Ptr("Printer._http._tcp.local".into()));
    assert_eq!(m.answers[0].ttl, 4500);
    assert!(!m.answers[0].cache_flush);

    assert_eq!(m.answers[1].name, "Printer._http._tcp.local");
    assert_eq!(
        m.answers[1].data,
        RData::Srv { priority: 0, weight: 0, port: 631, target: "printer.local".into() }
    );
    assert!(m.answers[1].cache_flush);
    assert_eq!(m.answers[1].class, 1);

    assert_eq!(m.answers[2].data, RData::Txt(vec![b"rp=ipp/p".to_vec(), b"ty=hp".to_vec()]));

    assert_eq!(m.answers[3].name, "printer.local");
    assert_eq!(m.answers[3].data, RData::A(Ipv4Addr::new(10, 0, 1, 7)));
    assert_eq!(m.answers[3].rtype(), rtype::A);
}

#[test]
fn parses_query_with_qu_bit() {
    let mut p = header(0x0000, 1, 0);
    p.extend(labels(&["_services", "_dns-sd", "_udp", "local"]));
    p.extend(rtype::PTR.to_be_bytes());
    p.extend(0x8001u16.to_be_bytes());
    let m = Message::parse(&p).unwrap();
    assert!(!m.header.response);
    assert_eq!(m.questions[0].name, "_services._dns-sd._udp.local");
    assert_eq!(m.questions[0].qtype, rtype::PTR);
    assert!(m.questions[0].unicast_response);
    assert_eq!(m.questions[0].class, 1);
}

#[test]
fn parses_aaaa_and_nsec() {
    let mut p = header(0x8400, 0, 2);
    let v6: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    rr(&mut p, &labels(&["host", "local"]), rtype::AAAA, 1, 120, &v6.octets());
    // NSEC "host.local" covering A (1) and AAAA (28).
    let mut nsec = labels(&["host", "local"]);
    nsec.extend([0, 4, 0x40, 0x00, 0x00, 0x08]);
    rr(&mut p, &labels(&["host", "local"]), rtype::NSEC, 1, 120, &nsec);

    let m = Message::parse(&p).unwrap();
    assert_eq!(m.answers[0].data, RData::Aaaa(v6));
    assert_eq!(
        m.answers[1].data,
        RData::Nsec { next: "host.local".into(), types: vec![1, 28] }
    );
}

#[test]
fn unknown_types_are_kept_raw() {
    let mut p = header(0x8400, 0, 1);
    rr(&mut p, &labels(&["x", "local"]), 13, 1, 10, b"\x01\x02");
    let m = Message::parse(&p).unwrap();
    assert_eq!(m.answers[0].data, RData::Other { rtype: 13, data: vec![1, 2] });
}

#[test]
fn escapes_dots_in_labels() {
    let mut p = header(0x8400, 0, 1);
    rr(&mut p, &labels(&["TV. Room", "_x", "local"]), rtype::TXT, 1, 10, b"");
    let m = Message::parse(&p).unwrap();
    assert_eq!(m.answers[0].name, "TV\\. Room._x.local");
    assert_eq!(split_instance(&m.answers[0].name), Some(("TV\\. Room", "_x.local")));
    assert_eq!(split_instance("nolabels"), None);
}

#[test]
fn rejects_pointer_loop() {
    let mut p = header(0x0000, 1, 0);
    p.extend([1, b'a', 0xc0, 12]); // label, then pointer back to itself
    p.extend([0, 1, 0, 1]);
    assert_eq!(Message::parse(&p), Err(ParseError::NameTooLong));
}

#[test]
fn rejects_forward_pointer() {
    let mut p = header(0x0000, 1, 0);
    p.extend([0xc0, 0xff, 0, 1, 0, 1]);
    assert_eq!(Message::parse(&p), Err(ParseError::BadPointer));
}

#[test]
fn rejects_bad_rdata_length() {
    let mut p = header(0x8400, 0, 1);
    rr(&mut p, &labels(&["x", "local"]), rtype::A, 1, 10, &[1, 2, 3]);
    assert_eq!(Message::parse(&p), Err(ParseError::BadRdata("A")));
}

/// An AAAA record of any length but 16, or an NSEC whose type bitmap is
/// empty, too long or runs over its record, is malformed.
#[test]
fn rejects_malformed_aaaa_and_nsec_data() {
    let parse = |rtype: u16, rdata: &[u8]| {
        let mut p = header(0x8400, 0, 1);
        rr(&mut p, &labels(&["x", "local"]), rtype, 1, 10, rdata);
        Message::parse(&p)
    };
    assert_eq!(parse(rtype::AAAA, &[0; 4]), Err(ParseError::BadRdata("AAAA")));
    assert_eq!(parse(rtype::AAAA, &[0; 17]), Err(ParseError::BadRdata("AAAA")));
    assert!(parse(rtype::AAAA, &[0; 16]).is_ok());

    let next = labels(&["x", "local"]);
    let nsec = |bitmap: &[u8]| [next.as_slice(), bitmap].concat();
    assert!(parse(rtype::NSEC, &nsec(&[0, 1, 0x40])).is_ok(), "block 0, one byte: A");
    assert_eq!(parse(rtype::NSEC, &nsec(&[0, 0])), Err(ParseError::BadRdata("NSEC")), "empty bitmap");
    let long = [[0u8, 33].as_slice(), &[0; 33]].concat();
    assert_eq!(parse(rtype::NSEC, &nsec(&long)), Err(ParseError::BadRdata("NSEC")), "over 32 bytes");
    assert_eq!(parse(rtype::NSEC, &nsec(&[0, 4, 0x40])), Err(ParseError::BadRdata("NSEC")), "runs over");
}

#[test]
fn huge_counts_do_not_allocate_or_panic() {
    let mut p = header(0x8400, 0xffff, 0xffff);
    p.truncate(12);
    assert_eq!(Message::parse(&p), Err(ParseError::Truncated));
}

#[test]
fn mangled_input_never_panics() {
    let good = announcement();
    for i in 0..good.len() {
        let _ = Message::parse(&good[..i]);
        for b in [0x00, 0x3f, 0xc0, 0xff] {
            let mut bad = good.clone();
            bad[i] = b;
            let _ = Message::parse(&bad);
        }
    }
}

#[test]
fn encode_round_trips() {
    let rec = |name: &str, cache_flush, data| Record {
        name: name.into(),
        class: 1,
        cache_flush,
        ttl: 120,
        data,
    };
    let msg = Message {
        header: Header {
            id: 7,
            response: true,
            opcode: 0,
            authoritative: true,
            truncated: false,
            rcode: 0,
        },
        questions: vec![Question {
            name: "_http._tcp.local".into(),
            qtype: rtype::PTR,
            class: 1,
            unicast_response: true,
        }],
        answers: vec![
            rec("_http._tcp.local", false, RData::Ptr("TV\\. Room._http._tcp.local".into())),
            rec(
                "TV\\. Room._http._tcp.local",
                true,
                RData::Srv { priority: 1, weight: 2, port: 80, target: "tv.local".into() },
            ),
            rec("TV\\. Room._http._tcp.local", true, RData::Txt(vec![b"a=b".to_vec(), b"c".to_vec()])),
        ],
        authorities: vec![],
        additionals: vec![
            rec("tv.local", true, RData::A(Ipv4Addr::new(10, 0, 1, 7))),
            rec("tv.local", true, RData::Aaaa("fd00::7".parse().unwrap())),
            rec(
                "tv.local",
                true,
                RData::Nsec { next: "tv.local".into(), types: vec![1, 28, 300] },
            ),
            rec("x.local", false, RData::Other { rtype: 99, data: vec![1, 2, 3] }),
        ],
    };
    assert_eq!(Message::parse(&msg.encode().unwrap()).unwrap(), msg);
}

/// `bytes` parsed and serialized again says the same: it parses to the
/// same message, and serializes to the same bytes, which are not the same
/// as `bytes` where it had names compressed.
fn round_trip(what: &str, bytes: &[u8]) {
    let message = Message::parse(bytes).unwrap_or_else(|e| panic!("{what}: {e}"));
    let out = message.encode().unwrap_or_else(|e| panic!("{what}: {e}"));
    let again = Message::parse(&out).unwrap_or_else(|e| panic!("{what}: serialized, {e}"));
    assert_eq!(again, message, "{what}: serialized, it says the same");
    assert_eq!(again.encode().unwrap(), out, "{what}: and serializes the same");
}

/// A packet with something in every section and in the header.
fn every_section() -> Vec<u8> {
    let mut p = header(0x8600 | 3, 1, 1); // a response, authoritative, truncated, rcode 3
    p[8..10].copy_from_slice(&1u16.to_be_bytes());
    p[10..12].copy_from_slice(&2u16.to_be_bytes());
    p.extend(labels(&["_http", "_tcp", "local"]));
    p.extend(rtype::PTR.to_be_bytes());
    p.extend(0x8001u16.to_be_bytes());
    let mut ptr_data = vec![2];
    ptr_data.extend(b"tv");
    ptr_data.extend(pointer(12));
    rr(&mut p, &pointer(12), rtype::PTR, 1, 4500, &ptr_data);
    let mut srv = vec![0, 1, 0, 2, 0x1f, 0x90];
    srv.extend(labels(&["tv", "local"]));
    rr(&mut p, &labels(&["tv", "_http", "_tcp", "local"]), rtype::SRV, 0x8001, 120, &srv);
    rr(&mut p, &labels(&["tv", "local"]), rtype::A, 0x8001, 120, &[10, 0, 1, 7]);
    rr(&mut p, &labels(&["tv", "local"]), rtype::AAAA, 0x8001, 120, &"fd00::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
    p
}

#[test]
fn a_packet_that_is_parsed_and_serialized_again_says_the_same() {
    let mut query = header(0x0000, 1, 0);
    query.extend(labels(&["_services", "_dns-sd", "_udp", "local"]));
    query.extend(rtype::PTR.to_be_bytes());
    query.extend(0x8001u16.to_be_bytes());

    let mut address = header(0x8400, 0, 2);
    rr(&mut address, &labels(&["host", "local"]), rtype::AAAA, 1, 120, &"fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    let mut nsec = labels(&["host", "local"]);
    nsec.extend([0, 4, 0x40, 0x00, 0x00, 0x08, 1, 1, 0x80]); // A and AAAA, and a type of block 1
    rr(&mut address, &labels(&["host", "local"]), rtype::NSEC, 1, 120, &nsec);

    let mut raw = header(0x8400, 0, 1);
    rr(&mut raw, &labels(&["x", "local"]), 13, 1, 10, b"\x01\x02");

    let mut dotted = header(0x8400, 0, 2);
    rr(&mut dotted, &labels(&["TV. Room", "_x", "local"]), rtype::TXT, 1, 10, b"");
    rr(&mut dotted, &labels(&["back\\slash", "local"]), rtype::TXT, 1, 10, b"\x03a=b");

    let mut goodbye = header(0x8400, 0, 1);
    rr(&mut goodbye, &labels(&["tv", "local"]), rtype::A, 0x8001, 0, &[10, 0, 1, 7]);

    for (what, bytes) in [
        ("an announcement with compressed names", announcement()),
        ("a query of the unicast kind", query),
        ("addresses and the types a name has", address),
        ("a record of a type it does not know", raw),
        ("names with a dot and a backslash in a label", dotted),
        ("a goodbye", goodbye),
        ("every section, and the header", every_section()),
    ] {
        round_trip(what, &bytes);
    }
}

/// What the header and the sections say is what comes out, not just that it
/// parses again: the unicast and cache-flush bits, the TTL, the sections
/// of a record, and what the header says.
#[test]
fn what_a_packet_says_is_what_is_serialized() {
    let message = Message::parse(&every_section()).unwrap();
    let again = Message::parse(&message.encode().unwrap()).unwrap();
    assert_eq!(
        (again.header.id, again.header.response, again.header.authoritative, again.header.truncated, again.header.rcode),
        (0x1234, true, true, true, 3)
    );
    assert_eq!((again.questions.len(), again.answers.len(), again.authorities.len(), again.additionals.len()), (1, 1, 1, 2));
    assert!(again.questions[0].unicast_response);
    assert_eq!((again.answers[0].name.as_str(), again.authorities[0].name.as_str()), ("_http._tcp.local", "tv._http._tcp.local"));
    assert!(again.additionals.iter().all(|r| r.cache_flush && r.ttl == 120));
}

/// An empty TXT record is none, whether it is written as no data or as the
/// single empty string that DNS-SD writes it as, and is written the latter
/// way.
#[test]
fn an_empty_txt_record_is_one_however_it_is_written() {
    for rdata in [&b""[..], b"\x00"] {
        let mut p = header(0x8400, 0, 1);
        rr(&mut p, &labels(&["tv", "_x", "local"]), rtype::TXT, 1, 10, rdata);
        let message = Message::parse(&p).unwrap();
        assert_eq!(message.answers[0].data, RData::Txt(vec![]));
        let out = message.encode().unwrap();
        assert_eq!(&out[out.len() - 3..], [0, 1, 0], "one empty string, of length 1");
        round_trip("an empty TXT record", &p);
    }
}

/// Whatever the parser makes of a packet, however mangled, can be
/// serialized, and comes back the same.
#[test]
fn what_the_parser_makes_of_a_mangled_packet_can_be_serialized_again() {
    let mut parsed = 0;
    for good in [announcement(), every_section()] {
        let mut candidates = vec![good.clone()];
        for i in 0..good.len() {
            candidates.push(good[..i].to_vec());
            for b in [0x00, 0x01, 0x3f, 0x41, 0x7f, 0xc0, 0xff] {
                let mut bad = good.clone();
                bad[i] = b;
                candidates.push(bad);
            }
        }
        for (n, bytes) in candidates.iter().enumerate() {
            if Message::parse(bytes).is_ok() {
                parsed += 1;
                round_trip(&format!("mangled packet {n}"), bytes);
            }
        }
    }
    assert!(parsed > 100, "{parsed} of them parsed: enough to mean something");
}

#[test]
fn reverse_names_round_trip() {
    let v4: IpAddr = "10.0.1.9".parse().unwrap();
    assert_eq!(reverse_name(v4), "9.1.0.10.in-addr.arpa");
    let v6: IpAddr = "fd00:0:1::5".parse().unwrap();
    assert_eq!(
        reverse_name(v6),
        "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"
    );
    for addr in [v4, v6, "2001:db8:abcd:12::fe".parse().unwrap()] {
        assert_eq!(reverse_addr(&reverse_name(addr)), Some(addr));
        assert_eq!(reverse_addr(&reverse_name(addr).to_ascii_uppercase()), Some(addr), "case does not matter");
    }
    for not in ["tv.local", "1.0.10.in-addr.arpa", "256.1.0.10.in-addr.arpa", "x.ip6.arpa", "10.in-addr.arpa.local"] {
        assert_eq!(reverse_addr(not), None, "{not}");
    }
    // An IPv6 name of other than 32 single hex digits.
    let v6_name = reverse_name(v6);
    let short = v6_name.strip_prefix("5.").unwrap();
    let long = format!("0.{v6_name}");
    // 32 labels still, but one of two digits.
    let wide = v6_name.replacen("5.", "05.", 1);
    for not in [short, &long, &wide, "ip6.arpa"] {
        assert_eq!(reverse_addr(not), None, "{not}");
    }
}

#[test]
fn encode_rejects_bad_names() {
    let with_name = |name: &str| Message {
        header: Header { id: 0, response: true, opcode: 0, authoritative: false, truncated: false, rcode: 0 },
        questions: vec![],
        answers: vec![Record { name: name.into(), class: 1, cache_flush: false, ttl: 0, data: RData::A(Ipv4Addr::LOCALHOST) }],
        authorities: vec![],
        additionals: vec![],
    };
    assert_eq!(with_name("a..b").encode(), Err(EncodeError::EmptyLabel));
    assert_eq!(with_name(&"x".repeat(64)).encode(), Err(EncodeError::LabelTooLong));
    assert_eq!(with_name(&vec!["x".repeat(60); 5].join(".")).encode(), Err(EncodeError::NameTooLong));
    assert!(with_name("fine.local.").encode().is_ok());
}
