//! DNS wire-format parser (RFC 1035) with the mDNS (RFC 6762) twists: the top
//! bit of a question's class is "unicast response wanted", and the top bit of
//! a record's class is "cache flush".
//!
//! Names are returned as dot-joined strings without a trailing dot (the root
//! is the empty string). A literal `.` or `\` inside a label is escaped with a
//! backslash, so DNS-SD instance names like `Living Room. TV` stay one label;
//! use [`split_instance`] to take the first label off a name.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod rtype {
    pub const A: u16 = 1;
    pub const PTR: u16 = 12;
    pub const TXT: u16 = 16;
    pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33;
    pub const NSEC: u16 = 47;
    pub const ANY: u16 = 255;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The message ended before a field did.
    Truncated,
    /// A label length byte used the reserved 0b01/0b10 prefixes.
    BadLabel(u8),
    /// A compression pointer did not point strictly backwards.
    BadPointer,
    /// A name exceeded 255 bytes on the wire (this also catches pointer loops).
    NameTooLong,
    /// Record data did not match its declared length or type layout.
    BadRdata(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated => write!(f, "message truncated"),
            ParseError::BadLabel(b) => write!(f, "invalid label length byte {b:#04x}"),
            ParseError::BadPointer => write!(f, "invalid compression pointer"),
            ParseError::NameTooLong => write!(f, "name too long"),
            ParseError::BadRdata(what) => write!(f, "malformed {what} record data"),
        }
    }
}

impl std::error::Error for ParseError {}

pub type Result<T> = std::result::Result<T, ParseError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    /// QR bit: true for a response, false for a query.
    pub response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub rcode: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
    /// The QU bit: the asker would accept a unicast reply.
    pub unicast_response: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// The raw character-strings; DNS-SD interprets them as `key=value`.
    Txt(Vec<Vec<u8>>),
    Nsec {
        next: String,
        types: Vec<u16>,
    },
    Other {
        rtype: u16,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub class: u16,
    /// The cache-flush bit: this record replaces any cached set of its name and type.
    pub cache_flush: bool,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Message {
    pub fn parse(buf: &[u8]) -> Result<Message> {
        let mut r = Reader { buf, pos: 0 };
        let id = r.u16()?;
        let flags = r.u16()?;
        let (qd, an, ns, ar) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);

        let header = Header {
            id,
            response: flags & 0x8000 != 0,
            opcode: ((flags >> 11) & 0xf) as u8,
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            rcode: (flags & 0xf) as u8,
        };

        // Counts come from the wire, so never pre-allocate from them.
        let questions = (0..qd).map(|_| r.question()).collect::<Result<Vec<_>>>()?;
        let answers = r.records(an)?;
        let authorities = r.records(ns)?;
        let additionals = r.records(ar)?;

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Answers, authorities and additionals, in wire order.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
    }
}

impl Record {
    pub fn rtype(&self) -> u16 {
        match &self.data {
            RData::A(_) => rtype::A,
            RData::Aaaa(_) => rtype::AAAA,
            RData::Ptr(_) => rtype::PTR,
            RData::Srv { .. } => rtype::SRV,
            RData::Txt(_) => rtype::TXT,
            RData::Nsec { .. } => rtype::NSEC,
            RData::Other { rtype, .. } => *rtype,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    EmptyLabel,
    LabelTooLong,
    NameTooLong,
    /// A TXT character-string over 255 bytes.
    StringTooLong,
    /// Too many records, or record data over 65535 bytes.
    TooLarge,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EncodeError::EmptyLabel => "empty label in name",
            EncodeError::LabelTooLong => "label longer than 63 bytes",
            EncodeError::NameTooLong => "name longer than 255 bytes",
            EncodeError::StringTooLong => "TXT string longer than 255 bytes",
            EncodeError::TooLarge => "message section too large",
        })
    }
}

impl std::error::Error for EncodeError {}

impl Message {
    /// Serialize to wire format. Names are written uncompressed.
    pub fn encode(&self) -> std::result::Result<Vec<u8>, EncodeError> {
        let h = &self.header;
        let flags = (h.response as u16) << 15
            | ((h.opcode & 0xf) as u16) << 11
            | (h.authoritative as u16) << 10
            | (h.truncated as u16) << 9
            | (h.rcode & 0xf) as u16;
        let count = |n: usize| u16::try_from(n).map_err(|_| EncodeError::TooLarge);

        let mut out = Vec::new();
        out.extend(h.id.to_be_bytes());
        out.extend(flags.to_be_bytes());
        out.extend(count(self.questions.len())?.to_be_bytes());
        out.extend(count(self.answers.len())?.to_be_bytes());
        out.extend(count(self.authorities.len())?.to_be_bytes());
        out.extend(count(self.additionals.len())?.to_be_bytes());

        for q in &self.questions {
            put_name(&mut out, &q.name)?;
            out.extend(q.qtype.to_be_bytes());
            out.extend((q.class & 0x7fff | (q.unicast_response as u16) << 15).to_be_bytes());
        }
        for rec in self.records() {
            put_record(&mut out, rec)?;
        }
        Ok(out)
    }
}

/// Inverse of the escaping done when parsing: split on unescaped dots.
fn name_labels(name: &str) -> std::result::Result<Vec<Vec<u8>>, EncodeError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Ok(Vec::new());
    }
    let mut labels = vec![String::new()];
    let mut escaped = false;
    for c in name.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            '.' if !escaped => labels.push(String::new()),
            _ => {
                escaped = false;
                labels.last_mut().unwrap().push(c);
            }
        }
    }
    labels
        .into_iter()
        .map(|l| match l.len() {
            0 => Err(EncodeError::EmptyLabel),
            1..=63 => Ok(l.into_bytes()),
            _ => Err(EncodeError::LabelTooLong),
        })
        .collect()
}

fn put_name(out: &mut Vec<u8>, name: &str) -> std::result::Result<(), EncodeError> {
    let labels = name_labels(name)?;
    if labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1 > 255 {
        return Err(EncodeError::NameTooLong);
    }
    for l in labels {
        out.push(l.len() as u8);
        out.extend(l);
    }
    out.push(0);
    Ok(())
}

fn put_record(out: &mut Vec<u8>, rec: &Record) -> std::result::Result<(), EncodeError> {
    put_name(out, &rec.name)?;
    out.extend(rec.rtype().to_be_bytes());
    out.extend((rec.class & 0x7fff | (rec.cache_flush as u16) << 15).to_be_bytes());
    out.extend(rec.ttl.to_be_bytes());

    let len_at = out.len();
    out.extend([0, 0]);
    match &rec.data {
        RData::A(a) => out.extend(a.octets()),
        RData::Aaaa(a) => out.extend(a.octets()),
        RData::Ptr(name) => put_name(out, name)?,
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            out.extend(priority.to_be_bytes());
            out.extend(weight.to_be_bytes());
            out.extend(port.to_be_bytes());
            put_name(out, target)?;
        }
        RData::Txt(strings) => {
            // RFC 6763: an empty TXT record is a single zero-length string.
            if strings.is_empty() {
                out.push(0);
            }
            for s in strings {
                out.push(u8::try_from(s.len()).map_err(|_| EncodeError::StringTooLong)?);
                out.extend(s);
            }
        }
        RData::Nsec { next, types } => {
            put_name(out, next)?;
            let mut blocks: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
            for t in types {
                let bitmap = blocks.entry((t >> 8) as u8).or_default();
                let idx = (t & 0xff) as usize;
                bitmap[idx / 8] |= 0x80 >> (idx % 8);
            }
            for (block, bitmap) in blocks {
                let len = bitmap.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                out.push(block);
                out.push(len as u8);
                out.extend(&bitmap[..len]);
            }
        }
        RData::Other { data, .. } => out.extend(data),
    }

    let rdlen = u16::try_from(out.len() - len_at - 2).map_err(|_| EncodeError::TooLarge)?;
    out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
    Ok(())
}

/// Split the first label off a name, honouring `\.` escapes:
/// `"My Printer._ipp._tcp.local"` becomes `("My Printer", "_ipp._tcp.local")`.
pub fn split_instance(name: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (i, c) in name.char_indices() {
        match c {
            '\\' if !escaped => escaped = true,
            '.' if !escaped => return Some((&name[..i], &name[i + 1..])),
            _ => escaped = false,
        }
    }
    None
}

/// The reverse-mapping name of `addr`: `9.1.0.10.in-addr.arpa` for 10.0.1.9,
/// and the 32 nibbles of an IPv6 address, last first, under `ip6.arpa`.
pub fn reverse_name(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(a) => {
            let [a, b, c, d] = a.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(a) => {
            let nibbles: Vec<String> =
                a.octets().iter().rev().flat_map(|b| [b & 0xf, b >> 4]).map(|n| format!("{n:x}")).collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

/// The address a reverse-mapping name is of, if it is one: the inverse of
/// [`reverse_name`], ignoring case.
pub fn reverse_addr(name: &str) -> Option<IpAddr> {
    let lower = name.to_ascii_lowercase();
    if let Some(rest) = lower.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = rest.split('.').map(|l| l.parse().ok()).collect::<Option<_>>()?;
        let [d, c, b, a] = octets[..] else { return None };
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }
    let rest = lower.strip_suffix(".ip6.arpa")?;
    let nibbles: Vec<u8> = rest
        .split('.')
        .map(|l| match l.as_bytes() {
            [c] => (*c as char).to_digit(16).map(|n| n as u8),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if nibbles.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, pair) in nibbles.rchunks(2).enumerate() {
        octets[i] = pair[1] << 4 | pair[0];
    }
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Result<String> {
        let mut out = String::new();
        let mut cursor = self.pos;
        let mut resume = None;
        let mut wire_len = 0usize;

        loop {
            let len = *self.buf.get(cursor).ok_or(ParseError::Truncated)?;
            match len & 0xc0 {
                0x00 => {
                    cursor += 1;
                    if len == 0 {
                        break;
                    }
                    let len = len as usize;
                    let label = self
                        .buf
                        .get(cursor..cursor + len)
                        .ok_or(ParseError::Truncated)?;
                    cursor += len;

                    // Every cycle in a pointer chain must contain a label,
                    // so this limit also bounds the loop.
                    wire_len += len + 1;
                    if wire_len > 254 {
                        return Err(ParseError::NameTooLong);
                    }

                    if !out.is_empty() {
                        out.push('.');
                    }
                    for c in String::from_utf8_lossy(label).chars() {
                        if c == '.' || c == '\\' {
                            out.push('\\');
                        }
                        out.push(c);
                    }
                }
                0xc0 => {
                    let low = *self.buf.get(cursor + 1).ok_or(ParseError::Truncated)?;
                    let target = (((len & 0x3f) as usize) << 8) | low as usize;
                    resume.get_or_insert(cursor + 2);
                    if target >= cursor {
                        return Err(ParseError::BadPointer);
                    }
                    cursor = target;
                }
                _ => return Err(ParseError::BadLabel(len)),
            }
        }

        self.pos = resume.unwrap_or(cursor);
        Ok(out)
    }

    fn question(&mut self) -> Result<Question> {
        let name = self.name()?;
        let qtype = self.u16()?;
        let class = self.u16()?;
        Ok(Question {
            name,
            qtype,
            class: class & 0x7fff,
            unicast_response: class & 0x8000 != 0,
        })
    }

    fn records(&mut self, count: u16) -> Result<Vec<Record>> {
        (0..count).map(|_| self.record()).collect()
    }

    fn record(&mut self) -> Result<Record> {
        let name = self.name()?;
        let rtype = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let rdlen = self.u16()? as usize;
        let end = self.pos.checked_add(rdlen).ok_or(ParseError::Truncated)?;
        if end > self.buf.len() {
            return Err(ParseError::Truncated);
        }

        let data = self.rdata(rtype, end)?;
        if self.pos != end {
            return Err(ParseError::BadRdata("length mismatch in"));
        }

        Ok(Record {
            name,
            class: class & 0x7fff,
            cache_flush: class & 0x8000 != 0,
            ttl,
            data,
        })
    }

    fn rdata(&mut self, rtype: u16, end: usize) -> Result<RData> {
        let remaining = end - self.pos;
        Ok(match rtype {
            rtype::A => {
                if remaining != 4 {
                    return Err(ParseError::BadRdata("A"));
                }
                let b = self.bytes(4)?;
                RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            rtype::AAAA => {
                if remaining != 16 {
                    return Err(ParseError::BadRdata("AAAA"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(self.bytes(16)?);
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            rtype::PTR => RData::Ptr(self.name()?),
            rtype::SRV => RData::Srv {
                priority: self.u16()?,
                weight: self.u16()?,
                port: self.u16()?,
                target: self.name()?,
            },
            rtype::TXT => {
                let mut strings = Vec::new();
                while self.pos < end {
                    let len = self.u8()? as usize;
                    if self.pos + len > end {
                        return Err(ParseError::BadRdata("TXT"));
                    }
                    strings.push(self.bytes(len)?.to_vec());
                }
                RData::Txt(strings)
            }
            rtype::NSEC => {
                let next = self.name()?;
                let mut types = Vec::new();
                while self.pos < end {
                    let block = self.u8()? as u16;
                    let len = self.u8()? as usize;
                    if len == 0 || len > 32 || self.pos + len > end {
                        return Err(ParseError::BadRdata("NSEC"));
                    }
                    for (i, byte) in self.bytes(len)?.iter().enumerate() {
                        for bit in 0..8 {
                            if byte & (0x80 >> bit) != 0 {
                                types.push(block * 256 + (i as u16) * 8 + bit);
                            }
                        }
                    }
                }
                RData::Nsec { next, types }
            }
            _ => RData::Other {
                rtype,
                data: self.bytes(remaining)?.to_vec(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
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
}
