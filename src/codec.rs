//! The DNS wire format (RFC 1035), decoded and encoded, with the mDNS (RFC 6762)
//! twists: the top bit of a question's class is "unicast response wanted", and
//! the top bit of a record's class is "cache flush". [`Message::parse`] takes a
//! packet apart into a [`Message`], and [`Message::encode`] makes one from it:
//! everything the daemon sends is made so.
//!
//! Names are returned as dot-joined strings without a trailing dot (the root
//! is the empty string). A literal `.` or `\` inside a label is escaped with a
//! backslash, so DNS-SD instance names like `Living Room. TV` stay one label;
//! use [`split_instance`] to take the first label off a name.

use alloc::collections::BTreeMap;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

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

impl core::error::Error for ParseError {}

pub type Result<T> = core::result::Result<T, ParseError>;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

impl core::error::Error for EncodeError {}

impl Message {
    /// Serialize to wire format. Names are written uncompressed.
    pub fn encode(&self) -> core::result::Result<Vec<u8>, EncodeError> {
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
fn name_labels(name: &str) -> core::result::Result<Vec<Vec<u8>>, EncodeError> {
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

fn put_name(out: &mut Vec<u8>, name: &str) -> core::result::Result<(), EncodeError> {
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

fn put_record(out: &mut Vec<u8>, rec: &Record) -> core::result::Result<(), EncodeError> {
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
                // A single empty string is how an empty record is written
                // (RFC 6763 section 6.1), so it is what none is, as the
                // encoder writes it.
                if strings.len() == 1 && strings[0].is_empty() {
                    strings.clear();
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
#[path = "../tests/unit/codec.rs"]
mod tests;
