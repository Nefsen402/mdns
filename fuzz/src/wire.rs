//! Raw mDNS packets, built byte by byte, so that they can be wrong in ways
//! the daemon's own encoder never is: labels of any bytes and any length,
//! any class, any record type.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const A: u16 = 1;
pub const PTR: u16 = 12;
pub const TXT: u16 = 16;
pub const AAAA: u16 = 28;
pub const SRV: u16 = 33;
pub const IN: u16 = 1;

/// A name as its labels, each of any bytes.
pub type Name = Vec<Vec<u8>>;

/// `s` split on its dots.
pub fn name(s: &str) -> Name {
    s.split('.').map(|l| l.as_bytes().to_vec()).collect()
}

pub enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(Name),
    Srv { port: u16, target: Name },
    Txt(Vec<Vec<u8>>),
}

pub struct Rr {
    pub name: Name,
    pub class: u16,
    pub cache_flush: bool,
    pub ttl: u32,
    pub rdata: Rdata,
}

/// A response: answers, and more records in the additional section.
#[derive(Default)]
pub struct Packet {
    pub answers: Vec<Rr>,
    pub additionals: Vec<Rr>,
}

impl Packet {
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Id 0; a response, authoritative.
        for field in [0u16, 0x8400, 0, self.answers.len() as u16, 0, self.additionals.len() as u16] {
            out.extend(field.to_be_bytes());
        }
        for rr in self.answers.iter().chain(&self.additionals) {
            put_rr(&mut out, rr);
        }
        out
    }
}

fn put_name(out: &mut Vec<u8>, name: &Name) {
    for label in name {
        // A label over 63 bytes turns into the reserved length bits: that
        // is for the caller to want or not.
        out.push(label.len() as u8);
        out.extend(label);
    }
    out.push(0);
}

fn put_rr(out: &mut Vec<u8>, rr: &Rr) {
    put_name(out, &rr.name);
    let rtype = match rr.rdata {
        Rdata::A(_) => A,
        Rdata::Aaaa(_) => AAAA,
        Rdata::Ptr(_) => PTR,
        Rdata::Srv { .. } => SRV,
        Rdata::Txt(_) => TXT,
    };
    out.extend(rtype.to_be_bytes());
    out.extend((rr.class | (rr.cache_flush as u16) << 15).to_be_bytes());
    out.extend(rr.ttl.to_be_bytes());
    let mut data = Vec::new();
    match &rr.rdata {
        Rdata::A(a) => data.extend(a.octets()),
        Rdata::Aaaa(a) => data.extend(a.octets()),
        Rdata::Ptr(n) => put_name(&mut data, n),
        Rdata::Srv { port, target } => {
            data.extend([0, 0, 0, 0]);
            data.extend(port.to_be_bytes());
            put_name(&mut data, target);
        }
        Rdata::Txt(strings) => {
            for s in strings {
                data.push(s.len() as u8);
                data.extend(s);
            }
        }
    }
    out.extend((data.len() as u16).to_be_bytes());
    out.extend(data);
}
