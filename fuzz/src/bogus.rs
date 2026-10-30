//! Devices that must never be reflected, and the canaries that must.
//!
//! Every bogus device is an otherwise well-formed announcement (an address, a
//! service's PTR, SRV and TXT) with exactly one thing wrong with it, so that
//! a daemon that overlooked it would reflect the device.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::parser::Message;
use crate::wire::{name, Name, Packet, Rdata, Rr, IN};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    /// Packets the parser rejects.
    Unparseable,
    /// Names no device can have: not under `.local`, a dot or a control
    /// character inside a host label, invalid UTF-8, a bad service type, a
    /// class other than IN.
    Name,
    /// Addresses no device can be reached at, and SRV port 0.
    Address,
    /// Well-formed devices, but thousands of them from one sender: only a
    /// few may be reflected.
    Flood,
}

impl Category {
    pub const ALL: [Category; 4] = [Category::Unparseable, Category::Name, Category::Address, Category::Flood];

    pub fn label(self) -> &'static str {
        match self {
            Category::Unparseable => "unparseable",
            Category::Name => "names",
            Category::Address => "addresses",
            Category::Flood => "floods",
        }
    }

    pub fn from_label(s: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.label() == s)
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One bogus packet, and what is wrong with it.
pub struct Bogus {
    pub category: Category,
    pub what: String,
    pub bytes: Vec<u8>,
    /// Sent over IPv6 rather than IPv4.
    pub v6: bool,
}

/// xorshift64*: small, fast, and the same run from the same seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

/// A device, as the records that would announce it.
struct Spec {
    host: Name,
    addr: IpAddr,
    instance: Name,
    kind: Name,
    target: Name,
    port: u16,
    class: u16,
}

const KINDS: [&str; 4] = ["_http._tcp.local", "_ipp._tcp.local", "_airplay._tcp.local", "_smb._tcp.local"];

pub struct Generator {
    rng: Rng,
    /// Every device made gets a number of its own, so names never repeat.
    serial: u64,
}

impl Generator {
    pub fn new(seed: u64) -> Generator {
        Generator { rng: Rng::new(seed), serial: 0 }
    }

    pub fn rng(&mut self) -> &mut Rng {
        &mut self.rng
    }

    /// A well-formed device, numbered, of the family `v6`.
    fn spec(&mut self, prefix: &str, v6: bool) -> Spec {
        self.serial += 1;
        let n = self.serial;
        let host = name(&format!("{prefix}-{n}.local"));
        let kind = self.rng.pick(&KINDS);
        let addr = if v6 {
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, (n >> 16) as u16, n as u16))
        } else {
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 10 + self.rng.below(240) as u8))
        };
        Spec {
            target: host.clone(),
            host,
            addr,
            instance: name(&format!("{prefix} {n}.{kind}")),
            kind: name(kind),
            port: 1 + self.rng.below(65534) as u16,
            class: IN,
        }
    }

    /// The packet announcing `spec`, its records shuffled about.
    fn announce(&mut self, spec: &Spec) -> Packet {
        let ttl = |rng: &mut Rng| rng.pick(&[1, 10, 120, 4500, 86400, u32::MAX >> 1]);
        let address = match spec.addr {
            IpAddr::V4(a) => Rdata::A(a),
            IpAddr::V6(a) => Rdata::Aaaa(a),
        };
        let unique = |name: &Name, ttl, rdata| Rr { name: name.clone(), class: spec.class, cache_flush: true, ttl, rdata };
        let mut records = vec![
            unique(&spec.host, ttl(&mut self.rng), address),
            Rr { name: spec.kind.clone(), class: spec.class, cache_flush: false, ttl: ttl(&mut self.rng), rdata: Rdata::Ptr(spec.instance.clone()) },
            unique(&spec.instance, ttl(&mut self.rng), Rdata::Srv { port: spec.port, target: spec.target.clone() }),
            unique(&spec.instance, ttl(&mut self.rng), Rdata::Txt(vec![b"bogus=1".to_vec()])),
        ];
        for i in (1..records.len()).rev() {
            records.swap(i, self.rng.below(i + 1));
        }
        let mut packet = Packet::default();
        for rr in records {
            if self.rng.chance(25) {
                packet.additionals.push(rr);
            } else {
                packet.answers.push(rr);
            }
        }
        packet
    }

    /// A bogus packet of `category`.
    pub fn bogus(&mut self, category: Category) -> Bogus {
        let v6 = self.rng.chance(30);
        match category {
            Category::Unparseable => self.unparseable(v6),
            Category::Name => self.bad_name(v6),
            Category::Address => self.bad_address(v6),
            Category::Flood => self.flood(v6),
        }
    }

    fn unparseable(&mut self, v6: bool) -> Bogus {
        let spec = self.spec("broken", v6);
        let good = self.announce(&spec).bytes();
        for _ in 0..32 {
            let mut bytes = good.clone();
            let what = self.corrupt(&mut bytes);
            if Message::parse(&bytes).is_err() {
                return Bogus { category: Category::Unparseable, what, bytes, v6 };
            }
        }
        // Too short for a header: that never parses.
        Bogus { category: Category::Unparseable, what: "a packet shorter than a header".into(), bytes: good[..11].to_vec(), v6 }
    }

    /// Break `bytes` in one of the ways a packet can be broken.
    fn corrupt(&mut self, bytes: &mut Vec<u8>) -> String {
        let len = bytes.len();
        match self.rng.below(7) {
            0 => {
                let at = 12 + self.rng.below(len - 12);
                bytes.truncate(at);
                format!("cut short at byte {at}")
            }
            1 => {
                let byte = 0x40 | self.rng.below(0x80) as u8;
                bytes[12] = byte;
                format!("a label length byte of {byte:#04x}, which is reserved")
            }
            2 => {
                bytes[12] = 0xc0;
                bytes[13] = 0x0c;
                "a compression pointer to itself".into()
            }
            3 => {
                bytes[12] = 0xc0 | self.rng.below(0x3f) as u8;
                bytes[13] = 0xff;
                "a compression pointer forward".into()
            }
            4 => {
                let more = 1 + self.rng.below(0xffff) as u16;
                let count = u16::from_be_bytes([bytes[6], bytes[7]]).saturating_add(more);
                bytes[6..8].copy_from_slice(&count.to_be_bytes());
                format!("{count} answers counted, fewer there")
            }
            5 => {
                for _ in 0..1 + self.rng.below(8) {
                    let at = 12 + self.rng.below(len - 12);
                    bytes[at] = self.rng.next() as u8;
                }
                "bytes overwritten at random".into()
            }
            _ => {
                let at = 12 + self.rng.below(len - 12);
                let junk: Vec<u8> = (0..1 + self.rng.below(16)).map(|_| self.rng.next() as u8).collect();
                bytes.splice(at..at, junk);
                format!("junk inserted at byte {at}")
            }
        }
    }

    fn bad_name(&mut self, v6: bool) -> Bogus {
        let mut spec = self.spec("badname", v6);
        let n = self.serial;
        let what = match self.rng.below(10) {
            0 => {
                let tld = self.rng.pick(&["com", "example", "lan", "arpa"]);
                spec.host = name(&format!("badname-{n}.{tld}"));
                spec.target = spec.host.clone();
                format!("a hostname under .{tld}, not .local")
            }
            1 => {
                spec.host = name(&format!("badname-{n}"));
                spec.target = spec.host.clone();
                "a hostname of one label, with no domain".into()
            }
            2 => {
                spec.host = vec![format!("badname.{n}").into_bytes(), b"local".to_vec()];
                spec.target = spec.host.clone();
                "a dot inside a host label".into()
            }
            3 => {
                let c = self.rng.pick(&[0u8, 1, 7, 0x0a, 0x1b, 0x7f, b' ']);
                spec.host = vec![[b"badname".as_slice(), &[c], n.to_string().as_bytes()].concat(), b"local".to_vec()];
                spec.target = spec.host.clone();
                format!("the byte {c:#04x} inside a host label")
            }
            4 => {
                spec.host = vec![[b"badname-\xff\xfe".as_slice(), n.to_string().as_bytes()].concat(), b"local".to_vec()];
                spec.target = spec.host.clone();
                "invalid UTF-8 in a host label".into()
            }
            5 => {
                let kind = self.rng.pick(&["_http._xyz.local", "http._tcp.local", "_http.local", "_._tcp.local", "_http._tcp.com"]);
                spec.kind = name(kind);
                spec.instance = name(&format!("badname {n}.{kind}"));
                format!("a service type of {kind}")
            }
            6 => {
                spec.instance = name(&format!("badname {n}._http._tcp.example.com"));
                spec.kind = name("_http._tcp.example.com");
                "a service instance under example.com".into()
            }
            7 => {
                spec.target = name(&format!("elsewhere-{n}.example.com"));
                "a service pointing at a host not under .local".into()
            }
            8 => {
                spec.host = vec![[b"badname-".as_slice(), &[0xc3], n.to_string().as_bytes()].concat(), b"local".to_vec()];
                spec.target = spec.host.clone();
                "a host label that breaks off midway through a UTF-8 character".into()
            }
            _ => {
                spec.class = self.rng.pick(&[3, 4, 254, 255]);
                format!("records of class {}, not IN", spec.class)
            }
        };
        let bytes = self.announce(&spec).bytes();
        Bogus { category: Category::Name, what, bytes, v6 }
    }

    fn bad_address(&mut self, v6: bool) -> Bogus {
        let mut spec = self.spec("badaddr", v6);
        let what = if self.rng.chance(15) {
            spec.port = 0;
            "a service on port 0".into()
        } else {
            spec.addr = if v6 {
                IpAddr::V6(self.rng.pick(&[
                    Ipv6Addr::UNSPECIFIED,
                    Ipv6Addr::LOCALHOST,
                    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
                    Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 1),
                    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 1, 5).to_ipv6_mapped(),
                ]))
            } else {
                IpAddr::V4(self.rng.pick(&[
                    Ipv4Addr::UNSPECIFIED,
                    Ipv4Addr::BROADCAST,
                    Ipv4Addr::new(0, 1, 2, 3),
                    Ipv4Addr::new(224, 0, 0, 251),
                    Ipv4Addr::new(239, 1, 2, 3),
                    Ipv4Addr::LOCALHOST,
                    Ipv4Addr::new(127, 1, 2, 3),
                    Ipv4Addr::new(169, 254, 1, 2),
                    Ipv4Addr::new(240, 0, 0, 1),
                ]))
            };
            format!("an address of {}", spec.addr)
        };
        let bytes = self.announce(&spec).bytes();
        Bogus { category: Category::Address, what, bytes, v6 }
    }

    fn flood(&mut self, v6: bool) -> Bogus {
        let spec = self.spec("flood", v6);
        let bytes = self.announce(&spec).bytes();
        Bogus { category: Category::Flood, what: "one of many devices from one sender".into(), bytes, v6 }
    }
}

/// The hostname of canary `k`.
pub fn canary_host(k: u64) -> String {
    format!("canary-{k}.local")
}

/// The instance name of canary `k`'s service.
pub fn canary_instance(k: u64) -> String {
    format!("Canary {k}._http._tcp.local")
}

/// Canary `k`'s address, from which it is also sent, as a device announces
/// itself: one of its own, so that no one sender describes many devices.
pub fn canary_addr(k: u64) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 1, 100 + (k % 150) as u8)
}

/// Canary `k`: a well-formed device that must be reflected.
pub fn canary(k: u64) -> Vec<u8> {
    let host = name(&canary_host(k));
    let instance = name(&canary_instance(k));
    let rr = |name: &Name, cache_flush, rdata| Rr { name: name.clone(), class: IN, cache_flush, ttl: 120, rdata };
    let packet = Packet {
        answers: vec![
            rr(&host, true, Rdata::A(canary_addr(k))),
            rr(&name("_http._tcp.local"), false, Rdata::Ptr(instance.clone())),
            rr(&instance, true, Rdata::Srv { port: 8000, target: host.clone() }),
            rr(&instance, true, Rdata::Txt(vec![format!("canary={k}").into_bytes()])),
        ],
        additionals: vec![],
    };
    packet.bytes()
}
