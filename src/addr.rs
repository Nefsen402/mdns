//! The kinds of address the layers above all speak of: the family of one,
//! whether it is only good on its own link, and the network an interface has.
//! Nothing here depends on anything else of the daemon.

use core::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

/// The family of `addr`.
pub fn family_of(addr: IpAddr) -> Family {
    if addr.is_ipv4() { Family::V4 } else { Family::V6 }
}

/// Link-local: IPv6 `fe80::/10` and IPv4 `169.254.0.0/16`. Valid on one link
/// only, so never to be handed to another network.
pub fn is_link_local(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// A network an interface is on: an address of the interface, and the length
/// of the prefix that makes the network of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl Prefix {
    /// Whether `ip` is in this network.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let bits = |a: &IpAddr| match a {
            IpAddr::V4(a) => (u128::from(a.to_bits()) << 96, 32),
            IpAddr::V6(a) => (a.to_bits(), 128),
        };
        let ((net, width), (ip, other)) = (bits(&self.addr), bits(ip));
        if width != other {
            return false;
        }
        let len = u32::from(self.len).min(width);
        let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
        net & mask == ip & mask
    }
}

/// The network written as `addr/len`, for tests.
#[cfg(test)]
pub fn prefix(net: &str) -> Prefix {
    let (addr, len) = net.split_once('/').unwrap();
    Prefix { addr: addr.parse().unwrap(), len: len.parse().unwrap() }
}

#[cfg(test)]
#[path = "../tests/unit/addr.rs"]
mod tests;
