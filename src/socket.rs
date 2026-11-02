//! Per-interface mDNS sockets.
//!
//! Each socket is pinned to a single interface and bound to the mDNS
//! multicast group address rather than the wildcard, so it shows up in
//! `ss` as `224.0.0.251%wifi:5353` and only ever sees that link's traffic.

use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{anyhow, bail, Context, Result};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::net::{sockopt, AddressFamily, SocketFlags, SocketType};

use crate::errno::{self, Why};


pub const MDNS_PORT: u16 = 5353;
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

// Not exported by the libc crate on all versions (Linux >= 4.20).
const IPV6_MULTICAST_ALL: libc::c_int = 29;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

pub struct MdnsSocket {
    pub index: u32,
    pub family: Family,
    pub socket: OwnedFd,
}

impl MdnsSocket {
    /// A second handle on this socket for sending, plus the group address
    /// (scoped to this interface for IPv6) to send to. It keeps the source
    /// port at 5353 and the socket's interface binding.
    pub fn sender(&self) -> Result<(OwnedFd, SocketAddr)> {
        let dest = match self.family {
            Family::V4 => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
            Family::V6 => SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, self.index)),
        };
        Ok((rustix::io::fcntl_dupfd_cloexec(&self.socket, 0).map_err(Why)?, dest))
    }

}

/// The address this host uses on `interface` for `family`: the source
/// address the kernel picks for traffic to the mDNS group there, which is the
/// primary IPv4 address and, for IPv6, the link-local address. Nothing is
/// sent.
pub fn local_addr(interface: &str, family: Family) -> Result<IpAddr> {
    let index = ifindex(interface)?;
    let group = match family {
        Family::V4 => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
        Family::V6 => SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, index)),
    };
    // A throwaway socket: connecting UDP only makes the kernel choose a
    // source address, which getsockname then reveals.
    let probe = udp(family)?;
    bind_device(&probe, interface)?;
    rustix::net::connect(&probe, &group).map_err(Why).with_context(|| format!("finding the address used on {interface}"))?;
    let local = rustix::net::getsockname(&probe).map_err(Why)?;
    SocketAddr::try_from(local).map(|a| a.ip()).map_err(|_| anyhow!("no local address on {interface}"))
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

/// The networks the interface called `name` is on, as its network namespace
/// has them, of either family: its addresses with their prefix lengths.
pub fn prefixes(name: &str) -> Result<Vec<Prefix>> {
    let mut list: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: getifaddrs fills in `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(Why(errno::last())).context("listing the interfaces' addresses");
    }
    let mut out = Vec::new();
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list getifaddrs made, not yet freed.
        let ifa = unsafe { &*at };
        at = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a NUL-terminated name, as getifaddrs gives it.
        if unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() != name.as_bytes() {
            continue;
        }
        // SAFETY: the address and mask are sockaddrs of the family the
        // address says, as getifaddrs gives them.
        let prefix = unsafe {
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let addr = &*ifa.ifa_addr.cast::<libc::sockaddr_in>();
                    let mask = &*ifa.ifa_netmask.cast::<libc::sockaddr_in>();
                    let addr = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                    Prefix { addr: IpAddr::V4(addr), len: u32::from_be(mask.sin_addr.s_addr).count_ones() as u8 }
                }
                libc::AF_INET6 => {
                    let addr = &*ifa.ifa_addr.cast::<libc::sockaddr_in6>();
                    let mask = &*ifa.ifa_netmask.cast::<libc::sockaddr_in6>();
                    let len = mask.sin6_addr.s6_addr.iter().map(|b| b.count_ones()).sum::<u32>() as u8;
                    Prefix { addr: IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)), len }
                }
                _ => continue,
            }
        };
        out.push(prefix);
    }
    // SAFETY: the list getifaddrs made, freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(out)
}


/// The MTU of the interface called `name`, as its network namespace has it.
pub fn mtu(name: &str) -> Result<u32> {
    // SAFETY: an all-zero ifreq is valid: an empty name and a zero union.
    let mut req: libc::ifreq = unsafe { core::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= req.ifr_name.len() || bytes.contains(&0) {
        bail!("not an interface name: {name:?}");
    }
    for (dst, &b) in req.ifr_name.iter_mut().zip(bytes) {
        *dst = b as libc::c_char;
    }
    // Any socket will do for the ioctl; it is closed when `sock` drops.
    let sock = rustix::net::socket_with(AddressFamily::INET, SocketType::DGRAM, SocketFlags::CLOEXEC, None).map_err(Why)?;
    // SAFETY: `req` is a valid ifreq naming the interface; SIOCGIFMTU fills
    // in its MTU.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU, &mut req) } != 0 {
        return Err(Why(errno::last())).with_context(|| format!("reading the MTU of {name}"));
    }
    // SAFETY: SIOCGIFMTU set the MTU member of the union.
    let mtu = unsafe { req.ifr_ifru.ifru_mtu };
    u32::try_from(mtu).with_context(|| format!("{name} says its MTU is {mtu}"))
}

pub fn ifindex(name: &str) -> Result<u32> {
    let cname = CString::new(name).context("interface name contains NUL")?;
    // SAFETY: cname is a valid NUL-terminated string.
    match unsafe { libc::if_nametoindex(cname.as_ptr()) } {
        0 => bail!("no such interface: {name}"),
        idx => Ok(idx),
    }
}

pub fn open(interface: &str, family: Family) -> Result<MdnsSocket> {
    let index = ifindex(interface)?;
    let socket = udp(family)?;
    let fd = &socket;

    // Share port 5353 with avahi (and anything else) during migration.
    sockopt::set_socket_reuseaddr(fd, true).map_err(Why)?;
    sockopt::set_socket_reuseport(fd, true).map_err(Why)?;
    bind_device(fd, interface)?;

    // Without this, the kernel delivers group traffic from *any* interface
    // joined by *any* socket on the host, defeating the per-link isolation.
    match family {
        Family::V4 => set_int(fd, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL, 0)?,
        Family::V6 => {
            sockopt::set_ipv6_v6only(fd, true).map_err(Why)?;
            set_int(fd, libc::IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)?;
        }
    }

    match family {
        Family::V4 => {
            sockopt::set_ip_multicast_loop(fd, false).map_err(Why)?;
            sockopt::set_ip_multicast_ttl(fd, 255).map_err(Why)?;
            rustix::net::bind(fd, &SocketAddrV4::new(GROUP_V4, MDNS_PORT)).map_err(Why)?;
            sockopt::set_ip_add_membership_with_ifindex(fd, &GROUP_V4, &Ipv4Addr::UNSPECIFIED, index).map_err(Why)?;
        }
        Family::V6 => {
            sockopt::set_ipv6_multicast_loop(fd, false).map_err(Why)?;
            sockopt::set_ipv6_multicast_hops(fd, 255).map_err(Why)?;
            rustix::net::bind(fd, &SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, index)).map_err(Why)?;
            sockopt::set_ipv6_add_membership(fd, &GROUP_V6, index).map_err(Why)?;
        }
    }

    Ok(MdnsSocket {
        index,
        family,
        socket,
    })
}

/// A UDP socket of `family`, not inherited by programs run from here.
fn udp(family: Family) -> Result<OwnedFd> {
    let domain = match family {
        Family::V4 => AddressFamily::INET,
        Family::V6 => AddressFamily::INET6,
    };
    Ok(rustix::net::socket_with(domain, SocketType::DGRAM, SocketFlags::CLOEXEC, Some(rustix::net::ipproto::UDP)).map_err(Why)?)
}

/// Pin `fd` to `interface`: it hears and sends nothing elsewhere.
fn bind_device(fd: impl AsFd, interface: &str) -> Result<()> {
    let name = interface.as_bytes();
    // SAFETY: the descriptor is open, and `name` is readable for its length;
    // the kernel takes the name without a NUL.
    let rc = unsafe {
        libc::setsockopt(fd.as_fd().as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr().cast(), name.len() as libc::socklen_t)
    };
    if rc != 0 {
        return Err(Why(errno::last())).with_context(|| format!("binding to {interface}"));
    }
    Ok(())
}

/// An integer socket option rustix has no wrapper for.
fn set_int(fd: impl AsFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> Result<()> {
    // SAFETY: the descriptor is open, and we pass a pointer to a c_int along
    // with its exact size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_fd().as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Why(errno::last()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_interfaces_mtu_is_read() {
        assert!(mtu("lo").unwrap() >= 1280, "every network namespace has a loopback");
        assert!(mtu("no-such-if0").is_err());
        assert!(mtu("a-name-far-too-long-for-one").is_err());
        assert!(mtu("nul\0").is_err());
    }

    #[test]
    fn a_prefix_holds_the_addresses_of_its_network() {
        for (net, inside, outside) in [
            ("10.0.2.1/24", "10.0.2.255", "10.0.3.0"),
            ("10.0.2.1/32", "10.0.2.1", "10.0.2.2"),
            ("10.0.2.1/0", "192.0.2.1", "::1"),
            ("2001:db8:2::1/64", "2001:db8:2::ffff:1", "2001:db8:3::1"),
            ("2001:db8:2::1/128", "2001:db8:2::1", "2001:db8:2::2"),
            ("::/0", "2001:db8::1", "10.0.2.1"),
            ("::a00:201/96", "::a00:2ff", "10.0.2.1"), // the families are not mixed
        ] {
            assert!(prefix(net).contains(&ip(inside)), "{net} holds {inside}");
            assert!(!prefix(net).contains(&ip(outside)), "{net} does not hold {outside}");
        }
    }

    #[test]
    fn the_loopback_interface_is_on_its_network() {
        let nets = prefixes("lo").unwrap();
        assert!(nets.contains(&prefix("127.0.0.1/8")), "{nets:?}");
        assert!(prefixes("no-such-interface").unwrap().is_empty());
    }

    /// Manual check against a real interface: `MDNS_TEST_IFACE=br cargo test
    /// live_local_addr -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_local_addr() {
        let iface = std::env::var("MDNS_TEST_IFACE").unwrap();
        for family in [Family::V4, Family::V6] {
            let addr = local_addr(&iface, family).unwrap();
            println!("{iface} {family:?}: {addr}");
            assert!(!addr.is_loopback() && !addr.is_unspecified());
            assert_eq!(addr.is_ipv4(), family == Family::V4);
        }
    }
}
