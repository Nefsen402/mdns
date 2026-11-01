//! Per-interface mDNS sockets.
//!
//! Each socket is pinned to a single interface and bound to the mDNS
//! multicast group address rather than the wildcard, so it shows up in
//! `ss` as `224.0.0.251%wifi:5353` and only ever sees that link's traffic.

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;

use anyhow::{anyhow, bail, Context, Result};
use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};

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
    pub interface: String,
    pub index: u32,
    pub family: Family,
    pub socket: Socket,
}

impl MdnsSocket {
    /// A second handle on this socket for sending, plus the group address
    /// (scoped to this interface for IPv6) to send to. It keeps the source
    /// port at 5353 and the socket's interface binding.
    pub fn sender(&self) -> Result<(UdpSocket, SocketAddr)> {
        let dest = match self.family {
            Family::V4 => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
            Family::V6 => SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, self.index)),
        };
        Ok((self.socket.try_clone()?.into(), dest))
    }

}

/// The address this host uses on `interface` for `family`: the source
/// address the kernel picks for traffic to the mDNS group there, which is the
/// primary IPv4 address and, for IPv6, the link-local address. Nothing is
/// sent.
pub fn local_addr(interface: &str, family: Family) -> Result<IpAddr> {
    let index = ifindex(interface)?;
    let (domain, group) = match family {
        Family::V4 => (Domain::IPV4, SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT))),
        Family::V6 => (Domain::IPV6, SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, index))),
    };
    // A throwaway socket: connecting UDP only makes the kernel choose a
    // source address, which `local_addr` then reveals.
    let probe = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    probe.bind_device(Some(interface.as_bytes()))?;
    probe.connect(&group.into()).with_context(|| format!("finding the address used on {interface}"))?;
    probe
        .local_addr()?
        .as_socket()
        .map(|a| a.ip())
        .ok_or_else(|| anyhow!("no local address on {interface}"))
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
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills in `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(std::io::Error::last_os_error()).context("listing the interfaces' addresses");
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
        if unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_bytes() != name.as_bytes() {
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
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= req.ifr_name.len() || bytes.contains(&0) {
        bail!("not an interface name: {name:?}");
    }
    for (dst, &b) in req.ifr_name.iter_mut().zip(bytes) {
        *dst = b as libc::c_char;
    }
    // Any socket will do for the ioctl; it is closed when `sock` drops.
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    // SAFETY: `req` is a valid ifreq naming the interface; SIOCGIFMTU fills
    // in its MTU.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU, &mut req) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("reading the MTU of {name}"));
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
    let domain = match family {
        Family::V4 => Domain::IPV4,
        Family::V6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Share port 5353 with avahi (and anything else) during migration.
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind_device(Some(interface.as_bytes()))?;

    // Without this, the kernel delivers group traffic from *any* interface
    // joined by *any* socket on the host, defeating the per-link isolation.
    match family {
        Family::V4 => set_int(&socket, libc::IPPROTO_IP, libc::IP_MULTICAST_ALL, 0)?,
        Family::V6 => {
            socket.set_only_v6(true)?;
            set_int(&socket, libc::IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)?;
        }
    }

    match family {
        Family::V4 => {
            socket.set_multicast_loop_v4(false)?;
            socket.set_multicast_ttl_v4(255)?;
            socket.bind(&SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)).into())?;
            socket.join_multicast_v4_n(&GROUP_V4, &InterfaceIndexOrAddress::Index(index))?;
        }
        Family::V6 => {
            socket.set_multicast_loop_v6(false)?;
            socket.set_multicast_hops_v6(255)?;
            socket.bind(
                &SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, index)).into(),
            )?;
            socket.join_multicast_v6(&GROUP_V6, index)?;
        }
    }

    Ok(MdnsSocket {
        interface: interface.to_string(),
        index,
        family,
        socket,
    })
}

fn set_int(socket: &Socket, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> Result<()> {
    // SAFETY: the fd is valid for the lifetime of `socket`, and we pass a
    // pointer to a c_int along with its exact size.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
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
