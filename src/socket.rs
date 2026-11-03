//! Per-interface mDNS sockets.
//!
//! On Linux each socket is pinned to a single interface and bound to the mDNS
//! multicast group address rather than the wildcard, so it shows up in
//! `ss` as `224.0.0.251%wifi:5353` and only ever sees that link's traffic. If
//! what is sent to the daemon itself is to be heard too (`on` in `[Listen]`) it
//! is bound to the wildcard address instead, `0.0.0.0%wifi:5353`: pinned to the
//! interface still, and joined to the group on it alone.
//!
//! The BSDs cannot pin a socket to an interface. There is one socket for each
//! family, shared by every interface, bound to the wildcard address and joined
//! to the group on each interface as it is opened. It asks the system which
//! interface each datagram came in on, and the [`Hub`] that owns it says which
//! interface that is, to hand the datagram to; what came in on another is
//! dropped. Sending says which interface it goes out of, each time. The cargo
//! feature `portable-sockets` makes Linux do the same, to test it.

use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{bail, Context, Result};
use rustix::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use rustix::io::Errno;
use rustix::net::{sockopt, AddressFamily, SocketFlags, SocketType};

use crate::runtime::{errno, Why};


pub const MDNS_PORT: u16 = 5353;
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
pub struct MdnsSocket {
    pub index: u32,
    pub family: Family,
    pub socket: OwnedFd,
}

#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
impl MdnsSocket {
    /// A second handle on this socket for sending, plus the group address
    /// (scoped to this interface for IPv6) to send to. It keeps the source
    /// port at 5353 and the socket's interface binding.
    pub fn sender(&self) -> Result<(Sender, SocketAddr)> {
        Ok((Sender::from(rustix::io::fcntl_dupfd_cloexec(&self.socket, 0).map_err(Why)?), group_of(self.family, self.index)))
    }
}

/// What a segment sends with: a socket, and, where one socket is shared by
/// every interface, the interface a datagram is to go out of.
pub struct Sender {
    fd: OwnedFd,
    /// The index of the interface, and its first IPv4 address, if the socket is
    /// not pinned to it.
    out: Option<(u32, Option<Ipv4Addr>)>,
}

impl From<OwnedFd> for Sender {
    fn from(fd: OwnedFd) -> Sender {
        Sender { fd, out: None }
    }
}

impl Sender {
    /// Send `bytes` to `dest`, out of the interface this is for. All sending is
    /// done here, one at a time, so what is said of the interface to a socket
    /// others send with is still what it is when the datagram goes.
    pub fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> core::result::Result<(), Errno> {
        if let Some((index, v4)) = self.out {
            match (dest, v4) {
                (SocketAddr::V4(_), Some(addr)) => sockopt::set_ip_multicast_if(&self.fd, &addr)?,
                (SocketAddr::V6(_), _) => sockopt::set_ipv6_multicast_if(&self.fd, index)?,
                (SocketAddr::V4(_), None) => {}
            }
        }
        rustix::net::sendto(&self.fd, bytes, rustix::net::SendFlags::empty(), &dest).map(drop)
    }
}

/// The group to send to on the interface with `index`: scoped to it for IPv6.
fn group_of(family: Family, index: u32) -> SocketAddr {
    match family {
        Family::V4 => SocketAddr::V4(SocketAddrV4::new(GROUP_V4, MDNS_PORT)),
        Family::V6 => SocketAddr::V6(SocketAddrV6::new(GROUP_V6, MDNS_PORT, 0, index)),
    }
}

/// A datagram a socket has heard.
pub struct Datagram {
    pub len: usize,
    /// Who sent it, if it is from an IP address.
    pub from: Option<SocketAddr>,
    /// The interface it came in on, where the socket cannot say by being
    /// pinned to one: the [`Hub`] hands it to that interface's link.
    #[cfg_attr(all(target_os = "linux", not(feature = "portable-sockets")), allow(dead_code))]
    pub arrived_on: Option<u32>,
    /// The address it was sent to, where the socket is bound to the wildcard
    /// and so hears what is sent to others: the group, or the daemon itself.
    #[cfg_attr(all(target_os = "linux", not(feature = "portable-sockets")), allow(dead_code))]
    pub to: Option<IpAddr>,
}

/// Whether sockets are pinned to their interface, as only Linux does.
#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
mod pinned {
    use super::*;

    // Not exported by the libc crate on all versions (Linux >= 4.20).
    const IPV6_MULTICAST_ALL: libc::c_int = 29;

    /// A socket pinned to `interface` over `family`: bound to the group, or, if
    /// `unicast`, to the wildcard address, which hears what is sent to the
    /// daemon itself too.
    pub fn open(interface: &str, family: Family, unicast: bool) -> Result<MdnsSocket> {
        let index = ifindex(interface)?;
        let socket = udp(family)?;
        let fd = &socket;

        // Share port 5353 with avahi (and anything else) during migration.
        sockopt::set_socket_reuseaddr(fd, true).map_err(Why)?;
        sockopt::set_socket_reuseport(fd, true).map_err(Why)?;
        bind_device(fd, interface)?;

        // A socket that hears the daemon itself is told what each datagram was sent to,
        // for the sender to be checked of those that were not to the group.
        if unicast {
            match family {
                Family::V4 => set_int(fd, libc::IPPROTO_IP, IP_ARRIVAL, 1)?,
                Family::V6 => set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?,
            }
        }

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
                let addr = if unicast { Ipv4Addr::UNSPECIFIED } else { GROUP_V4 };
                rustix::net::bind(fd, &SocketAddrV4::new(addr, MDNS_PORT)).map_err(Why)?;
                sockopt::set_ip_add_membership_with_ifindex(fd, &GROUP_V4, &Ipv4Addr::UNSPECIFIED, index).map_err(Why)?;
            }
            Family::V6 => {
                sockopt::set_ipv6_multicast_loop(fd, false).map_err(Why)?;
                sockopt::set_ipv6_multicast_hops(fd, 255).map_err(Why)?;
                let (addr, scope) = if unicast { (Ipv6Addr::UNSPECIFIED, 0) } else { (GROUP_V6, index) };
                rustix::net::bind(fd, &SocketAddrV6::new(addr, MDNS_PORT, 0, scope)).map_err(Why)?;
                sockopt::set_ipv6_add_membership(fd, &GROUP_V6, index).map_err(Why)?;
            }
        }

        Ok(MdnsSocket {
            index,
            family,
            socket,
        })
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
            return Err(Why(errno())).with_context(|| format!("binding to {interface}"));
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
pub use pinned::open;

/// Whether the group can be joined on `interface` over `family` now: a socket
/// of the interface's own is joined by its index, and needs nothing of it.
#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
pub fn joinable(_interface: &str, _family: Family) -> bool {
    true
}

/// Where sockets are pinned to their interface, each hears for itself and
/// there is nothing shared to read.
#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
pub struct Hub;

#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
impl Hub {
    pub fn new(_families: &[Family], _unicast: &[Family]) -> Result<Hub> {
        Ok(Hub)
    }

    pub fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        core::iter::empty()
    }

    pub fn receive(&self, _fd: RawFd, _deliver: impl FnMut(u32, SocketAddr, Option<IpAddr>, &[u8])) {}
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

/// Look at each entry of the list of the interfaces' addresses, as getifaddrs
/// has it, that has a name and an address.
fn each_address(mut f: impl FnMut(&libc::ifaddrs)) -> Result<()> {
    let mut list: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: getifaddrs fills in `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(Why(errno())).context("listing the interfaces' addresses");
    }
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list getifaddrs made, not yet freed.
        let ifa = unsafe { &*at };
        at = ifa.ifa_next;
        if !ifa.ifa_addr.is_null() && !ifa.ifa_name.is_null() {
            f(ifa);
        }
    }
    // SAFETY: the list getifaddrs made, freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(())
}

/// The networks the interface called `name` is on, as its network namespace
/// has them, of either family: its addresses with their prefix lengths.
pub fn prefixes(name: &str) -> Result<Vec<Prefix>> {
    let mut out = Vec::new();
    each_address(|ifa| {
        // SAFETY: a NUL-terminated name, as getifaddrs gives it.
        if ifa.ifa_netmask.is_null() || unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() != name.as_bytes() {
            return;
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
                _ => return,
            }
        };
        out.push(prefix);
    })?;
    Ok(out)
}

/// Every address the interface called `name` has, of `families`, for this host
/// to be reached at on it: see [`ordered`].
pub fn addresses(name: &str, families: &[Family]) -> Result<Vec<IpAddr>> {
    let found: Vec<IpAddr> = prefixes(name)?.into_iter().map(|p| p.addr).collect();
    Ok(ordered(&found, families))
}

/// `found`, of `families`, each once: IPv4 before IPv6 and routable before
/// link-local, so that where there are more than a device keeps, it is the
/// link-local ones that go. A link-local IPv6 address the system writes with
/// its scope in it (the BSDs) is written without.
fn ordered(found: &[IpAddr], families: &[Family]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = found
        .iter()
        .map(|a| match a {
            IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => {
                let mut s = v6.segments();
                s[1] = 0;
                IpAddr::V6(Ipv6Addr::from(s))
            }
            a => *a,
        })
        .filter(|a| !a.is_loopback() && !a.is_unspecified())
        .filter(|a| families.contains(&if a.is_ipv4() { Family::V4 } else { Family::V6 }))
        .collect();
    let link_local = |a: &IpAddr| match a {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    };
    out.sort_by_key(|a| (link_local(a), a.is_ipv6(), *a));
    out.dedup();
    out
}

/// The most a datagram read from an mDNS socket may hold: mDNS's own limit
/// (RFC 6762 section 17).
pub const MAX_DATAGRAM: usize = 9000;

/// The MTU of the interface called `name`, as its network namespace has it.
#[cfg(target_os = "linux")]
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
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU as _, &mut req) } != 0 {
        return Err(Why(errno())).with_context(|| format!("reading the MTU of {name}"));
    }
    // SAFETY: SIOCGIFMTU set the MTU member of the union.
    let mtu = unsafe { req.ifr_ifru.ifru_mtu };
    u32::try_from(mtu).with_context(|| format!("{name} says its MTU is {mtu}"))
}

/// The MTU of the interface called `name`: the BSDs keep it with the link-level
/// entry of the interface in the list of addresses, where Linux is asked.
#[cfg(not(target_os = "linux"))]
pub fn mtu(name: &str) -> Result<u32> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
        bail!("not an interface name: {name:?}");
    }
    let mut found = None;
    each_address(|ifa| {
        // SAFETY: a NUL-terminated name, as getifaddrs gives it.
        let named = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() == name.as_bytes();
        // SAFETY: the address is a sockaddr, which says what it is.
        if named && !ifa.ifa_data.is_null() && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_LINK {
            // SAFETY: the data of a link-level entry is the interface's if_data.
            found = Some(unsafe { (*ifa.ifa_data.cast::<libc::if_data>()).ifi_mtu } as u64);
        }
    })?;
    let mtu = found.with_context(|| format!("reading the MTU of {name}: no such interface"))?;
    u32::try_from(mtu).with_context(|| format!("{name} says its MTU is {mtu}"))
}

/// Everything `sock` has heard, each datagram given to `heard` with who sent
/// it and what it was sent to, for the socket of the interface `interface`.
pub fn drain(sock: impl AsFd, interface: &str, mut heard: impl FnMut(SocketAddr, Option<IpAddr>, &[u8])) {
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        match recv(&sock, &mut buf) {
            // A datagram from an IP address, as on a UDP socket.
            Ok(Datagram { len, from: Some(from), to, .. }) => heard(from, to, &buf[..len]),
            Ok(_) => {}
            Err(Errno::AGAIN) => return,
            Err(Errno::INTR) => {}
            Err(e) => {
                // Reported once (an ICMP error, say), it is cleared.
                eprintln!("{interface}: recv failed: {}", Why(e));
                return;
            }
        }
    }
}

pub fn ifindex(name: &str) -> Result<u32> {
    let cname = CString::new(name).context("interface name contains NUL")?;
    // SAFETY: cname is a valid NUL-terminated string.
    match unsafe { libc::if_nametoindex(cname.as_ptr()) } {
        0 => bail!("no such interface: {name}"),
        idx => Ok(idx),
    }
}

/// The option that has the system say, with each datagram, which interface
/// it came in on (IPv4): `IP_PKTINFO` on Linux, `IP_RECVIF` on the BSDs.
#[cfg(target_os = "linux")]
const IP_ARRIVAL: libc::c_int = libc::IP_PKTINFO;
#[cfg(not(target_os = "linux"))]
const IP_ARRIVAL: libc::c_int = libc::IP_RECVIF;

/// A datagram the socket has, with the interface it came in on and the address it was
/// sent to, where the socket was asked to say (see `IP_ARRIVAL`).
pub fn recv(sock: impl AsFd, buf: &mut [u8]) -> core::result::Result<Datagram, Errno> {
    // Room for the interface of either family, and more.
    let mut control = [0u64; 32];
    // SAFETY: all-zero is valid for a sockaddr_storage and a msghdr.
    let mut name: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    msg.msg_name = (&mut name as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = core::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = core::mem::size_of_val(&control) as _;
    // SAFETY: the descriptor is open, and `msg` points at buffers that live
    // as long as the call, with the lengths it says.
    let len = unsafe { libc::recvmsg(sock.as_fd().as_raw_fd(), &mut msg, 0) };
    if len < 0 {
        return Err(errno());
    }
    let (arrived_on, to) = control_of(&msg);
    Ok(Datagram { len: len as usize, from: socket_addr(&name, msg.msg_namelen), arrived_on, to })
}

/// The address a datagram came from, as the system wrote it.
fn socket_addr(name: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = len as usize;
    // SAFETY: the storage is big enough for either, and the family says
    // which it was filled in as, to as long as `len`.
    unsafe {
        match i32::from(name.ss_family) {
            libc::AF_INET if len >= core::mem::size_of::<libc::sockaddr_in>() => {
                let a = &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(a.sin_port))))
            }
            libc::AF_INET6 if len >= core::mem::size_of::<libc::sockaddr_in6>() => {
                let a = &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
                Some(SocketAddr::V6(SocketAddrV6::new(ip, u16::from_be(a.sin6_port), 0, a.sin6_scope_id)))
            }
            _ => None,
        }
    }
}

/// The interface the datagram came in on, and the address it was sent to,
/// by the control messages that came with it.
fn control_of(msg: &libc::msghdr) -> (Option<u32>, Option<IpAddr>) {
    let (mut index, mut to) = (None, None);
    // SAFETY: the control messages are those the system wrote in the buffer
    // `msg` points at, walked as the macros say.
    unsafe {
        let mut at = libc::CMSG_FIRSTHDR(msg);
        while !at.is_null() {
            let header = &*at;
            let data_len = (header.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
            let data = core::slice::from_raw_parts(libc::CMSG_DATA(at), data_len);
            index = index.or_else(|| arrival::index_of(header.cmsg_level, header.cmsg_type, data));
            to = to.or_else(|| arrival::destination_of(header.cmsg_level, header.cmsg_type, data));
            at = libc::CMSG_NXTHDR(msg, at);
        }
    }
    (index, to)
}

/// Whether sockets are told apart by the interface a datagram came in on: the
/// BSDs, and Linux with `portable-sockets`.
#[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
mod portable {
    use super::*;
    use anyhow::anyhow;

    /// The first IPv4 address of `interface`: what the group is joined by, and
    /// what traffic to it is sent from, where an interface is named by its
    /// address.
    pub(super) fn interface_v4(interface: &str) -> Result<Ipv4Addr> {
        prefixes(interface)?
            .into_iter()
            .find_map(|p| match p.addr {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            })
            .ok_or_else(|| anyhow!("no IPv4 address on {interface}"))
    }

    /// The sockets of the BSDs and of `portable-sockets`: one for each family,
    /// shared by every interface.
    pub struct Hub {
        /// Each with whether what is sent to the daemon itself is heard too, and
        /// not only what is sent to the group.
        sockets: Vec<(Family, bool, OwnedFd)>,
    }

    impl Hub {
        /// The sockets for `families`, bound to the wildcard address and not yet
        /// joined to the group on any interface.
        pub fn new(families: &[Family], unicast: &[Family]) -> Result<Hub> {
            let mut sockets = Vec::new();
            for &family in families {
                let socket = udp(family)?;
                let fd = &socket;
                // Share port 5353 with avahi (and anything else).
                sockopt::set_socket_reuseaddr(fd, true).map_err(Why)?;
                sockopt::set_socket_reuseport(fd, true).map_err(Why)?;
                match family {
                    Family::V4 => {
                        set_int(fd, libc::IPPROTO_IP, IP_ARRIVAL, 1)?;
                        // Where the address it was sent to is not with the interface's.
                        #[cfg(not(target_os = "linux"))]
                        set_int(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, 1)?;
                        sockopt::set_ip_multicast_loop(fd, false).map_err(Why)?;
                        sockopt::set_ip_multicast_ttl(fd, 255).map_err(Why)?;
                        rustix::net::bind(fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)).map_err(Why)?;
                    }
                    Family::V6 => {
                        sockopt::set_ipv6_v6only(fd, true).map_err(Why)?;
                        set_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
                        sockopt::set_ipv6_multicast_loop(fd, false).map_err(Why)?;
                        sockopt::set_ipv6_multicast_hops(fd, 255).map_err(Why)?;
                        rustix::net::bind(fd, &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0)).map_err(Why)?;
                    }
                }
                // Never waited on: the loop reads it when it is readable.
                rustix::io::ioctl_fionbio(fd, true).map_err(Why)?;
                sockets.push((family, unicast.contains(&family), socket));
            }
            Ok(Hub { sockets })
        }

        /// The descriptors to wait on.
        pub fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
            self.sockets.iter().map(|(_, _, s)| s.as_raw_fd())
        }

        fn socket(&self, family: Family) -> Result<&OwnedFd> {
            self.sockets.iter().find(|(f, _, _)| *f == family).map(|(_, _, s)| s).ok_or_else(|| anyhow!("no {family:?} socket"))
        }

        /// Join the group on `interface` over `family`, and give back what to send
        /// out of it with, and the group to send to there.
        pub fn join(&self, interface: &str, family: Family) -> Result<(Sender, SocketAddr)> {
            let index = ifindex(interface)?;
            let socket = self.socket(family)?;
            let v4 = match family {
                Family::V4 => {
                    let addr = interface_v4(interface)?;
                    sockopt::set_ip_add_membership(socket, &GROUP_V4, &addr).map_err(Why)?;
                    Some(addr)
                }
                Family::V6 => {
                    sockopt::set_ipv6_add_membership(socket, &GROUP_V6, index).map_err(Why)?;
                    None
                }
            };
            let fd = rustix::io::fcntl_dupfd_cloexec(socket, 0).map_err(Why)?;
            Ok((Sender { fd, out: Some((index, v4)) }, group_of(family, index)))
        }

        /// Leave the group on `interface`, as it is gone: what is not joined
        /// any more is not heard, though what leaving says is not looked at,
        /// as an interface that is gone has nothing to leave.
        pub fn leave(&self, interface: &str, family: Family) {
            let (Ok(index), Ok(socket)) = (ifindex(interface), self.socket(family)) else { return };
            let _ = match family {
                Family::V4 => match interface_v4(interface) {
                    Ok(addr) => sockopt::set_ip_drop_membership(socket, &GROUP_V4, &addr),
                    Err(_) => return,
                },
                Family::V6 => sockopt::set_ipv6_drop_membership(socket, &GROUP_V6, index),
            };
        }

        /// Everything the socket `fd`, if it is one of these, has heard: each
        /// datagram with the index of the interface it came in on, and who sent
        /// it. What the system does not say the interface of is not given.
        pub fn receive(&self, fd: RawFd, mut deliver: impl FnMut(u32, SocketAddr, Option<IpAddr>, &[u8])) {
            let Some((family, unicast, socket)) = self.sockets.iter().find(|(_, _, s)| s.as_raw_fd() == fd) else { return };
            let group = match family {
                Family::V4 => IpAddr::V4(GROUP_V4),
                Family::V6 => IpAddr::V6(GROUP_V6),
            };
            let mut buf = [0u8; MAX_DATAGRAM];
            loop {
                match recv(socket, &mut buf) {
                    Ok(Datagram { len, from: Some(from), arrived_on: Some(index), to }) => {
                        // To the group is what is heard; to the daemon itself only if asked
                        // to; to any other group, or to what the system does not say, not.
                        let wanted = match to {
                            Some(to) if to == group => true,
                            Some(to) if to.is_multicast() => false,
                            Some(_) => *unicast,
                            None => false,
                        };
                        if wanted {
                            deliver(index, from, to, &buf[..len]);
                        }
                    }
                    Ok(_) => {}
                    Err(Errno::AGAIN) => return,
                    Err(Errno::INTR) => {}
                    Err(e) => {
                        // Reported once (an ICMP error, say), it is cleared.
                        eprintln!("recv failed: {}", Why(e));
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
pub use portable::Hub;

/// Whether the group can be joined on `interface` over `family` now: the shared
/// sockets join it over IPv4 by an address of the interface, which one that has
/// only come up, as one does that is yet to be given its address by DHCP, has
/// not. Over IPv6 it is joined by the interface's index, and needs no address.
#[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
pub fn joinable(interface: &str, family: Family) -> bool {
    family == Family::V6 || portable::interface_v4(interface).is_ok()
}

/// Reading the control message that says which interface a datagram came in
/// on. Pure, so it is tested with the bytes of each system's, which can all be
/// had here.
mod arrival {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// The interface a control message of `level` and `kind` says a datagram
    /// came in on, if it is one that does.
    pub fn index_of(level: libc::c_int, kind: libc::c_int, data: &[u8]) -> Option<u32> {
        match (level, kind) {
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => from_in6_pktinfo(data),
            #[cfg(target_os = "linux")]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => from_in_pktinfo(data),
            #[cfg(not(target_os = "linux"))]
            (libc::IPPROTO_IP, libc::IP_RECVIF) => from_sockaddr_dl(data),
            _ => None,
        }
    }

    /// The address a control message of `level` and `kind` says a datagram was
    /// sent to, if it is one that does.
    pub fn destination_of(level: libc::c_int, kind: libc::c_int, data: &[u8]) -> Option<IpAddr> {
        match (level, kind) {
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data.get(..16)?).ok()?))),
            #[cfg(target_os = "linux")]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => addr_from_in_pktinfo(data),
            #[cfg(not(target_os = "linux"))]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => addr_from_in_addr(data),
            _ => None,
        }
    }

    /// Linux's `struct in_pktinfo`: the interface, then the address it was
    /// routed to, then the one in its header, which is the one it was sent to.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn addr_from_in_pktinfo(data: &[u8]) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data.get(8..12)?).ok()?)))
    }

    /// The BSDs' `IP_RECVDSTADDR`: the address, as a `struct in_addr`.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn addr_from_in_addr(data: &[u8]) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data.get(..4)?).ok()?)))
    }

    /// `struct in6_pktinfo`: the address it was sent to, then the interface.
    pub fn from_in6_pktinfo(data: &[u8]) -> Option<u32> {
        Some(u32::from_ne_bytes(data.get(16..20)?.try_into().ok()?)).filter(|&i| i != 0)
    }

    /// Linux's `struct in_pktinfo`: the interface, then two addresses.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn from_in_pktinfo(data: &[u8]) -> Option<u32> {
        Some(u32::from_ne_bytes(data.get(0..4)?.try_into().ok()?)).filter(|&i| i != 0)
    }

    /// The BSDs' `struct sockaddr_dl`, which `IP_RECVIF` gives: its length and
    /// family, one byte each, then the interface's index.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub fn from_sockaddr_dl(data: &[u8]) -> Option<u32> {
        Some(u32::from(u16::from_ne_bytes(data.get(2..4)?.try_into().ok()?))).filter(|&i| i != 0)
    }
}
/// A UDP socket of `family`, not inherited by programs run from here.
fn udp(family: Family) -> Result<OwnedFd> {
    let domain = match family {
        Family::V4 => AddressFamily::INET,
        Family::V6 => AddressFamily::INET6,
    };
    Ok(rustix::net::socket_with(domain, SocketType::DGRAM, SocketFlags::CLOEXEC, Some(rustix::net::ipproto::UDP)).map_err(Why)?)
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
        return Err(Why(errno()).into());
    }
    Ok(())
}

/// The loopback interface, as it is called here: what tests that need an
/// interface that is there use.
#[cfg(test)]
pub(crate) const LOOPBACK: &str = if cfg!(target_os = "linux") { "lo" } else { "lo0" };

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The interface a datagram came in on is read from what the system says, in
    /// the form each has: the two families', and Linux's and the BSDs' for IPv4.
    #[test]
    fn the_interface_a_datagram_came_in_on_is_read_from_each_systems_control_message() {
        // IPv6, the same everywhere: the address it was sent to, then the interface.
        let mut in6 = [0u8; 20];
        in6[..16].copy_from_slice(&"ff02::fb".parse::<Ipv6Addr>().unwrap().octets());
        in6[16..].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(arrival::from_in6_pktinfo(&in6), Some(7));
        assert_eq!(arrival::from_in6_pktinfo(&in6[..19]), None, "too short");
        assert_eq!(arrival::from_in6_pktinfo(&[0u8; 20]), None, "no interface is not one");

        // Linux's IPv4: the interface, the address it was sent to, the one it was sent from.
        let mut in4 = [0u8; 12];
        in4[..4].copy_from_slice(&5u32.to_ne_bytes());
        in4[4..8].copy_from_slice(&[224, 0, 0, 251]);
        assert_eq!(arrival::from_in_pktinfo(&in4), Some(5));
        assert_eq!(arrival::from_in_pktinfo(&in4[..3]), None);

        // The BSDs' IPv4: a link-level address of a length, a family (AF_LINK is 18 on all of
        // them) and the interface's index, then its name and the rest.
        let mut dl = [0u8; 20];
        dl[0] = 20;
        dl[1] = 18;
        dl[2..4].copy_from_slice(&300u16.to_ne_bytes());
        dl[4] = 3;
        assert_eq!(arrival::from_sockaddr_dl(&dl), Some(300), "an index too big for a byte");
        assert_eq!(arrival::from_sockaddr_dl(&dl[..3]), None);
        assert_eq!(arrival::from_sockaddr_dl(&[0u8; 20]), None);

        // The address it was sent to, in the form of each: IPv6's, Linux's and the BSDs'.
        let group = "224.0.0.251".parse::<Ipv4Addr>().unwrap();
        in4[8..12].copy_from_slice(&group.octets());
        assert_eq!(arrival::addr_from_in_pktinfo(&in4), Some(IpAddr::V4(group)));
        assert_eq!(arrival::addr_from_in_pktinfo(&in4[..11]), None);
        assert_eq!(arrival::addr_from_in_addr(&group.octets()), Some(IpAddr::V4(group)));
        assert_eq!(arrival::addr_from_in_addr(&[224, 0, 0]), None);
        assert_eq!(arrival::destination_of(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6), Some("ff02::fb".parse().unwrap()));
        assert_eq!(arrival::destination_of(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6[..15]), None);
        assert_eq!(arrival::destination_of(libc::IPPROTO_IPV6, -1, &in6), None);

        // Told apart by level and kind: what is not about the interface is not read.
        assert_eq!(arrival::index_of(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6), Some(7));
        assert_eq!(arrival::index_of(libc::IPPROTO_IPV6, -1, &in6), None);
        assert_eq!(arrival::index_of(libc::SOL_SOCKET, libc::IPV6_PKTINFO, &in6), None);
    }

    use super::LOOPBACK;

    #[test]
    fn the_addresses_to_advertise_are_all_of_the_wanted_families_routable_first() {
        let found = [ip("fe80::1"), ip("fd00::2"), ip("10.0.0.9"), ip("127.0.0.1"), ip("169.254.1.1"), ip("10.0.0.5"), ip("2001:db8::3"), ip("10.0.0.9"), ip("fe80:2::7")];
        assert_eq!(
            ordered(&found, &[Family::V4, Family::V6]),
            [ip("10.0.0.5"), ip("10.0.0.9"), ip("2001:db8::3"), ip("fd00::2"), ip("169.254.1.1"), ip("fe80::1"), ip("fe80::7")],
            "each once, routable first, the scope of a link-local taken out, no loopback"
        );
        assert_eq!(ordered(&found, &[Family::V4]), [ip("10.0.0.5"), ip("10.0.0.9"), ip("169.254.1.1")]);
        assert_eq!(ordered(&found, &[]), Vec::<IpAddr>::new());
    }

    #[test]
    fn an_interfaces_mtu_is_read() {
        assert!(mtu(LOOPBACK).unwrap() >= 1280, "every network namespace has a loopback");
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
        let nets = prefixes(LOOPBACK).unwrap();
        assert!(nets.contains(&prefix("127.0.0.1/8")), "{nets:?}");
        assert!(prefixes("no-such-interface").unwrap().is_empty());
    }
}
