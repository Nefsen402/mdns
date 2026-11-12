//! What an interface hears and says with.
//!
//! A [`Link`] is all that an [`Interface`](crate::interface::Interface) knows of how it is reached: it
//! listens over every family the interface is used over, and what is said goes
//! to everyone on it, which is each family's group or, for a tunnel that cannot
//! carry multicast, each of its peers.
//!
//! Per-interface mDNS sockets.
//!
//! On Linux each socket is pinned to a single interface and bound to the mDNS
//! multicast group address rather than the wildcard, so it shows up in
//! `ss` as `224.0.0.251%wifi:5353` and only ever sees that link's traffic. If
//! what is sent to the daemon itself is to be heard too (`on` in `[Interface]`) it
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

use crate::config;
use crate::runtime::{errno, Why};


pub use crate::config::MDNS_PORT;
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

/// The families `interface` is used over: those of its peers, if it has any,
/// and else those it listens over.
pub fn families(interface: &config::Interface) -> Vec<Family> {
    if interface.peers.is_empty() {
        [(interface.ipv4, Family::V4), (interface.ipv6, Family::V6)]
            .into_iter()
            .filter_map(|(listen, family)| listen.enabled().then_some(family))
            .collect()
    } else {
        [(true, Family::V4), (false, Family::V6)]
            .into_iter()
            .filter_map(|(v4, family)| interface.peers.iter().any(|peer| peer.is_ipv4() == v4).then_some(family))
            .collect()
    }
}

/// The families of `interface` of which what is sent to the daemon itself is
/// heard too: none with peers, which are heard alone.
pub fn unicast(interface: &config::Interface) -> Vec<Family> {
    if !interface.peers.is_empty() {
        return Vec::new();
    }
    [(interface.ipv4, Family::V4), (interface.ipv6, Family::V6)]
        .into_iter()
        .filter_map(|(listen, family)| listen.unicast().then_some(family))
        .collect()
}

/// Whether `interface` takes a datagram sent to `to`, if that is known: what is
/// sent to the group always, and what is sent to the daemon itself only over a
/// family it hears that over. A socket of an interface's own hears no more than
/// that already; the sockets shared by every interface, which hear what any of
/// them does, have to be held to it.
pub fn hears(interface: &config::Interface, to: Option<IpAddr>) -> bool {
    match to {
        Some(to) if !to.is_multicast() => unicast(interface).contains(&family_of(to)),
        _ => true,
    }
}

/// The families of `interface` that it cannot be listened to over yet, as it
/// has no address to join the group by: they are joined when it has one. A
/// peer's is not a group to join, and needs no address of the interface's.
pub fn missing(interface: &config::Interface) -> Vec<Family> {
    families(interface).into_iter().filter(|&family| interface.peers.is_empty() && !joinable(&interface.name, family)).collect()
}

/// What an interface hears and says with, and all that an interface knows of how
/// it is reached: it listens over every family it is used over, and what it
/// says goes to everyone on the link, which is each family's group.
#[derive(Default)]
pub struct Link {
    /// What it hears with, a socket for each family, for the event loop to
    /// read when they are readable. None where one socket for each family is
    /// shared by every interface, which is the hub's.
    listeners: Vec<OwnedFd>,
    outs: Vec<Out>,
    /// The hosts it talks to alone, instead of to the groups: only what they
    /// send is heard.
    peers: Vec<IpAddr>,
}

/// A way to send over one family, to everyone on the link over it.
struct Out {
    family: Family,
    sender: Sender,
    /// Where everyone on the link is over this family: its group.
    to: Vec<SocketAddr>,
    /// Whether a host on the link may be asked directly, at its own address,
    /// and its answer is heard.
    direct: bool,
}

impl Link {
    /// A link that sends over `family` with `sender` to `to`, which asks hosts
    /// directly too: for what is not an interface's own, a test's.
    pub fn to(family: Family, sender: impl Into<Sender>, to: SocketAddr) -> Link {
        Link::default().and(family, sender, to)
    }

    /// A link that talks to the peer at `to` alone, over `family` with `sender`,
    /// and hears only it: for what is not an interface's own, a test's.
    pub fn to_peer(family: Family, sender: impl Into<Sender>, to: SocketAddr) -> Link {
        let mut link = Link { peers: alloc::vec![to.ip()], ..Link::default() };
        link.add(family, sender.into(), alloc::vec![to], false);
        link
    }

    /// This, and over `family` too.
    pub fn and(mut self, family: Family, sender: impl Into<Sender>, to: SocketAddr) -> Link {
        self.add(family, sender.into(), alloc::vec![to], true);
        self
    }

    /// Say over `family` with `sender` to `to`, and ask hosts directly if
    /// `direct`, replacing what there was over the family.
    pub(crate) fn add(&mut self, family: Family, sender: Sender, to: Vec<SocketAddr>, direct: bool) {
        self.outs.retain(|out| out.family != family);
        self.outs.push(Out { family, sender, to, direct });
    }

    /// The hosts it talks to alone, if it does not use the groups.
    pub fn peers(&self) -> &[IpAddr] {
        &self.peers
    }

    /// Whether it talks to peers alone.
    pub fn peered(&self) -> bool {
        !self.peers.is_empty()
    }

    /// Whether `addr` is one of its peers.
    pub fn is_peer(&self, addr: IpAddr) -> bool {
        self.peers.contains(&addr)
    }

    /// Whether it is used over no family: it says nothing, and hears nothing.
    pub fn is_empty(&self) -> bool {
        self.outs.is_empty()
    }

    /// The families it is used over.
    pub fn families(&self) -> Vec<Family> {
        self.outs.iter().map(|out| out.family).collect()
    }

    /// The descriptors it hears with, for the event loop to wait on.
    pub fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.listeners.iter().map(|fd| fd.as_raw_fd())
    }

    /// Everything the socket `fd` has heard, if it is one of its: from whom,
    /// to what address if that is known, and what.
    pub fn drain(&self, fd: RawFd, interface: &str, heard: impl FnMut(SocketAddr, Option<IpAddr>, &[u8])) {
        if let Some(listener) = self.listeners.iter().find(|l| l.as_raw_fd() == fd) {
            drain(listener, interface, heard);
        }
    }

    /// Say `bytes` to everyone on the link, over every family. Every one is
    /// tried; the first error is returned. A no-op if it is used over none.
    pub fn send(&self, bytes: &[u8]) -> Result<()> {
        let mut first_err = None;
        for out in &self.outs {
            for &dest in &out.to {
                if let Err(e) = out.sender.send_to(bytes, dest) {
                    first_err.get_or_insert(anyhow::Error::new(Why(e)).context(format!("sending to {dest}")));
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Answer a host over its `family`: to everyone on the link over it, or,
    /// if it is a legacy resolver, to `to` alone. Over another family if it is
    /// not used over that one. A no-op if it is used over none.
    pub fn reply(&self, family: Family, to: Option<SocketAddr>, bytes: &[u8]) -> Result<()> {
        let Some(out) = self.outs.iter().find(|out| out.family == family).or(self.outs.first()) else {
            return Ok(());
        };
        let dests = to.map(|to| alloc::vec![to]).unwrap_or_else(|| out.to.clone());
        for dest in dests {
            out.sender.send_to(bytes, dest).map_err(Why).with_context(|| format!("sending to {dest}"))?;
        }
        Ok(())
    }

    /// Say `bytes` to the host at `addr` alone, at its mDNS port (RFC 6762
    /// section 5.5), over its family. Whether it was sent. To a link-local
    /// address the kernel has to look up the link-layer address first.
    pub fn ask(&self, addr: IpAddr, bytes: &[u8]) -> bool {
        let Some(out) = self.outs.iter().find(|out| out.family == family_of(addr)) else { return false };
        let dest = match (addr, out.to.first()) {
            (IpAddr::V6(addr), Some(SocketAddr::V6(group))) => SocketAddr::V6(SocketAddrV6::new(addr, MDNS_PORT, 0, group.scope_id())),
            (addr, _) => SocketAddr::new(addr, MDNS_PORT),
        };
        out.sender.send_to(bytes, dest).is_ok()
    }

    /// Whether the host at `addr` is to be asked directly: it is over a family
    /// that hears what is sent to the daemon itself.
    pub fn reaches(&self, addr: IpAddr) -> bool {
        self.outs.iter().any(|out| out.family == family_of(addr) && out.direct)
    }
}

/// The family of `addr`.
fn family_of(addr: IpAddr) -> Family {
    if addr.is_ipv4() { Family::V4 } else { Family::V6 }
}

/// What an interface sends with: a socket, and, where one socket is shared by
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
    pub fn socket(interface: &str, family: Family, unicast: bool) -> Result<(u32, OwnedFd)> {
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

        Ok((index, socket))
    }

    /// A socket pinned to `interface` over `family` that does not join the
    /// group: bound to the wildcard address at `port`, which hears what is
    /// sent to the daemon. Which of what it hears is from a peer is for
    /// whoever reads it to say.
    pub fn peer_socket(interface: &str, family: Family, port: u16) -> Result<(u32, OwnedFd)> {
        let index = ifindex(interface)?;
        let socket = udp(family)?;
        let fd = &socket;
        sockopt::set_socket_reuseaddr(fd, true).map_err(Why)?;
        sockopt::set_socket_reuseport(fd, true).map_err(Why)?;
        bind_device(fd, interface)?;
        match family {
            Family::V4 => rustix::net::bind(fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).map_err(Why)?,
            Family::V6 => {
                sockopt::set_ipv6_v6only(fd, true).map_err(Why)?;
                rustix::net::bind(fd, &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).map_err(Why)?;
            }
        }
        Ok((index, socket))
    }

    /// Pin `fd` to `interface`: it hears and sends nothing elsewhere.
    pub(super) fn bind_device(fd: impl AsFd, interface: &str) -> Result<()> {
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

/// For a manual test on a real interface: the socket of `interface` over
/// `family` that hears what a host on this one sends to the group, and the
/// link that sends from a second handle on it.
#[cfg(all(test, target_os = "linux", not(feature = "portable-sockets")))]
pub(crate) fn looped(interface: &str, family: Family) -> (OwnedFd, Link) {
    let (index, socket) = pinned::socket(interface, family, false).unwrap();
    match family {
        Family::V4 => sockopt::set_ip_multicast_loop(&socket, true).unwrap(),
        Family::V6 => sockopt::set_ipv6_multicast_loop(&socket, true).unwrap(),
    }
    let sender = Sender::from(rustix::io::fcntl_dupfd_cloexec(&socket, 0).unwrap());
    (socket, Link::to(family, sender, group_of(family, index)))
}

#[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
impl Link {
    /// The link of `interface`, with a socket of its own for each family it is
    /// used over, pinned to it, which also hears what is sent to the daemon
    /// itself for those it says so of. It keeps the source port at 5353, and
    /// sends to the group (scoped to the interface for IPv6), or, if it has
    /// peers, to them alone.
    pub fn open(interface: &config::Interface) -> Result<Link> {
        if !interface.peers.is_empty() {
            return Link::open_peers(&interface.name, &interface.peers, interface.peer_port);
        }
        let (name, unicast) = (&interface.name, unicast(interface));
        let mut link = Link::default();
        for family in families(interface) {
            let (index, socket) = pinned::socket(name, family, unicast.contains(&family))
                .with_context(|| format!("opening {family:?} socket on {name}"))?;
            // Never waited on: the loop reads it when it is readable, and a
            // send that cannot go out at once fails, and is tried again.
            rustix::io::ioctl_fionbio(&socket, true).map_err(Why)?;
            let sender = Sender::from(rustix::io::fcntl_dupfd_cloexec(&socket, 0).map_err(Why)?);
            link.add(family, sender, alloc::vec![group_of(family, index)], unicast.contains(&family));
            link.listeners.push(socket);
        }
        Ok(link)
    }

    /// The link of `interface` that talks to `peers` alone, at `port`, with a
    /// socket of its own for each family they are of, pinned to it. It keeps
    /// the source port at `port`, which the peers hear it from.
    fn open_peers(interface: &str, peers: &[IpAddr], port: u16) -> Result<Link> {
        let mut link = Link { peers: peers.to_vec(), ..Link::default() };
        for family in [Family::V4, Family::V6] {
            let of_family: Vec<IpAddr> = peers.iter().copied().filter(|&peer| family_of(peer) == family).collect();
            if of_family.is_empty() {
                continue;
            }
            let (index, socket) = pinned::peer_socket(interface, family, port)
                .with_context(|| format!("opening {family:?} socket on {interface}"))?;
            rustix::io::ioctl_fionbio(&socket, true).map_err(Why)?;
            let sender = Sender::from(rustix::io::fcntl_dupfd_cloexec(&socket, 0).map_err(Why)?);
            // A link-local peer is where it is by the interface.
            let to = of_family
                .into_iter()
                .map(|peer| match peer {
                    IpAddr::V6(v6) if crate::device::is_link_local(&peer) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, index)),
                    peer => SocketAddr::new(peer, port),
                })
                .collect();
            link.add(family, sender, to, false);
            link.listeners.push(socket);
        }
        Ok(link)
    }
}

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

/// Whether the interface called `name` is a loopback one (`lo`, or `lo0` on
/// the BSDs): it says so itself, and so is not taken by its name.
pub fn is_loopback(name: &str) -> bool {
    let mut loopback = false;
    let _ = each_address(|ifa| {
        // SAFETY: a NUL-terminated name, as getifaddrs gives it.
        if unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() == name.as_bytes() {
            loopback |= ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
        }
    });
    loopback
}

/// The names of the interfaces there are.
pub fn interfaces() -> Result<Vec<alloc::string::String>> {
    // SAFETY: if_nameindex gives a list ended by an entry of index zero, or null.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return Err(Why(errno())).context("listing the interfaces");
    }
    let mut names = Vec::new();
    let mut at = list;
    // SAFETY: `at` stays within the list, up to its last entry, which is of index zero
    // and name null; the names are NUL-terminated.
    unsafe {
        while (*at).if_index != 0 && !(*at).if_name.is_null() {
            names.push(CStr::from_ptr((*at).if_name).to_string_lossy().into_owned());
            at = at.add(1);
        }
        libc::if_freenameindex(list);
    }
    Ok(names)
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

        /// The link of `interface`, joined to the group over the families it is
        /// used over and can be now, asking hosts directly over those it hears
        /// what is sent to the daemon itself of.
        pub fn link(&self, interface: &config::Interface) -> Result<Link> {
            if !interface.peers.is_empty() {
                bail!("{}: Peer= needs a socket of the interface's own, which this system cannot make", interface.name);
            }
            let (name, unicast, missing) = (&interface.name, unicast(interface), missing(interface));
            let mut link = Link::default();
            for family in families(interface).into_iter().filter(|family| !missing.contains(family)) {
                let (sender, dest) = self.join(name, family).with_context(|| format!("joining the group over {family:?} on {name}"))?;
                link.add(family, sender, alloc::vec![dest], unicast.contains(&family));
            }
            Ok(link)
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
#[path = "../tests/unit/listener.rs"]
mod tests;
