//! What the kernel says about interfaces coming and going, by rtnetlink.
//!
//! A socket bound to an interface stops hearing anything when the interface
//! is deleted and created again (a VLAN reconfigured, hostapd restarted): it
//! stays bound to the old index, and its group memberships went with it. So
//! the daemon listens for link and address changes, and acts on those to the
//! interfaces it serves. Only the few fields it needs are read.
//!
//! Linux has netlink, and FreeBSD (14 and 15) a netlink of the same messages, so
//! the same code reads them: only the socket is made another way. FreeBSD says
//! of ARP what its routing socket does not, which is why it is netlink there too.
//! Elsewhere [`Netlink`] hears of nothing, and what reads the messages, with the
//! constants of their format, is not used.
#![cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code, unused_imports))]

use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustix::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use rustix::io::Errno;

use crate::runtime::{errno, Why};

use crate::prelude::*;

/// A change to an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The interface called `name` is there, with `index`, and is up (and
    /// running) or not, with its MTU if the kernel said. Sent when it appears
    /// and whenever it changes.
    Link { index: u32, name: String, up: bool, mtu: Option<u32> },
    /// The interface with `index` is gone.
    Gone { index: u32 },
    /// An address of the interface with `index` was added or removed.
    Address { index: u32 },
    /// The neighbour table of the interface with `index` has `ip` at
    /// link-layer address `mac`, or with `None`, no longer (the entry went,
    /// or the neighbour could not be reached).
    Neighbour { index: u32, ip: IpAddr, mac: Option<Vec<u8>> },
    /// Changes were lost (the kernel's queue ran over): what is there has to
    /// be looked at afresh.
    Lost,
}

// rtnetlink, from <linux/rtnetlink.h> and <linux/if.h>.
#[cfg(target_os = "linux")]
const RTMGRP_LINK: u32 = 0x1;
#[cfg(target_os = "linux")]
const RTMGRP_NEIGH: u32 = 0x4;
#[cfg(target_os = "linux")]
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
#[cfg(target_os = "linux")]
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
/// The states of a neighbour entry whose link-layer address can be used:
/// reachable, stale, delay, probe and permanent.
const NUD_USABLE: u16 = 0x02 | 0x04 | 0x08 | 0x10 | 0x80;
/// FreeBSD's netlink, from <netlink/netlink.h> and <netlink/netlink_route.h>: its
/// address family, the level of its options, the one that joins a group, and the
/// groups.
#[cfg(target_os = "freebsd")]
const AF_NETLINK: libc::c_int = 38;
#[cfg(target_os = "freebsd")]
const NETLINK_ROUTE: libc::c_int = 0;
#[cfg(target_os = "freebsd")]
const SOL_NETLINK: libc::c_int = 270;
#[cfg(target_os = "freebsd")]
const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;
#[cfg(target_os = "freebsd")]
const RTNLGRP_LINK: libc::c_int = 1;
#[cfg(target_os = "freebsd")]
const RTNLGRP_NEIGH: libc::c_int = 3;
#[cfg(target_os = "freebsd")]
const RTNLGRP_IPV4_IFADDR: libc::c_int = 5;
#[cfg(target_os = "freebsd")]
const RTNLGRP_IPV6_IFADDR: libc::c_int = 9;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;

/// The sizes of a message header, of the link and address messages that
/// follow it, and of an attribute header.
const NLMSG_HDRLEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const NDMSG_LEN: usize = 12;
const RTA_HDRLEN: usize = 4;

/// A socket that hears of link and address changes.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub struct Netlink {
    fd: OwnedFd,
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
impl Netlink {
    #[cfg(target_os = "linux")]
    pub fn open() -> Result<Netlink, Why> {
        // SAFETY: plain socket creation; the result is checked.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(Why(errno()));
        }
        // SAFETY: `fd` was just created and is owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero sockaddr_nl is valid; the fields set are its own.
        let mut addr: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_NEIGH;
        // SAFETY: `addr` is a valid sockaddr_nl of the size given.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Why(errno()));
        }
        Ok(Netlink { fd })
    }

    /// FreeBSD's netlink is not bound to the groups it wants, but joined to
    /// them one by one.
    #[cfg(target_os = "freebsd")]
    pub fn open() -> Result<Netlink, Why> {
        // SAFETY: plain socket creation; the result is checked.
        let fd = unsafe { libc::socket(AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(Why(errno()));
        }
        // SAFETY: `fd` was just created and is owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        for group in [RTNLGRP_LINK, RTNLGRP_NEIGH, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR] {
            // SAFETY: the option is an int, of which `group` is one.
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    SOL_NETLINK,
                    NETLINK_ADD_MEMBERSHIP,
                    (&group as *const libc::c_int).cast(),
                    core::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(Why(errno()));
            }
        }
        Ok(Netlink { fd })
    }

    /// Ask the kernel for every entry of every interface's neighbour table:
    /// they come as [`Change::Neighbour`]s among the next changes. For what
    /// was there before the daemon started, or before changes were lost.
    pub fn request_neighbours(&self) -> Result<(), Why> {
        let mut msg = Vec::with_capacity(NLMSG_HDRLEN + NDMSG_LEN);
        msg.extend(((NLMSG_HDRLEN + NDMSG_LEN) as u32).to_ne_bytes());
        msg.extend(RTM_GETNEIGH.to_ne_bytes());
        msg.extend((NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        msg.extend(1u32.to_ne_bytes()); // sequence
        msg.extend(0u32.to_ne_bytes()); // port: the kernel fills it in
        msg.extend([0u8; NDMSG_LEN]); // every family, every interface
        self.send_to_kernel(&msg)
    }

    #[cfg(target_os = "linux")]
    fn send_to_kernel(&self, msg: &[u8]) -> Result<(), Why> {
        // SAFETY: an all-zero sockaddr_nl is the kernel's address.
        let mut kernel: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: `msg` is readable for its length, and `kernel` is a valid
        // sockaddr_nl of the size given.
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n < 0 { Err(Why(errno())) } else { Ok(()) }
    }

    /// What is sent on FreeBSD's netlink socket is for the kernel: it needs no address.
    #[cfg(target_os = "freebsd")]
    fn send_to_kernel(&self, msg: &[u8]) -> Result<(), Why> {
        // SAFETY: `msg` is readable for its length.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if n < 0 { Err(Why(errno())) } else { Ok(()) }
    }

    /// The descriptor to wait on: readable when there are changes.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// The changes the kernel has reported since last asked, without
    /// waiting: none if there are none yet.
    pub fn changes(&self) -> Result<Vec<Change>, Why> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut changes = Vec::new();
        loop {
            // SAFETY: `buf` is writable for its whole length.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if n >= 0 {
                changes.extend(parse(&buf[..n as usize]));
                continue;
            }
            match errno() {
                Errno::INTR => continue,
                Errno::AGAIN => return Ok(changes),
                Errno::NOBUFS => changes.push(Change::Lost),
                e => return Err(Why(e)),
            }
        }
    }
}

/// Where there is no netlink, nothing is heard of links, addresses or
/// neighbours coming and going: interfaces are those there when the daemon
/// starts, and what the neighbour table knows of the devices is not learned.
/// The routing socket of the other BSDs says the same things in another way,
/// which this does not read yet.
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub struct Netlink;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
impl Netlink {
    pub fn open() -> Result<Netlink, Why> {
        Ok(Netlink)
    }

    pub fn request_neighbours(&self) -> Result<(), Why> {
        Ok(())
    }

    /// No descriptor: waiting on a negative one waits for nothing.
    pub fn fd(&self) -> RawFd {
        -1
    }

    pub fn changes(&self) -> Result<Vec<Change>, Why> {
        Ok(Vec::new())
    }
}

/// The changes in one datagram of rtnetlink messages. What cannot be read is
/// skipped.
pub fn parse(buf: &[u8]) -> Vec<Change> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + NLMSG_HDRLEN <= buf.len() {
        let len = u32_at(buf, at) as usize;
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            break;
        }
        let kind = u16_at(buf, at + 4);
        let body = &buf[at + NLMSG_HDRLEN..at + len];
        match kind {
            RTM_NEWLINK | RTM_DELLINK if body.len() >= IFINFOMSG_LEN => {
                let index = u32_at(body, 4);
                if kind == RTM_DELLINK {
                    out.push(Change::Gone { index });
                } else if let (Some(name), mtu) = link_attrs(&body[IFINFOMSG_LEN..]) {
                    let flags = u32_at(body, 8);
                    let up = flags & (IFF_UP | IFF_RUNNING) == IFF_UP | IFF_RUNNING;
                    out.push(Change::Link { index, name, up, mtu });
                }
            }
            RTM_NEWADDR | RTM_DELADDR if body.len() >= IFADDRMSG_LEN => {
                out.push(Change::Address { index: u32_at(body, 4) });
            }
            RTM_NEWNEIGH | RTM_DELNEIGH if body.len() >= NDMSG_LEN => {
                let index = u32_at(body, 4);
                let state = u16_at(body, 8);
                let (ip, mac) = neighbour_attrs(&body[NDMSG_LEN..]);
                if let Some(ip) = ip {
                    let usable = kind == RTM_NEWNEIGH && state & NUD_USABLE != 0;
                    out.push(Change::Neighbour { index, ip, mac: mac.filter(|_| usable) });
                }
            }
            _ => {}
        }
        at += align(len);
    }
    out
}

/// The interface name and MTU among a link message's attributes. No name if
/// an attribute runs over the end, as nothing after it can be trusted.
fn link_attrs(mut attrs: &[u8]) -> (Option<String>, Option<u32>) {
    let (mut name, mut mtu) = (None, None);
    while attrs.len() >= RTA_HDRLEN {
        let len = u16_at(attrs, 0) as usize;
        if len < RTA_HDRLEN || len > attrs.len() {
            return (None, None);
        }
        let data = &attrs[RTA_HDRLEN..len];
        match u16_at(attrs, 2) {
            IFLA_IFNAME => {
                let bytes = data.split(|&b| b == 0).next().unwrap_or_default();
                name = String::from_utf8(bytes.to_vec()).ok();
            }
            IFLA_MTU if data.len() >= 4 => mtu = Some(u32_at(data, 0)),
            _ => {}
        }
        attrs = attrs.get(align(len)..).unwrap_or_default();
    }
    (name, mtu)
}

/// The address and link-layer address among a neighbour message's
/// attributes. Nothing if an attribute runs over the end.
fn neighbour_attrs(mut attrs: &[u8]) -> (Option<IpAddr>, Option<Vec<u8>>) {
    let (mut ip, mut mac) = (None, None);
    while attrs.len() >= RTA_HDRLEN {
        let len = u16_at(attrs, 0) as usize;
        if len < RTA_HDRLEN || len > attrs.len() {
            return (None, None);
        }
        let data = &attrs[RTA_HDRLEN..len];
        match (u16_at(attrs, 2), data.len()) {
            (NDA_DST, 4) => ip = Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (NDA_DST, 16) => ip = Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).expect("16 bytes")))),
            (NDA_LLADDR, 1..) => mac = Some(data.to_vec()),
            _ => {}
        }
        attrs = attrs.get(align(len)..).unwrap_or_default();
    }
    (ip, mac)
}

/// Netlink lengths are padded to four bytes.
fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([buf[at], buf[at + 1]])
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message of `kind` with `body`, as the kernel lays it out.
    fn message(kind: u16, body: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + body.len();
        let mut out = Vec::new();
        out.extend((len as u32).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend([0u8; 10]);
        out.extend(body);
        out.resize(align(out.len()), 0);
        out
    }

    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(((RTA_HDRLEN + data.len()) as u16).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend(data);
        out.resize(align(out.len()), 0);
        out
    }

    fn link(kind: u16, index: u32, flags: u32, name: &str) -> Vec<u8> {
        let mut body = vec![0u8; 4];
        body.extend(index.to_ne_bytes());
        body.extend(flags.to_ne_bytes());
        body.extend(0u32.to_ne_bytes());
        // The MTU first, as the kernel sends many before the name.
        body.extend(attr(IFLA_MTU, &1500u32.to_ne_bytes()));
        body.extend(attr(IFLA_IFNAME, format!("{name}\0").as_bytes()));
        message(kind, &body)
    }

    fn address(kind: u16, index: u32) -> Vec<u8> {
        let mut body = vec![10, 24, 0, 0];
        body.extend(index.to_ne_bytes());
        message(kind, &body)
    }

    #[test]
    fn reads_links_coming_going_and_their_addresses() {
        let mut buf = link(RTM_NEWLINK, 7, IFF_UP | IFF_RUNNING, "mdns-a");
        buf.extend(link(RTM_NEWLINK, 8, IFF_UP, "wifi"));
        buf.extend(address(RTM_NEWADDR, 7));
        buf.extend(address(RTM_DELADDR, 8));
        buf.extend(link(RTM_DELLINK, 7, 0, "mdns-a"));
        assert_eq!(parse(&buf), [
            Change::Link { index: 7, name: "mdns-a".into(), up: true, mtu: Some(1500) },
            Change::Link { index: 8, name: "wifi".into(), up: false, mtu: Some(1500) },
            Change::Address { index: 7 },
            Change::Address { index: 8 },
            Change::Gone { index: 7 },
        ]);
    }

    /// A link message without an MTU, or with one too short to read, says
    /// nothing of it.
    #[test]
    fn a_link_without_an_mtu_says_none() {
        let named = |extra: Vec<u8>| {
            let mut body = vec![0u8; 4];
            body.extend(9u32.to_ne_bytes());
            body.extend((IFF_UP | IFF_RUNNING).to_ne_bytes());
            body.extend(0u32.to_ne_bytes());
            body.extend(extra);
            body.extend(attr(IFLA_IFNAME, b"wifi\0"));
            parse(&message(RTM_NEWLINK, &body))
        };
        assert_eq!(named(vec![]), [Change::Link { index: 9, name: "wifi".into(), up: true, mtu: None }]);
        assert_eq!(named(attr(IFLA_MTU, &[1, 2])), [Change::Link { index: 9, name: "wifi".into(), up: true, mtu: None }]);
        assert_eq!(named(attr(IFLA_MTU, &9000u32.to_ne_bytes())), [Change::Link { index: 9, name: "wifi".into(), up: true, mtu: Some(9000) }]);
    }

    fn neighbour(kind: u16, index: u32, state: u16, ip: &[u8], mac: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![if ip.len() == 4 { 2 } else { 10 }, 0, 0, 0];
        body.extend(index.to_ne_bytes());
        body.extend(state.to_ne_bytes());
        body.extend([0u8, 1]); // flags, type
        body.extend(attr(NDA_DST, ip));
        if let Some(mac) = mac {
            body.extend(attr(NDA_LLADDR, mac));
        }
        message(kind, &body)
    }

    /// A neighbour entry that can be used gives its link-layer address; one
    /// that went, failed or is still being resolved, none.
    #[test]
    fn reads_neighbour_entries() {
        let mac = [0x04, 0x09, 0x86, 0x43, 0xe3, 0xf6];
        let v6: IpAddr = "fd00:0:2::73".parse().unwrap();
        let v6_octets = match v6 { IpAddr::V6(a) => a.octets(), _ => unreachable!() };
        let mut buf = neighbour(RTM_NEWNEIGH, 5, 0x02, &v6_octets, Some(&mac)); // reachable
        buf.extend(neighbour(RTM_NEWNEIGH, 5, 0x04, &[10, 0, 2, 73], Some(&mac))); // stale
        buf.extend(neighbour(RTM_NEWNEIGH, 5, 0x20, &[10, 0, 2, 74], Some(&mac))); // failed
        buf.extend(neighbour(RTM_NEWNEIGH, 5, 0x01, &[10, 0, 2, 75], None)); // incomplete
        buf.extend(neighbour(RTM_DELNEIGH, 5, 0x04, &v6_octets, Some(&mac)));
        let mac = Some(mac.to_vec());
        assert_eq!(parse(&buf), [
            Change::Neighbour { index: 5, ip: v6, mac: mac.clone() },
            Change::Neighbour { index: 5, ip: "10.0.2.73".parse().unwrap(), mac },
            Change::Neighbour { index: 5, ip: "10.0.2.74".parse().unwrap(), mac: None },
            Change::Neighbour { index: 5, ip: "10.0.2.75".parse().unwrap(), mac: None },
            Change::Neighbour { index: 5, ip: v6, mac: None },
        ]);
        // Without an address, or with one of another length, it says nothing.
        assert!(parse(&neighbour(RTM_NEWNEIGH, 5, 0x02, &[1, 2, 3], None)).is_empty());
    }

    #[test]
    fn what_cannot_be_read_is_skipped() {
        assert!(parse(&[]).is_empty());
        assert!(parse(&[1, 2, 3]).is_empty());
        // A length past the end stops the reading, and what came before stands.
        let mut buf = address(RTM_NEWADDR, 3);
        let mut broken = link(RTM_NEWLINK, 4, 0, "x");
        broken[0] = 0xff;
        buf.extend(broken);
        assert_eq!(parse(&buf), [Change::Address { index: 3 }]);
        // A link without a name, or with an attribute running over, is skipped.
        let mut nameless = vec![0u8; 4];
        nameless.extend(5u32.to_ne_bytes());
        nameless.extend([0u8; 8]);
        nameless.extend([0xff, 0x00, 0x03, 0x00]);
        assert!(parse(&message(RTM_NEWLINK, &nameless)).is_empty());
        // Other kinds of message are none of its business.
        assert!(parse(&message(2, &[0u8; 20])).is_empty());
    }

    /// Manual check against the real kernel: needs nothing but a network
    /// namespace to change, `unshare -rn cargo test netlink_live -- --ignored`.
    #[test]
    #[ignore]
    fn netlink_live() {
        let netlink = Netlink::open().unwrap();
        std::process::Command::new("ip").args(["link", "add", "nl-test", "type", "dummy"]).status().unwrap();
        let changes = netlink.changes().unwrap();
        assert!(changes.iter().any(|c| matches!(c, Change::Link { name, .. } if name == "nl-test")), "{changes:?}");
    }
}
