//! What the kernel says about interfaces coming and going, by rtnetlink.
//!
//! A socket bound to an interface stops hearing anything when the interface
//! is deleted and created again (a VLAN reconfigured, hostapd restarted): it
//! stays bound to the old index, and its group memberships went with it. So
//! the daemon listens for link and address changes, and acts on those to the
//! interfaces it serves. Only the few fields it needs are read.
//!
//! What the kernel says is not what the rest of the daemon is told. A
//! [`Netlink`] keeps what it knows of each interface, and gives an [`Event`]
//! only where something is new: an interface is *up* (new, or up again,
//! under a new index), is *down* (down, deleted, or renamed), has a new MTU
//! or new addresses, or a neighbour has changed. The kernel's order of
//! messages, its repeats, and what is lost when its queue runs over (which
//! is asked for again, and compared) are its own business.
//!
//! Linux has netlink, and FreeBSD (14 and 15) a netlink of the same messages, so
//! the same code reads them: only the socket is made another way. FreeBSD says
//! of ARP what its routing socket does not, which is why it is netlink there too.
//! Elsewhere [`Netlink`] hears of nothing, and what reads the messages, with the
//! constants of their format, is not used.
#![cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code, unused_imports))]

use alloc::vec;
use alloc::vec::Vec;
use hashbrown::{HashMap, HashSet};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustix::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use rustix::io::Errno;

use crate::runtime::{errno, Why};

use crate::prelude::*;

/// What the daemon is told of the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The interface called `name` is there and up (and running), with
    /// `index`, as it is new, or up again, or created again. `back` if it was
    /// up before.
    Up { name: String, index: u32, mtu: Option<u32>, back: bool },
    /// The interface called `name` is no longer up, or there.
    Down { name: String, index: u32 },
    /// The MTU of the interface called `name`, that is up, is now `mtu`.
    Mtu { name: String, mtu: u32 },
    /// An address of the interface called `name`, that is up, was added or
    /// removed.
    Addresses { name: String, index: u32 },
    /// The neighbour table of the interface with `index` has `ip` at
    /// link-layer address `mac`, or with `None`, no longer (the entry went,
    /// or the neighbour could not be reached).
    Neighbour { index: u32, ip: IpAddr, mac: Option<Vec<u8>> },
}

/// A change to an interface, as the kernel says it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Change {
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
    /// The kernel has said everything of the dump asked for with sequence
    /// number `seq`.
    Done { seq: u32 },
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
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;
const RTM_GETNEIGH: u16 = 30;
const NLMSG_DONE: u16 = 3;
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

/// The sequence numbers of the dumps asked for.
const NEIGHBOUR_DUMP: u32 = 1;
const LINK_DUMP: u32 = 2;

/// A socket that hears of link and address changes.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub struct Netlink {
    fd: OwnedFd,
    tracker: Tracker,
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
        Ok(Netlink { fd, tracker: Tracker::default() })
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
        Ok(Netlink { fd, tracker: Tracker::default() })
    }

    /// Ask the kernel for every interface and then every entry of every
    /// interface's neighbour table: they come as [`Event`]s among the next
    /// ones, those of what is new to the daemon. For what was there before it
    /// started, or before changes were lost; an interface that is not among
    /// them is down.
    pub fn resync(&mut self) -> Result<(), Why> {
        let mut msg = Vec::with_capacity(NLMSG_HDRLEN + IFINFOMSG_LEN);
        msg.extend(((NLMSG_HDRLEN + IFINFOMSG_LEN) as u32).to_ne_bytes());
        msg.extend(RTM_GETLINK.to_ne_bytes());
        msg.extend((NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        msg.extend(LINK_DUMP.to_ne_bytes());
        msg.extend(0u32.to_ne_bytes()); // port: the kernel fills it in
        msg.extend([0u8; IFINFOMSG_LEN]); // every family, every interface
        self.tracker.dumping = Some(HashSet::new());
        self.send_to_kernel(&msg)
    }

    /// Ask the kernel for every entry of every interface's neighbour table.
    /// Only one dump is made at a time on a socket: this is for when the one
    /// of the links is done.
    fn request_neighbours(&self) -> Result<(), Why> {
        let mut msg = Vec::with_capacity(NLMSG_HDRLEN + NDMSG_LEN);
        msg.extend(((NLMSG_HDRLEN + NDMSG_LEN) as u32).to_ne_bytes());
        msg.extend(RTM_GETNEIGH.to_ne_bytes());
        msg.extend((NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        msg.extend(NEIGHBOUR_DUMP.to_ne_bytes());
        msg.extend(0u32.to_ne_bytes());
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

    /// What is new since last asked, without waiting: nothing if there is
    /// nothing yet.
    pub fn events(&mut self) -> Result<Vec<Event>, Why> {
        let mut buf = vec![0u8; 64 * 1024];
        let mut events = Vec::new();
        loop {
            // SAFETY: `buf` is writable for its whole length.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if n >= 0 {
                for change in parse(&buf[..n as usize]) {
                    // The neighbours are asked for when the links are all said.
                    let links_done = change == Change::Done { seq: LINK_DUMP };
                    self.tracker.apply(change, &mut events);
                    if links_done {
                        if let Err(e) = self.request_neighbours() {
                            eprintln!("netlink: asking for the neighbour tables failed: {e}");
                        }
                    }
                }
                continue;
            }
            match errno() {
                Errno::INTR => continue,
                Errno::AGAIN => return Ok(events),
                // What was lost is not known: look at everything again.
                Errno::NOBUFS => {
                    if let Err(e) = self.resync() {
                        eprintln!("netlink: asking for what is there failed: {e}");
                    }
                }
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

    pub fn resync(&mut self) -> Result<(), Why> {
        Ok(())
    }

    /// No descriptor: waiting on a negative one waits for nothing.
    pub fn fd(&self) -> RawFd {
        -1
    }

    pub fn events(&mut self) -> Result<Vec<Event>, Why> {
        Ok(Vec::new())
    }
}

/// What is known of each interface, to turn what the kernel says into what
/// is new.
#[derive(Default)]
struct Tracker {
    links: HashMap<u32, Tracked>,
    /// The names that have been up, for saying one is back.
    seen: HashSet<String>,
    /// While the links are being asked for again, the indexes of those said
    /// so far: when it is done, any other is gone.
    dumping: Option<HashSet<u32>>,
}

struct Tracked {
    name: String,
    up: bool,
    mtu: Option<u32>,
}

impl Tracker {
    /// Say what `change` makes new, in `events`.
    fn apply(&mut self, change: Change, events: &mut Vec<Event>) {
        match change {
            Change::Link { index, name, up, mtu } => {
                if let Some(said) = &mut self.dumping {
                    said.insert(index);
                }
                // An interface of the name under another index, or the index under
                // another name: what was there is gone.
                let stale: Vec<u32> = self
                    .links
                    .iter()
                    .filter(|&(&i, l)| (l.name == name) != (i == index))
                    .map(|(&i, _)| i)
                    .collect();
                for i in stale {
                    self.forget(i, events);
                }
                match self.links.get_mut(&index) {
                    Some(link) => {
                        let (was_up, was_mtu) = (link.up, link.mtu);
                        link.up = up;
                        link.mtu = mtu.or(link.mtu);
                        match (was_up, up) {
                            (true, false) => events.push(Event::Down { name, index }),
                            (false, true) => {
                                let mtu = link.mtu;
                                events.push(self.up(name, index, mtu));
                            }
                            (true, true) if mtu.is_some() && mtu != was_mtu => {
                                events.extend(mtu.map(|mtu| Event::Mtu { name, mtu }))
                            }
                            _ => {}
                        }
                    }
                    None => {
                        self.links.insert(index, Tracked { name: name.clone(), up, mtu });
                        if up {
                            events.push(self.up(name, index, mtu));
                        }
                    }
                }
            }
            Change::Gone { index } => self.forget(index, events),
            Change::Address { index } => {
                if let Some(Tracked { name, up: true, .. }) = self.links.get(&index) {
                    events.push(Event::Addresses { name: name.clone(), index });
                }
            }
            Change::Neighbour { index, ip, mac } => {
                if self.links.contains_key(&index) {
                    events.push(Event::Neighbour { index, ip, mac });
                }
            }
            Change::Done { seq: LINK_DUMP } => {
                let said = self.dumping.take().unwrap_or_default();
                let gone: Vec<u32> = self.links.keys().copied().filter(|i| !said.contains(i)).collect();
                for index in gone {
                    self.forget(index, events);
                }
            }
            Change::Done { .. } => {}
        }
    }

    fn up(&mut self, name: String, index: u32, mtu: Option<u32>) -> Event {
        let back = !self.seen.insert(name.clone());
        Event::Up { name, index, mtu, back }
    }

    /// The interface with `index` is gone.
    fn forget(&mut self, index: u32, events: &mut Vec<Event>) {
        if let Some(Tracked { name, up: true, .. }) = self.links.remove(&index) {
            events.push(Event::Down { name, index });
        }
    }
}

/// The changes in one datagram of rtnetlink messages. What cannot be read is
/// skipped.
fn parse(buf: &[u8]) -> Vec<Change> {
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
            NLMSG_DONE => out.push(Change::Done { seq: u32_at(buf, at + 8) }),
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

    /// What the kernel says, as a [`Tracker`] turns it into what is new.
    fn said(tracker: &mut Tracker, changes: Vec<Change>) -> Vec<Event> {
        let mut events = Vec::new();
        for change in changes {
            tracker.apply(change, &mut events);
        }
        events
    }

    fn link_change(index: u32, name: &str, up: bool, mtu: u32) -> Change {
        Change::Link { index, name: name.into(), up, mtu: Some(mtu) }
    }

    fn up(name: &str, index: u32, mtu: u32, back: bool) -> Event {
        Event::Up { name: name.into(), index, mtu: Some(mtu), back }
    }

    fn down(name: &str, index: u32) -> Event {
        Event::Down { name: name.into(), index }
    }

    #[test]
    fn an_interface_is_up_once_however_often_it_is_said_so() {
        let mut t = Tracker::default();
        assert_eq!(said(&mut t, vec![link_change(3, "ra", false, 1500)]), [], "not up yet");
        assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1500)]), [up("ra", 3, 1500, false)]);
        assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1500), link_change(3, "ra", true, 1500)]), []);
        assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1400)]), [Event::Mtu { name: "ra".into(), mtu: 1400 }]);
    }

    #[test]
    fn an_interface_down_and_up_again_is_back() {
        let mut t = Tracker::default();
        said(&mut t, vec![link_change(3, "ra", true, 1500)]);
        assert_eq!(said(&mut t, vec![link_change(3, "ra", false, 1500)]), [down("ra", 3)]);
        // Its addresses going with it are not news.
        assert_eq!(said(&mut t, vec![Change::Address { index: 3 }]), []);
        assert_eq!(said(&mut t, vec![link_change(3, "ra", true, 1500)]), [up("ra", 3, 1500, true)]);
        assert_eq!(said(&mut t, vec![Change::Address { index: 3 }]), [Event::Addresses { name: "ra".into(), index: 3 }]);
    }

    #[test]
    fn an_interface_made_again_is_down_and_up() {
        let mut t = Tracker::default();
        said(&mut t, vec![link_change(3, "ra", true, 1500)]);
        // Deleted, and made again; or made again before the deletion was said.
        assert_eq!(said(&mut t, vec![Change::Gone { index: 3 }, link_change(5, "ra", true, 1500)]), [down("ra", 3), up("ra", 5, 1500, true)]);
        assert_eq!(said(&mut t, vec![link_change(6, "ra", true, 1500)]), [down("ra", 5), up("ra", 6, 1500, true)]);
        // Renamed.
        assert_eq!(said(&mut t, vec![link_change(6, "rb", true, 1500)]), [down("ra", 6), up("rb", 6, 1500, false)]);
        // One that was down is not down again.
        said(&mut t, vec![link_change(6, "rb", false, 1500)]);
        assert_eq!(said(&mut t, vec![Change::Gone { index: 6 }]), []);
    }

    #[test]
    fn asking_again_finds_what_was_lost() {
        let mut t = Tracker::default();
        said(&mut t, vec![link_change(3, "ra", true, 1500), link_change(4, "rb", true, 1500)]);
        t.dumping = Some(HashSet::new());
        // Of the two, one is said again, unchanged, and one not at all; a third is new.
        let events = said(&mut t, vec![link_change(3, "ra", true, 1500), link_change(7, "rc", true, 1500), Change::Done { seq: LINK_DUMP }]);
        assert_eq!(events, [up("rc", 7, 1500, false), down("rb", 4)]);
        // The dump of neighbours ending says nothing.
        assert_eq!(said(&mut t, vec![Change::Done { seq: NEIGHBOUR_DUMP }]), []);
    }

    #[test]
    fn neighbours_are_those_of_interfaces_known() {
        let mut t = Tracker::default();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let entry = |index| Change::Neighbour { index, ip, mac: None };
        assert_eq!(said(&mut t, vec![entry(3)]), []);
        said(&mut t, vec![link_change(3, "ra", true, 1500)]);
        assert_eq!(said(&mut t, vec![entry(3)]), [Event::Neighbour { index: 3, ip, mac: None }]);
    }

    /// Manual check against the real kernel: needs nothing but a network
    /// namespace to change, `unshare -rn cargo test netlink_live -- --ignored`.
    #[test]
    #[ignore]
    fn netlink_live() {
        let mut netlink = Netlink::open().unwrap();
        std::process::Command::new("ip").args(["link", "add", "nl-test", "type", "dummy"]).status().unwrap();
        std::process::Command::new("ip").args(["link", "set", "nl-test", "up"]).status().unwrap();
        let events = netlink.events().unwrap();
        assert!(events.iter().any(|e| matches!(e, Event::Up { name, .. } if name == "nl-test")), "{events:?}");
    }
}
