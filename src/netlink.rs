//! What the kernel says about interfaces coming and going, by rtnetlink.
//!
//! A socket bound to an interface stops hearing anything when the interface
//! is deleted and created again (a VLAN reconfigured, hostapd restarted): it
//! stays bound to the old index, and its group memberships went with it. So
//! the daemon listens for link and address changes, and acts on those to the
//! interfaces it serves. Only the few fields it needs are read.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A change to an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The interface called `name` is there, with `index`, and is up (and
    /// running) or not. Sent when it appears and whenever it changes.
    Link { index: u32, name: String, up: bool },
    /// The interface with `index` is gone.
    Gone { index: u32 },
    /// An address of the interface with `index` was added or removed.
    Address { index: u32 },
    /// Changes were lost (the kernel's queue ran over): what is there has to
    /// be looked at afresh.
    Lost,
}

// rtnetlink, from <linux/rtnetlink.h> and <linux/if.h>.
const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const IFLA_IFNAME: u16 = 3;
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;

/// The sizes of a message header, of the link and address messages that
/// follow it, and of an attribute header.
const NLMSG_HDRLEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTA_HDRLEN: usize = 4;

/// A socket that hears of link and address changes.
pub struct Netlink {
    fd: OwnedFd,
}

impl Netlink {
    pub fn open() -> io::Result<Netlink> {
        // SAFETY: plain socket creation; the result is checked.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created and is owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero sockaddr_nl is valid; the fields set are its own.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        // SAFETY: `addr` is a valid sockaddr_nl of the size given.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Netlink { fd })
    }

    /// Wait for the next changes the kernel reports.
    pub fn changes(&self) -> io::Result<Vec<Change>> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: `buf` is writable for its whole length.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n >= 0 {
                return Ok(parse(&buf[..n as usize]));
            }
            match io::Error::last_os_error() {
                e if e.kind() == io::ErrorKind::Interrupted => continue,
                e if e.raw_os_error() == Some(libc::ENOBUFS) => return Ok(vec![Change::Lost]),
                e => return Err(e),
            }
        }
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
                } else if let Some(name) = link_name(&body[IFINFOMSG_LEN..]) {
                    let flags = u32_at(body, 8);
                    out.push(Change::Link { index, name, up: flags & (IFF_UP | IFF_RUNNING) == IFF_UP | IFF_RUNNING });
                }
            }
            RTM_NEWADDR | RTM_DELADDR if body.len() >= IFADDRMSG_LEN => {
                out.push(Change::Address { index: u32_at(body, 4) });
            }
            _ => {}
        }
        at += align(len);
    }
    out
}

/// The interface name among a link message's attributes.
fn link_name(mut attrs: &[u8]) -> Option<String> {
    while attrs.len() >= RTA_HDRLEN {
        let len = u16_at(attrs, 0) as usize;
        if len < RTA_HDRLEN || len > attrs.len() {
            return None;
        }
        if u16_at(attrs, 2) == IFLA_IFNAME {
            let name = &attrs[RTA_HDRLEN..len];
            let name = name.split(|&b| b == 0).next().unwrap_or_default();
            return String::from_utf8(name.to_vec()).ok();
        }
        attrs = attrs.get(align(len)..).unwrap_or_default();
    }
    None
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
        // Another attribute first, as the kernel sends many.
        body.extend(attr(4, &1500u32.to_ne_bytes()));
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
            Change::Link { index: 7, name: "mdns-a".into(), up: true },
            Change::Link { index: 8, name: "wifi".into(), up: false },
            Change::Address { index: 7 },
            Change::Address { index: 8 },
            Change::Gone { index: 7 },
        ]);
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
