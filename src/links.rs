//! Each interface the daemon serves, its sockets kept open as it comes and
//! goes.
//!
//! A [`Segment`] is the interface's list of devices, and lives as long as the
//! daemon. Its sockets do not: an interface can be deleted and created again
//! (a VLAN reconfigured, hostapd restarted), and a socket bound to the old one
//! hears nothing. So a [`Link`] opens sockets while the interface is there,
//! and [`follow`] acts on what [`netlink`](crate::netlink) reports: an
//! interface gone has its sockets closed and its devices forgotten, one that
//! comes back gets new sockets, has everything announced on it again and is
//! probed, and one whose addresses change has the advertised name updated.
//! An interface that is not there when the daemon starts is waited for.

use alloc::rc::Rc;
use core::net::{IpAddr, SocketAddr};

use rustix::fd::{AsRawFd, OwnedFd, RawFd};
use rustix::io::Errno;

use anyhow::{Context, Result};

use crate::config::{AdvertiseConfig, Config, Interface};
use crate::device::{Device, Service};
use crate::runtime::Why;
use crate::netlink::{Change, Netlink};
use crate::segment::{Owner, Segment};
use crate::socket::{self, Family, Hub};

use crate::prelude::*;

/// The most a datagram read from an mDNS socket may hold: mDNS's own limit
/// (RFC 6762 section 17).
pub const MAX_DATAGRAM: usize = 9000;

/// One interface the daemon serves, and the sockets it has on it while it is
/// there.
pub struct Link {
    interface: String,
    families: Vec<Family>,
    /// The families of which what is sent to the daemon itself is heard too.
    #[cfg_attr(not(all(target_os = "linux", not(feature = "portable-sockets"))), allow(dead_code))]
    unicast: Vec<Family>,
    segment: Segment,
    /// The names to advertise with this host's addresses here.
    advertise: Vec<AdvertiseConfig>,
    /// The interface's index, while it has sockets on it.
    index: Option<u32>,
    /// Whether it was up (and running) when last heard of. Nothing is
    /// announced or asked on one that is not, and its addresses, going as it
    /// goes down, are not taken for a change.
    up: bool,
    /// Whether it has had sockets before: one that comes again is back.
    was_here: bool,
    /// Its MTU, once known: what a packet sent on it may hold follows it.
    mtu: Option<u32>,
    /// The sockets it hears on while the interface is there, one per family,
    /// for the event loop to read when they are readable. None where one socket
    /// per family is shared by every interface: it is the hub's, which joins
    /// the group on this interface for as long as it is there.
    sockets: Vec<OwnedFd>,
    #[cfg_attr(all(target_os = "linux", not(feature = "portable-sockets")), allow(dead_code))]
    hub: Rc<Hub>,
}

impl Link {
    /// The link for `interface`, over `families`, with what the names to
    /// advertise in `config` say of it. It has no sockets until
    /// [`open`](Link::open).
    pub fn new(interface: &Interface, families: &[Family], unicast: &[Family], config: &Config, hub: Rc<Hub>) -> Link {
        let segment = Segment::new(&interface.name, families);
        segment.set_min_lifetime(interface.min_lifetime);
        segment.set_max_addrs(interface.max_addrs);
        segment.set_direct(unicast);
        segment.set_max_devices(interface.max_devices);
        segment.set_max_services(interface.max_services);
        segment.set_reannounce(interface.reannounce);
        segment.set_refresh_before(interface.refresh_before);
        // The rounds run in the event loop; the interval is between starts.
        segment.set_probe_interval(interface.probe_interval);

        Link {
            interface: interface.name.clone(),
            families: families.to_vec(),
            unicast: unicast.to_vec(),
            segment,
            advertise: config
                .advertise
                .iter()
                .filter(|a| a.interfaces.is_empty() || a.interfaces.iter().any(|i| *i == interface.name))
                .cloned()
                .collect(),
            index: None,
            up: true,
            was_here: false,
            mtu: None,
            sockets: Vec::new(),
            hub,
        }
    }

    pub fn segment(&self) -> &Segment {
        &self.segment
    }

    /// Open a socket for each family on the interface, if it is there, for
    /// the event loop to read, both feeding the one list of devices, and
    /// advertise the name. Returns whether it was there.
    pub fn open(&mut self) -> Result<bool> {
        let Ok(index) = socket::ifindex(&self.interface) else {
            return Ok(false);
        };
        self.take_mtu(socket::mtu(&self.interface).ok());
        self.open_sockets()?;
        self.index = Some(index);
        self.was_here = true;
        if self.up {
            self.addresses_changed();
        }
        Ok(true)
    }

    /// A socket of its own for each family, pinned to the interface.
    #[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
    fn open_sockets(&mut self) -> Result<()> {
        let mut sockets = Vec::new();
        for &family in &self.families {
            let sock = socket::open(&self.interface, family, self.unicast.contains(&family))
                .with_context(|| format!("opening {family:?} socket on {}", self.interface))?;
            sockets.push(sock);
        }
        let mut receivers = Vec::new();
        for sock in sockets {
            // Never waited on: the loop reads it when it is readable, and a
            // send that cannot go out at once fails, and is tried again.
            rustix::io::ioctl_fionbio(&sock.socket, true).map_err(Why)?;
            let (tx, dest) = sock.sender()?;
            self.segment.attach(sock.family, tx, dest);
            eprintln!("listening on {} ({:?})", self.interface, sock.family);
            receivers.push(sock.socket);
        }
        self.sockets = receivers;
        Ok(())
    }

    /// The shared sockets, joined to the group on this interface.
    #[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
    fn open_sockets(&mut self) -> Result<()> {
        for &family in &self.families {
            let (tx, dest) = self
                .hub
                .join(&self.interface, family)
                .with_context(|| format!("joining the group over {family:?} on {}", self.interface))?;
            self.segment.attach(family, tx, dest);
            eprintln!("listening on {} ({:?})", self.interface, family);
        }
        Ok(())
    }

    /// Close the sockets, as the interface is gone: nothing is heard or sent
    /// until it is back.
    fn close(&mut self) {
        #[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
        if self.index.is_some() {
            for &family in &self.families {
                self.hub.leave(&self.interface, family);
            }
        }
        self.sockets.clear();
        self.segment.detach_all();
        self.index = None;
    }

    /// The interface's addresses are new: tell its segment the networks it is
    /// on, and announce the advertised name with them.
    fn addresses_changed(&self) {
        match socket::prefixes(&self.interface) {
            Ok(prefixes) => self.segment.set_prefixes(prefixes),
            Err(e) => eprintln!("{}: {e:#}", self.interface),
        }
        self.advertise();
    }

    /// Announce the names to advertise with all of this host's addresses on the
    /// interface, of the families listened to, read afresh. With none at all,
    /// they are withdrawn.
    fn advertise(&self) {
        if self.advertise.is_empty() {
            return;
        }
        let addrs = socket::addresses(&self.interface, &self.families).unwrap_or_default();
        for block in &self.advertise {
            self.advertise_one(block, &addrs);
        }
    }

    fn advertise_one(&self, block: &AdvertiseConfig, addrs: &[IpAddr]) {
        let AdvertiseConfig { name, ttl, services, .. } = block;
        if addrs.is_empty() {
            eprintln!("{}: no address to advertise {name} with", self.interface);
            if let Err(e) = self.segment.remove_manual(Owner::Own, name) {
                eprintln!("{}: withdrawing {name} failed: {e:#}", self.interface);
            }
            return;
        }
        let mut device = Device { hostname: Some(name.clone()), ..Device::default() };
        device.add_addrs(addrs);
        // Each is of an instance named for the host, as Avahi's %h is.
        let label = name.split('.').next().unwrap_or(name);
        device.services = services
            .iter()
            .map(|(kind, port)| Service {
                instance: format!("{label}.{kind}.local"),
                kind: format!("{kind}.local"),
                port: *port,
                target: Some(name.clone()),
                ..Service::default()
            })
            .collect();
        match self.segment.add_manual_ttl(Owner::Own, device, *ttl) {
            Ok(true) => {
                let shown: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
                eprintln!("{}: advertising {name} as {} (TTL {}s)", self.interface, shown.join(", "), ttl.as_secs());
            }
            Ok(false) => {}
            Err(e) => eprintln!("{}: not advertising {name}: {e:#}", self.interface),
        }
    }

    /// Act on `change`, if it is about this interface.
    pub fn changed(&mut self, change: &Change) {
        match change {
            Change::Link { index, name, up, mtu } if *name == self.interface => {
                self.take_mtu(*mtu);
                let came_up = *up && !self.up;
                self.up = *up;
                if self.index != Some(*index) {
                    // It appeared, or was created again under a new index.
                    let how = if self.was_here { "back" } else { "here" };
                    self.close();
                    match self.open() {
                        Ok(true) => {
                            eprintln!("{}: {how} (index {index}), listening", self.interface);
                            // Not yet up, it is announced and asked on once it is.
                            if *up {
                                self.came_back();
                            }
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("{}: {e:#}", self.interface);
                            self.close();
                        }
                    }
                } else if came_up {
                    eprintln!("{}: up", self.interface);
                    self.addresses_changed();
                    self.came_back();
                }
            }
            Change::Gone { index } if self.index == Some(*index) => self.gone(),
            // An interface going down loses its addresses: that is not news.
            Change::Address { index } if self.index == Some(*index) && self.up => self.addresses_changed(),
            Change::Neighbour { index, ip, mac } if self.index == Some(*index) => self.segment.neighbour(*ip, mac.clone()),
            Change::Lost => self.look_again(),
            _ => {}
        }
    }

    /// The interface is gone: close its sockets, and forget the devices on
    /// it, whose copies elsewhere are withdrawn.
    fn gone(&mut self) {
        eprintln!("{}: gone; waiting for it to come back", self.interface);
        self.close();
        self.segment.forget_discovered();
    }

    /// Changes were lost: see for ourselves whether the interface is there,
    /// under which index, and what its addresses are.
    fn look_again(&mut self) {
        match socket::ifindex(&self.interface) {
            Ok(index) if self.index != Some(index) => {
                let name = self.interface.clone();
                self.changed(&Change::Link { index, name, up: true, mtu: None });
            }
            Ok(_) => {
                self.take_mtu(socket::mtu(&self.interface).ok());
                self.addresses_changed();
            }
            Err(_) if self.index.is_some() => self.gone(),
            Err(_) => {}
        }
    }

    /// Take the interface's MTU, if it is known and new: packets sent on it
    /// are kept within what it leaves.
    fn take_mtu(&mut self, mtu: Option<u32>) {
        let Some(mtu) = mtu.filter(|&m| Some(m) != self.mtu) else { return };
        let max_packet = self.segment.set_mtu(mtu);
        let how = if self.mtu.is_some() { "now" } else { "is" };
        eprintln!("{}: MTU {how} {mtu}: packets of at most {max_packet} bytes", self.interface);
        self.mtu = Some(mtu);
    }

    /// The descriptors of its sockets, for the event loop to wait on.
    pub fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.sockets.iter().map(|s| s.as_raw_fd())
    }

    /// The interface's index, while it has sockets on it: what a datagram of a
    /// socket that every interface shares is told apart by.
    pub fn index(&self) -> Option<u32> {
        self.index
    }

    /// Handle a datagram that came in on this interface.
    pub fn heard(&self, from: SocketAddr, to: Option<IpAddr>, datagram: &[u8]) {
        if !self.segment.accepts(from.ip(), to) {
            return;
        }
        if let Err(e) = self.segment.handle(from, datagram) {
            eprintln!("{}: reply failed: {e:#}", self.interface);
        }
    }

    /// Handle everything the socket `fd` has heard, if it is one of this
    /// link's: the event loop found it readable.
    pub fn receive(&self, fd: RawFd) {
        let Some(sock) = self.sockets.iter().find(|s| s.as_raw_fd() == fd) else { return };
        let mut buf = [0u8; MAX_DATAGRAM];
        loop {
            match socket::recv(sock, &mut buf) {
                Ok(datagram) => {
                    // A datagram from an IP address, as on a UDP socket.
                    let Some(from) = datagram.from else { continue };
                    self.heard(from, datagram.to, &buf[..datagram.len]);
                }
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => {}
                Err(e) => {
                    // Reported once (an ICMP error, say), it is cleared.
                    eprintln!("{}: recv failed: {}", self.interface, Why(e));
                    return;
                }
            }
        }
    }

    /// The interface is back, or up again: whoever is on it now may never
    /// have heard what is announced there, nor been asked about.
    fn came_back(&self) {
        if let Err(e) = self.segment.announce_all() {
            eprintln!("{}: announcing again failed: {e:#}", self.interface);
        }
        self.segment.start_probe("return");
    }
}

/// Ask `netlink` for the neighbour tables: at startup, for what was there
/// already, and when changes were lost.
pub fn ask_neighbours(netlink: &Netlink) {
    if let Err(e) = netlink.request_neighbours() {
        eprintln!("netlink: asking for the neighbour tables failed: {e}");
    }
}

/// Act on the `changes` `netlink` reported, for `links`.
pub fn follow(netlink: &Netlink, links: &mut [Link], changes: &[Change]) {
    if changes.contains(&Change::Lost) {
        ask_neighbours(netlink);
    }
    for change in changes {
        for link in links.iter_mut() {
            link.changed(change);
        }
    }
}
