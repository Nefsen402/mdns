//! Each interface the daemon serves, its sockets kept open as it comes and
//! goes.
//!
//! A [`Segment`] is the interface's list of devices, and lives as long as the
//! daemon. Its sockets do not: an interface can be deleted and created again
//! (a VLAN reconfigured, hostapd restarted), and a socket bound to the old one
//! hears nothing. So a [`Link`] opens sockets while the interface is there,
//! and [`track`] follows what [`netlink`](crate::netlink) reports: an
//! interface gone has its sockets closed and its devices forgotten, one that
//! comes back gets new sockets, has everything announced on it again and is
//! probed, and one whose addresses change has the advertised name updated.
//! An interface that is not there when the daemon starts is waited for.

use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::config::Config;
use crate::device::Device;
use crate::netlink::{Change, Netlink};
use crate::socket::{self, Event, Family, MdnsSocket, Owner, Segment};
use crate::timer::Timer;

/// How often a receive loop looks up from waiting to see whether it is to
/// stop: a socket whose interface is gone may never hear anything again.
const STOP_CHECK: Duration = Duration::from_millis(500);

/// One interface the daemon serves, and the sockets it has on it while it is
/// there.
pub struct Link {
    interface: String,
    families: Vec<Family>,
    segment: Segment,
    /// The name to advertise with this host's addresses, and its TTL.
    advertise: Option<(String, Duration)>,
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
    /// Tells the receive loops of the current sockets to stop.
    stop: Arc<AtomicBool>,
}

impl Link {
    /// The link for `interface`, over `families`, configured by `config`,
    /// with its upkeep on `timer` and its changes logged. It has no sockets
    /// until [`open`](Link::open).
    pub fn new(interface: &str, families: &[Family], config: &Config, timer: &Timer) -> Link {
        let segment = Segment::new(interface, families);
        segment.set_min_lifetime(config.min_lifetime);
        segment.set_max_addrs(config.max_addrs);
        segment.set_reflect_ttl(config.reflect_ttl);

        // Placeholder consumer: log changes to the discovered list.
        let events = segment.subscribe();
        let name = interface.to_string();
        thread::spawn(move || {
            // Questions passed on for the reflector are not worth a line each.
            for event in events.iter().filter(|e| !matches!(e, Event::Question(_))) {
                eprintln!("{name}: {event:?}");
            }
        });
        segment.schedule(timer, config.refresh_before);

        Link {
            interface: interface.to_string(),
            families: families.to_vec(),
            segment,
            advertise: config.advertise.clone().map(|name| (name, config.advertise_ttl)),
            index: None,
            up: true,
            was_here: false,
            mtu: None,
            stop: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn segment(&self) -> &Segment {
        &self.segment
    }

    /// Open a socket for each family on the interface, if it is there, start
    /// a receive loop for each, both feeding the one list of devices, and
    /// advertise the name. Returns whether it was there.
    pub fn open(&mut self) -> Result<bool> {
        let Ok(index) = socket::ifindex(&self.interface) else {
            return Ok(false);
        };
        self.take_mtu(socket::mtu(&self.interface).ok());
        let mut sockets = Vec::new();
        for &family in &self.families {
            let sock = socket::open(&self.interface, family)
                .with_context(|| format!("opening {family:?} socket on {}", self.interface))?;
            sockets.push(sock);
        }
        let stop = Arc::new(AtomicBool::new(false));
        for sock in sockets {
            let (tx, dest) = sock.sender()?;
            self.segment.attach(sock.family, tx, dest);
            eprintln!("listening on {} ({:?})", self.interface, sock.family);
            let (segment, stop) = (self.segment.clone(), stop.clone());
            thread::spawn(move || recv_loop(sock, segment, stop));
        }
        self.stop = stop;
        self.index = Some(index);
        self.was_here = true;
        if self.up {
            self.advertise();
        }
        Ok(true)
    }

    /// Close the sockets, as the interface is gone: their receive loops stop,
    /// and nothing is sent until it is back.
    fn close(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.segment.detach_all();
        self.index = None;
    }

    /// Announce the name to advertise with this host's addresses on the
    /// interface, one of each family, read afresh: on its own link the
    /// router's link-local address is as good as any, and for IPv6 it is the
    /// one the kernel picks. With none at all, it is withdrawn.
    fn advertise(&self) {
        let Some((name, ttl)) = &self.advertise else { return };
        let addrs: Vec<IpAddr> = self.families.iter().filter_map(|&f| socket::local_addr(&self.interface, f).ok()).collect();
        if addrs.is_empty() {
            eprintln!("{}: no address to advertise {name} with", self.interface);
            if let Err(e) = self.segment.remove_manual(Owner::Own, name) {
                eprintln!("{}: withdrawing {name} failed: {e:#}", self.interface);
            }
            return;
        }
        let mut device = Device { hostname: Some(name.clone()), ..Device::default() };
        device.add_addrs(&addrs);
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
                    self.advertise();
                    self.came_back();
                }
            }
            Change::Gone { index } if self.index == Some(*index) => self.gone(),
            // An interface going down loses its addresses: that is not news.
            Change::Address { index } if self.index == Some(*index) && self.up => self.advertise(),
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
                self.advertise();
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

    /// The interface is back, or up again: whoever is on it now may never
    /// have heard what is announced there, nor been asked about.
    fn came_back(&self) {
        if let Err(e) = self.segment.announce_all() {
            eprintln!("{}: announcing again failed: {e:#}", self.interface);
        }
        let (segment, name) = (self.segment.clone(), self.interface.clone());
        thread::spawn(move || {
            if let Err(e) = segment.probe() {
                eprintln!("{name}: probe failed: {e:#}");
            }
        });
    }
}

/// Follow what `netlink` reports, for `links`, until it fails.
pub fn track(netlink: Netlink, mut links: Vec<Link>) {
    loop {
        let changes = match netlink.changes() {
            Ok(changes) => changes,
            Err(e) => {
                eprintln!("netlink: {e}; no longer following interfaces as they come and go");
                return;
            }
        };
        for change in &changes {
            for link in &mut links {
                link.changed(change);
            }
        }
    }
}

/// Handle what `sock` hears, until told to `stop`.
fn recv_loop(sock: MdnsSocket, segment: Segment, stop: Arc<AtomicBool>) {
    let udp: UdpSocket = sock.socket.into();
    if let Err(e) = udp.set_read_timeout(Some(STOP_CHECK)) {
        eprintln!("{} {:?}: {e}", sock.interface, sock.family);
    }
    let mut buf = [0u8; 9000];
    while !stop.load(Ordering::Relaxed) {
        match udp.recv_from(&mut buf) {
            Ok((len, from)) => {
                if let Err(e) = segment.handle(from, &buf[..len]) {
                    eprintln!("{} {:?}: reply failed: {e:#}", sock.interface, sock.family);
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => {
                eprintln!("{} {:?}: recv failed: {e}", sock.interface, sock.family);
                return;
            }
        }
    }
}
