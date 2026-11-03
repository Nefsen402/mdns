// No std: its I/O is rustix's, its memory libc's malloc, and a panic aborts.
// Tests are built with std.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

// First, for its print macros.
#[macro_use]
mod runtime;
// Shared with mdnsctl, whose options take values; the daemon's take none.
#[allow(dead_code)]
mod args;
#[path = "avahi-compat.rs"]
mod avahi_compat;
mod config;
mod device;
mod ipc;
mod netlink;
mod parser;
mod poll;
mod reflector;
mod segment;
mod signal;
mod socket;
mod time;

use alloc::rc::Rc;
use core::ffi::c_int;

use rustix::fd::{AsRawFd, OwnedFd, RawFd};

use hashbrown::HashSet;
use time::Instant;

use anyhow::{Context, Result};

use config::{AdvertiseConfig, Config, Forward, Interface, Neighbours};
use netlink::{Event, Netlink};
use reflector::Reflector;
use segment::{Owner, Segment};
use socket::{Family, Hub};

/// What every module takes from alloc, as std's prelude would give it.
mod prelude {
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

use prelude::*;

/// The name the runtime says panics and bad command lines under.
#[cfg_attr(test, allow(dead_code))]
const PROGRAM: &str = "mdnsd";

/// Run the command line `args`, after the program's name: the exit status.
/// An error is said as std says one main returns.
#[cfg_attr(test, allow(dead_code))]
fn run(args: Vec<String>) -> c_int {
    match daemon(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e:?}");
            1
        }
    }
}

/// One configured segment, over every family the daemon listens on.
pub struct Group {
    pub name: String,
    pub reflector: Reflector,
}

fn daemon(args: Vec<String>) -> Result<()> {
    let signals = signal::install().context("handling shutdown signals")?;

    let Some(path) = config_path(args)? else {
        println!("usage: mdnsd [config-file]  (default {})", config::DEFAULT_PATH);
        return Ok(());
    };
    let config = Config::load(&path)?;

    let families: Vec<Family> = [(config.ipv4, Family::V4), (config.ipv6, Family::V6)]
        .into_iter()
        .filter_map(|(listen, family)| listen.enabled().then_some(family))
        .collect();
    let unicast: Vec<Family> = [(config.ipv4, Family::V4), (config.ipv6, Family::V6)]
        .into_iter()
        .filter_map(|(listen, family)| listen.unicast().then_some(family))
        .collect();

    // Hear of interfaces coming and going from before the sockets are opened,
    // so that no change in between is missed.
    // On FreeBSD it is an option of the kernel, which one built without it has not:
    // interfaces are then not followed, as where there is nothing to follow them by.
    let netlink = match Netlink::open() {
        Ok(netlink) => Some(netlink),
        Err(e) if cfg!(target_os = "freebsd") => {
            eprintln!("netlink: {e}; interfaces are not followed as they come and go (does the kernel have netlink?)");
            None
        }
        Err(e) => return Err(e).context("listening for interface changes (netlink)"),
    };

    // One reflector per configured segment, over the interfaces that are
    // there, which come and go. Where segments share an interface and both
    // want a hostname announced there, the one listed first wins.
    let mut segments = Vec::new();
    for (rank, seg) in (0..).zip(&config.segments) {
        let reflector =
            Reflector::with_options(rank, Vec::new(), &seg.untrusted, seg.forward, seg.neighbour_addresses, seg.reflected_when, seg.reflect_ttl)
            .with_context(|| format!("starting segment {:?}", seg.name))?;
        eprintln!("segment {:?}: {}", seg.name, seg.interfaces.join(", "));
        if !seg.untrusted.is_empty() {
            eprintln!("segment {:?}: {} not told about the others", seg.name, seg.untrusted.join(", "));
        }
        let forwarding = match seg.forward {
            Forward::Always => "every question asked on one interface",
            Forward::Unknown => "only questions nothing announced on an interface answers",
            Forward::Never => "no questions",
        };
        eprintln!("segment {:?}: asking {forwarding} on the others", seg.name);
        let when = seg.reflected_when;
        if when != config::ReflectedWhen::default() {
            let needs: Vec<&str> = [(when.address, "address"), (when.hostname, "hostname"), (when.service, "service")]
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, name)| *name)
                .collect();
            eprintln!("segment {:?}: reflecting devices that have: {}", seg.name, needs.join(", "));
        }
        match seg.neighbour_addresses {
            Neighbours::Always => eprintln!("segment {:?}: reflecting the addresses from the neighbour table of every family", seg.name),
            Neighbours::LinkLocal => {}
            Neighbours::Never => {
                eprintln!("segment {:?}: reflecting only the addresses devices announce, not those from the neighbour table", seg.name)
            }
        }
        if let Some(ttl) = seg.reflect_ttl {
            eprintln!("segment {:?}: announcing reflected devices with a TTL of {}s", seg.name, ttl.as_secs());
        }
        segments.push(Group { name: seg.name.clone(), reflector });
    }

    // One entry per interface that is there, however many segments use it,
    // with a socket for each family and one list of devices for both: mDNS
    // records do not belong to the transport they come over. One that is not
    // there yet is waited for.
    let hub = Rc::new(socket::Hub::new(&families, &unicast).context("opening the sockets")?);
    let interfaces = config.interfaces();
    let mut ifaces = Ifaces { config: &config, families: families.clone(), unicast, hub, groups: &segments, live: Vec::new(), seen: HashSet::new(), skipped: HashSet::new() };
    for interface in &interfaces {
        if ifaces.add(&interface.name)? == Opened::Absent {
            eprintln!("{}: not there yet; waiting for it", interface.name);
        }
    }

    // What is settled for those named; the others are said when they are
    // there. Each is looked for as soon as it is there, and then again every
    // `probe_interval`: most devices only answer when asked, so without this a
    // quiet one expires and is withdrawn from the other networks. The probes run
    // as rounds in the event loop, so startup is not held up; `mdnsctl probe`
    // does the same on demand.
    for interface in &interfaces {
        describe(interface);
    }
    // Those already there that a pattern names, which netlink says of too, but
    // not on a system that has none.
    for name in socket::interfaces().unwrap_or_default() {
        if is_pattern_match(&config, &name) {
            ifaces.add(&name)?;
        }
    }

    let mut server = ipc::Server::bind(&config.socket, config.socket_mode as rustix::fs::RawMode)?;
    let mut avahi = match &config.avahi_socket {
        Some(path) => Some(avahi_compat::Server::bind(path, &config.advertise, &families)?),
        None => None,
    };

    let signal = event_loop(&signals, netlink, &mut ifaces, &mut server, &mut avahi)?;
    eprintln!("received {signal}: withdrawing reflected devices");
    // The loop has stopped, and the upkeep with it, while the goodbyes go
    // out: the watches are told, and dropping the reflectors withdraws all
    // they announced.
    server.shut_down();
    drop(server);
    drop(avahi);
    let links: Vec<Segment> = ifaces.live.iter().map(|i| i.segment.clone()).collect();
    drop(ifaces);
    drop(segments);
    // With the reflectors gone, what is left in the manual lists is the
    // advertised name: say goodbye to it too.
    for link in &links {
        for host in link.manual_devices().into_iter().filter_map(|d| d.hostname) {
            if let Err(e) = link.remove_manual(Owner::Own, &host) {
                eprintln!("{}: withdrawing {host} failed: {e:#}", link.interface());
            }
        }
    }
    let _ = rustix::fs::unlink(config.socket.as_str());
    Ok(())
}

/// Say what is settled for `interface`.
fn describe(interface: &Interface) {
    let name = &interface.name;
    match interface.min_lifetime.as_secs() {
        0 => eprintln!("{name}: keeping a device for as long as its records say"),
        kept => eprintln!("{name}: keeping a device for at least {kept}s after it was last heard from"),
    }
    if interface.reannounce {
        eprintln!("{name}: announcing reflected devices again at 80% of their TTL, changed or not");
    }
    match interface.refresh_before {
        Some(before) => eprintln!(
            "{name}: asking devices to answer again {}s before they would expire, or three quarters of the way through a shorter life",
            before.as_secs()
        ),
        None => eprintln!("{name}: refreshing devices before they expire is off"),
    }
    // Each interface is probed as often as the most frequent of its segments
    // asks.
    match interface.probe_interval {
        Some(interval) => {
            eprintln!("{name}: probing every {}s", interval.as_secs());
            // With refreshing on, each device is asked just before it
            // would expire, so a long interval only delays finding new
            // devices.
            // Most devices announce their addresses for two minutes.
            let kept = interface.min_lifetime.max(core::time::Duration::from_secs(120));
            if interface.refresh_before.is_none() && interval > kept {
                eprintln!(
                    "warning: that is longer than the {}s a device is usually kept without being heard from, \
                     so devices on {name} whose records all expire sooner will come and go between probes",
                    kept.as_secs()
                );
            }
        }
        None => eprintln!("{name}: not probing periodically (no ProbeInterval= for it): only at startup and on request"),
    }
}

/// Whether the config has the interface `name` by a pattern, not by name.
fn is_pattern_match(config: &Config, name: &str) -> bool {
    config.wants(name) && !config.segments.iter().any(|seg| seg.interfaces.iter().any(|i| i == name))
}

/// How opening an interface went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opened {
    /// It is not there.
    Absent,
    /// It is there, and cannot be joined to the group over any family yet, having
    /// no address to do it by: it is opened when it is given one.
    Waiting,
    /// It is listened to, over every family it can be yet.
    Listening,
}

/// The interfaces the daemon serves that are there and up, and how it listens
/// on them. What netlink says of the network is acted on here: an interface
/// that is there and in the config gets sockets of its own and a list of
/// devices, which every segment of the config that names it is given; one
/// that goes down or away has them taken from the segments and closed, its
/// devices forgotten; and one that comes again is a new one, listened to and
/// asked of from the start. A socket bound to an interface that was deleted
/// and created again (a VLAN reconfigured, hostapd restarted) hears nothing,
/// so none is kept across that.
struct Ifaces<'a> {
    config: &'a Config,
    families: Vec<Family>,
    /// The families of which what is sent to the daemon itself is heard too.
    unicast: Vec<Family>,
    hub: Rc<Hub>,
    /// The reflector of each segment of the config, in its order.
    groups: &'a [Group],
    live: Vec<Iface>,
    /// The names of those that have been there, for saying one is back.
    seen: HashSet<String>,
    /// The names of loopback interfaces a pattern matched and were left, for saying so once.
    skipped: HashSet<String>,
}

/// One interface that is there: its list of devices, and the sockets it has
/// on it.
struct Iface {
    name: String,
    segment: Segment,
    /// The names to advertise with this host's addresses here.
    advertise: Vec<AdvertiseConfig>,
    /// The interface's index.
    index: u32,
    /// The families it is there and not listened to over, as it has no address to
    /// join the group by yet (IPv4, where the sockets are shared): they are
    /// joined when it has one.
    missing: Vec<Family>,
    /// Its MTU, once known: what a packet sent on it may hold follows it.
    mtu: Option<u32>,
    /// The sockets it hears on, one per family, for the event loop to read
    /// when they are readable. None where one socket per family is shared by
    /// every interface: it is the hub's, which joins the group on this
    /// interface for as long as it is there.
    sockets: Vec<OwnedFd>,
}

impl Ifaces<'_> {
    /// Whether the config names the interface `name` in a segment.
    fn wants(&self, name: &str) -> bool {
        self.config.wants(name)
    }

    /// Serve the interface `name`, if it is wanted, is there and is not
    /// served already: open its sockets, and give it to the segments that
    /// name it, to be told of what is known and tell of what it finds. Says
    /// whether it was there, and could be listened to.
    fn add(&mut self, name: &str) -> Result<Opened> {
        if !self.wants(name) || self.live.iter().any(|i| i.name == name) {
            return Ok(Opened::Absent);
        }
        let Ok(index) = socket::ifindex(name) else {
            return Ok(Opened::Absent);
        };
        // A pattern is for the networks there are: what a loopback interface hears
        // is what this host sends itself. One that is named is wanted.
        if is_pattern_match(self.config, name) && socket::is_loopback(name) {
            if self.skipped.insert(name.to_string()) {
                eprintln!("{name}: a loopback interface, which a pattern does not take; name it to listen on it");
            }
            return Ok(Opened::Absent);
        }
        let mut iface = Iface::new(&self.config.interface(name), index, self);
        iface.take_mtu(socket::mtu(name).ok());
        // Of the families it has no address to join the group over, only what is
        // waited for waits: IPv6 is listened to when IPv4 cannot be yet.
        iface.missing = self.families.iter().copied().filter(|&f| !socket::joinable(name, f)).collect();
        if !iface.missing.is_empty() {
            eprintln!("{name}: no IPv4 address yet: IPv4 is listened to when it has one");
        }
        if iface.missing.len() == self.families.len() {
            return Ok(Opened::Waiting);
        }
        iface.open_sockets(self)?;
        let first = self.seen.insert(name.to_string());
        let how = if first { "here" } else { "back" };
        if first && is_pattern_match(self.config, name) {
            describe(&self.config.interface(name));
        }
        if how == "back" {
            eprintln!("{name}: up");
        }
        eprintln!("{name}: {how} (index {index}), listening");
        iface.addresses_changed(&self.families);
        for (seg, group) in self.config.segments.iter().zip(self.groups) {
            if seg.has(name) {
                group.reflector.add(iface.segment.clone())?;
            }
        }
        // Whoever is there may never have been asked about.
        iface.segment.start_probe(how);
        self.live.push(iface);
        Ok(Opened::Listening)
    }

    /// Stop serving the interface at `at`, as it is gone or down: what was
    /// found on it is forgotten, and what the segments announced of that is
    /// withdrawn, and the segments let go of it.
    fn remove(&mut self, at: usize) {
        let iface = self.live.remove(at);
        // Nothing is heard or sent until it is back.
        iface.segment.detach_all();
        iface.segment.forget_discovered();
        let reflectors: Vec<&Reflector> = self.groups.iter().map(|g| &g.reflector).collect();
        reflector::deliver(&reflectors);
        for r in &reflectors {
            r.remove(&iface.name);
        }
        iface.close(self);
    }

    /// Act on what `netlink` said is new.
    fn follow(&mut self, events: &[Event]) {
        for event in events {
            if let Err(e) = self.changed(event) {
                eprintln!("{e:#}");
            }
        }
    }

    fn changed(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Up { name, index, .. } => {
                // One of that name that is there is of another index: it was made again.
                if let Some(at) = self.live.iter().position(|i| i.name == *name && i.index != *index) {
                    self.remove(at);
                }
                self.add(name)?;
            }
            Event::Down { name, index } => {
                if let Some(at) = self.live.iter().position(|i| i.index == *index) {
                    eprintln!("{name}: down; waiting for it to come up");
                    self.remove(at);
                }
            }
            Event::Mtu { name, mtu } => {
                if let Some(iface) = self.live.iter_mut().find(|i| i.name == *name) {
                    iface.take_mtu(Some(*mtu));
                }
            }
            Event::Addresses { name, index } => match self.live.iter().position(|i| i.index == *index) {
                // One that was waiting for an address to listen over a family by, and has one now.
                Some(at) if self.live[at].missing.iter().any(|&f| socket::joinable(name, f)) => {
                    self.remove(at);
                    self.add(name)?;
                }
                Some(at) => self.live[at].addresses_changed(&self.families),
                // Perhaps one that is there, and had no address to be joined to the group by.
                None => {
                    self.add(name)?;
                }
            },
            Event::Neighbour { index, ip, mac } => {
                if let Some(iface) = self.live.iter().find(|i| i.index == *index) {
                    iface.segment.neighbour(*ip, mac.clone());
                }
            }
        }
        Ok(())
    }
}

impl Iface {
    /// The entry for `interface`, with what the names to advertise in the
    /// config say of it. It has no sockets until
    /// [`open_sockets`](Iface::open_sockets).
    fn new(interface: &Interface, index: u32, ifaces: &Ifaces) -> Iface {
        let segment = Segment::new(&interface.name, &ifaces.families);
        segment.set_min_lifetime(interface.min_lifetime);
        segment.set_max_addrs(interface.max_addrs);
        segment.set_direct(&ifaces.unicast);
        segment.set_max_devices(interface.max_devices);
        segment.set_max_services(interface.max_services);
        segment.set_reannounce(interface.reannounce);
        segment.set_refresh_before(interface.refresh_before);
        // The rounds run in the event loop; the interval is between starts.
        segment.set_probe_interval(interface.probe_interval);

        Iface {
            name: interface.name.clone(),
            segment,
            advertise: ifaces
                .config
                .advertise
                .iter()
                .filter(|a| a.interfaces.is_empty() || a.interfaces.iter().any(|i| config::glob(i, &interface.name)))
                .cloned()
                .collect(),
            index,
            missing: Vec::new(),
            mtu: None,
            sockets: Vec::new(),
        }
    }

    /// A socket of its own for each family, pinned to the interface.
    #[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
    fn open_sockets(&mut self, ifaces: &Ifaces) -> Result<()> {
        let mut sockets = Vec::new();
        for &family in &ifaces.families {
            let sock = socket::open(&self.name, family, ifaces.unicast.contains(&family))
                .with_context(|| format!("opening {family:?} socket on {}", self.name))?;
            sockets.push(sock);
        }
        let mut receivers = Vec::new();
        for sock in sockets {
            // Never waited on: the loop reads it when it is readable, and a
            // send that cannot go out at once fails, and is tried again.
            rustix::io::ioctl_fionbio(&sock.socket, true).map_err(runtime::Why)?;
            let (tx, dest) = sock.sender()?;
            self.segment.attach(sock.family, tx, dest);
            eprintln!("listening on {} ({:?})", self.name, sock.family);
            receivers.push(sock.socket);
        }
        self.sockets = receivers;
        Ok(())
    }

    /// The shared sockets, joined to the group on this interface.
    #[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
    fn open_sockets(&mut self, ifaces: &Ifaces) -> Result<()> {
        for &family in ifaces.families.iter().filter(|f| !self.missing.contains(f)) {
            let (tx, dest) = ifaces
                .hub
                .join(&self.name, family)
                .with_context(|| format!("joining the group over {family:?} on {}", self.name))?;
            self.segment.attach(family, tx, dest);
            eprintln!("listening on {} ({:?})", self.name, family);
        }
        Ok(())
    }

    /// Let go of the sockets: the shared ones leave the group on this interface.
    fn close(self, ifaces: &Ifaces) {
        #[cfg(not(all(target_os = "linux", not(feature = "portable-sockets"))))]
        for &family in &ifaces.families {
            ifaces.hub.leave(&self.name, family);
        }
        #[cfg(all(target_os = "linux", not(feature = "portable-sockets")))]
        let _ = ifaces;
    }

    /// The interface's addresses are new: tell its segment the networks it is
    /// on, and announce the advertised name with them.
    fn addresses_changed(&self, families: &[Family]) {
        match socket::prefixes(&self.name) {
            Ok(prefixes) => self.segment.set_prefixes(prefixes),
            Err(e) => eprintln!("{}: {e:#}", self.name),
        }
        // Announce the names to advertise with all of this host's addresses on
        // the interface, of the families listened to, read afresh. With none at
        // all, they are withdrawn.
        if self.advertise.is_empty() {
            return;
        }
        let addrs = socket::addresses(&self.name, families).unwrap_or_default();
        for block in &self.advertise {
            self.segment.advertise(block, &addrs);
        }
    }

    /// Take the interface's MTU, if it is known and new: packets sent on it
    /// are kept within what it leaves.
    fn take_mtu(&mut self, mtu: Option<u32>) {
        let Some(mtu) = mtu.filter(|&m| Some(m) != self.mtu) else { return };
        let max_packet = self.segment.set_mtu(mtu);
        let how = if self.mtu.is_some() { "now" } else { "is" };
        eprintln!("{}: MTU {how} {mtu}: packets of at most {max_packet} bytes", self.name);
        self.mtu = Some(mtu);
    }

    /// The descriptors of its sockets, for the event loop to wait on.
    fn fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.sockets.iter().map(|s| s.as_raw_fd())
    }

    /// Handle everything the socket `fd` has heard, if it is one of this
    /// interface's: the event loop found it readable.
    fn receive(&self, fd: RawFd) {
        if let Some(sock) = self.sockets.iter().find(|s| s.as_raw_fd() == fd) {
            socket::drain(sock, &self.name, |from, to, datagram| self.segment.hear(from, to, datagram));
        }
    }
}

/// The configuration file the command line names, or the default; `None` if
/// it asks for help.
fn config_path(args: Vec<String>) -> Result<Option<String>, args::Error> {
    let mut parser = args::Parser::new(args);
    let mut path = None;
    while let Some(arg) = parser.next()? {
        match arg {
            args::Arg::Short('h') | args::Arg::Long("help") => return Ok(None),
            args::Arg::Value(word) if path.is_none() => path = Some(word),
            arg => return Err(arg.unexpected()),
        }
    }
    Ok(Some(path.unwrap_or_else(|| config::DEFAULT_PATH.to_string())))
}

/// The event loop: read what `links` hear, follow what netlink reports for
/// them, and run each link's upkeep when it is due, handing what changes to
/// the reflectors of `groups`; and serve the control socket's clients through
/// `server`; until a shutdown signal comes, whose name is returned. Should
/// netlink fail, interfaces are no longer followed, and the daemon goes on
/// as they are. Nothing changes but what the loop does, so what it is to
/// wait for is worked out afresh each time round.
fn event_loop(
    signals: &signal::Signals,
    netlink: Option<Netlink>,
    ifaces: &mut Ifaces,
    server: &mut ipc::Server,
    avahi: &mut Option<avahi_compat::Server>,
) -> Result<&'static str> {
    let groups = ifaces.groups;
    let reflectors: Vec<&Reflector> = groups.iter().map(|g| &g.reflector).collect();
    let mut netlink = netlink;
    if let Some(netlink) = netlink.as_mut() {
        // What is there already, and what is known of its neighbours.
        if let Err(e) = netlink.resync() {
            eprintln!("netlink: asking for what is there failed: {e}");
        }
    }
    loop {
        let upkeep = ifaces.live.iter().filter_map(|i| i.segment.next_due());
        let next = upkeep.chain(reflectors.iter().filter_map(|r| r.next_retry())).chain(server.next_due()).chain(avahi.as_ref().and_then(|a| a.next_due())).min();
        // The signals and netlink, then every link's sockets, each with the
        // link it is of, then the sockets shared by the interfaces, if there
        // are any, then the control socket and its clients.
        let mut fds = vec![poll::readable(signals.fd())];
        fds.push(poll::readable(netlink.as_ref().map_or(-1, Netlink::fd)));
        let sockets: Vec<(usize, i32)> =
            ifaces.live.iter().enumerate().flat_map(|(i, l)| l.fds().map(move |fd| (i, fd))).collect();
        fds.extend(sockets.iter().map(|&(_, fd)| poll::readable(fd)));
        let shared: Vec<i32> = ifaces.hub.fds().collect();
        let shared_at = fds.len();
        fds.extend(shared.iter().map(|&fd| poll::readable(fd)));
        let clients = fds.len();
        fds.extend(server.fds());
        let avahi_at = fds.len();
        fds.extend(avahi.as_ref().map(avahi_compat::Server::fds).unwrap_or_default());
        let timeout = next.map(|at| at.saturating_duration_since(Instant::now()));
        // A clock that moves only when it is told to is not waited on: what is not
        // due now is due after the request that moves it, which wakes the loop.
        #[cfg(feature = "test-clock")]
        let timeout = timeout.filter(|wait| wait.is_zero());
        poll::wait(&mut fds, timeout).context("waiting for something to do")?;
        if let Some(name) = signals.take() {
            return Ok(name);
        }
        // What was heard first: a change of interfaces may close the sockets.
        for (&(link, fd), _) in sockets.iter().zip(&fds[2..shared_at]).filter(|(_, p)| poll::ready(p)) {
            ifaces.live[link].receive(fd);
        }
        // A datagram of a shared socket goes to the link of the interface it came
        // in on, and to none if that is not one of ours.
        for (&fd, _) in shared.iter().zip(&fds[shared_at..clients]).filter(|(_, p)| poll::ready(p)) {
            ifaces.hub.receive(fd, |index, from, to, datagram| {
                if let Some(iface) = ifaces.live.iter().find(|i| i.index == index) {
                    iface.segment.hear(from, to, datagram);
                }
            });
        }
        if let Some(n) = netlink.as_mut().filter(|_| poll::ready(&fds[1])) {
            match n.events() {
                Ok(events) => ifaces.follow(&events),
                Err(e) => {
                    eprintln!("netlink: {e}; no longer following interfaces as they come and go");
                    netlink = None;
                }
            }
        }
        // Requests last, so that one is answered with what everything that came
        // before it has done, and what a request does (move the test clock, say)
        // is run on before the next one is.
        server.ready(&fds[clients..avahi_at]);
        if let Some(avahi) = avahi.as_mut().filter(|_| avahi_at < fds.len()) {
            avahi.ready(&fds[avahi_at..]);
        }
        let now = Instant::now();
        for iface in ifaces.live.iter() {
            if iface.segment.next_due().is_some_and(|at| at <= now) {
                iface.segment.upkeep(now);
            }
        }
        reflector::deliver(&reflectors);
        for r in &reflectors {
            r.retry(now);
        }
        server.tick(groups, now);
        if let Some(avahi) = avahi.as_mut() {
            avahi.tick(groups, now);
        }
    }
}
