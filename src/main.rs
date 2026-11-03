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
mod links;
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

use hashbrown::HashMap;
use time::Instant;

use anyhow::{Context, Result};

use config::{Config, Forward, Neighbours};
use links::Link;
use netlink::Netlink;
use reflector::Reflector;
use segment::{Owner, Segment};
use socket::Family;

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
    let netlink = Netlink::open().context("listening for interface changes (netlink)")?;

    // One link per interface, however many segments use it, with a socket
    // for each family and one list of devices for both: mDNS records do not
    // belong to the transport they come over. One that is not there yet is
    // waited for.
    let hub = Rc::new(socket::Hub::new(&families, &unicast).context("opening the sockets")?);
    let mut tracked = Vec::new();
    let mut links: HashMap<&str, Segment> = HashMap::new();
    for interface in config.interfaces() {
        let mut link = Link::new(interface, &families, &unicast, &config, hub.clone());
        if !link.open()? {
            eprintln!("{interface}: not there yet; waiting for it");
        }
        links.insert(interface, link.segment().clone());
        tracked.push(link);
    }

    // One reflector per configured segment, over the shared links. Where
    // segments share an interface and both want a hostname announced there,
    // the one listed first wins.
    let mut segments = Vec::new();
    for (rank, seg) in (0..).zip(&config.segments) {
        let members = seg.interfaces.iter().map(|iface| links[iface.as_str()].clone()).collect();
        let reflector =
            Reflector::with_options(rank, members, &seg.untrusted, seg.forward, seg.neighbour_addresses, seg.reflected_when, seg.reflect_ttl)
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

    // Look for devices right away instead of waiting for them to announce
    // themselves, and then again every `probe_interval`: most devices only
    // answer when asked, so without this a quiet one expires and is withdrawn
    // from the other networks. The probes run as rounds in the event loop, so
    // startup is not held up; `mdnsctl probe` does the same on demand.
    for interface in config.interfaces() {
        eprintln!(
            "{interface}: keeping a device for at least {}s after it was last heard from",
            config.min_lifetime_of(interface).as_secs()
        );
        if config.reannounce_on(interface) {
            eprintln!("{interface}: announcing reflected devices again at 80% of their TTL, changed or not");
        }
    }
    match config.refresh_before {
        Some(before) => {
            eprintln!("asking devices to answer again {}s before they would expire", before.as_secs());
            for interface in config.interfaces() {
                let kept = config.min_lifetime_of(interface);
                if before >= kept {
                    eprintln!(
                        "warning: that is not shorter than the {}s a device on {interface} is kept at least, so a \
                         device whose records expire sooner is always due and is asked about every {}s while it answers",
                        kept.as_secs(),
                        (before.as_secs() / 4).max(5)
                    );
                }
            }
        }
        None => eprintln!("refreshing devices before they expire is off"),
    }
    // Each interface is probed as often as the most frequent of its segments
    // asks.
    for interface in config.interfaces() {
        match config.probe_interval_of(interface) {
            Some(interval) => {
                eprintln!("{interface}: probing every {}s", interval.as_secs());
                // With refreshing on, each device is asked just before it
                // would expire, so a long interval only delays finding new
                // devices.
                let kept = config.min_lifetime_of(interface);
                if config.refresh_before.is_none() && interval > kept {
                    eprintln!(
                        "warning: that is longer than the {}s a device is kept without being heard from, \
                         so devices on {interface} whose records all expire sooner will come and go between probes",
                        kept.as_secs()
                    );
                }
            }
            None => eprintln!(
                "{interface}: not probing periodically (no ProbeInterval= for it): only at startup and on request"
            ),
        }
    }
    // The rounds run in the event loop; the interval is between starts.
    for link in links.values() {
        link.set_probe_interval(config.probe_interval_of(link.interface()));
        link.start_probe("startup");
    }

    let mut server = ipc::Server::bind(&config.socket, config.socket_mode as rustix::fs::RawMode)?;
    let mut avahi = match &config.avahi_socket {
        Some(path) => Some(avahi_compat::Server::bind(path, &config.advertise, &families)?),
        None => None,
    };

    let signal = event_loop(&signals, netlink, &hub, &mut tracked, &segments, &mut server, &mut avahi)?;
    eprintln!("received {signal}: withdrawing reflected devices");
    // The loop has stopped, and the upkeep with it, while the goodbyes go
    // out: the watches are told, and dropping the reflectors withdraws all
    // they announced.
    server.shut_down();
    drop(server);
    drop(avahi);
    drop(segments);
    // With the reflectors gone, what is left in the manual lists is the
    // advertised name: say goodbye to it too.
    for link in links.values() {
        for host in link.manual_devices().into_iter().filter_map(|d| d.hostname) {
            if let Err(e) = link.remove_manual(Owner::Own, &host) {
                eprintln!("{}: withdrawing {host} failed: {e:#}", link.interface());
            }
        }
    }
    let _ = rustix::fs::unlink(config.socket.as_str());
    Ok(())
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
    netlink: Netlink,
    hub: &socket::Hub,
    links: &mut [Link],
    groups: &[Group],
    server: &mut ipc::Server,
    avahi: &mut Option<avahi_compat::Server>,
) -> Result<&'static str> {
    let reflectors: Vec<&Reflector> = groups.iter().map(|g| &g.reflector).collect();
    links::ask_neighbours(&netlink);
    let mut netlink = Some(netlink);
    loop {
        let upkeep = links.iter().filter_map(|l| l.segment().next_due());
        let next = upkeep.chain(reflectors.iter().filter_map(|r| r.next_retry())).chain(server.next_due()).chain(avahi.as_ref().and_then(|a| a.next_due())).min();
        // The signals and netlink, then every link's sockets, each with the
        // link it is of, then the sockets shared by the interfaces, if there
        // are any, then the control socket and its clients.
        let mut fds = vec![poll::readable(signals.fd())];
        fds.push(poll::readable(netlink.as_ref().map_or(-1, Netlink::fd)));
        let sockets: Vec<(usize, i32)> =
            links.iter().enumerate().flat_map(|(i, l)| l.fds().map(move |fd| (i, fd))).collect();
        fds.extend(sockets.iter().map(|&(_, fd)| poll::readable(fd)));
        let shared: Vec<i32> = hub.fds().collect();
        let shared_at = fds.len();
        fds.extend(shared.iter().map(|&fd| poll::readable(fd)));
        let clients = fds.len();
        fds.extend(server.fds());
        let avahi_at = fds.len();
        fds.extend(avahi.as_ref().map(avahi_compat::Server::fds).unwrap_or_default());
        poll::wait(&mut fds, next.map(|at| at.saturating_duration_since(Instant::now())))
            .context("waiting for something to do")?;
        if let Some(name) = signals.take() {
            return Ok(name);
        }
        // What was heard first: a change of interfaces may close the sockets.
        for (&(link, fd), _) in sockets.iter().zip(&fds[2..shared_at]).filter(|(_, p)| poll::ready(p)) {
            links[link].receive(fd);
        }
        // A datagram of a shared socket goes to the link of the interface it came
        // in on, and to none if that is not one of ours.
        for (&fd, _) in shared.iter().zip(&fds[shared_at..clients]).filter(|(_, p)| poll::ready(p)) {
            hub.receive(fd, |index, from, to, datagram| {
                if let Some(link) = links.iter().find(|l| l.index() == Some(index)) {
                    link.heard(from, to, datagram);
                }
            });
        }
        server.ready(&fds[clients..avahi_at]);
        if let Some(avahi) = avahi.as_mut().filter(|_| avahi_at < fds.len()) {
            avahi.ready(&fds[avahi_at..]);
        }
        if let Some(n) = netlink.as_ref().filter(|_| poll::ready(&fds[1])) {
            match n.changes() {
                Ok(changes) => links::follow(n, links, &changes),
                Err(e) => {
                    eprintln!("netlink: {e}; no longer following interfaces as they come and go");
                    netlink = None;
                }
            }
        }
        let now = Instant::now();
        for link in links.iter() {
            if link.segment().next_due().is_some_and(|at| at <= now) {
                link.segment().upkeep(now);
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
