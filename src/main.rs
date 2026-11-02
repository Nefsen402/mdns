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
mod timespan;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use config::Config;
use links::Link;
use netlink::Netlink;
use reflector::{Forward, Neighbours, Reflector};
use segment::{Owner, Segment};
use socket::Family;

/// One configured segment, over every family the daemon listens on.
pub struct Group {
    pub name: String,
    pub reflector: Reflector,
}

fn main() -> Result<()> {
    let signals = signal::install().context("handling shutdown signals")?;

    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_PATH));
    let config = Config::load(&path)?;

    let families: Vec<Family> = [(config.ipv4, Family::V4), (config.ipv6, Family::V6)]
        .into_iter()
        .filter_map(|(enabled, family)| enabled.then_some(family))
        .collect();

    // Hear of interfaces coming and going from before the sockets are opened,
    // so that no change in between is missed.
    let netlink = Netlink::open().context("listening for interface changes (netlink)")?;

    // One link per interface, however many segments use it, with a socket
    // for each family and one list of devices for both: mDNS records do not
    // belong to the transport they come over. One that is not there yet is
    // waited for.
    let mut tracked = Vec::new();
    let mut links: HashMap<&str, Segment> = HashMap::new();
    for interface in config.interfaces() {
        let mut link = Link::new(interface, &families, &config);
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
            Reflector::with_options(rank, members, &seg.untrusted, seg.forward, seg.neighbour_addresses, seg.reflect_ttl)
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
    eprintln!("keeping a device for at least {}s after it was last heard from", config.min_lifetime.as_secs());
    for interface in config.interfaces().into_iter().filter(|i| config.reannounce_on(i)) {
        eprintln!("{interface}: announcing reflected devices again at 80% of their TTL, changed or not");
    }
    match config.refresh_before {
        Some(before) => {
            eprintln!("asking devices to answer again {}s before they would expire", before.as_secs());
            if before >= config.min_lifetime {
                eprintln!(
                    "warning: that is not shorter than the {}s a device is kept at least, so a device whose records \
                     expire sooner is always due and is asked about every {}s while it answers",
                    config.min_lifetime.as_secs(),
                    (before.as_secs() / 4).max(5)
                );
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
                if config.refresh_before.is_none() && interval > config.min_lifetime {
                    eprintln!(
                        "warning: that is longer than the {}s a device is kept without being heard from, \
                         so devices on {interface} whose records all expire sooner will come and go between probes",
                        config.min_lifetime.as_secs()
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

    let segments = Arc::new(segments);
    let mut server = ipc::Server::bind(&config.socket)?;

    let signal = run(&signals, netlink, &mut tracked, &segments, &mut server)?;
    eprintln!("received {signal}: withdrawing reflected devices");
    server.shut_down();
    drop(server);
    // The loop has stopped, and the upkeep with it, while the goodbyes go out.
    release(segments);
    // With the reflectors gone, what is left in the manual lists is the
    // advertised name: say goodbye to it too.
    for link in links.values() {
        for host in link.manual_devices().into_iter().filter_map(|d| d.hostname) {
            if let Err(e) = link.remove_manual(Owner::Own, &host) {
                eprintln!("{}: withdrawing {host} failed: {e:#}", link.interface());
            }
        }
    }
    let _ = std::fs::remove_file(&config.socket);
    Ok(())
}

/// The event loop: read what `links` hear, follow what netlink reports for
/// them, and run each link's upkeep when it is due, handing what changes to
/// the reflectors of `groups`; and serve the control socket's clients through
/// `server`; until a shutdown signal comes, whose name is returned. Should
/// netlink fail, interfaces are no longer followed, and the daemon goes on
/// as they are. Nothing changes but what the loop does, so what it is to
/// wait for is worked out afresh each time round.
fn run(
    signals: &signal::Signals,
    netlink: Netlink,
    links: &mut [Link],
    groups: &[Group],
    server: &mut ipc::Server,
) -> Result<&'static str> {
    let reflectors: Vec<&Reflector> = groups.iter().map(|g| &g.reflector).collect();
    links::ask_neighbours(&netlink);
    let mut netlink = Some(netlink);
    loop {
        let upkeep = links.iter().filter_map(|l| l.segment().next_due());
        let next = upkeep.chain(reflectors.iter().filter_map(|r| r.next_retry())).chain(server.next_due()).min();
        // The signals and netlink, then every link's sockets, each with the
        // link it is of, then the control socket and its clients.
        let mut fds = vec![poll::readable(signals.fd())];
        fds.push(poll::readable(netlink.as_ref().map_or(-1, Netlink::fd)));
        let sockets: Vec<(usize, i32)> =
            links.iter().enumerate().flat_map(|(i, l)| l.fds().map(move |fd| (i, fd))).collect();
        fds.extend(sockets.iter().map(|&(_, fd)| poll::readable(fd)));
        let clients = fds.len();
        fds.extend(server.fds());
        poll::wait(&mut fds, next.map(|at| at.saturating_duration_since(Instant::now())))
            .context("waiting for something to do")?;
        if let Some(name) = signals.take() {
            return Ok(name);
        }
        // What was heard first: a change of interfaces may close the sockets.
        for (&(link, fd), _) in sockets.iter().zip(&fds[2..clients]).filter(|(_, p)| poll::ready(p)) {
            links[link].receive(fd);
        }
        server.ready(&fds[clients..]);
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
    }
}

/// Drop the reflectors, which sends goodbyes for everything they announced.
/// An IPC request may be holding a reference for a moment, so wait it out.
fn release(mut segments: Arc<Vec<Group>>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match Arc::try_unwrap(segments) {
            Ok(groups) => return drop(groups),
            Err(still_shared) if Instant::now() < deadline => {
                segments = still_shared;
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                eprintln!("segments still in use after 5s; exiting without goodbyes");
                return;
            }
        }
    }
}
