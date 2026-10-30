mod config;
mod device;
mod ipc;
mod parser;
mod reflector;
mod signal;
mod socket;
mod timer;

use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use config::Config;
use reflector::Reflector;
use device::Device;
use socket::{Family, MdnsSocket, Owner, Segment};
use timer::Timer;

/// One configured segment for one address family.
pub struct Group {
    pub name: String,
    pub family: Family,
    pub reflector: Reflector,
}

fn main() -> Result<()> {
    // Before any thread exists, so that every thread inherits the mask.
    signal::block().context("blocking shutdown signals")?;

    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_PATH));
    let config = Config::load(&path)?;
    let timer = Timer::new().context("starting the timer")?;

    let families: Vec<Family> = [(config.ipv4, Family::V4), (config.ipv6, Family::V6)]
        .into_iter()
        .filter_map(|(enabled, family)| enabled.then_some(family))
        .collect();

    // One socket per interface and family, however many segments use it.
    // IPv4 and IPv6 are kept entirely separate: own socket, own device
    // lists, own events.
    let mut links: HashMap<(&str, Family), Segment> = HashMap::new();
    for interface in config.interfaces() {
        for &family in &families {
            let link = start_link(
                interface,
                family,
                config.advertise.as_deref().map(|name| (name, config.advertise_ttl)),
                config.refresh_before,
                config.min_lifetime,
                config.reflect_ttl,
                &timer,
            )?;
            links.insert((interface, family), link);
        }
    }

    // One reflector per configured segment and family, each over the shared
    // per-interface links of that family. Where segments share an interface
    // and both want a hostname announced there, the one listed first wins.
    let mut segments = Vec::new();
    for (rank, seg) in (0..).zip(&config.segments) {
        for &family in &families {
            let members = seg
                .interfaces
                .iter()
                .map(|iface| links[&(iface.as_str(), family)].clone())
                .collect();
            let reflector = Reflector::with_untrusted(rank, members, &seg.untrusted)
                .with_context(|| format!("starting segment {:?} ({family:?})", seg.name))?;
            eprintln!("segment {:?} ({family:?}): {}", seg.name, seg.interfaces.join(", "));
            if !seg.untrusted.is_empty() {
                eprintln!("segment {:?} ({family:?}): {} not told about the others", seg.name, seg.untrusted.join(", "));
            }
            segments.push(Group {
                name: seg.name.clone(),
                family,
                reflector,
            });
        }
    }

    // Look for devices right away instead of waiting for them to announce
    // themselves, and then again every `probe_interval`: most devices only
    // answer when asked, so without this a quiet one expires and is withdrawn
    // from the other networks. The probes run on their own threads, so startup
    // is not held up; `mdnsctl probe` does the same on demand.
    eprintln!("keeping a device for at least {}s after it was last heard from", config.min_lifetime.as_secs());
    match config.reflect_ttl {
        Some(ttl) => eprintln!(
            "announcing reflected devices with a TTL of {}s, again every {}s",
            ttl.as_secs(),
            ttl.as_secs() * 4 / 5
        ),
        None => eprintln!("announcing reflected devices with the TTL they announced themselves with"),
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
    for link in links.values() {
        let link = link.clone();
        let interval = config.probe_interval_of(link.interface());
        thread::spawn(move || {
            let name = format!("{}/{:?}", link.interface(), link.family());
            let mut first = true;
            loop {
                let started = Instant::now();
                match link.probe() {
                    Ok(queries) if first => eprintln!("{name}: startup probe sent {queries} queries"),
                    // Routine probes are not worth a journal line each.
                    Ok(_) => {}
                    Err(e) => eprintln!("{name}: {} probe failed: {e:#}", if first { "startup" } else { "periodic" }),
                }
                first = false;
                // The interval is between starts, and a probe itself takes a few seconds.
                match interval {
                    Some(i) => thread::sleep(i.saturating_sub(started.elapsed())),
                    None => return,
                }
            }
        });
    }

    let segments = Arc::new(segments);
    ipc::serve(&config.socket, &segments, timer.watcher())?;

    let signal = signal::wait().context("waiting for shutdown signal")?;
    eprintln!("received {signal}: withdrawing reflected devices");
    // No more upkeep while the goodbyes go out.
    drop(timer);
    release(segments);
    // With the reflectors gone, what is left in the manual lists is the
    // advertised name: say goodbye to it too.
    for link in links.values() {
        for host in link.manual_devices().into_iter().filter_map(|d| d.hostname) {
            if let Err(e) = link.remove_manual(Owner::Own, &host) {
                eprintln!("{}/{:?}: withdrawing {host} failed: {e:#}", link.interface(), link.family());
            }
        }
    }
    let _ = std::fs::remove_file(&config.socket);
    Ok(())
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

/// Open the socket for one interface and family and start its threads:
/// receive/respond and an event logger, which run until the process exits.
/// Expiry, refreshing and re-announcement run on `timer`.
///
/// With `advertise`, the link also announces that name (say `router.local`)
/// with this host's address on the interface, as a reflected device with a
/// hostname and an address but no services, with its records valid for `ttl`.
/// The address is read once, here.
fn start_link(
    interface: &str,
    family: Family,
    advertise: Option<(&str, Duration)>,
    refresh_before: Option<Duration>,
    min_lifetime: Duration,
    reflect_ttl: Option<Duration>,
    timer: &Timer,
) -> Result<Segment> {
    let sock = socket::open(interface, family)
        .with_context(|| format!("opening {family:?} socket on {interface}"))?;
    eprintln!("listening on {interface} ({family:?})");

    let link = Segment::new(interface, family);
    link.set_min_lifetime(min_lifetime);
    link.set_reflect_ttl(reflect_ttl);
    let (tx, dest) = sock.sender()?;
    link.attach(tx, dest);

    if let Some((name, ttl)) = advertise {
        // On its own link, the router's link-local address is as good as any,
        // and for IPv6 it is the one the kernel picks.
        let router = sock.local_addr().and_then(|addr| {
            let (link_local, routable) =
                if device::is_link_local(&addr) { (Some(addr), None) } else { (None, Some(addr)) };
            let device = Device { hostname: Some(name.to_string()), link_local, routable, ..Device::default() };
            link.add_manual_ttl(Owner::Own, device, ttl).map(|_| addr)
        });
        match router {
            Ok(addr) => eprintln!("{interface}/{family:?}: advertising {name} as {addr} (TTL {}s)", ttl.as_secs()),
            // An interface without an address of this family has nothing to
            // advertise; that is not a reason to refuse to start.
            Err(e) => eprintln!("{interface}/{family:?}: not advertising {name}: {e:#}"),
        }
    }

    // Placeholder consumer: log changes to the discovered list.
    let events = link.subscribe();
    let name = format!("{interface}/{family:?}");
    thread::spawn({
        let name = name.clone();
        move || {
            // Questions passed on for the reflector are not worth a line each.
            for event in events.iter().filter(|e| !matches!(e, socket::Event::Question(_))) {
                eprintln!("{name}: {event:?}");
            }
        }
    });

    link.schedule(timer, refresh_before);

    let receiver = link.clone();
    thread::spawn(move || recv_loop(sock, receiver));
    Ok(link)
}

fn recv_loop(sock: MdnsSocket, segment: Segment) {
    let udp: UdpSocket = sock.socket.into();
    let mut buf = [0u8; 9000];
    loop {
        match udp.recv_from(&mut buf) {
            Ok((len, from)) => {
                if let Err(e) = segment.handle(from, &buf[..len]) {
                    eprintln!("{} {:?}: reply failed: {e:#}", sock.interface, sock.family);
                }
            }
            Err(e) => {
                eprintln!("{} {:?}: recv failed: {e}", sock.interface, sock.family);
                return;
            }
        }
    }
}
