mod config;
mod ipc;
mod parser;
mod reflector;
mod signal;
mod socket;

use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use config::Config;
use reflector::Reflector;
use socket::{Device, Family, MdnsSocket, Segment};

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
            let link = start_link(interface, family, config.advertise.as_deref())?;
            links.insert((interface, family), link);
        }
    }

    // One reflector per configured segment and family, each over the shared
    // per-interface links of that family.
    let mut segments = Vec::new();
    for seg in &config.segments {
        for &family in &families {
            let members = seg
                .interfaces
                .iter()
                .map(|iface| links[&(iface.as_str(), family)].clone())
                .collect();
            let reflector = Reflector::new(members)
                .with_context(|| format!("starting segment {:?} ({family:?})", seg.name))?;
            eprintln!("segment {:?} ({family:?}): {}", seg.name, seg.interfaces.join(", "));
            segments.push(Group {
                name: seg.name.clone(),
                family,
                reflector,
            });
        }
    }

    // Look for devices right away instead of waiting for them to announce
    // themselves. The probes run on their own threads, so startup is not held
    // up; `mdnsctl probe` does the same on demand.
    for link in links.values() {
        let link = link.clone();
        thread::spawn(move || {
            let name = format!("{}/{:?}", link.interface(), link.family());
            match link.probe() {
                Ok(queries) => eprintln!("{name}: startup probe sent {queries} queries"),
                Err(e) => eprintln!("{name}: startup probe failed: {e:#}"),
            }
        });
    }

    let segments = Arc::new(segments);
    ipc::serve(&config.socket, &segments)?;

    let signal = signal::wait().context("waiting for shutdown signal")?;
    eprintln!("received {signal}: withdrawing reflected devices");
    release(segments);
    // With the reflectors gone, what is left in the manual lists is the
    // advertised name: say goodbye to it too.
    for link in links.values() {
        for host in link.manual_devices().into_iter().filter_map(|d| d.hostname) {
            if let Err(e) = link.remove_manual(&host) {
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
/// receive/respond, expiry/re-announcement, and an event logger. They run
/// until the process exits.
///
/// With `advertise`, the link also announces that name (say `router.local`)
/// with this host's address on the interface, as a reflected device with a
/// hostname and an address but no services. The address is read once, here.
fn start_link(interface: &str, family: Family, advertise: Option<&str>) -> Result<Segment> {
    let sock = socket::open(interface, family)
        .with_context(|| format!("opening {family:?} socket on {interface}"))?;
    eprintln!("listening on {interface} ({family:?})");

    let link = Segment::new(interface, family);
    let (tx, dest) = sock.sender()?;
    link.attach(tx, dest);

    if let Some(name) = advertise {
        // On its own link, the router's link-local address is as good as any,
        // and for IPv6 it is the one the kernel picks.
        let router = sock.local_addr().and_then(|addr| {
            let (link_local, routable) =
                if socket::is_link_local(&addr) { (Some(addr), None) } else { (None, Some(addr)) };
            link.add_manual(Device { hostname: Some(name.to_string()), link_local, routable, services: Vec::new() })
                .map(|_| addr)
        });
        match router {
            Ok(addr) => eprintln!("{interface}/{family:?}: advertising {name} as {addr}"),
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
            for event in events {
                eprintln!("{name}: {event:?}");
            }
        }
    });

    let reaper = link.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(10));
        let now = Instant::now();
        reaper.expire(now);
        if let Err(e) = reaper.reannounce(now) {
            eprintln!("{name}: re-announce failed: {e:#}");
        }
    });

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
