//! Local control socket.
//!
//! A Unix stream socket speaking one request per line and answering each with
//! one line of JSON. A connection may send any number of requests.
//!
//! ```text
//! segments
//!   {"ok":true,"segments":[{"name":"IoT","interfaces":["wifi"],"families":["v4","v6"]}]}
//! devices <segment name>
//!   {"ok":true,"name":"IoT","devices":[{"interface":"wifi","family":"v6",
//!    "hostname":"tv.local","routable":"fd00:0:1::7","link_local":"fe80::7",
//!    "services":[{"instance":...}]}]}
//! probe [<segment name>]
//!   {"ok":true,"probed":[{"interface":"wifi","family":"v4","queries":14,"error":null}]}
//! watch <segment name>
//!   {"ok":true,"name":"IoT","watching":true}
//!   {"event":"added","segment":"IoT","ttl":4500,"device":{...as in devices...}}
//!   {"event":"removed","segment":"IoT","ttl":0,"device":{...}}
//! timers
//!   {"ok":true,"timers":[{"id":1,"name":"upkeep wifi/V4","running":false,
//!    "due_in_ms":93000,"runs":4,"last_run_ago_ms":3000,"last_took_us":210,
//!    "pending":[{"what":"re-announce","who":"router.local","due_in_ms":93000}]}]}
//! ```
//!
//! Errors are `{"ok":false,"error":"..."}`. `devices` lists what was
//! discovered on the segment's own interfaces, not reflected copies from
//! other segments. `probe` actively queries the interfaces of the segment
//! (of all segments if no name is given) and replies after about four
//! seconds, once the answers have been processed; list what was found with
//! `devices`.
//!
//! `watch` takes over the connection: after the first reply, a line follows
//! for every device that appears (`added`), changes (`updated`) or goes
//! (`removed`) on the segment's own interfaces, until the client hangs up. It
//! has the device as `devices` lists it, and `ttl`: for how many more seconds
//! the daemon keeps the device without hearing from it, or 0 if it is gone (it
//! said goodbye or ran out). Nothing is replayed: only changes from then on. A
//! failure after the first line is a final `{"ok":false,"error":"..."}`.
//!
//! `timers` lists what the daemon's timer has scheduled, soonest first, for
//! debugging. `due_in_ms` is 0 for one that is overdue (its callback is queued
//! behind another) and `null` for one that is running now or never due;
//! `last_run_ago_ms` and `last_took_us` are `null` until it has run. A link's
//! `upkeep` timer is set for the first of its `pending` list: everything it is
//! waiting to do, soonest first, as `what` (`expire`, `refresh` or
//! `re-announce`), to `who` (a hostname, or the address of a device that has
//! none), and `due_in_ms` from now (0 if it is due).
//! 
//!
//! A device has up to two addresses, of the entry's family: `routable` (IPv4,
//! or global/ULA IPv6) and `link_local`; either is `null` when unknown.

use std::collections::HashMap;
use std::fs::{self, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::reflector::Notice;
use crate::socket::{Device, Event, Family, Segment};
use crate::timer::Watcher;
use crate::Group;

/// Longest request line accepted.
const MAX_LINE: u64 = 4096;

/// Idle connections are closed after this long, so clients can't pile up threads.
const IDLE: Duration = Duration::from_secs(60);

/// How often a watch checks that its client is still there, and how
/// long it lets a write to a client that is not reading take.
const STREAM_CHECK: Duration = Duration::from_secs(1);
const STREAM_WRITE: Duration = Duration::from_secs(10);

/// Bind the socket and serve it on background threads. Binding happens
/// before this returns so a bad path or a second instance is reported at
/// startup. The returned handle is the accept loop.
///
/// The server only holds a weak reference, so it never keeps the segments
/// alive: once the owner drops them, requests are answered "shutting down".
pub fn serve(path: &Path, groups: &Arc<Vec<Group>>, timers: Watcher) -> Result<JoinHandle<()>> {
    let listener = bind(path)?;
    let groups = Arc::downgrade(groups);
    eprintln!("ipc: listening on {}", path.display());
    Ok(thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let groups = Weak::clone(&groups);
                    let timers = timers.clone();
                    thread::spawn(move || match serve_connection(stream, &groups, &timers) {
                        Err(e) if !matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                            eprintln!("ipc: connection ended: {e}");
                        }
                        _ => {}
                    });
                }
                Err(e) => {
                    eprintln!("ipc: accept failed: {e}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }))
}

/// Bind, replacing a stale socket file left by a previous run but never a
/// live instance and never a file that is not a socket.
fn bind(path: &Path) -> Result<UnixListener> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            bail!("{} exists and is not a socket", path.display());
        }
        if UnixStream::connect(path).is_ok() {
            bail!("{} is in use by a running instance", path.display());
        }
        fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // Owner and group only.
    fs::set_permissions(path, Permissions::from_mode(0o660))
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok(listener)
}

fn serve_connection(stream: UnixStream, groups: &Weak<Vec<Group>>, timers: &Watcher) -> io::Result<()> {
    stream.set_read_timeout(Some(IDLE))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader).take(MAX_LINE).read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') && n as u64 >= MAX_LINE {
            writeln!(writer, "{}", error("request too long"))?;
            return Ok(());
        }
        let request = line.trim();
        if let Some(name) = watch_arg(request) {
            // Hold the segments only long enough to register: a stream that
            // lasts must not keep the daemon from releasing them at shutdown.
            let registered = match groups.upgrade() {
                Some(groups) => follow(&groups, name),
                None => Err(error("shutting down")),
            };
            return match registered {
                Ok((name, events)) => stream_events(&mut writer, &name, &events),
                Err(reply) => writeln!(writer, "{reply}"),
            };
        }
        let reply = match groups.upgrade() {
            Some(groups) => handle(&groups, timers, request),
            None => error("shutting down").to_string(),
        };
        writeln!(writer, "{reply}")?;
    }
}

/// The segment name of a `watch` request, if it is one.
fn watch_arg(request: &str) -> Option<&str> {
    let (command, arg) = request.split_once(char::is_whitespace).unwrap_or((request, ""));
    command.eq_ignore_ascii_case("watch").then(|| arg.trim())
}

/// Start following the devices of the named segment, on every interface and
/// family of it. The receiver ends when the segments are dropped.
fn follow(groups: &[Group], name: &str) -> Result<(String, Receiver<Notice>), Value> {
    let name = segment_arg(name);
    if name.is_empty() {
        return Err(error("usage: watch <segment name>"));
    }
    let members: Vec<&Group> = groups.iter().filter(|g| g.name == name).collect();
    if members.is_empty() {
        return Err(error(&format!("no such segment: {name}")));
    }
    let (tx, rx) = mpsc::channel();
    for group in members {
        group.reflector.watch(tx.clone());
    }
    Ok((name.to_string(), rx))
}

/// Send what happens to the segment's devices, a line each, until the client
/// goes away or the daemon stops.
fn stream_events(writer: &mut UnixStream, name: &str, events: &Receiver<Notice>) -> io::Result<()> {
    writer.set_write_timeout(Some(STREAM_WRITE))?;
    writeln!(writer, "{}", json!({ "ok": true, "name": name, "watching": true }))?;
    loop {
        match events.recv_timeout(STREAM_CHECK) {
            Ok(notice) => writeln!(writer, "{}", notice_json(name, &notice))?,
            Err(RecvTimeoutError::Timeout) => {
                if client_gone(writer)? {
                    return Ok(());
                }
            }
            Err(RecvTimeoutError::Disconnected) => return writeln!(writer, "{}", error("shutting down")),
        }
    }
}

/// Has the client hung up (or sent something, which a watch does not
/// expect)? Looks without consuming or waiting.
fn client_gone(stream: &UnixStream) -> io::Result<bool> {
    let mut byte = 0u8;
    // SAFETY: the descriptor is open for the life of `stream`, and `byte` is
    // one writable byte.
    let n = unsafe {
        libc::recv(stream.as_raw_fd(), (&mut byte as *mut u8).cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT)
    };
    if n >= 0 {
        return Ok(true);
    }
    match io::Error::last_os_error() {
        e if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
        e => Err(e),
    }
}

fn notice_json(segment: &str, notice: &Notice) -> Value {
    let (event, device) = match &notice.event {
        Event::Added(d) => ("added", d),
        Event::Updated(d) => ("updated", d),
        Event::Removed(d) => ("removed", d),
    };
    json!({
        "event": event,
        "segment": segment,
        "ttl": notice.ttl.as_secs(),
        "device": device_json(&notice.interface, notice.family, device),
    })
}

/// Answer one request line with one line of JSON.
pub fn handle(groups: &[Group], timers: &Watcher, request: &str) -> String {
    let (command, arg) = match request.split_once(char::is_whitespace) {
        Some((command, arg)) => (command, arg.trim()),
        None => (request, ""),
    };
    match command.to_ascii_lowercase().as_str() {
        "segments" => segments(groups),
        "devices" => devices(groups, arg),
        "probe" => probe(groups, arg),
        "timers" => timer_list(groups, timers),
        "watch" => error("watch streams events: it needs a connection of its own"),
        "" => error("empty request"),
        other => error(&format!("unknown command {other:?}; try: segments, devices <name>, probe [name], watch <name>, timers")),
    }
    .to_string()
}

fn segments(groups: &[Group]) -> Value {
    let mut names: Vec<&str> = Vec::new();
    for g in groups {
        if !names.contains(&g.name.as_str()) {
            names.push(&g.name);
        }
    }

    let list: Vec<Value> = names
        .into_iter()
        .map(|name| {
            let members: Vec<&Group> = groups.iter().filter(|g| g.name == name).collect();
            let interfaces: Vec<&str> = members[0].reflector.segments().iter().map(Segment::interface).collect();
            let mut families: Vec<&str> = members.iter().map(|g| family_name(g.family)).collect();
            families.sort_unstable();
            json!({ "name": name, "interfaces": interfaces, "families": families })
        })
        .collect();
    json!({ "ok": true, "segments": list })
}

/// A segment name argument, with optional surrounding quotes removed.
fn segment_arg(arg: &str) -> &str {
    arg.strip_prefix('"').and_then(|n| n.strip_suffix('"')).unwrap_or(arg)
}

fn devices(groups: &[Group], name: &str) -> Value {
    let name = segment_arg(name);
    if name.is_empty() {
        return error("usage: devices <segment name>");
    }
    let members: Vec<&Group> = groups.iter().filter(|g| g.name == name).collect();
    if members.is_empty() {
        return error(&format!("no such segment: {name}"));
    }

    let mut list = Vec::new();
    for g in members {
        for seg in g.reflector.segments() {
            let mut found = seg.devices();
            found.sort_by_key(|d| (d.key(), d.routable, d.link_local));
            list.extend(found.iter().map(|d| device(seg, d)));
        }
    }
    json!({ "ok": true, "name": name, "devices": list })
}

/// Probe every interface of the named segment, or of all segments. An
/// interface shared by several segments is probed once.
fn probe(groups: &[Group], name: &str) -> Value {
    let name = segment_arg(name);
    let members: Vec<&Group> = groups.iter().filter(|g| name.is_empty() || g.name == name).collect();
    if members.is_empty() {
        return error(&format!("no such segment: {name}"));
    }

    let mut links: Vec<&Segment> = Vec::new();
    for seg in members.iter().flat_map(|g| g.reflector.segments()) {
        if !links.iter().any(|l| l.interface() == seg.interface() && l.family() == seg.family()) {
            links.push(seg);
        }
    }

    // The links are independent, so probe them together: the reply takes one
    // probe's time, not one per interface.
    let results: Vec<Value> = thread::scope(|scope| {
        let running: Vec<_> = links
            .iter()
            .map(|&seg| scope.spawn(move || (seg, seg.probe())))
            .collect();
        running
            .into_iter()
            .map(|handle| {
                let (seg, result) = handle.join().expect("probe thread panicked");
                let (queries, err) = match result {
                    Ok(n) => (Some(n), None),
                    Err(e) => (None, Some(format!("{e:#}"))),
                };
                json!({
                    "interface": seg.interface(),
                    "family": family_name(seg.family()),
                    "queries": queries,
                    "error": err,
                })
            })
            .collect()
    });
    json!({ "ok": true, "probed": results })
}

fn timer_list(groups: &[Group], timers: &Watcher) -> Value {
    let Some(all) = timers.snapshot() else {
        return error("the timer is not running");
    };
    let now = Instant::now();
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);

    // What each link's timer is waiting for, by the id of its entry. A link
    // that is in several segments is asked once.
    let mut links: Vec<&Segment> = Vec::new();
    for seg in groups.iter().flat_map(|g| g.reflector.segments()) {
        if !links.iter().any(|l| l.interface() == seg.interface() && l.family() == seg.family()) {
            links.push(seg);
        }
    }
    let mut pending: HashMap<u64, Vec<Value>> = links
        .into_iter()
        .filter_map(|seg| {
            let waiting = seg
                .pending()
                .into_iter()
                .map(|p| json!({ "what": p.what, "who": p.who, "due_in_ms": ms(p.at.saturating_duration_since(now)) }))
                .collect();
            Some((seg.timer_id()?, waiting))
        })
        .collect();
    let list: Vec<Value> = all
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "running": t.running,
                "due_in_ms": t.due.map(|at| ms(at.saturating_duration_since(now))),
                "runs": t.runs,
                "last_run_ago_ms": t.last_run.map(|at| ms(now.saturating_duration_since(at))),
                "last_took_us": t.last_took.map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
                "pending": pending.remove(&t.id).unwrap_or_default(),
            })
        })
        .collect();
    json!({ "ok": true, "timers": list })
}

fn device(seg: &Segment, d: &Device) -> Value {
    device_json(seg.interface(), seg.family(), d)
}

fn device_json(interface: &str, family: Family, d: &Device) -> Value {
    let services: Vec<Value> = d
        .services
        .iter()
        .map(|s| {
            json!({
                "instance": s.instance,
                "type": s.kind,
                "port": s.port,
                "target": s.target,
                "txt": s.txt,
            })
        })
        .collect();
    json!({
        "interface": interface,
        "family": family_name(family),
        "hostname": d.hostname,
        "routable": d.routable.map(|a| a.to_string()),
        "link_local": d.link_local.map(|a| a.to_string()),
        "services": services,
    })
}

fn family_name(family: Family) -> &'static str {
    match family {
        Family::V4 => "v4",
        Family::V6 => "v6",
    }
}

fn error(message: &str) -> Value {
    json!({ "ok": false, "error": message })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use super::*;
    use crate::parser::{Header, Message, RData, Record};
    use crate::reflector::Reflector;

    fn group(name: &str, family: Family, interfaces: &[&str]) -> (Group, Vec<Segment>) {
        let segs: Vec<Segment> = interfaces.iter().map(|i| Segment::new(i, family)).collect();
        let reflector = Reflector::new(segs.clone()).unwrap();
        (Group { name: name.into(), family, reflector }, segs)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rec(name: &str, data: RData) -> Record {
        Record { name: name.into(), class: 1, cache_flush: false, ttl: 120, data }
    }

    /// Make `seg` hear a full announcement from `from`.
    fn announce(seg: &Segment, from: &str, host: &str, instance: &str) {
        let addr: Ipv4Addr = from.parse().unwrap();
        let msg = Message {
            header: Header { id: 0, response: true, opcode: 0, authoritative: true, truncated: false, rcode: 0 },
            questions: vec![],
            answers: vec![
                rec(host, RData::A(addr)),
                rec("_http._tcp.local", RData::Ptr(format!("{instance}._http._tcp.local"))),
                rec(
                    &format!("{instance}._http._tcp.local"),
                    RData::Srv { priority: 0, weight: 0, port: 80, target: host.into() },
                ),
                rec(&format!("{instance}._http._tcp.local"), RData::Txt(vec![b"k=v".to_vec()])),
            ],
            authorities: vec![],
            additionals: vec![],
        };
        seg.handle(SocketAddr::new(IpAddr::V4(addr), 5353), &msg.encode().unwrap()).unwrap();
    }

    #[test]
    fn lists_the_timers_soonest_first() {
        let timer = crate::timer::Timer::new().unwrap();
        let _later = timer.schedule("later", Duration::from_secs(600), || crate::timer::Next::Stop);
        let _sooner = timer.schedule("sooner", Duration::from_secs(60), || crate::timer::Next::Stop);
        let _never = timer.schedule("never", Duration::MAX, || crate::timer::Next::Stop);

        let reply: Value = serde_json::from_str(&handle(&[], &timer.watcher(), "timers")).unwrap();
        assert_eq!(reply["ok"], true);
        let list = reply["timers"].as_array().unwrap();
        let names: Vec<&str> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["sooner", "later", "never"]);

        let due = list[0]["due_in_ms"].as_u64().unwrap();
        assert!((59_000..=60_000).contains(&due), "{due}");
        assert_eq!(list[0]["running"], false);
        assert_eq!(list[0]["runs"], 0);
        assert!(list[0]["last_run_ago_ms"].is_null() && list[0]["last_took_us"].is_null());
        assert!(list[2]["due_in_ms"].is_null());
        assert!(list[0]["id"].is_u64());
    }

    #[test]
    fn timers_say_what_each_one_is_waiting_for() {
        let timer = crate::timer::Timer::new().unwrap();
        let (g, segs) = group("IoT", Family::V4, &["wifi"]);
        let (g2, _) = group("other", Family::V4, &["eth"]);
        segs[0].schedule(&timer, Some(Duration::from_secs(30)));
        segs[0].observe(ip("10.0.1.7"));

        let reply: Value = serde_json::from_str(&handle(&[g, g2], &timer.watcher(), "timers")).unwrap();
        let list = reply["timers"].as_array().unwrap();
        assert_eq!(list.len(), 1, "only wifi was scheduled");
        assert_eq!(list[0]["name"], "upkeep wifi/V4");
        let pending = list[0]["pending"].as_array().unwrap();
        assert_eq!(pending.len(), 1, "an unnamed device is only expired");
        assert_eq!((pending[0]["what"].as_str(), pending[0]["who"].as_str()), (Some("expire"), Some("10.0.1.7")));
        let due = pending[0]["due_in_ms"].as_u64().unwrap();
        assert!((299_000..=300_000).contains(&due), "{due}");
        // The timer is set for it.
        assert!(list[0]["due_in_ms"].as_u64().unwrap().abs_diff(due) < 1000);
    }

    #[test]
    fn timers_reports_a_timer_that_is_gone() {
        let reply: Value = serde_json::from_str(&handle(&[], &Watcher::default(), "timers")).unwrap();
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("timer"));
    }

    #[test]
    fn lists_segments_merging_families() {
        let (m4, _) = group("media", Family::V4, &["a", "b"]);
        let (m6, _) = group("media", Family::V6, &["a", "b"]);
        let (iot, _) = group("iot", Family::V4, &["c"]);
        let groups = [m4, m6, iot];
        assert_eq!(
            handle(&groups, &Watcher::default(), "segments"),
            r#"{"ok":true,"segments":[{"name":"media","interfaces":["a","b"],"families":["v4","v6"]},{"name":"iot","interfaces":["c"],"families":["v4"]}]}"#
        );
    }

    #[test]
    fn lists_devices_of_a_segment() {
        let (iot, segs) = group("IoT to br0", Family::V4, &["c"]);
        segs[0].observe(ip("10.0.3.9"));
        assert_eq!(
            handle(&[iot], &Watcher::default(), r#"devices "IoT to br0""#),
            r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"c","family":"v4","hostname":null,"routable":"10.0.3.9","link_local":null,"services":[]}]}"#
        );
    }

    #[test]
    fn devices_carry_services_and_escape_json() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", r#"My "TV""#);
        segs[1].observe(ip("10.0.2.1"));
        let out = handle(&[g], &Watcher::default(), "DEVICES media");
        assert!(
            out.contains(r#""interface":"a","family":"v4","hostname":"tv.local","routable":"10.0.1.5","link_local":null"#),
            "{out}"
        );
        assert!(
            out.contains(r#"{"instance":"My \"TV\"._http._tcp.local","type":"_http._tcp.local","port":80,"target":"tv.local","txt":["k=v"]}"#),
            "{out}"
        );
        assert!(out.contains(r#""interface":"b","family":"v4","hostname":null,"routable":"10.0.2.1""#), "{out}");
        // Interface order is preserved.
        assert!(out.find(r#""interface":"a""#) < out.find(r#""interface":"b""#));
    }

    #[test]
    fn reflected_copies_are_not_listed() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", "TV");
        std::thread::sleep(Duration::from_millis(150));
        assert!(!segs[1].manual_devices().is_empty(), "precondition: reflected onto b");
        let out = handle(&[g], &Watcher::default(), "devices media");
        assert_eq!(out.matches("\"routable\"").count(), 1, "{out}");
    }

    #[test]
    fn probes_each_interface_once_even_when_segments_share_it() {
        let (a, b, c) = (
            Segment::new("a", Family::V4),
            Segment::new("b", Family::V4),
            Segment::new("c", Family::V4),
        );
        let groups = [
            Group { name: "x".into(), family: Family::V4, reflector: Reflector::new(vec![a.clone(), b.clone()]).unwrap() },
            Group { name: "y".into(), family: Family::V4, reflector: Reflector::new(vec![a, c]).unwrap() },
        ];
        let interfaces = |request: &str| -> Vec<String> {
            let reply: Value = serde_json::from_str(&handle(&groups, &Watcher::default(), request)).unwrap();
            assert_eq!(reply["ok"], true, "{reply}");
            reply["probed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["interface"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(interfaces("probe"), ["a", "b", "c"]);
        assert_eq!(interfaces("probe x"), ["a", "b"]);
        assert_eq!(interfaces(r#"probe "y""#), ["a", "c"]);
    }

    #[test]
    fn probe_reports_what_was_sent_per_interface() {
        let (g, _segs) = group("media", Family::V4, &["a"]);
        // No sender is attached in tests, so nothing is sent.
        assert_eq!(
            handle(&[g], &Watcher::default(), "probe media"),
            r#"{"ok":true,"probed":[{"interface":"a","family":"v4","queries":0,"error":null}]}"#
        );
    }

    #[test]
    fn reports_errors() {
        let (g, _) = group("media", Family::V4, &["a", "b"]);
        let groups = [g];
        for (request, expect) in [
            ("devices nope", "no such segment: nope"),
            ("probe nope", "no such segment: nope"),
            ("devices", "usage"),
            ("", "empty request"),
            ("frobnicate", "unknown command"),
        ] {
            let out = handle(&groups, &Watcher::default(), request);
            assert!(out.starts_with(r#"{"ok":false,"error":""#) && out.contains(expect), "{request}: {out}");
        }
    }

    /// Names come off the network and may contain anything; a reply must
    /// still be exactly one line, or a device could forge extra replies.
    #[test]
    fn replies_stay_on_one_line_whatever_the_names_contain() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", "My\nTV\"\\");
        let out = handle(&[g], &Watcher::default(), "devices media");
        assert!(!out.contains('\n'), "{out}");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["devices"][0]["services"][0]["instance"],
            "My\nTV\"\\._http._tcp.local"
        );
    }

    fn temp_socket(tag: &str) -> PathBuf {
        // Unix socket paths are limited to ~108 bytes, so stay relative to
        // the package root (cargo's test working directory).
        fs::create_dir_all("target").unwrap();
        let path = PathBuf::from(format!("target/mdnsd-test-{}-{tag}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    fn ask(stream: &mut UnixStream, reader: &mut BufReader<UnixStream>, request: &str) -> String {
        writeln!(stream, "{request}").unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line.trim_end().to_string()
    }

    #[test]
    fn serves_requests_over_the_socket() {
        let (g, segs) = group("IoT", Family::V4, &["wifi"]);
        segs[0].observe(ip("10.0.1.7"));
        let path = temp_socket("serve");
        let groups = Arc::new(vec![g]);
        serve(&path, &groups, Watcher::default()).unwrap();

        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o660);

        let mut stream = UnixStream::connect(&path).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        // Several requests on one connection.
        assert!(ask(&mut stream, &mut reader, "segments").contains(r#""name":"IoT""#));
        assert!(ask(&mut stream, &mut reader, "devices IoT").contains(r#""routable":"10.0.1.7""#));
        assert!(ask(&mut stream, &mut reader, "bogus").contains(r#""ok":false"#));

        // Oversized requests are refused and the connection closed.
        let mut big = UnixStream::connect(&path).unwrap();
        big.write_all(&vec![b'x'; MAX_LINE as usize + 10]).unwrap();
        let mut reply = String::new();
        BufReader::new(big).read_line(&mut reply).unwrap();
        assert!(reply.contains("request too long"));

        // Once the owner lets go of the segments, the server does not hold
        // them alive and says so.
        drop(groups);
        assert!(ask(&mut stream, &mut reader, "segments").contains("shutting down"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn watch_streams_changes_without_holding_the_segments() {
        let (g, segs) = group("IoT", Family::V4, &["wifi"]);
        let path = temp_socket("watch");
        let groups = Arc::new(vec![g]);
        serve(&path, &groups, Watcher::default()).unwrap();

        let mut stream = UnixStream::connect(&path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        assert_eq!(ask(&mut stream, &mut reader, "WATCH IoT"), r#"{"ok":true,"name":"IoT","watching":true}"#);
        // The stream does not keep the daemon from letting go of the segments.
        assert_eq!(Arc::strong_count(&groups), 1);

        let mut next = || {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<Value>(&line).unwrap()
        };
        segs[0].observe(ip("10.0.1.7"));
        let added = next();
        assert_eq!((added["event"].as_str(), added["segment"].as_str()), (Some("added"), Some("IoT")));
        assert_eq!(added["ttl"], 300);
        assert_eq!(added["device"]["interface"], "wifi");
        assert_eq!(added["device"]["routable"], "10.0.1.7");

        segs[0].expire(Instant::now() + Duration::from_secs(3600));
        let removed = next();
        assert_eq!(removed["event"], "removed");
        assert_eq!(removed["ttl"], 0);
        assert_eq!(removed["device"]["routable"], "10.0.1.7");

        // Failures are ordinary replies, and the connection can go on.
        let mut other = UnixStream::connect(&path).unwrap();
        let mut other_reader = BufReader::new(other.try_clone().unwrap());
        assert!(ask(&mut other, &mut other_reader, "watch nope").contains("no such segment: nope"));
        let mut other = UnixStream::connect(&path).unwrap();
        let mut other_reader = BufReader::new(other.try_clone().unwrap());
        assert!(ask(&mut other, &mut other_reader, "watch").contains("usage: watch"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn watch_is_refused_where_it_cannot_stream() {
        let reply: Value = serde_json::from_str(&handle(&[], &Watcher::default(), "watch IoT")).unwrap();
        assert_eq!(reply["ok"], false);
    }

    #[test]
    fn bind_replaces_stale_sockets_but_not_live_ones_or_files() {
        let path = temp_socket("bind");
        drop(UnixListener::bind(&path).unwrap()); // leaves a dead socket file
        let live = bind(&path).expect("stale socket is replaced");
        assert!(bind(&path).is_err(), "live instance is protected");
        drop(live);
        fs::remove_file(&path).unwrap();

        fs::write(&path, "precious").unwrap();
        assert!(bind(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "precious");
        fs::remove_file(&path).unwrap();
    }
}
