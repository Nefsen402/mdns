//! Local control socket.
//!
//! A Unix stream socket speaking one request per line and answering each with
//! one line of JSON. A connection may send any number of requests.
//!
//! ```text
//! segments
//!   {"ok":true,"segments":[{"name":"IoT","interfaces":["wifi"],"untrusted":[],"families":["v4","v6"]}]}
//! devices [--query=<type>]... <segment name>
//!   {"ok":true,"name":"IoT","devices":[{"interface":"wifi","hostname":"tv.local",
//!    "addresses":["10.0.1.7","fd00:0:1::7","fe80::7"],"address_ttl":120,
//!    "services":[{"instance":...}]}]}
//! probe [<segment name>]
//!   {"ok":true,"probed":[{"interface":"wifi","queries":14,"error":null}]}
//! watch [--query=<type>]... [--interval=<seconds>] <segment name>
//!   {"ok":true,"name":"IoT","watching":true}
//!   {"event":"present","segment":"IoT","ttl":300,"device":{...}}   (--query only)
//!   {"event":"added","segment":"IoT","ttl":4500,"device":{...as in devices...}}
//!   {"event":"removed","segment":"IoT","ttl":0,"device":{...}}
//! timers
//!   {"ok":true,"timers":[{"id":1,"name":"upkeep wifi","running":false,
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
//! `--query=` names a service type (`_shelly._tcp`, `.local` optional) to
//! ask for by name on every interface of the segment, and narrows the reply
//! to the devices of that type, each with only its services of that type;
//! it may be given more than once. Many devices answer only when asked for
//! their type, and not when asked what types there are, so neither a probe
//! nor waiting finds them. `devices` replies once the asking is done, about
//! four seconds later, with what answered and what was known already.
//! `watch` first sends a `present` line for each device of the type already
//! known, asks, and with `--interval=` asks again that often (at least
//! every ten seconds, never more often). A device that loses its last
//! service of the type is `removed` from the watch. The types asked for are
//! remembered, so probes ask for them from then on.
//!
//! `timers` lists what the daemon's timer has scheduled, soonest first, for
//! debugging. `due_in_ms` is 0 for one that is overdue (its callback is queued
//! behind another) and `null` for one that is running now or never due;
//! `last_run_ago_ms` and `last_took_us` are `null` until it has run. A link's
//! `upkeep` timer is set for the first of its `pending` list: everything it is
//! waiting to do, soonest first, as `what` (`expire`, `refresh` or
//! `re-announce`), to `who` (a hostname, or the address of a device that has
//! none, or a hostname and one of its addresses, for that address running out
//! on its own), and `due_in_ms` from now (0 if it is due).
//! 
//!
//! A device is listed once, whichever family it was heard over, with its
//! `addresses` of both: routable ones first (IPv4, then global or ULA IPv6),
//! then link-local ones (`169.254/16`, `fe80::/10`), which only mean something
//! on the device's own link. Up to eight of a family; empty when it announced
//! none and was not heard from.
//!
//! The TTLs a device announced itself with are kept: `address_ttl` for its
//! address records and `ttl` for each service (the SRV record's, else the PTR's
//! or TXT's), in seconds, `null` when not known. A reflected copy is announced
//! with them, unless the configuration says otherwise.

use std::collections::{HashMap, HashSet};
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
use crate::device::{is_type, Device};
use crate::socket::{Event, Family, Segment};
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

/// The least a watch's `--interval=` may be: asking takes about four seconds,
/// and asking more often than this is only noise.
const MIN_QUERY_INTERVAL: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });

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
        if let Some(arg) = watch_arg(request) {
            // Hold the segments only long enough to register: a stream that
            // lasts must not keep the daemon from releasing them at shutdown.
            let registered = match groups.upgrade() {
                Some(groups) => follow(&groups, arg),
                None => Err(error("shutting down")),
            };
            return match registered {
                Ok(watch) => stream_events(&mut writer, groups, watch),
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

/// The arguments of a `watch` request, if it is one.
fn watch_arg(request: &str) -> Option<&str> {
    let (command, arg) = request.split_once(char::is_whitespace).unwrap_or((request, ""));
    command.eq_ignore_ascii_case("watch").then(|| arg.trim())
}

/// What a `devices` or `watch` request asks for besides its segment.
#[derive(Debug, Default, PartialEq, Eq)]
struct Query {
    /// The service types to ask for by name, and to narrow the reply to;
    /// none for every device.
    kinds: Vec<String>,
    /// How often a watch asks for them again.
    interval: Option<Duration>,
}

/// The `--query=` and `--interval=` options `arg` starts with, and the
/// segment name after them.
fn query_args(arg: &str) -> Result<(Query, &str), Value> {
    let mut query = Query::default();
    let mut rest = arg.trim_start();
    while rest.starts_with("--") {
        let (option, after) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        rest = after.trim_start();
        if let Some(kind) = option.strip_prefix("--query=") {
            let kind = service_type(kind)?;
            if !query.kinds.iter().any(|k| k.eq_ignore_ascii_case(&kind)) {
                query.kinds.push(kind);
            }
        } else if let Some(secs) = option.strip_prefix("--interval=") {
            let secs = secs.parse().ok().filter(|&s| s >= MIN_QUERY_INTERVAL.as_secs()).ok_or_else(|| {
                error(&format!("invalid --interval {secs:?}: whole seconds, at least {}", MIN_QUERY_INTERVAL.as_secs()))
            })?;
            query.interval = Some(Duration::from_secs(secs));
        } else {
            return Err(error(&format!("unknown option {option}")));
        }
    }
    if query.interval.is_some() && query.kinds.is_empty() {
        return Err(error("--interval needs a --query to ask again"));
    }
    Ok((query, rest))
}

/// `name` as a full service type, `.local` added if it was left off.
fn service_type(name: &str) -> Result<String, Value> {
    let name = name.trim_end_matches('.');
    let full = if name.to_ascii_lowercase().ends_with(".local") { name.to_string() } else { format!("{name}.local") };
    if is_type(&full) {
        Ok(full)
    } else {
        Err(error(&format!("not a service type: {name:?} (like _http._tcp)")))
    }
}

/// The interfaces of the named segment, or of all segments if `name` is
/// empty, each once.
fn links_of<'a>(groups: &'a [Group], name: &str) -> Vec<&'a Segment> {
    let mut links: Vec<&Segment> = Vec::new();
    for seg in groups.iter().filter(|g| name.is_empty() || g.name == name).flat_map(|g| g.reflector.segments()) {
        if !links.iter().any(|l| l.interface() == seg.interface()) {
            links.push(seg);
        }
    }
    links
}

/// Run `f` on each of `links` at once, as they are independent: it takes
/// one's time, not one per interface. What each returned, as `probe` and
/// `devices --query` report it.
fn on_each(links: &[&Segment], f: impl Fn(&Segment) -> Result<usize> + Sync) -> Vec<Value> {
    thread::scope(|scope| {
        let f = &f;
        let running: Vec<_> = links.iter().map(|&seg| scope.spawn(move || (seg, f(seg)))).collect();
        running
            .into_iter()
            .map(|handle| {
                let (seg, result) = handle.join().expect("query thread panicked");
                let (queries, err) = match result {
                    Ok(n) => (Some(n), None),
                    Err(e) => (None, Some(format!("{e:#}"))),
                };
                json!({ "interface": seg.interface(), "queries": queries, "error": err })
            })
            .collect()
    })
}

/// A watch on a segment, as registered.
struct Watch {
    name: String,
    query: Query,
    events: Receiver<Notice>,
    /// With a query, the devices of its types known when it started, as
    /// `present` lines.
    present: Vec<Value>,
}

/// Start following the devices of the named segment, on every interface and
/// family of it. The receiver ends when the segments are dropped.
fn follow(groups: &[Group], arg: &str) -> Result<Watch, Value> {
    let (query, name) = query_args(arg)?;
    let name = segment_arg(name);
    if name.is_empty() {
        return Err(error("usage: watch [--query=<type>]... [--interval=<seconds>] <segment name>"));
    }
    let members: Vec<&Group> = groups.iter().filter(|g| g.name == name).collect();
    if members.is_empty() {
        return Err(error(&format!("no such segment: {name}")));
    }
    let (tx, rx) = mpsc::channel();
    for group in &members {
        group.reflector.watch(tx.clone());
    }
    let mut present = Vec::new();
    if !query.kinds.is_empty() {
        for seg in links_of(groups, name) {
            for device in seg.devices().iter().filter_map(|d| d.only_kinds(&query.kinds)) {
                let ttl = seg.lifetime_left(&device);
                let notice = Notice { interface: seg.interface().to_string(), event: Event::Added(device), ttl };
                present.push(event_json("present", name, &notice));
            }
        }
    }
    Ok(Watch { name: name.to_string(), query, events: rx, present })
}

/// Ask for the types of `query` on the interfaces of the named segment, in
/// the background, holding the segments only while asking.
fn ask_in_background(groups: &Weak<Vec<Group>>, name: &str, kinds: &[String]) {
    let (groups, name, kinds) = (groups.clone(), name.to_string(), kinds.to_vec());
    thread::spawn(move || {
        if let Some(groups) = groups.upgrade() {
            on_each(&links_of(&groups, &name), |seg| seg.query_types(&kinds));
        }
    });
}

/// Send what happens to the segment's devices, a line each, until the client
/// goes away or the daemon stops. With a query, only devices of its types,
/// asked for at the start and every interval.
fn stream_events(writer: &mut UnixStream, groups: &Weak<Vec<Group>>, watch: Watch) -> io::Result<()> {
    let Watch { name, query, events, present } = watch;
    writer.set_write_timeout(Some(STREAM_WRITE))?;
    writeln!(writer, "{}", json!({ "ok": true, "name": name, "watching": true }))?;
    // The devices of the query's types shown, so that one that loses its last
    // service of them is shown to go.
    let mut shown: HashSet<(String, String)> = HashSet::new();
    for line in &present {
        if let (Some(interface), Some(host)) = (line["device"]["interface"].as_str(), line["device"]["hostname"].as_str()) {
            shown.insert((interface.to_string(), host.to_ascii_lowercase()));
        }
        writeln!(writer, "{line}")?;
    }
    let mut next_ask = (!query.kinds.is_empty()).then(Instant::now);
    loop {
        if let Some(at) = next_ask.filter(|&at| at <= Instant::now()) {
            ask_in_background(groups, &name, &query.kinds);
            next_ask = query.interval.map(|every| at + every);
        }
        let wait = next_ask.map_or(STREAM_CHECK, |at| at.saturating_duration_since(Instant::now()).min(STREAM_CHECK));
        match events.recv_timeout(wait) {
            Ok(notice) => {
                let line = if query.kinds.is_empty() {
                    notice_json(&name, &notice)
                } else {
                    narrowed(&name, notice, &query.kinds, &mut shown)
                };
                if let Some(json) = line {
                    writeln!(writer, "{json}")?;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if client_gone(writer)? {
                    return Ok(());
                }
            }
            Err(RecvTimeoutError::Disconnected) => return writeln!(writer, "{}", error("shutting down")),
        }
    }
}

/// A change as a watch for the service types `kinds` shows it: the device
/// with only its services of those types, if it has any, or its going, if
/// it had and no longer has; `None` for one it never showed.
fn narrowed(segment: &str, notice: Notice, kinds: &[String], shown: &mut HashSet<(String, String)>) -> Option<Value> {
    let (removed, device) = match &notice.event {
        Event::Added(d) | Event::Updated(d) => (false, d),
        Event::Removed(d) => (true, d),
        Event::Question(_) => return None,
    };
    let key = device.key().map(|k| (notice.interface.clone(), k));
    let was_shown = key.as_ref().is_some_and(|k| shown.contains(k));
    match device.only_kinds(kinds) {
        Some(narrow) if !removed => {
            let kind = match &notice.event {
                Event::Added(_) => "added",
                _ if was_shown => "updated",
                _ => "added",
            };
            if let Some(key) = key {
                shown.insert(key);
            }
            Some(event_json(kind, segment, &Notice { event: Event::Updated(narrow), ..notice }))
        }
        // Gone, or no longer of the types: gone from the watch. One without
        // a hostname cannot be told apart, so its going is shown whenever it
        // was of the types.
        narrow if was_shown || (key.is_none() && narrow.is_some()) => {
            if let Some(key) = &key {
                shown.remove(key);
            }
            let gone = narrow.unwrap_or_else(|| Device { services: Vec::new(), ..device.clone() });
            Some(event_json("removed", segment, &Notice { event: Event::Removed(gone), ttl: Duration::ZERO, ..notice }))
        }
        _ => None,
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

/// A device's change as `watch` shows it; `None` for what is not one.
fn notice_json(segment: &str, notice: &Notice) -> Option<Value> {
    let event = match &notice.event {
        Event::Added(_) => "added",
        Event::Updated(_) => "updated",
        Event::Removed(_) => "removed",
        Event::Question(_) => return None,
    };
    Some(event_json(event, segment, notice))
}

/// A watch line saying `event` of the device of `notice`.
fn event_json(event: &str, segment: &str, notice: &Notice) -> Value {
    let device = match &notice.event {
        Event::Added(d) | Event::Updated(d) | Event::Removed(d) => device_json(&notice.interface, d),
        Event::Question(_) => Value::Null,
    };
    json!({ "event": event, "segment": segment, "ttl": notice.ttl.as_secs(), "device": device })
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
        other => error(&format!(
            "unknown command {other:?}; try: segments, devices [--query=<type>] <name>, probe [name], watch <name>, timers"
        )),
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
            let mut families: Vec<&str> = members
                .iter()
                .flat_map(|g| g.reflector.segments())
                .flat_map(|seg| seg.families().iter().map(|&f| family_name(f)))
                .collect();
            families.sort_unstable();
            families.dedup();
            let untrusted = members[0].reflector.untrusted();
            json!({ "name": name, "interfaces": interfaces, "untrusted": untrusted, "families": families })
        })
        .collect();
    json!({ "ok": true, "segments": list })
}

/// A segment name argument, with optional surrounding quotes removed.
fn segment_arg(arg: &str) -> &str {
    arg.strip_prefix('"').and_then(|n| n.strip_suffix('"')).unwrap_or(arg)
}

fn devices(groups: &[Group], arg: &str) -> Value {
    let (query, name) = match query_args(arg) {
        Ok(parsed) => parsed,
        Err(reply) => return reply,
    };
    if query.interval.is_some() {
        return error("--interval is for watch: devices asks once");
    }
    let name = segment_arg(name);
    if name.is_empty() {
        return error("usage: devices [--query=<type>]... <segment name>");
    }
    let members: Vec<&Group> = groups.iter().filter(|g| g.name == name).collect();
    if members.is_empty() {
        return error(&format!("no such segment: {name}"));
    }
    if !query.kinds.is_empty() {
        on_each(&links_of(groups, name), |seg| seg.query_types(&query.kinds));
    }

    let mut list = Vec::new();
    for g in members {
        for seg in g.reflector.segments() {
            let mut found = seg.devices();
            if !query.kinds.is_empty() {
                found = found.iter().filter_map(|d| d.only_kinds(&query.kinds)).collect();
            }
            found.sort_by_key(|d| (d.key(), d.addrs().collect::<Vec<_>>()));
            list.extend(found.iter().map(|d| device_json(seg.interface(), d)));
        }
    }
    json!({ "ok": true, "name": name, "devices": list })
}

/// Probe every interface of the named segment, or of all segments. An
/// interface shared by several segments is probed once.
fn probe(groups: &[Group], name: &str) -> Value {
    let name = segment_arg(name);
    let links = links_of(groups, name);
    if links.is_empty() {
        return error(&format!("no such segment: {name}"));
    }
    json!({ "ok": true, "probed": on_each(&links, Segment::probe) })
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
        if !links.iter().any(|l| l.interface() == seg.interface()) {
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

fn device_json(interface: &str, d: &Device) -> Value {
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
                "subtypes": s.subtypes,
                "ttl": (s.ttl != 0).then_some(s.ttl),
            })
        })
        .collect();
    json!({
        "interface": interface,
        "hostname": d.hostname,
        "addresses": d.addrs().map(|a| a.to_string()).collect::<Vec<_>>(),
        "address_ttl": d.ttl,
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
        let segs: Vec<Segment> = interfaces.iter().map(|i| Segment::new(i, &[family])).collect();
        let reflector = Reflector::new(0, segs.clone()).unwrap();
        (Group { name: name.into(), reflector }, segs)
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
        assert_eq!(list[0]["name"], "upkeep wifi");
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
            r#"{"ok":true,"segments":[{"name":"media","interfaces":["a","b"],"untrusted":[],"families":["v4","v6"]},{"name":"iot","interfaces":["c"],"untrusted":[],"families":["v4"]}]}"#
        );
    }

    #[test]
    fn segments_say_which_interfaces_are_untrusted() {
        let segs: Vec<Segment> = ["br0", "wifi"].iter().map(|i| Segment::new(i, &[Family::V4])).collect();
        let reflector = Reflector::with_untrusted(0, segs, &["wifi".to_string()]).unwrap();
        let groups = [Group { name: "IoT to br0".into(), reflector }];
        assert_eq!(
            handle(&groups, &Watcher::default(), "segments"),
            r#"{"ok":true,"segments":[{"name":"IoT to br0","interfaces":["br0","wifi"],"untrusted":["wifi"],"families":["v4"]}]}"#
        );
    }

    #[test]
    fn lists_devices_of_a_segment() {
        let (iot, segs) = group("IoT to br0", Family::V4, &["c"]);
        segs[0].observe(ip("10.0.3.9"));
        assert_eq!(
            handle(&[iot], &Watcher::default(), r#"devices "IoT to br0""#),
            r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"c","hostname":null,"addresses":["10.0.3.9"],"address_ttl":null,"services":[]}]}"#
        );
    }

    #[test]
    fn devices_carry_services_and_escape_json() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", r#"My "TV""#);
        segs[1].observe(ip("10.0.2.1"));
        let out = handle(&[g], &Watcher::default(), "DEVICES media");
        assert!(
            out.contains(r#""interface":"a","hostname":"tv.local","addresses":["10.0.1.5"],"address_ttl":120"#),
            "{out}"
        );
        assert!(
            out.contains(r#"{"instance":"My \"TV\"._http._tcp.local","type":"_http._tcp.local","port":80,"target":"tv.local","txt":["k=v"],"subtypes":[],"ttl":120}"#),
            "{out}"
        );
        assert!(out.contains(r#""interface":"b","hostname":null,"addresses":["10.0.2.1"]"#), "{out}");
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
        assert_eq!(out.matches("\"addresses\"").count(), 1, "{out}");
    }

    #[test]
    fn probes_each_interface_once_even_when_segments_share_it() {
        let (a, b, c) = (
            Segment::new("a", &[Family::V4]),
            Segment::new("b", &[Family::V4]),
            Segment::new("c", &[Family::V4]),
        );
        let groups = [
            Group { name: "x".into(), reflector: Reflector::new(0, vec![a.clone(), b.clone()]).unwrap() },
            Group { name: "y".into(), reflector: Reflector::new(1, vec![a, c]).unwrap() },
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
            r#"{"ok":true,"probed":[{"interface":"a","queries":0,"error":null}]}"#
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
        // Control characters are refused when heard; what is left to escape
        // is quotes and backslashes.
        // A backslash in a label is `\\` in the escaped form names are kept in.
        announce(&segs[0], "10.0.1.5", "tv.local", "My \"TV\" \\\\ back");
        let out = handle(&[g], &Watcher::default(), "devices media");
        assert!(!out.contains('\n'), "{out}");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["devices"][0]["services"][0]["instance"],
            "My \"TV\" \\\\ back._http._tcp.local"
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
        assert!(ask(&mut stream, &mut reader, "devices IoT").contains(r#""addresses":["10.0.1.7"]"#));
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
        assert_eq!(added["device"]["addresses"][0], "10.0.1.7");

        segs[0].expire(Instant::now() + Duration::from_secs(3600));
        let removed = next();
        assert_eq!(removed["event"], "removed");
        assert_eq!(removed["ttl"], 0);
        assert_eq!(removed["device"]["addresses"][0], "10.0.1.7");

        // Failures are ordinary replies, and the connection can go on.
        let mut other = UnixStream::connect(&path).unwrap();
        let mut other_reader = BufReader::new(other.try_clone().unwrap());
        assert!(ask(&mut other, &mut other_reader, "watch nope").contains("no such segment: nope"));
        let mut other = UnixStream::connect(&path).unwrap();
        let mut other_reader = BufReader::new(other.try_clone().unwrap());
        assert!(ask(&mut other, &mut other_reader, "watch").contains("usage: watch"));
        let _ = fs::remove_file(&path);
    }

    /// A segment on `interface` that sends to the returned socket.
    fn wired(interface: &str) -> (Segment, std::net::UdpSocket) {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let seg = Segment::new(interface, &[Family::V4]);
        seg.attach(Family::V4, std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), rx.local_addr().unwrap());
        (seg, rx)
    }

    /// The queries `rx` has had, as their questions' names and their known
    /// answers' count, waiting a little for the first.
    fn queries(rx: &std::net::UdpSocket) -> Vec<(Vec<String>, usize)> {
        let mut buf = [0u8; 9000];
        let mut out = Vec::new();
        while let Ok(n) = rx.recv(&mut buf) {
            let m = Message::parse(&buf[..n]).unwrap();
            if !m.header.response {
                out.push((m.questions.iter().map(|q| q.name.clone()).collect(), m.answers.len()));
            }
        }
        out
    }

    #[test]
    fn query_options_take_service_types_and_how_often_to_ask() {
        let parse = |arg: &str| query_args(arg).map(|(q, rest)| (q.kinds, q.interval.map(|d| d.as_secs()), rest.to_string()));
        assert_eq!(parse("IoT to br0"), Ok((vec![], None, "IoT to br0".into())));
        assert_eq!(
            parse("--query=_shelly._tcp --query=_Shelly._tcp.local. --query=_hue._tcp.local --interval=30 \"IoT\""),
            Ok((vec!["_shelly._tcp.local".into(), "_hue._tcp.local".into()], Some(30), "\"IoT\"".into()))
        );
        let err = |arg: &str| parse(arg).unwrap_err()["error"].as_str().unwrap().to_string();
        assert!(err("--query=shelly IoT").contains("not a service type"));
        assert!(err("--query=_a._b._tcp IoT").contains("not a service type"));
        assert!(err("--interval=0 --query=_x._tcp IoT").contains("invalid --interval"));
        assert!(err("--interval=5m --query=_x._tcp IoT").contains("invalid --interval"));
        assert!(err("--interval=30 IoT").contains("needs a --query"));
        assert!(err("--bogus IoT").contains("unknown option --bogus"));
    }

    /// `devices --query` asks for the type on every interface of the segment,
    /// and lists only devices of it, with only their services of it.
    #[test]
    fn devices_with_a_query_ask_and_list_only_that_type() {
        let (a, a_rx) = wired("a");
        let (b, b_rx) = wired("b");
        let groups = [Group { name: "IoT".into(), reflector: Reflector::new(0, vec![a.clone(), b.clone()]).unwrap() }];
        announce(&a, "10.0.1.7", "tv.local", "TV");
        a.observe(ip("10.0.1.8"));
        let reply: Value =
            serde_json::from_str(&handle(&groups, &Watcher::default(), "devices --query=_http._tcp IoT")).unwrap();
        assert_eq!(reply["ok"], true, "{reply}");
        let hosts: Vec<&str> = reply["devices"].as_array().unwrap().iter().filter_map(|d| d["hostname"].as_str()).collect();
        assert_eq!(hosts, ["tv.local"]);
        assert_eq!(reply["devices"].as_array().unwrap().len(), 1, "not the one without the type");
        let http = |rx| queries(rx).into_iter().filter(|(names, _)| names == &["_http._tcp.local"]).collect::<Vec<_>>();
        let on_a = http(&a_rx);
        assert!(on_a.len() == 3 && on_a.iter().all(|&(_, known)| known == 1), "three rounds, with the TV known: {on_a:?}");
        assert_eq!(http(&b_rx).len(), 3);

        let reply = handle(&groups, &Watcher::default(), "devices --query=_ipp._tcp IoT");
        assert!(reply.contains(r#""devices":[]"#), "{reply}");
        for (request, why) in [
            ("devices --query=_http._tcp --interval=30 IoT", "--interval is for watch"),
            ("devices --query=http IoT", "not a service type"),
            ("devices --query=_http._tcp", "usage: devices"),
        ] {
            assert!(handle(&groups, &Watcher::default(), request).contains(why), "{request}");
        }
    }

    /// `watch --query` shows the devices of the type already known as
    /// present, asks for it, then and every interval, and shows only devices
    /// of it from then on.
    #[test]
    fn watch_with_a_query_shows_what_is_there_asks_and_asks_again() {
        let (seg, rx) = wired("wifi");
        let groups = Arc::new(vec![Group { name: "IoT".into(), reflector: Reflector::new(0, vec![seg.clone()]).unwrap() }]);
        announce(&seg, "10.0.1.7", "tv.local", "TV");
        let path = temp_socket("watch-query");
        serve(&path, &groups, Watcher::default()).unwrap();

        let mut stream = UnixStream::connect(&path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let ack = ask(&mut stream, &mut reader, "watch --query=_http._tcp --interval=1 IoT");
        assert_eq!(ack, r#"{"ok":true,"name":"IoT","watching":true}"#);
        let mut next = || {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<Value>(&line).unwrap()
        };
        let present = next();
        assert_eq!((present["event"].as_str(), present["device"]["hostname"].as_str()), (Some("present"), Some("tv.local")));
        assert_eq!(present["ttl"], 300);

        // Asked at once, with the TV as a known answer, and again a second on.
        thread::sleep(Duration::from_millis(1500));
        let asked: Vec<_> = queries(&rx).into_iter().filter(|(names, _)| names == &["_http._tcp.local"]).collect();
        assert!(asked.len() >= 6 && asked.iter().all(|&(_, known)| known == 1), "{asked:?}");

        // One without the type is not shown; one with it is.
        seg.observe(ip("10.0.1.8"));
        announce(&seg, "10.0.1.9", "plug.local", "Plug");
        let added = next();
        assert_eq!((added["event"].as_str(), added["device"]["hostname"].as_str()), (Some("added"), Some("plug.local")));
        let _ = fs::remove_file(&path);
    }

    /// A watch for a type shows a device gaining it as added, changing as
    /// updated, losing it or going as removed, and nothing of the others.
    #[test]
    fn a_watch_for_a_type_narrows_what_it_shows() {
        let kinds = ["_http._tcp.local".to_string()];
        let mut shown = HashSet::new();
        let tv = |services: bool| {
            let seg = Segment::new("wifi", &[Family::V4]);
            announce(&seg, "10.0.1.7", "tv.local", "TV");
            let mut d = seg.devices().remove(0);
            if !services {
                d.services.clear();
            }
            d
        };
        let notice = |event| Notice { interface: "wifi".into(), event, ttl: Duration::from_secs(120) };
        let mut show = |event| narrowed("IoT", notice(event), &kinds, &mut shown).map(|v| v["event"].as_str().unwrap().to_string());

        assert_eq!(show(Event::Updated(tv(false))), None);
        assert_eq!(show(Event::Updated(tv(true))).as_deref(), Some("added"));
        assert_eq!(show(Event::Updated(tv(true))).as_deref(), Some("updated"));
        assert_eq!(show(Event::Updated(tv(false))).as_deref(), Some("removed"));
        assert_eq!(show(Event::Updated(tv(false))), None);
        assert_eq!(show(Event::Added(tv(true))).as_deref(), Some("added"));
        assert_eq!(show(Event::Removed(tv(true))).as_deref(), Some("removed"));
        assert_eq!(show(Event::Removed(tv(true))), None, "not shown since");

        // One without a hostname cannot be told apart: its going is shown.
        let mut nameless = tv(true);
        nameless.hostname = None;
        assert_eq!(show(Event::Removed(nameless)).as_deref(), Some("removed"));
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
