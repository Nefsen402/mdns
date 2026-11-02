//! Local control socket.
//!
//! A Unix stream socket speaking one request per line and answering each with
//! one line of JSON. A connection may send any number of requests.
//!
//! ```text
//! segments
//!   {"ok":true,"segments":[{"name":"IoT","interfaces":["wifi"],"untrusted":[],"families":["v4","v6"]}]}
//! devices <segment name>
//!   {"ok":true,"name":"IoT","devices":[{"interface":"wifi","hostname":"tv.local",
//!    "addresses":["10.0.1.7","fd00:0:1::7","fe80::7"],"neighbour_addresses":[],"address_ttl":120,
//!    "services":[{"instance":...}]}]}
//! probe [<segment name>]
//!   {"ok":true,"probed":[{"interface":"wifi","queries":14,"error":null}]}
//! watch [--query=<type>]... [--interval=<seconds>] <segment name>
//!   {"ok":true,"name":"IoT","watching":true}
//!   {"event":"present","segment":"IoT","ttl":300,"device":{...}}   (--query only)
//!   {"event":"added","segment":"IoT","ttl":4500,"device":{...as in devices...}}
//!   {"event":"removed","segment":"IoT","ttl":0,"device":{...}}
//! watchers
//!   {"ok":true,"watchers":[{"id":3,"segment":"IoT","query":["_shelly._tcp.local"],
//!    "interval_s":60,"pid":4242,"uid":1000,"age_ms":93000}]}
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
//! `watch --query=` names a service type (`_shelly._tcp`, `.local` optional)
//! to ask for by name on every interface of the segment, and narrows the
//! watch to the devices of that type, each with only its services of that
//! type; it may be given more than once. Many devices answer only when asked
//! for their type, and not when asked what types there are, so neither a
//! probe nor waiting finds them. The watch first sends a `present` line for
//! each device of the type already known, asks, and with `--interval=` asks
//! again that often (at least every ten seconds, never more often). A device
//! that loses its last service of the type is `removed` from the watch. The
//! types asked for are remembered, so probes ask for them from then on.
//! `devices` only lists what is known: to ask for a type and see what
//! answers, watch with a query for as long as you care to wait, as `mdnsctl
//! devices --query` does.
//!
//! `watchers` lists the watches streaming now, oldest first: the segment,
//! the `--query` types (empty for none) and `--interval` (`null` for none)
//! each was asked with, how long it has been open, and the process and user
//! holding it, as the kernel reports the other end of its connection (`null`
//! if it cannot).
//!
//! `timers` lists each link's upkeep, which the event loop runs when it is
//! due, soonest first, for debugging. `due_in_ms` is 0 for one that is due
//! and `null` for one that is running now or never due; `last_run_ago_ms` and
//! `last_took_us` are `null` until it has run. It is due at the first of its
//! `pending` list: everything it is waiting to do, soonest first, as `what`
//! (`expire`, `refresh` or `re-announce`), to `who` (a hostname, or the
//! address of a device that has none, or a hostname and one of its
//! addresses, for that address running out on its own), and `due_in_ms` from
//! now (0 if it is due).
//! 
//!
//! A device is listed once, whichever family it was heard over, with its
//! `addresses` of both: routable ones first (IPv4, then global or ULA IPv6),
//! then link-local ones (`169.254/16`, `fe80::/10`), which only mean something
//! on the device's own link. Up to eight of a family; empty when it announced
//! none and was not heard from. `neighbour_addresses` are those of them it did
//! not announce: of a family it announced no routable address of, the kernel's
//! neighbour table lists them under the link-layer address of one it
//! announced. Which of them are reflected is each segment's to say
//! (`NeighbourAddresses=`); all are listed here.
//!
//! The TTLs a device announced itself with are kept: `address_ttl` for its
//! address records and `ttl` for each service (the SRV record's, else the PTR's
//! or TXT's), in seconds, `null` when not known. A reflected copy is announced
//! with them, unless the configuration says otherwise.

use hashbrown::HashMap;
use core::time::Duration;

use rustix::fd::{AsRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::time::Instant;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::reflector::Notice;
use crate::device::{is_type, Device, Origin};
use crate::runtime::Why;
use crate::poll;
use crate::segment::{Event, Probed, Segment};
use crate::socket::Family;
use crate::Group;

use crate::prelude::*;

/// Longest request line accepted.
const MAX_LINE: u64 = 4096;

/// Connections that send nothing for this long are closed, so that clients
/// cannot pile up.
const IDLE: Duration = Duration::from_millis(if cfg!(test) { 300 } else { 60_000 });

/// How long a client may leave what it is to be told waiting, without
/// taking any of it, and how much of it may wait: past either, it is let go.
const STREAM_WRITE: Duration = Duration::from_millis(if cfg!(test) { 200 } else { 10_000 });
const MAX_OUTPUT: usize = 1 << 20;

/// The longest `probe` waits for a probe, which takes a few seconds, to
/// finish: mdnsctl waits fifteen.
const PROBE_WAIT: Duration = Duration::from_secs(10);

/// The least a watch's `--interval=` may be: asking takes about four seconds,
/// and asking more often than this is only noise.
const MIN_QUERY_INTERVAL: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });

/// The control socket and its clients, served from the event loop: nothing
/// here waits, and what a client is to be told waits in its buffer until it
/// takes it.
pub struct Server {
    listener: OwnedFd,
    clients: Vec<Client>,
    next_watch: u64,
}

/// A connection to the control socket.
struct Client {
    stream: OwnedFd,
    peer: Option<Peer>,
    /// What it has sent that is not yet a whole line.
    input: Vec<u8>,
    /// What it is to be told, once it takes more.
    output: Vec<u8>,
    /// When it last sent something, for [`IDLE`].
    active: Instant,
    /// Since when its output has waited without any of it being taken, for
    /// [`STREAM_WRITE`].
    stalled: Option<Instant>,
    state: State,
    /// It is closed once its output is written, or at once if it is gone.
    closing: bool,
    gone: bool,
}

enum State {
    /// Answering requests, a line each.
    Requests,
    /// Waiting for the probes it asked for, by interface and number, to reply
    /// once they are done, or once it has waited `until`.
    Probing { probes: Vec<(String, u64, Option<Probed>)>, until: Instant },
    /// Streaming what happens to a segment's devices.
    Watching(Streaming),
}

/// A watch, as it streams.
struct Streaming {
    id: u64,
    name: String,
    query: Query,
    /// The devices of the query's types shown, as shown, so that one that
    /// loses its last service of them is shown to go, and one shown already
    /// is not shown again unchanged.
    shown: HashMap<(String, String), Value>,
    /// When to ask for the query's types again, if ever.
    next_ask: Option<Instant>,
    since: Instant,
}

impl Server {
    /// Bind the control socket at `path`, before anything else happens, so
    /// that a bad path or a second instance is reported at startup.
    pub fn bind(path: &str) -> Result<Server> {
        let listener = bind(path)?;
        eprintln!("ipc: listening on {path}");
        Ok(Server { listener, clients: Vec::new(), next_watch: 0 })
    }

    /// The descriptors to wait on: the listener, readable when someone
    /// connects, and every client, readable when it sends or hangs up, and
    /// writable when it can take what waits for it.
    pub fn fds(&self) -> Vec<libc::pollfd> {
        let mut fds = vec![poll::readable(self.listener.as_raw_fd())];
        for c in &self.clients {
            let mut fd = poll::readable(c.stream.as_raw_fd());
            if !c.output.is_empty() {
                fd.events |= libc::POLLOUT;
            }
            fds.push(fd);
        }
        fds
    }

    /// Accept, read and write what `fds` (as [`Server::fds`] gave them, after
    /// waiting) say can be.
    pub fn ready(&mut self, fds: &[libc::pollfd]) {
        if fds.first().is_some_and(poll::ready) {
            self.accept();
        }
        for (c, fd) in self.clients.iter_mut().zip(&fds[1..]) {
            if poll::ready(fd) {
                c.read();
            }
            if fd.revents & libc::POLLOUT != 0 {
                c.flush(Instant::now());
            }
        }
    }

    fn accept(&mut self) {
        loop {
            match rustix::net::accept_with(&self.listener, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK) {
                Ok(stream) => {
                    let peer = peer_of(&stream);
                    let now = Instant::now();
                    let state = State::Requests;
                    let c = Client { stream, peer, input: Vec::new(), output: Vec::new(), active: now, stalled: None, state, closing: false, gone: false };
                    self.clients.push(c);
                }
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => {}
                Err(e) => {
                    // Out of descriptors, say: those who wait are taken next
                    // time round.
                    eprintln!("ipc: accept failed: {}", Why(e));
                    return;
                }
            }
        }
    }

    /// Answer what has come in, finish the probes clients wait for, stream
    /// what has happened to the watches, write what can be written, and let
    /// go of clients that are done, gone, idle or not reading.
    pub fn tick(&mut self, groups: &[Group], now: Instant) {
        let watching = self.watches();
        let notices: Vec<(&str, Notice)> =
            groups.iter().flat_map(|g| g.reflector.take_notices().into_iter().map(move |n| (g.name.as_str(), n))).collect();
        let links = links_of(groups, "");
        for i in 0..self.clients.len() {
            let c = &mut self.clients[i];
            match &mut c.state {
                State::Requests => {}
                State::Probing { probes, until } => {
                    for (interface, id, result) in probes.iter_mut().filter(|(_, _, r)| r.is_none()) {
                        *result = links.iter().find(|s| s.interface() == interface).and_then(|s| s.probed(*id));
                    }
                    if probes.iter().all(|(_, _, r)| r.is_some()) || now >= *until {
                        let results = probes.drain(..).map(|(interface, _, r)| (interface, r)).collect();
                        push_line(&mut c.output, &probe_reply(results));
                        c.state = State::Requests;
                    }
                }
                State::Watching(watch) => {
                    if let Some(at) = watch.next_ask.filter(|&at| at <= now) {
                        ask_for_types(groups, &watch.name, &watch.query.kinds);
                        watch.next_ask = watch.query.interval.map(|every| at + every);
                    }
                    for (_, notice) in notices.iter().filter(|(name, _)| *name == watch.name) {
                        let line = if watch.query.kinds.is_empty() {
                            notice_json(&watch.name, notice)
                        } else {
                            narrowed(&watch.name, notice.clone(), &watch.query.kinds, &mut watch.shown)
                        };
                        if let Some(line) = line {
                            push_line(&mut c.output, &line);
                        }
                    }
                }
            }
            if matches!(c.state, State::Requests) {
                self.next_watch = c.answer(groups, &watching, self.next_watch, now);
            }
            let c = &mut self.clients[i];
            c.flush(now);
            let idle = matches!(c.state, State::Requests) && c.output.is_empty() && now >= c.active + IDLE;
            let stuck = c.stalled.is_some_and(|since| now >= since + STREAM_WRITE) || c.output.len() > MAX_OUTPUT;
            if idle || stuck {
                c.gone = true;
            }
        }
        self.clients.retain(|c| !c.gone && !(c.closing && c.output.is_empty()));
    }

    /// When [`Server::tick`] next has something to do of its own accord: a
    /// client to give up waiting for, a watch to ask again for its types.
    pub fn next_due(&self) -> Option<Instant> {
        self.clients
            .iter()
            .filter_map(|c| {
                let own = match &c.state {
                    State::Requests => Some(c.active + IDLE),
                    State::Probing { until, .. } => Some(*until),
                    State::Watching(watch) => watch.next_ask,
                };
                [own, c.stalled.map(|since| since + STREAM_WRITE)].into_iter().flatten().min()
            })
            .min()
    }

    /// Tell every watch the daemon is stopping, as far as it takes it now.
    pub fn shut_down(&mut self) {
        let now = Instant::now();
        for c in self.clients.iter_mut().filter(|c| matches!(c.state, State::Watching(_))) {
            push_line(&mut c.output, &error("shutting down"));
            c.flush(now);
        }
    }

    /// The watches streaming now, as `watchers` lists them.
    fn watches(&self) -> Watches {
        let open = self
            .clients
            .iter()
            .filter_map(|c| match &c.state {
                State::Watching(w) => {
                    let query = Query { kinds: w.query.kinds.clone(), interval: w.query.interval };
                    Some(Open { id: w.id, segment: w.name.clone(), query, peer: c.peer, since: w.since })
                }
                _ => None,
            })
            .collect();
        Watches { open }
    }
}

impl Client {
    /// Take what it has sent. One that hangs up, or sends anything to a watch,
    /// which expects nothing, is gone.
    fn read(&mut self) {
        let mut buf = [0u8; 4096];
        loop {
            match rustix::io::read(&self.stream, &mut buf) {
                Ok(0) => return self.gone = true,
                Ok(_) if matches!(self.state, State::Watching(_)) => return self.gone = true,
                Ok(n) => {
                    self.input.extend_from_slice(&buf[..n]);
                    self.active = Instant::now();
                }
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => {}
                Err(_) => return self.gone = true,
            }
        }
    }

    /// Write what it can take of its output, minding how long it has not
    /// taken any.
    fn flush(&mut self, now: Instant) {
        let mut wrote = 0;
        while wrote < self.output.len() {
            match rustix::io::write(&self.stream, &self.output[wrote..]) {
                Ok(0) => break,
                Ok(n) => wrote += n,
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => {}
                Err(_) => {
                    self.gone = true;
                    break;
                }
            }
        }
        self.output.drain(..wrote);
        self.stalled = match (self.output.is_empty(), wrote) {
            (true, _) => None,
            (false, 0) => self.stalled.or(Some(now)),
            (false, _) => Some(now),
        };
    }

    /// Answer the whole lines it has sent, until one starts something that
    /// takes longer than an answer: a probe or a watch. Returns the next
    /// watch's number.
    fn answer(&mut self, groups: &[Group], watches: &Watches, mut next_watch: u64, now: Instant) -> u64 {
        while matches!(self.state, State::Requests) && !self.closing {
            let Some(end) = self.input.iter().position(|&b| b == b'\n') else {
                if self.input.len() as u64 >= MAX_LINE {
                    push_line(&mut self.output, &error("request too long"));
                    self.closing = true;
                }
                break;
            };
            let line: Vec<u8> = self.input.drain(..=end).collect();
            if line.len() as u64 > MAX_LINE {
                push_line(&mut self.output, &error("request too long"));
                self.closing = true;
                break;
            }
            let line = String::from_utf8_lossy(&line);
            let request = line.trim();
            if let Some(arg) = watch_arg(request) {
                match follow(groups, arg) {
                    Ok(watch) => {
                        next_watch += 1;
                        self.watch(watch, next_watch, now);
                    }
                    Err(reply) => {
                        push_line(&mut self.output, &reply);
                        self.closing = true;
                    }
                }
            } else if let Some(arg) = probe_arg(request) {
                match start_probes(groups, arg) {
                    Ok(probes) => {
                        let probes = probes.into_iter().map(|(interface, id)| (interface, id, None)).collect();
                        self.state = State::Probing { probes, until: now + PROBE_WAIT };
                    }
                    Err(reply) => push_line(&mut self.output, &reply),
                }
            } else {
                push_line(&mut self.output, &handle(groups, watches, request));
            }
        }
        next_watch
    }

    /// Start streaming `watch`: say so, list what is there of its types, and
    /// ask for them at once.
    fn watch(&mut self, watch: Watch, id: u64, now: Instant) {
        let Watch { name, query, present } = watch;
        push_line(&mut self.output, &json!({ "ok": true, "name": name, "watching": true }));
        let mut shown = HashMap::new();
        for line in &present {
            if let (Some(interface), Some(host)) = (line["device"]["interface"].as_str(), line["device"]["hostname"].as_str()) {
                shown.insert((interface.to_string(), host.to_ascii_lowercase()), line["device"].clone());
            }
            push_line(&mut self.output, line);
        }
        let next_ask = (!query.kinds.is_empty()).then_some(now);
        self.state = State::Watching(Streaming { id, name, query, shown, next_ask, since: now });
    }
}

/// Bind, replacing a stale socket file left by a previous run but never a
/// live instance and never a file that is not a socket.
fn bind(path: &str) -> Result<OwnedFd> {
    if let Ok(st) = rustix::fs::lstat(path) {
        if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Socket {
            bail!("{path} exists and is not a socket");
        }
        if unix_socket(SocketFlags::CLOEXEC).and_then(|fd| connect(&fd, path)).is_ok() {
            bail!("{path} is in use by a running instance");
        }
        rustix::fs::unlink(path).map_err(Why).with_context(|| format!("removing stale {path}"))?;
    }
    let listener = unix_socket(SocketFlags::CLOEXEC | SocketFlags::NONBLOCK).map_err(Why).context("making the control socket")?;
    let addr = SocketAddrUnix::new(path).map_err(Why).with_context(|| format!("binding {path}"))?;
    rustix::net::bind(&listener, &addr).map_err(Why).with_context(|| format!("binding {path}"))?;
    rustix::net::listen(&listener, 128).map_err(Why).with_context(|| format!("listening on {path}"))?;
    // Owner and group only.
    rustix::fs::chmod(path, rustix::fs::Mode::from_raw_mode(0o660)).map_err(Why).with_context(|| format!("setting permissions on {path}"))?;
    Ok(listener)
}

/// A stream socket of the Unix family, with `flags`.
fn unix_socket(flags: SocketFlags) -> rustix::io::Result<OwnedFd> {
    rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, flags, None)
}

/// Connect `fd` to the Unix socket at `path`.
fn connect(fd: &OwnedFd, path: &str) -> rustix::io::Result<()> {
    rustix::io::retry_on_intr(|| rustix::net::connect(fd, &SocketAddrUnix::new(path)?))
}

/// The watches streaming now, for `watchers`.
#[derive(Default)]
pub struct Watches {
    open: Vec<Open>,
}

/// One watch, as `watchers` lists it.
struct Open {
    id: u64,
    segment: String,
    query: Query,
    peer: Option<Peer>,
    since: Instant,
}

/// The process at the other end of a connection, as the kernel has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    pid: i32,
    uid: u32,
}

impl Watches {
    fn json(&self) -> Value {
        let list: Vec<Value> = self
            .open
            .iter()
            .map(|w| {
                json!({
                    "id": w.id,
                    "segment": w.segment,
                    "query": w.query.kinds,
                    "interval_s": w.query.interval.map(|d| d.as_secs()),
                    "pid": w.peer.map(|p| p.pid),
                    "uid": w.peer.map(|p| p.uid),
                    "age_ms": u64::try_from(w.since.elapsed().as_millis()).unwrap_or(u64::MAX),
                })
            })
            .collect();
        json!({ "ok": true, "watchers": list })
    }
}

/// Who is at the other end of `stream`, or `None` if the kernel will not say.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_of(stream: &OwnedFd) -> Option<Peer> {
    let cred = rustix::net::sockopt::socket_peercred(stream).ok()?;
    Some(Peer { pid: cred.pid.as_raw_pid(), uid: cred.uid.as_raw() })
}

/// Who is at the other end of `stream`, or `None` if the system will not say.
/// The BSDs say whose user it is, and not which process.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_of(stream: &OwnedFd) -> Option<Peer> {
    use rustix::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the descriptor is open, and the two are valid to write to.
    (unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(Peer { pid: 0, uid })
}

/// Queue `line` and a newline for a client, to go out whole: it is never
/// given half a line to take for a whole one.
fn push_line(output: &mut Vec<u8>, line: &impl core::fmt::Display) {
    output.extend_from_slice(format!("{line}\n").as_bytes());
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

/// A watch on a segment, as registered.
struct Watch {
    name: String,
    query: Query,
    /// With a query, the devices of its types known when it started, as
    /// `present` lines.
    present: Vec<Value>,
}

/// Start following the devices of the named segment, on every interface and
/// family of it: its reflectors' notices are streamed from now on.
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
    Ok(Watch { name: name.to_string(), query, present })
}

/// Ask for the types of a watch's query on the interfaces of the named
/// segment: the event loop runs the rounds, while the watch goes on.
fn ask_for_types(groups: &[Group], name: &str, kinds: &[String]) {
    for seg in links_of(groups, name) {
        seg.query_types(kinds);
    }
}

/// A change as a watch for the service types `kinds` shows it: the device
/// with only its services of those types, if it has any, or its going, if
/// it had and no longer has; `None` for one it never showed, or shows already
/// just so. A device it already shows is updated, even when the segment calls
/// it added: one listed as present when the watch started can be told of again
/// as it is filed.
fn narrowed(segment: &str, notice: Notice, kinds: &[String], shown: &mut HashMap<(String, String), Value>) -> Option<Value> {
    let (removed, device) = match &notice.event {
        Event::Added(d) | Event::Updated(d) => (false, d),
        Event::Removed(d) => (true, d),
        Event::Question(_) => return None,
    };
    let key = device.key().map(|k| (notice.interface.clone(), k));
    let was_shown = key.as_ref().is_some_and(|k| shown.contains_key(k));
    match device.only_kinds(kinds) {
        Some(narrow) if !removed => {
            let line = event_json(if was_shown { "updated" } else { "added" }, segment, &Notice { event: Event::Updated(narrow), ..notice });
            if let Some(key) = key {
                if shown.get(&key) == Some(&line["device"]) {
                    return None;
                }
                shown.insert(key, line["device"].clone());
            }
            Some(line)
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
pub fn handle(groups: &[Group], watches: &Watches, request: &str) -> String {
    let (command, arg) = match request.split_once(char::is_whitespace) {
        Some((command, arg)) => (command, arg.trim()),
        None => (request, ""),
    };
    match command.to_ascii_lowercase().as_str() {
        "segments" => segments(groups),
        "devices" => devices(groups, arg),
        "probe" => probe(groups, arg),
        "timers" => timer_list(groups),
        "watchers" => watches.json(),
        "watch" => error("watch streams events: it needs a connection of its own"),
        "" => error("empty request"),
        other => error(&format!(
            "unknown command {other:?}; try: segments, devices <name>, probe [name], watch [--query=<type>] <name>, watchers, timers"
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

fn devices(groups: &[Group], name: &str) -> Value {
    if name.starts_with("--") {
        return error("devices lists what is known: to ask for a type, watch with --query");
    }
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
            found.sort_by_key(|d| (d.key(), d.addrs().collect::<Vec<_>>()));
            list.extend(found.iter().map(|d| device_json(seg.interface(), d)));
        }
    }
    json!({ "ok": true, "name": name, "devices": list })
}

/// Start probing every interface of the named segment, or of all segments:
/// each one's name, and the number its probe is known by. An interface shared
/// by several segments is probed once. They run at once, as they are
/// independent: they take one's time, not one per interface.
fn start_probes(groups: &[Group], name: &str) -> Result<Vec<(String, u64)>, Value> {
    let name = segment_arg(name);
    let links = links_of(groups, name);
    if links.is_empty() {
        return Err(error(&format!("no such segment: {name}")));
    }
    Ok(links.into_iter().map(|seg| (seg.interface().to_string(), seg.probe())).collect())
}

/// The reply to `probe`: how it went on each interface, `None` for one that
/// did not finish in time.
fn probe_reply(results: Vec<(String, Option<Probed>)>) -> Value {
    let probed: Vec<Value> = results
        .into_iter()
        .map(|(interface, result)| {
            let (queries, err) = match result.unwrap_or_else(|| Err("the probe did not finish".into())) {
                Ok(n) => (Some(n), None),
                Err(e) => (None, Some(e)),
            };
            json!({ "interface": interface, "queries": queries, "error": err })
        })
        .collect();
    json!({ "ok": true, "probed": probed })
}

/// Probe, and reply with what is done at once, as on an interface that
/// cannot send: the rest is "did not finish". The server starts the probes,
/// and replies once the event loop has run them.
fn probe(groups: &[Group], name: &str) -> Value {
    match start_probes(groups, name) {
        Ok(probes) => {
            let links = links_of(groups, "");
            let done = |interface: &str, id| links.iter().find(|s| s.interface() == interface).and_then(|s| s.probed(id));
            probe_reply(probes.into_iter().map(|(interface, id)| (interface.clone(), done(&interface, id))).collect())
        }
        Err(reply) => reply,
    }
}

/// The arguments of a `probe` request, if it is one.
fn probe_arg(request: &str) -> Option<&str> {
    let (command, arg) = request.split_once(char::is_whitespace).unwrap_or((request, ""));
    command.eq_ignore_ascii_case("probe").then(|| arg.trim())
}

fn timer_list(groups: &[Group]) -> Value {
    let now = Instant::now();
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);

    // Each link's upkeep, and what it is waiting to do. A link that is in
    // several segments is listed once.
    let mut links: Vec<&Segment> = Vec::new();
    for seg in groups.iter().flat_map(|g| g.reflector.segments()) {
        if !links.iter().any(|l| l.interface() == seg.interface()) {
            links.push(seg);
        }
    }
    let mut list: Vec<(Option<Instant>, Value)> = (1..)
        .zip(links)
        .map(|(id, seg)| {
            let info = seg.upkeep_info();
            let pending: Vec<Value> = seg
                .pending()
                .into_iter()
                .map(|p| json!({ "what": p.what, "who": p.who, "due_in_ms": ms(p.at.saturating_duration_since(now)) }))
                .collect();
            let due = info.due.filter(|_| !info.running);
            let timer = json!({
                "id": id,
                "name": format!("upkeep {}", seg.interface()),
                "running": info.running,
                "due_in_ms": due.map(|at| ms(at.saturating_duration_since(now))),
                "runs": info.runs,
                "last_run_ago_ms": info.last_run.map(|at| ms(now.saturating_duration_since(at))),
                "last_took_us": info.last_took.map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
                "pending": pending,
            });
            (due, timer)
        })
        .collect();
    // Soonest first; what is never due, last.
    list.sort_by_key(|(due, _)| (due.is_none(), *due));
    json!({ "ok": true, "timers": list.into_iter().map(|(_, t)| t).collect::<Vec<_>>() })
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
        "neighbour_addresses": d.addresses.iter().filter(|a| a.origin == Origin::Neighbour).map(|a| a.ip.to_string()).collect::<Vec<_>>(),
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
    use std::fs;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};

    use super::*;

    /// `socket` as the daemon takes a socket.
    fn fd(socket: impl std::os::fd::IntoRawFd) -> rustix::fd::OwnedFd {
        // SAFETY: a descriptor just given up by its owner.
        unsafe { rustix::fd::FromRawFd::from_raw_fd(socket.into_raw_fd()) }
    }
    use crate::parser::{Header, Message, RData, Record};
    use crate::reflector::{deliver_made, Reflector};

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
        let (g, segs) = group("IoT", Family::V4, &["later", "sooner", "never"]);
        segs[0].observe(ip("10.0.1.7"));
        segs[1].set_min_lifetime(Duration::from_secs(60));
        segs[1].observe(ip("10.0.2.7"));

        let reply: Value = serde_json::from_str(&handle(&[g], &Watches::default(), "timers")).unwrap();
        assert_eq!(reply["ok"], true);
        let list = reply["timers"].as_array().unwrap();
        let names: Vec<&str> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["upkeep sooner", "upkeep later", "upkeep never"]);

        let due = list[0]["due_in_ms"].as_u64().unwrap();
        assert!((59_000..=60_000).contains(&due), "{due}");
        assert_eq!(list[0]["running"], false);
        assert_eq!(list[0]["runs"], 0);
        assert!(list[0]["last_run_ago_ms"].is_null() && list[0]["last_took_us"].is_null());
        assert!(list[2]["due_in_ms"].is_null(), "nothing known, never due");
        assert!(list[0]["id"].is_u64());
    }

    #[test]
    fn timers_say_what_each_one_is_waiting_for() {
        let (g, segs) = group("IoT", Family::V4, &["wifi"]);
        let (g2, _) = group("other", Family::V4, &["eth", "wifi"]);
        segs[0].set_refresh_before(Some(Duration::from_secs(30)));
        segs[0].observe(ip("10.0.1.7"));
        segs[0].upkeep(Instant::now());

        let reply: Value = serde_json::from_str(&handle(&[g, g2], &Watches::default(), "timers")).unwrap();
        let list = reply["timers"].as_array().unwrap();
        assert_eq!(list.len(), 2, "wifi, in two segments, once: {list:?}");
        let wifi = list.iter().find(|t| t["name"] == "upkeep wifi").unwrap();
        let pending = wifi["pending"].as_array().unwrap();
        assert_eq!(pending.len(), 1, "an unnamed device is only expired");
        assert_eq!((pending[0]["what"].as_str(), pending[0]["who"].as_str()), (Some("expire"), Some("10.0.1.7")));
        let due = pending[0]["due_in_ms"].as_u64().unwrap();
        assert!((299_000..=300_000).contains(&due), "{due}");
        // The upkeep is due for it, and has run once.
        assert!(wifi["due_in_ms"].as_u64().unwrap().abs_diff(due) < 1000);
        assert_eq!(wifi["runs"], 1);
        assert!(wifi["last_run_ago_ms"].is_u64() && wifi["last_took_us"].is_u64());
    }

    #[test]
    fn lists_segments_merging_families() {
        let (m4, _) = group("media", Family::V4, &["a", "b"]);
        let (m6, _) = group("media", Family::V6, &["a", "b"]);
        let (iot, _) = group("iot", Family::V4, &["c"]);
        let groups = [m4, m6, iot];
        assert_eq!(
            handle(&groups, &Watches::default(), "segments"),
            r#"{"ok":true,"segments":[{"name":"media","interfaces":["a","b"],"untrusted":[],"families":["v4","v6"]},{"name":"iot","interfaces":["c"],"untrusted":[],"families":["v4"]}]}"#
        );
    }

    #[test]
    fn segments_say_which_interfaces_are_untrusted() {
        let segs: Vec<Segment> = ["br0", "wifi"].iter().map(|i| Segment::new(i, &[Family::V4])).collect();
        let reflector = Reflector::with_untrusted(0, segs, &["wifi".to_string()]).unwrap();
        let groups = [Group { name: "IoT to br0".into(), reflector }];
        assert_eq!(
            handle(&groups, &Watches::default(), "segments"),
            r#"{"ok":true,"segments":[{"name":"IoT to br0","interfaces":["br0","wifi"],"untrusted":["wifi"],"families":["v4"]}]}"#
        );
    }

    #[test]
    fn lists_devices_of_a_segment() {
        let (iot, segs) = group("IoT to br0", Family::V4, &["c"]);
        segs[0].observe(ip("10.0.3.9"));
        assert_eq!(
            handle(&[iot], &Watches::default(), r#"devices "IoT to br0""#),
            r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"c","hostname":null,"addresses":["10.0.3.9"],"neighbour_addresses":[],"address_ttl":null,"services":[]}]}"#
        );
    }

    #[test]
    fn devices_carry_services_and_escape_json() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", r#"My "TV""#);
        segs[1].observe(ip("10.0.2.1"));
        let out = handle(&[g], &Watches::default(), "DEVICES media");
        assert!(
            out.contains(r#""interface":"a","hostname":"tv.local","addresses":["10.0.1.5"],"neighbour_addresses":[],"address_ttl":120"#),
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
        deliver_made();
        assert!(!segs[1].manual_devices().is_empty(), "precondition: reflected onto b");
        let out = handle(&[g], &Watches::default(), "devices media");
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
            let reply: Value = serde_json::from_str(&handle(&groups, &Watches::default(), request)).unwrap();
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
            handle(&[g], &Watches::default(), "probe media"),
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
            let out = handle(&groups, &Watches::default(), request);
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
        let out = handle(&[g], &Watches::default(), "devices media");
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

    /// The server at `path`, with `groups`, run the way the event loop runs
    /// it, with the segments' upkeep and the reflectors' deliveries, a turn
    /// at a time, as a test waits for what a client is told.
    struct Harness {
        server: Server,
        groups: Vec<Group>,
    }

    impl Harness {
        fn new(path: &Path, groups: Vec<Group>) -> Harness {
            Harness { server: Server::bind(path.to_str().unwrap()).unwrap(), groups }
        }

        /// One turn of the loop.
        fn pump(&mut self) {
            let mut fds = self.server.fds();
            poll::wait(&mut fds, Some(Duration::from_millis(1))).unwrap();
            self.server.ready(&fds);
            let now = Instant::now();
            for seg in self.groups.iter().flat_map(|g| g.reflector.segments()) {
                if seg.next_due().is_some_and(|at| at <= now) {
                    seg.upkeep(now);
                }
            }
            crate::reflector::deliver(&self.groups.iter().map(|g| &g.reflector).collect::<Vec<_>>());
            self.server.tick(&self.groups, now);
        }

        /// The next line the server tells `reader`, turning the loop until it
        /// comes; empty if the server closes the connection instead.
        fn line(&mut self, reader: &mut BufReader<UnixStream>) -> String {
            reader.get_ref().set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut line = String::new();
            loop {
                match reader.read_line(&mut line) {
                    Ok(0) => return line,
                    Ok(_) if line.ends_with('\n') => return line.trim_end().to_string(),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("{e}"),
                }
                assert!(Instant::now() < deadline, "nothing from the server; so far {line:?}");
                self.pump();
            }
        }

        fn json(&mut self, reader: &mut BufReader<UnixStream>) -> Value {
            serde_json::from_str(&self.line(reader)).unwrap()
        }

        fn ask(&mut self, stream: &mut UnixStream, reader: &mut BufReader<UnixStream>, request: &str) -> String {
            writeln!(stream, "{request}").unwrap();
            self.line(reader)
        }
    }

    /// A client of the server at `path`, and its replies.
    fn connect(path: &Path) -> (UnixStream, BufReader<UnixStream>) {
        let stream = UnixStream::connect(path).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        (stream, reader)
    }

    #[test]
    fn serves_requests_over_the_socket() {
        let (g, segs) = group("IoT", Family::V4, &["wifi"]);
        segs[0].observe(ip("10.0.1.7"));
        let path = temp_socket("serve");
        let mut h = Harness::new(&path, vec![g]);

        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o660);

        let (mut stream, mut reader) = connect(&path);
        // Several requests on one connection.
        assert!(h.ask(&mut stream, &mut reader, "segments").contains(r#""name":"IoT""#));
        assert!(h.ask(&mut stream, &mut reader, "devices IoT").contains(r#""addresses":["10.0.1.7"]"#));
        assert!(h.ask(&mut stream, &mut reader, "bogus").contains(r#""ok":false"#));

        // Oversized requests are refused and the connection closed.
        let (mut big, mut big_reader) = connect(&path);
        big.write_all(&vec![b'x'; MAX_LINE as usize + 10]).unwrap();
        assert!(h.line(&mut big_reader).contains("request too long"));
        assert_eq!(h.line(&mut big_reader), "", "closed");

        // Requests that come in pieces, or several in one, are answered a
        // line each.
        stream.write_all(b"segm").unwrap();
        h.pump();
        stream.write_all(b"ents\ndevices IoT\n").unwrap();
        assert!(h.line(&mut reader).contains(r#""segments""#));
        assert!(h.line(&mut reader).contains(r#""devices""#));

        // One that says nothing for long enough is let go.
        let (_idle, mut idle_reader) = connect(&path);
        let start = Instant::now();
        assert_eq!(h.line(&mut idle_reader), "", "closed");
        assert!(start.elapsed() >= IDLE);
        let _ = fs::remove_file(&path);
    }

    /// probe replies once the probes are done, and the server goes on
    /// meanwhile.
    #[test]
    fn probe_is_answered_once_done_while_the_rest_goes_on() {
        let (seg, _rx) = wired("wifi");
        let path = temp_socket("probe");
        let mut h = Harness::new(&path, vec![Group { name: "IoT".into(), reflector: Reflector::new(0, vec![seg.clone()]).unwrap() }]);

        let (mut stream, mut reader) = connect(&path);
        writeln!(stream, "probe IoT").unwrap();
        let (mut other, mut other_reader) = connect(&path);
        assert!(h.ask(&mut other, &mut other_reader, "segments").contains("IoT"), "answered meanwhile");
        assert_eq!(h.line(&mut reader), r#"{"ok":true,"probed":[{"interface":"wifi","queries":3,"error":null}]}"#);
        // And the connection takes requests again.
        assert!(h.ask(&mut stream, &mut reader, "segments").contains("IoT"));
        let _ = fs::remove_file(&path);
    }

    /// A client that takes nothing of what it is told for long enough, or
    /// lets too much pile up, is let go.
    #[test]
    fn a_client_that_does_not_read_is_let_go() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let now = Instant::now();
        let mut c = Client {
            stream: fd(ours),
            peer: None,
            input: Vec::new(),
            output: vec![b'x'; MAX_OUTPUT / 2],
            active: now,
            stalled: None,
            state: State::Requests,
            closing: false,
            gone: false,
        };
        c.flush(now);
        let stalled = c.stalled.expect("the rest waits");
        c.flush(now + Duration::from_millis(50));
        assert_eq!(c.stalled, Some(stalled), "nothing taken: still since then");
        // Taking some starts the wait afresh.
        let mut buf = vec![0u8; 64 << 10];
        let mut theirs = theirs;
        theirs.read_exact(&mut buf).unwrap();
        c.flush(now + Duration::from_millis(100));
        assert_eq!(c.stalled, Some(now + Duration::from_millis(100)));

        let mut server = Server { listener: fd(UnixListener::bind(temp_socket("stalled")).unwrap()), clients: vec![c], next_watch: 0 };
        server.tick(&[], now + Duration::from_millis(150));
        assert_eq!(server.clients.len(), 1, "not yet");
        server.tick(&[], now + Duration::from_millis(100) + STREAM_WRITE);
        assert!(server.clients.is_empty(), "let go");

        // Too much waiting is let go at once.
        let (ours, _theirs) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let state = State::Requests;
        let c = Client { stream: fd(ours), peer: None, input: Vec::new(), output: vec![b'x'; MAX_OUTPUT * 2], active: now, stalled: None, state, closing: false, gone: false };
        server.clients.push(c);
        server.tick(&[], now);
        assert!(server.clients.is_empty());
        let _ = fs::remove_file(temp_socket("stalled"));
    }

    #[test]
    fn watch_streams_changes_until_the_daemon_stops() {
        let (g, segs) = group("IoT", Family::V4, &["wifi"]);
        let path = temp_socket("watch");
        let mut h = Harness::new(&path, vec![g]);

        let (mut stream, mut reader) = connect(&path);
        assert_eq!(h.ask(&mut stream, &mut reader, "WATCH IoT"), r#"{"ok":true,"name":"IoT","watching":true}"#);

        segs[0].observe(ip("10.0.1.7"));
        let added = h.json(&mut reader);
        assert_eq!((added["event"].as_str(), added["segment"].as_str()), (Some("added"), Some("IoT")));
        assert_eq!(added["ttl"], 300);
        assert_eq!(added["device"]["interface"], "wifi");
        assert_eq!(added["device"]["addresses"][0], "10.0.1.7");

        segs[0].expire(Instant::now() + Duration::from_secs(3600));
        let removed = h.json(&mut reader);
        assert_eq!(removed["event"], "removed");
        assert_eq!(removed["ttl"], 0);
        assert_eq!(removed["device"]["addresses"][0], "10.0.1.7");

        // Failures are ordinary replies, and the connection can go on.
        let (mut other, mut other_reader) = connect(&path);
        assert!(h.ask(&mut other, &mut other_reader, "watch nope").contains("no such segment: nope"));
        let (mut other, mut other_reader) = connect(&path);
        assert!(h.ask(&mut other, &mut other_reader, "watch").contains("usage: watch"));

        // When the daemon stops, the watch is told so.
        h.server.shut_down();
        assert!(h.line(&mut reader).contains("shutting down"));
        let _ = fs::remove_file(&path);
    }

    /// A segment on `interface` that sends to the returned socket.
    fn wired(interface: &str) -> (Segment, std::net::UdpSocket) {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let seg = Segment::new(interface, &[Family::V4]);
        seg.attach(Family::V4, fd(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap());
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

    /// `devices` lists what is known, and asks nothing: an option is refused,
    /// pointing to `watch --query`, which asks.
    #[test]
    fn devices_lists_what_is_known_and_asks_nothing() {
        let (a, a_rx) = wired("a");
        let groups = [Group { name: "IoT".into(), reflector: Reflector::new(0, vec![a.clone()]).unwrap() }];
        announce(&a, "10.0.1.7", "tv.local", "TV");
        let ask = |request: &str| handle(&groups, &Watches::default(), request);
        let reply: Value = serde_json::from_str(&ask("devices IoT")).unwrap();
        assert_eq!(reply["devices"][0]["hostname"], "tv.local");
        for request in ["devices --query=_http._tcp IoT", "devices --interval=30 IoT"] {
            assert!(ask(request).contains("watch with --query"), "{request}");
        }
        assert!(queries(&a_rx).is_empty(), "nothing asked");
    }

    #[test]
    fn watch_with_a_query_shows_what_is_there_asks_and_asks_again() {
        let (seg, rx) = wired("wifi");
        let groups = vec![Group { name: "IoT".into(), reflector: Reflector::new(0, vec![seg.clone()]).unwrap() }];
        announce(&seg, "10.0.1.7", "tv.local", "TV");
        let path = temp_socket("watch-query");
        let mut h = Harness::new(&path, groups);

        let (mut stream, mut reader) = connect(&path);
        let ack = h.ask(&mut stream, &mut reader, "watch --query=_http._tcp --interval=1 IoT");
        assert_eq!(ack, r#"{"ok":true,"name":"IoT","watching":true}"#);
        let present = h.json(&mut reader);
        assert_eq!((present["event"].as_str(), present["device"]["hostname"].as_str()), (Some("present"), Some("tv.local")));
        assert_eq!(present["ttl"], 300);

        // Asked at once, with the TV as a known answer, and again a second on.
        let mut asked = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while asked.len() < 6 && Instant::now() < deadline {
            h.pump();
            asked.extend(queries(&rx).into_iter().filter(|(names, _)| names == &["_http._tcp.local"]));
        }
        assert!(asked.len() >= 6 && asked.iter().all(|&(_, known)| known == 1), "{asked:?}");

        // One without the type is not shown; one with it is.
        seg.observe(ip("10.0.1.8"));
        announce(&seg, "10.0.1.9", "plug.local", "Plug");
        let added = h.json(&mut reader);
        assert_eq!((added["event"].as_str(), added["device"]["hostname"].as_str()), (Some("added"), Some("plug.local")));
        let _ = fs::remove_file(&path);
    }

    /// A watch for a type shows a device gaining it as added, changing as
    /// updated, losing it or going as removed, and nothing of the others.
    #[test]
    fn a_watch_for_a_type_narrows_what_it_shows() {
        let kinds = ["_http._tcp.local".to_string()];
        let mut shown = HashMap::new();
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

        let moved = || {
            let mut d = tv(true);
            d.services[0].port = 8080;
            d
        };

        assert_eq!(show(Event::Updated(tv(false))), None);
        assert_eq!(show(Event::Updated(tv(true))).as_deref(), Some("added"));
        assert_eq!(show(Event::Updated(tv(true))), None, "nothing of it shown changed");
        assert_eq!(show(Event::Updated(moved())).as_deref(), Some("updated"));
        // Added again while shown, as one listed as present can be: an update,
        // or nothing at all if it is just as shown.
        assert_eq!(show(Event::Added(tv(true))).as_deref(), Some("updated"));
        assert_eq!(show(Event::Added(tv(true))), None);
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
    fn watchers_lists_the_open_watches_and_who_holds_them() {
        let (g, _segs) = group("IoT", Family::V4, &["wifi"]);
        let path = temp_socket("watchers");
        let mut h = Harness::new(&path, vec![g]);
        let open = |h: &mut Harness, request: &str| {
            let (mut stream, mut reader) = connect(&path);
            assert!(h.ask(&mut stream, &mut reader, request).contains(r#""watching":true"#));
            stream
        };
        let list = |h: &mut Harness| {
            let (mut stream, mut reader) = connect(&path);
            let reply: Value = serde_json::from_str(&h.ask(&mut stream, &mut reader, "watchers")).unwrap();
            assert_eq!(reply["ok"], true);
            reply["watchers"].as_array().unwrap().clone()
        };
        assert!(list(&mut h).is_empty());

        let first = open(&mut h, "watch IoT");
        let _second = open(&mut h, "watch --query=_shelly._tcp --interval=60 IoT");
        let watchers = list(&mut h);
        assert_eq!(watchers.len(), 2, "{watchers:?}");
        let me = (std::process::id() as i64, unsafe { libc::getuid() } as i64);
        for w in &watchers {
            assert_eq!(w["segment"], "IoT");
            assert_eq!((w["pid"].as_i64().unwrap(), w["uid"].as_i64().unwrap()), me, "the kernel's word for who holds it");
            assert!(w["age_ms"].as_u64().is_some());
        }
        assert!(watchers[0]["id"].as_u64() < watchers[1]["id"].as_u64(), "oldest first");
        assert_eq!((watchers[0]["query"].as_array().unwrap().len(), &watchers[0]["interval_s"]), (0, &Value::Null));
        assert_eq!(watchers[1]["query"][0], "_shelly._tcp.local");
        assert_eq!(watchers[1]["interval_s"], 60);

        // A watch whose client is gone leaves the list at once.
        drop(first);
        h.pump();
        let watchers = list(&mut h);
        assert_eq!(watchers.len(), 1, "{watchers:?}");
        assert_eq!(watchers[0]["query"][0], "_shelly._tcp.local");
        let _ = fs::remove_file(&path);
    }

    /// A watch says what happened to a device as the daemon says it: added,
    /// updated or removed. Questions are not changes, and are not shown.
    #[test]
    fn a_watch_line_says_what_happened() {
        let seg = Segment::new("wifi", &[Family::V4]);
        announce(&seg, "10.0.1.7", "tv.local", "TV");
        let tv = seg.devices().remove(0);
        let line = |event| notice_json("IoT", &Notice { interface: "wifi".into(), event, ttl: Duration::from_secs(120) });
        for (event, said) in [
            (Event::Added(tv.clone()), "added"),
            (Event::Updated(tv.clone()), "updated"),
            (Event::Removed(tv.clone()), "removed"),
        ] {
            let json = line(event).unwrap();
            assert_eq!((json["event"].as_str(), json["segment"].as_str()), (Some(said), Some("IoT")));
            assert_eq!((json["ttl"].as_u64(), json["device"]["hostname"].as_str()), (Some(120), Some("tv.local")));
        }
        assert!(line(Event::Question(vec![])).is_none());
    }

    #[test]
    fn watch_is_refused_where_it_cannot_stream() {
        let reply: Value = serde_json::from_str(&handle(&[], &Watches::default(), "watch IoT")).unwrap();
        assert_eq!(reply["ok"], false);
    }

    #[test]
    fn bind_replaces_stale_sockets_but_not_live_ones_or_files() {
        let path = temp_socket("bind");
        drop(UnixListener::bind(path.to_str().unwrap()).unwrap()); // leaves a dead socket file
        let live = bind(path.to_str().unwrap()).expect("stale socket is replaced");
        assert!(bind(path.to_str().unwrap()).is_err(), "live instance is protected");
        drop(live);
        fs::remove_file(&path).unwrap();

        fs::write(&path, "precious").unwrap();
        assert!(bind(path.to_str().unwrap()).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "precious");
        fs::remove_file(&path).unwrap();
    }
}
