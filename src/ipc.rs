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
//! other segments, and this host as `[Advertise]` has it announce itself (with
//! `"own":true`: nothing is heard of it, as it does not hear itself). `probe` actively queries the interfaces of the segment
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

use alloc::boxed::Box;
use hashbrown::HashMap;
use core::time::Duration;

use rustix::fd::{AsRawFd, OwnedFd};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

use crate::time::Instant;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::segment::Notice;
use crate::device::{is_type, Device, Origin};
use crate::runtime::Why;
use crate::poll;
use crate::interface::{Event, Probed, Interface};
use crate::listener::Family;
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
    pub fn bind(path: &str, mode: rustix::fs::RawMode) -> Result<Server> {
        let listener = bind(path, mode)?;
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
            groups.iter().flat_map(|g| g.segment.take_notices().into_iter().map(move |n| (g.name.as_str(), n))).collect();
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
/// Listen on a Unix socket at `path` with permissions `mode`, replacing a
/// stale one.
pub fn bind(path: &str, mode: rustix::fs::RawMode) -> Result<OwnedFd> {
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
    rustix::fs::chmod(path, rustix::fs::Mode::from_raw_mode(mode)).map_err(Why).with_context(|| format!("setting permissions on {path}"))?;
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

/// The process at the other end of a connection, as the kernel has it. Where
/// the system does not say which process, only whose it is, there is no `pid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    pid: Option<i32>,
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
                    "pid": w.peer.and_then(|p| p.pid),
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
    Some(Peer { pid: Some(cred.pid.as_raw_pid()), uid: cred.uid.as_raw() })
}

/// Who is at the other end of `stream`, or `None` if the system will not say.
/// FreeBSD says whose user it is and which process, as `LOCAL_PEERCRED` does
/// since 13.0.
#[cfg(target_os = "freebsd")]
fn peer_of(stream: &OwnedFd) -> Option<Peer> {
    use rustix::fd::AsRawFd;

    /// `struct xucred`, which the `libc` crate does not let the process be read
    /// from: after the groups there is a union of a pointer and `cr_pid`, which
    /// is why it is not right after them.
    #[repr(C)]
    struct XUcred {
        version: libc::c_uint,
        uid: libc::uid_t,
        ngroups: libc::c_short,
        groups: [libc::gid_t; 16],
        pid: PidOrPointer,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    union PidOrPointer {
        pid: libc::pid_t,
        _unused: *mut libc::c_void,
    }
    /// The level of the options of a Unix socket (`SOL_LOCAL`), and `XUCRED_VERSION`.
    const SOL_LOCAL: libc::c_int = 0;
    const XUCRED_VERSION: libc::c_uint = 0;

    // SAFETY: all zeros is what it is before the kernel fills it in.
    let mut cred: XUcred = unsafe { core::mem::zeroed() };
    let mut len = core::mem::size_of::<XUcred>() as libc::socklen_t;
    // SAFETY: the descriptor is open, and `cred` is as long as `len` says.
    let ok = unsafe {
        libc::getsockopt(stream.as_raw_fd(), SOL_LOCAL, libc::LOCAL_PEERCRED, (&mut cred as *mut XUcred).cast(), &mut len)
    } == 0;
    // SAFETY: the kernel wrote the union by its `cr_pid` member, and it is plain data.
    let pid = Some(unsafe { cred.pid.pid }).filter(|&p| p > 0);
    (ok && cred.version == XUCRED_VERSION).then_some(Peer { pid, uid: cred.uid })
}

/// Who is at the other end of `stream`, or `None` if the system will not say.
/// The other BSDs say whose user it is, and not which process.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
fn peer_of(stream: &OwnedFd) -> Option<Peer> {
    use rustix::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the descriptor is open, and the two are valid to write to.
    (unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(Peer { pid: None, uid })
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
pub fn links_of(groups: &[Group], name: &str) -> Vec<Interface> {
    let mut links: Vec<Interface> = Vec::new();
    for seg in groups.iter().filter(|g| name.is_empty() || g.name == name).flat_map(|g| g.segment.interfaces()) {
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
/// family of it: its segment's notices are streamed from now on.
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
                present.push(event_json("present", name, seg.interface(), &device, ttl));
            }
            // Nothing is heard of this host: it is here as it advertises itself.
            for (device, ttl) in seg.own_devices().iter().filter_map(|(d, ttl)| Some((d.borrow().only_kinds(&query.kinds)?, *ttl))) {
                let mut line = event_json("present", name, seg.interface(), &device, ttl);
                line["device"]["own"] = Value::Bool(true);
                present.push(line);
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
    let removed = matches!(notice.event, Event::Removed(_));
    let device = notice.event.device()?.borrow();
    let key = device.key().map(|k| (notice.interface.clone(), k));
    let was_shown = key.as_ref().is_some_and(|k| shown.contains_key(k));
    match device.only_kinds(kinds) {
        Some(narrow) if !removed => {
            let line = event_json(if was_shown { "updated" } else { "added" }, segment, &notice.interface, &narrow, notice.ttl);
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
            let gone = narrow.unwrap_or_else(|| Device { services: Box::default(), ..device.clone() });
            Some(event_json("removed", segment, &notice.interface, &gone, Duration::ZERO))
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
    Some(event_json(event, segment, &notice.interface, &notice.event.device()?.borrow(), notice.ttl))
}

/// A watch line saying `event` of `device`, which has `ttl` left, on `interface`.
fn event_json(event: &str, segment: &str, interface: &str, device: &Device, ttl: Duration) -> Value {
    json!({ "event": event, "segment": segment, "ttl": ttl.as_secs(), "device": device_json(interface, device) })
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
        #[cfg(feature = "test-clock")]
        "advance" => advance(arg),
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
            let interfaces: Vec<String> = members[0].segment.interfaces().iter().map(|s| s.interface().to_string()).collect();
            let mut families: Vec<&str> = members
                .iter()
                .flat_map(|g| g.segment.interfaces())
                .flat_map(|seg| seg.families().to_vec())
                .map(family_name)
                .collect();
            families.sort_unstable();
            families.dedup();
            let untrusted = members[0].segment.untrusted();
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
        for seg in g.segment.interfaces() {
            let mut found = seg.devices();
            found.sort_by_key(|d| (d.key(), d.addrs().collect::<Vec<_>>()));
            list.extend(found.iter().map(|d| device_json(seg.interface(), d)));
            // This host, as it advertises itself, is among them.
            list.extend(seg.own_devices().iter().map(|(d, ttl)| own_json(seg.interface(), &d.borrow(), *ttl)));
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

/// Move the clock forward by the milliseconds `arg` says. What is due by then is
/// done before the next request is answered: the event loop runs what is due
/// after the request that moved the clock.
#[cfg(feature = "test-clock")]
fn advance(arg: &str) -> Value {
    match arg.parse::<u64>() {
        Ok(ms) => {
            crate::time::advance(Duration::from_millis(ms));
            json!({ "ok": true, "advanced_ms": ms })
        }
        Err(_) => error("advance <milliseconds>"),
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
    let mut links: Vec<Interface> = Vec::new();
    for seg in groups.iter().flat_map(|g| g.segment.interfaces()) {
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
                "instance": s.instance(),
                "type": s.kind(),
                "port": s.port(),
                "target": s.target(),
                // Text where it is: a value that is not is shown as the nearest.
                "txt": s.txt().map(|t| String::from_utf8_lossy(t)).collect::<Vec<_>>(),
                "subtypes": s.subtypes().collect::<Vec<_>>(),
                "ttl": (s.ttl() != 0).then_some(s.ttl()),
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

/// This host's own device, as it advertises itself on `interface`.
fn own_json(interface: &str, d: &Device, ttl: Duration) -> Value {
    let mut json = device_json(interface, d);
    json["own"] = Value::Bool(true);
    json["address_ttl"] = json!(ttl.as_secs());
    json
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
#[path = "../tests/unit/ipc.rs"]
mod tests;
