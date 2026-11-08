//! `mdnsctl`: command line client for the daemon's control socket (see
//! `ipc.rs` for the protocol). Every IPC command has a subcommand here.

// No std: its I/O is rustix's, its memory libc's malloc, and a panic aborts.
// Tests are built with std.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::ffi::CString;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, CStr};
use core::fmt;
use core::net::IpAddr;
use core::time::Duration;

use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
#[cfg(any(target_os = "linux", target_os = "android"))]
use rustix::process::PidfdFlags;
use rustix::process::{Pid, Signal, WaitOptions, WaitStatus};
use serde_json::Value;

use crate::runtime::{errno, Why};

// First, for its print macros.
#[macro_use]
#[path = "runtime.rs"]
mod runtime;
#[path = "args.rs"]
mod args;
// Shared with the daemon, which waits on more than a subscriber does.
#[allow(dead_code)]
#[path = "poll.rs"]
mod poll;
#[path = "signal.rs"]
mod signal;
// The daemon's: for its socket's path, and systemd time spans.
#[allow(dead_code)]
#[path = "config.rs"]
mod config;

/// Stdout, for what streams to it: a write fails once no one reads it.
struct Stdout;

impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        runtime::write_all(1, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

const TIMEOUT: Duration = Duration::from_secs(5);

/// A probe takes the daemon about four seconds to run before it replies.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Keep in sync with `ipc::MIN_QUERY_INTERVAL` in the daemon.
const MIN_INTERVAL: Duration = Duration::from_secs(10);

/// How long `devices --query` takes what answers, unless `--wait` says.
const DEFAULT_WAIT: Duration = Duration::from_secs(4);

/// How long a subscriber waits to connect again after losing the daemon, at
/// first and at most: the wait doubles with each failed try.
const RECONNECT_FIRST: Duration = Duration::from_millis(if cfg!(test) { 10 } else { 1000 });
const RECONNECT_MOST: Duration = Duration::from_millis(if cfg!(test) { 50 } else { 30_000 });

/// Events a subscriber holds while its script is busy; one past that is
/// dropped, and said so in the log.
const QUEUE: usize = 1024;

/// How often a subscriber looks up from waiting to see whether it was told
/// to stop.
const STOP_CHECK: Duration = Duration::from_millis(50);


#[derive(Debug, PartialEq, Eq)]
enum Command {
    Segments,
    Devices(Target),
    Probe(Option<String>),
    Watch(Target),
    Subscribe(Subscription),
    Watchers,
    Timers,
}

/// The segment of `devices` or `watch`, and the service types to ask for and
/// show (`--query`), how often a watch asks again (`--interval`), and how
/// long `devices --query` takes what answers (`--wait`).
#[derive(Debug, Default, PartialEq, Eq)]
struct Target {
    segment: String,
    query: Vec<String>,
    interval: Option<Duration>,
    wait: Option<Duration>,
}

/// What `subscribe` watches, and the script it runs for each event.
#[derive(Debug, PartialEq, Eq)]
struct Subscription {
    target: Target,
    /// The script and its arguments, run directly (its shebang says how).
    script: Vec<String>,
    /// Stay attached instead of going into the background.
    foreground: bool,
    /// Where a subscriber in the background writes what it has to say, and
    /// its script's output.
    log: Option<String>,
}

impl From<&str> for Target {
    fn from(segment: &str) -> Target {
        Target { segment: segment.into(), ..Target::default() }
    }
}

impl Target {
    /// The request line for `command` on this target.
    fn request(&self, command: &str) -> String {
        let mut line = command.to_string();
        for kind in &self.query {
            line.push_str(&format!(" --query={kind}"));
        }
        if let Some(every) = self.interval {
            line.push_str(&format!(" --interval={}", every.as_secs()));
        }
        format!("{line} {}", self.segment)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    socket: String,
    json: bool,
    /// For `devices`: each device a line of JSON of its own.
    segmented: bool,
    verbose: bool,
    command: Command,
}

/// What each command is called, what it does, what it takes after its
/// options, and the options of its own, as `--help` shows them.
struct CommandInfo {
    name: &'static str,
    about: &'static str,
    args: &'static str,
    arguments: &'static [(&'static str, &'static str)],
    options: &'static [(&'static str, &'static str)],
}

const QUERY_HELP: &str = "Ask for this service type by name, and list only devices of it";
const INTERVAL_HELP: &str = "Ask for the --query types again this often (at least 10s)";
const SEGMENT: (&str, &str) = ("<NAME>...", "The segment");

const COMMANDS: &[CommandInfo] = &[
    CommandInfo { name: "segments", about: "List the configured segments", args: "", arguments: &[], options: &[] },
    CommandInfo {
        name: "devices",
        about: "List the devices discovered in a segment",
        args: " <NAME>...",
        arguments: &[SEGMENT],
        options: &[("--query <TYPE>", QUERY_HELP), ("--wait <SPAN>", "How long to take what answers a --query [default: 4s]")],
    },
    CommandInfo {
        name: "probe",
        about: "Actively query for devices (all segments, or one)",
        args: " [NAME]...",
        arguments: &[("[NAME]...", "The segment; all of them if left out")],
        options: &[],
    },
    CommandInfo {
        name: "watch",
        about: "Print the devices of a segment as they appear and go",
        args: " <NAME>...",
        arguments: &[SEGMENT],
        options: &[("--query <TYPE>", "Ask for this service type by name, and show only devices of it"), ("--interval <SPAN>", INTERVAL_HELP)],
    },
    CommandInfo {
        name: "subscribe",
        about: "Run SCRIPT for each change in a segment, in the background",
        args: " <NAME>... -- <SCRIPT>...",
        arguments: &[SEGMENT, ("<SCRIPT>...", "The script to run for each change, and its arguments, after --")],
        options: &[
            ("--query <TYPE>", "Ask for this service type by name, and run SCRIPT only for devices of it"),
            ("--interval <SPAN>", INTERVAL_HELP),
            ("--foreground", "Stay attached instead of going into the background"),
            ("--log <FILE>", "Append what the subscriber has to say, and SCRIPT's output, to FILE"),
        ],
    },
    CommandInfo { name: "watchers", about: "List the watches open on the daemon, and who holds them", args: "", arguments: &[], options: &[] },
    CommandInfo { name: "timers", about: "List the timers the daemon has scheduled", args: "", arguments: &[], options: &[] },
];

const GLOBAL_OPTIONS: &[(&str, &str)] = &[
    ("-s, --socket <PATH>", "The control socket [default: /run/mdnsd/mdnsd.sock]"),
    ("-v, --verbose", "List devices with all details (addresses, services)"),
    ("--json", "Print the daemon's reply unchanged"),
    ("--segmented-json", "With devices: print each device as a line of JSON of its own"),
    ("-h, --help", "Print help"),
];

/// What the command line asks for instead of a command: help or the version,
/// printed to stdout, or a usage error, printed to stderr with how to use it;
/// with no command at all, the help, to stderr.
#[derive(Debug, PartialEq, Eq)]
enum Early {
    Help(String),
    Version,
    Usage { message: String, usage: String },
    NoCommand,
}

impl Early {
    fn usage(command: Option<&CommandInfo>, message: impl Into<String>) -> Early {
        Early::Usage { message: message.into(), usage: usage_line(command) }
    }

    /// Print it as it is for, and the exit code that goes with it.
    fn exit(self) -> c_int {
        match self {
            Early::Help(text) => print!("{text}"),
            Early::Version => println!("mdnsctl {}", env!("CARGO_PKG_VERSION")),
            Early::Usage { message, usage } => {
                eprintln!("error: {message}\n\nUsage: {usage}\n\nFor more information, try '--help'.");
                return 2;
            }
            Early::NoCommand => {
                eprint!("{}", help(None));
                return 2;
            }
        }
        0
    }
}

fn usage_line(command: Option<&CommandInfo>) -> String {
    match command {
        Some(c) => format!("mdnsctl {} [OPTIONS]{}", c.name, c.args),
        None => "mdnsctl [OPTIONS] <COMMAND>".to_string(),
    }
}

/// Lines of `rows` as a column of names and one of what they are, under
/// `title`, as `--help` lists them.
fn help_section(out: &mut String, title: &str, rows: &[(&str, &str)]) {
    // A long option alone lines up with those that have a short one.
    let indent = |name: &str| if name.starts_with("--") { 6 } else { 2 };
    let column = rows.iter().map(|(name, _)| indent(name) + name.len()).max().unwrap_or(0) + 2;
    out.push_str(&format!("\n{title}:\n"));
    for (name, about) in rows {
        out.push_str(&format!("{:indent$}{name:<width$}{about}\n", "", indent = indent(name), width = column - indent(name)));
    }
}

/// `--help`, for `command` or for mdnsctl as a whole.
fn help(command: Option<&CommandInfo>) -> String {
    let mut out = format!("{}\n\nUsage: {}\n", command.map_or("Query the mdnsd daemon over its control socket", |c| c.about), usage_line(command));
    match command {
        Some(c) => {
            if !c.arguments.is_empty() {
                help_section(&mut out, "Arguments", c.arguments);
            }
            let options: Vec<(&str, &str)> = c.options.iter().chain(GLOBAL_OPTIONS).copied().collect();
            help_section(&mut out, "Options", &options);
        }
        None => {
            let commands: Vec<(&str, &str)> = COMMANDS.iter().map(|c| (c.name, c.about)).collect();
            help_section(&mut out, "Commands", &commands);
            let options: Vec<(&str, &str)> = GLOBAL_OPTIONS.iter().copied().chain([("-V, --version", "Print version")]).collect();
            help_section(&mut out, "Options", &options);
        }
    }
    out
}

/// A `--query` service type, as given: the daemon checks it is one.
fn service_type(value: &str) -> Result<String, String> {
    if value.is_empty() || value.contains(char::is_whitespace) {
        return Err("not a service type (like _http._tcp)".into());
    }
    Ok(value.to_string())
}

/// A `--wait`: a time span longer than nothing.
fn wait_span(value: &str) -> Result<Duration, String> {
    let span = config::parse_timespan(value).map_err(|e| e.to_string())?;
    if span.is_zero() {
        return Err("it must be longer than nothing".into());
    }
    Ok(span)
}

/// An `--interval`: a time span of at least [`MIN_INTERVAL`], in whole
/// seconds as the daemon takes it, part of a second more being a second
/// more, so it is never asked more often than said.
fn interval_span(value: &str) -> Result<Duration, String> {
    let span = config::parse_timespan(value).map_err(|e| e.to_string())?;
    if span < MIN_INTERVAL {
        return Err(format!("it must be at least {}s", MIN_INTERVAL.as_secs()));
    }
    Ok(Duration::from_secs(span.as_secs() + u64::from(span.subsec_nanos() > 0)))
}

/// Read the command line into [`Options`]. Options may come anywhere, before
/// the command or after it; a segment's name is the words left over, so it
/// needs no quoting even with spaces in it; `subscribe`'s script is what
/// comes after `--`. Help, the version and usage errors come back as
/// [`Early`].
fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, Early> {
    use args::Arg::{Long, Short, Value};

    let mut args: Vec<String> = args.into_iter().collect();
    let after_dashes = args.iter().position(|a| a == "--").map(|at| args.split_off(at).split_off(1));
    let mut parser = args::Parser::new(args);
    let (mut socket, mut verbose, mut json, mut segmented, mut asked_help) = (config::DEFAULT_SOCKET.to_string(), false, false, false, false);
    let mut command: Option<&CommandInfo> = None;
    let (mut words, mut query, mut interval, mut wait, mut foreground, mut log) = (Vec::new(), Vec::new(), None, None, false, None);
    let takes = |command: Option<&CommandInfo>, option: &str| command.is_some_and(|c| c.options.iter().any(|(o, _)| o.starts_with(option)));
    let bad = |command, e: args::Error| Early::usage(command, e.to_string());
    loop {
        let arg = match parser.next() {
            Ok(Some(arg)) => arg,
            Ok(None) => break,
            Err(e) => return Err(bad(command, e)),
        };
        let invalid = |name: &str, value: &str, e: String| Early::usage(command, format!("invalid value '{value}' for '--{name}': {e}"));
        match arg {
            Short('s') | Long("socket") => socket = parser.value().map_err(|e| bad(command, e))?,
            Short('v') | Long("verbose") => verbose = true,
            Long("json") => json = true,
            Long("segmented-json") => segmented = true,
            Short('h') | Long("help") => asked_help = true,
            Short('V') | Long("version") => return Err(Early::Version),
            Long("query") if takes(command, "--query") => {
                let v = parser.value().map_err(|e| bad(command, e))?;
                query.push(service_type(&v).map_err(|e| invalid("query", &v, e))?);
            }
            Long("wait") if takes(command, "--wait") => {
                let v = parser.value().map_err(|e| bad(command, e))?;
                wait = Some(wait_span(&v).map_err(|e| invalid("wait", &v, e))?);
            }
            Long("interval") if takes(command, "--interval") => {
                let v = parser.value().map_err(|e| bad(command, e))?;
                interval = Some(interval_span(&v).map_err(|e| invalid("interval", &v, e))?);
            }
            Long("foreground") if takes(command, "--foreground") => foreground = true,
            Long("log") if takes(command, "--log") => {
                let v = parser.value().map_err(|e| bad(command, e))?;
                if v.is_empty() {
                    return Err(invalid("log", &v, "a file is needed".into()));
                }
                log = Some(v);
            }
            Value(word) => {
                match command {
                    Some(_) => words.push(word),
                    None => match COMMANDS.iter().find(|c| c.name == word) {
                        Some(c) => command = Some(c),
                        None => return Err(Early::usage(None, format!("unrecognized subcommand '{word}'"))),
                    },
                }
            }
            arg => return Err(bad(command, arg.unexpected())),
        }
    }
    if asked_help {
        return Err(Early::Help(help(command)));
    }
    let Some(info) = command else {
        return Err(Early::NoCommand);
    };
    let usage = |message: &str| Early::usage(command, message);
    let script = match (info.name, after_dashes) {
        ("subscribe", Some(script)) if !script.is_empty() => script,
        ("subscribe", _) => return Err(usage("a script to run is needed, after --")),
        (_, rest) => {
            words.extend(rest.unwrap_or_default());
            Vec::new()
        }
    };
    if (wait.is_some() || interval.is_some()) && query.is_empty() {
        return Err(usage(&format!("--{} is for --query", if wait.is_some() { "wait" } else { "interval" })));
    }
    if segmented && info.name != "devices" {
        return Err(usage("--segmented-json is for devices"));
    }
    if segmented && json {
        return Err(usage("--segmented-json and --json are one or the other"));
    }
    // The protocol is one request per line.
    let name = words.join(" ");
    if name.contains(['\n', '\r']) {
        return Err(usage("a segment's name cannot hold a line break"));
    }
    let target = |interval, wait| match name.trim().is_empty() {
        true if words.is_empty() => Err(usage("the segment's name is needed")),
        true => Err(usage("the segment's name is blank")),
        false => Ok(Target { segment: name.clone(), query: query.clone(), interval, wait }),
    };
    let command = match info.name {
        "devices" => Command::Devices(target(None, wait)?),
        "probe" => Command::Probe(Some(name.clone()).filter(|n| !n.trim().is_empty())),
        "watch" => Command::Watch(target(interval, None)?),
        "subscribe" => Command::Subscribe(Subscription { target: target(interval, None)?, script, foreground, log }),
        _ if !words.is_empty() => return Err(usage(&format!("unexpected argument '{}' found", words[0]))),
        "segments" => Command::Segments,
        "watchers" => Command::Watchers,
        _ => Command::Timers,
    };
    Ok(Options { socket, json, segmented, verbose, command })
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// Bad command line.
    Usage(String),
    /// Could not talk to the daemon.
    Connect(String),
    /// The daemon answered with an error.
    Server(String),
}

// The system, through rustix, and what only libc does: forking and running
// a program, the environment, and the words for an error.

/// The time on the monotonic clock: for how long something takes, and when
/// to do something next.
fn now() -> Duration {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// Write all of `buf` to `fd`, waiting as it must.
fn write_all(fd: impl AsFd, mut buf: &[u8]) -> Result<(), Errno> {
    while !buf.is_empty() {
        match rustix::io::write(&fd, buf) {
            Ok(0) => return Err(Errno::PIPE),
            Ok(n) => buf = &buf[n..],
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// All of the file at `path`.
fn read_file(path: &str) -> Result<Vec<u8>, Errno> {
    let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
    loop {
        match rustix::io::read(&fd, &mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
}

/// Make reads and writes on `fd` return at once, with `AGAIN`, rather than
/// wait.
fn set_nonblocking(fd: impl AsFd) -> Result<(), Errno> {
    let flags = rustix::fs::fcntl_getfl(&fd)?;
    rustix::fs::fcntl_setfl(&fd, flags | OFlags::NONBLOCK)
}

/// The environment variable `name`, if it is set and text.
fn getenv(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    // SAFETY: a NUL-terminated name; what getenv returns, if anything, is a
    // NUL-terminated string that stays put while nothing changes the
    // environment, which nothing here does.
    let value = unsafe { libc::getenv(name.as_ptr()) };
    // SAFETY: as above.
    (!value.is_null()).then(|| unsafe { CStr::from_ptr(value) }.to_str().ok().map(str::to_string)).flatten()
}

/// End the process, with `code`.
fn exit(code: i32) -> ! {
    // SAFETY: exit takes a status, and does not return.
    unsafe { libc::exit(code) }
}

unsafe extern "C" {
    /// The process's environment, as `NAME=value` strings, NULL-terminated.
    static environ: *const *const c_char;
}

/// Run `program` (a path) with `args`, in the environment of this process
/// with `env` added, its stdin from `stdin`. That it could not be run at all
/// (not there, not executable) is an error here, not an exit status later.
fn spawn(program: &str, args: &[String], env: &[(&str, String)], stdin: &OwnedFd) -> Result<Pid, Errno> {
    let c_string = |s: &str| CString::new(s).map_err(|_| Errno::INVAL);
    // Everything the child needs is made before it is: between fork and
    // exec, it may not allocate.
    let path = c_string(program)?;
    let argv: Vec<CString> = core::iter::once(program).chain(args.iter().map(String::as_str)).map(c_string).collect::<Result<_, _>>()?;
    let mut envp: Vec<CString> = Vec::new();
    // SAFETY: environ is a NULL-terminated array of NUL-terminated strings,
    // which nothing here changes.
    unsafe {
        let mut at = environ;
        while !at.is_null() && !(*at).is_null() {
            let entry = CStr::from_ptr(*at);
            let name = entry.to_bytes().split(|&b| b == b'=').next().unwrap_or_default();
            if !env.iter().any(|(n, _)| n.as_bytes() == name) {
                envp.push(entry.to_owned());
            }
            at = at.add(1);
        }
    }
    for (name, value) in env {
        envp.push(c_string(&format!("{name}={value}"))?);
    }
    let argv_ptrs: Vec<*const c_char> = argv.iter().map(|a| a.as_ptr()).chain(core::iter::once(core::ptr::null())).collect();
    let envp_ptrs: Vec<*const c_char> = envp.iter().map(|e| e.as_ptr()).chain(core::iter::once(core::ptr::null())).collect();
    // The child says why it could not run the program, if it could not; a
    // program that runs closes this, as it is not inherited.
    let (report_rx, report_tx) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let (stdin, report) = (stdin.as_raw_fd(), report_tx.as_raw_fd());

    // SAFETY: no other thread is running, and the child makes only
    // async-signal-safe calls on what was made above until it runs the
    // program or exits.
    match unsafe { libc::fork() } {
        -1 => Err(errno()),
        0 => unsafe {
            if stdin == 0 || libc::dup2(stdin, 0) >= 0 {
                // A program starts with SIGPIPE as the system has it, whatever
                // this process did with it.
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }
            let errno = (*crate::runtime::errno_location()).to_ne_bytes();
            libc::write(report, errno.as_ptr().cast(), errno.len());
            libc::_exit(127)
        },
        pid => {
            drop(report_tx);
            // SAFETY: fork returned the PID of the child it made.
            let pid = unsafe { Pid::from_raw_unchecked(pid) };
            let mut errno = [0u8; 4];
            let mut got = 0;
            while got < errno.len() {
                match rustix::io::read(&report_rx, &mut errno[got..]) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(Errno::INTR) => {}
                    Err(e) => return Err(e),
                }
            }
            if got == 0 {
                return Ok(pid);
            }
            // It never ran: reap it.
            let _ = rustix::process::waitpid(Some(pid), WaitOptions::empty());
            Err(Errno::from_raw_os_error(i32::from_ne_bytes(errno)))
        }
    }
}

/// How a process ended, as std says it.
fn status_text(status: WaitStatus) -> String {
    match (status.exit_status(), status.terminating_signal()) {
        (Some(code), _) => format!("exit status: {code}"),
        (_, Some(sig)) => format!("signal: {sig}"),
        _ => format!("{status:?}"),
    }
}

fn connect_err(socket: &str, e: Errno) -> Failure {
    Failure::Connect(format!("cannot talk to {socket}: {} (is the daemon running, and can you access the socket?)", Why(e)))
}

/// A connection to the daemon: its socket, and what of its next line has
/// come.
#[derive(Debug)]
struct Conn {
    fd: OwnedFd,
    pending: Vec<u8>,
}

impl Conn {
    /// The next whole line, without its newline; `None` once the daemon has
    /// closed the connection, a line it cut short not counting as one.
    fn read_line(&mut self) -> Result<Option<String>, Errno> {
        let mut buf = [0u8; 4096];
        loop {
            if let Some(end) = self.pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                return Ok(Some(String::from_utf8_lossy(&line[..end]).into_owned()));
            }
            match rustix::io::read(&self.fd, &mut buf) {
                Ok(0) => return Ok(None),
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(Errno::INTR) => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// How long a read may wait before it fails with `AGAIN`; `None` for as
    /// long as it takes. A write may wait [`TIMEOUT`].
    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), Errno> {
        use rustix::net::sockopt::{set_socket_timeout, Timeout};
        set_socket_timeout(&self.fd, Timeout::Recv, timeout)?;
        set_socket_timeout(&self.fd, Timeout::Send, Some(TIMEOUT))
    }
}

/// Connect and send one request line, waiting up to `timeout` for replies.
fn send(socket: &str, line: &str, timeout: Duration) -> Result<Conn, Failure> {
    let err = |e| connect_err(socket, e);
    let connected = || {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
        let addr = SocketAddrUnix::new(socket)?;
        let fd = rustix::net::socket_with(AddressFamily::UNIX, SocketType::STREAM, SocketFlags::CLOEXEC, None)?;
        rustix::io::retry_on_intr(|| rustix::net::connect(&fd, &addr))?;
        Ok(fd)
    };
    let conn = Conn { fd: connected().map_err(err)?, pending: Vec::new() };
    conn.set_read_timeout(Some(timeout)).map_err(err)?;
    write_all(&conn.fd, format!("{line}\n").as_bytes()).map_err(err)?;
    Ok(conn)
}

/// Send one request line and return the one-line reply.
fn request(socket: &str, line: &str, timeout: Duration) -> Result<String, Failure> {
    let mut conn = send(socket, line, timeout)?;
    match conn.read_line().map_err(|e| connect_err(socket, e))? {
        Some(reply) => Ok(reply.trim_end().to_string()),
        None => Err(Failure::Connect("the daemon closed the connection without replying".into())),
    }
}

/// The error a reply carries, if it is one.
fn server_error(reply: &Value) -> Option<Failure> {
    (reply["ok"] == Value::Bool(false))
        .then(|| Failure::Server(reply["error"].as_str().unwrap_or("request failed").to_string()))
}

/// Send the watch request `line` and wait for the daemon to accept it: the
/// stream its events will come on, with no time limit from then on.
fn open_watch(socket: &str, line: &str) -> Result<Conn, Failure> {
    let mut conn = send(socket, line, TIMEOUT)?;
    let Some(ack) = conn.read_line().map_err(|e| connect_err(socket, e))? else {
        return Err(Failure::Connect("the daemon closed the connection".into()));
    };
    let reply: Value =
        serde_json::from_str(ack.trim_end()).map_err(|e| Failure::Server(format!("unreadable reply: {e}")))?;
    if let Some(failure) = server_error(&reply) {
        return Err(failure);
    }
    // Now it waits for changes, however long that takes.
    conn.set_read_timeout(None).map_err(|e| connect_err(socket, e))?;
    Ok(conn)
}

/// Follow a segment: print each change the daemon reports until it stops (an
/// error) or `out` is closed (success: `mdnsctl watch | head` is fine).
fn watch(opts: &Options, target: &Target, out: &mut impl fmt::Write) -> Result<(), Failure> {
    let socket = &opts.socket;
    let mut conn = open_watch(socket, &target.request("watch"))?;
    let mut seen = BTreeSet::new();
    loop {
        let Some(line) = conn.read_line().map_err(|e| connect_err(socket, e))? else {
            return Err(Failure::Connect("the daemon closed the connection".into()));
        };
        let text = line.trim_end();
        let reply: Value =
            serde_json::from_str(text).map_err(|e| Failure::Server(format!("unreadable reply: {e}")))?;
        if let Some(failure) = server_error(&reply) {
            return Err(failure);
        }
        let shown = if opts.json {
            Some(format!("{text}\n"))
        } else {
            render_event(&reply, opts.verbose, &mut seen)?
        };
        if let Some(shown) = shown
            && out.write_str(&shown).is_err()
        {
            return Ok(());
        }
    }
}

/// List the devices of the types `target` asks for: open a watch for them,
/// which sends those already known and asks for the rest, and take what
/// comes for `--wait`. Each device is printed as `devices` lists it the first
/// time it is found (so those known come at once), and the summary that
/// `devices` ends with after the wait; with `--json`, one reply at the end,
/// as `devices` gives it, with each device as last heard of and none that
/// went; with `--segmented-json`, each device a line of JSON of its own the
/// moment it is found, as `--json` has it, and nothing at the end.
fn devices_query(opts: &Options, target: &Target, out: &mut impl fmt::Write) -> Result<(), Failure> {
    let socket = &opts.socket;
    let mut conn = open_watch(socket, &target.request("watch"))?;
    let deadline = now() + target.wait.unwrap_or(DEFAULT_WAIT);
    // What is found, by where and who it is, as last heard of.
    let mut found: Vec<(String, Value)> = Vec::new();
    // What is printed: hosts, or with -v devices, by their key.
    let mut shown = BTreeSet::new();
    loop {
        let left = deadline.saturating_sub(now());
        if left.is_zero() {
            break;
        }
        conn.set_read_timeout(Some(left)).map_err(|e| connect_err(socket, e))?;
        let line = match conn.read_line() {
            Ok(Some(line)) => line,
            Ok(None) => return Err(Failure::Connect("the daemon closed the connection".into())),
            Err(Errno::AGAIN) => break,
            Err(e) => return Err(connect_err(socket, e)),
        };
        let event: Value =
            serde_json::from_str(line.trim_end()).map_err(|e| Failure::Server(format!("unreadable reply: {e}")))?;
        if let Some(failure) = server_error(&event) {
            return Err(failure);
        }
        let device = &event["device"];
        let key = device_key(device);
        found.retain(|(k, _)| *k != key);
        if event["event"].as_str().ok_or_else(bad_reply)? == "removed" {
            continue;
        }
        found.push((key.clone(), device.clone()));
        let text = match (opts.json, opts.verbose) {
            _ if opts.segmented => shown.insert(key).then(|| format!("{device}\n")),
            (true, _) => None,
            (false, true) if shown.insert(key) => Some(verbose_lines(device, &device_row(device)?, [0, 0])),
            (false, true) => None,
            (false, false) => brief_row(device)
                .filter(|row| shown.insert(row[0].to_ascii_lowercase()))
                .map(|row| brief_line(&row, [0, 0])),
        };
        if let Some(text) = text
            && out.write_str(&text).is_err()
        {
            return Ok(());
        }
    }
    drop(conn);

    let name = target.segment.trim_matches('"');
    let text = if opts.segmented {
        String::new()
    } else if opts.json {
        let devices: Vec<Value> = found.into_iter().map(|(_, d)| d).collect();
        format!("{}\n", serde_json::json!({ "ok": true, "name": name, "devices": devices }))
    } else if opts.verbose {
        devices_summary(name, found.len(), 0)
    } else {
        let hosts: BTreeSet<String> = found.iter().filter_map(|(_, d)| d["hostname"].as_str()).map(str::to_ascii_lowercase).collect();
        let unnamed = found.iter().filter(|(_, d)| !d["hostname"].is_string()).count();
        devices_summary(name, hosts.len(), unnamed)
    };
    let _ = out.write_str(&text);
    Ok(())
}

/// What tells a device of a watch apart from the others: where it is, and
/// its hostname, or else its first address.
fn device_key(device: &Value) -> String {
    let who = match device["hostname"].as_str() {
        Some(host) => host.to_ascii_lowercase(),
        None => device["addresses"][0].as_str().unwrap_or_default().to_string(),
    };
    format!("{}\0{who}", device["interface"].as_str().unwrap_or_default())
}

/// Subscribe: open the watch, then (unless in the foreground) go into the
/// background, printing the PID, and run the script for each event until
/// told to stop. What can go wrong before the first event is reported here,
/// for the caller; what goes wrong later is logged.
fn subscribe(opts: &Options, sub: &Subscription) -> Result<(), Failure> {
    let script = executable(&sub.script[0]).map_err(Failure::Usage)?;
    let log = match &sub.log {
        Some(path) => Some(
            rustix::fs::open(path.as_str(), OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND | OFlags::CLOEXEC, Mode::from_raw_mode(0o666))
                .map_err(|e| Failure::Usage(format!("cannot write to {path}: {}", Why(e))))?,
        ),
        None => None,
    };
    let line = sub.target.request("watch");
    // In the background, the watch is opened by the process that holds it,
    // so that `watchers` lists the subscriber's PID, not its parent's.
    let conn = if sub.foreground { open_watch(&opts.socket, &line)? } else { detach(&opts.socket, &line, log.as_ref())? };
    let signals = signal::install().map_err(|e| Failure::Usage(format!("cannot handle signals: {e}")))?;
    note(&format!("watching {}, running {script} for each change", sub.target.segment));

    let mut subscriber = Subscriber::new(&opts.socket, &line, conn, script, sub.script[1..].to_vec());
    loop {
        let mut fds = vec![poll::readable(signals.fd())];
        fds.extend(subscriber.fds());
        let timeout = subscriber.deadline().map(|at| at.saturating_sub(now()));
        if let Err(e) = poll::wait(&mut fds, timeout) {
            note(&format!("cannot wait: {e}"));
            break;
        }
        if signals.take().is_some() {
            break;
        }
        subscriber.turn(&fds[1..], now());
    }
    subscriber.stop();
    note("stopped");
    Ok(())
}

/// `name` as a script to run: a path, or a name looked up in `PATH`, of an
/// executable file. Made absolute, so that it is the same file whatever
/// happens to the working directory or `PATH` later, but not resolved
/// through symlinks: `sh` linked to `bash`, or a busybox applet, behaves by
/// the name it is run under.
fn executable(name: &str) -> Result<String, String> {
    let candidates: Vec<String> = if name.contains('/') {
        vec![name.to_string()]
    } else {
        // An empty entry is the working directory.
        let path = getenv("PATH").unwrap_or_default();
        path.split(':').map(|dir| if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") }).collect()
    };
    let runnable = |p: &String| rustix::fs::stat(p.as_str()).is_ok_and(|st| FileType::from_raw_mode(st.st_mode).is_file() && st.st_mode & 0o111 != 0);
    let found = candidates.into_iter().find(runnable).ok_or_else(|| format!("{name}: not an executable file"))?;
    if found.starts_with('/') {
        return Ok(found);
    }
    let cwd = rustix::process::getcwd(Vec::new()).map_err(|e| format!("{name}: {}", Why(e)))?;
    let cwd = cwd.to_string_lossy();
    Ok(format!("{cwd}/{}", found.trim_start_matches("./")))
}

/// Go into the background, and open the watch `line` there. The child, in a
/// session of its own, opens it and tells the parent how that went: the
/// parent then prints the child's PID and exits, or returns the error, for
/// the caller to hear of. The child carries on with the watch, its output
/// going to `log`, or nowhere.
fn detach(socket: &str, line: &str, log: Option<&OwnedFd>) -> Result<Conn, Failure> {
    let failed = |e| Failure::Connect(format!("cannot go into the background: {}", Why(e)));
    let (report_rx, report_tx) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(failed)?;
    // SAFETY: no other thread has been started, so the child is a full copy.
    match unsafe { libc::fork() } {
        -1 => Err(failed(errno())),
        0 => {
            drop(report_rx);
            let opened = settle_in_background(log).and_then(|()| open_watch(socket, line));
            // How it went: `+`, or a letter for the kind of error and the
            // message.
            let report = match &opened {
                Ok(_) => "+".to_string(),
                Err(Failure::Server(m)) => format!("S{m}"),
                Err(Failure::Connect(m) | Failure::Usage(m)) => format!("C{m}"),
            };
            let _ = write_all(&report_tx, report.as_bytes());
            drop(report_tx);
            let Ok(conn) = opened else { exit(1) };
            Ok(conn)
        }
        pid => {
            drop(report_tx);
            let mut report = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = rustix::io::retry_on_intr(|| rustix::io::read(&report_rx, &mut buf)) {
                report.extend_from_slice(&buf[..n]);
            }
            let report = String::from_utf8_lossy(&report).into_owned();
            // Nothing at all: the child died before it could say.
            match (report.chars().next(), report.get(1..).unwrap_or_default()) {
                (Some('+'), _) => {
                    println!("{pid}");
                    exit(0);
                }
                (None, _) => Err(Failure::Connect("the subscriber died before it was watching".into())),
                (Some('S'), message) => Err(Failure::Server(message.into())),
                (_, message) => Err(Failure::Connect(message.into())),
            }
        }
    }
}

/// In the child of [`detach`]: leave the caller's session, so that its
/// terminal going away does not take the subscriber with it, and send stdin
/// from `/dev/null` and stdout and stderr to `log`, or there.
fn settle_in_background(log: Option<&OwnedFd>) -> Result<(), Failure> {
    let failed = |what: &str, e| Failure::Connect(format!("cannot go into the background: {what}: {}", Why(e)));
    rustix::process::setsid().map_err(|e| failed("setsid", e))?;
    let null = rustix::fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty());
    let null = null.map_err(|e| Failure::Connect(format!("cannot open /dev/null: {}", Why(e))))?;
    let out = log.unwrap_or(&null);
    rustix::stdio::dup2_stdin(&null).map_err(|e| failed("dup2", e))?;
    rustix::stdio::dup2_stdout(out).map_err(|e| failed("dup2", e))?;
    rustix::stdio::dup2_stderr(out).map_err(|e| failed("dup2", e))?;
    Ok(())
}

/// A subscriber: the watch it reads events from, opened again whenever it is
/// lost, and the script it runs for each event, one at a time, all from one
/// loop that waits on whichever of them has something to do. Times are of
/// [`now`].
struct Subscriber {
    socket: String,
    line: String,
    script: String,
    args: Vec<String>,
    /// The watch while it is open.
    watch: Option<Conn>,
    /// While it is not: when to try to open it again, and how long to wait
    /// after that if it fails.
    retry: Option<(Duration, Duration)>,
    /// Events waiting for the script.
    queue: VecDeque<String>,
    running: Option<Running>,
}

/// The script, running for an event.
struct Running {
    pid: Pid,
    /// Readable once it has exited, where the kernel can say so.
    pidfd: Option<OwnedFd>,
    /// Its stdin, and what of the event is still to be written to it.
    stdin: Option<(OwnedFd, Vec<u8>)>,
    event: String,
}

impl Subscriber {
    /// A subscriber reading the watch `line` from `conn`, as opened on
    /// `socket`, running `script` with `args`.
    fn new(socket: &str, line: &str, conn: Conn, script: String, args: Vec<String>) -> Subscriber {
        let (socket, line) = (socket.to_string(), line.to_string());
        let mut subscriber = Subscriber { socket, line, script, args, watch: None, retry: None, queue: VecDeque::new(), running: None };
        subscriber.watching(conn);
        subscriber
    }

    /// Read events from `conn` from now on, without waiting on it.
    fn watching(&mut self, conn: Conn) {
        match set_nonblocking(&conn.fd) {
            Ok(()) => (self.watch, self.retry) = (Some(conn), None),
            Err(e) => {
                note(&format!("lost the daemon: {}", Why(e)));
                self.retry = Some((now() + RECONNECT_FIRST, RECONNECT_FIRST));
            }
        }
    }

    /// The descriptors to wait on: the watch, readable when events come; the
    /// script's stdin, writable when it takes more; and the script, readable
    /// once it exits.
    fn fds(&self) -> Vec<libc::pollfd> {
        let mut fds = Vec::new();
        if let Some(conn) = &self.watch {
            fds.push(poll::readable(conn.fd.as_raw_fd()));
        }
        if let Some(running) = &self.running {
            if let Some((stdin, _)) = &running.stdin {
                fds.push(libc::pollfd { fd: stdin.as_raw_fd(), events: libc::POLLOUT, revents: 0 });
            }
            if let Some(pidfd) = &running.pidfd {
                fds.push(poll::readable(pidfd.as_raw_fd()));
            }
        }
        fds
    }

    /// When to look again whatever happens: to open the watch again, or to
    /// see whether a script the kernel cannot tell of has exited.
    fn deadline(&self) -> Option<Duration> {
        let check = self.running.as_ref().filter(|r| r.pidfd.is_none()).map(|_| now() + STOP_CHECK);
        self.retry.map(|(at, _)| at).into_iter().chain(check).min()
    }

    /// Do what `fds` (as [`Subscriber::fds`] gave them, after waiting) say
    /// can be done, and what is due at `now`.
    fn turn(&mut self, fds: &[libc::pollfd], now: Duration) {
        let ready = |fd: i32, flags: libc::c_short| fds.iter().any(|p| p.fd == fd && p.revents & (flags | libc::POLLHUP | libc::POLLERR) != 0);
        if self.watch.as_ref().is_some_and(|conn| ready(conn.fd.as_raw_fd(), libc::POLLIN)) {
            self.read();
        }
        if let Some(running) = &mut self.running {
            if running.stdin.as_ref().is_some_and(|(stdin, _)| ready(stdin.as_raw_fd(), libc::POLLOUT)) {
                running.feed();
            }
            let exited = running.pidfd.as_ref().is_none_or(|pidfd| ready(pidfd.as_raw_fd(), libc::POLLIN));
            if exited {
                match rustix::process::waitpid(Some(running.pid), WaitOptions::NOHANG) {
                    // Stopped or continued is not ended.
                    Ok(Some((_, status))) if status.exited() || status.signaled() => {
                        if status.exit_status() != Some(0) {
                            note(&format!("{} {}, for: {}", self.script, status_text(status), running.event));
                        }
                        self.running = None;
                    }
                    Ok(_) | Err(Errno::INTR) => {}
                    Err(e) => {
                        note(&format!("lost {}: {}", self.script, Why(e)));
                        self.running = None;
                    }
                }
            }
        }
        if self.running.is_none()
            && let Some(event) = self.queue.pop_front()
        {
            self.start(event);
        }
        if let Some((at, wait)) = self.retry.filter(|&(at, _)| at <= now) {
            match open_watch(&self.socket, &self.line) {
                Ok(conn) => {
                    note("watching again");
                    self.watching(conn);
                }
                Err(failure) => {
                    if let Failure::Server(why) = failure {
                        note(&format!("the daemon refuses the watch: {why}"));
                    }
                    let wait = (wait * 2).min(RECONNECT_MOST);
                    self.retry = Some((at.max(now) + wait, wait));
                }
            }
        }
    }

    /// Take what the watch has sent: each whole line that is an event goes in
    /// the queue. The watch lost, it is opened again after a while.
    fn read(&mut self) {
        let Some(conn) = &mut self.watch else { return };
        let mut lines = Vec::new();
        let lost = loop {
            match conn.read_line() {
                Ok(Some(line)) => lines.push(line),
                // Cut off by the end of the stream: what is pending is not a
                // line to trust.
                Ok(None) => break Some("the daemon closed the connection".to_string()),
                Err(Errno::AGAIN) => break None,
                Err(e) => break Some(format!("lost the daemon: {}", Why(e))),
            }
        };
        let mut lost = lost;
        for text in lines {
            if let Err(why) = self.take(text.trim_end()) {
                lost = Some(why);
                break;
            }
        }
        if let Some(why) = lost {
            note(&format!("{why}; watching again once the daemon is back"));
            self.watch = None;
            self.retry = Some((now() + RECONNECT_FIRST, RECONNECT_FIRST));
        }
    }

    /// Queue `text`, a line of the watch, if it is an event; one that does
    /// not fit, as the script is that far behind, is dropped, and said so.
    /// The daemon ending the watch is an error.
    fn take(&mut self, text: &str) -> Result<(), String> {
        let event: Value = match serde_json::from_str(text) {
            Ok(event) => event,
            Err(e) => {
                note(&format!("skipped an unreadable line from the daemon ({e}): {text}"));
                return Ok(());
            }
        };
        if let Some(Failure::Server(why)) = server_error(&event) {
            return Err(format!("the daemon ended the watch: {why}"));
        }
        if event["event"].as_str().is_none() {
            note(&format!("skipped a line from the daemon that is not an event: {text}"));
        } else if self.queue.len() >= QUEUE {
            note(&format!("dropped an event: the script is {QUEUE} events behind"));
        } else {
            self.queue.push_back(text.to_string());
        }
        Ok(())
    }

    /// Run the script for `event`: its JSON line on stdin, written as the
    /// script takes it, and what [`event_env`] takes from it in the
    /// environment.
    fn start(&mut self, event: String) {
        let cannot = |e| note(&format!("cannot run {}: {}", self.script, Why(e)));
        let (stdin_rx, stdin_tx) = match rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC) {
            Ok(pipe) => pipe,
            Err(e) => return cannot(e),
        };
        let pid = match spawn(&self.script, &self.args, &event_env(&event), &stdin_rx) {
            Ok(pid) => pid,
            Err(e) => return cannot(e),
        };
        drop(stdin_rx);
        // A script that does not read its input must not hold the subscriber up.
        let stdin = set_nonblocking(&stdin_tx).is_ok().then(|| (stdin_tx, format!("{event}\n").into_bytes()));
        // Where there is no pidfd, whether it has exited is looked at every so often.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let pidfd = rustix::process::pidfd_open(pid, PidfdFlags::empty()).ok();
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let pidfd = None;
        let mut running = Running { pid, pidfd, stdin, event };
        running.feed();
        self.running = Some(running);
    }

    /// Stop the script, if one is running, and wait for it.
    fn stop(&mut self) {
        if let Some(running) = self.running.take() {
            let _ = rustix::process::kill_process(running.pid, Signal::TERM);
            let _ = rustix::io::retry_on_intr(|| rustix::process::waitpid(Some(running.pid), WaitOptions::empty()));
        }
    }
}

impl Running {
    /// Write what the script takes of the event, closing its stdin once it
    /// has all of it, or will take no more.
    fn feed(&mut self) {
        let Some((stdin, rest)) = &mut self.stdin else { return };
        loop {
            match rustix::io::write(&stdin, rest) {
                Ok(n) if n == rest.len() => break self.stdin = None,
                Ok(n) => drop(rest.drain(..n)),
                Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => {}
                Err(_) => break self.stdin = None,
            }
        }
    }
}

/// The environment a script gets for `event`, for scripts that would rather
/// not read JSON: what happened, where, and the device's name and first
/// address. Empty for what the event does not have.
fn event_env(event: &str) -> Vec<(&'static str, String)> {
    let event: Value = serde_json::from_str(event).unwrap_or(Value::Null);
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let device = &event["device"];
    vec![
        ("MDNS_EVENT", text(&event["event"])),
        ("MDNS_SEGMENT", text(&event["segment"])),
        ("MDNS_TTL", event["ttl"].as_u64().map(|t| t.to_string()).unwrap_or_default()),
        ("MDNS_INTERFACE", text(&device["interface"])),
        ("MDNS_HOSTNAME", text(&device["hostname"])),
        ("MDNS_ADDRESS", text(&device["addresses"][0])),
    ]
}

/// Say something in a subscriber's log (its stderr), with the time.
fn note(message: &str) {
    eprintln!("{} mdnsctl[{}]: {message}", utc_now(), rustix::process::getpid().as_raw_pid());
}

/// The time now, in UTC, as `2026-10-30T15:52:01Z`.
fn utc_now() -> String {
    let secs = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec as u64;
    let (days, rest) = ((secs / 86_400) as i64, secs % 86_400);
    // From days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest / 60 % 60, rest % 60)
}

/// Run a command and return the text to print.
fn execute(opts: &Options) -> Result<String, Failure> {
    let (line, timeout) = match &opts.command {
        Command::Segments => ("segments".to_string(), TIMEOUT),
        Command::Devices(target) => (target.request("devices"), TIMEOUT),
        Command::Probe(None) => ("probe".to_string(), PROBE_TIMEOUT),
        Command::Probe(Some(name)) => (format!("probe {name}"), PROBE_TIMEOUT),
        Command::Watchers => ("watchers".to_string(), TIMEOUT),
        Command::Timers => ("timers".to_string(), TIMEOUT),
        Command::Watch(_) => unreachable!("watch streams: see watch()"),
        Command::Subscribe(_) => unreachable!("subscribe streams: see subscribe()"),
    };
    let raw = request(&opts.socket, &line, timeout)?;
    let reply: Value =
        serde_json::from_str(&raw).map_err(|e| Failure::Server(format!("unreadable reply: {e}")))?;

    if reply["ok"] != Value::Bool(true) {
        return Err(server_error(&reply).unwrap_or_else(|| Failure::Server("request failed".into())));
    }
    if opts.json {
        return Ok(format!("{raw}\n"));
    }
    if opts.segmented {
        let devices = reply["devices"].as_array().ok_or_else(bad_reply)?;
        return Ok(devices.iter().map(|d| format!("{d}\n")).collect());
    }
    match opts.command {
        Command::Segments => render_segments(&reply),
        Command::Devices(_) if opts.verbose => render_devices(&reply),
        Command::Devices(_) => render_devices_brief(&reply),
        Command::Probe(_) => render_probe(&reply),
        Command::Watchers => render_watchers(&reply, user_name, command_line),
        Command::Timers => render_timers(&reply),
        Command::Watch(_) => unreachable!("watch streams: see watch()"),
        Command::Subscribe(_) => unreachable!("subscribe streams: see subscribe()"),
    }
}

fn bad_reply() -> Failure {
    Failure::Server("unexpected reply shape".into())
}

fn strings(v: &Value) -> Vec<&str> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

fn render_segments(reply: &Value) -> Result<String, Failure> {
    let list = reply["segments"].as_array().ok_or_else(bad_reply)?;
    let mut rows = vec![vec!["NAME".to_string(), "INTERFACES".into(), "FAMILIES".into()]];
    for seg in list {
        // An untrusted interface is told nothing of the others.
        let untrusted = strings(&seg["untrusted"]);
        let interfaces: Vec<String> = strings(&seg["interfaces"])
            .into_iter()
            .map(|i| if untrusted.contains(&i) { format!("{i} (untrusted)") } else { i.to_string() })
            .collect();
        rows.push(vec![
            seg["name"].as_str().ok_or_else(bad_reply)?.to_string(),
            interfaces.join(", "),
            strings(&seg["families"]).join(", "),
        ]);
    }
    Ok(table(&rows))
}

fn render_probe(reply: &Value) -> Result<String, Failure> {
    let list = reply["probed"].as_array().ok_or_else(bad_reply)?;
    let mut rows = vec![vec!["INTERFACE".to_string(), "RESULT".into()]];
    for link in list {
        let result = match link["error"].as_str() {
            Some(error) => format!("error: {error}"),
            None => format!("{} queries sent", link["queries"]),
        };
        rows.push(vec![link["interface"].as_str().ok_or_else(bad_reply)?.to_string(), result]);
    }
    let mut out = table(&rows);
    out.push_str("\nList what answered with: mdnsctl devices <name>\n");
    Ok(out)
}

/// A duration given in milliseconds, in the largest units that read well.
fn span(ms: u64) -> String {
    match ms {
        0..1000 => format!("{ms}ms"),
        // Tenths of a second, rounded half up, without floating point: that pulls in
        // some kilobytes of code to format the one number.
        1000..60_000 => {
            let tenths = (ms + 50) / 100;
            format!("{}.{}s", tenths / 10, tenths % 10)
        }
        60_000..3_600_000 => format!("{}m {:02}s", ms / 60_000, ms / 1000 % 60),
        _ => format!("{}h {:02}m", ms / 3_600_000, ms / 60_000 % 60),
    }
}

fn render_timers(reply: &Value) -> Result<String, Failure> {
    let list = reply["timers"].as_array().ok_or_else(bad_reply)?;
    let mut rows = vec![vec!["NAME", "STATE", "DUE", "RUNS", "LAST RUN", "TOOK"].into_iter().map(String::from).collect::<Vec<_>>()];
    for timer in list {
        let (state, due) = match (timer["running"].as_bool(), timer["due_in_ms"].as_u64()) {
            (Some(true), _) => ("running", "-".to_string()),
            (Some(false), Some(0)) => ("waiting", "now".to_string()),
            (Some(false), Some(ms)) => ("waiting", format!("in {}", span(ms))),
            (Some(false), None) => ("idle", "never".to_string()),
            _ => return Err(bad_reply()),
        };
        let last = timer["last_run_ago_ms"].as_u64().map_or("-".to_string(), |ms| format!("{} ago", span(ms)));
        let took = timer["last_took_us"].as_u64().map_or("-".to_string(), |us| match us {
            0..1000 => format!("{us}us"),
            _ => span(us / 1000),
        });
        rows.push(vec![
            timer["name"].as_str().ok_or_else(bad_reply)?.to_string(),
            state.to_string(),
            due,
            timer["runs"].as_u64().ok_or_else(bad_reply)?.to_string(),
            last,
            took,
        ]);
        // What the timer is waiting for, which is what it is set to the first of.
        for item in timer["pending"].as_array().into_iter().flatten() {
            let due = match item["due_in_ms"].as_u64().ok_or_else(bad_reply)? {
                0 => "now".to_string(),
                ms => format!("in {}", span(ms)),
            };
            let what = item["what"].as_str().ok_or_else(bad_reply)?;
            let who = item["who"].as_str().ok_or_else(bad_reply)?;
            let mut row = vec![format!("  {what:<11} {who}"), String::new(), due];
            row.resize(6, String::new());
            rows.push(row);
        }
    }
    Ok(table(&rows))
}

/// One line per open watch, oldest first: what it watches, how often it asks
/// again, how long it has been open, and the process holding it, named with
/// `user` and `command`, which may not know (another user's process may be
/// hidden).
fn render_watchers(
    reply: &Value,
    user: impl Fn(u32) -> Option<String>,
    command: impl Fn(i32) -> Option<String>,
) -> Result<String, Failure> {
    let list = reply["watchers"].as_array().ok_or_else(bad_reply)?;
    if list.is_empty() {
        return Ok("no watchers\n".into());
    }
    let mut rows = vec![
        ["ID", "SEGMENT", "QUERY", "EVERY", "AGE", "PID", "USER", "COMMAND"].map(String::from).to_vec(),
    ];
    for w in list {
        let query: Vec<&str> = w["query"]
            .as_array()
            .ok_or_else(bad_reply)?
            .iter()
            .map(|k| k.as_str().map(|k| k.strip_suffix(".local").unwrap_or(k)).ok_or_else(bad_reply))
            .collect::<Result<_, _>>()?;
        let query = if query.is_empty() { "-".to_string() } else { query.join(", ") };
        let every = w["interval_s"].as_u64().map_or("-".to_string(), |s| span(s * 1000));
        let pid = w["pid"].as_i64().and_then(|p| i32::try_from(p).ok());
        let uid = w["uid"].as_u64().and_then(|u| u32::try_from(u).ok());
        rows.push(vec![
            w["id"].as_u64().ok_or_else(bad_reply)?.to_string(),
            w["segment"].as_str().ok_or_else(bad_reply)?.to_string(),
            query,
            every,
            span(w["age_ms"].as_u64().ok_or_else(bad_reply)?),
            pid.map_or("-".to_string(), |p| p.to_string()),
            uid.map_or("-".to_string(), |u| user(u).unwrap_or_else(|| u.to_string())),
            pid.and_then(&command).unwrap_or_else(|| "-".to_string()),
        ]);
    }
    Ok(table(&rows))
}

/// The name of the user with `uid`, from `/etc/passwd`.
fn user_name(uid: u32) -> Option<String> {
    let passwd = String::from_utf8(read_file("/etc/passwd").ok()?).ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        (fields.nth(1)?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

/// The command line of the process `pid`, if this one may see it: `/proc`
/// has it on Linux.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn command_line(pid: i32) -> Option<String> {
    words_of(&read_file(&format!("/proc/{pid}/cmdline")).ok()?)
}

/// The command line of the process `pid`, if this one may see it: FreeBSD and
/// DragonFly give it as a `sysctl`, where `/proc` is not mounted.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn command_line(pid: i32) -> Option<String> {
    // -1 is the process asking, here: no process is that.
    if pid <= 0 {
        return None;
    }
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ARGS, pid];
    let mut buf = vec![0u8; 16 << 10];
    let mut len = buf.len();
    // SAFETY: `mib` is four long, and `buf` is as long as `len` says; nothing is set.
    let ok = unsafe { libc::sysctl(mib.as_mut_ptr(), 4, buf.as_mut_ptr().cast(), &mut len, core::ptr::null_mut(), 0) } == 0;
    words_of(buf.get(..len).filter(|_| ok)?)
}

/// The other systems do not say: the column is left empty.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "dragonfly")))]
fn command_line(_pid: i32) -> Option<String> {
    None
}

/// A command line as the system has it, its words each ended by a NUL.
fn words_of(raw: &[u8]) -> Option<String> {
    let words: Vec<String> =
        raw.split(|&b| b == 0).filter(|w| !w.is_empty()).map(|w| String::from_utf8_lossy(w).into_owned()).collect();
    (!words.is_empty()).then(|| words.join(" "))
}

/// One line per named device: its DNS name, its pretty name (the service
/// instance name, such as "OZAL Speakers") and, last, all of its addresses,
/// IPv4 before IPv6. A host heard on several interfaces of the segment is one
/// line. Devices that have not announced a hostname have no DNS name to show,
/// so they are only counted.
fn render_devices_brief(reply: &Value) -> Result<String, Failure> {
    struct Named {
        host: String,
        pretty: Vec<String>,
        /// (link-local, IPv6, address): sorting on this puts routable IPv4
        /// first, then routable IPv6, then link-local ones.
        addrs: Vec<(bool, bool, String)>,
    }

    let name = reply["name"].as_str().ok_or_else(bad_reply)?;
    let devices = reply["devices"].as_array().ok_or_else(bad_reply)?;

    let mut named: Vec<Named> = Vec::new();
    let mut unnamed = 0;
    for device in devices {
        let Some(host) = device["hostname"].as_str() else {
            unnamed += 1;
            continue;
        };
        let entry = match named.iter().position(|n| n.host.eq_ignore_ascii_case(host)) {
            Some(i) => &mut named[i],
            None => {
                named.push(Named { host: host.to_string(), pretty: vec![], addrs: vec![] });
                named.last_mut().unwrap()
            }
        };
        for addr in strings(&device["addresses"]) {
            let item = (is_link_local(addr), addr.contains(':'), shown_addr(device, addr));
            if !entry.addrs.contains(&item) {
                entry.addrs.push(item);
            }
        }
        for p in pretty_names(device) {
            if !entry.pretty.contains(&p) {
                entry.pretty.push(p);
            }
        }
    }

    let rows: Vec<[String; 3]> = named
        .iter_mut()
        .map(|n| {
            let pretty = if n.pretty.is_empty() { "-".to_string() } else { n.pretty.join(", ") };
            let addrs: Vec<&str> = n.addrs.iter().map(|(_, _, a)| a.as_str()).collect();
            let addrs = if addrs.is_empty() { "-".to_string() } else { addrs.join(", ") };
            [n.host.clone(), pretty, addrs]
        })
        .collect();

    let width = |col: usize| rows.iter().map(|r| r[col].len()).max().unwrap_or(0);
    let widths = [width(0), width(1)];
    let mut out: String = rows.iter().map(|row| brief_line(row, widths)).collect();
    out.push_str(&devices_summary(name, rows.len(), unnamed));
    Ok(out)
}

/// A device's line in the brief listing: its DNS name, pretty name and
/// addresses, the first two padded to `widths` (none when the rest are not
/// known yet, as when they are printed as they come).
fn brief_line([host, pretty, addrs]: &[String; 3], [w0, w1]: [usize; 2]) -> String {
    format!("  {host:<w0$}  {pretty:<w1$}  {addrs}\n")
}

/// A device as the brief listing has it, or `None` for one without a name:
/// its DNS name, its pretty names and its addresses, routable IPv4 first,
/// then routable IPv6, then link-local.
fn brief_row(device: &Value) -> Option<[String; 3]> {
    let host = device["hostname"].as_str()?;
    let pretty = pretty_names(device);
    let pretty = if pretty.is_empty() { "-".to_string() } else { pretty.join(", ") };
    let addrs = strings(&device["addresses"]);
    let addrs: Vec<String> = addrs.into_iter().map(|a| shown_addr(device, a)).collect();
    let addrs = if addrs.is_empty() { "-".to_string() } else { addrs.join(", ") };
    Some([host.to_string(), pretty, addrs])
}

/// The line a listing of `name` ends with: how many devices it showed, and
/// how many without a name it did not.
fn devices_summary(name: &str, shown: usize, unnamed: usize) -> String {
    let mut out = match (shown, unnamed) {
        (0, 0) => format!("{name}: no devices\n"),
        (0, _) => format!("{name}: no named devices\n"),
        (1, _) => format!("{name}: 1 device\n"),
        (n, _) => format!("{name}: {n} devices\n"),
    };
    if unnamed > 0 {
        let s = if unnamed == 1 { "" } else { "s" };
        out.push_str(&format!("({unnamed} device{s} without a name not shown; use -v to list everything)\n"));
    }
    out
}

/// The human names of a device's services, from its instance names: the
/// first label, without the AirPlay `<MAC>@` prefix, each name once.
fn pretty_names(device: &Value) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for svc in device["services"].as_array().into_iter().flatten() {
        let kind = svc["type"].as_str().unwrap_or("");
        let instance = svc["instance"].as_str().unwrap_or("");
        let label = instance.strip_suffix(&format!(".{kind}")).unwrap_or(instance);
        let label = unescape_label(label);
        let name = match label.split_once('@') {
            Some((mac, rest)) if mac.len() == 12 && mac.chars().all(|c| c.is_ascii_hexdigit()) => rest,
            _ => &label,
        };
        if !name.is_empty() && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// Undo the daemon's escaping of `.` and `\` inside a name label.
fn unescape_label(label: &str) -> String {
    let mut out = String::new();
    let mut chars = label.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            out.extend(chars.next());
        } else {
            out.push(c);
        }
    }
    out
}

/// A device's addresses, as the daemon lists them (routable ones first); `-`
/// if it has none.
fn device_addrs(device: &Value) -> String {
    let addrs: Vec<String> = strings(&device["addresses"]).into_iter().map(|a| shown_addr(device, a)).collect();
    if addrs.is_empty() { "-".to_string() } else { addrs.join(", ") }
}

/// `addr` of `device` as a listing shows it: in parentheses if it was learned
/// from the neighbour table rather than announced.
fn shown_addr(device: &Value, addr: &str) -> String {
    if strings(&device["neighbour_addresses"]).contains(&addr) { format!("({addr})") } else { addr.to_string() }
}

/// Whether `addr` is link-local, `169.254/16` or `fe80::/10`: it only means
/// something on the device's own link.
fn is_link_local(addr: &str) -> bool {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_link_local(),
        Ok(IpAddr::V6(a)) => a.segments()[0] & 0xffc0 == 0xfe80,
        Err(_) => false,
    }
}

fn render_devices(reply: &Value) -> Result<String, Failure> {
    let name = reply["name"].as_str().ok_or_else(bad_reply)?;
    let devices = reply["devices"].as_array().ok_or_else(bad_reply)?;

    let rows = devices.iter().map(device_row).collect::<Result<Vec<_>, Failure>>()?;
    let width = |col: usize| rows.iter().map(|r| r[col].len()).max().unwrap_or(0);
    let widths = [width(0), width(1)];
    let mut out = String::new();
    for (device, row) in devices.iter().zip(&rows) {
        out.push_str(&verbose_lines(device, row, widths));
    }
    out.push_str(&devices_summary(name, devices.len(), 0));
    Ok(out)
}

/// A device as `devices -v` lists it: interface, addresses and hostname
/// (`row`, the first two padded to `widths`), then its services.
fn verbose_lines(device: &Value, [interface, addrs, host]: &[String; 3], [w0, w1]: [usize; 2]) -> String {
    format!("  {interface:<w0$}  {addrs:<w1$}  {host}\n{}", service_lines(device))
}

/// The columns of a device in the verbose listing: interface, addresses,
/// hostname.
fn device_row(device: &Value) -> Result<[String; 3], Failure> {
    // The hostname is the last column, so the TTL of its address records can
    // follow it.
    let mut hostname = device["hostname"].as_str().unwrap_or("-").to_string();
    if let Some(ttl) = device["address_ttl"].as_u64() {
        hostname.push_str(&format!("  addr-ttl={ttl}"));
    }
    Ok([
        device["interface"].as_str().ok_or_else(bad_reply)?.to_string(),
        device_addrs(device),
        hostname,
    ])
}

/// One indented line for each service of a device in the verbose listing, with
/// the TTL its records were announced with.
fn service_lines(device: &Value) -> String {
    let mut out = String::new();
    for svc in device["services"].as_array().into_iter().flatten() {
        let kind = svc["type"].as_str().unwrap_or("");
        let instance = svc["instance"].as_str().unwrap_or("");
        let label = instance.strip_suffix(&format!(".{kind}")).unwrap_or(instance);
        out.push_str(&format!("      {label}  {kind}  :{}", svc["port"]));
        if let Some(target) = svc["target"].as_str() {
            out.push_str(&format!(" -> {target}"));
        }
        if let Some(ttl) = svc["ttl"].as_u64() {
            out.push_str(&format!("  ttl={ttl}"));
        }
        // `_universal._sub._ipp._tcp.local` is `_universal`.
        let subtypes: Vec<&str> =
            strings(&svc["subtypes"]).into_iter().map(|sub| sub.split_once("._sub.").map_or(sub, |(label, _)| label)).collect();
        if !subtypes.is_empty() {
            out.push_str(&format!("  sub={}", subtypes.join(",")));
        }
        let txt = strings(&svc["txt"]);
        if !txt.is_empty() {
            out.push_str(&format!("  [{}]", txt.join(", ")));
        }
        out.push('\n');
    }
    out
}

/// One change of a `watch`, as a line (or, verbose, a device and its
/// services), starting with what happened and how long the daemon keeps the
/// device; the rest is as `devices` shows it. `seen` is what has been shown:
/// the first time a device is named is `added` whatever the daemon called it,
/// then `updated`, and `removed` (ttl 0) when it goes. Devices that have not
/// announced a name are skipped unless verbose.
fn render_event(
    event: &Value,
    verbose: bool,
    seen: &mut BTreeSet<(String, String)>,
) -> Result<Option<String>, Failure> {
    let device = &event["device"];
    let ttl = event["ttl"].as_u64().ok_or_else(bad_reply)?;
    let kind = event["event"].as_str().ok_or_else(bad_reply)?;
    let row = device_row(device)?;

    let key = device["hostname"].as_str().map(|h| (h.to_ascii_lowercase(), row[0].clone()));
    let label = match (kind, &key) {
        ("removed", Some(key)) => {
            seen.remove(key);
            "removed"
        }
        ("removed", None) => "removed",
        ("present", Some(key)) => {
            seen.insert(key.clone());
            "present"
        }
        ("present", None) => "present",
        ("added" | "updated", Some(key)) if seen.insert(key.clone()) => "added",
        ("added" | "updated", Some(_)) => "updated",
        // Nothing to track it by: say what the daemon said.
        ("added", None) => "added",
        ("updated", None) => "updated",
        _ => return Err(bad_reply()),
    };
    let ttl = format!("{:<9}", format!("ttl={ttl}"));

    if verbose {
        let mut out = format!("{label:<7}  {ttl}  {}  {}  {}\n", row[0], row[1], row[2]);
        out.push_str(&service_lines(device));
        return Ok(Some(out));
    }
    let Some(host) = device["hostname"].as_str() else {
        return Ok(None);
    };
    let pretty = pretty_names(device);
    let pretty = if pretty.is_empty() { "-".to_string() } else { pretty.join(", ") };
    Ok(Some(format!("{label:<7}  {ttl}  {host}  {pretty}  {}\n", row[1])))
}

/// Left-aligned columns; the last column is not padded.
fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| rows.iter().filter_map(|r| r.get(c)).map(String::len).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in rows {
        let last = row.len() - 1;
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(c, cell)| if c == last { cell.clone() } else { format!("{cell:<w$}", w = widths[c]) })
            .collect();
        // Rows may leave their last cells empty.
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }
    out
}

/// The name the runtime says panics and bad command lines under.
#[cfg_attr(test, allow(dead_code))]
const PROGRAM: &str = "mdnsctl";

/// Run the command line `args`, after the program's name: the exit status.
/// Tests run the parts, not this.
#[cfg_attr(test, allow(dead_code))]
fn run(args: Vec<String>) -> c_int {
    let opts = match parse_args(args) {
        Ok(opts) => opts,
        // Help and version to stdout with 0, usage errors to stderr with 2.
        Err(early) => return early.exit(),
    };
    let result = match &opts.command {
        Command::Watch(target) => watch(&opts, target, &mut Stdout),
        Command::Devices(target) if !target.query.is_empty() => devices_query(&opts, target, &mut Stdout),
        Command::Subscribe(sub) => subscribe(&opts, sub),
        _ => execute(&opts).map(|text| print!("{text}")),
    };
    match result {
        Ok(()) => 0,
        Err(Failure::Server(message)) => {
            eprintln!("mdnsctl: {message}");
            1
        }
        Err(Failure::Connect(message) | Failure::Usage(message)) => {
            eprintln!("mdnsctl: {message}");
            2
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/ipc_client.rs"]
mod tests;
