//! `mdnsctl`: command line client for the daemon's control socket (see
//! `ipc.rs` for the protocol). Every IPC command has a subcommand here.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

#[path = "timespan.rs"]
mod timespan;

/// Keep in sync with `config::DEFAULT_SOCKET` in the daemon.
const DEFAULT_SOCKET: &str = "/run/mdnsd/mdnsd.sock";

const TIMEOUT: Duration = Duration::from_secs(5);

/// A probe takes the daemon about four seconds to run before it replies, and
/// so does `devices --query`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// Keep in sync with `ipc::MIN_QUERY_INTERVAL` in the daemon.
const MIN_INTERVAL: Duration = Duration::from_secs(10);

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

/// Set by SIGTERM or SIGINT: a subscriber stops its script and exits.
static STOP: AtomicBool = AtomicBool::new(false);

/// (command, arguments, description): the whole IPC surface.
const COMMANDS: &[(&str, &str, &str)] = &[
    ("segments", "", "list the configured segments"),
    ("devices", "[--query TYPE]... <name>", "list the devices discovered in a segment"),
    ("probe", "[<name>]", "actively query for devices (all segments, or one)"),
    ("watch", "[--query TYPE]... [--interval SPAN] <name>", "print the devices of a segment as they appear and go"),
    (
        "subscribe",
        "[--query TYPE]... [--interval SPAN] [--foreground] [--log FILE] <name> -- SCRIPT [ARG]...",
        "run SCRIPT for each change in a segment, in the background",
    ),
    ("watchers", "", "list the watches open on the daemon, and who holds them"),
    ("timers", "", "list the timers the daemon has scheduled"),
];

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
/// show (`--query`), and how often a watch asks again (`--interval`).
#[derive(Debug, Default, PartialEq, Eq)]
struct Target {
    segment: String,
    query: Vec<String>,
    interval: Option<Duration>,
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
    log: Option<PathBuf>,
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
    socket: PathBuf,
    json: bool,
    verbose: bool,
    command: Command,
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Run(Options),
    Help,
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

fn usage() -> String {
    let mut out = String::from("usage: mdnsctl [-s PATH] [-v] [--json] <command>\n\ncommands:\n");
    for (name, args, about) in COMMANDS {
        let synopsis = format!("{name} {args}");
        let synopsis = synopsis.trim_end();
        // One too long for the column has its description on a line of its own.
        if synopsis.len() < 18 {
            out.push_str(&format!("  {synopsis:<18}{about}\n"));
        } else {
            out.push_str(&format!("  {synopsis}\n  {:<18}{about}\n", ""));
        }
    }
    out.push_str(&format!(
        "\noptions:\n  -s, --socket PATH  control socket (default {DEFAULT_SOCKET})\n  -v, --verbose      list devices with all details (addresses, services)\n      --json         print the daemon's reply unchanged\n  -h, --help         show this help\n"
    ));
    out
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Parsed, Failure> {
    let mut args = args.into_iter();
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut json = false;
    let mut verbose = false;
    let mut words: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        // Once the command starts, everything left belongs to it.
        if !words.is_empty() {
            words.push(arg);
            continue;
        }
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--json" => json = true,
            "-v" | "--verbose" => verbose = true,
            "-s" | "--socket" => {
                let path = args.next().ok_or_else(|| Failure::Usage(format!("{arg} needs a path")))?;
                socket = PathBuf::from(path);
            }
            _ if arg.starts_with("--socket=") => socket = PathBuf::from(&arg["--socket=".len()..]),
            _ if arg.starts_with('-') && arg.len() > 1 => {
                return Err(Failure::Usage(format!("unknown option {arg}")));
            }
            _ => words.push(arg),
        }
    }

    let Some((name, rest)) = words.split_first() else {
        return Err(Failure::Usage("missing command".into()));
    };
    let command = match name.as_str() {
        "segments" if rest.is_empty() => Command::Segments,
        "segments" => return Err(Failure::Usage("segments takes no arguments".into())),
        "devices" => Command::Devices(target("devices", rest, false)?),
        "probe" => {
            let segment = rest.join(" ");
            if segment.contains(['\n', '\r']) {
                return Err(Failure::Usage("segment name contains a line break".into()));
            }
            Command::Probe((!segment.trim().is_empty()).then_some(segment))
        }
        "watch" => Command::Watch(target("watch", rest, true)?),
        "subscribe" => Command::Subscribe(subscription(rest)?),
        "watchers" if rest.is_empty() => Command::Watchers,
        "watchers" => return Err(Failure::Usage("watchers takes no arguments".into())),
        "timers" if rest.is_empty() => Command::Timers,
        "timers" => return Err(Failure::Usage("timers takes no arguments".into())),
        other => return Err(Failure::Usage(format!("unknown command {other:?}"))),
    };
    Ok(Parsed::Run(Options { socket, json, verbose, command }))
}

fn connect_err(socket: &Path, e: io::Error) -> Failure {
    Failure::Connect(format!(
        "cannot talk to {}: {e} (is the daemon running, and can you access the socket?)",
        socket.display()
    ))
}

/// Connect and send one request line, waiting up to `timeout` for replies.
fn send(socket: &Path, line: &str, timeout: Duration) -> Result<UnixStream, Failure> {
    let err = |e| connect_err(socket, e);
    let mut stream = UnixStream::connect(socket).map_err(err)?;
    stream.set_read_timeout(Some(timeout)).map_err(err)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(err)?;
    writeln!(stream, "{line}").map_err(err)?;
    Ok(stream)
}

/// Send one request line and return the one-line reply.
fn request(socket: &Path, line: &str, timeout: Duration) -> Result<String, Failure> {
    let stream = send(socket, line, timeout)?;
    let mut reply = String::new();
    let n = BufReader::new(stream).read_line(&mut reply).map_err(|e| connect_err(socket, e))?;
    if n == 0 {
        return Err(Failure::Connect("the daemon closed the connection without replying".into()));
    }
    Ok(reply.trim_end().to_string())
}

/// The error a reply carries, if it is one.
fn server_error(reply: &Value) -> Option<Failure> {
    (reply["ok"] == Value::Bool(false))
        .then(|| Failure::Server(reply["error"].as_str().unwrap_or("request failed").to_string()))
}

/// Follow a segment: print each change the daemon reports until it stops (an
/// error) or `out` is closed (success: `mdnsctl watch | head` is fine).
/// The target of `command` from the words after it: `--query` and (for a
/// watch) `--interval` options, as `--query TYPE` or `--query=TYPE`, and the
/// segment name of the rest. Names may contain spaces, so `devices IoT to
/// br0` needs no quoting.
fn target(command: &str, rest: &[String], watching: bool) -> Result<Target, Failure> {
    let mut target = Target::default();
    let mut words: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        let word = rest[i].as_str();
        i += 1;
        let (option, inline) = match word.split_once('=') {
            Some((option, value)) => (option, Some(value)),
            None => (word, None),
        };
        if option != "--query" && !(watching && option == "--interval") {
            words.push(word);
            continue;
        }
        let value = match inline {
            Some(value) => value,
            None => {
                i += 1;
                rest.get(i - 1).ok_or_else(|| Failure::Usage(format!("{option} needs a value")))?
            }
        };
        if value.is_empty() || value.contains(char::is_whitespace) {
            return Err(Failure::Usage(format!("invalid {option} {value:?}")));
        }
        if option == "--query" {
            target.query.push(value.to_string());
            continue;
        }
        let every = timespan::parse(value).map_err(|e| Failure::Usage(format!("invalid --interval {value:?}: {e}")))?;
        if every < MIN_INTERVAL {
            return Err(Failure::Usage(format!("--interval must be at least {}s", MIN_INTERVAL.as_secs())));
        }
        // The daemon takes whole seconds.
        target.interval = Some(Duration::from_secs(every.as_secs() + u64::from(every.subsec_nanos() > 0)));
    }
    if target.interval.is_some() && target.query.is_empty() {
        return Err(Failure::Usage("--interval needs a --query to ask again".into()));
    }
    target.segment = words.join(" ");
    if target.segment.trim().is_empty() {
        return Err(Failure::Usage(format!("{command} needs a segment name")));
    }
    // The protocol is one request per line.
    if target.segment.contains(['\n', '\r']) {
        return Err(Failure::Usage("segment name contains a line break".into()));
    }
    Ok(target)
}

/// Send the watch request `line` and wait for the daemon to accept it: the
/// stream its events will come on, with no time limit from then on.
fn open_watch(socket: &Path, line: &str) -> Result<BufReader<UnixStream>, Failure> {
    let mut reader = BufReader::new(send(socket, line, TIMEOUT)?);
    let mut ack = String::new();
    if reader.read_line(&mut ack).map_err(|e| connect_err(socket, e))? == 0 {
        return Err(Failure::Connect("the daemon closed the connection".into()));
    }
    let reply: Value =
        serde_json::from_str(ack.trim_end()).map_err(|e| Failure::Server(format!("unreadable reply: {e}")))?;
    if let Some(failure) = server_error(&reply) {
        return Err(failure);
    }
    // Now it waits for changes, however long that takes.
    reader.get_ref().set_read_timeout(None).map_err(|e| connect_err(socket, e))?;
    Ok(reader)
}

fn watch(opts: &Options, target: &Target, out: &mut impl Write) -> Result<(), Failure> {
    let socket = &opts.socket;
    let mut reader = open_watch(socket, &target.request("watch"))?;
    let mut line = String::new();
    let mut seen = HashSet::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| connect_err(socket, e))?;
        if n == 0 {
            return Err(Failure::Connect("the daemon closed the connection".into()));
        }
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
        if let Some(shown) = shown {
            if out.write_all(shown.as_bytes()).and_then(|()| out.flush()).is_err() {
                return Ok(());
            }
        }
    }
}

/// The subscription the words after `subscribe` describe: options and the
/// segment name as for `watch`, then `--` and the script, with its
/// arguments.
fn subscription(rest: &[String]) -> Result<Subscription, Failure> {
    let split = rest
        .iter()
        .position(|w| w == "--")
        .ok_or_else(|| Failure::Usage("subscribe needs `-- SCRIPT` to run for each change".into()))?;
    let (before, script) = (&rest[..split], &rest[split + 1..]);
    if script.is_empty() {
        return Err(Failure::Usage("subscribe needs a script after --".into()));
    }
    let mut foreground = false;
    let mut log = None;
    let mut words = Vec::new();
    let mut i = 0;
    while i < before.len() {
        let word = before[i].as_str();
        i += 1;
        let file = match word {
            "--foreground" => {
                foreground = true;
                continue;
            }
            "--log" => {
                i += 1;
                before.get(i - 1).map(String::as_str)
            }
            _ => match word.strip_prefix("--log=") {
                Some(file) => Some(file),
                None => {
                    words.push(before[i - 1].clone());
                    continue;
                }
            },
        };
        match file {
            Some(file) if !file.is_empty() => log = Some(PathBuf::from(file)),
            _ => return Err(Failure::Usage("--log needs a file".into())),
        }
    }
    Ok(Subscription { target: target("subscribe", &words, true)?, script: script.to_vec(), foreground, log })
}

/// Subscribe: open the watch, then (unless in the foreground) go into the
/// background, printing the PID, and run the script for each event until
/// told to stop. What can go wrong before the first event is reported here,
/// for the caller; what goes wrong later is logged.
fn subscribe(opts: &Options, sub: &Subscription) -> Result<(), Failure> {
    let script = executable(&sub.script[0]).map_err(Failure::Usage)?;
    let log = match &sub.log {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| Failure::Usage(format!("cannot write to {}: {e}", path.display())))?,
        ),
        None => None,
    };
    let line = sub.target.request("watch");
    // In the background, the watch is opened by the process that holds it,
    // so that `watchers` lists the subscriber's PID, not its parent's.
    let reader = if sub.foreground { open_watch(&opts.socket, &line)? } else { detach(&opts.socket, &line, log.as_ref())? };
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the handler only stores to an atomic, which is
        // async-signal-safe.
        unsafe { libc::signal(signal, on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    }
    note(&format!("watching {}, running {} for each change", sub.target.segment, script.display()));

    let (tx, rx) = mpsc::sync_channel(QUEUE);
    let socket = opts.socket.clone();
    thread::spawn(move || feed(&socket, &line, reader, &tx));
    run_scripts(&rx, &script, &sub.script[1..], &STOP);
    note("stopped");
    Ok(())
}

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// `name` as a script to run: a path, or a name looked up in `PATH`, of an
/// executable file. Made absolute, so that it is the same file whatever
/// happens to the working directory or `PATH` later, but not resolved
/// through symlinks: `sh` linked to `bash`, or a busybox applet, behaves by
/// the name it is run under.
fn executable(name: &str) -> Result<PathBuf, String> {
    let candidates: Vec<PathBuf> = if name.contains('/') {
        vec![PathBuf::from(name)]
    } else {
        std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).map(|dir| dir.join(name)).collect())
            .unwrap_or_default()
    };
    let runnable = |p: &PathBuf| p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
    let found = candidates.into_iter().find(runnable).ok_or_else(|| format!("{name}: not an executable file"))?;
    std::path::absolute(&found).map_err(|e| format!("{name}: {e}"))
}

/// Go into the background, and open the watch `line` there. The child, in a
/// session of its own, opens it and tells the parent how that went: the
/// parent then prints the child's PID and exits, or returns the error, for
/// the caller to hear of. The child carries on with the watch, its output
/// going to `log`, or nowhere.
fn detach(socket: &Path, line: &str, log: Option<&File>) -> Result<BufReader<UnixStream>, Failure> {
    let _ = io::stdout().flush();
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 returns.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Failure::Connect(format!("cannot go into the background: {}", io::Error::last_os_error())));
    }
    // SAFETY: both were just opened, and are owned by nothing else.
    let (mut report_rx, mut report_tx) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    // SAFETY: no other thread has been started, so the child is a full copy.
    match unsafe { libc::fork() } {
        -1 => Err(Failure::Connect(format!("cannot go into the background: {}", io::Error::last_os_error()))),
        0 => {
            drop(report_rx);
            // SAFETY: the child leaves the caller's session.
            unsafe { libc::setsid() };
            let opened = open_watch(socket, line);
            // How it went: `+`, or a letter for the kind of error and the
            // message.
            let report = match &opened {
                Ok(_) => "+".to_string(),
                Err(Failure::Server(m)) => format!("S{m}"),
                Err(Failure::Connect(m) | Failure::Usage(m)) => format!("C{m}"),
            };
            let _ = report_tx.write_all(report.as_bytes());
            drop(report_tx);
            let Ok(reader) = opened else { std::process::exit(1) };
            let null = File::options().read(true).write(true).open("/dev/null");
            let null = null.map_err(|e| Failure::Connect(format!("cannot open /dev/null: {e}")))?;
            let out = log.unwrap_or(&null);
            // SAFETY: plain descriptor calls on descriptors open in this
            // process; the duplicates replace stdin, stdout and stderr.
            unsafe {
                libc::dup2(null.as_raw_fd(), 0);
                libc::dup2(out.as_raw_fd(), 1);
                libc::dup2(out.as_raw_fd(), 2);
            }
            Ok(reader)
        }
        pid => {
            drop(report_tx);
            let mut report = String::new();
            let _ = report_rx.read_to_string(&mut report);
            // Nothing at all: the child died before it could say.
            match (report.chars().next(), report.get(1..).unwrap_or_default()) {
                (Some('+'), _) => {
                    println!("{pid}");
                    std::process::exit(0);
                }
                (None, _) => Err(Failure::Connect("the subscriber died before it was watching".into())),
                (Some('S'), message) => Err(Failure::Server(message.into())),
                (_, message) => Err(Failure::Connect(message.into())),
            }
        }
    }
}

/// Pass each event of the watch on `reader` to `events`, opening the watch
/// again whenever it is lost (the daemon restarted, say), until whatever
/// takes the events is gone.
fn feed(socket: &Path, line: &str, mut reader: BufReader<UnixStream>, events: &SyncSender<String>) {
    loop {
        match forward(&mut reader, events) {
            Ok(()) => return,
            Err(why) => note(&format!("{why}; watching again once the daemon is back")),
        }
        let mut wait = RECONNECT_FIRST;
        reader = loop {
            thread::sleep(wait);
            match open_watch(socket, line) {
                Ok(reader) => {
                    note("watching again");
                    break reader;
                }
                Err(Failure::Server(why)) => note(&format!("the daemon refuses the watch: {why}")),
                Err(_) => {}
            }
            wait = (wait * 2).min(RECONNECT_MOST);
        };
    }
}

/// Pass the events on `reader` to `events` until the watch is lost (`Err`,
/// saying how) or whatever takes them is gone (`Ok`). One that does not fit
/// because the script is that far behind is dropped, and said so.
fn forward(reader: &mut BufReader<UnixStream>, events: &SyncSender<String>) -> Result<(), String> {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return Err("the daemon closed the connection".into()),
            // Cut off by the end of the stream: not a line to trust.
            Ok(_) if !line.ends_with('\n') => return Err("the daemon closed the connection".into()),
            Ok(_) => {}
            Err(e) => return Err(format!("lost the daemon: {e}")),
        }
        let text = line.trim_end();
        let event: Value = match serde_json::from_str(text) {
            Ok(event) => event,
            Err(e) => {
                note(&format!("skipped an unreadable line from the daemon ({e}): {text}"));
                continue;
            }
        };
        if let Some(Failure::Server(why)) = server_error(&event) {
            return Err(format!("the daemon ended the watch: {why}"));
        }
        if event["event"].as_str().is_none() {
            note(&format!("skipped a line from the daemon that is not an event: {text}"));
            continue;
        }
        match events.try_send(text.to_string()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => note(&format!("dropped an event: the script is {QUEUE} events behind")),
            Err(TrySendError::Disconnected(_)) => return Ok(()),
        }
    }
}

/// Run `script` with `args` for each event that comes, one at a time, until
/// `stop` is set.
fn run_scripts(events: &Receiver<String>, script: &Path, args: &[String], stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        let event = match events.recv_timeout(STOP_CHECK) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        match run_script(script, args, &event, stop) {
            Ok(Some(status)) if status.success() => {}
            Ok(Some(status)) => note(&format!("{} {status}, for: {event}", script.display())),
            Ok(None) => return,
            Err(e) => note(&format!("cannot run {}: {e}", script.display())),
        }
    }
}

/// Run `script` with `args` for `event`: its JSON line on stdin, and what
/// [`event_env`] takes from it in the environment. Its exit status, or `None`
/// if `stop` was set while it ran, in which case it was sent SIGTERM.
fn run_script(script: &Path, args: &[String], event: &str, stop: &AtomicBool) -> io::Result<Option<ExitStatus>> {
    let mut child = std::process::Command::new(script)
        .args(args)
        .envs(event_env(event))
        .stdin(Stdio::piped())
        .spawn()?;
    // From a thread of its own: a script that does not read its input must
    // not hold the subscriber up.
    if let Some(mut stdin) = child.stdin.take() {
        let line = format!("{event}\n");
        thread::spawn(move || {
            let _ = stdin.write_all(line.as_bytes());
        });
    }
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if stop.load(Ordering::SeqCst) {
            // SAFETY: a plain signal to the child, which has not been reaped.
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            child.wait()?;
            return Ok(None);
        }
        thread::sleep(STOP_CHECK);
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
    eprintln!("{} mdnsctl[{}]: {message}", utc_now(), std::process::id());
}

/// The time now, in UTC, as `2026-10-30T15:52:01Z`.
fn utc_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
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
        Command::Devices(target) if target.query.is_empty() => (target.request("devices"), TIMEOUT),
        Command::Devices(target) => (target.request("devices"), PROBE_TIMEOUT),
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
        1000..60_000 => format!("{:.1}s", ms as f64 / 1000.0),
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
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        (fields.nth(1)?.parse::<u32>().ok()? == uid).then(|| name.to_string())
    })
}

/// The command line of the process `pid`, if this one may see it.
fn command_line(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
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
    if devices.is_empty() {
        return Ok(format!("{name}: no devices\n"));
    }

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
            let item = (is_link_local(addr), addr.contains(':'), addr.to_string());
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
    named.sort_by_key(|n| n.host.to_ascii_lowercase());

    let rows: Vec<[String; 3]> = named
        .iter_mut()
        .map(|n| {
            n.addrs.sort_by_key(|(link_local, v6, _)| (*link_local, *v6));
            let pretty = if n.pretty.is_empty() { "-".to_string() } else { n.pretty.join(", ") };
            let addrs: Vec<&str> = n.addrs.iter().map(|(_, _, a)| a.as_str()).collect();
            [n.host.clone(), pretty, addrs.join(", ")]
        })
        .collect();

    let mut out = match rows.len() {
        0 => format!("{name}: no named devices\n"),
        1 => format!("{name}: 1 device\n"),
        n => format!("{name}: {n} devices\n"),
    };
    let width = |col: usize| rows.iter().map(|r| r[col].len()).max().unwrap_or(0);
    let (w0, w1) = (width(0), width(1));
    for [host, pretty, addrs] in &rows {
        out.push_str(&format!("  {host:<w0$}  {pretty:<w1$}  {addrs}\n"));
    }
    if unnamed > 0 {
        let s = if unnamed == 1 { "" } else { "s" };
        out.push_str(&format!("\n({unnamed} device{s} without a name not shown; use -v to list everything)\n"));
    }
    Ok(out)
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
    let addrs = strings(&device["addresses"]);
    if addrs.is_empty() { "-".to_string() } else { addrs.join(", ") }
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
    if devices.is_empty() {
        return Ok(format!("{name}: no devices\n"));
    }

    let rows = devices.iter().map(device_row).collect::<Result<Vec<_>, Failure>>()?;
    let widths: Vec<usize> = (0..2).map(|c| rows.iter().map(|r| r[c].len()).max().unwrap_or(0)).collect();

    let plural = if devices.len() == 1 { "" } else { "s" };
    let mut out = format!("{name}: {} device{plural}\n", devices.len());
    for (device, row) in devices.iter().zip(&rows) {
        out.push_str(&format!("  {:<w0$}  {:<w1$}  {}\n", row[0], row[1], row[2], w0 = widths[0], w1 = widths[1]));
        out.push_str(&service_lines(device));
    }
    Ok(out)
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
    seen: &mut HashSet<(String, String)>,
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

fn main() -> ExitCode {
    let opts = match parse_args(std::env::args().skip(1)) {
        Ok(Parsed::Run(opts)) => opts,
        Ok(Parsed::Help) => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(Failure::Usage(message)) => {
            eprintln!("mdnsctl: {message}\n\n{}", usage());
            return ExitCode::from(2);
        }
        Err(_) => unreachable!("parse_args only reports usage errors"),
    };

    let result = match &opts.command {
        Command::Watch(target) => watch(&opts, target, &mut io::stdout().lock()),
        Command::Subscribe(sub) => subscribe(&opts, sub),
        _ => execute(&opts).map(|text| print!("{text}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Server(message)) => {
            eprintln!("mdnsctl: {message}");
            ExitCode::from(1)
        }
        Err(Failure::Connect(message) | Failure::Usage(message)) => {
            eprintln!("mdnsctl: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread::{self, JoinHandle};

    use super::*;

    fn parse(args: &[&str]) -> Result<Parsed, Failure> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    fn opts(args: &[&str]) -> Options {
        match parse(args).unwrap() {
            Parsed::Run(o) => o,
            Parsed::Help => panic!("unexpected help"),
        }
    }

    #[test]
    fn parses_commands_and_options() {
        let o = opts(&["segments"]);
        assert_eq!(
            o,
            Options { socket: DEFAULT_SOCKET.into(), json: false, verbose: false, command: Command::Segments }
        );

        let o = opts(&["-s", "/x.sock", "--json", "devices", "IoT", "to", "br0"]);
        assert_eq!(o.socket, PathBuf::from("/x.sock"));
        assert!(o.json);
        assert_eq!(o.command, Command::Devices("IoT to br0".into()));

        assert_eq!(opts(&["--socket=/y.sock", "segments"]).socket, PathBuf::from("/y.sock"));
        // Options after the command belong to the command.
        assert_eq!(opts(&["devices", "--json"]).command, Command::Devices("--json".into()));
        assert!(!opts(&["devices", "IoT"]).verbose);
        assert!(opts(&["-v", "devices", "IoT"]).verbose);
        assert!(opts(&["--verbose", "--json", "devices", "IoT"]).verbose);
        // After the command, "-v" is part of the segment name, not a flag.
        assert_eq!(opts(&["devices", "-v"]).command, Command::Devices("-v".into()));
        assert_eq!(opts(&["probe"]).command, Command::Probe(None));
        assert_eq!(opts(&["probe", "  "]).command, Command::Probe(None));
        assert_eq!(opts(&["probe", "IoT", "to", "br0"]).command, Command::Probe(Some("IoT to br0".into())));
        assert_eq!(opts(&["timers"]).command, Command::Timers);
        assert_eq!(opts(&["watchers"]).command, Command::Watchers);
        assert_eq!(opts(&["watch", "IoT", "to", "br0"]).command, Command::Watch("IoT to br0".into()));
        assert_eq!(parse(&["--help"]), Ok(Parsed::Help));
        assert_eq!(parse(&["segments", "-h"]), Err(Failure::Usage("segments takes no arguments".into())));
    }

    /// `--query` and `--interval` may come anywhere after the command, with
    /// their value as the next word or after `=`; the other words are the
    /// segment's name. They go to the daemon ahead of it.
    #[test]
    fn devices_and_watch_take_a_query() {
        let o = opts(&["devices", "--query", "_shelly._tcp", "IoT", "--query=_hue._tcp", "to", "br0"]);
        let target = Target { segment: "IoT to br0".into(), query: vec!["_shelly._tcp".into(), "_hue._tcp".into()], interval: None };
        assert_eq!(target.request("devices"), "devices --query=_shelly._tcp --query=_hue._tcp IoT to br0");
        assert_eq!(o.command, Command::Devices(target));

        let o = opts(&["watch", "--interval", "1min", "--query=_shelly._tcp", "IoT"]);
        let Command::Watch(target) = o.command else { panic!("{o:?}") };
        assert_eq!(target.interval, Some(Duration::from_secs(60)));
        assert_eq!(target.request("watch"), "watch --query=_shelly._tcp --interval=60 IoT");
        // Part of a second more is a second more: never asked more often than said.
        let Command::Watch(target) = opts(&["watch", "--interval=10.5s", "--query=_x._tcp", "IoT"]).command else { panic!() };
        assert_eq!(target.interval, Some(Duration::from_secs(11)));
        // devices asks once: --interval is part of the name there.
        assert_eq!(opts(&["devices", "--interval=1min"]).command, Command::Devices("--interval=1min".into()));
    }

    #[test]
    fn rejects_bad_command_lines() {
        for args in [
            &[][..],
            &["frobnicate"],
            &["devices"],
            &["devices", "  "],
            &["segments", "extra"],
            &["timers", "extra"],
            &["watchers", "IoT"],
            &["watch"],
            &["watch", "  "],
            &["watch", "a\nsegments"],
            &["--bogus", "segments"],
            &["-s"],
            &["devices", "a\nsegments"],
            &["probe", "a\nsegments"],
            &["devices", "--query"],
            &["devices", "--query", "_x._tcp"],
            &["devices", "--query=", "IoT"],
            &["devices", "--query=_x._tcp\nsegments", "IoT"],
            &["watch", "--interval=1min", "IoT"],
            &["watch", "--query=_x._tcp", "--interval=5s", "IoT"],
            &["watch", "--query=_x._tcp", "--interval=soon", "IoT"],
        ] {
            assert!(matches!(parse(args), Err(Failure::Usage(_))), "{args:?}");
        }
    }

    /// The man page must keep up with the commands, options and default path.
    #[test]
    fn man_page_covers_every_command_and_option() {
        let man = include_str!("../man/mdnsctl.1");
        for (name, _, _) in COMMANDS {
            assert!(man.contains(&format!(".B {name}")) || man.contains(&format!("\\fB{name}\\fR")), "{name}");
        }
        for option in ["\\-\\-json", "\\-\\-socket", "\\-\\-help", "\\-\\-verbose"] {
            assert!(man.contains(option), "{option}");
        }
        assert!(man.contains(DEFAULT_SOCKET));
    }

    #[test]
    fn usage_lists_every_command() {
        let text = usage();
        for (name, _, about) in COMMANDS {
            assert!(text.contains(name) && text.contains(about), "{name}");
        }
    }

    const SEGMENTS: &str = r#"{"ok":true,"segments":[{"name":"media_stuff","interfaces":["br0","media"],"families":["v4","v6"]},{"name":"IoT","interfaces":["wifi"],"families":["v4"]}]}"#;
    const DEVICES: &str = r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"br0","hostname":"printer.local","addresses":["10.0.0.10"],"services":[{"instance":"Printer._http._tcp.local","type":"_http._tcp.local","port":631,"target":"printer.local","txt":["rp=ipp","ty=hp"]}]},{"interface":"wifi","hostname":null,"addresses":["10.0.1.7"],"services":[]}]}"#;

    /// A device entry as the daemon sends it.
    fn entry(interface: &str, host: Option<&str>, addresses: &[&str], services: &str) -> String {
        let host = host.map_or("null".to_string(), |h| format!("\"{h}\""));
        let addresses: Vec<String> = addresses.iter().map(|a| format!("\"{a}\"")).collect();
        format!(
            r#"{{"interface":"{interface}","hostname":{host},"addresses":[{}],"services":[{services}]}}"#,
            addresses.join(",")
        )
    }

    fn reply(name: &str, entries: &[String]) -> String {
        format!(r#"{{"ok":true,"name":"{name}","devices":[{}]}}"#, entries.join(","))
    }

    #[test]
    fn segments_mark_untrusted_interfaces() {
        let reply: Value = serde_json::from_str(
            r#"{"ok":true,"segments":[{"name":"IoT to br0","interfaces":["br0","wifi"],"untrusted":["wifi"],"families":["v4","v6"]},{"name":"old","interfaces":["a"],"families":["v4"]}]}"#,
        )
        .unwrap();
        assert_eq!(
            render_segments(&reply).unwrap(),
            "NAME        INTERFACES             FAMILIES\nIoT to br0  br0, wifi (untrusted)  v4, v6\nold         a                      v4\n"
        );
    }

    #[test]
    fn renders_segments_as_a_table() {
        let reply: Value = serde_json::from_str(SEGMENTS).unwrap();
        assert_eq!(
            render_segments(&reply).unwrap(),
            "NAME         INTERFACES  FAMILIES\nmedia_stuff  br0, media  v4, v6\nIoT          wifi        v4\n"
        );
    }

    #[test]
    fn renders_devices_with_services() {
        let reply: Value = serde_json::from_str(DEVICES).unwrap();
        assert_eq!(
            render_devices(&reply).unwrap(),
            "IoT to br0: 2 devices\n  br0   10.0.0.10  printer.local\n      Printer  _http._tcp.local  :631 -> printer.local  [rp=ipp, ty=hp]\n  wifi  10.0.1.7   -\n"
        );
        let empty: Value = serde_json::from_str(r#"{"ok":true,"name":"IoT","devices":[]}"#).unwrap();
        assert_eq!(render_devices(&empty).unwrap(), "IoT: no devices\n");
    }

    #[test]
    fn verbose_listing_shows_both_addresses() {
        let json = reply(
            "x",
            &[
                entry("a", Some("h.local"), &["fd00::5", "fe80::5"], ""),
                entry("a", None, &["fe80::9"], ""),
            ],
        );
        let out = render_devices(&serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(
            out,
            format!("x: 2 devices\n  a  fd00::5, fe80::5  h.local\n  a  fe80::9{}-\n", " ".repeat(11))
        );
    }

    #[test]
    fn verbose_service_lines_show_subtypes_by_their_label() {
        let device: Value = serde_json::from_str(
            r#"{"services":[{"instance":"Office._ipp._tcp.local","type":"_ipp._tcp.local","port":631,"target":"printer.local",
                "txt":[],"subtypes":["_universal._sub._ipp._tcp.local","_cups._sub._ipp._tcp.local"],"ttl":120}]}"#,
        )
        .unwrap();
        assert_eq!(
            service_lines(&device),
            "      Office  _ipp._tcp.local  :631 -> printer.local  ttl=120  sub=_universal,_cups\n"
        );
    }

    fn brief(json: &str) -> String {
        render_devices_brief(&serde_json::from_str(json).unwrap()).unwrap()
    }

    #[test]
    fn brief_listing_shows_dns_name_and_pretty_name() {
        let reply: Value = serde_json::from_str(DEVICES).unwrap();
        assert_eq!(
            render_devices_brief(&reply).unwrap(),
            "IoT to br0: 1 device\n  printer.local  Printer  10.0.0.10\n\n(1 device without a name not shown; use -v to list everything)\n"
        );
    }

    #[test]
    fn brief_listing_cleans_names() {
        // A speaker with addresses of both families, and an AirPlay-style
        // "<MAC>@Name" instance.
        let svc = |instance: &str, kind: &str| {
            format!(r#"{{"instance":"{instance}","type":"{kind}","port":7000,"target":"x.local","txt":[]}}"#)
        };
        let services = format!(
            "{},{}",
            svc("04098643E3F7@OZAL Speakers._raop._tcp.local", "_raop._tcp.local"),
            svc("OZAL Speakers._airplay._tcp.local", "_airplay._tcp.local"),
        );
        let json = reply(
            "media",
            &[
                entry("media", Some("OZAL-Speakers.local"), &["10.0.2.73", "fe80::1"], &services),
                entry("media", Some("tv.local"), &["10.0.2.9"], &svc(r"Living Room\\. TV._http._tcp.local", "_http._tcp.local")),
            ],
        );
        assert_eq!(
            brief(&json),
            "media: 2 devices\n  OZAL-Speakers.local  OZAL Speakers    10.0.2.73, fe80::1\n  tv.local             Living Room. TV  10.0.2.9\n"
        );
    }

    #[test]
    fn brief_listing_shows_every_address_routable_before_link_local_without_duplicates() {
        let json = reply(
            "x",
            &[
                entry("a", Some("dual.local"), &["10.0.0.5", "fd00::5", "fe80::1"], ""),
                entry("b", Some("dual.local"), &["10.0.1.5"], ""),
                entry("a", Some("v6only.local"), &["fe80::2"], ""),
                entry("b", Some("v6only.local"), &["fe80::2"], ""),
            ],
        );
        // Routable IPv4, then routable IPv6, then link-local; each address once.
        assert_eq!(
            brief(&json),
            "x: 2 devices\n  dual.local    -  10.0.0.5, 10.0.1.5, fd00::5, fe80::1\n  v6only.local  -  fe80::2\n"
        );
    }

    #[test]
    fn brief_listing_edge_cases() {
        // Several distinct names are all shown; no services shows a dash.
        let two = r#"{"instance":"Kitchen._a._tcp.local","type":"_a._tcp.local","port":1,"target":null,"txt":[]},
                     {"instance":"Hall._b._tcp.local","type":"_b._tcp.local","port":2,"target":null,"txt":[]}"#;
        let json = reply(
            "x",
            &[
                entry("a", Some("b.local"), &["1.1.1.1"], two),
                entry("a", Some("A.local"), &["1.1.1.2"], ""),
            ],
        );
        assert_eq!(
            brief(&json),
            "x: 2 devices\n  A.local  -              1.1.1.2\n  b.local  Kitchen, Hall  1.1.1.1\n"
        );

        // Only unnamed devices, none at all.
        let only_unnamed = reply(
            "x",
            &[entry("a", None, &["1.1.1.1"], ""), entry("a", None, &["fe80::1"], "")],
        );
        assert_eq!(
            brief(&only_unnamed),
            "x: no named devices\n\n(2 devices without a name not shown; use -v to list everything)\n"
        );
        assert_eq!(brief(r#"{"ok":true,"name":"x","devices":[]}"#), "x: no devices\n");
    }

    #[test]
    fn renders_probe_results() {
        let reply: Value = serde_json::from_str(
            r#"{"ok":true,"probed":[{"interface":"br0","queries":14,"error":null},{"interface":"wifi","queries":null,"error":"sending to ff02::fb: Network is unreachable"}]}"#,
        )
        .unwrap();
        assert_eq!(
            render_probe(&reply).unwrap(),
            "INTERFACE  RESULT\nbr0        14 queries sent\nwifi       error: sending to ff02::fb: Network is unreachable\n\nList what answered with: mdnsctl devices <name>\n"
        );
    }

    /// Everything after `--` is the script and its arguments, options
    /// included; before it, the options and the segment name, as for
    /// `watch`, and `--foreground` and `--log`.
    #[test]
    fn subscribe_takes_a_watch_and_a_script() {
        let o = opts(&[
            "subscribe", "--query", "_shelly._tcp", "--interval=1min", "--log", "/var/log/plugs.log", "IoT", "to", "br0",
            "--", "/usr/local/bin/configure", "--fast", "--query", "--",
        ]);
        let Command::Subscribe(sub) = o.command else { panic!("{o:?}") };
        assert_eq!(sub.target.segment, "IoT to br0");
        assert_eq!(sub.target.query, ["_shelly._tcp"]);
        assert_eq!(sub.target.interval, Some(Duration::from_secs(60)));
        assert_eq!(sub.log, Some(PathBuf::from("/var/log/plugs.log")));
        assert!(!sub.foreground);
        assert_eq!(sub.script, ["/usr/local/bin/configure", "--fast", "--query", "--"]);
        assert_eq!(sub.target.request("watch"), "watch --query=_shelly._tcp --interval=60 IoT to br0");

        let Command::Subscribe(sub) = opts(&["subscribe", "--foreground", "--log=x.log", "lan", "--", "s"]).command else { panic!() };
        assert!(sub.foreground);
        assert_eq!((sub.log, sub.target.segment.as_str()), (Some(PathBuf::from("x.log")), "lan"));

        for args in [
            &["subscribe", "lan"][..],
            &["subscribe", "lan", "--"],
            &["subscribe", "--", "script"],
            &["subscribe", "--log", "--", "script"],
            &["subscribe", "--log=", "lan", "--", "script"],
            &["subscribe", "--interval=1min", "lan", "--", "script"],
        ] {
            assert!(matches!(parse(args), Err(Failure::Usage(_))), "{args:?}");
        }
    }

    #[test]
    fn a_script_gets_the_event_in_its_environment_too() {
        let event = r#"{"event":"added","segment":"IoT","ttl":4500,"device":{"interface":"wifi","hostname":"plug.local","addresses":["10.0.1.9","fd00::9"],"services":[]}}"#;
        assert_eq!(event_env(event), [
            ("MDNS_EVENT", "added".to_string()),
            ("MDNS_SEGMENT", "IoT".into()),
            ("MDNS_TTL", "4500".into()),
            ("MDNS_INTERFACE", "wifi".into()),
            ("MDNS_HOSTNAME", "plug.local".into()),
            ("MDNS_ADDRESS", "10.0.1.9".into()),
        ]);
        // What the event has not got is empty.
        let nameless = r#"{"event":"removed","segment":"IoT","ttl":0,"device":{"interface":"wifi","hostname":null,"addresses":[],"services":[]}}"#;
        let env = event_env(nameless);
        assert_eq!((env[4].1.as_str(), env[5].1.as_str(), env[2].1.as_str()), ("", "", "0"));
        assert!(event_env("not json").iter().all(|(_, v)| v.is_empty()));
    }

    #[test]
    fn a_script_is_an_executable_file_found_by_path_or_in_path() {
        let sh = executable("sh").unwrap();
        assert!(sh.is_absolute() && sh.file_name() == Some("sh".as_ref()), "not followed through a symlink: {}", sh.display());
        assert_eq!(executable(sh.to_str().unwrap()).unwrap(), sh);
        assert!(executable("target").is_err(), "a directory");
        assert!(executable("Cargo.toml").is_err(), "not on PATH, and no slash");
        assert!(executable("./Cargo.toml").unwrap_err().contains("not an executable"));
        assert!(executable("./no-such-script").is_err());
    }

    /// A script under `target/` that appends its stdin and environment to
    /// `out`, then exits with `status`.
    fn script(tag: &str, status: u8) -> (PathBuf, PathBuf) {
        std::fs::create_dir_all("target").unwrap();
        let path = PathBuf::from(format!("target/mdnsctl-test-{}-{tag}.sh", std::process::id()));
        let out = PathBuf::from(format!("target/mdnsctl-test-{}-{tag}.out", std::process::id()));
        let _ = std::fs::remove_file(&out);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n{{ cat; echo \"$1|$MDNS_EVENT|$MDNS_HOSTNAME|$MDNS_ADDRESS\"; }} >> {}\nexit {status}\n",
                out.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (executable(path.to_str().unwrap()).unwrap(), out)
    }

    const EVENT: &str = r#"{"event":"added","segment":"IoT","ttl":4500,"device":{"interface":"wifi","hostname":"plug.local","addresses":["10.0.1.9"],"services":[]}}"#;

    #[test]
    fn a_script_is_run_with_the_event_on_stdin_and_in_its_environment() {
        let (path, out) = script("run", 3);
        let status = run_script(&path, &["arg".into()], EVENT, &AtomicBool::new(false)).unwrap().unwrap();
        assert_eq!(status.code(), Some(3));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), format!("{EVENT}\narg|added|plug.local|10.0.1.9\n"));
    }

    #[test]
    fn a_script_running_when_told_to_stop_is_stopped() {
        let stop = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let sleeper = executable("sleep").unwrap();
        let ran = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(200));
                stop.store(true, Ordering::SeqCst);
            });
            run_script(&sleeper, &["30".into()], EVENT, &stop).unwrap()
        });
        assert_eq!(ran, None);
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    /// Events are run in the order they came, one at a time, a failing script
    /// holding up none; with nothing more to come, it is done.
    #[test]
    fn scripts_are_run_for_each_event_in_turn() {
        let (path, out) = script("turns", 1);
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        for host in ["a.local", "b.local", "c.local"] {
            tx.send(EVENT.replace("plug.local", host)).unwrap();
        }
        drop(tx);
        run_scripts(&rx, &path, &[], &AtomicBool::new(false));
        let lines: Vec<String> = std::fs::read_to_string(&out).unwrap().lines().filter(|l| l.starts_with('|')).map(String::from).collect();
        assert_eq!(lines, ["|added|a.local|10.0.1.9", "|added|b.local|10.0.1.9", "|added|c.local|10.0.1.9"]);
    }

    /// A subscriber that loses the daemon watches again once it is back, and
    /// the events of both connections come through, in order.
    #[test]
    fn a_subscriber_watches_again_after_losing_the_daemon() {
        std::fs::create_dir_all("target").unwrap();
        let path = PathBuf::from(format!("target/mdnsctl-test-{}-again.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let daemon = thread::spawn(move || {
            let mut asked = Vec::new();
            for event in ["first", "second"] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
                asked.push(line);
                writeln!(stream, "{ACK}").unwrap();
                writeln!(stream, "{}", EVENT.replace("plug.local", event)).unwrap();
                if event == "second" {
                    thread::sleep(Duration::from_millis(500));
                }
            }
            asked
        });

        let reader = open_watch(&path, "watch --query=_x._tcp IoT").unwrap();
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let socket = path.clone();
        thread::spawn(move || feed(&socket, "watch --query=_x._tcp IoT", reader, &tx));
        let next = || rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(next().contains("first"));
        assert!(next().contains("second"));
        assert_eq!(daemon.join().unwrap(), ["watch --query=_x._tcp IoT\n"; 2], "the same watch, again");
        let _ = std::fs::remove_file(&path);
    }

    /// Only events reach a script: a line that is not JSON, or not an event,
    /// is skipped, and one cut off by the end of the stream (a daemon that
    /// stopped while writing it) ends the watch, not taken for whole.
    #[test]
    fn only_whole_events_reach_a_script() {
        let (path, daemon) = streaming_daemon(
            "whole",
            vec![ACK.into(), "not json".into(), r#"{"ok":true}"#.into(), EVENT.into()],
        );
        let mut reader = open_watch(&path, "watch IoT").unwrap();
        let cut = thread::spawn(move || {
            daemon.join().unwrap();
        });
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        assert_eq!(forward(&mut reader, &tx), Err("the daemon closed the connection".into()));
        cut.join().unwrap();
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), [EVENT]);

        // A last line without its newline is not an event, even if it reads
        // as one.
        let path = PathBuf::from(format!("target/mdnsctl-test-{}-cut.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let daemon = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut String::new()).unwrap();
            stream.write_all(format!("{ACK}\n{EVENT}\n{EVENT}").as_bytes()).unwrap();
        });
        let mut reader = open_watch(&path, "watch IoT").unwrap();
        daemon.join().unwrap();
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        assert_eq!(forward(&mut reader, &tx), Err("the daemon closed the connection".into()));
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), [EVENT], "the cut-off second one is not passed on");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_refused_subscription_is_an_error_at_once() {
        let (path, _daemon) = fake_daemon("refused", r#"{"ok":false,"error":"no such segment: nope"}"#);
        assert_eq!(
            open_watch(&path, "watch nope").unwrap_err(),
            Failure::Server("no such segment: nope".into())
        );
    }

    #[test]
    fn the_time_is_told_in_utc() {
        let now = utc_now();
        assert_eq!(now.len(), 20, "{now}");
        assert!(now.starts_with("20") && now.ends_with('Z') && now.as_bytes()[10] == b'T', "{now}");
    }

    /// A watcher is shown with what it watches and who holds it; what the
    /// process or user cannot be named by is shown as the number, or `-`.
    #[test]
    fn renders_watchers() {
        let reply: Value = serde_json::from_str(
            r#"{"ok":true,"watchers":[
                {"id":3,"segment":"IoT","query":[],"interval_s":null,"pid":4242,"uid":1000,"age_ms":93000},
                {"id":7,"segment":"lan","query":["_shelly._tcp.local","_hue._tcp.local"],"interval_s":60,"pid":5151,"uid":0,"age_ms":2500},
                {"id":9,"segment":"lan","query":[],"interval_s":null,"pid":null,"uid":null,"age_ms":10}]}"#,
        )
        .unwrap();
        let user = |uid: u32| (uid == 1000).then(|| "alex".to_string());
        let command = |pid: i32| (pid == 4242).then(|| "mdnsctl watch IoT".to_string());
        assert_eq!(
            render_watchers(&reply, user, command).unwrap(),
            "ID  SEGMENT  QUERY                    EVERY   AGE     PID   USER  COMMAND\n\
             3   IoT      -                        -       1m 33s  4242  alex  mdnsctl watch IoT\n\
             7   lan      _shelly._tcp, _hue._tcp  1m 00s  2.5s    5151  0     -\n\
             9   lan      -                        -       10ms    -     -     -\n"
        );
        let none: Value = serde_json::from_str(r#"{"ok":true,"watchers":[]}"#).unwrap();
        assert_eq!(render_watchers(&none, user, command).unwrap(), "no watchers\n");
        assert!(render_watchers(&serde_json::json!({"ok":true}), user, command).is_err());
    }

    #[test]
    fn this_process_is_named_by_its_user_and_command_line() {
        let me = std::process::id() as i32;
        assert!(command_line(me).is_some_and(|c| !c.is_empty()));
        assert_eq!(user_name(0).as_deref(), Some("root"));
        assert!(command_line(-1).is_none());
    }

    #[test]
    fn renders_timers() {
        let reply: Value = serde_json::from_str(
            r#"{"ok":true,"timers":[
                {"id":1,"name":"upkeep br0/V4","running":false,"due_in_ms":93000,"runs":4,"last_run_ago_ms":3500,"last_took_us":210},
                {"id":2,"name":"upkeep wifi/V4","running":false,"due_in_ms":0,"runs":0,"last_run_ago_ms":null,"last_took_us":null},
                {"id":3,"name":"busy","running":true,"due_in_ms":null,"runs":9,"last_run_ago_ms":90,"last_took_us":null},
                {"id":4,"name":"parked","running":false,"due_in_ms":null,"runs":1,"last_run_ago_ms":4500000,"last_took_us":25000}]}"#,
        )
        .unwrap();
        assert_eq!(
            render_timers(&reply).unwrap(),
            "NAME            STATE    DUE        RUNS  LAST RUN    TOOK\n\
             upkeep br0/V4   waiting  in 1m 33s  4     3.5s ago    210us\n\
             upkeep wifi/V4  waiting  now        0     -           -\n\
             busy            running  -          9     90ms ago    -\n\
             parked          idle     never      1     1h 15m ago  25ms\n"
        );
        assert!(render_timers(&serde_json::json!({"ok":true})).is_err());
    }

    fn event(kind: &str, ttl: u64, host: Option<&str>, addr: &str, services: &str) -> Value {
        serde_json::from_str(&format!(
            r#"{{"event":"{kind}","segment":"IoT","ttl":{ttl},"device":{{"interface":"wifi","hostname":{},"addresses":["{addr}"],"services":{services}}}}}"#,
            host.map_or("null".to_string(), |h| format!("\"{h}\""))
        ))
        .unwrap()
    }

    const PLUG: &str = r#"[{"instance":"Plug S._shelly._tcp.local","type":"_shelly._tcp.local","port":80,"target":"plug.local","txt":["gen=2"]}]"#;

    #[test]
    fn watch_lines_say_what_happened_and_for_how_long() {
        let mut seen = HashSet::new();
        let mut show = |e: Value, verbose| render_event(&e, verbose, &mut seen).unwrap();

        // Heard by address first: nothing to show until it has a name.
        assert_eq!(show(event("added", 300, None, "10.0.1.9", "[]"), false), None);
        // The first named sighting is "added", whatever the daemon called it.
        assert_eq!(
            show(event("updated", 4500, Some("plug.local"), "10.0.1.9", PLUG), false).as_deref(),
            Some("added    ttl=4500   plug.local  Plug S  10.0.1.9\n")
        );
        assert_eq!(
            show(event("updated", 4400, Some("plug.local"), "10.0.1.9", PLUG), false).as_deref(),
            Some("updated  ttl=4400   plug.local  Plug S  10.0.1.9\n")
        );
        // Heard over IPv6 too, it is the same device: an update.
        assert!(show(event("added", 300, Some("plug.local"), "fd00::9", "[]"), false).unwrap().starts_with("updated  "));
        // Gone: ttl 0, and a later return is "added" again.
        assert_eq!(
            show(event("removed", 0, Some("plug.local"), "10.0.1.9", PLUG), false).as_deref(),
            Some("removed  ttl=0      plug.local  Plug S  10.0.1.9\n")
        );
        assert!(show(event("added", 300, Some("plug.local"), "10.0.1.9", PLUG), false).unwrap().starts_with("added  "));

        // Already there when a watch for its type started: present, and then
        // seen, so a change to it is an update.
        let mut seen = HashSet::new();
        let mut show = |e: Value| render_event(&e, false, &mut seen).unwrap();
        assert!(show(event("present", 280, Some("hue.local"), "10.0.1.3", PLUG)).unwrap().starts_with("present  ttl=280 "));
        assert!(show(event("updated", 300, Some("hue.local"), "10.0.1.3", PLUG)).unwrap().starts_with("updated  "));
    }

    #[test]
    fn verbose_watch_lines_are_a_device_with_its_services() {
        let mut seen = HashSet::new();
        let shown = render_event(&event("added", 4500, Some("plug.local"), "10.0.1.9", PLUG), true, &mut seen)
            .unwrap()
            .unwrap();
        assert_eq!(
            shown,
            "added    ttl=4500   wifi  10.0.1.9  plug.local\n      Plug S  _shelly._tcp.local  :80 -> plug.local  [gen=2]\n"
        );
        // Verbose shows devices that have no name too.
        let unnamed = render_event(&event("added", 300, None, "10.0.1.9", "[]"), true, &mut seen).unwrap().unwrap();
        assert_eq!(unnamed, "added    ttl=300    wifi  10.0.1.9  -\n");
    }

    #[test]
    fn a_malformed_event_is_an_error() {
        let mut seen = HashSet::new();
        assert!(render_event(&serde_json::json!({"event":"added"}), false, &mut seen).is_err());
        let mut odd = event("exploded", 1, Some("x.local"), "10.0.0.1", "[]");
        assert!(render_event(&odd, false, &mut seen).is_err());
        odd["event"] = "added".into();
        assert!(render_event(&odd, false, &mut seen).is_ok());
    }

    /// A fake daemon that acknowledges a watch, sends `lines`, and hangs up.
    fn streaming_daemon(tag: &str, lines: Vec<String>) -> (PathBuf, JoinHandle<String>) {
        std::fs::create_dir_all("target").unwrap();
        let path = PathBuf::from(format!("target/mdnsctl-test-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let socket_file = path.clone();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = std::fs::remove_file(&socket_file);
            let mut asked = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut asked).unwrap();
            for line in lines {
                writeln!(stream, "{line}").unwrap();
            }
            asked
        });
        (path, handle)
    }

    const ACK: &str = r#"{"ok":true,"name":"IoT","watching":true}"#;

    fn watch_options(path: &Path, json: bool) -> Options {
        Options { socket: path.into(), json, verbose: false, command: Command::Watch("IoT".into()) }
    }

    #[test]
    fn watch_prints_changes_until_the_daemon_stops() {
        let added = event("added", 4500, Some("plug.local"), "10.0.1.9", PLUG).to_string();
        let removed = event("removed", 0, Some("plug.local"), "10.0.1.9", PLUG).to_string();
        let (path, daemon) = streaming_daemon("watch", vec![ACK.into(), added.clone(), removed.clone()]);

        let mut out = Vec::new();
        let result = watch(&watch_options(&path, false), &"IoT".into(), &mut out);
        assert_eq!(daemon.join().unwrap(), "watch IoT\n");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "added    ttl=4500   plug.local  Plug S  10.0.1.9\nremoved  ttl=0      plug.local  Plug S  10.0.1.9\n"
        );
        // The daemon went away: that is a failure, not a clean end.
        assert!(matches!(result, Err(Failure::Connect(m)) if m.contains("closed")));
    }

    #[test]
    fn watch_json_prints_each_event_unchanged_and_not_the_acknowledgement() {
        let added = event("added", 4500, Some("plug.local"), "10.0.1.9", PLUG).to_string();
        let (path, daemon) = streaming_daemon("watch-json", vec![ACK.into(), added.clone()]);
        let mut out = Vec::new();
        let _ = watch(&watch_options(&path, true), &"IoT".into(), &mut out);
        daemon.join().unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("{added}\n"));
    }

    #[test]
    fn watch_reports_refusals_and_failures_mid_stream() {
        let (path, daemon) = streaming_daemon("watch-refused", vec![r#"{"ok":false,"error":"no such segment: IoT"}"#.into()]);
        assert_eq!(
            watch(&watch_options(&path, false), &"IoT".into(), &mut Vec::new()),
            Err(Failure::Server("no such segment: IoT".into()))
        );
        daemon.join().unwrap();

        let (path, daemon) = streaming_daemon("watch-stopped", vec![ACK.into(), r#"{"ok":false,"error":"shutting down"}"#.into()]);
        assert_eq!(
            watch(&watch_options(&path, false), &"IoT".into(), &mut Vec::new()),
            Err(Failure::Server("shutting down".into()))
        );
        daemon.join().unwrap();
    }

    /// `mdnsctl watch | head` must not be an error when the reader leaves.
    #[test]
    fn watch_ends_quietly_when_the_output_is_closed() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let added = event("added", 4500, Some("plug.local"), "10.0.1.9", PLUG).to_string();
        let (path, daemon) = streaming_daemon("watch-closed", vec![ACK.into(), added]);
        assert_eq!(watch(&watch_options(&path, false), &"IoT".into(), &mut Closed), Ok(()));
        daemon.join().unwrap();
    }

    #[test]
    fn timers_list_what_they_wait_for_under_each_timer() {
        let reply: Value = serde_json::from_str(
            r#"{"ok":true,"timers":[
                {"id":1,"name":"upkeep br0/V4","running":false,"due_in_ms":93000,"runs":4,"last_run_ago_ms":3500,"last_took_us":210,
                 "pending":[{"what":"re-announce","who":"router.local","due_in_ms":93000},
                            {"what":"expire","who":"10.0.0.10","due_in_ms":182000},
                            {"what":"refresh","who":"OZAL-Speakers.local","due_in_ms":0}]},
                {"id":2,"name":"upkeep wifi/V4","running":false,"due_in_ms":null,"runs":1,"last_run_ago_ms":8000,"last_took_us":96,"pending":[]}]}"#,
        )
        .unwrap();
        assert_eq!(
            render_timers(&reply).unwrap(),
            "NAME                               STATE    DUE        RUNS  LAST RUN  TOOK\n\
             upkeep br0/V4                      waiting  in 1m 33s  4     3.5s ago  210us\n\
             \x20 re-announce router.local                  in 1m 33s\n\
             \x20 expire      10.0.0.10                     in 3m 02s\n\
             \x20 refresh     OZAL-Speakers.local           now\n\
             upkeep wifi/V4                     idle     never      1     8.0s ago  96us\n"
        );
        // A daemon that does not say what it waits for is still listed.
        let old: Value = serde_json::from_str(r#"{"ok":true,"timers":[{"id":1,"name":"x","running":false,"due_in_ms":5,"runs":0,"last_run_ago_ms":null,"last_took_us":null}]}"#).unwrap();
        assert!(render_timers(&old).is_ok());
        assert!(render_timers(&serde_json::json!({"ok":true,"timers":[{"id":1,"name":"x","running":false,"due_in_ms":5,"runs":0,"pending":[{"what":"expire"}]}]})).is_err());
    }

    #[test]
    fn verbose_listings_show_the_ttls_the_device_announced() {
        let device = r#"{"interface":"wifi","hostname":"plug.local","addresses":["10.0.1.9"],"address_ttl":120,"services":[{"instance":"Plug S._shelly._tcp.local","type":"_shelly._tcp.local","port":80,"target":"plug.local","txt":["gen=2"],"ttl":4500},{"instance":"Plug S._http._tcp.local","type":"_http._tcp.local","port":80,"target":"plug.local","txt":[],"ttl":null}]}"#;
        let reply: Value = serde_json::from_str(&format!(r#"{{"ok":true,"name":"IoT","devices":[{device}]}}"#)).unwrap();
        assert_eq!(
            render_devices(&reply).unwrap(),
            "IoT: 1 device\n  wifi  10.0.1.9  plug.local  addr-ttl=120\n      Plug S  _shelly._tcp.local  :80 -> plug.local  ttl=4500  [gen=2]\n      Plug S  _http._tcp.local  :80 -> plug.local\n"
        );
        // A watch shows them too, after its own ttl: how long the daemon keeps the device.
        let event: Value = serde_json::from_str(&format!(r#"{{"event":"added","segment":"IoT","ttl":300,"device":{device}}}"#)).unwrap();
        let shown = render_event(&event, true, &mut HashSet::new()).unwrap().unwrap();
        assert!(shown.starts_with("added    ttl=300    wifi  10.0.1.9  plug.local  addr-ttl=120\n"), "{shown}");
        // The brief views stay as they were.
        let brief = render_event(&event, false, &mut HashSet::new()).unwrap().unwrap();
        assert_eq!(brief, "added    ttl=300    plug.local  Plug S  10.0.1.9\n");
    }

    #[test]
    fn spans_read_naturally() {
        let shown: Vec<String> = [0, 999, 1000, 59_999, 60_000, 3_599_999, 3_600_000, 90_000_000].map(span).into();
        assert_eq!(shown, ["0ms", "999ms", "1.0s", "60.0s", "1m 00s", "59m 59s", "1h 00m", "25h 00m"]);
    }

    #[test]
    fn timers_asks_the_daemon() {
        const REPLY: &str = r#"{"ok":true,"timers":[{"id":1,"name":"upkeep br0/V4","running":false,"due_in_ms":5000,"runs":0,"last_run_ago_ms":null,"last_took_us":null}]}"#;
        let (path, daemon) = fake_daemon("timers", REPLY);
        let out = run(&path, false, Command::Timers).unwrap();
        assert_eq!(daemon.join().unwrap(), "timers\n");
        assert!(out.contains("upkeep br0/V4") && out.contains("in 5.0s"), "{out}");

        let (path, daemon) = fake_daemon("timers-json", REPLY);
        assert_eq!(run(&path, true, Command::Timers).unwrap(), format!("{REPLY}\n"));
        daemon.join().unwrap();
    }

    /// A one-shot fake daemon: replies to one request, returns what it was asked.
    fn fake_daemon(tag: &str, reply: &'static str) -> (PathBuf, JoinHandle<String>) {
        // Unix socket paths are limited to ~108 bytes, so stay relative to
        // the package root (cargo's test working directory).
        std::fs::create_dir_all("target").unwrap();
        let path = PathBuf::from(format!("target/mdnsctl-test-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let socket_file = path.clone();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = std::fs::remove_file(&socket_file);
            let mut asked = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut asked).unwrap();
            writeln!(stream, "{reply}").unwrap();
            asked
        });
        (path, handle)
    }

    fn run(path: &Path, json: bool, command: Command) -> Result<String, Failure> {
        execute(&Options { socket: path.into(), json, verbose: false, command })
    }

    fn run_verbose(path: &Path, command: Command) -> Result<String, Failure> {
        execute(&Options { socket: path.into(), json: false, verbose: true, command })
    }

    #[test]
    fn talks_to_the_daemon() {
        let (path, daemon) = fake_daemon("segments", SEGMENTS);
        let out = run(&path, false, Command::Segments).unwrap();
        assert_eq!(daemon.join().unwrap(), "segments\n");
        assert!(out.starts_with("NAME"));

        let (path, daemon) = fake_daemon("devices", DEVICES);
        let out = run(&path, false, Command::Devices("IoT to br0".into())).unwrap();
        assert_eq!(daemon.join().unwrap(), "devices IoT to br0\n");
        assert!(out.starts_with("IoT to br0: 1 device\n"), "brief by default: {out}");

        let (path, daemon) = fake_daemon("devices-v", DEVICES);
        let out = run_verbose(&path, Command::Devices("IoT to br0".into())).unwrap();
        daemon.join().unwrap();
        assert!(out.starts_with("IoT to br0: 2 devices\n") && out.contains("10.0.1.7"), "verbose: {out}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn probe_asks_for_all_segments_or_one() {
        const REPLY: &str = r#"{"ok":true,"probed":[{"interface":"br0","queries":3,"error":null}]}"#;
        let (path, daemon) = fake_daemon("probe-all", REPLY);
        let out = run(&path, false, Command::Probe(None)).unwrap();
        assert_eq!(daemon.join().unwrap(), "probe\n");
        assert!(out.contains("br0        3 queries sent"), "{out}");

        let (path, daemon) = fake_daemon("probe-one", REPLY);
        run(&path, false, Command::Probe(Some("IoT to br0".into()))).unwrap();
        assert_eq!(daemon.join().unwrap(), "probe IoT to br0\n");
    }

    #[test]
    fn json_mode_passes_the_reply_through() {
        let (path, daemon) = fake_daemon("json", SEGMENTS);
        assert_eq!(run(&path, true, Command::Segments).unwrap(), format!("{SEGMENTS}\n"));
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reports_server_and_connection_errors() {
        let (path, daemon) = fake_daemon("err", r#"{"ok":false,"error":"no such segment: nope"}"#);
        assert_eq!(
            run(&path, false, Command::Devices("nope".into())),
            Err(Failure::Server("no such segment: nope".into()))
        );
        daemon.join().unwrap();

        let (path2, daemon) = fake_daemon("junk", "not json");
        assert!(matches!(run(&path2, false, Command::Segments), Err(Failure::Server(m)) if m.contains("unreadable")));
        daemon.join().unwrap();

        let missing = PathBuf::from("target/mdnsctl-test-nonexistent.sock");
        assert!(matches!(run(&missing, false, Command::Segments), Err(Failure::Connect(_))));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path2);
    }
}
