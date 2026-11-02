//! `mdnsctl`: command line client for the daemon's control socket (see
//! `ipc.rs` for the protocol). Every IPC command has a subcommand here.

use std::collections::{HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

#[path = "args.rs"]
mod args;
// Shared with the daemon, which waits on more than a subscriber does.
#[allow(dead_code)]
#[path = "poll.rs"]
mod poll;
#[path = "signal.rs"]
mod signal;
#[path = "timespan.rs"]
mod timespan;

/// Keep in sync with `config::DEFAULT_SOCKET` in the daemon.
const DEFAULT_SOCKET: &str = "/run/mdnsd/mdnsd.sock";

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
    fn exit(self) -> ExitCode {
        match self {
            Early::Help(text) => print!("{text}"),
            Early::Version => println!("mdnsctl {}", env!("CARGO_PKG_VERSION")),
            Early::Usage { message, usage } => {
                eprintln!("error: {message}\n\nUsage: {usage}\n\nFor more information, try '--help'.");
                return ExitCode::from(2);
            }
            Early::NoCommand => {
                eprint!("{}", help(None));
                return ExitCode::from(2);
            }
        }
        ExitCode::SUCCESS
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
    let span = timespan::parse(value).map_err(|e| e.to_string())?;
    if span.is_zero() {
        return Err("it must be longer than nothing".into());
    }
    Ok(span)
}

/// An `--interval`: a time span of at least [`MIN_INTERVAL`], in whole
/// seconds as the daemon takes it, part of a second more being a second
/// more, so it is never asked more often than said.
fn interval_span(value: &str) -> Result<Duration, String> {
    let span = timespan::parse(value).map_err(|e| e.to_string())?;
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
    let (mut socket, mut verbose, mut json, mut segmented, mut asked_help) = (PathBuf::from(DEFAULT_SOCKET), false, false, false, false);
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
            Short('s') | Long("socket") => socket = PathBuf::from(parser.value().map_err(|e| bad(command, e))?),
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
                log = Some(PathBuf::from(v));
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

/// Follow a segment: print each change the daemon reports until it stops (an
/// error) or `out` is closed (success: `mdnsctl watch | head` is fine).
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
        if let Some(shown) = shown
            && out.write_all(shown.as_bytes()).and_then(|()| out.flush()).is_err()
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
fn devices_query(opts: &Options, target: &Target, out: &mut impl Write) -> Result<(), Failure> {
    let socket = &opts.socket;
    let mut reader = open_watch(socket, &target.request("watch"))?;
    let deadline = Instant::now() + target.wait.unwrap_or(DEFAULT_WAIT);
    // What is found, by where and who it is, as last heard of.
    let mut found: Vec<(String, Value)> = Vec::new();
    // What is printed: hosts, or with -v devices, by their key.
    let mut shown = HashSet::new();
    let mut line = String::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        reader.get_ref().set_read_timeout(Some(left)).map_err(|e| connect_err(socket, e))?;
        line.clear();
        match reader.read_line(&mut line) {
            Ok(n) if n == 0 || !line.ends_with('\n') => {
                return Err(Failure::Connect("the daemon closed the connection".into()));
            }
            Ok(_) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => break,
            Err(e) => return Err(connect_err(socket, e)),
        }
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
            && out.write_all(text.as_bytes()).and_then(|()| out.flush()).is_err()
        {
            return Ok(());
        }
    }
    drop(reader);

    let name = target.segment.trim_matches('"');
    let text = if opts.segmented {
        String::new()
    } else if opts.json {
        let mut devices: Vec<Value> = found.into_iter().map(|(_, d)| d).collect();
        devices.sort_by_key(|d| (d["interface"].to_string(), d["hostname"].to_string().to_ascii_lowercase(), d["addresses"].to_string()));
        format!("{}\n", serde_json::json!({ "ok": true, "name": name, "devices": devices }))
    } else if opts.verbose {
        devices_summary(name, found.len(), 0)
    } else {
        let hosts: HashSet<String> = found.iter().filter_map(|(_, d)| d["hostname"].as_str()).map(str::to_ascii_lowercase).collect();
        let unnamed = found.iter().filter(|(_, d)| !d["hostname"].is_string()).count();
        devices_summary(name, hosts.len(), unnamed)
    };
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
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
    let signals = signal::install().map_err(|e| Failure::Usage(format!("cannot handle signals: {e}")))?;
    note(&format!("watching {}, running {} for each change", sub.target.segment, script.display()));

    let mut subscriber = Subscriber::new(&opts.socket, &line, reader, script, sub.script[1..].to_vec());
    loop {
        let mut fds = vec![poll::readable(signals.fd())];
        fds.extend(subscriber.fds());
        let timeout = subscriber.deadline().map(|at| at.saturating_duration_since(Instant::now()));
        if let Err(e) = poll::wait(&mut fds, timeout) {
            note(&format!("cannot wait: {e}"));
            break;
        }
        if signals.take().is_some() {
            break;
        }
        subscriber.turn(&fds[1..], Instant::now());
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
            let opened = settle_in_background(log).and_then(|()| open_watch(socket, line));
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

/// In the child of [`detach`]: leave the caller's session, so that its
/// terminal going away does not take the subscriber with it, and send stdin
/// from `/dev/null` and stdout and stderr to `log`, or there.
fn settle_in_background(log: Option<&File>) -> Result<(), Failure> {
    let failed = |what: &str| Failure::Connect(format!("cannot go into the background: {what}: {}", io::Error::last_os_error()));
    // SAFETY: setsid takes no arguments; it fails only for a process group
    // leader, which a child just forked is not.
    if unsafe { libc::setsid() } == -1 {
        return Err(failed("setsid"));
    }
    let null = File::options().read(true).write(true).open("/dev/null");
    let null = null.map_err(|e| Failure::Connect(format!("cannot open /dev/null: {e}")))?;
    let out = log.unwrap_or(&null);
    for (from, to) in [(&null, 0), (out, 1), (out, 2)] {
        // SAFETY: both descriptors are open in this process; dup2 replaces
        // `to` (stdin, stdout or stderr) with a copy of `from`.
        if unsafe { libc::dup2(from.as_raw_fd(), to) } == -1 {
            return Err(failed("dup2"));
        }
    }
    Ok(())
}

/// A subscriber: the watch it reads events from, opened again whenever it is
/// lost, and the script it runs for each event, one at a time, all from one
/// loop that waits on whichever of them has something to do.
struct Subscriber {
    socket: PathBuf,
    line: String,
    script: PathBuf,
    args: Vec<String>,
    /// The watch while it is open, and what of its next line has come.
    watch: Option<(UnixStream, Vec<u8>)>,
    /// While it is not: when to try to open it again, and how long to wait
    /// after that if it fails.
    retry: Option<(Instant, Duration)>,
    /// Events waiting for the script.
    queue: VecDeque<String>,
    running: Option<Running>,
}

/// The script, running for an event.
struct Running {
    child: std::process::Child,
    /// Readable once it has exited, where the kernel can say so.
    pidfd: Option<OwnedFd>,
    /// Its stdin, and what of the event is still to be written to it.
    stdin: Option<(ChildStdin, Vec<u8>)>,
    event: String,
}

impl Subscriber {
    /// A subscriber reading the watch `line` from `reader`, as opened on
    /// `socket`, running `script` with `args`.
    fn new(socket: &Path, line: &str, reader: BufReader<UnixStream>, script: PathBuf, args: Vec<String>) -> Subscriber {
        // What came after the acknowledgement is the start of the events.
        let pending = reader.buffer().to_vec();
        let stream = reader.into_inner();
        let watch = match stream.set_nonblocking(true) {
            Ok(()) => Some((stream, pending)),
            Err(e) => {
                note(&format!("lost the daemon: {e}"));
                None
            }
        };
        let retry = watch.is_none().then(|| (Instant::now() + RECONNECT_FIRST, RECONNECT_FIRST));
        let (socket, line) = (socket.to_path_buf(), line.to_string());
        Subscriber { socket, line, script, args, watch, retry, queue: VecDeque::new(), running: None }
    }

    /// The descriptors to wait on: the watch, readable when events come; the
    /// script's stdin, writable when it takes more; and the script, readable
    /// once it exits.
    fn fds(&self) -> Vec<libc::pollfd> {
        let mut fds = Vec::new();
        if let Some((stream, _)) = &self.watch {
            fds.push(poll::readable(stream.as_raw_fd()));
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
    fn deadline(&self) -> Option<Instant> {
        let check = self.running.as_ref().filter(|r| r.pidfd.is_none()).map(|_| Instant::now() + STOP_CHECK);
        self.retry.map(|(at, _)| at).into_iter().chain(check).min()
    }

    /// Do what `fds` (as [`Subscriber::fds`] gave them, after waiting) say
    /// can be done, and what is due at `now`.
    fn turn(&mut self, fds: &[libc::pollfd], now: Instant) {
        let ready = |fd: RawFd, flags: libc::c_short| fds.iter().any(|p| p.fd == fd && p.revents & (flags | libc::POLLHUP | libc::POLLERR) != 0);
        if self.watch.as_ref().is_some_and(|(stream, _)| ready(stream.as_raw_fd(), libc::POLLIN)) {
            self.read();
        }
        if let Some(running) = &mut self.running {
            if running.stdin.as_ref().is_some_and(|(stdin, _)| ready(stdin.as_raw_fd(), libc::POLLOUT)) {
                running.feed();
            }
            let exited = running.pidfd.as_ref().is_none_or(|pidfd| ready(pidfd.as_raw_fd(), libc::POLLIN));
            if exited {
                match running.child.try_wait() {
                    Ok(Some(status)) => {
                        if !status.success() {
                            note(&format!("{} {status}, for: {}", self.script.display(), running.event));
                        }
                        self.running = None;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        note(&format!("lost {}: {e}", self.script.display()));
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
                Ok(reader) => {
                    note("watching again");
                    let fresh = Subscriber::new(&self.socket, &self.line, reader, PathBuf::new(), Vec::new());
                    (self.watch, self.retry) = (fresh.watch, fresh.retry);
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
        let Some((stream, pending)) = &mut self.watch else { return };
        let mut buf = [0u8; 4096];
        let lost = loop {
            match stream.read(&mut buf) {
                // Cut off by the end of the stream: what is pending is not a
                // line to trust.
                Ok(0) => break Some("the daemon closed the connection".to_string()),
                Ok(n) => pending.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break None,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Some(format!("lost the daemon: {e}")),
            }
        };
        let mut lines = Vec::new();
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            lines.push(String::from_utf8_lossy(&pending.drain(..=end).collect::<Vec<u8>>()).trim_end().to_string());
        }
        let mut lost = lost;
        for text in lines {
            if let Err(why) = self.take(&text) {
                lost = Some(why);
                break;
            }
        }
        if let Some(why) = lost {
            note(&format!("{why}; watching again once the daemon is back"));
            self.watch = None;
            self.retry = Some((Instant::now() + RECONNECT_FIRST, RECONNECT_FIRST));
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
        let spawned = std::process::Command::new(&self.script)
            .args(&self.args)
            .envs(event_env(&event))
            .stdin(Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) => return note(&format!("cannot run {}: {e}", self.script.display())),
        };
        // SAFETY: pidfd_open takes a PID and flags, and returns a new
        // descriptor or -1; the child is ours and not yet reaped.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
        // SAFETY: a descriptor just made, owned by nothing else.
        let pidfd = (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
        // A script that does not read its input must not hold the subscriber up.
        let stdin = child.stdin.take().filter(|stdin| set_nonblocking(stdin.as_raw_fd()).is_ok());
        let stdin = stdin.map(|stdin| (stdin, format!("{event}\n").into_bytes()));
        let mut running = Running { child, pidfd, stdin, event };
        running.feed();
        self.running = Some(running);
    }

    /// Stop the script, if one is running, and wait for it.
    fn stop(&mut self) {
        if let Some(mut running) = self.running.take() {
            // SAFETY: a plain signal to the child, which has not been reaped.
            unsafe { libc::kill(running.child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = running.child.wait();
        }
    }
}

impl Running {
    /// Write what the script takes of the event, closing its stdin once it
    /// has all of it, or will take no more.
    fn feed(&mut self) {
        let Some((stdin, rest)) = &mut self.stdin else { return };
        loop {
            match stdin.write(rest) {
                Ok(n) if n == rest.len() => break self.stdin = None,
                Ok(n) => drop(rest.drain(..n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break self.stdin = None,
            }
        }
    }
}

/// Make `fd` non-blocking.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL on a descriptor the caller holds.
    let ok = unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
    };
    if ok { Ok(()) } else { Err(io::Error::last_os_error()) }
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
    named.sort_by_key(|n| n.host.to_ascii_lowercase());

    let rows: Vec<[String; 3]> = named
        .iter_mut()
        .map(|n| {
            n.addrs.sort_by_key(|(link_local, v6, _)| (*link_local, *v6));
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
    let mut addrs = strings(&device["addresses"]);
    addrs.sort_by_key(|a| (is_link_local(a), a.contains(':')));
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
    let parsed = args::from_env().map_err(|e| Early::usage(None, e.to_string())).and_then(parse_args);
    let opts = match parsed {
        Ok(opts) => opts,
        // Help and version to stdout with 0, usage errors to stderr with 2.
        Err(early) => return early.exit(),
    };

    let result = match &opts.command {
        Command::Watch(target) => watch(&opts, target, &mut io::stdout().lock()),
        Command::Devices(target) if !target.query.is_empty() => devices_query(&opts, target, &mut io::stdout().lock()),
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

    fn parse(args: &[&str]) -> Result<Options, Early> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    fn opts(args: &[&str]) -> Options {
        parse(args).unwrap_or_else(|e| panic!("{args:?}: {e:?}"))
    }

    #[test]
    fn parses_commands_and_options() {
        let o = opts(&["segments"]);
        assert_eq!(
            o,
            Options { socket: DEFAULT_SOCKET.into(), json: false, segmented: false, verbose: false, command: Command::Segments }
        );

        let o = opts(&["-s", "/x.sock", "--json", "devices", "IoT", "to", "br0"]);
        assert_eq!(o.socket, PathBuf::from("/x.sock"));
        assert!(o.json);
        assert_eq!(o.command, Command::Devices("IoT to br0".into()));
        assert_eq!(opts(&["--socket=/y.sock", "segments"]).socket, PathBuf::from("/y.sock"));

        // Options may come anywhere, before the command or after it, and
        // among the words of a segment's name.
        let o = opts(&["devices", "IoT", "-v", "to", "br0", "--json", "--socket", "/z.sock"]);
        assert!(o.verbose && o.json);
        assert_eq!((o.socket, o.command), (PathBuf::from("/z.sock"), Command::Devices("IoT to br0".into())));
        assert!(!opts(&["devices", "IoT"]).verbose);
        assert!(opts(&["-v", "devices", "IoT"]).verbose);
        assert!(opts(&["--verbose", "--json", "devices", "IoT"]).verbose);

        assert_eq!(opts(&["probe"]).command, Command::Probe(None));
        assert_eq!(opts(&["probe", "IoT", "to", "br0"]).command, Command::Probe(Some("IoT to br0".into())));
        assert_eq!(opts(&["timers"]).command, Command::Timers);
        assert_eq!(opts(&["watchers"]).command, Command::Watchers);
        assert_eq!(opts(&["watch", "IoT", "to", "br0"]).command, Command::Watch("IoT to br0".into()));
        for help in [&["--help"][..], &["segments", "-h"], &["devices", "--help"]] {
            assert!(matches!(parse(help), Err(Early::Help(_))), "{help:?}");
        }
        assert_eq!(parse(&["--version"]), Err(Early::Version));
        assert_eq!(parse(&["-v"]), Err(Early::NoCommand), "the help, as an error");
    }

    /// `--query` and `--interval` may come anywhere, with their value as the
    /// next word or after `=`; the other words are the segment's name. They
    /// go to the daemon ahead of it.
    #[test]
    fn devices_and_watch_take_a_query() {
        let o = opts(&["devices", "--query", "_shelly._tcp", "IoT", "--query=_hue._tcp", "to", "br0"]);
        let target = Target { segment: "IoT to br0".into(), query: vec!["_shelly._tcp".into(), "_hue._tcp".into()], interval: None, wait: None };
        assert_eq!(target.request("devices"), "devices --query=_shelly._tcp --query=_hue._tcp IoT to br0");
        assert_eq!(o.command, Command::Devices(target));

        let o = opts(&["watch", "--interval", "1min", "--query=_shelly._tcp", "IoT"]);
        let Command::Watch(target) = o.command else { panic!("{o:?}") };
        assert_eq!(target.interval, Some(Duration::from_secs(60)));
        assert_eq!(target.request("watch"), "watch --query=_shelly._tcp --interval=60 IoT");
        // Part of a second more is a second more: never asked more often than said.
        let Command::Watch(target) = opts(&["watch", "--interval=10.5s", "--query=_x._tcp", "IoT"]).command else { panic!() };
        assert_eq!(target.interval, Some(Duration::from_secs(11)));
        // devices takes no --interval: it waits, it does not ask again.
        assert!(parse(&["devices", "--query=_x._tcp", "--interval=1min", "IoT"]).is_err());
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
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    /// The man page must keep up with the commands, options and default path.
    #[test]
    fn man_page_covers_every_command_and_option() {
        let man = include_str!("../man/mdnsctl.1");
        for CommandInfo { name, .. } in COMMANDS {
            assert!(man.contains(&format!(".B {name}")) || man.contains(&format!("\\fB{name}\\fR")), "{name}");
        }
        for option in ["\\-\\-json", "\\-\\-segmented\\-json", "\\-\\-socket", "\\-\\-help", "\\-\\-verbose"] {
            assert!(man.contains(option), "{option}");
        }
        assert!(man.contains(DEFAULT_SOCKET));
    }

    #[test]
    fn usage_lists_every_command() {
        let text = help(None);
        for command in COMMANDS {
            assert!(text.contains(&format!("  {:<11}{}\n", command.name, command.about)), "{}: {text}", command.name);
        }
    }

    /// Each command's help lists what it takes, its own options and the
    /// others, in two columns; a long option alone lines up with those that
    /// have a short one.
    #[test]
    fn a_commands_help_lists_its_arguments_and_options() {
        let Err(Early::Help(text)) = parse(&["subscribe", "--help"]) else { panic!() };
        assert_eq!(
            text,
            "Run SCRIPT for each change in a segment, in the background\n\
             \n\
             Usage: mdnsctl subscribe [OPTIONS] <NAME>... -- <SCRIPT>...\n\
             \n\
             Arguments:\n\
             \x20 <NAME>...    The segment\n\
             \x20 <SCRIPT>...  The script to run for each change, and its arguments, after --\n\
             \n\
             Options:\n\
             \x20     --query <TYPE>     Ask for this service type by name, and run SCRIPT only for devices of it\n\
             \x20     --interval <SPAN>  Ask for the --query types again this often (at least 10s)\n\
             \x20     --foreground       Stay attached instead of going into the background\n\
             \x20     --log <FILE>       Append what the subscriber has to say, and SCRIPT's output, to FILE\n\
             \x20 -s, --socket <PATH>    The control socket [default: /run/mdnsd/mdnsd.sock]\n\
             \x20 -v, --verbose          List devices with all details (addresses, services)\n\
             \x20     --json             Print the daemon's reply unchanged\n\
             \x20     --segmented-json   With devices: print each device as a line of JSON of its own\n\
             \x20 -h, --help             Print help\n"
        );
        // A usage error says how to use the command it was about.
        let Err(Early::Usage { usage, .. }) = parse(&["devices"]) else { panic!() };
        assert_eq!(usage, "mdnsctl devices [OPTIONS] <NAME>...");
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
            "  br0   10.0.0.10  printer.local\n      Printer  _http._tcp.local  :631 -> printer.local  [rp=ipp, ty=hp]\n  wifi  10.0.1.7   -\nIoT to br0: 2 devices\n"
        );
        let empty: Value = serde_json::from_str(r#"{"ok":true,"name":"IoT","devices":[]}"#).unwrap();
        assert_eq!(render_devices(&empty).unwrap(), "IoT: no devices\n");
    }

    /// An address learned from the neighbour table is shown in parentheses,
    /// in the brief listing and with -v.
    #[test]
    fn listings_show_neighbour_addresses_in_parentheses() {
        let device: Value = serde_json::from_str(
            r#"{"interface":"media","hostname":"speakers.local","addresses":["10.0.2.73","fd00:0:2::73","fe80::9"],
                "neighbour_addresses":["fd00:0:2::73"],"address_ttl":120,"services":[]}"#,
        )
        .unwrap();
        assert_eq!(device_addrs(&device), "10.0.2.73, (fd00:0:2::73), fe80::9");
        assert_eq!(brief_row(&device).unwrap()[2], "10.0.2.73, (fd00:0:2::73), fe80::9");
        let reply = serde_json::json!({ "ok": true, "name": "media", "devices": [device] });
        assert_eq!(render_devices_brief(&reply).unwrap(), "  speakers.local  -  10.0.2.73, (fd00:0:2::73), fe80::9\nmedia: 1 device\n");
        // A daemon that does not say is no matter.
        let older: Value = serde_json::from_str(r#"{"addresses":["10.0.2.73"]}"#).unwrap();
        assert_eq!(device_addrs(&older), "10.0.2.73");
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
            format!("  a  fd00::5, fe80::5  h.local\n  a  fe80::9{}-\nx: 2 devices\n", " ".repeat(11))
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
            "  printer.local  Printer  10.0.0.10\nIoT to br0: 1 device\n(1 device without a name not shown; use -v to list everything)\n"
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
            "  OZAL-Speakers.local  OZAL Speakers    10.0.2.73, fe80::1\n  tv.local             Living Room. TV  10.0.2.9\nmedia: 2 devices\n"
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
            "  dual.local    -  10.0.0.5, 10.0.1.5, fd00::5, fe80::1\n  v6only.local  -  fe80::2\nx: 2 devices\n"
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
            "  A.local  -              1.1.1.2\n  b.local  Kitchen, Hall  1.1.1.1\nx: 2 devices\n"
        );

        // Only unnamed devices, none at all.
        let only_unnamed = reply(
            "x",
            &[entry("a", None, &["1.1.1.1"], ""), entry("a", None, &["fe80::1"], "")],
        );
        assert_eq!(
            brief(&only_unnamed),
            "x: no named devices\n(2 devices without a name not shown; use -v to list everything)\n"
        );
        assert_eq!(brief(r#"{"ok":true,"name":"x","devices":[]}"#), "x: no devices\n");
        // No address yet: a dash, as -v shows it, not trailing blanks.
        assert_eq!(
            brief(r#"{"ok":true,"name":"x","devices":[{"interface":"a","hostname":"h.local","addresses":[],"address_ttl":null,"services":[]}]}"#),
            "  h.local  -  -\nx: 1 device\n"
        );
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
            assert!(parse(args).is_err(), "{args:?}");
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
    /// `out`, then exits with `status`. It is put in place by `install`: a
    /// file this process had open for writing could be held open a moment by
    /// a child another test forks meanwhile, and could not be run ("Text file
    /// busy") until that child execs.
    fn script(tag: &str, status: u8) -> (PathBuf, PathBuf) {
        std::fs::create_dir_all("target").unwrap();
        let path = PathBuf::from(format!("target/mdnsctl-test-{}-{tag}.sh", std::process::id()));
        let draft = path.with_extension("draft");
        let out = PathBuf::from(format!("target/mdnsctl-test-{}-{tag}.out", std::process::id()));
        let _ = std::fs::remove_file(&out);
        std::fs::write(
            &draft,
            format!(
                "#!/bin/sh\n{{ cat; echo \"$1|$MDNS_EVENT|$MDNS_HOSTNAME|$MDNS_ADDRESS\"; }} >> {}\nexit {status}\n",
                out.display()
            ),
        )
        .unwrap();
        let installed = std::process::Command::new("install").arg("-m755").arg(&draft).arg(&path).status().unwrap();
        assert!(installed.success());
        (executable(path.to_str().unwrap()).unwrap(), out)
    }

    const EVENT: &str = r#"{"event":"added","segment":"IoT","ttl":4500,"device":{"interface":"wifi","hostname":"plug.local","addresses":["10.0.1.9"],"services":[]}}"#;

    /// A subscriber with no watch, running `script` with `args`.
    fn idle(script: PathBuf, args: &[&str]) -> Subscriber {
        let args = args.iter().map(|a| a.to_string()).collect();
        Subscriber { socket: PathBuf::new(), line: String::new(), script, args, watch: None, retry: None, queue: VecDeque::new(), running: None }
    }

    /// Turn `sub` as subscribe's loop does, until `done` says so.
    fn turn_until(sub: &mut Subscriber, done: impl Fn(&Subscriber) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(sub) {
            assert!(Instant::now() < deadline, "not done in time");
            let mut fds = sub.fds();
            let timeout = sub.deadline().map_or(STOP_CHECK, |at| at.saturating_duration_since(Instant::now()).min(STOP_CHECK));
            poll::wait(&mut fds, Some(timeout)).unwrap();
            sub.turn(&fds, Instant::now());
        }
    }

    /// Nothing running, and nothing waiting to.
    fn settled(sub: &Subscriber) -> bool {
        sub.running.is_none() && sub.queue.is_empty()
    }

    /// The events a test script has written out, as `|event|hostname|address`.
    fn ran(out: &Path) -> Vec<String> {
        std::fs::read_to_string(out).unwrap_or_default().lines().filter(|l| l.starts_with('|')).map(String::from).collect()
    }

    #[test]
    fn a_script_is_run_with_the_event_on_stdin_and_in_its_environment() {
        let (path, out) = script("run", 3);
        let mut sub = idle(path, &["arg"]);
        sub.queue.push_back(EVENT.into());
        turn_until(&mut sub, settled);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), format!("{EVENT}\narg|added|plug.local|10.0.1.9\n"));
    }

    #[test]
    fn a_script_running_when_told_to_stop_is_stopped() {
        let mut sub = idle(executable("sleep").unwrap(), &["30"]);
        sub.queue.push_back(EVENT.into());
        turn_until(&mut sub, |s| s.running.is_some());
        thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        sub.stop();
        assert!(sub.running.is_none());
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    }

    /// Events are run in the order they came, one at a time, a failing script
    /// holding up none.
    #[test]
    fn scripts_are_run_for_each_event_in_turn() {
        let (path, out) = script("turns", 1);
        let mut sub = idle(path, &[]);
        for host in ["a.local", "b.local", "c.local"] {
            sub.queue.push_back(EVENT.replace("plug.local", host));
        }
        turn_until(&mut sub, settled);
        assert_eq!(ran(&out), ["|added|a.local|10.0.1.9", "|added|b.local|10.0.1.9", "|added|c.local|10.0.1.9"]);
    }

    /// A script that does not read its input holds nothing up, and one past
    /// the queue's room is dropped.
    #[test]
    fn a_script_that_reads_nothing_holds_nothing_up() {
        let mut sub = idle(executable("true").unwrap(), &[]);
        let big = format!(r#"{{"event":"added","pad":"{}"}}"#, "x".repeat(1 << 20));
        sub.queue.push_back(big);
        turn_until(&mut sub, settled);
        for _ in 0..QUEUE {
            sub.take(EVENT).unwrap();
        }
        assert_eq!(sub.queue.len(), QUEUE);
        sub.take(EVENT).unwrap();
        assert_eq!(sub.queue.len(), QUEUE, "dropped");
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

        let (again, out) = script("again", 0);
        let reader = open_watch(&path, "watch --query=_x._tcp IoT").unwrap();
        let mut sub = Subscriber::new(&path, "watch --query=_x._tcp IoT", reader, again, Vec::new());
        turn_until(&mut sub, |s| settled(s) && ran(&out).len() == 2);
        assert_eq!(ran(&out), ["|added|first|10.0.1.9", "|added|second|10.0.1.9"]);
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
        let (whole, out) = script("whole", 0);
        let reader = open_watch(&path, "watch IoT").unwrap();
        daemon.join().unwrap();
        let mut sub = Subscriber::new(&path, "watch IoT", reader, whole, Vec::new());
        turn_until(&mut sub, |s| s.watch.is_none() && settled(s));
        assert_eq!(ran(&out), ["|added|plug.local|10.0.1.9"]);
        assert!(sub.retry.is_some(), "to watch again");

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
        let (cut, out) = script("cut", 0);
        let reader = open_watch(&path, "watch IoT").unwrap();
        daemon.join().unwrap();
        let mut sub = Subscriber::new(&path, "watch IoT", reader, cut, Vec::new());
        turn_until(&mut sub, |s| s.watch.is_none() && settled(s));
        assert_eq!(ran(&out), ["|added|plug.local|10.0.1.9"], "the cut-off second one is not passed on");
        let _ = std::fs::remove_file(&path);
    }

    /// A daemon that answers one request with `lines`, then keeps the
    /// connection open for `hold`, as a watch does, and tells what it was asked.
    fn holding_daemon(tag: &str, lines: Vec<String>, hold: Duration) -> (PathBuf, JoinHandle<String>) {
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
            thread::sleep(hold);
            asked
        });
        (path, handle)
    }

    fn found(kind: &str, host: Option<&str>, addrs: &[&str]) -> String {
        serde_json::json!({
            "event": kind, "segment": "IoT", "ttl": if kind == "removed" { 0 } else { 120 },
            "device": { "interface": "wifi", "hostname": host, "addresses": addrs, "address_ttl": 120,
                "services": [{ "instance": format!("{} plug._x._tcp.local", host.unwrap_or("A")), "type": "_x._tcp.local",
                    "port": 80, "target": host, "txt": [], "subtypes": [], "ttl": 120 }] },
        })
        .to_string()
    }

    /// What `devices --query` sees: one known, one without a name, one that
    /// answers and then says more, and the first going.
    fn query_stream() -> Vec<String> {
        vec![
            ACK.into(),
            found("present", Some("a.local"), &["10.0.1.1"]),
            found("added", None, &["10.0.1.2"]),
            found("added", Some("c.local"), &["10.0.1.3"]),
            found("updated", Some("c.local"), &["10.0.1.3", "fd00::3"]),
            found("removed", Some("a.local"), &["10.0.1.1"]),
        ]
    }

    fn query_options(path: &Path, json: bool, verbose: bool, wait: Duration) -> (Options, Target) {
        let target = Target { segment: "IoT".into(), query: vec!["_x._tcp".into()], wait: Some(wait), ..Target::default() };
        let opts = Options { socket: path.into(), json, segmented: false, verbose, command: Command::Segments };
        (opts, target)
    }

    /// `devices --query` is a watch for the type, taken for `--wait`: each
    /// device printed as `devices` lists it, as soon as it is found, then the
    /// summary `devices` ends with, of what is left at the end.
    #[test]
    fn devices_with_a_query_print_what_is_found_as_it_comes() {
        let wait = Duration::from_millis(300);
        let (path, daemon) = holding_daemon("query-text", query_stream(), wait * 3);
        let (opts, target) = query_options(&path, false, false, wait);
        let started = Instant::now();
        let mut out = Vec::new();
        devices_query(&opts, &target, &mut out).unwrap();
        assert!(started.elapsed() >= wait && started.elapsed() < wait * 3, "{:?}", started.elapsed());
        assert_eq!(daemon.join().unwrap(), "watch --query=_x._tcp IoT\n", "a watch for the type, nothing else");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "  a.local  a.local plug  10.0.1.1\n  c.local  c.local plug  10.0.1.3\n\
             IoT: 1 device\n(1 device without a name not shown; use -v to list everything)\n",
            "each as it is first found, then what is left"
        );

        // And with -v, as `devices -v`, the unnamed one too.
        let (path, _daemon) = holding_daemon("query-verbose", query_stream(), wait * 3);
        let (opts, target) = query_options(&path, false, true, wait);
        let mut out = Vec::new();
        devices_query(&opts, &target, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.ends_with("IoT: 2 devices\n"), "{text}");
        assert!(text.contains("c.local  addr-ttl=120") && text.contains("10.0.1.2"), "{text}");
    }

    /// With `--json`, one reply at the end, as `devices` gives it: each
    /// device as last heard of, and none that went.
    #[test]
    fn devices_with_a_query_and_json_print_one_reply_at_the_end() {
        let wait = Duration::from_millis(300);
        let (path, _daemon) = holding_daemon("query-json", query_stream(), wait * 3);
        let (opts, target) = query_options(&path, true, false, wait);
        let mut out = Vec::new();
        devices_query(&opts, &target, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        let reply: Value = serde_json::from_str(&text).unwrap();
        assert_eq!((&reply["ok"], &reply["name"]), (&Value::Bool(true), &Value::from("IoT")));
        let devices = reply["devices"].as_array().unwrap();
        let hosts: Vec<&Value> = devices.iter().map(|d| &d["hostname"]).collect();
        assert_eq!(hosts, [&Value::from("c.local"), &Value::Null], "{devices:?}");
        assert_eq!(devices[0]["addresses"], serde_json::json!(["10.0.1.3", "fd00::3"]), "as last heard of");
    }

    #[test]
    fn devices_with_a_query_report_a_refusal_or_a_daemon_that_goes() {
        let (path, _daemon) = holding_daemon("query-refused", vec![r#"{"ok":false,"error":"no such segment: IoT"}"#.into()], Duration::ZERO);
        let (opts, target) = query_options(&path, false, false, Duration::from_secs(5));
        assert_eq!(devices_query(&opts, &target, &mut Vec::new()), Err(Failure::Server("no such segment: IoT".into())));

        let (path, _daemon) = holding_daemon("query-gone", vec![ACK.into()], Duration::ZERO);
        let (opts, target) = query_options(&path, false, false, Duration::from_secs(5));
        assert!(matches!(devices_query(&opts, &target, &mut Vec::new()), Err(Failure::Connect(_))));
    }

    #[test]
    fn segmented_json_is_for_devices_alone() {
        let o = opts(&["--segmented-json", "devices", "IoT"]);
        assert!(o.segmented && !o.json);
        assert!(opts(&["--segmented-json", "devices", "--query=_x._tcp", "IoT"]).segmented);
        for args in [&["--segmented-json", "segments"][..], &["--segmented-json", "watch", "IoT"], &["--json", "--segmented-json", "devices", "IoT"]] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    /// With `--segmented-json`, `devices` prints each device as a line of its
    /// own, as the daemon has it, and nothing else.
    #[test]
    fn devices_print_a_line_of_json_per_device() {
        let (path, _daemon) = fake_daemon("segmented", DEVICES);
        let opts = Options { socket: path, json: false, segmented: true, verbose: false, command: Command::Devices("IoT to br0".into()) };
        let out = execute(&opts).unwrap();
        let reply: Value = serde_json::from_str(DEVICES).unwrap();
        let lines: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(&lines, reply["devices"].as_array().unwrap());
    }

    /// With `--segmented-json`, `devices --query` prints each device as a line
    /// of its own the moment it is found, unnamed ones too, and nothing at
    /// the end.
    #[test]
    fn devices_with_a_query_print_a_line_of_json_per_device_as_found() {
        let wait = Duration::from_millis(300);
        let (path, _daemon) = holding_daemon("query-segmented", query_stream(), wait * 3);
        let (mut opts, target) = query_options(&path, false, false, wait);
        opts.segmented = true;
        let mut out = Vec::new();
        devices_query(&opts, &target, &mut out).unwrap();
        let lines: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let hosts: Vec<&Value> = lines.iter().map(|d| &d["hostname"]).collect();
        assert_eq!(hosts, [&Value::from("a.local"), &Value::Null, &Value::from("c.local")], "each once, as found");
        assert_eq!(lines[2]["addresses"], serde_json::json!(["10.0.1.3"]), "as first found");
        assert!(lines.iter().all(|d| d["interface"] == "wifi"));
    }

    #[test]
    fn devices_take_how_long_to_wait_for_answers() {
        let Command::Devices(t) = opts(&["devices", "--query", "_x._tcp", "--wait", "1.5s", "IoT"]).command else { panic!() };
        assert_eq!((t.wait, t.segment.as_str()), (Some(Duration::from_millis(1500)), "IoT"));
        assert_eq!(t.request("watch"), "watch --query=_x._tcp IoT", "the wait is mdnsctl's own");
        let Command::Devices(t) = opts(&["devices", "--query=_x._tcp", "IoT"]).command else { panic!() };
        assert_eq!(t.wait, None, "the default");
        for args in [&["devices", "--wait=2s", "IoT"][..], &["devices", "--query=_x._tcp", "--wait=0", "IoT"], &["devices", "--query=_x._tcp", "--wait=soon", "IoT"]] {
            assert!(parse(args).is_err(), "{args:?}");
        }
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
        Options { socket: path.into(), json, segmented: false, verbose: false, command: Command::Watch("IoT".into()) }
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
            "  wifi  10.0.1.9  plug.local  addr-ttl=120\n      Plug S  _shelly._tcp.local  :80 -> plug.local  ttl=4500  [gen=2]\n      Plug S  _http._tcp.local  :80 -> plug.local\nIoT: 1 device\n"
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
        execute(&Options { socket: path.into(), json, segmented: false, verbose: false, command })
    }

    fn run_verbose(path: &Path, command: Command) -> Result<String, Failure> {
        execute(&Options { socket: path.into(), json: false, segmented: false, verbose: true, command })
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
        assert!(out.ends_with("IoT to br0: 1 device\n(1 device without a name not shown; use -v to list everything)\n"), "brief by default: {out}");

        let (path, daemon) = fake_daemon("devices-v", DEVICES);
        let out = run_verbose(&path, Command::Devices("IoT to br0".into())).unwrap();
        daemon.join().unwrap();
        assert!(out.ends_with("IoT to br0: 2 devices\n") && out.contains("10.0.1.7"), "verbose: {out}");
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
