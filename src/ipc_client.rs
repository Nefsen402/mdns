//! `mdnsctl`: command line client for the daemon's control socket (see
//! `ipc.rs` for the protocol). Every IPC command has a subcommand here.

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde_json::Value;

/// Keep in sync with `config::DEFAULT_SOCKET` in the daemon.
const DEFAULT_SOCKET: &str = "/run/mdnsd/mdnsd.sock";

const TIMEOUT: Duration = Duration::from_secs(5);

/// A probe takes the daemon about four seconds to run before it replies.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// (command, arguments, description): the whole IPC surface.
const COMMANDS: &[(&str, &str, &str)] = &[
    ("segments", "", "list the configured segments"),
    ("devices", "<name>", "list the devices discovered in a segment"),
    ("probe", "[<name>]", "actively query for devices (all segments, or one)"),
    ("watch", "<name>", "print the devices of a segment as they appear and go"),
    ("timers", "", "list the timers the daemon has scheduled"),
];

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Segments,
    Devices(String),
    Probe(Option<String>),
    Watch(String),
    Timers,
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
        out.push_str(&format!("  {:<18}{about}\n", format!("{name} {args}").trim_end()));
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
        "devices" => {
            // Names may contain spaces, so `devices IoT to br0` needs no quoting.
            let segment = rest.join(" ");
            if segment.trim().is_empty() {
                return Err(Failure::Usage("devices needs a segment name".into()));
            }
            // The protocol is one request per line.
            if segment.contains(['\n', '\r']) {
                return Err(Failure::Usage("segment name contains a line break".into()));
            }
            Command::Devices(segment)
        }
        "probe" => {
            let segment = rest.join(" ");
            if segment.contains(['\n', '\r']) {
                return Err(Failure::Usage("segment name contains a line break".into()));
            }
            Command::Probe((!segment.trim().is_empty()).then_some(segment))
        }
        "watch" => {
            let segment = rest.join(" ");
            if segment.trim().is_empty() {
                return Err(Failure::Usage("watch needs a segment name".into()));
            }
            if segment.contains(['\n', '\r']) {
                return Err(Failure::Usage("segment name contains a line break".into()));
            }
            Command::Watch(segment)
        }
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
fn watch(opts: &Options, name: &str, out: &mut impl Write) -> Result<(), Failure> {
    let socket = &opts.socket;
    let mut reader = BufReader::new(send(socket, &format!("watch {name}"), TIMEOUT)?);
    let mut line = String::new();
    let mut seen = HashSet::new();
    let mut acknowledged = false;
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
        if !acknowledged {
            // Now it waits for changes, however long that takes.
            reader.get_ref().set_read_timeout(None).map_err(|e| connect_err(socket, e))?;
            acknowledged = true;
            continue;
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

/// Run a command and return the text to print.
fn execute(opts: &Options) -> Result<String, Failure> {
    let (line, timeout) = match &opts.command {
        Command::Segments => ("segments".to_string(), TIMEOUT),
        Command::Devices(name) => (format!("devices {name}"), TIMEOUT),
        Command::Probe(None) => ("probe".to_string(), PROBE_TIMEOUT),
        Command::Probe(Some(name)) => (format!("probe {name}"), PROBE_TIMEOUT),
        Command::Timers => ("timers".to_string(), TIMEOUT),
        Command::Watch(_) => unreachable!("watch streams: see watch()"),
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
        Command::Timers => render_timers(&reply),
        Command::Watch(_) => unreachable!("watch streams: see watch()"),
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
    let mut rows = vec![vec!["INTERFACE".to_string(), "FAMILY".into(), "RESULT".into()]];
    for link in list {
        let result = match link["error"].as_str() {
            Some(error) => format!("error: {error}"),
            None => format!("{} queries sent", link["queries"]),
        };
        rows.push(vec![
            link["interface"].as_str().ok_or_else(bad_reply)?.to_string(),
            link["family"].as_str().ok_or_else(bad_reply)?.to_string(),
            result,
        ]);
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

/// One line per named device: its DNS name, its pretty name (the service
/// instance name, such as "OZAL Speakers") and, last, all of its addresses,
/// IPv4 before IPv6. The IPv4 and IPv6 entries of a device are merged. Devices
/// that have not announced a hostname have no DNS name to show, so they are
/// only counted.
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
        for (link_local, field) in [(false, "routable"), (true, "link_local")] {
            if let Some(addr) = device[field].as_str() {
                let item = (link_local, addr.contains(':'), addr.to_string());
                if !entry.addrs.contains(&item) {
                    entry.addrs.push(item);
                }
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

/// A device's addresses, the routable one first; `-` if it has none.
fn device_addrs(device: &Value) -> String {
    let addrs: Vec<&str> = ["routable", "link_local"].iter().filter_map(|f| device[*f].as_str()).collect();
    if addrs.is_empty() { "-".to_string() } else { addrs.join(", ") }
}

fn render_devices(reply: &Value) -> Result<String, Failure> {
    let name = reply["name"].as_str().ok_or_else(bad_reply)?;
    let devices = reply["devices"].as_array().ok_or_else(bad_reply)?;
    if devices.is_empty() {
        return Ok(format!("{name}: no devices\n"));
    }

    let rows = devices.iter().map(device_row).collect::<Result<Vec<_>, Failure>>()?;
    let widths: Vec<usize> = (0..3).map(|c| rows.iter().map(|r| r[c].len()).max().unwrap_or(0)).collect();

    let plural = if devices.len() == 1 { "" } else { "s" };
    let mut out = format!("{name}: {} device{plural}\n", devices.len());
    for (device, row) in devices.iter().zip(&rows) {
        out.push_str(&format!(
            "  {:<w0$}  {:<w1$}  {:<w2$}  {}\n",
            row[0],
            row[1],
            row[2],
            row[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2]
        ));
        out.push_str(&service_lines(device));
    }
    Ok(out)
}

/// The columns of a device in the verbose listing: interface, family,
/// addresses, hostname.
fn device_row(device: &Value) -> Result<[String; 4], Failure> {
    // The hostname is the last column, so the TTL of its address records can
    // follow it.
    let mut hostname = device["hostname"].as_str().unwrap_or("-").to_string();
    if let Some(ttl) = device["address_ttl"].as_u64() {
        hostname.push_str(&format!("  addr-ttl={ttl}"));
    }
    Ok([
        device["interface"].as_str().ok_or_else(bad_reply)?.to_string(),
        device["family"].as_str().ok_or_else(bad_reply)?.to_string(),
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

    let key = device["hostname"].as_str().map(|h| (h.to_ascii_lowercase(), row[1].clone()));
    let label = match (kind, &key) {
        ("removed", Some(key)) => {
            seen.remove(key);
            "removed"
        }
        ("removed", None) => "removed",
        ("added" | "updated", Some(key)) if seen.insert(key.clone()) => "added",
        ("added" | "updated", Some(_)) => "updated",
        // Nothing to track it by: say what the daemon said.
        ("added", None) => "added",
        ("updated", None) => "updated",
        _ => return Err(bad_reply()),
    };
    let ttl = format!("{:<9}", format!("ttl={ttl}"));

    if verbose {
        let mut out = format!("{label:<7}  {ttl}  {}  {}  {}  {}\n", row[0], row[1], row[2], row[3]);
        out.push_str(&service_lines(device));
        return Ok(Some(out));
    }
    let Some(host) = device["hostname"].as_str() else {
        return Ok(None);
    };
    let pretty = pretty_names(device);
    let pretty = if pretty.is_empty() { "-".to_string() } else { pretty.join(", ") };
    Ok(Some(format!("{label:<7}  {ttl}  {host}  {pretty}  {}\n", row[2])))
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
        Command::Watch(name) => watch(&opts, name, &mut io::stdout().lock()),
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
        assert_eq!(opts(&["watch", "IoT", "to", "br0"]).command, Command::Watch("IoT to br0".into()));
        assert_eq!(parse(&["--help"]), Ok(Parsed::Help));
        assert_eq!(parse(&["segments", "-h"]), Err(Failure::Usage("segments takes no arguments".into())));
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
            &["watch"],
            &["watch", "  "],
            &["watch", "a\nsegments"],
            &["--bogus", "segments"],
            &["-s"],
            &["devices", "a\nsegments"],
            &["probe", "a\nsegments"],
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
    const DEVICES: &str = r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"br0","family":"v4","hostname":"printer.local","routable":"10.0.0.10","link_local":null,"services":[{"instance":"Printer._http._tcp.local","type":"_http._tcp.local","port":631,"target":"printer.local","txt":["rp=ipp","ty=hp"]}]},{"interface":"wifi","family":"v4","hostname":null,"routable":"10.0.1.7","link_local":null,"services":[]}]}"#;

    /// A device entry as the daemon sends it.
    fn entry(interface: &str, family: &str, host: Option<&str>, routable: Option<&str>, link_local: Option<&str>, services: &str) -> String {
        let q = |v: Option<&str>| v.map_or("null".to_string(), |v| format!("\"{v}\""));
        format!(
            r#"{{"interface":"{interface}","family":"{family}","hostname":{},"routable":{},"link_local":{},"services":[{services}]}}"#,
            q(host),
            q(routable),
            q(link_local)
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
            "IoT to br0: 2 devices\n  br0   v4  10.0.0.10  printer.local\n      Printer  _http._tcp.local  :631 -> printer.local  [rp=ipp, ty=hp]\n  wifi  v4  10.0.1.7   -\n"
        );
        let empty: Value = serde_json::from_str(r#"{"ok":true,"name":"IoT","devices":[]}"#).unwrap();
        assert_eq!(render_devices(&empty).unwrap(), "IoT: no devices\n");
    }

    #[test]
    fn verbose_listing_shows_both_addresses() {
        let json = reply(
            "x",
            &[
                entry("a", "v6", Some("h.local"), Some("fd00::5"), Some("fe80::5"), ""),
                entry("a", "v6", None, None, Some("fe80::9"), ""),
            ],
        );
        let out = render_devices(&serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(
            out,
            format!("x: 2 devices\n  a  v6  fd00::5, fe80::5  h.local\n  a  v6  fe80::9{}-\n", " ".repeat(11))
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
    fn brief_listing_merges_families_and_cleans_names() {
        // A speaker seen over v4 and v6, with an AirPlay-style "<MAC>@Name" instance.
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
                entry("media", "v4", Some("OZAL-Speakers.local"), Some("10.0.2.73"), None, &services),
                entry("media", "v6", Some("OZAL-Speakers.local"), None, Some("fe80::1"), &services),
                entry(
                    "media",
                    "v4",
                    Some("tv.local"),
                    Some("10.0.2.9"),
                    None,
                    &svc(r"Living Room\\. TV._http._tcp.local", "_http._tcp.local"),
                ),
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
                entry("a", "v6", Some("dual.local"), Some("fd00::5"), Some("fe80::1"), ""),
                entry("a", "v4", Some("dual.local"), Some("10.0.0.5"), None, ""),
                entry("b", "v4", Some("dual.local"), Some("10.0.1.5"), None, ""),
                entry("a", "v6", Some("v6only.local"), None, Some("fe80::2"), ""),
                entry("b", "v6", Some("v6only.local"), None, Some("fe80::2"), ""),
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
                entry("a", "v4", Some("b.local"), Some("1.1.1.1"), None, two),
                entry("a", "v4", Some("A.local"), Some("1.1.1.2"), None, ""),
            ],
        );
        assert_eq!(
            brief(&json),
            "x: 2 devices\n  A.local  -              1.1.1.2\n  b.local  Kitchen, Hall  1.1.1.1\n"
        );

        // Only unnamed devices, none at all.
        let only_unnamed = reply(
            "x",
            &[entry("a", "v4", None, Some("1.1.1.1"), None, ""), entry("a", "v6", None, None, Some("fe80::1"), "")],
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
            r#"{"ok":true,"probed":[{"interface":"br0","family":"v4","queries":14,"error":null},{"interface":"wifi","family":"v6","queries":null,"error":"sending to ff02::fb: Network is unreachable"}]}"#,
        )
        .unwrap();
        assert_eq!(
            render_probe(&reply).unwrap(),
            "INTERFACE  FAMILY  RESULT\nbr0        v4      14 queries sent\nwifi       v6      error: sending to ff02::fb: Network is unreachable\n\nList what answered with: mdnsctl devices <name>\n"
        );
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

    fn event(kind: &str, ttl: u64, host: Option<&str>, family: &str, addr: &str, services: &str) -> Value {
        serde_json::from_str(&format!(
            r#"{{"event":"{kind}","segment":"IoT","ttl":{ttl},"device":{{"interface":"wifi","family":"{family}","hostname":{},"routable":"{addr}","link_local":null,"services":{services}}}}}"#,
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
        assert_eq!(show(event("added", 300, None, "v4", "10.0.1.9", "[]"), false), None);
        // The first named sighting is "added", whatever the daemon called it.
        assert_eq!(
            show(event("updated", 4500, Some("plug.local"), "v4", "10.0.1.9", PLUG), false).as_deref(),
            Some("added    ttl=4500   plug.local  Plug S  10.0.1.9\n")
        );
        assert_eq!(
            show(event("updated", 4400, Some("plug.local"), "v4", "10.0.1.9", PLUG), false).as_deref(),
            Some("updated  ttl=4400   plug.local  Plug S  10.0.1.9\n")
        );
        // Its IPv6 side is a device of its own.
        assert!(show(event("added", 300, Some("plug.local"), "v6", "fd00::9", "[]"), false).unwrap().starts_with("added  "));
        // Gone: ttl 0, and a later return is "added" again.
        assert_eq!(
            show(event("removed", 0, Some("plug.local"), "v4", "10.0.1.9", PLUG), false).as_deref(),
            Some("removed  ttl=0      plug.local  Plug S  10.0.1.9\n")
        );
        assert!(show(event("added", 300, Some("plug.local"), "v4", "10.0.1.9", PLUG), false).unwrap().starts_with("added  "));
    }

    #[test]
    fn verbose_watch_lines_are_a_device_with_its_services() {
        let mut seen = HashSet::new();
        let shown = render_event(&event("added", 4500, Some("plug.local"), "v4", "10.0.1.9", PLUG), true, &mut seen)
            .unwrap()
            .unwrap();
        assert_eq!(
            shown,
            "added    ttl=4500   wifi  v4  10.0.1.9  plug.local\n      Plug S  _shelly._tcp.local  :80 -> plug.local  [gen=2]\n"
        );
        // Verbose shows devices that have no name too.
        let unnamed = render_event(&event("added", 300, None, "v4", "10.0.1.9", "[]"), true, &mut seen).unwrap().unwrap();
        assert_eq!(unnamed, "added    ttl=300    wifi  v4  10.0.1.9  -\n");
    }

    #[test]
    fn a_malformed_event_is_an_error() {
        let mut seen = HashSet::new();
        assert!(render_event(&serde_json::json!({"event":"added"}), false, &mut seen).is_err());
        let mut odd = event("exploded", 1, Some("x.local"), "v4", "10.0.0.1", "[]");
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
        let added = event("added", 4500, Some("plug.local"), "v4", "10.0.1.9", PLUG).to_string();
        let removed = event("removed", 0, Some("plug.local"), "v4", "10.0.1.9", PLUG).to_string();
        let (path, daemon) = streaming_daemon("watch", vec![ACK.into(), added.clone(), removed.clone()]);

        let mut out = Vec::new();
        let result = watch(&watch_options(&path, false), "IoT", &mut out);
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
        let added = event("added", 4500, Some("plug.local"), "v4", "10.0.1.9", PLUG).to_string();
        let (path, daemon) = streaming_daemon("watch-json", vec![ACK.into(), added.clone()]);
        let mut out = Vec::new();
        let _ = watch(&watch_options(&path, true), "IoT", &mut out);
        daemon.join().unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("{added}\n"));
    }

    #[test]
    fn watch_reports_refusals_and_failures_mid_stream() {
        let (path, daemon) = streaming_daemon("watch-refused", vec![r#"{"ok":false,"error":"no such segment: IoT"}"#.into()]);
        assert_eq!(
            watch(&watch_options(&path, false), "IoT", &mut Vec::new()),
            Err(Failure::Server("no such segment: IoT".into()))
        );
        daemon.join().unwrap();

        let (path, daemon) = streaming_daemon("watch-stopped", vec![ACK.into(), r#"{"ok":false,"error":"shutting down"}"#.into()]);
        assert_eq!(
            watch(&watch_options(&path, false), "IoT", &mut Vec::new()),
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
        let added = event("added", 4500, Some("plug.local"), "v4", "10.0.1.9", PLUG).to_string();
        let (path, daemon) = streaming_daemon("watch-closed", vec![ACK.into(), added]);
        assert_eq!(watch(&watch_options(&path, false), "IoT", &mut Closed), Ok(()));
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
        let device = r#"{"interface":"wifi","family":"v4","hostname":"plug.local","routable":"10.0.1.9","link_local":null,"address_ttl":120,"services":[{"instance":"Plug S._shelly._tcp.local","type":"_shelly._tcp.local","port":80,"target":"plug.local","txt":["gen=2"],"ttl":4500},{"instance":"Plug S._http._tcp.local","type":"_http._tcp.local","port":80,"target":"plug.local","txt":[],"ttl":null}]}"#;
        let reply: Value = serde_json::from_str(&format!(r#"{{"ok":true,"name":"IoT","devices":[{device}]}}"#)).unwrap();
        assert_eq!(
            render_devices(&reply).unwrap(),
            "IoT: 1 device\n  wifi  v4  10.0.1.9  plug.local  addr-ttl=120\n      Plug S  _shelly._tcp.local  :80 -> plug.local  ttl=4500  [gen=2]\n      Plug S  _http._tcp.local  :80 -> plug.local\n"
        );
        // A watch shows them too, after its own ttl: how long the daemon keeps the device.
        let event: Value = serde_json::from_str(&format!(r#"{{"event":"added","segment":"IoT","ttl":300,"device":{device}}}"#)).unwrap();
        let shown = render_event(&event, true, &mut HashSet::new()).unwrap().unwrap();
        assert!(shown.starts_with("added    ttl=300    wifi  v4  10.0.1.9  plug.local  addr-ttl=120\n"), "{shown}");
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
        const REPLY: &str = r#"{"ok":true,"probed":[{"interface":"br0","family":"v4","queries":3,"error":null}]}"#;
        let (path, daemon) = fake_daemon("probe-all", REPLY);
        let out = run(&path, false, Command::Probe(None)).unwrap();
        assert_eq!(daemon.join().unwrap(), "probe\n");
        assert!(out.contains("br0        v4      3 queries sent"), "{out}");

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
