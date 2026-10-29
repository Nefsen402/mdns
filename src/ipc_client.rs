//! `mdnsctl`: command line client for the daemon's control socket (see
//! `ipc.rs` for the protocol). Every IPC command has a subcommand here.

use std::io::{BufRead, BufReader, Write};
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
];

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Segments,
    Devices(String),
    Probe(Option<String>),
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
        other => return Err(Failure::Usage(format!("unknown command {other:?}"))),
    };
    Ok(Parsed::Run(Options { socket, json, verbose, command }))
}

/// Send one request line and return the one-line reply.
fn request(socket: &Path, line: &str, timeout: Duration) -> Result<String, Failure> {
    let connect_err = |e: std::io::Error| {
        Failure::Connect(format!(
            "cannot talk to {}: {e} (is the daemon running, and can you access the socket?)",
            socket.display()
        ))
    };
    let mut stream = UnixStream::connect(socket).map_err(connect_err)?;
    stream.set_read_timeout(Some(timeout)).map_err(connect_err)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(connect_err)?;
    writeln!(stream, "{line}").map_err(connect_err)?;

    let mut reply = String::new();
    let n = BufReader::new(stream).read_line(&mut reply).map_err(connect_err)?;
    if n == 0 {
        return Err(Failure::Connect("the daemon closed the connection without replying".into()));
    }
    Ok(reply.trim_end().to_string())
}

/// Run a command and return the text to print.
fn execute(opts: &Options) -> Result<String, Failure> {
    let (line, timeout) = match &opts.command {
        Command::Segments => ("segments".to_string(), TIMEOUT),
        Command::Devices(name) => (format!("devices {name}"), TIMEOUT),
        Command::Probe(None) => ("probe".to_string(), PROBE_TIMEOUT),
        Command::Probe(Some(name)) => (format!("probe {name}"), PROBE_TIMEOUT),
    };
    let raw = request(&opts.socket, &line, timeout)?;
    let reply: Value =
        serde_json::from_str(&raw).map_err(|e| Failure::Server(format!("unreadable reply: {e}")))?;

    if reply["ok"] != Value::Bool(true) {
        let message = reply["error"].as_str().unwrap_or("request failed");
        return Err(Failure::Server(message.to_string()));
    }
    if opts.json {
        return Ok(format!("{raw}\n"));
    }
    match opts.command {
        Command::Segments => render_segments(&reply),
        Command::Devices(_) if opts.verbose => render_devices(&reply),
        Command::Devices(_) => render_devices_brief(&reply),
        Command::Probe(_) => render_probe(&reply),
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
        rows.push(vec![
            seg["name"].as_str().ok_or_else(bad_reply)?.to_string(),
            strings(&seg["interfaces"]).join(", "),
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

/// One line per named device: its DNS name and its pretty name (the service
/// instance name, such as "OZAL Speakers"). The IPv4 and IPv6 entries of a
/// device are merged. Devices that have not announced a hostname have no DNS
/// name to show, so they are only counted.
fn render_devices_brief(reply: &Value) -> Result<String, Failure> {
    let name = reply["name"].as_str().ok_or_else(bad_reply)?;
    let devices = reply["devices"].as_array().ok_or_else(bad_reply)?;
    if devices.is_empty() {
        return Ok(format!("{name}: no devices\n"));
    }

    let mut named: Vec<(String, Vec<String>)> = Vec::new();
    let mut unnamed = 0;
    for device in devices {
        let Some(host) = device["hostname"].as_str() else {
            unnamed += 1;
            continue;
        };
        let pretty = pretty_names(device);
        match named.iter_mut().find(|(h, _)| h.eq_ignore_ascii_case(host)) {
            Some((_, names)) => {
                for p in pretty {
                    if !names.contains(&p) {
                        names.push(p);
                    }
                }
            }
            None => named.push((host.to_string(), pretty)),
        }
    }
    named.sort_by_key(|(host, _)| host.to_ascii_lowercase());

    let mut out = match named.len() {
        0 => format!("{name}: no named devices\n"),
        1 => format!("{name}: 1 device\n"),
        n => format!("{name}: {n} devices\n"),
    };
    let width = named.iter().map(|(host, _)| host.len()).max().unwrap_or(0);
    for (host, names) in &named {
        let pretty = if names.is_empty() { "-".to_string() } else { names.join(", ") };
        out.push_str(&format!("  {host:<width$}  {pretty}\n"));
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

fn render_devices(reply: &Value) -> Result<String, Failure> {
    let name = reply["name"].as_str().ok_or_else(bad_reply)?;
    let devices = reply["devices"].as_array().ok_or_else(bad_reply)?;
    if devices.is_empty() {
        return Ok(format!("{name}: no devices\n"));
    }

    let rows = devices
        .iter()
        .map(|d| {
            Ok(vec![
                d["interface"].as_str().ok_or_else(bad_reply)?.to_string(),
                d["family"].as_str().ok_or_else(bad_reply)?.to_string(),
                d["addr"].as_str().ok_or_else(bad_reply)?.to_string(),
                d["hostname"].as_str().unwrap_or("-").to_string(),
            ])
        })
        .collect::<Result<Vec<_>, Failure>>()?;
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
        for svc in device["services"].as_array().into_iter().flatten() {
            let kind = svc["type"].as_str().unwrap_or("");
            let instance = svc["instance"].as_str().unwrap_or("");
            let label = instance.strip_suffix(&format!(".{kind}")).unwrap_or(instance);
            out.push_str(&format!("      {label}  {kind}  :{}", svc["port"]));
            if let Some(target) = svc["target"].as_str() {
                out.push_str(&format!(" -> {target}"));
            }
            let txt = strings(&svc["txt"]);
            if !txt.is_empty() {
                out.push_str(&format!("  [{}]", txt.join(", ")));
            }
            out.push('\n');
        }
    }
    Ok(out)
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
        out.push_str(&cells.join("  "));
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

    match execute(&opts) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
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
    const DEVICES: &str = r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"br0","family":"v4","addr":"10.0.0.10","hostname":"printer.local","services":[{"instance":"Printer._http._tcp.local","type":"_http._tcp.local","port":631,"target":"printer.local","txt":["rp=ipp","ty=hp"]}]},{"interface":"wifi","family":"v4","addr":"10.0.1.7","hostname":null,"services":[]}]}"#;

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

    fn brief(json: &str) -> String {
        render_devices_brief(&serde_json::from_str(json).unwrap()).unwrap()
    }

    #[test]
    fn brief_listing_shows_dns_name_and_pretty_name() {
        let reply: Value = serde_json::from_str(DEVICES).unwrap();
        assert_eq!(
            render_devices_brief(&reply).unwrap(),
            "IoT to br0: 1 device\n  printer.local  Printer\n\n(1 device without a name not shown; use -v to list everything)\n"
        );
    }

    #[test]
    fn brief_listing_merges_families_and_cleans_names() {
        // A speaker seen over v4 and v6, with an AirPlay-style "<MAC>@Name" instance.
        let svc = |instance: &str, kind: &str| {
            format!(r#"{{"instance":"{instance}","type":"{kind}","port":7000,"target":"x.local","txt":[]}}"#)
        };
        let device = |family: &str, addr: &str| {
            format!(
                r#"{{"interface":"media","family":"{family}","addr":"{addr}","hostname":"OZAL-Speakers.local","services":[{},{}]}}"#,
                svc("04098643E3F7@OZAL Speakers._raop._tcp.local", "_raop._tcp.local"),
                svc("OZAL Speakers._airplay._tcp.local", "_airplay._tcp.local"),
            )
        };
        let other = format!(
            r#"{{"interface":"media","family":"v4","addr":"10.0.2.9","hostname":"tv.local","services":[{}]}}"#,
            svc(r"Living Room\\. TV._http._tcp.local", "_http._tcp.local")
        );
        let json = format!(
            r#"{{"ok":true,"name":"media","devices":[{},{},{other}]}}"#,
            device("v4", "10.0.2.73"),
            device("v6", "fe80::1")
        );
        assert_eq!(
            brief(&json),
            "media: 2 devices\n  OZAL-Speakers.local  OZAL Speakers\n  tv.local             Living Room. TV\n"
        );
    }

    #[test]
    fn brief_listing_edge_cases() {
        // Several distinct names are all shown; no services shows a dash.
        let json = r#"{"ok":true,"name":"x","devices":[
            {"interface":"a","family":"v4","addr":"1.1.1.1","hostname":"b.local","services":[
                {"instance":"Kitchen._a._tcp.local","type":"_a._tcp.local","port":1,"target":null,"txt":[]},
                {"instance":"Hall._b._tcp.local","type":"_b._tcp.local","port":2,"target":null,"txt":[]}]},
            {"interface":"a","family":"v4","addr":"1.1.1.2","hostname":"A.local","services":[]}]}"#;
        assert_eq!(brief(json), "x: 2 devices\n  A.local  -\n  b.local  Kitchen, Hall\n");

        // Only unnamed devices, none at all.
        let only_unnamed = r#"{"ok":true,"name":"x","devices":[
            {"interface":"a","family":"v4","addr":"1.1.1.1","hostname":null,"services":[]},
            {"interface":"a","family":"v6","addr":"fe80::1","hostname":null,"services":[]}]}"#;
        assert_eq!(
            brief(only_unnamed),
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
