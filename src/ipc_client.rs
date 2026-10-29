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

/// (command, arguments, description): the whole IPC surface.
const COMMANDS: &[(&str, &str, &str)] = &[
    ("segments", "", "list the configured segments"),
    ("devices", "<name>", "list the devices discovered in a segment"),
];

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Segments,
    Devices(String),
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    socket: PathBuf,
    json: bool,
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
    let mut out = String::from("usage: mdnsctl [-s PATH] [--json] <command>\n\ncommands:\n");
    for (name, args, about) in COMMANDS {
        out.push_str(&format!("  {:<18}{about}\n", format!("{name} {args}").trim_end()));
    }
    out.push_str(&format!(
        "\noptions:\n  -s, --socket PATH  control socket (default {DEFAULT_SOCKET})\n      --json         print the daemon's reply unchanged\n  -h, --help         show this help\n"
    ));
    out
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Parsed, Failure> {
    let mut args = args.into_iter();
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut json = false;
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
        other => return Err(Failure::Usage(format!("unknown command {other:?}"))),
    };
    Ok(Parsed::Run(Options { socket, json, command }))
}

/// Send one request line and return the one-line reply.
fn request(socket: &Path, line: &str) -> Result<String, Failure> {
    let connect_err = |e: std::io::Error| {
        Failure::Connect(format!(
            "cannot talk to {}: {e} (is the daemon running, and can you access the socket?)",
            socket.display()
        ))
    };
    let mut stream = UnixStream::connect(socket).map_err(connect_err)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(connect_err)?;
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
    let line = match &opts.command {
        Command::Segments => "segments".to_string(),
        Command::Devices(name) => format!("devices {name}"),
    };
    let raw = request(&opts.socket, &line)?;
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
        Command::Devices(_) => render_devices(&reply),
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
        assert_eq!(o, Options { socket: DEFAULT_SOCKET.into(), json: false, command: Command::Segments });

        let o = opts(&["-s", "/x.sock", "--json", "devices", "IoT", "to", "br0"]);
        assert_eq!(o.socket, PathBuf::from("/x.sock"));
        assert!(o.json);
        assert_eq!(o.command, Command::Devices("IoT to br0".into()));

        assert_eq!(opts(&["--socket=/y.sock", "segments"]).socket, PathBuf::from("/y.sock"));
        // Options after the command belong to the command.
        assert_eq!(opts(&["devices", "--json"]).command, Command::Devices("--json".into()));
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
        for option in ["\\-\\-json", "\\-\\-socket", "\\-\\-help"] {
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
        execute(&Options { socket: path.into(), json, command })
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
        assert!(out.starts_with("IoT to br0: 2 devices"));
        let _ = std::fs::remove_file(&path);
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
