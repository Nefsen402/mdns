use std::io::{BufRead, BufReader};
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use super::*;

/// Seconds are told in tenths, as `{:.1}` of a float told them, but for a tie
/// of exactly half a tenth, which was rounded to the even one and is now up.
#[test]
fn a_span_of_seconds_reads_in_tenths_as_it_did_with_a_float() {
    assert_eq!(span(0), "0ms");
    assert_eq!(span(999), "999ms");
    assert_eq!(span(1000), "1.0s");
    assert_eq!(span(1049), "1.0s");
    assert_eq!(span(1051), "1.1s");
    assert_eq!(span(1050), "1.1s", "a tie goes up");
    assert_eq!(span(29_700), "29.7s");
    assert_eq!(span(60_000), "1m 00s");
    assert_eq!(span(3_600_000), "1h 00m");
    let mut ties = 0;
    for ms in 1000..60_000u64 {
        let old = format!("{:.1}s", ms as f64 / 1000.0);
        if ms % 100 == 50 {
            ties += 1;
        } else {
            assert_eq!(span(ms), old, "{ms}ms");
        }
    }
    assert_eq!(ties, 590);
}

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
        Options { socket: config::DEFAULT_SOCKET.into(), json: false, segmented: false, verbose: false, command: Command::Segments }
    );

    let o = opts(&["-s", "/x.sock", "--json", "devices", "IoT", "to", "br0"]);
    assert_eq!(o.socket, "/x.sock");
    assert!(o.json);
    assert_eq!(o.command, Command::Devices("IoT to br0".into()));
    assert_eq!(opts(&["--socket=/y.sock", "segments"]).socket, "/y.sock");

    // Options may come anywhere, before the command or after it, and
    // among the words of a segment's name.
    let o = opts(&["devices", "IoT", "-v", "to", "br0", "--json", "--socket", "/z.sock"]);
    assert!(o.verbose && o.json);
    assert_eq!((o.socket.as_str(), o.command), ("/z.sock", Command::Devices("IoT to br0".into())));
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
    let man = include_str!("../../man/mdnsctl.1");
    for CommandInfo { name, .. } in COMMANDS {
        assert!(man.contains(&format!(".B {name}")) || man.contains(&format!("\\fB{name}\\fR")), "{name}");
    }
    for option in ["\\-\\-json", "\\-\\-segmented\\-json", "\\-\\-socket", "\\-\\-help", "\\-\\-verbose"] {
        assert!(man.contains(option), "{option}");
    }
    assert!(man.contains(config::DEFAULT_SOCKET));
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
fn brief_listing_shows_every_address_once() {
    let json = reply(
        "x",
        &[
            entry("a", Some("dual.local"), &["10.0.0.5", "fd00::5", "fe80::1"], ""),
            entry("b", Some("dual.local"), &["10.0.1.5"], ""),
            entry("a", Some("v6only.local"), &["fe80::2"], ""),
            entry("b", Some("v6only.local"), &["fe80::2"], ""),
        ],
    );
    // Each address once, of both interfaces, and each device on one line.
    let text = brief(&json);
    for addr in ["10.0.0.5", "10.0.1.5", "fd00::5", "fe80::1", "fe80::2"] {
        assert_eq!(text.matches(addr).count(), 1, "{addr} in {text}");
    }
    assert_eq!(text.lines().count(), 3, "{text}");
    assert!(text.contains("dual.local") && text.contains("v6only.local") && text.ends_with("x: 2 devices\n"), "{text}");
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
    let text = brief(&json);
    assert!(text.contains("  b.local  Kitchen, Hall  1.1.1.1\n"), "{text}");
    assert!(text.contains("  A.local  -              1.1.1.2\n"), "{text}");
    assert!(text.ends_with("x: 2 devices\n"), "{text}");

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
    assert_eq!(sub.log.as_deref(), Some("/var/log/plugs.log"));
    assert!(!sub.foreground);
    assert_eq!(sub.script, ["/usr/local/bin/configure", "--fast", "--query", "--"]);
    assert_eq!(sub.target.request("watch"), "watch --query=_shelly._tcp --interval=60 IoT to br0");

    let Command::Subscribe(sub) = opts(&["subscribe", "--foreground", "--log=x.log", "lan", "--", "s"]).command else { panic!() };
    assert!(sub.foreground);
    assert_eq!((sub.log.as_deref(), sub.target.segment.as_str()), (Some("x.log"), "lan"));

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
    assert!(sh.starts_with('/') && sh.ends_with("/sh"), "not followed through a symlink: {sh}");
    assert_eq!(executable(&sh).unwrap(), sh);
    // One found by a relative path is made absolute.
    let cwd = std::env::current_dir().unwrap();
    assert_eq!(executable("./src/../Cargo.toml").unwrap_err(), "./src/../Cargo.toml: not an executable file");
    let (script, _) = script("relative", 0);
    let relative = script.strip_prefix(&format!("{}/", cwd.display())).unwrap();
    assert_eq!(executable(&format!("./{relative}")).unwrap(), script);
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
fn script(tag: &str, status: u8) -> (String, PathBuf) {
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

#[test]
fn errors_say_what_is_wrong() {
    assert_eq!(read_file("/no/such/file").unwrap_err(), Errno::NOENT);
    // What main says of a command line that is not text.
    assert_eq!(args::Error::NotUtf8.to_string(), "the command line is not UTF-8");
}

#[test]
fn a_program_runs_with_its_input_and_environment() {
    // Not inherited, as in Subscriber::start: a script holding the
    // writing end of its own stdin would never see it end.
    let (stdin_rx, stdin_tx) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let (out, _) = script("spawned", 3);
    let out_file = PathBuf::from(out.replace(".sh", ".out"));
    let pid = spawn(&out, &["one".into()], &[("MDNS_HOSTNAME", "set".into())], &stdin_rx).unwrap();
    drop(stdin_rx);
    write_all(&stdin_tx, b"input\n").unwrap();
    drop(stdin_tx);
    let (_, status) = rustix::process::waitpid(Some(pid), WaitOptions::empty()).unwrap().unwrap();
    assert_eq!(status_text(status), "exit status: 3");
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), "input\none||set|\n");
}

#[test]
fn a_program_that_cannot_run_is_an_error_at_once() {
    let (stdin, _) = rustix::pipe::pipe().unwrap();
    assert_eq!(spawn("/no/such/program", &[], &[], &stdin).unwrap_err(), Errno::NOENT);
    assert_eq!(spawn("/etc/passwd", &[], &[], &stdin).unwrap_err(), Errno::ACCESS);
}

/// A subscriber with no watch, running `script` with `args`.
fn idle(script: String, args: &[&str]) -> Subscriber {
    let args = args.iter().map(|a| a.to_string()).collect();
    Subscriber { socket: String::new(), line: String::new(), script, args, watch: None, retry: None, queue: VecDeque::new(), running: None }
}

/// Turn `sub` as subscribe's loop does, until `done` says so.
fn turn_until(sub: &mut Subscriber, done: impl Fn(&Subscriber) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done(sub) {
        assert!(Instant::now() < deadline, "not done in time");
        let mut fds = sub.fds();
        let timeout = sub.deadline().map_or(STOP_CHECK, |at| at.saturating_sub(now()).min(STOP_CHECK));
        poll::wait(&mut fds, Some(timeout)).unwrap();
        sub.turn(&fds, now());
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
    let path = format!("target/mdnsctl-test-{}-again.sock", std::process::id());
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
    let path = format!("target/mdnsctl-test-{}-cut.sock", std::process::id());
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
fn holding_daemon(tag: &str, lines: Vec<String>, hold: Duration) -> (String, JoinHandle<String>) {
    std::fs::create_dir_all("target").unwrap();
    let path = format!("target/mdnsctl-test-{}-{tag}.sock", std::process::id());
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

fn query_options(path: &str, json: bool, verbose: bool, wait: Duration) -> (Options, Target) {
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
    let mut out = String::new();
    devices_query(&opts, &target, &mut out).unwrap();
    assert!(started.elapsed() >= wait && started.elapsed() < wait * 3, "{:?}", started.elapsed());
    assert_eq!(daemon.join().unwrap(), "watch --query=_x._tcp IoT\n", "a watch for the type, nothing else");
    assert_eq!(
        out,
        "  a.local  a.local plug  10.0.1.1\n  c.local  c.local plug  10.0.1.3\n\
         IoT: 1 device\n(1 device without a name not shown; use -v to list everything)\n",
        "each as it is first found, then what is left"
    );

    // And with -v, as `devices -v`, the unnamed one too.
    let (path, _daemon) = holding_daemon("query-verbose", query_stream(), wait * 3);
    let (opts, target) = query_options(&path, false, true, wait);
    let mut out = String::new();
    devices_query(&opts, &target, &mut out).unwrap();
    let text = out;
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
    let mut out = String::new();
    devices_query(&opts, &target, &mut out).unwrap();
    let text = out;
    assert_eq!(text.lines().count(), 1, "{text}");
    let reply: Value = serde_json::from_str(&text).unwrap();
    assert_eq!((&reply["ok"], &reply["name"]), (&Value::Bool(true), &Value::from("IoT")));
    let devices = reply["devices"].as_array().unwrap();
    let hosts: Vec<&Value> = devices.iter().map(|d| &d["hostname"]).collect();
    assert!(hosts.len() == 2 && hosts.contains(&&Value::Null) && hosts.contains(&&Value::from("c.local")), "{devices:?}");
    let c = devices.iter().find(|d| d["hostname"] == "c.local").unwrap();
    assert_eq!(c["addresses"], serde_json::json!(["10.0.1.3", "fd00::3"]), "as last heard of");
}

#[test]
fn devices_with_a_query_report_a_refusal_or_a_daemon_that_goes() {
    let (path, _daemon) = holding_daemon("query-refused", vec![r#"{"ok":false,"error":"no such segment: IoT"}"#.into()], Duration::ZERO);
    let (opts, target) = query_options(&path, false, false, Duration::from_secs(5));
    assert_eq!(devices_query(&opts, &target, &mut String::new()), Err(Failure::Server("no such segment: IoT".into())));

    let (path, _daemon) = holding_daemon("query-gone", vec![ACK.into()], Duration::ZERO);
    let (opts, target) = query_options(&path, false, false, Duration::from_secs(5));
    assert!(matches!(devices_query(&opts, &target, &mut String::new()), Err(Failure::Connect(_))));
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
    let mut out = String::new();
    devices_query(&opts, &target, &mut out).unwrap();
    let lines: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
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
    if cfg!(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "dragonfly")) {
        assert!(command_line(me).is_some_and(|c| !c.is_empty()));
    } else {
        assert!(command_line(me).is_none(), "the system does not say");
    }
    assert_eq!(user_name(0).as_deref(), Some("root"));
    assert!(command_line(-1).is_none());
    assert!(command_line(i32::MAX).is_none(), "no such process");
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
    let mut seen = BTreeSet::new();
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
    let mut seen = BTreeSet::new();
    let mut show = |e: Value| render_event(&e, false, &mut seen).unwrap();
    assert!(show(event("present", 280, Some("hue.local"), "10.0.1.3", PLUG)).unwrap().starts_with("present  ttl=280 "));
    assert!(show(event("updated", 300, Some("hue.local"), "10.0.1.3", PLUG)).unwrap().starts_with("updated  "));
}

#[test]
fn verbose_watch_lines_are_a_device_with_its_services() {
    let mut seen = BTreeSet::new();
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
    let mut seen = BTreeSet::new();
    assert!(render_event(&serde_json::json!({"event":"added"}), false, &mut seen).is_err());
    let mut odd = event("exploded", 1, Some("x.local"), "10.0.0.1", "[]");
    assert!(render_event(&odd, false, &mut seen).is_err());
    odd["event"] = "added".into();
    assert!(render_event(&odd, false, &mut seen).is_ok());
}

/// A fake daemon that acknowledges a watch, sends `lines`, and hangs up.
fn streaming_daemon(tag: &str, lines: Vec<String>) -> (String, JoinHandle<String>) {
    std::fs::create_dir_all("target").unwrap();
    let path = format!("target/mdnsctl-test-{}-{tag}.sock", std::process::id());
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

fn watch_options(path: &str, json: bool) -> Options {
    Options { socket: path.into(), json, segmented: false, verbose: false, command: Command::Watch("IoT".into()) }
}

#[test]
fn watch_prints_changes_until_the_daemon_stops() {
    let added = event("added", 4500, Some("plug.local"), "10.0.1.9", PLUG).to_string();
    let removed = event("removed", 0, Some("plug.local"), "10.0.1.9", PLUG).to_string();
    let (path, daemon) = streaming_daemon("watch", vec![ACK.into(), added.clone(), removed.clone()]);

    let mut out = String::new();
    let result = watch(&watch_options(&path, false), &"IoT".into(), &mut out);
    assert_eq!(daemon.join().unwrap(), "watch IoT\n");
    assert_eq!(
        out,
        "added    ttl=4500   plug.local  Plug S  10.0.1.9\nremoved  ttl=0      plug.local  Plug S  10.0.1.9\n"
    );
    // The daemon went away: that is a failure, not a clean end.
    assert!(matches!(result, Err(Failure::Connect(m)) if m.contains("closed")));
}

#[test]
fn watch_json_prints_each_event_unchanged_and_not_the_acknowledgement() {
    let added = event("added", 4500, Some("plug.local"), "10.0.1.9", PLUG).to_string();
    let (path, daemon) = streaming_daemon("watch-json", vec![ACK.into(), added.clone()]);
    let mut out = String::new();
    let _ = watch(&watch_options(&path, true), &"IoT".into(), &mut out);
    daemon.join().unwrap();
    assert_eq!(out, format!("{added}\n"));
}

#[test]
fn watch_reports_refusals_and_failures_mid_stream() {
    let (path, daemon) = streaming_daemon("watch-refused", vec![r#"{"ok":false,"error":"no such segment: IoT"}"#.into()]);
    assert_eq!(
        watch(&watch_options(&path, false), &"IoT".into(), &mut String::new()),
        Err(Failure::Server("no such segment: IoT".into()))
    );
    daemon.join().unwrap();

    let (path, daemon) = streaming_daemon("watch-stopped", vec![ACK.into(), r#"{"ok":false,"error":"shutting down"}"#.into()]);
    assert_eq!(
        watch(&watch_options(&path, false), &"IoT".into(), &mut String::new()),
        Err(Failure::Server("shutting down".into()))
    );
    daemon.join().unwrap();
}

/// `mdnsctl watch | head` must not be an error when the reader leaves.
#[test]
fn watch_ends_quietly_when_the_output_is_closed() {
    struct Closed;
    impl fmt::Write for Closed {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            Err(fmt::Error)
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
    let shown = render_event(&event, true, &mut BTreeSet::new()).unwrap().unwrap();
    assert!(shown.starts_with("added    ttl=300    wifi  10.0.1.9  plug.local  addr-ttl=120\n"), "{shown}");
    // The brief views stay as they were.
    let brief = render_event(&event, false, &mut BTreeSet::new()).unwrap().unwrap();
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
fn fake_daemon(tag: &str, reply: &'static str) -> (String, JoinHandle<String>) {
    // Unix socket paths are limited to ~108 bytes, so stay relative to
    // the package root (cargo's test working directory).
    std::fs::create_dir_all("target").unwrap();
    let path = format!("target/mdnsctl-test-{}-{tag}.sock", std::process::id());
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

fn run(path: &str, json: bool, command: Command) -> Result<String, Failure> {
    execute(&Options { socket: path.into(), json, segmented: false, verbose: false, command })
}

fn run_verbose(path: &str, command: Command) -> Result<String, Failure> {
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

    let missing = "target/mdnsctl-test-nonexistent.sock".to_string();
    assert!(matches!(run(&missing, false, Command::Segments), Err(Failure::Connect(_))));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&path2);
}
