//! Local control socket.
//!
//! A Unix stream socket speaking one request per line and answering each with
//! one line of JSON. A connection may send any number of requests.
//!
//! ```text
//! segments
//!   {"ok":true,"segments":[{"name":"IoT","interfaces":["wifi"],"families":["v4","v6"]}]}
//! devices <segment name>
//!   {"ok":true,"name":"IoT","devices":[{"interface":"wifi","family":"v4",
//!    "addr":"10.0.1.7","hostname":"tv.local","services":[{"instance":...}]}]}
//! probe [<segment name>]
//!   {"ok":true,"probed":[{"interface":"wifi","family":"v4","queries":14,"error":null}]}
//! ```
//!
//! Errors are `{"ok":false,"error":"..."}`. `devices` lists what was
//! discovered on the segment's own interfaces, not reflected copies from
//! other segments. `probe` actively queries the interfaces of the segment
//! (of all segments if no name is given) and replies after about four
//! seconds, once the answers have been processed; list what was found with
//! `devices`.

use std::fs::{self, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::socket::{Device, Family, Segment};
use crate::Group;

/// Longest request line accepted.
const MAX_LINE: u64 = 4096;

/// Idle connections are closed after this long, so clients can't pile up threads.
const IDLE: Duration = Duration::from_secs(60);

/// Bind the socket and serve it on background threads. Binding happens
/// before this returns so a bad path or a second instance is reported at
/// startup. The returned handle is the accept loop.
///
/// The server only holds a weak reference, so it never keeps the segments
/// alive: once the owner drops them, requests are answered "shutting down".
pub fn serve(path: &Path, groups: &Arc<Vec<Group>>) -> Result<JoinHandle<()>> {
    let listener = bind(path)?;
    let groups = Arc::downgrade(groups);
    eprintln!("ipc: listening on {}", path.display());
    Ok(thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let groups = Weak::clone(&groups);
                    thread::spawn(move || match serve_connection(stream, &groups) {
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

fn serve_connection(stream: UnixStream, groups: &Weak<Vec<Group>>) -> io::Result<()> {
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
        let reply = match groups.upgrade() {
            Some(groups) => handle(&groups, line.trim()),
            None => error("shutting down").to_string(),
        };
        writeln!(writer, "{reply}")?;
    }
}

/// Answer one request line with one line of JSON.
pub fn handle(groups: &[Group], request: &str) -> String {
    let (command, arg) = match request.split_once(char::is_whitespace) {
        Some((command, arg)) => (command, arg.trim()),
        None => (request, ""),
    };
    match command.to_ascii_lowercase().as_str() {
        "segments" => segments(groups),
        "devices" => devices(groups, arg),
        "probe" => probe(groups, arg),
        "" => error("empty request"),
        other => error(&format!("unknown command {other:?}; try: segments, devices <name>, probe [name]")),
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
            let mut families: Vec<&str> = members.iter().map(|g| family_name(g.family)).collect();
            families.sort_unstable();
            json!({ "name": name, "interfaces": interfaces, "families": families })
        })
        .collect();
    json!({ "ok": true, "segments": list })
}

/// A segment name argument, with optional surrounding quotes removed.
fn segment_arg(arg: &str) -> &str {
    arg.strip_prefix('"').and_then(|n| n.strip_suffix('"')).unwrap_or(arg)
}

fn devices(groups: &[Group], name: &str) -> Value {
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
            found.sort_by_key(|d| d.addr);
            list.extend(found.iter().map(|d| device(seg, d)));
        }
    }
    json!({ "ok": true, "name": name, "devices": list })
}

/// Probe every interface of the named segment, or of all segments. An
/// interface shared by several segments is probed once.
fn probe(groups: &[Group], name: &str) -> Value {
    let name = segment_arg(name);
    let members: Vec<&Group> = groups.iter().filter(|g| name.is_empty() || g.name == name).collect();
    if members.is_empty() {
        return error(&format!("no such segment: {name}"));
    }

    let mut links: Vec<&Segment> = Vec::new();
    for seg in members.iter().flat_map(|g| g.reflector.segments()) {
        if !links.iter().any(|l| l.interface() == seg.interface() && l.family() == seg.family()) {
            links.push(seg);
        }
    }

    // The links are independent, so probe them together: the reply takes one
    // probe's time, not one per interface.
    let results: Vec<Value> = thread::scope(|scope| {
        let running: Vec<_> = links
            .iter()
            .map(|&seg| scope.spawn(move || (seg, seg.probe())))
            .collect();
        running
            .into_iter()
            .map(|handle| {
                let (seg, result) = handle.join().expect("probe thread panicked");
                let (queries, err) = match result {
                    Ok(n) => (Some(n), None),
                    Err(e) => (None, Some(format!("{e:#}"))),
                };
                json!({
                    "interface": seg.interface(),
                    "family": family_name(seg.family()),
                    "queries": queries,
                    "error": err,
                })
            })
            .collect()
    });
    json!({ "ok": true, "probed": results })
}

fn device(seg: &Segment, d: &Device) -> Value {
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
            })
        })
        .collect();
    json!({
        "interface": seg.interface(),
        "family": family_name(seg.family()),
        "addr": d.addr.to_string(),
        "hostname": d.hostname,
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
        let segs: Vec<Segment> = interfaces.iter().map(|i| Segment::new(i, family)).collect();
        let reflector = Reflector::new(segs.clone()).unwrap();
        (Group { name: name.into(), family, reflector }, segs)
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
    fn lists_segments_merging_families() {
        let (m4, _) = group("media", Family::V4, &["a", "b"]);
        let (m6, _) = group("media", Family::V6, &["a", "b"]);
        let (iot, _) = group("iot", Family::V4, &["c"]);
        let groups = [m4, m6, iot];
        assert_eq!(
            handle(&groups, "segments"),
            r#"{"ok":true,"segments":[{"name":"media","interfaces":["a","b"],"families":["v4","v6"]},{"name":"iot","interfaces":["c"],"families":["v4"]}]}"#
        );
    }

    #[test]
    fn lists_devices_of_a_segment() {
        let (iot, segs) = group("IoT to br0", Family::V4, &["c"]);
        segs[0].observe(ip("10.0.3.9"));
        assert_eq!(
            handle(&[iot], r#"devices "IoT to br0""#),
            r#"{"ok":true,"name":"IoT to br0","devices":[{"interface":"c","family":"v4","addr":"10.0.3.9","hostname":null,"services":[]}]}"#
        );
    }

    #[test]
    fn devices_carry_services_and_escape_json() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", r#"My "TV""#);
        segs[1].observe(ip("10.0.2.1"));
        let out = handle(&[g], "DEVICES media");
        assert!(out.contains(r#""interface":"a","family":"v4","addr":"10.0.1.5","hostname":"tv.local""#), "{out}");
        assert!(
            out.contains(r#"{"instance":"My \"TV\"._http._tcp.local","type":"_http._tcp.local","port":80,"target":"tv.local","txt":["k=v"]}"#),
            "{out}"
        );
        assert!(out.contains(r#""interface":"b","family":"v4","addr":"10.0.2.1""#), "{out}");
        // Interface order is preserved.
        assert!(out.find(r#""interface":"a""#) < out.find(r#""interface":"b""#));
    }

    #[test]
    fn reflected_copies_are_not_listed() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", "TV");
        std::thread::sleep(Duration::from_millis(150));
        assert!(!segs[1].manual_devices().is_empty(), "precondition: reflected onto b");
        let out = handle(&[g], "devices media");
        assert_eq!(out.matches("\"addr\"").count(), 1, "{out}");
    }

    #[test]
    fn probes_each_interface_once_even_when_segments_share_it() {
        let (a, b, c) = (
            Segment::new("a", Family::V4),
            Segment::new("b", Family::V4),
            Segment::new("c", Family::V4),
        );
        let groups = [
            Group { name: "x".into(), family: Family::V4, reflector: Reflector::new(vec![a.clone(), b.clone()]).unwrap() },
            Group { name: "y".into(), family: Family::V4, reflector: Reflector::new(vec![a, c]).unwrap() },
        ];
        let interfaces = |request: &str| -> Vec<String> {
            let reply: Value = serde_json::from_str(&handle(&groups, request)).unwrap();
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
            handle(&[g], "probe media"),
            r#"{"ok":true,"probed":[{"interface":"a","family":"v4","queries":0,"error":null}]}"#
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
            let out = handle(&groups, request);
            assert!(out.starts_with(r#"{"ok":false,"error":""#) && out.contains(expect), "{request}: {out}");
        }
    }

    /// Names come off the network and may contain anything; a reply must
    /// still be exactly one line, or a device could forge extra replies.
    #[test]
    fn replies_stay_on_one_line_whatever_the_names_contain() {
        let (g, segs) = group("media", Family::V4, &["a", "b"]);
        announce(&segs[0], "10.0.1.5", "tv.local", "My\nTV\"\\");
        let out = handle(&[g], "devices media");
        assert!(!out.contains('\n'), "{out}");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["devices"][0]["services"][0]["instance"],
            "My\nTV\"\\._http._tcp.local"
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
        serve(&path, &groups).unwrap();

        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o660);

        let mut stream = UnixStream::connect(&path).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        // Several requests on one connection.
        assert!(ask(&mut stream, &mut reader, "segments").contains(r#""name":"IoT""#));
        assert!(ask(&mut stream, &mut reader, "devices IoT").contains(r#""addr":"10.0.1.7""#));
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
