use crate::device::edit;

fn added(device: Device) -> Event {
    Event::Added(device.into())
}

/// An update to `device`, from just as it is: how it changed is not
/// what a watch shows.
fn updated(device: Device) -> Event {
    Event::Updated(device.into())
}

fn removed(device: Device) -> Event {
    Event::Removed(device.into())
}

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use super::*;
use crate::config::Forward;
use crate::listener::Link;
use crate::device::EditService;

/// A segment that keeps a device at least five minutes, which is what these
/// tests of what is listed assume; the default keeps one for its TTL.
fn interface(name: &str) -> Interface {
    let seg = Interface::new(name);
    seg.set_min_lifetime(Duration::from_secs(300));
    seg
}

/// `socket` as the daemon takes a socket.
fn fd(socket: impl std::os::fd::IntoRawFd) -> rustix::fd::OwnedFd {
    // SAFETY: a descriptor just given up by its owner.
    unsafe { rustix::fd::FromRawFd::from_raw_fd(socket.into_raw_fd()) }
}
use crate::codec::{Header, Message, RData, Record};
use crate::segment::{deliver_made, Segment};

/// A segment that is used over `family`, to somewhere nobody listens.
fn linked(name: &str, family: Family) -> Interface {
    let seg = interface(name);
    let socket = fd(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
    seg.attach(Link::to(family, socket, "127.0.0.1:9".parse().unwrap()));
    seg
}

fn group(name: &str, family: Family, interfaces: &[&str]) -> (Group, Vec<Interface>) {
    let segs: Vec<Interface> = interfaces.iter().map(|i| linked(i, family)).collect();
    let segment = Segment::new(segs.clone()).unwrap();
    (Group { name: name.into(), segment }, segs)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn rec(name: &str, data: RData) -> Record {
    Record { name: name.into(), class: 1, cache_flush: false, ttl: 120, data }
}

/// Make `seg` hear a full announcement from `from`.
fn announce(seg: &Interface, from: &str, host: &str, instance: &str) {
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
fn lists_interfaces_merging_families() {
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
fn interfaces_say_which_interfaces_are_untrusted() {
    let segs: Vec<Interface> = ["br0", "wifi"].iter().map(|i| linked(i, Family::V4)).collect();
    let segment = Segment::with_untrusted(segs, &["wifi".to_string()]).unwrap();
    let groups = [Group { name: "IoT to br0".into(), segment }];
    assert_eq!(
        handle(&groups, &Watches::default(), "segments"),
        r#"{"ok":true,"segments":[{"name":"IoT to br0","interfaces":["br0","wifi"],"untrusted":["wifi"],"families":["v4"]}]}"#
    );
}

#[test]
fn lists_devices_of_a_interface() {
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
        out.contains(r#"{"instance":"My \"TV\"._http._tcp.local","type":"_http._tcp.local","port":80,"target":"tv.local","txt":["k=v"],"subtypes":[],"ttl":120,"ptr_ttl":120,"txt_ttl":120}"#),
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
    assert!(!segs[1].reflected_devices().is_empty(), "precondition: reflected onto b");
    let out = handle(&[g], &Watches::default(), "devices media");
    assert_eq!(out.matches("\"addresses\"").count(), 1, "{out}");
}

/// This host, with an ssh service, as `[Advertise]` makes it.
fn advertise_self(seg: &Interface) {
    let mut pc = Device {
        hostname: Some("pc.local".into()),
        services: vec![crate::device::ServiceParts {
            instance: "pc._ssh._tcp.local".into(),
            kind: "_ssh._tcp.local".into(),
            port: 22,
            target: Some("pc.local".into()),
            ..Default::default()
        }
        .into()]
        .into(),
        ..Device::default()
    };
    pc.add_addrs(&[ip("10.0.0.5")]);
    seg.add_reflected_ttl(crate::interface::OWN, &crate::device::Shared::new(pc), Duration::from_secs(120)).unwrap();
}

/// Nothing is heard of this host, so it is listed as it advertises itself,
/// and a reflected copy of another's device still is not.
#[test]
fn the_host_is_listed_as_it_advertises_itself() {
    let (g, segs) = group("lan", Family::V4, &["a", "b"]);
    advertise_self(&segs[0]);
    announce(&segs[1], "10.0.1.5", "tv.local", "TV");
    deliver_made();
    let reply: Value = serde_json::from_str(&handle(&[g], &Watches::default(), "devices lan")).unwrap();
    let devices = reply["devices"].as_array().unwrap();
    let own: Vec<&Value> = devices.iter().filter(|d| d["own"] == true).collect();
    assert_eq!(own.len(), 1, "{reply}");
    assert_eq!((own[0]["interface"].as_str(), own[0]["hostname"].as_str()), (Some("a"), Some("pc.local")));
    assert_eq!(own[0]["addresses"], json!(["10.0.0.5"]));
    assert_eq!(own[0]["address_ttl"], 120);
    assert_eq!(own[0]["services"][0]["type"], "_ssh._tcp.local");
    // The tv is heard of, once, and not as one of the host's own; the copy of it on a is not listed.
    assert_eq!(devices.iter().filter(|d| d["hostname"] == "tv.local").count(), 1, "{reply}");
    assert_eq!(devices.len(), 2, "{reply}");
}

#[test]
fn a_watch_for_a_type_the_host_offers_shows_it_present_and_for_another_does_not() {
    let (seg, _rx) = wired("a");
    advertise_self(&seg);
    let groups = vec![Group { name: "lan".into(), segment: Segment::new(vec![seg.clone()]).unwrap() }];
    let present = |arg: &str| follow(&groups, arg).ok().unwrap().present;
    let lines = present("--query=_ssh._tcp lan");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!((lines[0]["event"].as_str(), lines[0]["device"]["hostname"].as_str()), (Some("present"), Some("pc.local")));
    assert_eq!((lines[0]["ttl"].as_u64(), lines[0]["device"]["own"].as_bool()), (Some(120), Some(true)));
    assert_eq!(lines[0]["device"]["services"][0]["port"], 22);
    assert!(present("--query=_http._tcp lan").is_empty());
}

#[test]
fn probes_each_interface_once_even_when_interfaces_share_it() {
    let (a, b, c) = (
        interface("a"),
        interface("b"),
        interface("c"),
    );
    let groups = [
        Group { name: "x".into(), segment: Segment::new(vec![a.clone(), b.clone()]).unwrap() },
        Group { name: "y".into(), segment: Segment::new(vec![a, c]).unwrap() },
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
    // No link is attached to it, so nothing is sent.
    let g = Group { name: "media".into(), segment: Segment::new(vec![interface("a")]).unwrap() };
    assert_eq!(
        handle(&[g], &Watches::default(), "probe media"),
        r#"{"ok":true,"probed":[{"interface":"a","queries":0,"error":null}]}"#
    );
}

/// The clock moves forward only where the daemon is built with one that can.
/// Where it is, it is a clock of its own that the other tests, which run in the
/// same process, would share: run it on its own (`-- --test-threads=1`).
#[test]
fn the_clock_is_moved_only_by_a_daemon_built_for_it() {
    let (g, _) = group("media", Family::V4, &["a", "b"]);
    let groups = [g];
    let out = handle(&groups, &Watches::default(), "advance 1500");
    if cfg!(feature = "test-clock") {
        let before = Instant::now();
        assert_eq!(Instant::now(), before, "it does not move by itself");
        let out2 = handle(&groups, &Watches::default(), "advance 2000");
        assert!(out.contains(r#""ok":true"#) && out2.contains(r#""advanced_ms":2000"#), "{out} {out2}");
        assert_eq!(Instant::now(), before + Duration::from_secs(2), "and by exactly what it is told");
        assert!(handle(&groups, &Watches::default(), "advance soon").contains("advance <milliseconds>"));
    } else {
        assert!(out.contains("unknown command"), "{out}");
    }
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
/// it, with the segments' upkeep and the segments' deliveries, a turn
/// at a time, as a test waits for what a client is told.
struct Harness {
    server: Server,
    groups: Vec<Group>,
}

impl Harness {
    fn new(path: &Path, groups: Vec<Group>) -> Harness {
        Harness { server: Server::bind(path.to_str().unwrap(), 0o660).unwrap(), groups }
    }

    /// One turn of the loop.
    fn pump(&mut self) {
        let mut fds = self.server.fds();
        poll::wait(&mut fds, Some(Duration::from_millis(1))).unwrap();
        self.server.ready(&fds);
        let now = Instant::now();
        for seg in self.groups.iter().flat_map(|g| g.segment.interfaces()) {
            if seg.next_due().is_some_and(|at| at <= now) {
                seg.upkeep(now);
            }
        }
        crate::segment::deliver(&self.groups.iter().map(|g| &g.segment).collect::<Vec<_>>());
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
    let mut h = Harness::new(&path, vec![Group { name: "IoT".into(), segment: Segment::new(vec![seg.clone()]).unwrap() }]);

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
    // Some of it: how much the socket holds is the system's, and BSDs hold less than 64 KiB.
    assert!(theirs.read(&mut buf).unwrap() > 0);
    c.flush(now + Duration::from_millis(100));
    assert_eq!(c.stalled, Some(now + Duration::from_millis(100)));

    let mut server = Server { listener: fd(UnixListener::bind(temp_socket("stalled")).unwrap()), clients: vec![c], next_watch: 0, watched: false };
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

/// An interface called `name` that sends to the returned socket.
fn wired(name: &str) -> (Interface, std::net::UdpSocket) {
    let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let seg = interface(name);
    seg.attach(Link::to(Family::V4, fd(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()), rx.local_addr().unwrap()));
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
fn query_options_take_service_types() {
    let parse = |arg: &str| query_args(arg).map(|(q, rest)| (q.kinds, rest.to_string()));
    assert_eq!(parse("IoT to br0"), Ok((vec![], "IoT to br0".into())));
    assert_eq!(
        parse("--query=_shelly._tcp --query=_Shelly._tcp.local. --query=_hue._tcp.local \"IoT\""),
        Ok((vec!["_shelly._tcp.local".into(), "_hue._tcp.local".into()], "\"IoT\"".into()))
    );
    let err = |arg: &str| parse(arg).unwrap_err()["error"].as_str().unwrap().to_string();
    assert!(err("--query=shelly IoT").contains("not a service type"));
    assert!(err("--query=_a._b._tcp IoT").contains("not a service type"));
    // How often to ask is the interface's say, as of any question.
    assert!(err("--interval=30 --query=_x._tcp IoT").contains("unknown option --interval=30"));
    assert!(err("--bogus IoT").contains("unknown option --bogus"));
}

/// `devices` lists what is known, and asks nothing: an option is refused,
/// pointing to `watch --query`, which asks.
#[test]
fn devices_lists_what_is_known_and_asks_nothing() {
    let (a, a_rx) = wired("a");
    let groups = [Group { name: "IoT".into(), segment: Segment::new(vec![a.clone()]).unwrap() }];
    announce(&a, "10.0.1.7", "tv.local", "TV");
    let ask = |request: &str| handle(&groups, &Watches::default(), request);
    let reply: Value = serde_json::from_str(&ask("devices IoT")).unwrap();
    assert_eq!(reply["devices"][0]["hostname"], "tv.local");
    assert!(ask("devices --query=_http._tcp IoT").contains("watch with --query"));
    assert!(queries(&a_rx).is_empty(), "nothing asked");
}

#[test]
fn watch_with_a_query_shows_what_is_there_and_asks_as_the_interface_says() {
    let (seg, rx) = wired("wifi");
    let groups = vec![Group { name: "IoT".into(), segment: Segment::new(vec![seg.clone()]).unwrap() }];
    announce(&seg, "10.0.1.7", "tv.local", "TV");
    let path = temp_socket("watch-query");
    let mut h = Harness::new(&path, groups);
    // What of the type was asked, as the daemon puts it, for as long as it takes.
    let http = |h: &mut Harness, rx: &std::net::UdpSocket| {
        let mut asked = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(600);
        while Instant::now() < deadline {
            h.pump();
            asked.extend(queries(rx).into_iter().filter(|(names, _)| names == &["_http._tcp.local"]));
        }
        asked
    };

    let (mut stream, mut reader) = connect(&path);
    let ack = h.ask(&mut stream, &mut reader, "watch --query=_http._tcp IoT");
    assert_eq!(ack, r#"{"ok":true,"name":"IoT","watching":true}"#);
    let present = h.json(&mut reader);
    assert_eq!((present["event"].as_str(), present["device"]["hostname"].as_str()), (Some("present"), Some("tv.local")));
    assert_eq!(present["ttl"], 300);

    // Asked, with the TV as a known answer, in the three rounds of the query.
    let asked = http(&mut h, &rx);
    assert!(!asked.is_empty() && asked.iter().all(|&(_, known)| known == 1), "{asked:?}");

    // Another watch for the same type shows what is there, and asks nothing: it
    // has been asked, and what answered is known.
    let (mut second, mut second_reader) = connect(&path);
    h.ask(&mut second, &mut second_reader, "watch --query=_http._tcp IoT");
    assert_eq!(h.json(&mut second_reader)["event"], "present");
    assert!(http(&mut h, &rx).is_empty(), "asked once");

    // A type that is new is asked, and so is one where the interface asks nothing
    // of the others' questions: what a person asks for is.
    let (mut third, mut third_reader) = connect(&path);
    h.ask(&mut third, &mut third_reader, "watch --query=_ipp._tcp IoT");
    let ipp = {
        let mut asked = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(600);
        while Instant::now() < deadline {
            h.pump();
            asked.extend(queries(&rx).into_iter().filter(|(names, _)| names == &["_ipp._tcp.local"]));
        }
        asked
    };
    assert!(!ipp.is_empty(), "a new type is asked");
    seg.set_forward(Forward::Never);
    let (mut fourth, mut fourth_reader) = connect(&path);
    h.ask(&mut fourth, &mut fourth_reader, "watch --query=_hue._tcp IoT");
    let mut hue = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(600);
    while Instant::now() < deadline {
        h.pump();
        hue.extend(queries(&rx).into_iter().filter(|(names, _)| names == &["_hue._tcp.local"]));
    }
    assert!(!hue.is_empty(), "asked though the interface asks nothing of its own accord");

    // One without the type is not shown; one with it is.
    seg.observe(ip("10.0.1.8"));
    announce(&seg, "10.0.1.9", "plug.local", "Plug");
    let added = h.json(&mut reader);
    assert_eq!((added["event"].as_str(), added["device"]["hostname"].as_str()), (Some("added"), Some("plug.local")));
    let _ = fs::remove_file(&path);
}

/// Where an interface asks nothing of its own accord, the types that watches
/// are for are told to it, as long as they are open: that is what keeps up the
/// devices they are for.
#[test]
fn the_interfaces_are_told_the_types_the_watches_open_are_for() {
    let (seg, _rx) = wired("wifi");
    seg.set_active(false);
    let groups = vec![Group { name: "IoT".into(), segment: Segment::new(vec![seg.clone()]).unwrap() }];
    let path = temp_socket("watch-types");
    let mut h = Harness::new(&path, groups);
    h.pump();
    assert!(seg.watched().is_empty());

    // A watch that is for no type is for none.
    let (mut plain, mut plain_reader) = connect(&path);
    h.ask(&mut plain, &mut plain_reader, "watch IoT");
    h.pump();
    assert!(seg.watched().is_empty());

    let (mut first, mut first_reader) = connect(&path);
    h.ask(&mut first, &mut first_reader, "watch --query=_http._tcp --query=_Shelly._tcp IoT");
    h.pump();
    assert_eq!(seg.watched(), ["_http._tcp.local", "_shelly._tcp.local"]);

    // The types of all of them, each once.
    let (mut second, mut second_reader) = connect(&path);
    h.ask(&mut second, &mut second_reader, "watch --query=_http._tcp --query=_hue._tcp IoT");
    h.pump();
    assert_eq!(seg.watched(), ["_http._tcp.local", "_hue._tcp.local", "_shelly._tcp.local"]);

    // A watch that is closed is not one: what it was for goes.
    drop(first);
    drop(first_reader);
    h.pump();
    h.pump();
    assert_eq!(seg.watched(), ["_http._tcp.local", "_hue._tcp.local"]);
    drop(second);
    drop(second_reader);
    h.pump();
    h.pump();
    assert!(seg.watched().is_empty(), "{:?}", seg.watched());
    let _ = fs::remove_file(&path);
}

/// A watch for a type shows a device gaining it as added, changing as
/// updated, losing it or going as removed, and nothing of the others.
#[test]
fn a_watch_for_a_type_narrows_what_it_shows() {
    let kinds = ["_http._tcp.local".to_string()];
    let mut shown = HashMap::new();
    let tv = |services: bool| {
        let seg = interface("wifi");
        announce(&seg, "10.0.1.7", "tv.local", "TV");
        let mut d = seg.devices().remove(0);
        if !services {
            edit(&mut d.services).clear();
        }
        d
    };
    let notice = |event| Notice { interface: "wifi".into(), event, ttl: Duration::from_secs(120) };
    let mut show = |event| narrowed("IoT", notice(event), &kinds, &mut shown).map(|v| v["event"].as_str().unwrap().to_string());

    let moved = || {
        let mut d = tv(true);
        d.services[0].edit(|p| p.port = 8080);
        d
    };

    assert_eq!(show(updated(tv(false))), None);
    assert_eq!(show(updated(tv(true))).as_deref(), Some("added"));
    assert_eq!(show(updated(tv(true))), None, "nothing of it shown changed");
    assert_eq!(show(updated(moved())).as_deref(), Some("updated"));
    // Added again while shown, as one listed as present can be: an update,
    // or nothing at all if it is just as shown.
    assert_eq!(show(added(tv(true))).as_deref(), Some("updated"));
    assert_eq!(show(added(tv(true))), None);
    assert_eq!(show(updated(tv(false))).as_deref(), Some("removed"));
    assert_eq!(show(updated(tv(false))), None);
    assert_eq!(show(added(tv(true))).as_deref(), Some("added"));
    assert_eq!(show(removed(tv(true))).as_deref(), Some("removed"));
    assert_eq!(show(removed(tv(true))), None, "not shown since");

    // One without a hostname cannot be told apart: its going is shown.
    let mut nameless = tv(true);
    nameless.hostname = None;
    assert_eq!(show(removed(nameless)).as_deref(), Some("removed"));
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
    let _second = open(&mut h, "watch --query=_shelly._tcp IoT");
    let watchers = list(&mut h);
    assert_eq!(watchers.len(), 2, "{watchers:?}");
    let (pid, uid) = (std::process::id() as i64, unsafe { libc::getuid() } as i64);
    for w in &watchers {
        assert_eq!(w["segment"], "IoT");
        assert_eq!(w["uid"].as_i64().unwrap(), uid, "the kernel's word for who holds it");
        // Where the system says only whose it is, there is no process to name.
        if cfg!(any(target_os = "linux", target_os = "android", target_os = "freebsd")) {
            assert_eq!(w["pid"].as_i64(), Some(pid));
        } else {
            assert!(w["pid"].is_null(), "{w}");
        }
        assert!(w["age_ms"].as_u64().is_some());
    }
    assert!(watchers[0]["id"].as_u64() < watchers[1]["id"].as_u64(), "oldest first");
    assert_eq!(watchers[0]["query"].as_array().unwrap().len(), 0);
    assert_eq!(watchers[1]["query"][0], "_shelly._tcp.local");
    assert!(watchers[1].get("interval_s").is_none(), "there is no interval to say");

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
    let seg = interface("wifi");
    announce(&seg, "10.0.1.7", "tv.local", "TV");
    let tv = seg.devices().remove(0);
    let line = |event| notice_json("IoT", &Notice { interface: "wifi".into(), event, ttl: Duration::from_secs(120) });
    for (event, said) in [
        (added(tv.clone()), "added"),
        (updated(tv.clone()), "updated"),
        (removed(tv.clone()), "removed"),
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
    let live = bind(path.to_str().unwrap(), 0o660).expect("stale socket is replaced");
    assert!(bind(path.to_str().unwrap(), 0o660).is_err(), "live instance is protected");
    drop(live);
    fs::remove_file(&path).unwrap();

    fs::write(&path, "precious").unwrap();
    assert!(bind(path.to_str().unwrap(), 0o660).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "precious");
    fs::remove_file(&path).unwrap();
}
