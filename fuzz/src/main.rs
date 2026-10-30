//! A fuzzer for the reflector, from the outside.
//!
//! It builds the daemon on its own (a debug build, so that overflow checks
//! and debug assertions are on), runs it in a network namespace of its own
//! with one segment of two interfaces, and sends nothing but bogus devices on
//! one: unparseable packets, impossible names and addresses, floods. None of
//! them may come out on the other. Among them go canaries, well-formed
//! devices that must come out, within a few seconds, to show that the daemon
//! is still alive and reflecting. Every other canary speaks only IPv6, and
//! every canary has to come out over both families.
//!
//! It needs no privileges: it runs itself in a user namespace (`unshare -rn`)
//! and the daemon in a network namespace within that.
//!
//! ```text
//! cargo run --release -- [--seed N] [--duration SECS] [--rate PACKETS_PER_SEC]
//!                        [--only unparseable,names,addresses,floods]
//!                        [--stop-on-first] [--daemon PATH]
//! ```
//!
//! Each run is logged to `target/fuzz-runs/<seed>/`: every input sent, the
//! daemon's own log, and the failures with the inputs that caused them.

#[path = "../../src/parser.rs"]
#[allow(dead_code)]
mod parser;

mod bogus;
mod net;
mod watch;
mod wire;

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use bogus::{Category, Generator};
use watch::Ledger;

/// Which part of the fuzzer this process is, by this variable: unset outside,
/// `fuzzer` in the user namespace, `router` where the daemon runs.
const STAGE: &str = "MDNS_FUZZ_STAGE";
const DAEMON: &str = "MDNS_FUZZ_DAEMON";
const CONFIG: &str = "MDNS_FUZZ_CONFIG";

/// How often a canary is sent, and how long it may take to come out.
const CANARY_EVERY: Duration = Duration::from_secs(1);
const CANARY_RESEND: Duration = Duration::from_secs(2);
const CANARY_TIMEOUT: Duration = Duration::from_secs(6);

/// Flood devices sent at once, every so often.
const FLOOD_BURST: usize = 250;
const FLOOD_EVERY: Duration = Duration::from_secs(5);

/// Time for late reflections after the last input.
const GRACE: Duration = Duration::from_secs(3);

const TICK: Duration = Duration::from_millis(10);

struct Options {
    seed: u64,
    duration: Duration,
    rate: u32,
    only: Vec<Category>,
    stop_on_first: bool,
    daemon: Option<PathBuf>,
}

fn main() -> ExitCode {
    let stage = std::env::var(STAGE).unwrap_or_default();
    if stage == "router" {
        return router();
    }
    let opts = match options(std::env::args().skip(1)) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("mdns-fuzz: {e}");
            eprintln!(
                "usage: mdns-fuzz [--seed N] [--duration SECS] [--rate PACKETS_PER_SEC]\n                 \
                 [--only unparseable,names,addresses,floods] [--stop-on-first] [--daemon PATH]"
            );
            return ExitCode::from(2);
        }
    };
    let result = if stage == "fuzzer" { fuzz(&opts) } else { outside(&opts) };
    result.unwrap_or_else(|e| {
        eprintln!("mdns-fuzz: {e}");
        ExitCode::FAILURE
    })
}

fn options(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let mut opts = Options {
        seed: now.as_nanos() as u64 % 1_000_000_007,
        duration: Duration::from_secs(60),
        rate: 200,
        only: Category::ALL.to_vec(),
        stop_on_first: false,
        daemon: None,
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|_| format!("{arg}: not a number: {v}"));
        match arg.as_str() {
            "--seed" => opts.seed = number(value()?)?,
            "--duration" => opts.duration = Duration::from_secs(number(value()?)?),
            "--rate" => opts.rate = number(value()?)?.clamp(1, 100_000) as u32,
            "--only" => {
                opts.only = value()?
                    .split(',')
                    .map(|c| Category::from_label(c).ok_or_else(|| format!("no such category: {c}")))
                    .collect::<Result<_, _>>()?;
            }
            "--stop-on-first" => opts.stop_on_first = true,
            "--daemon" => opts.daemon = Some(PathBuf::from(value()?)),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(opts)
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Build the daemon, then run the rest in a user and network namespace.
fn outside(opts: &Options) -> Result<ExitCode, String> {
    let daemon = match &opts.daemon {
        Some(path) => path.clone(),
        None => {
            let target = repo().join("target/fuzz-daemon");
            eprintln!("mdns-fuzz: building the daemon (debug, with overflow checks) in {}", target.display());
            let status = Command::new(env!("CARGO"))
                .args(["build", "--bin", "mdns", "--manifest-path"])
                .arg(repo().join("Cargo.toml"))
                .arg("--target-dir")
                .arg(&target)
                .status()
                .map_err(|e| format!("running cargo: {e}"))?;
            if !status.success() {
                return Err("building the daemon failed".into());
            }
            target.join("debug/mdns")
        }
    };
    let daemon = daemon.canonicalize().map_err(|e| format!("{}: {e}", daemon.display()))?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let e = Command::new("unshare").args(["-r", "-n", "--"]).arg(me).args(std::env::args().skip(1)).env(STAGE, "fuzzer").env(DAEMON, daemon).exec();
    Err(format!("running unshare: {e}"))
}

/// In the daemon's namespace: take over its interfaces, and become it.
fn router() -> ExitCode {
    if let Err(e) = net::take_over() {
        eprintln!("mdns-fuzz router: {e}");
        return ExitCode::FAILURE;
    }
    let daemon = std::env::var_os(DAEMON).unwrap_or_default();
    let e = Command::new(daemon).arg(std::env::var_os(CONFIG).unwrap_or_default()).exec();
    eprintln!("mdns-fuzz router: running the daemon: {e}");
    ExitCode::FAILURE
}

/// One input sent, kept to say what caused a failure.
struct Input {
    category: Category,
    what: String,
    v6: bool,
    bytes: Vec<u8>,
}

fn fuzz(opts: &Options) -> Result<ExitCode, String> {
    let run = repo().join("target/fuzz-runs").join(opts.seed.to_string());
    std::fs::create_dir_all(&run).map_err(|e| format!("{}: {e}", run.display()))?;
    let run = run.canonicalize().map_err(|e| e.to_string())?;
    let socket = run.join("mdnsd.sock");
    let _ = std::fs::remove_file(&socket);
    let config = run.join("mdnsd.conf");
    std::fs::write(
        &config,
        format!("[Ipc]\nSocket={}\n\n[Segment]\nName=fuzz\nInterfaces={},{}\n", socket.display(), net::DAEMON_A, net::DAEMON_B),
    )
    .map_err(|e| e.to_string())?;

    net::make_links().map_err(|e| format!("making the links: {e}"))?;
    let log = File::create(run.join("daemon.log")).map_err(|e| e.to_string())?;
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut daemon = Command::new("unshare")
        .args(["-n", "--"])
        .arg(me)
        .env(STAGE, "router")
        .env(CONFIG, &config)
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| format!("starting the daemon's namespace: {e}"))?;
    let result = drive(opts, &run, &socket, &mut daemon);
    let _ = daemon.kill();
    let _ = daemon.wait();
    result
}

fn drive(opts: &Options, run: &Path, socket: &Path, daemon: &mut Child) -> Result<ExitCode, String> {
    net::hand_over(daemon.id()).map_err(|e| format!("handing over the links: {e}"))?;
    let ready = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        if let Ok(Some(status)) = daemon.try_wait() {
            return Err(format!("the daemon exited before it was ready ({status}); see {}/daemon.log", run.display()));
        }
        if Instant::now() > ready {
            return Err(format!("the daemon was not ready within 10s; see {}/daemon.log", run.display()));
        }
        thread::sleep(TICK);
    }
    let rss_before = rss(daemon.id());

    let ledger = Arc::new(Mutex::new(Ledger::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let mut watchers = Vec::new();
    for v6 in [false, true] {
        let listener = net::listener(net::FUZZ_B, v6).map_err(|e| format!("listening on {}: {e}", net::FUZZ_B))?;
        let (ledger, stop) = (ledger.clone(), stop.clone());
        watchers.push(thread::spawn(move || watch::watch(listener, v6, ledger, stop)));
    }
    let send4 = net::sender(net::FUZZ_A, false).map_err(|e| format!("sending on {}: {e}", net::FUZZ_A))?;
    let send6 = net::sender(net::FUZZ_A, true).map_err(|e| format!("sending on {}: {e}", net::FUZZ_A))?;
    let send = |bytes: &[u8], v6: bool| {
        let (socket, to) = if v6 { &send6 } else { &send4 };
        // A packet too big or refused is just one input fewer.
        let _ = socket.send_to(bytes, to);
    };

    let send_canary = |k: u64| {
        // A packet refused is a canary late, which the ledger will notice.
        if let Ok((socket, to)) = net::sender_from(net::FUZZ_A, bogus::canary_addr(k)) {
            let _ = socket.send_to(&bogus::canary(k), to);
        }
    };

    let mut sent_log = BufWriter::new(File::create(run.join("sent.log")).map_err(|e| e.to_string())?);
    let mut inputs: Vec<Input> = Vec::new();
    let mut generator = Generator::new(opts.seed);
    let flooding = opts.only.contains(&Category::Flood);
    let steady: Vec<Category> = opts.only.iter().copied().filter(|c| *c != Category::Flood).collect();
    let per_tick = (opts.rate as u128 * TICK.as_millis() / 1000).max(1) as usize;

    eprintln!("mdns-fuzz: seed {}, {}s, {} inputs/s, logging to {}", opts.seed, opts.duration.as_secs(), opts.rate, run.display());
    let start = Instant::now();
    let (mut next_canary, mut next_flood) = (start, start + FLOOD_EVERY);
    let mut canary = 0u64;
    let (mut resent, mut late) = (HashSet::new(), HashSet::new());
    let mut exited = None;

    loop {
        let now = Instant::now();
        let feeding = now < start + opts.duration;
        if !feeding && now > start + opts.duration + GRACE {
            break;
        }
        if let Ok(Some(status)) = daemon.try_wait() {
            exited = Some(status);
            ledger.lock().unwrap().stalled(inputs.len().checked_sub(1).map(|i| i as u64), format!("the daemon exited: {status}"));
            break;
        }
        if feeding && now >= next_canary {
            canary += 1;
            ledger.lock().unwrap().canary_sent(canary);
            send_canary(canary);
            next_canary += CANARY_EVERY;
        }
        {
            let mut ledger = ledger.lock().unwrap();
            let mut stalled = Vec::new();
            for (&k, c) in &ledger.canaries {
                let age = now.saturating_duration_since(c.sent);
                if c.seen().is_none() && age > CANARY_RESEND && resent.insert(k) {
                    send_canary(k);
                }
                if c.seen().is_none() && age > CANARY_TIMEOUT && late.insert(k) {
                    let missing = match (c.seen_v4, c.seen_v6) {
                        (None, None) => "either family",
                        (None, Some(_)) => "IPv4",
                        _ => "IPv6",
                    };
                    stalled.push((k, missing));
                }
            }
            for (k, missing) in stalled {
                let last = inputs.len().checked_sub(1).map(|i| i as u64);
                let kind = if bogus::canary_v6(k) { "IPv6-only" } else { "IPv4" };
                let secs = CANARY_TIMEOUT.as_secs();
                ledger.stalled(last, format!("{kind} canary {k} did not come out over {missing} within {secs}s"));
            }
        }
        if feeding {
            if flooding && now >= next_flood {
                for _ in 0..FLOOD_BURST {
                    let input = keep(generator.bogus(Category::Flood), &mut inputs, &mut sent_log, &ledger);
                    send(&input.bytes, input.v6);
                }
                next_flood += FLOOD_EVERY;
            }
            if !steady.is_empty() {
                for _ in 0..per_tick {
                    let category = generator.rng().pick(&steady);
                    let input = keep(generator.bogus(category), &mut inputs, &mut sent_log, &ledger);
                    send(&input.bytes, input.v6);
                }
            }
        }
        if opts.stop_on_first && !ledger.lock().unwrap().violations.is_empty() {
            break;
        }
        thread::sleep(TICK);
    }
    let _ = sent_log.flush();
    stop.store(true, Ordering::Relaxed);
    for w in watchers {
        let _ = w.join();
    }
    let rss_after = if exited.is_none() { rss(daemon.id()) } else { None };

    let ledger = ledger.lock().unwrap();
    report(opts, run, &ledger, &inputs, (rss_before, rss_after))
}

fn report(opts: &Options, run: &Path, ledger: &Ledger, inputs: &[Input], rss: (Option<u64>, Option<u64>)) -> Result<ExitCode, String> {
    let mut sent: BTreeMap<&str, usize> = BTreeMap::new();
    for input in inputs {
        *sent.entry(input.category.label()).or_default() += 1;
    }
    let reflected = ledger.canaries.values().filter(|c| c.seen().is_some()).count();
    let slowest = ledger.canaries.values().filter_map(|c| c.seen().map(|s| s - c.sent)).max().unwrap_or_default();
    let v6 = ledger.canaries.keys().filter(|&&k| bogus::canary_v6(k)).count();
    let sent: Vec<String> = sent.iter().map(|(c, n)| format!("{n} {c}")).collect();
    println!("seed {}: sent {} inputs ({})", opts.seed, inputs.len(), sent.join(", "));
    println!(
        "canaries: {reflected} of {} ({v6} IPv6-only) reflected over both families, the slowest in {:.1}s; {} packets judged on the far side",
        ledger.canaries.len(),
        slowest.as_secs_f64(),
        ledger.packets
    );
    match rss {
        (Some(before), Some(after)) => println!("daemon memory: {before} kB before, {after} kB after"),
        (Some(before), None) => println!("daemon memory: {before} kB before; it was gone after"),
        _ => {}
    }

    let mut failures = File::create(run.join("failures.txt")).map_err(|e| e.to_string())?;
    let mut by_kind: BTreeMap<String, Vec<&watch::Violation>> = BTreeMap::new();
    for v in &ledger.violations {
        let kind = match v.category {
            Some(c) => c.label().to_string(),
            None if v.liveness => "liveness".into(),
            None => "unattributed".into(),
        };
        by_kind.entry(kind).or_default().push(v);
        let input = v.input.and_then(|i| inputs.get(i as usize).map(|input| (i, input)));
        let _ = writeln!(failures, "{}", v.what);
        if let Some((i, input)) = input {
            let _ = writeln!(failures, "  from input {i}: {} ({}, {})\n  {}", input.what, input.category, family(input.v6), hex(&input.bytes));
        }
    }
    for kind in Category::ALL.iter().map(|c| c.label()).chain(["liveness", "unattributed"]) {
        let found = by_kind.get(kind).map_or(&[][..], |v| v.as_slice());
        let always = kind == "liveness" || (kind == "unattributed" && !found.is_empty());
        let tried = always || opts.only.iter().any(|c| c.label() == kind);
        if !tried {
            continue;
        }
        if found.is_empty() {
            println!("ok    {kind}");
            continue;
        }
        if kind == "liveness" {
            println!("FAIL  {kind}: {} failure(s), for example:", found.len());
            for v in found.iter().take(5) {
                match v.input.and_then(|i| inputs.get(i as usize)) {
                    Some(input) => println!("      {} (the last input before: {}, {})", v.what, input.what, family(input.v6)),
                    None => println!("      {}", v.what),
                }
            }
            continue;
        }
        let culprits: HashSet<u64> = found.iter().filter_map(|v| v.input).collect();
        let total = inputs.iter().filter(|i| i.category.label() == kind).count();
        if culprits.is_empty() {
            println!("FAIL  {kind}: {} failure(s):", found.len());
        } else {
            println!("FAIL  {kind}: {} of {total} inputs got through, for example:", culprits.len());
        }
        let mut shown = HashSet::new();
        for v in found.iter().filter(|v| shown.insert(v.input.map(|i| &inputs[i as usize].what))).take(5) {
            match v.input.and_then(|i| inputs.get(i as usize)) {
                Some(input) => println!("      {} ({}), {}", input.what, family(input.v6), v.what),
                None => println!("      {}", v.what),
            }
        }
    }
    println!("details: {}/failures.txt, sent.log, daemon.log", run.display());
    Ok(if ledger.violations.is_empty() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// Keep bogus input `b`: log it, tell the ledger the names in it, and add it
/// to `inputs`, which it is then the last of.
fn keep<'a>(b: bogus::Bogus, inputs: &'a mut Vec<Input>, log: &mut impl Write, ledger: &Mutex<Ledger>) -> &'a Input {
    let id = inputs.len() as u64;
    ledger.lock().unwrap().bogus_sent(id, b.category, &b.bytes);
    let _ = writeln!(log, "{id}\t{}\t{}\t{}\t{}", b.category, family(b.v6), b.what, hex(&b.bytes));
    inputs.push(Input { category: b.category, what: b.what, v6: b.v6, bytes: b.bytes });
    inputs.last().expect("just pushed")
}

/// How much memory process `pid` has resident, in kB.
fn rss(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn family(v6: bool) -> &'static str {
    if v6 { "IPv6" } else { "IPv4" }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
