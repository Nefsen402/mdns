//! What comes out on the far side, judged.
//!
//! The fuzzer only ever sends bogus devices and canaries, so in any response
//! the daemon sends on the far side, every record must be a canary's (or one
//! a canary's service brings with it). Anything else is a bogus device that
//! got through. Queries are the daemon's own questions, not devices, and are
//! not judged.

use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::bogus::{canary_host, canary_instance, Category};
use crate::parser::{Message, RData, Record};

/// More distinct flood devices than this getting through is a failure: one
/// sender must not be able to fill the other side.
pub const FLOOD_LIMIT: usize = 64;

pub struct Violation {
    /// What the input was meant to break, if it can be told.
    pub category: Option<Category>,
    /// The daemon stopped reflecting, or running, rather than reflected
    /// something it should not have.
    pub liveness: bool,
    /// The input that taught the daemon the leaked name, if it can be told.
    pub input: Option<u64>,
    pub what: String,
}

pub struct Canary {
    pub sent: Instant,
    pub seen: Option<Instant>,
}

#[derive(Default)]
pub struct Ledger {
    pub canaries: HashMap<u64, Canary>,
    canary_hosts: HashMap<String, u64>,
    canary_instances: HashSet<String>,
    /// Every name a bogus input taught the daemon, in lowercase, and which
    /// input and what kind it was.
    bogus: HashMap<String, (Category, u64)>,
    pub violations: Vec<Violation>,
    /// The leaks already reported, so that one is reported once however
    /// often the daemon repeats it.
    reported: HashSet<String>,
    floods: HashSet<String>,
    pub packets: u64,
}

impl Ledger {
    pub fn canary_sent(&mut self, k: u64) {
        self.canary_hosts.insert(canary_host(k).to_ascii_lowercase(), k);
        self.canary_instances.insert(canary_instance(k).to_ascii_lowercase());
        self.canaries.entry(k).or_insert(Canary { sent: Instant::now(), seen: None });
    }

    /// Remember the names in bogus input `id`, as the daemon read them: of
    /// its hosts and instances, which are its own. Not the owner of a PTR,
    /// a service type, which every device of that type has.
    pub fn bogus_sent(&mut self, id: u64, category: Category, bytes: &[u8]) {
        let Ok(msg) = Message::parse(bytes) else { return };
        for rec in msg.records() {
            let own = match &rec.data {
                RData::Ptr(target) => vec![target.as_str()],
                _ => names(rec),
            };
            for name in own {
                self.bogus.entry(name.to_ascii_lowercase()).or_insert((category, id));
            }
        }
    }

    pub fn fail(&mut self, category: Option<Category>, input: Option<u64>, what: String) {
        self.violations.push(Violation { category, liveness: false, input, what });
    }

    /// The daemon stopped reflecting, or running; `last` was the last input.
    pub fn stalled(&mut self, last: Option<u64>, what: String) {
        self.violations.push(Violation { category: None, liveness: true, input: last, what });
    }

    fn judge(&mut self, packet: &[u8]) {
        self.packets += 1;
        let msg = match Message::parse(packet) {
            Ok(msg) => msg,
            Err(e) => return self.fail(None, None, format!("the daemon sent a packet it cannot parse itself ({e})")),
        };
        if !msg.header.response {
            return;
        }
        for rec in msg.records() {
            if let Some(&k) = self.canary_hosts.get(&rec.name.to_ascii_lowercase()) {
                if rec.ttl > 0
                    && matches!(rec.data, RData::A(_))
                    && let Some(c) = self.canaries.get_mut(&k)
                {
                    c.seen.get_or_insert(Instant::now());
                }
                continue;
            }
            if self.allowed(rec) {
                continue;
            }
            // The most particular name first: for a PTR, the instance.
            let origin = names(rec).iter().rev().find_map(|n| self.bogus.get(&n.to_ascii_lowercase()).copied());
            if let Some((Category::Flood, _)) = origin {
                // A device is counted by its address record.
                let device = matches!(rec.data, RData::A(_) | RData::Aaaa(_));
                if device && self.floods.insert(rec.name.to_ascii_lowercase()) && self.floods.len() == FLOOD_LIMIT + 1 {
                    self.fail(Some(Category::Flood), None, format!("more than {FLOOD_LIMIT} flood devices from one sender got through"));
                }
                continue;
            }
            let shown = format!("{} {:?}", rec.name, rec.data);
            if self.reported.insert(shown.clone()) {
                let what = format!("got through: {shown} (ttl {})", rec.ttl);
                self.fail(origin.map(|o| o.0), origin.map(|o| o.1), what);
            }
        }
    }

    /// A record a canary brings with it, other than its own: its service's
    /// browse PTR, and the type enumeration.
    fn allowed(&self, rec: &Record) -> bool {
        let name = rec.name.to_ascii_lowercase();
        match &rec.data {
            RData::Ptr(target) => {
                let target = target.to_ascii_lowercase();
                // The type enumeration names types, not devices: a device
                // that got through is caught by its own records.
                (name == "_http._tcp.local" && self.canary_instances.contains(&target))
                    || name == "_services._dns-sd._udp.local"
            }
            _ => self.canary_instances.contains(&name),
        }
    }
}

/// The names a record is about: its own, and those it points at.
fn names(rec: &Record) -> Vec<&str> {
    let mut out = vec![rec.name.as_str()];
    match &rec.data {
        RData::Ptr(target) | RData::Srv { target, .. } => out.push(target),
        _ => {}
    }
    out
}

/// Judge every packet `socket` hears, until the ledger says to stop.
pub fn watch(socket: UdpSocket, ledger: Arc<Mutex<Ledger>>, stop: Arc<std::sync::atomic::AtomicBool>) {
    let mut buf = [0u8; 9000];
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            ledger.lock().unwrap().judge(&buf[..n]);
        }
    }
}
