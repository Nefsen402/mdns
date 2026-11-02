//! systemd-style (INI) configuration.
//!
//! ```ini
//! [Listen]            ; optional
//! IPv4=yes
//! IPv6=yes
//!
//! [Ipc]               ; optional
//! Socket=/run/mdnsd/mdnsd.sock
//!
//! [Probe]             ; optional
//! RefreshBefore=30s
//! ProbeInterval=4min  ; off unless set
//!
//! [Advertise]         ; optional
//! Hostname=router.local
//!
//! [Segment]
//! Name=media_stuff
//! Interfaces=br0,media
//!
//! [Segment]
//! Name="IoT"
//! Interfaces=wifi
//! ProbeInterval=1min  ; [Probe] ProbeInterval= unless set
//! ForwardQuestions=unknown  ; always, unknown or never; always unless set
//!
//! [Interface]         ; optional: without a Name=, for every interface
//! MaxAddresses=8      ; 8 unless set
//!
//! [Interface]         ; optional, for each interface that needs its own
//! Name=wifi
//! MinimumLifetime=1h  ; 5min unless set
//! ```
//!
//! Each `[Segment]` is a group of interfaces whose devices are reflected
//! between every pair of them; a segment of one interface only tracks. An
//! interface may appear in several segments, which is how `br0` can see both
//! `media` and `wifi` while those two never see each other.
//!
//! Section and key names are case-insensitive. Like systemd, `#` and `;`
//! start comment lines, repeated keys append (an empty assignment resets),
//! and values may be quoted. Interface lists are separated by commas or
//! whitespace.

use core::fmt;
use core::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::runtime::Why;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const DEFAULT_PATH: &str = "/etc/mdnsd.conf";
pub const DEFAULT_SOCKET: &str = "/run/mdnsd/mdnsd.sock";

/// Probing more often than this would be a flood, not a probe.
const MIN_PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// How long before a device would expire it is asked to answer again.
pub const DEFAULT_REFRESH_BEFORE: Duration = Duration::from_secs(30);

/// A smaller margin would have devices asked about almost as soon as they
/// were heard from, which is no use to anyone.
const MIN_REFRESH_BEFORE: Duration = Duration::from_secs(30);

/// How long the address records of the advertised name are cached by others.
/// Two minutes is the usual for host names (Avahi used it for `router.local`).
pub const DEFAULT_ADVERTISE_TTL: Duration = Duration::from_secs(120);

/// Names are re-announced at 80% of their TTL, so a shorter one would be a flood.
const MIN_HOST_TTL: Duration = Duration::from_secs(10);

/// A longer one is a typo, and a name would outlive its host for a day.
const MAX_HOST_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// A longer floor than this is a typo: it would keep devices that are long
/// gone, and a silly one (`99999999999999s`) would overflow the clock.
const MAX_MIN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The default for how long a device is kept at least after it was last heard
/// from, whatever TTLs it announced. See [`Segment::set_min_lifetime`].
pub const DEFAULT_MIN_LIFETIME: Duration = Duration::from_secs(300);

/// The default for how many addresses of a family a device is kept with:
/// enough for a global and a ULA address, a few temporary ones, and a
/// link-local one. See `[Interface] MaxAddresses=`.
pub const DEFAULT_MAX_ADDRS: usize = 8;

/// Which of the questions asked on one of a reflector's segments it puts to
/// the others (`ForwardQuestions=`). Never a probe, nor one about a name a
/// device on the asking segment owns: it answers for itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Forward {
    /// Every one. A browse for a type that one device was heard to have can
    /// have other answers still, from devices that only answer when asked.
    #[default]
    Always,
    /// Those that nothing announced on the asking segment has an answer to.
    Unknown,
    /// None: only what devices announce, or answer a probe with, is reflected.
    Never,
}

/// Which of the addresses a device was given from the neighbour table a
/// reflector reflects with it (`NeighbourAddresses=`). They are learned, and
/// listed, whichever.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Neighbours {
    /// All of them, of any family: a device that announced only an IPv4
    /// address is reflected with its IPv6 ones too.
    Always,
    /// Those of a family the device announced a link-local address of: it
    /// speaks that family, if only on its own link.
    #[default]
    LinkLocal,
    /// None: only what devices announce.
    Never,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SegmentConfig {
    pub name: String,
    pub interfaces: Vec<String>,
    /// Interfaces of the segment that are announced nothing: their devices
    /// are announced to the others, but not the others' to them.
    pub untrusted: Vec<String>,
    /// How often to probe its interfaces for devices: `None` follows
    /// `[Probe] ProbeInterval=`, and `Some(None)` is off for this segment.
    pub probe_interval: Option<Option<Duration>>,
    /// Which questions asked on one of its interfaces are put to the others.
    pub forward: Forward,
    /// Which of the addresses a device was given from the neighbour table are
    /// reflected with it.
    pub neighbour_addresses: Neighbours,
    /// Whether what is reflected onto its interfaces is announced again
    /// before its TTL runs out though it has not changed.
    pub reannounce: bool,
    /// The TTL of the address records of the devices it reflects; `None`
    /// (the default) announces each with the TTL it announced itself with.
    pub reflect_ttl: Option<Duration>,
}

/// What is set for one interface, whichever segments it is in, or, without a
/// name, for every interface that has no setting of its own. Each setting
/// that is `None` is left to the nameless section, and then to its default.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: Option<String>,
    /// The least a device heard on it is kept after it was last heard from,
    /// whatever TTLs it announced: the default is [`DEFAULT_MIN_LIFETIME`],
    /// and zero keeps it for exactly its longest TTL.
    pub min_lifetime: Option<Duration>,
    /// How many addresses of a family a device heard on it is kept with, at
    /// most: the default is [`DEFAULT_MAX_ADDRS`].
    pub max_addrs: Option<usize>,
}

#[derive(Debug)]
pub struct Config {
    pub segments: Vec<SegmentConfig>,
    pub interface_settings: Vec<InterfaceConfig>,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Where the IPC server listens.
    pub socket: String,
    /// A `.local` name to announce and answer for with this host's own
    /// addresses on every interface.
    pub advertise: Option<String>,
    /// The TTL of the advertised name's address records, which it is
    /// re-announced at 80% of.
    pub advertise_ttl: Duration,
    /// How often to probe the interfaces of segments that do not set their
    /// own; `None` (the default) probes only at startup and on request. See
    /// [`Config::probe_interval_of`].
    pub probe_interval: Option<Duration>,
    /// How long before a device would expire to ask it to answer again;
    /// `None` leaves that to the periodic probe.
    pub refresh_before: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            segments: Vec::new(),
            interface_settings: Vec::new(),
            ipv4: true,
            ipv6: true,
            socket: DEFAULT_SOCKET.to_string(),
            advertise: None,
            advertise_ttl: DEFAULT_ADVERTISE_TTL,
            probe_interval: None,
            refresh_before: Some(DEFAULT_REFRESH_BEFORE),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let text = read_to_string(path).with_context(|| format!("reading {path}"))?;
        Self::parse(&text).with_context(|| format!("parsing {path}"))
    }

    /// Every interface named by any segment, once each, in first-seen order.
    pub fn interfaces(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for iface in self.segments.iter().flat_map(|s| &s.interfaces) {
            if !out.contains(&iface.as_str()) {
                out.push(iface);
            }
        }
        out
    }

    /// How often to probe `interface` for devices: as often as the most
    /// frequent of the segments it is in asks, each its own `ProbeInterval=`
    /// or else the one in `[Probe]`; `None` if none of them probes.
    pub fn probe_interval_of(&self, interface: &str) -> Option<Duration> {
        self.segments
            .iter()
            .filter(|seg| seg.interfaces.iter().any(|i| i == interface))
            .filter_map(|seg| seg.probe_interval.unwrap_or(self.probe_interval))
            .min()
    }

    /// A setting of `interface`: the one in its own `[Interface]`, or else the
    /// one in the `[Interface]` without a name.
    fn setting_of<T>(&self, interface: &str, get: impl Fn(&InterfaceConfig) -> Option<T>) -> Option<T> {
        let named = |i: &&InterfaceConfig| i.name.as_deref() == Some(interface);
        let all = |i: &&InterfaceConfig| i.name.is_none();
        let own = self.interface_settings.iter().find(named).and_then(&get);
        own.or_else(|| self.interface_settings.iter().find(all).and_then(&get))
    }

    /// The least a device heard on `interface` is kept after it was last
    /// heard from: its `MinimumLifetime=`, or else [`DEFAULT_MIN_LIFETIME`].
    pub fn min_lifetime_of(&self, interface: &str) -> Duration {
        self.setting_of(interface, |i| i.min_lifetime).unwrap_or(DEFAULT_MIN_LIFETIME)
    }

    /// How many addresses of a family a device heard on `interface` is kept
    /// with, at most: its `MaxAddresses=`, or else [`DEFAULT_MAX_ADDRS`].
    pub fn max_addrs_of(&self, interface: &str) -> usize {
        self.setting_of(interface, |i| i.max_addrs).unwrap_or(DEFAULT_MAX_ADDRS)
    }

    /// Whether what is announced on `interface` is announced again though it
    /// has not changed: if any of its segments says so.
    pub fn reannounce_on(&self, interface: &str) -> bool {
        self.segments.iter().any(|seg| seg.reannounce && seg.interfaces.iter().any(|i| i == interface))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let unit = parse_unit(text)?;
        let mut config = Config::default();
        // Header line of each [Segment] and [Interface], for error messages.
        let mut segment_lines = Vec::new();
        let mut interface_lines = Vec::new();

        for section in &unit.sections {
            let name = section.name.to_ascii_lowercase();
            if name == "segment" {
                config.segments.push(SegmentConfig::default());
                segment_lines.push(section.line);
            }
            if name == "interface" {
                config.interface_settings.push(InterfaceConfig::default());
                interface_lines.push(section.line);
            }

            for entry in &section.entries {
                let key = entry.key.to_ascii_lowercase();
                let lineno = entry.line;
                let value = entry.unquoted().to_string();

                match (name.as_str(), key.as_str()) {
                    ("segment", "name") => {
                        config.segments.last_mut().unwrap().name = value;
                    }
                    ("segment", "interfaces") => {
                        let list = &mut config.segments.last_mut().unwrap().interfaces;
                        if value.is_empty() {
                            list.clear();
                        } else {
                            list.extend(
                                value
                                    .split(|c: char| c == ',' || c.is_whitespace())
                                    .filter(|s| !s.is_empty())
                                    .map(String::from),
                            );
                        }
                    }
                    ("segment", "untrusted") => {
                        let list = &mut config.segments.last_mut().unwrap().untrusted;
                        if value.is_empty() {
                            list.clear();
                        } else {
                            list.extend(
                                value
                                    .split(|c: char| c == ',' || c.is_whitespace())
                                    .filter(|s| !s.is_empty())
                                    .map(String::from),
                            );
                        }
                    }
                    ("segment", "probeinterval") => {
                        let interval = parse_span(&value, lineno, "ProbeInterval", MIN_PROBE_INTERVAL)?;
                        config.segments.last_mut().unwrap().probe_interval = Some(interval);
                    }
                    ("interface", "name") => {
                        config.interface_settings.last_mut().unwrap().name = Some(value).filter(|v| !v.is_empty());
                    }
                    ("interface", "maxaddresses") => {
                        config.interface_settings.last_mut().unwrap().max_addrs = Some(parse_max_addrs(&value, lineno)?);
                    }
                    ("interface", "minimumlifetime") => {
                        config.interface_settings.last_mut().unwrap().min_lifetime = Some(parse_lifetime(&value, lineno)?);
                    }
                    ("segment", "neighbouraddresses") => {
                        config.segments.last_mut().unwrap().neighbour_addresses = parse_neighbours(&value, lineno)?;
                    }
                    ("segment", "reannounce") => {
                        config.segments.last_mut().unwrap().reannounce = !value.is_empty() && parse_bool(entry, lineno)?;
                    }
                    ("segment", "reflectttl") => {
                        config.segments.last_mut().unwrap().reflect_ttl = match value.to_ascii_lowercase().as_str() {
                            "auto" | "" => None,
                            _ => Some(parse_host_ttl(&value, lineno, "ReflectTTL")?),
                        };
                    }
                    ("segment", "forwardquestions") => {
                        config.segments.last_mut().unwrap().forward = parse_forward(&value, lineno)?;
                    }
                    ("listen", "ipv4") => config.ipv4 = parse_bool(entry, lineno)?,
                    ("listen", "ipv6") => config.ipv6 = parse_bool(entry, lineno)?,
                    ("probe", "probeinterval") => {
                        config.probe_interval = parse_span(&value, lineno, "ProbeInterval", MIN_PROBE_INTERVAL)?;
                    }
                    ("probe", "interval") => bail!("line {lineno}: Interval= is now called ProbeInterval="),
                    ("devices", "minimumlifetime") => {
                        bail!("line {lineno}: MinimumLifetime= is now a setting of [Interface]")
                    }
                    ("devices", "maxaddresses") => {
                        bail!("line {lineno}: MaxAddresses= is now a setting of [Interface]")
                    }
                    ("probe", "refreshbefore") => {
                        config.refresh_before = parse_span(&value, lineno, "RefreshBefore", MIN_REFRESH_BEFORE)?;
                    }
                    ("advertise", "hostname") => {
                        config.advertise = Some(local_name(&value, lineno)?);
                    }
                    ("advertise", "ttl") => config.advertise_ttl = parse_host_ttl(&value, lineno, "TTL")?,
                    ("ipc", "socket") => {
                        if value.is_empty() {
                            bail!("line {lineno}: Socket= needs a path");
                        }
                        config.socket = value;
                    }
                    (s, k) => bail!("line {lineno}: unknown setting {k:?} in [{s}]"),
                }
            }
        }

        config.validate(&segment_lines, &interface_lines)?;
        Ok(config)
    }

    fn validate(&self, segment_lines: &[usize], interface_lines: &[usize]) -> Result<()> {
        if self.segments.is_empty() {
            bail!("no [Segment] defined");
        }
        if !self.ipv4 && !self.ipv6 {
            bail!("[Listen] IPv4= and IPv6= are both disabled");
        }

        for (i, seg) in self.segments.iter().enumerate() {
            let at = segment_lines[i];
            if seg.name.is_empty() {
                bail!("[Segment] at line {at} has no Name=");
            }
            if seg.interfaces.is_empty() {
                bail!("segment {:?} (line {at}) has no Interfaces=", seg.name);
            }
            if let Some(dup) = seg
                .interfaces
                .iter()
                .enumerate()
                .find(|(n, iface)| seg.interfaces[..*n].contains(iface))
            {
                bail!("segment {:?} lists interface {} twice", seg.name, dup.1);
            }
            if let Some(stray) = seg.untrusted.iter().find(|u| !seg.interfaces.contains(u)) {
                bail!("segment {:?} (line {at}) has Untrusted={stray}, which is not in its Interfaces=", seg.name);
            }
            if let Some(dup) = seg.untrusted.iter().enumerate().find(|(n, u)| seg.untrusted[..*n].contains(u)) {
                bail!("segment {:?} lists {} as untrusted twice", seg.name, dup.1);
            }
            if seg.interfaces.len() >= 2 && seg.untrusted.len() == seg.interfaces.len() {
                bail!("segment {:?} (line {at}) has no trusted interface to announce to", seg.name);
            }
            for other in &self.segments[..i] {
                if other.name == seg.name {
                    bail!("two segments are named {:?}", seg.name);
                }
                // Two segments sharing a pair of interfaces would both
                // reflect between them, and each would withdraw the other's
                // announcements.
                let shared: Vec<&str> = seg
                    .interfaces
                    .iter()
                    .filter(|iface| other.interfaces.contains(iface))
                    .map(String::as_str)
                    .collect();
                if shared.len() >= 2 {
                    bail!(
                        "segments {:?} and {:?} both reflect between {}",
                        other.name,
                        seg.name,
                        shared.join(" and ")
                    );
                }
            }
        }
        for (i, setting) in self.interface_settings.iter().enumerate() {
            let at = interface_lines[i];
            let Some(name) = &setting.name else {
                if self.interface_settings[..i].iter().any(|other| other.name.is_none()) {
                    bail!("[Interface] at line {at} has no Name=, like an earlier one: only one can be for every interface");
                }
                continue;
            };
            if !self.segments.iter().any(|seg| seg.interfaces.contains(name)) {
                bail!("[Interface] {name} (line {at}) is not in the Interfaces= of any segment");
            }
            if self.interface_settings[..i].iter().any(|other| other.name.as_ref() == Some(name)) {
                bail!("two [Interface] sections are named {name}");
            }
        }
        Ok(())
    }
}

/// A name to advertise: a hostname under `.local`. A bare label such as
/// `router` means `router.local`.
fn local_name(value: &str, lineno: usize) -> Result<String> {
    if value.is_empty() {
        bail!("line {lineno}: Hostname= needs a name");
    }
    let name = if value.contains('.') { value.to_string() } else { format!("{value}.local") };
    if !name.to_ascii_lowercase().ends_with(".local") {
        bail!("line {lineno}: {name:?} is not under .local, the only domain mDNS answers for");
    }
    for label in name.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !ok {
            bail!("line {lineno}: {name:?} is not a valid hostname (label {label:?})");
        }
    }
    if name.len() > 253 {
        bail!("line {lineno}: {name:?} is too long");
    }
    Ok(name)
}

/// A systemd time span such as `4min`, `1.5h` or `1h 30min`; one that adds
/// up to zero (`0`, `0s`) is `Duration::ZERO`.
fn timespan(value: &str, lineno: usize, key: &str) -> Result<Duration> {
    parse_timespan(value).map_err(|e| anyhow!("line {lineno}: invalid {key} {value:?}: {e}"))
}

/// How many addresses of a family a device is kept with: a number, at least
/// one, or `infinity` for no limit at all.
fn parse_max_addrs(value: &str, lineno: usize) -> Result<usize> {
    if value.eq_ignore_ascii_case("infinity") {
        return Ok(usize::MAX);
    }
    value
        .parse()
        .ok()
        .filter(|&n| n >= 1)
        .ok_or_else(|| anyhow!("line {lineno}: MaxAddresses= must be a number of at least 1, or infinity, not {value:?}"))
}

/// The minimum lifetime of a device: a time span, where zero means no minimum.
fn parse_lifetime(value: &str, lineno: usize) -> Result<Duration> {
    let span = timespan(value, lineno, "MinimumLifetime")?;
    if span > MAX_MIN_LIFETIME {
        bail!("line {lineno}: MinimumLifetime= must be at most {} hours", MAX_MIN_LIFETIME.as_secs() / 3600);
    }
    Ok(span)
}

/// The TTL of the address records of a name we announce: a time span between
/// the limits.
fn parse_host_ttl(value: &str, lineno: usize, key: &str) -> Result<Duration> {
    let span = timespan(value, lineno, key)?;
    if span < MIN_HOST_TTL || span > MAX_HOST_TTL {
        bail!(
            "line {lineno}: {key}= must be between {} seconds and {} hours",
            MIN_HOST_TTL.as_secs(),
            MAX_HOST_TTL.as_secs() / 3600
        );
    }
    Ok(span)
}

/// A time span setting called `key`, with `0`, `off` or `infinity` meaning
/// never, and at least `min`.
fn parse_span(value: &str, lineno: usize, key: &str, min: Duration) -> Result<Option<Duration>> {
    if matches!(value.to_ascii_lowercase().as_str(), "off" | "infinity") {
        return Ok(None);
    }
    let span = timespan(value, lineno, key)?;
    if span.is_zero() {
        return Ok(None);
    }
    if span < min {
        bail!("line {lineno}: {key}= must be at least {} seconds", min.as_secs());
    }
    Ok(Some(span))
}

fn parse_neighbours(value: &str, lineno: usize) -> Result<Neighbours> {
    match value.to_ascii_lowercase().as_str() {
        "always" => Ok(Neighbours::Always),
        // An empty assignment resets, as everywhere.
        "link-local" | "" => Ok(Neighbours::LinkLocal),
        "never" => Ok(Neighbours::Never),
        _ => bail!("line {lineno}: invalid NeighbourAddresses {value:?}: always, link-local or never"),
    }
}

fn parse_forward(value: &str, lineno: usize) -> Result<Forward> {
    match value.to_ascii_lowercase().as_str() {
        // An empty assignment resets, as everywhere.
        "always" | "" => Ok(Forward::Always),
        "unknown" => Ok(Forward::Unknown),
        "never" => Ok(Forward::Never),
        _ => bail!("line {lineno}: invalid ForwardQuestions {value:?}: always, unknown or never"),
    }
}

/// All of the file at `path`, as text.
fn read_to_string(path: &str) -> Result<String> {
    let fd = rustix::fs::open(path, rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::empty()).map_err(Why)?;
    let (mut bytes, mut buf) = (Vec::new(), [0u8; 4096]);
    loop {
        match rustix::io::retry_on_intr(|| rustix::io::read(&fd, &mut buf)).map_err(Why)? {
            0 => break,
            n => bytes.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("not UTF-8 text"))
}

/// A systemd boolean: `1`/`yes`/`true`/`on` or `0`/`no`/`false`/`off`.
fn parse_bool(entry: &Entry, lineno: usize) -> Result<bool> {
    entry.as_bool().ok_or_else(|| anyhow!("line {lineno}: invalid boolean {:?}", entry.unquoted()))
}

// systemd time spans, as `systemd.time(7)` has them: `30`, `1.5h`,
// `2min 30s`, `.5s`. Numbers, each with an optional fraction and an optional
// unit (seconds if none), added up; whitespace between them, and between a
// number and its unit, is optional. Units are case-sensitive: `m` is
// minutes, `M` months.

const NS_PER_SEC: u128 = 1_000_000_000;

/// Each unit's names, and how many nanoseconds it is. A month and a year are
/// systemd's: 30.44 and 365.25 days.
const UNITS: &[(&[&str], u128)] = &[
    (&["nsec", "ns"], 1),
    (&["usec", "us", "µs", "μs"], 1_000),
    (&["msec", "ms"], 1_000_000),
    (&["seconds", "second", "sec", "s"], NS_PER_SEC),
    (&["minutes", "minute", "min", "m"], 60 * NS_PER_SEC),
    (&["hours", "hour", "hr", "h"], 3_600 * NS_PER_SEC),
    (&["days", "day", "d"], 86_400 * NS_PER_SEC),
    (&["weeks", "week", "w"], 604_800 * NS_PER_SEC),
    (&["months", "month", "M"], 2_629_800 * NS_PER_SEC),
    (&["years", "year", "y"], 31_557_600 * NS_PER_SEC),
];

/// What is wrong with a time span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimespanError {
    /// Nothing but whitespace.
    Empty,
    /// No number where one was due: what was there instead.
    Number(String),
    /// A unit that is not one.
    Unit(String),
    /// More than a `Duration` holds.
    TooLong,
}

impl fmt::Display for TimespanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimespanError::Empty => write!(f, "empty time span"),
            TimespanError::Number(at) => write!(f, "expected a number at {at:?}"),
            TimespanError::Unit(unit) => write!(f, "unknown unit {unit:?}"),
            TimespanError::TooLong => write!(f, "time span too long"),
        }
    }
}

/// The time span `s` adds up to. One that adds up to nothing (`0`, `0s`) is
/// `Duration::ZERO`; a fraction finer than a nanosecond is dropped.
pub fn parse_timespan(s: &str) -> Result<Duration, TimespanError> {
    let mut rest = s.trim();
    if rest.is_empty() {
        return Err(TimespanError::Empty);
    }
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let (whole, after) = digits(rest);
        let (fraction, after) = match after.strip_prefix('.') {
            Some(after) => digits(after),
            None => ("", after),
        };
        if whole.is_empty() && fraction.is_empty() {
            return Err(TimespanError::Number(rest.to_string()));
        }
        // A number straight after a fraction ("1.2.3s") is a typo.
        if after.starts_with('.') {
            return Err(TimespanError::Number(after.to_string()));
        }
        let after = after.trim_start();
        let end = after.find(|c: char| c.is_ascii_digit() || c == '.' || c.is_whitespace()).unwrap_or(after.len());
        let (unit, after) = after.split_at(end);
        let per = match unit {
            "" => NS_PER_SEC,
            _ => UNITS.iter().find(|(names, _)| names.contains(&unit)).map(|&(_, ns)| ns).ok_or_else(|| TimespanError::Unit(unit.into()))?,
        };

        let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| TimespanError::TooLong)? };
        let mut part = whole.checked_mul(per).ok_or(TimespanError::TooLong)?;
        let mut place = per;
        for digit in fraction.bytes() {
            place /= 10;
            part += u128::from(digit - b'0') * place;
        }
        total = total.checked_add(part).ok_or(TimespanError::TooLong)?;
        rest = after.trim_start();
    }
    let secs = u64::try_from(total / NS_PER_SEC).map_err(|_| TimespanError::TooLong)?;
    Ok(Duration::new(secs, (total % NS_PER_SEC) as u32))
}

/// The ASCII digits `s` starts with, and what follows them.
fn digits(s: &str) -> (&str, &str) {
    s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()))
}

// The syntax of systemd unit files, as far as this file uses it: `[Section]`
// headers, `Key=Value` assignments, comment lines starting with `#` or `;`,
// blank lines, a backslash at the end of a line continuing it on the next,
// and values that may be quoted. What the sections and keys mean is for
// [`Config::parse`].

/// A unit file, taken apart.
#[derive(Debug, Default, PartialEq, Eq)]
struct Unit {
    pub sections: Vec<Section>,
}

/// A `[Section]`, and the assignments under it.
#[derive(Debug, PartialEq, Eq)]
struct Section {
    pub name: String,
    /// The line of its header, from 1.
    pub line: usize,
    pub entries: Vec<Entry>,
}

/// A `Key=Value` assignment.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    pub key: String,
    /// As written, after the `=`, its continuation lines joined: quotes and
    /// all.
    pub value: String,
    /// The line it starts on, from 1.
    pub line: usize,
}

impl Entry {
    /// The value without the quotes around it, if it has a matching pair, and
    /// without the whitespace around it.
    pub fn unquoted(&self) -> &str {
        let value = self.value.trim();
        let quoted = value.len() >= 2 && (value.starts_with('"') && value.ends_with('"') || value.starts_with('\'') && value.ends_with('\''));
        if quoted { &value[1..value.len() - 1] } else { value }
    }

    /// The value as one of systemd's booleans, if it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self.unquoted().trim().to_ascii_lowercase().as_str() {
            "1" | "yes" | "true" | "on" => Some(true),
            "0" | "no" | "false" | "off" => Some(false),
            _ => None,
        }
    }
}

/// What is wrong with a unit file, and where.
#[derive(Debug, PartialEq, Eq)]
struct SyntaxError {
    pub line: usize,
    pub message: &'static str,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl core::error::Error for SyntaxError {}

/// Take `text` apart as systemd unit syntax.
fn parse_unit(text: &str) -> Result<Unit, SyntaxError> {
    let mut unit = Unit::default();
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).zip(1..);
    while let Some((line, n)) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(header) = trimmed.strip_prefix('[') {
            let Some(name) = header.strip_suffix(']') else {
                return Err(SyntaxError { line: n, message: "a section header without its closing ]" });
            };
            unit.sections.push(Section { name: name.trim().to_string(), line: n, entries: Vec::new() });
            continue;
        }
        let Some(section) = unit.sections.last_mut() else {
            return Err(SyntaxError { line: n, message: "assignment outside of a section" });
        };
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(SyntaxError { line: n, message: "not an assignment (Key=Value)" });
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(SyntaxError { line: n, message: "an assignment without a key" });
        }
        // A backslash at the end of a line goes on with the next, in place of
        // it a space, unless there is whitespace before it already.
        let mut value = value.trim_start().to_string();
        while let Some(rest) = value.strip_suffix('\\') {
            value = rest.to_string();
            let Some((next, _)) = lines.next() else { break };
            if !value.ends_with([' ', '\t']) {
                value.push(' ');
            }
            value.push_str(next.trim_end());
        }
        section.entries.push(Entry { key: key.to_string(), value: value.trim_end().to_string(), line: n });
    }
    Ok(unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[segment]
name=media_stuff
interfaces=br0,media

[segment]
name="IoT"
interfaces=wifi

[segment]
name="IoT to br0"
interfaces=br0,wifi
"#;

    fn seg(name: &str, interfaces: &[&str]) -> SegmentConfig {
        SegmentConfig {
            name: name.into(),
            interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
            ..SegmentConfig::default()
        }
    }

    #[test]
    fn untrusted_interfaces_are_listed_and_checked() {
        let parse = |extra: &str| Config::parse(&format!("[Segment]\nName=s\nInterfaces=br0,media,wifi\n{extra}"));
        assert!(parse("").unwrap().segments[0].untrusted.is_empty());
        assert_eq!(parse("Untrusted=media").unwrap().segments[0].untrusted, ["media"]);
        // The same kind of list as Interfaces=, with the key in any case.
        assert_eq!(parse("untrusted=media, wifi").unwrap().segments[0].untrusted, ["media", "wifi"]);
        assert_eq!(parse("UNTRUSTED=media\nUntrusted=wifi").unwrap().segments[0].untrusted, ["media", "wifi"]);
        assert!(parse("Untrusted=media\nUntrusted=").unwrap().segments[0].untrusted.is_empty(), "empty resets");

        // Only interfaces of the segment, each once.
        assert!(parse("Untrusted=eth9").unwrap_err().to_string().contains("not in its Interfaces"));
        assert!(parse("Untrusted=media,media").is_err());
        // Someone has to be told about the others.
        assert!(parse("Untrusted=br0,media,wifi").unwrap_err().to_string().contains("no trusted interface"));
        assert!(parse("Untrusted=media,wifi").is_ok());
        // A segment of one interface reflects nothing anyway.
        assert!(Config::parse("[Segment]\nName=s\nInterfaces=wifi\nUntrusted=wifi\n").is_ok());
    }

    #[test]
    fn advertise_is_optional_and_validated() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().advertise, None);

        let with = |value: &str| Config::parse(&format!("[Advertise]\nHostname={value}\n{EXAMPLE}"));
        assert_eq!(with("router.local").unwrap().advertise.as_deref(), Some("router.local"));
        assert_eq!(with("\"My-Router.LOCAL\"").unwrap().advertise.as_deref(), Some("My-Router.LOCAL"));
        // A bare label means that label under .local.
        assert_eq!(with("router").unwrap().advertise.as_deref(), Some("router.local"));

        for bad in ["", "router.lan", "router.example.com", "bad name.local", "a..local", ".local", "ro_uter.local"] {
            assert!(with(bad).is_err(), "should reject {bad:?}");
        }
        assert!(with(&format!("{}.local", "x".repeat(64))).is_err());
        assert!(with(&format!("{}.local", "x".repeat(63))).is_ok());
    }

    #[test]
    fn advertise_ttl_defaults_to_two_minutes_and_is_bounded() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().advertise_ttl, Duration::from_secs(120));

        let with = |value: &str| Config::parse(&format!("[Advertise]\nTTL={value}\n{EXAMPLE}"));
        assert_eq!(with("2min").unwrap().advertise_ttl, Duration::from_secs(120));
        assert_eq!(with("1h").unwrap().advertise_ttl, Duration::from_secs(3600));
        assert_eq!(with("10").unwrap().advertise_ttl, Duration::from_secs(10));
        assert_eq!(with("24h").unwrap().advertise_ttl, Duration::from_secs(86400));
        for bad in ["9s", "0", "", "off", "infinity", "25h", "soon", "99999999999999s"] {
            assert!(with(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn reflect_ttl_follows_the_device_unless_set_and_is_bounded() {
        let segments = |extra: &str| {
            let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=y,z"));
            c.map(|c| (c.segments[0].reflect_ttl, c.segments[1].reflect_ttl))
        };
        let ttl = |value: &str| segments(&format!("ReflectTTL={value}")).map(|(a, _)| a);
        assert_eq!(segments("").unwrap(), (None, None));
        assert_eq!(ttl("auto").unwrap(), None);
        assert_eq!(ttl("AUTO").unwrap(), None);
        assert_eq!(ttl("2min").unwrap(), Some(Duration::from_secs(120)));
        assert_eq!(ttl("30min").unwrap(), Some(Duration::from_secs(1800)));
        assert_eq!(ttl("10").unwrap(), Some(Duration::from_secs(10)));
        assert_eq!(segments("ReflectTTL=5min\nReflectTTL=").unwrap(), (None, None), "empty resets");
        assert_eq!(segments("ReflectTTL=5min").unwrap(), (Some(Duration::from_secs(300)), None), "each its own");
        for bad in ["9s", "0", "off", "infinity", "25h", "soon", "99999999999999s"] {
            assert!(ttl(bad).is_err(), "should reject {bad:?}");
        }
        // It is independent of the advertised name's, and no longer a device setting.
        let c = Config::parse("[Advertise]\nTTL=1h\n[Segment]\nName=a\nInterfaces=x\nReflectTTL=5min").unwrap();
        assert_eq!((c.segments[0].reflect_ttl, c.advertise_ttl), (Some(Duration::from_secs(300)), Duration::from_secs(3600)));
        assert!(error_of(&format!("[Devices]\nReflectTTL=5min\n{EXAMPLE}")).contains("unknown setting"));
    }

    /// The man page must document every key and a config that really parses.
    #[test]
    fn man_page_documents_every_key_and_its_example_parses() {
        let man = include_str!("../man/mdnsd.conf.5");
        for key in [
            "IPv4=", "IPv6=", "Socket=", "MinimumLifetime=", "ProbeInterval=", "RefreshBefore=", "Hostname=", "TTL=",
            "ReflectTTL=", "MaxAddresses=", "Name=", "Interfaces=", "Untrusted=", "ForwardQuestions=", "NeighbourAddresses=",
            "Reannounce=",
        ] {
            assert!(man.contains(&format!(".B {key}")), "{key}");
        }
        assert!(man.contains(DEFAULT_SOCKET));

        let start = man.find("[Listen]\nIPv4").expect("example in the man page");
        let example = &man[start..start + man[start..].find("\n.fi").unwrap()];
        let c = Config::parse(example).unwrap();
        assert_eq!(c.segments.len(), 3);
    }

    #[test]
    fn parses_segments() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(
            c.segments,
            [
                seg("media_stuff", &["br0", "media"]),
                seg("IoT", &["wifi"]),
                seg("IoT to br0", &["br0", "wifi"]),
            ]
        );
        assert_eq!(c.interfaces(), ["br0", "media", "wifi"]);
        assert!(c.ipv4 && c.ipv6);
    }

    #[test]
    fn keys_are_case_insensitive_and_lists_flexible() {
        let c = Config::parse(
            "# c\n[Listen]\nIPv6=no\n[SEGMENT]\nNAME = 'a b'\nInterfaces=x y, z\nInterfaces=w\n",
        )
        .unwrap();
        assert_eq!(c.segments, [seg("a b", &["x", "y", "z", "w"])]);
        assert!(c.ipv4 && !c.ipv6);
    }

    #[test]
    fn ipc_socket_defaults_and_overrides() {
        let c = Config::parse(EXAMPLE).unwrap();
        assert_eq!(c.socket, DEFAULT_SOCKET);
        let c = Config::parse(&format!("[Ipc]\nSocket=\"/tmp/x.sock\"\n{EXAMPLE}")).unwrap();
        assert_eq!(c.socket, "/tmp/x.sock");
        assert!(Config::parse(&format!("[Ipc]\nSocket=\n{EXAMPLE}")).is_err());
    }

    #[test]
    fn empty_assignment_resets_interfaces() {
        let c = Config::parse("[Segment]\nName=a\nInterfaces=x\nInterfaces=\nInterfaces=y\n").unwrap();
        assert_eq!(c.segments[0].interfaces, ["y"]);
    }

    #[test]
    fn overlap_of_a_single_interface_is_fine() {
        assert!(Config::parse("[Segment]\nName=a\nInterfaces=x,y\n[Segment]\nName=b\nInterfaces=x,z\n").is_ok());
    }

    fn error_of(text: &str) -> String {
        format!("{:#}", Config::parse(text).unwrap_err())
    }

    #[test]
    fn syntax_errors_name_their_line() {
        assert!(error_of("[Segment]\nName=a\nInterfaces\n").contains("line 3"), "no '='");
        assert!(error_of("# c\n\nInterfaces=a\n").contains("line 3"), "outside a section");
        assert!(error_of("# c\n\nInterfaces=a\n").contains("assignment outside of a section"));
        assert!(error_of("[Segment\nName=a\n").contains("line 1"), "unterminated header");
    }

    #[test]
    fn semantic_errors_name_their_line() {
        let with = |body: &str| error_of(&format!("\n# comment\n{body}"));
        assert!(with("[Segment]\nName=a\nInterfaces=x\nBogus=1\n").contains("line 6"), "unknown key");
        assert!(with("[Listen]\nIPv4=maybe\n[Segment]\nName=a\nInterfaces=x\n").contains("line 4"), "bad boolean");
        assert!(with("[Segment]\nInterfaces=x\n").contains("line 3"), "segment without a name, at its header");
        assert!(with("[Advertise]\nHostname=router.lan\n").contains("line 4"), "hostname outside .local");
    }

    #[test]
    fn booleans_follow_systemd() {
        let parse = |v: &str| Config::parse(&format!("[Listen]\nIPv4={v}\nIPv6=no\n[Segment]\nName=a\nInterfaces=x\n"));
        for yes in ["1", "yes", "true", "on", "YES", "True", "\"on\""] {
            assert!(parse(yes).unwrap().ipv4, "{yes}");
        }
        for no in ["0", "no", "false", "off", "OFF"] {
            // IPv6=no as well makes both families off, which is its own error.
            assert!(error_of(&format!("[Listen]\nIPv4={no}\nIPv6=no\n[Segment]\nName=a\nInterfaces=x\n")).contains("both disabled"), "{no}");
        }
        assert!(parse("enabled").is_err());
    }

    #[test]
    fn comments_blank_lines_crlf_and_continuations_are_fine() {
        // Comments and blank lines inside a section, and Windows line endings.
        let c = Config::parse("[Segment]\r\n# c\r\nName=a\r\n\r\n; d\r\nInterfaces=x,y\r\n").unwrap();
        assert_eq!(c.segments, [seg("a", &["x", "y"])]);
        // A line ending in a backslash continues on the next, as in unit files.
        let c = Config::parse("[Segment]\nName=a\nInterfaces=x \\\n    y,z\n").unwrap();
        assert_eq!(c.segments[0].interfaces, ["x", "y", "z"]);
        // A value may contain an equals sign.
        let c = Config::parse("[Segment]\nName=a=b\nInterfaces=x\n").unwrap();
        assert_eq!(c.segments[0].name, "a=b");
    }

    /// Each segment forwards every question unless it says otherwise.
    #[test]
    fn forwarding_questions_is_set_per_segment_and_always_by_default() {
        let forward = |extra: &str| {
            let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=z")).unwrap();
            (c.segments[0].forward, c.segments[1].forward)
        };
        assert_eq!(forward(""), (Forward::Always, Forward::Always));
        assert_eq!(forward("ForwardQuestions=Unknown"), (Forward::Unknown, Forward::Always));
        assert_eq!(forward("ForwardQuestions=never"), (Forward::Never, Forward::Always));
        assert_eq!(forward("ForwardQuestions=never\nForwardQuestions="), (Forward::Always, Forward::Always));
        let bad = error_of("[Segment]\nName=a\nInterfaces=x\nForwardQuestions=sometimes");
        assert!(bad.contains("line 4") && bad.contains("ForwardQuestions"), "{bad}");
    }

    /// A config is read from its file, and an error says which file, and,
    /// for what is in it, which line.
    #[test]
    fn a_config_is_loaded_from_its_file() {
        std::fs::create_dir_all("target").unwrap();
        let path = format!("target/config-test-{}.conf", std::process::id());
        std::fs::write(&path, "[Segment]\nName=lan\nInterfaces=eth0\n").unwrap();
        assert_eq!(Config::load(&path).unwrap().segments[0].interfaces, ["eth0"]);

        std::fs::write(&path, "[Segment]\nName=lan\nInterfaces=eth0\nBogus=1\n").unwrap();
        let err = format!("{:#}", Config::load(&path).unwrap_err());
        assert!(err.contains(&format!("parsing {path}")) && err.contains("line 4"), "{err}");
        std::fs::remove_file(&path).unwrap();

        let err = format!("{:#}", Config::load(&path).unwrap_err());
        assert!(err.contains(&format!("reading {path}")), "{err}");
    }

    /// A hostname to advertise is at most 253 bytes, as a DNS name is, even
    /// with every label short enough.
    #[test]
    fn an_advertised_hostname_is_not_too_long() {
        let label = "a".repeat(63);
        let long = format!("{label}.{label}.{label}.{label}.local");
        let err = error_of(&format!("[Advertise]\nHostname={long}\n{EXAMPLE}"));
        assert!(err.contains("line 2") && err.contains("is too long"), "{err}");
        let fits = format!("{label}.{label}.{label}.{}.local", "a".repeat(52));
        assert_eq!(fits.len(), 250);
        assert!(Config::parse(&format!("[Advertise]\nHostname={fits}\n{EXAMPLE}")).is_ok());
    }

    /// Each segment says which addresses from the neighbour table it
    /// reflects; of families a device announced a link-local address of,
    /// unless it says otherwise.
    #[test]
    fn segments_choose_which_neighbour_addresses_to_reflect() {
        let segments = |extra: &str| {
            let c = Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=z")).unwrap();
            (c.segments[0].neighbour_addresses, c.segments[1].neighbour_addresses)
        };
        assert_eq!(segments(""), (Neighbours::LinkLocal, Neighbours::LinkLocal));
        assert_eq!(segments("NeighbourAddresses=always"), (Neighbours::Always, Neighbours::LinkLocal));
        assert_eq!(segments("NeighbourAddresses=Never"), (Neighbours::Never, Neighbours::LinkLocal));
        assert_eq!(segments("neighbouraddresses=never\nNeighbourAddresses="), (Neighbours::LinkLocal, Neighbours::LinkLocal));
        for bad in ["sometimes", "yes", "no"] {
            let err = error_of(&format!("[Segment]\nName=a\nInterfaces=x\nNeighbourAddresses={bad}"));
            assert!(err.contains("line 4") && err.contains("always, link-local or never"), "{err}");
        }
    }

    /// Unchanged devices are not announced again unless a segment says so,
    /// and then on each of its interfaces, shared or not.
    #[test]
    fn a_segment_can_reannounce_unchanged_devices() {
        let config = |extra: &str| {
            Config::parse(&format!("[Segment]\nName=a\nInterfaces=x,y\n{extra}\n[Segment]\nName=b\nInterfaces=y,z")).unwrap()
        };
        let on = |c: &Config| ["x", "y", "z"].map(|i| c.reannounce_on(i));
        assert_eq!(on(&config("")), [false, false, false]);
        assert_eq!(on(&config("Reannounce=yes")), [true, true, false]);
        assert_eq!(on(&config("reannounce=TRUE")), [true, true, false]);
        assert_eq!(on(&config("Reannounce=no")), [false, false, false]);
        assert_eq!(on(&config("Reannounce=yes\nReannounce=")), [false, false, false], "empty resets");
        let err = error_of("[Segment]\nName=a\nInterfaces=x\nReannounce=sometimes");
        assert!(err.contains("line 4"), "{err}");
    }

    #[test]
    fn the_probe_interval_is_off_by_default_and_takes_systemd_time_spans() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().probe_interval, None);

        let with = |v: &str| Config::parse(&format!("[Probe]\nProbeInterval={v}\n{EXAMPLE}"));
        let secs = |v: &str| with(v).unwrap().probe_interval.map(|d| d.as_secs());
        assert_eq!(secs("4min"), Some(240));
        assert_eq!(secs("30s"), Some(30));
        assert_eq!(secs("1h"), Some(3600));
        assert_eq!(secs("1h 30min"), Some(5400));
        assert_eq!(secs("90"), Some(90), "a bare number is seconds");
        assert_eq!(secs("\"10min\""), Some(600));
        for never in ["0", "0s", "0min", "off", "OFF", "infinity"] {
            assert_eq!(secs(never), None, "{never}");
        }
    }

    #[test]
    fn bad_probe_intervals_are_rejected_with_their_line() {
        let with = |v: &str| error_of(&format!("[Probe]\nProbeInterval={v}\n{EXAMPLE}"));
        assert!(with("soon").contains("line 2") && with("soon").contains("invalid ProbeInterval"));
        assert!(with("5s").contains("at least 10 seconds"));
        assert!(with("").contains("line 2"), "an empty value is not a time span");
        assert!(with("3 fortnights").contains("invalid"));
        // The old name says what it is called now.
        let old = error_of(&format!("[Probe]\nInterval=4min\n{EXAMPLE}"));
        assert!(old.contains("line 2") && old.contains("ProbeInterval="), "{old}");
    }

    /// Three segments over br0: one that follows [Probe], one with its own
    /// interval, and one that turns probing off for itself.
    fn probing(probe: &str) -> Config {
        Config::parse(&format!(
            "{probe}
[Segment]
Name=default
Interfaces=br0,lan
[Segment]
Name=often
Interfaces=br0,media
ProbeInterval=1min
[Segment]
Name=quiet
Interfaces=wifi,guest
ProbeInterval=off
"
        ))
        .unwrap()
    }

    #[test]
    fn a_segment_probes_as_often_as_it_says_or_else_as_probe_says() {
        let c = probing("[Probe]\nProbeInterval=4min");
        let secs = |iface: &str| c.probe_interval_of(iface).map(|d| d.as_secs());
        assert_eq!(c.segments.iter().map(|s| s.probe_interval).collect::<Vec<_>>(), [
            None,
            Some(Some(Duration::from_secs(60))),
            Some(None)
        ]);
        assert_eq!(secs("lan"), Some(240), "from [Probe]");
        assert_eq!(secs("media"), Some(60));
        assert_eq!(secs("br0"), Some(60), "in two segments: the more frequent one");
        assert_eq!(secs("wifi"), None, "off for its only segment, whatever [Probe] says");
        assert_eq!(secs("nonesuch"), None);

        // Without [Probe], only the segment that asks is probed.
        let c = probing("");
        assert_eq!(c.probe_interval_of("lan"), None);
        assert_eq!(c.probe_interval_of("br0"), Some(Duration::from_secs(60)));
    }

    #[test]
    fn a_segment_probe_interval_is_checked_like_the_global_one() {
        let with = |v: &str| error_of(&format!("[Segment]\nName=x\nInterfaces=a\nProbeInterval={v}\n"));
        assert!(with("5s").contains("line 4") && with("5s").contains("ProbeInterval= must be at least 10 seconds"));
        assert!(with("soon").contains("invalid ProbeInterval"));
        // The last one counts, and 0 is off.
        let c = Config::parse("[Segment]\nName=x\nInterfaces=a\nProbeInterval=1min\nProbeInterval=0\n").unwrap();
        assert_eq!(c.segments[0].probe_interval, Some(None));
    }

    #[test]
    fn refreshing_before_expiry_defaults_on_and_takes_systemd_time_spans() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().refresh_before, Some(DEFAULT_REFRESH_BEFORE));

        let with = |v: &str| Config::parse(&format!("[Probe]\nRefreshBefore={v}\n{EXAMPLE}"));
        let secs = |v: &str| with(v).unwrap().refresh_before.map(|d| d.as_secs());
        assert_eq!(secs("1min"), Some(60));
        assert_eq!(secs("30s"), Some(30), "the minimum is allowed");
        assert_eq!(secs("45s"), Some(45));
        assert_eq!(secs("10min"), Some(600), "longer than the idle floor is allowed");
        for never in ["0", "off", "infinity"] {
            assert_eq!(secs(never), None, "{never}");
        }
        // It is independent of the periodic probe, in both directions.
        let both = Config::parse(&format!("[Probe]\nProbeInterval=off\nRefreshBefore=2min\n{EXAMPLE}")).unwrap();
        assert_eq!((both.probe_interval, both.refresh_before), (None, Some(Duration::from_secs(120))));

        let err = |v: &str| error_of(&format!("[Probe]\nRefreshBefore={v}\n{EXAMPLE}"));
        assert!(err("20s").contains("RefreshBefore= must be at least 30 seconds"), "{}", err("20s"));
        assert!(err("soon").contains("line 2") && err("soon").contains("invalid RefreshBefore"));
    }

    #[test]
    fn max_addresses_defaults_to_eight_and_has_no_upper_bound() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().max_addrs_of("br0"), DEFAULT_MAX_ADDRS);
        let with = |v: &str| Config::parse(&format!("{EXAMPLE}\n[Interface]\nMaxAddresses={v}"));
        let max = |v: &str| with(v).unwrap().max_addrs_of("br0");
        assert_eq!(max("2"), 2);
        assert_eq!(max("100000"), 100_000);
        assert_eq!(max("infinity"), usize::MAX, "no limit at all");
        assert_eq!(max("Infinity"), usize::MAX);
        for bad in ["0", "-1", "many", ""] {
            let err = error_of(&format!("{EXAMPLE}\n[Interface]\nMaxAddresses={bad}"));
            assert!(err.contains("MaxAddresses="), "{bad:?}: {err}");
        }
    }

    #[test]
    fn an_interface_is_set_its_own_minimum_lifetime_whatever_segments_it_is_in() {
        let c = Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=wifi\nMinimumLifetime=1h\n[Interface]\nName=media\nMinimumLifetime=0"))
            .unwrap();
        let secs = |i: &str| c.min_lifetime_of(i).as_secs();
        assert_eq!((secs("wifi"), secs("media")), (3600, 0), "wifi is in two segments");
        assert_eq!(secs("br0"), 300, "an interface with no section has the default");
        assert_eq!(secs("elsewhere"), 300);
    }

    #[test]
    fn an_interface_section_without_a_name_is_for_every_interface_that_has_none_of_its_own() {
        let c = Config::parse(&format!(
            "{EXAMPLE}\n[Interface]\nMinimumLifetime=1h\nMaxAddresses=4\n[Interface]\nName=wifi\nMinimumLifetime=30s"
        ))
        .unwrap();
        let (secs, max) = (|i: &str| c.min_lifetime_of(i).as_secs(), |i: &str| c.max_addrs_of(i));
        assert_eq!((secs("br0"), secs("media"), secs("wifi")), (3600, 3600, 30));
        // A setting the interface's own section leaves out comes from the one for all.
        assert_eq!((max("br0"), max("wifi")), (4, 4));
        // Whichever comes first.
        let c = Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=wifi\nMaxAddresses=2\n[Interface]\nMaxAddresses=4")).unwrap();
        assert_eq!((c.max_addrs_of("wifi"), c.max_addrs_of("br0")), (2, 4));
        // An empty Name= names nothing, so the section is for every interface.
        assert!(Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=\nMaxAddresses=3")).is_ok(), "an empty Name= is no name");
    }

    #[test]
    fn an_interface_section_names_an_interface_of_a_segment_once() {
        let err = |text: &str| error_of(&format!("{EXAMPLE}\n{text}"));
        assert!(err("[Interface]\nMaxAddresses=2\n[Interface]\nMinimumLifetime=1h").contains("only one can be for every interface"));
        assert!(err("[Interface]\nName=eth9\nMinimumLifetime=1h").contains("not in the Interfaces= of any segment"));
        assert!(err("[Interface]\nName=br0\n[Interface]\nName=br0").contains("two [Interface] sections are named br0"));
        assert!(err("[Interface]\nName=br0\nBogus=1").contains("unknown setting"));
    }

    #[test]
    fn the_settings_that_were_a_devices_are_now_an_interfaces() {
        for key in ["MinimumLifetime=5min", "MaxAddresses=4"] {
            let err = error_of(&format!("[Devices]\n{key}\n{EXAMPLE}"));
            assert!(err.contains("line 2") && err.contains("now a setting of [Interface]"), "{err}");
        }
    }

    #[test]
    fn the_minimum_lifetime_defaults_to_five_minutes_and_takes_systemd_time_spans() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().min_lifetime_of("br0"), Duration::from_secs(300));

        let with = |v: &str| Config::parse(&format!("{EXAMPLE}\n[Interface]\nName=br0\nMinimumLifetime={v}"));
        let secs = |v: &str| with(v).unwrap().min_lifetime_of("br0").as_secs();
        assert_eq!(secs("5min"), 300);
        assert_eq!(secs("90s"), 90);
        assert_eq!(secs("1h"), 3600);
        assert_eq!(secs("1d"), 86400, "the longest allowed");
        assert_eq!(secs("0"), 0, "zero means no minimum: a device lives for exactly its TTL");
        assert_eq!(secs("0s"), 0);

        let err = |v: &str| error_of(&format!("{EXAMPLE}\n[Interface]\nName=br0\nMinimumLifetime={v}"));
        assert!(err("2d").contains("at most 24 hours"));
        // A value that parses but would overflow the clock when added to "now".
        assert!(err("99999999999999s").contains("at most 24 hours"), "{}", err("99999999999999s"));
        assert!(err("18446744073709551615s").contains("at most 24 hours"));
        assert!(err("99999999999y").contains("at most 24 hours"), "{}", err("99999999999y"));
        assert!(err("5fortnights").contains("invalid MinimumLifetime"), "an unknown unit is just invalid");
        assert_eq!(secs("1.5h"), 5400, "a fraction, as systemd takes it");
        assert!(err("soon").contains("invalid MinimumLifetime"));
        assert!(err("").contains("MinimumLifetime"), "an empty value is not a time span");
        // Unlike the probe settings, `off` and `infinity` are not "never": a device must be able to expire.
        assert!(err("off").contains("invalid MinimumLifetime"));
        assert!(err("infinity").contains("invalid MinimumLifetime"));
    }

    #[test]
    fn rejects_bad_input() {
        let bad = [
            ("", "no segments"),
            ("[Segment]\nInterfaces=a\n", "missing name"),
            ("[Segment]\nName=a\n", "missing interfaces"),
            ("[Segment]\nName=a\nInterfaces=x\n[Segment]\nName=a\nInterfaces=y\n", "duplicate name"),
            ("[Segment]\nName=a\nInterfaces=x,x\n", "duplicate interface"),
            (
                "[Segment]\nName=a\nInterfaces=x,y\n[Segment]\nName=b\nInterfaces=y,x,z\n",
                "two segments reflect the same pair",
            ),
            ("[Listen]\nIPv4=no\nIPv6=no\n[Segment]\nName=a\nInterfaces=x\n", "no families"),
            ("[Segment]\nName=a\nInterfaces=x\nBogus=1\n", "unknown key"),
            ("[Other]\nName=a\n", "unknown section"),
            ("Name=a\n", "outside a section"),
            ("[Segment]\nName a\n", "not an assignment"),
        ];
        for (text, why) in bad {
            assert!(Config::parse(text).is_err(), "should reject: {why}");
        }
    }

    fn entries(text: &str) -> Vec<(String, String, String, usize)> {
        let unit = parse_unit(text).unwrap();
        unit.sections.iter().flat_map(|s| s.entries.iter().map(|e| (s.name.clone(), e.key.clone(), e.value.clone(), e.line))).collect()
    }

    #[test]
    fn takes_sections_and_assignments_apart() {
        let text = "# about\n\n[Listen]\nIPv4 = yes\n; no\n[Segment]\r\nName=a=b\r\nInterfaces=\n";
        let unit = parse_unit(text).unwrap();
        assert_eq!(unit.sections.iter().map(|s| (s.name.as_str(), s.line)).collect::<Vec<_>>(), [("Listen", 3), ("Segment", 6)]);
        assert_eq!(
            entries(text),
            [
                ("Listen".into(), "IPv4".into(), "yes".into(), 4),
                ("Segment".into(), "Name".into(), "a=b".into(), 7),
                ("Segment".into(), "Interfaces".into(), "".into(), 8),
            ]
        );
        assert_eq!(parse_unit("").unwrap(), Unit::default());
    }

    #[test]
    fn a_backslash_continues_a_line() {
        assert_eq!(entries("[S]\nK=x \\\n    y,z\nL=1\n")[0].2, "x     y,z");
        assert_eq!(entries("[S]\nK=x\\\ny\n")[0].2, "x y", "a space in its place");
        assert_eq!(entries("[S]\nK=x\\\ny\nL=1\n")[1].3, 4, "lines still counted");
        assert_eq!(entries("[S]\nK=x\\")[0].2, "x", "at the very end");
    }

    #[test]
    fn values_may_be_quoted_and_booleans_are_systemds() {
        let entry = |value: &str| Entry { key: "K".into(), value: value.into(), line: 1 };
        assert_eq!(entry(" \"/tmp/x y\" ").unquoted(), "/tmp/x y");
        assert_eq!(entry("'a'").unquoted(), "a");
        assert_eq!(entry("\"a'").unquoted(), "\"a'", "not a matching pair");
        assert_eq!(entry("\"").unquoted(), "\"");
        for yes in ["1", "yes", "TRUE", "On", "\"on\""] {
            assert_eq!(entry(yes).as_bool(), Some(true), "{yes}");
        }
        for no in ["0", "no", "False", "OFF"] {
            assert_eq!(entry(no).as_bool(), Some(false), "{no}");
        }
        assert_eq!(entry("enabled").as_bool(), None);
        assert_eq!(entry("").as_bool(), None);
    }

    #[test]
    fn says_what_is_wrong_and_where() {
        let error = |text: &str| parse_unit(text).unwrap_err().to_string();
        assert_eq!(error("# c\n\nName=a\n"), "line 3: assignment outside of a section");
        assert_eq!(error("[Segment]\nName a\n"), "line 2: not an assignment (Key=Value)");
        assert_eq!(error("[Segment\nName=a\n"), "line 1: a section header without its closing ]");
        assert_eq!(error("[S]\n=a\n"), "line 2: an assignment without a key");
    }

    fn ms(s: &str) -> u128 {
        parse_timespan(s).unwrap_or_else(|e| panic!("{s:?}: {e}")).as_millis()
    }

    #[test]
    fn whole_numbers_with_and_without_units_add_up() {
        assert_eq!(ms("30"), 30_000);
        assert_eq!(ms("2min"), 120_000);
        assert_eq!(ms("1h 30min"), 5_400_000);
        assert_eq!(ms("2min30s"), 150_000);
        assert_eq!(ms(" 5 min  10 "), 310_000);
        assert_eq!(ms("1d"), 86_400_000);
        assert_eq!(ms("1w"), 604_800_000);
        assert_eq!(ms("1m"), 60_000, "minutes");
        assert_eq!(ms("1M"), 2_629_800_000, "months");
        assert_eq!(ms("1y"), 31_557_600_000);
        assert_eq!(parse_timespan("250us"), Ok(Duration::from_micros(250)));
        assert_eq!(parse_timespan("3µs 7ns"), Ok(Duration::from_nanos(3_007)));
    }

    #[test]
    fn numbers_may_have_a_fraction() {
        assert_eq!(ms("1.5s"), 1_500);
        assert_eq!(ms("10.5"), 10_500);
        assert_eq!(ms("1.5h"), 5_400_000);
        assert_eq!(ms("0.25min"), 15_000);
        assert_eq!(ms(".5s"), 500);
        assert_eq!(ms("5."), 5_000);
        assert_eq!(ms("1.5min 30.25s"), 120_250);
        assert_eq!(parse_timespan("1.5us"), Ok(Duration::from_nanos(1_500)));
        // Finer than a nanosecond is dropped.
        assert_eq!(parse_timespan("1.123456789123s"), Ok(Duration::from_nanos(1_123_456_789)));
    }

    #[test]
    fn nothing_adds_up_to_zero() {
        assert_eq!(parse_timespan("0"), Ok(Duration::ZERO));
        assert_eq!(parse_timespan("0s 0.0min"), Ok(Duration::ZERO));
    }

    #[test]
    fn what_is_not_a_time_span_is_refused() {
        assert_eq!(parse_timespan(""), Err(TimespanError::Empty));
        assert_eq!(parse_timespan("  "), Err(TimespanError::Empty));
        assert_eq!(parse_timespan("soon"), Err(TimespanError::Number("soon".into())));
        assert_eq!(parse_timespan("-5s"), Err(TimespanError::Number("-5s".into())));
        assert_eq!(parse_timespan("."), Err(TimespanError::Number(".".into())));
        assert_eq!(parse_timespan("5 s s"), Err(TimespanError::Number("s".into())));
        assert_eq!(parse_timespan("5fortnights"), Err(TimespanError::Unit("fortnights".into())));
        assert_eq!(parse_timespan("5MIN"), Err(TimespanError::Unit("MIN".into())));
        assert_eq!(parse_timespan("5s$"), Err(TimespanError::Unit("s$".into())));
        assert_eq!(parse_timespan("1.2.3s"), Err(TimespanError::Number(".3s".into())));
        assert_eq!(parse_timespan("99999999999999999999999999999999999999999"), Err(TimespanError::TooLong));
        assert_eq!(parse_timespan("999999999999999999999y"), Err(TimespanError::TooLong));
    }
}
