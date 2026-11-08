//! systemd-style (INI) configuration, read once at startup.
//!
//! The settings, their defaults and an example are in `man/mdnsd.conf.5`, which
//! a test here keeps in step: every key is in it, and its example parses.
//!
//! [`Config::parse`] turns the text into a [`Config`] and checks it as a whole.
//! What is set for an interface is gathered from the `[Interface]` sections
//! and the segments it is in into one [`Interface`], by [`Config::interface`].

use core::fmt;
use core::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::runtime::Why;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Whether `name` is matched by `pattern`: `*` stands for any run of
/// characters, even none, and `?` for any one; the rest stand for themselves.
pub fn glob(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut at_p, mut at_n) = (0, 0);
    // Where the last `*` was, and how much of the name it has taken.
    let mut star: Option<(usize, usize)> = None;
    while at_n < n.len() {
        if at_p < p.len() && p[at_p] == b'*' {
            star = Some((at_p, at_n));
            at_p += 1;
        } else if at_p < p.len() && (p[at_p] == b'?' || p[at_p] == n[at_n]) {
            at_p += 1;
            at_n += 1;
        } else if let Some((star_p, star_n)) = star {
            // Let the star take one more.
            star = Some((star_p, star_n + 1));
            at_p = star_p + 1;
            at_n = star_n + 1;
        } else {
            return false;
        }
    }
    p[at_p..].iter().all(|&c| c == b'*')
}

/// Whether `name` has a wildcard in it, so names many interfaces.
pub fn is_pattern(name: &str) -> bool {
    name.contains(['*', '?'])
}

pub const DEFAULT_PATH: &str = "/etc/mdnsd.conf";
pub const DEFAULT_SOCKET: &str = "/run/mdnsd/mdnsd.sock";
/// Anyone may use it: what it tells is what is multicast on the link, and the
/// one request that does anything, `probe`, is one a user could send themselves.
pub const DEFAULT_SOCKET_MODE: u32 = 0o666;

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

/// A name may be re-announced at 80% of its TTL (`Reannounce=`), so a shorter one would be a flood.
const MIN_HOST_TTL: Duration = Duration::from_secs(10);

/// A longer one is a typo, and a name would outlive its host for a day.
const MAX_HOST_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// A longer floor than this is a typo: it would keep devices that are long
/// gone, and a silly one (`99999999999999s`) would overflow the clock.
const MAX_MIN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The default for how long a device is kept at least after it was last heard
/// from, whatever TTLs it announced: a minute, so that a device that announces a
/// TTL of a second, as a buggy one may, is not asked about every few seconds. See
/// [`Segment::set_min_lifetime`].
pub const DEFAULT_MIN_LIFETIME: Duration = Duration::from_secs(60);

/// The default for how many addresses of a family a device is kept with:
/// enough for a global and a ULA address, a few temporary ones, and a
/// link-local one. See `[Interface] MaxAddresses=`.
pub const DEFAULT_MAX_ADDRS: usize = 8;

/// The default for how many devices an interface remembers: one sender
/// inventing endless devices, or many forged ones, must not grow the list
/// without bound. A sleep proxy or Thread border router speaks for several
/// hosts, but not for this many. See `[Interface] MaxDevices=`.
pub const DEFAULT_MAX_DEVICES: usize = 1024;

/// The default for how many services a device is kept with: more would be a
/// flood, not a device. See `[Interface] MaxServices=`.
pub const DEFAULT_MAX_SERVICES: usize = 64;

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

/// What a device must have been heard to have, to be reflected from a segment
/// (`ReflectedWhen=`): a routable address, a hostname, and a service whose
/// host and port are known. Everything unless set; a device with no service,
/// say, is then found by name alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReflectedWhen {
    pub address: bool,
    pub hostname: bool,
    pub service: bool,
    /// Which of a device's services are reflected with it
    /// (`ReflectedServices=`).
    pub kinds: ServiceKinds,
}

impl Default for ReflectedWhen {
    fn default() -> ReflectedWhen {
        ReflectedWhen { address: true, hostname: true, service: true, kinds: ServiceKinds::default() }
    }
}

/// The service types that are reflected (`ReflectedServices=`), such as
/// `_ipp._tcp`: only those in `only` if it has any, and never those in `not`.
/// Types are kept in lowercase, without the `.local`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceKinds {
    only: BTreeSet<String>,
    not: BTreeSet<String>,
}

impl ServiceKinds {
    /// Whether the service type `kind`, as devices have it (`_ipp._tcp.local`),
    /// is reflected.
    pub fn allows(&self, kind: &str) -> bool {
        let kind = kind.trim_end_matches('.');
        let kind = kind.strip_suffix(".local").unwrap_or(kind).to_ascii_lowercase();
        !self.not.contains(&kind) && (self.only.is_empty() || self.only.contains(&kind))
    }

    /// Whether every type is.
    pub fn is_all(&self) -> bool {
        self.only.is_empty() && self.not.is_empty()
    }

    /// The types as they were written: those named, and those kept out with a
    /// `!` before.
    pub fn words(&self) -> Vec<String> {
        self.only.iter().cloned().chain(self.not.iter().map(|k| format!("!{k}"))).collect()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SegmentConfig {
    pub name: String,
    /// The interfaces of the segment: names, or patterns of them (`enp*`), and
    /// those kept out of it, with a `!` before (`!br*`).
    pub interfaces: Vec<String>,
    /// Interfaces of the segment that are announced nothing: their devices
    /// are announced to the others, but not the others' to them. Each is one
    /// of `interfaces` or a name one of them matches.
    pub untrusted: Vec<String>,
    /// How often to probe its interfaces for devices: `None` follows the
    /// `ProbeInterval=` of each interface, and `Some(None)` is off for this
    /// segment.
    pub probe_interval: Option<Option<Duration>>,
    /// Which questions asked on one of its interfaces are put to the others.
    pub forward: Forward,
    /// Which of the addresses a device was given from the neighbour table are
    /// reflected with it.
    pub neighbour_addresses: Neighbours,
    /// Whether what is reflected onto its interfaces is announced again
    /// before its TTL runs out though it has not changed.
    pub reannounce: bool,
    /// What a device has to have to be reflected (`ReflectedWhen=`).
    pub reflected_when: ReflectedWhen,
    /// The TTL of the address records of the devices it reflects; `None`
    /// (the default) announces each with the TTL it announced itself with.
    pub reflect_ttl: Option<Duration>,
}

impl SegmentConfig {
    /// The names and patterns of `interfaces` that are of it, not those with a
    /// `!` that are not.
    fn included(&self) -> impl Iterator<Item = &str> {
        self.interfaces.iter().map(String::as_str).filter(|i| !i.starts_with('!'))
    }

    /// The names and patterns of `interfaces` that a `!` keeps out, without it.
    fn excluded(&self) -> impl Iterator<Item = &str> {
        self.interfaces.iter().filter_map(|i| i.strip_prefix('!'))
    }

    /// Whether the interface `name` is one of the segment's: one that
    /// `Interfaces=` has, and none that it keeps out.
    pub fn has(&self, name: &str) -> bool {
        self.included().any(|i| glob(i, name)) && !self.excluded().any(|i| glob(i, name))
    }
}

/// What one `[Interface]` section sets: for one interface, whichever segments
/// it is in, or, without a name, for every interface that has no setting of its
/// own. Each setting that is `None` is left to the nameless section, and then to
/// its default. What the daemon goes by is [`Interface`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct InterfaceConfig {
    name: Option<String>,
    min_lifetime: Option<Duration>,
    /// `Some(None)` is off.
    refresh_before: Option<Option<Duration>>,
    /// `None` is off, and so is `Some(None)`.
    probe_interval: Option<Option<Duration>>,
    max_addrs: Option<usize>,
    max_devices: Option<usize>,
    max_services: Option<usize>,
}

/// Everything that is settled for one interface, with every default filled in,
/// whichever segments it is in: what its section says, or else the section
/// without a name, or else the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// The least a device heard on it is kept after it was last heard from,
    /// whatever TTLs it announced: [`DEFAULT_MIN_LIFETIME`] unless set, and
    /// zero keeps it for exactly its longest TTL.
    pub min_lifetime: Duration,
    /// How long before a device heard on it would expire to ask it to answer
    /// again: [`DEFAULT_REFRESH_BEFORE`] unless set; `None` leaves that to the
    /// periodic probe.
    pub refresh_before: Option<Duration>,
    /// How often to probe it for devices: as often as the most frequent of the
    /// segments it is in asks, each its own `ProbeInterval=` or else the
    /// interface's; `None` if none of them probes.
    pub probe_interval: Option<Duration>,
    /// How many addresses of a family a device heard on it is kept with, at
    /// most: [`DEFAULT_MAX_ADDRS`] unless set.
    pub max_addrs: usize,
    /// How many devices it remembers, at most: [`DEFAULT_MAX_DEVICES`] unless
    /// set. A host beyond that is not learned of.
    pub max_devices: usize,
    /// How many services a device heard on it is kept with, at most:
    /// [`DEFAULT_MAX_SERVICES`] unless set.
    pub max_services: usize,
    /// Whether what is announced on it is announced again though it has not
    /// changed: if any of its segments says so.
    pub reannounce: bool,
}

/// What is listened for over one family of IP (`IPv4=`, `IPv6=`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Listen {
    /// Nothing: the family is not used.
    Off,
    /// What is sent to the mDNS group, which is what devices send to be heard
    /// by all on the link, and all that is asked of them.
    Multicast,
    /// That, and what is sent to the daemon's own address at the mDNS port,
    /// of a host on the interface's networks or link-local: the answers to a
    /// question it asked of a device directly, and what resolvers ask it.
    #[default]
    On,
}

impl Listen {
    /// Whether the family is used at all.
    pub fn enabled(self) -> bool {
        self != Listen::Off
    }

    /// Whether what is sent to the daemon itself is heard.
    pub fn unicast(self) -> bool {
        self == Listen::On
    }
}

#[derive(Debug)]
pub struct Config {
    pub segments: Vec<SegmentConfig>,
    /// What each `[Interface]` section sets, which [`Config::interface`] makes
    /// the settings of an interface of.
    settings: Vec<InterfaceConfig>,
    pub ipv4: Listen,
    pub ipv6: Listen,
    /// Where the IPC server listens.
    pub socket: String,
    /// The permissions of the control socket.
    pub socket_mode: u32,
    /// Where to listen as avahi-daemon does, for what asks it for the address
    /// of a name (`nss-mdns`); nowhere unless set.
    pub avahi_socket: Option<String>,
    /// The names this host announces and answers for, with its own addresses.
    pub advertise: Vec<AdvertiseConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            segments: Vec::new(),
            settings: Vec::new(),
            ipv4: Listen::default(),
            ipv6: Listen::default(),
            socket: DEFAULT_SOCKET.to_string(),
            socket_mode: DEFAULT_SOCKET_MODE,
            avahi_socket: None,
            advertise: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let text = read_to_string(path).with_context(|| format!("reading {path}"))?;
        Self::parse(&text).with_context(|| format!("parsing {path}"))
    }

    /// What is settled for the interface `name`, with every default filled in:
    /// what its `[Interface]` section says, or else the one without a name, or
    /// else the default; and, from the segments that have it, how often it is
    /// probed and whether it announces again. An interface that no segment has
    /// has what is set for all of them, and nothing of its segments.
    pub fn interface(&self, name: &str) -> Interface {
        let mut segments = self.segments.iter().filter(|seg| seg.has(name));
        let own_probe = setting_of(&self.settings, name, None, |i| i.probe_interval);
        Interface {
            name: name.to_string(),
            min_lifetime: setting_of(&self.settings, name, DEFAULT_MIN_LIFETIME, |i| i.min_lifetime),
            refresh_before: setting_of(&self.settings, name, Some(DEFAULT_REFRESH_BEFORE), |i| i.refresh_before),
            probe_interval: segments.clone().filter_map(|seg| seg.probe_interval.unwrap_or(own_probe)).min(),
            max_addrs: setting_of(&self.settings, name, DEFAULT_MAX_ADDRS, |i| i.max_addrs),
            max_devices: setting_of(&self.settings, name, DEFAULT_MAX_DEVICES, |i| i.max_devices),
            max_services: setting_of(&self.settings, name, DEFAULT_MAX_SERVICES, |i| i.max_services),
            reannounce: segments.any(|seg| seg.reannounce),
        }
    }

    /// What is settled for each interface named by any segment, once each, in
    /// first-seen order: those named, not those a pattern may match.
    pub fn interfaces(&self) -> Vec<Interface> {
        self.interface_names().into_iter().filter(|name| !is_pattern(name)).map(|name| self.interface(name)).collect()
    }

    /// Whether any segment has the interface `name`.
    pub fn wants(&self, name: &str) -> bool {
        self.segments.iter().any(|seg| seg.has(name))
    }

    /// The interfaces named by any segment, or patterns of them, once each, in first-seen order.
    fn interface_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for iface in self.segments.iter().flat_map(|s| s.included()) {
            if !out.contains(&iface) {
                out.push(iface);
            }
        }
        out
    }

    pub fn parse(text: &str) -> Result<Config> {
        let unit = parse_unit(text)?;
        let mut config = Config::default();
        // Header line of each [Segment] and [Interface], for error messages.
        let mut segment_lines = Vec::new();
        let mut interface_lines = Vec::new();
        let mut advertise_lines = Vec::new();
        // What each [Interface] section sets, which `Config::interface` goes by.
        let mut settings: Vec<InterfaceConfig> = Vec::new();

        for section in &unit.sections {
            let name = section.name.to_ascii_lowercase();
            if name == "segment" {
                config.segments.push(SegmentConfig::default());
                segment_lines.push(section.line);
            }
            if name == "advertise" {
                config.advertise.push(AdvertiseConfig::default());
                advertise_lines.push(section.line);
            }
            if name == "interface" {
                settings.push(InterfaceConfig::default());
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
                        settings.last_mut().unwrap().name = Some(value).filter(|v| !v.is_empty());
                    }
                    ("interface", "maxservices") => {
                        settings.last_mut().unwrap().max_services =
                            Some(parse_limit(&value, lineno, "MaxServices")?);
                    }
                    ("interface", "maxdevices") => {
                        settings.last_mut().unwrap().max_devices =
                            Some(parse_limit(&value, lineno, "MaxDevices")?);
                    }
                    ("interface", "maxaddresses") => {
                        settings.last_mut().unwrap().max_addrs = Some(parse_limit(&value, lineno, "MaxAddresses")?);
                    }
                    ("interface", "probeinterval") => {
                        let interval = parse_span(&value, lineno, "ProbeInterval", MIN_PROBE_INTERVAL)?;
                        settings.last_mut().unwrap().probe_interval = Some(interval);
                    }
                    ("interface", "refreshbefore") => {
                        let before = parse_span(&value, lineno, "RefreshBefore", MIN_REFRESH_BEFORE)?;
                        settings.last_mut().unwrap().refresh_before = Some(before);
                    }
                    ("interface", "minimumlifetime") => {
                        settings.last_mut().unwrap().min_lifetime = Some(parse_lifetime(&value, lineno)?);
                    }
                    ("segment", "neighbouraddresses") => {
                        config.segments.last_mut().unwrap().neighbour_addresses = parse_neighbours(&value, lineno)?;
                    }
                    ("segment", "reannounce") => {
                        config.segments.last_mut().unwrap().reannounce = !value.is_empty() && parse_bool(entry, lineno)?;
                    }
                    ("segment", "reflectedwhen") => {
                        // The services are `ReflectedServices=`'s, whichever comes first.
                        let when = &mut config.segments.last_mut().unwrap().reflected_when;
                        let kinds = core::mem::take(&mut when.kinds);
                        *when = ReflectedWhen { kinds, ..parse_reflected_when(&value, lineno)? };
                    }
                    ("segment", "reflectedservices") => {
                        // Repeated, it adds; an empty assignment resets, as everywhere.
                        let more = parse_service_kinds(&value, lineno)?;
                        let kinds = &mut config.segments.last_mut().unwrap().reflected_when.kinds;
                        if value.is_empty() {
                            *kinds = more;
                        } else {
                            kinds.only.extend(more.only);
                            kinds.not.extend(more.not);
                        }
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
                    ("listen", "ipv4") => config.ipv4 = parse_listen(entry, lineno, "IPv4")?,
                    ("listen", "ipv6") => config.ipv6 = parse_listen(entry, lineno, "IPv6")?,
                    ("probe", "probeinterval" | "interval") => {
                        bail!("line {lineno}: ProbeInterval= is now a setting of [Interface]")
                    }
                    ("probe", "refreshbefore") => {
                        bail!("line {lineno}: RefreshBefore= is now a setting of [Interface]")
                    }
                    ("devices", "minimumlifetime") => {
                        bail!("line {lineno}: MinimumLifetime= is now a setting of [Interface]")
                    }
                    ("devices", "maxaddresses") => {
                        bail!("line {lineno}: MaxAddresses= is now a setting of [Interface]")
                    }
                    ("advertise", "hostname") => {
                        config.advertise.last_mut().unwrap().name = local_name(&value, lineno)?;
                    }
                    ("advertise", "interface") => {
                        let block = config.advertise.last_mut().unwrap();
                        if value.is_empty() {
                            block.interfaces.clear();
                        }
                        for name in value.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()) {
                            if !block.interfaces.iter().any(|i| i == name) {
                                block.interfaces.push(name.to_string());
                            }
                        }
                    }
                    ("advertise", "services") => {
                        let block = config.advertise.last_mut().unwrap();
                        if value.is_empty() {
                            block.services.clear();
                        }
                        for word in value.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()) {
                            let service = parse_service(word, lineno)?;
                            if !block.services.contains(&service) {
                                block.services.push(service);
                            }
                        }
                    }
                    ("advertise", "ttl") => config.advertise.last_mut().unwrap().ttl = parse_host_ttl(&value, lineno, "TTL")?,
                    ("ipc", "avahisocket") => config.avahi_socket = Some(value).filter(|v| !v.is_empty()),
                    ("ipc", "socket") => {
                        if value.is_empty() {
                            bail!("line {lineno}: Socket= needs a path");
                        }
                        config.socket = value;
                    }
                    ("ipc", "mode") => config.socket_mode = parse_mode(&value, lineno)?,
                    (s, k) => bail!("line {lineno}: unknown setting {k:?} in [{s}]"),
                }
            }
        }

        config.validate(&segment_lines, &interface_lines, &advertise_lines, &settings)?;
        config.settings = settings;
        Ok(config)
    }

    fn validate(
        &self,
        segment_lines: &[usize],
        interface_lines: &[usize],
        advertise_lines: &[usize],
        settings: &[InterfaceConfig],
    ) -> Result<()> {
        if self.segments.is_empty() {
            bail!("no [Segment] defined");
        }
        if !self.ipv4.enabled() && !self.ipv6.enabled() {
            bail!("[Listen] IPv4= and IPv6= are both off");
        }
        let listened = self.interface_names();
        for (i, block) in self.advertise.iter().enumerate() {
            let at = advertise_lines[i];
            if block.name.is_empty() {
                bail!("[Advertise] at line {at} has no Hostname=");
            }
            if let Some(stray) = block.interfaces.iter().find(|i| if is_pattern(i) { !covered(&listened, i) } else { !self.wants(i) }) {
                bail!("[Advertise] at line {at} has Interface={stray}, which is not in any segment's Interfaces=");
            }
            // One name is of one set of addresses on an interface.
            let on = |b: &AdvertiseConfig, iface: &str| b.interfaces.is_empty() || b.interfaces.iter().any(|i| glob(i, iface));
            if let Some(other) = self.advertise[..i]
                .iter()
                .find(|o| o.name.eq_ignore_ascii_case(&block.name) && listened.iter().any(|&iface| on(o, iface) && on(block, iface)))
            {
                bail!("[Advertise] at line {at} has Hostname={}, which another does on the same interface", other.name);
            }
        }

        for (i, seg) in self.segments.iter().enumerate() {
            let at = segment_lines[i];
            if seg.name.is_empty() {
                bail!("[Segment] at line {at} has no Name=");
            }
            if seg.interfaces.is_empty() {
                bail!("segment {:?} (line {at}) has no Interfaces=", seg.name);
            }
            if seg.interfaces.iter().any(|i| i.strip_prefix('!').is_some_and(str::is_empty)) {
                bail!("segment {:?} (line {at}) has a ! in Interfaces= that keeps nothing out", seg.name);
            }
            if seg.included().next().is_none() {
                bail!("segment {:?} (line {at}) has only interfaces kept out in Interfaces=", seg.name);
            }
            if let Some(both) = seg.included().find(|i| seg.excluded().any(|x| glob(x, i))) {
                bail!("segment {:?} (line {at}) has Interfaces={both}, which it also keeps out", seg.name);
            }
            if !seg.reflected_when.kinds.is_all() && !seg.reflected_when.service {
                bail!(
                    "segment {:?} (line {at}) has ReflectedServices= without enabling service filtering: add service to ReflectedWhen=",
                    seg.name
                );
            }
            if let Some(dup) = seg
                .interfaces
                .iter()
                .enumerate()
                .find(|(n, iface)| seg.interfaces[..*n].contains(iface))
            {
                bail!("segment {:?} lists interface {} twice", seg.name, dup.1);
            }
            let included: Vec<&str> = seg.included().collect();
            if let Some(stray) = seg.untrusted.iter().find(|u| !covered(&included, u) || (!is_pattern(u) && !seg.has(u))) {
                bail!("segment {:?} (line {at}) has Untrusted={stray}, which is not in its Interfaces=", seg.name);
            }
            if let Some(dup) = seg.untrusted.iter().enumerate().find(|(n, u)| seg.untrusted[..*n].contains(u)) {
                bail!("segment {:?} lists {} as untrusted twice", seg.name, dup.1);
            }
            if included.len() >= 2 && included.iter().all(|i| covered(&seg.untrusted, i)) {
                bail!("segment {:?} (line {at}) has no trusted interface to announce to", seg.name);
            }
            for other in &self.segments[..i] {
                if other.name == seg.name {
                    bail!("two segments are named {:?}", seg.name);
                }
                // Two segments sharing a pair of interfaces would both
                // reflect between them, and each would withdraw the other's
                // announcements.
                let shared: Vec<&str> = seg.included().filter(|iface| other.included().any(|o| o == *iface)).collect();
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
        for (i, setting) in settings.iter().enumerate() {
            let at = interface_lines[i];
            let Some(name) = &setting.name else {
                if settings[..i].iter().any(|other| other.name.is_none()) {
                    bail!("[Interface] at line {at} has no Name=, like an earlier one: only one can be for every interface");
                }
                continue;
            };
            // A pattern is for whichever interfaces it matches, if any.
            if !is_pattern(name) && !self.wants(name) {
                bail!("[Interface] {name} (line {at}) is not in the Interfaces= of any segment");
            }
            if settings[..i].iter().any(|other| other.name.as_ref() == Some(name)) {
                bail!("two [Interface] sections are named {name}");
            }
        }
        Ok(())
    }
}

/// Whether `name`, a name or a pattern, is one of `listed` or is matched by
/// one of them.
fn covered(listed: &[impl AsRef<str>], name: &str) -> bool {
    listed.iter().any(|l| l.as_ref() == name || glob(l.as_ref(), name))
}

/// A setting of `interface`: the one in its own `[Interface]`, or else the one in
/// the first `[Interface]` named for a pattern that matches it that has it, or else
/// the one in the `[Interface]` without a name, or else `default`.
fn setting_of<T>(settings: &[InterfaceConfig], interface: &str, default: T, get: impl Fn(&InterfaceConfig) -> Option<T>) -> T {
    let named = settings.iter().find(|i| i.name.as_deref() == Some(interface)).and_then(&get);
    let matching = || {
        settings
            .iter()
            .filter(|i| i.name.as_deref().is_some_and(|name| is_pattern(name) && glob(name, interface)))
            .find_map(&get)
    };
    named
        .or_else(matching)
        .or_else(|| settings.iter().find(|i| i.name.is_none()).and_then(&get))
        .unwrap_or(default)
}

/// One `[Advertise]` section: a name, and what it is announced with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertiseConfig {
    /// The `.local` name to announce and answer for with this host's own
    /// addresses.
    pub name: String,
    /// The TTL of the name's address records: how long others keep them, and,
    /// on an interface of a segment that re-announces, when it is announced
    /// again (at 80% of it).
    pub ttl: Duration,
    /// The services to announce under the name, each as its type
    /// (`_ssh._tcp`) and port, by an instance named for the host.
    pub services: Vec<(String, u16)>,
    /// The interfaces to advertise on; all of those listened to if none.
    pub interfaces: Vec<String>,
}

impl Default for AdvertiseConfig {
    fn default() -> Self {
        AdvertiseConfig { name: String::new(), ttl: DEFAULT_ADVERTISE_TTL, services: Vec::new(), interfaces: Vec::new() }
    }
}

/// A service to advertise: its type and port, as `_ssh._tcp:22`.
fn parse_service(word: &str, lineno: usize) -> Result<(String, u16)> {
    let bad = || anyhow!("line {lineno}: Services= takes a type and a port, such as _ssh._tcp:22, not {word:?}");
    let (kind, port) = word.split_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().ok().filter(|&p| p != 0).ok_or_else(bad)?;
    let (service, proto) = kind.split_once('.').ok_or_else(bad)?;
    let named = service.len() >= 2
        && service.len() <= 16
        && service.starts_with('_')
        && service.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !named || !(proto.eq_ignore_ascii_case("_tcp") || proto.eq_ignore_ascii_case("_udp")) {
        return Err(bad());
    }
    Ok((kind.to_ascii_lowercase(), port))
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

/// A limit on how many of something are kept: a number, at least one, or
/// `infinity` for no limit at all.
fn parse_limit(value: &str, lineno: usize, key: &str) -> Result<usize> {
    if value.eq_ignore_ascii_case("infinity") {
        return Ok(usize::MAX);
    }
    value
        .parse()
        .ok()
        .filter(|&n| n >= 1)
        .ok_or_else(|| anyhow!("line {lineno}: {key}= must be a number of at least 1, or infinity, not {value:?}"))
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
/// A file mode, in octal as systemd's are: `0660`, `660`, `0o660`.
fn parse_mode(value: &str, lineno: usize) -> Result<u32> {
    let digits = value.strip_prefix("0o").unwrap_or(value);
    match u32::from_str_radix(digits, 8) {
        Ok(mode) if !digits.is_empty() && mode <= 0o777 => Ok(mode),
        _ => bail!("line {lineno}: Mode= must be an octal mode such as 0660, not {value:?}"),
    }
}

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

fn parse_reflected_when(value: &str, lineno: usize) -> Result<ReflectedWhen> {
    // An empty assignment resets, as everywhere.
    if value.is_empty() {
        return Ok(ReflectedWhen::default());
    }
    let mut when = ReflectedWhen { address: false, hostname: false, service: false, kinds: ServiceKinds::default() };
    for word in value.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()) {
        match word.to_ascii_lowercase().as_str() {
            "address" => when.address = true,
            "hostname" => when.hostname = true,
            "service" => when.service = true,
            _ => bail!("line {lineno}: invalid ReflectedWhen {word:?}: address, hostname or service"),
        }
    }
    // A device is announced, and tracked, by its name.
    if !when.hostname {
        bail!("line {lineno}: ReflectedWhen= must include hostname: a device is announced by its name");
    }
    Ok(when)
}

fn parse_service_kinds(value: &str, lineno: usize) -> Result<ServiceKinds> {
    let mut kinds = ServiceKinds::default();
    for word in value.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()) {
        let (excluded, name) = match word.strip_prefix('!') {
            Some(name) => (true, name),
            None => (false, word),
        };
        let name = name.trim_end_matches('.');
        let name = name.strip_suffix(".local").unwrap_or(name).to_ascii_lowercase();
        // A service type: `_name._tcp` or `_name._udp`.
        let valid = name
            .strip_suffix("._tcp")
            .or_else(|| name.strip_suffix("._udp"))
            .and_then(|service| service.strip_prefix('_'))
            .is_some_and(|service| !service.is_empty() && !service.contains(['.', '*', '?']));
        if !valid {
            bail!("line {lineno}: invalid ReflectedServices {word:?}: a service type such as _ipp._tcp, or !_ssh._tcp to keep one out");
        }
        if excluded { kinds.not.insert(name) } else { kinds.only.insert(name) };
    }
    Ok(kinds)
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
/// What is listened for over a family: `off`, `multicast` or `on`, and no
/// other.
fn parse_listen(entry: &Entry, lineno: usize, key: &str) -> Result<Listen> {
    let value = entry.unquoted();
    match value.to_ascii_lowercase().as_str() {
        "off" => Ok(Listen::Off),
        "multicast" => Ok(Listen::Multicast),
        "on" => Ok(Listen::On),
        _ => bail!("line {lineno}: {key}= must be off, multicast or on, not {value:?}"),
    }
}

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
#[path = "../tests/unit/config.rs"]
mod tests;
