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
//! [Devices]           ; optional
//! MinimumLifetime=5min
//!
//! [Probe]             ; optional
//! RefreshBefore=30s
//! Interval=4min       ; off unless set
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

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use systemd_unit_edit::{parse_timespan, Entry, Parse, SystemdUnit, TimespanParseError};

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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SegmentConfig {
    pub name: String,
    pub interfaces: Vec<String>,
}

#[derive(Debug)]
pub struct Config {
    pub segments: Vec<SegmentConfig>,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Where the IPC server listens.
    pub socket: PathBuf,
    /// A `.local` name to announce and answer for with this host's own
    /// addresses on every interface.
    pub advertise: Option<String>,
    /// The TTL of the advertised name's address records, which it is
    /// re-announced at 80% of.
    pub advertise_ttl: Duration,
    /// The TTL of the address records of reflected devices, which they are
    /// re-announced at 80% of; `None` (the default) announces each with the
    /// TTL it announced itself with.
    pub reflect_ttl: Option<Duration>,
    /// How often to probe every interface for devices; `None` (the default)
    /// probes only at startup and on request.
    pub probe_interval: Option<Duration>,
    /// How long before a device would expire to ask it to answer again;
    /// `None` leaves that to the periodic probe.
    pub refresh_before: Option<Duration>,
    /// The least a device is kept after it was last heard from, whatever TTLs
    /// it announced. Zero keeps it for exactly its longest TTL.
    pub min_lifetime: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            segments: Vec::new(),
            ipv4: true,
            ipv6: true,
            socket: PathBuf::from(DEFAULT_SOCKET),
            advertise: None,
            advertise_ttl: DEFAULT_ADVERTISE_TTL,
            reflect_ttl: None,
            probe_interval: None,
            refresh_before: Some(DEFAULT_REFRESH_BEFORE),
            min_lifetime: crate::socket::DEFAULT_MIN_LIFETIME,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
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

    pub fn parse(text: &str) -> Result<Config> {
        let unit = parse_syntax(text)?;
        let mut config = Config::default();
        // Header line of each [Segment], for error messages.
        let mut segment_lines = Vec::new();

        for section in unit.sections() {
            let name = section.name().unwrap_or_default().to_ascii_lowercase();
            if name == "segment" {
                config.segments.push(SegmentConfig::default());
                segment_lines.push(section.line() + 1);
            }

            for entry in section.entries() {
                // Comments and blank lines come back as entries without a key.
                let Some(key) = entry.key() else { continue };
                let key = key.to_ascii_lowercase();
                let lineno = entry.line() + 1;
                // An empty assignment has no value at all.
                let value = entry.unquoted_value().unwrap_or_default();

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
                    ("listen", "ipv4") => config.ipv4 = parse_bool(&entry, lineno)?,
                    ("listen", "ipv6") => config.ipv6 = parse_bool(&entry, lineno)?,
                    ("probe", "interval") => {
                        config.probe_interval = parse_span(&value, lineno, "Interval", MIN_PROBE_INTERVAL)?;
                    }
                    ("devices", "minimumlifetime") => {
                        config.min_lifetime = parse_lifetime(&value, lineno)?;
                    }
                    ("probe", "refreshbefore") => {
                        config.refresh_before = parse_span(&value, lineno, "RefreshBefore", MIN_REFRESH_BEFORE)?;
                    }
                    ("advertise", "hostname") => {
                        config.advertise = Some(local_name(&value, lineno)?);
                    }
                    ("advertise", "ttl") => config.advertise_ttl = parse_host_ttl(&value, lineno, "TTL")?,
                    ("devices", "reflectttl") => {
                        config.reflect_ttl = match value.to_ascii_lowercase().as_str() {
                            "auto" => None,
                            _ => Some(parse_host_ttl(&value, lineno, "ReflectTTL")?),
                        };
                    }
                    ("ipc", "socket") => {
                        if value.is_empty() {
                            bail!("line {lineno}: Socket= needs a path");
                        }
                        config.socket = PathBuf::from(value);
                    }
                    (s, k) => bail!("line {lineno}: unknown setting {k:?} in [{s}]"),
                }
            }
        }

        config.validate(&segment_lines)?;
        Ok(config)
    }

    fn validate(&self, segment_lines: &[usize]) -> Result<()> {
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

/// Parse the text as systemd unit syntax, reporting the first error with the
/// line it is on.
fn parse_syntax(text: &str) -> Result<SystemdUnit> {
    let parse = Parse::<SystemdUnit>::parse_unit(text);
    if parse.ok() {
        return Ok(parse.to_result().expect("no syntax errors"));
    }
    let message = match parse.errors().first().map(String::as_str) {
        // The parser calls an assignment before any [Section] header a missing header.
        Some(m) if m.starts_with("expected section header") => "assignment outside of a section",
        Some(m) => m,
        None => "syntax error",
    };
    match failing_line(text) {
        Some(line) => bail!("line {line}: {message}"),
        None => bail!("{message}"),
    }
}

/// The line a syntax error is on. The parser reports its errors without a
/// position, so ask it: the error is on the first line at which the text up to
/// and including that line no longer parses. Config files are small, so
/// parsing every prefix costs nothing.
fn failing_line(text: &str) -> Option<usize> {
    let mut end = 0;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        end += line.len();
        if !Parse::<SystemdUnit>::parse_unit(&text[..end]).ok() {
            return Some(i + 1);
        }
    }
    None
}

/// A systemd time span such as `4min` or `1h 30min`; one that adds up to zero
/// (`0`, `0s`) is `Duration::ZERO`.
fn timespan(value: &str, lineno: usize, key: &str) -> Result<Duration> {
    match parse_timespan(value) {
        Ok(span) => Ok(span),
        // The crate reports a span that adds up to zero ("0", "0s") as empty.
        Err(TimespanParseError::Empty) if !value.trim().is_empty() => Ok(Duration::ZERO),
        Err(e) => bail!("line {lineno}: invalid {key} {value:?}: {e}"),
    }
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

/// A systemd boolean: `1`/`yes`/`true`/`on` or `0`/`no`/`false`/`off`.
fn parse_bool(entry: &Entry, lineno: usize) -> Result<bool> {
    entry
        .value_as_bool()
        .ok_or_else(|| anyhow!("line {lineno}: invalid boolean {:?}", entry.unquoted_value().unwrap_or_default()))
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
        }
    }

    /// The example shipped in `examples/` (and quoted in the README) must stay valid.
    #[test]
    fn the_shipped_example_parses() {
        let c = Config::parse(include_str!("../examples/mdnsd.conf")).unwrap();
        assert_eq!(
            c.segments,
            [
                seg("media_stuff", &["br0", "media"]),
                seg("IoT", &["wifi"]),
                seg("IoT to br0", &["br0", "wifi"]),
            ]
        );
        assert_eq!(c.socket, PathBuf::from("/run/mdnsd/mdnsd.sock"));
        assert_eq!(c.advertise.as_deref(), Some("router.local"));
        assert_eq!(c.probe_interval, None, "the example does not set an Interval");
        assert_eq!(c.refresh_before, Some(Duration::from_secs(30)));
        assert_eq!(c.refresh_before, Some(DEFAULT_REFRESH_BEFORE), "the example shows the default");
        assert_eq!(c.min_lifetime, crate::socket::DEFAULT_MIN_LIFETIME, "the example shows the default");
        assert!(c.ipv4 && c.ipv6);
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
        assert_eq!(Config::parse(EXAMPLE).unwrap().reflect_ttl, None);

        let with = |value: &str| Config::parse(&format!("[Devices]\nReflectTTL={value}\n{EXAMPLE}"));
        assert_eq!(with("auto").unwrap().reflect_ttl, None);
        assert_eq!(with("AUTO").unwrap().reflect_ttl, None);
        assert_eq!(with("2min").unwrap().reflect_ttl, Some(Duration::from_secs(120)));
        assert_eq!(with("30min").unwrap().reflect_ttl, Some(Duration::from_secs(1800)));
        assert_eq!(with("10").unwrap().reflect_ttl, Some(Duration::from_secs(10)));
        for bad in ["9s", "0", "", "off", "infinity", "25h", "soon", "99999999999999s"] {
            assert!(with(bad).is_err(), "should reject {bad:?}");
        }
        // It is independent of the advertised name's.
        let both = Config::parse(&format!("[Devices]\nReflectTTL=5min\n[Advertise]\nTTL=1h\n{EXAMPLE}")).unwrap();
        assert_eq!(
            (both.reflect_ttl, both.advertise_ttl),
            (Some(Duration::from_secs(300)), Duration::from_secs(3600))
        );
    }

    /// The man page must document every key and a config that really parses.
    #[test]
    fn man_page_documents_every_key_and_its_example_parses() {
        let man = include_str!("../man/mdnsd.conf.5");
        for key in [
            "IPv4=", "IPv6=", "Socket=", "MinimumLifetime=", "Interval=", "RefreshBefore=", "Hostname=", "TTL=",
            "ReflectTTL=", "Name=", "Interfaces=",
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
        assert_eq!(c.socket, PathBuf::from(DEFAULT_SOCKET));
        let c = Config::parse(&format!("[Ipc]\nSocket=\"/tmp/x.sock\"\n{EXAMPLE}")).unwrap();
        assert_eq!(c.socket, PathBuf::from("/tmp/x.sock"));
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

    #[test]
    fn the_probe_interval_is_off_by_default_and_takes_systemd_time_spans() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().probe_interval, None);

        let with = |v: &str| Config::parse(&format!("[Probe]\nInterval={v}\n{EXAMPLE}"));
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
        let with = |v: &str| error_of(&format!("[Probe]\nInterval={v}\n{EXAMPLE}"));
        assert!(with("soon").contains("line 2") && with("soon").contains("invalid Interval"));
        assert!(with("5s").contains("at least 10 seconds"));
        assert!(with("").contains("line 2"), "an empty value is not a time span");
        assert!(with("3 fortnights").contains("invalid"));
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
        let both = Config::parse(&format!("[Probe]\nInterval=off\nRefreshBefore=2min\n{EXAMPLE}")).unwrap();
        assert_eq!((both.probe_interval, both.refresh_before), (None, Some(Duration::from_secs(120))));

        let err = |v: &str| error_of(&format!("[Probe]\nRefreshBefore={v}\n{EXAMPLE}"));
        assert!(err("20s").contains("RefreshBefore= must be at least 30 seconds"), "{}", err("20s"));
        assert!(err("soon").contains("line 2") && err("soon").contains("invalid RefreshBefore"));
    }

    #[test]
    fn the_minimum_lifetime_defaults_to_five_minutes_and_takes_systemd_time_spans() {
        assert_eq!(Config::parse(EXAMPLE).unwrap().min_lifetime, Duration::from_secs(300));

        let with = |v: &str| Config::parse(&format!("[Devices]\nMinimumLifetime={v}\n{EXAMPLE}"));
        let secs = |v: &str| with(v).unwrap().min_lifetime.as_secs();
        assert_eq!(secs("5min"), 300);
        assert_eq!(secs("90s"), 90);
        assert_eq!(secs("1h"), 3600);
        assert_eq!(secs("1d"), 86400, "the longest allowed");
        assert_eq!(secs("0"), 0, "zero means no minimum: a device lives for exactly its TTL");
        assert_eq!(secs("0s"), 0);

        let err = |v: &str| error_of(&format!("[Devices]\nMinimumLifetime={v}\n{EXAMPLE}"));
        assert!(err("2d").contains("at most 24 hours") && err("2d").contains("line 2"));
        // A value that parses but would overflow the clock when added to "now".
        assert!(err("99999999999999s").contains("at most 24 hours"), "{}", err("99999999999999s"));
        assert!(err("18446744073709551615s").contains("at most 24 hours"));
        assert!(err("99999999999y").contains("invalid MinimumLifetime"), "an unknown unit is just invalid");
        assert!(err("soon").contains("invalid MinimumLifetime"));
        assert!(err("").contains("line 2"), "an empty value is not a time span");
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
}
