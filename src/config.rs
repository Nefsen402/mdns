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

use anyhow::{anyhow, bail, Context, Result};
use systemd_unit_edit::{Entry, Parse, SystemdUnit};

pub const DEFAULT_PATH: &str = "/etc/mdnsd.conf";
pub const DEFAULT_SOCKET: &str = "/run/mdnsd/mdnsd.sock";

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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            segments: Vec::new(),
            ipv4: true,
            ipv6: true,
            socket: PathBuf::from(DEFAULT_SOCKET),
            advertise: None,
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
                    ("advertise", "hostname") => {
                        config.advertise = Some(local_name(&value, lineno)?);
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

    /// The man page must document every key and a config that really parses.
    #[test]
    fn man_page_documents_every_key_and_its_example_parses() {
        let man = include_str!("../man/mdnsd.conf.5");
        for key in ["IPv4=", "IPv6=", "Socket=", "Hostname=", "Name=", "Interfaces="] {
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
