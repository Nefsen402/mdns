//! The syntax of systemd unit files, as far as `mdnsd.conf` uses it:
//! `[Section]` headers, `Key=Value` assignments, comment lines starting with
//! `#` or `;`, blank lines, a backslash at the end of a line continuing it on
//! the next, and values that may be quoted. What the sections and keys mean
//! is for [`config`](crate::config).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// A unit file, taken apart.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Unit {
    pub sections: Vec<Section>,
}

/// A `[Section]`, and the assignments under it.
#[derive(Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    /// The line of its header, from 1.
    pub line: usize,
    pub entries: Vec<Entry>,
}

/// A `Key=Value` assignment.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
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
pub struct SyntaxError {
    pub line: usize,
    pub message: &'static str,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl core::error::Error for SyntaxError {}

/// Take `text` apart.
pub fn parse(text: &str) -> Result<Unit, SyntaxError> {
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

    fn entries(text: &str) -> Vec<(String, String, String, usize)> {
        let unit = parse(text).unwrap();
        unit.sections.iter().flat_map(|s| s.entries.iter().map(|e| (s.name.clone(), e.key.clone(), e.value.clone(), e.line))).collect()
    }

    #[test]
    fn takes_sections_and_assignments_apart() {
        let text = "# about\n\n[Listen]\nIPv4 = yes\n; no\n[Segment]\r\nName=a=b\r\nInterfaces=\n";
        let unit = parse(text).unwrap();
        assert_eq!(unit.sections.iter().map(|s| (s.name.as_str(), s.line)).collect::<Vec<_>>(), [("Listen", 3), ("Segment", 6)]);
        assert_eq!(
            entries(text),
            [
                ("Listen".into(), "IPv4".into(), "yes".into(), 4),
                ("Segment".into(), "Name".into(), "a=b".into(), 7),
                ("Segment".into(), "Interfaces".into(), "".into(), 8),
            ]
        );
        assert_eq!(parse("").unwrap(), Unit::default());
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
        let error = |text: &str| parse(text).unwrap_err().to_string();
        assert_eq!(error("# c\n\nName=a\n"), "line 3: assignment outside of a section");
        assert_eq!(error("[Segment]\nName a\n"), "line 2: not an assignment (Key=Value)");
        assert_eq!(error("[Segment\nName=a\n"), "line 1: a section header without its closing ]");
        assert_eq!(error("[S]\n=a\n"), "line 2: an assignment without a key");
    }
}
