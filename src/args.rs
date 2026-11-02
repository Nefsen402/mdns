//! A command line, taken apart: options, short (`-v`, bundled as `-vs PATH`)
//! and long (`--socket PATH`, `--socket=PATH`), and the words between them.
//! What the options mean is for whoever asks; this only says which is which,
//! as it comes, and hands over an option's value when asked for it.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;

/// One piece of the command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Arg<'a> {
    /// `-x`, or one letter of `-xyz`.
    Short(char),
    /// `--name`, or the name of `--name=value`.
    Long(&'a str),
    /// A word that is not an option: everything after `--` is one.
    Value(String),
}

impl Arg<'_> {
    /// The error for an argument whoever asked does not take.
    pub fn unexpected(&self) -> Error {
        match self {
            Arg::Short(c) => Error::Unknown(format!("-{c}")),
            Arg::Long(name) => Error::Unknown(format!("--{name}")),
            Arg::Value(word) => Error::Unwanted(word.clone()),
        }
    }
}

/// What is wrong with a command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// An option that is not one.
    Unknown(String),
    /// A word nothing takes.
    Unwanted(String),
    /// An option that needs a value, at the end of the line.
    MissingValue(String),
    /// A value given, with `=`, to an option that takes none.
    UnwantedValue { option: String, value: String },
    /// A command line that is not UTF-8.
    NotUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Unknown(option) => write!(f, "invalid option '{option}'"),
            Error::Unwanted(word) => write!(f, "unexpected argument '{word}' found"),
            Error::MissingValue(option) => write!(f, "missing argument for option '{option}'"),
            Error::UnwantedValue { option, value } => write!(f, "unexpected argument for option '{option}': {value:?}"),
            Error::NotUtf8 => write!(f, "the command line is not UTF-8"),
        }
    }
}

impl core::error::Error for Error {}

/// The arguments still to come, and where in them it is.
pub struct Parser {
    args: VecDeque<String>,
    /// The rest of a bundle of short options (`yz` of `-xyz`), and the
    /// option it came after, for an error.
    shorts: Option<(String, char)>,
    /// The name of the last long option, which [`Arg::Long`] lends.
    long: String,
    /// The value given to it with `=`, until taken.
    attached: Option<String>,
    /// Past `--`: everything is a word.
    words_only: bool,
}

impl Parser {
    pub fn new(args: impl IntoIterator<Item = String>) -> Parser {
        Parser { args: args.into_iter().collect(), shorts: None, long: String::new(), attached: None, words_only: false }
    }

    /// The next piece of the command line, or `None` at its end. A value
    /// given with `=` that was not taken is an error now.
    pub fn next(&mut self) -> Result<Option<Arg<'_>>, Error> {
        if let Some(value) = self.attached.take() {
            return Err(Error::UnwantedValue { option: format!("--{}", self.long), value });
        }
        if let Some((rest, _)) = self.shorts.take() {
            let mut chars = rest.chars();
            if let Some(c) = chars.next() {
                let rest = chars.as_str();
                if !rest.is_empty() {
                    self.shorts = Some((rest.to_string(), c));
                }
                // Kept for `value`, should it be asked for this option's.
                self.shorts.get_or_insert((String::new(), c)).1 = c;
                return Ok(Some(Arg::Short(c)));
            }
        }
        let Some(arg) = self.args.pop_front() else { return Ok(None) };
        if self.words_only || arg == "-" || !arg.starts_with('-') {
            return Ok(Some(Arg::Value(arg)));
        }
        if arg == "--" {
            self.words_only = true;
            return self.next();
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (long, None),
            };
            self.long = name.to_string();
            self.attached = value;
            return Ok(Some(Arg::Long(&self.long)));
        }
        self.shorts = Some((arg[1..].to_string(), '-'));
        self.next()
    }

    /// The value of the option just given: what came after `=`, the rest of
    /// a bundle (`PATH` of `-sPATH`), or else the next argument, whatever it
    /// looks like.
    pub fn value(&mut self) -> Result<String, Error> {
        if let Some(value) = self.attached.take() {
            return Ok(value);
        }
        let option = match self.shorts.take() {
            Some((rest, _)) if !rest.is_empty() => return Ok(rest),
            Some((_, c)) => format!("-{c}"),
            None => format!("--{}", self.long),
        };
        self.args.pop_front().ok_or(Error::MissingValue(option))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser(args: &[&str]) -> Parser {
        Parser::new(args.iter().map(|a| a.to_string()))
    }

    /// Everything the command line holds, the value of each option named in
    /// `valued` taken with it.
    fn all(args: &[&str], valued: &[&str]) -> Result<Vec<String>, Error> {
        let mut p = parser(args);
        let mut out = Vec::new();
        while let Some(arg) = p.next()? {
            let (name, takes) = match arg {
                Arg::Short(c) => (format!("-{c}"), valued.contains(&c.to_string().as_str())),
                Arg::Long(name) => (format!("--{name}"), valued.contains(&name)),
                Arg::Value(word) => (word, false),
            };
            out.push(if takes { format!("{name}={}", p.value()?) } else { name });
        }
        Ok(out)
    }

    #[test]
    fn tells_options_from_words() {
        assert_eq!(all(&["devices", "-v", "IoT", "--json"], &[]), Ok(vec!["devices".into(), "-v".into(), "IoT".into(), "--json".into()]));
        assert_eq!(all(&["-", "x"], &[]).unwrap(), ["-", "x"], "a lone dash is a word");
        assert_eq!(all(&[], &[]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn options_take_their_values_every_way() {
        let got = all(&["--socket", "/a", "--socket=/b", "-s", "/c", "-s/d", "--socket=", "--query=a=b"], &["socket", "s", "query"]);
        assert_eq!(got.unwrap(), ["--socket=/a", "--socket=/b", "-s=/c", "-s=/d", "--socket=", "--query=a=b"]);
        // A value may look like an option.
        assert_eq!(all(&["--log", "--json"], &["log"]).unwrap(), ["--log=--json"]);
    }

    #[test]
    fn short_options_bundle() {
        assert_eq!(all(&["-vh"], &[]).unwrap(), ["-v", "-h"]);
        assert_eq!(all(&["-vs", "/a", "x"], &["s"]).unwrap(), ["-v", "-s=/a", "x"]);
        assert_eq!(all(&["-vs/a"], &["s"]).unwrap(), ["-v", "-s=/a"]);
        assert_eq!(all(&["-é"], &[]).unwrap(), ["-é"], "a letter, not a byte");
    }

    #[test]
    fn after_two_dashes_all_are_words() {
        assert_eq!(all(&["sub", "--", "-x", "--y", "--"], &[]).unwrap(), ["sub", "-x", "--y", "--"]);
    }

    #[test]
    fn says_what_is_wrong() {
        assert_eq!(all(&["--socket"], &["socket"]).unwrap_err().to_string(), "missing argument for option '--socket'");
        assert_eq!(all(&["-s"], &["s"]).unwrap_err().to_string(), "missing argument for option '-s'");
        assert_eq!(all(&["-vs"], &["s"]).unwrap_err().to_string(), "missing argument for option '-s'");
        assert_eq!(all(&["--verbose=yes"], &[]).unwrap_err().to_string(), r#"unexpected argument for option '--verbose': "yes""#);
        assert_eq!(Arg::Long("bogus").unexpected().to_string(), "invalid option '--bogus'");
        assert_eq!(Arg::Short('x').unexpected().to_string(), "invalid option '-x'");
        assert_eq!(Arg::Value("extra".into()).unexpected().to_string(), "unexpected argument 'extra' found");
    }
}
