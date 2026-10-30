//! systemd time spans, as `systemd.time(7)` has them: `30`, `1.5h`,
//! `2min 30s`, `.5s`.
//!
//! Numbers, each with an optional fraction and an optional unit (seconds if
//! none), added up; whitespace between them, and between a number and its
//! unit, is optional. Units are case-sensitive: `m` is minutes, `M` months.
//! Shared by the daemon's configuration and `mdnsctl`.

use std::fmt;
use std::time::Duration;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Nothing but whitespace.
    Empty,
    /// No number where one was due: what was there instead.
    Number(String),
    /// A unit that is not one.
    Unit(String),
    /// More than a `Duration` holds.
    TooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Empty => write!(f, "empty time span"),
            Error::Number(at) => write!(f, "expected a number at {at:?}"),
            Error::Unit(unit) => write!(f, "unknown unit {unit:?}"),
            Error::TooLong => write!(f, "time span too long"),
        }
    }
}

/// The time span `s` adds up to. One that adds up to nothing (`0`, `0s`) is
/// `Duration::ZERO`; a fraction finer than a nanosecond is dropped.
pub fn parse(s: &str) -> Result<Duration, Error> {
    let mut rest = s.trim();
    if rest.is_empty() {
        return Err(Error::Empty);
    }
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let (whole, after) = digits(rest);
        let (fraction, after) = match after.strip_prefix('.') {
            Some(after) => digits(after),
            None => ("", after),
        };
        if whole.is_empty() && fraction.is_empty() {
            return Err(Error::Number(rest.to_string()));
        }
        // A number straight after a fraction ("1.2.3s") is a typo.
        if after.starts_with('.') {
            return Err(Error::Number(after.to_string()));
        }
        let after = after.trim_start();
        let end = after.find(|c: char| c.is_ascii_digit() || c == '.' || c.is_whitespace()).unwrap_or(after.len());
        let (unit, after) = after.split_at(end);
        let per = match unit {
            "" => NS_PER_SEC,
            _ => UNITS.iter().find(|(names, _)| names.contains(&unit)).map(|&(_, ns)| ns).ok_or_else(|| Error::Unit(unit.into()))?,
        };

        let whole: u128 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| Error::TooLong)? };
        let mut part = whole.checked_mul(per).ok_or(Error::TooLong)?;
        let mut place = per;
        for digit in fraction.bytes() {
            place /= 10;
            part += u128::from(digit - b'0') * place;
        }
        total = total.checked_add(part).ok_or(Error::TooLong)?;
        rest = after.trim_start();
    }
    let secs = u64::try_from(total / NS_PER_SEC).map_err(|_| Error::TooLong)?;
    Ok(Duration::new(secs, (total % NS_PER_SEC) as u32))
}

/// The ASCII digits `s` starts with, and what follows them.
fn digits(s: &str) -> (&str, &str) {
    s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(s: &str) -> u128 {
        parse(s).unwrap_or_else(|e| panic!("{s:?}: {e}")).as_millis()
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
        assert_eq!(parse("250us"), Ok(Duration::from_micros(250)));
        assert_eq!(parse("3µs 7ns"), Ok(Duration::from_nanos(3_007)));
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
        assert_eq!(parse("1.5us"), Ok(Duration::from_nanos(1_500)));
        // Finer than a nanosecond is dropped.
        assert_eq!(parse("1.123456789123s"), Ok(Duration::from_nanos(1_123_456_789)));
    }

    #[test]
    fn nothing_adds_up_to_zero() {
        assert_eq!(parse("0"), Ok(Duration::ZERO));
        assert_eq!(parse("0s 0.0min"), Ok(Duration::ZERO));
    }

    #[test]
    fn what_is_not_a_time_span_is_refused() {
        assert_eq!(parse(""), Err(Error::Empty));
        assert_eq!(parse("  "), Err(Error::Empty));
        assert_eq!(parse("soon"), Err(Error::Number("soon".into())));
        assert_eq!(parse("-5s"), Err(Error::Number("-5s".into())));
        assert_eq!(parse("."), Err(Error::Number(".".into())));
        assert_eq!(parse("5 s s"), Err(Error::Number("s".into())));
        assert_eq!(parse("5fortnights"), Err(Error::Unit("fortnights".into())));
        assert_eq!(parse("5MIN"), Err(Error::Unit("MIN".into())));
        assert_eq!(parse("5s$"), Err(Error::Unit("s$".into())));
        assert_eq!(parse("1.2.3s"), Err(Error::Number(".3s".into())));
        assert_eq!(parse("99999999999999999999999999999999999999999"), Err(Error::TooLong));
        assert_eq!(parse("999999999999999999999y"), Err(Error::TooLong));
    }
}
