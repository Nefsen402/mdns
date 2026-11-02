//! A point in time, as std's `Instant` is one, without std: on the
//! monotonic clock, which only goes forward, and on Linux does not count
//! time spent suspended, as std's does not either.

use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::time::Duration;

/// A moment on the monotonic clock, from some point in the past.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
    /// The start of the clock: before anything that has happened.
    pub const START: Instant = Instant(Duration::ZERO);

    /// Now.
    pub fn now() -> Instant {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        Instant(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
    }

    /// How long after `earlier` this is: zero if it is not after it.
    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// How long ago this was: zero if it is still to come.
    pub fn elapsed(&self) -> Duration {
        Instant::now().saturating_duration_since(*self)
    }

    /// `d` later, if the clock can say so.
    pub fn checked_add(&self, d: Duration) -> Option<Instant> {
        self.0.checked_add(d).map(Instant)
    }

    /// `d` earlier, if the clock goes back that far.
    pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
        self.0.checked_sub(d).map(Instant)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    /// `d` later; one too far away for the clock panics, as with std.
    fn add(self, d: Duration) -> Instant {
        self.checked_add(d).expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    /// `d` earlier; before the clock began panics, as with std.
    fn sub(self, d: Duration) -> Instant {
        self.checked_sub(d).expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, d: Duration) {
        *self = *self - d;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    /// How long after `earlier` this is: zero if it is not, as with std.
    fn sub(self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaves_as_std_does() {
        let a = Instant::now();
        let b = Instant::now();
        assert!(b >= a);
        assert_eq!(a - b, Duration::ZERO, "earlier minus later is nothing");
        let later = a + Duration::from_secs(5);
        assert_eq!(later - a, Duration::from_secs(5));
        assert_eq!(later.saturating_duration_since(a), Duration::from_secs(5));
        assert_eq!(later - Duration::from_secs(5), a);
        assert_eq!(a.checked_add(Duration::MAX), None, "too far for the clock");
        assert_eq!(a.checked_sub(Duration::MAX), None);
        assert!(later.elapsed() == Duration::ZERO && a.elapsed() < Duration::from_secs(1));
    }
}
