//! A point in time, as std's `Instant` is one, without std: on the
//! monotonic clock, which only goes forward, and on Linux does not count
//! time spent suspended, as std's does not either.

use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::time::Duration;

/// A moment on the monotonic clock, from some point in the past.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

/// With the `test-clock` feature the clock is not the system's: it is at a fixed
/// time when the daemon starts, and moves only when [`advance`] says, by exactly
/// that much, however long the daemon runs. What happens when a time has passed
/// then does not depend on how long anything took.
#[cfg(feature = "test-clock")]
static CLOCK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(START_OF_TEST_TIME.as_nanos() as u64);

/// Where the test clock starts: an hour in, which is further than any time
/// the daemon looks back from now.
#[cfg(feature = "test-clock")]
const START_OF_TEST_TIME: Duration = Duration::from_secs(3600);

/// Move the test clock forward by `by`.
#[cfg(feature = "test-clock")]
pub fn advance(by: Duration) {
    let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
    CLOCK.fetch_add(nanos, core::sync::atomic::Ordering::Relaxed);
}

impl Instant {
    /// The start of the clock: before anything that has happened.
    pub const START: Instant = Instant(Duration::ZERO);

    /// Now.
    pub fn now() -> Instant {
        #[cfg(feature = "test-clock")]
        return Instant(Duration::from_nanos(CLOCK.load(core::sync::atomic::Ordering::Relaxed)));
        #[cfg(not(feature = "test-clock"))]
        {
            let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
            Instant(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
        }
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
#[path = "../tests/unit/time.rs"]
mod tests;
