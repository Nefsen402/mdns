//! Shutdown signals, turned into something the event loop can wait on: a
//! handler writes the signal's number to a pipe, whose other end the loop
//! polls (the self-pipe trick). Writing to a pipe is one of the few things a
//! handler may safely do.

use core::sync::atomic::{AtomicI32, Ordering};

use rustix::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::runtime::{errno, Why};

/// The pipe's writing end, for the handler: -1 until [`install`]ed.
static WRITE_END: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    // SAFETY: errno is the calling thread's, and only write(2), which is
    // async-signal-safe, runs between saving and restoring it. A full pipe
    // already says a signal came: losing this byte loses nothing.
    unsafe {
        let errno = *crate::runtime::errno_location();
        let byte = sig as u8;
        libc::write(WRITE_END.load(Ordering::Relaxed), (&byte as *const u8).cast(), 1);
        *crate::runtime::errno_location() = errno;
    }
}

/// The reading end of the pipe SIGTERM and SIGINT are written to.
pub struct Signals {
    read: OwnedFd,
}

/// Handle SIGTERM and SIGINT from now on by writing to a pipe, whose reading
/// end is returned. Call once.
pub fn install() -> Result<Signals, Why> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 fills in.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(Why(errno()));
    }
    // SAFETY: both were just created, and are owned by nothing else. The
    // writing end lives as long as the process, for the handler.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    WRITE_END.store(fds[1], Ordering::Relaxed);
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: an all-zero sigaction is valid; the fields set are its own,
        // and the handler only does what a handler may.
        let rc = unsafe {
            let mut action: libc::sigaction = core::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(sig, &action, core::ptr::null_mut())
        };
        if rc != 0 {
            return Err(Why(errno()));
        }
    }
    Ok(Signals { read })
}

impl Signals {
    pub fn fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    /// The name of the signal that came since last asked, if one did.
    pub fn take(&self) -> Option<&'static str> {
        let mut last = None;
        let mut buf = [0u8; 16];
        loop {
            // SAFETY: `buf` is writable for its whole length.
            let n = unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return last;
            }
            last = Some(if i32::from(buf[n as usize - 1]) == libc::SIGINT { "SIGINT" } else { "SIGTERM" });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_is_read_from_the_pipe() {
        let signals = install().unwrap();
        assert_eq!(signals.take(), None);
        // SAFETY: raising a signal whose handler was just installed.
        unsafe { libc::raise(libc::SIGINT) };
        assert_eq!(signals.take(), Some("SIGINT"));
        assert_eq!(signals.take(), None, "taken");
    }
}
