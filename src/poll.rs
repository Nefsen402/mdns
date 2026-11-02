//! Waiting on several descriptors at once, with poll(2): with the handful of
//! descriptors the daemon has, nothing more elaborate is called for.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// A descriptor to wait on until it can be read.
pub fn readable(fd: RawFd) -> libc::pollfd {
    libc::pollfd { fd, events: libc::POLLIN, revents: 0 }
}

/// Whether `fd` came back from [`wait`] with something to do: readable, or
/// closed or failed at the other end, which a read then tells of.
pub fn ready(fd: &libc::pollfd) -> bool {
    fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
}

/// Wait until one of `fds` is ready, or `timeout` (`None`: no limit) passes.
/// Interrupted by a signal, it returns early, with nothing ready.
pub fn wait(fds: &mut [libc::pollfd], timeout: Option<Duration>) -> io::Result<()> {
    // Rounded up, so that what is due is due when it returns.
    let ms = timeout.map_or(-1, |t| i32::try_from(t.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX));
    for fd in fds.iter_mut() {
        fd.revents = 0;
    }
    // SAFETY: `fds` is a valid array of pollfd of the length given.
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(())
}

/// A way for other threads to cut the event loop's wait short: a pipe, whose
/// reading end the loop waits on.
pub struct Waker {
    read: OwnedFd,
    write: OwnedFd,
}

impl Waker {
    pub fn new() -> io::Result<Waker> {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors pipe2 fills in.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both were just created, and are owned by nothing else.
        unsafe { Ok(Waker { read: OwnedFd::from_raw_fd(fds[0]), write: OwnedFd::from_raw_fd(fds[1]) }) }
    }

    /// Make the loop look again. A full pipe already says so.
    pub fn wake(&self) {
        // SAFETY: one byte from a valid buffer.
        unsafe { libc::write(self.write.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    }

    pub fn fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    /// Take what woke the loop, so that it waits again.
    pub fn clear(&self) {
        let mut buf = [0u8; 64];
        // SAFETY: `buf` is writable for its whole length.
        while unsafe { libc::read(self.read.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use std::time::Instant;

    #[test]
    fn waits_for_what_is_readable_or_the_timeout() {
        let (a, b) = UnixDatagram::pair().unwrap();
        let mut fds = [readable(b.as_raw_fd())];
        let start = Instant::now();
        wait(&mut fds, Some(Duration::from_millis(30))).unwrap();
        assert!(!ready(&fds[0]) && start.elapsed() >= Duration::from_millis(30));

        a.send(b"x").unwrap();
        wait(&mut fds, None).unwrap();
        assert!(ready(&fds[0]));
    }

    #[test]
    fn a_waker_wakes_the_wait_until_cleared() {
        let waker = Waker::new().unwrap();
        let mut fds = [readable(waker.fd())];
        waker.wake();
        waker.wake();
        wait(&mut fds, None).unwrap();
        assert!(ready(&fds[0]));
        waker.clear();
        wait(&mut fds, Some(Duration::ZERO)).unwrap();
        assert!(!ready(&fds[0]), "cleared");
    }
}
