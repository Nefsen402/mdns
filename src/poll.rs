//! Waiting on several descriptors at once, with poll(2): with the handful of
//! descriptors the daemon has, nothing more elaborate is called for.

use std::io;
use std::os::fd::RawFd;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
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
}
