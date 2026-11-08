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
