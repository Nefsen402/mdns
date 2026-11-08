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
