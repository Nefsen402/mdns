//! Shutdown signals, handled synchronously rather than in a handler: they
//! are blocked in every thread, and the main thread waits for them.

use std::io;
use std::mem::MaybeUninit;

fn shutdown_set() -> libc::sigset_t {
    let mut set = MaybeUninit::uninit();
    // SAFETY: sigemptyset initializes the set before it is read.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM);
        libc::sigaddset(set.as_mut_ptr(), libc::SIGINT);
        set.assume_init()
    }
}

/// Block SIGTERM and SIGINT in the calling thread. Threads spawned
/// afterwards inherit the mask, so call this before spawning any.
pub fn block() -> io::Result<()> {
    let set = shutdown_set();
    // SAFETY: `set` is a valid, initialized sigset_t; the old mask is unused.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    match rc {
        0 => Ok(()),
        errno => Err(io::Error::from_raw_os_error(errno)),
    }
}

/// Wait until SIGTERM or SIGINT arrives and return its name. They must have
/// been blocked with [`block`].
pub fn wait() -> io::Result<&'static str> {
    let set = shutdown_set();
    let mut sig = 0;
    // SAFETY: `set` is valid and `sig` is a valid out-pointer.
    match unsafe { libc::sigwait(&set, &mut sig) } {
        0 if sig == libc::SIGINT => Ok("SIGINT"),
        0 => Ok("SIGTERM"),
        errno => Err(io::Error::from_raw_os_error(errno)),
    }
}
