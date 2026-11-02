//! An error from the system, as the system words it. rustix, without std,
//! says only "os error 2": [`Why`] says "No such file or directory (os error
//! 2)", as std would.

use core::ffi::CStr;
use core::fmt;

use rustix::io::Errno;

/// An error from the system, worded by it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Why(pub Errno);

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 128];
        // SAFETY: `buf` is writable for its length; the XSI strerror_r writes a
        // NUL-terminated message into it, or fails and leaves it alone.
        let ok = unsafe { libc::strerror_r(self.0.raw_os_error(), buf.as_mut_ptr().cast(), buf.len()) } == 0;
        match CStr::from_bytes_until_nul(&buf).ok().and_then(|m| m.to_str().ok()).filter(|_| ok) {
            Some(message) => write!(f, "{message} (os error {})", self.0.raw_os_error()),
            None => write!(f, "os error {}", self.0.raw_os_error()),
        }
    }
}

impl fmt::Debug for Why {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl core::error::Error for Why {}

impl From<Errno> for Why {
    fn from(e: Errno) -> Why {
        Why(e)
    }
}

/// What the last libc call that failed left in `errno`.
pub fn last() -> Errno {
    // SAFETY: errno is the calling thread's, and always there to read.
    Errno::from_raw_os_error(unsafe { *libc::__errno_location() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_an_error_as_the_system_does() {
        assert_eq!(Why(Errno::NOENT).to_string(), "No such file or directory (os error 2)");
        assert_eq!(alloc::format!("{:?}", Why(Errno::NOENT)), "No such file or directory (os error 2)");
    }
}
