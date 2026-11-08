//! What std gives a program, for one built without it: print macros, its
//! start (SIGPIPE ignored, as std has it), its memory and an end to it when
//! it panics, and errors from the system worded as std words them. The
//! crate names itself with a `PROGRAM` constant, and runs its command line
//! with `run(args) -> c_int`. Tests are built with std, and use std's.
//!
//! Declared first in the crate, with `#[macro_use]`, for the macros.

use core::ffi::{c_int, CStr};
use core::fmt;

use rustix::io::Errno;

// What std's print macros do, to stdout and stderr: tests use std's, which
// the test harness captures.
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! print {
    ($($arg:tt)*) => { $crate::runtime::write_out(1, &::alloc::format!($($arg)*)) };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! println {
    ($($arg:tt)*) => { $crate::runtime::write_out(1, &::alloc::format!("{}\n", format_args!($($arg)*))) };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprint {
    ($($arg:tt)*) => { $crate::runtime::write_out(2, &::alloc::format!($($arg)*)) };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprintln {
    ($($arg:tt)*) => { $crate::runtime::write_out(2, &::alloc::format!("{}\n", format_args!($($arg)*))) };
}

/// Write all of `bytes` to `fd` (stdout or stderr), waiting as it must.
pub fn write_all(fd: c_int, mut bytes: &[u8]) -> Result<(), rustix::io::Errno> {
    // SAFETY: stdout and stderr are open for as long as the process runs.
    let fd = unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) };
    while !bytes.is_empty() {
        match rustix::io::write(fd, bytes) {
            Ok(0) => return Err(rustix::io::Errno::PIPE),
            Ok(n) => bytes = &bytes[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Write `text` to `fd` (stdout or stderr), as far as it goes.
#[cfg_attr(test, allow(dead_code))]
pub fn write_out(fd: c_int, text: &str) {
    let _ = write_all(fd, text.as_bytes());
}

/// An error from the system, worded by it, as std would: rustix, without
/// std, says only "os error 2", where this says "No such file or directory
/// (os error 2)".
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

/// Where this thread's `errno` is: libc keeps it behind a function whose name
/// is the system's own.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "dragonfly"))]
pub fn errno_location() -> *mut libc::c_int {
    // SAFETY: the function only returns the address of the thread's errno.
    unsafe { libc::__errno_location() }
}

/// Where this thread's `errno` is.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub fn errno_location() -> *mut libc::c_int {
    // SAFETY: the function only returns the address of the thread's errno.
    unsafe { libc::__error() }
}

/// Where this thread's `errno` is.
#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
pub fn errno_location() -> *mut libc::c_int {
    // SAFETY: the function only returns the address of the thread's errno.
    unsafe { libc::__errno() }
}

/// What the last libc call that failed left in `errno`.
pub fn errno() -> Errno {
    // SAFETY: errno is the calling thread's, and always there to read.
    Errno::from_raw_os_error(unsafe { *errno_location() })
}

#[cfg(not(test))]
mod start {
    use core::alloc::{GlobalAlloc, Layout};
    use core::ffi::{c_char, c_int, CStr};
    use core::fmt::Write;

    use alloc::string::ToString;
    use alloc::vec::Vec;

    // std would link libc: the libc crate only declares it.
    #[link(name = "c")]
    unsafe extern "C" {}

    /// The program's start: its arguments as text, after its name.
    #[unsafe(no_mangle)]
    extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
        let mut args = Vec::new();
        for i in 1..argc.max(1) as usize {
            // SAFETY: argv holds argc NUL-terminated strings.
            match unsafe { CStr::from_ptr(*argv.add(i)) }.to_str() {
                Ok(arg) => args.push(arg.to_string()),
                Err(_) => {
                    eprintln!("{}: {}", crate::PROGRAM, crate::args::Error::NotUtf8);
                    return 2;
                }
            }
        }
        // As std does: a write to a pipe or socket no one reads fails, rather
        // than ending the program, and is dealt with where it happens. A
        // program it runs starts with SIGPIPE as the system has it.
        // SAFETY: setting a disposition, before anything else runs.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        crate::run(args)
    }

    /// The most alignment malloc gives whatever is asked of it.
    const MIN_ALIGN: usize = if cfg!(target_pointer_width = "64") { 16 } else { 8 };

    /// libc's malloc, as std's own allocator uses it.
    struct Malloc;

    // SAFETY: what malloc, posix_memalign and realloc return is aligned as
    // asked, or null, and is freed only with free.
    unsafe impl GlobalAlloc for Malloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
                // SAFETY: as above.
                unsafe { libc::malloc(layout.size()).cast() }
            } else {
                let mut out = core::ptr::null_mut();
                let align = layout.align().max(core::mem::size_of::<usize>());
                // SAFETY: as above; `align` is a power of two, and a multiple of
                // the size of a pointer.
                match unsafe { libc::posix_memalign(&mut out, align, layout.size()) } {
                    0 => out.cast(),
                    _ => core::ptr::null_mut(),
                }
            }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
            // SAFETY: as above.
            unsafe { libc::free(ptr.cast()) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if layout.align() <= MIN_ALIGN && layout.align() <= new_size {
                // SAFETY: as above.
                return unsafe { libc::realloc(ptr.cast(), new_size).cast() };
            }
            // SAFETY: as above: a new allocation, what fits of the old copied
            // in, and the old freed.
            unsafe {
                let new = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
                if !new.is_null() {
                    core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                    self.dealloc(ptr, layout);
                }
                new
            }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Malloc = Malloc;

    /// Stderr, unbuffered, for a panic, which may be about memory.
    struct Stderr;

    impl Write for Stderr {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            super::write_out(2, s);
            Ok(())
        }
    }

    // core and alloc come built to unwind, and so name the unwinder's entry
    // points; nothing here unwinds, as a panic aborts, so they are never
    // called, and are not worth linking libgcc_s for.
    #[unsafe(no_mangle)]
    extern "C" fn rust_eh_personality() {}

    #[unsafe(no_mangle)]
    extern "C" fn _Unwind_Resume() -> ! {
        // SAFETY: abort takes nothing, and does not return.
        unsafe { libc::abort() }
    }

    /// Say what went wrong, and end at once.
    #[panic_handler]
    fn panic(info: &core::panic::PanicInfo) -> ! {
        let _ = writeln!(Stderr, "{}: {info}", crate::PROGRAM);
        // SAFETY: abort takes nothing, and does not return.
        unsafe { libc::abort() }
    }
}

#[cfg(test)]
#[path = "../tests/unit/runtime.rs"]
mod tests;
