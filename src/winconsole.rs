//! The release build is a window program; started from a terminal, its text output goes to
//! that terminal (unless it is already redirected, e.g. to a pipe).
#![allow(unsafe_code)] // Windows console API; named exception in AGENTS.md

pub fn attach() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_OUTPUT_HANDLE};
        // SAFETY: both calls take plain values and no pointers; a failure (no parent console)
        // is reported by the return value and simply leaves the program without a console.
        unsafe {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            if h.is_null() || h as isize == -1 {
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
        }
    }
}
