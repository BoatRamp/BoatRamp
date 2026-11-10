// Non-PIE static init shim (the O3b hypothesis): PID 1, mounts /proc, then execve()s the static-PIE
// payload -- so PID 1 itself is non-PIE (boots clean) and the static-PIE binary is reached via a
// normal execve (where musl static-PIE self-relocation works), keeping the payload's ASLR.
use std::ffi::CString;
use std::io::Write;
fn cstr(s: &str) -> CString { CString::new(s).unwrap() }
fn main() {
    unsafe {
        libc::mount(cstr("proc").as_ptr(), cstr("/proc").as_ptr(), cstr("proc").as_ptr(), 0, std::ptr::null());
        println!("SHIM-ALIVE nonpie_init pid={} mounted_proc exec=/payload", libc::getpid());
        let _ = std::io::stdout().flush();
        let path = cstr("/payload");
        let argv = [path.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        println!("SHIM-EXECVE-FAILED errno={}", *libc::__errno_location());
        let _ = std::io::stdout().flush();
        libc::reboot(libc::RB_AUTOBOOT);
        loop { libc::pause(); }
    }
}
