// Faithful static-PIE proxy for boatramp's own-binary-as-init payload: same musl crt1 static-PIE
// self-relocation (built with the repo's exact `-C target-feature=-crt-static` recipe => ET_DYN,
// no PT_INTERP, zero DT_NEEDED). Proves reaching main + reports ASLR via AT_ENTRY.
use std::ffi::CString;
use std::io::Write;
fn cstr(s: &str) -> CString { CString::new(s).unwrap() }
fn read_trim(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default().lines().next().unwrap_or("").to_string()
}
fn main() {
    unsafe {
        libc::mount(cstr("proc").as_ptr(), cstr("/proc").as_ptr(), cstr("proc").as_ptr(), 0, std::ptr::null());
        let pid = libc::getpid();
        println!("PAYLOAD-ALIVE reached_main pid={pid}");
        println!("PAYLOAD-AT_ENTRY 0x{:x}", libc::getauxval(libc::AT_ENTRY));
        println!("PAYLOAD-AT_BASE 0x{:x}", libc::getauxval(libc::AT_BASE));
        println!("PAYLOAD-MAIN_ADDR {:p}", main as *const ());
        println!("PAYLOAD-MAPS0 {}", read_trim("/proc/self/maps"));
        println!("PAYLOAD-RANDOMIZE_VA {}", read_trim("/proc/sys/kernel/randomize_va_space"));
        println!("PAYLOAD-DONE power_off");
        let _ = std::io::stdout().flush();
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
        loop { libc::pause(); }
    }
}
