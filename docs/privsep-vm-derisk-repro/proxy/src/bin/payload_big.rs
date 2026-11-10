// Same as payload.rs but with a LARGE self-relocation table (~100k R_X86_64_RELATIVE entries,
// multi-MB RELASZ) to match the scale of boatramp's real static-PIE binary (240,782 relocs /
// 5.7 MB RELASZ, per docs/privsep-build-hardening.md) — rules out a reloc-table-SIZE-triggered
// #GP during musl crt1 self-relocation as PID 1.
use std::ffi::CString;
use std::io::Write;

static DATA: u8 = 7;
#[repr(transparent)]
#[derive(Clone, Copy)]
struct P(*const u8);
unsafe impl Sync for P {}
// Array repeat of a &static pointer: the linker emits one R_X86_64_RELATIVE reloc per slot.
#[used]
static PTRS: [P; 100_000] = [P(&DATA as *const u8); 100_000];

fn cstr(s: &str) -> CString { CString::new(s).unwrap() }
fn read_trim(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default().lines().next().unwrap_or("").to_string()
}
fn main() {
    unsafe {
        libc::mount(cstr("proc").as_ptr(), cstr("/proc").as_ptr(), cstr("proc").as_ptr(), 0, std::ptr::null());
        // Touch both ends of the relocated table so it is not dead-stripped and the relocations
        // must have been applied correctly for these reads to be valid.
        let a = std::ptr::read_volatile(&PTRS[0]).0;
        let b = std::ptr::read_volatile(&PTRS[99_999]).0;
        let ok = a == &DATA as *const u8 && b == &DATA as *const u8;
        println!("PAYLOADBIG-ALIVE reached_main pid={} reloc_table_ok={}", libc::getpid(), ok);
        println!("PAYLOADBIG-RELOC_SAMPLE a={:p} b={:p} data={:p}", a, b, &DATA as *const u8);
        println!("PAYLOAD-AT_ENTRY 0x{:x}", libc::getauxval(libc::AT_ENTRY));
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
