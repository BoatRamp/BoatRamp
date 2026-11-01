//! CPU-affinity pinning so a frontend/backend pair measured on one box don't steal each other's
//! core (the faithfulness discipline the task spec calls out explicitly — "pin CPU affinity
//! (taskset) so the two endpoints don't steal each other's core"). Linux-only (`sched_setaffinity`
//! has no portable equivalent); a no-op elsewhere so the harness still BUILDS on macOS/CI.

use std::io;

#[cfg(target_os = "linux")]
pub fn pin_current_thread(core: usize) -> io::Result<()> {
    // SAFETY: `set` is a correctly-sized, zeroed, stack-local `cpu_set_t`; the macros only ever
    // touch bits within it.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread(_core: usize) -> io::Result<()> {
    Ok(())
}
