//! `boatramp-privsep-vm-shim` — the **non-PIE init shim** for the scoped privsep VM substrate
//! (own-binary-as-init, `crates/boatramp/DESIGN-privsep-phase3-vm-derisk.md` §1, the O3b hypothesis
//! validated live on firecracker + `/dev/kvm`).
//!
//! It is PID 1 inside the microVM (booted `rdinit=/init`): it mounts `/proc`, `/sys`, `/dev`, then
//! `execve`s the real static-PIE `boatramp __vm-guest`. Why a shim at all: boatramp's shipped musl
//! release binary is a genuine **static-PIE** (`.cargo/config.toml` `-C target-feature=-crt-static`,
//! for ASLR), which can `#GP`-fault as a minimal-kernel guest's *direct* PID 1 (no dynamic linker to
//! finish the self-relocation — O3b). A tiny **non-PIE** shim boots clean as PID 1 and reaches the
//! static-PIE binary via a normal `execve` (where musl `crt1` self-relocation works), so boatramp
//! keeps its ASLR and the release pipeline ships ONE static-PIE binary + this ~kilobyte shim — no dual
//! PIE/non-PIE artifact (de-risk §1.4).
//!
//! Built NON-PIE in a dedicated invocation (`RUSTFLAGS="-C target-feature=+crt-static -C
//! relocation-model=static"`), which OVERRIDES the workspace static-PIE musl config for this one
//! binary — the same recipe the bench `guest/build-initrd.sh` uses for its guest init. A standalone
//! crate depending on nothing but `libc` + `std`, so it stays tiny and self-contained.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use std::ffi::CString;

    fn cstr(s: &str) -> CString {
        CString::new(s).expect("static shim path has no interior NUL")
    }
    // Write a marker to the console via a RAW `write(2)` — NOT `println!`, which PANICS (abort, exit
    // 101) if init's stdout fd is not wired, which the kernel does not always do for PID 1. A failed
    // write here is ignored; the shim must never panic as PID 1 (that is "Attempted to kill init").
    fn say(msg: &[u8]) {
        // SAFETY: write(2) of a valid byte slice to fd 1; errors are ignored on purpose.
        unsafe {
            libc::write(1, msg.as_ptr().cast(), msg.len());
        }
    }

    // SAFETY: each call is a plain libc syscall with valid, fully-initialized arguments; this process
    // is PID 1 in a fresh microVM guest, so these mounts/execve touch only the guest's own namespaces.
    unsafe {
        // Wire init's stdin/stdout/stderr to the console EXPLICITLY (the kernel does not reliably open
        // /dev/console for PID 1), so the markers below are visible on `ttyS0` and nothing panics on a
        // closed fd. /dev/console is a static node in the initramfs, available before any mount.
        let console = libc::open(cstr("/dev/console").as_ptr(), libc::O_RDWR);
        if console >= 0 {
            libc::dup2(console, 0);
            libc::dup2(console, 1);
            libc::dup2(console, 2);
            if console > 2 {
                libc::close(console);
            }
        }
        // Mount the pseudo-filesystems the guest serve needs: /proc (the Landlock ABI probe reads the
        // kernel's own FS-ABI; sandbox self-checks read /proc/self), /sys, and a devtmpfs /dev.
        libc::mount(
            cstr("proc").as_ptr(),
            cstr("/proc").as_ptr(),
            cstr("proc").as_ptr(),
            0,
            std::ptr::null(),
        );
        libc::mount(
            cstr("sysfs").as_ptr(),
            cstr("/sys").as_ptr(),
            cstr("sysfs").as_ptr(),
            0,
            std::ptr::null(),
        );
        libc::mount(
            cstr("devtmpfs").as_ptr(),
            cstr("/dev").as_ptr(),
            cstr("devtmpfs").as_ptr(),
            0,
            std::ptr::null(),
        );
        say(b"SHIM-ALIVE nonpie_init exec=/boatramp __vm-guest\n");

        // execve the real static-PIE boatramp in guest-serve mode. A clean, minimal argv + empty env
        // (the guest reads its label/port from the packed /privsep-vm-guest.json; no secrets cross in).
        let path = cstr("/boatramp");
        let a0 = cstr("boatramp");
        let a1 = cstr("__vm-guest");
        let argv = [a0.as_ptr(), a1.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());

        // execve only returns on failure. Log + power off so firecracker exits and the host trips
        // FailNodeClosed (PID 1 must never return cleanly, or the kernel panics).
        say(b"SHIM-EXECVE-FAILED\n");
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
        loop {
            libc::pause();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "boatramp-privsep-vm-shim is a Linux-only microVM init (own-binary-as-init); not supported on \
         this target"
    );
    std::process::ExitCode::FAILURE
}
