//! Build the freestanding guest init (`src/vminit.c`) into a static, libc-free
//! ELF that the OCI rootfs builder embeds at `/sbin/init` — only with the `build`
//! feature (the OCI→ext4 pipeline).
//!
//! The init is a **Linux guest** binary whose arch mirrors the build host's: an
//! x86_64 host boots x86_64 KVM guests (the embedded VMM), an Apple-silicon host
//! boots aarch64 guests (the macOS Virtualization.framework backend). Compiler
//! selection, in order:
//!   1. `VMINIT_CC` — an explicit compiler command line (may include args), for a
//!      custom cross toolchain.
//!   2. Native `cc` when the host is **Linux** of the guest arch — the long-proven
//!      path (CI builds the x86_64 init this way; unchanged).
//!   3. `zig cc --target=<arch>-linux-musl` to **cross-compile** from a non-Linux
//!      host (e.g. macOS → aarch64-linux): hermetic, bundles its own ELF linker.
//!   4. Otherwise an empty placeholder + a warning, so the crate still compiles and
//!      unit-tests; `build_rootfs` is then non-functional on that host (as before).

use std::path::Path;

fn main() {
    // `build_rootfs` (behind the `build` feature) `include_bytes!`s the result.
    if std::env::var_os("CARGO_FEATURE_BUILD").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=src/vminit.c");
    for v in ["VMINIT_CC", "ZIG", "CC"] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("vminit");

    // The guest arch mirrors the host arch (cross-arch guests aren't supported).
    let guest_arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        return placeholder(&out, "host arch is neither x86_64 nor aarch64");
    };

    // The compiler command (program + any leading args) to prepend to the sources.
    let mut argv: Vec<String> = Vec::new();
    if let Some(line) = std::env::var_os("VMINIT_CC") {
        argv.extend(line.to_string_lossy().split_whitespace().map(String::from));
    } else if cfg!(target_os = "linux") {
        // Native cc on a Linux host of the guest arch — the proven path.
        argv.push(std::env::var("CC").unwrap_or_else(|_| "cc".into()));
    } else if let Some(zig) = find_zig() {
        // Cross-compile to <arch>-linux from a non-Linux host (e.g. macOS).
        argv.push(zig);
        argv.push("cc".into());
        argv.push(format!("--target={guest_arch}-linux-musl"));
    } else {
        return placeholder(
            &out,
            "no cross-compiler for the guest vminit (install `zig` or set VMINIT_CC); \
             `compute build` is non-functional on this host",
        );
    }

    let program = argv[0].clone();
    let status = std::process::Command::new(&program)
        .args(&argv[1..])
        .args([
            "-static",
            "-nostdlib",
            "-ffreestanding",
            "-no-pie",
            "-Os",
            "-Wall",
            "-fno-stack-protector",
            "src/vminit.c",
            "-o",
        ])
        .arg(&out)
        .status()
        .unwrap_or_else(|e| panic!("running {program} to build vminit.c: {e}"));
    assert!(
        status.success(),
        "{program} failed to build src/vminit.c ({status})"
    );
}

/// Locate a `zig` binary: the `ZIG` env override, else a `PATH` lookup.
fn find_zig() -> Option<String> {
    if let Some(z) = std::env::var_os("ZIG") {
        return Some(z.to_string_lossy().into_owned());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("zig"))
        .find(|cand| cand.is_file())
        .map(|cand| cand.to_string_lossy().into_owned())
}

/// Emit an empty init + a build warning (the crate still compiles + unit-tests;
/// `build_rootfs` is non-functional on this host).
fn placeholder(out: &Path, why: &str) {
    std::fs::write(out, b"").expect("write vminit placeholder");
    println!("cargo:warning=guest vminit not built: {why}");
}
