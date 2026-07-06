//! Build the freestanding guest init (`src/vminit.c`) into a static, libc-free
//! x86_64 binary that the OCI rootfs builder embeds at `/sbin/init`. Only when
//! the `build` feature (the OCI→ext4 pipeline) is enabled.
//!
//! The init is a **Linux x86_64 guest** binary, so it can only be produced on a
//! Linux x86_64 build host (`cc` here compiles for the host) — which is where
//! `boatramp compute build` runs anyway (it also needs `mke2fs`). On other dev
//! hosts we emit an empty placeholder so the crate still compiles + unit-tests;
//! `build_rootfs` there would be non-functional, but it isn't supported off
//! Linux x86_64.

fn main() {
    // `build_rootfs` (behind the `build` feature) `include_bytes!`s the result.
    if std::env::var_os("CARGO_FEATURE_BUILD").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=src/vminit.c");
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("vminit");

    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        std::fs::write(&out, b"").expect("write vminit placeholder");
        println!(
            "cargo:warning=guest vminit not built (needs a linux-x86_64 host); \
             `compute build` is non-functional on this host"
        );
        return;
    }

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let status = std::process::Command::new(&cc)
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
        .unwrap_or_else(|e| panic!("running {cc} to build vminit.c: {e}"));
    assert!(
        status.success(),
        "{cc} failed to build src/vminit.c ({status})"
    );
}
