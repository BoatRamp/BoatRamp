//! Fixture builder for the VZ scale-to-zero live test
//! (`boatramp-vz` `tests/vz_live.rs::vz_live_snapshot_restore_roundtrip`): build a
//! bootable aarch64 ext4 rootfs from busybox + the baked guest `vminit`. The
//! entrypoint copies the kernel `boot_id` (regenerated on every cold boot, held in
//! kernel RAM) into a tmpfs file, serves it over httpd, and heartbeats it to the
//! serial console — so a restore that preserves RAM keeps emitting the SAME nonce,
//! a cold boot a DIFFERENT one. Gated on the `build` feature (`oci::build_rootfs`).
//!
//! Run inside `nix develop` (needs zig to cross-compile vminit + mke2fs):
//!   BOATRAMP_VZFIX_OUT=/tmp/vz-fixtures/rootfs.ext4 \
//!     cargo run -p boatramp-firecracker --features build --example vzfix

#[tokio::main]
async fn main() {
    let out = std::env::var_os("BOATRAMP_VZFIX_OUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("vz-fixtures/rootfs.ext4"));
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let entrypoint = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        // boot_id → tmpfs nonce (kernel-generated once per cold boot, held in RAM),
        // serve it over httpd (daemonizes), then heartbeat the SAME nonce to the
        // serial console every 2s. The heartbeat is a networking-independent restore
        // probe: a resumed guest keeps printing the same VZFIX-NONCE to the restore
        // process's serial; a cold reboot shows kernel boot messages + a new nonce.
        "cp /proc/sys/kernel/random/boot_id /tmp/nonce; \
         echo VZFIX-READY nonce=$(cat /tmp/nonce); \
         busybox httpd -p 8080 -h /tmp; \
         while true; do echo VZFIX-NONCE=$(cat /tmp/nonce); sleep 2; done"
            .to_string(),
    ];
    let env: Vec<(String, String)> = vec![];
    boatramp_firecracker::oci::build_rootfs("busybox:latest", &entrypoint, &env, &out, 128, &[])
        .await
        .expect("build_rootfs should produce a bootable ext4");
    let meta = std::fs::metadata(&out).expect("rootfs exists");
    eprintln!("built rootfs at {} ({} bytes)", out.display(), meta.len());
}
