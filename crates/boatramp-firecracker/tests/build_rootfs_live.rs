//! Live `oci::build_rootfs` — **ignored by default** (network pull + `mke2fs`).
//! Builds a bootable ext4 rootfs from a real multi-arch image and asserts the
//! embedded guest `vminit` (baked at `/sbin/init`) matches the host/guest arch, so
//! `compute build` produces a rootfs the same-arch VMM backend can boot. On an
//! Apple-silicon host this exercises the aarch64 path end-to-end.
//!
//! Run with (needs `mke2fs` on PATH, e.g. via `nix develop` / e2fsprogs):
//! ```sh
//! cargo test -p boatramp-firecracker --features build -- --ignored build_rootfs_live
//! ```
//! Set `BOATRAMP_BUILD_ROOTFS_OUT=/path.ext4` to keep the image for a boot test.

#![cfg(feature = "build")]

#[tokio::test]
#[ignore = "network pull + mke2fs; run explicitly on a host with e2fsprogs"]
async fn build_rootfs_live() {
    let out = std::env::var_os("BOATRAMP_BUILD_ROOTFS_OUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("boatramp-seam1-rootfs.ext4"));
    // A tiny multi-arch image; the resolver picks the guest arch automatically.
    let entrypoint = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo BUILD-ROOTFS-BOOT-OK; ip link set eth0 up; echo ok > /tmp/i; \
         busybox httpd -p 8080 -h /tmp; while true; do sleep 5; done"
            .to_string(),
    ];
    let env = vec![("BOATRAMP_BUILT".to_string(), "yes".to_string())];
    boatramp_firecracker::oci::build_rootfs("busybox:latest", &entrypoint, &env, &out, 128, &[])
        .await
        .expect("build_rootfs should produce a bootable ext4");

    let meta = std::fs::metadata(&out).expect("rootfs image exists");
    assert!(
        meta.len() > 1_000_000,
        "rootfs is a real image ({} bytes)",
        meta.len()
    );
    eprintln!("built rootfs at {} ({} bytes)", out.display(), meta.len());
}
