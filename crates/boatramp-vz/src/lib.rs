//! macOS-native compute backend for boatramp: run a Linux workload as a
//! lightweight **per-replica virtual machine** on Apple silicon via Apple's
//! **Virtualization.framework**, driven in-process from Rust through the
//! [`objc2-virtualization`](https://docs.rs/objc2-virtualization) bindings.
//!
//! It is the macOS/Apple-silicon analog of the Linux/KVM embedded VMM backend
//! ([`boatramp-firecracker`](../boatramp_firecracker/index.html)): same
//! [`ComputeBackend`](boatramp_core::compute::ComputeBackend) seam, same
//! `Artifact::VmImages` (an `ext4` rootfs + a guest `vmlinux`), same
//! `Endpoint{host: guest_ip, port}` model, same verify-before-boot kernel gate —
//! but the VM is booted by Virtualization.framework's `VZVirtualMachine` instead
//! of an in-process KVM VMM. Each replica runs in **its own re-exec'd process**
//! (`boatramp __vz-run <WorkerConfig>`), so boatramp stays a **single binary**
//! and a guest can't share an address space with the serve process or a sibling.
//!
//! Crate layout (mirrors the firecracker split — a pure, cross-platform layer
//! plus a macOS-only VM host):
//! - [`config`] — the `WorkerConfig`/`WorkerVolume` wire types + kernel-cmdline
//!   assembly (pure, cross-platform, unit-tested everywhere).
//! - [`net`] — guest-IP → MAC derivation + the default `ip=` cmdline (pure).
//! - `vm` — the `VZVirtualMachineConfiguration` builder + run loop
//!   (`target_os = "macos"` only).
//! - `backend` — the [`ComputeBackend`] impl (`backend` feature).
//!
//! ## Requirements
//! Apple silicon + macOS 26 (recommended). macOS 15 is the technical floor but
//! lacks container-to-container networking over vmnet; the caller
//! (`boatramp-node`'s `build_compute`) capability-detects and skips this backend
//! on Intel / older macOS, exactly like the `/dev/kvm` check gates the KVM VMM.

pub mod config;
pub mod net;

#[cfg(all(target_os = "macos", feature = "backend"))]
pub mod vm;

#[cfg(feature = "backend")]
pub mod backend;

pub use config::{WorkerConfig, WorkerVolume};

#[cfg(feature = "backend")]
pub use backend::VzBackend;

/// The re-exec subcommand the backend invokes for each VM: `<self_exe> __vz-run
/// <json-WorkerConfig>`. The host binary (and the crate's own `vz-worker` bin)
/// route it to [`vm::run_worker`] (macOS) — mirroring the KVM backend's
/// `__vmm-run`.
pub const VZ_RUN_SUBCOMMAND: &str = "__vz-run";

/// A verify-before-boot gate for a staged guest kernel, run right before the VM
/// loads it. Mirrors `boatramp_firecracker::KernelVerifier` so the same
/// `PostureKernelVerifier` (in `boatramp-node`) drives both backends: the kernel
/// is ring-0 code, so under the strict (multi-tenant) posture it must clear the
/// content-hash + allow-list + signature bar before any guest runs it.
///
/// The trait lives here (not behind the `backend` feature) so a caller can name
/// it without the async runtime, matching the firecracker crate.
pub trait KernelVerifier: std::fmt::Debug + Send + Sync {
    /// Verify the staged kernel `bytes` (whose content hash is `expected_hash`).
    /// `Ok(())` ⇒ boot is allowed; `Err(_)` aborts `materialize` (nothing boots).
    fn verify(&self, bytes: &[u8], expected_hash: &str) -> Result<(), String>;
}

/// A no-op [`KernelVerifier`] for tests / the single-tenant default where the
/// content hash is the only bar (the backend still hashes-checks blobs when it
/// stages them by content-addressed key). Never use under the strict posture.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAnyKernel;

impl KernelVerifier for AllowAnyKernel {
    fn verify(&self, _bytes: &[u8], _expected_hash: &str) -> Result<(), String> {
        Ok(())
    }
}
