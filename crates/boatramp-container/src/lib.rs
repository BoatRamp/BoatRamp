//! Native Linux **container** backend for boatramp tier-2 compute.
//!
//! boatramp is its own minimal OCI runtime: a workload runs in a re-exec'd,
//! self-jailing worker (namespaces + cgroups + `pivot_root` + seccomp +
//! drop-privileges), `execve`-ing the entrypoint while sharing the host kernel.
//! No KVM — so this is the backend that runs on commodity Linux (and is testable
//! without virtualization). Per the isolation matrix it is **trusted-tier**;
//! untrusted multi-tenant code goes to the VMM/cloudflare backends.
//!
//! This crate's **pure layer** (cross-platform + unit-tested):
//! - [`net`] — a VM's **veth** pair into the bridge (the container analogue of
//!   the VMM's tap); names/IPAM are pure, the netlink calls are the Linux seam.
//! - [`sandbox`] — [`SandboxPlan`], the fully-resolved, serializable plan the
//!   self-jail worker applies (mounts, cgroup v2 limits, namespaces, argv/env).
//! - [`seccomp`] — the default-deny syscall allow-list the worker compiles to a
//!   BPF filter and installs before `execve`.
//!
//! The worker that *applies* a plan (the real `unshare`/`mount`/`pivot_root`/
//! seccomp syscalls) + the `ComputeBackend` impl, Linux-only.

// FFI/syscall-shaped and `target_os = "linux"`-gated: the container runtime
// (unshare/mount/pivot_root/seccomp) can't be compiled or `--fix`ed from a
// non-Linux host, so exempt the workspace lint floor here (per the Phase-0
// plan's crate-level allows for the FFI-shaped crates).
#![allow(
    clippy::use_self,
    clippy::redundant_closure_for_method_calls,
    clippy::explicit_iter_loop,
    clippy::explicit_into_iter_loop,
    clippy::manual_string_new,
    clippy::semicolon_if_nothing_returned
)]

/// The native container [`ComputeBackend`] (Linux): re-execs the self-jail
/// worker, wires veth + netns, stages the rootfs.
#[cfg(target_os = "linux")]
pub mod backend;
/// CRIU checkpoint/restore for scale-to-zero (Linux). Pure arg-builders + the
/// `criu` dump/restore drivers.
#[cfg(target_os = "linux")]
pub mod criu;
/// Per-project internal DNS — the pure, host-testable query-handling core
/// (parse question → decide answer/NXDOMAIN/refused/forward). Cross-platform.
pub mod dns;
/// The Linux socket seam for the internal DNS resolver: binds `gateway:53`, reads
/// the query source IP, and drives [`dns::Resolver`]. Linux-only (binds a socket).
#[cfg(target_os = "linux")]
pub mod dns_server;
/// `docker exec`-style re-entry into a running container (Linux): join the
/// container's namespaces + `execvp` a one-shot command, capturing its output.
#[cfg(target_os = "linux")]
pub mod exec;
/// The guest-log sink: drain the worker's (guest's) stdout/stderr to `tracing`
/// + a per-container log file. Cross-platform + unit-tested.
pub mod logsink;
pub mod net;
/// Writing a container's `/etc/resolv.conf` (points the guest at the internal
/// resolver on the bridge gateway). Pure filesystem work; cross-platform + tested.
pub mod resolvconf;
pub mod sandbox;
pub mod seccomp;
#[cfg(target_os = "linux")]
pub mod worker;

#[cfg(target_os = "linux")]
pub use backend::ContainerBackend;
#[cfg(target_os = "linux")]
pub use net::ensure_bridge;
pub use net::VethNetwork;
pub use sandbox::{CgroupLimits, Mount, Namespaces, SandboxPlan};
pub use seccomp::default_allowlist;
