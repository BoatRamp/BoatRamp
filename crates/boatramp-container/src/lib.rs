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

/// The native container [`ComputeBackend`] (Linux): re-execs the self-jail
/// worker, wires veth + netns, stages the rootfs.
#[cfg(target_os = "linux")]
pub mod backend;
/// The guest-log sink: drain the worker's (guest's) stdout/stderr to `tracing`
/// + a per-container log file. Cross-platform + unit-tested.
pub mod logsink;
pub mod net;
pub mod sandbox;
pub mod seccomp;
#[cfg(target_os = "linux")]
pub mod worker;

#[cfg(target_os = "linux")]
pub use backend::ContainerBackend;
pub use net::VethNetwork;
pub use sandbox::{CgroupLimits, Mount, Namespaces, SandboxPlan};
pub use seccomp::default_allowlist;
