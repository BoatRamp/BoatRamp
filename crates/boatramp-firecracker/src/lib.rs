//! Firecracker microVM executor for boatramp's tier-3 compute.
//!
//! boatramp **is** the orchestrator: it builds the Firecracker machine config,
//! owns IP allocation, places replicas across KVM nodes, and drives the VMM —
//! no separate container runtime. This crate is the executor:
//!
//! - [`config`] — the Firecracker API/config-file model + a builder that turns a
//!   [`boatramp_types::compute::ComputeSpec`] + allocated resources into the JSON
//!   Firecracker boots from.
//! - [`ipam`] — a per-node IP pool (tap device IPs) with MAC derivation.
//! - [`net`] — the `ip`/`nft` command sequences for the host bridge + egress NAT
//!   and each VM's tap (setup + teardown).
//! - [`api`] — the ordered Firecracker REST API boot sequence + a minimal
//!   HTTP-over-unix-socket transport.
//! - [`executor`] — [`LaunchPlan`] (the pure tap + spawn + boot + teardown plan,
//!   optionally under the **jailer**) and [`Executor`], the runner that applies a
//!   plan against a [`executor::Host`], rolling back on failure.
//!
//! Placement/scheduling is backend-generic and lives in
//! `boatramp_core::compute` (the `ComputeBackend` trait + the bin-packer), since
//! it is shared with the other execution backends.
//!
//! The plans, sequences, rollback ordering, and jailer wiring are pure +
//! unit-tested via a recording fake. Only the real side effects — actually
//! spawning Firecracker/jailer, the live API round-trip, and the `ip`/`nft`
//! plumbing ([`executor::SystemHost`]) — require **Linux + `/dev/kvm`**, so
//! they are exercised by the `--ignored` `fc_live` test.

pub mod api;
pub mod config;
// The embedded rust-vmm boot-layout layer: pure x86_64 memory map / e820 /
// virtio-MMIO allocation. Cross-platform + unit-tested; the KVM runtime is the
// KVM-host seam.
pub mod embedded;
// A minimal Intel MP table: lets the embedded VMM's guest kernel discover
// the IO-APIC + route legacy IRQs (timer, COM1). Pure + unit-tested.
pub mod mptable;
// The embedded VMM KVM runtime: brings up an in-process microVM from the
// `embedded` layout. Linux + `/dev/kvm` only, behind the `embedded` feature; the
// live boot is the `compute-live` seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]
pub mod embedded_vmm;
// The embedded VMM's MMIO device manager: routes vCPU MMIO exits to the
// per-device transports + services notified queues. Linux + `embedded`; the
// routing/notify dispatch is mock-tested, the live run-loop wiring is the seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]
pub mod device_manager;
// The embedded VMM's virtio-block device backend: serves the guest's disk
// over the virtqueue bridge. Linux + `embedded` feature; unit-tested via a mock
// ring + an in-memory backing, the live wiring is the `compute-live` seam.
pub mod executor;
pub mod net;
#[cfg(feature = "build")]
pub mod oci;
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]
pub mod virtio_block;
// The embedded VMM's virtio-net device backend: bridges guest frames to a
// host tap over the virtqueue bridge. Linux + `embedded`; mock-tested.
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]
pub mod virtio_net;
// A host tap device: `/dev/net/tun` + `TUNSETIFF` for the embedded VMM's
// virtio-net. Linux + `embedded`; opening it needs `CAP_NET_ADMIN`, so the live
// wiring is the `compute-live` seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]
pub mod tap;
// The embedded VMM's seccomp sandbox: a default-deny run-loop syscall
// allow-list that confines the VM thread. The list is pure + unit-tested
// cross-platform; compiling/installing the BPF filter is the Linux seam.
#[cfg(feature = "embedded")]
pub mod embedded_seccomp;
// The embedded VMM's snapshot/restore state (scale-to-zero): capture a paused
// microVM's full vCPU + chip state (the guest RAM streams separately). Linux +
// `embedded`; the live snapshot→restore→resume cycle is the `compute-live` seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "embedded"))]
pub mod embedded_snapshot;
// The virtio-MMIO transport register protocol: pure state machine, the
// foundation for the embedded VMM's virtio devices. Cross-platform + unit-tested.
pub mod virtio_mmio;
// The VMM `ComputeBackend` impl (`backend` feature). Unix-only (it uses the
// real `SystemHost`); the orchestration is pure-testable, the boot is the KVM seam.
#[cfg(all(feature = "backend", unix))]
pub mod backend;

#[cfg(all(feature = "backend", unix))]
pub use backend::VmmBackend;

// Verify-before-boot: the trust gate a staged kernel clears before it is loaded
// into a guest. The trait + relaxed hash-only verifier live here (no auth deps);
// the posture-scaled signature-checking impl lives in the server.
#[cfg(feature = "backend")]
pub mod kernel_verify;
#[cfg(feature = "backend")]
pub use kernel_verify::{HashOnlyVerifier, KernelVerifier};

// The embedded VMM `ComputeBackend` impl: runs each replica as an
// in-process `EmbeddedVmm` instead of an external `firecracker` process. Needs
// both `backend` (the trait + async runtime) and `embedded` (the KVM runtime);
// Linux + `/dev/kvm`. The orchestration is pure-testable; the boot is the seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "backend", feature = "embedded"))]
pub mod embedded_backend;
#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "backend", feature = "embedded"))]
pub use embedded_backend::EmbeddedVmmBackend;

pub use config::{FcMachine, MachineResources};
pub use executor::{Executor, ExecutorConfig, Host, JailerConfig, LaunchPlan, Pid, RunningVm};
pub use net::{HostCommand, NodeNetwork, TapNetwork};
