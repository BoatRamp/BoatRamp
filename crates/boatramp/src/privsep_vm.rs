//! The **scoped privsep VM substrate** (firecracker/Linux, static-parser-frontends-only) — the
//! owner-greenlit first cut of the Phase-3 VM backend (`crates/boatramp/DESIGN-privsep-phase3-vm.md`
//! §2 Option A + `DESIGN-privsep-phase3-vm-derisk.md` §1 the O3b init-shim). It launches a
//! privilege-separated **static-parser frontend** (a group-C `listen.*` instance holding NO crown
//! jewel and NO backend credential — the lint's P3; `check_vm_secret_blindness_closure` Tier 3) inside
//! a hardware-virtualized microVM GUEST (its own kernel — the strongest wall), reached over a vsock
//! byte-relay that carries ONLY untrusted client bytes.
//!
//! **What this module is / is NOT (the scope fence):**
//! - It wires the vsock **client-byte** relay (Model A, design §1c): the secret-blind root binds the
//!   privileged TCP listener, accepts each client, and relays the client's bytes over firecracker's
//!   host-side vsock UDS bridge to the frontend-in-guest. The guest runs the SAME static-PIE
//!   `boatramp` binary (own-binary-as-init) as a self-contained parse-and-serve surface.
//! - It does **NOT** wire any vsock **key-material** relay, and never routes key bytes through the
//!   root (owner-GATED, `DESIGN-privsep-phase3-vm.md` §3 / S2). A scoped static-parser frontend holds
//!   zero key material, so root-holds-no-secret is trivially preserved — the composition lint
//!   (`check_vm_secret_blindness_closure`) refuses any VM instance outside this scope BEFORE any spawn.
//!
//! **Invariants honored (the Security obligations, design §8):**
//! - **S1 (transport authority).** The guest gets NO network device (no tap/bridge/IP) and NO drives —
//!   its ONLY peer is the host relay over vsock (host↔guest). It cannot dial an arbitrary CID; a
//!   sibling VM's CID is unreachable (guest↔guest vsock is not routed). A firecracker/guest death
//!   trips `FailNodeClosed` (the firecracker child is supervised by the root's existing wait loop).
//! - **S3 (guest-kernel verify-before-boot).** The guest kernel is hashed + matched against the
//!   operator-pinned `BOATRAMP_PRIVSEP_VM_KERNEL_SHA256` before boot (reusing the compute plane's
//!   [`boatramp_firecracker::HashOnlyVerifier`] shape); a mismatch REFUSES fail-closed.
//! - **S4 (in-guest wall).** The frontend-in-guest installs its OWN per-capability seccomp/Landlock
//!   profile fail-closed `Enforced` (the dynamic `ABI::from(kernel)` floor,
//!   `MIN_LANDLOCK_ABI = V5`) BEFORE serving a byte — exactly as a host-side instance does
//!   ([`crate::privsep::run_vm_guest`]), so the guest kernel MUST clear the Landlock floor. The
//!   in-guest profile is defense-in-depth UNDER the hypervisor wall (design §5).
//!
//! The non-PIE init shim (the standalone `boatramp-privsep-vm-shim` crate) is PID 1 (own-binary-as-init
//! needs a non-PIE PID 1; a static-PIE #GP-faults on an old minimal guest kernel — O3b): it mounts
//! `/proc,/sys,/dev` then `execve`s the static-PIE `boatramp __vm-guest` (keeping the payload's ASLR —
//! de-risk §1.4).

use std::path::PathBuf;

/// The fixed in-guest path the shim `execve`s and the guest config is packed at.
#[cfg(target_os = "linux")]
pub(crate) const GUEST_BOATRAMP_PATH: &str = "/boatramp";
/// The real [`crate::config::ServerConfig`] the frontend slice loads inside the guest.
#[cfg(target_os = "linux")]
pub(crate) const GUEST_CONFIG_PATH: &str = "/boatramp.cfg";
/// The non-secret per-guest launch descriptor (label + vsock port) the `__vm-guest` entry reads.
#[cfg(target_os = "linux")]
pub(crate) const GUEST_DESCRIPTOR_PATH: &str = "/privsep-vm-guest.json";
/// The default guest vsock port the frontend binds and the host relay dials (the operator/live gate
/// default; each VM has its own guest CID + UDS, so the port can be shared across VMs).
pub const DEFAULT_GUEST_VSOCK_PORT: u32 = 5201;

/// The non-secret per-guest launch descriptor packed into the initramfs (names/ports only — NEVER a
/// secret; the root is secret-blind and this crosses into the guest in the clear). The guest's real
/// capability slice comes from the packed [`ServerConfig`](crate::config::ServerConfig) at
/// `GUEST_CONFIG_PATH`, resolved by label — the SAME slice resolution a host-side instance uses.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct GuestDescriptor {
    /// The instance label whose slice this guest serves.
    pub label: String,
    /// The vsock port the frontend binds (CID_ANY) and the host relay dials.
    pub vsock_port: u32,
}

/// The operator-provisioned VM assets the scoped substrate needs. NON-SECRET paths + a content hash;
/// read from the environment captured at root start (before the env scrub), so a static-parser-frontend
/// VM composition is a pure config selection, not a new secret surface.
///
/// - `BOATRAMP_PRIVSEP_VM_FIRECRACKER` — the `firecracker` binary (the out-of-process VMM).
/// - `BOATRAMP_PRIVSEP_VM_KERNEL` — the uncompressed guest `vmlinux` (ring-0 code; S3-verified).
/// - `BOATRAMP_PRIVSEP_VM_KERNEL_SHA256` — the pinned guest-kernel content hash (S3). REQUIRED under
///   the strict posture; if absent the boot refuses fail-closed (a privsep guest kernel is
///   higher-trust than a tenant workload — design §2 / S3).
/// - `BOATRAMP_PRIVSEP_VM_SHIM` — the non-PIE init shim (`boatramp-privsep-vm-shim`), PID 1.
#[derive(Clone, Debug)]
pub struct VmAssets {
    pub firecracker_bin: PathBuf,
    pub guest_kernel: PathBuf,
    pub guest_kernel_sha256: Option<String>,
    pub shim_bin: PathBuf,
}

impl VmAssets {
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| -> Result<PathBuf, String> {
            std::env::var_os(k)
                .map(PathBuf::from)
                .ok_or_else(|| format!("the VM substrate needs {k} (an operator-provisioned path)"))
        };
        Ok(Self {
            firecracker_bin: get("BOATRAMP_PRIVSEP_VM_FIRECRACKER")?,
            guest_kernel: get("BOATRAMP_PRIVSEP_VM_KERNEL")?,
            guest_kernel_sha256: std::env::var("BOATRAMP_PRIVSEP_VM_KERNEL_SHA256")
                .ok()
                .filter(|s| !s.is_empty()),
            shim_bin: get("BOATRAMP_PRIVSEP_VM_SHIM")?,
        })
    }
}

// ============================================================================================
// Linux implementation — the real mechanism. Everything below needs AF_VSOCK + firecracker + KVM.
// ============================================================================================
#[cfg(target_os = "linux")]
mod imp {
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use sha2::{Digest, Sha256};

    use super::{GuestDescriptor, VmAssets};

    // ---- raw AF_VSOCK (same hand-rolled style as `privsep_link`'s raw SCM_RIGHTS; the bench's
    //      `vsock_raw.rs` is the lower-level reference). The GUEST half only: bind/listen/accept. The
    //      HOST half dials firecracker's UDS bridge (a plain UnixStream), never AF_VSOCK directly. ----
    const AF_VSOCK: i32 = 40;
    const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    fn last_err(what: &str) -> io::Error {
        io::Error::other(format!("{what}: {}", io::Error::last_os_error()))
    }

    /// Bind + listen AF_VSOCK on `port` (CID_ANY), returning the listening fd. Called by the guest
    /// BEFORE it installs its Landlock/seccomp profile (the frontend profile denies `bind` — the host
    /// model has the root bind; inside the guest there is no root, so the guest binds pre-wall and only
    /// `accept`s after — exactly the "root binds, frontend accepts" split, self-contained).
    pub(crate) fn vsock_bind_listen(port: u32) -> io::Result<OwnedFd> {
        // SAFETY: a plain socket(2)/bind(2)/listen(2) sequence over a fully-initialized sockaddr_vm.
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(last_err("socket(AF_VSOCK)"));
        }
        // SAFETY: `fd` is a fresh owned socket fd.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let addr = SockaddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };
        // SAFETY: `addr` is valid + correctly sized (matches sizeof(sockaddr)).
        let rc = unsafe {
            libc::bind(
                owned.as_raw_fd(),
                (&addr as *const SockaddrVm).cast(),
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(last_err("bind(AF_VSOCK)"));
        }
        // SAFETY: `fd` is a live socket.
        if unsafe { libc::listen(owned.as_raw_fd(), 64) } != 0 {
            return Err(last_err("listen(AF_VSOCK)"));
        }
        Ok(owned)
    }

    /// Block for one inbound vsock connection (one host-relayed client), returning the accepted fd.
    fn vsock_accept(listener: RawFd) -> io::Result<OwnedFd> {
        // SAFETY: null addr/addrlen is a valid accept(2) when the peer address is not wanted; `listener`
        // is a live listening socket.
        let rc = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
        if rc < 0 {
            return Err(last_err("accept(AF_VSOCK)"));
        }
        // SAFETY: `rc` is a fresh accepted fd we now own.
        Ok(unsafe { OwnedFd::from_raw_fd(rc) })
    }

    // ---- minimal newc cpio writer (in-process — the secret-blind root execs nothing but its own
    //      binary, so the initramfs is assembled in-memory, never by shelling out to `cpio`). The
    //      guest kernel loads an UNCOMPRESSED newc cpio as its initramfs directly. ----
    struct Cpio {
        buf: Vec<u8>,
        ino: u32,
    }

    impl Cpio {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                ino: 1,
            }
        }

        /// Append one entry. `mode` is the full st_mode (type bits included); `rdev` is `(major, minor)`
        /// for a device node (else `(0, 0)`).
        fn entry(&mut self, name: &str, mode: u32, nlink: u32, rdev: (u32, u32), data: &[u8]) {
            let ino = self.ino;
            self.ino += 1;
            let namesize = name.len() + 1; // includes the trailing NUL
            // newc header: "070701" (magic) + 13 × 8-hex fields, each written explicitly:
            // ino, mode, uid=0, gid=0, nlink, mtime=0, filesize, devmajor=0, devminor=0,
            // rdevmajor, rdevminor, namesize, check=0. Total = 6 + 13*8 = 110 bytes.
            let header = format!(
                "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{size:08x}{devmaj:08x}{devmin:08x}{rmaj:08x}{rmin:08x}{namesize:08x}{check:08x}",
                uid = 0u32,
                gid = 0u32,
                mtime = 0u32,
                size = data.len() as u32,
                devmaj = 0u32,
                devmin = 0u32,
                rmaj = rdev.0,
                rmin = rdev.1,
                check = 0u32,
            );
            debug_assert_eq!(header.len(), 110, "newc header is 110 bytes");
            self.buf.extend_from_slice(header.as_bytes());
            self.buf.extend_from_slice(name.as_bytes());
            self.buf.push(0);
            // Pad the (header+name) to a 4-byte boundary so file data starts aligned.
            while !self.buf.len().is_multiple_of(4) {
                self.buf.push(0);
            }
            self.buf.extend_from_slice(data);
            while !self.buf.len().is_multiple_of(4) {
                self.buf.push(0);
            }
        }

        fn dir(&mut self, name: &str) {
            self.entry(name, 0o040_755, 2, (0, 0), &[]);
        }
        fn chardev(&mut self, name: &str, major: u32, minor: u32) {
            self.entry(name, 0o020_666, 1, (major, minor), &[]);
        }
        fn file(&mut self, name: &str, mode: u32, data: &[u8]) {
            self.entry(name, 0o100_000 | mode, 1, (0, 0), data);
        }

        fn finish(mut self) -> Vec<u8> {
            // The newc end-of-archive marker.
            self.entry("TRAILER!!!", 0, 1, (0, 0), &[]);
            self.buf
        }
    }

    /// Assemble the guest initramfs (uncompressed newc cpio) IN MEMORY: the non-PIE shim as `/init`
    /// (PID 1), the real static-PIE `boatramp` binary, the real `ServerConfig`, and the non-secret
    /// per-guest descriptor. No distro userland, no block device — the smallest guest TCB (design §2
    /// Option A). Returns the path written under `work_dir`.
    fn assemble_initramfs(
        work_dir: &Path,
        shim_bin: &Path,
        boatramp_bin: &Path,
        server_config: &[u8],
        descriptor: &GuestDescriptor,
    ) -> io::Result<PathBuf> {
        let read = |p: &Path| -> io::Result<Vec<u8>> {
            std::fs::read(p).map_err(|e| io::Error::other(format!("reading {}: {e}", p.display())))
        };
        let shim = read(shim_bin)?;
        let boatramp = read(boatramp_bin)?;
        let descriptor_json = serde_json::to_vec(descriptor)
            .map_err(|e| io::Error::other(format!("serializing the guest descriptor: {e}")))?;

        let mut cpio = Cpio::new();
        cpio.dir("proc");
        cpio.dir("sys");
        cpio.dir("dev");
        cpio.chardev("dev/console", 5, 1);
        cpio.chardev("dev/null", 1, 3);
        cpio.file("init", 0o755, &shim); // the non-PIE shim is PID 1 (rdinit=/init)
        cpio.file(
            super::GUEST_BOATRAMP_PATH.trim_start_matches('/'),
            0o755,
            &boatramp,
        );
        cpio.file(
            super::GUEST_CONFIG_PATH.trim_start_matches('/'),
            0o644,
            server_config,
        );
        cpio.file(
            super::GUEST_DESCRIPTOR_PATH.trim_start_matches('/'),
            0o644,
            &descriptor_json,
        );
        let image = cpio.finish();

        let out = work_dir.join("initramfs.cpio");
        std::fs::write(&out, &image)
            .map_err(|e| io::Error::other(format!("writing the initramfs: {e}")))?;
        Ok(out)
    }

    /// S3: verify the guest kernel (ring-0 code) against the operator-pinned content hash BEFORE boot.
    /// Reuses the compute plane's content-hash gate shape; a mismatch — or, under the strict posture, a
    /// MISSING pin — refuses fail-closed (a privsep guest kernel is higher-trust than a tenant workload).
    fn verify_guest_kernel(kernel: &Path, pinned_sha256: Option<&str>) -> io::Result<()> {
        let bytes = std::fs::read(kernel)
            .map_err(|e| io::Error::other(format!("reading the guest kernel: {e}")))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        match pinned_sha256 {
            Some(expected) if expected.eq_ignore_ascii_case(&actual) => Ok(()),
            Some(expected) => Err(io::Error::other(format!(
                "guest-kernel S3 verify FAILED: {} hashes {actual}, operator pinned {expected} — \
                 refusing to boot an unverified ring-0 kernel",
                kernel.display()
            ))),
            None => Err(io::Error::other(format!(
                "guest-kernel S3 verify REFUSED: no BOATRAMP_PRIVSEP_VM_KERNEL_SHA256 pin for {} — a \
                 privsep guest kernel is ring-0 code under a higher-trust instance and MUST be pinned \
                 (design §2 / S3)",
                kernel.display()
            ))),
        }
    }

    /// Boot the frontend microVM: kernel + the in-memory initramfs + a vsock device, NO drives, NO net
    /// (S1 — the guest's only peer is the host relay). Out-of-process firecracker child (`--no-api`,
    /// the whole machine is static config). Returns the child + the host-side vsock UDS path.
    struct BootedVm {
        child: Child,
        uds_path: PathBuf,
    }

    /// The DEDICATED, non-world-writable runtime root under which each VM's single-socket vsock-UDS
    /// directory is created (0700) — replacing world-writable `std::env::temp_dir()` (`/tmp`, mode
    /// 1777), whose shared, world-writable namespace exposed a TOCTOU/connect surface around
    /// firecracker's socket. Prefers an explicit `$RUNTIME_DIRECTORY` (systemd `RuntimeDirectory=`,
    /// already a 0700 per-service dir under `/run`), else `/run/boatramp-vm` (created 0700 under `/run`
    /// — a root-owned 0755 tmpfs, NOT world-writable). The relay's minimal mount-ns root binds exactly
    /// this per-VM dir, so a `/run`-based location stays reachable to the relay while every OTHER host
    /// UDS path is removed. Fail-closed: if a non-world-writable 0700 root cannot be established, returns
    /// `Err` — NEVER a silent fall-back to `/tmp`.
    fn vm_vsock_runtime_root() -> io::Result<PathBuf> {
        let base = match std::env::var_os("RUNTIME_DIRECTORY") {
            Some(d) if !d.is_empty() => {
                // systemd may pass a colon-separated list; the first entry is this service's own dir.
                let first = d.to_string_lossy();
                let first = first.split(':').next().unwrap_or_default();
                if first.is_empty() {
                    PathBuf::from("/run/boatramp-vm")
                } else {
                    PathBuf::from(first).join("vm-relay")
                }
            }
            _ => PathBuf::from("/run/boatramp-vm"),
        };
        std::fs::create_dir_all(&base).map_err(|e| {
            io::Error::other(format!(
                "creating the VM vsock runtime root {}: {e}",
                base.display()
            ))
        })?;
        // Lock it to 0700 and VERIFY it is not world-writable (fail-closed — a world-writable runtime
        // root would reopen the very TOCTOU/connect surface this moves away from `/tmp` to close).
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            io::Error::other(format!(
                "locking the VM vsock runtime root {} to 0700: {e}",
                base.display()
            ))
        })?;
        let mode = std::fs::metadata(&base)?.permissions().mode();
        if mode & 0o002 != 0 {
            return Err(io::Error::other(format!(
                "the VM vsock runtime root {} is world-writable (mode {:o}) — refusing fail-closed",
                base.display(),
                mode & 0o777
            )));
        }
        Ok(base)
    }

    /// The guest kernel cmdline (Finding 2 — acpi=off Security review). `acpi=off` + `pci=off` are
    /// LOAD-BEARING: on the firecracker *binary* backend (kernel >= 6.12) ACPICA rejects the
    /// reduced-hardware DSDT and disables ACPI mid-boot, leaving NO device-IRQ routing unless the guest
    /// falls back to the legacy PIC — which `acpi=off` forces (paired with `X86_MPPARSE` OFF + a KVM
    /// in-kernel irqchip). Pulled into a named const so a pure CI unit test can assert the two args are
    /// present (a future edit that drops `acpi=off` would silently break device IRQs ⇒ no vsock); the
    /// guest-side companion is the kernel-config guard in `crate::privsep::run_vm_guest`.
    const GUEST_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off acpi=off ro rdinit=/init";

    fn boot_firecracker(
        assets: &VmAssets,
        work_dir: &Path,
        initramfs: &Path,
        guest_cid: u32,
    ) -> io::Result<BootedVm> {
        verify_guest_kernel(&assets.guest_kernel, assets.guest_kernel_sha256.as_deref())?;
        // The vsock UDS path must fit `sockaddr_un.sun_path` (SUN_LEN ≈ 108 bytes) — a deep work_dir
        // would overflow it — so the UDS lives at a SHORT unique path under a DEDICATED, NON-world-
        // writable runtime root ([`vm_vsock_runtime_root`] — NOT world-writable `/tmp`, which exposed a
        // TOCTOU/connect surface around firecracker's socket), while the (long-path-tolerant) initramfs
        // / config / console stay in `work_dir`. The per-VM dir is mode 0700 and holds ONLY this socket,
        // so the relay's Landlock FS view can grant that one directory (Landlock cannot O_PATH-open a
        // socket inode on static-musl — `boatramp_server::sandbox::relay_supervisor_policy`) while
        // staying tight. Fail-closed: if a non-world-writable runtime root can't be set up, refuse.
        let runtime_root = vm_vsock_runtime_root()?;
        let uds_dir = runtime_root.join(format!("brvsk-{}-{}", guest_cid, std::process::id()));
        let _ = std::fs::remove_dir_all(&uds_dir); // a stale dir from a prior run would block the bind
        std::fs::create_dir_all(&uds_dir)
            .map_err(|e| io::Error::other(format!("creating the vsock UDS dir: {e}")))?;
        // 0700 (owner-only): the single-socket dir is reachable ONLY by the firecracker-booting node and
        // the relay (same uid 0) — remove the world-traversable/connect surface of the old `/tmp` dir.
        std::fs::set_permissions(&uds_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| io::Error::other(format!("locking the vsock UDS dir to 0700: {e}")))?;
        let uds_path = uds_dir.join("vsock.sock");
        let config_path = work_dir.join("firecracker.json");
        // Raw firecracker machine config: kernel + initrd + vsock, `drives: []`, no
        // `network-interfaces` (the production `FcMachine` has no initrd/vsock fields; the bench
        // `vsock.rs` proves this exact kernel+initramfs+vsock shape).
        //
        // `acpi=off` is LOAD-BEARING (Phase-3c). The firecracker *binary* backend presents its
        // virtio-mmio devices' interrupt topology over ACPI (its config ships `X86_MPPARSE` off,
        // `ACPI=y` — the embedded rust-vmm VMM uses the MPTABLE/cmdline path instead). On a guest
        // kernel >= 6.10 — which the privsep in-guest Landlock-V5 wall REQUIRES
        // (`MIN_LANDLOCK_ABI`, kernel >= 6.10) — ACPICA 20240827 (kernels >= 6.12) REJECTS
        // firecracker 1.13.x's reduced-hardware DSDT during operation-region init
        // (`ACPI Error: AE_BAD_PARAMETER, During Region initialization`), which makes the kernel
        // DISABLE ACPI entirely. With ACPI disabled mid-boot the IOAPIC is known (from the MADT)
        // but NO device-IRQ routing is set up (`preallocated irqs: 0`, no legacy i8259), so every
        // device interrupt is dead: the 8250 serial's IRQ-driven TX returns EIO (userspace console
        // writes fail — PID 1's own `println!` then panics the guest), and the virtio-vsock driver's
        // `request_irq` for its MMIO IRQ returns -EINVAL (the guest-driver probe fails `-22`), so the
        // vsock transport never comes up and the host byte-relay can never reach the frontend.
        // `acpi=off` sidesteps the broken DSDT: with `X86_MPPARSE` off too, the guest falls back to
        // the legacy PC model (`APIC: Keep in PIC mode(8259)`, `preallocated irqs: 16`) that
        // firecracker's KVM in-kernel irqchip emulates and routes GSI 0-15 to — so the serial (IRQ 4)
        // and the vsock device (IRQ 5) both get working IRQ lines. The guest needs
        // `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y` so the device is discovered off the
        // `virtio_mmio.device=` cmdline firecracker appends (ACPI enumeration is now off); the shipped
        // `boatramp-vmlinux` already enables it (for the embedded-VMM path), so this is a pure
        // boot-arg change. Live-proven on lighthouse (kernel 6.12.67, Landlock V5): clean boot, vsock
        // probe succeeds, host<->guest relay serves a 200 (Phase-3c serve gate). A privsep guest runs
        // no ACPI-dependent devices (no PCI, no power-management, single vcpu), so dropping ACPI is
        // safe. Must stay paired with `X86_MPPARSE` OFF: were it ON, `acpi=off` would make the kernel
        // hunt for an MPTABLE the firecracker binary does not emit.
        let config = format!(
            r#"{{
  "boot-source": {{
    "kernel_image_path": {kernel},
    "initrd_path": {initrd},
    "boot_args": "{boot_args}"
  }},
  "drives": [],
  "machine-config": {{ "vcpu_count": 1, "mem_size_mib": 1024 }},
  "vsock": {{ "guest_cid": {cid}, "uds_path": {uds} }}
}}"#,
            kernel = json_str(&assets.guest_kernel.to_string_lossy()),
            initrd = json_str(&initramfs.to_string_lossy()),
            boot_args = GUEST_BOOT_ARGS,
            cid = guest_cid,
            uds = json_str(&uds_path.to_string_lossy()),
        );
        std::fs::write(&config_path, config)
            .map_err(|e| io::Error::other(format!("writing the firecracker config: {e}")))?;
        // Capture the guest serial console (`console=ttyS0`) to a file — both so it never blocks
        // firecracker (an undrained pipe would), and so the live gate can read the guest's markers
        // (SHIM-ALIVE / PRIVSEP VM GUEST SERVING).
        let console = work_dir.join("console.log");
        let log = std::fs::File::create(&console)
            .map_err(|e| io::Error::other(format!("creating the guest console log: {e}")))?;
        let log2 = log
            .try_clone()
            .map_err(|e| io::Error::other(format!("cloning the console log handle: {e}")))?;
        let child = Command::new(&assets.firecracker_bin)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| {
                io::Error::other(format!(
                    "spawning firecracker ({}): {e}",
                    assets.firecracker_bin.display()
                ))
            })?;
        // The vsock UDS appears once firecracker's vsock DEVICE is up; a bounded wait, else firecracker
        // itself never came up. NOTE (acpi=off Security review, Finding 1): this is a DEVICE-UP
        // PRECONDITION so the relay has a socket to dial — NOT a guest-health gate. It returns as soon as
        // the UDS file exists, which is independent of whether the GUEST bound its vsock listener and
        // actually serves. The POSITIVE readiness assertion (the guest served a 200) is
        // [`relay_readiness_probe`], run by the separate relay process behind its profile; a
        // degraded-but-booted guest trips `FailNodeClosed` there, never here.
        let deadline = Instant::now() + Duration::from_secs(15);
        while !uds_path.exists() {
            if Instant::now() > deadline {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(
                    "firecracker's vsock device UDS never appeared within 15s (firecracker did not \
                     bring up the vsock device — the guest could not have booted)",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(BootedVm { child, uds_path })
    }

    /// Minimal JSON string escaper for the two paths we interpolate (no control chars expected in a
    /// filesystem path, but quotes/backslashes are escaped so a crafted work-dir can't break the JSON).
    fn json_str(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// Dial firecracker's host-side vsock bridge (docs/vsock.md): connect the device UDS, send
    /// `CONNECT <port>\n`, read `OK <port>\n`; the UnixStream then mirrors the guest's AF_VSOCK
    /// connection on that port. This is the ONLY path into the guest (S1).
    fn dial_guest(uds_path: &Path, guest_port: u32) -> io::Result<UnixStream> {
        let mut stream = UnixStream::connect(uds_path)?;
        stream.write_all(format!("CONNECT {guest_port}\n").as_bytes())?;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() > 256 {
                return Err(io::Error::other("vsock CONNECT handshake line too long"));
            }
        }
        if !line.starts_with(b"OK") {
            return Err(io::Error::other(format!(
                "firecracker vsock CONNECT refused: {}",
                String::from_utf8_lossy(&line)
            )));
        }
        Ok(stream)
    }

    /// The MAX concurrent relayed client connections the separate `__vm-relay` process will service
    /// at once (F2 — availability bound). `run_relay` spawned an UNBOUNDED thread-per-connection, so
    /// a client-connection flood could exhaust host threads/memory (a DoS). This fixes the inflight
    /// budget: at the cap, a new client is SHED (closed) rather than admitted.
    ///
    /// Value rationale: it matches the node's existing default per-scope connection ceiling
    /// (`boatramp_server`'s `DEFAULT_STREAM_CONNECTIONS` = 256) — an already-blessed order of
    /// magnitude for concurrent connections to ONE serving scope — and so bounds host growth to a
    /// fixed budget (≤ 256 relayed connections, each holding at most the 2 `splice_bidirectional`
    /// threads) instead of unbounded. It sits comfortably ABOVE the guest's own backpressure points
    /// (the vsock `listen(64)` backlog + the guest's 64-deep accept channel in
    /// [`guest_accept_serve_loop`]), so a healthy single-frontend guest is never artificially
    /// throttled by the relay while a flood is still shed. A scoped static-parser frontend is a
    /// single VM; this is a per-relay (per-frontend) budget.
    pub(crate) const MAX_INFLIGHT_RELAY_CONNS: usize = 256;

    /// RAII reservation for ONE inflight relayed connection: decrements the shared counter on drop
    /// (when the per-connection splice thread ends), freeing the slot for a new client.
    struct InflightGuard(Arc<AtomicUsize>);

    impl Drop for InflightGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// WS-C admission posture (try-acquire → SHED, never block): atomically reserve one of `max`
    /// inflight slots, returning a guard that frees it on drop, or `None` when the relay is already
    /// at its budget (the caller then sheds the client by closing it, rather than spawning an
    /// unbounded thread). Lock-free `fetch_add` + bounds-check, backing the over-count out if we
    /// exceeded — the SAME `fetch_add`/`fetch_sub` inflight shape the HTTP serve path uses, and the
    /// SAME try-acquire→shed posture the stream serve path uses (a blocking `acquire` would stall
    /// the accept loop and the kernel listener backlog behind it).
    fn reserve_inflight_slot(counter: &Arc<AtomicUsize>, max: usize) -> Option<InflightGuard> {
        let prev = counter.fetch_add(1, Ordering::SeqCst);
        if prev >= max {
            counter.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(InflightGuard(counter.clone()))
    }

    /// The MINIMUM interval between two emitted shed-path warnings (LOW-2). At the inflight cap the
    /// relay sheds clients; warning on EVERY shed amplifies log/CPU/disk pressure under the very flood
    /// F2 defends against. One warning per interval — each carrying a running summary — is enough to
    /// surface the condition without becoming a second DoS vector.
    const SHED_WARN_INTERVAL: Duration = Duration::from_secs(5);

    /// Rate-limiter / sampler for the F2 shed-path warning (LOW-2). Emits at most ONE warning per
    /// [`SHED_WARN_INTERVAL`] (plus always the first shed), each summarizing the sheds since the last
    /// one — so a flood produces a bounded trickle of warnings, never one-per-shed, yet no shed is
    /// silently dropped from the count. O(1): three fixed scalars, NO unbounded state. The relay's
    /// accept loop is single-threaded, so this needs no synchronization.
    struct ShedWarnSampler {
        /// Total sheds since the relay started (monotonic — the cumulative figure in each summary).
        total: u64,
        /// Sheds since the last EMITTED warning (reset to 0 whenever one is emitted).
        since_last_warn: u64,
        /// When the last warning was emitted; `None` ⇒ none yet (so the first shed always warns).
        last_warn: Option<Instant>,
    }

    impl ShedWarnSampler {
        fn new() -> Self {
            Self {
                total: 0,
                since_last_warn: 0,
                last_warn: None,
            }
        }

        /// Record one shed at `now`. Returns `Some((total, since_last_warn))` when a warning is DUE
        /// (the first shed, then at most once per [`SHED_WARN_INTERVAL`]), else `None`. The returned
        /// `since_last_warn` counts the sheds this warning summarizes (this one included); it resets
        /// after the warning is emitted so the next summary covers only the sheds that follow.
        fn record(&mut self, now: Instant) -> Option<(u64, u64)> {
            self.total += 1;
            self.since_last_warn += 1;
            let due = match self.last_warn {
                None => true,
                Some(t) => now.duration_since(t) >= SHED_WARN_INTERVAL,
            };
            if due {
                let summary = (self.total, self.since_last_warn);
                self.last_warn = Some(now);
                self.since_last_warn = 0;
                Some(summary)
            } else {
                None
            }
        }
    }

    /// The host-side **client-byte relay** (Model A, design §1c): the root already bound the privileged
    /// public TCP `listener`; here it accepts each client and relays the client's bytes to the
    /// frontend-in-guest over a fresh vsock connection, splicing bytes both ways. The relay carries
    /// ONLY untrusted client bytes — NEVER key material (the scoped frontend holds no key; the HARD
    /// EXCLUSION). Runs for the node's life; a guest death EOFs the dials (the firecracker child,
    /// supervised separately, is the authoritative `FailNodeClosed` signal).
    ///
    /// Two callers, ONE byte-pipe (reuse, not parallelize): the in-root relay THREAD spawned by
    /// [`launch_frontend_vm`] (the live-gate path), and the SEPARATE least-authority relay PROCESS
    /// ([`crate::privsep::run_vm_relay`], the owner's S1 placement — this runs it on the relay
    /// process's main thread, behind its own Enforced least-authority profile). It returns when
    /// `accept` ends (the pre-bound listener closed); the separate process reads that return as
    /// `FailNodeClosed`.
    pub(crate) fn run_relay(
        label: String,
        listener: std::net::TcpListener,
        uds_path: PathBuf,
        guest_port: u32,
    ) {
        tracing::info!(
            instance = %label,
            max_inflight = MAX_INFLIGHT_RELAY_CONNS,
            "[privsep] VM relay: accepting client TCP; relaying bytes to the frontend-in-guest over \
             vsock (client bytes only — no key material crosses the root; S1); inflight connections \
             are bounded (F2)"
        );
        let inflight = Arc::new(AtomicUsize::new(0));
        // LOW-2: rate-limit the shed-path warning so a connection flood can't turn the defence (F2)
        // into a log/CPU/disk-amplification DoS of its own.
        let mut shed_warn = ShedWarnSampler::new();
        loop {
            let (client, _peer) = match listener.accept() {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(instance = %label, error = %e, "[privsep] VM relay: accept ended");
                    return;
                }
            };
            // F2 — WS-C admission: reserve an inflight slot before servicing. At the cap, SHED this
            // client (drop ⇒ close) rather than spawn an unbounded thread; the accept loop keeps
            // running so the listener backlog is still drained. The permit is MOVED into the worker
            // thread and held for the connection's whole life (freed when the splice ends).
            let Some(permit) = reserve_inflight_slot(&inflight, MAX_INFLIGHT_RELAY_CONNS) else {
                // LOW-2: emit at most one warning per SHED_WARN_INTERVAL, each with a running summary
                // (the first shed always warns); the drop/close itself is unconditional.
                if let Some((shed_total, shed_since_last_warn)) = shed_warn.record(Instant::now()) {
                    tracing::warn!(
                        instance = %label,
                        max_inflight = MAX_INFLIGHT_RELAY_CONNS,
                        shed_total,
                        shed_since_last_warn,
                        interval_secs = SHED_WARN_INTERVAL.as_secs(),
                        "[privsep] VM relay: at the inflight-connection cap — shedding clients \
                         (closing them); availability bound (F2). Rate-limited: shed_since_last_warn \
                         clients were shed since the previous warning."
                    );
                }
                drop(client);
                continue;
            };
            let uds = uds_path.clone();
            let label2 = label.clone();
            std::thread::spawn(move || {
                let _permit = permit; // held for the whole connection; frees the slot on drop
                let guest = match dial_guest(&uds, guest_port) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(instance = %label2, error = %e, "[privsep] VM relay: dial");
                        return;
                    }
                };
                splice_bidirectional(client, guest);
            });
        }
    }

    /// Copy bytes both ways between the client TCP stream and the guest vsock stream until either side
    /// closes, then shut the other down. A transparent byte pipe — the parse happens in the guest.
    fn splice_bidirectional(client: std::net::TcpStream, guest: UnixStream) {
        let (Ok(mut c_r), Ok(mut g_w)) = (client.try_clone(), guest.try_clone()) else {
            return;
        };
        let (mut g_r, mut c_w) = (guest, client);
        let up = std::thread::spawn(move || {
            let _ = io::copy(&mut c_r, &mut g_w);
            let _ = g_w.shutdown(std::net::Shutdown::Write);
        });
        let _ = io::copy(&mut g_r, &mut c_w);
        let _ = c_w.shutdown(std::net::Shutdown::Write);
        let _ = up.join();
    }

    /// Everything the root hands over to the supervise loop for a launched VM frontend: the firecracker
    /// child (supervised like any instance — a guest death trips `FailNodeClosed`) and the relay
    /// handle (detached for the node's life).
    pub struct VmLaunch {
        pub child: Child,
        pub _relay: std::thread::JoinHandle<()>,
    }

    /// What [`boot_frontend_vm`] hands the OPERATOR supervise dispatch: the firecracker child (a guest
    /// death ⇒ `FailNodeClosed`), the host-side vsock UDS the SEPARATE `__vm-relay` process dials, and
    /// the guest serial console path (for the `FailNodeClosed` diagnostic). NO in-root relay thread —
    /// the operator path runs the byte-relay in a dedicated least-authority process
    /// ([`crate::privsep::run_vm_relay`]), NEVER inside the secret-blind root (S1).
    pub struct BootedFrontendVm {
        pub child: Child,
        pub uds_path: PathBuf,
        pub console: PathBuf,
    }

    /// Boot ONE scoped static-parser-frontend VM for the OPERATOR supervise dispatch: assemble the
    /// initramfs (shim + the real static-PIE binary + the real config + the non-secret descriptor),
    /// S3-verify + boot the microVM — and STOP. It does NOT bind/accept/relay: the operator path binds
    /// the listener in the root, boots here, then `fork`+`exec`s a SEPARATE least-authority `__vm-relay`
    /// process to do the host↔guest byte-relay (S1 — the relay, NOT the secret-blind root, is the
    /// host-side vsock endpoint). The caller supervises `BootedFrontendVm.child` (the firecracker child)
    /// AND the relay child; either's death ⇒ `FailNodeClosed`.
    pub fn boot_frontend_vm(
        current_exe: &Path,
        label: &str,
        config_path: &Path,
        assets: &VmAssets,
        work_dir: &Path,
        guest_cid: u32,
        guest_port: u32,
    ) -> Result<BootedFrontendVm, String> {
        std::fs::create_dir_all(work_dir)
            .map_err(|e| format!("creating the VM work dir {}: {e}", work_dir.display()))?;
        let server_config = std::fs::read(config_path)
            .map_err(|e| format!("reading the config for the guest: {e}"))?;
        let descriptor = GuestDescriptor {
            label: label.to_string(),
            vsock_port: guest_port,
        };
        let initramfs = assemble_initramfs(
            work_dir,
            &assets.shim_bin,
            current_exe,
            &server_config,
            &descriptor,
        )
        .map_err(|e| format!("assembling the guest initramfs: {e}"))?;
        let booted = boot_firecracker(assets, work_dir, &initramfs, guest_cid)
            .map_err(|e| format!("booting the frontend microVM: {e}"))?;
        tracing::info!(
            instance = %label,
            pid = booted.child.id(),
            guest_cid,
            guest_port,
            "[privsep] root: frontend microVM booted (own-binary-as-init via the non-PIE shim; vsock \
             only, no net, no drives — the hypervisor wall is the PRIMARY containment). The host-side \
             vsock endpoint is the SEPARATE __vm-relay process, not the root (S1)"
        );
        Ok(BootedFrontendVm {
            child: booted.child,
            uds_path: booted.uds_path,
            console: work_dir.join("console.log"),
        })
    }

    /// Launch ONE scoped static-parser-frontend VM with the in-root relay THREAD (the live-gate path
    /// `tests/privsep_vm_live.rs` exercises): boot via [`boot_frontend_vm`], then spawn the host
    /// client-byte relay over the ALREADY-bound TCP `listener` on a thread. The OPERATOR dispatch does
    /// NOT use this (it runs the relay in a separate least-authority PROCESS — S1); this stays for the
    /// mechanism's own serve gate, which proves the vsock transport + guest serve end-to-end.
    #[allow(clippy::too_many_arguments)]
    pub fn launch_frontend_vm(
        current_exe: &Path,
        label: &str,
        config_path: &Path,
        listener: std::net::TcpListener,
        assets: &VmAssets,
        work_dir: &Path,
        guest_cid: u32,
        guest_port: u32,
    ) -> Result<VmLaunch, String> {
        let booted = boot_frontend_vm(
            current_exe,
            label,
            config_path,
            assets,
            work_dir,
            guest_cid,
            guest_port,
        )?;
        let uds = booted.uds_path.clone();
        let relay_label = label.to_string();
        let relay = std::thread::Builder::new()
            .name(format!("privsep-vm-relay-{label}"))
            .spawn(move || run_relay(relay_label, listener, uds, guest_port))
            .map_err(|e| format!("spawning the VM relay thread: {e}"))?;
        Ok(VmLaunch {
            child: booted.child,
            _relay: relay,
        })
    }

    /// The POSITIVE readiness handshake the separate `__vm-relay` process performs AFTER installing its
    /// Enforced least-authority profile and BEFORE entering its accept loop (acpi=off Security review,
    /// Finding 1). It replaces the EMERGENT-only "guest healthy?" signal: [`boot_firecracker`]'s
    /// host-side UDS wait returns as soon as firecracker's vsock DEVICE is up — independent of whether
    /// the GUEST ever bound its listener and served — so a degraded-but-booted guest would have been
    /// relayed to silently. This asserts the guest actually SERVES: within `deadline`, dial the
    /// firecracker vsock UDS (retried — the guest may still be booting), do a trivial HTTP/1.1
    /// request/response round-trip, and require a `200`. On success the relay is cleared to serve; if
    /// the deadline passes with no served `200`, it returns `Err` — the relay process then exits and the
    /// root's supervise loop trips `FailNodeClosed` (a bounded, POSITIVE gate, not an open-ended wait).
    ///
    /// It runs behind the relay's profile, so it uses ONLY allowed verbs (`socket`/`connect`/`read`/
    /// `write`/`shutdown` + the thread `clone`/`futex`) — the SAME socket surface the accept loop uses.
    /// The probe connection is just another client from the guest's view (`Connection: close`, so the
    /// guest closes after responding and the probe reads to EOF).
    ///
    /// **Blocking dial + watchdog deadline (NOT per-attempt `SO_RCVTIMEO`).** It reuses the EXACT
    /// blocking handshake shape the proven in-root relay's [`dial_guest`] runs — a plain blocking
    /// read of firecracker's `OK` reply — because firecracker's host-vsock CONNECT handshake does NOT
    /// tolerate a short `SO_RCVTIMEO` across reconnects: a read-timeout that fires mid-handshake leaves
    /// firecracker's host-side muxer wedged, so every subsequent reconnect then times out too (observed
    /// live: a 3s `SO_RCVTIMEO` made EVERY attempt time out even with the guest serving, while the
    /// timeout-free `dial_guest` on the same socket gets `OK` immediately). A dedicated worker thread
    /// retries the blocking dial (firecracker refuses — EOF — until the guest binds its vsock listener),
    /// while THIS thread bounds the whole wait with `deadline` via `recv_timeout`; a wedged blocking
    /// dial is torn down when the relay exits (`FailNodeClosed`). Bounded + POSITIVE.
    pub(crate) fn relay_readiness_probe(
        uds_path: &Path,
        guest_port: u32,
        deadline: Instant,
    ) -> Result<(), String> {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel::<Result<u32, String>>();
        let uds = uds_path.to_path_buf();
        std::thread::Builder::new()
            .name("vm-relay-readiness".to_string())
            .spawn(move || {
                let mut attempt = 0u32;
                loop {
                    attempt += 1;
                    match probe_once_blocking(&uds, guest_port) {
                        Ok(()) => {
                            let _ = tx.send(Ok(attempt));
                            return;
                        }
                        Err(e) => {
                            // Report progress (the guest is likely still booting → firecracker EOFs the
                            // CONNECT); back off briefly and retry until we serve a 200 or the relay dies.
                            if tx.send(Err(e)).is_err() {
                                return; // the main thread gave up (deadline) — stop
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                }
            })
            .map_err(|e| format!("spawning the readiness-probe thread: {e}"))?;

        let mut last_err = String::from("no attempt completed");
        let mut attempts: u32 = 0;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "the frontend-in-guest did not serve a 200 over vsock within the readiness \
                     deadline ({attempts} attempts; last error: {last_err}) — FailNodeClosed \
                     (refusing to relay clients to a guest that never positively served; the UDS \
                     merely existing is NOT proof the guest is healthy)"
                ));
            }
            match rx.recv_timeout(deadline - now) {
                Ok(Ok(attempt)) => {
                    tracing::info!(
                        attempts = attempt,
                        "[privsep] __vm-relay: readiness handshake OK — the frontend-in-guest served \
                         a 200 over vsock; clearing the relay to accept clients (Finding 1 positive \
                         gate)"
                    );
                    return Ok(());
                }
                Ok(Err(e)) => {
                    attempts += 1;
                    last_err = e;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "the frontend-in-guest did not serve a 200 over vsock within the readiness \
                         deadline ({attempts} attempts; last error: {last_err}) — FailNodeClosed"
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(
                        "the readiness-probe thread ended unexpectedly — FailNodeClosed"
                            .to_string(),
                    );
                }
            }
        }
    }

    /// One readiness attempt, BLOCKING (no `SO_RCVTIMEO` — see [`relay_readiness_probe`]): dial
    /// firecracker's host-side vsock bridge exactly as [`dial_guest`] does, then do a minimal HTTP/1.1
    /// `GET /` and require a `200` status line. firecracker refuses the CONNECT (EOF on the reply read)
    /// until the guest is listening, which surfaces as `Err` and is retried.
    fn probe_once_blocking(uds_path: &Path, guest_port: u32) -> Result<(), String> {
        let mut stream =
            UnixStream::connect(uds_path).map_err(|e| format!("connect vsock UDS: {e}"))?;
        // Firecracker host-initiated vsock: CONNECT <port>\n → OK <port>\n once the guest is listening.
        stream
            .write_all(format!("CONNECT {guest_port}\n").as_bytes())
            .map_err(|e| format!("write CONNECT: {e}"))?;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream
                .read_exact(&mut byte)
                .map_err(|e| format!("read CONNECT reply: {e}"))?;
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
            if line.len() > 256 {
                return Err("vsock CONNECT reply line too long".to_string());
            }
        }
        if !line.starts_with(b"OK") {
            return Err(format!(
                "firecracker vsock CONNECT refused (guest not listening yet?): {}",
                String::from_utf8_lossy(&line)
            ));
        }
        // The guest's vsock listener is up; now prove it SERVES (not just listens).
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: readiness\r\nConnection: close\r\n\r\n")
            .map_err(|e| format!("write readiness GET: {e}"))?;
        let mut resp = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break, // the guest closed (Connection: close)
                Ok(n) => {
                    resp.extend_from_slice(&buf[..n]);
                    if resp.len() >= 4096 {
                        break;
                    }
                }
                Err(e) => return Err(format!("read readiness response: {e}")),
            }
        }
        let head = String::from_utf8_lossy(&resp);
        if head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200") {
            Ok(())
        } else {
            Err(format!(
                "readiness response was not a 200 (got {} bytes; first line: {:?})",
                resp.len(),
                head.lines().next().unwrap_or("<none>")
            ))
        }
    }

    // ------------------------------------------------------------------------------------------
    // GUEST side: the `__vm-guest` serve loop (runs INSIDE the microVM, as the static-PIE boatramp
    // execve'd by the non-PIE shim). The caller [`crate::privsep::run_vm_guest`] has already resolved
    // this instance's slice and installed its fail-closed `Enforced` profile (S4) BEFORE calling here —
    // except the vsock listener, which MUST be bound before the profile (the profile denies `bind`).
    // ------------------------------------------------------------------------------------------

    /// A tokio async adapter over a raw (non-blocking) vsock fd, so the guest serves each relayed
    /// client connection with the REAL hand-rolled HTTP stack ([`boatramp_http::serve_connection`]) —
    /// the SAME parser a host-side instance runs, now behind the hypervisor wall.
    struct AsyncVsock {
        inner: tokio::io::unix::AsyncFd<OwnedFd>,
    }

    impl AsyncVsock {
        fn new(fd: OwnedFd) -> io::Result<Self> {
            // SAFETY: `fd` is a live owned socket fd; set O_NONBLOCK for the reactor.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(last_err("fcntl(F_GETFL)"));
            }
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                return Err(last_err("fcntl(F_SETFL, O_NONBLOCK)"));
            }
            // `AsyncFd::new` is deprecated for the general `AsRawFd` case (I/O-safety ergonomics), but
            // here `fd` is an `OwnedFd` — the socket is owned for the adapter's whole life — so the
            // construction is sound; allow the deprecation locally rather than churn the API.
            #[allow(deprecated)]
            let inner = tokio::io::unix::AsyncFd::new(fd)?;
            Ok(Self { inner })
        }
    }

    impl tokio::io::AsyncRead for AsyncVsock {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            loop {
                let mut guard = match self.inner.poll_read_ready(cx) {
                    std::task::Poll::Ready(Ok(g)) => g,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                };
                let fd = guard.get_inner().as_raw_fd();
                let unfilled = buf.initialize_unfilled();
                // SAFETY: read(2) into a valid mutable buffer of its own length.
                let rc = unsafe { libc::read(fd, unfilled.as_mut_ptr().cast(), unfilled.len()) };
                if rc >= 0 {
                    buf.advance(rc as usize);
                    return std::task::Poll::Ready(Ok(()));
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return std::task::Poll::Ready(Err(err));
            }
        }
    }

    impl tokio::io::AsyncWrite for AsyncVsock {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            loop {
                let mut guard = match self.inner.poll_write_ready(cx) {
                    std::task::Poll::Ready(Ok(g)) => g,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                };
                let fd = guard.get_inner().as_raw_fd();
                // SAFETY: write(2) from a valid slice.
                let rc = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
                if rc >= 0 {
                    return std::task::Poll::Ready(Ok(rc as usize));
                }
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return std::task::Poll::Ready(Err(err));
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            // SAFETY: shutdown(2) the write half of a live socket fd.
            unsafe { libc::shutdown(self.inner.get_ref().as_raw_fd(), libc::SHUT_WR) };
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The guest's static-parser serve loop: `accept` each host-relayed client on the (pre-bound,
    /// post-wall) vsock `listener`, and serve it with the REAL HTTP/1+2 stack + the minimal 200 handler
    /// (the SAME `serve_connection` + `MinimalHandler` a host-side backend runs). The untrusted-byte
    /// parse happens HERE, behind the hypervisor wall. As (post-execve) PID 1 this NEVER returns cleanly
    /// — a fatal error logs to the serial console and powers the guest off so the host trips
    /// `FailNodeClosed` (design §5 — guest-death ⇒ node teardown).
    pub(crate) fn guest_accept_serve_loop(listener: OwnedFd, label: &str) -> ! {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => guest_fatal(&format!("building the guest Tokio runtime: {e}")),
        };
        tracing::info!(
            instance = %label,
            "[privsep] VM guest: serving relayed client connections over vsock with the hand-rolled \
             HTTP stack (the static-parser surface, behind the hypervisor wall)"
        );
        println!("PRIVSEP VM GUEST SERVING instance={label}");
        // The blocking `accept(2)` runs on a DEDICATED thread (not a runtime worker) so a single-vcpu
        // guest's current-thread runtime is never stalled by it — it feeds each accepted fd to the
        // async consumer over a channel (the same split `run_backend` uses for its blocking link drain).
        rt.block_on(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<OwnedFd>(64);
            let listener_fd = listener.as_raw_fd();
            let accept = std::thread::spawn(move || {
                // Keep `listener` owned by this thread for the loop's life (closed when it ends).
                let _owned = listener;
                loop {
                    match vsock_accept(listener_fd) {
                        Ok(fd) => {
                            if tx.blocking_send(fd).is_err() {
                                break; // the consumer is gone
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "[privsep] VM guest: vsock accept error");
                            break;
                        }
                    }
                }
            });
            while let Some(fd) = rx.recv().await {
                tokio::spawn(async move {
                    let stream = match AsyncVsock::new(fd) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(error = %e, "[privsep] VM guest: adopting a vsock conn");
                            return;
                        }
                    };
                    if let Err(e) = boatramp_http::serve_connection(stream, MinimalHandler).await {
                        tracing::debug!(error = %e, "[privsep] VM guest: connection served with error");
                    }
                });
            }
            let _ = accept.join();
        });
        guest_fatal("the guest serve loop returned (unreachable)")
    }

    /// The scoped-cut guest handler: a fixed 200 proving the end-to-end byte path
    /// (client → root TCP listener → vsock relay → guest parse → response). The authority-scoped app
    /// router / inward forward-to-a-host-backend (§1d) is the next increment.
    struct MinimalHandler;

    impl boatramp_http::Handler for MinimalHandler {
        async fn handle(&self, _req: boatramp_http::Request) -> boatramp_http::Response {
            boatramp_http::response(
                200,
                b"boatramp privsep VM static-parser frontend (scoped first cut)\n".to_vec(),
            )
        }
    }

    /// A fatal guest error: log to the serial console, sync, and power off so the firecracker child
    /// EXITS — which the host's supervise loop reads as `FailNodeClosed`. PID 1 must never return.
    fn guest_fatal(msg: &str) -> ! {
        eprintln!("PRIVSEP VM GUEST FATAL: {msg}");
        let _ = io::stderr().flush();
        // SAFETY: sync(2) + reboot(RB_AUTOBOOT) are the clean PID-1 power-off; no pointers.
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_AUTOBOOT);
        }
        // If reboot somehow returns, spin rather than return from PID 1 (a kernel panic is worse).
        loop {
            // SAFETY: pause(2) blocks until a signal; no pointers.
            unsafe {
                libc::pause();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::Cpio;

        /// Finding 2 (acpi=off Security review) — a pure CI guard that the guest boot cmdline keeps the
        /// two LOAD-BEARING args. `acpi=off` + `X86_MPPARSE` off is what drops the firecracker-binary
        /// guest to the legacy PIC so device IRQs route (the serial + vsock come up); a future edit that
        /// silently dropped `acpi=off` would reintroduce the `-22` vsock-probe failure. This asserts the
        /// boot-arg half of the precondition in CI (no KVM); the config half is the guest-side
        /// kernel-config guard, and the live boot is the lighthouse serve gate.
        #[test]
        fn guest_boot_args_keep_the_loadbearing_acpi_off_and_pci_off() {
            let args = super::GUEST_BOOT_ARGS;
            assert!(
                args.split_whitespace().any(|a| a == "acpi=off"),
                "the guest boot cmdline MUST keep `acpi=off` (the firecracker-binary DSDT fails on \
                 ACPICA >= 20240827, so ACPI must be off for device IRQs to route): {args:?}"
            );
            assert!(
                args.split_whitespace().any(|a| a == "pci=off"),
                "the guest boot cmdline MUST keep `pci=off` (a privsep guest has no PCI): {args:?}"
            );
            assert!(
                args.contains("rdinit=/init"),
                "the guest boot cmdline MUST rdinit the non-PIE shim at /init: {args:?}"
            );
        }

        /// Socketpair/loopback proof of the relay's BYTE TRANSPARENCY (the Model-A copy-relay the
        /// separate `__vm-relay` process runs behind its profile): a loopback TCP pair stands in for
        /// (client peer ↔ the relay's client side) and a `UnixStream` socketpair for (the relay's
        /// guest side ↔ a fake guest). The relay must move bytes UNCHANGED in BOTH directions — it is
        /// a transparent pipe, the parse is in the guest — including arbitrary non-UTF8 / NUL bytes
        /// (the "opaque client bytes" contract), and must propagate a half-close so a client EOF tears
        /// down the guest leg. No key material is involved: the relay only ever sees these raw bytes.
        #[test]
        fn relay_splices_opaque_bytes_both_ways_and_propagates_half_close() {
            use std::io::{Read, Write};
            use std::net::{TcpListener, TcpStream};
            use std::os::unix::net::UnixStream;

            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
            let addr = listener.local_addr().unwrap();
            // The "client peer" (the connect end) — split into a write + read handle so each can be
            // closed independently (and ALL copies dropped to signal EOF to the relay).
            let client_peer = TcpStream::connect(addr).expect("connect loopback");
            let mut client_w = client_peer.try_clone().unwrap();
            let mut client_r = client_peer;
            let (relay_client_side, _peer) = listener.accept().expect("accept loopback");
            // The fake guest (the far end of the vsock stand-in) — likewise split.
            let (relay_guest_side, fake_guest) = UnixStream::pair().expect("vsock stand-in pair");
            let mut guest_w = fake_guest.try_clone().unwrap();
            let mut guest_r = fake_guest;

            // The relay runs its transparent byte pipe between the two.
            let relay = std::thread::spawn(move || {
                super::splice_bidirectional(relay_client_side, relay_guest_side);
            });

            // client → guest: arbitrary opaque bytes (NUL + 0xFF included) arrive unchanged.
            let to_guest: &[u8] = b"REQ \x00\xff\x01 opaque client bytes";
            client_w.write_all(to_guest).unwrap();
            let mut got = vec![0u8; to_guest.len()];
            guest_r.read_exact(&mut got).unwrap();
            assert_eq!(
                got.as_slice(),
                to_guest,
                "client→guest bytes must be opaque/unchanged"
            );

            // guest → client: likewise unchanged.
            let to_client: &[u8] = b"RESP \x02\xfe\x00 opaque guest bytes";
            guest_w.write_all(to_client).unwrap();
            let mut got2 = vec![0u8; to_client.len()];
            client_r.read_exact(&mut got2).unwrap();
            assert_eq!(
                got2.as_slice(),
                to_client,
                "guest→client bytes must be opaque/unchanged"
            );

            // Half-close: the client closes (both halves) → the relay's client→guest leg reads EOF and
            // shuts the guest WRITE half → the guest read drains to EOF (a dead client reliably tears
            // the guest leg down rather than hanging).
            drop(client_w);
            drop(client_r);
            let mut tail = Vec::new();
            guest_r
                .read_to_end(&mut tail)
                .expect("guest read drains to EOF after client close");

            // Then the fake guest closing (every handle) ends the relay's guest→client leg → the relay
            // byte-pipe returns cleanly (the separate process reads that return as FailNodeClosed).
            drop(guest_w);
            drop(guest_r);
            relay
                .join()
                .expect("the relay byte-pipe returns after both legs close");
        }

        /// Pure CI gate for the in-process newc cpio writer (no KVM needed): every entry's header is
        /// exactly 110 bytes, aligned to 4, with the magic + the TRAILER. This catches a mis-sized
        /// header (the live gate once found a 115-byte header) in CI, not only on a real boot.
        #[test]
        fn cpio_newc_headers_are_110_bytes_aligned_and_terminated() {
            let mut cpio = Cpio::new();
            cpio.dir("proc");
            cpio.chardev("dev/console", 5, 1);
            cpio.file("init", 0o755, b"a non-trivial payload of some length");
            let image = cpio.finish();

            // Walk the archive, validating each 110-byte newc header, its field widths, and 4-byte
            // alignment, until the TRAILER.
            let mut off = 0usize;
            let mut saw_trailer = false;
            let mut entries = 0usize;
            while off + 110 <= image.len() {
                let hdr = &image[off..off + 110];
                assert_eq!(&hdr[0..6], b"070701", "newc magic at offset {off}");
                // Every field after the magic is 8 ASCII hex digits.
                assert!(
                    hdr[6..110].iter().all(u8::is_ascii_hexdigit),
                    "header fields are 8-hex at offset {off}"
                );
                let namesize =
                    usize::from_str_radix(std::str::from_utf8(&hdr[94..102]).unwrap(), 16).unwrap();
                let filesize =
                    usize::from_str_radix(std::str::from_utf8(&hdr[54..62]).unwrap(), 16).unwrap();
                let name = &image[off + 110..off + 110 + namesize - 1]; // minus the NUL
                if name == b"TRAILER!!!" {
                    saw_trailer = true;
                    break;
                }
                entries += 1;
                // Name (padded to 4 after the 110-byte header), then data (padded to 4).
                let after_name = off + 110 + namesize;
                let data_start = after_name.div_ceil(4) * 4;
                assert!(data_start.is_multiple_of(4), "data starts 4-aligned");
                let next = (data_start + filesize).div_ceil(4) * 4;
                assert!(next.is_multiple_of(4), "next entry 4-aligned");
                off = next;
            }
            assert!(saw_trailer, "the archive ends with a TRAILER!!! entry");
            assert_eq!(entries, 3, "proc dir + console dev + init file");
        }

        /// F2: the relay's inflight-connection bound is ENFORCED — `reserve_inflight_slot` admits up
        /// to `max`, SHEDS (returns `None`) at the cap without leaking a slot, and re-admits once a
        /// guard is dropped (the per-connection splice thread ending frees the slot). Mutation: make
        /// `reserve_inflight_slot` always return `Some` (drop the bound check) and the shed assert
        /// reddens.
        #[test]
        fn inflight_bound_admits_to_the_cap_then_sheds_and_frees_on_drop() {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicUsize, Ordering};

            let counter = Arc::new(AtomicUsize::new(0));
            let max = 3usize;

            // Admit exactly `max` connections — each within budget is granted.
            let mut permits = Vec::new();
            for i in 0..max {
                let p = super::reserve_inflight_slot(&counter, max);
                assert!(p.is_some(), "slot {i} within the budget must be admitted");
                permits.push(p.unwrap());
            }
            assert_eq!(
                counter.load(Ordering::SeqCst),
                max,
                "the counter tracks admitted slots"
            );

            // At the cap, the next client is SHED (None) — and the over-count is backed out, so a
            // shed attempt never leaks a slot (a leak would permanently shrink the usable budget).
            assert!(
                super::reserve_inflight_slot(&counter, max).is_none(),
                "at the cap a new client MUST be shed (the bound is enforced)"
            );
            assert_eq!(
                counter.load(Ordering::SeqCst),
                max,
                "a shed attempt must not leak an inflight slot"
            );

            // Freeing ONE (drop the guard, as the splice thread ending would) reopens exactly one
            // slot, which a new client can then take.
            permits.pop();
            assert_eq!(
                counter.load(Ordering::SeqCst),
                max - 1,
                "dropping a guard frees its slot"
            );
            assert!(
                super::reserve_inflight_slot(&counter, max).is_some(),
                "a freed slot must be re-admittable"
            );

            // The shipped relay budget is the documented availability bound.
            assert_eq!(super::MAX_INFLIGHT_RELAY_CONNS, 256);
        }

        /// LOW-2: the shed-path warning is rate-limited — the FIRST shed warns, further sheds inside
        /// the interval are counted but SILENT, and the first shed AFTER the interval warns again with
        /// a summary covering exactly the sheds since the last warning. Mutation: make `record` always
        /// return `Some(..)` (drop the interval gate) and the "silent inside the interval" asserts
        /// redden. Deterministic (a synthetic `Instant` base + offsets — no sleeping).
        #[test]
        fn shed_warn_sampler_rate_limits_and_summarizes() {
            use super::{SHED_WARN_INTERVAL, ShedWarnSampler};
            use std::time::{Duration, Instant};

            let t0 = Instant::now();
            let mut s = ShedWarnSampler::new();

            // The very first shed always warns: total 1, summarizing 1 shed.
            assert_eq!(
                s.record(t0),
                Some((1, 1)),
                "the first shed must warn immediately"
            );
            // More sheds inside the interval are counted but emit NO warning.
            assert_eq!(s.record(t0 + Duration::from_millis(1)), None);
            assert_eq!(
                s.record(t0 + SHED_WARN_INTERVAL - Duration::from_millis(1)),
                None,
                "a shed still inside the interval must stay silent"
            );
            // The first shed at/after the interval warns again: total is now 4, and the summary covers
            // the 3 sheds since the last warning (the two silent ones + this one).
            assert_eq!(
                s.record(t0 + SHED_WARN_INTERVAL),
                Some((4, 3)),
                "a shed at the interval boundary must warn with a since-last summary"
            );
            // The counter reset: the next shed inside the new interval is silent again.
            assert_eq!(
                s.record(t0 + SHED_WARN_INTERVAL + Duration::from_millis(1)),
                None
            );
            // After another full interval, warn again; since-last is 2 (the silent one + this one).
            assert_eq!(
                s.record(t0 + SHED_WARN_INTERVAL + SHED_WARN_INTERVAL),
                Some((6, 2))
            );
        }
    }
}

// ---- host-facing re-exports (Linux) ----
#[cfg(target_os = "linux")]
pub use imp::{BootedFrontendVm, VmLaunch, boot_frontend_vm, launch_frontend_vm};
#[cfg(target_os = "linux")]
pub(crate) use imp::{
    guest_accept_serve_loop, relay_readiness_probe, run_relay, vsock_bind_listen,
};

// ============================================================================================
// Cross-platform surface. The VM substrate needs AF_VSOCK + firecracker + KVM (Linux only — the `imp`
// module above), but the composition still PARSES + LINTS `substrate: vm` as valid vocabulary
// everywhere, and the spawn gate reasons about scope on every platform.
// ============================================================================================

/// Resolve the per-guest descriptor (label + vsock port) packed at `GUEST_DESCRIPTOR_PATH` — read by
/// the in-guest `__vm-guest` entry (Linux only).
#[cfg(target_os = "linux")]
pub(crate) fn read_guest_descriptor() -> Result<GuestDescriptor, String> {
    let bytes = std::fs::read(GUEST_DESCRIPTOR_PATH)
        .map_err(|e| format!("reading the guest descriptor {GUEST_DESCRIPTOR_PATH}: {e}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("parsing the guest descriptor {GUEST_DESCRIPTOR_PATH}: {e}"))
}

/// Pure (host-testable) scope predicate: a `substrate: vm` instance is **scoped-wired** in this cut
/// IFF it is a key-free static-parser frontend — it holds at least one group-C `listen.*` surface and
/// NOTHING else (no crown jewel, no backend credential, no exec/control authority). This is exactly
/// the lint's P3 (`check_vm_secret_blindness_closure` Tier 3). Any other VM shape — a co-located sealer
/// bundle (P1, which needs the owner-GATED key path), a backend, an exec/control instance — is NOT
/// wired in the scoped first cut and the supervisor refuses it fail-closed.
pub(crate) fn is_scoped_static_parser_frontend(
    capabilities: &[boatramp_core::privsep::HostAuthority],
) -> bool {
    !capabilities.is_empty() && capabilities.iter().all(|a| a.is_listener())
}
