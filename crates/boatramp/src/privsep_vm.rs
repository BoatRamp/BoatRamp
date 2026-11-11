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
//! The non-PIE init shim (`src/bin/privsep_vm_shim.rs`) is PID 1 (own-binary-as-init needs a non-PIE
//! PID 1; a static-PIE #GP-faults on an old minimal guest kernel — O3b): it mounts `/proc,/sys,/dev`
//! then `execve`s the static-PIE `boatramp __vm-guest` (keeping the payload's ASLR — de-risk §1.4).

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
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
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
            // newc header: "070701" + 13 × 8-hex fields.
            let header = format!(
                "070701{ino:08x}{mode:08x}00000000000000000000{nlink:08x}00000000{size:08x}00000000000000000{rmaj:08x}{rmin:08x}{namesize:08x}00000000",
                size = data.len() as u32,
                rmaj = rdev.0,
                rmin = rdev.1,
            );
            debug_assert_eq!(header.len(), 110, "newc header is 110 bytes");
            self.buf.extend_from_slice(header.as_bytes());
            self.buf.extend_from_slice(name.as_bytes());
            self.buf.push(0);
            // Pad the (header+name) to a 4-byte boundary so file data starts aligned.
            while self.buf.len() % 4 != 0 {
                self.buf.push(0);
            }
            self.buf.extend_from_slice(data);
            while self.buf.len() % 4 != 0 {
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

    fn boot_firecracker(
        assets: &VmAssets,
        work_dir: &Path,
        initramfs: &Path,
        guest_cid: u32,
    ) -> io::Result<BootedVm> {
        verify_guest_kernel(&assets.guest_kernel, assets.guest_kernel_sha256.as_deref())?;
        let uds_path = work_dir.join("vsock.sock");
        let config_path = work_dir.join("firecracker.json");
        // Raw firecracker machine config: kernel + initrd + vsock, `drives: []`, no
        // `network-interfaces` (the production `FcMachine` has no initrd/vsock fields; the bench
        // `vsock.rs` proves this exact kernel+initramfs+vsock shape).
        let config = format!(
            r#"{{
  "boot-source": {{
    "kernel_image_path": {kernel},
    "initrd_path": {initrd},
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro rdinit=/init"
  }},
  "drives": [],
  "machine-config": {{ "vcpu_count": 1, "mem_size_mib": 1024 }},
  "vsock": {{ "guest_cid": {cid}, "uds_path": {uds} }}
}}"#,
            kernel = json_str(&assets.guest_kernel.to_string_lossy()),
            initrd = json_str(&initramfs.to_string_lossy()),
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
        // The vsock UDS appears once the device is up; a bounded wait, else the guest never came up.
        let deadline = Instant::now() + Duration::from_secs(15);
        while !uds_path.exists() {
            if Instant::now() > deadline {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other(
                    "firecracker's vsock UDS never appeared within 15s (guest did not boot)",
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

    /// The host-side **client-byte relay** (Model A, design §1c): the root already bound the privileged
    /// public TCP `listener`; here it accepts each client and relays the client's bytes to the
    /// frontend-in-guest over a fresh vsock connection, splicing bytes both ways. The relay carries
    /// ONLY untrusted client bytes — NEVER key material (the scoped frontend holds no key; the HARD
    /// EXCLUSION). Runs on its own thread for the node's life; a guest death EOFs the dials (the
    /// firecracker child, supervised separately, is the authoritative `FailNodeClosed` signal).
    fn run_relay(
        label: String,
        listener: std::net::TcpListener,
        uds_path: PathBuf,
        guest_port: u32,
    ) {
        tracing::info!(
            instance = %label,
            "[privsep] VM relay: accepting client TCP; relaying bytes to the frontend-in-guest over \
             vsock (client bytes only — no key material crosses the root; S1)"
        );
        loop {
            let (client, _peer) = match listener.accept() {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(instance = %label, error = %e, "[privsep] VM relay: accept ended");
                    return;
                }
            };
            let uds = uds_path.clone();
            let label2 = label.clone();
            std::thread::spawn(move || {
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

    /// Launch ONE scoped static-parser-frontend VM: assemble the initramfs (shim + real binary + real
    /// config + descriptor), S3-verify + boot the microVM, and spawn the host client-byte relay over
    /// the ALREADY-bound TCP `listener`. The caller supervises `VmLaunch.child`.
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
             only, no net, no drives — the hypervisor wall is the PRIMARY containment)"
        );
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
            Ok(Self {
                inner: tokio::io::unix::AsyncFd::new(fd)?,
            })
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
}

// ---- host-facing re-exports (Linux) ----
#[cfg(target_os = "linux")]
pub use imp::{VmLaunch, launch_frontend_vm};
#[cfg(target_os = "linux")]
pub(crate) use imp::{guest_accept_serve_loop, vsock_bind_listen};

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
