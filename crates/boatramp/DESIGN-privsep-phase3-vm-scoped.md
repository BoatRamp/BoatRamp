# DESIGN — privsep Phase-3 VM substrate: the **scoped first cut** (what landed)

*Crate-local note. Branch `privsep-vm-scoped`, built on `feat/privsep` (Phases 0–4 + WS-D/E + Wave-2 +
the Container substrate + the S2 secret-blindness lint). It records what the owner-greenlit scoped VM
first cut (2026-11-10: **firecracker/Linux, static-parser-frontends-only, key-free, invariant-preserving**)
actually BUILT, and the gates that remain owner/Security decisions. Reads with
`DESIGN-privsep-phase3-vm.md` (the full substrate design + the O1–O5 / S1–S4 decision list) and
`DESIGN-privsep-phase3-vm-derisk.md` (O3b + the S2 wiring).*

## What this cut BUILDS (shipped on this branch)

The scoped VM substrate **mechanism**, as real, clippy-clean, Linux-gated code
(`crates/boatramp/src/privsep_vm.rs` + the non-PIE shim `src/bin/privsep_vm_shim.rs` + the
`__vm-guest` guest entry in `src/privsep.rs`):

1. **Own-binary-as-init (O3b).** The non-PIE init shim (`boatramp-privsep-vm-shim`, built non-PIE in a
   dedicated `RUSTFLAGS` invocation) is PID 1 in the microVM; it mounts `/proc,/sys,/dev` and `execve`s
   the literal **static-PIE** `boatramp __vm-guest`, preserving the payload's ASLR (de-risk §1.4) — one
   static-PIE binary + a ~kilobyte shim, no dual build artifact.
2. **In-process initramfs assembly.** A minimal newc cpio (written in-memory — the secret-blind root
   execs nothing but its own binary, so no shelling to `cpio`): `/init` = the shim, `/boatramp` = the
   real static-PIE binary, `/boatramp.cfg` = the real `ServerConfig`, `/privsep-vm-guest.json` = a
   non-secret descriptor (label + vsock port). Smallest guest TCB (Option A; no distro userland, no
   block device).
3. **Firecracker boot + S3.** Kernel + initramfs + a vsock device, `drives: []`, NO net (S1 — the
   guest's only peer is the host relay). The guest kernel is hash-pinned + verified before boot (S3),
   reusing the compute plane's content-hash gate shape; a missing/mismatched pin refuses fail-closed.
4. **Host client-byte relay (Model A, §1c).** The root binds the privileged TCP listener, accepts each
   client, and relays the client's **bytes** into the guest over firecracker's host-side vsock UDS
   bridge. The relay carries ONLY untrusted client bytes — **never key material** (the HARD EXCLUSION).
5. **Guest serve (S4).** `__vm-guest` resolves its slice from the packed config, binds AF_VSOCK, installs
   the SAME fail-closed `Enforced` seccomp/Landlock profile a host-side instance installs
   (`install_privsep_instance_profile`, extracted so the two can't drift), and serves the relayed client
   with the REAL `boatramp_http` stack over an `AsyncFd` vsock adapter. The hypervisor boundary is the
   primary wall; the in-guest profile is defense-in-depth.
6. **Enforcing composition lint (safety).** `check_vm_secret_blindness_closure` (already in `feat/privsep`,
   Tier 1/2/3) refuses, BEFORE any spawn, any VM instance outside the key-free scope — a key-material
   link relayed through the root (Tier 1), a VM key holder without its co-located sealer (Tier 2), or any
   VM instance that is not a key-free listener-only parser frontend / co-located sealer bundle (Tier 3).
   Mutation-proven by the `boatramp-types` unit tests (a key-material-in-VM config FAILS; the correct
   no-secret static-parser-frontend config PASSES).
7. **Live serve gate.** `tests/privsep_vm_live.rs` + `docs/privsep-vm-scoped-repro/` boot a real
   firecracker microVM on lighthouse and serve a `200` over the vsock relay — exercising the real Rust
   launcher end-to-end. Not a GitHub-CI gate (hosted runners have no `/dev/kvm`); the evidence is the
   lighthouse run.

The guarantee enforced: **a static-parser-frontend VM instance carries zero key material, so
root-holds-no-secret is trivially preserved** — statically, by the lint, before any spawn.

## What stays DEFERRED (owner/Security gates — flagged, not guessed)

- **S1 — the relay placement. RESOLVED (owner, 2026-11-14): a SEPARATE least-authority relay process
  (`__vm-relay`), NOT a widening of the root.** The host client-byte relay needs
  `accept4`/`connect`/`read`/`write`; the secret-blind root's TCB-floor self-profile is **networkless**
  (`derive_root_profile` → `ROOT_NET_STRIP`) and hard-kills `fork`. The two shapes were (a) widen the
  root's self-profile for the relay syscalls (bounded, but new TCB in the secret-blind root) or (b) a
  separate least-authority relay process. The owner chose **(b)** — keep the TCB floor minimal; a relay
  bug, parsing untrusted client bytes, stays OUT of the root. See the **S1 section** below for what is
  now landed (the root→relay boundary contract) and what the next increment wires. Until that wiring
  lands, `resolve_spawn_backend` still refuses a `substrate: vm` frontend fail-closed (no silent
  downgrade); the MECHANISM is built + live-gated.
- **S3/S4 — the guest-kernel floor.** The in-guest fail-closed `Enforced` profile requires Landlock
  `MIN_LANDLOCK_ABI = V5` (kernel ≥ 6.10). The firecracker CI kernels (≤ 6.1, Landlock ABI ≤ V2) and
  boatramp's own `linux_6_1` compute-plane guest kernel do NOT meet it — a privsep VM needs a
  **provisioned** ≥ 6.10 Landlock guest kernel (the live gate builds a 6.12.67 one,
  `docs/privsep-vm-scoped-repro/kernel.nix`). Guest-kernel provenance + the verify-before-boot bar is
  the S3 owner/Security decision; the V5 floor coupling is S4.
- **§1d — inward forward.** A scoped VM frontend serves self-contained (parse → 200). Forwarding the
  parsed request inward to a host-side backend over vsock (the client-splice byte-relay, §1d) is the next
  increment, not this cut.
- **The vsock KEY-material relay — EXCLUDED (owner-gated).** Any transport that routes key bytes through
  the secret-blind root (design §3 / S2) is out of scope and refused by the lint + the spawn gate.
- **vz / macOS; multi-VM CID/port topology; restart-path supervision** — follow-ons (design §6, §1b, §5).

## S1 — the separate `__vm-relay` process: what's landed, what's next

The owner RESOLVED S1 (2026-11-14) as a **separate least-authority relay process** (`__vm-relay`),
not a widening of the secret-blind root. The relay accepts each client on the root-bound public TCP
listener and splices its bytes to the frontend-in-guest over firecracker's vsock UDS bridge — it
carries ONLY untrusted client bytes, never key material (a scoped static-parser frontend holds no
key, enforced by `check_vm_secret_blindness_closure` before spawn), so the relay is itself
secret-blind.

### Landed in this increment (the root→relay BOUNDARY CONTRACT — pure, host-tested, inert)

The S1 analog of WS-B's `InstanceSpawnSpec` (the fully-formed, tested command + environment the root
hands the OS), in `crates/boatramp/src/privsep.rs`:

- **`VM_RELAY_SUBCOMMAND = "__vm-relay"`** — the internal `argv[1]` token (mirrors
  `__root`/`__instance`/`__vm-guest`; kept out of the clap enum).
- **`VmRelayDescriptor { label, uds_path, guest_port }`** + **`PRIVSEP_VM_RELAY_ENV`** — the
  NON-SECRET launch descriptor (names/paths/a port only) the root hands the relay, serialized into
  its env var (like `PRIVSEP_FDS_ENV` / `PRIVSEP_AUTHORITY_LINKS_ENV`); `to_env_value` /
  `from_env_value` / `from_env` round-trip it.
- **`VmRelaySpawnSpec { label, argv, env }` + `to_command`** and **`plan_vm_relay_spec(...)`** — the
  pure builder: argv `["__vm-relay", "<label>"]`; the env is the SAME minimal secret-scrub every
  capability-less instance gets (`build_instance_env(parent, &[], declared_secret_env)` — so a
  `_TOKEN`/`_SECRET`/… or a config-declared BYO-credential var is scrubbed, Finding-1 parity) plus
  ONLY the two non-secret wiring vars; the pre-bound public TCP listener rides the ONE existing
  fd-pass mechanism (`PrivsepChildFds { links: {}, listener: Some(fd) }`), not a parallel one.
- Unit tests (`vm_relay_descriptor_round_trips_through_its_env_value`,
  `plan_vm_relay_spec_is_secret_blind_and_wires_the_boundary`) prove the round-trip + that NOT ONE of
  three secret-bearing parent vars (a secret `BOATRAMP_*`, a config-declared BYO credential, a cloud
  credential) crosses to the relay, while the listener fd + descriptor wire correctly.

Nothing is wired into the runtime: `resolve_spawn_backend` still refuses `substrate: vm` fail-closed,
the secret-blind root / the two prod VM-refusal gates / the lint are untouched, and the contract is
inert dead-code (`#[allow(dead_code)]` on `to_command`) until the next increment calls it.

### Next increment (Security-reviewed + Linux-live-gated — NOT in this cut)

1. **The relay's own least-authority seccomp/Landlock profile** (a NEW `DerivedProfile`, the one
   genuinely Security-critical design piece — recommended shape, to ratify): seccomp = the Phase-0
   `ALLOWED` baseline KEEPING only the socket verbs the relay needs (`socket` for AF_UNIX,
   `connect`, `accept4`, the read/write/`shutdown` family) — i.e. a SUBSET of `ROOT_NET_STRIP`,
   NOT `bind`/`listen`/`socketpair` (the listener is passed pre-bound) — MINUS `KEY_LOCK`, MINUS
   `EXEC_SPAWN` (the relay never execs — TIGHTER than the root); kill = the full `KILL_SURFACE`
   INCLUDING `execve`/`execveat` + `fork`/`vfork` (the relay spawns nothing; threads use
   `clone`/`CLONE_THREAD`, which stays allowed). Landlock view = READ+EXECUTE on its own static
   binary only, plus the ONE firecracker vsock UDS path it dials — NO config, NO `data_dir`, NO key,
   NO instance state. Derive it pure + unit-tested (like `root_supervisor_allowlist`), install it
   through the SAME `install_derived` machinery, fail-closed `Enforced`.
2. **The supervise dispatch**: for a scoped-frontend `substrate: vm` instance, the root binds the
   public listener, assembles+boots the microVM (`launch_frontend_vm`, minus its in-root relay
   thread), then `fork`+`exec`s the `__vm-relay` child via `VmRelaySpawnSpec::to_command` — `dup2`ing
   the listener onto the fixed fd + passing the vsock UDS path in the descriptor — and supervises BOTH
   the firecracker child and the relay child (either's death ⇒ `FailNodeClosed`). Flip
   `resolve_spawn_backend` to accept the scoped shape.
3. **`run_vm_relay()` entry** (the `__vm-relay` dispatch in `lib.rs`, beside `__vm-guest`): read the
   descriptor + the listener fd, install the profile (1), run `privsep_vm::run_relay` behind it.
4. **Linux live gate**: invert a fail-closed `#[ignore]`d relay gate to assert the separate relay
   process serves end-to-end over the vsock bridge on lighthouse+KVM (the mechanism's serve path
   already proven; this validates the process split + its profile).

### Relay egress containment — F1/F2 Security-review follow-ups (landed 2026-11-18)

The relay's own least-authority profile (item 1 above) and `run_vm_relay()` entry (item 3) landed, and
an independent Security review of them (F1 = a Landlock `AccessNet` deny-all-TCP wall,
`SandboxPolicy::deny_all_tcp`; F2 = an inflight-connection bound) returned SHIP-WITH-FIXES with three
follow-ups, now closed:

- **MED-1 — the netless relay runs in a FRESH, EMPTY network namespace.** F1's Landlock `AccessNet`
  governs ONLY TCP bind/connect; it left **UDP** egress open (the relay's seccomp legitimately KEEPS
  `socket`/`sendto`/`connect` to dial the vsock UDS, and seccomp filters by name, not by the socket's
  domain argument), so a compromised relay could `sendto` the spliced client bytes / C2 / pivot over
  UDP. The robust fix (Security reviewer's recommendation; the strongest primitive) is
  `unshare(CLONE_NEWNET)` into an empty, loopback-only netns with no route anywhere — closing UDP **and**
  TCP **and** raw/packet **and** abstract-UDS egress at once, with no route to 169.254.169.254 at all.
  It is LAYERED over F1 + the relay seccomp set (defence in depth, not a replacement). The **pathname**
  AF_UNIX vsock UDS still dials (AF_UNIX pathname sockets are not netns-scoped) and the inherited,
  root-netns-bound public TCP listener still `accept`s (a socket keeps its creation netns) — BOTH
  live-proven on lighthouse (kernel 6.12), on glibc AND static-musl. Privilege path: the relay is
  `fork`+`exec`'d by the privileged root and INHERITS root's capabilities (the SAME userns-free model
  the Container substrate uses for its `unshare(NS/IPC/UTS/CGROUP)`); it uses `CAP_SYS_ADMIN` ONCE, in
  `run_vm_relay_confined`'s pre-profile window (the profile hard-kills `unshare`/`setns`), then drops
  ALL capabilities before installing the profile and touching a client byte. `enter_empty_netns()`
  takes that userns-free `CLONE_NEWNET` path when privileged and FALLS BACK to
  `unshare(CLONE_NEWUSER|CLONE_NEWNET)` for an UNPRIVILEGED caller (never the production relay — the
  unprivileged `live-gate-sandbox` probe), both yielding an egress-equivalent loopback-only netns.
  **netns is the LOAD-BEARING wall precisely because it does not depend on an LSM hook firing**: a
  virtualized CI runner can REPORT `AccessNet` support yet silently NOT enforce the net hook (this
  reddened `feat/privsep`'s `live-gate-sandbox` on the GHA runner — F1 alone was a no-op there), whereas
  an empty netns simply has no route. Fail-closed: if NO empty netns can be entered / verified
  loopback-only, the relay REFUSES to serve — never a full-network fallback. Reusable primitives in
  `boatramp_server::sandbox`, shared by the relay and both live gates.
- **INFO — a REAL in-process capability drop.** Two steps, both before the profile install:
  (1) `drop_all_capabilities()` = `SECBIT_NOROOT` + bounding-set clear (incl. `CAP_NET_RAW`) + ambient
  clear — the ONE shared sequence every privsep instance's `pre_exec` also calls (consolidated); but
  `prctl` only gates RE-acquisition at the next `execve`. An instance drops its effective caps via the
  `execve` that follows its `pre_exec`; the relay NEVER execs, so (2) `clear_current_capabilities()` =
  `capset(2)` clears the EFFECTIVE/PERMITTED/INHERITABLE sets IN-PROCESS, leaving the relay with ZERO
  capabilities while serving. The relay runs `capset` BEFORE installing its seccomp profile (so it is
  not yet filtered) and AFTER its one privileged op (the netns unshare).
- **Relay profile — grant the vsock UDS's DIRECTORY, not the socket inode.** Landlock rules are built
  by O_PATH-opening the granted path, and the `landlock` crate cannot open a SOCKET inode on the shipped
  static-musl build (`ENXIO` → the Landlock layer fails → `install_derived` → `Partial` →
  `enforce_privsep_status` REFUSES → the relay would never serve on musl). `relay_supervisor_policy` now
  grants the uds's PARENT DIRECTORY (a regular dir opens everywhere, so the install's O_PATH open of the
  IN-view grant succeeds); `boot_firecracker` nests the UDS in a DEDICATED per-VM directory holding only
  that socket, so the grant stays tight. A latent bug on the shipped target, found + fixed here. NOTE
  the dir grant does NOT block an OUT-of-view pathname-UDS `connect(2)` — Landlock's `AccessFs` does not
  mediate UDS connect at all (see INFO-1 below); that pivot is closed by the mount-ns, not this view.
- **LOW-2 — the F2 shed-path warning is rate-limited** (`ShedWarnSampler`): at most one warning per 5s,
  each with a running "N sheds since the last warning" summary — so the availability defence can't turn
  into a log/CPU/disk-amplification DoS of its own under the very flood it sheds. O(1), fixed state.

### Pre-VM-go-live hardening — two INFO items from a follow-up Security review (landed 2026-11-18)

A pre-go-live Security review of the relay flagged two residual INFO items (both TCB-adjacent;
fail-closed; validated on lighthouse kernel 6.12 + the GHA runner). The VM substrate stays
prod-gated-off (`resolve_spawn_backend` refuses `substrate: vm`); these mitigations touch the RELAY
ONLY (no monolith/root/instance/container change).

- **INFO-1 — pathname-`AF_UNIX` egress: a minimal mount-ns `pivot_root`.** The empty netns (MED-1)
  closes all IP egress and every ABSTRACT-namespace UDS, but a **pathname** `AF_UNIX` socket is NOT
  netns-scoped, and Landlock's `AccessFs` does not mediate `connect(2)` to a UDS (the relay's dir-grant
  governs the install's O_PATH opens, not the kernel's `unix_find_other` path walk). The open question —
  does the narrow Landlock dir-view block an out-of-view pathname-UDS `connect()`? — is now **settled
  EMPIRICALLY**: the new `relay_mount_ns_contains_pathname_uds_pivot` live gate's no-mount-ns mutation
  arm connects an out-of-view host UDS SUCCESSFULLY under the netns + dir-view alone, i.e. the pivot was
  OPEN (a compromised relay could reach `/run/docker.sock`, a dbus/systemd/postgres socket, … for a
  local pivot). The robust fix: `sandbox::enter_minimal_mount_ns` enters a private mount namespace and
  `pivot_root`s into a minimal tmpfs root holding ONLY the relay's own binary (execute-pin) + the one
  vsock-UDS dir (bind-mounted at their real absolute paths), so NO host UDS path resolves. Reuses the
  `boatramp-container` worker's mount-ns/`pivot_root` idiom. Done in `run_vm_relay_confined`'s
  pre-profile window (the profile hard-kills `unshare`/`mount`/`pivot_root`), using the inherited
  `CAP_SYS_ADMIN`, then ALL caps are dropped and the profile installed from inside the minimal root.
  Layered UNDER the netns + F1 + the seccomp set (a different mechanism — no LSM hook, no route). The
  gate is mutation-verified (remove the mount-ns ⇒ the out-of-view connect reopens) and runs on the
  real runner. The relay stays uid 0 (never setuids); the mount-ns, not a uid drop, is the wall.
- **INFO-2 — per-VM vsock dir perms.** `boot_firecracker` created the per-VM dir `brvsk-{cid}-{pid}`
  under `std::env::temp_dir()` (world-writable `/tmp`, mode 1777) at the default 0755 — a TOCTOU/connect
  surface around firecracker's socket. It now creates it mode 0700 under a DEDICATED, non-world-writable
  runtime root (`vm_vsock_runtime_root`: `$RUNTIME_DIRECTORY` else `/run/boatramp-vm`, both under `/run`
  — root-owned, NOT world-writable), verified non-world-writable fail-closed. The dir stays single-
  socket (only `vsock.sock`; config/console stay in `work_dir`) so the relay's RO dir grant stays tight,
  and the relay's minimal mount-ns root binds exactly this dir so a `/run`-based location stays reachable
  while every OTHER host UDS path is removed. Fail-closed if the runtime root can't be set up (NEVER a
  silent fall-back to `/tmp`).

Toward **O4 full capability parity** (backends in VMs, owner 2026-11-14), S1's separated relay is the
transport prerequisite; the inward backend relay (§1d), guest net/egress, and secret-blind cred
delivery (key material stays in-guest / relayed by the key-holder sealer, never the root) are the
subsequent O4 increments on this same separated-relay foundation. Note the relay's empty netns is for
the netless scoped frontend; an O4 backend-in-VM path that needs guest egress will provision it
explicitly (a veth/slirp into the relay netns), never by removing this wall.

## Phase-3c — the vsock byte-relay transport: the `acpi=off` fix + the serve gate going GREEN

The scoped serve gate (`tests/privsep_vm_live.rs`) had never actually reached a 200 — booting the
Landlock-V5 (>= 6.10) guest the in-guest wall requires, the guest's **virtio-vsock probe failed `-22`
(EINVAL)** and PID 1 died with no console output. Root-caused live on lighthouse (kernel 6.12.67,
firecracker 1.13.1 binary) to a SINGLE cause, NOT a vsock device-config / CID / driver-mismatch issue:

- The firecracker **binary** backend presents its virtio-mmio devices' interrupt topology over **ACPI**
  (its guest config ships `X86_MPPARSE` off, `ACPI=y`; the embedded rust-vmm VMM uses the MPTABLE +
  `virtio_mmio.device=` cmdline path instead — see `flake.nix` `vmlinux`). On a guest kernel >= 6.12,
  **ACPICA 20240827 REJECTS firecracker 1.13.x's reduced-hardware DSDT during operation-region init**
  (`ACPI Error: AE_BAD_PARAMETER, During Region initialization (…/tbxfload-52)` → `ACPI: Unable to load
  the System Description Tables` → `ACPI: disabled`). (5.10/6.1's older ACPICA accepted it; those lack
  Landlock V5, so they were never a real option — this is a genuine firecracker-1.13 ↔ ACPICA-20240827
  incompatibility, and every kernel with Landlock V5 that nixpkgs still ships is >= 6.12.)
- With ACPI disabled mid-boot the IOAPIC is known (from the MADT, parsed earlier) but **no device-IRQ
  routing is set up** (`preallocated irqs: 0`, no legacy i8259, `/proc/interrupts` has no numbered
  lines). So EVERY device interrupt is dead: the 8250 serial's IRQ-driven TX returns **EIO** — userspace
  `/dev/console` writes fail, and PID 1's own `println!("PRIVSEP VM GUEST SERVING …")` then PANICS the
  guest (exit 101 → "Attempted to kill init"), which is why the console was silent AND the guest died;
  and the virtio-vsock driver's `request_irq` (its MMIO IRQ) returns **-EINVAL**, so `virtio_vsock_probe`
  → `virtio_find_vqs` fails `-22` and the transport never comes up — the host byte-relay can never reach
  the frontend. (The `-22` is thus the **guest-driver probe**, not a host `connect()/bind()`.)

**Fix (two lines, kernel-version-INDEPENDENT, no code logic change):**

1. **`acpi=off`** in the guest kernel cmdline (`boot_firecracker`). With `X86_MPPARSE` also off (as the
   firecracker config ships it) the guest falls back to the legacy PC model — `APIC: Keep in PIC
   mode(8259)`, `preallocated irqs: 16` — that **firecracker's KVM in-kernel irqchip emulates and routes
   GSI 0-15 to**. The serial (IRQ 4) and the vsock device (IRQ 5) then get working IRQ lines. Safe: a
   privsep guest runs no ACPI-dependent devices (no PCI, no power-mgmt, single vcpu). MUST stay paired
   with `X86_MPPARSE` OFF (ON + `acpi=off` would make the kernel hunt for an MPTABLE the firecracker
   binary does not emit).
2. **`CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`** in the guest kernel — since ACPI enumeration is now off,
   the device is discovered off the `virtio_mmio.device=` cmdline firecracker appends. The shipped
   `boatramp-vmlinux` **already enables this** (for the embedded-VMM path, `flake.nix`), so for the
   production kernel the fix is the `acpi=off` boot-arg ALONE; only the repro's own `kernel.nix` /
   `fc-base.config` needed the flag added.

**Live-proven on lighthouse** (kernel 6.12.67 + Landlock V5, firecracker 1.13.1, static-musl static-PIE
`boatramp` + the non-PIE shim, 3 consecutive runs): clean boot (`SHIM-ALIVE` on the serial console — PID1/
console sane), `virtio-mmio.0 … IRQ 5` registers with **no `-22`**, `AF_VSOCK bound`, the in-guest
Enforced Landlock-V5 + seccomp profile installs (`status=Enforced`), `PRIVSEP VM GUEST SERVING`, and the
host↔guest **byte relay serves a real `200`** through `boatramp_http` behind the hypervisor wall
(`PRIVSEP VM SCOPED SERVE OK`, the frontend body marker asserted). The transport mechanism works.

**Still open (NOT this increment):** the serve gate stays `#[ignore]`d + lighthouse-driven (hosted CI has
no `/dev/kvm`); `resolve_spawn_backend` still refuses `substrate: vm` fail-closed — the operator-facing
**supervise dispatch** (root binds the listener, boots the VM minus its in-root relay thread, `fork`+`exec`s
the separate `__vm-relay`, supervises both → `FailNodeClosed` on either death) is the next increment, and
the whole Phase-3c delta (this `acpi=off` transport fix + the dispatch) gates on the **Security review**.
