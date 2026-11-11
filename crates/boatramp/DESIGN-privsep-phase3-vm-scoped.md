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

- **S1 — the relay placement (the gate for operator-facing wiring).** The host client-byte relay needs
  `accept4`/`connect`/`read`/`write`; the secret-blind root's TCB-floor self-profile is **networkless**
  (`derive_root_profile` → `ROOT_NET_STRIP`) and hard-kills `fork`. So the relay CANNOT run inside the
  confined root as-is. Two shapes, an owner/Security call: (a) **widen the root's self-profile** for the
  relay syscalls when VM frontends exist (bounded — no new key access, no new bind, execve still
  pinned — but it is new TCB in the secret-blind root, exactly what design §1b/§8 S1 flags); or (b) a
  **separate least-authority relay process** (`__vm-relay`, its own narrow profile). Until this is
  ratified, `resolve_spawn_backend` refuses a `substrate: vm` frontend fail-closed with a message naming
  this gate (no silent downgrade). The MECHANISM is built + live-gated; only the operator-facing
  supervise dispatch waits on S1.
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
