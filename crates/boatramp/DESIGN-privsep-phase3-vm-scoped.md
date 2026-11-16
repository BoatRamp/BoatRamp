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

Toward **O4 full capability parity** (backends in VMs, owner 2026-11-14), S1's separated relay is the
transport prerequisite; the inward backend relay (§1d), guest net/egress, and secret-blind cred
delivery (key material stays in-guest / relayed by the key-holder sealer, never the root) are the
subsequent O4 increments on this same separated-relay foundation.
