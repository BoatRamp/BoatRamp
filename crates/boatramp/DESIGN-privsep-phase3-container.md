# DESIGN — privsep Phase-3 substrate: the **Container** spawn backend

*Crate-local design note (privsep Phase-3). Branch `privsep-container-wire`, built on
`privsep-phase3-container` tip `171114c3` (itself on `feat/privsep` `808c2bd9`). Status: **OPTION C
WIRED (owner-approved simple model).** The Container substrate is now a wired spawn backend; the
hard rootfs reconciliation (#1) is RESOLVED by choosing Option C (no `pivot_root`, no worker, no
`SandboxPlan` change). TCB-critical; goes to Security before any fold. **§8 below documents exactly
what was built + the Security flags** (read it first for the current state; §1–§7 are the original
design reasoning that led to Option C).*

---

## 0. The question

Wire `[privsep].instances.<name>.substrate = "container"` so the root supervisor spawns a
privilege-separated `__instance` inside `boatramp-container`'s namespace/cgroup confinement —
**preserving every Phase-1 guarantee** (materialization-by-construction, the per-capability
`Enforced` seccomp/Landlock wall, env-blindness, `FailNodeClosed`, the root-wired fd topology) —
instead of the current fail-closed refusal in
[`resolve_spawn_backend`](src/privsep.rs) (~line 785).

**Verdict of this pass: Container cannot be wired end-to-end in this cut without resolving three
TCB-critical design questions that are genuinely ambiguous and require owner + Security
ratification (§1, §2b, §5b below). The substrate therefore stays refused fail-closed, with a
sharpened refusal that names the specific blockers and points here. What is unambiguous and safe
is built (§7).** Flagging beats guessing on the root's spawn sequence.

### The OsProcess baseline we must not regress (what "preserve every guarantee" means)

The wired `OsProcess` backend is, in `supervise::run` (`src/privsep.rs` ~1714):

1. a root-created `socketpair(2)` per `local` link (`LinkEndpoint::socketpair`, both ends CLOEXEC);
2. the root binds each `listen.*` holder's privileged public listener and keeps the fd open;
3. each inherited end/listener is assigned a **globally-unique target fd number above every
   source fd**, and the per-instance `BOATRAMP_PRIVSEP_FDS` map names `link → fd` + `listener →
   fd`;
4. `spawn_wired_instance` (`src/privsep.rs` ~1131): `std::process::Command` with
   `env_clear().envs(spec.env)` (F11-B minimal scrubbed env) + the fd map / unseal allowlist /
   authority-serve links as extra `BOATRAMP_*` env; a `pre_exec` that `dup2`s each `(src → tgt)`
   and clears `CLOEXEC`, then `PR_SET_PDEATHSIG(SIGKILL)`; then `cmd.spawn()` re-execs
   `boatramp __instance <label> --config <path>`;
5. in the child, `run_instance` → `instance_serve::run` installs the **per-capability** seccomp +
   Landlock profile itself (`derive_profile` + `install_derived` + `enforce_privsep_status`,
   fail-closed `Enforced` fleetwide), reconstructs its endpoints from `PrivsepChildFds::from_env`,
   and serves;
6. the root installs its own tightest self-profile AFTER the spawn loop, then supervises:
   **any child exit tears the whole node down (`FailNodeClosed`).**

The container substrate must deliver the SAME six properties with a namespace/cgroup wall ADDED
underneath — namespaces/cgroups are *additive* confinement, never a replacement for the
per-capability wall (design §Phase-3).

---

## 1. What runs inside the container — the OCI-vs-own-binary reconciliation **[FLAG — the blocker]**

**Requirement.** The container must host the **host's own static-musl `boatramp` binary** in
`__instance` mode (the fork+exec model), NOT an arbitrary OCI image. The instance is the same
re-exec of `current_exe()` the OsProcess backend does, only wrapped in namespaces + a cgroup.

**What `boatramp-container` actually offers (read in full):**

- `ComputeBackend::launch` / `run_ephemeral` (`backend.rs`) are built around a **`ComputeSpec`**:
  an OCI `RootSource::Image`/`Tar` staged from `Storage` blobs into `<data_dir>/compute/rootfs/…`,
  a **veth pair into a bridge**, per-node **IPAM**, internal **DNS** / `resolv.conf`, persistent
  replicas vs one-shot clients. **None of that applies to a privsep instance**, which runs the
  host binary, needs no registry pull, no veth, no IPAM, no DNS. This entry is the **wrong seam**.
- The reusable lower layer is **`SandboxPlan`** (`sandbox.rs`) + the **`worker`** module
  (`worker.rs`), re-exec'd as `boatramp __sandbox`: `setup_cgroup` → `unshare` namespaces → fork a
  PID-ns init → `pivot_root` **into a rootfs** → standard mounts (`/proc` `/sys`ro `/dev` `/tmp`
  `/run`) → `sethostname` → drop caps + uid/gid → install a default-deny seccomp filter → `execvpe`
  `plan.argv[0]`.

**The irreducible tension: `pivot_root`.** The worker's security model *requires* pivoting into a
rootfs and detaching the host root. So `plan.argv[0]` must resolve to the boatramp binary **inside
that rootfs after the pivot** — the host's `current_exe()` path is gone once `/.put_old` is
detached. There is no "run the host binary, no rootfs" mode. This forces a rootfs-model decision
that is genuinely ambiguous and TCB-critical:

- **Option A — minimal synthetic rootfs.** The root stages a tiny rootfs containing just the
  static-musl `boatramp` binary (bind-mounted or hardlinked read-only) + the config file + the
  `SYSTEM_READ_ROOTS` the process needs (`/etc/resolv.conf`, CA bundle, `/proc`). Clean blast
  radius (the instance sees nothing of the host FS beyond what Landlock would grant anyway), but a
  new rootfs-assembly path to design + a per-instance staging cost.
- **Option B — bind-mount the host binary + config into a stock minimal rootfs**, argv =
  `/boatramp __instance <label> --config /boatramp.cfg`. Simpler staging; must get the
  bind-mounts + read-only posture exactly right so the instance cannot mutate the shared staged
  tree (cf. `run_ephemeral`'s `readonly_root`).
- **Option C — skip `pivot_root`; unshare only `CLONE_NEWNS` + `CLONE_NEWCGROUP` (+ optionally
  pid/ipc/uts) and keep the host mount view**, relying on the per-capability **Landlock** wall for
  the FS confinement (it already restricts the instance to `data_dir` + its own binary + config).
  This matches the privsep model best — Landlock *is* the FS wall; the namespaces add
  pid/cgroup/ipc/uts isolation on top — but it is **NOT what `boatramp-container`'s worker does**
  (its whole worker is pivot-root-shaped), so Option C is effectively a *new* confined-spawn
  primitive that reuses only `unshare` + `setup_cgroup`, not the worker.

**Flag.** Options A/B reuse the worker but inherit its rootfs machinery and the single-fd limit
(§2). Option C is the cleanest fit for privsep's "Landlock is the FS wall" posture but means the
"reuses `boatramp-container`" framing in the `InstanceSubstrate` docs really means "reuses its
`unshare`/cgroup primitives," not its worker. **This choice is the load-bearing decision and must
be ratified by the owner + Security before any code.** Recommended default to bring as INPUT:
**Option C** (unshare mount+pid+ipc+uts+cgroup namespaces, NO net unless a backend needs egress —
see §5b, NO pivot_root, Landlock remains the FS confinement), because it preserves the Phase-1
model with the least new TCB and avoids duplicating the rootfs/mount sequence. But this is a
recommendation, not a settled decision.

---

## 2. The link across the namespace boundary — **CONFIRMED works; the fd-pass MECHANISM is the gap**

**2a. Cross-namespace fd-pass is sound (the reason Container is simpler than VM).** The `local`
transport is a root-created `AF_UNIX`/`SOCK_STREAM` **`socketpair(2)`** (`privsep_link.rs`). An
already-connected socketpair end is a plain open fd: it is **not** affected by a child entering a
new mount/pid/ipc/uts/user namespace, and it is **not** affected by a new **net** namespace either
— an `AF_UNIX` socketpair has no network address and is not namespaced by netns, so the two ends
keep talking across the boundary on the shared kernel. `SCM_RIGHTS` fd-passing
(`send_client_conn`/`recv_client_conn`) likewise works across namespaces (it moves an fd between
two processes on one kernel, unaffected by netns). **So the `privsep_link` transport is unchanged
for Container** — this is exactly why Container is strictly simpler than VM (a VM has its own
kernel, so the socketpair cannot cross; VM needs a vsock re-plumb). **CONFIRMED, no change needed
to `privsep_link`.**

**2b. The MECHANISM to hand the fds into the confined child is the gap [FLAG].** The OsProcess
backend passes **many** fds (every link end + the listener) at **fixed target numbers**, dup'd in
`pre_exec`, named in `BOATRAMP_PRIVSEP_FDS`. The container worker today passes **exactly ONE** fd:
`SandboxPlan.exec_stdin_fd: Option<i32>`, `dup2`'d onto fd 0 just before `execvpe`. Two
sub-problems:

- **The worker forks a PID-ns init between the launcher spawn and the `execve`.** fds survive the
  fork (the child inherits the fd table) and survive the `execvpe` iff CLOEXEC is cleared — so the
  path exists, but the plan must carry a **general dup list** `[(src,tgt)]` + a CLOEXEC-clear, the
  way `spawn_wired_instance`'s `pre_exec` does, rather than the single `exec_stdin_fd`.
- **Who opens the socketpair, and does it survive the launcher→worker handshake?** For OsProcess
  the root opens the socketpair and the child inherits it directly. For Container the root still
  opens it (it must — the socketpair is the root-wired topology, F2/F5), and the end must be
  inherited by the `__sandbox` worker and survive its internal fork+pivot+execve to the final
  `__instance`. The handshake currently uses the worker's own fd 0/1 for the `plan`/`ready`/`go`
  lines; the passed fds must be kept clear of that and clear of the `exec_stdin_fd` convention.

**Flag.** This needs a **small, TCB-critical extension to `SandboxPlan` + `worker`**: generalize
`exec_stdin_fd: Option<i32>` to a `pass_fds: Vec<(i32,i32)>` dup list applied in the worker's
forked child before `execvpe` (CLOEXEC cleared on each target), and a root-side path that opens
the socketpair + bound listener and arranges the worker to inherit them. Because it mutates the
`boatramp-container` **worker** (a compute-plane TCB component the privsep program *reuses*),
Security must review it. It is mechanically well-understood (it mirrors `spawn_wired_instance`
exactly) but should NOT be built ahead of the §1 rootfs decision, because the two interact (under
Option C there is no worker/pivot and the root can do the whole `unshare`+dup itself in one
`pre_exec`, needing NO `SandboxPlan` change at all — which is a further argument for Option C).

---

## 3. Sandbox composition — **CONFIRMED sound (nested install is a solved pattern here)**

The per-capability seccomp/Landlock profile MUST still install **inside** the container
(namespaces/cgroups are additive). This is **already a solved pattern in this codebase**: the
`exec.compute` per-tenant router `fork`s children from an *already-confined* process, and each
child installs its OWN strictly-tighter nested seccomp + Landlock over the inherited filter —
`boatramp-server::sandbox` explicitly allows the `SANDBOX_INSTALL` syscalls (`seccomp`,
`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`) on such a parent, and
documents that seccomp + Landlock are **monotonic** (a child only ADDs restrictions), so nesting
cannot escape. The container case is the same shape:

- **If the container worker installs its own default-deny seccomp first (Options A/B):** that
  filter (`seccomp::default_allowlist`, which includes `seccomp`, `prctl`, `fork`, `execve`, the
  `landlock_*` family per `worker.rs`/`seccomp.rs`) is the *outer* layer; the privsep instance's
  own `derive_profile` install nests UNDER it. The union the privsep profile needs must be a
  subset of the container allowlist — verified: the container allowlist is broad (trusted-tier)
  and permits the install syscalls + the per-capability syscalls the privsep profiles use. The
  result is STRICTLY TIGHTER than either alone, which is only better. **Confirm with the live gate
  (§8).**
- **If Option C (no worker, root does the unshare):** there is no outer seccomp; the instance
  installs its per-capability profile exactly as OsProcess does today — no composition question at
  all. (Another point for Option C.)

- **The own-exe execute-pin + static-musl.** The privsep sandbox Landlock-pins `execve` to the
  instance's own binary (`SandboxPolicy::execute_paths`, populated from `current_exe()` for an
  `exec.compute` instance; empty + exec-killed otherwise). Under Options A/B the binary lives at a
  pivoted path (e.g. `/boatramp`), so the execute-pin must resolve the **post-pivot** path, and the
  binary MUST be **static-musl** (the release target per `.cargo/config.toml` /
  `nix/package-musl.nix` is fully static) so a pivoted, minimal rootfs with no dynamic loader /
  `/lib` can still `execve` it. Under Option C the path is unchanged (`current_exe()` still valid),
  and static-musl still matters only for the (unchanged) exec.compute re-exec. **CONFIRMED the
  requirement; the post-pivot path resolution is an Options-A/B detail folded into §1.**

**Net:** sandbox composition introduces **no new unsolved problem** — it either nests like the
existing per-tenant pattern (A/B) or is unchanged (C). Not a blocker.

---

## 4. Env-blindness + FailNodeClosed + PDEATHSIG — **mostly carries; two items to pin [partial FLAG]**

- **Env-blindness (F11-B).** The spawn still goes through `InstanceSpawnSpec::to_command` →
  `env_clear().envs(minimal scrubbed env)`. Under Options A/B the `__sandbox` worker is spawned
  with `env_clear` too and the `SandboxPlan.env` becomes the instance's env — so the scrub must be
  applied to the **plan's env**, not the worker Command's env (the worker re-execs with the plan's
  env, so a leak would be in the plan). Under Option C it is byte-identical to OsProcess.
  **Pin: the F11-B minimal-env contract must target whichever env the `__instance` ultimately
  `execve`s with.** Not hard, but must be explicit under A/B.
- **`FailNodeClosed`.** The supervise loop `try_wait`s the children it spawned and tears the node
  down on any exit. Under A/B the root's direct child is the `__sandbox` **worker/monitor** (which
  waitpids the PID-ns init); the root must observe the *worker's* exit as the instance's exit, and
  the worker must propagate the instance's death as its own exit code (it already `waitpid`s +
  `exit_code`s its init). Under Option C the child IS the `__instance` and `FailNodeClosed` is
  unchanged. **Pin: confirm the worker→root exit propagation under A/B so a dead instance still
  trips `FailNodeClosed` (no serving with a hole).**
- **`PR_SET_PDEATHSIG`.** OsProcess sets it in the child's `pre_exec` so a dead root takes the
  child with it. Under A/B PDEATHSIG set in the final `__instance` tracks its *parent* = the
  worker's PID-ns init, NOT the root — so a root crash would be caught by the worker's own death
  chain (the init dies → PID-ns reaps), but the exact chain must be verified (the pid-ns init
  dying kills the ns). Under Option C PDEATHSIG is unchanged (child's parent is the root). **Pin:
  verify the death-signal chain under A/B; it is a best-effort hardening (not the containment),
  but must not silently leave an orphaned authority-holding instance.** Another point for C.

**Net:** under Option C, §4 is byte-identical to OsProcess (no new risk). Under A/B, three items
need explicit handling + live verification. This asymmetry is the strongest architectural argument
for Option C and is the key input to bring to the owner.

---

## 5. Operator surface

**5a. The entry point already exists.** `[privsep].instances.<name>.substrate = "container"`
parses + lints today (it is valid composition vocabulary; the closure lint is substrate-agnostic).
The only change at wiring time is `InstanceSubstrate::is_wired(Container) → true` + the dispatch in
`resolve_spawn_backend`/`supervise::run`. **Kept refused until §1/§2b/§5b land.**

**5b. New per-instance container knobs — minimal, and SHAPE deferred [FLAG].** Two knobs are
plausibly needed; both are deferred (their shape depends on §1 and is owner app-design per the
"owner owns application design" rule — bring as INPUT, do not settle here):

- **cgroup limits** (cpu.max / memory.max / pids.max). `SandboxPlan` derives these from a
  `ComputeSpec`'s vCPU/mem ask; a privsep instance has no such ask. Options: (i) no per-instance
  limits (inherit the node cgroup — simplest, recommended default), or (ii) an optional
  `[privsep].instances.<name>.container.{cpu,memory,pids}` block. Recommend (i) for the first cut;
  add (ii) only if an operator asks.
- **userns mapping.** The container worker defaults to rootless (`USERNS_HOST_BASE = 100000`). A
  privsep instance already runs privilege-dropped as the host user; whether to ADD a user
  namespace (and with which map) interacts with §1 (Option C may skip `CLONE_NEWUSER` entirely,
  since the per-capability Landlock + seccomp wall + the existing privilege drop already contain
  it). Recommend: **no user namespace in the first cut** (the Phase-1 wall is load-bearing; a
  userns is additive and can come later), flagged for Security.

**Principle:** keep the operator surface MINIMAL — `substrate: container` and nothing else in the
first wired cut; cgroup/userns knobs are follow-ons gated on demand. This mirrors how `substrate`,
`lifecycle`, and `per_tenant` were each landed as carried-and-linted vocabulary ahead of a
consumer — but the knobs are NOT added speculatively here, because adding config the spawn cannot
yet consume, before §1 fixes their shape, would be churn.

---

## 6. Why `Vm` stays refused (unchanged)

VM has its own kernel: the `local` socketpair CANNOT cross (unlike Container — §2a), so VM needs a
vsock re-plumb of the whole link transport + a guest-side boot of the instance + a per-request
vsock crossing. Strictly harder than Container and out of scope. `is_wired(Vm) = false`,
refused fail-closed naming `boatramp-firecracker`/`boatramp-vz`.

---

## 7. What this cut BUILDS (unambiguous + safe) vs. leaves DESIGN-ONLY

**BUILT:**

1. **This design note** — the primary deliverable.
2. **Sharpened `resolve_spawn_backend` Container refusal** — the generic "spawn backend not wired"
   is replaced for Container with a precise, reviewer-useful message naming the three blockers
   (own-binary rootfs reconciliation §1, the multi-fd pass §2b, the per-instance namespace/egress
   policy §5b) and pointing at this note. `is_wired(Container)` stays `false`; Vm unchanged. The
   fail-closed posture (no silent downgrade to OsProcess, no partial spawn) is preserved exactly.
3. **Unit test** asserting the sharpened Container refusal mentions the blockers, Vm stays refused,
   OsProcess stays wired.
4. **A `#[ignore]`d live-gate test** (`privsep_live.rs`) that forks `boatramp __root` against a
   valid composition whose one instance is pinned `substrate: container` and asserts the node
   **refuses fail-closed end-to-end** (the root exits non-zero with the substrate message; it never
   binds the listener, never partially spawns). Marker `PRIVSEP CONTAINER SUBSTRATE REFUSED OK`.
   **This gate inverts** to assert a real 200 + `PRIVSEP CONTAINER SUBSTRATE OK` when §1/§2b land —
   the test carries a header note saying so.
5. **CI wiring** — the `live-gate-privsep` job's pass-count grep is bumped and the new marker is
   grepped, so a silent skip/compile-out fails the merge.

**DESIGN-ONLY (flagged above, NOT built — needs owner + Security ratification):**

- §1 the rootfs model (Option A/B/C) — the load-bearing blocker.
- §2b the `SandboxPlan`/worker multi-fd extension (or, under Option C, the root-side
  unshare+dup — no `SandboxPlan` change).
- §4 the A/B env-target / worker-exit-propagation / PDEATHSIG-chain handling (byte-identical to
  OsProcess under Option C).
- §5b the per-instance cgroup/userns knobs (shape deferred).

**Recommended path forward (INPUT for the owner):** adopt **Option C** (unshare
mount+pid+ipc+uts+cgroup, no pivot_root, no net unless a backend needs egress, no userns in the
first cut; Landlock remains the FS wall). It preserves the Phase-1 model with the least new TCB,
needs **no change to the `boatramp-container` worker or `SandboxPlan`** (the root does the
`unshare` + cgroup-join itself and then the existing `spawn_wired_instance` `pre_exec` + the
unchanged per-capability profile install run exactly as today), and makes §2b/§4 byte-identical to
OsProcess. Under Option C the "reuses `boatramp-container`" framing means "reuses its
`unshare`/cgroup/seccomp primitives," which should be stated plainly to the owner.

**Backend-egress corner (applies to any option):** a `backend.*` instance confined to a fresh
**net** namespace with no veth cannot reach its Postgres/KV/blob backends. So either such instances
keep the host net namespace (don't unshare `CLONE_NEWNET`), or they get veth wiring (which drags
back the full backend networking machinery — an argument against containerizing backend instances
at all in the first cut). Listener/relay frontends need no egress (they bind via the root-passed
listener fd and relay inward over the socketpair), so they CAN take a net namespace. **This
per-instance namespace policy is part of §1/§5b and must be ratified.**

---

## 8. WHAT WAS BUILT — Option C wired (owner-approved) + Security flags

Owner approved **Option C**. The Container substrate is now a wired spawn backend. This section is
the authoritative record of the implementation; §1–§7 above are the reasoning that led here.

### 8.1 Exactly what the code does

- **`InstanceSubstrate::is_wired`** (`boatramp-types/src/privsep.rs`): now
  `matches!(self, OsProcess | Container)`. `Vm` stays `false` (its own kernel ⇒ the `local`
  socketpair cannot cross — §6; a vsock re-plumb is the next increment).
- **`resolve_spawn_backend`** (`boatramp/src/privsep.rs`): Container now returns `Ok` via the
  `is_wired()` fast-path (the old sharpened Container refusal is removed as dead code). `Vm` keeps a
  fail-closed refusal that now offers BOTH wired fallbacks (`OsProcess`/`Container`).
- **`spawn_wired_instance`** (`boatramp/src/privsep.rs`, the root's OWN fork+exec primitive, shared
  by the boot supervisor AND the per-tenant router): for a `spec.substrate == Container` child, the
  child's `pre_exec` first runs
  `unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP)`, THEN the
  byte-identical OsProcess sequence — the `(src→tgt)` `dup2` loop with `CLOEXEC` cleared, then
  `PR_SET_PDEATHSIG(SIGKILL)`. The socketpair + `SCM_RIGHTS` fd-pass, the `env_clear().envs(scrubbed)`
  (F11-B), `PR_SET_PDEATHSIG`, and the root's `try_wait` → `FailNodeClosed` supervision are
  **unchanged** (for an OsProcess child the container branch is a no-op, so that path is literally
  byte-identical). No change to `boatramp-container`'s `worker`, `SandboxPlan`, or the nested
  per-capability profile. An `unshare` failure ⇒ `pre_exec` returns `Err` ⇒ `spawn()` fails ⇒ the
  supervisor `kill_all`s + returns `Err` ⇒ node down (`FailNodeClosed`) — **never** a silent
  downgrade to an unconfined OS process.
- **Namespace self-check** (`verify_container_namespaces_unshared`, called from `run_instance`
  before the sandbox install): a Container instance reads `/proc/self/ns/{mnt,ipc,uts,cgroup}` and
  its parent's (`/proc/<getppid()>/ns/...`) and refuses to serve (`FailNodeClosed`) unless all four
  DIFFER. This makes "a Container instance served" **imply** "it was in fresh namespaces": it catches
  the one failure mode the spawner-side `unshare` cannot (a dispatch regression that spawns a
  Container spec WITHOUT the `unshare`). The live gate's 200 is the proof, exactly as the
  signer-unseal gate's 200 proves the unseal.
- **Deliberately NOT unshared:** `CLONE_NEWNET` (a `backend.*` instance keeps host-net egress to its
  DB/KV/blob — §5b/§egress corner) and `CLONE_NEWUSER` (no user namespace in the first cut — §5b).
- **No `pivot_root`, no rootfs:** the per-capability **Landlock** profile remains the FS wall
  (`CLONE_NEWNS` only gives a *copy* of the mount table; the Landlock grants resolve to the same
  inodes, so the FS confinement is unchanged). The own-exe execute-pin is unchanged (`current_exe()`
  still valid — no pivot), so the static-musl execute-pin the per-tenant router relies on still holds.

### 8.2 FLAGS for the Security review

1. **Root / `CAP_SYS_ADMIN` requirement (NEW operational precondition).** The simple model unshares
   WITHOUT a user namespace, so the root supervisor needs `CAP_SYS_ADMIN` for the `unshare` to
   succeed. This is the normal privsep posture (the root binds privileged listeners), but it is now a
   HARD precondition for `substrate: container`: on a node lacking it, the container instance
   fail-closes (correct, but operationally it means container substrate is root-only until a userns
   increment lands). The live gate runs the node under `sudo -n` to obtain it.
2. **PID-namespace simple-model semantic.** `unshare(CLONE_NEWPID)` does NOT move the CALLER into the
   new pid namespace — only its future children. So the `__instance` process itself keeps the root's
   pid namespace; the pid-ns isolation applies to any sub-processes it forks (e.g. a per-tenant
   router's children), not to the instance process. The self-check therefore asserts mnt/ipc/uts/
   cgroup (immediate) but NOT pid. A stricter model (fork a pid-ns init, as the container worker does)
   is a possible future increment; it was deliberately NOT done here to keep `FailNodeClosed`/
   PDEATHSIG/reaping byte-identical to OsProcess (the whole point of Option C).
3. **Net namespace shared (egress decision — as instructed).** `CLONE_NEWNET` is NOT unshared, so a
   `backend.*` instance keeps its path to Postgres/KV/blob and the already-connected client socket an
   SCM_RIGHTS splice hands it still works. Net isolation is therefore NOT provided by this cut; if it
   is ever added it must be opt-in and off by default (and it needs the veth/egress story in the
   egress corner above). Flagged as the main containment gap vs. a full container.
4. **Mount-namespace / Landlock interaction.** With `CLONE_NEWNS` but no `pivot_root` and no remount,
   the instance gets a copy of the host mount table; it mounts nothing (seccomp kills `mount`), and
   Landlock paths resolve identically. The live gate validates that the nested Landlock profile still
   reaches `Enforced` inside the unshared mount namespace. No propagation hardening (e.g. recursively
   `MS_PRIVATE`) is done — not needed for additive isolation, but noted.
5. **Self-check reads `/proc/<ppid>/ns/*`.** Needs ptrace-read (same-uid) access to the parent; holds
   because both run as the root supervisor's uid at that point (before the instance's sandbox drop).
   If a future increment adds a userns/uid remap, revisit this read.
6. **`per_tenant` + container interaction NOT exercised.** A `PerTenantTemplate` pinned
   `substrate: container` would fork per-tenant children from inside the unshared namespaces via the
   same `spawn_wired_instance`; the pid-ns semantic (#2) means those children WOULD get the new pid
   namespace. Not tested in this cut (the gate uses a static `core`); flagged as a follow-on to
   validate explicitly.

### 8.3 Tests + gate

- Unit: `resolve_spawn_backend_wires_os_process_and_container_and_refuses_vm` (boatramp) +
  `instance_substrate_defaults_to_os_process_and_round_trips_through_ron` (boatramp-types) assert
  `is_wired(Container)==true`, `is_wired(OsProcess)==true`, `is_wired(Vm)==false`, and the Vm refusal.
- Live gate: `privsep_container_substrate_serves_end_to_end` (was the fail-closed-refusal gate,
  inverted per the original §7 note) — serves a real 200 from a `substrate: container` `core`; marker
  `PRIVSEP CONTAINER SUBSTRATE OK`. CI `live-gate-privsep` grep + pass-count updated.
