# DESIGN — privsep Phase 5: node SELF-HOSTING

**Status: P5-0 + P5-1 + P5-2 + P5-3 (write-plane SURFACE + served mutation) + P5-4 (cross-instance
authorize relay + node-own wasm ENGINE stand-up self-validation) IMPLEMENTED on `feat/privsep`.**
The gateway reverse-proxy serve surface + the node-own-function routing + the persistent `wasmtime-cache`
grant are surfaced as P5-4 remainder (see §2 P5-4); the egress-decision (P5-5), the `is_wired` flip +
full Security pass (P5-6) follow.
P5-0 shipped the composition *vocabulary* (`[privsep].node_serve`, `NodeServeMode`) + a fail-closed
root *gate*. P5-1 added the authority-scoped app-router *seam*. **P5-2 WIRED that seam LIVE** on the
backend serve path for the READ data plane on the LIGHTWEIGHT substrates (`os-process` / `container`):
under `node_serve = node-self-host` a `backend.*` data-holder serves the node's own read plane through
the authority-scoped router (classify → route → a real control-plane KV read), replacing the Phase-1
`MinimalHandler` stub; the **VM data-holder stays REFUSED** (design §3a). **P5-3 (this cut) adds the
control-plane MUTATION SURFACE under the `backend.kv` sandbox**: a boot WRITE-plane self-validation
(`NodeDataPlane::validate_write_plane`) exercises the real control-plane store mutation path (durable
put + checkpoint + maintenance GC + read-back + durable delete) under the per-capability Landlock/seccomp
profile — the write/flush/compaction/GC/manifest object-store paths a READ never touches — and
fail-closes the node (FailNodeClosed) on any EACCES; the request classifier now DECOMPOSES a mutation
into its `{control.admin-api authorize, backend.kv write}` sub-ops (INFO-2) and the handler routes each
independently, failing the whole request closed if any is unsatisfiable (INFO-3 hard 5xx). The SERVED,
authorized client mutation (end-principal re-validation + the `control.admin-api`→crown-jewel relay)
stays fail-closed — the remaining P5-3 work. The remaining self-host surfaces — the SERVED mutation,
the gateway, the node-own handler engine, and any VM/net-ns data-reach — stay fail-closed per request
and are P5-3-serve..P5-5; `NodeServeMode::is_wired(NodeSelfHost)` stays `false` (it tracks the FULL
mode, flipped only at P5-6 after each increment's Security review). This note defines the target,
sequences the increments, and SURFACES — without deciding — the owner questions. It is the companion to
`DESIGN-privsep-phase3-container.md`, `DESIGN-privsep-phase3-vm-scoped.md`, and
`DESIGN-privsep-phase3-vm.md`.

Terminology note: "self-hosted" is overloaded in this codebase (the self-hosted-vs-Vercel product
framing; `--mode cluster` self-hosted cluster). This note means something narrower and internal:
**the node running its OWN serve path under the privsep composition.** The config spelling is
`node_serve = node-self-host`; the wired default is `node_serve = guest-workloads`.

---

## 0. Where we are today (the baseline this builds on)

When `[privsep]` is present, the root supervisor already composes and serves:

- `plan_root` runs the fail-closed screens + lints (secret-blind F1/F11-A, closure F7, sealed-signer,
  VM secret-blindness/scope S2, per-tenant policy), then `run_root_with_config` binds the privileged
  listeners, `fork`+`exec`s one `__instance` per static entry, wires `socketpair(2)` links, and runs
  the `FailNodeClosed` supervise loop. Three substrates are wired for the instance's process:
  `OsProcess`, `Container` (Option C — unshare mount/ipc/uts/cgroup, no `pivot_root`, Landlock is the
  FS wall, net ns shared), and the scoped `Vm` (a key-free static-parser frontend only).
- Each `__instance` installs its per-capability `Enforced` seccomp/Landlock profile, then
  `instance_serve::run` dispatches a ROLE from its held authority set:
  - a `listen.*` **frontend** accepts on the inherited listener fd and splices each accepted client fd
    to its backend over the local link (`SCM_RIGHTS`);
  - a **crown jewel** (`secrets.sealer` / `token.signer`) that the root designated authority-serve
    links for serves the **WS-E authority grammar** (`seal`/`unseal`/`mint_token`/… — results, never
    keys), re-validating each call's end-principal context;
  - a `token.signer` with a sealed source first UNLOCKS its key via the sealer over the link;
  - a **per-tenant template** (`exec.wasmtime`, `InstanceLifecycle::PerTenantTemplate`) is instantiated
    on demand by the router, scoped to one project, and serves guest workloads;
  - a plain **backend** (a client-fd link, no listener) receives client fds and serves each with the
    hand-rolled HTTP stack and a **`MinimalHandler` (a fixed 200)**.

That last line is the gap. The code says it plainly: *"the full authority-scoped app router is the
authority-serve follow-on"* (`instance_serve::serve_client_fd`, `run_backend`). Today a backend
instance proves the byte path but does NOT run the node's real control-plane/data-plane app. **Phase 5
is that follow-on: replace the stub with the node's own, authority-scoped serve path.**

So the honest framing: guest workloads (per-tenant wasm, scoped-VM parser frontends) and the crown-
jewel grammars ARE composed under privsep today. The **node's own serving** — admin API, gateway,
handler engine for the node's own functions, and the managed-DB/KV/blob data plane — is not; it is
the monolith's job, reached only in the non-privsep default, or stubbed in the composed path.

---

## 1. DEFINITION — what "self-hosting" concretely means

**Self-hosting = the node dogfoods the privsep composition for its OWN serve path.** Every request the
node serves for itself — a control-plane mutation, a gateway proxy hop, a site/media read, a handler
invocation, a managed-DB/KV/blob access — is served by an instance holding ONLY the authority that
request needs, over root-wired links, behind a per-capability `Enforced` wall, with any instance death
failing the node closed. The monolith path (one process holding `HostAuthority::ALL`) remains the
non-privsep default; self-hosting is the composed node serving the SAME product surface, split.

Concretely, Phase 5 replaces `MinimalHandler` with the **authority-scoped node app router**: each
instance runs the real serve pipeline, but constructs and reaches only the slice its held
`HostAuthority` set permits (the `MaterializationGate` already forecloses the rest by construction).

### 1.1 Classification of the node's OWN components

The axis is the existing A–E `AuthorityGroup` grouping. Phase 5 adds no new `HostAuthority`; it wires
the serve path onto the authorities that already name these surfaces.

**(R) The secret-blind ROOT — bootstrap + supervision only, NO app logic.**
The root stays exactly what it is: the TCB floor. It binds privileged listeners and passes the fds; it
`fork`+`exec`s instances and wires links; it runs the `FailNodeClosed` supervise loop and the
secret-blind per-tenant router dispatch (names only — `TenantScope`, never a secret). Under
self-hosting it gains NOTHING that serves app bytes, holds a key, or opens a pool. It does not run the
admin API, the gateway, the handler engine, or any backend. Its self-profile stays the networkless
`derive_root_profile` floor (`ROOT_NET_STRIP`). **Invariant: no node component "graduates" into the
root.** If a component cannot be split out of the root, it is not a Phase-5 candidate — it is a bug.

**(F) Key-free FRONTEND instances — group C `listen.*` (hold NO key).**
`listen.public-tls`, `listen.http-parse`, `listen.gateway`, `listen.mail`, `listen.overlay`,
`listen.s3ingress`, `listen.inbound-tcp`. These parse untrusted attacker bytes and forward typed
requests / splice client fds inward. They are the primary inversion target and already run as the
"frontend" role. Two notes specific to self-hosting:
- `listen.public-tls` materializes the live **cert private key** to terminate TLS — it is key-FREE of
  crown-jewel material but NOT of a serving secret. It stays walled from `listen.http-parse` (design
  §6) and is an authority-bearing frontend for cert purposes, not a pure parser.
- `listen.gateway` is the reverse-proxy ingress. As a frontend it parses and forwards; the proxy's
  upstream dial is an egress concern (see §3a).

**(A·auth) Crown-jewel AUTHORITY instances — group A (hold keys; serve RESULTS, never keys).**
`secrets.sealer`, `token.signer`, `image.signer`, `overlay.dial-signer`, `s3ingress.root`,
`cluster.join-signer`. Already served via the WS-E `privsep_authority` grammar: the frontend/app
relays a bounded `AuthorityCall` with a re-validated end-principal context + PoP; the response type
admits NO key-bearing variant. Self-hosting changes nothing structural here — it makes the node's own
app the *caller* of these grammars instead of the monolith reaching the key in-process.

**(B·auth) Data-holder AUTHORITY instances — group B `backend.*` (THE hard part).**
`backend.kv` (control-plane source of truth), `backend.sql` (control-plane + managed-DB + BYO pools),
`backend.blob` (object store), `backend.messaging` (bus). These hold creds and open pools, and the
node's real serving READS AND WRITES through them constantly (unlike the infrequent crown-jewel
grammars). Self-hosting must either (i) run the node's data-plane serve logic INSIDE each backend
instance and have frontends relay typed requests to it, or (ii) keep an app/control instance that
reaches the backends over mediated links. Either way the backend instance must reach its actual data
store across the isolation boundary — **the egress problem of §3a, the central owner decision.**

**(E·auth) Control-plane AUTHORITY instances — group E.**
`control.admin-api` (the `/api/*` MUTATION surface — publish, token mint-request, config set, tenancy
apply) and `acme.dns-control` (ACME account + DNS cred). `control.admin-api` is an authority instance
that drives mutations through the group-A/B authorities; it must itself be reached by a frontend and
must relay to the signer/backends rather than hold their keys.

**(D·exec) Execution AUTHORITY instances — group D.**
`exec.wasmtime` (the handler/JIT engine) and `exec.compute` (the compute-plane orchestrator /
per-tenant fork primitive). `exec.wasmtime` for GUEST workloads is already the per-tenant template
path. Self-hosting raises the question of the node's OWN functions (e.g. the dogfood console, if it is
served as a function vs. static assets) — are they a node-scoped `exec.wasmtime` instance, distinct
from the per-tenant templates? `exec.compute` stays the secret-blind orchestrator (it holds no keys;
"the thing that runs VMs holds no keys").

### 1.2 Summary table

| Node component (serve surface)        | Authority              | Phase-5 class        |
|---------------------------------------|------------------------|----------------------|
| listener binds, fork/exec, supervise  | (bootstrap only)       | **R** secret-blind root |
| per-tenant router dispatch (names)    | (bootstrap only)       | **R** secret-blind root |
| TLS terminate                         | `listen.public-tls`    | **F** frontend (cert key) |
| HTTP/1+2 parse                        | `listen.http-parse`    | **F** frontend (key-free) |
| gateway reverse-proxy ingress         | `listen.gateway`       | **F** frontend (+egress §3a) |
| mail / overlay / s3ingress / raw-tcp  | `listen.*`             | **F** frontend       |
| seal/unseal, mint token/cap/sig       | group A                | **A·auth** (WS-E grammar) |
| control-plane KV source of truth      | `backend.kv`           | **B·auth** data-holder (§3a) |
| SQL pools (control + managed + BYO)   | `backend.sql`          | **B·auth** data-holder (§3a) |
| object store                          | `backend.blob`         | **B·auth** data-holder (§3a) |
| messaging bus                         | `backend.messaging`    | **B·auth** data-holder (§3a) |
| `/api/*` mutation surface             | `control.admin-api`    | **E·auth** control   |
| ACME / DNS control                    | `acme.dns-control`     | **E·auth** control   |
| handler engine (node's own functions) | `exec.wasmtime`        | **D·exec** (§3 scoping Q) |
| compute orchestrator                  | `exec.compute`         | **D·exec** (secret-blind) |

---

## 2. INCREMENTS — smallest-first, buildable, each its own Security review

Each increment stands up on `feat/privsep`, release-ready and reviewable in isolation; none flips
`NodeServeMode::is_wired` for `NodeSelfHost` until the last. The ordering de-risks by serving the
LEAST-sensitive surfaces first and leaving the data-plane egress decision (§3a) until its own
increment, so it is never force-bundled with the cheaper wins.

**P5-0 (this cut) — vocabulary + fail-closed gate (DONE, SAFE-ONLY).**
`NodeServeMode { GuestWorkloads(default, wired), NodeSelfHost(not wired) }` on `PrivsepConfig`; the
root's `check_node_self_host_gate` refuses `NodeSelfHost` in `plan_root` before any spawn with the
`PRIVSEP_NODE_SELF_HOST_UNWIRED` marker; a pure unit test + an invertible `#[ignore]`d end-to-end gate.
No serve path, no `is_wired` flip. This is the seam every later increment grows from.

**P5-1 — the authority-scoped app router seam (no live flip).**
Define the typed seam that replaces `MinimalHandler`: a `NodeServeHandler` the instance constructs
from its `MaterializationGate`, routing only to the authorities it holds and relaying everything else
over the appropriate link (crown-jewel grammar, or a backend request). Unit-tested host-side; the
backend still serves the stub until P5-2 wires a real surface. Proves the router shape + the
"construct-only-what-you-hold" discipline without serving the node's real app.

**P5-2 — read-only data-plane on `backend.*`, Container/OsProcess substrate only. — IMPLEMENTED.**
The smallest real surface: serve the node's READ path (a site/media/static read that touches
`backend.kv`/`backend.blob`) from a `backend.*` instance, reached by the `listen.http-parse` frontend
over the splice. Confined by `substrate: container` (Option C) or `os-process`, where **the net ns is
SHARED**, so the backend reaches its store with no new crossing (this sidesteps §3a entirely for the
first real surface).

*What landed (code):*
- `instance_serve::run_backend` branches on `node_serve`: under `node-self-host` it builds a
  `NodeServeHandler` (the gate-derived `NodeServeRouter` + the node read plane) ONCE and serves every
  client fd through it — replacing `MinimalHandler` on the LIVE apply path; `guest-workloads` keeps the
  stub unchanged. Fail-closed stand-up: a read-plane open failure exits the instance → `FailNodeClosed`.
- `NodeServeHandler::serve` classifies each request (`classify_request_surface`: a safe GET/HEAD ⇒ the
  `backend.kv` READ surface, a mutating method ⇒ the `control.admin-api` write surface), makes the
  authority-scoped `NodeRoute` decision from the gate's held set + the reachability map derived LIVE
  from the link topology (`derive_node_reachability`), and EXECUTES it: a HELD data-plane READ surface
  is served from the read plane (`NodeReadPlane::Kv` — a real `domain/<host>` control-plane KV read);
  every other surface (a write, a crown-jewel / backend RELAY, or a REFUSE) fails closed with a 503,
  never a stubbed 200 (the "no silent downgrade" invariant).
- The root gate (`check_node_self_host_gate` → `check_node_self_host_read_plane`) ADMITS node-self-host
  for the P5-2 shape and REFUSES a `backend.*` data-holder on `substrate: vm`
  (`PrivsepError::NodeSelfHostVmDataHolder`, marker `PRIVSEP_NODE_SELF_HOST_VM_DATA_HOLDER_REFUSED`) —
  defence-in-depth beside the structural S2 `VmInstanceOutsideApprovedScope` scope lint (which fires
  first in `plan_root`) and `resolve_spawn_backend`'s VM-shape gate.

*Isolation (HIGH-1):* P5-2 adds NO new exec/fork path — the data-holder is the existing fork+exec'd
`__instance`, which already runs `set_process_undumpable()` (`PR_SET_DUMPABLE(0)`) at entry, before the
gate is built. The read plane + router run inside that already-hardened instance, so the HIGH-1
cross-instance `/proc/<pid>/mem` wall holds unchanged on every substrate P5-2 touches.

*Tests:* host-tested on the real `serve_connection` apply path with an in-memory KV (a seeded host ⇒
200, an unseeded host ⇒ 404, a write/relay/refuse ⇒ 503) + the gate admit/refuse + the reachability
derivation; live gates (lighthouse, `#[ignore]`d): `PRIVSEP NODE SELF-HOST READ-PLANE OK` (os-process
serve) + `PRIVSEP NODE SELF-HOST VM DATA-HOLDER REFUSED OK`. **The real control-plane KV opening +
reading under the derived per-capability Landlock profile is NOT yet validated live** (authored on
macOS) — it is the biggest P5-2 unknown (§5) and MUST pass the lighthouse live gate before any cut; an
`EPERM` on the pool open FailNodeCloses the node (the gate surfaces it). The **Container** substrate
read-plane serve is a flagged lighthouse follow-on: the substrate wiring is already proven by
`PRIVSEP CONTAINER SUBSTRATE OK` and the read-plane handler is substrate-independent (host-tested), so
only a Container re-run of gate B remains to confirm the KV opens under the container's Landlock FS wall.

**P5-3 — control-plane MUTATION. The WRITE SURFACE under the `backend.kv` sandbox is IMPLEMENTED; the
SERVED authorized mutation is the remaining work.**

*What landed (code):* the coherent first piece — the deploy/routing-store MUTATION path proven under
the `backend.kv` per-capability Landlock/seccomp profile.
- `NodeReadPlane` → `NodeDataPlane` (read + write), holding the one `backend.kv` control-plane
  `DeployStore` (no double-open). `NodeDataPlane::validate_write_plane` runs a REAL control-plane store
  mutation round-trip — `put_durable_checkpointed` ×2 (WAL write → memtable freeze to an L0 SST →
  manifest rewrite) + `maintenance_gc` (the `wal/`/`compacted/`/`manifest/`/`compactions/` list+delete)
  + read-back + `delete_checkpointed` — on a RESERVED, cleaned-up key (`_privsep/selfhost/writeplane-
  probe/<pid>`). This drives the write/flush/compaction/GC/manifest object-store paths a READ never
  touches, all under `<data_dir>/kv-slate` (the `backend.kv` rw grant). Run at `backend.kv`-holder
  stand-up BEFORE serving a byte, authenticated-by-construction (never on a client's behalf — it mirrors
  the signer's boot key self-test), bounded by the same fail-loud 30s timeout as the store open; a
  fail-closed EACCES returns `Err` → the instance exits → `FailNodeClosed`.
- `classify_request` now returns a `RequestPlan` DECOMPOSITION (INFO-2): a safe method is a single
  `backend.kv` read; a mutating method is a `ControlMutation { authorize: control.admin-api, write:
  backend.kv }`. `NodeServeHandler::serve_control_mutation` routes EACH sub-op independently and fails
  the WHOLE request closed (hard 503, INFO-3) if any is `Refuse` — never a partial serve of the held
  half.

*What remains (P5-3-serve):* the SERVED, authorized client mutation. A client PUT still fails closed:
serving it requires (a) the end-principal `AuthorityContext` + PoP re-validation (design §4 item 6) so a
frontend RCE cannot assert authority it cannot prove, and (b) the cross-instance `control.admin-api`→
group-A crown-jewel relay (verified context + PoP on every mint/sign). Both are the next increment. Plus
the fine-grained `/api/*` method/path → operation map (a mint/sign operation adds a crown-jewel sub-op
to the decomposition) and the other control-plane authority state (`backend.sql`/`backend.blob`/
`backend.messaging` mutations, `acme.dns-control`). Still Container/OsProcess (shared net).

**P5-4 — the gateway + node-own handler engine. The authorize relay + the node-own wasm ENGINE
stand-up are IMPLEMENTED; the gateway serve surface + the node-own-function routing remain.**

*What landed (P5-4-authorize):* the cross-instance control-plane authorize relay — a `backend.kv`
holder serves an authorized mutation by relaying the `rights_for` decision to a SPLIT
`control.admin-api` holder over a verified `ControlAuthorizeServe` grammar endpoint (the group-E
analog of the WS-E crown-jewel grammar). See the §2 P5-3 carry-forwards + the code.

*What landed (P5-4-proper — the node OWNS its wasm execution engine under the sandbox):* a node-self-host
instance holding `exec.wasmtime` SELF-VALIDATES its wasm engine at stand-up, UNDER its per-capability
seccomp/Landlock profile, BEFORE it holds the engine — the engine counterpart of the `backend.kv` boot
write-plane self-validation. `HandlerEngine::self_validate_stand_up` (boatramp-handlers) builds the
node's wasm engine (the SAME `build_engine` config the real handler engine uses) and COMPILES a trivial
embedded component — the cranelift codegen → executable-`mmap(PROT_EXEC)` path a read/write/stub serve
never exercises. `instance_serve::run` runs it (`run_node_exec_engine_self_validation`, a fail-loud 30s
bounded probe) for an `exec.wasmtime` holder under `node_serve = node-self-host`; a compile failure (a
killed JIT syscall, a Landlock wall its codegen trips) returns `Err` → the instance exits →
`FailNodeClosed`. The JIT `mmap`/`mprotect` syscalls are already in the un-gated seccomp baseline
(name-only, no `PROT_EXEC` arg filter) and the persisted compile cache is best-effort, so the compile
SHOULD pass — but that is a claim only a live run settles (a host test without the sandbox is a FALSE
GREEN); the live gate `privsep_node_self_host_exec_engine_serves_end_to_end` (marker `PRIVSEP NODE
SELF-HOST EXEC-ENGINE OK`) is the decisive proof. `is_wired(NodeSelfHost)` stays false (P5-6). A VM
`exec.wasmtime` holder is already refused (`resolve_spawn_backend` admits only a key-free static-parser
frontend — all-listener — on `vm`), so no new gate is needed.

*What remains (surfaced, NOT this cut):*
- **The node-own-function SERVE routing** — wiring the node's own functions to be SERVED by the
  validated engine (classify a function request → route to the held `exec.wasmtime` → invoke). This
  needs the §3 scoping owner decision first (which of the node's OWN surfaces are functions vs. static
  assets — the dogfood console is static assets today, not a function), so it is deliberately not built.
  This cut proves the engine STANDS UP under the sandbox; it does not yet serve a node-own function.
- **The persistent `wasmtime-cache` Landlock grant** — `backend_state_subdir(ExecWasmtime)` is `None`,
  so an `exec.wasmtime` instance is NOT granted `<data_dir>/wasmtime-cache` RW; the engine's persisted
  compile cache (executable native artifacts, `0o700`) therefore degrades to no-cache under the sandbox
  (cold cranelift compile each boot — a perf, not a correctness, gap, since the cache is best-effort).

  **The local compile cache's integrity model (corrected — it is NOT content-MAC'd).** An earlier
  draft of this bullet called the cache "MAC-gated on the AOT-deserialize path (`boatramp-server::aot`)."
  That conflated two DISTINCT artifact sources and is wrong. There are two deserialize paths, and only
  one is HMAC-gated:
  1. **The cluster-distributed AOT artifact path** (`boatramp-server::aot` → `hydrate_request_artifact`):
     a precompiled `Component` fetched from the SHARED blob store (`aot/<fingerprint>/<wasm-hash>`, which
     other principals can write) IS framed with an HMAC keyed by a cluster-shared secret and verified in
     constant time BEFORE `Component::deserialize`. The MAC exists precisely because that source is
     attacker-writable. This path does NOT touch the local on-disk `wasmtime-cache`.
  2. **The local on-disk compile cache** (`wasmtime::Cache`, `<data_dir>/wasmtime-cache`, written/read
     transparently by wasmtime during a cranelift compile — `boatramp-handlers::engine::build_persistent_cache`):
     has **NO cryptographic integrity**. Its entries are addressed by a content-HASH KEY of the compile
     inputs (the module bytes + the engine's compiler/version config — wasmtime's `ModuleCacheEntry` /
     `HashedEngineCompileEnv`), and the deserialize path validates only a wasmtime VERSION string + a
     compiler-config *compatibility* check (`ModuleVersionStrategy`, default = the wasmtime crate version;
     wasmtime 50 `engine/serialization.rs`). That is a **compatibility KEY, not a MAC over the cache
     contents**: wasmtime documents `Component::deserialize` as unsafe / trusted-input-only — a crafted
     *same-version* blob is "trivially … arbitrary code execution". The cache's only integrity defense
     today is filesystem: the dir is created `0o700` (so no OTHER local principal can plant a forged
     entry), which `build_persistent_cache` itself notes ("it is not content-MAC'd").

  **What this implies for P5-6 (why the grant must be EXCLUSIVE + node-own-WRITES-only).** Because the
  local cache is NOT integrity-protected, a POISONED cache entry = native-code execution on the next
  `deserialize` of that entry. So the grant cannot simply be "RW to the `exec.wasmtime` holder": the
  cache subtree must be Landlock-**EXCLUSIVE** to the node-own `exec.wasmtime` instance (disjoint from
  every OTHER instance's grants) and **writable ONLY by it** (every other instance ro or — preferably —
  none). A SHARED or attacker-writable cache would let a lower-authority instance plant an entry the
  node-own engine then loads as host code — a cache-poisoning → RCE path. This is exactly the blast the
  HMAC gate neutralizes for the cluster/blob source (path 1) but which has NO equivalent for the local
  cache (path 2); the Landlock exclusivity is what substitutes for the missing MAC. (It remains true that
  an `exec.wasmtime` instance already runs native code in-process, so RW to its OWN cache does not widen
  *its own* blast radius — the new risk is entirely about OTHER instances being able to write it.)

  **Safe groundwork landed on this sub-branch (`privsep-p5-6-preconds`) — grant stays refused.** The
  disjointness precondition is now locked in the composition layer without granting anything live:
  `boatramp_server::sandbox::NODE_OWN_EXEC_CACHE_SUBDIR` / `node_own_exec_cache_dir` name the reserved
  subtree (single source of truth, cross-referenced to `build_persistent_cache`), and
  `check_grant_disjointness` gained a fail-closed tripwire + `CompositionGrantError::BackendCollidesWithReservedExecCache`
  guaranteeing a backend's state subtree can NEVER collide with the reserved cache subtree (inert today —
  no backend maps to it — since the eventual exclusive RW grant is a sibling subtree that must not overlap
  any backend-state grant). This is pure/unit-tested and changes NO live grant; `is_wired(NodeSelfHost)`
  stays `false`.

  **What remains OWNER-GATED (cannot be cleanly separated from the flip — do NOT build silently).**
  Wiring the actual grant means threading `node_serve = node-self-host` + a node-own-vs-guest ROLE into
  the grant-derivation — adding `node_own_exec_cache_dir` to the node-own instance's `base_read_write`
  (`build_instance_sandbox_inputs`) and pre-creating it before the ruleset (mirroring `kv-slate` in
  `install_privsep_instance_profile`) — but ONLY for the node-own holder, never for a guest per-tenant
  `exec.wasmtime` template. The grant layer does NOT model that role today (`instance_backend_state_grants`
  keys on the held authority set alone; both node-own and guest exec holders hold exactly
  `{exec.wasmtime}`), and it interacts with an owner design decision — **do guest per-tenant `exec.wasmtime`
  templates get a persisted compile cache at all, and if so WHERE?** A cache SHARED across tenants is a
  cross-tenant cache-poisoning vector; a per-tenant cache multiplies the disjointness surface. Settling
  that + deciding which of the node's own surfaces are functions (the §2 node-own-serve-routing scoping)
  is a precondition to the grant. The grant itself is therefore part of the P5-6 flip (its own independent
  FS-trust Security review), not this safe-groundwork cut.
- **The gateway (`listen.gateway`) reverse-proxy serve surface** — `listen.gateway` has no dedicated
  bound listener fd yet (`instance_listener_addr` binds only `listen.public-tls`/`listen.http-parse`; the
  other listener binds are a documented follow-on), and the reverse-proxy's upstream DIAL is a real
  outbound-egress / SSRF surface (`proxy::dispatch_gateway` → `UpstreamClient::dial`, guarded by
  `gateway_addr_allowed_for` + a pinned, anti-rebind `resolve_target`) whose general case depends on the
  §3a egress owner decision. Its seccomp profile ALREADY permits outbound `connect()` (`needs_outbound`
  includes `ListenGateway`), so the syscall surface is open; the remaining work is binding the gateway
  listener fd + a node-self-host gateway serve surface (classify a proxy request → read the upstream
  route from `backend.kv` → dial under the SSRF gate). A NEW trust decision (what the node-own gateway
  dials), deliberately NOT made silently in this cut.

**P5-5 — the EGRESS decision for VM / net-namespaced backends (gated on §3a).**
Only after the owner settles §3a: if `backend.*` may run in a VM (or a net-namespaced container), wire
the chosen data-reach mechanism (a mediated data relay, a vsock proxy, or an explicit refusal that
keeps `backend.*` on shared-net substrates). This is the highest-risk increment and the one most
likely to need a live Linux test; it is deliberately last.

**P5-6 — flip `is_wired(NodeSelfHost)` + the full self-host Security pass.**
Only when P5-2..P5-5 are each reviewed and the composition closure lint has a self-host clause
(see §4). Flipping the arm and inverting the `#[ignore]`d gate from the refusal marker to a live serve
marker is the single mechanical change; the review gates the flip.

---

## 3. OWNER DECISIONS to surface (I am NOT deciding these)

### 3a. (THE BIG ONE) Should `backend.*` data-holders run as confined instances — and how do they reach their data across the isolation boundary?

The tension: a confined instance in a **fresh network namespace** cannot reach its DB/KV/blob — the
egress/networking problem. But the two wired substrates behave differently, and this is load-bearing:

- **`os-process` / `container` (Option C) SHARE the host net namespace** — deliberately, per
  `DESIGN-privsep-phase3-container.md` ("a `backend.*` instance keeps host-net egress; pid-ns is a
  deferred increment"). So for these substrates **there is no egress problem**: a `backend.sql`
  instance dials its Postgres/Tigris/NATS exactly as the monolith does. The containment is the
  per-capability Landlock/seccomp wall + the separate address space, NOT a network wall. **P5-2/P5-3
  can serve the node's real data plane with no new crossing.** This is why the increments front-load
  the shared-net substrates.
- **`vm` (own kernel, own network stack)** genuinely has the egress problem, and it is entangled with
  secret-blindness (§4): a VM-hosted `backend.*` reaching its store either needs its OWN egress (a
  guest network device — widening the VM's reach and attack surface) or a HOST-mediated data relay
  across the vsock. A host relay that carries DB rows / blob bytes / KEK-adjacent data risks routing
  sensitive bytes THROUGH the secret-blind root's relay — the exact Tier-1 violation the S2 VM
  secret-blindness lint (`check_vm_secret_blindness_closure`) already forbids for key material. The
  scoped VM first cut is key-free listener-only precisely to avoid this.

**Decisions for the owner:**
1. Do `backend.*` data-holders run as confined privsep instances under self-hosting **at all**, or
   does the node keep an un-split data plane (a single backend instance ≈ today's "core") while only
   the frontends / control / crown jewels split? (A partial self-host is a legitimate target.)
2. If they do split, is `backend.*` **restricted to shared-net substrates** (`os-process`/`container`)
   — i.e. `substrate: vm` on a `backend.*` stays refused, as it is today — or is a VM-hosted backend a
   goal? If a goal: which data-reach mechanism (guest-own egress vs. host-mediated relay), and how is
   secret-blindness preserved across it (§4)?
3. Is a **net-namespaced container** (a stricter Option than C, with its own net ns) ever wanted for
   `backend.*`? That reintroduces the egress problem on the container path too and would need the same
   data-reach answer as the VM.

My read (input only, owner decides): front-load shared-net substrates (§2 P5-2..P5-4); keep
`substrate: vm` on `backend.*` refused; treat VM/net-ns data-holders as a separate, later,
owner-gated increment (P5-5) rather than a Phase-5 precondition.

### 3b. Operational-model changes to ratify

- **Startup sequence / boot ordering.** Self-hosting makes the node's own serving depend on N
  instances standing up (and the signer unlocking) before the first request is served. Boot is
  slower and has more failure points; the dependency order (sealer → signer unlock → backends →
  control → frontends) must be defined. Acceptable?
- **Failure / restart semantics.** `FailNodeClosed` means ANY serving instance's death tears the whole
  node down — correct for containment, but for the node's OWN serving it means a crash in, say, the
  admin-API instance kills the data plane too. Is whole-node fail-closed the right blast policy for
  self-hosting, or should some node-own instances be individually restart-class (re-exec) without a
  full node teardown? (This interacts with crown-jewel policy, which must stay fail-closed.)
- **Resource cost.** One process per authority slice (plus per-tenant templates) multiplies RSS, fds,
  and scheduler load vs. the monolith. For small nodes this may be prohibitive. Is self-hosting an
  opt-in for large/multi-tenant nodes, with the monolith the default for small ones? (Consistent with
  the memory rule: posture — single- vs multi-tenant — not clustering, is the default axis.)
- **Observability.** Logs/metrics/traces now span instances over links; a request's trace crosses the
  splice and the authority-call relay. The operator-facing story (how a self-hosted node's health and
  a single request's path are observed) needs a decision — reuse the existing tracing spans across the
  link, or add a correlation id the frontend stamps and relays.
- **`control.admin-api` reachability.** Today the admin API is same-origin (the dogfood console).
  Splitting it changes how it is reached internally (a dedicated frontend? the public parser relays
  `/api/*` to it?). The owner owns this app-shaped decision.

---

## 4. SECURITY items to RATIFY at build time (non-negotiable; each increment's review gates on them)

1. **The root's secret-blindness MUST hold — including via any byte-relay.** No key material (KEK,
   signer key, overlay seed, HKDF root, cert key, or any sealed-then-unsealed plaintext) may be routed
   through the secret-blind root, its per-tenant router dispatch, or any host-side relay it supervises
   (the vsock `__vm-relay`, a future data relay). The S2 lint (`check_vm_secret_blindness_closure`)
   already forbids a key-bearing link crossing a VM boundary; a self-host data relay (§3a) must be
   proven under the SAME lint, extended to cover data-plane relays, or refused. The root's self-profile
   stays the networkless `ROOT_NET_STRIP` floor.
2. **Fail-closed on any instance death.** Every self-host serving instance is under `FailNodeClosed`;
   no degraded serve, no silent downgrade to the monolith or the stub. The P5-0 gate already refuses
   the unwired mode rather than serving from a stub — that posture holds for every increment.
3. **Landlock ABI floor.** Every self-host instance installs its per-capability profile and REFUSES to
   serve unless it reports `Enforced` (`enforce_privsep_status`), on the real ABI (`ABI::from(kernel)`
   — beware the `PartiallyEnforced`-on-newer-kernel trap, `DESIGN`/memory `landlock-abi-reporting`). A
   VM-hosted component additionally asserts the guest-kernel config guard (`CONFIG_SECURITY_LANDLOCK`,
   plus the `acpi=off` preconditions) and clears the `MIN_LANDLOCK_ABI` floor or refuses.
4. **Verify-before-boot for any VM-hosted node component.** A node component in a microVM reuses the
   scoped-VM verify-before-boot: the pinned `boatramp-vmlinux` artifact + the `CONFIG_IKCONFIG_PROC=y`
   kernel-config guard + the relay's positive readiness gate converting any boot degradation into a
   loud `FailNodeClosed`. No VM-hosted self-host component boots unverified.
5. **Materialization-by-construction stays the primary wall.** A self-host instance constructs ONLY
   the authority objects it holds (`MaterializationGate::ensure`); the authority-scoped app router must
   route through held authorities / links, never reach a dropped one. The composition-closure lint
   gains a self-host clause: under `node_serve = node-self-host` the union of instances' authorities
   must still equal `ALL`, no crown jewel co-resides a listener/exec/control surface, and (new) the
   node-own serve wiring reaches each backend only over a mediated link, never in-process in a frontend.
6. **End-principal re-validation for the node's own control plane.** The node's own `/api/*` mutations
   and crown-jewel calls carry the same verified `AuthorityContext` + per-call PoP the WS-E grammar
   requires; a frontend RCE cannot assert authority it cannot prove.

---

## 5. OPEN RISKS / unknowns (reasoned vs. needs a live test)

**Reasoned (design-level confidence, no live test needed to assert the shape):**
- The shared-net substrates (`os-process`/`container`) dissolve the egress problem for P5-2..P5-4 —
  this follows directly from Option C sharing the net ns (documented, code-confirmed). Confidence: high.
- No new `HostAuthority` is needed — the A–E vocabulary already names every node serve surface; Phase 5
  is wiring, not vocabulary. Confidence: high.
- The root gains no app logic; every node component splits OUT of the root. Confidence: high (it is an
  invariant, not a measurement — a component that cannot split is out of scope, not a root graduation).
- Whole-node `FailNodeClosed` is correct for containment but is a real availability tradeoff for the
  node's own serving — this is a design tension to resolve (§3b), not an unknown.

**Needs a live Linux / lighthouse test to confirm (do NOT claim without it — memory: "serve-proof of
ONE path is not the production path; reproduce, don't reason"):**
- Whether the node's REAL data-plane serve path actually runs under the derived per-capability
  seccomp/Landlock profile without a denied syscall the stub never exercised. The real app touches far
  more of libc / the pool drivers / TLS than `MinimalHandler`; the derived profiles may be too tight
  and only a live run on lighthouse will surface a fail-closed `EPERM`. This is the single biggest
  practical unknown.
- The resource cost (RSS/fd/scheduler) of a full self-host composition on a representative node —
  needs measurement, not estimation (the benchmark host is authoritative).
- Boot-time / cold-start latency of the full dependency chain (sealer → unlock → backends → control →
  frontends) under the sandbox — live only.
- For P5-5 (if pursued): whether any VM data-reach mechanism can carry data-plane bytes WITHOUT routing
  sensitive material through the root's relay, and whether the S2 lint can be extended to prove it.
  Entirely unproven; must be de-risked on lighthouse before any wiring, exactly as the scoped VM was
  (two wrong RCAs there were caught by TESTING, not asserting).
- Cross-instance observability (does a request's trace actually stitch across the splice + the
  authority-call relay) — needs a live run to confirm the spans correlate.

**Explicitly out of scope for this note:** the compute-plane `ComputeBackend`-trait generalization
(the owner decision that per-tenant spawning stays inside the secret-blind router via fork+exec; noted
in `privsep.rs` as "the compute-plane generalization is Phase 5"). That is a separate reading of
"Phase 5" and is NOT this note's node-self-hosting target; if the owner wants both under one phase
number, they are independent workstreams.

---

## 6. What the P5-0/P5-1/P5-2/P5-3 cuts ship

- **Vocabulary** (`boatramp-types/src/privsep.rs`, P5-0): `NodeServeMode { GuestWorkloads, NodeSelfHost }`
  with `tag()` / `is_wired()` / `is_node_self_host()` (mirrors `InstanceSubstrate`), and a
  `node_serve: NodeServeMode` field on `PrivsepConfig` (struct-level `#[serde(default)]` ⇒ every
  pre-Phase-5 config is byte-unchanged; default `GuestWorkloads`). `is_wired(NodeSelfHost)` stays
  `false` through P5-3 (it tracks the FULL mode — incl. the SERVED mutation; P5-6 flips it).
- **Gate** (`boatramp/src/privsep.rs`): `check_node_self_host_gate`, wired into `plan_root` (step 2d).
  `GuestWorkloads` is a no-op. `check_node_self_host_data_plane` (renamed from P5-2's
  `check_node_self_host_read_plane`) ADMITS node-self-host for the data-plane shape (P5-2 read + P5-3
  write) and REFUSES a `backend.*` data-holder on `substrate: vm` (`PrivsepError::NodeSelfHostVmDataHolder`,
  marker `NODE_SELF_HOST_VM_DATA_HOLDER_MARKER` = `"PRIVSEP_NODE_SELF_HOST_VM_DATA_HOLDER_REFUSED"`).
- **Serve path** (P5-1 seam → P5-2 read live → P5-3 write surface): `NodeServeRouter` / `NodeRoute` /
  `NodeServeHandler` / `NodeDataPlane` (read + `validate_write_plane`) / `RequestPlan` (the INFO-2
  mutation decomposition) + `run_backend`'s `node_serve` branch (which runs the boot write-plane
  self-validation). See §2 P5-2/P5-3.
- **Tests:** host unit/apply-path tests — `node_self_host_data_plane_admits_lightweight_and_refuses_vm_data_holder`,
  `p5_2_node_serve_handler_serves_a_held_read_on_the_live_apply_path`,
  `p5_2_node_serve_handler_fail_closes_write_relay_and_refuse` (now incl. the mutation decomposition),
  `p5_3_classify_request_decomposes_a_mutation_into_authorize_and_write`,
  `p5_3_write_plane_self_validation_round_trips_a_control_plane_mutation`,
  `p5_2_derive_node_reachability_maps_peer_authorities_over_links`, plus the P5-1 router tests; live
  gates (`tests/privsep_live.rs`, `#[ignore]`d) `privsep_node_self_host_read_plane_serves_end_to_end`
  (`PRIVSEP NODE SELF-HOST READ-PLANE OK`), `privsep_node_self_host_write_plane_serves_end_to_end`
  (`PRIVSEP NODE SELF-HOST WRITE-PLANE OK`) + `privsep_node_self_host_vm_data_holder_refused_end_to_end`
  (`PRIVSEP NODE SELF-HOST VM DATA-HOLDER REFUSED OK`); `ci.yml` bumped to 10 privsep-live tests.

**Still NOT wired (fail-closed, pending P5-3-serve..P5-6 + their Security reviews):** the SERVED
authorized control-plane mutation (end-principal re-validation + the `control.admin-api`→crown-jewel
relay), the gateway, the node-own handler engine, any VM/net-ns data-reach, and the full
`is_wired(NodeSelfHost)` flip. These are refused per request by the router (a 503), never served from a
stub. The `backend.kv` write SURFACE itself is proven under the sandbox by the boot write-plane
self-validation.
