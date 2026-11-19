# DESIGN — privsep Phase 5: node SELF-HOSTING

**Status: DESIGN-FIRST. Nothing in this note is wired. Self-hosting is REFUSED, fail-closed.**
This cut ships only the composition *vocabulary* (`[privsep].node_serve`, `NodeServeMode`) and a
fail-closed *gate* that refuses it in the root before any spawn, plus an invertible `#[ignore]`d
end-to-end gate. The self-host serve path itself is the Phase-5 workstream and lands only after its
own Security review. This note defines the target, sequences the increments, and SURFACES — without
deciding — the owner questions. It is the companion to `DESIGN-privsep-phase3-container.md`,
`DESIGN-privsep-phase3-vm-scoped.md`, and `DESIGN-privsep-phase3-vm.md`.

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

**P5-2 — read-only data-plane on `backend.*`, Container/OsProcess substrate only.**
The smallest real surface: serve the node's READ path (a site/media/static read that touches
`backend.kv`/`backend.blob`) from a `backend.*` instance, reached by the `listen.http-parse` frontend
over the splice, with the backend scoping every access by the request's verified principal. Confined
by `substrate: container` (Option C) or `os-process`, where **the net ns is SHARED**, so the backend
reaches its store with no new crossing (this sidesteps §3a entirely for the first real surface). Live
gate on lighthouse: a real read served end-to-end through the composed, confined node.

**P5-3 — control-plane MUTATION on `control.admin-api` + the crown-jewel grammars.**
Wire `/api/*` mutations: the frontend relays to `control.admin-api`, which relays mint/sign to the
group-A grammars (already built) and writes through `backend.*`. This exercises the cross-instance
authorization fully (verified context + PoP on every crown-jewel call) for the node's own control
plane. Still Container/OsProcess (shared net).

**P5-4 — the gateway + node-own handler engine.**
`listen.gateway` as a self-hosted frontend (its upstream dial is the egress question, §3a) and the
node's own `exec.wasmtime` functions (resolve the §3 scoping question first). Sequenced here because
both are heavier and one (gateway egress) depends on §3a's answer.

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

## 6. What THIS cut ships (safe-only scaffolding)

- **Vocabulary** (`boatramp-types/src/privsep.rs`): `NodeServeMode { GuestWorkloads, NodeSelfHost }`
  with `tag()` / `is_wired()` / `is_node_self_host()` (mirrors `InstanceSubstrate`), and a
  `node_serve: NodeServeMode` field on `PrivsepConfig` (struct-level `#[serde(default)]` ⇒ every
  pre-Phase-5 config is byte-unchanged; default `GuestWorkloads`).
- **Fail-closed gate** (`boatramp/src/privsep.rs`): `NODE_SELF_HOST_UNWIRED_MARKER`
  (`"PRIVSEP_NODE_SELF_HOST_UNWIRED"`), a pure `check_node_self_host_gate`, a new
  `PrivsepError::NodeSelfHostUnwired` variant carrying the marker, and a call wired into `plan_root`
  (step 2d) so the root refuses `node-self-host` BEFORE any spawn. `GuestWorkloads` is a no-op — no
  running composition changes.
- **Tests:** a pure host-testable unit test
  (`node_self_host_mode_is_refused_fail_closed_before_any_spawn_spec`) asserting the default authorizes
  and `NodeSelfHost` refuses end-to-end through `plan_root` with the marker; and an invertible
  `#[ignore]`d live gate (`privsep_node_self_host_refuses_fail_closed_end_to_end`, in
  `tests/privsep_live.rs`) that forks the real `__root` on an otherwise-valid composition selecting
  `node_serve: NodeSelfHost`, asserts it refuses + exits with the marker + never serves, and prints
  `PRIVSEP NODE SELF-HOST REFUSED OK` for the CI gate. When Phase 5 lands, this gate flips to a serve
  gate (the fixture is already the serving-gate shape) and `is_wired(NodeSelfHost)` flips — one
  mechanical inversion point.

**Not shipped (by design):** any serve path, any `is_wired` flip, any change to an existing go-live
gate or substrate arm. Self-hosting stays refused, fail-closed, pending the Phase-5 workstream and its
Security review.
