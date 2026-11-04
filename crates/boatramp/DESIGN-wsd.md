# WS-D — Finding-2 authority de-coupling (the public parser holds the least authority)

Status: DESIGN + implementation (privsep Phase-1/3/4, `feat/privsep`). TCB-critical — this is a
privilege-separation boundary, gated by its own Security review before it merges to the privsep
release. Builds on `../../../boatramp-roadmap/plans/PLAN-privsep-phase1.md` (the vocabulary §1, the
feature-link §3, the closure lint §5) and `PLAN-privsep-fabric-composition.md` (§caveat 1, the
"axes cover each other" insight).

## The finding (owner decision 2026-11-03, Phase-4 WS-C Security review, Finding-2)

The most-exposed **public-parser** instance (`listen.http-parse` — the hand-rolled h2/h1 parser, the
fuzzed surface, the Phase-3 inversion target) must hold **NEITHER `exec.compute`** (spawn / fork+execve
of compute workloads) **NOR control-plane-KV (`backend.kv` / kv-slate) rw**. A **separate non-public
backend instance** holds spawn + KV, reached by the parser over a **narrow link**. Rationale (least
privilege): a parser RCE in today's co-located router can still fork the own pinned binary + rw the
whole control-plane KV (site config, deploy manifests, tokens-at-rest, sealed-cred ciphertext). The
most-exposed component must hold the least authority.

## Where the co-location lives today (the target)

Two shapes hold a public parser:

1. **The plain splice frontend** (`run_frontend` → `run_backend`): the `listen.*` frontend accepts and
   splices raw client fds to a backend. In the live gate `frontend`-inversion composition the parser
   (`listen.public-tls` + `listen.http-parse` + `exec.wasmtime`) holds no `exec.compute` and no
   `backend.kv` — it **already satisfies Finding-2**. (The `exec.wasmtime` on it is the Phase-3
   inverted-frontend shape, not a spawn authority; the finding names `exec.compute` and `backend.kv`.)

2. **The per-tenant router** (`run_per_tenant_frontend`): holds `listen.public-tls` + `listen.http-parse`
   **+ `backend.kv`** (to resolve Host→project against the control-plane `DeployStore`) **+ `exec.compute`**
   (to fork a per-tenant `exec.wasmtime` child via the root's own fork+exec primitive). **This is the
   co-located router Finding-2 targets** — a parser RCE here forks arbitrary workloads and rw's the
   whole control-plane KV. This is the one WS-D must invert.

## The authority split

The per-tenant router splits along the authority line into two instances wired over one `local` link:

- **Parser instance** — `{listen.public-tls, listen.http-parse}`. Public: binds nothing (the root
  binds + fd-passes the listener), accepts client connections, peeks the `Host` (its job as the
  http-parse holder — a bounded `MSG_PEEK` that consumes nothing), and **forwards each accepted client
  fd + the peeked Host string inward** to the supervisor over the parser→supervisor link. It holds
  **NO `exec.compute`, NO `backend.kv`** — it cannot fork and cannot open the KV. Its derived profile
  **kills `execve`/`execveat`/`fork`/`vfork`** (no `exec.compute`) and **does not grant the `kv-slate`
  FS subtree** (no `backend.kv`) — the wall under the lint.

- **Supervisor instance** — `{backend.kv, exec.compute}`. Non-public: binds no listener, parses **no
  raw client bytes**. It receives `(client_fd, host-head)` over the parser link, resolves the
  **host-head string** → project against the control-plane KV (`backend.kv`), instantiates / wakes the
  per-tenant `exec.wasmtime` child (`exec.compute` — the root's own fork+exec, scale-to-zero pool),
  and relays the client fd onward to that child. It owns all the fail-closed routing policy
  (unresolved/wildcard/foreign host → refuse; no fallback tenant). Its profile grants fork+execve
  (execute-pinned to its own binary only — no ELF-drop-then-exec, even on the writable `kv-slate`) and
  the `kv-slate` rw subtree.

- **Per-tenant child** — `{exec.wasmtime}`, `lifecycle: PerTenantTemplate`, one isolated process per
  project (unchanged from Phase 4). It does the **full HTTP parse + serve** on the relayed client fd,
  scoped by its unforgeable wired identity.

```
client ──TCP──> [parser: listen.*]            (accept + MSG_PEEK Host; no KV, no fork)
                      │  send_client_conn(client_fd, head = host)      SCM_RIGHTS, hop 1
                      ▼
                [supervisor: backend.kv + exec.compute]   (resolve host→project via KV; fork/pool child)
                      │  relay_client(client_fd, head = project)       SCM_RIGHTS, hop 2
                      ▼
                [per-tenant child: exec.wasmtime]          (full HTTP parse + serve, scope-keyed)
                      └── response streams back over the client socket it now holds
```

## The narrow link protocol

No new typed grammar is introduced for this hop. The parser→supervisor link **reuses the existing
`local` client-fd splice** (`LinkEndpoint::send_client_conn(fd, head)` / `recv_client_conn()` —
`SCM_RIGHTS`, unidirectional frontend→backend, F5: the received fd confers no authority). The narrowing
is in what rides it:

- **The only fd that crosses is an accepted client connection** (F5), parser→supervisor→child. No link
  fd, listener fd, or key fd ever crosses (invariant 8).
- **The head is the peeked `Host` string** (bounded by `MAX_HEAD_LEN`). It is the parser's sole
  routing *input* — it never selects a tenant directly. The supervisor **re-resolves** it against the
  authoritative KV (`DeployStore::resolve_site_by_host`) and applies the same fail-closed policy the
  monolith/router does. The per-tenant child additionally cross-checks the routing head against its
  own wired identity (defence-in-depth; the wired identity stays authoritative).

Why a Host string and not a raw-byte re-peek on the supervisor: the supervisor holds `backend.kv` +
`exec.compute`, so it must touch **no raw untrusted client bytes** — otherwise it is itself "a parser
with spawn+KV", re-introducing exactly what the finding forbids. The parser (the http-parse holder)
owns the only untrusted-byte parse (the bounded Host peek); the supervisor consumes only the resulting
string (used as a KV lookup key) and the opaque client fd it passes onward.

Why trusting the parser-supplied Host is safe: a parser RCE can set the head to any value → the
connection reaches whatever tenant that Host maps to. That is not a privilege escalation — any client
can already open a connection with `Host: <that-tenant>`. The connection carries the client's own
bytes; the per-tenant child serves under its own wired identity; no cross-tenant data is reachable.
The supervisor never forks or KV-writes on the parser's behalf beyond the normal resolve/instantiate a
real client would trigger.

## The structural guarantee (the lint)

`check_composition_closure` gains a fail-closed refusal (run in the root, before any spawn): an
instance holding **`listen.http-parse`** must hold **neither `exec.compute` nor `backend.kv`**
(`CompositionViolation::PublicParserWithSpawnOrControlKv`). This makes Finding-2 a boot-time-provable,
restart-class invariant — no on-disk composition can put the public parser in the same address space
as spawn or the control-plane KV. Together with the per-capability profile (execve killed + no kv-slate
grant for a parser), the containment is structural, not conventional: a parser RCE provably cannot fork
or rw the KV.

## Profile (already built; nailed down by a test)

The per-capability derivation (`boatramp_server::sandbox`) already enforces the wall and is unchanged
by WS-D: a non-`exec.compute` instance kills `execve`/`execveat`/`fork`/`vfork`
(`derive_seccomp_killlist`); a non-`backend.kv` instance gets no `kv-slate` grant
(`backend_state_subdir` / `instance_backend_state_grants`); and an `exec.compute` holder's Landlock
execute-pin covers only its own binary, never the writable `kv-slate`. WS-D adds a focused test nailing
Finding-2's exact property for a `{listen.http-parse}` instance.

## Open decisions / flags for the owner + Security review

1. **Lint scope — named parser vs all untrusted-byte listeners.** Implemented for the finding's exact
   target, `listen.http-parse`. The same RCE argument applies to the other group-C parsers
   (`listen.mail`, `listen.overlay`, `listen.gateway`, …): the design calls them "same character." The
   F8 tier already *warns* on `backend.* × listen.*`. **Decision needed:** promote the hard refusal to
   all group-C listeners (not just http-parse), and/or widen the forbidden-partner set beyond
   `{exec.compute, backend.kv}` to all `backend.*` / `exec.wasmtime`. NB `listen.http-parse ×
   exec.wasmtime` must stay allowed — that is the legitimate Phase-3 inverted frontend.

2. **Host-head trust (parser → supervisor).** Chosen: the parser peeks + supplies the Host string; the
   supervisor re-resolves it authoritatively against the KV. Alternative considered: the supervisor
   re-peeks the Host from the received fd (routing derived from real client bytes, not the parser's
   claim) — rejected because it gives the KV+spawn instance a raw-byte parse surface, contradicting the
   finding. The residual is that a parser RCE can mis-state the Host (argued harmless above). Security
   to ratify.

3. **Two SCM_RIGHTS hops on the per-tenant hot path.** The split adds one fd-pass hop
   (parser→supervisor) beyond the pre-split router→child single hop. All hops are `local` socketpair
   passes (no crypto, no net stack), but this is a real hot-path delta the owner's measurement-gating
   (PLAN §6.2 / bench-host-divergence) should quantify before Phase-3's substrate pick.

4. **Full Phase-3 typed-inward inversion (NOT in this cut).** This cut keeps the FULL hand-rolled HTTP
   parse in the per-tenant child / splice backend (raw-fd splice). The deeper Phase-3 inversion — the
   `listen.http-parse` instance parses and forwards a *typed request* so that **no** key/spawn/KV
   holder ever sees raw untrusted bytes — is the remaining work. Finding-2's lint guarantees the
   *capability* split now; the per-tenant child still runs the full parser, but it holds only
   `exec.wasmtime` for ONE tenant (contained by Phase 4). Flagged so the reviewer does not read the lint
   as more than it is.

5. **Supervisor = `{backend.kv, exec.compute}` as one instance.** Kept together (one "non-public
   backend"). A further split (KV on one instance, spawn on another, the parser/supervisor asking each
   over separate links) is possible but not required by the finding; it would add hops. Flagged.

6. **Frontend `bind`/`listen` seccomp tightening (pre-existing, tracked).** The parser's derived
   profile still grants `bind`/`listen` (via `needs_inbound`) though the root binds the listener and
   passes the fd. Tightening the parser to deny `bind` is a tracked Phase-1 follow-on (PLAN Round-5),
   orthogonal to Finding-2 (which is about `execve` + the KV subtree, both already denied on the
   parser).

## Live-gate re-wiring

- `privsep_two_instance` (#1) and `privsep_sealer_signer_unseal` (#2): the `edge` parser held
  `exec.compute`; moved off it (a parked `compute`/`core` instance hosts it) so the parser is
  lint-clean.
- `privsep_frontend_inversion` (#3): already compliant — unchanged.
- `privsep_per_tenant` (#4): re-wired to the split topology (`parser` + `supervisor` + `tenant-wasm` +
  `core` + `aux`), the serving per-tenant inversion.

The Linux `live gate (privsep)` job (lighthouse / CI, musl-static) is the final validation of the
forked+sandboxed topology, as for every privsep live gate; the merge-gate build/clippy/fmt + the
host-testable routing/link/lint unit tests run everywhere.
