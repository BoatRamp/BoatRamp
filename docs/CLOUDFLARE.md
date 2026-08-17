# boatramp on Cloudflare — mode design

> This is the **design rationale** for the Cloudflare deployment mode:
> boatramp on CF Containers, fronted by a thin edge Worker, with no
> Durable-Object coordinator fork. The `boatramp cloudflare` command deploys it
> **natively over the Cloudflare REST API** — no wrangler, nothing generated for
> the operator to run.

> **Platform boundary (validated live + against CF docs):** a multi-node Raft
> quorum is **not possible** on Cloudflare Containers — they scale to zero and
> have no container-to-container networking (all ingress is mediated by the owning
> Durable Object), so a majority of voting peers can't stay simultaneously running
> and exchange low-latency RPCs. So on Cloudflare boatramp runs as a **single
> durable instance**: a DO-singleton container with **all state in R2** (blobs
> over S3, control-plane metadata as a SlateDB store on the same bucket — SlateDB's
> single-writer manifest fencing matches the one-container-at-a-time DO model). A
> parked/replaced container restores its state from R2. The multi-node Raft cluster
> below is the **self-hosted / VM / orchestrator** story, where peers have real
> networking; the parts of this doc that describe a CF Raft quorum are the original
> design exploration, superseded by this boundary.

Cloudflare-hosted is the third deployment mode. The decision (superseding the
earlier Durable-Object-coordinator sketch): **CF-hosted runs the native boatramp
binary on Cloudflare Containers as a single durable instance**, fronted by a thin
edge **Worker**. There is **no separate coordinator** and no Durable-Object
coordinator fork — the container's own single writer coordinates, its state durable
in R2 — so the behavior contract and the operator UX are **identical** to a
self-hosted deploy, not forked. Containers run the boatramp binary
(tokio/axum/wasmtime) unchanged, so this is a *deployment/management* target, not a
runtime rewrite. (A multi-node Raft quorum is a self-hosted-only topology; it can't
run on CF Containers — see §4.)

> Why not a Workers/Durable-Object rewrite: it would split coordination behavior
> (a bespoke DO coordinator vs the native binary) and force a second implementation
> to build, test, and keep in conformance. Accepting a single writer (libsql is
> single-writer anyway) + the uniform UX makes "run our real binary on CF, state in
> R2" the simpler and more honest design. CF Containers run our real binary, so we
> don't need to become a Worker.

> Status: the cluster mechanism CF reuses is implemented and tested
> in-process / over localhost HTTP. The CF-specific layer — deployment/management
> tooling, the edge Worker, and the platform wiring (Container networking,
> always-on instances, durable volumes) — is built against the platform and
> validated live on Cloudflare.

---

## 1. Topology

```
            ┌───────────────────────── Cloudflare edge (every PoP) ──────────────────────────┐
  client ──▶│  Worker (Rust→Wasm, reuses boatramp_core::route): static-from-R2 + cache + TLS  │
            └───────────────┬───────────────────────────────────────────────────────────────┘
                            │ dynamic / handler requests
                 ┌──────────▼───────────────────────────────────────────────┐
                 │ boatramp Container (native binary) — one DURABLE instance  │
                 │   • a single scale-to-zero instance (the DO singleton)     │
                 │   • all durable state in R2; no peer networking or voting  │
                 │     quorum (a multi-node Raft cluster isn't possible on CF  │
                 │     Containers). A parked/replaced container restores from  │
                 │     R2. Coordinator = the single writer (LogMessaging).     │
                 └───────┬───────────────────┬──────────────────────────────┘
                         │                   │
                    R2 (blobs over the   D1 / libsql (sql)
                    S3 API + SlateDB KV)
```

| Concern | CF binding | boatramp seam (reused) |
| --- | --- | --- |
| Blobs / `Storage` | **R2** | the `s3` backend (S3-compatible) |
| Control-plane `KvStore` | a **SlateDB store on R2** (durable, single-writer) | the `slatedb` backend over an object store (`--kv-s3`) |
| Messaging coordinator | the **single instance** (`LogMessaging`) — the DO gives one container at a time | unchanged — no DO coordinator |
| `sql` binding | **D1** or libsql (per-site) | the engine-agnostic `SqlBackend` |
| Edge routing / static / cache / TLS | the **Worker** | static serving + host routing |

## 2. Global serving from a single durable writer

- **Edge everywhere:** the Worker runs in every PoP — global routing, cache, and
  static-from-R2 with no cold start. The serving fast path is genuinely global.
- **One durable writer:** dynamic/handler requests reach the single container
  instance, whose control-plane state is a strongly-consistent SlateDB store on R2
  and whose blobs are on R2 — so a scale-to-zero stop loses nothing. This matches
  libsql's single-writer model; control-plane writes are small + infrequent.
- **Not a multi-region Raft cluster.** The multi-region voting-quorum + learner
  design below is the **self-hosted / VM / orchestrator** story (real peer
  networking, always-on voters); it does not apply to Cloudflare Containers, where
  the durable single writer above is the architecture.

## 3. What's reused vs. CF-specific

**Reused wholesale (no CF variant):** consensus + `RaftKv` + persistent
stores + HTTP client-write forwarding + `RaftMessaging` (the messaging
coordinator) + the cross-node `StreamBus` + cron-via-`is_leader` + dynamic
membership + the cross-mode conformance suite. CF runs the *same* code, so it
passes the *same* `assert_conformance` battery.

**CF-specific (the build):**
- **Edge Worker** — routing, static-from-R2, cache, TLS; proxies dynamic/handler
  requests to the Container cluster.
- **Native deployment** — `boatramp cloudflare` drives the Cloudflare REST API
  directly (no wrangler): ensure R2/D1/KV, upload the edge Worker (its bindings +
  the Durable-Object migration), and create/reconcile the **container application**
  over the container ("cloudchamber") API — endpoints proven from wrangler's
  open-source client and ported into `boatramp-cloudflare::api`. The app is
  Durable-Object-backed + scale-to-zero (no separate rollout: create/modify sets the
  active version, and the next request provisions an instance from it). Same
  one-token, env-provided UX as the S3/GCS/Azure backends; the request shaping is
  unit-tested offline against the exact API shapes, and the whole flow is
  live-validated end-to-end. See `PLAN-native-cloudflare-deploy.md`.
- **Backend selection** — R2 for `Storage`, D1/libsql for `sql`; both already
  exist behind the trait seams.

## 4. Platform specifics — verified (why CF is single-instance)

These were the open questions for a multi-node CF cluster. Verified against
Cloudflare's docs, they are exactly why a CF Raft quorum **isn't possible**, so
CF is the durable single writer above:

- **No always-on Containers.** CF Containers scale to zero and Cloudflare "does
  not guarantee that any instance will run for any set period of time" — so a
  majority of voting members can't be kept simultaneously running. A Raft quorum
  needs that; the single durable instance doesn't.
- **No inter-Container networking.** All ingress to a container is mediated by its
  owning Durable Object (`getTcpPort().fetch()`); one container can't dial
  another. Routing Raft RPCs DO→DO would add cold-start latency incompatible with
  consensus election timeouts — Cloudflare themselves moved off Raft for their WAN
  for this reason.
- **Durable state is R2, not a per-node Raft log** — a SlateDB store on R2 for the
  control plane (`--kv-s3`) + R2 blobs; a parked/replaced container restores from
  it.
- **Container lifecycle** is managed by a per-instance Durable Object (the CF
  Containers model); that DO is *infrastructure*, not a boatramp coordinator, and
  its one-container-at-a-time guarantee is what makes SlateDB's single-writer
  fencing correct.

## 5. TLS on CF

The edge Worker terminates TLS with **Cloudflare-managed certificates** (free,
automatic for domains on CF), so cluster-managed certs
are primarily for the **self-hosted** cluster. At the UX level both are uniform:
the operator declares domains; the environment provides the certs.

## 6. Cache coherence on CF (the no-consensus deployment)

If a CF deployment runs the **shared-store** topology (stateless Containers over
one Cloudflare KV, rather than the Raft-on-Containers mode), config coherence
uses the cross-mode invalidation mechanism: each Container
fronts CF KV with a `CachedKv`, the changelog gives targeted poll-based
invalidation, and content-addressed `SiteConfig` keeps the surface to
pointers. CF KV's own propagation latency is the poll floor.

The **real-time upgrade** is push: boatramp exposes the sink already —
`POST /api/cache/invalidate {keys:[…]}` on each Container drops just those keys
(empty body = full flush). The **CF-specific delivery** is a
**Durable Object** (or **Queue**) that the writer notifies on a control-plane
write and that fans the changed keys out to every Container's
`/api/cache/invalidate`. That `CacheCoordinator` Durable Object is **Rust → Wasm**
(`workers-rs`) in the `boatramp cloudflare` artifacts — like the edge Worker
itself, boatramp is Wasm-first, so the edge runs Wasm, not hand-written JS (the
only JS is the bootstrap shim `worker-build` auto-generates). It's validated live
on the platform. (The Raft-on-Containers mode needs none of this — replication
keeps every node current.)
