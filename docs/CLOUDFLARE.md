# boatramp on Cloudflare — mode design

> This is the **design rationale** for the Cloudflare deployment mode:
> boatramp's cluster mode on CF Containers, fronted by a thin edge Worker, with
> no Durable-Object coordinator fork. The `boatramp cloudflare` command
> generates the deployment.

Cloudflare-hosted is the third deployment mode. The
decision (superseding the earlier Durable-Object-coordinator sketch): **CF-hosted
is boatramp's own cluster mode running on Cloudflare Containers**, fronted by a
thin edge **Worker**. There is **no separate coordinator** — the single-writer
coordinator is the **Raft leader** on every multi-node mode (self-hosted cluster
*and* CF), so the behavior contract and the operator UX are **identical**, not
forked. Containers run the native boatramp binary (tokio/axum/wasmtime) unchanged,
so this is a *deployment/management* target, not a runtime rewrite.

> Why not a Workers/Durable-Object rewrite: it would split coordination behavior
> (DO single-writer vs Raft leader) and force a second coordinator implementation
> to build, test, and keep in conformance. Uniform UX + accepting single-writer
> (libsql is single-writer anyway) makes "cluster mode, hosted on CF" the simpler
> and more honest design. CF Containers run our real binary, so we don't need to
> become a Worker.

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
                 │ boatramp Containers (native binary) — one Raft cluster     │
                 │   • voting quorum (3–5) in a primary region               │
                 │   • learner instances in other regions: local reads,      │
                 │     forward writes to the leader                          │
                 │   coordinator = Raft leader (RaftMessaging, cron via       │
                 │   is_leader) — identical to self-hosted cluster           │
                 └───────┬───────────────────┬───────────────────┬──────────┘
                         │                   │                   │
                      R2 (blobs)       D1 / libsql (sql)    durable volume / R2
                                                            (per-node Raft store)
```

| Concern | CF binding | boatramp seam (reused) |
| --- | --- | --- |
| Blobs / `Storage` | **R2** | the `s3` backend (S3-compatible) |
| Control-plane `KvStore` | the **replicated Raft state** (`RaftKv`) on the Containers | unchanged |
| Messaging coordinator | the **Raft leader** (`RaftMessaging`) | unchanged — no DO |
| `sql` binding | **D1** or libsql (per-site) | the engine-agnostic `SqlBackend` |
| Per-node Raft log/state | Container **durable volume** (or R2-backed) | `persist::PersistentLogStore` |
| Edge routing / static / cache / TLS | the **Worker** | static serving + host routing |

## 2. Why this exploits multi-region (under single-writer)

- **Edge everywhere:** the Worker runs in every PoP — global routing, cache, and
  static-from-R2 with no cold start. The serving fast path is genuinely global.
- **Local reads everywhere:** far-region Containers join as Raft **learners**
  (replicate the log, serve reads from local applied state, don't vote), so reads
  are fast in every region while the voting quorum stays in one low-latency
  region. boatramp already has this (`raft::add_voter` + openraft learners +
  `RaftKv` reads-from-local-applied).
- **Writes** funnel to the leader — accepted, and consistent with libsql's
  single-writer model. Writes are small, infrequent control-plane / claim ops,
  so the occasional cross-region write hop is cheap.

## 3. What's reused vs. CF-specific

**Reused wholesale (no CF variant):** consensus + `RaftKv` + persistent
stores + HTTP client-write forwarding + `RaftMessaging` (the messaging
coordinator) + the cross-node `StreamBus` + cron-via-`is_leader` + dynamic
membership + the cross-mode conformance suite. CF runs the *same* code, so it
passes the *same* `assert_conformance` battery.

**CF-specific (the build):**
- **Edge Worker** — routing, static-from-R2, cache, TLS; proxies dynamic/handler
  requests to the Container cluster.
- **Deployment/management** — `boatramp deploy --target cloudflare`: build the
  container image, generate the wrangler config (Container + lifecycle DO +
  R2/D1/KV bindings + the Worker) and the `[cluster]` topology, push, apply.
  Uniform UX with the other deploy targets; live CF API calls are exercised
  against the platform, and image + config generation is unit-testable in isolation.
- **Backend selection** — R2 for `Storage`, D1/libsql for `sql`; both already
  exist behind the trait seams.

## 4. Platform specifics to verify (designed for, not guessed)

- **Always-on Containers** for Raft voters (no scale-to-zero for members);
  learners may be more elastic.
- **Inter-Container networking** for the Raft HTTP mesh. The transport is
  abstracted (`RaftNetworkFactory` / `HttpForwarder`), so if direct
  container-to-container HTTP isn't available, the mesh routes via CF service
  bindings or a DO relay — a transport swap, not an architecture change.
- **Durable per-node Raft store** — a Container persistent volume, or back
  `PersistentLogStore` with R2/D1.
- **Container lifecycle** is managed by a per-instance Durable Object (the CF
  Containers model); that DO is *infrastructure*, not a boatramp coordinator.

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
