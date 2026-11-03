# The control-plane KV stack (architecture)

boatramp keeps **blobs** (file contents) in a streaming `Storage` backend and
all **control-plane metadata** (manifests, current pointers, site config,
tokens, certs, domain-verifications, messaging, the Raft log+state) in a
`KvStore`. This note puts the KV layering in order, because one small trait
(`KvStore`) deliberately plays **three different roles**, and there are **two
coherent topologies** that compose them differently.

## 1. One trait, three roles

`KvStore` is intentionally tiny (`get`/`put`/`delete`/`list_prefix`/
`write_batch` + the `invalidate_cache` hook). Its implementors fall into three
layers:

| Role | Implementors | What it is |
| --- | --- | --- |
| **Storage** (terminal, durable) | `SlateKv` (SlateDB over object_store: local FS / S3 / R2 / GCS), `CloudflareKv`, `MemoryKv` | Where the bytes actually rest. |
| **Consensus frontend** | `RaftKv` | Turns writes into replicated Raft log entries; serves reads from each node's **local applied state**. Persists its log + applied state to a **Storage** backend (per node). |
| **Caching decorator** | `CachedKv` | A write-through LRU in front of any `KvStore`. |

They compose: `CachedKv(SlateKv)`, or `RaftKv` whose `PersistentLogStore` /
`PersistentStateMachine` sit on a `SlateKv` (or any `Arc<dyn KvStore>` —
`CloudflareKv` included).

## 2. Two topologies (you pick one — they are not layered together)

### A. Consensus (`RaftKv`)
Control-plane writes go to the Raft leader, are committed to the replicated log,
and **applied to every node's state machine**; reads come from the node's local
applied state. This is **cluster mode** and the **Cloudflare-Containers** mode.

- Each node keeps its **own** durable Raft store. **This store is NOT shared** —
  sharing a Raft log across nodes breaks Raft. (The store is per-node; only the
  *blob* `Storage`, e.g. S3/R2, is shared.)
- No cache-staleness, no `SIGHUP`: `RaftKv` reads local applied state with no LRU
  in front, and replication keeps that state current.

### B. Shared-store / no-consensus (`CachedKv`)
One backend is the source of truth and coherence is **the store's** job, not a
consensus layer. N stateless boatramp processes each front it with a local
`CachedKv` LRU; blobs are shared too.

- The shared store is something already replicated/consistent on its own —
  **Cloudflare KV**, or a **SlateDB-on-R2/S3** that several processes open.
- A write by one process isn't visible to another until its LRU evicts —
  **`SIGHUP`** (`KvStore::invalidate_cache`) forces the re-read.
- **Single-node on local disk is just this topology with one process** and a
  local `SlateKv`; the cache never goes stale because nothing else writes.

## 3. How the frontend is selected today

Purely by config: `serve` builds `RaftKv` when `[cluster]` is present, else
`CachedKv(<storage>)` where `--kv` chose the storage (slatedb / cloudflare /
memory). So **`--kv` selects the *storage*; the *frontend* is consensus iff you
configured a cluster.**

## 4. "RaftKv as the only frontend?" — the trade-off

It's tempting (and matches the uniform-UX goal) to make `RaftKv` the single
frontend always, running single-node as a **one-voter Raft**. That's already
*possible* — configure `[cluster]` with one node and you get exactly that; the
only reason `CachedKv` exists is the **lean, no-consensus** path.

Making it the *default* would:
- **+** unify on one frontend; delete the cache-staleness/`SIGHUP` concern;
  pluggable storage underneath (Raft-over-SlateDB or Raft-over-Cloudflare-KV).
- **−** pull the Raft machinery (`openraft` + deps) into **every** build, against
  the lean-default goal, and add per-write Raft cost to a single static-site host
  that needs no coordination.

**Recommendation:** keep **both** topologies — they serve genuinely different
needs (multi-writer coordination vs. an already-replicated shared store / a lone
node) — but treat the layering above as the canonical model:
- `--kv` = storage; consensus frontend iff `[cluster]`.
- Topology A shares **blobs**, never the Raft store; "shared KV" is a topology-B
  notion only.
- `RaftKv`-always is available on demand (1-voter cluster) for operators who want
  uniform consensus; we don't force it as the default.

## 5. Where this leaves Cloudflare

The Cloudflare-Containers mode (see `CLOUDFLARE.md`) is **topology A**
(RaftKv on Containers, per-node Raft store on a durable volume, R2 for blobs) —
it does **not** use Cloudflare KV as the control plane. `CloudflareKv` (the
`--kv cloudflare` backend) is a **topology-B storage** choice: a non-cluster
deployment (or several stateless frontends) putting its KV in Cloudflare KV,
which is itself globally replicated — so it needs no Raft, just `CachedKv` +
`SIGHUP`/TTL for freshness.
