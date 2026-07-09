# Storage & KV

boatramp stores blobs in a streaming `Storage` backend and all control-plane
metadata in a `KvStore`. The `KvStore` trait is deliberately tiny
(`get`/`put`/`delete`/`list_prefix`/`write_batch`), and it plays **three roles**.

## One trait, three roles

| Role | Implementors | What it is |
| --- | --- | --- |
| **Storage** (durable) | `SlateKv` (SlateDB over local FS / S3 / R2 / GCS), `CloudflareKv`, `MemoryKv` | Where the bytes rest. |
| **Consensus frontend** | `RaftKv` | Turns writes into replicated Raft entries; serves reads from local applied state. Persists its log + state to a Storage backend per node. |
| **Caching decorator** | `CachedKv` | A write-through LRU in front of any `KvStore`. |

They compose: `CachedKv(SlateKv)`, or `RaftKv` over a per-node `SlateKv`.

## Two topologies (pick one)

### Consensus (`RaftKv`)
Writes go to the leader, commit to the replicated log, and apply to **every**
node's state machine; reads come from local applied state. This is cluster mode
and Cloudflare-Containers mode.

- Each node keeps its **own** durable Raft store — **not shared** (sharing a Raft
  log breaks Raft). Only *blobs* (S3/R2) are shared.
- No cache staleness, no `SIGHUP`: `RaftKv` reads local applied state with no LRU
  in front.

### Shared-store / no-consensus (`CachedKv`)
One backend is the source of truth and coherence is the store's job. N stateless
frontends each front it with a local `CachedKv`; blobs are shared too.

- The shared store is itself replicated/consistent — **Cloudflare KV**, or a
  shared **SlateDB-on-R2**.
- A peer's write isn't visible until the local LRU evicts — `SIGHUP` (or the
  changelog) forces the re-read. See [Cache Coherence](./cache-coherence.md).
- A single node on local disk is just this with one process; the cache never
  goes stale because nothing else writes.

## SlateDB specifics

SlateDB is **single-writer** (manifest fencing). The shared-SlateDB topology is
therefore one writer process + read replicas (`SlateKv::open_reader` over
SlateDB's `DbReader`), which serve reads and poll the manifest for new data;
control-plane writes funnel to the writer.

## Selecting backends

`--kv` selects the *storage*; the *frontend* is consensus only if a `[cluster]`
config is present. `--blobs` selects the blob `Storage`. The per-site SQL
binding (libsql: a file per site, or a sqld namespace per site) is configured
under `[handlers.bindings.sql]`.
