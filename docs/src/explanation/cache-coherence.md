# Cache Coherence

This concerns only the **shared-store / no-consensus** topology — N stateless
processes over one shared `KvStore`, each fronting it with a local `CachedKv`
LRU. The Raft topology needs none of it (replication keeps every node's applied
state current; `RaftKv` has no LRU). A single process doesn't either.

The goal: a process picks up another process's control-plane write promptly and
cheaply, scaling to thousands of sites — without TTL desync and without flushing
the world on every write.

## Why not the obvious options

- **Per-entry TTL** — every entry goes stale on its own clock; you tune a guess
  and live with desync.
- **Flush-all on any write** — one site's edit flushes every process's whole LRU
  → all frontends re-fetch their working set → a thundering herd on every write.
  Cost scales with `cache_size × write_rate`. Kept only as a rare backstop.

## Targeted invalidation via a changelog

Invalidate **only the changed keys** (pop site X's entries; leave the others
hot). Cost is **O(write rate)**, independent of site count; O(1) per change.

On a control-plane write, one entry `_inval/{millis}-{writer}-{n}` listing the
changed keys is appended to the shared store. Each process polls for entries
after its cursor, pops those keys from its LRU, and advances the cursor (its own
entries are skipped). Old entries are trimmed; a rare full flush is the gap
backstop. The feed is just KV data, so it works over Cloudflare KV or shared
SlateDB alike. Enable with `--shared-cache-coherence`.

For real-time (poll-free) delivery, a pusher (a Cloudflare Durable Object /
Queue, Redis, or ops) can `POST /api/cache/invalidate {keys:[…]}` directly.

## Minimizing the surface: content-addressed config

The fewer *mutable* keys, the smaller the problem. `SiteConfig` is
content-addressed: an immutable `siteconfig/<hash>` body (caches forever, dedups
across sites) plus a tiny mutable `site/<site>` pointer. Only the pointer changes
on an edit, so the feed carries pointers, not config bodies — and the bodies
never need invalidation at all. (This also makes config edits atomic pointer
flips, like deploy activation.)

## What is never cached

Coordination state — rate-limit windows (`ratelimit/<site>/<ip>`) and messaging
claim/lease state (`mqp/…`) — is read through the **uncached** backend; caching
it would yield stale leases / wrong counts in shared mode.
