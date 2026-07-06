# boatramp keyspace (single source of truth)

This is the authoritative map of every key boatramp writes, across the two
backends it uses. It is derived from the key-builder functions in the code
(`*_key` in `boatramp-core::deploy`/`cert`, `boatramp_types::authz`,
`boatramp-core::messaging`, and `boatramp-cluster::persist`); when you add a key,
update it **here** and
keep the prefixes distinct.

Two backends:

- **Storage** (`boatramp_core::Storage`: fs / S3 / R2) — holds blob *content*.
- **KV** (`boatramp_core::kv::KvStore`: SlateDB / memory / Cloudflare KV; or the
  replicated `RaftKv` in cluster mode) — holds all control-plane metadata.

## Storage (blob content)

| Key | Value | Written by |
| --- | --- | --- |
| `<2>/<sha256>` | raw file bytes (sharded by the first 2 hex chars of the hash, e.g. `ab/abcdef…`) | `DeployStore::put_blob` |

Blobs are content-addressed and immutable: the key *is* the SHA-256 of the
bytes. `boatramp scrub` re-hashes each to detect drift.

## KV (control plane)

| Key | Value |
| --- | --- |
| `manifests/<id>` | a deployment `Manifest` (file→hash map + `DeployConfig`); `<id>` is the manifest's content hash |
| `meta/<id>` | `DeployMeta` for a deployment (created-at, sizes, source/branch/author/message) |
| `current/<site>` | the live deployment id for a site |
| `history/<site>` | the site's activation log (`HistoryEntry[]`) |
| `alias/<site>/<name>` | a named alias (`staging`, `preview-…`) → deployment id |
| `site/<site>` | **mutable pointer** → the content hash of the site's current `SiteConfig` (the only key that changes on a config edit) |
| `siteconfig/<hash>` | **immutable, content-addressed** `SiteConfig` body (domains, security, access, compression, handler policy); keyed by its hash → caches forever, dedups across sites |
| `domain/<host>` | exact host → site name (virtualhost routing index) |
| `wildcard/<suffix>` | wildcard suffix → site name (e.g. `example.com` for `*.example.com`) |
| `domainverify/<site>/<host>` | a `DomainVerification` ownership challenge |
| `authz/policy` | the RBAC `AuthzPolicy` (roles → right templates); absent ⇒ the built-in default |
| `authz/tokens/<id>` | `TokenMeta` for an issued token (label, roles, timestamps); keyed by its authority revocation id. The token itself is never stored |
| `authz/revoked/<id>` | a revocation marker (presence ⇒ the token with that authority revocation id, and its attenuations, is revoked) |
| `cert/<domain>` | a `StoredCert` (chain + key + expiry) — the cluster-managed cert store |

### Messaging (handler `wasi:messaging`)

| Key prefix | Value |
| --- | --- |
| `mq/<topic>/<id>` | a queued `Record` |
| `mqp/<topic>/<id>` | in-flight (claimed/processing) marker |
| `mqdead/<topic>/<id>` | a dead-lettered record |

### Cluster Raft store (cluster mode only)

Held in each node's **durable local** KV (distinct from the replicated control
plane the cluster serves), written by `boatramp_cluster::persist`:

| Key | Value |
| --- | --- |
| `raft/vote` | the node's current vote |
| `raft/committed`, `raft/purged` | log progress markers |
| `raft/log/<index:020>` | a Raft log entry |
| `raft/sm/last_applied` | last-applied log id |
| `raft/sm/membership` | cluster membership |
| `raft/sm/d/<key>` | applied state-machine data (mirrors the control-plane keys above) |
| `raft/snapshot` | the latest snapshot |

## Conventions

- Prefixes are distinct and slash-delimited so a prefix scan (`list_prefix`)
  enumerates one kind without matching another.
- Multi-key changes that must be atomic (e.g. writing a `SiteConfig` and
  rebuilding its `domain/`/`wildcard/` index) go through `KvStore::write_batch`,
  which commits as one durable, atomic flush.
- The control-plane KV is fronted by a **write-through** LRU (`CachedKv`): every
  `put`/`delete`/`write_batch` updates the cache, so an `activate` is visible
  immediately (no stale `current/<site>`).
- **Immutable vs mutable keys** (matters for cache coherence — see
  `ARCHITECTURE-kv.md`): content-addressed keys (`manifests/<id>`,
  `siteconfig/<hash>`, blobs) are immutable — safe to cache forever and never in
  the shared-mode invalidation feed. Only the mutable pointers/config
  (`current/<site>`, `site/<site>`, `domain/`, `authz/`, `cert/`, …) need
  invalidation. Coordination state (`ratelimit/<site>/<ip>`, messaging `mqp/…`)
  is **never cached** (read through the uncached backend).
