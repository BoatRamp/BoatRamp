# KV Keyspace

The authoritative map of every key boatramp writes, across its two backends.
Prefixes are distinct and slash-delimited so a `list_prefix` scan enumerates one
kind without matching another.

- **Storage** (fs / S3 / R2) — blob content.
- **KV** (SlateDB / memory / Cloudflare KV; or `RaftKv` in cluster mode) — all
  control-plane metadata.

## Storage (blob content)

| Key | Value |
| --- | --- |
| `<2>/<sha256>` | raw file bytes, sharded by the first 2 hex chars of the hash (e.g. `ab/abcdef…`) |

Blobs are content-addressed and immutable: the key *is* the SHA-256. `boatramp
scrub` re-hashes each to detect drift.

## KV (control plane)

| Key | Value |
| --- | --- |
| `manifests/<id>` | a deployment `Manifest` (file→hash map + `DeployConfig`); `<id>` is its content hash |
| `meta/<id>` | `DeployMeta` (created-at, sizes, source/branch/author/message) |
| `current/<site>` | the live deployment id for a site |
| `history/<site>` | the site's activation log |
| `alias/<site>/<name>` | a named alias → deployment id |
| `site/<site>` | **mutable pointer** → the hash of the site's current `SiteConfig` |
| `siteconfig/<hash>` | **immutable** content-addressed `SiteConfig` body (dedups across sites) |
| `domain/<host>` | exact host → site (routing index) |
| `wildcard/<suffix>` | wildcard suffix → site |
| `domainverify/<site>/<host>` | a domain-ownership challenge |
| `authz/policy` | the RBAC policy (roles → rights); absent ⇒ the built-in default |
| `authz/tokens/<id>` | issued-token metadata (label, roles); the token is never stored |
| `authz/revoked/<id>` | a revocation marker (presence ⇒ revoked) |
| `auth/root/<alg:hex>` | an extra trusted **root anchor** (`auth rotate-root`, make-before-break) |
| `cert/<domain>` | a stored cert (chain + key + expiry) — cluster-managed |

### Mesh membership (cluster mode, replicated)

The dynamic-join trust + routing state, replicated through the control plane so
every node (and a restart) converges. See
[Deploy a self-hosted cluster](../how-to/deploy-cluster.md).

| Key prefix | Value |
| --- | --- |
| `mesh/trust/<node>/<pubkey>` | an accepted mesh public key (the sole authority on who may speak on the mesh) |
| `mesh/addr/<node>` | a member's advisory mesh URL (routing; the TLS re-authenticates by key) |
| `mesh/revoked/<pubkey>` | a durable **revocation tombstone** — a fresh token can't re-admit this key until un-revoked (F6) |
| `mesh/join/used/<jti>` | a spent single-use join-token handle (makes admission single-use) |

### Messaging (handler `wasi:messaging`)

| Key prefix | Value |
| --- | --- |
| `mq/<topic>/<id>` | a queued record |
| `mqp/<topic>/<id>` | in-flight (claimed) marker |
| `mqdead/<topic>/<id>` | a dead-lettered record |

### Cluster Raft store (cluster mode only)

Each node's **durable local** KV, distinct from the replicated control plane it
serves:

| Key | Value |
| --- | --- |
| `raft/vote` | the node's current vote |
| `raft/committed`, `raft/purged` | log progress markers |
| `raft/log/<index:020>` | a Raft log entry |
| `raft/sm/last_applied`, `raft/sm/membership` | applied-state metadata |
| `raft/sm/d/<key>` | applied state-machine data (mirrors the control-plane keys) |
| `raft/snapshot` | the latest snapshot |

## Immutable vs mutable

Content-addressed keys (`manifests/<id>`, `siteconfig/<hash>`, blobs) are
immutable — cached forever, never in the [cache-coherence](../architecture/cache-coherence.md)
feed. Only mutable pointers/config (`current/`, `site/`, `domain/`, `tokens/`,
`cert/`) need invalidation. Coordination state (`ratelimit/`, `mqp/`) is never
cached.
