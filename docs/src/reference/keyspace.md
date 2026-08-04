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

Since 0.2.0 the keyspace splits three ways under the [project](../how-to/projects.md)
re-keying (a migration — see [Upgrade a store to project scoping](../how-to/migrate-to-projects.md)):

- **Project-scoped** — every mutable per-name record lives under
  `project/<proj>/…`. Pre-project resources migrate to the reserved `default`
  project, so they land under `project/default/…`. The owning project is always
  part of the key.
- **Global content-addressed** — dedup-shared immutable bodies keyed by their own
  hash. A content hash is a self-authenticating capability, so these bodies dedup
  across *all* projects (GC unions reachability over every project before it
  collects one).
- **Global-uniqueness index** — the domain-routing index. The **key** stays global
  (a host is globally unique), but its **value** now carries the owning
  `(project, site)`.

### Global — content-addressed bodies & singletons

| Key | Value |
| --- | --- |
| `manifests/<id>` | a deployment `Manifest` (file→hash map + `DeployConfig`); `<id>` is its content hash |
| `meta/<id>` | `DeployMeta` (created-at, sizes, source/branch/author/message) |
| `siteconfig/<hash>` | **immutable** content-addressed `SiteConfig` body (dedups across sites & projects) |
| `daemonconfig/<hash>` | **immutable** content-addressed dynamic-daemon-config body |
| `projectver/<hash>` | **immutable** content-addressed project spec body |
| `projectmeta/<proj>` | **mutable pointer** → the hash of the project's current spec |
| `owner/<kind>/<name>` | reverse index: a resource `(kind, name)` → its owning project (single-membership guard) |
| `authz/policy` | the RBAC policy (roles → rights); absent ⇒ the built-in default |
| `authz/tokens/<id>` | issued-token metadata (label, roles); the token is never stored |
| `authz/revoked/<id>` | a revocation marker (presence ⇒ revoked) |
| `auth/root/<alg:hex>` | an extra trusted **root anchor** (`auth rotate-root`, make-before-break) |
| `cert/<domain>` | a stored cert (chain + key + expiry) — cluster-managed |

### Global — domain-routing index (key global, value carries the owner)

| Key | Value |
| --- | --- |
| `domain/<host>` | exact host → `DomainOwner { project, site }` (a bare-string value is read as the `default` project, back-compat) |
| `wildcard/<suffix>` | wildcard suffix → `DomainOwner { project, site }` |
| `httpchallenge/<host>/<token>` | O(1) index for the self-serve HTTP-01 edge route → the owning `(project, site)` |

### Project-scoped (`project/<proj>/…`, mutable per-name)

| Key | Value |
| --- | --- |
| `project/<proj>/current/<site>` | the live deployment id for a site |
| `project/<proj>/history/<site>` | the site's activation log |
| `project/<proj>/alias/<site>/<name>` | a named alias → deployment id |
| `project/<proj>/site/<site>` | **mutable pointer** → the hash of the site's current `SiteConfig` |
| `project/<proj>/domainverify/<site>/<host>` | a pending domain-ownership challenge |
| `project/<proj>/dnsmanaged/<site>/…` | managed-DNS reconciliation state |
| `project/<proj>/functions/<name>` | a function's metadata (current version pointer) |
| `project/<proj>/functions/<name>/versions/<id>` | an immutable function version |
| `project/<proj>/functions/<name>/alias/<label>` | a function alias → version |
| `project/<proj>/functions/<name>/triggers/<id>` | an event trigger (webhook/queue/cron/blob) |
| `project/<proj>/functions/<name>/invocations/<id>` | an async invocation record |
| `project/<proj>/functions/<name>/idem/<key>` | an idempotency marker |
| `project/<proj>/metering/<name>` | a function's usage/quota counters |
| `project/<proj>/blobnotify/<function>/…` | blob-change watch state |
| `project/<proj>/compute/<name>` | a compute workload spec pointer |
| `project/<proj>/compute_state/<workload>/<replica>` | a replica's lifecycle/snapshot state |
| `project/<proj>/workflows/<name>` | a declarative workflow definition |
| `project/<proj>/workflows/<name>/runs/<id>` | a workflow run |

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

The `<topic>` is project-qualified for a non-`default` project (`<proj>/<topic>`),
so two projects' same-named topics stay isolated; the `default` project's topics are
unprefixed (byte-identical to pre-0.2.0).

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

Content-addressed keys (`manifests/<id>`, `siteconfig/<hash>`, `projectver/<hash>`,
blobs) are immutable — cached forever, never in the
[cache-coherence](../explanation/cache-coherence.md) feed. Only mutable
pointers/config (`project/<proj>/current/`, `project/<proj>/site/`, `domain/`,
`projectmeta/`, `authz/tokens/`, `cert/`) need invalidation. Coordination state
(`ratelimit/`, `mqp/`) is never cached.
