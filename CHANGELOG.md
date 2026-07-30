# Changelog

All notable changes to boatramp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project is pre-1.0, so the API
(HTTP, CLI, config, and the published library crates) may change between minor
versions.

## [0.1.2]

### Changed
- **BREAKING (external SQL): one placeholder syntax everywhere.** The handler
  `sql` binding's contract is now **numbered `?N` placeholders** (`?1`, `?2`, …)
  on *every* backend. The external Postgres/MySQL backends previously passed
  statements through to the driver, so they required the engine's *native* syntax
  (Postgres `$1`, MySQL `?`); they now take the same `?N` as the managed libsql
  default and the host rewrites to the native form. Statements are validated
  fail-closed — native `$N`, bare `?`, `:name`/`@name`, out-of-range indices, and
  placeholder/parameter miscounts are **rejected** rather than silently bound to
  the wrong value (closing a cross-tenant wrong-parameter hazard at the `sql`
  scoping boundary).
  **Migration:** in guest SQL that targets an external Postgres/MySQL database,
  change native placeholders to `?N` (mechanical: `$1`→`?1`; a bare `?` →
  `?1`/`?2`/… in order). Casts move onto the placeholder: `$1::int` → `?1::int`.
  SQL against the managed libsql default is unaffected. Adds a `sqlparser`
  dependency (dialect-aware tokenizer) behind the `sql*` features.

[0.1.2]: https://github.com/BoatRamp/BoatRamp/releases/tag/v0.1.2

## [0.1.1]

### Added
- **Function-to-function invoke.** A function can call a sibling **in-process** via
  the new `invoke` capability (a `boatramp:handlers/invoke` WIT interface), instead
  of a network round-trip. Calls are gated by a per-function wildcard target
  allowlist (`invoke_targets`), capped at a maximum call depth to stop invocation
  loops, and the callee is quota-admitted and metered exactly like an external
  invoke. New `examples/handlers/invoke-caller` guest and a `just build-fixtures`
  recipe to rebuild the example test fixtures.

### Changed
- **crates.io metadata.** Every published crate now carries the project README,
  `homepage`/`documentation` (https://boatramp.dev), `keywords`, and `categories`,
  and the package authors are set to Uranion — so the crate pages are complete.
- Updated the vendored `spin` lockfile entries off the yanked 0.9.8/0.10.0.

[0.1.1]: https://github.com/BoatRamp/BoatRamp/releases/tag/v0.1.1

## [0.1.0]

The first public release: boatramp is a self-hosted, streaming-first alternative to
Vercel — one binary that is both the server and the CLI.

### Publishing & serving
- Atomic, immutable, content-addressed deployments with instant rollback, named
  aliases (staging/previews), and virtualhost routing.
- Custom domains with ownership verification (HTTP + DNS-01), automatic TLS
  (ACME, ACME-DNS wildcard, operator certs, and a pinned raw-public-key control
  channel), and managed DNS across many providers.
- Visitor access control (basic auth, IP rules, rate limiting), caching, and
  optional on-the-fly compression.

### Compute
- WebAssembly handlers and functions: sync/async/scheduled invocation, metering and
  quotas, signed webhooks, queue/blob-change triggers, and declarative workflows;
  bindings for kv, sql, blobstore, and messaging; Rust/JS/Python developer flows.
- Containers and Firecracker microVMs (an embedded rust-vmm VMM), scale-to-zero, and
  a reverse-proxy gateway with health-checked load balancing.

### Storage
- Blob backends: filesystem, S3, GCS, Azure (with their change-notification
  providers). KV backends: SlateDB, in-memory, Cloudflare KV. External bring-your-own
  PostgreSQL/MySQL for the `sql` binding.

### Control plane & security
- COSE/CWT tokens with Cedar RBAC, per-request DPoP proof-of-possession, offline
  delegation, external signers (KMS/HSM/Vault/PKCS#11), and OIDC.
- A curated security-posture model and hardened defaults.

### Fleet
- A self-hosted Raft cluster with dynamic join over a raw-public-key mutual-TLS mesh,
  an in-binary Kubernetes operator, and a Cloudflare Containers deployment target.
- Dynamic daemon configuration (no-restart operational knobs) and Prometheus metrics.

### Interfaces
- An embedded web management console.
- A Model Context Protocol (MCP) server to drive one or more instances from an AI
  agent, over stdio or an HTTP `/mcp` endpoint.

[0.1.0]: https://github.com/BoatRamp/BoatRamp/releases/tag/v0.1.0
