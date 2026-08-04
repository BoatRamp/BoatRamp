# Changelog

All notable changes to boatramp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project is pre-1.0, so the API
(HTTP, CLI, config, and the published library crates) may change between minor
versions.

## [0.2.0]

### Security
- **Project tenant isolation of the guest data plane.** A managed handler's / function's
  `wasi:keyvalue`, `wasi:blobstore`, `sql`, and `wasi:messaging` namespaces are now
  scoped to the owning project, so two projects that each own a same-named site or
  function no longer share one data namespace. The reserved `default` project keeps the
  pre-project (unprefixed) keys, so an existing single-project store is byte-identical and
  needs no data migration. (Side effect: function `sql` databases, previously ungranted
  due to a name-validation bug, now open correctly and are per-project isolated.)
- **Resource-name validation.** Project / site / function / compute / workflow names are
  rejected at the write boundary if they contain a path separator, `*`, whitespace, or a
  control character (or are `.`/`..`), closing store-key integrity and authz-target
  edge cases.

### Added
- **First-class Projects — the multi-site owning + tenant boundary.** A **project**
  (Uchron's *Workspace*) owns many sites plus their functions and compute, and is the
  tenant boundary a managed handler's row-level scope resolves to. New `boatramp
  project {create,ls,show,rm}` and a `/api/projects` + `/api/projects/<proj>/…` control
  surface; a global `--project` flag (falling back to `[publish].project` →
  `BOATRAMP_PROJECT` → the reserved `default` project) targets the site-scoped commands.
  A site's name is now unique only *within* its project, so two projects can each own a
  `blog`, and their sites, crons, consumers, async invocations, and workflow runs are
  scheduled independently. Cedar gains a `Project` resource with `project_admin`/
  `project_publisher`/`project_viewer` roles; a project-admin token cannot touch a
  sibling project.
- **`boatramp apply` — declarative project reconcile.** One RON manifest (`apply.cfg`)
  declares a whole project — its member sites (each a content dir + optional build +
  routing + site config), top-level functions, and compute workloads — and `apply`
  reconciles it in a single pass: sites reuse the content-addressed deploy flow (upload
  only the missing blobs, then activate), functions and compute are create-or-replace.
  It is **pure upsert and never prunes**, so declarative and imperative (CLI/API)
  management coexist. `--dry-run` prints the plan and mutates nothing.
- **Kubernetes `Site`/`Function` CRDs gain an optional `project`** — a k8s-managed site
  reconciles to its project's control-plane API (empty ⇒ `default`).
- **Function-to-function invoke for site handlers (mesh orchestrator).** A site
  handler (a `routing.handlers` route) reached over HTTP with the end user's bearer
  can now call sibling functions **in-process** via the `invoke` capability, exactly
  like a top-level function. `HandlerConfig` gains `invoke_targets` (the same
  deny-by-default, `*`-wildcard allowlist as `FunctionConfig.invoke_targets`), and
  `invoke` is a recognized handler import — gated by the site's `allow_imports`, the
  handler's `imports`, and a non-empty `invoke_targets`. The callee is quota-admitted
  and depth-capped as on the top-level path, and the caller's `Authorization` is
  forwarded to the callee unchanged.

### Changed
- **BREAKING (data model): every resource is owned by a project; the store is
  re-keyed under `project/<proj>/…`.** Sites, functions, compute, workflows,
  invocations, metering, aliases, and domain verifications are now stored per project
  (content-addressed bodies — manifests, blobs, site/compute config — stay global and
  deduped; the domain-routing index stays a global key whose value carries the owning
  `(project, site)`). Pre-existing resources belong to the reserved `default` project,
  so a single-site user's URLs and behaviour are unchanged (`/api/sites/<name>` and an
  omitted `--project` are byte-identical to before). Garbage collection now unions
  reachability across *all* projects, so a blob shared between two projects is never
  collected while either still references it.
  **Migration required.** An existing (pre-0.2.0) store must be migrated to the
  project-scoped layout before it will serve: run `boatramp migrate` (supports
  `--dry-run`, a `--stage` copy-then-soak, and `--finalize`), or start the server with
  `serve --auto-migrate`. The migration is online, idempotent, and resumable
  (copy-before-delete with a `schema/version` cursor); no content-addressed body ever
  moves — only the mutable per-name pointers re-key and the domain index values are
  rewritten to `{project: "default", site}`. `serve` refuses an unmigrated store unless
  `--auto-migrate` is set. The store migration is now a **versioned migration
  mechanism** — an ordered registry of forward-only migrations the engine walks by a
  monotonic `schema/version`, composed of reusable copy/verify/rewrite steps — so future
  breaking store changes are additive registry entries, not one-off codemods.
- **BREAKING (compute): the root-filesystem source is a typed `RootSource`.**
  `ComputeSpec.rootfs` was one overloaded string that meant a different thing per
  backend — an OCI image reference (docker/cloudflare), a tar rootfs archive (native
  container), or a rootfs filesystem image (firecracker micro-VM). It is now
  `root: RootSource { Image | Tar | Rootfs }`, one variant per artifact form, matched
  1:1 to the backends that accept it (a mismatch is a typed error, not a silent
  runtime failure). `boatramp compute set` now takes exactly one of `--image`,
  `--tar`, or `--rootfs` (previously a file-only `--rootfs` that could not carry an
  image reference and hard-coded ext4).
  **Migration:** re-declare compute workloads with the source flag that matches the
  target substrate — `--image <ref>` for docker/cloudflare, `--tar <artifact>` for the
  native container runtime, `--rootfs <artifact>` for the micro-VM. Stored
  `ComputeSpec` JSON changes shape (`"rootfs": "…"` → `"root": {"image"|"tar"|"rootfs": "…"}`).

[0.2.0]: https://github.com/BoatRamp/BoatRamp/releases/tag/v0.2.0

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
