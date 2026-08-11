# Changelog

All notable changes to boatramp are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com); the project is pre-1.0, so the API
(HTTP, CLI, config, and the published library crates) may change between minor
versions.

## [Unreleased]

### Added
- **Edge response cache for handlers (`[handlers.cache]`).** A site can opt into a
  host-level cache that serves a cacheable `GET`/`HEAD` response **without
  re-instantiating the handler** — the execution analogue of the existing compile cache.
  A response is stored only when it explicitly opts in via `Cache-Control: max-age`/
  `s-maxage` and its size is known (`Content-Length`) and within `max_entry_bytes`;
  it is **never** cached when private (`no-store`/`private`/`no-cache`, a `Set-Cookie`,
  `Vary: *`, or an `Authorization` request without `public`/`s-maxage`). Entries are
  keyed by the request's project-qualified scope (so two tenants never collide), honor
  `Vary`, and expire by TTL (clamped to `max_ttl_secs`, lazily evicted on read). Backed
  by the site's KV store; disabled by default. Foundation for GraphQL persisted-query
  caching.
- **`wss`/`https` WebSocket upstreams for the gateway.** The gateway's WebSocket /
  HTTP-upgrade tunnelling now completes a TLS handshake to `https`/`wss` upstreams —
  previously only `http`/`ws`/`unix:` were wired. So a private service reached over TLS
  (e.g. a compute-workload GraphQL server that speaks `graphql-ws`) can be proxied through
  the edge. Server-auth uses the platform's webpki roots against the resolved upstream
  host, pinned to the posture-validated address (the same SSRF guard as the plaintext
  path); the `ring` crypto provider is pinned explicitly.
- **`boatramp compose`: fuse WebAssembly components into one handler.** Author resolvers
  or middleware as separate, WIT-typed components and link them into a single component
  **in-process** — no network hop, checked at compile time — then deploy the one fused
  `.wasm` through the normal content-addressed path. The fused component's exports are
  unchanged (still e.g. `wasi:http/incoming-handler`); only the imports a plugin provides
  are satisfied internally, while host imports (`wasi:http`, `sql`, `kv`, …) stay imported
  for the runtime to supply. Composition runs in-process, so it needs no external
  toolchain and never runs on the serving node — it is a build step that emits one
  component (`compose --edge a.wasm --plugin b.wasm -o fused.wasm`).
- **Streaming function-to-function invoke.** A handler can now call a sibling function
  and consume its response as a **stream** — status and headers up front, the body pulled
  incrementally through a new `incoming-response` resource — so a large or
  incrementally-produced result is never buffered whole in host memory. The buffered
  `invoke` stays the simple default; the streaming variant is the opt-in for big or
  incremental (`@defer`-style) responses. It keeps the same in-process path (no network
  hop), target allowlist, and call-depth cap; streamed responses are metered at hand-off
  (bytes-out from a declared `Content-Length` when present).
- **GraphQL edge query-guard (`[handlers.graphql]`).** A site can opt into parsing
  incoming GraphQL operations at the edge and **rejecting them before the handler runs**
  when they exceed a depth or complexity limit, or (unless allowed) are
  schema-introspection queries — defense-in-depth over the per-request fuel cap against
  the deep/wide-query denial-of-service class it can't fully catch. Fragments are expanded
  so nesting can't hide behind them, and cyclic fragments terminate. Only a bounded POST
  body is inspected (a larger or unknown-length body passes through unguarded, so the guard
  can't exhaust memory); a rejection is a GraphQL-shaped `400`. Off by default. The first
  step toward GraphQL-native serving.

## [0.2.4]

### Added
- **Tunable privileges for shared-kernel workloads, so a stock DB image can init.** The
  docker + native-container backends drop every Linux capability by default, which stops
  a stock `postgres`/`mysql` entrypoint (it `chown`s its data dir and `gosu`-drops to its
  user). Three composable ways to fix it, cleanest first: `ComputeSpec.user`
  (`compute set --user uid[:gid]`) runs the image **rootless** against a volume boatramp
  pre-`chown`s for that uid — no capabilities, honored under any posture; `cap_add`
  (`--cap-add CHOWN …`) grants specific capabilities back on top of the dropped-`ALL`
  default, **single-tenant only** (the multi-tenant guard strips it, like
  `writable_root`; on the native-container backend the caps are user-namespace-bounded);
  and `[compute].managed_db_privilege` (`rootless` default | `caps`) makes a **managed
  database** (a handler `sql` binding sourced from a DB boatramp runs) apply the right
  strategy automatically, so it initializes with zero extra operator config. The stored,
  content-addressed `ComputeSpec` is never mutated — the managed-DB strategy is applied
  to the launch spec only, and never overrides an operator-set `user`/`cap_add`.
  `no-new-privileges` stays on in every path. See
  [Run a container or microVM](docs/src/how-to/compute.md).
- **Embed the compute backends in-process: `NodeInput::worker_exe`.** The
  container + microVM backends re-exec a per-workload worker (`__sandbox` /
  `__vmm-run` / `__vz-run`); they now re-exec `NodeInput.worker_exe` (default:
  `current_exe()`, which is what `boatramp serve` wants). An **embedding harness**
  whose own binary doesn't implement those subcommands can point `worker_exe` at a
  built `boatramp` binary and drive the real container/microVM backends in-process —
  the serving/tenancy plane stays embedded via `assemble`, only each workload's worker
  is a re-exec. (The docker backend needs no re-exec at all — it talks to a daemon — so
  docker-backed compute, e.g. Postgres-as-OCI, embeds through `assemble` today.) See
  [Embed the node](docs/src/how-to/embed.md).

### Fixed
- **A non-root docker workload can create its own runtime dir (`/run/...`), so a managed
  DB inits with zero operator config.** The hardened docker `HostConfig` mounts a small
  tmpfs at `/run`; Docker special-cases a bare `/run` tmpfs to `0755 root:root`, which a
  workload running as a non-root user cannot write. A stock `postgres` entrypoint does
  `mkdir -p /var/run/postgresql` (its unix-socket dir) as its own uid and, when that
  silently fails, never starts its init server — so `CREATE DATABASE` never runs and the
  managed DB comes up missing its database. The `/tmp` + `/run` tmpfs mounts are now
  `mode=1777` (world-writable + sticky, matching a real `/tmp`/`/run`), so the entrypoint
  creates and owns its runtime dir exactly as it expects. General, not image-specific
  (MySQL's `/run/mysqld`, nginx's `/run/nginx`, … all rely on the same); `noexec`/`nosuid`
  keep the mount hardened. Reproduced and fixed live, rootless under the exact hardened
  flags, against both **`postgres:16`** (`mkdir -p /var/run/postgresql`, silent under
  `|| :`) and **`mysql:8.0`** (`mkdir -p /var/run/mysqld`, a hard `set -e` abort:
  `mkdir: cannot create directory '/var/run/mysqld': Permission denied`) — each then
  initializes its database with zero operator config.
- **Untagged docker image references default to `:latest`.** `compute set/build --image
  <name>` with no tag (e.g. `--image alpine`) no longer pulls *every* tag of the repo
  (slow, and a hard failure on any repo that still carries an ancient v1-manifest tag) —
  the docker backend now splits the reference into `fromImage` + `tag`, defaulting an
  untagged one to `latest` (a registry `host:port` is not mistaken for a tag; a digest
  pin is passed through), and records the fully-qualified reference it pulled.

### Changed
- **The compute reconcile tick is configurable** via `BOATRAMP_COMPUTE_RECONCILE_TICK_MS`
  (milliseconds; default 30s). Compute-backed tests can set it low so a workload's
  launch/scale reconcile converges in a fraction of a second instead of waiting a full
  30s tick.

## [0.2.3]

### Added
- **Scale-to-zero for the native `container` backend (CRIU).** An idle container
  workload is now parked to disk and later woken with its **in-RAM state intact** —
  the container analog of the microVM backends' snapshot/restore, using CRIU
  (Checkpoint/Restore In Userspace, the same mechanism runc/Podman `checkpoint`
  use). `snapshot` dumps the container's process tree (freeing all its resources,
  holding its IP); `restore` checkpoints it back and re-attaches its veth/`eth0`, so
  a woken container resumes exactly where it left off (validated end-to-end: a
  per-process nonce served over HTTP survives the park/wake round-trip). It is
  **capability-detected** — advertised only when a usable `criu` is present on the
  node (`criu check` passes), so a `scale_to_zero` workload is never placed on a node
  that couldn't wake it (the scheduler routes it to a capable backend otherwise).
  This brings scale-to-zero to the shared-kernel/trusted-tier path (dense, fast,
  no VM) alongside the strong-isolation microVM backends (`vmm-embedded`, `vmm`,
  `vmm-vz`). **Also fixes four latent bugs on the container launch path** (which had
  never been exercised live): the userns id-maps are now written by the privileged
  launcher (a just-`unshare`d worker can't self-write a range map); `/proc`/`/sys`
  are mounted before the old root is detached (userns `mount_too_revealing`); the
  seccomp allow-list adds `fork`/`vfork` (musl-static workloads use the raw syscall);
  and the container init `setsid`s to lead its own session. Needs `criu` on the node
  (Linux; `CONFIG_CHECKPOINT_RESTORE` + `CAP_CHECKPOINT_RESTORE`/`CAP_SYS_ADMIN`).
- **macOS-native microVM compute backend (`vmm-vz`).** On Apple silicon + macOS 15+,
  boatramp runs each compute replica as a lightweight Linux VM via Apple's
  Virtualization.framework — the macOS analog of the Linux/KVM `vmm-embedded`
  backend, with **strong per-VM isolation** (`IsolationClass::VmKvm`) and an
  **identical user surface** (same `ComputeSpec`, `boatramp compute` CLI, and
  `/api/compute` — the environment difference lives entirely behind the backend
  seam). It stays a **single binary**: each VM runs in a re-exec'd `__vz-run`
  worker (mirroring the KVM `__vmm-run`), driven in-process through
  `objc2-virtualization`. Capability-detected and registered only on a capable
  host; off macOS the crate compiles to its pure orchestration layer (the objc2
  deps are `target_os="macos"`-gated), so Linux builds are unaffected. **Validated
  end-to-end on Apple silicon** under the free self-signable
  `com.apple.security.virtualization` entitlement: a real Linux userspace boots
  from an `ext4` rootfs, gets a static vmnet IP, and **runs PostgreSQL 16 with its
  data directory on a persistent virtio-block volume** — the port is reachable from
  the macOS host over vmnet, and the data survives a full VM restart. macOS 26 is
  recommended (macOS 15's vmnet lacks container-to-container networking).
  **`compute build` produces arm64 images on macOS**: the guest `vminit` is now
  arch-portable (x86_64 + aarch64), the `boatramp-firecracker` build cross-compiles
  the aarch64 init via `zig` on macOS, and the OCI pull + kernel trust are
  arch-scoped to the guest arch — validated end-to-end (a Docker Hub image built to
  an arm64 rootfs on macOS boots under `vmm-vz` and serves). A **signed first-party
  arm64 kernel is shipped**: `boatramp-vmlinux` v0.2.3 publishes an ES256-signed
  `boatramp-vmlinux-aarch64` (a raw arm64 `Image`) whose hash is on the arch-scoped
  allow-list, so strict-posture `vmm-vz` on Apple silicon verifies it out of the box
  (as the x86_64 kernel does on Linux) — the allow-list pins the published signed
  asset (the aarch64 build is not currently bit-reproducible across build hosts, so
  verify against the release `.sha256`/`.sig`, not a local rebuild). This kernel
  **enables the generic
  PCIe host + virtio-pci**: Virtualization.framework presents its virtio disk/net/
  console over a PCIe host bridge (not the cmdline virtio-mmio the Firecracker config
  targets), so the earlier `CONFIG_PCI`-off build never booted under VZ; the PCI build
  boots, mounts its root over virtio-blk, and gets its static IP via kernel `ip=`
  autoconfig over virtio-net. The **released macOS binaries are code-signed** with the
  `com.apple.security.virtualization` entitlement (ad-hoc, the last build step, with a
  survive-assert per podman #21843) so the shipped binary can boot VMs.
- **Scale-to-zero on `vmm-vz`** (`scale_to_zero: true`). An idle `vmm-vz` replica is
  now parked to disk and later woken, the macOS analog of the KVM embedded VMM's
  scale-to-zero: `snapshot` pauses the VM, writes its state with
  `saveMachineStateToURL:`, and stops it; `restore` recreates the VM and
  `restoreMachineStateFromURL:` + resumes it. The key is a **stable
  `VZGenericMachineIdentifier`** threaded from launch through park to wake (via a
  `VZGenericPlatformConfiguration`): Virtualization.framework rejects a restore whose
  identifier differs from the saved VM's, so the backend mints one per replica and
  persists it with the snapshot. **Validated end-to-end on Apple silicon** — a parked
  guest wakes with its exact in-RAM state intact (init does not re-run), gated by
  `tests/vz_live.rs::vz_live_snapshot_restore_roundtrip`. See
  [`compute`](docs/src/reference/boatramp-cfg.md#compute) and
  [The kernel and its trust](docs/src/how-to/compute.md).
- **Managed SQL on a database boatramp runs.** A handler `sql` database can now be
  sourced from a Postgres/MySQL **compute workload boatramp runs** instead of a
  hand-mapped connection URL: set `compute: "<workload>"` (with `database`/`user`)
  on the entry instead of `url_env`. boatramp resolves the workload's live endpoint
  on demand and builds the connection, so the binding **follows the database across
  restarts** with no config change. Omit `password_env` and boatramp **fully manages
  the credential** — it generates a strong password once, seals it with the
  `[secrets]` envelope, injects it into the DB workload's server-init env
  (`POSTGRES_*` / `MYSQL_*`) at launch, and connects the handler with the same sealed
  password, so the operator sets no DB secret at all. A managed database **requires a
  `[secrets]` envelope** (it fails closed rather than store a credential it cannot
  seal) and a **persistent volume** on the DB workload (so the initialized password
  survives a restart — pairs with the 0.2.2 docker volumes). Needs the `sql-postgres`
  / `sql-mysql` build feature. See *Managed SQL on a database boatramp runs* in
  [Use handler bindings](docs/src/how-to/handler-bindings.md).

## [0.2.2]

### Added
- **Docker / native-container workloads: writable root + external persistent volumes.**
  A docker workload now honors a spec's `volumes` (previously ignored, silently
  running storage-less). Back the volume with the new `[compute].docker_volume_mode`
  knob: `named` (default) attaches a daemon-managed `docker volume` by name (portable
  across daemons and Docker Desktop / macOS), `bind` bind-mounts a host directory
  under `<data_dir>/compute/volumes/<name>` (local daemon only). Volumes are
  node-local — outside the blob-snapshot durability the microVM backend's volumes get.
- **`compute set` / `compute build --writable-root`.** Opt into a writable root
  filesystem for a container workload instead of the hardened read-only-root default.
  Honored **only under the single-tenant security posture** (the multi-tenant guard
  forces the read-only root back on); every other hardening — dropped capabilities,
  `no-new-privileges`, the PID cap — stays. A persistent volume remains the idiomatic
  path for app writes.
- **`boatramp_node::assemble` — the serve-node assembly as a library.** The wiring
  `boatramp serve` runs (store → handler runtime → deploy store → compute +
  domain-verify reconcile loops → a router-ready node) is now a published library
  call, so an embedder — or an in-process fidelity test — builds the exact same graph
  the binary runs. Both the single-node and cluster serve paths share it. See the
  updated *Embed boatramp as a library* guide.

### Fixed
- **Scheduler: a workload requiring persistent volumes or scale-to-zero is no longer
  placed on a backend that can't provide it.** Such a spec could previously be
  scheduled onto an incapable backend and run storage-less (silent data loss) or
  always-on (a silently missed cost optimization). Placement now treats the missing
  capability as ineligible and returns "insufficient capacity" instead of running
  wrong.
- **Cluster image: the filesystem blob backend is compiled in.** After `build_blobs`
  moved into `boatramp-node` (whose `fs` arm is feature-gated), the slim cluster build
  (`--no-default-features --features operator,cluster,tls`) no longer pulled `fs`, so a
  cluster pod serving the zero-config default `--blobs fs` crashed with "no filesystem
  blob support". The `cluster` feature now requires `fs`.

## [0.2.1]

### Added
- **Compute bindings: the managed `sql` for opaque compute workloads.** A docker or
  native-container workload can now declare a managed dependency with
  `compute set <name> --bind sql` and reach the **same per-tenant-scoped `SqlBackend`
  a WASI handler gets** — over libsql's hrana-over-HTTP `/v2/pipeline` wire protocol
  served by a per-node, token-multiplexed sql-shim — instead of hand-gluing a
  connection string. The reconcile mints an instance-lifetime bearer token and injects
  `BOATRAMP_SQL_URL` + `_AUTH_TOKEN`; no long-lived DB secret ever enters the guest, and
  the wire has no "open database" verb, so a workload is structurally scoped to its
  project's namespace. Opt-in via `[compute].sql_shim_url`.
- **`[compute].docker_endpoint`.** Publish a docker/podman workload's port to the host
  (`127.0.0.1:<ephemeral>`) by default, so the sql-shim and health checks reach it under
  rootless podman and remote daemons where the container-bridge IP is not host-routable.
- **Declarative functions in `apply.cfg`.** A function may now declare its `imports`,
  `env`, `invoke_targets`, and resource `limits` in the project manifest.

### Fixed
- **Firecracker: a workload's runtime `env` reaches the guest (the "env drop").** Env set
  at launch was silently dropped (only `compute build`-time env reached the guest). It is
  now delivered over a launch-time kernel-cmdline channel (`boatramp.env=<hex>`) the guest
  init decodes, placing runtime entries first so they override the baked image env.
- **Firecracker/embedded VMM: the microVM now boots its virtio-block root.** The signed
  `boatramp-vmlinux` is built with `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y`, so the in-process
  embedded VMM's virtio-MMIO cmdline device transport is discovered; previously the guest
  never saw `/dev/vda` and root mount failed. (Additive; the firecracker-binary ACPI path
  is unaffected.)
- **Projects: imperative writes honor `--project`.** `sync`, `compute set`, and function
  deploy now route to the selected project instead of a project-unaware path; a write to a
  missing project is rejected (the existence check runs after authz, so it is not an
  existence oracle); the reserved `default` project is materialized so it is always
  visible; a site's config is applied before activation, not after.

### Changed
- **Kernel trust: the CMDLINE_DEVICES kernel is allow-listed.** `kernel_allowed_hashes`
  adds the new signed `boatramp-vmlinux` hash alongside the prior release (the previous
  kernel stays trusted so current operators are not broken), and the kernel how-to reads
  the hash and signature from the downloaded release artifacts rather than hardcoding them.

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
