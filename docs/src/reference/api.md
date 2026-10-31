# Control-plane HTTP API

The control-plane API is the transport the CLI speaks to a server. Most operators
never call it directly — the `boatramp` subcommands wrap it — but it is a stable,
documented surface for building your own tooling. This page lists the endpoints;
the [CLI reference](./cli.md) maps each command onto them.

## Conventions

- **Base path.** Every control-plane endpoint is under `/api`. Public serving
  (host-routed content, `/_sites/*`, `/healthz`) is a separate, unauthenticated
  surface.
- **Authentication.** A bearer token in `Authorization: Bearer <token>`. Every
  `/api/*` request is authenticated and authorized, except the handful gated by
  their own single-use credential (bootstrap, join, OIDC exchange). The exact
  right each endpoint requires is in the
  [request-to-right mapping](./rbac.md#request-to-right-mapping).
- **Bodies.** Requests and responses are JSON, except blob upload (raw bytes) and
  `/api/metrics` (Prometheus text).
- **Errors.** A non-2xx status carries a JSON `{ "error": "..." }`. `401` is a
  missing or invalid token; `403` is a valid token without the required right.

## Projects

A [project](../how-to/projects.md) owns sites, functions, and compute, and is the
tenant boundary. Since 0.2.0 every site/function/compute/workflow endpoint has a
project-scoped counterpart under `/api/projects/:project/…`; the legacy top-level
paths (`/api/sites/…`, `/api/functions/…`, `/api/compute/…`, `/api/workflows/…`)
target the reserved `default` project and stay byte-identical to pre-0.2.0.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/projects` | List projects. |
| `POST` | `/api/projects` | Create a project. |
| `GET` | `/api/projects/:project` | Get one project's record. |
| `DELETE` | `/api/projects/:project` | Delete an empty project (refused while it owns resources or is `default`). |
| any | `/api/projects/:project/sites/…` | Per-project site endpoints — the same shapes as [Sites & deployments](#sites--deployments), scoped to the project. |
| any | `/api/projects/:project/{functions,compute,workflows,graphql}/…` | Per-project function / compute / workflow / GraphQL-admin endpoints, scoped to the project. |

## Project export & import

Stream a whole project — its managed-database contents, control-plane KV slice, and blobs — off a
**running node** as a single portable `BRPROJ` bundle, and back in. This is how you **clone** a
project into another environment (staging → prod, a per-customer copy) or recover one. Both verbs
run against a running node and are gated **`Project·Admin` on the `?project=` target** — a
Project·Admin for project X can export/import X, not another project Y (the `project-export`
feature; on by default). See [Export, import & clone a project](../how-to/clone-project.md) for the CLI and the
full operational picture (format, atomicity, the managed-DB restore constraints).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/project-export?project=<name>[&data_only=true\|false][&include_identity=true\|false][&resumable=<dir>][&mode=differential\|incremental&base=<dir>]` | Stream a `BRPROJ` bundle of `project` out as the response body (`application/octet-stream`). `data_only` defaults to `true` (app data only — no identity/RBAC/routing); `include_identity=true` implies a full bundle and requires the `X-Boatramp-Transport-Key` header. With `resumable=<dir>` the bundle is instead written as a **member-object directory** under the node's `[serve] resumable_export_dir` base (returns JSON naming `resumable_dir`, not a stream): each member is a separate object written `.part`-then-rename, so a re-run skips members already present + SHA-verified — a dropped export resumes instead of restarting. `mode` + `base` take a **delta** against a prior resumable `base` dir (`incremental` chains onto the parent, `differential` diffs a fixed base); both are required together and only with `resumable` (a delta is a node-local member-object directory, not a stream — else `400`). See [Incremental & true-delta export](../how-to/delta-export.md). `Project·Admin` on the `?project=` target. |
| `POST` | `/api/project-import?project=<name>[&apply=true][&force=true][&overwrite=true][&allow_schema_skew=true][&identity=fresh\|adopt][&resumable=<dir>][&enumerate_mismatches=true][&skip_member_mismatch=true][&skip_any_blob_mismatch=true]` | Import a `BRPROJ` bundle (the request body) into `project`, or — with `resumable=<dir>` — from the member-object directory under `[serve] resumable_export_dir` that a resumable export produced. Dry-run (a plan, mutates nothing) unless `apply=true`. `identity=adopt` requires the `X-Boatramp-Transport-Key` header. The three `*mismatch*` params are the clone-robustness member-mismatch policy (see [Member-mismatch tolerance](#member-mismatch-tolerance) below); not accepted with `resumable`. Returns the import report as JSON. `Project·Admin` on the `?project=` target. |

The bundle is **streamed** on both ends — the node never stages the whole bundle to a temp file.
A small/sidecar-framed member (the control-plane KV slice, small blobs, the identity container)
stages to one bounded temp at a time (peak ≈ the largest such member); a large streamed member (a
managed SQL dump, a libsql snapshot, a large blob) is **chunked** (64 MiB parts, each hashed and
counted as it streams, with a trailing checksum+size record verified once the whole member has
passed through) — peak for those members is one chunk, not the whole member. A truncated or
corrupted stream fails loud at import (the per-member checksum catches it), never silently.

A **full** import of a **managed, dedicated/single-tenant** Postgres/MySQL/libsql database is
**atomic**: it restores into a not-yet-live shadow database, verifies it, then swaps it in only
after verification succeeds (a Postgres/MySQL database rename, or a libsql file rename) — any
failure tears the shadow down and leaves the live database untouched. The untrusted dump is applied
by a freshly-minted, import-scoped **non-superuser** role (Postgres/MySQL) or a confined SQLite
authorizer (libsql) — never the binding's own (superuser-grade, on a managed co-located server)
credential — closing an RCE-on-import hazard a crafted dump could otherwise exploit. This
atomic path does **not** cover: a **data-only** import, a **shared**-tenant managed database (even
on a full bundle), or an older pre-chunking bundle's managed dump — those are refused for a managed
target with a `501` explaining that a full, dedicated-bundle re-export (or an external,
bring-your-own-URL binding) is the way forward; a least-privilege data-only apply is a pending
follow-up. An **external** (bring-your-own-URL) database binding is unaffected by any of this — it
restores with the operator's own configured credential against the operator's own database (their
trust boundary, not boatramp's managed cluster).

A Postgres extension in the dump (e.g. `vector`/pgvector) is only created if it is on the operator's
[trusted-extension allowlist](./boatramp-cfg.md#handlers)
(`handlers.bindings.sql.migrate_trusted_extensions` — the same allowlist the
[in-app migration `extension` step](../how-to/in-app-migrations.md#enable-an-extension) uses); the
superuser maintenance connection pre-creates each allowlisted extension in the shadow before the
non-superuser apply runs, so the dump's own `CREATE EXTENSION IF NOT EXISTS` no-ops instead of
failing. An extension not on the allowlist fails the restore.

A bundle member is capped at **256 GiB**, and a whole bundle at **1 TiB** — fixed node limits, not
currently exposed as a config key or CLI flag. Exceeding either refuses the import with a `501`
naming the cap.

### Member-mismatch tolerance

By default, an import (either `/api/project-import` or the `clone/from` orchestrator below)
**hard-fails on the first member** whose streamed bytes disagree with its declared size/SHA-256
(a strict verify-then-apply). Three independent query params / body fields (shared by both
surfaces) relax that for the common "one stale re-generable derivative blocks a huge clone" case —
see [Recover from a mismatched/stale clone member](../how-to/clone-project.md#recover-from-a-mismatched-or-stale-clone-member)
for the worked recovery flow:

| Param (query on `project-import`, JSON field on `clone/from`) | Default | Effect |
| --- | --- | --- |
| `enumerate_mismatches` | `false` | **Assess scope.** Scan every member, record **every** mismatch (path + class `der`/`base`/`primary` + size/checksum, declared vs. streamed), apply nothing that mismatches, and fail at the end instead of at the first — so the caller learns the full scope in one pass. |
| `skip_member_mismatch` | `false` | **Tolerate.** Warn + continue past a mismatched member instead of hard-failing (the member is **not** applied — the target re-derives a skipped derivative on access). **Default-scoped to re-generable `der/` derivatives** — see the blob-key classification below; a baseline/primary/non-blob mismatch **still hard-fails**. Each tolerated skip is recorded in the returned `ImportReport.notes`. |
| `skip_any_blob_mismatch` | `false` | Broaden `skip_member_mismatch` from `der/`-only to **any** blob member (baselines + primaries too). Requires `skip_member_mismatch`. **Never** tolerates a non-blob (DB/KV/identity) member even so. |

`enumerate_mismatches` overrides `skip_member_mismatch` — an enumerate pass is always a pure
assessment (nothing is ever applied), never a mutation, even for a `der/`-class finding.

#### The `der`/`base` blob-key convention (guest-facing contract)

Which blob objects are safe to skip, bless, or purge is decided **structurally**, from the
object's storage key, by one shared classifier (`boatramp_core::blob_class`) — not by a flag the
caller sets. A key is classified by its `/`-separated path **components** (never a substring —
a segment `thunder` or `database` does **not** match):

- a component exactly `base` → **baseline** (load-bearing; never skipped/reconciled/purged without
  the explicit, audited `--include-primary`/`--skip-member-mismatch-any-blob` opt-in);
- else a component exactly `der` → **derivative** (re-generable — the only class tolerated by
  the *default* scope of clone skip, `blob reconcile`, and `blob purge --legacy-derivatives`);
- a key with **both** `base`/`der` has `base` win (the conservative bias — load-bearing wins ties);
- anything else → **primary** (an original/user object; load-bearing, same treatment as baseline).

This is a **contract your application must honor**, not an implementation detail: if a guest
stores load-bearing data under a literal `der` path component, that data becomes eligible to be
silently skipped on a tolerant clone, blessed (declared-size-rewritten) by a default `blob
reconcile`, or deleted by `blob purge --legacy-derivatives` — because the host can only tell a
re-generable derivative from load-bearing data by this path convention. Put **only** genuinely
re-generable derivatives (thumbnails, format transcodes, resized variants — anything your
application regenerates on a cache miss) under a `der/` component, and keep baselines/originals
under `base/` or any path with neither component.

### Streaming clone

A **streaming clone** pulls a project directly from a live **source** node into a **target** node,
restoring each member as it streams in — **no `BRPROJ` bundle is ever materialized** on an operator
disk or the source volume. The target fetches a cheap manifest (a blob LIST plus the non-blob member
paths — a list, not a body read), diffs it against its own content-addressed store, and pulls only
the members it is missing; a re-run re-diffs and transfers only the remainder (resumable), and blobs
flow bucket → bucket. All three endpoints are reached project-scoped as
`/api/projects/<proj>/clone/…` and are gated **`Project·Admin`** — the source surfaces on the source
project, the orchestrator on the target project (two Project·Admin authorizations, **no** node-global
`System·Admin`). They back `boatramp project import <target> --clone-from <source-url>`. Present with
the `project-export` feature.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/projects/<proj>/clone/manifest[?data_only=true\|false]` | **Source.** The cheap clone manifest — a LIST of the project's blob objects (each an `etag`/`size` content ref for the target's per-SHA presence diff) plus the non-blob member paths the stream will carry. No full materialization. `Project·Admin`. |
| `POST` | `/api/projects/<proj>/clone/stream[?data_only=true\|false]` | **Source.** Stream a format-v2/v3 bundle of exactly the members the target is missing — the request body is the target's skip set (the content-matched blob member paths to omit). `Project·Admin`. |
| `POST` | `/api/projects/<target>/clone/from` | **Target orchestrator.** Pull the project from a live source node: fetch its manifest, diff this node's store, and (on apply) pull the missing members over the stream and restore through the same atomic shadow path as an import (always a **fresh** identity; the target enforces its own project scope on every member). Body `{ source_url, source_project?, apply?, verify?, overwrite?, force?, data_only?, enumerate_mismatches?, skip_member_mismatch?, skip_any_blob_mismatch? }` — the last three are the [member-mismatch tolerance](#member-mismatch-tolerance) policy, same semantics as `project-import`; the operator's source-node Project-Admin bearer rides in the `X-Boatramp-Source-Token` header, and `source_url` must be an absolute **https** URL resolving to a public address (SSRF-guarded). The **default** (`apply=false`, `verify=false`) returns a cheap **`ClonePlan`** JSON (manifest + diff only — **no** stream, nothing restored). `apply=true` (or `verify=true`, the stream-level validate) returns an **NDJSON progress stream** (`application/x-ndjson`): a `plan` event, periodic `progress` heartbeats, then one terminal `report`/`error` event. `Project·Admin`. |

## Sites & deployments

The paths below target the `default` project; the `/api/projects/:project/sites/…`
counterparts are identical but scoped to `:project`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/sites` | List sites. |
| `POST` | `/api/sites/:site/deployments` | Create a deployment from a manifest. |
| `GET` | `/api/sites/:site/deployments` | List a site's deployments. |
| `GET` | `/api/sites/:site/deployments/:id` | Get one deployment. |
| `POST` | `/api/sites/:site/deployments/:id/activate` | Make a deployment the live one. |
| `GET` | `/api/sites/:site/current` | The currently active deployment. |
| `GET`/`PUT` | `/api/sites/:site/config` | Read / replace the [site config](./siteconfig.md). |
| `PUT`/`DELETE` | `/api/sites/:site/aliases/:name` | Manage named aliases. |
| `GET` | `/api/sites/:site/aliases` | List aliases. |

## Blobs

| Method | Path | Purpose |
| --- | --- | --- |
| `PUT` | `/api/blobs/:hash` | Upload a content-addressed blob (raw body; the server verifies the hash). |
| `POST` | `/api/blob-mint-upload` | Mint a scoped, short-lived S3 upload credential for a project+site's blob container (`blob_upload` · `write`, `blob-upload` feature). See [Direct-to-storage blob ingress](../how-to/blob-ingress.md). |

### Blob-backend migration (node-level)

Complete a zero-downtime blob-backend switch on a managed node reachable only over the
control plane (no `fly ssh` / local shell). These operate on the node's **own** configured
blob store — never a client-named backend — so they are gated at `system` · `admin` (the
destructive drain/purge) or `system` · `read` (the status probe), like `prune` / `scrub` /
`sql-move`. The singular hyphenated paths (`blob-drain`, `blob-status`, `blob-purge`)
deliberately do **not** collide with the `/api/blobs/…` (`Blobs` · `Deploy`) content-upload
matcher, so a ship-only publisher can never reach them.

#### `POST /api/blob-drain`

Since 0.6.3. Drain the node's own configured `[serve].blob_fallback` read-fallback
**secondary → primary** (`Storage::drain_pair` on the live composite), so the fallback can be
removed. The client guides; the running daemon (which already holds both backends open)
executes. `system` · `admin`.

The body names **no** source or destination — the daemon drains only its own configured pair:

```json
{ "dry_run": false, "concurrency": 8, "prefix": "" }
```

All fields are optional (`deny_unknown_fields`); `dry_run` defaults to `false`, `concurrency`
to the engine default (8), an absent/empty `prefix` drains every object.

The response is an **NDJSON** stream (`application/x-ndjson`) — one JSON object per line — kept
alive over a chunked connection so an edge idle-timeout can't cut a long copy (the copy is
idempotent and resumable, so a dropped connection is safe to re-run). Progress lines are tagged
`"type":"progress"`; the final line is tagged `"type":"report"`:

```
{"type":"progress","done":2,"total":3,"copied":2,"skipped":0,"copied_bytes":4096,"dry_run":false}
{"type":"report","total_objects":3,"copied_objects":3,"skipped_objects":0,"copied_bytes":6144,"verified":true,"dry_run":false,"secondary_drained":true,"message":"SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node."}
```

`secondary_drained` is `true` **only** on a verified-complete, non-dry-run drain. A verify
failure reports `secondary_drained:false` plus the missing keys. With no `[serve].blob_fallback`
configured, the request is a **422** (`{ "error": "no blob_fallback configured; nothing to drain" }`).

#### `GET /api/blob-status`

Since 0.6.4. Query the node's structured transition-mode state — whether a read-fallback
secondary is currently attached (the node is mid-migration) — instead of grepping the startup
log warning. `system` · `read`.

```json
{ "blob_fallback_active": true }
```

#### `POST /api/blob-purge`

Since 0.6.4 (`legacy_derivatives` mode: v0.50.0). Reclaim a **provably-safe-only** object set on
the node's blob store. Dry-run by default (report only, delete nothing); `apply: true` deletes.
`system` · `admin`.

```json
{ "mode": "unreferenced", "apply": false, "prefix": "" }
```

`deny_unknown_fields`. `mode` is required and is one of:

- `"unreferenced"` — on-demand garbage collection: delete content-addressed blobs no live
  deploy manifest references (nothing serving can break). Refused with **409** while a
  read-fallback secondary is attached (drain and drop `[serve].blob_fallback` first). `prefix`
  is ignored in this mode.
- `"drained_source"` — the migration decommission: delete the read-fallback secondary's objects
  that are **byte-confirmed present in the primary** (fail-closed — an unconfirmed object is
  kept). `prefix` restricts the scope. With no `[serve].blob_fallback` configured, the request is
  a **422**.
- `"legacy_derivatives"` — delete stale image derivatives of a **superseded format** (e.g. the
  pre-WEBP `.jpg` leftovers): deletes **only** `der/`-classified objects (see
  [the `der`/`base` convention](#member-mismatch-tolerance)) whose extension matches
  `superseded_ext`, under `prefix`. A referenced baseline/primary — even with the same extension —
  and the current-format derivative are **never** touched. `superseded_ext` is **required**; a
  missing or empty value is a **422** (`"legacy_derivatives purge requires a non-empty
  superseded_ext … refusing a blanket derivative delete"`), never a blanket delete.

```json
{ "mode": "legacy_derivatives", "apply": false, "prefix": "hblob/acme/", "superseded_ext": "jpg" }
```

The response is **NDJSON** (progress lines then a final `"type":"report"` line), the same shape
as the drain:

```
{"type":"report","mode":"drained_source","apply":true,"considered":3,"purged":1,"would_purge":0,"skipped_unconfirmed":2,"purged_bytes":17,"message":"drained-source purge complete: reclaimed 1 confirmed-duplicated object(s) (17 byte(s)); kept 2 unconfirmed"}
{"type":"report","mode":"legacy_derivatives","apply":true,"considered":4200,"purged":12,"would_purge":0,"skipped_not_superseded":4188,"bytes_purged":98765,"message":"legacy-derivative purge complete: purged 12 superseded der/ object(s) (98765 byte(s)); kept 4188 non-superseded object(s)"}
```

See [Migrate the blob backend](../how-to/blob-backend-migration.md).

#### `GET /api/blob-verify`

Blob integrity report. Read-only, `system` · `read`. Two classes:

```json
{ "dead_references": [ { "hash": "<sha256>", "referrer": "acme/blog" } ],
  "size_mismatches": [ { "hash": "<sha256>", "referrer": "acme/blog", "declared": 48213, "stored": 12345 } ] }
```

- `dead_references` — a blob a live site deployment or function references that is **missing**
  from the backend (would `404` on invoke/serve) — unchanged since this endpoint shipped.
- `size_mismatches` (**v0.50.0**) — a **referenced** blob whose manifest-declared size disagrees
  with what the backend actually stores. The serve path emits the *declared* size as
  `Content-Length`, so a shorter stored object streams a truncated/hung response — and this is
  exactly the index↔object drift that makes a streaming clone fail-closed (`stored` is `null`
  when the backend reports no size for an otherwise-present object; it is never dropped from the
  list on that account). Repair a `der/`-classified entry with `POST /api/blob-reconcile`; a
  baseline/primary entry signals a truncation/corruption to investigate.

#### `POST /api/blob-reconcile`

Since v0.50.0. **Guarded repair** for the `size_mismatches` class above: bless an index↔object
size drift by re-writing each in-scope object so its declared size matches its stored body.
Dry-run by default (report only, writes nothing); `apply: true` writes. `system` · `admin` — the
same node-destructive grade as `/api/blob-purge` (re-checked defense-in-depth in the handler, not
just the authz middleware); the singular hyphenated path cannot collide with the
`/api/blobs/` (`blobs` · `deploy`) content-upload matcher.

```json
{ "prefix": "", "apply": false, "include_primary": false }
```

`deny_unknown_fields`. **Default-scoped to re-generable `der/`-classified objects** (see
[the `der`/`base` convention](#member-mismatch-tolerance)); `include_primary: true` is the
**dangerous, audited opt-in** to also reconcile baseline/primary objects — it blesses a possible
truncation on load-bearing data, so use it only after confirming the drift is benign. Returns a
single JSON report (not NDJSON — a reconcile is a bounded one-pass operation):

```json
{ "apply": true, "include_primary": false, "considered": 4200, "drifted": 3, "reconciled": 3,
  "would_reconcile": 0, "skipped_out_of_scope": 1, "skipped_too_large": 0, "skipped_unreadable": 0,
  "bytes_reconciled": 9876 }
```

## Domains

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`/`POST`/`DELETE` | `/api/sites/:site/domains/:host/verification` | Manage a domain-ownership challenge. |
| `POST` | `/api/sites/:site/domains/:host/verification/check` | Check the challenge. |
| `GET` | `/api/sites/:site/domain-verifications` | List pending verifications. |
| `POST` | `/api/sites/:site/domains/:host/attach-unverified` | **`system·admin` only.** Attach a host WITHOUT an ownership proof (`domain add --unverified`). |
| `POST` | `/api/sites/:site/domains/:host/verify-records` | **`system·admin` only.** Verify a set of DNS records resolve as expected (read-only diagnostic; `domain verify-records`). |

## Tokens

| Method | Path | Purpose |
| --- | --- | --- |
| `POST`/`GET` | `/api/tokens` | Mint / list tokens. |
| `DELETE` | `/api/tokens/:id` | Revoke a token by its id. |
| `POST` | `/api/tokens/bootstrap` | Mint the first admin token with the single-use bootstrap secret. |
| `GET` | `/api/auth/whoami` | The presented token's own roles. |
| `POST` | `/api/auth/exchange` | Exchange an OIDC JWT for a short-TTL token (`oidc` feature). |

## Cluster

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/cluster/join-token` | Mint a single-use bearer mesh join token (admin). |
| `POST` | `/api/cluster/join` | Admit a joining node (gated by the join token in the body + a possession proof, not admin RBAC). |
| `GET` | `/api/cluster/members` | List the Raft membership (node, voter, caught-up, leader, address). |
| `POST` | `/api/cluster/promote` | Promote a caught-up learner to a voter (leader-only). |
| `POST` | `/api/cluster/rotate-key` | Rotate this node's mesh key (make-before-break). |
| `POST` | `/api/cluster/revoke` | Revoke a node from the mesh (durable tombstone + drop from quorum). |

See [Deploy a self-hosted cluster](../how-to/deploy-cluster.md) and
[Run on Kubernetes](../how-to/kubernetes.md).

## Overlay

The overlay forward-flow **discovery** surface — what backs self-serve
[`boatramp forward svc/<name>`](./cli.md#boatramp-forward) and
[`boatramp expose --server`](./cli.md#boatramp-expose). Explicit rights (not the
deny-safe `System·Admin` default) so an operator role can self-serve without full
node-admin. Present with the `overlay` feature.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/overlay/dial` | Resolve a service to its relay/egress topology and mint a holder-bound dial capability for it (signed by the node's root issuer, still scope-verified at the egress). `Overlay·Write`. |
| `POST` | `/api/overlay/expose` | Resolve this node's ingress-relay topology and mint a holder-bound **publish** capability for a service (self-serve `boatramp expose`). `Overlay·Admin` — strictly above dial's `Overlay·Write`, because publishing CLAIMS a name that forward clients trust and pin. |
| `GET` | `/api/overlay/services` | List the overlay service directory — the services you can `forward` to. `Overlay·Read`. |
| `POST` | `/api/overlay/invite` | Mint a single-use `overlay-enroll` invitation (role + service scope) + a `brojoin1.…` ticket for `boatramp overlay join`. `Overlay·Admin` — admitting a new identity into the overlay trust set is owner-grade, like publishing a name. |
| `POST` | `/api/overlay/enroll` | Redeem a `brojoin1.…` invitation: the enrollee proves possession of its overlay identity and is admitted into the relay's live trust set. **No right** — gated by the single-use invitation itself (like `/api/cluster/join`), not an admin bearer. |
| `POST` | `/api/overlay/pair-code` | Mint a single-use, short-TTL pairing **rendezvous** code (`bropair1…`, optionally also a human-typeable short code) so two peers that cannot direct-dial can meet through this node's ingress relay. `Overlay·Admin` — minting one stands up a relay rendezvous slot; `404` when this node runs no ingress relay (`[overlay] accept_exposed`). |
| `GET` | `/api/overlay/pair-relay` | Look up this cluster's pairing ingress-relay topology (relay address + identity) for the human-typeable **short-code** path, which carries no topology of its own. **No right** — the short-code dialer has no credential yet; this discloses only non-secret topology, never a capability. `404` with no ingress relay. |

The directory is a **merged view**: the static `[overlay]` routes ∪ the services
currently published by live `boatramp expose` exposers (when this node runs an
ingress relay accepting them). A dial to an exposed service resolves to an
`egress_id` that is the exposer identity the relay **verified at registration**
(holder-bound), delivered over this authenticated response; the forward client pins
exactly that id as its end-to-end peer, so the QUIC data plane can never substitute
the peer — a cross-wired flow fails the client's E2EE pin, never a silent
cross-wire. A live exposer wins a name collision with a static route.

The dial request names the service and the caller's overlay identity (an
`ed25519:<hex>` holder key); `ttl_secs` is optional and clamped to the node's
`[overlay].max_dial_ttl_secs`:

```json
{ "service": "svc/db", "holder_pubkey": "ed25519:<hex>", "ttl_secs": 3600 }
```

The response is the resolved topology plus the minted capability:

```json
{
  "relay": "10.0.0.1:9100",
  "relay_id": "ed25519:<relay-key>",
  "egress_id": "ed25519:<egress-key>",
  "relay_client_auth": "capability-only",
  "token": "<minted dial capability>",
  "expires_at": 1760000000
}
```

A node with no root private key cannot mint and returns `501`; an unknown service
is `404`; a non-`ed25519` `holder_pubkey` is `400`.

`POST /api/overlay/expose` mirrors `dial` for the reverse-ingress (publish)
direction. The request names the service to publish and the caller's overlay
identity; the response is this node's ingress-relay topology plus the minted
publish capability and the cluster trust root the exposer verifies incoming forward
clients against:

```json
{
  "relay": "10.0.0.1:9100",
  "relay_id": "ed25519:<relay-key>",
  "service": "svc/db",
  "token": "<minted publish capability>",
  "trust_root": "ed25519:<cluster-root-pub>",
  "relay_client_auth": "capability-only",
  "expires_at": 1760000000
}
```

A node with no root private key returns `501`; a node that runs no ingress relay
accepting exposed services (`[overlay] accept_exposed`) returns `404`; a
non-`ed25519` `holder_pubkey` is `400`. The relay still holder-binds and
scope-verifies the publish capability at registration — this route only gates WHO
may obtain one. See the [`[overlay]`](./boatramp-cfg.md#overlay) serve roles.

### Overlay pairing

Relay-blind rendezvous + a **commit-then-reveal** short authentication string (SAS), so two
operators' devices can mutually verify identities and detect an active man-in-the-middle, with no
reachable control plane needed for the handshake itself. `POST /api/overlay/pair-code` only stands
up the meeting point; the pairing handshake + SAS derivation happen directly between the two peers
(direct dial or through the relay, which bridges only ciphertext).

`POST /api/overlay/pair-code` request (all optional):

```json
{ "ttl_secs": 300, "short": false, "accepter_pubkey": "ed25519:<hex>" }
```

`ttl_secs` defaults to 300s, clamped to a 600s ceiling (a pairing code is a short-lived meeting
credential, never a long-lived one — redemption is unauthenticated by design, so a code must not
stand open for long). `short` also mints a human-typeable short code (digit count set by
[`[overlay] pair_short_code_digits`](./boatramp-cfg.md#overlay)) aliasing the same rendezvous.
`accepter_pubkey` (the accepter's `ed25519:<hex>` overlay identity) is **required** only when this
relay runs `[overlay] pairing_park = "authenticated"`, in which case the response also mints a
holder-bound `overlay-pairing-park` capability for that key — ignored (and optional) against the
default OPEN-mode relay. The response:

```json
{
  "relay": "10.0.0.1:9100",
  "relay_id": "ed25519:<relay-key>",
  "rendezvous": "<hex rendezvous id>",
  "expires_at": 1760000300,
  "short_code": "1234-5678",
  "park_cap": "<COSE overlay-pairing-park capability>"
}
```

`short_code`/`park_cap` are present only when requested/applicable. A node with no root private key
returns `501` (only when `accepter_pubkey` is given, i.e. authenticated-park mode); a node that
accepts no ingress-relay rendezvous (`[overlay] accept_exposed`) returns `404`.

`GET /api/overlay/pair-relay` is the companion lookup for the short-code path (a short code, unlike
`bropair1…`, carries no topology of its own): it returns `{ "relay": "...", "relay_id": "..." }`
with no authentication required — the short-code dialer has no credential yet, and this discloses
only non-secret topology (the same values every authenticated pair-code/expose mint already
returns), never a capability. `404` with no ingress relay.

A **leaked pairing code only lets someone race to redeem it** ahead of the legitimate peer — not
forge a matching SAS: whoever ends up on the other end of the handshake still has to produce a SAS
that matches what the legitimate peer expects, and a relay-in-the-middle's two independent
handshake legs necessarily diverge. See [`boatramp overlay pair` / `pair-code`](./cli.md#boatramp-overlay)
for the full pairing walkthrough.

### Overlay flow policy

An optional, operator-authored **per-flow access policy** (a Cedar policy in its own
`Overlay` namespace) that gates the dial/publish-cap **mint** above — **deny-or-shrink-TTL
only**, and **separate** from the RBAC right that grants `Overlay·Write`/`Admin`. All three
verbs are gated `System·Admin` (the `GET`/`test` surfaces are a policy-enumeration oracle, so
they sit with `PUT` at the top tier).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/overlay/policy` | Return the active flow policy (Cedar text) + its version (`ETag`). `System·Admin`. |
| `PUT` | `/api/overlay/policy` | Replace the policy (validated on PUT: parse + schema + a single `not_after` temporal bound; `400` verbatim otherwise). `If-Match`/`409` CAS. An empty body turns the gate off. `System·Admin`. |
| `POST` | `/api/overlay/policy/test` | Dry-run a dial/expose mint against the active (or an inline) policy — ALLOW/DENY + TTL ceiling + deciding policies + diagnostics. **No mint.** `System·Admin`. |

Posture (four states): absent **or** empty ⇒ the gate is **off** (allow, preserving pre-feature
behavior); a present policy ⇒ evaluated (Cedar default-deny within — the FIRST stored policy is a
default-deny cliff, so `PUT` warns); corrupt ⇒ fail-closed deny-all; the store unreadable ⇒
fail-closed deny. A denied mint returns `403 flow denied by policy` (deliberately non-enumerable —
use `test` for detail). The policy can only **deny** a mint RBAC already permitted, or pull its TTL
**down** (`ttl = min(requested, policy_ceiling, server_max)`); it never rewrites the minted
capability's scope or holder.

The flow principal `Overlay::Holder` carries `role`/`scope`/`enrolled` **only** when the dial/expose
request presents a root-signed `overlay-member` credential bound to the holder key (`member_key ==
holder_pubkey`, else `400`); a key-only holder has none of them (default-deny-safe). Because the
minted capability is offline-verified, the gate has no real-time revocation, rate/quota, or
concurrent-session limit — a tightening is bounded by the capability TTL (set
`[overlay].max_dial_ttl_secs` to your acceptable revocation latency), and only a single `not_after`
(`context.now <= N`) temporal bound is allowed.

A policy rule can also scope to the **node** actually serving the flow: the `Overlay::Service`
resource is a member of `Overlay::Node`, populated from the mint's resolved target — the dial's
`egress_id`, or the expose relay's `relay_id` — so `resource in Overlay::Node::"<id>"` restricts a
rule to one serving node regardless of which service name reaches it (an absent/unresolved node
simply never matches a node-scoped rule — default-deny-safe). Combine it with a
`resource == Overlay::Service::"<name>"` check, or use it alone to gate every service a given node
fronts. Preview a node-scoped rule with the console's policy "Node (optional)" test field (the CLI's
`overlay policy test` has no `--node` flag yet).

## Root anchors

Make-before-break root-key rotation (`auth rotate-root`). Admin-scoped.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/auth/root` | List the extra trusted root anchors. |
| `PUT` | `/api/auth/root` | Trust a new root anchor (`{ "pubkey": "alg:hex" }`). |
| `DELETE` | `/api/auth/root/:pubkey` | Retire a root anchor. |

See [Migrate the root key](../how-to/migrate-root-key.md).

## Certificates & cache

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/certs` | TLS certificate status. |
| `POST` | `/api/cache/invalidate` | Invalidate cached responses. |

## Operations

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`/`POST` | `/api/prune` | Report / delete unreferenced deployments. |
| `POST` | `/api/scrub` | Delete unreferenced blobs. |
| `GET` | `/api/metrics` | Prometheus exposition (always available). |
| `GET`/`PUT` | `/api/authz/policy` | Read / replace the [RBAC policy](./rbac.md#the-policy-document). |

## Functions & workflows

Top-level (`default`-project) function and workflow endpoints; the
`/api/projects/:project/…` counterparts scope to another project.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/functions` | List functions. |
| `PUT`/`DELETE` | `/api/functions/:name` | Manage one function — `PUT` deploys/replaces the current version. |
| `POST` | `/api/functions/:name/rollback` | Roll back to a prior version. |
| `PUT` | `/api/functions/:name/aliases/:label` | Manage a version alias. |
| `POST` | `/api/functions/:name/invoke` | Invoke synchronously / async / scheduled. |
| `GET` | `/api/functions/:name/invocations/:id` | Get an async invocation record. |
| `GET`/`PUT`/`DELETE` | `/api/functions/:name/triggers[/:id]` | Manage event triggers (webhook/queue/cron/blob) — create/update via `PUT` on `/:id`. |
| `GET` | `/api/functions/:name/usage` | Metering / quota counters. |
| `GET`/`PUT`/`DELETE` | `/api/workflows/:name` | Manage a declarative workflow. |
| `POST` | `/api/workflows/:name/runs` | Start a workflow run. |
| `GET` | `/api/workflows/:name/runs/:id` | Get one workflow run. |

## Compute

Top-level paths target the `default` project; `/api/projects/:project/compute/…`
scopes to another project.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/compute` | List compute workloads. |
| `GET`/`PUT`/`DELETE` | `/api/compute/:name` | Manage one workload. |
| `POST` | `/api/compute/:name/exec` | Run a command inside a running replica (docker-exec style; posture-gated by `allow_compute_exec`). Since 0.3.9. |
| `POST` | `/api/compute/dev-bind-blob` | Mint a blob-shim `BOATRAMP_BLOB_URL` + token for a non-managed local process (dev/CI). System·Admin; posture-gated by `allow_dev_blob_bind`. |
| `POST` | `/api/compute/dev-bind-messaging` | Mint a messaging-shim `BOATRAMP_MESSAGING_URL` + token (publish AND consume) for a non-managed local process (dev/CI). System·Admin; posture-gated by `allow_dev_messaging_bind`. |

The control-plane surface is uniform whether or not execution is available on the
node. Only the **microVM** backend needs `/dev/kvm`; the native **container** backend
instead needs the `br-boatramp` bridge and `CAP_NET_ADMIN` (both compute backends are
Linux-only). On macOS / Windows compute runs through the remote-docker backend. See
[Run compute workloads](../how-to/compute.md).

### Compute operations (node-global)

These operate across **every** tenant on the node and are gated at `system` · `admin`
— not the per-project `/api/compute/*` right. Since 0.3.9 (volumes: 0.3.11;
maintenance/diagnostics: 0.3.14).

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/compute/volumes` | List persistent volumes (in-use vs orphaned). |
| `DELETE` | `/api/compute/volumes/:name` | Reclaim a volume (`?force=true` to remove one still referenced). |
| `GET` | `/api/compute/status` | Observed per-replica runtime state (health, lifecycle phase, IP:port, backend). |
| `GET` | `/api/compute/ipam` | The compute-bridge IP-pool allocation. |
| `GET` | `/api/compute/dns` | The internal-DNS fleet view. |
| `POST` | `/api/compute/dns/resolve` | Resolve an internal name as a container would (diagnostic). |
| `POST` | `/api/compute/reconcile` | Force a reconcile pass. |
| `POST` | `/api/compute/maintenance/set-health` | Override a replica's stored health. |
| `POST` | `/api/compute/maintenance/restart` | Stop + relaunch a replica. |
| `POST` | `/api/compute/maintenance/netdiag` | Run a network diagnostic. |
| `POST` | `/api/compute/maintenance/reap` | Reap orphaned replicas (no desired workload + no live container). Destructive; **dry-run unless** the body sets `dry_run: false`. Body `{ project?, workload?, replica?, dry_run?, grace_secs?, reclaim_volumes? }` — a targeted reap needs all of `project`+`workload`+`replica`, else it scans every project. Fail-closed (never reaps a live/desired replica). `501` when the node has no reaper. |
| `GET`/`POST`/`DELETE` | `/api/compute/registry-auth[/<name>]` | Operator node-wide registry pull credentials (`[compute].registry_auth`): `GET /api/compute/registry-auth` lists names + metadata, `POST` seals/rotates a `{username,password}` under a `name`, `DELETE /api/compute/registry-auth/<name>` removes one. The credential value is never returned. |

See [Diagnose compute](../how-to/diagnose-compute.md).

## Managed SQL (operator)

Run a migration script or a single query against a managed co-located database via
its sealed credential (resolved server-side). Project-owned (`project` · `deploy`);
writes are additionally posture-gated. Top-level paths target the `default` project;
`/api/projects/:project/sql/…` scopes to another project. Since 0.3.9 (`ping`: 0.3.14;
`sql-move`: 0.5.0).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/sql/:db/exec` | Run a migration / statement script against the managed database `:db`. |
| `POST` | `/api/sql/:db/query` | Run a single query and return its rows. |
| `POST` | `/api/sql/:db/ping` | Active per-replica reachability probe (bypasses the stored-health gate). |
| `POST` | `/api/sql-move` | Relocate a libsql database to a new binding name, data intact — body `{project, site, from, to}`. Node-level `system` · `admin` (not this table's `project` · `deploy`); local single-node only, a remote/sqld backend is refused `422`. Backs `boatramp sql move`. |

## Schema migrations (owner-gated)

Apply an ordered migration step set — `function` / `sql` / `extension` steps — to a
managed database `:db`, run as the project's non-superuser **owner** role and tracked in
a host-owned ledger. Input is **upload-then-trigger**: the JSON step-set bundle is
uploaded via `PUT /api/blobs/:hash` and referenced by hash. The mutating verbs are gated
at `project` · `admin` (never the deploy-grade publisher right `/api/sql/` uses); `status`
needs only `project` · `read`. Top-level paths target the `default` project;
`/api/projects/:project/migrate/…` scopes to another project. Since 0.4.25 (Postgres only).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/migrate/:db/apply` | Apply the pending suffix of the bundle; body `{ bundle }`. `project` · `admin`. |
| `POST` | `/api/migrate/:db/dry-run` | Report which ids would apply, running nothing; body `{ bundle }`. `project` · `admin`. |
| `POST` | `/api/migrate/:db/baseline` | Record the prefix through `up_to` as already-applied without running it; body `{ bundle, up_to }`. `project` · `admin`. |
| `GET` | `/api/migrate/:db/status` | Read the applied-migration ledger (id, ordinal, hash, kind, applied-at, origin). `project` · `read`. |

See [Run owner-gated schema migrations](../how-to/in-app-migrations.md).

## Provisioning drift-repair (owner-gated)

Converge a managed database's provisioning against spec — create/seal the non-superuser owner
role, re-own the database + its objects + the migration ledger, re-grant runtime privileges —
idempotently and data-preservingly (`boatramp project repair`). Deliberately **not** under
`/api/sql/` (whose catch-all resolves to `project` · `deploy`, which a ship-only publisher holds
— nesting there would be an escalation); its own `/api/repair/*` prefix gates **both** verbs at
`project` · `admin`. Dry-run is the report-only posture the CLI uses by default. Top-level paths
target the `default` project; `/api/projects/:project/repair/…` scopes to another project. Since
0.5.2 (all SQL backends).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/repair/:db` | Apply the reconcile — converge provisioning against spec. `project` · `admin`. |
| `POST` | `/api/repair/:db/dry-run` | Drift-detect + report the plan, changing nothing (the default CLI posture). `project` · `admin`. |

## Managed databases (declarative)

The project-scoped declarative front door onto the daemon-level managed-database provisioning
stack (a per-tenant Postgres/MySQL whose credential boatramp mints and seals). These back
`boatramp db ls | get | status` and the `apply`-manifest `databases:` block; there is no
`db create` — the manifest is the sole authoring surface. Declaring a database mints owner-role
identities (`CREATE ROLE` / owner-role DDL as superuser), so the write verbs gate at
`project` · `admin` — the same owner-grade placement as `/api/migrate/` and `/api/repair/`, above
the project-deploy catch-all, so a `project_publisher` / deployer can never reach them; the reads
are `project` · `read`. Top-level paths target the `default` project;
`/api/projects/:project/databases/…` scopes to another project. Since 0.6.0.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/databases` | List the project's declared databases (each an `ApplyDatabase`). `project` · `read`. |
| `GET` | `/api/databases/:name` | Get one declared database, or `404`. `project` · `read`. |
| `PUT` | `/api/databases/:name` | Declare (persist + eagerly provision) a database from an `ApplyDatabase` body. `204` on success. `project` · `admin`. |
| `POST` | `/api/databases/:name/ensure` | Re-provision an already-declared database idempotently. `204`. `project` · `admin`. |
| `GET` | `/api/databases/:name/status` | The stored declaration + the workload's live **readiness** (`starting` / `service-ready` / `provisioned` / `provision-failed`, distinct from bare TCP health), plus a **`data_dir`** ownership signal (`ok` + a sample foreign-owned entry) when a replica is stuck up-but-not-answering because its data directory carries foreign-owned files — the filesystem fault `/api/repair` does not cover — and a **`pending_restart`** flag (a staged restart-requiring config change, e.g. a flipped `delta_capture`, not yet applied — clear it with `POST …/restart`). `project` · `read`. |
| `POST` | `/api/databases/:name/users/:user/ensure` | Operator-provision (idempotent) a login role `:user` on the managed database (mailroom C2). The host mints + seals a password by default, or binds a bring-your-own one from a sealed secret (see `boatramp db ensure user`). On a shared cluster the role name is per-tenant-qualified so it can't collide across tenants. `project` · `admin`. |
| `DELETE` | `/api/databases/:name/users/:user` | Drop the login role `:user` (idempotent — absent ⇒ still `204`). `project` · `admin`. |
| `POST` | `/api/databases/:name/restart` | Restart a **dedicated, project-scoped** managed database — stop its replica so the reconcile loop relaunches it fresh (same data volume), applying any staged restart-requiring config change (e.g. a flipped `delta_capture`). Returns JSON `{workload, config_applied, replicas_restarted}`. A shared-tenant/site-scoped/BYO binding is refused. `project` · `admin`. |

The `PUT` body is a typed `ApplyDatabase` (`deny_unknown_fields`) — a **safe projection** that
carries only the fields a project author may declare. Naming an excluded field (`image`,
`password_env` / `url_env` / `read_url_env` / `migration_url_env`, `path`, `compute`) fails to
parse — those are the security contract (arbitrary-image RCE, BYO-secret/SSRF, host-fs traversal,
author-named workload). The credential is never carried or referenced; boatramp fully manages and
seals it.

```json
{
  "name": "app",
  "kind": "postgres",
  "version": 16,
  "size": "medium",
  "tenant": "shared",
  "tenant_scope": "project",
  "extensions": ["pgcrypto"],
  "rls_session": true,
  "tenant_guc": "app.tenant_id"
}
```

Only `name` and `kind` (`postgres` / `mysql`) are required. `size` is a `small` / `medium` /
`large` preset (default `small`, → bounded vcpus/mem/volume, not raw VM knobs); `tenant` is
`single` (default) / `shared`; `tenant_scope` is `project` (default) / `site`. The remaining
optional fields — `version`, `extensions`, `read_only`, the RLS knobs (`rls_session`, `tenant_guc`,
`session_guc`, `tenant_all_marker`), and the capped `pool_max` / `connect_timeout_secs` /
`startup_grace_secs` — are omitted from a response when unset.

`GET /api/databases` returns a JSON array of `ApplyDatabase`; `GET /api/databases/:name` returns
one. `GET /api/databases/:name/status` wraps the declaration with a workload handle and a coarse
provisioned fact (never a secret):

```json
{
  "database": { "name": "app", "kind": "postgres", "size": "medium", "tenant": "shared", "tenant_scope": "project" },
  "workload": "bramp-db-<project>-app",
  "declared": true
}
```

The declarative `databases:` manifest block that drives these routes is covered under
[Declare a managed database](../how-to/managed-databases.md); see also [Apply a manifest](../how-to/apply.md).

## Secrets & email profiles

Project-scoped credential stores, gated by the `secrets` right (see
[RBAC](./rbac.md#request-to-right-mapping)). A value never leaves over the API — the
list/show responses are metadata-only (secrets) or redacted (email). Present only
when a `[secrets]` key envelope is configured (else a clear `501`). Secrets since
0.3.10; email profiles since 0.3.18.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/projects/:project/secrets` | Set (seal) a secret `{ name, value }`; returns metadata, never the value. |
| `GET` | `/api/projects/:project/secrets` | List secret names + metadata (no values). |
| `DELETE` | `/api/projects/:project/secrets/:name` | Delete a secret. |
| `PUT` | `/api/projects/:project/email/profiles/:name` | Set / partial-update an SMTP profile (sealed password); returns the redacted profile. |
| `GET` | `/api/projects/:project/email/profiles[/:name]` | List / show email profiles (redacted). |
| `DELETE` | `/api/projects/:project/email/profiles/:name` | Delete an email profile. |
| `PUT` | `/api/projects/:project/tenant-secrets/:tenant/:name` | Seal a **per-tenant** secret (e.g. a firm's own third-party OAuth `client_secret`); returns metadata, never the value. |
| `GET` | `/api/projects/:project/tenant-secrets/:tenant` | List one tenant's secret names + metadata (never project-wide — no cross-tenant name oracle). |
| `DELETE` | `/api/projects/:project/tenant-secrets/:tenant/:name` | Delete a tenant's secret. |

See [Store secrets](../how-to/secrets.md) and [Send email](../how-to/send-email.md).

## Tenancy schema

The project's per-table tenant-key map — the isolation boundary that scopes every
guest query. Read with `project` · `read`; replace/clear with `project` · `admin`
(above the publisher's deploy right, so a publisher cannot redraw the boundary).
Since 0.4.3.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/projects/:project/tenancy` | Read the tenancy schema. |
| `PUT` | `/api/projects/:project/tenancy` | Replace the tenancy schema. |
| `DELETE` | `/api/projects/:project/tenancy` | Clear it (back to deny-by-default). |

See [Isolate tenants](../how-to/tenant-isolation.md).

## GraphQL

The subgraph registry, the operation safelist, and the composed supergraph — a
project-owned surface. Top-level paths target the `default` project;
`/api/projects/:project/graphql/…` scopes to another project. See
[Serve a GraphQL API](../how-to/graphql.md).

| Method | Path | Purpose |
| --- | --- | --- |
| `PUT`/`DELETE` | `/api/graphql/subgraphs/:name` | Register (SDL body) / unregister a subgraph; a publish recomposes and is rejected if it doesn't compose — unless `?compose=defer` **stages** it (writes the SDL without composing). |
| `PUT` | `/api/graphql/subgraphs/:name/sql` | Register a SQL-backed subgraph by introspecting a site's managed database. |
| `PUT` | `/api/graphql/subgraphs/:name/function` | Register a function-backed subgraph by introspecting its `_service { sdl }`. |
| `POST` | `/api/graphql/compose` | Batch-compose every **staged** (`?compose=defer`) subgraph: validates the whole set once and promotes it live in a single version bump — for an `apply` that deploys several subgraphs together without an intermediate broken-compose state. |
| `GET` | `/api/graphql/supergraph` | The composed supergraph (subgraphs, `@key` entities, root fields). |
| `POST`/`GET` | `/api/graphql/safelist` | Register a trusted operation (returns its hash) / list the safelist. |
| `DELETE` | `/api/graphql/safelist/:hash` | Remove an operation from the safelist. |

A function that self-declares a subgraph auto-registers on deploy; pass
`?register_subgraph=false` to `PUT /api/functions/:name` to opt a deploy out. See
[Federation](../how-to/graphql.md#federation).

## Observability

Present with the `handlers` feature.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/node-health` | Node-global health snapshot (`System·Read`): `/data` filesystem headroom (`data_*` + a per-subdir `data_breakdown`) plus `replicas_unhealthy` — every replica `phase=running` but `HEALTHY=NO` (the reachable-but-not-served signature), the same signal the [alerting loop](../how-to/node-health-alerting.md) pages on. |
| `GET` | `/api/instance-stats` | Node-global handler-runtime stats (`System·Read`): warm-cache capacity/evictions, lane occupancy, and the per-phase serve timings. |
| `GET` | `/api/sites/:site/_boatramp/handlers` | Per-handler operator stats. |
| `GET` | `/api/sites/:site/_boatramp/logs` | Captured per-site guest logs. |
| `GET` | `/api/sites/:site/_boatramp/logs/stream` | Stream per-site logs (SSE). |
| `POST` | `/api/sites/:site/_boatramp/dlq` | Dead-letter-queue operations. |
| `GET`/`POST` | `/api/projects/:project/_boatramp/bus/dlq` | Shared **project-bus** DLQ: inspect (`Project·Read`) / purge·redrive·discard (`Project·Admin`). Since 0.4.24. |
| `GET` | `/api/projects/:project/_boatramp/bus/queue/{peek,replay,groups}` | Project-bus live-queue inspection (`Project·Read`). Since 0.4.24. |
| `POST` | `/api/projects/:project/_boatramp/bus/queue/{group,pause}` | Project-bus group reset·delete / pause·resume (`Project·Admin`). Since 0.4.24. |
| `GET` | `/api/functions/:name/_boatramp/logs` | Captured per-function guest logs (project-owned read). Since 0.3.17. |
| `GET` | `/api/functions/:name/_boatramp/logs/stream` | Stream per-function logs (SSE). Since 0.3.17. |

The function-logs endpoints have a `/api/projects/:project/functions/…` counterpart
scoped to another project. See [Observe a running server](../how-to/observe.md).

## Agent (MCP)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST`/`GET`/`DELETE` | `/mcp` | [Model Context Protocol](../how-to/mcp.md#over-http) endpoint (streamable-http), for driving this node from an AI agent. |

Unlike `/api/*`, `/mcp` is gated only by a **valid plain bearer** (not a specific
right): each MCP tool call is separately re-authorized in-process against the
forwarded token's scope. On by default; toggle with `mcp.enabled`
([daemon config](./daemon-config.md)). `cnf`/DPoP tokens are rejected — use a plain
bearer or the stdio transport.

## Public (unauthenticated) endpoints

Never token-authenticated. Visitor access control (basic auth / IP rules / rate
limit) is applied per-site inside the serving handlers.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness. |
| `GET` | `/readyz` | Readiness. |
| any | `/` (host-routed) | Serve site content, selected by `Host` — see [How a request reaches your site](../explanation/addressing.md). |
| any | `/_sites/<name>/*` | Serve a site by name (admin/testing). |
| `GET` | `/_deploy/*` | Serve a deployment by id (an unguessable content-hash capability). |
| `GET` | `/.well-known/boatramp-domain-verification/:token` | Serve a pending HTTP domain-ownership challenge token, ahead of host routing, so an unattached host can verify itself. See [Attach a custom domain](../how-to/custom-domain.md). |
| `GET` | `/.well-known/boatramp-bootstrap-identity` | The root-key-signed attestation of this node's `--tls rpk` control-plane TLS key (`404` when none is set). See [Reach the control plane on day zero](../how-to/bootstrap-tls.md). |
| `POST` | `/_webhooks/:name` | Signed inbound-webhook ingress for a function (`handlers` feature) — **signature-gated, not token-gated**: the request's own signature is verified before the function runs. See [Functions](../how-to/functions.md). |
