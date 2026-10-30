# Export, import & clone a project

A project's state — its managed-database contents, its control-plane KV slice, and its
blobs — can be streamed off a running node as a single portable **BRPROJ bundle**, then
imported into a project on the same node or a different one. This is how you **clone** a
project into another environment (staging → prod, a per-customer copy) or recover one.

Both verbs run against a **running node** and are gated at **`Project·Admin` on the `?project=`
target** — self-serve for a project's own admin (a Project·Admin for project X can export/import X,
never another project Y), **not** node-global `System·Admin`. A project publisher or deployer still
cannot reach them.

## Export a bundle

```console
$ boatramp project export acme --out acme.brproj --server https://cp.acme.com
```

| Flag | Default | Description |
| --- | --- | --- |
| `--out <file>` | — | Write the BRPROJ bundle to this file (required). |
| `--full` | data-only | Export a **full** bundle (schema + data). The default is **data-only**: application data only — no identity, RBAC, or routing. |
| `--include-identity` | off | Include the project KEK (passphrase-wrapped) for a **same-environment recovery**. Implies `--full` and needs a transport key (`--transport-key-file`, else `BOATRAMP_EXPORT_TRANSPORT_KEY`, else an interactive prompt). Local KEK envelopes only. |
| `--transport-key-file <FILE>` | — | File holding the transport passphrase that wraps the identity container. |

Server seam: `POST /api/project-export` (streams the bundle out).

### Ship only what changed (incremental & true-delta)

To keep a staging/DR copy **in step** with production without re-shipping the whole project each
time, take a **delta** export — it carries only the control-plane KV upserts/tombstones, the
new/changed blobs, and (for an opted-in managed SQL database) the **row-level changes** since a
base. A delta is written as a node-local **resumable** directory and chains onto a base with
`--resumable <dir> --mode incremental --base <dir>`. See
[Incremental & true-delta export](./delta-export.md) for the full flow, the three SQL engines
and their modes, the `delta_capture` opt-in + restart, and the security/scope limits.

## Import a bundle

Import is a **dry-run plan by default** — it mutates nothing until you pass `--apply`.

```console
$ boatramp project import acme-copy --in acme.brproj --server https://cp.acme.com   # plan only
$ boatramp project import acme-copy --in acme.brproj --apply --server https://cp.acme.com
```

| Flag | Default | Description |
| --- | --- | --- |
| `--in <file>` | — | The bundle file to import (required). |
| `--apply` | dry-run | Execute the import (default: a plan that mutates nothing). |
| `--force` | off | Overlay a **non-empty** control-plane KV destination (the commingle override; only meaningful for a full bundle). |
| `--overwrite` | off | Replace an **existing** target project (one that already holds its own KV/blob data). Default off — a clone into a fresh target is the safe default; this is opt-in. |
| `--allow-schema-skew` | off | Proceed despite a Postgres schema-ledger fingerprint mismatch between the bundle and the target. |
| `--identity <fresh\|adopt>` | `fresh` | `fresh` — the target mints its own identity and source-sealed secrets are dropped. `adopt` — install the bundle's KEK for a same-environment recovery (requires a transport key). |
| `--transport-key-file <FILE>` | — | File holding the transport passphrase (for `--identity adopt`). Falls back to `BOATRAMP_EXPORT_TRANSPORT_KEY`, then an interactive prompt. |
| `--enumerate-mismatches` | off | **Assess scope**: scan every member, report every declared≠streamed integrity mismatch (path + class), apply nothing that mismatches, and fail at the end. See [Recover from a mismatched/stale clone member](#recover-from-a-mismatched-or-stale-clone-member). |
| `--skip-member-mismatch` | off | Warn + continue past a mismatched member instead of hard-failing, scoped to re-generable `der/` derivatives by default. See below. |
| `--skip-member-mismatch-any-blob` | off | Broaden `--skip-member-mismatch` to any blob member (never non-blob). Requires `--skip-member-mismatch`. See below. |

Server seam: `POST /api/project-import`. (The three member-mismatch flags are **not** accepted
with `--resumable`.)

## Clone a project (via a bundle)

The simplest clone is an **export followed by an import** into a new project name — it stages a
whole `BRPROJ` bundle on the operator's disk between the two steps (for a large project, prefer
the [streaming clone](#streaming-clone-pull-from-a-live-source-node) below, which stages nothing):

```console
$ boatramp project export acme --out acme.brproj --server https://cp.acme.com
$ boatramp project import acme-staging --in acme.brproj --apply --server https://cp.acme.com
```

Clone the **data only** (the default bundle) when copying application data into a fresh
project — the target keeps its own identity, RBAC, and routing. For a **same-environment
recovery** of the original project (identity intact), export with `--full
--include-identity` and import with `--identity adopt`.

## Streaming clone (pull from a live source node)

A **streaming clone** pulls a project directly from a live **source** node into the **target** node
you run the command against, restoring each member as it streams in. Nothing is staged whole: there
is **no 33 GB `BRPROJ` bundle** parked on an operator disk (as the bundle clone above needs) or
written out as a member-object directory on the source volume (as a resumable export needs) — the
bytes flow source → target and land in the target's own stores as they arrive.

```console
$ boatramp project import acme \
    --clone-from https://src.acme.com \
    --clone-source-token-file ./src-admin.token \
    --apply --server https://dst.acme.com
```

`--clone-from` turns `project import` into a third mode (alongside `--in <file>` and
`--resumable <dir>`, and mutually exclusive with both). Like every import it is a **dry-run by
default** — add `--apply` to execute.

| Flag | Default | Description |
| --- | --- | --- |
| `--clone-from <SOURCE_URL>` | — | The **source** node's base URL — an absolute **`https://`** URL (plain-HTTP and private/loopback targets are refused by an SSRF guard). Selects the streaming-clone mode. |
| `--clone-source-project <PROJECT>` | the target name | The project to clone **on the source**. Defaults to the target `<project>` you named — the common same-name env-clone (e.g. `acme` → `acme`). |
| `--clone-source-token-file <FILE>` | — | File holding the operator's **source-node** `Project·Admin` token. Falls back to `BOATRAMP_CLONE_SOURCE_TOKEN`. The token is sent to the target in a header over TLS and forwarded to the source — **never** on the command line. |
| `--clone-data-only` | off | Pull **application data only** — no control-plane KV / identity (the target keeps its own). |
| `--apply` | dry-run | Execute the clone (default: a **cheap plan** on the target that mutates nothing — see below). |
| `--clone-verify` | off | A **stream-level validate** (only without `--apply`): open the source stream and check the whole bundle end-to-end **without** mutating the target. The default dry-run is the cheap plan (manifest + diff only); reach for this when you want the heavier full-transfer validation a plan does not perform. |
| `--overwrite` | off | Replace an **existing**, populated target project (otherwise a clone targets a fresh project). |
| `--enumerate-mismatches` | off | **Assess scope**: scan every member, report every declared≠streamed integrity mismatch (path + class), apply nothing that mismatches, and fail at the end. Pair with `--clone-verify` or the default dry-run plan. See [below](#recover-from-a-mismatched-or-stale-clone-member). |
| `--skip-member-mismatch` | off | Warn + continue past a mismatched member instead of hard-failing, scoped to re-generable `der/` derivatives by default. See [below](#recover-from-a-mismatched-or-stale-clone-member). |
| `--skip-member-mismatch-any-blob` | off | Broaden `--skip-member-mismatch` to any blob member (never non-blob). Requires `--skip-member-mismatch`. |

### The dry-run is a cheap plan (not a trial transfer)

**The default `--clone-from` dry-run is a cheap PLAN**: the target fetches the source manifest,
diffs it against its own store, and **stops there** — it reports what a real clone *would* do
without opening the source stream or transferring a byte. It answers in the time of a manifest
fetch plus a diff, even for a project of tens of thousands of blobs:

```console
$ boatramp project import acme --clone-from https://src.acme.com \
    --clone-source-token-file ./src-admin.token --server https://dst.acme.com
clone plan for `acme` ← `acme` (full):
  blobs: 18214 to transfer, 0 already present, 18214 total (~33203MB bytes)
  members: sql/app.pgc, kv/control-plane.jsonl
  (dry-run — nothing transferred; re-run with --apply to execute)
```

> **Semantics change (v0.49.0).** Before v0.49, a `--clone-from` dry-run opened the source stream
> and pulled *every missing member* to validate the bundle without committing — i.e. it did nearly
> all the work of a real clone and then returned a single report at the very end (minutes of silence
> for a large project). The dry-run is now the **cheap plan** above. The old stream-level validate
> is still available on demand behind **`--clone-verify`** (above). `--apply` is unchanged — it
> streams and commits.

### Progress on `--apply`

A real clone of tens of GB can take many minutes. `--apply` (and `--clone-verify`) now surface
**live progress**: the target prints the **plan up front**, then periodic transfer heartbeats
(bytes transferred, elapsed) on **stderr** as members stream in, and finally the import report —
so a long clone is never a silent wait. `--output-format json` keeps **stdout** to the clean
final result (the plan + report) while the heartbeats stay on stderr.

### How it resumes without staging a bundle

The target first fetches a cheap **manifest** from the source (`clone/manifest`) — a *list* of the
source project's blob objects plus the non-blob member paths (managed-DB dumps, the KV slice), never
a body read, so it stays cheap even at tens of GB. It diffs that list against its **own
content-addressed store**, then asks the source (`clone/stream`) to stream **only the members it is
missing**. Blobs flow **bucket → bucket**. An interrupted clone is **resumable**: a re-run re-diffs
and transfers only what is still missing, not the whole project again. Each member is restored
through the same **atomic shadow-restore** path a bundle import uses (a managed dedicated DB restores
into a shadow and swaps in only after it verifies), so a failed clone leaves the live target
untouched.

### Authorization and tenancy

A streaming clone carries **no node-global `System·Admin`** anywhere — it is **two `Project·Admin`
authorizations**:

- **Target.** The token you authenticate the `boatramp project import` call with (`--server` /
  `[deploy].server`) must hold `Project·Admin` on the **target** project — it drives the orchestrator
  (`POST /api/projects/<target>/clone/from`).
- **Source.** The `--clone-source-token-file` / `BOATRAMP_CLONE_SOURCE_TOKEN` token must hold
  `Project·Admin` on the **source** project — the target forwards it to the source's `clone/manifest`
  and `clone/stream` surfaces. Clone refuses to start without it.

The target always restores a **fresh** identity (a clone is a *different* environment — identity
adoption is the recovery-oriented bundle import path, not clone) and enforces its **own** project
scope on every member it writes: a source-declared scope is never trusted, and a blob ref outside the
source project's own prefix is refused fail-closed. See
[API reference: Streaming clone](../reference/api.md#streaming-clone) for the HTTP contract.

## Recover from a mismatched or stale clone member

A large project occasionally accumulates a few blob objects whose **declared** size/checksum (in
the manifest) no longer agrees with what the backend actually **stores** — most often a stale
image derivative left over from a format change (pre-WEBP `.jpg` thumbnails, say). By default,
both `--in <file>` and `--clone-from` import **hard-fail on the first such mismatch** — a correct,
but blunt, response when the mismatch is on data the target can regenerate on its own.

This is the realistic shape: a 43.5 GB clone fails partway through with something like

```
error: clone failed after the stream opened: size MISMATCH for member
"blobs/acme/blog/images/der/<sha>/512.jpg": declared 48213, streamed 12345
```

### 1. Assess the scope — is it one stale blob, or many?

Re-run with `--enumerate-mismatches` (pair it with `--clone-verify` for a stream-level clone, or
just the default dry-run plan for a bundle import) to scan **every** member in one pass and report
**every** mismatch — path, class (`der`/`base`/`primary`), and the declared-vs-streamed
size/checksum — before touching anything:

```console
$ boatramp project import acme --clone-from https://src.acme.com \
    --clone-source-token-file ./src-admin.token --clone-verify --enumerate-mismatches \
    --server https://dst.acme.com
error: clone failed after the stream opened: 3 member(s) failed integrity verification (declared ≠ streamed):
  • "blobs/acme/blog/images/der/<sha1>/512.jpg" [der] Size: declared 48213, streamed 12345
  • "blobs/acme/blog/images/der/<sha2>/256.jpg" [der] Size: declared 9871, streamed 9871
  • "blobs/acme/sql/app.pgc" [non-blob] Checksum: declared <hash>, streamed <hash>
```

(Non-zero exit — `--enumerate-mismatches` always ends in this error when at least one mismatch
exists; it never applies anything.)

An enumerate pass **applies nothing** — it is a pure assessment, even for a `der/`-class finding.
A non-blob (DB/KV/identity) or baseline/primary finding in that list is one `--skip-member-mismatch`
will **not** fix (see step 2) — it needs its own repair (re-export the source, or fix it at the
source with `blob reconcile`/`blob purge`, step 3).

### 2. Get the clone through — tolerate the re-generable ones

If every hard finding is a `der/` derivative, re-run with `--skip-member-mismatch`: it warns and
continues past each `der/` mismatch instead of hard-failing — the member is **not** applied, and
the target re-derives it the first time something requests it. A baseline, a primary/original
blob, or any DB/KV/identity member still hard-fails, so this cannot silently swallow a mismatch on
load-bearing data:

```console
$ boatramp project import acme --clone-from https://src.acme.com \
    --clone-source-token-file ./src-admin.token --apply --skip-member-mismatch \
    --server https://dst.acme.com
cloned `acme` ← `acme` (full): transferred 18214 of 18214 blobs (~33203MB bytes)
  restored: 18213 blobs, pg 1, libsql 0, kv 412 records
  note: SKIPPED member "blobs/acme/blog/images/der/<sha1>/512.jpg" [der] (Size mismatch: declared 48213, streamed 12345) — NOT applied; the target re-derives it on access
```

Each tolerated skip is echoed as a `note:` line (for `--clone-from`) or in the import report JSON
(for `--in <file>`) — so you know exactly what the target will regenerate on first access. If a
baseline/primary mismatch turns out to be one you've decided is actually safe to bless (rare —
double-check it is not real corruption first), the louder, explicit
`--skip-member-mismatch-any-blob` broadens the tolerance to any blob member; it still never
tolerates a non-blob member.

### 3. Optionally, clean up the source so the next clone is clean

`--skip-member-mismatch` treats the symptom on the target; the drift still exists on the
**source**'s index. Two source-side tools fix it there:

- **`boatramp blob reconcile`** blesses the drift by rewriting the source's stored bytes so the
  declared size matches the body — default-scoped to `der/` (the audited `--include-primary` opt-in
  covers baseline/primary, but double-check first — it blesses a possible truncation).
- **`boatramp blob purge --legacy-derivatives --superseded-ext jpg`** instead **deletes** the
  stale-format derivatives outright (rather than blessing their declared size) — the right call
  when the mismatch is really leftover pre-format-change cruft the application will regenerate
  anyway.

```console
$ boatramp blob verify --server https://cp.acme.com                                   # confirm scope
$ boatramp blob reconcile --prefix hblob/acme/ --server https://cp.acme.com            # dry-run
$ boatramp blob reconcile --prefix hblob/acme/ --apply --server https://cp.acme.com    # bless
```

See [`blob verify`](../reference/cli.md#blob-verify), [`blob reconcile`](../reference/cli.md#blob-reconcile),
and [`blob purge`](../reference/cli.md#blob-purge) in the CLI reference, and
[the `der`/`base` blob-key convention](../reference/api.md#member-mismatch-tolerance) for exactly
which objects each tool is allowed to touch.

### The `der`/`base` convention is a contract your application must honor

Every one of these tools — the clone-skip above, `blob reconcile`'s default scope, and
`blob purge --legacy-derivatives` — decides "safe to skip/bless/delete" **structurally**, from a
whole `/`-separated path **component** on the blob's storage key, never from a flag you pass per
object:

- a component exactly `base` → **baseline** (load-bearing — never touched without an explicit,
  audited opt-in);
- else a component exactly `der` → **derivative** (re-generable — the only class these tools
  touch by default);
- `base` wins a tie (a key with both components is a baseline);
- anything else → **primary** (an original/user object — load-bearing, treated like a baseline).

The match is on whole segments, not substrings (a segment `thunder` or `database` is **primary**,
not a derivative). If your application stores load-bearing data under a literal `der` path
component, that data becomes eligible to be silently skipped on a tolerant clone, blessed by a
default `blob reconcile`, or deleted by a legacy-derivative purge — so keep `der/` for genuinely
re-generable content only (thumbnails, transcodes, resized variants your app regenerates on a
cache miss), and put everything else under `base/` or a path with neither component.

## The bundle format: streamed, not staged

A BRPROJ bundle is a plain tar whose members are the project's managed-database dumps, its
control-plane KV slice, and its blobs. Both export and import **stream** the bundle — the node
never buffers the whole bundle to a temp file on either end:

- A small member (the KV slice, small blobs, the identity container) stages to **one bounded
  temp file at a time**, so the transient on-disk footprint peaks at the size of the largest
  such member, never the whole bundle.
- A large, streamed member — a managed Postgres/MySQL dump, a libsql snapshot, or a large blob —
  is **chunked**: it is written as a run of fixed-size (64 MiB) parts, each hashed and
  byte-counted as it streams through, followed by a trailing checksum + size record verified
  once the whole member has passed (a **trailing-SHA**, not a leading one — so neither side ever
  needs to buffer or re-read the member to compute it). The transient footprint for a chunked
  member is one 64 MiB chunk, not the member's full size.

A truncated or corrupted bundle — a dropped connection, a bit flip in transit — fails **loud** at
import (the per-member checksum catches it) rather than silently restoring a partial database.
The bundle format has evolved (v1 → v2 → v3) purely to remove staging bottlenecks; a current node
reads every prior version, and writes the newest form only when it actually has a chunked member
to write — an older-format bundle stays byte-identical to what a prior release would have produced.

## Managed-database restore is atomic

Restoring a **full** export of a **managed, dedicated (single-tenant)** Postgres, MySQL, or libsql
database is atomic: the dump is applied into a **shadow** — a not-yet-live database — verified,
and only then **swapped in** (a Postgres/MySQL database rename, or a libsql file rename) in place
of the live one. Any failure along the way — a checksum mismatch, a truncated stream, a restore
error, a disconnect — tears the shadow down and leaves the live database completely untouched;
nothing is ever half-restored. (The swap itself is per-member atomic, not whole-bundle atomic: if a
bundle has several managed databases, a later member failing does not roll back an earlier member
that already swapped in. Overwriting a populated database also transiently peaks at roughly twice
its on-disk size, during the brief window where both the old and the new copy exist.)

**The restore never runs as the database's own superuser.** A bundle's SQL dump is
attacker-controllable data (it is, after all, a file an operator can hand you), so applying it
under the binding's own credential — which on a managed, co-located server is the bootstrap
superuser — would let a crafted dump (`COPY … TO PROGRAM`, `CREATE FUNCTION … LANGUAGE c`, and
similar) execute arbitrary code on restore. Instead:

- **Postgres/MySQL**: the dump is applied through a freshly-minted, import-scoped,
  **non-superuser** role that exists only for the duration of one import's shadow apply (a
  random password, dropped once the swap completes or the shadow is torn down). A fail-closed
  probe refuses the apply outright if the resolved role turns out to be a superuser.
- **libsql/SQLite**: the restore connection runs under a SQLite *authorizer* that confines a
  streamed `.dump` to the shadow's own schema — denying `ATTACH`/`DETACH`/every `PRAGMA` at
  prepare time, so a crafted `ATTACH DATABASE '/some/other/file'` is refused before the target
  file is ever opened, never touching anything outside the shadow.

### Enabling a Postgres extension on restore (e.g. pgvector)

If a Postgres dump expects an extension (`CREATE EXTENSION IF NOT EXISTS "vector"`, say, for
pgvector), the non-superuser apply role has no privilege to create it — so the extension must
already exist in the shadow before the dump runs. boatramp pre-creates every extension on the
operator's **trusted-extension allowlist** (the same allowlist an
[in-app migration's `extension` step](./in-app-migrations.md#enable-an-extension) uses) in the
shadow, via the superuser maintenance connection, *before* the non-superuser apply — so the
dump's own `CREATE EXTENSION IF NOT EXISTS` becomes a no-op instead of failing:

```toml
[handlers.bindings.sql]
migrate_trusted_extensions = ["pgcrypto", "uuid-ossp", "citext", "vector"]
```

An empty/unset allowlist means **no** extension can be enabled this way; restoring a dump that
needs `vector` (or any other extension) against an operator who has not added it to the allowlist
fails the restore. Add exactly the extensions you intend to use — this is the same
operator-controlled gate [Declare a managed database](./managed-databases.md) and schema
migrations use, so widening it here widens it everywhere.

### Two restore scenarios that are currently refused

**Data-only (or shared-tenant) import into a managed database is refused.** The atomic,
non-superuser shadow-restore path above exists only for a **full** bundle restored into a
**dedicated (single-tenant)** managed database. A **data-only** import, or a **full** import
into a **shared**-tenant managed database, cannot use that path yet — and applying either
directly against the live database would mean connecting as the binding's own (superuser-grade)
credential, reopening exactly the RCE risk the shadow-restore path exists to close. So both are
refused outright, with an error like:

```
import refused: a MANAGED pg database ("app") can only be restored via the atomic chunked
shadow path (a FULL, dedicated/Single bundle). A data-only or Shared sidecar restore would
apply the untrusted dump as the bootstrap superuser (RCE risk); a least-privilege sidecar
apply is a pending follow-up. Re-export as a FULL dedicated bundle, or import into an
external (bring-your-own-URL) binding.
```

If you hit this: re-export with `--full` against a dedicated-tenant target, or restore into an
**external** (bring-your-own-URL) database binding instead — see the next point. A
least-privilege path for data-only/shared-tenant restore is a planned follow-up, not yet shipped.

**An external (bring-your-own-URL) database binding is unaffected by any of this.** Only a
boatramp-*managed*, co-located database goes through the shadow-restore machinery (and its
refusals) above. A database you run yourself, referenced via `url_env`, always restores with
*your own* configured credential against *your own* database — your trust boundary, not
boatramp's managed cluster — exactly as a data-only or full import always has.

### Import size caps

A single bundle member is capped at **256 GiB**, and the whole bundle at **1 TiB** — fixed node
limits, not currently exposed as a config key or CLI flag (the numbers are hard-coded in the
import driver; raising them requires a boatramp build, not a config change). Exceeding either
cap refuses the import outright, naming the cap it hit.

## See also

- [Declare a managed database](./managed-databases.md) — the same trusted-extension allowlist
  and managed-vs-external/single-vs-shared distinctions this page relies on.
- [In-app schema migrations](./in-app-migrations.md#enable-an-extension) — the
  `migrate_trusted_extensions` allowlist in its original (migration) context.
- [RBAC reference](../reference/rbac.md) — the `Project·Admin` gate on the export/import and clone verbs,
  and the `System·Admin` gate on `blob reconcile`/`blob purge`.
- [API reference: Project export & import](../reference/api.md#project-export--import) — the
  `/api/project-export` / `/api/project-import` HTTP contract, including
  [member-mismatch tolerance](../reference/api.md#member-mismatch-tolerance) and the `der`/`base`
  blob-key convention.
- [CLI reference: `blob verify`](../reference/cli.md#blob-verify),
  [`blob reconcile`](../reference/cli.md#blob-reconcile), and
  [`blob purge`](../reference/cli.md#blob-purge) — the source-side integrity tools this page's
  [clone-mismatch recovery](#recover-from-a-mismatched-or-stale-clone-member) flow uses.
