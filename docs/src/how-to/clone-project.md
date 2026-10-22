# Export, import & clone a project

A project's state — its managed-database contents, its control-plane KV slice, and its
blobs — can be streamed off a running node as a single portable **BRPROJ bundle**, then
imported into a project on the same node or a different one. This is how you **clone** a
project into another environment (staging → prod, a per-customer copy) or recover one.

Both verbs run against a **running node** and are gated at **`System·Admin`** (the node
operator — a project admin, publisher, or deployer cannot reach them).

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

Server seam: `POST /api/project-import`.

## Clone a project

There is no single `clone` verb — a clone is an **export followed by an import** into a
new project name:

```console
$ boatramp project export acme --out acme.brproj --server https://cp.acme.com
$ boatramp project import acme-staging --in acme.brproj --apply --server https://cp.acme.com
```

Clone the **data only** (the default bundle) when copying application data into a fresh
project — the target keeps its own identity, RBAC, and routing. For a **same-environment
recovery** of the original project (identity intact), export with `--full
--include-identity` and import with `--identity adopt`.

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
- [RBAC reference](../reference/rbac.md) — the `System·Admin` gate on both verbs.
- [API reference: Project export & import](../reference/api.md#project-export--import) — the
  `/api/project-export` / `/api/project-import` HTTP contract.
