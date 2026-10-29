# Incremental & true-delta export

A full [project export](./clone-project.md) ships the whole project every time. A **delta
export** ships only what **changed** since a chosen base — the control-plane KV upserts and
tombstones, the new and changed blobs (and blob tombstones), and, for a managed SQL database
that opts in, the actual **row-level changes** since the base rather than a fresh dump. It is
how you keep a staging/DR copy in step with production cheaply, or ship a nightly that carries
only the day's writes.

Delta export builds on the **resumable** export surface (a node-local member-object directory),
not the single-file `BRPROJ` stream — a delta chains onto a base that lives on the node, so it
is resumable-only. Both verbs are gated at **`Project·Admin` on the target project**, like the full export.

## What ships as a true delta — and what falls back

| Family | Delta shipped |
| --- | --- |
| Control-plane **KV** | Always a true delta — the upserts + tombstones since the base. |
| **Blobs** | Always a true delta — only new/changed objects, plus tombstones for deletes. |
| Managed **Postgres** / **MySQL** | A true **row delta** (logical-WAL / binlog replay) **when** the database opted in with `delta_capture` and was restarted — otherwise a **full dump within the delta bundle**. |
| Managed/local **libsql / SQLite** | A true **changeset** delta when the node was built with the `sql-delta-libsql` engine — otherwise a full dump within the delta bundle. |

The rule is **all-families-consistent**: a SQL family that cannot ship a true row delta for a
given link does not silently drop out — it full-dumps **inside** the same delta bundle, so the
bundle always restores to a correct, complete state. True SQL deltas are **best-effort**; the
bundle's correctness and the node's disk safety are not.

## Before you start

- The node must have a **resumable export base** configured — `[serve] resumable_export_dir`
  in `boatramp.cfg`. Without it the resumable surface (and so delta export) is refused
  fail-closed. See the [`boatramp.cfg` reference](../reference/boatramp-cfg.md).
- A token with **`Project·Admin`** on the project being exported.
- For a true **Postgres/MySQL** row delta: the database must have `delta_capture` enabled and
  have been **restarted** to adopt it (below). For a true **libsql** delta: the node must be
  built with the `sql-delta-libsql` feature.

## 1. Take a base, then a delta

A delta is always measured against a **base** — an earlier resumable export directory on the
same node. Take a base (a full resumable export), then take deltas against it:

```console
# a BASE: a full resumable export, written as the node-local directory `nightly-base`
$ boatramp project export acme --resumable nightly-base --server https://cp.acme.com

# …writes happen in the project…

# a DELTA against that base, written as `nightly-d1`
$ boatramp project export acme --resumable nightly-d1 --mode incremental --base nightly-base \
    --server https://cp.acme.com
```

| Flag | Default | Description |
| --- | --- | --- |
| `--resumable <DIR>` | — | Write a resumable **member-object directory** of this name under the node's `[serve] resumable_export_dir` base (a relative, host-confined name) instead of streaming a file. Required for a delta. A re-run resumes (members already present + SHA-verified are skipped). |
| `--mode <differential\|incremental>` | full export | Take a **delta** against `--base`. Omit for a full (non-delta) export. Requires `--base`. |
| `--base <DIR>` | — | The base (`differential`) / parent (`incremental`) resumable-dir name to chain onto — a prior `--resumable` export on the same node. Required with `--mode`. |

(`differential` and `incremental` are the accepted long values; the short aliases `diff` /
`inc` are also understood.)

### Differential vs incremental — and chains

| `--mode` | Diffs against | Chains? |
| --- | --- | --- |
| `differential` | a **fixed** full base | No — every differential delta is measured against the same base. |
| `incremental` | the **parent** (the base, or a prior delta) | Yes — `base → d1 → d2 → …`, each link measured against the one before it. |

An **incremental chain** is the usual shape for "keep a copy in step": each run points `--base`
at the previous run's directory, so each delta carries only that interval's changes.

```console
$ boatramp project export acme --resumable base    --server …                       # base
$ boatramp project export acme --resumable d1 --mode incremental --base base --server …   # base → d1
$ boatramp project export acme --resumable d2 --mode incremental --base d1   --server …   # base → d1 → d2
```

## 2. Import a delta (the whole chain restores)

Import the **newest** link. The import resolves the base chain back to its root full bundle and
applies **base → each delta in order** — you do not import the links one at a time:

```console
# dry-run plan (mutates nothing)
$ boatramp project import acme-dr --resumable d2 --server https://cp.acme.com
# execute
$ boatramp project import acme-dr --resumable d2 --apply --server https://cp.acme.com
```

The chain is refused if it does not terminate in a full base, if two links disagree on their
source project/site (a spliced chain), or if any member fails its SHA — all fail-closed, before
anything is applied. The managed-SQL restore is **atomic** (shadow-restore + swap), exactly as
for a full import — see [Managed-database restore is atomic](./clone-project.md#managed-database-restore-is-atomic).

## 3. Enable true row deltas for a Postgres/MySQL database

A true Postgres/MySQL row delta needs logical decoding on the server — Postgres `wal_level =
logical`, MySQL row binary logging + GTID. Those are **start-only** server settings, and
boatramp does **not** turn them on for every managed database (they cost WAL/binlog
amplification you should not pay on databases you never delta-export). You opt a specific
database in with **`delta_capture`** in its `databases:` manifest entry:

```ron
databases: [
    ( name: "app", kind: postgres, version: 16, size: medium,
      tenant: single, tenant_scope: project,
      delta_capture: true ),              // opt this DB into true row deltas
]
```

Because `delta_capture` flips a start-only setting, it only takes effect after the database is
**restarted**. Until then, a delta export of that database would silently fall back to a full
dump — so boatramp instead **refuses the delta loudly**, telling you to restart:

```text
database "app": delta export refused — `delta_capture` is enabled but the server has not been
restarted to adopt it yet (true-delta needs wal_level=logical / binary logging, which only take
effect at server start); ensure `delta_capture: true` is set and run `boatramp db restart --db
app` (or apply with `restart_policy: auto`) before a delta export of this database
```

### Apply the restart: `restart_policy` + `boatramp db restart`

A config change that only takes effect at start is staged as **pending** until the database is
restarted. The **`restart_policy`** manifest field chooses how:

| `restart_policy` | Behaviour on `apply` |
| --- | --- |
| `manual` (default) | Stage the change and mark the database **pending restart** — it keeps running the old config until you run `boatramp db restart`. |
| `auto` | Apply the change and **restart the database immediately** on apply (only when a restart-requiring field actually changed; an unchanged re-apply is a no-op). |

Restart a database explicitly (the `manual`-policy path, and the first-class restart verb for
ops generally):

```console
$ boatramp db restart --db app
restarted database `app` (workload `bramp-db-app`)
  pending config change applied
  replicas stopped: 1 (the reconcile loop will relaunch)
```

`--db` defaults to `default`. The restart stops each replica so the reconcile loop relaunches it
fresh **on the same data volume**, adopting any staged config in the process.

A **pending restart** is surfaced by the read verbs so you never forget one:

```console
$ boatramp db status app
database `app`
  readiness:       provisioned
  declared:        yes
  pending restart: yes — a staged config change has not been applied; run `boatramp db restart --db app`
```

The restart primitive is for a **dedicated (`tenant: single`), project-scoped** managed
database. A shared-tenant server (it hosts other tenants) or a site-scoped binding (no single
workload) is out of scope and refused with a clear message; a bring-your-own-URL database is
not boatramp's to restart.

## The three engines & their modes

| Engine | Mechanism | Modes that true-delta | Across a chain's links |
| --- | --- | --- | --- |
| **Postgres** | logical-WAL replay (`pgoutput`) | **incremental only** | Only the **first** delta true-deltas; later links **full-dump** |
| **MySQL** | binlog/GTID replay (row events) | **incremental only** | Only the **first** delta true-deltas; later links **full-dump** |
| **libsql / SQLite** | session **changeset** | **differential and incremental** | Every link true-deltas (a re-diffable file snapshot) |

**Why pg/mysql true-delta only the first link.** A Postgres logical replication slot advances
as it is drained, and a MySQL base records a single snapshot GTID coordinate — neither can
re-emit a fixed base→N interval for a later link. So in an incremental chain `base → d1 → d2`,
only `d1` carries a true WAL/binlog delta; `d2` (and beyond) full-dump within the delta bundle.
The chain still **restores correctly**: on import, a newer full dump supersedes the earlier WAL,
so the chain yields the final state regardless of which links were true-delta vs fallback. A
`differential` pg/mysql delta always full-dumps (it cannot re-use the one advancing slot).

**libsql true-deltas across every link.** A libsql base is a fixed **file snapshot** that every
delta can re-diff, so both modes produce a true changeset and every link of a chain is a true
changeset — `base → d1 → d2` restores as the base snapshot plus each changeset applied in order.
libsql true-delta needs only the `sql-delta-libsql` build (no `delta_capture`, no restart — it
diffs file snapshots in-process).

### When a SQL family full-dumps instead (fallback triggers)

Any of these makes a SQL family ship a full dump **inside** the delta bundle instead of a true
row delta (never an error, never a dropped family):

- the database is **not** `delta_capture`-enabled (pg/mysql), or the node lacks the
  `sql-delta-libsql` engine;
- the mode is `differential` (pg/mysql);
- the binding is **Shared**-tenant, **external** (bring-your-own-URL), or not managed;
- the schema changed since the base (a schema-fingerprint mismatch), or — MySQL — there was DDL
  in the delta's range;
- the Postgres capture slot was lost or dropped by the disk-fill guard (below).

The one case that is **not** a silent fallback is `delta_capture` enabled-but-not-restarted: that
refuses loudly (above), because you explicitly asked for a true delta.

## Disk safety: slot lifetime & the WAL-pinned ceiling

A Postgres logical replication slot pins WAL from its position forward — an un-drained or
forgotten slot fills the data disk, the exact failure the export program exists to prevent. The
true-delta machinery is bounded fail-closed:

- **Off by default.** A database pays no `wal_level = logical` WAL amplification until you set
  `delta_capture` and restart it. Only a **base** export of a `delta_capture` database creates a
  slot.
- **One interval, then gone.** A slot lives exactly one base→delta interval: a delta export
  **drains and drops** it. A failed/abandoned delta never pins WAL indefinitely.
- **A hard WAL-pinned ceiling.** The managed server launches with `max_slot_wal_keep_size`, so a
  slot that would pin more than its budget is dropped and that delta **falls back to a full
  dump** — disk safety wins over best-effort true-delta.
- **Orphan sweep.** A reconcile pass drops stray capture slots (and the ephemeral capture roles)
  left by an interrupted export, so nothing leaks a WAL pin.

## Security posture

Replaying an untrusted WAL/binlog/changeset stream is the same tenant-escape surface as a
crafted SQL dump, and is confined the same way:

- **Capture** runs as a **dedicated, ephemeral** `REPLICATION`-grade role that the maintenance
  superuser creates and drops with the slot — least-privilege, never the tenant's own role,
  never persisted.
- **Replay** applies the decoded stream as the **ephemeral non-superuser** apply role (Postgres
  grants scoped to the shadow only; MySQL `ALL` on the shadow only, plus `REPLICATION_APPLIER` +
  `SESSION_VARIABLES_ADMIN`), or, for libsql, under a **base-table apply filter** (abort on
  conflict) that confines a changeset to the restored base's own tables. A crafted stream that
  tries to write outside the target — a `DROP TABLE` in
  a foreign schema, a write to another tenant's database, a changeset touching a table outside
  the base — is **refused** fail-closed: the shadow is dropped, nothing swaps, and the target
  (and every other tenant) is left byte-unchanged.
- This is proven live by a **crafted-escape gate** per engine (including through a multi-delta
  chain), seeding a second isolated unit — a second tenant database for Postgres/MySQL, a second
  site for libsql — and asserting zero foreign bytes in it after a refused crafted delta.

## Scope limits (today)

- True SQL row deltas are for a **managed, dedicated (`tenant: single`)** Postgres/MySQL
  database. A **Shared**-tenant or **external** binding full-dumps.
- Postgres/MySQL true-delta is **incremental-mode only**; `differential` full-dumps.
- Delta export is **resumable-only** (it chains onto a node-local base) and is **not** itself
  resumable mid-delta in the way a base export is — a dropped true-delta export re-runs from the
  base.
- A delta bundle carries no identity container; include identity only in the full base, then
  chain deltas.

## See also

- [Export, import & clone a project](./clone-project.md) — the full-bundle export/import this
  builds on, and the atomic managed-DB restore.
- [Declare a managed database](./managed-databases.md) — `delta_capture`, `restart_policy`, and
  `boatramp db restart`.
- [`boatramp project` / `boatramp db` CLI](../reference/cli.md#boatramp-project) — the flags.
- [API reference: Project export & import](../reference/api.md#project-export--import) — the
  `mode` / `base` / `resumable` query contract and the db-restart endpoint.
