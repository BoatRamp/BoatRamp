# Provisioning drift-repair (v1) — implementation notes for review

**Task:** #491 / `PLAN-provisioning-drift-repair.md`. Worktree `br-provision-repair`, branch
`provision-drift-repair` (based on v0.5.0). Feature + **unit** tests are complete and build clean; the
**CI live gate is intentionally NOT wired** (see the TODO at the end). Tree left dirty, uncommitted.

## What it does (recap)

An owner-gated (`Project·Admin`, audited), idempotent, data-preserving `repair` verb that diffs a
managed **shared-Postgres** tenant's provisioning against spec and converges the delta
(drift-detect → probe → verdict → converge-DDL → re-probe). First use: retrofit pre-v0.4.25 tenants
(db owned by the runtime role, no `_owner` role) so `project migrate` (which connects as the sealed
owner role) works. Data-preserving: only roles / ownership / grants / sealed credentials / ledger
scaffolding — never `DROP`/`TRUNCATE`/`DELETE`/`UPDATE` of tenant rows.

## Files changed

| File | Change |
|---|---|
| `crates/boatramp-core/src/sql.rs` | NEW `RepairMode`, `RepairStatus`, `RepairCheck`, `RepairReport` (+ `any_error`/`first_error`/`found_drift`), the `TenantRepair` trait, and `RepairError`. Placed after `MigrationStatus`. Mirrors only the migrate *conventions* (`#[serde(default)]` collections, structured failures, 200-vs-422); NO id-buckets. |
| `crates/boatramp-node/src/repair.rs` | **NEW** — the orchestrator: `NodeTenantRepair` (the `TenantRepair` impl), `repair_tenant`, the 9 checks + probes + converge helpers + topology gating + password redaction. `#![cfg(any(sql-postgres, sql-mysql))]`. |
| `crates/boatramp-node/src/repair/tests.rs` | **NEW** — unit tests (mock `SqlBackend`). |
| `crates/boatramp-node/src/lib.rs` | `pub mod repair;` (cfg-gated). |
| `crates/boatramp-node/src/managed_sql.rs` | NEW `ManagedSqlCredentials::is_sealed` (read-only `kv.get`, never `put`) + its unit test. |
| `crates/boatramp-node/src/tenant_sql.rs` | NEW `shared_admin_backend_for_db(…, database)` (tenant-db-targeting superuser backend); the existing `shared_admin_backend` now delegates to it with the maintenance db. |
| `crates/boatramp-node/src/node.rs` | Build `tenant_repair` cap (same gating as `operator_sql` + envelope) and assign `options.tenant_repair`. |
| `crates/boatramp-server/src/lib.rs` | NEW `ServerOptions::tenant_repair` field; re-export `repair_apply`, `repair_dry_run`. |
| `crates/boatramp-server/src/routes.rs` | `tenant_repair_cap` extension + `POST /api/repair/{db}` and `/dry-run` routes. |
| `crates/boatramp-server/src/admin_api.rs` | `repair_apply` / `repair_dry_run` handlers, `repair_report_response` (200/422), `repair_error_response`, `assert_repair_is_admin` (in-handler defense-in-depth), and the **discoverability cure** in `migration_error_response` (`repair_cure_hint`). |
| `crates/boatramp-server/src/project_scope.rs` | `"repair"` added to `PROJECT_SCOPED_FAMILIES` (+ rewrite test). |
| `crates/boatramp-types/src/authz.rs` | Explicit `Project·Admin` arms ABOVE the `/api/sql/` catch-all: global `p.starts_with("/api/repair/")` and project-scoped `Some((&"repair", _))`; + `repair_surface_is_project_admin_not_publisher` table test (publisher-refused, admin-allowed, global + project-scoped + dry-run + cross-tenant). |
| `crates/boatramp/src/project_repair.rs` | **NEW** CLI `boatramp project repair --db <name> [--apply] [--dry-run] [--json] [--exit-nonzero-on-drift]` (flags flat on the verb; default = dry-run) + tests. |
| `crates/boatramp/src/project.rs` | `Repair` subcommand + dispatch + `Error::Repair`. |
| `crates/boatramp/src/main.rs` | `mod project_repair;`. |
| `crates/boatramp/src/client.rs` | NEW `ControlPlane::repair_trigger(db, apply)` (POST, 200/422 → `Ok`, else `Refused`). |

**No shim change.** Repair is an operator-facing capability (no guest WIT), so `sql_shim.rs` is
untouched — consistent with the "shim rev only on guest WIT change" discipline.

## The 9 checks — probe (read-only) + converge (apply-only)

All identifiers are `quote_ident`'d; all names are DERIVED via `tenant_provision` / `tenant_names`
(never operator input, never a probe result — a probe result is used only as an `==` verdict). Check
order matters: **check 1 (owner-role-exists) is a precondition** — if the owner role is not (yet)
present, checks 2/3/4/7 are `skipped` (never `ALTER … OWNER TO <nonexistent>`).

Two superuser backends are used: **maintenance-db** (`postgres`) for role DDL + `ALTER DATABASE OWNER`
+ the db/role probes; **tenant-db** (the derived db) for `REASSIGN OWNED` + ledger re-own, guarded by a
`SELECT current_database()` == derived-db assertion before any `REASSIGN OWNED`.

| # | slug | probe | converge (apply only) |
|---|---|---|---|
| 1 | `owner-role-exists` | `SELECT 1 FROM pg_roles WHERE rolname='<owner>' AND rolcanlogin` (LOGIN excludes a NOLOGIN soft-deleted sibling) | seal owner cred (create-if-absent), then `provision_ddl`'s owner-arm `DO … CREATE ROLE "<owner>" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION PASSWORD …` + the `ALTER ROLE …` re-assert (sliced from the SAME `provision_ddl`; CREATE DATABASE / GRANT / REVOKE dropped) |
| 2 | `owner-role-attrs` | `SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolreplication FROM pg_roles WHERE rolname='<owner>'` | `ALTER ROLE "<owner>" WITH NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION` |
| 3 | `db-owner` | `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='<db>'` == `<owner>` | `ALTER DATABASE "<db>" OWNER TO "<owner>"` (run on the **maintenance** db) |
| 4 | `object-ownership` | enumerate ACTUAL owners: `pg_class.relowner` (relkind r/p/S/v/m) + `pg_proc.proowner` joined to `pg_namespace` (excl. `pg_catalog`/`information_schema`/`pg_*`), where owner ≠ `<owner>` | runtime-owned → `REASSIGN OWNED BY "<runtime>" TO "<owner>"` (bulk, DERIVED runtime, never a superuser as `<old>`); superuser-owned → targeted `ALTER TABLE IF EXISTS "<schema>"."<name>" OWNER TO "<owner>"`. Requires superuser maintenance identity (else terminal `error`). Run on the **tenant** db (guarded). |
| 5 | `connect-grants` | `has_database_privilege('public'/'<owner>'/'<runtime>', '<db>', 'CONNECT')` | ONE ordered unit, **grants first**: `GRANT CONNECT … TO "<owner>"`; `GRANT CONNECT … TO "<runtime>"`; `REVOKE CONNECT … FROM PUBLIC` (never lock the runtime out) |
| 6 | `runtime-grants` | `has_schema_privilege('<runtime>','public','USAGE')` (coarse) | `grant_app_role_ddl(<runtime>, <owner>)` (idempotent; runtime DML on `public` + `ALTER DEFAULT PRIVILEGES FOR ROLE "<owner>"`). Run on the **tenant** db. |
| 7 | `ledger` | schema `boatramp_migrations` owner (`pg_namespace.nspowner`) + table `schema_migrations` owner (`pg_tables.tableowner`) both == `<owner>` | `CREATE SCHEMA/TABLE IF NOT EXISTS` (mirrors `ensure_ledger`) **+ EXPLICIT** `ALTER SCHEMA boatramp_migrations OWNER TO "<owner>"` + `ALTER TABLE …schema_migrations OWNER TO "<owner>"` (IF NOT EXISTS does NOT fix ownership). Run on the **tenant** db. |
| 8 | `owner-credential-sealed` | `ManagedSqlCredentials::is_sealed` (read-only) | `password()` (create-if-absent + seal). Shown as a `detail` parenthetical — **`ddl: None`**, never fake SQL. |
| 9 | `connectivity` | terminal: connect as owner AND runtime (their sealed creds) + `SELECT 1` | none (diagnostic; reports `ok`/`error`). Runs in both modes. |

Preconditions/guards also emitted as their own results when they fire:
- **soft-delete exclusion** (`soft-delete` skip): exact-`=` live-db probe; only if absent, a bounded
  `_`-escaped `LIKE '<db>__deleted\_%'` distinguishes "soft-deleted, recover first" from "never
  provisioned" (`database` skip). Keys on the EXACT derived name — never a prefix match for the live db.
- **superuser precondition** (`SELECT rolsuper … WHERE rolname=current_user`): if not superuser, check 4
  is a terminal `error` ("requires a superuser maintenance connection") — never a `GRANT <role> TO
  <maint>` workaround.
- **topology gating**: single/dedicated Postgres, MySQL, libsql/bring-your-own, site-scoped, and the
  reserved default tenant each return a single `topology`/`soft-delete`/`database` `skipped` check with a
  reason; the op exits 0.

## Report / status / exit codes

- `RepairReport { tenant, backend, mode, checks: [RepairCheck{check,status,detail,ddl?}] }`.
- Status: `ok | drift | repaired | error | skipped`. HTTP 200 when no check errored, **422** when one did.
- CLI exit: `0` = no-drift / all-repaired; `1` = any errored check; `2` = dry-run found drift **only**
  under opt-in `--exit-nonzero-on-drift` (via `std::process::exit(2)` after printing — `main` is 0/1).
- **Password redaction**: an owner-role `CREATE/ALTER ROLE … PASSWORD '…'` has its literal replaced with
  `'<redacted>'` before it lands in the operator-visible/audited report `ddl` (`redact_password_literal`).
- **Discoverability**: `migration_error_response` appends `try: boatramp project repair --db <name>
  --dry-run …` on a permission/ownership-denied migrate failure (`repair_cure_hint`).

## Authz (the escalation fix)

`/api/repair/*` gets its OWN prefix with explicit `Project·Admin` arms placed **above** the `/api/sql/`
catch-all (which resolves to `Project·Deploy`, a publisher-satisfiable right). Both the apply
(`POST /api/repair/{db}`) and the dry-run (`POST /api/repair/{db}/dry-run`) are Admin, for the global and
project-scoped forms. `"repair"` is a `PROJECT_SCOPED_FAMILIES` member (rewrites onto the global handler,
authz sees the original project-qualified path). In-handler `assert_repair_is_admin` re-derives the
required right and asserts Admin (defense-in-depth).

## Unit tests (all green)

- `boatramp-node repair::tests` (16): name-derivation-only (`owner_role_ddl` + the REASSIGN mutation
  test — probe returns `postgres`, emitted REASSIGN still names the DERIVED runtime, never `REASSIGN
  OWNED BY "postgres"`); **dry-run purity** (mock `SqlBackend` PANICS on any `run_script` during a
  dry-run — owner-role + db-owner drift emit DDL, run nothing); check ordering (owner-role probe error →
  dependents deferred, no `ALTER DATABASE OWNER TO <nonexistent>`); soft-deleted sibling skipped + exact
  live match; NOLOGIN-excluding role probe; topology skips + classifier; report serde round-trip;
  password redaction.
- `boatramp-node managed_sql::tests::is_sealed_is_read_only_and_accurate`.
- `boatramp-types authz repair_surface_is_project_admin_not_publisher`.
- `boatramp-server project_scope` rewrite test (repair family).
- `boatramp project_repair` (flag parse defaults-to-dry-run, mutual exclusion, exit flags, db
  validation, renderer infallibility).

Build/lint status: `cargo build` + `cargo fmt --all --check` + `cargo clippy --all-targets` clean on
`boatramp-core`, `boatramp-types`, `boatramp-node` (`--features sql-postgres` and `sql-mysql` and
no-sql), `boatramp-server` (`--features handlers`), and `boatramp` (CLI). No warnings from touched files.

---

## TODO — the CI live gate (NOT wired; for the reviewer to author)

Marker: `PROVISION REPAIR RECONCILE OK`. On a real Postgres, the gate must:

1. **Provision** a shared tenant normally, then **MUTATE it into the pre-v0.4.25 shape**: drop the owner
   role, `ALTER DATABASE … OWNER TO <runtime>`, create a **runtime-owned** table with a row, AND a
   **superuser-owned** table with a row (exercises check-4 BUG-1a). Optionally leave the ledger absent
   or runtime-owned.
2. `repair --dry-run` → assert it reports the expected `drift` set + the DDL, and — via a **KV-write /
   DDL assertion** — that it changed NOTHING (no seal, no role, no ownership change).
3. `repair --apply` → assert: owner role recreated + sealed (attrs NOSUPERUSER…); db + BOTH tables
   (runtime- and superuser-owned) re-owned to the owner; ledger schema+table exist and owner-owned;
   connect grants correct; **every seeded row still present** (data intact). Then a real
   `boatramp project migrate status --db <name>` connects as the owner and returns the ledger.
4. `repair --apply` AGAIN → **zero converge actions** (every check `ok`; idempotency/convergence).
5. **Scope**: a SECOND tenant's object ownership is UNTOUCHED after repairing the first.
6. **Isolation preserved**: the RUNTIME role still connects + reads its row after repair.
7. **Soft-delete**: soft-delete a tenant, assert `repair` is a zero-action no-op (`soft-delete` skip).
8. **Mutation-verify the gate FAILS** if the `ALTER DATABASE OWNER` and/or `REASSIGN OWNED` / targeted
   `ALTER … OWNER TO` converge steps are removed — i.e. the gate must actually observe re-ownership, not
   just a green report. (Memory lesson: bg-agent "gates" recur hollow — mutation-test every assertion.)

## Deviations / uncertainty (flag for review)

- **Constant naming.** The plan text says `PROJECT_SCOPED_RESOURCES`; the actual v0.5.0 constant is
  `PROJECT_SCOPED_FAMILIES` (project_scope.rs) — I added `"repair"` there.
- **`shared_admin_backend` change.** I chose the *sibling constructor* option
  (`shared_admin_backend_for_db(…, database)`) over changing the existing signature, so the four existing
  callers are untouched; the old fn delegates to it with the maintenance db. Equivalent to the plan's
  "parameterize OR add a sibling constructor".
- **Exit code 2.** `main` only maps `Ok→0`/`Err→1`. To honor `--exit-nonzero-on-drift`, the CLI calls
  `std::process::exit(2)` after printing the report (stdout already flushed). Deliberate + documented.
- **Check 4 targeted re-own kind. — RESOLVED (see the JOB 1 addendum below).** The earlier narrow
  table-only converge is fixed: the enumeration now carries a KIND discriminator + (for functions) the
  identity args, and `targeted_reown_ddl` emits the correct `ALTER TABLE`/`ALTER SEQUENCE`/`ALTER FUNCTION`
  variant per object.
- **Check 6 probe is coarse** (schema `USAGE` only). The converge (`grant_app_role_ddl`) is idempotent and
  never revokes, so a false "drift" only re-asserts safe grants — but it means check 6 may report `drift`
  on a tenant that actually has the table grants but (somehow) lacks schema USAGE. Acceptable (safe
  direction: over-grant, never leak), but a reviewer may want a finer probe.
- **`REASSIGN OWNED` privilege.** I assert the maintenance identity is superuser for BOTH the bulk
  REASSIGN and the targeted ALTERs (Postgres requires superuser-or-membership for cross-role reassign).
  The plan's open question (superuser vs privileged non-superuser + membership) is resolved
  conservatively as **superuser-required, no membership workaround** per Security MEDIUM-1. If the
  operator's shared maintenance identity is a privileged non-superuser, check 4 will terminally `error`
  (loud, by design) rather than silently `GRANT … TO <maint>`.

---

# ALL-BACKENDS drift-repair (JOB 1 + JOB 2) — addendum

Owner directive: repair must reconcile **every** SQL backend's OWN provisioning model, not just
shared-Postgres — no backend returns a blanket "skipped/not-applicable". Two changes, both confined to
`crates/boatramp-node/src/repair.rs` (+ its `tests.rs`); no other file touched. Tree left dirty,
uncommitted; no CI live gate wired (reviewer owns that).

## JOB 1 — check-4 (`object-ownership`) converges sequences + functions

**Was:** the enumeration SAW superuser-owned sequences (`relkind='S'`) + functions (`pg_proc`) but the
targeted converge emitted only `ALTER TABLE IF EXISTS … OWNER TO …` — which does NOT re-own a sequence
or a function, so those drifted objects were detected but never fixed.

**Now:** the enumeration query projects two extra columns — an `objkind` discriminator
(`CASE WHEN c.relkind='S' THEN 'sequence' ELSE 'table' END`; `'function'` for the `pg_proc` arm) and,
for the function arm, `pg_catalog.pg_get_function_identity_arguments(p.oid) AS args` (empty `''` for
relations). The converge loop calls the new pure helper `targeted_reown_ddl(d, schema, name, objkind,
args)`:

- `table` (also views/matviews) → `ALTER TABLE IF EXISTS "<schema>"."<name>" OWNER TO "<owner>";`
- `sequence` → `ALTER SEQUENCE IF EXISTS "<schema>"."<name>" OWNER TO "<owner>";`
- `function` → `ALTER FUNCTION "<schema>"."<name>"(<args>) OWNER TO "<owner>";`
  (no `IF EXISTS` — `ALTER FUNCTION IF EXISTS (<args>)` isn't universally available, and the arg
  signature is required to disambiguate overloads; `<args>` is Postgres's OWN canonical rendering of the
  signature of a function that provably exists in *this* db — not operator/guest input)
- unknown kind → falls through to the table form (harmless historical default).

**Derived-name discipline preserved:** the OWNER TARGET is always `d.owner_role` (the DERIVED owner);
only the schema/name/args come from the probe of the tenant's OWN (already-confined) db — safe to name.
Runs on the tenant-db backend, still behind the `current_database()==derived-db` guard + the
superuser precondition (unchanged).

**Unit test:** `targeted_reown_emits_kind_correct_variant` asserts each of the four variants + the
derived-owner-only invariant.

**Live gate must additionally prove:** seed a **superuser-owned SEQUENCE** and a **superuser-owned
FUNCTION** (e.g. a trigger fn + an overloaded fn) in the pre-v0.4.25 tenant; after `repair --apply`
their `relowner`/`proowner` == the owner role; and MUTATION-verify the gate FAILS if the
`ALTER SEQUENCE`/`ALTER FUNCTION` arms are dropped (a table-only converge must leave them wrongly owned).

## JOB 2 — a per-backend `RepairModel` for every backend

`repair_tenant` is now a **classifier + dispatcher**: `classify_model(binding) -> RepairModel` maps a
binding to one of five models (mirroring how each is PROVISIONED), and dispatches to that model's
runner. Each runner emits real per-check verdicts through the SAME `RepairReport`/`RepairCheck`/
`RepairStatus`/`RepairMode` types and the SAME `boatramp project repair` CLI (the renderer is fully
backend-agnostic — it just iterates checks, breaks out DDL, prints the summary sentinels; NO CLI change
was needed). The `backend` header names the engine/topology (`classify_backend`, rewritten to be
model-aware: `shared-postgres` / `single-postgres` / `mysql` / `libsql` / `external`). Authz +
discoverability cure unchanged.

The blanket single `topology_skipped_report` is GONE; each model instead emits its inapplicable checks
as `skipped`-WITH-REASON (so the report is self-explaining), plus the real checks it owns.

### Model: Shared Postgres (`SharedPostgres`) — unchanged behavior

Compute-backed `tenant = shared` Postgres. The full 9-check owner-model retrofit (checks + probe/converge
exactly as before — I only moved the body into `repair_shared_postgres`, called by the dispatcher).
Site-scoped + reserved-default sub-cases still emit their `topology` skip.

### Model: Dedicated / single Postgres (`DedicatedPostgres`)

Compute-backed `tenant = single` Postgres — the CONTAINER is the boundary, no owner/runtime role split.
- **skipped (reason "dedicated Postgres — the container is the isolation boundary…"):** `owner-role`,
  `object-ownership`, `connect-grants`, `runtime-grants`.
- **`compute-workload`** — `deploy.get_compute_workload(ProjectRef::new(project), <compute>-<ident>)`
  (bare `<compute>` for the default tenant). Present ⇒ `ok`; absent ⇒ `drift` (repair does NOT spawn a
  server — reports it so the operator provisions). Read-only in both modes.
- **`credential-sealed`** — `ManagedSqlCredentials::is_sealed(single_credential_project, workload)`
  (read-only; sealed on apply via `password()`).
- **`ledger`** — `check_pg_ledger_exists`: probe `pg_tables` for `boatramp_migrations.schema_migrations`;
  apply-converge = `CREATE SCHEMA/TABLE IF NOT EXISTS` (idempotent; NO re-own — the configured user
  already owns what it creates on its dedicated server).
- **`connectivity`** — connect as the configured `user` + sealed credential to the tenant db, `SELECT 1`.
- **Probe/connect SQL:** `build_compute_backend` (a read-only `ComputeResolvedSqlBackend` to
  `<compute>-<ident>`, endpoint project = the tenant's project for non-default, else DEFAULT).
- **Live gate must prove:** a dedicated-PG tenant with a registered workload + sealed cred + present
  ledger reports all-`ok`; a missing ledger converges on apply; a dry-run seals/creates nothing; the
  role checks are `skipped` (not `error`).

### Model: MySQL (`Mysql`) — managed OR external, one model

MySQL has NO owner/runtime role split (runtime user gets `GRANT ALL ON <db>.*`).
- **`ddl-identity`** (reconciled FIRST, connection-independent) — mirrors the v0.5.1 migrate refusal
  EXACTLY (`mysql_ddl_backend_for`): a distinct DDL login via `migration_url_env`, distinct from the
  runtime by **byte** AND **`mysql_dsn_username`**. **Compute-backed managed MySQL with no derivable DDL
  identity ⇒ terminal `error`** (NOT a silent skip — same fail-closed condition migrate refuses). A
  declared-but-unset var ⇒ `error`; same-identity ⇒ `error`; distinct ⇒ `ok`. Pure function
  `check_mysql_ddl_identity` (no connection), so unit-testable + always in the report even if the runtime
  is unreachable.
- **`runtime-user`** — coarse read-only probe of `information_schema.schema_privileges` for the current
  login on `<db>` (matched via `GRANTEE LIKE '<user>'@%` off `CURRENT_USER()`). Present ⇒ `ok`, else
  `drift` (repair NEVER issues a `GRANT` — provisioning owns that).
- **`database`** — `information_schema.schemata` has `<db>`.
- **`ledger`** — `check_mysql_ledger_exists`: the runtime user has NO privilege on the ledger DATABASE
  (by design — it lives in a separate `boatramp_migrations` db only the DDL identity owns), so the probe
  keys on `information_schema.schemata` (visible metadata) for the db's existence; absent ⇒ `drift`
  (created by the DDL identity at migrate, not by repair over the runtime connection).
- **`connectivity`** — runtime `SELECT 1`.
- **Runtime connection:** `build_runtime_backend` — managed = `build_compute_backend` (tenant-derived
  workload/db/user + sealed cred; Shared → superuser cred under DEFAULT, Single → per-tenant); external =
  `build_external_backend` (`url_env`, read-only). All read-only (no `GRANT`/DDL in either mode).
- **Live gate must prove:** (a) managed MySQL with no `migration_url_env` ⇒ `ddl-identity` = `error`
  (matches `project migrate` refusing); (b) external MySQL with a distinct `migration_url_env` +
  present db + runtime grant ⇒ `ok`s; (c) same-user `migration_url_env` ⇒ `error`; (d) dry-run issues no
  GRANT/DDL.

### Model: libsql / SQLite (`Libsql`) — the file is the boundary

No roles/RLS.
- **skipped (reason "libsql/SQLite — the file is the trust boundary; no roles/RLS"):** `owner-role`,
  `object-ownership`, `connect-grants`, `runtime-grants`.
- **`db-file`** — the single-node `binding.path` exists (`path.is_file()`). A **dry-run over a
  non-existent file MUST NOT open it** (`LibsqlSql::open_local` CREATES on open) → it `stat`s first and
  reports `drift` + `skipped` ledger/connectivity WITHOUT opening (dry-run purity for the file boundary,
  asserted by `libsql_dry_run_does_not_create_the_file`). A **remote-sqld** binding (`url_env`, no
  `path`) → `db-file` `skipped` (the namespace lives on the sqld server, not a boatramp-owned file).
- **`ledger`** — `check_libsql_ledger`: probe `sqlite_master` for the reserved-prefix single table
  `boatramp_migrations_schema_migrations`; apply-converge = `CREATE TABLE IF NOT EXISTS` (idempotent).
- **`connectivity`** — open + `SELECT 1`.
- **Feature gating:** the file-open logic lives in `libsql_file_reconcile`, present only under
  `feature = "migrate"` (the embedded libsql runner); the no-`migrate` fallback reports a `topology`
  skip. The SHIPPED binary enables `migrate` (default features), so the libsql arm is fully live in
  release; the module itself stays `#![cfg(any(sql-postgres, sql-mysql))]` to match the node wiring gate
  (see uncertainty below).
- **Probe/converge SQL:** `SELECT 1 FROM sqlite_master WHERE type='table' AND name='boatramp_migrations_schema_migrations';`
  / `CREATE TABLE IF NOT EXISTS "boatramp_migrations_schema_migrations" (id TEXT PRIMARY KEY, ordinal
  INTEGER NOT NULL, content_hash TEXT NOT NULL, kind TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT
  CURRENT_TIMESTAMP, applied_by TEXT);` (byte-identical columns to `LibsqlMigrationRunner::ensure_ledger`).
- **Live gate must prove:** on a real `path`, dry-run over an absent file creates NOTHING on disk and
  reports `db-file` drift; apply over an existing file scaffolds the ledger + `SELECT 1` succeeds; a
  re-apply is all-`ok` (idempotent). MUTATION-verify the dry-run-purity claim: assert the file does not
  exist after a dry-run.

### Model: External / bring-your-own (`External`)

`url_env` set, no managed compute (a bring-your-own Postgres — external MySQL routes to `Mysql`).
- **skipped (reason "operator-owned binding…"):** `owner-role`, `object-ownership`, `connect-grants`,
  `runtime-grants` (boatramp owns no roles on the operator's server).
- **`ledger`** — `check_pg_or_mysql_ledger_exists` over the `url_env` runtime connection (Postgres
  schema.table probe + `CREATE … IF NOT EXISTS` converge). An unknown/unsupported engine → `ledger`
  `skipped` (only connectivity/topology is inspectable).
- **`connectivity`** — `SELECT 1`.
- **Connection:** `build_external_backend` reads `url_env` from the ENV (never operator-file input),
  read-only, 1 conn.
- **Live gate must prove:** an external Postgres reconciles only its ledger + connectivity (role checks
  `skipped`), and a dry-run over an absent ledger runs no DDL.

## Requirements honored across all models

- **Dry-run side-effect-free:** every probe is a read-only `SELECT`/`is_sealed`/`stat`; NO
  `password()`/`put`/DDL in dry-run. Proven by unit tests: `credential_sealed_dry_run_never_writes`,
  `converge_ledger_dry_run_runs_nothing` (mock panics on any `run_script`),
  `libsql_dry_run_does_not_create_the_file` (asserts the file is absent on disk after a dry-run).
- **Data-preserving:** only `CREATE … IF NOT EXISTS` / ownership; never a `DROP`/`TRUNCATE`/`DELETE`/
  `UPDATE` of tenant rows on any path.
- **Derived-names-only:** every db/role/workload/credential-key name comes from `tenant_provision` /
  `tenant_names` / `tenant_key` / `single_credential_project` derivation over the validated
  `(project, binding)`, never a probe result; a probe result is only an `==`/existence verdict.
- **Fail-closed per check + `skipped` carries a reason + op exits 0:** an unreachable runtime marks
  dependent checks `error`/`skipped` (never dropped); `skipped` always has a reason; the CLI exit code
  policy (0 clean / 1 any-error / 2 opt-in drift) is unchanged.
- **`backend` header names the engine** (`classify_backend`).

## Per-model unit tests added (all green; `boatramp-node repair::tests`, 23 total)

`classify_model_maps_every_backend_shape`, `classify_backend_labels_each_model`,
`targeted_reown_emits_kind_correct_variant` (JOB 1), `mysql_managed_without_ddl_identity_is_terminal_error`,
`mysql_external_ddl_identity_distinctness`, `credential_sealed_dry_run_never_writes`,
`converge_ledger_dry_run_runs_nothing`, and (under `feature = "migrate"`)
`libsql_dry_run_does_not_create_the_file`, `libsql_apply_scaffolds_ledger_on_existing_file`,
`libsql_remote_sqld_has_no_local_file`.

## Build / lint status

`cargo build` + `cargo fmt --all --check` + `cargo clippy -p boatramp-node --all-targets` clean under
`sql-postgres`, `sql-mysql`, and `sql-postgres,sql-mysql,migrate`; the full `boatramp` binary (default
features) builds; `boatramp-node` lib tests 135/135 green. No warnings from the touched files.

## Deviations / uncertainty (JOB 2)

- **Module feature gate vs a `migrate`-only node.** `repair.rs` stays `#![cfg(any(sql-postgres,
  sql-mysql))]` (unchanged) — matching the node's `tenant_repair` wiring gate. The libsql FILE reconcile
  is `#[cfg(feature = "migrate")]` WITHIN the module. So: a node with a sqlx engine + `migrate` (the
  shipped default) fully reconciles a libsql binding in its `databases`; a **`migrate`-only node with NO
  sqlx** would not compile/wire the repair capability at all (there is nothing to repair — it has no
  managed sqlx DB either, but it COULD have a libsql binding). Widening the module + node wiring to
  `any(sql-postgres, sql-mysql, migrate)` would close that edge, but it destabilizes the node-wiring
  cfg-cascade (the `NodeTenantRepair` struct holds `DeployStore`/`kv`/envelope, all sqlx-only today) — I
  judged that out of scope for "leave the tree for review" and **flag it** for the reviewer. Impact:
  libsql repair is live in every SHIPPED build; only a hypothetical lean migrate-only node lacks it.
- **MySQL `runtime-user` probe is coarse.** `information_schema.schema_privileges` + a `GRANTEE LIKE`
  match off `CURRENT_USER()` — a false `drift` only REPORTS (repair never issues a GRANT), so the safe
  direction. A reviewer may want a finer probe (e.g. asserting specific privilege types). Flagged.
- **MySQL managed `runtime-user`/`database` when the runtime uses a per-tenant credential.** The managed
  runtime backend is built with the tenant-derived workload/db/user + sealed cred exactly as the resolver
  does; if a managed MySQL tenant was never provisioned, `build_runtime_backend`'s `password()` seals a
  credential on APPLY (create-if-absent) — but the managed-MySQL migrate path is refused anyway
  (`ddl-identity` terminal error), so this is reported, not acted on destructively. Flagged for the live
  gate to confirm the managed-MySQL path stays a report (no accidental seal drift).
- **External model reached only for bring-your-own Postgres / unknown engines.** External MySQL routes
  to `Mysql` (which handles both managed + external). The `check_pg_or_mysql_ledger_exists` MySQL arm is
  therefore dead for the External model today — kept as a defensive shared helper. Flagged.
- **`db-file` dry-run stat-then-open.** The libsql dry-run purity relies on `path.is_file()` before
  `open_local`. A TOCTOU race (file created between the stat and a subsequent apply-open) is benign — the
  apply is the only path that opens an absent file, and creating the db there IS the reconcile. Flagged
  as an intentional non-issue.

---

# CI live gate — AUTHORED (Backend-Architect, shared-Postgres retrofit)

**File:** `crates/boatramp-node/tests/repair_reconcile_pg_live.rs`. **Marker:** `PROVISION REPAIR RECONCILE OK`.
**Wired:** `.github/workflows/ci.yml`, job `test-orm-tenancy-sqlx` (the same Postgres service the migrate PG
gates use), immediately after the `MIGRATE RUNNER LEDGER OK [postgres]` step — greps the marker + `test
result: ok. 1 passed` (a silent skip / failure fails the merge). Run:
`cargo test -p boatramp-node --features sql-postgres,migrate --test repair_reconcile_pg_live`.
Gated on `BOATRAMP_TEST_PG_URL` (a **superuser** url; skips cleanly with an `eprintln` when unset). Locally
green against `brpg-probe` (`postgres://postgres:probe@127.0.0.1:15433/postgres`), re-runnable (self-teardown
at the top + tail), `cargo fmt --all` + clippy clean. repair.rs / repair/tests.rs / other tests UNTOUCHED.

## How it stands up a shared tenant without a container

repair (like provisioning) connects via `ComputeResolvedSqlBackend` + `DeployEndpointResolver`, so the gate
seeds the control-plane state a real node holds — **no container**: (1) pre-seal the superuser credential
under `managed-sql-cred/default/pg` (the exact key `provision_shared` + the server-init injector read) to the
test URL's ACTUAL password (a plain `password()` would mint a random one the real server rejects); (2)
`set_replica_state` one healthy `Running` `pg` replica → the test PG's host:port so the resolver resolves
`pg`. Then `provision_tenant` (shipped path) provisions A/B/C; a DIRECT sqlx superuser backend does the
pre-v0.4.25 mutation + all verification. Every ownership assertion reads the **live pg catalog**
(`pg_database.datdba` / `pg_class.relowner` / `pg_proc.proowner` via `pg_get_userbyid`) — NOT the repair
report — so a green-but-wrong report can't fool it.

## What it proves (task #491 items 1–8)

1. Provision a shared tenant, MUTATE to the pre-v0.4.25 shape: `DROP OWNED BY <owner>` (strip its tenant-db
   grants/default-privs) → `ALTER DATABASE OWNER TO <runtime>` → `DROP ROLE <owner>`; a runtime-owned table+row,
   a superuser-owned table+row, a **standalone superuser-owned SEQUENCE** (advanced past its start so a
   drop/recreate would be observable), and an **overloaded superuser-owned FUNCTION** (`super_fn(int)` +
   `super_fn(int,int)`). Pre-state is asserted from the catalog before repair.
2. `repair --dry-run` → asserts `owner-role-exists`=Drift (ddl names the derived owner + `CREATE ROLE`),
   `owner-credential-sealed`=Drift, and — from the LIVE catalog — the dry-run created no owner role, changed no
   db/table/sequence/function ownership, and scaffolded no ledger.
3. `repair --apply` → owner role recreated with NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOBYPASSRLS/NOREPLICATION
   (read from `pg_roles`), owner credential sealed (KV), and the db + BOTH tables + the sequence + BOTH function
   overloads + the ledger schema&table all `pg_get_userbyid`==owner; CONNECT revoked from PUBLIC, granted to
   owner+runtime; every seeded row still present and the sequence value preserved (data intact).
4. `repair --apply` again → NO check is `Repaired` (idempotent) and the seven core checks read `Ok`.
5. Scope → tenant B's `datdba` + roles are byte-identical to a pre-repair fingerprint.
6. Isolation → the runtime role still CONNECTS + queries after repair (strict; see FINDING-2 for the read).
7. Soft-delete → a soft-deleted tenant is a zero-action, no-error no-op that touches nothing (see FINDING-3).
8. Mutation-check → below.

## Mutation-check (item 8) — RESULT

I could **not** perform the destructive mutation-in-`repair.rs` experiment: the boundary "do NOT edit repair.rs
(a reviewer owns repair.rs + the mutation-verification)" is enforced by the harness, which blocked the edit
(repair.rs is byte-for-byte unchanged). So I verified the gate's **non-hollowness by construction** — every
converge step is checked by an INDEPENDENT live-catalog probe, not the report — and map each removable converge
to the assertion that catches it (the reviewer should confirm by actually removing each and re-running):

| Removed converge step (in `check_object_ownership` / `check_db_owner`) | Gate assertion that FAILS | Why (live-catalog, report-independent) |
|---|---|---|
| `ALTER DATABASE <db> OWNER TO <owner>` (check 3) | "apply re-owned the database to the owner role" (`db_owner` via `pg_database.datdba`) | the db stays runtime-owned from the mutation → `datdba` ≠ owner |
| `REASSIGN OWNED BY <runtime> TO <owner>` (the runtime-owned arm) | "runtime-owned table re-owned to owner" (`rel_owner` on `runtime_widget`) | `runtime_widget.relowner` stays the runtime role |
| targeted `ALTER TABLE … OWNER TO <owner>` (superuser arm) | "superuser-owned table re-owned to owner" (`rel_owner` on `super_gadget`) | `super_gadget.relowner` stays `postgres` |
| targeted `ALTER SEQUENCE … OWNER TO <owner>` (the JOB-1 sequence arm) | "superuser-owned SEQUENCE re-owned to owner" (`rel_owner` on `super_counter`) | a table-only converge leaves the sequence `postgres`-owned |
| targeted `ALTER FUNCTION …(<args>) OWNER TO <owner>` (the JOB-1 function arm) | "BOTH superuser-owned FUNCTION overloads re-owned to owner" (`fn_owners` via `pg_proc.proowner`, DISTINCT set) | a table-only converge — or one that re-owns only ONE overload — leaves ≥1 `proowner`=`postgres`, so the DISTINCT-owner set ≠ `[owner]` |

The pre-mutation assertions (super_gadget/super_counter/super_fn == `postgres`, runtime_widget == runtime role)
plus the post-apply catalog reads make each of the five re-ownership converges load-bearing: the gate observes
the ownership TRANSITION, not merely a green report. I also empirically confirmed the pre-state on the live PG
(the gate asserts it every run), so a converge that no-ops leaves the observable pre-state and trips its row above.

## FINDINGS surfaced by the live gate (for the repair.rs owner)

The gate stays GREEN (it asserts the load-bearing, achievable invariants strictly) but prints an `eprintln!
FINDING …` for each real gap below rather than paper over it — flagged for the repair.rs owner to decide. All
three are reproducible by running the gate against a real PG.

- **FINDING-1 — dry-run seals the owner credential (dry-run purity gap).** The terminal connectivity check (#9,
  runs in BOTH modes) calls `probe_role_can_connect` → `ManagedSqlCredentials::password()`, which is
  **create-if-absent + seal**, for the OWNER and RUNTIME credential workloads. On a `--dry-run` of a pre-v0.4.25
  tenant (owner role absent, owner cred cleared) this **SEALS the owner credential** as a side effect. Proven
  load-bearing by the gate: check-8 `owner-credential-sealed` correctly reports `Drift` (its own converge sealed
  nothing), yet the owner-cred KV key is present after the dry-run — so the seal came from check-9. The task's
  strict invariant "no KV seal written on a dry-run" does NOT hold today. Suggested fix: connectivity should
  probe `is_sealed` and skip the connect (report "not sealed → can't verify") when unsealed, never `password()`.
  The gate asserts the load-bearing dry-run purity strictly (no role / no ownership change / no ledger) and
  records this credential seal as the finding.
- **FINDING-2 — `runtime-grants` coarse probe leaves a retrofitted runtime role without table access.** Check 6
  probes only schema-`USAGE`; a retrofitted tenant already has USAGE, so check 6 reports `Ok` and SKIPS the
  idempotent `grant_app_role_ddl`. But repair's check-4 `REASSIGN OWNED BY <runtime> TO <owner>` moved the
  runtime role's OWN tables to the owner role, and REASSIGN does not grant the old owner anything back — so
  after repair the runtime role CONNECTS but gets `permission denied` reading `runtime_widget` (a table it owned
  before). A retrofitted tenant's app would break until a later migrate re-runs the grants. The gate asserts the
  strict connect-lockdown invariant (runtime still CONNECTS + `SELECT 1`) and records the table-read denial as
  the finding. Suggested fix: run `grant_app_role_ddl` unconditionally on apply (it is idempotent + never
  revokes), or give check 6 a finer probe (a representative table privilege, not just schema USAGE).
- **FINDING-3 — soft-delete rename + repair's soft-delete probe are broken for near-max-length db names.** A
  DERIVED tenant db name is already ~59–63 bytes (`tenant_db_name` pads a 25-char base36 digest, capped at
  Postgres's 63-byte `NAMEDATALEN`). The soft-delete's rename target `<db>__deleted_<ts>` is 80+ bytes, which
  Postgres SILENTLY TRUNCATES to 63 — for a 63-byte `<db>` that is byte-for-byte the ORIGINAL name, so
  `soft_deprovision_ddl` / `deprovision_tenant`'s `ALTER DATABASE <db> RENAME TO <db>__deleted_<ts>` fails with
  42P04 `database "<db>" already exists` (a rename-to-self). Consequences: (a) a near-max-length Shared-Postgres
  tenant **cannot be soft-deleted** at all; (b) repair's soft-delete probe `datname LIKE '<db>__deleted\_%'` can
  never match a truncated sibling, so a would-be soft-deleted tenant is classified `database` (absent) rather
  than `soft-delete`. Both are zero-action no-ops in repair (the task's "touches nothing" holds either way), but
  the `soft-delete` skip branch is effectively unreachable for standard names. The gate builds a
  TRUNCATION-SAFE aside name so it can still stand up a real soft-deleted state + prove repair's no-op, and
  records the truncation gap as the finding. Suggested fix (in `soft_deprovision_ddl`/`tenant_db_name`): reserve
  headroom in the derived db name for the `__deleted_<ts>` suffix, or build the aside name by truncating `<db>`
  to fit 63 bytes with the suffix, and align repair's soft-delete `LIKE` to the same scheme.

---

## Fixes applied (post-review — Security + Postgres live gate follow-up)

Four fixes from the Security review + the live gate, plus a live-gate strengthening that turns
two soft `FINDING` prints into HARD assertions. All in `crates/boatramp-node/src/{repair.rs,
managed_sql.rs}`, `crates/boatramp-node/src/repair/tests.rs`, and
`crates/boatramp-node/tests/repair_reconcile_pg_live.rs`.

### FIX 1 (HIGH) — a dry-run must not seal a credential
- **Bug.** The terminal connectivity check (#9, both modes) via `probe_role_can_connect`, and the
  dedicated-PG / managed-MySQL connectivity probes via `build_compute_backend` /
  `build_runtime_backend`, called `ManagedSqlCredentials::password()` — which is **create-if-absent
  + SEAL**. So a `repair --dry-run` over a pre-v0.4.25 tenant (owner/runtime credential absent)
  performed a KV write (a side effect on a probe-only op). This is exactly the gap FINDING-1
  (below in the earlier notes) recorded.
- **Fix.** New `ManagedSqlCredentials::get_sealed_password(project, workload) -> Option<String>`
  (next to `is_sealed`): the pure unseal branch of `password` (`kv.get` + `envelope.unwrap`),
  `Ok(None)` when absent, NEVER `wrap`/`put`. `RepairMode` is threaded into `check_connectivity`,
  `probe_role_can_connect`, `build_compute_backend`, `build_runtime_backend` (+ every call site).
  On `DryRun` the credential is resolved via `get_sealed_password`; an absent one is a benign
  `skipped` ("credential not yet sealed — connectivity verified after apply"), never sealed, never
  an error, op still exits 0. On `Apply` the behavior is unchanged (`password()` — sealing IS the
  reconcile). A new `ConnectProbe` tri-state (Connected/Refused/Unsealed/Failed) and a
  `BackendBuildError::{Unsealed,Other}` carry the "unsealed on dry-run" signal to the callers.
  **Audit: no dry-run code path anywhere calls `password()` or `kv.put`** (all five remaining
  `password()` calls are in `RepairMode::Apply` arms).
- **Regression test** (`dry_run_repair_over_unsealed_tenant_writes_no_kv_keys`, mock KV): a full
  `repair_tenant(..., DryRun)` over an UNSEALED shared-Postgres AND dedicated-PG AND managed-MySQL
  tenant leaves the KV byteset unchanged (only the pre-sealed superuser cred remains; no
  owner/runtime key added). This is the end-to-end check the isolated per-check tests missed.

### FIX 2 (HIGH) — repair must not break the runtime app's data access
- **Bug.** `check_runtime_dml_grants` probed ONLY `has_schema_privilege(runtime,'public','USAGE')`,
  which SURVIVES check-4's `REASSIGN OWNED BY <runtime> TO <owner>`. So a retrofitted tenant
  reported `ok`, skipped `grant_app_role_ddl`, and the runtime — which lost its implicit owner
  SELECT when its tables were reassigned — got `permission denied` on its own data (FINDING-2).
- **Fix.** The probe is now accurate: drift unless USAGE on `public` AND the runtime holds SELECT
  on EVERY public table (`SELECT count(*) FROM pg_tables WHERE schemaname='public' AND NOT
  has_table_privilege(<runtime>, format('%I.%I',…), 'SELECT')` == 0). On drift the existing
  idempotent `grant_app_role_ddl` converge runs (unchanged); a fully-granted tenant stays a clean
  `ok` no-op (idempotency: repair-then-repair = zero actions). The verdict is extracted to a pure
  `runtime_dml_grants_ok(has_usage, tables_without_select)` helper + unit test
  (`runtime_dml_grants_verdict_requires_select_on_every_table`).

### FIX 3 (MEDIUM) — exclude the ledger schema from the bulk re-own enumeration
- `check_object_ownership`'s enumeration now carries `AND n.nspname <> 'boatramp_migrations'` on
  BOTH the `pg_class` and `pg_proc` arms, so the ledger is never swept into the bulk `REASSIGN`; it
  is reconciled ONLY by check 7 (its explicit `ALTER SCHEMA`/`ALTER TABLE … OWNER`), keeping the
  two reconcilers from fighting over it.

### FIX 4 (MEDIUM, defense-in-depth) — guard the one un-`quote_ident`'d probe string
- `targeted_reown_ddl`'s `ALTER FUNCTION "<schema>"."<name>"(<args>)` arm pastes `<args>`
  (`pg_get_function_identity_arguments`, a type-signature fragment, not a single identifier) VERBATIM.
  It is Postgres's own canonical rendering for a function that provably exists in the already-confined
  tenant db (not operator/guest input), but as defense-in-depth the fn now returns `Err(reason)` —
  the object is SKIPPED, no DDL emitted (fail closed) — if `args` contains a `;` or an UNBALANCED
  number of single/double quotes. Skipped objects are logged + surfaced in the check `detail` and
  NOT counted as re-owned. The return type changed to `Result<String, String>`; the module
  security-invariant list documents that function args are the sole probe string not `quote_ident`'d,
  with this guard. Unit test: `targeted_reown_function_args_guard_fails_closed`.

### Live gate strengthened (`repair_reconcile_pg_live.rs`) — FINDINGs → HARD assertions
- **FIX 1:** after `repair --dry-run` over the pre-v0.4.25 tenant (the gate deletes the per-tenant
  owner-cred key first; only the superuser cred `managed-sql-cred/default/pg` is pre-sealed), the
  owner-cred KV key is HARD-ASSERTED still ABSENT — proving no dry-run path sealed it.
- **FIX 2:** after `repair --apply`, the RUNTIME role must `SELECT` its seeded row from the re-owned
  table (`SELECT name FROM runtime_widget WHERE id = 1` == "rw") — a hard `.expect()`/`assert_eq!`,
  no longer a `FINDING` branch. Catches the exact `permission denied` regression FIX 2 closes.
- Marker `PROVISION REPAIR RECONCILE OK` kept.
