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
- **Check 4 targeted re-own kind.** For a superuser-owned object I emit `ALTER TABLE IF EXISTS … OWNER
  TO …`. `ALTER TABLE` covers tables/views/matviews; a bare sequence/function of the same name would not
  be re-owned by that statement. In the witness (a shared tenant's schema is superuser-LOADED tables),
  this is sufficient, but **a reviewer may want to also emit `ALTER SEQUENCE`/`ALTER FUNCTION` variants**
  (guarded/kind-detected) for full generality. The enumeration already SEES sequences (`relkind='S'`) and
  functions (`pg_proc`), so the drift is *detected*; only the targeted converge is table-shaped. I left it
  narrow to avoid emitting a wrong-kind ALTER that isn't `IF EXISTS`-guardable for functions. **Flagged.**
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
