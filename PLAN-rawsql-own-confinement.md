# PLAN — close the raw-SQL own/session `{scope}` marker OR-escape (P0)

**Branch:** `rawsql-own-confinement` · **Base:** v0.5.7 (`63dd275`) · **Severity:** P0 tenant-isolation
**Status:** owner-directed fix (2026-09-26). Pre-existing (v0.5.7 and earlier). Ship behind a Security-review loop to convergence + a mutation-verified gate → hotfix release.

## The hole (verified, live-demonstrated)
The raw-SQL `{scope}` marker for **own/session** scope is string-substituted into guest-controlled SQL with NO AST check: `crates/boatramp-handlers/src/tenant.rs::sql_marker` (Own/OwnOrNull/Null arms) returns a bare predicate `tenant_col = ?N`, and `crates/boatramp-handlers/src/bindings/sql.rs::apply_scope_marker` does `statement.replace(SCOPE_MARKER, &pred)`. An untrusted `read:"own"`/`write:"own"` wasm guest OR-escapes it:
```sql
UPDATE orders SET status='void' WHERE 1=1 OR {scope}   -- → WHERE 1=1 OR tenant_id=? → ALL tenants
DELETE FROM orders WHERE {scope} OR ('a'='a')          -- → ALL tenants
SELECT * FROM orders WHERE {scope} OR 1=1              -- cross-tenant READ disclosure
```
Cross-tenant **read AND write**. Unbackstopped on libsql/SQLite (the default), MySQL, external/BYO Postgres; managed Postgres only if operator opted into `rls_session`+`tenant_guc` AND the app authored `WITH CHECK` policies. The codebase documents this exact escape as "structurally unfixable with a text marker" (`crates/boatramp-core/src/target_sql.rs:6-9`) and built an airtight AST-rewrite fix — but applied it ONLY to the **target-read** path (`rewrite_target_read` / `is_target()`), leaving own/session read+write on the escapable marker. The **ORM path is SAFE** (structural `force_scope` injection, guest WHERE parenthesized — `orm.rs`).

## Fix — force-inject the confinement at the AST level for own/session (read AND write), matching what the ORM + the target-read path already do
Do to raw-SQL own/session what `target_sql.rs` already does to target reads and what `orm.rs::force_scope` does to typed queries: parse the guest statement into an AST and inject the tenant confinement structurally onto EVERY table reference, where the guest cannot move or `OR`-escape it. Backend-independent (rewrites the SQL before any engine sees it), so it covers libsql/SQLite/MySQL/Postgres uniformly without relying on RLS.

### Reuse, don't reinvent
- `crates/boatramp-core/src/target_sql.rs` already has the complete, completeness-argued `VisitMut` walk (`rewrite_target_select`): confines every table ref (root FROM, JOINs, subqueries, CTEs refused up front, UNION/INTERSECT/EXCEPT arms), parenthesizes the guest WHERE before AND-ing the confinement. **Generalize it** to take a per-table predicate builder for the OWN/SESSION axes (not just target), or add sibling entrypoints `rewrite_own_read`/`rewrite_own_write` that reuse the same walk with the own/session predicate.
- The per-table predicate for own/session READ mirrors `orm.rs::read_pred`: `Tenant`/`TenantKeyed` → `tenant_col = <own>`; `TenantOrSession` → the R3 disjunction `(tenant = T OR session = S)` over held facts; `TenantOrBase` → `(tenant = <own> OR tenant IS NULL)`; `Unscoped` → no predicate (global read). (Note: `SharedWritable` does not exist on this base — it arrives when #503 rebases onto this fix; leave a clean extension point.)
- WRITE semantics mirror `orm.rs::force_scope` / `write_target`:
  - **UPDATE/DELETE:** parenthesize the guest WHERE and AND `tenant_col = <own>` (or the session-axis value) onto the target table; and for UPDATE, prevent the guest SETting the tenant column to another tenant (drop/re-append the tenant assignment forced to `<own>`, as the ORM does).
  - **INSERT:** force-stamp the tenant column in the VALUES/columns (an INSERT has no WHERE — the marker was always meaningless for INSERT), and scope any `INSERT … SELECT` source through the same read rewrite. Refuse an `Unscoped` INSERT unstamped (deny-by-default, unchanged) — global writes are ORM-only (per #503; on this base the plain `Unscoped` write stays refused).

### Marker compatibility
Currently own/session raw SQL REQUIRES `{scope}`. Switch to the airtight AST rewrite (as target already is — no marker needed) and make `{scope}` OPTIONAL/ignored: if present, neutralize it (`1 = 1`) since the host now injects the real, unescapable confinement structurally. Existing guests that place `{scope}` keep working (it becomes inert; the AST-injected confinement is authoritative). Document the shift ("raw-SQL scoping is now host-injected structurally; `{scope}` is no longer required and cannot be escaped").

### Preserve every existing invariant
- Target read/write paths unchanged (already airtight).
- `all` mode: no confinement (unchanged); the `apply_all_write_rls` GUC path stays as-is.
- RLS GUC stays as optional defense-in-depth.
- Reserved-session-key write guard, multi-statement refusal, CTE refusal, `?N` placeholder handling — preserved.
- Fail-closed: an unparseable statement, a no-principal own write, an undeclared table → refused (do NOT fall back to the escapable marker).

## Security invariants the gate must prove (mutation-verified, behavioral — not structural)
Marker e.g. `RAWSQL OWN-CONFINEMENT AST OK`, run on libsql/SQLite + Postgres + MySQL where feasible:
1. **OR-escape neutralized (the core):** `UPDATE t SET x=1 WHERE 1=1 OR {scope}` (and `{scope} OR 1=1`, `... OR ('a'='a')`, marker under parens/`CASE`/`NOT`) under `write:"own"` tenant A writes ONLY tenant A's rows — a victim tenant B's rows are UNCHANGED. Neuter the AST injection (revert to string marker) ⇒ B's rows change ⇒ gate FAILS.
2. **Read OR-escape neutralized:** `SELECT * FROM t WHERE {scope} OR 1=1` under `read:"own"` A returns ONLY A's rows (no B rows).
3. **Multi-table / JOIN / subquery confinement:** a guest JOIN or `IN (SELECT … FROM t2)` confines t2 too (no cross-tenant leak via a joined/subquery table) — reuse the target-path completeness.
4. **INSERT force-stamp:** `INSERT INTO t (tenant_col, x) VALUES ('victimB', 1)` under A lands stamped `tenant_col = A` (guest-supplied tenant overridden), NOT B; `INSERT … SELECT` source is scoped to A.
5. **UPDATE cannot re-tenant:** `UPDATE t SET tenant_col='victimB' WHERE {scope}` cannot move A's row to B (tenant assignment forced to A or refused).
6. **TenantOrSession / TenantOrBase / Unscoped** own reads/writes behave exactly as the ORM (disjunction / base-inclusive / global-read) — no regression.
7. **Parity with ORM:** the same query via the raw `sql` binding and via the `orm` binding yield equivalent confinement (cross-surface parity — the load-bearing invariant `tenant.rs:9-11`).
8. **Fail-closed:** unparseable / no-principal / undeclared ⇒ refused, never the old marker fallback.
Each: mutation-test that reverting the mechanism FAILS the assertion. Add the gate to `.github/workflows/ci.yml` mirroring the existing cross-surface mutation-gate convention.

## Notes / sequencing
- **Perf:** every own/session raw-SQL statement now gets parsed+rewritten (previously only target did). Hot-path cost; correctness wins for a P0. Note it in the release; optimize later if needed.
- **#503 interaction:** #503 (`scoped-unscoped-write`, held) removed its raw-SQL exemption and is ORM-only for global writes. After THIS P0 lands on main, #503 rebases onto it and teaches this AST-rewrite about `SharedWritable` (read-none, write-allowed-if-global) at the clean extension point. P0 ships FIRST (hotfix), then #503 rebases + ships.
- This is a hotfix: version-bump (next patch), full local musl clippy before tag (v0.5.7 lesson), CI+Release, construens gets no request note (owner/security-initiated) but a CHANGELOG security entry.

## Constraints for the build
- Build + test only; no version bump / no release / no push / no tag / no shim.
- Reuse `target_sql.rs`'s proven walk + completeness argument; mirror `orm.rs::force_scope`/`read_pred`/`write_target` for the per-table predicates + write semantics. Read all three before writing.
- Edition 2024 let-chains; CI `-D warnings`; `cargo clippy -p <crate> --all-targets` + `cargo fmt` + `typos` clean on touched crates. Commit incrementally, `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer (`PRE_COMMIT_ALLOW_NO_CONFIG=1` if needed).
