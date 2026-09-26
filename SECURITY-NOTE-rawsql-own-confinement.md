# DRAFT Security Note — raw-SQL own/session `{scope}` marker OR-escape (P0)

**Status:** DRAFT (for the Security-Engineer review + a hotfix release). Not a released CHANGELOG.
**Severity:** P0 tenant-isolation. Pre-existing (v0.5.7 and earlier).
**Branch:** `rawsql-own-confinement` (base v0.5.7 `63dd275`).

## Summary

An untrusted `read:"own"` / `write:"own"` (or `session`) wasm guest that imported the raw `sql`
binding could read AND write **across tenants** by `OR`-escaping the guest-cooperative `{scope}`
marker. The marker was string-substituted into guest SQL with no AST check:

```sql
UPDATE orders SET status='void' WHERE 1=1 OR {scope}   -- → OR tenant_id=? → ALL tenants
DELETE FROM orders WHERE {scope} OR ('a'='a')          -- → ALL tenants
SELECT * FROM orders WHERE {scope} OR 1=1              -- cross-tenant READ disclosure
```

Cross-tenant read AND write, unbackstopped on libsql/SQLite (the default), MySQL, and external/BYO
Postgres; managed Postgres was only protected if the operator opted into `rls_session` + `tenant_guc`
AND the app authored `WITH CHECK` policies. The codebase already documented this exact escape as
"structurally unfixable with a text marker" (`target_sql.rs`) and had closed it for the **target-read**
path only, leaving own/session read+write on the escapable marker. The **ORM path was already safe**
(structural `force_scope` injection).

## Fix

Force-inject the tenant confinement at the **AST** level for own/session (read AND write), exactly as
the target-read path and the ORM already do — backend-independent (the SQL is rewritten before any
engine sees it), so it covers libsql/SQLite/MySQL/Postgres uniformly without relying on RLS.

- The completeness-argued `VisitMut` walk in `boatramp_core::target_sql` is **generalized** over a
  `Confiner` trait; the target path (`TargetConfiner`) is byte-for-byte unchanged and a new
  `OwnConfiner` mirrors `orm::Scope::read_pred`. `rewrite_own_read` confines EVERY table reference
  (root FROM, JOINs, subqueries, set-op arms; CTEs refused) to the caller's own/session partition;
  the guest `WHERE` is parenthesised before the confinement is `AND`-ed on, so a top-level `OR`
  cannot widen past the gate.
- `rewrite_own_write` mirrors `orm::Scope::write_target`/`force_scope`: UPDATE/DELETE AND
  `tenant_col = <own>` onto the parenthesised guest WHERE; an UPDATE cannot re-tenant (a guest
  `SET tenant_col = …` is forced back to `<own>`); an INSERT force-stamps the tenant column in VALUES
  (a guest-supplied tenant is overridden) and read-confines any `INSERT … SELECT` source; a plain
  `Unscoped` (global) write stays refused (deny-by-default — global writes are ORM-only on this base).
- The `{scope}` marker is now **optional and inert** (neutralised to `1 = 1` if present) — the
  confinement is host-injected structurally, so a guest can neither move nor `OR`-escape it. Existing
  guests that placed `{scope}` keep working.
- **Fail-closed**: unparseable / no-principal own write / undeclared table / multi-table or qualified
  write target / unsupported shape → refused. Never a fall-back to the old marker.

`SharedWritable` (read-none, write-allowed-if-global) is NOT a variant on this base; a clean extension
point is documented in `OwnConfiner::table_read_pred` for #503's rebase.

## Verification

`RAWSQL OWN-CONFINEMENT AST OK` — a live, behavioral, **mutation-verified** gate
(`crates/boatramp-storage/tests/rawsql_own_confinement.rs`) proving the 8 invariants on a REAL engine
(embedded libsql + env-gated Postgres + MySQL): (1) write OR-escape neutralized (victim B unchanged);
(2) read OR-escape neutralized; (3) JOIN/subquery multi-table confinement; (4) INSERT force-stamp
overrides a forged tenant; (5) UPDATE cannot re-tenant; (6) OwnOrNull/NullOnly ORM parity; (7) raw↔orm
cross-surface parity (read + write); (8) fail-closed + DELETE OR-escape confined.

A runtime mutation seam reverts the confinement to the old escapable string marker
(`RAWSQL_CONFINE_MUTATION=string-marker`) or to no confinement (`no-confinement`); the CI steps loop
both and assert the gate then exits non-zero — so a hollow gate or a regression that re-opens the hole
fails the merge. Verified locally: the real fix passes all three engines; `string-marker` kills
invariants 1-6,8; `no-confinement` kills all 8.

## Residual notes

- **Perf:** every own/session raw-SQL statement is now parsed+rewritten once (previously only the
  target path parsed). Hot-path cost; parse-once per statement, correctness wins for a P0.
- **Not covered by the AST walk (refused, not silently passed):** CTE-led statements, multi-table /
  `USING` DELETEs, `UPDATE … FROM`, `ON CONFLICT` upserts (use the typed `orm` surface), `INSERT …
  SELECT` that names the tenant column, exotic table sources. These fail closed.
