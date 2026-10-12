# Default-scope migration (v0.31.0, Security Finding 8)

**This is a BREAKING, data-re-homing change. Read this before upgrading a node that has served
`default`-project traffic.**

## What changed

`ProjectRef::qualified(base)` used to special-case the reserved `default` project to a **bare**,
one-segment data-plane scope (`qualified(default, "blog") == "blog"`). That single-segment default
let a `default`-project workload **collide** with a same-named **named** project across every
client-composed-key data family — e.g. the default project's site `acme` keyed
`hblob/acme/…`, a prefix of the named project `acme`'s `hblob/acme/blog/…`.

As of v0.31.0 `qualified` is **always** two-segment, including the default project:
`qualified(default, "blog") == "default/blog"`. `default` is now a normal project, **disjoint** from
every named project (no named project can be `default` — it is reserved at project-create). This
re-homes the data that persists the scope string: `{base}` → `default/{base}`.

## What is NOT affected

- **Managed Postgres / MySQL (RLS).** No `qualified()` output feeds the managed SQL backends; their
  tenancy keys on the tenant-axis column (the session GUC), not on the scope string. **There is no
  RLS migration** — do not expect one.
- **The control plane.** The `project/<proj>/…` control-plane keys, `projectmeta/`, the owner index,
  and `ProjectRekeyV1` are unchanged (they were already project-scoped). `validate_resource_name`
  still accepts `default` as a resource-name string (DEFAULT_DB_NAME + role-target/project-scope
  routing rely on it); the reservation lives only at **project-create**.
- **Ephemeral state** (in-memory permit/meter/log-scope keys) recomputes after the upgrade — no
  migration.

## The serve guard (hard data-safety gate)

The control-plane schema version is bumped. A node whose store is below the new version **refuses to
serve** until it is migrated (`boatramp migrate`), exactly like the 0.2.0 project re-key. A silent
auto-flip would make a running node's default-scoped data appear to vanish; the guard prevents that.

## Migration, substrate by substrate

Run these as a discrete step **before** rolling the new binary into serving. Do the KV stage first,
soak while the blob drain runs, then finalize + retire together.

### 1. KV (`hkv/` + all `mq*/`) — `boatramp migrate` (automated)

The KV re-home is a registered online migration (`default-scope-rehome`, schema version 2). It moves
`hkv/{base}/…` → `hkv/default/{base}/…` and every messaging KV family
(`mq/`, `mqdead/`, `mqpause/`, `mqpolicy/`, `mqready/`, `mqglog/`, `mqgstate/`, `mqlogmax/`, `mqgd/`)
the same way — **only** for keys whose scope segment is a bare default scope (not a known project).

```
boatramp migrate --stage       # copy + read-back verify; keeps the old keys (the soak window)
#   ... soak; run the blob drain (step 2) ...
boatramp migrate --finalize    # delete the old keys, now that the new spelling is verified
```

`--stage` is **strongly preferred** over the one-shot (`boatramp migrate` with no flag): the staged
`dual` soak is what enables the translating blob read-fallback (step 2) and leaves a rollback window.

**Messaging continuity.** `mqgstate/{topic}/{group}` holds durable consumer-group **offsets**; they
are copied in the **same forward pass** as their `mqglog`/`mqgd` and before the new binary serves (the
version guard enforces this). The runtime only ever addresses the **new** spelling, so no topic is
claimable under two spellings at once (no double-delivery), and the old spelling is deleted only at
`--finalize` (no lost offsets). The message **payloads** live in blob (step 2).

Idempotent + safe to re-run: a key already under `…/default/…`, or under a named project, is a no-op.

### 2. Blob (`hblob/`, `mqp/`, `mqgp/`) — read-fallback (automatic during the soak) + drain/retire

While the KV migration is in its `dual` soak, the node automatically wraps every `wasi:blobstore`
backend in a **translating read-fallback**: a miss at the new `hblob/default/{site}/…` key retries the
old bare `hblob/{site}/…` key, serves it, and background-copies it forward. So serving has **no gap**
even before the drain finishes. (It is active only during the soak; it blocks GC — drain-then-finalize.)

Proactively re-home the rest with the `blob_rehome` engine (`boatramp_storage::blob_rehome`):

- **drain** — copy every bare default-scoped object (`hblob/{site}/…`, `mqp/…`, `mqgp/…`) to its
  `…/default/…` key, `head`-verify, idempotent-skip, **never deleting the source**.
- **retire** — delete each old key **only after** its new key verifies present at matching size
  (copy-before-delete). Run this at the end of the soak, together with `boatramp migrate --finalize`.

Then remove the transition (the fallback deactivates once the store leaves the `dual` soak) and
restart.

### 3. libsql SQL — local copy-verify (operator step); remote sqld (MANDATORY operator step)

A per-site libsql database's on-disk identity is `qualified(site)`, so the default project's files
move from `{dir}/{site}.db` → `{dir}/default/{site}.db` (named DBs:
`{dir}/{site}/{name}.db` → `{dir}/default/{site}/{name}.db`).

- **Local (single-node).** `LibsqlSqlBackends::rehome_default_site_db(site, name)` performs the
  data-preserving sequence (`VACUUM INTO` the new path → `PRAGMA integrity_check` → remove the source
  + its `-wal`/`-shm` sidecars → drop the cached identity). Idempotent; refuses to clobber a non-empty
  destination. Run it per default-project `(site, database)` before serving the new binary.
- **Remote sqld / cluster (MANDATORY, not auto-migrated).** A namespace relocation needs an atomic
  server-side fork API sqld does not expose, so the engine **refuses** it fail-closed (an app-level
  copy could lose writes racing the copy). Migrate each default-project namespace by hand: create the
  new namespace `bramp-{dns_token("default/<site>")}`, copy the data (e.g. sqld dump/restore or a
  `.dump` replay), verify, then cut over. Do this **before** the new binary serves.

## Rollback

While the KV migration is staged (pre-`--finalize`) and the blob old keys are not yet retired, the
old spelling still exists — revert the binary and the node serves the old scope again. After
`--finalize` + retire, rollback is a restore from backup.
