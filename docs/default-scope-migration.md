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

## Serve on a below-version store (v0.34.0: never bricks)

**As of v0.34.0 `serve` never refuses, and never re-homes as a boot side effect.** A node whose store
is below the new version **serves its EXISTING layout** via backward-read-compat decorators (KV
`hkv/`+`mq*/`, a translating blob backend, and a libsql open-path resolver) — so rolling the new binary
onto an un-migrated store is a true no-op (no crash-loop, no 503 window, nothing appears to vanish). It
logs the explicit `boatramp migrate` step. The re-home is a deliberate, operator-run step you perform
when ready; it is reversible until you finalize (`boatramp migrate --abort`).

`serve --auto-migrate` is still accepted and still stages the re-home at boot (before the runtime is
built — the zero-stale-decorator path), but it is now **failure-safe**: any staging error (a name
collision, a mid-flight interruption, a transient error) is logged and the node falls through to
serving the existing layout. It can no longer exit the process. (This replaced the pre-v0.34.0 guard
that refused to serve and, under `--auto-migrate`, crash-looped on a collision.)

### Interactive migration (v0.34.0)

`boatramp migrate --interactive` (CLI) and the console **Store migration** wizard (Maintenance page,
`System·Admin`) walk you through the plan, prompt at each decision point (a name collision →
rename / skip / abort), and stage the re-home honoring your answers. The console *arms* the answers and
the node stages them at the next restart (via `serve --auto-migrate`, before it serves); the CLI stages
directly. Both drive the same engine, so the surfaces can't diverge.

## Migration, substrate by substrate

Run these as a discrete step **before** rolling the new binary into serving. Do the KV stage first,
soak while the blob drain runs, then finalize + retire together.

### Canonical command sequence (single-node)

Run **every step with the node stopped** (a maintenance window). The offline commands
(`boatramp migrate`, `boatramp blob rehome`, `boatramp sql rehome-default`) open the control-plane KV
/ libsql files directly, so they must NOT run against a live daemon (the KV is single-writer; the
libsql re-home moves files). The serve guard + `boatramp migrate --finalize` refuse until all three
substrates are re-homed, so the order is enforced, not just advised.

```
# 0. Stop the old binary. QUIESCE project-create for the whole pass (see the note below).
# 1. KV forward — stages into the dual soak (the DEFAULT now; one-shot is not offered):
boatramp migrate                              # `--dry-run` to preview; `--stage` is the explicit synonym
# 2. libsql re-home, per default-project site (node stopped ⇒ no source lock, races no writer):
boatramp sql rehome-default --site <site> [--db <name>] [--node-config boatramp.cfg]
# 3. Blob drain — copy old→new, keep old (head-verified, never deletes the source):
boatramp blob rehome                          # [--node-config boatramp.cfg]
# 4. Blob retire — delete each old key only after its new key verifies; sets the finalize marker:
boatramp blob rehome --finalize
# 5. KV finalize — reclaim the old KV keys (REFUSES until blob is retired + libsql re-homed):
boatramp migrate --finalize --node-config boatramp.cfg
# 6. Start the NEW binary. Everything is at the new spelling; the serve guard passes.
```

**Minimal-downtime variant (`serve --auto-migrate`).** `--auto-migrate` stages the KV and serves
immediately, with the translating blob read-fallback bridging cold default blobs — so there is no
serving gap while you have not yet drained blobs. BUT: (a) the serve guard REFUSES if the default
project's libsql is un-re-homed (libsql has no fallback), so run `boatramp sql rehome-default` with the
node stopped **first**; and (b) completing the re-home (steps 3–5 above) still requires stopping the
node (the offline commands take the KV single-writer lock), after which you restart. So `--auto-migrate`
buys a serving node during the blob soak, not a lock-free finalize.

**Quiesce project-create during the forward pass.** The KV re-home decides "bare default scope vs
named project" from the `projectmeta/` set read at the start of the forward; creating a new project
mid-pass whose name collides with a default-project resource name could leave that resource's data
un-re-homed. Freeze `POST /api/projects` for the window (it is a brief, stopped-node operation).

### 1. KV (`hkv/` + all `mq*/`) — `boatramp migrate`

A registered online migration (`default-scope-rehome`, schema version 2): `hkv/{base}/…` →
`hkv/default/{base}/…` and every messaging KV family (`mq/`, `mqdead/`, `mqpause/`, `mqpolicy/`,
`mqready/`, `mqglog/`, `mqgstate/`, `mqlogmax/`, `mqgd/`) the same way — **only** for keys whose scope
segment is a bare default scope (not a known project). v0.31.0: `boatramp migrate` (no flag) now
**stages** into the `dual` soak (never one-shot), because the soak is what enables the translating blob
read-fallback; `serve --auto-migrate` stages too. `boatramp migrate --finalize` reclaims the old KV
keys **only after** verifying the blob substrate is retired (a marker `boatramp blob rehome --finalize`
sets) and the default-project libsql is re-homed (an on-disk scan via `--node-config`) — because
clearing the soak disengages the blob read-fallback.

A **fail-closed pre-migration guard** refuses the forward pass if a default-project site/compute is
named `default` (its bare scope collides with the re-home prefix) or like an existing tenant project
(the pre-existing commingling — the two share a bare keyspace with no provenance to split them). This
is an OFFLINE `boatramp migrate` refusal, **not** a serve error — the node keeps serving the existing
layout meanwhile (and `serve --auto-migrate` falls back to serving rather than failing). **Resolve it
manually** with the existing operator tools: re-create the colliding default-project resource under a
new, non-colliding name via the normal deploy flow (e.g. `boatramp deploy --site <new> …`), delete the
old one, then re-run `boatramp migrate`. The `--interactive` flow and the console wizard surface each
collision as a rename / skip / abort decision and re-check it. (The old `--allow-default-named-resource`
flag, which proceeded while silently stranding the resource's data, has been **removed**.)

**Messaging continuity.** `mqgstate/{topic}/{group}` offsets are copied in the **same forward pass** as
their `mqglog`/`mqgd` and before the new binary serves (the version guard enforces this). The runtime
only ever addresses the **new** spelling (no double-delivery), and the old spelling is deleted only at
`--finalize` (no lost offsets). Idempotent + safe to re-run.

### 2. Blob (`hblob/`, `mqp/`, `mqgp/`) — read-fallback (automatic during the soak) + `boatramp blob rehome`

While the KV migration is in its `dual` soak, the node automatically wraps every `wasi:blobstore`
backend in a **translating read-fallback**: a miss at the new `hblob/default/{site}/…` key retries the
old bare `hblob/{site}/…` key, serves it, and background-copies it forward — so serving has **no gap**
even before the drain finishes (active only during the soak; it blocks GC — drain-then-finalize).

Proactively re-home the rest with `boatramp blob rehome` (offline, node-local — builds the node's own
backend from `--node-config` and reads the `projectmeta/` set from the control-plane KV):

- `boatramp blob rehome` — **drain**: copy every bare default-scoped object (`hblob/{site}/…`,
  `mqp/…`, `mqgp/…`) to its `…/default/…` key, `head`-verify, idempotent-skip, **never deleting the
  source**.
- `boatramp blob rehome --finalize` — **retire**: delete each old key **only after** its new key
  verifies present at matching size (copy-before-delete), then verify none remain and set the marker
  `boatramp migrate --finalize` requires. Run after a verified soak, before the KV finalize. (A node
  with no default blob data still runs this once — a 0-object pass — to set the marker.)

### 3. libsql SQL — `boatramp sql rehome-default` (local); remote sqld (MANDATORY operator step)

A per-site libsql database's on-disk identity is `qualified(site)`, so the default project's files move
from `{dir}/{site}.db` → `{dir}/default/{site}.db` (named DBs:
`{dir}/{site}/{name}.db` → `{dir}/default/{site}/{name}.db`). **libsql has NO runtime fallback** — an
un-re-homed default DB would be opened post-flip at the non-existent `{dir}/default/{site}.db` and
auto-created EMPTY — so the serve guard **REFUSES to serve** while a bare `{dir}/*.db` default database
exists. Re-home it **pre-serve** (the node is stopped, so the copy takes **no source lock** and races
no writer):

- **Local (single-node):** `boatramp sql rehome-default --site <site> [--db <name>]` — the
  data-preserving sequence (`VACUUM INTO` → `PRAGMA integrity_check` → remove the source + `-wal`/`-shm`
  → drop the cached identity). Idempotent; refuses to clobber a non-empty destination. Run per
  default-project `(site, database)` before starting the new binary.
- **Remote sqld / cluster (MANDATORY, not auto-migrated):** `boatramp sql rehome-default` **refuses**
  fail-closed for a remote binding (an app-level namespace copy could lose writes racing the copy).
  Migrate each default-project namespace by hand: create `bramp-{dns_token("default/<site>")}`, copy
  (sqld dump/restore or a `.dump` replay), verify, cut over — **before** the new binary serves.

## Rollback

**Before any re-home has run** (v0.34.0): rolling the binary back and forth is a no-op either way —
the new binary serves the un-migrated store via backward-read-compat, and the old binary serves it
natively.

**While the KV migration is staged (pre-`--finalize`)**: the old spelling still exists, so reverting
the binary serves the old scope again. Better, `boatramp migrate --abort` rolls the stage back to the
exact pre-forward bytes (fail-closed — it refuses, deleting nothing, if any staged key received a
write during the soak). **libsql is the exception:** `boatramp sql rehome-default` MOVES the file (no
soak), so reverting after it run requires restoring `{dir}/{site}.db` from backup (or moving
`{dir}/default/{site}.db` back); `--abort` covers KV + blob, not libsql.

**After the KV `--finalize` + the blob retire**: the old keys are gone, so rollback is a restore from
backup.
