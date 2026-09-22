# Run owner-gated schema migrations

Your handlers own their **rows**; you also need to evolve the **schema** they run
against — add a table, an index, an RLS policy, a column — and sometimes run a real
**data** migration (backfill a column, sync an external source, verify an invariant).
boatramp gives you an owner-gated, control-plane migration surface for its managed
databases whose base primitive is a **wasm function**: **you supply the ordered steps,
boatramp owns the sequencing, tracking, idempotency, and transactionality**, and you
trigger it with an admin token. There is no migration framework to embed and no
long-lived DDL credential to hand out — a step runs once, in order, and is recorded so a
re-run is a no-op.

> **Postgres only (this release).** The owner-role / RLS model and transactional DDL are
> Postgres semantics. A migration against a MySQL managed database is refused with a clear
> error. Shipped in v0.4.25.

## The step model

A migration is an **ordered set of steps**. Each step has a stable, author-given `id` and
is **exactly one** of three kinds:

- a **`function`** step — the base: a project function that boatramp invokes to do
  arbitrary migration work, including DDL via a host-mediated owner-role capability;
- a **`sql`** step — sugar: a DDL/DML script run as the project owner role;
- an **`extension`** step — sugar: an allowlisted Postgres extension enabled by name.

`sql` and `extension` are the easy cases of the same ordered, ledgered sequence — a `sql`
step is just "run this DDL as the owner", with no function to author. Reach for a
`function` step when a migration needs logic: a conditional backfill, a verification query,
an external-source sync, or DDL interleaved with DML.

boatramp owns everything else. It applies only the **pending suffix** (steps whose `id`
isn't already recorded), in the order you gave, exactly once, and it refuses a set that
reordered or changed an already-applied step (see [How it stays safe](#how-it-stays-safe)).

## A function migration step

A function step is an ordinary boatramp project function — a `wasi:http` handler — that
**imports `boatramp:handlers/migrate-ddl`**. Inside a migration run the host attaches that
capability, backed by an orchestrator-owned **owner-role** connection; the function calls
`migrate::exec` / `migrate::exec-batch` (DDL/DML) and `migrate::query` (verification) and
the host executes each statement as the owner. The function can also do everything a normal
function can — sync an external source over `wasi:http`, compute, log — so a data migration
and its schema change live in one author-controlled step.

A minimal Rust guest (from `examples/handlers/migrate-fn`):

```rust
wit_bindgen::generate!({ world: "handler", path: "wit", generate_all });

use boatramp::handlers::migrate_ddl;
use boatramp::handlers::migrate_ddl_types::MigrateError;
use exports::wasi::http::incoming_handler::Guest;
// … wasi:http request/response glue elided …

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        // Create the schema (auto-committed as the owner role).
        if let Err(e) = migrate_ddl::exec(
            "CREATE TABLE IF NOT EXISTS orders (\
               id bigserial PRIMARY KEY, tenant_id text NOT NULL, total numeric NOT NULL)",
        ) {
            return respond(outparam, 500, format!("ddl failed: {}", reason(&e)).as_bytes());
        }

        // Back-fill / verify: the owner sees ALL rows (correct for a data migration).
        match migrate_ddl::query("SELECT count(*) FROM orders WHERE tenant_id IS NULL") {
            Ok(json) => respond(outparam, 200, json.as_bytes()), // a 2xx return records the step
            Err(e) => respond(outparam, 500, format!("verify failed: {}", reason(&e)).as_bytes()),
        }
    }
}

fn reason(e: &MigrateError) -> String {
    match e {
        MigrateError::NotAMigration => "not-a-migration".into(),
        MigrateError::LedgerProtected => "ledger-protected".into(),
        MigrateError::TxnControl => "txn-control".into(),
        MigrateError::Sql(m) => format!("sql:{m}"),
    }
}
```

> The [`compat::migrate`](https://docs.rs/) module in the `boatramp-uchron-shim` (its
> off-by-default `migrate` feature) wraps this so a migration function calls
> `migrate::exec(ddl)` / `migrate::query(sql)` ergonomically.

Four properties of a function step are load-bearing — know them before you write one:

- **The capability is inert outside a migration run.** `migrate-ddl` is attached **only**
  when the `Project·Admin` orchestrator invokes the function *as a migration step*
  (a host-stamped context). Invoked as a normal request, consumer, or cron job, the same
  component has no binding and every verb returns a distinct, self-explaining
  **`not-a-migration`** error (not a bare `access-denied`) — so the author can tell "this
  is running where owner-DDL isn't available" from "my DDL was wrong". The function does
  not self-flag as a migration; the bundle references it, and the orchestrator sets the
  context.
- **The binding-split.** During a migration run the function does **not** get its normal
  tenant-scoped `sql` binding. All of its database work goes through `migrate-ddl` at
  **owner altitude**, so it reads and writes **all rows** regardless of tenant — which is
  exactly right for a schema or data migration, and is why a migration function is not RLS-
  subject. (It cannot hold both a tenant `sql` connection and the owner connection in one
  run, so it can never disable RLS as owner and then read cross-tenant through a tenant
  binding.)
- **No ledger, no transaction control.** `migrate-ddl` refuses any statement that
  references the host-owned `boatramp_migrations` schema (**`ledger-protected`**) or issues
  its own `BEGIN`/`COMMIT`/`ROLLBACK` (**`txn-control`**) — each `exec` auto-commits on the
  host-held owner connection. Your step can neither corrupt the ledger it is tracked in nor
  desync the wrapper.
- **At-least-once + author-idempotent.** A function step's ledger row is written **only
  after** the function returns success (a 2xx). A crash or a non-2xx return mid-step records
  **nothing**, so the *whole step re-runs* on the next apply. Write the migration logic so a
  re-run is safe (`CREATE TABLE IF NOT EXISTS`, an idempotent back-fill). A function that
  returns non-2xx surfaces as a `failed { id, error }` in the report — its own status + body
  for an author-returned error, or `function invocation failed` for a trap.

### Pin the function version

By default a function step resolves the function's **active** version at apply time. Pin an
explicit `version` in the step so a replay runs identical bytes:

```json
{ "id": "0004_backfill", "function": { "name": "backfill-orders", "version": "v3" } }
```

The recorded content-hash for a `function` step binds the **resolved component blob**, not
just the version tag — so if you redeploy `backfill-orders` under the same `v3` tag after it
was applied, the next apply catches the change as a content-hash mismatch (`409`). Pin the
version you tested, and treat an applied migration's bytes as immutable.

## The bundle: upload, then trigger

Input is **upload-then-trigger**. You serialize the ordered step set as a JSON **bundle**,
upload it content-addressed via the existing blob endpoint, then reference it by hash when
you apply. A hand-authored bundle and a CLI-generated one serialize identically (stable JSON
field set), so they **hash-agree**.

The bundle body is a JSON object with a `steps` array. Each step is an `id` plus exactly one
of `function` / `sql` / `extension`:

```json
{
  "steps": [
    { "id": "0001_init",
      "sql": "CREATE TABLE orders (id bigserial PRIMARY KEY, tenant_id text NOT NULL, total numeric NOT NULL);" },

    { "id": "0002_pgcrypto", "extension": "pgcrypto" },

    { "id": "0003_orders_tenant_idx",
      "sql": "CREATE INDEX CONCURRENTLY orders_tenant_idx ON orders (tenant_id);",
      "no_transaction": true },

    { "id": "0004_backfill",
      "function": { "name": "backfill-orders", "version": "v3", "args": "{\"batch\":500}" } }
  ]
}
```

- A **`sql`** step carries the script; add `"no_transaction": true` for DDL Postgres forbids
  in a transaction (see below).
- An **`extension`** step names the extension (allowlisted; see below).
- A **`function`** step names the project function, an optional pinned `version` (defaults to
  the active version), and an opaque `args` string handed to the function as its invoke
  request body — boatramp does not interpret `args`; the function parses it.

The `boatramp` CLI does the upload-then-trigger in one step. You give it the step set one of two
ways — a **migrations directory** it assembles (the everyday path), or a pre-authored bundle file.

**From a migrations directory (`--dir`).** Keep one file per step in a directory; the CLI reads
them, assembles the canonical bundle, uploads, and triggers:

```sh
migrations/
  0001_init.sql              # → sql step (file body is the script)
  0002_pgcrypto.ext          # → extension step (file body is the extension name)
  0003_orders_idx.notx.sql   # → sql step with no_transaction (CREATE INDEX CONCURRENTLY)
  0004_backfill.fn.json      # → function step: {"name":"backfill-orders","version":"v3","args":"…"}

boatramp project migrate apply --project acme --db appdb -d migrations/
```

The step `id` is the file name minus its kind suffix, and steps apply in **lexicographic filename
order** (zero-pad your prefixes). The suffix picks the kind — `.sql`, `.notx.sql`, `.ext`,
`.fn.json` — so nothing is silently miscategorized; a file with any other suffix is a hard error
(a mistyped migration must not vanish), and two files resolving to the same `id` are refused. An
`extension` must be an `.ext` file because a raw `sql` step may not `CREATE EXTENSION` (below).

**From a pre-authored bundle (`--file`).** If you generate the canonical `{ "steps": [ … ] }`
document yourself, upload it directly instead:

```sh
boatramp project migrate apply --project acme --db appdb -f migrations.json
```

Either way the CLI `PUT`s the bundle to the blob endpoint, `POST`s the trigger, and renders the
`MigrationReport` (a step that ran-but-failed exits non-zero, so a deploy script halts on it);
`--json` emits the raw report. The verb lives under `project` (not the top-level `boatramp
migrate`, which is the unrelated pre-0.2.0 store re-key) because a schema migration is a
project-scoped admin operation. A directory-assembled bundle and a hand-authored one with the same
steps serialize to the same canonical form, so they **hash-agree**.

Equivalently, the raw HTTP contract the CLI drives — upload the bundle (its hash is the
sha256-hex; the endpoint verifies it), then trigger:

```sh
# 1. upload the content-addressed bundle
HASH=$(sha256sum migrations.json | cut -d' ' -f1)
curl -sS -X PUT "https://cp.example.com/api/blobs/$HASH" \
  -H "Authorization: Bearer $BOATRAMP_TOKEN" \
  --data-binary @migrations.json

# 2. apply it against managed database `appdb` in project `acme`
curl -sS -X POST https://cp.example.com/api/projects/acme/migrate/appdb/apply \
  -H "Authorization: Bearer $BOATRAMP_TOKEN" \
  -H 'content-type: application/json' \
  -d "{ \"bundle\": \"$HASH\" }"
```

Paths target the named project; the top-level `/api/migrate/…` counterpart targets the
`default` project (with the CLI, omit `--project`). The migrate client is a **thin uploader** —
it assembles the bundle from whatever on-disk layout you keep, PUTs the blob, and POSTs the
trigger. boatramp stays agnostic to your directory shape; the HTTP surface above is the contract.

## apply / dry-run / baseline / status

Four verbs on a managed database `:db`, all referencing an uploaded bundle by hash (except
`status`, which reads the ledger):

**Apply** the pending suffix (`{ "bundle": "<hash>" }`). The response is a structured
`MigrationReport`:

```json
{ "newly_applied":   ["0002_pgcrypto", "0003_orders_tenant_idx", "0004_backfill"],
  "already_applied": ["0001_init"],
  "pending":         [],
  "failed":          null,
  "kinds":           { "0001_init": "sql", "0002_pgcrypto": "extension",
                       "0003_orders_tenant_idx": "sql", "0004_backfill": "function" } }
```

- `already_applied` — recorded on an earlier call, skipped (idempotent no-op).
- `newly_applied` — applied by **this** call, in order.
- `pending` — populated only by a **dry-run** (the ids that *would* apply); empty on a real
  apply.
- `failed` — the step that ran but failed (`{ id, error }`); `null` on success.
- `kinds` — every reported id mapped to its kind (`sql` / `extension` / `function`), so a
  thin client can tell what each id was without re-parsing the bundle.

**Dry-run** computes the plan without running or recording anything — same body,
`pending` lists the ids that would apply:

```sh
boatramp project migrate dry-run --project acme --db appdb -d migrations/
# raw HTTP:
curl -sS -X POST .../migrate/appdb/dry-run -H "Authorization: Bearer $BOATRAMP_TOKEN" \
  -H 'content-type: application/json' -d "{ \"bundle\": \"$HASH\" }"
```

**Status** reads the applied ledger (id, ordinal, content hash, kind, applied-at, and the
`origin` marker — `apply` vs `baseline`):

```sh
boatramp project migrate status --project acme --db appdb   # add --json for the raw ledger
# raw HTTP:
curl -sS .../migrate/appdb/status -H "Authorization: Bearer $BOATRAMP_TOKEN"
```

**Baseline** is covered in [its own section](#adopt-an-existing-database-baseline) below.

### Tokens: admin to mutate, read to inspect

`apply`, `dry-run`, and `baseline` require a **`Project·Admin`** token; `status` needs only
**`Project·Read`**. This is deliberately stronger than the deploy-grade *publisher* right
that ships code — DDL redraws the schema, so **a ship-only CI token cannot migrate the
schema**. Mint a scoped admin token per project rather than reusing the fleet root
(see [Make a scoped deploy token](./ci-token.md)). Uploading the bundle blob is a
deploy-grade action (`Blobs·Deploy`), the same as any other blob upload.

### HTTP status codes: `200`/`422` vs the error codes

boatramp splits "couldn't attempt the request" from "a step ran but failed":

- A clean apply is **`200`**; a step that **ran but failed** (a `sql` error, or a function
  returning non-2xx) is **`422`** with the same `MigrationReport` body, where `failed` names
  exactly which migration broke and why:

  ```json
  { "newly_applied": ["0001_init"], "already_applied": [], "pending": [],
    "failed": { "id": "0002_bad", "error": "relation \"orders\" does not exist" },
    "kinds":  { "0001_init": "sql", "0002_bad": "sql" } }
  ```

  Either way the body is the same shape, so a thin client parses `failed{id,error}` and
  branches on the status.

- Everything else is a non-2xx *without* a report body: **`409`** (the set diverged from the
  ledger, or an applied step's body/blob changed), **`503` + `Retry-After`** (the managed
  database is still starting — retryable), **`501`** (no managed database on this node),
  **`400`** (a malformed step — none or more than one of `function`/`sql`/`extension`, an
  unparsable bundle, a raw `CREATE EXTENSION` in a `sql` step, or an extension not on the
  allowlist).

## How it stays safe

The migration surface runs owner-authority DDL — from a `sql` step or a function's
`migrate-ddl` calls — without ever handing out cluster-superuser reach.

**DDL runs as a dedicated per-project non-superuser owner role.** Every managed tenant is
provisioned with a **three-identity** model:

- the **cluster superuser** — only ever provisions the shells (creates the database and the
  roles); a migration never connects as it;
- a per-project **owner role**, created explicitly
  `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` — this is who both your `sql` steps and a
  function step's `migrate-ddl` calls run as;
- the **runtime login role** your handlers connect as, kept a **non-owner** so row-level
  security is still enforced against it.

Because the owner role is a plain non-superuser that owns only this tenant's own database,
**Postgres itself denies** the dangerous moves — `DROP DATABASE other`,
`ALTER ROLE … SUPERUSER`, `COPY … TO PROGRAM`, an untrusted `CREATE EXTENSION` — by
privilege, not by a check boatramp has to remember. A function step's DDL is therefore **no
more powerful than a `sql` sugar-step** (both are arbitrary DDL as the confined owner); a
function adds *interleaving with its own logic*, not a new escalation.

> On a Shared multi-tenant server, a real project runs its migrations as that project's own
> per-project non-superuser owner role, so the engine denies cross-tenant / cross-database
> reach by privilege. On a single-tenant install, the reserved `default` project's migrations
> run as **that install's configured identity** (your own user) — there is no other tenant to
> be isolated from.

**The ledger is host-owned.** Applied migrations are tracked in
`boatramp_migrations.schema_migrations` — a schema **outside `public`** that the owner role
owns and the runtime app role has no grant on (the app only ever gets DML on `public`). A
function step is additionally forbidden from touching that schema through `migrate-ddl`
(`ledger-protected`). Your handlers cannot read, forge, or clear their own migration history.

**Ordering is fixed and immutable.** On every apply boatramp checks the recorded ledger is an
ordered **prefix** of the steps you sent, matching `id` **and** a content hash — for a
`sql`/`extension` step the intrinsic hash of its body, and for a `function` step the hash
bound to the **resolved component blob**:

- a **reordered or dropped** step ⇒ `409` (prefix divergence), and
- **editing an already-applied step's body**, or **redeploying a pinned function under the
  same version tag**, ⇒ `409` (content-hash mismatch).

So you cannot silently re-apply, reorder, or rewrite history — the only legal change to a
migration set is **appending** new steps.

## Enable an extension

A raw `sql` step **may not** `CREATE EXTENSION` (a `400`, or refused fail-closed by the
non-superuser owner regardless) — and neither can a function's `migrate::exec`. The sole path
is a dedicated `extension` step:

```json
{ "id": "0002_pgcrypto", "extension": "pgcrypto" }
```

boatramp runs a host-templated `CREATE EXTENSION IF NOT EXISTS "<name>"` — no guest SQL, no
injection surface — but only if `<name>` is on the operator's **trusted-extension allowlist**,
set in the node config:

```toml
[handlers.bindings.sql]
migrate_trusted_extensions = ["pgcrypto", "uuid-ossp", "citext"]
```

An empty/unset list means **no extension** can be enabled through a migration (the safest
default); a name not on the list is refused with a `400`. This allowlist is the *single,
operator-controlled gate* on which extensions a project may install — deliberately the
operator's decision, not the app author's, because some extensions (`dblink`,
`postgres_fdw`, …) widen cross-database reach. Keep it tight and add those only knowingly.

## Non-transactional `sql` steps

boatramp wraps each `sql` step and its ledger row in one owner transaction so DDL and its
record commit (or roll back) together. Some Postgres DDL cannot run inside a transaction —
`CREATE INDEX CONCURRENTLY`, `ALTER TYPE … ADD VALUE`, `VACUUM`. Mark those
`no_transaction: true`:

```json
{ "id": "0003_orders_tenant_idx",
  "sql": "CREATE INDEX CONCURRENTLY orders_tenant_idx ON orders (tenant_id);",
  "no_transaction": true }
```

The trade-off is explicit: boatramp runs the script, then records the ledger row in a
**following** statement, so there's a window where the DDL applied but the row didn't (a crash
between them). The author **owns that step's idempotency** — write it so a re-run is safe
(`CREATE INDEX CONCURRENTLY IF NOT EXISTS`), because a re-submit will run it again.
Transactional `sql` steps have no such window; reach for `no_transaction` only for DDL
Postgres forbids in a transaction. (A `function` step is *always* at-least-once — see
[A function migration step](#a-function-migration-step) — so the same idempotency discipline
applies to any function.)

## Adopt an existing database: `baseline`

A database provisioned by a **pre-v0.4.25** boatramp already carries its full schema, applied
via the old path, but the host-owned ledger starts **empty** — so a first `apply` of your full
step set would treat *every* step as pending and try to re-run `CREATE TABLE …` against a
populated database (a `422`). `baseline` closes that gap: it **records a prefix of the step set
as already-applied WITHOUT running any step**.

```sh
boatramp project migrate baseline --project acme --db appdb \
  -d migrations/ --up-to 0097_last_old_path_migration
# raw HTTP:
curl -sS -X POST .../migrate/appdb/baseline -H "Authorization: Bearer $BOATRAMP_TOKEN" \
  -H 'content-type: application/json' \
  -d "{ \"bundle\": \"$HASH\", \"up_to\": \"0097_last_old_path_migration\" }"
```

- It writes ledger rows for the steps **up to and including `up_to`** (or the whole set if
  `up_to` is unset), computing the **same content-hash `apply` would** — but **runs neither a
  `sql`/`extension` step nor a function invocation**. Recorded rows carry an
  **`origin = baseline`** marker, so `status` distinguishes a baselined prefix (never run on
  this DB) from a genuinely applied one.
- A later `apply` of the same set sees the baselined prefix as `already_applied` (matching ids
  + hashes) and runs only the genuinely-pending **suffix**.
- `Project·Admin`, audited, and prefix-consistent: valid only on an **empty ledger** or as a
  strict, consistent extension of what's recorded — a divergence (a boundary behind the
  recorded rows, or an `up_to` not in the set) is refused `409`, exactly like `apply`.

So you baseline preview/prod at "everything applied through the last old-path migration", then
a normal `apply` lands only the held suffix — no data migration, no re-creating an existing
object.

## Operators: migrating existing tenants to the owner model

New tenants provision with the three-identity model **automatically** — nothing to do. A
tenant provisioned by a **pre-v0.4.25** boatramp, though, has its database owned by the runtime
role and its tables owned by the cluster superuser; there is no owner role yet, so a migration
has nowhere to connect as owner. Move such a tenant once, as a one-shot step.

Find the boatramp-derived owner role name — it's the `_owner`-suffixed per-tenant role, in
`pg_roles` (it will exist after you re-run provisioning; the name is derived from the managed
binding + tenant). Then, **as the superuser, against that tenant's database**:

```sql
ALTER DATABASE "<db>" OWNER TO "<owner_role>";
REASSIGN OWNED BY <superuser> TO "<owner_role>";
```

Then re-run provisioning (it is idempotent) so the owner-keyed default privileges and the
sealed owner credential are in place. After that, the migration surface can connect as the
owner role and the tenant is on the modern model. This is the operator's one-shot step; tenants
created afterward need none of it. (This fixes *who* runs DDL; to adopt the migrator on a DB
that already has its schema, `baseline` the recorded prefix as above.)

## A note on trust

A migration `function` is a **trusted, `Project·Admin`-authored data-plane actor**, by design:

- It reads and writes **all rows** as the owner role (RLS does not apply to it) — correct for a
  schema/data migration, but it means a migration function is not confined the way a normal
  tenant-scoped handler is. Only deploy functions you'd trust with your whole schema as
  migration steps.
- It retains `wasi:http` egress and its other granted capabilities; a migration invocation
  inherits the **same egress / SSRF posture** as any function on the node. An external-source
  sync from a migration is subject to the same egress controls (and no more) as an ordinary
  handler.

Neither is a hole in the owner-role confinement — Postgres still denies the owner cross-database
/ role-escalation moves — but they are the honest cost of "a migration is a function": you are
running author-supplied code at owner altitude, under an admin token, on demand.

## The general pattern

This surface is an instance of a general boatramp shape: an **owner-authenticated control-plane
operation with a thin client** — the caller assembles a declarative request (here, a
content-addressed step-set bundle) and posts it with an admin token, while boatramp owns the
privileged, sequenced, tracked execution. There is no long-lived privileged credential in the
client and no imperative script running against your database. Expect the same "admin request →
owner-only admin API" shape to generalize to future privileged operations.

## See also

- [Isolate tenants within a project](./tenant-isolation.md) — the RLS the runtime role is held
  to, which the owner/runtime split preserves (and which a migration function operates above).
- [Use kv / sql / blobstore / messaging](./handler-bindings.md) — the managed `sql` binding a
  migration targets (and which a function step does *not* hold during a migration run).
- [Bootstrap authentication & mint tokens](./auth-bootstrap.md) /
  [Make a scoped deploy token](./ci-token.md) — the admin token these endpoints need.
- [Control-plane HTTP API](../reference/api.md) — the full `/api/migrate/*` and `/api/blobs/*`
  endpoint reference.
