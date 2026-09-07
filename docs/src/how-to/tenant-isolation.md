# Isolate tenants within a project

boatramp has **two** tenant boundaries, and they stack:

1. **Project = database.** A [project](./projects.md) maps 1:1 to its own managed
   database(s). One project can never see another's rows — the project id is an
   un-escapable key prefix, so cross-project isolation is *structural*, not a check you
   can forget. A single-tenant app needs nothing on this page: the project boundary is
   the whole isolation.
2. **In-site sub-tenancy** (this page). When **one** project's database holds rows for
   many tenants — a SaaS whose customers each get a storefront, a portal serving many
   organizations — you discriminate them with a **tenant column** (`tenant_id`, `org`, …)
   and scope every query to the caller's tenant. This is opt-in, declared, and
   **host-forced**.

## The one rule that makes it safe: the guest never supplies the tenant

Under boatramp v0.4.0 the tenant **value** is resolved **host-side**, from a verified
source, and injected into every query the guest runs. A handler cannot pass, spoof, or
forget it. There is no `WHERE tenant_id = ?` for an app author to get wrong and no
guest-supplied scope to audit — a missed predicate cannot leak across tenants because the
predicate isn't the guest's to write.

> Pre-0.4 the guest called `open(db).scoped(column, value)` and supplied the value itself.
> That API is **gone**; see [Migrating from pre-0.4](#migrating-from-pre-04).

An app declares tenancy along **three independent decisions**.

## Dimension 0: opt in (or explicitly out)

A `sql`/`orm`-using function or site carries a **tenancy decision**:

- **`scoped`** — in-site sub-tenancy is on; the host scopes every query (below).
- **`disabled`** — deliberately no in-site tenancy; plain queries, the project=database
  boundary is the whole isolation. This is the explicit single-tenant declaration.
- **undeclared** (no block at all) — under the `single-tenant`/`dev` posture this is
  treated as `disabled`; under **`multi-tenant`** it is **refused at activation**. The
  [`require_tenancy_declaration`](../reference/boatramp-cfg.md#security) posture knob (on
  under `multi-tenant`) forces the decision to be a reviewed choice, never an accidental
  omission — the class of bug where a developer simply never thought about tenancy.

## Dimension 1: the tenant source

`scoped` tenancy names **how the host resolves "own"** — every source is host-verified
and bound once per invocation:

| Source | How "own" is resolved | Use for |
| --- | --- | --- |
| `token` | A verified JWT claim (default `tid`) on the app's **own** bearer token, checked against a configured JWKS/issuer. | Authenticated console/portal paths. |
| `domain` | The routed request domain's [context tag](./custom-domain.md#map-each-host-to-a-tenant-domainscontexts) (`domains.contexts`). | Storefronts / public-render paths — one deployment, many customer domains, no app-side `Host`→tenant lookup. |
| `signed_context` | A host-verifiable signed context on an async job/message. **Reserved** — not yet wired; a function requiring "own" via it fails closed. | (future) async workers. |
| `none` | There is no "own" tenant (truly anonymous / HMAC-webhook auth). Only the `null`/`all` access modes are meaningful; an "own" mode fails closed. | Funnel reads, unauthenticated webhooks. |

For the **`token`** source, configure the JWKS/issuer that verifies the app bearer with a
`token_claims` block (issuer + `jwks_env` **or** `jwks_url`, optional `audience`). boatramp
verifies signature / `iss` / `exp` (algorithm pinned to the JWKS key) and a missing or bad
token denies. This is the same verifier the [GraphQL data connector](./graphql.md) uses.

## Dimension 2: the access mode, per read/write axis

`scoped` tenancy carries a separate **access mode** for the `read` and `write` axes.
Cross-tenant is **default-deny**:

| Mode | Rows reachable on this axis |
| --- | --- |
| `none` | none (deny this axis entirely) |
| `null` | only the shared baseline (`<column> IS NULL`) |
| `own` (default) | only the resolved tenant |
| `own_or_null` | the resolved tenant **plus** the shared baseline |
| `all` | every tenant — **cross-tenant** |

- **`all` needs the operator's blessing.** It is gated by the
  [`allow_cross_tenant_db`](../reference/boatramp-cfg.md#security) posture knob — **off**
  under `multi-tenant`, where an `all` request is silently **capped to `own`**. A guest
  can ask for cross-tenant reads and still get only its own rows unless the operator opted
  in. `own`/`own_or_null`/`null` need no ceiling.
- **`own_or_null` on the write axis degrades to `own`** — a write never lands in the
  shared (`NULL`) baseline. A common shape is `read: own_or_null, write: own`: read your
  own rows plus shared defaults, write only your own.
- A mode that needs an "own" value (`own`, `own_or_null`) with an **unresolvable** source
  (e.g. no token present) **fails closed** — it never falls back to unscoped.

> **Base-vs-override reads (`own_first()`).** A common `own_or_null` shape is a two-layer table: a
> shared **base** row (`tenant_id IS NULL`) plus an optional per-tenant **override**, where a lookup
> wants *the override if present, else the base*. Since the tenant column is host-injected and
> hidden, the [`orm` builder](./handler-bindings.md#typed-queries-with-the-orm-builder) exposes
> `own_first()` (sort own rows ahead of base — `ORDER BY is_own DESC`) and `is_own()` (a `0`/`1`
> own-ness expression) so you can express this without naming `tenant_id`. Host-resolved from the
> same scope, fail-closed off an own-tenant read; needs the `orm-own-pref` capability. Raw SQL keeps
> using its own `ORDER BY` with the `{scope}` marker.

## Where you declare it

Tenancy lives at two grains, and the domain source is wired in a third place:

- **Site ceiling** — [`SiteConfig.handlers.tenancy`](../reference/siteconfig.md#handlerstenancy).
  The maximum a site's handlers may reach. PUT with the rest of site config.
- **Per top-level function** — the `tenancy` (+ `token_claims`) block on a
  [function](./apply.md) in `apply.cfg` / `function deploy`. It narrows **within** the
  site ceiling; it can never widen it.
- **Domain context tags** — [`domains.contexts`](./custom-domain.md#map-each-host-to-a-tenant-domainscontexts)
  in site config supplies the value for the `domain` source: host-or-wildcard → an opaque
  tenant tag.

The wire shape is a tagged `mode` (JSON for the admin API / SiteConfig; the RON equivalent
in `apply.cfg`):

```json
{ "mode": "scoped",
  "column": "tenant_id",
  "source": { "kind": "token", "claim": "tid" },
  "read":  "own_or_null",
  "write": "own" }
```

```json
{ "mode": "disabled" }
```

## Both query surfaces are scoped the same way

Whichever way a handler queries, the host applies the **same** tenant predicate:

- **The [`orm`](./handler-bindings.md#typed-queries-with-the-orm-builder) builder** folds
  the scope in **structurally** — into `WHERE`/`HAVING`, every joined table (qualified per
  alias), `INSERT` rows and `INSERT … SELECT` sources, `RETURNING`, `UNION` branches, and
  narrow subqueries. You write the query; the tenant clause appears in the SQL by
  construction. Nothing to add, nothing to miss.
- **Raw [`sql`](./handler-bindings.md#the-four-data-bindings)** uses a **`{scope}` marker**. Put
  `{scope}` where the tenant predicate belongs and the host replaces it with
  `<column> = ?N` (bound to the verified value) for the axis the statement implies
  (a leading `SELECT` uses the read axis; `INSERT`/`UPDATE`/`DELETE` the write axis):

  ```sql
  SELECT id, total FROM orders WHERE status = ?1 AND {scope}
  DELETE FROM orders WHERE id = ?1 AND {scope}
  ```

  Under `scoped` tenancy a statement that **omits** `{scope}` is **refused before it
  reaches the database** (fail-closed) — you cannot accidentally run an unscoped raw
  query. When tenancy is `disabled`/undeclared, a `{scope}` you leave in is harmlessly
  replaced with `1 = 1`, so the same SQL is safe either way.

## Invoke chains carry the tenant, host-side

When a function invokes a sibling (the [`invoke`](./functions.md) capability), the
**caller's resolved tenant value** rides along host-side — the sibling does **not**
re-resolve from a request it never saw, and the caller cannot inject a different value. The
sibling then applies **its own** declared modes over that inherited value (posture-capped
as usual). Background paths with no caller tenant (a cron, a queue drain) fail closed for
an `own` mode rather than run unscoped.

## Worked example — a multi-storefront SaaS

One deployment serves every customer on their own domain, all rows in one database
discriminated by `tenant_id`:

1. **Attach the domains and tag each with its tenant** in site config
   ([`domains.contexts`](./custom-domain.md#map-each-host-to-a-tenant-domainscontexts)):

   ```json
   { "domains": {
       "wildcards": ["*.shops.example.com"],
       "contexts": { "acme.shops.example.com": "acme", "globex.shops.example.com": "globex" } } }
   ```

2. **Declare `domain`-sourced tenancy** as the site ceiling (`handlers.tenancy`):

   ```json
   { "mode": "scoped", "column": "tenant_id",
     "source": { "kind": "domain" }, "read": "own", "write": "own" }
   ```

3. **Write ordinary handlers.** A request to `acme.shops.example.com` runs with the tenant
   bound to `acme`; every `orm` query and every `{scope}`-marked raw query sees only
   `tenant_id = 'acme'`. The handler code contains no tenant logic at all — add a customer
   by attaching a domain and tagging it, no redeploy.

For a **token**-authenticated console over the same data, declare a second function with
`source: { "kind": "token", "claim": "tid" }` + a `token_claims` block, and (if it needs an
admin view across tenants) `read: all` — which the operator must enable fleet-wide with
`allow_cross_tenant_db`.

## Migrating from pre-0.4

Before v0.4.0 a guest scoped its own queries:

```rust
// pre-0.4 — REMOVED
let db = sql::open("main")?.scoped("tenant_id", tenant)?;
let db = orm::open("main")?.scoped("tenant_id", tenant);
```

That guest-supplied scope is gone. Now:

1. **Drop `.scoped(col, value)`** — `open()` returns a plain handle; query entry is on it
   directly.
2. **Declare tenancy in config** (Dimensions 0–2 above) so the host injects the scope.
3. **For raw SQL**, add the [`{scope}` marker](#both-query-surfaces-are-scoped-the-same-way)
   where your old `tenant_id = ?` predicate was. The `orm` builder needs no change beyond
   dropping `.scoped(...)` — it scopes structurally.

The value the host binds is the **verified** one (token claim / domain tag), so the app no
longer computes or trusts a `tenant` variable at all. A single-tenant app that had no
`.scoped(...)` call declares `{ "mode": "disabled" }` (or runs under `single-tenant`/`dev`
where undeclared is fine).

## See also

- [Use kv / sql / blobstore / messaging](./handler-bindings.md) — the `sql` and `orm`
  bindings the scope is applied to.
- [SiteConfig schema](../reference/siteconfig.md#handlerstenancy) — the `handlers.tenancy`
  field.
- [Attach a custom domain](./custom-domain.md#map-each-host-to-a-tenant-domainscontexts) —
  `domains.contexts` for the domain source.
- [boatramp.cfg schema](../reference/boatramp-cfg.md#security) — the
  `require_tenancy_declaration` and `allow_cross_tenant_db` posture knobs.
