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
| `signed_context` | A host-verifiable signed context stamped on an async job/message. The producer host-stamps its own verified tenant at publish; a consumer declaring `sources: [(kind: "signed_context")]` resolves that tenant on the async lane (verified against the fleet anchor). A forged/expired/absent context resolves nothing, so an "own" op fails closed. Wired since v0.4.3. | Message consumers, cron, webhooks, workflow steps, fan-out workers. |
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
- **Per component** — the `tenancy` (+ `token_claims`) block on a top-level **function**, a
  route **handler**, or a bus **consumer** in `apply.cfg` (since v0.4.7). A per-handler value
  narrows **within** the site ceiling; it can never widen it (a widening — e.g. `disabled`
  removing scoping under a `scoped` ceiling — is refused fail-closed at bind). This lets one
  site host, say, a `payments.wasm` handler at `all` beside a `portal.wasm` handler at `own`.
- **Domain context tags** — [`domains.contexts`](./custom-domain.md#map-each-host-to-a-tenant-domainscontexts)
  in site config supplies the value for the `domain` source: host-or-wildcard → an opaque
  tenant tag.

The wire shape is a tagged `mode`. In the **admin API / SiteConfig** it is JSON:

```json
{ "mode": "scoped",
  "column": "tenant_id",
  "sources": [{ "kind": "token", "claim": "tid" }],
  "read":  "own_or_null",
  "write": "own" }
```

In **`apply.cfg` / `project.cfg`** (RON) it is the byte-identical, **fully-quoted** form —
the enum tags/values are quoted strings, not bare identifiers (`column` is required for
`scoped`):

```ron
tenancy: (mode: "scoped", column: "tenant_id", sources: [(kind: "token", claim: "tid")], read: "own_or_null", write: "own")
tenancy: (mode: "disabled")
```

An async worker resolves its own tenant from the producer-stamped context:

```ron
tenancy: (mode: "scoped", column: "tenant_id", sources: [(kind: "signed_context")], read: "own", write: "own")
```

## An unscoped `all` route under an `own` site (authorized exception)

Sometimes one route on an otherwise `own`-ceilinged site must legitimately reach **every** tenant —
an M2M `/token` endpoint that validates a client credential across the fleet, an internal `/svc/*`
admin, a payment webhook. A per-route tenancy normally may only *narrow* within the site ceiling, so
`read: all` on an `own` site is refused. Rather than smuggle the broad reach into a top-level `all`
function (which hides *what* is broad behind a `function:` indirection), declare the exception
**inline and greppably** — under a **three-key** model where no single actor, and no single line,
reaches `all`:

1. **The site owner** opts the site in:
   [`SiteConfig.handlers.allow_ceiling_exceptions = true`](../reference/siteconfig.md#handlersallow_ceiling_exceptions).
   Default `false`; while `false`, every route's exception token is inert. A site left at the default
   is provably exception-free without scanning its routes.
2. **The deployer** marks the specific route with `exceed_site_ceiling: true` on its `scoped` tenancy:

   ```ron
   # apply.cfg — one route deliberately broader than the site ceiling
   (route: "/token", methods: ["POST"], component: "token.wasm", imports: ["sql"],
    tenancy: (mode: "scoped", column: "tenant_id", sources: [(kind: "token", claim: "tid")],
              read: "all", write: "all", exceed_site_ceiling: true))
   ```

3. **The operator** must still permit crossing tenants at all — the
   [`allow_cross_tenant_db`](../reference/boatramp-cfg.md#security) posture. With it **off**, an
   authorized `all` route is clamped to `own` at runtime (and `apply` warns you it will be).

The exception is deliberately narrow: it can only widen the **read/write access mode** (up to `all`)
of a `scoped` route on the **same tenant column**. It can never remove scoping (`disabled`), switch to
the target axis, or change the column — those would escape the operator posture backstop, so they stay
refused. `exceed_site_ceiling: true` is a *separate* field from `read`/`write` on purpose: a bare
`read: all` without it still fails closed, so a config typo never silently widens.

A widening that lacks either deployer key is refused **at deploy** with a message naming the route and
the exact fix (not an opaque runtime error), and `boatramp apply --dry-run` flags every route that
declares an exception:

```text
  ⚠ route "/token" [POST]: exceeds the site tenancy ceiling (authorized via `exceed_site_ceiling`;
    the site must set `allow_ceiling_exceptions`, and an `all` grant also needs the operator posture
    `allow_cross_tenant_db`).
```

The `/graphql` gateway is its own route — a token on `/token` never widens the gateway (or any
sibling); each route carries its own exception.

### Migrating from an `all`-ceilinged site

If you set the whole site to `all` just to allow one broad route, tighten it: flip the site ceiling to
`own`, set `allow_ceiling_exceptions = true`, and add `exceed_site_ceiling: true` to **only** the routes
that need it. Every other route is now provably confined to its own tenant, and the broad ones are
greppable in one place.

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

## Writing a genuinely-global table from a `scoped` route

A `scoped` route reads its own rows and, by default, writes only its own rows. A table
declared `{ "kind": "unscoped" }` (global reference data like `countries`) is
**globally readable** but **write-deny-by-default** — a shared-data write is a cross-tenant
blast, so the host refuses it. The old workaround, `write: "all"`, is the **wrong fix**: it
**co-widens reads** to every tenant and breaks your isolation.

The right shape (since #503): keep `read: "own"` and open **only the write** of a
*genuinely tenant-less* table — an OAuth CSRF `oauth_state`, a cross-tenant counter, a
webhook idempotency-key table — where the row has no tenant dimension at all. **Reads are
unaffected either way.**

**The one-axis decision rule** — pick by *who writes the table*:

- **Few / sensitive writers → keep the table plain `unscoped` and list it per route**
  (`unscoped_writes`). **This is the recommended default** (least-privilege): only the
  routes you name may write it; every other route still gets the read-only-reference
  contract.
- **Genuinely-global / many writers → declare the table write-global once**
  (`{ "kind": "unscoped", "writable": true }`). Any `scoped` route may then write it
  unstamped — one declaration, no per-route bookkeeping.

**Mental model:** *`writable` / `unscoped_writes` open a table's **write** with **no tenant
stamp**, **through the typed [`orm`](./handler-bindings.md#the-four-data-bindings) binding
only** — they never touch reads, and a **target** route can never use them.*

Both mechanisms are OR'd: a write is allowed if the table is write-global **or** the route
lists it. A write is stamped/refused **freshly per write** — if you later re-declare a
listed table as a tenant table, the list entry goes inert and the write is tenant-stamped
as normal (a listed table can never be written unstamped once it stops being global).

> **Global writes go through the `orm` binding, not raw `sql`.** The unstamped global write
> is an `orm`-only capability. On the **raw `sql`** surface there is *no* write-global
> exemption: a raw-SQL write to a global table is treated like any other scoped write — it
> **requires the `{scope}` marker** (an unmarked write is refused) and the injected
> `tenant = ?` predicate scopes it to your **own** tenant. This is deliberate: a raw-SQL
> statement is opaque text, and a comment-based redirect (e.g. a MySQL `/*! … */`
> version-comment) could hide a cross-tenant write from the host's parser. The `orm`
> binding names the table as a typed value (nothing to hide) and automatically scopes an
> `INSERT … SELECT` source, so it is the safe — and only — path for an unstamped global
> write. **If you need to write a global table, use the `orm` binding.**

### Recipe 1 — OAuth `/start` (per-tenant config read + a global CSRF write)

The canonical case: read per-tenant provider config (`read: "own"`) and INSERT a genuinely
global CSRF `state` row **via the `orm` binding** (the shared callback recovers the tenant
from `state`, so the table has no tenant column). Keep `oauth_state` plain and list it on the
route (least-privilege):

```json
// project tenancy schema
{ "default_tenant_key": "tenant_id",
  "tables": {
    "oidc_provider": { "kind": "tenant" },
    "oauth_state":   { "kind": "unscoped" } } }
```
```ron
// the /start route: reads its own config, writes the one global table
tenancy: (mode: "scoped", column: "tenant_id",
          sources: [(kind: "token", claim: "tid")],
          read: "own", write: "own",
          unscoped_writes: ["oauth_state"])
```

### Recipe 2 — a global counter written by many routes

A cross-tenant metrics counter every route bumps. Many writers ⇒ declare it write-global
once, no per-route list:

```json
{ "tables": { "global_counter": { "kind": "unscoped", "writable": true } } }
```

Any `scoped` route may now update `global_counter` unstamped **through the `orm` binding**;
a route reading it still reads globally, and its *own* tables stay `own`-scoped. (A raw-SQL
`UPDATE global_counter …` is still marker-scoped to the route's own tenant — global writes
are an `orm`-binding capability.)

### Recipe 3 — a webhook consumer with a global idempotency-key table

A bus **consumer** dedupes deliveries on a shared `idempotency_key` table. Consumers carry
`tenancy` too, so list it on the consumer:

```ron
consumers: [( topic: "bus:webhooks",
              component: "webhook.wasm", imports: ["sql"],
              tenancy: (mode: "scoped", column: "tenant_id",
                        sources: [(kind: "signed_context")],
                        read: "own", write: "own",
                        unscoped_writes: ["idempotency_key"]) )]
```

### The operator-trust residual

The host **cannot verify** a table declared global is *truly* tenant-less — it takes the
operator's word. A **misdeclaration** (marking a table that really does carry per-tenant
rows as `writable: true`, or listing it in `unscoped_writes`) lets **any** granted route
write across tenants, unstamped. So treat a write-global declaration as a security
decision: only ever open the write of a table with **no tenant dimension**. `boatramp
tenancy apply` prints the write-global tables so you can review exactly which shared tables
are openable. A **target** route (another tenant's public subset) can *never* write a global
table — both opt-ins are refused on the target axis.

The exemption is scoped to the `orm` binding on purpose. The raw `sql` binding is opaque
text the host would have to *parse* to know which table a write targets, and a parser can be
fooled (a MySQL/MariaDB `/*! … */` version-comment the engine executes but a parser skips
can redirect the write to a different table). Rather than trust that parse for a
security-critical allow decision, boatramp gives the raw path no write-global exemption at
all — a raw-SQL write to a global table is marker-scoped to your own tenant or refused — and
routes all unstamped global writes through the injection-immune `orm` binding.

Apply-time validation is fail-fast: `unscoped_writes` entries are cross-checked against the
stored schema — an unknown table, or one that resolves to a **tenant** kind, is a **422**
(the list can never write a tenant table unstamped anyway); a redundant entry (the table is
already `writable: true`) is a warning.

## Invoke chains carry the tenant, host-side

When a function invokes a sibling (the [`invoke`](./functions.md) capability), the
**caller's resolved tenant value** rides along host-side — the sibling does **not**
re-resolve from a request it never saw, and the caller cannot inject a different value. The
sibling then applies **its own** declared modes over that inherited value (posture-capped
as usual). Background paths with no caller tenant (a cron, a queue drain) fail closed for
an `own` mode rather than run unscoped.

## Async lane: stamp the tenant an emitter verified in-guest (`present-token`)

A message **consumer** resolves its own tenant on the async lane from a `signed_context`
source — but only if the **producer** stamped one on the message. The host stamps the
producer's own tenant automatically when it resolved one (a request bearer, a routed
domain). When the emitter's tenant authority is verified **in-guest** instead — an app JWT
in a POST body, a portal cookie's bearer — it hands the credential to the host with the
`tenancy` capability (since v0.4.7):

```rust
// The emitter declares `imports: ["tenancy"]` + a `token` source + `token_claims`.
boatramp::handlers::tenancy::present_token(&handoff_jwt)?; // host RE-verifies, extracts the tenant
emit::message("bus:handoff.confirmed", &payload)?;         // now carries that tenant's context
```

The **host** re-verifies the presented token against the component's declared `token_claims`
(JWKS / issuer / audience / expiry) and stamps the extracted tenant — the guest never names
a tenant value; it can only cause a stamp for a tenant it holds a validly-signed token for.
Deny-by-default (no grant / no `token_claims` / an invalid token stamps nothing).

## Cross-tenant reads: target fields (another tenant's public subset)

Reading **another** tenant `B`'s *public* subset (an embed, a storefront funnel, a handoff)
is the separate **target** axis, declared on a GraphQL field with
`@tenant(scope: target, via: […], public: …)`. Since v0.4.7 the external `/graphql` gateway
serves these on **wasm** subgraphs too (reads and writes), resolving `B` per fetch from
`domain` / `capability` / `handle` and confining the subgraph's own `sql`/`orm` to
`tenant = B AND <public subset>`. See
[Cross-tenant target fields](./graphql.md#cross-tenant-target-fields) for the target-field model.

### Include the shared baseline: `target_or_null`

`scope: target_or_null` is the target-axis analog of `own_or_null` (Dimension 2): it widens a
target **read** from `tenant = B AND <public subset>` to
`(tenant = B OR tenant IS NULL) AND <public subset>` — tenant `B`'s public rows **plus** the
shared `NULL`-tenant baseline (catalog defaults, reference data, seeded rows every tenant
shares). Use it when the storefront you embed layers a customer's own public rows over a
common base catalog and you want both in one field.

- **Read-only.** The write axis on a target field is `own`/`none` regardless — a write still
  stamps `tenant = B` and can never land in the shared baseline. `target_or_null` widens
  reads only.
- **Same confinement, wider tenant predicate.** The public-subset filter still applies to
  **both** arms; only the tenant equality is relaxed to `(= B OR IS NULL)`. Tenant `A` is
  never reachable.
- **The public subset is mandatory here even under a capability.** For plain `target`, a
  `via: [capability]` field is exempt from the subset (the audience-bound capability naming
  `tid = B` *is* the authorization). `target_or_null` removes that exemption: the shared
  `NULL`-base rows are a different trust partition than the capability-authorized `B`, so the
  base arm must be visibility-gated. A `target_or_null` field over a table with no declared
  public subset is refused deny-by-default.
- **Plain-Column tables only.** Like `own_or_null` (Dimension 2), the OR-null widening applies
  only to a straight tenant-column table — never a session-keyed or unscoped table (no
  `NULL`-row to safely share). The SQL/GDC subgraph path (AND-only terms) fails closed rather
  than approximate the disjunction.

```graphql
# B's published products layered over the shared base catalog
baseProducts: [Product!]! @tenant(scope: target_or_null, via: [domain], public: "products")
```

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
     "sources": [ { "kind": "domain" } ], "read": "own", "write": "own" }
   ```

3. **Write ordinary handlers.** A request to `acme.shops.example.com` runs with the tenant
   bound to `acme`; every `orm` query and every `{scope}`-marked raw query sees only
   `tenant_id = 'acme'`. The handler code contains no tenant logic at all — add a customer
   by attaching a domain and tagging it, no redeploy.

For a **token**-authenticated console over the same data, declare a second function with
`sources: [ { "kind": "token", "claim": "tid" } ]` + a `token_claims` block, and (if it needs
an admin view across tenants) `read: all` — which the operator must enable fleet-wide with
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
