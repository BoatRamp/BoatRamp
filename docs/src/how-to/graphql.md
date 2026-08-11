# Serve a GraphQL API

A GraphQL API on boatramp is a normal Wasm handler that speaks GraphQL (for
example built with [async-graphql]). Point boatramp at it, turn on
`[handlers.graphql]`, and the platform treats GraphQL as a protocol it
understands — guarding it, resolving persisted queries, and (optionally)
federating several subgraphs into one supergraph. boatramp stays GraphQL-*aware*,
not a GraphQL *engine*: it parses a query only as far as the guard, persisted
queries, and the federation planner need; your schema and resolver logic stay in
your handler.

Everything below is **opt-in per site** and off by default.

## Turn it on

```ron
// boatramp.cfg — the site's handler config
handlers: (
    enabled: true,
    graphql: (
        enabled: true,
        max_depth: Some(12),
        max_complexity: Some(500),
        introspection: Some(false),
    ),
)
```

## The GraphiQL explorer

```ron
graphql: ( enabled: true, graphiql: true, introspection: Some(true) )
```

With `graphiql` on, opening the endpoint in a **browser** (any `Accept: text/html`
request) serves the GraphiQL IDE, which posts queries back to the same URL. Pair it with
`introspection: Some(true)` so the explorer can load your schema. It's a developer
convenience — leave it (and introspection) off in production.

## GraphQL from your database (no resolver code)

boatramp already runs your site's database as a managed workload, so it can also expose
it as a GraphQL API directly — **no handler, no resolvers**. Turn on the data connector
and name what to expose:

```ron
graphql: (
    enabled: true,
    data: (
        enabled: true,
        tables: {
            "users": (
                columns: ["id", "name"],
                // Row-level isolation: only rows whose `tenant` equals the request's
                // host-asserted `project` claim are visible.
                row_filter: [( column: "tenant", claim: "project" )],
            ),
        },
    ),
)
```

boatramp introspects the database, generates the schema (an object type per table plus
`users`, `users_by_pk`, and `where`/`order_by`/`limit`/`offset` arguments), and answers
each query by **compiling it to one parameterized SQL statement**. It is a *compiler*, not
an execution engine: a query it can't lower is rejected, never run partially — the database
does the executing.

Two guarantees make this safe to point at real data:

- **Deny-by-default.** Only the tables and columns you list are exposed; everything else is
  invisible and unqueryable. Selecting an unexposed column is an error, not a leak.
- **Fail-closed row isolation.** A table's `row_filter` is applied to *every* access, its
  value bound from a host-asserted claim (e.g. `project`). If the claim is absent the request
  is denied — a missing claim never widens access.

Every value is a bound parameter (injection-safe), and every identifier comes only from the
introspected, exposed schema. It's off by default; managed libsql is supported today.

**Relationships.** Foreign keys become relationship fields — a to-one field for each outgoing
FK and a to-many field for the rows that reference this one. A nested query resolves in **one
SQL statement** (relationships compile to correlated JSON subqueries), so there is no N+1, and
the row filter applies **inside** each relationship too — a nested row a tenant shouldn't see
stays hidden.

**Mutations** are opt-in:

```ron
graphql: ( enabled: true, data: ( enabled: true, mutations: true, tables: { … } ) )
```

You get `insert_<table>`, `update_<table>`, and `delete_<table>`, each returning
`{ affected_rows }`. Writes run in a transaction, use only exposed columns, and the row
filter is enforced on every write: an inserted row is forced to belong to the tenant, and an
update/delete only touches the tenant's rows. An unbounded update/delete (no `where`) is
refused.

**A wasm-resolved field.** A field can be served by a wasm function instead of a column,
listed per table:

```ron
"users": ( columns: ["id", "name"], resolvers: { "recommendations": "recommender" } )
```

The connector resolves the row's columns from SQL, then fills the delegated field with a
single batched invoke to the function (a local `_entities` fetch, joined by key — no N+1).
The map is also the allowlist: only these fields delegate, only to these functions. This is
GraphQL→SQL and GraphQL→Wasi blended at field grain; the coarser form is a SQL source acting
as a **federation subgraph** composed with wasm subgraphs (see [Federation](#federation)).

## The query-guard

With the guard on, an incoming GraphQL operation is parsed **at the edge and
rejected before your handler runs** when it:

- exceeds `max_depth` (deepest selection nesting, with fragments expanded so a
  query can't hide depth behind a fragment), or
- exceeds `max_complexity` (total field count — a schema-free cost proxy), or
- is a schema-introspection query (`__schema`/`__type`) and `introspection` is
  not allowed.

This is defense-in-depth over the per-handler fuel cap against the deep/wide
query denial-of-service class the fuel cap can't fully catch. A rejection is a
GraphQL-shaped `400`.

Every query-bearing POST is inspected — the body is buffered up to a 1 MiB edge
cap **regardless of its declared length**, so a chunked or oversized request can't
slip past the guard by omitting or misstating `Content-Length`. A GraphQL request
is small; a query body over the cap is refused with a GraphQL-shaped `413` rather
than passed through. Only an upload/form POST (`multipart/form-data`,
`application/x-www-form-urlencoded`), which carries no query the edge parses, passes
through untouched.

## Persisted queries + safelist

```ron
graphql: ( enabled: true, persisted_queries: true )   // or: safelist: true
```

With `persisted_queries`, a client may send a query **hash**
(`extensions.persistedQuery.sha256Hash`) instead of the full query. The edge
resolves the hash to the stored query and hands the full query to your handler.
On a first miss it returns `PersistedQueryNotFound`; the client re-sends the
query alongside the hash and the edge registers it (after verifying the hash).

`safelist` mode is stronger: only **pre-registered** hashes run and the edge
never registers a new one — persisted queries become a **query allowlist**, a
real security control.

## Subscriptions

A GraphQL **subscription** operation sent to a graphql-enabled site is served as a
[graphql-sse] event stream (the "distinct connections" mode). The subscription's
single root field names a messaging **topic**; a producer — a mutation handler, a
function, a consumer — publishes each event to that topic (via the `messaging`
binding), and each is delivered to the client as a graphql-sse `next` event, with
`Last-Event-ID` resume and a heartbeat, bounded by the site's stream connection caps.

```graphql
subscription { messageAdded { id body } }   # streams the "messageAdded" topic
```

Because the frames are standard graphql-sse, a normal GraphQL client (Apollo Client,
urql, or the `graphql-sse` library) consumes the subscription directly.

The host only fans out — it does **not** execute the subscription. The payload your
producer publishes to the topic is delivered verbatim as the `next` event's data, so
publish the **execution result** for each event — the JSON your resolver would return,
e.g. `{"data": {"messageAdded": {"id": "1", "body": "hi"}}}`. No handler component
runs per event.

[graphql-sse]: https://github.com/enisdenjo/graphql-sse/blob/master/PROTOCOL.md

## Federation

For a multi-team schema, run several **subgraph** handlers and let boatramp
compose them into one supergraph.

### Register subgraphs

Publish each subgraph's SDL to the project registry:

```bash
curl -X PUT --data-binary @accounts.graphql \
  https://api.example.com/api/projects/acme/graphql/subgraphs/accounts
curl -X PUT --data-binary @reviews.graphql \
  https://api.example.com/api/projects/acme/graphql/subgraphs/reviews
```

Each publish recomposes the whole supergraph and **rejects the change if it
does not compose** (a field co-owned without `@shareable`, or SDL that does not
parse) — a bad publish never corrupts the registry. Read the composed
supergraph with `GET /api/projects/acme/graphql/supergraph`.

### The gateway

Mark a site as the gateway:

```ron
graphql: ( enabled: true, federated: true )
```

A query to that site is **planned** against the registered subgraphs — root
fields are grouped by their owning subgraph, and a field owned by another
subgraph on a `@key` entity becomes a dependent `_entities` fetch joined on the
entity key — and **executed** by dispatching each fetch to its subgraph
function over the in-process invoke path (no network hop), stitching the results
by key. A subgraph named `accounts` is invoked as the function named `accounts`.

The registry (the SDL) and the deployed subgraph function are separate: if you
register a subgraph's SDL but never deploy a function of that name, a query that
routes to it fails with an explicit `subgraph \`accounts\` is registered but no
function named \`accounts\` is deployed` error rather than a silently-wrong result.
Deploy each registered subgraph as a function of the same name.

### The subgraph contract

A boatramp subgraph is just a function whose handler is a **federation
subgraph** — it must expose the standard federation contract:

- `Query._service { sdl }` returning its SDL, and
- `Query._entities(representations: [_Any!]!): [_Entity]!` resolving entities by
  their `@key`.

You do not write these by hand: a GraphQL library with federation support
provides them. With [async-graphql], derive your entity types and mark their
key with `#[graphql(entity)]` resolvers; the library generates `_service` and
`_entities`. boatramp's gateway then speaks exactly this contract to your
subgraph — the schema semantics stay in your code.

> **Scope.** Core federation — `@key` entities, `@external`/`@shareable`, root
> and entity fetches — is supported. The exotic Federation v2 corners
> (`@interfaceObject`, progressive `@override`, deep `@requires` chains) are not
> yet planned; a query that needs them will not compose or plan.

[async-graphql]: https://github.com/async-graphql/async-graphql
