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
messaging-backed SSE stream. The subscription's single root field names a **topic**;
a producer — a mutation handler, a function, a consumer — publishes each event to
that topic (via the `messaging` binding), and the connected client receives them as
SSE events, with `Last-Event-ID` resume and a heartbeat, bounded by the site's stream
connection caps.

```graphql
subscription { messageAdded { id body } }   # streams the "messageAdded" topic
```

The host only fans out — the payload delivered to the client is exactly what your
producer publishes to the topic (typically the subscription's result JSON). No handler
component runs per event.

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
