# Use the messaging binding

**For: app developers**

The `wasi:messaging` binding gives a handler **publish/subscribe and queues**. A
handler publishes to a topic; a **consumer** declared in `routing.consumers`
subscribes to that topic and processes each message off the request path. Grant
`wasi:messaging` to both the publishing handler and the consuming component, and
match the topic name on each side. See
[Run consumers, crons, and streams](./background-work.md).

This is one of the four data bindings an operator wires up — see
[Use handler bindings](./handler-bindings.md) for the shared mechanics (granting a
binding, calling a sibling function, cookie auth).

## Grant it

Name `wasi:messaging` in the `imports` list of each component's
`routing.handlers` / `routing.consumers` entry, capped by the site's
allowed-imports policy. See [Grant a binding](./handler-bindings.md#grant-a-binding).

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "api.wasm",
          methods: ["POST"],
          imports: ["wasi:messaging"] ),
    ],
),
```

The messaging binding takes **no per-binding backend block** — it follows the
server's backends set under `serve`.

## Read bus stats (`messaging-stats`)

A component that needs to *show* how a flow is doing — "is this customer's sync backed up or
dead-lettering?" — grants the read-only **`messaging-stats`** capability and reads the gauges
boatramp already computes for a topic: `get(topic)` returns `{ dead_letter_count, backlog,
in_flight }`, and `groups(topic)` returns per-consumer-group `{ group, in_flight, lag }`. It is
**read-only** — there is no claim/redrive/purge here. (Since v0.4.26. With the shim:
`messaging_stats::get(topic)` / `groups(topic)`.)

It is tenant-scoped **host-side**, because per-topic depth/DLQ counts are otherwise a cross-tenant
oracle:

- A **plain** topic reads the component's own private namespace (host-prefixed), exactly like a
  publish — a component only ever sees its own.
- A **`bus:` topic** must be one the component **declared** in its `stats_topics`, and a per-tenant
  topic is declared as a **template** with a `{tenant}` placeholder (e.g. `bus:sync/{tenant}/import`).
  The guest names that template verbatim; the **host** substitutes *this invocation's* resolved
  tenant into `{tenant}` before reading — the guest never supplies the tenant, so it cannot name
  another tenant's topic. A `bus:` topic that isn't a declared template, or a `{tenant}` template
  with no resolved tenant, is refused (`not-declared`, fail-closed); an ungranted component gets
  `access-denied`.

```ron
// A subgraph that shows per-flow depth/DLQ declares the template it will read:
( name: "subgraph-sync",
  imports: ["messaging-stats", "graphql"],
  stats_topics: ["bus:sync/{tenant}/import"] )
```

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
