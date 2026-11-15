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

## Topic namespaces: component-private vs the project bus

A topic name resolves into one of two **host-namespaced** namespaces (the guest never writes the
`{site}`/`{project}` prefix itself, so it can neither read another component's private topic nor
forge the project prefix):

- A **plain** topic (e.g. `orders.created`) is **component-private**, host-namespaced under
  `{site}/{alias}/<topic>` (site-scoped). A handler's publish and its OWN consumer's subscribe to the
  same plain name meet here; nothing outside the component reaches it.
- A **`bus:` topic** (e.g. `bus:orders.created`) addresses the **shared project bus**,
  `{project}/bus/<topic>`. This is the only namespace that crosses components: a handler's
  `bus:deliver` publish and a native [compute worker](./native-compute-worker.md) bound with
  `--bind messaging:deliver` (which claims from `{project}/bus/deliver`) are the SAME queue. Use it to
  hand work from a request-path handler to an off-path worker or consumer in the same project.

So a handler that must reach a `bind-messaging` worker publishes `bus:<topic>`, not a plain topic.

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
