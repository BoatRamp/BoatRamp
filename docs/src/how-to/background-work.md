# Run consumers, crons, and streams

Background work runs as WebAssembly handlers that boatramp invokes for you
instead of per HTTP request: **consumers** process messages off a topic, and
**crons** invoke a route on a schedule. You declare each one in the `routing`
section of `project.cfg`, pointing it at a handler, and boatramp runs it for the
live deployment. For the component build and site policy, see
[Deploy a handler](./deploy-handler.md).

## Declare a consumer

A consumer is invoked once per message on its `topic`. Give it a retry budget: a
message that fails is retried up to `max_attempts` times, then dead-lettered.

```ron
routing: (
    consumers: [
        ( topic: "emails", component: "mailer.wasm",
          imports: ["sql", "wasi:messaging"],
          max_attempts: 5 ),
    ],
),
```

## Share a topic across components: the project bus

A plain consumer `topic` is site-private — only that site's own handlers publish to
it. To let **different components** talk over one topic — a handler in one site, a
function, or an [external webhook](#ingest-external-events) — publish to and
subscribe from the shared **project bus** with a `bus:` prefix:

```ron
routing: (
    consumers: [
        // Subscribe to the project-wide `orders.created` bus topic.
        ( topic: "bus:orders.created", component: "fulfil.wasm",
          imports: ["wasi:messaging"] ),
    ],
),
```

Anything in the project publishes to the same topic — a guest via `wasi:messaging`
(`publish("bus:orders.created", …)`), a function's queue trigger, or a webhook
ingress. The bus is scoped to the **project** (a workspace): every member shares
it, and it is isolated from other projects. Producer and consumer are decoupled —
add or remove consumers without touching the producer.

## Fan out to independent workers: consumer groups

By default the consumers on a topic form a **work-queue**: each message goes to
exactly one of them (competing consumers — add more to scale throughput). Give a
consumer a **`group`** and it becomes a durable **fan-out subscriber** instead — it
receives *every* message on the topic, on its own cursor, with its own retries and
dead-letters. Consumers in different groups each process every message:

```ron
routing: (
    consumers: [
        ( topic: "bus:orders.created", component: "billing.wasm",
          group: "billing", imports: ["sql"] ),
        ( topic: "bus:orders.created", component: "audit.wasm",
          group: "audit", imports: ["wasi:blobstore"] ),
    ],
),
```

`billing` and `audit` each receive every order event; a slow or failing group never
blocks the other. A new group starts at `start: latest` (only events published after
it subscribes — the default) or `start: earliest` (replay the retained backlog):

```ron
( topic: "bus:orders.created", component: "reindex.wasm",
  group: "reindex", start: earliest ),
```

Omitting `group` keeps the work-queue behaviour — unchanged.

## Ingest external events

To bring an **external** event (a Stripe or GitHub webhook, a partner callback)
onto the bus without writing a consumer, deploy a function whose webhook
*publishes* to a bus topic. A signature-verified request drops its body onto the
bus and returns `202` — no code runs — and consumer groups process it like any
other event:

```sh
BOATRAMP_STRIPE_SECRET=… boatramp function deploy stripe-events \
    --component ./noop.wasm \
    --webhook-secret-env BOATRAMP_STRIPE_SECRET \
    --webhook-publish payments.event
```

Callers `POST /_webhooks/stripe-events` with the signature header, and a verified
event lands on `bus:payments.event`. It stays **deny-by-default** — no secret ⇒
`503`, a missing or wrong signature ⇒ `401`, an oversize body ⇒ `413` — so a
spoofed post never reaches the bus. (The `--component` is still required today but
is never run for a publishing webhook.) For the signature scheme, see
[signed webhooks](./functions.md#signed-webhooks).

## Declare a cron

A cron invokes an existing route on a schedule, using a standard five-field cron
expression. The route runs as if a request arrived for it:

```ron
routing: (
    crons: [
        ( schedule: "0 * * * *", route: "/api/rollup" ),
    ],
),
```

Sync to activate the new routing. Each component is validated at `sync`:

```sh
boatramp sync ./dist --site my-site
```

```text
validated mailer.wasm — consumer topic "emails"
activated my-site -> a1b2c3d4
```

In a cluster a cron fires on the one node that **owns** it (a stable hash over the live
membership), so cron work spreads across the fleet — it fires **once per minute**, cluster-wide,
not once per node. During a rare membership change (a node joining or leaving) a single tick may be
missed; crons are best-effort periodic, so a skipped minute during a reshuffle is expected, not a
failure. On a single node this is unchanged — every scheduled minute fires.

## Operate the dead-letter queue

When a message exhausts `max_attempts`, boatramp dead-letters it and retains the
payload until you clear it. Once you have fixed the cause, requeue the
dead-lettered messages onto the live topic:

```sh
boatramp dlq redrive emails --site my-site
```

```text
redrive: 12 dead-lettered message(s) on topic "emails"
```

If the messages are unrecoverable, drop them and reclaim the space instead:

```sh
boatramp dlq purge emails --site my-site
```

```text
purge: 12 dead-lettered message(s) on topic "emails"
```

To scope either command to a background alias rather than the live site, add
`--alias {site}/{alias}`.

### Operate the shared project bus

The commands above manage a **single site's** queues. To inspect or manage the
shared **project bus** — the `bus:<topic>` keyspace every site in a project
publishes to and consumes from — add `--bus` instead of `--site`:

```sh
boatramp dlq ls orders.created --bus
boatramp dlq redrive orders.created --bus
boatramp queue peek orders.created --bus
boatramp queue pause orders.created --bus
```

The project comes from your config's `[publish].project` (or `--project`). Because
the bus is shared across the whole project, its **destructive** operations
(`dlq redrive`/`discard`/`purge`, `queue group-reset`/`group-delete`/`pause`) require
a **project-admin** token — stronger than the per-site write a site's own DLQ needs;
inspection (`dlq ls`/`show`, `queue peek`/`replay`/`groups`) requires project-read. A
token scoped to one project can only ever reach that project's bus. `--bus` and
`--alias` are mutually exclusive (the bus is not per-deployment).

## Watch lag and dead-letters

Check consumer backlog and dead-letter counts with `boatramp stats`:

```sh
boatramp stats --site my-site
```

```text
site my-site
  queue/emails   invocations 512   errors 1   lag 0   dead-letters 0
```

A growing `lag` means consumers are falling behind the incoming rate; a nonzero
dead-letter count is messages waiting for you to redrive or purge. For tailing
guest output and the full metric surface, see
[Observe a running server](./observe.md).

## Publish durability: strong by default

`publish()` returns only after the message is **crash-durable** — written and
flushed to the durable store (its WAL persisted to object storage), so an
acknowledged publish survives a process crash *and* a power loss. This is a
**stronger** guarantee than NATS JetStream's default synchronous publish, which
acknowledges once the message is in the server's memory with the fsync deferred.
That safety costs latency: a single sequential publisher pays roughly one flush
interval per message. Concurrent publishers amortize it — the per-node
group-commit coalesces everything landing in one flush window into a single
durable write — and `publish_batch` commits a whole batch in one flush, so the
throughput you care about for a fan-out fabric stays high while every ack means
*persisted*. **Reach for a weaker mode only if single-publisher latency is your
bottleneck after batching.**

### Opt into fast-ack (`messaging_max_unflushed_msgs`)

If a workload needs JetStream-like publish latency and can tolerate a bounded
loss window, an operator can set, in the node's `[handlers]` config:

```toml
[handlers]
messaging_max_unflushed_msgs = 256   # 0 (default) = strong durability
```

With `N > 0`, `publish()` acknowledges on the in-memory buffer insert (≈tens of
µs) and a durable checkpoint is forced every `N` messages. The trade is explicit:

- **What you gain:** single-publisher publish drops from ≈one flush interval to
  ≈tens of µs; aggregate throughput rises accordingly.
- **What you give up:** acknowledged-but-unflushed messages are **lost on a
  process crash, OOM, `SIGKILL`, or power loss** before the next flush. The loss
  window is bounded by **both count and time** — at most `N` messages **and** at
  most one store `flush_interval` (the background WAL-flush timer persists every
  buffered write within one interval regardless of publish activity, ~5 ms in a
  boatramp deploy vs JetStream's 2 s fsync interval), whichever comes first. So a
  slow trickle can't leave a message un-durable longer than `flush_interval`, and a
  burst can't leave more than `N` un-durable. Pick `N` against your tolerance.
- **Honest positioning:** this is *weaker* than the strong default, and — because
  boatramp's buffer is in process memory — also **weaker than JetStream's
  default** (whose page-cache ack survives a *process* crash; boatramp's does
  not). It is faster than both. It is **not** "JetStream parity."

Scope and safety:

- **Bus publish only.** Consumer at-least-once is unchanged: a message that *was*
  flushed still redelivers on lease expiry, and ack/claim/dead-letter transitions
  are always fully durable. The only new failure is a just-published,
  not-yet-flushed message vanishing on a crash.
- **Control plane is never affected.** Deploy/config/domain/auth state and guest
  `wasi:keyvalue` writes stay fully durable regardless of this knob, even though
  they share the same store.
- **Operator-only, single-node.** It lives in daemon config (a site can't set
  it); a node with `N > 0` logs a warning at startup. In a cluster, publish
  durability is replication and this knob has no effect.
