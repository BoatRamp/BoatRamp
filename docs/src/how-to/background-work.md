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

### Test a direct-MX mailer offline

A consumer that relays mail itself — resolving a recipient domain's MX and dialing
it directly, rather than handing off to a fixed SMTP relay — imports the consumer-lane
`dns-resolve` capability (plus the host-mediated `tcp-egress`) so it can look up
`resolve-mx` / `resolve-addr` host-side. That resolver normally uses the node's system
DNS, which makes a **fully-offline / hermetic test** awkward: there is no recipient
domain to point at.

For dev/test, the operator can seed a **static resolver override** in `boatramp.cfg`
so the mailer resolves known answers with **no network**:

```ron
// boatramp.cfg (operator/serve config — DEV/TEST only, leave unset in production)
handlers: (
    dns_resolve_override: (
        records: [
            ( name: "example.com", mx: [( preference: 10, exchange: "mx1.example.com" )] ),
            ( name: "mx1.example.com", addrs: ["93.184.216.34"] ),
        ],
    ),
)
```

Now the mailer's `resolve-mx("example.com")` returns `mx1.example.com` and
`resolve-addr("mx1.example.com")` returns the seeded address, all offline. This is an
operator knob only — a guest/project can never set it — and the answers still pass the
normal grant + `allow_guest_tcp_egress` posture + SSRF floor, so pointing a test MX at a
private/loopback sink additionally needs `allow_guest_private_egress`. See
[DEV/TEST resolver override](../reference/boatramp-cfg.md#devtest-resolver-override) for
the full schema and security model.

### Cap a consumer's concurrency

All consumers share one **async-lane** concurrency budget (`async_max_concurrency`).
A burst in one consumer (say a thumbnail backfill of thousands of images) can
occupy the whole lane and starve the others. Give a consumer its own
`max_concurrency` to cap how many of its messages run at once, independent of the
rest of the lane:

```ron
routing: (
    consumers: [
        // At most 2 thumbnail decodes in flight; other consumers keep their headroom.
        ( topic: "bus:thumbnail.requested", component: "thumb.wasm",
          imports: ["wasi:blobstore", "wasi:messaging"],
          max_concurrency: 2 ),
    ],
),
```

The value is clamped to the lane ceiling (`min(max_concurrency, async_max_concurrency)`
— it can only narrow a consumer, never raise it above the operator budget). Unset
⇒ the consumer shares the lane as before (no change). This is pure admission
control: ordering, at-least-once delivery, and retry/dead-letter semantics are
unchanged. Pair it with `async_max_memory_mb` for a memory-heavy worker — cap the
concurrency so N concurrent runs fit the memory budget.

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

## Push events to browsers over SSE (streams)

A **stream** is a host-level endpoint that fans a set of messaging topics out to connected clients
as [Server-Sent Events][SSE] — the server→client push primitive for live dashboards, notifications,
progress, and **presence / assignment** feeds. No guest runs per connection: anything in the project
`publish`es to a topic (a handler, a consumer, a function, a webhook) and the host broadcasts each
message to every client subscribed to that stream's route. A browser consumes it with a one-liner:

```js
const es = new EventSource("/live/inbox");
es.onmessage = (e) => applyPresenceEvent(JSON.parse(e.data));
```

Declare a `stream` in `routing`, listing the topics it broadcasts:

```ron
routing: (
    streams: [
        // Browsers GET /live/inbox as an EventSource; every message published to either
        // bus topic is delivered to all connected subscribers.
        ( route: "/live/inbox",
          topics: ["bus:inbox.presence", "bus:inbox.assignment"] ),
    ],
),
```

Publish from anywhere in the project — e.g. a handler that assigns a conversation emits the event on
the bus, and every connected browser sees it without the handler knowing who is listening:

```rust
// inside a normal request handler, consumer, or function
messaging::publish("bus:inbox.assignment",
    serde_json::to_vec(&AssignmentEvent { conversation, agent })?.as_slice())?;
```

The producer needs `imports: ["wasi:messaging"]`; the stream route itself grants no guest capability
(it is pure host fan-out). Because the topics are `bus:`-prefixed they are
[project-scoped](#share-a-topic-across-components-the-project-bus), so a producer in one site and the
stream endpoint in another meet on the same topic.

**What the host handles for you:** each client gets an SSE connection with a periodic heartbeat
(so an idle feed stays open through proxies); every event carries a monotonic `id:`, and a browser
`EventSource` that drops and reconnects sends the last id as `Last-Event-ID`, so the host replays
only what the client missed. A connection with no traffic for the idle window is torn down (the
client reconnects if it still wants the feed), an absolute max-duration bounds it, and per-scope +
per-IP connection caps (shared with the [session](./sessions.md) budget) bound a client that opens
many. Put the route behind the usual [visitor-access](./visitor-access.md) controls to require a
verified subscriber.

**Add a client→server backchannel:** set `websocket: true` to serve the same route as a WebSocket
instead of SSE (full-duplex), and give it a `publish_topic` so messages the client sends are
published onto that topic for a consumer to process:

```ron
( route: "/live/chat", topics: ["bus:chat.out"],
  websocket: true, publish_topic: "bus:chat.in" ),
```

### Per-subscriber scoped streams (`authz`)

By default a `stream` broadcasts its fixed `topics` to **every** connection. For a multi-scope feed —
shared inboxes, per-room chat, per-user notifications — where a subscriber must receive events only
for the scopes it belongs to, add an `authz` block. The connection is then **authorized before it
attaches** and subscribes **only** the topics it is authorized for: a non-member is refused `403`, an
anonymous connection `401`, and a cross-scope event (published to a topic the connection never
subscribes) is structurally undeliverable. It is the streaming analog of the platform's per-request
tenancy scoping. Absent `authz` ⇒ the broadcast behavior above, unchanged.

Capture the per-connection scope in the `route` with the matcher's `:name` syntax, and reference it
in `topics` with the `{name}` template:

```ron
// A shared-inbox feed scoped per mailbox the subscriber belongs to.
( route: "/events/shared/:mailbox",
  topics: ["shared/{mailbox}/presence", "shared/{mailbox}/assignment"],
  authz: scoped(
      // Verify the subscriber's bearer (the same app-IdP token verification handlers + the data
      // connector use); its claims feed the membership checks.
      token_claims: ( issuer: "https://idp.example", jwks_env: "IDP_JWKS" ),
      // Deny-by-default: EVERY check must pass. Use either method, or both.
      membership: [
          // (A-i) the verified token enumerates the mailboxes the subscriber may join
          claim( param: "mailbox", claim: "mailboxes" ),
          // (A-ii) OR a parameterized predicate against the site's managed DB (member iff ≥1 row);
          // `$name` binds the route param or a verified claim — never string-interpolated.
          sql( query: "SELECT 1 FROM mailbox_members WHERE mailbox = $mailbox AND subject = $sub" ),
      ],
  ) ),
```

- **Claim membership** suits scopes small enough to enumerate in the token; **SQL membership** suits a
  membership table in the site's managed database. The resolved topic is *exactly* the subscriber's
  scope (`shared/<mailbox>/presence`), so a publisher to another mailbox's topic can never reach this
  connection — the isolation is the topic subscription itself, not a post-hoc filter.

When membership can't reduce to a claim or a SQL predicate, hand the decision to a guest:

```ron
( route: "/events/shared/:mailbox", topics: ["shared/{mailbox}/events"],
  authz: guest_mediated( handler: "stream-authorizer" ) ),
```

The host invokes the `stream-authorizer` function with the connection's request (and, when
`token_claims` is set, the host-verified principal as the `x-boatramp-stream-principal` header); the
function returns the topic set to grant (`["shared/abc/events"]` or `{"topics": […]}`) or a non-2xx to
refuse. The returned topics are **confined to the declared `topics` templates** — a guest chooses
*which* declared scopes, never a new topic namespace.

> Scoped-stream bearer verification needs the `oidc` feature (like the data connector's token
> claims); without it a scoped stream fails closed.

### Which push primitive?

| Use | Primitive | Guest code per connection? |
| --- | --- | --- |
| Fan a topic out to many subscribers (presence, notifications, dashboards) | **`stream`** (this section) | No — host-only pub/sub |
| One request, one long response body the handler writes incrementally (token streaming, a progress feed from a single call) | a **streaming handler** (`streaming: true` + a `#[handler(stream)]` body — see [Deploy a handler](./deploy-handler.md)) | Yes — one `handle` call holds the body open |
| A resumable, bidirectional channel that runs *your* code per inbound frame (agent UIs, chat with tool calls) | **`session`** (see [Build a duplex agent session](./sessions.md)) | Yes — re-entered per frame |

[SSE]: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events

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
