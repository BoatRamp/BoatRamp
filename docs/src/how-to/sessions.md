# Build a duplex agent session (SSE + resume)

A **session** is a long-lived, resumable, bidirectional channel between a client and a
WebAssembly guest — the primitive for streaming agent UIs (AG-UI, chat, tool-call
streams). The client opens an [SSE] stream to receive frames and `POST`s frames back
on the same route; boatramp owns the ordering, buffering, resume, and lifetime, and
**re-enters your guest once per inbound frame** rather than holding a long-lived
instance. Every frame is **opaque bytes** — boatramp never parses your protocol, so
you can carry AG-UI events, JSON, or anything else.

A session differs from a [stream](./background-work.md#stream-a-topic-to-the-browser)
(host-only pub/sub fan-out, no guest, no backchannel) and from a plain streaming
[handler](./deploy-handler.md) (one request, one response body): a session runs *your*
code per client message and streams results back, across reconnects.

> The `session` capability is **experimental** and ships in the default build behind the
> `session` cargo feature. A component that uses it declares `requires = ["session"]`, so
> deploying it to a host build without the capability is refused cleanly (see
> [capability compatibility](./deploy-handler.md)).

## Declare a session route

Add a `sessions` entry to your site's `routing` in `project.cfg`, pointing it at a
component that exports the session handler:

```ron
routing: (
    sessions: [
        ( route: "GET /agent",
          component: "agent.wasm",
          // Extra per-frame capabilities the handler uses. The session backchannel
          // itself is intrinsic to the route — you may list `session` for clarity, but
          // `sql`/`orm`/`invoke`/… are what actually need granting.
          imports: ["session", "sql"],
          // Host-forced tenancy for any sql/orm the handler runs per frame, resolved
          // ONCE at open from the verified bearer and carried across every re-entry
          // (identical to a handler — see Isolate tenants within a project).
          tenancy: ( column: "tenant_id", source: Token ),
          token_claims: ( jwks_url: "https://issuer/.well-known/jwks.json",
                          issuer: "https://issuer/", claim: "org" ) ),
    ],
),
```

The client addresses one session by a `?id=<id>` query parameter it chooses (see the
[wire protocol](#the-client-wire-protocol)); the host namespaces it under your project,
so ids never collide across tenants.

## Write the handler

The host calls your `handle` export **once per inbound frame batch** with the pending
frames and the last checkpoint. This is *mechanism B*: **no in-memory state survives
between re-entries** — you rehydrate from the checkpoint each time and persist the next
one before returning. You get three host calls: `send` (enqueue an outbound frame,
ordered, host-buffered for at-least-once resume), `checkpoint` (persist opaque resume
state), and `close` (end the session).

With the [shim](./deploy-handler.md) the boilerplate is a macro:

```rust
use boatramp_uchron_compat as compat;
use compat::session::Session;
use compat::CompatError;

#[compat::session(route = "GET /agent", requires = ["session"])]
fn handle(mut s: Session) -> Result<(), CompatError> {
    // Rehydrate turn count from the resume checkpoint (never a static/in-memory value).
    let mut turns: u32 = s.resumed()
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    while let Some(frame) = s.recv() {               // drain this batch's inbound frames
        if frame.as_slice() == b"cancel" {           // (recv() -> None means "drained", not closed)
            return s.close("client cancel");
        }
        turns += 1;
        s.send(format!("event: turn {turns}\n").as_bytes())?;  // opaque bytes out
    }
    s.checkpoint(&turns.to_le_bytes())?;             // survives the next re-entry
    Ok(())
}
```

Raw `wit-bindgen` guests export `boatramp:handlers/session-handler` and import
`boatramp:handlers/session` directly — see `examples/handlers/session-echo` for a
complete, dependency-free example (it backs the live capability gate).

Because delivery is **at-least-once**, a re-entry may run again after a trap or a
reconnect — so make `handle` **idempotent with respect to its own effects** (gate them
on the checkpoint, or tolerate a replay). Frames your handler already `send`-committed
before a mid-batch trap are kept; the inbound frame redelivers.

## The client wire protocol

A session is served on its route as **SSE out + POST in**, keyed by `?id=`:

**Receive** — open the SSE stream:

```
GET /agent?id=<id>              Accept: text/event-stream
GET /agent?id=<id>              Last-Event-ID: <cursor>     # resume after a drop
```

Each outbound frame arrives as an SSE event named `frame`, whose `data:` is the
**base64** of your opaque payload and whose `id:` is a monotonic **cursor**. On
reconnect the browser's `EventSource` sends the last `id:` as `Last-Event-ID`
automatically, and the host replays only frames past that cursor. A terminal
`event: close` (its `data:` the close reason) means the session ended.

**Send** — `POST` an inbound frame body to the same route:

```
POST /agent?id=<id>                                   # body = one opaque frame
POST /agent?id=<id>   Idempotency-Key: <key>          # dedupe a retried POST
POST /agent?id=<id>&ack=<cursor>                      # ack received frames (GC the buffer)
```

A `POST` returns `202` once the re-entry committed, `200` if it was a de-duplicated
retry, `410` if the session is closed, and `400`/`413` for a bad id / oversized frame.
Supply an `Idempotency-Key` to make retries safe (delivered once), and `ack` the highest
cursor you've received periodically so the host can release the outbound buffer during a
long stream.

## Security & isolation

- **Cross-tenant isolation is structural.** The session record is keyed under the
  verified caller's project; no id can reach another tenant's session.
- **A session id is a bearer capability *within* a tenant.** Binding re-verifies the
  caller's tenant on every open/POST (a different tenant is refused `403`), but two users
  of the *same* tenant are not distinguished — so **use an unguessable id** (a UUID; the
  shim generates one) and don't treat a session as a per-user boundary beyond the tenant.
- **Tenancy is host-forced.** Any `sql`/`orm` your handler runs per frame is scoped to
  the tenant resolved at open — never guest-spoofable, fail-closed, exactly as for a
  [handler](./tenant-isolation.md).

## Limits & lifetime

Sessions are bounded by host defaults: 1 MiB per frame, 256 unacked outbound frames
(backpressure past that), a 256-entry inbound dedup window, a 4 MiB checkpoint, a
5-minute idle TTL, and a per-project live-session cap. An idle or closed session is
reaped automatically; its client simply reconnects (with `Last-Event-ID`) if it still
wants the feed. Per-scope and per-IP connection caps apply to both the SSE and the POST
side, shared with the [stream](./background-work.md) budget.

[SSE]: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events
