# Deploy & invoke a function

A **top-level function** is a WASI component you deploy and call by name, with its
own version line — independent of any site deployment. Use it when you want a unit
of compute that is invoked directly (sync or async), versioned and rolled back on
its own, and reused across sites. For the concept, see
[Functions: the compute primitive](../explanation/functions.md); to run one behind
a route instead, see [Deploy a handler](./deploy-handler.md).

All of the commands below take `--server <url>` (or read it from `project.cfg`) and
require a token with `system·admin` for writes / invoke, `system·read` for reads.

## Deploy a version

Deploy a component `.wasm` as a named function. The CLI uploads it as a
content-addressed blob first, then registers the version:

```console
$ boatramp function deploy greeter --component ./greeter.wasm
deployed greeter  [wasm]  a1b2c3d4e5f6
```

The printed id is the **version** — the component's content hash. Deploying the
same bytes again is idempotent; deploying new bytes appends a version and makes it
active. Choose a stronger [runtime substrate](../explanation/compute-model.md) with
`--runtime microvm` (or `container`).

## List and inspect

```console
$ boatramp function ls
greeter  [wasm]  a1b2c3d4e5f6  invoke:greeter

$ boatramp function get greeter
greeter
  runtime: wasm
  version: a1b2c3d4e5f6
```

## Invoke it

A **sync** invoke runs the function inline and streams back its response. The
request body is sent to the function; `--data` / `--data-file` supply it:

```console
$ boatramp function invoke greeter --data '{"name":"Ada"}'
Hello, Ada!
```

An **async** invoke durably enqueues the call and returns an id to poll — the run
survives a restart and is retried, then dead-lettered, on failure:

```console
$ boatramp function invoke greeter --async --data '{"name":"Ada"}'
queued 7f3a…  [queued]

$ boatramp function invocation greeter 7f3a…
7f3a…  [succeeded]  attempts=1
  result: HTTP 200
```

### Idempotency

Pass `--idempotency-key <key>` to make an invoke safe to retry: a repeat with the
same key **replays the first call's outcome** instead of running the function
again. This holds for both sync and async.

```console
$ boatramp function invoke greeter --idempotency-key order-42 --data '…'
```

## Versions, aliases, and rollback

A top-level function carries its own version line, so you can promote and roll back
without touching any site:

```console
# Point a label at a version (e.g. a stable "prod" alias).
$ boatramp function alias greeter prod a1b2c3d4e5f6

# Invoke a specific version or alias instead of the active one.
$ boatramp function invoke greeter --version prod

# Roll the active version back to an earlier one.
$ boatramp function rollback greeter --to a1b2c3d4e5f6
```

## Usage & quotas

Every invocation is metered host-side. Read the aggregate:

```console
$ boatramp function usage greeter
greeter
  invocations: 128 (126 ok, 2 failed)
  duration:    5310 ms total
  bytes:       40960 in / 81920 out
```

The same counters are exported as Prometheus series
(`boatramp_function_invocations_total`, `…_failures_total`,
`…_duration_ms_total`) — see [Observe](./observe.md).

A function may declare a **quota** in its config, enforced fail-closed (over the
limit ⇒ `429`):

- `max_invocations` over a `window_secs` window — a fixed-window rate limit.
- `max_concurrent` — the most in-flight invocations at once (per node).

## Signed webhooks

To let an external system trigger a function over a *public, signature-verified*
endpoint, deploy it with a webhook secret reference:

```console
$ BOATRAMP_HOOK_SECRET=… boatramp function deploy ingest \
    --component ./ingest.wasm --webhook-secret-env BOATRAMP_HOOK_SECRET
```

Callers then `POST /_webhooks/ingest` with an `X-Boatramp-Signature` header holding
the `HMAC-SHA256(body, secret)` hex (a leading `sha256=` is accepted). boatramp
verifies the signature **constant-time, before the function runs** — a missing or
wrong signature is `401`, and the secret lives only in the host env var you named,
never in the stored config.

## Remove it

```console
$ boatramp function rm greeter
removed greeter
```

Content-addressed component blobs are shared, so removal leaves them for
[`prune`](./prune-scrub.md).
