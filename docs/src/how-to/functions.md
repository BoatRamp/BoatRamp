# Deploy & invoke a function

A **top-level function** is a WASI component you deploy and call by name, with its
own version line — independent of any site deployment. Use it when you want a unit
of compute that is invoked directly (sync or async), versioned and rolled back on
its own, and reused across sites. For the concept, see
[Functions: the compute primitive](../explanation/functions.md); to run one behind
a route instead, see [Deploy a handler](./deploy-handler.md).

All of the commands below take `--server <url>` (or read it from `project.cfg`) and
require a token with `system·admin` for writes / invoke, `system·read` for reads.

## Scaffold a new function

Start from a template instead of hand-wiring a `wasi:http` component:

```console
$ boatramp function init greeter
scaffolded greeter in ./greeter
  next: cd greeter && boatramp function build

$ cd greeter && boatramp function build
built target/wasm32-wasip2/release/greeter.wasm
  deploy: boatramp function deploy <name> --component target/wasm32-wasip2/release/greeter.wasm
```

`function init` writes a minimal component (a `handle` function you edit) plus its
`wit/` world; `function build` compiles it and prints the produced component,
detecting the language from the project files:

- **`--lang rust`** (default) — a `wasi:http` component built with `cargo build
  --release --target wasm32-wasip2`. Needs the `wasm32-wasip2` target (`rustup
  target add wasm32-wasip2`, or the project's `nix develop` shell).
- **`--lang js`** — a JavaScript component built with
  [`jco componentize`](https://github.com/bytecodealliance/jco) (fetched
  version-pinned via `npx`, so only Node is required; `nix develop` provides it).
- **`--lang python`** — a Python component built with
  [`componentize-py`](https://github.com/bytecodealliance/componentize-py) (run
  version-pinned via `uvx`, so only `uv` is required; `nix develop` provides it).

The produced `.wasm` is a portable WASI component in every case — deploy it with
`function deploy`, and it runs on the same engine. Note the JS and Python
components bundle their language runtime (~12–18 MB) and so are larger than a Rust
component; pick the language that fits your code.

### Run it locally

Before deploying, exercise the component **locally** — no server, no upload. The
harness runs the component in-process through the same engine that serves it in
production:

```console
# One request + assertions (exits non-zero if an assertion fails):
$ boatramp function test --component target/wasm32-wasip2/release/greeter.wasm \
    --path /hello --expect-status 200 --expect-body "hello"
HTTP 200
hello from your boatramp function (/hello)
ok

# Or serve it on a local port and curl it:
$ boatramp function dev --component target/wasm32-wasip2/release/greeter.wasm --port 8787
serving …/greeter.wasm on http://127.0.0.1:8787  (Ctrl-C to stop)
```

The harness grants no host capabilities (kv/sql/blobstore/messaging), so it suits
components that only use the HTTP request/response — capability-backed local
testing comes later. `function test`/`dev` are in the build compiled with the
`handlers` feature (the engine).

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

## Scheduled & event triggers

A top-level function can also be reached by a **trigger** the server dispatches on
its own — no caller. Add one with `function trigger add`:

```console
# Run the function on a schedule (a durable async invocation each fire).
$ boatramp function trigger add greeter tick --cron "0 * * * *"

# Invoke the function per message on its queue `fn/greeter/jobs`.
$ boatramp function trigger add greeter jobs --queue jobs

# Invoke the function when an object changes under `fn/greeter/uploads/`.
$ boatramp function trigger add greeter onupload --blob uploads/

$ boatramp function trigger ls greeter
jobs  [queue]
onupload  [blob]
tick  [cron]

$ boatramp function trigger rm greeter tick
```

- A **cron** fire enqueues a durable invocation (retried, then dead-lettered, like
  any [async invoke](#invoke-it)).
- A **queue** trigger claims messages from the function's own `fn/<name>/<topic>`
  topic and invokes the function once per message, acking on success.
- A **blob** trigger fires when an object changes under the watched prefix — and it
  fires for **any** writer, not just boatramp, because it uses the storage
  backend's native change notification (inotify/FSEvents locally, S3→SQS in the
  cloud). The changed key + kind arrive as the invocation's JSON body. It needs a
  **watch-capable** storage backend: on one that can't watch, adding the trigger is
  refused (a `400`, never a silent no-op). In a cluster the scheduler fires each
  trigger on the leader, exactly once.

### Cloud blob triggers (auto-provisioning)

The `function trigger add --blob` command is **identical** on every backend — the
environment difference hides behind the storage backend. On the filesystem the
watch is zero-config (inotify/FSEvents). On a cloud object store the native event
pipeline must be created first, so boatramp provisions it for you — "auto-DNS, but
for object-store events." What boatramp creates is recorded in a managed-notification
ledger and **retracted** when you remove the trigger, so no cloud resources leak.

Each cloud backend uses its native pipeline:

- **S3** (`--blobs s3`) — an **SQS queue** + a queue access policy + a bucket
  `QueueConfiguration` (added by **read-merge-write**, so existing notifications are
  preserved and an overlapping foreign entry is refused, never clobbered). Fully
  auto-provisioned.
- **GCS** (`--blobs gcs`) — a **Pub/Sub** topic + subscription + a bucket
  `notificationConfig`. Auto-provisioned except the one-time IAM grant giving the
  GCS service agent `roles/pubsub.publisher` on the topic (the `dry-run` recipe
  prints it).
- **Azure** (`--blobs azure`) — a **Storage Queue** (auto-provisioned) fed by an
  **Event Grid** subscription. The Event Grid subscription is a one-time
  management-plane (Azure AD) step the `dry-run` recipe prints as an `az eventgrid`
  command; boatramp manages + consumes the queue.

You pick the behavior with a **tier** in the server's `boatramp.cfg` (the elevated
cloud credentials live server-side, not in the CLI):

```ron
serve: (
    // dry-run | provision | verify-only | refuse (default)
    blob_notify_tier: "provision",
    // S3: the AWS account id (scopes the SQS queue policy).
    // GCS: the GCP project id (for the topic + notificationConfig).
    // Azure: unused (the queue shares the account's shared-key auth).
    blob_notify_account_id: "123456789012",
)
```

- **`dry-run`** — adding the trigger prints the exact pipeline to apply and does
  **not** activate (nothing is mutated, no credentials needed).
- **`provision`** — boatramp creates + reconciles + retracts the pipeline (needs
  credentials allowed to manage SQS + the bucket notification config).
- **`verify-only`** — you pre-wired the pipeline; boatramp checks it exists, then
  consumes it.
- **`refuse`** (default) — no pipeline, no provisioning ⇒ the trigger is refused
  (fail-closed). This is why a cloud blob trigger with no tier configured is a
  `400`: the behavior stays conceptually clear, never a silent no-op.

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
