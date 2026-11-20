# Write a native compute worker

**For: operators & app developers**

boatramp runs opaque OCI containers and microVMs, not only Wasm handlers (see
[Run a container or microVM](./compute.md)). A **native worker** — a program in any
language, built as an ordinary image — can reach the *same* managed message bus and the
*same* per-site blob store a Wasm handler reaches through its
[`wasi:messaging`](./handler-binding-messaging.md) and
[`wasi:blobstore`](./handler-binding-blob.md) bindings. There is no SDK to link: the worker
talks to **two per-node HTTP shims** with an off-the-shelf HTTP client, authenticating with a
bearer token boatramp hands it. The messaging and blob namespaces are shared with handlers
byte for byte, so a native worker and a Wasm handler on the same project interoperate.

This guide covers the shim wire protocol, the credentials a deployed workload is given, the
local `compute bind-*` development loop, and how to cross-build and deploy the worker image.

## The two per-node shims

Each shim is a single node-internal listener (bound to the compute bridge-gateway IP or
loopback — never a public address). Every request carries `Authorization: Bearer <token>`,
and the token is scoped to exactly one project/site (and optionally one topic or container);
the worker cannot name another tenant's namespace. The worker learns each shim's base URL and
token from its environment (see [the next section](#what-a-deployed-workload-sees)).

### Messaging shim — the project bus

A worker produces to and consumes from the project bus `{project}/bus/<topic>` — the same bus
a `wasi:messaging` producer publishes to and a consumer claims from.

> **Reaching this worker from a handler.** A `wasi:messaging` handler meets this worker only on the
> shared project bus, which it addresses with the **`bus:` selector**: a handler's `bus:deliver`
> publish maps to `{project}/bus/deliver` — the same queue a worker bound with `--bind
> messaging:deliver` claims from. A **plain** topic (no `bus:` prefix) is **component-private**
> (host-namespaced `{site}/{alias}/<topic>`, site-scoped), so it never reaches the project bus and
> cannot reach this worker. See [the messaging binding](./handler-binding-messaging.md#topic-namespaces-component-private-vs-the-project-bus).

| Method & path | Purpose |
|---|---|
| `POST /publish/{topic}` | Publish; the request body is the raw message payload. Optional `?delay_ms=`, `?ttl_ms=`, `?priority=`. |
| `POST /claim/{topic}` | Lease up to `?max=` messages (default 1), with `?lease_ms=` and `?max_attempts=`. Returns `{"messages":[…]}`. |
| `POST /ack` | Acknowledge one message: body `{"handle":"<opaque>"}`. Removes it from the queue. |
| `POST /nack` | Negative-acknowledge: body `{"handle":"<opaque>"}`. Redelivers it (the attempt is charged again). |

A claimed message is `{"id","topic","attempts","payload_b64","handle"}` — the payload is
base64 (standard), and `handle` is an opaque, self-contained string you hand back verbatim to
`ack`/`nack`.

### Blob shim — the per-site object store

A worker reads and writes objects under `{container}/{key}`, exactly the objects a
`wasi:blobstore` handler for the same site sees.

| Method & path | Purpose |
|---|---|
| `PUT /{container}/{key}` | Write an object (request body is the bytes; `Content-Type` is recorded). |
| `GET /{container}/{key}` | Read an object; honors a single `Range:` header. |
| `HEAD /{container}/{key}` | Existence + size, no body. |
| `DELETE /{container}/{key}` | Remove an object (deleting a missing object is not an error). |
| `GET /{container}` | **List** the keys under the container. Optional `?prefix=`, `?after=`, `?limit=`. |

`LIST` returns `{"keys":[…],"cursor":<opaque|null>}`. The keys are **container-relative**
(the internal `hblob/{site}/{container}/` prefix is stripped, and boatramp's reserved
`.boatramp*` namespace is hidden) — the same names a `wasi:blobstore` `blob-list` handler
returns. One response holds up to 1000 keys; when `cursor` is non-null, pass it back as
`?after=<cursor>` to fetch the next page. A `?prefix=` narrows the listing within the
container (it must be container-relative — no leading `/`, no `..`).

## What a deployed workload sees

When you deploy a worker with `compute set` and add a `--bind`, boatramp injects the shim URL
and a per-replica bearer token into the workload's environment:

| `--bind` | Injected env |
|---|---|
| `--bind messaging` (or `messaging:<topic>`) | `BOATRAMP_MESSAGING_URL`, `BOATRAMP_MESSAGING_URL_AUTH_TOKEN` |
| `--bind blob` (or `blob:<container>`) | `BOATRAMP_BLOB_URL`, `BOATRAMP_BLOB_URL_AUTH_TOKEN` |

A bare `--bind messaging` is bus-wide (any topic); `--bind messaging:deliver` confines the
token to the `deliver` topic. A bare `--bind blob` is site-wide; `--bind blob:assets` confines
the token to the `assets` container. The token is minted per replica, rotates on restart, and
is revoked when the replica stops — the operator's storage/bus credentials never enter the
guest.

If your program reads differently named variables, remap with templated `--env`: the
`{{messaging.url}}` / `{{messaging.token}}` and `{{blob.url}}` / `{{blob.token}}` placeholders
(and the topic-/container-qualified `{{messaging.<topic>.url}}`, `{{blob.<container>.url}}`,
etc.) expand to the same values. For example:

```sh
boatramp compute set worker \
  --image ghcr.io/acme/worker:1 --port 8080 \
  --bind messaging:deliver --bind blob:assets \
  --env "QUEUE_URL={{messaging.url}}" \
  --env "QUEUE_TOKEN={{messaging.token}}" \
  --env "S3_LIKE_URL={{blob.url}}" \
  --env "S3_LIKE_TOKEN={{blob.token}}"
```

## Worked example

A worker needs nothing but an HTTP client. With `curl`:

```sh
# --- blob: write, read back, and list the container ---
curl -fsS -X PUT "$BOATRAMP_BLOB_URL/assets/report.json" \
  -H "Authorization: Bearer $BOATRAMP_BLOB_URL_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @report.json

curl -fsS "$BOATRAMP_BLOB_URL/assets/report.json" \
  -H "Authorization: Bearer $BOATRAMP_BLOB_URL_AUTH_TOKEN" -o report.copy.json

# List the keys under a prefix (container-relative names come back):
curl -fsS "$BOATRAMP_BLOB_URL/assets?prefix=report" \
  -H "Authorization: Bearer $BOATRAMP_BLOB_URL_AUTH_TOKEN"
# => {"keys":["report.json"],"cursor":null}

# --- messaging: publish, then claim / ack ---
curl -fsS -X POST "$BOATRAMP_MESSAGING_URL/publish/deliver" \
  -H "Authorization: Bearer $BOATRAMP_MESSAGING_URL_AUTH_TOKEN" \
  --data-binary 'hello world'

msg=$(curl -fsS -X POST "$BOATRAMP_MESSAGING_URL/claim/deliver?max=1" \
  -H "Authorization: Bearer $BOATRAMP_MESSAGING_URL_AUTH_TOKEN")
handle=$(printf '%s' "$msg" | jq -r '.messages[0].handle')

# process the payload ( .messages[0].payload_b64 is base64 ), then ack it:
curl -fsS -X POST "$BOATRAMP_MESSAGING_URL/ack" \
  -H "Authorization: Bearer $BOATRAMP_MESSAGING_URL_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"handle\":\"$handle\"}"
```

## Develop locally: the `compute bind-*` loop

You can run the worker as a plain local process against a boatramp node *before* you build an
image, by minting the same `BOATRAMP_*_URL` + token pair into your shell. `compute bind-blob`
mints a blob credential and `compute bind-messaging` a messaging credential; `--export`
prints `export …` lines so the output is `eval`-able:

```sh
# point at the node once (or pass --server <url> on each call; env fallback BOATRAMP_SERVER)
export BOATRAMP_SERVER=http://127.0.0.1:8080

# a site-scoped blob credential for the `mailroom` site, confined to the `assets` container:
eval "$(boatramp compute bind-blob --site mailroom --container assets --export)"

# a messaging credential for the `default` project bus, confined to the `deliver` topic:
eval "$(boatramp compute bind-messaging --topic deliver --export)"

# BOATRAMP_BLOB_URL(+_AUTH_TOKEN) and BOATRAMP_MESSAGING_URL(+_AUTH_TOKEN) are now in the env —
# run the worker exactly as a deployed replica would see it:
./target/debug/worker
```

`--server` is accepted on the `compute` command (`boatramp compute bind-blob --server <url>
…`), falling back to `$BOATRAMP_SERVER` and then `[deploy].server`. `bind-blob` requires
`--site` (the workload identity whose per-site namespace to bind); `bind-messaging` has no
`--site` because the bus is project-scoped. Both take `--project` (default `default`); omit
`--container`/`--topic` for a namespace-wide credential.

### Enable the bind loop on the node (operator)

Two node-side preconditions:

1. **A `[compute]` section.** The shims only listen when the node is in compute mode, which a
   `[compute]` section switches on — it starts the compute reconcile loop (idle and harmless
   with no declared workloads; it never touches your data) and lets you set the shim listen
   addresses. Point each shim URL at the bridge-gateway IP or loopback:

   ```ron
   // boatramp.cfg (RON)
   compute: (
       blob_shim_url:      "http://127.0.0.1:8082",
       messaging_shim_url: "http://127.0.0.1:8083",
   ),
   ```

2. **The dev-bind posture override.** `compute bind-blob` / `bind-messaging` hand a credential
   to a process *outside* the sandboxed-workload model, so they are off in every profile but
   `dev`. Rather than switch the whole node to the `dev` profile, keep it **single-tenant** and
   opt in with just the two knobs:

   ```ron
   // boatramp.cfg (RON) — stay single-tenant, enable only dev-bind
   security: (
       profile: "single-tenant",
       overrides: (
           allow_dev_blob_bind:      true,
           allow_dev_messaging_bind: true,
       ),
   ),
   ```

   Equivalently, `BOATRAMP_SECURITY_ALLOW_DEV_BLOB_BIND=true` /
   `BOATRAMP_SECURITY_ALLOW_DEV_MESSAGING_BIND=true`. Without the override the dev-bind
   endpoints return `403`.

The `compute bind-*` calls hit node-global `System·Admin` endpoints. If the node runs with
**control-plane auth disabled on a loopback listener** (a common local setup), those admin
calls need no token — run the `bind-*` commands directly. On an authenticated node, use an
admin token as usual. (This no-token convenience is only for the *control-plane* admin call;
the shim data plane always requires its minted per-replica bearer token.)

## Cross-build and deploy the worker image

A native worker is deployed as an OCI image the node pulls (`compute set --image`). Build a
static binary so the image is minimal and portable, package it for `linux/amd64`, push it, and
set the workload:

```sh
# 1. a static binary (musl avoids a libc dependency in the final image)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# 2. an amd64 image (buildx makes the platform explicit even on an arm64 host)
docker buildx build --platform linux/amd64 \
  -t ghcr.io/acme/worker:1 --push .

# 3. deploy: one replica, with the managed bindings wired in
boatramp compute set worker \
  --image ghcr.io/acme/worker:1 \
  --port 8080 \
  --bind messaging:deliver \
  --bind blob:assets
```

A minimal `Dockerfile` for the static binary:

```dockerfile
FROM scratch
COPY target/x86_64-unknown-linux-musl/release/worker /worker
ENTRYPOINT ["/worker"]
```

For a **private registry**, seal a pull credential once and reference it with `--pull-secret`:

```sh
printf '%s' "$GHCR_TOKEN" | boatramp compute registry-auth set ghcr-pull \
  --username acme --password-stdin
boatramp compute set worker --image ghcr.io/acme/worker:1 --port 8080 \
  --pull-secret ghcr-pull --bind blob:assets
```

The registry host, its auth realm, and every redirect hop are **SSRF-screened and must be
https** — a private registry reachable only on a loopback/internal (RFC-1918, link-local,
CGNAT, ULA, …) address is currently **refused**. Use an externally-resolvable public
registry, or preload the image and launch with `--pull-policy if-not-present`. A
digest-pinned reference (`…@sha256:`/`@sha512:`) is verified against its digest on pull. See
[Pull from a private registry](./compute.md#pull-from-a-private-registry).

> **Operator note — the native container backend needs nftables under multi-tenant.** Each
> worker's veth gets a per-port nftables anti-spoof filter on the shared `br-boatramp` bridge.
> Under the `multi-tenant` posture a node with no usable `nft` **refuses every launch**
> (fail-closed); a single-tenant node warns and proceeds. Install `nft` and grant the node
> `CAP_NET_ADMIN` (on NixOS, [`services.boatramp.compute = true`](./install.md#nix--nixos)).
> See [Node networking: nftables anti-spoof](./compute.md#node-networking-nftables-anti-spoof-required-for-multi-tenant).

See [Run a container or microVM](./compute.md) for the full `compute set` surface (volumes,
scale-to-zero, regions, resource limits) and
[Diagnose & work around compute issues](./diagnose-compute.md) for operating the reconcile
plane.
