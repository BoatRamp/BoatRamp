# Use the blobstore binding

**For: app developers**

The `wasi:blobstore` binding gives a handler **per-site blob storage** over the
server's `Storage` backend, key-prefixed per site. Use it for uploaded files and
generated artifacts too large for the key/value store.

This is one of the four data bindings an operator wires up — see
[Use handler bindings](./handler-bindings.md) for the shared mechanics (granting a
binding, calling a sibling function, cookie auth).

## Grant it

Name `wasi:blobstore` in the `imports` list of the handler's `routing.handlers`
entry, capped by the site's allowed-imports policy. See
[Grant a binding](./handler-bindings.md#grant-a-binding).

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "api.wasm",
          methods: ["GET", "POST"],
          imports: ["wasi:blobstore"] ),
    ],
),
```

## Backend

The blobstore binding takes **no per-binding backend block** — it follows the
server's `blobs` backend set under `serve`. To change the backend, see the `serve`
configuration in the [boatramp.cfg schema](../reference/boatramp-cfg.md); to switch
an existing node's blob backend with zero downtime, see
[Switch the blob backend](./blob-backend-migration.md) (an operator task).

## Large uploads

A wasm guest reads and writes blob objects by key through `wasi:blobstore`, but it
can't accept a multi-gigabyte upload streamed through the sandbox. To let a client
*outside* the sandbox upload binary objects **directly** into a project's blob
container — authenticated, resumable, over S3 — and have the guest then read them
by key with the unchanged binding, see
[Ingest large uploads over S3 (blob-ingress)](./blob-ingress.md).

For how blob storage relates to the rest of the storage stack, see
[Storage, KV, and KvStore's three roles](../explanation/storage.md).

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
