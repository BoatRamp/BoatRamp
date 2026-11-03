# Use the kv binding

**For: app developers**

The `wasi:keyvalue` binding gives a handler a **per-site key/value store**. Use it
for session state, counters, and small hot records the handler reads and writes on
the request path.

This is one of the four data bindings an operator wires up — see
[Use handler bindings](./handler-bindings.md) for the shared mechanics (granting a
binding, calling a sibling function, cookie auth).

## Grant it

Name `wasi:keyvalue` in the `imports` list of the handler's `routing.handlers`
entry, capped by the site's allowed-imports policy — exactly like every other
binding. See [Grant a binding](./handler-bindings.md#grant-a-binding) for the
mechanics and the deny-by-default rule.

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "api.wasm",
          methods: ["GET", "POST"],
          imports: ["wasi:keyvalue"] ),
    ],
),
```

## Backend

The kv binding takes **no per-binding backend block** — it follows the server's
`kv` backend set under `serve` (the same store the control plane uses, namespaced
per site). To change the backend, see the `serve` configuration in the
[boatramp.cfg schema](../reference/boatramp-cfg.md).

For how the key/value store is laid out and the roles it plays, see
[Storage, KV, and KvStore's three roles](../explanation/storage.md) and the
[KV keyspace reference](../reference/keyspace.md).

Tail guest output with `boatramp logs` if a binding call traps — see
[Observe a running server](./observe.md).
