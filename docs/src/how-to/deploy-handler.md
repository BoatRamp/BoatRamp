# Deploy a handler

Serve a route from an already-built WebAssembly component. A handler is a
[function](../explanation/functions.md) reached by an HTTP route — you declare it
in `project.cfg`, validate the manifest, then sync, and the sync step validates the
component blob and activates it against the site policy.

To build a component from scratch, see
[Write your first handler](../tutorials/first-handler.md). To use the host
bindings from guest code, see [Use handler bindings](./handler-bindings.md). To
run the same kind of component *invoked by name* instead of behind a route, see
[Deploy & invoke a function](./functions.md).

## Before you start

- A component built to the `wasm32-wasip2` target that exports
  `wasi:http/incoming-handler`. Sync rejects a component without this export.
- The component file reachable from your project root (here, `dist/api.wasm`).
- A server built with the `handlers` feature.
- The **site policy enabled** (`handlers.enabled` on the site) and its
  `allow_imports` covering every import you request — set this in
  [step 3](#3-enable-handlers-on-the-site). `sync` does **not** set it, so a fresh
  site refuses a handler deployment until you do.

## 1. Declare the handler in `project.cfg`

Add the handler to the `routing.handlers` list. Each entry names a route pattern,
the allowed methods, the component file, and the host imports it may use (`sql`,
`wasi:keyvalue`, `wasi:blobstore`, `wasi:messaging`, `invoke`, plus `wasi:http` /
`wasi:io`, which every handler gets):

```ron
routing: (
    handlers: [
        ( route: "/api/**", component: "dist/api.wasm",
          methods: ["GET", "POST"],
          imports: ["sql", "wasi:keyvalue"] ),
    ],
),
```

A component receives only the imports it declares here, and only those the site
also grants. Unlisted interfaces (for example `wasi:filesystem`) are refused even
when named.

A handler can also call a sibling top-level function in-process: grant it
`invoke` and add an `invoke_targets` allowlist naming the functions it may reach
(deny by default, `*` wildcards allowed). See
[Deploy & invoke a function](./functions.md) and
[Use handler bindings](./handler-bindings.md).

## 2. Validate the manifest

Check the config shape and route table before you deploy:

```sh
boatramp validate
```

```text
project.cfg: routing OK (1 handler: /api/** [GET, POST])
```

`validate` checks the manifest. The component blob itself — parseability, the
`wasi:http/incoming-handler` export, and the import allowlist — is validated at
sync.

## 3. Enable handlers on the site

The route you declared ships **in the deployment**, but a deployment that ships
handlers is refused at activation unless the **site** permits them. That gate is the
site's `handlers.enabled` policy — a piece of
[site config](../reference/siteconfig.md#handlers) **separate from the deployment**,
and **`sync` never sets it**. Skip this step and the sync below fails with:

```text
activation refused: deployment ships handlers/consumers but the site has them disabled
```

Enable it once, either way:

**Declaratively with `boatramp apply`** — an `apply.cfg` carries both the deployment
routing *and* the site policy, and applies them in the right order (policy first,
then activate):

```ron
sites: [(
    name: "my-site",
    path: "./dist",
    routing: ( handlers: [( route: "/api/**", component: "dist/api.wasm",
                            methods: ["GET", "POST"], imports: ["sql", "wasi:keyvalue"] )] ),
    // The site policy — the gate. `allow_imports` must be a superset of every
    // handler's `imports`.
    config:  ( handlers: ( enabled: true, allow_imports: ["sql", "wasi:keyvalue"] ) ),
)],
```

```sh
boatramp apply            # sets the site policy, then deploys + activates
```

**Or set the policy directly on the site over the admin API** (then use `sync` as in
step 4). `PUT …/config` replaces the whole site config, so `GET` it first and merge if
the site already has domains/access configured:

```sh
curl -fsS -X PUT "$SERVER/api/sites/my-site/config" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"handlers":{"enabled":true,"allow_imports":["sql","wasi:keyvalue"]}}'
```

An import a handler requests but the site's `allow_imports` doesn't grant is refused at
activation — see [Use handler bindings](./handler-bindings.md).

## 4. Sync the deployment

Upload the component and activate it:

```sh
boatramp sync ./dist --site my-site
```

```text
validated dist/api.wasm — exports wasi:http/incoming-handler, imports OK
activated my-site -> 7f3a2b2c — handler /api/**
```

If the component requests an import the site does not allow, sync rejects the
deployment and the previous one stays live.

## 5. Call the route

```sh
curl https://my-site.example/api/health
```

```text
{"status":"ok"}
```

A method outside the handler's `methods` list returns `405`; a path outside the
route pattern falls through to rewrites, then static content.

## Reference

- Route and import fields: [project.cfg schema](../reference/project-cfg.md).
- Using bindings from guest code: [Use handler bindings](./handler-bindings.md).
- Build a handler end to end: [Write your first handler](../tutorials/first-handler.md).
