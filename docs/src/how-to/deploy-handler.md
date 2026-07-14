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
- Site policy that permits handlers and allows every import you request. The
  requested imports are intersected with the site's allowed imports at
  activation; an import the site does not grant is refused — see
  [Use handler bindings](./handler-bindings.md).

## 1. Declare the handler in `project.cfg`

Add the handler to the `routing.handlers` list. Each entry names a route pattern,
the allowed methods, the component file, and the host imports it may use (`sql`,
`wasi:keyvalue`, `wasi:blobstore`, `wasi:messaging`, plus `wasi:http` / `wasi:io`,
which every handler gets):

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

## 3. Sync the deployment

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

## 4. Call the route

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
