# Compose components into one handler

A handler is a single WebAssembly component. But you often want to author it in
**pieces** — a resolver here, a middleware there, a shared library of business
logic — each a separate, independently-built component with a typed WIT
interface. `boatramp compose` **fuses** those pieces into one linked component,
in-process, so you deploy a single `.wasm` while keeping the parts separate in
your source tree.

Linking happens **at build time and is checked at compile time**: a plugin's
exports must match the interface the edge imports, or composition fails. There is
no network hop at runtime and no dynamic plugin loading — the fused component is
one artifact the runtime instantiates like any other.

## The shape: an edge and its plugins

Composition has two roles:

- The **edge** (root) component exports the handler world (e.g.
  `wasi:http/incoming-handler`) and **imports** the interfaces its plugins
  provide.
- Each **plugin** (leaf) component **exports** an interface that satisfies one of
  the edge's imports.

For example, an edge that needs an `adder` interface and a plugin that provides
it, declared in WIT:

```wit
package example:demo;

interface adder {
    add: func(a: u32, b: u32) -> u32;
}

// The plugin provides `adder`.
world plugin {
    export adder;
}

// The edge needs `adder` and exports the handler entry point.
world edge {
    import adder;
    export run: func() -> u32;
}
```

Build each to a component (`wasm32-wasip2`), then fuse them:

```sh
boatramp compose \
  --edge edge.wasm \
  --plugin adder.wasm \
  -o handler.wasm
# composed edge.wasm + 1 plugin(s) -> handler.wasm (… bytes)
```

`--plugin` is repeatable — pass one per plugin. The output is a normal component
you deploy through the usual path:

```sh
boatramp blob put handler.wasm            # content-addressed upload
# …then reference it from a handler route as you would any component.
```

## What stays imported

Composition only satisfies the imports a **plugin** provides. The fused
component's **exports are unchanged** (it still exports e.g.
`wasi:http/incoming-handler`), and every **host** import a part declares —
`wasi:http`, `sql`, `kv`, `messaging`, `invoke`, `graphql`, … — **stays
imported**, for the runtime to supply at instantiation. So composition is purely
about linking your own components together; it never absorbs or hides the
platform capabilities a handler is granted (those still go through the site's
`allow_imports` gate as usual).

If a plugin's exports don't match any edge import, or a component is malformed,
`compose` fails with a `compose failed: …` message and writes nothing.

## When to use it

- **GraphQL resolvers as plugins.** Author each resolver (or a group) as its own
  component and fuse them into one federation-subgraph handler — see
  [Serve a GraphQL API](./graphql.md).
- **Reusable middleware.** Keep an auth/logging/validation layer as a plugin and
  compose it onto several edge handlers.
- **A shared logic library** built once and linked into multiple handlers.

Composition runs entirely in-process (it needs no external `wac` toolchain) and
**never runs on the serving node** — it is a build step that emits one component,
exactly like any other artifact you deploy.
