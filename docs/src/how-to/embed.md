# Embed boatramp as a library

boatramp is normally a single binary (server + CLI), but the server is a
**backend-agnostic library crate** you can embed in your own Rust application:
mount its HTTP surface into an existing `axum` app, or run it as a managed
sub-service. You hand it storage; it gives you the publishing API and the public
serving of your sites, handlers, and functions.

This is the right tool when you want boatramp's publish/serve plane *inside*
another process — an existing service, a desktop app, a test harness, a custom
control plane — rather than as a separate daemon.

## What is (and isn't) a library

- **`boatramp-server`** is the request-plane library. Its own crate doc puts it
  plainly: *"The server is backend-agnostic: it is handed a [`DeployStore`] (blobs
  in any `Storage`, metadata in any `KvStore`)."* The storage backends live in
  **`boatramp-storage`**, the domain types in **`boatramp-core`** — all published
  on crates.io.
- **`boatramp-node`** is the *assembly* library. It holds the batteries-included
  node wiring the `boatramp serve` binary used to inline: building the store
  (`build_blobs` / `build_kv`), the compute backends (`build_compute`), the handler
  runtime (`build_handler_runtime`), control-plane auth (`configure_auth`), and the
  node graph that ties them together —
  [`assemble(NodeInput) -> RunningNode`](#3c-assemble-the-full-node-boatramp-node).
  It depends on the concrete backend crates `boatramp-server` deliberately avoids,
  so it is the batteries-included assembler you can embed *or* test in-process.
- **The `boatramp` binary is a thin shell.** What is left in the binary is the
  *environment*, not the assembly: parsing `project.cfg` / `boatramp.cfg`, the
  store-migration guard, SIGHUP/signal handling, transport + TLS/ACME dispatch,
  cluster bring-up, and the web console. So embedding gives you the server *and* the
  assembly; you supply the environment you want. A basic embedded server is a few
  lines; a faithful batteries-included node is a `boatramp_node::assemble` call.

> The published library crates are pre-1.0 (0.2.x); the API may change between
> minor versions.

## Fidelity: what embedding does and doesn't cover

Which surface you embed decides how much of the real node you exercise:

- **`router()` alone** runs boatramp's library request handling but skips the
  *assembly* — how config becomes a store + compute backends + reconcile loops
  before the router exists. That assembly is exactly where integration bugs live: a
  site's config applied at the wrong point in activation, posture gating of
  shared-kernel compute, the default-project materialization. A `router()`-only
  harness sails past all of them.
- **`boatramp_node::assemble`** closes most of that gap: it *is* the serve binary's
  node-graph wiring (store → handler runtime → deploy store → compute + reconcile
  loops → a router-ready node), so an in-process test drives the same assembly the
  operator runs. `boatramp-node` ships exactly such a fidelity test. This is the
  surface to embed — and to test against — when you want the real node.

What **neither** exercises, and what therefore still needs the **real artifact**:
the CLI / `project.cfg` / `boatramp.cfg` parsing, the store-migration guard,
transport + TLS/ACME, cluster bring-up, and — the big one — the **real compute
backends** (docker / microVM), which need a live daemon (`dockerd`, `/dev/kvm`) and
process re-exec that no in-process harness provides. So `assemble` is a
high-fidelity harness for the assembly + serving plane, but validating the compute
backends, the CLI, and packaging still means driving `boatramp serve` (or the
container image) over HTTP and the CLI against real backends — which is what the
crate's live/e2e tests and the release boot gate do.

## 1. Add the dependencies

```toml
[dependencies]
# The lean static server (no wasm handler engine by default — see step 5).
boatramp-server  = "0.2"
boatramp-core    = "0.2"
# Concrete backends: filesystem blobs; SlateDB is the default embedded KV.
boatramp-storage = { version = "0.2", features = ["fs"] }
axum   = "0.8"
tokio  = { version = "1", features = ["full"] }
```

The three moving parts you provide:

| Piece | Trait | This example uses |
| --- | --- | --- |
| Blob storage | `boatramp_core::Storage` | `boatramp_storage::FsStorage` (a directory) |
| Control-plane metadata | `boatramp_core::kv::KvStore` | `boatramp_core::kv::MemoryKv` (ephemeral) |
| Handler engine (optional) | — | `HandlerRuntime::disabled()` (no wasm) |

## 2. Build a `DeployStore`

The `DeployStore` is boatramp's control-plane handle over a `Storage` + a
`KvStore`:

```rust
use std::sync::Arc;
use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::MemoryKv;
use boatramp_storage::FsStorage;

let storage = Arc::new(FsStorage::new("/var/lib/myapp/blobs"));
let kv = Arc::new(MemoryKv::new());
let deploy = DeployStore::new(storage, kv);
```

`MemoryKv` is in-process and **not durable** — fine for a test or an ephemeral
embed. For production, swap in the durable embedded KV, `boatramp_storage::SlateKv`
(the `slatedb` feature, transactional and durable on every write — the same store
the single-node binary uses), and keep `FsStorage` (or S3/GCS/Azure) for blobs.

## 3a. Run it standalone

`serve` binds a listener and runs the whole server (publishing API + site
serving), including the background scheduler when the handler engine is present:

```rust
use boatramp_server::{serve, Auth, HandlerRuntime};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let storage = std::sync::Arc::new(boatramp_storage::FsStorage::new("./blobs"));
    let kv = std::sync::Arc::new(boatramp_core::kv::MemoryKv::new());
    let deploy = boatramp_core::deploy::DeployStore::new(storage, kv);

    serve(
        "127.0.0.1:8080".parse()?,   // SocketAddr
        deploy,
        Auth::disabled(),            // dev only — see step 4
        HandlerRuntime::disabled(),  // no wasm handlers — see step 5
    )
    .await?;
    Ok(())
}
```

`boatramp_server::shutdown_signal()` is the graceful-shutdown future the standalone
path awaits; `serve_with(.., ServerOptions)` takes explicit request limits, CORS
allow-list, security posture, and PoP settings.

## 3b. Mount it into your own app

If you want to control the transport (your own listener, TLS, hyper config,
`tower` middleware, or extra routes), take the `axum::Router` directly instead:

```rust
use boatramp_server::{router, Auth, HandlerRuntime};

let app = router(deploy, Auth::disabled(), HandlerRuntime::disabled())
    // compose your own middleware / observability:
    .layer(tower_http::trace::TraceLayer::new_for_http());

let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
    .await?;
```

`router_with(.., ServerOptions)` is the same with explicit options.

> **boatramp owns the root path space.** It serves sites by **host** at `/` and
> exposes the control plane under `/api/…`, so `merge` boatramp's router with your
> own **non-colliding root routes** or wrap it in middleware — do **not** `nest` it
> under a path prefix (that breaks host-based serving and the absolute API paths).
> The connect-info make-service is what lets handlers see the peer address (IP
> rules, rate limiting, access logs).

## 3c. Assemble the full node (`boatramp-node`)

Steps 3a/3b give you the request plane over a bare `DeployStore`. To embed the
**batteries-included node** — the store plus the handler runtime, the compute
backends, and the background reconcile loops, wired exactly as `boatramp serve`
does — call `boatramp_node::assemble`. It is the same assembly the binary runs,
reachable as a library:

```toml
# The assembly crate. `fs` for filesystem blobs; `handlers` for the wasm engine.
boatramp-node = { version = "0.2", features = ["fs", "handlers"] }
```

```rust
use std::sync::Arc;
use boatramp_node::{assemble, NodeInput, RunningNode};

let storage = Arc::new(boatramp_storage::FsStorage::new("./blobs"));
let kv = Arc::new(boatramp_core::kv::MemoryKv::new());
let config = boatramp_node::config::ServerConfig::default(); // or parsed from boatramp.cfg
let options = boatramp_server::ServerOptions::default();      // posture, limits, PoP …

let RunningNode { deploy, handlers, auth, options, reconcile } = assemble(NodeInput {
    config: &config,
    data_dir: std::path::Path::new("./data"),
    storage,
    kv,
    auth: boatramp_server::Auth::disabled(), // dev only — see step 4
    options,
    watch_provider: None,          // cloud blob-change notifications, if any
    provision_tier: Default::default(),
})
.await?;

// Hand the wired node to a transport — or `router_with(deploy, auth, handlers, options)`
// to mount it into your own app (step 3b).
boatramp_server::serve_with("127.0.0.1:8080".parse()?, deploy, auth, handlers, options).await?;
// `reconcile` holds the compute + domain-verify loops — keep it in scope while serving.
```

`assemble` materializes the reserved `default` project, builds the handler runtime
and any configured compute backends, and spawns the reconcile loops; you still
provide the *environment* the binary would otherwise resolve for you (parsing the
config, the migration guard, signals, the transport). This is also the surface an
in-process fidelity test should target — see the fidelity note above.

## 4. Authentication

`Auth::disabled()` leaves the control plane open — only acceptable for a private
test or a trusted in-process boundary. For anything reachable, build a real `Auth`
(root key + minted tokens, OIDC, or an external signer) exactly as the
[auth bootstrap](./auth-bootstrap.md) guide describes; `auth.is_disabled()` reports
which mode you're in. Under a hardened [security posture](./security-posture.md),
`ServerOptions` also carries the PoP/`cnf` enforcement knobs.

## 5. Add the WebAssembly handler engine (optional)

The default build is the lean static server — no `wasmtime`. To serve handlers,
functions, and their `kv` / `sql` / `blobstore` / `messaging` bindings, enable the
`handlers` feature and build a `HandlerRuntime` over an engine plus the same
backends:

```toml
boatramp-server = { version = "0.2", features = ["handlers"] }
```

```rust
// with the `handlers` feature:
let handlers = boatramp_server::HandlerRuntime::new(
    engine,            // boatramp_handlers::HandlerEngine
    kv.clone(),        // Arc<dyn KvStore> — wasi:keyvalue, per-site namespaced
    storage.clone(),   // Arc<dyn Storage> — wasi:blobstore, per-site namespaced
    Some(sql),         // per-site sql provider, or None to withhold the capability
    Some(messaging),   // wasi:messaging provider, or None
);
```

The guest namespaces are scoped per project/site by the server, so the same
backends you pass here back every tenant safely.

## Production checklist

- **Durable backends:** `SlateKv` (or an external KV) for metadata; `FsStorage`
  or a cloud blob store for blobs. `MemoryKv` loses everything on restart.
- **Real auth** (step 4) for any non-loopback surface.
- **`serve_with` / `router_with`** to set upload/body limits, CORS, and the
  security posture rather than the permissive defaults.
- **Publish into it** the same way the CLI does — over the HTTP publishing API
  (`boatramp sync` against your embedded server) — so you reuse the negotiated,
  content-addressed, atomic-activate flow.
- **`boatramp_node::assemble`** (step 3c) is the reference wiring for the full node
  (store + handlers + compute + reconcile). For the *environment* around it —
  cluster, TLS/ACME, the web console — the binary's `serve` path
  (`crates/boatramp/src/serve.rs`) remains the reference.
