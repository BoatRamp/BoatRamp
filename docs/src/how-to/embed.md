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

- **`boatramp-server`** is the library. Its own crate doc puts it plainly: *"The
  server is backend-agnostic: it is handed a [`DeployStore`] (blobs in any
  `Storage`, metadata in any `KvStore`)."* The storage backends live in
  **`boatramp-storage`**, the domain types in **`boatramp-core`** — all published
  on crates.io.
- **The `boatramp` binary is not a library.** All the high-level orchestration —
  parsing `project.cfg` / `boatramp.cfg`, assembling the store + compute backends
  + reconcile loops + cluster + TLS + the web console — lives in the binary, not a
  crate. So embedding gives you the *server*, and you assemble the pieces you want
  (storage, auth, optional handler engine) yourself. A basic embedded server is a
  few lines; reproducing the full batteries-included node means wiring those pieces
  as the binary's `serve` path does.

> The published library crates are pre-1.0 (0.2.x); the API may change between
> minor versions.

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
- The binary's `serve` path (`crates/boatramp/src/serve.rs`) is the reference for
  wiring the fuller feature set (cluster, TLS, ACME, the web console, compute
  backends) if you need it embedded too.
