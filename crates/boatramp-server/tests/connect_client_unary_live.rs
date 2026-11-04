//! Live end-to-end gate for the **Connect / gRPC-web GENERATED CLIENT, unary** (luigi BR-REQ-1,
//! PLAN-connect-grpc §9 / IU-5). The client-side mirror of the `connect_unary_live` serving gate:
//! where that gate drove the live serving path with a hand-written HTTP request, this one drives it
//! with the GENERATED `connect.greeter.v1` client (`connect_clients::greeter::GreeterClient`) over
//! the `boatramp-connect-client` shim + its `PlaintextHttpTransport` — proving the generated client,
//! the client shim, and the shared `boatramp-connect-frame` codec round-trip against a REAL compiled
//! guest (`connect-greeter.wasm`) served over the ACTUAL hand-rolled HTTP/1.1 stack on a loopback
//! socket. This is the "end-to-end proof" the IU-5 client-codegen deliverable gates on.
//!
//! Two wires, both unary, both via the one generated `say_hello` call:
//!   1. **Connect** (`application/proto`, the client default): bare message in, bare message out.
//!   2. **gRPC-web** (`application/grpc-web+proto`): the client frames the request and parses the
//!      `[data frame][grpc-status:0 trailers]` response — the client half of the host residual.
//!
//! `#[ignore]`d (real loopback sockets, timing-sensitive like the other socket live gates) and run
//! with `--include-ignored` in the `live gate (connect-client)` CI job; the gate greps the
//! `CONNECT CLIENT UNARY LIVE OK` marker + the pass count, so a silent skip / compile-out fails the
//! merge (the ignore-gated-tests-not-evidence discipline). The fixture is `include_bytes!`-embedded
//! (prebuilt + committed), so it runs on musl with no wasm toolchain.
#![cfg(all(feature = "handlers", feature = "compression"))]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boatramp_connect_client::{ClientProtocol, Endpoint, PlaintextHttpTransport};
use boatramp_core::ByteStream;
use boatramp_core::config::{
    CompressionConfig, DeployConfig, HandlerConfig, HandlersSiteConfig, SiteConfig,
};
use boatramp_core::deploy::{DeployStore, FileEntry, Manifest, sha256_hex};
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_server::{Auth, HandlerRuntime, router, serve_plaintext_listener};
use boatramp_storage::FsStorage;
use connect_clients::greeter::{GreeterClient, SayHelloRequest};
use futures::StreamExt;
use tokio::net::TcpListener;

const CONNECT_GREETER: &[u8] = include_bytes!("fixtures/connect-greeter.wasm");

const SITE: &str = "greetersite";
/// The Connect RPC path the deploy handler routes on (the generated client derives the same path
/// from `GreeterClient::SERVICE` + the method name).
const RPC_PATH: &str = "/connect.greeter.v1.Greeter/SayHello";

/// Build the live app: a real engine + runtime serving the compiled `connect-greeter` component on
/// a handlers-enabled site with on-the-fly compression ON (so the gRPC-web wire actively exercises
/// the never-compress-framed-bodies residual, as on the serving-side gate).
async fn live_app() -> axum::Router {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-connect-client-unary-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(CONNECT_GREETER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(CONNECT_GREETER)) })
            .boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "connect/greeter.wasm".to_string(),
        FileEntry {
            hash,
            size: CONNECT_GREETER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let config = DeployConfig {
        handlers: vec![HandlerConfig {
            route: RPC_PATH.to_string(),
            methods: vec!["POST".to_string()],
            component: "connect/greeter.wasm".to_string(),
            imports: vec![],
            streaming: false,
            limits: None,
            env: BTreeMap::new(),
            secrets: vec![],
            no_secrets: false,
            invoke_targets: vec![],
            stats_topics: vec![],
            tenant_secret_names: vec![],
            upload_containers: vec![],
            blobstore_containers: vec![],
            egress_allowlist: vec![],
            dns_publish_zones: vec![],
            dns_publish_ns_targets: vec![],
            tenancy: None,
            token_claims: None,
        }],
        ..Default::default()
    };
    let manifest = Manifest {
        files,
        config,
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .activate(ProjectRef::DEFAULT, SITE, &id)
        .await
        .unwrap();
    deploy
        .set_site_config(
            ProjectRef::DEFAULT,
            SITE,
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec![],
                    ..Default::default()
                }),
                compression: CompressionConfig {
                    enabled: true,
                    min_size: 0,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let engine = HandlerEngine::new(Limits::default(), 16).unwrap();
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    router(deploy, Auth::disabled(), runtime)
}

/// Bind a loopback socket and serve `app` over the real hand-rolled HTTP stack; return its address.
async fn spawn_server(app: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = serve_plaintext_listener(listener, app, std::future::pending::<()>()).await;
    });
    addr
}

/// Run the blocking generated-client call off the async runtime (the client shim's
/// `PlaintextHttpTransport` is a synchronous `std::net::TcpStream`), returning the greeting.
async fn say_hello(base_url: String, protocol: ClientProtocol, name: &str) -> String {
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        let transport = PlaintextHttpTransport::with_read_timeout(Duration::from_secs(15));
        let endpoint = Endpoint::new(base_url).with_protocol(protocol);
        GreeterClient::say_hello(&transport, &endpoint, SayHelloRequest { name })
            .expect("unary RPC round-trip")
            .greeting
    })
    .await
    .expect("spawn_blocking join")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: drives a GENERATED Connect client against a real guest over the hand-rolled HTTP \
            stack on a loopback socket; run via --include-ignored in the `live gate (connect-client)` job"]
async fn connect_generated_client_unary_round_trips() {
    let app = live_app().await;
    let addr = spawn_server(app).await;
    let base = format!("http://{addr}/_sites/{SITE}");

    // ---- 1. Connect wire (the client default): bare application/proto -------------------------
    let greeting = say_hello(base.clone(), ClientProtocol::Connect, "boatramp").await;
    assert_eq!(
        greeting, "hello, boatramp!",
        "the generated GreeterClient.say_hello round-trips over the Connect wire"
    );

    // ---- 2. gRPC-web wire: the client frames the request + parses data+trailers ----------------
    let greeting = say_hello(base.clone(), ClientProtocol::GrpcWeb, "grpcweb").await;
    assert_eq!(
        greeting, "hello, grpcweb!",
        "the generated GreeterClient.say_hello round-trips over the gRPC-web wire"
    );

    // The marker the CI gate greps — reached only after BOTH wires round-tripped through the
    // generated client + the client shim + the shared frame codec against the live serving path.
    println!("CONNECT CLIENT UNARY LIVE OK");
}
