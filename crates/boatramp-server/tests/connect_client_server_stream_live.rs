//! Live end-to-end gate for the **Connect / gRPC-web GENERATED CLIENT, server-stream** (luigi
//! BR-REQ-1, PLAN-connect-grpc §9 / IU-5). The client-side mirror of the
//! `connect_server_stream_guest_live` serving gate: it drives the live guest-streaming serving path
//! with the GENERATED `connect.ticker.v1` client (`connect_clients::ticker::TickerClient`) over the
//! `boatramp-connect-client` shim, which returns a `ServerStream<Tick>` iterator. Proves the
//! generated client reads N framed `Tick`s and the terminal end-of-stream status for both wires,
//! against a REAL compiled guest (`connect-ticker.wasm`) over the hand-rolled HTTP/1.1 stack.
//!
//! Two wires, both via the one generated `subscribe` call:
//!   1. **Connect streaming** (`application/connect+proto`, the client default): N data frames +
//!      an in-body Connect EndStream (ok).
//!   2. **gRPC-web** (`application/grpc-web+proto`): N data frames + a `grpc-status: 0` trailers
//!      frame — the client half of the never-compress-framed-bodies residual.
//!
//! `#[ignore]`d (timing-sensitive loopback sockets) and run with `--include-ignored` in the
//! `live gate (connect-client)` CI job; the gate greps the `CONNECT CLIENT SERVER-STREAM LIVE OK`
//! marker + the pass count. The fixture is `include_bytes!`-embedded, so it runs on musl with no
//! wasm toolchain.
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
use connect_clients::ticker::{SubscribeRequest, Tick, TickerClient};
use futures::StreamExt;
use tokio::net::TcpListener;

const CONNECT_TICKER: &[u8] = include_bytes!("fixtures/connect-ticker.wasm");

const SITE: &str = "tickersite";
const RPC_PATH: &str = "/connect.ticker.v1.Ticker/Subscribe";
/// How many ticks the request asks for (`SubscribeRequest { uint32 count = 1 }`).
const WANT_TICKS: u32 = 4;

/// Build the live app: a real engine + runtime serving the compiled `connect-ticker` component on
/// the STREAMING lane, handlers-enabled, compression ON.
async fn live_app() -> axum::Router {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-connect-client-ss-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(CONNECT_TICKER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(CONNECT_TICKER)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "connect/ticker.wasm".to_string(),
        FileEntry {
            hash,
            size: CONNECT_TICKER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let config = DeployConfig {
        handlers: vec![HandlerConfig {
            route: RPC_PATH.to_string(),
            methods: vec!["POST".to_string()],
            component: "connect/ticker.wasm".to_string(),
            imports: vec![],
            streaming: true,
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

/// Drive the generated `TickerClient.subscribe` off the async runtime and drain the stream, asserting
/// `WANT_TICKS` ticks with `seq` 1..=WANT_TICKS and a clean (ok) terminal status.
async fn subscribe_and_assert(base_url: String, protocol: ClientProtocol) {
    tokio::task::spawn_blocking(move || {
        let transport = PlaintextHttpTransport::with_read_timeout(Duration::from_secs(15));
        let endpoint = Endpoint::new(base_url).with_protocol(protocol);
        let stream = TickerClient::subscribe(
            &transport,
            &endpoint,
            SubscribeRequest { count: WANT_TICKS },
        )
        .expect("open server-stream");
        let (ticks, status): (Vec<Tick>, _) = stream.collect_all().expect("drain server-stream");
        assert_eq!(
            ticks.len() as u32,
            WANT_TICKS,
            "the generated client yields {WANT_TICKS} Ticks; got {}",
            ticks.len()
        );
        for (i, tick) in ticks.iter().enumerate() {
            assert_eq!(
                tick.seq,
                (i as i64) + 1,
                "Tick {i} decodes to seq {}",
                i + 1
            );
        }
        assert!(
            status.is_ok(),
            "the stream ends with an ok terminal status; got {status}"
        );
    })
    .await
    .expect("spawn_blocking join")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live: drives a GENERATED Connect server-stream client against a real guest over the \
            hand-rolled HTTP stack on a loopback socket; run via --include-ignored in the \
            `live gate (connect-client)` job"]
async fn connect_generated_client_server_stream_round_trips() {
    let app = live_app().await;
    let addr = spawn_server(app).await;
    let base = format!("http://{addr}/_sites/{SITE}");

    // ---- 1. Connect streaming wire (the client default) ---------------------------------------
    subscribe_and_assert(base.clone(), ClientProtocol::Connect).await;

    // ---- 2. gRPC-web wire ----------------------------------------------------------------------
    subscribe_and_assert(base.clone(), ClientProtocol::GrpcWeb).await;

    // The marker the CI gate greps — reached only after BOTH wires streamed N Ticks + a clean
    // terminal status through the generated client + the client shim against the live serving path.
    println!("CONNECT CLIENT SERVER-STREAM LIVE OK");
}
