//! Live capability gate for host-owned **inbound-TCP listeners** (`boatramp:handlers/tcp-connection-host`,
//! PLAN-handler-tcp-inbound). Unlike the per-predicate unit gates (which use a pending future, not a
//! real non-yielding fiber), this drives the REAL prod per-connection path —
//! [`HandlerRuntime::dispatch_tcp_connection`] over a REAL loopback `TcpListener` accept, splitting the
//! accepted socket into the `wasi:io` streams handed to a REAL compiled guest component — over an
//! in-memory control plane, and asserts the four properties the primitive promises, each within a
//! bounded wall-clock so a regression turns the test RED rather than hanging CI:
//!
//!   a. **ECHO round-trip**: `tcp-echo.wasm` reads the connection and echoes every byte back; the
//!      client gets the identical bytes, then a clean EOF ends the guest.
//!   b. **IDLE-timeout teardown**: a quiet connection is torn down at ~`idle_timeout` and the socket
//!      closes (the guest is blocked in a suspending `blocking-read`; the host watchdog preempts it).
//!   c. **MAX-DURATION teardown of the SPIN guest (THE HIGH-FIX PROOF)**: `tcp-spin.wasm` busy-loops
//!      forever with NO suspending host call; it is torn down at ~`max_conn_duration`. This can ONLY
//!      happen because the conn-lane epoch arms `epoch_deadline_async_yield_and_update` (yield, not
//!      trap), so the non-yielding fiber periodically returns `Poll::Pending` and the host wall-clock
//!      watchdog in the dispatch `select!` gets re-polled and drops the call. Without that fix this
//!      scenario HANGS (the fiber pins its worker and the watchdog never runs) — so the bounded
//!      assertion here is a genuine regression test for the HIGH finding.
//!   d. **PEER-DROP mid-stream**: the client drops after a partial write; the guest's input stream
//!      surfaces the drop (EOF) and the connection is cleaned up — no leak, no hang.
//!
//! NOT `#[ignore]`d — it is a CI gate (wired into `.github/workflows/ci.yml`, grepping the success
//! marker `TCP-LISTENER LIVE OK` + the pass count, so a silent skip fails the job). Uses SHORT
//! timeouts so it runs in a couple of seconds.

#![cfg(feature = "tcp-listener")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boatramp_core::ByteStream;
use boatramp_core::config::{DeployConfig, HandlersSiteConfig, SiteConfig};
use boatramp_core::deploy::{DeployStore, FileEntry, Manifest, sha256_hex};
use boatramp_core::function::FunctionConfig;
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_server::HandlerRuntime;
use boatramp_storage::FsStorage;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const TCP_ECHO: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/tcp-echo.wasm");
const TCP_SPIN: &[u8] = include_bytes!("../../boatramp-handlers/tests/fixtures/tcp-spin.wasm");

const SITE: &str = "edgesite";
const COMPONENT: &str = "tcp/handler.wasm";

/// Build a real `HandlerRuntime` (tcp-listener posture ON) + `DeployStore` whose active DEFAULT/SITE
/// deployment CONTAINS `component_wasm` at [`COMPONENT`]. A listener is NODE-level config (not a
/// route), so the deployment only needs to hold the component file — `dispatch_tcp_connection`
/// resolves it by (project, site, component path). `seq` keeps the temp blob dir unique per scenario.
async fn live_runtime(component_wasm: &'static [u8], seq: u32) -> (HandlerRuntime, DeployStore) {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-tcp-live-{}-{seq}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(component_wasm);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(component_wasm)) }).boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        COMPONENT.to_string(),
        FileEntry {
            hash,
            size: component_wasm.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );
    let manifest = Manifest {
        files,
        config: DeployConfig::default(),
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
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Posture ON (`with_tcp_listener(true)`) — the dispatch gate's posture arm; the operator-declared
    // arm is satisfied by this being a resolved listener dispatch (we only dispatch declared listeners).
    let engine = HandlerEngine::new(Limits::default(), 16)
        .unwrap()
        .with_tcp_listener(true);
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    (runtime, deploy)
}

/// Bind a loopback `TcpListener`, then spawn the REAL accept→dispatch step (exactly what the
/// `tcp_listener_serve` accept loop does per connection): accept one connection, `set_nodelay`, split
/// it, and drive `HandlerRuntime::dispatch_tcp_connection` with the given idle/max-duration. Returns
/// the dispatch `JoinHandle` (its `Result<(), String>` is the dispatch outcome) and the bound addr.
async fn bind_and_serve(
    runtime: HandlerRuntime,
    deploy: DeployStore,
    idle: Duration,
    max_dur: Duration,
) -> (JoinHandle<Result<(), String>>, std::net::SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let _ = stream.set_nodelay(true);
        let (read_half, write_half) = stream.into_split();
        runtime
            .dispatch_tcp_connection(
                &deploy,
                ProjectRef::DEFAULT.as_str(),
                SITE,
                COMPONENT,
                &FunctionConfig::default(),
                peer.to_string(),
                read_half,
                write_half,
                idle,
                max_dur,
            )
            .await
    });
    (handle, addr)
}

/// Await a dispatch `JoinHandle` with a hard outer timeout, returning the elapsed wall-clock. Panics
/// (RED) if the outer timeout fires — a regression that hangs the connection fails here, not by
/// hanging CI forever.
async fn await_dispatch(
    handle: JoinHandle<Result<(), String>>,
    hard_timeout: Duration,
    what: &str,
) -> (Result<(), String>, Duration) {
    let t0 = Instant::now();
    let outcome = tokio::time::timeout(hard_timeout, handle).await;
    let elapsed = t0.elapsed();
    match outcome {
        Ok(join) => (join.expect("dispatch task panicked"), elapsed),
        Err(_) => panic!(
            "{what}: dispatch did NOT complete within {hard_timeout:?} (a hang — regression in the \
             conn-lane teardown / epoch-yield)"
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_listener_live_echo_idle_spin_peerdrop() {
    // ---- a. ECHO round-trip ----------------------------------------------------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 1).await;
        let (handle, addr) =
            bind_and_serve(runtime, deploy, Duration::from_secs(5), Duration::from_secs(30)).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        let payload = b"hello, tcp world";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
            .await
            .expect("echo read timed out")
            .expect("echo read failed");
        assert_eq!(&got, payload, "echo must return the identical bytes");
        // Clean close: shut the client's write half → the guest reads EOF → returns Ok.
        client.shutdown().await.unwrap();
        let (res, _) = await_dispatch(handle, Duration::from_secs(5), "echo").await;
        assert!(res.is_ok(), "echo dispatch should end cleanly: {res:?}");
    }

    // ---- b. IDLE-timeout teardown ----------------------------------------------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 2).await;
        // Short idle (500ms); long max so idle is unambiguously the cause.
        let (handle, addr) = bind_and_serve(
            runtime,
            deploy,
            Duration::from_millis(500),
            Duration::from_secs(30),
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        // Stay quiet — no bytes in either direction. The host watchdog must tear the connection down.
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(5), "idle").await;
        assert!(res.is_ok(), "idle teardown should end cleanly: {res:?}");
        assert!(
            elapsed < Duration::from_secs(4),
            "idle teardown took too long ({elapsed:?}) — watchdog not firing near idle_timeout"
        );
        // The teardown dropped the store → the write half closed → the client observes EOF.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("client read after idle teardown timed out")
            .expect("client read after idle teardown errored");
        assert_eq!(n, 0, "the peer socket must be closed (EOF) after idle teardown");
    }

    // ---- c. MAX-DURATION teardown of the SPIN guest (THE HIGH-FIX PROOF) --------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_SPIN, 3).await;
        // Long idle (won't fire); short max-duration (1s). The spin guest never yields on its own —
        // only the conn-lane epoch-yield lets the watchdog preempt it at ~max_conn_duration.
        let (handle, addr) = bind_and_serve(
            runtime,
            deploy,
            Duration::from_secs(30),
            Duration::from_secs(1),
        )
        .await;
        let _client = TcpStream::connect(addr).await.unwrap();
        // Hard 10s outer timeout: WITHOUT the epoch-yield fix the dispatch hangs (the fiber pins a
        // worker, the watchdog can't be re-polled) and this panics RED. WITH the fix it returns at ~1s.
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(10), "spin max-duration").await;
        assert!(res.is_ok(), "spin max-duration teardown should end cleanly: {res:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "spin teardown took {elapsed:?} — the epoch-yield must let the watchdog preempt a \
             non-yielding guest well under the outer timeout (near max_conn_duration=1s)"
        );
    }

    // ---- d. PEER-DROP mid-stream -----------------------------------------------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 4).await;
        let (handle, addr) =
            bind_and_serve(runtime, deploy, Duration::from_secs(5), Duration::from_secs(30)).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        // Partial write + read it back (confirming the guest is engaged), then DROP the client.
        let partial = b"partial";
        client.write_all(partial).await.unwrap();
        let mut got = vec![0u8; partial.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
            .await
            .expect("peer-drop echo read timed out")
            .expect("peer-drop echo read failed");
        assert_eq!(&got, partial);
        drop(client); // abrupt peer drop mid-stream
        // The guest's input stream must surface the drop (EOF) and the connection clean up — bounded.
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(5), "peer-drop").await;
        assert!(res.is_ok(), "peer-drop should clean up without error: {res:?}");
        assert!(
            elapsed < Duration::from_secs(4),
            "peer-drop cleanup took too long ({elapsed:?}) — the drop didn't surface to the guest"
        );
    }

    // The single success marker the CI gate greps for — printed ONLY after all four scenarios held
    // against the real compiled guests + the real dispatch path.
    println!(
        "TCP-LISTENER LIVE OK: echo round-trip, idle teardown, spin max-duration preemption (HIGH \
         proof), and peer-drop cleanup all held end to end over real loopback sockets."
    );
}
