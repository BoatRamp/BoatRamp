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
        let (handle, addr) = bind_and_serve(
            runtime,
            deploy,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
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
        assert_eq!(
            n, 0,
            "the peer socket must be closed (EOF) after idle teardown"
        );
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
        let (res, elapsed) =
            await_dispatch(handle, Duration::from_secs(10), "spin max-duration").await;
        assert!(
            res.is_ok(),
            "spin max-duration teardown should end cleanly: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "spin teardown took {elapsed:?} — the epoch-yield must let the watchdog preempt a \
             non-yielding guest well under the outer timeout (near max_conn_duration=1s)"
        );
    }

    // ---- d. PEER-DROP mid-stream -----------------------------------------------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 4).await;
        let (handle, addr) = bind_and_serve(
            runtime,
            deploy,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
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
        assert!(
            res.is_ok(),
            "peer-drop should clean up without error: {res:?}"
        );
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

/// cap-req 06: a self-signed cert → an `Arc<ServerConfig>` for the listener + a `TlsConnector`
/// that trusts it (the test client). The private key lives only in the server config.
fn tls_fixtures() -> (Arc<rustls::ServerConfig>, tokio_rustls::TlsConnector) {
    // Match production's process-default provider (serve.rs `install_crypto_provider`); idempotent.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        Arc::new(server_cfg),
        tokio_rustls::TlsConnector::from(Arc::new(client_cfg)),
    )
}

/// Like [`bind_and_serve`] but the host TERMINATES TLS before the guest sees bytes — the exact
/// accept→handshake→split→dispatch path `run_listener` takes for a `tls` listener (cap-req 06).
async fn bind_and_serve_tls(
    runtime: HandlerRuntime,
    deploy: DeployStore,
    server_cfg: Arc<rustls::ServerConfig>,
    idle: Duration,
    max_dur: Duration,
) -> (JoinHandle<Result<(), String>>, std::net::SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let _ = stream.set_nodelay(true);
        // Host-side TLS termination: a failed handshake returns Err (NO plaintext fallthrough).
        let tls = acceptor
            .accept(stream)
            .await
            .map_err(|e| format!("inbound-TLS handshake failed: {e}"))?;
        let (read_half, write_half) = tokio::io::split(tls);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_listener_tls_live_terminates_and_refuses_plaintext() {
    // (a) IMPLICIT-TLS echo: the host terminates TLS; the guest echoes the DECRYPTED plaintext.
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 10).await;
        let (server_cfg, connector) = tls_fixtures();
        let (handle, addr) = bind_and_serve_tls(
            runtime,
            deploy,
            server_cfg,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector
            .connect(domain, tcp)
            .await
            .expect("client TLS handshake");
        let payload = b"hello over TLS";
        tls.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut got))
            .await
            .expect("tls echo read timed out")
            .expect("tls echo read failed");
        assert_eq!(
            &got, payload,
            "the guest echoes the decrypted plaintext — the host terminated TLS"
        );
        tls.shutdown().await.ok();
        let (res, _) = await_dispatch(handle, Duration::from_secs(5), "tls-echo").await;
        assert!(res.is_ok(), "tls echo dispatch ends cleanly: {res:?}");
    }
    // (b) A PLAINTEXT client to a TLS listener is REFUSED: the handshake fails, the guest is NEVER
    //     dispatched, and no bytes are echoed back (no plaintext fallthrough).
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 11).await;
        let (server_cfg, _connector) = tls_fixtures();
        let (handle, addr) = bind_and_serve_tls(
            runtime,
            deploy,
            server_cfg,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let mut raw = TcpStream::connect(addr).await.unwrap();
        raw.write_all(b"not tls, just plaintext bytes").await.ok();
        let (res, _) = await_dispatch(handle, Duration::from_secs(5), "tls-refuse").await;
        assert!(
            res.is_err(),
            "a plaintext client to a TLS listener must be refused (no fallthrough): {res:?}"
        );
        // The client may receive a TLS alert (rustls rejecting the non-TLS ClientHello) or EOF —
        // but NEVER an echo of its plaintext (the guest never ran, so it can't have echoed).
        let mut buf = [0u8; 8];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), raw.read(&mut buf)).await {
            assert_ne!(
                &buf[..n.min(8)],
                &b"not tls,"[..n.min(8)],
                "the plaintext was NOT echoed — the connection is refused, not served"
            );
        }
    }
    println!(
        "TCP-LISTENER-TLS LIVE OK: host-TLS termination (implicit) + plaintext-client refusal"
    );
}

/// Like [`bind_and_serve_tls`] but STARTTLS (cap-req 06, Stage B): the EXACT accept-arm path for a
/// `tls.starttls` listener — spawn the real [`boatramp_server::tcp_starttls`] pump on the raw socket
/// (it interposes the plaintext dialog + upgrades in-band on the declared trigger) and dispatch the
/// guest on the resulting duplex halves. No reimplementation: the live gate drives the production pump.
async fn bind_and_serve_starttls(
    runtime: HandlerRuntime,
    deploy: DeployStore,
    server_cfg: Arc<rustls::ServerConfig>,
    grammar: boatramp_server::tcp_starttls::StarttlsGrammar,
    idle: Duration,
    max_dur: Duration,
) -> (JoinHandle<Result<(), String>>, std::net::SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let _ = stream.set_nodelay(true);
        let (g_read, g_write, pump) =
            boatramp_server::tcp_starttls::spawn_pump(stream, acceptor, grammar);
        let res = runtime
            .dispatch_tcp_connection(
                &deploy,
                ProjectRef::DEFAULT.as_str(),
                SITE,
                COMPONENT,
                &FunctionConfig::default(),
                peer.to_string(),
                g_read,
                g_write,
                idle,
                max_dur,
            )
            .await;
        pump.abort(); // guest returned ⇒ tear the pump + socket down (no-op if it already ended)
        res
    });
    (handle, addr)
}

fn grammar(
    trigger: &str,
    response: &str,
    tag_capture: bool,
) -> boatramp_server::tcp_starttls::StarttlsGrammar {
    boatramp_server::tcp_starttls::StarttlsGrammar {
        trigger: trigger.to_string(),
        response: response.to_string(),
        tag_capture,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_listener_starttls_live_upgrades_and_refuses_injection() {
    use rustls::pki_types::ServerName;

    // ---- (a) SMTP-shaped full upgrade + pre-upgrade plaintext proof ------------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 20).await;
        let (server_cfg, connector) = tls_fixtures();
        let (handle, addr) = bind_and_serve_starttls(
            runtime,
            deploy,
            server_cfg,
            grammar("STARTTLS", "220 2.0.0 Ready to start TLS", false),
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);

        // A non-trigger line is forwarded to the guest and echoed back over CLEARTEXT (proves the
        // pre-upgrade dialog is genuine plaintext).
        let hello = b"EHLO test\r\n";
        client.write_all(hello).await.unwrap();
        let mut echoed = vec![0u8; hello.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
            .await
            .expect("pre-upgrade plaintext echo timed out")
            .expect("pre-upgrade plaintext echo failed");
        assert_eq!(&echoed, hello, "the pre-upgrade dialog is plaintext");

        // The trigger line: the host injects the declared response (NOT an echo — the guest never
        // sees STARTTLS).
        client.write_all(b"STARTTLS\r\n").await.unwrap();
        let resp_expected = b"220 2.0.0 Ready to start TLS\r\n";
        let mut resp = vec![0u8; resp_expected.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut resp))
            .await
            .expect("STARTTLS response timed out")
            .expect("STARTTLS response read failed");
        assert_eq!(
            &resp, resp_expected,
            "the host injected the declared response; the guest never handled STARTTLS"
        );

        // Upgrade: the TLS handshake runs on the SAME socket the host now wraps.
        let domain = ServerName::try_from("localhost").unwrap();
        let mut tls = connector
            .connect(domain, client)
            .await
            .expect("STARTTLS client handshake");

        // The guest now serves over the decrypted stream — echo the post-TLS bytes.
        let post = b"hello post-tls";
        tls.write_all(post).await.unwrap();
        let mut got = vec![0u8; post.len()];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut got))
            .await
            .expect("post-TLS echo timed out")
            .expect("post-TLS echo failed");
        assert_eq!(&got, post, "the guest serves over the upgraded TLS stream");
        tls.shutdown().await.ok();
        let (res, _) = await_dispatch(handle, Duration::from_secs(5), "starttls-smtp").await;
        assert!(res.is_ok(), "SMTP STARTTLS dispatch ends cleanly: {res:?}");
    }

    // ---- (a′) IMAP tag-capture upgrade — SAME engine, DIFFERENT config ---------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 21).await;
        let (server_cfg, connector) = tls_fixtures();
        let (handle, addr) = bind_and_serve_starttls(
            runtime,
            deploy,
            server_cfg,
            grammar("STARTTLS", "{tag} OK begin TLS", true),
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);

        let cap = b"a1 CAPABILITY\r\n";
        client.write_all(cap).await.unwrap();
        let mut echoed = vec![0u8; cap.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
            .await
            .expect("imap pre-upgrade echo timed out")
            .expect("imap pre-upgrade echo failed");
        assert_eq!(&echoed, cap);

        client.write_all(b"a2 STARTTLS\r\n").await.unwrap();
        let resp_expected = b"a2 OK begin TLS\r\n"; // {tag} -> a2 (verbatim)
        let mut resp = vec![0u8; resp_expected.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut resp))
            .await
            .expect("imap STARTTLS response timed out")
            .expect("imap STARTTLS response read failed");
        assert_eq!(
            &resp, resp_expected,
            "the captured tag is echoed verbatim into the response — one generic engine, two configs"
        );

        let domain = ServerName::try_from("localhost").unwrap();
        let mut tls = connector
            .connect(domain, client)
            .await
            .expect("imap STARTTLS client handshake");
        let post = b"done";
        tls.write_all(post).await.unwrap();
        let mut got = vec![0u8; post.len()];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut got))
            .await
            .expect("imap post-TLS echo timed out")
            .expect("imap post-TLS echo failed");
        assert_eq!(&got, post);
        tls.shutdown().await.ok();
        let (res, _) = await_dispatch(handle, Duration::from_secs(5), "starttls-imap").await;
        assert!(res.is_ok(), "IMAP STARTTLS dispatch ends cleanly: {res:?}");
    }

    // ---- (c) Injection safety (RFC 3207 §4 / CVE-2011-0411 class) ---------------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 22).await;
        let (server_cfg, _connector) = tls_fixtures();
        let (handle, addr) = bind_and_serve_starttls(
            runtime,
            deploy,
            server_cfg,
            grammar("STARTTLS", "220 Ready", false),
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);

        // Pipeline the trigger AND an injected command in ONE segment. A vulnerable server would
        // buffer the post-trigger bytes and replay them as a post-TLS command.
        client
            .write_all(b"STARTTLS\r\nINJECTED-CMD please-run\r\n")
            .await
            .unwrap();

        // The host-injected response arrives first (written before the handshake begins).
        let resp_expected = b"220 Ready\r\n";
        let mut resp = vec![0u8; resp_expected.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut resp))
            .await
            .expect("injection-case response timed out")
            .expect("injection-case response read failed");
        assert_eq!(&resp, resp_expected);

        // The host then feeds the socket (now holding `INJECTED-CMD…`) to the TLS layer, which reads
        // it as a malformed ClientHello and fails the handshake. Whatever the client reads next is a
        // TLS alert or EOF — and must NEVER contain the injected bytes (the guest never saw them;
        // there is no post-TLS channel in which they could run).
        let mut total = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break, // EOF or quiet
                Ok(Ok(n)) => total.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break, // reset
            }
            if total.len() > 4096 {
                break;
            }
        }
        assert!(
            !total.windows(b"INJECTED".len()).any(|w| w == b"INJECTED"),
            "a byte pipelined after the trigger must NEVER cross the TLS boundary or be echoed/run"
        );

        // The failed handshake drops the pump → closes the duplex → the guest reads EOF → ends cleanly.
        let (res, _) = await_dispatch(handle, Duration::from_secs(5), "starttls-injection").await;
        assert!(
            res.is_ok(),
            "guest ends cleanly on EOF after a refused upgrade: {res:?}"
        );
    }

    // ---- (d) Connect, speak, but never send the trigger ⇒ idle teardown --------------------------
    {
        let (runtime, deploy) = live_runtime(TCP_ECHO, 23).await;
        let (server_cfg, _connector) = tls_fixtures();
        let (handle, addr) = bind_and_serve_starttls(
            runtime,
            deploy,
            server_cfg,
            grammar("STARTTLS", "220 ok", false),
            Duration::from_millis(500),
            Duration::from_secs(30),
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        // Speak one non-trigger line (echoed), then go silent — never send STARTTLS.
        let line = b"EHLO x\r\n";
        client.write_all(line).await.unwrap();
        let mut echoed = vec![0u8; line.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
            .await
            .expect("pre-trigger echo timed out")
            .expect("pre-trigger echo failed");
        assert_eq!(&echoed, line);
        // Silent now. The conn-lane idle watchdog (on the duplex) must tear the connection down.
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(5), "starttls-idle").await;
        assert!(
            res.is_ok(),
            "idle teardown of a pre-trigger connection: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "idle teardown took {elapsed:?} — the watchdog must bound a STARTTLS connection stuck \
             before the trigger"
        );
    }

    println!(
        "TCP-LISTENER-STARTTLS LIVE OK: smtp upgrade, imap tag-capture upgrade, pre-upgrade \
         plaintext, injection refused, pre-trigger idle teardown — all held end to end."
    );
}
