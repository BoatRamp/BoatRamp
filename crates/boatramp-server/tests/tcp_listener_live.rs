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
/// A `session-handler` guest (cap-req 08): on each inbound frame it checkpoints a running count and
/// sends `echo#<count>:<frame>` — so re-entry #2 resuming `#2` proves the host-held checkpoint
/// survived the instance drop between frames.
#[cfg(feature = "session")]
const SESSION_ECHO: &[u8] =
    include_bytes!("../../boatramp-handlers/tests/fixtures/session-echo.wasm");
/// A SERVER-SPEAKS-FIRST `session-handler` guest (mailroom cap-req 17): greets ("* OK session-greet
/// ready\r\n") on the first re-entry that has not yet checkpointed a `greeted` flag — including a
/// re-entry carrying NO frames, i.e. the host's connect-time dispatch. Echoes any later frame back
/// prefixed `GOT:`, and closes on a `cancel` frame. See `examples/handlers/session-greet`.
#[cfg(feature = "session")]
const SESSION_GREET: &[u8] =
    include_bytes!("../../boatramp-handlers/tests/fixtures/session-greet.wasm");
/// A `session-handler` guest (mailroom cap-req #22 — session→connection escalation): greets, then on
/// a `BRIDGE <host> <port>` frame calls `session::promote-connection` to escalate the connection to a
/// persistent duplex splice to the named upstream (host-dialed through the reused egress gate); on a
/// refused promote it replies `REFUSED` and stays in the session model. See
/// `examples/handlers/session-imap-bridge`.
#[cfg(all(feature = "session", feature = "tcp-egress"))]
const SESSION_IMAP_BRIDGE: &[u8] =
    include_bytes!("../../boatramp-handlers/tests/fixtures/session-imap-bridge.wasm");

const SITE: &str = "edgesite";
const COMPONENT: &str = "tcp/handler.wasm";

/// Build a real `HandlerRuntime` (tcp-listener posture ON) + `DeployStore` whose active DEFAULT/SITE
/// deployment CONTAINS `component_wasm` at [`COMPONENT`]. A listener is NODE-level config (not a
/// route), so the deployment only needs to hold the component file — `dispatch_tcp_connection`
/// resolves it by (project, site, component path). `seq` keeps the temp blob dir unique per scenario.
async fn live_runtime(component_wasm: &'static [u8], seq: u32) -> (HandlerRuntime, DeployStore) {
    live_runtime_with_posture(component_wasm, seq, true).await
}

/// Like [`live_runtime`] but with the `allow_guest_tcp_listener` posture explicitly set — so a test
/// can prove the engine-level dispatch gate refuses when the posture is OFF (cap-req 08 MEDIUM-1 /
/// the shared mutation-verified `tcp_listener_dispatch_decision`).
async fn live_runtime_with_posture(
    component_wasm: &'static [u8],
    seq: u32,
    allow_tcp_listener: bool,
) -> (HandlerRuntime, DeployStore) {
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
        .with_tcp_listener(allow_tcp_listener);
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
                boatramp_handlers::ConnectionSecurity::plaintext(),
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
        let (res, _) = await_dispatch(handle, Duration::from_secs(20), "echo").await;
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
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(20), "idle").await;
        assert!(res.is_ok(), "idle teardown should end cleanly: {res:?}");
        assert!(
            elapsed < Duration::from_secs(12),
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
            await_dispatch(handle, Duration::from_secs(20), "spin max-duration").await;
        assert!(
            res.is_ok(),
            "spin max-duration teardown should end cleanly: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(12),
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
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(20), "peer-drop").await;
        assert!(
            res.is_ok(),
            "peer-drop should clean up without error: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(12),
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
                boatramp_handlers::ConnectionSecurity::tls(),
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
        let (res, _) = await_dispatch(handle, Duration::from_secs(20), "tls-echo").await;
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
        let (res, _) = await_dispatch(handle, Duration::from_secs(20), "tls-refuse").await;
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
        // Same wiring as the production accept arm (mailroom cap-req #16): one `starttls-pending`
        // handle shared between the pump (which flips it to TLS on the in-band upgrade) and the guest
        // dispatch (which exposes it via `tcp-connection-context`).
        let conn_security = boatramp_handlers::ConnectionSecurity::starttls_pending();
        let (g_read, g_write, pump) = boatramp_server::tcp_starttls::spawn_pump(
            stream,
            acceptor,
            grammar,
            conn_security.clone(),
        );
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
                conn_security,
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
        let (res, _) = await_dispatch(handle, Duration::from_secs(20), "starttls-smtp").await;
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
        let (res, _) = await_dispatch(handle, Duration::from_secs(20), "starttls-imap").await;
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
        let (res, _) = await_dispatch(handle, Duration::from_secs(20), "starttls-injection").await;
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
        let (res, elapsed) = await_dispatch(handle, Duration::from_secs(20), "starttls-idle").await;
        assert!(
            res.is_ok(),
            "idle teardown of a pre-trigger connection: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(12),
            "idle teardown took {elapsed:?} — the watchdog must bound a STARTTLS connection stuck \
             before the trigger"
        );
    }

    println!(
        "TCP-LISTENER-STARTTLS LIVE OK: smtp upgrade, imap tag-capture upgrade, pre-upgrade \
         plaintext, injection refused, pre-trigger idle teardown — all held end to end."
    );
}

/// Like [`bind_and_serve`] but SESSION mode (cap-req 08): the host drives the accepted connection
/// through [`HandlerRuntime::dispatch_session_connection`] (the re-entrant session model) instead of
/// the long-lived `tcp-connection-handler`. No `idle_timeout` — a session connection is parked, not
/// evicted, when quiet; only `max_dur` (and dead-peer EOF) ends it.
#[cfg(feature = "session")]
async fn bind_and_serve_session(
    runtime: HandlerRuntime,
    deploy: DeployStore,
    reentry_timeout: Duration,
    max_dur: Duration,
) -> (JoinHandle<Result<(), String>>, std::net::SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let _ = stream.set_nodelay(true);
        let (read_half, write_half) = stream.into_split();
        runtime
            .dispatch_session_connection(
                &deploy,
                ProjectRef::DEFAULT.as_str(),
                SITE,
                COMPONENT,
                &FunctionConfig::default(),
                peer.to_string(),
                read_half,
                write_half,
                reentry_timeout,
                max_dur,
                boatramp_handlers::ConnectionSecurity::plaintext(),
                std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            )
            .await
    });
    (handle, addr)
}

/// cap-req 08 SESSION-OVER-LISTENER load-bearing gate. Drives a REAL `session-handler` guest over a
/// REAL loopback socket through the re-entrant session path and proves the hibernation property end to
/// end: (1) two inbound frames on ONE connection drive TWO instantiations — so the wasm instance is
/// RELEASED between frames, not pinned for the connection's life (the whole point of #08); (2) the
/// running count RESUMES across that drop (`echo#2`, not `echo#1`) — so the host-held checkpoint
/// carried the guest's state while no instance existed; (3) a quiet gap between frames does NOT tear
/// the connection down (parked, not evicted — the IMAP-IDLE property); (4) a peer EOF ends it cleanly.
#[cfg(feature = "session")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_listener_live_reentry_checkpoint_and_instance_release() {
    async fn read_exact_timed(client: &mut TcpStream, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut buf))
            .await
            .expect("session echo read timed out")
            .expect("session echo read failed");
        buf
    }

    let (runtime, deploy) = live_runtime(SESSION_ECHO, 40).await;
    let base_insts = runtime
        .instance_stats()
        .expect("engine present")
        .session
        .instantiations;
    // Generous per-re-entry deadline (the happy-path re-entries finish in ms) + a long absolute cap so
    // the quiet gap below is not what ends the connection.
    let (handle, addr) = bind_and_serve_session(
        runtime.clone(),
        deploy,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client.set_nodelay(true);

    // Frame 1: the guest echoes `echo#1:hello` and checkpoints count=1 — all within ONE re-entry,
    // after which the store (and instance) is dropped.
    client.write_all(b"hello").await.unwrap();
    let got1 = read_exact_timed(&mut client, b"echo#1:hello".len()).await;
    assert_eq!(&got1, b"echo#1:hello", "first re-entry echoes with count=1");

    // Quiet gap: the driver is now parked on the socket read holding NO instance. A quiet gap that
    // would be irrelevant to a tcp-connection (which pins an instance regardless) proves the session
    // connection stays alive while idle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Frame 2: a FRESH re-entry resumes the count from the host-held checkpoint → `echo#2:world`.
    client.write_all(b"world").await.unwrap();
    let got2 = read_exact_timed(&mut client, b"echo#2:world".len()).await;
    assert_eq!(
        &got2, b"echo#2:world",
        "count RESUMED across the instance drop — the host-held checkpoint carried the state"
    );

    // THE hibernation proof: two frames on ONE connection drove (at least) two instantiations — i.e.
    // the instance was released and re-created per frame, never pinned for the connection's life.
    let after = runtime
        .instance_stats()
        .expect("engine present")
        .session
        .instantiations;
    assert!(
        after - base_insts >= 2,
        "two frames must re-instantiate (instance RELEASED between re-entries): {base_insts} → {after}"
    );

    // Clean close: drop the client → the driver reads EOF → the connection ends cleanly (bounded).
    drop(client);
    let (res, _) = await_dispatch(handle, Duration::from_secs(20), "session-listener").await;
    assert!(
        res.is_ok(),
        "session connection ends cleanly on peer EOF: {res:?}"
    );

    // ---- MEDIUM-1: the engine-level posture gate refuses on the SESSION path too -----------------
    // With `allow_guest_tcp_listener` OFF, the re-entry's `tcp_listener_dispatch_decision` guard fails
    // closed — the guest never runs, so an inbound frame is NOT echoed (belt-and-suspenders behind the
    // bind-site posture gate, matching the connection path).
    {
        let (runtime_off, deploy_off) = live_runtime_with_posture(SESSION_ECHO, 41, false).await;
        let base_off = runtime_off
            .instance_stats()
            .expect("engine present")
            .session
            .instantiations;
        let (handle, addr) = bind_and_serve_session(
            runtime_off.clone(),
            deploy_off,
            Duration::from_secs(5),
            Duration::from_secs(30),
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        client.write_all(b"hello").await.unwrap();
        // No echo must arrive (the re-entry is refused). Reading returns EOF/err, never `echo#1:hello`.
        let mut buf = [0u8; 16];
        match tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => {} // EOF or quiet — refused, as required
            Ok(Ok(n)) => assert_ne!(
                &buf[..n.min(5)],
                b"echo#",
                "posture OFF must refuse the session re-entry — the guest must NOT have run"
            ),
            Ok(Err(_)) => {} // reset — also fine
        }
        let after_off = runtime_off
            .instance_stats()
            .expect("engine present")
            .session
            .instantiations;
        assert_eq!(
            after_off, base_off,
            "posture OFF: the session guest was NEVER instantiated (dispatch refused before the store)"
        );
        drop(client);
        let _ = await_dispatch(handle, Duration::from_secs(20), "session-posture-off").await;
    }

    println!(
        "SESSION-LISTENER LIVE OK: re-entry + checkpoint-resume across the instance drop, two frames \
         drove two instantiations (no pinned instance), survived an idle gap, clean EOF teardown, \
         and posture-OFF refuses the re-entry (guest never instantiated)."
    );
}

/// cap-req 17 LIVE gate: the host's CONNECT-TIME dispatch (an empty `frames: []` batch invoked once,
/// BEFORE the first inbound read) lets a server-speaks-first guest `send` its greeting without
/// waiting for the client to write anything first — the INVERSE of
/// [`session_listener_live_reentry_checkpoint_and_instance_release`] (which writes `"hello"` before
/// its first read). Drives a REAL `session-greet` guest over a REAL loopback socket: the client
/// reads the greeting FIRST (no prior write — this is the whole point: a greeting-first client like
/// Thunderbird/Apple Mail/Python `imaplib` would otherwise deadlock), then writes one frame and reads
/// the ordinary echoed reply — proving the connection falls straight through to the normal read loop
/// afterwards (no hang, no added latency beyond the one connect-time guest invocation).
#[cfg(feature = "session")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_listener_live_connect_greeting_before_client_speaks() {
    const GREETING: &[u8] = b"* OK session-greet ready\r\n";

    let (runtime, deploy) = live_runtime(SESSION_GREET, 42).await;
    let base_insts = runtime
        .instance_stats()
        .expect("engine present")
        .session
        .instantiations;
    let (handle, addr) = bind_and_serve_session(
        runtime.clone(),
        deploy,
        Duration::from_secs(5),
        Duration::from_secs(30),
    )
    .await;

    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client.set_nodelay(true);

    // THE proof: read the greeting WITHOUT writing anything first. Pre-cap-req-17, the guest's
    // first re-entry happens only after the client writes ≥1 byte, so this read would hang forever
    // against the old shape — bounded here so a regression turns the test RED, not a CI hang.
    let mut got = vec![0u8; GREETING.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
        .await
        .expect(
            "connect-time greeting read timed out — the guest never greeted before the client wrote",
        )
        .expect("connect-time greeting read failed");
    assert_eq!(
        &got, GREETING,
        "the guest must greet on the EMPTY connect-time batch, before any client byte"
    );

    // The connect dispatch alone must have instantiated the guest (the hibernation property holds
    // for it too: no instance is held between the connect dispatch and the next re-entry).
    let after_connect = runtime
        .instance_stats()
        .expect("engine present")
        .session
        .instantiations;
    assert!(
        after_connect - base_insts >= 1,
        "the connect-time dispatch must instantiate the guest: {base_insts} → {after_connect}"
    );

    // Normal operation continues straight afterwards: one real frame gets the ordinary echoed
    // reply — no hang, no extra latency; the driver fell through to the read loop as required.
    client.write_all(b"hi").await.unwrap();
    let mut got2 = vec![0u8; b"GOT:hi".len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got2))
        .await
        .expect("post-greeting echo read timed out")
        .expect("post-greeting echo read failed");
    assert_eq!(
        &got2, b"GOT:hi",
        "the connection must fall through to the ordinary read loop after the connect dispatch"
    );

    // Clean close: drop the client → the driver reads EOF → the connection ends cleanly (bounded).
    drop(client);
    let (res, _) =
        await_dispatch(handle, Duration::from_secs(20), "session-connect-greeting").await;
    assert!(
        res.is_ok(),
        "session connection ends cleanly on peer EOF: {res:?}"
    );

    println!(
        "SESSION CONNECT GREETING OK: a server-speaks-first guest greeted at connect — BEFORE the \
         client wrote anything — then normal re-entry continued unaffected (one frame echoed), and \
         the connection tore down cleanly on EOF."
    );
}

// ===================== cap-req 22: session→connection escalation (promote) =========================

/// Like [`live_runtime`] but with host-mediated `tcp-egress` + private-egress ON (the fake upstreams
/// are on loopback, which the SSRF floor would otherwise refuse) and a controllable `max_concurrency`
/// so the lane-isolation scenario can size the session-socket re-entry pool down to 1.
#[cfg(all(feature = "session", feature = "tcp-egress"))]
async fn live_runtime_egress(
    component_wasm: &'static [u8],
    seq: u32,
    max_concurrency: usize,
) -> (HandlerRuntime, DeployStore) {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-tcp-promote-{}-{seq}", std::process::id()));
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

    let engine = HandlerEngine::new(
        Limits {
            max_concurrency,
            ..Limits::default()
        },
        16,
    )
    .unwrap()
    .with_tcp_listener(true)
    .with_tcp_egress(true)
    .with_private_egress(true)
    .with_tcp_egress_timeouts(Duration::from_secs(2), Duration::from_secs(10));
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    (runtime, deploy)
}

/// Drive ONE accepted session connection through `dispatch_session_connection` with a given set of
/// granted `imports` + `egress_allowlist` (the promote authorization — a `promote-connection` requires
/// BOTH the `wasi:sockets` grant in `imports` AND the target in the allowlist, Security review
/// MEDIUM-1). Returns the dispatch handle + the listener addr.
#[cfg(all(feature = "session", feature = "tcp-egress"))]
async fn bind_and_serve_session_egress(
    runtime: HandlerRuntime,
    deploy: DeployStore,
    max_dur: Duration,
    imports: Vec<String>,
    egress_allowlist: Vec<String>,
) -> (JoinHandle<Result<(), String>>, std::net::SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let _ = stream.set_nodelay(true);
        let (read_half, write_half) = stream.into_split();
        let fn_config = FunctionConfig {
            imports,
            egress_allowlist,
            ..FunctionConfig::default()
        };
        runtime
            .dispatch_session_connection(
                &deploy,
                ProjectRef::DEFAULT.as_str(),
                SITE,
                COMPONENT,
                &fn_config,
                peer.to_string(),
                read_half,
                write_half,
                Duration::from_secs(5),
                max_dur,
                boatramp_handlers::ConnectionSecurity::plaintext(),
                std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            )
            .await
    });
    (handle, addr)
}

/// A one-shot REACHABLE upstream that records whether ANY byte ever reached it (Security review
/// LOW-2): the fail-closed test points the bridge at THIS (reachable, non-allowlisted) upstream and
/// asserts it receives ZERO bytes — so neutering the egress gate (which would then connect + deliver
/// the preamble) turns the assertion RED. Returns the "got bytes" flag + its addr; the accept task is
/// detached and holds the listener for a short grace window.
#[cfg(all(feature = "session", feature = "tcp-egress"))]
async fn spawn_byte_detector_upstream() -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::net::SocketAddr,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let got = std::sync::Arc::new(AtomicBool::new(false));
    let got2 = std::sync::Arc::clone(&got);
    tokio::spawn(async move {
        // If the gate refuses, the host never connects here, so no accept fires within the grace.
        if let Ok(Ok((mut s, _))) =
            tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
        {
            let mut buf = [0u8; 64];
            if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await
                && n > 0
            {
                got2.store(true, Ordering::SeqCst);
            }
        }
    });
    (got, addr)
}

/// A one-shot fake upstream: accept exactly one connection and hand its socket back over a channel,
/// so the test plays the upstream end of a promoted splice directly.
#[cfg(all(feature = "session", feature = "tcp-egress"))]
async fn spawn_one_shot_upstream() -> (
    tokio::sync::oneshot::Receiver<TcpStream>,
    std::net::SocketAddr,
) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((s, _)) = listener.accept().await {
            let _ = s.set_nodelay(true);
            let _ = tx.send(s);
        }
    });
    (rx, addr)
}

/// cap-req 22 PROMOTE (session→connection escalation) load-bearing live gate. Drives a REAL
/// `session-imap-bridge` guest over REAL loopback sockets and proves the four properties #22 promises,
/// each within a bounded wall-clock so a regression turns the test RED:
///
///   1. **DUPLEX + PERSISTENCE + close-teardown**: after greeting, a `BRIDGE` command promotes the
///      connection; the host writes the guest's preamble to the (gate-authorized) upstream, then
///      splices BOTH ways for the whole session — proven by 20 interleaved client↔upstream exchanges
///      that each would have been a separate re-entry, with `session.instantiations` UNCHANGED across
///      them (the upstream socket persisted; the guest was never re-entered). Closing the client tears
///      the splice down and closes the upstream socket.
///   2. **MAX-DURATION teardown**: an idle live splice is reaped at the absolute `max_conn_duration`.
///   3. **FAIL-CLOSED**: promoting to an upstream NOT in the listener's `egress_allowlist` is refused
///      by the REUSED egress/connect gate (`not-authorized`) — the guest replies `REFUSED`, NO splice
///      happens, and the session keeps serving re-entries. (Mutation-verified for free: the dial goes
///      through `resolve_and_gate_tcp_egress`, whose gate carries the `BOATRAMP_TCPEGRESS_MUTATION`
///      anti-hollow seam — neutering the gate turns this assertion RED.)
///   4. **LANE ISOLATION (v0.36.0 lesson)**: with the session-socket re-entry pool sized to 1, a
///      SECOND connection's re-entries still complete PROMPTLY while the first connection's splice is
///      live — proving the long-held duplex splice holds NO re-entry permit (and thus cannot starve
///      the re-entry pool or the shared async lane).
#[cfg(all(feature = "session", feature = "tcp-egress"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live promote-splice gate: timing-sensitive, runs only in the dedicated tcp-listener-live CI job via --include-ignored, not the general --all-features suite (flaked on a loaded runner 2026-10-30)"]
async fn session_listener_live_promote_splice_fail_closed_and_lane_isolation() {
    const GREETING: &[u8] = b"* OK session-imap-bridge ready\r\n";
    const PREAMBLE: &[u8] = b"PREAMBLE\r\n";

    async fn read_line(c: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
            tokio::time::timeout(Duration::from_secs(30), c.read_exact(&mut b))
                .await
                .expect("read_line timed out")
                .expect("read_line failed");
            buf.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
        buf
    }
    async fn read_exact_timed(s: &mut TcpStream, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut buf))
            .await
            .expect("splice read timed out")
            .expect("splice read failed");
        buf
    }

    // ---- 1. DUPLEX + PERSISTENCE + CLOSE TEARDOWN ------------------------------------------------
    {
        let (runtime, deploy) = live_runtime_egress(SESSION_IMAP_BRIDGE, 60, 4).await;
        let (up_rx, up_addr) = spawn_one_shot_upstream().await;
        let (handle, addr) = bind_and_serve_session_egress(
            runtime.clone(),
            deploy,
            Duration::from_secs(30),
            // Granted egress (`wasi:sockets`) + the upstream allowlisted — the strict parity #22
            // requires (Security review MEDIUM-1): a bridge that legitimately dials upstreams.
            vec!["wasi:sockets".into()],
            vec![format!("127.0.0.1:{}", up_addr.port())],
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        assert_eq!(
            &read_line(&mut client).await,
            GREETING,
            "connect-time greeting"
        );

        // Promote: the host dials the (allowlisted) upstream + writes the preamble, then splices.
        client
            .write_all(format!("BRIDGE 127.0.0.1 {}\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut up = tokio::time::timeout(Duration::from_secs(30), up_rx)
            .await
            .expect("the host never dialed the upstream (promote failed?)")
            .expect("upstream sender dropped");
        assert_eq!(
            &read_exact_timed(&mut up, PREAMBLE.len()).await,
            PREAMBLE,
            "the host writes the guest preamble to the upstream BEFORE splicing"
        );

        // First duplex exchange — the splice is now live.
        client.write_all(b"ping-01").await.unwrap();
        assert_eq!(
            &read_exact_timed(&mut up, 7).await,
            b"ping-01",
            "client -> upstream"
        );
        up.write_all(b"pong-01").await.unwrap();
        assert_eq!(
            &read_exact_timed(&mut client, 7).await,
            b"pong-01",
            "upstream -> client"
        );

        // PERSISTENCE: capture the instantiation count now (the promote re-entry is done) and prove it
        // does NOT move across 19 more interleaved exchanges — the splice never re-enters the guest,
        // and the ONE upstream socket persists across what each would have been a hibernation point.
        let insts_baseline = runtime
            .instance_stats()
            .expect("engine present")
            .session
            .instantiations;
        for i in 2..=20u8 {
            let req = format!("ping-{i:02}");
            client.write_all(req.as_bytes()).await.unwrap();
            assert_eq!(read_exact_timed(&mut up, req.len()).await, req.as_bytes());
            let rsp = format!("pong-{i:02}");
            up.write_all(rsp.as_bytes()).await.unwrap();
            assert_eq!(
                read_exact_timed(&mut client, rsp.len()).await,
                rsp.as_bytes()
            );
        }
        let insts_after = runtime
            .instance_stats()
            .expect("engine present")
            .session
            .instantiations;
        assert_eq!(
            insts_after, insts_baseline,
            "a promoted splice must NOT re-enter the guest (the upstream socket persists; the duplex \
             relay runs entirely off the re-entry model)"
        );

        // CLOSE TEARDOWN: drop the client -> the splice ends -> the upstream socket is closed (EOF).
        drop(client);
        let mut tail = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(30), up.read(&mut tail))
            .await
            .expect("upstream EOF timed out")
            .expect("upstream read failed");
        assert_eq!(
            n, 0,
            "closing the client tears the splice down + closes the upstream socket"
        );
        let (res, _) =
            await_dispatch(handle, Duration::from_secs(30), "promote-splice-close").await;
        assert!(
            res.is_ok(),
            "promoted splice ends cleanly on client close: {res:?}"
        );
    }

    // ---- 2. MAX-DURATION TEARDOWN of a live splice -----------------------------------------------
    {
        let (runtime, deploy) = live_runtime_egress(SESSION_IMAP_BRIDGE, 61, 4).await;
        let (up_rx, up_addr) = spawn_one_shot_upstream().await;
        let (handle, addr) = bind_and_serve_session_egress(
            runtime,
            deploy,
            Duration::from_secs(2), // short absolute cap
            vec!["wasi:sockets".into()],
            vec![format!("127.0.0.1:{}", up_addr.port())],
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        let _ = read_line(&mut client).await;
        client
            .write_all(format!("BRIDGE 127.0.0.1 {}\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut up = tokio::time::timeout(Duration::from_secs(30), up_rx)
            .await
            .expect("upstream dial timed out")
            .expect("upstream sender dropped");
        let _ = read_exact_timed(&mut up, PREAMBLE.len()).await;
        // Idle (no bytes either way) -> the absolute max_conn_duration must reap the live splice.
        let (res, elapsed) =
            await_dispatch(handle, Duration::from_secs(30), "promote-splice-maxdur").await;
        assert!(
            res.is_ok(),
            "promoted splice ends on max_conn_duration: {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(18),
            "max-duration must bound an idle live splice ({elapsed:?})"
        );
        let mut tail = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(30), up.read(&mut tail))
            .await
            .expect("upstream EOF timed out")
            .expect("upstream read failed");
        assert_eq!(
            n, 0,
            "the upstream socket is closed on max-duration teardown"
        );
    }

    // ---- 3. FAIL-CLOSED (true guard — Security review LOW-2 + MEDIUM-1) ---------------------------
    // Each sub-case points the bridge at a REACHABLE byte-detector upstream and asserts it receives
    // ZERO bytes: if the gate/grant check were neutered the host WOULD connect + deliver the preamble,
    // flipping the detector → RED. (A merely-unreachable target would pass whether refused OR just
    // unreachable, which is why the old `127.0.0.1:1` form could not guard the gate.)

    // 3a — allowlist refusal WITH the egress grant present: `wasi:sockets` granted, but the (reachable)
    // target is NOT in the allowlist ⇒ RefusedByGate ⇒ `not-authorized`, and NO bytes reach it.
    {
        let (runtime, deploy) = live_runtime_egress(SESSION_IMAP_BRIDGE, 62, 4).await;
        let (fb_got, fb_addr) = spawn_byte_detector_upstream().await;
        let (handle, addr) = bind_and_serve_session_egress(
            runtime,
            deploy,
            Duration::from_secs(30),
            vec!["wasi:sockets".into()],
            // Allowlist a DECOY port — NOT the reachable detector the client will try to bridge to.
            vec!["127.0.0.1:9".to_string()],
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        let _ = read_line(&mut client).await;
        client
            .write_all(format!("BRIDGE 127.0.0.1 {}\n", fb_addr.port()).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            &read_line(&mut client).await,
            b"REFUSED\r\n",
            "promote to a reachable-but-UN-ALLOWLISTED upstream is refused fail-closed (NO splice)"
        );
        // Session keeps serving re-entries after a refused promote.
        client.write_all(b"hello\n").await.unwrap();
        assert_eq!(
            &read_line(&mut client).await,
            b"GOT:hello\n",
            "after a refused promote the session continues in the re-entry model"
        );
        // Grace for a (hypothetically neutered) gate to connect + deliver the preamble, then prove it
        // did NOT: the reused egress gate refused BEFORE any connect, so the upstream got nothing.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !fb_got.load(std::sync::atomic::Ordering::SeqCst),
            "a refused promote must send ZERO bytes to the un-allowlisted upstream (gate guard)"
        );
        drop(client);
        let (res, _) =
            await_dispatch(handle, Duration::from_secs(30), "promote-fail-closed-3a").await;
        assert!(
            res.is_ok(),
            "clean end after a refused promote (3a): {res:?}"
        );
    }

    // 3b — strict egress-GRANT parity (Security review MEDIUM-1): the target IS reachable AND in the
    // allowlist, but the listener is NOT granted `wasi:sockets` ⇒ the promote dialer gets an EMPTY
    // allowlist ⇒ RefusedByGate ⇒ `not-authorized`, and NO bytes reach the upstream. Proves promote
    // requires the egress GRANT, not merely the `session` grant + a populated allowlist.
    {
        let (runtime, deploy) = live_runtime_egress(SESSION_IMAP_BRIDGE, 64, 4).await;
        let (fb_got, fb_addr) = spawn_byte_detector_upstream().await;
        let (handle, addr) = bind_and_serve_session_egress(
            runtime,
            deploy,
            Duration::from_secs(30),
            // NO `wasi:sockets` grant …
            Vec::new(),
            // … even though the reachable upstream IS allowlisted.
            vec![format!("127.0.0.1:{}", fb_addr.port())],
        )
        .await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        let _ = read_line(&mut client).await;
        client
            .write_all(format!("BRIDGE 127.0.0.1 {}\n", fb_addr.port()).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            &read_line(&mut client).await,
            b"REFUSED\r\n",
            "promote WITHOUT the `wasi:sockets` grant is refused even to an allowlisted upstream"
        );
        client.write_all(b"hello\n").await.unwrap();
        assert_eq!(
            &read_line(&mut client).await,
            b"GOT:hello\n",
            "session continues after a grant-refused promote"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !fb_got.load(std::sync::atomic::Ordering::SeqCst),
            "a promote lacking the egress grant must send ZERO bytes to the upstream (grant guard)"
        );
        drop(client);
        let (res, _) =
            await_dispatch(handle, Duration::from_secs(30), "promote-fail-closed-3b").await;
        assert!(
            res.is_ok(),
            "clean end after a grant-refused promote (3b): {res:?}"
        );
    }

    // ---- 4. LANE ISOLATION: a live splice holds NO session re-entry permit -----------------------
    {
        // Session-socket re-entry pool = 1. If a promoted splice wrongly held a re-entry permit, a
        // SECOND connection's re-entry would block until the splice ended. It must not.
        let (runtime, deploy) = live_runtime_egress(SESSION_IMAP_BRIDGE, 63, 1).await;
        let (up_rx, up_addr) = spawn_one_shot_upstream().await;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let allow = vec![format!("127.0.0.1:{}", up_addr.port())];
        {
            let runtime = runtime.clone();
            let deploy = deploy.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let _ = stream.set_nodelay(true);
                    let (r, w) = stream.into_split();
                    let runtime = runtime.clone();
                    let deploy = deploy.clone();
                    let allow = allow.clone();
                    tokio::spawn(async move {
                        let fc = FunctionConfig {
                            imports: vec!["wasi:sockets".into()],
                            egress_allowlist: allow,
                            ..FunctionConfig::default()
                        };
                        let _ = runtime
                            .dispatch_session_connection(
                                &deploy,
                                ProjectRef::DEFAULT.as_str(),
                                SITE,
                                COMPONENT,
                                &fc,
                                peer.to_string(),
                                r,
                                w,
                                Duration::from_secs(5),
                                Duration::from_secs(30),
                                boatramp_handlers::ConnectionSecurity::plaintext(),
                                std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
                            )
                            .await;
                    });
                }
            });
        }
        // Connection A: promote -> a live splice that must NOT hold the single re-entry permit.
        let mut a = TcpStream::connect(addr).await.unwrap();
        let _ = a.set_nodelay(true);
        let _ = read_line(&mut a).await;
        a.write_all(format!("BRIDGE 127.0.0.1 {}\n", up_addr.port()).as_bytes())
            .await
            .unwrap();
        let mut up = tokio::time::timeout(Duration::from_secs(30), up_rx)
            .await
            .expect("upstream dial timed out")
            .expect("upstream sender dropped");
        let _ = read_exact_timed(&mut up, PREAMBLE.len()).await;

        // Connection B: with A's splice live and the re-entry pool = 1, B's connect-dispatch + inbound
        // re-entries must still complete PROMPTLY. A timeout here is the lane-isolation regression.
        let mut b = TcpStream::connect(addr).await.unwrap();
        let _ = b.set_nodelay(true);
        assert_eq!(
            &read_line(&mut b).await,
            GREETING,
            "client B's connect-dispatch re-entry completed while A's splice is live (not pool-starved)"
        );
        b.write_all(b"hi\n").await.unwrap();
        assert_eq!(
            &read_line(&mut b).await,
            b"GOT:hi\n",
            "client B's inbound re-entry completed while A's splice is live (lane isolation holds)"
        );
        // A's splice is still live throughout (B interleaved with it); tear everything down.
        drop(a);
        drop(b);
        drop(up);
    }

    println!(
        "SESSION PROMOTE LIVE OK: promote-connection escalated a session connection to a persistent \
         duplex splice (preamble written to the gate-authorized upstream, bidirectional relay across \
         20 exchanges with ZERO further re-entry), tore down on client close + on max_conn_duration, \
         and FAIL-CLOSED as a TRUE guard — a refused promote (un-allowlisted upstream, AND a listener \
         lacking the `wasi:sockets` grant) delivered ZERO bytes to a REACHABLE upstream (reused egress \
         gate + strict grant parity), while the live splice held no re-entry permit (lane isolation, \
         pool of 1)."
    );
}
