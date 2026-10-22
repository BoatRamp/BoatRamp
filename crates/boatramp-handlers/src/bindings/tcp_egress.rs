//! The host-terminated outbound-TLS **egress** binding (`boatramp:handlers/tcp-egress`,
//! `PLAN-handler-tcp-egress` Build A, mailroom cap-req #15): the OUTBOUND mirror of the host-owned
//! inbound-TCP listener (`tcp-connection-handler`, `bindings/` has no equivalent file for THAT one —
//! it is dispatched directly by the engine — because it is an EXPORT; `tcp-egress` is an IMPORT, so
//! it gets a normal `Host`/`HostConnection` binding like `sql`/`blob_upload`).
//!
//! `wasi:sockets` itself is served by wasmtime and gives the GUEST the raw socket + streams — there
//! is no host hook to wrap a guest's own outbound connection in TLS (the engine's only lever is the
//! pure yes/no `socket_addr_check`). Instead the HOST dials the TCP connection AND terminates TLS
//! here, handing the guest only plaintext `wasi:io` streams. The guest does ZERO crypto.
//!
//! # Security model — reused, not forked
//! The dial reuses the EXACT SAME gate the gated `wasi:sockets` outbound-TCP capability's
//! `socket_addr_check` closure calls: [`crate::engine::resolve_and_gate_tcp_egress`] drives the SAME
//! `tcp_connect_decision` predicate (posture `allow_guest_tcp_egress` + connect-only + the
//! `is_global_ip` SSRF floor + the per-handler `egress_allowlist`). It also reuses the SAME
//! verifying rustls `ClientConfig` ([`crate::engine::guest_egress_client_config`]: webpki ⊕ the
//! operator's `extra_roots`, an explicit `aws-lc-rs` provider, full certificate verification) a
//! guest's own `wasi:http` egress uses. The capability arm reuses the `wasi:sockets` grant too (see
//! `boatramp`'s `capability_token`) — no new grant kind anywhere in this stack.
//!
//! # DNS-rebinding choke point (load-bearing)
//! `host` is resolved EXACTLY ONCE, inside [`crate::engine::resolve_and_gate_tcp_egress`]; each
//! resolved candidate address is checked individually through the gate, and [`connect_dial`] below
//! connects ONLY to an address already in that checked set — it never calls `lookup_host` again.
//! See that function's doc comment for the attack this closes.
//!
//! Build A implements implicit TLS only (`verify-mode.strict`); `opportunistic` (Build B's relay
//! path) is refused with `unsupported-verify-mode` rather than a relaxed verifier.

use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::{DynInputStream, DynOutputStream};

use crate::engine::{
    TcpEgressResolveError, guest_egress_client_config, resolve_and_gate_tcp_egress,
};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/tcp-egress-host",
        async: {
            only_imports: ["connect-tls", "[method]connection.shutdown-output"],
        },
        with: {
            // Reuse wasmtime-wasi's OWN already-generated `wasi:io` bindings (the same mapping
            // `tcp_connection_world` uses for the inbound listener), so the `input-stream`/
            // `output-stream` resources this interface `use`s are the SAME `DynInputStream`/
            // `DynOutputStream` Rust type the engine already pushes into the store table.
            "wasi:io": wasmtime_wasi::bindings::io,
            "boatramp:handlers/tcp-egress/connection": super::TcpEgressConnection,
        },
    });
}

use generated::boatramp::handlers::{tcp_egress, tcp_egress_types};
pub use tcp_egress_types::{EgressError, VerifyMode};

/// The chunk budget for the host→guest write stream, mirroring the inbound listener's
/// `TCP_CONN_WRITE_BUDGET` (PLAN-handler-tcp-inbound) — enough to keep a chatty writer from
/// stalling on per-chunk backpressure without buffering unboundedly.
const TCP_EGRESS_WRITE_BUDGET: usize = 64 * 1024;

/// A boxed, type-erased `AsyncRead`/`AsyncWrite` half. `Box<dyn Trait>` is `Unpin` regardless of the
/// pointee, so [`TcpEgressConnection`] needs no `Pin` ceremony. Boxing (rather than a concrete
/// `tokio_rustls::client::TlsStream<TcpStream>` split half) is what lets the anti-hollow
/// `skip_tls_wrap` mutation substitute the RAW pre-TLS halves with the identical field shape — never
/// reached in a shipped build (see [`tcpegress_tls_mutation`]).
type BoxedRead = Box<dyn tokio::io::AsyncRead + Send + Unpin + 'static>;
type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'static>;

/// The host-dialed, (normally) host-terminated-TLS outbound connection a granted guest holds. Not
/// constructible by the guest — returned by `connect-tls`. See the module docs for the
/// forward-compatibility note re: Build B's `start-tls`.
pub struct TcpEgressConnection {
    /// `None` once handed off by `take-input`.
    input: Option<BoxedRead>,
    /// `None` once handed off by `take-output`, or consumed by `shutdown-output`.
    output: Option<BoxedWrite>,
    idle_timeout: Duration,
}

/// Enforces the `tcp-egress` per-dial READ/IDLE timeout directly inside `poll_read`/`poll_write`.
/// There is no outer watchdog loop for these streams (unlike the inbound conn lane's `select!` — a
/// guest drives `wasi:io` reads/writes on its own schedule, possibly long after `connect-tls`
/// returned), so the bound has to live INSIDE the adapter itself: each call restarts a deadline; if
/// neither progress (a read producing bytes/EOF, or `poll_write` accepting bytes) nor the inner
/// future resolves before the deadline fires, the call resolves a `TimedOut` io error — surfaced to
/// the guest as a stream error on its next read/write, exactly like an abrupt peer drop. Any
/// progress resets the clock. Generic over `T: Unpin`, so `Pin<Box<Sleep>>` + `T: Unpin` together
/// make the whole wrapper `Unpin` (no manual pin-projection needed).
struct IdleTimeout<T> {
    inner: T,
    idle: Duration,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl<T> IdleTimeout<T> {
    fn new(inner: T, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }

    fn touch(&mut self) {
        self.deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle);
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleTimeout<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = std::pin::Pin::get_mut(self);
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                this.touch();
                Poll::Ready(r)
            }
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tcp-egress idle timeout: no data from peer",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleTimeout<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = std::pin::Pin::get_mut(self);
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(r) => {
                this.touch();
                Poll::Ready(r)
            }
            Poll::Pending => match this.deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tcp-egress idle timeout: peer not accepting writes",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = std::pin::Pin::get_mut(self);
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = std::pin::Pin::get_mut(self);
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl TcpEgressConnection {
    fn take_input(&mut self) -> Option<DynInputStream> {
        let idle = self.idle_timeout;
        self.input.take().map(|r| {
            Box::new(wasmtime_wasi::pipe::AsyncReadStream::new(IdleTimeout::new(
                r, idle,
            ))) as DynInputStream
        })
    }

    fn take_output(&mut self) -> Option<DynOutputStream> {
        let idle = self.idle_timeout;
        self.output.take().map(|w| {
            Box::new(wasmtime_wasi::pipe::AsyncWriteStream::new(
                TCP_EGRESS_WRITE_BUDGET,
                IdleTimeout::new(w, idle),
            )) as DynOutputStream
        })
    }

    /// Half-close the write side if it hasn't been taken yet; a no-op otherwise (see the WIT doc).
    async fn shutdown_output(&mut self) {
        if let Some(mut w) = self.output.take() {
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
        }
    }
}

/// Per-invocation view of the `tcp-egress` capability: the resource table (holding `connection`
/// handles) plus the SAME gate inputs (allowlist / posture / SSRF-private-egress / extra trust
/// roots / timeouts) the engine copies from itself and from this invocation's `Bindings` at
/// `new_store` time (see `HandlerEngine::build_linker`).
pub struct TcpEgressHost<'a> {
    table: &'a mut ResourceTable,
    /// The node posture's `allow_guest_tcp_egress` — the EXACT SAME flag that gates the raw
    /// `wasi:sockets` capability. No new posture knob.
    enabled: bool,
    allow_private: bool,
    allowlist: Arc<[String]>,
    extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl<'a> TcpEgressHost<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        table: &'a mut ResourceTable,
        enabled: bool,
        allow_private: bool,
        allowlist: Arc<[String]>,
        extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            table,
            enabled,
            allow_private,
            allowlist,
            extra_roots,
            connect_timeout,
            idle_timeout,
        }
    }
}

impl tcp_egress::Host for TcpEgressHost<'_> {
    async fn connect_tls(
        &mut self,
        host: String,
        port: u16,
        sni: String,
        verify: VerifyMode,
    ) -> Result<Resource<TcpEgressConnection>, EgressError> {
        if !matches!(verify, VerifyMode::Strict) {
            return Err(EgressError::UnsupportedVerifyMode);
        }

        // The DNS-rebinding choke: resolve ONCE, check EACH candidate through the reused gate.
        let checked = resolve_and_gate_tcp_egress(
            &host,
            port,
            &self.allowlist,
            self.allow_private,
            self.enabled,
        )
        .await
        .map_err(|e| match e {
            TcpEgressResolveError::DnsFailure => EgressError::DnsFailure,
            TcpEgressResolveError::RefusedByGate => EgressError::RefusedByGate,
        })?;

        let (input, output) = connect_dial(&checked, &sni, self.connect_timeout, &self.extra_roots)
            .await
            .map(split_boxed)?;

        let conn = TcpEgressConnection {
            input: Some(input),
            output: Some(output),
            idle_timeout: self.idle_timeout,
        };
        self.table
            .push(conn)
            .map_err(|e| EgressError::Other(e.to_string()))
    }
}

impl tcp_egress::HostConnection for TcpEgressHost<'_> {
    // `take-input`/`take-output`/`shutdown-output` are plain (non-`result<_,_>`) WIT funcs, so
    // bindgen generates bare return types here — a resource-table lookup failure on a handle this
    // SAME host issued (and that outlives it only within one invocation) would be an internal
    // engine bug, not a guest-triggerable condition, so it is `expect`ed rather than threaded
    // through a WIT-level error (there is none to thread it through).
    fn take_input(
        &mut self,
        self_: Resource<TcpEgressConnection>,
    ) -> Option<Resource<DynInputStream>> {
        let conn = self
            .table
            .get_mut(&self_)
            .expect("tcp-egress connection resource handle must be valid");
        conn.take_input()
            .map(|s| self.table.push(s).expect("push input-stream into table"))
    }

    fn take_output(
        &mut self,
        self_: Resource<TcpEgressConnection>,
    ) -> Option<Resource<DynOutputStream>> {
        let conn = self
            .table
            .get_mut(&self_)
            .expect("tcp-egress connection resource handle must be valid");
        conn.take_output()
            .map(|s| self.table.push(s).expect("push output-stream into table"))
    }

    async fn shutdown_output(&mut self, self_: Resource<TcpEgressConnection>) {
        let conn = self
            .table
            .get_mut(&self_)
            .expect("tcp-egress connection resource handle must be valid");
        conn.shutdown_output().await;
    }

    fn drop(&mut self, rep: Resource<TcpEgressConnection>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

/// Split a boxed read/write pair's worth of bytes-flow into the two `BoxedRead`/`BoxedWrite` halves
/// [`TcpEgressConnection`] stores. A tiny named helper so [`tcp_egress::Host::connect_tls`]'s success
/// path reads as one pipeline regardless of which [`DialedStream`] variant it got.
fn split_boxed(stream: DialedStream) -> (BoxedRead, BoxedWrite) {
    match stream {
        DialedStream::Tls(s) => {
            let (r, w) = tokio::io::split(*s);
            (Box::new(r), Box::new(w))
        }
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        DialedStream::RawMutation(s) => {
            let (r, w) = tokio::io::split(s);
            (Box::new(r), Box::new(w))
        }
    }
}

/// What [`connect_dial`] hands back: normally the TLS-terminated stream. The `RawMutation` arm
/// exists ONLY to let the anti-hollow `skip_tls_wrap` mutation (test / `tcpegress-gate-mutation`
/// feature) hand back the pre-handshake TCP stream instead — never constructed in a shipped build.
enum DialedStream {
    // Boxed: a `TlsStream` is large relative to a bare `TcpStream`, and this enum is otherwise
    // short-lived (immediately split into the two boxed halves `TcpEgressConnection` stores).
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
    RawMutation(tokio::net::TcpStream),
}

/// Connect to one of the already-gate-CHECKED `addrs` (the DNS-rebinding choke's output — see the
/// module docs) and terminate TLS. NEVER resolves `sni`/any hostname again; every candidate in
/// `addrs` is dialed in order, the first successful TCP connect wins, and the TLS handshake (or, ONLY
/// under the `skip_tls_wrap` mutation, nothing) runs against that same connected socket. Both the
/// connect and the handshake share ONE `connect_timeout` budget per candidate (establishing the
/// connection is one conceptual step).
async fn connect_dial(
    addrs: &[std::net::SocketAddr],
    sni: &str,
    connect_timeout: Duration,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<DialedStream, EgressError> {
    let mut last_err: Option<String> = None;
    let mut saw_timeout = false;
    let mut tcp_stream = None;
    for addr in addrs {
        match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                tcp_stream = Some(s);
                break;
            }
            Ok(Err(e)) => last_err = Some(e.to_string()),
            Err(_) => saw_timeout = true,
        }
    }
    let tcp_stream = match tcp_stream {
        Some(s) => s,
        None if last_err.is_none() && saw_timeout => return Err(EgressError::ConnectTimeout),
        None => {
            return Err(EgressError::ConnectFailed(last_err.unwrap_or_else(|| {
                "every candidate address refused the connection".into()
            })));
        }
    };

    // ANTI-HOLLOW MUTATION SEAM (`tcpegress-gate-mutation` / cfg(test) only — NEVER in a shipped
    // build, since the feature is never enabled there): `skip_tls_wrap` hands back the RAW TCP
    // stream with NO TLS handshake at all, so the CI gate can prove a test driving a REAL TLS round
    // trip through this path goes RED when the wrap is skipped. Not a backdoor — it only reads a
    // test env var, gated by a cargo feature that is never part of a shipped build.
    if tcpegress_tls_mutation().as_deref() == Some("skip_tls_wrap") {
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        return Ok(DialedStream::RawMutation(tcp_stream));
    }

    let tls_config = guest_egress_client_config(extra_roots)
        .map_err(|_| EgressError::TlsFailure("TLS client config error".into()))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| EgressError::TlsFailure(format!("invalid SNI {sni:?}: {e}")))?;
    let tls_stream =
        tokio::time::timeout(connect_timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| EgressError::ConnectTimeout)?
            .map_err(|e| EgressError::TlsFailure(e.to_string()))?;
    Ok(DialedStream::Tls(Box::new(tls_stream)))
}

/// The active TLS-wrap mutation (`PLAN-handler-tcp-egress` Build A / mailroom #15 anti-hollow gate),
/// or `None`. Present ONLY under `cfg(test)` (this crate's own unit gate) or the
/// `tcpegress-gate-mutation` feature (the SAME lane the existing `tcp_connect_decision` gate-mutation
/// uses); a shipped build has NEITHER, so [`connect_dial`] ALWAYS terminates TLS before handing back
/// a `connection`. `skip_tls_wrap` is the one recognized value. NOT a backdoor — it only reads a test
/// env var.
#[cfg(any(test, feature = "tcpegress-gate-mutation"))]
fn tcpegress_tls_mutation() -> Option<String> {
    std::env::var("BOATRAMP_TCPEGRESS_TLS_MUTATION").ok()
}
#[cfg(not(any(test, feature = "tcpegress-gate-mutation")))]
#[inline]
fn tcpegress_tls_mutation() -> Option<String> {
    None
}

/// Add the `tcp-egress` interface to `linker`, resolving the per-invocation [`TcpEgressHost`] view
/// via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> TcpEgressHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    tcp_egress::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use wasmtime_wasi::Pollable as _;

    /// Serializes every test in this module that touches `BOATRAMP_TCPEGRESS_TLS_MUTATION`
    /// (setting it OR relying on it being unset) — mirrors `engine.rs`'s own `ENV_LOCK` discipline
    /// for `BOATRAMP_ASYNCLANE_MUTATION`/`BOATRAMP_TCPEGRESS_MUTATION`, since Rust's test harness
    /// runs tests in parallel threads within one process and the env var is process-global. An
    /// async-aware `tokio::sync::Mutex` (not `std::sync::Mutex`, which `engine.rs`'s tests use) —
    /// this module's critical sections span real `.await`s (the network dial itself), which a
    /// `std::sync::Mutex` guard must never be held across.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Mint a throwaway CA + a `localhost` leaf signed by it (mirrors
    /// `engine::egress_tls_tests::ca_and_leaf`, duplicated here so this module's tests are
    /// self-contained like every other `bindings/*.rs` file's test module).
    fn ca_and_leaf() -> (
        CertificateDer<'static>,
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
    ) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        let ca_der = ca_cert.der().clone();
        let chain = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (ca_der, chain, key)
    }

    /// A one-shot loopback rustls TLS server: accepts one connection, completes the handshake, then
    /// writes `greeting` and closes. Returns its bound port.
    async fn spawn_tls_server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        greeting: &'static [u8],
    ) -> u16 {
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await
                && let Ok(mut tls) = acceptor.accept(tcp).await
            {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut tls, greeting).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
            }
        });
        port
    }

    /// Dial `127.0.0.1:port` via the real `connect_tls` host call and read the connection until EOF
    /// (`StreamError::Closed`) OR a transport error (e.g. the idle timeout firing because the
    /// mutated/raw peer never speaks a protocol either side understands), returning whatever bytes
    /// arrived either way — the test only cares whether the EXACT greeting came back, so any other
    /// outcome (fewer/garbled bytes, or a transport error) already proves the point. A SHORT idle
    /// timeout keeps the mutated (deadlocked, since neither raw peer sends first) run fast.
    /// `allow_private` + the allowlist are test-supplied knobs — exactly like
    /// `tcp_egress_allowlist_gate` in `engine.rs` passes them directly rather than going through any
    /// real operator config.
    async fn dial_and_read(
        port: u16,
        allow_private: bool,
        allowlist: &[&str],
        extra_roots: &[CertificateDer<'static>],
    ) -> Result<Vec<u8>, String> {
        let mut table = ResourceTable::new();
        let allow: Vec<String> = allowlist.iter().map(ToString::to_string).collect();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            allow_private,
            Arc::from(allow),
            Arc::from(extra_roots.to_vec()),
            Duration::from_secs(5),
            Duration::from_millis(300),
        );
        let conn_res = tcp_egress::Host::connect_tls(
            &mut host,
            "127.0.0.1".to_string(),
            port,
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        let in_res = tcp_egress::HostConnection::take_input(&mut host, conn_res)
            .expect("input not yet taken");
        let stream: &mut DynInputStream = table.get_mut(&in_res).unwrap();
        let mut buf = Vec::new();
        loop {
            match stream.read(4096) {
                // Nothing buffered yet (not closed either) — wait for the background reader, then
                // retry the same (non-blocking) `read`.
                Ok(bytes) if bytes.is_empty() => stream.ready().await,
                Ok(bytes) => buf.extend_from_slice(&bytes),
                Err(wasmtime_wasi::StreamError::Closed) => break,
                Err(e) => return Err(format!("read failed after {} bytes: {e:?}", buf.len())),
            }
        }
        Ok(buf)
    }

    /// `PLAN-handler-tcp-egress` Build A anti-hollow gate (mirrors the inbound TE-3 harness style):
    /// a REAL loopback TLS server hands a plaintext greeting through `connect-tls` + `take-input` —
    /// proving the host actually dials, terminates TLS, and exposes decrypted bytes to the guest as
    /// `wasi:io`. MUTATION-VERIFIED: re-run with `BOATRAMP_TCPEGRESS_TLS_MUTATION=skip_tls_wrap` the
    /// SAME kind of assertion MUST fail (the client skips its own handshake, so what arrives on the
    /// wire is the server's raw TLS handshake record, never the plaintext greeting) — proving the
    /// TLS wrap is load-bearing, not cosmetic. Prints the grep-able marker `TCP-EGRESS TLS WRAP OK`.
    #[tokio::test]
    async fn tcpegress_mutation() {
        let _g = ENV_LOCK.lock().await;
        unsafe { std::env::remove_var("BOATRAMP_TCPEGRESS_TLS_MUTATION") };

        let (ca, chain, key) = ca_and_leaf();
        const GREETING: &[u8] = b"TCP-EGRESS TLS OK";
        let port = spawn_tls_server(chain, key, GREETING).await;
        let allow = [format!("127.0.0.1:{port}")];
        let allow_refs: Vec<&str> = allow.iter().map(String::as_str).collect();

        let clean = dial_and_read(port, true, &allow_refs, std::slice::from_ref(&ca)).await;
        match clean {
            Ok(bytes) => assert_eq!(
                bytes, GREETING,
                "a clean dial must terminate TLS and hand back the server's plaintext greeting"
            ),
            Err(e) => panic!("clean dial failed: {e:?}"),
        }
        println!("TCP-EGRESS TLS WRAP OK");

        // Mutation guard: skip the TLS wrap and prove the SAME assertion now fails. A fresh server
        // instance (the first was consumed by the clean dial above).
        unsafe { std::env::set_var("BOATRAMP_TCPEGRESS_TLS_MUTATION", "skip_tls_wrap") };
        let (ca2, chain2, key2) = ca_and_leaf();
        let port2 = spawn_tls_server(chain2, key2, GREETING).await;
        let allow2 = [format!("127.0.0.1:{port2}")];
        let allow2_refs: Vec<&str> = allow2.iter().map(String::as_str).collect();
        let mutated = dial_and_read(port2, true, &allow2_refs, std::slice::from_ref(&ca2)).await;
        unsafe { std::env::remove_var("BOATRAMP_TCPEGRESS_TLS_MUTATION") };

        let hollow = matches!(mutated.as_deref(), Ok(bytes) if bytes == GREETING);
        assert!(
            !hollow,
            "HOLLOW GATE: skipping the TLS wrap must NOT still produce the server's plaintext \
             greeting (got {mutated:?}) — the wrap is supposed to be load-bearing"
        );
    }

    /// Gate reuse (the capability-specific checks, PLAN-handler-tcp-egress Build A): a target
    /// outside the allowlist, and a private target without `allow_private`, are both denied BEFORE
    /// any network I/O — `connect-tls` never even attempts a TCP connect. No network needed (IP
    /// literals resolve synchronously).
    #[tokio::test]
    async fn gate_reuse_denies_unallowlisted_and_private_targets() {
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            false,
            Arc::from(vec!["93.184.216.34:443".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        // Not in the allowlist (a different, genuinely global IP).
        let err = tcp_egress::Host::connect_tls(
            &mut host,
            "8.8.4.4".to_string(),
            443,
            "dns.google".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("a non-allowlisted target must be refused");
        assert!(matches!(err, EgressError::RefusedByGate));

        // Allowlisted by IP:port, but PRIVATE and `allow_private` is off — the SSRF floor denies it.
        let mut host2 = TcpEgressHost::new(
            &mut table,
            true,
            false,
            Arc::from(vec!["10.0.0.5:5432".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let err2 = tcp_egress::Host::connect_tls(
            &mut host2,
            "10.0.0.5".to_string(),
            5432,
            "db.internal".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("an allowlisted-but-private target must still clear the SSRF floor");
        assert!(matches!(err2, EgressError::RefusedByGate));

        // The posture gate off ⇒ deny-all, even for an otherwise-fine target.
        let mut host3 = TcpEgressHost::new(
            &mut table,
            false,
            true,
            Arc::from(vec!["93.184.216.34:443".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let err3 = tcp_egress::Host::connect_tls(
            &mut host3,
            "93.184.216.34".to_string(),
            443,
            "example.com".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("posture off must deny every dial");
        assert!(matches!(err3, EgressError::RefusedByGate));

        println!("TCP-EGRESS GATE REUSE OK");
    }

    /// Build A implements `verify-mode.strict` only; `opportunistic` is refused cleanly (Build B's
    /// relay path), never silently downgraded to a relaxed verifier.
    #[tokio::test]
    async fn opportunistic_verify_mode_is_refused() {
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(vec!["93.184.216.34:443".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let err = tcp_egress::Host::connect_tls(
            &mut host,
            "93.184.216.34".to_string(),
            443,
            "example.com".to_string(),
            VerifyMode::Opportunistic,
        )
        .await
        .expect_err("opportunistic must be refused in this build");
        assert!(matches!(err, EgressError::UnsupportedVerifyMode));
    }

    /// The DNS-rebinding choke point: an IP-literal host "resolves" to exactly itself (no network),
    /// and the returned checked set is the CONCRETE address the caller must connect to — not a bare
    /// yes/no — so a later connect can never silently target a different, unchecked address.
    #[tokio::test]
    async fn resolve_and_gate_returns_the_checked_concrete_address() {
        let allow = vec!["93.184.216.34:443".to_string()];
        let checked =
            crate::engine::resolve_and_gate_tcp_egress("93.184.216.34", 443, &allow, false, true)
                .await
                .expect("an allowlisted global literal must be checked-and-returned");
        assert_eq!(
            checked,
            vec!["93.184.216.34:443".parse::<std::net::SocketAddr>().unwrap()]
        );

        // A denied literal returns the typed refusal, not a silent empty success.
        let denied =
            crate::engine::resolve_and_gate_tcp_egress("10.0.0.5", 5432, &allow, false, true).await;
        assert_eq!(denied, Err(TcpEgressResolveError::RefusedByGate));
    }

    /// Connect-timeout: bind a listener but never `.accept()` it, so the TCP handshake completes
    /// (it is accepted into the OS backlog) yet the TLS handshake hangs forever waiting for a
    /// `ServerHello` nobody sends — the short configured `connect_timeout` must fire rather than
    /// hanging the invocation.
    #[tokio::test]
    async fn tls_handshake_hang_times_out() {
        let _g = ENV_LOCK.lock().await;
        unsafe { std::env::remove_var("BOATRAMP_TCPEGRESS_TLS_MUTATION") };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Keep the listener alive (bound + listening) but never accept — the connect itself
        // succeeds into the backlog; it's the handshake that then hangs.
        let _keep_alive = listener;

        let allow = [format!("127.0.0.1:{port}")];
        let allow_refs: Vec<&str> = allow.iter().map(String::as_str).collect();
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(
                allow_refs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            Arc::from(Vec::new()),
            Duration::from_millis(150),
            Duration::from_secs(5),
        );
        let err = tcp_egress::Host::connect_tls(
            &mut host,
            "127.0.0.1".to_string(),
            port,
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("a hung TLS handshake must time out, not hang the invocation");
        assert!(matches!(err, EgressError::ConnectTimeout), "{err:?}");
    }

    /// Connect-failed (non-timeout): dial a port nothing is listening on (bind then immediately
    /// drop the listener) — loopback refuses instantly.
    #[tokio::test]
    async fn connect_refused_is_connect_failed_not_timeout() {
        let _g = ENV_LOCK.lock().await;
        unsafe { std::env::remove_var("BOATRAMP_TCPEGRESS_TLS_MUTATION") };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let allow = vec![format!("127.0.0.1:{port}")];
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(allow),
            Arc::from(Vec::new()),
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let err = tcp_egress::Host::connect_tls(
            &mut host,
            "127.0.0.1".to_string(),
            port,
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("a refused connect must not look like success");
        assert!(matches!(err, EgressError::ConnectFailed(_)), "{err:?}");
    }

    /// The `IdleTimeout` adapter: a reader that never produces data must surface a `TimedOut` io
    /// error once the idle window elapses. Uses a short REAL wall-clock window (no `tokio`
    /// `test-util`/paused-time feature is enabled in this crate), mirroring
    /// `conn_watchdog_fires_max_duration_then_idle`'s same real-short-duration discipline in
    /// `engine.rs`.
    #[tokio::test]
    async fn idle_timeout_read_fires_on_a_silent_peer() {
        let (silent_end, _never_written_end) = tokio::io::duplex(64);
        let mut reader = IdleTimeout::new(silent_end, Duration::from_millis(50));
        let mut byte = [0u8; 1];
        let err = tokio::io::AsyncReadExt::read(&mut reader, &mut byte)
            .await
            .expect_err("a silent peer must time out, not hang forever");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
