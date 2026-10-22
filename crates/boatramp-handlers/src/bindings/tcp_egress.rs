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
//! resolved candidate address is checked individually through the gate, and [`connect_and_handshake`]
//! below connects ONLY to an address already in that checked set — it never calls `lookup_host`
//! again. See that function's doc comment for the attack this closes.
//!
//! # One shared deadline, capped fan-out (Security review M1)
//! The WHOLE pipeline — resolve, gate-check every candidate, connect, and the TLS handshake — runs
//! under exactly ONE `connect_timeout` ([`tcp_egress::Host::connect_tls`] is the only
//! `tokio::time::timeout` call site in the dial path), mirroring the `wasi:http` egress path's
//! single-budget semantics: never a separate timeout per gated candidate plus another for the
//! handshake. An async host import can't be epoch-trapped, so an unbounded pipeline would let a
//! guest naming a many-homed (or broad-CIDR-allowlisted) blackholed host pin a sync-lane slot for
//! `(N+1)*connect_timeout` and fan out N TCP SYNs. [`MAX_DIAL_CANDIDATES`] additionally caps how
//! many gate-checked candidates one dial ever attempts, independent of the time budget.
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

/// Cap on how many gate-CHECKED candidate addresses one `connect-tls` dial ATTEMPTS (Security
/// review M1) — independent of the shared `connect_timeout` budget (see the module docs), this
/// bounds the TCP-SYN fan-out a guest-named many-homed (or broad-CIDR-allowlisted) target can
/// cause for one call. A dual-stack-ish handful (4–8) covers normal multi-homing without letting a
/// pathological allowlist multiply the attempt count unboundedly.
const MAX_DIAL_CANDIDATES: usize = 8;

/// Fixed, non-verbose reason strings for `connect-failed`/`tls-failure` (Security review L1) —
/// parity with the `wasi:http` egress path's generic `ConnectionRefused`/`TlsProtocolError`: raw
/// `io::Error`/rustls `Display` text (which can echo OS-specific detail, or an internal
/// address/port resolved from a domain allowlist entry) never reaches the guest.
const REASON_CONNECT_FAILED: &str = "connect failed";
const REASON_TLS_CONFIG: &str = "tls configuration error";
const REASON_INVALID_SNI: &str = "invalid sni";
const REASON_TLS_HANDSHAKE: &str = "tls handshake failed";
const REASON_INTERNAL: &str = "internal error";

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
///
/// Lifecycle: while `input`/`output` are still `Some` (before the guest's `take-input`/
/// `take-output`), dropping this value closes the socket abruptly. Once BOTH are taken, this
/// struct holds nothing live — it is inert, droppable in any order, and the connection only
/// actually closes once BOTH taken `wasi:io` streams have themselves been dropped.
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
    /// Security review L2: the flush/shutdown itself is bounded by `idle_timeout` — a peer that
    /// fills its receive window and stops reading would otherwise pend this await for as long as
    /// TCP's own (far longer) retransmission timers, and an async host import can't be
    /// epoch-trapped out of it. A timeout here is a best-effort abandon (same as any other failure
    /// path — `shutdown-output` never reports an error), not a graceful close; the socket is still
    /// dropped once the resource itself is dropped.
    async fn shutdown_output(&mut self) {
        if let Some(mut w) = self.output.take() {
            let _ = tokio::time::timeout(
                self.idle_timeout,
                tokio::io::AsyncWriteExt::shutdown(&mut w),
            )
            .await;
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

        // Security review M1: the WHOLE resolve + gate-check + connect + handshake pipeline runs
        // under exactly ONE `connect_timeout` — this is the ONLY `tokio::time::timeout` call site
        // in the dial path (see the module docs). `dial_pipeline` itself carries no timeout of its
        // own, so a slow DNS resolve simply leaves correspondingly less budget for the
        // connect/handshake rather than adding a fresh window on top.
        let dialed = tokio::time::timeout(
            self.connect_timeout,
            dial_pipeline(
                &host,
                port,
                &sni,
                &self.allowlist,
                self.allow_private,
                self.enabled,
                &self.extra_roots,
            ),
        )
        .await
        .map_err(|_| EgressError::ConnectTimeout)
        .and_then(|r| r)?;

        let (input, output) = split_boxed(dialed);

        let conn = TcpEgressConnection {
            input: Some(input),
            output: Some(output),
            idle_timeout: self.idle_timeout,
        };
        self.table
            .push(conn)
            .map_err(|_| EgressError::Other(REASON_INTERNAL.to_string()))
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

/// What [`connect_and_handshake`] hands back: normally the TLS-terminated stream. The
/// `RawMutation` arm exists ONLY to let the anti-hollow `skip_tls_wrap` mutation (test /
/// `tcpegress-gate-mutation` feature) hand back the pre-handshake TCP stream instead — never
/// constructed in a shipped build.
enum DialedStream {
    // Boxed: a `TlsStream` is large relative to a bare `TcpStream`, and this enum is otherwise
    // short-lived (immediately split into the two boxed halves `TcpEgressConnection` stores).
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
    RawMutation(tokio::net::TcpStream),
}

// Manual (not derived) `Debug`: `tokio_rustls::client::TlsStream`/`TcpStream` don't implement it,
// and this is only ever needed for a test's `expect_err` message.
impl std::fmt::Debug for DialedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls(_) => f.write_str("DialedStream::Tls(..)"),
            #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
            Self::RawMutation(_) => f.write_str("DialedStream::RawMutation(..)"),
        }
    }
}

/// Resolve `host`, gate-check every candidate (the DNS-rebinding choke — see the module docs), and
/// connect + terminate TLS over the first of at most [`MAX_DIAL_CANDIDATES`] checked addresses to
/// succeed. Carries NO timeout of its own (Security review M1): [`tcp_egress::Host::connect_tls`]
/// wraps this ENTIRE call in one `connect_timeout`, so a slow resolve leaves correspondingly less
/// budget for the connect/handshake rather than adding a fresh window on top of it.
async fn dial_pipeline(
    host: &str,
    port: u16,
    sni: &str,
    allowlist: &[String],
    allow_private: bool,
    posture: bool,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<DialedStream, EgressError> {
    let checked = resolve_and_gate_tcp_egress(host, port, allowlist, allow_private, posture)
        .await
        .map_err(|e| match e {
            TcpEgressResolveError::DnsFailure => EgressError::DnsFailure,
            TcpEgressResolveError::RefusedByGate => EgressError::RefusedByGate,
        })?;
    // Security review M1: cap how many gate-checked candidates this dial ATTEMPTS — independent of
    // the shared time budget above, so a many-homed (or broad-CIDR-allowlisted) target can't fan
    // out an unbounded number of TCP SYNs for one guest call.
    let candidates = &checked[..checked.len().min(MAX_DIAL_CANDIDATES)];
    connect_and_handshake(candidates, sni, extra_roots).await
}

/// Connect to the first of the already-gate-CHECKED `addrs` to succeed, and terminate TLS (or, ONLY
/// under the `skip_tls_wrap` mutation, nothing) over that same connected socket. NEVER resolves
/// `sni`/any hostname again. Carries no timeout of its own — see [`dial_pipeline`]'s doc; it is
/// cancelled cleanly (a plain future drop) if the caller's single outer timeout fires at any point,
/// mid-loop or mid-handshake.
async fn connect_and_handshake(
    addrs: &[std::net::SocketAddr],
    sni: &str,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<DialedStream, EgressError> {
    let mut tcp_stream = None;
    for addr in addrs {
        if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
            tcp_stream = Some(s);
            break;
        }
    }
    // Security review L1: a coarse, fixed reason — never the raw `io::Error` text (which can echo
    // OS-specific detail or an internal address resolved from a domain allowlist entry).
    let tcp_stream =
        tcp_stream.ok_or_else(|| EgressError::ConnectFailed(REASON_CONNECT_FAILED.to_string()))?;

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
        .map_err(|_| EgressError::TlsFailure(REASON_TLS_CONFIG.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| EgressError::TlsFailure(REASON_INVALID_SNI.to_string()))?;
    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|_| EgressError::TlsFailure(REASON_TLS_HANDSHAKE.to_string()))?;
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

    /// `PLAN-handler-tcp-egress` Build A anti-hollow gate (mirrors the `tcp_egress_allowlist_gate` /
    /// `tcp_listener_dispatch_gate` #503 mutation-loop convention — this test does NOT toggle the
    /// mutation itself): a REAL loopback TLS server hands a plaintext greeting through
    /// `connect-tls` + `take-input` — proving the host actually dials, terminates TLS, and exposes
    /// decrypted bytes to the guest as `wasi:io`. Prints the grep-able marker `TCP-EGRESS TLS WRAP
    /// OK`. MUTATION-VERIFIED externally: the CI gate re-runs this EXACT test with
    /// `BOATRAMP_TCPEGRESS_TLS_MUTATION=skip_tls_wrap` set in the environment, which must make it
    /// FAIL (the client then skips its own handshake, so what arrives on the wire is the server's
    /// raw TLS handshake record, never the plaintext greeting) — proving the TLS wrap is
    /// load-bearing, not cosmetic. A plain `cargo test` run (the var unset) always takes the clean
    /// path.
    #[tokio::test]
    async fn tcpegress_tls_wrap_gate() {
        let (ca, chain, key) = ca_and_leaf();
        const GREETING: &[u8] = b"TCP-EGRESS TLS OK";
        let port = spawn_tls_server(chain, key, GREETING).await;
        let allow = [format!("127.0.0.1:{port}")];
        let allow_refs: Vec<&str> = allow.iter().map(String::as_str).collect();

        let dialed = dial_and_read(port, true, &allow_refs, std::slice::from_ref(&ca)).await;
        match dialed {
            Ok(bytes) => assert_eq!(
                bytes, GREETING,
                "a clean dial must terminate TLS and hand back the server's plaintext greeting \
                 (a failure here under BOATRAMP_TCPEGRESS_TLS_MUTATION=skip_tls_wrap is the \
                 EXPECTED mutation-verification outcome, not a real regression)"
            ),
            Err(e) => panic!("dial failed: {e}"),
        }
        println!("TCP-EGRESS TLS WRAP OK");
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
        // Security review L1: the payload is the fixed, coarse reason — never a raw `io::Error`
        // (which on most platforms would read something like "Connection refused (os error 61)").
        match err {
            EgressError::ConnectFailed(reason) => assert_eq!(reason, REASON_CONNECT_FAILED),
            other => panic!("expected ConnectFailed, got {other:?}"),
        }
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

    /// Security review M1 (the cap half): `dial_pipeline` only ever ATTEMPTS the first
    /// [`MAX_DIAL_CANDIDATES`] gate-checked addresses. Construct `MAX_DIAL_CANDIDATES` refused
    /// candidates (distinct LOW ports on loopback — ports 1.. are essentially never listened on in
    /// a test sandbox, so these refuse immediately, never hang) followed by ONE real listener as
    /// the `(MAX_DIAL_CANDIDATES + 1)`-th candidate: if the cap is respected, that listener is
    /// NEVER reached, so the whole dial still fails. A control run puts the SAME listener WITHIN
    /// the cap and confirms it IS reached (the dial then fails only at the TLS handshake, because
    /// the listener speaks no TLS — proving the TCP connect itself succeeded).
    ///
    /// Deliberately all on `127.0.0.1` (never a second loopback alias like `127.0.0.2`): macOS
    /// only auto-configures `127.0.0.1` on `lo0` — the rest of `127.0.0.0/8` needs an explicit
    /// `ifconfig … alias`, which a test must not depend on.
    #[tokio::test]
    async fn max_dial_candidates_caps_the_attempted_set() {
        // A real listener standing in for "a candidate that WOULD succeed if tried". Accepts and
        // immediately drops every connection — this test is about candidate-count capping, not
        // the handshake (covered by `tcpegress_tls_wrap_gate`/`tls_handshake_hang_times_out`).
        let good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((socket, _)) = good.accept().await {
                drop(socket);
            }
        });

        // `MAX_DIAL_CANDIDATES` low, almost-certainly-unused ports on loopback, then the good one
        // (its OS-assigned ephemeral port, necessarily distinct) as the candidate immediately
        // BEYOND the cap.
        let mut candidates: Vec<std::net::SocketAddr> = (1..=MAX_DIAL_CANDIDATES as u16)
            .map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)))
            .collect();
        assert_eq!(candidates.len(), MAX_DIAL_CANDIDATES);
        candidates.push(good_addr);

        let beyond_cap = &candidates[..candidates.len().min(MAX_DIAL_CANDIDATES)];
        let err = connect_and_handshake(beyond_cap, "localhost", &[])
            .await
            .expect_err(
                "every candidate WITHIN the cap is refused; the good one beyond it must never \
                 be attempted",
            );
        assert!(
            matches!(err, EgressError::ConnectFailed(_)),
            "beyond the cap, the dial must fail the same way as if the good candidate didn't \
             exist at all; got {err:?}"
        );

        // Control: move the good address to WITHIN the cap (replace the last refused entry) and
        // confirm it IS reached — the TCP connect succeeds, so the failure moves to the handshake.
        let mut within_cap = candidates[..MAX_DIAL_CANDIDATES - 1].to_vec();
        within_cap.push(good_addr);
        assert_eq!(within_cap.len(), MAX_DIAL_CANDIDATES);
        let err2 = connect_and_handshake(&within_cap, "localhost", &[])
            .await
            .expect_err("the good address speaks no TLS, so the handshake must fail");
        assert!(
            matches!(err2, EgressError::TlsFailure(_)),
            "a reachable-but-non-TLS peer within the cap must fail at the HANDSHAKE stage (proving \
             the connect itself succeeded), not ConnectFailed; got {err2:?}"
        );
    }

    /// Security review M1 (the shared-deadline half): the WHOLE `connect_tls` pipeline (resolve +
    /// gate-check + connect + handshake) is bounded by roughly ONE `connect_timeout`, not a sum of
    /// separate per-phase budgets — reusing the handshake-hang technique
    /// (`tls_handshake_hang_times_out`) as the one kind of "slow step" this test suite can simulate
    /// hermetically (a genuinely unresponsive TCP peer only fails on the OS's own SYN-retry timers,
    /// tens of seconds, so a true many-SLOW-candidate network blackhole can't be reproduced in a
    /// fast unit test — see [`max_dial_candidates_caps_the_attempted_set`] for the complementary
    /// fan-out-cap proof, and the module docs for why ONE `tokio::time::timeout` call site is now
    /// the whole story). Before the fix, the (here, trivially-fast) TCP connect and the handshake
    /// hang each had their OWN separate `connect_timeout` window, stacking to roughly 2x; now there
    /// is exactly one.
    #[tokio::test]
    async fn single_deadline_bounds_the_whole_pipeline_not_per_phase() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _keep_alive = listener;

        let allow = vec![format!("127.0.0.1:{port}")];
        let connect_timeout = Duration::from_millis(150);
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(allow),
            Arc::from(Vec::new()),
            connect_timeout,
            Duration::from_secs(5),
        );
        let started = std::time::Instant::now();
        let err = tcp_egress::Host::connect_tls(
            &mut host,
            "127.0.0.1".to_string(),
            port,
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("a hung handshake must still time out");
        let elapsed = started.elapsed();
        assert!(matches!(err, EgressError::ConnectTimeout), "{err:?}");
        // A generous ceiling (2x the budget), comfortably below what stacking a separate
        // connect-phase timeout and a separate handshake-phase timeout would have allowed under
        // the pre-fix code (which could reach ~2x `connect_timeout` even for this single-candidate
        // case, since the TCP connect itself has its own full timeout window before the
        // handshake's), while tolerant of ordinary scheduler jitter in CI.
        assert!(
            elapsed < connect_timeout * 2,
            "the whole pipeline must be bounded by roughly ONE connect_timeout \
             ({connect_timeout:?}), not stacked per-phase budgets — took {elapsed:?}"
        );
    }
}
