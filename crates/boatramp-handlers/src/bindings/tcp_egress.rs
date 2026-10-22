//! The host-terminated outbound-TLS **egress** binding (`boatramp:handlers/tcp-egress`,
//! `PLAN-handler-tcp-egress`, mailroom cap-req #15): the OUTBOUND mirror of the host-owned
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
//! `boatramp`'s `capability_token`) — no new grant kind anywhere in this stack. Build B's
//! `connect-plaintext` dial reuses the IDENTICAL gate + choke.
//!
//! # DNS-rebinding choke point (load-bearing)
//! `host` is resolved EXACTLY ONCE, inside [`crate::engine::resolve_and_gate_tcp_egress`]; each
//! resolved candidate address is checked individually through the gate, and [`connect_checked`]
//! below connects ONLY to an address already in that checked set — it never calls `lookup_host`
//! again. See that function's doc comment for the attack this closes.
//!
//! # One shared deadline, capped fan-out (Security review M1)
//! The WHOLE pipeline — resolve, gate-check every candidate, connect, and the TLS handshake — runs
//! under exactly ONE `connect_timeout` per dial (`connect-tls`/`connect-plaintext`'s own `timeout`
//! call is the only `tokio::time::timeout` call site in THAT path; `start-tls` gets its own, FRESH
//! one-timeout budget for the handshake, since it runs at an arbitrary later point chosen by the
//! guest), mirroring the `wasi:http` egress path's single-budget semantics: never a separate timeout
//! per gated candidate plus another for the handshake. An async host import can't be epoch-trapped,
//! so an unbounded pipeline would let a guest naming a many-homed (or broad-CIDR-allowlisted)
//! blackholed host pin a sync-lane slot for `(N+1)*connect_timeout` and fan out N TCP SYNs.
//! [`MAX_DIAL_CANDIDATES`] additionally caps how many gate-checked candidates one dial ever
//! attempts, independent of the time budget.
//!
//! # Build B: STARTTLS / opportunistic relay (`connect-plaintext` + `start-tls`)
//! Build A implements implicit TLS only (`connect-tls`, `verify-mode.strict`). Build B adds the
//! relay/STARTTLS path: [`tcp_egress::Host::connect_plaintext`] dials with NO TLS, handing the guest
//! a `connection` it drives in plaintext (via `take-input`/`take-output`) to speak a protocol's own
//! negotiation (e.g. SMTP `EHLO`/`STARTTLS`); [`tcp_egress::HostConnection::start_tls`] then upgrades
//! THAT SAME connection in place. Two things make this safe:
//!
//! 1. **Injection safety (the CVE-2011-0411 class, RFC 3207 §4).** [`PlaintextEgressInput`] reads
//!    directly off the raw socket with `try_read`/`readable()` and NO background task — unlike
//!    [`wasmtime_wasi::pipe::AsyncReadStream`] (used for the already-TLS phase, where read-ahead is
//!    harmless), nothing is ever consumed from the peer ahead of the guest's own `read`/`ready`
//!    cadence. So any bytes a peer pipelines immediately after its plaintext affirmative reply are
//!    STILL sitting unread on the wire when `start_tls` reclaims the raw halves — the TLS handshake
//!    reads them as its own first input, which fails to parse as a valid TLS record rather than ever
//!    reaching the guest as plaintext. See [`PlaintextEgressInput`]'s doc and
//!    `tcpegress_starttls_injection_safe` below.
//! 2. **Opportunistic gating (the load-bearing security decision).** `verify-mode.opportunistic`
//!    (RFC 7435 — accept any peer certificate, still verify the handshake signature) is honored ONLY
//!    by `start_tls`: [`opportunistic_relay_client_config`] is called from exactly one call site
//!    (`handshake_tls`'s `Opportunistic` arm) that `start_tls` alone reaches in a shipped build.
//!    `connect_tls` keeps its unconditional `return Err(UnsupportedVerifyMode)` for anything but
//!    `strict` — see its doc and `connect_tls_opportunistic_mutation_seam` below for the
//!    mutation-verified proof that this refusal, not the verifier's mere non-existence, is what
//!    stops a guest from downgrading the strict PULL path.

use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
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
            only_imports: [
                "connect-tls",
                "connect-plaintext",
                "[method]connection.shutdown-output",
                "[method]connection.start-tls",
            ],
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
/// stalling on per-chunk backpressure without buffering unboundedly. Used for the TLS-phase
/// `AsyncWriteStream` budget AND (Build B) as the plaintext phase's `check-write` permit / read
/// chunk cap — the plaintext negotiation is short-lived, so one shared size is plenty.
const TCP_EGRESS_WRITE_BUDGET: usize = 64 * 1024;

/// Cap on how many gate-CHECKED candidate addresses one dial (`connect-tls` or `connect-plaintext`)
/// ATTEMPTS (Security review M1) — independent of the shared `connect_timeout` budget (see the
/// module docs), this bounds the TCP-SYN fan-out a guest-named many-homed (or
/// broad-CIDR-allowlisted) target can cause for one call. A dual-stack-ish handful (4–8) covers
/// normal multi-homing without letting a pathological allowlist multiply the attempt count
/// unboundedly.
const MAX_DIAL_CANDIDATES: usize = 8;

/// Fixed, non-verbose reason strings for `connect-failed`/`tls-failure`/`other` (Security review
/// L1) — parity with the `wasi:http` egress path's generic `ConnectionRefused`/`TlsProtocolError`:
/// raw `io::Error`/rustls `Display` text (which can echo OS-specific detail, or an internal
/// address/port resolved from a domain allowlist entry) never reaches the guest.
const REASON_CONNECT_FAILED: &str = "connect failed";
const REASON_TLS_CONFIG: &str = "tls configuration error";
const REASON_INVALID_SNI: &str = "invalid sni";
const REASON_TLS_HANDSHAKE: &str = "tls handshake failed";
const REASON_INTERNAL: &str = "internal error";
/// `start-tls` was called on a `connect-tls`-originated (already implicit-TLS) connection — it only
/// ever applies to a `connect-plaintext` connection's pre-upgrade phase.
const REASON_NOT_PLAINTEXT: &str = "start-tls not valid on this connection";
/// `start-tls` was called a second time on a `connect-plaintext` connection that has already been
/// upgraded (or whose upgrade already failed and consumed the raw halves).
const REASON_ALREADY_UPGRADED: &str = "connection already upgraded or upgrade already attempted";

/// A boxed, type-erased `AsyncRead`/`AsyncWrite` half. `Box<dyn Trait>` is `Unpin` regardless of the
/// pointee, so [`TcpEgressConnection`] needs no `Pin` ceremony. Boxing (rather than a concrete
/// `tokio_rustls::client::TlsStream<TcpStream>` split half) is what lets the anti-hollow
/// `skip_tls_wrap` / `skip_start_tls_wrap` mutations substitute the RAW pre-TLS halves with the
/// identical field shape — never reached in a shipped build.
type BoxedRead = Box<dyn tokio::io::AsyncRead + Send + Unpin + 'static>;
type BoxedWrite = Box<dyn tokio::io::AsyncWrite + Send + Unpin + 'static>;

/// Enforces the `tcp-egress` per-dial READ/IDLE timeout directly inside `poll_read`/`poll_write`.
/// There is no outer watchdog loop for these streams (unlike the inbound conn lane's `select!` — a
/// guest drives `wasi:io` reads/writes on its own schedule, possibly long after the dial returned),
/// so the bound has to live INSIDE the adapter itself: each call restarts a deadline; if neither
/// progress (a read producing bytes/EOF, or `poll_write` accepting bytes) nor the inner future
/// resolves before the deadline fires, the call resolves a `TimedOut` io error — surfaced to the
/// guest as a stream error on its next read/write, exactly like an abrupt peer drop. Any progress
/// resets the clock. Generic over `T: Unpin`, so `Pin<Box<Sleep>>` + `T: Unpin` together make the
/// whole wrapper `Unpin` (no manual pin-projection needed). Used for the TLS phase only — the
/// plaintext phase (Build B) bounds its own `readable()`/`writable()` waits directly (see
/// [`PlaintextEgressInput`]/[`PlaintextEgressOutput`]).
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

/// Wraps a TLS-terminated write half so DROPPING the `output-stream` resource built from it (once
/// `take-output` has handed it off as a separate resource) still attempts a graceful TLS
/// `close_notify` — Build A had no path for this at all (the WIT `shutdown-output` method is only
/// effective BEFORE `take-output` runs; see `connection`'s doc). Best-effort, bounded by the
/// connection's idle timeout, and never surfaced as a guest-visible error (there is no error channel
/// for a `Drop`). If the guest itself drives a `poll_shutdown` to completion (e.g. a protocol that
/// explicitly half-closes before dropping), `inner` is already `None` by the time `Drop` runs, so
/// this never double-sends `close_notify`.
struct CloseNotifyOnDrop {
    inner: Option<BoxedWrite>,
    idle: Duration,
}

impl CloseNotifyOnDrop {
    fn new(inner: BoxedWrite, idle: Duration) -> Self {
        Self {
            inner: Some(inner),
            idle,
        }
    }
}

impl tokio::io::AsyncWrite for CloseNotifyOnDrop {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = std::pin::Pin::get_mut(self);
        match this.inner.as_mut() {
            Some(w) => std::pin::Pin::new(w).poll_write(cx, buf),
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tcp-egress: write after shutdown",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = std::pin::Pin::get_mut(self);
        match this.inner.as_mut() {
            Some(w) => std::pin::Pin::new(w).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = std::pin::Pin::get_mut(self);
        match this.inner.as_mut() {
            Some(w) => {
                let r = std::pin::Pin::new(w).poll_shutdown(cx);
                if r.is_ready() {
                    // The guest itself drove the close_notify to completion — nothing left for
                    // `Drop` to do.
                    this.inner = None;
                }
                r
            }
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for CloseNotifyOnDrop {
    fn drop(&mut self) {
        if let Some(mut w) = self.inner.take() {
            let idle = self.idle;
            tokio::spawn(async move {
                let _ =
                    tokio::time::timeout(idle, tokio::io::AsyncWriteExt::shutdown(&mut w)).await;
            });
        }
    }
}

/// Which dial produced a [`TcpEgressConnection`] — governs whether `start-tls` is even applicable.
#[derive(Debug)]
enum ConnKind {
    /// `connect-tls` (Build A): already TLS-terminated; `start-tls` is ALWAYS refused
    /// (`REASON_NOT_PLAINTEXT`) — the strict PULL path never downgrades, structurally.
    ImplicitTls,
    /// `connect-plaintext` (Build B): raw TCP until `start-tls` succeeds exactly once.
    Relay { upgraded: bool },
}

/// Per-write "could not finish synchronously" remainder + the raw write half, SHARED (see
/// [`PlaintextEgressInput`]'s doc for why) so `start_tls` can reclaim the half even after
/// `take-output` has handed a [`PlaintextEgressOutput`] to the guest.
struct PlaintextWriterState {
    /// `None` once reclaimed by `start_tls` (successfully or not) or closed.
    half: Option<OwnedWriteHalf>,
    /// Bytes accepted by `write()` that a non-blocking `try_write` loop couldn't fully send;
    /// drained opportunistically by `check_write`/`ready`.
    pending: Bytes,
}

/// The pre-upgrade raw TCP halves of a `connect-plaintext` connection, SHARED via `Arc<Mutex<_>>`
/// between [`TcpEgressConnection`]'s own bookkeeping and whatever [`PlaintextEgressInput`]/
/// [`PlaintextEgressOutput`] resources `take-input`/`take-output` have already handed the guest —
/// so `start_tls` can reclaim them via [`OwnedReadHalf::reunite`] even after they have been taken
/// out as separate `wasi:io` stream resources.
struct PlaintextHalves {
    read: Arc<tokio::sync::Mutex<Option<OwnedReadHalf>>>,
    write: Arc<tokio::sync::Mutex<PlaintextWriterState>>,
}

/// The host-dialed outbound connection a granted guest holds — either already TLS-terminated
/// (`connect-tls`, Build A) or, before a successful `start-tls`, a raw plaintext TCP connection
/// (`connect-plaintext`, Build B). Not constructible by the guest.
///
/// See the `connection` WIT resource's own doc for the full lifecycle (two phases for a
/// `connect-plaintext` connection; `take-input`/`take-output` callable once per phase).
pub struct TcpEgressConnection {
    kind: ConnKind,
    /// `Some` only in the pre-upgrade phase of a `Relay` connection.
    plaintext: Option<PlaintextHalves>,
    /// TLS-terminated halves: populated directly by `connect-tls`, or by a successful `start-tls`
    /// (which also clears `plaintext` and flips `ConnKind::Relay.upgraded` to `true`). `None` while
    /// a `Relay` connection is still in its plaintext phase.
    input: Option<BoxedRead>,
    output: Option<BoxedWrite>,
    /// Pre-upgrade `take-input`/`take-output` "callable once per phase" bookkeeping for the
    /// `plaintext` phase. The POST-upgrade (or `connect-tls`) phase needs no equivalent flags: it
    /// relies on `input`/`output`'s own `Option::take()` one-shot semantics.
    plaintext_input_taken: bool,
    plaintext_output_taken: bool,
    idle_timeout: Duration,
    /// The per-dial connect timeout, reused by `start_tls` as its OWN fresh handshake budget (it
    /// runs at an arbitrary later point chosen by the guest, long after the original dial's own
    /// timeout window closed). Unused by an `ImplicitTls` connection.
    connect_timeout: Duration,
    /// The operator's extra trust roots, reused by `start_tls`'s `strict` arm (kept here rather than
    /// threaded through the method call so `TcpEgressHost::start_tls` stays a thin dispatch). Unused
    /// by an `ImplicitTls` connection (its TLS config was already built at `connect_tls` time).
    extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
}

impl TcpEgressConnection {
    fn new_implicit_tls(input: BoxedRead, output: BoxedWrite, idle_timeout: Duration) -> Self {
        Self {
            kind: ConnKind::ImplicitTls,
            plaintext: None,
            input: Some(input),
            output: Some(output),
            plaintext_input_taken: false,
            plaintext_output_taken: false,
            idle_timeout,
            connect_timeout: Duration::ZERO,
            extra_roots: Arc::from(Vec::new()),
        }
    }

    fn new_relay(
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
        idle_timeout: Duration,
        connect_timeout: Duration,
        extra_roots: Arc<[rustls::pki_types::CertificateDer<'static>]>,
    ) -> Self {
        Self {
            kind: ConnKind::Relay { upgraded: false },
            plaintext: Some(PlaintextHalves {
                read: Arc::new(tokio::sync::Mutex::new(Some(read))),
                write: Arc::new(tokio::sync::Mutex::new(PlaintextWriterState {
                    half: Some(write),
                    pending: Bytes::new(),
                })),
            }),
            input: None,
            output: None,
            plaintext_input_taken: false,
            plaintext_output_taken: false,
            idle_timeout,
            connect_timeout,
            extra_roots,
        }
    }

    fn take_input(&mut self) -> Option<DynInputStream> {
        if let Some(pt) = &self.plaintext {
            if self.plaintext_input_taken {
                return None;
            }
            self.plaintext_input_taken = true;
            return Some(Box::new(PlaintextEgressInput {
                half: pt.read.clone(),
                idle_timeout: self.idle_timeout,
            }) as DynInputStream);
        }
        let idle = self.idle_timeout;
        self.input.take().map(|r| {
            Box::new(wasmtime_wasi::pipe::AsyncReadStream::new(IdleTimeout::new(
                r, idle,
            ))) as DynInputStream
        })
    }

    fn take_output(&mut self) -> Option<DynOutputStream> {
        if let Some(pt) = &self.plaintext {
            if self.plaintext_output_taken {
                return None;
            }
            self.plaintext_output_taken = true;
            return Some(Box::new(PlaintextEgressOutput {
                state: pt.write.clone(),
                idle_timeout: self.idle_timeout,
            }) as DynOutputStream);
        }
        let idle = self.idle_timeout;
        self.output.take().map(|w| {
            Box::new(wasmtime_wasi::pipe::AsyncWriteStream::new(
                TCP_EGRESS_WRITE_BUDGET,
                IdleTimeout::new(CloseNotifyOnDrop::new(w, idle), idle),
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
        if let Some(pt) = &self.plaintext {
            let mut st = pt.write.lock().await;
            if let Some(mut half) = st.half.take() {
                let _ = tokio::time::timeout(
                    self.idle_timeout,
                    tokio::io::AsyncWriteExt::shutdown(&mut half),
                )
                .await;
            }
            return;
        }
        if let Some(mut w) = self.output.take() {
            let _ = tokio::time::timeout(
                self.idle_timeout,
                tokio::io::AsyncWriteExt::shutdown(&mut w),
            )
            .await;
        }
    }

    /// Upgrade a `connect-plaintext` connection to TLS in place (Build B) — see the WIT
    /// `connection.start-tls` doc for the full contract (opportunistic gating + injection safety).
    ///
    /// Reclaims the raw TCP halves via [`OwnedReadHalf::reunite`] regardless of whether
    /// `take-input`/`take-output` already handed them to the guest as separate resources — both
    /// sides are SHARED (`Arc<Mutex<_>>`) for exactly this reason. Runs the handshake under a FRESH
    /// `connect_timeout` window (the original dial's own timeout already closed by the time the
    /// guest gets around to calling this).
    ///
    /// On a FAILED upgrade attempt the raw halves have already been consumed (reunited and handed
    /// to the failed handshake, which drops — and so closes — them): the connection cannot fall back
    /// to plaintext after a failed `start-tls` (that would itself be a downgrade oracle). The guest
    /// must treat any `start-tls` error as fatal and drop the connection.
    async fn start_tls(&mut self, sni: &str, verify: VerifyMode) -> Result<(), EgressError> {
        match &self.kind {
            ConnKind::ImplicitTls => {
                return Err(EgressError::Other(REASON_NOT_PLAINTEXT.to_string()));
            }
            ConnKind::Relay { upgraded: true } => {
                return Err(EgressError::Other(REASON_ALREADY_UPGRADED.to_string()));
            }
            ConnKind::Relay { upgraded: false } => {}
        }
        let Some(pt) = &self.plaintext else {
            return Err(EgressError::Other(REASON_INTERNAL.to_string()));
        };

        let tcp = {
            let mut rguard = pt.read.lock().await;
            let mut wguard = pt.write.lock().await;
            let rhalf = rguard
                .take()
                .ok_or_else(|| EgressError::Other(REASON_ALREADY_UPGRADED.to_string()))?;
            let whalf = wguard
                .half
                .take()
                .ok_or_else(|| EgressError::Other(REASON_ALREADY_UPGRADED.to_string()))?;
            // Injection safety (see the module + WIT docs): any bytes a peer pipelined past its
            // plaintext affirmative reply are STILL sitting unread on the wire at this point —
            // neither `PlaintextEgressInput`/`PlaintextEgressOutput` ever buffered ahead of the
            // guest's own calls. `reunite` hands back the SAME socket; the handshake below reads
            // from it going forward, so those bytes become the TLS record parser's own first input.
            rhalf
                .reunite(whalf)
                .map_err(|_| EgressError::Other(REASON_INTERNAL.to_string()))?
        };

        // ANTI-HOLLOW MUTATION SEAM (`tcpegress-gate-mutation` / cfg(test) only — NEVER in a shipped
        // build): `skip_start_tls_wrap` hands the SAME raw (unencrypted) halves right back as if
        // "upgraded", with no handshake at all, so the CI gate can prove a test driving a REAL TLS
        // round trip through `start-tls` goes RED when the wrap is skipped.
        if tcpegress_tls_mutation().as_deref() == Some("skip_start_tls_wrap") {
            #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
            {
                let (r, w) = tokio::io::split(tcp);
                self.input = Some(Box::new(r));
                self.output = Some(Box::new(w));
                self.plaintext = None;
                if let ConnKind::Relay { upgraded } = &mut self.kind {
                    *upgraded = true;
                }
                return Ok(());
            }
        }

        let tls_stream = tokio::time::timeout(
            self.connect_timeout,
            handshake_tls(tcp, sni, verify, &self.extra_roots),
        )
        .await
        .map_err(|_| EgressError::ConnectTimeout)
        .and_then(|r| r)?;

        let (r, w) = tokio::io::split(tls_stream);
        self.input = Some(Box::new(r));
        self.output = Some(Box::new(w));
        self.plaintext = None;
        if let ConnKind::Relay { upgraded } = &mut self.kind {
            *upgraded = true;
        }
        Ok(())
    }
}

/// The guest-facing `input-stream` for the PRE-upgrade (plaintext) phase of a `connect-plaintext`
/// connection: reads directly off the raw TCP half via `try_read`/`readable()` with NO background
/// task — mirrors wasmtime-wasi's OWN `wasi:sockets` `TcpReadStream` (same pattern, see
/// `wasmtime-wasi`'s `tcp.rs`), just over a SHARED cell so `start_tls` can reach the half even after
/// it has been taken.
///
/// This is the structural property Build B's injection safety relies on: the host NEVER consumes a
/// byte from the peer ahead of what THIS call (driven by the guest's own `read`/`ready` cadence)
/// asks for — there is no background buffering, unlike [`wasmtime_wasi::pipe::AsyncReadStream`]
/// (used for the already-TLS phase, where read-ahead is harmless). So whatever the peer sent that
/// neither the guest nor the host has read yet simply stays in the kernel socket buffer until
/// `start_tls` reclaims the raw halves and hands them to the TLS handshake — which treats any such
/// bytes as its own (encrypted-channel) protocol input, never as plaintext handed to the guest.
struct PlaintextEgressInput {
    half: Arc<tokio::sync::Mutex<Option<OwnedReadHalf>>>,
    idle_timeout: Duration,
}

#[wasmtime_wasi::async_trait]
impl wasmtime_wasi::InputStream for PlaintextEgressInput {
    fn read(&mut self, size: usize) -> wasmtime_wasi::StreamResult<Bytes> {
        let Ok(mut guard) = self.half.try_lock() else {
            // Serialized per-invocation guest calls make concurrent access unreachable in
            // practice; treat it as "nothing ready yet" rather than trap.
            return Ok(Bytes::new());
        };
        let Some(half) = guard.as_ref() else {
            return Err(wasmtime_wasi::StreamError::Closed);
        };
        if size == 0 {
            return Ok(Bytes::new());
        }
        let mut buf = BytesMut::zeroed(size.min(TCP_EGRESS_WRITE_BUDGET));
        match half.try_read(&mut buf) {
            // A 0-byte read indicates the peer closed its write side.
            Ok(0) => {
                *guard = None;
                Err(wasmtime_wasi::StreamError::Closed)
            }
            Ok(n) => {
                buf.truncate(n);
                Ok(buf.freeze())
            }
            // Differentiates "nothing ready right now" from a closed/errored stream, exactly like
            // wasmtime-wasi's own `TcpReader::read`.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Bytes::new()),
            Err(e) => {
                *guard = None;
                Err(wasmtime_wasi::StreamError::LastOperationFailed(e.into()))
            }
        }
    }
}

#[wasmtime_wasi::async_trait]
impl wasmtime_wasi::Pollable for PlaintextEgressInput {
    async fn ready(&mut self) {
        let guard = self.half.lock().await;
        if let Some(half) = guard.as_ref() {
            // Best-effort bound: see `IdleTimeout`'s doc for why a silent peer must not pend this
            // forever. A timeout here is never surfaced as an error directly — the NEXT `read()`
            // call just observes "still nothing ready" (or, if the socket is actually dead, the
            // real I/O error).
            let _ = tokio::time::timeout(self.idle_timeout, half.readable()).await;
        }
    }
}

/// The guest-facing `output-stream` for the PRE-upgrade (plaintext) phase of a `connect-plaintext`
/// connection. Mirrors [`PlaintextEgressInput`]'s "no background task" discipline (not strictly
/// required for injection safety on the write side, but keeps BOTH halves of the plaintext phase on
/// the same simple, auditable model as wasmtime-wasi's own `wasi:sockets` `TcpWriteStream`).
struct PlaintextEgressOutput {
    state: Arc<tokio::sync::Mutex<PlaintextWriterState>>,
    idle_timeout: Duration,
}

impl PlaintextEgressOutput {
    /// Drain as much of `pending` as a non-blocking `try_write` loop allows. Returns `Ok(())`
    /// whether or not it fully drained (the caller checks `pending.is_empty()`); `Err` only for a
    /// real I/O failure, at which point the caller tears the connection down.
    fn try_drain(half: &OwnedWriteHalf, pending: &mut Bytes) -> std::io::Result<()> {
        while !pending.is_empty() {
            match half.try_write(pending) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "tcp-egress plaintext write returned 0",
                    ));
                }
                Ok(n) => {
                    let _ = pending.split_to(n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[wasmtime_wasi::async_trait]
impl wasmtime_wasi::OutputStream for PlaintextEgressOutput {
    fn write(&mut self, bytes: Bytes) -> wasmtime_wasi::StreamResult<()> {
        let Ok(mut st) = self.state.try_lock() else {
            return Err(wasmtime_wasi::StreamError::trap(
                "concurrent access to resource not supported",
            ));
        };
        let Some(half) = st.half.as_ref() else {
            return Err(wasmtime_wasi::StreamError::Closed);
        };
        if !st.pending.is_empty() {
            // The WASI contract requires calling `check-write` (which would have reported 0) before
            // writing again while bytes are still queued — mirrors wasmtime-wasi's own
            // `TcpWriter::write`.
            return Err(wasmtime_wasi::StreamError::trap(
                "unpermitted: must call check_write first",
            ));
        }
        let mut remaining = bytes;
        match Self::try_drain(half, &mut remaining) {
            Ok(()) => {
                st.pending = remaining;
                Ok(())
            }
            Err(e) => {
                st.half = None;
                Err(wasmtime_wasi::StreamError::LastOperationFailed(e.into()))
            }
        }
    }

    fn flush(&mut self) -> wasmtime_wasi::StreamResult<()> {
        let Ok(st) = self.state.try_lock() else {
            return Err(wasmtime_wasi::StreamError::trap(
                "concurrent access to resource not supported",
            ));
        };
        // No host-side buffering beyond `pending` (already opportunistically drained by
        // `check_write`/`ready`) — a no-op unless the stream is already closed.
        if st.half.is_none() {
            return Err(wasmtime_wasi::StreamError::Closed);
        }
        Ok(())
    }

    fn check_write(&mut self) -> wasmtime_wasi::StreamResult<usize> {
        let Ok(mut st) = self.state.try_lock() else {
            return Err(wasmtime_wasi::StreamError::trap(
                "concurrent access to resource not supported",
            ));
        };
        if st.half.is_none() {
            return Err(wasmtime_wasi::StreamError::Closed);
        }
        if !st.pending.is_empty() {
            // `half` is TAKEN (not just borrowed) for the duration of the drain attempt — a fresh
            // owned local, never a borrow of `st` itself — so there is no conflict with the
            // simultaneous `&mut st.pending`/`st.half = ...` field accesses below.
            let half = st.half.take().expect("checked Some above");
            let mut pending = std::mem::take(&mut st.pending);
            let result = Self::try_drain(&half, &mut pending);
            st.pending = pending;
            match result {
                Ok(()) => st.half = Some(half),
                Err(e) => return Err(wasmtime_wasi::StreamError::LastOperationFailed(e.into())),
            }
            if !st.pending.is_empty() {
                return Ok(0);
            }
        }
        Ok(TCP_EGRESS_WRITE_BUDGET)
    }
}

#[wasmtime_wasi::async_trait]
impl wasmtime_wasi::Pollable for PlaintextEgressOutput {
    async fn ready(&mut self) {
        let mut st = self.state.lock().await;
        if st.pending.is_empty() || st.half.is_none() {
            return;
        }
        {
            let half_ref = st.half.as_ref().expect("checked Some above");
            let _ = tokio::time::timeout(self.idle_timeout, half_ref.writable()).await;
        }
        if st.half.is_none() {
            return;
        }
        let half = st.half.take().expect("checked Some above");
        let mut pending = std::mem::take(&mut st.pending);
        let result = Self::try_drain(&half, &mut pending);
        st.pending = pending;
        if result.is_ok() {
            st.half = Some(half);
        }
        // On error, `half` is dropped here (closing the socket) and `st.half` stays `None`.
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
        // Opportunistic gating (the load-bearing security decision, Build B): `connect-tls` (the
        // strict PULL path) refuses anything but `strict`, UNCONDITIONALLY in a shipped build. The
        // `admit_opportunistic_on_pull` seam below is a dead branch there (`tcpegress_tls_mutation()`
        // always returns `None`) — it exists ONLY so the CI anti-hollow gate can prove THIS refusal,
        // not the relaxed verifier's mere non-existence, is what stops a guest downgrading this
        // path. See `connect_tls_opportunistic_mutation_seam` below.
        if !matches!(verify, VerifyMode::Strict)
            && tcpegress_tls_mutation().as_deref() != Some("admit_opportunistic_on_pull")
        {
            return Err(EgressError::UnsupportedVerifyMode);
        }

        // Security review M1: the WHOLE resolve + gate-check + connect + handshake pipeline runs
        // under exactly ONE `connect_timeout` — this is the ONLY `tokio::time::timeout` call site
        // in THIS dial path (see the module docs).
        let dialed = tokio::time::timeout(
            self.connect_timeout,
            dial_pipeline(
                &host,
                port,
                &sni,
                &self.allowlist,
                self.allow_private,
                self.enabled,
                verify,
                &self.extra_roots,
            ),
        )
        .await
        .map_err(|_| EgressError::ConnectTimeout)
        .and_then(|r| r)?;

        let (input, output) = split_boxed(dialed);
        let conn = TcpEgressConnection::new_implicit_tls(input, output, self.idle_timeout);
        self.table
            .push(conn)
            .map_err(|_| EgressError::Other(REASON_INTERNAL.to_string()))
    }

    async fn connect_plaintext(
        &mut self,
        host: String,
        port: u16,
    ) -> Result<Resource<TcpEgressConnection>, EgressError> {
        // Same single-deadline discipline as `connect_tls` (Security review M1), over the SAME
        // reused gate + DNS-rebinding choke — just no handshake at this stage.
        let tcp = tokio::time::timeout(
            self.connect_timeout,
            dial_plaintext_pipeline(
                &host,
                port,
                &self.allowlist,
                self.allow_private,
                self.enabled,
            ),
        )
        .await
        .map_err(|_| EgressError::ConnectTimeout)
        .and_then(|r| r)?;

        let (read_half, write_half) = tcp.into_split();
        let conn = TcpEgressConnection::new_relay(
            read_half,
            write_half,
            self.idle_timeout,
            self.connect_timeout,
            self.extra_roots.clone(),
        );
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

    async fn start_tls(
        &mut self,
        self_: Resource<TcpEgressConnection>,
        sni: String,
        verify: VerifyMode,
    ) -> Result<(), EgressError> {
        let conn = self
            .table
            .get_mut(&self_)
            .expect("tcp-egress connection resource handle must be valid");
        conn.start_tls(&sni, verify).await
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

/// Connect to the first of the already-gate-CHECKED `addrs` to succeed. NEVER resolves any hostname
/// again. Carries no timeout of its own — the caller's single outer timeout bounds it; cancelled
/// cleanly (a plain future drop) if that timeout fires mid-loop.
async fn connect_checked(
    addrs: &[std::net::SocketAddr],
) -> Result<tokio::net::TcpStream, EgressError> {
    for addr in addrs {
        if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
            return Ok(s);
        }
    }
    // Security review L1: a coarse, fixed reason — never the raw `io::Error` text (which can echo
    // OS-specific detail or an internal address resolved from a domain allowlist entry).
    Err(EgressError::ConnectFailed(
        REASON_CONNECT_FAILED.to_string(),
    ))
}

/// Perform the TLS CLIENT handshake over an already-connected `io` (a fresh `TcpStream` for
/// `connect-tls`'s dial, or the reunited raw socket for `start-tls`'s upgrade) — the ONE place
/// either path builds a `ClientConfig` and runs `TlsConnector::connect`. `verify` picks the trust
/// model: `strict` reuses [`guest_egress_client_config`] (webpki ⊕ operator `extra_roots`, full
/// verification — the SAME config a guest's own `wasi:http` egress gets); `opportunistic` builds
/// [`opportunistic_relay_client_config`] (RFC 7435 — accept any peer certificate, still verify the
/// handshake signature). Carries no timeout of its own; the caller bounds it.
async fn handshake_tls<IO>(
    io: IO,
    sni: &str,
    verify: VerifyMode,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<tokio_rustls::client::TlsStream<IO>, EgressError>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let tls_config = match verify {
        VerifyMode::Strict => guest_egress_client_config(extra_roots)
            .map_err(|_| EgressError::TlsFailure(REASON_TLS_CONFIG.to_string()))?,
        VerifyMode::Opportunistic => opportunistic_relay_client_config()
            .map_err(|_| EgressError::TlsFailure(REASON_TLS_CONFIG.to_string()))?,
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| EgressError::TlsFailure(REASON_INVALID_SNI.to_string()))?;
    connector
        .connect(server_name, io)
        .await
        .map_err(|_| EgressError::TlsFailure(REASON_TLS_HANDSHAKE.to_string()))
}

/// The relaxed/pinned rustls `ClientConfig` for the `start-tls` relay path ONLY (RFC 7435
/// opportunistic encryption, Build B) — accepts ANY peer certificate (self-signed, expired,
/// hostname-mismatched, unchained) without hard-failing identity verification, while still
/// cryptographically verifying the TLS handshake SIGNATURE against the offered certificate's own
/// public key (via rustls's own [`rustls::crypto::verify_tls12_signature`]/
/// [`rustls::crypto::verify_tls13_signature`]) — so a peer with no matching private key at all still
/// cannot complete a handshake; only the peer's IDENTITY is left unauthenticated, not the
/// handshake's cryptographic integrity. SEPARATE from [`guest_egress_client_config`] (which
/// `connect-tls` ALWAYS uses). Called from exactly one place, [`handshake_tls`]'s `Opportunistic`
/// arm — see the opportunistic-gating doc on `TcpEgressHost::connect_tls` / `connection.start-tls`.
fn opportunistic_relay_client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algs = provider.signature_verification_algorithms;
    rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map(|b| {
            b.dangerous()
                .with_custom_certificate_verifier(Arc::new(OpportunisticServerCertVerifier {
                    algs,
                }))
                .with_no_client_auth()
        })
}

/// RFC 7435 opportunistic verifier: accepts any peer identity, still enforces real handshake
/// signatures — see [`opportunistic_relay_client_config`]'s doc.
#[derive(Debug)]
struct OpportunisticServerCertVerifier {
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for OpportunisticServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // RFC 7435: accept ANY peer certificate — self-signed, expired, hostname-mismatched,
        // unchained — never hard-fail identity verification.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Resolve `host`, gate-check every candidate (the DNS-rebinding choke — see the module docs), and
/// connect + terminate TLS over the first of at most [`MAX_DIAL_CANDIDATES`] checked addresses to
/// succeed. Carries NO timeout of its own (Security review M1): the caller wraps this ENTIRE call in
/// one `connect_timeout`, so a slow resolve leaves correspondingly less budget for the
/// connect/handshake rather than adding a fresh window on top of it.
#[allow(clippy::too_many_arguments)]
async fn dial_pipeline(
    host: &str,
    port: u16,
    sni: &str,
    allowlist: &[String],
    allow_private: bool,
    posture: bool,
    verify: VerifyMode,
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
    connect_and_handshake(candidates, sni, verify, extra_roots).await
}

/// Build B's plaintext counterpart to [`dial_pipeline`]: the SAME resolve + gate-check + connect
/// pipeline, with NO handshake — the guest drives the plaintext protocol itself over the returned
/// raw `TcpStream`'s (later-split) halves.
async fn dial_plaintext_pipeline(
    host: &str,
    port: u16,
    allowlist: &[String],
    allow_private: bool,
    posture: bool,
) -> Result<tokio::net::TcpStream, EgressError> {
    let checked = resolve_and_gate_tcp_egress(host, port, allowlist, allow_private, posture)
        .await
        .map_err(|e| match e {
            TcpEgressResolveError::DnsFailure => EgressError::DnsFailure,
            TcpEgressResolveError::RefusedByGate => EgressError::RefusedByGate,
        })?;
    let candidates = &checked[..checked.len().min(MAX_DIAL_CANDIDATES)];
    connect_checked(candidates).await
}

/// Connect to the first of the already-gate-CHECKED `addrs` to succeed, and terminate TLS (or, ONLY
/// under the `skip_tls_wrap` mutation, nothing) over that same connected socket.
async fn connect_and_handshake(
    addrs: &[std::net::SocketAddr],
    sni: &str,
    verify: VerifyMode,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<DialedStream, EgressError> {
    let tcp_stream = connect_checked(addrs).await?;

    // ANTI-HOLLOW MUTATION SEAM (`tcpegress-gate-mutation` / cfg(test) only — NEVER in a shipped
    // build, since the feature is never enabled there): `skip_tls_wrap` hands back the RAW TCP
    // stream with NO TLS handshake at all, so the CI gate can prove a test driving a REAL TLS round
    // trip through this path goes RED when the wrap is skipped. Not a backdoor — it only reads a
    // test env var, gated by a cargo feature that is never part of a shipped build.
    if tcpegress_tls_mutation().as_deref() == Some("skip_tls_wrap") {
        #[cfg(any(test, feature = "tcpegress-gate-mutation"))]
        return Ok(DialedStream::RawMutation(tcp_stream));
    }

    let tls_stream = handshake_tls(tcp_stream, sni, verify, extra_roots).await?;
    Ok(DialedStream::Tls(Box::new(tls_stream)))
}

/// The active TLS-wrap mutation (`PLAN-handler-tcp-egress` anti-hollow gate), or `None`. Present
/// ONLY under `cfg(test)` (this crate's own unit gate) or the `tcpegress-gate-mutation` feature (the
/// SAME lane the existing `tcp_connect_decision` gate-mutation uses); a shipped build has NEITHER,
/// so every check this file gates on it is unconditional. Recognized values: `skip_tls_wrap`
/// (`connect-tls` hands back the raw, un-terminated stream), `skip_start_tls_wrap` (`start-tls`
/// "upgrades" without ever handshaking), and `admit_opportunistic_on_pull` (`connect-tls` no longer
/// refuses `verify-mode.opportunistic`). NOT a backdoor — it only reads a test env var.
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

    /// A SELF-signed, UNCHAINED leaf (no CA at all) — for the opportunistic-mode tests, where the
    /// whole point is a certificate `guest_egress_client_config`'s strict verification would reject.
    fn self_signed_leaf() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        use rcgen::{CertificateParams, KeyPair};
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    fn server_tls_config(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> rustls::ServerConfig {
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap()
    }

    /// A one-shot loopback rustls TLS server: accepts one connection, completes the handshake, then
    /// writes `greeting` and closes. Returns its bound port.
    async fn spawn_tls_server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        greeting: &'static [u8],
    ) -> u16 {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls_config(chain, key)));
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

    /// A STARTTLS-shaped loopback peer: writes `plaintext_greeting` in PLAIN TCP first, THEN (on the
    /// SAME connection) performs the TLS server handshake and writes `tls_greeting` encrypted. Models
    /// a real relay: "220 Ready\r\n" in the clear, then the client upgrades.
    async fn spawn_plaintext_then_tls_server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        plaintext_greeting: &'static [u8],
        tls_greeting: &'static [u8],
    ) -> u16 {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls_config(chain, key)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut tcp, _)) = listener.accept().await {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut tcp, plaintext_greeting).await;
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut tls, tls_greeting).await;
                    let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
                }
            }
        });
        port
    }

    /// A malicious/misbehaving STARTTLS-shaped peer: writes `plaintext_greeting` immediately
    /// followed (same write call, so coalesced on the wire) by `injected` — bytes a well-behaved
    /// peer would never send before receiving a ClientHello. Never performs any TLS handshake at
    /// all (the point of the injection-safety test is that the host's handshake attempt chokes on
    /// `injected`, not that a legitimate handshake later succeeds).
    async fn spawn_injecting_peer(
        plaintext_greeting: &'static [u8],
        injected: &'static [u8],
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut tcp, _)) = listener.accept().await {
                let mut both = Vec::with_capacity(plaintext_greeting.len() + injected.len());
                both.extend_from_slice(plaintext_greeting);
                both.extend_from_slice(injected);
                let _ = tokio::io::AsyncWriteExt::write_all(&mut tcp, &both).await;
                // Keep the socket open a little so the client's handshake attempt has something to
                // read; then just let it drop (no TLS response ever comes).
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        port
    }

    fn host_fixture<'a>(table: &'a mut ResourceTable, port: u16) -> TcpEgressHost<'a> {
        TcpEgressHost::new(
            table,
            true,
            true,
            Arc::from(vec![format!("127.0.0.1:{port}")]),
            Arc::from(Vec::new()),
            Duration::from_secs(5),
            Duration::from_millis(500),
        )
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
        read_stream_to_eof(&mut host, conn_res).await
    }

    /// Reconstruct a fresh handle to the SAME underlying table entry as `conn_res` — `Resource<T>`
    /// is intentionally `!Copy` (the component ABI's own atomic take/borrow tracking cares about
    /// move semantics), but these tests dispatch host methods directly (no real guest in the loop),
    /// where only the plain `rep()` index is ever consulted (`ResourceTable::get_mut` just reads
    /// `key.rep()`) — so re-deriving a handle from the same `rep` is exactly equivalent to the
    /// original for this harness's purposes, letting one test call MULTIPLE host methods
    /// (`take-input`, `start-tls`, `take-input` again, ...) against the one connection resource.
    fn reborrow(conn_res: &Resource<TcpEgressConnection>) -> Resource<TcpEgressConnection> {
        Resource::new_own(conn_res.rep())
    }

    /// Read a taken `input-stream` resource to EOF/error, returning whatever bytes arrived.
    async fn read_stream_to_eof(
        host: &mut TcpEgressHost<'_>,
        conn_res: Resource<TcpEgressConnection>,
    ) -> Result<Vec<u8>, String> {
        let in_res = tcp_egress::HostConnection::take_input(host, conn_res)
            .expect("input not yet taken for this phase");
        let stream: &mut DynInputStream = host.table.get_mut(&in_res).unwrap();
        let mut buf = Vec::new();
        loop {
            match stream.read(4096) {
                Ok(bytes) if bytes.is_empty() => stream.ready().await,
                Ok(bytes) => buf.extend_from_slice(&bytes),
                Err(wasmtime_wasi::StreamError::Closed) => break,
                Err(e) => return Err(format!("read failed after {} bytes: {e:?}", buf.len())),
            }
        }
        Ok(buf)
    }

    /// Read EXACTLY `n` bytes from a taken `input-stream` resource (never more) — models a careful
    /// guest's own line-based protocol reader, which asks for only as much as it expects.
    async fn read_exact_n(
        host: &mut TcpEgressHost<'_>,
        in_res: &Resource<DynInputStream>,
        n: usize,
    ) -> Vec<u8> {
        let stream: &mut DynInputStream = host.table.get_mut(in_res).unwrap();
        let mut buf = Vec::with_capacity(n);
        while buf.len() < n {
            match stream.read(n - buf.len()) {
                Ok(bytes) if bytes.is_empty() => stream.ready().await,
                Ok(bytes) => buf.extend_from_slice(&bytes),
                Err(e) => panic!("read_exact_n failed after {} bytes: {e:?}", buf.len()),
            }
        }
        buf
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

    /// Build A implements `verify-mode.strict` only (on the PULL path); `opportunistic` is refused
    /// cleanly, never silently downgraded to a relaxed verifier. Build B keeps this refusal
    /// UNCONDITIONAL on `connect-tls` — see `connect_tls_opportunistic_mutation_seam` for the
    /// mutation-verified proof that this check (not the relaxed verifier's absence) is load-bearing.
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
        .expect_err("opportunistic must be refused on connect-tls");
        assert!(matches!(err, EgressError::UnsupportedVerifyMode));
    }

    /// `PLAN-handler-tcp-egress` Build B anti-hollow gate for the OPPORTUNISTIC-GATING structural
    /// enforcement — the critical security decision of this build. Without the mutation, this is
    /// simply the SAME refusal as `opportunistic_verify_mode_is_refused` above (a real TLS server is
    /// still spun up, just never dialed). MUTATION-VERIFIED (the #503 convention): the CI gate
    /// re-runs this EXACT test with `BOATRAMP_TCPEGRESS_TLS_MUTATION=admit_opportunistic_on_pull`
    /// set, which must make `connect-tls(..., opportunistic)` SUCCEED against a peer presenting a
    /// SELF-SIGNED, UNCHAINED certificate the strict path would reject — proving the explicit
    /// refusal in `connect_tls` (not the relaxed verifier's mere non-existence) is the ONLY thing
    /// stopping a guest from downgrading the strict PULL path's verification.
    #[tokio::test]
    async fn connect_tls_opportunistic_mutation_seam() {
        let (chain, key) = self_signed_leaf();
        const GREETING: &[u8] = b"TCP-EGRESS OPPORTUNISTIC MUTATION OK";
        let port = spawn_tls_server(chain, key, GREETING).await;
        let mut table = ResourceTable::new();
        let mut host = host_fixture(&mut table, port);

        let result = tcp_egress::Host::connect_tls(
            &mut host,
            "127.0.0.1".to_string(),
            port,
            "localhost".to_string(),
            VerifyMode::Opportunistic,
        )
        .await;

        if tcpegress_tls_mutation().as_deref() == Some("admit_opportunistic_on_pull") {
            let conn_res = result.expect(
                "under the mutation, opportunistic must be ADMITTED on connect-tls (proving the \
                 explicit refusal is what normally stops it)",
            );
            let bytes = read_stream_to_eof(&mut host, conn_res)
                .await
                .expect("mutated opportunistic dial must still complete a real handshake");
            assert_eq!(bytes, GREETING);
            println!(
                "TCP-EGRESS OPPORTUNISTIC-ON-PULL MUTATION ADMITTED (expected only under the \
                 mutation seam)"
            );
        } else {
            let err =
                result.expect_err("without the mutation, opportunistic must still be refused");
            assert!(matches!(err, EgressError::UnsupportedVerifyMode));
        }
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
        let err = connect_and_handshake(beyond_cap, "localhost", VerifyMode::Strict, &[])
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
        let err2 = connect_and_handshake(&within_cap, "localhost", VerifyMode::Strict, &[])
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

    /// Build B gate reuse: `connect-plaintext` goes through the IDENTICAL `egress_allowlist` + SSRF
    /// + posture gate as `connect-tls` (same DNS-rebinding choke, `resolve_and_gate_tcp_egress`) —
    /// no separate, possibly-weaker, gate for the relay path.
    #[tokio::test]
    async fn connect_plaintext_gate_reuse_denies_unallowlisted_and_private_targets() {
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            false,
            Arc::from(vec!["93.184.216.34:587".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let err = tcp_egress::Host::connect_plaintext(&mut host, "8.8.4.4".to_string(), 587)
            .await
            .expect_err("a non-allowlisted target must be refused");
        assert!(matches!(err, EgressError::RefusedByGate));

        let mut host2 = TcpEgressHost::new(
            &mut table,
            true,
            false,
            Arc::from(vec!["10.0.0.5:587".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let err2 = tcp_egress::Host::connect_plaintext(&mut host2, "10.0.0.5".to_string(), 587)
            .await
            .expect_err("an allowlisted-but-private target must still clear the SSRF floor");
        assert!(matches!(err2, EgressError::RefusedByGate));

        let mut host3 = TcpEgressHost::new(
            &mut table,
            false,
            true,
            Arc::from(vec!["93.184.216.34:587".to_string()]),
            Arc::from(Vec::new()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let err3 =
            tcp_egress::Host::connect_plaintext(&mut host3, "93.184.216.34".to_string(), 587)
                .await
                .expect_err("posture off must deny every dial");
        assert!(matches!(err3, EgressError::RefusedByGate));

        println!("TCP-EGRESS GATE REUSE PLAINTEXT OK");
    }

    /// `start-tls` is refused on an `ImplicitTls` (`connect-tls`-originated) connection — the strict
    /// PULL path has no plaintext phase to upgrade from.
    #[tokio::test]
    async fn start_tls_refused_on_implicit_tls_connection() {
        let (ca, chain, key) = ca_and_leaf();
        const GREETING: &[u8] = b"IMPLICIT";
        let port = spawn_tls_server(chain, key, GREETING).await;
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(vec![format!("127.0.0.1:{port}")]),
            Arc::from(vec![ca]),
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
        .expect("implicit-tls dial must succeed");
        let err = tcp_egress::HostConnection::start_tls(
            &mut host,
            conn_res,
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("start-tls must be refused on an already-implicit-TLS connection");
        assert!(matches!(err, EgressError::Other(_)));
    }

    /// `start-tls` is refused a SECOND time — whether the first attempt succeeded or failed, the
    /// connection does not offer a plaintext fallback (that would be a downgrade oracle).
    #[tokio::test]
    async fn start_tls_refused_after_already_upgraded() {
        let (ca, chain, key) = ca_and_leaf();
        const PLAIN: &[u8] = b"220 ready\r\n";
        const AFTER: &[u8] = b"after tls";
        let port = spawn_plaintext_then_tls_server(chain, key, PLAIN, AFTER).await;
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(vec![format!("127.0.0.1:{port}")]),
            Arc::from(vec![ca]),
            Duration::from_secs(5),
            Duration::from_millis(300),
        );
        let conn_res =
            tcp_egress::Host::connect_plaintext(&mut host, "127.0.0.1".to_string(), port)
                .await
                .expect("plaintext dial must succeed");
        let in_res = tcp_egress::HostConnection::take_input(&mut host, reborrow(&conn_res))
            .expect("plaintext input not yet taken");
        let _ = read_exact_n(&mut host, &in_res, PLAIN.len()).await;
        tcp_egress::HostConnection::start_tls(
            &mut host,
            reborrow(&conn_res),
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect("the first start-tls must succeed");

        let err = tcp_egress::HostConnection::start_tls(
            &mut host,
            conn_res,
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect_err("a second start-tls must be refused, not re-attempt an upgrade");
        assert!(matches!(err, EgressError::Other(_)));
    }

    /// `PLAN-handler-tcp-egress` Build B anti-hollow gate (mirrors the `tcpegress_tls_wrap_gate`
    /// #503 convention): a real STARTTLS-shaped loopback peer sends a plaintext greeting, THEN
    /// upgrades to a real TLS handshake on the SAME connection. The guest reads the plaintext
    /// greeting via `connect-plaintext` + `take-input`, calls `start-tls`, then calls `take-input`
    /// AGAIN (the connection's SECOND phase) and reads the DECRYPTED post-TLS greeting — proving
    /// `start-tls` genuinely upgrades the SAME connection in place. Prints the grep-able marker
    /// `TCP-EGRESS STARTTLS OK`. MUTATION-VERIFIED externally: the CI gate re-runs this EXACT test
    /// with `BOATRAMP_TCPEGRESS_TLS_MUTATION=skip_start_tls_wrap` set, which must make it FAIL (the
    /// "upgraded" connection is still raw TCP, so the post-"upgrade" read sees nothing a real TLS
    /// client would — the server is left waiting for a ClientHello that never arrives) — proving
    /// `start-tls`'s wrap is load-bearing, not cosmetic.
    #[tokio::test]
    async fn starttls_round_trip_upgrades_to_real_tls() {
        let (ca, chain, key) = ca_and_leaf();
        const PLAIN: &[u8] = b"220 ready for tls\r\n";
        const AFTER: &[u8] = b"TCP-EGRESS STARTTLS OK";
        let port = spawn_plaintext_then_tls_server(chain, key, PLAIN, AFTER).await;
        let mut table = ResourceTable::new();
        let mut host = TcpEgressHost::new(
            &mut table,
            true,
            true,
            Arc::from(vec![format!("127.0.0.1:{port}")]),
            Arc::from(vec![ca]),
            Duration::from_secs(5),
            Duration::from_millis(500),
        );

        let conn_res =
            tcp_egress::Host::connect_plaintext(&mut host, "127.0.0.1".to_string(), port)
                .await
                .expect("plaintext dial must succeed");
        let plain_in = tcp_egress::HostConnection::take_input(&mut host, reborrow(&conn_res))
            .expect("plaintext input not yet taken");
        let greeting = read_exact_n(&mut host, &plain_in, PLAIN.len()).await;
        assert_eq!(
            greeting, PLAIN,
            "the plaintext greeting must arrive un-encrypted"
        );

        tcp_egress::HostConnection::start_tls(
            &mut host,
            reborrow(&conn_res),
            "localhost".to_string(),
            VerifyMode::Strict,
        )
        .await
        .expect("start-tls must upgrade the connection");

        let bytes = read_stream_to_eof(&mut host, conn_res)
            .await
            .expect("post-upgrade read must succeed");
        assert_eq!(
            bytes, AFTER,
            "a failure here under BOATRAMP_TCPEGRESS_TLS_MUTATION=skip_start_tls_wrap is the \
             EXPECTED mutation-verification outcome, not a real regression"
        );
        println!("TCP-EGRESS STARTTLS OK");
    }

    /// RFC 7435 opportunistic relay: `start-tls(..., opportunistic)` against a peer presenting a
    /// SELF-SIGNED, UNCHAINED certificate — which the strict path (and `connect-tls` unconditionally)
    /// would reject — still completes, and the guest reads the real decrypted post-TLS bytes.
    /// Prints the grep-able marker `TCP-EGRESS STARTTLS OPPORTUNISTIC OK`.
    #[tokio::test]
    async fn start_tls_opportunistic_accepts_self_signed_cert() {
        let (chain, key) = self_signed_leaf();
        const PLAIN: &[u8] = b"220 ready for tls\r\n";
        const AFTER: &[u8] = b"TCP-EGRESS STARTTLS OPPORTUNISTIC OK";
        let port = spawn_plaintext_then_tls_server(chain, key, PLAIN, AFTER).await;
        let mut table = ResourceTable::new();
        // Deliberately NO extra_roots — a strict upgrade against this cert would fail.
        let mut host = host_fixture(&mut table, port);

        let conn_res =
            tcp_egress::Host::connect_plaintext(&mut host, "127.0.0.1".to_string(), port)
                .await
                .expect("plaintext dial must succeed");
        let plain_in = tcp_egress::HostConnection::take_input(&mut host, reborrow(&conn_res))
            .expect("plaintext input not yet taken");
        let greeting = read_exact_n(&mut host, &plain_in, PLAIN.len()).await;
        assert_eq!(greeting, PLAIN);

        tcp_egress::HostConnection::start_tls(
            &mut host,
            reborrow(&conn_res),
            "localhost".to_string(),
            VerifyMode::Opportunistic,
        )
        .await
        .expect("opportunistic start-tls must accept the self-signed, unchained certificate");

        let bytes = read_stream_to_eof(&mut host, conn_res)
            .await
            .expect("post-upgrade read must succeed");
        assert_eq!(bytes, AFTER);
        println!("TCP-EGRESS STARTTLS OPPORTUNISTIC OK");
    }

    /// Injection safety (the CVE-2011-0411 class, RFC 3207 §4): a peer that pipelines bytes
    /// immediately after its plaintext affirmative reply — before the guest ever calls `start-tls` —
    /// must NOT have those bytes delivered to the guest as decrypted TLS plaintext. The test's
    /// "guest" reads EXACTLY the expected reply line (mirroring a careful protocol parser that reads
    /// only as much as it expects, never more) via [`read_exact_n`], leaving the injected tail bytes
    /// UNREAD on the wire — exactly the scenario [`PlaintextEgressInput`]'s "no background task, no
    /// read-ahead" design is built to make safe. `start-tls` then reads those still-unread bytes as
    /// its own handshake input: since `INJECTED-COMMAND\r\n` doesn't parse as a valid TLS record,
    /// the handshake fails (`tls-failure`) — proving the bytes were fed to the TLS record parser,
    /// not smuggled through to the guest as plaintext. Prints the grep-able marker
    /// `TCP-EGRESS STARTTLS INJECTION SAFE`.
    #[tokio::test]
    async fn starttls_injection_bytes_never_reach_guest_as_tls_plaintext() {
        const PLAIN: &[u8] = b"220 ready for tls\r\n";
        const INJECTED: &[u8] = b"INJECTED-COMMAND please-run\r\n";
        let port = spawn_injecting_peer(PLAIN, INJECTED).await;
        let mut table = ResourceTable::new();
        let mut host = host_fixture(&mut table, port);

        let conn_res =
            tcp_egress::Host::connect_plaintext(&mut host, "127.0.0.1".to_string(), port)
                .await
                .expect("plaintext dial must succeed");
        let plain_in = tcp_egress::HostConnection::take_input(&mut host, reborrow(&conn_res))
            .expect("plaintext input not yet taken");
        // Read EXACTLY the expected reply — the injected tail is deliberately left unread on the
        // wire, still sitting in the kernel socket buffer.
        let greeting = read_exact_n(&mut host, &plain_in, PLAIN.len()).await;
        assert_eq!(greeting, PLAIN);

        let err = tcp_egress::HostConnection::start_tls(
            &mut host,
            conn_res,
            "localhost".to_string(),
            VerifyMode::Opportunistic,
        )
        .await
        .expect_err(
            "the injected plaintext bytes must choke the TLS handshake (a protocol/framing \
             error), never be accepted as TLS plaintext",
        );
        assert!(
            matches!(err, EgressError::TlsFailure(_)),
            "expected the handshake itself to fail on the injected bytes; got {err:?}"
        );
        println!("TCP-EGRESS STARTTLS INJECTION SAFE");
    }
}
