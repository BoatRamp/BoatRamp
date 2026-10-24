//! Host-owned inbound-TCP **listener** serving (PLAN-handler-tcp-inbound).
//!
//! The node binds + listens + accepts on an operator-declared `[serve.listeners.<name>]` and hands
//! each ALREADY-ACCEPTED connection to a guest `tcp-connection-handler` via
//! [`HandlerRuntime::dispatch_tcp_connection`]. The guest owns no socket — it receives only the
//! connection's `wasi:io` streams (NEVER `wasi:sockets`); bind/listen/accept stay here, host-side.
//!
//! This module is the reusable accept loop + lifecycle (per-listener `max_conns` cap, graceful drain
//! on the process shutdown signal); the orchestration that iterates the config + gates on the posture
//! lives one layer up (`boatramp::serve::spawn_listeners`). Modeled on the aux-listener spawn pattern
//! (`spawn_s3_ingress`) — detached + shutdown-signal driven.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::HandlerRuntime;
use boatramp_core::deploy::DeployStore;

/// How long the accept loop waits for in-flight connections to finish on shutdown before abandoning
/// the drain. Each live connection also has its own `max_conn_duration` cap, so this is a backstop.
const LISTENER_DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// Log a per-source-IP rate-limit refusal (cap-req 18), warn-once then debit to debug so a flood can't
/// spam the log. Shared by the direct-listener (accept-loop) and proxy-path (spawned-task) admissions.
fn log_rate_refusal(warned: &AtomicBool, name: &str, peer: SocketAddr) {
    if warned.swap(true, Ordering::Relaxed) {
        tracing::debug!(
            listener = %name, %peer,
            "inbound-TCP connection refused by per-source-IP rate limit"
        );
    } else {
        tracing::warn!(
            listener = %name, %peer,
            "inbound-TCP connection refused by per-source-IP rate limit (cap-req 18); further \
             refusals on this listener log at debug"
        );
    }
}

/// The fully-resolved parameters of one `[serve.listeners.<name>]` accept loop (built one layer up
/// from the config, so this module needs no `boatramp-node` dependency). `fn_config` carries the
/// listener's imports / env / operator-pinned tenancy, and an EMPTY `egress_allowlist` (Phase-1
/// invariant: a `tcp-connection-host` guest can't hold `wasi:sockets`).
pub struct ListenerParams {
    /// The listener's config key (for logging).
    pub name: String,
    /// The address to bind + accept on.
    pub bind: SocketAddr,
    /// The operator-pinned project whose active deployment holds the component.
    pub project: String,
    /// The operator-pinned site within `project`.
    pub site: String,
    /// The guest `.wasm` component path within the deployment (exports `tcp-connection-handler`).
    pub component: String,
    /// The guest binding config (imports / env / pinned tenancy; empty egress allowlist).
    pub fn_config: boatramp_core::function::FunctionConfig,
    /// Per-listener cap on simultaneously-live connections (a DoS bound atop the engine conn lane).
    pub max_conns: usize,
    /// Tear a connection down after this long with no bytes in either direction.
    pub idle_timeout: Duration,
    /// Absolute cap on a single connection's lifetime regardless of activity.
    pub max_conn_duration: Duration,
    /// Host-side TLS termination (cap-req 06). `Some` ⇒ every accepted connection is wrapped in a
    /// `TlsAcceptor` built from this `ServerConfig` BEFORE the guest sees it, so the guest gets a
    /// plaintext stream over the decrypted connection (implicit TLS — 465/993). A failed handshake
    /// drops the connection; there is NO plaintext fallthrough. `None` ⇒ the plaintext listener
    /// (unchanged). The orchestrator (which holds `rustls`) builds the config from the sealed cert
    /// material; the private key lives only inside it and never reaches the guest.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Declarative STARTTLS (cap-req 06, Stage B). `Some` ⇒ the connection starts in **plaintext**,
    /// the host forwards the guest's dialog, and on the declared trigger line it upgrades the socket
    /// to TLS in-band (requires `tls` to be `Some` — the same cert material). `None` ⇒ implicit TLS
    /// (when `tls` is `Some`) or plaintext (when `tls` is `None`), unchanged. The grammar is the only
    /// protocol-specific data; the host runs a generic trigger→response→wrap engine
    /// ([`crate::tcp_starttls`]).
    pub starttls: Option<crate::tcp_starttls::StarttlsGrammar>,
    /// `true` ⇒ drive each connection through the re-entrant SESSION model (cap-req 08): the host owns
    /// the socket and re-enters the guest's `session-handler` per inbound batch, holding NO instance
    /// between batches (idle ⇒ socket + checkpoint only; `idle_timeout` does NOT evict). `false`
    /// (default) ⇒ the long-lived `tcp-connection-handler` model (one instance pinned per connection).
    /// A `bool` (not the node's `ListenerMode`) keeps this module free of a `boatramp-node` dependency;
    /// the orchestrator maps the config. TLS/STARTTLS composition is identical — it only decides how the
    /// `(read, write)` halves are produced.
    pub session_mode: bool,
    /// Per-source-IP connection-rate admission (cap-req 18): `Some` ⇒ each accepted connection is
    /// admitted through a per-peer-IP token bucket BEFORE any guest work, so a FaaS listener guest
    /// (which can't see the peer IP) keeps native-daemon brute-force protection; over-rate
    /// connections are closed cheaply. `None` ⇒ no per-IP limit (the `max_conns` live-cap still
    /// applies). The orchestrator builds this from the listener config's rate/burst.
    pub peer_conn_limit: Option<crate::peer_conn_limit::PeerConnLimiter>,
    /// Trust a PROXY-protocol (v1/v2) header to recover the real client address behind an L4 proxy
    /// (cap-req 18 completion). `true` ⇒ each connection must present a well-formed header (dropped
    /// otherwise, fail-closed) and that address drives the per-IP limit + the guest's `peer`. `false`
    /// ⇒ the kernel peer is used, unchanged. The orchestrator copies it from the listener config.
    pub proxy_protocol: bool,
    /// Trusted-proxy source CIDRs for `proxy_protocol` (security-review MEDIUM-1): `ip/prefix` strings.
    /// When non-empty, a PROXY header is trusted ONLY from a kernel peer inside one of these CIDRs
    /// (else the connection is dropped). Empty ⇒ trust a header from any source (firewall-only mode),
    /// which is permitted ONLY alongside `proxy_protocol_trust_any` (enforced at config load).
    /// Parsed once at [`run_listener`]; a malformed entry fails the listener closed (it is not served).
    pub proxy_protocol_trusted_cidrs: Vec<String>,
    /// Explicit opt-in to trust a PROXY header from ANY source when `proxy_protocol_trusted_cidrs` is
    /// empty (senior-architect review — OWNER DECISION: require trusted CIDRs). Config validation
    /// refuses `proxy_protocol` + empty CIDRs unless this is `true`; this field is the runtime
    /// defense-in-depth backstop — [`run_listener`] fails the listener CLOSED (does not serve) if it
    /// ever sees `proxy_protocol` + empty CIDRs + `!trust_any`, so the "trust any source" posture is
    /// never reached by omission.
    pub proxy_protocol_trust_any: bool,
}

/// How long to wait for a connection's PROXY-protocol header before dropping it (cap-req 18): a
/// trusted proxy prepends it immediately, so this is short — it only bounds a slow/missing header.
const PROXY_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper cap on the dedicated PROXY-protocol **pre-admission** slots (senior-architect review, Item
/// 5). On a `proxy_protocol` listener the header read + per-IP admission run under their OWN modest
/// semaphore — NOT the main `max_conns` gate — so a stalled/absent header can only pin a cheap,
/// short-lived (≤ [`PROXY_HEADER_READ_TIMEOUT`]) pre-admission slot, never a whole-connection
/// `max_conns` permit. The gate is sized `min(max_conns, this)` so a large `max_conns` doesn't allow
/// unbounded concurrent header-reading tasks.
const PROXY_PREADMIT_MAX_SLOTS: usize = 2_048;

/// Spawn the accept loop for one listener, detached. Returns immediately; the loop runs until the
/// process shutdown signal fires, then drains in-flight connections (bounded by
/// [`LISTENER_DRAIN_DEADLINE`]). A bind failure logs an error and the loop exits (serving continues
/// without this listener — a listener is additive, never a hard boot dependency).
pub fn spawn_listener(runtime: HandlerRuntime, deploy: DeployStore, params: ListenerParams) {
    tokio::spawn(async move {
        run_listener(runtime, deploy, params).await;
    });
}

async fn run_listener(runtime: HandlerRuntime, deploy: DeployStore, params: ListenerParams) {
    let ListenerParams {
        name,
        bind,
        project,
        site,
        component,
        fn_config,
        max_conns,
        idle_timeout,
        max_conn_duration,
        tls,
        starttls,
        session_mode,
        peer_conn_limit,
        proxy_protocol,
        proxy_protocol_trusted_cidrs,
        proxy_protocol_trust_any,
    } = params;

    // Parse the trusted-proxy CIDRs once (security-review MEDIUM-1). A malformed entry fails the
    // listener CLOSED — a misconfigured trusted set must not silently fall back to trusting any
    // source. Empty ⇒ trust a PROXY header from any kernel peer (firewall-only mode).
    let proxy_trusted: Vec<ipnet::IpNet> = {
        let mut nets = Vec::with_capacity(proxy_protocol_trusted_cidrs.len());
        for entry in &proxy_protocol_trusted_cidrs {
            match entry.parse::<ipnet::IpNet>() {
                Ok(net) => nets.push(net),
                Err(e) => {
                    tracing::error!(
                        listener = %name, cidr = %entry, error = %e,
                        "NOT serving listener: malformed `proxy_protocol_trusted_cidrs` entry \
                         (fail-closed — a bad trusted set must not trust any source)"
                    );
                    return;
                }
            }
        }
        nets
    };
    // Require a trusted source for PROXY-protocol (senior-architect review — OWNER DECISION: require).
    // Config validation already refuses `proxy_protocol` + empty CIDRs unless `proxy_protocol_trust_any`
    // is set; this is the runtime defense-in-depth backstop, so even a config path that bypassed that
    // check can never reach the "trust a header from any source" posture by omission — it fails the
    // listener CLOSED (not served) exactly like a malformed CIDR.
    if proxy_protocol && proxy_trusted.is_empty() && !proxy_protocol_trust_any {
        tracing::error!(
            listener = %name, %bind,
            "NOT serving listener: `proxy_protocol` is on with no `proxy_protocol_trusted_cidrs` and \
             `proxy_protocol_trust_any` is false (fail-closed — a header from any source is spoofable)"
        );
        return;
    }

    let listener = match TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                listener = %name, %bind, error = %e,
                "inbound-TCP listener failed to bind; NOT serving it (serving continues)"
            );
            return;
        }
    };
    tracing::info!(
        listener = %name, %bind, %project, %site, component = %component, max_conns,
        mode = if session_mode { "session" } else { "connection" },
        "serving host-owned inbound-TCP listener (PLAN-handler-tcp-inbound)"
    );
    // One-time startup warning (cap-req 08 / Security review LOW): a session-mode listener on a build
    // WITHOUT the `session` feature can't serve — every connection is dropped. Config validation can't
    // see cargo features, so warn loudly ONCE here at bind instead of only per-connection in `drive`.
    #[cfg(not(feature = "session"))]
    if session_mode {
        tracing::warn!(
            listener = %name, %bind,
            "listener is mode = \"session\" but this build lacks the `session` feature; every \
             connection will be DROPPED — rebuild with `session` or use mode = \"connection\""
        );
    }

    // Build the TLS acceptor once (cap-req 06); `None` ⇒ a plaintext listener. `TlsAcceptor` is a
    // cheap `Arc` clone per connection.
    let tls = tls.map(tokio_rustls::TlsAcceptor::from);

    // Per-listener live-connection cap: a live connection holds one permit for its whole life; at the
    // ceiling a new connection is dropped (fail-closed backpressure) rather than unboundedly spawned.
    let conn_gate = Arc::new(Semaphore::new(max_conns));
    // PROXY-protocol **pre-admission** gate (senior-architect review, Item 5): on a `proxy_protocol`
    // listener the header read + per-IP admission run under THIS modest semaphore, and the main
    // `conn_gate` permit is taken only AFTER the real client IP is admitted — so a stalled/absent
    // header can pin only a cheap, ≤ PROXY_HEADER_READ_TIMEOUT pre-admission slot, never a
    // whole-connection `max_conns` permit (the pin bug this fixes). Sized modestly relative to
    // `max_conns`. Inert for a direct listener (it admits before the permit — already correct).
    let pre_admit_gate = Arc::new(Semaphore::new(max_conns.clamp(1, PROXY_PREADMIT_MAX_SLOTS)));
    // Per-source-IP connection-rate admission (cap-req 18); `None` ⇒ no per-IP limit. Shared via `Arc`
    // so the admission can run EITHER in this accept loop (a DIRECT listener — the real client IP is
    // the kernel peer) OR inside the spawned task after a PROXY-protocol header reveals the real client
    // IP (cap-req 18 completion, behind a trusted proxy). The warn-once flag is an `AtomicBool` for the
    // same reason: the proxy-path admission logs from a spawned task.
    let peer_conn_limit = peer_conn_limit.map(Arc::new);
    let rate_limit_warned = Arc::new(AtomicBool::new(false));
    // Shared, read-only per-connection inputs (cloned cheaply into each spawned task).
    let project = Arc::new(project);
    let site = Arc::new(site);
    let component = Arc::new(component);
    let fn_config = Arc::new(fn_config);

    let shutdown = crate::shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(listener = %name, error = %e, "inbound-TCP accept failed");
                        continue;
                    }
                };
                // Nagle off: a request/response protocol over this stream shouldn't coalesce small
                // writes behind the delayed-ack timer. Best-effort.
                let _ = stream.set_nodelay(true);
                // cap-req 18 / security-review MEDIUM-1: on a proxy_protocol listener with a trusted
                // -CIDR set, only a connection FROM the trusted proxy may have its header trusted —
                // drop anything else (fail-closed), so a firewall gap can't become source-IP spoofing.
                // (Empty set ⇒ firewall-only mode, permitted only with `proxy_protocol_trust_any`.)
                // Compare the CANONICAL kernel-peer IP: on a dual-stack `[::]` listener an IPv4 proxy
                // arrives as a v4-mapped `::ffff:a.b.c.d`, which would never match an IPv4 trusted CIDR
                // (e.g. `10.0.0.0/8`) and would be dropped fail-closed; `to_canonical()` unwraps it so
                // the operator's IPv4 CIDR matches (a genuine IPv6 peer is left as-is).
                if proxy_protocol
                    && !proxy_trusted.is_empty()
                    && !proxy_trusted
                        .iter()
                        .any(|net| net.contains(&peer.ip().to_canonical()))
                {
                    tracing::debug!(
                        listener = %name, %peer,
                        "dropping connection: kernel peer not in `proxy_protocol_trusted_cidrs`"
                    );
                    drop(stream);
                    continue;
                }
                let runtime = runtime.clone();
                let deploy = deploy.clone();
                let name = name.clone();
                let project = Arc::clone(&project);
                let site = Arc::clone(&site);
                let component = Arc::clone(&component);
                let fn_config = Arc::clone(&fn_config);
                // Cheap clone (an `Arc<ServerConfig>` inside); `None` ⇒ the plaintext listener.
                let tls = tls.clone();
                // Declarative STARTTLS grammar (cap-req 06, Stage B); `None` ⇒ implicit TLS / plaintext.
                let starttls = starttls.clone();

                if proxy_protocol {
                    // PROXY path (cap-req 18 completion + senior-architect review Item 5): the real
                    // client IP isn't known until the header is read, so acquire only a cheap
                    // PRE-ADMISSION slot here (NOT the main `max_conns` permit), read the header + admit
                    // on the real IP inside the spawn, and take the `conn_gate` permit ONLY AFTER
                    // admission — so a stalled/absent header can never pin a whole-connection permit.
                    let Ok(pre_permit) = Arc::clone(&pre_admit_gate).try_acquire_owned() else {
                        tracing::warn!(
                            listener = %name, %peer,
                            "inbound-TCP proxy listener at pre-admission ceiling; dropping connection"
                        );
                        drop(stream);
                        continue;
                    };
                    let conn_gate = Arc::clone(&conn_gate);
                    let peer_conn_limit = peer_conn_limit.clone();
                    let rate_limit_warned = Arc::clone(&rate_limit_warned);
                    tokio::spawn(async move {
                        // Held only for the header read + admission; released before the connection runs.
                        let pre_permit = pre_permit;
                        let mut stream = stream;
                        // Consume the PROXY-protocol header (plaintext, BEFORE any TLS) to recover the
                        // real client address. Fail-closed: a missing/malformed header drops the
                        // connection (a direct client can't forge one — parsing is off unless the
                        // operator declared a trusted proxy fronts this listener).
                        let peer = match crate::proxy_protocol::read_proxy_header(
                            &mut stream,
                            PROXY_HEADER_READ_TIMEOUT,
                        )
                        .await
                        {
                            Ok(Some(real)) => real,
                            // LOCAL (v2) / UNKNOWN (v1): the proxy's own connection — use the kernel peer.
                            Ok(None) => peer,
                            Err(e) => {
                                tracing::debug!(
                                    listener = %name, %peer, error = %e,
                                    "dropping connection: no/malformed PROXY-protocol header on a \
                                     proxy_protocol listener"
                                );
                                return;
                            }
                        };
                        // Per-source-IP admission on the REAL client IP, still under the pre-admission
                        // slot — before any whole-connection permit is committed.
                        if let Some(limiter) = &peer_conn_limit
                            && !limiter.admit(peer.ip())
                        {
                            log_rate_refusal(&rate_limit_warned, &name, peer);
                            return;
                        }
                        // Admitted: NOW take the whole-connection permit. At the ceiling, drop (the
                        // header phase cost only a pre-admission slot, not a `max_conns` permit).
                        let Ok(permit) = Arc::clone(&conn_gate).try_acquire_owned() else {
                            tracing::warn!(
                                listener = %name, %peer, max_conns,
                                "inbound-TCP listener at max_conns; dropping connection"
                            );
                            return;
                        };
                        // Header phase done — free the pre-admission slot (the main permit now bounds
                        // this connection for its whole life).
                        drop(pre_permit);
                        let _permit = permit;
                        terminate_and_drive(
                            &runtime, &deploy, &name, project.as_str(), site.as_str(),
                            component.as_str(), &fn_config, tls, starttls, stream,
                            peer.to_string(), idle_timeout, max_conn_duration, session_mode,
                        )
                        .await;
                    });
                } else {
                    // DIRECT path (unchanged ordering — already correct): the real client IP is the
                    // kernel peer, so admit per-source-IP BEFORE committing the `max_conns` permit.
                    if let Some(limiter) = &peer_conn_limit
                        && !limiter.admit(peer.ip())
                    {
                        log_rate_refusal(&rate_limit_warned, &name, peer);
                        drop(stream);
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&conn_gate).try_acquire_owned() else {
                        tracing::warn!(
                            listener = %name, %peer, max_conns,
                            "inbound-TCP listener at max_conns; dropping connection"
                        );
                        drop(stream);
                        continue;
                    };
                    tokio::spawn(async move {
                        // Hold the per-listener permit for the connection's whole life.
                        let _permit = permit;
                        terminate_and_drive(
                            &runtime, &deploy, &name, project.as_str(), site.as_str(),
                            component.as_str(), &fn_config, tls, starttls, stream,
                            peer.to_string(), idle_timeout, max_conn_duration, session_mode,
                        )
                        .await;
                    });
                }
            }
            _ = &mut shutdown => {
                tracing::info!(listener = %name, %bind, "inbound-TCP listener shutting down; draining in-flight connections");
                break;
            }
        }
    }

    // Drain: acquiring ALL permits means every in-flight dispatch has released its permit (returned).
    // Bounded by the deadline so a wedged connection can't block process exit indefinitely (each
    // connection is independently bounded by `max_conn_duration`).
    let _ = tokio::time::timeout(
        LISTENER_DRAIN_DEADLINE,
        conn_gate.acquire_many(max_conns as u32),
    )
    .await;
}

/// Apply the connection's TLS/STARTTLS/plaintext termination layer, then [`drive`] it (shared by the
/// direct and proxy accept paths — Item 5 factored this out of the accept loop so both can call it
/// after acquiring the main `conn_gate` permit at the right point). `stream` is the raw accepted TCP
/// stream (for the proxy path, positioned just past the consumed PROXY-protocol header). A failed TLS
/// handshake drops the connection — there is NO plaintext fallthrough and the cert key never reaches
/// the guest.
#[allow(clippy::too_many_arguments)]
async fn terminate_and_drive(
    runtime: &HandlerRuntime,
    deploy: &DeployStore,
    name: &str,
    project: &str,
    site: &str,
    component: &str,
    fn_config: &boatramp_core::function::FunctionConfig,
    // Cheap `Arc`-backed clones per connection; `None` ⇒ plaintext listener.
    tls: Option<tokio_rustls::TlsAcceptor>,
    starttls: Option<crate::tcp_starttls::StarttlsGrammar>,
    stream: tokio::net::TcpStream,
    peer: String,
    idle_timeout: Duration,
    max_conn_duration: Duration,
    session_mode: bool,
) {
    match (tls, starttls) {
        // Host-side TLS termination (cap-req 06, implicit TLS): complete the handshake BEFORE the
        // guest sees any bytes, then hand the guest the DECRYPTED halves. A failed handshake drops
        // the connection — NO plaintext fallthrough, and the cert key never reaches the guest.
        (Some(acceptor), None) => match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                let (read_half, write_half) = tokio::io::split(tls_stream);
                // Implicit TLS (:993/:465): the wire is TLS-protected for the connection's whole
                // life (mailroom cap-req #16).
                drive(
                    runtime,
                    deploy,
                    name,
                    project,
                    site,
                    component,
                    fn_config,
                    peer,
                    read_half,
                    write_half,
                    idle_timeout,
                    max_conn_duration,
                    session_mode,
                    boatramp_handlers::ConnectionSecurity::tls(),
                )
                .await;
            }
            Err(e) => tracing::warn!(
                listener = %name, %peer, error = %e,
                "inbound-TLS handshake failed; dropping connection"
            ),
        },
        // STARTTLS (cap-req 06, Stage B): the guest runs on an in-memory duplex while the pump owns
        // the socket — forwarding the plaintext dialog, upgrading to TLS in-band on the declared
        // trigger (the guest never sees the trigger and does no crypto), then passing decrypted bytes
        // through. A failed handshake drops the pump, which closes the duplex → the guest reads EOF
        // (no plaintext fallthrough).
        (Some(acceptor), Some(grammar)) => {
            // STARTTLS (:587/:143): starts plaintext; the pump flips this handle to TLS on the
            // in-band upgrade (mailroom cap-req #16). The pump and the guest dispatch share the SAME
            // underlying flag (clone of one Arc).
            let conn_security = boatramp_handlers::ConnectionSecurity::starttls_pending();
            let (g_read, g_write, pump) =
                crate::tcp_starttls::spawn_pump(stream, acceptor, grammar, conn_security.clone());
            drive(
                runtime,
                deploy,
                name,
                project,
                site,
                component,
                fn_config,
                peer,
                g_read,
                g_write,
                idle_timeout,
                max_conn_duration,
                session_mode,
                conn_security,
            )
            .await;
            // Guest returned (completed / idle / max-duration) ⇒ tear the pump + socket down. If the
            // pump already ended (client gone / handshake failed) this is a no-op.
            pump.abort();
        }
        // Plaintext listener — unchanged. A STARTTLS grammar without a cert is refused at config
        // validation, so `(None, Some(_))` cannot occur in practice; it is handled here as a plaintext
        // connection (fail-safe — never an unterminated "STARTTLS" that silently stays cleartext).
        (None, _) => {
            let (read_half, write_half) = stream.into_split();
            // Plaintext listener — no TLS, none negotiable (mailroom cap-req #16).
            drive(
                runtime,
                deploy,
                name,
                project,
                site,
                component,
                fn_config,
                peer,
                read_half,
                write_half,
                idle_timeout,
                max_conn_duration,
                session_mode,
                boatramp_handlers::ConnectionSecurity::plaintext(),
            )
            .await;
        }
    }
}

/// Dispatch one accepted connection (plaintext socket halves OR a host-terminated TLS stream's
/// split halves — `dispatch_tcp_connection` is generic over `AsyncRead`/`AsyncWrite`). The shared
/// tail of the plaintext + TLS accept arms, so the only difference between them is how `(read, write)`
/// is produced. Logs a dispatch failure (never a hard error — the accept loop keeps serving).
#[allow(clippy::too_many_arguments)]
async fn drive<R, W>(
    runtime: &HandlerRuntime,
    deploy: &DeployStore,
    name: &str,
    project: &str,
    site: &str,
    component: &str,
    fn_config: &boatramp_core::function::FunctionConfig,
    peer: String,
    read_half: R,
    write_half: W,
    idle_timeout: Duration,
    max_conn_duration: Duration,
    session_mode: bool,
    // Live wire-security of this connection (mailroom cap-req #16): `tls` for an implicit-TLS
    // listener, `plaintext` for a plaintext one, `starttls-pending` (flipped to `tls` by the pump)
    // for STARTTLS. Threaded to the guest's `tcp-connection-context` import.
    conn_security: boatramp_handlers::ConnectionSecurity,
) where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Session mode (cap-req 08): drive the connection through the re-entrant session model (host owns
    // the socket, no instance pinned between inbound batches, `idle_timeout` does not evict). Falls
    // back to a loud drop if the `session` feature is not compiled into this build.
    if session_mode {
        #[cfg(feature = "session")]
        {
            if let Err(e) = runtime
                .dispatch_session_connection(
                    deploy,
                    project,
                    site,
                    component,
                    fn_config,
                    peer.clone(),
                    read_half,
                    write_half,
                    // `idle_timeout` is the PER-RE-ENTRY processing deadline in session mode (bounds a
                    // single re-entry / a stuck slow-peer write), NOT a between-re-entry idle eviction —
                    // a parked quiet connection survives, bounded only by `max_conn_duration`.
                    idle_timeout,
                    max_conn_duration,
                    conn_security,
                )
                .await
            {
                tracing::warn!(listener = %name, %peer, error = %e, "session listener connection dispatch failed");
            }
        }
        #[cfg(not(feature = "session"))]
        {
            let _ = (
                read_half,
                write_half,
                idle_timeout,
                max_conn_duration,
                conn_security,
            );
            tracing::error!(
                listener = %name, %peer,
                "listener is session-mode but this build lacks the `session` feature; dropping connection"
            );
        }
        return;
    }
    if let Err(e) = runtime
        .dispatch_tcp_connection(
            deploy,
            project,
            site,
            component,
            fn_config,
            peer.clone(),
            read_half,
            write_half,
            idle_timeout,
            max_conn_duration,
            conn_security,
        )
        .await
    {
        tracing::warn!(listener = %name, %peer, error = %e, "inbound-TCP connection dispatch failed");
    }
}
