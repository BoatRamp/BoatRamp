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
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::HandlerRuntime;
use boatramp_core::deploy::DeployStore;

/// How long the accept loop waits for in-flight connections to finish on shutdown before abandoning
/// the drain. Each live connection also has its own `max_conn_duration` cap, so this is a backstop.
const LISTENER_DRAIN_DEADLINE: Duration = Duration::from_secs(10);

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
}

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
    } = params;

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
    // Per-source-IP connection-rate admission (cap-req 18); `None` ⇒ no per-IP limit. Checked in the
    // accept loop below (single task, so a plain flag throttles the refusal log without a lock).
    let mut rate_limit_warned = false;
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
                // cap-req 18: per-source-IP connection-rate admission BEFORE any guest work. A peer
                // over its token-bucket rate is refused + closed cheaply (restoring brute-force
                // protection a FaaS listener guest can't do itself — it never sees the peer IP). The
                // FIRST refusal on this listener logs at warn (an operator signal); the rest at debug,
                // so a flood can't spam the log.
                if let Some(limiter) = &peer_conn_limit
                    && !limiter.admit(peer.ip())
                {
                    if !rate_limit_warned {
                        rate_limit_warned = true;
                        tracing::warn!(
                            listener = %name, %peer,
                            "inbound-TCP connection refused by per-source-IP rate limit (cap-req 18); \
                             further refusals on this listener log at debug"
                        );
                    } else {
                        tracing::debug!(
                            listener = %name, %peer,
                            "inbound-TCP connection refused by per-source-IP rate limit"
                        );
                    }
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
                tokio::spawn(async move {
                    // Hold the per-listener permit for the connection's whole life.
                    let _permit = permit;
                    let peer = peer.to_string();
                    match (tls, starttls) {
                        // Host-side TLS termination (cap-req 06, implicit TLS): complete the
                        // handshake BEFORE the guest sees any bytes, then hand the guest the
                        // DECRYPTED halves. A failed handshake drops the connection — there is NO
                        // plaintext fallthrough, and the cert key never reaches the guest.
                        (Some(acceptor), None) => match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let (read_half, write_half) = tokio::io::split(tls_stream);
                                // Implicit TLS (:993/:465): the wire is TLS-protected for the
                                // connection's whole life (mailroom cap-req #16).
                                drive(
                                    &runtime, &deploy, &name, project.as_str(), site.as_str(),
                                    component.as_str(), &fn_config, peer, read_half, write_half,
                                    idle_timeout, max_conn_duration, session_mode,
                                    boatramp_handlers::ConnectionSecurity::tls(),
                                )
                                .await;
                            }
                            Err(e) => tracing::warn!(
                                listener = %name, %peer, error = %e,
                                "inbound-TLS handshake failed; dropping connection"
                            ),
                        },
                        // STARTTLS (cap-req 06, Stage B): the guest runs on an in-memory duplex while
                        // the pump owns the socket — forwarding the plaintext dialog, upgrading to TLS
                        // in-band on the declared trigger (the guest never sees the trigger and does no
                        // crypto), then passing decrypted bytes through. A failed handshake drops the
                        // pump, which closes the duplex → the guest reads EOF (no plaintext fallthrough).
                        (Some(acceptor), Some(grammar)) => {
                            // STARTTLS (:587/:143): starts plaintext; the pump flips this handle to
                            // TLS on the in-band upgrade (mailroom cap-req #16). The pump and the
                            // guest dispatch share the SAME underlying flag (clone of one Arc).
                            let conn_security =
                                boatramp_handlers::ConnectionSecurity::starttls_pending();
                            let (g_read, g_write, pump) = crate::tcp_starttls::spawn_pump(
                                stream,
                                acceptor,
                                grammar,
                                conn_security.clone(),
                            );
                            drive(
                                &runtime, &deploy, &name, project.as_str(), site.as_str(),
                                component.as_str(), &fn_config, peer, g_read, g_write,
                                idle_timeout, max_conn_duration, session_mode,
                                conn_security,
                            )
                            .await;
                            // Guest returned (completed / idle / max-duration) ⇒ tear the pump + socket
                            // down. If the pump already ended (client gone / handshake failed) this is a
                            // no-op.
                            pump.abort();
                        }
                        // Plaintext listener — unchanged. A STARTTLS grammar without a cert is refused
                        // at config validation, so `(None, Some(_))` cannot occur in practice; it is
                        // handled here as a plaintext connection (fail-safe — never an unterminated
                        // "STARTTLS" that silently stays cleartext).
                        (None, _) => {
                            let (read_half, write_half) = stream.into_split();
                            // Plaintext listener — no TLS, none negotiable (mailroom cap-req #16).
                            drive(
                                &runtime, &deploy, &name, project.as_str(), site.as_str(),
                                component.as_str(), &fn_config, peer, read_half, write_half,
                                idle_timeout, max_conn_duration, session_mode,
                                boatramp_handlers::ConnectionSecurity::plaintext(),
                            )
                            .await;
                        }
                    }
                });
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
