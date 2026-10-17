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
        "serving host-owned inbound-TCP listener (PLAN-handler-tcp-inbound)"
    );

    // Build the TLS acceptor once (cap-req 06); `None` ⇒ a plaintext listener. `TlsAcceptor` is a
    // cheap `Arc` clone per connection.
    let tls = tls.map(tokio_rustls::TlsAcceptor::from);

    // Per-listener live-connection cap: a live connection holds one permit for its whole life; at the
    // ceiling a new connection is dropped (fail-closed backpressure) rather than unboundedly spawned.
    let conn_gate = Arc::new(Semaphore::new(max_conns));
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
                tokio::spawn(async move {
                    // Hold the per-listener permit for the connection's whole life.
                    let _permit = permit;
                    let peer = peer.to_string();
                    match tls {
                        // Host-side TLS termination (cap-req 06, implicit TLS): complete the
                        // handshake BEFORE the guest sees any bytes, then hand the guest the
                        // DECRYPTED halves. A failed handshake drops the connection — there is NO
                        // plaintext fallthrough, and the cert key never reaches the guest.
                        Some(acceptor) => match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let (read_half, write_half) = tokio::io::split(tls_stream);
                                drive(
                                    &runtime, &deploy, &name, project.as_str(), site.as_str(),
                                    component.as_str(), &fn_config, peer, read_half, write_half,
                                    idle_timeout, max_conn_duration,
                                )
                                .await;
                            }
                            Err(e) => tracing::warn!(
                                listener = %name, %peer, error = %e,
                                "inbound-TLS handshake failed; dropping connection"
                            ),
                        },
                        None => {
                            let (read_half, write_half) = stream.into_split();
                            drive(
                                &runtime, &deploy, &name, project.as_str(), site.as_str(),
                                component.as_str(), &fn_config, peer, read_half, write_half,
                                idle_timeout, max_conn_duration,
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
) where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
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
        )
        .await
    {
        tracing::warn!(listener = %name, %peer, error = %e, "inbound-TCP connection dispatch failed");
    }
}
