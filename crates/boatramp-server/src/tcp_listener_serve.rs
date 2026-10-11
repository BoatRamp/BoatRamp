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
                let (read_half, write_half) = stream.into_split();
                let runtime = runtime.clone();
                let deploy = deploy.clone();
                let name = name.clone();
                let project = Arc::clone(&project);
                let site = Arc::clone(&site);
                let component = Arc::clone(&component);
                let fn_config = Arc::clone(&fn_config);
                tokio::spawn(async move {
                    // Hold the per-listener permit for the connection's whole life.
                    let _permit = permit;
                    let peer = peer.to_string();
                    if let Err(e) = runtime
                        .dispatch_tcp_connection(
                            &deploy,
                            project.as_str(),
                            site.as_str(),
                            component.as_str(),
                            &fn_config,
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
