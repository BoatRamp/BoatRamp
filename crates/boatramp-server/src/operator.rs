//! The operator / metrics endpoints: consumer + DLQ queue health, the dead-letter
//! redrive/purge actions, the operator log tail (poll + SSE), and the Prometheus
//! `/metrics` scrape. All handler-runtime introspection, so the whole module is
//! `handlers`-gated; it pulls the serve-pipeline scope in via `use super::*`.

use super::*;

#[cfg(feature = "handlers")]
impl HandlerRuntimeInner {
    /// Live SSE connection count attributable to `site` — its live scope plus
    /// any preview/alias sub-scopes (`{site}/…`).
    fn stream_connections_for_site(&self, site: &str) -> usize {
        let counts = self.stream_ip_counts.lock().unwrap();
        let sub_prefix = format!("{site}/");
        counts
            .iter()
            .filter(|((scope, _), _)| scope == site || scope.starts_with(&sub_prefix))
            .map(|(_, n)| *n as usize)
            .sum()
    }
}

/// One consumer's queue health for the operator view.
#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct ConsumerStat {
    /// The deployment scope the consumer runs under (site, or `{site}/{alias}`).
    scope: String,
    /// The consumer's declared (scope-relative) topic.
    topic: String,
    /// Messages still queued (claimable or leased) — the consumer lag.
    backlog: usize,
    /// Messages parked in the dead-letter store (exhausted retries).
    dead_letters: usize,
}

/// The `/_boatramp/handlers` operator response: per-`(trigger, route)`
/// invocation stats, per-consumer queue health, and the live stream count.
#[cfg(feature = "handlers")]
#[derive(Serialize, Default)]
struct OperatorStats {
    handlers: Vec<metrics::HandlerStat>,
    consumers: Vec<ConsumerStat>,
    stream_connections: usize,
}

/// Authenticated per-site operator stats (`site:<site>` scope via the API auth
/// middleware). Reports handler invocation counters, consumer backlog +
/// dead-letter counts across the site's active deployments, and live SSE
/// connections.
#[cfg(feature = "handlers")]
pub(super) async fn operator_handler_stats(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        // Handlers compiled in but no runtime configured: empty stats.
        return Json(OperatorStats::default()).into_response();
    };
    let handler_stats = inner.metrics.snapshot_site(&site);
    let mut consumers = Vec::new();
    if let Some(messaging) = &inner.messaging {
        match collect_consumer_stats(&deploy, messaging.as_ref(), &site).await {
            Ok(stats) => consumers = stats,
            Err(err) => return deploy_error_response(err),
        }
    }
    Json(OperatorStats {
        handlers: handler_stats,
        consumers,
        stream_connections: inner.stream_connections_for_site(&site),
    })
    .into_response()
}

/// Which dead-letter operation `POST …/_boatramp/dlq` should run.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum DlqAction {
    /// Drop the dead-lettered messages (records + payloads).
    Purge,
    /// Requeue them onto the live topic with a fresh attempt count.
    Redrive,
}

/// `POST …/_boatramp/dlq` request: which consumer topic, and what to do.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct DlqRequest {
    /// The consumer's topic (scope-relative, as declared in the deploy config).
    topic: String,
    /// Background-alias scope (`{site}/{alias}`); omitted = the live site.
    #[serde(default)]
    alias: Option<String>,
    /// `purge` or `redrive`.
    action: DlqAction,
}

#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct DlqResponse {
    /// Number of dead-lettered messages affected.
    affected: usize,
}

/// Operator dead-letter management (`POST …/_boatramp/dlq`, site·write): purge or
/// redrive a consumer topic's dead-letter queue. The topic is
/// namespaced to the site (or a background alias) exactly as the dispatcher does,
/// so an operator can only touch their own site's queues.
#[cfg(feature = "handlers")]
pub(super) async fn operator_dlq(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Json(req): Json<DlqRequest>,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return not_found();
    };
    let Some(messaging) = inner.messaging.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "messaging backend not configured\n",
        )
            .into_response();
    };
    // Same namespacing as `collect_consumer_stats`: `{site}/{topic}`, or
    // `{site}/{alias}/{topic}` for a background-alias consumer.
    let scope = match &req.alias {
        Some(alias) => format!("{site}/{alias}"),
        None => site.clone(),
    };
    let namespaced = format!("{scope}/{}", req.topic);
    let result = match req.action {
        DlqAction::Purge => messaging.purge_dead_letters(&namespaced).await,
        DlqAction::Redrive => messaging.redrive_dead_letters(&namespaced).await,
    };
    match result {
        Ok(affected) => Json(DlqResponse { affected }).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("dead-letter operation failed: {err}\n"),
        )
            .into_response(),
    }
}

/// Gather consumer backlog + dead-letter counts for every consumer across a
/// site's active deployments (current + background aliases), mirroring the
/// scheduler's activation policy (previews are never background-active).
#[cfg(feature = "handlers")]
async fn collect_consumer_stats(
    deploy: &DeployStore,
    messaging: &dyn boatramp_core::messaging::Messaging,
    site: &str,
) -> Result<Vec<ConsumerStat>, DeployError> {
    let mut out = Vec::new();
    let Some(site_config) = deploy.get_site_config(site).await? else {
        return Ok(out);
    };
    let Some(site_handlers) = site_config.handlers.as_ref().filter(|h| h.enabled) else {
        return Ok(out);
    };
    let mut active: Vec<(String, String)> = Vec::new();
    if let Some(id) = deploy.current_id(site).await? {
        active.push((id, site.to_string()));
    }
    for alias in &site_handlers.background_aliases {
        if let Some(id) = deploy.get_alias(site, alias).await? {
            active.push((id, format!("{site}/{alias}")));
        }
    }
    for (id, scope) in active {
        let Some(manifest) = deploy.get_manifest(&id).await? else {
            continue;
        };
        for consumer in &manifest.config.consumers {
            let namespaced = format!("{scope}/{}", consumer.topic);
            out.push(ConsumerStat {
                scope: scope.clone(),
                topic: consumer.topic.clone(),
                backlog: messaging.backlog(&namespaced).await.unwrap_or(0),
                dead_letters: messaging.dead_letter_count(&namespaced).await.unwrap_or(0),
            });
        }
    }
    Ok(out)
}

/// Query params for the logs endpoint:
/// `?limit=<n>&after=<seq>&stream=stdout|stderr`.
#[cfg(feature = "handlers")]
#[derive(Deserialize)]
pub(super) struct LogsQuery {
    limit: Option<usize>,
    after: Option<u64>,
    stream: Option<String>,
}

/// The logs endpoint response: recent captured lines + the rate-cap drop count.
#[cfg(feature = "handlers")]
#[derive(Serialize)]
struct LogsResponse {
    entries: Vec<logs::LogEntry>,
    dropped: u64,
}

/// Authenticated per-site captured guest logs (`site:<site>` scope). Returns the
/// most recent lines (newest last), optionally filtered to one stream, plus the
/// count dropped by the per-site rate cap.
#[cfg(feature = "handlers")]
pub(super) async fn operator_logs(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Response {
    let Some(inner) = handlers.inner.as_ref() else {
        return Json(LogsResponse {
            entries: Vec::new(),
            dropped: 0,
        })
        .into_response();
    };
    let stream = match query.stream.as_deref() {
        Some("stdout") => Some(boatramp_handlers::LogStream::Stdout),
        Some("stderr") => Some(boatramp_handlers::LogStream::Stderr),
        _ => None,
    };
    let limit = query.limit.unwrap_or(200).min(1000);
    let (entries, dropped) = inner
        .logs
        .tail(&site, limit, query.after.unwrap_or(0), stream);
    Json(LogsResponse { entries, dropped }).into_response()
}

/// Live log tail over SSE (`GET …/_boatramp/logs/stream`): subscribe to the
/// capture feed, filter to this site, and emit each line as an SSE `log` event
/// (the `id` is the line seq, so a reconnect can resume). The console uses this
/// instead of polling. Same `site·read` gating as the poll endpoint.
#[cfg(feature = "handlers")]
pub(super) async fn operator_logs_stream(
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Path(site): Path<String>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    let Some(inner) = handlers.inner.as_ref() else {
        return (StatusCode::NOT_FOUND, "handlers disabled\n").into_response();
    };
    let rx = inner.logs.subscribe();
    let stream = futures::stream::unfold(rx, move |mut rx| {
        let site = site.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok((scope, entry)) if scope == site => {
                        let data = serde_json::to_string(&entry).unwrap_or_default();
                        let event = Event::default()
                            .id(entry.seq.to_string())
                            .event("log")
                            .data(data);
                        return Some((Ok::<_, std::convert::Infallible>(event), rx));
                    }
                    // Another site's line — keep waiting.
                    Ok(_) => continue,
                    // Fell behind: skip the gap and resume.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Admin-scoped Prometheus text exporter (`*` scope via the API auth
/// middleware). Always renders the process-wide serving + lifecycle counters
/// (request status classes / cache results / bytes, deploys, activations, cert
/// renewals); with the handlers feature it also renders the
/// per-`(site, trigger, route)` invocation counters plus, sampled at scrape
/// time, per-consumer queue-depth + dead-letter gauges across every site
/// (queue depth / consumer lag / DLQ).
#[cfg_attr(not(feature = "handlers"), allow(unused_variables))]
pub(super) async fn prometheus_metrics(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Extension(daemon): Extension<Arc<DaemonRuntime>>,
) -> Response {
    let mut body = srvmetrics::server_metrics().render_prometheus();
    // The active dynamic-config generation, as an info gauge whose `generation`
    // label is the `daemon/current` content address (`none` on the pure file
    // baseline). Scraping it across a cluster shows whether every node converged.
    let generation = daemon.generation().unwrap_or_else(|| "none".to_string());
    body.push_str(
        "# HELP boatramp_daemon_config_info Active dynamic daemon-config generation.\n\
         # TYPE boatramp_daemon_config_info gauge\n",
    );
    body.push_str(&format!(
        "boatramp_daemon_config_info{{generation=\"{generation}\"}} 1\n"
    ));
    #[cfg(feature = "handlers")]
    if let Some(inner) = handlers.inner.as_ref() {
        body.push_str(&inner.metrics.render_prometheus());
        if let Some(messaging) = &inner.messaging {
            let mut rows = Vec::new();
            // Best-effort: a deploy-store error just omits the gauges rather
            // than failing the whole scrape.
            if let Ok(sites) = deploy.list_sites().await {
                for site in sites {
                    if let Ok(stats) =
                        collect_consumer_stats(&deploy, messaging.as_ref(), &site).await
                    {
                        for s in stats {
                            rows.push(metrics::ConsumerGauge {
                                site: site.clone(),
                                scope: s.scope,
                                topic: s.topic,
                                backlog: s.backlog,
                                dead_letters: s.dead_letters,
                            });
                        }
                    }
                }
            }
            body.push_str(&metrics::render_consumer_gauges(&rows));
        }
        // Function usage series (FA-4), from the persisted metering aggregates.
        // Best-effort: a store error omits the block rather than failing the scrape.
        if let Ok(mut usage) = deploy.list_metering().await {
            if !usage.is_empty() {
                usage.sort_by(|a, b| a.function.cmp(&b.function));
                body.push_str(
                    "# HELP boatramp_function_invocations_total Function invocations metered.\n\
                     # TYPE boatramp_function_invocations_total counter\n",
                );
                for m in &usage {
                    let f = metrics::escape_label(&m.function);
                    body.push_str(&format!(
                        "boatramp_function_invocations_total{{function=\"{f}\"}} {}\n",
                        m.invocations
                    ));
                }
                body.push_str(
                    "# HELP boatramp_function_failures_total Function invocations that failed to deliver.\n\
                     # TYPE boatramp_function_failures_total counter\n",
                );
                for m in &usage {
                    let f = metrics::escape_label(&m.function);
                    body.push_str(&format!(
                        "boatramp_function_failures_total{{function=\"{f}\"}} {}\n",
                        m.failures
                    ));
                }
                body.push_str(
                    "# HELP boatramp_function_duration_ms_total Summed function wall-clock duration, ms.\n\
                     # TYPE boatramp_function_duration_ms_total counter\n",
                );
                for m in &usage {
                    let f = metrics::escape_label(&m.function);
                    body.push_str(&format!(
                        "boatramp_function_duration_ms_total{{function=\"{f}\"}} {}\n",
                        m.duration_ms_total
                    ));
                }
            }
        }
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}
