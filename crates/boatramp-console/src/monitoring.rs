//! The node **Monitoring** page: node-global, read-only operator signals that
//! previously had no home in the console —
//!
//! - `GET /api/version` — the running build (also shown as a header badge).
//! - `GET /api/instance-stats` — wasm instance lifecycle + memory (feature
//!   `handlers`; a `404` means the server was built without it).
//! - `GET /api/blob-status` — whether a read-fallback secondary is attached.
//! - `GET /api/kv-status` — control-plane KV health.
//! - the Prometheus `/api/metrics` dump, folded in from the old standalone tab.
//!
//! All are `System·Read` node-global; the server already gates them, so this is
//! pure presentation (no mutation). Each section refreshes independently.

use yew::prelude::*;

use crate::format::human_bytes;
use crate::hooks::{Fetch, use_api};
use crate::models::{
    BlobStatus, InstanceStatsSnapshot, KvStatus, LaneStats, NodeVersion, ProcessMemory,
};
use crate::observability::Metrics;
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// The Monitoring page: node version + instance stats + blob/kv health + metrics.
#[function_component(Monitoring)]
pub fn monitoring() -> Html {
    html! {
        <div class="space-y-8">
            <h2 class="text-lg font-semibold text-slate-900">{ "Monitoring" }</h2>
            <InstanceStatsCard />
            <div class="grid gap-6 lg:grid-cols-2">
                <BlobStatusCard />
                <KvStatusCard />
            </div>
            <Metrics />
        </div>
    }
}

/// A compact node-version pill for the header (`GET /api/version`). Renders
/// nothing until the version is known or if the fetch fails, so the header
/// never shows a spinner or an error for a non-essential badge.
#[function_component(NodeVersionBadge)]
pub fn node_version_badge() -> Html {
    let version =
        use_api(|client| async move { client.get_json::<NodeVersion>("/api/version").await });
    match &version.state {
        Fetch::Ready(v) => html! {
            <span class="hidden rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500 sm:inline"
                  title="running node build">
                { format!("v{}", v.version) }
            </span>
        },
        _ => html! {},
    }
}

/// `GET /api/instance-stats`: process memory + the three serve lanes.
#[function_component(InstanceStatsCard)]
fn instance_stats_card() -> Html {
    let stats = use_api(|client| async move {
        client
            .get_json::<InstanceStatsSnapshot>("/api/instance-stats")
            .await
    });

    let body = match &stats.state {
        Fetch::Loading => html! { <Spinner label="Loading instance stats…" /> },
        Fetch::Failed(err) if err.is_not_found() => handlers_disabled_note(),
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(stats.reload.clone())} />
        },
        Fetch::Ready(s) => html! {
            <div class="space-y-5">
                { memory_line(&s.memory) }
                <div class="grid gap-4 md:grid-cols-3">
                    { lane_card("request", &s.request) }
                    { lane_card("consumer", &s.consumer) }
                    { lane_card("session", &s.session) }
                </div>
            </div>
        },
    };

    card("Wasm instances", stats.reload.clone(), body)
}

/// `GET /api/blob-status`: is a read-fallback secondary attached (mid-migration)?
#[function_component(BlobStatusCard)]
fn blob_status_card() -> Html {
    let status =
        use_api(|client| async move { client.get_json::<BlobStatus>("/api/blob-status").await });

    let body = match &status.state {
        Fetch::Loading => html! { <Spinner label="Loading blob status…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(status.reload.clone())} />
        },
        Fetch::Ready(s) if s.blob_fallback_active => html! {
            <div class="flex items-center gap-2">
                <Pill text="read-fallback attached" tone={Tone::Warn} />
                <span class="text-sm text-slate-500">{ "a secondary store is serving reads (migration in progress)" }</span>
            </div>
        },
        Fetch::Ready(_) => html! {
            <div class="flex items-center gap-2">
                <Pill text="primary only" tone={Tone::Good} />
                <span class="text-sm text-slate-500">{ "no read-fallback secondary attached" }</span>
            </div>
        },
    };

    card("Blob storage", status.reload.clone(), body)
}

/// `GET /api/kv-status`: control-plane KV health (state pill + raw detail).
#[function_component(KvStatusCard)]
fn kv_status_card() -> Html {
    let status =
        use_api(|client| async move { client.get_json::<KvStatus>("/api/kv-status").await });

    let body = match &status.state {
        Fetch::Loading => html! { <Spinner label="Loading KV status…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(status.reload.clone())} />
        },
        Fetch::Ready(s) => {
            let (tone, label) = kv_tone(&s.state);
            let detail = if s.detail.is_empty() {
                html! {}
            } else {
                let pretty = serde_json::to_string_pretty(&s.detail)
                    .unwrap_or_else(|_| serde_json::Value::Object(s.detail.clone()).to_string());
                html! {
                    <pre class="mt-3 max-h-60 overflow-auto rounded-lg bg-slate-50 p-3 text-xs leading-relaxed \
                                text-slate-700">{ pretty }</pre>
                }
            };
            html! {
                <div>
                    <div class="flex items-center gap-2">
                        <Pill text={label} tone={tone} />
                        <span class="text-sm text-slate-500">{ &s.state }</span>
                    </div>
                    { detail }
                </div>
            }
        }
    };

    card("Control-plane KV", status.reload.clone(), body)
}

/// Map a `kv-status` state string to a pill tone + short label.
fn kv_tone(state: &str) -> (Tone, &'static str) {
    match state {
        "ok" | "recovered_lossless" => (Tone::Good, "healthy"),
        "recovered" => (Tone::Warn, "recovered"),
        "degraded" => (Tone::Bad, "degraded"),
        _ => (Tone::Neutral, "unknown"),
    }
}

/// Process memory: RSS vs the per-instance ceiling (uncapped shown as `∞`).
fn memory_line(memory: &ProcessMemory) -> Html {
    let rss = memory
        .rss_bytes
        .map(human_bytes)
        .unwrap_or_else(|| "— (off Linux)".to_string());
    // `u64::MAX` is the uncapped sentinel; anything near it is effectively uncapped.
    let limit = if memory.per_instance_limit_bytes >= u64::MAX / 2 {
        "∞ (uncapped)".to_string()
    } else {
        human_bytes(memory.per_instance_limit_bytes)
    };
    html! {
        <div class="flex flex-wrap gap-x-8 gap-y-2 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
            { stat("Process RSS", rss) }
            { stat("Per-instance limit", limit) }
        </div>
    }
}

/// One serve lane's lifecycle counters, as a small card.
fn lane_card(name: &str, lane: &LaneStats) -> Html {
    html! {
        <div class="rounded-lg border border-slate-200 p-4">
            <div class="mb-3 flex items-center justify-between">
                <h4 class="text-sm font-semibold text-slate-900">{ name }</h4>
                <span class="text-xs text-slate-400">
                    { format!("{} / {} warm", lane.warm_now, lane.warm_capacity) }
                </span>
            </div>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                { stat("in-flight", format!("{} / {}", lane.in_flight, lane.lane_ceiling)) }
                { stat("warm hits", lane.warm_hits.to_string()) }
                { stat("cold misses", lane.cold_misses.to_string()) }
                { stat("evictions", lane.evictions.to_string()) }
                { stat("instantiations", lane.instantiations.to_string()) }
                { stat("instantiate", format!("{}µs avg / {}µs max", lane.instantiate_us_avg, lane.instantiate_us_max)) }
                { stat("cold compile", format!("{}ms avg / {}ms max", lane.compile_ms_avg, lane.compile_ms_max)) }
            </dl>
        </div>
    }
}

/// A `<dt>/<dd>` stat pair (label + value).
fn stat(label: &str, value: String) -> Html {
    html! {
        <div class="flex items-baseline justify-between gap-3">
            <dt class="text-slate-500">{ label }</dt>
            <dd class="font-medium text-slate-900">{ value }</dd>
        </div>
    }
}

/// A section card with a title and a Refresh button wired to `reload`.
fn card(title: &str, reload: Callback<()>, body: Html) -> Html {
    let on_refresh = Callback::from(move |_: MouseEvent| reload.emit(()));
    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div class="mb-4 flex items-center justify-between">
                <h3 class="text-base font-semibold text-slate-900">{ title }</h3>
                <button onclick={on_refresh}
                        class="rounded-md border border-slate-300 px-2.5 py-1 text-sm font-medium \
                               text-slate-700 hover:bg-slate-50">
                    { "Refresh" }
                </button>
            </div>
            { body }
        </section>
    }
}

/// Shown when `/api/instance-stats` 404s because the server was built without
/// the `handlers` feature (same friendly treatment as the per-site views).
fn handlers_disabled_note() -> Html {
    html! {
        <p class="text-sm text-slate-500">
            { "Not available — this server was built without the " }
            <code class="rounded bg-slate-100 px-1 py-0.5 text-xs">{ "handlers" }</code>
            { " feature." }
        </p>
    }
}
