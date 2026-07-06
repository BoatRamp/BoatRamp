//! Observability: the Prometheus metrics dump
//! (`/api/metrics`, admin), a per-site live log tail (`/_boatramp/logs`,
//! polled), and per-site handler stats (`/_boatramp/handlers`, raw JSON).
//!
//! These endpoints exist only on a server built with the `handlers` feature; a
//! `404` is shown as a friendly "not available on this server" note rather than
//! an error.

use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::auth::use_session;
use crate::hooks::{use_api, Fetch};
use crate::logstream;
use crate::models::{LogEntry, LogsResponse};
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// Cap the in-memory log buffer so a long session stays bounded.
fn cap_buffer(buf: &mut Vec<String>) {
    const MAX: usize = 1000;
    if buf.len() > MAX {
        let drop = buf.len() - MAX;
        buf.drain(0..drop);
    }
}

/// The admin-scoped Prometheus metrics dump. Refreshable.
#[function_component(Metrics)]
pub fn metrics() -> Html {
    let text = use_api(|client| async move { client.get_text("/api/metrics").await });

    let body = match &text.state {
        Fetch::Loading => html! { <Spinner label="Loading metrics…" /> },
        Fetch::Failed(err) if err.is_not_found() => feature_disabled_note(),
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(text.reload.clone())} />
        },
        Fetch::Ready(dump) if dump.trim().is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No metrics reported yet." }</p>
        },
        Fetch::Ready(dump) => html! {
            <pre class="max-h-96 overflow-auto rounded-lg bg-slate-900 p-4 text-xs leading-relaxed \
                        text-slate-100">{ dump }</pre>
        },
    };

    let on_refresh = {
        let reload = text.reload.clone();
        Callback::from(move |_: MouseEvent| reload.emit(()))
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div class="mb-4 flex items-center justify-between">
                <h3 class="text-base font-semibold text-slate-900">{ "Prometheus metrics" }</h3>
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

/// A per-site observability tab: the live log tail + handler stats.
#[derive(Properties, PartialEq)]
pub struct SiteObservabilityProps {
    /// The site whose logs/stats are shown.
    pub site: String,
}

#[function_component(SiteObservability)]
pub fn site_observability(props: &SiteObservabilityProps) -> Html {
    html! {
        <div class="space-y-8">
            <LogTail site={props.site.clone()} />
            <HandlerStats site={props.site.clone()} />
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct SiteProp {
    site: String,
}

/// A live log tail: seed the recent backlog from the poll endpoint (which also
/// surfaces 404 → feature-disabled / 401 → sign-out), then stream new lines over
/// SSE (`…/logs/stream`) via fetch (so the Bearer token rides along).
#[function_component(LogTail)]
fn log_tail(props: &SiteProp) -> Html {
    let session = use_session();
    let site = props.site.clone();
    // Interior-mutable buffer so the long-lived SSE callback always appends to
    // the latest; `force` re-renders when it changes.
    let buffer = use_mut_ref(Vec::<String>::new);
    let disabled = use_state(|| false);
    let error = use_state(|| Option::<String>::None);
    let paused = use_state(|| false);
    let force = use_force_update();

    {
        let session = session.clone();
        let site = site.clone();
        let buffer = buffer.clone();
        let disabled = disabled.clone();
        let error = error.clone();
        let force = force.clone();
        use_effect_with((*paused, *disabled), move |(is_paused, is_disabled)| {
            // Holding the stream handle keeps it open; dropping it (cleanup on
            // pause / unmount) aborts the fetch.
            let mut handle: Option<logstream::LogStreamHandle> = None;
            if !*is_paused && !*is_disabled {
                // 1. Seed the recent backlog (and surface 404 / 401).
                {
                    let client = session.client();
                    let session = session.clone();
                    let site = site.clone();
                    let buffer = buffer.clone();
                    let disabled = disabled.clone();
                    let error = error.clone();
                    let force = force.clone();
                    spawn_local(async move {
                        let path = format!("/api/sites/{site}/_boatramp/logs?limit=200");
                        match client.get_json::<LogsResponse>(&path).await {
                            Ok(resp) => {
                                {
                                    let mut buf = buffer.borrow_mut();
                                    for entry in &resp.entries {
                                        buf.push(format!("[{}] {}", entry.stream, entry.line));
                                    }
                                    cap_buffer(&mut buf);
                                }
                                force.force_update();
                            }
                            Err(err) if err.is_unauthorized() => session.sign_out(),
                            Err(err) if err.is_not_found() => disabled.set(true),
                            Err(err) => error.set(Some(err.to_string())),
                        }
                    });
                }
                // 2. Live tail over SSE (fetch streaming carries the Bearer).
                if let Some(token) = session.bearer() {
                    let base = session.api_base();
                    let url = format!(
                        "{}/api/sites/{site}/_boatramp/logs/stream",
                        base.trim_end_matches('/')
                    );
                    let buffer = buffer.clone();
                    let force = force.clone();
                    handle = Some(logstream::open(&url, &token, move |payload| {
                        if let Ok(entry) = serde_json::from_str::<LogEntry>(&payload) {
                            {
                                let mut buf = buffer.borrow_mut();
                                buf.push(format!("[{}] {}", entry.stream, entry.line));
                                cap_buffer(&mut buf);
                            }
                            force.force_update();
                        }
                    }));
                }
            }
            move || drop(handle)
        });
    }

    let toggle = {
        let paused = paused.clone();
        Callback::from(move |_: MouseEvent| paused.set(!*paused))
    };

    if *disabled {
        return html! {
            <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Live logs" }</h3>
                { feature_disabled_note() }
            </section>
        };
    }

    let lines = buffer.borrow();

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div class="mb-4 flex items-center justify-between">
                <h3 class="text-base font-semibold text-slate-900">{ "Live logs" }</h3>
                <div class="flex items-center gap-2">
                    if *paused {
                        <Pill text="paused" tone={Tone::Warn} />
                    } else {
                        <Pill text="streaming" tone={Tone::Good} />
                    }
                    <button onclick={toggle}
                            class="rounded-md border border-slate-300 px-2.5 py-1 text-sm font-medium \
                                   text-slate-700 hover:bg-slate-50">
                        { if *paused { "Resume" } else { "Pause" } }
                    </button>
                </div>
            </div>
            if let Some(msg) = &*error {
                <div class="mb-4"><ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /></div>
            }
            if lines.is_empty() {
                <p class="text-sm text-slate-500">{ "No log lines captured yet." }</p>
            } else {
                <pre class="max-h-96 overflow-auto rounded-lg bg-slate-900 p-4 text-xs leading-relaxed \
                            text-slate-100">{ lines.join("\n") }</pre>
            }
        </section>
    }
}

/// Per-site handler stats, rendered as pretty-printed JSON (the server returns a
/// free-form `serde_json::Value`, so we show it raw rather than guess a schema).
#[function_component(HandlerStats)]
fn handler_stats(props: &SiteProp) -> Html {
    let site = props.site.clone();
    let stats = {
        let site = site.clone();
        use_api(move |client| {
            let site = site.clone();
            async move {
                client
                    .get_json::<serde_json::Value>(&format!("/api/sites/{site}/_boatramp/handlers"))
                    .await
            }
        })
    };

    let body = match &stats.state {
        Fetch::Loading => html! { <Spinner label="Loading stats…" /> },
        Fetch::Failed(err) if err.is_not_found() => feature_disabled_note(),
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(stats.reload.clone())} />
        },
        Fetch::Ready(value) => {
            let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
            html! {
                <pre class="max-h-96 overflow-auto rounded-lg bg-slate-50 p-4 text-xs leading-relaxed \
                            text-slate-700">{ pretty }</pre>
            }
        }
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Handler stats" }</h3>
            { body }
        </section>
    }
}

/// A friendly note shown when an endpoint 404s because the server was built
/// without the `handlers` feature.
fn feature_disabled_note() -> Html {
    html! {
        <p class="text-sm text-slate-500">
            { "Not available — this server was built without the " }
            <code class="rounded bg-slate-100 px-1 py-0.5 text-xs">{ "handlers" }</code>
            { " feature." }
        </p>
    }
}
