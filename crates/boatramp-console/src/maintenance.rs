//! Cluster-wide maintenance ops: prune (dry-run →
//! confirm → delete), integrity scrub, and the managed-cert status list. These
//! are admin-scoped (`*` token), not per-site.

use boatramp_types::cert::CertStatus;
use boatramp_types::deploy::{GcReport, ScrubReport};
use gloo_dialogs::confirm;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::auth::use_session;
use crate::format::relative_age;
use crate::hooks::{use_api, Fetch};
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// The maintenance view: prune, scrub, certs.
#[function_component(Maintenance)]
pub fn maintenance() -> Html {
    html! {
        <div class="space-y-8">
            <Certs />
            <Prune />
            <Scrub />
        </div>
    }
}

/// Managed-cert status: `GET /api/certs` → `Vec<CertStatus>` (domain + expiry,
/// never key material). Flags certs expiring within 14 days.
#[function_component(Certs)]
fn certs() -> Html {
    let list = use_api(|client| async move {
        client.get_json::<Vec<CertStatus>>("/api/certs").await
    });

    let body = match &list.state {
        Fetch::Loading => html! { <Spinner label="Loading certs…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(list.reload.clone())} />
        },
        Fetch::Ready(certs) if certs.is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No managed certificates." }</p>
        },
        Fetch::Ready(certs) => html! {
            <table class="w-full text-sm">
                <thead>
                    <tr class="border-b border-slate-200 text-left text-slate-500">
                        <th class="py-2 font-medium">{ "Domain" }</th>
                        <th class="py-2 font-medium">{ "Expires" }</th>
                        <th class="py-2 font-medium text-right">{ "Status" }</th>
                    </tr>
                </thead>
                <tbody>
                    { for certs.iter().map(cert_row) }
                </tbody>
            </table>
        },
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Certificates" }</h3>
            { body }
        </section>
    }
}

fn cert_row(cert: &CertStatus) -> Html {
    let now = crate::format::now_unix();
    let remaining = cert.not_after_unix.saturating_sub(now);
    let (tone, label) = if cert.not_after_unix <= now {
        (Tone::Bad, "expired")
    } else if remaining < 14 * 86_400 {
        (Tone::Warn, "expiring")
    } else {
        (Tone::Good, "valid")
    };
    // Show the time until expiry as a relative span (re-using relative_age on a
    // future timestamp would read "ago"; instead express days remaining).
    let expires = if cert.not_after_unix <= now {
        format!("{} ago", relative_age(cert.not_after_unix))
    } else {
        let days = remaining / 86_400;
        format!("in {days}d")
    };
    html! {
        <tr class="border-b border-slate-100">
            <td class="py-2.5 text-slate-700">{ &cert.domain }</td>
            <td class="py-2.5 text-slate-600">{ expires }</td>
            <td class="py-2.5 text-right"><Pill text={label} tone={tone} /></td>
        </tr>
    }
}

/// Prune: a read-only dry-run report (`GET /api/prune`), then an explicit
/// "Delete now" that POSTs (`POST /api/prune`) after confirmation.
#[function_component(Prune)]
fn prune() -> Html {
    let session = use_session();
    let report = use_api(|client| async move {
        client.get_json::<GcReport>("/api/prune").await
    });
    let result = use_state(|| Option::<Result<GcReport, String>>::None);

    let run_delete = {
        let session = session.clone();
        let report_reload = report.reload.clone();
        let result = result.clone();
        Callback::from(move |_: MouseEvent| {
            if !confirm(
                "Permanently delete orphan manifests and unreferenced blobs? \
                 This cannot be undone.",
            ) {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let report_reload = report_reload.clone();
            let result = result.clone();
            spawn_local(async move {
                match client.post_empty::<GcReport>("/api/prune").await {
                    Ok(report) => {
                        result.set(Some(Ok(report)));
                        report_reload.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => result.set(Some(Err(err.to_string()))),
                }
            });
        })
    };

    let dry_run = match &report.state {
        Fetch::Loading => html! { <Spinner label="Scanning…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(report.reload.clone())} />
        },
        Fetch::Ready(report) => gc_report_view(report, "Reclaimable (dry run)"),
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div class="mb-4 flex items-center justify-between">
                <h3 class="text-base font-semibold text-slate-900">{ "Prune" }</h3>
                <button onclick={run_delete}
                        class="rounded-md bg-rose-600 px-3 py-1.5 text-sm font-medium text-white \
                               hover:bg-rose-700">
                    { "Delete now" }
                </button>
            </div>
            { dry_run }
            if let Some(result) = &*result {
                <div class="mt-4 border-t border-slate-100 pt-4">
                    {
                        match result {
                            Ok(report) => gc_report_view(report, "Deleted"),
                            Err(msg) => html! {
                                <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
                            },
                        }
                    }
                </div>
            }
        </section>
    }
}

/// Render a [`GcReport`] under a heading.
fn gc_report_view(report: &GcReport, heading: &str) -> Html {
    html! {
        <div>
            <p class="mb-2 text-sm font-medium text-slate-600">{ heading.to_string() }</p>
            <dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
                <Stat label="Manifests" value={format!("{} / {}", report.manifests_removed, report.manifests_total)} />
                <Stat label="Blobs" value={format!("{} / {}", report.blobs_removed, report.blobs_total)} />
                <Stat label="Reclaimed" value={human_bytes(report.bytes_reclaimed)} />
            </dl>
        </div>
    }
}

/// Scrub: verify every stored blob still hashes to its key
/// (`POST /api/scrub` → `ScrubReport`). Read-only on the server side.
#[function_component(Scrub)]
fn scrub() -> Html {
    let session = use_session();
    let result = use_state(|| Option::<Result<ScrubReport, String>>::None);
    let running = use_state(|| false);

    let run = {
        let session = session.clone();
        let result = result.clone();
        let running = running.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let result = result.clone();
            let running = running.clone();
            running.set(true);
            spawn_local(async move {
                let outcome = client.post_empty::<ScrubReport>("/api/scrub").await;
                running.set(false);
                match outcome {
                    Ok(report) => result.set(Some(Ok(report))),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => result.set(Some(Err(err.to_string()))),
                }
            });
        })
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div class="mb-4 flex items-center justify-between">
                <h3 class="text-base font-semibold text-slate-900">{ "Integrity scrub" }</h3>
                <button onclick={run} disabled={*running}
                        class="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium \
                               text-slate-700 hover:bg-slate-50 disabled:opacity-50">
                    { if *running { "Scrubbing…" } else { "Run scrub" } }
                </button>
            </div>
            if let Some(result) = &*result {
                {
                    match result {
                        Ok(report) => scrub_report_view(report),
                        Err(msg) => html! {
                            <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
                        },
                    }
                }
            } else {
                <p class="text-sm text-slate-500">
                    { "Verify every stored blob still hashes to its key." }
                </p>
            }
        </section>
    }
}

/// Render a [`ScrubReport`]: a clean badge, or the mismatch / read-error lists.
fn scrub_report_view(report: &ScrubReport) -> Html {
    if report.is_clean() {
        return html! {
            <div class="flex items-center gap-2">
                <Pill text="clean" tone={Tone::Good} />
                <span class="text-sm text-slate-600">
                    { format!("{} blobs verified, no corruption.", report.checked) }
                </span>
            </div>
        };
    }
    html! {
        <div class="space-y-3">
            <div class="flex items-center gap-2">
                <Pill text="findings" tone={Tone::Bad} />
                <span class="text-sm text-slate-600">
                    { format!("{} checked · {} mismatched · {} unreadable",
                              report.checked, report.mismatched.len(), report.errors.len()) }
                </span>
            </div>
            if !report.mismatched.is_empty() {
                <div>
                    <p class="text-xs font-medium text-slate-500">{ "Hash mismatches" }</p>
                    <ul class="mt-1 space-y-1">
                        { for report.mismatched.iter().map(|m| html! {
                            <li class="font-mono text-xs text-rose-600">{ &m.key }</li>
                        }) }
                    </ul>
                </div>
            }
            if !report.errors.is_empty() {
                <div>
                    <p class="text-xs font-medium text-slate-500">{ "Read errors" }</p>
                    <ul class="mt-1 space-y-1">
                        { for report.errors.iter().map(|e| html! {
                            <li class="font-mono text-xs text-rose-600">
                                { format!("{}: {}", e.key, e.error) }
                            </li>
                        }) }
                    </ul>
                </div>
            }
        </div>
    }
}

/// A small label/value stat cell.
#[derive(Properties, PartialEq)]
struct StatProps {
    label: AttrValue,
    value: AttrValue,
}

#[function_component(Stat)]
fn stat(props: &StatProps) -> Html {
    html! {
        <div>
            <dt class="text-slate-500">{ &props.label }</dt>
            <dd class="font-medium text-slate-800">{ &props.value }</dd>
        </div>
    }
}

/// Human-readable byte size (binary units).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
