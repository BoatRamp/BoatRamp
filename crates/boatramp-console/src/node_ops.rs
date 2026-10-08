//! Node-global operations for the Maintenance page (admin, `System·Admin`):
//! blob drain/purge (NDJSON progress streams), control-plane KV
//! checkpoint/export/import, cluster membership, trust-anchor rotation, and
//! read-only views of the daemon config + RBAC policy.
//!
//! Every destructive action is confirmed ([`gloo_dialogs::confirm`]) with a
//! message naming exactly what it changes; dry-run is always the default. The
//! server gates each endpoint (`System·Admin`); this is the operator surface.

use std::rc::Rc;

use serde_json::Value;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::HtmlInputElement;
use yew::prelude::*;

use gloo_dialogs::confirm;

use crate::api::ApiError;
use crate::auth::use_session;
use crate::format::{human_bytes, now_unix};
use crate::hooks::{Fetch, use_api};
use crate::models::{DaemonConfigResponse, JoinToken, MeshMember};
use crate::ndjson::{self, StreamEnd};
use crate::widgets::{ErrorBanner, Pill, Section, Spinner, TextField, Tone};

// ===========================================================================
// Blobs — drain + purge (NDJSON progress streams)
// ===========================================================================

/// Blob drain: copy every object the primary is missing from the attached
/// read-fallback secondary (`POST /api/blob-drain`). Dry-run by default;
/// "Drain for real" confirms. A 422 means no `[serve.blob_fallback]` is
/// configured (nothing to drain).
#[function_component(BlobDrain)]
pub fn blob_drain() -> Html {
    let session = use_session();
    let lines = use_mut_ref(Vec::<Value>::new);
    let running = use_state(|| false);
    let error = use_state(|| Option::<String>::None);
    let disabled = use_state(|| false);
    let force = use_force_update();

    let run: Rc<dyn Fn(bool)> = {
        let session = session.clone();
        let lines = lines.clone();
        let running = running.clone();
        let error = error.clone();
        let disabled = disabled.clone();
        let force = force.clone();
        Rc::new(move |dry_run: bool| {
            if !dry_run
                && !confirm(
                    "Drain the read-fallback secondary into the primary for real? This copies \
                     every object the primary is missing; it deletes nothing.",
                )
            {
                return;
            }
            let Some(token) = session.bearer() else {
                session.sign_out();
                return;
            };
            let body = serde_json::json!({ "dry_run": dry_run }).to_string();
            start_stream(StreamOp {
                base: session.api_base(),
                token,
                path: "/api/blob-drain",
                body,
                lines: lines.clone(),
                running: running.clone(),
                error: error.clone(),
                disabled: disabled.clone(),
                force: force.clone(),
                sign_out: sign_out_cb(&session),
            });
        })
    };

    let on_dry = {
        let run = run.clone();
        Callback::from(move |_: MouseEvent| run(true))
    };
    let on_real = Callback::from(move |_: MouseEvent| run(false));

    html! {
        <Section title="Blob drain">
            <p class="text-sm text-slate-500">
                { "Copy every object the primary is missing from the attached read-fallback \
                   secondary, so the secondary can be removed." }
            </p>
            if *disabled {
                { note("No read-fallback secondary is attached (no [serve.blob_fallback]); nothing to drain.") }
            } else {
                <div class="flex gap-2">
                    <button onclick={on_dry} disabled={*running} class={BTN_SECONDARY}>{ "Dry run" }</button>
                    <button onclick={on_real} disabled={*running} class={BTN_DANGER}>{ "Drain for real" }</button>
                </div>
                if *running { <Spinner label="Draining…" /> }
                if let Some(msg) = &*error {
                    <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
                }
                { render_stream(&lines.borrow()) }
            }
        </Section>
    }
}

/// Blob purge: reclaim provably-safe blobs (`POST /api/blob-purge`), in one of
/// two modes — `unreferenced` (GC of blobs no manifest points at) or
/// `drained_source` (decommission a drained secondary). Dry-run by default;
/// "Apply" confirms. 409 = unsafe unreferenced GC while a fallback is attached;
/// 422 = no drained secondary.
#[function_component(BlobPurge)]
pub fn blob_purge() -> Html {
    let session = use_session();
    let mode = use_state(|| "unreferenced".to_string());
    let lines = use_mut_ref(Vec::<Value>::new);
    let running = use_state(|| false);
    let error = use_state(|| Option::<String>::None);
    let disabled = use_state(|| false);
    let force = use_force_update();

    let run: Rc<dyn Fn(bool)> = {
        let session = session.clone();
        let mode = mode.clone();
        let lines = lines.clone();
        let running = running.clone();
        let error = error.clone();
        let disabled = disabled.clone();
        let force = force.clone();
        Rc::new(move |apply: bool| {
            if apply
                && !confirm(&format!(
                    "Permanently reclaim blobs in '{}' mode? Dry-run first to see what would be \
                     removed. This cannot be undone.",
                    *mode
                ))
            {
                return;
            }
            let Some(token) = session.bearer() else {
                session.sign_out();
                return;
            };
            let body = serde_json::json!({ "mode": *mode, "apply": apply }).to_string();
            start_stream(StreamOp {
                base: session.api_base(),
                token,
                path: "/api/blob-purge",
                body,
                lines: lines.clone(),
                running: running.clone(),
                error: error.clone(),
                disabled: disabled.clone(),
                force: force.clone(),
                sign_out: sign_out_cb(&session),
            });
        })
    };

    let on_mode = {
        let mode = mode.clone();
        Callback::from(move |e: Event| {
            if let Some(sel) = e.target_dyn_into::<web_sys::HtmlSelectElement>() {
                mode.set(sel.value());
            }
        })
    };
    let on_dry = {
        let run = run.clone();
        Callback::from(move |_: MouseEvent| run(false))
    };
    let on_apply = Callback::from(move |_: MouseEvent| run(true));

    html! {
        <Section title="Blob purge">
            <p class="text-sm text-slate-500">
                { "Reclaim provably-safe blobs. 'unreferenced' GCs blobs no manifest points at; \
                   'drained source' decommissions a fully-drained secondary." }
            </p>
            <div class="flex flex-wrap items-center gap-2">
                <select onchange={on_mode} disabled={*running} class={SELECT}>
                    <option value="unreferenced" selected={*mode == "unreferenced"}>{ "unreferenced (GC)" }</option>
                    <option value="drained_source" selected={*mode == "drained_source"}>{ "drained source" }</option>
                </select>
                <button onclick={on_dry} disabled={*running} class={BTN_SECONDARY}>{ "Dry run" }</button>
                <button onclick={on_apply} disabled={*running} class={BTN_DANGER}>{ "Apply" }</button>
            </div>
            if *disabled {
                { note("No read-fallback secondary is attached (no [serve.blob_fallback]); there is no drained secondary to purge.") }
            }
            if *running { <Spinner label="Purging…" /> }
            if let Some(msg) = &*error {
                <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
            }
            { render_stream(&lines.borrow()) }
        </Section>
    }
}

/// The handles + inputs a streaming op needs; grouped so [`start_stream`] has a
/// readable signature.
struct StreamOp {
    base: String,
    token: String,
    path: &'static str,
    body: String,
    lines: Rc<std::cell::RefCell<Vec<Value>>>,
    running: UseStateHandle<bool>,
    error: UseStateHandle<Option<String>>,
    disabled: UseStateHandle<bool>,
    force: UseForceUpdateHandle,
    sign_out: Callback<()>,
}

/// Kick off an NDJSON stream, wiring each line into `lines` and the terminal
/// outcome into `running`/`error`/`disabled`. 401 signs out; 422 flips the
/// "nothing configured" note; any other non-2xx surfaces the server's message.
fn start_stream(op: StreamOp) {
    op.lines.borrow_mut().clear();
    op.error.set(None);
    op.disabled.set(false);
    op.running.set(true);
    op.force.force_update();

    let url = format!("{}{}", op.base.trim_end_matches('/'), op.path);
    let on_line = {
        let lines = op.lines.clone();
        let force = op.force.clone();
        move |line: String| {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                lines.borrow_mut().push(v);
                force.force_update();
            }
        }
    };
    let on_end = {
        let running = op.running.clone();
        let error = op.error.clone();
        let disabled = op.disabled.clone();
        let force = op.force.clone();
        let sign_out = op.sign_out.clone();
        move |end: StreamEnd| {
            running.set(false);
            match end {
                StreamEnd::Done => {}
                StreamEnd::Http { status: 401, .. } => sign_out.emit(()),
                StreamEnd::Http { status: 422, .. } => disabled.set(true),
                StreamEnd::Http { status, body } => error.set(Some(err_message(status, &body))),
                StreamEnd::Transport(msg) => error.set(Some(msg)),
            }
            force.force_update();
        }
    };
    ndjson::post_stream(&url, &op.token, op.body, on_line, on_end);
}

/// Render the latest progress line + the final report line of a stream.
fn render_stream(lines: &[Value]) -> Html {
    if lines.is_empty() {
        return html! {};
    }
    let progress = lines.iter().rev().find(|v| v["type"] == "progress");
    let report = lines.iter().rev().find(|v| v["type"] == "report");
    html! {
        <div class="mt-3 space-y-3">
            if let Some(p) = progress { { progress_row(p) } }
            if let Some(r) = report { { report_block(r) } }
        </div>
    }
}

/// A compact progress line (whichever counters the stream carries).
fn progress_row(p: &Value) -> Html {
    let mut cells: Vec<Html> = Vec::new();
    let mut push =
        |label: &str, val: String| cells.push(html! { <span>{ format!("{label}: {val}") }</span> });
    if let (Some(done), Some(total)) = (num(p, "done"), num(p, "total")) {
        push("progress", format!("{done} / {total}"));
    }
    if let Some(n) = num(p, "copied") {
        push("copied", n.to_string());
    }
    if let Some(n) = num(p, "purged") {
        push("purged", n.to_string());
    }
    if let Some(n) = num(p, "skipped").or_else(|| num(p, "skipped_unconfirmed")) {
        push("skipped", n.to_string());
    }
    if let Some(n) = num(p, "copied_bytes").or_else(|| num(p, "purged_bytes")) {
        push("bytes", human_bytes(n));
    }
    html! {
        <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">{ for cells }</div>
    }
}

/// The final report line: a tone pill + the server's message, plus any missing-key list.
fn report_block(r: &Value) -> Html {
    let failed =
        r.get("error").is_some() || r.get("verified").and_then(Value::as_bool) == Some(false);
    let (tone, label) = if failed {
        (Tone::Bad, "failed")
    } else {
        (Tone::Good, "done")
    };
    let message = r
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| r.get("message").and_then(Value::as_str))
        .unwrap_or("complete")
        .to_string();
    let missing: Vec<String> = r
        .get("missing_keys")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    html! {
        <div class="space-y-2 border-t border-slate-100 pt-3">
            <div class="flex items-center gap-2">
                <Pill text={label} tone={tone} />
                <span class="text-sm text-slate-600">{ message }</span>
            </div>
            if !missing.is_empty() {
                <ul class="space-y-0.5">
                    { for missing.iter().map(|k| html! {
                        <li class="font-mono text-xs text-rose-600">{ k }</li>
                    }) }
                </ul>
            }
        </div>
    }
}

// ===========================================================================
// Control-plane KV — checkpoint / export / import
// ===========================================================================

/// KV checkpoint: freeze the WAL→L0 so the volume is a consistent snapshot
/// point (`POST /api/kv-checkpoint`). Read-only to the data; safe to run.
#[function_component(KvCheckpoint)]
pub fn kv_checkpoint() -> Html {
    let session = use_session();
    let result = use_state(|| Option::<Result<String, String>>::None);
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
                let outcome = client.post_text("/api/kv-checkpoint").await;
                running.set(false);
                match outcome {
                    Ok(msg) => result.set(Some(Ok(msg.trim().to_string()))),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => result.set(Some(Err(err.to_string()))),
                }
            });
        })
    };

    html! {
        <Section title="KV checkpoint">
            <p class="text-sm text-slate-500">
                { "Advance the durable frontier (WAL→L0) so the store is a consistent, bootable \
                   snapshot point — run before snapshotting the volume." }
            </p>
            <button onclick={run} disabled={*running} class={BTN_SECONDARY}>
                { if *running { "Checkpointing…" } else { "Checkpoint now" } }
            </button>
            if let Some(result) = &*result {
                { match result {
                    Ok(msg) => html! {
                        <div class="flex items-center gap-2">
                            <Pill text="done" tone={Tone::Good} />
                            <span class="text-sm text-slate-600">{ msg }</span>
                        </div>
                    },
                    Err(msg) => html! { <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /> },
                } }
            }
        </Section>
    }
}

/// KV export: download the whole control plane as a binary dump
/// (`GET /api/kv-export`). The dump carries SEALED secret ciphertext (never
/// plaintext or the envelope key) plus plaintext config + RBAC.
#[function_component(KvExport)]
pub fn kv_export() -> Html {
    let session = use_session();
    let running = use_state(|| false);
    let error = use_state(|| Option::<String>::None);

    let run = {
        let session = session.clone();
        let running = running.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let running = running.clone();
            let error = error.clone();
            running.set(true);
            error.set(None);
            spawn_local(async move {
                let outcome = client.get_bytes("/api/kv-export").await;
                running.set(false);
                match outcome {
                    Ok(bytes) => {
                        if let Err(msg) = trigger_download("boatramp-kv-dump", &bytes) {
                            error.set(Some(msg));
                        }
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    html! {
        <Section title="KV export">
            <p class="text-sm text-slate-500">
                { "Download the full control plane (sealed secret ciphertext + config + RBAC) as a \
                   binary dump. Store it securely — it restores via KV import." }
            </p>
            <button onclick={run} disabled={*running} class={BTN_SECONDARY}>
                { if *running { "Exporting…" } else { "Download dump" } }
            </button>
            if let Some(msg) = &*error {
                <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
            }
        </Section>
    }
}

/// KV import: restore/overlay a `boatramp-kv-dump` (`POST /api/kv-import`).
/// Dry-run (plan) by default; "Apply" confirms. A separate "force" toggle
/// (own warning) overlays onto a non-empty / already-identified destination.
#[function_component(KvImport)]
pub fn kv_import() -> Html {
    let session = use_session();
    // (filename, bytes) of the selected dump file.
    let file = use_mut_ref(|| Option::<(String, Vec<u8>)>::None);
    let filename = use_state(|| Option::<String>::None);
    let force = use_state(|| false);
    let result = use_state(|| Option::<Result<Value, String>>::None);
    let running = use_state(|| false);

    let on_file = {
        let file = file.clone();
        let filename = filename.clone();
        let result = result.clone();
        Callback::from(move |e: Event| {
            let Some(input) = e.target_dyn_into::<HtmlInputElement>() else {
                return;
            };
            let Some(f) = input.files().and_then(|l| l.get(0)) else {
                return;
            };
            let name = f.name();
            let file = file.clone();
            let filename = filename.clone();
            let result = result.clone();
            result.set(None);
            spawn_local(async move {
                match read_file_bytes(f).await {
                    Ok(bytes) => {
                        *file.borrow_mut() = Some((name.clone(), bytes));
                        filename.set(Some(name));
                    }
                    Err(msg) => result.set(Some(Err(msg))),
                }
            });
        })
    };

    let on_force = {
        let force = force.clone();
        Callback::from(move |e: Event| {
            if let Some(input) = e.target_dyn_into::<HtmlInputElement>() {
                force.set(input.checked());
            }
        })
    };

    let run: Rc<dyn Fn(bool)> = {
        let session = session.clone();
        let file = file.clone();
        let force = force.clone();
        let result = result.clone();
        let running = running.clone();
        Rc::new(move |apply: bool| {
            let Some((_, bytes)) = file.borrow().clone() else {
                result.set(Some(Err("Choose a dump file first.".to_string())));
                return;
            };
            if apply
                && !confirm(
                    "Import this dump into the control plane? Run the dry-run first and review the \
                     plan. Existing keys with the same name will be overwritten.",
                )
            {
                return;
            }
            let path = format!("/api/kv-import?apply={}&force={}", apply, *force);
            let client = session.client();
            let session = session.clone();
            let result = result.clone();
            let running = running.clone();
            running.set(true);
            spawn_local(async move {
                let outcome = client
                    .post_bytes_json::<Value>(&path, "application/octet-stream", bytes)
                    .await;
                running.set(false);
                match outcome {
                    Ok(plan) => result.set(Some(Ok(plan))),
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    Err(err) => result.set(Some(Err(err.to_string()))),
                }
            });
        })
    };

    let on_dry = {
        let run = run.clone();
        Callback::from(move |_: MouseEvent| run(false))
    };
    let on_apply = Callback::from(move |_: MouseEvent| run(true));

    html! {
        <Section title="KV import">
            <p class="text-sm text-slate-500">
                { "Restore or overlay a boatramp-kv-dump. Dry-run plans the write; Apply commits it." }
            </p>
            <input type="file" onchange={on_file} class="block text-sm text-slate-600" />
            if let Some(name) = &*filename {
                <p class="text-xs text-slate-500">{ format!("selected: {name}") }</p>
            }
            <label class="flex items-center gap-2 text-sm text-amber-700">
                <input type="checkbox" checked={*force} onchange={on_force}
                       class="h-4 w-4 rounded border-slate-300 text-amber-600 focus:ring-amber-500" />
                { "force — overlay onto a non-empty / already-identified control plane (commingles data)" }
            </label>
            <div class="flex gap-2">
                <button onclick={on_dry} disabled={*running} class={BTN_SECONDARY}>{ "Dry run" }</button>
                <button onclick={on_apply} disabled={*running} class={BTN_DANGER}>{ "Apply import" }</button>
            </div>
            if *running { <Spinner label="Importing…" /> }
            if let Some(result) = &*result {
                { match result {
                    Ok(plan) => import_plan_view(plan),
                    Err(msg) => html! { <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /> },
                } }
            }
        </Section>
    }
}

/// Render a KV import plan/report (`mode:"dry_run"` plan or `mode:"applied"`).
fn import_plan_view(plan: &Value) -> Html {
    let mode = plan.get("mode").and_then(Value::as_str).unwrap_or("");
    let headline = if mode == "applied" {
        format!(
            "applied — wrote {}, verified {}",
            num(plan, "written").unwrap_or(0),
            num(plan, "verified").unwrap_or(0)
        )
    } else {
        format!(
            "dry run — {} source entries, would write {}",
            num(plan, "source_entries").unwrap_or(0),
            num(plan, "would_write").unwrap_or(0)
        )
    };
    let tone = if plan.get("would_refuse_commingle").and_then(Value::as_bool) == Some(true) {
        Tone::Warn
    } else {
        Tone::Good
    };
    let pretty = serde_json::to_string_pretty(plan).unwrap_or_else(|_| plan.to_string());
    html! {
        <div class="space-y-2 border-t border-slate-100 pt-3">
            <div class="flex items-center gap-2">
                <Pill text={if mode == "applied" { "applied" } else { "plan" }} tone={tone} />
                <span class="text-sm text-slate-600">{ headline }</span>
            </div>
            <pre class="max-h-60 overflow-auto rounded-lg bg-slate-50 p-3 text-xs text-slate-700">{ pretty }</pre>
        </div>
    }
}

// ===========================================================================
// Cluster — members, join token, promote, revoke
// ===========================================================================

/// Cluster membership + mesh controls. On a non-cluster node the endpoints 501;
/// then only the note shows and the mutating controls are hidden.
#[function_component(Cluster)]
pub fn cluster() -> Html {
    let members = use_api(|client| async move {
        client
            .get_json::<Vec<MeshMember>>("/api/cluster/members")
            .await
    });

    match &members.state {
        Fetch::Loading => {
            html! { <Section title="Cluster"><Spinner label="Loading members…" /></Section> }
        }
        Fetch::Failed(ApiError::Status { code: 501, .. }) => html! {
            <Section title="Cluster">{ note("This node is not a cluster node.") }</Section>
        },
        Fetch::Failed(err) => html! {
            <Section title="Cluster">
                <ErrorBanner message={err.to_string()} on_retry={Some(members.reload.clone())} />
            </Section>
        },
        Fetch::Ready(list) => html! {
            <Section title="Cluster">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-slate-200 text-left text-slate-500">
                            <th class="py-2 font-medium">{ "Node" }</th>
                            <th class="py-2 font-medium">{ "Role" }</th>
                            <th class="py-2 font-medium">{ "Status" }</th>
                            <th class="py-2 font-medium">{ "Address" }</th>
                        </tr>
                    </thead>
                    <tbody>{ for list.iter().map(member_row) }</tbody>
                </table>
                <JoinTokenCard />
                <NodeAction title="Promote a learner" verb="Promote" path="/api/cluster/promote"
                            confirm_msg="Promote this learner to a voter?" on_done={members.reload.clone()} />
                <NodeAction title="Revoke a node" verb="Revoke" path="/api/cluster/revoke"
                            confirm_msg="Revoke this node from the mesh? It will be removed from membership."
                            on_done={members.reload.clone()} />
            </Section>
        },
    }
}

fn member_row(m: &MeshMember) -> Html {
    let role = if m.voter { "voter" } else { "learner" };
    let (tone, label) = if m.leader {
        (Tone::Good, "leader")
    } else if m.caught_up {
        (Tone::Neutral, "caught up")
    } else {
        (Tone::Warn, "lagging")
    };
    html! {
        <tr class="border-b border-slate-100">
            <td class="py-2.5 font-mono text-slate-700">{ m.node }</td>
            <td class="py-2.5 text-slate-600">{ role }</td>
            <td class="py-2.5"><Pill text={label} tone={tone} /></td>
            <td class="py-2.5 font-mono text-xs text-slate-500">{ m.addr.clone().unwrap_or_default() }</td>
        </tr>
    }
}

/// Mint a single-use mesh join token (`POST /api/cluster/join-token`), shown once.
#[function_component(JoinTokenCard)]
fn join_token_card() -> Html {
    let session = use_session();
    let result = use_state(|| Option::<Result<JoinToken, String>>::None);
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
                let body = serde_json::json!({});
                let outcome = client
                    .post_json::<_, JoinToken>("/api/cluster/join-token", &body)
                    .await;
                running.set(false);
                match outcome {
                    Ok(tok) => result.set(Some(Ok(tok))),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => result.set(Some(Err(err.to_string()))),
                }
            });
        })
    };

    html! {
        <div class="border-t border-slate-100 pt-4">
            <div class="flex items-center justify-between">
                <h4 class="text-sm font-semibold text-slate-900">{ "Join token" }</h4>
                <button onclick={run} disabled={*running} class={BTN_SECONDARY}>
                    { if *running { "Minting…" } else { "Mint join token" } }
                </button>
            </div>
            if let Some(result) = &*result {
                { match result {
                    Ok(tok) => html! {
                        <div class="mt-2 space-y-1">
                            <p class="text-xs text-slate-500">
                                { format!("expires in ~{} min — shown once, copy it now",
                                          tok.expires_at.saturating_sub(now_unix()).div_ceil(60)) }
                            </p>
                            <pre class="overflow-auto rounded-lg bg-slate-900 p-3 text-xs text-slate-100">{ &tok.token }</pre>
                        </div>
                    },
                    Err(msg) => html! { <div class="mt-2"><ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /></div> },
                } }
            }
        </div>
    }
}

/// A node-id action (promote / revoke): a number input + a confirmed POST
/// `{node_id}`.
#[derive(Properties, PartialEq)]
struct NodeActionProps {
    title: AttrValue,
    verb: AttrValue,
    path: AttrValue,
    confirm_msg: AttrValue,
    on_done: Callback<()>,
}

#[function_component(NodeAction)]
fn node_action(props: &NodeActionProps) -> Html {
    let session = use_session();
    let node_id = use_state(String::new);
    let error = use_state(|| Option::<String>::None);

    let on_input = {
        let node_id = node_id.clone();
        Callback::from(move |v: String| node_id.set(v))
    };
    let run = {
        let session = session.clone();
        let node_id = node_id.clone();
        let error = error.clone();
        let path = props.path.to_string();
        let confirm_msg = props.confirm_msg.to_string();
        let on_done = props.on_done.clone();
        Callback::from(move |_: MouseEvent| {
            let Ok(id) = node_id.trim().parse::<u64>() else {
                error.set(Some("Enter a numeric node id.".to_string()));
                return;
            };
            if !confirm(&format!("{confirm_msg} (node {id})")) {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let error = error.clone();
            let path = path.clone();
            let on_done = on_done.clone();
            spawn_local(async move {
                let body = serde_json::json!({ "node_id": id });
                match client.post_no_content_json(&path, &body).await {
                    Ok(()) => {
                        error.set(None);
                        on_done.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    html! {
        <div class="border-t border-slate-100 pt-4">
            <div class="flex items-end gap-2">
                <div class="w-40">
                    <TextField label={props.title.clone()} value={(*node_id).clone()}
                               placeholder="node id" on_change={on_input} />
                </div>
                <button onclick={run} class={BTN_DANGER}>{ props.verb.clone() }</button>
            </div>
            if let Some(msg) = &*error {
                <div class="mt-2"><ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /></div>
            }
        </div>
    }
}

// ===========================================================================
// Trust — root anchors (make-before-break rotation)
// ===========================================================================

/// Root trust anchors (`GET/PUT /api/auth/root`, `DELETE /api/auth/root/{key}`).
/// Add the new key BEFORE removing the old (make-before-break).
#[function_component(RootAnchors)]
pub fn root_anchors() -> Html {
    let session = use_session();
    let anchors =
        use_api(|client| async move { client.get_json::<Vec<String>>("/api/auth/root").await });
    let new_key = use_state(String::new);
    let error = use_state(|| Option::<String>::None);

    let on_input = {
        let new_key = new_key.clone();
        Callback::from(move |v: String| new_key.set(v))
    };
    let add = {
        let session = session.clone();
        let new_key = new_key.clone();
        let error = error.clone();
        let reload = anchors.reload.clone();
        Callback::from(move |_: MouseEvent| {
            let key = new_key.trim().to_string();
            if key.is_empty() {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let new_key = new_key.clone();
            let error = error.clone();
            let reload = reload.clone();
            spawn_local(async move {
                let body = serde_json::json!({ "pubkey": key });
                match client.put_json("/api/auth/root", &body).await {
                    Ok(()) => {
                        new_key.set(String::new());
                        error.set(None);
                        reload.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    let list = match &anchors.state {
        Fetch::Loading => html! { <Spinner label="Loading anchors…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(anchors.reload.clone())} />
        },
        Fetch::Ready(keys) if keys.is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No root anchors." }</p>
        },
        Fetch::Ready(keys) => html! {
            <ul class="space-y-1">
                { for keys.iter().map(|k| anchor_row(&session, k, anchors.reload.clone(), error.clone())) }
            </ul>
        },
    };

    html! {
        <Section title="Root trust anchors">
            <p class="text-sm text-slate-500">
                { "Signing keys trusted to issue tokens. Rotate make-before-break: add the new key \
                   first, confirm it works, then remove the old one." }
            </p>
            { list }
            <div class="flex items-end gap-2 border-t border-slate-100 pt-4">
                <div class="flex-1">
                    <TextField label="Add anchor" value={(*new_key).clone()}
                               placeholder="es256:…" mono={true} on_change={on_input} />
                </div>
                <button onclick={add} class={BTN_SECONDARY}>{ "Add" }</button>
            </div>
            if let Some(msg) = &*error {
                <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
            }
        </Section>
    }
}

/// One anchor row with a confirmed remove. A non-401 failure surfaces via
/// `error` (a destructive action must not fail silently); 401 re-auths.
fn anchor_row(
    session: &crate::auth::Session,
    key: &str,
    reload: Callback<()>,
    error: UseStateHandle<Option<String>>,
) -> Html {
    let session = session.clone();
    let key_owned = key.to_string();
    let remove = Callback::from(move |_: MouseEvent| {
        if !confirm(&format!(
            "Remove root anchor {key_owned}? Tokens signed only by this key will stop verifying."
        )) {
            return;
        }
        // URL-encode the alg:hex key for the path segment.
        let encoded = String::from(js_sys::encode_uri_component(&key_owned));
        let path = format!("/api/auth/root/{encoded}");
        let client = session.client();
        let session = session.clone();
        let reload = reload.clone();
        let error = error.clone();
        spawn_local(async move {
            match client.delete(&path).await {
                Ok(()) => {
                    error.set(None);
                    reload.emit(());
                }
                Err(err) if err.is_unauthorized() => session.sign_out(),
                Err(err) => error.set(Some(err.to_string())),
            }
        });
    });
    html! {
        <li class="flex items-center justify-between gap-3">
            <span class="truncate font-mono text-xs text-slate-700">{ key }</span>
            <button onclick={remove}
                    class="shrink-0 text-xs font-medium text-rose-600 hover:text-rose-700">
                { "Remove" }
            </button>
        </li>
    }
}

// ===========================================================================
// Config views (read-only this stage)
// ===========================================================================

/// Read-only view of the dynamic daemon config (`GET /api/daemon/config`).
#[function_component(DaemonConfigView)]
pub fn daemon_config_view() -> Html {
    let cfg = use_api(|client| async move {
        client
            .get_json::<DaemonConfigResponse>("/api/daemon/config")
            .await
    });

    let body = match &cfg.state {
        Fetch::Loading => html! { <Spinner label="Loading config…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(cfg.reload.clone())} />
        },
        Fetch::Ready(resp) => {
            let generation = resp
                .generation
                .clone()
                .unwrap_or_else(|| "file baseline".to_string());
            let pretty = serde_json::to_string_pretty(&resp.config)
                .unwrap_or_else(|_| resp.config.to_string());
            html! {
                <>
                    <p class="text-xs text-slate-500">{ format!("generation: {generation}") }</p>
                    <pre class="max-h-72 overflow-auto rounded-lg bg-slate-50 p-3 text-xs text-slate-700">{ pretty }</pre>
                </>
            }
        }
    };

    html! {
        <Section title="Daemon config">
            <p class="text-sm text-slate-500">{ "The live dynamic config. Editing comes in a later stage." }</p>
            { body }
        </Section>
    }
}

/// Read-only view of the RBAC policy (`GET /api/authz/policy`).
#[function_component(AuthzPolicyView)]
pub fn authz_policy_view() -> Html {
    let policy =
        use_api(|client| async move { client.get_json::<Value>("/api/authz/policy").await });

    let body = match &policy.state {
        Fetch::Loading => html! { <Spinner label="Loading policy…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(policy.reload.clone())} />
        },
        Fetch::Ready(p) => {
            let version = p.get("version").and_then(Value::as_u64).unwrap_or(0);
            let pretty = serde_json::to_string_pretty(p).unwrap_or_else(|_| p.to_string());
            html! {
                <>
                    <p class="text-xs text-slate-500">{ format!("version: {version}") }</p>
                    <pre class="max-h-72 overflow-auto rounded-lg bg-slate-50 p-3 text-xs text-slate-700">{ pretty }</pre>
                </>
            }
        }
    };

    html! {
        <Section title="RBAC policy">
            <p class="text-sm text-slate-500">{ "The roles→rights policy. Editing comes in a later stage." }</p>
            { body }
        </Section>
    }
}

// ===========================================================================
// Shared helpers + styles
// ===========================================================================

const BTN_SECONDARY: &str = "rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 \
     hover:bg-slate-50 disabled:opacity-50";
const BTN_DANGER: &str = "rounded-md bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 \
     disabled:opacity-50";
const SELECT: &str = "rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm focus:border-sky-500 \
     focus:outline-none focus:ring-1 focus:ring-sky-500";

/// A muted "not available / nothing to do" note.
fn note(text: &str) -> Html {
    html! { <p class="text-sm text-slate-500">{ text.to_string() }</p> }
}

/// Read an unsigned field off a hand-built JSON line.
fn num(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

/// Build a `HTTP <status>: <error>` message from a non-2xx body ({"error":…} or text).
fn err_message(status: u16, body: &str) -> String {
    let detail = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| body.trim().to_string());
    if detail.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {detail}")
    }
}

/// A sign-out [`Callback`] over the session (so a stream's `on_end` can re-auth).
fn sign_out_cb(session: &crate::auth::Session) -> Callback<()> {
    let session = session.clone();
    Callback::from(move |_| session.sign_out())
}

/// Read a `File`'s bytes via its `arrayBuffer()`.
async fn read_file_bytes(file: web_sys::File) -> Result<Vec<u8>, String> {
    let buf = JsFuture::from(file.array_buffer()).await.map_err(|e| {
        e.as_string()
            .unwrap_or_else(|| "could not read file".to_string())
    })?;
    Ok(js_sys::Uint8Array::new(&buf).to_vec())
}

/// Trigger a browser download of `bytes` as `filename` (Blob → object URL →
/// a programmatic `<a download>` click → revoke).
fn trigger_download(filename: &str, bytes: &[u8]) -> Result<(), String> {
    download_inner(filename, bytes).map_err(|e| {
        e.as_string()
            .unwrap_or_else(|| "download failed".to_string())
    })
}

fn download_inner(filename: &str, bytes: &[u8]) -> Result<(), JsValue> {
    let array = js_sys::Array::new();
    array.push(&js_sys::Uint8Array::from(bytes));
    let blob = web_sys::Blob::new_with_u8_array_sequence(&array)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)?;
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or_else(|| JsValue::from_str("no document"))?;
    let anchor: web_sys::HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    anchor.click();
    web_sys::Url::revoke_object_url(&url)?;
    Ok(())
}
