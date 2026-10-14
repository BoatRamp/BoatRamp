//! System·Admin "Project transfer" panel — the web-console surface for native project
//! export / import (the env-clone feature). Mirrors the control-plane KV export/import in
//! [`crate::node_ops`]: a binary bundle download and a file-upload raw-byte POST, plus the
//! identity controls. The transport passphrase (for `include identity` / `adopt`) is entered
//! in a `type=password` field and sent in the `X-Boatramp-Transport-Key` HEADER — never a
//! query param / URL — and is read only at submit (never kept in component state).
//!
//! Endpoints (both `System·Admin`, server-gated — the console shows a 403 in-page if the
//! token lacks the scope, like every other admin panel):
//! - `POST /api/project-export?project&data_only&include_identity` → streams the bundle.
//! - `POST /api/project-import?project&apply&force&allow_schema_skew&identity` (bundle body).

use serde_json::Value;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use gloo_dialogs::confirm;

use crate::api::ApiError;
use crate::auth::use_session;
use crate::node_ops::{read_file_bytes, trigger_download};
use crate::widgets::{CheckField, ErrorBanner, INPUT, Pill, Section, Spinner, TextField, Tone};

const BTN_SECONDARY: &str = "rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 \
     hover:bg-slate-50 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 \
     focus-visible:ring-sky-500 focus-visible:ring-offset-2";
const BTN_DANGER: &str = "rounded-md bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 \
     disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 \
     focus-visible:ring-offset-2";

/// Percent-encode a project name for a query string (mirrors `node_ops`).
fn enc(s: &str) -> String {
    js_sys::encode_uri_component(s)
        .as_string()
        .unwrap_or_else(|| s.to_string())
}

/// Read a `type=password` input's trimmed value from its ref (empty if absent/unmounted).
fn ref_value(r: &NodeRef) -> String {
    r.cast::<HtmlInputElement>()
        .map(|el| el.value().trim().to_string())
        .unwrap_or_default()
}

// ===========================================================================
// Export
// ===========================================================================

/// Project export: download a BRPROJ bundle (`POST /api/project-export`). `data-only`
/// carries application data only; `include identity` adds the passphrase-wrapped KEK for a
/// same-environment recovery (implies a FULL bundle + a transport passphrase).
#[function_component(ProjectExport)]
pub fn project_export() -> Html {
    let session = use_session();
    let project = use_state(String::new);
    let data_only = use_state(|| true);
    let include_identity = use_state(|| false);
    let key_ref = use_node_ref();
    let running = use_state(|| false);
    let error = use_state(|| Option::<String>::None);
    // A short "downloaded" confirmation (filename + a secret-handling reminder when the
    // bundle carries the wrapped KEK) — the browser download alone gives no in-page outcome.
    let done = use_state(|| Option::<String>::None);

    let on_project = {
        let project = project.clone();
        Callback::from(move |v: String| project.set(v))
    };
    let on_data_only = {
        let data_only = data_only.clone();
        Callback::from(move |v: bool| data_only.set(v))
    };
    let on_include_identity = {
        let include_identity = include_identity.clone();
        Callback::from(move |v: bool| include_identity.set(v))
    };

    let run = {
        let session = session.clone();
        let project = project.clone();
        let data_only = data_only.clone();
        let include_identity = include_identity.clone();
        let key_ref = key_ref.clone();
        let running = running.clone();
        let error = error.clone();
        let done = done.clone();
        Callback::from(move |_: MouseEvent| {
            let name = (*project).trim().to_string();
            if name.is_empty() {
                error.set(Some("Enter a project name.".into()));
                return;
            }
            // `include identity` implies a FULL bundle (data-only carries no identity) and
            // needs a transport passphrase to wrap the KEK.
            let include_identity = *include_identity;
            let data_only = *data_only && !include_identity;
            let key = ref_value(&key_ref);
            if include_identity && key.is_empty() {
                error.set(Some(
                    "Include identity needs a transport passphrase.".into(),
                ));
                return;
            }
            let path = format!(
                "/api/project-export?project={}&data_only={data_only}&include_identity={include_identity}",
                enc(&name)
            );
            let client = session.client();
            let session = session.clone();
            let running = running.clone();
            let error = error.clone();
            let done = done.clone();
            running.set(true);
            error.set(None);
            done.set(None);
            spawn_local(async move {
                let outcome = if include_identity {
                    client
                        .get_bytes_with_header(&path, "X-Boatramp-Transport-Key", &key)
                        .await
                } else {
                    client.get_bytes(&path).await
                };
                running.set(false);
                match outcome {
                    Ok(bytes) => {
                        let fname = format!("{name}-bundle.brproj");
                        if let Err(msg) = trigger_download(&fname, &bytes) {
                            error.set(Some(msg));
                        } else if include_identity {
                            done.set(Some(format!(
                                "{fname} — carries the wrapped KEK; store it securely and delete when done."
                            )));
                        } else {
                            done.set(Some(format!("{fname} — store it securely.")));
                        }
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    html! {
        <Section title="Project export">
            <p class="text-sm text-slate-500">
                { "Export a project (managed DB dumps + control-plane KV + blobs) to a portable \
                   BRPROJ bundle, streamed from the running node. Store it securely." }
            </p>
            <TextField label="Project" value={(*project).clone()} placeholder="acme"
                       on_change={on_project} />
            <CheckField label="data-only (application data only — no control-plane KV / identity)"
                        checked={*data_only && !*include_identity}
                        disabled={*include_identity}
                        on_change={on_data_only} />
            <CheckField label="include identity (wrap the project KEK for a same-environment recovery; implies FULL)"
                        checked={*include_identity} on_change={on_include_identity} />
            if *include_identity {
                <p class="text-xs text-slate-500">
                    { "Identity included → a full bundle; data-only doesn't apply." }
                </p>
                <label class="block">
                    <span class="block text-sm font-medium text-slate-700">
                        { "Transport passphrase" }
                    </span>
                    <input ref={key_ref} id="export-transport-key" type="password"
                           autocomplete="off" aria-describedby="export-transport-hint"
                           class={INPUT} placeholder="wraps the exported KEK" />
                </label>
                <p id="export-transport-hint" class="text-xs text-amber-700">
                    { "The bundle will carry the KEK (passphrase-wrapped) — handle it as a secret." }
                </p>
            }
            <button onclick={run} disabled={*running} class={BTN_SECONDARY}>
                { if *running { "Exporting…" } else { "Download bundle" } }
            </button>
            if let Some(msg) = &*error {
                <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
            }
            if let Some(d) = &*done {
                <div role="status" class="flex items-center gap-2">
                    <Pill text="downloaded" tone={Tone::Good} />
                    <span class="text-sm text-slate-600">{ d.clone() }</span>
                </div>
            }
        </Section>
    }
}

// ===========================================================================
// Import
// ===========================================================================

/// Project import: upload a BRPROJ bundle (`POST /api/project-import`). Dry-run (plan) by
/// default; "Apply" confirms. `adopt` installs the bundle's KEK (same-environment recovery,
/// needs the transport passphrase); the default `fresh` mints a new identity and drops the
/// source's sealed secrets.
#[function_component(ProjectImport)]
pub fn project_import() -> Html {
    let session = use_session();
    let project = use_state(String::new);
    let file = use_mut_ref(|| Option::<(String, Vec<u8>)>::None);
    let filename = use_state(|| Option::<String>::None);
    let force = use_state(|| false);
    let allow_schema_skew = use_state(|| false);
    let adopt = use_state(|| false);
    let key_ref = use_node_ref();
    let result = use_state(|| Option::<Result<Value, String>>::None);
    let running = use_state(|| false);
    // Apply is gated on a COMPLETED dry-run of the current inputs; any input change clears it
    // so the operator can never apply a plan they haven't reviewed for the current settings.
    let planned = use_state(|| false);

    let on_project = {
        let project = project.clone();
        let planned = planned.clone();
        Callback::from(move |v: String| {
            project.set(v);
            planned.set(false);
        })
    };
    let on_force = {
        let force = force.clone();
        let planned = planned.clone();
        Callback::from(move |v: bool| {
            force.set(v);
            planned.set(false);
        })
    };
    let on_skew = {
        let allow_schema_skew = allow_schema_skew.clone();
        let planned = planned.clone();
        Callback::from(move |v: bool| {
            allow_schema_skew.set(v);
            planned.set(false);
        })
    };
    let on_adopt = {
        let adopt = adopt.clone();
        let planned = planned.clone();
        Callback::from(move |v: bool| {
            adopt.set(v);
            planned.set(false);
        })
    };

    let on_file = {
        let file = file.clone();
        let filename = filename.clone();
        let result = result.clone();
        let planned = planned.clone();
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
            planned.set(false);
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

    let run: std::rc::Rc<dyn Fn(bool)> = {
        let session = session.clone();
        let project = project.clone();
        let file = file.clone();
        let force = force.clone();
        let allow_schema_skew = allow_schema_skew.clone();
        let adopt = adopt.clone();
        let key_ref = key_ref.clone();
        let result = result.clone();
        let running = running.clone();
        let planned = planned.clone();
        std::rc::Rc::new(move |apply: bool| {
            let name = (*project).trim().to_string();
            if name.is_empty() {
                result.set(Some(Err("Enter the target project name.".to_string())));
                return;
            }
            let Some((_, bytes)) = file.borrow().clone() else {
                result.set(Some(Err("Choose a bundle file first.".to_string())));
                return;
            };
            let adopt = *adopt;
            let key = ref_value(&key_ref);
            if adopt && key.is_empty() {
                result.set(Some(Err(
                    "Adopt needs the transport passphrase that was used on export.".to_string(),
                )));
                return;
            }
            let identity = if adopt { "adopt" } else { "fresh" };
            if apply {
                let msg = if adopt {
                    format!(
                        "Import into `{name}` and ADOPT the bundle's identity — this INSTALLS the \
                         source KEK on this node (a same-environment recovery). Run the dry-run \
                         first. Continue?"
                    )
                } else {
                    format!(
                        "Import into `{name}` (identity: fresh — source-sealed secrets are dropped). \
                         Existing control-plane keys may be overwritten. Run the dry-run first. \
                         Continue?"
                    )
                };
                if !confirm(&msg) {
                    return;
                }
            }
            let path = format!(
                "/api/project-import?project={}&apply={apply}&force={}&allow_schema_skew={}&identity={identity}",
                enc(&name),
                *force,
                *allow_schema_skew,
            );
            let client = session.client();
            let session = session.clone();
            let result = result.clone();
            let running = running.clone();
            let planned = planned.clone();
            running.set(true);
            spawn_local(async move {
                let outcome = if adopt {
                    client
                        .post_bytes_json_with_header::<Value>(
                            &path,
                            "application/octet-stream",
                            "X-Boatramp-Transport-Key",
                            &key,
                            bytes,
                        )
                        .await
                } else {
                    client
                        .post_bytes_json::<Value>(&path, "application/octet-stream", bytes)
                        .await
                };
                running.set(false);
                match outcome {
                    Ok(report) => {
                        // A completed DRY-RUN unlocks Apply (of these same inputs).
                        if !apply {
                            planned.set(true);
                        }
                        result.set(Some(Ok(report)));
                    }
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
        <Section title="Project import">
            <p class="text-sm text-slate-500">
                { "Restore a BRPROJ bundle into a project. Dry-run plans the import; Apply commits it." }
            </p>
            <TextField label="Target project" value={(*project).clone()} placeholder="acme"
                       on_change={on_project} />
            <label class="block">
                <span class="mb-1 block text-sm font-medium text-slate-700">{ "Bundle file" }</span>
                <input type="file" accept=".brproj" aria-label="Bundle file" onchange={on_file}
                       class="block text-sm text-slate-600 file:mr-3 file:rounded-md file:border-0 \
                              file:bg-slate-100 file:px-3 file:py-1.5 file:text-sm file:font-medium \
                              hover:file:bg-slate-200" />
            </label>
            if let Some(name) = &*filename {
                <p class="text-xs text-slate-500">{ format!("selected: {name}") }</p>
            }
            <CheckField label="allow schema skew (proceed past a Postgres schema-ledger mismatch)"
                        checked={*allow_schema_skew} on_change={on_skew} />
            <label class="flex items-start gap-2 text-sm text-amber-700">
                <input type="checkbox" checked={*force}
                       onchange={Callback::from(move |e: Event| {
                           if let Some(i) = e.target_dyn_into::<HtmlInputElement>() { on_force.emit(i.checked()); }
                       })}
                       class="mt-0.5 h-4 w-4 shrink-0 rounded border-slate-300 text-amber-700 focus:ring-amber-500" />
                { "force — overlay a non-empty control-plane KV (commingles data)" }
            </label>
            <label class="flex items-start gap-2 text-sm text-rose-700">
                <input type="checkbox" checked={*adopt}
                       onchange={Callback::from(move |e: Event| {
                           if let Some(i) = e.target_dyn_into::<HtmlInputElement>() { on_adopt.emit(i.checked()); }
                       })}
                       class="mt-0.5 h-4 w-4 shrink-0 rounded border-slate-300 text-rose-700 focus:ring-rose-500" />
                { "adopt identity — INSTALL the bundle's KEK (same-environment recovery only)" }
            </label>
            if *adopt {
                <label class="block">
                    <span class="block text-sm font-medium text-slate-700">
                        { "Transport passphrase" }
                    </span>
                    <input ref={key_ref} id="import-transport-key" type="password"
                           autocomplete="off" aria-describedby="import-transport-hint"
                           class={INPUT} placeholder="the passphrase used on export" />
                </label>
                <p id="import-transport-hint" class="text-xs text-amber-700">
                    { "Must match the transport passphrase used when the bundle was exported." }
                </p>
            }
            <div class="flex items-center gap-2">
                <button onclick={on_dry} disabled={*running} class={BTN_SECONDARY}>{ "Dry run" }</button>
                <button onclick={on_apply} disabled={*running || !*planned} class={BTN_DANGER}>{ "Apply import" }</button>
                if !*planned {
                    <span class="text-xs text-slate-500">{ "Run a dry-run first." }</span>
                }
            </div>
            if *running { <Spinner label="Importing…" /> }
            <div role="status" aria-live="polite">
                if let Some(result) = &*result {
                    { match result {
                        Ok(report) => import_report_view(report),
                        Err(msg) => html! { <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /> },
                    } }
                }
            </div>
        </Section>
    }
}

/// Render the project-import `ImportReport` JSON (dry-run plan or applied result).
fn import_report_view(report: &Value) -> Html {
    let n = |k: &str| report.get(k).and_then(Value::as_u64).unwrap_or(0);
    let dry = report.get("dry_run").and_then(Value::as_bool).unwrap_or(true);
    let skew = report
        .get("schema_skew")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let headline = format!(
        "{} — pg {}, libsql {}, kv {} (verified {}), blobs {}",
        if dry { "dry run" } else { "applied" },
        n("pg_databases"),
        n("libsql_databases"),
        n("kv_records"),
        n("kv_verified"),
        n("blobs"),
    );
    let tone = if skew > 0 { Tone::Warn } else { Tone::Good };
    let pretty = serde_json::to_string_pretty(report).unwrap_or_else(|_| report.to_string());
    html! {
        <div class="space-y-2 border-t border-slate-100 pt-3">
            <div class="flex items-center gap-2">
                <Pill text={if dry { "plan" } else { "applied" }} tone={tone} />
                <span class="text-sm text-slate-600">{ headline }</span>
            </div>
            <pre class="max-h-60 overflow-auto rounded-lg bg-slate-50 p-3 text-xs text-slate-700">{ pretty }</pre>
        </div>
    }
}
