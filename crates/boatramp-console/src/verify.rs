//! The domain-ownership verification flow.
//!
//! Start a challenge (DNS-TXT or HTTP-token), show the operator the record/token
//! to publish, run the check (on success the server attaches the host to the
//! site), and list / drop challenges. Mirrors the CLI's `domain` subcommands
//! (`crates/boatramp/src/client.rs`).

use boatramp_types::domain_verify::{DomainVerification, VerificationMethod};
use gloo_dialogs::confirm;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::auth::use_session;
use crate::models::CheckResult;
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// Percent-encode a host for a URL path segment. Hostnames are `[a-z0-9.-]` plus
/// a leading `*.` for wildcards; only `*` needs escaping (matches the CLI's
/// `host_segment`).
fn host_segment(host: &str) -> String {
    host.replace('*', "%2A")
}

/// The verification panel for one site.
#[derive(Properties, PartialEq)]
pub struct DomainVerificationsProps {
    /// The site whose domain challenges are managed.
    pub site: String,
}

#[function_component(DomainVerifications)]
pub fn domain_verifications(props: &DomainVerificationsProps) -> Html {
    let session = use_session();
    let site = props.site.clone();
    // Reload trigger: bump to re-fetch after start/check/remove.
    let nonce = use_state(|| 0u32);
    let list = use_state(|| Option::<Vec<DomainVerification>>::None);
    let error = use_state(|| Option::<String>::None);

    // Fetch the challenge list whenever the nonce changes.
    {
        let session = session.clone();
        let site = site.clone();
        let list = list.clone();
        let error = error.clone();
        use_effect_with(*nonce, move |_| {
            let client = session.client();
            spawn_local(async move {
                match client
                    .get_json::<Vec<DomainVerification>>(&format!(
                        "/api/sites/{site}/domain-verifications"
                    ))
                    .await
                {
                    Ok(v) => list.set(Some(v)),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
            || ()
        });
    }

    let reload = {
        let nonce = nonce.clone();
        Callback::from(move |_: ()| nonce.set(*nonce + 1))
    };

    // --- Start a challenge ---
    let host_ref = use_node_ref();
    let method = use_state(|| VerificationMethod::Http);
    let on_method = {
        let method = method.clone();
        Callback::from(move |e: Event| {
            let value = e
                .target_dyn_into::<web_sys::HtmlSelectElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            method.set(match value.as_str() {
                "dns" => VerificationMethod::Dns,
                _ => VerificationMethod::Http,
            });
        })
    };
    let start = {
        let session = session.clone();
        let site = site.clone();
        let host_ref = host_ref.clone();
        let method = method.clone();
        let reload = reload.clone();
        let error = error.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let host = host_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            if host.is_empty() {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let method = *method;
            let reload = reload.clone();
            let error = error.clone();
            let host_ref = host_ref.clone();
            error.set(None);
            spawn_local(async move {
                let path = format!(
                    "/api/sites/{site}/domains/{}/verification?method={}",
                    host_segment(&host),
                    method.as_str()
                );
                match client.post_empty::<DomainVerification>(&path).await {
                    Ok(_) => {
                        if let Some(el) = host_ref.cast::<HtmlInputElement>() {
                            el.set_value("");
                        }
                        reload.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    let body = match &*list {
        None if error.is_some() => Html::default(),
        None => html! { <Spinner label="Loading challenges…" /> },
        Some(challenges) if challenges.is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No domain challenges. Start one below." }</p>
        },
        Some(challenges) => html! {
            <ul class="space-y-3">
                { for challenges.iter().map(|v| html! {
                    <Challenge key={v.host.clone()} site={site.clone()}
                               verification={v.clone()} on_changed={reload.clone()} />
                }) }
            </ul>
        },
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Domain verification" }</h3>
            if let Some(msg) = &*error {
                <div class="mb-4"><ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /></div>
            }
            { body }
            <form onsubmit={start} class="mt-4 flex flex-wrap items-end gap-3 border-t border-slate-100 pt-4">
                <div class="flex-1 min-w-[12rem]">
                    <label class="block text-xs font-medium text-slate-500">{ "Host" }</label>
                    <input ref={host_ref} placeholder="example.com or *.example.com"
                           class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm font-mono" />
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-500">{ "Method" }</label>
                    <select onchange={on_method}
                            class="mt-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-sm">
                        <option value="http" selected={*method == VerificationMethod::Http}>{ "HTTP token" }</option>
                        <option value="dns" selected={*method == VerificationMethod::Dns}>{ "DNS TXT" }</option>
                    </select>
                </div>
                <button type="submit"
                        class="rounded-md bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700">
                    { "Start challenge" }
                </button>
            </form>
        </section>
    }
}

/// One challenge row: its status, the record/token to publish, and check /
/// remove actions.
#[derive(Properties, PartialEq)]
struct ChallengeProps {
    site: String,
    verification: DomainVerification,
    on_changed: Callback<()>,
}

#[function_component(Challenge)]
fn challenge(props: &ChallengeProps) -> Html {
    let session = use_session();
    let v = props.verification.clone();
    let site = props.site.clone();
    // The result of the most recent check (passed/attached + any detail).
    let check = use_state(|| Option::<CheckResult>::None);
    let error = use_state(|| Option::<String>::None);

    let run_check = {
        let session = session.clone();
        let site = site.clone();
        let host = v.host.clone();
        let check = check.clone();
        let error = error.clone();
        let on_changed = props.on_changed.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let host = host.clone();
            let check = check.clone();
            let error = error.clone();
            let on_changed = on_changed.clone();
            error.set(None);
            spawn_local(async move {
                let path = format!(
                    "/api/sites/{site}/domains/{}/verification/check",
                    host_segment(&host)
                );
                match client.post_empty::<CheckResult>(&path).await {
                    Ok(result) => {
                        let attached = result.attached;
                        check.set(Some(result));
                        // On a successful attach the host moved into the config;
                        // refresh the list so its state reflects that.
                        if attached {
                            on_changed.emit(());
                        }
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    let remove = {
        let session = session.clone();
        let site = site.clone();
        let host = v.host.clone();
        let on_changed = props.on_changed.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            if !confirm(&format!("Drop the verification challenge for {host}?")) {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let host = host.clone();
            let on_changed = on_changed.clone();
            let error = error.clone();
            spawn_local(async move {
                let path = format!(
                    "/api/sites/{site}/domains/{}/verification",
                    host_segment(&host)
                );
                match client.delete(&path).await {
                    Ok(()) => on_changed.emit(()),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    let (tone, label) = if v.verified {
        (Tone::Good, "verified")
    } else {
        (Tone::Warn, "pending")
    };

    // The record/token instructions, per method.
    let instructions = match v.method {
        VerificationMethod::Dns => html! {
            <div>
                <p class="text-xs text-slate-500">{ "Add this DNS TXT record:" }</p>
                <code class="mt-1 block break-all rounded bg-slate-50 p-2 text-xs text-slate-700">
                    { format!("{}  TXT  \"{}\"", v.dns_record_name(), v.token) }
                </code>
            </div>
        },
        VerificationMethod::Http => html! {
            <div>
                <p class="text-xs text-slate-500">{ "Serve this token over HTTP:" }</p>
                <code class="mt-1 block break-all rounded bg-slate-50 p-2 text-xs text-slate-700">
                    { format!("GET {}", v.http_challenge_url()) }
                </code>
                <code class="mt-1 block break-all rounded bg-slate-50 p-2 text-xs text-slate-700">
                    { format!("body: {}", v.token) }
                </code>
            </div>
        },
    };

    html! {
        <li class="rounded-lg border border-slate-200 p-4">
            <div class="flex items-center justify-between">
                <span class="font-mono text-sm font-medium text-slate-800">{ &v.host }</span>
                <div class="flex items-center gap-3">
                    <Pill text={label} tone={tone} />
                    <span class="text-xs text-slate-400">{ v.method.as_str() }</span>
                </div>
            </div>
            <div class="mt-3 space-y-2">{ instructions }</div>
            if let Some(result) = &*check {
                <div class="mt-3 text-sm">
                    if result.passed {
                        <span class="text-emerald-600">
                            { if result.attached { "Verified and attached." } else { "Verified." } }
                        </span>
                    } else {
                        <span class="text-amber-600">
                            { result.detail.clone().unwrap_or_else(|| "Not yet — check the record.".into()) }
                        </span>
                    }
                </div>
            }
            if let Some(msg) = &*error {
                <p class="mt-2 text-sm text-rose-600">{ msg }</p>
            }
            <div class="mt-3 flex gap-2">
                <button onclick={run_check}
                        class="rounded-md bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-700">
                    { "Check now" }
                </button>
                <button onclick={remove}
                        class="rounded-md border border-rose-200 px-3 py-1.5 text-xs font-medium \
                               text-rose-600 hover:bg-rose-50">
                    { "Drop" }
                </button>
            </div>
        </li>
    }
}
