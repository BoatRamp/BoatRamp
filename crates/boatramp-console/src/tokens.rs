//! API tokens + cache invalidation, admin-scoped.
//!
//! Mint / list / revoke control-plane tokens (`/api/tokens`), and push a cache
//! invalidation (`POST /api/cache/invalidate` — empty key list flushes all).

use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::auth::use_session;
use crate::format::relative_age;
use crate::hooks::{use_api, Fetch};
use crate::models::{
    CreateTokenRequest, CreateTokenResponse, GrantedRole, InvalidateRequest, TokenMeta,
};
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// The tokens + cache view.
#[function_component(Tokens)]
pub fn tokens() -> Html {
    html! {
        <div class="space-y-8">
            <TokenList />
            <CacheInvalidation />
        </div>
    }
}

/// Mint / list / revoke control-plane tokens.
#[function_component(TokenList)]
fn token_list() -> Html {
    let session = use_session();
    let list = use_api(|client| async move {
        client.get_json::<Vec<TokenMeta>>("/api/tokens").await
    });
    // The freshly-minted plaintext token, shown once after creation.
    let minted = use_state(|| Option::<String>::None);
    let action_error = use_state(|| Option::<String>::None);
    let label_ref = use_node_ref();
    let roles_ref = use_node_ref();

    let create = {
        let session = session.clone();
        let reload = list.reload.clone();
        let minted = minted.clone();
        let action_error = action_error.clone();
        let label_ref = label_ref.clone();
        let roles_ref = roles_ref.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let label = label_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            if label.is_empty() {
                action_error.set(Some("A label is required.".into()));
                return;
            }
            // Comma- or space-separated role specs (`<role>` or `<role>:<site>`).
            let roles: Vec<String> = roles_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default()
                .split([',', ' '])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if roles.is_empty() {
                action_error.set(Some("At least one role is required.".into()));
                return;
            }
            let client = session.client();
            let session = session.clone();
            let reload = reload.clone();
            let minted = minted.clone();
            let action_error = action_error.clone();
            let label_ref = label_ref.clone();
            let roles_ref = roles_ref.clone();
            action_error.set(None);
            spawn_local(async move {
                let body = CreateTokenRequest {
                    label,
                    roles,
                    ttl_secs: None,
                };
                match client
                    .post_json::<_, CreateTokenResponse>("/api/tokens", &body)
                    .await
                {
                    Ok(resp) => {
                        minted.set(Some(resp.token));
                        if let Some(el) = label_ref.cast::<HtmlInputElement>() {
                            el.set_value("");
                        }
                        if let Some(el) = roles_ref.cast::<HtmlInputElement>() {
                            el.set_value("");
                        }
                        reload.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => action_error.set(Some(err.to_string())),
                }
            });
        })
    };

    let revoke = {
        let session = session.clone();
        let reload = list.reload.clone();
        let action_error = action_error.clone();
        Callback::from(move |id: String| {
            if !gloo_dialogs::confirm("Revoke this token? Any client using it loses access.") {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let reload = reload.clone();
            let action_error = action_error.clone();
            spawn_local(async move {
                match client.delete(&format!("/api/tokens/{id}")).await {
                    Ok(()) => reload.emit(()),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => action_error.set(Some(err.to_string())),
                }
            });
        })
    };

    let rows = match &list.state {
        Fetch::Loading => html! { <Spinner label="Loading tokens…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(list.reload.clone())} />
        },
        Fetch::Ready(tokens) if tokens.is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No tokens minted." }</p>
        },
        Fetch::Ready(tokens) => html! {
            <table class="w-full text-sm">
                <thead>
                    <tr class="border-b border-slate-200 text-left text-slate-500">
                        <th class="py-2 font-medium">{ "Label" }</th>
                        <th class="py-2 font-medium">{ "Roles" }</th>
                        <th class="py-2 font-medium">{ "Created" }</th>
                        <th class="py-2 font-medium text-right">{ "Action" }</th>
                    </tr>
                </thead>
                <tbody>
                    { for tokens.iter().map(|t| token_row(t, &revoke)) }
                </tbody>
            </table>
        },
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "API tokens" }</h3>
            if let Some(token) = &*minted {
                <div class="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 p-4">
                    <p class="text-sm font-medium text-emerald-800">
                        { "New token — copy it now, it won't be shown again:" }
                    </p>
                    <code class="mt-2 block break-all rounded bg-white p-2 font-mono text-xs text-slate-700">
                        { token }
                    </code>
                </div>
            }
            if let Some(msg) = &*action_error {
                <div class="mb-4"><ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} /></div>
            }
            { rows }
            <form onsubmit={create} class="mt-4 flex flex-wrap items-end gap-3 border-t border-slate-100 pt-4">
                <div class="flex-1 min-w-[10rem]">
                    <label class="block text-xs font-medium text-slate-500">{ "Label" }</label>
                    <input ref={label_ref} placeholder="ci-deploy"
                           class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm" />
                </div>
                <div class="flex-1 min-w-[12rem]">
                    <label class="block text-xs font-medium text-slate-500">
                        { "Roles (e.g. admin, publisher:blog)" }
                    </label>
                    <input ref={roles_ref} placeholder="publisher:blog, viewer:docs"
                           class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm font-mono" />
                </div>
                <button type="submit"
                        class="rounded-md bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700">
                    { "Mint token" }
                </button>
            </form>
        </section>
    }
}

fn render_role(role: &GrantedRole) -> String {
    match &role.target {
        Some(t) => format!("{}:{}", role.name, t),
        None => role.name.clone(),
    }
}

fn token_row(token: &TokenMeta, revoke: &Callback<String>) -> Html {
    let id = token.revocation_id.clone();
    let on_click = {
        let revoke = revoke.clone();
        Callback::from(move |_: MouseEvent| revoke.emit(id.clone()))
    };
    let roles = if token.roles.is_empty() {
        html! { <Pill text="—" tone={Tone::Warn} /> }
    } else {
        html! {
            <span class="flex flex-wrap gap-1">
                { for token.roles.iter().map(|r| html! { <Pill text={render_role(r)} tone={Tone::Neutral} /> }) }
            </span>
        }
    };
    html! {
        <tr class="border-b border-slate-100">
            <td class="py-2.5 text-slate-700">{ &token.label }</td>
            <td class="py-2.5">{ roles }</td>
            <td class="py-2.5 text-slate-600">{ relative_age(token.created_at) }</td>
            <td class="py-2.5 text-right">
                <button onclick={on_click}
                        class="rounded-md border border-rose-200 px-2.5 py-1 text-xs font-medium \
                               text-rose-600 hover:bg-rose-50">
                    { "Revoke" }
                </button>
            </td>
        </tr>
    }
}

/// Push a cache invalidation: specific keys (one per line), or flush everything.
#[function_component(CacheInvalidation)]
fn cache_invalidation() -> Html {
    let session = use_session();
    let keys_ref = use_node_ref();
    let status = use_state(|| Option::<Result<String, String>>::None);

    let invalidate = {
        let session = session.clone();
        let keys_ref = keys_ref.clone();
        let status = status.clone();
        Callback::from(move |flush_all: bool| {
            let keys: Vec<String> = if flush_all {
                Vec::new()
            } else {
                keys_ref
                    .cast::<web_sys::HtmlTextAreaElement>()
                    .map(|el| el.value())
                    .unwrap_or_default()
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            };
            if !flush_all && keys.is_empty() {
                status.set(Some(Err("Enter at least one key, or use Flush all.".into())));
                return;
            }
            let count = keys.len();
            let client = session.client();
            let session = session.clone();
            let status = status.clone();
            spawn_local(async move {
                match client
                    .post_no_content_json("/api/cache/invalidate", &InvalidateRequest { keys })
                    .await
                {
                    Ok(()) => status.set(Some(Ok(if flush_all {
                        "Flushed the whole cache.".to_string()
                    } else {
                        format!("Invalidated {count} key(s).")
                    }))),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => status.set(Some(Err(err.to_string()))),
                }
            });
        })
    };

    let on_invalidate = {
        let invalidate = invalidate.clone();
        Callback::from(move |_: MouseEvent| invalidate.emit(false))
    };
    let on_flush = {
        let invalidate = invalidate.clone();
        Callback::from(move |_: MouseEvent| {
            if gloo_dialogs::confirm("Flush the entire cache?") {
                invalidate.emit(true);
            }
        })
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Cache invalidation" }</h3>
            <label class="block text-sm font-medium text-slate-700">{ "Keys (one per line)" }</label>
            <textarea ref={keys_ref} rows="3"
                      class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm font-mono" />
            <div class="mt-3 flex items-center gap-3">
                <button onclick={on_invalidate}
                        class="rounded-md bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700">
                    { "Invalidate keys" }
                </button>
                <button onclick={on_flush}
                        class="rounded-md border border-rose-300 px-3 py-1.5 text-sm font-medium \
                               text-rose-600 hover:bg-rose-50">
                    { "Flush all" }
                </button>
                if let Some(result) = &*status {
                    {
                        match result {
                            Ok(msg) => html! { <span class="text-sm text-emerald-600">{ msg }</span> },
                            Err(msg) => html! { <span class="text-sm text-rose-600">{ msg }</span> },
                        }
                    }
                }
            </div>
        </section>
    }
}
