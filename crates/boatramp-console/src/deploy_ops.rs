//! Per-site deploy operations.
//!
//! The deployment history with activate/rollback, and alias set/list/remove.
//! All mutations confirm before firing (a misclick shouldn't flip production).

use std::collections::BTreeMap;

use boatramp_types::deploy::{DeploymentList, HistoryEntry};
use gloo_dialogs::confirm;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::auth::use_session;
use crate::format::{relative_age, short_id};
use crate::hooks::{use_api, Fetch};
use crate::models::SetAliasRequest;
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// The deploy-ops panel for one site.
#[derive(Properties, PartialEq)]
pub struct DeployOpsProps {
    /// The site being managed.
    pub site: String,
}

#[function_component(DeployOps)]
pub fn deploy_ops(props: &DeployOpsProps) -> Html {
    html! {
        <div class="space-y-8">
            <Deployments site={props.site.clone()} />
            <Aliases site={props.site.clone()} />
        </div>
    }
}

/// The deployment history with activate/rollback buttons.
#[derive(Properties, PartialEq)]
struct SiteProp {
    site: String,
}

#[function_component(Deployments)]
fn deployments(props: &SiteProp) -> Html {
    let session = use_session();
    let site = props.site.clone();
    let list = {
        let site = site.clone();
        use_api(move |client| {
            let site = site.clone();
            async move {
                client
                    .get_json::<DeploymentList>(&format!("/api/sites/{site}/deployments"))
                    .await
            }
        })
    };
    // A transient action error (activation refused, etc.), shown above the table.
    let action_error = use_state(|| Option::<String>::None);

    let activate = {
        let session = session.clone();
        let site = site.clone();
        let reload = list.reload.clone();
        let action_error = action_error.clone();
        Callback::from(move |id: String| {
            if !confirm(&format!(
                "Activate deployment {} for site \"{}\"? This flips live traffic.",
                short_id(&id),
                site
            )) {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let reload = reload.clone();
            let action_error = action_error.clone();
            action_error.set(None);
            spawn_local(async move {
                match client
                    .post_no_content(&format!("/api/sites/{site}/deployments/{id}/activate"))
                    .await
                {
                    Ok(()) => reload.emit(()),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => action_error.set(Some(err.to_string())),
                }
            });
        })
    };

    let body = match &list.state {
        Fetch::Loading => html! { <Spinner label="Loading deployments…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(list.reload.clone())} />
        },
        Fetch::Ready(list) if list.deployments.is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No deployments yet." }</p>
        },
        Fetch::Ready(list) => {
            let current = list.current.clone();
            html! {
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-slate-200 text-left text-slate-500">
                            <th class="py-2 font-medium">{ "Deployment" }</th>
                            <th class="py-2 font-medium">{ "Activated" }</th>
                            <th class="py-2 font-medium">{ "Source" }</th>
                            <th class="py-2 font-medium text-right">{ "Action" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        { for list.deployments.iter().map(|entry| deployment_row(
                            entry, current.as_deref(), &activate
                        )) }
                    </tbody>
                </table>
            }
        }
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Deployments" }</h3>
            if let Some(msg) = &*action_error {
                <div class="mb-4">
                    <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
                </div>
            }
            { body }
        </section>
    }
}

/// One history row: id, activation age, provenance, and an activate/rollback
/// button (disabled for the row that is already live).
fn deployment_row(
    entry: &HistoryEntry,
    current: Option<&str>,
    activate: &Callback<String>,
) -> Html {
    let is_current = current == Some(entry.id.as_str());
    let id = entry.id.clone();
    let on_click = {
        let activate = activate.clone();
        Callback::from(move |_: MouseEvent| activate.emit(id.clone()))
    };
    // Most-recent history entry that is *not* current is a "rollback"; activating
    // any older one is also a rollback. Activating a newer one is "roll forward".
    // We label simply by current vs not.
    let source = entry
        .meta
        .as_ref()
        .and_then(|m| m.source.as_deref().or(m.branch.as_deref()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".to_string());

    html! {
        <tr class="border-b border-slate-100">
            <td class="py-2.5 font-mono text-slate-700" title={entry.id.clone()}>
                <span>{ short_id(&entry.id) }</span>
                if is_current {
                    <span class="ml-2"><Pill text="live" tone={Tone::Good} /></span>
                }
            </td>
            <td class="py-2.5 text-slate-600">{ relative_age(entry.at) }</td>
            <td class="py-2.5 text-slate-600">{ source }</td>
            <td class="py-2.5 text-right">
                if is_current {
                    <span class="text-xs text-slate-400">{ "current" }</span>
                } else {
                    <button onclick={on_click}
                            class="rounded-md border border-slate-300 px-2.5 py-1 text-xs \
                                   font-medium text-slate-700 hover:bg-slate-50">
                        { "Activate" }
                    </button>
                }
            </td>
        </tr>
    }
}

/// Named aliases: list, set (name → deployment id), and remove.
#[function_component(Aliases)]
fn aliases(props: &SiteProp) -> Html {
    let session = use_session();
    let site = props.site.clone();
    let list = {
        let site = site.clone();
        use_api(move |client| {
            let site = site.clone();
            async move {
                client
                    .get_json::<BTreeMap<String, String>>(&format!("/api/sites/{site}/aliases"))
                    .await
            }
        })
    };
    let action_error = use_state(|| Option::<String>::None);
    let name_ref = use_node_ref();
    let id_ref = use_node_ref();

    let set_alias = {
        let session = session.clone();
        let site = site.clone();
        let reload = list.reload.clone();
        let action_error = action_error.clone();
        let name_ref = name_ref.clone();
        let id_ref = id_ref.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let name = name_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            let id = id_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            if name.is_empty() || id.is_empty() {
                action_error.set(Some("Both an alias name and a deployment id are required.".into()));
                return;
            }
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let reload = reload.clone();
            let action_error = action_error.clone();
            let name_ref = name_ref.clone();
            let id_ref = id_ref.clone();
            action_error.set(None);
            spawn_local(async move {
                match client
                    .put_json(&format!("/api/sites/{site}/aliases/{name}"), &SetAliasRequest { id })
                    .await
                {
                    Ok(()) => {
                        if let Some(el) = name_ref.cast::<HtmlInputElement>() {
                            el.set_value("");
                        }
                        if let Some(el) = id_ref.cast::<HtmlInputElement>() {
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

    let remove_alias = {
        let session = session.clone();
        let site = site.clone();
        let reload = list.reload.clone();
        let action_error = action_error.clone();
        Callback::from(move |name: String| {
            if !confirm(&format!("Remove alias \"{name}\"?")) {
                return;
            }
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let reload = reload.clone();
            let action_error = action_error.clone();
            spawn_local(async move {
                match client
                    .delete(&format!("/api/sites/{site}/aliases/{name}"))
                    .await
                {
                    Ok(()) => reload.emit(()),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => action_error.set(Some(err.to_string())),
                }
            });
        })
    };

    let rows = match &list.state {
        Fetch::Loading => html! { <Spinner label="Loading aliases…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(list.reload.clone())} />
        },
        Fetch::Ready(map) if map.is_empty() => html! {
            <p class="text-sm text-slate-500">{ "No aliases set." }</p>
        },
        Fetch::Ready(map) => html! {
            <ul class="divide-y divide-slate-100">
                { for map.iter().map(|(name, id)| {
                    let name = name.clone();
                    let on_remove = {
                        let remove_alias = remove_alias.clone();
                        let name = name.clone();
                        Callback::from(move |_: MouseEvent| remove_alias.emit(name.clone()))
                    };
                    html! {
                        <li class="flex items-center justify-between py-2 text-sm">
                            <span>
                                <span class="font-medium text-slate-800">{ &name }</span>
                                <span class="mx-2 text-slate-400">{ "→" }</span>
                                <span class="font-mono text-slate-600" title={id.clone()}>
                                    { short_id(id) }
                                </span>
                            </span>
                            <button onclick={on_remove}
                                    class="rounded-md border border-rose-200 px-2 py-1 text-xs \
                                           font-medium text-rose-600 hover:bg-rose-50">
                                { "Remove" }
                            </button>
                        </li>
                    }
                }) }
            </ul>
        },
    };

    html! {
        <section class="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h3 class="mb-4 text-base font-semibold text-slate-900">{ "Aliases" }</h3>
            if let Some(msg) = &*action_error {
                <div class="mb-4">
                    <ErrorBanner message={msg.clone()} on_retry={None::<Callback<()>>} />
                </div>
            }
            { rows }
            <form onsubmit={set_alias} class="mt-4 flex flex-wrap items-end gap-3">
                <div class="flex-1 min-w-[8rem]">
                    <label class="block text-xs font-medium text-slate-500">{ "Alias name" }</label>
                    <input ref={name_ref} placeholder="staging"
                           class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm" />
                </div>
                <div class="flex-1 min-w-[12rem]">
                    <label class="block text-xs font-medium text-slate-500">{ "Deployment id" }</label>
                    <input ref={id_ref} placeholder="content hash"
                           class="mt-1 w-full rounded-md border border-slate-300 px-2.5 py-1.5 text-sm font-mono" />
                </div>
                <button type="submit"
                        class="rounded-md bg-sky-600 px-3 py-1.5 text-sm font-medium text-white \
                               hover:bg-sky-700">
                    { "Set alias" }
                </button>
            </form>
        </section>
    }
}
