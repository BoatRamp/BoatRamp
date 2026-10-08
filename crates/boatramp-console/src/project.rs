//! The multi-project selector for the header: list, switch, and create.
//!
//! The console is scoped to one project at a time (default: `default`). Switching
//! re-scopes every project-family API path (see [`crate::api::ApiClient::with_project`]);
//! node-global pages (Monitoring, Maintenance, Tokens) are unaffected. A full
//! projects page (per-project tenancy schema view/edit, delete) comes in a later
//! stage — this stage establishes the scope selector the family stages build on.

use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlSelectElement;
use yew::prelude::*;

use crate::auth::{DEFAULT_PROJECT, use_session};
use crate::hooks::{Fetch, use_api};
use crate::models::ProjectSummary;

/// The header project control: a dropdown to switch the active project, plus a
/// toggle-reveal inline form to create one. On a token without `System·Read`
/// (can't list projects) it degrades to a static label of the active project.
#[function_component(ProjectSelector)]
pub fn project_selector() -> Html {
    let session = use_session();
    let projects = use_api(|client| async move {
        client
            .get_json::<Vec<ProjectSummary>>("/api/projects")
            .await
    });
    let creating = use_state(|| false);
    let active = session.project().to_string();

    let on_change = {
        let session = session.clone();
        Callback::from(move |e: Event| {
            if let Some(sel) = e.target_dyn_into::<HtmlSelectElement>() {
                session.set_project(sel.value());
            }
        })
    };
    let toggle_create = {
        let creating = creating.clone();
        Callback::from(move |_: MouseEvent| creating.set(!*creating))
    };

    // The option list always offers `default`, then the declared projects.
    let names: Vec<String> = match &projects.state {
        Fetch::Ready(list) => {
            let mut ns = vec![DEFAULT_PROJECT.to_string()];
            ns.extend(
                list.iter()
                    .map(|p| p.name.clone())
                    .filter(|n| n != DEFAULT_PROJECT),
            );
            ns
        }
        // Can't list (loading / forbidden): keep the active project usable.
        _ => {
            let mut ns = vec![DEFAULT_PROJECT.to_string()];
            if active != DEFAULT_PROJECT {
                ns.push(active.clone());
            }
            ns
        }
    };

    html! {
        <div class="flex items-center gap-1.5">
            <span class="text-xs text-slate-400">{ "project" }</span>
            <select onchange={on_change}
                    class="rounded-md border border-slate-300 py-1 pl-2 pr-7 text-sm font-medium \
                           text-slate-700 focus:border-sky-500 focus:outline-none focus:ring-1 \
                           focus:ring-sky-500">
                { for names.iter().map(|n| html! {
                    <option value={n.clone()} selected={*n == active}>{ n.clone() }</option>
                }) }
            </select>
            <button onclick={toggle_create} title="create a project"
                    class="rounded-md border border-slate-300 px-2 py-1 text-sm font-medium \
                           text-slate-600 hover:bg-slate-50">
                { if *creating { "×" } else { "+" } }
            </button>
            if *creating {
                <CreateProject
                    on_done={{
                        let creating = creating.clone();
                        let reload = projects.reload.clone();
                        Callback::from(move |_| { creating.set(false); reload.emit(()); })
                    }} />
            }
        </div>
    }
}

/// Inline "new project" form: a slug input + Create. On success it switches the
/// session to the new project and emits `on_done` (which closes the form and
/// reloads the list). A `409`/`422` from the server surfaces inline.
#[derive(Properties, PartialEq)]
struct CreateProjectProps {
    on_done: Callback<()>,
}

#[function_component(CreateProject)]
fn create_project(props: &CreateProjectProps) -> Html {
    let session = use_session();
    let name = use_state(String::new);
    let error = use_state(|| Option::<String>::None);
    let busy = use_state(|| false);

    let on_input = {
        let name = name.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                name.set(input.value());
            }
        })
    };
    let create = {
        let session = session.clone();
        let name = name.clone();
        let error = error.clone();
        let busy = busy.clone();
        let on_done = props.on_done.clone();
        Callback::from(move |_: MouseEvent| {
            let slug = name.trim().to_string();
            if slug.is_empty() {
                error.set(Some("Enter a project name.".to_string()));
                return;
            }
            let client = session.client();
            let session = session.clone();
            let error = error.clone();
            let busy = busy.clone();
            let on_done = on_done.clone();
            busy.set(true);
            spawn_local(async move {
                let body = serde_json::json!({ "name": slug, "display": slug });
                let outcome = client
                    .post_json::<_, serde_json::Value>("/api/projects", &body)
                    .await;
                busy.set(false);
                match outcome {
                    Ok(_) => {
                        session.set_project(slug);
                        on_done.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => error.set(Some(err.to_string())),
                }
            });
        })
    };

    html! {
        <div class="flex items-center gap-1.5">
            <input value={(*name).clone()} oninput={on_input} placeholder="new-project-slug"
                   class="w-40 rounded-md border border-slate-300 px-2 py-1 text-sm shadow-sm \
                          focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500" />
            <button onclick={create} disabled={*busy}
                    class="rounded-md bg-sky-600 px-2.5 py-1 text-sm font-medium text-white \
                           hover:bg-sky-700 disabled:opacity-50">
                { if *busy { "…" } else { "Create" } }
            </button>
            if let Some(msg) = &*error {
                <span class="text-xs text-rose-600">{ msg }</span>
            }
        </div>
    }
}
