//! The project-level GraphQL section: the composed-supergraph (subgraph /
//! federation) view and the operation-safelist manager.
//!
//! Both drive the project-owned GraphQL registry, scoped to the active project
//! by the [`crate::api::ApiClient`] (`/api/graphql/…` → `/api/projects/<proj>/
//! graphql/…`). Reads need `Project·Read`; the safelist register/remove need
//! `Project·Deploy`, so a reader's token degrades those mutations to an inline
//! "lacks the required scope" note rather than a fatal error. Every endpoint
//! lives behind the server's `handlers` feature, so a `404` shows the same
//! friendly "built without handlers" note the observability views use.

use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::auth::use_session;
use crate::hooks::{Fetch, use_api};
use crate::models::{RegisterSafelistOp, SafelistHash, SafelistOp, SupergraphSummary};
use crate::widgets::{
    BtnVariant, Button, ErrorBanner, Pill, Section, Spinner, TextAreaField, Tone,
};

/// The GraphQL section page: the federation view stacked over the safelist
/// manager, both scoped to the active project (switched via the header
/// selector).
#[function_component(GraphqlPage)]
pub fn graphql_page() -> Html {
    html! {
        <div class="space-y-8">
            <div>
                <h2 class="text-lg font-semibold text-slate-900">{ "GraphQL" }</h2>
                <p class="mt-0.5 text-sm text-slate-500">
                    { "The composed federation supergraph and the trusted-operation safelist for the \
                       active project. Switch projects from the selector in the header." }
                </p>
            </div>
            <SupergraphView />
            <SafelistManager />
        </div>
    }
}

/// The read-only composed-supergraph (subgraph / federation) view: the
/// registered subgraphs, the root `Query`/`Mutation` fields mapped to their
/// owning subgraph, and the federated entities.
#[function_component(SupergraphView)]
fn supergraph_view() -> Html {
    let sg = use_api(|client| async move {
        client
            .get_json::<SupergraphSummary>("/api/graphql/supergraph")
            .await
    });

    let refresh = {
        let reload = sg.reload.clone();
        Callback::from(move |_: MouseEvent| reload.emit(()))
    };
    let action = html! {
        <Button variant={BtnVariant::Secondary} label="Refresh" onclick={refresh} />
    };

    let body = match &sg.state {
        Fetch::Loading => html! { <Spinner label="Loading supergraph…" /> },
        Fetch::Failed(err) if err.is_not_found() => feature_disabled_note(),
        // A 400 is "no composed supergraph yet" or a composition error (the detailed
        // message isn't carried on a GET); point the operator at the subgraph registry.
        Fetch::Failed(crate::ApiError::Status { code: 400, .. }) => html! {
            <p class="text-sm text-slate-500">
                { "No composed supergraph for this project yet. Register subgraphs with " }
                <code class="rounded bg-slate-100 px-1.5 py-0.5 text-xs">{ "boatramp graphql subgraph" }</code>
                { " (a composition error also reports here)." }
            </p>
        },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(sg.reload.clone())} />
        },
        Fetch::Ready(summary)
            if summary.subgraphs.is_empty()
                && summary.root_query.is_empty()
                && summary.root_mutation.is_empty() =>
        {
            html! {
                <p class="text-sm text-slate-500">{ "No subgraphs registered for this project yet." }</p>
            }
        }
        Fetch::Ready(summary) => render_summary(summary),
    };

    html! {
        <Section title="Federation supergraph"
                 description="The composed schema for the active project (read-only)."
                 action={action}>
            { body }
        </Section>
    }
}

/// Render a non-empty supergraph summary.
fn render_summary(s: &SupergraphSummary) -> Html {
    html! {
        <div class="space-y-5">
            <div>
                <h4 class="mb-2 text-sm font-medium text-slate-600">
                    { format!("Subgraphs ({})", s.subgraphs.len()) }
                </h4>
                if s.subgraphs.is_empty() {
                    <p class="text-sm text-slate-500">{ "None." }</p>
                } else {
                    <div class="flex flex-wrap gap-1.5">
                        { for s.subgraphs.iter().map(|n| html! {
                            <Pill text={n.clone()} tone={Tone::Neutral} />
                        }) }
                    </div>
                }
            </div>
            { root_fields("Query roots", &s.root_query) }
            { root_fields("Mutation roots", &s.root_mutation) }
            if !s.entities.is_empty() {
                <div>
                    <h4 class="mb-2 text-sm font-medium text-slate-600">
                        { format!("Entities ({})", s.entities.len()) }
                    </h4>
                    <div class="overflow-x-auto">
                        <table class="min-w-full text-left text-sm">
                            <thead>
                                <tr class="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                                    <th scope="col" class="py-1.5 pr-4 font-medium">{ "Type" }</th>
                                    <th scope="col" class="py-1.5 pr-4 font-medium">{ "Key" }</th>
                                    <th scope="col" class="py-1.5 font-medium">{ "Resolved by" }</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-100">
                                { for s.entities.iter().map(|(ty, e)| html! {
                                    <tr>
                                        <td class="py-1.5 pr-4 font-mono text-slate-800">{ ty }</td>
                                        <td class="py-1.5 pr-4 font-mono text-slate-600">{ &e.key }</td>
                                        <td class="py-1.5 text-slate-600">{ e.subgraphs.join(", ") }</td>
                                    </tr>
                                }) }
                            </tbody>
                        </table>
                    </div>
                </div>
            }
        </div>
    }
}

/// Render one root-field group (field → owning subgraph) as a definition list.
fn root_fields(title: &str, fields: &std::collections::BTreeMap<String, String>) -> Html {
    if fields.is_empty() {
        return Html::default();
    }
    html! {
        <div>
            <h4 class="mb-2 text-sm font-medium text-slate-600">
                { format!("{title} ({})", fields.len()) }
            </h4>
            <ul class="divide-y divide-slate-100">
                { for fields.iter().map(|(field, owner)| html! {
                    <li class="flex items-center justify-between py-1.5 text-sm">
                        <span class="font-mono text-slate-800">{ field }</span>
                        <span class="text-xs text-slate-500">{ owner }</span>
                    </li>
                }) }
            </ul>
        </div>
    }
}

/// The operation-safelist manager: list the trusted (persisted) operations,
/// register a new one, and remove one by hash. Reads with `Project·Read`;
/// register/remove need `Project·Deploy` — a `403` degrades to an inline note
/// and disables the register form rather than erroring out.
#[function_component(SafelistManager)]
fn safelist_manager() -> Html {
    let session = use_session();
    let list = use_api(|client| async move {
        client
            .get_json::<Vec<SafelistOp>>("/api/graphql/safelist")
            .await
    });

    // The pending new-operation draft, a mutate status line, and whether a 403
    // has told us the token can't deploy (so we stop offering the mutations).
    let draft = use_state(String::new);
    let status = use_state(|| Option::<(bool, String)>::None); // (is_error, message)
    let read_only = use_state(|| false);

    let register = {
        let session = session.clone();
        let draft = draft.clone();
        let status = status.clone();
        let read_only = read_only.clone();
        let reload = list.reload.clone();
        Callback::from(move |_: MouseEvent| {
            let query = draft.trim().to_string();
            if query.is_empty() {
                status.set(Some((true, "Enter an operation to register.".to_string())));
                return;
            }
            let client = session.client();
            let session = session.clone();
            let draft = draft.clone();
            let status = status.clone();
            let read_only = read_only.clone();
            let reload = reload.clone();
            status.set(Some((false, "Registering…".to_string())));
            spawn_local(async move {
                let body = RegisterSafelistOp { query };
                match client
                    .post_json_detailed::<_, SafelistHash>("/api/graphql/safelist", &body)
                    .await
                {
                    Ok(hash) => {
                        draft.set(String::new());
                        status.set(Some((
                            false,
                            format!("Registered as {}", short_hash(&hash.hash)),
                        )));
                        reload.emit(());
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) if err.is_forbidden() => {
                        read_only.set(true);
                        status.set(Some((
                            true,
                            "Your token lacks the required scope (Project·Deploy) to register operations."
                                .to_string(),
                        )));
                    }
                    Err(err) => status.set(Some((true, err.to_string()))),
                }
            });
        })
    };

    let on_draft = {
        let draft = draft.clone();
        Callback::from(move |v: String| draft.set(v))
    };

    let body = match &list.state {
        Fetch::Loading => html! { <Spinner label="Loading safelist…" /> },
        Fetch::Failed(err) if err.is_not_found() => feature_disabled_note(),
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(list.reload.clone())} />
        },
        Fetch::Ready(ops) => {
            let count = ops.len();
            html! {
                <div class="space-y-4">
                    if count == 0 {
                        <p class="text-sm text-slate-500">
                            { "No safelisted operations. Guest runs are deny-by-default, so none are \
                               permitted until one is registered." }
                        </p>
                    } else {
                        <ul class="divide-y divide-slate-100">
                            { for ops.iter().map(|op| render_op_row(op, &session, &list.reload, &status, &read_only)) }
                        </ul>
                    }
                    { register_form(&draft, on_draft.clone(), register.clone(), &status, *read_only) }
                </div>
            }
        }
    };

    let count_badge = match &list.state {
        Fetch::Ready(ops) => html! {
            <span class="text-sm text-slate-500">
                { format!("{} operation{}", ops.len(), if ops.len() == 1 { "" } else { "s" }) }
            </span>
        },
        _ => Html::default(),
    };

    html! {
        <Section title="Operation safelist"
                 description="Trusted GraphQL operations a guest may run (deny-by-default)."
                 action={count_badge}>
            { body }
        </Section>
    }
}

/// One safelist row: the operation text + its hash, with a Remove button that
/// degrades on `403` exactly like the register form.
fn render_op_row(
    op: &SafelistOp,
    session: &crate::auth::Session,
    reload: &Callback<()>,
    status: &UseStateHandle<Option<(bool, String)>>,
    read_only: &UseStateHandle<bool>,
) -> Html {
    let hash = op.hash.clone();
    let remove = {
        let session = session.clone();
        let reload = reload.clone();
        let status = status.clone();
        let read_only = read_only.clone();
        let hash = hash.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let reload = reload.clone();
            let status = status.clone();
            let read_only = read_only.clone();
            let hash = hash.clone();
            spawn_local(async move {
                match client
                    .delete(&format!("/api/graphql/safelist/{hash}"))
                    .await
                {
                    Ok(()) => reload.emit(()),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) if err.is_forbidden() => {
                        read_only.set(true);
                        status.set(Some((
                            true,
                            "Your token lacks the required scope (Project·Deploy) to remove operations."
                                .to_string(),
                        )));
                    }
                    Err(err) => status.set(Some((true, err.to_string()))),
                }
            });
        })
    };

    html! {
        <li class="py-2">
            <div class="flex items-start justify-between gap-3">
                <pre class="max-h-40 flex-1 overflow-auto rounded bg-slate-50 p-2 text-xs \
                            leading-relaxed text-slate-700">{ &op.query }</pre>
                if !**read_only {
                    <Button variant={BtnVariant::DangerSubtle} label="Remove" onclick={remove} />
                }
            </div>
            <p class="mt-1 font-mono text-[11px] text-slate-400">{ short_hash(&op.hash) }</p>
        </li>
    }
}

/// The register-operation form (a textarea + button), or a read-only note when a
/// prior `403` showed the token can't deploy.
fn register_form(
    draft: &UseStateHandle<String>,
    on_draft: Callback<String>,
    register: Callback<MouseEvent>,
    status: &UseStateHandle<Option<(bool, String)>>,
    read_only: bool,
) -> Html {
    html! {
        <div class="border-t border-slate-100 pt-4">
            if read_only {
                <p class="text-sm text-slate-500">
                    { "Registering operations needs a token with Project·Deploy on this project." }
                </p>
            } else {
                <>
                    <TextAreaField label="Register a trusted operation"
                        value={(**draft).clone()} rows={4}
                        hint="The exact GraphQL operation text. It is validated (parse + depth/complexity) before it is stored."
                        on_change={on_draft} />
                    <div class="mt-2">
                        <Button variant={BtnVariant::Primary} label="Register operation" onclick={register} />
                    </div>
                </>
            }
            if let Some((is_error, msg)) = &**status {
                <p role="status" aria-live="polite"
                   class={if *is_error { "mt-2 text-sm text-rose-700" } else { "mt-2 text-sm text-slate-500" }}>
                    { msg }
                </p>
            }
        </div>
    }
}

/// A short, display-friendly hash (first 12 hex chars + ellipsis).
fn short_hash(hash: &str) -> String {
    if hash.len() > 12 {
        format!("{}…", &hash[..12])
    } else {
        hash.to_string()
    }
}

/// The shared "built without the handlers feature" note (the GraphQL registry
/// endpoints only exist there), mirroring the observability views' idiom.
fn feature_disabled_note() -> Html {
    html! {
        <p class="text-sm text-slate-500">
            { "Not available — this server was built without the " }
            <code class="rounded bg-slate-100 px-1 py-0.5 text-xs">{ "handlers" }</code>
            { " feature." }
        </p>
    }
}
