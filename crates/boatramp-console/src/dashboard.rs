//! The read-only dashboard.
//!
//! `GET /api/sites` → the site list; then per site its current deployment +
//! age (`GET /api/sites/:site/deployments` → [`DeploymentList`]) and its
//! domains (`GET /api/sites/:site/config` → [`SiteConfig`]). No mutations.

use boatramp_types::config::SiteConfig;
use boatramp_types::deploy::DeploymentList;
use yew::prelude::*;

use crate::format::{relative_age, short_id};
use crate::hooks::{use_api, Fetch};
use crate::widgets::{ErrorBanner, Pill, Spinner, Tone};

/// The dashboard: the list of sites, each with a status card.
#[derive(Properties, PartialEq)]
pub struct DashboardProps {
    /// Emitted with a site name when a card is clicked (the shell navigates to
    /// that site's deploy-ops view).
    pub on_select: Callback<String>,
}

#[function_component(Dashboard)]
pub fn dashboard(props: &DashboardProps) -> Html {
    let sites = use_api(|client| async move { client.get_json::<Vec<String>>("/api/sites").await });

    match &sites.state {
        Fetch::Loading => html! { <Spinner label="Loading sites…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(sites.reload.clone())} />
        },
        Fetch::Ready(list) if list.is_empty() => html! {
            <div class="rounded-lg border border-dashed border-slate-300 bg-white p-10 text-center">
                <p class="text-slate-500">{ "No sites yet. Publish one with " }
                    <code class="rounded bg-slate-100 px-1.5 py-0.5 text-sm">{ "boatramp sync" }</code>
                    { "." }
                </p>
            </div>
        },
        Fetch::Ready(list) => html! {
            <div>
                <div class="mb-6 flex items-center justify-between">
                    <h2 class="text-lg font-semibold text-slate-900">{ "Sites" }</h2>
                    <span class="text-sm text-slate-500">
                        { format!("{} site{}", list.len(), if list.len() == 1 { "" } else { "s" }) }
                    </span>
                </div>
                <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    { for list.iter().map(|name| html! {
                        <SiteCard key={name.clone()} site={name.clone()}
                                  on_select={props.on_select.clone()} />
                    }) }
                </div>
            </div>
        },
    }
}

/// A single site's status card: current deployment id + age (from the
/// deployment list) and its configured domains (from the site config).
#[derive(Properties, PartialEq)]
pub struct SiteCardProps {
    /// The site name.
    pub site: String,
    /// Emitted with the site name when the card is clicked.
    pub on_select: Callback<String>,
}

#[function_component(SiteCard)]
pub fn site_card(props: &SiteCardProps) -> Html {
    let site = props.site.clone();
    let on_click = {
        let on_select = props.on_select.clone();
        let site = site.clone();
        Callback::from(move |_: MouseEvent| on_select.emit(site.clone()))
    };
    let deployments = {
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
    let config = {
        let site = site.clone();
        use_api(move |client| {
            let site = site.clone();
            async move {
                client
                    .get_json::<SiteConfig>(&format!("/api/sites/{site}/config"))
                    .await
            }
        })
    };

    html! {
        <div onclick={on_click}
             class="cursor-pointer rounded-xl border border-slate-200 bg-white p-5 shadow-sm \
                    transition hover:border-sky-300 hover:shadow">
            <div class="flex items-center justify-between">
                <h3 class="truncate font-semibold text-slate-900">{ &props.site }</h3>
                { current_badge(&deployments.state) }
            </div>
            <dl class="mt-4 space-y-2 text-sm">
                <div class="flex justify-between">
                    <dt class="text-slate-500">{ "Current" }</dt>
                    <dd class="font-mono text-slate-700">{ current_summary(&deployments.state) }</dd>
                </div>
                <div class="flex justify-between">
                    <dt class="text-slate-500">{ "Deployments" }</dt>
                    <dd class="text-slate-700">{ deployment_count(&deployments.state) }</dd>
                </div>
                <div>
                    <dt class="text-slate-500">{ "Domains" }</dt>
                    <dd class="mt-1">{ domains_summary(&config.state) }</dd>
                </div>
            </dl>
        </div>
    }
}

/// A live/empty badge from the deployment list.
fn current_badge(state: &Fetch<DeploymentList>) -> Html {
    match state {
        Fetch::Ready(list) if list.current.is_some() => html! {
            <Pill text="live" tone={Tone::Good} />
        },
        Fetch::Ready(_) => html! { <Pill text="no deploy" tone={Tone::Neutral} /> },
        _ => Html::default(),
    }
}

/// The current deployment id + age (or status text).
fn current_summary(state: &Fetch<DeploymentList>) -> Html {
    match state {
        Fetch::Loading => html! { <span class="text-slate-400">{ "…" }</span> },
        Fetch::Failed(err) => html! { <span class="text-rose-500" title={err.to_string()}>{ "error" }</span> },
        Fetch::Ready(list) => match &list.current {
            Some(id) => {
                // Find this id's activation time in the history for the age.
                let age = list
                    .deployments
                    .iter()
                    .find(|h| &h.id == id)
                    .map(|h| relative_age(h.at))
                    .unwrap_or_else(|| "—".to_string());
                html! { <span title={id.clone()}>{ format!("{} · {}", short_id(id), age) }</span> }
            }
            None => html! { <span class="text-slate-400">{ "—" }</span> },
        },
    }
}

/// The history depth.
fn deployment_count(state: &Fetch<DeploymentList>) -> Html {
    match state {
        Fetch::Ready(list) => html! { { list.deployments.len() } },
        Fetch::Failed(_) => html! { <span class="text-rose-500">{ "—" }</span> },
        Fetch::Loading => html! { <span class="text-slate-400">{ "…" }</span> },
    }
}

/// The configured domains (primary + aliases + wildcards), or "none".
fn domains_summary(state: &Fetch<SiteConfig>) -> Html {
    match state {
        Fetch::Loading => html! { <span class="text-slate-400 text-sm">{ "…" }</span> },
        Fetch::Failed(err) => html! { <span class="text-rose-500 text-sm" title={err.to_string()}>{ "error" }</span> },
        Fetch::Ready(config) => {
            let domains = &config.domains;
            let mut hosts: Vec<String> = Vec::new();
            if let Some(primary) = &domains.primary {
                hosts.push(primary.clone());
            }
            hosts.extend(domains.aliases.iter().cloned());
            hosts.extend(domains.wildcards.iter().cloned());
            if hosts.is_empty() {
                html! { <span class="text-sm text-slate-400">{ "none configured" }</span> }
            } else {
                html! {
                    <div class="flex flex-wrap gap-1">
                        { for hosts.iter().map(|h| html! {
                            <span class="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600">
                                { h }
                            </span>
                        }) }
                    </div>
                }
            }
        }
    }
}
