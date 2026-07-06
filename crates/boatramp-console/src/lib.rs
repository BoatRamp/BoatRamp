//! boatramp web management console (Yew CSR Wasm SPA).
//!
//! Talks to the existing control-plane API (`/api/*`) with a Bearer token; every
//! payload deserializes into `boatramp-types`, so the wire format can't drift
//! from the server.

mod api;
mod auth;
mod config_editor;
mod dashboard;
mod deploy_ops;
mod format;
mod hooks;
mod logstream;
mod maintenance;
mod models;
mod observability;
mod oidc;
mod tokens;
mod verify;
mod widgets;

pub use api::{ApiClient, ApiError, ApiResult};

use auth::{use_session, AuthProvider, LoginView};
use config_editor::ConfigEditor;
use dashboard::Dashboard;
use deploy_ops::DeployOps;
use maintenance::Maintenance;
use observability::{Metrics, SiteObservability};
use hooks::{use_api, Fetch};
use models::WhoAmI;
use tokens::Tokens;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

/// Root component: the [`AuthProvider`] owns the session, then the app shows the
/// login gate or the authenticated shell. The API base URL is empty (same-origin
/// dogfood deploy — no CORS); a separately-hosted console sets a non-empty `base`
/// here, and the server must allow that origin via the
/// `ServerOptions::cors_allowed_origins` allowlist (opt-in; empty ⇒ same-origin).
#[function_component(App)]
pub fn app() -> Html {
    html! {
        <AuthProvider base="">
            <Shell />
        </AuthProvider>
    }
}

/// The view the authenticated shell is showing.
#[derive(Clone, PartialEq)]
enum View {
    /// The all-sites overview (dashboard).
    Sites,
    /// A single site's management view (deploy ops / config / observability).
    Site(String),
    /// Cluster-wide maintenance (prune / scrub / certs).
    Maintenance,
    /// API tokens + cache invalidation (admin-scoped).
    Tokens,
    /// The Prometheus metrics dump (admin-scoped).
    Metrics,
}

/// Switches between the login view and the authenticated console, and owns the
/// in-app navigation (a single reactive [`View`] — no router needed for this
/// shallow tree; a deep-link router can layer on later).
#[function_component(Shell)]
fn shell() -> Html {
    let session = use_session();
    let view = use_state(|| View::Sites);
    // An OIDC callback error, surfaced on the login view when the redirect
    // round-trip fails (state mismatch, token-exchange error, …).
    let oidc_error = use_state(|| Option::<String>::None);

    // On mount, if the URL is an OIDC `?code=&state=` callback, complete the
    // PKCE exchange to get the IdP JWT, then trade it for a boatramp **token**
    // at `/api/auth/exchange` (the edge only authorizes tokens)
    // and sign in with that. On failure surface the message and fall back to the
    // login view. `complete_callback` strips the query + clears the PKCE state
    // itself, so a reload never re-runs a spent exchange.
    {
        let session = session.clone();
        let oidc_error = oidc_error.clone();
        let base = session.api_base();
        use_effect_with((), move |_| {
            if oidc::is_callback() {
                spawn_local(async move {
                    match oidc::complete_callback().await {
                        Ok(jwt) => match oidc::exchange_for_token(&base, &jwt).await {
                            Ok(token) => session.sign_in(token),
                            Err(msg) => oidc_error.set(Some(msg)),
                        },
                        Err(msg) => oidc_error.set(Some(msg)),
                    }
                });
            }
            || ()
        });
    }

    if !session.is_authenticated() {
        return html! { <LoginView error={(*oidc_error).clone()} /> };
    }

    let on_sign_out = {
        let session = session.clone();
        Callback::from(move |_| session.sign_out())
    };
    let select_site = {
        let view = view.clone();
        Callback::from(move |site: String| view.set(View::Site(site)))
    };
    let go = |target: View, view: UseStateHandle<View>| {
        Callback::from(move |_: MouseEvent| view.set(target.clone()))
    };

    let nav_class = |active: bool| {
        if active {
            "rounded-md bg-slate-100 px-3 py-1.5 text-sm font-medium text-slate-900"
        } else {
            "rounded-md px-3 py-1.5 text-sm font-medium text-slate-500 hover:text-slate-800"
        }
    };

    let content = match &*view {
        View::Sites => html! { <Dashboard on_select={select_site.clone()} /> },
        View::Site(site) => html! {
            <div>
                <button onclick={go(View::Sites, view.clone())}
                        class="mb-4 text-sm text-slate-500 hover:text-slate-800">
                    { "← All sites" }
                </button>
                <SiteDetail site={site.clone()} />
            </div>
        },
        View::Maintenance => html! { <Maintenance /> },
        View::Tokens => html! { <Tokens /> },
        View::Metrics => html! { <Metrics /> },
    };

    html! {
        <div class="min-h-screen bg-slate-50 text-slate-800">
            <header class="border-b border-slate-200 bg-white">
                <div class="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
                    <div class="flex items-center gap-6">
                        <h1 class="text-lg font-semibold tracking-tight">{ "boatramp console" }</h1>
                        <nav class="flex items-center gap-1">
                            <button onclick={go(View::Sites, view.clone())}
                                    class={nav_class(matches!(&*view, View::Sites | View::Site(_)))}>
                                { "Sites" }
                            </button>
                            <button onclick={go(View::Maintenance, view.clone())}
                                    class={nav_class(matches!(&*view, View::Maintenance))}>
                                { "Maintenance" }
                            </button>
                            <button onclick={go(View::Tokens, view.clone())}
                                    class={nav_class(matches!(&*view, View::Tokens))}>
                                { "Tokens" }
                            </button>
                            <button onclick={go(View::Metrics, view.clone())}
                                    class={nav_class(matches!(&*view, View::Metrics))}>
                                { "Metrics" }
                            </button>
                        </nav>
                    </div>
                    <div class="flex items-center gap-3">
                        <Identity />
                        <button onclick={on_sign_out}
                                class="rounded-md border border-slate-300 px-3 py-1.5 text-sm \
                                       font-medium text-slate-600 hover:bg-slate-50">
                            { "Sign out" }
                        </button>
                    </div>
                </div>
            </header>
            <main class="mx-auto max-w-6xl px-6 py-10">
                { content }
            </main>
        </div>
    }
}

/// The signed-in principal's roles, shown in the header (`GET /api/auth/whoami`).
/// Renders nothing when auth is disabled or no roles are reported.
#[function_component(Identity)]
fn identity() -> Html {
    let who = use_api(|client| async move { client.get_json::<WhoAmI>("/api/auth/whoami").await });
    let Fetch::Ready(who) = &who.state else {
        return html! {};
    };
    if !who.auth_enabled || who.roles.is_empty() {
        return html! {};
    }
    let roles = who
        .roles
        .iter()
        .map(|r| match &r.target {
            Some(t) => format!("{}:{}", r.name, t),
            None => r.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    html! {
        <span class="hidden text-xs text-slate-500 sm:inline" title="your roles">
            { roles }
        </span>
    }
}

/// A single site's management view: a title plus tabs for deploy ops and
/// the config editor.
#[derive(Properties, PartialEq)]
struct SiteDetailProps {
    site: String,
}

/// Which per-site tab is active.
#[derive(Clone, Copy, PartialEq)]
enum SiteTab {
    Deployments,
    Config,
    Observability,
}

#[function_component(SiteDetail)]
fn site_detail(props: &SiteDetailProps) -> Html {
    let tab = use_state(|| SiteTab::Deployments);

    let tab_class = |active: bool| {
        if active {
            "border-b-2 border-sky-600 px-1 py-2 text-sm font-medium text-slate-900"
        } else {
            "border-b-2 border-transparent px-1 py-2 text-sm font-medium text-slate-500 \
             hover:text-slate-800"
        }
    };
    let select = |target: SiteTab, tab: UseStateHandle<SiteTab>| {
        Callback::from(move |_: MouseEvent| tab.set(target))
    };

    html! {
        <div>
            <h2 class="mb-4 text-lg font-semibold text-slate-900">{ &props.site }</h2>
            <div class="mb-6 flex gap-6 border-b border-slate-200">
                <button onclick={select(SiteTab::Deployments, tab.clone())}
                        class={tab_class(matches!(*tab, SiteTab::Deployments))}>
                    { "Deployments" }
                </button>
                <button onclick={select(SiteTab::Config, tab.clone())}
                        class={tab_class(matches!(*tab, SiteTab::Config))}>
                    { "Configuration" }
                </button>
                <button onclick={select(SiteTab::Observability, tab.clone())}
                        class={tab_class(matches!(*tab, SiteTab::Observability))}>
                    { "Observability" }
                </button>
            </div>
            {
                match *tab {
                    SiteTab::Deployments => html! { <DeployOps site={props.site.clone()} /> },
                    SiteTab::Config => html! { <ConfigEditor site={props.site.clone()} /> },
                    SiteTab::Observability => html! {
                        <SiteObservability site={props.site.clone()} />
                    },
                }
            }
        </div>
    }
}
