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
use hooks::{use_api, Fetch};
use maintenance::Maintenance;
use models::{FunctionSummary, WhoAmI};
use observability::{FunctionLogs, Metrics, SiteObservability};
use tokens::Tokens;
use wasm_bindgen_futures::spawn_local;
use widgets::{ErrorBanner, Spinner};
use yew::prelude::*;
use yew_router::prelude::*;

/// Root component: the [`AuthProvider`] owns the session, a [`BrowserRouter`]
/// owns the client-side history routing, then the app shows the login gate or
/// the authenticated shell. The router's `basename` comes from
/// [`console_base`] (the server-injected mount path), so the console works
/// under any path the operator mounts it at (e.g. `/_console`). The API base URL
/// is empty (same-origin — the `/api` it drives is root-absolute regardless of
/// the mount); a separately-hosted console sets a non-empty `base` here and the
/// server must allow that origin via `ServerOptions::cors_allowed_origins`.
#[function_component(App)]
pub fn app() -> Html {
    html! {
        <AuthProvider base="">
            <BrowserRouter basename={console_base()}>
                <Shell />
            </BrowserRouter>
        </AuthProvider>
    }
}

/// The base path the console is served under, read from the
/// `<meta name="boatramp-console-base">` the server injects when it mounts the
/// console at a sub-path. `None` for a root-mounted deploy (no `basename`).
fn console_base() -> Option<AttrValue> {
    let content = web_sys::window()?
        .document()?
        .query_selector("meta[name=\"boatramp-console-base\"]")
        .ok()??
        .get_attribute("content")?;
    (!content.is_empty() && content != "/").then(|| AttrValue::from(content))
}

/// The console's client-side routes. Kept deliberately shallow (the per-site
/// tabs stay component-local); paths are relative to the router `basename`.
#[derive(Clone, Routable, PartialEq)]
enum Route {
    /// The all-sites overview (dashboard).
    #[at("/")]
    Sites,
    /// A single site's management view (deploy ops / config / observability).
    #[at("/sites/:name")]
    Site { name: String },
    /// The project's top-level functions (log viewer).
    #[at("/functions")]
    Functions,
    /// A single function's live guest logs.
    #[at("/functions/:name")]
    Function { name: String },
    /// Cluster-wide maintenance (prune / scrub / certs).
    #[at("/maintenance")]
    Maintenance,
    /// API tokens + cache invalidation (admin-scoped).
    #[at("/tokens")]
    Tokens,
    /// The Prometheus metrics dump (admin-scoped).
    #[at("/metrics")]
    Metrics,
    /// Any unknown path redirects to the overview.
    #[not_found]
    #[at("/404")]
    NotFound,
}

/// The top-nav group a route belongs to, so `/sites/:name` still lights up the
/// "Sites" tab.
fn nav_group(route: &Route) -> u8 {
    match route {
        Route::Sites | Route::Site { .. } => 0,
        Route::Functions | Route::Function { .. } => 1,
        Route::Maintenance => 2,
        Route::Tokens => 3,
        Route::Metrics => 4,
        Route::NotFound => 5,
    }
}

/// Render the page for a route.
fn switch(route: Route) -> Html {
    match route {
        Route::Sites => html! { <SitesPage /> },
        Route::Site { name } => html! { <SitePage name={name} /> },
        Route::Functions => html! { <FunctionsPage /> },
        Route::Function { name } => html! { <FunctionPage name={name} /> },
        Route::Maintenance => html! { <Maintenance /> },
        Route::Tokens => html! { <Tokens /> },
        Route::Metrics => html! { <Metrics /> },
        Route::NotFound => html! { <Redirect<Route> to={Route::Sites} /> },
    }
}

/// Switches between the login view and the authenticated console; inside the
/// [`BrowserRouter`], so navigation is real history routing (deep-linkable).
#[function_component(Shell)]
fn shell() -> Html {
    let session = use_session();
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

    html! {
        <div class="min-h-screen bg-slate-50 text-slate-800">
            <header class="border-b border-slate-200 bg-white">
                <div class="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
                    <div class="flex items-center gap-6">
                        <h1 class="text-lg font-semibold tracking-tight">{ "boatramp console" }</h1>
                        <nav class="flex items-center gap-1">
                            <NavItem to={Route::Sites} label="Sites" />
                            <NavItem to={Route::Functions} label="Functions" />
                            <NavItem to={Route::Maintenance} label="Maintenance" />
                            <NavItem to={Route::Tokens} label="Tokens" />
                            <NavItem to={Route::Metrics} label="Metrics" />
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
                <Switch<Route> render={switch} />
            </main>
        </div>
    }
}

/// A top-nav item: a router [`Link`] that highlights when its route group is
/// active (so `/sites/:name` keeps "Sites" lit).
#[derive(Properties, PartialEq)]
struct NavItemProps {
    to: Route,
    label: AttrValue,
}

#[function_component(NavItem)]
fn nav_item(props: &NavItemProps) -> Html {
    let active = use_route::<Route>()
        .as_ref()
        .is_some_and(|r| nav_group(r) == nav_group(&props.to));
    let class = if active {
        "rounded-md bg-slate-100 px-3 py-1.5 text-sm font-medium text-slate-900"
    } else {
        "rounded-md px-3 py-1.5 text-sm font-medium text-slate-500 hover:text-slate-800"
    };
    html! {
        <Link<Route> to={props.to.clone()} classes={classes!(class)}>
            { props.label.clone() }
        </Link<Route>>
    }
}

/// The all-sites overview; selecting a site navigates to its page.
#[function_component(SitesPage)]
fn sites_page() -> Html {
    let navigator = use_navigator().expect("console is rendered inside a Router");
    let on_select = Callback::from(move |site: String| {
        navigator.push(&Route::Site { name: site });
    });
    html! { <Dashboard on_select={on_select} /> }
}

/// A single site's page: a back link to the overview plus the site detail.
#[derive(Properties, PartialEq)]
struct SitePageProps {
    name: String,
}

#[function_component(SitePage)]
fn site_page(props: &SitePageProps) -> Html {
    html! {
        <div>
            <Link<Route> to={Route::Sites}
                classes={classes!("mb-4", "inline-block", "text-sm", "text-slate-500", "hover:text-slate-800")}>
                { "← All sites" }
            </Link<Route>>
            <SiteDetail site={props.name.clone()} />
        </div>
    }
}

/// The functions overview: the project's **top-level** functions (GraphQL subgraphs,
/// auth functions, workers) — the ones whose guest output is otherwise unreadable.
/// Selecting one opens its live log view. `GET /api/functions` returns both top-level
/// and site-derived summaries; the latter are named `"<site>/<fn>"` and their output is
/// the site's, so they are filtered out here (a function log view is meaningful only for
/// a bare-named, invoke-addressable top-level function).
#[function_component(FunctionsPage)]
fn functions_page() -> Html {
    let navigator = use_navigator().expect("console is rendered inside a Router");
    let functions = use_api(|client| async move {
        client
            .get_json::<Vec<FunctionSummary>>("/api/functions")
            .await
    });

    match &functions.state {
        Fetch::Loading => html! { <Spinner label="Loading functions…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(functions.reload.clone())} />
        },
        Fetch::Ready(list) => {
            let top_level: Vec<&FunctionSummary> =
                list.iter().filter(|f| !f.name.contains('/')).collect();
            if top_level.is_empty() {
                return html! {
                    <div class="rounded-lg border border-dashed border-slate-300 bg-white p-10 text-center">
                        <p class="text-slate-500">{ "No top-level functions. Deploy one with " }
                            <code class="rounded bg-slate-100 px-1.5 py-0.5 text-sm">{ "boatramp function" }</code>
                            { "." }
                        </p>
                    </div>
                };
            }
            html! {
                <div>
                    <div class="mb-6 flex items-center justify-between">
                        <h2 class="text-lg font-semibold text-slate-900">{ "Functions" }</h2>
                        <span class="text-sm text-slate-500">
                            { format!("{} function{}", top_level.len(),
                                      if top_level.len() == 1 { "" } else { "s" }) }
                        </span>
                    </div>
                    <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                        { for top_level.into_iter().map(|f| {
                            let name = f.name.clone();
                            let navigator = navigator.clone();
                            let onclick = Callback::from(move |_: MouseEvent| {
                                navigator.push(&Route::Function { name: name.clone() });
                            });
                            html! {
                                <button key={f.name.clone()} {onclick}
                                        class="rounded-xl border border-slate-200 bg-white p-5 text-left \
                                               shadow-sm hover:border-slate-300 hover:shadow">
                                    <div class="font-medium text-slate-900">{ &f.name }</div>
                                    if !f.runtime.is_empty() {
                                        <div class="mt-1 text-xs text-slate-500">{ &f.runtime }</div>
                                    }
                                    <div class="mt-3 text-sm text-slate-500">{ "View live logs →" }</div>
                                </button>
                            }
                        }) }
                    </div>
                </div>
            }
        }
    }
}

/// A single function's page: a back link plus its live guest-log tail.
#[derive(Properties, PartialEq)]
struct FunctionPageProps {
    name: String,
}

#[function_component(FunctionPage)]
fn function_page(props: &FunctionPageProps) -> Html {
    html! {
        <div>
            <Link<Route> to={Route::Functions}
                classes={classes!("mb-4", "inline-block", "text-sm", "text-slate-500", "hover:text-slate-800")}>
                { "← All functions" }
            </Link<Route>>
            <h2 class="mb-6 text-lg font-semibold text-slate-900">{ &props.name }</h2>
            <FunctionLogs name={props.name.clone()} />
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
