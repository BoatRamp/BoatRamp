//! Auth state + login.
//!
//! Pure client-side: the token lives in a top-level reactive [`Session`] context
//! (Yew context), mirrored to `sessionStorage` so a reload survives (operator-
//! only admin tool; the usual XSS caveat). A `401` from any API call routes back
//! to the login view via [`Session::sign_out`]. Token acquisition is either
//! *paste a control-plane token* or **OIDC** via the OAuth2 Authorization-Code +
//! PKCE flow ([`crate::oidc`]); both yield a Bearer the existing `/api/*`
//! accepts and both land here through [`Session::sign_in`].

use gloo_storage::{SessionStorage, Storage};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::api::ApiClient;
use crate::oidc::{self, OidcConfig};

/// `sessionStorage` key for the persisted bearer token.
const TOKEN_KEY: &str = "boatramp.console.token";

/// The reactive auth/session context shared across the app: the current bearer
/// token (if signed in) and the API base URL. Cloning is cheap; equality drives
/// re-render when the token changes (sign-in / sign-out).
#[derive(Clone, PartialEq)]
pub struct Session {
    /// The bearer token, or `None` when signed out.
    token: Option<String>,
    /// API base URL (empty = same-origin dogfood deploy).
    base: String,
    /// Setter handle, so any component can sign in / out and the whole tree
    /// re-renders. Set the new token (or `None` to sign out).
    set: Callback<Option<String>>,
}

impl Session {
    /// Whether a token is held (the app is past the login gate).
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// The API base URL (empty = same-origin), for callers that issue requests
    /// outside an [`ApiClient`] — e.g. the OIDC→token exchange at sign-in.
    pub fn api_base(&self) -> String {
        self.base.clone()
    }

    /// The current bearer token, for callers that build a raw `fetch` (the SSE
    /// log tail — `EventSource` can't carry an `Authorization` header).
    pub fn bearer(&self) -> Option<String> {
        self.token.clone()
    }

    /// An [`ApiClient`] bound to the current token + base URL — the handle every
    /// data view uses to call the control-plane API.
    pub fn client(&self) -> ApiClient {
        ApiClient::new(self.base.clone(), self.token.clone())
    }

    /// Persist `token` and re-render the tree (the login → dashboard switch).
    pub fn sign_in(&self, token: String) {
        // Mirror to sessionStorage for reload survival; a failure (private mode)
        // is non-fatal — the in-memory token still works for this session.
        let _ = SessionStorage::set(TOKEN_KEY, &token);
        self.set.emit(Some(token));
    }

    /// Clear the token (the `401` interceptor + the explicit sign-out button).
    pub fn sign_out(&self) {
        SessionStorage::delete(TOKEN_KEY);
        self.set.emit(None);
    }
}

/// The auth provider: owns the token state (seeded from `sessionStorage`) and
/// hands a [`Session`] context down to `children`. Wrap the whole app in this.
#[derive(Properties, PartialEq)]
pub struct AuthProviderProps {
    /// API base URL (empty = same-origin). Threaded through to the [`Session`].
    #[prop_or_default]
    pub base: String,
    /// The app tree that consumes the [`Session`] context.
    pub children: Html,
}

#[function_component(AuthProvider)]
pub fn auth_provider(props: &AuthProviderProps) -> Html {
    // Seed from sessionStorage so a reload stays signed in.
    let token = use_state(|| SessionStorage::get::<String>(TOKEN_KEY).ok());

    let set = {
        let token = token.clone();
        Callback::from(move |next: Option<String>| token.set(next))
    };

    let session = Session {
        token: (*token).clone(),
        base: props.base.clone(),
        set,
    };

    html! {
        <ContextProvider<Session> context={session}>
            { props.children.clone() }
        </ContextProvider<Session>>
    }
}

/// Read the [`Session`] from context. Panics only if a component is mounted
/// outside [`AuthProvider`], which is a programming error.
#[hook]
pub fn use_session() -> Session {
    use_context::<Session>().expect("Session context — wrap the app in <AuthProvider>")
}

/// The login view: paste a control-plane token (single/multi-token), or sign in
/// with OIDC (Authorization Code + PKCE). The token path stores the Bearer in
/// the [`Session`] directly; the OIDC path redirects to the IdP and lands back
/// through the callback handler in [`crate::App`] (which also calls
/// [`Session::sign_in`]). Either way the app re-renders into the authenticated
/// shell. An `error` prop surfaces a failed OIDC callback from the redirect.
#[derive(Properties, PartialEq)]
pub struct LoginViewProps {
    /// A message from a failed OIDC callback (shown above the form), if any.
    #[prop_or_default]
    pub error: Option<String>,
}

#[function_component(LoginView)]
pub fn login_view(props: &LoginViewProps) -> Html {
    let session = use_session();
    let input = use_node_ref();
    let error = use_state(|| Option::<String>::None);

    // OIDC config fields, pre-filled from localStorage (issuer/client_id/scope
    // are not secret — persisted for operator convenience).
    let oidc_cfg = use_state(OidcConfig::load);
    let issuer_ref = use_node_ref();
    let client_id_ref = use_node_ref();
    let scope_ref = use_node_ref();
    let oidc_error = use_state(|| Option::<String>::None);
    let oidc_busy = use_state(|| false);

    let on_submit = {
        let session = session.clone();
        let input = input.clone();
        let error = error.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let value = input
                .cast::<HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            let token = value.trim().to_string();
            if token.is_empty() {
                error.set(Some("Enter a control-plane token.".into()));
                return;
            }
            error.set(None);
            session.sign_in(token);
        })
    };

    let on_oidc = {
        let issuer_ref = issuer_ref.clone();
        let client_id_ref = client_id_ref.clone();
        let scope_ref = scope_ref.clone();
        let oidc_error = oidc_error.clone();
        let oidc_busy = oidc_busy.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let read = |r: &NodeRef| {
                r.cast::<HtmlInputElement>()
                    .map(|el| el.value())
                    .unwrap_or_default()
            };
            let config = OidcConfig {
                issuer: read(&issuer_ref),
                client_id: read(&client_id_ref),
                scope: read(&scope_ref),
            };
            oidc_error.set(None);
            oidc_busy.set(true);
            let oidc_error = oidc_error.clone();
            let oidc_busy = oidc_busy.clone();
            spawn_local(async move {
                // On success this navigates away (the page is replaced), so we
                // only ever observe the error branch here.
                if let Err(msg) = oidc::start_login(config).await {
                    oidc_error.set(Some(msg));
                    oidc_busy.set(false);
                }
            });
        })
    };

    html! {
        <main class="min-h-screen bg-slate-50 flex items-center justify-center px-6 py-12">
            <div class="w-full max-w-md">
                <div class="mb-8 text-center">
                    <h1 class="text-2xl font-semibold tracking-tight text-slate-900">
                        { "boatramp console" }
                    </h1>
                    <p class="mt-1 text-sm text-slate-500">
                        { "Sign in with a control-plane token or OIDC." }
                    </p>
                </div>
                if let Some(msg) = &props.error {
                    <div class="mb-4 rounded-md border border-rose-200 bg-rose-50 px-3 py-2 \
                                text-sm text-rose-700">
                        { "OIDC sign-in failed: " }{ msg }
                    </div>
                }
                <form onsubmit={on_submit}
                      class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                    <label for="token" class="block text-sm font-medium text-slate-700">
                        { "API token" }
                    </label>
                    <input ref={input} id="token" type="password" autocomplete="off"
                           placeholder="paste your Bearer token"
                           class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm \
                                  shadow-sm focus:border-sky-500 focus:outline-none focus:ring-1 \
                                  focus:ring-sky-500" />
                    if let Some(msg) = &*error {
                        <p class="mt-2 text-sm text-rose-600">{ msg }</p>
                    }
                    <button type="submit"
                            class="mt-4 w-full rounded-md bg-sky-600 px-3 py-2 text-sm font-medium \
                                   text-white shadow-sm hover:bg-sky-700 focus:outline-none \
                                   focus:ring-2 focus:ring-sky-500 focus:ring-offset-2">
                        { "Sign in" }
                    </button>
                </form>

                <div class="my-6 flex items-center gap-3 text-xs uppercase tracking-wide \
                            text-slate-400">
                    <span class="h-px flex-1 bg-slate-200"></span>
                    { "or" }
                    <span class="h-px flex-1 bg-slate-200"></span>
                </div>

                <form onsubmit={on_oidc}
                      class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
                    <h2 class="text-sm font-medium text-slate-700">{ "Sign in with OIDC" }</h2>
                    <p class="mt-1 text-xs text-slate-500">
                        { "OAuth2 Authorization Code + PKCE. The IdP must allow the console's \
                           redirect URI and issue a JWT whose claim carries boatramp roles; the \
                           console exchanges it for a token at /api/auth/exchange." }
                    </p>

                    <label for="oidc-issuer"
                           class="mt-4 block text-sm font-medium text-slate-700">
                        { "Issuer URL" }
                    </label>
                    <input ref={issuer_ref} id="oidc-issuer" type="url" autocomplete="off"
                           value={oidc_cfg.issuer.clone()}
                           placeholder="https://idp.example.com"
                           class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm \
                                  shadow-sm focus:border-sky-500 focus:outline-none focus:ring-1 \
                                  focus:ring-sky-500" />

                    <label for="oidc-client-id"
                           class="mt-3 block text-sm font-medium text-slate-700">
                        { "Client ID" }
                    </label>
                    <input ref={client_id_ref} id="oidc-client-id" type="text" autocomplete="off"
                           value={oidc_cfg.client_id.clone()}
                           placeholder="the console's client_id at the IdP"
                           class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm \
                                  shadow-sm focus:border-sky-500 focus:outline-none focus:ring-1 \
                                  focus:ring-sky-500" />
                    <p class="mt-1 text-xs text-slate-500">
                        { "The console's own registration with the IdP — distinct from the API's \
                           audience, so it must be supplied here." }
                    </p>

                    <label for="oidc-scope"
                           class="mt-3 block text-sm font-medium text-slate-700">
                        { "Scope " }
                        <span class="font-normal text-slate-400">{ "(optional)" }</span>
                    </label>
                    <input ref={scope_ref} id="oidc-scope" type="text" autocomplete="off"
                           value={oidc_cfg.scope.clone()}
                           placeholder={oidc::DEFAULT_SCOPE}
                           class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm \
                                  shadow-sm focus:border-sky-500 focus:outline-none focus:ring-1 \
                                  focus:ring-sky-500" />

                    if let Some(msg) = &*oidc_error {
                        <p class="mt-2 text-sm text-rose-600">{ msg }</p>
                    }
                    <button type="submit" disabled={*oidc_busy}
                            class="mt-4 w-full rounded-md border border-slate-300 bg-white px-3 \
                                   py-2 text-sm font-medium text-slate-700 shadow-sm \
                                   hover:bg-slate-50 focus:outline-none focus:ring-2 \
                                   focus:ring-sky-500 focus:ring-offset-2 disabled:opacity-60">
                        { if *oidc_busy { "Redirecting…" } else { "Sign in with OIDC" } }
                    </button>
                </form>
            </div>
        </main>
    }
}
