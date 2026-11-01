//! The site config editor — the big typed form.
//!
//! GET `/api/sites/:site/config` → [`SiteConfig`], edit it field-by-field (all
//! typed against `boatramp-types`), PUT it back. Covers domains, transport
//! security (HTTPS redirect / HSTS / CSP / frame-options), visitor access
//! control (basic-auth / IP rules / rate limit), the WAF (UA rules + anomaly
//! scoring), and on-the-fly compression. The domain-ownership verification flow
//! lives alongside it ([`DomainVerifications`]).

use std::collections::BTreeMap;
use std::rc::Rc;

use boatramp_types::access::{BasicAuth, RateLimit, hash_password};
use boatramp_types::config::{
    CookieAuthConfig, HandlerGraphqlConfig, HandlerGraphqlDataConfig, HandlerGraphqlRowTerm,
    HandlerGraphqlTableConfig, HandlersSiteConfig, Hsts, SiteConfig,
};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::auth::use_session;
use crate::hooks::{Fetch, use_api};
use crate::verify::DomainVerifications;
use crate::widgets::{
    BtnVariant, Button, CheckField, ErrorBanner, INPUT, NumberField, Pill, Section, Spinner,
    TextAreaField, TextField, Tone, TriStateField,
};

/// The config editor for one site.
#[derive(Properties, PartialEq)]
pub struct ConfigEditorProps {
    /// The site whose config is edited.
    pub site: String,
}

#[function_component(ConfigEditor)]
pub fn config_editor(props: &ConfigEditorProps) -> Html {
    let site = props.site.clone();
    let loaded = {
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

    match &loaded.state {
        Fetch::Loading => html! { <Spinner label="Loading config…" /> },
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(loaded.reload.clone())} />
        },
        // Re-mount the form with the loaded config as its initial state; `key`
        // forces a fresh form when the config reloads after a save.
        Fetch::Ready(config) => html! {
            <ConfigForm site={site.clone()} initial={Rc::new(config.clone())} />
        },
    }
}

/// The editable form, seeded from the loaded [`SiteConfig`].
#[derive(Properties, PartialEq)]
struct ConfigFormProps {
    site: String,
    initial: Rc<SiteConfig>,
}

#[function_component(ConfigForm)]
fn config_form(props: &ConfigFormProps) -> Html {
    let session = use_session();
    let site = props.site.clone();
    // The working copy the form edits; `PUT` sends this verbatim.
    let config = use_state(|| (*props.initial).clone());
    // The last-saved baseline: edits are "dirty" against this, and a successful
    // save advances it (so "saved" doesn't go stale as editing continues, and a
    // Discard can restore it).
    let baseline = use_state(|| (*props.initial).clone());
    // Save status: idle / saving / saved / error.
    let status = use_state(|| SaveStatus::Idle);

    let dirty = *config != *baseline;

    let save = {
        let session = session.clone();
        let site = site.clone();
        let config = config.clone();
        let baseline = baseline.clone();
        let status = status.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let body = (*config).clone();
            let baseline = baseline.clone();
            let status = status.clone();
            status.set(SaveStatus::Saving);
            spawn_local(async move {
                match client
                    .put_json(&format!("/api/sites/{site}/config"), &body)
                    .await
                {
                    Ok(()) => {
                        baseline.set(body);
                        status.set(SaveStatus::Saved);
                    }
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => status.set(SaveStatus::Error(err.to_string())),
                }
            });
        })
    };

    let discard = {
        let config = config.clone();
        let baseline = baseline.clone();
        let status = status.clone();
        Callback::from(move |_: MouseEvent| {
            config.set((*baseline).clone());
            status.set(SaveStatus::Idle);
        })
    };

    html! {
        <div class="space-y-6">
            <DomainsPanel config={config.clone()} />
            <SecurityPanel config={config.clone()} />
            <AccessPanel config={config.clone()} />
            // Cookie-session auth is a visitor-auth concern, not a wasm-handler one —
            // its own section, next to Access control.
            <CookieAuthPanel config={config.clone()} />
            <WafPanel config={config.clone()} />
            <HandlersPanel config={config.clone()} />
            // The GraphQL edge is the largest per-site subtree and a primary serving
            // posture — its own top-level section, not buried under Handlers.
            <GraphqlPanel config={config.clone()} />
            <CompressionPanel config={config.clone()} />
            <DomainVerifications site={site.clone()} />

            <div class="sticky bottom-4 flex items-center justify-end gap-3 rounded-xl border \
                        border-slate-200 bg-white/90 p-4 shadow backdrop-blur">
                { save_bar_status(&status, dirty) }
                if dirty {
                    <Button variant={BtnVariant::Secondary} label="Discard" onclick={discard} />
                }
                <Button variant={BtnVariant::Primary}
                        busy={matches!(&*status, SaveStatus::Saving)} busy_label="Saving…"
                        disabled={!dirty} label="Save config" onclick={save} />
            </div>
        </div>
    }
}

/// Shared prop for every editor panel: the working config state. Each panel
/// builds its own `update` closure over it (see [`make_update`]).
#[derive(Properties, PartialEq)]
struct PanelProps {
    config: UseStateHandle<SiteConfig>,
}

/// A mutator over a panel's `config` handle: it takes a closure that edits the
/// config in place, applies it to a clone, and stores the result.
type Update = Rc<dyn Fn(&dyn Fn(&mut SiteConfig))>;

/// Build an [`Update`] over `config`: clone the config, apply the caller's edit,
/// store it back. `Rc` so the per-field callbacks can share it cheaply.
fn make_update(config: &UseStateHandle<SiteConfig>) -> Update {
    let config = config.clone();
    Rc::new(move |f: &dyn Fn(&mut SiteConfig)| {
        let mut next = (*config).clone();
        f(&mut next);
        config.set(next);
    })
}

/// The save-in-flight / result indicator.
#[derive(Clone, PartialEq)]
enum SaveStatus {
    Idle,
    Saving,
    Saved,
    Error(String),
}

/// The save-bar indicator. A pending edit (`dirty`) shows an amber "unsaved
/// changes" pill, which takes precedence over a stale "saved" so the operator is
/// never misled into thinking new edits are persisted. A failure renders its
/// reason as VISIBLE text inside an assertive `alert`; progress/state live in a
/// persistent polite `status` region so changes are announced, never buried in a
/// hover-only `title`.
fn save_bar_status(status: &SaveStatus, dirty: bool) -> Html {
    if let SaveStatus::Error(msg) = status {
        return html! {
            <span role="alert" class="text-sm font-medium text-rose-700">
                { format!("Save failed: {msg}") }
            </span>
        };
    }
    let inner = match status {
        SaveStatus::Saving => html! { <span class="text-sm text-slate-500">{ "Saving…" }</span> },
        _ if dirty => html! { <Pill text="unsaved changes" tone={Tone::Warn} /> },
        SaveStatus::Saved => html! { <Pill text="saved" tone={Tone::Good} /> },
        _ => Html::default(),
    };
    // Always-present polite region (empty when idle), so its text changes announce.
    html! { <span role="status" aria-live="polite">{ inner }</span> }
}

// ---- Lines <-> Vec<String> helpers -----------------------------------------

/// Join a list into newline-separated text for a textarea.
fn lines_join(items: &[String]) -> String {
    items.join("\n")
}

/// Split textarea text into a trimmed, empty-filtered list.
fn lines_split(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

// ---- Domains ----------------------------------------------------------------

#[function_component(DomainsPanel)]
fn domains_panel(props: &PanelProps) -> Html {
    let cfg = &*props.config;
    let update = make_update(&props.config);

    let on_primary = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let v = v.trim().to_string();
            update(&move |c: &mut SiteConfig| {
                c.domains.primary = if v.is_empty() { None } else { Some(v.clone()) };
            });
        })
    };
    let on_aliases = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.domains.aliases = list.clone());
        })
    };
    let on_wildcards = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.domains.wildcards = list.clone());
        })
    };
    let on_canonical = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| c.domains.canonical_redirect = v);
        })
    };

    html! {
        <Section title="Domains">
            <TextField label="Primary hostname" value={cfg.domains.primary.clone().unwrap_or_default()}
                       placeholder="example.com" on_change={on_primary} mono=true />
            <TextAreaField label="Aliases (one per line)" value={lines_join(&cfg.domains.aliases)}
                           hint="Exact hostnames, e.g. www.example.com" on_change={on_aliases} />
            <TextAreaField label="Wildcards (one per line)" value={lines_join(&cfg.domains.wildcards)}
                           hint="e.g. *.example.com (suffix match)" on_change={on_wildcards} />
            <CheckField label="Redirect aliases to the primary host (301 canonicalization)"
                        checked={cfg.domains.canonical_redirect} on_change={on_canonical} />
        </Section>
    }
}

// ---- Transport security -----------------------------------------------------

#[function_component(SecurityPanel)]
fn security_panel(props: &PanelProps) -> Html {
    let cfg = &*props.config;
    let update = make_update(&props.config);
    let sec = &cfg.security;

    let on_https = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| c.security.https_redirect = v)
        })
    };
    let on_hsts_toggle = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                c.security.hsts = if v { Some(Hsts::default()) } else { None };
            });
        })
    };
    let on_hsts_max_age = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let secs = v.trim().parse::<u64>().unwrap_or(0);
            update(&move |c: &mut SiteConfig| {
                if let Some(h) = c.security.hsts.as_mut() {
                    h.max_age = secs;
                }
            });
        })
    };
    let on_hsts_subdomains = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                if let Some(h) = c.security.hsts.as_mut() {
                    h.include_subdomains = v;
                }
            });
        })
    };
    let on_hsts_preload = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                if let Some(h) = c.security.hsts.as_mut() {
                    h.preload = v;
                }
            });
        })
    };
    let on_csp = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let v = v.trim().to_string();
            update(&move |c: &mut SiteConfig| {
                c.security.csp = if v.is_empty() { None } else { Some(v.clone()) };
            });
        })
    };
    let on_frame = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let v = v.trim().to_string();
            update(&move |c: &mut SiteConfig| {
                c.security.frame_options = if v.is_empty() { None } else { Some(v.clone()) };
            });
        })
    };

    html! {
        <Section title="Transport security">
            <CheckField label="Redirect plain HTTP to HTTPS (proxy-aware)"
                        checked={sec.https_redirect} on_change={on_https} />
            <CheckField label="Send Strict-Transport-Security (HSTS) on HTTPS"
                        checked={sec.hsts.is_some()} on_change={on_hsts_toggle} />
            if let Some(hsts) = &sec.hsts {
                <div class="ml-6 space-y-3 border-l border-slate-100 pl-4">
                    <TextField label="HSTS max-age (seconds)" value={hsts.max_age.to_string()}
                               on_change={on_hsts_max_age} />
                    <CheckField label="includeSubDomains" checked={hsts.include_subdomains}
                                on_change={on_hsts_subdomains} />
                    <CheckField label="preload" checked={hsts.preload} on_change={on_hsts_preload} />
                </div>
            }
            <TextField label="Content-Security-Policy" value={sec.csp.clone().unwrap_or_default()}
                       placeholder="default-src 'self'" hint="Leave blank to send no CSP header."
                       on_change={on_csp} />
            <TextField label="X-Frame-Options" value={sec.frame_options.clone().unwrap_or_default()}
                       placeholder="DENY or SAMEORIGIN" on_change={on_frame} />
        </Section>
    }
}

// ---- Access control ---------------------------------------------------------

#[function_component(AccessPanel)]
fn access_panel(props: &PanelProps) -> Html {
    let cfg = &*props.config;
    let update = make_update(&props.config);
    let access = &cfg.access;

    // --- IP rules ---
    let on_allow = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.access.ip.allow = list.clone());
        })
    };
    let on_deny = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.access.ip.deny = list.clone());
        })
    };
    let on_trusted = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.access.trusted_proxies = list.clone());
        })
    };

    // --- Rate limit ---
    let on_rl_toggle = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                c.access.rate_limit = if v {
                    Some(RateLimit { rps: 10, burst: 0 })
                } else {
                    None
                };
            });
        })
    };
    let on_rps = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let rps = v.trim().parse::<u32>().unwrap_or(0);
            update(&move |c: &mut SiteConfig| {
                if let Some(rl) = c.access.rate_limit.as_mut() {
                    rl.rps = rps;
                }
            });
        })
    };
    let on_burst = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let burst = v.trim().parse::<u32>().unwrap_or(0);
            update(&move |c: &mut SiteConfig| {
                if let Some(rl) = c.access.rate_limit.as_mut() {
                    rl.burst = burst;
                }
            });
        })
    };

    // --- Basic auth ---
    let on_basic_toggle = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                c.access.basic_auth = if v {
                    Some(BasicAuth {
                        realm: "Restricted".to_string(),
                        users: BTreeMap::new(),
                    })
                } else {
                    None
                };
            });
        })
    };
    let on_realm = {
        let update = update.clone();
        Callback::from(move |v: String| {
            update(&move |c: &mut SiteConfig| {
                if let Some(auth) = c.access.basic_auth.as_mut() {
                    auth.realm = v.clone();
                }
            });
        })
    };

    html! {
        <Section title="Access control">
            <div>
                <h4 class="mb-2 text-sm font-medium text-slate-600">{ "IP rules (CIDR or bare IP)" }</h4>
                <div class="grid gap-3 sm:grid-cols-2">
                    <TextAreaField label="Allow (empty = allow all)" value={lines_join(&access.ip.allow)}
                                   on_change={on_allow} />
                    <TextAreaField label="Deny (wins over allow)" value={lines_join(&access.ip.deny)}
                                   on_change={on_deny} />
                </div>
                <div class="mt-3">
                    <TextAreaField label="Trusted proxies (CIDR — honor X-Forwarded-For from these)"
                                   value={lines_join(&access.trusted_proxies)} rows={2}
                                   on_change={on_trusted} />
                </div>
            </div>

            <div class="border-t border-slate-100 pt-4">
                <CheckField label="Rate limit visitors" checked={access.rate_limit.is_some()}
                            on_change={on_rl_toggle} />
                if let Some(rl) = &access.rate_limit {
                    <div class="ml-6 mt-3 grid gap-3 border-l border-slate-100 pl-4 sm:grid-cols-2">
                        <TextField label="Requests / second" value={rl.rps.to_string()}
                                   on_change={on_rps} />
                        <TextField label="Burst (0 = same as rps)" value={rl.burst.to_string()}
                                   on_change={on_burst} />
                    </div>
                }
            </div>

            <div class="border-t border-slate-100 pt-4">
                <CheckField label="HTTP Basic auth" checked={access.basic_auth.is_some()}
                            on_change={on_basic_toggle} />
                if let Some(auth) = &access.basic_auth {
                    <div class="ml-6 mt-3 space-y-3 border-l border-slate-100 pl-4">
                        <TextField label="Realm" value={auth.realm.clone()} on_change={on_realm} />
                        <BasicAuthUsers config={props.config.clone()} />
                    </div>
                }
            </div>
        </Section>
    }
}

/// The basic-auth user list with an add/remove form. Passwords are hashed in the
/// browser with the shared argon2 `hash_password` (the same code the server
/// uses), so a plaintext password never crosses the wire.
#[function_component(BasicAuthUsers)]
fn basic_auth_users(props: &PanelProps) -> Html {
    let cfg = &*props.config;
    let update = make_update(&props.config);
    let user_ref = use_node_ref();
    let pass_ref = use_node_ref();

    let users: Vec<String> = cfg
        .access
        .basic_auth
        .as_ref()
        .map(|auth| auth.users.keys().cloned().collect())
        .unwrap_or_default();

    let add = {
        let update = update.clone();
        let user_ref = user_ref.clone();
        let pass_ref = pass_ref.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let user = user_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            let pass = pass_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value())
                .unwrap_or_default();
            if user.is_empty() || pass.is_empty() {
                return;
            }
            let hash = hash_password(&pass);
            update(&move |c: &mut SiteConfig| {
                if let Some(auth) = c.access.basic_auth.as_mut() {
                    auth.users.insert(user.clone(), hash.clone());
                }
            });
            if let Some(el) = user_ref.cast::<HtmlInputElement>() {
                el.set_value("");
            }
            if let Some(el) = pass_ref.cast::<HtmlInputElement>() {
                el.set_value("");
            }
        })
    };

    let remove = {
        let update = update.clone();
        Callback::from(move |name: String| {
            update(&move |c: &mut SiteConfig| {
                if let Some(auth) = c.access.basic_auth.as_mut() {
                    auth.users.remove(&name);
                }
            });
        })
    };

    html! {
        <div>
            <p class="mb-2 text-sm font-medium text-slate-600">{ "Users" }</p>
            if users.is_empty() {
                <p class="text-sm text-slate-500">{ "No users — anyone is prompted but none can pass." }</p>
            } else {
                <ul class="divide-y divide-slate-100">
                    { for users.iter().map(|name| {
                        let name = name.clone();
                        let on_remove = {
                            let remove = remove.clone();
                            let name = name.clone();
                            Callback::from(move |_: MouseEvent| remove.emit(name.clone()))
                        };
                        html! {
                            <li class="flex items-center justify-between py-1.5 text-sm">
                                <span class="font-medium text-slate-700">{ &name }</span>
                                <button onclick={on_remove}
                                        class="text-xs font-medium text-rose-700 hover:underline">
                                    { "Remove" }
                                </button>
                            </li>
                        }
                    }) }
                </ul>
            }
            <form onsubmit={add} class="mt-2 flex flex-wrap items-end gap-2">
                <input ref={user_ref} placeholder="username"
                       class="rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm \
                              focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500" />
                <input ref={pass_ref} type="password" placeholder="password" autocomplete="new-password"
                       class="rounded-md border border-slate-300 px-2.5 py-1.5 text-sm shadow-sm \
                              focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500" />
                <button type="submit"
                        class="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium \
                               text-slate-700 hover:bg-slate-50">
                    { "Add user" }
                </button>
            </form>
        </div>
    }
}

// ---- WAF --------------------------------------------------------------------

#[function_component(WafPanel)]
fn waf_panel(props: &PanelProps) -> Html {
    let cfg = &*props.config;
    let update = make_update(&props.config);
    let waf = &cfg.access.waf;

    let on_ua_toggle = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| c.access.waf.user_agent.enabled = v)
        })
    };
    let on_ua_deny = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.access.waf.user_agent.deny = list.clone());
        })
    };
    let on_ua_allow = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.access.waf.user_agent.allow = list.clone());
        })
    };
    let on_anom_toggle = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| c.access.waf.anomaly.enabled = v)
        })
    };
    let on_threshold = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let t = v.trim().parse::<u32>().unwrap_or(1);
            update(&move |c: &mut SiteConfig| c.access.waf.anomaly.threshold = t);
        })
    };
    let on_empty_ua = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| c.access.waf.anomaly.score_empty_user_agent = v)
        })
    };
    let on_missing_accept = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| c.access.waf.anomaly.score_missing_accept = v)
        })
    };
    let on_susp_paths = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| c.access.waf.anomaly.suspicious_paths = list.clone());
        })
    };

    html! {
        <Section title="Web application firewall">
            <CheckField label="User-agent rules" checked={waf.user_agent.enabled}
                        on_change={on_ua_toggle} />
            if waf.user_agent.enabled {
                <div class="ml-6 grid gap-3 border-l border-slate-100 pl-4 sm:grid-cols-2">
                    <TextAreaField label="Deny regexes (any match blocks)"
                                   value={lines_join(&waf.user_agent.deny)} on_change={on_ua_deny} />
                    <TextAreaField label="Allow regexes (non-empty = UA must match one)"
                                   value={lines_join(&waf.user_agent.allow)} on_change={on_ua_allow} />
                </div>
            }
            <div class="border-t border-slate-100 pt-4">
                <CheckField label="Anomaly scoring" checked={waf.anomaly.enabled}
                            on_change={on_anom_toggle} />
                if waf.anomaly.enabled {
                    <div class="ml-6 mt-3 space-y-3 border-l border-slate-100 pl-4">
                        <TextField label="Block threshold (min 1)" value={waf.anomaly.threshold.to_string()}
                                   on_change={on_threshold} />
                        <CheckField label="+1 when User-Agent is empty/missing"
                                    checked={waf.anomaly.score_empty_user_agent} on_change={on_empty_ua} />
                        <CheckField label="+1 when Accept header is missing"
                                    checked={waf.anomaly.score_missing_accept} on_change={on_missing_accept} />
                        <TextAreaField label="Suspicious path substrings"
                                       value={lines_join(&waf.anomaly.suspicious_paths)}
                                       hint="e.g. /.env, /.git/, /wp-login" on_change={on_susp_paths} />
                    </div>
                }
            </div>
        </Section>
    }
}

// ---- Compression ------------------------------------------------------------

/// Parse a cap text field: empty ⇒ `None` (engine default), else the parsed number.
fn parse_opt_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.parse().ok()).flatten()
}

/// Like [`parse_opt_u32`] for the 64-bit fuel cap.
fn parse_opt_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.parse().ok()).flatten()
}

/// Render an optional cap as a text-field value (`None` ⇒ empty).
fn cap_str<T: ToString>(v: Option<T>) -> String {
    v.map(|n| n.to_string()).unwrap_or_default()
}

/// The site's WebAssembly handler policy (`SiteConfig.handlers`): the enablement gate
/// activation checks against, the import allowlist, and the per-handler resource caps.
#[function_component(HandlersPanel)]
fn handlers_panel(props: &PanelProps) -> Html {
    let update = make_update(&props.config);
    // The current policy (a default when unset) for rendering.
    let h = props.config.handlers.clone().unwrap_or_default();

    let on_enabled = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                c.handlers
                    .get_or_insert_with(HandlersSiteConfig::default)
                    .enabled = v;
            });
        })
    };
    let on_imports = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| {
                c.handlers
                    .get_or_insert_with(HandlersSiteConfig::default)
                    .allow_imports = list.clone();
            });
        })
    };
    let on_mem = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let val = parse_opt_u32(&v);
            update(&move |c: &mut SiteConfig| {
                c.handlers
                    .get_or_insert_with(HandlersSiteConfig::default)
                    .max_memory_mb = val;
            });
        })
    };
    let on_timeout = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let val = parse_opt_u32(&v);
            update(&move |c: &mut SiteConfig| {
                c.handlers
                    .get_or_insert_with(HandlersSiteConfig::default)
                    .max_timeout_ms = val;
            });
        })
    };
    let on_conc = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let val = parse_opt_u32(&v);
            update(&move |c: &mut SiteConfig| {
                c.handlers
                    .get_or_insert_with(HandlersSiteConfig::default)
                    .max_concurrency = val;
            });
        })
    };
    let on_fuel = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let val = parse_opt_u64(&v);
            update(&move |c: &mut SiteConfig| {
                c.handlers
                    .get_or_insert_with(HandlersSiteConfig::default)
                    .max_fuel = val;
            });
        })
    };

    html! {
        <Section title="Handlers">
            <CheckField label="Run WebAssembly handlers on this site" checked={h.enabled}
                        on_change={on_enabled} />
            if h.enabled {
                <div class="ml-6 space-y-3 border-l border-slate-100 pl-4">
                    <TextAreaField label="Allowed imports (one per line)"
                        value={lines_join(&h.allow_imports)}
                        hint={"Interfaces a handler may import (sql, wasi:keyvalue, invoke, …). Must be a superset of every handler's declared imports, or activation is refused."}
                        on_change={on_imports} />
                    <TextField label="Max memory (MiB)" value={cap_str(h.max_memory_mb)}
                               hint="Empty ⇒ engine default." on_change={on_mem} />
                    <TextField label="Max timeout (ms)" value={cap_str(h.max_timeout_ms)}
                               hint="Empty ⇒ engine default." on_change={on_timeout} />
                    <TextField label="Max concurrency" value={cap_str(h.max_concurrency)}
                               hint="Concurrent invocations for this site." on_change={on_conc} />
                    <TextField label="Max fuel" value={cap_str(h.max_fuel)}
                               hint="Per-handler CPU fuel budget." on_change={on_fuel} />
                </div>
            } else {
                <p class="ml-6 text-sm text-slate-500">
                    { "A deployment that ships handlers is refused at activation until this is on." }
                </p>
            }
        </Section>
    }
}

// ---- GraphQL edge posture (handlers.graphql) --------------------------------

/// Set the `enforce_safelist` flag, preserving the plan invariant that the
/// safelist is strictly stronger than APQ: enabling enforcement also turns
/// `persisted_queries` on (a safelist *is* a persisted-query allowlist). Pure +
/// DOM-free so the invariant is unit-testable (re-exported for the tests).
pub fn set_enforce_safelist(g: &mut HandlerGraphqlConfig, on: bool) {
    g.enforce_safelist = on;
    if on {
        g.persisted_queries = true;
    }
}

/// Whether the site's handler import allowlist grants the guest `graphql`
/// capability (`graphql::run`). The edge guard / federation / data-connector all
/// run at the edge regardless, but a guest that calls `graphql::run` needs this —
/// so the panel surfaces a hint, not a hard lock, when it is absent.
fn graphql_import_allowed(cfg: &SiteConfig) -> bool {
    cfg.handlers
        .as_ref()
        .is_some_and(|h| h.allow_imports.iter().any(|i| i == "graphql"))
}

/// The per-site GraphQL edge query-guard + federation + data-connector posture
/// (`handlers.graphql`), its own top-level section. Presence (the `Option`) is
/// one toggle; the inner `enabled` is the master edge switch that actually serves
/// GraphQL at the route — the plan's two-toggle nuance, spelled out under the
/// presence checkbox. The dangerous production toggles (introspection ON,
/// GraphiQL ON) carry an inline warning and a modal confirm.
#[function_component(GraphqlPanel)]
fn graphql_panel(props: &PanelProps) -> Html {
    let update = make_update(&props.config);
    let import_ok = graphql_import_allowed(&props.config);
    let present = props
        .config
        .handlers
        .as_ref()
        .and_then(|h| h.graphql.clone());

    // Presence toggle: seed a default block / clear to `None`.
    let on_present = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                let h = c.handlers.get_or_insert_with(HandlersSiteConfig::default);
                h.graphql = v.then(HandlerGraphqlConfig::default);
            });
        })
    };

    html! {
        <Section title="GraphQL edge"
                 description="Serve GraphQL at this site: the query-guard, the federation gateway, and the SQL data connector.">
            <CheckField label="Configure the GraphQL edge (query-guard / federation / data connector)"
                        checked={present.is_some()} on_change={on_present} />
            <p class="text-xs text-slate-500">
                { "Serving is gated by two switches: this one configures the edge, and the \
                   \u{201c}GraphQL edge enabled\u{201d} switch below actually serves it. Both \
                   unchecked-here (absent) and \u{201c}configured but off\u{201d} serve nothing \
                   \u{2014} \u{201c}configured but off\u{201d} keeps the settings saved without serving." }
            </p>
            if let Some(g) = present {
                <div class="ml-6 mt-3 space-y-4 border-l border-slate-100 pl-4">
                    if !import_ok {
                        <p class="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
                            { "Note: " }
                            <code class="rounded bg-amber-100 px-1 py-0.5">{ "graphql" }</code>
                            { " is not in this site's allowed imports (Handlers section), so a guest \
                               handler cannot call graphql::run. The edge guard, federation, and data \
                               connector below still apply at the edge." }
                        </p>
                    }
                    <GraphqlGuard config={props.config.clone()} g={g.clone()} />
                    // Everything below is served ONLY while the edge is enabled; when it's off,
                    // dim + annotate so "Connector active" / "Federation gateway" / "GraphiQL is
                    // served" don't read as live. The controls stay editable (settings are saved).
                    <div class={if g.enabled { "space-y-4" } else { "space-y-4 opacity-60" }}>
                        if !g.enabled {
                            <p class="rounded-md bg-slate-100 px-3 py-2 text-xs text-slate-600">
                                { "The edge is off \u{2014} these settings are saved but inactive \
                                   until the edge is enabled above." }
                            </p>
                        }
                        // The data connector is a primary serving MODE, not fine-tuning —
                        // surfaced directly, not inside the Advanced disclosure.
                        <DataConnectorPanel config={props.config.clone()} />
                        <details class="rounded-md border border-slate-200 bg-slate-50 p-3">
                            <summary class="cursor-pointer text-sm font-medium text-slate-700">
                                { "Advanced: persisted queries, federation, GraphiQL, endpoint path" }
                            </summary>
                            <div class="mt-3 space-y-4">
                                <GraphqlPersisted config={props.config.clone()} g={g.clone()} />
                                <GraphqlFederation config={props.config.clone()} g={g.clone()} />
                                <GraphqlGraphiql config={props.config.clone()} g={g.clone()} />
                                <GraphqlEndpoint config={props.config.clone()} g={g.clone()} />
                            </div>
                        </details>
                    </div>
                </div>
            }
        </Section>
    }
}

/// Shared prop for the GraphQL sub-panels: the whole config handle (so each
/// mutates `handlers.graphql` in place through [`make_update`], never rebuilding
/// it) plus a snapshot of the current `graphql` block for rendering.
#[derive(Properties, PartialEq)]
struct GraphqlProps {
    config: UseStateHandle<SiteConfig>,
    g: HandlerGraphqlConfig,
}

/// Mutate `handlers.graphql` in place (a no-op if the block was cleared since).
fn with_graphql(update: &Update, f: impl Fn(&mut HandlerGraphqlConfig) + 'static) {
    update(&move |c: &mut SiteConfig| {
        if let Some(g) = c.handlers.as_mut().and_then(|h| h.graphql.as_mut()) {
            f(g);
        }
    });
}

/// Tier 2 (always visible): the query-guard limits + the introspection tri-state.
#[function_component(GraphqlGuard)]
fn graphql_guard(props: &GraphqlProps) -> Html {
    let update = make_update(&props.config);
    let g = &props.g;

    let on_active = {
        let update = update.clone();
        Callback::from(move |v: bool| with_graphql(&update, move |g| g.enabled = v))
    };
    let on_depth = {
        let update = update.clone();
        Callback::from(move |v: Option<u64>| {
            with_graphql(&update, move |g| g.max_depth = v.map(|n| n as u32))
        })
    };
    let on_complexity = {
        let update = update.clone();
        Callback::from(move |v: Option<u64>| {
            with_graphql(&update, move |g| g.max_complexity = v.map(|n| n as u32))
        })
    };
    let on_introspection = {
        let update = update.clone();
        Callback::from(move |v: Option<bool>| {
            // Turning introspection ON in production can leak a multi-tenant schema;
            // confirm the dangerous transition before applying it.
            if v == Some(true)
                && !gloo_dialogs::confirm(
                    "Allow schema introspection on this site's GraphQL endpoint? In a \
                     multi-tenant deployment this exposes the schema to every caller. Keep it \
                     off unless this endpoint is meant to be publicly explorable.",
                )
            {
                // The native radio already flipped to the new choice; force a re-render so it
                // reconciles back to the (unchanged) committed value instead of showing a state
                // the config doesn't hold. `use_state` always re-renders, and Yew re-applies the
                // radio's `checked` on every render — so a no-op config write reverts the control.
                update(&|_: &mut SiteConfig| {});
                return;
            }
            with_graphql(&update, move |g| g.introspection = v);
        })
    };

    html! {
        <div class="space-y-3">
            <CheckField
                label={if g.enabled {
                    "GraphQL edge enabled (serve GraphQL at this route)"
                } else {
                    "Configured but OFF — nothing is served at this route until enabled"
                }}
                checked={g.enabled} on_change={on_active} />
            <div class="grid gap-3 sm:grid-cols-2">
                <NumberField label="Max query depth" value={g.max_depth.map(u64::from)}
                             min={1} max={50} placeholder="server default"
                             hint="Deepest selection nesting (1–50). Blank = server default."
                             on_change={on_depth} />
                <NumberField label="Max complexity (field count)" value={g.max_complexity.map(u64::from)}
                             min={1} max={100000} placeholder="server default"
                             hint="Total selected fields (1–100000). Blank = server default."
                             on_change={on_complexity} />
            </div>
            <TriStateField label="Schema introspection" name="graphql-introspection"
                           value={g.introspection}
                           default_label="Server default (off under multi-tenant)"
                           on_label="Allowed" off_label="Blocked"
                           hint="Introspection lets a client read the schema. The default follows \
                                 the server's tenancy posture."
                           on_change={on_introspection} />
            if g.introspection == Some(true) {
                <p class="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
                    { "Introspection is forced ON — the schema is readable by any caller of this endpoint." }
                </p>
            }
        </div>
    }
}

/// Tier 3: automatic persisted queries + the stronger safelist enforcement.
#[function_component(GraphqlPersisted)]
fn graphql_persisted(props: &GraphqlProps) -> Html {
    let update = make_update(&props.config);
    let g = &props.g;

    let on_persisted = {
        let update = update.clone();
        Callback::from(move |v: bool| with_graphql(&update, move |g| g.persisted_queries = v))
    };
    let on_safelist = {
        let update = update.clone();
        Callback::from(move |v: bool| with_graphql(&update, move |g| set_enforce_safelist(g, v)))
    };

    // The APQ explanation is a persistent node tied to the APQ control by
    // `aria-describedby`, and a persistent polite live region announces the
    // implication when enforcement forces APQ on (otherwise the auto-check is silent).
    let apq_desc_id = "graphql-apq-desc";
    let implication = if g.enforce_safelist {
        "Safelist enforcement just turned Automatic persisted queries on; it stays on and locked while enforcement is active."
    } else {
        ""
    };
    html! {
        <div class="space-y-2">
            <h4 class="text-sm font-medium text-slate-600">{ "Persisted queries" }</h4>
            <CheckField label="Enforce the safelist (only pre-registered operations run)"
                        checked={g.enforce_safelist} on_change={on_safelist} />
            <CheckField label="Automatic persisted queries (clients may send a query hash)"
                        checked={g.persisted_queries} disabled={g.enforce_safelist}
                        describedby={Some(AttrValue::from(apq_desc_id))}
                        on_change={on_persisted} />
            <p id={apq_desc_id} class="text-xs text-slate-500">
                { "A safelist is a persisted-query allowlist, so enforcing it also enables APQ and \
                   locks it on. Disabling enforcement leaves APQ on (they are independent) — uncheck \
                   it here to turn it off. Register operations under the GraphQL section." }
            </p>
            <p role="status" aria-live="polite" class="text-xs text-slate-500">{ implication }</p>
        </div>
    }
}

/// Tier 3: federation gateway toggle + the per-site composition / edge-visibility lists.
#[function_component(GraphqlFederation)]
fn graphql_federation(props: &GraphqlProps) -> Html {
    let update = make_update(&props.config);
    let g = &props.g;

    let on_federated = {
        let update = update.clone();
        Callback::from(move |v: bool| with_graphql(&update, move |g| g.federated = v))
    };
    let on_subgraphs = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            with_graphql(&update, move |g| {
                // Blank ⇒ `None` (compose ALL registered subgraphs); a non-empty list is an
                // explicit include-set. The distinction is load-bearing — don't collapse to `[]`.
                g.subgraphs = if list.is_empty() {
                    None
                } else {
                    Some(list.clone())
                };
            });
        })
    };
    let on_hidden_ops = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            with_graphql(&update, move |g| g.edge_hidden_operations = list.clone());
        })
    };
    let on_hidden_subs = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            with_graphql(&update, move |g| g.edge_hidden_subgraphs = list.clone());
        })
    };

    html! {
        <div class="space-y-2">
            <CheckField label="Federation gateway (compose the project's subgraphs)"
                        checked={g.federated} on_change={on_federated} />
            if g.federated {
                <div class="ml-6 space-y-3 border-l border-slate-100 pl-4">
                    <TextAreaField label="Composed subgraphs (one per line; blank = all registered)"
                        value={lines_join(g.subgraphs.as_deref().unwrap_or_default())}
                        rows={2}
                        hint="An explicit include-set makes this site's supergraph a distinct subset."
                        on_change={on_subgraphs} />
                    <TextAreaField label="Hidden operations (qualified subgraph.rootField, one per line)"
                        value={lines_join(&g.edge_hidden_operations)} rows={2}
                        hint="Make these roots unreachable from the external edge (internal paths still reach them)."
                        on_change={on_hidden_ops} />
                    <TextAreaField label="Hidden subgraphs (one per line)"
                        value={lines_join(&g.edge_hidden_subgraphs)} rows={2}
                        hint="Hide every root field owned by these subgraphs from the external edge."
                        on_change={on_hidden_subs} />
                </div>
            }
        </div>
    }
}

/// Tier 3: the GraphiQL in-browser explorer (a dangerous-in-prod convenience).
#[function_component(GraphqlGraphiql)]
fn graphql_graphiql(props: &GraphqlProps) -> Html {
    let update = make_update(&props.config);
    let g = &props.g;

    let on_graphiql = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            if v && !gloo_dialogs::confirm(
                "Serve the GraphiQL explorer on this site? It is a browser IDE for the API — a \
                 developer convenience that should normally stay off in production.",
            ) {
                // The native checkbox already flipped on; force a re-render so Yew re-applies the
                // committed `checked` and the box visibly reverts (see on_introspection).
                update(&|_: &mut SiteConfig| {});
                return;
            }
            with_graphql(&update, move |g| g.graphiql = v);
        })
    };

    html! {
        <div class="space-y-1">
            <CheckField label="Serve the GraphiQL in-browser explorer"
                        checked={g.graphiql} on_change={on_graphiql} />
            if g.graphiql {
                <p class="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
                    { "GraphiQL is served — a browser GET to the endpoint returns the IDE. Pair with \
                       introspection for schema docs; keep both off in production." }
                </p>
            }
        </div>
    }
}

/// Tier 3: the GraphQL endpoint route pattern override.
#[function_component(GraphqlEndpoint)]
fn graphql_endpoint(props: &GraphqlProps) -> Html {
    let update = make_update(&props.config);
    let g = &props.g;

    let on_route = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let v = v.trim().to_string();
            with_graphql(&update, move |g| {
                g.route = if v.is_empty() { None } else { Some(v.clone()) };
            });
        })
    };

    html! {
        <TextField label="Endpoint path" value={g.route.clone().unwrap_or_default()}
                   placeholder="/graphql" mono=true
                   hint="Where the GraphQL edge engages. Blank = /graphql. Set this if your endpoint lives elsewhere."
                   on_change={on_route} />
    }
}

// ---- GraphQL data connector (handlers.graphql.data) -------------------------

/// Mutate `handlers.graphql.data` in place (no-op if cleared since).
fn with_data(update: &Update, f: impl Fn(&mut HandlerGraphqlDataConfig) + 'static) {
    update(&move |c: &mut SiteConfig| {
        if let Some(d) = c
            .handlers
            .as_mut()
            .and_then(|h| h.graphql.as_mut())
            .and_then(|g| g.data.as_mut())
        {
            f(d);
        }
    });
}

/// The deny-by-default GraphQL→SQL data connector (`handlers.graphql.data`). The
/// common fields (source / tables / columns / row filters) are typed; the two
/// deepest fields (per-table `resolvers`, connector `claims_from_token`) ship as
/// a validated JSON escape hatch, as the plan specifies for Phase 1.
#[function_component(DataConnectorPanel)]
fn data_connector_panel(props: &PanelProps) -> Html {
    let update = make_update(&props.config);
    let data = props
        .config
        .handlers
        .as_ref()
        .and_then(|h| h.graphql.as_ref())
        .and_then(|g| g.data.clone());

    let on_present = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            with_graphql(&update, move |g| {
                g.data = v.then(HandlerGraphqlDataConfig::default);
            });
        })
    };
    let on_enabled = {
        let update = update.clone();
        Callback::from(move |v: bool| with_data(&update, move |d| d.enabled = v))
    };
    let on_source = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let v = v.trim().to_string();
            with_data(&update, move |d| d.source = v.clone());
        })
    };
    let on_mutations = {
        let update = update.clone();
        Callback::from(move |v: bool| with_data(&update, move |d| d.mutations = v))
    };

    html! {
        <div class="space-y-2">
            <CheckField label="Serve GraphQL from a managed database (data connector)"
                        checked={data.is_some()} on_change={on_present} />
            if let Some(d) = data {
                <div class="ml-6 space-y-3 border-l border-slate-100 pl-4">
                    <CheckField
                        label={if d.enabled { "Connector active" } else { "Configured but paused" }}
                        checked={d.enabled} on_change={on_enabled} />
                    <TextField label="Source database" value={d.source.clone()}
                               placeholder="site default database" mono=true
                               hint="The managed SQL database to expose. Blank = the site's default."
                               on_change={on_source} />
                    <CheckField label="Allow mutations (insert / update / delete)"
                                checked={d.mutations} on_change={on_mutations} />
                    if d.mutations {
                        <p class="rounded-md bg-amber-50 px-3 py-2 text-xs text-amber-800">
                            { "Mutations are ON — the generated API can write to the database. Leave off for a read-only API." }
                        </p>
                    }
                    if d.enabled && d.tables.is_empty() {
                        <p class="rounded-md bg-slate-100 px-3 py-2 text-xs text-slate-600">
                            { "No tables exposed — the connector is deny-by-default, so nothing is queryable yet. Add a table below." }
                        </p>
                    }
                    <DataTables config={props.config.clone()} />
                    <ClaimsHatch config={props.config.clone()} />
                </div>
            }
        </div>
    }
}

/// The exposed-tables editor: add/remove a table (deny-by-default), and per table
/// edit its readable columns, row-filter terms, and (via a JSON hatch) resolvers.
#[function_component(DataTables)]
fn data_tables(props: &PanelProps) -> Html {
    let update = make_update(&props.config);
    let table_ref = use_node_ref();
    let tables: Vec<String> = props
        .config
        .handlers
        .as_ref()
        .and_then(|h| h.graphql.as_ref())
        .and_then(|g| g.data.as_ref())
        .map(|d| d.tables.keys().cloned().collect())
        .unwrap_or_default();

    let add = {
        let update = update.clone();
        let table_ref = table_ref.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let name = table_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                return;
            }
            with_data(&update, move |d| {
                d.tables
                    .entry(name.clone())
                    .or_insert_with(HandlerGraphqlTableConfig::default);
            });
            if let Some(el) = table_ref.cast::<HtmlInputElement>() {
                el.set_value("");
            }
        })
    };

    html! {
        <div>
            <h4 class="mb-2 text-sm font-medium text-slate-600">{ "Exposed tables" }</h4>
            if tables.is_empty() {
                <p class="text-sm text-slate-500">{ "None — add a table to expose it." }</p>
            } else {
                <div class="space-y-3">
                    { for tables.iter().map(|name| html! {
                        <DataTableRow key={name.clone()} config={props.config.clone()} table={name.clone()}
                                      focus_after_remove={table_ref.clone()} />
                    }) }
                </div>
            }
            <form onsubmit={add} class="mt-2 flex flex-wrap items-end gap-2">
                <input ref={table_ref} aria-label="New table name"
                       placeholder="table name" class={classes!("flex-1", INPUT)} />
                <button type="submit"
                        class="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium \
                               text-slate-700 hover:bg-slate-50 focus-visible:outline-none \
                               focus-visible:ring-2 focus-visible:ring-sky-600 focus-visible:ring-offset-2">
                    { "Add table" }
                </button>
            </form>
        </div>
    }
}

/// One exposed table's editor. `table` is the map key being edited.
#[derive(Properties, PartialEq)]
struct DataTableRowProps {
    config: UseStateHandle<SiteConfig>,
    table: String,
    /// The add-table input (owned by the parent list), focused after this row is
    /// removed so keyboard focus lands on a sensible neighbour, not nowhere.
    focus_after_remove: NodeRef,
}

/// Mutate one table's config in place (no-op if the table or connector was cleared since).
fn with_table(
    update: &Update,
    table: String,
    f: impl Fn(&mut HandlerGraphqlTableConfig) + 'static,
) {
    update(&move |c: &mut SiteConfig| {
        if let Some(t) = c
            .handlers
            .as_mut()
            .and_then(|h| h.graphql.as_mut())
            .and_then(|g| g.data.as_mut())
            .and_then(|d| d.tables.get_mut(&table))
        {
            f(t);
        }
    });
}

#[function_component(DataTableRow)]
fn data_table_row(props: &DataTableRowProps) -> Html {
    let update = make_update(&props.config);
    let table = props.table.clone();
    let cfg = props
        .config
        .handlers
        .as_ref()
        .and_then(|h| h.graphql.as_ref())
        .and_then(|g| g.data.as_ref())
        .and_then(|d| d.tables.get(&table))
        .cloned()
        .unwrap_or_default();

    let col_ref = use_node_ref();
    let claim_ref = use_node_ref();

    let on_columns = {
        let update = update.clone();
        let table = table.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            with_table(&update, table.clone(), move |t| t.columns = list.clone());
        })
    };
    let remove_table = {
        let update = update.clone();
        let table = table.clone();
        let focus_ref = props.focus_after_remove.clone();
        Callback::from(move |_: MouseEvent| {
            let table = table.clone();
            with_data(&update, move |d| {
                d.tables.remove(&table);
            });
            // This row is about to unmount — move focus to the add-table input so it
            // doesn't fall back to the document body.
            if let Some(el) = focus_ref.cast::<HtmlInputElement>() {
                let _ = el.focus();
            }
        })
    };
    let add_filter = {
        let update = update.clone();
        let table = table.clone();
        let col_ref = col_ref.clone();
        let claim_ref = claim_ref.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let column = col_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            let claim = claim_ref
                .cast::<HtmlInputElement>()
                .map(|el| el.value().trim().to_string())
                .unwrap_or_default();
            if column.is_empty() || claim.is_empty() {
                return;
            }
            let table = table.clone();
            with_table(&update, table, move |t| {
                t.row_filter.push(HandlerGraphqlRowTerm {
                    column: column.clone(),
                    claim: claim.clone(),
                });
            });
            if let Some(el) = col_ref.cast::<HtmlInputElement>() {
                el.set_value("");
            }
            if let Some(el) = claim_ref.cast::<HtmlInputElement>() {
                el.set_value("");
            }
        })
    };

    html! {
        <div class="rounded-md border border-slate-200 bg-white p-3">
            <div class="mb-2 flex items-center justify-between">
                <span class="font-mono text-sm font-medium text-slate-800">{ &props.table }</span>
                <Button variant={BtnVariant::DangerSubtle} label="Remove table"
                        aria_label={AttrValue::from(format!("Remove table {}", props.table))}
                        onclick={remove_table} />
            </div>
            <TextAreaField label="Readable columns (one per line; deny-by-default)"
                value={lines_join(&cfg.columns)} rows={3}
                hint="Only these columns are visible. A column absent here is invisible to the API."
                on_change={on_columns} />
            <div class="mt-3">
                <h4 class="mb-1 text-sm font-medium text-slate-600">{ "Row filters (tenant isolation)" }</h4>
                if cfg.row_filter.is_empty() {
                    <p class="text-xs text-slate-500">{ "No row filters — every row is visible (subject to the host project scope)." }</p>
                } else {
                    <ul class="divide-y divide-slate-100">
                        { for cfg.row_filter.iter().enumerate().map(|(i, term)| {
                            let remove = {
                                let update = update.clone();
                                let table = table.clone();
                                let col_ref = col_ref.clone();
                                Callback::from(move |_: MouseEvent| {
                                    let table = table.clone();
                                    with_table(&update, table, move |t| {
                                        if i < t.row_filter.len() { t.row_filter.remove(i); }
                                    });
                                    // The removed row's button unmounts — move focus to the
                                    // add-filter column input (a sensible, persistent neighbour).
                                    if let Some(el) = col_ref.cast::<HtmlInputElement>() {
                                        let _ = el.focus();
                                    }
                                })
                            };
                            let aria = AttrValue::from(format!(
                                "Remove row filter {} = claim({})", term.column, term.claim
                            ));
                            html! {
                                <li class="flex items-center justify-between py-1.5 text-sm">
                                    <span class="font-mono text-slate-700">
                                        { format!("{} = claim({})", term.column, term.claim) }
                                    </span>
                                    <button onclick={remove} aria-label={aria}
                                            class="text-xs font-medium text-rose-700 hover:underline \
                                                   focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-600">
                                        { "Remove" }
                                    </button>
                                </li>
                            }
                        }) }
                    </ul>
                }
                <form onsubmit={add_filter} class="mt-2 flex flex-wrap items-end gap-2">
                    <input ref={col_ref} aria-label="Filter column" placeholder="column"
                           class={classes!("flex-1", INPUT)} />
                    <input ref={claim_ref} aria-label="Token claim" placeholder="claim (e.g. project, tid)"
                           class={classes!("flex-1", INPUT)} />
                    <button type="submit"
                            class="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium \
                                   text-slate-700 hover:bg-slate-50 focus-visible:outline-none \
                                   focus-visible:ring-2 focus-visible:ring-sky-600 focus-visible:ring-offset-2">
                        { "Add filter" }
                    </button>
                </form>
            </div>
        </div>
    }
}

/// The connector `claims_from_token` JSON escape hatch: a draft textarea that is
/// parsed and validated as `HandlerGraphqlTokenClaims` only on Apply, so a
/// half-typed value never corrupts the config. Blank ⇒ clears the field.
#[function_component(ClaimsHatch)]
fn claims_hatch(props: &PanelProps) -> Html {
    let update = make_update(&props.config);
    let current = props
        .config
        .handlers
        .as_ref()
        .and_then(|h| h.graphql.as_ref())
        .and_then(|g| g.data.as_ref())
        .and_then(|d| d.claims_from_token.clone());

    // The pretty-printed current value seeds the draft; edits are local until Apply.
    let seed = current
        .as_ref()
        .and_then(|c| serde_json::to_string_pretty(c).ok())
        .unwrap_or_default();
    let draft = use_state(|| seed.clone());
    let error = use_state(|| Option::<String>::None);
    let err_id = "claims-from-token-error";

    let on_input = {
        let draft = draft.clone();
        Callback::from(move |v: String| draft.set(v))
    };
    let apply = {
        let update = update.clone();
        let draft = draft.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let text = draft.trim().to_string();
            if text.is_empty() {
                with_data(&update, move |d| d.claims_from_token = None);
                // Normalise the draft so the "unapplied edits" signal clears.
                draft.set(String::new());
                error.set(None);
                return;
            }
            match serde_json::from_str::<boatramp_types::config::HandlerGraphqlTokenClaims>(&text) {
                Ok(parsed) => {
                    // Re-seed the draft with the canonical pretty form that was just committed, so
                    // draft == committed and the pending signal clears (a later edit re-raises it).
                    let pretty =
                        serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| text.clone());
                    with_data(&update, move |d| d.claims_from_token = Some(parsed.clone()));
                    draft.set(pretty);
                    error.set(None);
                }
                Err(e) => error.set(Some(format!("Invalid JSON: {e}"))),
            }
        })
    };

    // Draft edits only reach the config on Apply, but global dirty tracking compares
    // config vs. baseline — so an unapplied draft shows no unsaved signal and a global
    // Save would persist WITHOUT it. Surface that gap explicitly.
    let pending = (*draft).trim() != seed.trim();

    html! {
        <div>
            <TextAreaField label="claims_from_token (JSON — advanced)"
                value={(*draft).clone()} rows={5}
                invalid={error.is_some()}
                describedby={error.is_some().then(|| AttrValue::from(err_id))}
                hint="Bind row-filter claims from a verified app token (issuer + JWKS). Blank clears it. A bad/absent token denies — never widens."
                on_change={on_input} />
            if let Some(msg) = &*error {
                <p id={err_id} role="alert" class="mt-1 text-xs text-rose-700">{ msg }</p>
            }
            <div class="mt-2 flex flex-wrap items-center gap-3">
                <Button variant={if pending { BtnVariant::Primary } else { BtnVariant::Secondary }}
                        label="Apply claims" onclick={apply} />
                if pending && error.is_none() {
                    <span role="status" aria-live="polite" class="text-xs font-medium text-amber-700">
                        { "Unapplied edits — click Apply (a global Save won't include them)." }
                    </span>
                }
            </div>
        </div>
    }
}

// ---- Cookie session auth (handlers.cookie_auth) -----------------------------

/// The browser cookie-session auth block (`handlers.cookie_auth`). boatramp only
/// *reads* the named cookie as the bearer when no `Authorization` header is
/// present; the empty `allowed_origins` default (same-origin only) is framed
/// positively as the common, safe case.
#[function_component(CookieAuthPanel)]
fn cookie_auth_panel(props: &PanelProps) -> Html {
    let update = make_update(&props.config);
    let ca = props
        .config
        .handlers
        .as_ref()
        .and_then(|h| h.cookie_auth.clone());

    let on_present = {
        let update = update.clone();
        Callback::from(move |v: bool| {
            update(&move |c: &mut SiteConfig| {
                let h = c.handlers.get_or_insert_with(HandlersSiteConfig::default);
                h.cookie_auth = v.then(CookieAuthConfig::default);
            });
        })
    };
    let on_name = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let v = v.trim().to_string();
            update(&move |c: &mut SiteConfig| {
                if let Some(ca) = c.handlers.as_mut().and_then(|h| h.cookie_auth.as_mut()) {
                    ca.cookie_name = v.clone();
                }
            });
        })
    };
    let on_origins = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let list = lines_split(&v);
            update(&move |c: &mut SiteConfig| {
                if let Some(ca) = c.handlers.as_mut().and_then(|h| h.cookie_auth.as_mut()) {
                    ca.allowed_origins = list.clone();
                }
            });
        })
    };

    html! {
        <Section title="Cookie session auth"
                 description="Let a browser session cookie stand in as the app bearer when a request carries no Authorization header.">
            <CheckField label="Enable browser cookie session auth" checked={ca.is_some()}
                        on_change={on_present} />
            if let Some(ca) = ca {
                <div class="ml-6 mt-3 space-y-3 border-l border-slate-100 pl-4">
                    <TextField label="Cookie name" value={ca.cookie_name.clone()} mono=true
                               placeholder="__Host-session"
                               hint="The cookie whose value is the app bearer. Set it HttpOnly; Secure; SameSite=Lax with a __Host- prefix."
                               on_change={on_name} />
                    <TextAreaField label="Additional allowed origins (one per line)"
                        value={lines_join(&ca.allowed_origins)} rows={2}
                        hint="Cross-origin apps allowed to call this API (scheme+host[+port], e.g. https://app.example.com). Empty = same-origin only — the common case."
                        on_change={on_origins} />
                </div>
            }
        </Section>
    }
}

#[function_component(CompressionPanel)]
fn compression_panel(props: &PanelProps) -> Html {
    let cfg = &*props.config;
    let update = make_update(&props.config);

    let on_toggle = {
        let update = update.clone();
        Callback::from(move |v: bool| update(&move |c: &mut SiteConfig| c.compression.enabled = v))
    };
    let on_min = {
        let update = update.clone();
        Callback::from(move |v: String| {
            let n = v.trim().parse::<u64>().unwrap_or(0);
            update(&move |c: &mut SiteConfig| c.compression.min_size = n);
        })
    };

    html! {
        <Section title="Compression">
            <CheckField label="On-the-fly response compression" checked={cfg.compression.enabled}
                        on_change={on_toggle} />
            if cfg.compression.enabled {
                <div class="ml-6 border-l border-slate-100 pl-4">
                    <TextField label="Minimum size (bytes)" value={cfg.compression.min_size.to_string()}
                               hint="Don't compress responses smaller than this." on_change={on_min} />
                </div>
            }
        </Section>
    }
}
