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

use boatramp_types::access::{hash_password, BasicAuth, RateLimit};
use boatramp_types::config::{Hsts, SiteConfig};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::auth::use_session;
use crate::hooks::{use_api, Fetch};
use crate::verify::DomainVerifications;
use crate::widgets::{
    CheckField, ErrorBanner, Pill, Section, Spinner, TextAreaField, TextField, Tone,
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
    // Save status: idle / saving / saved / error.
    let status = use_state(|| SaveStatus::Idle);

    let save = {
        let session = session.clone();
        let site = site.clone();
        let config = config.clone();
        let status = status.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let site = site.clone();
            let body = (*config).clone();
            let status = status.clone();
            status.set(SaveStatus::Saving);
            spawn_local(async move {
                match client
                    .put_json(&format!("/api/sites/{site}/config"), &body)
                    .await
                {
                    Ok(()) => status.set(SaveStatus::Saved),
                    Err(err) if err.is_unauthorized() => session.sign_out(),
                    Err(err) => status.set(SaveStatus::Error(err.to_string())),
                }
            });
        })
    };

    html! {
        <div class="space-y-6">
            <DomainsPanel config={config.clone()} />
            <SecurityPanel config={config.clone()} />
            <AccessPanel config={config.clone()} />
            <WafPanel config={config.clone()} />
            <CompressionPanel config={config.clone()} />
            <DomainVerifications site={site.clone()} />

            <div class="sticky bottom-4 flex items-center justify-end gap-3 rounded-xl border \
                        border-slate-200 bg-white/90 p-4 shadow backdrop-blur">
                { save_status_view(&status) }
                <button onclick={save} disabled={matches!(&*status, SaveStatus::Saving)}
                        class="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white \
                               hover:bg-sky-700 disabled:opacity-50">
                    { "Save config" }
                </button>
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

fn save_status_view(status: &SaveStatus) -> Html {
    match status {
        SaveStatus::Idle => Html::default(),
        SaveStatus::Saving => html! { <span class="text-sm text-slate-500">{ "Saving…" }</span> },
        SaveStatus::Saved => html! { <Pill text="saved" tone={Tone::Good} /> },
        SaveStatus::Error(msg) => html! {
            <span class="text-sm text-rose-600" title={msg.clone()}>{ "Save failed" }</span>
        },
    }
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
        Callback::from(move |v: bool| update(&move |c: &mut SiteConfig| c.security.https_redirect = v))
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
                <p class="text-sm text-slate-400">{ "No users — anyone is prompted but none can pass." }</p>
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
                                        class="text-xs font-medium text-rose-600 hover:underline">
                                    { "Remove" }
                                </button>
                            </li>
                        }
                    }) }
                </ul>
            }
            <form onsubmit={add} class="mt-2 flex flex-wrap items-end gap-2">
                <input ref={user_ref} placeholder="username"
                       class="rounded-md border border-slate-300 px-2.5 py-1.5 text-sm" />
                <input ref={pass_ref} type="password" placeholder="password" autocomplete="new-password"
                       class="rounded-md border border-slate-300 px-2.5 py-1.5 text-sm" />
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
        Callback::from(move |v: bool| update(&move |c: &mut SiteConfig| c.access.waf.user_agent.enabled = v))
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
        Callback::from(move |v: bool| update(&move |c: &mut SiteConfig| c.access.waf.anomaly.enabled = v))
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
        Callback::from(move |v: bool| update(&move |c: &mut SiteConfig| c.access.waf.anomaly.score_empty_user_agent = v))
    };
    let on_missing_accept = {
        let update = update.clone();
        Callback::from(move |v: bool| update(&move |c: &mut SiteConfig| c.access.waf.anomaly.score_missing_accept = v))
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
