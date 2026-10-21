//! The overlay **flow-policy editor + explain/dry-run view** (overlay per-flow access-policy
//! increment-2, Stage B) — the `System·Admin`-gated console surface over `GET`/`PUT
//! /api/overlay/policy` and `POST /api/overlay/policy/test` (inc1 + Stage A).
//!
//! This is a **thin client**: it never decides authorization itself — a `403` is always the
//! server's call ([`forbidden_note`]), and a policy is never treated as valid until the server's
//! `PUT` compiles it (REQUIRED #5). The one thing it DOES decide client-side is whether to show
//! the default-deny **cliff** warning before issuing a `PUT` ([`needs_cliff_confirm`]) — a pure,
//! unit-tested mirror of the server's own `was_off` check (`put_overlay_policy` in
//! `boatramp-server/src/control_api.rs`), so the warning fires in exactly the cases the server's
//! one-time `warning` response field would.
//!
//! # States
//! - **Loading** — the initial `GET`.
//! - **Forbidden** — the token lacks `System·Admin` (the `GET`/`test` surfaces are a
//!   policy-enumeration oracle, so they sit at the same tier as the `PUT`, REQUIRED #6).
//! - **Empty** (the gate is OFF) — `GET` returned an empty/whitespace body: every dial/expose
//!   mint is currently allowed, ungated.
//! - **Present** — a policy is stored and compiles.
//! - **Corrupt** — the stored bytes do NOT compile. Detected indirectly: a `GET` alone can't
//!   distinguish "a policy that denies everything" from "garbled Cedar text" (both are just
//!   bytes), so on load we additionally fire a harmless `POST /policy/test` probe against the
//!   STORED policy (no inline `policy` override) and read its `note` — the server sets `note` to
//!   name the stored policy corrupt ONLY on that fail-closed branch, and leaves it `None` for any
//!   policy that actually compiles (whatever it then decides). This is a LIVE OUTAGE, not an edit
//!   error: the gate is failing closed (deny-all) for every mint, right now, independent of this
//!   editor.
//!
//! # The default-deny cliff
//! Storing a FIRST policy (nothing was stored before) flips the mint gate from OFF (allow-all) to
//! default-deny (every dial/expose NOT matched by a `permit` is denied) — the single most
//! consequential edit this surface can make. [`needs_cliff_confirm`] detects that exact
//! absent→present transition client-side, BEFORE issuing the `PUT`, and the editor blocks on an
//! inline preview (never a bare `confirm()` — the preview embeds a live [`DryRunPanel`] against
//! the draft so the operator can run their own identity/flow and see it still works before
//! committing). The server's one-time `warning` (present only on the PUT that actually performs
//! this transition) is then kept as a persistent post-save banner.
//!
//! # ETag / `If-Match`
//! `GET`'s `ETag` is held and echoed back as the next `PUT`'s `If-Match` (ETag → If-Match), so two
//! concurrent editors racing a write get a `409` (surfaced inline, verbatim) rather than a lost
//! write — never a blind clobber.

use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlSelectElement;
use yew::prelude::*;

use crate::api::{ApiError, ApiResult};
use crate::auth::use_session;
use crate::widgets::{
    BtnVariant, Button, CheckField, ErrorBanner, Pill, SELECT, Section, Spinner, TextAreaField,
    TextField, Tone,
};

/// `GET`/`PUT /api/overlay/policy` — the stored Cedar text + optimistic-concurrency version.
pub const POLICY_PATH: &str = "/api/overlay/policy";
/// `POST /api/overlay/policy/test` — the dry-run (no mint).
pub const TEST_PATH: &str = "/api/overlay/policy/test";

// ===========================================================================
// Wire-type mirrors (console-side; see `store_migration.rs`'s header for why these are hand
// mirrored rather than shared — `boatramp-server`'s request/response shapes are private to that
// crate, and the console cannot depend on `boatramp-core` (wasm32-only, see Cargo.toml)).
// ===========================================================================

/// `PUT /api/overlay/policy` response (mirrors the server's `OverlayPolicyPutResponse`).
#[derive(Clone, PartialEq, Deserialize)]
struct PutResponse {
    #[serde(default)]
    warning: Option<String>,
}

/// `POST /api/overlay/policy/test` request (mirrors the server's `OverlayPolicyTestRequest`).
/// `policy: Some(text)` previews `text` inline (pre-store); `None` evaluates the STORED policy.
#[derive(Clone, PartialEq, Serialize, Default)]
pub struct TestRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    pub action: String,
    pub service: String,
    pub holder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrolled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requestor: Option<String>,
    /// The serving node's overlay identity to preview a node-scoped rule against (Stage A).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub ttl_requested: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<u64>,
}

/// `POST /api/overlay/policy/test` response (mirrors the server's `OverlayPolicyTestResponse`).
/// This is the ONLY surface (System·Admin authoring oracle) that exposes `deciding_policies` /
/// `diagnostics` at all — the live mint's `403` never does.
#[derive(Clone, PartialEq, Deserialize)]
pub struct FlowPolicyTestResponse {
    /// `"allow"` or `"deny"`.
    pub decision: String,
    #[serde(default)]
    pub ttl_ceiling: Option<u64>,
    #[serde(default)]
    pub deciding_policies: Vec<String>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    /// A human note about the policy posture (feature off / corrupt), when relevant.
    #[serde(default)]
    pub note: Option<String>,
}

// ===========================================================================
// Pure decision/shaping helpers — kept out of the `html!` bodies so the invariants that matter
// (the cliff fires on exactly one transition; diagnostics are never silently dropped) are
// unit-testable without mounting the component. The component calls these SAME functions, so a
// regression here is a regression in the real render path, not a parallel reimplementation.
// ===========================================================================

/// Whether storing a non-empty draft now would flip the mint gate from OFF (nothing stored —
/// every dial/expose is allowed ungated) to default-deny — the absent→present transition, and
/// ONLY that transition. Editing an already-present policy (`stored_is_off = false`) is an
/// ordinary edit regardless of the draft; clearing a draft back to empty (`draft_is_off = true`)
/// turns the gate OFF, the opposite direction — neither is a cliff. Mirrors the server's own
/// `was_off` check in `put_overlay_policy` (`boatramp-server/src/control_api.rs`), so this
/// client-side warning fires in exactly the cases the server's one-time `warning` would.
pub fn needs_cliff_confirm(stored_is_off: bool, draft_is_off: bool) -> bool {
    stored_is_off && !draft_is_off
}

/// The diagnostic lines for a dry-run result. Trivial, but pulling it out of the `html!` body
/// makes the "diagnostics must actually reach the render" invariant directly testable.
pub fn explain_diagnostics(resp: &FlowPolicyTestResponse) -> &[String] {
    &resp.diagnostics
}

/// Whether a `/policy/test` `note` names the STORED policy corrupt (as opposed to the other
/// `note`-carrying case, the feature being off, or no note at all for a policy that compiles).
/// String-matched because the server's `note` is a human message, not a structured enum — this is
/// the only signal GET→probe gives us.
fn note_says_corrupt(note: Option<&str>) -> bool {
    note.is_some_and(|n| n.contains("corrupt"))
}

// ===========================================================================
// Load state
// ===========================================================================

/// The policy as last confirmed from the server, classified into the four-state posture.
#[derive(Clone, PartialEq)]
enum Loaded {
    /// Nothing stored — the mint gate is OFF.
    Empty { etag: Option<String> },
    /// A policy is stored and compiles.
    Present {
        etag: Option<String>,
        stored: String,
    },
    /// The stored bytes do NOT compile — live outage, failing closed (deny-all).
    Corrupt {
        etag: Option<String>,
        stored: String,
    },
}

#[derive(Clone, PartialEq)]
enum LoadState {
    Loading,
    Forbidden,
    Loaded(Loaded),
    Error(ApiError),
}

/// A harmless `/policy/test` probe used ONLY to read the STORED policy's `note` (no inline
/// `policy` override) — the decision/deciding_policies/diagnostics it returns are irrelevant here,
/// just whether `note` names it corrupt. The placeholder service/holder match nothing real.
fn corruption_probe() -> TestRequest {
    TestRequest {
        action: "dial".to_string(),
        service: "__policy_corruption_probe__".to_string(),
        holder: "__policy_corruption_probe__".to_string(),
        ttl_requested: 1,
        ..Default::default()
    }
}

/// The overlay flow-policy editor + explain page. `System·Admin`-gated; a `403` renders the calm
/// [`forbidden_note`] (never a client-side authz decision — the server's `403` is the only call).
#[function_component(OverlayPolicy)]
pub fn overlay_policy() -> Html {
    let session = use_session();
    let state = use_state(|| LoadState::Loading);
    // Bump to re-fetch (initial load, Retry, and after a successful PUT — so the posture and the
    // held `ETag` both come from a fresh GET rather than being hand-advanced client-side).
    let tick = use_state(|| 0u32);

    {
        let state = state.clone();
        let session = session.clone();
        let tick_val = *tick;
        use_effect_with(tick_val, move |_| {
            state.set(LoadState::Loading);
            let client = session.client();
            let session = session.clone();
            let state = state.clone();
            spawn_local(async move {
                match client.get_text_with_etag(POLICY_PATH).await {
                    Ok((body, etag)) => {
                        if body.trim().is_empty() {
                            state.set(LoadState::Loaded(Loaded::Empty { etag }));
                            return;
                        }
                        match client
                            .post_json_detailed::<TestRequest, FlowPolicyTestResponse>(
                                TEST_PATH,
                                &corruption_probe(),
                            )
                            .await
                        {
                            Ok(resp) if note_says_corrupt(resp.note.as_deref()) => {
                                state
                                    .set(LoadState::Loaded(Loaded::Corrupt { etag, stored: body }));
                            }
                            Ok(_) => {
                                state
                                    .set(LoadState::Loaded(Loaded::Present { etag, stored: body }));
                            }
                            Err(ApiError::Unauthorized) => session.sign_out(),
                            Err(err) => state.set(LoadState::Error(err)),
                        }
                    }
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    Err(ApiError::Forbidden) => state.set(LoadState::Forbidden),
                    Err(err) => state.set(LoadState::Error(err)),
                }
            });
            || ()
        });
    }

    let reload = {
        let tick = tick.clone();
        Callback::from(move |()| tick.set(*tick + 1))
    };

    match &*state {
        LoadState::Loading => html! { <Spinner label="Loading overlay flow policy…" /> },
        LoadState::Forbidden => forbidden_note(),
        LoadState::Error(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(reload.clone())} />
        },
        LoadState::Loaded(loaded) => html! {
            <PolicyEditor key={(*tick).to_string()} loaded={loaded.clone()} on_saved={reload.clone()} />
        },
    }
}

/// Shown when the token is valid but lacks `System·Admin`.
fn forbidden_note() -> Html {
    html! {
        <div role="status" aria-live="polite" class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
            <p class="text-sm font-medium text-amber-800">
                { "You need node-admin to view or edit the overlay flow policy." }
            </p>
            <p class="mt-1 text-sm text-amber-700">
                { "Your token is valid but lacks " }
                <code class="rounded bg-amber-100 px-1 py-0.5 text-xs">{ "System·Admin" }</code>
                { ". The GET/test surfaces here are a policy-enumeration oracle, so they sit at \
                   the same tier as editing the gate, not a lesser overlay role." }
            </p>
        </div>
    }
}

// ===========================================================================
// The editor (remounted via `key` after every reload, so its draft/save state always starts
// fresh from the latest server-confirmed posture — the same convention `config_editor.rs` uses).
// ===========================================================================

#[derive(Properties, PartialEq)]
struct PolicyEditorProps {
    loaded: Loaded,
    /// Re-fetch the outer posture (after a successful PUT) — a fresh GET re-derives
    /// Empty/Present/Corrupt and hands back the new `ETag`, rather than hand-advancing either
    /// client-side.
    on_saved: Callback<()>,
}

/// The save-in-flight / result indicator (mirrors `config_editor.rs`'s `SaveStatus`).
#[derive(Clone, PartialEq)]
enum SaveStatus {
    Idle,
    Saving,
    Saved,
    Error(String),
}

#[function_component(PolicyEditor)]
fn policy_editor(props: &PolicyEditorProps) -> Html {
    let session = use_session();

    let (etag, stored, corrupt) = match &props.loaded {
        Loaded::Empty { etag } => (etag.clone(), String::new(), false),
        Loaded::Present { etag, stored } => (etag.clone(), stored.clone(), false),
        Loaded::Corrupt { etag, stored } => (etag.clone(), stored.clone(), true),
    };
    let stored_is_off = matches!(&props.loaded, Loaded::Empty { .. });

    let draft = use_state(|| stored.clone());
    let status = use_state(|| SaveStatus::Idle);
    // The server's one-time cliff warning — once shown, kept for the rest of this mount (a
    // "persistent post-save banner", not a toast that disappears on the next render).
    let warning = use_state(|| Option::<String>::None);
    // The blocking cliff-confirm panel (absent→present transition only; see `needs_cliff_confirm`).
    let pending_cliff = use_state(|| false);

    let dirty = *draft != stored;

    // The actual PUT, shared by the normal Save path and the cliff-confirm's "Store it" button —
    // the cliff panel never issues a DIFFERENT write than Save would have, it only gates when.
    let do_put = {
        let session = session.clone();
        let draft = draft.clone();
        let status = status.clone();
        let warning = warning.clone();
        let pending_cliff = pending_cliff.clone();
        let on_saved = props.on_saved.clone();
        let etag = etag.clone();
        Callback::from(move |()| {
            let client = session.client();
            let session = session.clone();
            let body = (*draft).clone();
            let status = status.clone();
            let warning = warning.clone();
            let pending_cliff = pending_cliff.clone();
            let on_saved = on_saved.clone();
            let if_match = etag.clone();
            status.set(SaveStatus::Saving);
            spawn_local(async move {
                let outcome = client
                    .put_text_if_match::<PutResponse>(POLICY_PATH, &body, if_match.as_deref())
                    .await;
                match outcome {
                    Ok(resp) => {
                        if let Some(w) = resp.warning {
                            warning.set(Some(w));
                        }
                        status.set(SaveStatus::Saved);
                        pending_cliff.set(false);
                        on_saved.emit(());
                    }
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    Err(err) => {
                        // Surfaced verbatim (400 Cedar compile error / 409 conflict) — see
                        // `ApiClient::put_text_if_match`'s doc comment.
                        status.set(SaveStatus::Error(err.to_string()));
                        pending_cliff.set(false);
                    }
                }
            });
        })
    };

    let on_save_click = {
        let draft = draft.clone();
        let pending_cliff = pending_cliff.clone();
        let do_put = do_put.clone();
        Callback::from(move |_: MouseEvent| {
            let draft_is_off = draft.trim().is_empty();
            if needs_cliff_confirm(stored_is_off, draft_is_off) {
                pending_cliff.set(true);
            } else {
                do_put.emit(());
            }
        })
    };

    let on_draft_change = {
        let draft = draft.clone();
        Callback::from(move |v: String| draft.set(v))
    };

    let on_cancel_cliff = {
        let pending_cliff = pending_cliff.clone();
        Callback::from(move |_: MouseEvent| pending_cliff.set(false))
    };
    let on_confirm_cliff = {
        let do_put = do_put.clone();
        Callback::from(move |_: MouseEvent| do_put.emit(()))
    };

    html! {
        <Section title="Overlay flow policy"
                 description="Operator-authored Cedar policy gating the overlay dial/publish-cap \
                              mint — deny-or-shrink-TTL only; it can never widen what RBAC already \
                              permitted.">
            if corrupt {
                { corrupt_banner() }
            }
            if let Some(w) = &*warning {
                { warning_banner(w) }
            }
            if stored_is_off && !corrupt {
                { off_banner() }
            }

            <TextAreaField label="Policy (Cedar text)" value={(*draft).clone()} rows={16}
                           hint="Empty turns the mint gate OFF (every dial/expose allowed ungated)."
                           on_change={on_draft_change} />

            if let SaveStatus::Error(msg) = &*status {
                <div role="alert" class="rounded-md border border-rose-200 bg-rose-50 px-3 py-2">
                    <p class="text-sm text-rose-700 whitespace-pre-wrap">{ msg }</p>
                </div>
            }

            if *pending_cliff {
                { cliff_preview(&draft, &on_confirm_cliff, &on_cancel_cliff) }
            }

            <div class="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
                { save_bar_status(&status, dirty) }
                <Button variant={BtnVariant::Primary} busy={matches!(&*status, SaveStatus::Saving)}
                        busy_label="Saving…" disabled={!dirty || *pending_cliff}
                        label="Save policy" onclick={on_save_click} />
            </div>

            <div class="border-t border-slate-100 pt-4">
                <h4 class="mb-2 text-sm font-medium text-slate-600">
                    { "Validate / dry-run the draft" }
                </h4>
                <p class="mb-2 text-xs text-slate-500">
                    { "Shares one path with Save: the server compiles the draft the same way \
                       either button sends it, so a 400 here is the same error Save would hit." }
                </p>
                <DryRunPanel policy_override={Some((*draft).clone())} />
            </div>

            <div class="border-t border-slate-100 pt-4">
                <h4 class="mb-2 text-sm font-medium text-slate-600">
                    { "Explain — what the STORED (live) policy currently decides" }
                </h4>
                <DryRunPanel policy_override={Option::<String>::None} />
            </div>
        </Section>
    }
}

/// A live outage banner — the stored policy fails to compile, so the gate is failing closed
/// (deny-all) for every mint right now, independent of anything done in this editor.
fn corrupt_banner() -> Html {
    html! {
        <div role="alert" class="rounded-lg border-2 border-rose-400 bg-rose-50 px-4 py-3">
            <p class="text-sm font-bold text-rose-900">
                { "LIVE OUTAGE — the stored overlay flow policy is CORRUPT. The live gate is \
                   failing closed: every dial/expose mint is being DENIED right now, not just \
                   edits made here. Fix and store a valid policy below to restore minting." }
            </p>
        </div>
    }
}

/// The server's one-time CLIFF warning (present only on the PUT that stored the first policy),
/// kept visible for the rest of this mount rather than a transient toast.
fn warning_banner(msg: &str) -> Html {
    html! {
        <div role="alert" class="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3">
            <p class="text-sm text-amber-800 whitespace-pre-wrap">{ msg }</p>
        </div>
    }
}

/// Nothing is stored — the mint gate is OFF, every dial/expose is allowed ungated.
fn off_banner() -> Html {
    html! {
        <div role="status" class="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
            <p class="text-sm font-medium text-slate-700">
                { "No flow policy is stored — the mint gate is OFF: every dial/expose is \
                   currently allowed, ungated." }
            </p>
        </div>
    }
}

/// The blocking cliff-confirm preview (absent→present only; see `needs_cliff_confirm`). Embeds a
/// live [`DryRunPanel`] against the draft so the operator sees their own access BEFORE
/// committing, rather than a bare `confirm()` dialog.
fn cliff_preview(
    draft: &UseStateHandle<String>,
    on_confirm: &Callback<MouseEvent>,
    on_cancel: &Callback<MouseEvent>,
) -> Html {
    html! {
        <div role="alertdialog" aria-label="Confirm storing the first overlay flow policy"
             class="space-y-3 rounded-lg border-2 border-amber-300 bg-amber-50 p-4">
            <p class="text-sm font-semibold text-amber-900">
                { "Storing this policy flips the overlay mint gate from OFF (every dial/expose \
                   currently allowed) to DEFAULT-DENY: from the moment it is stored, every \
                   dial/expose NOT matched by a `permit` in this policy is denied." }
            </p>
            <p class="text-sm text-amber-800">
                { "Preview your own access under the draft before committing — fill in a flow \
                   you expect to still work (e.g. your own holder key) and run it below." }
            </p>
            <DryRunPanel policy_override={Some((**draft).clone())} />
            <div class="flex items-center gap-2 border-t border-amber-200 pt-3">
                <Button variant={BtnVariant::Danger} label="Store it — flip the gate on"
                        onclick={on_confirm.clone()} />
                <Button variant={BtnVariant::Secondary} label="Cancel" onclick={on_cancel.clone()} />
            </div>
        </div>
    }
}

/// The save-bar indicator (mirrors `config_editor.rs`'s `save_bar_status`): a pending edit takes
/// precedence over a stale "saved" so the operator is never misled about whether new edits persisted.
fn save_bar_status(status: &SaveStatus, dirty: bool) -> Html {
    match status {
        SaveStatus::Saving => html! { <span class="text-sm text-slate-500">{ "Saving…" }</span> },
        SaveStatus::Error(msg) => html! {
            <span class="text-sm text-rose-700" title={msg.clone()}>{ "Save failed" }</span>
        },
        _ if dirty => html! { <Pill text="unsaved changes" tone={Tone::Warn} /> },
        SaveStatus::Saved => html! { <Pill text="saved" tone={Tone::Good} /> },
        SaveStatus::Idle => Html::default(),
    }
}

// ===========================================================================
// The explain/dry-run form (shared by: the editor's "Validate/dry-run the draft", the cliff
// preview, and the standalone "Explain — stored policy" section).
// ===========================================================================

#[derive(Properties, PartialEq)]
struct DryRunPanelProps {
    /// `Some(text)` evaluates against this inline policy (a pre-store preview of a draft);
    /// `None` evaluates against whatever the server currently has stored (the live policy).
    policy_override: Option<String>,
}

#[function_component(DryRunPanel)]
fn dry_run_panel(props: &DryRunPanelProps) -> Html {
    let session = use_session();
    let action = use_state(|| "dial".to_string());
    let service = use_state(String::new);
    let holder = use_state(String::new);
    let role = use_state(String::new);
    let scope = use_state(String::new);
    let enrolled = use_state(|| false);
    let node = use_state(String::new);
    let ttl = use_state(|| "3600".to_string());
    let now = use_state(String::new);
    let busy = use_state(|| false);
    let result = use_state(|| Option::<ApiResult<FlowPolicyTestResponse>>::None);

    let on_action = {
        let action = action.clone();
        Callback::from(move |e: Event| {
            if let Some(sel) = e.target_dyn_into::<HtmlSelectElement>() {
                action.set(sel.value());
            }
        })
    };
    let on_service = {
        let service = service.clone();
        Callback::from(move |v: String| service.set(v))
    };
    let on_holder = {
        let holder = holder.clone();
        Callback::from(move |v: String| holder.set(v))
    };
    let on_role = {
        let role = role.clone();
        Callback::from(move |v: String| role.set(v))
    };
    let on_scope = {
        let scope = scope.clone();
        Callback::from(move |v: String| scope.set(v))
    };
    let on_node = {
        let node = node.clone();
        Callback::from(move |v: String| node.set(v))
    };
    let on_ttl = {
        let ttl = ttl.clone();
        Callback::from(move |v: String| ttl.set(v))
    };
    let on_now = {
        let now = now.clone();
        Callback::from(move |v: String| now.set(v))
    };
    let on_enrolled = {
        let enrolled = enrolled.clone();
        Callback::from(move |v: bool| enrolled.set(v))
    };

    let on_run = {
        let session = session.clone();
        let action = action.clone();
        let service = service.clone();
        let holder = holder.clone();
        let role = role.clone();
        let scope = scope.clone();
        let enrolled = enrolled.clone();
        let node = node.clone();
        let ttl = ttl.clone();
        let now = now.clone();
        let busy = busy.clone();
        let result = result.clone();
        let policy_override = props.policy_override.clone();
        Callback::from(move |_: MouseEvent| {
            let client = session.client();
            let session = session.clone();
            let req = TestRequest {
                policy: policy_override.clone(),
                action: (*action).clone(),
                service: (*service).clone(),
                holder: (*holder).clone(),
                role: (!role.is_empty()).then(|| (*role).clone()),
                scope: (!scope.is_empty()).then(|| (*scope).clone()),
                enrolled: (*enrolled).then_some(true),
                requestor: None,
                node: (!node.is_empty()).then(|| (*node).clone()),
                ttl_requested: ttl.trim().parse().unwrap_or(3600),
                now: now.trim().parse().ok(),
            };
            let busy = busy.clone();
            let result = result.clone();
            busy.set(true);
            spawn_local(async move {
                let outcome = client
                    .post_json_detailed::<TestRequest, FlowPolicyTestResponse>(TEST_PATH, &req)
                    .await;
                busy.set(false);
                match outcome {
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    other => result.set(Some(other)),
                }
            });
        })
    };

    html! {
        <div class="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
            <div class="grid gap-3 sm:grid-cols-2">
                <label class="block">
                    <span class="block text-sm font-medium text-slate-700">{ "Action" }</span>
                    <select value={(*action).clone()} onchange={on_action} class={SELECT}>
                        <option value="dial">{ "dial" }</option>
                        <option value="expose">{ "expose" }</option>
                    </select>
                </label>
                <TextField label="Service" value={(*service).clone()} placeholder="svc/db"
                           mono=true on_change={on_service} />
                <TextField label="Holder key" value={(*holder).clone()} placeholder="ed25519:…"
                           mono=true on_change={on_holder} />
                <TextField label="TTL requested (seconds)" value={(*ttl).clone()} on_change={on_ttl} />
                <TextField label="Role (optional)" value={(*role).clone()} on_change={on_role} />
                <TextField label="Scope (optional)" value={(*scope).clone()} on_change={on_scope} />
                <TextField label="Node (optional)" value={(*node).clone()}
                           hint="The serving node's overlay identity (Stage A)." on_change={on_node} />
                <TextField label="Now (optional, Unix seconds)" value={(*now).clone()}
                           hint="Defaults to the server clock — set to preview a `not_after` cutoff."
                           on_change={on_now} />
                <CheckField label="Enrolled (holder presented a verified overlay-member credential)"
                            checked={*enrolled} on_change={on_enrolled} />
            </div>
            <Button variant={BtnVariant::Secondary} busy={*busy} busy_label="Running…"
                    label="Run dry-run" onclick={on_run} />
            { dry_run_result(&result) }
        </div>
    }
}

/// The dry-run result: a clear ALLOW/DENY pill (text-labeled, not color-only), the TTL ceiling,
/// deciding policies, diagnostics (via [`explain_diagnostics`] — see its doc), and any `note`.
fn dry_run_result(result: &UseStateHandle<Option<ApiResult<FlowPolicyTestResponse>>>) -> Html {
    match &**result {
        None => html! {},
        Some(Err(err)) => html! {
            <div role="alert" class="rounded-md border border-rose-200 bg-rose-50 px-3 py-2">
                <p class="text-sm text-rose-700 whitespace-pre-wrap">{ err.to_string() }</p>
            </div>
        },
        Some(Ok(resp)) => {
            let (label, tone) = if resp.decision == "allow" {
                ("ALLOW", Tone::Good)
            } else {
                ("DENY", Tone::Bad)
            };
            let diagnostics = explain_diagnostics(resp);
            html! {
                <div class="space-y-2 rounded-md border border-slate-200 bg-slate-50 p-3">
                    <div class="flex flex-wrap items-center gap-2">
                        <Pill text={label} tone={tone} />
                        if let Some(ceiling) = resp.ttl_ceiling {
                            <span class="text-xs text-slate-600">
                                { format!("TTL pulled down to {ceiling}s") }
                            </span>
                        }
                    </div>
                    if let Some(note) = &resp.note {
                        <p class="text-xs font-medium text-amber-700">{ note }</p>
                    }
                    if !resp.deciding_policies.is_empty() {
                        <div>
                            <p class="text-xs font-medium text-slate-500">{ "Deciding policies" }</p>
                            <ul class="mt-1 space-y-0.5">
                                { for resp.deciding_policies.iter().map(|p| html! {
                                    <li class="font-mono text-xs text-slate-600">{ p }</li>
                                }) }
                            </ul>
                        </div>
                    }
                    if !diagnostics.is_empty() {
                        <div>
                            <p class="text-xs font-medium text-slate-500">{ "Diagnostics" }</p>
                            <ul class="mt-1 space-y-0.5">
                                { for diagnostics.iter().map(|d| html! {
                                    <li class="text-xs text-slate-600">{ d }</li>
                                }) }
                            </ul>
                        </div>
                    }
                </div>
            }
        }
    }
}
