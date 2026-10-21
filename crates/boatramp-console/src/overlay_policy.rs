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
//! absent→present transition client-side, BEFORE issuing the `PUT`, and the editor blocks on
//! [`CliffDialog`] — a real (if hand-rolled) modal: focus moves into it the instant it mounts,
//! Tab/Shift+Tab cycle within it, Escape cancels, and "Store it" stays disabled until the operator
//! has both acknowledged the consequence AND run the embedded dry-run at least once against their
//! own drafted policy. The server's one-time `warning` (present only on the PUT that actually
//! performs this transition) — and a general "Policy saved." notice for every successful PUT — are
//! lifted to [`OverlayPolicy`] (which does NOT remount on a reload, unlike [`PolicyEditor`]), so
//! flipping the gate to default-deny doesn't destroy the one durable confirmation the operator
//! gets of it.
//!
//! # ETag / `If-Match`
//! `GET`'s `ETag` is held and echoed back as the next `PUT`'s `If-Match` (ETag → If-Match), so two
//! concurrent editors racing a write get a `409` — surfaced as a dedicated "someone else changed
//! it, reload first" banner (not a dead-end loop: re-Saving with the same stale `ETag` would just
//! 409 again) — rather than a lost write.

use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlElement, HtmlSelectElement, KeyboardEvent};
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

/// Format a save/validate error for display: an `ApiError::Status`'s body IS the server's literal
/// Cedar compile error (400) or conflict message (409) — shown verbatim, not wrapped in the
/// generic `Display` impl's `"HTTP {code}: {body}"` prefix, which just adds noise once the banner
/// around it already distinguishes which case this is.
fn format_save_error(err: &ApiError) -> String {
    match err {
        ApiError::Status { body, .. } if !body.is_empty() => body.clone(),
        other => other.to_string(),
    }
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

/// Props for [`OverlayPolicy`].
#[derive(Properties, PartialEq, Clone)]
pub struct OverlayPolicyProps {
    /// Reports whether the editor's draft currently has unsaved edits — `OverlayPage` (in
    /// `lib.rs`) uses this to confirm before a tab switch would discard them.
    #[prop_or_default]
    pub on_dirty: Callback<bool>,
}

/// The overlay flow-policy editor + explain page. `System·Admin`-gated; a `403` renders the calm
/// [`forbidden_note`] (never a client-side authz decision — the server's `403` is the only call).
#[function_component(OverlayPolicy)]
pub fn overlay_policy(props: &OverlayPolicyProps) -> Html {
    let session = use_session();
    let state = use_state(|| LoadState::Loading);
    // Bump to re-fetch (initial load, Retry, a 409's "Reload", and after a successful PUT).
    let tick = use_state(|| 0u32);
    // True only while a background refetch is in flight AND we already have a previous `Loaded`
    // value on screen — so a reload after Save (or a 409's Reload) never flashes the full-page
    // Spinner or resets scroll; the previous content stays up until the fresh GET lands.
    let refreshing = use_state(|| false);
    // Lifted OUT of `PolicyEditor` (which remounts via `key` on every reload) so neither is
    // destroyed within a frame of a successful save — see the module doc.
    let warning = use_state(|| Option::<String>::None);
    let saved_notice = use_state(|| Option::<String>::None);

    {
        let state = state.clone();
        let session = session.clone();
        let tick_val = *tick;
        let refreshing = refreshing.clone();
        let have_loaded = matches!(&*state, LoadState::Loaded(_));
        use_effect_with(tick_val, move |_| {
            if have_loaded {
                refreshing.set(true);
            } else {
                state.set(LoadState::Loading);
            }
            let client = session.client();
            let session = session.clone();
            let state = state.clone();
            let refreshing = refreshing.clone();
            spawn_local(async move {
                let outcome: ApiResult<Loaded> = async {
                    let (body, etag) = client.get_text_with_etag(POLICY_PATH).await?;
                    if body.trim().is_empty() {
                        return Ok(Loaded::Empty { etag });
                    }
                    let probe = client
                        .post_json_detailed::<TestRequest, FlowPolicyTestResponse>(
                            TEST_PATH,
                            &corruption_probe(),
                        )
                        .await?;
                    Ok(if note_says_corrupt(probe.note.as_deref()) {
                        Loaded::Corrupt { etag, stored: body }
                    } else {
                        Loaded::Present { etag, stored: body }
                    })
                }
                .await;
                refreshing.set(false);
                match outcome {
                    Ok(loaded) => state.set(LoadState::Loaded(loaded)),
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    Err(ApiError::Forbidden) => state.set(LoadState::Forbidden),
                    Err(err) => state.set(LoadState::Error(err)),
                }
            });
            || ()
        });
    }

    // A plain re-fetch with no "a save just happened" semantics (initial Retry, 409's Reload).
    let reload = {
        let tick = tick.clone();
        Callback::from(move |()| tick.set(*tick + 1))
    };
    // A successful PUT reports its outcome here: always shows a durable "Policy saved." notice,
    // and keeps the server's one-time cliff warning visible (if this PUT was the one that
    // triggered it) for the rest of this mount — then re-fetches like any other reload.
    let on_save_success = {
        let warning = warning.clone();
        let saved_notice = saved_notice.clone();
        let reload = reload.clone();
        Callback::from(move |cliff_warning: Option<String>| {
            if let Some(w) = cliff_warning {
                warning.set(Some(w));
            }
            saved_notice.set(Some("Policy saved.".to_string()));
            reload.emit(());
        })
    };
    // The "Policy saved." notice is durable across the reload the save itself triggers (that's
    // the whole point of lifting it here), but it shouldn't linger once the operator starts a NEW
    // edit on the fresh draft — clear it the moment `PolicyEditor` reports dirty again.
    let on_editor_dirty = {
        let saved_notice = saved_notice.clone();
        let on_dirty = props.on_dirty.clone();
        Callback::from(move |dirty: bool| {
            if dirty {
                saved_notice.set(None);
            }
            on_dirty.emit(dirty);
        })
    };

    match &*state {
        LoadState::Loading => html! { <Spinner label="Loading overlay flow policy…" /> },
        LoadState::Forbidden => forbidden_note(),
        LoadState::Error(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(reload.clone())} />
        },
        LoadState::Loaded(loaded) => html! {
            <>
                if let Some(w) = &*warning {
                    { warning_banner(w) }
                }
                if let Some(s) = &*saved_notice {
                    { saved_notice_banner(s) }
                }
                if *refreshing {
                    <p role="status" class="mb-2 text-xs text-slate-600">{ "Refreshing…" }</p>
                }
                <PolicyEditor key={(*tick).to_string()} loaded={loaded.clone()}
                              on_saved={on_save_success.clone()} on_reload={reload.clone()}
                              on_dirty={on_editor_dirty.clone()} />
            </>
        },
    }
}

/// Shown when the token is valid but lacks `System·Admin`.
fn forbidden_note() -> Html {
    html! {
        <div role="status" class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
            <p class="text-sm font-medium text-amber-800">
                { "You need System·Admin to view or edit the overlay flow policy." }
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

/// The server's one-time CLIFF warning (present only on the PUT that stored the first policy),
/// kept visible for the rest of this mount rather than a transient toast.
fn warning_banner(msg: &str) -> Html {
    html! {
        <div role="alert" class="mb-4 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3">
            <p class="text-sm text-amber-800 whitespace-pre-wrap">{ msg }</p>
        </div>
    }
}

/// A durable "it worked" notice for every successful save — lives on [`OverlayPolicy`], not the
/// `key`-remounted [`PolicyEditor`], so flipping the gate doesn't erase it within a frame.
fn saved_notice_banner(msg: &str) -> Html {
    html! {
        <div role="status" class="mb-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3">
            <p class="text-sm font-medium text-emerald-800">{ msg }</p>
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
    /// A successful PUT reports its outcome (the server's optional one-time cliff `warning`) up
    /// to `OverlayPolicy`, which shows the durable banners and re-fetches.
    on_saved: Callback<Option<String>>,
    /// A plain re-fetch with no "a save just happened" semantics — the 409-conflict banner's
    /// "Reload" button.
    on_reload: Callback<()>,
    /// Reports the draft's dirty state up to `OverlayPage`.
    #[prop_or_default]
    on_dirty: Callback<bool>,
}

/// The save-in-flight / result indicator (mirrors `config_editor.rs`'s `SaveStatus`).
#[derive(Clone, PartialEq)]
enum SaveStatus {
    Idle,
    Saving,
    Saved,
    /// A `409`: someone else changed the policy since this editor loaded it. Re-sending the same
    /// stale `If-Match` would just 409 again, so Save is disabled until a Reload.
    Conflict(String),
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
    let pending_cliff = use_state(|| false);
    let root_ref = use_node_ref();
    let save_trigger_ref = use_node_ref();
    let dialog_was_open = use_mut_ref(|| false);

    let dirty = *draft != stored;

    // Focus the remounted section's root on every mount. This component only ever (re)mounts on
    // the initial load or right after a successful save (a fresh `key`); in both cases moving
    // focus to the new content is the standard SPA "content changed" a11y pattern, so a screen
    // reader announces the heading instead of focus silently sitting on a now-detached node.
    {
        let root_ref = root_ref.clone();
        use_effect_with((), move |()| {
            if let Some(el) = root_ref.cast::<HtmlElement>() {
                let _ = el.focus();
            }
            || ()
        });
    }

    // Report dirty state up to `OverlayPage` (confirms before a tab switch would discard it).
    {
        let on_dirty = props.on_dirty.clone();
        use_effect_with(dirty, move |dirty| {
            on_dirty.emit(*dirty);
            || ()
        });
    }

    // Restore focus to the Save button once the cliff dialog closes via Cancel/Escape — NOT after
    // a successful confirm (the whole component remounts then, and the fresh mount's own
    // focus-the-root effect above takes over). Guarded by `dialog_was_open` so this only fires on
    // an actual true→false transition, never on the initial (always-false) render.
    {
        let save_trigger_ref = save_trigger_ref.clone();
        let dialog_was_open = dialog_was_open.clone();
        let open = *pending_cliff;
        use_effect_with(open, move |open| {
            let was_open = *dialog_was_open.borrow();
            if was_open
                && !*open
                && let Some(el) = save_trigger_ref.cast::<HtmlElement>()
            {
                let _ = el.focus();
            }
            *dialog_was_open.borrow_mut() = *open;
            || ()
        });
    }

    // If the draft empties out WHILE the cliff dialog is open (the dialog is inline, not a true
    // viewport-covering modal, so the textarea underneath stays editable), the absent→present
    // transition it was warning about no longer applies: close it rather than leave a stale
    // warning showing over a draft that would no longer trigger it.
    {
        let pending_cliff = pending_cliff.clone();
        let was_pending = *pending_cliff;
        let draft_val = (*draft).clone();
        use_effect_with(draft_val, move |d| {
            if was_pending && d.trim().is_empty() {
                pending_cliff.set(false);
            }
            || ()
        });
    }

    // The actual PUT, shared by the normal Save path and the cliff dialog's "Store it" button —
    // the cliff dialog never issues a DIFFERENT write than Save would have, it only gates when.
    let do_put = {
        let session = session.clone();
        let draft = draft.clone();
        let status = status.clone();
        let pending_cliff = pending_cliff.clone();
        let on_saved = props.on_saved.clone();
        let etag = etag.clone();
        Callback::from(move |()| {
            let client = session.client();
            let session = session.clone();
            let body = (*draft).clone();
            let status = status.clone();
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
                        status.set(SaveStatus::Saved);
                        pending_cliff.set(false);
                        on_saved.emit(resp.warning);
                    }
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    Err(err @ ApiError::Status { code: 409, .. }) => {
                        status.set(SaveStatus::Conflict(format_save_error(&err)));
                        pending_cliff.set(false);
                    }
                    Err(err) => {
                        // Surfaced verbatim (400 Cedar compile error) — see
                        // `ApiClient::put_text_if_match`'s doc comment.
                        status.set(SaveStatus::Error(format_save_error(&err)));
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
        Callback::from(move |()| pending_cliff.set(false))
    };
    let on_confirm_cliff = {
        let do_put = do_put.clone();
        Callback::from(move |()| do_put.emit(()))
    };
    let on_reload_click = {
        let on_reload = props.on_reload.clone();
        Callback::from(move |_: MouseEvent| on_reload.emit(()))
    };

    const ERROR_ID: &str = "overlay-policy-draft-error";
    let invalid = matches!(&*status, SaveStatus::Error(_));

    html! {
        <div ref={root_ref} tabindex="-1">
        <Section title="Overlay flow policy"
                 description="Operator-authored Cedar policy gating the overlay dial/expose mint \
                              — deny-or-shrink-TTL only; it can never widen what RBAC already \
                              permitted.">
            if corrupt {
                { corrupt_banner() }
            }
            if stored_is_off && !corrupt {
                { off_banner() }
            }

            <TextAreaField label="Policy (Cedar text)" value={(*draft).clone()} rows={16}
                           hint="Empty turns the mint gate OFF (every dial/expose allowed ungated)."
                           invalid={invalid}
                           describedby={invalid.then(|| AttrValue::from(ERROR_ID))}
                           on_change={on_draft_change} />

            {
                match &*status {
                    SaveStatus::Error(msg) => html! {
                        <div id={ERROR_ID} role="alert"
                             class="rounded-md border border-rose-200 bg-rose-50 px-3 py-2">
                            <pre class="whitespace-pre-wrap font-mono text-sm text-rose-700">{ msg }</pre>
                        </div>
                    },
                    SaveStatus::Conflict(msg) => html! {
                        <div role="alert" class="rounded-md border border-amber-300 bg-amber-50 px-3 py-2">
                            <p class="text-sm text-amber-800">
                                { "Someone else changed the policy since you loaded it — saving \
                                   now would be rejected again. Reload to see their version \
                                   before saving." }
                            </p>
                            <pre class="mt-1 whitespace-pre-wrap font-mono text-xs text-amber-700">{ msg }</pre>
                            <div class="mt-2">
                                <Button variant={BtnVariant::Secondary} label="Reload"
                                        onclick={on_reload_click.clone()} />
                            </div>
                        </div>
                    },
                    _ => html! {},
                }
            }

            if *pending_cliff {
                <CliffDialog draft={(*draft).clone()} on_confirm={on_confirm_cliff}
                             on_cancel={on_cancel_cliff} />
            }

            <div class="flex flex-wrap items-center gap-3 border-t border-slate-100 pt-4">
                { save_bar_status(&status, dirty) }
                <Button node_ref={save_trigger_ref} variant={BtnVariant::Primary}
                        busy={matches!(&*status, SaveStatus::Saving)} busy_label="Saving…"
                        disabled={!dirty || *pending_cliff || matches!(&*status, SaveStatus::Conflict(_))}
                        label="Save policy" onclick={on_save_click} />
            </div>

            <div class="border-t border-slate-100 pt-4">
                <h4 id="validate-draft-heading" class="mb-2 text-sm font-medium text-slate-600">
                    { "Validate / dry-run the draft" }
                </h4>
                <p class="mb-2 text-xs text-slate-500">
                    { "Shares one path with Save: the server compiles the draft the same way \
                       either button sends it, so a 400 here is the same error Save would hit." }
                </p>
                <section aria-labelledby="validate-draft-heading">
                    <DryRunPanel policy_override={Some((*draft).clone())} />
                </section>
            </div>

            <div class="border-t border-slate-100 pt-4">
                <h4 id="explain-stored-heading" class="mb-2 text-sm font-medium text-slate-600">
                    { "Explain — what the STORED (live) policy currently decides" }
                </h4>
                <section aria-labelledby="explain-stored-heading">
                    <DryRunPanel policy_override={Option::<String>::None} />
                </section>
            </div>
        </Section>
        </div>
    }
}

/// A live outage banner — the stored policy fails to compile, so the gate is failing closed
/// (deny-all) for every mint right now, independent of anything done in this editor.
fn corrupt_banner() -> Html {
    html! {
        <div role="alert" class="mb-4 rounded-lg border-2 border-rose-400 bg-rose-50 px-4 py-3">
            <p class="text-sm font-bold text-rose-900">
                { "LIVE OUTAGE — the stored overlay flow policy is CORRUPT. The live gate is \
                   failing closed: every dial/expose mint is being DENIED right now, not just \
                   edits made here. Fix and store a valid policy below to restore minting." }
            </p>
        </div>
    }
}

/// Nothing is stored — the mint gate is OFF, every dial/expose is allowed ungated.
fn off_banner() -> Html {
    html! {
        <div role="status" class="mb-4 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
            <p class="text-sm font-medium text-slate-700">
                { "No flow policy is stored — the mint gate is OFF: every dial/expose is \
                   currently allowed, ungated." }
            </p>
        </div>
    }
}

/// The save-bar indicator (mirrors `config_editor.rs`'s `save_bar_status`): a pending edit takes
/// precedence over a stale "saved" so the operator is never misled about whether new edits persisted.
fn save_bar_status(status: &SaveStatus, dirty: bool) -> Html {
    match status {
        SaveStatus::Saving => html! { <span class="text-sm text-slate-500">{ "Saving…" }</span> },
        SaveStatus::Error(_) => html! {
            <span class="text-sm text-rose-700">{ "Save failed" }</span>
        },
        SaveStatus::Conflict(_) => html! {
            <span class="text-sm text-amber-700">{ "Save conflict" }</span>
        },
        _ if dirty => html! { <Pill text="unsaved changes" tone={Tone::Warn} /> },
        SaveStatus::Saved => html! { <Pill text="saved" tone={Tone::Good} /> },
        SaveStatus::Idle => Html::default(),
    }
}

// ===========================================================================
// The cliff dialog — a real (if hand-rolled) modal, not a bare `confirm()`.
// ===========================================================================

/// Elements considered "focusable" for the Tab-trap below: native interactive elements plus
/// anything with an explicit, non-negative `tabindex`. Good enough for a dialog built entirely
/// from this crate's own form widgets (no third-party custom elements to account for).
const FOCUSABLE_SELECTOR: &str = "button:not([disabled]), input:not([disabled]), \
     select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

#[derive(Properties, PartialEq)]
struct CliffDialogProps {
    draft: String,
    on_confirm: Callback<()>,
    on_cancel: Callback<()>,
}

/// The blocking cliff-confirm dialog (absent→present transition only; see [`needs_cliff_confirm`]).
/// Focus moves into it the instant it mounts (this component only ever renders while the cliff is
/// pending, so mounting IS opening — the fresh render that shows it and the render that disables
/// Save are the same commit, so there is no earlier point to move focus from), Tab/Shift+Tab cycle
/// within it ([`trap_tab_key`]), Escape cancels, and "Store it" stays disabled until the operator
/// has both acknowledged the consequence (a checkbox) AND run the embedded dry-run at least once.
///
/// Deliberately NOT `aria-modal` (R1b): the rest of the page stays interactive (the draft textarea
/// above this dialog is not disabled/`inert`, so the operator can still edit it — see the
/// draft-empties-while-open effect in `policy_editor`), so claiming a modality this component does
/// not actually enforce (no inert/`aria-hidden` background) would mislead assistive tech. `role` +
/// `aria-label` + `aria-describedby` + the focus trap + the ack/dry-run gate are the real,
/// enforced safety; a true inert-background modal is a bigger change, tracked separately.
#[function_component(CliffDialog)]
fn cliff_dialog(props: &CliffDialogProps) -> Html {
    let dialog_ref = use_node_ref();
    let ack = use_state(|| false);
    let dry_run_done = use_state(|| false);

    // The textarea above this dialog stays editable while it's open (see the module doc / R1b),
    // so a dry-run already run against an earlier draft must not keep "Store it" armed once the
    // operator edits the draft further — mirrors `DryRunPanel`'s own result-clearing on
    // `policy_override` change.
    {
        let dry_run_done = dry_run_done.clone();
        let draft = props.draft.clone();
        use_effect_with(draft, move |_| {
            dry_run_done.set(false);
            || ()
        });
    }

    {
        let dialog_ref = dialog_ref.clone();
        use_effect_with((), move |()| {
            if let Some(el) = dialog_ref.cast::<HtmlElement>() {
                let _ = el.focus();
                el.scroll_into_view();
            }
            || ()
        });
    }

    let on_keydown = {
        let dialog_ref = dialog_ref.clone();
        let on_cancel = props.on_cancel.clone();
        Callback::from(move |e: KeyboardEvent| match e.key().as_str() {
            "Escape" => {
                e.prevent_default();
                on_cancel.emit(());
            }
            "Tab" => {
                if let (Some(container), Some(focused)) = (
                    dialog_ref.cast::<HtmlElement>(),
                    e.target_dyn_into::<HtmlElement>(),
                ) {
                    trap_tab_key(&container, &focused, e.shift_key(), &e);
                }
            }
            _ => {}
        })
    };

    let on_ack = {
        let ack = ack.clone();
        Callback::from(move |v: bool| ack.set(v))
    };
    let on_dry_run_ran = {
        let dry_run_done = dry_run_done.clone();
        Callback::from(move |()| dry_run_done.set(true))
    };
    let on_confirm = {
        let cb = props.on_confirm.clone();
        Callback::from(move |_: MouseEvent| cb.emit(()))
    };
    let on_cancel = {
        let cb = props.on_cancel.clone();
        Callback::from(move |_: MouseEvent| cb.emit(()))
    };

    let armable = *ack && *dry_run_done;
    const WARNING_ID: &str = "cliff-warning-text";

    html! {
        <div ref={dialog_ref} role="alertdialog"
             aria-label="Confirm storing the first overlay flow policy"
             aria-describedby={WARNING_ID}
             tabindex="-1" onkeydown={on_keydown}
             class="my-4 space-y-3 rounded-lg border-2 border-amber-300 bg-amber-50 p-4">
            <p id={WARNING_ID} class="text-sm font-semibold text-amber-900">
                { "Storing this policy flips the overlay mint gate from OFF (every dial/expose \
                   currently allowed) to DEFAULT-DENY: from the moment it is stored, every \
                   dial/expose NOT matched by a `permit` in this policy is denied." }
            </p>
            <p class="text-sm text-amber-800">
                { "Run the dry-run below against a flow you expect to still work (e.g. your own \
                   holder key) — it must run at least once before you can store." }
            </p>
            <DryRunPanel policy_override={Some(props.draft.clone())} on_ran={Some(on_dry_run_ran)} />
            <CheckField
                label="I understand every unmatched dial/expose will be denied once this is stored."
                checked={*ack} on_change={on_ack} />
            <div class="flex flex-wrap items-center gap-2 border-t border-amber-200 pt-3">
                <Button variant={BtnVariant::Danger} disabled={!armable}
                        label="Store it — flip the gate to default-deny" onclick={on_confirm} />
                <Button variant={BtnVariant::Secondary} label="Cancel" onclick={on_cancel} />
            </div>
            if !armable {
                <p class="text-xs text-amber-700">
                    { "Run the dry-run and check the box above to enable storing." }
                </p>
            }
        </div>
    }
}

/// Tab-trap: keep focus cycling within `container` while a dialog is open — Tab past the last
/// focusable element wraps to the first, Shift+Tab past the first wraps to the last. Identity
/// compared via `is_same_node` (`web_sys` extern types don't derive `PartialEq`, so `==` is not
/// available between two `HtmlElement`s).
///
/// R1a: focus starts on the CONTAINER itself right after the dialog opens (`tabindex="-1"`, so it
/// is never one of the `FOCUSABLE_SELECTOR` matches). A Shift+Tab as that very first keystroke
/// used to fall through uncaught: `tabindex="-1"` removes the container from the browser's normal
/// tab order, so a native reverse-Tab from it lands on whatever is focusable just BEFORE the
/// dialog in the page (e.g. the textarea above it) — escaping the trap. Forward Tab from the
/// container needs no special case: the browser already lands on the first focusable CHILD
/// (document order), which is `first`. So only the Shift+Tab direction needs "focus is not
/// anywhere in the trapped set at all" treated the same as "focus is on `first`".
fn trap_tab_key(container: &HtmlElement, focused: &HtmlElement, shift: bool, e: &KeyboardEvent) {
    let Ok(list) = container.query_selector_all(FOCUSABLE_SELECTOR) else {
        return;
    };
    let len = list.length();
    if len == 0 {
        return;
    }
    let first = list.get(0).and_then(|n| n.dyn_into::<HtmlElement>().ok());
    let last = list
        .get(len - 1)
        .and_then(|n| n.dyn_into::<HtmlElement>().ok());
    let is_same = |el: &Option<HtmlElement>| {
        el.as_ref()
            .is_some_and(|e| focused.is_same_node(e.dyn_ref::<web_sys::Node>()))
    };
    let in_trapped_set = (0..len).any(|i| {
        list.get(i)
            .and_then(|n| n.dyn_into::<HtmlElement>().ok())
            .is_some_and(|el| focused.is_same_node(el.dyn_ref::<web_sys::Node>()))
    });
    if shift && (is_same(&first) || !in_trapped_set) {
        e.prevent_default();
        if let Some(last) = &last {
            let _ = last.focus();
        }
    } else if !shift && is_same(&last) {
        e.prevent_default();
        if let Some(first) = &first {
            let _ = first.focus();
        }
    }
}

// ===========================================================================
// The explain/dry-run form (shared by: the editor's "Validate/dry-run the draft", the cliff
// dialog, and the standalone "Explain — stored policy" section).
// ===========================================================================

#[derive(Properties, PartialEq)]
struct DryRunPanelProps {
    /// `Some(text)` evaluates against this inline policy (a pre-store preview of a draft);
    /// `None` evaluates against whatever the server currently has stored (the live policy).
    policy_override: Option<String>,
    /// Notified once a dry-run completes (success or error) — the cliff dialog uses this to
    /// require at least one run before "Store it" can be armed.
    #[prop_or_default]
    on_ran: Option<Callback<()>>,
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

    // A result evaluated against a DIFFERENT policy (draft vs. stored, or an edited draft) is
    // misleading once shown — clear it whenever the caller switches which policy this panel
    // evaluates (the editor's "Validate the draft" panel re-passes `policy_override` on every
    // keystroke, so a stale ALLOW/DENY never lingers past the edit that invalidated it).
    {
        let result = result.clone();
        let policy_override = props.policy_override.clone();
        use_effect_with(policy_override, move |_| {
            result.set(None);
            || ()
        });
    }

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
        let on_ran = props.on_ran.clone();
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
            let on_ran = on_ran.clone();
            busy.set(true);
            spawn_local(async move {
                let outcome = client
                    .post_json_detailed::<TestRequest, FlowPolicyTestResponse>(TEST_PATH, &req)
                    .await;
                busy.set(false);
                match outcome {
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    other => {
                        result.set(Some(other));
                        if let Some(cb) = &on_ran {
                            cb.emit(());
                        }
                    }
                }
            });
        })
    };

    let caption = if props.policy_override.is_some() {
        "Evaluating: your unsaved draft"
    } else {
        "Evaluating: the live stored policy"
    };

    html! {
        <div class="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
            <p class="text-xs font-medium uppercase tracking-wide text-slate-500">{ caption }</p>
            <div class="grid gap-3 sm:grid-cols-2">
                <label class="block">
                    <span class="block text-sm font-medium text-slate-700">{ "Action" }</span>
                    <select value={(*action).clone()} onchange={on_action} class={SELECT}>
                        <option value="dial">{ "dial" }</option>
                        <option value="expose">{ "expose" }</option>
                    </select>
                </label>
                <TextField label="Service" value={(*service).clone()} hint="e.g. svc/db"
                           mono=true on_change={on_service} />
                <TextField label="Holder key" value={(*holder).clone()} hint="e.g. ed25519:…"
                           mono=true on_change={on_holder} />
                <TextField label="TTL requested (seconds)" value={(*ttl).clone()}
                           input_type={Some(AttrValue::from("number"))} on_change={on_ttl} />
                <TextField label="Role (optional)" value={(*role).clone()} on_change={on_role} />
                <TextField label="Scope (optional)" value={(*scope).clone()} on_change={on_scope} />
                <TextField label="Node (optional)" value={(*node).clone()}
                           hint="The serving node's overlay identity (Stage A)." on_change={on_node} />
                <TextField label="Now (optional, Unix seconds)" value={(*now).clone()}
                           input_type={Some(AttrValue::from("number"))}
                           hint="Defaults to the server clock — set to preview a `not_after` cutoff."
                           on_change={on_now} />
                <CheckField label="Enrolled (holder presented a verified overlay-member credential)"
                            checked={*enrolled} on_change={on_enrolled} />
            </div>
            <p class="text-xs text-slate-500">
                { "Tip: leaving Service/Holder empty evaluates an unmatched flow — expect DENY \
                   until you fill in a real target." }
            </p>
            <Button variant={BtnVariant::Secondary} busy={*busy} busy_label="Running…"
                    label="Run dry-run" onclick={on_run} />
            { dry_run_result(&result) }
        </div>
    }
}

/// The dry-run result: a headline decision (text-labeled, not color-only — a plain "Decision:
/// ALLOW/DENY" line, colored but never relying on color alone), in an `aria-live` region so a
/// screen reader hears it without needing to re-find the result after clicking Run; the TTL
/// ceiling, deciding policies (or an explicit "no permit matched" note on an unmatched deny),
/// diagnostics (via [`explain_diagnostics`] — see its doc), and any `note`.
fn dry_run_result(result: &UseStateHandle<Option<ApiResult<FlowPolicyTestResponse>>>) -> Html {
    match &**result {
        None => html! {},
        Some(Err(err)) => html! {
            <div role="alert" class="rounded-md border border-rose-200 bg-rose-50 px-3 py-2">
                <p class="text-sm text-rose-700 whitespace-pre-wrap">{ err.to_string() }</p>
            </div>
        },
        Some(Ok(resp)) => {
            let (headline_class, label) = if resp.decision == "allow" {
                ("text-emerald-700", "ALLOW")
            } else {
                ("text-rose-700", "DENY")
            };
            let diagnostics = explain_diagnostics(resp);
            let no_match = resp.decision != "allow" && resp.deciding_policies.is_empty();
            html! {
                <div role="status" aria-live="polite"
                     class="space-y-2 rounded-md border border-slate-200 bg-slate-50 p-3">
                    <div class="flex flex-wrap items-center gap-2">
                        <p class={classes!("text-base", "font-semibold", headline_class)}>
                            { format!("Decision: {label}") }
                        </p>
                        if let Some(ceiling) = resp.ttl_ceiling {
                            <span class="text-xs text-slate-600">
                                { format!("TTL pulled down to {ceiling}s") }
                            </span>
                        }
                    </div>
                    if let Some(note) = &resp.note {
                        <p class="text-xs font-medium text-amber-700">{ note }</p>
                    }
                    if no_match {
                        <p class="text-xs text-slate-500">
                            { "No permit matched — denied by default." }
                        </p>
                    } else if !resp.deciding_policies.is_empty() {
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
