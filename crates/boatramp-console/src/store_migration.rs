//! The **control-plane store migration** wizard for the Maintenance page (admin,
//! `System·Admin`) — the operator surface over `/api/store-migrate/*` for the
//! default-scope re-home (the Finding-8 migration-safety work).
//!
//! This mirrors the [`node_ops`](crate::node_ops) conventions: every POST is
//! confirmed ([`gloo_dialogs::confirm`]) with a message naming exactly what it
//! changes, nothing is destructive from the console (arming is non-destructive;
//! it only persists the operator's decisions for the next boot to stage, and the
//! `abort` roll-back is lossless), and there is **no client-side role check** —
//! the server gates each endpoint and a `401` signs the session out via
//! [`crate::auth::Session::sign_out`]; a `403` surfaces as an error.
//!
//! The wizard is a small state machine driven by polling `GET
//! /api/store-migrate/status` ([`StatusResponse`]):
//!   1. STATUS — version + layout status + the forward summary.
//!   2. DECISIONS — one radio group per collision the operator must resolve.
//!   3. ARM — a `confirm()`-gated POST of the assembled [`MigrationAnswers`].
//!   4. RESTART — after arming, keep polling; a dropped socket during the node restart is
//!      expected and shows "restarting…", not a failure, and when `status` returns `Dual`
//!      the staged view takes over.
//!
//! ## Wire types (console-side mirror — DRIFT RISK)
//!
//! The engine types ([`MigrationPlan`]/`MigrationDecision`/`DecisionRoute`/
//! `RouteInput`/`RouteInputKind`/`MigrationAnswers`/`Status`) live only in
//! `boatramp_core::migrate`, which is a native crate the console cannot depend
//! on. Sharing them (moving them into `boatramp-types` and re-exporting from
//! `boatramp_core::migrate`) was out of reach for this change: it would mean
//! editing `boatramp-core`, which is out of scope here. So the subset the
//! wizard reads/writes is mirrored below as `#[derive(Deserialize)]` structs,
//! matched field-for-field to the server's `#[derive(Serialize)]` shapes — the
//! same convention as [`crate::models`]. **These can drift from the server:**
//! a field rename, or a new `Status`/`RouteInputKind` variant, is not caught at
//! compile time and would fail deserialization at runtime. The durable fix is to
//! promote these to `boatramp-types` in a change that may touch `boatramp-core`.

use std::collections::HashMap;

use gloo_dialogs::confirm;
use gloo_timers::callback::Timeout;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::api::ApiError;
use crate::auth::{Session, use_session};
use crate::widgets::{BtnVariant, Button, ErrorBanner, Pill, Section, Spinner, Tone};

const STATUS_PATH: &str = "/api/store-migrate/status";
const ARM_PATH: &str = "/api/store-migrate/arm";
const ABORT_PATH: &str = "/api/store-migrate/abort";

/// How often to re-poll `status` while waiting for the node to restart.
const POLL_MS: u32 = 3_000;

// ===========================================================================
// Wire-type mirror (see the module header — console-side, DRIFT RISK)
// ===========================================================================

/// `GET /api/store-migrate/status` → `{ "plan": MigrationPlan, "armed": MigrationAnswers | null }`.
#[derive(Clone, PartialEq, Deserialize)]
struct StatusResponse {
    plan: MigrationPlan,
    #[serde(default)]
    armed: Option<MigrationAnswers>,
}

/// The read-only interactive migration plan (mirror of `boatramp_core::migrate::MigrationPlan`).
#[derive(Clone, PartialEq, Deserialize)]
struct MigrationPlan {
    status: Status,
    current_version: u32,
    target_version: u32,
    #[serde(default)]
    decisions: Vec<MigrationDecision>,
    #[serde(default)]
    summary: Vec<String>,
}

/// How the store needs to be treated (mirror of `boatramp_core::migrate::Status`; the server
/// serializes these externally-tagged, so the JSON is the bare variant name).
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
enum Status {
    Ready,
    NeedsMigration,
    Dual,
}

/// An operator-answerable fork (mirror of `boatramp_core::migrate::MigrationDecision`).
#[derive(Clone, PartialEq, Deserialize)]
struct MigrationDecision {
    id: String,
    question: String,
    #[serde(default)]
    routes: Vec<DecisionRoute>,
}

/// One route of a [`MigrationDecision`] (mirror of `boatramp_core::migrate::DecisionRoute`).
#[derive(Clone, PartialEq, Deserialize)]
struct DecisionRoute {
    key: String,
    label: String,
    #[serde(default)]
    input: Option<RouteInput>,
    #[serde(default)]
    note: Option<String>,
}

/// A free-text input a route requires (mirror of `boatramp_core::migrate::RouteInput`).
#[derive(Clone, PartialEq, Deserialize)]
struct RouteInput {
    prompt: String,
    #[allow(dead_code)]
    kind: RouteInputKind,
}

/// The validation class for a [`RouteInput`] (mirror of `boatramp_core::migrate::RouteInputKind`).
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
enum RouteInputKind {
    ResourceName,
}

/// The operator's answers — POSTed to `arm` (`Serialize`), and echoed back in `status.armed`
/// (`Deserialize`). Mirror of `boatramp_core::migrate::MigrationAnswers`.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
struct MigrationAnswers {
    #[serde(default)]
    skip_collisions: Vec<String>,
    #[serde(default)]
    aborted: bool,
}

/// `POST /api/store-migrate/arm` → `{armed, aborted, restart_required, next}`.
#[derive(Clone, PartialEq, Deserialize)]
struct ArmResponse {
    #[serde(default)]
    restart_required: bool,
    #[serde(default)]
    aborted: bool,
    #[serde(default)]
    next: String,
}

/// `POST /api/store-migrate/abort` → `{action, ...}` (`rolled-back` or `unarmed`).
#[derive(Clone, PartialEq, Deserialize)]
struct AbortResponse {
    action: String,
}

// ===========================================================================
// State
// ===========================================================================

/// The latest `status` fetch. The last good value is kept across re-polls (no
/// flicker); an error carries `waiting` so the restart window can render it as
/// "restarting…" instead of a hard failure.
#[derive(Clone, PartialEq)]
enum StatusFetch {
    Loading,
    Loaded(StatusResponse),
    Error { err: ApiError, waiting: bool },
}

/// The outcome banner of the most recent arm/abort — a success note or an error.
#[derive(Clone, PartialEq)]
enum ActionMsg {
    Ok(String),
    Err(String),
}

// ===========================================================================
// The wizard
// ===========================================================================

/// The store-migration wizard. One `Section` whose body is the current phase,
/// derived from the polled `status` + the operator's in-progress decision picks.
#[function_component(StoreMigration)]
pub fn store_migration() -> Html {
    let session = use_session();
    let status = use_state(|| StatusFetch::Loading);
    // Bump to (re-)fetch `status`; the poll chain and the Re-check / Retry
    // buttons all drive the wizard through this.
    let tick = use_state(|| 0u32);
    // Were we polling (waiting for a restart) when the current fetch started? An
    // error then renders as "restarting…" rather than a failure.
    let polling = use_state(|| false);
    // The pending re-poll timer; replaced each cycle and dropped (cancelled) on unmount.
    let poll = use_mut_ref(|| Option::<Timeout>::None);
    // decision id → chosen route key.
    let choices = use_state(HashMap::<String, String>::new);
    let action = use_state(|| Option::<ActionMsg>::None);
    let busy = use_state(|| false);

    // Fetch `status` whenever `tick` changes, self-rescheduling a re-poll while
    // armed answers are pending a restart (or while an error is seen mid-restart).
    {
        let status = status.clone();
        let session = session.clone();
        let polling = polling.clone();
        let poll = poll.clone();
        let tick = tick.clone();
        let tick_val = *tick;
        let was_polling = *polling;
        use_effect_with(tick_val, move |_| {
            let client = session.client();
            spawn_local(async move {
                match client.get_json::<StatusResponse>(STATUS_PATH).await {
                    Ok(resp) => {
                        // Keep polling while answers are armed but the store has not yet
                        // staged (restart pending). Once it is `Dual`, the boot consumed
                        // them and we stop.
                        let keep = resp.armed.is_some() && resp.plan.status != Status::Dual;
                        status.set(StatusFetch::Loaded(resp));
                        polling.set(keep);
                        *poll.borrow_mut() = keep.then(|| {
                            let tick = tick.clone();
                            Timeout::new(POLL_MS, move || tick.set(tick_val + 1))
                        });
                    }
                    Err(ApiError::Unauthorized) => session.sign_out(),
                    Err(err) => {
                        // A dropped socket / 5xx while waiting for the restart is expected —
                        // keep polling and show "restarting…"; otherwise it is a real error.
                        status.set(StatusFetch::Error {
                            err,
                            waiting: was_polling,
                        });
                        *poll.borrow_mut() = was_polling.then(|| {
                            let tick = tick.clone();
                            Timeout::new(POLL_MS, move || tick.set(tick_val + 1))
                        });
                    }
                }
            });
            || ()
        });
    }

    let reload = {
        let tick = tick.clone();
        Callback::from(move |_| tick.set(*tick + 1))
    };
    let on_pick = {
        let choices = choices.clone();
        Callback::from(move |(id, key): (String, String)| {
            let mut next = (*choices).clone();
            next.insert(id, key);
            choices.set(next);
        })
    };

    let body = match &*status {
        StatusFetch::Loading => {
            html! { <Spinner label="Checking the control-plane store layout…" /> }
        }
        StatusFetch::Error { err, waiting: true } => restarting_view(err),
        StatusFetch::Error {
            err,
            waiting: false,
        } => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(reload.clone())} />
        },
        StatusFetch::Loaded(resp) => {
            let plan = &resp.plan;
            if plan.status == Status::Dual {
                dual_view(plan, &session, &action, &busy, &reload)
            } else if resp.armed.is_some() {
                armed_view(
                    resp.armed.as_ref().unwrap(),
                    &session,
                    &action,
                    &busy,
                    &reload,
                )
            } else if plan.status == Status::Ready {
                ready_view(plan)
            } else {
                decisions_view(
                    plan, &choices, &on_pick, &session, &action, &busy, &reload, &polling, &tick,
                )
            }
        }
    };

    html! {
        <Section title="Store migration"
                 description="Control-plane store-layout migration — the default-scope re-home. \
                              Arming stages it at the next node restart; nothing here is destructive.">
            if let Some(msg) = &*action {
                { action_banner(msg) }
            }
            { body }
        </Section>
    }
}

// ===========================================================================
// Phase views
// ===========================================================================

/// STATUS — the store is at the current layout; nothing to do.
fn ready_view(plan: &MigrationPlan) -> Html {
    html! {
        <div class="space-y-2">
            <div class="flex items-center gap-2">
                <Pill text="up to date" tone={Tone::Good} />
                <span class="text-sm text-slate-600">
                    { format!("Schema version {} — the current layout.", plan.current_version) }
                </span>
            </div>
            <p class="text-sm text-slate-500">
                { "Nothing to do. The control-plane store is already at the layout this binary requires." }
            </p>
        </div>
    }
}

/// STATUS + DECISIONS + ARM — the store needs the re-home. Resolve any
/// collisions, then arm for the next restart.
#[allow(clippy::too_many_arguments)]
fn decisions_view(
    plan: &MigrationPlan,
    choices: &UseStateHandle<HashMap<String, String>>,
    on_pick: &Callback<(String, String)>,
    session: &Session,
    action: &UseStateHandle<Option<ActionMsg>>,
    busy: &UseStateHandle<bool>,
    reload: &Callback<()>,
    polling: &UseStateHandle<bool>,
    tick: &UseStateHandle<u32>,
) -> Html {
    // Arm-ability: an `abort` pick arms a "do not migrate" and always applies;
    // otherwise every decision must be answered and none left on `rename` (which
    // the server refuses until it is resolved externally and gone from the plan).
    let any_abort = plan
        .decisions
        .iter()
        .any(|d| choices.get(&d.id).map(String::as_str) == Some("abort"));
    let all_answered = plan.decisions.iter().all(|d| choices.contains_key(&d.id));
    let any_rename = plan
        .decisions
        .iter()
        .any(|d| choices.get(&d.id).map(String::as_str) == Some("rename"));
    let armable = any_abort || (all_answered && !any_rename);

    let answers = {
        let aborted = any_abort;
        let skip_collisions = if aborted {
            Vec::new()
        } else {
            plan.decisions
                .iter()
                .filter(|d| choices.get(&d.id).map(String::as_str) == Some("skip"))
                .map(|d| d.id.clone())
                .collect()
        };
        MigrationAnswers {
            skip_collisions,
            aborted,
        }
    };

    let on_arm = arm_callback(answers.clone(), session, action, busy, polling, tick);

    html! {
        <div class="space-y-5">
            <div class="flex items-center gap-2">
                <Pill text="migration needed" tone={Tone::Warn} />
                <span class="text-sm text-slate-600">
                    { format!("Schema version {} → {}.", plan.current_version, plan.target_version) }
                </span>
            </div>

            if !plan.decisions.is_empty() {
                <div class="space-y-4">
                    <p class="text-sm text-slate-600">
                        { "Resolve each decision below, then arm. A collision you mean to " }
                        <strong>{ "rename" }</strong>
                        { " must be re-created under a new name externally (the normal deploy flow) \
                           and re-checked — the wizard does not rename anything." }
                    </p>
                    { for plan.decisions.iter().map(|d| {
                        let selected = choices.get(&d.id).cloned();
                        decision_card(d, selected.as_deref(), on_pick, reload)
                    }) }
                </div>
            }

            { summary_block(plan) }

            if any_abort {
                <div role="alert" class="rounded-md border border-amber-300 bg-amber-50 px-3 py-2">
                    <p class="text-sm text-amber-800">
                        { "Abort is selected on a decision — this cancels the ENTIRE migration, and \
                           your skip/rename answers on the other decisions are ignored. Clear it to \
                           keep resolving collisions." }
                    </p>
                </div>
            }

            <div class="flex flex-wrap items-center gap-2 border-t border-slate-100 pt-4">
                <Button variant={BtnVariant::Primary} busy={**busy} busy_label="Arming…"
                        disabled={!armable}
                        label={if any_abort { "Record 'do not migrate'" } else { "Arm & stage at restart" }}
                        onclick={on_arm} />
                <Button variant={BtnVariant::Secondary} label="Re-check"
                        onclick={reload_click(reload)} />
                if !armable {
                    <span class="text-xs text-slate-500">
                        { if any_rename {
                            "Re-create the renamed resource(s) externally, then Re-check — rename decisions can't be armed."
                          } else {
                            "Answer every decision to arm."
                          } }
                    </span>
                }
            </div>

            { arm_consequences(&answers, any_rename) }
        </div>
    }
}

/// ARM result + RESTART — answers are armed and the node must be restarted to
/// stage them. Keep polling; show how to proceed, and offer to un-arm.
fn armed_view(
    armed: &MigrationAnswers,
    session: &Session,
    action: &UseStateHandle<Option<ActionMsg>>,
    busy: &UseStateHandle<bool>,
    reload: &Callback<()>,
) -> Html {
    let headline = if armed.aborted {
        "A 'do not migrate' decision is armed — the next restart will NOT stage the re-home."
            .to_string()
    } else if armed.skip_collisions.is_empty() {
        "The re-home is armed.".to_string()
    } else {
        format!(
            "The re-home is armed, skipping {} collision(s).",
            armed.skip_collisions.len()
        )
    };
    let on_unarm = abort_callback(session, action, busy, reload, AbortKind::Unarm);

    html! {
        <div class="space-y-4">
            <div class="flex items-center gap-2">
                <Pill text="armed" tone={Tone::Warn} />
                <span class="text-sm text-slate-600">{ headline }</span>
            </div>
            if !armed.aborted {
                <ol class="list-decimal space-y-1 pl-5 text-sm text-slate-600">
                    <li>{ "Restart the node now — " }<code class="font-mono text-xs">{ "serve --auto-migrate" }</code>
                        { " stages the re-home at boot, before it serves (no process serves a stale layout)." }</li>
                    <li>{ "After it comes back it will be " }<strong>{ "staged (dual soak)" }</strong>
                        { " — this panel updates automatically." }</li>
                </ol>
            }
            if !armed.skip_collisions.is_empty() {
                { id_list("Skipping", &armed.skip_collisions) }
            }
            <div class="flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                <Spinner label="Waiting for restart… reconnecting" />
            </div>
            <div class="flex flex-wrap items-center gap-2 border-t border-slate-100 pt-4">
                <Button variant={BtnVariant::DangerSubtle} busy={**busy} busy_label="Un-arming…"
                        label="Abort (un-arm)" onclick={on_unarm} />
                <span class="text-xs text-slate-500">
                    { "Un-arm the pending answers so the next restart stages nothing." }
                </span>
            </div>
        </div>
    }
}

/// STAGED — the forward is done, old keys retained (the dual soak). Only the
/// CLI finalize (after the blob + libsql re-home) remains, or a lossless abort.
fn dual_view(
    plan: &MigrationPlan,
    session: &Session,
    action: &UseStateHandle<Option<ActionMsg>>,
    busy: &UseStateHandle<bool>,
    reload: &Callback<()>,
) -> Html {
    let on_abort = abort_callback(session, action, busy, reload, AbortKind::RollBack);
    html! {
        <div class="space-y-4">
            <div role="status" class="flex items-center gap-2">
                <Pill text="staged · finalize pending" tone={Tone::Warn} />
                <span class="text-sm text-slate-600">
                    { format!("Schema version {} — forward done, old keys retained (dual soak).", plan.current_version) }
                </span>
            </div>
            <p class="text-sm text-slate-600">
                { "Staged — restart to adopt, then re-home blob + libsql and run " }
                <code class="font-mono text-xs">{ "boatramp migrate --finalize" }</code>
                { " (CLI) to drop the old keys. The finalize is deliberately not exposed here: it \
                   must run after the restart and the other substrates are re-homed." }
            </p>
            <div class="flex flex-wrap items-center gap-2 border-t border-slate-100 pt-4">
                <Button variant={BtnVariant::Danger} busy={**busy} busy_label="Rolling back…"
                        label="Abort (roll back)" onclick={on_abort} />
                <span class="text-xs text-slate-500">
                    { "Delete the re-homed copies and return the store to its pre-migration layout \
                       (lossless while nothing wrote to the new keys during the soak)." }
                </span>
            </div>
        </div>
    }
}

/// RESTART — a fetch failed while waiting for the node to come back. Expected;
/// render it as reconnecting, not a hard failure (all state lives server-side).
fn restarting_view(err: &ApiError) -> Html {
    html! {
        <div class="space-y-2">
            <div class="flex items-center gap-3 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                <Spinner label="Restarting… reconnecting" />
            </div>
            <p class="text-xs text-slate-500">{ format!("(last attempt: {err})") }</p>
        </div>
    }
}

// ===========================================================================
// Decision + summary rendering
// ===========================================================================

/// One decision as a radio group; the rename route, when picked, shows the
/// external-action guidance + a Re-check button (the wizard does not rename).
fn decision_card(
    decision: &MigrationDecision,
    selected: Option<&str>,
    on_pick: &Callback<(String, String)>,
    reload: &Callback<()>,
) -> Html {
    html! {
        <fieldset class="rounded-lg border border-slate-200 p-4">
            <legend class="px-1 text-sm font-medium text-slate-800">{ &decision.question }</legend>
            <div class="mt-2 space-y-3">
                { for decision.routes.iter().map(|r| {
                    route_row(&decision.id, r, selected == Some(r.key.as_str()), on_pick)
                }) }
            </div>
            if selected == Some("rename") {
                <div class="mt-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2">
                    <p class="text-xs text-amber-800">
                        { "Re-create this resource under the new, non-colliding name via the normal \
                           deploy flow and delete the old one. The wizard does " }
                        <strong>{ "not" }</strong>
                        { " perform the rename — once it is gone, Re-check so it drops out of the plan." }
                    </p>
                    <div class="mt-2">
                        <Button variant={BtnVariant::Secondary} label="Re-check" onclick={reload_click(reload)} />
                    </div>
                </div>
            }
        </fieldset>
    }
}

/// One route radio: the label, the input prompt (rename), and the route note.
fn route_row(
    decision_id: &str,
    route: &DecisionRoute,
    checked: bool,
    on_pick: &Callback<(String, String)>,
) -> Html {
    let on_change = {
        let on_pick = on_pick.clone();
        let id = decision_id.to_string();
        let key = route.key.clone();
        Callback::from(move |_: Event| on_pick.emit((id.clone(), key.clone())))
    };
    html! {
        <label class="flex items-start gap-2">
            <input type="radio" name={decision_id.to_string()} checked={checked} onchange={on_change}
                   class="mt-0.5 h-4 w-4 shrink-0 border-slate-300 text-sky-600 focus:ring-sky-500" />
            <span class="block">
                <span class="text-sm text-slate-700">{ &route.label }</span>
                if let Some(input) = &route.input {
                    <span class="block text-xs text-slate-500">
                        { format!("You supply the {} when you re-create it externally.", input.prompt) }
                    </span>
                }
                if let Some(note) = &route.note {
                    <span class="block text-xs text-slate-500">{ note }</span>
                }
            </span>
        </label>
    }
}

/// The forward-work summary lines (or a muted fallback).
fn summary_block(plan: &MigrationPlan) -> Html {
    if plan.summary.is_empty() {
        return html! {};
    }
    html! {
        <div class="rounded-lg bg-slate-50 p-3">
            <p class="text-xs font-medium text-slate-500">{ "Planned forward work" }</p>
            <ul class="mt-1 space-y-0.5">
                { for plan.summary.iter().map(|s| html! {
                    <li class="text-xs text-slate-600">{ s }</li>
                }) }
            </ul>
        </div>
    }
}

/// A preview of what arming will persist, so the confirm() is not the first the
/// operator learns of it.
fn arm_consequences(answers: &MigrationAnswers, any_rename: bool) -> Html {
    if any_rename {
        return html! {};
    }
    let line = if answers.aborted {
        "Arming records a 'do not migrate' decision; the next restart stages nothing.".to_string()
    } else if answers.skip_collisions.is_empty() {
        "Arming stages the full re-home at the next restart.".to_string()
    } else {
        format!(
            "Arming stages the re-home at the next restart, leaving {} collision(s) un-re-homed.",
            answers.skip_collisions.len()
        )
    };
    html! { <p class="text-xs text-slate-500">{ line }</p> }
}

/// A labeled list of decision/collision ids.
fn id_list(label: &str, ids: &[String]) -> Html {
    html! {
        <div>
            <p class="text-xs font-medium text-slate-500">{ label.to_string() }</p>
            <ul class="mt-1 space-y-0.5">
                { for ids.iter().map(|id| html! {
                    <li class="font-mono text-xs text-slate-600">{ id }</li>
                }) }
            </ul>
        </div>
    }
}

/// The arm/abort outcome banner.
fn action_banner(msg: &ActionMsg) -> Html {
    match msg {
        ActionMsg::Ok(text) => html! {
            <div role="status" class="flex items-start gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3">
                <Pill text="done" tone={Tone::Good} />
                <span class="text-sm text-emerald-800">{ text }</span>
            </div>
        },
        ActionMsg::Err(text) => html! {
            <div role="alert" class="rounded-lg border border-rose-200 bg-rose-50 px-4 py-3">
                <p class="text-sm text-rose-700 whitespace-pre-wrap">{ text }</p>
            </div>
        },
    }
}

// ===========================================================================
// Mutations (confirm()-gated)
// ===========================================================================

/// Which `abort` the button drives (only the confirm wording + label differ; the
/// server picks the real action from the store's status).
#[derive(Clone, Copy)]
enum AbortKind {
    /// The store is staged (dual soak) → roll it back.
    RollBack,
    /// Answers are armed but nothing is staged → un-arm them.
    Unarm,
}

/// Build the confirm()-gated ARM click handler for the assembled `answers`.
fn arm_callback(
    answers: MigrationAnswers,
    session: &Session,
    action: &UseStateHandle<Option<ActionMsg>>,
    busy: &UseStateHandle<bool>,
    polling: &UseStateHandle<bool>,
    tick: &UseStateHandle<u32>,
) -> Callback<MouseEvent> {
    let session = session.clone();
    let action = action.clone();
    let busy = busy.clone();
    let polling = polling.clone();
    let tick = tick.clone();
    Callback::from(move |_: MouseEvent| {
        let prompt = if answers.aborted {
            "Arm a 'do not migrate' decision?\n\nThe next node restart will NOT stage the \
             re-home. Nothing changes now."
                .to_string()
        } else if answers.skip_collisions.is_empty() {
            "Arm the migration and stage it at the next restart?\n\nThis only records the decision — the \
             re-home runs when you restart the node with serve --auto-migrate (it stages at boot, before \
             serving). Nothing destructive happens now."
                .to_string()
        } else {
            format!(
                "Arm the migration, leaving {} collision(s) un-re-homed?\n\nThis only records the decision \
                 — the re-home runs at the next restart (serve --auto-migrate, staged at boot). Nothing \
                 destructive happens now.",
                answers.skip_collisions.len()
            )
        };
        if !confirm(&prompt) {
            return;
        }
        let client = session.client();
        let session = session.clone();
        let action = action.clone();
        let busy = busy.clone();
        let polling = polling.clone();
        let tick = tick.clone();
        let answers = answers.clone();
        let next_tick = *tick + 1;
        busy.set(true);
        action.set(None);
        spawn_local(async move {
            let outcome = client
                .post_json_detailed::<MigrationAnswers, ArmResponse>(ARM_PATH, &answers)
                .await;
            busy.set(false);
            match outcome {
                Ok(resp) => {
                    let msg = if resp.aborted {
                        "Armed a 'do not migrate' decision.".to_string()
                    } else if resp.restart_required {
                        format!("Armed. {}", resp.next)
                    } else {
                        resp.next
                    };
                    action.set(Some(ActionMsg::Ok(msg)));
                    // Enter the restart-wait phase and refetch (now showing armed answers).
                    polling.set(true);
                    tick.set(next_tick);
                }
                Err(ApiError::Unauthorized) => session.sign_out(),
                // 409 = an unresolved decision; show the server's message, stay on step 2,
                // and refetch the plan in case the decisions changed.
                Err(err) => {
                    action.set(Some(ActionMsg::Err(err.to_string())));
                    tick.set(next_tick);
                }
            }
        });
    })
}

/// Build the confirm()-gated ABORT click handler (roll back a staged store, or
/// un-arm pending answers — the server chooses based on the store's status).
fn abort_callback(
    session: &Session,
    action: &UseStateHandle<Option<ActionMsg>>,
    busy: &UseStateHandle<bool>,
    reload: &Callback<()>,
    kind: AbortKind,
) -> Callback<MouseEvent> {
    let session = session.clone();
    let action = action.clone();
    let busy = busy.clone();
    let reload = reload.clone();
    Callback::from(move |_: MouseEvent| {
        let prompt = match kind {
            AbortKind::RollBack => {
                "Roll back the staged re-home?\n\nThis deletes the re-homed copies and returns the \
                 control-plane store to its pre-migration layout. It is lossless only while nothing has \
                 written to the new keys during the soak; the server refuses (keeps everything) otherwise."
            }
            AbortKind::Unarm => {
                "Un-arm the pending migration answers?\n\nThe next restart will stage nothing until you \
                 arm again. Nothing is staged yet, so this only clears the parked decision."
            }
        };
        if !confirm(prompt) {
            return;
        }
        let client = session.client();
        let session = session.clone();
        let action = action.clone();
        let busy = busy.clone();
        let reload = reload.clone();
        busy.set(true);
        action.set(None);
        spawn_local(async move {
            let outcome = client
                .post_empty_detailed::<AbortResponse>(ABORT_PATH)
                .await;
            busy.set(false);
            match outcome {
                Ok(resp) => {
                    let msg = match resp.action.as_str() {
                        "rolled-back" => {
                            "Rolled back — the store is back at its pre-migration layout."
                        }
                        "unarmed" => "Un-armed — the pending answers were cleared.",
                        _ => "Done.",
                    };
                    action.set(Some(ActionMsg::Ok(msg.to_string())));
                    reload.emit(());
                }
                Err(ApiError::Unauthorized) => session.sign_out(),
                Err(err) => {
                    action.set(Some(ActionMsg::Err(err.to_string())));
                    reload.emit(());
                }
            }
        });
    })
}

/// A `MouseEvent` → `reload()` adapter (the Re-check / Re-check-again buttons).
fn reload_click(reload: &Callback<()>) -> Callback<MouseEvent> {
    let reload = reload.clone();
    Callback::from(move |_: MouseEvent| reload.emit(()))
}
