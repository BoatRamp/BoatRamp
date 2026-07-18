//! Declarative workflow orchestration (FA-6): the `/api/workflows` control
//! surface (define/list/get/delete definitions, start/inspect runs) plus the
//! executor drain that advances each run step by step and compensates on
//! failure. `handlers`-gated; pulls the serve-pipeline scope in via
//! `use super::*`.

use super::*;

/// Max request body buffered as a workflow run's initial input.
#[cfg(feature = "handlers")]
const MAX_WORKFLOW_INPUT_BYTES: usize = 1024 * 1024;

/// Body of `PUT /api/workflows/:name` — the step DAG (the name comes from the path).
#[cfg(feature = "handlers")]
#[derive(serde::Deserialize)]
pub(super) struct WorkflowBody {
    steps: Vec<boatramp_core::workflow::Step>,
}

/// `PUT /api/workflows/:name` (FA-6) — define/replace a workflow. The DAG is
/// validated (unique ids, deps resolve, acyclic) before it is stored. `system·admin`.
#[cfg(feature = "handlers")]
pub(super) async fn define_workflow(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    Json(body): Json<WorkflowBody>,
) -> Response {
    let workflow = boatramp_core::workflow::Workflow {
        name: name.clone(),
        steps: body.steps,
    };
    if let Err(reason) = workflow.validate() {
        return (StatusCode::BAD_REQUEST, format!("{reason}\n")).into_response();
    }
    if let Err(err) = deploy.put_workflow(&workflow).await {
        return deploy_error_response(err);
    }
    Json(workflow).into_response()
}

/// `GET /api/workflows` (FA-6) — list workflow definitions. `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn list_workflows_handler(State(deploy): State<DeployStore>) -> Response {
    match deploy.list_workflows().await {
        Ok(mut list) => {
            list.sort_by(|a, b| a.name.cmp(&b.name));
            Json(list).into_response()
        }
        Err(err) => deploy_error_response(err),
    }
}

/// `GET /api/workflows/:name` (FA-6) — a workflow definition. `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn get_workflow_handler(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.get_workflow(&name).await {
        Ok(Some(w)) => Json(w).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("no workflow {name:?}\n")).into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `DELETE /api/workflows/:name` (FA-6) — remove a workflow definition (runs are
/// left as history). `system·admin`. Idempotent.
#[cfg(feature = "handlers")]
pub(super) async fn delete_workflow_handler(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
) -> Response {
    match deploy.delete_workflow(&name).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// `POST /api/workflows/:name/runs` (FA-6) — start a run. The request body is the
/// run's initial input (delivered to the root steps). Returns `202` + the queued
/// run; the executor drain advances it. `system·admin`.
#[cfg(feature = "handlers")]
pub(super) async fn start_workflow_run(
    State(deploy): State<DeployStore>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let workflow = match deploy.get_workflow(&name).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("no workflow {name:?}\n")).into_response()
        }
        Err(err) => return deploy_error_response(err),
    };
    let body = match axum::body::to_bytes(request.into_body(), MAX_WORKFLOW_INPUT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "workflow input exceeds the cap\n",
            )
                .into_response()
        }
    };
    let now = now_unix();
    let id = new_invocation_id();
    let input_b64 = (!body.is_empty()).then(|| b64_encode(&body));
    let run = boatramp_core::workflow::WorkflowRun::start(&workflow, id, input_b64, now);
    if let Err(err) = deploy.put_workflow_run(&run).await {
        return deploy_error_response(err);
    }
    (StatusCode::ACCEPTED, Json(run)).into_response()
}

/// `GET /api/workflows/:name/runs/:id` (FA-6) — poll a run's status/step state.
/// `system·read`.
#[cfg(feature = "handlers")]
pub(super) async fn get_workflow_run_handler(
    State(deploy): State<DeployStore>,
    Path((name, id)): Path<(String, String)>,
) -> Response {
    match deploy.get_workflow_run(&name, &id).await {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            format!("no run {id:?} for workflow {name:?}\n"),
        )
            .into_response(),
        Err(err) => deploy_error_response(err),
    }
}

/// Drain a workflow's non-terminal runs, advancing each by one tick. Driven from
/// the scheduler tick, leader-gated like the invocation drain.
#[cfg(feature = "handlers")]
pub(super) async fn drain_workflow_runs(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    workflow: &boatramp_core::workflow::Workflow,
) {
    let runs = match deploy.list_workflow_runs(&workflow.name).await {
        Ok(runs) => runs,
        Err(err) => {
            tracing::warn!(workflow = %workflow.name, %err, "listing workflow runs failed");
            return;
        }
    };
    for run in runs {
        if run.is_terminal() {
            continue;
        }
        advance_workflow_run(inner, deploy, workflow, run).await;
    }
}

/// Advance one run by a tick: run every ready step once, then settle the run
/// (succeeded when all steps did; failed + compensated when a step exhausted its
/// retries). A step whose function is missing or returns a `5xx` (engine wrapper)
/// is a failure, retried up to its `max_attempts`.
#[cfg(feature = "handlers")]
async fn advance_workflow_run(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    workflow: &boatramp_core::workflow::Workflow,
    mut run: boatramp_core::workflow::WorkflowRun,
) {
    use boatramp_core::workflow::StepStatus;
    let now = now_unix();
    for step_id in run.ready_steps(workflow) {
        let Some(step) = workflow.step(&step_id).cloned() else {
            continue;
        };
        let input = build_step_input(&run, &step);
        let outcome = run_workflow_step(inner, deploy, &step, input).await;
        let Some(sr) = run.steps.get_mut(&step_id) else {
            continue;
        };
        sr.attempts = sr.attempts.saturating_add(1);
        sr.updated = now;
        match outcome {
            Some(output) => {
                sr.status = StepStatus::Succeeded;
                sr.output_b64 = Some(b64_encode(&output));
                run.completed_order.push(step_id.clone());
            }
            None if sr.attempts >= step.retry.max_attempts => sr.status = StepStatus::Failed,
            None => sr.status = StepStatus::Pending, // retry next tick
        }
    }
    // Settle the run.
    let any_failed = run.steps.values().any(|r| r.status == StepStatus::Failed);
    if any_failed {
        compensate_run(inner, deploy, workflow, &mut run).await;
        run.status = boatramp_core::workflow::WorkflowStatus::Failed;
    } else if run.all_succeeded() {
        run.status = boatramp_core::workflow::WorkflowStatus::Succeeded;
    }
    run.updated = now_unix();
    let _ = deploy.put_workflow_run(&run).await;
}

/// Run a single step's function (active version) with `input` as its request body.
/// Returns the response body on a delivered guest response, or `None` on a
/// missing function / engine-level failure (a retryable step failure).
#[cfg(feature = "handlers")]
async fn run_workflow_step(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    step: &boatramp_core::workflow::Step,
    input: Vec<u8>,
) -> Option<Vec<u8>> {
    let function = match deploy.get_function(&step.function).await {
        Ok(Some(f)) => f,
        _ => return None,
    };
    let component = function.resolve(&function.active).map(str::to_owned)?;
    let request = build_step_request(input);
    let (response, _duration) =
        execute_function(inner, deploy, &function, &component, request).await;
    let (status, _content_type, body) = capture_response(response).await;
    // A guest response (any status the guest itself set, incl. 4xx) is delivered;
    // an engine wrapper 5xx (timeout/trap/overload/missing blob) is a failure.
    let delivered = status != StatusCode::INTERNAL_SERVER_ERROR
        && status != StatusCode::GATEWAY_TIMEOUT
        && status != StatusCode::SERVICE_UNAVAILABLE;
    delivered.then_some(body)
}

/// On a run failure, invoke each completed step's `compensate` function in reverse
/// completion order (best-effort) and mark those steps `compensated`.
#[cfg(feature = "handlers")]
async fn compensate_run(
    inner: &HandlerRuntimeInner,
    deploy: &DeployStore,
    workflow: &boatramp_core::workflow::Workflow,
    run: &mut boatramp_core::workflow::WorkflowRun,
) {
    let completed = run.completed_order.clone();
    for step_id in completed.iter().rev() {
        let Some(step) = workflow.step(step_id) else {
            continue;
        };
        if let Some(compensate_fn) = &step.compensate {
            if let Ok(Some(function)) = deploy.get_function(compensate_fn).await {
                if let Some(component) = function.resolve(&function.active).map(str::to_owned) {
                    let request = build_step_request(Vec::new());
                    // Best-effort rollback; its outcome does not change the verdict.
                    let _ = execute_function(inner, deploy, &function, &component, request).await;
                }
            }
        }
        if let Some(sr) = run.steps.get_mut(step_id) {
            sr.status = boatramp_core::workflow::StepStatus::Compensated;
            sr.updated = now_unix();
        }
    }
}

/// The input a step's function receives: for a root step, the run's initial input;
/// otherwise a JSON object mapping each dependency's step id → its output (as a
/// string). Data-transform is deliberately minimal (the scope guard).
#[cfg(feature = "handlers")]
fn build_step_input(
    run: &boatramp_core::workflow::WorkflowRun,
    step: &boatramp_core::workflow::Step,
) -> Vec<u8> {
    if step.depends_on.is_empty() {
        return run.input_b64.as_deref().map(b64_decode).unwrap_or_default();
    }
    let mut map = serde_json::Map::new();
    for dep in &step.depends_on {
        let out = run
            .steps
            .get(dep)
            .and_then(|r| r.output_b64.as_deref())
            .map(b64_decode)
            .unwrap_or_default();
        map.insert(
            dep.clone(),
            serde_json::Value::String(String::from_utf8_lossy(&out).into_owned()),
        );
    }
    serde_json::to_vec(&serde_json::Value::Object(map)).unwrap_or_default()
}

/// Build the engine request for a step: a `POST` carrying the input body as JSON.
#[cfg(feature = "handlers")]
fn build_step_request(input: Vec<u8>) -> Request {
    axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("/")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(input))
        .unwrap_or_else(|_| Request::new(axum::body::Body::empty()))
}
