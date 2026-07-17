//! FA-6 declarative **workflow** orchestration — a small DAG of function-invocation
//! steps with durable state, retries, fan-in/fan-out barriers, and on-failure
//! compensation. Deliberately *not* a general workflow/BPMN engine (the PLAN-faas
//! scope guard): a step is one function invocation, edges are `depends_on`, and the
//! executor advances the DAG on the same KV-durable + scheduler-drain substrate the
//! async invocation queue uses (Raft-replicated in cluster mode).
//!
//! A **chain** is a linear `depends_on`; a **fan-out** is many steps depending on
//! one; a **fan-in / barrier join** is one step depending on many. On a step's
//! terminal failure the run fails and each already-succeeded step's `compensate`
//! function runs in reverse completion order.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A step's retry policy — fixed attempts; the drain re-runs a failed step on a
/// later tick until `max_attempts` is reached, then the step (and run) fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Max attempts before the step is failed (default `1` = no retry).
    #[serde(default = "one")]
    pub max_attempts: u32,
}

fn one() -> u32 {
    1
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 1 }
    }
}

/// One workflow step: invoke `function` once every step in `depends_on` has
/// succeeded. `depends_on` with more than one entry is a fan-in barrier; empty is
/// a root step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Unique step id within the workflow.
    pub id: String,
    /// The function to invoke (active version).
    pub function: String,
    /// Step ids that must succeed first (empty = a root step).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Retry policy for this step.
    #[serde(default)]
    pub retry: RetryPolicy,
    /// A compensation function invoked if the run fails *after* this step
    /// succeeded (rollback runs compensations in reverse completion order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensate: Option<String>,
}

/// A declarative workflow: a DAG of function-invocation steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    /// Unique workflow name.
    pub name: String,
    /// The steps (any order; edges are `depends_on`).
    pub steps: Vec<Step>,
}

impl Workflow {
    /// Validate the DAG: non-empty, unique step ids, every `depends_on` resolves,
    /// and no cycle. `Err(reason)` describes the first problem found.
    pub fn validate(&self) -> Result<(), String> {
        if self.steps.is_empty() {
            return Err("workflow has no steps".to_string());
        }
        let mut ids = BTreeSet::new();
        for step in &self.steps {
            if !ids.insert(step.id.as_str()) {
                return Err(format!("duplicate step id {:?}", step.id));
            }
        }
        for step in &self.steps {
            for dep in &step.depends_on {
                if !ids.contains(dep.as_str()) {
                    return Err(format!("step {:?} depends on unknown {dep:?}", step.id));
                }
                if dep == &step.id {
                    return Err(format!("step {:?} depends on itself", step.id));
                }
            }
        }
        self.check_acyclic()
    }

    /// A step by id.
    pub fn step(&self, id: &str) -> Option<&Step> {
        self.steps.iter().find(|s| s.id == id)
    }

    /// Depth-first cycle detection over the `depends_on` edges.
    fn check_acyclic(&self) -> Result<(), String> {
        // 0 = unvisited, 1 = on the current path, 2 = done.
        let mut state: BTreeMap<&str, u8> =
            self.steps.iter().map(|s| (s.id.as_str(), 0u8)).collect();
        // Iterative DFS to avoid recursion depth limits on a large workflow.
        for root in &self.steps {
            if state[root.id.as_str()] != 0 {
                continue;
            }
            let mut stack: Vec<(&str, usize)> = vec![(root.id.as_str(), 0)];
            while let Some((id, idx)) = stack.pop() {
                let step = self.step(id).expect("id came from steps");
                if idx == 0 {
                    state.insert(id, 1);
                }
                if idx < step.depends_on.len() {
                    stack.push((id, idx + 1));
                    let dep = step.depends_on[idx].as_str();
                    match state[dep] {
                        1 => return Err(format!("cycle through step {dep:?}")),
                        0 => stack.push((dep, 0)),
                        _ => {}
                    }
                } else {
                    state.insert(id, 2);
                }
            }
        }
        Ok(())
    }
}

/// A step's run state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Not yet started (deps unmet or waiting for a drain tick).
    #[default]
    Pending,
    /// Executing.
    Running,
    /// Completed successfully.
    Succeeded,
    /// Exhausted its retries.
    Failed,
    /// Was rolled back by its `compensate` function after a downstream failure.
    Compensated,
}

/// The run state of a workflow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    /// Steps still executing.
    #[default]
    Running,
    /// Every step succeeded.
    Succeeded,
    /// A step failed (after retries); completed steps were compensated.
    Failed,
}

/// One step's durable run record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRun {
    /// The step id.
    pub id: String,
    /// Current status.
    pub status: StepStatus,
    /// Attempts so far.
    #[serde(default)]
    pub attempts: u32,
    /// The step function's response body, base64 (its output, wired to dependents).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_b64: Option<String>,
    /// Last update (unix seconds).
    pub updated: u64,
}

/// A durable workflow run — the unit the executor advances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRun {
    /// Opaque run id.
    pub id: String,
    /// The workflow this runs.
    pub workflow: String,
    /// Overall status.
    pub status: WorkflowStatus,
    /// Per-step run state, by step id.
    pub steps: BTreeMap<String, StepRun>,
    /// The order steps *succeeded* in (for reverse-order compensation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_order: Vec<String>,
    /// The run's initial input, base64 (delivered to root steps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_b64: Option<String>,
    /// Unix create time.
    pub created: u64,
    /// Unix last-update time.
    pub updated: u64,
}

impl WorkflowRun {
    /// A fresh run of `workflow`: every step `pending`.
    pub fn start(
        workflow: &Workflow,
        id: impl Into<String>,
        input_b64: Option<String>,
        now: u64,
    ) -> Self {
        let steps = workflow
            .steps
            .iter()
            .map(|s| {
                (
                    s.id.clone(),
                    StepRun {
                        id: s.id.clone(),
                        status: StepStatus::Pending,
                        attempts: 0,
                        output_b64: None,
                        updated: now,
                    },
                )
            })
            .collect();
        Self {
            id: id.into(),
            workflow: workflow.name.clone(),
            status: WorkflowStatus::Running,
            steps,
            completed_order: Vec::new(),
            input_b64,
            created: now,
            updated: now,
        }
    }

    /// Whether the run reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            WorkflowStatus::Succeeded | WorkflowStatus::Failed
        )
    }

    /// Step ids that are `pending` and whose every dependency has `succeeded` —
    /// the steps a drain tick may run now (fan-out yields several at once; a
    /// fan-in step appears only once all its deps are done).
    pub fn ready_steps(&self, workflow: &Workflow) -> Vec<String> {
        workflow
            .steps
            .iter()
            .filter(|step| {
                self.steps
                    .get(&step.id)
                    .is_some_and(|r| r.status == StepStatus::Pending)
                    && step.depends_on.iter().all(|dep| {
                        self.steps
                            .get(dep)
                            .is_some_and(|r| r.status == StepStatus::Succeeded)
                    })
            })
            .map(|s| s.id.clone())
            .collect()
    }

    /// Whether every step has succeeded (⇒ the run succeeds).
    pub fn all_succeeded(&self) -> bool {
        self.steps
            .values()
            .all(|r| r.status == StepStatus::Succeeded)
    }
}

/// KV keyspace for workflows (definitions + runs), mirroring the function keyspace.
pub mod keys {
    /// A workflow definition.
    pub fn definition(name: &str) -> String {
        format!("workflows/{name}")
    }
    /// A workflow run.
    pub fn run(name: &str, id: &str) -> String {
        format!("workflows/{name}/runs/{id}")
    }
    /// The prefix under which all of a workflow's runs live.
    pub fn runs_prefix(name: &str) -> String {
        format!("workflows/{name}/runs/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(id: &str, deps: &[&str]) -> Step {
        Step {
            id: id.to_string(),
            function: format!("fn-{id}"),
            depends_on: deps.iter().map(std::string::ToString::to_string).collect(),
            retry: RetryPolicy::default(),
            compensate: None,
        }
    }

    #[test]
    fn validate_catches_dupes_missing_deps_and_cycles() {
        // A valid chain a -> b -> c.
        let ok = Workflow {
            name: "w".into(),
            steps: vec![step("a", &[]), step("b", &["a"]), step("c", &["b"])],
        };
        assert!(ok.validate().is_ok());

        // Empty.
        assert!(Workflow {
            name: "w".into(),
            steps: vec![]
        }
        .validate()
        .is_err());

        // Duplicate id.
        assert!(Workflow {
            name: "w".into(),
            steps: vec![step("a", &[]), step("a", &[])],
        }
        .validate()
        .is_err());

        // Unknown dep.
        assert!(Workflow {
            name: "w".into(),
            steps: vec![step("a", &["ghost"])],
        }
        .validate()
        .is_err());

        // Cycle a -> b -> a.
        assert!(Workflow {
            name: "w".into(),
            steps: vec![step("a", &["b"]), step("b", &["a"])],
        }
        .validate()
        .is_err());
    }

    #[test]
    fn ready_steps_respects_the_dag_barrier() {
        // Fan-out + fan-in: root -> {x, y} -> join.
        let wf = Workflow {
            name: "w".into(),
            steps: vec![
                step("root", &[]),
                step("x", &["root"]),
                step("y", &["root"]),
                step("join", &["x", "y"]),
            ],
        };
        assert!(wf.validate().is_ok());
        let mut run = WorkflowRun::start(&wf, "r1", None, 0);
        // Only the root is ready first.
        assert_eq!(run.ready_steps(&wf), vec!["root".to_string()]);

        // Root done → x and y both ready (fan-out); join not yet (barrier).
        run.steps.get_mut("root").unwrap().status = StepStatus::Succeeded;
        let ready: BTreeSet<String> = run.ready_steps(&wf).into_iter().collect();
        assert_eq!(ready, BTreeSet::from(["x".to_string(), "y".to_string()]));

        // Only x done → join still blocked on y.
        run.steps.get_mut("x").unwrap().status = StepStatus::Succeeded;
        assert!(!run.ready_steps(&wf).contains(&"join".to_string()));

        // Both done → join ready (fan-in barrier released).
        run.steps.get_mut("y").unwrap().status = StepStatus::Succeeded;
        assert_eq!(run.ready_steps(&wf), vec!["join".to_string()]);

        // All done → the run may succeed.
        run.steps.get_mut("join").unwrap().status = StepStatus::Succeeded;
        assert!(run.all_succeeded());
    }

    #[test]
    fn run_serde_round_trips_and_reports_terminal() {
        let wf = Workflow {
            name: "w".into(),
            steps: vec![step("a", &[])],
        };
        let run = WorkflowRun::start(&wf, "r1", Some("aGk=".into()), 5);
        assert!(!run.is_terminal());
        let json = serde_json::to_string(&run).unwrap();
        let back: WorkflowRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back, run);
        assert!(json.contains("\"status\":\"running\""));
    }

    #[test]
    fn keyspace_is_stable() {
        assert_eq!(keys::definition("etl"), "workflows/etl");
        assert_eq!(keys::run("etl", "r1"), "workflows/etl/runs/r1");
        assert_eq!(keys::runs_prefix("etl"), "workflows/etl/runs/");
    }
}
