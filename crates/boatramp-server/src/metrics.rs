//! In-memory handler observability: per-`(site, trigger,
//! route)` invocation counters plus a structured per-invocation log line. Cheap
//! enough to update on every invocation (a short critical section under one
//! mutex); read by the operator endpoint and the Prometheus exporter.
//!
//! Fuel/CPU metering is intentionally absent — the engine bounds invocations by
//! a wall-clock epoch deadline, and per-handler CPU fuel is an explicit
//! hardening item — so the recorded cost dimension is wall-clock `duration_ms`.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;

/// What triggered an invocation (the `trigger` field of the log line).
#[derive(Clone, Copy, Debug)]
pub enum Trigger {
    /// A public request matched a handler route.
    Http,
    /// The scheduler fired a due cron.
    Cron,
    /// The scheduler delivered a message to a consumer.
    Consumer,
    /// A direct `POST /api/functions/<name>/invoke` (sync or drained async).
    Invoke,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Cron => "cron",
            Self::Consumer => "consumer",
            Self::Invoke => "invoke",
        }
    }
}

/// The bucket a finished invocation falls into.
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Ok,
    Timeout,
    OutOfFuel,
    /// The guest exhausted its linear-memory budget (a denied `memory.grow` then a trap). Distinct
    /// from [`Trap`](Self::Trap) so the DLQ / stats read `out-of-memory` — an operator can tell memory
    /// exhaustion from a generic crash (construens async-lane-memory-budget request #4).
    OutOfMemory,
    Overloaded,
    Trap,
    /// A consumer returned a clean `Err` (a downstream denial/validation failure) — NOT a wasm trap.
    /// Distinct from [`Trap`](Self::Trap) so the DLQ reason reads `consumer-error`, legible as a guest
    /// -returned error rather than a crash (PLAN-async-persona legible-terminal-outcome taxonomy).
    ConsumerError,
    Error,
}

impl Outcome {
    /// Classify an engine result into an outcome bucket.
    pub fn from_result<T>(result: &Result<T, boatramp_handlers::HandlerError>) -> Self {
        use boatramp_handlers::HandlerError;
        match result {
            Ok(_) => Self::Ok,
            Err(HandlerError::Timeout) => Self::Timeout,
            Err(HandlerError::OutOfFuel) => Self::OutOfFuel,
            Err(HandlerError::OutOfMemory) => Self::OutOfMemory,
            Err(HandlerError::Overloaded) => Self::Overloaded,
            Err(HandlerError::Trap(_)) => Self::Trap,
            Err(HandlerError::ConsumerError(_)) => Self::ConsumerError,
            Err(HandlerError::Compile(_))
            | Err(HandlerError::NoResponse)
            | Err(HandlerError::Internal(_)) => Self::Error,
        }
    }

    /// The stable host-classification label. Also used as the dead-letter `last_error` (SEC6:
    /// host-reason-only), so the DLQ reason aligns with the operator's invocation-outcome buckets.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::OutOfFuel => "out-of-fuel",
            Self::OutOfMemory => "out-of-memory",
            Self::Overloaded => "overloaded",
            Self::Trap => "trap",
            Self::ConsumerError => "consumer-error",
            Self::Error => "error",
        }
    }
}

/// Aggregated counters for one `(site, trigger, route)` cell.
#[derive(Default, Clone, Serialize)]
pub struct Counters {
    pub invocations: u64,
    pub ok: u64,
    pub timeout: u64,
    pub out_of_fuel: u64,
    /// Guest linear-memory-budget exhaustion (distinct from `trap`) — construens async-lane #4.
    pub out_of_memory: u64,
    pub overloaded: u64,
    pub trap: u64,
    /// Clean consumer-returned errors (distinct from `trap`) — PLAN-async-persona taxonomy.
    pub consumer_error: u64,
    pub error: u64,
    /// Sum of wall-clock durations (for computing a mean in the UI).
    pub total_duration_ms: u64,
}

impl Counters {
    fn bump(&mut self, outcome: Outcome, duration: Duration) {
        self.invocations += 1;
        self.total_duration_ms += duration.as_millis() as u64;
        match outcome {
            Outcome::Ok => self.ok += 1,
            Outcome::Timeout => self.timeout += 1,
            Outcome::OutOfFuel => self.out_of_fuel += 1,
            Outcome::OutOfMemory => self.out_of_memory += 1,
            Outcome::Overloaded => self.overloaded += 1,
            Outcome::Trap => self.trap += 1,
            Outcome::ConsumerError => self.consumer_error += 1,
            Outcome::Error => self.error += 1,
        }
    }
}

/// One row of the operator stats response: a `(trigger, route)` and its counters.
#[derive(Serialize)]
pub struct HandlerStat {
    pub trigger: String,
    pub route: String,
    #[serde(flatten)]
    pub counters: Counters,
}

/// The process-wide handler metrics registry.
#[derive(Default)]
pub struct Metrics {
    // (site, trigger, route) -> counters. A `BTreeMap` so snapshots/exports are
    // deterministically ordered.
    inner: Mutex<BTreeMap<(String, &'static str, String), Counters>>,
    // Orphaned ready/indexed topics (v0.7.1): concrete topics with claimable work that NO active
    // consumer subscription covers (exact OR `{tenant}`-match), keyed topic -> claimable-message
    // count. Replaced wholesale each scheduler maintenance pass (a topic that gains a consumer, or
    // drains, simply drops out on the next pass). A `BTreeMap` so the export is deterministically
    // ordered. This is the single signal that surfaces the "declared-but-un-routable consumer /
    // producer-with-no-consumer" silent stuck-backlog defect.
    orphaned: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    /// Replace the set of **orphaned ready topics** (v0.7.1): concrete topics with claimable work
    /// that no active consumer subscription covers. The scheduler recomputes this cheaply each
    /// maintenance pass (a set-difference over the already-enumerated indexed topics vs the active
    /// consumers' matchers) and replaces the whole map, so a topic that gains a consumer or drains
    /// drops out on the next pass. Read by [`render_orphaned_gauges`](Self::render_orphaned_gauges)
    /// (Prometheus `orphaned_ready_topic{topic}`) and [`orphaned_topics`](Self::orphaned_topics)
    /// (the operator `stats` block).
    pub fn set_orphaned_topics(&self, topics: BTreeMap<String, u64>) {
        *self.orphaned.lock().unwrap() = topics;
    }

    /// A snapshot of the current orphaned ready topics (topic -> claimable count) for the operator
    /// `stats` view.
    pub fn orphaned_topics(&self) -> BTreeMap<String, u64> {
        self.orphaned.lock().unwrap().clone()
    }

    /// Render the orphaned-ready-topic gauges in Prometheus text format (v0.7.1): one
    /// `orphaned_ready_topic{topic="…"}` series per orphaned topic carrying its claimable-message
    /// count. Empty (no series) when nothing is orphaned — the healthy steady state.
    pub fn render_orphaned_gauges(&self) -> String {
        let map = self.orphaned.lock().unwrap();
        let mut out = String::new();
        out.push_str(
            "# HELP boatramp_orphaned_ready_topic Claimable messages on a topic no active consumer covers.\n\
             # TYPE boatramp_orphaned_ready_topic gauge\n",
        );
        for (topic, count) in map.iter() {
            out.push_str(&format!(
                "boatramp_orphaned_ready_topic{{topic=\"{}\"}} {}\n",
                escape(topic),
                count,
            ));
        }
        out
    }
    /// Record a finished invocation **and** emit the structured log line.
    // A telemetry sink: each argument is an orthogonal dimension of the `handler invocation` signal
    // (site/trigger/route/component/outcome/duration + the instance cold/instantiate timing), so
    // bundling them into a struct would only move the fan-out, not reduce it.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &self,
        site: &str,
        trigger: Trigger,
        route: &str,
        component_hash: &str,
        outcome: Outcome,
        duration: Duration,
        // Per-invocation instance timing (construens ask #3), when this invocation drove a serve:
        // `cold` = it paid a (re)compile; `instantiate_ms` = the per-invocation instantiate cost.
        // `None` on a path with no serve (e.g. a pre-serve refusal / the consumer lane) → logged as
        // `cold=false, instantiate_ms=0` so the line's schema is stable; the `outcome` disambiguates.
        cold: Option<bool>,
        instantiate_ms: Option<u64>,
    ) {
        {
            let mut map = self.inner.lock().unwrap();
            map.entry((site.to_string(), trigger.as_str(), route.to_string()))
                .or_default()
                .bump(outcome, duration);
        }
        tracing::info!(
            target: "boatramp::handler",
            site,
            trigger = trigger.as_str(),
            route,
            component = component_hash,
            outcome = outcome.as_str(),
            duration_ms = duration.as_millis() as u64,
            cold = cold.unwrap_or(false),
            instantiate_ms = instantiate_ms.unwrap_or(0),
            "handler invocation"
        );
    }

    /// Per-`(trigger, route)` stats for one site (operator endpoint).
    pub fn snapshot_site(&self, site: &str) -> Vec<HandlerStat> {
        let map = self.inner.lock().unwrap();
        map.iter()
            .filter(|((s, _, _), _)| s == site)
            .map(|((_, trigger, route), counters)| HandlerStat {
                trigger: (*trigger).to_string(),
                route: route.clone(),
                counters: counters.clone(),
            })
            .collect()
    }

    /// Render all counters in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let map = self.inner.lock().unwrap();
        let mut out = String::new();
        out.push_str(
            "# HELP boatramp_handler_invocations_total Handler invocations by site, trigger, route, outcome.\n\
             # TYPE boatramp_handler_invocations_total counter\n",
        );
        for ((site, trigger, route), c) in map.iter() {
            for (outcome, value) in [
                ("ok", c.ok),
                ("timeout", c.timeout),
                ("out-of-fuel", c.out_of_fuel),
                ("out-of-memory", c.out_of_memory),
                ("overloaded", c.overloaded),
                ("trap", c.trap),
                ("consumer-error", c.consumer_error),
                ("error", c.error),
            ] {
                out.push_str(&format!(
                    "boatramp_handler_invocations_total{{site=\"{}\",trigger=\"{}\",route=\"{}\",outcome=\"{}\"}} {}\n",
                    escape(site),
                    trigger,
                    escape(route),
                    outcome,
                    value,
                ));
            }
        }
        out.push_str(
            "# HELP boatramp_handler_duration_ms_total Summed wall-clock invocation duration (ms).\n\
             # TYPE boatramp_handler_duration_ms_total counter\n",
        );
        for ((site, trigger, route), c) in map.iter() {
            out.push_str(&format!(
                "boatramp_handler_duration_ms_total{{site=\"{}\",trigger=\"{}\",route=\"{}\"}} {}\n",
                escape(site),
                trigger,
                escape(route),
                c.total_duration_ms,
            ));
        }
        out
    }
}

/// One consumer's live queue gauges for the Prometheus exporter (queue depth /
/// consumer lag / DLQ). Gathered from the messaging backend at
/// scrape time (not a running counter), so it reflects current state.
pub struct ConsumerGauge {
    /// The site the consumer belongs to.
    pub site: String,
    /// The deployment scope (site, or `{site}/{alias}`).
    pub scope: String,
    /// The consumer's scope-relative topic.
    pub topic: String,
    /// Messages still queued (claimable or leased) — depth / consumer lag.
    pub backlog: usize,
    /// Messages parked in the dead-letter store.
    pub dead_letters: usize,
}

/// Render consumer queue depth + dead-letter gauges in Prometheus text format.
/// Separate from [`Metrics::render_prometheus`] because these are sampled from
/// the messaging backend at scrape time rather than accumulated per invocation.
pub fn render_consumer_gauges(rows: &[ConsumerGauge]) -> String {
    let mut out = String::new();
    out.push_str(
        "# HELP boatramp_consumer_backlog Messages queued (claimable or leased) per consumer.\n\
         # TYPE boatramp_consumer_backlog gauge\n",
    );
    for r in rows {
        out.push_str(&format!(
            "boatramp_consumer_backlog{{site=\"{}\",scope=\"{}\",topic=\"{}\"}} {}\n",
            escape(&r.site),
            escape(&r.scope),
            escape(&r.topic),
            r.backlog,
        ));
    }
    out.push_str(
        "# HELP boatramp_consumer_dead_letters Dead-lettered messages per consumer.\n\
         # TYPE boatramp_consumer_dead_letters gauge\n",
    );
    for r in rows {
        out.push_str(&format!(
            "boatramp_consumer_dead_letters{{site=\"{}\",scope=\"{}\",topic=\"{}\"}} {}\n",
            escape(&r.site),
            escape(&r.scope),
            escape(&r.topic),
            r.dead_letters,
        ));
    }
    out
}

/// Escape a Prometheus label value (`\`, `"`, newline).
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Public wrapper over [`escape`] for callers rendering their own series (e.g. the
/// FA-4 function-usage gauges).
pub fn escape_label(value: &str) -> String {
    escape(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_gauges_render_depth_and_dlq() {
        let rows = [
            ConsumerGauge {
                site: "blog".into(),
                scope: "blog".into(),
                topic: "orders/created".into(),
                backlog: 5,
                dead_letters: 2,
            },
            ConsumerGauge {
                site: "shop".into(),
                scope: "shop/staging".into(),
                topic: "events".into(),
                backlog: 0,
                dead_letters: 0,
            },
        ];
        let out = render_consumer_gauges(&rows);
        assert!(out.contains("# TYPE boatramp_consumer_backlog gauge"));
        assert!(out.contains(
            "boatramp_consumer_backlog{site=\"blog\",scope=\"blog\",topic=\"orders/created\"} 5"
        ));
        assert!(out.contains("# TYPE boatramp_consumer_dead_letters gauge"));
        assert!(out.contains(
            "boatramp_consumer_dead_letters{site=\"blog\",scope=\"blog\",topic=\"orders/created\"} 2"
        ));
        assert!(out.contains(
            "boatramp_consumer_backlog{site=\"shop\",scope=\"shop/staging\",topic=\"events\"} 0"
        ));
    }
}
