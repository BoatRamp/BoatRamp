//! A bounded, shared wait for a **managed database** to become ready, used by the managed-DB
//! client paths (`boatramp sql exec` / `sql query` and `boatramp project migrate …`).
//!
//! A still-provisioning managed backend answers a managed-DB operation with a **retryable `503` +
//! `Retry-After`** (`SqlError::Unavailable` server-side — the backend is starting / has no healthy
//! replica; the same not-ready state `GET /api/sql/{db}/status`'s readiness probe reports with a
//! `retry_after_secs` hint). Before this module the CLI ignored both signals and failed the op
//! immediately on a managed-pg cold start.
//!
//! Rather than each call site building a *second* readiness probe (poll `/status`, then run the op
//! — a TOCTOU gap, and a parallel code path), there is **one** wait helper,
//! [`send_with_ready_wait`], that binds the operation's OWN retryable 503: it re-issues the request,
//! sleeps the advertised `Retry-After`, and retries until a bounded budget elapses, then hands the
//! final response back to the caller to handle exactly as before. This consolidates the wait into a
//! single seam the managed-DB client paths share (consolidate, don't parallelize).

use std::future::Future;
use std::time::{Duration, Instant};

/// The default bounded wait for a still-provisioning managed database, in seconds — generous
/// enough to cover a managed backend's first cold start (image pull + init), the case the
/// tokenfield DX report hit. Tunable per-invocation via `--wait-ready-secs`.
pub(crate) const DEFAULT_WAIT_READY_SECS: u64 = 120;

/// The fallback inter-attempt delay when a not-ready `503` carries no (or an unparseable)
/// `Retry-After` — matches the server's advertised hint (`SQL_NOT_READY_RETRY_AFTER_SECS`).
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(2);

/// A floor on the inter-attempt sleep, so a `Retry-After: 0` (or a tiny value) can never spin the
/// retry loop into a hot CPU/network hammer while still inside the budget.
const MIN_SLEEP: Duration = Duration::from_millis(50);

/// How long to wait on a still-provisioning managed database before giving up. `budget` of
/// [`Duration::ZERO`] ⇒ **don't wait**: make exactly one attempt and surface a not-ready response
/// immediately (scripting / `--no-wait`).
#[derive(Debug, Clone, Copy)]
pub struct WaitPolicy {
    budget: Duration,
}

impl WaitPolicy {
    /// A policy that waits up to `budget` for readiness.
    pub fn new(budget: Duration) -> Self {
        Self { budget }
    }

    /// A policy that does not wait: one attempt, then surface whatever came back.
    pub fn no_wait() -> Self {
        Self {
            budget: Duration::ZERO,
        }
    }
}

/// The two wait knobs shared by every managed-DB apply subcommand (`sql exec`, `sql query`,
/// `project migrate apply` / `dry-run` / `baseline`), flattened into each with `#[command(flatten)]`
/// so the behaviour and help are identical everywhere.
#[derive(Debug, Clone, clap::Args)]
pub struct WaitFlags {
    /// Max seconds to wait for a still-provisioning managed database to become ready before
    /// failing (`0` = don't wait — fail immediately if the backend isn't ready). The default
    /// covers a managed backend's first cold start (image pull + init). While waiting, the
    /// command honours the server's retryable `503` + `Retry-After`.
    #[arg(long, default_value_t = DEFAULT_WAIT_READY_SECS, value_name = "SECS")]
    wait_ready_secs: u64,

    /// Don't wait for a provisioning managed database — fail immediately if it isn't ready yet
    /// (for scripting / CI). Equivalent to `--wait-ready-secs 0`.
    #[arg(long, conflicts_with = "wait_ready_secs")]
    no_wait: bool,
}

impl WaitFlags {
    /// Resolve the flags to a [`WaitPolicy`]. `--no-wait` (or `--wait-ready-secs 0`) ⇒ no wait.
    pub fn policy(&self) -> WaitPolicy {
        if self.no_wait || self.wait_ready_secs == 0 {
            WaitPolicy::no_wait()
        } else {
            WaitPolicy::new(Duration::from_secs(self.wait_ready_secs))
        }
    }

    /// A waiting policy of `secs` seconds (test/helper constructor — the clap path uses `policy`).
    #[cfg(test)]
    pub(crate) fn waiting(secs: u64) -> Self {
        Self {
            wait_ready_secs: secs,
            no_wait: false,
        }
    }

    /// A non-waiting policy (test/helper constructor).
    #[cfg(test)]
    pub(crate) fn never() -> Self {
        Self {
            wait_ready_secs: 0,
            no_wait: true,
        }
    }
}

/// Parse a `Retry-After` **delta-seconds** header into a [`Duration`]. The server only ever emits
/// delta-seconds (never an HTTP-date), so a non-integer value falls back to [`None`] (the caller
/// uses [`DEFAULT_RETRY_AFTER`]).
fn parse_retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Send a managed-DB request, **waiting** on a still-provisioning backend.
///
/// `op` builds and sends a **fresh** request each call (so a retry re-issues cleanly). While the
/// response is a retryable managed-not-ready `503`, this honours its `Retry-After` and retries until
/// `policy`'s budget elapses; then it returns the final response — a success, a terminal error, or
/// the last `503` once the budget is spent — for the caller to handle exactly as it did before.
///
/// It always makes **at least one** attempt, so `WaitPolicy::no_wait` still runs the operation once
/// (failing immediately on a `503`). A never-ready backend returns a `503` cleanly at the bounded
/// timeout — never a hang, never a silent immediate failure.
pub async fn send_with_ready_wait<F, Fut>(
    policy: WaitPolicy,
    mut op: F,
) -> reqwest::Result<reqwest::Response>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = reqwest::Result<reqwest::Response>>,
{
    let deadline = Instant::now() + policy.budget;
    let mut announced = false;
    loop {
        let resp = op().await?;
        // A still-provisioning managed backend is the ONLY thing that answers a retryable `503`
        // (+ `Retry-After`). Anything else — a success or a terminal error (400/409/501/…) — is
        // handed straight back; waiting is only for the transient not-ready state.
        if resp.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE {
            return Ok(resp);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // Budget spent (or `no_wait`): surface the 503 for the caller to render.
            return Ok(resp);
        }
        // Sleep the advertised Retry-After, floored (anti-hammer) and capped to the budget left.
        let sleep = parse_retry_after(&resp)
            .unwrap_or(DEFAULT_RETRY_AFTER)
            .max(MIN_SLEEP)
            .min(remaining);
        if !announced {
            tracing::info!(
                "managed database not ready yet (still provisioning); waiting up to {}s for it \
                 to become ready…",
                policy.budget.as_secs()
            );
            announced = true;
        }
        drop(resp);
        tokio::time::sleep(sleep).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Spawn a mock control-plane endpoint on a loopback port whose `POST /op` answers a retryable
    /// `503` + `Retry-After: 0` for the first `fail_n` requests, then `204 No Content`. Returns the
    /// base URL and the shared hit counter so a test can assert how many attempts were made.
    async fn spawn_flaky_op(fail_n: usize) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_route = Arc::clone(&hits);
        let app = axum::Router::new().route(
            "/op",
            axum::routing::post(move || {
                let hits = Arc::clone(&hits_route);
                async move {
                    let n = hits.fetch_add(1, Ordering::SeqCst);
                    if n < fail_n {
                        // Retry-After: 0 → the helper floors to MIN_SLEEP, keeping the test fast.
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            [(axum::http::header::RETRY_AFTER, "0")],
                            "managed database not ready\n",
                        )
                            .into_response()
                    } else {
                        axum::http::StatusCode::NO_CONTENT.into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://127.0.0.1:{}", addr.port()), hits)
    }

    use axum::response::IntoResponse;

    #[tokio::test]
    async fn waits_through_pending_then_succeeds_once_ready() {
        // 503 twice, then 204: with a generous budget the wait-loop binds and the op succeeds,
        // after exactly 3 attempts. (MUTATION PROOF: delete the retry loop in
        // `send_with_ready_wait` — a single send — and this fails, seeing the first 503.)
        let (base, hits) = spawn_flaky_op(2).await;
        let client = reqwest::Client::new();
        let url = format!("{base}/op");
        let resp = send_with_ready_wait(WaitPolicy::new(Duration::from_secs(10)), || {
            client.post(&url).send()
        })
        .await
        .expect("request transport ok");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::NO_CONTENT,
            "the op succeeds once the backend is ready"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "two not-ready attempts, then the ready one"
        );
    }

    #[tokio::test]
    async fn never_ready_fails_cleanly_at_the_bounded_timeout() {
        // Always 503: a bounded budget returns the 503 (not an Err, not a hang), and only after
        // roughly the budget — never an immediate fail.
        let (base, hits) = spawn_flaky_op(usize::MAX).await;
        let client = reqwest::Client::new();
        let url = format!("{base}/op");
        let budget = Duration::from_millis(300);
        let start = Instant::now();
        let resp = send_with_ready_wait(WaitPolicy::new(budget), || client.post(&url).send())
            .await
            .expect("request transport ok");
        let elapsed = start.elapsed();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "a never-ready backend surfaces the 503 at the timeout"
        );
        assert!(
            elapsed >= Duration::from_millis(250),
            "it actually waited ~the budget, not an immediate fail (elapsed {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "it did not hang past the bounded timeout (elapsed {elapsed:?})"
        );
        assert!(
            hits.load(Ordering::SeqCst) >= 2,
            "it retried more than once within the budget"
        );
    }

    #[tokio::test]
    async fn no_wait_makes_exactly_one_attempt() {
        // `no_wait` surfaces the first 503 immediately (one attempt) — the scripting escape hatch.
        let (base, hits) = spawn_flaky_op(usize::MAX).await;
        let client = reqwest::Client::new();
        let url = format!("{base}/op");
        let start = Instant::now();
        let resp = send_with_ready_wait(WaitPolicy::no_wait(), || client.post(&url).send())
            .await
            .expect("request transport ok");
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "no_wait makes exactly one attempt"
        );
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "no_wait does not sleep"
        );
    }

    #[test]
    fn flags_map_to_policy() {
        // `--no-wait` and `--wait-ready-secs 0` both mean don't wait; a positive value waits.
        assert_eq!(WaitFlags::never().policy().budget, Duration::ZERO);
        assert_eq!(
            WaitFlags::waiting(0).policy().budget,
            Duration::ZERO,
            "--wait-ready-secs 0 is no-wait"
        );
        assert_eq!(
            WaitFlags::waiting(45).policy().budget,
            Duration::from_secs(45)
        );
    }
}
