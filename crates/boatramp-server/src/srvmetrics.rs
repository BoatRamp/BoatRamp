//! Process-wide HTTP/lifecycle metrics: request-level
//! dimensions (status class + cache result + response bytes) plus deploy and
//! certificate-renewal counters. These complement the per-`(site, trigger,
//! route)` handler counters in [`crate::metrics`] (which exist only with the
//! `handlers` feature) and are always-on, so the Prometheus endpoint reports
//! serving health even on a build without handlers.
//!
//! Server metrics are genuinely *process*-global (one HTTP listener, one deploy
//! store), so they live in a [`std::sync::LazyLock`] reached via
//! [`server_metrics`] rather than threaded through every handler signature —
//! the access-log middleware, the deploy handlers, and the certificate-renewal
//! path (in the CLI crate) all record against the same registry.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

/// The process-wide server-metrics registry.
pub static SERVER_METRICS: LazyLock<ServerMetrics> = LazyLock::new(ServerMetrics::default);

/// The process-wide [`ServerMetrics`]. Cheap to call (no allocation).
pub fn server_metrics() -> &'static ServerMetrics {
    &SERVER_METRICS
}

/// Always-on HTTP + lifecycle counters. Request cells are keyed by
/// `(status_class, cache_result)`; the rest are scalar totals.
#[derive(Default)]
pub struct ServerMetrics {
    requests: Mutex<std::collections::BTreeMap<(&'static str, &'static str), u64>>,
    response_bytes: AtomicU64,
    deployments: AtomicU64,
    activations: AtomicU64,
    cert_renewals: AtomicU64,
}

impl ServerMetrics {
    /// Record a finished HTTP request: its status class (`2xx`…), the coarse
    /// cache result derived from the status, and the bytes streamed back.
    pub fn record_request(&self, status: u16, bytes: u64) {
        self.response_bytes.fetch_add(bytes, Ordering::Relaxed);
        let mut map = self.requests.lock().unwrap();
        *map.entry((status_class(status), cache_result(status)))
            .or_insert(0) += 1;
    }

    /// Record a deployment manifest having been created.
    pub fn record_deployment(&self) {
        self.deployments.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a deployment activation (the live/alias pointer flip).
    pub fn record_activation(&self) {
        self.activations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a TLS certificate (re)issue (ACME issuance / renewal).
    pub fn record_cert_renewal(&self) {
        self.cert_renewals.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the counters in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# HELP boatramp_http_requests_total HTTP requests by status class and cache result.\n\
             # TYPE boatramp_http_requests_total counter\n",
        );
        for ((class, cache), value) in self.requests.lock().unwrap().iter() {
            out.push_str(&format!(
                "boatramp_http_requests_total{{status_class=\"{class}\",cache_result=\"{cache}\"}} {value}\n"
            ));
        }
        for (name, help, value) in [
            (
                "boatramp_http_response_bytes_total",
                "Total response body bytes streamed.",
                self.response_bytes.load(Ordering::Relaxed),
            ),
            (
                "boatramp_deployments_total",
                "Deployment manifests created.",
                self.deployments.load(Ordering::Relaxed),
            ),
            (
                "boatramp_activations_total",
                "Deployment activations (live/alias pointer flips).",
                self.activations.load(Ordering::Relaxed),
            ),
            (
                "boatramp_cert_renewals_total",
                "TLS certificate issues/renewals.",
                self.cert_renewals.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        out
    }
}

/// The status class label (`2xx`, `3xx`, …) for a response code.
fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// A coarse cache outcome derived from the status: a conditional/range hit vs a
/// full body vs a redirect/error. Shared with the access-log line so the log and
/// the metric agree on the classification.
pub fn cache_result(status: u16) -> &'static str {
    match status {
        304 => "not-modified",
        206 => "partial",
        200 => "full",
        s if (300..400).contains(&s) => "redirect",
        s if s >= 400 => "error",
        _ => "-",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_renders_request_dimensions() {
        let m = ServerMetrics::default();
        m.record_request(200, 1024);
        m.record_request(200, 512);
        m.record_request(304, 0);
        m.record_request(404, 48);
        m.record_deployment();
        m.record_activation();
        m.record_cert_renewal();

        let out = m.render_prometheus();
        assert!(out.contains("# TYPE boatramp_http_requests_total counter"));
        assert!(out.contains(
            "boatramp_http_requests_total{status_class=\"2xx\",cache_result=\"full\"} 2"
        ));
        assert!(out.contains(
            "boatramp_http_requests_total{status_class=\"3xx\",cache_result=\"not-modified\"} 1"
        ));
        assert!(out.contains(
            "boatramp_http_requests_total{status_class=\"4xx\",cache_result=\"error\"} 1"
        ));
        assert!(out.contains("boatramp_http_response_bytes_total 1584"));
        assert!(out.contains("boatramp_deployments_total 1"));
        assert!(out.contains("boatramp_activations_total 1"));
        assert!(out.contains("boatramp_cert_renewals_total 1"));
    }

    #[test]
    fn cache_result_classifies_status() {
        assert_eq!(cache_result(200), "full");
        assert_eq!(cache_result(206), "partial");
        assert_eq!(cache_result(304), "not-modified");
        assert_eq!(cache_result(301), "redirect");
        assert_eq!(cache_result(500), "error");
    }
}
