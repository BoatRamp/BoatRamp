# Metrics & access-log fields

boatramp exports Prometheus metrics and a structured access log from the same
serving path. This page lists the exported metrics and the access-log fields. For
how to scrape and read them, see [Observe a running server](../how-to/observe.md).

The Prometheus exporter at `/api/metrics` is admin-scoped. The handler and
consumer metrics are present only when the binary is built with the `handlers`
feature.

## Prometheus metrics

Exported at `/api/metrics`.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `boatramp_http_requests_total` | counter | `status_class`, `cache_result` | Requests by status class (`2xx` / `3xx` / …) and cache result. |
| `boatramp_http_response_bytes_total` | counter | — | Total response body bytes streamed. |
| `boatramp_deployments_total` | counter | — | Deployment manifests created. |
| `boatramp_activations_total` | counter | — | Activations (live / alias pointer flips). |
| `boatramp_cert_renewals_total` | counter | — | ACME certificate issues and renewals. |
| `boatramp_daemon_config_info` | gauge | `generation` | Always `1`; the `generation` label is the active [dynamic-config](./daemon-config.md) content address (`none` on the pure file baseline). Scrape it fleet-wide to confirm every node converged. |

With the `handlers` feature the exporter also renders per-`(site, trigger,
route)` handler-invocation counters and per-consumer queue-depth and dead-letter
gauges.

## Access-log fields

Every request is logged on the `boatramp::access` tracing target. Set
`BOATRAMP_LOG_FORMAT=json` for a machine-readable sink; verbosity follows
`RUST_LOG` (default `boatramp=info`).

| Field | Meaning |
| --- | --- |
| `method` | HTTP request method. |
| `path` | Request path. |
| `host` | Request host. |
| `client_ip` | Client IP address. |
| `status` | Response status code. |
| `bytes` | Response body bytes. |
| `encoding` | Content encoding applied to the response. |
| `cache_result` | Cache outcome for the request (see below). |
| `duration_ms` | Time taken to serve the request, in milliseconds. |

### `cache_result` values

| Value | Meaning |
| --- | --- |
| `full` | Served fully from cache. |
| `partial` | Partial-content (`Range`) response. |
| `not-modified` | Conditional request answered `304`. |
| `redirect` | Answered with a redirect. |
| `error` | Answered with an error. |
