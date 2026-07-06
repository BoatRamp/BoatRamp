# Observability

## Access logs

Every request is logged via the `boatramp::access` tracing target: method, path,
host, client IP, status, **bytes**, **encoding**, **cache-result**
(full / partial / not-modified / redirect / error), and duration. Set
`BOATRAMP_LOG_FORMAT=json` for a machine-readable JSON sink:

```sh
BOATRAMP_LOG_FORMAT=json boatramp serve
```

Log verbosity follows `RUST_LOG` (default `boatramp=info`).

## Health checks

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | Liveness — the process is up. |
| `/readyz` | Readiness — a cheap KV probe; `503` when the metadata backend is unreachable. |

## Metrics

An admin-scoped Prometheus exporter is **always** served at `/api/metrics`. It
carries the process-wide serving + lifecycle counters:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `boatramp_http_requests_total` | `status_class`, `cache_result` | requests by 2xx/3xx/… and full/partial/not-modified/redirect/error (cache-hit ratio is derivable) |
| `boatramp_http_response_bytes_total` | — | total response body bytes streamed |
| `boatramp_deployments_total` | — | deployment manifests created |
| `boatramp_activations_total` | — | activations (live/alias pointer flips) |
| `boatramp_cert_renewals_total` | — | ACME certificate issues/renewals |

With the `handlers` feature it additionally renders per-`(site, trigger, route)`
handler-invocation counters and per-consumer queue-depth / dead-letter gauges.
The same per-request dimensions are also in the structured access log.

## Guest logs & handler stats

For sites running handlers:

```sh
boatramp logs  --site my-site --follow     # tail captured guest stdout/stderr
boatramp stats --site my-site              # invocation counts, consumer lag, DLQ
```

A per-site `max_log_rate` cap prevents a noisy guest from flooding the sink
(over-cap lines are dropped and counted).

### Dead-letter queue

Messages that exhaust `max_attempts` are **dead-lettered** (kept, with their
payload, for inspection — counted in `stats`). Clear or replay them with:

```sh
boatramp dlq redrive my-topic --site my-site   # requeue with a fresh attempt count
boatramp dlq purge   my-topic --site my-site   # drop them (records + payloads)
```

Redrive once the cause of failure is fixed; purge to reclaim the space. (Add
`--alias <name>` to target a background-alias consumer's queue.)

## Graceful shutdown

Ctrl-C / SIGTERM drains in-flight requests under a deadline (the plain listener
via graceful shutdown; TLS via an `axum_server` handle). In-flight handler
invocations finish within their own epoch timeout.
