# Observe a running server

This page covers the four ways to watch a running boatramp server: the JSON
access log, the health endpoints, the Prometheus metrics endpoint, and the
per-site CLI (`logs` and `stats`). Each is one command or one endpoint away.

For the full metric list and the full set of access-log fields, see the
[metrics reference](../reference/metrics.md). This page covers only how to reach
them.

## Read the access log

Every request is logged on the `boatramp::access` tracing target. Set
`BOATRAMP_LOG_FORMAT=json` for a machine-readable sink, and start the server:

```sh
BOATRAMP_LOG_FORMAT=json boatramp serve
```

Each request writes one JSON object to stdout:

```text
{"target":"boatramp::access","method":"GET","path":"/index.html","host":"my-site.example","client_ip":"203.0.113.7","status":200,"bytes":1841,"encoding":"br","cache_result":"full","duration_ms":3}
```

The `cache_result` field is one of `full`, `partial`, `not-modified`,
`redirect`, or `error`. Verbosity follows `RUST_LOG` (default `boatramp=info`).
Pipe the sink to your log shipper, or to `jq` to read one field:

```sh
BOATRAMP_LOG_FORMAT=json boatramp serve | jq -r 'select(.target=="boatramp::access") | .status'
```

```text
200
304
200
```

## Check health

Two endpoints report health. Point a load balancer or orchestrator probe at
them:

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | Liveness — the process is up. |
| `/readyz` | Readiness — a cheap KV probe; returns `503` when the metadata backend is unreachable. |

Probe readiness — a `503` means the process is up but the metadata backend is
unreachable, so route no traffic to this node yet:

```sh
curl -i http://localhost:8080/readyz
```

```text
HTTP/1.1 200 OK

ready
```

## Scrape metrics

An admin-scoped Prometheus exporter is always served at `/api/metrics`, carrying
the process-wide serving and lifecycle counters. With the `handlers` feature it
also renders per-handler invocation counters and per-consumer queue-depth and
dead-letter gauges. Scrape it:

```sh
curl http://localhost:8080/api/metrics
```

```text
# HELP boatramp_http_requests_total requests by status class and cache result
# TYPE boatramp_http_requests_total counter
boatramp_http_requests_total{status_class="2xx",cache_result="full"} 1420
boatramp_http_requests_total{status_class="3xx",cache_result="not-modified"} 87
boatramp_deployments_total 12
boatramp_activations_total 9
```

For every metric, its labels, and their meaning, see the
[metrics reference](../reference/metrics.md).

## Tail guest logs and read handler stats

For sites running handlers, two commands report per-site activity. Tail the
captured guest stdout and stderr, with `--follow` to stream new lines:

```sh
boatramp logs my-site --follow
```

```text
2026-07-09T12:04:11Z my-site http/GET/api/hello  stdout  handling request id=7f3a
2026-07-09T12:04:19Z my-site queue/emails        stderr  retry 1: upstream timeout
```

Read invocation counts, consumer lag, and dead-letter totals:

```sh
boatramp stats my-site
```

```text
site my-site
  http/GET/api/hello   invocations 1420   errors 3
  queue/emails         invocations  512   errors 1   lag 0   dead-letters 2
```

Messages that exhaust their retry budget are dead-lettered — kept with their
payload and counted here. Inspect the cause in `logs`, then redrive or purge
them; see [Run consumers, crons, and streams](./background-work.md).

## Reference

- Full metric and access-log-field tables: [Metrics reference](../reference/metrics.md).
