# Load-balance & proxy upstreams

The gateway reverse-proxies routes to backends you declare — a compute workload,
a pool of servers, or a private service — with load balancing, health checks,
and retries. You declare **upstreams** (backends) and **routes** (path →
upstream) per site.

## Proxy a route to one backend

```sh
boatramp gateway upstream add api http://10.0.0.5:8080 --site my-site
boatramp gateway route add /api --upstream api --site my-site
```

```text
upstream api → http://10.0.0.5:8080
route /api → api
```

Requests to `/api/*` now forward to the backend. List what's declared:

```sh
boatramp gateway ls --site my-site
```

## Load-balance across a pool

Give several `--backend` URLs and a policy. `round-robin` (default) or `random`:

```sh
boatramp gateway upstream add api \
  --backend http://10.0.0.5:8080 \
  --backend http://10.0.0.6:8080 \
  --lb round-robin --retries 1 --site my-site
```

`--retries` tries another backend on a connect failure (body-less requests only).

To resolve the pool from DNS instead of listing backends, discover an A/AAAA
record set:

```sh
boatramp gateway upstream add api \
  --discover-host api.internal --discover-port 8080 --discover-ttl 30 \
  --site my-site
```

## Add health checks

**Passive** ejection removes a backend after consecutive failures and returns it
after a cooldown:

```sh
boatramp gateway upstream add api \
  --backend http://10.0.0.5:8080 --backend http://10.0.0.6:8080 \
  --health-timeout-ms 5000 --site my-site
```

**Active** probing checks a path on an interval and requires a healthy status:

```sh
boatramp gateway upstream add api \
  --backend http://10.0.0.5:8080 \
  --probe-path /healthz --probe-interval-ms 10000 \
  --probe-healthy 2 --probe-unhealthy 3 --probe-status 200 \
  --site my-site
```

## Rewrite the forwarded request

On a route, override the upstream `Host` header, strip a path prefix, and set
timeouts:

```sh
boatramp gateway route add /app --upstream api \
  --host-header app.internal --strip-prefix /app \
  --connect-timeout-ms 2000 --request-timeout-ms 30000 --site my-site
```

## Private and Unix-socket upstreams

Targeting a private IP or a `unix:` socket is gated by the operator
[security posture](./security-posture.md): under the strict `multi-tenant`
default, a site cannot declare private-IP or Unix-socket upstreams, which blocks
a site from reaching internal services (an SSRF class). An operator enables them
per deployment with `allow_site_private_upstreams` / `allow_site_unix_upstreams`.

> **Warning:** enable private or Unix-socket upstreams only for sites you trust.
> They let a route reach anything the server can reach on the host or private
> network.
