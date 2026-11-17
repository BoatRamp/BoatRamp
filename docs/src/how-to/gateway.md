# Load-balance & proxy upstreams

**For: operators**

The gateway reverse-proxies routes to backends you declare — a compute workload,
a pool of servers, or a private service — with load balancing, health checks,
and retries. You declare **upstreams** (backends) and **routes** (path →
upstream) per site. To proxy to a container or microVM boatramp runs, first
[run a container or microVM](./compute.md), then point an upstream at it.

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

### Route to the nearest region

With `--lb nearest`, the gateway sends each request to the **nearest healthy**
backend by region: tag each backend with `--region URL=REGION`, and name the
request header your CDN/edge sets with the client's region via
`--client-region-header` (e.g. `fly-region`, `cf-ipcountry`):

```sh
boatramp gateway upstream add api \
  --backend http://us.internal:8080 --region http://us.internal:8080=us-east \
  --backend http://eu.internal:8080 --region http://eu.internal:8080=eu-west \
  --lb nearest --client-region-header fly-region --retries 1 --site my-site
```

Selection is **health-first, then by distance**: an unhealthy nearest backend is
skipped for a healthy farther one (kept only as a last-resort fallback), and if the
client region is unknown the pool falls back to health-first order — never a hard
failure. By default nearness is binary (same region wins); to rank *how* far apart
regions are, set a distance table (`region_map`) in the site config directly.

**Compute-backed pools tag themselves.** When the upstream resolves its pool from a
compute workload (`compute: <name>`, replicas managed by the reconcile loop) rather
than static `--backend`s, you don't write a `--region` map: each replica is
**auto-tagged** with the region of the node it runs on — that node's
[`[compute].region`](../reference/boatramp-cfg.md#compute). Just set `--lb nearest`
+ `--client-region-header` on the upstream and give each node a `[compute].region`,
and every request goes to the nearest healthy replica.

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

On an upstream, control the `Host` header sent to the backend, strip a path prefix,
and set timeouts:

```sh
boatramp gateway upstream add api http://10.0.0.5:8080 \
  --host-header app.internal --strip-prefix /app \
  --connect-timeout-ms 2000 --request-timeout-ms 30000 --site my-site
```

### Choosing the forwarded `Host`

The `Host` header the backend receives is independent of which site the request
matched — routing is always decided on the client's own (verified-domain) `Host`,
never on anything you set here. You have three choices:

| Mode | How | Backend receives |
|------|-----|------------------|
| **Upstream authority** (default) | neither flag | the upstream's own host, e.g. `10.0.0.5:8080` |
| **Fixed override** | `--host-header app.internal` | exactly `app.internal` on every request |
| **Preserve client Host** | `--preserve-host` | the client's original `Host`, e.g. `api-dev.example.com` |

`--host-header` and `--preserve-host` are mutually exclusive.

Use **`--preserve-host`** when one backend fronts many domains and routes strictly
by the request `Host` (a virtual-host origin). Without it, the default rewrite sends
the backend the upstream's address (`10.0.0.5:8080`), which such a backend does not
recognise — so it returns its own `404`/`421` for the unknown vhost. Preserving the
client `Host` lets the backend route by the real published domain:

```sh
# api-dev.example.com and app-dev.example.com both front one vhost-routing origin.
boatramp gateway upstream add rev http://127.0.0.1:9099 --preserve-host --site api-dev
boatramp gateway route add /** rev --site api-dev
```

> **Security:** `--preserve-host` forwards a client-controllable `Host` to your
> backend — it is an explicit, per-upstream opt-in. It only sets the forwarded
> header value; it never changes which upstream is dialed (the connection is always
> pinned to the upstream's configured `target`), so it cannot be turned into SSRF or
> cross-upstream confusion. Enable it only when your backend is prepared to receive
> the real request `Host`.

## Tune upstream memory vs throughput

Each upstream connection keeps a read buffer, and a busy reverse proxy holds one per
concurrent request — so at high fan-out that buffer is the dominant memory cost. It
defaults to **32 KiB**, a good balance for typical API/CDN responses. Raise it for
large responses at low concurrency (fewer, larger reads = a bit more throughput), or
lower it to trim memory on a high-fan-out, memory-tight node:

```sh
boatramp gateway upstream add api http://10.0.0.5:8080 \
  --read-buffer-bytes 131072 --site my-site
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
