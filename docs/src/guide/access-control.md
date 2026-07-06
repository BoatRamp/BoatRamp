# Access Control & WAF

Visitor access control is **per-site** (`SiteConfig.access`) and runs before any
content is read, so it never stalls a response in flight. The order is:

**WAF → IP rules → rate limit → basic auth.**

## Basic auth, IP rules, rate limiting

```sh
boatramp access --site my-site --help
```

- **Basic auth** — argon2id-hashed credentials; visitors get a `401` challenge.
- **IP rules** — CIDR allow/deny. Behind a trusted proxy, the real client IP is
  resolved from `X-Forwarded-For` only when the direct peer is a configured
  trusted proxy.
- **Rate limiting** — a per-`(site, client-IP)` token bucket (`rps` / `burst`),
  returning `429` + `Retry-After`. In a multi-process deployment,
  `--cluster-rate-limit` shares an approximate fixed-window count through the
  control-plane KV instead of per-node buckets.

## The WAF

A small, fully-configurable web-application firewall (`SiteConfig.access.waf`,
off by default) runs as the outermost filter. Two independently-toggleable
features:

- **User-agent rules** — a regex deny-list (any match blocks) plus an optional
  regex allow-list (when set, a UA matching none is blocked).
- **Anomaly scoring** — sums points for configurable signals (empty
  `User-Agent`, missing `Accept`, suspicious path substrings — each weighted)
  and blocks at a threshold.

A malformed regex is ignored rather than fatal, so a typo can't wedge the site
open or shut. A blocked request gets `403`.

## SSRF guard on proxy rewrites

A `project.cfg` `routing` rewrite to an absolute URL becomes a streamed reverse proxy.
Targets are checked against the deploy's `proxy_allow` list and every resolved
address must be public — private, loopback, link-local, CGNAT, and the
cloud-metadata IP are refused. Publishing a *private* service is a separate,
explicitly-opted-in gateway capability.
