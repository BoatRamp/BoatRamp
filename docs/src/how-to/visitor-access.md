# Restrict visitor access

Control who can reach a site's public content: password-protect a staging site,
allow or deny by IP, and cap request rate. These controls are per-site and apply
before any content is read, so a blocked request never stalls a response in
flight.

Requests pass the controls in order — **WAF → IP rules → rate limit → basic
auth** — and the first to reject wins. This page covers public-facing access
only. To publish a private upstream or tune the SSRF guard, see
[Load-balance & proxy upstreams](./gateway.md); to manage control-plane operators
and tokens, see [Bootstrap authentication](./auth-bootstrap.md).

All commands take `--site` (or read it from `project.cfg`). Show the current
policy:

```sh
boatramp access show --site my-site
```

```text
site my-site
  basic-auth   0 users (disabled)
  ip           no rules
  rate-limit   disabled
```

## Password-protect a site

Add a basic-auth user. The password is read from `--password` or, if omitted,
from stdin; it is stored argon2id-hashed, never in plaintext. Visitors without
valid credentials get a `401` challenge:

```sh
boatramp access basic-auth add preview --realm "Staging" --site staging
```

```text
basic-auth: added user 'preview' — site 'staging' now requires authentication
```

Remove a user, or disable basic auth entirely:

```sh
boatramp access basic-auth rm preview --site staging
boatramp access basic-auth disable --site staging
```

## Allow or deny by IP

IP rules take a CIDR or a bare address. Adding an allow rule denies every
unlisted client; deny wins over allow:

```sh
boatramp access ip allow 203.0.113.0/24 --site my-site
```

```text
ip: allow 203.0.113.0/24 — unlisted clients denied
```

```sh
boatramp access ip deny 198.51.100.7 --site my-site
```

Clear all IP rules with `boatramp access ip clear`. Behind a reverse proxy, the
client address is read from `X-Forwarded-For` only when the direct peer is a
trusted proxy — register yours:

```sh
boatramp access trusted-proxy add 10.0.0.0/8 --site my-site
```

## Apply a rate limit

Set a per-client sustained rate and an optional burst. Over-limit requests get
`429`:

```sh
boatramp access rate-limit set 20 --burst 40 --site my-site
```

```text
rate-limit: 20 rps, burst 40 (per client IP)
```

In a multi-process deployment, serve `--cluster-rate-limit` so the count is
shared through the control-plane KV instead of counted per node. Disable the
limit with `boatramp access rate-limit disable`.

## The WAF

The web-application firewall is the outermost filter in the ordering above. Its
signals are part of the site's access policy; a request the WAF rejects is
answered `403` before any other check runs.
