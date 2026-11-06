# Wildcard certs with DNS-01

**For: operators**

Issue a `*.example.com` certificate by proving control of the domain through a
DNS TXT record instead of an HTTP path.

## Why wildcards need DNS-01

A wildcard name has no single host the CA can reach, so it cannot use the
challenge that `--tls acme` runs. DNS-01 is the only ACME challenge that
authorizes a wildcard: the CA gives you a token, you publish it as an
`_acme-challenge` TXT record, and the CA validates the record — not a path on
your server. To publish that record without hand-editing your zone, boatramp
drives a managed DNS provider through its API.

## Issue the certificate

Set the provider's credentials in the environment, then start `serve` with
`--tls acme-dns`. This example uses Cloudflare:

```sh
export CLOUDFLARE_ZONE_ID=… CLOUDFLARE_API_TOKEN=…
boatramp serve --tls acme-dns \
  --acme-domain example.com \
  --acme-dns-provider cloudflare
```

```text
acme-dns: cloudflare provider ready
acme: authorizing example.com, *.example.com via dns-01
acme: published _acme-challenge.example.com TXT, waiting for propagation
acme: certificate issued (expires 2026-10-07)
serving https://0.0.0.0:8080
```

`--acme-domain` covers both the apex and its wildcard. Repeat the flag for more
domains.

The ten built-in providers are the same set the DNS automation uses —
`cloudflare`, `route53`, `oci`, `digitalocean`, `hetzner`, `ns1`, `dnsimple`,
`gcp-dns`, `azure-dns`, and `akamai` — each reading its credentials from
provider-specific environment variables. For the full provider-by-variable table
see [DNS providers & credentials](../reference/dns-providers.md); for pointing
custom domains at your server see
[Automate DNS with a provider](./auto-dns.md).

> **Several zones from one serve?** `--acme-dns-provider` + the env vars drive a
> **single** zone. To issue wildcards across domains in **different** zones from one
> `serve`, declare a `[serve.dns_providers]` **list** instead — one entry per zone, each
> with its own sealed `token`/`boatramp:…` credential; issuance routes by the
> certificate's longest-suffix `zone_root`. See
> [`serve.dns_providers`](../reference/boatramp-cfg.md#servedns_providers).

## Add preview subdomains

To serve by-id preview deployments over HTTPS, add `--acme-wildcard-preview`. It
issues `*.deploy.<domain>` alongside the primary wildcard:

```sh
boatramp serve --tls acme-dns \
  --acme-domain example.com --acme-dns-provider cloudflare \
  --acme-wildcard-preview
```

```text
acme: authorizing *.example.com, *.deploy.example.com via dns-01
acme: certificate issued (expires 2026-10-07)
```

## Wait for DNS propagation

After writing the `_acme-challenge` TXT, boatramp **waits until the record is
actually visible** in your zone before it tells the CA to validate — the CA
checks the record the moment it is told to, so validating before the record has
propagated is what makes an order fail (`challenge failed`) and a cert
crash-loop. boatramp resolves the `_acme-challenge` name and only proceeds once
the expected value appears:

```text
acme: published _acme-challenge.example.com TXT, waiting for propagation
acme: _acme-challenge.example.com observed; validating
acme: certificate issued (expires 2026-10-07)
```

The wait is a real readiness poll, not a fixed sleep. The check queries the
zone's **authoritative** nameservers directly (finding the zone apex and its NS
set, following a CNAME-delegated `_acme-challenge` to the zone that serves it),
so a recursive resolver's negative cache can't make a freshly-written record keep
reading as "not live" — issuance confirms readiness promptly instead of leaning
on the CA's retry. If authoritative discovery can't run (NS unreachable, no SOA),
it falls back to the recursive resolver, then to a blind wait, so it is never
worse than a recursive-only check.

- `--acme-propagation-wait-secs` (env `BOATRAMP_ACME_PROPAGATION_WAIT`, default
  `45`) is the **maximum** time to wait. Issuance proceeds the instant the record
  is observed at the authoritative nameservers; if the wait elapses first, boatramp
  logs a warning and tells the CA to validate anyway (the CA retries on its own),
  so a slow-propagating zone still gets a cert rather than crashing.
- `--acme-propagation-poll-interval-secs` (env
  `BOATRAMP_ACME_PROPAGATION_POLL_INTERVAL`, default `2`) is how often it
  re-checks DNS.
- `BOATRAMP_ACME_PROPAGATION_RESOLVER` overrides the recursive resolver used for
  zone/NS discovery and the fallback check with a comma-separated `ip[:port]` list
  (UDP) — useful when the container's own resolver caches negative answers
  aggressively; e.g. `BOATRAMP_ACME_PROPAGATION_RESOLVER=1.1.1.1,8.8.8.8`.

These same propagation knobs apply to the on-demand per-SNI issuer when it uses
the DNS-01 challenge, as `propagation_wait_secs` / `propagation_poll_interval_secs`
under `[serve.on_demand_tls]` — see [Issue certificates on-demand](./on-demand-tls.md)
for issuing a certificate per verified domain at the first handshake, instead of
enumerating every name here.

## Publish the TXT record by hand

Without a provider account, use the default `manual` provider. boatramp prints
the record and waits for you to add it:

```sh
boatramp serve --tls acme-dns --acme-domain example.com --acme-dns-provider manual
```

```text
acme: add this DNS record, then continue:
  _acme-challenge.example.com  TXT  "3P1eF9…kQ"
acme: certificate issued (expires 2026-10-07)
```

## Mix challenges per control-plane domain

`--tls` sets **one** challenge for all your `--acme-domain` names — `acme-dns` is
DNS-01 (this page), `acme` is TLS-ALPN-01. To obtain **one** control-plane domain
by a *different* challenge — e.g. a concrete host you'd rather validate on the
`:443` edge with no DNS write, while the zone wildcard stays on DNS-01 — list a
per-domain override under `[serve.control_plane_tls]`:

```ron
// Node default is DNS-01 (--tls acme-dns); serve cp.example.com via TLS-ALPN-01
// (validated on the node's own :443, no DNS write), wildcard stays DNS-01.
serve: (
    control_plane_tls: [
        ( domain: "cp.example.com", challenge: "tls-alpn-01" ),
        ( domain: "*.example.com",  challenge: "dns-01" ),
    ],
)
```

A domain with no entry uses the `--tls` default, so a flat `--acme-domain` config
is unchanged. A `"tls-alpn-01"` override on a **wildcard** is refused at config
load — only DNS-01 can satisfy a wildcard.

This is **how the node obtains its own cert** (Concept 1). It is distinct from
`[serve.on_demand_tls].challenge`, which governs how the on-demand engine issues
certs for *other* (tenant) domains (Concept 2) — see
[Issue certificates on-demand](./on-demand-tls.md). Full key details in
[`serve.control_plane_tls`](../reference/boatramp-cfg.md#servecontrol_plane_tls).

## Reference

- All `serve` TLS flags: [CLI reference](../reference/cli.md).
- Provider credentials: [DNS providers & credentials](../reference/dns-providers.md).
- Per-domain challenge override: [`serve.control_plane_tls`](../reference/boatramp-cfg.md#servecontrol_plane_tls).
