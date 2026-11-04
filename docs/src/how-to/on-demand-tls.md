# Issue certificates on-demand

**For: operators**

Serve HTTPS on a custom domain the moment it is attached and verified — the
certificate is issued at the **first TLS handshake** for that hostname, with no
`serve` restart and no need to list the domain in `--acme-domain` ahead of time.
This is how you front many customer-owned domains without enumerating them.

## When to use this

You have (or expect) **many attached custom domains** — one per tenant,
customer vanity domains CNAMEd to your edge — and you don't want to restart the
server or edit a flag every time one is added. With on-demand issuance you
**attach and verify** a domain once (see [Attach a custom
domain](./custom-domain.md)) and it simply starts serving over HTTPS on its next
visit.

Compare the three ways to get certificates:

- **On-demand per-SNI (this page).** Best for a large or changing set of
  attached, verified domains you don't want to enumerate. Each verified domain
  gets its own certificate, issued the first time someone connects to it.
- **Static `--acme-domain` list** ([Get an automatic
  certificate](./acme-cert.md)). Best for a small, fixed set of names known at
  startup — your apex, your control-plane host. You pass each one on the command
  line. (At least one static `--acme-domain` is still required under `--tls
  acme-dns`; see below.)
- **A `*.base` wildcard via DNS-01** ([Wildcard certs with
  DNS-01](./wildcard-dns01.md)). Best when every site is a **subdomain of one
  zone you control** (`<tenant>.apps.example.com`): a single certificate covers
  the whole subtree. A wildcard can't cover a customer's *own* domain in a zone
  you don't control — that's exactly the gap on-demand fills.

On-demand composes with the other two: the static set and any wildcard keep
serving unchanged, and on-demand covers every other verified domain on top.

> **New in v0.53.0: on-demand issuance now works on a single node**, not only in
> a cluster. Earlier releases wired the per-SNI engine only on the cluster serve
> path; a single-node server silently had no on-demand engine. A single node now
> gets the same engine, over its local control-plane store.

## How it works

With the engine enabled, boatramp installs a per-SNI certificate resolver at the
TLS edge:

1. A client opens a TLS connection for `app.customer.com` (SNI).
2. If a certificate is already issued and cached, it is served immediately.
3. On a miss, the resolver **checks the authorization gate** (below) and, for an
   authorized name, triggers issuance in the background and **fails this one
   handshake**. The client retries; by then the certificate is warm and the
   connection succeeds.

So the very first connection to a brand-new domain may take a moment (or a
client-side retry) while the certificate is obtained; every connection after
that is instant. Issued certificates are cached and persisted in the
control-plane store and renewed before expiry, exactly like the static set.

## The authorization gate (read this)

On-demand issuance only ever obtains a certificate for a domain that is
**attached to a site *and* ownership-verified** — the same verification you
complete with `domain add` / `domain verify` (or a DNS-verified ancestor zone /
wildcard covering the name). Resolution or mere attachment is **not** enough.

Any other SNI — a name you've never attached, or one attached but not yet
verified — is **refused** (no certificate, no CA call) and briefly
negatively-cached. This is the whole point: a stranger pointing arbitrary
hostnames at your edge, or a tenant cycling bogus names, **cannot** make you open
ACME orders and burn your certificate-authority rate budget. The engine fails
closed, bounds concurrent issuances, and caps orders per hour (see
`rate_limit_per_hour` below).

## Set it up

### 1. Enable the engine

Add a `[serve.on_demand_tls]` block to `boatramp.cfg`:

```ron
serve: (
    on_demand_tls: (
        enabled: true,
        contact_email: "ops@example.com",   // optional: ACME expiry-warning contact
        rate_limit_per_hour: 50,            // CA orders per rolling hour; default 50, 0 ⇒ unlimited
    ),
),
```

The full key list — `challenge`, `directory_url`, `contact_email`,
`max_inflight`, `negative_ttl_secs`, `rate_limit_per_hour`, and the two DNS-01
propagation knobs — is in the [config reference](../reference/boatramp-cfg.md#serveon_demand_tls).
The default challenge is **TLS-ALPN-01**, which validates on the `443` edge with
no extra port and no per-domain DNS write — ideal for customer-owned domains that
are simply CNAMEd to you. To validate over DNS-01 instead (when you control the
zone, e.g. for a wildcard), set `challenge: "dns-01"`; that path uses the node's
configured ACME DNS provider and the `propagation_wait_secs` /
`propagation_poll_interval_secs` knobs (the same readiness poll described in
[Wildcard certs with DNS-01](./wildcard-dns01.md)).

### 2. Start `serve` in `acme-dns` mode

On-demand issuance runs alongside the `--tls acme-dns` certificate path. Start
the server as you would for DNS-01, pointing it at your DNS provider:

```sh
boatramp serve --tls acme-dns \
  --acme-domain example.com \
  --acme-dns-provider cloudflare
```

```text
on-demand per-SNI TLS issuance ENABLED (allowlist = verified custom domains)
serving https://0.0.0.0:8080
```

`--acme-domain` still names your **static** set — at least one is required (your
apex or control-plane host), and it is issued up front just as in [Get an
automatic certificate](./acme-cert.md). The on-demand engine then handles every
*other* verified domain on top, without any of them appearing on the command
line. For the provider names and their credential variables see [DNS providers &
credentials](../reference/dns-providers.md).

> **Customer domains in different zones?** On-demand per-SNI issuance uses the node's ACME
> DNS provider, which `--acme-dns-provider` pins to **one** zone. To front domains in
> **multiple** zones from one serve, configure a `[serve.dns_providers]` **list** (one
> per-zone provider each, sealed-ref credentials); every DNS-01 challenge routes to the
> provider whose `zone_root` is the longest suffix of the certificate's name. See
> [`serve.dns_providers`](../reference/boatramp-cfg.md#servedns_providers).

### 3. Attach and verify a domain

For each customer domain, attach and verify it once — and point its DNS at your
edge so both the visitor's handshake and the ACME TLS-ALPN-01 validation reach
you:

```sh
boatramp domain add app.customer.com --provider cloudflare
```

```text
verified app.customer.com and attached it to my-site
```

See [Attach a custom domain](./custom-domain.md) for the manual HTTP/DNS methods,
and [Automate DNS with a provider](./auto-dns.md) to close the verification loop
through your provider. Once the domain is verified and pointed here, the next
HTTPS request to it issues and serves its certificate automatically — no restart.

## Encrypt the issued keys at rest

Without a `[secrets]` key envelope, the issued certificate private keys **and**
the persisted ACME account credentials are stored **unencrypted** in the
control-plane store (boatramp warns loudly at startup when this is the case).
Configure `[secrets]` so they are wrapped at rest — see [Encrypt secrets at
rest](./secrets-at-rest.md).

## Single node vs. cluster

The configuration and behavior are **identical** on a single node and in a
cluster; only the issuer plumbing differs, and it is handled for you:

- **Single node.** That one node is always the issuer and serves every verified
  domain. Certificates persist in its local control-plane store.
- **Cluster.** The leader places the CA order; followers serve the replicated
  certificate. A brand-new domain whose first handshake lands on a *follower* is
  relayed to the leader to issue, then replicated — the operator does nothing
  differently. See [Manage certificates in a cluster](./cluster-certs.md).

A host-owned inbound-TCP listener can also opt into the shared engine with
`on_demand = true` in its `tls` block, issuing per-SNI for its own project's
verified domains; see the [config
reference](../reference/boatramp-cfg.md#serveon_demand_tls).

## Reference

- Config keys: [`serve.on_demand_tls`](../reference/boatramp-cfg.md#serveon_demand_tls).
- All `serve` TLS flags: [CLI reference](../reference/cli.md).
- Related: [Get an automatic certificate](./acme-cert.md) ·
  [Wildcard certs with DNS-01](./wildcard-dns01.md) ·
  [Attach a custom domain](./custom-domain.md) ·
  [Automate DNS with a provider](./auto-dns.md).
