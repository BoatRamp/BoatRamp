# Automate DNS with a provider

boatramp can drive your managed-DNS provider directly, so pointing a verified
custom domain and proving ownership become single commands instead of manual
zone edits. This page covers both tasks. For custom-domain concepts, see
[Attach a custom domain](./custom-domain.md).

## Before you start

- A supported managed-DNS provider with its credentials exported in your
  environment. The `--provider` names and their credential variables are in
  [DNS providers & credentials](../reference/dns-providers.md).
- A running server you can reach with `--server`.

Credentials are read from the environment only, never from a config file.

## Verify ownership automatically

Passing `--provider` to `domain add` closes the ownership-verification loop for
you. It publishes the `_boatramp-verify.<host>` TXT record through the provider,
polls until the record resolves, attaches the host, then retracts the challenge
record:

```sh
boatramp domain add app.example.com --provider cloudflare
```

```text
published _boatramp-verify.app.example.com TXT for app.example.com; waiting for it to resolve...
verified app.example.com and attached it to my-site
```

`--provider` writes **only** the ownership-proof TXT — never the host's `A`,
`AAAA`, or `CNAME`. Verification always happens before the host is pointed or
served, so boatramp cannot be induced to point or serve a hostname you have not
proven you control. Without a provider, `domain add` verifies over HTTP if the
host already resolves here, otherwise prints the record to publish by hand so you
can run `domain verify` afterward.

## Point the domain at your server

Once the host is verified, point it at the server — a separate, explicit step.
The `--target` value decides the record type: an IPv4/IPv6 literal becomes an
`A`/`AAAA`, and anything else becomes a `CNAME`:

```sh
boatramp dns configure-domain www.example.com --provider cloudflare --target lb.example.net
```

```text
pointed CNAME www.example.com -> lb.example.net
```

Use an address target at a true apex, where a `CNAME` is invalid:

```sh
boatramp dns configure-domain example.com --provider cloudflare --target 203.0.113.7
```

```text
pointed A example.com -> 203.0.113.7
```

Add `--proxied` to route the record through Cloudflare's edge (cache / WAF / edge
TLS). It is Cloudflare-only, chosen per domain, applies to address and `CNAME`
records, and forces the automatic TTL Cloudflare requires:

```sh
boatramp dns configure-domain docs.example.com --provider cloudflare --target app.fly.dev --proxied
```

```text
pointed CNAME docs.example.com -> app.fly.dev (proxied)
```

## Wildcard on Cloudflare: disable Universal SSL first

If you point a **wildcard** (`*.example.com`) at a Cloudflare **DNS-only** (grey-cloud)
zone and let something else terminate TLS with a wildcard certificate validated over
**DNS-01** — for example a fly wildcard cert — Cloudflare's **Universal SSL** will
silently block issuance.

Universal SSL (on by default for a newly-added zone) runs Cloudflare's own
domain-control validation, whose managed `TXT` records at `_acme-challenge.example.com`
**clobber the DNS-01 challenge delegation**. The ACME CA reads Cloudflare's tokens
instead of the delegated challenge, so the wildcard certificate never validates and sits
"Not verified" indefinitely. The failure is sneaky:

- It hits the **wildcard only**. An exact host (`console.example.com`) validates over
  HTTP-01 and issues fine — so wildcard TLS hangs while exact-host TLS works, which looks
  like a fluke.
- It is worst on **new zones** (Universal SSL still actively validating), and can recur
  at the external CA's **renewal** time even on an established zone.

For a DNS-only zone the Cloudflare edge certificate is never served, so the fix is to
disable Universal SSL. `boatramp dns configure-domain` detects this: when you point a
wildcard at a Cloudflare DNS-only zone it checks the setting and, if enabled, prints a
warning. Pass `--disable-cf-universal-ssl` to turn it off in the same step (needs a token
with `Zone.SSL and Certificates:Edit`):

```sh
boatramp dns configure-domain '*.example.com' --provider cloudflare \
  --target app.fly.dev --disable-cf-universal-ssl
```

Then re-trigger the wildcard cert so DNS-01 can validate against the now-unobstructed
delegation, e.g.:

```sh
fly certs remove '*.example.com' && fly certs add '*.example.com'
```

Equivalent manual steps: dashboard **SSL/TLS → Edge Certificates → Universal SSL →
Disable**, or `PATCH /zones/<id>/ssl/universal/settings {"enabled": false}`.

For a **proxied** (orange-cloud) zone the edge certificate *is* served, so don't disable
Universal SSL — use a [Cloudflare Origin CA
certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/) for
the origin instead.

## Reference

- Provider names and credential variables:
  [DNS providers & credentials](../reference/dns-providers.md).
