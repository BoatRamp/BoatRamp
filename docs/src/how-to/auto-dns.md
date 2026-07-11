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

## Reference

- Provider names and credential variables:
  [DNS providers & credentials](../reference/dns-providers.md).
