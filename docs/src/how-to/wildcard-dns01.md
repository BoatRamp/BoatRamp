# Wildcard certs with DNS-01

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

## Reference

- All `serve` TLS flags: [CLI reference](../reference/cli.md).
- Provider credentials: [DNS providers & credentials](../reference/dns-providers.md).
