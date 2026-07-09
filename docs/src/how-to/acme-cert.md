# Get an automatic certificate

Issue a certificate for one domain from Let's Encrypt and serve it over HTTPS.
boatramp requests the certificate on first start, caches it, and renews it before
expiry — no cron, no manual `certbot`.

For a wildcard certificate, a `*.deploy.<host>` preview certificate, or a domain
you cannot expose on the public internet, use DNS-01 instead — see
[Wildcard certs with DNS-01](./wildcard-dns01.md).

## Before you start

- The domain's `A` (and `AAAA`, if you serve IPv6) record points at the server's
  public IP.
- The host is attached to a site, so a request for it resolves to content — see
  [Attach a custom domain](./custom-domain.md).
- The ACME challenge reaches the server on port `443` (and port `80` if you bind
  the redirect listener below).

## Issue the certificate

Start `serve` in `acme` mode and name the domain:

```sh
boatramp serve --tls acme --acme-domain example.com --acme-contact ops@example.com
```

`--acme-domain` is repeatable — pass it once per domain to cover several on one
account. `--acme-contact` registers an email with the ACME account for expiry
warnings; it is optional but recommended.

On first start, boatramp registers the account, solves the challenge, and issues
the certificate:

```text
acme: registering account (contact ops@example.com) at Let's Encrypt production
acme: ordering certificate for example.com
acme: certificate issued for example.com — expires 2026-10-07, cached ./data/acme
serving https://0.0.0.0:8080
```

Verify the live site presents it:

```sh
curl -sI https://example.com/
```

```text
HTTP/2 200
strict-transport-security: max-age=63072000
```

## Redirect HTTP to HTTPS

Bind a second plain-HTTP listener so visitors on `http://` are upgraded. In any
TLS mode, `--http-redirect-addr` answers plain HTTP with a `308` to HTTPS:

```sh
boatramp serve --tls acme --acme-domain example.com --http-redirect-addr 0.0.0.0:80
```

```sh
curl -sI http://example.com/
```

```text
HTTP/1.1 308 Permanent Redirect
location: https://example.com/
```

## Where the certificate is cached

boatramp writes the account key and issued certificate to `--acme-cache` (default
`./data/acme`). Restarts reuse the cached certificate instead of ordering a new
one, and renewal rewrites the same directory. Point it at durable storage and
back it up, or Let's Encrypt rate limits apply the next time an empty cache
re-orders from scratch:

```sh
boatramp serve --tls acme --acme-domain example.com --acme-cache /var/lib/boatramp/acme
```

## Reference

- All `serve` TLS flags: [CLI reference](../reference/cli.md).
- Wildcard and preview certs via DNS-01: [Wildcard certs with DNS-01](./wildcard-dns01.md).
