# TLS & HTTPS

TLS is selected with `--tls off|custom|acme|acme-dns` (HTTPS modes need the
`tls` / `acme-dns` feature). The rustls `aws_lc_rs` crypto provider is installed
at startup.

| Mode | What it does |
| --- | --- |
| `off` | Plain HTTP (terminate TLS at a proxy). Default. |
| `custom` | `--tls-cert` / `--tls-key` (PEM) you supply. |
| `acme` | Automatic certs via ACME (TLS-ALPN-01). |
| `acme-dns` | ACME DNS-01, incl. `*.deploy.<host>` wildcard preview certs. |

## Behind a proxy (`off`)

When TLS is terminated upstream, set the site's `security.https_redirect` so
proxied plain-HTTP requests are upgraded. The effective scheme is read from
`X-Forwarded-Proto`, so the redirect and HSTS behave correctly behind the proxy.

## ACME DNS-01

For wildcards (including the preview host), use DNS-01 with a provider:

```sh
boatramp serve --tls acme-dns \
  --acme-domain example.com --acme-wildcard-preview \
  --acme-dns-provider cloudflare        # or route53 | oci | manual
```

Provider credentials come from the environment — see `boatramp dns --help`. The
`boatramp dns` subcommand also helps preview and apply the required records.

## Transport security headers

Per-site `SecurityConfig` controls:

- **HSTS** — `Strict-Transport-Security` on HTTPS responses (configurable
  `max-age`, `includeSubDomains`, `preload`).
- **CSP** and **X-Frame-Options** — opt-in (a default CSP would break inline
  scripts common to static sites).

`X-Content-Type-Options: nosniff` and `Referrer-Policy:
strict-origin-when-cross-origin` are sent by default.

## Dual listeners

In any TLS mode, `--http-redirect-addr 0.0.0.0:80` binds a second plain-HTTP
listener that 308-redirects everything to HTTPS.

## HTTP/3

With the `http3` feature, `--tls custom --http3` also serves HTTP/3 (QUIC) on
the same UDP port, advertised so clients upgrade.

## Cluster-managed certs

In a cluster, the Raft leader issues each cert once and stores it in the
replicated control plane; every node serves the replicated cert and hot-swaps on
renewal. `boatramp cert-status` shows domain + expiry.
