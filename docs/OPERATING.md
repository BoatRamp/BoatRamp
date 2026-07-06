# Operating boatramp

A practical guide to running a boatramp server and publishing to it. For the
storage layout see `KEYSPACE.md`; for multi-node and Cloudflare see
`CLOUDFLARE.md`.

boatramp has one binary with subcommands. Configuration precedence is uniform
everywhere: **flag/env > config file > built-in default**. The config file is
`project.cfg` for the project commands and `boatramp.cfg` for `serve` (both RON).

## Quick start

```sh
# Serve (plain HTTP on 127.0.0.1:8080, filesystem + SlateDB under ./data):
boatramp serve

# Publish a built site directory to a server:
boatramp sync ./dist --server https://pad.example.com --site mysite --token "$TOK"
```

## Subcommands

| Command | Purpose |
| --- | --- |
| `serve` | Run the server (selects backends + TLS + auth). |
| `sync` | Negotiate a manifest, upload missing blobs (streamed), activate. |
| `build` / `bundle` | Run a build command / the embedded JS+CSS bundler (`bundler` feature). |
| `validate` | Validate a `project.cfg` (its `routing`) / handler bundle locally. |
| `deployments` / `status` / `rollback` | Inspect history; show current; re-activate a prior deploy. |
| `domain` | Verify + attach hostnames to a site (see **Domains** below). |
| `alias` / `access` | Manage named aliases; configure visitor access control. |
| `gateway` | Publish a private service through the edge (reverse proxy). |
| `compute` | Manage Firecracker microVM workloads (KVM nodes). |
| `auth` | Generate / inspect the control-plane root key (`auth init`). |
| `token` | Mint/list/revoke control-plane tokens. |
| `dns` | DNS-01 helper for wildcard certs (`acme-dns` feature). |
| `logs` / `stats` | Tail guest logs; show handler/consumer/stream stats (`handlers`). |
| `prune` | Delete orphan deployments + unreferenced blobs (`--dry-run` to preview). |
| `scrub` | Verify every stored blob still hashes to its key (integrity). |
| `cloudflare` | Generate a Cloudflare deployment (`cluster` feature). |

## `boatramp.cfg` (server)

The server daemon config, read by `serve` (RON):

```ron
(
    serve: (
        addr: "0.0.0.0:8080",            // bind address
        data_dir: "./data",              // fs blobs in <dir>/blobs, KV in <dir>/kv-slate
        auth_root_private_key: "…",      // token root key (issuing node) — enables auth
        // auth_root_public_key: "…",    // …or just the public key (verify-only node)
        // Operational request limits (all optional; unlimited by default):
        max_upload_bytes: 1073741824,    // reject blob uploads larger than this
        upload_idle_timeout_secs: 30,    // abort a stalled upload (slowloris)
        max_concurrent_uploads: 16,      // 503 beyond this many in-flight uploads
        http_redirect_addr: "0.0.0.0:80",// in a TLS mode, redirect :80 → HTTPS
    ),
    // cluster: ( … ) — multi-node config ; handlers: ( … ) — handler runtime config
)
```

## `project.cfg` (project)

Per-project client config, read by `sync` / `build` / `bundle` / `validate`
(RON):

```ron
(
    publish: (                           // client-side defaults for sync/deployments/…
        server: "https://pad.example.com",
        site: "mysite",
        // token: "…",                   // or BOATRAMP_TOKEN
    ),
    build: (
        command: "npm run build",
        output: "dist",
    ),
    routing: ( … ),                      // deploy-scoped redirects/rewrites/headers/handlers
)
```

Site-scoped config (**domains, transport security, visitor access, handler
policy**) is in **neither** file — it lives in the KV as `SiteConfig`
(`site/<site>/config`) and is edited via `domain` / `access` / the
`GET|PUT /api/sites/:site/config` API, so it travels with the server, not the
client.

## TLS

`--tls off|custom|acme|acme-dns` (HTTPS modes need the `tls` / `acme-dns`
feature):

- `off` — plain HTTP; terminate TLS at a proxy. Set the site's
  `security.https_redirect` so proxied HTTP is upgraded (proxy-aware via
  `X-Forwarded-Proto`).
- `custom` — `--tls-cert`/`--tls-key` (PEM).
- `acme` — automatic certs (TLS-ALPN-01).
- `acme-dns` — DNS-01, including `*.deploy.<host>` wildcard preview certs;
  `--acme-dns-provider manual|cloudflare|route53|oci`.

In any TLS mode, `--http-redirect-addr 0.0.0.0:80` binds a second listener that
308-redirects plain HTTP to HTTPS. **HSTS** and an opt-in **CSP** /
**X-Frame-Options** come from the site's `security` config; `nosniff` and
`Referrer-Policy: strict-origin-when-cross-origin` are sent by default.

## Authentication (control plane)

Public serving is never authenticated. The control-plane edge authorizes
**COSE/CWT** tokens with granular **RBAC** (action × resource);
if no root key is set, auth is **disabled** (development only).

1. Generate the root key once: `boatramp auth init` prints the private key (the
   issuing node) and the public key (verify-only nodes).
2. Run the issuing node with `--auth-root-private-key <hex>` (or
   `serve.auth_root_private_key` / `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`); other
   nodes may run verify-only with `--auth-root-public-key <hex>`.
3. Mint tokens (issuing node only): `boatramp token create <label> --role <role>`
   where `--role` is `<role>` or `<role>:<site>` — e.g. `admin`,
   `publisher:blog`, `viewer:blog`. `--ttl-secs` adds an expiry. `token ls` /
   `token rm <id>` list and revoke. The token is shown once and never stored.

Default roles: `admin` (everything), `publisher:<site>` (read/write/deploy that
site + blob upload), `deployer:<site>` (read+deploy, no config), `viewer:<site>`
(read), `operator` (system/cert read + cache). Override via the `authz/policy`
KV doc.

**OIDC** (`oidc` feature): with `--oidc-issuer` set on the issuing node, clients
exchange an IdP JWT for a short-TTL token at `POST /api/auth/exchange` (the
configured claim — `--oidc-scope-claim`, default `scope` — carries the role
specs); the edge then only ever sees boatramp tokens.

Clients send `Authorization: Bearer <token>` from `BOATRAMP_TOKEN` /
`publish.token`.

## Domains (ownership verification)

Attaching a custom domain is gated on proving you control it, before it routes
or gets a cert:

```sh
boatramp domain add app.example.com --method http   # or: --method dns
#   → prints a token to publish (an HTTP file or a _boatramp-verify TXT record)
boatramp domain verify app.example.com               # checks it, then attaches
boatramp domain ls                                   # attached + pending
```

`--method dns` needs a server built with the `domain-verify-dns` feature
(public-DNS TXT lookup); `--method http` works in every build.

## Maintenance

- `boatramp prune [--dry-run]` — reclaim orphan deployments + unreferenced
  blobs (retention via `--keep-last`/`--keep-age`; `--grace` protects in-flight
  deploys).
- `boatramp scrub` — re-hash every stored blob; exits non-zero on any
  corruption/unreadable blob, so it fits a cron or healthcheck.
- `/healthz` (liveness) and `/readyz` (readiness; probes the KV). SIGTERM/Ctrl-C
  drains in-flight requests under a deadline.

## Secrets at rest

boatramp keeps the secret surface small and defers storage to the chosen
backend; operators are responsible for protecting these:

- **TLS private keys** — `--tls-key` PEM (custom) or the ACME cache directory
  (`--acme-cache`); in cluster mode, cert material is replicated as `cert/<domain>`
  in the control-plane KV. Protect the cache dir / KV store at rest (filesystem
  permissions, or backend encryption for S3/R2/SlateDB-on-object-store).
- **API tokens** — never stored in cleartext: only the SHA-256 is persisted
  (`tokens/<hash>`); the plaintext is shown once at `token create`. The single
  bootstrap token lives only in config/env.
- **OIDC** — boatramp holds no client secret; it only fetches the issuer's
  public JWKS and verifies signatures.
- **Backend / cloud credentials** (S3, Cloudflare, Route53, OCI) — read from the
  environment (see each provider's `--help`), never written to the KV.

Put the data directory (or the object store) behind appropriate access controls
and at-rest encryption; boatramp does not add its own envelope encryption.

## Container image

boatramp ships as a single static-ish binary, so it containerizes cleanly.

```sh
# Reproducible, Nix-first image (Linux builders; the CI release pushes it to the Gitea registry):
nix build .#container && docker load < result      # → boatramp:latest

# …or the plain Dockerfile for non-Nix users (default features s3 + cloudflare-kv;
# override for the HA/Raft cluster image):
docker build -t boatramp:latest .
docker build --build-arg FEATURES=cluster -t boatramp:cluster .

# Run it (edge/LB terminates TLS; boatramp listens plain on :8080):
docker run -p 8080:8080 \
  -e BOATRAMP_ADDR=0.0.0.0:8080 \
  boatramp:latest serve --blobs s3 --kv cloudflare --tls off
```

The image runs as a non-root user and ships no build tools in the runtime layer.
With remote backends (`--blobs s3 --kv cloudflare`) nothing is written to local
disk, so no writable volume is needed. For the Cloudflare Containers deployment
(image + edge Worker + R2/KV), see the [Cloudflare guide](./src/deployment/cloudflare.md).

## Worked examples

**Single-page app (SPA fallback).** Real files are served first; everything else
falls back to `index.html` so client-side routing works. In `project.cfg`:

```ron
(
    routing: (
        clean_urls: true,
        rewrites: [ (from: "/**", to: "/index.html") ],
        headers: [ (matches: "/assets/**", set: { "Cache-Control": "public, max-age=31536000, immutable" }) ],
    ),
)
```

(Routing order is redirects → static file → rewrites → 404, so a `/**` rewrite
never shadows a real asset.)

**Multiple domains on one site.** Prove ownership of each host, then they route
to the site. The site's `SiteConfig.domains` is the canonical record:

```sh
boatramp domain add example.com --method dns && boatramp domain verify example.com
boatramp domain add www.example.com --method dns && boatramp domain verify www.example.com
```

```json
{
  "domains": {
    "primary": "example.com",
    "aliases": ["www.example.com"],
    "wildcards": ["*.preview.example.com"],
    "canonical_redirect": true
  }
}
```

`canonical_redirect` 301s exact aliases (e.g. `www`) to the primary; wildcard
hosts serve as-is.

**Proxied API (same origin).** Forward a path prefix to a backend so the browser
sees one origin (no CORS). A proxy rewrite needs the upstream host on
`proxy_allow`; private/loopback targets are always refused (SSRF guard). In
`project.cfg`:

```ron
(
    routing: (
        rewrites: [ (from: "/api/**", to: "https://api.example.com/:splat") ],
        proxy_allow: ["api.example.com"],
    ),
)
```

To publish a **private** upstream (an internal address the SSRF guard would
otherwise block), declare it under the site's `gateway` instead.
