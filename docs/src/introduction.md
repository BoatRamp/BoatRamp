# boatramp

**boatramp** is a self-hosted, **streaming-first** alternative to Vercel for
publishing static websites, WebAssembly handlers, and private services — a web
server, an HTTP API, and a CLI shipped as a **single binary**.

> **Streaming, not buffering.** Every byte path streams: uploads flow from the
> client straight into the backend, downloads flow from the backend straight to
> the client, and files are hashed in fixed-size chunks. No file is ever held
> whole in memory — on the client, the server, or in any backend.

> **Atomic, content-addressed deploys.** `boatramp sync` publishes a folder as
> an immutable deployment and flips the site to it with a single atomic
> operation. Readers always see the previous deploy or the new one in full —
> never a half-written mix. Identical bytes are stored once (dedup), unchanged
> files are never re-uploaded, and rollback is just re-activating an older
> deployment.

## What you get

- **Static publishing** with atomic activation, instant rollback, and content
  dedup — `sync` an unchanged tree and nothing uploads.
- **Virtualhost routing** — many sites on one server, resolved by `Host`, with
  domain-ownership verification before a custom domain goes live.
- **TLS** — operator certs, automatic ACME, or wildcard ACME DNS-01; plus an
  optional HTTP→HTTPS redirect listener and HSTS.
- **WebAssembly handlers** — run sandboxed Wasm components for dynamic routes,
  with `keyvalue`, `blobstore`, `sql`, and `messaging` host bindings.
- **Access control & a configurable WAF** — basic auth, IP rules, rate limiting
  (per-node or cluster-wide), and user-agent / anomaly filtering.
- **Authorization** — COSE/CWT tokens with granular RBAC (roles → action ×
  resource rights) decided by Cedar, offline public-key verification, a signing
  key that can live in a KMS/HSM/Vault, offline holder-key delegation, and an
  OIDC-JWT → token exchange.
- **One UX across deploy targets** — the same commands, flags, and config for a
  single node, a self-hosted Raft cluster, or Cloudflare Containers.

## How the docs are organized

- **[Getting Started](./getting-started/installation.md)** — install, publish
  your first site, and learn the core concepts.
- **[Guide](./guide/cli.md)** — task-oriented chapters for everyday operation.
- **[Deployment](./deployment/single-node.md)** — single-node, clustering, and
  Cloudflare.
- **[Architecture](./architecture/overview.md)** — how the pieces fit, for
  operators and contributors.

> boatramp is pre-1.0. Some capabilities described here are validated against
> live infrastructure — those are flagged in context.
