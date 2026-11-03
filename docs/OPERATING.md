# Moved → the operator how-to guides

The operator guide now lives in the book (`docs/src/`), split into focused,
maintained how-to guides. Start here:

- **[Start here: operators](./src/how-to/operators.md)** — the operator
  reading path (published at <https://docs.boatramp.dev/how-to/operators.html>).

The topics this file used to cover map to:

- Serve, backends & production config → [Deploy a single node in production](./src/how-to/deploy-single-node.md)
- TLS modes → [Get an automatic certificate](./src/how-to/acme-cert.md), [Wildcard certs with DNS-01](./src/how-to/wildcard-dns01.md)
- Control-plane auth & tokens → [Bootstrap authentication & mint tokens](./src/how-to/auth-bootstrap.md), [Make a scoped CI deploy token](./src/how-to/ci-token.md)
- Domains → [Attach a custom domain](./src/how-to/custom-domain.md)
- Maintenance, durability & recovery → [Garbage-collect & verify integrity](./src/how-to/prune-scrub.md), [Back up & restore](./src/how-to/backup.md), [Observe: logs, metrics, health, stats](./src/how-to/observe.md)
- Secrets at rest → [Encrypt secrets at rest](./src/how-to/secrets-at-rest.md)
- Routing & proxy worked examples → [Configure routing](./src/how-to/routing.md), [Load-balance & proxy upstreams](./src/how-to/gateway.md)
- Container image / Cloudflare → [Deploy on Cloudflare Containers](./src/how-to/deploy-cloudflare.md), [Run on Kubernetes](./src/how-to/kubernetes.md)

(This file was a 290-line operator overview that lived outside the book and was
invisible to operators browsing the docs site. Its content is now covered by the
maintained how-to guides above; this stub keeps the path findable.)
