# boatramp

boatramp is a self-hosted, streaming-first alternative to Vercel and Netlify,
shipped as one Rust binary that is both the server and the CLI. You run it
yourself to publish static sites, WebAssembly handlers, and edge compute, with
atomic deployments and instant rollback. The same commands and config run on a
single node, a self-hosted cluster, or Cloudflare Containers.

## Where to start

- **New here?** Publish something in ten minutes —
  [Publish your first site](./tutorials/first-site.md).
- **Running it in production?** Start with
  [Deploy a single node](./how-to/deploy-single-node.md).
- **Writing handlers?** Build and deploy one in
  [Write your first handler](./tutorials/first-handler.md).
- **Automating or integrating?** Read the
  [authentication & authorization model](./explanation/auth-model.md).

## What boatramp does

| | |
| --- | --- |
| [Static hosting](./tutorials/first-site.md) | Content-addressed blobs, atomic deploys, instant rollback. |
| [Domains & TLS](./how-to/custom-domain.md) | Virtualhosts, ownership verification, automatic certificates. |
| [Auto-DNS](./how-to/auto-dns.md) | Ten managed-DNS providers for ACME and custom domains. |
| [Handlers](./tutorials/first-handler.md) | Sandboxed Wasm components with kv / sql / blobstore / messaging bindings. |
| [Compute](./how-to/compute.md) | Containers and microVMs behind a route, with scale-to-zero. |
| [Gateway](./how-to/gateway.md) | Load-balancing reverse proxy with health checks and retries. |
| [Clustering](./how-to/deploy-cluster.md) | Raft-replicated control plane, multi-region reads. |
| [Auth](./how-to/auth-bootstrap.md) | COSE/CWT tokens, Cedar RBAC, external signers. |
| [Caching & observability](./how-to/caching.md) | Automatic caching, compression, metrics, and logs. |

## Understand it

The [core concepts](./explanation/concepts.md) explain the deployment model, and
[what boatramp is](./explanation/what-is-boatramp.md) covers where it fits and
what it is not. For per-capability release status, see
[Maturity, validation & support](./explanation/maturity.md).
