# Cloudflare

The Cloudflare target runs boatramp's **own cluster mode on Cloudflare
Containers**, fronted by a thin edge Worker. There is no separate coordinator —
the single-writer coordinator is the Raft leader everywhere, so the behavior and
the operator UX are identical to a self-hosted cluster, not forked. The
Containers run the native boatramp binary unchanged.

## Container image

Build the image boatramp runs in the Container. Two paths:

```sh
# Reproducible, Nix-first (Linux builders; the CI release pushes it to the Gitea registry):
nix build .#container && docker load < result          # → boatramp:latest

# …or the plain Dockerfile. The HA/Raft cluster image needs --features cluster
# (the `boatramp cloudflare` generator emits its own Dockerfile that does this):
docker build --build-arg FEATURES=cluster -t registry/boatramp:v1 .
docker push registry/boatramp:v1
```

The default image features are `s3` (R2) + `cloudflare-kv`; the `tls` feature is
omitted because the edge terminates TLS. The image runs as a non-root user, ships
no build tools in the runtime layer, and — with remote backends — writes nothing
to local disk, so it needs no writable volume (a voter's durable Raft store is
the one exception, mounted as a Container volume).

## Generate the deployment

```sh
boatramp cloudflare \
  --region wnam --region weur --region apac \
  --primary wnam --quorum 3 \
  --image registry/boatramp:v1 \
  --domain example.com \
  --r2-bucket blobs --d1 sql \
  --out ./cloudflare
```

This plans the topology (voting quorum in the primary region + read-only
learners elsewhere) and writes:

- per-node `nodes/<id>.cfg` `cluster` fragments (RON);
- a `Dockerfile` that builds the cluster binary with a durable Raft-store volume;
- a `wrangler.jsonc` wiring the Worker + Container + R2/D1 bindings + routes;
- the **edge Worker as a Rust → Wasm crate** (`worker/`), built with
  `worker-build` — boatramp is Wasm-first, so the edge runs Wasm, not authored
  JS (the only JS is the bootstrap shim `worker-build` generates). It serves
  static-from-R2 and forwards dynamic requests to the cluster, reusing
  `boatramp-core` routing so edge and origin can't drift.

Review the artifacts, then `wrangler deploy` (or re-run with `--apply`).

## Bindings

| Concern | CF binding |
| --- | --- |
| Blobs | R2 (the `s3` backend) |
| Control plane | replicated Raft state on the Containers |
| `sql` | D1 / libsql per site |
| Per-node Raft store | a Container durable volume (or R2-backed) |
| Edge routing / static / cache / TLS | the Worker |

## TLS

The edge Worker terminates TLS with Cloudflare-managed certificates, so
cluster-managed certs are primarily for the self-hosted cluster. The UX is
uniform: declare domains, the environment provides the certs. boatramp itself
runs `--tls off` behind the Worker.

## Secrets & hardening

R2 and KV credentials (and any DB DSN) are supplied as **Cloudflare secret
bindings → Container env**, never baked into the image; boatramp reads them from
the environment at startup. The Container has no public listener — it is reachable
only through the Worker, a defense-in-depth property on top of boatramp's usual
tenant isolation / SSRF guard / access control (which run unchanged inside it).

## Operator workflow

1. Build + push the image (above), or let CI publish it to the Gitea registry on a `v*` tag.
2. Create the R2 bucket + KV namespace; set the R2/KV credentials as wrangler
   secrets.
3. `boatramp cloudflare … --apply` (or review the artifacts and `wrangler deploy`).
4. Point publishing at the Worker URL — `boatramp sync --server https://<worker-url>`
   works exactly as against any boatramp server (content is backend-durable).
5. Verify: `curl https://<domain>/healthz`, then scrape `/api/metrics` (admin).

> The CF-specific layer (the Worker, Container networking, always-on instances,
> durable volumes) is validated live on the platform. The image + config
> generation is deterministic and unit-tested.
