# Deploy on Cloudflare Containers

boatramp runs on Cloudflare as its own cluster mode: the boatramp binary runs in
Cloudflare Containers, and a thin edge Worker routes to it. The Worker reuses the
same routing engine as the origin, so the edge and the Containers do not drift.
This is the same binary and the same commands as a self-hosted cluster —
Cloudflare is a deploy target, not a fork. For why the edge runs Wasm and why
there is no separate coordinator, see
[Deployment topologies](../explanation/topologies.md).

The deploy is **native**: `boatramp cloudflare` drives the Cloudflare REST API
directly — ensuring the R2/D1 resources, uploading the edge Worker, and creating
the container application. There is no `wrangler`, and nothing is generated for
you to run by hand — the same one-token, env-provided model as the S3/GCS/Azure
backends.

## Before you start

- `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` in your environment. The
  token needs the Workers Scripts, Containers, R2, and D1 scopes (plus DNS for a
  custom domain). boatramp never sees your token except through the environment.
- **Docker**, to build the container image.
- A Cloudflare account with the **Workers paid plan** (Containers require it).

## 1. Build + push the container image

Build the image the Containers run and push it to a registry Cloudflare can pull
from (its managed registry, or Docker Hub / ECR / GAR):

```sh
docker build -t registry.example.com/boatramp:v1 .
docker push registry.example.com/boatramp:v1
```

```text
v1: digest: sha256:… size: 1573
```

## 2. Deploy

Preview the plan first (`--dry-run` mutates nothing) — it prints the resources,
image, edge-Worker metadata, and container application it will apply:

```sh
boatramp cloudflare \
  --region enam --primary enam --quorum 1 \
  --image registry.example.com/boatramp:v1 \
  --r2-bucket boatramp-blobs --d1 boatramp-sql \
  --dry-run
```

Then drop `--dry-run` to apply. `boatramp cloudflare` ensures the R2 bucket + D1
database (idempotent), uploads the edge Worker (creating its Durable Object
namespaces), and creates + rolls out the container application referencing your
image:

```sh
boatramp cloudflare \
  --region enam --primary enam --quorum 1 \
  --image registry.example.com/boatramp:v1 \
  --r2-bucket boatramp-blobs --d1 boatramp-sql
```

```text
cloudflare: account reachable; container API responsive
cloudflare: ensured R2 bucket "boatramp-blobs" + D1 database "boatramp-sql" (…)
cloudflare: uploaded edge Worker "boatramp"
cloudflare: creating container application "boatramp"
cloudflare: container application "boatramp" at version 1 (standard tier); an instance provisions on the first request
cloudflare: native deploy complete — boatramp running on CF Containers
```

The container is **scale-to-zero**: no instance runs until the first request,
which provisions one (a cold start pulls the image + boots — up to ~2 minutes; the
edge Worker rides it out and retries). Subsequent requests reuse the warm instance.

On Cloudflare, boatramp runs as a **single durable instance** — deploy with
`--quorum 1` and one `--region`. A multi-node Raft quorum is **not possible on
the platform**: CF Containers scale to zero and have no container-to-container
networking (every request is mediated by the container's Durable Object), so a
majority of voting peers can't stay simultaneously running and exchange the
low-latency RPCs consensus needs. Instead, the single instance keeps **all state
durably in R2** (see below), which is Cloudflare's architecture for this — a
parked or replaced container restores its state from R2. (Multi-node Raft targets
self-hosted / VM / orchestrator deployments with real peer networking; to inspect
what such a topology's reference artifacts look like, add `--emit-artifacts
./cloudflare` — those are not a Cloudflare deploy.)

### Control-plane auth

The container binds a public port (behind the edge Worker), so boatramp requires
control-plane auth to be enabled. Set `BOATRAMP_AUTH_ROOT_PRIVATE_KEY` (from
`boatramp auth init`) before deploying — the deploy delivers it to the container so
public site routes stay open while `/api/*` requires a token. If you don't set one,
the deploy **generates and prints** a key once; save it (mint tokens with it, and
reuse it to redeploy with the same root — Cloudflare can't return it later). Mint an
admin token offline with the same key: `boatramp token mint --role admin`.

> **Durable state in R2.** The deploy points the container at R2 for **all** durable
> state: blobs go to the R2 bucket over the S3 API, and the control-plane metadata
> (deploy manifests, the per-site `current` pointer) is a SlateDB store on the same
> bucket. So a scale-to-zero instance keeps everything across a stop — the in-image
> `/data` now holds only ephemeral caches (the wasmtime compile cache). The R2 S3
> credentials are derived from your API token (no separate token to provision, and
> the container never holds the raw Cloudflare token), so the token needs only its
> existing R2 scope.

## 3. Publish and verify

Point publishing at the deployed domain — it behaves like any boatramp server, and
deploys persist across cold starts (state is durable in R2):

```sh
boatramp sync ./dist --site my-site --server https://example.com
curl https://example.com/healthz
```

```text
ok
```

## Reference

- Full `cluster:` schema: [boatramp.cfg schema](../reference/boatramp-cfg.md).
- The edge/origin split and its trade-offs:
  [Deployment topologies](../explanation/topologies.md).
