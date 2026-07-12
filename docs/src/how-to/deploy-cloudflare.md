# Deploy on Cloudflare Containers

boatramp runs on Cloudflare as its own cluster mode: the boatramp binary runs in
Cloudflare Containers, and a thin edge Worker routes to it. The Worker reuses the
same routing engine as the origin, so the edge and the Containers do not drift.
This is the same binary and the same commands as a self-hosted cluster —
Cloudflare is a deploy target, not a fork. For why the edge runs Wasm and why
there is no separate coordinator, see
[Deployment topologies](../explanation/topologies.md).

## Before you start

- `wrangler` installed and authenticated against your Cloudflare account.
- A boatramp build with `--features cluster`. The generated `Dockerfile` builds
  the binary with this feature, so a Docker builder is enough.
- An R2 bucket (blobs) and a D1 database (the `sql` handler binding), created
  ahead of time, with their credentials set as wrangler secrets.

## 1. Build the container image

Build the image the Containers run, and push it to a registry Cloudflare can
pull from:

```sh
docker build -t registry.example.com/boatramp:v1 .
docker push registry.example.com/boatramp:v1
```

```text
v1: digest: sha256:… size: 1573
```

## 2. Generate the deployment

Run `boatramp cloudflare` to plan the topology and write the deployment artifacts
— per-node cluster configs, a `Dockerfile`, a `wrangler.jsonc`, and the edge
Worker crate:

```sh
boatramp cloudflare \
  --region wnam --region weur --region apac \
  --primary wnam --quorum 3 \
  --image registry.example.com/boatramp:v1 \
  --domain example.com --r2-bucket boatramp-blobs --d1 boatramp-sql \
  --out ./cloudflare
```

```text
Generated 5 node(s) (3 voters in wnam, 2 learner(s)) → ./cloudflare
Review the artifacts, then `wrangler deploy` (or re-run with --apply).
```

`--primary` hosts the voting quorum; the other regions host read-only learners
that serve local reads and forward writes to the leader. Keep `--quorum` odd.

The generated config is **uniform** across nodes ([dynamic join](./deploy-cluster.md)):
node 1 founds via `BOATRAMP_CLUSTER_INIT=1` and the rest join with a
`BOATRAMP_CLUSTER_JOIN` ticket — no per-node id or peer map. Set those env vars in
each instance's container config (Cloudflare Containers instances are otherwise
fungible, so the founder is designated by env, not by a baked-in config).

## 3. Deploy

Review the artifacts, then push them with wrangler:

```sh
cd ./cloudflare && wrangler deploy
```

```text
Published boatramp
  https://example.com/*
```

To generate and deploy in one step, re-run step 2 with `--apply` (it runs
`wrangler deploy` for you and needs your Cloudflare credentials).

## 4. Publish and verify

Point publishing at the deployed domain — it behaves the same as any boatramp
server, because content is backend-durable:

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
