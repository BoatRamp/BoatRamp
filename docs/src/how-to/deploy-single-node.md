# Deploy a single node in production

One process, local disk, authenticated control plane, TLS. Blobs go to the
filesystem; control-plane metadata goes to an embedded SlateDB that is durable on
every write. This is the whole platform on one host.

For when to move beyond one node, see
[Deployment topologies](../explanation/topologies.md).

## 1. Generate a root key and set up auth

The control plane authenticates every management request. Generate a root key
once:

```sh
boatramp auth init
```

```text
BOATRAMP_AUTH_ROOT_PRIVATE_KEY=es256:6f2c…
BOATRAMP_AUTH_ROOT_PUBLIC_KEY=es256:03a1…
```

Keep the private key in the server's environment (or a secrets manager). Full
flow — including minting your first admin token — is in
[Bootstrap authentication](./auth-bootstrap.md).

> **Warning:** under the default `multi-tenant` security posture, `serve` refuses
> to start on a non-loopback address with no root key. That is deliberate: a
> public bind with auth off exposes the control plane. Configure a key (below),
> or bind `127.0.0.1`, or select a looser posture for local use — see
> [Choose a security posture](./security-posture.md).

## 2. Run the server

```sh
boatramp serve \
  --addr 0.0.0.0:8080 \
  --data-dir /var/lib/boatramp \
  --auth-root-private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY"
```

```text
control-plane auth enabled (issuer)
serving http://0.0.0.0:8080 — data /var/lib/boatramp
```

Blobs land under `<data-dir>/blobs` and the KV under `<data-dir>/kv-slate`. A
write-through in-memory cache fronts hot metadata, so an `activate` is visible
immediately.

Prefer a config file for anything non-trivial: put the same settings in
`boatramp.cfg` and run `boatramp serve --config boatramp.cfg`. Flags and
environment variables override the file. See the
[boatramp.cfg schema](../reference/boatramp-cfg.md).

## 3. Add TLS

Terminate TLS at boatramp with an automatic certificate:

```sh
boatramp serve --config boatramp.cfg \
  --tls acme --acme-domain pad.example.com \
  --http-redirect-addr 0.0.0.0:80
```

`--http-redirect-addr` opens a second listener that answers plain HTTP with a
`308` to HTTPS. For wildcard certificates, custom certificates, and the DNS-01
flow, see [Get an automatic certificate](./acme-cert.md).

To terminate TLS at a reverse proxy instead, run `--tls off`, set the site's
`https_redirect`, and list the proxy in the site's `trusted_proxies` so
`X-Forwarded-For` and `X-Forwarded-Proto` are believed.

## 4. Choose the storage backends

`--blobs` and `--kv` select where data rests. The defaults (`fs`, `slatedb`)
suit a single node.

| Flag | Default | Alternatives |
| --- | --- | --- |
| `--blobs` | `fs` | `s3` (S3 / MinIO / R2 — needs `--features s3`) |
| `--kv` | `slatedb` | `memory`, `cloudflare` (needs `--features cloudflare-kv`) |

SlateDB runs over any object store, so a single node can keep its KV on S3/R2 as
well. Full option list: [boatramp.cfg schema](../reference/boatramp-cfg.md).

## Next steps

- [Bootstrap authentication & mint tokens](./auth-bootstrap.md)
- [Attach a custom domain](./custom-domain.md)
- [Back up & restore](./backup.md)
- [Observe: logs, metrics, health, stats](./observe.md)
- Scale out: [Deploy a self-hosted cluster](./deploy-cluster.md)
