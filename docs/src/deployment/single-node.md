# Single-Node

The simplest deployment: one process, local disk. Blobs go to the filesystem,
control-plane metadata to an embedded SlateDB.

```sh
boatramp serve \
  --addr 0.0.0.0:8080 \
  --data-dir /var/lib/boatramp \
  --auth-root-private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY"
```

Generate the root key once with `boatramp auth init` (see
[Authentication](../guide/authentication.md)), then mint an admin token with
`boatramp token create admin --role admin`.

This stores blobs under `<data-dir>/blobs` and the KV under `<data-dir>/kv-slate`
(a transactional LSM that is durable on each write). A front LRU keeps hot
metadata in memory; because it is write-through, an `activate` is visible
immediately.

## Backends

`--blobs` and `--kv` select where data rests:

| Flag | Options |
| --- | --- |
| `--blobs` | `fs` (default), `s3` (S3/MinIO/R2; `--features s3`) |
| `--kv` | `slatedb` (default), `memory`, `cloudflare` (`--features cloudflare-kv`) |

SlateDB runs over any `object_store` backend (local FS, S3, R2, GCS), so a
single node can keep its KV on object storage too.

## TLS

Add `--tls custom` (your cert) or `--tls acme` (automatic). See
[TLS & HTTPS](../guide/tls.md). For automatic HTTP→HTTPS, add
`--http-redirect-addr 0.0.0.0:80`.

## Behind a proxy

Run `--tls off` and terminate TLS at nginx/Caddy/etc. Set the site's
`security.https_redirect` and list the proxy in `access.trusted_proxies` so
`X-Forwarded-For` / `X-Forwarded-Proto` are believed.

## When to scale out

A single node is a single writer and a single point of failure. For
high-availability control-plane writes and multi-region reads, move to
[Clustering](./cluster.md); to run several stateless frontends over one shared
KV, see [Cache Coherence](../architecture/cache-coherence.md).
