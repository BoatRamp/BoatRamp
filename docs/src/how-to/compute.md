# Run a container or microVM

A **compute workload** runs a long-lived server — a container image or a
microVM — behind a route, next to your static content and Wasm handlers. Use it
when a Wasm handler is not enough: an existing container image, a language
runtime, or code that needs a full OS. For the choice between a handler, a
container, and a microVM, see
[Compute: handlers vs containers vs microVMs](../explanation/compute-model.md).

Compute backends are Linux-only and capability-detected at startup: a container
backend where the host allows it, and a microVM backend where `/dev/kvm` exists.
Enable compute by adding a `compute:` section to `boatramp.cfg` (see the
[schema](../reference/boatramp-cfg.md#compute)).

## Deploy a container image

`compute build` takes an OCI image reference, builds an ext4 root filesystem from
it, uploads it, and registers the workload in one step. It needs the `mke2fs`
tool (`e2fsprogs`) on the host and a kernel blob provisioned once.

```sh
boatramp compute build web \
  --image nginx:1.27 \
  --kernel <vmlinux-blob-hash> \
  --port 80 \
  --vcpus 1 --mem-mib 256 --replicas 2
```

```text
built ext4 rootfs from nginx:1.27 (1024 MiB) — blob sha256:1a2b…
workload web set: 2 replicas, port 80, isolation trusted
```

The scheduler places the replicas on nodes that advertise compute capacity and
reconciles them toward the desired count. Check status:

```sh
boatramp compute ls
```

```text
NAME  REPLICAS  PORT  ISOLATION  STATE
web   2/2       80    trusted    Healthy
```

## Choose the isolation level

`--isolation` decides which backend may run the workload:

| `--isolation` | Runs on | Use for |
| --- | --- | --- |
| `trusted` (default) | a container (shared kernel) or a microVM | your own images |
| `untrusted` | a microVM only (never a shared kernel) | third-party or tenant code |

```sh
boatramp compute build tenant-app --image ghcr.io/acme/app:1.4 \
  --kernel <vmlinux-blob-hash> --port 8080 --isolation untrusted
```

Under the strict `multi-tenant` security posture, shared-kernel (container)
compute is disabled, so every workload runs in a microVM regardless of
`--isolation`. See [Choose a security posture](./security-posture.md).

## Set a workload from existing blobs

If you already pushed a rootfs and kernel, register the workload directly with
`compute set` (same flags as `build`, minus the image build):

```sh
boatramp compute set api \
  --rootfs <rootfs-blob-hash> --kernel <vmlinux-blob-hash> \
  --port 8080 --replicas 3 \
  --entrypoint /usr/bin/api --env LOG=info
```

Inspect a workload's desired state:

```sh
boatramp compute get api
```

## Next steps

- [Scale compute to zero](./scale-to-zero.md) when a workload is idle.
- [Load-balance & proxy upstreams](./gateway.md) to route traffic to it.
