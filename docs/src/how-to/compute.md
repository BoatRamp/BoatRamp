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

## Provision a kernel

Every workload boots in a microVM, which needs a **kernel** as well as a root
filesystem. Supply a Firecracker-compatible uncompressed Linux kernel (`vmlinux`)
— build one, or use a released microVM kernel — provisioned once and shared across
every workload.

`--kernel` (like `--rootfs`) accepts any of three forms: a **local file**, a
**URL**, or a **blob hash** already in the store. Point it straight at a file or
URL and the CLI uploads it for you:

```sh
boatramp compute build web --image nginx:1.27 --kernel ./vmlinux --port 80
# or a URL:
boatramp compute build web --image nginx:1.27 \
  --kernel https://example.com/vmlinux-6.1 --port 80
```

To upload a kernel once and reuse its hash across commands, use
[`blob put`](../reference/cli.md#boatramp-blob):

```sh
boatramp blob put ./vmlinux
```

```text
1a2b3c4d…    # the content-address; pass it as --kernel 1a2b3c4d…
```

## The kernel and its trust

You do not have to pass `--kernel` on every workload. A node has a **fleet default
kernel** — a [dynamic setting](../reference/daemon-config.md) you change without a
restart:

```sh
boatramp config set compute.default_kernel '{"source":"…","sha256":"…","sig":"…"}'
```

A workload that omits `--kernel` uses that default. Changing the default retargets
**new** microVMs and reboots; in-flight guests keep their kernel until they cycle.

The kernel is **verified before boot**, scaled by the [security posture](./security-posture.md):

- **Always:** the kernel bytes must hash to the pinned `sha256` — a mismatch never
  boots.
- **`multi-tenant` (strict):** the hash must be on the static
  `[compute].kernel_allowed_hashes` allow-list **and** carry a signature verifying
  against a static `[compute].kernel_signing_pubkeys` key. So an admin token can
  only *select* a kernel the host operator pre-vetted and signed — never introduce
  a new one.
- **`single-tenant` / `dev`:** a verified hash pin suffices.

boatramp ships a first-party signing public key built in, so the signed default
kernel it distributes verifies out of the box. `boatramp security explain` shows
the resolved kernel-trust bar.

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
