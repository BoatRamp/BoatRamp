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

`--kernel` (like `--tar` / `--rootfs`) accepts any of three forms: a **local file**, a
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
restart. boatramp distributes a first-party signed microVM kernel
([`boatramp-vmlinux`](https://github.com/BoatRamp/boatramp-vmlinux/releases)); set
it up once by uploading the released `vmlinux` as a blob and pointing the default
kernel at that content hash:

```sh
# 1. fetch the signed release (kernel + its .sha256 + .sig) and upload the kernel as a blob
base=https://github.com/BoatRamp/boatramp-vmlinux/releases/latest/download
curl -fsSLO "$base/boatramp-vmlinux-x86_64"
curl -fsSLO "$base/boatramp-vmlinux-x86_64.sha256"
curl -fsSLO "$base/boatramp-vmlinux-x86_64.sig"
boatramp blob put boatramp-vmlinux-x86_64        # prints the blob hash == its sha256

# 2. point the fleet default at it (source = the blob hash; sha256 + sig from the release
#    artifacts, so this stays correct across releases)
boatramp config set compute.default_kernel "{
  \"source\": \"$(cat boatramp-vmlinux-x86_64.sha256)\",
  \"sha256\": \"$(cat boatramp-vmlinux-x86_64.sha256)\",
  \"sig\":    \"$(cat boatramp-vmlinux-x86_64.sig)\"
}"
```

`source` is the **blob hash** the backend stages (not the release URL). A workload
that omits `--kernel` uses this default. Changing it retargets **new** microVMs and
reboots; in-flight guests keep their kernel until they cycle.

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

### Kernels are per guest-arch (macOS `vmm-vz`)

The guest kernel matches the backend's guest architecture: the Linux/KVM embedded
VMM boots an **x86_64** `vmlinux`, while the macOS Virtualization.framework backend
(`vmm-vz`, Apple silicon) boots a raw **arm64** `Image`. An x86_64 kernel can't boot
an arm64 VM, so `[compute].kernel_allowed_hashes` is arch-scoped — an Apple-silicon
node trusts only `boatramp-vmlinux-aarch64` releases, an x86_64 node only the
`x86_64` ones — and `--kernel` / `compute.default_kernel` on macOS must point at an
arm64 kernel (the release's `boatramp-vmlinux-aarch64` asset, or any uncompressed
arm64 `Image`). Everything else — `--kernel`, the fleet default, verify-before-boot
— is identical. Under `single-tenant` / `dev` the content-hash pin alone suffices,
so `vmm-vz` runs with any operator-supplied arm64 kernel; the strict posture on
Apple silicon needs the signed `boatramp-vmlinux-aarch64` release (its hash is baked
into the arch-scoped allow-list on release).

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

## Set a workload from an existing source

`compute set` registers a workload from a **root-filesystem source** — exactly one
of, matched to the substrate you want:

- `--image <ref>` — an OCI image reference the runtime pulls (`docker` / `cloudflare`).
- `--tar <hash|file|url>` — a tar rootfs archive the native `container` runtime unpacks.
- `--rootfs <hash|file|url>` — a rootfs filesystem image (a block device; `ext4` by
  default) the `firecracker` micro-VM attaches.

```sh
# A registry image on the docker backend (e.g. a database):
boatramp compute set pg --image pgvector/pgvector:pg16 --port 5432 --env POSTGRES_PASSWORD=pw

# A pre-built ext4 rootfs + kernel on the micro-VM backend:
boatramp compute set api \
  --rootfs <rootfs-blob-hash> --kernel <vmlinux-blob-hash> \
  --port 8080 --replicas 3 \
  --entrypoint /usr/bin/api --env LOG=info
```

Inspect a workload's desired state:

```sh
boatramp compute get api
```

## Docker workloads: read-only root, writable root, and volumes

A docker (or native-container) workload runs **hardened** by default: a read-only
root filesystem, all Linux capabilities dropped, no privilege escalation, and a PID
cap. The idiomatic path for app writes is a **persistent volume**, not a writable
root — attach one (in-guest mount → named backing) via the API or a `project.cfg`
manifest, and the data persists across restarts.

For an image that insists on writing outside a declared volume, `--writable-root`
relaxes *only* the read-only-root default (every other hardening stays on):

```sh
boatramp compute set legacy-app --image acme/legacy:1 --port 8080 --writable-root
```

`--writable-root` is honored **only under the single-tenant security posture** — the
strict `multi-tenant` guard forces the hardened read-only root back on (and, being
shared-kernel, won't place the workload on docker at all). See
[Choose a security posture](./security-posture.md).

How the docker backend stores a volume is set by `[compute].docker_volume_mode`:
`named` (default) uses a daemon-managed `docker volume` (portable across daemons and
Docker Desktop / macOS); `bind` uses a host directory under
`<data_dir>/compute/volumes/<name>` (local daemon only). Either way the volume is
**node-local** — it is not part of the blob-snapshot durability story the microVM
backend's volumes get, and does not follow a workload across nodes.

## Next steps

- [Scale compute to zero](./scale-to-zero.md) when a workload is idle.
- [Load-balance & proxy upstreams](./gateway.md) to route traffic to it.
