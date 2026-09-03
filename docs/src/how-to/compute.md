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
into the arch-scoped allow-list on release). An operator-supplied arm64 kernel must
enable the **generic PCIe host + virtio-pci** (`CONFIG_PCI`, `CONFIG_PCI_HOST_GENERIC`,
`CONFIG_VIRTIO_PCI`): Virtualization.framework presents its virtio disk/net/console
over a PCIe host bridge, so a `CONFIG_PCI`-off kernel finds no devices and never boots.
The `boatramp-vmlinux-aarch64` release is built this way.

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

## Running a stock image that needs privileges (e.g. a database)

Because every capability is dropped, a stock image whose entrypoint runs as root and
then **`chown`s a data dir and drops to its own user** (the classic `postgres` /
`mysql` init) can't initialize on the shared-kernel backends out of the box — the
`chown` needs `CAP_CHOWN`/`CAP_FOWNER` and the privilege-drop needs
`CAP_SETUID`/`CAP_SETGID`. Two ways to make it work, cleanest first:

**Run it rootless (preferred).** Point the entrypoint at the image's own DB user with
`--user`, backed by a persistent volume boatramp pre-owns for that uid — the entrypoint
then skips both the `chown` and the privilege-drop, so it needs **no capabilities** and
works under **any** posture:

```sh
boatramp compute set pg --image postgres:16 --port 5432 \
    --user 999:999 --volume pgdata:/var/lib/postgresql/data
```

**Add back the capabilities (fallback).** For an image that won't run rootless,
`--cap-add` grants specific capabilities on top of the dropped-`ALL` default. It is
honored **only under the single-tenant posture** (the multi-tenant guard strips it,
same as `--writable-root`); on the native-container backend the caps are bounded by the
workload's user namespace:

```sh
boatramp compute set pg --image postgres:16 --port 5432 \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --cap-add SETUID --cap-add SETGID \
    --volume pgdata:/var/lib/postgresql/data
```

**Managed databases do this for you.** When a handler `sql` binding is sourced from a
database boatramp runs (see [Managed SQL](./handler-bindings.md)), boatramp applies a
privilege strategy automatically — no `--user`/`--cap-add` needed. The strategy is
`[compute].managed_db_privilege`: `rootless` (the default — run as the image's DB user
against its pre-owned volume, no capabilities, any posture) or `caps` (add the minimal
set; single-tenant only).

## Startup grace (slow-starting images)

A freshly launched replica gets a **startup grace**: the reconcile loop leaves a
still-unhealthy replica alone until the grace elapses, treating it as *starting* rather
than a broken launch to stop and relaunch. This keeps a slow-initializing image — a stock
database doing its first `initdb` — from being killed mid-init into a crash loop. Only
after the grace does a replica that is still unhealthy get stopped + relaunched (the
self-heal for a genuinely broken launch).

`--startup-grace-secs` sets it on any workload; omit it for the default (**30s**):

```sh
boatramp compute set worker --image acme/slow-boot:1 --port 8080 --startup-grace-secs 90
```

**Managed databases raise it automatically.** A managed co-located database uses a
larger per-engine default — **Postgres 60s**, **MySQL 120s** — because a stock database's
first boot runs `initdb` before it opens its port. Override it per binding with
`startup_grace_secs` (or the env var
`BOATRAMP_HANDLERS_SQL_DB_<NAME>_STARTUP_GRACE_SECS`); omit it for the engine default.

## Reach a sibling workload by name (internal DNS)

A workload can reach another workload **in the same project** — or that project's
managed database — **by name**, without the control plane injecting a numeric
`ip:port`. boatramp runs a small DNS resolver on the compute bridge gateway and
points every container's `/etc/resolv.conf` at it, so a guest resolves a peer with
either the bare short name or its fully-qualified internal name:

- `web` — the bare workload name (the `search <project>.boatramp.internal` line in
  the container's resolv.conf completes it), or
- `web.acme.boatramp.internal` — the FQDN, `<workload>.<project>.<domain>`.

Either form resolves to the workload's **live, healthy replica IP** from the
current reconcile state. A managed database is a workload too, so an app container
in project `acme` can reach its co-located Postgres as `pg-<ident>` (or by the
short name of whatever `compute` its `sql` binding names) — the same address the
`sql` binding injects, now reachable by name.

Resolution is **isolated per project**. The resolver maps the querying container's
bridge IP to its `(project, workload)`, so a tenant is only ever told an address in
**its own** project:

- an internal name in another project → refused (never resolved across the tenant
  boundary),
- an internal name that currently has no healthy replica → `NXDOMAIN`,
- an external name (or a query from a source that is not a known co-located
  container) → forwarded to the upstream resolver.

External DNS keeps working: anything outside a project's internal namespace is
forwarded to `compute.dns_upstream` (default `1.1.1.1:53`).

It is **on by default** on the Linux container backend. Turn it off, point external
lookups at your own resolver, or rename the internal suffix with three knobs (all
[env-settable](../reference/env.md#compute-backend)):

```ron
// boatramp.cfg
compute: (
    internal_dns: true,             // default; false leaves the image's resolv.conf untouched
    dns_upstream: "1.1.1.1:53",     // where external names are forwarded
    dns_domain:   "boatramp.internal",
)
```

## Known constraints

- **Compute is leader-node-only for now.** The control plane schedules and
  reconciles workloads, but a workload's replicas and its managed database do not
  yet span cluster nodes — a workload's endpoints are node-local bridge IPs on the
  node that runs it. Run compute (and managed databases) on a single node, or on
  the cluster leader, until multi-node replica spreading lands.
- **Internal name resolution is within a project.** By design, a name resolves only
  inside the querying container's own project — there is no cross-project name
  resolution. That is the tenant-isolation boundary, not a limitation to work
  around; to share a service between projects, front it with a route.

## Manage persistent volumes

Unregistering a workload (`compute rm`) leaves its **persistent volume** on disk, so its
data survives an accidental delete and a re-`set`. List what's on the node and reclaim a
volume you no longer need:

```bash
boatramp compute volume ls
```

```text
NAME                  SIZE    IN-USE
pg-acme_3f9c…         214 MiB yes
old-cache             12 MiB  no
```

`IN-USE` marks a volume still referenced by a registered workload's active spec.
Removing one of those would pull data out from under a running (or relaunching) replica,
so `rm` refuses it:

```bash
boatramp compute volume rm old-cache          # ok — orphaned
boatramp compute volume rm pg-acme_3f9c…       # refused: in use
boatramp compute rm pg-acme_3f9c… && \
  boatramp compute volume rm pg-acme_3f9c…     # the safe order
```

Pass `--force` to remove a still-referenced volume anyway (disposable data only — it
will be re-created empty on the next launch).

## Next steps

- [Scale compute to zero](./scale-to-zero.md) when a workload is idle.
- [Load-balance & proxy upstreams](./gateway.md) to route traffic to it.
