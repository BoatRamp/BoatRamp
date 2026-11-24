# Scale compute to zero

**For: operators & app developers**

A scale-to-zero workload snapshots and stops when it goes idle, then restores on
the next request. You pay no CPU or memory for an idle service, and a cold
request pays a restore instead of a full boot. It applies to **microVM**
workloads, whose device-model state (including in-flight queue cursors) can be
snapshotted and resumed, and to **native container** workloads on a Linux host
with a working [CRIU](https://criu.org/) (the container's process tree is
checkpointed to disk and restored with its in-RAM state intact).

Enable it per workload with `--scale-to-zero`:

```sh
boatramp compute build web \
  --image nginx:1.27 --kernel <vmlinux-blob-hash> \
  --port 80 --scale-to-zero
```

```text
workload web set: 1 replica, port 80, scale-to-zero on
```

The workload runs normally under load. When it is idle, its state is snapshotted
and the microVM (or container) stops; the next request restores it from the
snapshot. A restore is faster than a boot because the guest resumes where it left
off rather than re-initializing.

## Waking on another node

A parked workload can wake on a node **other** than the one that parked it when
its snapshot was exported to tenant-scoped storage: if the home node is full or
gone, the control plane re-places the wake on another node offering the same
backend, which fetches the snapshot and restores there. This works for **microVM**
workloads and, since v0.72.0, for **native container** workloads — the resume node
re-materializes the container's root filesystem from its content-addressed source
(re-staging the tar blob, or re-pulling the digest-pinned image) before the CRIU
restore, exactly as a microVM re-materializes its content-addressed kernel/rootfs
blobs.

A container is cross-node-capable only when its rootfs is **deterministically
re-materializable offline** and it holds no node-local state that must move:

- its source is a **tar rootfs blob** or a **digest-pinned image** (`…@sha256:…`) —
  a mutable `name:tag` image is not content-addressed, so it stays **same-node**; and
- it declares **no persistent volume** — a volume's data is node-local and is not
  carried by scale-to-zero, so a volume-bearing workload stays **same-node**.

A workload outside that boundary still parks and wakes normally on its **home**
node; it simply isn't re-placed elsewhere. If a cross-node re-materialization or
restore ever fails, the wake falls back to a clean cold start — never a partial or
wrong container. The exported snapshot is sealed (an authenticated-integrity stamp)
and stored under a per-project key on the project's own backend, so a node can only
ever fetch its own tenant's snapshot.

> **Note:** the snapshot/restore mechanism is validated live (a serve → snapshot
> → restore → serve round-trip). The automatic idle→snapshot and request→restore
> reconcile is being finished; treat scale-to-zero as production-ready for the
> mechanism and pre-1.0 for the fully automatic idle detection. See
> [Maturity, validation & support](../explanation/maturity.md).

For the mechanism itself and when to choose scale-to-zero over always-on, see
[Compute: handlers vs containers vs microVMs](../explanation/compute-model.md).
