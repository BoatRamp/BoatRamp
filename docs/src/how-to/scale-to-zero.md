# Scale compute to zero

A scale-to-zero workload snapshots and stops when it goes idle, then restores on
the next request. You pay no CPU or memory for an idle service, and a cold
request pays a restore instead of a full boot. It applies to microVM workloads,
whose device-model state (including in-flight queue cursors) can be snapshotted
and resumed.

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
and the microVM stops; the next request restores it from the snapshot. A restore
is faster than a boot because the guest resumes where it left off rather than
re-initializing.

> **Note:** the snapshot/restore mechanism is validated live (a serve → snapshot
> → restore → serve round-trip). The automatic idle→snapshot and request→restore
> reconcile is being finished; treat scale-to-zero as production-ready for the
> mechanism and pre-1.0 for the fully automatic idle detection. See
> [Maturity, validation & support](../explanation/maturity.md).

For the mechanism itself and when to choose scale-to-zero over always-on, see
[Compute: handlers vs containers vs microVMs](../explanation/compute-model.md).
