# Compute: functions and their runtimes

The unit of compute is a [function](./functions.md) — a portable WASI component.
Its **runtime** is a separate choice: *where* that function's code executes. The
three runtimes differ in isolation, startup cost, and what code they can run; pick
the lightest one that fits. This is one knob on the function, not three different
kinds of compute.

## The three runtimes

**Wasm** (the default) — the component runs in an in-process wasmtime sandbox with
capability-based host bindings (kv, sql, blobstore, messaging). Instantiation is
sub-millisecond, memory is small, and the sandbox is strong because the guest can
only touch what you grant. The constraint is the model: the code must compile to a
`wasi:http` component. This is the runtime a [handler](../how-to/deploy-handler.md)
(a route-triggered function) uses, and the one to reach for first.

**Container** — an OCI image run as a long-lived workload with a shared host
kernel, isolated with a jailed worker, namespaces, cgroups, and a seccomp filter.
It runs any Linux program, starts quickly, and is memory-efficient, but it shares
the kernel — so it is appropriate for code you trust.

**microVM** — a rootfs image run inside a Firecracker-class virtual machine
with its own kernel (build one from an OCI image with `compute build`). It gives
hardware-level isolation for untrusted or tenant-supplied code, at the cost of a
heavier boot and a kernel per instance.
boatramp ships both an external-Firecracker backend and an embedded rust-vmm
backend; a microVM backend is available on Linux hosts with `/dev/kvm`.

## The root filesystem is typed

A non-Wasm runtime boots from a **root filesystem source**, and the three
substrates accept three different artifact forms. Since 0.2.0 this is a typed
`RootSource` with one variant per form — not one overloaded string — so a mismatch
is a typed error at declare time rather than a silent runtime failure:

- **`image`** — an OCI image reference the backend pulls (the `docker` and
  `cloudflare` substrates).
- **`tar`** — a tar rootfs archive, unpacked for the native `container` runtime.
- **`rootfs`** — a rootfs filesystem image (a block device; `ext4` by default),
  which the `firecracker` microVM mounts alongside its kernel.

`boatramp compute set` takes exactly one of `--image` / `--tar` / `--rootfs`,
matched to the target substrate; `compute build` produces a `rootfs` from an OCI
image. See [Run a container or microVM](../how-to/compute.md).

## Choosing

| | Wasm | Container | microVM |
| --- | --- | --- | --- |
| Isolation | in-process capability sandbox | shared kernel + namespaces | own kernel (hardware) |
| Startup | sub-millisecond | fast | boot (or restore) |
| Runs | `wasi:http` components | any Linux program | any Linux program |
| Trust | any | code you trust | untrusted / tenant code |

A function selects its runtime with a `runtime` knob (`wasm` by default); the
trigger, versioning, and addressing are the same whichever runtime executes it.
The isolation choice is also a posture decision. Under the strict `multi-tenant`
[security posture](./security-posture.md), shared-kernel (container) compute is
disabled, so a workload marked `--isolation untrusted` — or any workload under
that posture — runs in a microVM. A `single-tenant` operator who owns every
image can allow containers for their lower overhead.

## Scale to zero

A microVM workload can snapshot its running state and stop when idle, then
restore on the next request, so an idle service costs nothing. A restore resumes
the guest where it paused rather than booting it. See
[Scale compute to zero](../how-to/scale-to-zero.md).

## Where it runs

The control plane schedules workloads across nodes that advertise compute
capacity and reconciles the running replicas toward the desired count. The
backends are capability-detected per host (container where allowed, microVM where
`/dev/kvm` exists), so the same workload definition runs wherever it can. See the
[architecture overview](./architecture.md).
