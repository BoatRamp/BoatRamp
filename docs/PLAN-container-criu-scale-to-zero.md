# PLAN — CRIU-backed scale-to-zero for the native `container` backend

## Goal
Give the native `container` backend the same **state-preserving** scale-to-zero the
microVM backends have (`vmm-embedded`, `vmm` firecracker, `vmm-vz`): an idle replica
is checkpointed to disk, its processes killed, and later restored with in-RAM state
intact — so `scale_to_zero: true` means one thing on every backend (the uniform-UX
invariant). The container analog of VM snapshot/restore is **CRIU** (Checkpoint/Restore
In Userspace), the same mechanism runc/Podman `checkpoint`/`restore` use.

## What the checkpoint target actually is (from the code)
`ContainerBackend::launch` → `boatramp __sandbox` worker (`worker.rs`):
- `prepare()`: create cgroup `/sys/fs/cgroup/boatramp/<id>`, `unshare({mount,pid,net,uts,ipc,user})`, write uid/gid maps (container id 0 → host 100000, 65536 ids).
- launcher moves the veth peer into the worker netns + configures `eth0` (`configure_in_netns`).
- `jail_and_run()`: `fork()` → child = **PID 1** of the new pidns → `pivot_root` into the rootfs, bind volumes + standard mounts (`/proc`, `/sys` ro, `/dev`/`/tmp` tmpfs), drop caps, drop to unpriv uid/gid, install seccomp, `execve` entrypoint. Parent = monitor, `waitpid`s.
- `launch_inner` then `drop(child)` — the serve process **detaches**; the tree lives in the cgroup.

So CRIU must dump/restore a **userns + pidns + mntns(pivot_root) + netns + utsns + ipcns**
tree with **external bind mounts** (volumes + rootfs) and a **veth into the host bridge**,
with seccomp on the leaf. This is the *full runc-parity* CRIU scenario, not a subset.

## Design

### 0. Prerequisite refactor — track the running pid (small, self-contained)
The backend currently detaches the child, so it has no pid to checkpoint. Add a
`running: Mutex<HashMap<String, RunningContainer>>` (`{pid, ip, plan, port}`) populated by
`launch` and consumed by `snapshot`/`stop` — mirroring `VzBackend`/`EmbeddedVmmBackend`.

### 1. Capability detection (gate the promise on the environment)
`ContainerBackend::new` probes once and stores `criu_ok: bool`:
- `criu` binary on PATH **and** `criu check --feature mnt_ext_map` (or `criu check --all`) passes,
- kernel `CONFIG_CHECKPOINT_RESTORE=y`,
- we hold `CAP_CHECKPOINT_RESTORE` (kernel ≥5.9) or `CAP_SYS_ADMIN`.
`capabilities().scale_to_zero = self.criu_ok`. Where absent, the scheduler already routes a
`scale_to_zero` workload to a capable backend (`compute.rs:366`) — no regression.

### 2. `snapshot()` (park)
1. Look up `RunningContainer` (pid). `Ok(None)` if not running.
2. `criu dump --tree <pid> --images-dir <dir>` with:
   `--manage-cgroups=full`, `--empty-ns net` (we own networking — CRIU won't touch the
   netns contents), `--external mnt[...]` for the rootfs bind + each volume bind + the
   pseudo-mounts, `--tcp-established`, `--file-locks`, `--link-remap`, `--ghost-limit`.
   CRIU kills the tree on a successful dump.
3. Tear down the veth (like `stop`, but keep the IP reserved). Persist a snapshot record
   (`data_ref = <images-dir>|<ip>|<port>`; the `<id>.plan.json` beside it).

### 3. `restore()` (wake)
1. Re-reserve the IP; re-run `veth.host_setup()`.
2. `criu restore --images-dir <dir> --restore-detached --manage-cgroups=full --empty-ns net`
   `--ext-mount-map` (each external bind → its current host source) and an
   `--action-script <boatramp __criu-net-setup ...>`. At the `setup-namespaces` /
   `post-setup-namespaces` hook CRIU exports `CRTOOLS_INIT_PID`; the action-script is a new
   hidden `boatramp` subcommand that reuses `move_peer_into_netns` + `configure_in_netns`
   to plug the veth peer into the restored netns and re-add `eth0`/route — exactly the
   launch-time network setup, retargeted at the CRIU-created netns.
3. Record the new pid in `running`; return the `Instance` at the same endpoint.

### 4. Tests
- **Native (every host, no privilege):** `RunningContainer` map; snapshot-ref encode/decode;
  the CRIU **arg-vector builders** for dump + restore (assert flags, `--external`/
  `--ext-mount-map` entries, action-script wiring) — pure functions, no `criu` run;
  capability-probe parsing.
- **Live (`#[ignore]`, privileged Linux + CRIU):** `container_criu_roundtrip` in the
  `container_live` seam — launch a container serving a boot-nonce, `snapshot`, `restore`,
  re-probe the nonce, assert it's preserved and the process didn't cold-restart. Mirrors the
  VZ `vz_live_snapshot_restore_roundtrip`.

## Honest risks
1. **runc-parity CRIU.** userns + pidns + external-mount-map + the pivot_root'd mount tree are
   the parts runc/CRIU co-hardened over years. Expect iteration; needs a modern CRIU (≥3.17)
   and kernel ≥5.9. Some workloads (GPU, exotic fds) never checkpoint.
2. **Two-process monitor+init model.** Our `fork()` (monitor waits on PID-1) may need to change
   to a CRIU-friendly shape (e.g. don't detach; a supervisor that CRIU restore-detached
   reattaches to). Possible small change to `worker.rs`.
3. **`--empty-ns net` + action-script netns handshake** is the fiddliest runtime bit but reuses
   code we already have.

## The blocker I can't resolve myself: where does the live round-trip run?
The `container` backend is **Linux-only + privileged** (namespaces, cgroup v2, CAP_*). This
dev host is **macOS** — I cannot run it, let alone CRIU, here. The existing `container_live`
seam has no automated privileged-Linux runner either. So a *validated* live round-trip needs a
privileged Linux host with CRIU, which does not currently exist in reach. Building the whole
integration and committing it **without** a live checkpoint→restore is exactly the VZ
overclaim trap ("a save you can't restore is useless") — I won't do that silently.
