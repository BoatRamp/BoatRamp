# Scoped privsep VM substrate — live serve-gate reproduction

Reproduction material for the **scoped VM first cut** (firecracker/Linux, static-parser-frontends-only)
in `crates/boatramp/src/privsep_vm.rs` + `crates/boatramp/DESIGN-privsep-phase3-vm.md` §1c. It drives
the committed integration test `crates/boatramp/tests/privsep_vm_live.rs`
(`privsep_vm_scoped_frontend_serves_200_over_vsock`), which boots a **real** firecracker microVM and
serves a `200` over the vsock relay — exercising the real Rust host launcher
`boatramp::privsep_vm::launch_frontend_vm`.

## What it proves

A key-free **static-parser frontend** (`listen.http-parse` only — no crown jewel, no backend
credential) runs inside a hardware-virtualized microVM guest, reached over a vsock **client-byte** relay
(Model A — the secret-blind root binds the privileged TCP listener, accepts, and relays the client's
bytes into the guest; NO key material ever crosses the root). Inside the guest, the **non-PIE init
shim** (own-binary-as-init, O3b) is PID 1 and `execve`s the literal static-PIE `boatramp __vm-guest`,
which binds AF_VSOCK, installs its fail-closed `Enforced` seccomp/Landlock profile (S4), and serves the
relayed client with the real `boatramp_http` stack. The hypervisor boundary is the primary wall; the
in-guest per-capability profile is defense-in-depth.

This closes the de-risk §1.5 fidelity gap (the **literal** `boatramp` binary via the shim, not a proxy)
and adds the transport proof (the vsock relay + guest serve + HTTP 200 end-to-end).

## Prerequisites (lighthouse-only)

- `/dev/kvm` + `firecracker` (nixpkgs#firecracker 1.13.x). Firecracker's x86_64 loader needs the
  UNCOMPRESSED `vmlinux` ELF — a bzImage fails with "Invalid Elf magic number".
- A **Landlock-V5** guest kernel — kernel **>= 6.10** with `CONFIG_SECURITY_LANDLOCK=y`. This is the
  privsep profile's `MIN_LANDLOCK_ABI = ABI::V5` floor
  (`crates/boatramp-server/src/sandbox.rs`). **The firecracker CI kernels (<= 6.1, Landlock ABI <= V2)
  do NOT meet it** — this is the concrete S3/S4 guest-kernel-provenance requirement. Build one with
  `kernel.nix` (a 6.12.67 microVM kernel = the firecracker CI 6.1 x86_64 config + Landlock enabled,
  against `pkgs.linux_6_12`):

  ```sh
  # fetch the firecracker CI base config, enable Landlock, build:
  curl -fsSLo fc-base.config \
    https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.13.1/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config
  printf 'CONFIG_SECURITY=y\nCONFIG_SECURITYFS=y\nCONFIG_SECURITY_LANDLOCK=y\nCONFIG_LSM="landlock,yama,bpf"\n' >> fc-base.config
  nix-build kernel.nix -o kernel-result        # -> kernel-result/vmlinux (the uncompressed ELF firecracker needs)
  ```

## Run

```sh
# on lighthouse, from the repo root, inside the agent scratch clone:
nix shell nixpkgs#rustup nixpkgs#cargo-zigbuild nixpkgs#zig nixpkgs#firecracker \
          nixpkgs#binutils nixpkgs#gcc nixpkgs#pkg-config nixpkgs#openssl --command \
  env GUEST_KERNEL=$PWD/kbuild/kernel-result/vmlinux \
  bash docs/privsep-vm-scoped-repro/run.sh
```

The driver builds the musl static-PIE `boatramp` + the non-PIE shim, pins the guest-kernel hash (S3),
and runs the serve gate, which greps `PRIVSEP VM SCOPED SERVE OK`.

## Not a GitHub-CI gate

GitHub's hosted runners have no `/dev/kvm`, so this is **not** wired as a GitHub-CI merge gate. The
evidence is the lighthouse run captured in the log. The composition lint
(`check_vm_secret_blindness_closure`, which refuses any VM instance outside the key-free scope) IS a
pure unit gate that runs in CI.
