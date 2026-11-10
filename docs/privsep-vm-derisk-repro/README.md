# privsep VM substrate — O3b de-risk reproduction harness

Reproduction material for the **O3b** validation in
`crates/boatramp/DESIGN-privsep-phase3-vm-derisk.md` §1 (the non-PIE init-shim hypothesis for
own-binary-as-init). **De-risk only — not shippable code, not part of the boatramp workspace** (the
`proxy/` crate carries its own empty `[workspace]` table so the parent build never sees it).

## What it proves

A tiny non-PIE static **init shim** can be the firecracker guest's PID 1, mount `/proc`, and `execve`
a genuine **static-PIE** payload (boatramp's exact release ELF class: `Type: DYN`, static-pie linked,
no `PT_INTERP`, zero `DT_NEEDED`, musl `crt1` self-relocation), which then runs with **ASLR preserved**
(randomized `AT_ENTRY` across boots). Built with the repo's exact release toolchain (`rustc 1.99.1` +
`cargo-zigbuild` + zig musl, `-C target-feature=-crt-static -C relocation-model=pic`).

## Layout

- `proxy/src/bin/payload.rs` — static-PIE payload: mounts `/proc`, reports `AT_ENTRY` / load base /
  `randomize_va_space`, powers the VM off.
- `proxy/src/bin/payload_big.rs` — same, plus a ~2.4 MB / 100,694-entry `R_X86_64_RELATIVE` table
  (approaching boatramp's real 5.7 MB / 240,782) to cover the self-relocation table-size dimension.
- `proxy/src/bin/shim.rs` — the non-PIE init shim (PID 1 → `execve("/payload")`).
- `o3b_driver2.sh` — builds the static-PIE + non-PIE proxies, classifies ELF, and runs experiments
  C (non-PIE direct), A (static-PIE direct), B (shim → static-PIE), each booted twice.
- `o3b_driver3.sh` — the large-reloc variant: experiments D (big direct) + E (shim → big).

## Run (lighthouse — needs `/dev/kvm`)

```sh
cd ~/boatramp-agent-tests/privsep-vm-derisk   # the single agent scratch folder
nix shell nixpkgs#rustup nixpkgs#cargo-zigbuild nixpkgs#zig nixpkgs#gcc nixpkgs#binutils \
          nixpkgs#file nixpkgs#firecracker nixpkgs#cpio nixpkgs#gzip nixpkgs#curl \
  --command bash o3b_driver2.sh
nix shell nixpkgs#rustup nixpkgs#cargo-zigbuild nixpkgs#zig nixpkgs#gcc nixpkgs#binutils \
          nixpkgs#file nixpkgs#firecracker nixpkgs#cpio nixpkgs#gzip \
  --command bash o3b_driver3.sh
```

The drivers download the firecracker CI `vmlinux-5.10.225` guest kernel, build the proxies, assemble
the initramfs images, and boot each in firecracker 1.13.1, capturing the guest serial console.

## Recorded result (lighthouse, firecracker 1.13.1 + vmlinux-5.10.225 + rustc 1.99.1)

Every boot reached `main` with **zero** `#GP` / panic / segfault in any serial log.

| Exp | PID 1 | ASLR (`AT_ENTRY` boot1 vs boot2) |
|---|---|---|
| C non-PIE direct | non-PIE payload | fixed `0x1013030` (no ASLR — expected) |
| A static-PIE direct | static-PIE payload | ACTIVE `0x7f8318802090` ≠ `0x7f56d52fc090` |
| B **shim → static-PIE** | non-PIE shim | **ACTIVE** `0x7f756a0dd090` ≠ `0x7f068ceb1090` |
| D big-reloc direct | static-PIE (100,694 relocs) | ACTIVE; `reloc_table_ok=true` |
| E **shim → big-reloc** | non-PIE shim | **ACTIVE**; `reloc_table_ok=true` |

Verdict: **O3b PASS** — the shim path boots clean and preserves ASLR; the baseline `#GP` did not
reproduce on this (kernel, toolchain) combo (so the shim is kernel-agnostic insurance). See the design
note §1.4 for the full reading.
