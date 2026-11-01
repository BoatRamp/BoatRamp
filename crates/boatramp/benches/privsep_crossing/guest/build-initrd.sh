#!/usr/bin/env bash
# Builds the minimal firecracker-guest initrd for the `vsock-firecracker` substrate.
#
# `privsep-vsock-guest` (the `[[bin]]` target in `crates/boatramp/Cargo.toml`, source
# `../vsock_guest_main.rs`) is PID 1 inside the microVM (booted via `rdinit=/init`): it depends on
# nothing but `libc` + `std` (via the `#[path]`-included `wire.rs` / `vsock_raw.rs`, shared with
# the host-side bench binary), so it cross-compiles fast and links fully static
# (`x86_64-unknown-linux-musl`, `crt-static`, non-PIE). A dynamically linked OR self-relocating
# static-PIE guest init cannot run as a minimal initrd's PID 1 — see the relocation-model note
# below and the methodology caveats in `../main.rs`.
#
# Usage (inside `nix develop`, for the musl rustup target + its linker):
#   bash guest/build-initrd.sh /path/to/out/initrd.cpio.gz
#
# Lighthouse-only (needs a Linux static/musl toolchain + `cpio`); not run by CI.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../../.." && pwd)"
out="${1:?usage: build-initrd.sh <out-initrd.cpio.gz>}"

(
  cd "$repo_root"
  # `-C relocation-model=static`: the musl target otherwise defaults to a self-relocating
  # static-PIE, which general-protection-faults at startup in a firecracker/minimal-kernel guest
  # with no dynamic linker to finish the relocation (confirmed empirically: serial console shows
  # a #GP right at the first post-libc-init syscall, before `main` ever runs; a plain non-PIE
  # static binary needs no such relocation step and boots cleanly as PID 1).
  RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static" \
    cargo build --release --target x86_64-unknown-linux-musl \
    -p boatramp --bin privsep-vsock-guest
)

bin="$repo_root/target/x86_64-unknown-linux-musl/release/privsep-vsock-guest"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/root"
cp "$bin" "$scratch/root/init"
chmod +x "$scratch/root/init"

( cd "$scratch/root" && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$out"
echo "wrote $out ($(stat -c%s "$out" 2>/dev/null || stat -f%z "$out") bytes)" >&2
