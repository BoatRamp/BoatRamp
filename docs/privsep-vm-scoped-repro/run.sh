#!/usr/bin/env bash
# Live serve gate for the SCOPED privsep VM substrate (firecracker/Linux, static-parser-frontends-only
# — `crates/boatramp/DESIGN-privsep-phase3-vm.md` §1c / the de-risk §1.5 "first serve-gate assertion").
#
# It builds the real assets and drives the committed integration test
# `crates/boatramp/tests/privsep_vm_live.rs` (`privsep_vm_scoped_frontend_serves_200_over_vsock`),
# which exercises the REAL Rust host launcher `boatramp::privsep_vm::launch_frontend_vm`: assemble the
# initramfs (the non-PIE shim as /init + the literal static-PIE `boatramp` + the real config), S3-verify
# + boot a firecracker microVM (kernel + initramfs + vsock, no net, no drives), run the host client-byte
# relay, and — in the guest — `execve` `boatramp __vm-guest`, bind AF_VSOCK, install the fail-closed
# `Enforced` profile (S4), and serve a relayed client to a 200 with the real `boatramp_http` stack.
#
# LIGHTHOUSE-ONLY. Requires:
#   - /dev/kvm + firecracker (nixpkgs#firecracker 1.13.x accepts the bzImage directly);
#   - a Landlock-V5 guest kernel (kernel >= 6.10 with CONFIG_SECURITY_LANDLOCK=y — the privsep profile's
#     MIN_LANDLOCK_ABI floor; the firecracker CI kernels (<=6.1) do NOT meet it — S3/S4). See
#     `kbuild/kernel.nix` for the 6.12.67 Landlock microVM kernel this repo builds.
#   - a musl static-PIE `boatramp` + a NON-PIE shim, both built below.
#
# Run (from the repo root, on lighthouse, inside the agent scratch clone):
#   GUEST_KERNEL=/abs/path/to/bzImage bash docs/privsep-vm-scoped-repro/run.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
TARGET=x86_64-unknown-linux-musl
: "${GUEST_KERNEL:?set GUEST_KERNEL to the Landlock-V5 guest bzImage/vmlinux (kernel >= 6.10)}"
FIRECRACKER="${FIRECRACKER:-$(command -v firecracker)}"
: "${FIRECRACKER:?firecracker not found — run inside \`nix shell nixpkgs#firecracker\`}"

# Deterministic musl toolchain: a `zig cc` wrapper as the C compiler / archiver / linker for the musl
# target (cc-rs uses CC_<triple> for C deps like ring/aws-lc-sys; rustc uses the LINKER var). This is
# what cargo-zigbuild does internally, pinned here so a bare `nix shell` resolves it reliably.
: "${ZIG:=$(command -v zig)}"
: "${ZIG:?zig not found — run inside \`nix shell nixpkgs#zig\`}"
WRAP="$(mktemp -d)"
printf '#!/bin/sh\nexec %s cc -target x86_64-linux-musl "$@"\n' "$ZIG" > "$WRAP/zcc"; chmod +x "$WRAP/zcc"
printf '#!/bin/sh\nexec %s c++ -target x86_64-linux-musl "$@"\n' "$ZIG" > "$WRAP/zcxx"; chmod +x "$WRAP/zcxx"
printf '#!/bin/sh\nexec %s ar "$@"\n' "$ZIG" > "$WRAP/zar"; chmod +x "$WRAP/zar"
export CC_x86_64_unknown_linux_musl="$WRAP/zcc"
export CXX_x86_64_unknown_linux_musl="$WRAP/zcxx"
export AR_x86_64_unknown_linux_musl="$WRAP/zar"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$WRAP/zcc"

echo "## 1. musl static-PIE boatramp (the guest own-binary-as-init payload)"
cargo build --release --target "$TARGET" -p boatramp \
  --no-default-features --features fs,sandbox 2>&1 | tail -3 || exit 1
GUEST_BIN="$REPO/target/$TARGET/release/boatramp"

echo "## 2. NON-PIE init shim (a standalone libc-only crate; dedicated non-PIE RUSTFLAGS override)"
RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static" \
  cargo build --release --target "$TARGET" -p boatramp-privsep-vm-shim 2>&1 | tail -3 || exit 1
SHIM_BIN="$REPO/target/$TARGET/release/boatramp-privsep-vm-shim"

echo "## 3. classify the ELF shapes (payload must be static-PIE DYN, shim must be non-PIE EXEC)"
for b in "$GUEST_BIN" "$SHIM_BIN"; do
  t=$(readelf -h "$b" 2>/dev/null | awk -F: '/Type:/{print $2}' | sed 's/^ *//')
  printf '   %-28s Type=%s\n' "$(basename "$b")" "$t"
done

echo "## 4. S3 pin: the guest-kernel content hash"
KSHA=$(sha256sum "$GUEST_KERNEL" | awk '{print $1}')
echo "   kernel=$GUEST_KERNEL sha256=$KSHA"

echo "## 5. run the live serve gate (boots a real microVM; needs /dev/kvm)"
# The host test harness builds for the host (gnu) — drop the musl toolchain env (steps 1-2 only) so a
# host dev-dep (aws-lc-sys) builds with the native cc, not the zig musl wrapper.
unset CC_x86_64_unknown_linux_musl CXX_x86_64_unknown_linux_musl AR_x86_64_unknown_linux_musl \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER
export BOATRAMP_PRIVSEP_VM_FIRECRACKER="$FIRECRACKER"
export BOATRAMP_PRIVSEP_VM_KERNEL="$GUEST_KERNEL"
export BOATRAMP_PRIVSEP_VM_KERNEL_SHA256="$KSHA"
export BOATRAMP_PRIVSEP_VM_SHIM="$SHIM_BIN"
export BOATRAMP_PRIVSEP_VM_GUEST_BIN="$GUEST_BIN"
export RUST_LOG="${RUST_LOG:-boatramp=info}"

# The test HARNESS runs on the HOST (lighthouse) and only orchestrates: it packs the already-built
# MUSL guest binary (BOATRAMP_PRIVSEP_VM_GUEST_BIN) + the non-PIE shim into the initramfs and boots the
# microVM. So it builds NATIVELY (host glibc) — NOT for musl — which sidesteps cross-compiling the
# dev-dependency C crates (aws-lc-sys) to musl. Only the guest payload (step 1) is musl static-PIE.
cargo test -p boatramp \
  --no-default-features --features fs,sandbox \
  --test privsep_vm_live -- --ignored --nocapture 2>&1 | tee /tmp/privsep-vm-scoped-live.log
trap 'rm -rf "$WRAP"' EXIT
rc=${PIPESTATUS[0]}

echo
if grep -q 'PRIVSEP VM SCOPED SERVE OK' /tmp/privsep-vm-scoped-live.log; then
  echo "RESULT: PRIVSEP VM SCOPED SERVE OK — the scoped frontend served a 200 over the vsock relay"
  exit 0
else
  echo "RESULT: live serve gate did NOT reach the 200 marker (exit $rc) — inspect the serial console above"
  exit 1
fi
