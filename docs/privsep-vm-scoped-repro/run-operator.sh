#!/usr/bin/env bash
# Live gate for the scoped privsep VM substrate's OPERATOR SUPERVISE-DISPATCH (S1 —
# `crates/boatramp/DESIGN-privsep-phase3-vm-scoped.md`). Unlike `run.sh` (which drives
# `privsep_vm_live.rs` → `launch_frontend_vm`, byte-relay on an in-root THREAD), this drives the REAL
# operator path via `boatramp __root`: bind the listener, boot the microVM guest (NO in-root relay),
# `fork`+`exec` a SEPARATE `__vm-relay` process, run its POSITIVE readiness handshake (Finding 1), and
# supervise BOTH the firecracker child and the relay child. It proves: serve a 200 end-to-end
# (`PRIVSEP VM SUPERVISE SERVE OK`), then SIGKILL the relay child ⇒ FailNodeClosed
# (`PRIVSEP VM RELAY-KILL FAILCLOSED OK`), then SIGKILL firecracker ⇒ FailNodeClosed
# (`PRIVSEP VM FIRECRACKER-KILL FAILCLOSED OK`).
#
# LIGHTHOUSE-ONLY and runs the test under SUDO: the root must be privileged (/dev/kvm + the privileged
# listener bind), and the `__vm-relay` child inherits CAP_SYS_ADMIN from it to enter its netns/mount-ns.
#
# Run (from the repo root, on lighthouse, inside the agent scratch clone):
#   GUEST_KERNEL=/abs/path/to/vmlinux bash docs/privsep-vm-scoped-repro/run-operator.sh
set -uo pipefail

# The musl link step opens ~1000+ object files at once; the default 1024 fd limit overflows it
# (`ProcessFdQuotaExceeded`). Raise it (1M, else 64k) before any build.
ulimit -n 1048576 2>/dev/null || ulimit -n 65536 2>/dev/null || true

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
TARGET=x86_64-unknown-linux-musl
: "${GUEST_KERNEL:?set GUEST_KERNEL to the Landlock-V5 guest vmlinux (kernel >= 6.10)}"
FIRECRACKER="${FIRECRACKER:-$(command -v firecracker)}"
: "${FIRECRACKER:?firecracker not found — run inside \`nix shell nixpkgs#firecracker\`}"

: "${ZIG:=$(command -v zig)}"
: "${ZIG:?zig not found — run inside \`nix shell nixpkgs#zig\`}"
command -v cargo-zigbuild >/dev/null || { echo "cargo-zigbuild not found — run inside \`nix shell nixpkgs#cargo-zigbuild\`"; exit 1; }

# `cargo zigbuild` (NOT plain `cargo build` + a hand-rolled `zig cc` wrapper): cargo-zigbuild
# translates the Rust triple `x86_64-unknown-linux-musl` to zig's `x86_64-linux-musl` and handles the
# `ring` / `aws-lc-sys` cross asm. A bare `zig cc -target x86_64-linux-musl` wrapper breaks on current
# zig (>= 0.15), which rejects the `--target=x86_64-unknown-linux-musl` cc-rs ALSO passes through
# ("UnknownOperatingSystem").
echo "## 1. musl static-PIE boatramp (the ROOT binary AND the guest own-binary-as-init payload)"
cargo zigbuild --release --target "$TARGET" -p boatramp \
  --no-default-features --features fs,sandbox 2>&1 | tail -3 || exit 1
ROOT_BIN="$REPO/target/$TARGET/release/boatramp"

echo "## 2. NON-PIE init shim (dedicated non-PIE RUSTFLAGS override)"
RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static" \
  cargo zigbuild --release --target "$TARGET" -p boatramp-privsep-vm-shim 2>&1 | tail -3 || exit 1
SHIM_BIN="$REPO/target/$TARGET/release/boatramp-privsep-vm-shim"

echo "## 3. S3 pin: the guest-kernel content hash"
KSHA=$(sha256sum "$GUEST_KERNEL" | awk '{print $1}')
echo "   kernel=$GUEST_KERNEL sha256=$KSHA"

echo "## 4. build the operator live-gate harness (native gnu — orchestrates only; drop the musl env)"
unset CC_x86_64_unknown_linux_musl CXX_x86_64_unknown_linux_musl AR_x86_64_unknown_linux_musl \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER
# Discover the compiled test binary robustly via cargo's JSON message stream (the human "Executable"
# line's path layout varies; the `executable` field is canonical).
TESTBIN="$(cargo test -p boatramp --no-default-features --features fs,sandbox \
  --test privsep_vm_operator_live --no-run --message-format=json 2>/dev/null \
  | grep -oE '"executable":"[^"]*privsep_vm_operator_live[^"]*"' \
  | tail -1 | sed -E 's/"executable":"(.*)"/\1/')"
: "${TESTBIN:?could not locate the compiled operator live-gate test binary}"
echo "   test binary = $TESTBIN"

echo "## 5. run the operator live gate UNDER SUDO (root boots the microVM + supervises the relay)"
export BOATRAMP_PRIVSEP_VM_FIRECRACKER="$FIRECRACKER"
export BOATRAMP_PRIVSEP_VM_KERNEL="$GUEST_KERNEL"
export BOATRAMP_PRIVSEP_VM_KERNEL_SHA256="$KSHA"
export BOATRAMP_PRIVSEP_VM_SHIM="$SHIM_BIN"
export BOATRAMP_PRIVSEP_VM_ROOT_BIN="$ROOT_BIN"
export RUST_LOG="${RUST_LOG:-boatramp=info}"
sudo -E env \
  BOATRAMP_PRIVSEP_VM_FIRECRACKER="$BOATRAMP_PRIVSEP_VM_FIRECRACKER" \
  BOATRAMP_PRIVSEP_VM_KERNEL="$BOATRAMP_PRIVSEP_VM_KERNEL" \
  BOATRAMP_PRIVSEP_VM_KERNEL_SHA256="$BOATRAMP_PRIVSEP_VM_KERNEL_SHA256" \
  BOATRAMP_PRIVSEP_VM_SHIM="$BOATRAMP_PRIVSEP_VM_SHIM" \
  BOATRAMP_PRIVSEP_VM_ROOT_BIN="$BOATRAMP_PRIVSEP_VM_ROOT_BIN" \
  RUST_LOG="$RUST_LOG" \
  "$TESTBIN" --ignored --nocapture 2>&1 | tee /tmp/privsep-vm-operator-live.log
rc=${PIPESTATUS[0]}

echo
need=(
  "PRIVSEP VM SUPERVISE SERVE OK"
  "PRIVSEP VM RELAY-KILL FAILCLOSED OK"
  "PRIVSEP VM FIRECRACKER-KILL FAILCLOSED OK"
)
ok=1
for m in "${need[@]}"; do
  if ! grep -qF "$m" /tmp/privsep-vm-operator-live.log; then
    echo "MISSING MARKER: $m"; ok=0
  fi
done
if [ "$ok" = 1 ] && [ "$rc" = 0 ]; then
  echo "RESULT: operator supervise-dispatch OK — served a 200, and killing EITHER child FailNodeClosed the node"
  exit 0
else
  echo "RESULT: operator live gate did NOT pass (exit $rc) — inspect the log + the guest serial console above"
  exit 1
fi
