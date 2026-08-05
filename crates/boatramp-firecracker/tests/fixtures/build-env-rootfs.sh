#!/usr/bin/env bash
# Build the vminit+envdump ext4 rootfs for the `delivers_runtime_env_to_the_
# guest_via_cmdline` live test (the microVM env-drop end-to-end validation).
#
# Mirrors boatramp_firecracker::oci::{write_init,build_ext4}: /sbin/init = the
# freestanding vminit, /etc/boatramp/{argv,env,cwd}, the pseudo-fs mount-point
# dirs, and the workload binary at /envdump. The baked env carries a var the
# runtime cmdline overrides (BR_TEST) and a baked-only var (BR_BAKED); the test
# injects BR_RUNTIME + BR_TEST via `boatramp.env=<hex>` and asserts the runtime
# values win and arrive. No mount/root needed: `mke2fs -d` populates from a dir.
#
# Usage: build-env-rootfs.sh [OUT.ext4] [CRATE_DIR]
#   OUT.ext4   output image path        (default: /tmp/br-env-root.ext4)
#   CRATE_DIR  the boatramp-firecracker crate root, holding src/vminit.c
#              (default: two levels up from this script)
# Honors $CC (default cc). Then run the test with:
#   BOATRAMP_TEST_KERNEL=<vmlinux> BOATRAMP_TEST_ROOTFS=<OUT.ext4> \
#     cargo test -p boatramp-firecracker --features embedded --lib \
#     delivers_runtime_env_to_the_guest_via_cmdline -- --ignored --nocapture
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-/tmp/br-env-root.ext4}"
CRATE_DIR="${2:-"$(cd "$here/../.." && pwd)"}"
CC="${CC:-cc}"
VMINIT="$CRATE_DIR/src/vminit.c"
ENVDUMP="$here/envdump.c"
ROOT="$(dirname "$OUT")/br-env-root.dir"
CFLAGS=(-static -nostdlib -ffreestanding -no-pie -Os -Wall -fno-stack-protector)

rm -rf "$ROOT" "$OUT"
mkdir -p "$ROOT"/{sbin,etc/boatramp,proc,sys,dev,tmp,run}

"$CC" "${CFLAGS[@]}" "$VMINIT" -o "$ROOT/sbin/init"
"$CC" "${CFLAGS[@]}" "$ENVDUMP" -o "$ROOT/envdump"
chmod 0755 "$ROOT/sbin/init" "$ROOT/envdump"

# NUL-separated exec spec (matches oci::nul_join: each string NUL-terminated).
printf '/envdump\0' > "$ROOT/etc/boatramp/argv"
printf 'BR_TEST=baked_loses\0BR_BAKED=baked_ok\0' > "$ROOT/etc/boatramp/env"
printf '/' > "$ROOT/etc/boatramp/cwd"

mke2fs -q -t ext4 -F -d "$ROOT" "$OUT" 128m
rm -rf "$ROOT"
echo "built $OUT ($(stat -c %s "$OUT" 2>/dev/null || stat -f %z "$OUT") bytes)"
