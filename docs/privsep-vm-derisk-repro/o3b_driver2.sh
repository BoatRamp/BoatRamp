#!/usr/bin/env bash
# O3b validation driver v2 — faithful Rust+musl+cargo-zigbuild proxies built with the repo's EXACT
# release recipe (`-C target-feature=-crt-static` => genuine static-PIE ET_DYN, per
# docs/privsep-build-hardening.md). Reproduces the baseline, tests the shim fix, measures ASLR.
#
# Run under: nix shell nixpkgs#rustup nixpkgs#cargo-zigbuild nixpkgs#zig nixpkgs#binutils nixpkgs#file \
#            nixpkgs#firecracker nixpkgs#cpio nixpkgs#gzip nixpkgs#curl --command bash o3b_driver2.sh
set -uo pipefail
WORK="$HOME/boatramp-agent-tests/privsep-vm-derisk"; mkdir -p "$WORK"; cd "$WORK"
KERNEL="$WORK/vmlinux-5.10.225"
TARGET=x86_64-unknown-linux-musl
export RUSTUP_HOME="$WORK/.rustup" CARGO_HOME="$WORK/.cargo"
export PATH="$CARGO_HOME/bin:$PATH"

echo "############ O3b DRIVER v2 START $(date -u +%FT%TZ) ############"
# --- rustup toolchain (idempotent) ---
if ! rustc --version >/dev/null 2>&1; then
  echo "## installing rust stable + musl target (first run)"
  rustup default stable >/tmp/rustup.log 2>&1 || { echo "rustup default stable failed"; tail -20 /tmp/rustup.log; exit 1; }
fi
rustup target add "$TARGET" >>/tmp/rustup.log 2>&1
echo "## rustc: $(rustc --version)   cargo-zigbuild: $(cargo-zigbuild --version 2>/dev/null)"

OUT="target/$TARGET/release"
build(){ # $1 extra-rustflags  -> builds payload+shim into $OUT
  ( cd proxy && RUSTFLAGS="$1" cargo zigbuild --release --target "$TARGET" --bin payload --bin shim ) >/tmp/cargo.log 2>&1 \
    || { echo "BUILD FAILED (RUSTFLAGS=$1):"; tail -30 /tmp/cargo.log; return 1; }
}

echo "## build A: static-PIE payload (repo PIE recipe: -C target-feature=-crt-static -C relocation-model=pic)"
build "-C target-feature=-crt-static -C relocation-model=pic" || exit 1
cp "proxy/$OUT/payload" payload_pie
echo "## build B: non-PIE baseline payload + shim (rustc musl default = +crt-static => ET_EXEC)"
build "" || exit 1
cp "proxy/$OUT/payload" payload_nopie
cp "proxy/$OUT/shim" shim_nopie

echo "## ELF classification:"
for b in payload_pie payload_nopie shim_nopie; do
  [ -x "$b" ] || { echo "   $b MISSING"; continue; }
  t=$(readelf -h "$b" 2>/dev/null | awk -F: '/Type:/{print $2}' | sed 's/^ *//')
  interp=$(readelf -l "$b" 2>/dev/null | grep -c INTERP)
  needed=$(readelf -d "$b" 2>/dev/null | grep -c NEEDED)
  relasz=$(readelf -d "$b" 2>/dev/null | awk '/RELASZ/{print $NF}')
  printf '   %-13s Type=%-42s PT_INTERP=%s DT_NEEDED=%s RELASZ=%s\n' "$b" "$t" "$interp" "$needed" "${relasz:-0}"
  printf '     %s\n' "$(file -b "$b" | cut -c1-82)"
done

mk_initrd(){ # $1 out  $2 init  [$3 payload]
  local out="$1" init="$2" payload="${3:-}" d; d=$(mktemp -d)
  mkdir -p "$d/proc" "$d/sys" "$d/dev"; cp "$init" "$d/init"; chmod 0755 "$d/init"
  [ -n "$payload" ] && { cp "$payload" "$d/payload"; chmod 0755 "$d/payload"; }
  sudo mknod "$d/dev/console" c 5 1 2>/dev/null; sudo chmod 0666 "$d/dev/console"
  sudo mknod "$d/dev/null" c 1 3 2>/dev/null; sudo chmod 0666 "$d/dev/null"
  ( cd "$d" && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$out"; rm -rf "$d"
  echo "   built $out ($(ls -l "$out" | awk '{print $5}') bytes)"
}
boot_once(){ local initrd="$1" log="$2" cfg; cfg=$(mktemp)
  cat > "$cfg" <<JSON
{ "boot-source": { "kernel_image_path": "$KERNEL", "initrd_path": "$initrd",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro rdinit=/init" },
  "drives": [], "machine-config": { "vcpu_count": 1, "mem_size_mib": 256 } }
JSON
  timeout 40 firecracker --no-api --config-file "$cfg" > "$log" 2>&1; rm -f "$cfg"; }
run_exp(){ local name="$1" initrd="$2" e1="" e2="" m1="" m2=""
  echo; echo "======== EXPERIMENT: $name ========"
  for i in 1 2; do local log="boot_${name}_${i}.log"; boot_once "$initrd" "$log"
    local shim alive entry fail panic
    shim=$(grep -c -E 'SHIM-ALIVE' "$log"); alive=$(grep -c -E 'PAYLOAD-ALIVE' "$log")
    entry=$(grep -E 'PAYLOAD-AT_ENTRY' "$log" | head -1 | awk '{print $2}')
    fail=$(grep -c -E 'SHIM-EXECVE-FAILED' "$log")
    panic=$(grep -c -iE 'Kernel panic|general protection|unable to handle kernel|segfault|Attempted to kill init|trap invalid opcode|BUG:|Oops' "$log")
    printf '  boot %d: shim_alive=%s payload_alive=%s at_entry=%s execve_failed=%s fault/panic=%s\n' "$i" "$shim" "$alive" "${entry:-NONE}" "$fail" "$panic"
    local mapsbase; mapsbase=$(grep -E 'PAYLOAD-MAPS0' "$log" | head -1 | awk '{print $2}')
    if [ "$i" = 1 ]; then e1="$entry"; m1="$mapsbase"; else e2="$entry"; m2="$mapsbase"; fi
  done
  echo "  --- verdict($name): ---"
  if [ -n "$e1" ] && [ -n "$e2" ]; then
    if [ "$e1" != "$e2" ]; then echo "  ASLR: ACTIVE  (AT_ENTRY differs: $e1 vs $e2 ; maps-base $m1 vs $m2)"
    else echo "  ASLR: NOT observed (AT_ENTRY identical: $e1)"; fi
  else echo "  payload did NOT reach main on >=1 boot -> inspect boot_${name}_*.log"; fi
}
echo "## assembling initramfs images"
mk_initrd initrd_pie_direct.cpio.gz   payload_pie
mk_initrd initrd_nopie_direct.cpio.gz payload_nopie
mk_initrd initrd_shim_pie.cpio.gz     shim_nopie payload_pie
run_exp "C_nonpie_direct" initrd_nopie_direct.cpio.gz
run_exp "A_pie_direct"    initrd_pie_direct.cpio.gz
run_exp "B_shim_to_pie"   initrd_shim_pie.cpio.gz
echo; echo "############ O3b DRIVER v2 END $(date -u +%FT%TZ) ############"
