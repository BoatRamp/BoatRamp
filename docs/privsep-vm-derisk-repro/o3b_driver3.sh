#!/usr/bin/env bash
# O3b driver v3 — large-relocation-table static-PIE variant (~100k RELATIVE relocs, multi-MB RELASZ,
# matching boatramp's real 240k/5.7MB scale) to rule out a reloc-size-triggered #GP. Reuses the
# toolchain + kernel + shim from v2.
set -uo pipefail
WORK="$HOME/boatramp-agent-tests/privsep-vm-derisk"; cd "$WORK"
KERNEL="$WORK/vmlinux-5.10.225"; TARGET=x86_64-unknown-linux-musl
export RUSTUP_HOME="$WORK/.rustup" CARGO_HOME="$WORK/.cargo"; export PATH="$CARGO_HOME/bin:$PATH"
OUT="target/$TARGET/release"
echo "############ O3b DRIVER v3 (big-reloc) START $(date -u +%FT%TZ) ############"
( cd proxy && RUSTFLAGS="-C target-feature=-crt-static -C relocation-model=pic" cargo zigbuild --release --target "$TARGET" --bin payload_big ) >/tmp/cargo_big.log 2>&1 \
  || { echo "BUILD payload_big FAILED:"; tail -30 /tmp/cargo_big.log; exit 1; }
cp "proxy/$OUT/payload_big" payload_big
t=$(readelf -h payload_big | awk -F: '/Type:/{print $2}' | sed 's/^ *//')
relasz=$(readelf -d payload_big | awk '/RELASZ/{print $(NF-1)}')
relac=$(readelf -d payload_big | awk '/RELACOUNT/{print $NF}')
printf '## payload_big: Type=%s RELASZ=%s bytes RELACOUNT=%s  size=%s bytes\n' "$t" "$relasz" "$relac" "$(stat -c%s payload_big)"
mk_initrd(){ local out="$1" init="$2" payload="${3:-}" d; d=$(mktemp -d)
  mkdir -p "$d/proc" "$d/sys" "$d/dev"; cp "$init" "$d/init"; chmod 0755 "$d/init"
  [ -n "$payload" ] && { cp "$payload" "$d/payload"; chmod 0755 "$d/payload"; }
  sudo mknod "$d/dev/console" c 5 1 2>/dev/null; sudo chmod 0666 "$d/dev/console"
  sudo mknod "$d/dev/null" c 1 3 2>/dev/null; sudo chmod 0666 "$d/dev/null"
  ( cd "$d" && find . | cpio -o -H newc 2>/dev/null | gzip -9 ) > "$out"; rm -rf "$d"
  echo "   built $out ($(stat -c%s "$out") bytes)"; }
boot_once(){ local initrd="$1" log="$2" cfg; cfg=$(mktemp)
  cat > "$cfg" <<JSON
{ "boot-source": { "kernel_image_path": "$KERNEL", "initrd_path": "$initrd",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro rdinit=/init" },
  "drives": [], "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 } }
JSON
  timeout 45 firecracker --no-api --config-file "$cfg" > "$log" 2>&1; rm -f "$cfg"; }
run_exp(){ local name="$1" initrd="$2" e1="" e2=""
  echo; echo "======== EXPERIMENT: $name ========"
  for i in 1 2; do local log="boot_${name}_${i}.log"; boot_once "$initrd" "$log"
    local shim alive okln entry panic
    shim=$(grep -c -E 'SHIM-ALIVE' "$log"); alive=$(grep -c -E 'PAYLOADBIG-ALIVE' "$log")
    okln=$(grep -E 'PAYLOADBIG-ALIVE' "$log" | head -1)
    entry=$(grep -E 'PAYLOAD-AT_ENTRY' "$log" | head -1 | awk '{print $2}')
    panic=$(grep -c -iE 'Kernel panic|general protection|unable to handle kernel|segfault|Attempted to kill init|trap invalid opcode|BUG:|Oops' "$log")
    printf '  boot %d: shim_alive=%s big_alive=%s at_entry=%s fault/panic=%s | %s\n' "$i" "$shim" "$alive" "${entry:-NONE}" "$panic" "$okln"
    [ "$i" = 1 ] && e1="$entry" || e2="$entry"
  done
  if [ -n "$e1" ] && [ -n "$e2" ] && [ "$e1" != "$e2" ]; then echo "  ASLR: ACTIVE ($e1 vs $e2)"
  elif [ -n "$e1" ] && [ "$e1" = "$e2" ]; then echo "  ASLR: NOT observed ($e1)"
  else echo "  did NOT reach main on >=1 boot"; fi; }
mk_initrd initrd_big_direct.cpio.gz payload_big
mk_initrd initrd_shim_big.cpio.gz   shim_nopie payload_big
run_exp "D_big_direct" initrd_big_direct.cpio.gz
run_exp "E_shim_to_big" initrd_shim_big.cpio.gz
echo; echo "############ O3b DRIVER v3 END $(date -u +%FT%TZ) ############"
