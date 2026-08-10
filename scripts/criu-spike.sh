#!/usr/bin/env bash
# CRIU spike driver — run ON lighthouse inside `nix develop`, as a user with
# passwordless sudo. Launches a real boatramp container (held, no auto-stop),
# inspects networking/httpd, then (phase 2) drives criu dump/restore by hand.
#
#   cd ~/boatramp-criu && nix develop --command bash scripts/criu-spike.sh [inspect|criu]
set -u
cd "$(dirname "$0")/.."
BIN="$PWD/target/debug/boatramp"
TB="$PWD/$(ls -t target/debug/deps/container_live-* | grep -v '\.d$' | head -1)"
ROOTFS=/tmp/bb-rootfs.tar.gz
CG=/sys/fs/cgroup/boatramp/clive-0
PHASE="${1:-inspect}"

clean() {
  sudo pkill -9 -f "target/debug/deps/container_live" 2>/dev/null
  sudo pkill -9 -f "$BIN __sandbox" 2>/dev/null
  [ -d "$CG" ] && { echo 1 | sudo tee "$CG/cgroup.kill" >/dev/null 2>&1; sleep 1; sudo rmdir "$CG" 2>/dev/null; }
  for v in $(ip -o link | grep -oE '(vth|cth)-clive[^:@ ]*'); do sudo ip link del "$v" 2>/dev/null; done
  sudo rm -rf /tmp/boatramp-clive-* /tmp/clive.out 2>/dev/null
}

echo "== pre-clean =="; clean
echo "== launch (held 90s, no auto-stop) =="
sudo --preserve-env=PATH \
  BOATRAMP_BIN="$BIN" BOATRAMP_CONTAINER_ROOTFS="$ROOTFS" \
  BOATRAMP_CONTAINER_HOLD_SECS=90 BOATRAMP_CONTAINER_NO_STOP=1 \
  "$TB" --ignored --nocapture --test-threads=1 container_live_launch_and_hold > /tmp/clive.out 2>&1 &
sleep 10

DD=$(ls -td /tmp/boatramp-clive-*/ 2>/dev/null | head -1)
PID=$(cat "$CG/cgroup.procs" 2>/dev/null | head -1)
echo "== launch output =="; grep -E 'id=|endpoint|cgroup.procs|nonce' /tmp/clive.out
echo "== container log ($DD) =="; sudo cat "${DD}compute/logs/clive-0.log" 2>/dev/null | head -10
echo "== cgroup procs =="; cat "$CG/cgroup.procs" 2>/dev/null | tr '\n' ' '; echo
echo "== root pid=$PID: netns eth0 + listeners =="
if [ -n "$PID" ]; then
  sudo nsenter -t "$PID" -n ip -br addr 2>&1 | head
  sudo nsenter -t "$PID" -n ss -ltnp 2>&1 | head
fi
echo "== host: veth + bridge =="; ip -br link | grep -iE 'clive|br-boatramp'
echo "== host -> container =="
ping -c1 -W1 10.0.0.2 2>&1 | tail -2
curl -s --max-time 3 http://10.0.0.2:8080/nonce; echo " (curl rc=$?)"

if [ "$PHASE" = "criu" ] && [ -n "$PID" ]; then
  CRIU=$(command -v criu 2>/dev/null)
  if [ -z "$CRIU" ]; then
    for o in $(nix build --extra-experimental-features 'nix-command flakes' --no-link --print-out-paths nixpkgs#criu 2>/dev/null); do
      [ -x "$o/bin/criu" ] && CRIU="$o/bin/criu" && break
    done
  fi
  echo "criu = $CRIU ($("$CRIU" --version 2>/dev/null | head -1))"
  # The monitor (`boatramp __sandbox`) owns the user/net/mnt/uts/ipc namespaces and
  # is the top of the tree (its child is pid1 of the new pidns). Dump from it.
  MON=""
  for p in $(cat "$CG/cgroup.procs"); do
    if grep -qa "__sandbox" "/proc/$p/cmdline" 2>/dev/null; then MON=$p; break; fi
  done
  [ -z "$MON" ] && MON=$PID
  # pid1 of the container = the monitor's child (first descendant).
  C1=$(ps -o pid= --ppid "$MON" 2>/dev/null | head -1 | tr -d ' ')
  IMG=/tmp/criu-img; sudo rm -rf "$IMG"; sudo mkdir -p "$IMG"
  echo "== PHASE 2: ROUND-TRIP  monitor=$MON  container-pid1=$C1 =="
  NONCE1=$(curl -s --max-time 3 http://10.0.0.2:8080/nonce)
  echo "nonce1 (pre-dump) = $NONCE1"
  # The container root is a host bind mount (source path = mountinfo field 4 of `/`).
  ROOTFS=$(sudo awk '$5=="/"{print $4; exit}' "/proc/$C1/mountinfo")
  echo "rootfs (host) = $ROOTFS"
  RFLAGS="--root $ROOTFS --ext-mount-map auto --enable-external-masters --manage-cgroups=full --tcp-established --file-locks --empty-ns net --shell-job"

  echo "-- DUMP (kill) pid1=$C1 --"
  sudo "$CRIU" dump -t "$C1" -D "$IMG" -v4 -o dump.log $RFLAGS
  echo "dump rc=$?  (container should now be gone)"
  sudo grep -iE "Error \(" "$IMG/dump.log" 2>/dev/null | tail -4
  echo "pid1 alive after dump? $(kill -0 "$C1" 2>/dev/null && echo yes || echo NO)"
  echo "container image size: $(sudo du -sh "$IMG" 2>/dev/null | cut -f1)"

  echo "-- RESTORE (detached, empty net ns) --"
  sudo "$CRIU" restore -D "$IMG" -v4 -o restore.log $RFLAGS \
    --restore-detached --pidfile "$IMG/restore.pid"
  echo "restore rc=$?"
  echo "--- restore.log (last 22) ---"; sudo tail -22 "$IMG/restore.log" 2>/dev/null
  RPID=$(sudo cat "$IMG/restore.pid" 2>/dev/null)
  echo "restored pid1 = $RPID  alive? $(kill -0 "$RPID" 2>/dev/null && echo yes || echo NO)"

  echo "-- observe restored state (nsenter into its mount ns, read /tmp/nonce) --"
  NONCE2=$(sudo nsenter -t "$RPID" -m -p /bin/busybox cat /tmp/nonce 2>/dev/null || sudo nsenter -t "$RPID" -m cat /tmp/nonce 2>/dev/null)
  echo "nonce2 (post-restore) = $NONCE2"
  if [ -n "$NONCE1" ] && [ "$NONCE1" = "$NONCE2" ]; then
    echo "RESULT: RESTORE OK - in-RAM state preserved ($NONCE1)"
  else
    echo "RESULT: MISMATCH nonce1=$NONCE1 nonce2=$NONCE2"
  fi
  sudo kill -9 "$RPID" 2>/dev/null
fi

echo "== cleanup =="; clean; echo "done"
