#!/usr/bin/env bash
# Run the backend-driven CRIU scale-to-zero round-trip test ON lighthouse, inside
# `nix develop`, as a user with passwordless sudo. Sets up the bridge + cgroup
# controller delegation + resolves criu, then runs the ignored live test.
#   cd ~/boatramp-criu && nix develop --command bash scripts/criu-test.sh [testname]
set -u
cd "$(dirname "$0")/.."
TEST="${1:-container_criu_roundtrip}"

# Bridge with the gateway IP (host reaches the container over it).
sudo ip link add br-boatramp type bridge 2>/dev/null || true
sudo ip addr add 10.0.0.1/24 dev br-boatramp 2>/dev/null || true
sudo ip link set br-boatramp up
# cgroup v2 controller delegation for the boatramp parent cgroup (leaf needs cpu/mem/pids).
sudo mkdir -p /sys/fs/cgroup/boatramp
echo "+cpu +memory +pids" | sudo tee /sys/fs/cgroup/boatramp/cgroup.subtree_control >/dev/null 2>&1 || true

# Resolve a criu binary (the backend's Criu::detect reads $BOATRAMP_CRIU).
CRIU=$(command -v criu 2>/dev/null)
if [ -z "$CRIU" ]; then
  for o in $(nix build --extra-experimental-features 'nix-command flakes' --no-link --print-out-paths nixpkgs#criu 2>/dev/null); do
    [ -x "$o/bin/criu" ] && CRIU="$o/bin/criu" && break
  done
fi
echo "criu = $CRIU"

BIN="$PWD/target/debug/boatramp"
TB="$PWD/$(ls -t target/debug/deps/container_live-* | grep -v '\.d$' | head -1)"
sudo --preserve-env=PATH \
  BOATRAMP_BIN="$BIN" BOATRAMP_CONTAINER_ROOTFS=/tmp/bb-rootfs.tar.gz BOATRAMP_CRIU="$CRIU" \
  "$TB" --ignored --nocapture --test-threads=1 "$TEST"
rc=$?
# best-effort cleanup of any leftover instance
sudo find /sys/fs/cgroup/boatramp -maxdepth 1 -name 'ccriu-*' -o -name 'clive-*' 2>/dev/null | while read -r c; do echo 1 | sudo tee "$c/cgroup.kill" >/dev/null 2>&1; sudo rmdir "$c" 2>/dev/null; done
for v in $(ip -o link 2>/dev/null | grep -oE '(vth|cth)-(ccriu|clive)[^:@ ]*'); do sudo ip link del "$v" 2>/dev/null; done
sudo rm -rf /tmp/boatramp-ccriu-* /tmp/boatramp-clive-* 2>/dev/null
exit $rc
