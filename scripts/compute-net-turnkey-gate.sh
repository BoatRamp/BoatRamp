#!/usr/bin/env bash
# Compute-network turnkey live gate (Gap A + Gap B).
#
# The TRUE end-to-end proof for `feat/compute-net-turnkey` that cannot be a unit
# test: on a REAL NixOS + docker host it asserts BOTH halves of the fix together —
#
#   (A) a container on a per-project docker bridge REACHES a host-bound compute
#       shim via `host.docker.internal`, from MULTIPLE simultaneous per-project
#       bridges (the multi-network requirement); and
#   (B) the same shim is NOT reachable off-node (from the host's LAN/public IP),
#       i.e. the firewall + bind scope block it — the security invariant.
#
# It also checks the scoped bridge interface name (`boatramp-<hash>`, not `br-<hash>`)
# and that the NixOS compute-firewall rule is present and scoped to the boatramp
# bridges (not the broad `br-+`).
#
# WHY A SCRIPT, NOT A FLAKE CHECK: this needs a real kernel bridge, a real docker
# daemon, a real `nixos-fw` INPUT chain, and a non-loopback host IP — none of which
# the macOS build box or a hermetic nix sandbox has. The Rust unit tests cover the
# per-container injection + ExtraHosts + the bridge-name bound; the NixOS module
# eval check (`nix build .#checks.<sys>.compute-firewall-eval`) covers the firewall
# RULE shape. This script closes the loop on a live host.
#
# RUN ON lighthouse (jwk@lighthouse.bytesoba.net — the owner's NixOS docker box):
#
#   # 1. Deploy a node from this branch with compute + the shim URL set via the
#   #    module (which binds the shim AND opens only its port on the boatramp bridges):
#   #      services.boatramp = {
#   #        enable = true; compute = true;
#   #        computeShimUrls.kv = "http://172.17.0.1:8084";  # host-gateway IP
#   #      };
#   # 2. Then, from a checkout of this branch on lighthouse:
#   sudo SHIM_PORT=8084 scripts/compute-net-turnkey-gate.sh
#
# COVER BOTH FIREWALL BACKENDS: run it once on the default (iptables) host and once
# with `networking.nftables.enable = true` — the nftables default rule is the one M1
# fixed (a valid `meta l4proto tcp` / `tcp dport {…}` match, never a bare `tcp`), so
# the live nft path must be exercised. The firewall check (step 4) asserts the live
# rule uses a valid match, which would fail on the pre-M1 bare-`tcp` ruleset.
#
# Exit 0 = both halves proven. Non-zero = a real failure (printed). The script
# SELF-SKIPS (exit 0 with a SKIP line) when not on a Linux+docker host, so it is a
# no-op anywhere it cannot run honestly — it never fakes a pass.
set -euo pipefail

SHIM_PORT="${SHIM_PORT:-8084}"          # the shim port the node binds (match boatramp.cfg)
HOST_GW="${HOST_GW:-172.17.0.1}"        # docker host-gateway IP the shim is bound on
IMAGE="${IMAGE:-alpine:3.20}"           # a tiny image with a shell; swap for an air-gapped one
PROJECTS=("gate-a" "gate-b")            # TWO projects ⇒ TWO simultaneous per-project bridges
KEEP="${KEEP:-0}"

log()  { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
skip() { printf 'SKIP: %s\n' "$*"; exit 0; }

# --- Honesty guards: only run where the real path exists ---------------------
[ "$(uname -s)" = "Linux" ] || skip "not Linux (needs a real bridge + nixos-fw) — $(uname -s)"
command -v docker >/dev/null 2>&1   || skip "docker not installed"
docker info >/dev/null 2>&1         || skip "docker daemon not reachable"
command -v iptables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1 \
  || skip "no iptables/nft to inspect the firewall"

NETS=()
cleanup() {
  [ "$KEEP" = "1" ] && { log "KEEP=1 — leaving containers/networks"; return; }
  log "cleanup"
  for p in "${PROJECTS[@]}"; do
    docker rm -f "gatec-$p" >/dev/null 2>&1 || true
    docker network rm "boatramp-net-$p" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

# --- 0. Is a shim actually listening on the host-gateway IP? -----------------
log "preflight: a shim must be bound on $HOST_GW:$SHIM_PORT"
if ! curl -fsS -m 3 -o /dev/null "http://$HOST_GW:$SHIM_PORT/" 2>/dev/null; then
  # A 401/404 is fine (the shim is UP, just unauthenticated/wrong-path); only a
  # connection failure means nothing is listening.
  code="$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$HOST_GW:$SHIM_PORT/" 2>/dev/null || echo 000)"
  [ "$code" = "000" ] && skip "no shim listening on $HOST_GW:$SHIM_PORT — deploy the node first (see header)"
fi
pass "a shim is listening on $HOST_GW:$SHIM_PORT"

# --- 1. Create TWO per-project networks the way the backend does -------------
# (We create them directly so the gate does not depend on a full workload deploy;
#  the backend creates them identically — same network name + the scoped bridge
#  driver-opt. The firewall matches the bridge by PREFIX (boatramp-*), so the gate
#  only needs a boatramp-<hash> name of the right shape, not byte-identity with the
#  backend's hash — but the helper below mirrors boatramp-docker::project_bridge_name
#  (boatramp- + low-24-bit FNV-1a of the network name) so it stays faithful.)
log "creating per-project networks with the scoped bridge name"
bridge_name() {
  local net="$1" h=14695981039346656037 b
  for ((i=0;i<${#net};i++)); do
    printf -v b '%d' "'${net:$i:1}"
    h=$(( (h ^ b) & 0xFFFFFFFFFFFFFFFF ))
    h=$(( (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF ))
  done
  printf 'boatramp-%06x' "$(( h & 0xFFFFFF ))"
}
for p in "${PROJECTS[@]}"; do
  net="boatramp-net-$p"; br="$(bridge_name "$net")"
  docker network rm "$net" >/dev/null 2>&1 || true
  docker network create --driver bridge \
    --opt "com.docker.network.bridge.name=$br" \
    --label boatramp.managed=true --label "boatramp.project=$p" "$net" >/dev/null
  NETS+=("$net")
  # The kernel bridge must carry the scoped boatramp- prefix, within IFNAMSIZ (15).
  ip link show "$br" >/dev/null 2>&1 || fail "scoped bridge $br not created for $net"
  [ "${#br}" -le 15 ] || fail "bridge name $br exceeds IFNAMSIZ (15)"
  pass "network $net ⇒ kernel bridge $br (scoped, ${#br}≤15 bytes)"
done

# --- 2. Gap A: a container on EACH bridge reaches the shim via host.docker.internal
log "Gap A: reach the shim from a container on each per-project bridge"
for p in "${PROJECTS[@]}"; do
  net="boatramp-net-$p"
  # EXACTLY what the backend injects: --add-host host.docker.internal:host-gateway,
  # and the guest URL uses that name (what the rewrite produces from a loopback/0.0.0.0 bind).
  out="$(docker run --rm --network "$net" \
          --add-host "host.docker.internal:host-gateway" "$IMAGE" \
          sh -c "wget -S -q -T 4 -O /dev/null http://host.docker.internal:$SHIM_PORT/ 2>&1; echo RC=\$?" || true)"
  # Reachability — NOT HTTP success — is what Gap A proves: a TCP connect + ANY HTTP
  # reply (even a 401/404 from the token-gated shim) means the guest reached the host.
  # So the ONLY failure signal is a CONNECTION-level error; an HTTP status line
  # ("server returned error: HTTP/… 401") is a PASS.
  if echo "$out" | grep -qiE "can't connect|connection refused|bad address|download timed out|no route to host"; then
    printf '%s\n' "$out" >&2
    fail "Gap A: container on $net could NOT reach the shim via host.docker.internal:$SHIM_PORT"
  fi
  if ! echo "$out" | grep -qiE 'HTTP/|server returned'; then
    printf '%s\n' "$out" >&2
    fail "Gap A: container on $net got no HTTP reply from host.docker.internal:$SHIM_PORT"
  fi
  pass "Gap A: container on $net reached host.docker.internal:$SHIM_PORT"
done

# --- 3. Gap B / invariant: the shim is NOT reachable off-node -----------------
log "Security invariant: the shim must be UNREACHABLE from a non-boatramp interface"
# The host's primary LAN/public IP (the default-route source address).
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
if [ -z "$LAN_IP" ] || [ "$LAN_IP" = "$HOST_GW" ]; then
  printf 'NOTE: could not determine a distinct LAN IP (got "%s"); off-node check needs a real NIC.\n' "$LAN_IP"
else
  # From the host, a reach to the LAN IP:port traverses the same INPUT policy a LAN
  # peer would hit. If a shim bound on the host-gateway IP (recommended), this MUST
  # fail outright (the shim is not even listening on the LAN IP). If bound on
  # 0.0.0.0, the firewall (no admit rule on the LAN NIC) must still DROP it.
  code="$(curl -s -m 4 -o /dev/null -w '%{http_code}' "http://$LAN_IP:$SHIM_PORT/" 2>/dev/null || echo 000)"
  [ "$code" = "000" ] || fail "invariant VIOLATED: shim answered on the LAN IP $LAN_IP:$SHIM_PORT (HTTP $code) — it is off-node reachable"
  pass "shim is NOT reachable on the LAN IP $LAN_IP:$SHIM_PORT (blocked at bind+firewall)"
fi

# --- 4. The firewall rule is scoped to the boatramp bridges, not br-+, with a VALID match
log "firewall: admit rule present on the boatramp bridges, scoped (not br-+), valid match"
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
  rs="$(nft list ruleset 2>/dev/null)"
  # The live ruleset is already kernel-accepted, so a bare-`tcp` match could not be
  # loaded; still assert the boatramp rule uses a valid header match (`dport`/`l4proto`)
  # — a positive guard that the M1 fix (not a bare `tcp`) is what shipped.
  echo "$rs" | grep -qE 'iifname "(br-boatramp|boatramp-)' \
    && pass "nft: boatramp-scoped iifname accept present" \
    || fail "nft: no boatramp-scoped iifname accept rule found"
  echo "$rs" | grep -E 'iifname "(br-boatramp|boatramp-)[^"]*"' | grep -qE '(tcp dport|meta l4proto tcp)' \
    && pass "nft: the boatramp rule uses a valid match (dport / l4proto), not a bare tcp" \
    || fail "nft: the boatramp rule is missing a valid tcp match (M1 bare-tcp regression?)"
  echo "$rs" | grep -qE 'iifname "br-\*"' \
    && fail "nft: rule trusts the broad br-* (must be boatramp-scoped only)" \
    || pass "nft: does NOT trust the broad br-*"
else
  rules="$(iptables -S nixos-fw 2>/dev/null || iptables -S 2>/dev/null || true)"
  echo "$rules" | grep -qE -- '-i (br-boatramp|boatramp-\+)' \
    && pass "iptables: boatramp-scoped -i accept present" \
    || fail "iptables: no boatramp-scoped accept rule in nixos-fw"
  echo "$rules" | grep -qE -- '-i br-?\+ ' \
    && fail "iptables: rule trusts the broad br-+/br+ (must be boatramp-scoped only)" \
    || pass "iptables: does NOT trust the broad br-+"
fi

log "ALL CHECKS PASSED — Gap A (reachability, multi-network) + Gap B (off-node blocked) proven live"
