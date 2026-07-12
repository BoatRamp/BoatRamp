#!/usr/bin/env bash
# End-to-end Kubernetes operator gate (K7): install the operator via Helm, found a
# BoatRampCluster, verify it reaches quorum, scale up/down, roll the image, and
# recover a killed pod — asserting a healthy StatefulSet at each step.
#
# Runs against a throwaway kind (default) or k3d cluster. Requires: docker, helm,
# kubectl, and one of `kind` / `k3d`. Slow + infra-heavy — the CI nightly leg, not
# the per-push gate. Local run:
#
#   scripts/e2e-k8s.sh                 # builds the image, uses kind
#   PROVIDER=k3d KEEP=1 scripts/e2e-k8s.sh   # reuse k3d, keep the cluster
set -euo pipefail

PROVIDER="${PROVIDER:-kind}"
CLUSTER="${CLUSTER:-boatramp-e2e}"
NS="${NS:-boatramp-system}"
IMAGE="${IMAGE:-boatramp:e2e}"
KEEP="${KEEP:-0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

log() { printf '\n=== %s ===\n' "$*"; }
cleanup() {
  [ "$KEEP" = "1" ] && return
  case "$PROVIDER" in
    kind) kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true ;;
    k3d)  k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true ;;
  esac
}
trap cleanup EXIT

log "Build the operator image ($IMAGE)"
# A slim image from a statically-ish linked release binary (musl in CI); the
# operator + serve are the one binary.
docker build -t "$IMAGE" -f "$ROOT/scripts/e2e.Dockerfile" "$ROOT"

log "Create the $PROVIDER cluster + load the image"
case "$PROVIDER" in
  kind)
    kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"
    kubectl config use-context "kind-$CLUSTER"
    kind load docker-image "$IMAGE" --name "$CLUSTER"
    ;;
  k3d)
    k3d cluster list | grep -q "$CLUSTER" || k3d cluster create "$CLUSTER"
    kubectl config use-context "k3d-$CLUSTER"
    k3d image import "$IMAGE" -c "$CLUSTER"
    ;;
  *) echo "unknown PROVIDER=$PROVIDER" >&2; exit 2 ;;
esac

log "Install the operator (Helm chart)"
helm upgrade --install boatramp-operator "$ROOT/charts/boatramp-operator" \
  --namespace "$NS" --create-namespace \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE#*:}" \
  --set image.pullPolicy=IfNotPresent --wait --timeout 120s
kubectl -n "$NS" rollout status deploy/boatramp-operator --timeout=120s

log "Provision the root key + admin token secret"
root_priv="$(docker run --rm "$IMAGE" auth init 2>/dev/null | sed -n 's/^BOATRAMP_AUTH_ROOT_PRIVATE_KEY=//p')"
root_pub="$(docker run --rm "$IMAGE" auth pubkey --private-key "$root_priv" 2>/dev/null)"
# A bootstrap-minted admin token would need the cluster running first; for the
# e2e we seed a token the operator uses to drive membership. (In production, mint
# it via `token bootstrap` against the founded cluster.)
kubectl -n "$NS" create secret generic prod-admin --from-literal=token=placeholder \
  --dry-run=client -o yaml | kubectl apply -f -

log "Found a 3-node cluster"
kubectl -n "$NS" apply -f - <<EOF
apiVersion: boatramp.dev/v1alpha1
kind: BoatRampCluster
metadata: { name: prod }
spec:
  mode: cluster
  replicas: 3
  storage: 1Gi
  posture: dev
  rootPubkey: "$root_pub"
  adminTokenSecret: prod-admin
EOF

assert_ready() {
  local want="$1"
  log "Wait for $want ready pods"
  for _ in $(seq 1 60); do
    local ready
    ready="$(kubectl -n "$NS" get sts prod -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
    [ "${ready:-0}" = "$want" ] && { echo "ok: $ready/$want ready"; return 0; }
    sleep 5
  done
  kubectl -n "$NS" get pods; echo "FAILED: never reached $want ready" >&2; exit 1
}
assert_ready 3

log "Scale up to 5"
kubectl -n "$NS" patch boatrampcluster prod --type merge -p '{"spec":{"replicas":5}}'
assert_ready 5

log "Rolling upgrade (re-apply the same image tag → a rollout)"
kubectl -n "$NS" patch boatrampcluster prod --type merge \
  -p "{\"spec\":{\"image\":\"$IMAGE\"}}"
kubectl -n "$NS" rollout status sts/prod --timeout=180s
assert_ready 5

log "Kill a pod → StatefulSet recovers it"
kubectl -n "$NS" delete pod prod-2 --wait=false
assert_ready 5

log "Scale down to 3"
kubectl -n "$NS" patch boatrampcluster prod --type merge -p '{"spec":{"replicas":3}}'
assert_ready 3

log "PASS — operator e2e (install → found → scale 3→5→3 → rolling upgrade → kill-pod recovery)"
