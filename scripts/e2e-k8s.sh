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
# On a failed run, surface *why* before the cluster is torn down — the helm/rollout
# wait only reports `Available: 0/1`, so dump the operator's state (a crash-loop, an
# OOMKill, an image error, pending scheduling) into the CI log.
dump_diagnostics() {
  log "FAILED — diagnostics ($NS)"
  kubectl -n "$NS" get pods -o wide 2>/dev/null || true
  kubectl -n "$NS" describe pods 2>/dev/null | sed -n '/Last State:/,+4p;/Events:/,$p' | tail -60 || true
  # The operator Deployment and each cluster pod are separate failure surfaces.
  # Dump per pod (a `statefulset/…` selector picks one arbitrary — usually healthy —
  # pod, so a single crashing ordinal is missed); a crash-loop only shows its cause
  # in the *previous* container's log.
  local pods
  pods="$(kubectl -n "$NS" get pods -o name 2>/dev/null)"
  for p in $pods; do
    kubectl -n "$NS" logs "$p" --all-containers --tail=120 --prefix 2>/dev/null || true
    kubectl -n "$NS" logs "$p" --all-containers --previous --tail=120 --prefix 2>/dev/null || true
  done
  kubectl -n "$NS" get events --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
}
cleanup() {
  rc=$?
  [ "$rc" -ne 0 ] && dump_diagnostics
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

log "Provision the root key + admin token + auth secrets"
root_priv="$(docker run --rm "$IMAGE" auth init 2>/dev/null | sed -n 's/^BOATRAMP_AUTH_ROOT_PRIVATE_KEY=//p')"
root_pub="$(docker run --rm "$IMAGE" auth pubkey --private-key "$root_priv" 2>/dev/null)"
# A real admin token, minted OFFLINE with the root key (the executor uses it to
# authenticate to /api/cluster/*). No `cnf`, so no DPoP proof is required — plain
# bearer. (In production you'd instead `token bootstrap` against the founded
# cluster; offline mint is the air-gap/CI path and needs no running cluster.)
admin_token="$(docker run --rm -e BOATRAMP_AUTH_ROOT_PRIVATE_KEY="$root_priv" "$IMAGE" \
  token mint --role admin --ttl-secs 86400 2>/dev/null)"
kubectl -n "$NS" create secret generic prod-admin --from-literal=token="$admin_token" \
  --dry-run=client -o yaml | kubectl apply -f -
# The auth Secret the pods read: the root PRIVATE key (the founder signs join
# tokens / attestations / member assertions with it, and every pod self-attests
# its RPK-TLS control-plane key) + a bootstrap secret. Referenced by `authSecret`.
kubectl -n "$NS" create secret generic prod-auth \
  --from-literal=root-private-key="$root_priv" \
  --from-literal=bootstrap-secret="$(openssl rand -hex 16)" \
  --dry-run=client -o yaml | kubectl apply -f -

log "Found a 3-node cluster"
kubectl -n "$NS" apply -f - <<EOF
apiVersion: boatramp.dev/v1alpha1
kind: BoatRampCluster
metadata: { name: prod }
spec:
  mode: cluster
  # Pin the image the test built + loaded into the node; without this the operator
  # falls back to its ghcr.io default, which the offline kind/k3d node cannot pull
  # (ImagePullBackOff). Backticks are avoided here: this heredoc is unquoted so
  # \$IMAGE expands, and backticks would trigger command substitution.
  image: $IMAGE
  replicas: 3
  storage: 1Gi
  posture: dev
  rootPubkey: "$root_pub"
  authSecret: prod-auth
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

# ── Compute-backend serve-pod placement (mailroom #26 NEW-1) ─────────────────
# A cluster that HOSTS ITS OWN MANAGED COMPUTE (spec.computeBackend) must have its
# serve pods placed in a DEDICATED namespace, running as the least-privilege compute
# ServiceAccount (NOT the operator's cluster-wide SA — F4) and labelled as the compute
# consumer (so the per-workload NetworkPolicies bind — F3). Prove the operator does
# this: assert the operator-rendered Deployment's POD TEMPLATE (the pod need not be
# Ready — this gates the placement the operator applies, not image bring-up).
CNS="boatramp-compute"
log "Enable the compute-backend RBAC in the dedicated namespace ($CNS)"
# --reuse-values keeps the image.* settings from the install above; the chart creates
# the dedicated namespace + the compute SA + its namespace-scoped Role/RoleBinding, and
# REFUSES (helm fail) if $CNS equals the operator release namespace ($NS).
helm upgrade boatramp-operator "$ROOT/charts/boatramp-operator" --reuse-values \
  --set computeBackend.kubernetes.enabled=true \
  --set computeBackend.kubernetes.namespace="$CNS" --wait --timeout 120s
kubectl get ns "$CNS" >/dev/null
kubectl -n "$CNS" get serviceaccount boatramp-compute >/dev/null
kubectl -n "$CNS" get role boatramp-compute >/dev/null

log "Provision auth + admin secrets in $CNS"
kubectl -n "$CNS" create secret generic compute-admin --from-literal=token="$admin_token" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$CNS" create secret generic compute-auth \
  --from-literal=root-private-key="$root_priv" \
  --from-literal=bootstrap-secret="$(openssl rand -hex 16)" \
  --dry-run=client -o yaml | kubectl apply -f -

log "Deploy a compute-hosting cluster in $CNS (spec.computeBackend)"
kubectl -n "$CNS" apply -f - <<EOF
apiVersion: boatramp.dev/v1alpha1
kind: BoatRampCluster
metadata: { name: compute }
spec:
  mode: stateless
  image: $IMAGE
  replicas: 1
  posture: dev
  rootPubkey: "$root_pub"
  authSecret: compute-auth
  adminTokenSecret: compute-admin
  computeBackend:
    serviceAccountName: boatramp-compute
EOF

log "Assert the serve pod lands in $CNS with the compute SA + consumer label"
dep_ok=0
for _ in $(seq 1 30); do
  kubectl -n "$CNS" get deploy compute >/dev/null 2>&1 && { dep_ok=1; break; }
  sleep 2
done
[ "$dep_ok" = 1 ] || { echo "FAILED: operator never created deploy/compute in $CNS" >&2; exit 1; }
sa="$(kubectl -n "$CNS" get deploy compute -o jsonpath='{.spec.template.spec.serviceAccountName}')"
consumer="$(kubectl -n "$CNS" get deploy compute -o jsonpath='{.spec.template.metadata.labels.boatramp\.dev/compute-consumer}')"
[ "$sa" = "boatramp-compute" ] || { echo "FAILED: serve pod SA is '$sa', want boatramp-compute (F4)" >&2; exit 1; }
[ "$consumer" = "true" ] || { echo "FAILED: serve pod missing boatramp.dev/compute-consumer=true (got '$consumer') (F3)" >&2; exit 1; }
echo "ok: serve pod in $CNS runs as SA=$sa, compute-consumer=$consumer"

log "PASS — operator compute placement (dedicated ns + compute SA + consumer label)"
echo "OPERATOR COMPUTE-PLACEMENT OK"
