# Run boatramp on Kubernetes

boatramp ships a **Kubernetes operator in the same binary** — there is no separate
controller image or Helm chart to track. The operator reconciles a
`BoatRampCluster` custom resource into its workloads (a StatefulSet for cluster
mode, or a Deployment + HPA for a stateless frontend) and drives the Raft
membership as pods come and go, using the same [dynamic-join](./deploy-cluster.md)
model as the CLI — the ordinal-0 pod founds, the rest join with a ticket.

## Install the operator

The operator ships as a **Helm chart** (`charts/boatramp-operator`) — CRDs, a
least-privilege `ClusterRole`, and the operator Deployment:

```sh
helm install boatramp-operator ./charts/boatramp-operator \
  --namespace boatramp-system --create-namespace
```

Or, without Helm, apply the same bundle emitted by the binary itself:

```sh
boatramp operator manifests | kubectl apply -f -
```

`boatramp operator crds` prints just the CRDs (the chart's `crds/` are generated
from these — a CI check guards against drift); `boatramp operator run` is the
controller entrypoint (what the Deployment runs). The operator watches
`BoatRampCluster` and the tenant `Site` CRD (and `Function`, once the FaaS backend
lands) and reconciles them via server-side apply, so it owns exactly the fields it
sets. Release images are cosign-signed with an attached CycloneDX SBOM.

## Create a cluster

Give the operator the cluster's **root anchor** and an **admin token** so it can
drive membership, then declare the cluster:

```sh
# The admin token the operator uses for /api/cluster/* (from `token bootstrap`):
kubectl create secret generic prod-admin --from-literal=token="$ADMIN_TOKEN"
```

```yaml
apiVersion: boatramp.dev/v1alpha1
kind: BoatRampCluster
metadata:
  name: prod
spec:
  mode: cluster                 # or `stateless` (Deployment + HPA)
  replicas: 3
  storage: 10Gi                 # per-node Raft PVC (cluster mode)
  posture: multi-tenant         # the operator enforces this floor
  rootPubkey: "es256:03a1…"     # the cluster root anchor (auth pubkey)
  adminTokenSecret: prod-admin  # Secret with an admin `token` key
```

The reconciler:

1. Applies the StatefulSet (+ headless Service, per-node PVC, PDB), a client
   Service, and a ConfigMap.
2. Designates **pod-0 as the founder** — the pod reads its own name from the
   downward API (`BOATRAMP_POD_NAME`); ordinal 0 founds, every other ordinal
   joins. (The node *identity* is still derived from each pod's mesh key.)
3. As pods become ready, drives one **quorum-safe** membership transition per
   reconcile against the cluster API: add the joining pod as a learner (by
   rolling a fresh single-use join ticket into the `<name>-join` Secret the pods
   read as `BOATRAMP_CLUSTER_JOIN`), promote a caught-up learner to a voter, or —
   on scale-down — remove an out-of-range member *before* its pod is deleted. It
   never acts without quorum and never removes the last voter.

Without `adminTokenSecret`/`rootPubkey` the operator still reconciles the
workloads and **plans + reports** membership, but does not execute it.

## Observe

```sh
kubectl get boatrampcluster            # PHASE + QUORUM print-columns
kubectl describe brc prod              # .status.members + observedGeneration
```

`boatramp cluster status --server <client-service-url>` gives the same
address-primary membership view the CLI shows for a bare-metal cluster (the pod
address is the handle for `cluster remove`).

## Declare sites with GitOps

A `Site` custom resource is reconciled into a boatramp site on its cluster's
control plane — declare hostnames in Git, `kubectl apply`, and a **finalizer**
cleans up the routing on `kubectl delete`:

```yaml
apiVersion: boatramp.dev/v1alpha1
kind: Site
metadata:
  name: marketing
spec:
  cluster: prod            # omit ⇒ the sole cluster in the namespace
  domains:
    - example.com          # → primary
    - www.example.com      # → alias
    - "*.preview.example.com"  # → wildcard
```

The operator resolves the target `BoatRampCluster`, uses its `adminTokenSecret`
to `PUT` the site config, and reports `.status.phase`. (`kubectl get site` shows
it.) Publishing content to the site is still a `boatramp sync` / CI deploy — the
`Site` CR governs its identity + domains, not its deployments.

> **`Function` (FaaS):** the `Function` CRD is installed and watched, but its
> apply path awaits the FaaS backend (`PLAN-faas`); today it reports a `Pending`
> status. Don't rely on it to deploy a component yet.

## Scaling

Change `spec.replicas` and re-apply. The operator converges one member at a time:
scale-up adds learners then promotes them; scale-down removes the highest
ordinals first, always quorum-safe. Kill a pod and the StatefulSet recreates it;
it rejoins (or resumes from its PVC) with no manual step.

## `spec` reference

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `mode` | `cluster` \| `stateless` | `cluster` | Raft StatefulSet, or a stateless Deployment + HPA. |
| `replicas` | integer | `1` | Desired node count. |
| `image` | string | operator's own image | Container image (an explicit version). |
| `storage` | string | — | Per-node Raft PVC size (cluster mode). |
| `posture` | string | — | Security posture floor; a tenant CRD can never relax it. |
| `adminTokenSecret` | string | — | Secret (key `token`) with an admin control-plane token — enables the membership executor. |
| `rootPubkey` | string | — | The cluster root anchor (`alg:hex`) a joining pod verifies against. |

## See also

- [Deploy a self-hosted cluster](./deploy-cluster.md) — the dynamic-join model the
  operator automates.
- [Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md).
- [Deployment topologies](../explanation/topologies.md).
