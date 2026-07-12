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

Provision the cluster's keys as Secrets, then declare the cluster. The pods need
the root **private** key to sign join tokens/attestations (`authSecret`); the
operator needs an **admin token** to drive membership (`adminTokenSecret`):

```sh
# The auth Secret wired into the pods: the root private key (the founder signs
# with it) + a single-use bootstrap secret (to mint the first admin token).
kubectl create secret generic prod-auth \
  --from-literal=root-private-key="$BOATRAMP_AUTH_ROOT_PRIVATE_KEY" \
  --from-literal=bootstrap-secret="$(openssl rand -hex 16)"

# The admin token the operator uses for /api/cluster/* — mint it against the
# founded cluster with the bootstrap secret (`token bootstrap`), then store it:
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
  authSecret: prod-auth         # Secret: root-private-key (+ bootstrap-secret)
  adminTokenSecret: prod-admin  # Secret with an admin `token` key
```

The operator renders a `[cluster]` config into the pods (so `serve` runs the
embedded Raft node), runs each pod's control plane over **RPK-TLS** (`--tls rpk`),
wires the root private key + bootstrap secret from `authSecret`, exposes the mesh
port on the headless Service, and gives each pod its own dialable advertise
address via the downward API — so the founder can sign, self-attest, and joiners
can be reached. Because the control plane is RPK-TLS (RFC 7250 raw public keys),
which the kubelet's HTTP prober can't speak, cluster-mode pods are probed with a
**TCP-socket** readiness check — a node binds its listener only after it has
founded/joined and is serving, so "port open" is the right readiness gate.

The reconciler:

1. Applies the StatefulSet (+ headless Service, per-node PVC, PDB), a client
   Service, and a ConfigMap.
2. Designates **pod-0 as the founder** — the pod reads its own name from the
   downward API (`BOATRAMP_POD_NAME`); ordinal 0 founds, every other ordinal
   joins. (The node *identity* is still derived from each pod's mesh key.)
3. Reaches every pod's control plane over an **RPK-TLS channel pinned to that
   pod's root-attested key** — the same attestation-pin a joiner uses — so no
   membership call trusts an unauthenticated endpoint.
4. Keeps a fresh single-use **join ticket** in the `<name>-join` Secret (which
   the pods read as `BOATRAMP_CLUSTER_JOIN`) while the cluster is below its
   desired size, so a booting joiner can self-join at startup; its redemption
   adds it as a Raft learner on the leader.
5. Drives one **quorum-safe** membership transition per reconcile against the
   cluster API — promote a caught-up learner to a voter (on the leader), or, on
   scale-down, remove an out-of-range member *before* its pod is deleted. It
   never acts without quorum and never removes the last voter.

Without `adminTokenSecret`/`rootPubkey` the operator still reconciles the
workloads and **plans + reports** membership, but does not execute it (both are
needed: the token to authenticate, the root pubkey to pin the pods' RPK-TLS).

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

The operator resolves the target `BoatRampCluster` and `PUT`s the site config over
the same **pinned RPK-TLS channel** to the cluster's pod-0 that the membership
executor uses (`adminTokenSecret` + `rootPubkey`), then reports `.status.phase`.
(`kubectl get site` shows it.) Publishing content to the site is still a
`boatramp sync` / CI deploy — the `Site` CR governs its identity + domains, not
its deployments.

> **`Function` (FaaS):** the `Function` CRD is installed and watched, but its
> apply path awaits the FaaS backend (`PLAN-faas`); today it reports a `Pending`
> status. Don't rely on it to deploy a component yet.

## Scaling

Change `spec.replicas` and re-apply. The operator converges one member at a time:
scale-up adds learners then promotes them; scale-down removes the highest
ordinals first, always quorum-safe. Kill a pod and the StatefulSet recreates it;
it rejoins (or resumes from its PVC) with no manual step.

A node's **PVC is retained** on scale-down and on StatefulSet delete
(`persistentVolumeClaimRetentionPolicy: Retain`) — a Raft voter's durable
log/state is never auto-reclaimed. Removing the data is an explicit operator step.

## Rolling upgrades

Bump `spec.image` and re-apply. The operator drives a **quorum-aware** rolling
upgrade: it pauses the StatefulSet rollout (via the `RollingUpdate` partition)
whenever the cluster lacks a spare ready voter, so an upgrade never drops the
cluster below quorum. Combined with the PodDisruptionBudget, a node drain behaves
the same way. When a voter's pod does restart, Raft re-elects a new leader
automatically (a sub-second election); explicit leader-transfer to avoid that brief
write pause is a future optimization (openraft 0.9 has no simple transfer call).

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
| `authSecret` | string | — | Secret wiring auth into the pods: `root-private-key` (the founder signs with it) + optional `bootstrap-secret`. |

## See also

- [Deploy a self-hosted cluster](./deploy-cluster.md) — the dynamic-join model the
  operator automates.
- [Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md).
- [Deployment topologies](../explanation/topologies.md).
