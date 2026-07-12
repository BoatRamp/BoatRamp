# boatramp-operator Helm chart

Installs the in-binary boatramp Kubernetes operator (CRDs + a least-privilege
`ClusterRole` + the operator `Deployment`). The operator is a subcommand of the
one boatramp binary — there is no separate controller image.

```sh
helm install boatramp-operator ./charts/boatramp-operator \
  --namespace boatramp-system --create-namespace
```

Then create a `BoatRampCluster` (see [Run on Kubernetes](https://boatramp.dev/how-to/kubernetes.html)).

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/boatramp/boatramp` | Operator image (same as the server). |
| `image.tag` | chart `appVersion` | Image tag. |
| `image.pullPolicy` | `IfNotPresent` | — |
| `replicaCount` | `1` | Operator replicas (one active reconciler is enough). |
| `watchNamespace` | `""` (all) | Restrict the operator to one namespace. |
| `resources` | small | Requests/limits. |
| `podSecurityContext` / `securityContext` | hardened | runAsNonRoot, drop ALL caps, read-only rootfs. |

## Keeping the CRDs in sync (single source of truth)

`crds/boatramp-crds.yaml` is **generated** from the Rust CRD types — the same
source as `boatramp operator manifests`. Regenerate after a CRD change:

```sh
cargo run -p boatramp --features operator -- operator crds \
  > charts/boatramp-operator/crds/boatramp-crds.yaml
```

The `templates/rbac.yaml` role mirrors `boatramp operator manifests`; keep the two
in step (a CI check diffs them).
