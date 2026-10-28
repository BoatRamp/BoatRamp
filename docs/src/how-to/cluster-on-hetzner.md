# Bring up a boatramp cluster on Hetzner

Standing up a Kubernetes cluster, getting a `kubectl` context, and installing the
boatramp operator onto it is the same for **every** boatramp deployment — it is not
app-specific. So the generic bring-up tooling lives with the platform, in boatramp's
dev shell, rather than being re-added to each app's own setup:

- [`hetzner-k3s`](https://github.com/vitobotta/hetzner-k3s) — provisions a k3s cluster
  on Hetzner Cloud (servers, private network, firewall, load balancer, `kubeconfig`).
- [`kubectl`](https://kubernetes.io/docs/reference/kubectl/) — talks to the cluster and
  applies the operator.

Both are in the dev shell, so `nix develop` (or `direnv allow`) is all you need — no
per-app install. This runbook takes you from nothing to a `BoatRampCluster` running on
Hetzner. The cluster-provisioning step is Hetzner-specific today; everything from "install
the operator" on is provider-agnostic.

> This is the generic platform layer only. App- and provider-specific infrastructure —
> a Floating IP + rDNS for SMTP `:25`, MX/SPF/DKIM DNS records, object storage — stays
> with the app, not here.

## Prerequisites

- A [Hetzner Cloud](https://console.hetzner.cloud/) project and a **read/write API token**
  for it (Project → Security → API tokens).
- An SSH key pair (e.g. `~/.ssh/id_ed25519[.pub]`); hetzner-k3s uploads the public key and
  uses the private key to configure the nodes.
- The boatramp dev shell:

  ```sh
  nix develop        # provides hetzner-k3s, kubectl, and the boatramp CLI
  hetzner-k3s --version
  ```

## 1. Write the cluster config

hetzner-k3s is config-driven. The minimal shape below (hetzner-k3s **v2**,
`config_format_version: 1`) creates a 3-master HA control plane and one worker pool. See
the upstream [configuration reference](https://github.com/vitobotta/hetzner-k3s/blob/main/docs/Creating_a_cluster.md)
for the full schema (autoscaling pools, CNI/Cilium, custom firewall rules, addons).

```yaml
# cluster_config.yaml — keep your token out of version control (see note below).
---
hetzner_token: <your-hetzner-cloud-api-token>
cluster_name: boatramp
kubeconfig_path: "./kubeconfig"
k3s_version: v1.32.0+k3s1          # `hetzner-k3s releases` lists the current options
config_format_version: 1

networking:
  ssh:
    port: 22
    use_agent: false
    public_key_path: "~/.ssh/id_ed25519.pub"
    private_key_path: "~/.ssh/id_ed25519"
  allowed_networks:
    ssh: ["0.0.0.0/0"]             # tighten to your admin IP/CIDR for production
    api: ["0.0.0.0/0"]             # firewalls the API server (:6443)
  public_network:
    ipv4: true
    ipv6: true
  private_network:
    enabled: true
    subnet: 10.0.0.0/16
  cni:
    enabled: true
    mode: flannel

datastore:
  mode: etcd

masters_pool:
  instance_type: cpx22
  instance_count: 3                # 1 is fine for dev/testing, not production
  locations: [fsn1, hel1, nbg1]    # HA: each master in a distinct location

worker_node_pools:
  - name: default
    instance_type: cpx22
    instance_count: 3
    location: hel1
```

Keep the API token out of git. Either drop `hetzner_token` from the file and let the tool
read it from your environment, or template it in at apply time:

```sh
export HCLOUD_TOKEN=…            # or keep hetzner_token in an untracked, gitignored file
```

## 2. Provision the cluster

```sh
hetzner-k3s create --config cluster_config.yaml
```

This creates the servers, private network, firewall, and load balancer, installs k3s, and
writes the admin `kubeconfig` to `./kubeconfig`. Re-running `create` is idempotent — it
reconciles the cluster toward the config (scale a pool by changing `instance_count` and
re-running).

## 3. Point kubectl at it

```sh
export KUBECONFIG="$PWD/kubeconfig"
kubectl get nodes          # every master + worker should be Ready
```

## 4. Install the boatramp operator and declare a cluster

The cluster now exists; the rest is provider-agnostic. boatramp ships its operator **in the
same binary** (no separate controller image), as a Helm chart or a `kubectl apply` bundle:

```sh
helm install boatramp-operator ./charts/boatramp-operator \
  --namespace boatramp-system --create-namespace
# …or, without Helm:
boatramp operator manifests | kubectl apply -f -
```

Then declare a `BoatRampCluster` and the operator reconciles it into a running cluster. The
full flow — provisioning the cluster's auth/admin Secrets and the `BoatRampCluster` fields —
is in [Run boatramp on Kubernetes](./kubernetes.md).

## Tear it down

```sh
hetzner-k3s delete --config cluster_config.yaml
```

This deletes every Hetzner resource the config created. (It does **not** touch anything your
app provisioned outside hetzner-k3s — Floating IPs, DNS records, object storage, etc.)
