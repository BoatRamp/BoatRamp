# Start here: operators

**For: operators** — you install, secure, and run boatramp in production. This
is a reading path, not a new section: every link lands in a how-to group. For
the full menu, see the [how-to index](./index.md).

## 1. Get it running

- [Install boatramp](./install.md) (or [build from source](./build-from-source.md))
- [Deploy a single node in production](./deploy-single-node.md)
- Run a quick end-to-end first in [Publish your first site](../tutorials/first-site.md).

## 2. Lock it down

- [Choose & inspect a security posture](./security-posture.md) — do this before you expose the node.
- [Bootstrap authentication & mint tokens](./auth-bootstrap.md)
- [Reach the control plane on day zero (RPK TLS)](./bootstrap-tls.md)
- [Sign in with OIDC](./oidc.md), [make a scoped CI deploy token](./ci-token.md)
- [Hold the signing key in a KMS/HSM/Vault](./external-signer.md)
- [Restrict visitor access](./visitor-access.md), [encrypt secrets at rest](./secrets-at-rest.md)

## 3. Domains, DNS & TLS

- [Attach a custom domain](./custom-domain.md)
- [Get an automatic certificate](./acme-cert.md), [wildcard certs with DNS-01](./wildcard-dns01.md)
- [Automate DNS with a provider](./auto-dns.md)

## 4. Provision what apps need

- [Declare a managed database](./managed-databases.md)
- [Isolate tenants within a project](./tenant-isolation.md)
- [Run a container or microVM](./compute.md), [scale compute to zero](./scale-to-zero.md)
- [Load-balance & proxy upstreams](./gateway.md)

## 5. Operate it

- [Observe: logs, metrics, health, stats](./observe.md), [alert on node & system health](./node-health-alerting.md)
- [Back up & restore](./backup.md), [export, import & clone a project](./clone-project.md)
- [Garbage-collect & verify integrity](./prune-scrub.md)
- [Rotate the root key](./rotate-root-key.md), [upgrade a store to project scoping](./upgrade-store-to-projects.md)

## 6. Scale out

- [Deploy a self-hosted cluster](./deploy-cluster.md), [manage certificates in a cluster](./cluster-certs.md)
- [Bring up a cluster on Hetzner](./cluster-on-hetzner.md), [run on Kubernetes](./kubernetes.md)
- [Deploy on Cloudflare Containers](./deploy-cloudflare.md)
- [Reach services over the overlay (service tunneler)](./service-tunneler.md)

Prefer to understand the model first? See
[Deployment topologies & the one-UX seam](../explanation/topologies.md) and
[The security posture model](../explanation/security-posture.md).
