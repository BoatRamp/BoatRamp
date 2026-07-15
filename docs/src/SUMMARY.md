# Summary

[boatramp](./index.md)

# Tutorials

- [Publish your first site](./tutorials/first-site.md)
- [Write your first handler](./tutorials/first-handler.md)
- [Run a three-node cluster locally](./tutorials/cluster-localhost.md)

# How-to guides

- [Install boatramp](./how-to/install.md)
- [Build from source](./how-to/build-from-source.md)
- [Publish, roll back, and alias a site](./how-to/publish.md)
- [Configure routing](./how-to/routing.md)
- [Migrate from Netlify / Cloudflare Pages](./how-to/migrate.md)
- [Attach a custom domain](./how-to/custom-domain.md)
- [Get an automatic certificate](./how-to/acme-cert.md)
- [Wildcard certs with DNS-01](./how-to/wildcard-dns01.md)
- [Automate DNS with a provider](./how-to/auto-dns.md)
- [Bootstrap authentication & mint tokens](./how-to/auth-bootstrap.md)
- [Reach the control plane on day zero (RPK TLS)](./how-to/bootstrap-tls.md)
- [Make a scoped CI deploy token](./how-to/ci-token.md)
- [PoP-bind a control-plane token (DPoP)](./how-to/pop-tokens.md)
- [Sign in with OIDC](./how-to/oidc.md)
- [Hold the signing key in a KMS/HSM/Vault](./how-to/external-signer.md)
- [Restrict visitor access](./how-to/visitor-access.md)
- [Choose & inspect a security posture](./how-to/security-posture.md)
- [Encrypt secrets at rest](./how-to/secrets-at-rest.md)
- [Deploy a handler](./how-to/deploy-handler.md)
- [Use kv / sql / blobstore / messaging](./how-to/handler-bindings.md)
- [Run consumers, crons, and streams](./how-to/background-work.md)
- [Deploy & invoke a function](./how-to/functions.md)
- [Orchestrate functions with workflows](./how-to/workflows.md)
- [Run a container or microVM](./how-to/compute.md)
- [Scale compute to zero](./how-to/scale-to-zero.md)
- [Load-balance & proxy upstreams](./how-to/gateway.md)
- [Control caching](./how-to/caching.md)
- [Enable compression](./how-to/compression.md)
- [Back up & restore](./how-to/backup.md)
- [Garbage-collect & verify integrity](./how-to/prune-scrub.md)
- [Observe: logs, metrics, health, stats](./how-to/observe.md)
- [Manage certificates in a cluster](./how-to/cluster-certs.md)
- [Deploy a single node in production](./how-to/deploy-single-node.md)
- [Deploy a self-hosted cluster](./how-to/deploy-cluster.md)
- [Run on Kubernetes (the in-binary operator)](./how-to/kubernetes.md)
- [Migrate the root key](./how-to/migrate-root-key.md)
- [Deploy on Cloudflare Containers](./how-to/deploy-cloudflare.md)

# Explanation

- [What is boatramp](./explanation/what-is-boatramp.md)
- [Core concepts & the deployment model](./explanation/concepts.md)
- [Functions: the compute primitive](./explanation/functions.md)
- [Architecture overview](./explanation/architecture.md)
- [Storage, KV, and KvStore's three roles](./explanation/storage.md)
- [Cache coherence](./explanation/cache-coherence.md)
- [The request pipeline](./explanation/request-pipeline.md)
- [How a request reaches your site](./explanation/addressing.md)
- [Authentication & authorization](./explanation/auth-model.md)
- [Mesh identity & the single root anchor](./explanation/SECURITY-mesh-identity.md)
- [The security posture model](./explanation/security-posture.md)
- [The configuration model](./explanation/config-model.md)
- [Compute: functions and their runtimes](./explanation/compute-model.md)
- [Deployment topologies & the one-UX seam](./explanation/topologies.md)
- [Maturity, validation & support](./explanation/maturity.md)

# Reference

- [CLI](./reference/cli.md)
- [project.cfg schema](./reference/project-cfg.md)
- [boatramp.cfg schema](./reference/boatramp-cfg.md)
- [Dynamic daemon config](./reference/daemon-config.md)
- [Routing config schema](./reference/routing.md)
- [SiteConfig schema](./reference/siteconfig.md)
- [Environment variables](./reference/env.md)
- [Control-plane HTTP API](./reference/api.md)
- [RBAC roles, actions & resources](./reference/rbac.md)
- [DNS providers & credentials](./reference/dns-providers.md)
- [Cargo features & platform support](./reference/features.md)
- [Metrics & access-log fields](./reference/metrics.md)
- [KV keyspace](./reference/keyspace.md)
- [Errors & exit codes](./reference/errors.md)
- [Glossary](./reference/glossary.md)

---

[Contributing](./contributing.md)
