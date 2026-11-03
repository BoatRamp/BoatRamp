# How-to guides

Task-oriented recipes — "how do I X". Each guide is a single job, command-first,
and links out to the reference for exhaustive detail. New here? Follow a
[tutorial](../tutorials/first-site.md) first; want the "why", read an
[explanation](../explanation/concepts.md).

Not sure where to start? Pick your reading path:

- **[Start here: operators](./operators.md)** — you will run boatramp in production.
- **[Start here: app developers](./app-developers.md)** — you write handlers, functions, and edge compute.

## Most common tasks

- [Publish, roll back, and alias a site](./publish.md)
- [Attach a custom domain](./custom-domain.md) and [get an automatic certificate](./acme-cert.md)
- [Deploy a handler](./deploy-handler.md) or [deploy & invoke a function](./functions.md)
- [Use handler bindings](./handler-bindings.md) (kv, sql, blobstore, messaging)
- [Declare a managed database](./managed-databases.md)
- [Bootstrap authentication & mint tokens](./auth-bootstrap.md)
- [Deploy a single node in production](./deploy-single-node.md)
- [Back up & restore](./backup.md)
- [Run a container or microVM](./compute.md)

## By topic

### Install & embed

Get the binary, build it yourself, or embed it as a library.

- [Install boatramp](./install.md)
- [Build from source](./build-from-source.md)
- [Embed boatramp as a library](./embed.md)

### Sites: publish & configure

Publish static sites, organize them into projects and tenants, and shape routing.

- [Publish, roll back, and alias a site](./publish.md)
- [Organize sites into a project](./projects.md)
- [Declare a project with `apply`](./apply.md)
- [Author configs in RON or JSON](./config-formats.md)
- [Configure routing](./routing.md)
- [Isolate tenants within a project](./tenant-isolation.md)
- [Let an app configure its own project](./self-configure.md)
- [Migrate from Netlify / Cloudflare Pages](./migrate-from-netlify.md)

### Domains, DNS & TLS

Attach hostnames, get certificates, and automate DNS.

- [Attach a custom domain](./custom-domain.md)
- [Get an automatic certificate](./acme-cert.md)
- [Wildcard certs with DNS-01](./wildcard-dns01.md)
- [Issue certificates on-demand](./on-demand-tls.md)
- [Automate DNS with a provider](./auto-dns.md)
- [Manage certificates in a cluster](./cluster-certs.md)

### Auth, identity & secrets

Bootstrap the control plane, mint and scope tokens, sign in with OIDC, pick a
security posture, and manage secrets.

#### Bootstrap & sign in

- [Bootstrap authentication & mint tokens](./auth-bootstrap.md)
- [Reach the control plane on day zero (RPK TLS)](./bootstrap-tls.md)
- [Sign in with OIDC](./oidc.md)

#### Tokens & capabilities

- [Make a scoped CI deploy token](./ci-token.md)
- [PoP-bind a control-plane token (DPoP)](./pop-tokens.md)
- [Mint a delegated capability](./delegated-capabilities.md)

#### Keys, secrets & posture

- [Hold the signing key in a KMS/HSM/Vault](./external-signer.md)
- [Rotate the root key](./rotate-root-key.md)
- [Encrypt secrets at rest](./secrets-at-rest.md)
- [Choose & inspect a security posture](./security-posture.md)
- [Restrict visitor access](./visitor-access.md)
- [Give handlers & functions secrets](./secrets.md)

### Functions, handlers & workflows

The guest-developer path. Read these roughly in order:

1. [Deploy & invoke a function](./functions.md) — start here; the compute primitive.
2. [Deploy a handler](./deploy-handler.md) — put a function behind a route.
3. [Use handler bindings](./handler-bindings.md) — give it data bindings. One focused
   page each: [kv](./handler-binding-kv.md), [sql & orm](./handler-binding-sql.md),
   [blobstore](./handler-binding-blob.md), [messaging](./handler-binding-messaging.md).
4. [Compose components into one handler](./compose.md) — assemble multiple components.
5. [Run consumers, crons, and streams](./background-work.md) — background work.
6. [Orchestrate functions with workflows](./workflows.md) — chain into a durable DAG.
7. [Build a duplex agent session (SSE + resume)](./sessions.md) — long-lived streams.
8. [Serve a GraphQL API](./graphql.md) — a GraphQL surface over your data.
9. [Send email from a function or handler](./send-email.md) — the email capability.

### Data: databases, migrations & blobs

Declare managed stores, run schema migrations, and ingest large blobs.

- [Declare a managed database](./managed-databases.md)
- [Run owner-gated schema migrations](./in-app-migrations.md)
- [Ingest large uploads over S3 (blob-ingress)](./blob-ingress.md)

> Switching the blob *backend* is an operator task — see [Switch the blob backend
> with zero downtime](./blob-backend-migration.md) under [Operations, backup & data movement](#operations-backup--data-movement).

### Containers & microVMs

Run OCI containers and Firecracker microVMs behind a route.

- [Run a container or microVM](./compute.md)
- [Scale compute to zero](./scale-to-zero.md)
- [Diagnose & work around compute issues](./diagnose-compute.md) — troubleshooting.

### Networking & gateway

Reverse-proxy upstreams, tune caching and compression, and reach private services.

- [Load-balance & proxy upstreams](./gateway.md)
- [Control caching](./caching.md)
- [Enable compression](./compression.md)
- [Reach services over the overlay (service tunneler)](./service-tunneler.md)

### Run boatramp in production

Install the boatramp **server** into a production topology — one node, a cluster,
Kubernetes, or Cloudflare. (To deploy your *site*, see [Sites](#sites-publish--configure);
to deploy your *handler or function*, see [Functions, handlers & workflows](#functions-handlers--workflows).)

- [Deploy a single node in production](./deploy-single-node.md)
- [Deploy a self-hosted cluster](./deploy-cluster.md)
- [Bring up a cluster on Hetzner](./cluster-on-hetzner.md)
- [Run on Kubernetes (the in-binary operator)](./kubernetes.md)
- [Deploy on Cloudflare Containers](./deploy-cloudflare.md)

> Managing TLS for a cluster? Cluster certificates live under [Domains, DNS &
> TLS](#domains-dns--tls) — see [Manage certificates in a cluster](./cluster-certs.md).

### Operations, backup & data movement

Observe, alert, and move data between servers, and keep a node healthy over time.

#### Back up, export & clone

Backup, export, and clone are one family — pick the one that matches your goal:

- [Back up & restore](./backup.md) — snapshot a node and restore it.
- [Export, import & clone a project](./clone-project.md) — move a whole project between servers.
- [Incremental & true-delta export](./delta-export.md) — repeatable, delta-only exports.

#### Observe & alert

- [Observe: logs, metrics, health, stats](./observe.md)
- [Alert on node & system health](./node-health-alerting.md)

#### Maintain & migrate

- [Upgrade boatramp to a new version](./upgrade-boatramp.md) — pull the new binary/image, roll a cluster, migrate, roll back.
- [Garbage-collect & verify integrity](./prune-scrub.md)
- [Switch the blob backend with zero downtime](./blob-backend-migration.md)
- [Upgrade a store to project scoping](./upgrade-store-to-projects.md)

### Integrations & tooling

Drive and extend boatramp from a console, a generated client, or an AI agent.

- [Enable the embedded web console](./web-console.md)
- [Generate a Connect / gRPC client](./connect-clients.md)
- [Drive boatramp from an AI agent (MCP)](./mcp.md)
