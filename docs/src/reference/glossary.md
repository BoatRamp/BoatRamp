# Glossary

The canonical term for each concept, used consistently across these docs. Where a
concept has a fuller treatment, the definition links to it.

## Sites & content

**Site** — a named project boatramp serves. The unit that owns domains, config,
and deployments.

**Deployment** — an immutable published version of a site's content, identified by
a content hash. A deployment is created, then [activated](#activation); it never
changes in place.

**Activation** — flipping a site's *current* pointer to a deployment, making it the
live one. The reverse is a rollback (activating an earlier deployment).

**Current** — the deployment a site serves by default. One per site.

**Manifest** — the path→hash map that defines a deployment's content, plus its
folded-in [routing config](./routing.md).

**Blob** — the content-addressed bytes of one file, stored once and referenced by
hash. Identical files across deployments share a blob.

**Alias** — a named pointer to a deployment besides *current* (e.g. `staging`),
used for previews and opt-in [background work](../how-to/background-work.md).

**Preview** — a deployment served by its id at `/_deploy/<id>` before (or instead
of) activation. The id is an unguessable content hash.

## Compute

**Handler** — a WebAssembly [component](#component) bound to a route, run in an
in-process sandbox. See the [compute model](../explanation/compute-model.md).

**Component** — a `wasm32-wasip2` WebAssembly component: the artifact a handler,
consumer, or stream runs.

**Consumer** — a message-triggered handler, invoked once per message on a topic.

**Cron** — a scheduled invocation of a handler route.

**Stream** — a host-level SSE or WebSocket endpoint that fans out messaging topics
to connected clients.

**Import** — a host capability a handler requests (`wasi:keyvalue`, `sql`, …),
granted only if the site's allowlist permits it.

**External database** — an operator-configured Postgres/MySQL a handler or
function opens by name through the `sql` binding (*bring-your-own*), as opposed to
the managed per-site libsql default. Isolation is the operator's. See
[Use handler bindings](../how-to/handler-bindings.md#bring-your-own-database-external-postgres--mysql).

**Compute** (workload) — container or microVM execution, distinct from an
in-process handler. Needs KVM on the host. See
[Run compute workloads](../how-to/compute.md).

## Routing & serving

**The gateway** — the reverse proxy and load balancer that publishes private
upstream services through a site. See
[Expose a private service](../how-to/gateway.md).

**Request pipeline** — the fixed ordered stages every served request runs through.
See [The request pipeline](../explanation/request-pipeline.md).

**Security posture** — the operator profile (multi-tenant / single-tenant / dev)
plus overrides that set the security defaults. See
[Security posture](../explanation/security-posture.md).

## Control plane & auth

**Control plane** — the authenticated management API (publishing, config, tokens).
Distinct from public content serving, which is unauthenticated. See the
[API reference](./api.md).

**Token** — a signed, offline-verifiable credential (`COSE_Sign1` over a CWT) that
carries granted roles. See [Authentication & authorization](../explanation/auth-model.md).

**Role / action / resource / right** — the [RBAC](./rbac.md) vocabulary. A role
expands to rights; a right is an action on a resource, optionally site-scoped.

**Signer** — the seam that holds the token signing key: a local key, a cloud KMS,
Vault, or a PKCS#11 HSM. See [external signer](../how-to/external-signer.md).

**Delegation / attenuation** — narrowing a token offline into a further-scoped
child, with no server round-trip. A child can only add restrictions.

**Proof-of-possession (PoP / DPoP)** — a token bound to a holder key (`cnf`) whose
private half never travels with the token; the client signs a fresh per-request
proof, so a leaked token alone is inert. See [PoP-bind a token](../how-to/pop-tokens.md).

## Storage & topology

**Storage / KvStore** — the two backend seams: `Storage` for blobs, `KvStore` for
metadata. Swapping either swaps a backend without changing the CLI. See
[Deployment topologies](../explanation/topologies.md).

**Node** — one `boatramp serve` process.

**Cluster** — a set of nodes replicating the control plane over Raft.

**Voter / learner** — a Raft node that counts toward quorum (voter) or serves local
reads and forwards writes without voting (learner).

**Mesh** — the raw-public-key mutual-TLS network between cluster nodes. See
[cluster mesh certificates](../how-to/cluster-certs.md).
