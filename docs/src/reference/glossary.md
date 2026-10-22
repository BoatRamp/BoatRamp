# Glossary

The canonical term for each concept, used consistently across these docs. Where a
concept has a fuller treatment, the definition links to it.

## Sites & content

**Site** — a named project boatramp serves. The unit that owns domains, config,
and deployments.

**Project** — the Workspace (Uchron term) that owns many sites, functions, and
compute, and is the tenant boundary for a managed handler's row-level scope. Every
resource belongs to exactly one project; a site name is unique only within its
project. See [Organize sites into a project](../how-to/projects.md).

**default project** — the reserved project holding all pre-0.2.0 resources and
anything deployed without an explicit `--project`; byte-identical to
single-project behaviour, and cannot be deleted.

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

## Overlay fabric

**Overlay** — boatramp's relay-blind, capability-gated, end-to-end-encrypted network
for reaching in-cluster services from the outside (or publishing a local service
into the cluster), with no VPN and no exposed ports. See
[`boatramp forward`](./cli.md#boatramp-forward) /
[`boatramp expose`](./cli.md#boatramp-expose).

**Relay / ingress** — a node accepting external client dials and forwarding them,
ciphertext-blind, into the cluster. Configured under
[`[overlay]`](./boatramp-cfg.md#overlay).

**Egress / terminator** — a node fronting a local backend service; it independently
re-verifies every dial's capability against the proven client identity
(zero-trust), so a compromised relay can't reach the backend on its own.

**Dial capability** — a holder-bound, time-bounded credential minted to reach a
specific overlay service (`boatramp forward`, `Overlay·Write`).

**Publish capability** — a holder-bound, time-bounded credential minted to publish
a service name into the cluster (`boatramp expose`, `Overlay·Admin`) — a
stronger grant than a dial capability, because it claims a name other clients
trust and pin.

**Exposer** — a client registered with a relay under `boatramp expose`, publishing
a local service into the cluster's self-serve directory.

**Pairing** — the operator-to-operator flow (`boatramp overlay pair` /
`pair-code`) that mutually verifies two overlay identities via a
relay-blind handshake and a human-compared **SAS**, admitting a MITM-free peer
into local trust with no shared control plane required for the handshake.

**SAS (short authentication string)** — a few words or digits, derived
deterministically from a pairing handshake's transcript, that two operators
compare out of band; a match rules out an active man-in-the-middle.

**Pairing PARK** — the relay-hosted rendezvous an `overlay pair-code` recipient
parks at (`overlay pair --accept`) so a NAT'd peer can redeem the code and meet
through the relay. Per relay, `open` (unauthenticated — the SAS is the trust
anchor) or `authenticated` (requires an `overlay-pairing-park` capability).

**Flow policy** — an optional, operator-authored Cedar policy that can deny or
shrink the TTL of a dial/publish mint the RBAC layer already permits — a
narrower, separate gate from RBAC itself. See
[Overlay flow policy](./api.md#overlay-flow-policy).
