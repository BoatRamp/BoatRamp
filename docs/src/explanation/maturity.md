# Maturity, validation & support

boatramp is pre-1.0. The core is feature-complete and tested; some capabilities
that depend on real cloud or multi-host environments are validated at the
mechanism level and have a remaining live-operation seam. This page states, per
capability, what "done" means so you can judge what to run in production.

## What "validated" means here

Every capability has unit and integration tests that run in CI, plus native
validation of its mechanism. Some also have a live seam — an `#[ignore]`d test or
an operational path that needs a real cluster, cloud account, or KVM host to
exercise end to end. A live seam means the code is written and the mechanism is
proven; the remaining work is real-environment operation, not implementation.

## Status by capability

| Capability | Status |
| --- | --- |
| Static hosting, atomic deploys & rollback | Stable. |
| Routing (redirects, rewrites, headers, SPA) | Stable. |
| Domains, TLS, ACME (HTTP-01 + DNS-01) | Stable. |
| Auto-DNS (10 managed providers) | Stable; each cloud provider's live round-trip is a per-provider seam (Cloudflare validated against a real zone). |
| Authentication, RBAC, external signers | Stable; KMS/HSM/Vault backends have live seams for the specific service. |
| Wasm handlers + host bindings | Stable. |
| Caching, compression, observability | Stable. |
| Single-node deployment | Stable. |
| Clustering (Raft) | In-process complete; live multi-host operation is the remaining seam. |
| Compute — containers & microVMs | The backends and the embedded VMM boot and serve real images; scale-to-zero snapshot/restore is validated live. The automatic idle→snapshot reconcile and VMM persistent volumes are being finished. |
| Cloudflare Containers target | Declarative generate + deploy is complete; live cloud deploy/scale is a beta seam. |

## Support

There is no compatibility guarantee before 1.0: config formats, CLI flags, and
the KV keyspace may change between releases. Pin a version, read the release
notes before upgrading, and back up before you do (see
[Back up & restore](../how-to/backup.md)).

For the up-to-date, code-level status of any specific area, the repository's
roadmap is authoritative — the tables above summarize it but the code and its
tests are the source of truth.
