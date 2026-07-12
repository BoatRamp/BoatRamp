# Mesh identity & the single root anchor

A boatramp cluster is defined by **one root of trust** — the control-plane root
key. This page explains what that key protects, the blast radius it carries, and
the custody choices you have. It is an **advisory**, not a gate: boatramp does not
force any particular custody on you.

## What the root key does

The same root key underwrites everything a cluster trusts:

- **Control-plane authorization** — it signs the COSE/CWT tokens that authorize
  `/api/*` operations.
- **Mesh admission** — it signs the single-use **join tokens** and the
  **root-signed member assertions** a joiner verifies before trusting any peer.
- **Node TLS identity** — it signs each node's bootstrap attestation, which a
  joiner (or `auth pin`) verifies to pin that node's raw-public-key TLS identity.

A node knows only the **root public key** (the anchor). There is no peer map: a
node's own mesh keypair is generated on first boot, its id is derived from that
key, and every trust decision keys on the **full public key**, never on the id.

## Mesh private keys never leave a node

Each node generates and persists its own Ed25519 mesh identity (`0600`) and
**only that node ever holds or mints its private key**. The CLI and the
Kubernetes operator handle only the *root* key and *tokens* — never a node's mesh
private key. Key rotation is node-local and make-before-break: a node rotates its
own key, trusts the new one cluster-wide, then retires the old — with no window
where a valid peer is rejected.

## The blast radius (F8), stated plainly

Because the one root key now gates **mesh admission** as well as token authz, its
blast radius is larger than a design with an independent per-node trust layer. If
the root **private** key is compromised, an attacker can mint join tokens and
member assertions — i.e. admit nodes to the mesh — in addition to authorizing
control-plane operations.

boatramp surfaces this rather than hiding it: a cluster running on a **local**
root key logs a one-line advisory at startup. That is the entire enforcement —
there is **no hard KMS/HSM requirement at any posture**.

## Custody is your choice, never gated

The root key may be:

- a **local** key (raw bytes in a `0600` file), or
- an **external signer** — AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault
  Transit, or a PKCS#11 HSM. The `Signer` trait is remote-capable, so *signing*
  (not just at-rest encryption) can live in the external backend and the private
  key need never enter process memory.

Both are valid at every security posture. Choosing an external signer narrows the
blast radius (a compromised node cannot exfiltrate a key it never held), which is
why it is **recommended** for multi-tenant or internet-facing clusters — but it is
never imposed.

### Narrowing it further, without imposing KMS

Two independent defenses reduce the blast radius without touching custody:

- **A root-pubkey *set*.** `cluster.root_pubkeys` is a set, enabling
  make-before-break **root rotation** (add the new anchor, re-sign, retire the
  old) with no rejection window — see [Migrate the root key](../how-to/migrate-root-key.md).
- **A distinct mesh-admission signer.** You can mint join tokens (and member
  assertions) with a **separate key** from the admin-token root and trust it via
  `auth rotate-root --add <admission-pubkey>`. The join path verifies against the
  admin root *and* the anchor set, so admission is authorized by the distinct key
  while the admin-token root stays independent — compromise of one does not grant
  the other. This narrows the radius *without* a separate signer config or forcing
  anyone onto an HSM. (Put the admission pubkey in the join ticket's anchors so
  joiners verify members against it.)

## Seeds are integrity-relevant (F2)

A seed's attestation proves it is a **fleet member under the root anchor** — it
does **not** prove the seed is live, non-revoked, or the partition you intend. So
treat `cluster.seeds` (and the join ticket) as **integrity-protected** input: a
signed/Secret source in Kubernetes, not a mutable plain ConfigMap.

## Revocation is durable and re-admit-proof (F6)

Removing a node writes a durable **revocation tombstone** keyed on its full mesh
public key. A fresh join token cannot silently re-admit a just-removed key — an
explicit un-revoke is required first. A `remove` racing an in-flight `join` always
resolves to *removed*.

## See also

- [Deploy a self-hosted cluster](../how-to/deploy-cluster.md)
- [Migrate the root key](../how-to/migrate-root-key.md)
- [Bootstrap TLS & pinning](../how-to/bootstrap-tls.md)
- [Auth model](./auth-model.md)
