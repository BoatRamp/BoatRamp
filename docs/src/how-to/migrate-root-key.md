# Migrate the root key

A cluster **is** its root key, so custody of that key (local ⇄ external
KMS/HSM/Vault) is a first-class, low-friction operation — you never rebuild the
cluster or hand-edit every node. There are two paths, depending on whether the
target backend can import your existing key material.

For *why* custody matters and the blast radius it carries, see
[Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md).

## Same-key custody move (zero re-pin)

If the target backend can **import** key material (AWS KMS import, Vault Transit
import, GCP KMS), the **public key — the anchor — is unchanged**. Nothing re-pins
and nothing re-signs: it is purely a custody change.

1. Import your existing key into the external backend (per that backend's docs).
2. Re-point `[serve.signer]` from the local key to the external backend — see
   [Hold the signing key in a KMS/HSM/Vault](./external-signer.md) for the backend
   config.
3. Restart. boatramp verifies the imported key yields the **same** public anchor
   and continues; every node still trusts the same root, so no join re-pins.

This is the reverse, too (external → local, e.g. offboarding a KMS): re-point
`[serve.signer]` back to the local key material.

## New-key rotation (import-less HSMs)

When the backend **cannot** import (keys must be generated in-HSM), the anchor
must rotate. This uses the root-pubkey **set** (`cluster.root_pubkeys`) for a
make-before-break, cluster-wide rotation with **no window where a node rejects a
valid token**:

1. Mint the new anchor in the target backend.
2. Add its public key to the replicated root-pubkey set — every node now trusts
   **both** the old and new anchors.
3. Re-sign live attestations/tokens under the new key.
4. After propagation, retire the old anchor.

> **Status:** the root-pubkey *set* that makes both anchors trusted is in place
> today. The one-command driver, `boatramp auth rotate-root --to <signer>`, that
> automates steps 1–4 is planned; until it lands, the set can be edited and
> re-signed manually. The same-key custody move above needs no such automation.

## See also

- [Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md)
- [Hold the signing key in a KMS/HSM/Vault](./external-signer.md)
- [Deploy a self-hosted cluster](./deploy-cluster.md)
