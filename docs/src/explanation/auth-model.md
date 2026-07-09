# Authentication & authorization

The control-plane API — publishing, config, tokens — authenticates every request.
Public serving never does. This page explains the model: how a credential is
signed, how a request is authorized, and how a token can be narrowed offline. For
the tasks, see [Bootstrap authentication](../how-to/auth-bootstrap.md); for the
right vocabulary, see [RBAC roles, actions & resources](../reference/rbac.md).

## Tokens are signed claim sets

A boatramp token is a `COSE_Sign1` structure over a CWT claim set (RFC 8392 /
9052). The claims name the granted roles, an expiry, and a revocation id; the
whole thing is signed by the control plane's root key. This has one property that
shapes the rest of the design: **verifying a token needs only the public key**.
There is no per-request database lookup — a node checks the signature and the
expiry against a public key it holds, decides the request, and moves on. Every
node can authorize independently, including read replicas that never mint
anything.

Revocation is the one piece that is not purely offline: a revoked token's id is
recorded, and the verify path rejects it. That check is a small keyed lookup, not
a signature-scale cost.

## Authorization is Cedar RBAC

Once a token verifies, the request is authorized with
[Cedar](https://www.cedarpolicy.com/). Cedar decides whether the token's granted
roles carry a **right** — an action (`read`, `write`, `deploy`, `admin`) on a
**resource** (`site`, `blobs`, `tokens`, `certs`, `cache`, `system`), optionally
scoped to one site — that satisfies what the endpoint requires. The policy is
data: a default role-to-rights mapping ships built in, and an operator can
replace it (validated server-side, so a bad policy cannot brick the control
plane). Unmapped paths fall through to `system` · `admin`, so a narrow token
never reaches an ungated action by accident. The full vocabulary is in the
[RBAC reference](../reference/rbac.md).

## The signing key can live outside the process

Because verification needs only the public key, the private signing key is used
in exactly one place — minting — and can be held wherever you trust. boatramp
resolves the public half at startup as the trust anchor and calls a **signer** to
mint each token. The signer is a seam: a local key, a cloud KMS (AWS / GCP /
Azure), HashiCorp Vault, or a PKCS#11 HSM. A verify-only node needs just the
public key and cannot mint at all. See
[Hold the signing key in a KMS/HSM/Vault](../how-to/external-signer.md).

## Delegation narrows a token offline

A token minted as *delegatable* carries a holder public key (a `cnf` claim). The
holder can **attenuate** it — sign a restrict-only block that adds caveats like
"one site only", "read-only", or an earlier expiry — with no server round-trip
and without the root key. Verification walks the chain: each block must be signed
by the previous block's holder key, the caveats intersect, and the earliest
expiry wins. Because a block can only *add* restrictions, a delegated credential
can never widen authority beyond the original. Revoking the original by its id
revokes every credential delegated from it. This is how you hand a further-scoped
credential to a third party without minting a new token — see
[Make a scoped CI deploy token](../how-to/ci-token.md).

## Where auth does not apply

Public content serving is unauthenticated by design — a visitor fetching a page
is not a control-plane principal. To restrict who may *view* a site, use
per-site [visitor access control](../how-to/visitor-access.md), which is a
separate mechanism from control-plane authorization.
