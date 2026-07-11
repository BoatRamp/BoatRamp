# PoP-bind a control-plane token (DPoP)

A control-plane token is a **bearer** token: whoever holds the bytes can use it
until it expires or is revoked. If one leaks — a CI log, a `.env`, a laptop — it is
replayable as-is within that window.

A **PoP-bound** (proof-of-possession) token closes that gap. The token carries a
holder public key (`cnf`, RFC 8747); the matching **private** key never travels
with the token. On every request the client signs a small proof with that private
key binding *this* request (method, path, the server's origin, the token, and — on
writes — the body). The server rejects the token unless a valid, fresh proof
accompanies it. A leaked token **alone** is then inert.

This is boatramp's take on DPoP (RFC 9449) expressed over the existing COSE `cnf`.
It works over **any** TLS mode (public ACME, a proxy/CDN, or `--tls rpk`) — unlike
channel binding, it does not depend on the transport.

## 1. Set the server's canonical origin

The proof binds an `aud` — the fleet's public origin — which the server compares
against its **configured** value, never a `Host`/`X-Forwarded-*` header. Set it
once:

```ron
// boatramp.cfg
serve: (
    pop_origin: "https://cp.example.com",
)
```

or `--pop-origin https://cp.example.com` / `BOATRAMP_POP_ORIGIN`. Without it, a
holder-bound token cannot be verified and is rejected — so configure it before
issuing PoP tokens.

## 2. Mint a PoP-bound token

`token create --pop` generates a fresh holder keypair, mints the token against its
public half, and prints **both** secrets as ready-to-export shell lines:

```sh
boatramp token create "ci deploy" --role publisher:blog --pop
```

```text
BOATRAMP_TOKEN=g6Rh...            # the token (a cnf/holder-bound COSE_Sign1)
BOATRAMP_TOKEN_HOLDER_KEY=es256:9f8c…   # the holder PRIVATE key — the signing key
```

Store both now — neither can be recovered. The decisive win comes when the holder
key lives **somewhere the token does not** (a secrets manager, an HSM/KMS): an
attacker then needs *two* separately-held secrets, not one.

## 3. Use it

Export all three values; every `boatramp` command then signs a fresh proof per
request automatically — one seam, no per-command flags:

```sh
export BOATRAMP_SERVER=https://cp.example.com
export BOATRAMP_TOKEN=g6Rh...
export BOATRAMP_TOKEN_HOLDER_KEY=es256:9f8c…
export BOATRAMP_POP_ORIGIN=https://cp.example.com   # matches the server's pop_origin

boatramp deployments --site blog        # signed transparently
```

With no holder key set, the client is a plain bearer client (unchanged) — so a
non-PoP token keeps working exactly as before.

## 4. (Optional) require PoP fleet-wide

A `cnf` token *always* requires a proof. To additionally forbid **plain** bearer
tokens across the whole node, turn on the `require_pop` posture knob:

```ron
// boatramp.cfg
security: ( overrides: ( require_pop: true ) )
```

`boatramp security explain` shows the resolved value. Now every token must be
holder-bound; a plain bearer is rejected with `401`.

## How it works

The per-request proof is a short `COSE_Sign1` (`br_kind = "pop"`) signed by the
holder key, binding:

- **`htm` + `htp`** — the request method and path (the path survives a reverse
  proxy; the host/scheme are **not** trusted from the request).
- **`aud`** — the server's configured `pop_origin`.
- **`ath`** — a hash of the presented token (so a stolen proof can't be paired
  with a different token).
- **`bh`** — a hash of the request body, on writes with a buffered body.
- **`iat` + `jti`** — issued-at (a tight ~60 s freshness window) and a unique id.

The server verifies the proof against the credential's **terminal** `cnf` — so for
a delegated ([attenuated](./auth-bootstrap.md)) chain the binding follows the last
delegate, not the root — then runs a **node-local** replay check on the `jti`.

## What it protects — and what it doesn't

- **Does:** a leaked *token* is inert without the holder key; a captured *proof* is
  bound to one method+path+token+body and expires in ~60 s.
- **Trade-off — cross-node replay:** the `jti` replay cache is node-local (a
  shared cache would cost a consensus round-trip per request). A captured proof can
  be replayed on a *different* node within the freshness window — bounded by the
  tight window + `ath` binding + revocation, and documented rather than hidden.
- **Trade-off — streamed bodies:** large/streamed uploads (blobs) are not
  body-bound (they carry their own content hash elsewhere); only method+path+token
  are bound for those.
- **Not a fix for host compromise:** if the token *and* the holder key sit in the
  same place (co-located CI/`.env`), PoP raises "steal one file" to "steal two
  files in the same place" — real defense-in-depth, not a substitute for holding
  the key separately.

## Rollout & anti-downgrade

The server **never** accepts a `cnf` token without a valid proof — there is no
silent fall-back to bearer semantics. Roll out by upgrading nodes first, then
issuing `cnf` tokens: a token minted with `--pop` only verifies on a node that
enforces the proof, so a not-yet-upgraded node simply rejects it rather than
downgrading it. Flip `require_pop` on only once every node enforces PoP.
