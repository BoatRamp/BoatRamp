# Reach the control plane on day zero (`--tls rpk`)

Before a host has a certificate, the control-plane API is normally reached over
plaintext loopback, an SSH tunnel, or a TLS-terminating proxy. On a bare-metal or
VPS node you often want an **encrypted, authenticated** control channel from the
first second — with no ACME, tunnel, or proxy. `--tls rpk` gives you that using a
**raw public key** (RFC 7250) the client pins.

This is for the **operator/CLI** channel, not public browser traffic (browsers
can't pin a raw public key). Your sites keep serving over ACME / custom certs as
usual — this is orthogonal.

## 1. Serve with `--tls rpk`

```sh
boatramp serve --tls rpk --addr 0.0.0.0:8443 --data-dir /var/lib/boatramp
```

On startup it generates (once) a dedicated control-plane TLS identity at
`<data-dir>/controlplane-tls.key` (Ed25519, `0600`) — **not** your root auth key,
so a KMS/HSM-held root signer keeps working — and prints its public key:

```text
serving HTTPS (RPK bootstrap TLS) addr=0.0.0.0:8443 pubkey=302a300506032b6570032100db36…e28a
control-plane RPK TLS identity — pin the client with:
  --server-pubkey 302a300506032b6570032100db36…e28a
```

The identity is **public, not a secret** — it's the exact key the client verifies
against. Note it (or read it later from the startup log).

## 2. Pin it from the client

Copy the printed key to `BOATRAMP_SERVER_PUBKEY`, and every `boatramp` command
pins the control plane to that identity over an encrypted channel:

```sh
export BOATRAMP_SERVER=https://cp.example.com:8443
export BOATRAMP_SERVER_PUBKEY=302a300506032b6570032100db36…e28a
export BOATRAMP_TOKEN=…                 # your control-plane token

boatramp token ls                        # …runs over pinned RPK TLS
```

- The **channel** is authenticated by the pin (a wrong or missing pin aborts the
  handshake — it never falls back to trusting an unknown key).
- **You** are authenticated by the bearer `BOATRAMP_TOKEN`, exactly as over any
  other TLS mode.

If `BOATRAMP_SERVER_PUBKEY` is unset, the client uses ordinary WebPKI TLS — so the
same commands work unchanged once the host has a real certificate.

## How it works

`--tls rpk` reuses boatramp's cluster-mesh RFC 7250 stack (`boatramp-rpktls`): the
server presents its raw public key, the client verifies it is **exactly** the
pinned key — no CA, no hostname check, no `notBefore`/`notAfter` clock hazard.
Trust is established by that one out-of-band step: obtaining the key fingerprint
through a trusted channel (the startup log on the box you just provisioned). The
handshake is TLS 1.3 with the `X25519MLKEM768` post-quantum-hybrid group.

## When to use it

- **First-boot / bare-metal / VPS**: an encrypted control plane before ACME, with
  no tunnel or proxy — pin the printed key and go.
- **Not for browsers or public site traffic** — use `--tls acme` / `acme-dns` /
  `custom` there.
- On a platform that terminates TLS for you (fly.io, Cloudflare), you don't need
  this — run `--tls off` behind the platform's edge.

> **Coming next:** an attestation-based path (`--root-pubkey`) where the client
> pins only your **root** key once and learns each node's TLS identity from a
> root-signed attestation served at
> `/.well-known/boatramp-bootstrap-identity` — one anchor for the whole fleet.
> The server already serves that attestation under `--tls rpk`.
