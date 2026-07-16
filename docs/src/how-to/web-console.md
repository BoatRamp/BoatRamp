# Enable the embedded web console

boatramp ships a small web **management console** — a WebAssembly single-page app
that drives the control-plane `/api` (sites, deployments, tokens, config,
observability). It is **baked into the binary** and served, when you turn it on,
from the same origin as the API. Nothing to deploy separately, no CORS to
configure.

## Turn it on

Every shipped build already bakes the console in — the `console` feature is **on
by default**, and the release binaries and the Nix/OCI images stage the real SPA.
So on a prebuilt boatramp there's nothing to compile; you only enable *serving*
it in `boatramp.cfg`:

```ron
serve: (
    addr: "0.0.0.0:8080",
    console: (
        enabled: true,
    ),
),
```

Restart `serve` and open **`https://<your-host>/_console`**. That's it.

### Building from source

The console is a WebAssembly SPA (a Trunk build artifact), which a plain
`cargo build` can't produce. So build it once first, then the binary embeds the
real assets:

```sh
just console               # builds crates/boatramp-console/dist (needs `nix develop`)
cargo build -p boatramp --release
```

If you build the binary *without* first building the SPA, it still compiles — a
placeholder page is baked in instead, explaining how to build the real one. To
leave the console out entirely, drop the default feature:
`cargo build -p boatramp --no-default-features --features fs,slatedb`.

## Where it's served (defaults + overrides)

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Serve the console at all (opt-in). |
| `host` | `*` | Which `Host` the console answers on: `*` (any), an exact host (`console.example.com`), or a leading wildcard (`*.example.com`). |
| `path` | `/_console` | The URL path prefix it mounts at. Kept under the reserved `/_` namespace so it never collides with a published site. |

For example, to serve it only on a dedicated admin host at the site root:

```ron
console: ( enabled: true, host: "console.example.com", path: "/" ),
```

The console has a real client-side router, so pages are deep-linkable URLs under
the mount path (e.g. `/_console/sites/blog`) — a refresh or a shared link lands
on the right page.

## Sign in

The static shell loads for anyone who reaches the path, then you authenticate to
the API from inside it — either **paste a control-plane token** or use **OIDC**
(if your instance has an issuer configured). Your token's roles decide what you
can see and do (an `admin` token sees everything; a scoped token sees only its
sites). Mint one with:

```sh
boatramp token create --role admin "console"     # or a narrower --role
```

## Security notes

- The console's **static assets are served unauthenticated** at the mount path.
  They hold no secrets, and every action goes through the token-gated `/api`, so
  a bearer token is still required to do anything. (A bearer token can't gate a
  top-level browser navigation anyway — the path is obscurity, the token is the
  real gate.)
- For a management UI, prefer serving it **behind TLS** and, if you want
  network-level gating, on a **dedicated `host`** you can firewall or put behind
  a VPN/reverse-proxy.
- Because it's same-origin with the API, you do **not** need to add anything to
  `cors_allowed_origins`. (That knob is only for hosting the console — or another
  browser client — on a *different* origin.)

## See also

- [Bootstrap authentication & mint tokens](./auth-bootstrap.md)
- [Sign in with OIDC](./oidc.md)
- [Cargo features](../reference/features.md) — the `console` build feature.
