# Configuration

boatramp has three configuration surfaces, split by audience. The two file-based
ones are **RON**:

1. **`project.cfg`** — one per project folder, read by the client commands
   (`sync`, `build`, `bundle`, `validate`): where/how to publish, an optional
   build/bundle step, and the deploy-scoped `routing` config. See
   [`project.cfg`](#projectcfg).
2. **`boatramp.cfg`** — the server daemon config, read by `serve`. Every value
   can also be passed as a flag or env var. See [`boatramp.cfg`](#boatrampcfg).
3. **`SiteConfig`** — per-site settings (domains, transport security, access
   control, compression, handler policy). This lives in the control-plane KV,
   not in a file, so it travels with the server and is edited via the API and
   the `domain` / `access` subcommands.

Precedence for overridable server settings is **flag / env > `boatramp.cfg` >
default**.

## `project.cfg`

Authored in each project folder; copy
[`examples/site/project.cfg.example`](https://github.com/BoatRamp/BoatRamp/blob/main/examples/site/project.cfg.example).
The `routing` section is folded into the immutable deployment manifest, so it
rolls back atomically with the content.

```ron
(
    // Where to publish (or use --server/--site and BOATRAMP_TOKEN).
    publish: (
        server: "https://pad.example.com",
        site: "my-site",
    ),
    // Optional build step run before `sync`.
    build: (
        command: "npm run build",
        output: "dist",
    ),
    // Deploy-scoped routing — redirects, rewrites (SPA fallback + reverse-proxy
    // targets), header rules, the Cache-Control default, clean-URLs, the
    // directory index, custom error documents, the trailing-slash policy, and
    // any handlers/consumers/crons/streams.
    routing: (
        clean_urls: true,
        redirects: [ (from: "/old/:slug", to: "/new/:slug") ],
        headers: [ (matches: "**.js", set: { "Cache-Control": "public, max-age=31536000, immutable" }) ],
    ),
)
```

Validate it locally with `boatramp validate`. Migrating from Netlify/Pages?
`sync` also folds `_redirects` and `_headers` files into the routing config
automatically. Handlers/consumers/crons/streams are covered in
[WebAssembly Handlers](./handlers.md).

## `boatramp.cfg`

The server config; copy
[`boatramp.cfg.example`](https://github.com/BoatRamp/BoatRamp/blob/main/boatramp.cfg.example).

```ron
(
    serve: (
        addr: "0.0.0.0:8080",            // bind address
        data_dir: "./data",              // fs blobs in <dir>/blobs, KV in <dir>/kv-slate
        auth_root_private_key: "es256:…",// token root key (issuing node) — enables auth
        // auth_root_public_key: "es256:…", // …or just the public key (verify-only node)
        // signer: AwsKms(key_id: "…"),  // …or a KMS/HSM/Vault-held root key — see Authentication

        // Operational request limits (all optional; unlimited by default):
        max_upload_bytes: 1073741824,    // reject blob uploads larger than this
        upload_idle_timeout_secs: 30,    // abort a stalled upload (slowloris)
        max_concurrent_uploads: 16,      // 503 beyond this many in-flight uploads

        // Serving knobs:
        default_site: "marketing",       // served for an unmatched Host (else 404)
        http_redirect_addr: "0.0.0.0:80",// in a TLS mode, redirect :80 → HTTPS
        protect_previews: true,          // require a token to view /_deploy previews

        // Shared-mode coherence (multiple frontends over one shared KV):
        cluster_rate_limit: false,       // rate-limit via the shared KV, not per node
        shared_cache_coherence: false,   // changelog-based cache invalidation
    ),
)
```

The `cluster` section is covered in [Clustering](../deployment/cluster.md);
`handlers` in [WebAssembly Handlers](./handlers.md).

Use `--config <path>` to point at a specific file (it defaults to `project.cfg`
for the project commands and `boatramp.cfg` for `serve`).

## Where each setting lives

- **Deploy tier** (content concerns — `project.cfg` `routing`): redirects,
  rewrites, headers, cache, content types. Rolls back with the deployment.
- **Site tier** (`SiteConfig` in the KV): domains, HTTPS-redirect/HSTS/CSP,
  access control, WAF, compression, handler policy. Operator-controlled.
- **Server tier** (`boatramp.cfg` `serve` / flags): bind address, backends,
  TLS, request limits, default site.

Where the tiers overlap on a response header, the site/transport tier wins; the
content tier owns `Cache-Control` and `Content-Type`.
