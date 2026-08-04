# Declare a project with `apply`

`boatramp apply` reads one RON manifest that declares a whole **project** — its
member sites, top-level functions, and compute workloads — and reconciles it to that
desired state in a single pass. It is the declarative counterpart to `sync` (one
site) and the imperative `function` / `compute` commands.

`apply` is **pure upsert and never prunes**: it touches only the resources the
manifest names, so declarative and imperative (CLI / API) management coexist — a site
you `sync`'d or a function you deployed by hand that is absent from the manifest is
left untouched. There is deliberately no `--prune`.

## Before you start

- A boatramp server and a token that can publish. See
  [Bootstrap authentication & mint tokens](./auth-bootstrap.md).
- Optional: an existing project — `apply` creates a named project if it is missing.

## 1. Write `apply.cfg`

```ron
(
    // Target project. Omit to use --project / BOATRAMP_PROJECT / default.
    project: "acme",

    sites: [
        // A prebuilt folder.
        ( name: "www", path: "www/dist", routing: ( clean_urls: true ) ),

        // A site with its own build step and a custom domain in its config.
        (
            name: "docs",
            build:  ( command: "npm run docs", output: "site" ),
            config: ( domains: ( primary: "docs.acme.com" ) ),
        ),
    ],

    functions: [
        (
            name: "resize", component: "resize.wasm", runtime: "wasm",
            imports: ["sql", "invoke"],           // requested host capabilities
            env: { "IDP_JWKS": "https://idp/.well-known/jwks.json" },
            invoke_targets: ["thumbnail", "img-*"],  // deny-by-default invoke allowlist
        ),
    ],

    compute: [
        ( name: "api", spec: { "spec": { "root": { "image": "ghcr.io/acme/api:1" } }, "replicas": 2 } ),
    ],
)
```

Each `sites[]` entry is a slug plus:

- `path` — the content directory (defaults to the site build's `output`, then `.`).
- `build` — an optional per-site build command run before publishing.
- `routing` — deploy-scoped routing (redirects / rewrites / headers / handlers /
  crons …), folded into the deployment so it is atomic with the content and rolls
  back with it. Same schema as `project.cfg`'s `routing`.
- `config` — the mutable [`SiteConfig`](../reference/siteconfig.md) (domains, access,
  handlers enablement …), PUT after the deployment activates.

`functions[]` mirror `boatramp function deploy`: a `component` path plus an optional
`runtime`, `webhook_secret_env`, and — parity with a site handler — `imports`
(requested capabilities like `sql` / `invoke`), `env` (static, non-secret vars),
`invoke_targets` (the deny-by-default function-to-function allowlist), and `limits`.
`compute[]` carry a raw `spec` PUT straight to the compute endpoint, the same body
`boatramp compute set` builds.

## 2. Preview the plan

```bash
boatramp apply -f apply.cfg --dry-run
```

`--dry-run` prints what *would* be built, deployed, activated, and PUT — and mutates
nothing (no build, no upload, no writes).

## 3. Apply

```bash
boatramp apply -f apply.cfg
```

`apply` resolves the target project (the manifest's `project:`, else
`--project` / `BOATRAMP_PROJECT` / `default`), ensures a named project exists, then
reconciles each site, function, and compute workload in turn:

- **Sites** reuse the content-addressed `sync` flow — hash the tree, upload only the
  blobs the server is missing, then atomically activate. Re-applying an unchanged site
  uploads nothing.
- **Functions** and **compute** are create-or-replace PUTs to their project-scoped
  endpoints.

Because it is a create-or-replace upsert, running `apply` repeatedly is safe and
converges: the only writes are for resources whose content actually changed.

## Mixing declarative and imperative

You can manage part of a project with `apply.cfg` and the rest by hand. Declare the
three sites you want version-controlled; keep the others on `sync`. `apply` never
enumerates or deletes resources it does not name, so a domain you attached with
`boatramp domain add`, an alias, or a token created out of band all survive an
`apply`. Management is cooperative (last-writer-wins per named resource), not
authoritative.

## See also

- [Organize sites into a project](./projects.md)
- [Publish, roll back, and alias a site](./publish.md)
- [project.cfg schema](../reference/project-cfg.md)
