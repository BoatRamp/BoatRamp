# project.cfg schema

`project.cfg` is the per-project config, read by the client commands (`sync`,
`build`, `bundle`, `validate`). It is [RON](https://github.com/ron-rs/ron), lives
in the project folder, and is optional — a missing file means all defaults.

```ron
(
    publish: ( server: "https://pad.example.com", site: "my-site" ),
    build: ( command: "npm run build", output: "dist" ),
    routing: (
        clean_urls: true,
        redirects: [ (from: "/old/:slug", to: "/new/:slug", status: 301) ],
    ),
)
```

Sections:

| Section | Purpose |
| --- | --- |
| `publish` | Where and what to publish (`sync`). |
| `build` | An optional build command run before `sync`. |
| `bundle` | The in-process JS/CSS bundler (`bundler` feature). |
| `routing` | Redirects, rewrites, headers, handlers — folded into the deployment. |

## `publish`

| Field | Type | Description |
| --- | --- | --- |
| `server` | url | Server base URL. Flag `--server`, env `BOATRAMP_SERVER`. |
| `site` | string | Site to publish to. Flag `--site`, env `BOATRAMP_SITE`. |
| `token` | string | Control-plane token. Prefer `BOATRAMP_TOKEN` so it is not on disk. |

## `build`

Run before `sync`; its output directory is what gets published.

| Field | Type | Description |
| --- | --- | --- |
| `command` | string | Shell command to run (e.g. `npm run build`). |
| `output` | string | Directory the build emits and `sync` publishes (e.g. `dist`). |

## `bundle`

The in-process bundler (Rolldown for JS/TS, lightningcss for CSS). Needs the
`bundler` feature.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `outdir` | string | `dist` | Output directory for bundled assets. |
| `js` | list | — | JS/TS entry points (tree-shaken, code-split). |
| `css` | list | — | CSS entry points (`@import` inlined). |
| `minify` | bool | `true` | Minify the output. |

## `routing`

The bulk of a project's config: redirects, rewrites, headers, SPA fallback,
clean URLs, error documents, and the handler/consumer/cron/stream declarations.
It is compiled and checked at `sync` (and by `boatramp validate`), then folded
into the immutable deployment manifest — so it is atomic with the content and
rolls back with it.

The full field-by-field schema is on its own page:
[Routing config schema](./routing.md).

Validate a `project.cfg` (including `routing`) without publishing:

```sh
boatramp validate
```

```text
project.cfg: routing OK (2 redirects, 1 handler)
```
