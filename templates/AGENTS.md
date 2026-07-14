# Building this project on boatramp — guide for AI agents

This file tells an AI coding agent (Claude Code, Codex, etc.) how to develop a
project that is **built on and deployed by [boatramp](https://github.com/BoatRamp/BoatRamp)**
— a self-hosted, streaming-first web platform shipped as one Rust binary (web
server + publishing API + CLI). Read it before writing code or running commands.

> **How to install this file.** Drop it in the project root. Codex reads
> `AGENTS.md` directly. For Claude Code, either rename it to `CLAUDE.md`, symlink
> `CLAUDE.md -> AGENTS.md`, or add a one-line `CLAUDE.md` that says “See
> `AGENTS.md`”. Keep project-specific instructions in the same file below the
> `PROJECT` block.

---

## PROJECT — fill this in (delete the guidance once done)

<!-- The agent should replace these with the real values for THIS project. -->

- **Name:** `<project name>`
- **What it is:** `<one line — a static site? a site + WASM handlers? a service behind the gateway?>`
- **Publishes to:** server `<https://…>` , site `<site-name>`
- **Build:** `<the build command, e.g. "just build" or "npm run build">` → output dir `<e.g. dist>`
- **Local dev:** `<how to run it locally, e.g. "just dev">`
- **Toolchain:** `<Rust + wasm32? Node? nothing?>` — pinned by `<flake.nix / rust-toolchain.toml / package.json>`

---

## The one thing to get right

**boatramp is not Vercel/Netlify with different words for the same commands.** Its
CLI verbs are specific and small. AI agents reliably hallucinate plausible-but-fake
commands (`boatramp init`, `boatramp deploy`, `boatramp build my-app`, `boatramp
back`). **None of those exist.** Before you put any `boatramp …` command in code,
a script, CI, docs, or site copy, **verify it against the real binary**:

```sh
boatramp --help              # the real, complete command list
boatramp <command> --help    # the real flags for that command
```

If a command or flag is not in that output, it does not exist — do not invent it.
This project’s predecessor (boatramp.dev) shipped a design mock full of invented
commands; every one had to be corrected against the real CLI. Don’t repeat that.

**The real verbs you will actually use:** `serve`, `sync`, `build`, `validate`,
`rollback`, `status`, `deployments`. That’s the whole day-to-day surface.

| You might reach for… | It does not exist. Use… |
| --- | --- |
| `boatramp init` / `new` / `create` | Nothing — just make files. There is no scaffolder. |
| `boatramp deploy` | `boatramp sync <dir> --server <url> --site <site>` |
| `boatramp back` / `revert` / `undo` | `boatramp rollback [--to <id>]` |
| `boatramp build <app>` | `boatramp build` runs the *configured* `[build].command` only |
| `boatramp up` / `start` | `boatramp serve` |

---

## Mental model: what a deployment *is*

A boatramp deployment is an **immutable, content-addressed snapshot of a
directory** plus a routing manifest, published atomically:

- You produce a **static output directory** (HTML/CSS/JS/assets, plus any
  `.wasm` handler components). That directory *is* the deployable unit.
- `boatramp sync <dir>` hashes every file, uploads only blobs the server doesn’t
  already have, records a manifest (content + routing), and **flips the site to
  the new deployment in one atomic step**. In-flight requests are never split
  across versions.
- The previous deployment still exists. `boatramp rollback` flips back instantly
  — no rebuild, no re-upload.
- **Publishing content ≠ redeploying the server.** You almost never restart or
  redeploy the boatramp server to ship a change; you `sync` a new directory to a
  running server. The server is long-lived infrastructure; deployments are cheap.

Consequence for you: **the build produces a plain directory; boatramp ships it.**
Don’t design a bespoke deploy mechanism — assemble `dist/` and `sync` it.

---

## Typical project layout

```
project.cfg          # boatramp deploy + routing config (RON) — the one file boatramp reads
<source>/            # your hand-authored content / app source
scripts/ or justfile # a small build that assembles the output directory
dist/  (gitignored)  # the built, deployable directory  → what `sync` publishes
flake.nix            # (optional) devshell that puts `boatramp` + toolchain on PATH
.github/workflows/   # CI: build, then `boatramp sync`
```

Keep the build **simple and boring**: its only job is to emit a directory. A
project can be pure static HTML, static + a WASM “island” for interactivity
(progressive enhancement — the static site must still work if the island fails to
load), static + `when` conditional routing (server-side redirects on language /
cookie / file existence, no code — see below), or static + server-side WASM
handlers. Pick the least dynamic option that meets the need.

---

## `project.cfg` — the config this project owns

`project.cfg` is [RON](https://github.com/ron-rs/ron), lives in the project root,
and is read by the client commands (`sync`, `build`, `validate`). It is optional
(absent = all defaults). Four sections:

```ron
(
    // WHERE + WHAT to publish. The token is NEVER here — pass it as BOATRAMP_TOKEN.
    publish: ( server: "https://example.com", site: "www" ),

    // An optional build run before `sync`; its `output` dir is what gets published.
    build: ( command: "just build", output: "dist" ),

    // The bulk of the config: how requests are routed within the deployment.
    routing: (
        index: ["index.html"],
        clean_urls: true,                       // /about → /about.html
        trailing_slash: Preserve,               // or Add / Remove
        error_documents: { 404: "/404.html" },
        redirects: [ (from: "/old/:slug", to: "/new/:slug", status: 301) ],
        rewrites:  [ (from: "/launch", to: "/install.sh", status: 200) ], // internal, no URL change
        headers: [
            (matches: "/**",        set: { "X-Content-Type-Options": "nosniff" }),
            (matches: "/fonts/**",  set: { "Cache-Control": "public, max-age=31536000, immutable" }),
        ],
        cache: ( default: "public, max-age=0, must-revalidate" ),
        mime_overrides: { ".wasm": "application/wasm" },
        // handlers: [ ... ]  // only if the project serves dynamic routes — see below
    ),
)
```

- **Secrets never go in `project.cfg`.** The publish token is supplied out-of-band
  as `BOATRAMP_TOKEN`. Server/site can also come from `BOATRAMP_SERVER` /
  `BOATRAMP_SITE` or the `--server` / `--site` flags (flags > env > file).
- `routing` is compiled and validated at `sync` and folded into the immutable
  deployment — so routing is **atomic with content and rolls back with it**.
- **Validate without publishing** after any `project.cfg` change:

  ```sh
  boatramp validate      # → "project.cfg: routing OK (2 redirects, 1 handler)"
  ```

  The authoritative field-by-field schema: `docs/reference/project-cfg.md` and
  `docs/reference/routing.md` in the boatramp repo.

---

## The local dev loop

Run the real server locally and publish to it — this is how you verify behavior
(routing, headers, handlers) exactly as production will serve it:

```sh
boatramp serve                                   # http://127.0.0.1:8080, data in ./data
boatramp sync ./dist --server http://127.0.0.1:8080 --site <site> -m "local dev"
curl http://127.0.0.1:8080/                      # the only site → served at /
```

Notes verified against the CLI:
- `boatramp serve` with no args = plain HTTP on `127.0.0.1:8080`, data under `./data`.
- `sync`’s path defaults to `[build].output`, then `.`. Use `--build` to run the
  configured build first, `--no-build` to publish an already-built dir as-is.
- A single site is served at `/`. Multiple sites are addressed by host — see
  `docs/explanation/addressing.md`.
- Re-`sync` after any change; only changed blobs upload and the flip is atomic.

If the project has a `justfile`, prefer wiring these into `just dev` / `just build`
/ `just deploy` so the commands are discoverable (`just --list`).

---

## Server-side conditions without a handler (`when`)

Before reaching for a handler, check whether a **conditional redirect/rewrite**
does the job. A `routing.redirects`/`rewrites` rule can carry a `when` condition —
a tiny server-side expression over the request (`Accept-Language`, cookies,
headers, `file_exists(...)`) — and a `${…}` computed destination. This covers the
common "route on the request" cases (locale negotiation, file-existence fallback,
country/cookie splits) in config, with no WASM to build:

```ron
redirects: [
    // One rule → the visitor's preferred locale.
    ( from: "/", to: "/${prefers_language(['fr','en','de'])}/", status: 302,
      when: "prefers_language(['fr','en','de']) != ''" ),
],
```

boatramp adds the right `Vary` header automatically. Full grammar:
`docs/reference/routing.md` (“Conditional rules”). Prefer this over a handler when
you only need to *decide a route*, not generate a response.

## Going dynamic: handlers (only if you actually need server-side logic)

Static-first is the default. If the project needs to *generate* a response
server-side (not just pick a route — that's `when`, above), boatramp runs
**WebAssembly handlers** — components built for `wasm32-wasip2` that export
`wasi:http/incoming-handler`, sandboxed in-process (they reach only the host
capabilities you grant). Wire them under `routing.handlers`:

```ron
handlers: [
    ( route: "/api/hello", component: "hello.wasm", methods: ["GET"], imports: [] ),
],
```

- Build: `cargo build -p <handler> --target wasm32-wasip2 --release`, then copy the
  `.wasm` into the deploy dir next to your static files.
- The component is validated at `sync` (parseable + exports the handler interface).
- Data access (kv / sql / blobstore / messaging) is **opt-in per handler** via
  `imports`/bindings — see `docs/how-to/handler-bindings.md`.
- Background work (consumers, crons, streams) and heavier compute (containers,
  microVMs, the reverse-proxy `gateway`) exist but are advanced — reach for them
  only when a handler genuinely can’t do the job, and read the matching how-to
  first. Client-side interactivity (a WASM/JS “island”) is usually the better,
  cheaper choice than a server handler for UI behavior.

---

## Deploy / CI

CI’s job: build the output directory, then `sync` it to the live server with a
scoped publisher token. It does **not** redeploy the server.

```sh
# In CI, with BOATRAMP_TOKEN set to a publisher token scoped to this site:
<build the dist/ directory>                      # e.g. `just build`
boatramp sync dist --no-build \
  --server https://example.com --site <site> -m "${GITHUB_SHA::7}"
```

- `BOATRAMP_TOKEN` is a **scoped publisher token** minted with `boatramp token
  create` (mint against the target server; keep it in CI secrets, never in the
  repo). `--source`/`--branch`/`--author` default to the current git context.
- Use `--no-build` in CI when the previous step already built `dist/` (so `sync`
  publishes as-is instead of re-running `[build].command`, which may need tools
  not on PATH in that step).
- Gate the job on the secret being present so the workflow stays a green no-op
  until deploy is configured.
- Instant rollback is a one-liner if a deploy goes wrong: `boatramp rollback`.

If the project ships boatramp itself via a Nix flake, the pattern is to add
`boatramp.url = "github:BoatRamp/BoatRamp"` as an input and put it on `PATH` in the
devshell (or `nix run .#boatramp -- sync …` in CI).

---

## Working discipline (do this every time)

1. **Verify commands against `--help` before using them.** No invented verbs/flags.
2. **`boatramp validate`** after any `project.cfg` change, before committing.
3. **Prove it locally**: `serve` + `sync` + `curl` the actual routes/headers you
   changed. Don’t claim routing/handler behavior you haven’t observed.
4. **Least dynamic wins**: static → client-side island → `when` conditional
   routing → WASM handler → heavier compute, in that order of preference. Justify
   any step up.
5. **Secrets stay out of the repo** (`BOATRAMP_TOKEN` and friends are env-only).
6. **The build emits a directory; boatramp ships it.** Don’t build a parallel
   deploy path.
7. When docs/site copy show a command, it must be a command you actually ran.

---

## Where the authoritative answers live

Everything here is a summary; the source of truth is the boatramp repo’s docs
(`docs/src/…`, rendered at the project’s docs site):

- **CLI reference** — `reference/cli.md` (or `boatramp <cmd> --help`)
- **`project.cfg`** — `reference/project-cfg.md`; **routing** — `reference/routing.md`
- **Tutorials** — `tutorials/first-site.md`, `tutorials/first-handler.md`
- **Publishing / rollback / aliases** — `how-to/publish.md`
- **Custom domains + TLS** — `how-to/custom-domain.md`, `how-to/acme-cert.md`
- **Handlers & bindings** — `how-to/deploy-handler.md`, `how-to/handler-bindings.md`
- **Concepts & the deployment model** — `explanation/concepts.md`,
  `explanation/addressing.md`
- **Tokens & auth** — `how-to/ci-token.md`, `how-to/auth-bootstrap.md`

When this guide and the live `--help` / docs disagree, **the binary and the docs
win** — update this file.
