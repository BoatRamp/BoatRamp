# Publish, roll back, and alias a site

Every publish is an immutable **deployment**: `boatramp sync` uploads a folder's
blobs, records a manifest, and activates the **site** to point at it. Activation
is a pointer flip, so switching between deployments is instant. This page covers
publishing, inspecting history, rolling back, and aliases.

Routing config (redirects, headers, SPA fallback) lives in `project.cfg`; see
[Configure routing](./routing.md).

## Publish a folder

`sync` negotiates a manifest with the server, streams only the blobs it is
missing, then activates the result:

```sh
boatramp sync ./dist --site my-site --server https://pad.example.com
```

```text
scanned 128 file(s), 142 unique blob(s)
uploading 12 missing blob(s) (3.4 MiB)… done
activated my-site -> 4f3a2b2c
```

Re-running `sync` on an unchanged tree uploads nothing. Change one file and only
that blob uploads before the site flips. Preview a publish without writing
anything:

```sh
boatramp sync ./dist --site my-site --dry-run
```

```text
scanned 128 file(s), 12 changed — would upload 12 blob(s) (3.4 MiB), then activate
dry run: nothing uploaded
```

## Inspect the current deployment

```sh
boatramp status --site my-site
```

```text
my-site  live 4f3a2b2c  age 4m  128 files
```

## Review history

```sh
boatramp deployments --site my-site
```

```text
* 4f3a2b2c  2026-07-09 14:02  128 files
  5c7742de  2026-07-09 11:18  127 files
  1a09e3b4  2026-07-08 22:40  126 files
```

## Label a deployment

So you can tell at a glance what a deployment *is*, `sync` records provenance
alongside it — shown in `status`, `deployments`, and the web console.

When run inside a git repo, `sync` captures the commit SHA, branch, and (via
`git describe --tags`) the nearest **release tag** automatically. Override any of
them, add a free-form message, or attach arbitrary `key=value` tags:

```sh
boatramp sync ./dist --site my-site \
  -m "hotfix: cache headers" \
  --tag env=prod --tag ticket=ABC-123
```

`--tag` is repeatable and takes `key=value`. All of it is optional metadata: it
never affects the (content-addressed) deployment id, and re-deploying an
unchanged tree preserves the prior provenance. `status` shows it in full:

```text
my-site
  deployment  4f3a2b2c
  activated   4m ago
  release     v1.2.3
  tags        env=prod ticket=ABC-123
```

## Roll back

Re-activate the previous deployment. Because activation is a pointer flip, this
takes effect at once and uploads nothing:

```sh
boatramp rollback --site my-site
```

```text
my-site rolled back to 5c7742de (was 4f3a2b2c)
```

Target a specific deployment by its id or a unique prefix:

```sh
boatramp rollback 1a09e3b4 --site my-site
```

```text
my-site activated 1a09e3b4 (was 4f3a2b2c)
```

## Point an alias at a deployment

An **alias** is a named pointer alongside the live site — a `staging` URL, a
per-branch preview. Point one at a deployment id (from `deployments`):

```sh
boatramp alias set staging 4f3a2b2c --site my-site
```

```text
alias staging -> 4f3a2b2c
```

List and remove aliases:

```sh
boatramp alias ls --site my-site
boatramp alias rm staging --site my-site
```

To serve an alias on its own hostname, see
[Attach a custom domain](./custom-domain.md). For every command and flag, see the
[CLI reference](../reference/cli.md).
