# The CLI

boatramp is one binary with subcommands. Configuration precedence is uniform
everywhere: **flag / env var > config file > built-in default**. The config file
is `project.cfg` for the project commands and `boatramp.cfg` for `serve` (both
RON).

| Command | Purpose |
| --- | --- |
| `serve` | Run the server (selects backends + TLS + auth). |
| `sync` | Negotiate a manifest, upload missing blobs (streamed), activate. |
| `build` | Run your build command before publishing. |
| `bundle` | The embedded JS+CSS bundler (`bundler` feature). |
| `validate` | Validate a `project.cfg` (its `routing`) / handler bundle locally. |
| `deployments` | List a site's deployment history (newest first; `*` = live). |
| `status` | Show a site's current deployment (id, age, size). |
| `rollback` | Re-activate the previous deployment, or a specific id. |
| `domain` | Verify + attach hostnames to a site. |
| `alias` | Manage named aliases (e.g. `staging`, `preview-…`). |
| `access` | Configure visitor access control. |
| `token` | Mint / list / revoke control-plane API tokens. |
| `dns` | DNS-01 helper for wildcard certs (`acme-dns` feature). |
| `logs` | Tail a site's captured guest stdout/stderr (`handlers`). |
| `stats` | Show handler invocation / consumer / stream stats. |
| `dlq` | Purge or redrive a consumer topic's dead-letter queue. |
| `prune` | Delete orphan deployments + unreferenced blobs. |
| `scrub` | Verify every stored blob still hashes to its key. |
| `cert-status` | Show cluster-managed certificate status. |
| `cloudflare` | Generate a Cloudflare deployment (`cluster` feature). |

Run `boatramp <command> --help` for the flags of any subcommand. The project
commands read defaults from `project.cfg`, `serve` from `boatramp.cfg` — see
[Configuration](./configuration.md).

## Common flags

- `--server <url>` (env `BOATRAMP_SERVER`) — the boatramp server to talk to.
- `--site <name>` (env `BOATRAMP_SITE`) — the site to act on.
- `--config <path>` — use a specific config file (defaults to `project.cfg`,
  or `boatramp.cfg` for `serve`).
- Client auth is sent as `Authorization: Bearer` from `BOATRAMP_TOKEN` or
  `publish.token`.

## Logs as JSON

Set `BOATRAMP_LOG_FORMAT=json` for machine-readable structured logs (including
the per-request `boatramp::access` line).
