# Drive boatramp from an AI agent (MCP)

boatramp ships a [Model Context Protocol](https://modelcontextprotocol.io) server,
so an agent like Claude (Desktop, Code) or Codex can operate your control plane in
natural language: list sites, inspect deployments, activate or roll back, manage
domains and aliases, tail logs, invoke functions, and inspect the cluster. One
agent can drive **several** boatramp instances — each registered by name.

The server is the same binary you already run. It offers **two transports**, both
built into the default binary (the `mcp` feature):

- **stdio** — the `boatramp mcp` subcommand a desktop agent spawns. Can drive
  **many** named instances from `~/.config/boatramp/mcp.toml`.
- **HTTP** — a `/mcp` endpoint served by `boatramp serve` itself, for driving *that*
  node over the network. On by default; see [Over HTTP](#over-http) below.

Both expose the **same, complete, enumerated tool set** — one named tool per
control-plane operation (no generic passthrough), so every call is legible in an
audit log and bounded by the token's scope.

## Register your instances

Each instance the agent can reach is a `[[instances]]` block in
`~/.config/boatramp/mcp.toml`. Add one with `mcp setup add` — secrets are stored as
**specs** (`env:VAR`, `path:/file`, or a literal), never resolved into the file:

```console
$ boatramp mcp setup add prod \
    --server https://boatramp.example.com \
    --token env:BOATRAMP_TOKEN
added instance 'prod' -> https://boatramp.example.com

$ boatramp mcp setup add lab \
    --server https://10.0.0.5:8080 \
    --token path:/etc/boatramp/lab.token \
    --insecure
```

Flags:

| Flag | Meaning |
| --- | --- |
| `--server <url>` | The control-plane base URL (required). |
| `--token <spec>` | Admin token: `env:VAR`, `path:/file`, or a literal. Omit for an unauthenticated/dev plane. |
| `--holder-key <spec>` | The token's `cnf` holder private key, for per-request DPoP/PoP proofs (see [PoP-bind a token](./pop-tokens.md)). |
| `--server-pubkey <hex>` | Pin the server's raw public key (RFC 7250 `--tls rpk`); see [bootstrap TLS](./bootstrap-tls.md). |
| `--insecure` | Skip TLS verification (self-signed cert on a trusted private network only). |

List and remove them:

```console
$ boatramp mcp setup list
registered instances (~/.config/boatramp/mcp.toml):
  prod -> https://boatramp.example.com (token)
  lab -> https://10.0.0.5:8080 (token, insecure-tls)

$ boatramp mcp setup remove lab
```

## Connect an agent (stdio)

Point your agent at `boatramp mcp` (or `boatramp mcp serve`). For **Claude
Desktop**, add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "boatramp": {
      "command": "boatramp",
      "args": ["mcp"],
      "env": { "BOATRAMP_TOKEN": "<your admin token>" }
    }
  }
}
```

For **Claude Code**:

```console
$ claude mcp add boatramp -- boatramp mcp
```

The token env vars your instance specs reference (`env:BOATRAMP_TOKEN` above) must
be present in the process the agent spawns — set them in the `env` block (Claude
Desktop) or your shell (Claude Code).

## Over HTTP

`boatramp serve` also serves the MCP protocol at **`POST /mcp`** (streamable-http),
so an agent can drive *that* node over the network without spawning the CLI. It's
**on by default** whenever the control-plane API is served.

Point an HTTP-capable MCP client at `https://<your-node>/mcp` with an
`Authorization: Bearer <token>` header — for Claude Code:

```console
$ claude mcp add --transport http boatramp https://boatramp.example.com/mcp \
    --header "Authorization: Bearer $BOATRAMP_TOKEN"
```

How it authenticates (this is the important part):

- **Opening the channel requires a valid token.** No token, or an invalid one, and
  `/mcp` answers `401` — it's gated exactly like the rest of the control plane.
- **Each tool call runs with *your* token's authority.** The endpoint forwards your
  bearer to the node's own control-plane API in-process for every operation, so
  authorization is re-checked per call against your token's scope. Give the agent a
  least-privilege token and the write/destructive tools simply `403` — the HTTP
  endpoint grants nothing the token doesn't already grant. Nothing is minted, so it
  works even on verify-only nodes that hold no signing key.
- **Use a plain bearer, not a `cnf`/DPoP token.** A holder-bound token can't be
  re-proven for the in-process calls (the node has no holder key). `/mcp` rejects one
  at the door with a clear error rather than letting every tool call fail an opaque
  proof check; DPoP-bound setups use the stdio transport, which holds the holder key
  and signs each call.
- **Kill-switch.** `/mcp` is on by default, but you can turn it off fleet-wide with
  no restart: `boatramp config set mcp.enabled false` (it then answers `404`); set it
  back to `true` to restore. A fast lever if you need to shut the surface off.

> **Reaching `/mcp` remotely requires configuring the node's origin.** As an
> anti-[DNS-rebinding](https://developer.mozilla.org/en-US/docs/Web/Security)
> defence, `/mcp` accepts a request only if its `Host` header is loopback
> (`localhost`/`127.0.0.1`/`::1`) *or* the node's configured canonical origin
> (`[serve] pop_origin` — the same origin you set for DPoP). A co-located agent
> (e.g. Claude Code on the same host) works out of the box; for a remote agent, set
> `pop_origin` to the public URL you serve on. The allowlist is never emptied, so
> the rebinding defence stays on.

## Using it

Ask the agent naturally: *"list the sites on prod"*, *"what's the current
deployment for docs?"*, *"roll docs back to the previous deployment"*, *"tail the
last 50 log lines for the api site"*, *"invoke the resize-image function with this
payload"*.

When more than one instance is registered, name it (*"on lab, …"*); with a single
instance the agent can omit it. `list_instances` shows what's available.

### Tools

The tool set is a **complete, enumerated mirror of the control-plane API** — one
named tool per operation, with no generic passthrough, so every call is legible in
an audit log. It spans sites + deployments (`list_sites`, `get_site_config` /
`put_site_config`, `list_deployments` / `current_deployment` / `get_deployment`,
`activate_deployment`, `delete_site`), aliases + domains (`list_aliases` /
`set_alias` / `remove_alias`, `list_domains` / `start_domain_verification` /
`check_domain_verification` / `remove_domain`), functions + workflows
(`list_functions` / `invoke_function` / `function_usage` / `list_triggers` /
`rollback_function` / `set_function_alias`, `list_workflows` / `get_workflow` /
`define_workflow` / `delete_workflow` / `start_workflow_run`), observability
(`tail_logs`, `handler_stats`, `operate_dlq`), fleet + config (`cluster_members` /
`promote_member` / `revoke_member` / `rotate_mesh_key` / `create_join_token`,
`get_daemon_config` / `set_daemon_config` / `rollback_daemon_config`,
`invalidate_cache`, `list_compute`, `cert_status`, `prune_report`, `scrub_blobs`),
and identity (`mint_token`, `revoke_token`, `whoami`).

> **Authorization is the token's, not the agent's.** Every call carries the
> caller's token, so the agent can do exactly what that token is scoped to — no
> more. Give the agent a least-privilege token (see
> [make a scoped token](./ci-token.md)); a read-only token makes the write and
> fleet-admin tools `403`. The write, delete, token, and cluster tools can be
> **destructive** (overwrite config, delete sites/aliases/domains, mint/revoke
> tokens, change cluster membership) — scope accordingly.
