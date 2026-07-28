# Drive boatramp from an AI agent (MCP)

boatramp ships a [Model Context Protocol](https://modelcontextprotocol.io) server,
so an agent like Claude (Desktop, Code) or Codex can operate your control plane in
natural language: list sites, inspect deployments, activate or roll back, manage
domains and aliases, tail logs, invoke functions, and inspect the cluster. One
agent can drive **several** boatramp instances — each registered by name.

The server is the same binary you already run. It speaks MCP over **stdio** (what a
desktop agent spawns), and is built into the default binary (the `mcp` feature).

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

## Using it

Ask the agent naturally: *"list the sites on prod"*, *"what's the current
deployment for docs?"*, *"roll docs back to the previous deployment"*, *"tail the
last 50 log lines for the api site"*, *"invoke the resize-image function with this
payload"*.

When more than one instance is registered, name it (*"on lab, …"*); with a single
instance the agent can omit it. `list_instances` shows what's available.

### Tools

Typed tools cover the common surface: `list_sites`, `get_site_config`,
`put_site_config`, `list_deployments` / `current_deployment` / `get_deployment`,
`activate_deployment`, `list_aliases` / `set_alias` / `remove_alias`,
`list_domains` / `start_domain_verification` / `check_domain_verification` /
`remove_domain`, `tail_logs`, `handler_stats`, `operate_dlq`, `list_functions` /
`invoke_function` / `function_usage`, `cluster_members`, `cert_status`,
`prune_report`, `scrub_blobs`, and `whoami`.

For anything not wrapped by a typed tool (tokens, cluster promote/revoke, daemon
config, cache invalidation, …), the `api_request` tool reaches **any** `/api/…`
endpoint directly — full coverage of the control-plane API.

> **Authorization is the token's, not the agent's.** Every call carries the
> instance's configured token, so the agent can do exactly what that token is
> scoped to — no more. Give the agent a least-privilege token (see
> [make a scoped token](./ci-token.md)); a read-only token makes the write and
> `api_request` tools 403. Write tools and `api_request` can be **destructive**
> (overwrite config, delete aliases/domains, purge queues) — scope accordingly.
