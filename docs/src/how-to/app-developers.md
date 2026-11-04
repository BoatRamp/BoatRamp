# Start here: app developers

**For: app developers** — you write handlers, functions, and edge compute that
run on someone's boatramp. This is a reading path, not a new section: every link
lands in a how-to group. For the full menu, see the [how-to index](./index.md).

## 1. Write your first function

- [Install boatramp](./install.md) — you only need the CLI.
- [Write your first handler](../tutorials/first-handler.md) — the guaranteed-success tutorial.
- [Deploy & invoke a function](./functions.md) — the compute primitive.

## 2. Build real handlers

Read the Functions, handlers & workflows group (in the [how-to index](./index.md))
roughly in order:

- [Deploy a handler](./deploy-handler.md) — put a function behind a route.
- [Use handler bindings](./handler-bindings.md) — data bindings ([kv](./handler-binding-kv.md), [sql & orm](./handler-binding-sql.md), [blobstore](./handler-binding-blob.md), [messaging](./handler-binding-messaging.md)).
- [Compose components into one handler](./compose.md)
- [Run consumers, crons, and streams](./background-work.md)
- [Orchestrate functions with workflows](./workflows.md)
- [Build a duplex agent session (SSE + resume)](./sessions.md)
- [Serve a GraphQL API](./graphql.md), [send email from a function or handler](./send-email.md)

## 3. Work with data

- [Declare a managed database](./managed-databases.md) (your operator may do this for you)
- [Run owner-gated schema migrations](./in-app-migrations.md)
- [Ingest large uploads over S3 (blob-ingress)](./blob-ingress.md)

## 4. Secrets & capabilities

- [Give handlers & functions secrets](./secrets.md)
- [Mint a delegated capability](./delegated-capabilities.md)
- [PoP-bind a control-plane token (DPoP)](./pop-tokens.md)

## 5. Ship & integrate

- [Organize sites into a project](./projects.md), [declare a project with `apply`](./apply.md)
- [Let an app configure its own project](./self-configure.md)
- [Generate a Connect / gRPC client](./connect-clients.md)
- [Drive boatramp from an AI agent (MCP)](./mcp.md)

Want the "why" first? See [Functions: the compute primitive](../explanation/functions.md)
and [Core concepts & the deployment model](../explanation/concepts.md).
