# What is boatramp?

boatramp is software you run to publish static sites, WebAssembly handlers, and
private services on your own infrastructure. It ships as a single Rust binary
that is both the server and the CLI: the same executable serves HTTP, exposes a
control-plane API, and drives deployments from the command line. You install it,
point it at a folder, and it hosts what you publish.

Two principles shape everything else.

**Streaming-first.** Every byte path streams. Uploads flow from the client
straight into the backend, downloads flow from the backend straight to the
client, and files are hashed in fixed-size chunks. No file is ever held whole in
memory — on the client, the server, or in any backend.

**Atomic, immutable deployments.** Publishing writes a folder as a
content-addressed, immutable deployment and flips the site to it in one atomic
operation. Readers see the old deployment or the new one in full, never a
half-written mix. Identical bytes are stored once, unchanged files are not
re-uploaded, and rollback is re-activating an older deployment.

## What boatramp is not

boatramp is not a hosted platform you rent. There is no account to sign up for
and no bill tied to bandwidth or build minutes — you own the machine and the
data. It is also not a CDN you point at an origin, and not a web server you hand
a config file. Where Vercel and Netlify run the infrastructure for you, boatramp
gives you the same publishing model to run yourself. Where Caddy and nginx serve
files and proxy requests, boatramp adds deployments, virtualhost routing, TLS
issuance, sandboxed handlers, and authorization as one system.

## Who it is for

Developers who want atomic deploys and instant rollback without a vendor, and
operators who want one binary, one config format, and the same commands whether
they run a single node, a Raft cluster, or Cloudflare Containers.

## Where to go next

- Evaluating boatramp? Publish something in [your first site](../tutorials/first-site.md).
- Running it in production? Start with [deploying a single node](../how-to/deploy-single-node.md).
- Writing dynamic routes? See the [handlers tutorial](../tutorials/first-handler.md).
- Want the model behind it? Read the [core concepts](./concepts.md).
