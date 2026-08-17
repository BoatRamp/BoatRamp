//! `boatramp cloudflare` — deploy boatramp on **CF Containers** behind an edge
//! Worker (`docs/CLOUDFLARE.md`), **natively** over the Cloudflare REST API. No
//! wrangler, nothing generated for the operator to run — the same one-token,
//! env-provided UX as the S3/GCS/Azure backends. boatramp runs as a single
//! **durable** instance (all state in R2): CF Containers scale to zero and have
//! no container-to-container networking, so a multi-node Raft quorum isn't
//! possible on the platform — the durable single-writer is the CF architecture
//! (see [`Error::NativeMultiInstance`]).
//!
//! From a small set of inputs (regions, the voting-quorum region, the container
//! image) it plans the cluster **topology** (a voting quorum in the primary
//! region, plus read-only learners elsewhere), then drives the deploy through
//! the [`boatramp_cloudflare::api`] client. The three steps are:
//!
//! 1. ensure the R2 bucket (blobs) + D1 database (the `sql` binding), idempotently;
//! 2. upload a self-contained edge Worker — one ES module defining the
//!    `BoatrampNode` container Durable Object (starts the container + proxies to
//!    boatramp's HTTP port) and `CacheCoordinator`, plus the DO migration that
//!    creates their namespaces;
//! 3. create/modify the **container application** (image + instances + region
//!    constraints + the node DO namespace) and roll it out.
//!
//! `--dry-run` previews the full plan (offline, deterministic, unit-tested);
//! `--emit-artifacts <dir>` writes reference files (Dockerfile, the Rust→Wasm edge
//! Worker source, per-node `boatramp.cfg` fragments) for inspection — not a deploy
//! step, and the multi-node topology it can render targets self-hosted / VM /
//! orchestrator deployments, not Cloudflare (where only `--quorum 1` deploys).

use std::path::PathBuf;

use crate::config::ProjectConfig;

/// A failure generating or applying a Cloudflare deployment.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `--quorum` was zero.
    #[error("--quorum must be at least 1")]
    BadQuorum,
    /// `--primary` is not one of the `--region` values.
    #[error("--primary {0:?} must be one of --region {1:?}")]
    PrimaryNotListed(String, Vec<String>),
    /// Creating an output directory or writing a generated artifact failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A native Cloudflare REST API call failed.
    #[error(transparent)]
    Api(#[from] boatramp_cloudflare::api::ApiError),
    /// A build/serialization step in the native deploy failed.
    #[error("native cloudflare deploy: {0}")]
    Native(String),
    /// A multi-node Raft quorum can't run on Cloudflare Containers — a hard
    /// platform boundary, not a missing feature. CF Containers scale to zero and
    /// have no container-to-container networking (all ingress is mediated by the
    /// owning Durable Object), so a majority of voting peers can't stay
    /// simultaneously running and exchange low-latency RPCs. The Cloudflare
    /// architecture is a single **durable** instance instead (state in R2).
    #[error(
        "Cloudflare runs boatramp as a single durable instance (got {0} nodes). CF Containers \
         scale to zero and have no container-to-container networking, so a persistent Raft \
         quorum of peers isn't possible on the platform. Use `--quorum 1` with one `--region`: \
         the instance's state is durable in R2 (a parked/replaced container restores from it), \
         which is the Cloudflare architecture. Multi-node Raft targets self-hosted / VM / \
         container-orchestrator deployments with real peer networking."
    )]
    NativeMultiInstance(usize),
}

/// `cloudflare` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp cloudflare`.
#[derive(Debug, clap::Args)]
pub struct CloudflareArgs {
    /// CF region code to run boatramp Containers in (repeatable). The
    /// `--primary` region hosts the voting quorum; the others host read-only
    /// learners (local reads, writes forwarded to the leader).
    #[arg(long = "region", required = true)]
    regions: Vec<String>,

    /// The region that hosts the voting quorum (must be one of `--region`).
    #[arg(long)]
    primary: String,

    /// Number of voting nodes in the primary region (keep odd; default 3).
    #[arg(long, default_value_t = 3)]
    quorum: usize,

    /// Container image reference for the boatramp binary.
    #[arg(long, default_value = "boatramp:latest")]
    image: String,

    /// Public domain the edge Worker serves (repeatable).
    #[arg(long = "domain")]
    domains: Vec<String>,

    /// R2 bucket binding name (blobs).
    #[arg(long, default_value = "boatramp-blobs")]
    r2_bucket: String,

    /// D1 database binding name (the `sql` handler binding).
    #[arg(long, default_value = "boatramp-sql")]
    d1: String,

    /// Internal port the Containers' `/raft` + `/stream` mesh listens on.
    #[arg(long, default_value_t = 7000)]
    mesh_port: u16,

    /// Control-plane root **private** key (`<alg>:<hex>`, from `boatramp auth
    /// init`) to enable control-plane auth on the container. Stored as an encrypted
    /// `secret_text` Worker binding and forwarded to the container at start. If
    /// omitted, a fresh key is generated and printed once — save it to redeploy
    /// with the same root (a lost key can't be recovered; CF secrets are
    /// write-only).
    #[arg(long, env = "BOATRAMP_AUTH_ROOT_PRIVATE_KEY")]
    auth_root_private_key: Option<String>,

    /// Print the deploy plan (resources, image, Worker metadata, container
    /// application) and mutate nothing.
    #[arg(long)]
    dry_run: bool,

    /// Instead of deploying, write the deployment artifacts (Dockerfile, edge
    /// Worker source, per-node cluster configs) to this directory for inspection.
    /// The deploy itself is native — this is a debugging escape hatch, not a step.
    #[arg(long)]
    emit_artifacts: Option<PathBuf>,
}

/// A node's voting role in the planned topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Voter,
    Learner,
}

/// One planned cluster node (a Container instance).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    id: u64,
    region: String,
    role: Role,
    /// Internal mesh base URL (placeholder scheme — finalized against CF
    /// Container networking; see `docs/CLOUDFLARE.md`).
    url: String,
}

/// Internal mesh URL for a node (the `[cluster].peers` value).
fn mesh_url(id: u64, mesh_port: u16) -> String {
    format!("http://boatramp-node-{id}.internal:{mesh_port}")
}

/// Where each node's **durable** Raft log/state store lives. Must be a
/// persistent volume — a voter that loses this on restart loses its log/vote
/// (see `docs/CLOUDFLARE.md`).
const RAFT_STORE_DIR: &str = "/var/lib/boatramp/raft";

/// Plan the topology: `quorum` voters in `primary`, one learner per other
/// region. Node ids are assigned `1..=N` with the bootstrap node (id 1) in the
/// primary region.
fn plan_topology(
    regions: &[String],
    primary: &str,
    quorum: usize,
    mesh_port: u16,
) -> Result<Vec<Node>> {
    if quorum == 0 {
        return Err(Error::BadQuorum);
    }
    if !regions.iter().any(|r| r == primary) {
        return Err(Error::PrimaryNotListed(
            primary.to_string(),
            regions.to_vec(),
        ));
    }
    let mut nodes = Vec::new();
    let mut id = 1u64;
    // Voting quorum in the primary region (id 1 is the bootstrap node).
    for _ in 0..quorum {
        nodes.push(Node {
            id,
            region: primary.to_string(),
            role: Role::Voter,
            url: mesh_url(id, mesh_port),
        });
        id += 1;
    }
    // One read-only learner per other region.
    for region in regions.iter().filter(|r| *r != primary) {
        nodes.push(Node {
            id,
            region: region.clone(),
            role: Role::Learner,
            url: mesh_url(id, mesh_port),
        });
        id += 1;
    }
    Ok(nodes)
}

/// The `cluster` `boatramp.cfg` (RON) fragment — the same shape `boatramp serve`
/// cluster mode consumes. Under the **dynamic-join** model the config is
/// **uniform** across nodes (no per-node id or peer map): each node derives its
/// own id from its mesh key and either **founds** (node 1, via
/// `BOATRAMP_CLUSTER_INIT=1`) or **joins** (others, via
/// `BOATRAMP_CLUSTER_JOIN=<ticket>` from `cluster add`). `this_id` selects only
/// the header comment shown to the operator.
fn render_node_config(nodes: &[Node], this_id: u64, mesh_port: u16) -> String {
    let _ = nodes;
    let mut out = String::new();
    out.push_str(
        "// Generated by `boatramp cloudflare` — uniform cluster config (boatramp.cfg).\n",
    );
    if this_id == 1 {
        out.push_str("// This is the FOUNDER: start it with env BOATRAMP_CLUSTER_INIT=1.\n");
    } else {
        out.push_str(
            "// This is a JOINER: start it with env BOATRAMP_CLUSTER_JOIN=<ticket>, where the\n\
             // ticket comes from `boatramp cluster add` run against the founder.\n",
        );
    }
    out.push_str(
        "// The root anchor defaults to serve.auth_root_public_key; the node id is derived\n\
         // from its own mesh key. No peer map, no node_id, no bootstrap flag.\n",
    );
    out.push_str("(\n");
    out.push_str("    cluster: (\n");
    out.push_str(&format!("        listen: \"0.0.0.0:{mesh_port}\",\n"));
    // The durable Raft store on the persistent volume (see the Dockerfile).
    out.push_str(&format!("        store_dir: \"{RAFT_STORE_DIR}\",\n"));
    out.push_str("    ),\n");
    out.push_str(")\n");
    out
}

/// A multi-stage Dockerfile building + running the cluster boatramp binary.
fn render_dockerfile(mesh_port: u16) -> String {
    format!(
        "# Generated by `boatramp cloudflare`.\n\
         FROM rust:1-slim AS build\n\
         WORKDIR /src\n\
         COPY . .\n\
         RUN cargo build --release -p boatramp --features cluster\n\
         \n\
         FROM debian:stable-slim\n\
         COPY --from=build /src/target/release/boatramp /usr/local/bin/boatramp\n\
         # The node-local cluster config is mounted/copied as boatramp.cfg.\n\
         COPY boatramp.cfg /etc/boatramp/boatramp.cfg\n\
         # Durable Raft store — back this with a persistent volume so a voter\n\
         # keeps its log/vote across restarts (CF Containers durable storage).\n\
         VOLUME [\"{RAFT_STORE_DIR}\"]\n\
         EXPOSE {mesh_port}\n\
         ENTRYPOINT [\"boatramp\", \"--config\", \"/etc/boatramp/boatramp.cfg\", \"serve\"]\n"
    )
}

/// The edge Worker as **Rust → Wasm** (`workers-rs`), not JavaScript — boatramp
/// is Wasm-first (handlers are Wasm components; the server runs wasmtime), so
/// the edge runs Wasm too. `worker-build` compiles this to wasm32 and emits a
/// ~10-line JS bootstrap shim (the only JS, auto-generated, not authored).
///
/// Crucially the edge **reuses `boatramp_types::route::resolve`** + the deploy
/// `Manifest`/`DeployConfig` — the *same* redirect/rewrite/clean-URL/
/// trailing-slash/dot-segment logic the Container runs — so the edge and the
/// origin never drift. `boatramp-types` is the small wasm-clean layer (no
/// Storage/KV/wasmtime), so the edge wasm stays lean. Template pinned to
/// `workers-rs`; the manifest-at-edge wiring + blob key scheme refined against
/// the live platform.
fn render_worker_rs() -> String {
    r#"//! boatramp edge Worker (Rust -> Wasm via workers-rs). Generated by
//! `boatramp cloudflare`. The edge applies the SAME routing as the Container by
//! calling `boatramp_types::route::resolve` over the site's deploy Manifest:
//! redirects/clean-URLs are answered at the edge, files stream from R2, and
//! anything dynamic (proxy, custom 404, handlers, ranges, access control) is
//! forwarded to a boatramp Container. Build with `worker-build --release`;
//! refined against the platform at beta.
//!
//! Depends on `boatramp-types` (not the full `boatramp-core`): the small,
//! wasm-clean routing/config/manifest layer, so the edge wasm stays lean and
//! shares one definition with the origin.

use std::collections::BTreeMap;

use boatramp_types::manifest::Manifest;
use boatramp_types::route::{resolve, Outcome};
use worker::*;

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Only GET/HEAD are served at the edge; everything else is the origin's.
    if !matches!(req.method(), Method::Get | Method::Head) {
        return forward(req, &env).await;
    }
    let url = req.url()?;
    let blobs = env.bucket("BLOBS")?;

    // Load the site's current Manifest (file set + DeployConfig) the Container
    // publishes to R2 for the edge. Absent -> let the origin handle it.
    let Some(bytes) = read_object(&blobs, "manifest/current.json").await? else {
        return forward(req, &env).await;
    };
    let manifest = match Manifest::from_bytes(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return forward(req, &env).await,
    };

    // The exact routing the Container runs — shared code, never re-implemented.
    match resolve(&manifest.config, &manifest.files, url.path()) {
        Outcome::Redirect { location, status } => {
            let mut headers = Headers::new();
            headers.set("location", &location)?;
            Ok(Response::empty()?.with_status(status).with_headers(headers))
        }
        Outcome::File { entry, .. } => match serve_blob(&blobs, &entry).await? {
            Some(response) => Ok(response),
            None => forward(req, &env).await,
        },
        // Proxy + custom-404 streaming need the full pipeline -> the Container.
        Outcome::Proxy { .. } | Outcome::NotFound { .. } => forward(req, &env).await,
    }
}

/// Serve a content-addressed blob (`<2hex>/<hash>`) from R2 with its type.
async fn serve_blob(
    blobs: &Bucket,
    entry: &boatramp_types::file::FileEntry,
) -> Result<Option<Response>> {
    let key = format!("{}/{}", &entry.hash[..2.min(entry.hash.len())], entry.hash);
    let Some(bytes) = read_object(blobs, &key).await? else {
        return Ok(None);
    };
    let mut headers = Headers::new();
    if let Some(content_type) = &entry.content_type {
        headers.set("content-type", content_type)?;
    }
    headers.set("cache-control", "public")?;
    Ok(Some(Response::from_bytes(bytes)?.with_headers(headers)))
}

async fn read_object(blobs: &Bucket, key: &str) -> Result<Option<Vec<u8>>> {
    match blobs.get(key).execute().await? {
        Some(object) => match object.body() {
            Some(body) => Ok(Some(body.bytes().await?)),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

/// Forward to a boatramp Container (the cluster runs the full serving pipeline).
async fn forward(req: Request, env: &Env) -> Result<Response> {
    let stub = env
        .durable_object("NODE")?
        .id_from_name("boatramp")?
        .get_stub()?;
    stub.fetch_with_request(req).await
}

/// Cache-invalidation coordinator (in Rust/Wasm): on a
/// control-plane write a Container POSTs the changed keys here; the DO fans them
/// out to every Container's `/api/cache/invalidate`. The fan-out registry +
/// transport are refined against the Containers API at beta.
#[durable_object]
pub struct CacheCoordinator {
    state: State,
    env: Env,
}

#[durable_object]
impl DurableObject for CacheCoordinator {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }
    async fn fetch(&mut self, mut req: Request) -> Result<Response> {
        // Body: {"keys":[...]} -> broadcast to the Container frontends (beta).
        let _ = (&self.state, &self.env, req.text().await?, BTreeMap::<String, ()>::new());
        Response::empty()
    }
}
"#
    .to_string()
}

/// The edge Worker crate's `Cargo.toml` (builds to a wasm32 `cdylib` via
/// `worker-build`). It depends on `boatramp-types` so the edge shares the
/// Container's routing/config code from the lean wasm-clean layer; pinned +
/// verified against the live platform.
fn render_worker_cargo() -> String {
    "# boatramp edge Worker - Rust -> Wasm (workers-rs). Built with `worker-build`.\n\
     [package]\n\
     name = \"boatramp-edge\"\n\
     version = \"0.1.0\"\n\
     edition = \"2021\"\n\
     \n\
     [lib]\n\
     crate-type = [\"cdylib\"]\n\
     \n\
     [dependencies]\n\
     worker = \"0.4\"\n\
     # Share the Container's routing/config: the edge runs the SAME logic via\n\
     # `boatramp_types::route::resolve`. `boatramp-types` is the small,\n\
     # wasm-clean layer (no Storage/KV/wasmtime), so the edge wasm stays lean.\n\
     # Point this at the deployed boatramp rev.\n\
     boatramp-types = { git = \"https://github.com/BoatRamp/BoatRamp\" }\n\
     # wasm32-unknown-unknown needs getrandom's browser backend (pulled in\n\
     # transitively by boatramp-types).\n\
     getrandom = { version = \"0.2\", features = [\"js\"] }\n\
     \n\
     [profile.release]\n\
     opt-level = \"s\"\n\
     lto = true\n"
        .to_string()
}

/// A reference README for the emitted artifacts (inspection only — the deploy is
/// native, over the CF REST API).
fn render_readme(args: &CloudflareArgs, nodes: &[Node]) -> String {
    let topo: String = nodes
        .iter()
        .map(|n| format!("- node {} — {} ({:?})", n.id, n.region, n.role))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# boatramp on Cloudflare (reference artifacts)\n\n\
         boatramp's cluster mode on CF Containers + an edge Worker\n\
         (docs/CLOUDFLARE.md). These files are for **inspection**; the deploy is\n\
         native (`boatramp cloudflare`), driving the Cloudflare REST API directly\n\
         — no wrangler, nothing here to run by hand.\n\n\
         ## Topology\n\n{topo}\n\n\
         Voting quorum in `{primary}`; other regions are read-only learners.\n\n\
         ## Image\n\n\
         The container image `{image}` (see `Dockerfile`) runs the cluster \
         binary. `boatramp cloudflare` references it and wires R2/D1 + the edge \
         Worker + the container application over the API.\n",
        topo = topo,
        primary = args.primary,
        image = args.image,
    )
}

/// Deploy boatramp's cluster mode to Cloudflare — natively over the CF REST API
/// (no wrangler, nothing generated for the operator to run). `--dry-run` previews
/// the plan; `--emit-artifacts <dir>` writes the Dockerfile/Worker/config files
/// for inspection instead of deploying.
pub async fn run(args: CloudflareArgs, _config: &ProjectConfig) -> Result<()> {
    if let Some(dir) = args.emit_artifacts.clone() {
        return emit_artifacts(&args, &dir);
    }
    deploy_native(&args).await
}

/// Write the deployment artifacts to `dir` for inspection (a debugging escape
/// hatch — the deploy itself is native). No `wrangler.jsonc`: wrangler is gone.
fn emit_artifacts(args: &CloudflareArgs, dir: &std::path::Path) -> Result<()> {
    let nodes = plan_topology(&args.regions, &args.primary, args.quorum, args.mesh_port)?;
    std::fs::create_dir_all(dir.join("worker/src"))?;
    std::fs::create_dir_all(dir.join("nodes"))?;
    std::fs::write(dir.join("Dockerfile"), render_dockerfile(args.mesh_port))?;
    std::fs::write(dir.join("worker/src/lib.rs"), render_worker_rs())?;
    std::fs::write(dir.join("worker/Cargo.toml"), render_worker_cargo())?;
    std::fs::write(dir.join("README.md"), render_readme(args, &nodes))?;
    for n in &nodes {
        std::fs::write(
            dir.join("nodes").join(format!("{}.cfg", n.id)),
            render_node_config(&nodes, n.id, args.mesh_port),
        )?;
    }
    println!(
        "Wrote deployment artifacts (for inspection) → {}",
        dir.display()
    );
    println!("Deploy natively with `boatramp cloudflare` (no --emit-artifacts).");
    Ok(())
}

/// The native-deploy defaults. `standard` (0.5 vCPU, 4 GiB, 8 GB disk) is the
/// smallest tier whose disk holds the batteries-included image (the `lite`/`basic`
/// tiers' ~2 GB disk is too small for the unpacked image and fails the pull); a
/// slimmer image could drop to a smaller tier — a follow-up.
const NATIVE_INSTANCE_TYPE: &str = "standard";
const NATIVE_COMPAT_DATE: &str = "2025-01-01";
const NATIVE_MIGRATION_TAG: &str = "v1";
/// The HTTP port boatramp serves inside the container (the edge Worker's
/// container DO proxies to it).
const CONTAINER_HTTP_PORT: u16 = 8080;

/// The edge Worker, uploaded as one self-contained ES module. It defines the two
/// Durable Object classes the deploy needs — `BoatrampNode` (the container DO:
/// starts the boatramp container on first request and proxies to its HTTP port)
/// and `CacheCoordinator` (the cache-invalidation fan-out; minimal for now) — and
/// a default handler that forwards every request to the container. Only the
/// built-in `cloudflare:workers` module is imported, so there is nothing to
/// bundle. The full Rust→Wasm edge Worker (R2 static serving + route parity, from
/// `render_worker_rs`) layers on top later; this is enough to run the cluster.
fn edge_worker_module() -> String {
    format!(
        r#"import {{ DurableObject }} from "cloudflare:workers";

// The container node: a Durable Object bound to the container application. On the
// first request it starts the container (if not running) and proxies to boatramp's
// HTTP port; subsequent requests reuse the running instance.
export class BoatrampNode extends DurableObject {{
  async fetch(request) {{
    try {{
      const c = this.ctx.container;
      if (!c) return new Response("no container binding on this DO", {{ status: 500 }});
      // The container port speaks plain HTTP (TLS terminates at the edge); rewrite
      // the request URL scheme so the proxied fetch doesn't try HTTPS.
      const url = new URL(request.url);
      url.protocol = "http:";
      const req = new Request(url, request);
      // Cold start: provisioning (image pull) + boot + boatramp's own init take
      // up to ~2 min, and a scale-to-zero container may be stopped between
      // requests. So (re)start whenever it isn't running and retry the proxied
      // fetch through the whole window — the transient errors here are
      // "not running"/"not listening"/connection-refused, all expected while it
      // comes up, so retry on any failure rather than an error-string allowlist.
      let lastErr;
      for (let i = 0; i < 120; i++) {{
        if (!c.running) {{
          try {{
            c.start({{ enableInternet: true }});
          }} catch (e) {{
            // Already starting (a concurrent request won the race) — fine.
          }}
        }}
        try {{
          return await c.getTcpPort({port}).fetch(req.clone());
        }} catch (e) {{
          lastErr = e;
          await new Promise((r) => setTimeout(r, 1000));
        }}
      }}
      return new Response("container did not become ready: " + lastErr, {{ status: 503 }});
    }} catch (e) {{
      return new Response("BoatrampNode: " + (e && e.stack || e), {{ status: 502 }});
    }}
  }}
}}

// The cache-invalidation coordinator (edge → container fan-out). Minimal for now:
// accepts POST /invalidate and returns ok; the fan-out is a follow-up.
export class CacheCoordinator extends DurableObject {{
  async fetch(_request) {{
    return new Response("ok");
  }}
}}

// Forward every request to the single container node (singleton instance).
export default {{
  async fetch(request, env) {{
    try {{
      const id = env.NODE.idFromName("boatramp");
      return await env.NODE.get(id).fetch(request);
    }} catch (e) {{
      return new Response("edge: " + (e && e.stack || e), {{ status: 502 }});
    }}
  }}
}};
"#,
        port = CONTAINER_HTTP_PORT,
    )
}

/// Deploy natively over the Cloudflare REST API — no wrangler, no generated
/// files. `--dry-run` previews the plan; otherwise it ensures the resources,
/// uploads the edge Worker (creating the DO namespaces), then creates/rolls out
/// the container application referencing the boatramp image.
async fn deploy_native(args: &CloudflareArgs) -> Result<()> {
    use boatramp_cloudflare::api::{plan_application, ApplicationAction, CfApi};
    use boatramp_cloudflare::deploy;

    let nodes = plan_topology(&args.regions, &args.primary, args.quorum, args.mesh_port)?;
    // The single instance founds the cluster (dynamic-join: node 1 = founder).
    // Multi-instance founder/join coordination across homogeneous Container
    // instances is a live follow-up.
    if nodes.len() > 1 {
        return Err(Error::NativeMultiInstance(nodes.len()));
    }
    let instances = nodes.len() as u32;

    if args.dry_run {
        // The plan redacts the secrets; the real deploy fills them from the
        // resolved root key + provisioned R2/KV credentials below.
        let plan_env = vec![
            (
                "BOATRAMP_AUTH_ROOT_PRIVATE_KEY".to_string(),
                "<auth-root-key>".to_string(),
            ),
            ("BOATRAMP_BLOBS".to_string(), "s3".to_string()),
            ("BOATRAMP_S3_BUCKET".to_string(), args.r2_bucket.clone()),
            (
                "BOATRAMP_S3_ENDPOINT".to_string(),
                "https://<account>.r2.cloudflarestorage.com".to_string(),
            ),
            ("BOATRAMP_S3_REGION".to_string(), "auto".to_string()),
            ("BOATRAMP_S3_PATH_STYLE".to_string(), "true".to_string()),
            (
                "AWS_ACCESS_KEY_ID".to_string(),
                "<r2-access-key>".to_string(),
            ),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "<r2-secret>".to_string(),
            ),
            ("BOATRAMP_KV_S3".to_string(), "true".to_string()),
        ];
        return print_native_plan(args, instances, plan_env);
    }

    // Resolve the control-plane root key. boatramp refuses to bind a public
    // listener with auth disabled (fail-closed), and the container must bind
    // 0.0.0.0 so the edge DO can reach it — so auth must be on. Prefer an
    // operator-provided key (stable across redeploys); otherwise generate one and
    // print it once so the operator can mint tokens + redeploy with the same root.
    let auth_root_key = match args.auth_root_private_key.clone() {
        Some(key) => key,
        None => {
            let signer =
                boatramp_core::cose::LocalSigner::generate(boatramp_core::cose::TokenAlg::Es256);
            let key = signer.private_hex();
            println!(
                "cloudflare: generated a control-plane root key — SAVE IT (mint tokens with it, \
                 and set it to redeploy with the same root):\n  \
                 BOATRAMP_AUTH_ROOT_PRIVATE_KEY={key}"
            );
            key
        }
    };
    let api = CfApi::from_env()?;
    // Fail loud early if the pinned (non-public) container API drifted or the
    // token lacks the scope, before mutating anything.
    api.probe().await?;
    println!("cloudflare: account reachable; container API responsive");

    // 1. Resources (idempotent): R2 bucket (durable blobs, via the S3 API), D1
    //    (the handler `sql` binding), and a Workers KV namespace (the durable
    //    control-plane metadata store the container reads/writes over REST).
    api.ensure_r2_bucket(&args.r2_bucket).await?;
    let d1 = api.ensure_d1_database(&args.d1).await?;
    let r2 = api.r2_s3_credentials().await?;
    println!(
        "cloudflare: ensured R2 bucket {:?} + D1 database {:?} ({})",
        args.r2_bucket, d1.name, d1.uuid
    );

    // Deliver the container's runtime config as environment. The container runs on
    // a private network reachable only through the edge Worker, so its config env
    // is not internet-exposed; hardening the secrets to Cloudflare's Secrets Store
    // is a follow-up. All durable state lives in **R2** — blobs via the S3 API, and
    // the control-plane metadata as a SlateDB store on the same bucket (`--kv-s3`).
    // A scale-to-zero instance keeps its state across stops; the image's `/data`
    // now holds only ephemeral caches (the wasmtime compile cache). The container
    // holds only the derived R2 S3 credentials (a one-way hash of the token), not
    // the Cloudflare token itself.
    let container_env = vec![
        (
            "BOATRAMP_AUTH_ROOT_PRIVATE_KEY".to_string(),
            auth_root_key.clone(),
        ),
        // Blobs → R2 over the S3-compatible API.
        ("BOATRAMP_BLOBS".to_string(), "s3".to_string()),
        ("BOATRAMP_S3_BUCKET".to_string(), args.r2_bucket.clone()),
        ("BOATRAMP_S3_ENDPOINT".to_string(), r2.endpoint.clone()),
        ("BOATRAMP_S3_REGION".to_string(), "auto".to_string()),
        ("BOATRAMP_S3_PATH_STYLE".to_string(), "true".to_string()),
        ("AWS_ACCESS_KEY_ID".to_string(), r2.access_key_id.clone()),
        ("AWS_SECRET_ACCESS_KEY".to_string(), r2.secret_access_key),
        // Control-plane metadata → SlateDB on the same R2 bucket (durable, strongly
        // consistent, single-writer — the DO gives us one instance at a time).
        ("BOATRAMP_KV_S3".to_string(), "true".to_string()),
    ];

    // 2. Upload the edge Worker — the DO migration creates the BoatrampNode +
    //    CacheCoordinator namespaces the container app binds to. Only migrate on
    //    the *first* upload: on a redeploy the namespaces already exist, and a
    //    repeated first-upload migration (`old_tag: None`) would conflict, so we
    //    re-upload just the code.
    let bindings = deploy::worker_bindings(&args.r2_bucket, &d1.uuid, &args.primary);
    let mut metadata = deploy::worker_metadata(bindings, NATIVE_MIGRATION_TAG, NATIVE_COMPAT_DATE);
    let already_migrated = api
        .find_do_namespace(deploy::WORKER_NAME, deploy::NODE_CLASS)
        .await?
        .is_some();
    if already_migrated {
        metadata.migrations = None;
    }
    let module = boatramp_cloudflare::api::workers::WorkerModule::js(
        metadata.main_module.clone(),
        edge_worker_module().into_bytes(),
    );
    api.upload_worker(deploy::WORKER_NAME, &metadata, vec![module])
        .await?;
    println!("cloudflare: uploaded edge Worker {:?}", deploy::WORKER_NAME);

    // 3. Resolve the node DO namespace + reconcile the container application.
    let ns_id = api
        .find_do_namespace(deploy::WORKER_NAME, deploy::NODE_CLASS)
        .await?
        .ok_or_else(|| {
            Error::Native(format!(
                "the {} DO namespace was not found after uploading the Worker",
                deploy::NODE_CLASS
            ))
        })?;
    let request = deploy::application_request(
        &args.image,
        instances,
        NATIVE_INSTANCE_TYPE,
        container_env,
        &ns_id,
    );
    let existing = api.list_applications().await?;
    // A DO-backed, scale-to-zero app has no persistent instances to roll across:
    // create/modify sets the active version in the app config, and the next
    // `container.start()` (driven by the DO on first request) provisions an
    // instance from it — so no separate rollout call is needed.
    let app = match plan_application(&existing, deploy::APP_NAME) {
        ApplicationAction::Create => {
            println!(
                "cloudflare: creating container application {:?}",
                deploy::APP_NAME
            );
            api.create_application(&request).await?
        }
        ApplicationAction::Modify(id) => {
            println!("cloudflare: updating container application {id}");
            // Modify uses a distinct body (`configuration`, no create-only fields).
            let modify = deploy::modify_request(&request);
            api.modify_application(&id, &modify).await?
        }
    };
    println!(
        "cloudflare: container application {:?} at version {} ({} tier); an instance provisions \
         on the first request",
        deploy::APP_NAME,
        app.version.map(|v| v.to_string()).unwrap_or_default(),
        NATIVE_INSTANCE_TYPE,
    );
    println!("cloudflare: native deploy complete — boatramp running on CF Containers");
    Ok(())
}

/// Build and print the native-deploy plan (dry-run): the resources to ensure, the
/// image, the Worker metadata (bindings + DO migration), and the container
/// application request — all from the pure planners, mutating nothing.
fn print_native_plan(
    args: &CloudflareArgs,
    instances: u32,
    env: Vec<(String, String)>,
) -> Result<()> {
    use boatramp_cloudflare::deploy;
    let bindings = deploy::worker_bindings(&args.r2_bucket, "<d1-id>", &args.primary);
    let metadata = deploy::worker_metadata(bindings, NATIVE_MIGRATION_TAG, NATIVE_COMPAT_DATE);
    let app = deploy::application_request(
        &args.image,
        instances,
        NATIVE_INSTANCE_TYPE,
        env,
        "<node-do-namespace>",
    );
    let meta_json =
        serde_json::to_string_pretty(&metadata).map_err(|e| Error::Native(e.to_string()))?;
    let app_json = serde_json::to_string_pretty(&app).map_err(|e| Error::Native(e.to_string()))?;
    println!("Native Cloudflare deploy plan (dry-run — nothing is mutated):\n");
    println!("  1. ensure R2 bucket    {:?}", args.r2_bucket);
    println!("  2. ensure D1 database  {:?}", args.d1);
    println!("  3. use container image {:?}", args.image);
    println!(
        "  4. upload edge Worker  {:?}, metadata:",
        deploy::WORKER_NAME
    );
    for line in meta_json.lines() {
        println!("       {line}");
    }
    println!("  5. create/roll out container application:");
    for line in app_json.lines() {
        println!("       {line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regions() -> Vec<String> {
        vec!["wnam".into(), "enam".into(), "weur".into()]
    }

    #[test]
    fn topology_is_quorum_in_primary_plus_learners_elsewhere() {
        let nodes = plan_topology(&regions(), "wnam", 3, 7000).unwrap();
        // 3 voters in wnam + 1 learner in each of enam, weur = 5 nodes.
        assert_eq!(nodes.len(), 5);
        let voters: Vec<&Node> = nodes.iter().filter(|n| n.role == Role::Voter).collect();
        assert_eq!(voters.len(), 3);
        assert!(voters.iter().all(|n| n.region == "wnam"));
        let learners: Vec<&Node> = nodes.iter().filter(|n| n.role == Role::Learner).collect();
        assert_eq!(learners.len(), 2);
        // Node 1 (the bootstrap node) is a primary-region voter.
        assert_eq!(nodes[0].id, 1);
        assert_eq!(nodes[0].role, Role::Voter);
    }

    #[test]
    fn primary_must_be_a_listed_region() {
        assert!(plan_topology(&regions(), "apac", 3, 7000).is_err());
    }

    fn native_args() -> CloudflareArgs {
        CloudflareArgs {
            regions: vec!["enam".into()],
            primary: "enam".into(),
            quorum: 1,
            image: "registry.cloudflare.com/acct/boatramp:v1".into(),
            domains: vec![],
            r2_bucket: "boatramp-blobs".into(),
            d1: "boatramp-sql".into(),
            mesh_port: 7000,
            auth_root_private_key: None,
            dry_run: true,
            emit_artifacts: None,
        }
    }

    #[test]
    fn edge_worker_module_is_self_contained_and_defines_the_do_classes() {
        // The uploaded edge Worker imports only the built-in module (nothing to
        // bundle) and defines the two DO classes the container app + migration need.
        let js = edge_worker_module();
        assert!(js.contains("import { DurableObject } from \"cloudflare:workers\""));
        assert!(js.contains("export class BoatrampNode extends DurableObject"));
        assert!(js.contains("export class CacheCoordinator extends DurableObject"));
        assert!(js.contains("this.ctx.container")); // starts + proxies to the container
        assert!(js.contains(&format!("getTcpPort({CONTAINER_HTTP_PORT})")));
        assert!(js.contains("env.NODE")); // forwards to the container node DO
    }

    #[test]
    fn native_dry_run_builds_the_plan_without_io() {
        // The dry-run planner is pure — it must not touch the network or write files.
        let args = native_args();
        assert!(
            print_native_plan(&args, 1, vec![("BOATRAMP_CLUSTER_INIT".into(), "1".into())]).is_ok()
        );
    }

    #[test]
    fn native_refuses_a_multi_instance_footprint() {
        // A multi-node topology isn't supported natively yet (founder/join
        // coordination is a live follow-up) — it must fail loud, not half-deploy.
        let nodes = plan_topology(&regions(), "wnam", 3, 7000).unwrap();
        assert!(nodes.len() > 1);
        assert!(matches!(
            Error::NativeMultiInstance(nodes.len()),
            Error::NativeMultiInstance(5)
        ));
    }

    #[test]
    fn node_config_is_uniform_and_env_designates_founder_vs_joiner() {
        let nodes = plan_topology(&regions(), "wnam", 3, 7000).unwrap();
        let cfg1 = render_node_config(&nodes, 1, 7000);
        // The founder is designated by env, not per-node config; no legacy RON
        // fields (check the `key:` syntax so prose in comments doesn't count).
        assert!(cfg1.contains("BOATRAMP_CLUSTER_INIT=1"));
        assert!(!cfg1.contains("node_id:"));
        assert!(!cfg1.contains("bootstrap:"));
        assert!(!cfg1.contains("voters:"));
        assert!(!cfg1.contains("peers:"));
        // The durable Raft store points at the persistent volume.
        assert!(cfg1.contains(&format!("store_dir: \"{RAFT_STORE_DIR}\"")));
        // A non-founder is a joiner (env ticket), and its config body is identical.
        let cfg4 = render_node_config(&nodes, 4, 7000);
        assert!(cfg4.contains("BOATRAMP_CLUSTER_JOIN"));
        let body = |s: &str| {
            s.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(body(&cfg1), body(&cfg4), "the config body is uniform");
    }

    #[test]
    fn node_config_parses_as_a_server_config() {
        // The generated RON must round-trip through the same loader `serve` uses.
        let nodes = plan_topology(&regions(), "wnam", 3, 7000).unwrap();
        let parsed = crate::config::ServerConfig::parse(&render_node_config(&nodes, 1, 7000))
            .expect("generated node config is valid boatramp.cfg RON");
        let cluster = parsed.cluster.expect("node config has a cluster section");
        assert!(cluster.seeds.is_empty()); // founding via env, not seeds
        assert_eq!(
            cluster.store_dir.as_deref(),
            Some(std::path::Path::new(RAFT_STORE_DIR))
        );
    }

    #[test]
    fn dockerfile_declares_the_durable_raft_volume() {
        let d = render_dockerfile(7000);
        assert!(
            d.contains(&format!("VOLUME [\"{RAFT_STORE_DIR}\"]")),
            "voters need a persistent volume for the Raft store"
        );
        assert!(d.contains("--features cluster"));
    }

    #[test]
    fn edge_worker_is_rust_wasm_not_js() {
        let lib = render_worker_rs();
        // workers-rs Rust, not JavaScript.
        assert!(lib.contains("use worker::*;"));
        assert!(lib.contains("#[event(fetch)]"));
        assert!(lib.contains("env.bucket(\"BLOBS\")")); // static-from-R2
        assert!(lib.contains("#[durable_object]")); // cache coordinator DO
        assert!(!lib.contains("export default")); // no JS handler
        let cargo = render_worker_cargo();
        assert!(cargo.contains("crate-type = [\"cdylib\"]")); // wasm32 cdylib
        assert!(cargo.contains("worker ="));
    }

    #[test]
    fn edge_worker_reuses_boatramp_types_routing() {
        let lib = render_worker_rs();
        // The edge runs the SAME routing as the Container, not a reimplementation,
        // via the lean wasm-clean `boatramp-types` (not full `boatramp-core`).
        assert!(lib.contains("use boatramp_types::route::{resolve, Outcome};"));
        assert!(lib.contains("use boatramp_types::manifest::Manifest;"));
        assert!(!lib.contains("boatramp_core"));
        assert!(lib.contains("resolve(&manifest.config, &manifest.files, url.path())"));
        // All four routing outcomes are handled.
        assert!(lib.contains("Outcome::Redirect"));
        assert!(lib.contains("Outcome::File"));
        assert!(lib.contains("Outcome::Proxy"));
        assert!(lib.contains("Outcome::NotFound"));
        // The crate depends on boatramp-types (+ the wasm getrandom backend).
        let cargo = render_worker_cargo();
        assert!(cargo.contains("boatramp-types = { git"));
        assert!(!cargo.contains("boatramp-core = { git"));
        assert!(cargo.contains("getrandom = { version = \"0.2\", features = [\"js\"] }"));
    }
}
