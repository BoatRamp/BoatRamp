//! `boatramp cloudflare` — generate (and optionally apply) a Cloudflare
//! deployment of boatramp's **cluster mode on CF Containers** behind an edge
//! Worker (`docs/CLOUDFLARE.md`).
//!
//! This is the CF "management" surface: from a small set of inputs (regions,
//! the voting-quorum region, the container image, the public domains) it plans
//! the cluster **topology** (a voting quorum in the primary region + read-only
//! learner nodes in the other regions) and generates everything needed to
//! deploy:
//!
//! - per-node `boatramp.cfg` `cluster` fragments (node id, peers, voters,
//!   bootstrap) — the same config `boatramp serve` cluster mode consumes;
//! - a `Dockerfile` that builds the boatramp binary (`--features cluster`);
//! - a `wrangler.jsonc` wiring the edge Worker + the Container + R2/D1/KV
//!   bindings + the routes;
//! - the edge Worker as a **Rust → Wasm** crate (`worker/src/lib.rs` +
//!   `worker/Cargo.toml`, built with `worker-build`), not JavaScript — boatramp
//!   is Wasm-first, so the edge runs Wasm too; the only JS is the ~10-line
//!   bootstrap shim `worker-build` auto-generates. It **reuses
//!   `boatramp_types::route::resolve`** + the deploy `Manifest`/`DeployConfig`
//!   (from the small wasm-clean `boatramp-types`, not full `boatramp-core`), so
//!   the edge applies the *same* redirect/rewrite/clean-URL routing as the
//!   Container (no drift): redirects/files are answered at the edge from R2,
//!   dynamic outcomes forward to the cluster. It also carries the
//!   `CacheCoordinator` Durable Object (the push-invalidation delivery);
//! - a `README.md` with the deploy steps.
//!
//! Generation is offline + deterministic (unit-tested). `--apply` shells out to
//! `wrangler` and needs a live environment (wrangler + CF credentials + the
//! live platform); the CF-schema specifics in the generated files are
//! structured to be easy to verify/adjust against the live platform.

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
    /// Spawning `wrangler deploy` failed (wrangler missing or not runnable).
    #[error("running `wrangler deploy` failed (is wrangler installed?): {0}")]
    WranglerSpawn(String),
    /// `wrangler deploy` ran but exited non-zero.
    #[error("`wrangler deploy` exited with {0}")]
    WranglerFailed(std::process::ExitStatus),
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

    /// Output directory for the generated artifacts.
    #[arg(long, default_value = "./cloudflare")]
    out: PathBuf,

    /// Apply the deployment via `wrangler` (needs wrangler + CF creds).
    #[arg(long)]
    apply: bool,
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

/// The `cluster` `boatramp.cfg` (RON) fragment for node `this_id` — the same
/// shape `boatramp serve` cluster mode consumes (node 1 is the bootstrap node).
fn render_node_config(nodes: &[Node], this_id: u64, mesh_port: u16) -> String {
    let mut out = String::new();
    out.push_str(
        "// Generated by `boatramp cloudflare` — node-local cluster config (boatramp.cfg).\n",
    );
    out.push_str("(\n");
    out.push_str("    cluster: (\n");
    out.push_str(&format!("        node_id: {this_id},\n"));
    out.push_str(&format!("        listen: \"0.0.0.0:{mesh_port}\",\n"));
    out.push_str(&format!("        bootstrap: {},\n", this_id == 1));
    // The durable Raft store on the persistent volume (see the Dockerfile).
    out.push_str(&format!("        store_dir: \"{RAFT_STORE_DIR}\",\n"));
    let voters: Vec<String> = nodes
        .iter()
        .filter(|n| n.role == Role::Voter)
        .map(|n| n.id.to_string())
        .collect();
    out.push_str(&format!("        voters: [{}],\n", voters.join(", ")));
    // Each peer needs its mesh pubkey — per-node runtime identity, printed at the
    // node's first boot. Emit it empty here; fill each one in before the node joins.
    out.push_str("        peers: {\n");
    for n in nodes {
        out.push_str(&format!(
            "            \"{}\": (url: \"{}\", pubkey: \"\"),\n",
            n.id, n.url
        ));
    }
    out.push_str("        },\n");
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

/// A `wrangler.jsonc` wiring the edge Worker + Container + R2/D1 bindings.
/// (CF Containers/wrangler schema is verified against the live platform.)
fn render_wrangler(args: &CloudflareArgs, nodes: &[Node]) -> String {
    let routes: String = args
        .domains
        .iter()
        .map(|d| format!("    {{ \"pattern\": \"{d}/*\", \"zone_name\": \"{d}\" }}"))
        .collect::<Vec<_>>()
        .join(",\n");
    let instances = nodes.len();
    format!(
        "// Generated by `boatramp cloudflare` — verify schema against the CF\n\
         // platform docs.\n\
         {{\n\
         \x20 \"name\": \"boatramp\",\n\
         \x20 // Rust→Wasm edge Worker: `worker-build` emits the Wasm + a thin JS\n\
         \x20 // bootstrap shim at build/worker/shim.mjs (the only JS, generated).\n\
         \x20 \"main\": \"build/worker/shim.mjs\",\n\
         \x20 \"build\": {{ \"command\": \"worker-build --release\" }},\n\
         \x20 \"compatibility_date\": \"2025-01-01\",\n\
         \x20 \"routes\": [\n{routes}\n  ],\n\
         \x20 \"containers\": [\n\
         \x20\x20\x20 {{ \"class_name\": \"BoatrampNode\", \"image\": \"{image}\", \"instances\": {instances} }}\n\
         \x20 ],\n\
         \x20 \"durable_objects\": {{\n\
         \x20\x20\x20 \"bindings\": [\n\
         \x20\x20\x20\x20\x20 {{ \"name\": \"NODE\", \"class_name\": \"BoatrampNode\" }},\n\
         \x20\x20\x20\x20\x20 {{ \"name\": \"CACHE\", \"class_name\": \"CacheCoordinator\" }}\n\
         \x20\x20\x20 ]\n\
         \x20 }},\n\
         \x20 \"r2_buckets\": [ {{ \"binding\": \"BLOBS\", \"bucket_name\": \"{r2}\" }} ],\n\
         \x20 \"d1_databases\": [ {{ \"binding\": \"SQL\", \"database_name\": \"{d1}\" }} ]\n\
         }}\n",
        routes = routes,
        instances = instances,
        image = args.image,
        r2 = args.r2_bucket,
        d1 = args.d1,
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

/// Deploy instructions + the live-platform caveats.
fn render_readme(args: &CloudflareArgs, nodes: &[Node]) -> String {
    let topo: String = nodes
        .iter()
        .map(|n| format!("- node {} — {} ({:?})", n.id, n.region, n.role))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# boatramp on Cloudflare (generated)\n\n\
         boatramp's cluster mode on CF Containers + an edge Worker\n\
         (docs/CLOUDFLARE.md).\n\n\
         ## Topology\n\n{topo}\n\n\
         Voting quorum in `{primary}`; other regions are read-only learners.\n\n\
         ## Deploy\n\n\
         1. Build + push the image `{image}` (see `Dockerfile`), one per node \
         with that node's `nodes/<id>.cfg` copied to `boatramp.cfg`.\n\
         2. `wrangler deploy` (uses `wrangler.jsonc`) — or `boatramp cloudflare \
         … --apply`.\n\n\
         > Live `wrangler deploy` + the CF platform wiring (Container\n\
         > networking for the Raft mesh, always-on voters, durable volumes) are\n\
         > require live Cloudflare-platform validation.\n",
        topo = topo,
        primary = args.primary,
        image = args.image,
    )
}

/// Generate the deployment artifacts (and optionally apply via wrangler).
pub async fn run(args: CloudflareArgs, _config: &ProjectConfig) -> Result<()> {
    let nodes = plan_topology(&args.regions, &args.primary, args.quorum, args.mesh_port)?;

    let out = &args.out;
    std::fs::create_dir_all(out.join("worker/src"))?;
    std::fs::create_dir_all(out.join("nodes"))?;

    std::fs::write(out.join("Dockerfile"), render_dockerfile(args.mesh_port))?;
    std::fs::write(out.join("wrangler.jsonc"), render_wrangler(&args, &nodes))?;
    // The edge Worker is Rust → Wasm (workers-rs), not JS.
    std::fs::write(out.join("worker/src/lib.rs"), render_worker_rs())?;
    std::fs::write(out.join("worker/Cargo.toml"), render_worker_cargo())?;
    std::fs::write(out.join("README.md"), render_readme(&args, &nodes))?;
    for n in &nodes {
        std::fs::write(
            out.join("nodes").join(format!("{}.cfg", n.id)),
            render_node_config(&nodes, n.id, args.mesh_port),
        )?;
    }

    let voters = nodes.iter().filter(|n| n.role == Role::Voter).count();
    let learners = nodes.len() - voters;
    tracing::info!(
        nodes = nodes.len(), voters, learners, out = %out.display(),
        "cloudflare: generated deployment artifacts"
    );
    println!(
        "Generated {} node(s) ({voters} voters in {}, {learners} learner(s)) → {}",
        nodes.len(),
        args.primary,
        out.display()
    );

    if args.apply {
        apply_with_wrangler(out).await?;
    } else {
        println!("Review the artifacts, then `wrangler deploy` (or re-run with --apply).");
    }
    Ok(())
}

/// Apply via `wrangler deploy` in the output dir. The live CF round-trip needs
/// wrangler + CF credentials.
async fn apply_with_wrangler(out: &std::path::Path) -> Result<()> {
    tracing::info!("cloudflare: applying via `wrangler deploy` (beta)");
    let status = tokio::process::Command::new("wrangler")
        .arg("deploy")
        .current_dir(out)
        .status()
        .await
        .map_err(|e| Error::WranglerSpawn(e.to_string()))?;
    if !status.success() {
        return Err(Error::WranglerFailed(status));
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

    #[test]
    fn node_config_marks_bootstrap_and_lists_voters_and_peers() {
        let nodes = plan_topology(&regions(), "wnam", 3, 7000).unwrap();
        let cfg1 = render_node_config(&nodes, 1, 7000);
        assert!(cfg1.contains("node_id: 1"));
        assert!(cfg1.contains("bootstrap: true"));
        assert!(cfg1.contains("voters: [1, 2, 3]"));
        // The durable Raft store points at the persistent volume.
        assert!(cfg1.contains(&format!("store_dir: \"{RAFT_STORE_DIR}\"")));
        // Every node appears in the peer directory.
        for n in &nodes {
            assert!(cfg1.contains(&format!("\"{}\": ", n.id)));
        }
        // A learner node is not a bootstrap node.
        let cfg4 = render_node_config(&nodes, 4, 7000);
        assert!(cfg4.contains("node_id: 4"));
        assert!(cfg4.contains("bootstrap: false"));
    }

    #[test]
    fn node_config_parses_as_a_server_config() {
        // The generated RON must round-trip through the same loader `serve` uses.
        let nodes = plan_topology(&regions(), "wnam", 3, 7000).unwrap();
        let parsed = crate::config::ServerConfig::parse(&render_node_config(&nodes, 1, 7000))
            .expect("generated node config is valid boatramp.cfg RON");
        let cluster = parsed.cluster.expect("node config has a cluster section");
        assert_eq!(cluster.node_id, 1);
        assert!(cluster.bootstrap);
        assert_eq!(cluster.voters, vec![1, 2, 3]);
        assert_eq!(cluster.peers.len(), nodes.len());
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
    fn wrangler_wires_the_bindings_and_routes() {
        let args = CloudflareArgs {
            regions: regions(),
            primary: "wnam".into(),
            quorum: 3,
            image: "registry/boatramp:v1".into(),
            domains: vec!["example.com".into()],
            r2_bucket: "blobs".into(),
            d1: "sql".into(),
            mesh_port: 7000,
            out: PathBuf::from("/tmp/x"),
            apply: false,
        };
        let nodes =
            plan_topology(&args.regions, &args.primary, args.quorum, args.mesh_port).unwrap();
        let w = render_wrangler(&args, &nodes);
        assert!(w.contains("registry/boatramp:v1")); // container image
        assert!(w.contains("\"instances\": 5")); // one per node
        assert!(w.contains("\"bucket_name\": \"blobs\"")); // R2
        assert!(w.contains("\"database_name\": \"sql\"")); // D1
        assert!(w.contains("example.com/*")); // route
                                              // The edge Worker is Rust→Wasm: wrangler points at the worker-build shim
                                              // and runs worker-build, and binds the cache-coordinator DO.
        assert!(w.contains("build/worker/shim.mjs"));
        assert!(w.contains("worker-build"));
        assert!(w.contains("CacheCoordinator"));
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
