//! The `serve` subcommand: select backends and run the server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use boatramp_core::cache_coherence::Changelog;
use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::{CachedKv, KvStore, MemoryKv};
use boatramp_core::Storage;
use boatramp_storage::FsStorage;
use clap::ValueEnum;

use crate::config::ServerConfig;

/// A failure running `boatramp serve`: selecting/initialising a backend, wiring
/// auth / OIDC / TLS, or the HTTP server itself exiting with an error. Most of
/// `serve` is behind a build feature (`tls` / `acme-dns` / `s3` / `slatedb` /
/// `cluster` / `handlers` / `http3` / `oidc` / `cloudflare-kv`), so each variant
/// is gated to match the `?` site / `bail!` it replaced — a variant is present
/// only when the code that produces it is compiled.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ---- "rebuild with --features X" guards (the selected backend/mode is
    // not compiled into this binary) ----------------------------------------
    /// `[cluster]` config present but the binary lacks cluster support.
    #[cfg(not(feature = "cluster"))]
    #[error(
        "[cluster] config is present but this build has no cluster support; \
         rebuild with `--features cluster`"
    )]
    NoClusterSupport,
    /// Refusing to bind a non-loopback address with control-plane auth disabled.
    /// Set auth keys, bind a loopback address, or — for local dev —
    /// relax `allow_unauthenticated_public_bind` in `[security]` (the `dev` profile).
    #[error(
        "refusing to bind {addr} with control-plane auth disabled: an \
         unauthenticated control plane must not be exposed to a non-loopback \
         address. Configure auth keys, bind a loopback address, or set the `dev` \
         security profile / `allow_unauthenticated_public_bind` for local dev"
    )]
    UnauthenticatedPublicBind { addr: std::net::SocketAddr },
    /// A `--tls custom`/`acme` mode selected but the binary lacks TLS support.
    #[cfg(not(feature = "tls"))]
    #[error("this build has no TLS support; rebuild with `--features tls`")]
    NoTlsSupport,
    /// `--tls acme-dns` selected but the binary lacks ACME DNS-01 support.
    #[cfg(not(feature = "acme-dns"))]
    #[error("this build has no ACME DNS-01 support; rebuild with `--features acme-dns`")]
    NoAcmeDnsSupport,
    /// `--blobs s3` selected but the binary lacks S3 support.
    #[cfg(not(feature = "s3"))]
    #[error("this build has no S3 support; rebuild with `--features s3`")]
    NoS3Support,
    /// `--kv slatedb` selected but the binary lacks SlateDB support.
    #[cfg(not(feature = "slatedb"))]
    #[error("this build has no slatedb support; rebuild with `--features slatedb`")]
    NoSlatedbSupport,
    /// `--kv cloudflare` selected but the binary lacks Cloudflare KV support.
    #[cfg(not(feature = "cloudflare-kv"))]
    #[error("this build has no Cloudflare KV support; rebuild with `--features cloudflare-kv`")]
    NoCloudflareKvSupport,

    // ---- configuration / argument validation -------------------------------
    /// A token root **private** key (hex) failed to parse.
    #[error("invalid auth root private key: {0}")]
    AuthPrivKey(String),
    /// A token root **public** key (hex) failed to parse.
    #[error("invalid auth root public key: {0}")]
    AuthPubKey(String),
    /// A `[cluster.peers]` directory key was not a node id (u64).
    #[cfg(feature = "cluster")]
    #[error("[cluster.peers] key {0:?} is not a node id (u64)")]
    BadPeerId(String),
    /// A raw-public-key TLS error — building the peer-mesh identity/config
    /// (`cluster`) or the `--tls rpk` bootstrap identity/config (`tls`). Both use
    /// the same RPK stack (`boatramp_rpktls`), so `mesh::MeshError` is an alias of
    /// `RpkError` and they share one `From` here (a second would collide).
    #[cfg(any(feature = "cluster", feature = "tls"))]
    #[error(transparent)]
    RpkTls(#[from] boatramp_rpktls::RpkError),
    /// Refusing to serve the peer mesh on a non-loopback address with no trust set
    /// configured — that would expose an unauthenticated control plane.
    /// Add each peer's `pubkey` to `[cluster.peers]`.
    #[cfg(feature = "cluster")]
    #[error(
        "refusing to serve the peer mesh on {0} (non-loopback) with an empty trust \
         set: add each peer's `pubkey` to [cluster.peers]"
    )]
    MeshUnconfigured(std::net::SocketAddr),
    /// Configuring the secrets-at-rest envelope failed.
    #[cfg(all(feature = "cluster", feature = "acme-dns"))]
    #[error("secrets envelope: {0}")]
    Envelope(String),
    /// Fetching the OIDC issuer's discovery document / JWKS failed.
    #[cfg(feature = "oidc")]
    #[error("OIDC setup failed: {0}")]
    OidcSetup(String),
    /// OIDC is enabled but no `--oidc-audience` is set, and the security posture
    /// requires one. Set an audience, or relax
    /// `oidc_require_audience` in `[security]` (e.g. the `dev` profile).
    #[cfg(feature = "oidc")]
    #[error(
        "OIDC is enabled without an audience, but the security posture requires one \
         (set --oidc-audience, or relax `oidc_require_audience`)"
    )]
    OidcAudienceRequired,
    /// `--tls custom` without `--tls-cert`.
    #[cfg(feature = "tls")]
    #[error("--tls-cert is required for --tls custom")]
    TlsCertRequired,
    /// `--tls custom` without `--tls-key`.
    #[cfg(feature = "tls")]
    #[error("--tls-key is required for --tls custom")]
    TlsKeyRequired,
    /// The `--tls-cert` PEM held no certificates (HTTP/3 cert loading).
    #[cfg(feature = "http3")]
    #[error("no certificates in {0}")]
    NoCert(String),
    /// The `--tls-key` PEM held no private key (HTTP/3 cert loading).
    #[cfg(feature = "http3")]
    #[error("no private key in {0}")]
    NoPrivateKey(String),
    /// `--tls acme` with no `--acme-domain`.
    #[cfg(feature = "tls")]
    #[error("at least one --acme-domain is required for --tls acme")]
    NoAcmeDomain,
    /// `--tls acme-dns` with no `--acme-domain`.
    #[cfg(feature = "acme-dns")]
    #[error("at least one --acme-domain is required for --tls acme-dns")]
    NoAcmeDomainDns,
    /// An unrecognised `--acme-dns-provider` value.
    #[cfg(feature = "acme-dns")]
    #[error("unknown --acme-dns-provider {0:?} (expected manual | cloudflare | route53 | oci)")]
    UnknownDnsProvider(String),
    /// No certificate is available yet — the cluster leader hasn't issued one.
    #[cfg(all(feature = "cluster", feature = "acme-dns"))]
    #[error(
        "no certificates available yet — awaiting the cluster leader to issue (retry shortly)"
    )]
    NoCertsYet,
    /// `--blobs s3` without `--s3-bucket`.
    #[cfg(feature = "s3")]
    #[error("--s3-bucket is required for --blobs s3")]
    S3BucketRequired,
    /// A handler `sql` binding named an env var that is not set.
    #[cfg(feature = "handlers")]
    #[error("handlers SQL binding: env var {0} is not set")]
    SqlEnvUnset(String),
    /// A cluster sqld `url` was set without the required `admin_url`.
    #[cfg(feature = "handlers")]
    #[error("handlers SQL binding: `url` (cluster sqld) requires `admin_url`")]
    SqlAdminUrlRequired,
    /// An unrecognised `[handlers.bindings.sql].preview_mode`.
    #[cfg(feature = "handlers")]
    #[error("handlers SQL binding: unknown preview_mode {0:?} (expected empty | branch | shared)")]
    UnknownPreviewMode(String),
    /// Reading the `preview_init` SQL script failed.
    #[cfg(feature = "handlers")]
    #[error("handlers SQL binding: reading preview_init {path:?}: {source}")]
    PreviewInitRead {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ---- propagated library errors (`#[from]`) ------------------------------
    /// Resolving the `[security]` posture (e.g. an unknown profile name) failed.
    #[error(transparent)]
    Security(#[from] boatramp_core::security::SecurityError),
    /// The HTTP server exited with an error.
    #[error(transparent)]
    Serve(#[from] boatramp_server::ServeError),
    /// A listener-bind / filesystem / axum-server I/O error on the serve path.
    #[cfg(any(feature = "tls", feature = "cluster"))]
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An ACME DNS-01 issuance / cert-serving-config error.
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    AcmeDns(#[from] crate::acme_dns::Error),
    /// An HTTP/3 (QUIC) endpoint / TLS-config error.
    #[cfg(feature = "http3")]
    #[error(transparent)]
    Http3(#[from] boatramp_server::Http3Error),
    /// A rustls error building the ACME client config (extra CA trust).
    #[cfg(feature = "tls")]
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    /// A cluster-managed-cert refresh error (replicated cert store).
    #[cfg(all(feature = "cluster", feature = "acme-dns"))]
    #[error(transparent)]
    ClusterTls(#[from] crate::cluster_tls::Error),
    /// Building / bootstrapping the embedded-Raft cluster node failed. Boxed: the
    /// openraft error types it wraps are ~230 bytes, and this variant is cold
    /// (constructed once, on a fatal bootstrap failure). Boxing it keeps `Error`
    /// — and `CliError` above it — under clippy's `result_large_err` threshold
    /// without a blanket `#[allow]`. `#[from]` can't box, so see the `From` below.
    #[cfg(feature = "cluster")]
    #[error(transparent)]
    Bootstrap(Box<boatramp_cluster::node::BootstrapError>),
    /// Opening the SlateDB / Cloudflare KV metadata store failed.
    #[cfg(any(feature = "slatedb", feature = "cloudflare-kv"))]
    #[error(transparent)]
    Kv(#[from] boatramp_core::kv::KvError),
    /// Building the WebAssembly handler engine failed.
    #[cfg(feature = "handlers")]
    #[error(transparent)]
    Handler(#[from] boatramp_handlers::HandlerError),
}

/// `serve` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

// Box the (large, openraft-backed) bootstrap error into [`Error`]: the variant is
// `Box<BootstrapError>` so `?` on a bare `BootstrapError` keeps working (thiserror's
// `#[from]` would generate `From<BootstrapError>`, not the boxing conversion).
#[cfg(feature = "cluster")]
impl From<boatramp_cluster::node::BootstrapError> for Error {
    fn from(e: boatramp_cluster::node::BootstrapError) -> Self {
        Error::Bootstrap(Box::new(e))
    }
}

// Guard the boxing decision: `Bootstrap` is boxed so this enum stays under clippy's
// `result_large_err` threshold (128 B) without a module-wide `#[allow]`. If a future
// variant grows past it, box that one too rather than re-adding the allow.
#[cfg(feature = "cluster")]
const _: () = assert!(std::mem::size_of::<Error>() <= 128);

/// How often the compute reconcile loop converges desired vs. running
/// replicas.
const COMPUTE_RECONCILE_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a scale-to-zero workload must go without a request before it is
/// snapshotted + parked. A requested workload is woken on demand.
const COMPUTE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The posture-scaled kernel-trust gate wired into the compute backends: it runs
/// [`boatramp_core::kernel_trust::verify_kernel`] on the staged kernel right
/// before boot. The always-on check is the content hash; under the strict
/// (multi-tenant) posture it additionally requires the pinned hash to be on the
/// static allow-list and to carry a signature — sourced from the **live fleet
/// default kernel** — verifying against a static signing key. No daemon, or a hash
/// that isn't the current signed default, has no signature source and so **fails
/// closed** under strict: the kernel does not boot.
#[cfg(target_os = "linux")]
struct PostureKernelVerifier {
    strict: bool,
    signing_keys: Vec<String>,
    allowed_hashes: Vec<String>,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
}

// `KernelVerifier` requires `Debug`, but `DaemonRuntime` isn't `Debug` (it holds a
// lock + a `Notify`); summarise instead of recursing into it.
#[cfg(target_os = "linux")]
impl std::fmt::Debug for PostureKernelVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostureKernelVerifier")
            .field("strict", &self.strict)
            .field("signing_keys", &self.signing_keys.len())
            .field("allowed_hashes", &self.allowed_hashes.len())
            .field("has_daemon", &self.daemon.is_some())
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl boatramp_firecracker::KernelVerifier for PostureKernelVerifier {
    // Fully-qualified: this module aliases `Result<T>` to its own error type.
    fn verify(&self, bytes: &[u8], expected_hash: &str) -> std::result::Result<(), String> {
        // The only signature we trust for this hash is the one on the current
        // fleet default kernel (the operator-vetted kernel); any other hash has no
        // signature source and fails the strict bar.
        let sig = self
            .daemon
            .as_ref()
            .and_then(|d| d.effective().default_kernel.clone())
            .filter(|dk| dk.sha256 == expected_hash)
            .and_then(|dk| dk.sig);
        let kref = boatramp_core::daemon_config::KernelRef {
            source: expected_hash.to_string(),
            sha256: expected_hash.to_string(),
            sig,
        };
        boatramp_core::kernel_trust::verify_kernel(
            bytes,
            &kref,
            self.strict,
            &self.signing_keys,
            &self.allowed_hashes,
        )
        .map_err(|e| e.to_string())
    }
}

/// Build this node's compute [`BackendRegistry`] + scheduler [`Node`] inventory
/// from the optional `[compute]` config. Backends
/// are **capability-detected**: a reachable Docker daemon ⇒ `docker`; Linux ⇒ the
/// native `container` backend; Linux + `/dev/kvm` ⇒ the in-process
/// `vmm-embedded` microVM backend (strongest isolation). Absent config ⇒ an empty
/// registry + a node advertising nothing, so the reconcile loop stays a no-op.
async fn build_compute(
    cfg: Option<&crate::config::ComputeConfig>,
    storage: std::sync::Arc<dyn boatramp_core::Storage>,
    data_dir: &std::path::Path,
    node_id: u64,
    strict: bool,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
) -> (
    boatramp_core::compute::BackendRegistry,
    boatramp_core::compute::Node,
) {
    use boatramp_core::compute::{BackendKind, BackendRegistry, Node};
    let mut backends: BackendRegistry = std::collections::BTreeMap::new();
    let empty_node = |id| Node {
        id,
        region: None,
        labels: std::collections::BTreeMap::new(),
        free_vcpus: 0,
        free_mem_mib: 0,
        backends: Vec::new(),
    };
    let Some(cfg) = cfg else {
        return (backends, empty_node(node_id));
    };

    // Remote docker: register only if a daemon actually answers.
    match boatramp_docker::DockerBackend::connect() {
        Ok(docker) => {
            if docker.reachable().await {
                backends.insert("docker".to_string(), std::sync::Arc::new(docker));
            } else {
                tracing::debug!("no reachable docker daemon; skipping docker backend");
            }
        }
        Err(e) => tracing::debug!(%e, "docker backend unavailable"),
    }

    // Native container backend (Linux only).
    #[cfg(target_os = "linux")]
    match std::env::current_exe() {
        Ok(self_exe) => match boatramp_container::ContainerBackend::new(
            storage.clone(),
            data_dir.to_path_buf(),
            cfg.bridge.clone(),
            &cfg.subnet,
            self_exe,
        ) {
            Ok(c) => {
                backends.insert("container".to_string(), std::sync::Arc::new(c));
            }
            Err(e) => tracing::warn!(%e, "container backend unavailable"),
        },
        Err(e) => tracing::warn!(%e, "current_exe for container backend"),
    }
    // Embedded VMM backend (Linux + x86_64 + `/dev/kvm`): in-process microVMs, no
    // external `firecracker` binary — the strongest isolation when KVM is available.
    // Like the container backend it enslaves each tap to `cfg.bridge` (assumed set
    // up). The embedded VMM is KVM-x86-specific, so this is x86_64-only; boatramp
    // still serves on linux/aarch64 (with the container backend, no embedded VMM).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::path::Path::new("/dev/kvm").exists() {
        match (
            std::env::current_exe(),
            boatramp_core::ipam::IpPool::new(&cfg.subnet),
        ) {
            (Ok(self_exe), Ok(pool)) => {
                let gateway = pool.gateway().to_string();
                // Verify-before-boot gate for every kernel this backend stages.
                let verifier: Arc<dyn boatramp_firecracker::KernelVerifier> =
                    Arc::new(PostureKernelVerifier {
                        strict,
                        signing_keys: cfg.kernel_signing_pubkeys.clone(),
                        allowed_hashes: cfg.kernel_allowed_hashes.clone(),
                        daemon: daemon.clone(),
                    });
                match boatramp_firecracker::EmbeddedVmmBackend::new(
                    storage.clone(),
                    self_exe, // re-exec'd as `__vmm-run` per VM (jailed subprocess)
                    data_dir.to_path_buf(),
                    cfg.bridge.clone(),
                    gateway,
                    &cfg.subnet,
                    verifier,
                ) {
                    Ok(vmm) => {
                        backends.insert("vmm-embedded".to_string(), std::sync::Arc::new(vmm));
                    }
                    Err(e) => tracing::warn!(%e, "embedded VMM backend unavailable"),
                }
            }
            (Err(e), _) => tracing::warn!(%e, "current_exe for VMM backend"),
            (_, Err(e)) => tracing::warn!(%e, "bad compute subnet for VMM backend"),
        }
    } else {
        tracing::debug!("no /dev/kvm; skipping embedded VMM backend");
    }

    let _ = (&storage, data_dir); // used only on Linux (container / VMM backends)
    // The kernel-trust verifier is wired only for the embedded VMM (x86_64 Linux);
    // silence `strict`/`daemon` everywhere else (non-Linux and linux/aarch64).
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let _ = (strict, &daemon);

    let free_vcpus = if cfg.vcpus > 0 {
        cfg.vcpus
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    };
    let free_mem_mib = if cfg.mem_mib > 0 { cfg.mem_mib } else { 1024 };
    let advertised: Vec<BackendKind> = backends
        .iter()
        .map(|(id, b)| BackendKind {
            id: id.clone(),
            isolation: b.capabilities().isolation,
        })
        .collect();
    tracing::info!(backends = ?advertised, free_vcpus, free_mem_mib, "compute node inventory");
    let node = Node {
        id: node_id,
        region: None,
        labels: std::collections::BTreeMap::new(),
        free_vcpus,
        free_mem_mib,
        backends: advertised,
    };
    (backends, node)
}

/// Blob (file-content) backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BlobBackend {
    /// Local filesystem (`<data-dir>/blobs`).
    Fs,
    /// S3-compatible object store (requires `--features s3`).
    S3,
}

/// Metadata (manifest + pointer) backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum KvBackend {
    /// Transactional LSM over object storage; durable local default
    /// (`<data-dir>/kv-slate`). Requires `--features slatedb` (on by default).
    Slatedb,
    /// In-memory (ephemeral; lost on restart).
    Memory,
    /// Cloudflare KV over REST (requires `--features cloudflare-kv`).
    Cloudflare,
}

/// TLS mode for the public listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TlsMode {
    /// Plain HTTP (terminate TLS at an upstream proxy).
    Off,
    /// HTTPS with an operator-supplied cert/key (requires `--features tls`).
    Custom,
    /// HTTPS with automatic ACME certificates (requires `--features tls`).
    Acme,
    /// HTTPS with ACME **DNS-01** certificates, incl. wildcard preview certs
    /// (requires `--features acme-dns`).
    AcmeDns,
    /// HTTPS with a **raw-public-key** (RFC 7250) identity the client pins — an
    /// encrypted, server-authenticated control channel with no ACME, tunnel, or
    /// TLS-terminating proxy (requires `--features tls`). The client authenticates
    /// with a bearer token; the identity printed at startup is pinned client-side
    /// with `--server-pubkey`. For a first-boot / bare-metal control plane.
    Rpk,
}

/// Arguments for `boatramp serve`.
#[derive(Debug, clap::Args)]
pub struct ServeArgs {
    /// Address to bind the HTTP server to (flag/env > `serve.addr` >
    /// `127.0.0.1:8080`).
    #[arg(long, env = "BOATRAMP_ADDR")]
    addr: Option<SocketAddr>,

    /// Data directory for filesystem backends (blobs in `<dir>/blobs`,
    /// metadata in `<dir>/kv`). Flag/env > `serve.data_dir` > `./data`.
    #[arg(long, env = "BOATRAMP_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Blob storage backend.
    #[arg(long, value_enum, default_value_t = BlobBackend::Fs)]
    blobs: BlobBackend,

    /// Metadata (KV) backend.
    #[arg(long, value_enum, default_value_t = KvBackend::Slatedb)]
    kv: KvBackend,

    /// S3 bucket (required for `--blobs s3`).
    #[arg(long, env = "BOATRAMP_S3_BUCKET")]
    s3_bucket: Option<String>,

    /// S3 endpoint URL, e.g. a MinIO server (optional).
    #[arg(long, env = "BOATRAMP_S3_ENDPOINT")]
    s3_endpoint: Option<String>,

    /// S3 region (optional).
    #[arg(long, env = "BOATRAMP_S3_REGION")]
    s3_region: Option<String>,

    /// Use S3 path-style addressing (required by MinIO).
    #[arg(long, env = "BOATRAMP_S3_PATH_STYLE")]
    s3_path_style: bool,

    /// Number of deploy manifests/pointers to keep in the in-memory LRU.
    #[arg(long, default_value_t = 256)]
    cache_entries: usize,

    /// Token root **private** key (hex) — this node verifies tokens *and*
    /// issues them (`/api/tokens`, OIDC exchange). Enables control-plane auth.
    /// Generate with `boatramp auth init`.
    #[arg(long, env = "BOATRAMP_AUTH_ROOT_PRIVATE_KEY")]
    auth_root_private_key: Option<String>,

    /// Token root **public** key (hex) — verify-only node (cannot issue).
    /// Enables control-plane auth. Ignored if `--auth-root-private-key` is set.
    #[arg(long, env = "BOATRAMP_AUTH_ROOT_PUBLIC_KEY")]
    auth_root_public_key: Option<String>,

    /// Single-use **bootstrap secret** enabling `POST /api/tokens/bootstrap` — mint
    /// the first control-plane token by presenting this secret (no admin bearer).
    /// Set it on a fresh deploy, run `boatramp token bootstrap`, then unset it.
    /// Rotating it re-enables bootstrap (recovery). Flag/env > `serve.bootstrap_secret`.
    #[arg(long, env = "BOATRAMP_BOOTSTRAP_SECRET")]
    bootstrap_secret: Option<String>,

    /// TLS mode for the listener.
    #[arg(long, value_enum, default_value_t = TlsMode::Off)]
    tls: TlsMode,

    /// PEM certificate chain (for `--tls custom`).
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM private key (for `--tls custom`).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Domain to obtain an ACME certificate for (repeatable; for `--tls acme`).
    #[arg(long = "acme-domain")]
    acme_domain: Vec<String>,

    /// ACME directory URL (defaults to Let's Encrypt production).
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    acme_directory: String,

    /// Contact email for the ACME account.
    #[arg(long)]
    acme_contact: Option<String>,

    /// Extra root CA (PEM) to trust for the ACME server (e.g. Pebble's CA).
    #[arg(long)]
    acme_ca_cert: Option<PathBuf>,

    /// Directory for the ACME certificate cache.
    #[arg(long, default_value = "./data/acme")]
    acme_cache: PathBuf,

    /// DNS provider for `--tls acme-dns` and `boatramp dns`
    /// (`manual` | `cloudflare` | `route53` | `oci`). Credentials come from the
    /// environment (see `boatramp dns --help`).
    #[arg(long, default_value = "manual")]
    acme_dns_provider: String,

    /// With `--tls acme-dns`, also issue a `*.deploy.<domain>` wildcard cert so
    /// the wildcard preview host form gets TLS.
    #[arg(long)]
    acme_wildcard_preview: bool,

    /// Reject blob uploads larger than this many bytes (default: unlimited).
    /// Flag/env > `serve.max_upload_bytes`.
    #[arg(long, env = "BOATRAMP_MAX_UPLOAD_BYTES")]
    max_upload_bytes: Option<u64>,

    /// Abort an upload whose body stalls (no bytes received) for longer than this
    /// many seconds — slowloris protection. Flag/env > `serve.upload_idle_timeout_secs`.
    #[arg(long, env = "BOATRAMP_UPLOAD_IDLE_TIMEOUT")]
    upload_idle_timeout_secs: Option<u64>,

    /// Cap simultaneous blob uploads; further uploads get 503 until a slot frees.
    /// Flag/env > `serve.max_concurrent_uploads`.
    #[arg(long, env = "BOATRAMP_MAX_CONCURRENT_UPLOADS")]
    max_concurrent_uploads: Option<usize>,

    /// In a TLS mode, also bind this plain-HTTP address (e.g. `0.0.0.0:80`) on a
    /// second listener that 308-redirects every request to HTTPS. Flag/env >
    /// `serve.http_redirect_addr`. Ignored when `--tls off`.
    #[arg(long, env = "BOATRAMP_HTTP_REDIRECT_ADDR")]
    http_redirect_addr: Option<SocketAddr>,

    /// Site to serve for a `Host` that matches no domain, instead of 404
    /// (catch-all). Flag/env > `serve.default_site`.
    #[arg(long, env = "BOATRAMP_DEFAULT_SITE")]
    default_site: Option<String>,

    /// The fleet's canonical public origin (e.g. `https://cp.example.com`) that a
    /// per-request proof-of-possession must bind to. Required for holder-bound
    /// (`cnf`/PoP) tokens; compared against a proof's origin, never a request
    /// header. Flag/env > `serve.pop_origin`.
    #[arg(long, env = "BOATRAMP_POP_ORIGIN")]
    pop_origin: Option<String>,

    /// Rate-limit cluster-wide via the control-plane KV (shared fixed-window)
    /// instead of per-node in-process buckets. Meaningful with a shared/
    /// replicated KV; adds a KV round-trip per limited request. Flag/env >
    /// `serve.cluster_rate_limit`.
    #[arg(long, env = "BOATRAMP_CLUSTER_RATE_LIMIT")]
    cluster_rate_limit: bool,

    /// Keep the local config cache coherent across processes sharing one KV
    /// (Cloudflare KV / shared SlateDB): publish each control-plane write to a
    /// changelog and poll it to invalidate just the keys peers changed.
    /// Turn on when running multiple stateless frontends
    /// over one shared store; unnecessary single-node or in a Raft cluster.
    /// Flag/env > `serve.shared_cache_coherence`.
    #[arg(long, env = "BOATRAMP_SHARED_CACHE_COHERENCE")]
    shared_cache_coherence: bool,

    /// Require a valid control-plane token to view deployment previews
    /// (`/_deploy/<id>` and `<id>.deploy.<host>`). Flag/env >
    /// `serve.protect_previews`.
    #[arg(long, env = "BOATRAMP_PROTECT_PREVIEWS")]
    protect_previews: bool,

    /// Also serve HTTP/3 (QUIC) on the same UDP port (with `--tls custom`).
    /// Requires the `http3` build feature.
    #[cfg(feature = "http3")]
    #[arg(long)]
    http3: bool,

    /// OIDC issuer URL for control-plane bearer-JWT auth (its JWKS is fetched at
    /// startup; tokens' scope claim must carry boatramp scopes). Requires the
    /// `oidc` build feature.
    #[cfg(feature = "oidc")]
    #[arg(long, env = "BOATRAMP_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// Expected JWT `aud` for OIDC auth (audience validation is skipped if unset).
    #[cfg(feature = "oidc")]
    #[arg(long, env = "BOATRAMP_OIDC_AUDIENCE")]
    oidc_audience: Option<String>,

    /// JWT claim carrying boatramp scopes for OIDC auth (default `scope`).
    #[cfg(feature = "oidc")]
    #[arg(long, env = "BOATRAMP_OIDC_SCOPE_CLAIM")]
    oidc_scope_claim: Option<String>,
}

impl ServeArgs {
    /// Merge upload limits from flags/env over the `serve` config defaults, then
    /// fall back to the security posture's default cap: an
    /// unconfigured `max_upload_bytes` is no longer unbounded. The posture's `0`
    /// means "explicitly unlimited" (e.g. the `dev` profile).
    fn server_limits(
        &self,
        serve_cfg: &crate::config::ServeConfig,
        posture: &boatramp_core::security::SecurityPosture,
    ) -> boatramp_server::ServerLimits {
        boatramp_server::ServerLimits {
            max_upload_bytes: self
                .max_upload_bytes
                .or(serve_cfg.max_upload_bytes)
                .or_else(|| (posture.max_upload_bytes != 0).then_some(posture.max_upload_bytes)),
            upload_idle_timeout: self
                .upload_idle_timeout_secs
                .or(serve_cfg.upload_idle_timeout_secs)
                .map(std::time::Duration::from_secs),
            max_concurrent_uploads: self
                .max_concurrent_uploads
                .or(serve_cfg.max_concurrent_uploads),
        }
    }
}

/// Entry point for `boatramp serve`. Resolution precedence for the overridable
/// settings is flag/env > `serve` in `boatramp.cfg` > built-in default.
pub async fn run(args: ServeArgs, config: &ServerConfig) -> Result<()> {
    let serve_cfg = config.serve.clone().unwrap_or_default();
    // Resolve the operator security posture once (profile preset + overrides);
    // absent `[security]` ⇒ the strict `multi-tenant` default. Threaded into
    // `ServerOptions` so it reaches the cluster path too.
    let posture = config.security.clone().unwrap_or_default().resolve()?;
    // Server-level options (flag/env > `serve` config). Resolved before the
    // `serve` fields below are consumed.
    let mut options = boatramp_server::ServerOptions {
        limits: args.server_limits(&serve_cfg, &posture),
        default_site: args.default_site.clone().or(serve_cfg.default_site.clone()),
        pop_origin: args.pop_origin.clone().or(serve_cfg.pop_origin.clone()),
        protect_previews: args.protect_previews || serve_cfg.protect_previews,
        posture,
        // The listener terminates TLS in any non-`Off` mode; used to derive the
        // request scheme when X-Forwarded-Proto isn't trusted.
        served_over_tls: !matches!(args.tls, TlsMode::Off),
        bootstrap_secret: args
            .bootstrap_secret
            .clone()
            .or(serve_cfg.bootstrap_secret.clone()),
        ..Default::default()
    };
    let cluster_rate_limit = args.cluster_rate_limit || serve_cfg.cluster_rate_limit;
    let addr = args
        .addr
        .or(serve_cfg.addr)
        .unwrap_or_else(|| "127.0.0.1:8080".parse().expect("valid default addr"));
    // Implicit host routing (first-label `<site>.host` / sole-site at root) is a
    // dev / single-operator convenience: enable it when the posture allows, or
    // unconditionally on a loopback bind (only local clients reach it, so there
    // is no host-spoofing exposure). Strict `multi-tenant` on a public bind keeps
    // it off, so an unmatched host resolves only to `default_site` or 404.
    options.implicit_routing = options.posture.allow_implicit_routing || addr.ip().is_loopback();
    let data_dir = args
        .data_dir
        .clone()
        .or(serve_cfg.data_dir)
        .unwrap_or_else(|| PathBuf::from("./data"));

    let storage = build_blobs(&args, &data_dir).await?;

    // Cluster mode (`[cluster]` config): the control-plane KvStore + messaging
    // come from the embedded-Raft cluster node, not the local backends.
    #[cfg(feature = "cluster")]
    if let Some(mut cluster_cfg) = config.cluster.clone() {
        // StatefulSet-native identity: a shared ConfigMap can't hold a per-pod node
        // id, so let the pod's ordinal drive it via env (the Kubernetes operator
        // wires `apps.kubernetes.io/pod-index` → `BOATRAMP_CLUSTER_NODE_ID` through
        // the downward API, and marks the lowest ordinal as the bootstrap node).
        apply_cluster_env_overrides(&mut cluster_cfg);
        return run_cluster(args, config, cluster_cfg, addr, data_dir, storage, options).await;
    }
    #[cfg(not(feature = "cluster"))]
    if config.cluster.is_some() {
        return Err(Error::NoClusterSupport);
    }

    let kv_backend = build_kv(&args, &data_dir).await?;
    // Shared-mode coherence: when several processes share
    // one KV, publish each write to a changelog over the *uncached* backend and
    // poll it to invalidate peer-changed keys.
    let shared_coherence = args.shared_cache_coherence || serve_cfg.shared_cache_coherence;
    let changelog = shared_coherence
        .then(|| Arc::new(Changelog::new(kv_backend.clone(), CHANGELOG_RETENTION_SECS)));
    // Front the metadata store with an LRU so hot reads stay in memory.
    let mut cached = CachedKv::new(kv_backend.clone(), args.cache_entries);
    if let Some(changelog) = &changelog {
        cached = cached.with_publisher(changelog.clone());
    }
    let kv: Arc<dyn KvStore> = Arc::new(cached);
    // Handle for a final flush on graceful shutdown (SHUT-1): `kv` is moved into
    // the deploy store below; this clone reaches its backing store's `flush`.
    let kv_handle = kv.clone();
    // Rate-limit windows are coordination state, not config: they must NOT be
    // cached (a stale window would count wrong), so the limiter uses the
    // *uncached* backend directly.
    if cluster_rate_limit {
        options.cluster_rate_limit_kv = Some(kv_backend.clone());
    }
    // The dynamic daemon-config runtime, built here so SIGHUP and the shared-store
    // changelog can **wake** an immediate reload (push-driven convergence) rather
    // than relying on the runtime's backstop tick.
    let daemon_runtime = Arc::new(boatramp_server::DaemonRuntime::new(
        boatramp_server::config_baseline(&options),
    ));
    options.daemon_runtime = Some(daemon_runtime.clone());
    spawn_sighup_reload(kv.clone(), Some(daemon_runtime.clone()));
    if let Some(changelog) = changelog {
        spawn_cache_poller(changelog, kv.clone(), Some(daemon_runtime.clone()));
    }
    let auth = configure_auth(
        serve_cfg.signer.as_ref(),
        args.auth_root_private_key
            .clone()
            .or(serve_cfg.auth_root_private_key.clone()),
        args.auth_root_public_key
            .clone()
            .or(serve_cfg.auth_root_public_key.clone()),
        &mut options,
        kv.clone(),
    )
    .await?;
    configure_oidc(&args, &mut options).await?;
    // Fail-closed: don't expose an unauthenticated control plane on a public bind.
    enforce_auth_bind(addr, &auth, &options.posture)?;
    // The handler runtime reuses the same blob/KV backends (per-site prefixed)
    // for its wasi:blobstore/keyvalue bindings; the sql binding is selected by
    // `[handlers.bindings.sql]` (default: per-site libsql files under <data-dir>).
    let handlers = build_handler_runtime(
        kv.clone(),
        storage.clone(),
        &data_dir,
        config.handlers.as_ref(),
        None,
        posture.max_handler_blob_bytes,
        posture.max_component_bytes,
    )?;
    let compute_storage = storage.clone();
    let deploy = DeployStore::new(storage, kv);

    // Compute reconcile loop. Single-node is always
    // the "leader". Backends are built from the `[compute]` config + capability
    // detection; a no-op when none are registered. Detached for the server's life.
    let (compute_backends, compute_node) =
        build_compute(
            config.compute.as_ref(),
            compute_storage,
            &data_dir,
            0,
            !posture.allow_shared_kernel_compute,
            options.daemon_runtime.clone(),
        )
        .await;
    let _reconcile = boatramp_server::spawn_compute_reconcile(
        deploy.clone(),
        compute_backends,
        vec![compute_node],
        boatramp_core::compute::BackendPolicy {
            // Strict posture: untrusted-grade (VM/platform) isolation only —
            // shared-kernel backends are ineligible.
            require_strong_isolation: !posture.allow_shared_kernel_compute,
            ..Default::default()
        },
        Arc::new(|| true),
        COMPUTE_RECONCILE_TICK,
        COMPUTE_IDLE_TIMEOUT,
    );

    tracing::info!(
        blobs = ?args.blobs, kv = ?args.kv, tls = ?args.tls,
        auth = !auth.is_disabled(), "starting boatramp"
    );
    // In a TLS mode, optionally bind a second plain-HTTP listener that redirects
    // to HTTPS. Ignored for `--tls off`.
    #[cfg(feature = "tls")]
    if !matches!(args.tls, TlsMode::Off) {
        if let Some(redirect_addr) = args.http_redirect_addr.or(serve_cfg.http_redirect_addr) {
            spawn_http_redirect(redirect_addr, deploy.clone(), posture);
        }
    }
    let serve_result = match args.tls {
        TlsMode::Off => boatramp_server::serve_with(addr, deploy, auth, handlers, options)
            .await
            .map_err(Error::Serve),
        TlsMode::Custom => serve_custom(&args, addr, deploy, auth, handlers, options).await,
        TlsMode::Acme => serve_acme(&args, addr, deploy, auth, handlers, options).await,
        TlsMode::AcmeDns => serve_acme_dns(&args, addr, deploy, auth, handlers, options).await,
        TlsMode::Rpk => serve_rpk(&args, addr, deploy, auth, handlers, options, &data_dir).await,
    };
    // Graceful shutdown: force a final flush of the metadata store (SHUT-1).
    if let Err(e) = kv_handle.flush().await {
        tracing::warn!(error = %e, "metadata store flush on shutdown failed");
    }
    serve_result
}

/// How long changelog feed entries are kept (comfortably larger than the poll
/// interval so a poller can't miss entries between polls).
const CHANGELOG_RETENTION_SECS: u64 = 60;

/// Drive the shared-mode cache-coherence poller: every
/// second, pop the keys peers changed; periodically trim the feed; and every few
/// minutes do a full flush as the gap backstop (rare, so no thundering herd).
/// Detached for the server's lifetime.
fn spawn_cache_poller(
    changelog: Arc<Changelog>,
    cache: Arc<dyn KvStore>,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
) {
    use std::time::Duration;
    tokio::spawn(async move {
        let poll = Duration::from_secs(1);
        let flush_every = Duration::from_secs(300);
        let mut cursor = changelog.current_cursor().await;
        let mut since_trim = Duration::ZERO;
        let mut since_flush = Duration::ZERO;
        loop {
            tokio::time::sleep(poll).await;
            let changed = changelog.poll(&mut cursor).await;
            if !changed.is_empty() {
                cache.invalidate_keys(&changed);
                // A peer wrote dynamic daemon config → wake an immediate reload.
                if let Some(daemon) = &daemon {
                    if changed.iter().any(|k| k.starts_with("daemon/")) {
                        daemon.notify_reload();
                    }
                }
            }
            since_trim += poll;
            if since_trim >= Duration::from_secs(30) {
                changelog.trim().await;
                since_trim = Duration::ZERO;
            }
            since_flush += poll;
            if since_flush >= flush_every {
                cache.invalidate_cache();
                cursor = changelog.current_cursor().await;
                since_flush = Duration::ZERO;
            }
        }
    });
}

/// Spawn a `SIGHUP` handler that drops the control-plane KV cache, so the next
/// reads pull fresh config from the backing store — the manual "reload config"
/// signal (e.g. after another node wrote new config to the shared/replicated
/// store). No-op on non-Unix. Detached for the server's lifetime.
#[cfg(unix)]
fn spawn_sighup_reload(kv: Arc<dyn KvStore>, daemon: Option<Arc<boatramp_server::DaemonRuntime>>) {
    tokio::spawn(async move {
        let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(sig) => sig,
            Err(err) => {
                tracing::warn!(%err, "could not install SIGHUP handler");
                return;
            }
        };
        while hup.recv().await.is_some() {
            kv.invalidate_cache();
            // Wake an immediate daemon-config reload (push, not the backstop tick).
            if let Some(daemon) = &daemon {
                daemon.notify_reload();
            }
            tracing::info!("SIGHUP: invalidated config cache (next reads reload from the store)");
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload(
    _kv: Arc<dyn KvStore>,
    _daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
) {
}

/// In a TLS mode, spawn a detached plain-HTTP listener on `addr` that
/// 308-redirects every request to HTTPS (dual-listener) — except the HTTP
/// domain-ownership challenge, which it serves directly so an unattached host
/// can verify itself over plain `:80` before it has a cert. Fire and forget: it
/// dies with the process; bind failures are logged, not fatal, so a missing
/// privilege on `:80` doesn't take down the HTTPS server. Uses `axum_server`
/// (the same plain/TLS server stack the TLS modes use).
#[cfg(feature = "tls")]
fn spawn_http_redirect(
    addr: SocketAddr,
    deploy: DeployStore,
    posture: boatramp_core::security::SecurityPosture,
) {
    tokio::spawn(async move {
        tracing::info!(%addr, "serving HTTP→HTTPS redirect listener");
        let service =
            boatramp_server::http_redirect_router(deploy, posture).into_make_service();
        if let Err(err) = axum_server::bind(addr).serve(service).await {
            tracing::error!(%addr, %err, "HTTP redirect listener failed");
        }
    });
}

/// Run in **self-hosted cluster mode**: the control-plane
/// `KvStore` and the `wasi:messaging` coordinator come from an embedded-Raft
/// cluster node instead of the local backends. This node serves its peer mesh
/// (`/raft/*` + `/stream/*`) on `[cluster].listen`, runs `DeployStore` over
/// `RaftKv` (writes→leader, reads→local durable state) and the dispatcher over
/// `RaftMessaging`, and fires crons only while it is the leader. Live multi-host
/// behavior needs live-platform validation; every component is gate-tested in-process.
/// How long a rotation waits for `K_new` to propagate before presenting it.
/// Only minimises the transient-rejection window — the live
/// verifier + dialer retry make a shorter/absent wait safe, not incorrect.
#[cfg(feature = "cluster")]
const MESH_ROTATION_PROPAGATION: std::time::Duration = std::time::Duration::from_secs(2);

/// Parse a mesh key-rotation cadence like `"30d"`, `"12h"`, `"90m"`, `"3600s"`
/// into a `Duration`. `None` for an empty/invalid value (⇒ no scheduled
/// rotation). Only the `s`/`m`/`h`/`d` suffixes are accepted.
#[cfg(feature = "cluster")]
fn parse_rotation_interval(spec: &str) -> Option<std::time::Duration> {
    let spec = spec.trim();
    let split = spec.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = spec.split_at(split);
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        "d" => n.checked_mul(86_400)?,
        _ => return None,
    };
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

/// Bridges the server's `/api/cluster/*` control routes to the cluster runtime
/// (join admission + key rotation) over [`ClusterNode`].
#[cfg(feature = "cluster")]
struct ClusterMeshControl(Arc<boatramp_cluster::node::ClusterNode>);

#[cfg(feature = "cluster")]
#[async_trait::async_trait]
impl boatramp_server::MeshControl for ClusterMeshControl {
    async fn admit(
        &self,
        node: u64,
        pubkey_hex: &str,
        jti: &str,
    ) -> std::result::Result<bool, String> {
        self.0
            .admit(node, pubkey_hex, jti)
            .await
            .map_err(|e| e.to_string())
    }

    async fn rotate_key(&self) -> std::result::Result<String, String> {
        let new_pub = self
            .0
            .rotate_key(MESH_ROTATION_PROPAGATION)
            .await
            .map_err(|e| e.to_string())?;
        Ok(new_pub.iter().map(|b| format!("{b:02x}")).collect())
    }

    async fn revoke(&self, node: u64) -> std::result::Result<(), String> {
        self.0.revoke(node).await.map_err(|e| e.to_string())
    }

    async fn members(&self) -> std::result::Result<Vec<boatramp_server::MeshMember>, String> {
        Ok(self
            .0
            .members()
            .into_iter()
            .map(|m| boatramp_server::MeshMember {
                node: m.node,
                voter: m.voter,
                caught_up: m.caught_up,
                leader: m.leader,
            })
            .collect())
    }

    async fn promote(&self, node: u64) -> std::result::Result<(), String> {
        self.0.promote(node).await.map_err(|e| e.to_string())
    }
}

/// Verifies a mesh client-write **cluster-write capability**: the
/// presented bearer must be a token signed by the control-plane root that grants
/// the `cluster-write` role. This trust root is separate from the mesh transport
/// key, so a mesh-key holder without a control-plane capability can't inject
/// writes.
#[cfg(feature = "cluster")]
struct MeshWriteAuthz {
    public: boatramp_core::cose::TokenPublicKey,
}

#[cfg(feature = "cluster")]
impl boatramp_cluster::http::ClientWriteAuthz for MeshWriteAuthz {
    fn authorize(&self, capability: Option<&str>) -> bool {
        let Some(token) = capability else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let Ok(verified) = boatramp_core::cose::verify(token, &self.public, now) else {
            return false;
        };
        verified.roles.iter().any(|r| r.name == "cluster-write")
    }
}

/// Build the mesh write gate from config: when `mesh.gate_client_writes` is
/// set and the token signer (root **private** key) is available, mint this node's
/// cluster-write capability and an authorizer for incoming forwards. Returns
/// `(None, None)` when disabled or the root key is absent (gating then off —
/// defense-in-depth is opt-in and must not break a keyless cluster).
#[cfg(feature = "cluster")]
#[allow(clippy::type_complexity)]
async fn build_mesh_write_gate(
    args: &ServeArgs,
    config: &ServerConfig,
    mesh_cfg: &crate::config::MeshConfig,
) -> Result<(
    Option<String>,
    Option<Arc<dyn boatramp_cluster::http::ClientWriteAuthz>>,
)> {
    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{self, Claims, LocalSigner, Signer};

    if !mesh_cfg.gate_client_writes.unwrap_or(false) {
        return Ok((None, None));
    }
    let priv_hex = args.auth_root_private_key.clone().or_else(|| {
        config
            .serve
            .as_ref()
            .and_then(|s| s.auth_root_private_key.clone())
    });
    let Some(priv_hex) = priv_hex else {
        tracing::warn!(
            "cluster.mesh.gate_client_writes is set but no token root private key is \
             configured — mesh client-write gating is disabled"
        );
        return Ok((None, None));
    };
    let signer =
        LocalSigner::from_private_hex(&priv_hex).map_err(|e| Error::AuthPrivKey(e.to_string()))?;
    // No TTL: the capability lives for this node's process (now_unix unused).
    let claims = Claims {
        roles: vec![GrantedRole::global("cluster-write")],
        kind: cose::KIND_CLUSTER_WRITE.to_string(),
        ttl_secs: None,
        now_unix: 0,
    };
    let capability = cose::mint(&claims, &signer)
        .await
        .map_err(|e| Error::AuthPrivKey(format!("minting cluster-write capability: {e}")))?;
    let authz: Arc<dyn boatramp_cluster::http::ClientWriteAuthz> = Arc::new(MeshWriteAuthz {
        public: signer.public_key(),
    });
    Ok((Some(capability), Some(authz)))
}

/// Build the configured secrets-at-rest envelope from `[secrets]`,
/// resolving a Vault token from the environment. `None` ⇒ store cleartext.
#[cfg(all(feature = "cluster", feature = "acme-dns"))]
fn build_cert_envelope(
    secrets: Option<&crate::config::SecretsConfig>,
    data_dir: &Path,
) -> Result<Option<Arc<dyn boatramp_core::envelope::KeyEnvelope>>> {
    use boatramp_server::envelope::{build_envelope, EnvelopeSpec};
    let Some(cfg) = secrets else {
        return Ok(None);
    };
    let spec = match cfg.envelope.as_str() {
        "" => EnvelopeSpec::None,
        "local" => EnvelopeSpec::Local {
            kek_file: cfg
                .kek_file
                .clone()
                .unwrap_or_else(|| data_dir.join("secrets/kek")),
        },
        "vault" => {
            let v = cfg.vault.as_ref().ok_or_else(|| {
                Error::Envelope(
                    "secrets.envelope = \"vault\" needs a [secrets.vault] section".into(),
                )
            })?;
            let token = std::env::var(&v.token_env).map_err(|_| {
                Error::Envelope(format!("Vault token env `{}` is not set", v.token_env))
            })?;
            EnvelopeSpec::Vault {
                addr: v.addr.clone(),
                key: v.key.clone(),
                token,
            }
        }
        other => {
            return Err(Error::Envelope(format!(
                "unknown secrets.envelope {other:?} (want \"local\" or \"vault\")"
            )))
        }
    };
    build_envelope(spec).map_err(|e| Error::Envelope(e.to_string()))
}

/// Reloads this node's dynamic daemon-config runtime whenever a replicated
/// `daemon/*` write is applied to the Raft state machine — push convergence for
/// cluster followers and the leader through ordinary log replication, no polling.
#[cfg(feature = "cluster")]
struct DaemonConfigObserver(Arc<boatramp_server::DaemonRuntime>);

#[cfg(feature = "cluster")]
impl boatramp_cluster::raft::ApplyObserver for DaemonConfigObserver {
    fn on_apply(&self, muts: &[boatramp_core::kv::WriteOp]) {
        use boatramp_core::kv::WriteOp;
        let touched = muts.iter().any(|m| match m {
            WriteOp::Put(k, _) | WriteOp::Delete(k) => k.starts_with("daemon/"),
        });
        if touched {
            self.0.notify_reload();
        }
    }

    fn on_reset(&self, keys: &[String]) {
        if keys.iter().any(|k| k.starts_with("daemon/")) {
            self.0.notify_reload();
        }
    }
}

#[cfg(feature = "cluster")]
#[allow(clippy::too_many_arguments)]
/// Apply StatefulSet-native cluster overrides from the environment: the pod's
/// ordinal sets `node_id` (`BOATRAMP_CLUSTER_NODE_ID`), and `BOATRAMP_CLUSTER_BOOTSTRAP`
/// marks the one node that initializes membership (the Kubernetes operator sets it
/// on the lowest ordinal). Config-file values are the fallback (non-k8s deploys).
#[cfg(feature = "cluster")]
fn apply_cluster_env_overrides(cfg: &mut crate::config::ClusterConfig) {
    if let Some(id) = std::env::var("BOATRAMP_CLUSTER_NODE_ID")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        cfg.node_id = id;
    }
    if let Ok(b) = std::env::var("BOATRAMP_CLUSTER_BOOTSTRAP") {
        cfg.bootstrap = matches!(b.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
    }
}

async fn run_cluster(
    args: ServeArgs,
    config: &ServerConfig,
    cluster_cfg: crate::config::ClusterConfig,
    addr: SocketAddr,
    data_dir: PathBuf,
    storage: Arc<dyn Storage>,
    mut options: boatramp_server::ServerOptions,
) -> Result<()> {
    use boatramp_cluster::node::{build_node, ClusterParams};

    // Node-local durable Raft log/state store (distinct from the *replicated*
    // control plane the cluster serves).
    let store_dir = cluster_cfg
        .store_dir
        .clone()
        .unwrap_or_else(|| data_dir.join("raft"));
    let durable_kv: Arc<dyn KvStore> = Arc::new(
        boatramp_storage::SlateKv::open_local_with_flush(store_dir, CONTROL_PLANE_FLUSH).await?,
    );
    // Keep a handle to force a final flush on graceful shutdown (SHUT-1): the
    // store is moved into the Raft stores below, so this clone is how we reach
    // its `flush` after serving stops.
    let durable_kv_handle = durable_kv.clone();

    use boatramp_cluster::mesh::{self, MeshIdentity, MeshTls, TrustSet};

    // Parse the string-keyed peer directory, splitting addressing (`url`) from
    // identity (`pubkey` → the genesis mesh trust set).
    let mut peers = std::collections::BTreeMap::new();
    let mut genesis_trust = std::collections::BTreeMap::new();
    for (id, entry) in &cluster_cfg.peers {
        let id: u64 = id.parse().map_err(|_| Error::BadPeerId(id.clone()))?;
        peers.insert(id, entry.url.clone());
        genesis_trust.insert(id, mesh::parse_public_key(&entry.pubkey)?);
    }

    // Load (or generate + persist `0600`) this node's Ed25519 mesh identity.
    let mesh_cfg = cluster_cfg.mesh.clone().unwrap_or_default();
    let key_file = mesh_cfg
        .key_file
        .clone()
        .unwrap_or_else(|| data_dir.join("mesh/identity.key"));
    let identity = MeshIdentity::load_or_generate(&key_file)?;
    tracing::info!(
        node_id = cluster_cfg.node_id,
        pubkey = %identity.public_key_hex(),
        "cluster: mesh identity (put this pubkey in the peers' [cluster.peers])"
    );

    // Fail closed: never expose an unauthenticated mesh on a non-loopback
    // bind. An empty trust set means no peer pubkeys were configured.
    if !cluster_cfg.listen.ip().is_loopback() && genesis_trust.is_empty() {
        return Err(Error::MeshUnconfigured(cluster_cfg.listen));
    }

    let mesh_tls = Arc::new(MeshTls::new(
        Arc::new(identity),
        TrustSet::from_map(genesis_trust),
    ));

    // Optionally gate mesh client-writes behind a control-plane cluster-write
    // capability (this node's capability + the authorizer for incoming forwards).
    let (write_capability, write_authz) = build_mesh_write_gate(&args, config, &mesh_cfg).await?;
    if write_authz.is_some() {
        tracing::info!("cluster: mesh client-write gating enabled");
    }

    // Dynamic daemon-config runtime: a cluster ApplyObserver wakes an immediate
    // reload on every replicated `daemon/*` apply, so leader and followers converge
    // by push (through ordinary log replication) with no polling.
    let daemon_runtime = Arc::new(boatramp_server::DaemonRuntime::new(
        boatramp_server::config_baseline(&options),
    ));
    options.daemon_runtime = Some(daemon_runtime.clone());
    let daemon_observer: Arc<dyn boatramp_cluster::raft::ApplyObserver> =
        Arc::new(DaemonConfigObserver(daemon_runtime));

    let node = Arc::new(
        build_node(ClusterParams {
            node_id: cluster_cfg.node_id,
            peers,
            // Empty ⇒ every peer votes; otherwise the listed ids are the voting
            // quorum and the rest join as read-only learners (multi-region).
            voters: cluster_cfg.voters.iter().copied().collect(),
            durable_kv,
            storage: storage.clone(),
            mesh: mesh_tls.clone(),
            cluster_write_capability: write_capability,
            extra_observers: vec![daemon_observer],
        })
        .await?,
    );

    // Serve this node's peer mesh over RFC 7250 raw-public-key mutual TLS 1.3:
    // every `/raft/*` + `/stream/*` request must present a trusted peer key. The
    // application `client-write` is additionally gated by the authorizer.
    let mesh_router = match write_authz {
        Some(authz) => node.router.clone().layer(axum::Extension::<
            boatramp_cluster::http::WriteAuthz,
        >(Some(authz))),
        None => node.router.clone(),
    };
    let mesh_config =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(mesh_tls.server()?));
    let listen = cluster_cfg.listen;
    tracing::info!(
        node_id = cluster_cfg.node_id, %listen,
        "cluster: serving peer mesh (mutual TLS)"
    );
    tokio::spawn(async move {
        if let Err(err) = axum_server::bind_rustls(listen, mesh_config)
            .serve(mesh_router.into_make_service())
            .await
        {
            tracing::error!(%err, "cluster: peer mesh server exited");
        }
    });

    // Initialize a brand-new cluster from this node (once), if configured.
    if cluster_cfg.bootstrap {
        node.bootstrap().await?;
        tracing::info!("cluster: bootstrapped membership");
    }

    // The mesh control hook: `POST /api/cluster/join` +
    // `/rotate-key` reach the cluster runtime through it.
    options.mesh_control = Some(Arc::new(ClusterMeshControl(node.clone())));

    // Scheduled mesh key rotation. Node-local, NOT leader-gated:
    // each node rotates its OWN key (only it holds/mints its private key), and
    // make-before-break is per-node + fail-safe, so nodes rotating independently
    // (even concurrently) is harmless. Absent cadence ⇒ manual rotation only.
    if let Some(interval) = mesh_cfg
        .key_rotation
        .as_deref()
        .and_then(parse_rotation_interval)
    {
        let rotate_node = node.clone();
        // Stagger the first rotation by node id (seconds) so a fleet booted
        // together doesn't rotate in lockstep; then every `interval`.
        let stagger = std::time::Duration::from_secs(cluster_cfg.node_id % 60);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval + stagger).await;
                match rotate_node.rotate_key(MESH_ROTATION_PROPAGATION).await {
                    Ok(pubkey) => tracing::info!(
                        pubkey = %pubkey.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "cluster: rotated mesh key on schedule"
                    ),
                    Err(err) => {
                        tracing::error!(%err, "cluster: scheduled mesh key rotation failed")
                    }
                }
            }
        });
    }

    // The control-plane KvStore + messaging are the cluster facades.
    let kv: Arc<dyn KvStore> = node.kv.clone();
    // Cluster-wide rate limiting shares the *replicated* RaftKv across nodes.
    if args.cluster_rate_limit || config.serve.as_ref().is_some_and(|s| s.cluster_rate_limit) {
        options.cluster_rate_limit_kv = Some(kv.clone());
    }
    // SIGHUP also force-reloads the daemon config (the ApplyObserver already
    // handles replicated `daemon/*` writes; this is the manual override).
    spawn_sighup_reload(kv.clone(), options.daemon_runtime.clone());
    let cluster_serve_cfg = config.serve.clone().unwrap_or_default();
    let auth = configure_auth(
        cluster_serve_cfg.signer.as_ref(),
        args.auth_root_private_key
            .clone()
            .or(cluster_serve_cfg.auth_root_private_key.clone()),
        args.auth_root_public_key
            .clone()
            .or(cluster_serve_cfg.auth_root_public_key),
        &mut options,
        kv.clone(),
    )
    .await?;
    configure_oidc(&args, &mut options).await?;
    // Fail-closed: don't expose an unauthenticated control plane on a public bind.
    enforce_auth_bind(addr, &auth, &options.posture)?;
    let handlers = build_handler_runtime(
        kv.clone(),
        storage.clone(),
        &data_dir,
        config.handlers.as_ref(),
        Some(node.messaging.clone()),
        options.posture.max_handler_blob_bytes,
        options.posture.max_component_bytes,
    )?;
    // Cron single-firing: only the Raft leader fires.
    let raft = node.raft.clone();
    let node_id = node.node_id;
    handlers.set_cron_leader_gate(Arc::new(move || {
        boatramp_cluster::raft::is_leader(&raft, node_id)
    }));

    let compute_storage = storage.clone();
    let deploy = DeployStore::new(storage, kv);

    // Compute reconcile loop — leader-gated like cron.
    {
        let raft = node.raft.clone();
        let leader_node_id = node.node_id;
        let (compute_backends, compute_node) = build_compute(
            config.compute.as_ref(),
            compute_storage,
            &data_dir,
            cluster_cfg.node_id,
            !options.posture.allow_shared_kernel_compute,
            options.daemon_runtime.clone(),
        )
        .await;
        let _reconcile = boatramp_server::spawn_compute_reconcile(
            deploy.clone(),
            compute_backends,
            vec![compute_node],
            boatramp_core::compute::BackendPolicy {
                // Strict posture: VM/platform isolation only.
                require_strong_isolation: !options.posture.allow_shared_kernel_compute,
                ..Default::default()
            },
            Arc::new(move || boatramp_cluster::raft::is_leader(&raft, leader_node_id)),
            COMPUTE_RECONCILE_TICK,
            COMPUTE_IDLE_TIMEOUT,
        );
    }

    tracing::info!(tls = ?args.tls, "cluster: serving public traffic");
    #[cfg(feature = "tls")]
    if !matches!(args.tls, TlsMode::Off) {
        let redirect = args
            .http_redirect_addr
            .or_else(|| config.serve.as_ref().and_then(|s| s.http_redirect_addr));
        if let Some(redirect_addr) = redirect {
            spawn_http_redirect(redirect_addr, deploy.clone(), options.posture);
        }
    }
    let serve_result = match args.tls {
        TlsMode::Off => boatramp_server::serve_with(addr, deploy, auth, handlers, options)
            .await
            .map_err(Error::Serve),
        TlsMode::Custom => serve_custom(&args, addr, deploy, auth, handlers, options).await,
        TlsMode::Acme => serve_acme(&args, addr, deploy, auth, handlers, options).await,
        // Raw-public-key control channel: a self-signed RPK identity the client
        // pins — no cluster cert management needed, so it serves like single-node.
        TlsMode::Rpk => serve_rpk(&args, addr, deploy, auth, handlers, options, &data_dir).await,
        // Cluster-managed certs: the leader issues + stores in the
        // replicated control plane; every node serves the replicated cert.
        #[cfg(feature = "acme-dns")]
        TlsMode::AcmeDns => {
            // Wrap replicated cert private keys at rest when `[secrets]` is set.
            let cert_store: Arc<dyn boatramp_core::cert::CertStore> =
                match build_cert_envelope(config.secrets.as_ref(), &data_dir)? {
                    Some(envelope) => Arc::new(boatramp_core::cert::KvCertStore::with_envelope(
                        node.kv.clone(),
                        envelope,
                    )),
                    None => Arc::new(boatramp_core::cert::KvCertStore::new(node.kv.clone())),
                };
            let cert_raft = node.raft.clone();
            let cert_node_id = node.node_id;
            serve_cluster_acme_dns(
                &args,
                addr,
                deploy,
                auth,
                handlers,
                options,
                cert_store,
                move || boatramp_cluster::raft::is_leader(&cert_raft, cert_node_id),
            )
            .await
        }
        #[cfg(not(feature = "acme-dns"))]
        TlsMode::AcmeDns => serve_acme_dns(&args, addr, deploy, auth, handlers, options).await,
    };

    // Graceful shutdown: force a final flush of the durable Raft store so no
    // committed log/state write is lost to the flush timer (SHUT-1).
    if let Err(e) = durable_kv_handle.flush().await {
        tracing::warn!(error = %e, "cluster: durable Raft store flush on shutdown failed");
    } else {
        tracing::info!("cluster: durable Raft store flushed on shutdown");
    }
    serve_result
}

/// Serve HTTPS with **cluster-managed** ACME DNS-01 certs:
/// the leader issues each cert (sole writer of the DNS-01 TXT — no races) and
/// stores it in the replicated control plane; every node loads the stored cert
/// and serves it, hot-swapping on renewal. The live CA round-trip needs
/// live-platform validation; the store↔serve bridge + leader-gating are unit-tested
/// (`crate::cluster_tls`).
#[cfg(all(feature = "cluster", feature = "acme-dns"))]
#[allow(clippy::too_many_arguments)]
async fn serve_cluster_acme_dns(
    args: &ServeArgs,
    addr: SocketAddr,
    deploy: DeployStore,
    auth: boatramp_server::Auth,
    handlers: boatramp_server::HandlerRuntime,
    options: boatramp_server::ServerOptions,
    cert_store: Arc<dyn boatramp_core::cert::CertStore>,
    is_leader: impl Fn() -> bool + Send + Sync + Clone + 'static,
) -> Result<()> {
    use boatramp_acme::acme::CertRequest;
    use std::time::Duration;

    if args.acme_domain.is_empty() {
        return Err(Error::NoAcmeDomainDns);
    }
    install_crypto_provider();

    let kind = parse_dns_provider(&args.acme_dns_provider)?;
    let provider: Arc<dyn boatramp_acme::dns::DnsProvider> =
        crate::acme_dns::build_provider(kind).await?.into();
    let base = CertRequest {
        directory_url: args.acme_directory.clone(),
        contact_email: args.acme_contact.clone(),
        domains: Vec::new(),
        dns_ttl: 60,
        propagation_delay: Duration::from_secs(15),
        timeout: Duration::from_secs(120),
    };
    let domains = crate::acme_dns::server_domains(&args.acme_domain, args.acme_wildcard_preview);
    let cache = args.acme_cache.clone();

    // Initial pass: the leader issues any missing cert + stores it; all nodes
    // load whatever is in the replicated store.
    let entries =
        cluster_refresh_certs(&cert_store, &domains, is_leader(), &provider, &base, &cache).await?;
    if entries.is_empty() {
        return Err(Error::NoCertsYet);
    }
    // HTTP/3: when enabled, stand up a QUIC endpoint sharing the same
    // ACME certs (build_server_configs gives a `h3`-ALPN config off one resolver);
    // its cert is hot-swapped on renewal below, exactly as the TCP path reloads.
    #[cfg(feature = "http3")]
    let (config, h3_endpoint) = if args.http3 {
        let (tcp, h3) = crate::acme_dns::build_server_configs(entries)?;
        let endpoint =
            boatramp_server::http3_endpoint(addr, boatramp_server::quinn_server_config(h3)?)?;
        (tcp, Some(endpoint))
    } else {
        (crate::acme_dns::build_server_config(entries)?, None)
    };
    #[cfg(not(feature = "http3"))]
    let config = crate::acme_dns::build_server_config(entries)?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

    // Background renewal: re-run the leader-gated pass and hot-swap (TCP + h3).
    {
        let (tls, cert_store, provider, base, cache, domains, is_leader) = (
            tls.clone(),
            cert_store.clone(),
            provider.clone(),
            base.clone(),
            cache.clone(),
            domains.clone(),
            is_leader.clone(),
        );
        #[cfg(feature = "http3")]
        let h3_renew = h3_endpoint.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
                match cluster_refresh_certs(
                    &cert_store,
                    &domains,
                    is_leader(),
                    &provider,
                    &base,
                    &cache,
                )
                .await
                {
                    Ok(entries) if !entries.is_empty() => {
                        #[cfg(feature = "http3")]
                        if let Some(endpoint) = &h3_renew {
                            match crate::acme_dns::build_server_configs(entries) {
                                Ok((tcp, h3)) => {
                                    tls.reload_from_config(Arc::new(tcp));
                                    match boatramp_server::quinn_server_config(h3) {
                                        Ok(qc) => endpoint.set_server_config(Some(qc)),
                                        Err(err) => {
                                            tracing::error!(%err, "cluster acme-dns: rebuilding h3 config failed")
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(%err, "cluster acme-dns: rebuilding TLS config failed")
                                }
                            }
                        } else {
                            match crate::acme_dns::build_server_config(entries) {
                                Ok(config) => tls.reload_from_config(Arc::new(config)),
                                Err(err) => {
                                    tracing::error!(%err, "cluster acme-dns: rebuilding TLS config failed")
                                }
                            }
                        }
                        #[cfg(not(feature = "http3"))]
                        match crate::acme_dns::build_server_config(entries) {
                            Ok(config) => tls.reload_from_config(Arc::new(config)),
                            Err(err) => {
                                tracing::error!(%err, "cluster acme-dns: rebuilding TLS config failed")
                            }
                        }
                    }
                    Ok(_) => {} // nothing stored yet (follower awaiting the leader)
                    Err(err) => tracing::error!(%err, "cluster acme-dns: renewal failed"),
                }
            }
        });
    }

    tracing::info!(%addr, domains = ?domains, "cluster: serving HTTPS (cluster-managed ACME DNS-01)");
    #[cfg(feature = "handlers")]
    let _scheduler = handlers.spawn_scheduler(deploy.clone());
    let handle = spawn_tls_shutdown();
    let app = boatramp_server::router_with(deploy, auth, handlers, options);
    // Serve h3 over the QUIC endpoint + advertise it on the HTTPS responses.
    #[cfg(feature = "http3")]
    let app = if let Some(endpoint) = h3_endpoint {
        let app_h3 = app.clone();
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_http3_endpoint(endpoint, app_h3).await {
                tracing::error!(%err, "cluster acme-dns: HTTP/3 listener failed");
            }
        });
        boatramp_server::advertise_http3(app, addr.port())
    } else {
        app
    };
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// One leader-gated refresh pass: per domain, the leader issues (live CA, via
/// `obtain_or_load`) + stores; every node loads the stored cert. Returns the
/// `(domain, cert)` entries to serve.
#[cfg(all(feature = "cluster", feature = "acme-dns"))]
async fn cluster_refresh_certs(
    cert_store: &Arc<dyn boatramp_core::cert::CertStore>,
    domains: &[String],
    is_leader: bool,
    provider: &Arc<dyn boatramp_acme::dns::DnsProvider>,
    base: &boatramp_acme::acme::CertRequest,
    cache: &Path,
) -> Result<Vec<(String, boatramp_acme::acme::IssuedCert)>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // The `issue` closure yields a *typed* error (`acme_dns::Error`); the
    // refresh itself fails with `cluster_tls::Error`, propagated via `?` into
    // our `ClusterTls` variant. (See `cluster_tls::refresh_entries` — its `Fut`
    // output bound must accept this typed error, not a boxed dynamic one.)
    let entries = crate::cluster_tls::refresh_entries(
        cert_store.as_ref(),
        domains,
        is_leader,
        now,
        |domain| {
            let (provider, base, cache) = (provider.clone(), base.clone(), cache.to_path_buf());
            async move {
                let issued =
                    crate::acme_dns::obtain_or_load(&domain, &base, provider.as_ref(), &cache)
                        .await?;
                Ok::<_, crate::acme_dns::Error>(crate::cluster_tls::issued_to_stored(&issued, now))
            }
        },
    )
    .await?;
    Ok(entries)
}

/// Parse the `--acme-dns-provider` value into a provider kind, using the
/// `ValueEnum` spellings + aliases so **every** built-in provider (all ten) is
/// selectable at serve time — exactly as for the `dns` subcommand (the old
/// hand-rolled match knew only four).
#[cfg(feature = "acme-dns")]
fn parse_dns_provider(value: &str) -> Result<crate::acme_dns::DnsProviderKind> {
    use clap::ValueEnum;
    crate::acme_dns::DnsProviderKind::from_str(value, true)
        .map_err(|_| Error::UnknownDnsProvider(value.to_string()))
}

/// Serve HTTPS with ACME **DNS-01** certificates (wildcards included). Obtains
/// each `--acme-domain` (and, with `--acme-wildcard-preview`, its
/// `*.deploy.<domain>`) via the configured DNS provider, serves them by SNI,
/// and renews in the background. The live CA + DNS round-trip is the
/// integration seam (validated against a Pebble/staging directory + real zone).
#[cfg(feature = "acme-dns")]
async fn serve_acme_dns(
    args: &ServeArgs,
    addr: SocketAddr,
    deploy: DeployStore,
    auth: boatramp_server::Auth,
    handlers: boatramp_server::HandlerRuntime,
    options: boatramp_server::ServerOptions,
) -> Result<()> {
    use std::time::Duration;

    use boatramp_acme::acme::CertRequest;

    if args.acme_domain.is_empty() {
        return Err(Error::NoAcmeDomainDns);
    }
    install_crypto_provider();

    let kind = parse_dns_provider(&args.acme_dns_provider)?;
    let provider = crate::acme_dns::build_provider(kind).await?;
    let base = CertRequest {
        directory_url: args.acme_directory.clone(),
        contact_email: args.acme_contact.clone(),
        domains: Vec::new(),
        dns_ttl: 60,
        propagation_delay: Duration::from_secs(15),
        timeout: Duration::from_secs(120),
    };
    let domains = crate::acme_dns::server_domains(&args.acme_domain, args.acme_wildcard_preview);

    // Obtain (or load cached) certs for every domain up front.
    let entries = obtain_all(&domains, &base, provider.as_ref(), &args.acme_cache).await?;
    // HTTP/3: a QUIC endpoint sharing the same ACME certs, hot-swapped on
    // renewal below.
    #[cfg(feature = "http3")]
    let (config, h3_endpoint) = if args.http3 {
        let (tcp, h3) = crate::acme_dns::build_server_configs(entries)?;
        let endpoint =
            boatramp_server::http3_endpoint(addr, boatramp_server::quinn_server_config(h3)?)?;
        (tcp, Some(endpoint))
    } else {
        (crate::acme_dns::build_server_config(entries)?, None)
    };
    #[cfg(not(feature = "http3"))]
    let config = crate::acme_dns::build_server_config(entries)?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

    // Background renewal: re-load (reissuing any near-expiry cert) and hot-swap
    // the served config (TCP + h3), so the process never needs a restart to renew.
    {
        let (tls, base, cache) = (tls.clone(), base.clone(), args.acme_cache.clone());
        let domains = domains.clone();
        let provider = crate::acme_dns::build_provider(kind).await?;
        #[cfg(feature = "http3")]
        let h3_renew = h3_endpoint.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
                match obtain_all(&domains, &base, provider.as_ref(), &cache).await {
                    Ok(entries) => {
                        #[cfg(feature = "http3")]
                        if let Some(endpoint) = &h3_renew {
                            match crate::acme_dns::build_server_configs(entries) {
                                Ok((tcp, h3)) => {
                                    tls.reload_from_config(Arc::new(tcp));
                                    match boatramp_server::quinn_server_config(h3) {
                                        Ok(qc) => endpoint.set_server_config(Some(qc)),
                                        Err(err) => {
                                            tracing::error!(%err, "acme-dns: rebuilding h3 config failed")
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(%err, "acme-dns: rebuilding TLS config failed")
                                }
                            }
                        } else {
                            match crate::acme_dns::build_server_config(entries) {
                                Ok(config) => tls.reload_from_config(Arc::new(config)),
                                Err(err) => {
                                    tracing::error!(%err, "acme-dns: rebuilding TLS config failed")
                                }
                            }
                        }
                        #[cfg(not(feature = "http3"))]
                        match crate::acme_dns::build_server_config(entries) {
                            Ok(config) => tls.reload_from_config(Arc::new(config)),
                            Err(err) => {
                                tracing::error!(%err, "acme-dns: rebuilding TLS config failed")
                            }
                        }
                    }
                    Err(err) => tracing::error!(%err, "acme-dns: renewal failed"),
                }
            }
        });
    }

    tracing::info!(%addr, domains = ?domains, "serving HTTPS (ACME DNS-01)");
    // Background scheduler (consumers/crons) — must run under TLS too, not only
    // `--tls off`; in cluster mode its cron tick is gated on `is_leader`. The
    // handle detaches for the server's lifetime.
    #[cfg(feature = "handlers")]
    let _scheduler = handlers.spawn_scheduler(deploy.clone());
    let handle = spawn_tls_shutdown();
    let app = boatramp_server::router_with(deploy, auth, handlers, options);
    #[cfg(feature = "http3")]
    let app = if let Some(endpoint) = h3_endpoint {
        let app_h3 = app.clone();
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_http3_endpoint(endpoint, app_h3).await {
                tracing::error!(%err, "acme-dns: HTTP/3 listener failed");
            }
        });
        boatramp_server::advertise_http3(app, addr.port())
    } else {
        app
    };
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// Obtain (or load) every domain's cert, returning `(SNI-pattern, cert)` pairs.
#[cfg(feature = "acme-dns")]
async fn obtain_all(
    domains: &[String],
    base: &boatramp_acme::acme::CertRequest,
    provider: &dyn boatramp_acme::dns::DnsProvider,
    cache: &Path,
) -> Result<Vec<(String, boatramp_acme::acme::IssuedCert)>> {
    let mut entries = Vec::with_capacity(domains.len());
    for domain in domains {
        let cert = crate::acme_dns::obtain_or_load(domain, base, provider, cache).await?;
        entries.push((domain.clone(), cert));
    }
    Ok(entries)
}

#[cfg(not(feature = "acme-dns"))]
async fn serve_acme_dns(
    _args: &ServeArgs,
    _addr: SocketAddr,
    _deploy: DeployStore,
    _auth: boatramp_server::Auth,
    _handlers: boatramp_server::HandlerRuntime,
    _options: boatramp_server::ServerOptions,
) -> Result<()> {
    Err(Error::NoAcmeDnsSupport)
}

/// Build the WebAssembly handler runtime. With the `handlers` feature it wraps a
/// wasmtime engine serving the kv/blob bindings from the server's own backends;
/// otherwise it is an empty placeholder (handler routes fall through to static).
#[cfg(feature = "handlers")]
fn build_handler_runtime(
    kv: Arc<dyn KvStore>,
    storage: Arc<dyn boatramp_core::Storage>,
    data_dir: &Path,
    handlers_cfg: Option<&crate::config::HandlersConfig>,
    messaging_override: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    max_blob_bytes: u64,
    max_component_bytes: u64,
) -> Result<boatramp_server::HandlerRuntime> {
    // Opt-in pooling allocator: faster instantiation, large
    // up-front virtual reservation — benchmark before enabling.
    let limits = boatramp_handlers::Limits::default();
    let engine = if handlers_cfg.is_some_and(|h| h.pooling) {
        boatramp_handlers::HandlerEngine::with_pooling(limits, 64)?
    } else {
        boatramp_handlers::HandlerEngine::new(limits, 64)?
    };
    let sql = build_sql_backends(handlers_cfg.and_then(|h| h.bindings.sql.as_ref()), data_dir)?;
    // The `wasi:messaging` substrate: single-node `LogMessaging` over the same
    // blob/KV backends by default, or the cluster coordinator when one is given.
    let messaging: Arc<dyn boatramp_core::messaging::Messaging> = messaging_override
        .unwrap_or_else(|| {
            Arc::new(boatramp_core::messaging::LogMessaging::new(
                storage.clone(),
                kv.clone(),
            ))
        });
    let runtime =
        boatramp_server::HandlerRuntime::new(engine, kv, storage, Some(sql), Some(messaging));
    // Apply the posture's host-side blob cap + component-size cap.
    runtime.set_max_blob_bytes(max_blob_bytes);
    runtime.set_max_component_bytes(max_component_bytes);
    Ok(runtime)
}

/// Resolve the `[handlers.bindings.sql]` config to the libsql SQL backend.
/// Single-node by default (an embedded file per site under `<data-dir>`); set
/// `url` to bind a shared sqld cluster (a namespace per site). Either way sites
/// get a real database boundary — see `boatramp_core::sql`.
#[cfg(feature = "handlers")]
fn build_sql_backends(
    cfg: Option<&crate::config::SqlBindingConfig>,
    data_dir: &Path,
) -> Result<Arc<dyn boatramp_core::sql::SqlBackends>> {
    let resolve_env = |var: &Option<String>| -> Result<Option<String>> {
        match var {
            Some(var) => Ok(Some(
                std::env::var(var).map_err(|_| Error::SqlEnvUnset(var.clone()))?,
            )),
            None => Ok(None),
        }
    };

    let backend = match cfg.and_then(|c| c.url.as_ref()) {
        // Cluster: a sqld namespace per site. Auth tokens come from the
        // environment, never the config file.
        Some(url) => {
            let cfg = cfg.expect("url implies cfg");
            let admin_url = cfg.admin_url.as_ref().ok_or(Error::SqlAdminUrlRequired)?;
            let token = resolve_env(&cfg.token_env)?.unwrap_or_default();
            let admin_token = resolve_env(&cfg.admin_token_env)?;
            let backends = boatramp_storage::LibsqlSqlBackends::remote(
                url.clone(),
                admin_url.clone(),
                token,
                admin_token,
            );
            // Optional read-replica routing: reads → replica, writes → primary.
            match &cfg.replica_url {
                Some(replica_url) => backends.with_read_replica(replica_url.clone()),
                None => backends,
            }
        }
        // Single-node: an embedded file per site.
        None => {
            let dir = cfg
                .and_then(|c| c.dir.clone())
                .unwrap_or_else(|| data_dir.join("handlers-sql"));
            boatramp_storage::LibsqlSqlBackends::local(dir)
        }
    };
    // Preview SQL policy (how preview deployments relate to live data).
    let preview_mode = match cfg.and_then(|c| c.preview_mode.as_deref()) {
        None | Some("empty") => boatramp_core::sql::PreviewSqlMode::Empty,
        Some("branch") => boatramp_core::sql::PreviewSqlMode::Branch,
        Some("shared") => boatramp_core::sql::PreviewSqlMode::Shared,
        Some(other) => return Err(Error::UnknownPreviewMode(other.to_string())),
    };
    let preview_init = match cfg.and_then(|c| c.preview_init.as_ref()) {
        Some(path) => {
            Some(
                std::fs::read_to_string(path).map_err(|err| Error::PreviewInitRead {
                    path: path.clone(),
                    source: err,
                })?,
            )
        }
        None => None,
    };
    Ok(Arc::new(
        backend.with_preview_policy(preview_mode, preview_init),
    ))
}

#[cfg(not(feature = "handlers"))]
fn build_handler_runtime(
    _kv: Arc<dyn KvStore>,
    _storage: Arc<dyn boatramp_core::Storage>,
    _data_dir: &Path,
    _handlers_cfg: Option<&crate::config::HandlersConfig>,
    _messaging_override: Option<Arc<dyn boatramp_core::messaging::Messaging>>,
    _max_blob_bytes: u64,
    _max_component_bytes: u64,
) -> Result<boatramp_server::HandlerRuntime> {
    Ok(boatramp_server::HandlerRuntime::disabled())
}

/// Build the control-plane [`Auth`](boatramp_server::Auth) from the resolved
/// root-key settings (flag/env > `serve` config). For an issuing node (a
/// private key) it also sets `options.issuer` so the token-create and
/// OIDC-exchange routes can mint. No key ⇒ auth disabled (dev).
/// Fail-closed bind guard: refuse to expose an unauthenticated
/// control plane on a non-loopback listener unless the posture explicitly allows
/// it, and warn loudly for any auth-disabled listener.
fn enforce_auth_bind(
    addr: SocketAddr,
    auth: &boatramp_server::Auth,
    posture: &boatramp_core::security::SecurityPosture,
) -> Result<()> {
    if auth.is_disabled() {
        if !addr.ip().is_loopback() && !posture.allow_unauthenticated_public_bind {
            return Err(Error::UnauthenticatedPublicBind { addr });
        }
        tracing::warn!(
            %addr,
            "control-plane auth is DISABLED — do not expose this listener to an untrusted network"
        );
    }
    Ok(())
}

async fn configure_auth(
    signer: Option<&crate::config::AuthSignerConfig>,
    private_key: Option<String>,
    public_key: Option<String>,
    options: &mut boatramp_server::ServerOptions,
    kv: Arc<dyn KvStore>,
) -> Result<boatramp_server::Auth> {
    use boatramp_core::cose::{LocalSigner, Signer, TokenPublicKey};
    // An external signer (KMS/HSM/Vault) issues *and* provides the trust anchor:
    // it resolves its own public key at connect.
    if let Some(cfg) = signer {
        let issuer = boatramp_server::signer::build_signer(&cfg.to_signer_config())
            .await
            .map_err(|e| Error::AuthPrivKey(e.to_string()))?;
        let public = issuer.public_key();
        options.issuer = Some(issuer);
        return Ok(boatramp_server::Auth::with_key(public, kv));
    }
    if let Some(hex) = private_key {
        let signer =
            LocalSigner::from_private_hex(&hex).map_err(|e| Error::AuthPrivKey(e.to_string()))?;
        let public = signer.public_key();
        options.issuer = Some(Arc::new(signer) as Arc<dyn Signer>);
        return Ok(boatramp_server::Auth::with_key(public, kv));
    }
    if let Some(hex) = public_key {
        let public =
            TokenPublicKey::from_hex(&hex).map_err(|e| Error::AuthPubKey(e.to_string()))?;
        return Ok(boatramp_server::Auth::with_key(public, kv));
    }
    Ok(boatramp_server::Auth::disabled())
}

/// Construct the OIDC verifier for `/api/auth/exchange` when `--oidc-issuer` is
/// set (fetching the issuer's JWKS now — the live network step) and
/// stash it in `options`. No-op without the `oidc` feature or the flag.
#[cfg(feature = "oidc")]
async fn configure_oidc(
    args: &ServeArgs,
    options: &mut boatramp_server::ServerOptions,
) -> Result<()> {
    let Some(issuer) = args.oidc_issuer.clone() else {
        return Ok(());
    };
    // Without an audience, a JWT minted for a different client at the
    // same issuer could be exchanged for a token. The posture can require one.
    if options.posture.oidc_require_audience && args.oidc_audience.is_none() {
        return Err(Error::OidcAudienceRequired);
    }
    let mut config = boatramp_server::OidcConfig::new(issuer);
    config.audience = args.oidc_audience.clone();
    if let Some(claim) = args.oidc_scope_claim.clone() {
        config.scope_claim = claim;
    }
    let http = reqwest::Client::new();
    let verifier = Arc::new(
        boatramp_server::OidcVerifier::from_discovery(&http, &config)
            .await
            .map_err(|err| Error::OidcSetup(err.to_string()))?,
    );
    tracing::info!(issuer = %config.issuer, "OIDC → token exchange enabled");
    // Periodically re-fetch the JWKS so an IdP key rollover is picked up without
    // a restart. Detached for the server's lifetime; fetch failures are logged.
    {
        let verifier = verifier.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                if let Err(err) = verifier.refresh().await {
                    tracing::warn!(%err, "OIDC JWKS refresh failed (keeping current keys)");
                }
            }
        });
    }
    options.oidc_verifier = Some(verifier);
    Ok(())
}

#[cfg(not(feature = "oidc"))]
async fn configure_oidc(
    _args: &ServeArgs,
    _options: &mut boatramp_server::ServerOptions,
) -> Result<()> {
    Ok(())
}

#[cfg(feature = "tls")]
async fn serve_custom(
    args: &ServeArgs,
    addr: SocketAddr,
    deploy: DeployStore,
    auth: boatramp_server::Auth,
    handlers: boatramp_server::HandlerRuntime,
    options: boatramp_server::ServerOptions,
) -> Result<()> {
    install_crypto_provider();
    let cert = args.tls_cert.clone().ok_or(Error::TlsCertRequired)?;
    let key = args.tls_key.clone().ok_or(Error::TlsKeyRequired)?;

    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await?;
    tracing::info!(%addr, "serving HTTPS (custom certificate)");
    // Background scheduler (consumers/crons) — must run under TLS too, not only
    // `--tls off`; in cluster mode its cron tick is gated on `is_leader`. The
    // handle detaches for the server's lifetime.
    #[cfg(feature = "handlers")]
    let _scheduler = handlers.spawn_scheduler(deploy.clone());
    let handle = spawn_tls_shutdown();
    let app = boatramp_server::router_with(deploy, auth, handlers, options);

    // Optionally serve HTTP/3 on the same UDP port, feeding the same router, and
    // advertise it (`Alt-Svc`) on the HTTPS responses so clients upgrade to h3 —
    // without the header the h3 listener is never discovered.
    #[cfg(feature = "http3")]
    let app = if args.http3 {
        let (certs, key) = load_cert_chain_and_key(&cert, &key)?;
        let app_h3 = app.clone();
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_http3(addr, certs, key, app_h3).await {
                tracing::error!(%err, "HTTP/3 listener failed");
            }
        });
        boatramp_server::advertise_http3(app, addr.port())
    } else {
        app
    };

    axum_server::bind_rustls(addr, config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// Serve the control-plane over **RFC 7250 raw-public-key TLS** (`--tls rpk`):
/// present a persisted control-plane RPK identity the client pins, with the
/// client authenticating via a bearer token (a server-authenticated channel). No
/// ACME, tunnel, or TLS-terminating proxy — an encrypted first-boot / bare-metal
/// control plane.
///
/// The identity is a dedicated `<data-dir>/controlplane-tls.key` (Ed25519,
/// `0600`), **not** the root auth key: the root key may be remote/async
/// (KMS/HSM) while rustls needs a local synchronous signing key, and
/// cross-protocol key reuse is poor hygiene. The public-key fingerprint is
/// logged + printed at startup so the operator can pin it (`--server-pubkey`).
#[cfg(feature = "tls")]
async fn serve_rpk(
    _args: &ServeArgs,
    addr: SocketAddr,
    deploy: DeployStore,
    auth: boatramp_server::Auth,
    handlers: boatramp_server::HandlerRuntime,
    mut options: boatramp_server::ServerOptions,
    data_dir: &Path,
) -> Result<()> {
    install_crypto_provider();

    let key_file = data_dir.join("controlplane-tls.key");
    let identity = boatramp_rpktls::RpkIdentity::load_or_generate(&key_file)?;
    let fingerprint = identity.public_key_hex();

    // If this node holds the root signing key, mint a root-signed attestation of
    // this TLS identity and serve it at `/.well-known/boatramp-bootstrap-identity`
    // so a client can pin *only* the root key and learn the TLS key from the
    // attestation. A verify-only node (no issuer) skips it; the client then pins
    // the printed identity directly with `--server-pubkey`.
    if let Some(signer) = options.issuer.clone() {
        // A year: the attested key is stable across restarts (persisted key file);
        // rotating the identity re-mints a fresh attestation on next boot.
        const ATTESTATION_TTL_SECS: u64 = 365 * 24 * 60 * 60;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match boatramp_core::cose::mint_attestation(
            &fingerprint,
            ATTESTATION_TTL_SECS,
            now,
            signer.as_ref(),
        )
        .await
        {
            Ok(att) => options.bootstrap_attestation = Some(att),
            Err(err) => {
                tracing::warn!(%err, "could not mint the bootstrap-TLS attestation; --root-pubkey pinning unavailable")
            }
        }
    }

    // No client-auth trust set: the client authenticates with a bearer token, not
    // a client cert (that is the mutual-`cnf` binding of a later stage).
    let rpk = boatramp_rpktls::RpkTls::new(Arc::new(identity), boatramp_rpktls::TrustSet::default());
    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(rpk.server_auth()?));

    tracing::info!(%addr, pubkey = %fingerprint, "serving HTTPS (RPK bootstrap TLS)");
    // The identity is public (not a secret); print it so the operator can copy it
    // to the client's `--server-pubkey`.
    println!("control-plane RPK TLS identity — pin the client with:\n  --server-pubkey {fingerprint}");

    #[cfg(feature = "handlers")]
    let _scheduler = handlers.spawn_scheduler(deploy.clone());
    let handle = spawn_tls_shutdown();
    let app = boatramp_server::router_with(deploy, auth, handlers, options);
    axum_server::bind_rustls(addr, config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

/// Load a PEM cert chain + private key as DER, for the HTTP/3 (quinn) listener.
#[cfg(feature = "http3")]
fn load_cert_chain_and_key(
    cert: &Path,
    key: &Path,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_pem = std::fs::read(cert)?;
    let certs =
        rustls_pemfile::certs(&mut &cert_pem[..]).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(Error::NoCert(cert.display().to_string()));
    }
    let key_pem = std::fs::read(key)?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| Error::NoPrivateKey(key.display().to_string()))?;
    Ok((certs, key))
}

#[cfg(feature = "tls")]
async fn serve_acme(
    args: &ServeArgs,
    addr: SocketAddr,
    deploy: DeployStore,
    auth: boatramp_server::Auth,
    handlers: boatramp_server::HandlerRuntime,
    options: boatramp_server::ServerOptions,
) -> Result<()> {
    use futures::StreamExt;
    use rustls_acme::{caches::DirCache, AcmeConfig};

    if args.acme_domain.is_empty() {
        return Err(Error::NoAcmeDomain);
    }
    install_crypto_provider();

    let mut config = AcmeConfig::new(args.acme_domain.clone())
        .cache(DirCache::new(args.acme_cache.clone()))
        .directory(args.acme_directory.clone());
    if let Some(contact) = &args.acme_contact {
        config = config.contact_push(format!("mailto:{contact}"));
    }
    if let Some(ca) = &args.acme_ca_cert {
        config = config.client_tls_config(acme_client_config(ca)?);
    }

    let mut state = config.state();
    let acceptor = state.axum_acceptor(state.default_rustls_config());
    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(event)) => tracing::info!("acme: {event:?}"),
                Some(Err(err)) => tracing::error!("acme error: {err}"),
                None => break,
            }
        }
    });

    tracing::info!(%addr, domains = ?args.acme_domain, "serving HTTPS (ACME)");
    // Background scheduler (consumers/crons) — must run under TLS too, not only
    // `--tls off`; in cluster mode its cron tick is gated on `is_leader`. The
    // handle detaches for the server's lifetime.
    #[cfg(feature = "handlers")]
    let _scheduler = handlers.spawn_scheduler(deploy.clone());
    let handle = spawn_tls_shutdown();
    axum_server::bind(addr)
        .handle(handle)
        .acceptor(acceptor)
        .serve(
            boatramp_server::router_with(deploy, auth, handlers, options)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    Ok(())
}

/// Install a process-wide default rustls crypto provider (rustls 0.23 requires
/// one before building any TLS config). Idempotent.
#[cfg(feature = "tls")]
fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// An `axum_server::Handle` that triggers graceful shutdown (10s drain) when a
/// Ctrl-C / SIGTERM signal arrives, matching the plain-HTTP listener.
#[cfg(feature = "tls")]
fn spawn_tls_shutdown() -> axum_server::Handle<SocketAddr> {
    let handle = axum_server::Handle::new();
    let trigger = handle.clone();
    tokio::spawn(async move {
        boatramp_server::shutdown_signal().await;
        trigger.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });
    handle
}

/// Build a rustls client config that trusts an extra root CA (for a test ACME
/// server like Pebble whose directory uses a self-signed certificate).
#[cfg(feature = "tls")]
fn acme_client_config(ca_path: &std::path::Path) -> Result<Arc<rustls::ClientConfig>> {
    let pem = std::fs::read(ca_path)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert?)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(not(feature = "tls"))]
async fn serve_custom(
    _args: &ServeArgs,
    _addr: SocketAddr,
    _deploy: DeployStore,
    _auth: boatramp_server::Auth,
    _handlers: boatramp_server::HandlerRuntime,
    _options: boatramp_server::ServerOptions,
) -> Result<()> {
    Err(Error::NoTlsSupport)
}

#[cfg(not(feature = "tls"))]
async fn serve_acme(
    _args: &ServeArgs,
    _addr: SocketAddr,
    _deploy: DeployStore,
    _auth: boatramp_server::Auth,
    _handlers: boatramp_server::HandlerRuntime,
    _options: boatramp_server::ServerOptions,
) -> Result<()> {
    Err(Error::NoTlsSupport)
}

#[cfg(not(feature = "tls"))]
async fn serve_rpk(
    _args: &ServeArgs,
    _addr: SocketAddr,
    _deploy: DeployStore,
    _auth: boatramp_server::Auth,
    _handlers: boatramp_server::HandlerRuntime,
    _options: boatramp_server::ServerOptions,
    _data_dir: &Path,
) -> Result<()> {
    Err(Error::NoTlsSupport)
}

async fn build_blobs(args: &ServeArgs, data_dir: &Path) -> Result<Arc<dyn Storage>> {
    match args.blobs {
        BlobBackend::Fs => Ok(Arc::new(FsStorage::new(data_dir.join("blobs")))),
        BlobBackend::S3 => build_s3(args).await,
    }
}

#[cfg(feature = "s3")]
async fn build_s3(args: &ServeArgs) -> Result<Arc<dyn Storage>> {
    let bucket = args.s3_bucket.clone().ok_or(Error::S3BucketRequired)?;
    let storage = boatramp_storage::S3Storage::connect(boatramp_storage::S3Options {
        bucket,
        endpoint: args.s3_endpoint.clone(),
        region: args.s3_region.clone(),
        force_path_style: args.s3_path_style,
    })
    .await;
    Ok(Arc::new(storage))
}

#[cfg(not(feature = "s3"))]
async fn build_s3(_args: &ServeArgs) -> Result<Arc<dyn Storage>> {
    Err(Error::NoS3Support)
}

async fn build_kv(args: &ServeArgs, data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    match args.kv {
        KvBackend::Slatedb => build_slatedb_kv(data_dir).await,
        KvBackend::Memory => Ok(Arc::new(MemoryKv::new())),
        KvBackend::Cloudflare => build_cloudflare_kv(),
    }
}

/// Control-plane flush interval for SlateDB. Deploys are serialized and a human
/// is waiting, so we favour per-write latency over the throughput-oriented
/// ~100 ms default (which the request-driven handler `wasi:keyvalue` store keeps).
#[cfg(feature = "slatedb")]
const CONTROL_PLANE_FLUSH: std::time::Duration = std::time::Duration::from_millis(5);

#[cfg(feature = "slatedb")]
async fn build_slatedb_kv(data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    Ok(Arc::new(
        boatramp_storage::SlateKv::open_local_with_flush(
            data_dir.join("kv-slate"),
            CONTROL_PLANE_FLUSH,
        )
        .await?,
    ))
}

#[cfg(not(feature = "slatedb"))]
async fn build_slatedb_kv(_data_dir: &Path) -> Result<Arc<dyn KvStore>> {
    Err(Error::NoSlatedbSupport)
}

#[cfg(feature = "cloudflare-kv")]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Ok(Arc::new(boatramp_storage::CloudflareKv::from_env()?))
}

#[cfg(not(feature = "cloudflare-kv"))]
fn build_cloudflare_kv() -> Result<Arc<dyn KvStore>> {
    Err(Error::NoCloudflareKvSupport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::security::SecurityProfile;

    /// The mesh write authorizer accepts only a token from the control-plane
    /// root granting `cluster-write` — no token, a wrong-role token, garbage, or a
    /// foreign-root capability are all refused.
    #[cfg(feature = "cluster")]
    #[tokio::test]
    async fn mesh_write_authz_accepts_only_a_cluster_write_capability() {
        use boatramp_cluster::http::ClientWriteAuthz;
        use boatramp_core::authz::GrantedRole;
        use boatramp_core::cose::{self, Claims, LocalSigner, Signer, TokenAlg};

        async fn cap(signer: &dyn Signer, role: &str) -> String {
            let claims = Claims {
                roles: vec![GrantedRole::global(role)],
                kind: cose::KIND_CLUSTER_WRITE.to_string(),
                ttl_secs: None,
                now_unix: 0,
            };
            cose::mint(&claims, signer).await.unwrap()
        }

        let signer = LocalSigner::generate(TokenAlg::Es256);
        let authz = MeshWriteAuthz {
            public: signer.public_key(),
        };

        assert!(
            authz.authorize(Some(&cap(&signer, "cluster-write").await)),
            "a real cluster-write capability"
        );

        assert!(!authz.authorize(None), "no capability");
        assert!(
            !authz.authorize(Some(&cap(&signer, "admin").await)),
            "wrong role"
        );
        assert!(!authz.authorize(Some("not-a-token")), "garbage");

        let other = LocalSigner::generate(TokenAlg::Es256);
        assert!(
            !authz.authorize(Some(&cap(&other, "cluster-write").await)),
            "foreign root key"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn rotation_interval_parses_units_and_rejects_junk() {
        use std::time::Duration;
        assert_eq!(
            parse_rotation_interval("30d"),
            Some(Duration::from_secs(30 * 86_400))
        );
        assert_eq!(
            parse_rotation_interval("12h"),
            Some(Duration::from_secs(12 * 3600))
        );
        assert_eq!(
            parse_rotation_interval("90m"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_rotation_interval(" 45s "),
            Some(Duration::from_secs(45))
        );
        // No unit, unknown unit, zero, and empty are all rejected (⇒ no schedule).
        assert_eq!(parse_rotation_interval("30"), None);
        assert_eq!(parse_rotation_interval("5w"), None);
        assert_eq!(parse_rotation_interval("0d"), None);
        assert_eq!(parse_rotation_interval(""), None);
    }

    /// An auth-disabled non-loopback bind is refused under the strict
    /// posture, allowed on loopback, and allowed when the posture opts in.
    #[test]
    fn fail_closed_refuses_unauthenticated_public_bind() {
        let disabled = boatramp_server::Auth::disabled();
        let strict = SecurityProfile::MultiTenant.preset();
        let dev = SecurityProfile::Dev.preset();
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Auth disabled + public + strict → refused.
        assert!(matches!(
            enforce_auth_bind(public, &disabled, &strict),
            Err(Error::UnauthenticatedPublicBind { .. })
        ));
        // Loopback is always permitted (local-dev convenience).
        assert!(enforce_auth_bind(loopback, &disabled, &strict).is_ok());
        // The `dev` posture opts into an unauthenticated public bind.
        assert!(enforce_auth_bind(public, &disabled, &dev).is_ok());
    }
}
