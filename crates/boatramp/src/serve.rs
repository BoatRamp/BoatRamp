//! The `serve` subcommand: select backends and run the server.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use boatramp_core::cache_coherence::Changelog;
use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::{CachedKv, KvStore};
use boatramp_core::migrate;
use boatramp_node::backends::{BlobBackend, KvBackend};
use clap::ValueEnum;

use crate::config::ServerConfig;

/// The control-plane KV builder, reused by the standalone `boatramp migrate` command.
pub(crate) use boatramp_node::backends::build_kv as build_control_plane_kv;
use boatramp_node::blobs::{BlobArgs, build_blobs};

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
    /// A `--tls custom`/`acme` mode selected but the binary lacks TLS support.
    #[cfg(not(feature = "tls"))]
    #[error("this build has no TLS support; rebuild with `--features tls`")]
    NoTlsSupport,
    /// `--tls acme-dns` selected but the binary lacks ACME DNS-01 support.
    #[cfg(not(feature = "acme-dns"))]
    #[error("this build has no ACME DNS-01 support; rebuild with `--features acme-dns`")]
    NoAcmeDnsSupport,

    // ---- configuration / argument validation -------------------------------
    /// A token root **private** key (hex) failed to parse (cluster write-capability
    /// minting). The single-node auth path's key errors now live in
    /// [`boatramp_node::Error`].
    #[cfg(feature = "cluster")]
    #[error("invalid auth root private key: {0}")]
    AuthPrivKey(String),
    /// A raw-public-key TLS error — building the peer-mesh identity/config
    /// (`cluster`) or the `--tls rpk` bootstrap identity/config (`tls`). Both use
    /// the same RPK stack (`boatramp_rpktls`), so `mesh::MeshError` is an alias of
    /// `RpkError` and they share one `From` here (a second would collide).
    #[cfg(any(feature = "cluster", feature = "tls"))]
    #[error(transparent)]
    RpkTls(#[from] boatramp_rpktls::RpkError),
    /// Refusing to serve the peer mesh on a non-loopback address with no trust set
    /// configured — that would expose an unauthenticated control plane.
    /// The peer mesh has no trust anchor on a non-loopback bind.
    #[cfg(feature = "cluster")]
    #[error(
        "refusing to serve the peer mesh on {0} (non-loopback) with an empty trust \
         set: found with --cluster-init or join with --cluster-join <ticket>"
    )]
    MeshUnconfigured(std::net::SocketAddr),
    /// The cluster startup decision failed closed (F5) or a join could not be
    /// completed (no join token, seeds unreachable, root mismatch, …).
    #[cfg(feature = "cluster")]
    #[error("cluster startup: {0}")]
    ClusterStartup(String),
    /// Configuring the secrets-at-rest envelope failed. Ungated: the #505 node-level sealed S3
    /// credential resolver builds the `[secrets]` envelope on the ordinary `serve` path (not just the
    /// cluster+acme-dns cert path), so this variant must exist in every build.
    #[error("secrets envelope: {0}")]
    Envelope(String),
    /// Enabling the local S3-ingress face failed closed — e.g. a multi-node deployment with no
    /// explicitly configured, cluster-uniform `s3_ingress_secret_file`, or a wrong-length secret
    /// file. Refuse to serve rather than expose an un-verifiable-across-nodes face.
    #[error("local S3-ingress face refused to enable: {0}")]
    S3Ingress(String),
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
    /// The `--tls-cert` PEM held no certificates (custom-cert / HTTP/3 loading).
    #[cfg(feature = "tls")]
    #[error("no certificates in {0}")]
    NoCert(String),
    /// The `--tls-key` PEM held no private key (custom-cert / HTTP/3 loading).
    #[cfg(feature = "tls")]
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
    #[error("no certificates available yet — awaiting the cluster leader to issue (retry shortly)")]
    NoCertsYet,

    // ---- propagated library errors (`#[from]`) ------------------------------
    /// Node-library assembly (handler runtime / SQL binding) failed.
    #[error(transparent)]
    Assembly(#[from] boatramp_node::Error),
    /// Resolving the `[security]` posture (e.g. an unknown profile name) failed.
    #[error(transparent)]
    Security(#[from] boatramp_core::security::SecurityError),
    /// The HTTP server exited with an error.
    #[error(transparent)]
    Serve(#[from] boatramp_server::ServeError),
    /// A listener-bind / filesystem / TLS-accept I/O error on the serve path.
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
    /// The control-plane store holds pre-0.2.0 (layout 1) data and has not been
    /// migrated to the project-scoped layout. Refusing to serve so a half-read
    /// store can't silently drop sites/functions. Run `boatramp migrate` (or start
    /// with `--auto-migrate`).
    #[error(
        "the control-plane store is not migrated to the project-scoped (0.2.0) layout; \
         run `boatramp migrate` first, or start `serve --auto-migrate`"
    )]
    UnmigratedStore,
    /// Running the store migration failed.
    #[error("store migration failed: {0}")]
    Migrate(String),
    /// A self-contradictory coordination configuration, refused BEFORE anything started (kv-sql WS4,
    /// UX-C4): a multi-writer SQL control-plane KV backend configured alongside a Raft cluster.
    #[error("{0}")]
    ContradictoryCoordination(String),
}

impl From<boatramp_core::migrate::MigrateError> for Error {
    fn from(e: boatramp_core::migrate::MigrateError) -> Self {
        Self::Migrate(e.to_string())
    }
}

/// `serve` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

// Box the (large, openraft-backed) bootstrap error into [`Error`]: the variant is
// `Box<BootstrapError>` so `?` on a bare `BootstrapError` keeps working (thiserror's
// `#[from]` would generate `From<BootstrapError>`, not the boxing conversion).
#[cfg(feature = "cluster")]
impl From<boatramp_cluster::node::BootstrapError> for Error {
    fn from(e: boatramp_cluster::node::BootstrapError) -> Self {
        Self::Bootstrap(Box::new(e))
    }
}

// Guard the boxing decision: `Bootstrap` is boxed so this enum stays under clippy's
// `result_large_err` threshold (128 B) without a module-wide `#[allow]`. If a future
// variant grows past it, box that one too rather than re-adding the allow.
#[cfg(feature = "cluster")]
const _: () = assert!(std::mem::size_of::<Error>() <= 128);

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
    /// Config file format for `--config` (`boatramp.cfg`): RON or JSON,
    /// auto-detected by extension (`.json` ⇒ JSON, everything else ⇒ RON). Set
    /// explicitly when piping Nickel/JSON to a non-`.json` config path.
    #[arg(long, value_enum)]
    pub format: Option<crate::config::ConfigFormat>,

    /// Address to bind the HTTP server to (flag/env > `serve.addr` >
    /// `127.0.0.1:8080`).
    #[arg(long, env = "BOATRAMP_ADDR")]
    addr: Option<SocketAddr>,

    /// Data directory for filesystem backends (blobs in `<dir>/blobs`,
    /// metadata in `<dir>/kv`). Flag/env > `serve.data_dir` > `./data`.
    #[arg(long, env = "BOATRAMP_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Blob storage backend.
    #[arg(long, value_enum, env = "BOATRAMP_BLOBS", default_value_t = BlobBackend::Fs)]
    blobs: BlobBackend,

    /// Metadata (KV) backend.
    #[arg(long, value_enum, env = "BOATRAMP_KV", default_value_t = KvBackend::Slatedb)]
    kv: KvBackend,

    /// Migrate a pre-0.2.0 (layout 1) control-plane store to the project-scoped
    /// layout at startup instead of refusing to serve. Off by default so the
    /// re-key is an explicit, one-time operator action (`boatramp migrate`).
    #[arg(long)]
    auto_migrate: bool,

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

    /// Run the SlateDB control-plane KV on the S3 store (`--blobs s3` config, e.g.
    /// R2) instead of local disk — durable, remote metadata for a container with
    /// no persistent volume. The LSM lives under `<bucket>/<kv-s3-prefix>`.
    #[arg(long, env = "BOATRAMP_KV_S3")]
    kv_s3: bool,

    /// Key prefix for the `--kv-s3` SlateDB store within the S3 bucket (keeps its
    /// LSM files apart from the blobs).
    #[arg(long, env = "BOATRAMP_KV_S3_PREFIX", default_value = "_kv")]
    kv_s3_prefix: String,

    /// LEGACY (v0.9.0: now redundant). Before v0.9.0 this opted a single-node cold open into
    /// repairing a torn TRAILING WAL tail. Self-heal-on-open is now the DEFAULT for the single-node
    /// control-plane store, so this flag is honored as a NO-OP with a one-line log. (On a cluster
    /// node it still opts the node-local Raft store into the tail repair — the cluster stays strict.)
    #[arg(long, env = "BOATRAMP_KV_REPAIR")]
    repair_wal: bool,

    /// Restore the pre-v0.9.0 FAIL-LOUD-on-any-torn-store behavior for the single-node control-plane
    /// SlateDB store (paranoid mode): a torn tail is NOT auto-quarantined — the node fails loud
    /// naming `kv recover` and (via C5) binds a recovery-mode listener rather than serving. Inverts
    /// the v0.9.0 default (self-heal a provably-safe trailing tail; loud only on an unsafe shape).
    /// A cluster node-local store is ALWAYS strict regardless of this flag (C8).
    #[arg(long, env = "BOATRAMP_KV_STRICT")]
    strict_kv: bool,

    /// GCS bucket (required for `--blobs gcs`).
    #[arg(long, env = "BOATRAMP_GCS_BUCKET")]
    gcs_bucket: Option<String>,

    /// GCS storage endpoint URL, e.g. a `fake-gcs-server` emulator (optional;
    /// defaults to the public GCS JSON API).
    #[arg(long, env = "BOATRAMP_GCS_ENDPOINT")]
    gcs_endpoint: Option<String>,

    /// Skip GCS credential resolution (anonymous — the emulator). Real GCS uses
    /// Application Default Credentials.
    #[arg(long, env = "BOATRAMP_GCS_ANONYMOUS")]
    gcs_anonymous: bool,

    /// Azure storage account name (required for `--blobs azure`).
    #[arg(long, env = "BOATRAMP_AZURE_ACCOUNT")]
    azure_account: Option<String>,

    /// Azure container name (required for `--blobs azure`).
    #[arg(long, env = "BOATRAMP_AZURE_CONTAINER")]
    azure_container: Option<String>,

    /// Azure storage account access key (shared-key auth; required unless
    /// `--azure-emulator`). Prefer the env var over the flag.
    #[arg(long, env = "BOATRAMP_AZURE_ACCESS_KEY")]
    azure_access_key: Option<String>,

    /// Use the Azurite emulator (well-known dev credentials + local endpoint).
    #[arg(long, env = "BOATRAMP_AZURE_EMULATOR")]
    azure_emulator: bool,

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
    #[arg(long, value_enum, env = "BOATRAMP_TLS", default_value_t = TlsMode::Off)]
    tls: TlsMode,

    /// PEM certificate chain (for `--tls custom`).
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// PEM private key (for `--tls custom`).
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// Domain to obtain an ACME certificate for (repeatable; for `--tls acme`). An
    /// explicit wildcard (`*.example.com`) is issued via DNS-01. `BOATRAMP_ACME_DOMAINS`
    /// takes a comma-separated list.
    #[arg(
        long = "acme-domain",
        env = "BOATRAMP_ACME_DOMAINS",
        value_delimiter = ','
    )]
    acme_domain: Vec<String>,

    /// ACME directory URL (defaults to Let's Encrypt production).
    #[arg(
        long,
        env = "BOATRAMP_ACME_DIRECTORY",
        default_value = "https://acme-v02.api.letsencrypt.org/directory"
    )]
    acme_directory: String,

    /// Contact email for the ACME account.
    #[arg(long, env = "BOATRAMP_ACME_CONTACT")]
    acme_contact: Option<String>,

    /// Extra root CA (PEM) to trust for the ACME server (e.g. Pebble's CA).
    #[arg(long, env = "BOATRAMP_ACME_CA_CERT")]
    acme_ca_cert: Option<PathBuf>,

    /// Directory for the ACME certificate cache.
    #[arg(long, env = "BOATRAMP_ACME_CACHE", default_value = "./data/acme")]
    acme_cache: PathBuf,

    /// DNS provider for `--tls acme-dns` and `boatramp dns`
    /// (`manual` | `cloudflare` | `route53` | `oci` | …). Credentials come from the
    /// environment (see `boatramp dns --help`).
    #[arg(long, env = "BOATRAMP_ACME_DNS_PROVIDER", default_value = "manual")]
    acme_dns_provider: String,

    /// With `--tls acme-dns`, also issue a `*.deploy.<domain>` wildcard cert so
    /// the wildcard preview host form gets TLS.
    #[arg(
        long,
        env = "BOATRAMP_ACME_WILDCARD_PREVIEW",
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true"
    )]
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

    /// **Found a brand-new cluster** from this node (the explicit, one-time
    /// genesis signal — F5). Required to bring up the first node with no seeds;
    /// refused if `[cluster].seeds` are set (a node either founds or joins, not
    /// both). A no-op once the node has durable state (restart resumes).
    #[arg(long, env = "BOATRAMP_CLUSTER_INIT")]
    cluster_init: bool,

    /// This node's own mesh base URL that peers should dial to reach it (e.g.
    /// `https://10.0.0.4:7000`). Advertised at join so the leader can replicate
    /// back. Defaults to `https://<cluster.listen>`; set it when the bind address
    /// isn't the reachable address (NAT / container / `0.0.0.0`).
    #[arg(long, env = "BOATRAMP_CLUSTER_ADVERTISE_ADDR")]
    cluster_advertise_addr: Option<String>,

    /// **Join an existing cluster** using a one-paste ticket from `cluster add`
    /// (bundles the seeds + root anchor + single-use token). Overrides
    /// `[cluster].seeds`/`root_pubkeys`/`join_token`. Mutually exclusive with
    /// `--cluster-init`.
    #[arg(long, env = "BOATRAMP_CLUSTER_JOIN")]
    cluster_join: Option<String>,

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
    // Resolve the `[serve.kv.sql]` connection config early (a pure config+env read, no I/O) so the
    // DERIVED coordination model is known BEFORE the cluster dispatch / any store open (kv-sql WS4).
    let sql_kv_cfg = resolve_sql_kv_config(serve_cfg.kv.as_ref().and_then(|k| k.sql.as_ref()));
    // The backend's DECLARED writer model (UX-C4 / C1 / C7): a multi-writer backend (Postgres/MySQL)
    // self-coordinates — N stateless nodes share one DB, no Raft — which auto-implies shared-mode
    // cache coherence + cluster-wide rate limiting, and REFUSES a Raft cluster alongside it.
    let multi_writer = declared_kv_writer_model(args.kv, sql_kv_cfg.as_ref())
        == boatramp_core::kv::WriterModel::MultiWriter;
    // Cluster-wide rate limiting: an explicit flag/config, OR auto-on under a multi-writer backend
    // (the N-node shared topology — per-node buckets would under-count). (UX-C4 derive-not-flag.)
    let cluster_rate_limit =
        args.cluster_rate_limit || serve_cfg.cluster_rate_limit || multi_writer;
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
    // Embedded web console (`[serve.console]`): when the operator enabled it,
    // mount the baked-in SPA at the configured host+path. Needs the `console`
    // build feature; enabling it without the feature is a logged no-op.
    if let Some(console) = serve_cfg.console.as_ref().filter(|c| c.enabled) {
        #[cfg(feature = "console")]
        {
            options.console = Some(boatramp_server::console::ConsoleMount::resolve(
                console.host.clone(),
                console.path.clone(),
            ));
        }
        #[cfg(not(feature = "console"))]
        {
            let _ = console;
            tracing::warn!(
                "[serve.console] enabled but this build lacks the `console` feature — \
                 the console is not served"
            );
        }
    }
    let data_dir = args
        .data_dir
        .clone()
        .or(serve_cfg.data_dir)
        .unwrap_or_else(|| PathBuf::from("./data"));

    // Cloud blob-change notification provisioning config (FA-5b2): the tier + the
    // account id that scopes a provisioned queue policy. Read before `storage` so
    // the notify-enabled S3 backend + its provider share one AWS config.
    let notify_tier = serve_cfg.blob_notify_tier;
    let notify_account = serve_cfg.blob_notify_account_id.clone();
    // `blob_args` carries no credential yet — the node-level sealed base S3 credential (#505) is
    // resolved from the `[secrets]` store, which needs the control-plane KV + envelope. Both are
    // built AFTER the cluster-mode fork below (single-node here; the Raft control-plane KV inside
    // `run_cluster` for a cluster), so the blob build is deferred to each path's `build_blobs_with_sealed_cred`
    // call, once its KV/envelope exist. This keeps ONE credential source honored on both paths without
    // opening a stray store or reading the base key from the ambient env when a sealed source is set.
    let s3_credential_cfg = serve_cfg.s3_credential.clone();
    // The blob backend + its per-backend options resolve flag/env > `[serve]` config > built-in
    // default — the uniform `serve` precedence. `--blobs`/`BOATRAMP_BLOBS` has a clap default of
    // `fs`, so a config-level `[serve].blobs` is honoured only when the flag/env was NOT explicitly
    // set; the fs/anonymous/path-style/emulator toggles are ORed (a set flag can only enable an
    // option) so the config value is honoured. `boatramp blob migrate` reads the SAME `[serve]`
    // fields from its `--from`/`--to` config files.
    let blobs_explicit =
        std::env::var_os("BOATRAMP_BLOBS").is_some() || args.blobs != BlobBackend::Fs;
    let blob_args = BlobArgs {
        blobs: if blobs_explicit {
            args.blobs
        } else {
            serve_cfg.blobs.unwrap_or(args.blobs)
        },
        s3_bucket: args
            .s3_bucket
            .clone()
            .or_else(|| serve_cfg.s3_bucket.clone()),
        s3_endpoint: args
            .s3_endpoint
            .clone()
            .or_else(|| serve_cfg.s3_endpoint.clone()),
        s3_region: args
            .s3_region
            .clone()
            .or_else(|| serve_cfg.s3_region.clone()),
        s3_path_style: args.s3_path_style || serve_cfg.s3_path_style,
        s3_credential: None,
        gcs_bucket: args
            .gcs_bucket
            .clone()
            .or_else(|| serve_cfg.gcs_bucket.clone()),
        gcs_endpoint: args
            .gcs_endpoint
            .clone()
            .or_else(|| serve_cfg.gcs_endpoint.clone()),
        gcs_anonymous: args.gcs_anonymous || serve_cfg.gcs_anonymous,
        azure_account: args
            .azure_account
            .clone()
            .or_else(|| serve_cfg.azure_account.clone()),
        azure_container: args
            .azure_container
            .clone()
            .or_else(|| serve_cfg.azure_container.clone()),
        azure_access_key: args
            .azure_access_key
            .clone()
            .or_else(|| serve_cfg.azure_access_key.clone()),
        azure_emulator: args.azure_emulator || serve_cfg.azure_emulator,
    };

    // UX-C4 self-contradiction refusal: a MULTI-WRITER SQL backend (self-coordinating) configured
    // ALONGSIDE a Raft cluster is meaningless (`run_cluster` never uses the configured KV backend).
    // Refuse LOUD here — BEFORE any store opens or mesh binds — naming both sides + the cure.
    if let Some(msg) = multi_writer_cluster_refusal(
        multi_writer,
        config.cluster.is_some(),
        args.cluster_init,
        args.cluster_join.is_some(),
    ) {
        return Err(Error::ContradictoryCoordination(msg));
    }

    // Cluster mode: triggered by a `[cluster]` config section OR the founding/
    // joining flags (`--cluster-init` / `--cluster-join <ticket>`), so a node can
    // join with just a ticket and no config file. The control-plane KvStore +
    // messaging then come from the embedded-Raft cluster node.
    #[cfg(feature = "cluster")]
    if config.cluster.is_some() || args.cluster_init || args.cluster_join.is_some() {
        let cluster_cfg = config.cluster.clone().unwrap_or_else(|| {
            // No `[cluster]` section: synthesize defaults (a flag-only bring-up).
            // The mesh binds the default port on the same host as `serve.addr`.
            crate::config::ClusterConfig {
                listen: std::net::SocketAddr::new(addr.ip(), DEFAULT_MESH_PORT),
                root_pubkeys: Vec::new(),
                seeds: Vec::new(),
                join_token: None,
                store_dir: None,
                mesh: None,
            }
        });
        // #505 (cluster path): the blob storage must be built BEFORE the Raft node (it feeds
        // `build_node` for cross-node message payloads), which is before the replicated control-plane KV
        // exists — so a `boatramp:` (KV-backed) node-cred ref cannot be resolved here. Refuse a
        // `boatramp:` ref STRUCTURALLY, by matching the ref scheme UP FRONT (not by relying on an empty
        // stand-in store making the resolve miss — a future refactor that seeded/shared that KV would
        // otherwise silently turn this into a live resolve against the wrong pre-replication store). The
        // envelope-only forms (`env:`/bare, posture-gated) resolve NORMALLY so their own errors (unset
        // var, posture-denied) surface UNWRAPPED — not buried under a misleading "use `env:`" suffix.
        // Absent source ⇒ the ambient AWS env chain (unchanged).
        let mut cluster_blob_args = blob_args;
        if let Some(cfg) = s3_credential_cfg.as_ref() {
            if let Some(name) =
                boatramp_node::s3_credential::boatramp_ref_name(&cfg.secret_access_key)
            {
                return Err(Error::S3Ingress(
                    boatramp_node::s3_credential::S3CredentialError::BoatrampRefOnCluster(
                        name.to_string(),
                    )
                    .to_string(),
                ));
            }
            let envelope = serve_secrets_envelope(config.secrets.as_ref(), &data_dir)?;
            let cred = boatramp_node::s3_credential::resolve_s3_credential(
                cfg,
                // No replicated control-plane KV yet on this path; a `boatramp:` ref was already
                // refused structurally above, so an empty in-memory store is a correct stand-in for
                // the `env:` forms (which never touch the KV).
                Arc::new(boatramp_core::kv::MemoryKv::new()),
                envelope,
                options.posture.allow_env_secret_refs,
                &boatramp_core::env::SystemEnv,
            )
            .await
            .map_err(|e| Error::S3Ingress(e.to_string()))?;
            cluster_blob_args.s3_credential = Some(cred);
        }
        let built_blobs =
            build_blobs(&cluster_blob_args, &data_dir, notify_tier, notify_account).await?;
        return run_cluster(
            args,
            config,
            cluster_cfg,
            addr,
            data_dir,
            built_blobs,
            options,
        )
        .await;
    }
    #[cfg(not(feature = "cluster"))]
    if config.cluster.is_some() {
        return Err(Error::NoClusterSupport);
    }

    // `--kv-s3` runs the SlateDB control-plane store on the S3 object store (R2),
    // reusing the `--blobs s3` addressing (bucket/endpoint/region/path-style) +
    // AWS-env credentials, so a volumeless container keeps durable metadata.
    let slate_s3 = args.kv_s3.then(|| boatramp_node::backends::SlateKvS3 {
        bucket: args.s3_bucket.clone().unwrap_or_default(),
        endpoint: args.s3_endpoint.clone(),
        region: args.s3_region.clone(),
        path_style: args.s3_path_style,
        prefix: args.kv_s3_prefix.clone(),
    });
    // Cold-open recovery policy (v0.9.0 KV-recovery, C8/C11). This `run` is the SINGLE-NODE path
    // (the `:672` dispatch already forked cluster → `run_cluster`), so the DEFAULT is self-heal a
    // provably-safe trailing torn WAL tail; `--strict-kv` / `BOATRAMP_KV_STRICT=1` restores the
    // pre-v0.9.0 fail-loud. (The cluster node-local Raft store opens in `run_cluster` and stays
    // strict — C8 — with its own opt-in `--repair-wal`.)
    let kv_policy = if args.strict_kv {
        boatramp_core::kv::KvOpenPolicy::Strict
    } else {
        boatramp_core::kv::KvOpenPolicy::SelfHeal
    };
    // C11 — log the active mode EVERY boot, so a torn-tail outcome is always attributable.
    match kv_policy {
        boatramp_core::kv::KvOpenPolicy::SelfHeal => tracing::info!(
            "control-plane KV open policy: SELF-HEAL (default) — a provably-safe trailing torn WAL \
             tail is auto-quarantined on open; an unsafe shape fails loud. `--strict-kv` opts out."
        ),
        boatramp_core::kv::KvOpenPolicy::Strict => tracing::info!(
            "control-plane KV open policy: STRICT (`--strict-kv`/BOATRAMP_KV_STRICT) — a torn store \
             fails loud into recovery mode; no auto-quarantine."
        ),
    }
    // C11 — a stale `--repair-wal` / `BOATRAMP_KV_REPAIR=1` is now redundant (self-heal is the
    // default); honor it as a NO-OP with a one-line log, never silently change its meaning.
    if args.repair_wal && !args.strict_kv {
        tracing::info!(
            "note: `--repair-wal` / `BOATRAMP_KV_REPAIR=1` is now the DEFAULT self-heal on the \
             single-node control plane — the flag/env is redundant (honored as a no-op)."
        );
    }
    // Close-in-progress breadcrumb (v0.11.0 UX C8b): if the PREVIOUS graceful close was cut short (a
    // `{root}/CLOSING.json` survived, i.e. fly SIGKILLed mid-close), WARN and point at `kill_timeout`.
    // Runs BEFORE build_kv so it is surfaced even on the recovery-mode path (a cut-short close is the
    // usual cause of the torn state). Read-and-clear (one-shot); best-effort.
    #[cfg(feature = "slatedb")]
    if args.kv == boatramp_node::backends::KvBackend::Slatedb
        && take_kv_close_breadcrumb(&data_dir, slate_s3.as_ref()).await
    {
        tracing::warn!(
            "control-plane KV: the PREVIOUS graceful close was CUT SHORT (a close-in-progress \
             breadcrumb survived) — fly likely SIGKILLed mid-close before the frontier was advanced. \
             The next cold open may self-heal a torn tail (lossless-for-acked by v0.11.0 fsync + \
             auto-recovery). Raise fly `kill_timeout` and `[serve.kv] close_deadline` to cover the \
             measured drain+close time."
        );
    }
    // `--kv sql` connection config (`sql_kv_cfg`) was resolved early (near the top of `run`) so the
    // writer-model / coordination could be derived before the cluster dispatch; reuse it here.
    let kv_backend = match boatramp_node::backends::build_kv(
        args.kv,
        &data_dir,
        slate_s3.as_ref(),
        kv_policy,
        sql_kv_cfg.as_ref(),
    )
    .await
    {
        Ok(backend) => backend,
        // A FATAL control-plane KV open must NOT bare-`exit(1)` into a PaaS crash-loop. The route is
        // backend-specific (C5 for SlateDB, C4 for SQL), encoded in `kv_open_failure_route` so the
        // policy is pure + unit-testable.
        Err(e) => match kv_open_failure_route(args.kv) {
            // C5 — SlateDB: bind the recovery-mode listener (503 for sites, 200 for probes,
            // diagnosis on `/api/kv-status`) with the SlateDB-specific `DEGRADED.json` diagnostic.
            KvOpenFailureRoute::SlatedbRecovery => {
                return enter_kv_recovery_mode(addr, &data_dir, slate_s3.as_ref(), &e.to_string())
                    .await;
            }
            // C4 — SQL (or a shared-DB unreachable at open): route to the SAME generic
            // recovery/readiness listener with a backend-appropriate diagnostic, not an exit.
            KvOpenFailureRoute::SqlRecovery => {
                return enter_sql_recovery_mode(addr, sql_kv_cfg.as_ref(), &e.to_string()).await;
            }
            // Memory never fails to open; Cloudflare KV has no local store to recover — propagate.
            KvOpenFailureRoute::Propagate => return Err(e.into()),
        },
    };
    // Shared-mode coherence: when several processes share one KV, publish each write to a changelog
    // over the *uncached* backend and poll it to invalidate peer-changed keys. AUTO-ON under a
    // multi-writer backend (UX-C4 derive-not-flag); the standalone `--shared-cache-coherence` flag is
    // DEPRECATED (honored, with a one-line note, for the legacy shared-SlateDB/Cloudflare topology).
    let flag_shared = args.shared_cache_coherence || serve_cfg.shared_cache_coherence;
    if flag_shared && multi_writer {
        tracing::info!(
            "note: `--shared-cache-coherence` / `[serve].shared_cache_coherence` is DEPRECATED and \
             now REDUNDANT — a multi-writer backend auto-enables shared-mode cache coherence."
        );
    } else if flag_shared {
        tracing::info!(
            "note: `--shared-cache-coherence` is DEPRECATED — it is now DERIVED from the backend's \
             writer model (auto-on for a multi-writer SQL backend). Honored here for the legacy \
             shared-SlateDB / Cloudflare-KV topology."
        );
    }
    let shared_coherence = flag_shared || multi_writer;
    let changelog = shared_coherence
        .then(|| Arc::new(Changelog::new(kv_backend.clone(), CHANGELOG_RETENTION_SECS)));
    // MF-3 stale-authz fence: the cross-node correctness FLOOR for the authz/crown-jewel keyspace in
    // multi-writer `shared` mode (replaces the 300s backstop for authz state). Built ONLY for a
    // multi-writer backend; single-writer / Raft never constructs one and its authz path is
    // unchanged. Shared (by `Arc`) between the authorizer (confirms it on a read-through) and the
    // cache poller (trips it when it cannot reach the store).
    let authz_fence = multi_writer.then(|| {
        Arc::new(boatramp_core::cache_coherence::AuthzFence::new(
            authz_fence_bound(),
        ))
    });
    // Front the metadata store with an LRU so hot reads stay in memory.
    let mut cached = CachedKv::new(kv_backend.clone(), args.cache_entries);
    if let Some(changelog) = &changelog {
        cached = cached.with_publisher(changelog.clone());
    }
    let kv: Arc<dyn KvStore> = Arc::new(cached);

    // #505: with the control-plane KV + `[secrets]` envelope now available, resolve the node-level
    // sealed base S3 credential (if configured) and build the blob backend with it. Absent ⇒ the
    // ambient AWS env chain (non-breaking). A configured sealed ref with no `[secrets]` envelope is a
    // fail-closed startup error (never a silent env fallback).
    let (built_blobs, sealed_s3_credential) = build_blobs_with_sealed_cred(
        &blob_args,
        s3_credential_cfg.as_ref(),
        serve_cfg.blob_fallback.as_ref(),
        &data_dir,
        kv.clone(),
        config.secrets.as_ref(),
        options.posture.allow_env_secret_refs,
        notify_tier,
        notify_account,
    )
    .await?;
    // The resolved sealed credential is consumed ONLY by the cloud blob-upload minter wiring below,
    // which is gated on a `blob-upload-*` cloud feature; when none is compiled (e.g. a plain `cluster`
    // build) the binding is otherwise unused. Discard it explicitly there to keep the build warning-free
    // without dropping the fail-closed resolution above (still runs for its startup-error side effect).
    #[cfg(not(any(
        feature = "blob-upload-aws",
        feature = "blob-upload-gcs",
        feature = "blob-upload-azure"
    )))]
    let _ = &sealed_s3_credential;
    let storage = built_blobs.storage.clone();

    // Blob-backend migration Part 2: a prominent startup WARNING while `[serve.blob_fallback]` is
    // active. Fallback is a bounded TRANSITION mode, not a steady state — the one live hazard is a
    // guest deleting its OWN object during the window (a primary-delete + a read fallback can
    // transiently resurrect it, within-tenant only — the key scheme is preserved). Name it
    // explicitly and point at the drain-then-drop doctrine.
    if let Some(fb) = serve_cfg.blob_fallback.as_ref() {
        tracing::warn!(
            secondary = %blob_fallback_identity(fb),
            "blob_fallback active — TRANSITION mode; drain with 'boatramp blob migrate', then remove \
             [serve].blob_fallback and restart the node. A guest deleting its own object during this \
             window can be transiently resurrected on read."
        );
    }

    // Layout guard (0.2.0): refuse to serve a store still on the pre-project layout
    // 1 — a half-read store would silently drop sites/functions/compute. The operator
    // migrates explicitly (`boatramp migrate`); `--auto-migrate` opts into an in-place
    // one-shot migration here. A `2-dual` store serves fine (reads are off the new
    // keys) and only needs a later `boatramp migrate --finalize` to reclaim old keys.
    match migrate::status(kv.as_ref()).await? {
        migrate::Status::Ready => {}
        migrate::Status::Dual => tracing::warn!(
            "control-plane store is in the 2-dual soak window; \
             run `boatramp migrate --finalize` to reclaim the old-layout keys"
        ),
        migrate::Status::NeedsMigration => {
            if args.auto_migrate {
                tracing::warn!(
                    "control-plane store is on the pre-0.2.0 layout; running a one-shot \
                     project re-keying migration (--auto-migrate)"
                );
                let report =
                    migrate::migrate(kv.as_ref(), migrate::MigrateOptions::one_shot()).await?;
                tracing::info!(
                    rekeyed = report.total_rekeyed(),
                    owner_entries = report.owner_entries,
                    "control-plane store migrated to the project-scoped layout"
                );
            } else {
                return Err(Error::UnmigratedStore);
            }
        }
    }

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
    // Boot snapshot of the KV degraded state for `GET /api/kv-status` (v0.9.0 KV-recovery, C6): if a
    // self-heal-on-open quarantined a torn tail this boot, the store wrote a DEGRADED.json breadcrumb
    // — surface it on the running (store-UP) server too, not only via `boatramp kv status`.
    #[cfg(feature = "slatedb")]
    {
        options.kv_degraded = read_kv_degraded_best_effort(&data_dir, slate_s3.as_ref()).await;
    }
    // Shared-mode coordination (kv-sql WS4): a non-Raft single-leader election (C1) + positive
    // control-plane identity/liveness (UX-C1), plus the backend-aware `kv-status` descriptor (C7).
    // Both coordination primitives run over the UNCACHED `kv_backend` (coordination state must never
    // be cached — a stale cached lease/roster would be wrong). SINGLE-WRITER keeps the always-true
    // leader gate + coordination "none" EXACTLY as before.
    let node_id = boatramp_core::shared_mode::random_node_id();
    let (is_leader_gate, leader_lease): (
        boatramp_server::CronLeaderGate,
        Option<Arc<boatramp_core::shared_mode::LeaderLease>>,
    ) = if multi_writer {
        let lease = Arc::new(boatramp_core::shared_mode::LeaderLease::new(
            kv_backend.clone(),
            node_id.clone(),
            boatramp_core::shared_mode::DEFAULT_LEASE_TTL,
        ));
        let gate = lease.gate();
        spawn_leader_lease(lease.clone());
        (gate, Some(lease))
    } else {
        (Arc::new(|| true), None)
    };
    // UX-C1: on a shared SQL KV, stamp/read the control-plane id + heartbeat this node into the
    // member roster, then report in the startup banner. Best-effort — a probe failure never crashes
    // the node (the store already opened; this is observability, not a correctness gate).
    let cp_report = if multi_writer {
        let identity = Arc::new(boatramp_core::shared_mode::ControlPlaneIdentity::new(
            kv_backend.clone(),
            node_id.clone(),
            boatramp_core::shared_mode::DEFAULT_MEMBER_WINDOW,
        ));
        match identity.join().await {
            Ok(report) => {
                tracing::info!("{}", report.banner());
                spawn_member_heartbeat(identity.clone());
                Some(report)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "shared control-plane identity probe failed on open (continuing; commingle / \
                     split-brain is NOT reported this boot)"
                );
                None
            }
        }
    } else {
        None
    };
    options.kv_coordination = Some(build_kv_status_info(
        args.kv,
        sql_kv_cfg.as_ref(),
        multi_writer,
        &data_dir,
        slate_s3.as_ref(),
        &node_id,
        cp_report.as_ref(),
    ));
    spawn_sighup_reload(kv.clone(), Some(daemon_runtime.clone()));
    if let Some(changelog) = changelog {
        spawn_cache_poller(
            changelog,
            kv.clone(),
            Some(daemon_runtime.clone()),
            authz_fence.clone(),
        );
    }
    // Periodic control-plane KV checkpoint + graceful-close budget (v0.9.0 KV-recovery, C1/C12).
    // The cadence advances the durable frontier so the self-heal-on-open trailing-tail loss window
    // stays bounded (default-ON, dirty-gated no-op when idle); the close budget bounds the graceful
    // shutdown. Both come from `[serve.kv]` (+ env override) — see `resolve_kv_durability`.
    let (kv_checkpoint_interval, kv_close_deadline) = resolve_kv_durability(serve_cfg.kv.as_ref());
    spawn_kv_checkpoint(kv.clone(), kv_checkpoint_interval);
    // MF-3/MF-4 — in multi-writer `shared` mode the authorizer gets the fence + the UNCACHED backing
    // store so it can read the authz keyspace THROUGH the cache (fence) and FAIL CLOSED (shed) when
    // the shared DB is unreachable. Single-writer passes `None` → the authz path is unchanged.
    let shared_authz = authz_fence
        .as_ref()
        .map(|fence| boatramp_node::auth::SharedAuthz {
            backing: kv_backend.clone(),
            fence: fence.clone(),
        });
    let auth = boatramp_node::auth::configure_auth(
        serve_cfg.signer.as_ref(),
        args.auth_root_private_key
            .clone()
            .or(serve_cfg.auth_root_private_key.clone()),
        args.auth_root_public_key
            .clone()
            .or(serve_cfg.auth_root_public_key.clone()),
        &mut options,
        kv.clone(),
        shared_authz,
    )
    .await?;
    configure_oidc(&args, &mut options).await?;
    // Fail-closed: don't expose an unauthenticated control plane on a public bind.
    boatramp_node::auth::enforce_auth_bind(addr, &auth, &options.posture)?;
    // Wire the built store + configured auth/options into a running node graph:
    // handler runtime, deploy store, compute + domain-verify reconcile loops. This
    // is the same assembly `boatramp serve` exercises, now a library call so an
    // embedder / in-process test builds the identical graph (PLAN-node-library N2b.3).
    // `_reconcile` holds the detached reconcile loops for the server's serving life.
    let boatramp_node::RunningNode {
        deploy,
        handlers,
        auth,
        options,
        reconcile,
    } = boatramp_node::assemble(boatramp_node::NodeInput {
        config,
        data_dir: data_dir.as_path(),
        storage,
        kv,
        auth,
        options,
        serve_addr: Some(addr),
        watch_provider: built_blobs.watch_provider.clone(),
        provision_tier: built_blobs.provision_tier,
        // Single-node: default messaging, id 0. The leader gate is always-true for a single-writer
        // backend (one node), or the shared CAS-lease election (C1) for a multi-writer backend — so
        // exactly ONE of N stateless nodes runs the five leader-gated singletons.
        messaging: None,
        is_leader: is_leader_gate,
        node_id: 0,
        // `boatramp serve` re-execs itself for compute workers (the child is boatramp).
        worker_exe: None,
    })
    .await?;

    tracing::info!(
        blobs = ?args.blobs, kv = ?args.kv, tls = ?args.tls,
        auth = !auth.is_disabled(), "starting boatramp"
    );
    // In a TLS mode, optionally bind a second plain-HTTP listener that redirects
    // to HTTPS. Ignored for `--tls off`.
    #[cfg(feature = "tls")]
    if !matches!(args.tls, TlsMode::Off)
        && let Some(redirect_addr) = args.http_redirect_addr.or(serve_cfg.http_redirect_addr)
    {
        spawn_http_redirect(redirect_addr, deploy.clone(), posture);
    }
    // Optionally bind the dedicated local S3-ingress listener (PLAN-blob-s3-ingress, opt-in via
    // `[serve].s3_ingress_addr`). Single-node here, so the fail-closed multi-node guard always admits;
    // an explicit `s3_ingress_secret_file` is honored, else an ephemeral per-process root is used.
    if let Some(s3_addr) = serve_cfg.s3_ingress_addr {
        spawn_s3_ingress(
            s3_addr,
            deploy.clone(),
            &auth,
            &options,
            serve_cfg.s3_ingress_secret_file.clone(),
            boatramp_server::s3_ingress::config::Deployment::SingleNode,
            #[cfg(feature = "blob-upload")]
            &handlers,
            #[cfg(feature = "blob-upload")]
            serve_cfg.s3_ingress_public_url.clone(),
            #[cfg(feature = "blob-upload")]
            serve_cfg
                .s3_ingress_mint_max_ttl_secs
                .unwrap_or(boatramp_node::config::DEFAULT_S3_INGRESS_MINT_MAX_TTL_SECS),
            #[cfg(feature = "blob-upload")]
            serve_cfg.s3_ingress_mint_max_bytes,
        )?;
    }
    // Cloud brokering (M4): when the node's blob backend is a cloud object store and
    // `[serve.s3_ingress_cloud]` is set, install a cloud `BlobUploadMinter` (used instead of the local
    // face) so a minted credential is a native scoped STS/CAB/SAS credential the client redeems
    // directly against the real store. Independent of the local `s3_ingress_addr` listener — a
    // cloud-only deployment never needs it. Gated on at least one cloud minter feature being compiled.
    #[cfg(any(
        feature = "blob-upload-aws",
        feature = "blob-upload-gcs",
        feature = "blob-upload-azure"
    ))]
    if let Some(cloud) = serve_cfg.s3_ingress_cloud.clone() {
        wire_cloud_blob_upload(
            &handlers,
            &blob_args,
            cloud,
            // #505: the SAME sealed base credential the blob backend uses (if any) so the minter's
            // STS/presign SDK config signs with the sealed key, not the ambient env chain.
            sealed_s3_credential.as_ref(),
            serve_cfg
                .s3_ingress_mint_max_ttl_secs
                .unwrap_or(boatramp_node::config::DEFAULT_S3_INGRESS_MINT_MAX_TTL_SECS),
            serve_cfg.s3_ingress_mint_max_bytes,
        )
        .await?;
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
    // Graceful shutdown (Part A): the serve future has returned (and has already quiesced the
    // scheduler + its detached children — `serve_with` on the plaintext path, every TLS serve
    // variant on its own tail). Now abort+await the reconcile loops and
    // cleanly CLOSE the control-plane store — not a bare `flush()` (which only pushed the WAL
    // buffer out, leaving a live store whose next crash could freeze a torn tail), but a real
    // `close()` that freezes memtables to L0 and advances the durable frontier, so the next cold
    // open has an empty WAL replay range. Bounded by the configurable `[serve.kv] close_deadline`
    // (C12; default generous 20s) — distinct WARN + fail-safe on timeout.
    // UX C8b: drop a close-in-progress breadcrumb before the close; a clean close clears it, a
    // cut-short one (fly SIGKILL) leaves it for the next boot's WARN.
    #[cfg(feature = "slatedb")]
    if args.kv == boatramp_node::backends::KvBackend::Slatedb {
        write_kv_close_breadcrumb(&data_dir, slate_s3.as_ref()).await;
    }
    // Shared-mode (C1): resign the leader lease on graceful shutdown so a successor takes over at
    // once instead of waiting a full TTL. Best-effort; a lost race / DB blip just lets it expire.
    if let Some(lease) = &leader_lease {
        lease.resign().await;
    }
    let close_clean = quiesce_and_close(kv_handle, reconcile, None, kv_close_deadline).await;
    #[cfg(feature = "slatedb")]
    if close_clean && args.kv == boatramp_node::backends::KvBackend::Slatedb {
        clear_kv_close_breadcrumb(&data_dir, slate_s3.as_ref()).await;
    }
    #[cfg(not(feature = "slatedb"))]
    let _ = close_clean;
    serve_result
}

/// Build the `[secrets]` key envelope from `[secrets]` config (mirrors `boatramp-node`'s private
/// `build_secrets_envelope`, kept in lockstep). `None` ⇒ no envelope (cleartext at rest / no sealed
/// secret store). Reachable from both `run` and `run_cluster` (unlike the cluster+acme-dns-gated
/// `build_cert_envelope`), so the #505 credential resolver can unseal on either path.
fn serve_secrets_envelope(
    secrets: Option<&crate::config::SecretsConfig>,
    data_dir: &Path,
) -> Result<Option<Arc<dyn boatramp_core::envelope::KeyEnvelope>>> {
    use boatramp_server::envelope::{EnvelopeSpec, build_envelope};
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
            )));
        }
    };
    build_envelope(spec).map_err(|e| Error::Envelope(e.to_string()))
}

/// Resolve the node-level sealed base S3 credential (#505) — if `[serve.s3_credential]` is set —
/// against the control-plane `kv` + the `[secrets]` envelope, inject it into a copy of `blob_args`,
/// build the blob backend, and return the resolved credential (so the SAME sealed credential also wires
/// the AWS cloud minter). Shared by the single-node (`run`) and cluster (`run_cluster`) paths so ONE
/// credential source is honored identically on both once each has its control-plane KV. Absent source
/// ⇒ the ambient AWS env chain (unchanged), and `Ok((_, None))`. A configured sealed ref with no
/// `[secrets]` envelope fails closed (a startup error), never a silent env fallback.
#[allow(clippy::too_many_arguments)]
async fn build_blobs_with_sealed_cred(
    blob_args: &BlobArgs,
    s3_credential_cfg: Option<&boatramp_node::config::S3CredentialConfig>,
    blob_fallback: Option<&boatramp_node::config::BlobFallbackConfig>,
    data_dir: &Path,
    kv: Arc<dyn KvStore>,
    secrets: Option<&crate::config::SecretsConfig>,
    allow_env_secret_refs: bool,
    notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    notify_account: Option<String>,
) -> Result<(
    boatramp_node::blobs::BuiltBlobs,
    Option<boatramp_node::s3_credential::SealedS3Credential>,
)> {
    let mut effective = blob_args.clone();
    let mut resolved = None;
    if let Some(cfg) = s3_credential_cfg {
        let envelope = serve_secrets_envelope(secrets, data_dir)?;
        let cred = boatramp_node::s3_credential::resolve_s3_credential(
            cfg,
            kv.clone(),
            envelope,
            allow_env_secret_refs,
            &boatramp_core::env::SystemEnv,
        )
        .await
        .map_err(|e| Error::S3Ingress(e.to_string()))?;
        tracing::info!(
            access_key_id = %cred.access_key_id(),
            "sourcing the base S3 credential from the [secrets] sealed store ([serve.s3_credential])"
        );
        effective.s3_credential = Some(cred.clone());
        // The resolved credential is returned so the SAME sealed base credential wires the AWS cloud
        // minter. Only the PRIMARY's credential is returned — the fallback SECONDARY is a read-only
        // drain source and is NEVER handed to the minter.
        resolved = Some(cred);
    }

    // Zero-downtime backend switch (blob-backend migration Part 2): when `[serve.blob_fallback]` is
    // configured, build a read-only SECONDARY and wrap `FallbackStorage(primary, secondary)`. The
    // secondary resolves its OWN sealed base S3 credential through the SAME `resolve_s3_credential`
    // path (same fail-closed posture, no second parser); it is discarded from `resolved` above so it
    // never reaches the minter.
    #[cfg(feature = "fallback")]
    if let Some(fb) = blob_fallback {
        let mut secondary_args = secondary_blob_args(fb);
        if let Some(cfg) = fb.s3_credential.as_ref() {
            let envelope = serve_secrets_envelope(secrets, data_dir)?;
            let cred = boatramp_node::s3_credential::resolve_s3_credential(
                cfg,
                kv,
                envelope,
                allow_env_secret_refs,
                &boatramp_core::env::SystemEnv,
            )
            .await
            .map_err(|e| Error::S3Ingress(e.to_string()))?;
            tracing::info!(
                access_key_id = %cred.access_key_id(),
                "sourcing the SECONDARY (blob_fallback) base S3 credential from the [secrets] sealed store"
            );
            secondary_args.s3_credential = Some(cred);
        }
        let timeout = std::time::Duration::from_secs(
            fb.secondary_timeout_secs
                .unwrap_or(boatramp_node::config::DEFAULT_BLOB_FALLBACK_TIMEOUT_SECS),
        );
        let built = boatramp_node::blobs::build_blobs_with_fallback(
            &effective,
            Some((&secondary_args, timeout)),
            data_dir,
            notify_tier,
            notify_account,
        )
        .await?;
        return Ok((built, resolved));
    }
    // Silence the unused binding on a `--no-default-features` build with no blob backend (no
    // `fallback` feature ⇒ the block above is cfg'd out).
    #[cfg(not(feature = "fallback"))]
    let _ = blob_fallback;

    let built = build_blobs(&effective, data_dir, notify_tier, notify_account).await?;
    Ok((built, resolved))
}

/// A short human identity for a `[serve.blob_fallback]` secondary — the backend plus its
/// bucket/path/endpoint — for the startup WARNING and CLI resolved-identity echo. Never renders a
/// credential.
fn blob_fallback_identity(fb: &boatramp_node::config::BlobFallbackConfig) -> String {
    use boatramp_node::backends::BlobBackend;
    match fb.blobs.unwrap_or(BlobBackend::Fs) {
        BlobBackend::Fs => "fs (data_dir/blobs)".to_string(),
        BlobBackend::S3 => format!(
            "s3 bucket={} endpoint={}",
            fb.s3_bucket.as_deref().unwrap_or("?"),
            fb.s3_endpoint.as_deref().unwrap_or("(default)")
        ),
        BlobBackend::Gcs => format!(
            "gcs bucket={} endpoint={}",
            fb.gcs_bucket.as_deref().unwrap_or("?"),
            fb.gcs_endpoint.as_deref().unwrap_or("(default)")
        ),
        BlobBackend::Azure => format!(
            "azure account={} container={}",
            fb.azure_account.as_deref().unwrap_or("?"),
            fb.azure_container.as_deref().unwrap_or("?")
        ),
    }
}

/// Map a `[serve.blob_fallback]` descriptor to a [`BlobArgs`] for the read-only SECONDARY backend.
/// Mirrors the primary `BlobArgs` shape field-for-field (its `s3_credential` is resolved separately by
/// the caller). The secondary's default backend is `fs` (matching the primary's `blobs` default).
#[cfg(feature = "fallback")]
fn secondary_blob_args(fb: &boatramp_node::config::BlobFallbackConfig) -> BlobArgs {
    BlobArgs {
        blobs: fb.blobs.unwrap_or(BlobBackend::Fs),
        s3_bucket: fb.s3_bucket.clone(),
        s3_endpoint: fb.s3_endpoint.clone(),
        s3_region: fb.s3_region.clone(),
        s3_path_style: fb.s3_path_style,
        s3_credential: None,
        gcs_bucket: fb.gcs_bucket.clone(),
        gcs_endpoint: fb.gcs_endpoint.clone(),
        gcs_anonymous: fb.gcs_anonymous,
        azure_account: fb.azure_account.clone(),
        azure_container: fb.azure_container.clone(),
        azure_access_key: fb.azure_access_key.clone(),
        azure_emulator: fb.azure_emulator,
    }
}

/// How long changelog feed entries are kept (comfortably larger than the poll
/// interval so a poller can't miss entries between polls).
const CHANGELOG_RETENTION_SECS: u64 = 60;

/// Quiesce the node's background KV writers, then cleanly `close()` the control-plane store —
/// the Part-A graceful-shutdown tail, shared by the single-node (`run`) and cluster
/// (`run_cluster`) paths.
///
/// Ordering is load-bearing: every task that can write the store must be stopped BEFORE the close,
/// because `close()` marks the store closed and then flushes — a write racing the mark errors
/// `Closed` or forces a new (torn-able) WAL segment. So we:
///   1. abort+**await** all reconcile loops (compute/domain-verify/tombstone/DNS) — an abort alone
///      only requests cancellation; awaiting guarantees the task issued its last write,
///   2. (cluster only, via `raft_shutdown`) shut the Raft apply/log writer down — a write/apply
///      after the store mark would lose a committed entry or desync the log vs the state machine,
///   3. `close()` the store — freeze memtables to L0, advance the durable frontier, so a
///      subsequent cold open has an empty WAL replay range (no torn tail).
///
/// The whole tail is wrapped in a `close_deadline` timeout (v0.9.0 KV-recovery, C12: the configurable
/// `[serve.kv] close_deadline`, default [`DEFAULT_KV_CLOSE_DEADLINE_SECS`]=20s — REPLACING the old
/// hardcoded 3s, which self-exited BEFORE fly's SIGKILL grace and left the frontier UN-advanced =
/// the exact torn tail this feature prevents). A stalled close is still abandoned (a genuinely-wedged
/// close must not hang shutdown forever), but only after the generous budget, and the abandonment is
/// logged DISTINCTLY (WARN naming the deadline) so a torn tail after a graceful stop is attributable
/// to a slow close. With continuous checkpointing (C1/C2) the close is cheap, so the budget rarely
/// bites. (The scheduler + its detached children are quiesced separately, inside `serve_with`, before
/// this runs — see [`boatramp_server::SchedulerHandle`].)
async fn quiesce_and_close(
    kv_handle: Arc<dyn KvStore>,
    reconcile: Vec<tokio::task::JoinHandle<()>>,
    raft_shutdown: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
    close_deadline: std::time::Duration,
) -> bool {
    let tail = async move {
        // (1) Stop every reconcile loop: abort THEN await, so none writes after this point.
        for handle in reconcile {
            handle.abort();
            let _ = handle.await;
        }
        // (2) Cluster: shut down Raft BEFORE the store close (see the doc above).
        if let Some(raft_shutdown) = raft_shutdown {
            raft_shutdown.await;
        }
        // (3) Close the store cleanly (flush memtables → L0, advance the durable frontier).
        if let Err(e) = kv_handle.close().await {
            tracing::warn!(error = %e, "control-plane store close on shutdown failed");
            false
        } else {
            // The success breadcrumb (C12): a graceful stop that logs this line advanced the frontier,
            // so a torn tail on the NEXT open cannot be blamed on this shutdown.
            tracing::info!(
                "control-plane store closed cleanly on shutdown (durable frontier advanced)"
            );
            true
        }
    };
    match tokio::time::timeout(close_deadline, tail).await {
        Ok(clean) => clean,
        Err(_) => {
            // The budget was hit: the close did NOT complete, so the durable frontier may be
            // un-advanced and the next cold open may see (and self-heal) a torn tail. Distinct WARN so
            // the operator can attribute a torn tail to a slow close and raise the budget + fly
            // `kill_timeout`. The close-in-progress breadcrumb is deliberately LEFT so the next boot
            // also WARNs (UX C8b).
            tracing::warn!(
                close_deadline_s = close_deadline.as_secs(),
                "graceful KV quiesce+close EXCEEDED the configured `[serve.kv] close_deadline` budget; \
                 abandoning the close so shutdown still proceeds — the durable frontier may be \
                 UN-ADVANCED, so the next cold open may self-heal a torn tail (lossless-for-acked by \
                 C1/C2). Raise `[serve.kv] close_deadline` and fly `kill_timeout` to cover the measured \
                 drain+close time."
            );
            false
        }
    }
}

/// Resolve the `[serve.kv]` durability knobs (v0.9.0 KV-recovery) — the periodic-checkpoint cadence
/// (C1) and the graceful-close budget (C12) — from config, with an env override so a fly deploy can
/// tune them without a config file: `BOATRAMP_KV_CHECKPOINT_INTERVAL` / `BOATRAMP_KV_CLOSE_DEADLINE`
/// (both seconds). An unparsable env value is ignored (the config/default wins) with a WARN — never a
/// silent misparse. Shared by `run` (single-node) and `run_cluster`.
fn resolve_kv_durability(
    kv_cfg: Option<&boatramp_node::config::KvConfig>,
) -> (Option<std::time::Duration>, std::time::Duration) {
    fn env_secs(var: &str) -> Option<u64> {
        match std::env::var(var) {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(secs) => Some(secs),
                Err(_) => {
                    tracing::warn!(%var, value = %raw, "ignoring unparsable env override (want seconds)");
                    None
                }
            },
            Err(_) => None,
        }
    }
    let cfg = kv_cfg.cloned().unwrap_or_default();
    let checkpoint = match env_secs("BOATRAMP_KV_CHECKPOINT_INTERVAL") {
        Some(0) => None, // env explicitly disables the cadence
        Some(secs) => Some(std::time::Duration::from_secs(secs)),
        None => cfg.checkpoint_interval(),
    };
    let close = match env_secs("BOATRAMP_KV_CLOSE_DEADLINE") {
        Some(secs) if secs > 0 => std::time::Duration::from_secs(secs),
        _ => cfg.close_deadline(),
    };
    (checkpoint, close)
}

/// Resolve the `[serve.kv.sql]` SQL-KV backend connection (UX-C2), overlaying the
/// `BOATRAMP_KV_SQL_*` env (env wins) so a fly deploy can configure `--kv sql` with no config file:
/// `BOATRAMP_KV_SQL_KIND`, `BOATRAMP_KV_SQL_PATH`, `BOATRAMP_KV_SQL_URL_ENV`,
/// `BOATRAMP_KV_SQL_POOL_MAX`. Returns `None` when neither the config block nor any env var is set
/// (the non-SQL backends ignore it; the SQL backend then errors with actionable guidance). The URL
/// itself is NEVER taken from config/env directly — only the NAME of the env var holding it
/// (`url_env`), mirroring `ExternalDatabaseConfig`.
fn resolve_sql_kv_config(
    base: Option<&boatramp_node::config::SqlKvConfig>,
) -> Option<boatramp_node::config::SqlKvConfig> {
    let env = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
    let kind = env("BOATRAMP_KV_SQL_KIND");
    let path = env("BOATRAMP_KV_SQL_PATH");
    let url_env = env("BOATRAMP_KV_SQL_URL_ENV");
    let pool_max = env("BOATRAMP_KV_SQL_POOL_MAX").and_then(|v| match v.trim().parse::<u32>() {
        Ok(n) => Some(n),
        Err(_) => {
            tracing::warn!(
                var = "BOATRAMP_KV_SQL_POOL_MAX",
                value = %v,
                "ignoring unparsable env override (want a positive integer)"
            );
            None
        }
    });
    if base.is_none() && kind.is_none() && path.is_none() && url_env.is_none() && pool_max.is_none()
    {
        return None;
    }
    let mut cfg = base.cloned().unwrap_or_default();
    if let Some(kind) = kind {
        cfg.kind = kind;
    }
    if let Some(path) = path {
        cfg.path = Some(path);
    }
    if let Some(url_env) = url_env {
        cfg.url_env = Some(url_env);
    }
    if let Some(pool_max) = pool_max {
        cfg.pool_max = Some(pool_max);
    }
    Some(cfg)
}

/// Spawn the periodic control-plane KV checkpoint task (v0.9.0 KV-recovery, C1). Every `interval` it
/// calls [`KvStore::checkpoint`](boatramp_core::kv::KvStore::checkpoint) — a dirty-gated WAL→L0
/// MemTable freeze that advances the durable frontier — bounding the self-heal-on-open trailing-tail
/// loss window to at most one interval for any write not already frontier-synced by a crown-jewel
/// path. `None` ⇒ the cadence is disabled (`[serve.kv] checkpoint_interval = 0`); the crown-jewel
/// per-write frontier-sync (C2) still runs, so an acked sealed secret is still lossless-for-acked.
/// The task is detached (lives for the process); an idle checkpoint is a cheap no-op, and a failure
/// is logged and retried on the next tick (never fatal to serving).
fn spawn_kv_checkpoint(kv: Arc<dyn KvStore>, interval: Option<std::time::Duration>) {
    let Some(interval) = interval else {
        tracing::info!(
            "control-plane KV periodic checkpoint DISABLED (`[serve.kv] checkpoint_interval = 0`); \
             crown-jewel per-write frontier-sync still active"
        );
        return;
    };
    tracing::info!(
        interval_s = interval.as_secs(),
        "control-plane KV periodic checkpoint enabled (advances the durable frontier on a cadence)"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick (checkpoint on the cadence, not at boot)
        loop {
            ticker.tick().await;
            if let Err(e) = kv.checkpoint().await {
                tracing::warn!(error = %e, "periodic control-plane KV checkpoint failed; retrying next tick");
            }
        }
    });
}

/// Best-effort read of the control-plane store's `DEGRADED.json` breadcrumb (v0.9.0 KV-recovery, C6)
/// WITHOUT opening the LSM store — used by the recovery-mode listener when the store will not open.
/// Builds the SAME object store + root the opener uses; ANY failure (store build, read) yields `None`
/// so the recovery listener still comes up with at least the open error.
#[cfg(feature = "slatedb")]
async fn read_kv_degraded_best_effort(
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
) -> Option<boatramp_core::kv::DegradedMarker> {
    use boatramp_storage::object_store::ObjectStore;
    let (store, root): (Arc<dyn ObjectStore>, String) = match slate_s3 {
        Some(s3) => (
            boatramp_storage::kv_slatedb::s3_object_store(&boatramp_storage::S3StoreConfig {
                bucket: s3.bucket.clone(),
                endpoint: s3.endpoint.clone(),
                region: s3.region.clone(),
                path_style: s3.path_style,
            })
            .ok()?,
            s3.prefix.clone(),
        ),
        None => (
            Arc::new(
                boatramp_storage::kv_slatedb::local_object_store(&data_dir.join("kv-slate"))
                    .ok()?,
            ),
            "kv".to_string(),
        ),
    };
    boatramp_storage::kv_slatedb::read_degraded_marker(&store, &root)
        .await
        .ok()
        .flatten()
}

/// Build the `(object store, root)` the control-plane KV opener uses (local `kv-slate` root `"kv"`, or
/// the configured S3 prefix) — shared by the close-in-progress breadcrumb helpers below.
#[cfg(feature = "slatedb")]
fn kv_close_store(
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
) -> Option<(Arc<dyn boatramp_storage::object_store::ObjectStore>, String)> {
    match slate_s3 {
        Some(s3) => Some((
            boatramp_storage::kv_slatedb::s3_object_store(&boatramp_storage::S3StoreConfig {
                bucket: s3.bucket.clone(),
                endpoint: s3.endpoint.clone(),
                region: s3.region.clone(),
                path_style: s3.path_style,
            })
            .ok()?,
            s3.prefix.clone(),
        )),
        None => Some((
            Arc::new(
                boatramp_storage::kv_slatedb::local_object_store(&data_dir.join("kv-slate"))
                    .ok()?,
            ),
            "kv".to_string(),
        )),
    }
}

/// The close-in-progress breadcrumb object path (v0.11.0 UX C8b): `{root}/CLOSING.json`.
#[cfg(feature = "slatedb")]
fn kv_close_breadcrumb_path(root: &str) -> boatramp_storage::object_store::path::Path {
    boatramp_storage::object_store::path::Path::from(format!("{root}/CLOSING.json"))
}

/// Write the close-in-progress breadcrumb (UX C8b): a tiny `{root}/CLOSING.json` (stamp only, NO
/// secrets — MF6) written when a graceful close STARTS. It is deleted on a clean close; a survivor on
/// the NEXT boot means the previous close was cut short (fly SIGKILL mid-close). Best-effort.
#[cfg(feature = "slatedb")]
async fn write_kv_close_breadcrumb(
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
) {
    use boatramp_storage::object_store::ObjectStoreExt;
    if let Some((store, root)) = kv_close_store(data_dir, slate_s3) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let body = format!(
            "{{\n  \"note\": \"a graceful control-plane KV close is in progress; deleted on clean \
             completion\",\n  \"started_unix\": {stamp}\n}}\n"
        );
        if let Err(e) = store
            .put(&kv_close_breadcrumb_path(&root), body.into_bytes().into())
            .await
        {
            tracing::debug!(error = %e, "could not write the KV close-in-progress breadcrumb (non-fatal)");
        }
    }
}

/// Delete the close-in-progress breadcrumb after a clean close (UX C8b). Best-effort.
#[cfg(feature = "slatedb")]
async fn clear_kv_close_breadcrumb(
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
) {
    use boatramp_storage::object_store::ObjectStoreExt;
    if let Some((store, root)) = kv_close_store(data_dir, slate_s3) {
        let _ = store.delete(&kv_close_breadcrumb_path(&root)).await;
    }
}

/// Read AND clear the close-in-progress breadcrumb at boot (UX C8b): `true` when a PRIOR close was cut
/// short (the breadcrumb survived) — the caller WARNs and points at `kill_timeout`. Best-effort.
#[cfg(feature = "slatedb")]
async fn take_kv_close_breadcrumb(
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
) -> bool {
    use boatramp_storage::object_store::ObjectStoreExt;
    let Some((store, root)) = kv_close_store(data_dir, slate_s3) else {
        return false;
    };
    let path = kv_close_breadcrumb_path(&root);
    let present = store.head(&path).await.is_ok();
    if present {
        let _ = store.delete(&path).await;
    }
    present
}

/// Enter the RECOVERY-MODE listener (v0.9.0 KV-recovery, C5) after a FATAL control-plane KV open —
/// instead of `exit(1)` into a fly crash-loop. Reads the `DEGRADED.json` breadcrumb (best-effort,
/// no store open), builds the `GET /api/kv-status` JSON diagnostic (open error + any breadcrumb +
/// the recovery steps), and binds the recovery listener on `addr` (503 for sites, 200 for probes).
async fn enter_kv_recovery_mode(
    addr: SocketAddr,
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
    open_err: &str,
) -> Result<()> {
    tracing::error!(
        error = %open_err,
        "control-plane KV FAILED TO OPEN — entering recovery mode (binding a 503 listener, NOT \
         exiting into a crash-loop). Diagnose via `GET /api/kv-status` or `boatramp kv recover`."
    );
    #[cfg(feature = "slatedb")]
    let marker = read_kv_degraded_best_effort(data_dir, slate_s3).await;
    #[cfg(not(feature = "slatedb"))]
    let marker: Option<boatramp_core::kv::DegradedMarker> = {
        let _ = (data_dir, slate_s3);
        None
    };
    // Legibility (UX C1): surface `frontier_source` + `last_durable_seq` on the recovery-mode listener
    // too, identical local-fs/S3 — derived from any DEGRADED.json breadcrumb (a prior partial recovery;
    // usually None here, since an F2 refusal writes no marker). `null`/`"unknown"` when no breadcrumb.
    let (frontier_source, last_durable_seq) = match &marker {
        Some(m) if !m.frontier_source.is_empty() => (
            serde_json::Value::from(m.frontier_source.clone()),
            serde_json::Value::from(m.frontier),
        ),
        Some(m) => (
            serde_json::Value::from("wal_replay"),
            serde_json::Value::from(m.frontier),
        ),
        None => (serde_json::Value::from("unknown"), serde_json::Value::Null),
    };
    let kv_status_json = serde_json::to_string_pretty(&serde_json::json!({
        "state": if marker.is_some() { "degraded_after_self_heal" } else { "unbootable" },
        "error": open_err,
        "frontier_source": frontier_source,
        "last_durable_seq": last_durable_seq,
        "degraded": marker,
        // Shape-aware guidance (UX C4): the empty/torn-manifest shape now recovers IN PLACE with
        // `kv recover --apply` (last-good-generation rollback, lossless); `--adopt-volume` is reserved
        // for the torn-out-of-scope-SST shape (a clean volume snapshot).
        "recovery": "Run `boatramp kv recover` (dry-run) to diagnose — it now WORKS on the \
                     empty/torn-manifest shape and prints the last-good-generation fallback plan. \
                     `boatramp kv recover --apply` rolls back to the last-good manifest generation \
                     (or quarantines a safe trailing WAL tail) IN PLACE, non-destructively. Reserve \
                     `boatramp kv recover --adopt-volume <mounted-path>` for a torn compacted/L0 SST \
                     (adopt a clean fly volume snapshot). `boatramp kv repair` is the offline \
                     tail-only quarantine. `boatramp kv status` shows this; `--ack` clears the \
                     breadcrumb once reviewed.",
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let diagnostic = boatramp_server::RecoveryDiagnostic {
        error: open_err.to_string(),
        kv_status_json,
    };
    boatramp_server::serve_recovery_mode(addr, diagnostic)
        .await
        .map_err(Error::Serve)
}

/// Classify the DECLARED writer model of the resolved KV backend WITHOUT opening it (kv-sql WS4) —
/// so the self-contradiction refusal (UX-C4) and the shared-coherence/rate-limit derivation can run
/// BEFORE the cluster dispatch / any store open. SlateDB/memory/cloudflare and `sql`+sqlite are
/// single-writer; `sql`+postgres/mysql are multi-writer (the engine self-coordinates). Mirrors
/// `build_sql_kv`'s alias set + `SqlKv::writer_model`'s declaration. Fail-safe: an unknown `sql`
/// kind classifies as SINGLE-writer (no spurious auto-shared / refusal — `build_kv` surfaces the
/// real "unknown kind" error).
fn declared_kv_writer_model(
    kv: KvBackend,
    sql: Option<&boatramp_node::config::SqlKvConfig>,
) -> boatramp_core::kv::WriterModel {
    use boatramp_core::kv::WriterModel;
    match kv {
        KvBackend::Sql => match sql.map(|c| c.kind.trim().to_ascii_lowercase()).as_deref() {
            Some("postgres" | "postgresql" | "pg" | "mysql" | "mariadb") => {
                WriterModel::MultiWriter
            }
            // "", "sqlite", "sqlite3", "libsql", or an unknown kind → single-writer (fail-safe).
            _ => WriterModel::SingleWriter,
        },
        KvBackend::Slatedb | KvBackend::Memory | KvBackend::Cloudflare => WriterModel::SingleWriter,
    }
}

/// The UX-C4 self-contradiction refusal message (pure + testable): a MULTI-WRITER SQL backend
/// (self-coordinating) configured ALONGSIDE a Raft cluster is meaningless — the DB IS the
/// coordinator, and `run_cluster` never even uses the configured KV backend. Returns the actionable
/// message to fail with (naming BOTH sides + the cure + "nothing started"), or `None` when there is
/// no contradiction: single-writer + cluster uses Raft as before, and multi-writer WITHOUT a cluster
/// scales as N stateless nodes.
fn multi_writer_cluster_refusal(
    multi_writer: bool,
    has_cluster_config: bool,
    cluster_init: bool,
    cluster_join: bool,
) -> Option<String> {
    if !multi_writer || !(has_cluster_config || cluster_init || cluster_join) {
        return None;
    }
    let mut sources = Vec::new();
    if has_cluster_config {
        sources.push("a `[cluster]` config section");
    }
    if cluster_init {
        sources.push("`--cluster-init` / `BOATRAMP_CLUSTER_INIT`");
    }
    if cluster_join {
        sources.push("`--cluster-join` / `BOATRAMP_CLUSTER_JOIN`");
    }
    Some(format!(
        "contradictory coordination configuration — NOTHING was started.\n\
         • the control-plane KV backend is a MULTI-WRITER SQL backend (`--kv sql` with a \
           Postgres/MySQL engine): it SELF-COORDINATES — N equal, stateless nodes share one database \
           and the engine serializes writes, so there is NO Raft.\n\
         • but a Raft cluster is ALSO configured ({}).\n\
         These are mutually exclusive by construction: the cluster path never uses the configured KV \
         backend, so \"multi-writer SQL + Raft\" cannot mean anything.\n\
         Cure — pick ONE coordination model:\n\
           · DROP the cluster configuration (remove `[cluster]`, `--cluster-init`, `--cluster-join`) \
             to scale with Postgres — deploy N instances against the SAME database URL, no mesh.\n\
           · OR switch the KV backend to `slatedb` (or `--kv sql` with a `sqlite` engine) to keep \
             Raft coordination.",
        sources.join(" + "),
    ))
}

/// How a FATAL control-plane KV open failure is routed (kv-sql WS4, C4/C5) — never `exit(1)` into a
/// PaaS crash-loop for a backend that can serve a recovery/readiness listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KvOpenFailureRoute {
    /// SlateDB: the recovery-mode listener with the SlateDB `DEGRADED.json` diagnostic (C5).
    SlatedbRecovery,
    /// SQL: the generic recovery/readiness listener with a SQL diagnostic (C4).
    SqlRecovery,
    /// Memory (never fails) / Cloudflare (no local store to recover): propagate the error.
    Propagate,
}

/// Classify how a `build_kv` open failure routes (pure + testable, C4/C5). SlateDB and SQL both enter
/// a 503 recovery/readiness listener instead of exiting; memory/cloudflare propagate.
fn kv_open_failure_route(kv: KvBackend) -> KvOpenFailureRoute {
    match kv {
        KvBackend::Slatedb => KvOpenFailureRoute::SlatedbRecovery,
        KvBackend::Sql => KvOpenFailureRoute::SqlRecovery,
        KvBackend::Memory | KvBackend::Cloudflare => KvOpenFailureRoute::Propagate,
    }
}

/// C4 — enter the generic recovery/readiness listener after a FATAL SQL control-plane KV open (or a
/// shared-DB unreachable at open), instead of bare-`exit(1)` into a PaaS crash-loop. The SlateDB
/// diagnostic BUILDER is SlateDB-specific; the LISTENER ([`serve_recovery_mode`]) is generic, so SQL
/// gets a backend-appropriate `/api/kv-status` diagnostic and the same 503-for-sites / 200-for-probes
/// behavior. (SQL crash recovery is the engine's own — there is no self-heal/`kv recover` here; the
/// fix is to restore DB reachability and redeploy/restart.)
async fn enter_sql_recovery_mode(
    addr: SocketAddr,
    sql: Option<&boatramp_node::config::SqlKvConfig>,
    open_err: &str,
) -> Result<()> {
    tracing::error!(
        error = %open_err,
        "SQL control-plane KV FAILED TO OPEN — entering recovery mode (binding a 503 listener, NOT \
         exiting into a crash-loop). The shared database is unreachable or rejected the open; fix \
         connectivity / credentials / `synchronous_commit=on`, then redeploy/restart. Diagnose via \
         `GET /api/kv-status`."
    );
    let kind = sql
        .map(|c| c.kind.trim())
        .filter(|k| !k.is_empty())
        .unwrap_or("sqlite")
        .to_ascii_lowercase();
    // Credential-redacted location: only the env var NAME (never the URL), or the on-disk path.
    let location = sql_kv_location(sql);
    let kv_status_json = serde_json::to_string_pretty(&serde_json::json!({
        "state": "unreachable",
        "error": open_err,
        "backend": {
            "family": "sql",
            "dialect": kind,
            "location": location,
            "connection": "failed",
        },
        "coordination": {
            // Derived but not yet joined — the store never opened.
            "mode": "shared",
            "control_plane_id": serde_json::Value::Null,
            "raft": serde_json::Value::Null,
        },
        "recovery": "The SQL control-plane database could not be opened. SQL crash recovery is the \
                     engine's own (WAL/fsync) — there is no `boatramp kv recover` for this backend. \
                     Confirm the database is reachable, the credentials/URL are correct, and (for \
                     Postgres) `synchronous_commit = on`, then redeploy/restart. The node is serving \
                     503 + Retry-After for sites (200 for health probes) and will NOT crash-loop.",
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let diagnostic = boatramp_server::RecoveryDiagnostic {
        error: open_err.to_string(),
        kv_status_json,
    };
    boatramp_server::serve_recovery_mode(addr, diagnostic)
        .await
        .map_err(Error::Serve)
}

/// A credential-redacted one-line location for a `[serve.kv.sql]` backend — the on-disk path for an
/// embedded SQLite db, or the NAME of the env var that holds the URL for an external engine (never
/// the URL itself, which may carry a password). Used by `kv-status` + the SQL recovery diagnostic.
fn sql_kv_location(sql: Option<&boatramp_node::config::SqlKvConfig>) -> String {
    let Some(cfg) = sql else {
        return "sql (unconfigured)".to_string();
    };
    let kind = cfg.kind.trim();
    let kind = if kind.is_empty() { "sqlite" } else { kind };
    match kind.to_ascii_lowercase().as_str() {
        "sqlite" | "sqlite3" | "libsql" => match cfg.path.as_deref().filter(|p| !p.is_empty()) {
            Some(path) => format!("sqlite:{path}"),
            None => "sqlite (path unset)".to_string(),
        },
        other => match cfg.url_env.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(env) => format!("{other} (url from env {env})"),
            None => format!("{other} (url_env unset)"),
        },
    }
}

/// Build the backend-aware `kv-status` descriptor (Architect C7) the node bootstrap feeds into
/// `ServerOptions`, so `GET /api/kv-status` reports the REAL backend + DERIVED coordination instead
/// of the hardcoded SlateDB `manifest_latest` vocabulary. Every string is credential-redacted.
#[allow(clippy::too_many_arguments)]
fn build_kv_status_info(
    kv: KvBackend,
    sql: Option<&boatramp_node::config::SqlKvConfig>,
    multi_writer: bool,
    data_dir: &Path,
    slate_s3: Option<&boatramp_node::backends::SlateKvS3>,
    node_id: &str,
    cp_report: Option<&boatramp_core::shared_mode::ControlPlaneJoinReport>,
) -> boatramp_server::KvStatusInfo {
    let (family, dialect, location) = match kv {
        KvBackend::Slatedb => (
            "slatedb",
            None,
            match slate_s3 {
                Some(s3) => format!("s3://{}/{} (object store)", s3.bucket, s3.prefix),
                None => format!("{}", data_dir.join("kv-slate").display()),
            },
        ),
        KvBackend::Memory => ("memory", None, "in-memory (ephemeral)".to_string()),
        KvBackend::Cloudflare => ("cloudflare", None, "cloudflare-kv (REST)".to_string()),
        KvBackend::Sql => {
            let kind = sql
                .map(|c| c.kind.trim())
                .filter(|k| !k.is_empty())
                .unwrap_or("sqlite")
                .to_ascii_lowercase();
            // Normalize the dialect name for the status surface.
            let dialect = match kind.as_str() {
                "sqlite" | "sqlite3" | "libsql" => "sqlite",
                "postgres" | "postgresql" | "pg" => "postgres",
                "mysql" | "mariadb" => "mysql",
                _ => "sqlite",
            };
            ("sql", Some(dialect.to_string()), sql_kv_location(sql))
        }
    };
    // Coordination is DERIVED from the writer model × node count (never a knob). This is the
    // `run()`/shared path: a multi-writer backend ⇒ `shared`; everything else here ⇒ `none` (the
    // Raft cluster has its OWN `run_cluster` path, which leaves this descriptor unset).
    let (mode, derived_from) = if multi_writer {
        (
            "shared",
            format!(
                "multi-writer backend ({}) — N equal stateless nodes share one database; the engine \
                 serializes writes + a single-leader lease gates the singletons (no Raft)",
                dialect.as_deref().unwrap_or("sql"),
            ),
        )
    } else {
        (
            "none",
            "single-writer backend, single node — no external coordinator".to_string(),
        )
    };
    boatramp_server::KvStatusInfo {
        backend_family: family.to_string(),
        backend_dialect: dialect,
        writer_model: if multi_writer {
            "multi_writer".to_string()
        } else {
            "single_writer".to_string()
        },
        location,
        connection: "ok".to_string(),
        coordination_mode: mode.to_string(),
        coordination_derived_from: derived_from,
        control_plane_id: cp_report
            .map(boatramp_core::shared_mode::ControlPlaneJoinReport::short_id),
        this_node: multi_writer.then(|| node_id.to_string()),
        members_seen: cp_report.map(|r| r.members_seen),
    }
}

/// Spawn the shared-mode leader-lease renew loop (kv-sql WS4, C1). Ticks ONCE immediately (so a node
/// can acquire an empty/expired lease at boot without waiting a full interval), then on the
/// `renew_interval` cadence. Logs leadership TRANSITIONS both directions (acquired / lost) so a
/// failover is legible. Detached for the process lifetime; a tick error is logged + retried next
/// tick (never fatal to serving).
fn spawn_leader_lease(lease: Arc<boatramp_core::shared_mode::LeaderLease>) {
    tracing::info!(
        node = %lease.node_id(),
        "shared-mode single-leader election active (non-Raft CAS-lease over the shared SQL KV) — \
         exactly one node runs the leader-gated singletons"
    );
    tokio::spawn(async move {
        let interval = lease.renew_interval();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut was_leader = false;
        loop {
            // The FIRST `tick()` of a `tokio::time::interval` returns immediately, so the first
            // acquire attempt happens at boot (not after one interval).
            ticker.tick().await;
            match lease.tick().await {
                Ok(is_leader) => {
                    if is_leader && !was_leader {
                        tracing::info!(node = %lease.node_id(), "shared-mode: ACQUIRED leadership");
                    } else if !is_leader && was_leader {
                        tracing::warn!(
                            node = %lease.node_id(),
                            "shared-mode: LOST leadership (lease taken over or could not renew)"
                        );
                    }
                    was_leader = is_leader;
                }
                Err(e) => tracing::warn!(
                    node = %lease.node_id(), error = %e,
                    "shared-mode leader-lease tick failed; retrying next interval"
                ),
            }
        }
    });
}

/// Spawn the shared-mode member-liveness heartbeat (kv-sql WS4, UX-C1): refresh this node's
/// `_cp/members/{node_id}` row on a cadence so a crashed node ages out of the roster and the live
/// member count stays accurate. Detached; a failure is logged + retried next tick.
fn spawn_member_heartbeat(identity: Arc<boatramp_core::shared_mode::ControlPlaneIdentity>) {
    tokio::spawn(async move {
        // Heartbeat comfortably faster than the member window so a live node never ages out.
        let interval = boatramp_core::shared_mode::DEFAULT_MEMBER_WINDOW / 3;
        let mut ticker = tokio::time::interval(interval.max(std::time::Duration::from_secs(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // consume the immediate tick (join() already heartbeat at boot)
        loop {
            ticker.tick().await;
            if let Err(e) = identity.heartbeat().await {
                tracing::warn!(
                    node = %identity.node_id(), error = %e,
                    "shared-mode member heartbeat failed; retrying next interval"
                );
            }
        }
    });
}

/// Drive the shared-mode cache-coherence poller: every
/// second, pop the keys peers changed; periodically trim the feed; and every few
/// minutes do a full flush as the gap backstop (rare, so no thundering herd).
/// Detached for the server's lifetime.
fn spawn_cache_poller(
    changelog: Arc<Changelog>,
    cache: Arc<dyn KvStore>,
    daemon: Option<Arc<boatramp_server::DaemonRuntime>>,
    authz_fence: Option<Arc<boatramp_core::cache_coherence::AuthzFence>>,
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
            // MF-3: a CHECKED poll distinguishes a successful (possibly empty) poll from an
            // unreachable store. On an error the node can no longer confirm currency, so TRIP the
            // authz fence at once (shed sooner) rather than silently treat "no entries" as current.
            // A successful poll does NOT confirm the authz fence: the `_inval` feed is best-effort /
            // suppressible, so only a direct authz read-through (in the authorizer) may vouch for the
            // authz keyspace — keeping the fence independent of NOTIFY.
            match changelog.poll_checked(&mut cursor).await {
                Ok(changed) if !changed.is_empty() => {
                    cache.invalidate_keys(&changed);
                    // A peer wrote dynamic daemon config → wake an immediate reload.
                    if let Some(daemon) = &daemon
                        && changed.iter().any(|k| k.starts_with("daemon/"))
                    {
                        daemon.notify_reload();
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    if let Some(fence) = &authz_fence {
                        fence.trip();
                    }
                    tracing::warn!(%err, "shared-mode cache poll failed; tripped the authz fence");
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

/// The MF-3 fence bound `T` — how long a shared-mode node may serve the cached authz keyspace before
/// re-confirming it against the store. Small (a few seconds); overridable via
/// `BOATRAMP_KV_AUTHZ_FENCE_SECS` (clamped to 1..=60s), default 3s.
fn authz_fence_bound() -> std::time::Duration {
    let secs = std::env::var("BOATRAMP_KV_AUTHZ_FENCE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(3)
        .clamp(1, 60);
    std::time::Duration::from_secs(secs)
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
/// privilege on `:80` doesn't take down the HTTPS server. Served through the same
/// unified `boatramp-http` stack the TLS modes use (no hyper/`axum_server`).
#[cfg(feature = "tls")]
fn spawn_http_redirect(
    addr: SocketAddr,
    deploy: DeployStore,
    posture: boatramp_core::security::SecurityPosture,
) {
    tokio::spawn(async move {
        tracing::info!(%addr, "serving HTTP→HTTPS redirect listener");
        let router = boatramp_server::http_redirect_router(deploy, posture);
        if let Err(err) =
            boatramp_server::serve_plaintext(addr, router, boatramp_server::shutdown_signal()).await
        {
            tracing::error!(%addr, %err, "HTTP redirect listener failed");
        }
    });
}

/// Build + install the M4 **cloud** blob-upload minter from the node's blob backend + the
/// `[serve.s3_ingress_cloud]` knobs (used INSTEAD of the local S3 face for a cloud-backed container).
/// Also registers the operator mint ceilings so the guest binding + operator route are wired even when
/// the local `s3_ingress_addr` listener is not enabled (a cloud-only deployment). No-op when the blob
/// backend is `fs`/in-memory (the local face handles those), or the matching cloud feature is off.
#[cfg(any(
    feature = "blob-upload-aws",
    feature = "blob-upload-gcs",
    feature = "blob-upload-azure"
))]
#[allow(clippy::too_many_arguments)]
async fn wire_cloud_blob_upload(
    handlers: &boatramp_server::HandlerRuntime,
    blob_args: &BlobArgs,
    cloud: boatramp_node::config::S3IngressCloud,
    // #505: the node-level sealed base S3 credential (if any). When set, the AWS minter's SDK config
    // signs with the sealed key rather than the ambient env chain (the SAME source the blob backend uses).
    sealed_s3_credential: Option<&boatramp_node::s3_credential::SealedS3Credential>,
    mint_max_ttl_secs: u64,
    mint_max_bytes: Option<u64>,
) -> Result<()> {
    use boatramp_server::blob_upload_minter::wiring::{CloudMinterSpec, build_cloud_minter};

    if mint_max_ttl_secs == 0 {
        return Ok(());
    }
    let spec = match blob_args.blobs {
        BlobBackend::S3 => CloudMinterSpec::Aws {
            bucket: blob_args.s3_bucket.clone().ok_or_else(|| {
                Error::S3Ingress("cloud blob-upload (S3): --s3-bucket required".into())
            })?,
            region: blob_args.s3_region.clone().unwrap_or_default(),
            endpoint: blob_args.s3_endpoint.clone(),
            force_path_style: blob_args.s3_path_style,
            role_arn: cloud.aws_role_arn.clone(),
            use_federation_token: cloud.aws_use_federation_token,
            // The STS-less presigned-only mode (Tigris/R2/MinIO): mint single-object presigned PUTs only.
            presigned_only: cloud.aws_presigned_only,
            // The sealed base credential, or `None` for the ambient AWS env chain (unchanged).
            base_credential: sealed_s3_credential.map(|c| {
                let (id, secret) = c.as_pair();
                boatramp_server::blob_upload_minter::wiring::BaseCredential::new(id, secret)
            }),
        },
        BlobBackend::Gcs => CloudMinterSpec::Gcs {
            bucket: blob_args.gcs_bucket.clone().ok_or_else(|| {
                Error::S3Ingress("cloud blob-upload (GCS): --gcs-bucket required".into())
            })?,
            endpoint: blob_args.gcs_endpoint.clone(),
        },
        BlobBackend::Azure => {
            let account = cloud
                .azure_account
                .clone()
                .or_else(|| blob_args.azure_account.clone())
                .ok_or_else(|| {
                    Error::S3Ingress("cloud blob-upload (Azure): account name required".into())
                })?;
            let service_url = cloud
                .azure_service_url
                .clone()
                .unwrap_or_else(|| format!("https://{account}.blob.core.windows.net/"));
            let container = blob_args.azure_container.clone().ok_or_else(|| {
                Error::S3Ingress("cloud blob-upload (Azure): --azure-container required".into())
            })?;
            CloudMinterSpec::Azure {
                account,
                service_url,
                container,
                hns: cloud.azure_hns,
            }
        }
        // fs / in-memory ⇒ the local S3 face mints (no cloud brokering).
        BlobBackend::Fs => return Ok(()),
    };
    let Some(minter) = build_cloud_minter(spec).await.map_err(Error::S3Ingress)? else {
        // The matching cloud feature isn't compiled in ⇒ fall back to the local face (if wired).
        return Ok(());
    };
    // Register the operator ceilings (the binding reads them from `blob_upload_config`); the cloud
    // minter overrides the actual `mint`. The face secret/endpoint are unused for a cloud minter, so a
    // throwaway ephemeral secret + a placeholder endpoint are harmless (never consulted).
    let ephemeral = boatramp_server::s3_ingress::credential::S3IngressSecret::generate()
        .map_err(|e| Error::S3Ingress(e.to_string()))?;
    handlers.set_blob_upload_minting(boatramp_server::blob_upload_minter::mint_config(
        ephemeral,
        "cloud-brokered".to_string(),
        mint_max_ttl_secs,
        mint_max_bytes,
    ));
    handlers.set_blob_upload_cloud_minter(minter);
    tracing::info!(backend = ?blob_args.blobs, "wired cloud blob-upload minter (native brokering)");
    Ok(())
}

// Private serve-wiring fn; the arg count only trips the lint under `--all-features` (the 4
// `blob-upload` mint params). Grouping them would just move the churn — allow it here.
#[allow(clippy::too_many_arguments)]
fn spawn_s3_ingress(
    addr: SocketAddr,
    deploy: DeployStore,
    auth: &boatramp_server::Auth,
    options: &boatramp_server::ServerOptions,
    secret_file: Option<PathBuf>,
    deployment: boatramp_server::s3_ingress::config::Deployment,
    // Guest/operator upload-mint wiring (M3): the runtime to register the mint config on (its
    // `session_signer` mints the session token), plus the public endpoint + operator ceilings. Only
    // used with the `blob-upload` feature; ignored otherwise.
    #[cfg(feature = "blob-upload")] handlers: &boatramp_server::HandlerRuntime,
    #[cfg(feature = "blob-upload")] public_url: Option<String>,
    #[cfg(feature = "blob-upload")] mint_max_ttl_secs: u64,
    #[cfg(feature = "blob-upload")] mint_max_bytes: Option<u64>,
) -> Result<()> {
    use boatramp_server::s3_ingress::listener;

    let public_key = auth.public_key().ok_or_else(|| {
        Error::S3Ingress(
            "the local S3 face needs a configured token trust anchor (enable auth)".into(),
        )
    })?;
    let secret = listener::load_ingress_secret(deployment, secret_file.as_deref())
        .map_err(|e| Error::S3Ingress(e.to_string()))?;
    // Wire guest/operator upload minting: the minter shares the SAME secret the face verifies under
    // (a clone, never a re-generate — a re-load would give a different single-node ephemeral root), and
    // targets the operator's public endpoint (else derived from the bind addr). Deny-by-default:
    // without this the `blob-upload` binding is never attached and a granted guest's `mint` fails.
    #[cfg(feature = "blob-upload")]
    if mint_max_ttl_secs > 0 {
        let endpoint_base = public_url.unwrap_or_else(|| format!("http://{addr}"));
        handlers.set_blob_upload_minting(boatramp_server::blob_upload_minter::mint_config(
            secret.clone(),
            endpoint_base,
            mint_max_ttl_secs,
            mint_max_bytes,
        ));
    }
    let guard = Arc::new(boatramp_server::UploadGuard::new(options.limits.clone()));
    let state = Arc::new(listener::build_state(public_key, secret, deploy, guard));
    tokio::spawn(async move {
        tracing::info!(%addr, "serving local S3-ingress face (dedicated listener)");
        if let Err(err) = listener::serve_s3(addr, state, boatramp_server::shutdown_signal()).await
        {
            tracing::error!(%addr, %err, "S3-ingress listener failed");
        }
    });
    Ok(())
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

/// Default Raft peer-mesh port when a node joins/founds with only flags (no
/// `[cluster]` section). Distinct from the public `serve.addr` port.
#[cfg(feature = "cluster")]
const DEFAULT_MESH_PORT: u16 = 7000;

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

/// Clock skew tolerated on a join possession proof: `proof_iat` must be within
/// this window of the admitting node's clock, so a captured proof cannot be
/// replayed indefinitely (the single-use `jti` is the primary anti-replay; this
/// bounds the pre-spend window). Symmetric to cover both directions of skew.
#[cfg(feature = "cluster")]
const JOIN_PROOF_MAX_SKEW_SECS: u64 = 300;

/// TTL on the root-signed member assertions handed back in a join response: long
/// enough for the joiner to verify + adopt each key within the round-trip, short
/// enough that a captured response can't seed a node much later. The joiner
/// verifies each against the root anchor before trusting it (PLAN-cluster-join F3).
#[cfg(feature = "cluster")]
const MEMBER_ASSERTION_TTL_SECS: u64 = 300;

/// Bridges the server's `/api/cluster/*` control routes to the cluster runtime
/// (join admission + key rotation) over [`ClusterNode`]. `issuer` is the
/// control-plane **root signer**: a join admits only if this node can mint
/// root-signed member assertions for the joiner to adopt.
#[cfg(feature = "cluster")]
struct ClusterMeshControl {
    node: Arc<boatramp_cluster::node::ClusterNode>,
    issuer: Option<Arc<dyn boatramp_core::cose::Signer>>,
}

#[cfg(feature = "cluster")]
#[async_trait::async_trait]
impl boatramp_server::MeshControl for ClusterMeshControl {
    async fn admit(
        &self,
        mesh_pubkey_hex: &str,
        jti: &str,
        possession_proof: &[u8],
        proof_iat: u64,
        now: u64,
        advertise_addr: Option<&str>,
    ) -> std::result::Result<boatramp_server::JoinOutcome, String> {
        use boatramp_server::JoinOutcome;

        // (1) Freshness: the proof must be stamped within the skew window. This
        // bounds how long a captured (pre-spend) proof stays presentable.
        let fresh = proof_iat <= now.saturating_add(JOIN_PROOF_MAX_SKEW_SECS)
            && now <= proof_iat.saturating_add(JOIN_PROOF_MAX_SKEW_SECS);
        if !fresh {
            return Ok(JoinOutcome::ProofInvalid);
        }

        // (2) The joiner is identified by the key it claims; parse it to SPKI.
        let Ok(spki) = boatramp_cluster::mesh::parse_public_key(mesh_pubkey_hex) else {
            return Ok(JoinOutcome::ProofInvalid);
        };

        // (3) Possession: the proof must be a signature by that very key over the
        // domain-separated join challenge — so a bearer token alone (without the
        // private key) cannot join in another key's name.
        let challenge = boatramp_core::cose::join_challenge(jti, mesh_pubkey_hex, proof_iat);
        if !boatramp_rpktls::verify_signature(&spki, &challenge, possession_proof) {
            return Ok(JoinOutcome::ProofInvalid);
        }

        // (4) Single-use + re-admit-proof: the state machine spends the `jti`
        // (idempotent replay ⇒ already-spent) and refuses a revoked key (F6). A
        // stale/spent token or a revoked key that survived (3) stops here.
        use boatramp_cluster::raft::AdmitOutcome;
        match self
            .node
            .admit(mesh_pubkey_hex, jti, advertise_addr)
            .await
            .map_err(|e| e.to_string())?
        {
            AdmitOutcome::Admitted => {}
            AdmitOutcome::Spent => return Ok(JoinOutcome::TokenSpent),
            AdmitOutcome::Revoked => return Ok(JoinOutcome::Revoked),
        }

        // (5) Vouch for the current members with root-signed assertions so the
        // joiner adopts each only after verifying it against the root anchor.
        let Some(issuer) = self.issuer.as_ref() else {
            return Err("cluster node has no root signing key to vouch for members".to_string());
        };
        let mut members = Vec::new();
        for (node_id, pubkey) in self.node.trusted_member_keys().await {
            let assertion = boatramp_core::cose::mint_member_assertion(
                node_id,
                &pubkey,
                MEMBER_ASSERTION_TTL_SECS,
                now,
                issuer.as_ref(),
            )
            .await
            .map_err(|e| e.to_string())?;
            members.push(assertion);
        }
        // Advisory routing so the joiner can dial every member (each dial is still
        // key-authenticated). Only entries for members it also verified above are
        // usable to it.
        let addrs = self.node.peer_addrs();
        Ok(JoinOutcome::Admitted { members, addrs })
    }

    async fn rotate_key(&self) -> std::result::Result<String, String> {
        let new_pub = self
            .node
            .rotate_key(MESH_ROTATION_PROPAGATION)
            .await
            .map_err(|e| e.to_string())?;
        Ok(new_pub.iter().map(|b| format!("{b:02x}")).collect())
    }

    async fn revoke(&self, node: u64) -> std::result::Result<(), String> {
        self.node.revoke(node).await.map_err(|e| e.to_string())
    }

    async fn members(&self) -> std::result::Result<Vec<boatramp_server::MeshMember>, String> {
        let addrs = self.node.peer_addrs();
        Ok(self
            .node
            .members()
            .into_iter()
            .map(|m| boatramp_server::MeshMember {
                node: m.node,
                voter: m.voter,
                caught_up: m.caught_up,
                leader: m.leader,
                addr: addrs.get(&m.node).cloned(),
            })
            .collect())
    }

    async fn promote(&self, node: u64) -> std::result::Result<(), String> {
        self.node.promote(node).await.map_err(|e| e.to_string())
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
    use boatramp_server::envelope::{EnvelopeSpec, build_envelope};
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
            )));
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

    fn on_reset(&self, data: &std::collections::BTreeMap<String, Vec<u8>>) {
        if data.keys().any(|k| k.starts_with("daemon/")) {
            self.0.notify_reload();
        }
    }
}

#[cfg(feature = "cluster")]
#[allow(clippy::too_many_arguments)]
async fn run_cluster(
    args: ServeArgs,
    config: &ServerConfig,
    mut cluster_cfg: crate::config::ClusterConfig,
    addr: SocketAddr,
    data_dir: PathBuf,
    built_blobs: boatramp_node::blobs::BuiltBlobs,
    mut options: boatramp_server::ServerOptions,
) -> Result<()> {
    use boatramp_cluster::node::{ClusterParams, build_node};

    // The blob backend; `built_blobs` also carries the optional FA-5b2 blob-change
    // watch provider + tier the handler runtime is wired with below. In the cluster path the blob
    // storage is needed BEFORE the Raft node (it feeds `build_node` for cross-node message payloads),
    // which is before the replicated control-plane KV exists — so the #505 sealed credential is resolved
    // up-front in `run` (against the node-local control-plane KV) and folded into `built_blobs` there.
    let storage = built_blobs.storage.clone();

    // Node-local durable Raft log/state store (distinct from the *replicated*
    // control plane the cluster serves).
    let store_dir = cluster_cfg
        .store_dir
        .clone()
        .unwrap_or_else(|| data_dir.join("raft"));
    // Whether this node's durable store dir already exists, captured BEFORE opening
    // (which creates it). A weak "has booted before" signal — NOT the resume gate:
    // the dir is created just by opening the KV, before a first join completes.
    let store_dir_existed = store_dir.exists();
    // Security M1: a cluster node NEVER self-quarantines its Raft-log tail. Auto-quarantining a
    // torn trailing Raft WAL object can regress the store below the committed index → a double-vote
    // or a log↔state-machine desync. So on the CLUSTER path we FORCE `repair = None` (strict cold
    // open — fail loud on a torn tail) regardless of `--repair-wal` / `BOATRAMP_KV_REPAIR=1`, and
    // WARN if the operator set that env/flag: the correct cluster recovery is to fail loud and
    // REJOIN from peers (which re-replicate the authoritative log), not to drop a local tail.
    if args.repair_wal {
        tracing::warn!(
            "cluster: IGNORING `--repair-wal` / `BOATRAMP_KV_REPAIR=1` on the node-local Raft \
             durable store — refusing to auto-quarantine a Raft log tail (it could regress below \
             the committed index → double-vote / log↔state-machine desync). A cluster node recovers \
             by failing loud then REJOINING peers (which re-replicate the log), not by dropping a \
             local tail. Opening STRICT."
        );
    }
    let repair: Option<boatramp_storage::kv_slatedb::RepairMode> = None;
    let durable_kv: Arc<dyn KvStore> = Arc::new(
        boatramp_storage::SlateKv::open_local_with_flush_repair(
            store_dir,
            boatramp_node::backends::CONTROL_PLANE_FLUSH,
            repair,
        )
        .await?,
    );
    // The real resume-vs-found/join signal (F5): whether the store holds COMMITTED
    // cluster state (persisted mesh trust). A store dir that exists but has no
    // committed trust means an earlier boot opened the KV but never finished its
    // join — such a node must re-derive its action (rejoin), not resume into an
    // empty-trust, fail-closed mesh. Checked once, over the raw store.
    let has_committed_state = boatramp_cluster::persist::has_committed_trust(&durable_kv)
        .await
        .map_err(|e| Error::ClusterStartup(e.to_string()))?;
    // Keep a handle to force a final flush on graceful shutdown (SHUT-1): the
    // store is moved into the Raft stores below, so this clone is how we reach
    // its `flush` after serving stops.
    let durable_kv_handle = durable_kv.clone();
    // Periodic checkpoint + graceful-close budget (v0.9.0 KV-recovery, C1/C12) for the node-local
    // durable Raft store: the cadence bounds its WAL replay tail (openraft's own flushing keeps
    // committed entries durable; this is defense-in-depth), and the close budget bounds the graceful
    // shutdown. (C8: the cluster self-heal-on-open stays STRICT — that is wired at the open site, not
    // here; the cadence/close budget are orthogonal loss-window bounds that always help.)
    let (kv_checkpoint_interval, kv_close_deadline) =
        resolve_kv_durability(config.serve.as_ref().and_then(|s| s.kv.as_ref()));
    spawn_kv_checkpoint(durable_kv_handle.clone(), kv_checkpoint_interval);

    use boatramp_cluster::mesh::{self, MeshIdentity, MeshTls, TrustSet};

    // No static peer map: the peer directory + mesh trust set start empty and are
    // populated by founding (self), joining (adopted members), or replication.
    let mut peers = std::collections::BTreeMap::new();
    let mut genesis_trust = std::collections::BTreeMap::new();

    // Load (or generate + persist `0600`) this node's Ed25519 mesh identity.
    let mesh_cfg = cluster_cfg.mesh.clone().unwrap_or_default();
    let key_file = mesh_cfg
        .key_file
        .clone()
        .unwrap_or_else(|| data_dir.join("mesh/identity.key"));
    let identity = MeshIdentity::load_or_generate(&key_file)?;

    // This node's Raft id is DERIVED from its mesh key (dynamic-join self-identity
    // — no config id).
    let node_id = boatramp_cluster::raft::derive_node_id(identity.public_key());
    tracing::info!(
        node_id,
        pubkey = %identity.public_key_hex(),
        "cluster: mesh identity"
    );

    // A one-paste `--cluster-join <ticket>` overrides the `[cluster]` seeds/root/
    // token: decode it and fold it into the config so the rest of the flow is
    // ticket-vs-config agnostic.
    if let Some(blob) = args.cluster_join.as_deref() {
        let ticket = crate::join::JoinTicket::decode(blob)
            .map_err(|e| Error::ClusterStartup(e.to_string()))?;
        cluster_cfg.seeds = ticket.seeds;
        cluster_cfg.root_pubkeys = ticket.root_pubkeys;
        cluster_cfg.join_token = Some(ticket.token);
    }

    // Decide founding vs joining vs resuming (F5): the single source of truth.
    let seeds_present = !cluster_cfg.seeds.is_empty();
    // The Kubernetes operator designates its **ordinal-0** StatefulSet pod as the
    // founder (via the downward-API pod name) — every other ordinal joins. This
    // designates the founder only; the node *identity* is still derived from the
    // mesh key, so it is not the reverted per-pod-identity coupling.
    let is_operator_founder =
        std::env::var("BOATRAMP_POD_NAME").is_ok_and(|name| name.rsplit('-').next() == Some("0"));
    let init_requested = args.cluster_init || is_operator_founder;
    let action = crate::join::decide_startup(&crate::join::StartupInputs {
        // Resume ONLY on committed state (persisted trust) — not on a store dir that
        // merely exists, which would wedge a joiner whose first join never finished.
        has_committed_state,
        // The dir already existing means this node booted before, but possibly never
        // committed any state; kept as the weaker "ever booted" signal for messaging.
        ever_member: store_dir_existed,
        seeds_present,
        init_requested,
    });
    // A resuming node seeds no genesis trust here — it rehydrates its trust set
    // from durable state inside `build_node`, so its empty-trust fail-closed check
    // is deferred until after that (below). Captured now: the `match action` moves.
    let is_resume = matches!(action, crate::join::StartupAction::Resume);

    // This node's own reachable mesh URL (advertised at join so the leader can
    // dial it), defaulting to the bind address.
    let self_advertise = args
        .cluster_advertise_addr
        .clone()
        .unwrap_or_else(|| format!("https://{}", cluster_cfg.listen));

    // A dynamic joiner starts with NO static membership; the seed admits it and
    // membership + trust arrive via replication. Bootstrap only when founding.
    let mut do_bootstrap = false;
    match action {
        crate::join::StartupAction::FailClosed(reason) => {
            return Err(Error::ClusterStartup(reason));
        }
        crate::join::StartupAction::Found => {
            // Genesis: this node is the sole founding member. List itself so
            // `build_node` takes the genesis path and `bootstrap` initializes it.
            peers.insert(node_id, self_advertise.clone());
            genesis_trust.insert(node_id, identity.public_key().to_vec());
            do_bootstrap = true;
            tracing::info!(node_id, "cluster: founding a new cluster (init)");
        }
        crate::join::StartupAction::Join => {
            // Redeem the join ticket against the seeds and adopt the returned,
            // root-verified members — seeding the trust set + peer directory with
            // NO static peer map. This node is a joiner: it does NOT list itself,
            // so `build_node` starts it with empty membership (the seed admits it).
            let roots = if cluster_cfg.root_pubkeys.is_empty() {
                config
                    .serve
                    .as_ref()
                    .and_then(|s| s.auth_root_public_key.clone())
                    .into_iter()
                    .collect()
            } else {
                cluster_cfg.root_pubkeys.clone()
            };
            let token = cluster_cfg
                .join_token
                .as_deref()
                .and_then(|s| {
                    crate::join::resolve_join_token(s, &boatramp_core::env::SystemEnv).transpose()
                })
                .transpose()
                .map_err(|e| Error::ClusterStartup(e.to_string()))?
                .ok_or_else(|| {
                    Error::ClusterStartup(
                        "joining requires [cluster].join_token (env:/path:/inline)".into(),
                    )
                })?;
            let ticket = crate::join::JoinTicket {
                seeds: cluster_cfg.seeds.clone(),
                root_pubkeys: roots,
                token,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let adopted = crate::join::join_cluster(&ticket, &identity, Some(&self_advertise), now)
                .await
                .map_err(|e| Error::ClusterStartup(e.to_string()))?;
            tracing::info!(
                node_id,
                members = adopted.len(),
                "cluster: joined via seeds"
            );
            for m in adopted {
                if let Ok(spki) = mesh::parse_public_key(&m.mesh_pubkey_hex) {
                    genesis_trust.insert(m.node_id, spki);
                }
                if let Some(addr) = m.mesh_addr {
                    peers.insert(m.node_id, addr);
                }
            }
        }
        crate::join::StartupAction::Resume => {
            // Durable state is authoritative; `build_node` hydrates trust + the
            // peer directory from it. Never re-bootstraps.
            tracing::info!(node_id, "cluster: resuming from durable state");
        }
    }

    // Fail closed: never bring up a non-loopback mesh with no trusted peers.
    // Found/Join seed `genesis_trust` right here, so they are checked now; a Resume
    // leaves it empty on purpose and is checked after `build_node` rehydrates its
    // trust from durable state.
    if !cluster_cfg.listen.ip().is_loopback() && genesis_trust.is_empty() && !is_resume {
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
            node_id,
            peers,
            // Empty ⇒ every peer votes; otherwise the listed ids are the voting
            // quorum and the rest join as read-only learners (multi-region).
            // Founding uses the self-only peer map ⇒ this node is the sole voter;
            // a joiner's membership arrives from the seed. No static voter list.
            voters: std::collections::BTreeSet::new(),
            durable_kv,
            storage: storage.clone(),
            mesh: mesh_tls.clone(),
            cluster_write_capability: write_capability,
            extra_observers: vec![daemon_observer],
        })
        .await?,
    );

    // A resuming node rehydrated its trust set from durable state inside
    // `build_node`. Only now can it fail closed on a genuinely empty trust (a wiped
    // or corrupt volume) — otherwise the mesh would come up trusting no peer.
    if is_resume && !cluster_cfg.listen.ip().is_loopback() && mesh_tls.trust().snapshot().is_empty()
    {
        return Err(Error::MeshUnconfigured(cluster_cfg.listen));
    }

    // Serve this node's peer mesh over RFC 7250 raw-public-key mutual TLS 1.3:
    // every `/raft/*` + `/stream/*` request must present a trusted peer key. The
    // application `client-write` is additionally gated by the authorizer.
    let mesh_router = match write_authz {
        Some(authz) => node.router.clone().layer(axum::Extension::<
            boatramp_cluster::http::WriteAuthz,
        >(Some(authz))),
        None => node.router.clone(),
    };
    let mut mesh_config = mesh_tls.server()?;
    mesh_config.alpn_protocols = boatramp_server::alpn_h1_h2();
    let listen = cluster_cfg.listen;
    tracing::info!(
        node_id, %listen,
        "cluster: serving peer mesh (mutual TLS)"
    );
    tokio::spawn(async move {
        if let Err(err) = boatramp_server::serve_tls(
            listen,
            mesh_config.into(),
            mesh_router,
            boatramp_server::shutdown_signal(),
        )
        .await
        {
            tracing::error!(%err, "cluster: peer mesh server exited");
        }
    });

    // Initialize a brand-new cluster from this node (once) when founding.
    if do_bootstrap {
        node.bootstrap().await?;
        // A founder is never admitted, so nothing else records its address —
        // publish it into the replicated directory so joiners (and restarts) can
        // dial it with no peer map.
        node.advertise_addr(&self_advertise).await?;
        tracing::info!("cluster: bootstrapped membership");
    }

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
        let stagger = std::time::Duration::from_secs(node_id % 60);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval + stagger).await;
                match rotate_node.rotate_key(MESH_ROTATION_PROPAGATION).await {
                    Ok(pubkey) => tracing::info!(
                        pubkey = %pubkey.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "cluster: rotated mesh key on schedule"
                    ),
                    Err(err) => {
                        tracing::error!(%err, "cluster: scheduled mesh key rotation failed");
                    }
                }
            }
        });
    }

    // The control-plane KvStore + messaging are the cluster facades.
    let kv: Arc<dyn KvStore> = node.kv.clone();

    // Layout guard (0.2.0), cluster path — the same fail-closed gate the single-node
    // path applies: refuse to serve a store still on the pre-project layout 1, since a
    // half-read store would silently drop sites/functions/compute. `node.kv` is the
    // replicated RaftKv facade, so a `--auto-migrate` here writes through Raft consensus
    // (a follower's writes forward to the leader) and every migration step is idempotent
    // + re-verifying — so even a concurrent racer converges rather than corrupts, no
    // CAS/leader-election needed. The load-bearing case is the founder (the leader,
    // authoritative for its own store) booting on legacy data; a joiner only ever
    // reaches an already-running cluster, which this guard kept from serving unmigrated.
    match migrate::status(kv.as_ref()).await? {
        migrate::Status::Ready => {}
        migrate::Status::Dual => tracing::warn!(
            "control-plane store is in the dual soak window; \
             run `boatramp migrate --finalize` to reclaim the old-layout keys"
        ),
        migrate::Status::NeedsMigration => {
            if args.auto_migrate {
                tracing::warn!(
                    "control-plane store is below the current schema version; running a \
                     one-shot migration through the cluster (--auto-migrate)"
                );
                let report =
                    migrate::migrate(kv.as_ref(), migrate::MigrateOptions::one_shot()).await?;
                tracing::info!(
                    rekeyed = report.total_rekeyed(),
                    owner_entries = report.owner_entries,
                    "control-plane store migrated to the project-scoped layout"
                );
            } else {
                return Err(Error::UnmigratedStore);
            }
        }
    }

    // Cluster-wide rate limiting shares the *replicated* RaftKv across nodes.
    if args.cluster_rate_limit || config.serve.as_ref().is_some_and(|s| s.cluster_rate_limit) {
        options.cluster_rate_limit_kv = Some(kv.clone());
    }
    // SIGHUP also force-reloads the daemon config (the ApplyObserver already
    // handles replicated `daemon/*` writes; this is the manual override).
    spawn_sighup_reload(kv.clone(), options.daemon_runtime.clone());
    let cluster_serve_cfg = config.serve.clone().unwrap_or_default();
    let auth = boatramp_node::auth::configure_auth(
        cluster_serve_cfg.signer.as_ref(),
        args.auth_root_private_key
            .clone()
            .or(cluster_serve_cfg.auth_root_private_key.clone()),
        args.auth_root_public_key
            .clone()
            .or(cluster_serve_cfg.auth_root_public_key),
        &mut options,
        kv.clone(),
        // Raft cluster = single-writer over a node-local store (replication keeps every node
        // current); no shared-mode authz guard — the authz path is unchanged.
        None,
    )
    .await?;
    configure_oidc(&args, &mut options).await?;
    // Fail-closed: don't expose an unauthenticated control plane on a public bind.
    boatramp_node::auth::enforce_auth_bind(addr, &auth, &options.posture)?;

    // The mesh control hook: `POST /api/cluster/join` + `/rotate-key` reach the
    // cluster runtime through it. Constructed after `configure_auth` so it carries
    // the control-plane root signer (`options.issuer`) — the join flow mints
    // root-signed member assertions with it.
    options.mesh_control = Some(Arc::new(ClusterMeshControl {
        node: node.clone(),
        issuer: options.issuer.clone(),
    }));
    // Node-graph assembly, shared with the single-node path (`boatramp_node::assemble`):
    // handler runtime, deploy store (+ reserved `default` project), compute + domain-
    // verify reconcile loops. The cluster differences are threaded as `NodeInput`
    // fields: the Raft messaging substrate, a Raft `is_leader` gate (cron firing +
    // both reconcile loops run only on the leader), and this node's compute id.
    let leader_raft = node.raft.clone();
    let leader_node_id = node.node_id;
    let is_leader: boatramp_server::CronLeaderGate =
        Arc::new(move || boatramp_cluster::raft::is_leader(&leader_raft, leader_node_id));
    let boatramp_node::RunningNode {
        deploy,
        handlers,
        auth,
        options,
        reconcile,
    } = boatramp_node::assemble(boatramp_node::NodeInput {
        config,
        data_dir: data_dir.as_path(),
        storage,
        kv,
        auth,
        options,
        serve_addr: Some(addr),
        watch_provider: built_blobs.watch_provider.clone(),
        provision_tier: built_blobs.provision_tier,
        messaging: Some(node.messaging.clone()),
        is_leader,
        node_id: node.node_id,
        worker_exe: None,
    })
    .await?;

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
    // Optionally bind the dedicated local S3-ingress listener. In cluster mode the deployment is
    // treated as MULTI-NODE — so the fail-closed guard REQUIRES an explicitly configured, cluster-
    // uniform `s3_ingress_secret_file` (never a per-node auto-generated key, which would make
    // credentials un-verifiable across nodes).
    if let Some(s3_addr) = cluster_serve_cfg.s3_ingress_addr {
        spawn_s3_ingress(
            s3_addr,
            deploy.clone(),
            &auth,
            &options,
            cluster_serve_cfg.s3_ingress_secret_file.clone(),
            boatramp_server::s3_ingress::config::Deployment::MultiNode,
            #[cfg(feature = "blob-upload")]
            &handlers,
            #[cfg(feature = "blob-upload")]
            cluster_serve_cfg.s3_ingress_public_url.clone(),
            #[cfg(feature = "blob-upload")]
            cluster_serve_cfg
                .s3_ingress_mint_max_ttl_secs
                .unwrap_or(boatramp_node::config::DEFAULT_S3_INGRESS_MINT_MAX_TTL_SECS),
            #[cfg(feature = "blob-upload")]
            cluster_serve_cfg.s3_ingress_mint_max_bytes,
        )?;
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

    // Graceful shutdown (Part A, cluster): the serve future has returned (and has already quiesced
    // the scheduler + its detached children — `serve_with` on the plaintext path, every TLS serve
    // variant on its own tail). Abort+await the reconcile loops,
    // THEN shut down Raft, THEN cleanly CLOSE the node-local durable Raft store. The Raft shutdown
    // MUST precede the store close: a write/apply after the store is marked closed would lose a
    // committed log/state entry or desync the log vs the state machine (the cluster's correctness
    // boundary). `close()` (not the old bare `flush()`) then advances the durable frontier so the
    // next cold open replays an empty WAL range. Bounded by the configurable `[serve.kv]
    // close_deadline` (C12; default generous 20s) — distinct WARN + fail-safe on timeout.
    let raft = node.raft.clone();
    let raft_shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        Box::pin(async move {
            if let Err(e) = raft.shutdown().await {
                tracing::warn!(error = %e, "cluster: raft shutdown on graceful stop failed");
            } else {
                tracing::info!("cluster: raft shut down on graceful stop");
            }
        });
    quiesce_and_close(
        durable_kv_handle,
        reconcile,
        Some(raft_shutdown),
        kv_close_deadline,
    )
    .await;
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
    let tls = boatramp_server::ReloadableTls::new(config);

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
                                    tls.reload(tcp);
                                    match boatramp_server::quinn_server_config(h3) {
                                        Ok(qc) => endpoint.set_server_config(Some(qc)),
                                        Err(err) => {
                                            tracing::error!(%err, "cluster acme-dns: rebuilding h3 config failed");
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(%err, "cluster acme-dns: rebuilding TLS config failed");
                                }
                            }
                        } else {
                            match crate::acme_dns::build_server_config(entries) {
                                Ok(config) => tls.reload(config),
                                Err(err) => {
                                    tracing::error!(%err, "cluster acme-dns: rebuilding TLS config failed");
                                }
                            }
                        }
                        #[cfg(not(feature = "http3"))]
                        match crate::acme_dns::build_server_config(entries) {
                            Ok(config) => tls.reload(config),
                            Err(err) => {
                                tracing::error!(%err, "cluster acme-dns: rebuilding TLS config failed");
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
    let scheduler = handlers.spawn_scheduler(deploy.clone());
    let (app, fast) = boatramp_server::router_with_fast(deploy, auth, handlers, options);
    // Serve h3 over the QUIC endpoint + advertise it on the HTTPS responses (on the
    // bypass too, so a hot-path response advertises h3 identically to the router).
    #[cfg(feature = "http3")]
    let (app, fast) = if let Some(endpoint) = h3_endpoint {
        let app_h3 = app.clone();
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_http3_endpoint(endpoint, app_h3).await {
                tracing::error!(%err, "cluster acme-dns: HTTP/3 listener failed");
            }
        });
        (
            boatramp_server::advertise_http3(app, addr.port()),
            fast.advertise_http3(addr.port()),
        )
    } else {
        (app, fast)
    };
    let serve_result =
        boatramp_server::serve_tls(addr, tls, (app, fast), boatramp_server::shutdown_signal())
            .await;
    // Fully quiesce the background scheduler (delivery drainer + blob watchers + in-flight crons)
    // once the serve future returns, BEFORE the caller's `quiesce_and_close` closes the store — so
    // no scheduler task can land a KV write into a fresh WAL segment after `close()` (Part A). This
    // mirrors `serve_with`, which quiesces its own scheduler on the plaintext (`--tls off`) path.
    #[cfg(feature = "handlers")]
    if let Some(handle) = scheduler {
        handle.quiesce().await;
    }
    serve_result?;
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
    let tls = boatramp_server::ReloadableTls::new(config);

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
                                    tls.reload(tcp);
                                    match boatramp_server::quinn_server_config(h3) {
                                        Ok(qc) => endpoint.set_server_config(Some(qc)),
                                        Err(err) => {
                                            tracing::error!(%err, "acme-dns: rebuilding h3 config failed");
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(%err, "acme-dns: rebuilding TLS config failed");
                                }
                            }
                        } else {
                            match crate::acme_dns::build_server_config(entries) {
                                Ok(config) => tls.reload(config),
                                Err(err) => {
                                    tracing::error!(%err, "acme-dns: rebuilding TLS config failed");
                                }
                            }
                        }
                        #[cfg(not(feature = "http3"))]
                        match crate::acme_dns::build_server_config(entries) {
                            Ok(config) => tls.reload(config),
                            Err(err) => {
                                tracing::error!(%err, "acme-dns: rebuilding TLS config failed");
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
    // handle is fully quiesced on graceful shutdown (below) so no scheduler task can
    // issue a KV write after the store is closed (Part A).
    #[cfg(feature = "handlers")]
    let scheduler = handlers.spawn_scheduler(deploy.clone());
    let (app, fast) = boatramp_server::router_with_fast(deploy, auth, handlers, options);
    #[cfg(feature = "http3")]
    let (app, fast) = if let Some(endpoint) = h3_endpoint {
        let app_h3 = app.clone();
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_http3_endpoint(endpoint, app_h3).await {
                tracing::error!(%err, "acme-dns: HTTP/3 listener failed");
            }
        });
        (
            boatramp_server::advertise_http3(app, addr.port()),
            fast.advertise_http3(addr.port()),
        )
    } else {
        (app, fast)
    };
    let serve_result =
        boatramp_server::serve_tls(addr, tls, (app, fast), boatramp_server::shutdown_signal())
            .await;
    // Fully quiesce the background scheduler (delivery drainer + blob watchers + in-flight crons)
    // once the serve future returns, BEFORE the caller's `quiesce_and_close` closes the store — so
    // no scheduler task can land a KV write into a fresh WAL segment after `close()` (Part A). This
    // mirrors `serve_with`, which quiesces its own scheduler on the plaintext (`--tls off`) path.
    #[cfg(feature = "handlers")]
    if let Some(handle) = scheduler {
        handle.quiesce().await;
    }
    serve_result?;
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

    let (certs, private_key) = load_cert_chain_and_key(&cert, &key)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    tracing::info!(%addr, "serving HTTPS (custom certificate)");
    // Background scheduler (consumers/crons) — must run under TLS too, not only
    // `--tls off`; in cluster mode its cron tick is gated on `is_leader`. The
    // handle is fully quiesced on graceful shutdown (below) so no scheduler task can
    // issue a KV write after the store is closed (Part A).
    #[cfg(feature = "handlers")]
    let scheduler = handlers.spawn_scheduler(deploy.clone());
    let (app, fast) = boatramp_server::router_with_fast(deploy, auth, handlers, options);

    // Optionally serve HTTP/3 on the same UDP port, feeding the same router, and
    // advertise it (`Alt-Svc`) on the HTTPS responses so clients upgrade to h3 —
    // without the header the h3 listener is never discovered. The bypass gets the same
    // Alt-Svc so a hot-path response advertises h3 identically.
    #[cfg(feature = "http3")]
    let (app, fast) = if args.http3 {
        let (certs, key) = load_cert_chain_and_key(&cert, &key)?;
        let app_h3 = app.clone();
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_http3(addr, certs, key, app_h3).await {
                tracing::error!(%err, "HTTP/3 listener failed");
            }
        });
        (
            boatramp_server::advertise_http3(app, addr.port()),
            fast.advertise_http3(addr.port()),
        )
    } else {
        (app, fast)
    };

    let serve_result = boatramp_server::serve_tls(
        addr,
        config.into(),
        (app, fast),
        boatramp_server::shutdown_signal(),
    )
    .await;
    // Fully quiesce the background scheduler (delivery drainer + blob watchers + in-flight crons)
    // once the serve future returns, BEFORE the caller's `quiesce_and_close` closes the store — so
    // no scheduler task can land a KV write into a fresh WAL segment after `close()` (Part A). This
    // mirrors `serve_with`, which quiesces its own scheduler on the plaintext (`--tls off`) path.
    #[cfg(feature = "handlers")]
    if let Some(handle) = scheduler {
        handle.quiesce().await;
    }
    serve_result?;
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
                tracing::warn!(%err, "could not mint the bootstrap-TLS attestation; --root-pubkey pinning unavailable");
            }
        }
    }

    // No client-auth trust set: the client authenticates with a bearer token, not
    // a client cert (that is the mutual-`cnf` binding of a later stage).
    let rpk =
        boatramp_rpktls::RpkTls::new(Arc::new(identity), boatramp_rpktls::TrustSet::default());
    let mut config = rpk.server_auth()?;
    config.alpn_protocols = boatramp_server::alpn_h1_h2();

    tracing::info!(%addr, pubkey = %fingerprint, "serving HTTPS (RPK bootstrap TLS)");
    // The identity is public (not a secret); print it so the operator can copy it
    // to the client's `--server-pubkey`.
    println!(
        "control-plane RPK TLS identity — pin the client with:\n  --server-pubkey {fingerprint}"
    );

    #[cfg(feature = "handlers")]
    let scheduler = handlers.spawn_scheduler(deploy.clone());
    let (app, fast) = boatramp_server::router_with_fast(deploy, auth, handlers, options);
    let serve_result = boatramp_server::serve_tls(
        addr,
        config.into(),
        (app, fast),
        boatramp_server::shutdown_signal(),
    )
    .await;
    // Fully quiesce the background scheduler (delivery drainer + blob watchers + in-flight crons)
    // once the serve future returns, BEFORE the caller's `quiesce_and_close` closes the store — so
    // no scheduler task can land a KV write into a fresh WAL segment after `close()` (Part A). This
    // mirrors `serve_with`, which quiesces its own scheduler on the plaintext (`--tls off`) path.
    #[cfg(feature = "handlers")]
    if let Some(handle) = scheduler {
        handle.quiesce().await;
    }
    serve_result?;
    Ok(())
}

/// Load a PEM cert chain + private key as DER — for the rustls `ServerConfig`
/// built by the custom-cert listener and (when enabled) the HTTP/3 (quinn) one.
#[cfg(feature = "tls")]
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
    use rustls_acme::{AcmeConfig, caches::DirCache};

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
    // Build one rustls config off the ACME state's cert resolver, advertising both
    // the serving ALPN (`h2`/`http/1.1`) and `acme-tls/1`. The resolver internally
    // detects a TLS-ALPN-01 challenge ClientHello and serves the challenge cert;
    // `serve_tls` recognizes the negotiated `acme-tls/1` and completes-then-drops
    // that handshake, serving everything else as HTTP. One config, no separate
    // acceptor — and no hyper.
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    rustls_config.alpn_protocols = boatramp_server::alpn_h1_h2();
    rustls_config.alpn_protocols.push(b"acme-tls/1".to_vec());
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
    // handle is fully quiesced on graceful shutdown (below) so no scheduler task can
    // issue a KV write after the store is closed (Part A).
    #[cfg(feature = "handlers")]
    let scheduler = handlers.spawn_scheduler(deploy.clone());
    let (app, fast) = boatramp_server::router_with_fast(deploy, auth, handlers, options);
    let serve_result = boatramp_server::serve_tls(
        addr,
        rustls_config.into(),
        (app, fast),
        boatramp_server::shutdown_signal(),
    )
    .await;
    // Fully quiesce the background scheduler (delivery drainer + blob watchers + in-flight crons)
    // once the serve future returns, BEFORE the caller's `quiesce_and_close` closes the store — so
    // no scheduler task can land a KV write into a fresh WAL segment after `close()` (Part A). This
    // mirrors `serve_with`, which quiesces its own scheduler on the plaintext (`--tls off`) path.
    #[cfg(feature = "handlers")]
    if let Some(handle) = scheduler {
        handle.quiesce().await;
    }
    serve_result?;
    Ok(())
}

/// Install a process-wide default rustls crypto provider (rustls 0.23 requires
/// one before building any TLS config). Idempotent.
#[cfg(feature = "tls")]
fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

#[cfg(test)]
mod tests {
    // Every OTHER test remaining in this module is `cluster`-gated; the import is unused
    // in a lean build (the single-node auth tests moved to `boatramp_node::auth`).
    #[cfg(feature = "cluster")]
    use super::*;

    // kv-sql WS4 classifier gates — NOT cluster-gated (pure config logic; run in every tier).
    use super::{
        KvOpenFailureRoute, declared_kv_writer_model, kv_open_failure_route,
        multi_writer_cluster_refusal,
    };
    use boatramp_core::kv::WriterModel;
    use boatramp_node::backends::KvBackend;
    use boatramp_node::config::SqlKvConfig;

    fn sql_cfg(kind: &str) -> SqlKvConfig {
        SqlKvConfig {
            kind: kind.to_string(),
            ..Default::default()
        }
    }

    /// C7/UX-C4 — the DECLARED writer model is derived WITHOUT opening the store: Postgres/MySQL are
    /// multi-writer; sqlite/empty/unknown + every non-SQL backend are single-writer (fail-safe).
    #[test]
    fn declared_writer_model_classifies_backends() {
        assert_eq!(
            declared_kv_writer_model(KvBackend::Sql, Some(&sql_cfg("postgres"))),
            WriterModel::MultiWriter
        );
        assert_eq!(
            declared_kv_writer_model(KvBackend::Sql, Some(&sql_cfg("pg"))),
            WriterModel::MultiWriter
        );
        assert_eq!(
            declared_kv_writer_model(KvBackend::Sql, Some(&sql_cfg("mysql"))),
            WriterModel::MultiWriter
        );
        assert_eq!(
            declared_kv_writer_model(KvBackend::Sql, Some(&sql_cfg("sqlite"))),
            WriterModel::SingleWriter
        );
        assert_eq!(
            declared_kv_writer_model(KvBackend::Sql, Some(&sql_cfg(""))),
            WriterModel::SingleWriter,
            "empty kind defaults to sqlite (single-writer)"
        );
        assert_eq!(
            declared_kv_writer_model(KvBackend::Sql, Some(&sql_cfg("weird"))),
            WriterModel::SingleWriter,
            "unknown kind is fail-safe single-writer (build_kv surfaces the real error)"
        );
        for b in [KvBackend::Slatedb, KvBackend::Memory, KvBackend::Cloudflare] {
            assert_eq!(declared_kv_writer_model(b, None), WriterModel::SingleWriter);
        }
    }

    /// UX-C4 — a multi-writer backend WITH any Raft-cluster signal is REFUSED, and the message names
    /// both sides + the cure + "nothing started"; every non-contradictory combination is allowed.
    #[test]
    fn multi_writer_with_cluster_is_refused() {
        // Refused: multi-writer + each cluster signal.
        for (cfg, init, join) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let msg = multi_writer_cluster_refusal(true, cfg, init, join)
                .expect("multi-writer + a cluster signal must refuse");
            assert!(msg.contains("NOTHING was started"));
            assert!(msg.to_lowercase().contains("multi-writer"));
            assert!(msg.contains("Raft"));
            assert!(msg.contains("Cure"));
        }
        // Allowed: multi-writer WITHOUT a cluster (scale as N stateless nodes).
        assert!(multi_writer_cluster_refusal(true, false, false, false).is_none());
        // Allowed: single-writer WITH a cluster (uses Raft, as before).
        assert!(multi_writer_cluster_refusal(false, true, true, true).is_none());
    }

    /// C7 — the backend-aware `kv-status` descriptor is honest per backend: a multi-writer Postgres
    /// reports family `sql` / dialect `postgres` / `multi_writer` / coordination `shared` with the
    /// cp-id + member count; SlateDB reports `slatedb` / `single_writer` / `none` and NO cp-id. The
    /// SQL location is credential-redacted (the env var NAME, never the URL).
    #[test]
    fn kv_status_descriptor_is_backend_honest() {
        use super::build_kv_status_info;
        use boatramp_core::shared_mode::ControlPlaneJoinReport;
        use std::path::Path;

        let mut pg = sql_cfg("postgres");
        pg.url_env = Some("BOATRAMP_PG_URL".to_string());
        let report = ControlPlaneJoinReport {
            control_plane_id: "7f3adeadbeef".to_string(),
            created_new: false,
            this_node: "node-x".to_string(),
            members_seen: 3,
        };
        let info = build_kv_status_info(
            KvBackend::Sql,
            Some(&pg),
            true,
            Path::new("./data"),
            None,
            "node-x",
            Some(&report),
        );
        assert_eq!(info.backend_family, "sql");
        assert_eq!(info.backend_dialect.as_deref(), Some("postgres"));
        assert_eq!(info.writer_model, "multi_writer");
        assert_eq!(info.coordination_mode, "shared");
        assert_eq!(info.control_plane_id.as_deref(), Some("cp-7f3adead"));
        assert_eq!(info.members_seen, Some(3));
        assert!(
            info.location.contains("BOATRAMP_PG_URL") && !info.location.contains("://"),
            "location names the env var, never the URL: {}",
            info.location
        );

        let slate = build_kv_status_info(
            KvBackend::Slatedb,
            None,
            false,
            Path::new("./data"),
            None,
            "node-x",
            None,
        );
        assert_eq!(slate.backend_family, "slatedb");
        assert_eq!(slate.writer_model, "single_writer");
        assert_eq!(slate.coordination_mode, "none");
        assert!(slate.control_plane_id.is_none());
    }

    /// C4 — a SQL open failure routes to the recovery listener (NOT `exit`/propagate); SlateDB keeps
    /// its own recovery route; memory/cloudflare propagate (memory never fails; CF has no local store).
    #[test]
    fn sql_open_failure_routes_to_recovery_not_exit() {
        assert_eq!(
            kv_open_failure_route(KvBackend::Sql),
            KvOpenFailureRoute::SqlRecovery,
            "a SQL open failure must enter the recovery listener, never exit(1)"
        );
        assert_eq!(
            kv_open_failure_route(KvBackend::Slatedb),
            KvOpenFailureRoute::SlatedbRecovery
        );
        assert_eq!(
            kv_open_failure_route(KvBackend::Memory),
            KvOpenFailureRoute::Propagate
        );
        assert_eq!(
            kv_open_failure_route(KvBackend::Cloudflare),
            KvOpenFailureRoute::Propagate
        );
    }

    /// **A3** — bounded close: a stalled `close()` is abandoned at the CONFIGURED `close_deadline`
    /// (v0.9.0 KV-recovery, C12 — no longer the old hardcoded 3s) so the process still makes progress
    /// on shutdown. A `KvStore` whose `close()` hangs forever must not wedge `quiesce_and_close`; it
    /// returns within ~the configured budget, not never.
    ///
    /// Mutation guarded: dropping the `tokio::time::timeout` wrapper in `quiesce_and_close` makes
    /// this test hang past its own bound and the harness kills it — i.e. the gate goes red.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a3_stalled_close_is_abandoned_at_deadline() {
        use boatramp_core::kv::{KvError, KvStore};
        use std::sync::Arc;

        // A store whose `close()` never returns (models a wedged object-store flush).
        struct HangingKv;
        #[async_trait::async_trait]
        impl KvStore for HangingKv {
            async fn get(&self, _k: &str) -> std::result::Result<Option<Vec<u8>>, KvError> {
                Ok(None)
            }
            async fn put(&self, _k: &str, _v: Vec<u8>) -> std::result::Result<(), KvError> {
                Ok(())
            }
            async fn delete(&self, _k: &str) -> std::result::Result<(), KvError> {
                Ok(())
            }
            async fn list_prefix(&self, _p: &str) -> std::result::Result<Vec<String>, KvError> {
                Ok(Vec::new())
            }
            async fn close(&self) -> std::result::Result<(), KvError> {
                // Hang forever — the deadline in `quiesce_and_close` must abandon it.
                std::future::pending::<()>().await;
                unreachable!("close() must be abandoned at the deadline")
            }
        }

        // With the virtual clock paused, `quiesce_and_close` should still resolve — the timeout fires
        // at the CONFIGURED budget we pass in (here a short test budget). `tokio::time::timeout` on the
        // OUTER bound proves the tail itself did not hang: it must complete strictly before we give up.
        let kv: Arc<dyn KvStore> = Arc::new(HangingKv);
        let configured_budget = std::time::Duration::from_secs(7);
        let outcome = tokio::time::timeout(
            configured_budget + std::time::Duration::from_secs(2),
            super::quiesce_and_close(kv, Vec::new(), None, configured_budget),
        )
        .await;
        assert!(
            outcome.is_ok(),
            "A3: a stalled close must be abandoned at the CONFIGURED close_deadline, not hang"
        );
    }

    /// **A2-cluster** — the Raft shutdown runs BEFORE the store close (the highest-risk ordering:
    /// a write/apply after the store mark would lose a committed entry or desync the log vs the
    /// state machine). An ordering-recording KV close + a raft-shutdown future push their order
    /// into a shared log; the gate asserts raft-shutdown precedes the store close.
    ///
    /// Anti-hollow mutation: swap the order in `quiesce_and_close` (close the store before awaiting
    /// `raft_shutdown`). Then the recorded order is `["close", "raft"]` and this assertion fails.
    #[tokio::test]
    async fn a2_cluster_raft_shuts_down_before_store_close() {
        use boatramp_core::kv::{KvError, KvStore};
        use std::sync::{Arc, Mutex};

        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));

        // A KV whose `close()` records "close" in the shared order log.
        struct OrderKv(Arc<Mutex<Vec<&'static str>>>);
        #[async_trait::async_trait]
        impl KvStore for OrderKv {
            async fn get(&self, _k: &str) -> std::result::Result<Option<Vec<u8>>, KvError> {
                Ok(None)
            }
            async fn put(&self, _k: &str, _v: Vec<u8>) -> std::result::Result<(), KvError> {
                Ok(())
            }
            async fn delete(&self, _k: &str) -> std::result::Result<(), KvError> {
                Ok(())
            }
            async fn list_prefix(&self, _p: &str) -> std::result::Result<Vec<String>, KvError> {
                Ok(Vec::new())
            }
            async fn close(&self) -> std::result::Result<(), KvError> {
                self.0.lock().unwrap().push("close");
                Ok(())
            }
        }

        let kv: Arc<dyn KvStore> = Arc::new(OrderKv(order.clone()));
        // The raft-shutdown future records "raft" when awaited (as the cluster path threads it).
        let raft_order = order.clone();
        let raft_shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            Box::pin(async move {
                raft_order.lock().unwrap().push("raft");
            });

        super::quiesce_and_close(
            kv,
            Vec::new(),
            Some(raft_shutdown),
            std::time::Duration::from_secs(20),
        )
        .await;

        assert_eq!(
            *order.lock().unwrap(),
            vec!["raft", "close"],
            "A2-cluster: raft.shutdown() MUST precede the store close (else a committed entry is \
             lost or the log desyncs the state machine)"
        );
    }

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

    /// #505 (MEDIUM-1): on the cluster serve path a `boatramp:<name>` node-cred is refused
    /// STRUCTURALLY by the up-front scheme check (`boatramp_ref_name` ⇒ `BoatrampRefOnCluster`), NOT by
    /// an incidental empty-store miss, while a legitimate `env:` misconfig resolves normally and
    /// surfaces its OWN error — never the misleading cluster "use `env:`" suffix. This asserts the exact
    /// composition the cluster branch performs (the branch itself needs a full Raft bring-up).
    #[cfg(feature = "cluster")]
    #[tokio::test]
    async fn cluster_path_refuses_boatramp_ref_structurally_and_surfaces_env_errors_unwrapped() {
        use boatramp_node::config::S3CredentialConfig;
        use boatramp_node::s3_credential::{
            S3CredentialError, boatramp_ref_name, resolve_s3_credential,
        };

        // (1) STRUCTURAL refusal: the scheme check fires for a `boatramp:` ref, yielding the dedicated
        // error, BEFORE any resolve touches a store. The cluster branch returns exactly this.
        let cfg = S3CredentialConfig {
            access_key_id: "AKID-PUBLIC".to_string(),
            secret_access_key: "boatramp:tigris-key".to_string(),
        };
        let name = boatramp_ref_name(&cfg.secret_access_key)
            .expect("a boatramp: ref is detected by the scheme check");
        let cluster_err =
            Error::S3Ingress(S3CredentialError::BoatrampRefOnCluster(name.to_string()).to_string())
                .to_string();
        assert!(
            cluster_err.contains("not supported on a cluster"),
            "the dedicated cluster refusal message: {cluster_err}"
        );

        // (2) An `env:` misconfig on the cluster path (unset var) resolves normally — an empty
        // in-memory stand-in KV is correct because `env:` never touches the store — and surfaces its
        // OWN error UNWRAPPED (mapped via `Error::S3Ingress(e.to_string())`), NOT the cluster suffix.
        let cfg = S3CredentialConfig {
            access_key_id: "AKID-PUBLIC".to_string(),
            secret_access_key: "env:UNSET_S3_SECRET_FOR_TEST".to_string(),
        };
        assert!(
            boatramp_ref_name(&cfg.secret_access_key).is_none(),
            "an env: ref is NOT caught by the boatramp scheme check"
        );
        let err = resolve_s3_credential(
            &cfg,
            std::sync::Arc::new(boatramp_core::kv::MemoryKv::new()),
            None,
            true, // allow_env_secret_refs: the dev posture, so it gets past the posture gate to `unset`
            &boatramp_core::env::MapEnv::new(),
        )
        .await
        .expect_err("an unset env var must error");
        assert_eq!(
            err,
            S3CredentialError::EnvVarUnset("UNSET_S3_SECRET_FOR_TEST".to_string())
        );
        let mapped = Error::S3Ingress(err.to_string()).to_string();
        assert!(
            mapped.contains("is not set"),
            "the env error surfaces its own message: {mapped}"
        );
        assert!(
            !mapped.contains("not supported on a cluster"),
            "the env error must NOT carry the misleading cluster suffix: {mapped}"
        );
    }
}
