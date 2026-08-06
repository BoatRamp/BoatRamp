//! Assembly errors surfaced by the node-library helpers (moved out of the
//! binary's `serve::Error`, which absorbs them via `#[from]`). Scoped to the
//! handler/SQL assembly today; grows as more of `assemble()` moves here.

/// A node-assembly error. Variants are feature-gated to the assembly path that
/// produces them, matching the crate's forwarded features.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A token root **private** key (hex) failed to parse, or an external signer
    /// (KMS/HSM/Vault) failed to build / resolve its public key.
    #[error("invalid auth root private key: {0}")]
    AuthPrivKey(String),
    /// A token root **public** key (hex) failed to parse.
    #[error("invalid auth root public key: {0}")]
    AuthPubKey(String),
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
    /// An external database named an unrecognised engine `kind`.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[error("handlers SQL binding: external database {name:?} has unknown kind {kind:?} (expected postgres | mysql)")]
    SqlExternalKind { name: String, kind: String },
    /// An external database entry omitted the required `url_env`.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[error("handlers SQL binding: external database {0:?} is missing `url_env`")]
    SqlExternalUrlEnvMissing(String),
    /// Building an external database backend (pool/URL parse) failed.
    #[cfg(any(feature = "sql-postgres", feature = "sql-mysql"))]
    #[error("handlers SQL binding: external database {name:?}: {source}")]
    SqlExternalConnect {
        name: String,
        #[source]
        source: boatramp_core::sql::SqlError,
    },
    /// External databases were configured but this build has no external SQL
    /// engine compiled in.
    #[cfg(all(
        feature = "handlers",
        not(any(feature = "sql-postgres", feature = "sql-mysql"))
    ))]
    #[error("handlers SQL binding: external database {0:?} needs an external SQL engine — rebuild with --features sql-postgres and/or sql-mysql")]
    SqlExternalUnavailable(String),

    /// `--kv slatedb` selected but this build lacks SlateDB support.
    #[cfg(not(feature = "slatedb"))]
    #[error("this build has no slatedb support; rebuild with `--features slatedb`")]
    NoSlatedbSupport,
    /// `--kv cloudflare` selected but this build lacks Cloudflare KV support.
    #[cfg(not(feature = "cloudflare-kv"))]
    #[error("this build has no Cloudflare KV support; rebuild with `--features cloudflare-kv`")]
    NoCloudflareKvSupport,
    /// Opening the KV store (SlateDB / Cloudflare) failed.
    #[cfg(any(feature = "slatedb", feature = "cloudflare-kv"))]
    #[error(transparent)]
    Kv(#[from] boatramp_core::kv::KvError),

    /// `--blobs fs` selected but this build lacks filesystem blob support.
    #[cfg(not(feature = "fs"))]
    #[error("this build has no filesystem blob support; rebuild with `--features fs`")]
    NoFsSupport,
    /// `--blobs s3` selected but this build lacks S3 support.
    #[cfg(not(feature = "s3"))]
    #[error("this build has no S3 support; rebuild with `--features s3`")]
    NoS3Support,
    /// `--blobs gcs` selected but this build lacks GCS support.
    #[cfg(not(feature = "gcs"))]
    #[error("this build has no GCS support; rebuild with `--features gcs`")]
    NoGcsSupport,
    /// `--blobs azure` selected but this build lacks Azure support.
    #[cfg(not(feature = "azure"))]
    #[error("this build has no Azure support; rebuild with `--features azure`")]
    NoAzureSupport,
    /// `--blobs s3` without `--s3-bucket`.
    #[cfg(feature = "s3")]
    #[error("--s3-bucket is required for --blobs s3")]
    S3BucketRequired,
    /// `--blobs gcs` was selected without a bucket.
    #[cfg(feature = "gcs")]
    #[error("--gcs-bucket is required for --blobs gcs")]
    GcsBucketRequired,
    /// Connecting the GCS backend failed (usually credential resolution).
    #[cfg(feature = "gcs")]
    #[error("GCS backend: {0}")]
    GcsConnect(String),
    /// `--blobs azure` was selected without an account/container.
    #[cfg(feature = "azure")]
    #[error("--azure-account and --azure-container are required for --blobs azure")]
    AzureConfigRequired,
    /// Connecting the Azure backend failed.
    #[cfg(feature = "azure")]
    #[error("Azure backend: {0}")]
    AzureConnect(String),

    /// Building the wasm handler engine failed.
    #[cfg(feature = "handlers")]
    #[error(transparent)]
    Handler(#[from] boatramp_handlers::HandlerError),
}

/// Node-assembly result alias.
pub type Result<T> = std::result::Result<T, Error>;
