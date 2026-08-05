//! Assembly errors surfaced by the node-library helpers (moved out of the
//! binary's `serve::Error`, which absorbs them via `#[from]`). Scoped to the
//! handler/SQL assembly today; grows as more of `assemble()` moves here.

/// A node-assembly error. Variants are feature-gated to the assembly path that
/// produces them, matching the crate's forwarded features.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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

    /// Building the wasm handler engine failed.
    #[cfg(feature = "handlers")]
    #[error(transparent)]
    Handler(#[from] boatramp_handlers::HandlerError),
}

/// Node-assembly result alias.
pub type Result<T> = std::result::Result<T, Error>;
