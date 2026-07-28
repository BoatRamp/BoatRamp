//! Error type for the MCP layer, with a mapping into rmcp's wire error so every
//! tool can `?`-propagate into a JSON-RPC error the agent sees.

/// A failure in the MCP server: configuration, instance resolution, or a
/// control-plane API call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The control plane returned a non-success HTTP status.
    #[error("control-plane api error ({status}): {message}")]
    Api {
        /// The HTTP status code.
        status: u16,
        /// The response body (or a summary of it).
        message: String,
    },

    /// An HTTP request to the control plane failed to complete.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// A configuration problem (bad file, duplicate/missing instance on edit).
    #[error("config error: {0}")]
    Config(String),

    /// A tool named an instance that is not registered.
    #[error("instance not found: '{0}'")]
    InstanceNotFound(String),

    /// No `instance` was given but more than one is registered, so the target is
    /// ambiguous. The message lists the registered names.
    #[error(
        "instance required: multiple instances are registered ({available}); pass the 'instance' parameter"
    )]
    InstanceRequired {
        /// Comma-separated registered instance names.
        available: String,
    },

    /// No instances are registered at all.
    #[error("no boatramp instances registered; run `boatramp mcp setup add <name> --server <url>` first")]
    NoInstances,

    /// A required argument (e.g. a token spec that resolves empty) was missing.
    #[error("invalid argument: {0}")]
    Invalid(String),

    /// Reading a local file (a blob/artifact to upload) failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// (De)serializing JSON failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Serializing the config TOML failed.
    #[error("toml write error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// Parsing the config TOML failed.
    #[error("toml parse error: {0}")]
    TomlDe(#[from] toml::de::Error),
}

/// The MCP layer's result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for rmcp::model::ErrorData {
    fn from(err: Error) -> Self {
        Self::new(
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            err.to_string(),
            None::<serde_json::Value>,
        )
    }
}
