//! Error types for the shared config/routing layer.

/// Errors from parsing or compiling deploy configuration ([`crate::config`]).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The deploy `routing` config could not be parsed.
    #[error("config parse error: {0}")]
    Parse(String),

    /// A route/header pattern is invalid.
    #[error("invalid pattern `{pattern}`: {reason}")]
    Pattern {
        /// The offending pattern.
        pattern: String,
        /// Why it was rejected.
        reason: String,
    },
}

impl ConfigError {
    /// Convenience constructor for [`ConfigError::Parse`].
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    /// Convenience constructor for [`ConfigError::Pattern`].
    pub fn pattern(pattern: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Pattern {
            pattern: pattern.into(),
            reason: reason.into(),
        }
    }
}
