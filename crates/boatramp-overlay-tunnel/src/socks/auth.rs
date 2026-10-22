//! Local SOCKS auth (plan §2/§5, open decision §9.2 — default ON): on a multi-user host any local
//! user could otherwise proxy under your overlay identity through an unauthenticated loopback SOCKS
//! port, so this proxy requires RFC-1929 username/password by default (`--no-local-auth` opts out).
//!
//! The generated credential needs cryptographically-strong randomness, but the SOCKS front-end adds
//! NO new dependency (plan §4/§7 — keeps the lean build ring-free): rather than pull a `getrandom`
//! dep of its own, this reuses the one dependency this crate already has — `OverlaySecret::generate`
//! (`boatramp-overlay-client`) already seeds an Ed25519 key from the platform RNG, so its 32-byte
//! seed is a ready source of secure random bytes with zero added dependency surface.
//!
//! Persistence (`load_or_generate`) is a generic "secret at a path, 0600, atomic-ish on first use"
//! mechanism — deliberately NOT XDG-aware itself: the CLI (which already resolves
//! `~/.config/boatramp/…` for the operator identity key) decides the actual path and passes it in,
//! keeping this core crate free of any assumption about where a consumer wants its secrets to live.

use std::path::Path;

use boatramp_overlay_client::OverlaySecret;

/// A loopback-local SOCKS credential (RFC 1929 username/password).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuth {
    pub username: String,
    pub password: String,
}

/// A failure generating or persisting a [`LocalAuth`].
#[derive(Debug, thiserror::Error)]
pub enum LocalAuthError {
    #[error("generating a local auth token: {0}")]
    Identity(#[from] boatramp_overlay_client::OverlayIdError),
    #[error("{path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The persisted file is not in the `user\npass\n` shape this module wrote.
    #[error("{0}: malformed local-auth file (expected two lines: username, password)")]
    Malformed(std::path::PathBuf),
}

impl LocalAuth {
    /// Generate a fresh credential. See the module doc for why this needs no new RNG dependency.
    pub fn generate() -> Result<Self, LocalAuthError> {
        let secret = OverlaySecret::generate()?;
        let seed = secret.seed_hex();
        let seed_str: &str = seed.as_str();
        let hex = seed_str.strip_prefix("ed25519:").unwrap_or(seed_str);
        let (user_half, pass_half) = hex.split_at(hex.len() / 2);
        Ok(Self {
            username: format!("tunnel-{user_half}"),
            password: pass_half.to_string(),
        })
    }

    /// Serialize as the two-line `username\npassword\n` shape [`load_or_generate`] reads back.
    fn to_file_contents(&self) -> String {
        format!("{}\n{}\n", self.username, self.password)
    }

    fn parse(path: &Path, contents: &str) -> Result<Self, LocalAuthError> {
        let mut lines = contents.lines();
        let (Some(username), Some(password)) = (lines.next(), lines.next()) else {
            return Err(LocalAuthError::Malformed(path.to_path_buf()));
        };
        if username.is_empty() || password.is_empty() {
            return Err(LocalAuthError::Malformed(path.to_path_buf()));
        }
        Ok(Self {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Load the credential persisted at `path`, generating + writing a fresh one (mode `0600`) on
    /// first use — mirroring the CLI's own `operator_identity()` key-at-rest pattern.
    pub fn load_or_generate(path: &Path) -> Result<Self, LocalAuthError> {
        let io = |source: std::io::Error| LocalAuthError::Io {
            path: path.to_path_buf(),
            source,
        };
        match std::fs::read_to_string(path) {
            Ok(contents) => Self::parse(path, &contents),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let auth = Self::generate()?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(io)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            parent,
                            std::fs::Permissions::from_mode(0o700),
                        );
                    }
                }
                #[cfg(unix)]
                {
                    use std::io::Write as _;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .map_err(io)?;
                    f.write_all(auth.to_file_contents().as_bytes())
                        .map_err(io)?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::write(path, auth.to_file_contents().as_bytes()).map_err(io)?;
                }
                Ok(auth)
            }
            Err(e) => Err(io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_non_empty_distinct_credentials() {
        let a = LocalAuth::generate().unwrap();
        let b = LocalAuth::generate().unwrap();
        assert!(!a.username.is_empty() && !a.password.is_empty());
        assert_ne!(a, b, "two generations must not collide");
    }

    #[test]
    fn load_or_generate_persists_0600_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("br-tunnel-auth-test-{}", std::process::id()));
        let path = dir.join("tunnel-socks.auth");
        let _ = std::fs::remove_dir_all(&dir);

        let first = LocalAuth::load_or_generate(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let second = LocalAuth::load_or_generate(&path).unwrap();
        assert_eq!(
            first, second,
            "a second load must return the SAME persisted credential"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_is_reported_not_silently_accepted() {
        let dir = std::env::temp_dir().join(format!("br-tunnel-auth-bad-{}", std::process::id()));
        let path = dir.join("tunnel-socks.auth");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "only-one-line\n").unwrap();
        let err = LocalAuth::load_or_generate(&path).unwrap_err();
        assert!(matches!(err, LocalAuthError::Malformed(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
