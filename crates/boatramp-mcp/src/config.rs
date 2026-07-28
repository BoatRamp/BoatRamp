//! The multi-instance MCP config (`~/.config/boatramp/mcp.toml`).
//!
//! One `[[instances]]` block per boatramp control plane the agent can drive. Like
//! the rest of boatramp's config surface, secrets are never written inline: the
//! `token` / `holder_key` fields are **specs** resolved at load time —
//! `env:VAR` reads an environment variable, `path:/file` reads a file (trimmed),
//! and anything else is treated as a literal (handy for a throwaway token, but
//! `env:`/`path:` are preferred).

use crate::error::{Error, Result};
use std::fs;
use std::path::PathBuf;

/// The whole config file: a list of named instances.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Every registered boatramp instance.
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
}

/// One boatramp control plane the MCP server can talk to.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstanceConfig {
    /// The name the agent uses to select this instance (unique).
    pub name: String,
    /// The control-plane base URL, e.g. `https://boatramp.example.com`.
    pub server: String,
    /// The admin/control-plane token spec (`env:VAR` / `path:/file` / literal).
    /// Empty resolves to no token (an unauthenticated/dev control plane).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// The token holder (`cnf`) private-key spec for per-request DPoP/PoP proofs
    /// (`env:VAR` / `path:/file` / literal hex). Required only for `cnf`-bound
    /// tokens; omit for a plain bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<String>,
    /// The server's raw-public-key SPKI hex to pin (RFC 7250 `--tls rpk`). When
    /// set, the client authenticates the server by this key instead of the web PKI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_pubkey: Option<String>,
    /// Skip TLS certificate verification for this instance (self-signed cert on a
    /// trusted private network only). Off by default; dangerous over the public net.
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Resolve a secret **spec** to its value: `env:VAR`, `path:/file`, or a literal.
/// An empty spec resolves to `None`. A named env var / file that is missing or
/// empty is an error (a misconfiguration, not a silent "no secret").
pub fn resolve_secret(spec: &str) -> Result<Option<String>> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }
    if let Some(var) = spec.strip_prefix("env:") {
        return match std::env::var(var) {
            Ok(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
            _ => Err(Error::Config(format!("env var {var} is unset or empty"))),
        };
    }
    if let Some(path) = spec.strip_prefix("path:") {
        let raw = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("secret file {path}: {e}")))?;
        let token = raw.trim().to_string();
        return if token.is_empty() {
            Err(Error::Config(format!("secret file {path} is empty")))
        } else {
            Ok(Some(token))
        };
    }
    Ok(Some(spec.to_string()))
}

/// `~/.config/boatramp` (honoring `$XDG_CONFIG_HOME`), falling back to `.` if no
/// home is discoverable.
pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("boatramp");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".config").join("boatramp");
        }
    }
    PathBuf::from(".")
}

/// The config file path (`<config_dir>/mcp.toml`), overridable in full via
/// `$BOATRAMP_MCP_CONFIG` (e.g. for tests or a non-standard location).
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("BOATRAMP_MCP_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    config_dir().join("mcp.toml")
}

impl Config {
    /// Load the config (an absent file is an empty config, not an error).
    pub fn load() -> Result<Self> {
        let path = config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(&path)?;
        Ok(toml::from_str(&contents)?)
    }

    /// Persist the config, creating the parent directory as needed.
    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Find an instance by name.
    pub fn find(&self, name: &str) -> Option<&InstanceConfig> {
        self.instances.iter().find(|i| i.name == name)
    }

    /// Add an instance (rejecting a duplicate name) and save.
    pub fn add(&mut self, instance: InstanceConfig) -> Result<()> {
        if self.find(&instance.name).is_some() {
            return Err(Error::Config(format!(
                "instance '{}' already exists; remove it first",
                instance.name
            )));
        }
        self.instances.push(instance);
        self.save()
    }

    /// Remove an instance by name (erroring if unknown) and save.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let before = self.instances.len();
        self.instances.retain(|i| i.name != name);
        if self.instances.len() == before {
            return Err(Error::InstanceNotFound(name.to_string()));
        }
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_spec_resolves_env_path_and_literal() {
        // SAFETY: single-threaded test; sets one process env var it also reads.
        unsafe { std::env::set_var("BOATRAMP_MCP_TEST_SECRET", "s3cr3t") };
        assert_eq!(
            resolve_secret("env:BOATRAMP_MCP_TEST_SECRET").unwrap(),
            Some("s3cr3t".to_string())
        );
        assert_eq!(
            resolve_secret("literal-tok").unwrap(),
            Some("literal-tok".into())
        );
        assert_eq!(resolve_secret("   ").unwrap(), None);
        assert!(resolve_secret("env:BOATRAMP_MCP_DEFINITELY_UNSET").is_err());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let cfg = Config {
            instances: vec![
                InstanceConfig {
                    name: "prod".into(),
                    server: "https://boatramp.example.com".into(),
                    token: "env:BOATRAMP_TOKEN".into(),
                    holder_key: Some("path:/keys/holder.hex".into()),
                    server_pubkey: None,
                    insecure: false,
                },
                InstanceConfig {
                    name: "lab".into(),
                    server: "https://10.0.0.5:8080".into(),
                    token: String::new(),
                    holder_key: None,
                    server_pubkey: Some("302a30...".into()),
                    insecure: true,
                },
            ],
        };
        let toml = toml::to_string_pretty(&cfg).unwrap();
        let back: Config = toml::from_str(&toml).unwrap();
        assert_eq!(back.instances.len(), 2);
        assert_eq!(
            back.find("prod").unwrap().server,
            "https://boatramp.example.com"
        );
        assert!(back.find("lab").unwrap().insecure);
        assert!(back.find("lab").unwrap().token.is_empty());
    }
}
