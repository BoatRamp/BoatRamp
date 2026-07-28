//! Instance management behind `boatramp mcp setup add/list/remove` — thin wrappers
//! over [`Config`] that also render a human summary for the CLI to print.

use crate::config::{config_path, Config, InstanceConfig};
use crate::error::Result;

/// Register a new instance (secrets are stored as specs, never resolved here).
pub fn add(instance: InstanceConfig) -> Result<String> {
    let name = instance.name.clone();
    let server = instance.server.clone();
    let mut cfg = Config::load()?;
    cfg.add(instance)?;
    Ok(format!(
        "added instance '{name}' -> {server}\nconfig: {}",
        config_path().display()
    ))
}

/// Remove an instance by name.
pub fn remove(name: &str) -> Result<String> {
    let mut cfg = Config::load()?;
    cfg.remove(name)?;
    Ok(format!("removed instance '{name}'"))
}

/// A human-readable listing of the registered instances.
pub fn list() -> Result<String> {
    let cfg = Config::load()?;
    if cfg.instances.is_empty() {
        return Ok(format!(
            "no instances registered ({})\nadd one: boatramp mcp setup add <name> --server <url> --token env:BOATRAMP_TOKEN",
            config_path().display()
        ));
    }
    let mut out = format!("registered instances ({}):\n", config_path().display());
    for i in &cfg.instances {
        let auth = if i.token.is_empty() {
            "no token"
        } else {
            "token"
        };
        let pin = if i.server_pubkey.is_some() {
            ", rpk-pinned"
        } else {
            ""
        };
        let insecure = if i.insecure { ", insecure-tls" } else { "" };
        out.push_str(&format!(
            "  {} -> {} ({auth}{pin}{insecure})\n",
            i.name, i.server
        ));
    }
    Ok(out)
}
