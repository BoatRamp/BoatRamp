//! The [`Backend`] the MCP tools resolve a [`ControlPlane`] from, and its two
//! shapes:
//!  - [`InstanceRegistry`] — many named HTTP instances (the stdio transport, from
//!    `mcp.toml`); a tool's `instance` param picks one.
//!  - [`SingleBackend`] — exactly one control plane, `instance` ignored (the
//!    in-`serve` HTTP `/mcp` endpoint, whose one plane is the local node).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::client::{ControlPlane, HttpControlPlane};
use crate::config::Config;
use crate::error::{Error, Result};

/// Resolves which [`ControlPlane`] a tool call targets, and lists what's available.
pub trait Backend: Send + Sync {
    /// Resolve the target control plane for an optional `instance` selector.
    fn resolve(&self, instance: Option<&str>) -> Result<&dyn ControlPlane>;
    /// `(name, base_url)` for every reachable control plane.
    fn list(&self) -> Vec<(&str, &str)>;
    /// Whether no control plane is registered.
    fn is_empty(&self) -> bool {
        self.list().is_empty()
    }
}

/// The set of connected boatramp instances, keyed by name (stdio, multi-instance).
pub struct InstanceRegistry {
    clients: BTreeMap<String, HttpControlPlane>,
}

impl InstanceRegistry {
    /// Build a registry, connecting every instance in `config`. An instance whose
    /// secrets can't be resolved is an error (fail loud, not a silent skip) so a
    /// misconfiguration surfaces at startup rather than mid-conversation.
    pub fn from_config(config: &Config) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for inst in &config.instances {
            clients.insert(inst.name.clone(), HttpControlPlane::from_instance(inst)?);
        }
        Ok(Self { clients })
    }
}

impl Backend for InstanceRegistry {
    fn resolve(&self, instance: Option<&str>) -> Result<&dyn ControlPlane> {
        if self.clients.is_empty() {
            return Err(Error::NoInstances);
        }
        match instance {
            Some(name) => self
                .clients
                .get(name)
                .map(|c| c as &dyn ControlPlane)
                .ok_or_else(|| Error::InstanceNotFound(name.to_string())),
            None => {
                if self.clients.len() == 1 {
                    Ok(self.clients.values().next().expect("len == 1") as &dyn ControlPlane)
                } else {
                    Err(Error::InstanceRequired {
                        available: self.clients.keys().cloned().collect::<Vec<_>>().join(", "),
                    })
                }
            }
        }
    }

    fn list(&self) -> Vec<(&str, &str)> {
        self.clients
            .iter()
            .map(|(name, cp)| (name.as_str(), cp.base_url()))
            .collect()
    }
}

/// A backend of exactly one control plane; the `instance` selector is ignored (it
/// exists only for tool-signature uniformity with the multi-instance case). Used
/// by the in-`serve` HTTP endpoint, whose single plane is the local node.
pub struct SingleBackend {
    cp: Arc<dyn ControlPlane>,
}

impl SingleBackend {
    /// Wrap a single control plane.
    pub fn new(cp: Arc<dyn ControlPlane>) -> Self {
        Self { cp }
    }
}

impl Backend for SingleBackend {
    fn resolve(&self, _instance: Option<&str>) -> Result<&dyn ControlPlane> {
        Ok(&*self.cp)
    }

    fn list(&self) -> Vec<(&str, &str)> {
        vec![(self.cp.name(), self.cp.base_url())]
    }
}
