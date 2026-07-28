//! Maps instance names to their [`ControlPlane`] connections and resolves which
//! one a tool call targets.

use std::collections::BTreeMap;

use crate::client::ControlPlane;
use crate::config::Config;
use crate::error::{Error, Result};

/// The set of connected boatramp instances, keyed by name.
pub struct InstanceRegistry {
    clients: BTreeMap<String, ControlPlane>,
}

impl InstanceRegistry {
    /// Build a registry, connecting every instance in `config`. An instance whose
    /// secrets can't be resolved is an error (fail loud, not a silent skip) so a
    /// misconfiguration surfaces at startup rather than mid-conversation.
    pub fn from_config(config: &Config) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for inst in &config.instances {
            let cp = ControlPlane::from_instance(inst)?;
            clients.insert(inst.name.clone(), cp);
        }
        Ok(Self { clients })
    }

    /// The number of registered instances.
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Whether no instances are registered.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// `(name, base_url)` for every registered instance.
    pub fn list(&self) -> Vec<(&str, &str)> {
        self.clients
            .iter()
            .map(|(name, cp)| (name.as_str(), cp.base_url()))
            .collect()
    }

    /// Resolve which control plane a call targets:
    ///  - `Some(name)` → that instance, or [`Error::InstanceNotFound`].
    ///  - `None` with exactly one registered → that one.
    ///  - `None` with several → [`Error::InstanceRequired`] listing the names.
    ///  - none registered → [`Error::NoInstances`].
    pub fn resolve(&self, instance: Option<&str>) -> Result<&ControlPlane> {
        if self.clients.is_empty() {
            return Err(Error::NoInstances);
        }
        match instance {
            Some(name) => self
                .clients
                .get(name)
                .ok_or_else(|| Error::InstanceNotFound(name.to_string())),
            None => {
                if self.clients.len() == 1 {
                    Ok(self.clients.values().next().expect("len == 1"))
                } else {
                    Err(Error::InstanceRequired {
                        available: self.clients.keys().cloned().collect::<Vec<_>>().join(", "),
                    })
                }
            }
        }
    }
}
