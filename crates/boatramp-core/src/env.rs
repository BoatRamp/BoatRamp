//! An injectable source of environment-variable **values**.
//!
//! Production reads the real process environment via [`SystemEnv`]; tests inject a
//! deterministic [`MapEnv`] so they never mutate the global process environment —
//! which, besides racing across parallel tests, is `unsafe` in edition 2024
//! (`std::env::set_var`). The config-named env resolvers (the site-secret pool,
//! `jwks_env`, a database `url_env`, a webhook `secret_env`, …) read through this
//! rather than calling [`std::env::var`] directly: the *name* still comes from
//! config, but the *lookup* is injectable, so a test supplies values by
//! constructing a [`MapEnv`] instead of poking the process environment.

use std::collections::HashMap;
use std::sync::Arc;

/// A read-only source of environment-variable values, keyed by name.
///
/// The single method returns `None` for an unset name (mirroring the
/// `std::env::var(..).ok()` the call sites used to do inline).
pub trait EnvSource: Send + Sync {
    /// The value bound to `key`, or `None` if it is unset (or not valid UTF-8).
    fn get(&self, key: &str) -> Option<String>;
}

/// The real process environment ([`std::env::var`]) — the production source.
///
/// A zero-sized type, so a production call site passes `&SystemEnv` inline with no
/// plumbing when it does not already hold one.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl EnvSource for SystemEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// An in-memory environment for tests: inject deterministic values without
/// mutating (or racing on) the global process environment.
#[derive(Debug, Clone, Default)]
pub struct MapEnv(HashMap<String, String>);

impl MapEnv {
    /// An empty map — every lookup misses (as if the var were unset).
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Bind `key` to `value`, builder-style.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Bind `key` to `value` in place.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for MapEnv {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        )
    }
}

impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

// Ergonomic forwarding so `&dyn EnvSource`, `&SystemEnv`, and a stored
// `Arc<dyn EnvSource>` are all usable wherever an `impl EnvSource` / `&dyn
// EnvSource` is expected.
impl<T: EnvSource + ?Sized> EnvSource for &T {
    fn get(&self, key: &str) -> Option<String> {
        (**self).get(key)
    }
}

impl<T: EnvSource + ?Sized> EnvSource for Arc<T> {
    fn get(&self, key: &str) -> Option<String> {
        (**self).get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_env_hits_and_misses() {
        let env = MapEnv::new().with("A", "1").with("B", "2");
        assert_eq!(env.get("A"), Some("1".to_string()));
        assert_eq!(env.get("B"), Some("2".to_string()));
        assert_eq!(env.get("MISSING"), None);
    }

    #[test]
    fn map_env_from_iter_and_dyn() {
        let env: MapEnv = [("X", "x"), ("Y", "y")].into_iter().collect();
        let dynref: &dyn EnvSource = &env;
        assert_eq!(dynref.get("X"), Some("x".to_string()));
        assert_eq!(dynref.get("Z"), None);
    }

    #[test]
    fn arc_and_ref_forward() {
        let env: Arc<dyn EnvSource> = Arc::new(MapEnv::new().with("K", "v"));
        assert_eq!(env.get("K"), Some("v".to_string()));
        let r = &env;
        assert_eq!(r.get("K"), Some("v".to_string()));
    }
}
