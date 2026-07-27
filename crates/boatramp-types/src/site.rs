//! The [`SiteName`] newtype: a site (tenant) identifier, distinct from other
//! string ids — especially a [`crate::host::Host`] — so the transposable
//! `(site, host)` argument pairs that thread through the deploy store become a
//! compile error rather than a silent swap.
//!
//! `#[serde(transparent)]`, so it serializes and sorts exactly as its inner
//! string: KV keys, API paths, and stored values are byte-for-byte unchanged.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A site name. Deliberately *not* `Deref<str>` — callers reach the string via
/// [`as_str`](Self::as_str) / `AsRef<str>` / `Display`, so it can't silently
/// coerce back into the `&str` it exists to be distinguished from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SiteName(String);

impl SiteName {
    /// Wrap a site identifier.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SiteName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SiteName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for SiteName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SiteName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_transparently_as_its_string() {
        let site = SiteName::new("blog");
        assert_eq!(serde_json::to_string(&site).unwrap(), "\"blog\"");
        assert_eq!(serde_json::from_str::<SiteName>("\"blog\"").unwrap(), site);
    }

    #[test]
    fn display_and_as_str_are_the_raw_name() {
        let site = SiteName::from("my-site");
        assert_eq!(site.as_str(), "my-site");
        assert_eq!(format!("domain/{site}"), "domain/my-site");
    }
}
