//! Path-pattern matching for redirects, rewrites, headers, and cache rules.
//!
//! One shared matcher backs every routing rule. A pattern is matched, anchored,
//! against a full request path (which always begins with `/`). Semantics:
//!
//! - `:name` matches exactly one path segment (no `/`) and captures it.
//! - `*` matches any run of characters **except** `/` (within one segment).
//! - `**` matches any run of characters **including** `/` (the "splat"); at most
//!   one `**` per pattern.
//!
//! Everything else is matched literally. Examples:
//!
//! | Pattern        | Matches                         | Captures            |
//! | -------------- | ------------------------------- | ------------------- |
//! | `/old/:slug`   | `/old/hello`                    | `slug = hello`      |
//! | `/api/**`      | `/api/v1/users`                 | `splat = v1/users`  |
//! | `**.js`        | `/a/b/app.js`, `/app.js`        | `splat = /a/b/app`  |
//! | `/assets/*`    | `/assets/app.css` (not nested)  | —                   |
//!
//! Targets (redirect/rewrite destinations) expand `:name` and `:splat` from the
//! captures — e.g. `from: "/old/:slug"` + `to: "/new/:slug"`.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

use lru::LruCache;
use regex::Regex;

use crate::error::ConfigError;

/// A compiled path pattern. Cloning is cheap — the underlying [`Regex`] is
/// reference-counted — so compiled patterns are cached and handed out by clone.
#[derive(Debug, Clone)]
pub struct Pattern {
    regex: Regex,
    names: Vec<String>,
}

/// Bound on the process-wide compiled-pattern cache. Patterns come from deploy
/// configs (bounded in practice); the LRU just caps pathological churn.
const PATTERN_CACHE_CAP: usize = 2048;

fn pattern_cache() -> &'static Mutex<LruCache<String, Pattern>> {
    static CACHE: OnceLock<Mutex<LruCache<String, Pattern>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(PATTERN_CACHE_CAP).expect("cap > 0"),
        ))
    })
}

/// The result of matching a [`Pattern`] against a path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    /// `:name` captures.
    pub params: BTreeMap<String, String>,
    /// The `**` capture, if the pattern had one.
    pub splat: Option<String>,
}

impl Pattern {
    /// Compile a pattern string, memoizing the result. Valid patterns compile
    /// at most once per process (hot routing paths recompile nothing); invalid
    /// patterns return an error and are not cached. Errors on a bad `:`
    /// placeholder, a second `**`, or an internally malformed regex.
    pub fn compile(pattern: &str) -> Result<Self, ConfigError> {
        Self::compile_with(pattern, false)
    }

    /// Compile a pattern, optionally **case-insensitive**: the path
    /// is matched ignoring ASCII case (e.g. `/About` matches `/about`). The
    /// cache distinguishes the two modes.
    pub fn compile_with(pattern: &str, case_insensitive: bool) -> Result<Self, ConfigError> {
        // A `\u{1}` prefix keys the case-insensitive variant separately (it can't
        // appear in a real path pattern).
        let cache_key = if case_insensitive {
            format!("\u{1}{pattern}")
        } else {
            pattern.to_string()
        };
        if let Some(cached) = pattern_cache().lock().unwrap().get(&cache_key) {
            return Ok(cached.clone());
        }
        let compiled = Self::compile_uncached(pattern, case_insensitive)?;
        pattern_cache()
            .lock()
            .unwrap()
            .put(cache_key, compiled.clone());
        Ok(compiled)
    }

    /// Compile a pattern string without consulting the cache.
    fn compile_uncached(pattern: &str, case_insensitive: bool) -> Result<Self, ConfigError> {
        let mut regex = if case_insensitive {
            String::from("(?i)^")
        } else {
            String::from("^")
        };
        let mut names = Vec::new();
        let mut has_splat = false;

        let bytes = pattern.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'*' => {
                    if bytes.get(i + 1) == Some(&b'*') {
                        if has_splat {
                            return Err(ConfigError::pattern(pattern, "at most one `**` allowed"));
                        }
                        has_splat = true;
                        regex.push_str("(?P<splat>.*)");
                        i += 2;
                    } else {
                        regex.push_str("[^/]*");
                        i += 1;
                    }
                }
                b':' => {
                    let start = i + 1;
                    let mut j = start;
                    while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
                    {
                        j += 1;
                    }
                    if j == start {
                        return Err(ConfigError::pattern(
                            pattern,
                            "`:` must be followed by a name",
                        ));
                    }
                    let name = &pattern[start..j];
                    if name == "splat" {
                        return Err(ConfigError::pattern(
                            pattern,
                            "`:splat` is reserved; use `**`",
                        ));
                    }
                    regex.push_str(&format!("(?P<{name}>[^/]+)"));
                    names.push(name.to_string());
                    i = j;
                }
                _ => {
                    // Advance one whole UTF-8 char and escape it literally.
                    let ch = pattern[i..].chars().next().expect("char boundary");
                    regex.push_str(&regex::escape(ch.encode_utf8(&mut [0u8; 4])));
                    i += ch.len_utf8();
                }
            }
        }
        regex.push('$');

        let regex =
            Regex::new(&regex).map_err(|err| ConfigError::pattern(pattern, err.to_string()))?;
        Ok(Self { regex, names })
    }

    /// Whether `path` matches.
    pub fn is_match(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }

    /// Match `path`, returning the captures, or `None` if it does not match.
    pub fn match_path(&self, path: &str) -> Option<Match> {
        let caps = self.regex.captures(path)?;
        let mut params = BTreeMap::new();
        for name in &self.names {
            if let Some(value) = caps.name(name) {
                params.insert(name.clone(), value.as_str().to_string());
            }
        }
        let splat = caps.name("splat").map(|m| m.as_str().to_string());
        Some(Match { params, splat })
    }
}

impl Match {
    /// Expand a target string, substituting `:name` and `:splat` from captures.
    /// Unknown `:placeholders` are left verbatim.
    pub fn expand(&self, target: &str) -> String {
        let mut out = String::with_capacity(target.len());
        let bytes = target.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b':' {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                let name = &target[start..j];
                if name == "splat" {
                    out.push_str(self.splat.as_deref().unwrap_or(""));
                } else if let Some(value) = self.params.get(name) {
                    out.push_str(value);
                } else {
                    out.push(':');
                    out.push_str(name);
                }
                i = j;
            } else {
                let ch = target[i..].chars().next().expect("char boundary");
                out.push(ch);
                i += ch.len_utf8();
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_is_cached() {
        // Use a distinctive pattern so the assertion is about this entry.
        let pat = "/cache-probe/:id/**";
        let a = Pattern::compile(pat).unwrap();
        let b = Pattern::compile(pat).unwrap();
        // The cached clone shares the same underlying compiled regex (Arc),
        // so the second compile did no work.
        assert!(
            std::ptr::eq(a.regex.as_str().as_ptr(), b.regex.as_str().as_ptr()),
            "second compile should return the cached pattern"
        );
        // Still behaves correctly.
        let m = b.match_path("/cache-probe/42/x/y").unwrap();
        assert_eq!(m.params.get("id").map(String::as_str), Some("42"));
        assert_eq!(m.splat.as_deref(), Some("x/y"));
    }

    #[test]
    fn placeholder_capture_and_expand() {
        let p = Pattern::compile("/old/:slug").unwrap();
        let m = p.match_path("/old/hello").unwrap();
        assert_eq!(m.params.get("slug").map(String::as_str), Some("hello"));
        assert_eq!(m.expand("/new/:slug"), "/new/hello");
        assert!(p.match_path("/old/a/b").is_none()); // single segment only
    }

    #[test]
    fn splat_capture_and_expand() {
        let p = Pattern::compile("/api/**").unwrap();
        let m = p.match_path("/api/v1/users").unwrap();
        assert_eq!(m.splat.as_deref(), Some("v1/users"));
        assert_eq!(
            m.expand("https://backend/:splat"),
            "https://backend/v1/users"
        );
    }

    #[test]
    fn star_is_within_segment() {
        let p = Pattern::compile("/assets/*").unwrap();
        assert!(p.is_match("/assets/app.css"));
        assert!(!p.is_match("/assets/sub/app.css"));
    }

    #[test]
    fn double_star_matches_extension_anywhere() {
        let p = Pattern::compile("**.js").unwrap();
        assert!(p.is_match("/app.js"));
        assert!(p.is_match("/a/b/c.js"));
        assert!(!p.is_match("/app.css"));
    }

    #[test]
    fn rejects_bad_patterns() {
        assert!(Pattern::compile("/a/**/b/**").is_err()); // two splats
        assert!(Pattern::compile("/x/:").is_err()); // empty name
    }

    #[test]
    fn literal_dots_are_escaped() {
        let p = Pattern::compile("/file.txt").unwrap();
        assert!(p.is_match("/file.txt"));
        assert!(!p.is_match("/fileXtxt"));
    }
}
