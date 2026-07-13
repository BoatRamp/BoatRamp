//! Request routing: turn a request path + [`DeployConfig`] + the manifest's file
//! set into an [`Outcome`]. Pure and synchronous so it is easy to unit-test; the
//! server turns the outcome into an HTTP response (conditional/range/headers).
//!
//! Order (Vercel-style, files win over rewrites):
//! 1. trailing-slash normalization → redirect
//! 2. explicit redirects (first match)
//! 3. resolve the request path to a file (clean-URLs + directory index)
//! 4. rewrites as a fallback for unmatched paths (proxy if absolute, else
//!    serve the rewritten internal path — this is how SPA fallback works)
//! 5. not found (with optional custom error document)

use std::collections::BTreeMap;

use crate::config::{DeployConfig, TrailingSlash};
use crate::file::FileEntry;
use crate::matcher::Pattern;
use crate::predicate::{EvalEnv, RequestContext};

/// What to do with a request, before HTTP concerns (conditional/range/headers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Redirect to `location` with `status`.
    Redirect {
        /// `Location` header value.
        location: String,
        /// 3xx status.
        status: u16,
    },
    /// Serve a resolved file (status 200).
    File {
        /// Resolved manifest key (for MIME overrides by extension).
        path: String,
        /// The manifest entry to stream.
        entry: FileEntry,
    },
    /// Reverse-proxy to an absolute URL.
    Proxy {
        /// Upstream URL.
        url: String,
    },
    /// Not found; `error` is the resolved custom error document, if configured.
    NotFound {
        /// Custom 404 document (resolved key + entry) to serve with status 404.
        error: Option<(String, FileEntry)>,
    },
}

/// An [`Outcome`] plus the response `Vary` header names any conditional rule the
/// resolver evaluated depends on (so a per-language / per-cookie redirect is not
/// cached across visitors). `vary` is empty for a purely path-based resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveResult {
    /// What to do with the request.
    pub outcome: Outcome,
    /// Deduplicated `Vary` header names (lower-cased) — see the type doc.
    pub vary: Vec<String>,
}

/// Resolve a request path to an [`Outcome`], ignoring conditional (`when`) rules
/// that need request context — a convenience for path-only callers/tests. Prefer
/// [`resolve_ctx`] on the request path so `when` predicates evaluate.
pub fn resolve(
    config: &DeployConfig,
    files: &BTreeMap<String, FileEntry>,
    request_path: &str,
) -> Outcome {
    resolve_ctx(config, files, request_path, &RequestContext::default()).outcome
}

/// Resolve a request to an [`Outcome`], evaluating each redirect/rewrite's
/// optional `when` predicate against `ctx`. A rule applies only when its path
/// pattern matches **and** its condition (if any) is true; the returned `vary`
/// carries the request dimensions those conditions read.
pub fn resolve_ctx(
    config: &DeployConfig,
    files: &BTreeMap<String, FileEntry>,
    request_path: &str,
    ctx: &RequestContext,
) -> ResolveResult {
    let path = if request_path.starts_with('/') {
        request_path.to_string()
    } else {
        format!("/{request_path}")
    };
    // Collapse `.`/`..`/`//` segments before any routing/lookup so a request
    // can't reach a manifest key via a non-canonical path, and `..` can never
    // climb above the deploy root (path hardening / audit).
    let path = normalize_dot_segments(&path);

    let mut vary: Vec<String> = Vec::new();
    // `file_exists(p)` mirrors real serving (clean-URLs + directory index), so a
    // predicate asks "would this path serve a file in *this* deploy?".
    let file_exists = |p: &str| resolve_file(config, files, p).is_some();

    let finish = |outcome: Outcome, mut vary: Vec<String>| {
        vary.sort();
        vary.dedup();
        ResolveResult { outcome, vary }
    };

    if let Some(location) = normalize_trailing_slash(config, &path) {
        return finish(
            Outcome::Redirect {
                location,
                status: 308,
            },
            vary,
        );
    }

    for redirect in &config.redirects {
        let Some(m) = Pattern::compile_with(&redirect.from, config.case_insensitive)
            .ok()
            .and_then(|p| p.match_path(&path))
        else {
            continue;
        };
        if !eval_when(&redirect.when, ctx, &path, &file_exists, &mut vary) {
            continue; // path matched but the condition is false — keep looking
        }
        return finish(
            Outcome::Redirect {
                location: m.expand(&redirect.to),
                status: redirect.status,
            },
            vary,
        );
    }

    if let Some((path, entry)) = resolve_file(config, files, &path) {
        return finish(Outcome::File { path, entry }, vary);
    }

    for rewrite in &config.rewrites {
        let Some(m) = Pattern::compile_with(&rewrite.from, config.case_insensitive)
            .ok()
            .and_then(|p| p.match_path(&path))
        else {
            continue;
        };
        if !eval_when(&rewrite.when, ctx, &path, &file_exists, &mut vary) {
            continue;
        }
        let target = m.expand(&rewrite.to);
        if is_absolute_url(&target) {
            return finish(Outcome::Proxy { url: target }, vary);
        }
        if let Some((path, entry)) = resolve_file(config, files, &target) {
            return finish(Outcome::File { path, entry }, vary);
        }
    }

    let error = config.error_documents.get(&404).and_then(|doc| {
        let key = doc.trim_start_matches('/').to_string();
        files.get(&key).map(|entry| (key, entry.clone()))
    });
    finish(Outcome::NotFound { error }, vary)
}

/// Evaluate a rule's optional `when` predicate against the request. Returns
/// whether the rule fires (a rule with no `when` always does), accumulating the
/// predicate's `Vary` dimensions into `vary` when the path already matched — the
/// outcome depended on them regardless of the result. A predicate that fails to
/// compile (impossible after `validate` accepted the deploy) fails closed: the
/// rule is skipped.
fn eval_when(
    when: &Option<String>,
    ctx: &RequestContext,
    path: &str,
    file_exists: &dyn Fn(&str) -> bool,
    vary: &mut Vec<String>,
) -> bool {
    let Some(src) = when else { return true };
    match crate::predicate::compile_cached(src) {
        Ok(pred) => {
            vary.extend(pred.vary_headers().iter().cloned());
            pred.eval(&EvalEnv {
                ctx,
                path,
                file_exists,
            })
        }
        Err(_) => false,
    }
}

/// Find the WebAssembly handler whose route and methods match this request, if
/// any (declaration order wins). Handlers sit **after redirects but before
/// rewrites/static** in the pipeline: the server consults
/// this only when [`resolve`] did not produce a redirect, and dispatches the
/// match in preference to any file/rewrite outcome.
///
/// An empty `methods` list matches every method; otherwise the request
/// `method` must appear in it (case-insensitive).
pub fn match_handler<'a>(
    handlers: &'a [crate::config::HandlerConfig],
    method: &str,
    request_path: &str,
) -> Option<&'a crate::config::HandlerConfig> {
    let path = if request_path.starts_with('/') {
        std::borrow::Cow::Borrowed(request_path)
    } else {
        std::borrow::Cow::Owned(format!("/{request_path}"))
    };
    handlers.iter().find(|handler| {
        let method_ok = handler.methods.is_empty()
            || handler
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method));
        method_ok
            && Pattern::compile(&handler.route)
                .map(|pattern| pattern.is_match(&path))
                .unwrap_or(false)
    })
}

/// Resolve a path to a file, applying clean-URLs and the directory index.
fn resolve_file(
    config: &DeployConfig,
    files: &BTreeMap<String, FileEntry>,
    path: &str,
) -> Option<(String, FileEntry)> {
    let key = path.trim_start_matches('/');
    let ci = config.case_insensitive;

    if let Some(hit) = lookup(files, key, ci) {
        return Some(hit);
    }

    if config.clean_urls && !key.is_empty() && !last_segment(key).contains('.') {
        let html = format!("{key}.html");
        if let Some(hit) = lookup(files, &html, ci) {
            return Some(hit);
        }
    }

    let base = key.trim_end_matches('/');
    for index in &config.index {
        let candidate = if base.is_empty() {
            index.clone()
        } else {
            format!("{base}/{index}")
        };
        if let Some(hit) = lookup(files, &candidate, ci) {
            return Some(hit);
        }
    }

    None
}

/// Look up a manifest key — exact, or (when `case_insensitive`) the first key
/// that matches ignoring ASCII case. The stored key's original case is returned
/// (the served path preserves the deploy's casing).
fn lookup(
    files: &BTreeMap<String, FileEntry>,
    key: &str,
    case_insensitive: bool,
) -> Option<(String, FileEntry)> {
    if let Some(entry) = files.get(key) {
        return Some((key.to_string(), entry.clone()));
    }
    if case_insensitive {
        if let Some((k, entry)) = files.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            return Some((k.clone(), entry.clone()));
        }
    }
    None
}

/// Compute a redirect target enforcing the trailing-slash policy, or `None`.
fn normalize_trailing_slash(config: &DeployConfig, path: &str) -> Option<String> {
    match config.trailing_slash {
        TrailingSlash::Preserve => None,
        TrailingSlash::Always => {
            if path != "/" && !path.ends_with('/') && !last_segment(path).contains('.') {
                Some(format!("{path}/"))
            } else {
                None
            }
        }
        TrailingSlash::Never => {
            if path != "/" && path.ends_with('/') {
                Some(path.trim_end_matches('/').to_string())
            } else {
                None
            }
        }
    }
}

/// Collapse `.` and `..` segments (and empty segments from `//`) in an
/// absolute path, RFC 3986-style. `..` never climbs above the root, so the
/// result is always a clean absolute path rooted at `/` — it cannot reference
/// anything outside the deploy. A trailing `/` (or trailing `.`/`..`) is
/// preserved as a trailing slash so the directory-index / trailing-slash policy
/// still applies.
fn normalize_dot_segments(path: &str) -> String {
    let trailing = path.ends_with('/')
        || path.ends_with("/.")
        || path.ends_with("/..")
        || path == "."
        || path == "..";
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {} // skip empty (`//`) and current-dir segments
            ".." => {
                out.pop(); // climb one level; popping past root is a no-op
            }
            other => out.push(other),
        }
    }
    let mut normalized = format!("/{}", out.join("/"));
    if trailing && !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

fn last_segment(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("")
}

fn is_absolute_url(target: &str) -> bool {
    target.starts_with("http://") || target.starts_with("https://")
}

/// A smart default `Cache-Control` for a served file, applied only
/// when the deploy config sets no blanket `cache.default` — explicit config and
/// header rules always win. Two heuristics:
///
/// * **fingerprinted assets** — a content-hashed filename (`app.4f3a2b2c.js`,
///   `index-a1b2c3d4.css`) never changes under that name, so it is safe to cache
///   forever: `public, max-age=31536000, immutable`.
/// * **HTML** — the entry documents that reference those assets must be
///   re-fetched to pick up a new deploy: `public, max-age=0, must-revalidate`.
///
/// Anything else returns `None` (no default imposed).
pub fn cache_control_default(
    served_path: &str,
    content_type: Option<&str>,
) -> Option<&'static str> {
    if is_fingerprinted(served_path) {
        Some("public, max-age=31536000, immutable")
    } else if is_html(served_path, content_type) {
        Some("public, max-age=0, must-revalidate")
    } else {
        None
    }
}

/// Whether a served filename carries a content-hash fingerprint, e.g.
/// `app.4f3a2b2c.js` or `index-a1b2c3d4.css`. Conservative: the token before the
/// extension must be ≥ 8 chars of `[0-9a-zA-Z_-]` and contain **both** a letter
/// and a digit — so plain words (`application.js`) and bare dates
/// (`report-20240115.pdf`) aren't mistaken for hashes and cached for a year.
fn is_fingerprinted(path: &str) -> bool {
    let name = last_segment(path);
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    if stem.is_empty() || ext.is_empty() {
        return false;
    }
    // The fingerprint is the last `.`/`-`-delimited token of the stem.
    let token = stem.rsplit(['.', '-']).next().unwrap_or("");
    token.len() >= 8
        && token.bytes().any(|b| b.is_ascii_alphabetic())
        && token.bytes().any(|b| b.is_ascii_digit())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Whether the response is HTML, by content type (preferred) or `.htm(l)` name.
fn is_html(path: &str, content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        if ct.split(';').next().map(str::trim) == Some("text/html") {
            return true;
        }
    }
    let name = last_segment(path);
    name.ends_with(".html") || name.ends_with(".htm")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_segments_are_collapsed_and_cannot_escape_root() {
        assert_eq!(normalize_dot_segments("/a/./b"), "/a/b");
        assert_eq!(normalize_dot_segments("/a//b"), "/a/b");
        assert_eq!(normalize_dot_segments("/a/../b"), "/b");
        // `..` past the root is a no-op — no escaping the deploy.
        assert_eq!(normalize_dot_segments("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_dot_segments("/a/../../b"), "/b");
        // Trailing-slash intent is preserved (for the directory-index policy).
        assert_eq!(normalize_dot_segments("/a/b/"), "/a/b/");
        assert_eq!(normalize_dot_segments("/a/.."), "/");
        assert_eq!(normalize_dot_segments("/"), "/");
    }

    #[test]
    fn resolve_serves_through_dot_segments() {
        let cfg = DeployConfig::default();
        let f = files(&["dir/page.html"]);
        // `/dir/sub/../page.html` collapses to `/dir/page.html` and serves it.
        match resolve(&cfg, &f, "/dir/sub/../page.html") {
            Outcome::File { path, .. } => assert_eq!(path, "dir/page.html"),
            other => panic!("expected file, got {other:?}"),
        }
    }

    #[test]
    fn cache_default_immutable_for_fingerprinted_assets() {
        let immutable = Some("public, max-age=31536000, immutable");
        // Common bundler fingerprint shapes.
        assert_eq!(
            cache_control_default("assets/app.4f3a2b2c.js", None),
            immutable
        );
        assert_eq!(cache_control_default("index-a1b2c3d4.css", None), immutable);
        assert_eq!(
            cache_control_default("main.abcdef12.woff2", None),
            immutable
        );
        assert_eq!(
            cache_control_default("vendor.3f8a9c2e1b7d.js", None),
            immutable
        );
    }

    #[test]
    fn cache_default_skips_non_fingerprinted() {
        // No digit (a word), too short, and a bare date — none are hashes.
        assert_eq!(cache_control_default("application.js", None), None);
        assert_eq!(cache_control_default("app.js", None), None);
        assert_eq!(cache_control_default("report-20240115.pdf", None), None);
        assert_eq!(cache_control_default("style.min.css", None), None);
    }

    #[test]
    fn cache_default_revalidate_for_html() {
        let revalidate = Some("public, max-age=0, must-revalidate");
        assert_eq!(cache_control_default("index.html", None), revalidate);
        assert_eq!(cache_control_default("about.htm", None), revalidate);
        // By content type even when the path has no extension (clean URL).
        assert_eq!(
            cache_control_default("/blog/post", Some("text/html; charset=utf-8")),
            revalidate
        );
    }

    fn entry() -> FileEntry {
        FileEntry {
            hash: "h".into(),
            size: 1,
            content_type: None,
            variants: Default::default(),
        }
    }

    fn files(paths: &[&str]) -> BTreeMap<String, FileEntry> {
        paths.iter().map(|p| (p.to_string(), entry())).collect()
    }

    #[test]
    fn serves_exact_and_index() {
        let files = files(&["index.html", "blog/index.html", "app.js"]);
        let cfg = DeployConfig::default();
        assert!(matches!(
            resolve(&cfg, &files, "/index.html"),
            Outcome::File { .. }
        ));
        assert!(
            matches!(resolve(&cfg, &files, "/"), Outcome::File { path, .. } if path == "index.html")
        );
        assert!(
            matches!(resolve(&cfg, &files, "/blog"), Outcome::File { path, .. } if path == "blog/index.html")
        );
        assert!(matches!(
            resolve(&cfg, &files, "/app.js"),
            Outcome::File { .. }
        ));
    }

    #[test]
    fn clean_urls() {
        let files = files(&["about.html"]);
        let off = DeployConfig::default();
        assert!(matches!(
            resolve(&off, &files, "/about"),
            Outcome::NotFound { .. }
        ));
        let on = DeployConfig {
            clean_urls: true,
            ..Default::default()
        };
        assert!(
            matches!(resolve(&on, &files, "/about"), Outcome::File { path, .. } if path == "about.html")
        );
    }

    #[test]
    fn redirect_with_placeholder() {
        let mut cfg = DeployConfig::default();
        cfg.redirects.push(crate::config::Redirect {
            from: "/old/:slug".into(),
            to: "/new/:slug".into(),
            status: 301,
            when: None,
        });
        assert_eq!(
            resolve(&cfg, &BTreeMap::new(), "/old/hi"),
            Outcome::Redirect {
                location: "/new/hi".into(),
                status: 301
            }
        );
    }

    #[test]
    fn conditional_redirect_honors_when_and_reports_vary() {
        let mut cfg = DeployConfig::default();
        // Send the root to the French tree only when the visitor prefers French.
        cfg.redirects.push(crate::config::Redirect {
            from: "/".into(),
            to: "/fr/".into(),
            status: 302,
            when: Some("prefers_language(['fr','en']) == 'fr'".into()),
        });
        let files = files(&["index.html"]);

        // French visitor → redirected; the outcome varies on Accept-Language.
        let fr = RequestContext {
            accept_languages: vec!["fr".into()],
            ..Default::default()
        };
        let r = resolve_ctx(&cfg, &files, "/", &fr);
        assert_eq!(
            r.outcome,
            Outcome::Redirect {
                location: "/fr/".into(),
                status: 302
            }
        );
        assert_eq!(r.vary, vec!["accept-language".to_string()]);

        // English visitor → NOT redirected (falls through to index.html), but the
        // response still varies on Accept-Language (a French visitor differs).
        let en = RequestContext {
            accept_languages: vec!["en".into()],
            ..Default::default()
        };
        let r = resolve_ctx(&cfg, &files, "/", &en);
        assert!(matches!(r.outcome, Outcome::File { path, .. } if path == "index.html"));
        assert_eq!(r.vary, vec!["accept-language".to_string()]);
    }

    #[test]
    fn conditional_redirect_on_missing_file() {
        let mut cfg = DeployConfig::default();
        // No French translation of this path → send to the English one.
        cfg.redirects.push(crate::config::Redirect {
            from: "/fr/only.html".into(),
            to: "/en/only.html".into(),
            status: 302,
            when: Some("!file_exists(path)".into()),
        });
        let ctx = RequestContext::default();

        // Missing localized file → the redirect fires.
        let missing = files(&["en/only.html"]);
        assert_eq!(
            resolve_ctx(&cfg, &missing, "/fr/only.html", &ctx).outcome,
            Outcome::Redirect {
                location: "/en/only.html".into(),
                status: 302
            }
        );
        // Present localized file → served, no redirect. A file check varies on
        // nothing (it reads only the URL + deploy content).
        let present = files(&["fr/only.html", "en/only.html"]);
        let r = resolve_ctx(&cfg, &present, "/fr/only.html", &ctx);
        assert!(matches!(r.outcome, Outcome::File { path, .. } if path == "fr/only.html"));
        assert!(r.vary.is_empty());
    }

    #[test]
    fn spa_fallback_via_rewrite() {
        let files = files(&["index.html", "assets/app.js"]);
        let mut cfg = DeployConfig::default();
        cfg.rewrites.push(crate::config::Rewrite {
            from: "/**".into(),
            to: "/index.html".into(),
            status: 200,
            when: None,
        });
        // Real file still wins.
        assert!(
            matches!(resolve(&cfg, &files, "/assets/app.js"), Outcome::File { path, .. } if path == "assets/app.js")
        );
        // Unknown route falls back to index.html.
        assert!(
            matches!(resolve(&cfg, &files, "/deep/route"), Outcome::File { path, .. } if path == "index.html")
        );
    }

    #[test]
    fn case_insensitive_serves_static_redirects_and_misses_when_off() {
        let files = files(&["assets/App.js", "About.html"]);
        // Off (default): exact case only.
        let off = DeployConfig::default();
        assert!(matches!(
            resolve(&off, &files, "/assets/app.js"),
            Outcome::NotFound { .. }
        ));
        // On: case-folded static lookup serves the stored (original-case) key.
        let mut on = DeployConfig {
            case_insensitive: true,
            ..Default::default()
        };
        assert!(
            matches!(resolve(&on, &files, "/assets/app.js"), Outcome::File { path, .. } if path == "assets/App.js")
        );
        // …and redirect rules match case-insensitively.
        on.redirects.push(crate::config::Redirect {
            from: "/Old/:slug".into(),
            to: "/new/:slug".into(),
            status: 301,
            when: None,
        });
        assert_eq!(
            resolve(&on, &files, "/old/hi"),
            Outcome::Redirect {
                location: "/new/hi".into(),
                status: 301
            }
        );
    }

    #[test]
    fn proxy_rewrite() {
        let mut cfg = DeployConfig::default();
        cfg.rewrites.push(crate::config::Rewrite {
            from: "/api/**".into(),
            to: "https://backend/:splat".into(),
            status: 200,
            when: None,
        });
        assert_eq!(
            resolve(&cfg, &BTreeMap::new(), "/api/users/1"),
            Outcome::Proxy {
                url: "https://backend/users/1".into()
            }
        );
    }

    #[test]
    fn custom_404() {
        let files = files(&["404.html"]);
        let mut cfg = DeployConfig::default();
        cfg.error_documents.insert(404, "/404.html".into());
        assert!(matches!(
            resolve(&cfg, &files, "/missing"),
            Outcome::NotFound { error: Some(_) }
        ));
    }

    #[test]
    fn trailing_slash_never_redirects() {
        let cfg = DeployConfig {
            trailing_slash: TrailingSlash::Never,
            ..Default::default()
        };
        assert_eq!(
            resolve(&cfg, &BTreeMap::new(), "/blog/"),
            Outcome::Redirect {
                location: "/blog".into(),
                status: 308
            }
        );
    }

    #[test]
    fn handler_matching_respects_route_and_methods() {
        use crate::config::HandlerConfig;
        let handler = |route: &str, methods: &[&str]| HandlerConfig {
            route: route.into(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            component: "h.wasm".into(),
            imports: Vec::new(),
            limits: None,
            env: BTreeMap::new(),
        };
        let handlers = vec![
            handler("/api/orders/*", &["GET", "POST"]),
            handler("/hooks/*", &[]),
        ];

        // Route + method match.
        assert_eq!(
            match_handler(&handlers, "post", "/api/orders/42").map(|h| h.route.as_str()),
            Some("/api/orders/*")
        );
        // Method not in the list -> no match.
        assert!(match_handler(&handlers, "DELETE", "/api/orders/42").is_none());
        // Empty methods matches any method.
        assert!(match_handler(&handlers, "PUT", "/hooks/x").is_some());
        // No route matches.
        assert!(match_handler(&handlers, "GET", "/static/page").is_none());
    }
}
