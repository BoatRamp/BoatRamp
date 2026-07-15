//! The embedded web management console (feature `console`).
//!
//! The `boatramp-console` Wasm SPA (its built `dist/`) is baked into the binary
//! with [`include_dir`] and served — when the operator enables it via
//! `[serve.console]` — at a configurable host + path ([`ConsoleMount`]).
//!
//! The mount path is a runtime value, so a static axum route can't express it;
//! instead a thin middleware ([`mount`]) intercepts requests whose host matches
//! and whose path is under the mount, before the site fallback.
//!
//! **Router-ready.** The SPA is served history-fallback style: a request for a
//! hashed asset returns that file; any other sub-path under the mount returns
//! `index.html`. `index.html` is rewritten so the console works under an
//! arbitrary base path — absolute `/asset` URLs are prefixed with the mount
//! path, and a `<base href>` + `<meta name="boatramp-console-base">` carry the
//! runtime base so the client-side router can adopt it as its `basename`. The
//! `/api` it drives stays root-absolute (same origin), unaffected by the mount.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};

/// The console's built assets, embedded at compile time.
static CONSOLE_DIST: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../boatramp-console/dist");

/// Where the console is mounted, resolved from `[serve.console]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleMount {
    /// Host pattern: `*` (any host), an exact host, or `*.suffix`.
    pub host: String,
    /// Normalized path prefix (leading `/`, no trailing `/`), e.g. `/_console`.
    /// Empty ⇒ mounted at the root.
    pub path: String,
}

impl ConsoleMount {
    /// Resolve from the operator's raw host/path, applying the defaults
    /// (`host = *`, `path = /_console`) and normalization.
    pub fn resolve(host: Option<String>, path: Option<String>) -> Self {
        let host = host
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "*".to_string());
        Self {
            host,
            path: normalize_path(path.as_deref()),
        }
    }
}

/// Normalize a mount path: default `/_console`, collapse to a single leading
/// slash with no trailing slash. A bare `/` (root mount) normalizes to empty.
fn normalize_path(path: Option<&str>) -> String {
    let raw = path
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("/_console");
    let core = raw.trim_matches('/');
    if core.is_empty() {
        String::new()
    } else {
        format!("/{core}")
    }
}

/// Does `host` (already port-stripped, any case) match the console's `pattern`?
/// `*` matches anything; `*.suffix` matches the apex `suffix` and any
/// `label.suffix`; otherwise an exact (case-insensitive) match.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        pattern == host
    }
}

/// Is `req_path` within the mount `path`? True for the mount itself and any
/// sub-path (so `/_console` and `/_console/foo` match, but `/_consolex` does
/// not). An empty mount path (root mount) matches everything.
pub fn path_under(mount: &str, req_path: &str) -> bool {
    if mount.is_empty() {
        return true;
    }
    req_path == mount
        || req_path
            .strip_prefix(mount)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Rewrite the built `index.html` for serving under `base` (the mount path, e.g.
/// `/_console`; empty for a root mount): prefix each embedded asset's absolute
/// `/name` reference with `base`, and inject a `<base href>` + a
/// `<meta name="boatramp-console-base">` so the client-side router adopts `base`
/// as its `basename`. Pure — unit-tested.
pub fn rewrite_index(index_html: &str, base: &str) -> String {
    let mut html = index_html.to_string();
    if !base.is_empty() {
        for file in CONSOLE_DIST.files() {
            if let Some(name) = file.path().to_str() {
                html = html.replace(&format!("/{name}"), &format!("{base}/{name}"));
            }
        }
    }
    let injection =
        format!("<base href=\"{base}/\"><meta name=\"boatramp-console-base\" content=\"{base}\">");
    match html.find("<head>") {
        Some(pos) => html.insert_str(pos + "<head>".len(), &injection),
        None => html.insert_str(0, &injection),
    }
    html
}

/// The static content-type for a console asset by extension.
fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    }
}

/// Serve the console for a request whose host+path already matched the mount.
fn serve_console(mount: &ConsoleMount, req_path: &str) -> Response {
    let sub = req_path
        .strip_prefix(&mount.path)
        .unwrap_or(req_path)
        .trim_start_matches('/');
    // A hashed asset serves that file; anything else is the SPA history-fallback.
    if !sub.is_empty() {
        if let Some(file) = CONSOLE_DIST.get_file(sub) {
            let mut resp = Response::new(Body::from(file.contents()));
            let h = resp.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(sub)),
            );
            // Filenames are content-hashed ⇒ safe to cache forever.
            h.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            );
            return resp;
        }
    }
    let Some(index) = CONSOLE_DIST.get_file("index.html") else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "console assets missing").into_response();
    };
    let html = rewrite_index(index.contents_utf8().unwrap_or_default(), &mount.path);
    let mut resp = Response::new(Body::from(html));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    // The index references hashed assets; keep it revalidated so a redeploy is
    // picked up (the assets themselves are immutable).
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

/// The mount config carried as middleware state.
#[derive(Clone)]
struct ConsoleState(Arc<ConsoleMount>);

/// Intercept a request for the mounted console; otherwise pass it through.
async fn intercept(State(state): State<ConsoleState>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(crate::strip_port)
        .unwrap_or("");
    let path = req.uri().path().to_string();
    if host_matches(&state.0.host, host) && path_under(&state.0.path, &path) {
        return serve_console(&state.0, &path);
    }
    next.run(req).await
}

/// Layer the console-intercept middleware onto `app` when a mount is configured.
pub fn mount(app: Router, console: Option<ConsoleMount>) -> Router {
    match console {
        Some(m) => app.layer(axum::middleware::from_fn_with_state(
            ConsoleState(Arc::new(m)),
            intercept,
        )),
        None => app,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_normalization() {
        assert_eq!(normalize_path(None), "/_console");
        assert_eq!(normalize_path(Some("")), "/_console");
        assert_eq!(normalize_path(Some("/_console")), "/_console");
        assert_eq!(normalize_path(Some("_console")), "/_console");
        assert_eq!(normalize_path(Some("/admin/console/")), "/admin/console");
        assert_eq!(normalize_path(Some("/")), "");
    }

    #[test]
    fn host_matching() {
        assert!(host_matches("*", "anything.example.com"));
        assert!(host_matches("console.example.com", "console.example.com"));
        assert!(host_matches("console.example.com", "Console.Example.COM"));
        assert!(!host_matches("console.example.com", "other.example.com"));
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "example.com")); // apex included
        assert!(!host_matches("*.example.com", "example.org"));
    }

    #[test]
    fn path_under_matching() {
        assert!(path_under("/_console", "/_console"));
        assert!(path_under("/_console", "/_console/"));
        assert!(path_under("/_console", "/_console/sites/blog"));
        assert!(!path_under("/_console", "/_consolex"));
        assert!(!path_under("/_console", "/api/sites"));
        assert!(path_under("", "/anything")); // root mount
    }

    #[test]
    fn resolve_defaults() {
        let m = ConsoleMount::resolve(None, None);
        assert_eq!(m.host, "*");
        assert_eq!(m.path, "/_console");
        let m = ConsoleMount::resolve(Some("console.x.com".into()), Some("/ui".into()));
        assert_eq!(m.host, "console.x.com");
        assert_eq!(m.path, "/ui");
    }

    #[test]
    fn serve_console_routes_asset_vs_index_vs_fallback() {
        let mount = ConsoleMount::resolve(Some("*".into()), Some("/_console".into()));
        // Mount root -> index (html).
        let r = serve_console(&mount, "/_console");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        // Unknown sub-path -> SPA history-fallback to index (html), not a 404.
        let r = serve_console(&mount, "/_console/sites/blog");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        // A real hashed asset -> its own content-type + immutable caching.
        let js = CONSOLE_DIST
            .files()
            .find(|f| f.path().extension().is_some_and(|e| e == "js"))
            .expect("dist has a .js asset");
        let name = js.path().to_str().unwrap();
        let r = serve_console(&mount, &format!("/_console/{name}"));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );
        assert!(r
            .headers()
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("immutable"));
    }

    #[test]
    fn index_rewrite_prefixes_assets_and_injects_base() {
        let idx =
            r#"<!DOCTYPE html><html><head><link href="/tailwind.css"/></head><body></body></html>"#;
        // With a base, absolute asset refs get prefixed + base injected. (The
        // real dist filenames are hashed; this checks the injection + <base>.)
        let out = rewrite_index(idx, "/_console");
        assert!(out.contains(r#"<base href="/_console/">"#));
        assert!(out.contains(r#"<meta name="boatramp-console-base" content="/_console">"#));
        // Root mount: base href "/" and empty meta, asset refs untouched.
        let out0 = rewrite_index(idx, "");
        assert!(out0.contains(r#"<base href="/">"#));
        assert!(out0.contains(r#"href="/tailwind.css""#));
    }
}
