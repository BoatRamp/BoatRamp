//! Deploy-scoped configuration (the `routing` section of `project.cfg`).
//!
//! This is the **immutable, deploy-scoped** config tier: it is authored as the
//! `routing` section of `project.cfg`, parsed at `sync` time, and folded into
//! the deployment manifest (`boatramp_core::deploy::Manifest`).
//! Because it travels inside the manifest it is atomic with the content and
//! rolls back with it.
//!
//! (The mutable, site-scoped tier — domains, TLS, access control — is a separate
//! `SiteConfig` in the KV store, added alongside the virtualhost/auth work.)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;
use crate::matcher::Pattern;

/// Deploy-scoped configuration — the `routing` section of `project.cfg`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeployConfig {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`]. Optional in
    /// `project.cfg` routing (defaults to 1); always present once folded in.
    pub version: u32,
    /// Directory-index candidates, tried in order (default `["index.html"]`).
    pub index: Vec<String>,
    /// Map extensionless URLs to `.html` files (`/about` → `/about.html`).
    pub clean_urls: bool,
    /// Match the request path **case-insensitively** against redirects, rewrites,
    /// and static files (`/About.HTML` serves `/about.html`). Off by default
    /// (paths are case-sensitive); opt-in for case-folding origins.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub case_insensitive: bool,
    /// Trailing-slash policy.
    pub trailing_slash: TrailingSlash,
    /// Status code → error document (e.g. `404 → /404.html`).
    pub error_documents: BTreeMap<u16, String>,
    /// Redirect rules (first match wins).
    pub redirects: Vec<Redirect>,
    /// Rewrite rules (internal rewrite or proxy; first match wins).
    pub rewrites: Vec<Rewrite>,
    /// Response-header rules (all matching rules apply, in order).
    pub headers: Vec<HeaderRule>,
    /// Cache-Control defaults.
    pub cache: CacheConfig,
    /// Extension → MIME overrides (e.g. `.webmanifest`).
    pub mime_overrides: BTreeMap<String, String>,
    /// Allowed upstream hosts for proxy rewrites (exact host or `.suffix`
    /// match). When empty, proxying to any *public* host is allowed; private,
    /// loopback, link-local, and similar internal addresses are always blocked
    /// (SSRF guard), regardless of this list.
    pub proxy_allow: Vec<String>,
    /// WebAssembly request handlers (deploy-scoped).
    /// Matched before static lookup, after redirects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handlers: Vec<HandlerConfig>,
    /// Message-consumer components, invoked per message on a topic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<ConsumerConfig>,
    /// Scheduled handler invocations (cron).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crons: Vec<CronConfig>,
    /// Host-level SSE endpoints fanning out messaging topics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<StreamConfig>,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            index: vec!["index.html".to_string()],
            clean_urls: false,
            case_insensitive: false,
            trailing_slash: TrailingSlash::default(),
            error_documents: BTreeMap::new(),
            redirects: Vec::new(),
            rewrites: Vec::new(),
            headers: Vec::new(),
            cache: CacheConfig::default(),
            mime_overrides: BTreeMap::new(),
            proxy_allow: Vec::new(),
            handlers: Vec::new(),
            consumers: Vec::new(),
            crons: Vec::new(),
            streams: Vec::new(),
        }
    }
}

impl DeployConfig {
    /// Parse a deploy-scoped `routing` document (RON). `implicit_some` is enabled
    /// so optional fields can be written as bare values (not `Some("...")`).
    pub fn from_ron(text: &str) -> Result<Self, ConfigError> {
        let options = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME);
        let config: Self = options
            .from_str(text)
            .map_err(|err| ConfigError::parse(err.to_string()))?;
        config.compile_check()?;
        Ok(config)
    }

    /// Whether `host` is permitted as a proxy-rewrite upstream by the
    /// `proxy_allow` list. An empty list permits any host (the separate
    /// public-IP SSRF guard still applies); otherwise the host must equal an
    /// entry or be a subdomain of a `.`-prefixed suffix entry.
    pub fn proxy_host_allowed(&self, host: &str) -> bool {
        if self.proxy_allow.is_empty() {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.proxy_allow.iter().any(|entry| {
            let entry = entry.trim().to_ascii_lowercase();
            match entry.strip_prefix('.') {
                Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
                None => host == entry,
            }
        })
    }

    /// Verify every route/header pattern compiles. Used by `from_ron` and the
    /// `validate` subcommand so bad patterns fail fast at deploy time.
    pub fn compile_check(&self) -> Result<(), ConfigError> {
        for redirect in &self.redirects {
            Pattern::compile(&redirect.from)?;
            if let Some(when) = &redirect.when {
                crate::predicate::Predicate::compile(when)?;
            }
            if crate::predicate::Template::is_template(&redirect.to) {
                crate::predicate::Template::compile(&redirect.to)?;
            }
        }
        for rewrite in &self.rewrites {
            Pattern::compile(&rewrite.from)?;
            if let Some(when) = &rewrite.when {
                crate::predicate::Predicate::compile(when)?;
            }
            if crate::predicate::Template::is_template(&rewrite.to) {
                crate::predicate::Template::compile(&rewrite.to)?;
            }
        }
        for header in &self.headers {
            Pattern::compile(&header.matches)?;
        }
        self.check_handlers()?;
        Ok(())
    }

    /// Offline validation of the handler/consumer/cron/stream config: route
    /// patterns compile, HTTP methods and requested imports are recognized,
    /// cron schedules parse, and every cron route is served by some declared
    /// handler. (Component *binary* validation happens at `sync`, where the
    /// `.wasm` bytes are available.)
    fn check_handlers(&self) -> Result<(), ConfigError> {
        let handler_patterns: Vec<Pattern> = self
            .handlers
            .iter()
            .map(|h| Pattern::compile(&h.route))
            .collect::<Result<_, _>>()?;

        for handler in &self.handlers {
            if handler.component.is_empty() {
                return Err(ConfigError::parse(format!(
                    "handler {} has an empty component path",
                    handler.route
                )));
            }
            for method in &handler.methods {
                check_http_method(method)?;
            }
            for import in &handler.imports {
                check_import(import)?;
            }
            // `env` is for static, non-secret strings; a secret belongs in
            // `[handlers].secrets` as a *reference* to a host env var, so it
            // never lands in the (content-addressed, stored) manifest.
            // Best-effort heuristic — catches accidents.
            for (key, value) in &handler.env {
                if looks_like_secret(value) {
                    return Err(ConfigError::parse(format!(
                        "handler {} env var {key:?} looks like a secret; move it to \
                         [handlers].secrets as a reference to a host env var rather than \
                         inlining it in `env` (which is stored in the manifest)",
                        handler.route
                    )));
                }
            }
        }
        for consumer in &self.consumers {
            if consumer.topic.is_empty() || consumer.component.is_empty() {
                return Err(ConfigError::parse(
                    "consumer needs a non-empty topic and component".to_string(),
                ));
            }
            for import in &consumer.imports {
                check_import(import)?;
            }
        }
        for cron in &self.crons {
            check_cron_schedule(&cron.schedule)?;
            if !handler_patterns.iter().any(|p| p.is_match(&cron.route)) {
                return Err(ConfigError::parse(format!(
                    "cron route {} is not served by any declared handler",
                    cron.route
                )));
            }
        }
        for stream in &self.streams {
            Pattern::compile(&stream.route)?;
            if stream.topics.is_empty() {
                return Err(ConfigError::parse(format!(
                    "stream {} subscribes to no topics",
                    stream.route
                )));
            }
        }
        Ok(())
    }
}

/// The standard interface vocabulary a handler may request.
/// `sql` is the one generic non-`wasi:` interface.
const KNOWN_IMPORTS: &[&str] = &[
    "sql",
    "wasi:http",
    "wasi:io",
    "wasi:keyvalue",
    "wasi:blobstore",
    "wasi:messaging",
    "wasi:clocks",
    "wasi:random",
    "wasi:logging",
];

/// Best-effort heuristic: does `value` look like a credential that should be a
/// `secrets` reference rather than a static `env` string?
/// Catches the common accidents — it is a guard, not a guarantee.
fn looks_like_secret(value: &str) -> bool {
    let v = value.trim();
    // A PEM private-key block.
    if v.contains("-----BEGIN") && v.contains("PRIVATE KEY") {
        return true;
    }
    // Well-known credential prefixes (cloud keys, VCS/chat/LLM tokens, …).
    const PREFIXES: &[&str] = &[
        "AKIA",
        "ASIA",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "glpat-",
        "AIza",
        "AccountKey=",
    ];
    if PREFIXES.iter().any(|p| v.contains(p)) {
        return true;
    }
    let has_digit = v.bytes().any(|b| b.is_ascii_digit());
    // A long pure-hex blob (API key / hash-shaped secret).
    if v.len() >= 40 && has_digit && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    // A long, mixed-case, token-charset, high-entropy string (base64-ish key).
    let charset_ok = v
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    let mixed_case =
        v.bytes().any(|b| b.is_ascii_uppercase()) && v.bytes().any(|b| b.is_ascii_lowercase());
    v.len() >= 32 && charset_ok && has_digit && mixed_case && shannon_entropy_bits(v) >= 3.5
}

/// Shannon entropy of `s` in bits per character (0 for empty).
fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn check_import(import: &str) -> Result<(), ConfigError> {
    if KNOWN_IMPORTS.contains(&import) {
        Ok(())
    } else {
        Err(ConfigError::parse(format!(
            "unknown handler import {import:?}; allowed: {}",
            KNOWN_IMPORTS.join(", ")
        )))
    }
}

fn check_http_method(method: &str) -> Result<(), ConfigError> {
    const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
    if METHODS.contains(&method) {
        Ok(())
    } else {
        Err(ConfigError::parse(format!(
            "unknown HTTP method {method:?}"
        )))
    }
}

/// Validate a standard 5-field cron schedule (`minute hour dom month dow`).
/// Each field is `*`, `*/step`, a number, an `a-b` range, an `a-b/step`, or a
/// comma list of those, within the field's numeric bounds.
fn check_cron_schedule(schedule: &str) -> Result<(), ConfigError> {
    // Validation = parsing the schedule (the same parser the scheduler uses to
    // evaluate it — one grammar, no drift).
    crate::cron::CronSchedule::parse(schedule)
        .map(|_| ())
        .map_err(|err| ConfigError::parse(format!("cron schedule {schedule:?}: {err}")))
}

/// Trailing-slash handling for request paths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrailingSlash {
    /// Leave the path as-is.
    #[default]
    Preserve,
    /// Redirect to add a trailing slash.
    Always,
    /// Redirect to strip a trailing slash.
    Never,
}

/// A redirect rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// Source pattern (see [`crate::matcher`]).
    pub from: String,
    /// Destination, with `:name`/`:splat` substitution.
    pub to: String,
    /// HTTP status (default 308 — permanent, method-preserving).
    #[serde(default = "default_redirect_status")]
    pub status: u16,
    /// Optional server-side condition (a [`crate::predicate`] expression over the
    /// request — `Accept-Language`, cookies, headers, `file_exists(...)`, …). When
    /// set, the rule fires only if it evaluates true. Compiled + type-checked at
    /// `validate`/`sync`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
}

fn default_redirect_status() -> u16 {
    308
}

/// A rewrite rule: serve a different path (internal) or proxy (absolute URL).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    /// Source pattern.
    pub from: String,
    /// Internal path or absolute proxy URL, with `:name`/`:splat` substitution.
    pub to: String,
    /// Status to serve for an internal rewrite (default 200).
    #[serde(default = "default_rewrite_status")]
    pub status: u16,
    /// Optional server-side condition — see [`Redirect::when`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
}

fn default_rewrite_status() -> u16 {
    200
}

/// A response-header rule applied to matching paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRule {
    /// Path pattern to match (named `matches` because `for` is a Rust keyword).
    pub matches: String,
    /// Headers to set.
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    /// Header names to remove.
    #[serde(default)]
    pub unset: Vec<String>,
}

/// Cache-Control defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Default `Cache-Control` for responses not covered by a header rule.
    pub default: Option<String>,
}

/// A WebAssembly request handler bound to a route (deploy-scoped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerConfig {
    /// Route pattern (matcher syntax).
    pub route: String,
    /// HTTP methods this handler answers (empty = all).
    #[serde(default)]
    pub methods: Vec<String>,
    /// Path to the component `.wasm` within the deployment.
    pub component: String,
    /// Requested capabilities (interface names; see `KNOWN_IMPORTS`).
    #[serde(default)]
    pub imports: Vec<String>,
    /// Optional resource limits (capped by site config at activation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<HandlerLimits>,
    /// Static environment variables (never secrets).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// Per-handler resource limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerLimits {
    /// Max linear memory, MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    /// Wall-clock timeout, milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
    /// CPU budget in wasmtime **fuel** units (instruction-count proxy); the
    /// guest traps when it runs out. A deterministic CPU bound on top of the
    /// wall-clock timeout. Omitted = unmetered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<u64>,
}

/// A message-consumer component, invoked per message on a topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerConfig {
    /// Topic to subscribe to (namespaced like all topics).
    pub topic: String,
    /// Path to the component `.wasm` within the deployment.
    pub component: String,
    /// Requested capabilities.
    #[serde(default)]
    pub imports: Vec<String>,
}

/// A scheduled invocation of a declared handler route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CronConfig {
    /// Standard 5-field cron schedule.
    pub schedule: String,
    /// Handler route to invoke (must be served by a declared handler).
    pub route: String,
    /// Overlap policy when a previous run is still in flight.
    #[serde(default)]
    pub overlap: Overlap,
}

/// Cron overlap policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Overlap {
    /// Skip the tick if the previous invocation is still running (default).
    #[default]
    Skip,
    /// Allow concurrent invocations.
    Allow,
}

/// A host-level SSE (or WebSocket) endpoint fanning out messaging topics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    /// Route the SSE (or WebSocket) endpoint is served at.
    pub route: String,
    /// Topics whose messages are broadcast to connected clients (server→client).
    pub topics: Vec<String>,
    /// Serve this route as a **WebSocket** instead of SSE:
    /// the same `topics` fan out server→client, and — bidirectionally — messages
    /// the client sends are published to [`publish_topic`](Self::publish_topic).
    /// Off by default (SSE).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub websocket: bool,
    /// For a `websocket` stream, the (scope-relative) topic that client→server
    /// messages are published to. `None` = the socket is receive-only (client
    /// sends are dropped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_topic: Option<String>,
}

/// Site-scoped, mutable configuration stored in the KV (not in the manifest).
///
/// Carries domains (virtualhost routing) and visitor access control; TLS,
/// previews, and retention land with their respective workstreams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SiteConfig {
    /// Schema version, pinned at [`crate::SCHEMA_VERSION`].
    pub version: u32,
    /// Hostnames this site answers to.
    pub domains: DomainConfig,
    /// Transport security: HTTPS redirect + HSTS (site tier).
    #[serde(default)]
    pub security: SecurityConfig,
    /// Visitor access control (basic auth, IP rules, rate limiting).
    #[serde(default)]
    pub access: crate::access::AccessConfig,
    /// WebAssembly handler caps + import allowlist (site-scoped).
    /// `None` = handlers disabled for the site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handlers: Option<HandlersSiteConfig>,
    /// On-the-fly response compression. Off by default;
    /// complements the precompressed-variant path for dynamic/unvaried responses.
    #[serde(default, skip_serializing_if = "CompressionConfig::is_default")]
    pub compression: CompressionConfig,
    /// Reverse-proxy gateway for publishing private services.
    /// `None` = no gateway routes. Declaring an upstream here is what authorizes
    /// reaching a private address (the SSRF guard stays public-only otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::gateway::GatewayConfig>,
}

impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            version: crate::SCHEMA_VERSION,
            domains: DomainConfig::default(),
            security: SecurityConfig::default(),
            access: crate::access::AccessConfig::default(),
            handlers: None,
            compression: CompressionConfig::default(),
            gateway: None,
        }
    }
}

/// On-the-fly compression policy. Opt-in: compresses a
/// response *only* when it has no precompressed variant / existing
/// `Content-Encoding`, its type is compressible, and (when known) its length is
/// at least `min_size`. Credentialed responses are skipped (BREACH safety).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionConfig {
    /// Master toggle (default off).
    pub enabled: bool,
    /// Don't compress a response whose `Content-Length` is below this (bytes).
    /// Streaming responses with no declared length are always eligible.
    pub min_size: u64,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_size: 1024,
        }
    }
}

impl CompressionConfig {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Site-scoped handler policy: the capability allowlist and resource caps that
/// a deployment's requested handler config is intersected against at
/// activation (deny by default).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HandlersSiteConfig {
    /// Whether handlers run for this site at all.
    pub enabled: bool,
    /// Interfaces handlers on this site may import (subset of `KNOWN_IMPORTS`).
    pub allow_imports: Vec<String>,
    /// Cap on per-handler memory (MiB).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u32>,
    /// Cap on per-handler timeout (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_timeout_ms: Option<u32>,
    /// Cap on concurrent invocations for the site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    /// Cap on per-handler CPU **fuel** (instruction-count proxy). A per-handler
    /// `fuel` may only lower this, never raise it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fuel: Option<u64>,
    /// Env-var name → secret reference, injected at instantiation (the value is
    /// a backend reference, resolved server-side — never a literal secret here).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
    /// Named aliases (besides the live/current deployment) whose deployments
    /// also run **background work** — consumers and crons. The
    /// current deployment always runs background work; previews never do. Empty
    /// by default, so only the current deployment is background-active. Each
    /// listed alias gets its own topic namespace (`{site}/{alias}/…`), isolated
    /// from the live one (e.g. opt `staging` in).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub background_aliases: Vec<String>,
    /// Cap on concurrent SSE stream connections for the site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_stream_connections: Option<u32>,
    /// Cap on captured guest log lines per second for the site, so a noisy guest
    /// can't flood the log sink. Lines over the cap are
    /// dropped (counted). `None` = the server default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_log_rate: Option<u32>,
}

impl SiteConfig {
    /// Parse from JSON (the KV storage / API format).
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        serde_json::from_slice(bytes).map_err(|err| ConfigError::parse(err.to_string()))
    }

    /// Serialize to JSON for KV storage.
    pub fn to_json(&self) -> Result<Vec<u8>, ConfigError> {
        serde_json::to_vec(self).map_err(|err| ConfigError::parse(err.to_string()))
    }
}

/// The hostnames a site answers to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DomainConfig {
    /// Primary/canonical hostname (e.g. `example.com`).
    pub primary: Option<String>,
    /// Additional exact hostnames (e.g. `www.example.com`).
    pub aliases: Vec<String>,
    /// Wildcard patterns (`*.example.com`), matched by suffix at any depth.
    pub wildcards: Vec<String>,
    /// Redirect exact-alias hosts to [`primary`](Self::primary) with a 301
    /// (apex↔www canonicalization). Only exact aliases redirect — wildcard hosts
    /// serve as-is. Off by default.
    pub canonical_redirect: bool,
}

impl DomainConfig {
    /// All exact hostnames (primary first, then aliases).
    pub fn exact_hosts(&self) -> impl Iterator<Item = &str> {
        self.primary
            .as_deref()
            .into_iter()
            .chain(self.aliases.iter().map(String::as_str))
    }
}

/// Site-scoped **transport security** (the site config tier owns transport
/// concerns). Off by default; the operator opts in once TLS is in
/// front (directly or via a terminating proxy).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// 301 plain-HTTP requests to HTTPS. Proxy-aware: the effective scheme is
    /// read from `X-Forwarded-Proto` behind a TLS-terminating proxy.
    pub https_redirect: bool,
    /// Send `Strict-Transport-Security` on HTTPS responses, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsts: Option<Hsts>,
    /// `Content-Security-Policy` header value, when set (opt-in: a default CSP
    /// would break the inline scripts/styles common in static sites, so the
    /// operator supplies the policy). Applied on host-routed responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csp: Option<String>,
    /// `X-Frame-Options` header value (e.g. `DENY`, `SAMEORIGIN`), when set.
    /// Opt-in: it can break legitimate embedding, so it isn't a default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_options: Option<String>,
}

/// HTTP Strict-Transport-Security policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Hsts {
    /// `max-age` in seconds.
    pub max_age: u64,
    /// Apply to subdomains too.
    pub include_subdomains: bool,
    /// Request inclusion in browser preload lists.
    pub preload: bool,
}

impl Default for Hsts {
    fn default() -> Self {
        // One year + includeSubDomains: the common safe baseline (preload is an
        // explicit opt-in since it's hard to undo).
        Self {
            max_age: 31_536_000,
            include_subdomains: true,
            preload: false,
        }
    }
}

impl Hsts {
    /// The `Strict-Transport-Security` header value.
    pub fn header_value(&self) -> String {
        let mut v = format!("max-age={}", self.max_age);
        if self.include_subdomains {
            v.push_str("; includeSubDomains");
        }
        if self.preload {
            v.push_str("; preload");
        }
        v
    }
}

/// Compute the canonicalization/HTTPS **redirect target** for a request, or
/// `None` if it's already canonical. `scheme` is the
/// effective scheme (`http`/`https`, proxy-aware), `host` the request host
/// (no port), `path_and_query` the rest of the URL. A single 301 collapses both
/// an HTTPS upgrade and an apex↔www redirect.
pub fn transport_redirect(
    security: &SecurityConfig,
    domains: &DomainConfig,
    scheme: &str,
    host: &str,
    path_and_query: &str,
) -> Option<String> {
    let target_scheme = if security.https_redirect && scheme == "http" {
        "https"
    } else {
        scheme
    };
    // Only exact aliases canonicalize to the primary; wildcard hosts serve as-is.
    let target_host = match &domains.primary {
        Some(primary)
            if domains.canonical_redirect
                && primary != host
                && domains.aliases.iter().any(|a| a == host) =>
        {
            primary.as_str()
        }
        _ => host,
    };
    if target_scheme == scheme && target_host == host {
        return None;
    }
    Some(format!("{target_scheme}://{target_host}{path_and_query}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let config = DeployConfig::from_ron("()").unwrap();
        assert_eq!(config.index, vec!["index.html".to_string()]);
        assert_eq!(config.trailing_slash, TrailingSlash::Preserve);
        assert!(config.redirects.is_empty());
    }

    #[test]
    fn transport_redirect_https_canonical_and_noop() {
        let mut domains = DomainConfig {
            primary: Some("example.com".into()),
            aliases: vec!["www.example.com".into()],
            ..Default::default()
        };
        let mut sec = SecurityConfig::default();

        // Defaults: nothing configured → no redirect.
        assert_eq!(
            transport_redirect(&sec, &domains, "http", "example.com", "/a?b=1"),
            None
        );

        // HTTPS redirect only.
        sec.https_redirect = true;
        assert_eq!(
            transport_redirect(&sec, &domains, "http", "example.com", "/a?b=1").as_deref(),
            Some("https://example.com/a?b=1")
        );
        // Already https → no-op.
        assert_eq!(
            transport_redirect(&sec, &domains, "https", "example.com", "/a"),
            None
        );

        // Canonical: an exact alias → primary (and HTTPS in one hop).
        domains.canonical_redirect = true;
        assert_eq!(
            transport_redirect(&sec, &domains, "http", "www.example.com", "/p").as_deref(),
            Some("https://example.com/p")
        );
        // The primary itself is canonical → only the scheme may change.
        assert_eq!(
            transport_redirect(&sec, &domains, "https", "example.com", "/p"),
            None
        );
        // A wildcard/non-alias host is NOT canonicalized (only the scheme).
        assert_eq!(
            transport_redirect(&sec, &domains, "https", "blog.example.com", "/p"),
            None
        );
        sec.https_redirect = false;
        assert_eq!(
            transport_redirect(&sec, &domains, "https", "www.example.com", "/p").as_deref(),
            Some("https://example.com/p"),
            "canonical redirect applies even without https_redirect"
        );
    }

    #[test]
    fn hsts_header_value() {
        assert_eq!(
            Hsts::default().header_value(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            Hsts {
                max_age: 60,
                include_subdomains: false,
                preload: true
            }
            .header_value(),
            "max-age=60; preload"
        );
    }

    #[test]
    fn secret_heuristic_flags_credentials_not_plain_config() {
        // Plain, legitimate `env` values are NOT flagged.
        for ok in [
            "info",
            "production",
            "https://api.example.com/v1",
            "3000",
            "en-US,en;q=0.9",
            "a-normal-kebab-case-flag",
        ] {
            assert!(!looks_like_secret(ok), "false positive on {ok:?}");
        }
        // Credential-shaped values ARE flagged.
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        for bad in [
            pem,
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a", // GitHub PAT shape
            "AIzaSyA-1234567890abcdefghijklmnopqrstuv", // Google API key shape
            "wJalrXUtnFEMI1bK7MDENGbPxRfiCYEXAMPLEKEY12", // mixed-case high-entropy
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef0123", // long hex
        ] {
            assert!(looks_like_secret(bad), "missed secret {bad:?}");
        }
    }

    #[test]
    fn check_handlers_rejects_secret_in_env() {
        use std::collections::BTreeMap;
        let config = DeployConfig {
            handlers: vec![HandlerConfig {
                route: "/h".into(),
                methods: Vec::new(),
                component: "h.wasm".into(),
                imports: Vec::new(),
                limits: None,
                env: BTreeMap::from([("AWS_KEY".to_string(), "AKIAIOSFODNN7EXAMPLE".to_string())]),
            }],
            ..Default::default()
        };
        let err = config.compile_check().unwrap_err().to_string();
        assert!(err.contains("looks like a secret"), "got: {err}");
    }

    #[test]
    fn parses_a_full_document() {
        let text = r#"(
            clean_urls: true,
            trailing_slash: Never,
            error_documents: { 404: "/404.html" },
            redirects: [ (from: "/old/:slug", to: "/new/:slug", status: 301) ],
            rewrites: [ (from: "/app/**", to: "/index.html") ],
            headers: [ (matches: "**.js", set: { "Cache-Control": "public, max-age=31536000, immutable" }) ],
            cache: ( default: "public, max-age=0, must-revalidate" ),
            mime_overrides: { ".webmanifest": "application/manifest+json" },
        )"#;
        let config = DeployConfig::from_ron(text).unwrap();
        assert!(config.clean_urls);
        assert_eq!(config.trailing_slash, TrailingSlash::Never);
        assert_eq!(config.redirects[0].status, 301);
        assert_eq!(config.rewrites[0].status, 200); // defaulted
        assert_eq!(
            config.error_documents.get(&404).map(String::as_str),
            Some("/404.html")
        );
    }

    #[test]
    fn rejects_bad_pattern_at_parse() {
        let text = r#"( redirects: [ (from: "/a/**/b/**", to: "/x") ] )"#;
        assert!(DeployConfig::from_ron(text).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        assert!(DeployConfig::from_ron("( nope: true )").is_err());
    }

    #[test]
    fn proxy_allow_list_matching() {
        // Empty list permits any host (the IP guard still applies separately).
        assert!(DeployConfig::default().proxy_host_allowed("anything.example"));

        let cfg = DeployConfig {
            proxy_allow: vec!["api.example.com".into(), ".internal.test".into()],
            ..DeployConfig::default()
        };
        assert!(cfg.proxy_host_allowed("api.example.com")); // exact
        assert!(cfg.proxy_host_allowed("API.EXAMPLE.COM")); // case-insensitive
        assert!(cfg.proxy_host_allowed("a.internal.test")); // suffix
        assert!(cfg.proxy_host_allowed("internal.test")); // suffix apex
        assert!(!cfg.proxy_host_allowed("evil.com"));
        assert!(!cfg.proxy_host_allowed("notapi.example.com"));
    }

    #[test]
    fn parses_handler_config() {
        let text = r#"(
            handlers: [
                ( route: "/api/orders/*", methods: ["GET", "POST"],
                  component: "handlers/orders.wasm",
                  imports: ["sql", "wasi:keyvalue", "wasi:messaging"],
                  limits: ( memory_mb: 64, timeout_ms: 10000 ),
                  env: { "LOG_LEVEL": "info" } ),
            ],
            consumers: [
                ( topic: "orders/created", component: "handlers/agg.wasm",
                  imports: ["sql"] ),
            ],
            crons: [ ( schedule: "0 */6 * * *", route: "/api/orders/reindex", overlap: Skip ) ],
            streams: [ ( route: "/events/orders", topics: ["orders/created"] ) ],
        )"#;
        let config = DeployConfig::from_ron(text).unwrap();
        assert_eq!(config.handlers.len(), 1);
        assert_eq!(config.handlers[0].imports.len(), 3);
        assert_eq!(
            config.handlers[0].limits.as_ref().unwrap().memory_mb,
            Some(64)
        );
        assert_eq!(config.consumers.len(), 1);
        assert_eq!(config.crons[0].overlap, Overlap::Skip);
        assert_eq!(config.streams[0].topics, vec!["orders/created".to_string()]);
    }

    #[test]
    fn handler_validation_rejects_bad_config() {
        // Unknown import.
        assert!(DeployConfig::from_ron(
            r#"( handlers: [ ( route: "/a", component: "a.wasm", imports: ["wasi:gpu"] ) ] )"#
        )
        .is_err());
        // Bad HTTP method.
        assert!(DeployConfig::from_ron(
            r#"( handlers: [ ( route: "/a", component: "a.wasm", methods: ["FETCH"] ) ] )"#
        )
        .is_err());
        // Cron route not served by any handler.
        assert!(DeployConfig::from_ron(
            r#"( handlers: [ ( route: "/a", component: "a.wasm" ) ],
                 crons: [ ( schedule: "* * * * *", route: "/nope" ) ] )"#
        )
        .is_err());
        // A cron whose route IS served validates.
        assert!(DeployConfig::from_ron(
            r#"( handlers: [ ( route: "/tasks/*", component: "a.wasm" ) ],
                 crons: [ ( schedule: "0 0 * * *", route: "/tasks/x" ) ] )"#
        )
        .is_ok());
    }

    #[test]
    fn cron_schedule_validation() {
        for ok in [
            "* * * * *",
            "0 */6 * * *",
            "30 2 1 1 0",
            "0,15,30,45 9-17 * * 1-5",
        ] {
            assert!(check_cron_schedule(ok).is_ok(), "{ok} should be valid");
        }
        for bad in [
            "* * * *",     // 4 fields
            "60 * * * *",  // minute out of range
            "* 24 * * *",  // hour out of range
            "* * 0 * *",   // dom < 1
            "* * * 13 *",  // month > 12
            "*/0 * * * *", // zero step
            "5-1 * * * *", // descending range
        ] {
            assert!(check_cron_schedule(bad).is_err(), "{bad} should be invalid");
        }
    }

    #[test]
    fn handler_free_config_omits_handler_fields() {
        // A static-only deploy serializes without any handler keys (so existing
        // manifest ids are unchanged).
        let json = serde_json::to_string(&DeployConfig::default()).unwrap();
        assert!(!json.contains("handlers"));
        assert!(!json.contains("crons"));
    }

    #[test]
    fn schema_version_defaults_to_one() {
        // Optional in RON; defaults to 1.
        assert_eq!(DeployConfig::from_ron("()").unwrap().version, 1);
        assert_eq!(DeployConfig::from_ron("(version: 1)").unwrap().version, 1);
        assert_eq!(SiteConfig::default().version, 1);
        // A version-less stored SiteConfig still reads as v1.
        assert_eq!(SiteConfig::from_json(b"{}").unwrap().version, 1);
    }
}
