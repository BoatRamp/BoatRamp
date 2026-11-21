//! Local config-FILE tooling behind `boatramp config convert` / `boatramp config diff`.
//!
//! These operate on the **local config files** — the node daemon config (`boatramp.cfg`)
//! and the project config (`project.cfg`) — not the dynamic daemon config the rest of
//! [`crate::config_cmd`] reads/writes over the control plane.
//!
//! Both file kinds already decode from **RON *and* JSON into the SAME typed structs** via
//! [`ServerConfig::parse_with_format`] / [`ProjectConfig::parse_with_format`] (RON ⇒
//! `ron_options().from_str`, JSON ⇒ `serde_json::from_str`). This module **reuses that one
//! parser** — it never adds a second — and adds only the inverse direction (re-serialize a
//! parsed value) plus a typed-value diff:
//!
//! * **convert** = parse in the source format → re-serialize in the target format
//!   ([`ron_options().to_string_pretty`](ron::Options::to_string_pretty) for RON,
//!   `serde_json::to_string_pretty` for JSON). Lossless at the TYPED level (round-trips
//!   RON↔JSON preserving the config value), but it serializes the config *value*, so
//!   source **comments and formatting are dropped** — it converts the config, not the text.
//! * **diff** canonicalises each input to a `serde_json::Value` (the same typed value
//!   regardless of source format) and walks the two trees, so a pure RON-vs-JSON **format
//!   difference yields NO diff** — only real value/topology changes do.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;

use crate::config::{
    ConfigError, ConfigFormat, ProjectConfig, ServerConfig, resolve_format, ron_options,
};

/// Which local config file kind a document is parsed as. The two kinds share no
/// top-level keys, so a non-empty document is unambiguous (see [`infer_kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConfigKind {
    /// The node daemon config (`boatramp.cfg` ⇒ [`ServerConfig`]): `serve` / `handlers` /
    /// `cluster` / `compute` / `security` / `secrets` / `overlay`.
    Node,
    /// The project config (`project.cfg` ⇒ [`ProjectConfig`]): `publish` / `build` /
    /// `bundle` / `routing`.
    Project,
}

impl ConfigKind {
    /// Lowercase label for output / error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Project => "project",
        }
    }
}

/// A failure in a `config convert` / `config diff` run.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading an input file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Parsing an input file into its typed config failed (wrapped with the file path).
    #[error("{path}: {source}")]
    Parse {
        /// The offending file.
        path: String,
        /// The underlying parse/validation error (same one `load` would raise).
        #[source]
        source: ConfigError,
    },
    /// Re-serializing to RON failed.
    #[error("RON serialization: {0}")]
    Ron(#[from] ron::Error),
    /// Re-serializing (or canonicalizing) to JSON failed.
    #[error("JSON serialization: {0}")]
    Json(#[from] serde_json::Error),
    /// The config kind could not be inferred and no `--kind` was given.
    #[error(
        "could not infer the config kind of {path}: it has no recognized node \
         (serve/handlers/cluster/compute/security/secrets/overlay) or project \
         (publish/build/bundle/routing) top-level keys, or keys from both. Pass \
         --kind node|project."
    )]
    KindInference {
        /// The file whose kind could not be inferred.
        path: String,
    },
    /// The two `diff` inputs are different config kinds.
    #[error(
        "diff inputs are different config kinds: {a} is {a_kind}, {b} is {b_kind}. \
         Both files must be the same kind (pass --kind to force one)."
    )]
    KindMismatch {
        /// First file.
        a: String,
        /// First file's inferred kind.
        a_kind: &'static str,
        /// Second file.
        b: String,
        /// Second file's inferred kind.
        b_kind: &'static str,
    },
}

/// `config convert` result: the converted document plus the kind/target it was rendered as.
#[derive(Debug)]
pub struct Converted {
    /// The config kind that was parsed (inferred or forced).
    pub kind: ConfigKind,
    /// The format the document was rendered to.
    pub to: ConfigFormat,
    /// The converted document text (RON or JSON, pretty-printed).
    pub text: String,
}

/// One semantic difference between two config documents.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffEntry {
    /// Dotted/bracketed path to the field, e.g. `routing.handlers[0].component`.
    pub path: String,
    /// Whether the field was added, removed, or changed (going from the first file to the second).
    pub change: DiffChange,
    /// The value in the first file (absent for an addition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<serde_json::Value>,
    /// The value in the second file (absent for a removal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<serde_json::Value>,
}

/// The kind of a single [`DiffEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffChange {
    /// Present only in the second file.
    Added,
    /// Present only in the first file.
    Removed,
    /// Present in both but with a different value.
    Changed,
}

/// `config diff` result.
#[derive(Debug)]
pub struct DiffResult {
    /// The config kind both inputs were parsed as.
    pub kind: ConfigKind,
    /// Whether `--topology` narrowed the comparison (dropping the expected-to-differ set).
    pub topology: bool,
    /// The differences, sorted by path. Empty ⇒ the two configs are semantically equal.
    pub entries: Vec<DiffEntry>,
}

impl DiffResult {
    /// Whether the two inputs differ (any entries survived).
    pub fn differs(&self) -> bool {
        !self.entries.is_empty()
    }
}

// --- convert ---------------------------------------------------------------

/// Convert the config document at `path` to `to`, auto-detecting the source format by
/// extension (`--from` overrides) and the kind by filename/content (`--kind` overrides).
pub fn convert(
    path: &Path,
    from: Option<ConfigFormat>,
    to: ConfigFormat,
    kind: Option<ConfigKind>,
) -> Result<Converted, Error> {
    let text = std::fs::read_to_string(path)?;
    let src_fmt = resolve_format(path, from);
    let kind = infer_kind(path, &text, src_fmt, kind)?;
    let out = convert_text(&text, src_fmt, to, kind).map_err(|e| match e {
        ConvertError::Parse(source) => Error::Parse {
            path: path.display().to_string(),
            source,
        },
        ConvertError::Serialize(e) => e,
    })?;
    Ok(Converted {
        kind,
        to,
        text: out,
    })
}

/// Parse `text` in `src` as `kind` and re-serialize it to `to`. The `Err` separates a
/// source-parse failure (the caller wraps it with the file path) from a serialize failure.
/// Pure — no I/O.
pub(crate) fn convert_text(
    text: &str,
    src: ConfigFormat,
    to: ConfigFormat,
    kind: ConfigKind,
) -> std::result::Result<String, ConvertError> {
    let out = match kind {
        ConfigKind::Node => serialize(&ServerConfig::parse_with_format(text, src)?, to)?,
        ConfigKind::Project => serialize(&ProjectConfig::parse_with_format(text, src)?, to)?,
    };
    Ok(out)
}

/// Error from the pure [`convert_text`] (either a parse or a serialize failure).
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConvertError {
    /// Source parse/validation failed.
    #[error(transparent)]
    Parse(#[from] ConfigError),
    /// Target serialization failed.
    #[error(transparent)]
    Serialize(#[from] Error),
}

/// Serialize a typed config value to `fmt`, pretty-printed. RON uses the SAME options as
/// the parser ([`ron_options`], `implicit_some`) so the output round-trips back through it.
fn serialize<T: Serialize>(value: &T, fmt: ConfigFormat) -> std::result::Result<String, Error> {
    Ok(match fmt {
        ConfigFormat::Json => serde_json::to_string_pretty(value)?,
        ConfigFormat::Ron => {
            let pretty = ron::ser::PrettyConfig::new().indentor("  ");
            ron_options().to_string_pretty(value, pretty)?
        }
    })
}

// --- diff ------------------------------------------------------------------

/// Diff the config documents at `a` and `b`. Each file's source format is auto-detected
/// by extension; the kind is inferred per-file (and must agree) unless `--kind` forces it.
/// With `topology`, the PLAN's expected-to-differ set is dropped before comparing.
pub fn diff(
    a: &Path,
    b: &Path,
    kind: Option<ConfigKind>,
    topology: bool,
) -> Result<DiffResult, Error> {
    let a_text = std::fs::read_to_string(a)?;
    let b_text = std::fs::read_to_string(b)?;
    let a_fmt = resolve_format(a, None);
    let b_fmt = resolve_format(b, None);
    let a_kind = infer_kind(a, &a_text, a_fmt, kind)?;
    let b_kind = infer_kind(b, &b_text, b_fmt, kind)?;
    if a_kind != b_kind {
        return Err(Error::KindMismatch {
            a: a.display().to_string(),
            a_kind: a_kind.as_str(),
            b: b.display().to_string(),
            b_kind: b_kind.as_str(),
        });
    }
    let kind = a_kind;
    let va = typed_value(&a_text, a_fmt, kind).map_err(parse_err(a))?;
    let vb = typed_value(&b_text, b_fmt, kind).map_err(parse_err(b))?;
    let entries = diff_trees(&va, &vb, topology);
    Ok(DiffResult {
        kind,
        topology,
        entries,
    })
}

/// Parse `text` in `fmt` as `kind` and canonicalise it to a `serde_json::Value` (the same
/// typed value regardless of source format). Pure — no I/O.
pub(crate) fn typed_value(
    text: &str,
    fmt: ConfigFormat,
    kind: ConfigKind,
) -> std::result::Result<serde_json::Value, ConfigError> {
    let value = match kind {
        ConfigKind::Node => serde_json::to_value(ServerConfig::parse_with_format(text, fmt)?),
        ConfigKind::Project => serde_json::to_value(ProjectConfig::parse_with_format(text, fmt)?),
    };
    // A serialize failure here is a programmer error (the structs always serialize), but
    // surface it as a parse error rather than panicking.
    value.map_err(ConfigError::Json)
}

/// Topology path segments the drift-lint treats as **expected-to-differ** and excludes
/// (`PLAN-dev-prod-manifest-overlay.md` deliverable 2):
///
/// * `tenancy` / `token_claims` — the per-route STRUCTURAL fork (prod `scoped`+token vs a
///   dev server that mints no tokens). Linting these would fire on every relaxed route.
/// * `domains` — per-environment domains.
/// * `publish` — the project's deploy-TARGET metadata (server URL / token / site / project),
///   inherently per-environment; not deployment topology.
///
/// Everything else — the route set, handler↔component bindings, functions, consumer topics,
/// and the capability grants (`imports` / `invoke_targets`) — is the must-match topology.
fn is_topology_excluded(segment: &str) -> bool {
    matches!(segment, "tenancy" | "token_claims" | "domains" | "publish")
}

/// Recursively diff two canonical JSON values, collecting [`DiffEntry`]s sorted by path.
pub(crate) fn diff_trees(
    left: &serde_json::Value,
    right: &serde_json::Value,
    topology: bool,
) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    diff_values("", left, right, topology, &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn diff_values(
    path: &str,
    left: &serde_json::Value,
    right: &serde_json::Value,
    topology: bool,
    out: &mut Vec<DiffEntry>,
) {
    use serde_json::Value;
    match (left, right) {
        (Value::Object(l), Value::Object(r)) => {
            let keys: BTreeSet<&String> = l.keys().chain(r.keys()).collect();
            for k in keys {
                // In topology mode, a whole expected-to-differ subtree is skipped at any depth.
                if topology && is_topology_excluded(k) {
                    continue;
                }
                let child = join(path, k);
                match (l.get(k), r.get(k)) {
                    (Some(lv), Some(rv)) => diff_values(&child, lv, rv, topology, out),
                    (Some(lv), None) => out.push(removed(child, lv)),
                    (None, Some(rv)) => out.push(added(child, rv)),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(l), Value::Array(r)) => {
            for i in 0..l.len().max(r.len()) {
                let child = format!("{path}[{i}]");
                match (l.get(i), r.get(i)) {
                    (Some(lv), Some(rv)) => diff_values(&child, lv, rv, topology, out),
                    (Some(lv), None) => out.push(removed(child, lv)),
                    (None, Some(rv)) => out.push(added(child, rv)),
                    (None, None) => {}
                }
            }
        }
        _ => {
            if left != right {
                out.push(DiffEntry {
                    path: path.to_string(),
                    change: DiffChange::Changed,
                    left: Some(left.clone()),
                    right: Some(right.clone()),
                });
            }
        }
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn added(path: String, value: &serde_json::Value) -> DiffEntry {
    DiffEntry {
        path,
        change: DiffChange::Added,
        left: None,
        right: Some(value.clone()),
    }
}

fn removed(path: String, value: &serde_json::Value) -> DiffEntry {
    DiffEntry {
        path,
        change: DiffChange::Removed,
        left: Some(value.clone()),
        right: None,
    }
}

// --- kind inference --------------------------------------------------------

/// Resolve the config kind: an explicit `--kind` wins; else the well-known filenames
/// (`boatramp.cfg` ⇒ node, `project.cfg` ⇒ project); else by content — a non-empty document
/// parses NON-default as exactly one kind, because the two kinds' top-level keys are disjoint
/// and serde drops the other kind's keys to defaults.
fn infer_kind(
    path: &Path,
    text: &str,
    fmt: ConfigFormat,
    override_: Option<ConfigKind>,
) -> Result<ConfigKind, Error> {
    if let Some(k) = override_ {
        return Ok(k);
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name == "boatramp.cfg" {
            return Ok(ConfigKind::Node);
        }
        if name == "project.cfg" {
            return Ok(ConfigKind::Project);
        }
    }
    infer_kind_from_content(text, fmt).ok_or_else(|| Error::KindInference {
        path: path.display().to_string(),
    })
}

/// Content-based kind detection (no filename): a document is this kind iff it parses to a
/// NON-default value as that kind and to the default as the other. Returns `None` when the
/// document is empty/ambiguous or carries keys from both kinds. Pure helper, so the parser
/// stays the single source of truth (no second/throwaway parser).
pub(crate) fn infer_kind_from_content(text: &str, fmt: ConfigFormat) -> Option<ConfigKind> {
    let node_non_default = ServerConfig::parse_with_format(text, fmt)
        .ok()
        .filter(|c| !is_default(c))
        .is_some();
    let project_non_default = ProjectConfig::parse_with_format(text, fmt)
        .ok()
        .filter(|c| !is_default(c))
        .is_some();
    match (node_non_default, project_non_default) {
        (true, false) => Some(ConfigKind::Node),
        (false, true) => Some(ConfigKind::Project),
        _ => None,
    }
}

/// Whether a parsed config equals its default (serialize both and compare — cheap and
/// derive-free). Used only to decide kind by content.
fn is_default<T: Serialize + Default>(value: &T) -> bool {
    serde_json::to_value(value).ok() == serde_json::to_value(T::default()).ok()
}

/// Wrap a [`ConfigError`] as a path-tagged [`Error::Parse`].
fn parse_err(path: &Path) -> impl FnOnce(ConfigError) -> Error + '_ {
    move |source| Error::Parse {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_RON: &str = r#"(serve: (default_site: "blog"))"#;
    const PROJECT_RON: &str = r#"(publish: (site: "blog"))"#;

    /// Convert a node config RON→JSON→RON→JSON and prove the typed VALUE is preserved at
    /// every hop (comparing the canonical JSON value, not the text).
    #[test]
    fn node_round_trips_ron_json_ron() {
        let v0 = typed_value(NODE_RON, ConfigFormat::Ron, ConfigKind::Node).unwrap();

        let json = convert_text(
            NODE_RON,
            ConfigFormat::Ron,
            ConfigFormat::Json,
            ConfigKind::Node,
        )
        .unwrap();
        let v_json = typed_value(&json, ConfigFormat::Json, ConfigKind::Node).unwrap();
        assert_eq!(v0, v_json, "RON→JSON preserved the value");

        let ron2 = convert_text(
            &json,
            ConfigFormat::Json,
            ConfigFormat::Ron,
            ConfigKind::Node,
        )
        .unwrap();
        let v_ron2 = typed_value(&ron2, ConfigFormat::Ron, ConfigKind::Node).unwrap();
        assert_eq!(v0, v_ron2, "JSON→RON preserved the value");

        let json2 = convert_text(
            &ron2,
            ConfigFormat::Ron,
            ConfigFormat::Json,
            ConfigKind::Node,
        )
        .unwrap();
        assert_eq!(
            json, json2,
            "JSON→RON→JSON is byte-identical at the typed level"
        );
    }

    /// Same, for a PROJECT config starting from JSON (JSON→RON→JSON).
    #[test]
    fn project_round_trips_json_ron_json() {
        let project_json = convert_text(
            PROJECT_RON,
            ConfigFormat::Ron,
            ConfigFormat::Json,
            ConfigKind::Project,
        )
        .unwrap();
        let v0 = typed_value(&project_json, ConfigFormat::Json, ConfigKind::Project).unwrap();

        let ron = convert_text(
            &project_json,
            ConfigFormat::Json,
            ConfigFormat::Ron,
            ConfigKind::Project,
        )
        .unwrap();
        let v_ron = typed_value(&ron, ConfigFormat::Ron, ConfigKind::Project).unwrap();
        assert_eq!(v0, v_ron, "JSON→RON preserved the value");

        let json2 = convert_text(
            &ron,
            ConfigFormat::Ron,
            ConfigFormat::Json,
            ConfigKind::Project,
        )
        .unwrap();
        let v2 = typed_value(&json2, ConfigFormat::Json, ConfigKind::Project).unwrap();
        assert_eq!(v0, v2, "RON→JSON preserved the value");
    }

    /// A pure format difference (same config in RON vs JSON) reports NO diff; a real value
    /// change does.
    #[test]
    fn diff_is_format_agnostic_but_catches_a_real_change() {
        // Equivalent project config, one written as RON, the other as JSON.
        let project_json = convert_text(
            PROJECT_RON,
            ConfigFormat::Ron,
            ConfigFormat::Json,
            ConfigKind::Project,
        )
        .unwrap();
        let va = typed_value(PROJECT_RON, ConfigFormat::Ron, ConfigKind::Project).unwrap();
        let vb = typed_value(&project_json, ConfigFormat::Json, ConfigKind::Project).unwrap();
        assert!(
            diff_trees(&va, &vb, false).is_empty(),
            "RON vs JSON of the same config is not a diff"
        );

        // A changed field IS a diff, named by its path.
        let changed = typed_value(
            r#"(publish: (site: "shop"))"#,
            ConfigFormat::Ron,
            ConfigKind::Project,
        )
        .unwrap();
        let entries = diff_trees(&va, &changed, false);
        assert_eq!(entries.len(), 1, "exactly one field differs");
        assert_eq!(entries[0].path, "publish.site");
        assert_eq!(entries[0].change, DiffChange::Changed);
    }

    /// Both config KINDS diff a changed field (node `serve.default_site`, project `publish.site`).
    #[test]
    fn diff_works_for_both_kinds() {
        let node_a = typed_value(NODE_RON, ConfigFormat::Ron, ConfigKind::Node).unwrap();
        let node_b = typed_value(
            r#"(serve: (default_site: "shop"))"#,
            ConfigFormat::Ron,
            ConfigKind::Node,
        )
        .unwrap();
        let node_diff = diff_trees(&node_a, &node_b, false);
        assert_eq!(node_diff.len(), 1);
        assert_eq!(node_diff[0].path, "serve.default_site");

        let proj_a = typed_value(PROJECT_RON, ConfigFormat::Ron, ConfigKind::Project).unwrap();
        let proj_b = typed_value(
            r#"(publish: (site: "shop"))"#,
            ConfigFormat::Ron,
            ConfigKind::Project,
        )
        .unwrap();
        assert_eq!(diff_trees(&proj_a, &proj_b, false).len(), 1);
    }

    /// The `--exit-code` drift-lint: a real difference ⇒ `differs()` true (non-zero exit);
    /// no difference ⇒ false (zero exit).
    #[test]
    fn differs_drives_the_exit_code() {
        let a = typed_value(PROJECT_RON, ConfigFormat::Ron, ConfigKind::Project).unwrap();
        let same = DiffResult {
            kind: ConfigKind::Project,
            topology: false,
            entries: diff_trees(&a, &a, false),
        };
        assert!(!same.differs(), "identical configs ⇒ exit zero");

        let b = typed_value(
            r#"(publish: (site: "shop"))"#,
            ConfigFormat::Ron,
            ConfigKind::Project,
        )
        .unwrap();
        let drift = DiffResult {
            kind: ConfigKind::Project,
            topology: false,
            entries: diff_trees(&a, &b, false),
        };
        assert!(drift.differs(), "a real difference ⇒ non-zero exit");
    }

    /// `--topology` ignores the expected-to-differ set (tenancy/token_claims/domains/publish)
    /// but still catches a real topology change (a route). Uses synthetic trees so the filter
    /// is exercised directly, independent of the manifest's exact field layout.
    #[test]
    fn topology_ignores_expected_to_differ_but_catches_a_route() {
        use serde_json::json;
        let prod = json!({
            "publish": {"server": "https://prod", "site": "app"},
            "routing": {
                "consumers": [{
                    "topic": "jobs", "component": "c.wasm",
                    "tenancy": {"scoped": {"sources": ["token"]}},
                    "token_claims": {"iss": "https://idp"},
                }],
                "handlers": [{"route": "/api", "component": "api.wasm", "imports": ["sql:main"]}],
            },
        });
        let dev = json!({
            "publish": {"server": "https://localhost", "site": "app-dev"},
            "routing": {
                "consumers": [{
                    "topic": "jobs", "component": "c.wasm",
                    "tenancy": {"disabled": true},
                }],
                // The route drifted: /api → /apiv2.
                "handlers": [{"route": "/apiv2", "component": "api.wasm", "imports": ["sql:main"]}],
            },
        });

        // Full diff: sees the route AND tenancy/token_claims/publish differences.
        let full = diff_trees(&prod, &dev, false);
        assert!(full.len() > 1);
        assert!(full.iter().any(|e| e.path.contains("tenancy")));
        assert!(full.iter().any(|e| e.path.starts_with("publish")));

        // Topology diff: ONLY the structural route change survives.
        let topo = diff_trees(&prod, &dev, true);
        assert_eq!(
            topo.len(),
            1,
            "only the route topology change survives, got {topo:?}"
        );
        assert_eq!(topo[0].path, "routing.handlers[0].route");
        assert!(
            !topo.iter().any(|e| e.path.contains("tenancy")
                || e.path.contains("token_claims")
                || e.path.starts_with("publish")),
            "expected-to-differ set is dropped in topology mode"
        );
    }

    /// Kind inference by content: a node doc infers node, a project doc infers project, an
    /// empty/ambiguous doc infers neither.
    #[test]
    fn kind_inference_by_content() {
        assert_eq!(
            infer_kind_from_content(NODE_RON, ConfigFormat::Ron),
            Some(ConfigKind::Node)
        );
        assert_eq!(
            infer_kind_from_content(PROJECT_RON, ConfigFormat::Ron),
            Some(ConfigKind::Project)
        );
        // Empty document: both parse to default ⇒ ambiguous.
        assert_eq!(infer_kind_from_content("()", ConfigFormat::Ron), None);
        // JSON project doc.
        assert_eq!(
            infer_kind_from_content(r#"{"publish":{"site":"blog"}}"#, ConfigFormat::Json),
            Some(ConfigKind::Project)
        );
    }

    /// `infer_kind` prefers the well-known filename over content.
    #[test]
    fn kind_inference_by_filename() {
        assert_eq!(
            infer_kind(Path::new("boatramp.cfg"), "()", ConfigFormat::Ron, None).unwrap(),
            ConfigKind::Node
        );
        assert_eq!(
            infer_kind(Path::new("project.cfg"), "()", ConfigFormat::Ron, None).unwrap(),
            ConfigKind::Project
        );
        // An explicit --kind beats everything.
        assert_eq!(
            infer_kind(
                Path::new("boatramp.cfg"),
                "()",
                ConfigFormat::Ron,
                Some(ConfigKind::Project)
            )
            .unwrap(),
            ConfigKind::Project
        );
    }
}
