//! The FaaS **function** model — PLAN-faas FA-1.
//!
//! A **function** is the compute *artifact*: a versioned WASI component + its
//! binding/capability config. It is the one primitive the engine runs (decision 1
//! — "one primitive, two views"). A **handler** is *not* a resource — it is a
//! function reached by an HTTP **route** trigger; likewise a *consumer* / *cron* is
//! a function reached by a queue / timer trigger (decision 5). Triggers are their
//! own objects, and many can point at one function version (decision 2).
//!
//! [`desugar`] lowers a site's deploy-scoped `handlers/consumers/crons/streams`
//! into functions + triggers with **no behavioural change** — the mandatory
//! non-breaking gate: a site's handlers must run identically before and after.
//! It is a pure config→shape transform; the content hash / version id of each
//! function is assigned later, at `sync`, when its component blob is uploaded.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{ConsumerConfig, DeployConfig, HandlerConfig, HandlerLimits, Overlap};
use crate::file::FileEntry;

/// A function's owner — a **site** or a **project/tenant**. Drives the KV/blob/sql
/// binding prefix and the inherited RBAC (a site-scoped function gains no privilege
/// over its site).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// Owned by a site: `fn/<site>/<name>`, binding prefix + RBAC of the site.
    Site(String),
    /// A top-level function owned by a project/tenant: `fn/<name>`.
    Project(String),
}

/// A function version's lifecycle (decision 3: `DeployPinned` is the default).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifecycle {
    /// Versions + rolls back atomically with the owning site's deploy.
    #[default]
    DeployPinned,
    /// Its own version / alias / rollback, independent of any deploy.
    Independent,
}

/// The execution substrate (decision 1: a per-function knob; `wasm` is the default
/// and scales to zero by instantiation; the stronger-isolation substrates are the
/// compute backends — see PLAN-compute-backends).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    #[default]
    Wasm,
    Microvm,
    Container,
}

/// A function's binding/capability config — the `HandlerConfig` capability fields
/// (imports, resource limits, static env) *minus its trigger* (route/methods, which
/// become a [`Trigger`]), plus the [`Runtime`] knob. A `HandlerConfig` *is* a
/// function's config, so the engine has one path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FunctionConfig {
    /// Requested host capabilities (interface names).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
    /// Optional resource limits (mem / timeout / fuel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<HandlerLimits>,
    /// Static, non-secret environment.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Execution substrate (default `wasm`).
    pub runtime: Runtime,
}

impl FunctionConfig {
    fn from_handler(h: &HandlerConfig) -> Self {
        FunctionConfig {
            imports: h.imports.clone(),
            limits: h.limits.clone(),
            env: h.env.clone(),
            runtime: Runtime::default(),
        }
    }
    fn from_consumer(c: &ConsumerConfig) -> Self {
        FunctionConfig {
            imports: c.imports.clone(),
            ..Default::default()
        }
    }
}

/// A reference to a function (a `None` version = the function's active version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionRef {
    /// The function name (site-scoped names are `<site>/<name>`).
    pub name: String,
    /// A specific version id, or `None` for the active version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A **trigger** — a separate object (decision 2). Many triggers may point at the
/// same function version (e.g. a route *and* a cron). A `target` of `None` is a
/// host-native trigger (a stream fan-out has no component).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// What fires the trigger.
    pub kind: TriggerKind,
    /// The function it invokes, or `None` for a host-native trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<FunctionRef>,
}

/// The event that fires a trigger. The role words (route/queue/cron/stream) are the
/// familiar site-view names; each is just *a way to reach a function*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TriggerKind {
    /// An HTTP route — the "handler" shape. `host` scopes it to a virtualhost.
    Route {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        path: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        methods: Vec<String>,
    },
    /// A stable invoke name — `/api/functions/<name>` (the FaaS verb, FA-3).
    Invoke { name: String },
    /// A message topic — the "consumer" shape.
    Queue { topic: String },
    /// A cron schedule — the "cron" shape.
    Cron {
        schedule: String,
        #[serde(default)]
        overlap: Overlap,
    },
    /// An object-storage change under a prefix (FA-5).
    Blob { prefix: String },
    /// A signed inbound webhook (FA-5).
    Webhook { path: String, secret: String },
    /// Host-native SSE / WebSocket topic fan-out — the "stream" shape (no component,
    /// so a stream trigger's `target` is `None`).
    Stream {
        topics: Vec<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        websocket: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        publish_topic: Option<String>,
    },
}

/// A stored, content-addressed function resource (the FA-1/FA-2 keyspace form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    /// The function name (unique within its owner).
    pub name: String,
    /// Who owns it (drives binding prefix + RBAC).
    pub owner: Owner,
    /// Immutable versions, newest last.
    pub versions: Vec<FunctionVersion>,
    /// The active version's id.
    pub active: String,
    /// Named aliases → version id (staging/previews; mirrors deploy aliases).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub aliases: BTreeMap<String, String>,
    /// Binding/capability config.
    pub config: FunctionConfig,
}

impl Function {
    /// A new top-level function with a single active version (the component blob).
    /// The version id **is** the component's content hash (content-addressed).
    pub fn new(
        name: impl Into<String>,
        owner: Owner,
        component_hash: impl Into<String>,
        config: FunctionConfig,
        lifecycle: Lifecycle,
        created: u64,
    ) -> Self {
        let hash = component_hash.into();
        Function {
            name: name.into(),
            owner,
            versions: vec![FunctionVersion {
                id: hash.clone(),
                component: hash.clone(),
                created,
                lifecycle,
            }],
            active: hash,
            aliases: BTreeMap::new(),
            config,
        }
    }

    /// Add a version for `component_hash` (id = the hash) and make it active. If a
    /// version with that hash already exists it is just re-activated (idempotent).
    /// Returns the (active) version id.
    pub fn upsert_version(
        &mut self,
        component_hash: impl Into<String>,
        lifecycle: Lifecycle,
        created: u64,
    ) -> String {
        let hash = component_hash.into();
        if !self.versions.iter().any(|v| v.id == hash) {
            self.versions.push(FunctionVersion {
                id: hash.clone(),
                component: hash.clone(),
                created,
                lifecycle,
            });
        }
        self.active = hash.clone();
        hash
    }

    /// Point `active` at an existing version id. `Err` if the version is unknown.
    pub fn rollback(&mut self, to: &str) -> Result<(), String> {
        if self.versions.iter().any(|v| v.id == to) {
            self.active = to.to_string();
            Ok(())
        } else {
            Err(format!("no version {to:?} in function {:?}", self.name))
        }
    }

    /// Set `label` → an existing version id. `Err` if the version is unknown.
    pub fn set_alias(&mut self, label: &str, version: &str) -> Result<(), String> {
        if self.versions.iter().any(|v| v.id == version) {
            self.aliases.insert(label.to_string(), version.to_string());
            Ok(())
        } else {
            Err(format!(
                "no version {version:?} in function {:?}",
                self.name
            ))
        }
    }
}

/// One immutable version of a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionVersion {
    /// Immutable content-hash id.
    pub id: String,
    /// The component blob hash.
    pub component: String,
    /// Unix creation time.
    pub created: u64,
    /// This version's lifecycle.
    #[serde(default)]
    pub lifecycle: Lifecycle,
}

/// The desugared shape of a function derived from a site's `DeployConfig`. The
/// `component` is still a **path** within the deploy — its content hash / version
/// id is assigned at `sync`, when the blob is uploaded (so this stays a pure
/// config→shape transform, testable without a blob store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSpec {
    /// Site-scoped function name (see [`handler_name`] / [`consumer_name`]).
    pub name: String,
    /// The component path within the deploy.
    pub component: String,
    /// Binding/capability config.
    pub config: FunctionConfig,
    /// Version lifecycle (deploy-scoped functions are `DeployPinned`).
    pub lifecycle: Lifecycle,
}

/// KV keyspace for a function (mirrors the deploy/alias immutability model).
pub mod keys {
    /// Function metadata.
    pub fn meta(name: &str) -> String {
        format!("functions/{name}")
    }
    /// An immutable version.
    pub fn version(name: &str, id: &str) -> String {
        format!("functions/{name}/versions/{id}")
    }
    /// A named alias → version id.
    pub fn alias(name: &str, label: &str) -> String {
        format!("functions/{name}/alias/{label}")
    }
    /// A trigger bound to the function.
    pub fn trigger(name: &str, id: &str) -> String {
        format!("functions/{name}/triggers/{id}")
    }
}

/// The site-scoped function name for an HTTP route handler — a slug of the route
/// (`/api/hello` → `api-hello`, `/` → `root`).
pub fn handler_name(route: &str) -> String {
    let s = slug(route);
    if s.is_empty() {
        "root".to_string()
    } else {
        s
    }
}

/// The site-scoped function name for a topic consumer (`orders` → `consumer-orders`).
pub fn consumer_name(topic: &str) -> String {
    format!("consumer-{}", slug(topic))
}

/// Lower-case alphanumeric slug, non-alnum runs collapsed to single `-`, trimmed.
fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !out.is_empty() && !dash {
            out.push('-');
            dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Lower a site's deploy-scoped compute config into **functions + triggers**
/// (decision 2), preserving behaviour exactly (the non-breaking gate):
///
/// - each `handler` → a `DeployPinned` [`FunctionSpec`] + a `Route` [`Trigger`];
/// - each `consumer` → a [`FunctionSpec`] + a `Queue` trigger;
/// - each `cron` → a `Cron` trigger onto the **function serving its route** (a
///   second trigger on one function — N triggers → one function);
/// - each `stream` → a host-native `Stream` trigger (`target: None`, no component).
///
/// Pure: no I/O, no hashing. The site handler surface (`routing.handlers`) is
/// unchanged — this is the internal lowering that FA-1..FA-3 build on.
pub fn desugar(cfg: &DeployConfig) -> (Vec<FunctionSpec>, Vec<Trigger>) {
    let mut functions = Vec::new();
    let mut triggers = Vec::new();

    for h in &cfg.handlers {
        let name = handler_name(&h.route);
        functions.push(FunctionSpec {
            name: name.clone(),
            component: h.component.clone(),
            config: FunctionConfig::from_handler(h),
            lifecycle: Lifecycle::DeployPinned,
        });
        triggers.push(Trigger {
            kind: TriggerKind::Route {
                host: None,
                path: h.route.clone(),
                methods: h.methods.clone(),
            },
            target: Some(FunctionRef {
                name,
                version: None,
            }),
        });
    }

    for c in &cfg.consumers {
        let name = consumer_name(&c.topic);
        functions.push(FunctionSpec {
            name: name.clone(),
            component: c.component.clone(),
            config: FunctionConfig::from_consumer(c),
            lifecycle: Lifecycle::DeployPinned,
        });
        triggers.push(Trigger {
            kind: TriggerKind::Queue {
                topic: c.topic.clone(),
            },
            target: Some(FunctionRef {
                name,
                version: None,
            }),
        });
    }

    for cr in &cfg.crons {
        // A cron fires an existing handler-function, addressed by its route.
        let target = cfg
            .handlers
            .iter()
            .find(|h| h.route == cr.route)
            .map(|h| FunctionRef {
                name: handler_name(&h.route),
                version: None,
            });
        triggers.push(Trigger {
            kind: TriggerKind::Cron {
                schedule: cr.schedule.clone(),
                overlap: cr.overlap,
            },
            target,
        });
    }

    for s in &cfg.streams {
        triggers.push(Trigger {
            kind: TriggerKind::Stream {
                topics: s.topics.clone(),
                websocket: s.websocket,
                publish_topic: s.publish_topic.clone(),
            },
            target: None,
        });
    }

    (functions, triggers)
}

/// Materialize desugared specs into stored [`Function`]s for a site, resolving each
/// component **path** to its blob hash via the deploy's file map (the blob hash is
/// the content-addressed version id). `created` is the deploy's activation time.
/// Specs whose component isn't in the file map are dropped (a validated deploy
/// always has them). This is the derived, read-only view of a site's functions
/// (FA-1); independently-stored top-level functions come with FA-2.
pub fn materialize(
    specs: &[FunctionSpec],
    site: &str,
    files: &BTreeMap<String, FileEntry>,
    created: u64,
) -> Vec<Function> {
    specs
        .iter()
        .filter_map(|s| {
            let hash = files.get(s.component.trim_start_matches('/'))?.hash.clone();
            Some(Function {
                name: s.name.clone(),
                owner: Owner::Site(site.to_string()),
                versions: vec![FunctionVersion {
                    id: hash.clone(),
                    component: hash.clone(),
                    created,
                    lifecycle: s.lifecycle,
                }],
                active: hash,
                aliases: BTreeMap::new(),
                config: s.config.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConsumerConfig, CronConfig, HandlerConfig, StreamConfig};

    fn handler(route: &str, component: &str, methods: &[&str], imports: &[&str]) -> HandlerConfig {
        HandlerConfig {
            route: route.into(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            component: component.into(),
            imports: imports.iter().map(|s| s.to_string()).collect(),
            limits: None,
            env: BTreeMap::new(),
        }
    }

    #[test]
    fn slugs_and_names() {
        assert_eq!(handler_name("/api/hello"), "api-hello");
        assert_eq!(handler_name("/"), "root");
        assert_eq!(handler_name("/a/b/*"), "a-b");
        assert_eq!(consumer_name("orders.new"), "consumer-orders-new");
    }

    /// The mandatory **non-breaking gate**: desugaring preserves every handler,
    /// consumer, cron, and stream's fields exactly — the same component, imports,
    /// routes/methods, topics, and the cron→handler binding.
    #[test]
    fn desugar_preserves_all_compute_config() {
        let cfg = DeployConfig {
            handlers: vec![
                handler("/api/hello", "hello.wasm", &["GET"], &["kv"]),
                handler("/api/report", "report.wasm", &[], &[]),
            ],
            consumers: vec![ConsumerConfig {
                topic: "orders".into(),
                component: "orders.wasm".into(),
                imports: vec!["sql".into()],
            }],
            crons: vec![CronConfig {
                schedule: "0 * * * *".into(),
                route: "/api/report".into(),
                overlap: Overlap::Skip,
            }],
            streams: vec![StreamConfig {
                route: "/live".into(),
                topics: vec!["ticks".into()],
                websocket: false,
                publish_topic: None,
            }],
            ..Default::default()
        };

        let (functions, triggers) = desugar(&cfg);

        // Two handlers + one consumer → three functions.
        assert_eq!(functions.len(), 3);
        let hello = functions.iter().find(|f| f.name == "api-hello").unwrap();
        assert_eq!(hello.component, "hello.wasm");
        assert_eq!(hello.config.imports, vec!["kv".to_string()]);
        assert_eq!(hello.lifecycle, Lifecycle::DeployPinned);
        assert_eq!(hello.config.runtime, Runtime::Wasm);
        let consumer = functions
            .iter()
            .find(|f| f.name == "consumer-orders")
            .unwrap();
        assert_eq!(consumer.component, "orders.wasm");
        assert_eq!(consumer.config.imports, vec!["sql".to_string()]);

        // Triggers: 2 routes + 1 queue + 1 cron + 1 stream = 5.
        assert_eq!(triggers.len(), 5);

        // The route trigger carries the exact path + methods and targets its function.
        let route = triggers
            .iter()
            .find(|t| matches!(&t.kind, TriggerKind::Route { path, .. } if path == "/api/hello"))
            .unwrap();
        match &route.kind {
            TriggerKind::Route { methods, host, .. } => {
                assert_eq!(methods, &["GET".to_string()]);
                assert!(host.is_none());
            }
            _ => unreachable!(),
        }
        assert_eq!(route.target.as_ref().unwrap().name, "api-hello");

        // The queue trigger.
        let queue = triggers
            .iter()
            .find(|t| matches!(&t.kind, TriggerKind::Queue { topic } if topic == "orders"))
            .unwrap();
        assert_eq!(queue.target.as_ref().unwrap().name, "consumer-orders");

        // The cron is a SECOND trigger on the /api/report function (N triggers → 1 fn).
        let cron = triggers
            .iter()
            .find(|t| matches!(&t.kind, TriggerKind::Cron { .. }))
            .unwrap();
        assert_eq!(cron.target.as_ref().unwrap().name, "api-report");

        // The stream is host-native: a trigger with no function target.
        let stream = triggers
            .iter()
            .find(|t| matches!(&t.kind, TriggerKind::Stream { .. }))
            .unwrap();
        assert!(stream.target.is_none());
        match &stream.kind {
            TriggerKind::Stream { topics, .. } => assert_eq!(topics, &["ticks".to_string()]),
            _ => unreachable!(),
        }
    }

    #[test]
    fn materialize_resolves_paths_to_blob_hashes() {
        let cfg = DeployConfig {
            handlers: vec![handler("/api/hello", "hello.wasm", &["GET"], &[])],
            ..Default::default()
        };
        let (specs, _) = desugar(&cfg);
        let files = BTreeMap::from([(
            "hello.wasm".to_string(),
            FileEntry {
                hash: "sha256:abc".into(),
                size: 10,
                content_type: None,
                variants: BTreeMap::new(),
            },
        )]);
        let funcs = materialize(&specs, "blog", &files, 1_800_000_000);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "api-hello");
        assert_eq!(funcs[0].owner, Owner::Site("blog".into()));
        assert_eq!(funcs[0].active, "sha256:abc");
        assert_eq!(funcs[0].versions[0].component, "sha256:abc");
        assert_eq!(funcs[0].versions[0].created, 1_800_000_000);
        // A spec whose component blob is absent is dropped (no phantom function).
        assert!(materialize(&specs, "blog", &BTreeMap::new(), 0).is_empty());
    }

    #[test]
    fn empty_config_desugars_to_nothing() {
        let (functions, triggers) = desugar(&DeployConfig::default());
        assert!(functions.is_empty() && triggers.is_empty());
    }

    #[test]
    fn model_serde_round_trips() {
        let f = Function {
            name: "resize".into(),
            owner: Owner::Project("acme".into()),
            versions: vec![FunctionVersion {
                id: "v1abc".into(),
                component: "blob:deadbeef".into(),
                created: 1_800_000_000,
                lifecycle: Lifecycle::Independent,
            }],
            active: "v1abc".into(),
            aliases: BTreeMap::from([("prod".into(), "v1abc".into())]),
            config: FunctionConfig {
                imports: vec!["blobstore".into()],
                runtime: Runtime::Microvm,
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<Function>(&json).unwrap(), f);

        // A trigger with a data-carrying kind + host-native (no target) both round-trip.
        for t in [
            Trigger {
                kind: TriggerKind::Route {
                    host: Some("example.com".into()),
                    path: "/x".into(),
                    methods: vec!["POST".into()],
                },
                target: Some(FunctionRef {
                    name: "resize".into(),
                    version: None,
                }),
            },
            Trigger {
                kind: TriggerKind::Stream {
                    topics: vec!["t".into()],
                    websocket: true,
                    publish_topic: Some("up".into()),
                },
                target: None,
            },
        ] {
            let j = serde_json::to_string(&t).unwrap();
            assert_eq!(serde_json::from_str::<Trigger>(&j).unwrap(), t);
        }
    }

    #[test]
    fn versioning_alias_and_rollback() {
        let mut f = Function::new(
            "resize",
            Owner::Project("acme".into()),
            "hashA",
            FunctionConfig::default(),
            Lifecycle::Independent,
            1,
        );
        assert_eq!(f.active, "hashA");
        assert_eq!(f.versions.len(), 1);

        // A new component → a new active version.
        f.upsert_version("hashB", Lifecycle::Independent, 2);
        assert_eq!(f.active, "hashB");
        assert_eq!(f.versions.len(), 2);
        // Re-deploying the same hash is idempotent (re-activates, no dup version).
        f.upsert_version("hashA", Lifecycle::Independent, 3);
        assert_eq!(f.active, "hashA");
        assert_eq!(f.versions.len(), 2);

        // Alias to a known version; unknown is rejected.
        f.set_alias("prod", "hashB").unwrap();
        assert_eq!(f.aliases.get("prod").map(String::as_str), Some("hashB"));
        assert!(f.set_alias("prod", "ghost").is_err());

        // Rollback to a known version; unknown is rejected.
        f.rollback("hashB").unwrap();
        assert_eq!(f.active, "hashB");
        assert!(f.rollback("ghost").is_err());
    }

    #[test]
    fn keyspace_is_stable() {
        assert_eq!(keys::meta("resize"), "functions/resize");
        assert_eq!(
            keys::version("resize", "v1"),
            "functions/resize/versions/v1"
        );
        assert_eq!(keys::alias("resize", "prod"), "functions/resize/alias/prod");
        assert_eq!(
            keys::trigger("resize", "t1"),
            "functions/resize/triggers/t1"
        );
    }
}
