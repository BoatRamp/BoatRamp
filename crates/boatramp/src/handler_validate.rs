//! Sync-time validation of WebAssembly handler/consumer component blobs.
//! Behind the `handlers` feature.
//!
//! For each declared handler/consumer, the component is decoded with
//! `wit-component` and checked: it is a parseable component, it exports the
//! role's required interface (`wasi:http/incoming-handler` for handlers,
//! `boatramp:handlers/messaging-handler` for consumers), and every interface it
//! imports is either a foundational baseline, or a capability the deploy config
//! declared — anything else (e.g. `wasi:filesystem`) is rejected. This fails at
//! `sync`, not at first request.
//!
//! Without the `handlers` feature, [`validate_deploy`] is a no-op: components
//! upload as opaque blobs and are validated server-side when the engine lands.

use std::path::Path;

use boatramp_core::config::DeployConfig;

/// A failure validating handler/consumer component blobs at sync time. The
/// variants only exist with the `handlers` feature (the no-op build never fails).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading a declared component `.wasm` from disk failed.
    #[cfg(feature = "handlers")]
    #[error("reading component {path}: {source}")]
    ReadComponent {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A component failed its import/export policy check.
    #[cfg(feature = "handlers")]
    #[error("{path}: {message}")]
    Validate { path: String, message: String },
}

/// `handler_validate` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// No-op validation when built without the `handlers` feature.
#[cfg(not(feature = "handlers"))]
pub fn validate_deploy(_dir: &Path, _config: &DeployConfig) -> Result<()> {
    Ok(())
}

#[cfg(feature = "handlers")]
pub use imp::{host_capabilities, validate_deploy, HostCapabilities};

/// The capability surface a host advertises (`boatramp capabilities` /
/// `/api/capabilities`): the `boatramp:handlers` package version it implements and
/// the import tokens a deploy may grant.
#[cfg(not(feature = "handlers"))]
#[derive(Debug, serde::Serialize)]
pub struct HostCapabilities {
    pub package: &'static str,
    pub version: String,
    pub declarable_imports: Vec<&'static str>,
}

/// Without the `handlers` feature the host implements no handler capabilities.
#[cfg(not(feature = "handlers"))]
pub fn host_capabilities() -> HostCapabilities {
    HostCapabilities {
        package: "boatramp:handlers",
        version: "0.0.0".to_string(),
        declarable_imports: Vec::new(),
    }
}

#[cfg(feature = "handlers")]
mod imp {
    use super::*;
    use wit_component::{decode, DecodedWasm};
    use wit_parser::{Resolve, WorldId, WorldItem};

    /// `(package "ns:name", interface name)` interface labels.
    type Labels = Vec<(String, String)>;

    /// The interface a component must export for its role.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Role {
        Handler,
        Consumer,
    }

    impl Role {
        fn required_export(self) -> (&'static str, &'static str) {
            match self {
                Self::Handler => ("wasi:http", "incoming-handler"),
                // Consumers export boatramp's message-delivery interface, which the
                // engine's dispatcher calls per delivery — see boatramp-handlers
                // `world consumer` (`boatramp:handlers/messaging-handler`).
                Self::Consumer => ("boatramp:handlers", "messaging-handler"),
            }
        }
    }

    /// Foundational interface packages a handler may import without declaring
    /// them (ABI/runtime essentials). `wasi:http` is here because every http
    /// handler imports its types; outbound-http egress is gated at runtime.
    const BASELINE_PKGS: &[&str] = &[
        "wasi:io",
        "wasi:clocks",
        "wasi:random",
        "wasi:cli",
        "wasi:logging",
        "wasi:http",
    ];

    /// The capability an imported `(package, interface)` belongs to, or `None`
    /// when the interface is not a grantable capability (and so is refused).
    ///
    /// This table is the contract, and it is deliberately keyed on the exact
    /// interfaces the handler engine adds to its linker (boatramp-handlers
    /// `build_linker`), so the sync validator and the runtime host cannot drift.
    /// The returned token is what a deploy lists in `imports` (docs
    /// `functions.md`). `wasi:keyvalue`/`wasi:blobstore` are the standard WASI
    /// interfaces; `sql` and messaging are boatramp's own `boatramp:handlers`
    /// interfaces (there is no ratified `wasi:sql`, and the messaging interface
    /// predates a stable `wasi:messaging`), matched by interface here — not by a
    /// package-name shape.
    fn capability_token(pkg: &str, iface: &str) -> Option<&'static str> {
        match (pkg, iface) {
            ("wasi:keyvalue", _) => Some("wasi:keyvalue"),
            ("wasi:blobstore", _) => Some("wasi:blobstore"),
            // `orm` is a **typed view of the same `sql` capability** — it runs on the
            // same per-invocation SQL session/backend and `use`s `sql-types`. So it
            // is the `sql` token: declaring `sql` grants orm (and inherits the
            // "requires a SQL backend" activation check). Before this it mapped to
            // None → "disallowed", so an orm-importing guest was rejected at deploy.
            ("boatramp:handlers", "sql-query" | "sql-types" | "orm") => Some("sql"),
            ("boatramp:handlers", "messaging-producer" | "messaging-types") => {
                Some("wasi:messaging")
            }
            ("boatramp:handlers", "invoke" | "invoke-types") => Some("invoke"),
            // GraphQL is a distinct capability (federated subgraph access over the
            // project's composed supergraph). Always linked, so it is gated only by
            // declaration (there is no server-level backend to reject against).
            ("boatramp:handlers", "graphql" | "graphql-types") => Some("graphql"),
            _ => None,
        }
    }

    /// An **informational** capability-surface revision reported by `boatramp
    /// capabilities` / `GET /api/capabilities` — NOT a linkable WIT package version
    /// (the `boatramp:handlers` package is deliberately unversioned) and NOT
    /// enforced. Host↔guest capability *availability* is decided by the guest's
    /// function-manifest `requires`, checked at deploy — see
    /// `PLAN-capability-contract-versioning-v2`. Bump when the capability surface
    /// changes so operators can see it; it links nothing.
    const HOST_HANDLERS_VERSION: (u64, u64, u64) = (0, 2, 0);

    /// The capability surface a host advertises (see the crate-level re-export).
    #[derive(Debug, serde::Serialize)]
    pub struct HostCapabilities {
        pub package: &'static str,
        pub version: String,
        pub declarable_imports: Vec<&'static str>,
    }

    /// What this host implements: the `boatramp:handlers` package version + the
    /// import tokens a deploy may grant.
    pub fn host_capabilities() -> HostCapabilities {
        let (m, n, p) = HOST_HANDLERS_VERSION;
        HostCapabilities {
            package: "boatramp:handlers",
            version: format!("{m}.{n}.{p}"),
            declarable_imports: boatramp_core::config::known_imports().to_vec(),
        }
    }

    /// Apply the import/export policy to a component's interface labels. Pure —
    /// the security-relevant decision lives here and is exhaustively tested.
    fn check_interface_policy(
        imports: &[(String, String)],
        exports: &[(String, String)],
        declared: &[String],
        role: Role,
    ) -> std::result::Result<(), String> {
        let (req_pkg, req_iface) = role.required_export();
        if !exports.iter().any(|(p, i)| p == req_pkg && i == req_iface) {
            return Err(format!("component does not export {req_pkg}/{req_iface}"));
        }

        for (pkg, iface) in imports {
            // Foundational interfaces need no declaration.
            if BASELINE_PKGS.contains(&pkg.as_str()) {
                continue;
            }
            // A grantable capability is allowed only if the deploy declared its
            // token. Anything that maps to no capability (wasi:filesystem,
            // wasi:sockets, an unknown boatramp:handlers interface, ...) is
            // refused even when it appears in `imports`.
            match capability_token(pkg, iface) {
                // The bare token (`sql`), or a **named** grant of the same capability
                // (`sql:product`, `sql:*`) — a component imports the single `sql` interface and
                // selects the database by name at runtime, so any `sql:*`/`sql:<name>` grant
                // satisfies its `sql` import.
                Some(token)
                    if declared.iter().any(|d| {
                        d == token || d.strip_prefix(token).is_some_and(|r| r.starts_with(':'))
                    }) =>
                {
                    continue
                }
                Some(token) => {
                    return Err(format!(
                        "component imports {pkg}/{iface} (the `{token}` capability) but the \
                         deploy does not declare it. Imports are component-scoped: every route \
                         binding this component must grant `{token}`, even routes that don't use it"
                    ))
                }
                None => {
                    return Err(format!(
                        "component imports disallowed interface {pkg}/{iface}"
                    ))
                }
            }
        }
        Ok(())
    }

    /// Decode a component's imported/exported interface labels as
    /// `(package "ns:name", interface name)` pairs.
    fn decode_interfaces(bytes: &[u8]) -> std::result::Result<(Labels, Labels), String> {
        let decoded = decode(bytes).map_err(|err| format!("not a valid component: {err}"))?;
        let (resolve, world) = match &decoded {
            DecodedWasm::Component(resolve, world) => (resolve, *world),
            DecodedWasm::WitPackage(..) => {
                return Err("file is a WIT package, not a component".to_string())
            }
        };
        Ok((
            interfaces(resolve, world, false),
            interfaces(resolve, world, true),
        ))
    }

    fn interfaces(resolve: &Resolve, world: WorldId, exports: bool) -> Labels {
        let world = &resolve.worlds[world];
        let items = if exports {
            &world.exports
        } else {
            &world.imports
        };
        items
            .iter()
            .filter_map(|(_, item)| match item {
                WorldItem::Interface { id, .. } => {
                    let iface = &resolve.interfaces[*id];
                    let pkg = &resolve.packages[iface.package?].name;
                    Some((
                        format!("{}:{}", pkg.namespace, pkg.name),
                        iface.name.clone()?,
                    ))
                }
                _ => None,
            })
            .collect()
    }

    /// Validate one component's bytes against its declared imports and role.
    pub fn validate_component(
        bytes: &[u8],
        declared: &[String],
        role: Role,
    ) -> std::result::Result<(), String> {
        let (imports, exports) = decode_interfaces(bytes)?;
        check_interface_policy(&imports, &exports, declared, role)
    }

    /// Validate every declared handler/consumer component in `config`, reading
    /// each `.wasm` relative to the deploy `dir`.
    pub fn validate_deploy(dir: &Path, config: &DeployConfig) -> Result<()> {
        for handler in &config.handlers {
            // Name the offending handler (route + methods), not just the component
            // file: one component may bind several routes, and each declares its own
            // imports, so the error must point at *which* route is under-granted.
            let label = format!("route {:?} [{}]", handler.route, handler.methods.join(","));
            check(
                dir,
                &handler.component,
                &handler.imports,
                Role::Handler,
                &label,
            )?;
        }
        for consumer in &config.consumers {
            let label = format!("consumer ({})", consumer.component);
            check(
                dir,
                &consumer.component,
                &consumer.imports,
                Role::Consumer,
                &label,
            )?;
        }
        let total = config.handlers.len() + config.consumers.len();
        if total > 0 {
            println!("validated {total} handler component(s)");
        }
        Ok(())
    }

    fn check(
        dir: &Path,
        component: &str,
        imports: &[String],
        role: Role,
        label: &str,
    ) -> Result<()> {
        let path = dir.join(component);
        let bytes = std::fs::read(&path).map_err(|err| Error::ReadComponent {
            path: path.display().to_string(),
            source: err,
        })?;
        validate_component(&bytes, imports, role).map_err(|err| Error::Validate {
            path: path.display().to_string(),
            message: format!("{label}: {err}"),
        })?;
        Ok(())
    }

    /// Build a real component from inline WIT, for tests (no guest toolchain).
    #[cfg(test)]
    fn build_fixture(wit: &str, world: &str) -> Vec<u8> {
        let mut resolve = Resolve::new();
        let pkg = resolve.push_source("fixture.wit", wit).unwrap();
        let world = resolve.select_world(&[pkg], Some(world)).unwrap();
        let mut module =
            wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
        wit_component::embed_component_metadata(
            &mut module,
            &resolve,
            world,
            wit_component::StringEncoding::UTF8,
        )
        .unwrap();
        wit_component::ComponentEncoder::default()
            .module(&module)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn lbl(pkg: &str, iface: &str) -> (String, String) {
            (pkg.to_string(), iface.to_string())
        }

        #[test]
        fn policy_requires_role_export() {
            let exports = [lbl("wasi:http", "incoming-handler")];
            assert!(check_interface_policy(&[], &exports, &[], Role::Handler).is_ok());
            assert!(check_interface_policy(&[], &exports, &[], Role::Consumer).is_err());
        }

        #[test]
        fn policy_gates_capability_imports() {
            let exports = [lbl("wasi:http", "incoming-handler")];
            let imports = [lbl("wasi:io", "streams"), lbl("wasi:keyvalue", "store")];
            assert!(check_interface_policy(
                &imports,
                &exports,
                &["wasi:keyvalue".into()],
                Role::Handler
            )
            .is_ok());
            assert!(check_interface_policy(&imports, &exports, &[], Role::Handler).is_err());
        }

        #[test]
        fn policy_rejects_unknown_allows_baseline() {
            let exports = [lbl("wasi:http", "incoming-handler")];
            // An unknown interface is refused even when named in `imports`:
            // declaring does not whitelist arbitrary packages.
            let fs = [lbl("wasi:filesystem", "types")];
            assert!(check_interface_policy(
                &fs,
                &exports,
                &["wasi:filesystem".into()],
                Role::Handler
            )
            .is_err());
            // A foundational interface needs no declaration.
            let base = [lbl("wasi:clocks", "monotonic-clock")];
            assert!(check_interface_policy(&base, &exports, &[], Role::Handler).is_ok());
        }

        #[test]
        fn policy_gates_sql_by_the_real_interface() {
            // The host provides SQL as boatramp:handlers/{sql-query,sql-types}
            // (boatramp-handlers world.wit + build_linker), declared as `sql`.
            let exports = [lbl("wasi:http", "incoming-handler")];
            let sql = [
                lbl("boatramp:handlers", "sql-query"),
                lbl("boatramp:handlers", "sql-types"),
            ];
            assert!(check_interface_policy(&sql, &exports, &["sql".into()], Role::Handler).is_ok());
            // A **named** grant satisfies the single `sql` import too — a component imports one
            // `sql` interface and selects the database by name at runtime.
            assert!(
                check_interface_policy(&sql, &exports, &["sql:product".into()], Role::Handler)
                    .is_ok()
            );
            assert!(
                check_interface_policy(&sql, &exports, &["sql:*".into()], Role::Handler).is_ok()
            );
            // Undeclared → rejected, and the message names the capability token.
            let err = check_interface_policy(&sql, &exports, &[], Role::Handler).unwrap_err();
            assert!(err.contains("`sql`"), "{err}");
            // A package that merely *looks* like sql is not a capability — the old
            // `ends_with(":sql")` shortcut is gone.
            let fake = [lbl("acme:sql", "readwrite")];
            assert!(
                check_interface_policy(&fake, &exports, &["sql".into()], Role::Handler).is_err()
            );
        }

        #[test]
        fn policy_gates_invoke_by_the_real_interface() {
            // The host provides function-to-function invoke as
            // boatramp:handlers/{invoke,invoke-types}, declared as `invoke`.
            let exports = [lbl("wasi:http", "incoming-handler")];
            let invoke = [
                lbl("boatramp:handlers", "invoke"),
                lbl("boatramp:handlers", "invoke-types"),
            ];
            assert!(
                check_interface_policy(&invoke, &exports, &["invoke".into()], Role::Handler)
                    .is_ok()
            );
            let err = check_interface_policy(&invoke, &exports, &[], Role::Handler).unwrap_err();
            assert!(err.contains("`invoke`"), "{err}");
        }

        #[test]
        fn policy_gates_orm_as_the_sql_capability() {
            // orm imports boatramp:handlers/orm and (via `use`) sql-types; it is the
            // `sql` capability, so declaring `sql` satisfies it and nothing extra is
            // needed. Before, `orm` mapped to no token and was rejected as disallowed.
            let exports = [lbl("wasi:http", "incoming-handler")];
            let orm = [
                lbl("boatramp:handlers", "orm"),
                lbl("boatramp:handlers", "sql-types"),
            ];
            assert!(check_interface_policy(&orm, &exports, &["sql".into()], Role::Handler).is_ok());
            assert!(
                check_interface_policy(&orm, &exports, &["sql:*".into()], Role::Handler).is_ok()
            );
            let err = check_interface_policy(&orm, &exports, &[], Role::Handler).unwrap_err();
            assert!(err.contains("`sql`"), "{err}");
        }

        #[test]
        fn policy_gates_graphql_by_the_real_interface() {
            // GraphQL is its own capability (host: boatramp:handlers/{graphql,
            // graphql-types}), declared as `graphql`.
            let exports = [lbl("wasi:http", "incoming-handler")];
            let gql = [
                lbl("boatramp:handlers", "graphql"),
                lbl("boatramp:handlers", "graphql-types"),
            ];
            assert!(
                check_interface_policy(&gql, &exports, &["graphql".into()], Role::Handler).is_ok()
            );
            let err = check_interface_policy(&gql, &exports, &[], Role::Handler).unwrap_err();
            assert!(err.contains("`graphql`"), "{err}");
        }

        #[test]
        fn policy_gates_messaging_producer_and_consumer_export() {
            // A request handler may import the messaging producer under a
            // `wasi:messaging` grant (the host interface is boatramp:handlers/*).
            let http_export = [lbl("wasi:http", "incoming-handler")];
            let producer = [lbl("boatramp:handlers", "messaging-producer")];
            assert!(check_interface_policy(
                &producer,
                &http_export,
                &["wasi:messaging".into()],
                Role::Handler
            )
            .is_ok());
            assert!(check_interface_policy(&producer, &http_export, &[], Role::Handler).is_err());

            // A consumer must export boatramp:handlers/messaging-handler; a plain
            // http export does not satisfy the consumer role.
            let handler_export = [lbl("boatramp:handlers", "messaging-handler")];
            assert!(check_interface_policy(&[], &handler_export, &[], Role::Consumer).is_ok());
            assert!(check_interface_policy(&[], &http_export, &[], Role::Consumer).is_err());
        }

        #[test]
        fn decodes_real_component_and_runs_export_check() {
            // A real, self-generated component exporting test:guest/incoming-handler.
            let wit = "package test:guest;\n\
                       interface incoming-handler { handle: func(); }\n\
                       world h { export incoming-handler; }";
            let bytes = build_fixture(wit, "h");
            // Decode + extraction succeed; the export check runs on real decoded
            // data — it exports test:guest, not wasi:http, so Handler is rejected.
            let err = validate_component(&bytes, &[], Role::Handler).unwrap_err();
            assert!(err.contains("wasi:http/incoming-handler"), "{err}");
            // Garbage bytes are rejected as an invalid component.
            assert!(validate_component(b"not a wasm component", &[], Role::Handler).is_err());
        }

        #[test]
        fn undeclared_capability_message_states_the_component_scoped_rule() {
            // The rejection must state the component-scoped rule inline, so a dev
            // isn't confused why a route that never uses the capability still needs
            // to grant it.
            let exports = [lbl("wasi:http", "incoming-handler")];
            let sql = [
                lbl("boatramp:handlers", "sql-query"),
                lbl("boatramp:handlers", "sql-types"),
            ];
            let err = check_interface_policy(&sql, &exports, &[], Role::Handler).unwrap_err();
            assert!(err.contains("component-scoped"), "{err}");
            assert!(err.contains("`sql`"), "{err}");
        }

        #[test]
        fn validate_deploy_names_the_offending_route_not_just_the_component() {
            use boatramp_core::config::{DeployConfig, HandlerConfig};
            use std::collections::BTreeMap;

            // A real component that fails validation (exports test:guest, not
            // wasi:http). The failure reason is immaterial here — what matters is
            // that the *route + methods* prefix the message (the §5 label), so with
            // one component on several routes the dev sees which one is at fault.
            let wit = "package test:guest;\n\
                       interface incoming-handler { handle: func(); }\n\
                       world h { export incoming-handler; }";
            let bytes = build_fixture(wit, "h");

            let dir = std::env::temp_dir().join(format!("br-validate-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("portal.wasm"), &bytes).unwrap();

            let config = DeployConfig {
                handlers: vec![HandlerConfig {
                    route: "/intake/status".into(),
                    methods: vec!["GET".into()],
                    component: "portal.wasm".into(),
                    imports: vec![],
                    streaming: false,
                    limits: None,
                    env: BTreeMap::new(),
                    invoke_targets: vec![],
                }],
                ..Default::default()
            };

            let err = validate_deploy(&dir, &config).unwrap_err().to_string();
            let _ = std::fs::remove_dir_all(&dir);
            assert!(err.contains("/intake/status"), "{err}");
            assert!(err.contains("GET"), "{err}");
        }
    }
}
