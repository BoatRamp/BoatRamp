//! Sync-time validation of WebAssembly handler/consumer component blobs.
//! Behind the `handlers` feature.
//!
//! For each declared handler/consumer, the component is decoded with
//! `wit-component` and checked: it is a parseable component, it exports the
//! role's required interface (`wasi:http/incoming-handler` for handlers,
//! `wasi:messaging/incoming-handler` for consumers), and every interface it
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
pub use imp::validate_deploy;

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
                Role::Handler => ("wasi:http", "incoming-handler"),
                Role::Consumer => ("wasi:messaging", "incoming-handler"),
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

    /// Capability packages that MUST appear in the handler's declared `imports`.
    const CAP_PKGS: &[&str] = &["wasi:keyvalue", "wasi:blobstore", "wasi:messaging"];

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

        let declares = |pkg: &str| {
            declared
                .iter()
                .any(|d| d == pkg || (d == "sql" && pkg.ends_with(":sql")))
        };
        for (pkg, iface) in imports {
            // Foundational interfaces need no declaration.
            if BASELINE_PKGS.contains(&pkg.as_str()) {
                continue;
            }
            // A grantable capability (kv/blob/messaging/sql) is allowed only if
            // declared. Declaration does NOT whitelist arbitrary packages — an
            // unknown interface (e.g. wasi:filesystem, wasi:sockets) is always
            // refused, even if listed in `imports`.
            let is_capability = CAP_PKGS.contains(&pkg.as_str()) || pkg.ends_with(":sql");
            if is_capability {
                if declares(pkg) {
                    continue;
                }
                return Err(format!(
                    "component imports {pkg}/{iface} but does not declare it"
                ));
            }
            return Err(format!(
                "component imports disallowed interface {pkg}/{iface}"
            ));
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
            check(dir, &handler.component, &handler.imports, Role::Handler)?;
        }
        for consumer in &config.consumers {
            check(dir, &consumer.component, &consumer.imports, Role::Consumer)?;
        }
        let total = config.handlers.len() + config.consumers.len();
        if total > 0 {
            println!("validated {total} handler component(s)");
        }
        Ok(())
    }

    fn check(dir: &Path, component: &str, imports: &[String], role: Role) -> Result<()> {
        let path = dir.join(component);
        let bytes = std::fs::read(&path).map_err(|err| Error::ReadComponent {
            path: path.display().to_string(),
            source: err,
        })?;
        validate_component(&bytes, imports, role).map_err(|err| Error::Validate {
            path: path.display().to_string(),
            message: err,
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
        fn policy_rejects_unknown_allows_sql_and_baseline() {
            let exports = [lbl("wasi:http", "incoming-handler")];
            let fs = [lbl("wasi:filesystem", "types")];
            assert!(check_interface_policy(
                &fs,
                &exports,
                &["wasi:filesystem".into()],
                Role::Handler
            )
            .is_err());
            let sql = [lbl("wasi:sql", "readwrite")];
            assert!(check_interface_policy(&sql, &exports, &["sql".into()], Role::Handler).is_ok());
            let base = [lbl("wasi:clocks", "monotonic-clock")];
            assert!(check_interface_policy(&base, &exports, &[], Role::Handler).is_ok());
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
    }
}
