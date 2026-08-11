//! The `compose` subcommand: fuse several WebAssembly components into one linked
//! component.
//!
//! A composed handler lets you author resolvers or middleware as separate,
//! WIT-typed components and link them **in-process** — no network hop, checked at
//! compile time — then deploy the single fused `.wasm` through the normal
//! content-addressed path. The fused component's exports are unchanged (still
//! e.g. `wasi:http/incoming-handler`); only the imports a plugin provides are
//! satisfied internally, while host imports (`wasi:http`, `sql`, `kv`, …) stay
//! imported for the runtime to supply.
//!
//! Composition runs in-process via `wac-graph` (the library behind the `wac`
//! tool), so it needs no external toolchain and never runs on the serving node —
//! it is a build step that emits one component.

use std::path::{Path, PathBuf};

use wac_graph::types::Package;
use wac_graph::{CompositionGraph, EncodeOptions};

/// A failure running `boatramp compose`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A referenced component file does not exist.
    #[error("component not found: {0}")]
    Missing(PathBuf),
    /// Reading a component file failed.
    #[error("reading {0}: {1}")]
    Read(PathBuf, #[source] std::io::Error),
    /// Writing the fused component failed.
    #[error("writing {0}: {1}")]
    Write(PathBuf, #[source] std::io::Error),
    /// The components could not be composed (a malformed component, or an
    /// import a plugin was expected to satisfy did not match).
    #[error("compose failed: {0}")]
    Compose(String),
}

type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp compose`.
#[derive(Debug, clap::Args)]
pub struct ComposeArgs {
    /// The root ("edge") component: it exports the handler world and imports the
    /// interfaces the plugins provide.
    #[arg(long)]
    edge: PathBuf,
    /// A plugin ("leaf") component whose exports satisfy one of the edge's
    /// imports. Repeatable.
    #[arg(long = "plugin", value_name = "COMPONENT")]
    plugins: Vec<PathBuf>,
    /// Where to write the fused component.
    #[arg(short, long)]
    output: PathBuf,
}

/// Fuse `edge` with `plugins` (each a name + component bytes) into one component,
/// returning the encoded bytes. Pure over bytes — no I/O — so it is unit-tested
/// against fixture components.
pub(crate) fn compose_components(edge: &[u8], plugins: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut graph = CompositionGraph::new();
    let edge_pkg = Package::from_bytes("root:edge", None, edge.to_vec(), graph.types_mut())
        .map_err(|e| Error::Compose(format!("edge component: {e}")))?;
    let edge_id = graph
        .register_package(edge_pkg)
        .map_err(|e| Error::Compose(format!("register edge: {e}")))?;

    let mut plug_ids = Vec::new();
    for (name, bytes) in plugins {
        let pkg = Package::from_bytes(
            &format!("plugin:{name}"),
            None,
            bytes.clone(),
            graph.types_mut(),
        )
        .map_err(|e| Error::Compose(format!("plugin {name}: {e}")))?;
        plug_ids.push(
            graph
                .register_package(pkg)
                .map_err(|e| Error::Compose(format!("register plugin {name}: {e}")))?,
        );
    }

    // Plug each plugin's exports into the edge's matching imports; the result
    // becomes the fused component's default export.
    wac_graph::plug(&mut graph, plug_ids, edge_id)
        .map_err(|e| Error::Compose(format!("plug: {e}")))?;

    graph
        .encode(EncodeOptions::default())
        .map_err(|e| Error::Compose(format!("encode: {e}")))
}

/// Entry point for `boatramp compose`.
pub fn run(args: ComposeArgs) -> Result<()> {
    let edge = read(&args.edge)?;
    let mut plugins = Vec::with_capacity(args.plugins.len());
    for (i, path) in args.plugins.iter().enumerate() {
        // A plugin's package name only needs to be unique in the graph; derive it
        // from the file stem (falling back to the index) for readable errors.
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.replace(|c: char| !c.is_ascii_alphanumeric(), "-"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("p{i}"));
        plugins.push((name, read(path)?));
    }
    let fused = compose_components(&edge, &plugins)?;
    std::fs::write(&args.output, &fused).map_err(|e| Error::Write(args.output.clone(), e))?;
    println!(
        "composed {} + {} plugin(s) -> {} ({} bytes)",
        args.edge.display(),
        args.plugins.len(),
        args.output.display(),
        fused.len()
    );
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(Error::Missing(path.to_path_buf()));
    }
    std::fs::read(path).map_err(|e| Error::Read(path.to_path_buf(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real components (built from `examples/compose/*` to wasm32-wasip2): the edge
    // imports `boatramp:composedemo/adder` and exports `run`; the plugin exports the
    // interface.
    const EDGE: &[u8] = include_bytes!("../tests/fixtures/compose-edge.wasm");
    const PLUGIN: &[u8] = include_bytes!("../tests/fixtures/compose-plugin.wasm");

    const ADDER: &str = "boatramp:composedemo/adder";

    /// Collect a component's **top-level** import and export names via `wasmparser`.
    /// A composed component *embeds* its inputs as nested sub-components (which still
    /// declare their own imports/exports), so we track nesting depth and only read the
    /// outermost component — the fused component's real, externally-visible interface.
    fn import_export_names(bytes: &[u8]) -> (Vec<String>, Vec<String>) {
        use wasmparser::{Parser, Payload};
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        let mut depth = 0i32;
        for payload in Parser::new(0).parse_all(bytes).flatten() {
            match payload {
                // Entering a nested module/component: its sections are not top-level.
                Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
                Payload::End(_) => depth -= 1,
                Payload::ComponentImportSection(reader) if depth == 0 => {
                    for imp in reader.into_iter().flatten() {
                        imports.push(imp.name.name.to_string());
                    }
                }
                Payload::ComponentExportSection(reader) if depth == 0 => {
                    for exp in reader.into_iter().flatten() {
                        exports.push(exp.name.name.to_string());
                    }
                }
                _ => {}
            }
        }
        (imports, exports)
    }

    #[test]
    fn fixtures_have_the_expected_shape() {
        // Sanity: the edge imports the interface (so composition has something to do)
        // and exports `run`; the plugin exports the interface.
        let (edge_imports, edge_exports) = import_export_names(EDGE);
        assert!(
            edge_imports.iter().any(|i| i.contains(ADDER)),
            "edge should import the adder interface, got {edge_imports:?}"
        );
        assert!(
            edge_exports.iter().any(|e| e == "run"),
            "edge should export run, got {edge_exports:?}"
        );
        let (_, plugin_exports) = import_export_names(PLUGIN);
        assert!(
            plugin_exports.iter().any(|e| e.contains(ADDER)),
            "plugin should export the adder interface, got {plugin_exports:?}"
        );
    }

    #[test]
    fn composing_satisfies_the_edge_import() {
        let fused = compose_components(EDGE, &[("plugin".into(), PLUGIN.to_vec())])
            .expect("composition should succeed");
        // The fused artifact is a valid component (wasmparser accepts it) that still
        // exports `run`, but no longer imports the interface the plugin provided —
        // that is the whole point: the import is satisfied internally, in-process.
        let (imports, exports) = import_export_names(&fused);
        assert!(
            !imports.iter().any(|i| i.contains(ADDER)),
            "the adder import must be satisfied by composition, still imported: {imports:?}"
        );
        assert!(
            exports.iter().any(|e| e == "run"),
            "the fused component must still export run, got {exports:?}"
        );
    }

    #[test]
    fn missing_component_file_is_reported() {
        let err = run(ComposeArgs {
            edge: PathBuf::from("/no/such/edge.wasm"),
            plugins: vec![],
            output: PathBuf::from("/tmp/unused-boatramp-compose.wasm"),
        })
        .unwrap_err();
        assert!(matches!(err, Error::Missing(_)));
    }
}
