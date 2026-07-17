//! `function build` — componentize a scaffolded function project to a WASI
//! component. The language is detected from the project files; each toolchain is
//! run version-pinned as a subprocess.

use super::{FunctionError, Result};

/// The pinned `componentize-py` version `function build` runs via `uvx` for Python.
const COMPONENTIZE_PY_VERSION: &str = "0.25.0";

/// The jco version `function build` pins for JS components (validated round-trip).
const JCO_VERSION: &str = "1.25.2";

/// Build a function project to a component and print the produced `.wasm` path.
/// The language is detected from the project files: `Cargo.toml` ⇒ Rust
/// (`cargo build --target wasm32-wasip2`), `package.json` ⇒ JS
/// (`jco componentize`).
pub(super) async fn build_project(dir: Option<std::path::PathBuf>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| std::path::PathBuf::from("."));
    let component = if dir.join("Cargo.toml").exists() {
        build_rust(&dir).await?
    } else if dir.join("package.json").exists() {
        build_js(&dir).await?
    } else if dir.join("pyproject.toml").exists() {
        build_python(&dir).await?
    } else {
        return Err(FunctionError::NoComponent);
    };
    println!("built {}", component.display());
    println!(
        "  deploy: boatramp function deploy <name> --component {}",
        component.display()
    );
    Ok(())
}

/// Compile a Rust function project → the produced component path.
async fn build_rust(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .current_dir(dir)
        .status()
        .await?;
    if !status.success() {
        return Err(FunctionError::BuildFailed);
    }
    // The cdylib output is a single `<crate>.wasm` under the release dir.
    let release = dir.join("target/wasm32-wasip2/release");
    std::fs::read_dir(&release)
        .ok()
        .and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().and_then(|e| e.to_str()) == Some("wasm"))
        })
        .ok_or(FunctionError::NoComponent)
}

/// Componentize a JS function project with `jco` → the produced component path.
/// `jco` is fetched via `npx` (version-pinned), so only Node is required.
async fn build_js(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("function");
    let out = format!("{name}.wasm");
    let status = tokio::process::Command::new("npx")
        .args([
            "--yes",
            &format!("@bytecodealliance/jco@{JCO_VERSION}"),
            "componentize",
            "handler.js",
            "--wit",
            "wit",
            "-n",
            "wasi:http/proxy",
            "-o",
            &out,
        ])
        .current_dir(dir)
        .status()
        .await?;
    if !status.success() {
        return Err(FunctionError::BuildFailed);
    }
    let component = dir.join(&out);
    if !component.exists() {
        return Err(FunctionError::NoComponent);
    }
    Ok(component)
}

/// Componentize a Python function project with `componentize-py` → the produced
/// component path. Run version-pinned via `uvx` (so only `uv` is required; `nix
/// develop` provides it), falling back to `componentize-py` on `PATH`.
async fn build_python(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("function");
    let out = format!("{name}.wasm");
    // `-d wit -w wasi:http/proxy componentize app -o <out>` — `app` is app.py.
    let build_args = [
        "-d",
        "wit",
        "-w",
        "wasi:http/proxy",
        "componentize",
        "app",
        "-o",
        &out,
    ];
    // Prefer a `componentize-py` already on PATH; otherwise fetch it via `uvx`.
    let status = if which("componentize-py") {
        tokio::process::Command::new("componentize-py")
            .args(build_args)
            .current_dir(dir)
            .status()
            .await?
    } else {
        tokio::process::Command::new("uvx")
            .arg("--from")
            .arg(format!("componentize-py=={COMPONENTIZE_PY_VERSION}"))
            .arg("componentize-py")
            .args(build_args)
            .current_dir(dir)
            .status()
            .await?
    };
    if !status.success() {
        return Err(FunctionError::BuildFailed);
    }
    let component = dir.join(&out);
    if !component.exists() {
        return Err(FunctionError::NoComponent);
    }
    Ok(component)
}

/// Whether an executable is on `PATH` (best-effort, for build-tool discovery).
fn which(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(cmd);
                p.is_file()
            })
        })
        .unwrap_or(false)
}
