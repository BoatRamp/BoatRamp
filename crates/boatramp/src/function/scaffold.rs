//! `function init` — scaffold a new function project from an embedded language
//! template. Pure local filesystem work (no network, no control plane).

use super::{FunctionError, Result};

/// The embedded function templates (`function init --lang <lang>`).
static RUST_TEMPLATE: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates/rust");
static JS_TEMPLATE: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates/js");
static PYTHON_TEMPLATE: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates/python");

/// Scaffold a new function project from a language template.
pub(super) fn init_project(name: &str, lang: &str, dir: Option<std::path::PathBuf>) -> Result<()> {
    let template = match lang {
        "rust" => &RUST_TEMPLATE,
        "js" | "javascript" => &JS_TEMPLATE,
        "python" | "py" => &PYTHON_TEMPLATE,
        other => return Err(FunctionError::UnknownLang(other.to_string())),
    };
    let crate_name = sanitize_crate_name(name);
    let target = dir
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(&crate_name);
    if target.exists() {
        return Err(FunctionError::AlreadyExists(target));
    }
    write_template(template, &target, &crate_name)?;
    println!("scaffolded {crate_name} in {}", target.display());
    println!("  next: cd {crate_name} && boatramp function build");
    Ok(())
}

/// Write every embedded template file to `dest_root`. Any `*.tmpl` file is written
/// without the `.tmpl` suffix with `BOATRAMP_FUNCTION_NAME` substituted (so
/// `Cargo.toml.tmpl` / `package.json.tmpl` become the real manifests).
fn write_template(
    dir: &include_dir::Dir,
    dest_root: &std::path::Path,
    crate_name: &str,
) -> Result<()> {
    let mut files: Vec<&include_dir::File> = Vec::new();
    collect_files(dir, &mut files);
    for file in files {
        let rel = file.path();
        let is_tmpl = rel
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "tmpl");
        let (rel, contents) = if is_tmpl {
            let text = std::str::from_utf8(file.contents())
                .unwrap_or_default()
                .replace("BOATRAMP_FUNCTION_NAME", crate_name);
            (rel.with_extension(""), text.into_bytes())
        } else {
            (rel.to_path_buf(), file.contents().to_vec())
        };
        let dest = dest_root.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, contents)?;
    }
    Ok(())
}

/// Recursively gather every file in the embedded directory (paths are relative to
/// the template root).
fn collect_files<'a>(dir: &'a include_dir::Dir, out: &mut Vec<&'a include_dir::File<'a>>) {
    out.extend(dir.files());
    for sub in dir.dirs() {
        collect_files(sub, out);
    }
}

/// A valid Rust crate name from a function name: lowercase, non-alphanumerics → `-`,
/// collapsed, trimmed. Empty input becomes `function`.
pub(super) fn sanitize_crate_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "function".to_string()
    } else {
        trimmed.to_string()
    }
}
