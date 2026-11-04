//! `cargo xtask` — the workspace dev-tool runner (see `.cargo/config.toml` for the alias).
//!
//! Today it exposes one task, `gen-docs`, the foundation of docs Phase 2
//! (PLAN-docs-structure Lever 2): regenerate the GENERATED reference pages from the code
//! source of truth, and — with `--check` — fail on drift.
//!
//! ```text
//! cargo xtask gen-docs           # regenerate the generated reference pages in place
//! cargo xtask gen-docs --check   # regenerate to a temp file + diff against the committed
//!                                # pages; nonzero exit on any difference (the CI drift gate)
//! ```
//!
//! Run it with a plain `cargo xtask gen-docs` — no extra `--features` / `--no-default-features`
//! — so the clap tree it introspects is always the default (batteries-included) build and the
//! output is reproducible between a developer's machine and CI.

mod cli;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One generated documentation page: where it lives (relative to the workspace root) and how
/// to render its current content from the code source of truth.
struct GenTarget {
    /// Path relative to the workspace root.
    rel_path: &'static str,
    /// Render the page's full, current content from code.
    render: fn() -> String,
}

/// The registry of generated pages. **This is the extension point for the rest of Phase 2:**
/// each remaining `reference/*.md` page becomes one more `GenTarget` whose `render` fn lives
/// in its own `src/<page>.rs` module.
///
/// TODO(PLAN-docs-structure Lever 2) — the remaining pages to generate, in rough priority:
///   * `boatramp-cfg.md`, `project-cfg.md`, `siteconfig.md`, `env.md` — from the serde/figment
///     config structs (already a library in `boatramp-node`; add it as an xtask dependency and
///     walk the structs — no new seam in the binary needed).
///   * `features.md` — from the `[features]` tables in the crate manifests.
///   * `rbac.md`     — from the Cedar vocabulary.
///   * `keyspace.md` — from the `*_key` builders.
///   * `wit.md` (NEW) — a guest-bindings reference from the `.wit` files (currently missing).
///
/// A page that must keep hand-written prose *around* a generated block (e.g. the config pages)
/// should generate into a delimited `<!-- gen:… start/end -->` region instead of owning a whole
/// file — add a small `replace_region(existing, marker, generated)` helper here when the first
/// such page lands. The CLI page uses the whole-file form because its hand-written companion is
/// a physically separate page (`cli.md`), which is the least-disruptive split for a page as
/// editorial and anchor-laden as the CLI one.
fn targets() -> Vec<GenTarget> {
    vec![GenTarget {
        rel_path: "docs/src/reference/cli-reference.md",
        render: cli::render,
    }]
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen-docs") => {
            let mut check = false;
            for a in &args[1..] {
                match a.as_str() {
                    "--check" => check = true,
                    other => {
                        eprintln!("xtask gen-docs: unexpected argument `{other}`");
                        usage();
                        return ExitCode::FAILURE;
                    }
                }
            }
            gen_docs(check)
        }
        _ => {
            usage();
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!("usage: cargo xtask gen-docs [--check]");
    eprintln!();
    eprintln!("  gen-docs           regenerate the generated reference pages in place");
    eprintln!(
        "  gen-docs --check   verify the committed pages match the code (CI drift gate; nonzero on drift)"
    );
}

fn gen_docs(check: bool) -> ExitCode {
    let root = workspace_root();
    let mut drift = false;

    for target in targets() {
        let content = (target.render)();
        let path = root.join(target.rel_path);

        if check {
            if check_target(&path, target.rel_path, &content) {
                drift = true;
            }
        } else {
            if let Err(e) = std::fs::write(&path, content.as_bytes()) {
                eprintln!("error: writing {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            println!("regenerated {}", target.rel_path);
        }
    }

    if check {
        if drift {
            eprintln!();
            eprintln!("::error:: generated reference docs are out of date (see the diff above).");
            eprintln!("Fix: run `cargo xtask gen-docs` and commit the changed files.");
            return ExitCode::FAILURE;
        }
        println!("generated reference docs are up to date.");
    }
    ExitCode::SUCCESS
}

/// Return true on drift: the committed page is missing, or differs from the freshly rendered
/// content. Prints a unified diff (committed vs generated) so CI logs show exactly what changed.
fn check_target(committed: &Path, rel_path: &str, rendered: &str) -> bool {
    if !committed.exists() {
        eprintln!("::error:: {rel_path} is missing — run `cargo xtask gen-docs`");
        return true;
    }

    let tmp = std::env::temp_dir().join(format!("xtask-gendocs-{}", rel_path.replace('/', "_")));
    if let Err(e) = std::fs::write(&tmp, rendered.as_bytes()) {
        eprintln!("error: writing temp file {}: {e}", tmp.display());
        return true;
    }

    match std::process::Command::new("diff")
        .arg("-u")
        .arg(committed)
        .arg(&tmp)
        .status()
    {
        Ok(status) if status.success() => false,
        Ok(_) => {
            eprintln!("::error:: {rel_path} is out of date (committed vs generated shown above)");
            true
        }
        // `diff` unavailable (unusual) — fall back to an exact byte comparison.
        Err(_) => match std::fs::read(committed) {
            Ok(bytes) if bytes == rendered.as_bytes() => false,
            _ => {
                eprintln!("::error:: {rel_path} differs from the generated content");
                true
            }
        },
    }
}

/// The workspace root, derived from this crate's location (`<root>/crates/xtask`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/xtask has a workspace-root grandparent")
        .to_path_buf()
}
