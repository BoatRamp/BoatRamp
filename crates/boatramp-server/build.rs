//! Stage the embedded web-console assets for the `console` feature.
//!
//! The console SPA's built `dist/` (in `../boatramp-console`) is a Trunk build
//! artifact, gitignored — so a fresh checkout doesn't have it. To keep the
//! `console` feature always-compilable, copy whatever `dist/` exists into
//! `$OUT_DIR/console-dist` (which `console.rs` embeds via `include_dir!`); when
//! nothing has been built yet, stage a placeholder `index.html` instead and warn.
//! The real assets come from `trunk build` in `crates/boatramp-console`
//! (`just console`), which the release pipeline runs before the binary build.

use std::{env, fs, path::Path};

fn main() {
    // Only the `console` feature embeds the SPA; skip otherwise.
    if env::var_os("CARGO_FEATURE_CONSOLE").is_none() {
        return;
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR set for a build script");
    let dest = Path::new(&out_dir).join("console-dist");
    let _ = fs::remove_dir_all(&dest);
    fs::create_dir_all(&dest).expect("create console-dist");

    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let src = Path::new(&manifest).join("../boatramp-console/dist");
    // Re-run when the built console changes (or first appears).
    println!("cargo:rerun-if-changed={}", src.display());

    let mut copied = 0usize;
    if src.is_dir() {
        for entry in fs::read_dir(&src).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name() {
                    fs::copy(&path, dest.join(name)).expect("copy console asset");
                    copied += 1;
                }
            }
        }
    }

    if copied == 0 {
        // No built SPA (fresh checkout / CI without a Trunk build). Stage a
        // placeholder so the feature compiles; the served page then explains how
        // to bake the real console.
        fs::write(
            dest.join("index.html"),
            "<!DOCTYPE html><html><head><title>boatramp console</title></head><body>\
             <p>The web console was not built into this binary. Build it with \
             <code>just console</code> (a <code>trunk build --release</code> in \
             <code>crates/boatramp-console</code>) and rebuild with \
             <code>--features console</code>.</p></body></html>",
        )
        .expect("write placeholder index.html");
        // `console` is now a default feature, so a plain debug `cargo build` hits
        // this path routinely — stay quiet there. Warn only for release builds,
        // where a missing dist means a placeholder would ship (the release + Nix
        // pipelines stage the real dist, so this should never fire in them).
        if env::var("PROFILE").as_deref() == Ok("release") {
            println!(
                "cargo:warning=`console` feature is on but crates/boatramp-console/dist is empty; \
                 embedded a placeholder. Run `just console` to bake the real console assets."
            );
        }
    }
}
