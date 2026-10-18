//! The `capabilities` subcommand: print the capability surface this host
//! implements — the informational `boatramp:handlers` surface revision, the
//! imports a deploy may declare, and the capability **features** a guest may
//! `require` in its manifest (each with its stability) — so an operator (or a
//! remote deploy) can check that a host satisfies a guest's requirements before
//! shipping it. The `features` list is exactly what the deploy-time `requires`
//! admission check enforces. The same data backs `GET /api/capabilities`.
//!
//! `capabilities check <component.wasm>` is the shift-left form: it scans a
//! component's manifest `requires` and reports whether *this* build satisfies
//! them, exiting non-zero on a gap — so a guest author can gate CI on "my
//! function still fits the boatramp version I target" instead of finding out at
//! deploy.

use std::path::PathBuf;

/// Arguments for `boatramp capabilities`.
#[derive(Debug, clap::Args)]
pub struct CapabilitiesArgs {
    /// Check a component's manifest `requires` against this build and exit non-zero
    /// if any required capability is missing (for CI gating). Reads the given
    /// `.wasm` component; needs the `handlers` feature.
    #[arg(long, value_name = "COMPONENT.wasm")]
    pub check: Option<PathBuf>,
}

/// The host's capability surface, as the `capabilities` command reports it (the
/// no-`--check` path). Serializes **transparently** to the inner
/// [`crate::handler_validate::HostCapabilities`], so `--output-format json` emits the
/// same object `GET /api/capabilities` returns. Rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(transparent)]
pub struct CapabilitiesOutput {
    caps: crate::handler_validate::HostCapabilities,
}

impl crate::output::Rendered for CapabilitiesOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        let caps = &self.caps;
        writeln!(w, "package: {}@{}", caps.package, caps.version)?;
        writeln!(
            w,
            "declarable imports: {}",
            caps.declarable_imports.join(", ")
        )?;
        let feats = caps
            .features
            .iter()
            .map(|c| format!("{} ({})", c.name, c.lifecycle.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(w, "capability features: {feats}")
    }
}

/// Report the host's capability surface, or run a component compatibility check.
///
/// The no-`--check` path is a DATA report: it returns the typed surface for
/// [`crate::output`] to render (human text, or JSON under `--output-format json`).
///
/// The `--check <component.wasm>` path is a CI gate: it writes its own report
/// (honoring the global `--output-format`) and **exits the process** with a status
/// code (0 = fits, 1 = missing a capability, 2 = usage/read error) so it reads
/// cleanly in a pipeline — it never returns, so `run` only yields a value on the
/// reporting path.
pub fn run(args: CapabilitiesArgs, mode: crate::output::OutputMode) -> CapabilitiesOutput {
    if let Some(component) = args.check.as_ref() {
        // Diverges (`-> !`): renders its own report and exits with the CI status code.
        check_component(component, matches!(mode, crate::output::OutputMode::Json));
    }
    CapabilitiesOutput {
        caps: crate::handler_validate::host_capabilities(),
    }
}

/// Check a component's `requires` against this build. See [`run`] for exit codes.
/// Always exits the process (`-> !`), so it is a terminal CI gate, never a value the
/// typed-output layer renders.
#[cfg(feature = "handlers")]
fn check_component(component: &std::path::Path, json: bool) -> ! {
    let bytes = match std::fs::read(component) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("cannot read {}: {err}", component.display());
            std::process::exit(2);
        }
    };
    let required = boatramp_server::component_requires(&bytes);
    let unmet = boatramp_server::unmet_requires(&bytes);
    if json {
        let report = serde_json::json!({
            "component": component.display().to_string(),
            "requires": required,
            "unmet": unmet,
            "ok": unmet.is_empty(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("check report serialize")
        );
    } else if required.is_empty() {
        println!(
            "ok: {} declares no capability requirements",
            component.display()
        );
    } else if unmet.is_empty() {
        println!(
            "ok: this host satisfies all {} requirement(s): {}",
            required.len(),
            required.join(", ")
        );
    } else {
        eprintln!(
            "MISSING: this host does not implement {}: {}",
            if unmet.len() == 1 {
                "capability"
            } else {
                "capabilities"
            },
            unmet.join(", ")
        );
        eprintln!("required: {}", required.join(", "));
        eprintln!("upgrade boatramp or enable those features — see `boatramp capabilities`.");
    }
    // Non-zero exit AFTER any report so `--json` still emits the machine-readable body.
    if !unmet.is_empty() {
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Without the `handlers` feature there is no capability registry to check against.
#[cfg(not(feature = "handlers"))]
fn check_component(_component: &std::path::Path, _json: bool) -> ! {
    eprintln!("`capabilities check` needs a build with the `handlers` feature");
    std::process::exit(2);
}
