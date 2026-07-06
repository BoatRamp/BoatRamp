//! The `bundle` subcommand: an in-process Rust bundler (`bundler` feature).
//!
//! - **JS/TS** via **Rolldown** — module graph, tree-shaking, code-splitting,
//!   minify — written to the output directory.
//! - **CSS** via **lightningcss** — `@import` inlining + minify.
//!
//! Configured by the `bundle` section in `project.cfg` (overridable by flags).
//! The output directory is then published with `boatramp sync <outdir>`. When
//! built without `--features bundler`, the subcommand explains how to enable it.

use crate::config::{BundleConfig, ProjectConfig};

/// A failure in the `bundle` subcommand (the in-process Rust bundler).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Neither JS nor CSS entry points were configured.
    #[error("nothing to bundle: set bundle.js / bundle.css in project.cfg or pass --js / --css")]
    NothingToBundle,
    /// This build was compiled without the embedded bundler.
    #[cfg(not(feature = "bundler"))]
    #[error("this build has no embedded bundler; rebuild with `--features bundler`")]
    NoBundler,
    /// Initializing the Rolldown bundler failed.
    #[cfg(feature = "bundler")]
    #[error("rolldown init: {0}")]
    RolldownInit(String),
    /// Rolldown failed to bundle the JS/TS entry points.
    #[cfg(feature = "bundler")]
    #[error("rolldown bundle failed: {0}")]
    RolldownBundle(String),
    /// lightningcss failed to bundle a CSS entry (its `@import` graph).
    #[cfg(feature = "bundler")]
    #[error("css bundle {0}: {1}")]
    CssBundle(String, String),
    /// lightningcss failed to minify a bundled stylesheet.
    #[cfg(feature = "bundler")]
    #[error("css minify {0}: {1}")]
    CssMinify(String, String),
    /// lightningcss failed to print a bundled stylesheet.
    #[cfg(feature = "bundler")]
    #[error("css print {0}: {1}")]
    CssPrint(String, String),
    /// Creating the output directory or writing a bundled asset failed.
    #[cfg(feature = "bundler")]
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `bundle` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp bundle`.
#[derive(Debug, clap::Args)]
pub struct BundleArgs {
    /// Output directory (overrides `[bundle].outdir`).
    #[arg(long)]
    outdir: Option<String>,

    /// JS/TS entry point(s) (repeatable; overrides `[bundle].js`).
    #[arg(long = "js")]
    js: Vec<String>,

    /// CSS entry point(s) (repeatable; overrides `[bundle].css`).
    #[arg(long = "css")]
    css: Vec<String>,

    /// Disable minification.
    #[arg(long)]
    no_minify: bool,
}

impl BundleArgs {
    /// Resolve the effective bundle config from flags + the `bundle` config.
    fn resolve(&self, config: &ProjectConfig) -> BundleConfig {
        let base = config.bundle.clone().unwrap_or_default();
        BundleConfig {
            outdir: self.outdir.clone().unwrap_or(base.outdir),
            js: if self.js.is_empty() {
                base.js
            } else {
                self.js.clone()
            },
            css: if self.css.is_empty() {
                base.css
            } else {
                self.css.clone()
            },
            minify: base.minify && !self.no_minify,
        }
    }
}

/// Entry point for `boatramp bundle`.
pub async fn run(args: BundleArgs, config: &ProjectConfig) -> Result<()> {
    let bundle = args.resolve(config);
    if bundle.js.is_empty() && bundle.css.is_empty() {
        return Err(Error::NothingToBundle);
    }
    run_bundle(&bundle).await
}

#[cfg(feature = "bundler")]
async fn run_bundle(bundle: &BundleConfig) -> Result<()> {
    let outdir = std::path::PathBuf::from(&bundle.outdir);
    std::fs::create_dir_all(&outdir)?;

    if !bundle.js.is_empty() {
        bundle_js(&bundle.js, &bundle.outdir, bundle.minify).await?;
        println!(
            "bundled {} JS entry point(s) -> {}",
            bundle.js.len(),
            bundle.outdir
        );
    }
    for entry in &bundle.css {
        let css = bundle_css(entry, bundle.minify)?;
        let name = std::path::Path::new(entry)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bundle.css".to_string());
        let dest = outdir.join(&name);
        std::fs::write(&dest, css.as_bytes())?;
        println!(
            "bundled CSS {entry} -> {} ({} bytes)",
            dest.display(),
            css.len()
        );
    }
    Ok(())
}

/// Bundle JS/TS entry points with Rolldown, writing chunks to `outdir`.
#[cfg(feature = "bundler")]
async fn bundle_js(entries: &[String], outdir: &str, minify: bool) -> Result<()> {
    use rolldown::{Bundler, BundlerOptions, InputItem, OutputFormat, RawMinifyOptions};

    let options = BundlerOptions {
        input: Some(
            entries
                .iter()
                .map(|import| InputItem {
                    name: None,
                    import: import.clone(),
                })
                .collect(),
        ),
        dir: Some(outdir.to_string()),
        format: Some(OutputFormat::Esm),
        minify: Some(RawMinifyOptions::Bool(minify)),
        ..Default::default()
    };
    let mut bundler =
        Bundler::new(options).map_err(|err| Error::RolldownInit(format!("{err:?}")))?;
    bundler
        .write()
        .await
        .map_err(|err| Error::RolldownBundle(format!("{err:?}")))?;
    Ok(())
}

/// Bundle a CSS entry (inlining `@import`) with lightningcss, returning the
/// (optionally minified) output.
#[cfg(feature = "bundler")]
fn bundle_css(entry: &str, minify: bool) -> Result<String> {
    use lightningcss::bundler::{Bundler, FileProvider};
    use lightningcss::stylesheet::{MinifyOptions, ParserOptions, PrinterOptions};

    let fs = FileProvider::new();
    let mut bundler = Bundler::new(&fs, None, ParserOptions::default());
    let mut stylesheet = bundler
        .bundle(std::path::Path::new(entry))
        .map_err(|err| Error::CssBundle(entry.to_string(), format!("{err:?}")))?;
    if minify {
        stylesheet
            .minify(MinifyOptions::default())
            .map_err(|err| Error::CssMinify(entry.to_string(), format!("{err:?}")))?;
    }
    let result = stylesheet
        .to_css(PrinterOptions {
            minify,
            ..Default::default()
        })
        .map_err(|err| Error::CssPrint(entry.to_string(), format!("{err:?}")))?;
    Ok(result.code)
}

#[cfg(not(feature = "bundler"))]
async fn run_bundle(_bundle: &BundleConfig) -> Result<()> {
    Err(Error::NoBundler)
}
