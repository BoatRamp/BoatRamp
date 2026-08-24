//! The `capabilities` subcommand: print the capability surface this host
//! implements — the `boatramp:handlers` package version and the imports a deploy
//! may declare — so an operator (or a remote deploy) can check compatibility
//! before shipping a guest that pins a capability version. The same data backs
//! `GET /api/capabilities`.

/// Arguments for `boatramp capabilities`.
#[derive(Debug, clap::Args)]
pub struct CapabilitiesArgs {
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

/// Print the host's capability surface. Infallible (a fixed, trivially
/// serialisable value), so it needs no error plumbing.
pub fn run(args: CapabilitiesArgs) {
    let caps: crate::handler_validate::HostCapabilities =
        crate::handler_validate::host_capabilities();
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&caps).expect("host capabilities serialize")
        );
    } else {
        println!("package: {}@{}", caps.package, caps.version);
        println!("declarable imports: {}", caps.declarable_imports.join(", "));
    }
}
