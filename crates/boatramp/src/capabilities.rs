//! The `capabilities` subcommand: print the capability surface this host
//! implements — the informational `boatramp:handlers` surface revision, the
//! imports a deploy may declare, and the capability **features** a guest may
//! `require` in its manifest — so an operator (or a remote deploy) can check that
//! a host satisfies a guest's requirements before shipping it. The `features` list
//! is exactly what the deploy-time `requires` admission check enforces. The same
//! data backs `GET /api/capabilities`.

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
        println!("capability features: {}", caps.features.join(", "));
    }
}
