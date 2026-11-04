//! boatramp — the binary entry point.
//!
//! A one-line shim over the crate library ([`boatramp::main_entry`]). The whole
//! CLI — the clap command tree, every subcommand, and the server — lives in
//! `src/lib.rs` so in-workspace tooling (the `cargo xtask gen-docs` reference
//! generator) can introspect the EXACT command tree this binary parses via
//! [`boatramp::cli_command`], without re-exec'ing the binary.

fn main() -> std::process::ExitCode {
    boatramp::main_entry()
}
