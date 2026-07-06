//! The `completions` / `man` subcommands.
//!
//! Both are pure generators over the derived clap [`Cli`](crate::Cli) command
//! tree — no config, no network, no runtime. Distro / Homebrew / Nix packages run
//! them at build time to ship the completion scripts + man page as their payload
//! (which is what makes those packages feel native), so they must stay in the
//! binary itself rather than be pre-baked, so the payload can never drift from the
//! actual flags.

use std::io;

use clap::CommandFactory;
use clap_complete::Shell;

use crate::Cli;

/// `boatramp completions <shell>` — write the shell-completion script for `shell`
/// to stdout (`boatramp completions bash > /etc/bash_completion.d/boatramp`).
pub fn completions(shell: Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut io::stdout());
}

/// `boatramp man` — render the top-level roff man page to stdout
/// (`boatramp man > boatramp.1`). Includes the subcommand summary table clap
/// derives from the `Command` enum.
pub fn man() -> io::Result<()> {
    clap_mangen::Man::new(Cli::command()).render(&mut io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The completion generator produces a non-empty script for every supported
    /// shell (a smoke test that the derived command tree stays generatable).
    #[test]
    fn completions_render_for_every_shell() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let mut cmd = Cli::command();
            let mut out = Vec::new();
            clap_complete::generate(shell, &mut cmd, "boatramp", &mut out);
            assert!(!out.is_empty(), "empty completion script for {shell:?}");
            assert!(
                String::from_utf8_lossy(&out).contains("boatramp"),
                "{shell:?} script does not mention the binary name"
            );
        }
    }

    /// The man page renders to valid, non-empty roff naming the binary.
    #[test]
    fn man_page_renders() {
        let mut out = Vec::new();
        clap_mangen::Man::new(Cli::command())
            .render(&mut out)
            .expect("render man page");
        let roff = String::from_utf8_lossy(&out);
        assert!(
            roff.contains("boatramp"),
            "man page missing the binary name"
        );
        assert!(
            roff.contains(".TH"),
            "man page missing the roff title header"
        );
    }
}
