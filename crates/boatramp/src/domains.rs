//! The `domain` subcommand: attach/detach hostnames to a site for virtualhost
//! routing. Attaching a custom domain is gated on **ownership verification**.
//!
//! `domain add` starts a challenge and, when there is no manual step left, goes
//! all the way — verifies and attaches in one command:
//!
//! * a host that **already resolves to this server** verifies over HTTP
//!   immediately (the server serves its own challenge token from the edge, so no
//!   prior deploy is needed — the fix for the attach chicken-and-egg);
//! * `--provider` publishes the DNS-TXT challenge for you, waits for it to
//!   resolve, and attaches.
//!
//! Otherwise (a live domain still pointing elsewhere, or `--no-wait`) it prints
//! the challenge to publish and you finish with `domain verify`. Attachment only
//! ever happens after ownership is proven — so the host routes and becomes
//! eligible for ACME.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `domain` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A hostname's ownership challenge was not satisfied.
    #[error("verification failed: {detail}\n\n{instructions}")]
    VerificationFailed {
        detail: String,
        instructions: String,
    },
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A `--provider` verification-dance problem (timeout, or the `acme-dns`
    /// feature is absent from this build).
    #[error("{0}")]
    Verify(String),
    /// Building the DNS provider for `--provider` failed (missing credential env var).
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    Provider(#[from] crate::acme_dns::Error),
    /// Publishing the challenge TXT during `--provider` failed.
    #[cfg(feature = "acme-dns")]
    #[error(transparent)]
    Dns(#[from] boatramp_acme::DnsError),
}

/// `domains` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp domain`.
#[derive(Debug, clap::Args)]
pub struct DomainArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: DomainCommand,
}

#[derive(Debug, Subcommand)]
enum DomainCommand {
    /// Verify ownership of a hostname and attach it to the site (use
    /// `*.example.com` for a wildcard).
    ///
    /// If the host already resolves to this server it is verified + attached in
    /// one step; otherwise the challenge to publish is printed and you finish
    /// with `domain verify`.
    Add {
        /// Hostname or `*.`-prefixed wildcard.
        host: String,
        /// Verification method: `http` (default) serves a token file; `dns`
        /// publishes a TXT record (needs a server built with `domain-verify-dns`).
        #[arg(long, default_value = "http")]
        method: String,
        /// Managed-DNS provider (e.g. `cloudflare`, `digitalocean`, `route53`).
        /// When set, boatramp publishes the `_boatramp-verify` TXT for you
        /// (credentials from the environment; needs a build with `acme-dns`),
        /// waits for it to resolve, and attaches — no manual DNS edit. Implies
        /// `--method dns` and writes only the `_boatramp-verify` TXT, never the
        /// host's A/CNAME (that stays an explicit, post-verify step).
        #[arg(long)]
        provider: Option<String>,
        /// Only start the challenge and print instructions — skip the immediate
        /// verify+attach. Use when the host doesn't resolve here yet.
        #[arg(long)]
        no_wait: bool,
        /// **Admin only.** Attach the host WITHOUT proving ownership — you assert
        /// it out-of-band. The host then serves normally (it bypasses the
        /// mandatory-verification gate). The server refuses this for a
        /// site-scoped token; it needs a `system·admin` token.
        #[arg(long)]
        unverified: bool,
    },
    /// Check a hostname's verification challenge; on success it is attached.
    Verify {
        /// Hostname or `*.`-prefixed wildcard.
        host: String,
    },
    /// Detach a hostname and drop its verification.
    Rm {
        /// Hostname to remove.
        host: String,
    },
    /// List the site's hostnames and any pending verifications.
    Ls,
    /// **Operator only.** Verify a set of DNS records resolve as expected (a
    /// read-only diagnostic — it attaches and persists nothing). Each `--record`
    /// is `KIND[/MODE]:NAME=VALUE`, where KIND is `txt`|`mx`|`cname`|`a` and MODE
    /// is `exact` (default) | `contains` | `prefix` (`contains`/`prefix` are TXT
    /// only). Needs a server built with `domain-verify-dns` and a `system·admin`
    /// token.
    VerifyRecords {
        /// Host this record set belongs to (operator context; records name
        /// themselves).
        host: String,
        /// A record spec `KIND[/MODE]:NAME=VALUE` (repeatable), e.g.
        /// `txt:_acme.example.com=tok`, `a:example.com=192.0.2.1`,
        /// `txt/contains:_dmarc.example.com=p=reject`.
        #[arg(long = "record", short = 'r', required = true, value_name = "SPEC")]
        records: Vec<String>,
    },
}

/// Parse one `KIND[/MODE]:NAME=VALUE` record spec. `VALUE` is everything after the
/// first `=`, so it may itself contain `=`/`:` (e.g. a DMARC policy or an IPv6
/// address); `NAME` has no `=`.
/// Escape ASCII/Unicode control characters (C0, DEL, C1 — including ESC `0x1b`,
/// newline, and CR) in a string before printing it to the operator's terminal.
/// Resolved DNS record values are attacker-controllable, so printing them raw
/// would allow terminal-escape sequences or injected log lines on the operator's
/// console. Printable text is left untouched; a control char renders as `\xNN`.
fn sanitize_for_terminal(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_record_spec(raw: &str) -> Result<boatramp_core::record_verify::RecordSpec> {
    use boatramp_core::record_verify::{MatchMode, RecordKind, RecordSpec};

    let bad = |msg: &str| {
        Error::Verify(format!(
            "invalid --record `{raw}`: {msg} (expected KIND[/MODE]:NAME=VALUE)"
        ))
    };
    let (kind_part, rest) = raw.split_once(':').ok_or_else(|| bad("missing `:`"))?;
    let (name, value) = rest.split_once('=').ok_or_else(|| bad("missing `=`"))?;
    if name.is_empty() {
        return Err(bad("empty record name"));
    }
    let (kind_str, mode_str) = match kind_part.split_once('/') {
        Some((k, m)) => (k, m),
        None => (kind_part, "exact"),
    };
    let kind = kind_str
        .parse::<RecordKind>()
        .map_err(|e| bad(&e.to_string()))?;
    let match_mode = mode_str
        .parse::<MatchMode>()
        .map_err(|e| bad(&e.to_string()))?;
    let spec = RecordSpec {
        kind,
        name: name.to_string(),
        value: value.to_string(),
        match_mode,
    };
    // Reject an illegal (kind, mode) pair locally, before the round-trip.
    spec.validate().map_err(|e| bad(&e.to_string()))?;
    Ok(spec)
}

/// One row of a `domain verify-records` report: the spec, its verdict, and the
/// values actually observed. `found` carries the raw resolved values (JSON escapes
/// control bytes safely); the human renderer sanitizes them for the terminal.
#[derive(Debug, serde::Serialize)]
pub struct RecordRow {
    kind: String,
    name: String,
    value: String,
    status: boatramp_core::record_verify::RecordState,
    found: Vec<String>,
}

/// The verdict of the auto-continue check a self-serve HTTP `domain add` runs right
/// after starting the challenge.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum AddCheckOutcome {
    /// Verified and attached in this `add`.
    VerifiedAttached,
    /// Verified; attach still pending (`domain verify` to attach).
    VerifiedPending,
    /// Not verified yet; `detail` explains why.
    NotVerified { detail: String },
    /// The host is not reachable here yet (a probe/transport error).
    NotReachable,
}

/// The result of a `boatramp domain` subcommand, rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum DomainOutput {
    /// `domain add --unverified`: the server's confirmation text (admin override).
    AttachedUnverified { message: String },
    /// `domain add`: ownership was already proven; `attached` says whether the host
    /// is also attached now.
    AlreadyVerified {
        host: String,
        site: String,
        attached: bool,
    },
    /// `domain add`: a challenge was started. Carries the method + the instructions to
    /// publish, and — when the `add` auto-continued (self-serve HTTP) — the check
    /// verdict. `outcome: None` ⇒ a manual publish step remains (`--no-wait` or a DNS
    /// challenge).
    ChallengeStarted {
        host: String,
        site: String,
        method: String,
        instructions: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        outcome: Option<AddCheckOutcome>,
    },
    /// `domain add --provider`: the host was already verified before the dance started.
    ProviderAlreadyVerified { host: String, site: String },
    /// `domain add --provider`: the challenge published + resolved; `attached` says
    /// whether it was also attached.
    ProviderVerified {
        host: String,
        site: String,
        attached: bool,
    },
    /// `domain verify`: the ownership check passed (attach follows on success).
    Verified {
        host: String,
        site: String,
        attached: bool,
    },
    /// `domain rm`: the host was detached from the site.
    Detached { host: String, site: String },
    /// `domain ls`: the site's attached hosts plus any pending verifications.
    List {
        site: String,
        domains: boatramp_core::config::DomainConfig,
        pending: Vec<boatramp_core::domain_verify::DomainVerification>,
    },
    /// `domain verify-records`: every record verified (a failing set prints the table
    /// then returns `Err`, so this variant only ever carries a passing report).
    Records {
        host: String,
        records: Vec<RecordRow>,
        verified: bool,
    },
}

/// Write the per-record verdict table of a `domain verify-records` report. Shared by
/// the success renderer and the failure path (which prints it before failing).
fn write_records_table(rows: &[RecordRow], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    use boatramp_core::record_verify::RecordState;
    for row in rows {
        let mark = match row.status {
            RecordState::Ok => "ok",
            RecordState::Mismatch => "MISMATCH",
            RecordState::Missing => "MISSING",
        };
        let found = if row.found.is_empty() {
            "(none)".to_string()
        } else {
            // Resolved record values are attacker-controllable (anyone who controls a
            // queried zone can embed ESC/newline bytes in a TXT record), so escape
            // control chars before printing them to the operator's terminal.
            row.found
                .iter()
                .map(|v| sanitize_for_terminal(v))
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(
            w,
            "{mark}  {} {} = {}  [found: {found}]",
            row.kind, row.name, row.value
        )?;
    }
    Ok(())
}

impl crate::output::Rendered for DomainOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::AttachedUnverified { message } => write!(w, "{message}"),
            Self::AlreadyVerified {
                host,
                site,
                attached,
            } => {
                if *attached {
                    writeln!(w, "{host} is already verified and attached to {site}")
                } else {
                    writeln!(w, "{host} is already verified for {site}")?;
                    writeln!(w, "run `boatramp domain verify {host}` to attach it")
                }
            }
            Self::ChallengeStarted {
                host,
                site,
                method,
                instructions,
                outcome,
            } => {
                writeln!(w, "started {method} verification for {host}\n")?;
                writeln!(w, "{instructions}")?;
                match outcome {
                    None => writeln!(w, "\nthen run `boatramp domain verify {host}`"),
                    Some(AddCheckOutcome::VerifiedAttached) => {
                        writeln!(w, "✓ verified {host} and attached it to {site}")
                    }
                    Some(AddCheckOutcome::VerifiedPending) => writeln!(
                        w,
                        "✓ verified {host}; run `boatramp domain verify {host}` to attach"
                    ),
                    Some(AddCheckOutcome::NotVerified { detail }) => {
                        writeln!(w, "not verified yet ({detail})")?;
                        writeln!(
                            w,
                            "complete the step above, then run `boatramp domain verify {host}`"
                        )
                    }
                    Some(AddCheckOutcome::NotReachable) => {
                        writeln!(w, "not reachable here yet")?;
                        writeln!(
                            w,
                            "complete the step above, then run `boatramp domain verify {host}`"
                        )
                    }
                }
            }
            Self::ProviderAlreadyVerified { host, site } => writeln!(
                w,
                "{host} is already verified for {site}; run `domain verify {host}` to attach"
            ),
            Self::ProviderVerified {
                host,
                site,
                attached,
            } => {
                if *attached {
                    writeln!(w, "verified {host} and attached it to {site}")
                } else {
                    writeln!(w, "verified {host} (run `domain verify {host}` to attach)")
                }
            }
            Self::Verified {
                host,
                site,
                attached,
            } => {
                if *attached {
                    writeln!(w, "verified {host} and attached it to {site}")
                } else {
                    writeln!(w, "verified {host}")
                }
            }
            Self::Detached { host, site } => writeln!(w, "detached {host} from {site}"),
            Self::List {
                site,
                domains,
                pending,
            } => {
                let mut any = false;
                if let Some(primary) = &domains.primary {
                    writeln!(w, "{primary}  (primary)")?;
                    any = true;
                }
                for alias in &domains.aliases {
                    writeln!(w, "{alias}")?;
                    any = true;
                }
                for wildcard in &domains.wildcards {
                    writeln!(w, "{wildcard}  (wildcard)")?;
                    any = true;
                }
                if !any {
                    writeln!(w, "no domains attached to {site}")?;
                }
                if !pending.is_empty() {
                    writeln!(w, "\npending verification:")?;
                    for v in pending {
                        let state = if v.verified {
                            "verified — run `domain verify` to attach"
                        } else {
                            "unverified"
                        };
                        writeln!(w, "  {}  ({}, {state})", v.host, v.method)?;
                    }
                }
                Ok(())
            }
            Self::Records { host, records, .. } => {
                write_records_table(records, w)?;
                writeln!(w, "\nall {} record(s) verified for {host}", records.len())
            }
        }
    }
}

/// Entry point for `boatramp domain`.
pub async fn run(args: DomainArgs, config: &ProjectConfig) -> Result<DomainOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );

    match args.command {
        DomainCommand::Ls => ls(&cp, &site).await,
        DomainCommand::Add {
            host,
            method,
            provider,
            no_wait,
            unverified,
        } => {
            // Admin override: attach without an ownership proof.
            if unverified {
                let message = cp.attach_domain_unverified(&site, &host).await?;
                return Ok(DomainOutput::AttachedUnverified { message });
            }
            // A managed-DNS provider does the whole dance (publish TXT → poll →
            // attach) itself.
            if let Some(provider) = provider.as_deref() {
                return add_via_provider(&cp, &site, &host, Some(provider)).await;
            }
            let verification = cp
                .start_domain_verification(&site, &host, Some(&method))
                .await?;
            if verification.verified {
                // Ownership already proven earlier — (re)attach it now.
                let result = cp.check_domain_verification(&site, &host).await?;
                return Ok(DomainOutput::AlreadyVerified {
                    host,
                    site,
                    attached: result.attached,
                });
            }
            let method = verification.method.to_string();
            let instructions = verification.instructions();

            // Auto-continue only when there's no manual step left: an HTTP
            // challenge for a host that already resolves here is served by this
            // server, so a single `domain add` verifies + attaches. A DNS
            // challenge (or `--no-wait`) always has a manual publish step, so we
            // stop after returning the instructions.
            let http_self_serve =
                verification.method == boatramp_core::domain_verify::VerificationMethod::Http;
            if no_wait || !http_self_serve {
                return Ok(DomainOutput::ChallengeStarted {
                    host,
                    site,
                    method,
                    instructions,
                    outcome: None,
                });
            }
            tracing::info!("checking whether {host} already resolves here…");
            let outcome = match cp.check_domain_verification(&site, &host).await {
                Ok(result) if result.passed && result.attached => AddCheckOutcome::VerifiedAttached,
                Ok(result) if result.passed => AddCheckOutcome::VerifiedPending,
                Ok(result) => AddCheckOutcome::NotVerified {
                    detail: result
                        .detail
                        .unwrap_or_else(|| "not reachable here yet".into()),
                },
                // A probe/transport error before the host is set up is expected —
                // guide the operator on rather than failing the command.
                Err(_) => AddCheckOutcome::NotReachable,
            };
            Ok(DomainOutput::ChallengeStarted {
                host,
                site,
                method,
                instructions,
                outcome: Some(outcome),
            })
        }
        DomainCommand::Verify { host } => {
            let result = cp.check_domain_verification(&site, &host).await?;
            if result.passed {
                Ok(DomainOutput::Verified {
                    host,
                    site,
                    attached: result.attached,
                })
            } else {
                let detail = result
                    .detail
                    .unwrap_or_else(|| "challenge not satisfied yet".into());
                Err(Error::VerificationFailed {
                    detail,
                    instructions: result.verification.instructions(),
                })
            }
        }
        DomainCommand::Rm { host } => {
            let mut site_config = cp.fetch_site_config(&site).await?;
            let domains = &mut site_config.domains;
            if domains.primary.as_deref() == Some(host.as_str()) {
                domains.primary = None;
            }
            domains.aliases.retain(|alias| alias != &host);
            domains.wildcards.retain(|wildcard| wildcard != &host);
            cp.put_site_config(&site, &site_config).await?;
            cp.remove_domain_verification(&site, &host).await?;
            Ok(DomainOutput::Detached { host, site })
        }
        DomainCommand::VerifyRecords { host, records } => {
            let specs = records
                .iter()
                .map(|r| parse_record_spec(r))
                .collect::<Result<Vec<_>>>()?;
            let report = cp.verify_records(&site, &host, &specs).await?;
            let rows: Vec<RecordRow> = specs
                .iter()
                .zip(report.records.iter())
                .map(|(spec, status)| RecordRow {
                    kind: spec.kind.to_string(),
                    name: spec.name.clone(),
                    value: spec.value.clone(),
                    status: status.status,
                    found: status.found.clone(),
                })
                .collect();
            if report.verified {
                Ok(DomainOutput::Records {
                    host,
                    records: rows,
                    verified: true,
                })
            } else {
                // The per-record table is shown on the failure path too (so the
                // operator sees which records failed), then the command fails
                // non-zero. This detail rides the error path, not `output::emit`.
                use std::io::Write as _;
                let mut out = std::io::stdout().lock();
                let _ = write_records_table(&rows, &mut out);
                let _ = out.flush();
                Err(Error::Verify(format!(
                    "one or more records did not verify for {host}"
                )))
            }
        }
    }
}

/// The `--provider` verification dance: publish the DNS-TXT challenge through the
/// provider, poll the server's ownership check until the record resolves, and
/// attach. It writes **only** the `_boatramp-verify` TXT — never the host's
/// A/CNAME — so ownership is proven before anything is pointed at this server.
#[cfg(feature = "acme-dns")]
async fn add_via_provider(
    cp: &crate::client::ControlPlane,
    site: &str,
    host: &str,
    provider: Option<&str>,
) -> Result<DomainOutput> {
    use std::time::Duration;

    use boatramp_acme::{DnsRecord, RecordKind};
    use clap::ValueEnum;

    use crate::acme_dns::{DnsProviderKind, build_provider};

    let provider_name = provider
        .ok_or_else(|| Error::Verify("missing `--provider <name>` (e.g. cloudflare)".into()))?;
    let kind = DnsProviderKind::from_str(provider_name, true)
        .map_err(|e| Error::Verify(format!("unknown --provider `{provider_name}`: {e}")))?;

    // `--auto` publishes a DNS TXT, so it is always the `dns` method.
    let verification = cp
        .start_domain_verification(site, host, Some("dns"))
        .await?;
    if verification.verified {
        return Ok(DomainOutput::ProviderAlreadyVerified {
            host: host.to_string(),
            site: site.to_string(),
        });
    }

    let provider = build_provider(kind).await?;
    let record = DnsRecord {
        kind: RecordKind::Txt(vec![verification.token.clone()]),
        name: verification.dns_record_name(),
        ttl: 60,
    };
    provider.upsert(&record).await?;
    tracing::info!(
        "published {} TXT for {host}; waiting for it to resolve...",
        verification.dns_record_name()
    );

    // Poll the server-side ownership check while the TXT propagates.
    const ATTEMPTS: usize = 10;
    const EVERY_SECS: u64 = 5;
    for attempt in 1..=ATTEMPTS {
        let result = cp.check_domain_verification(site, host).await?;
        if result.passed {
            // Ownership is recorded server-side now; retract the challenge TXT.
            let _ = provider.delete(&record).await;
            return Ok(DomainOutput::ProviderVerified {
                host: host.to_string(),
                site: site.to_string(),
                attached: result.attached,
            });
        }
        if attempt < ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(EVERY_SECS)).await;
        }
    }

    // Timed out: leave the TXT so a later `domain verify` still succeeds.
    Err(Error::Verify(format!(
        "published the challenge but it did not resolve within {}s — DNS may still \
         be propagating; re-run `boatramp domain verify {host}` shortly",
        ATTEMPTS as u64 * EVERY_SECS
    )))
}

/// Without the `acme-dns` feature there is no bundled DNS provider to publish the
/// challenge with, so `--provider` is unavailable.
#[cfg(not(feature = "acme-dns"))]
async fn add_via_provider(
    _cp: &crate::client::ControlPlane,
    _site: &str,
    _host: &str,
    _provider: Option<&str>,
) -> Result<DomainOutput> {
    Err(Error::Verify(
        "`--provider` requires a build with `--features acme-dns`".into(),
    ))
}

/// List attached hostnames plus any started-but-not-yet-attached verifications.
async fn ls(cp: &crate::client::ControlPlane, site: &str) -> Result<DomainOutput> {
    let site_config = cp.fetch_site_config(site).await?;
    let domains = site_config.domains.clone();

    // Surface challenges that have been started but whose host isn't attached
    // yet (unverified, or verified-but-detached) so the operator knows what's
    // still pending a `domain verify`.
    let attached: std::collections::BTreeSet<String> = domains
        .exact_hosts()
        .map(str::to_string)
        .chain(domains.wildcards.iter().cloned())
        .map(|h| boatramp_core::domain_verify::normalize_host(&h))
        .collect();
    let pending: Vec<_> = cp
        .list_domain_verifications(site)
        .await?
        .into_iter()
        .filter(|v| !attached.contains(&v.host))
        .collect();
    Ok(DomainOutput::List {
        site: site.to_string(),
        domains,
        pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_control_chars_but_keeps_printable() {
        // ESC, newline, CR, tab, DEL → escaped; printable (incl. non-ASCII) kept.
        assert_eq!(
            sanitize_for_terminal("v=spf1\x1b[31m\nok\tx\x7f café"),
            "v=spf1\\x1b[31m\\x0aok\\x09x\\x7f café"
        );
        assert_eq!(
            sanitize_for_terminal("plain.example.com"),
            "plain.example.com"
        );
    }

    #[test]
    fn parse_record_spec_value_may_contain_equals_and_colon() {
        let spec = parse_record_spec("txt/contains:_dmarc.example.com=p=reject;rua=x").unwrap();
        assert_eq!(spec.name, "_dmarc.example.com");
        assert_eq!(spec.value, "p=reject;rua=x");

        // IPv6 A value (colons) survives — split is on the first `=` only.
        let spec = parse_record_spec("a:host.example.com=2001:db8::1").unwrap();
        assert_eq!(spec.value, "2001:db8::1");

        // Contains/Prefix on a non-TXT kind is rejected locally.
        assert!(parse_record_spec("a/contains:example.com=192.0.2.1").is_err());
    }
}
