//! The `dns` subcommand: auto-configure the preview wildcard DNS record and
//! issue its wildcard TLS cert via ACME DNS-01 (task #13). Credentials for the
//! chosen provider come from the environment (see [`crate::acme_dns`]).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use boatramp_acme::acme::CertRequest;
use boatramp_acme::{domain_record, preview_record, preview_wildcard, PreviewTarget};

use crate::acme_dns::{build_provider, obtain_or_load, DnsProviderKind};
use crate::config::ProjectConfig;

/// A failure in the `dns` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Upserting/deleting the DNS record at the provider failed.
    #[error(transparent)]
    Provider(#[from] boatramp_acme::DnsError),
    /// Building the provider or obtaining the certificate failed (the
    /// [`crate::acme_dns`] helpers: env-var resolution, ACME DNS-01 issuance,
    /// or cert-cache I/O).
    #[error(transparent)]
    Acme(#[from] crate::acme_dns::Error),
}

/// `dns` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp dns`.
#[derive(Debug, clap::Args)]
pub struct DnsArgs {
    #[command(subcommand)]
    command: DnsCommand,
}

#[derive(Debug, clap::Subcommand)]
enum DnsCommand {
    /// Create the `*.deploy.<host>` record so by-id preview subdomains resolve
    /// to this server.
    Setup {
        /// DNS provider (`manual` prints the record to create by hand).
        #[arg(long, value_enum)]
        provider: DnsProviderKind,
        /// The site host, e.g. `example.com` (the record is `*.deploy.<host>`).
        #[arg(long)]
        host: String,
        /// Where the wildcard points: an IPv4/IPv6 address (→ A/AAAA) or another
        /// hostname (→ CNAME).
        #[arg(long)]
        target: String,
        /// Record TTL (seconds).
        #[arg(long, default_value_t = 120)]
        ttl: u32,
    },
    /// Point a **verified** custom domain (apex or sub-domain) at this server by
    /// upserting its A/AAAA/CNAME record via the provider. Verify ownership first
    /// (`boatramp domain add/verify`) — never point a host you don't control.
    ConfigureDomain {
        /// DNS provider (`manual` prints the record to create by hand).
        #[arg(long, value_enum)]
        provider: DnsProviderKind,
        /// The custom hostname, e.g. `www.example.com` or the apex `example.com`.
        host: String,
        /// Where it points: an IPv4/IPv6 address (→ A/AAAA) or another hostname
        /// (→ CNAME; invalid at a true apex — use an address there).
        #[arg(long)]
        target: String,
        /// Record TTL (seconds).
        #[arg(long, default_value_t = 300)]
        ttl: u32,
    },
    /// Issue (or renew) the `*.deploy.<host>` wildcard certificate via ACME
    /// DNS-01, into the cert cache `boatramp serve --tls acme-dns` reads.
    Cert {
        #[arg(long, value_enum)]
        provider: DnsProviderKind,
        /// The site host; the cert covers `*.deploy.<host>`.
        #[arg(long)]
        host: String,
        /// ACME directory URL (defaults to Let's Encrypt production).
        #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
        acme_directory: String,
        /// Contact email for the ACME account.
        #[arg(long)]
        acme_contact: Option<String>,
        /// Certificate cache directory.
        #[arg(long, default_value = "./data/acme")]
        cache: PathBuf,
    },
}

/// Entry point for `boatramp dns`.
pub async fn run(args: DnsArgs, _config: &ProjectConfig) -> Result<()> {
    match args.command {
        DnsCommand::Setup {
            provider,
            host,
            target,
            ttl,
        } => {
            let provider = build_provider(provider).await?;
            let record = preview_record(&host, &parse_target(&target), ttl);
            provider.upsert(&record).await?;
            println!(
                "configured {} {} -> {}",
                record.kind.as_str(),
                record.name,
                record.value
            );
        }
        DnsCommand::ConfigureDomain {
            provider,
            host,
            target,
            ttl,
        } => {
            let provider = build_provider(provider).await?;
            let record = domain_record(&host, &parse_target(&target), ttl);
            provider.upsert(&record).await?;
            println!(
                "pointed {} {} -> {}",
                record.kind.as_str(),
                record.name,
                record.value
            );
        }
        DnsCommand::Cert {
            provider,
            host,
            acme_directory,
            acme_contact,
            cache,
        } => {
            let provider = build_provider(provider).await?;
            let wildcard = preview_wildcard(&host);
            let base = CertRequest {
                directory_url: acme_directory,
                contact_email: acme_contact,
                domains: Vec::new(),
                dns_ttl: 60,
                propagation_delay: Duration::from_secs(15),
                timeout: Duration::from_secs(120),
            };
            obtain_or_load(&wildcard, &base, provider.as_ref(), &cache).await?;
            println!("certificate for {wildcard} ready under {}", cache.display());
        }
    }
    Ok(())
}

/// An IPv4/IPv6 literal becomes an address record; anything else a `CNAME`.
fn parse_target(target: &str) -> PreviewTarget {
    if let Ok(v4) = target.parse::<Ipv4Addr>() {
        PreviewTarget::Ipv4(v4)
    } else if let Ok(v6) = target.parse::<Ipv6Addr>() {
        PreviewTarget::Ipv6(v6)
    } else {
        PreviewTarget::Cname(target.to_string())
    }
}
