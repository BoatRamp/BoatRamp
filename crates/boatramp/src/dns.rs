//! The `dns` subcommand: auto-configure the preview wildcard DNS record and
//! issue its wildcard TLS cert via ACME DNS-01 (task #13). Credentials for the
//! chosen provider come from the environment (see [`crate::acme_dns`]).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use boatramp_acme::acme::CertRequest;
use boatramp_acme::{domain_record, preview_record, preview_wildcard, PreviewTarget};

use crate::acme_dns::{
    build_provider, build_provider_opts, cloudflare_dns_from_env, obtain_or_load, DnsProviderKind,
};
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
        /// Proxy the record through Cloudflare (orange-cloud: cache/WAF/edge TLS).
        /// Cloudflare-only; ignored by other providers, and forces automatic TTL.
        #[arg(long)]
        proxied: bool,
        /// Cloudflare + wildcard host only: if the zone's **Universal SSL** is enabled,
        /// disable it. Its ACME domain-control-validation TXT at `_acme-challenge.<zone>`
        /// otherwise clobbers a wildcard's DNS-01 delegation (e.g. a fly wildcard cert),
        /// so the wildcard never issues. Safe on a **DNS-only** (not `--proxied`) zone
        /// whose edge cert is unused; needs a token with `Zone.SSL and Certificates:Edit`.
        /// Without this flag, a clear warning is printed instead.
        #[arg(long)]
        disable_cf_universal_ssl: bool,
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
            proxied,
            disable_cf_universal_ssl,
        } => {
            // Preflight: pointing a **wildcard** at a Cloudflare **DNS-only** zone whose
            // Universal SSL is enabled can silently block a wildcard cert validated over
            // DNS-01 (its managed DCV TXT clobbers the `_acme-challenge` delegation).
            // Best-effort: warn (or disable with the flag), but NEVER block the record
            // upsert that is this command's actual job.
            if matches!(provider, DnsProviderKind::Cloudflare) && host.starts_with("*.") && !proxied
            {
                cloudflare_wildcard_ssl_preflight(disable_cf_universal_ssl).await;
            }
            let provider = build_provider_opts(provider, proxied).await?;
            let record = domain_record(&host, &parse_target(&target), ttl);
            provider.upsert(&record).await?;
            println!(
                "pointed {} {} -> {}{}",
                record.kind.as_str(),
                record.name,
                record.value,
                if proxied { " (proxied)" } else { "" }
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

/// Cloudflare + wildcard + DNS-only preflight: check the zone's **Universal SSL** and
/// either disable it (`disable = true`) or print a clear warning. Best-effort — every
/// path returns without error so it can never block the record upsert; a token that
/// lacks `Zone.SSL` permission just yields a "couldn't check" hint.
///
/// See [`CloudflareDns::universal_ssl_enabled`](boatramp_acme::cloudflare::CloudflareDns::universal_ssl_enabled)
/// for why Universal SSL breaks a wildcard's DNS-01 validation.
async fn cloudflare_wildcard_ssl_preflight(disable: bool) {
    let cf = match cloudflare_dns_from_env(false) {
        Ok(cf) => cf,
        // No CF creds in the env — nothing to check (the upsert below will report the
        // missing credential itself).
        Err(_) => return,
    };
    match cf.universal_ssl_enabled().await {
        Ok(true) if disable => match cf.set_universal_ssl(false).await {
            Ok(()) => eprintln!(
                "cloudflare: disabled Universal SSL on this zone (DNS-only) — now re-trigger the \
                 wildcard cert so DNS-01 can validate, e.g. `fly certs remove '*.<domain>'` then \
                 `fly certs add '*.<domain>'`."
            ),
            Err(e) => eprintln!(
                "cloudflare: could not disable Universal SSL ({e}) — the token needs `Zone.SSL \
                 and Certificates:Edit`. Disable it in the dashboard (SSL/TLS → Edge \
                 Certificates) or via `PATCH /zones/<id>/ssl/universal/settings {{\"enabled\":false}}`."
            ),
        },
        Ok(true) => eprintln!(
            "cloudflare: WARNING — Universal SSL is ENABLED on this zone. A wildcard cert \
             validated over DNS-01 (e.g. a fly wildcard) can be blocked: Cloudflare's own \
             domain-control-validation TXT records at `_acme-challenge.<domain>` clobber the \
             DNS-01 delegation, so the wildcard sits \"Not verified\" (exact-host certs over \
             HTTP-01 are unaffected — a confusing asymmetric failure). This zone is DNS-only, so \
             its Cloudflare edge cert is unused: disable Universal SSL — re-run with \
             `--disable-cf-universal-ssl`, or via the dashboard / `PATCH \
             /zones/<id>/ssl/universal/settings {{\"enabled\":false}}` — then re-trigger the \
             wildcard cert. See the wildcard-domain runbook."
        ),
        Ok(false) => {} // Universal SSL off — no conflict.
        Err(e) => eprintln!(
            "cloudflare: could not check Universal SSL ({e}) — the record-upsert token may lack \
             `Zone.SSL and Certificates:Read`. If a wildcard cert won't validate (stuck \"Not \
             verified\"), an enabled Universal SSL is the likely cause; see the wildcard-domain \
             runbook."
        ),
    }
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
