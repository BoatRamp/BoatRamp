//! Wildcard TLS via ACME DNS-01 + DNS auto-config (task #13), wiring the
//! `boatramp-acme` crate into the CLI (`dns` subcommand) and the server
//! (`--tls acme-dns`). Credentials come from the environment, never the config
//! file (the "no secrets in config" rule).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use boatramp_acme::dns::DnsProvider;
use boatramp_acme::{
    DnsError, DnsRecord, ManualDnsProvider, PreviewTarget, RecordKind, domain_record,
    preview_wildcard, validate_writable,
};
use clap::ValueEnum;

/// A failure in the ACME DNS-01 TLS path (the CLI `dns` subcommand and the
/// `--tls acme-dns` serve mode): resolving provider credentials, issuing/loading
/// a cert, or building the rustls serving config.
#[derive(Debug, thiserror::Error)]
// `Acme`/`Rustls` wrap sizeable library error enums next to several unit
// variants; the disparity is fine for a cold error path.
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// A required DNS-provider credential env var is not set.
    #[error("DNS provider: env var {0} is not set")]
    EnvVarNotSet(String),
    /// Reading the OCI private-key file (`OCI_PRIVATE_KEY_FILE`) failed.
    #[error("reading OCI_PRIVATE_KEY_FILE: {0}")]
    OciKeyRead(#[source] std::io::Error),
    /// Constructing the OCI DNS provider failed.
    #[error("{0}")]
    Oci(String),
    /// A PEM chain held no certificates.
    #[error("no certificates in PEM chain")]
    NoCertificates,
    /// A PEM document held no private key.
    #[error("no private key in PEM")]
    NoPrivateKey,
    /// Wraps an underlying error with the cert pattern it was loading.
    #[error("loading certificate for {pattern}: {source}")]
    LoadingCert {
        pattern: String,
        #[source]
        source: Box<Self>,
    },
    /// An ACME DNS-01 issuance failed.
    #[error(transparent)]
    Acme(#[from] boatramp_acme::acme::AcmeError),
    /// A rustls error building the serving config (signing key / config).
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    /// A filesystem error reading/writing the cert cache or parsing PEM input.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `acme_dns` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Which DNS provider backs the auto-config + DNS-01 challenges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DnsProviderKind {
    /// Print the records to create by hand (no credentials needed).
    Manual,
    /// Cloudflare (`CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_API_TOKEN`).
    Cloudflare,
    /// AWS Route 53 (`ROUTE53_HOSTED_ZONE_ID` + the standard AWS env chain).
    Route53,
    /// Oracle Cloud (`OCI_REGION`, `OCI_ZONE`, `OCI_KEY_ID`,
    /// `OCI_PRIVATE_KEY_FILE`).
    Oci,
    /// DigitalOcean (`DIGITALOCEAN_DOMAIN`, `DIGITALOCEAN_TOKEN`).
    #[value(name = "digitalocean", alias = "do")]
    DigitalOcean,
    /// Hetzner Cloud DNS (`HETZNER_ZONE`, `HETZNER_DNS_TOKEN`). The zone is
    /// addressed by name (no numeric id needed), and the token is now a Hetzner
    /// **Cloud** API token (Bearer auth) — the decommissioned classic DNS token
    /// no longer works. `HETZNER_ZONE_ID` is no longer read.
    Hetzner,
    /// NS1 / IBM (`NS1_ZONE`, `NS1_API_KEY`).
    Ns1,
    /// DNSimple (`DNSIMPLE_ACCOUNT_ID`, `DNSIMPLE_ZONE`, `DNSIMPLE_TOKEN`).
    Dnsimple,
    /// Google Cloud DNS (`GCP_DNS_PROJECT`, `GCP_DNS_ZONE`, `GCP_ACCESS_TOKEN`).
    #[value(name = "gcp-dns", alias = "gcp")]
    GcpDns,
    /// Azure DNS (`AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`,
    /// `AZURE_DNS_ZONE`, `AZURE_ACCESS_TOKEN`).
    #[value(name = "azure-dns", alias = "azure")]
    AzureDns,
    /// Akamai Edge DNS (`AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`,
    /// `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN`, `AKAMAI_ZONE`).
    Akamai,
}

fn env(var: &str) -> Result<String> {
    std::env::var(var).map_err(|_| Error::EnvVarNotSet(var.to_string()))
}

/// Build the configured [`DnsProvider`] from environment credentials.
pub async fn build_provider(kind: DnsProviderKind) -> Result<Box<dyn DnsProvider>> {
    build_provider_opts(kind, false).await
}

/// Build a **concrete** Cloudflare provider from the environment (the same
/// construction [`build_provider_opts`] uses for [`DnsProviderKind::Cloudflare`]).
/// Returned unboxed so Cloudflare-specific preflights (e.g. the wildcard Universal-SSL
/// check) can reach methods not on the generic `DnsProvider` trait.
pub fn cloudflare_dns_from_env(proxied: bool) -> Result<boatramp_acme::cloudflare::CloudflareDns> {
    Ok(boatramp_acme::cloudflare::CloudflareDns::new(
        env("CLOUDFLARE_ZONE_ID")?,
        env("CLOUDFLARE_API_TOKEN")?,
    )
    .with_proxied(proxied))
}

/// Like [`build_provider`], but sets Cloudflare's per-record proxy flag
/// (orange-cloud). `proxied` is Cloudflare-specific — every other provider
/// ignores it. Used by `dns configure-domain --proxied`, so proxying is chosen
/// per domain rather than as a global toggle.
pub async fn build_provider_opts(
    kind: DnsProviderKind,
    proxied: bool,
) -> Result<Box<dyn DnsProvider>> {
    Ok(match kind {
        DnsProviderKind::Manual => Box::new(ManualDnsProvider::new()),
        DnsProviderKind::Cloudflare => Box::new(cloudflare_dns_from_env(proxied)?),
        DnsProviderKind::Route53 => Box::new(
            boatramp_acme::route53::Route53Dns::from_env(env("ROUTE53_HOSTED_ZONE_ID")?).await,
        ),
        DnsProviderKind::Oci => {
            let pem =
                std::fs::read_to_string(env("OCI_PRIVATE_KEY_FILE")?).map_err(Error::OciKeyRead)?;
            Box::new(
                boatramp_acme::oci::OciDns::new(
                    &env("OCI_REGION")?,
                    env("OCI_ZONE")?,
                    env("OCI_KEY_ID")?,
                    &pem,
                )
                .map_err(|e| Error::Oci(e.to_string()))?,
            )
        }
        DnsProviderKind::DigitalOcean => {
            Box::new(boatramp_acme::digitalocean::DigitalOceanDns::new(
                env("DIGITALOCEAN_DOMAIN")?,
                env("DIGITALOCEAN_TOKEN")?,
            ))
        }
        DnsProviderKind::Hetzner => Box::new(boatramp_acme::hetzner::HetznerDns::new(
            env("HETZNER_ZONE")?,
            env("HETZNER_DNS_TOKEN")?,
        )),
        DnsProviderKind::Ns1 => Box::new(boatramp_acme::ns1::Ns1Dns::new(
            env("NS1_ZONE")?,
            env("NS1_API_KEY")?,
        )),
        DnsProviderKind::Dnsimple => Box::new(boatramp_acme::dnsimple::DnsimpleDns::new(
            env("DNSIMPLE_ACCOUNT_ID")?,
            env("DNSIMPLE_ZONE")?,
            env("DNSIMPLE_TOKEN")?,
        )),
        DnsProviderKind::GcpDns => Box::new(boatramp_acme::gcp_dns::GcpDns::new(
            env("GCP_DNS_PROJECT")?,
            env("GCP_DNS_ZONE")?,
            env("GCP_ACCESS_TOKEN")?,
        )),
        DnsProviderKind::AzureDns => Box::new(boatramp_acme::azure_dns::AzureDns::new(
            env("AZURE_SUBSCRIPTION_ID")?,
            env("AZURE_RESOURCE_GROUP")?,
            env("AZURE_DNS_ZONE")?,
            env("AZURE_ACCESS_TOKEN")?,
        )),
        DnsProviderKind::Akamai => Box::new(boatramp_acme::akamai::AkamaiDns::new(
            env("AKAMAI_HOST")?,
            env("AKAMAI_CLIENT_TOKEN")?,
            env("AKAMAI_CLIENT_SECRET")?,
            env("AKAMAI_ACCESS_TOKEN")?,
            env("AKAMAI_ZONE")?,
        )),
    })
}

// ---- custom-domain DNS reconcile (capability #24 Stage 6) ------------------
//
// The roadmap's auto-DNS planner (`boatramp_core::dns_managed::plan_reconcile`)
// landed with the ledger it reads, but nothing in the serve loop ever called
// it — the planner existed, unreachable from any live task. This section
// wires it in: a leader-gated background sweep that keeps every site's
// verified custom domains pointed at `--dns-target`, mirroring the
// leader-gated-tick shape of `boatramp_server::spawn_domain_verify_reconcile`
// / `spawn_compute_reconcile` (and this module's own cert-renewal loops in
// `serve.rs`) — the same `is_leader` gate makes it a single-writer in a
// cluster, so a follower never double-writes a zone.

/// Outcome of one [`reconcile_dns_once`] pass, for the loop's tracing summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsReconcileReport {
    /// Verified custom domains (re)pointed this pass (idempotent — `upsert`
    /// re-asserts every verified host every pass, so this counts assertions,
    /// not just changes).
    pub pointed: usize,
    /// Ledger entries retracted because their host is no longer attached.
    pub retracted: usize,
    /// Per-host failures (upsert / delete / ledger read-or-write). Each is
    /// simply retried on the next tick — a failure here never aborts the pass
    /// or the loop.
    pub errors: usize,
}

/// The ledger's serializable mirror of a `DnsRecord` this reconcile pass just
/// wrote. Always `A`/`AAAA`/`CNAME` — the only kinds [`domain_record`] emits.
fn managed_record_from_dns(record: &DnsRecord) -> boatramp_core::dns_managed::ManagedRecord {
    boatramp_core::dns_managed::ManagedRecord {
        kind: record.kind.as_str().to_string(),
        name: record.name.clone(),
        value: record.kind.flat_value(),
        ttl: record.ttl,
    }
}

/// Rebuild the `DnsRecord` a stored [`boatramp_core::dns_managed::ManagedRecord`]
/// describes, so a retract can call `provider.delete`. `None` for a kind this
/// loop never writes (the ledger is reconcile-task-owned, so this is
/// defensive, not expected in practice) — the caller drops such an entry
/// rather than retrying forever on something no `delete` call could fix.
fn dns_record_from_managed(rec: &boatramp_core::dns_managed::ManagedRecord) -> Option<DnsRecord> {
    let kind = match rec.kind.as_str() {
        "A" => RecordKind::A(rec.value.parse().ok()?),
        "AAAA" => RecordKind::Aaaa(rec.value.parse().ok()?),
        "CNAME" => RecordKind::Cname(rec.value.clone()),
        _ => return None,
    };
    Some(DnsRecord {
        kind,
        name: rec.name.clone(),
        ttl: rec.ttl,
    })
}

/// One DNS reconcile pass: for every site, point its verified **custom**
/// domains (`domain add`/`domain verify`-attached hosts — never the
/// `*.deploy.<host>` preview wildcard, which `--tls acme-dns`/`dns setup`
/// manage separately) at `target` via `provider` — `upsert` is contractually
/// idempotent, so a repeat sweep converges rather than duplicating — and
/// retract any ledger entry (`dnsmanaged/<site>/<host>`) whose host is no
/// longer attached (`domain rm`, a deleted site, or just dropping one host
/// from a verified wildcard+apex pair — see [`plan_reconcile`]'s per-raw-host
/// comparison). A per-host or per-provider failure is logged and skipped,
/// never aborts the sweep: one bad zone or a transient provider outage
/// self-heals on the next tick instead of stalling every other site.
pub async fn reconcile_dns_once(
    deploy: &boatramp_core::deploy::DeployStore,
    provider: &dyn DnsProvider,
    provider_name: &str,
    target: &PreviewTarget,
    ttl: u32,
) -> std::result::Result<DnsReconcileReport, boatramp_core::error::DeployError> {
    use boatramp_core::dns_managed::{ManagedDns, plan_reconcile};
    use boatramp_core::project::ProjectRef;
    use boatramp_core::site::SiteName;

    let mut report = DnsReconcileReport::default();
    // The site candidate set is the UNION of two enumerations:
    // - `all_sites_all` (not `list_sites_all`): a site is in scope once it has a
    //   config/activation history, whether or not it has ever been deployed —
    //   mirrors why `list_all_domain_verifications` fans out the same way (a
    //   verified custom domain can exist before the site's first publish).
    // - `list_all_managed_dns`: a site whose config was later wiped entirely via
    //   `delete_site` drops out of `all_sites_all`, but `delete_site` never sweeps
    //   the `dnsmanaged/` ledger — so its stray entries would otherwise become
    //   permanently unreachable (never retracted, the record left live forever).
    let mut sites: std::collections::BTreeSet<(String, String)> =
        deploy.all_sites_all().await?.into_iter().collect();
    for (project, site, _) in deploy.list_all_managed_dns().await? {
        sites.insert((project, site));
    }
    for (project_str, site_str) in sites {
        let project = ProjectRef::new(&project_str);
        let site = SiteName::new(&site_str);

        let verified: Vec<String> = match deploy.get_site_config(project, site.as_str()).await {
            Ok(Some(cfg)) => cfg
                .domains
                .primary
                .iter()
                .cloned()
                .chain(cfg.domains.aliases.iter().cloned())
                .chain(cfg.domains.wildcards.iter().cloned())
                .collect(),
            Ok(None) => Vec::new(),
            Err(err) => {
                tracing::warn!(
                    project = %project_str, site = %site_str, %err,
                    "dns reconcile: site config read failed; skipping this tick"
                );
                report.errors += 1;
                continue;
            }
        };
        let managed_entries = match deploy.list_managed_dns(project, &site).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    project = %project_str, site = %site_str, %err,
                    "dns reconcile: ledger read failed; skipping this tick"
                );
                report.errors += 1;
                continue;
            }
        };
        let managed: Vec<String> = managed_entries.iter().map(|m| m.host.clone()).collect();
        // `plan_reconcile` diffs per RAW host (wildcard preserved, never folded
        // onto its apex) — a `to_point`/`to_retract` entry IS the exact host to
        // write/retract, one ledger entry per entry; see its own docs for why a
        // wildcard and its apex must never be collapsed into one comparison key.
        let plan = plan_reconcile(&verified, &managed);

        for host in &plan.to_point {
            // Fail-closed re-assertion at point of use (parity with the cert path's
            // `is_host_issuance_authorized`): `cfg.domains` can carry a host whose
            // verification record was later dropped (verification and attachment are
            // separate state; only a NEWLY-added host is checked at attach time). A
            // DNS write has no backstop the way ACME issuance does (the CA's own
            // challenge), so this reconcile must re-check every tick, not just once.
            // `is_domain_verified` normalizes internally, so passing the wildcard
            // form here correctly reads the shared base-domain verification record.
            match deploy.is_domain_verified(project, &site, host).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        project = %project_str, site = %site_str, %host,
                        "dns reconcile: host is attached but no longer verified; refusing to point it"
                    );
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        project = %project_str, site = %site_str, %host, %err,
                        "dns reconcile: verification check failed; fail-closed, not pointing this tick"
                    );
                    report.errors += 1;
                    continue;
                }
            }
            let record = domain_record(host, target, ttl);
            if let Err(err) = validate_writable(provider, &record, host) {
                tracing::warn!(
                    project = %project_str, site = %site_str, %host, %err,
                    "dns reconcile: record refused by provider capability; will retry next tick"
                );
                report.errors += 1;
                continue;
            }
            if let Err(err) = provider.upsert(&record).await {
                tracing::warn!(
                    project = %project_str, site = %site_str, %host, %err,
                    "dns reconcile: upsert failed; will retry next tick"
                );
                report.errors += 1;
                continue;
            }
            let ledger = ManagedDns::new(
                host,
                provider_name,
                vec![managed_record_from_dns(&record)],
                now_unix(),
            );
            // A ledger-write failure here leaves a successfully-upserted record untracked
            // until the next tick re-upserts (idempotent) and retries this write — benign,
            // self-closing, never a double DNS write.
            if let Err(err) = deploy.set_managed_dns(project, &site, &ledger).await {
                tracing::warn!(
                    project = %project_str, site = %site_str, %host, %err,
                    "dns reconcile: ledger write failed after upsert; will retry next tick"
                );
                report.errors += 1;
                continue;
            }
            report.pointed += 1;
        }

        for host in &plan.to_retract {
            let Some(entry) = managed_entries.iter().find(|m| &m.host == host) else {
                continue;
            };
            let mut all_deleted = true;
            for rec in &entry.records {
                let Some(dns_record) = dns_record_from_managed(rec) else {
                    tracing::warn!(
                        project = %project_str, site = %site_str, %host, kind = %rec.kind,
                        "dns reconcile: stale ledger record has an unrecognized kind; dropping it"
                    );
                    continue;
                };
                match provider.delete(&dns_record).await {
                    // `NotFound` IS success for `delete` (the trait's own contract: absent is
                    // success, so a retried/already-converged teardown doesn't wedge here).
                    Ok(()) | Err(DnsError::NotFound) => {}
                    Err(err) => {
                        tracing::warn!(
                            project = %project_str, site = %site_str, %host, %err,
                            "dns reconcile: retract failed; will retry next tick"
                        );
                        all_deleted = false;
                        report.errors += 1;
                    }
                }
            }
            if all_deleted {
                if let Err(err) = deploy.remove_managed_dns(project, &site, host).await {
                    tracing::warn!(
                        project = %project_str, site = %site_str, %host, %err,
                        "dns reconcile: ledger removal failed; will retry next tick"
                    );
                    report.errors += 1;
                } else {
                    report.retracted += 1;
                }
            }
        }
    }
    Ok(report)
}

/// Spawn the leader-gated custom-domain DNS reconcile loop. Every `tick`,
/// while `is_leader()`, runs one [`reconcile_dns_once`] pass over every site.
/// Detached for the server's lifetime (mirrors the cert-renewal loops in
/// `serve.rs`, which are spawned the same fire-and-forget way); a pass error
/// is logged and retried next tick, never propagated into — or crashing —
/// the serve loop.
pub fn spawn_dns_reconcile(
    deploy: boatramp_core::deploy::DeployStore,
    provider: Arc<dyn DnsProvider>,
    provider_name: String,
    target: PreviewTarget,
    ttl: u32,
    is_leader: impl Fn() -> bool + Send + Sync + 'static,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        // `interval` fires immediately; skip that first tick so the sweep waits a
        // full period before its first run (mirrors `spawn_domain_verify_reconcile`;
        // the server is already up and serving by the time this first fires).
        interval.tick().await;
        loop {
            interval.tick().await;
            // ACCEPT (not fixed): a leadership-flap window where two nodes both briefly
            // read `is_leader() == true` can double-run a pass — harmless, since `upsert`/
            // `delete` are idempotent; same acceptance as the cert-renewal loop's own
            // leader-gated tick above.
            if !is_leader() {
                continue;
            }
            match reconcile_dns_once(&deploy, provider.as_ref(), &provider_name, &target, ttl).await
            {
                Ok(report) if report.pointed + report.retracted + report.errors > 0 => {
                    tracing::info!(
                        pointed = report.pointed,
                        retracted = report.retracted,
                        errors = report.errors,
                        "dns reconcile",
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(%err, "dns reconcile tick failed"),
            }
        }
    })
}

/// Whether a TLS SNI hostname matches a cert pattern. Exact match, or a single
/// wildcard label (`*.suffix` matches `one-label.suffix`, not `a.b.suffix`).
pub fn sni_matches(pattern: &str, sni: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        match sni.strip_suffix(suffix).and_then(|p| p.strip_suffix('.')) {
            Some(label) => !label.is_empty() && !label.contains('.'),
            None => false,
        }
    } else {
        pattern.eq_ignore_ascii_case(sni)
    }
}

/// The on-disk paths for a domain's cached cert + key + issuance stamp.
fn cache_paths(cache_dir: &Path, domain: &str) -> (PathBuf, PathBuf, PathBuf) {
    // `*` is illegal in many filesystems; encode the wildcard label.
    let safe = domain.replace('*', "_wildcard_");
    let dir = cache_dir.join(safe);
    (
        dir.join("cert.pem"),
        dir.join("key.pem"),
        dir.join("issued_at"),
    )
}

/// Reissue a cached cert once it is older than this (Let's Encrypt certs live
/// ~90 days; renew well before).
const RENEW_AFTER_SECS: u64 = 60 * 24 * 3600;

use boatramp_acme::acme::{CertRequest, IssuedCert};

use boatramp_core::time::now_unix;

/// Load a cached cert for `domain` if present and younger than
/// [`RENEW_AFTER_SECS`]; otherwise `None` (caller reissues).
fn load_fresh(cache_dir: &Path, domain: &str) -> Result<Option<IssuedCert>> {
    let (cert_p, key_p, stamp_p) = cache_paths(cache_dir, domain);
    if !cert_p.exists() || !key_p.exists() || !stamp_p.exists() {
        return Ok(None);
    }
    let issued_at: u64 = std::fs::read_to_string(&stamp_p)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if now_unix().saturating_sub(issued_at) >= RENEW_AFTER_SECS {
        return Ok(None);
    }
    Ok(Some(IssuedCert {
        certificate_pem: std::fs::read_to_string(&cert_p)?,
        private_key_pem: std::fs::read_to_string(&key_p)?,
    }))
}

fn write_cache(cache_dir: &Path, domain: &str, cert: &IssuedCert) -> Result<()> {
    let (cert_p, key_p, stamp_p) = cache_paths(cache_dir, domain);
    if let Some(parent) = cert_p.parent() {
        // The per-domain dir holds the private key, so lock it to the owner
        // (0700) on unix; the key file written below would otherwise be reachable
        // through a group/world-readable directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(parent)?;
    }
    // The cert chain + issuance stamp are public; only the key needs locking down.
    std::fs::write(&cert_p, &cert.certificate_pem)?;
    write_private_key(&key_p, &cert.private_key_pem)?;
    std::fs::write(&stamp_p, now_unix().to_string())?;
    Ok(())
}

/// Write the TLS private key owner-read/write only (0600) on unix so it is never
/// group- or world-readable. Mode 0600 is a unix concept, so other
/// platforms fall back to a plain `std::fs::write`.
fn write_private_key(key_p: &Path, private_key_pem: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(key_p)?;
        f.write_all(private_key_pem.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(key_p, private_key_pem)?;
    Ok(())
}

/// Obtain a cert for `domain` (single-SAN), reusing a fresh cached one. The CA
/// settings come from `base` (directory, contact, timeouts); the `domains`
/// field is overridden with `[domain]`.
pub async fn obtain_or_load(
    domain: &str,
    base: &CertRequest,
    provider: &dyn DnsProvider,
    cache_dir: &Path,
) -> Result<IssuedCert> {
    if let Some(cert) = load_fresh(cache_dir, domain)? {
        tracing::info!(domain, "using cached certificate");
        return Ok(cert);
    }
    tracing::info!(domain, "obtaining certificate via ACME DNS-01");
    let request = CertRequest {
        directory_url: base.directory_url.clone(),
        contact_email: base.contact_email.clone(),
        domains: vec![domain.to_string()],
        dns_ttl: base.dns_ttl,
        propagation_wait: base.propagation_wait,
        propagation_poll_interval: base.propagation_poll_interval,
        timeout: base.timeout,
        extra_root_ca: base.extra_root_ca.clone(),
    };
    let cert = boatramp_acme::acme::obtain_certificate(&request, provider).await?;
    // A genuine CA issuance/renewal (cache hits returned above) — count it for
    // the Prometheus `boatramp_cert_renewals_total` counter.
    boatramp_server::server_metrics().record_cert_renewal();
    write_cache(cache_dir, domain, &cert)?;
    Ok(cert)
}

/// The set of `(SNI-pattern, domain-to-certify)` a server needs: each
/// `--acme-domain` apex, plus its `*.deploy.<host>` wildcard when preview TLS
/// is on. The pattern and the certified domain are the same string.
pub fn server_domains(acme_domains: &[String], wildcard_preview: bool) -> Vec<String> {
    let mut out = Vec::new();
    for domain in acme_domains {
        out.push(domain.clone());
        if wildcard_preview {
            out.push(preview_wildcard(domain));
        }
    }
    out
}

// ---- rustls SNI resolver (serving the obtained certs) ----------------------

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Picks a cached [`CertifiedKey`] by SNI, honoring single-label wildcards
/// (so every `<id>.deploy.<host>` preview is served by the one wildcard cert).
/// `pub(crate)` so the serve path can build the node control-plane set ONCE and share it between the
/// `:443` edge config and the [`NodeCertSource`] handle a `use_node_cert` listener reads (Concept 1).
#[derive(Debug)]
pub(crate) struct SniCertResolver {
    entries: Vec<(String, Arc<CertifiedKey>)>,
}

impl SniCertResolver {
    /// The cached cert matching `sni` (exact or single-label wildcard). Factored out so a composite
    /// resolver can try the static certs first (see [`CompositeResolver`]).
    fn resolve_sni(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.entries
            .iter()
            .find(|(pattern, _)| sni_matches(pattern, sni))
            .map(|(_, key)| key.clone())
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.resolve_sni(hello.server_name()?)
    }
}

/// **Concept 1 — the node's own control-plane certificate source.** The live, hot-swappable set of
/// `--acme-domain` certs the `:443` edge serves (how the NODE obtains + serves its OWN cert, driven by
/// `--tls`/`--acme-domain`). Exposed as a SHARED handle so a `use_node_cert` listener resolves the SAME
/// cert the edge serves — never a one-time snapshot: the `--acme-domain` certs are hot-swapped on
/// renewal (serve.rs), so the renewal loop swaps a fresh [`SniCertResolver`] in via [`store`](Self::store)
/// and every reader (edge + listeners) picks it up on the next handshake (a lock-free atomic load, the
/// same primitive `ReloadableTls` uses).
///
/// This is deliberately SEPARATE from the Concept-2 on-demand engine ([`crate::on_demand_tls`]), which
/// ISSUES certs on demand for OTHER (tenant) domains under the #02 verified-domain gate. A
/// `use_node_cert` listener SERVES this source directly and never touches the on-demand issuance path —
/// so a pure control-plane FQDN (not a tenant attached+verified domain) is served without the
/// tenant-verification gate. See `crates/boatramp/DESIGN-acme-concept-decouple.md`.
#[cfg(feature = "acme-dns")]
#[derive(Clone)]
pub(crate) struct NodeCertSource {
    resolver: Arc<arc_swap::ArcSwap<SniCertResolver>>,
}

#[cfg(feature = "acme-dns")]
impl std::fmt::Debug for NodeCertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCertSource").finish_non_exhaustive()
    }
}

#[cfg(feature = "acme-dns")]
impl NodeCertSource {
    /// Wrap the initial control-plane resolver (the first obtained `--acme-domain` set).
    pub(crate) fn new(resolver: Arc<SniCertResolver>) -> Self {
        Self {
            resolver: Arc::new(arc_swap::ArcSwap::from(resolver)),
        }
    }

    /// Hot-swap the control-plane certs (the ACME renewal loop calls this with the freshly-obtained
    /// set); every reader — the `:443` edge and every `use_node_cert` listener — serves it on the next
    /// handshake. This is what makes the shared handle renewal-safe rather than a stale snapshot.
    pub(crate) fn store(&self, resolver: Arc<SniCertResolver>) {
        self.resolver.store(resolver);
    }

    /// The current control-plane cert for `sni` (exact / single-label wildcard), or `None` when the
    /// node holds no control-plane cert for the name (the managed tier then falls back / fails closed).
    pub(crate) fn resolve_sni(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.resolver.load().resolve_sni(sni)
    }
}

/// A three-tier SNI cert resolver (`ResolvesServerCert::resolve` consumes the `ClientHello` by value,
/// so this extracts the SNI + ALPN once and dispatches to each tier). The tiers keep the two TLS/ACME
/// concepts SEPARATE (see `DESIGN-acme-concept-decouple.md`):
///
/// 1. **managed_names tier (Concept 1):** an SNI in the listener's `server_names` allowlist is served
///    the NODE'S CONTROL-PLANE cert (the same `--acme-domain` cert the `:443` edge serves) directly from
///    [`node_certs`](Self::node_certs) — NEVER the on-demand engine. On a miss it falls back to the
///    listener's own static cert, else fails closed; it never triggers on-demand issuance. Empty managed
///    tier at the edge (so the edge is byte-for-byte unchanged).
/// 2. **catch_all_on_demand tier (Concept 2):** a non-managed SNI is served a static (pre-known) cert
///    if any, else — only when `catch_all_on_demand` — the on-demand per-SNI issuer (project-scope +
///    verified-domain gating intact). The `:443` edge and an `on_demand` catch-all listener set this.
/// 3. **static tier:** the listener's own `cert_file`/`key_file`.
///
/// Only built when `[serve.on_demand_tls]` is enabled (or a listener opts into `use_node_cert` /
/// `on_demand`); otherwise the static resolver is used alone (unchanged).
#[cfg(feature = "acme-dns")]
#[derive(Debug)]
struct CompositeResolver {
    static_resolver: Arc<SniCertResolver>,
    on_demand: Arc<crate::on_demand_tls::OnDemandResolver>,
    /// Cert served when the client sends **no** SNI. `None` at the public edge (an SNI-less handshake
    /// there has no domain to serve and is refused — unchanged). `Some` for a dedicated listener that
    /// carries its own static cert: it preserves the pre-composite `with_single_cert` behavior for a
    /// client that negotiates TLS without SNI, while a client that *does* send a verified SNI still
    /// gets per-domain on-demand issuance. This is transport-level only — nothing here knows or cares
    /// what protocol runs over the connection.
    default_cert: Option<Arc<CertifiedKey>>,
    /// cap-req #29 (Concept 1): the SNI **patterns** the listener serves the NODE'S CONTROL-PLANE cert
    /// for — resolved against [`node_certs`](Self::node_certs), the SAME source backing `:443`, NEVER
    /// the on-demand engine. The listener's own static cert (if any) is only the FALLBACK when the node
    /// holds no control-plane cert for the name. Empty at the edge and for a listener that did not opt
    /// into `use_node_cert` (so the resolution order is byte-for-byte unchanged there). A listener sets
    /// this to its `server_names` allowlist, which BOUNDS managed serving: an SNI outside it never gets
    /// the node cert.
    ///
    /// Matched with the SAME [`sni_matches`] semantics as the static tier (Security review F1):
    /// case-insensitive + single-label wildcard. A plain `HashSet::contains` would be a case-sensitive
    /// EXACT match, so a wildcard or mixed-case `server_names` entry would silently MISS the managed
    /// path and the static tier (which IS wildcard/case-aware) would serve the operator's static cert
    /// instead — a silent node-managed→static downgrade.
    managed_names: Vec<String>,
    /// **Concept 1** — the node's control-plane cert source the managed tier resolves against (the SAME
    /// live, hot-swappable handle the `:443` edge serves from). `Some` only for a `use_node_cert`
    /// listener; `None` at the edge and for a listener that did not opt in (then `managed_names` is
    /// empty and this is never consulted). Resolving the managed tier HERE — not through the on-demand
    /// engine — is the decoupling fix: a pure control-plane FQDN serves without the Concept-2
    /// tenant-verification gate.
    node_certs: Option<NodeCertSource>,
    /// Whether a NON-managed SNI may fall through to on-demand issuance (serve/trigger). `true` at the
    /// `:443` edge and for an `on_demand` catch-all listener (unchanged). `false` for a
    /// `use_node_cert`-only listener, so it serves ONLY its `managed_names` control-plane certs (and
    /// never serves — nor triggers issuance for — a domain outside its declared `server_names`).
    catch_all_on_demand: bool,
}

#[cfg(feature = "acme-dns")]
impl ResolvesServerCert for CompositeResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let Some(sni) = hello.server_name() else {
            // No SNI: serve the listener's own cert if it has one (else refuse, as the edge does).
            return self.default_cert.clone();
        };
        let is_acme_alpn = crate::on_demand_tls::is_acme_tls_alpn(&hello);
        // TIER 1 — managed_names (Concept 1): a listener-declared NODE control-plane name is served the
        // node's OWN cert (the SAME `--acme-domain` cert the `:443` edge serves) straight from
        // `node_certs`. The on-demand engine (Concept 2) is NEVER consulted for a managed name, so no
        // tenant-verification gate and no issuance trigger apply here — a pure control-plane FQDN
        // serves. The node control-plane cert is obtained via DNS-01 by the renewal loop, so a
        // TLS-ALPN-01 validation handshake never targets a managed name at a listener; `is_acme_alpn`
        // is irrelevant to this tier. On a genuine miss (the node holds no cert for the name yet) fall
        // back to the listener's OWN static cert if present, else fail closed — but do NOT trigger
        // on-demand issuance.
        if self
            .managed_names
            .iter()
            .any(|pattern| sni_matches(pattern, sni))
        {
            if let Some(key) = self
                .node_certs
                .as_ref()
                .and_then(|src| src.resolve_sni(sni))
            {
                return Some(key);
            }
            return self.static_resolver.resolve_sni(sni);
        }
        // TIER 2/3 — a NON-managed SNI (Concept 2): a static (pre-known) cert wins; else the catch-all
        // on-demand per-SNI issuer — but ONLY when this config enables it (the `:443` edge, and an
        // `on_demand` listener). A `use_node_cert`-only listener does NOT fall through here, so it never
        // serves or triggers a cert for a domain outside its `managed_names`.
        if let Some(key) = self.static_resolver.resolve_sni(sni) {
            return Some(key);
        }
        if self.catch_all_on_demand {
            return self.on_demand.resolve_sni(sni, is_acme_alpn);
        }
        None
    }
}

/// Parse a PEM chain + key into a rustls [`CertifiedKey`]. `pub(crate)` so the on-demand TLS issuer
/// (cap-req 03) builds the same `CertifiedKey` from a freshly-issued / stored cert.
pub(crate) fn certified_key_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        return Err(Error::NoCertificates);
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or(Error::NoPrivateKey)?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Build the SNI cert resolver from `entries` (`(SNI-pattern, cert)`). Shared by
/// the TCP and HTTP/3 server configs so they serve identical certs from one parse.
/// `pub(crate)` so the serve path can build the node control-plane set ONCE and share that single
/// `Arc<SniCertResolver>` between the `:443` edge config and the [`NodeCertSource`] handle.
pub(crate) fn sni_resolver(entries: Vec<(String, IssuedCert)>) -> Result<Arc<SniCertResolver>> {
    let mut resolved = Vec::new();
    for (pattern, cert) in entries {
        let key = certified_key_from_pem(&cert.certificate_pem, &cert.private_key_pem).map_err(
            |source| Error::LoadingCert {
                pattern: pattern.clone(),
                source: Box::new(source),
            },
        )?;
        resolved.push((pattern, Arc::new(key)));
    }
    Ok(Arc::new(SniCertResolver { entries: resolved }))
}

/// A TCP rustls config from an arbitrary cert resolver (shared by the static + composite builders),
/// advertising ALPN `h2`/`http/1.1`.
#[cfg(feature = "acme-dns")]
fn server_config_from(resolver: Arc<dyn ResolvesServerCert>) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    config
}

/// Build a rustls [`ServerConfig`](rustls::ServerConfig) for a **dedicated listener** (cap-req 03 #4 +
/// cap-req #29), composed from the three [`CompositeResolver`] tiers.
///
/// `static_cert` is the listener's OPTIONAL own `(cert_pem, key_pem)` static pair (cap-req #29): `Some`
/// ⇒ it serves `server_names` by SNI and an SNI-less handshake (and, for a `managed_names` SNI, is the
/// fallback when the node holds no control-plane cert); `None` ⇒ a pure node-cert listener with no
/// static cert (an SNI-less handshake then refuses cleanly, fail-closed).
///
/// `managed_names` (Concept 1) are the SNIs the listener serves the **node CONTROL-PLANE** cert for —
/// its `server_names` allowlist under `use_node_cert`, EMPTY otherwise — resolved against `node_certs`
/// (the SAME source backing `:443`), never the on-demand engine. `node_certs` is therefore `Some` for a
/// `use_node_cert` listener and `None` otherwise. `catch_all_on_demand` (Concept 2) decides whether a
/// NON-managed SNI may still reach the on-demand issuer: `true` for an `on_demand` catch-all listener,
/// `false` for a `use_node_cert`-only listener (bounding managed serving to `managed_names`).
///
/// Deliberately **protocol-agnostic**: it advertises **no ALPN** and routes nothing through
/// [`server_config_from`] (which would stamp `h2`/`http-1.1`). TLS management must not assume what
/// speaks over the connection — the listener's byte pump owns the protocol, the resolver owns only the
/// handshake. `on_demand` (the catch-all tier) is the *same* `Arc` the edge uses (via a project-scoped
/// resolver), so there is a single rate-limit / issuance budget and a single cluster certreq
/// single-flight (never a second engine — see the design note).
#[cfg(feature = "acme-dns")]
pub(crate) fn build_listener_server_config_composite(
    static_cert: Option<(&str, &str)>,
    server_names: &[String],
    managed_names: &[String],
    catch_all_on_demand: bool,
    on_demand: Arc<crate::on_demand_tls::OnDemandResolver>,
    node_certs: Option<NodeCertSource>,
) -> Result<rustls::ServerConfig> {
    // The listener's own static cert is now OPTIONAL (cap-req #29). When present it serves `server_names`
    // by SNI and an SNI-less handshake; when absent there is no static tier (the node control-plane cert
    // is the only source) and an SNI-less handshake has no cert to serve → fail-closed.
    let own = match static_cert {
        Some((cert_pem, key_pem)) => Some(Arc::new(certified_key_from_pem(cert_pem, key_pem)?)),
        None => None,
    };
    let entries = match &own {
        Some(own) => server_names
            .iter()
            .map(|name| (name.clone(), own.clone()))
            .collect(),
        None => Vec::new(),
    };
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
        static_resolver: Arc::new(SniCertResolver { entries }),
        on_demand,
        default_cert: own,
        managed_names: managed_names.to_vec(),
        node_certs,
        catch_all_on_demand,
    });
    // No ALPN: protocol-agnostic. Build the config directly rather than via `server_config_from`.
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver))
}

/// Build the `:443` edge rustls config from a **pre-built** static [`SniCertResolver`], so the serve
/// path can parse the `--acme-domain` set ONCE and share that single `Arc<SniCertResolver>` between the
/// edge config and the [`NodeCertSource`] handle a `use_node_cert` listener reads (one parse, one source
/// of truth, hot-swapped together on renewal). When `on_demand` is `Some` the edge composite has an
/// EMPTY managed tier + `catch_all_on_demand = true` (the public-edge shape); `None` is the static
/// resolver alone with the serving ALPN. Infallible (the fallible PEM parse already happened in
/// [`sni_resolver`]).
#[cfg(feature = "acme-dns")]
pub(crate) fn build_server_config_maybe_from_resolver(
    resolver: Arc<SniCertResolver>,
    on_demand: Option<Arc<crate::on_demand_tls::OnDemandResolver>>,
) -> rustls::ServerConfig {
    match on_demand {
        Some(r) => {
            let composite: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
                static_resolver: resolver,
                on_demand: r,
                default_cert: None,
                managed_names: Vec::new(),
                node_certs: None,
                catch_all_on_demand: true,
            });
            server_config_from(composite)
        }
        None => {
            let mut config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            config.alpn_protocols = boatramp_server::alpn_h1_h2();
            config
        }
    }
}

/// The TCP + h3 edge configs from a **pre-built** static resolver (the renewal-safe shared-handle seam
/// — see [`build_server_config_maybe_from_resolver`]). Both configs share the one resolver so they
/// serve identical certs, and the TCP leg advertises `h2`/`http-1.1` while the h3 leg advertises `h3`.
#[cfg(all(feature = "http3", feature = "acme-dns"))]
pub(crate) fn build_server_configs_maybe_from_resolver(
    resolver: Arc<SniCertResolver>,
    on_demand: Option<Arc<crate::on_demand_tls::OnDemandResolver>>,
) -> (rustls::ServerConfig, rustls::ServerConfig) {
    let (tcp_resolver, h3_resolver): (Arc<dyn ResolvesServerCert>, Arc<dyn ResolvesServerCert>) =
        match on_demand {
            Some(r) => {
                let composite: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
                    static_resolver: resolver,
                    on_demand: r,
                    default_cert: None,
                    managed_names: Vec::new(),
                    node_certs: None,
                    catch_all_on_demand: true,
                });
                (composite.clone(), composite)
            }
            None => (resolver.clone(), resolver),
        };
    let tcp = server_config_from(tcp_resolver);
    let mut h3 = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(h3_resolver);
    h3.alpn_protocols = vec![b"h3".to_vec()];
    (tcp, h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "http3", feature = "acme-dns"))]
    #[test]
    fn build_server_configs_sets_h3_alpn() {
        // rustls 0.23 needs a process crypto provider before building a config
        // (production installs it in `serve`); idempotent here.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        // Empty entries → empty SNI resolver; we only assert the ALPN wiring (the
        // TCP listener advertises h2+http/1.1 for the serve stack; the h3 listener
        // advertises `h3`).
        let (tcp, h3) =
            build_server_configs_maybe_from_resolver(sni_resolver(Vec::new()).unwrap(), None);
        assert_eq!(
            tcp.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "TCP config advertises the serving ALPN"
        );
        assert_eq!(
            h3.alpn_protocols,
            vec![b"h3".to_vec()],
            "h3 config advertises the h3 ALPN"
        );
    }

    /// Forward serve-path consolidation (PLAN §4): the edge builder must build a VALID resolver-only
    /// config from an EMPTY static resolver + `Some(on_demand_resolver)` — the serve-purely-on-demand
    /// case a single-node node (or a cluster follower awaiting the leader) uses when the static set is
    /// empty but on-demand issuance fronts it.
    #[cfg(feature = "acme-dns")]
    #[test]
    fn maybe_empty_entries_with_on_demand_builds_resolver_only_config() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let resolver = std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::from_cache(
            std::sync::Arc::new(crate::on_demand_tls::CertCache::default()),
        ));
        // EMPTY static resolver + an on-demand resolver ⇒ a valid composite config (serves on-demand).
        let cfg = build_server_config_maybe_from_resolver(
            sni_resolver(Vec::new()).unwrap(),
            Some(resolver),
        );
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "the resolver-only config still advertises the serving ALPN"
        );
    }

    #[test]
    fn wildcard_matches_one_label_only() {
        assert!(sni_matches(
            "*.deploy.example.com",
            "abc.deploy.example.com"
        ));
        // Two labels deep does not match a single-level wildcard.
        assert!(!sni_matches(
            "*.deploy.example.com",
            "a.b.deploy.example.com"
        ));
        // Different base.
        assert!(!sni_matches("*.deploy.example.com", "abc.deploy.other.com"));
        // Empty label.
        assert!(!sni_matches("*.deploy.example.com", ".deploy.example.com"));
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(sni_matches("example.com", "Example.COM"));
        assert!(!sni_matches("example.com", "www.example.com"));
    }

    #[test]
    fn cache_paths_encode_wildcard() {
        let (cert, key, stamp) = cache_paths(Path::new("/c"), "*.deploy.example.com");
        assert!(
            cert.to_string_lossy()
                .contains("_wildcard_.deploy.example.com")
        );
        assert!(key.ends_with("key.pem"));
        assert!(stamp.ends_with("issued_at"));
    }

    // The cached private key must not be group/world-readable, and
    // the per-domain dir holding it must be owner-only. (unix permission model)
    #[cfg(unix)]
    #[test]
    fn write_cache_locks_down_key_and_dir() {
        use std::os::unix::fs::PermissionsExt;
        // A unique scratch dir under the system temp root (`tempfile` isn't a dep
        // of this crate). RAII-removed at end of test, even on panic.
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "boatramp-acme-test-{}-{}",
            std::process::id(),
            now_unix()
        )));
        std::fs::create_dir_all(&scratch.0).unwrap();

        let cert = IssuedCert {
            certificate_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
                .to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"
                .to_string(),
        };
        write_cache(&scratch.0, "example.com", &cert).unwrap();

        let (_cert_p, key_p, _stamp_p) = cache_paths(&scratch.0, "example.com");
        let key_mode = std::fs::metadata(&key_p).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, 0o600, "private key must be owner read/write only");

        let dir_mode = std::fs::metadata(key_p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "per-domain cache dir must be owner-only");
    }

    // ---- listener on-demand TLS composite (cap-req 03 #4) -------------------------------------
    // An in-memory rustls handshake (no sockets, no HTTP, no mail grammar — protocol-agnostic) that
    // exercises `build_listener_server_config_composite`'s SNI dispatch end to end: the listener's own
    // static cert serves its `server_names` and an SNI-less handshake; a verified SNI already in the
    // on-demand cache serves that cert; an unknown SNI is refused (no cert ⇒ failed handshake).
    #[cfg(feature = "acme-dns")]
    mod listener_composite {
        use super::*;
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{ClientConnection, DigitallySignedStruct, ServerConnection, SignatureScheme};

        fn self_signed(name: &str) -> (String, String) {
            let kp = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
            let cert = params.self_signed(&kp).unwrap();
            (cert.pem(), kp.serialize_pem())
        }

        /// The leaf cert DER of a PEM chain (what a server presents as `peer_certificates()[0]`).
        fn leaf_der(cert_pem: &str) -> Vec<u8> {
            rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .next()
                .unwrap()
                .unwrap()
                .to_vec()
        }

        /// A client verifier that accepts any server cert — the test asserts WHICH cert the handshake
        /// yielded (or that it failed), not trust-chain validity.
        #[derive(Debug)]
        struct AcceptAny;
        impl ServerCertVerifier for AcceptAny {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                rustls::crypto::aws_lc_rs::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        /// Pump handshake bytes between two in-memory connections until both finish, or `Err` if the
        /// server (e.g.) resolves no cert for the SNI and aborts.
        fn drive(
            client: &mut ClientConnection,
            server: &mut ServerConnection,
        ) -> std::result::Result<(), rustls::Error> {
            for _ in 0..32 {
                let mut c2s = Vec::new();
                while client.wants_write() {
                    client.write_tls(&mut c2s).unwrap();
                }
                if !c2s.is_empty() {
                    let mut rd: &[u8] = &c2s;
                    while !rd.is_empty() {
                        server.read_tls(&mut rd).unwrap();
                    }
                    server.process_new_packets()?;
                }
                let mut s2c = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut s2c).unwrap();
                }
                if !s2c.is_empty() {
                    let mut rd: &[u8] = &s2c;
                    while !rd.is_empty() {
                        client.read_tls(&mut rd).unwrap();
                    }
                    client.process_new_packets()?;
                }
                if !client.is_handshaking() && !server.is_handshaking() {
                    return Ok(());
                }
            }
            Err(rustls::Error::General("handshake did not complete".into()))
        }

        /// The leaf cert a client handshaking with `name` is served, or `None` if the handshake fails.
        fn served_cert(
            config: &std::sync::Arc<rustls::ServerConfig>,
            name: ServerName<'static>,
        ) -> Option<Vec<u8>> {
            let client_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
                .with_no_client_auth();
            let mut client =
                ClientConnection::new(std::sync::Arc::new(client_config), name).unwrap();
            let mut server = ServerConnection::new(config.clone()).unwrap();
            drive(&mut client, &mut server).ok()?;
            client
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| c.as_ref().to_vec())
        }

        #[test]
        fn composite_serves_own_cached_and_refuses_unknown() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            // The listener's own static cert, for one configured server name.
            let (own_cert, own_key) = self_signed("own.example.test");
            // A verified custom domain already issued + cached by the on-demand engine.
            let (cached_cert, cached_key) = self_signed("cached.example.test");
            let cache = std::sync::Arc::new(crate::on_demand_tls::CertCache::default());
            cache.insert_issued(
                "cached.example.test",
                std::sync::Arc::new(certified_key_from_pem(&cached_cert, &cached_key).unwrap()),
            );
            // A from-cache resolver: a miss simply fails the handshake (no engine, no issuance).
            let on_demand =
                std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::from_cache(cache));

            let server_names = vec!["own.example.test".to_string()];
            let config = std::sync::Arc::new(
                build_listener_server_config_composite(
                    Some((&own_cert, &own_key)),
                    &server_names,
                    // An `on_demand` catch-all listener: no managed tier, the catch-all issuer serves a
                    // verified SNI that is NOT a static `server_name`.
                    &[],
                    true,
                    on_demand,
                    None, // no node control-plane source (Concept-1 managed tier is empty here)
                )
                .unwrap(),
            );
            // Protocol-agnostic: the composite advertises no ALPN.
            assert!(
                config.alpn_protocols.is_empty(),
                "listener composite must advertise no ALPN (protocol-agnostic)"
            );

            let own = ServerName::try_from("own.example.test").unwrap();
            let cached = ServerName::try_from("cached.example.test").unwrap();
            let unknown = ServerName::try_from("unseeded.example.test").unwrap();
            // An IP server name makes rustls send NO SNI → exercises the no-SNI default_cert branch.
            let no_sni = ServerName::try_from("127.0.0.1").unwrap();

            assert_eq!(
                served_cert(&config, own).as_deref(),
                Some(leaf_der(&own_cert).as_slice()),
                "own configured server_name is served the listener's static cert"
            );
            assert_eq!(
                served_cert(&config, cached).as_deref(),
                Some(leaf_der(&cached_cert).as_slice()),
                "a verified SNI in the on-demand cache is served that cert"
            );
            assert_eq!(
                served_cert(&config, unknown),
                None,
                "an unknown (unverified, uncached) SNI is refused — no cert, failed handshake"
            );
            assert_eq!(
                served_cert(&config, no_sni).as_deref(),
                Some(leaf_der(&own_cert).as_slice()),
                "an SNI-less handshake is served the listener's own default cert"
            );
            println!(
                "LISTENER ON-DEMAND TLS COMPOSITE OK: own+cached served, unknown refused, no-SNI default"
            );
        }

        /// A [`NodeCertSource`] seeded with `(sni-pattern, cert_pem, key_pem)` entries — the Concept-1
        /// node control-plane source a `use_node_cert` listener resolves its managed tier against (NOT
        /// the on-demand cache). Stands in for the `--acme-domain` certs the `:443` edge serves.
        fn node_source(entries: &[(&str, &str, &str)]) -> NodeCertSource {
            let resolved = entries
                .iter()
                .map(|(pat, cert, key)| {
                    (
                        (*pat).to_string(),
                        std::sync::Arc::new(certified_key_from_pem(cert, key).unwrap()),
                    )
                })
                .collect();
            NodeCertSource::new(std::sync::Arc::new(SniCertResolver { entries: resolved }))
        }

        // cap-req #29 (post-decouple): a `use_node_cert` listener serves the NODE'S CONTROL-PLANE cert
        // (the same `--acme-domain` cert the `:443` edge serves) for a domain in its `server_names`,
        // resolved straight from the shared `node_certs` source — NOT the listener's static cert, and
        // NOT the on-demand engine. The static cert, when present, is only the FALLBACK for a name the
        // node holds no control-plane cert for, and for an SNI-less handshake; with the catch-all OFF
        // (`use_node_cert` alone), an SNI OUTSIDE `server_names` is refused.
        //
        // MUTATION SENSE (what the decouple fix changes): the node control-plane cert lives in
        // `node_certs`, and the on-demand cache is seeded with a DIFFERENT cert for the SAME name. A
        // resolver that (as the pre-fix code did) routed the managed tier through the on-demand engine
        // would serve the on-demand cert; here it must serve the node_certs cert — the two pin the
        // before/after. The no-static-cert variant could not even be constructed before #29.
        #[test]
        fn use_node_cert_serves_node_source_over_static_and_bounds_to_server_names() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            // The node's control-plane cert for the managed name (what the `:443` edge serves). A
            // DIFFERENT static cert also covers that name (the listener's hand-fed fallback).
            let (node_cert, node_key) = self_signed("mail.example.test");
            let (static_cert, static_key) = self_signed("mail.example.test"); // same SAN, distinct key/cert
            // A domain NOT in this listener's `server_names` (the bound) whose cert IS in the on-demand
            // cache — proving the bound holds even for a cert the engine could serve (catch-all is off).
            let (other_cert, other_key) = self_signed("other.example.test");

            // The on-demand engine is seeded with a WRONG cert for the managed name + the out-of-bound
            // name. The managed tier must IGNORE it (served from node_certs); the bound keeps `other`.
            let (ondemand_wrong_cert, ondemand_wrong_key) = self_signed("mail.example.test");
            let cache = std::sync::Arc::new(crate::on_demand_tls::CertCache::default());
            cache.insert_issued(
                "mail.example.test",
                std::sync::Arc::new(
                    certified_key_from_pem(&ondemand_wrong_cert, &ondemand_wrong_key).unwrap(),
                ),
            );
            cache.insert_issued(
                "other.example.test",
                std::sync::Arc::new(certified_key_from_pem(&other_cert, &other_key).unwrap()),
            );
            let on_demand =
                std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::from_cache(cache));

            let node_certs = node_source(&[("mail.example.test", &node_cert, &node_key)]);
            let server_names = vec!["mail.example.test".to_string()];
            // `use_node_cert`-only: managed_names = server_names, catch_all = false, static cert present
            // (as the fallback), node_certs = the control-plane source — the exact shape serve.rs builds
            // for `use_node_cert = true`.
            let config = std::sync::Arc::new(
                build_listener_server_config_composite(
                    Some((&static_cert, &static_key)),
                    &server_names,
                    &server_names, // managed_names
                    false,         // catch_all_on_demand OFF (bounded to server_names)
                    on_demand,
                    Some(node_certs.clone()),
                )
                .unwrap(),
            );

            let mail = ServerName::try_from("mail.example.test").unwrap();
            let other = ServerName::try_from("other.example.test").unwrap();
            let no_sni = ServerName::try_from("127.0.0.1").unwrap();

            // THE decouple fix: the managed `server_name` is served the NODE CONTROL-PLANE cert (from
            // node_certs), NOT the listener's static cert, and NOT the on-demand cache's cert.
            let served_mail = served_cert(&config, mail);
            assert_eq!(
                served_mail.as_deref(),
                Some(leaf_der(&node_cert).as_slice()),
                "a managed server_name is served the node control-plane cert (not static, not on-demand)"
            );
            assert_ne!(
                served_mail.as_deref(),
                Some(leaf_der(&static_cert).as_slice()),
                "the static cert must NOT be preferred for a managed server_name"
            );
            assert_ne!(
                served_mail.as_deref(),
                Some(leaf_der(&ondemand_wrong_cert).as_slice()),
                "the on-demand engine must NOT be consulted for a managed server_name"
            );
            // The security BOUND: a domain OUTSIDE `server_names` is refused — a `use_node_cert`-only
            // listener never serves a cert for a domain it did not declare (catch-all OFF).
            assert_eq!(
                served_cert(&config, other),
                None,
                "a SNI outside server_names is refused (catch-all OFF — bounded to the allowlist)"
            );
            // The static cert is still the SNI-less default (fallback).
            assert_eq!(
                served_cert(&config, no_sni).as_deref(),
                Some(leaf_der(&static_cert).as_slice()),
                "an SNI-less handshake is served the static fallback cert"
            );

            // The PURE node-cert variant (NO static cert) — impossible to construct before #29.
            let config_no_static = std::sync::Arc::new(
                build_listener_server_config_composite(
                    None, // no static cert
                    &server_names,
                    &server_names,
                    false,
                    std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::from_cache(
                        std::sync::Arc::new(crate::on_demand_tls::CertCache::default()),
                    )),
                    Some(node_source(&[("mail.example.test", &node_cert, &node_key)])),
                )
                .unwrap(),
            );
            assert_eq!(
                served_cert(
                    &config_no_static,
                    ServerName::try_from("mail.example.test").unwrap()
                )
                .as_deref(),
                Some(leaf_der(&node_cert).as_slice()),
                "with NO static cert, the managed server_name is still served the node control-plane cert"
            );
            assert_eq!(
                served_cert(
                    &config_no_static,
                    ServerName::try_from("127.0.0.1").unwrap()
                ),
                None,
                "with NO static cert, an SNI-less handshake refuses cleanly (fail-closed)"
            );
            println!(
                "LISTENER USE-NODE-CERT OK: managed server_name served the node CONTROL-PLANE cert \
                 (not static, not on-demand), out-of-allowlist SNI refused, SNI-less falls back to \
                 static or fails closed"
            );
        }

        /// Anti-cheat discriminator (the task's required NEW offline test): a `use_node_cert` managed
        /// name is served from the ACTUAL node control-plane source even when the on-demand `CertCache`
        /// is EMPTY (never pre-seeded). The pre-fix code routed the managed tier through the on-demand
        /// engine, so with an empty cache it would fail the handshake; here it serves the node cert.
        #[test]
        fn use_node_cert_served_from_node_source_with_empty_on_demand_cache() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            let (node_cert, node_key) = self_signed("cp.example.test");
            // The on-demand engine's cache is EMPTY — a miss there fails the handshake (from_cache has a
            // dead trigger). The managed tier must NOT depend on it.
            let on_demand =
                std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::from_cache(
                    std::sync::Arc::new(crate::on_demand_tls::CertCache::default()),
                ));
            let node_certs = node_source(&[("cp.example.test", &node_cert, &node_key)]);
            let server_names = vec!["cp.example.test".to_string()];
            let config = std::sync::Arc::new(
                build_listener_server_config_composite(
                    None, // pure node-cert listener, no static material
                    &server_names,
                    &server_names,
                    false,
                    on_demand,
                    Some(node_certs),
                )
                .unwrap(),
            );
            assert_eq!(
                served_cert(&config, ServerName::try_from("cp.example.test").unwrap()).as_deref(),
                Some(leaf_der(&node_cert).as_slice()),
                "the managed name is served from the node control-plane source with an EMPTY on-demand \
                 cache — proof the managed tier never touches the on-demand engine"
            );
            println!(
                "LISTENER USE-NODE-CERT ANTI-CHEAT OK: node control-plane cert served without any \
                 on-demand cache pre-seeding"
            );
        }

        // CHANGE 1: a `use_node_cert` listener no longer needs the on-demand engine. With `--tls
        // acme-dns` (⇒ a `NodeCertSource` exists) but `[serve.on_demand_tls]` DISABLED, serve.rs builds
        // the listener composite with the PRODUCTION inert on-demand seam
        // ([`crate::on_demand_tls::OnDemandResolver::dead`]) + `catch_all_on_demand = false`: the managed
        // name is served the node control-plane cert, and a non-managed SNI fails closed (no engine to
        // issue). WITHOUT `--tls acme-dns` there is no `node_certs` source, and the managed name itself
        // fails closed — the serve.rs fail-closed branch, pinned here at the composite the branch builds.
        //
        // MUTATION SENSE: the first half (node_certs = Some, dead engine) is the exact shape CHANGE 1's
        // serve.rs arm builds when `use_node_cert` is set with no engine — it must SERVE. The second half
        // (node_certs = None) is the shape when the node is not `--tls acme-dns` — it must REFUSE. Flip
        // either and the paired assertion goes red.
        #[test]
        fn use_node_cert_no_engine_serves_with_source_and_fails_closed_without() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            let (node_cert, node_key) = self_signed("cp.example.test");
            let server_names = vec!["cp.example.test".to_string()];

            // (a) `--tls acme-dns`, on-demand DISABLED: the node control-plane source is present and the
            //     Concept-2 slot is the inert production `dead()` resolver (NOT a test seam).
            let served = {
                let config = std::sync::Arc::new(
                    build_listener_server_config_composite(
                        None, // pure node-cert listener, no static material
                        &server_names,
                        &server_names,
                        false, // catch_all OFF (no engine)
                        crate::on_demand_tls::OnDemandResolver::dead(),
                        Some(node_source(&[("cp.example.test", &node_cert, &node_key)])),
                    )
                    .unwrap(),
                );
                served_cert(&config, ServerName::try_from("cp.example.test").unwrap())
            };
            assert_eq!(
                served.as_deref(),
                Some(leaf_der(&node_cert).as_slice()),
                "use_node_cert serves the node control-plane cert with NO on-demand engine (CHANGE 1)"
            );

            // (b) NOT `--tls acme-dns` (no node_certs source): the managed name fails closed — exactly
            //     the serve.rs fail-closed outcome, expressed at the composite it would build.
            let config_no_source = std::sync::Arc::new(
                build_listener_server_config_composite(
                    None,
                    &server_names,
                    &server_names,
                    false,
                    crate::on_demand_tls::OnDemandResolver::dead(),
                    None, // no node control-plane source (not `--tls acme-dns`)
                )
                .unwrap(),
            );
            assert_eq!(
                served_cert(
                    &config_no_source,
                    ServerName::try_from("cp.example.test").unwrap()
                ),
                None,
                "without a node control-plane source the managed name fails closed (no silent serve)"
            );
            println!(
                "LISTENER USE-NODE-CERT NO-ENGINE OK: served with `--tls acme-dns` + on-demand OFF; \
                 fails closed without a node control-plane source"
            );
        }

        // Security review F1: a WILDCARD or MIXED-CASE `server_names` entry under `use_node_cert` must
        // route a covered concrete SNI to the NODE CONTROL-PLANE path — not silently fall through to the
        // static tier (which IS wildcard/case-aware via `sni_matches`) and serve the operator's static
        // cert. MUTATION SENSE: the pre-fix membership check was a case-sensitive EXACT
        // `HashSet::contains(sni)`, so `foo.wild.example.test` (not literally in the set) and
        // `mixed.example.test` (lowercased SNI vs a `Mixed.Example.Test` entry) MISSED the managed path
        // and the static cert was served. Here they are served from the node control-plane source.
        #[test]
        fn use_node_cert_wildcard_and_mixed_case_route_to_managed() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            // The node control-plane certs (as the renewal loop obtained them): a `*.wild` wildcard
            // control-plane cert + a mixed-case apex. The node_certs source matches them with the SAME
            // wildcard/case-insensitive `sni_matches` semantics as the managed-tier membership check.
            let (wild_cp_cert, wild_cp_key) = self_signed("foo.wild.example.test");
            let (mixed_cp_cert, mixed_cp_key) = self_signed("mixed.example.test");
            // A DIFFERENT static cert that ALSO covers both — what the operator hand-fed and what the
            // pre-fix bug would have served.
            let (static_cert, static_key) = self_signed("static.example.test");

            let node_certs = node_source(&[
                ("*.wild.example.test", &wild_cp_cert, &wild_cp_key),
                ("mixed.example.test", &mixed_cp_cert, &mixed_cp_key),
            ]);
            // The on-demand engine is EMPTY — the managed tier must not touch it.
            let on_demand =
                std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::from_cache(
                    std::sync::Arc::new(crate::on_demand_tls::CertCache::default()),
                ));

            // A wildcard entry + a MIXED-CASE entry — exactly the shapes the EXACT `contains` missed.
            let server_names = vec![
                "*.wild.example.test".to_string(),
                "Mixed.Example.Test".to_string(),
            ];
            let config = std::sync::Arc::new(
                build_listener_server_config_composite(
                    Some((&static_cert, &static_key)),
                    &server_names,
                    &server_names, // managed_names (use_node_cert)
                    false,         // catch_all OFF
                    on_demand,
                    Some(node_certs),
                )
                .unwrap(),
            );

            // A concrete host under the wildcard managed entry → node control-plane cert, not static.
            assert_eq!(
                served_cert(
                    &config,
                    ServerName::try_from("foo.wild.example.test").unwrap()
                )
                .as_deref(),
                Some(leaf_der(&wild_cp_cert).as_slice()),
                "a concrete SNI under a WILDCARD managed server_name is served the node control-plane cert"
            );
            // The mixed-case managed entry → node control-plane cert for the (lowercased) concrete SNI.
            assert_eq!(
                served_cert(&config, ServerName::try_from("mixed.example.test").unwrap())
                    .as_deref(),
                Some(leaf_der(&mixed_cp_cert).as_slice()),
                "a MIXED-CASE managed server_name is matched case-insensitively → node control-plane cert"
            );
            // Neither is the static cert (the pre-fix silent downgrade).
            assert_ne!(
                served_cert(
                    &config,
                    ServerName::try_from("foo.wild.example.test").unwrap()
                )
                .as_deref(),
                Some(leaf_der(&static_cert).as_slice()),
                "the static cert must NOT be served for a wildcard-covered managed name"
            );
            println!(
                "LISTENER USE-NODE-CERT WILDCARD/CASE OK: wildcard + mixed-case server_names route to \
                 the node control-plane path (no silent static downgrade)"
            );
        }

        // Security review F3 (post-decouple): isolate the PROJECT-SCOPE gate on the Concept-2 CATCH-ALL
        // tier. A `on_demand` catch-all listener pinned to project `mine` must NOT serve (nor trigger
        // issuance for) a cross-project SNI (`cross.example.test`, owned by `other`) whose cert is
        // already in the shared cache — the project scope, not a cache miss, is what refuses it. (The
        // Concept-1 managed tier no longer routes through this gate — a `use_node_cert` name is served
        // the NODE control-plane cert directly, bounded only by `server_names`; this test pins the
        // scope gate on the on-demand path, where it still lives and still matters.)
        #[tokio::test]
        async fn on_demand_catch_all_listener_refuses_a_cross_project_sni() {
            use boatramp_core::deploy::DeployStore;
            use boatramp_core::project::ProjectRef;

            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            let store = DeployStore::new(
                std::sync::Arc::new(NullStorage),
                std::sync::Arc::new(boatramp_core::kv::MemoryKv::new()),
            );
            // `cross.example.test` is owned + resolvable under project `other` (NOT `mine`).
            let other_cfg = boatramp_core::config::SiteConfig {
                domains: boatramp_core::config::DomainConfig {
                    primary: Some("cross.example.test".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            };
            store
                .set_site_config(ProjectRef::new("other"), "s", &other_cfg)
                .await
                .unwrap();
            // Warm the synchronous owner cache the scope check reads → cached_owner resolves to `other`.
            assert!(matches!(
                store.resolve_site_by_host("cross.example.test").await,
                Ok(Some(_))
            ));

            // Its cert is ALREADY in the shared cache (as if the edge issued it) — so the ONLY thing
            // that can stop the listener serving it is the project-scope gate, not a cache miss.
            let cache = std::sync::Arc::new(crate::on_demand_tls::CertCache::default());
            let (cross_cert, cross_key) = self_signed("cross.example.test");
            cache.insert_issued(
                "cross.example.test",
                std::sync::Arc::new(certified_key_from_pem(&cross_cert, &cross_key).unwrap()),
            );

            // A scoped resolver for `mine` with a CALLER-OWNED trigger channel, so we can assert no
            // issuance was triggered.
            let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(4);
            let scoped =
                std::sync::Arc::new(crate::on_demand_tls::OnDemandResolver::scoped_with_trigger(
                    cache,
                    "mine".to_string(),
                    store.clone(),
                    tx,
                ));
            // An `on_demand` catch-all listener: NO managed tier (empty), catch-all ON, no node_certs,
            // no static cert. Every presented SNI falls through to the scoped on-demand engine.
            let config = std::sync::Arc::new(
                build_listener_server_config_composite(
                    None,
                    &[],  // server_names
                    &[],  // managed_names (empty — Concept-1 tier off)
                    true, // catch_all_on_demand ON (Concept-2)
                    scoped,
                    None, // no node control-plane source
                )
                .unwrap(),
            );

            // The scope gate refuses: nothing is served for the cross-project domain…
            assert_eq!(
                served_cert(&config, ServerName::try_from("cross.example.test").unwrap()),
                None,
                "a cross-project SNI is NOT served by a scoped catch-all listener, even though cached"
            );
            // …and NO issuance was triggered (a CONFIRMED other-project owner is refused outright — no
            // serve, no trigger).
            assert!(
                rx.try_recv().is_err(),
                "a confirmed other-project SNI must trigger NO issuance (project-scope gate)"
            );
            println!(
                "ON-DEMAND CATCH-ALL CROSS-PROJECT OK: a cached domain owned by another project is \
                 neither served nor triggered (project-scope gate isolated on the Concept-2 tier)"
            );
        }
    }

    // ---- custom-domain DNS reconcile (capability #24 Stage 6) -------------

    /// A no-op blob `Storage` — `DeployStore`'s domain/ledger operations are
    /// KV-only, so this is never touched; it only satisfies `DeployStore::new`'s
    /// constructor (mirrors `on_demand_tls`'s test double of the same name).
    struct NullStorage;
    #[async_trait::async_trait]
    impl boatramp_core::Storage for NullStorage {
        async fn get(
            &self,
            _: &str,
        ) -> std::result::Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> std::result::Result<boatramp_core::GetObject, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: boatramp_core::ByteStream,
            _: boatramp_core::PutMeta,
        ) -> std::result::Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::unsupported("null"))
        }
        async fn head(
            &self,
            _: &str,
        ) -> std::result::Result<boatramp_core::ObjectMeta, boatramp_core::StorageError> {
            Err(boatramp_core::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> std::result::Result<(), boatramp_core::StorageError> {
            Ok(())
        }
        async fn list(
            &self,
            _: &str,
        ) -> std::result::Result<Vec<boatramp_core::ObjectMeta>, boatramp_core::StorageError>
        {
            Ok(Vec::new())
        }
    }

    fn fresh_store() -> boatramp_core::deploy::DeployStore {
        boatramp_core::deploy::DeployStore::new(
            Arc::new(NullStorage),
            Arc::new(boatramp_core::kv::MemoryKv::new()),
        )
    }

    /// A `DnsProvider` whose `upsert` always fails — proves a provider error is
    /// logged + counted, never panics or aborts the whole pass (the fail-safe
    /// contract this reconcile loop must uphold).
    struct FailingUpsertProvider;
    #[async_trait::async_trait]
    impl DnsProvider for FailingUpsertProvider {
        async fn upsert(
            &self,
            _record: &DnsRecord,
        ) -> std::result::Result<(), boatramp_acme::DnsError> {
            Err(boatramp_acme::DnsError::Backend(
                "simulated provider outage".to_string(),
            ))
        }
        async fn delete(
            &self,
            _record: &DnsRecord,
        ) -> std::result::Result<(), boatramp_acme::DnsError> {
            Ok(())
        }
    }

    /// The reconcile planner (`plan_reconcile`) existed with zero live callers
    /// before this change (the roadmap triage's grep-confirmed gap). This test
    /// exercises the wiring end to end: a verified custom domain gets pointed
    /// via the provider AND recorded in the ledger, in one pass.
    #[tokio::test]
    async fn reconcile_dns_once_points_a_verified_domain_and_writes_the_ledger() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        store
            .start_domain_verification(
                project,
                &site,
                "shop.example.test",
                VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "shop.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "shop.example.test")
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(report.pointed, 1, "the one verified domain is pointed");
        assert_eq!(report.retracted, 0);
        assert_eq!(report.errors, 0);

        let recorded = provider.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, boatramp_acme::DnsOp::Upsert);
        assert_eq!(recorded[0].1.name, "shop.example.test");

        let ledger = store
            .get_managed_dns(project, &site, "shop.example.test")
            .await
            .unwrap()
            .expect("the ledger must record the host this pass just pointed");
        assert_eq!(ledger.provider, "manual");
        assert_eq!(ledger.records.len(), 1);
        assert_eq!(ledger.records[0].kind, "A");
        assert_eq!(ledger.records[0].value, "203.0.113.9");
    }

    /// `upsert` is contractually idempotent, so a repeat sweep must converge —
    /// re-assert the SAME record, not grow the ledger or duplicate the write.
    /// Anti-hollow: a reconcile that forgot to normalize/dedupe before writing
    /// the ledger would instead accumulate entries here.
    #[tokio::test]
    async fn reconcile_dns_once_is_idempotent_on_repeat() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        store
            .start_domain_verification(
                project,
                &site,
                "shop.example.test",
                VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "shop.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "shop.example.test")
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());

        reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();
        let second = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(
            second.pointed, 1,
            "a repeat sweep re-asserts the same verified host"
        );
        assert_eq!(
            provider.recorded().len(),
            2,
            "two upserts total — both idempotent creates of the SAME record"
        );
        let entries = store.list_managed_dns(project, &site).await.unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the ledger holds exactly one entry, not a duplicate, after a repeat sweep"
        );
    }

    /// A ledger entry whose host is no longer attached (e.g. `domain rm` ran, or
    /// the site's config lost the alias) must be retracted at the provider AND
    /// dropped from the ledger — the self-heal half of `plan_reconcile`.
    #[tokio::test]
    async fn reconcile_dns_once_retracts_an_orphaned_ledger_entry() {
        use boatramp_core::dns_managed::{ManagedDns, ManagedRecord};
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        // No site domain attached — this ledger entry is already orphaned.
        let ledger = ManagedDns::new(
            "old.example.test",
            "manual",
            vec![ManagedRecord {
                kind: "A".to_string(),
                name: "old.example.test".to_string(),
                value: "203.0.113.9".to_string(),
                ttl: 300,
            }],
            1,
        );
        store
            .set_managed_dns(project, &site, &ledger)
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(report.retracted, 1);
        assert_eq!(report.pointed, 0);
        assert_eq!(report.errors, 0);

        let recorded = provider.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, boatramp_acme::DnsOp::Delete);

        assert!(
            store
                .get_managed_dns(project, &site, "old.example.test")
                .await
                .unwrap()
                .is_none(),
            "the ledger entry is dropped once its record is retracted"
        );
    }

    /// Fail-safe contract: a provider error on `upsert` is logged + counted,
    /// never panics or aborts the whole pass, and leaves no ledger entry for
    /// the failed host (so it is naturally retried on the next tick).
    #[tokio::test]
    async fn reconcile_dns_once_is_fail_safe_on_a_provider_error() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        store
            .start_domain_verification(
                project,
                &site,
                "shop.example.test",
                VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "shop.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "shop.example.test")
            .await
            .unwrap();

        let provider = FailingUpsertProvider;
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .expect("a provider error must not abort the whole pass — it is logged + counted");

        assert_eq!(report.pointed, 0);
        assert_eq!(report.errors, 1);
        assert!(
            store
                .get_managed_dns(project, &site, "shop.example.test")
                .await
                .unwrap()
                .is_none(),
            "no ledger entry is written for a host whose upsert failed"
        );
    }

    /// Security-review HIGH fix: `plan_reconcile` normalizes every host for
    /// comparison, which STRIPS a leading `*.` — so a `to_point` entry for a
    /// verified wildcard is the bare apex string. Writing that verbatim would
    /// silently clobber the customer's apex record every tick while never
    /// writing the wildcard it was actually supposed to point. This asserts
    /// the record actually written carries the WILDCARD name, and that the
    /// apex is never touched.
    #[tokio::test]
    async fn reconcile_dns_once_points_a_wildcard_as_a_wildcard_not_the_apex() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        // A wildcard verification record is keyed on its normalized (apex) form —
        // `attach_verified_domain` below is what records the WILDCARD spelling into
        // `domains.wildcards`.
        store
            .start_domain_verification(
                project,
                &site,
                "*.example.test",
                VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "*.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "*.example.test")
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(report.pointed, 1);
        let recorded = provider.recorded();
        assert_eq!(recorded.len(), 1, "exactly one record is written");
        assert_eq!(
            recorded[0].1.name, "*.example.test",
            "the record NAME must be the wildcard, not the apex `plan_reconcile` compares on"
        );
        assert!(
            recorded.iter().all(|(_, r)| r.name != "example.test"),
            "the apex must NEVER be written when only the wildcard is verified"
        );
    }

    /// Security-review HIGH fix, the collapse case: a verified wildcard AND its
    /// verified apex share ONE verification record but must be written and
    /// LEDGERED distinctly (not collapsed into one write/one ledger entry,
    /// one silently dropped) — each is independently trackable and retractable.
    #[tokio::test]
    async fn reconcile_dns_once_writes_wildcard_and_apex_distinctly_when_both_verified() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        // One verification record (keyed on the shared normalized form) backs both
        // attachments — exactly how a real `domain add *.example.test` + `domain add
        // example.test` pair converges in production.
        store
            .start_domain_verification(project, &site, "example.test", VerificationMethod::Dns, 100)
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "*.example.test")
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(
            report.pointed, 2,
            "both the apex and the wildcard are written"
        );
        let mut names: Vec<String> = provider
            .recorded()
            .into_iter()
            .map(|(_, r)| r.name)
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["*.example.test".to_string(), "example.test".to_string()]
        );

        // Each is its OWN ledger entry (per-raw-host keying, wildcard preserved) —
        // never collapsed into one shared entry, so each is independently
        // retractable without disturbing the other.
        let apex_ledger = store
            .get_managed_dns(project, &site, "example.test")
            .await
            .unwrap()
            .expect("the apex has its own ledger entry");
        assert_eq!(apex_ledger.records.len(), 1);
        assert_eq!(apex_ledger.records[0].name, "example.test");

        let wildcard_ledger = store
            .get_managed_dns(project, &site, "*.example.test")
            .await
            .unwrap()
            .expect("the wildcard has its OWN ledger entry, distinct from the apex");
        assert_eq!(wildcard_ledger.records.len(), 1);
        assert_eq!(wildcard_ledger.records[0].name, "*.example.test");
    }

    /// Security-review (round 2) MEDIUM fix — the subset-removal orphan: the
    /// ledger is keyed per RAW host, so dropping just `*.example.test` from
    /// `cfg.domains` (its shared verification record untouched, the apex still
    /// verified+attached) must RETRACT the wildcard's ledger entry AND delete
    /// its provider record — never silently drop it from tracking while it
    /// stays live (a dangling catch-all the operator asked to remove).
    #[tokio::test]
    async fn reconcile_dns_once_retracts_a_dropped_wildcard_without_touching_the_surviving_apex() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        store
            .start_domain_verification(project, &site, "example.test", VerificationMethod::Dns, 100)
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "*.example.test")
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        // First pass: both the apex and the wildcard get pointed + ledgered.
        reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();
        assert!(
            store
                .get_managed_dns(project, &site, "*.example.test")
                .await
                .unwrap()
                .is_some()
        );

        // Declarative drop: a `set_site_config` that re-writes `domains` with only
        // the apex alias (the verification store is untouched — `example.test`'s
        // shared verification record stays verified) — simulates `apply`/`PUT
        // site-config` re-adding aliases but not wildcards.
        let mut cfg = store
            .get_site_config(project, "storefront")
            .await
            .unwrap()
            .unwrap();
        cfg.domains.wildcards.clear();
        store
            .set_site_config(project, "storefront", &cfg)
            .await
            .unwrap();

        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(
            report.retracted, 1,
            "the dropped wildcard's ledger entry is retracted"
        );
        // The wildcard's record is actually DELETED at the provider — not just
        // dropped from the ledger while staying live.
        let recorded = provider.recorded();
        let deletes: Vec<&DnsRecord> = recorded
            .iter()
            .filter(|(op, _)| *op == boatramp_acme::DnsOp::Delete)
            .map(|(_, r)| r)
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].name, "*.example.test");
        assert!(
            store
                .get_managed_dns(project, &site, "*.example.test")
                .await
                .unwrap()
                .is_none(),
            "the wildcard's ledger entry must be gone, not orphaned"
        );
        // The apex is untouched: still ledgered, never retracted.
        assert!(
            store
                .get_managed_dns(project, &site, "example.test")
                .await
                .unwrap()
                .is_some(),
            "the surviving apex must stay pointed and ledgered"
        );
    }

    /// Security-review MEDIUM fix: `cfg.domains` is read directly for the
    /// "verified" set, but attachment and verification are SEPARATE state — a
    /// host's verification record can be dropped after it was attached (or, as
    /// here, never existed at all; only a newly-added host is checked at attach
    /// time). A DNS write has no backstop the way ACME issuance does, so this
    /// must re-assert verification at point of use, every tick, fail-closed.
    #[tokio::test]
    async fn reconcile_dns_once_refuses_to_point_an_attached_but_unverified_host() {
        use boatramp_core::config::{DomainConfig, SiteConfig};
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        // Written directly (like a raw `set_site_config`, or verification dropped
        // after the fact) — no `start_domain_verification`/`mark_domain_verified` at
        // all, so this host has NO verification record.
        let cfg = SiteConfig {
            domains: DomainConfig {
                primary: Some("attached-not-verified.example.test".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        store
            .set_site_config(project, "storefront", &cfg)
            .await
            .unwrap();

        let provider = ManualDnsProvider::new();
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(
            report.pointed, 0,
            "an attached-but-unverified host must never be pointed"
        );
        assert!(provider.recorded().is_empty());
        assert!(
            store
                .get_managed_dns(project, &site, "attached-not-verified.example.test")
                .await
                .unwrap()
                .is_none(),
            "no ledger entry for a host that was refused"
        );
    }

    /// Security-review LOW fix: `delete`'s own contract treats "already absent"
    /// as success (so a retried/already-converged teardown never wedges) — the
    /// retract path must honor that, not treat `DnsError::NotFound` as a failure
    /// that permanently strands the ledger entry.
    #[tokio::test]
    async fn reconcile_dns_once_retract_treats_not_found_as_success() {
        use boatramp_core::dns_managed::{ManagedDns, ManagedRecord};
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;

        struct NotFoundOnDeleteProvider;
        #[async_trait::async_trait]
        impl DnsProvider for NotFoundOnDeleteProvider {
            async fn upsert(&self, _record: &DnsRecord) -> std::result::Result<(), DnsError> {
                Ok(())
            }
            async fn delete(&self, _record: &DnsRecord) -> std::result::Result<(), DnsError> {
                Err(DnsError::NotFound)
            }
        }

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        let ledger = ManagedDns::new(
            "old.example.test",
            "manual",
            vec![ManagedRecord {
                kind: "A".to_string(),
                name: "old.example.test".to_string(),
                value: "203.0.113.9".to_string(),
                ttl: 300,
            }],
            1,
        );
        store
            .set_managed_dns(project, &site, &ledger)
            .await
            .unwrap();

        let provider = NotFoundOnDeleteProvider;
        let target = PreviewTarget::Ipv4("203.0.113.9".parse().unwrap());
        let report = reconcile_dns_once(&store, &provider, "manual", &target, 300)
            .await
            .unwrap();

        assert_eq!(
            report.retracted, 1,
            "NotFound on delete must count as success, not failure"
        );
        assert_eq!(report.errors, 0);
        assert!(
            store
                .get_managed_dns(project, &site, "old.example.test")
                .await
                .unwrap()
                .is_none(),
            "the ledger entry must still be dropped when the provider says NotFound"
        );
    }

    /// The leader-gated **trigger**: `spawn_dns_reconcile` must stay a no-op
    /// tick after tick while `is_leader()` is false (no split-brain double-
    /// writes in a cluster), then run the very next time it observes leadership
    /// — proven end to end via the ledger, not by inspecting the loop's
    /// internals. Uses the virtual clock (`start_paused`) so the gate is exact,
    /// not a timing guess.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn spawn_dns_reconcile_runs_only_while_leader() {
        use boatramp_core::domain_verify::VerificationMethod;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::site::SiteName;
        use std::sync::atomic::{AtomicBool, Ordering};

        let store = fresh_store();
        let project = ProjectRef::DEFAULT;
        let site = SiteName::new("storefront");
        store
            .start_domain_verification(
                project,
                &site,
                "shop.example.test",
                VerificationMethod::Dns,
                100,
            )
            .await
            .unwrap();
        store
            .mark_domain_verified(project, &site, "shop.example.test")
            .await
            .unwrap();
        store
            .attach_verified_domain(project, &site, "shop.example.test")
            .await
            .unwrap();

        let provider: Arc<dyn DnsProvider> = Arc::new(ManualDnsProvider::new());
        let is_leader_flag = Arc::new(AtomicBool::new(false));
        let gate = {
            let flag = is_leader_flag.clone();
            move || flag.load(Ordering::SeqCst)
        };
        let tick = std::time::Duration::from_secs(60);
        let handle = spawn_dns_reconcile(
            store.clone(),
            provider,
            "manual".to_string(),
            PreviewTarget::Ipv4("203.0.113.9".parse().unwrap()),
            300,
            gate,
            tick,
        );

        tokio::task::yield_now().await;
        // Several ticks pass while NOT leader — the gate must keep every pass a no-op.
        for _ in 0..3 {
            tokio::time::advance(tick).await;
            tokio::task::yield_now().await;
        }
        assert!(
            store
                .get_managed_dns(project, &site, "shop.example.test")
                .await
                .unwrap()
                .is_none(),
            "the reconcile loop must write nothing while `is_leader` is false"
        );

        // Become leader; the NEXT tick must run — and land — the pass.
        is_leader_flag.store(true, Ordering::SeqCst);
        tokio::time::advance(tick).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }

        handle.abort();
        assert!(
            store
                .get_managed_dns(project, &site, "shop.example.test")
                .await
                .unwrap()
                .is_some(),
            "once leader, the next tick must point the verified domain"
        );
    }
}
