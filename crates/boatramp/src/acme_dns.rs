//! Wildcard TLS via ACME DNS-01 + DNS auto-config (task #13), wiring the
//! `boatramp-acme` crate into the CLI (`dns` subcommand) and the server
//! (`--tls acme-dns`). Credentials come from the environment, never the config
//! file (the "no secrets in config" rule).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use boatramp_acme::dns::DnsProvider;
use boatramp_acme::{ManualDnsProvider, preview_wildcard};
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
#[derive(Debug)]
struct SniCertResolver {
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

/// Serves the static (wildcard) certs first, then falls back to on-demand per-SNI issuance
/// (cap-req 03). A concrete composite because `ResolvesServerCert::resolve` consumes the
/// `ClientHello` by value — it extracts the SNI + ALPN once and dispatches to each tier's
/// `resolve_sni`. Only built when `[serve.on_demand_tls]` is enabled; otherwise the static resolver
/// is used alone (unchanged).
#[cfg(all(feature = "acme-dns", feature = "cluster"))]
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
}

#[cfg(all(feature = "acme-dns", feature = "cluster"))]
impl ResolvesServerCert for CompositeResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let Some(sni) = hello.server_name() else {
            // No SNI: serve the listener's own cert if it has one (else refuse, as the edge does).
            return self.default_cert.clone();
        };
        let is_acme_alpn = crate::on_demand_tls::is_acme_tls_alpn(&hello);
        // A static (pre-known wildcard) cert wins; else on-demand per-SNI (serve/issue/trigger).
        self.static_resolver
            .resolve_sni(sni)
            .or_else(|| self.on_demand.resolve_sni(sni, is_acme_alpn))
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
fn sni_resolver(entries: Vec<(String, IssuedCert)>) -> Result<Arc<SniCertResolver>> {
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

/// Build a rustls [`ServerConfig`](rustls::ServerConfig) that serves
/// `entries` (`(SNI-pattern, cert)`) by SNI, advertising ALPN `h2`/`http/1.1` so
/// the serving stack negotiates HTTP/2 (the renewal path rebuilds through here, so
/// a hot-swapped config keeps the same ALPN).
pub fn build_server_config(entries: Vec<(String, IssuedCert)>) -> Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(sni_resolver(entries)?);
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    Ok(config)
}

/// Build both the TCP rustls config **and** an HTTP/3-ready one (ALPN `h3`) from
/// the same `entries`, sharing one SNI resolver. `IssuedCert`
/// isn't `Clone`, so this is how the h3 listener gets the same dynamic ACME certs
/// — and the caller swaps the quinn config on renewal exactly as the TCP path
/// reloads. Only the HTTP/3 serve path needs the paired config, so it is gated
/// on `http3` (matching its call sites) — without that feature a lone `acme-dns`
/// build would see it as dead.
#[cfg(feature = "http3")]
pub fn build_server_configs(
    entries: Vec<(String, IssuedCert)>,
) -> Result<(rustls::ServerConfig, rustls::ServerConfig)> {
    let resolver = sni_resolver(entries)?;
    let mut tcp = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    tcp.alpn_protocols = boatramp_server::alpn_h1_h2();
    let mut h3 = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    h3.alpn_protocols = vec![b"h3".to_vec()];
    Ok((tcp, h3))
}

/// A TCP rustls config from an arbitrary cert resolver (shared by the static + composite builders),
/// advertising ALPN `h2`/`http/1.1`.
#[cfg(all(feature = "acme-dns", feature = "cluster"))]
fn server_config_from(resolver: Arc<dyn ResolvesServerCert>) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    config
}

/// Like [`build_server_config`] but composed with an **on-demand** per-SNI resolver (cap-req 03): the
/// static wildcard certs win, then on-demand issuance handles an unknown-but-verified custom domain.
#[cfg(all(feature = "acme-dns", feature = "cluster"))]
pub fn build_server_config_composite(
    entries: Vec<(String, IssuedCert)>,
    on_demand: Arc<crate::on_demand_tls::OnDemandResolver>,
) -> Result<rustls::ServerConfig> {
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
        static_resolver: sni_resolver(entries)?,
        on_demand,
        default_cert: None,
    });
    Ok(server_config_from(resolver))
}

/// Build a rustls [`ServerConfig`](rustls::ServerConfig) for a **dedicated listener** (cap-req 03 #4):
/// its own static cert (served for `server_names` by SNI, and with no SNI) composed with the shared
/// on-demand per-SNI issuer, so a verified custom domain terminating here gets a cert the same way the
/// public edge does.
///
/// Deliberately **protocol-agnostic**: it advertises **no ALPN** and routes nothing through
/// [`server_config_from`] (which would stamp `h2`/`http-1.1`). TLS management must not assume what
/// speaks over the connection — the listener's byte pump owns the protocol, the resolver owns only the
/// handshake. `default_cert` preserves the pre-composite `with_single_cert` behavior for an SNI-less
/// client; `on_demand` is the *same* `Arc` the edge uses, so there is a single rate-limit / issuance
/// budget and a single cluster certreq single-flight (never a second engine — see the design note).
#[cfg(all(feature = "acme-dns", feature = "cluster"))]
pub fn build_listener_server_config_composite(
    cert_pem: &str,
    key_pem: &str,
    server_names: Option<&[String]>,
    on_demand: Arc<crate::on_demand_tls::OnDemandResolver>,
) -> Result<rustls::ServerConfig> {
    let own = Arc::new(certified_key_from_pem(cert_pem, key_pem)?);
    let entries = server_names
        .unwrap_or(&[])
        .iter()
        .map(|name| (name.clone(), own.clone()))
        .collect();
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
        static_resolver: Arc::new(SniCertResolver { entries }),
        on_demand,
        default_cert: Some(own),
    });
    // No ALPN: protocol-agnostic. Build the config directly rather than via `server_config_from`.
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver))
}

/// Like [`build_server_configs`] (TCP + h3) but composed with the on-demand resolver (cap-req 03).
#[cfg(all(feature = "http3", feature = "acme-dns", feature = "cluster"))]
pub fn build_server_configs_composite(
    entries: Vec<(String, IssuedCert)>,
    on_demand: Arc<crate::on_demand_tls::OnDemandResolver>,
) -> Result<(rustls::ServerConfig, rustls::ServerConfig)> {
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(CompositeResolver {
        static_resolver: sni_resolver(entries)?,
        on_demand,
        default_cert: None,
    });
    let tcp = server_config_from(resolver.clone());
    let mut h3 = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    h3.alpn_protocols = vec![b"h3".to_vec()];
    Ok((tcp, h3))
}

/// [`build_server_config`], composed with the on-demand resolver when `on_demand` is `Some` (cap-req
/// 03), else the static resolver alone (unchanged). The serve path calls this at every (re)build site.
#[cfg(all(feature = "acme-dns", feature = "cluster"))]
pub fn build_server_config_maybe(
    entries: Vec<(String, IssuedCert)>,
    on_demand: Option<Arc<crate::on_demand_tls::OnDemandResolver>>,
) -> Result<rustls::ServerConfig> {
    match on_demand {
        Some(r) => build_server_config_composite(entries, r),
        None => build_server_config(entries),
    }
}

/// [`build_server_configs`] (TCP + h3), composed with the on-demand resolver when `Some` (cap-req 03).
#[cfg(all(feature = "http3", feature = "acme-dns", feature = "cluster"))]
pub fn build_server_configs_maybe(
    entries: Vec<(String, IssuedCert)>,
    on_demand: Option<Arc<crate::on_demand_tls::OnDemandResolver>>,
) -> Result<(rustls::ServerConfig, rustls::ServerConfig)> {
    match on_demand {
        Some(r) => build_server_configs_composite(entries, r),
        None => build_server_configs(entries),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "http3")]
    #[test]
    fn build_server_configs_sets_h3_alpn() {
        // rustls 0.23 needs a process crypto provider before building a config
        // (production installs it in `serve`); idempotent here.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        // Empty entries → empty SNI resolver; we only assert the ALPN wiring (the
        // TCP listener advertises h2+http/1.1 for the serve stack; the h3 listener
        // advertises `h3`).
        let (tcp, h3) = build_server_configs(Vec::new()).unwrap();
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
    #[cfg(feature = "cluster")]
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
                    &own_cert,
                    &own_key,
                    Some(&server_names),
                    on_demand,
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
    }
}
