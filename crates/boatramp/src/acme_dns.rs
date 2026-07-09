//! Wildcard TLS via ACME DNS-01 + DNS auto-config (task #13), wiring the
//! `boatramp-acme` crate into the CLI (`dns` subcommand) and the server
//! (`--tls acme-dns`). Credentials come from the environment, never the config
//! file (the "no secrets in config" rule).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use boatramp_acme::dns::DnsProvider;
use boatramp_acme::{preview_wildcard, ManualDnsProvider};
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
        source: Box<Error>,
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
    /// Hetzner DNS (`HETZNER_ZONE_ID`, `HETZNER_ZONE`, `HETZNER_DNS_TOKEN`).
    Hetzner,
    /// NS1 / IBM (`NS1_ZONE`, `NS1_API_KEY`).
    Ns1,
    /// DNSimple (`DNSIMPLE_ACCOUNT_ID`, `DNSIMPLE_ZONE`, `DNSIMPLE_TOKEN`).
    Dnsimple,
}

fn env(var: &str) -> Result<String> {
    std::env::var(var).map_err(|_| Error::EnvVarNotSet(var.to_string()))
}

/// Build the configured [`DnsProvider`] from environment credentials.
pub async fn build_provider(kind: DnsProviderKind) -> Result<Box<dyn DnsProvider>> {
    Ok(match kind {
        DnsProviderKind::Manual => Box::new(ManualDnsProvider::new()),
        DnsProviderKind::Cloudflare => Box::new(boatramp_acme::cloudflare::CloudflareDns::new(
            env("CLOUDFLARE_ZONE_ID")?,
            env("CLOUDFLARE_API_TOKEN")?,
        )),
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
            env("HETZNER_ZONE_ID")?,
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
    })
}

/// Whether a TLS SNI hostname matches a cert pattern. Exact match, or a single
/// wildcard label (`*.suffix` matches `one-label.suffix`, not `a.b.suffix`).
pub fn host_matches(pattern: &str, sni: &str) -> bool {
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
    if now_secs().saturating_sub(issued_at) >= RENEW_AFTER_SECS {
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
    std::fs::write(&stamp_p, now_secs().to_string())?;
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
        propagation_delay: base.propagation_delay,
        timeout: base.timeout,
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

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        self.entries
            .iter()
            .find(|(pattern, _)| host_matches(pattern, sni))
            .map(|(_, key)| key.clone())
    }
}

/// Parse a PEM chain + key into a rustls [`CertifiedKey`].
fn certified_key_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
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
/// `entries` (`(SNI-pattern, cert)`) by SNI.
pub fn build_server_config(entries: Vec<(String, IssuedCert)>) -> Result<rustls::ServerConfig> {
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(sni_resolver(entries)?))
}

/// Build both the TCP rustls config **and** an HTTP/3-ready one (ALPN `h3`) from
/// the same `entries`, sharing one SNI resolver. `IssuedCert`
/// isn't `Clone`, so this is how the h3 listener gets the same dynamic ACME certs
/// — and the caller swaps the quinn config on renewal exactly as the TCP path
/// reloads.
pub fn build_server_configs(
    entries: Vec<(String, IssuedCert)>,
) -> Result<(rustls::ServerConfig, rustls::ServerConfig)> {
    let resolver = sni_resolver(entries)?;
    let tcp = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    let mut h3 = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    h3.alpn_protocols = vec![b"h3".to_vec()];
    Ok((tcp, h3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_server_configs_sets_h3_alpn() {
        // rustls 0.23 needs a process crypto provider before building a config
        // (production installs it in `serve`); idempotent here.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        // Empty entries → empty SNI resolver; we only assert the ALPN wiring (the
        // h3 listener must advertise `h3`, the TCP one must not force it).
        let (tcp, h3) = build_server_configs(Vec::new()).unwrap();
        assert!(tcp.alpn_protocols.is_empty(), "TCP config forces no ALPN");
        assert_eq!(
            h3.alpn_protocols,
            vec![b"h3".to_vec()],
            "h3 config advertises the h3 ALPN"
        );
    }

    #[test]
    fn wildcard_matches_one_label_only() {
        assert!(host_matches(
            "*.deploy.example.com",
            "abc.deploy.example.com"
        ));
        // Two labels deep does not match a single-level wildcard.
        assert!(!host_matches(
            "*.deploy.example.com",
            "a.b.deploy.example.com"
        ));
        // Different base.
        assert!(!host_matches(
            "*.deploy.example.com",
            "abc.deploy.other.com"
        ));
        // Empty label.
        assert!(!host_matches("*.deploy.example.com", ".deploy.example.com"));
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(host_matches("example.com", "Example.COM"));
        assert!(!host_matches("example.com", "www.example.com"));
    }

    #[test]
    fn cache_paths_encode_wildcard() {
        let (cert, key, stamp) = cache_paths(Path::new("/c"), "*.deploy.example.com");
        assert!(cert
            .to_string_lossy()
            .contains("_wildcard_.deploy.example.com"));
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
            now_secs()
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
}
