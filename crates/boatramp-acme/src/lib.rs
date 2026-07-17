//! Wildcard TLS provisioning for boatramp preview hosts.
//!
//! The wildcard preview host form `<id>.deploy.<site-host>` (served by the
//! server's host router) needs two things the static path-form preview does
//! not: DNS that resolves `*.deploy.<site-host>` to the server, and a
//! **wildcard** TLS cert — which only the ACME **DNS-01** challenge can issue.
//!
//! This crate provides both, environment-independently (the operator's
//! "uniform UX" principle): a pluggable [`DnsProvider`] layer (the only
//! per-environment piece) plus, behind the `acme` feature, a DNS-01 issuance
//! driver. The DNS abstraction + naming + challenge math are always available
//! and need no network; the ACME driver and the cloud providers are
//! feature-gated so a lean build pulls none of their dependencies.

pub mod dns;

#[cfg(feature = "acme")]
pub mod acme;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

#[cfg(feature = "route53")]
pub mod route53;

#[cfg(feature = "oci")]
pub mod oci;

#[cfg(feature = "digitalocean")]
pub mod digitalocean;

#[cfg(feature = "hetzner")]
pub mod hetzner;

#[cfg(feature = "ns1")]
pub mod ns1;

#[cfg(feature = "dnsimple")]
pub mod dnsimple;

#[cfg(feature = "gcp-dns")]
pub mod gcp_dns;

#[cfg(feature = "azure-dns")]
pub mod azure_dns;

#[cfg(feature = "akamai")]
pub mod akamai;

pub use dns::{
    acme_challenge_name, dns01_txt_value, domain_record, preview_record, preview_wildcard,
    DnsError, DnsOp, DnsProvider, DnsRecord, ManualDnsProvider, PreviewTarget, RecordKind,
};

/// Seconds since the Unix epoch, for the request-signing timestamps the OCI and
/// Akamai DNS providers stamp into their auth headers. (This crate is standalone,
/// so it keeps its own tiny clock read rather than depend on `boatramp-core` for
/// it.) Gated to the providers that use it so a lean build warns on neither.
#[cfg(any(feature = "oci", feature = "akamai"))]
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
