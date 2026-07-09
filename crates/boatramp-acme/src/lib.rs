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

pub use dns::{
    acme_challenge_name, dns01_txt_value, preview_record, preview_wildcard, DnsError, DnsOp,
    DnsProvider, DnsRecord, ManualDnsProvider, PreviewTarget, RecordKind,
};
