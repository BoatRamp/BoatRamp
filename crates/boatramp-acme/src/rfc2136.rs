//! RFC 2136 dynamic DNS UPDATE provider with RFC 8945 (ex-RFC 2845) TSIG signing
//! — the self-hosted analogue of the ten REST providers, for operators running
//! their own authoritative BIND / PowerDNS / Knot. Instead of a vendor REST API
//! it speaks the DNS wire protocol: an `UPDATE` opcode message carrying the
//! add/delete instructions, authenticated end-to-end with a shared TSIG key.
//!
//! # Why this is the lightest correct dependency
//!
//! The DNS-wire codec (`op::Message`, the RFC 2136 section model) and the RFC
//! 8945 TSIG implementation come from [`hickory_proto`], which is **already in
//! the dependency tree** (the `acme` feature pulls `hickory-resolver`, which
//! depends on it, and `boatramp-overlay-tunnel` depends on it directly). The
//! `rfc2136` feature therefore adds **no new crate** — it only turns on
//! `hickory-proto`'s `dnssec-ring` feature, whose TSIG HMAC runs over the `ring`
//! crate the `oci` / `gcp-dns` adapters already compile. A full third-party DNS
//! *client* (hickory-client, with its async runtime + rustls TLS transport)
//! would have been the heavy option; we deliberately use only the message codec
//! and the signer, **hand-rolling the UDP/TCP exchange over `tokio`**, so no
//! `rustls`/`__tls`/`__quic` stack is dragged in.
//!
//! # Wire operations (RFC 2136 §2.5)
//!
//! Every `upsert`/`delete` is ONE signed `UPDATE` message to the configured
//! authoritative server:
//!   * **Zone section** — the `zone` apex (an `SOA`-typed query), the only place
//!     a record may live; an owner outside it is refused (never sent).
//!   * **upsert of `TXT`** — "Add to an RRset" (§2.5.1): a single add record,
//!     zone class, so a **second** TXT value at the same owner (the wildcard +
//!     apex `_acme-challenge` / `_boatramp-verify` case) **coexists** rather than
//!     clobbering the first. Adding an identical RR is a documented no-op, so a
//!     retried challenge converges — idempotent by the protocol.
//!   * **upsert of `A`/`AAAA`/`CNAME`** — atomic replace: "Delete an RRset"
//!     (§2.5.2, class `ANY`) **then** add the new record, in one message, so
//!     pointing a host at a new address/alias leaves exactly one record and a
//!     re-run converges. (A `CNAME` is single-valued, and custom-domain pointing
//!     wants replace, not accumulate — unlike the additive challenge `TXT`.)
//!   * **delete** — "Delete an RR from an RRset" (§2.5.4, class `NONE`): removes
//!     exactly the one record's rdata, leaving any sibling values (so cleaning up
//!     one `_acme-challenge` value does not strip a concurrent one). Deleting an
//!     absent record is a protocol no-op (the server silently ignores it), so
//!     `delete` is idempotent and "already gone" is success — no `NotFound`.
//!
//! # Credential custody
//!
//! The TSIG key (name, algorithm, secret) is **operator config, never guest
//! input**. The secret is a base64 HMAC key decoded once at construction into the
//! [`TSigner`]; it is never logged (provider errors carry RCODEs / transport
//! detail, not key material) and in the config-file path arrives through the same
//! sealed-store / `env:` pointer the other providers' secrets use — never a
//! plaintext literal in the manifest.
//!
//! The request-construction + signing are pure and unit-tested (including a
//! sign→verify round-trip against hickory's own RFC 8945 verifier and a
//! wrong-key-rejected negative); the TCP exchange is a live seam exercised
//! against a real dynamic-DNS server (no nameserver in CI).

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::update_message::UpdateMessage;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, TSigner};

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

/// The default DNS service port, appended when the configured server carries no
/// explicit port.
const DEFAULT_PORT: u16 = 53;

/// How long to wait for the whole TCP exchange (connect + send + read response).
/// A dynamic UPDATE is a single small round-trip to an authoritative server the
/// operator controls; a stall past this is treated as a backend failure rather
/// than hanging a reconcile/issuance forever.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum TSIG clock skew (seconds) stamped into the signature's fudge. A few
/// minutes is the RFC 8945 norm — wide enough to tolerate ordinary host/server
/// clock drift, narrow enough to bound replay.
const TSIG_FUDGE: u16 = 300;

/// An RFC 2136 dynamic-UPDATE editor for ONE zone on ONE authoritative server,
/// authenticating every message with a TSIG key.
pub struct Rfc2136Dns {
    /// The authoritative server each UPDATE is sent to, as a `host:port` authority
    /// ready for `tokio::net::lookup_host` (a bare IP/host has `:53` appended at
    /// construction). Resolved per exchange so a changed address is picked up.
    server: String,
    /// The zone apex each UPDATE targets (the `SOA` owner), as an FQDN.
    zone: Name,
    /// The TSIG signer built from the key name/algorithm/secret.
    signer: TSigner,
}

impl Rfc2136Dns {
    /// Build a provider targeting `server` (an `ip`, `ip:port`, `host`, or
    /// `host:port` — `:53` is assumed when no port is given) for `zone`,
    /// authenticating with a TSIG key named `key_name` using `algorithm`
    /// (`hmac-sha256` | `hmac-sha384` | `hmac-sha512`; case-insensitive) and the
    /// base64-encoded `secret_b64`.
    ///
    /// Pure (no network / DNS lookup): a malformed zone/key name, an unsupported
    /// algorithm, or an undecodable secret is a [`DnsError::Config`] here, not a
    /// deferred surprise at the first write.
    pub fn new(
        server: &str,
        zone: &str,
        key_name: &str,
        algorithm: &str,
        secret_b64: &str,
    ) -> Result<Self, DnsError> {
        let server = normalize_server(server)?;
        let zone =
            fqdn(zone).map_err(|e| DnsError::Config(format!("rfc2136 zone {zone:?}: {e}")))?;
        let key_name = fqdn(key_name)
            .map_err(|e| DnsError::Config(format!("rfc2136 TSIG key name {key_name:?}: {e}")))?;
        let algorithm = parse_algorithm(algorithm)?;
        let secret = decode_secret(secret_b64)?;
        // `TSigner::new` itself rejects an algorithm whose HMAC it cannot compute;
        // `parse_algorithm` already restricts us to the supported three, so this is
        // belt-and-braces — a clear config error, never a panic.
        let signer = TSigner::new(secret, algorithm, key_name, TSIG_FUDGE)
            .map_err(|e| DnsError::Config(format!("rfc2136 TSIG signer: {e}")))?;
        Ok(Self {
            server,
            zone,
            signer,
        })
    }

    /// The configured `host:port` authority (for the live seam / diagnostics).
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Validate `record`'s owner name: a syntactically-legal FQDN that lies within
    /// the configured zone. An owner outside the zone is refused up front (an
    /// authoritative server would `NOTZONE`-reject it anyway, and this keeps a
    /// misconfigured write from ever leaving the host).
    fn owner_name(&self, record: &DnsRecord) -> Result<Name, DnsError> {
        let name = fqdn(&record.name).map_err(|e| {
            DnsError::InvalidRecord(format!("rfc2136 owner {:?}: {e}", record.name))
        })?;
        if !self.zone.zone_of(&name) {
            return Err(DnsError::Config(format!(
                "rfc2136: owner {:?} is not within the configured zone {}",
                record.name, self.zone
            )));
        }
        Ok(name)
    }

    /// The typed `(RecordType, RData)` for a writable record kind. The guardrail
    /// ([`crate::dns::validate_writable`]) refuses an unsupported kind before any
    /// adapter runs, but this also fails closed if one reaches the adapter
    /// directly.
    fn rdata(record: &DnsRecord) -> Result<(RecordType, RData), DnsError> {
        Ok(match &record.kind {
            RecordKind::A(ip) => (RecordType::A, RData::A(A(*ip))),
            RecordKind::Aaaa(ip) => (RecordType::AAAA, RData::AAAA(AAAA(*ip))),
            RecordKind::Cname(target) => {
                let t = fqdn(target).map_err(|e| {
                    DnsError::InvalidRecord(format!("rfc2136 CNAME target {target:?}: {e}"))
                })?;
                (RecordType::CNAME, RData::CNAME(CNAME(t)))
            }
            RecordKind::Txt(strings) => (RecordType::TXT, RData::TXT(TXT::new(strings.clone()))),
            other => {
                return Err(DnsError::UnsupportedRecordType {
                    provider: "rfc2136",
                    kind: other.tag(),
                });
            }
        })
    }

    /// A fresh `UPDATE`-opcode message with the zone section filled in (a random
    /// id, from [`Message::query`]). The caller appends the prerequisite/update
    /// records.
    fn new_update(&self) -> Message {
        let mut message = Message::query();
        message.metadata.op_code = OpCode::Update;
        message.metadata.recursion_desired = false;
        let mut zone = Query::new();
        zone.set_name(self.zone.clone())
            .set_query_class(DNSClass::IN)
            .set_query_type(RecordType::SOA);
        message.add_zone(zone);
        message
    }

    /// Build the UNSIGNED `UPDATE` message for an `upsert` (create-or-replace).
    /// `TXT` is additive (add-to-RRset, multi-value safe); `A`/`AAAA`/`CNAME`
    /// replace the RRset atomically (delete-RRset then add).
    fn build_upsert(&self, record: &DnsRecord) -> Result<Message, DnsError> {
        let name = self.owner_name(record)?;
        let (rtype, rdata) = Self::rdata(record)?;
        let mut message = self.new_update();

        if !matches!(record.kind, RecordKind::Txt(_)) {
            // Replace semantics for address/alias records: delete the whole
            // (name, type) RRset first (class ANY, TTL 0, empty rdata — §2.5.2).
            let mut del = Record::update0(name.clone(), 0, rtype);
            del.dns_class = DNSClass::ANY;
            message.add_update(del);
        }

        // Add the record (zone class IN, the real TTL + rdata — §2.5.1).
        let mut add = Record::from_rdata(name, record.ttl, rdata);
        add.dns_class = DNSClass::IN;
        message.add_update(add);
        Ok(message)
    }

    /// Build the UNSIGNED `UPDATE` message for a `delete` of exactly this record's
    /// rdata (class NONE, TTL 0 — §2.5.4), leaving any sibling values intact.
    fn build_delete(&self, record: &DnsRecord) -> Result<Message, DnsError> {
        let name = self.owner_name(record)?;
        let (_rtype, rdata) = Self::rdata(record)?;
        let mut message = self.new_update();
        let mut del = Record::from_rdata(name, 0, rdata);
        del.dns_class = DNSClass::NONE;
        message.add_update(del);
        Ok(message)
    }

    /// Sign `message` in place with the TSIG key and serialize it to the wire.
    /// The MAC covers the message as emitted plus the TSIG rdata, so this must be
    /// the last mutation before sending.
    fn sign_to_wire(&self, message: &mut Message) -> Result<Vec<u8>, DnsError> {
        let now = crate::now_secs();
        message
            .finalize(&self.signer, now)
            .map_err(|e| DnsError::Backend(format!("rfc2136 TSIG signing failed: {e}")))?;
        message
            .to_vec()
            .map_err(|e| DnsError::Backend(format!("rfc2136 message encode failed: {e}")))
    }

    /// Send the already-signed `wire` bytes to the server over TCP (length-prefixed
    /// per RFC 1035 §4.2.2) and return the parsed response, all under one timeout.
    async fn exchange(&self, wire: Vec<u8>) -> Result<Message, DnsError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        if wire.len() > u16::MAX as usize {
            return Err(DnsError::Backend(format!(
                "rfc2136 UPDATE message is {} bytes, over the 65535-byte DNS-over-TCP frame limit",
                wire.len()
            )));
        }

        let run = async {
            let mut stream = TcpStream::connect(self.server.as_str())
                .await
                .map_err(|e| {
                    DnsError::Backend(format!("rfc2136 connect to {}: {e}", self.server))
                })?;

            // DNS over TCP: a 2-byte big-endian length prefix, then the message.
            let len = (wire.len() as u16).to_be_bytes();
            stream
                .write_all(&len)
                .await
                .map_err(|e| DnsError::Backend(format!("rfc2136 send: {e}")))?;
            stream
                .write_all(&wire)
                .await
                .map_err(|e| DnsError::Backend(format!("rfc2136 send: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| DnsError::Backend(format!("rfc2136 send: {e}")))?;

            let mut len_buf = [0u8; 2];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| DnsError::Backend(format!("rfc2136 read response length: {e}")))?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp = vec![0u8; resp_len];
            stream
                .read_exact(&mut resp)
                .await
                .map_err(|e| DnsError::Backend(format!("rfc2136 read response: {e}")))?;
            Message::from_vec(&resp)
                .map_err(|e| DnsError::Backend(format!("rfc2136 parse response: {e}")))
        };

        tokio::time::timeout(EXCHANGE_TIMEOUT, run)
            .await
            .map_err(|_| {
                DnsError::Backend(format!(
                    "rfc2136 exchange with {} timed out after {}s",
                    self.server,
                    EXCHANGE_TIMEOUT.as_secs()
                ))
            })?
    }
}

/// Interpret an `UPDATE` response RCODE. `NoError` is success; for a `delete`,
/// the "nothing to remove" codes a strict server might return are ALSO success
/// (the record is already gone — idempotent teardown). Everything else — the
/// TSIG auth failures (`BADSIG`/`BADKEY`/`BADTIME`) included — is a backend
/// error, without echoing any key material.
fn check_response(resp: &Message, is_delete: bool) -> Result<(), DnsError> {
    match resp.response_code {
        ResponseCode::NoError => Ok(()),
        // A delete that finds nothing is a converged no-op, not a failure.
        ResponseCode::NXDomain | ResponseCode::NXRRSet if is_delete => Ok(()),
        other => Err(DnsError::Backend(format!(
            "rfc2136 server rejected the UPDATE: {other} ({})",
            u16::from(other)
        ))),
    }
}

/// Normalize a configured server authority into a `host:port` string for
/// `tokio::net::lookup_host`, appending [`DEFAULT_PORT`] when no port is present.
/// Handles a bare IPv4/IPv6 literal (IPv6 is bracketed), an already-`ip:port` /
/// `host:port`, and a bare hostname.
fn normalize_server(server: &str) -> Result<String, DnsError> {
    let server = server.trim();
    if server.is_empty() {
        return Err(DnsError::Config(
            "rfc2136 server address must not be empty".to_string(),
        ));
    }
    // Already an `ip:port` (v4 or bracketed v6) socket address — keep as-is.
    if std::net::SocketAddr::from_str(server).is_ok() {
        return Ok(server.to_string());
    }
    // A bare IP literal — append the default port (bracketing a v6 literal).
    if let Ok(ip) = IpAddr::from_str(server) {
        return Ok(match ip {
            IpAddr::V4(_) => format!("{server}:{DEFAULT_PORT}"),
            IpAddr::V6(_) => format!("[{server}]:{DEFAULT_PORT}"),
        });
    }
    // Otherwise a hostname, possibly with a port. A single trailing `:port`
    // (exactly one colon, a numeric tail) is kept; anything else gets the default
    // port appended. (A bare IPv6 without brackets already matched above.)
    if let Some((host, port)) = server.rsplit_once(':')
        && !host.contains(':')
        && !host.is_empty()
        && port.parse::<u16>().is_ok()
    {
        return Ok(server.to_string());
    }
    Ok(format!("{server}:{DEFAULT_PORT}"))
}

/// Parse a DNS name into its FQDN form (trailing-dot absolute). `from_ascii`
/// accepts the LDH + `_`/`*` labels the owner-name model uses; the result is
/// forced to FQDN so a relative owner is never sent.
fn fqdn(name: &str) -> Result<Name, DnsError> {
    let mut n = Name::from_ascii(name).map_err(|e| DnsError::InvalidRecord(e.to_string()))?;
    n.set_fqdn(true);
    Ok(n)
}

/// Parse a TSIG algorithm token (case-insensitive) into the hickory enum,
/// restricted to the HMAC-SHA2 family hickory can actually compute. `hmac-sha256`
/// is the modern default and what most dynamic-DNS deployments use.
fn parse_algorithm(algorithm: &str) -> Result<TsigAlgorithm, DnsError> {
    match algorithm.trim().to_ascii_lowercase().as_str() {
        "hmac-sha256" | "hmac_sha256" | "sha256" => Ok(TsigAlgorithm::HmacSha256),
        "hmac-sha384" | "hmac_sha384" | "sha384" => Ok(TsigAlgorithm::HmacSha384),
        "hmac-sha512" | "hmac_sha512" | "sha512" => Ok(TsigAlgorithm::HmacSha512),
        other => Err(DnsError::Config(format!(
            "rfc2136 TSIG algorithm {other:?} is not supported \
             (use hmac-sha256 | hmac-sha384 | hmac-sha512)"
        ))),
    }
}

/// Decode a base64 TSIG secret (standard alphabet, as `dnssec-keygen` /
/// `tsig-keygen` emit it). A non-empty decode is required — an empty key is a
/// config error, not a silently-weak signer.
fn decode_secret(secret_b64: &str) -> Result<Vec<u8>, DnsError> {
    use base64::Engine;
    let secret = base64::engine::general_purpose::STANDARD
        .decode(secret_b64.trim().as_bytes())
        .map_err(|_| DnsError::Config("rfc2136 TSIG secret is not valid base64".to_string()))?;
    if secret.is_empty() {
        return Err(DnsError::Config(
            "rfc2136 TSIG secret decoded to an empty key".to_string(),
        ));
    }
    Ok(secret)
}

#[async_trait]
impl DnsProvider for Rfc2136Dns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let mut message = self.build_upsert(record)?;
        let wire = self.sign_to_wire(&mut message)?;
        let resp = self.exchange(wire).await?;
        check_response(&resp, false)
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let mut message = self.build_delete(record)?;
        let wire = self.sign_to_wire(&mut message)?;
        let resp = self.exchange(wire).await?;
        check_response(&resp, true)
    }

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // The four kinds auto-DNS needs: TXT for the ACME DNS-01 challenge +
        // ownership-verification, A/AAAA/CNAME for custom-domain pointing. RFC
        // 2136 could carry any type the server accepts; the writer intentionally
        // scopes this adapter to the auto-DNS set (widening is a per-type rdata +
        // test addition, refused cleanly by the guardrail until then).
        &[
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
        ]
    }

    fn name(&self) -> &'static str {
        "rfc2136"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // A deterministic 32-byte base64 key for construction + signing tests.
    const TEST_SECRET_B64: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";

    fn provider() -> Rfc2136Dns {
        Rfc2136Dns::new(
            "192.0.2.53",
            "example.com",
            "update-key.example.com",
            "hmac-sha256",
            TEST_SECRET_B64,
        )
        .expect("valid config builds")
    }

    fn txt(name: &str, value: &str) -> DnsRecord {
        DnsRecord {
            kind: RecordKind::Txt(vec![value.to_string()]),
            name: name.to_string(),
            ttl: 60,
        }
    }

    // ---- construction / config validation --------------------------------

    #[test]
    fn supported_kinds_is_the_auto_dns_set() {
        let p = provider();
        for tag in [
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
        ] {
            assert!(p.supports_kind(tag), "rfc2136 should support {tag}");
        }
        assert_eq!(p.supported_kinds().len(), 4);
        assert_eq!(p.name(), "rfc2136");
        // Types outside the auto-DNS set are not offered (guardrail refuses them).
        assert!(!p.supports_kind(RecordKindTag::Mx));
        assert!(!p.supports_kind(RecordKindTag::Caa));
    }

    #[test]
    fn normalize_server_adds_default_port_and_keeps_explicit_ones() {
        // Bare IPv4 → :53.
        assert_eq!(normalize_server("192.0.2.53").unwrap(), "192.0.2.53:53");
        // IPv4:port kept.
        assert_eq!(
            normalize_server("192.0.2.53:5353").unwrap(),
            "192.0.2.53:5353"
        );
        // Bare IPv6 → bracketed :53.
        assert_eq!(
            normalize_server("2001:db8::53").unwrap(),
            "[2001:db8::53]:53"
        );
        // Bracketed IPv6:port kept.
        assert_eq!(
            normalize_server("[2001:db8::53]:5353").unwrap(),
            "[2001:db8::53]:5353"
        );
        // Bare hostname → :53; host:port kept.
        assert_eq!(
            normalize_server("ns1.example.com").unwrap(),
            "ns1.example.com:53"
        );
        assert_eq!(
            normalize_server("ns1.example.com:5353").unwrap(),
            "ns1.example.com:5353"
        );
        // Whitespace trimmed; empty refused.
        assert_eq!(
            normalize_server("  ns1.example.com  ").unwrap(),
            "ns1.example.com:53"
        );
        assert!(matches!(normalize_server("   "), Err(DnsError::Config(_))));
    }

    #[test]
    fn parse_algorithm_accepts_sha2_family_and_rejects_others() {
        assert_eq!(
            parse_algorithm("hmac-sha256").unwrap(),
            TsigAlgorithm::HmacSha256
        );
        assert_eq!(
            parse_algorithm("HMAC-SHA384").unwrap(),
            TsigAlgorithm::HmacSha384
        );
        assert_eq!(
            parse_algorithm("hmac-sha512").unwrap(),
            TsigAlgorithm::HmacSha512
        );
        // MD5 and SHA1 are legacy/weak and unsupported by the HMAC backend.
        assert!(matches!(
            parse_algorithm("hmac-md5"),
            Err(DnsError::Config(_))
        ));
        assert!(matches!(
            parse_algorithm("hmac-sha1"),
            Err(DnsError::Config(_))
        ));
    }

    #[test]
    fn construction_rejects_bad_secret_and_algorithm() {
        // Non-base64 secret.
        assert!(matches!(
            Rfc2136Dns::new(
                "192.0.2.53",
                "example.com",
                "k",
                "hmac-sha256",
                "not base64!!"
            ),
            Err(DnsError::Config(_))
        ));
        // Empty-decoding secret.
        assert!(matches!(
            Rfc2136Dns::new("192.0.2.53", "example.com", "k", "hmac-sha256", ""),
            Err(DnsError::Config(_))
        ));
        // Unsupported algorithm.
        assert!(matches!(
            Rfc2136Dns::new(
                "192.0.2.53",
                "example.com",
                "k",
                "hmac-md5",
                TEST_SECRET_B64
            ),
            Err(DnsError::Config(_))
        ));
    }

    // ---- UPDATE message construction (pure) ------------------------------

    #[test]
    fn upsert_txt_is_additive_single_add_in_the_zone() {
        let p = provider();
        let msg = p
            .build_upsert(&txt("_acme-challenge.example.com", "challenge-value"))
            .unwrap();
        // UPDATE opcode, one zone (SOA-typed at the apex).
        assert_eq!(msg.op_code, OpCode::Update);
        assert_eq!(msg.zones().len(), 1);
        assert_eq!(msg.zones()[0].query_type(), RecordType::SOA);
        assert_eq!(msg.zones()[0].name().to_ascii(), "example.com.");
        // No prerequisite (additive).
        assert!(msg.prerequisites().is_empty());
        // Exactly ONE update record: the TXT add, zone class IN, real TTL.
        assert_eq!(msg.updates().len(), 1);
        let add = &msg.updates()[0];
        assert_eq!(add.record_type(), RecordType::TXT);
        assert_eq!(add.dns_class, DNSClass::IN);
        assert_eq!(add.ttl, 60);
        assert_eq!(add.name.to_ascii(), "_acme-challenge.example.com.");
        match &add.data {
            RData::TXT(t) => assert_eq!(t.to_string(), "challenge-value"),
            other => panic!("expected TXT rdata, got {other:?}"),
        }
    }

    #[test]
    fn upsert_a_replaces_rrset_then_adds() {
        let p = provider();
        let rec = DnsRecord {
            kind: RecordKind::A(Ipv4Addr::new(203, 0, 113, 7)),
            name: "www.example.com".into(),
            ttl: 120,
        };
        let msg = p.build_upsert(&rec).unwrap();
        // Two updates: delete-RRset (class ANY, TTL 0, empty rdata) then add.
        assert_eq!(msg.updates().len(), 2);
        let del = &msg.updates()[0];
        assert_eq!(del.dns_class, DNSClass::ANY);
        assert_eq!(del.ttl, 0);
        assert_eq!(del.record_type(), RecordType::A);
        assert!(matches!(del.data, RData::Update0(_)));
        let add = &msg.updates()[1];
        assert_eq!(add.dns_class, DNSClass::IN);
        assert_eq!(add.ttl, 120);
        match &add.data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(203, 0, 113, 7)),
            other => panic!("expected A rdata, got {other:?}"),
        }
    }

    #[test]
    fn upsert_cname_and_aaaa_replace_rrset() {
        let p = provider();
        // CNAME.
        let cname = DnsRecord {
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "www.example.com".into(),
            ttl: 300,
        };
        let msg = p.build_upsert(&cname).unwrap();
        assert_eq!(msg.updates().len(), 2);
        assert_eq!(msg.updates()[0].dns_class, DNSClass::ANY);
        match &msg.updates()[1].data {
            RData::CNAME(c) => assert_eq!(c.0.to_ascii(), "lb.example.net."),
            other => panic!("expected CNAME rdata, got {other:?}"),
        }
        // AAAA.
        let aaaa = DnsRecord {
            kind: RecordKind::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            name: "www.example.com".into(),
            ttl: 300,
        };
        let msg = p.build_upsert(&aaaa).unwrap();
        assert_eq!(msg.updates().len(), 2);
        assert_eq!(msg.updates()[1].record_type(), RecordType::AAAA);
    }

    #[test]
    fn delete_removes_exactly_the_rdata_class_none() {
        let p = provider();
        let msg = p
            .build_delete(&txt("_acme-challenge.example.com", "challenge-value"))
            .unwrap();
        assert_eq!(msg.op_code, OpCode::Update);
        assert_eq!(msg.updates().len(), 1);
        let del = &msg.updates()[0];
        // §2.5.4 delete-one-RR: class NONE, TTL 0, the exact rdata (so siblings survive).
        assert_eq!(del.dns_class, DNSClass::NONE);
        assert_eq!(del.ttl, 0);
        assert_eq!(del.record_type(), RecordType::TXT);
        match &del.data {
            RData::TXT(t) => assert_eq!(t.to_string(), "challenge-value"),
            other => panic!("expected TXT rdata, got {other:?}"),
        }
    }

    #[test]
    fn owner_outside_the_zone_is_refused_not_sent() {
        let p = provider();
        let foreign = txt("_acme-challenge.evil.test", "v");
        assert!(matches!(p.build_upsert(&foreign), Err(DnsError::Config(_))));
        assert!(matches!(p.build_delete(&foreign), Err(DnsError::Config(_))));
    }

    #[test]
    fn unsupported_kind_fails_closed_in_the_adapter() {
        let p = provider();
        let mx = DnsRecord {
            kind: RecordKind::Mx {
                preference: 10,
                exchange: "mx.example.com".into(),
            },
            name: "example.com".into(),
            ttl: 300,
        };
        assert!(matches!(
            p.build_upsert(&mx),
            Err(DnsError::UnsupportedRecordType {
                provider: "rfc2136",
                kind: RecordKindTag::Mx,
            })
        ));
    }

    // ---- TSIG signing (real crypto, against hickory's own verifier) ------

    #[test]
    fn signed_update_verifies_with_the_same_key() {
        let p = provider();
        let mut msg = p
            .build_upsert(&txt("_acme-challenge.example.com", "v"))
            .unwrap();
        let wire = p.sign_to_wire(&mut msg).unwrap();
        // A TSIG RR is present after signing.
        assert!(msg.signature().is_some(), "finalize must attach a TSIG RR");
        // The emitted bytes carry a MAC the SAME signer accepts — this exercises
        // the real RFC 8945 HMAC path end-to-end (sign → wire → verify).
        p.signer
            .verify_message_byte(&wire, None, true)
            .expect("the signer must verify its own signed message");
    }

    #[test]
    fn signed_update_is_rejected_by_a_different_key() {
        let p = provider();
        let mut msg = p
            .build_upsert(&txt("_acme-challenge.example.com", "v"))
            .unwrap();
        let wire = p.sign_to_wire(&mut msg).unwrap();
        // A signer with a DIFFERENT secret must reject the MAC (tamper/forgery).
        let other = Rfc2136Dns::new(
            "192.0.2.53",
            "example.com",
            "update-key.example.com",
            "hmac-sha256",
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=",
        )
        .unwrap();
        assert!(
            other.signer.verify_message_byte(&wire, None, true).is_err(),
            "a different key must not verify the signature"
        );
    }

    // ---- response RCODE mapping ------------------------------------------

    #[test]
    fn check_response_maps_rcodes() {
        let ok = Message::query();
        // NoError → Ok for both upsert and delete.
        assert!(check_response(&ok, false).is_ok());
        assert!(check_response(&ok, true).is_ok());

        let mut refused = Message::query();
        refused.metadata.response_code = ResponseCode::Refused;
        assert!(matches!(
            check_response(&refused, false),
            Err(DnsError::Backend(_))
        ));

        let mut notauth = Message::query();
        notauth.metadata.response_code = ResponseCode::NotAuth;
        assert!(matches!(
            check_response(&notauth, true),
            Err(DnsError::Backend(_))
        ));

        // A strict server's "nothing to delete" is success for delete, error for upsert.
        let mut nxrrset = Message::query();
        nxrrset.metadata.response_code = ResponseCode::NXRRSet;
        assert!(check_response(&nxrrset, true).is_ok());
        assert!(check_response(&nxrrset, false).is_err());
    }

    #[test]
    fn signing_error_message_carries_no_key_material() {
        // The error strings on the write paths describe transport/RCODE state,
        // never the secret. Spot-check the auth-failure mapping does not include
        // the key bytes (it only names the RCODE).
        let mut badkey = Message::query();
        badkey.metadata.response_code = ResponseCode::BADKEY;
        let err = check_response(&badkey, false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("BADKEY") || msg.contains("17"),
            "names the RCODE: {msg}"
        );
        assert!(!msg.contains(TEST_SECRET_B64), "must not echo the secret");
    }

    // ---- live seam (real dynamic-DNS server) -----------------------------

    /// End-to-end against a REAL RFC 2136 server (BIND / PowerDNS / Knot / nsd).
    /// `#[ignore]` by policy (no nameserver in CI — matches every other adapter's
    /// `#[ignore]` live seam); run on the lighthouse live gate with a configured
    /// `allow-update { key … };` zone. Proves the hand-rolled TCP framing + TSIG
    /// round-trip against a server that actually validates the signature.
    ///
    /// ```sh
    /// RFC2136_SERVER=127.0.0.1:53 RFC2136_ZONE=example.test \
    /// RFC2136_TSIG_KEY_NAME=update-key RFC2136_TSIG_ALGORITHM=hmac-sha256 \
    /// RFC2136_TSIG_SECRET=<base64> \
    ///   cargo test -p boatramp-acme --features rfc2136 -- --ignored rfc2136_live
    /// ```
    #[tokio::test]
    #[ignore = "requires a live RFC 2136 server with a matching TSIG key (lighthouse live gate)"]
    async fn rfc2136_live_upsert_then_delete_txt() {
        let var =
            |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k} for the live seam"));
        let p = Rfc2136Dns::new(
            &var("RFC2136_SERVER"),
            &var("RFC2136_ZONE"),
            &var("RFC2136_TSIG_KEY_NAME"),
            &std::env::var("RFC2136_TSIG_ALGORITHM").unwrap_or_else(|_| "hmac-sha256".to_string()),
            &var("RFC2136_TSIG_SECRET"),
        )
        .expect("live config builds");
        let zone = var("RFC2136_ZONE");
        let rec = DnsRecord {
            kind: RecordKind::Txt(vec!["boatramp-rfc2136-live".into()]),
            name: format!("_acme-challenge.{zone}"),
            ttl: 60,
        };
        p.upsert(&rec).await.expect("upsert the challenge TXT");
        // Idempotent re-upsert of the same value converges (add of a dup is a no-op).
        p.upsert(&rec).await.expect("re-upsert converges");
        p.delete(&rec).await.expect("delete the challenge TXT");
        // Deleting an already-gone record is success (idempotent teardown).
        p.delete(&rec).await.expect("re-delete is a no-op");
    }
}
