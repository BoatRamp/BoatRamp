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
//! # Authenticating the reply (not just the request)
//!
//! Our outbound UPDATE is fully TSIG-signed, so no attacker can forge a *write*.
//! But the *outcome* must be authenticated too: acting on the RCODE alone would let
//! an on-path / TCP-injection attacker spoof the result — e.g. a forged `NXRRSet`
//! answering a `delete` would make us believe a failed teardown succeeded, leaving a
//! stale custom-domain `A`/`CNAME` pointer (subdomain-takeover-adjacent). So, exactly
//! as hickory's own client does, [`Message::finalize`] hands back a [`TSigVerifier`]
//! bound to the request's MAC + inception time, and every reply is run through it
//! (RFC 8945 §5.4): any outcome we would *believe* as success (`NoError`, or the
//! idempotent `NXDomain`/`NXRRSet` of a `delete`) MUST carry a valid response MAC and
//! echo the request's transaction id, or it is refused. A plain error RCODE — a
//! signed `BADSIG`/`BADKEY`/`BADTIME`, or the spec'd *unsigned* pre-TSIG error a
//! server may return (RFC 8945 §5.3.2) — is surfaced as a hard failure without being
//! trusted, never as a success.
//!
//! The request-construction + signing are pure and unit-tested (including a
//! sign→verify round-trip against hickory's own RFC 8945 verifier and a
//! wrong-key-rejected negative); the reply-authentication path is unit-tested against
//! responses signed by hickory's own `TSigResponseContext` (accept) plus
//! unsigned / tampered / id-mismatched / error negatives (reject). The TCP exchange
//! is a live seam exercised against a real dynamic-DNS server (no nameserver in CI).

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::update_message::UpdateMessage;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, TSigVerifier, TSigner};

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

/// A signed UPDATE ready to send, paired with everything needed to AUTHENTICATE the
/// reply to it: the wire bytes, hickory's response [`TSigVerifier`] (bound to our
/// request MAC + inception time, RFC 8945 §5.4), and the request transaction id to
/// match against the response.
struct SignedUpdate {
    wire: Vec<u8>,
    verifier: TSigVerifier,
    id: u16,
}

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

    /// Sign `message` in place with the TSIG key and serialize it to the wire,
    /// returning the bytes alongside what is needed to AUTHENTICATE the reply: the
    /// [`TSigVerifier`] hickory derives from the request (bound to the request MAC +
    /// inception time) and the request transaction id. The MAC covers the message as
    /// emitted plus the TSIG rdata, so signing is the last mutation before sending.
    fn sign_update(&self, message: &mut Message) -> Result<SignedUpdate, DnsError> {
        let now = crate::now_secs();
        // The header id is assigned at `Message::query()` and unchanged by signing;
        // the server echoes it in the response (RFC 1035 §4.1.1) and we match it.
        let id = message.id;
        let verifier = message
            .finalize(&self.signer, now)
            .map_err(|e| DnsError::Backend(format!("rfc2136 TSIG signing failed: {e}")))?
            // `finalize` always yields a verifier for a TSIG signer; a `None` would be
            // an upstream contract change — fail closed rather than skip verification.
            .ok_or_else(|| {
                DnsError::Backend("rfc2136 TSIG signing produced no response verifier".to_string())
            })?;
        let wire = message
            .to_vec()
            .map_err(|e| DnsError::Backend(format!("rfc2136 message encode failed: {e}")))?;
        Ok(SignedUpdate { wire, verifier, id })
    }

    /// Send the already-signed `wire` bytes to the server over TCP (length-prefixed
    /// per RFC 1035 §4.2.2) and return the RAW response bytes, all under one timeout.
    /// Parsing + TSIG authentication of the reply happen in [`check_signed_response`],
    /// which needs the exact bytes the server emitted to verify the MAC over them.
    async fn exchange(&self, wire: Vec<u8>) -> Result<Vec<u8>, DnsError> {
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
            Ok::<_, DnsError>(resp)
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

/// Authenticate and interpret a reply to a signed UPDATE (finding F1). Our request is
/// TSIG-signed, so a *write* cannot be forged — but the *outcome* must be authenticated
/// too, or an on-path / TCP-injection attacker could spoof it (e.g. a forged `NXRRSet`
/// answering a `delete`, making us believe a failed teardown succeeded and leaving a
/// stale custom-domain pointer). On top of the RCODE mapping in [`check_response`] this:
///
/// 1. matches the response's transaction id to the request's (RFC 1035 §4.1.1) — a
///    mismatch is a spoofed or stale datagram, refused whatever the RCODE claims;
/// 2. for any outcome we would BELIEVE as success (`NoError`, or the idempotent
///    `NXDomain`/`NXRRSet` of a `delete`), REQUIRES a valid response TSIG MAC bound to
///    our request MAC and within the fudge window — verified by hickory's own response
///    verifier (RFC 8945 §5.4). An unsigned or MAC-invalid "success" is NOT trusted.
///
/// A plain error RCODE is a failure we need not authenticate to DISBELIEVE: a signed
/// `BADSIG`/`BADKEY`/`BADTIME`, and the spec'd *unsigned* pre-TSIG error a server may
/// return (RFC 8945 §5.3.2), both surface here as a hard error — never a success, and
/// never a panic.
fn check_signed_response(
    resp_bytes: &[u8],
    verifier: &mut TSigVerifier,
    request_id: u16,
    is_delete: bool,
) -> Result<(), DnsError> {
    // Parse once, UNauthenticated, to read the id + RCODE. These must stay legible even
    // for a reply the authenticated path below refuses (an unsigned error, a tampered
    // MAC) — so we can surface a precise error instead of crashing.
    let resp = Message::from_vec(resp_bytes)
        .map_err(|e| DnsError::Backend(format!("rfc2136 parse response: {e}")))?;

    // (1) Transaction-id match. Hickory's verifier binds the MAC to our *request* MAC
    // (so a reply to a different exchange cannot verify), but the on-wire header id is
    // covered only via the TSIG original-id; an explicit match is cheap defence in
    // depth against a spoofed or stale datagram and gives a precise error.
    if resp.id != request_id {
        return Err(DnsError::Backend(format!(
            "rfc2136 response id {:#06x} does not match request id {:#06x} \
             (spoofed or stale reply)",
            resp.id, request_id
        )));
    }

    // (2) An error RCODE is a rejection we surface immediately — no MAC required to
    // DISBELIEVE it. This covers a signed BADSIG/BADKEY/BADTIME and a spec'd unsigned
    // pre-TSIG error alike, without trusting either as success.
    check_response(&resp, is_delete)?;

    // (3) We reached here only on a believed-success RCODE. REQUIRE a valid response
    // MAC before trusting it: hickory's verifier re-checks the MAC over these exact
    // bytes (prefixed with our request MAC) and the fudge window. Fail closed — an
    // unsigned or tampered success must not be believed.
    verifier.verify(resp_bytes).map_err(|e| {
        DnsError::Backend(format!(
            "rfc2136 response reported success ({}) but its TSIG MAC did not verify; \
             refusing to trust the outcome: {e}",
            resp.response_code
        ))
    })?;
    Ok(())
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
        let SignedUpdate {
            wire,
            mut verifier,
            id,
        } = self.sign_update(&mut message)?;
        let resp = self.exchange(wire).await?;
        check_signed_response(&resp, &mut verifier, id, false)
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let mut message = self.build_delete(record)?;
        let SignedUpdate {
            wire,
            mut verifier,
            id,
        } = self.sign_update(&mut message)?;
        let resp = self.exchange(wire).await?;
        check_signed_response(&resp, &mut verifier, id, true)
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
        let wire = p.sign_update(&mut msg).unwrap().wire;
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
        let wire = p.sign_update(&mut msg).unwrap().wire;
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

    // ---- response authentication (finding F1) ----------------------------

    /// Sign a fresh UPDATE the way the real `upsert`/`delete` path does, and hand back
    /// the client state needed to authenticate a reply: the response verifier, the
    /// request transaction id, and the request MAC (which a compliant server folds into
    /// its reply signature, RFC 8945 §5.4).
    fn signed_request(p: &Rfc2136Dns, is_delete: bool) -> (TSigVerifier, u16, Vec<u8>) {
        let rec = txt("_acme-challenge.example.com", "challenge");
        let mut msg = if is_delete {
            p.build_delete(&rec).unwrap()
        } else {
            p.build_upsert(&rec).unwrap()
        };
        let signed = p.sign_update(&mut msg).unwrap();
        let request_mac = msg
            .signature()
            .expect("a signed request carries a TSIG MAC")
            .data
            .mac
            .clone();
        (signed.verifier, signed.id, request_mac)
    }

    /// Forge the bytes a server returns for a signed UPDATE: a Response-type reply
    /// carrying `rcode`, its id echoing `request_id`, and — when `signed` — TSIG-signed
    /// over our `request_mac` exactly as a compliant server signs a reply, via hickory's
    /// own [`TSigResponseContext`]. `signed == false` yields the identical reply with NO
    /// TSIG: the spoofable, unsigned case an on-path attacker can inject.
    fn server_reply(
        signer: &TSigner,
        request_id: u16,
        request_mac: &[u8],
        rcode: ResponseCode,
        signed: bool,
    ) -> Vec<u8> {
        use hickory_proto::op::{Edns, MessageType};
        use hickory_proto::rr::TSigResponseContext;

        let mut resp = Message::query();
        resp.metadata.id = request_id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.op_code = OpCode::Update;
        resp.metadata.response_code = rcode;
        // Extended RCODEs (BADSIG/BADKEY/BADTIME, > 15) need an EDNS OPT to carry their
        // high bits on the wire; we only use these on the unsigned error path.
        if rcode.high() > 0 {
            resp.set_edns(Edns::new());
        }
        if !signed {
            return resp.to_vec().expect("encode unsigned reply");
        }
        let now = crate::now_secs();
        let unsigned = resp.to_vec().expect("encode reply before signing");
        let tsig =
            TSigResponseContext::new(request_id, now, signer.clone(), request_mac.to_vec(), None)
                .sign(&unsigned)
                .expect("server signs the reply");
        resp.set_signature(tsig);
        resp.to_vec().expect("encode signed reply")
    }

    #[test]
    fn signed_success_response_is_accepted() {
        let p = provider();
        let (mut verifier, id, mac) = signed_request(&p, false);
        let reply = server_reply(&p.signer, id, &mac, ResponseCode::NoError, true);
        check_signed_response(&reply, &mut verifier, id, false)
            .expect("a correctly signed NoError reply must be accepted");
    }

    #[test]
    fn unsigned_success_response_is_rejected() {
        let p = provider();
        let (mut verifier, id, mac) = signed_request(&p, false);
        // A NoError with NO TSIG — an on-path attacker's spoofed "success". Not believed.
        let reply = server_reply(&p.signer, id, &mac, ResponseCode::NoError, false);
        let err = check_signed_response(&reply, &mut verifier, id, false)
            .expect_err("an unsigned success must not be trusted");
        assert!(matches!(err, DnsError::Backend(_)), "{err:?}");
    }

    #[test]
    fn tampered_success_response_is_rejected() {
        let p = provider();
        let (mut verifier, id, mac) = signed_request(&p, false);
        let good = server_reply(&p.signer, id, &mac, ResponseCode::NoError, true);
        // Corrupt one MAC byte, leaving the id + RCODE intact, so the ONLY thing wrong
        // is the signature: a believed-success whose MAC no longer verifies.
        let mut resp = Message::from_vec(&good).unwrap();
        let mut sig = resp.take_signature().expect("reply carries a TSIG RR");
        sig.data.mac[0] ^= 0xFF;
        resp.set_signature(sig);
        let tampered = resp.to_vec().unwrap();
        let err = check_signed_response(&tampered, &mut verifier, id, false)
            .expect_err("a tampered success must not be trusted");
        assert!(matches!(err, DnsError::Backend(_)), "{err:?}");
    }

    #[test]
    fn response_id_mismatch_is_rejected() {
        let p = provider();
        let (mut verifier, id, mac) = signed_request(&p, false);
        // A perfectly-signed reply whose header id does not echo our request: a spoofed
        // or stale datagram, refused before the outcome is even weighed.
        let reply = server_reply(&p.signer, id ^ 0x1, &mac, ResponseCode::NoError, true);
        let err = check_signed_response(&reply, &mut verifier, id, false)
            .expect_err("an id mismatch must be rejected");
        match err {
            DnsError::Backend(m) => {
                assert!(m.contains("does not match request id"), "{m}");
            }
            other => panic!("expected a Backend error, got {other:?}"),
        }
    }

    #[test]
    fn spoofed_nxrrset_to_delete_is_not_believed() {
        let p = provider();

        // A SIGNED NXRRSet to a delete is the genuine authenticated idempotent no-op
        // ("already gone") — accepted.
        let (mut verifier, id, mac) = signed_request(&p, true);
        let signed = server_reply(&p.signer, id, &mac, ResponseCode::NXRRSet, true);
        check_signed_response(&signed, &mut verifier, id, true)
            .expect("a signed NXRRSet on a delete is the authenticated idempotent no-op");

        // An UNSIGNED NXRRSet is finding F1's attack: a forged "nothing to delete" that
        // would make us believe a failed teardown succeeded, leaving a stale custom-
        // domain pointer. It MUST NOT be believed.
        let (mut verifier, id, mac) = signed_request(&p, true);
        let spoofed = server_reply(&p.signer, id, &mac, ResponseCode::NXRRSet, false);
        let err = check_signed_response(&spoofed, &mut verifier, id, true)
            .expect_err("an unsigned NXRRSet on a delete must not be trusted as success");
        assert!(matches!(err, DnsError::Backend(_)), "{err:?}");
    }

    #[test]
    fn tsig_failure_rcodes_are_hard_errors() {
        let p = provider();
        // A TSIG/auth-failure RCODE is a hard error, never trusted as success, and
        // reading the RCODE never panics — whether or not the reply is signed. Real
        // servers return BADSIG/BADKEY/BADTIME UNSIGNED (RFC 8945 §5.3.2).
        for rcode in [
            ResponseCode::BADSIG,
            ResponseCode::BADKEY,
            ResponseCode::BADTIME,
            ResponseCode::NotAuth,
        ] {
            let (mut verifier, id, mac) = signed_request(&p, false);
            let reply = server_reply(&p.signer, id, &mac, rcode, false);
            let err = check_signed_response(&reply, &mut verifier, id, false)
                .expect_err("a TSIG-failure RCODE must be a hard error");
            assert!(
                matches!(err, DnsError::Backend(_)),
                "rcode {rcode:?}: {err:?}"
            );
        }
    }

    // ---- live seam (real dynamic-DNS server) -----------------------------

    /// End-to-end against a REAL RFC 2136 server (BIND / PowerDNS / Knot / nsd).
    /// `#[ignore]` by policy (no nameserver in CI — matches every other adapter's
    /// `#[ignore]` live seam); run on the lighthouse live gate with a configured
    /// `allow-update { key … };` zone. Proves the hand-rolled TCP framing + TSIG
    /// round-trip against a server that actually validates the signature, AND that the
    /// reply-authentication path (finding F1) holds against a real server: a WRONG-KEY
    /// provider's write is refused (the server answers a TSIG failure — BADKEY/BADSIG /
    /// NOTAUTH — which must surface as an error, never a believed success).
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
        let algorithm =
            std::env::var("RFC2136_TSIG_ALGORITHM").unwrap_or_else(|_| "hmac-sha256".to_string());
        let p = Rfc2136Dns::new(
            &var("RFC2136_SERVER"),
            &var("RFC2136_ZONE"),
            &var("RFC2136_TSIG_KEY_NAME"),
            &algorithm,
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

        // Finding F1, live: a WRONG-KEY provider (same key NAME, different secret) must
        // be refused by the real server — the TSIG-failure reply surfaces as an error,
        // not a believed success. This exercises the reply-authentication path end-to-
        // end against a server that actually produces a BADKEY/BADSIG/NOTAUTH answer.
        let wrong = Rfc2136Dns::new(
            &var("RFC2136_SERVER"),
            &zone,
            &var("RFC2136_TSIG_KEY_NAME"),
            &algorithm,
            // A valid-base64 but WRONG 32-byte secret.
            "d3Jvbmcta2V5LXdyb25nLWtleS13cm9uZy1rZXktMDE=",
        )
        .expect("wrong-key config builds");
        wrong
            .upsert(&rec)
            .await
            .expect_err("a wrong-key UPDATE must be refused by the server, not believed");
    }
}
