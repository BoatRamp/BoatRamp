//! The embedded DNS zone handler (plan §3.3): loopback `127.0.0.1:5353` (UDP + TCP), answering
//! **only** `<name>.svc.<cluster>.<zone>.` — resolving to `svc/<name>`, allocating/returning a
//! synthetic IP (A, short TTL) and recording the IP→service mapping. Absent from the catalog ⇒
//! NXDOMAIN; outside the zone ⇒ REFUSED (**never** recurses — this is split-horizon by construction:
//! a query this process cannot answer gets an explicit non-answer, never a guess and never a forward
//! to the real internet).
//!
//! Built on `hickory-proto`'s wire codec only (`op::Message::{from_vec,to_vec}` + `rr::*`) — this
//! hand-rolls the UDP/TCP listen loop and the single-zone matching logic itself, the same posture the
//! SOCKS front-end's hand-rolled codec takes (plan §2) and for the same reason: the parse/response
//! surface stays small, auditable, and entirely ours, rather than pulling in a general-purpose
//! authority/catalog server we would only ever use for one static zone.
//!
//! **Split by design, for testability (plan §6):** [`Zone::service_name`] and [`classify`] are pure,
//! synchronous string/name matching with zero I/O — unit-testable with no sockets, no runtime, no
//! catalog. [`respond`] adds exactly one async dependency (`is_known_service`, injected so the unit
//! tests below exercise it with a bare closure instead of a real [`crate::core::Tunnel`]) plus the
//! [`super::alloc::SyntheticIpAllocator`]. [`DnsServer`] is the thin socket-level glue on top.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

use super::alloc::{PoolExhausted, SyntheticIpAllocator};

/// Short TTL (plan §3.3) on every synthetic A answer: the mapping is only valid while THIS process
/// is running (a restart gets a fresh allocator), so a long-cached answer in some resolver would
/// outlive its own validity. 5s is short enough that a restart is invisible within one retry, long
/// enough not to turn every connection into its own DNS round trip.
pub const ANSWER_TTL_SECS: u32 = 5;

/// The configured zone (plan §9 open decision 1): operator-configurable `tld` (default `internal`,
/// RFC 8375), `cluster` label falling back to the project name. Fully qualified names this zone
/// answers for are `<name>.svc.<cluster>.<tld>.`
#[derive(Debug, Clone)]
pub struct Zone {
    pub tld: String,
    pub cluster: String,
}

impl Zone {
    #[must_use]
    pub fn new(tld: impl Into<String>, cluster: impl Into<String>) -> Self {
        Self {
            tld: tld.into(),
            cluster: cluster.into(),
        }
    }

    /// The zone suffix every answerable query must end with, fully qualified (trailing dot):
    /// `.svc.<cluster>.<tld>.`
    fn suffix(&self) -> String {
        format!(
            ".svc.{}.{}.",
            self.cluster.to_ascii_lowercase(),
            self.tld.to_ascii_lowercase()
        )
    }

    /// If `qname` (a raw DNS question name, e.g. `db.svc.myproj.internal` or
    /// `db.svc.myproj.internal.`) is inside this zone, the service-name candidate before the suffix
    /// (e.g. `db`) — **not yet checked against the catalog**; see [`classify`]. `None` ⇒ out of zone
    /// (plan §5 split-horizon: REFUSE, never recurse).
    #[must_use]
    pub fn service_name(&self, qname: &str) -> Option<String> {
        let mut fqdn = qname.to_ascii_lowercase();
        if !fqdn.ends_with('.') {
            fqdn.push('.');
        }
        let head = fqdn.strip_suffix(&self.suffix())?;
        if head.is_empty() {
            return None; // the bare zone apex (`svc.<cluster>.<tld>.`) names no service
        }
        Some(head.to_string())
    }
}

/// The outcome of matching one query name against the zone — before any catalog/allocator lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// In-zone; this is the candidate service name (not yet normalized or catalog-checked).
    InZone(String),
    /// Outside the configured zone — REFUSE, never recurse (plan §3.3/§5).
    OutOfZone,
}

/// Pure zone matching (plan §6: "DNS zone handler (in-zone→A, unknown→NXDOMAIN, out-of-zone→
/// refuse)" — this is the "in-zone vs. out-of-zone" half; catalog membership is [`respond`]'s job).
#[must_use]
pub fn classify(zone: &Zone, qname: &str) -> Classification {
    match zone.service_name(qname) {
        Some(name) => Classification::InZone(name),
        None => Classification::OutOfZone,
    }
}

/// Build the wire-format response to `query_bytes`. `is_known_service` is the injected catalog
/// check (in production, `|name| tunnel.catalog_contains(name)`-shaped; in the unit tests below, a
/// bare closure over a fixed set) — kept async because the real check (plan §1.2) may refresh the
/// catalog on a miss. Never recurses: every path here returns a response built entirely from
/// `zone`/`allocator`/`is_known_service`, never a forwarded upstream query.
///
/// # Errors
/// Only on a wire-level failure (an unparseable query, or the allocator's pool exhausted while
/// minting a fresh answer) — both already-safe-to-not-respond cases the caller treats as "drop the
/// datagram" (plan §5: a malformed/hostile packet gets silence, not a crash).
pub async fn respond<F, Fut>(
    query_bytes: &[u8],
    zone: &Zone,
    allocator: &SyntheticIpAllocator,
    is_known_service: F,
) -> Result<Vec<u8>, DnsError>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    let query = Message::from_vec(query_bytes).map_err(|e| DnsError::Parse(e.into()))?;
    // hickory-proto 0.26 folded id/message_type/op_code/response_code/recursion_available into
    // `Message::metadata` (a plain `Metadata` struct); `Message::new` now takes the first three
    // directly instead of the removed `set_id`/`set_message_type`/`set_op_code` setters.
    let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    // RD (recursion desired) is whatever the client asked; RA (recursion AVAILABLE) is always
    // false — this resolver never recurses, by construction (plan §3.3/§5 split-horizon).
    // (`Metadata::new` already defaults this to false; set explicitly for clarity.)
    response.metadata.recursion_available = false;

    let Some(question) = query.queries.first().cloned() else {
        response.metadata.response_code = ResponseCode::FormErr;
        return response.to_vec().map_err(DnsError::Encode);
    };
    response.add_query(question.clone());

    let qname = question.name().to_string();
    match classify(zone, &qname) {
        Classification::OutOfZone => {
            // Plan §3.3/§5: out-of-zone is REFUSED, never recursed — the split-horizon invariant.
            response.metadata.response_code = ResponseCode::Refused;
        }
        Classification::InZone(candidate) => match is_known_service(candidate).await {
            None => {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            Some(canonical_service) => {
                response.metadata.response_code = ResponseCode::NoError;
                if question.query_type() == RecordType::A {
                    let addr = allocator
                        .allocate(&canonical_service)
                        .map_err(DnsError::PoolExhausted)?;
                    let mut record = Record::from_rdata(
                        question.name().clone(),
                        ANSWER_TTL_SECS,
                        RData::A(A(addr)),
                    );
                    record.dns_class = DNSClass::IN;
                    response.add_answer(record);
                }
                // A known service queried as a non-A type (e.g. AAAA — this zone is IPv4-only)
                // gets NOERROR with an empty answer section (NODATA): the name exists, this record
                // type does not, which is the correct DNS answer — NOT NXDOMAIN (that would claim
                // the name itself does not exist).
            }
        },
    }

    response.to_vec().map_err(DnsError::Encode)
}

/// A failure building a DNS response.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("parsing DNS query: {0}")]
    Parse(#[source] hickory_proto::ProtoError),
    #[error("encoding DNS response: {0}")]
    Encode(#[source] hickory_proto::ProtoError),
    #[error(transparent)]
    PoolExhausted(#[from] PoolExhausted),
}

/// Checks a candidate service name against a [`crate::core::Tunnel`]'s catalog (production glue for
/// [`respond`]'s `is_known_service`): normalizes via [`crate::core::Tunnel::resolve_name`], then
/// looks the canonical name up in the current catalog snapshot. Returns the canonical `svc/<name>`
/// on a hit so [`respond`] allocates/answers under the SAME key the catalog and cap-cache use.
pub async fn tunnel_catalog_lookup(
    tunnel: &crate::core::Tunnel,
    candidate: String,
) -> Option<String> {
    let canonical = tunnel.resolve_name(&candidate);
    let hit = tunnel
        .catalog()
        .await
        .into_iter()
        .any(|entry| entry.service == canonical);
    hit.then_some(canonical)
}

/// A bound embedded DNS front-end (UDP + TCP, plan §3.3), ready to [`serve`](Self::serve).
pub struct DnsServer {
    udp: UdpSocket,
    tcp: TcpListener,
    zone: Zone,
    allocator: Arc<SyntheticIpAllocator>,
    tunnel: Arc<crate::core::Tunnel>,
}

/// A failure standing up or running the embedded DNS front-end.
#[derive(Debug, thiserror::Error)]
pub enum DnsServerError {
    #[error("binding DNS {0}: {1}")]
    Bind(SocketAddr, #[source] std::io::Error),
    #[error("accept: {0}")]
    Accept(#[source] std::io::Error),
}

/// How long one TCP DNS connection's whole exchange (length-prefix + query, response write) may
/// take — bounds a slow-loris peer exactly like the SOCKS front-end's handshake timeout
/// (`socks::server::HANDSHAKE_TIMEOUT`). DNS-over-TCP is a short, bounded exchange by nature.
const TCP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on concurrent in-flight DNS-over-TCP connections (Security review LOW — mirrors the SOCKS
/// front-end's own connection cap, `socks::DEFAULT_MAX_CONNECTIONS`/Security MEDIUM-3 there):
/// bounds a peer opening TCP DNS connections faster than they're served from spawning an unbounded
/// number of tasks / exhausting file descriptors. DNS-over-TCP is a rare, short-lived path in
/// practice (most queries are UDP, which never spawns a per-datagram task to begin with); this is
/// deliberately generous rather than tightly tuned.
const MAX_TCP_CONNECTIONS: usize = 256;

impl DnsServer {
    /// Bind UDP + TCP on `addr` (plan default `127.0.0.1:5353`).
    pub async fn bind(
        addr: SocketAddr,
        zone: Zone,
        allocator: Arc<SyntheticIpAllocator>,
        tunnel: Arc<crate::core::Tunnel>,
    ) -> Result<Self, DnsServerError> {
        let udp = UdpSocket::bind(addr)
            .await
            .map_err(|e| DnsServerError::Bind(addr, e))?;
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|e| DnsServerError::Bind(addr, e))?;
        Ok(Self {
            udp,
            tcp,
            zone,
            allocator,
            tunnel,
        })
    }

    /// The actually-bound address (resolves `:0` to the OS-assigned port — used by tests; production
    /// always binds the configured fixed port).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// Serve UDP + TCP until a fatal I/O error. Mirrors [`super::super::socks::SocksServer::serve`]'s
    /// shape: each datagram/connection is handled independently; one bad packet never takes the
    /// listener down.
    pub async fn serve(self) -> Result<(), DnsServerError> {
        let Self {
            udp,
            tcp,
            zone,
            allocator,
            tunnel,
        } = self;
        let udp = Arc::new(udp);
        let udp_loop = {
            let udp = Arc::clone(&udp);
            let zone = zone.clone();
            let allocator = Arc::clone(&allocator);
            let tunnel = Arc::clone(&tunnel);
            async move { serve_udp(&udp, &zone, &allocator, &tunnel).await }
        };
        let tcp_loop = serve_tcp(tcp, zone, allocator, tunnel);
        tokio::try_join!(udp_loop, tcp_loop)?;
        Ok(())
    }
}

async fn serve_udp(
    udp: &UdpSocket,
    zone: &Zone,
    allocator: &SyntheticIpAllocator,
    tunnel: &Arc<crate::core::Tunnel>,
) -> Result<(), DnsServerError> {
    // 64 KiB is the max a single DNS-over-UDP message could ever need (EDNS0 aside, which this
    // zone's tiny single-A-record answers never approach); oversized reads are simply truncated by
    // `recv_from`, which then fails to parse as a valid message and is dropped — never a panic.
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = udp
            .recv_from(&mut buf)
            .await
            .map_err(DnsServerError::Accept)?;
        let tunnel = Arc::clone(tunnel);
        match respond(&buf[..len], zone, allocator, |name| {
            let tunnel = Arc::clone(&tunnel);
            async move { tunnel_catalog_lookup(&tunnel, name).await }
        })
        .await
        {
            Ok(reply) => {
                if let Err(err) = udp.send_to(&reply, peer).await {
                    tracing::debug!(%peer, error = %err, "boatramp tunnel: DNS UDP reply send failed");
                }
            }
            Err(err) => {
                // A malformed query or an exhausted pool is dropped silently (plan §5: never crash
                // on hostile/malformed input) — the client's own resolver retries or times out.
                tracing::debug!(%peer, error = %err, "boatramp tunnel: DNS UDP query dropped");
            }
        }
    }
}

async fn serve_tcp(
    listener: TcpListener,
    zone: Zone,
    allocator: Arc<SyntheticIpAllocator>,
    tunnel: Arc<crate::core::Tunnel>,
) -> Result<(), DnsServerError> {
    // Acquired BEFORE spawning (same reasoning as `socks::server::accept_loop`): a saturated cap
    // backpressures the accept loop itself, rather than piling up unbounded spawned tasks each
    // waiting on a permit.
    let semaphore = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await.map_err(DnsServerError::Accept)?;
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("the DNS TCP connection semaphore is never closed");
        let zone = zone.clone();
        let allocator = Arc::clone(&allocator);
        let tunnel = Arc::clone(&tunnel);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = tokio::time::timeout(
                TCP_EXCHANGE_TIMEOUT,
                handle_tcp(stream, &zone, &allocator, &tunnel),
            )
            .await
            {
                tracing::debug!(%peer, error = %err, "boatramp tunnel: DNS TCP exchange timed out");
            }
        });
    }
}

async fn handle_tcp(
    mut stream: tokio::net::TcpStream,
    zone: &Zone,
    allocator: &SyntheticIpAllocator,
    tunnel: &Arc<crate::core::Tunnel>,
) {
    // DNS-over-TCP (RFC 1035 §4.2.2): a 2-byte big-endian length prefix, then exactly that many
    // message bytes.
    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut query_buf = vec![0u8; len];
    if stream.read_exact(&mut query_buf).await.is_err() {
        return;
    }
    let tunnel = Arc::clone(tunnel);
    let reply = respond(&query_buf, zone, allocator, |name| {
        let tunnel = Arc::clone(&tunnel);
        async move { tunnel_catalog_lookup(&tunnel, name).await }
    })
    .await;
    let Ok(reply) = reply else {
        return;
    };
    let Ok(reply_len) = u16::try_from(reply.len()) else {
        return;
    };
    let _ = stream.write_all(&reply_len.to_be_bytes()).await;
    let _ = stream.write_all(&reply).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_zone() -> Zone {
        Zone::new("internal", "myproj")
    }

    #[test]
    fn an_in_zone_name_yields_its_service_candidate() {
        assert_eq!(
            classify(&test_zone(), "db.svc.myproj.internal."),
            Classification::InZone("db".to_string())
        );
        // Non-FQDN (no trailing dot) input is accepted the same way — a resolver forwards queries
        // either way.
        assert_eq!(
            classify(&test_zone(), "db.svc.myproj.internal"),
            Classification::InZone("db".to_string())
        );
        // Case-folded.
        assert_eq!(
            classify(&test_zone(), "DB.SVC.MYPROJ.INTERNAL."),
            Classification::InZone("db".to_string())
        );
    }

    #[test]
    fn an_out_of_zone_name_is_refused_not_guessed() {
        assert_eq!(
            classify(&test_zone(), "example.com."),
            Classification::OutOfZone
        );
        // A different cluster label under the SAME tld is still out of zone — the zone is scoped to
        // exactly one cluster (plan §5 per-project isolation extends to the DNS front-end too).
        assert_eq!(
            classify(&test_zone(), "db.svc.otherproj.internal."),
            Classification::OutOfZone
        );
        // The bare zone apex names no service.
        assert_eq!(
            classify(&test_zone(), "svc.myproj.internal."),
            Classification::OutOfZone
        );
    }

    fn build_query(qname: &str, qtype: RecordType) -> Vec<u8> {
        use hickory_proto::op::Query;
        use hickory_proto::rr::Name;
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_ascii(qname).unwrap();
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(qtype);
        query.set_query_class(DNSClass::IN);
        msg.add_query(query);
        msg.to_vec().unwrap()
    }

    async fn known(_names: &[&str], candidate: String) -> Option<String> {
        if _names.contains(&candidate.as_str()) {
            Some(format!("svc/{candidate}"))
        } else {
            None
        }
    }

    #[tokio::test]
    async fn an_in_zone_known_service_a_query_gets_an_answer() {
        let zone = test_zone();
        let allocator = SyntheticIpAllocator::new(super::super::cidr::default_cidr());
        let query = build_query("db.svc.myproj.internal.", RecordType::A);
        let reply_bytes = respond(&query, &zone, &allocator, |name| known(&["db"], name))
            .await
            .unwrap();
        let reply = Message::from_vec(&reply_bytes).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
        assert!(
            !reply.metadata.recursion_available,
            "must never advertise recursion"
        );
        let RData::A(A(addr)) = &reply.answers[0].data else {
            panic!("expected an A record");
        };
        assert!(allocator.cidr().contains(*addr));
        assert_eq!(allocator.resolve(*addr), Some("svc/db".to_string()));
    }

    #[tokio::test]
    async fn an_in_zone_unknown_service_is_nxdomain() {
        let zone = test_zone();
        let allocator = SyntheticIpAllocator::new(super::super::cidr::default_cidr());
        let query = build_query("ghost.svc.myproj.internal.", RecordType::A);
        let reply_bytes = respond(&query, &zone, &allocator, |name| known(&["db"], name))
            .await
            .unwrap();
        let reply = Message::from_vec(&reply_bytes).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(reply.answers.is_empty());
        // An unknown name must never consume a synthetic address.
        assert_eq!(allocator.len(), 0);
    }

    #[tokio::test]
    async fn an_out_of_zone_query_is_refused_never_recursed() {
        let zone = test_zone();
        let allocator = SyntheticIpAllocator::new(super::super::cidr::default_cidr());
        let query = build_query("example.com.", RecordType::A);
        let reply_bytes = respond(&query, &zone, &allocator, |name| known(&["db"], name))
            .await
            .unwrap();
        let reply = Message::from_vec(&reply_bytes).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        assert!(reply.answers.is_empty());
    }

    #[tokio::test]
    async fn a_known_service_queried_as_aaaa_is_nodata_not_nxdomain() {
        let zone = test_zone();
        let allocator = SyntheticIpAllocator::new(super::super::cidr::default_cidr());
        let query = build_query("db.svc.myproj.internal.", RecordType::AAAA);
        let reply_bytes = respond(&query, &zone, &allocator, |name| known(&["db"], name))
            .await
            .unwrap();
        let reply = Message::from_vec(&reply_bytes).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty(), "IPv4-only zone: AAAA is NODATA");
    }

    #[tokio::test]
    async fn repeated_queries_for_the_same_service_return_a_stable_address() {
        let zone = test_zone();
        let allocator = SyntheticIpAllocator::new(super::super::cidr::default_cidr());
        let query = build_query("db.svc.myproj.internal.", RecordType::A);
        let first = Message::from_vec(
            &respond(&query, &zone, &allocator, |name| known(&["db"], name))
                .await
                .unwrap(),
        )
        .unwrap();
        let second = Message::from_vec(
            &respond(&query, &zone, &allocator, |name| known(&["db"], name))
                .await
                .unwrap(),
        )
        .unwrap();
        let RData::A(A(a1)) = &first.answers[0].data else {
            panic!()
        };
        let RData::A(A(a2)) = &second.answers[0].data else {
            panic!()
        };
        assert_eq!(a1, a2);
    }

    #[tokio::test]
    async fn a_malformed_query_is_reported_as_a_parse_error_not_a_panic() {
        let zone = test_zone();
        let allocator = SyntheticIpAllocator::new(super::super::cidr::default_cidr());
        // Far too short to even hold a 12-byte DNS header — guaranteed to fail parsing rather than
        // (as a longer garbage buffer might) parse as a header with a nonsensical question count.
        let err = respond(b"\x00\x01\x02", &zone, &allocator, |name| {
            known(&["db"], name)
        })
        .await
        .unwrap_err();
        assert!(matches!(err, DnsError::Parse(_)));
    }
}
