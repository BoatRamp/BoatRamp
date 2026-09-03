//! Per-project **internal DNS** — the pure, host-testable query-handling logic.
//!
//! boatramp runs a lightweight DNS responder on the compute **bridge gateway**
//! (`10.0.0.1:53`) so every co-located container resolves peers **by name** within
//! its project, instead of the control plane injecting a numeric `ip:port`. Each
//! container's `/etc/resolv.conf` points its single `nameserver` at the gateway
//! (see [`crate::resolvconf`]), so *all* of the guest's DNS — internal names AND
//! the outside world — flows through this resolver.
//!
//! This module is the **decision core**, deliberately free of any socket / netns /
//! netlink code so it compiles and unit-tests on every host (macOS included). It
//! parses a DNS question, then — given two injected closures — decides one of:
//!
//! * **answer** an internal `A`/`AAAA` name with a workload's live replica IP,
//! * **NXDOMAIN** an internal name that resolves to nothing *within the querying
//!   container's project* (the isolation boundary), or
//! * **forward** everything else (external names, non-`A`/`AAAA` types, and — the
//!   security-critical case — *every* query from a source IP that is not a known
//!   co-located container) to the upstream resolver, relaying its bytes verbatim.
//!
//! The **isolation** property is that the answer for an internal name is scoped by
//! the *source IP → project* map: a container in project `a` can only ever be told
//! the IP of a workload in project `a`. It is proven by
//! [`tests::project_a_cannot_resolve_project_b`].
//!
//! The Linux socket seam that binds `gateway:53`, reads the source IP off each
//! datagram, and drives [`Resolver::handle_query`] lives in [`crate::dns_server`].

use std::net::{Ipv4Addr, Ipv6Addr};

/// The internal DNS suffix every project's names live under: a workload `web` in
/// project `acme` answers to both the bare `web` and the FQDN
/// `web.acme.boatramp.internal`. Configurable via `compute.dns_domain`
/// (default `boatramp.internal`); the resolver is built with the effective value.
pub const DEFAULT_INTERNAL_DOMAIN: &str = "boatramp.internal";

/// A parsed DNS question — the single question a standard resolver query carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The queried name, lower-cased, dot-joined, no trailing dot (e.g. `web.acme`).
    pub name: String,
    /// The `QTYPE` (1 = A, 28 = AAAA, others forwarded opaquely).
    pub qtype: u16,
    /// The `QCLASS` (1 = IN; anything else is forwarded).
    pub qclass: u16,
}

/// `QTYPE`/`QCLASS` constants used by the internal path.
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// What the resolver decided for a query, returned by [`Resolver::handle_query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// We built a complete DNS response (answer, NXDOMAIN, or REFUSED); send these
    /// bytes straight back to the querying container.
    Reply(Vec<u8>),
    /// Not an internal query we answer — relay the *original* query bytes to the
    /// configured upstream resolver and return its response verbatim.
    Forward,
}

/// DNS `RCODE`s we emit.
mod rcode {
    /// No error — a normal answer (possibly with zero records).
    pub const NOERROR: u8 = 0;
    /// Format error — the query was unparsable.
    pub const FORMERR: u8 = 1;
    /// The name does not exist (no such internal workload in this project).
    pub const NXDOMAIN: u8 = 3;
    /// Refused — the source is a known container but the name belongs to another
    /// project (a cross-tenant lookup we must never satisfy).
    pub const REFUSED: u8 = 5;
}

/// The internal resolver: the effective internal domain plus the two lookups the
/// socket layer injects.
///
/// * `source_project` maps a **query source IP** to the project (and workload) of
///   the co-located container that owns it, or `None` when the source is not a
///   known container. This is the isolation anchor: an unknown source is answered
///   forward-only, and a known source can only ever be handed its *own* project's
///   names.
/// * `lookup` maps `(project, workload)` to the workload's current healthy replica
///   IPs (primary-first) — the same data [`DeployEndpointResolver`] serves the SQL
///   binding, here surfaced as name resolution.
///
/// [`DeployEndpointResolver`]: (in boatramp-node) the control-plane replica-state resolver.
pub struct Resolver<S, L> {
    /// The internal suffix (`boatramp.internal`), stored lower-cased, no dots at
    /// the ends. A name is "internal" iff it equals `<workload>.<project>.<domain>`
    /// or is the bare `<workload>` form.
    domain: String,
    /// Source IP → the owning container's `(project, workload)`; `None` ⇒ not one
    /// of our co-located containers.
    source_project: S,
    /// `(project, workload)` → the workload's healthy replica IPs (primary-first).
    lookup: L,
}

/// The addresses a workload resolves to, split by family so the resolver answers
/// only the queried `QTYPE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedAddrs {
    /// IPv4 replica addresses (for an `A` query), primary-first.
    pub v4: Vec<Ipv4Addr>,
    /// IPv6 replica addresses (for an `AAAA` query), primary-first.
    pub v6: Vec<Ipv6Addr>,
}

impl ResolvedAddrs {
    /// Whether the workload has no address at all (⇒ NXDOMAIN for a known,
    /// in-project name).
    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

impl<S, L> Resolver<S, L>
where
    S: Fn(Ipv4Addr) -> Option<(String, String)>,
    L: Fn(&str, &str) -> ResolvedAddrs,
{
    /// Build a resolver over the effective internal `domain` and the two lookups.
    pub fn new(domain: impl Into<String>, source_project: S, lookup: L) -> Self {
        let domain = domain.into().trim_matches('.').to_ascii_lowercase();
        Self {
            domain,
            source_project,
            lookup,
        }
    }

    /// Decide what to do with `query` (a full DNS request datagram) that arrived
    /// from container source IP `src`.
    ///
    /// The rules (in order):
    /// 1. Unparsable → a `FORMERR` reply (never forwarded — a malformed datagram
    ///    should not be relayed to the upstream).
    /// 2. Not an `IN` `A`/`AAAA` question, or a name that isn't in our internal
    ///    domain → **forward** (the guest's ordinary outbound DNS).
    /// 3. An internal name (`<workload>` or `<workload>.<project>.<domain>`):
    ///    * unknown source IP → **forward** (never leak internal names to a source
    ///      we don't own — treat it as a plain forwarder client),
    ///    * name's project ≠ the source's project → `REFUSED` (the cross-tenant
    ///      wall),
    ///    * in-project workload with a healthy replica → an `A`/`AAAA` **answer**,
    ///    * in-project name with no healthy replica (or no such workload) →
    ///      `NXDOMAIN`.
    pub fn handle_query(&self, src: Ipv4Addr, query: &[u8]) -> Decision {
        let parsed = match parse_query(query) {
            Some(p) => p,
            // A datagram we can't parse as a single-question query: answer FORMERR
            // rather than forwarding garbage upstream. If there's no id we can echo
            // (too short to even hold a header) there's nothing to send — reply with
            // a best-effort zeroed header.
            None => return Decision::Reply(error_reply(query, rcode::FORMERR)),
        };

        // Only IN A/AAAA questions are candidates for an internal answer; everything
        // else is ordinary outbound DNS the guest expects us to forward.
        let internal_type =
            matches!(parsed.q.qtype, TYPE_A | TYPE_AAAA) && parsed.q.qclass == CLASS_IN;
        if !internal_type {
            return Decision::Forward;
        }
        let Some((query_project, workload)) = self.classify_internal(&parsed.q.name) else {
            // Not one of our internal names ⇒ forward (an external name, or a name
            // in some other domain the guest asked for).
            return Decision::Forward;
        };

        // Isolation anchor: who is asking? An unknown source (not a co-located
        // container) is treated as a plain forwarder client — we never answer it an
        // internal name (that would leak the internal topology to an untracked peer).
        let Some((src_project, _src_workload)) = (self.source_project)(src) else {
            return Decision::Forward;
        };

        // The cross-tenant wall: a container may resolve ONLY its own project's
        // names. A name that carried an explicit foreign project (`w.other.<domain>`)
        // is REFUSED; the bare `<workload>` form is always interpreted in the
        // source's own project, so it can never address another tenant.
        let project = match query_project {
            // Explicit project in the FQDN.
            Some(p) if p == src_project => src_project.clone(),
            Some(_) => return Decision::Reply(error_reply(query, rcode::REFUSED)),
            // Bare `<workload>`: resolve within the source's own project.
            None => src_project.clone(),
        };

        let addrs = (self.lookup)(&project, &workload);
        if addrs.is_empty() {
            // A known, in-project name that currently resolves to nothing: NXDOMAIN,
            // so the guest fails fast instead of falling through to the internet.
            return Decision::Reply(error_reply(query, rcode::NXDOMAIN));
        }
        Decision::Reply(answer_reply(&parsed, &addrs))
    }

    /// Classify a queried name as an internal name and extract `(project, workload)`.
    ///
    /// Returns:
    /// * `Some((Some(project), workload))` for a fully-qualified
    ///   `<workload>.<project>.<domain>`,
    /// * `Some((None, workload))` for the bare single-label `<workload>` (project is
    ///   the caller's own, decided by the source IP),
    /// * `None` for anything not in our internal namespace (⇒ forward).
    fn classify_internal(&self, name: &str) -> Option<(Option<String>, String)> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(prefix) = name.strip_suffix(&format!(".{}", self.domain)) {
            // `<workload>.<project>` — exactly two labels ahead of the domain.
            let mut labels = prefix.rsplitn(2, '.');
            let project = labels.next()?.to_string();
            let workload = labels.next()?.to_string();
            if project.is_empty() || workload.is_empty() || workload.contains('.') {
                return None;
            }
            return Some((Some(project), workload));
        }
        // A bare single label with no dots is a same-project short name (`web`); a
        // multi-label name outside our domain is external.
        if !name.is_empty() && !name.contains('.') {
            return Some((None, name));
        }
        None
    }
}

/// A parsed query: the header id/flags plus its single question and the raw
/// question section (echoed verbatim into the answer, which is simplest + exact).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedQuery {
    /// The 16-bit transaction id (echoed into the reply).
    id: u16,
    /// The parsed question.
    q: Question,
    /// The raw bytes of the question section (name + qtype + qclass), so the reply
    /// can echo it without re-encoding the (compressible) name.
    question_wire: Vec<u8>,
}

/// Parse a DNS query datagram, extracting the id and its single question. Returns
/// `None` for anything that isn't a well-formed single-question query (which the
/// caller answers `FORMERR`). Only the fields the internal path needs are read;
/// name compression in a *question* is not permitted by the spec, so a plain label
/// walk is sufficient and safe (bounded by the packet length).
fn parse_query(buf: &[u8]) -> Option<ParsedQuery> {
    if buf.len() < 12 {
        return None; // no room for the 12-byte header
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return None; // exactly one question on the internal path
    }
    // Walk the QNAME labels starting right after the header.
    let mut pos = 12;
    let name_start = pos;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *buf.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break; // root label terminates the name
        }
        // A compression pointer (top two bits set) is illegal in a question; reject.
        if len & 0xC0 != 0 {
            return None;
        }
        let end = pos.checked_add(len)?;
        let label = buf.get(pos..end)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos = end;
    }
    let qtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*buf.get(pos + 2)?, *buf.get(pos + 3)?]);
    let question_end = pos + 4;
    let question_wire = buf.get(name_start..question_end)?.to_vec();
    Some(ParsedQuery {
        id,
        q: Question {
            name: labels.join("."),
            qtype,
            qclass,
        },
        question_wire,
    })
}

/// Build a response header for `id` with the standard response flags: QR=1
/// (response), AA=1 (we are authoritative for the internal zone), RD copied from
/// the request is unnecessary here (we set RA=0 — the internal zone is not a
/// recursive service), and the given `rcode` in the low nibble of byte 3.
fn response_header(id: u16, rcode: u8, ancount: u16) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0..2].copy_from_slice(&id.to_be_bytes());
    // Byte 2: QR=1, Opcode=0, AA=1, TC=0, RD=0.
    h[2] = 0b1000_0100;
    // Byte 3: RA=0, Z=0, RCODE.
    h[3] = rcode & 0x0F;
    // QDCOUNT = 1 (we echo the question); ANCOUNT as given; NSCOUNT + ARCOUNT stay 0.
    h[4..6].copy_from_slice(&1u16.to_be_bytes());
    h[6..8].copy_from_slice(&ancount.to_be_bytes());
    h
}

/// Build an error reply (NXDOMAIN / REFUSED / FORMERR) echoing the request's id and
/// — when parseable — its question section, with zero answers. For a datagram too
/// short to even hold a header we still emit a 12-byte header (id 0) so the socket
/// layer always has something to send.
fn error_reply(query: &[u8], rcode: u8) -> Vec<u8> {
    // Best-effort id echo: the first two bytes if present.
    let id = if query.len() >= 2 {
        u16::from_be_bytes([query[0], query[1]])
    } else {
        0
    };
    match parse_query(query) {
        Some(p) => {
            let mut out = response_header(id, rcode, 0).to_vec();
            out.extend_from_slice(&p.question_wire);
            out
        }
        None => {
            // Unparsable: header only, QDCOUNT forced to 0 (we didn't echo a question).
            let mut h = response_header(id, rcode, 0);
            h[4..6].copy_from_slice(&0u16.to_be_bytes());
            h.to_vec()
        }
    }
}

/// Build an answer echoing the question and appending one record per address of the
/// queried family (A for `TYPE_A`, AAAA for `TYPE_AAAA`). Each answer uses a
/// compression pointer (`0xC00C`) back to the question's name at offset 12 — the
/// standard, compact encoding every resolver understands.
fn answer_reply(parsed: &ParsedQuery, addrs: &ResolvedAddrs) -> Vec<u8> {
    /// TTL for an internal record (seconds). Short, so a replica move / restart is
    /// picked up quickly by a guest that caches.
    const TTL: u32 = 30;
    // Only answer the queried family.
    let (rtype, rdata): (u16, Vec<Vec<u8>>) = match parsed.q.qtype {
        TYPE_A => (
            TYPE_A,
            addrs.v4.iter().map(|ip| ip.octets().to_vec()).collect(),
        ),
        TYPE_AAAA => (
            TYPE_AAAA,
            addrs.v6.iter().map(|ip| ip.octets().to_vec()).collect(),
        ),
        _ => (parsed.q.qtype, Vec::new()),
    };
    let ancount = rdata.len() as u16;
    let mut out = response_header(parsed.id, rcode::NOERROR, ancount).to_vec();
    out.extend_from_slice(&parsed.question_wire);
    for data in &rdata {
        // NAME: pointer to the question name at offset 12.
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Encode a query datagram for `name`/`qtype` with transaction id `id` — the
    /// standard wire form a stub resolver in a guest would send.
    fn encode_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
        for label in name.trim_end_matches('.').split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // root
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&qclass.to_be_bytes());
        buf
    }

    /// Decode the `RCODE` from a reply's header byte 3.
    fn rcode_of(reply: &[u8]) -> u8 {
        reply[3] & 0x0F
    }

    /// Decode the ANCOUNT from a reply header.
    fn ancount_of(reply: &[u8]) -> u16 {
        u16::from_be_bytes([reply[6], reply[7]])
    }

    /// Extract the A-record IPv4 addresses from a reply (walk past the echoed
    /// question, then read each 16-byte-ish answer's rdata). Assumes our own
    /// `answer_reply` encoding (pointer name + fixed record shape).
    fn a_records(reply: &[u8]) -> Vec<Ipv4Addr> {
        // Skip header (12) + question: re-find the question end by walking the name.
        let mut pos = 12;
        while reply[pos] != 0 {
            pos += 1 + reply[pos] as usize;
        }
        pos += 1 + 4; // root + qtype + qclass
        let mut out = Vec::new();
        let mut i = 0;
        while i < ancount_of(reply) {
            // name pointer (2) + type (2) + class (2) + ttl (4) + rdlen (2)
            let rtype = u16::from_be_bytes([reply[pos + 2], reply[pos + 3]]);
            let rdlen = u16::from_be_bytes([reply[pos + 10], reply[pos + 11]]) as usize;
            let rdata = &reply[pos + 12..pos + 12 + rdlen];
            if rtype == TYPE_A && rdlen == 4 {
                out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            }
            pos += 12 + rdlen;
            i += 1;
        }
        out
    }

    /// Source IP → (project, workload).
    type OwnerMap = BTreeMap<Ipv4Addr, (String, String)>;
    /// (project, workload) → v4 addrs.
    type AddrMap = BTreeMap<(String, String), Vec<Ipv4Addr>>;

    /// A fleet: source IP → (project, workload), and (project, workload) → v4 addrs.
    fn fleet() -> (OwnerMap, AddrMap) {
        let mut owners = BTreeMap::new();
        // project "a": a "web" container at .2 and a "db" workload at .3.
        owners.insert(
            Ipv4Addr::new(10, 0, 0, 2),
            ("a".to_string(), "web".to_string()),
        );
        owners.insert(
            Ipv4Addr::new(10, 0, 0, 3),
            ("a".to_string(), "db".to_string()),
        );
        // project "b": a "db" workload at .4 (same short name as a's, different tenant).
        owners.insert(
            Ipv4Addr::new(10, 0, 0, 4),
            ("b".to_string(), "db".to_string()),
        );
        let mut addrs = BTreeMap::new();
        addrs.insert(
            ("a".to_string(), "db".to_string()),
            vec![Ipv4Addr::new(10, 0, 0, 3)],
        );
        addrs.insert(
            ("a".to_string(), "web".to_string()),
            vec![Ipv4Addr::new(10, 0, 0, 2)],
        );
        addrs.insert(
            ("b".to_string(), "db".to_string()),
            vec![Ipv4Addr::new(10, 0, 0, 4)],
        );
        (owners, addrs)
    }

    #[allow(clippy::type_complexity)]
    fn resolver(
        owners: OwnerMap,
        addrs: AddrMap,
    ) -> Resolver<impl Fn(Ipv4Addr) -> Option<(String, String)>, impl Fn(&str, &str) -> ResolvedAddrs>
    {
        Resolver::new(
            DEFAULT_INTERNAL_DOMAIN,
            move |ip| owners.get(&ip).cloned(),
            move |p, w| ResolvedAddrs {
                v4: addrs
                    .get(&(p.to_string(), w.to_string()))
                    .cloned()
                    .unwrap_or_default(),
                v6: Vec::new(),
            },
        )
    }

    #[test]
    fn in_project_bare_name_resolves_to_the_workload_ip() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // The "web" container (10.0.0.2) asks for the bare short name "db".
        let q = encode_query(0x1234, "db", TYPE_A, CLASS_IN);
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("expected an internal answer, got forward");
        };
        assert_eq!(rcode_of(&reply), rcode::NOERROR);
        assert_eq!(
            u16::from_be_bytes([reply[0], reply[1]]),
            0x1234,
            "echoes id"
        );
        assert_eq!(a_records(&reply), vec![Ipv4Addr::new(10, 0, 0, 3)]);
    }

    #[test]
    fn in_project_fqdn_resolves_to_the_workload_ip() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        let q = encode_query(0x2, "db.a.boatramp.internal", TYPE_A, CLASS_IN);
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("expected an internal answer");
        };
        assert_eq!(rcode_of(&reply), rcode::NOERROR);
        assert_eq!(a_records(&reply), vec![Ipv4Addr::new(10, 0, 0, 3)]);
    }

    /// THE ISOLATION TEST: project a's container must NOT be able to resolve project
    /// b's workload by its explicit FQDN — the cross-tenant lookup is REFUSED, and it
    /// never leaks b's address.
    #[test]
    fn project_a_cannot_resolve_project_b() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // a's "web" container (10.0.0.2) tries the FQDN of b's "db".
        let q = encode_query(0x3, "db.b.boatramp.internal", TYPE_A, CLASS_IN);
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("a cross-project internal name must not be forwarded");
        };
        assert_eq!(
            rcode_of(&reply),
            rcode::REFUSED,
            "cross-project resolution must be REFUSED"
        );
        assert_eq!(ancount_of(&reply), 0, "and must carry no address for b");
        assert!(
            a_records(&reply).is_empty(),
            "b's address must never leak into a's answer"
        );

        // The bare short name "db" from a's container resolves to a's OWN db, never b's.
        let q2 = encode_query(0x4, "db", TYPE_A, CLASS_IN);
        let Decision::Reply(reply2) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q2) else {
            panic!("expected a's own db");
        };
        assert_eq!(
            a_records(&reply2),
            vec![Ipv4Addr::new(10, 0, 0, 3)],
            "the bare name resolves within the caller's own project only"
        );
    }

    #[test]
    fn unknown_source_ip_is_forward_only_for_internal_names() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // A source that is NOT a co-located container asks for an internal name.
        let q = encode_query(0x5, "db.a.boatramp.internal", TYPE_A, CLASS_IN);
        assert_eq!(
            r.handle_query(Ipv4Addr::new(192, 168, 1, 1), &q),
            Decision::Forward,
            "an unknown source must never be answered an internal name"
        );
    }

    #[test]
    fn external_name_is_forwarded() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // Even from a known container, an external name is forwarded.
        let q = encode_query(0x6, "example.com", TYPE_A, CLASS_IN);
        assert_eq!(
            r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q),
            Decision::Forward
        );
    }

    #[test]
    fn non_a_query_type_is_forwarded() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // An MX (15) query for an internal name is forwarded (we only answer A/AAAA).
        let q = encode_query(0x7, "db.a.boatramp.internal", 15, CLASS_IN);
        assert_eq!(
            r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q),
            Decision::Forward
        );
    }

    #[test]
    fn in_project_name_with_no_healthy_replica_is_nxdomain() {
        let (owners, mut addrs) = fleet();
        // a's "db" workload exists (owner map) but currently has no healthy replica.
        addrs.remove(&("a".to_string(), "db".to_string()));
        let r = resolver(owners, addrs);
        let q = encode_query(0x8, "db", TYPE_A, CLASS_IN);
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("expected NXDOMAIN, not forward");
        };
        assert_eq!(rcode_of(&reply), rcode::NXDOMAIN);
    }

    #[test]
    fn unknown_in_project_workload_is_nxdomain() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // a's container asks for a workload name that doesn't exist in a.
        let q = encode_query(0x9, "nope", TYPE_A, CLASS_IN);
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("expected NXDOMAIN");
        };
        assert_eq!(rcode_of(&reply), rcode::NXDOMAIN);
    }

    #[test]
    fn aaaa_query_answers_only_v6() {
        let owners = {
            let mut m = BTreeMap::new();
            m.insert(
                Ipv4Addr::new(10, 0, 0, 2),
                ("a".to_string(), "web".to_string()),
            );
            m
        };
        // A workload with only a v4 address: an AAAA query resolves to zero records
        // (NXDOMAIN-style empty), NOT the v4 address in an AAAA answer.
        let r = Resolver::new(
            DEFAULT_INTERNAL_DOMAIN,
            move |ip| owners.get(&ip).cloned(),
            |_p, _w| ResolvedAddrs {
                v4: vec![Ipv4Addr::new(10, 0, 0, 9)],
                v6: Vec::new(),
            },
        );
        let q = encode_query(0xA, "web", TYPE_AAAA, CLASS_IN);
        // v4-only workload, AAAA asked: not empty overall, so we answer NOERROR with 0
        // AAAA records (the correct "name exists, no AAAA" response).
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("expected a reply");
        };
        assert_eq!(rcode_of(&reply), rcode::NOERROR);
        assert_eq!(
            ancount_of(&reply),
            0,
            "no AAAA records for a v4-only workload"
        );
    }

    #[test]
    fn malformed_query_is_formerr_not_forwarded() {
        let (owners, addrs) = fleet();
        let r = resolver(owners, addrs);
        // Too short to be a valid header.
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &[0x00, 0x01])
        else {
            panic!("a malformed query must not be forwarded upstream");
        };
        assert_eq!(rcode_of(&reply), rcode::FORMERR);
    }

    #[test]
    fn custom_domain_is_honored() {
        let owners = {
            let mut m = BTreeMap::new();
            m.insert(
                Ipv4Addr::new(10, 0, 0, 2),
                ("a".to_string(), "web".to_string()),
            );
            m
        };
        let addrs = {
            let mut m = BTreeMap::new();
            m.insert(
                ("a".to_string(), "db".to_string()),
                vec![Ipv4Addr::new(10, 0, 0, 3)],
            );
            m
        };
        let r = Resolver::new(
            "svc.internal",
            move |ip| owners.get(&ip).cloned(),
            move |p, w| ResolvedAddrs {
                v4: addrs
                    .get(&(p.to_string(), w.to_string()))
                    .cloned()
                    .unwrap_or_default(),
                v6: Vec::new(),
            },
        );
        // The FQDN under the configured domain resolves…
        let q = encode_query(0xB, "db.a.svc.internal", TYPE_A, CLASS_IN);
        let Decision::Reply(reply) = r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q) else {
            panic!("expected an answer under the custom domain");
        };
        assert_eq!(a_records(&reply), vec![Ipv4Addr::new(10, 0, 0, 3)]);
        // …while the default domain is now just an external name (forwarded).
        let q2 = encode_query(0xC, "db.a.boatramp.internal", TYPE_A, CLASS_IN);
        assert_eq!(
            r.handle_query(Ipv4Addr::new(10, 0, 0, 2), &q2),
            Decision::Forward,
        );
    }
}
