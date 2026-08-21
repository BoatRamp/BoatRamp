//! The verification kit: the canonical corpus + the normalized-verdict model + the
//! combinatorial generators, shared by the h1 gate (`tests/gate.rs`), the
//! differential-vs-hyper driver (`tests/differential.rs`), and the fuzz targets.
//!
//! Keeping one canonical, per-aspect-grouped corpus (rather than scattered ad-hoc tests)
//! is what makes coverage **auditable**: [`cases`] is the completeness checklist, and
//! [`gen`] fills the combinatorial gaps a hand-written list would miss.

use crate::h1::{self, BodyFraming, ParseResult};

pub mod cases;
pub mod gen;

/// A normalized parse verdict — comparable across parsers (boatramp vs hyper) and against
/// a hand-written expectation. Only the smuggling-relevant shape is captured: the method,
/// target path, and — crucially — the **body framing**, which fixes the message boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Parsed a request head with this normalized shape.
    Accept {
        method: String,
        path: String,
        framing: Framing,
    },
    /// More bytes are needed (a partial head) — NOT a rejection.
    Incomplete,
    /// Rejected (malformed / ambiguous). The specific reason is intentionally *not*
    /// compared across parsers (hyper's reasons differ) — only that both refuse.
    Reject,
}

/// Body framing, mirrored from [`BodyFraming`] but `Copy` for corpus tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Empty,
    Length(u64),
    Chunked,
}

impl From<&BodyFraming> for Framing {
    fn from(f: &BodyFraming) -> Self {
        match f {
            BodyFraming::Empty => Framing::Empty,
            BodyFraming::Length(n) => Framing::Length(*n),
            BodyFraming::Chunked => Framing::Chunked,
        }
    }
}

/// boatramp-http's normalized verdict for a single request head.
pub fn verdict(buf: &[u8]) -> Verdict {
    match h1::parse_request_head(buf) {
        ParseResult::Complete { head, .. } => Verdict::Accept {
            method: head.method.to_string(),
            path: head.uri.path().to_string(),
            framing: (&head.framing).into(),
        },
        ParseResult::Incomplete => Verdict::Incomplete,
        ParseResult::Reject(_) => Verdict::Reject,
    }
}

/// The protocol aspect a case exercises — the axis coverage is organized + audited along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aspect {
    RequestLine,
    HeaderSyntax,
    ContentLength,
    TransferEncoding,
    FramingMatrix,
    ChunkedCoding,
    Host,
    Connection,
    Pipelining,
    Limits,
    ResponseFraming,
}

/// The expected verdict for a curated case. `Accept` carries only the framing (the
/// method/path are evident from the input); most cases turn on framing or rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Accept(Framing),
    Incomplete,
    Reject,
}

/// A curated case: an input + the verdict boatramp-http must produce, tagged with the
/// protocol aspect it belongs to.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    pub aspect: Aspect,
    pub name: &'static str,
    pub input: &'static [u8],
    pub expect: Expect,
}

/// Whether a verdict satisfies a curated expectation.
pub fn satisfies(v: &Verdict, e: Expect) -> bool {
    matches!(
        (v, e),
        (Verdict::Reject, Expect::Reject)
            | (Verdict::Incomplete, Expect::Incomplete)
    ) || matches!((v, e), (Verdict::Accept { framing, .. }, Expect::Accept(f)) if *framing == f)
}

/// Every curated case across every aspect — the full checklist, for the differential
/// driver and coverage audits.
pub fn all() -> Vec<Case> {
    cases::ALL.iter().flat_map(|s| s.iter().copied()).collect()
}
