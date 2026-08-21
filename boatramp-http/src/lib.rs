//! BoatRamp's owned HTTP serving stack.
//!
//! One accept loop over hand-rolled HTTP/1.1 and HTTP/2 codecs, with the kernel
//! `splice()`/kTLS reverse-proxy body fast-paths hyper structurally can't do. The
//! protocols live as sibling modules over shared serving types:
//!
//! - [`h1`] — the HTTP/1.1 codec (built here, **test-first**: see its module docs and
//!   the `tests/` harness).
//! - `h2` — the concurrent multiplexed HTTP/2 driver (the current `boatramp-h2` crate,
//!   folded in as Stage 1 of `../boatramp-h2/DESIGN-serving.md`).
//! - `serve` — the unified accept-loop dispatcher (TLS ALPN / plaintext h2c-preface
//!   sniff → h1 vs h2), replacing the `boatramp-server` mux-serve bridge + `splice.rs`.
//!
//! Shared request/response/body/limit types will live at the crate root once the h2
//! codec is folded in; for now only the h1 codec + its safety gate are present.

pub mod h1;

// The verification kit (corpus + normalized-verdict model + combinatorial generators)
// shared by the h1 gate, the differential-vs-hyper driver, and the fuzz targets — one
// canonical, per-aspect-grouped source so coverage is auditable and reused across all
// three layers. Data-only + dev-oriented; it ships in this (publish=false) spike crate.
pub mod testkit;
