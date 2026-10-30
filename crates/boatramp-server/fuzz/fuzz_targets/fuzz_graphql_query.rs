#![no_main]
//! Fuzz the GraphQL query parser boatramp hands client query text to: `graphql_plan.rs`,
//! `graphql_data/compile.rs` and `graphql_gateway.rs` all call `async_graphql_parser::parse_query`
//! directly on the client-supplied query string. boatramp has no hand-rolled GraphQL grammar of
//! its own, so this fuzzes the exact third-party entry point it calls, as a `&str` (the same
//! shape it arrives in after JSON/body decode — this harness does not re-fuzz that decode step).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(query) = std::str::from_utf8(data) {
        let _ = async_graphql_parser::parse_query(query);
    }
});
