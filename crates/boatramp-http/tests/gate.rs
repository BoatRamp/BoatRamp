//! The h1 gate — layers 1 (curated per-aspect) + 2 (combinatorial generators): assert
//! boatramp-http's verdict on every case in the corpus. One test function per aspect, so
//! a failure names exactly which part of the protocol regressed. RED until the parser
//! lands (that's the TDD point); the corpus itself lives in `src/testkit/`.

use boatramp_http::testkit::{Case, cases, generators, satisfies, verdict};

fn check(label: &str, cases: &[Case]) {
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|c| {
            let got = verdict(c.input);
            (!satisfies(&got, c.expect)).then(|| {
                format!(
                    "  {:<40} input={:?}\n      expect={:?}  got={:?}",
                    c.name,
                    String::from_utf8_lossy(c.input),
                    c.expect,
                    got
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{label}: {}/{} case(s) failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

fn check_gen(label: &str, cases: Vec<generators::GenCase>) {
    let total = cases.len();
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|c| {
            let got = verdict(&c.input);
            (!satisfies(&got, c.expect)).then(|| {
                format!(
                    "  {:<28} input={:?}\n      expect={:?}  got={:?}",
                    c.name,
                    String::from_utf8_lossy(&c.input),
                    c.expect,
                    got
                )
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{label} (generated): {}/{total} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// --- layer 1: curated per-aspect --------------------------------------------
#[test]
fn request_line() {
    check("request_line", cases::REQUEST_LINE);
}
#[test]
fn header_syntax() {
    check("header_syntax", cases::HEADER_SYNTAX);
}
#[test]
fn content_length() {
    check("content_length", cases::CONTENT_LENGTH);
}
#[test]
fn transfer_encoding() {
    check("transfer_encoding", cases::TRANSFER_ENCODING);
}
#[test]
fn framing_matrix_curated() {
    check("framing_matrix", cases::FRAMING_MATRIX);
}
#[test]
fn host() {
    check("host", cases::HOST);
}
#[test]
fn connection() {
    check("connection", cases::CONNECTION);
}
#[test]
fn limits() {
    check("limits", cases::LIMITS);
}

// --- layer 2: combinatorial generators --------------------------------------
#[test]
fn generated_framing_matrix() {
    check_gen("framing_matrix", generators::framing_matrix());
}
#[test]
fn generated_whitespace() {
    check_gen("whitespace", generators::whitespace());
}
#[test]
fn generated_versions() {
    check_gen("versions", generators::versions());
}
#[test]
fn generated_header_bytes() {
    check_gen("header_bytes", generators::header_bytes());
}
