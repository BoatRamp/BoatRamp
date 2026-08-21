//! Combinatorial generators — the cases a hand-written list would miss. Each returns
//! owned `(name, input, expected verdict)` triples, consumed by the gate (assert the
//! expected verdict) and the differential driver (cross-check against hyper).

use super::{Expect, Framing};

/// A generated case with its expected verdict.
pub struct GenCase {
    pub name: String,
    pub input: Vec<u8>,
    pub expect: Expect,
}

fn req(headers: &str) -> Vec<u8> {
    format!("POST / HTTP/1.1\r\nHost: x\r\n{headers}\r\n").into_bytes()
}

/// The full Content-Length × Transfer-Encoding grid (RFC 9112 §6.3) — the smuggling core.
/// Every combination of a CL variant and a TE variant, with the required verdict.
pub fn framing_matrix() -> Vec<GenCase> {
    // (label, header-lines, is-valid-single-value, resolved length/marker)
    // CL variants: (label, lines, verdict-if-alone)
    let cls: &[(&str, &str, Expect)] = &[
        ("no-CL", "", Expect::Accept(Framing::Empty)),
        ("CL=6", "Content-Length: 6\r\n", Expect::Accept(Framing::Length(6))),
        ("CL-dup-same", "Content-Length: 6\r\nContent-Length: 6\r\n", Expect::Reject),
        ("CL-dup-diff", "Content-Length: 6\r\nContent-Length: 7\r\n", Expect::Reject),
        ("CL-bad", "Content-Length: six\r\n", Expect::Reject),
    ];
    // TE variants: (label, lines, verdict-if-alone)
    let tes: &[(&str, &str, Expect)] = &[
        ("no-TE", "", Expect::Accept(Framing::Empty)),
        ("TE-chunked", "Transfer-Encoding: chunked\r\n", Expect::Accept(Framing::Chunked)),
        ("TE-gzip", "Transfer-Encoding: gzip\r\n", Expect::Reject),
        ("TE-chunked-not-final", "Transfer-Encoding: chunked, gzip\r\n", Expect::Reject),
        ("TE-dup", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", Expect::Reject),
    ];

    let mut out = Vec::new();
    for (cl_name, cl_lines, cl_alone) in cls {
        for (te_name, te_lines, te_alone) in tes {
            let cl_present = !cl_lines.is_empty();
            let te_present = !te_lines.is_empty();
            let expect = match (cl_present, te_present) {
                // Both framing headers present is always a desync risk → reject.
                (true, true) => Expect::Reject,
                (true, false) => *cl_alone,
                (false, true) => *te_alone,
                (false, false) => Expect::Accept(Framing::Empty),
            };
            out.push(GenCase {
                name: format!("matrix[{cl_name} × {te_name}]"),
                input: req(&format!("{cl_lines}{te_lines}")),
                expect,
            });
        }
    }
    out
}

/// Request-line whitespace permutations — exactly one SP between the three tokens is
/// required; anything else is malformed (RFC 9112 §3).
pub fn whitespace() -> Vec<GenCase> {
    let seps: &[(&str, &str, bool)] = &[
        ("SP", " ", true),
        ("2SP", "  ", false),
        ("3SP", "   ", false),
        ("TAB", "\t", false),
        ("SP+TAB", " \t", false),
        ("VT", "\x0b", false),
        ("FF", "\x0c", false),
    ];
    let mut out = Vec::new();
    for (name, sep, ok) in seps {
        let line = format!("GET{sep}/{sep}HTTP/1.1");
        out.push(GenCase {
            name: format!("req-line-sep[{name}]"),
            input: format!("{line}\r\nHost: x\r\n\r\n").into_bytes(),
            expect: if *ok { Expect::Accept(Framing::Empty) } else { Expect::Reject },
        });
    }
    out
}

/// HTTP-version tokens — only `HTTP/1.0` and `HTTP/1.1` are accepted on this path.
pub fn versions() -> Vec<GenCase> {
    let vs: &[(&str, bool)] = &[
        ("HTTP/1.1", true),
        ("HTTP/1.0", true),
        ("HTTP/2.0", false),
        ("HTTP/0.9", false),
        ("HTTP/1", false),
        ("HTTP/11", false),
        ("HTTP/1.", false),
        ("HTTP/.1", false),
        ("HTTP/1.1.1", false),
        ("http/1.1", false),
        ("HTTP/01.1", false),
        ("HTTP/1.10", false),
        ("HTTP/1.1 ", false),
        ("HTTPS/1.1", false),
    ];
    let mut out = Vec::new();
    for (v, ok) in vs {
        out.push(GenCase {
            name: format!("version[{v}]"),
            input: format!("GET / {v}\r\nHost: x\r\n\r\n").into_bytes(),
            expect: if *ok { Expect::Accept(Framing::Empty) } else { Expect::Reject },
        });
    }
    out
}

/// Header name/value byte-class sweep — a `tchar` name and a VCHAR/OWS value are fine;
/// a delimiter/control in the name, or a control in the value, must be rejected.
pub fn header_bytes() -> Vec<GenCase> {
    fn is_tchar(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    }
    let mut out = Vec::new();
    // Every non-tchar visible/space byte injected into a header NAME must be rejected.
    for b in 0x21u8..=0x7e {
        if is_tchar(b) {
            continue;
        }
        // Skip ':' — it legitimately terminates the name.
        if b == b':' {
            continue;
        }
        let mut input = b"GET / HTTP/1.1\r\nHost: x\r\nX".to_vec();
        input.push(b);
        input.extend_from_slice(b"Y: v\r\n\r\n");
        out.push(GenCase {
            name: format!("name-byte[0x{b:02x}]"),
            input,
            expect: Expect::Reject,
        });
    }
    // Control bytes (except HTAB) in a header VALUE must be rejected.
    for b in (0x00u8..=0x1f).chain(std::iter::once(0x7f)) {
        if b == b'\t' || b == b'\r' || b == b'\n' {
            continue; // HTAB is legal OWS; CR/LF are line structure (tested elsewhere)
        }
        let mut input = b"GET / HTTP/1.1\r\nHost: x\r\nX: a".to_vec();
        input.push(b);
        input.extend_from_slice(b"b\r\n\r\n");
        out.push(GenCase {
            name: format!("value-ctl[0x{b:02x}]"),
            input,
            expect: Expect::Reject,
        });
    }
    out
}

/// All generated cases across every generator.
pub fn all() -> Vec<GenCase> {
    let mut v = framing_matrix();
    v.extend(whitespace());
    v.extend(versions());
    v.extend(header_bytes());
    v
}
