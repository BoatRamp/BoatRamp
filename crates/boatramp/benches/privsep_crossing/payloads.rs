//! The REAL serving-shape fixtures every substrate measures against: a representative parsed
//! `RequestHead` (the bytes that ride with an fd-pass splice / open a byte-relay exchange) and
//! the response-body sizes the task spec calls out — ~1 KiB (API JSON), ~64 KiB (typical page),
//! ~512 KiB and ~2 MiB (image-serve). No substrate gets a trivial 1-byte stand-in.

/// A representative parsed HTTP/1.1 request head (method + path + a realistic header set) — the
/// same shape `privsep_link::send_client_conn`'s `head` argument carries in production. ~300
/// bytes, which is a typical real head size (well under `MAX_HEAD_LEN`).
pub fn representative_head() -> Vec<u8> {
    concat!(
        "GET /sites/acme-corp/blog/2026/11/privsep-fabric-composition/index.html HTTP/1.1\r\n",
        "Host: acme-corp.boatramp.dev\r\n",
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15\r\n",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
        "Accept-Language: en-US,en;q=0.9\r\n",
        "Accept-Encoding: gzip, br\r\n",
        "Connection: keep-alive\r\n",
        "Cookie: session=4f3a9c2e-91b7-4e0a-8c3d-2b7f1a6e5d4c; theme=dark\r\n",
        "\r\n",
    )
    .as_bytes()
    .to_vec()
}

/// One benchmark payload size: a served response-body volume + its human label.
#[derive(Clone, Copy, Debug)]
pub struct PayloadSize {
    pub label: &'static str,
    pub bytes: usize,
}

pub const PAYLOAD_SIZES: &[PayloadSize] = &[
    PayloadSize {
        label: "1KiB",
        bytes: 1024,
    },
    PayloadSize {
        label: "64KiB",
        bytes: 64 * 1024,
    },
    PayloadSize {
        label: "512KiB",
        bytes: 512 * 1024,
    },
    PayloadSize {
        label: "2MiB",
        bytes: 2 * 1024 * 1024,
    },
];

pub fn find_payload(label: &str) -> Option<PayloadSize> {
    PAYLOAD_SIZES
        .iter()
        .copied()
        .find(|p| p.label.eq_ignore_ascii_case(label))
}
