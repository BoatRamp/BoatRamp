//! The HTTP/1.1 codec: the smuggling-gated request [`parse`]r + the connection
//! [`serve`] loop that drives a [`Handler`](crate::Handler) over it (keep-alive,
//! pipelining, request-body decode, response framing, timeouts).

pub mod client;
mod parse;
pub mod serve;

// The parser's public surface is re-exported at the `h1` level (the tests + the serve
// loop + the fuzz targets consume `h1::parse_request_head`, `h1::chunked`, etc.).
pub use parse::{
    BodyFraming, ParseResult, Reject, RequestHead, ResponseFraming, chunked, encode_response_head,
    parse_request_head, response_framing,
};

// The client codec (reverse-proxy upstream leg) — the mirror of the request parser +
// serve loop above.
pub use client::{
    BodyReader, Conn, RespParse, ResponseHead, encode_request_head, parse_response_head,
};

pub use serve::{DEFAULT_READ_TIMEOUT, serve_connection, serve_connection_with};
