//! HTTP/1.1 connection **upgrade** (RFC 9110 §7.8) — the mechanism behind WebSocket and
//! any `Connection: upgrade` protocol switch. It replaces hyper's `hyper::upgrade`, so
//! the serving path owns upgrades and does not fall back to hyper.
//!
//! Flow: the [`serve`](crate::h1::serve) loop, for a request that carries upgrade intent,
//! puts a pending handle in the request's extensions. A handler (or a reverse-proxy
//! bridge) calls [`on_upgrade`] to take that handle, returns a `101 Switching Protocols`
//! response, and awaits the returned [`OnUpgrade`]; once the loop has written the `101` it
//! reunites the connection and hands the raw byte stream — with any bytes the peer already
//! sent past the handshake replayed — to the awaiting consumer via [`Upgraded`].

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, header};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// Whether a request head carries HTTP upgrade intent: a `Connection` header listing the
/// `upgrade` token **and** an `Upgrade` header naming the target protocol.
pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    connection_upgrade && headers.contains_key(header::UPGRADE)
}

/// The raw connection handed to an upgrade consumer after the `101`, replaying any bytes
/// the peer already sent past the handshake before yielding the live socket. Both a
/// bidirectional byte stream ([`AsyncRead`] + [`AsyncWrite`]).
pub struct Upgraded {
    inner: Pin<Box<dyn Io>>,
    prefix: Bytes,
    pos: usize,
}

/// Object-safe bound for the upgraded IO.
trait Io: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> Io for T {}

impl Upgraded {
    pub(crate) fn new(io: impl AsyncRead + AsyncWrite + Send + 'static, prefix: Bytes) -> Self {
        Self {
            inner: Box::pin(io),
            prefix,
            pos: 0,
        }
    }
}

impl AsyncRead for Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        self.inner.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.as_mut().poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}

/// A future that resolves to the [`Upgraded`] connection once the server has written the
/// `101` and handed off the socket. Resolves to `Err` if the upgrade never completed (the
/// handler returned a non-`101` response, or the connection dropped first).
pub struct OnUpgrade(pub(crate) oneshot::Receiver<Upgraded>);

/// The upgrade never completed (no `101`, or the connection closed first).
#[derive(Debug, Clone, Copy)]
pub struct UpgradeError;

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection was not upgraded")
    }
}
impl std::error::Error for UpgradeError {}

impl std::future::Future for OnUpgrade {
    type Output = Result<Upgraded, UpgradeError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|r| r.map_err(|_| UpgradeError))
    }
}

/// The receiver side, parked in a request's extensions by the serve loop for a request
/// with upgrade intent; [`on_upgrade`] takes it out. `http::Extensions` requires `Clone`,
/// and a `oneshot::Receiver` is single-owner, so it is held behind a shared cell (mirrors
/// hyper's own clone-able upgrade handle).
#[derive(Clone)]
pub(crate) struct Pending(
    pub(crate) std::sync::Arc<std::sync::Mutex<Option<oneshot::Receiver<Upgraded>>>>,
);

impl Pending {
    pub(crate) fn new(rx: oneshot::Receiver<Upgraded>) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Some(rx))))
    }
}

/// Register interest in taking over this request's connection after a `101`. Returns the
/// future to await (once a `101` response is returned) for the raw [`Upgraded`] stream, or
/// `None` if the request had no upgrade intent (nothing to take over — or it was already
/// taken). Mirrors `hyper::upgrade::on`.
pub fn on_upgrade<B>(req: &mut http::Request<B>) -> Option<OnUpgrade> {
    req.extensions()
        .get::<Pending>()
        .and_then(|p| p.0.lock().unwrap().take())
        .map(OnUpgrade)
}

/// The WebSocket GUID appended to the client key before hashing (RFC 6455 §1.3).
const WS_MAGIC_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the `Sec-WebSocket-Accept` response-header value for a client's
/// `Sec-WebSocket-Key` during a WebSocket opening handshake (RFC 6455 §4.2.2 step 5.4):
/// `base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
///
/// `key` is the trimmed value of the request's `Sec-WebSocket-Key` header (its syntactic
/// validity is the handler's concern — this only derives the accept token). A handler that
/// returns a `101` for a WebSocket upgrade sets this on the response so the client can
/// confirm the handshake instead of hand-rolling the SHA-1 + base64 itself.
///
/// ```
/// // The canonical example from RFC 6455 §1.3.
/// let accept = boatramp_http::upgrade::sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ==");
/// assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
/// ```
pub fn sec_websocket_accept(key: &str) -> String {
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(WS_MAGIC_GUID);
    base64_encode(&sha1(&input))
}

/// SHA-1 (FIPS 180-4) of `data`. First-party so this crate stays dependency-free (it
/// hand-rolls HPACK's Huffman table for the same reason); the WS handshake hashes ~60
/// bytes once, so performance is immaterial.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];

    // Pad: append 0x80, then zeros, then the 64-bit big-endian bit length, to a multiple
    // of 64 bytes.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Standard base64 (RFC 4648) with `+/` and `=` padding — the alphabet
/// `Sec-WebSocket-Accept` requires.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vectors() {
        // FIPS 180-4 / RFC 3174 sample vectors.
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
        assert_eq!(
            sha1(b""),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ]
        );
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn sec_websocket_accept_rfc6455_example() {
        // RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
        assert_eq!(
            sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
