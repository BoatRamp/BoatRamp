//! The optional small HTTP `CONNECT` front-end (plan §2, behind `--http-connect`): reuses exactly
//! the SOCKS dispatch's invariants (loopback bind, hostname-only, unknown-name refused, never a real
//! outbound connect) over plain HTTP/1.1 `CONNECT host:port` instead of the SOCKS5 wire format — for
//! clients that speak `HTTPS_PROXY`/`http.proxy` rather than a SOCKS proxy.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::core::Tunnel;

use super::server::{SocksError, accept_loop, is_not_found, splice};

/// A failure parsing or answering an HTTP `CONNECT` request. Never surfaced to the peer beyond the
/// HTTP status line this module itself writes — logged by the caller.
#[derive(Debug, thiserror::Error)]
enum HttpConnectError {
    #[error("http-connect io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed CONNECT request line")]
    Malformed,
}

/// Run the HTTP CONNECT accept loop forever, dispatching each connection through `tunnel.open`.
pub(super) async fn accept_loop_over(
    listener: TcpListener,
    tunnel: Arc<Tunnel>,
) -> Result<(), SocksError> {
    accept_loop(listener, move |stream| {
        let tunnel = Arc::clone(&tunnel);
        async move {
            if let Err(err) = handle(&tunnel, stream).await {
                tracing::debug!(
                    error = %err,
                    "boatramp tunnel: http-connect connection ended with an error"
                );
            }
        }
    })
    .await
}

/// Read the request line + drain headers up to the blank line, returning `(method, target)` where
/// `target` is the `host:port` authority `CONNECT` carries (RFC 7231 §4.3.6).
async fn read_connect_request(
    stream: &mut BufReader<TcpStream>,
) -> Result<(String, String), HttpConnectError> {
    let mut first_line = String::new();
    let n = stream.read_line(&mut first_line).await?;
    if n == 0 {
        return Err(HttpConnectError::Malformed);
    }
    let mut parts = first_line.trim_end().split_ascii_whitespace();
    let method = parts.next().ok_or(HttpConnectError::Malformed)?.to_string();
    let target = parts.next().ok_or(HttpConnectError::Malformed)?.to_string();
    // Drain the remaining request headers up to the blank line; their content is irrelevant to a
    // transparent CONNECT tunnel.
    loop {
        let mut line = String::new();
        let n = stream.read_line(&mut line).await?;
        if n == 0 || line.trim_end().is_empty() {
            break;
        }
    }
    Ok((method, target))
}

async fn write_status(
    stream: &mut BufReader<TcpStream>,
    code: u16,
    reason: &str,
) -> Result<(), HttpConnectError> {
    let resp = format!("HTTP/1.1 {code} {reason}\r\n\r\n");
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Split an HTTP `CONNECT` authority (`host:port`) into its host part. `CONNECT`'s target always
/// carries an explicit port, so a plain `rsplit_once(':')` is correct here (unlike a bare hostname,
/// which might not have one).
fn host_of(authority: &str) -> &str {
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

async fn handle(tunnel: &Tunnel, stream: TcpStream) -> Result<(), HttpConnectError> {
    let mut stream = BufReader::new(stream);
    let (method, target) = read_connect_request(&mut stream).await?;
    if method != "CONNECT" {
        write_status(&mut stream, 501, "Not Implemented").await?;
        return Ok(());
    }
    let host = host_of(&target);
    if host.parse::<std::net::IpAddr>().is_ok() {
        tracing::warn!(
            "boatramp tunnel: refusing an HTTP CONNECT to an IP-literal destination — use a \
             hostname, this proxy resolves names to services, not addresses"
        );
        write_status(&mut stream, 403, "Forbidden — use a hostname").await?;
        return Ok(());
    }

    match tunnel.open(host).await {
        Ok(flow) => {
            write_status(&mut stream, 200, "Connection Established").await?;
            // Hand the whole `BufReader` (not `.into_inner()`) to the splice — it still implements
            // AsyncRead/AsyncWrite, and unwrapping first would silently drop any bytes the client
            // already pipelined into its internal read buffer.
            splice(stream, flow).await;
            Ok(())
        }
        Err(err) => {
            let (code, reason) = if is_not_found(&err) {
                (404, "Not Found")
            } else {
                (502, "Bad Gateway")
            };
            tracing::warn!(
                host = %host, error = %err,
                "boatramp tunnel: overlay dial failed; refusing the HTTP CONNECT"
            );
            write_status(&mut stream, code, reason).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_the_connect_port() {
        assert_eq!(host_of("db.svc:443"), "db.svc");
    }

    #[test]
    fn host_of_handles_a_bare_host_with_no_colon() {
        assert_eq!(host_of("db.svc"), "db.svc");
    }
}
