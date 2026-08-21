//! Native HTTP/1.1 upgrade (WebSocket / `Connection: upgrade`) — the mechanism that lets
//! the serving path own upgrades instead of falling back to hyper. A handler that accepts
//! the upgrade returns `101` and takes over the raw connection via `on_upgrade`; the loop
//! hands it the reunited socket (with any bytes sent past the handshake replayed).

use boatramp_http::{
    is_upgrade_request, on_upgrade, response, serve_connection, Handler, Request, Response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A handler that upgrades `Connection: upgrade` requests and echoes bytes over the
/// upgraded connection; everything else gets a plain 200.
struct EchoUpgrade;
impl Handler for EchoUpgrade {
    async fn handle(&self, mut req: Request) -> Response {
        if !is_upgrade_request(req.headers()) {
            return response(200, b"not-upgraded".to_vec());
        }
        // Take the upgrade handle, then spawn the post-upgrade echo loop.
        let on_up = on_upgrade(&mut req);
        tokio::spawn(async move {
            let Some(on_up) = on_up else { return };
            let Ok(mut up) = on_up.await else { return };
            let mut buf = [0u8; 1024];
            loop {
                match up.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if up.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        // Accept the upgrade: 101 + the switch headers.
        let mut resp = response(101, Vec::new());
        resp.headers_mut()
            .insert("upgrade", "echo".parse().unwrap());
        resp.headers_mut()
            .insert("connection", "upgrade".parse().unwrap());
        resp
    }
}

fn spawn() -> tokio::io::DuplexStream {
    let (client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let _ = serve_connection(server, EchoUpgrade).await;
    });
    client
}

/// Read up to (and including) the response head terminator; return `(head, leftover)`.
async fn read_head(c: &mut tokio::io::DuplexStream) -> (Vec<u8>, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = buf[..p + 4].to_vec();
            let rest = buf[p + 4..].to_vec();
            return (head, rest);
        }
        let n = c.read(&mut tmp).await.unwrap();
        assert!(n > 0, "connection closed before the response head");
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[tokio::test]
async fn upgrade_switches_protocols_and_bytes_flow_both_ways() {
    let mut c = spawn();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\n")
        .await
        .unwrap();
    let (head, leftover) = read_head(&mut c).await;
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{text}"
    );
    assert!(
        text.to_ascii_lowercase().contains("upgrade: echo\r\n"),
        "{text}"
    );
    assert!(leftover.is_empty(), "no upgraded bytes were sent yet");

    // Post-upgrade: the connection is now the echo protocol. Bytes round-trip both ways.
    c.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    c.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");

    c.write_all(b"second").await.unwrap();
    let mut got2 = [0u8; 6];
    c.read_exact(&mut got2).await.unwrap();
    assert_eq!(&got2, b"second");
}

#[tokio::test]
async fn bytes_sent_immediately_after_the_handshake_are_replayed() {
    // The client pipelines upgraded data right after the handshake CRLFCRLF — those bytes
    // land in the serve loop's buffer and must be replayed to the upgrade consumer.
    let mut c = spawn();
    c.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: echo\r\n\r\nEARLYDATA",
    )
    .await
    .unwrap();
    let (head, leftover) = read_head(&mut c).await;
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));

    // The echoed "EARLYDATA" must come back even though it arrived with the handshake.
    let mut got = Vec::new();
    got.extend_from_slice(&leftover);
    while got.len() < 9 {
        let mut tmp = [0u8; 32];
        let n = c.read(&mut tmp).await.unwrap();
        assert!(n > 0, "upgraded bytes were not replayed");
        got.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(&got[..9], b"EARLYDATA");
}

#[tokio::test]
async fn non_upgrade_request_is_served_normally() {
    let mut c = spawn();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("not-upgraded"), "{text}");
}
