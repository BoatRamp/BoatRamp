//! The SOCKS5 front-end (plan §2) — ships first (R1), unprivileged, loopback-bound. See
//! [`SocksServer`] for the entry point; `codec.rs` is the hand-rolled wire format, `auth.rs` is the
//! local RFC-1929 credential, `http_connect.rs` is the optional HTTP `CONNECT` sibling front-end.

mod auth;
mod codec;
mod http_connect;
mod server;

pub use auth::{LocalAuth, LocalAuthError};
pub use server::{SocksError, SocksServer};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{MockControlPlane, entry_at};
    use crate::core::{ControlPlane, Tunnel};
    use boatramp_overlay_client::OverlaySecret;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn start_server(
        directory: Vec<crate::core::ServiceInfo>,
        auth: Option<LocalAuth>,
    ) -> (SocketAddr, Arc<MockControlPlane>) {
        let cp = Arc::new(MockControlPlane::new(directory));
        let holder = OverlaySecret::generate().unwrap();
        let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
            .await
            .unwrap();
        let server = SocksServer::bind(tunnel, auth, "127.0.0.1:0".parse().unwrap(), None)
            .await
            .unwrap();
        let addr = server.socks_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        (addr, cp)
    }

    /// Minimal hand-written SOCKS5 client bytes — deliberately NOT built on `codec.rs`, so this
    /// proves real RFC-1928 wire interop rather than just "my encoder/decoder agree with each
    /// other".
    async fn socks_handshake(addr: SocketAddr, creds: Option<(&str, &str)>) -> TcpStream {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let methods: &[u8] = if creds.is_some() {
            &[0x00, 0x02]
        } else {
            &[0x00]
        };
        let mut greeting = vec![0x05, methods.len() as u8];
        greeting.extend_from_slice(methods);
        stream.write_all(&greeting).await.unwrap();
        let mut sel = [0u8; 2];
        stream.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel[0], 0x05);
        if sel[1] == 0x02 {
            let (user, pass) = creds.expect("server selected user/pass but we offered none");
            let mut frame = vec![0x01, user.len() as u8];
            frame.extend_from_slice(user.as_bytes());
            frame.push(pass.len() as u8);
            frame.extend_from_slice(pass.as_bytes());
            stream.write_all(&frame).await.unwrap();
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await.unwrap();
            assert_eq!(
                status,
                [0x01, 0x00],
                "local auth must succeed with the right creds"
            );
        } else {
            assert_eq!(sel[1], 0x00);
        }
        stream
    }

    async fn send_connect_domain(stream: &mut TcpStream, name: &str) -> u8 {
        let mut frame = vec![0x05, 0x01, 0x00, 0x03, name.len() as u8];
        frame.extend_from_slice(name.as_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        stream.write_all(&frame).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        reply[1]
    }

    #[tokio::test]
    async fn an_unknown_service_name_is_refused_with_host_unreachable_and_never_dialed() {
        let (addr, cp) = start_server(vec![], None).await;
        let mut stream = socks_handshake(addr, None).await;
        let rep = send_connect_domain(&mut stream, "ghost").await;
        assert_eq!(
            rep, 0x04,
            "unknown name must get SOCKS reply 0x04 (host unreachable)"
        );
        // The connection must be CLOSED after the refusal, not left open waiting for more requests
        // (never a fall-through to a real connect — there is nothing further to do with it).
        let mut buf = [0u8; 1];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "the server must close the connection after refusing");
        assert_eq!(
            cp.mint_calls.load(Ordering::SeqCst),
            0,
            "an unknown name must never reach a mint"
        );
    }

    #[tokio::test]
    async fn an_ip_literal_is_rejected_before_any_catalog_or_mint_lookup() {
        let (addr, cp) = start_server(
            vec![entry_at("svc/db", "127.0.0.1:1".parse().unwrap(), true)],
            None,
        )
        .await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        stream.read_exact(&mut sel).await.unwrap();
        // CONNECT to an IPv4 literal (127.0.0.1:1, the SAME address as the real catalog entry above
        // — proving the rejection is about the ATYP, not about which address was asked for).
        let mut frame = vec![0x05, 0x01, 0x00, 0x01];
        frame.extend_from_slice(&[127, 0, 0, 1]);
        frame.extend_from_slice(&1u16.to_be_bytes());
        stream.write_all(&frame).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], 0x02,
            "an IP literal must get SOCKS reply 0x02 (not allowed by ruleset)"
        );
        assert_eq!(
            cp.list_calls.load(Ordering::SeqCst),
            1,
            "only the server's own startup refresh"
        );
        assert_eq!(
            cp.mint_calls.load(Ordering::SeqCst),
            0,
            "an IP literal must never reach a mint"
        );
    }

    #[tokio::test]
    async fn bind_and_udp_associate_are_refused_as_command_not_supported() {
        let (addr, _cp) = start_server(vec![], None).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut sel = [0u8; 2];
        stream.read_exact(&mut sel).await.unwrap();
        // BIND (cmd=0x02) to a domain name.
        let mut frame = vec![0x05, 0x02, 0x00, 0x03, 2];
        frame.extend_from_slice(b"db");
        frame.extend_from_slice(&0u16.to_be_bytes());
        stream.write_all(&frame).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], 0x07,
            "BIND must get SOCKS reply 0x07 (command not supported)"
        );
    }

    #[tokio::test]
    async fn local_auth_rejects_the_wrong_credentials_and_closes() {
        let auth = LocalAuth {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let (addr, _cp) = start_server(vec![], Some(auth)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        stream.read_exact(&mut sel).await.unwrap();
        assert_eq!(
            sel[1], 0x02,
            "the server must insist on user/pass when local auth is configured"
        );
        let mut frame = vec![0x01, 1];
        frame.push(b'u');
        frame.push(1);
        frame.push(b'x');
        stream.write_all(&frame).await.unwrap();
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [0x01, 0x01], "wrong password must be rejected");
        let mut buf = [0u8; 1];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "the connection must close after a failed local auth");
    }

    #[tokio::test]
    async fn local_auth_accepts_the_right_credentials_then_still_refuses_an_unknown_name() {
        let auth = LocalAuth {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let (addr, _cp) = start_server(vec![], Some(auth)).await;
        let mut stream = socks_handshake(addr, Some(("u", "p"))).await;
        let rep = send_connect_domain(&mut stream, "ghost").await;
        assert_eq!(rep, 0x04);
    }

    #[tokio::test]
    async fn no_local_auth_mode_accepts_a_plain_no_auth_client() {
        let (addr, _cp) = start_server(vec![], None).await;
        let mut stream = socks_handshake(addr, None).await;
        let rep = send_connect_domain(&mut stream, "ghost").await;
        assert_eq!(rep, 0x04);
    }
}
