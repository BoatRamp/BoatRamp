//! A hand-rolled, minimal SOCKS5 wire codec (RFC 1928 + the RFC 1929 username/password
//! sub-negotiation). Deliberately NOT an off-the-shelf SOCKS server crate (plan §2): a stock SOCKS
//! server opens the outbound socket itself, and none cleanly let us intercept `CONNECT` and dispatch
//! to the overlay core instead — hand-rolling keeps the path dependency-free (so the lean SOCKS
//! build stays ring-free) and the parse surface small and easy to reason about end to end.
//!
//! Every function here is pure I/O framing — no overlay/catalog/cap logic. [`super::server`] is the
//! only caller, and it is the only place `CONNECT`'s destination name is turned into a dial.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SOCKS protocol version byte (both the greeting and the request/reply share it).
const VER_SOCKS5: u8 = 0x05;
/// RFC 1929 username/password sub-negotiation version byte.
const VER_USERPASS: u8 = 0x01;

/// A SOCKS5 auth method, as advertised in the client greeting / selected by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMethod {
    NoAuth,
    UserPass,
}

impl AuthMethod {
    const NO_AUTH_BYTE: u8 = 0x00;
    const USERPASS_BYTE: u8 = 0x02;
    /// "No acceptable methods" — the server's reply when nothing offered is acceptable.
    const NO_ACCEPTABLE_BYTE: u8 = 0xFF;

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            Self::NO_AUTH_BYTE => Some(Self::NoAuth),
            Self::USERPASS_BYTE => Some(Self::UserPass),
            _ => None,
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            Self::NoAuth => Self::NO_AUTH_BYTE,
            Self::UserPass => Self::USERPASS_BYTE,
        }
    }
}

/// The SOCKS5 request command (RFC 1928 §4). Only `Connect` is served (plan §2); `Bind` and
/// `UdpAssociate` are parsed (so the codec can recognize and REJECT them with the right reply) but
/// never dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Connect,
    Bind,
    UdpAssociate,
    /// Anything else — a malformed/unknown command byte.
    Other(u8),
}

impl Command {
    fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Connect,
            0x02 => Self::Bind,
            0x03 => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }
}

/// The request's destination address spec (RFC 1928 §5, `ATYP`). `Domainname` is the ONLY form this
/// proxy serves — it maps a hostname to a service name. IPv4/IPv6 are parsed (again, only so the
/// server can recognize and refuse them with the dedicated message) and never dialed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AddrSpec {
    Ipv4([u8; 4]),
    Domainname(String),
    Ipv6([u8; 16]),
}

/// A parsed SOCKS5 `CONNECT`-shaped request: command + destination + port. The port is parsed but
/// unused by the dispatcher (a service name carries no port — the egress owns that); it is kept here
/// only so the codec faithfully represents the wire frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub(crate) command: Command,
    pub(crate) addr: AddrSpec,
    pub(crate) port: u16,
}

/// A codec-level failure: bad framing, an unsupported version byte, or I/O. Every variant that is
/// NOT a plain I/O failure represents an input a correct client would never send — a malformed peer,
/// not a transient fault — and the server's response in every case is to refuse/close, never to
/// guess or fall back.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CodecError {
    #[error("socks io: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported SOCKS version byte {0:#x} (only SOCKS5 is served)")]
    UnsupportedVersion(u8),
    #[error("no acceptable auth method offered")]
    NoAcceptableAuthMethod,
    #[error("unsupported auth sub-negotiation version byte {0:#x}")]
    UnsupportedAuthVersion(u8),
    #[error("auth credentials rejected")]
    AuthRejected,
    #[error("unsupported address type byte {0:#x}")]
    UnsupportedAddrType(u8),
    #[error("a domain name must be valid UTF-8")]
    InvalidDomainName,
    /// Security MEDIUM-3: the greeting/auth/request handshake did not complete within the bound —
    /// a slow-loris peer must not be able to pin a connection task indefinitely.
    #[error("socks handshake timed out")]
    HandshakeTimeout,
}

/// Read the client greeting (`VER NMETHODS METHODS[NMETHODS]`) and pick an auth method:
/// [`require`] is the method the server insists on (e.g. `UserPass` when local auth is configured);
/// `None` means "whatever the client is willing to do, prefer no-auth". Writes the method-selection
/// reply itself (so a rejected greeting and its `0xFF` reply are one atomic step for the caller).
pub(crate) async fn negotiate_auth<S>(
    stream: &mut S,
    require: Option<AuthMethod>,
) -> Result<AuthMethod, CodecError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let [ver, nmethods] = head;
    if ver != VER_SOCKS5 {
        return Err(CodecError::UnsupportedVersion(ver));
    }
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    let offered: Vec<AuthMethod> = methods
        .iter()
        .copied()
        .filter_map(AuthMethod::from_byte)
        .collect();

    let chosen = match require {
        Some(required) if offered.contains(&required) => Some(required),
        Some(_) => None,
        // No local auth configured (no credential store to check anything against): select
        // `NoAuth` ONLY. Security LOW-1: the previous `offered.first()` fallback would select
        // `UserPass` for a client offering only that method, with nothing behind it to verify
        // against — the caller then has no credential to check, which is either a reachable panic
        // or (worse) a silent bypass, never "still safe" as the old comment claimed.
        None => offered
            .contains(&AuthMethod::NoAuth)
            .then_some(AuthMethod::NoAuth),
    };

    match chosen {
        Some(method) => {
            stream.write_all(&[VER_SOCKS5, method.to_byte()]).await?;
            Ok(method)
        }
        None => {
            stream
                .write_all(&[VER_SOCKS5, AuthMethod::NO_ACCEPTABLE_BYTE])
                .await?;
            Err(CodecError::NoAcceptableAuthMethod)
        }
    }
}

/// Read the RFC 1929 username/password sub-negotiation frame and check it against `(user, pass)`.
/// Always writes the status reply (success or failure) before returning, so the caller only needs to
/// close the connection on `Err`.
pub(crate) async fn verify_userpass<S>(
    stream: &mut S,
    expected_user: &str,
    expected_pass: &str,
) -> Result<(), CodecError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let [ver, ulen] = head;
    if ver != VER_USERPASS {
        return Err(CodecError::UnsupportedAuthVersion(ver));
    }
    let mut user = vec![0u8; ulen as usize];
    stream.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; plen[0] as usize];
    stream.read_exact(&mut pass).await?;

    // A plain (short-circuiting, non-constant-time) equality check — not hardened against a timing
    // side-channel. That is an accepted tradeoff, not an oversight: this credential only ever
    // guards a loopback SOCKS port against another local user, a threat model a sub-millisecond
    // timing difference over a local socket does not meaningfully weaken.
    let ok = user == expected_user.as_bytes() && pass == expected_pass.as_bytes();
    stream
        .write_all(&[VER_USERPASS, if ok { 0x00 } else { 0x01 }])
        .await?;
    if ok {
        Ok(())
    } else {
        Err(CodecError::AuthRejected)
    }
}

/// Read a SOCKS5 request (`VER CMD RSV ATYP DST.ADDR DST.PORT`). Parses every `ATYP` the RFC defines
/// (even the ones this proxy refuses) so the server can give a precise, correct reply rather than
/// just dropping the connection on an address form it doesn't serve.
pub(crate) async fn read_request<S>(stream: &mut S) -> Result<Request, CodecError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [ver, cmd, _rsv, atyp] = head;
    if ver != VER_SOCKS5 {
        return Err(CodecError::UnsupportedVersion(ver));
    }
    let command = Command::from_byte(cmd);
    let addr = match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            AddrSpec::Ipv4(buf)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf).await?;
            AddrSpec::Domainname(String::from_utf8(buf).map_err(|_| CodecError::InvalidDomainName)?)
        }
        0x04 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            AddrSpec::Ipv6(buf)
        }
        other => return Err(CodecError::UnsupportedAddrType(other)),
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    Ok(Request {
        command,
        addr,
        port,
    })
}

/// SOCKS5 reply codes this server actually sends (RFC 1928 §6, a subset). Named here rather than as
/// bare `u8`s at each call site so every reply path in [`super::server`] is self-documenting.
pub(crate) mod reply {
    pub(crate) const SUCCEEDED: u8 = 0x00;
    /// A general server failure (e.g. the overlay dial itself failed after a known service resolved).
    pub(crate) const GENERAL_FAILURE: u8 = 0x01;
    /// Policy refusal — used for an IP-literal destination (a supported `ATYP`, refused by *our*
    /// ruleset: "use a hostname — this proxy resolves names to services").
    pub(crate) const NOT_ALLOWED_BY_RULESET: u8 = 0x02;
    /// "Host unreachable" — used for a well-formed hostname that is simply not in the service
    /// catalog (plan §2's exact required code for an unknown name).
    pub(crate) const HOST_UNREACHABLE: u8 = 0x04;
    /// `BIND`/`UDP ASSOCIATE` — commands this proxy never serves.
    pub(crate) const COMMAND_NOT_SUPPORTED: u8 = 0x07;
}

/// Write a SOCKS5 reply (`VER REP RSV ATYP BND.ADDR BND.PORT`). The bind address/port are always
/// `0.0.0.0:0` — there is no real local socket behind a successful reply (the "connection" is a
/// virtual overlay [`boatramp_overlay_client::Flow`], not an OS socket), which is the normal, RFC-
/// compliant way a non-relay SOCKS gateway reports success.
pub(crate) async fn write_reply<S>(stream: &mut S, rep: u8) -> Result<(), CodecError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let frame = [VER_SOCKS5, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&frame).await?;
    Ok(())
}

/// Feed `data` as a SOCKS client's bytes through the greeting/auth ([`negotiate_auth`]) and request
/// ([`read_request`]) parse paths the real accept loop runs — writing any replies to a sink — and
/// assert they never panic: on arbitrary input the hand-rolled codec (plan §2/§5/§6, an
/// attacker-adjacent parse surface) must always return `Ok` or a [`CodecError`], never crash or grow
/// unbounded. Shared by the nightly `fuzz_socks_codec` cargo-fuzz target and the stable, always-run
/// regression test below, so there is exactly ONE copy of the harness to reason about — mirroring
/// [`crate::tun::netstack::fuzz_one_frame`]. Each flat corpus entry drives BOTH parsers from the
/// start of `data` (they run back-to-back on one real connection, but fuzzing each independently
/// gives libfuzzer a realistic shot at both decoders); the credentialed [`verify_userpass`] path
/// needs a live sub-negotiation on the same stream and stays covered by the unit tests, not this
/// flat harness.
pub fn fuzz_one_request(data: &[u8]) {
    thread_local! {
        // One reused current-thread runtime per fuzzing thread: the parsers do no real I/O (every
        // read resolves immediately against the in-memory `data`) and start no timers, so a bare
        // current-thread runtime is enough, and reusing it keeps the per-iteration cost a per-call
        // `Runtime::new` would otherwise dominate negligible.
        static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread tokio runtime for the SOCKS fuzz harness");
    }
    RT.with(|rt| {
        rt.block_on(async {
            let mut greeting = tokio::io::join(data, tokio::io::sink());
            let _ = negotiate_auth(&mut greeting, None).await;
            let mut request = tokio::io::join(data, tokio::io::sink());
            let _ = read_request(&mut request).await;
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stable (non-nightly, always-run-in-CI) regression net for [`fuzz_one_request`] — mirrors
    /// `tun::netstack`'s `fuzz_one_frame_never_panics_on_a_handful_of_edge_cases`: a handful of
    /// malformed/edge greetings + requests must each drive the parser to an `Ok`/`Err` without a
    /// panic. The nightly `fuzz_socks_codec` target explores far beyond these.
    #[test]
    fn fuzz_one_request_never_panics_on_a_handful_of_edge_cases() {
        fuzz_one_request(&[]);
        fuzz_one_request(&[0x05]); // VER only — truncated greeting
        fuzz_one_request(&[0x05, 0xff]); // claims 255 methods, none follow
        fuzz_one_request(&[0x04, 0x01, 0x00]); // wrong SOCKS version byte
        fuzz_one_request(&[0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0xff]); // domainname len 255, truncated
        fuzz_one_request(&[0xffu8; 64]); // all-ones garbage
    }

    /// Build a connected in-memory duplex pair: `client` is what a real SOCKS client would hold
    /// (write requests into it, read replies from it); `server` is passed to the codec functions
    /// under test, exactly as `server.rs` passes a real `TcpStream`.
    fn pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(4096)
    }

    #[tokio::test]
    async fn greeting_table_no_auth_required_prefers_no_auth_when_offered() {
        let (mut client, mut server) = pair();
        // VER=5, NMETHODS=2, methods = {no-auth, user/pass}
        client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        let chosen = negotiate_auth(&mut server, None).await.unwrap();
        assert_eq!(chosen, AuthMethod::NoAuth);
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }

    #[tokio::test]
    async fn greeting_table_requires_userpass_and_client_only_offers_no_auth() {
        let (mut client, mut server) = pair();
        // Client offers ONLY no-auth; server requires user/pass -> must refuse (0xFF) and error.
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let err = negotiate_auth(&mut server, Some(AuthMethod::UserPass))
            .await
            .unwrap_err();
        assert!(matches!(err, CodecError::NoAcceptableAuthMethod));
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn greeting_table_requires_userpass_and_client_offers_it() {
        let (mut client, mut server) = pair();
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let chosen = negotiate_auth(&mut server, Some(AuthMethod::UserPass))
            .await
            .unwrap();
        assert_eq!(chosen, AuthMethod::UserPass);
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x05, 0x02]);
    }

    #[tokio::test]
    async fn greeting_table_rejects_a_non_socks5_version_byte() {
        let (mut client, mut server) = pair();
        client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        let err = negotiate_auth(&mut server, None).await.unwrap_err();
        assert!(matches!(err, CodecError::UnsupportedVersion(0x04)));
    }

    #[tokio::test]
    async fn auth_table_accepts_correct_credentials() {
        let (mut client, mut server) = pair();
        // VER=1, ULEN=5 "alice", PLEN=3 "hi!"
        let mut frame = vec![0x01, 5];
        frame.extend_from_slice(b"alice");
        frame.push(3);
        frame.extend_from_slice(b"hi!");
        client.write_all(&frame).await.unwrap();
        verify_userpass(&mut server, "alice", "hi!").await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x01, 0x00]);
    }

    #[tokio::test]
    async fn auth_table_rejects_wrong_password() {
        let (mut client, mut server) = pair();
        let mut frame = vec![0x01, 5];
        frame.extend_from_slice(b"alice");
        frame.push(5);
        frame.extend_from_slice(b"wrong");
        client.write_all(&frame).await.unwrap();
        let err = verify_userpass(&mut server, "alice", "hi!")
            .await
            .unwrap_err();
        assert!(matches!(err, CodecError::AuthRejected));
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [0x01, 0x01]);
    }

    #[tokio::test]
    async fn connect_table_domainname_parses_the_hostname_and_port() {
        let (mut client, mut server) = pair();
        let mut frame = vec![0x05, 0x01, 0x00, 0x03, 6];
        frame.extend_from_slice(b"db.svc");
        frame.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&frame).await.unwrap();
        let req = read_request(&mut server).await.unwrap();
        assert_eq!(req.command, Command::Connect);
        assert_eq!(req.addr, AddrSpec::Domainname("db.svc".to_string()));
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn connect_table_ipv4_literal_parses_but_is_the_servers_job_to_refuse() {
        let (mut client, mut server) = pair();
        let mut frame = vec![0x05, 0x01, 0x00, 0x01];
        frame.extend_from_slice(&[127, 0, 0, 1]);
        frame.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&frame).await.unwrap();
        let req = read_request(&mut server).await.unwrap();
        // The codec parses it faithfully; policy (reject) lives in server.rs, proven there.
        assert_eq!(req.addr, AddrSpec::Ipv4([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn connect_table_bind_and_udp_associate_parse_as_their_own_commands() {
        let (mut client, mut server) = pair();
        let mut frame = vec![0x05, 0x02, 0x00, 0x03, 2];
        frame.extend_from_slice(b"db");
        frame.extend_from_slice(&0u16.to_be_bytes());
        client.write_all(&frame).await.unwrap();
        let req = read_request(&mut server).await.unwrap();
        assert_eq!(req.command, Command::Bind);
    }

    #[tokio::test]
    async fn malformed_table_an_unknown_address_type_is_rejected() {
        let (mut client, mut server) = pair();
        client.write_all(&[0x05, 0x01, 0x00, 0x99]).await.unwrap();
        let err = read_request(&mut server).await.unwrap_err();
        assert!(matches!(err, CodecError::UnsupportedAddrType(0x99)));
    }

    #[tokio::test]
    async fn malformed_table_a_truncated_frame_is_an_io_error_not_a_panic() {
        let (mut client, mut server) = pair();
        // Claim a 10-byte domain name but only send 3 — must error, never panic/hang past EOF.
        client
            .write_all(&[0x05, 0x01, 0x00, 0x03, 10])
            .await
            .unwrap();
        client.write_all(b"abc").await.unwrap();
        drop(client);
        let err = read_request(&mut server).await.unwrap_err();
        assert!(matches!(err, CodecError::Io(_)));
    }

    #[tokio::test]
    async fn malformed_table_a_non_utf8_domain_name_is_rejected() {
        let (mut client, mut server) = pair();
        let mut frame = vec![0x05, 0x01, 0x00, 0x03, 2];
        frame.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        frame.extend_from_slice(&0u16.to_be_bytes());
        client.write_all(&frame).await.unwrap();
        let err = read_request(&mut server).await.unwrap_err();
        assert!(matches!(err, CodecError::InvalidDomainName));
    }

    #[tokio::test]
    async fn write_reply_emits_the_rfc_shaped_success_frame() {
        let (mut client, mut server) = pair();
        write_reply(&mut server, reply::SUCCEEDED).await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }
}
