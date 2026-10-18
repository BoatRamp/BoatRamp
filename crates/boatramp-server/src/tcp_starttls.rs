//! Declarative, protocol-agnostic **STARTTLS** for host-owned inbound guest listeners
//! (cap-req 06, Stage B).
//!
//! STARTTLS upgrades a *plaintext* connection to TLS in-band, after the client sends a command
//! (SMTP `STARTTLS`, IMAP `<tag> STARTTLS`, POP3 `STLS`). The guest owns the whole plaintext dialog
//! (greeting, capability advertisement, everything post-TLS) and runs unchanged on the same
//! `tcp-connection-handler` world as a plaintext / implicit-TLS listener — so the server cannot do
//! the upgrade by parsing the guest's protocol. Instead the one protocol-specific fact — *which*
//! client line triggers the upgrade and *what* line to reply with — is supplied as **config data**
//! ([`StarttlsGrammar`]); the host runs a generic trigger→response→wrap engine. There are **no**
//! SMTP/IMAP/POP3 string literals in this module.
//!
//! ## How the upgrade happens without a guest WIT change (the pump)
//!
//! The guest is dispatched on an in-memory [`tokio::io::duplex`] pair; this module's pump owns the
//! real socket and sits between them during the plaintext phase:
//!
//! 1. **Plaintext, interposing.** The pump forwards bytes both ways (so the guest speaks the
//!    greeting / capability dialog verbatim) while watching the *client→guest* direction for the
//!    declared [`trigger`](StarttlsGrammar::trigger) at a line boundary. It reads the raw socket
//!    **one byte at a time** and stops the instant the trigger line's `\n` is consumed — so it never
//!    reads a single byte past the trigger before the handshake (the structural injection-safety
//!    property, see below). The trigger line is **not** forwarded to the guest.
//! 2. **Upgrade.** The pump writes the declared [`response`](StarttlsGrammar::response) line to the
//!    client, then performs the TLS handshake on the **whole** socket ([`TlsAcceptor::accept`]). Any
//!    client bytes sent after the trigger line are consumed only by the TLS record layer — never
//!    buffered and replayed as application data.
//! 3. **Transparent pass-through.** Post-handshake the pump is a plain decrypted byte copy in both
//!    directions for the connection's life. The guest's first post-TLS read is the client's
//!    re-EHLO / re-CAPABILITY / re-login per RFC 3207 / 2595 — it looks like a fresh command; the
//!    guest never knew an upgrade happened.
//!
//! ## Injection safety (RFC 3207 §4 / the CVE-2011-0411 class)
//!
//! The pump is the **sole** pre-TLS reader and **never over-reads**: byte-at-a-time reading that
//! halts on the trigger line's terminating `\n` guarantees that every byte the client sent *after*
//! that `\n` is still in the socket's receive buffer and is consumed only by [`TlsAcceptor::accept`].
//! A client that pipelines `STARTTLS\r\n<injected>` makes rustls read `<injected>` as a malformed
//! ClientHello ⇒ the handshake fails ⇒ the connection drops; the injected command is never delivered
//! to the guest and there is no post-TLS channel in which it could execute. There is no `BufReader` /
//! `read_until` anywhere in the pre-TLS path (that would slurp post-`\n` bytes into a buffer — the
//! exact vulnerability); the byte-at-a-time read is also cancel-safe inside the `select!` (a dropped
//! 1-byte read consumes nothing).

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

/// Byte budget for the pre-TLS line accumulator: a client line with no `\n` within this many bytes
/// (a slowloris / a malformed non-line-protocol peer) drops the connection. Mail command lines are
/// short; this is generous. (RFC 5321 caps a command line at 512 bytes; 4 KiB leaves ample room.)
const PRE_TLS_MAX_LINE: usize = 4096;

/// In-memory buffer (each direction) of the duplex between the pump and the guest. 64 KiB — enough to
/// keep a chatty post-TLS writer from stalling on per-chunk backpressure without buffering unboundedly.
const STARTTLS_DUPLEX_BUF: usize = 64 * 1024;

/// Read buffer for the guest→client (and post-TLS) copy direction.
const COPY_BUF: usize = 16 * 1024;

/// Declarative STARTTLS grammar — the **only** protocol knowledge, supplied as config data (it travels
/// with the guest's listener deploy). The host matches exactly one declared `trigger` line in the
/// client→server direction and injects exactly one declared `response`; it never parses or rewrites
/// the guest's own protocol output.
#[derive(Debug, Clone)]
pub struct StarttlsGrammar {
    /// The command the host watches for in the CLIENT→server direction, matched at a line boundary,
    /// ASCII-case-insensitively. With [`tag_capture`](Self::tag_capture) this is the token *after* the
    /// leading tag (IMAP `STARTTLS`); otherwise the whole line (SMTP `STARTTLS`, POP3 `STLS`).
    pub trigger: String,
    /// The single line the host writes to the client immediately before the handshake. `{tag}` is
    /// substituted with the captured tag when `tag_capture`; the host appends CRLF.
    pub response: String,
    /// IMAP-shaped: capture the leading whitespace-delimited token of the trigger line and echo it
    /// (verbatim — tags are case-sensitive) into `{tag}`.
    pub tag_capture: bool,
}

/// Match `line` (one raw line, `\n`-terminated or not) against the grammar's trigger.
///
/// Returns `None` for no match, `Some(None)` for a match with no captured tag, and `Some(Some(tag))`
/// for a match with a captured leading tag. The command is compared **ASCII-case-insensitively** (per
/// RFC 5321 / 3501 command grammar); a captured tag is kept **verbatim** (IMAP tags are case-sensitive
/// and the client expects its own tag echoed). Generic line-protocol primitives only — no mail tokens.
fn match_trigger(line: &[u8], g: &StarttlsGrammar) -> Option<Option<String>> {
    // Strip a trailing `\n`, then an optional preceding `\r`.
    let mut s = line;
    if s.last() == Some(&b'\n') {
        s = &s[..s.len() - 1];
    }
    if s.last() == Some(&b'\r') {
        s = &s[..s.len() - 1];
    }
    let trig = g.trigger.as_bytes();
    if g.tag_capture {
        // Split at the first run of ASCII spaces into (tag, rest); require a non-empty tag and the
        // rest to equal the trigger.
        let sp = s.iter().position(|&b| b == b' ')?;
        let tag = &s[..sp];
        if tag.is_empty() {
            return None;
        }
        // Defensive: the tag is echoed verbatim into the response line, so refuse any ASCII control
        // byte in it. A `\n`/space can't be here by construction (the line ends at `\n`; the tag stops
        // at the first space), so this can't inject a second response line even without the check —
        // but an embedded `\r`/NUL/control char has no legitimate place in a protocol tag, and
        // rejecting it keeps the host-written response strictly single-line and control-free.
        if tag.iter().any(u8::is_ascii_control) {
            return None;
        }
        let mut rest = &s[sp..];
        while rest.first() == Some(&b' ') {
            rest = &rest[1..];
        }
        if rest.eq_ignore_ascii_case(trig) {
            Some(Some(String::from_utf8_lossy(tag).into_owned()))
        } else {
            None
        }
    } else if s.eq_ignore_ascii_case(trig) {
        Some(None)
    } else {
        None
    }
}

/// Substitute `{tag}` in the response template with the captured tag (or the empty string). The caller
/// appends CRLF.
fn render_response(template: &str, tag: Option<&str>) -> String {
    template.replace("{tag}", tag.unwrap_or(""))
}

/// Drive a STARTTLS connection: forward the plaintext dialog between `socket` and the guest (on
/// `host_end`), upgrade to TLS on the declared trigger, then pass decrypted bytes through for the
/// connection's life. Returns when either side closes or the handshake fails (the caller aborts the
/// guest dispatch; dropping `host_end` makes the guest read EOF — there is never a plaintext
/// fallthrough of a failed upgrade).
pub(crate) async fn run_starttls_pump(
    mut socket: TcpStream,
    host_end: DuplexStream,
    acceptor: TlsAcceptor,
    grammar: StarttlsGrammar,
) -> io::Result<()> {
    let (mut hr, mut hw) = tokio::io::split(host_end);

    // ---- PHASE 1: plaintext, interposing (the injection-critical phase) ----
    let captured_tag: Option<String>;
    {
        // Borrow the socket halves so `socket` is reclaimable (whole) for the handshake afterward.
        let (mut sr, mut sw) = socket.split();
        let mut line: Vec<u8> = Vec::with_capacity(128);
        let mut gbuf = [0u8; COPY_BUF];
        loop {
            tokio::select! {
                biased;
                // client → guest: ONE byte at a time, so we never read past the trigger line's `\n`.
                r = sr.read_u8() => {
                    let b = match r {
                        Ok(b) => b,
                        Err(_) => return Ok(()), // client closed / errored before the trigger
                    };
                    line.push(b);
                    if line.len() > PRE_TLS_MAX_LINE {
                        return Ok(()); // no `\n` within the budget — drop (slowloris / non-line peer)
                    }
                    if b == b'\n' {
                        if let Some(tag) = match_trigger(&line, &grammar) {
                            captured_tag = tag;
                            break; // → Phase 2. The trigger line is deliberately NOT forwarded.
                        }
                        // Not the trigger: forward the whole line (CRLF included) to the guest.
                        if hw.write_all(&line).await.is_err() {
                            return Ok(()); // guest gone
                        }
                        line.clear();
                    }
                }
                // guest → client: forward the guest's own protocol output verbatim.
                n = hr.read(&mut gbuf) => {
                    let n = match n {
                        Ok(0) => return Ok(()), // guest finished before the upgrade
                        Ok(n) => n,
                        Err(_) => return Ok(()),
                    };
                    sw.write_all(&gbuf[..n]).await?;
                    sw.flush().await?;
                }
            }
        }
        // Write the declared response line (host-injected — the guest never handles the trigger), then
        // CRLF, then flush, before handing the socket to the TLS layer.
        let resp = render_response(&grammar.response, captured_tag.as_deref());
        sw.write_all(resp.as_bytes()).await?;
        sw.write_all(b"\r\n").await?;
        sw.flush().await?;
        // sr/sw borrows end here, releasing `socket`.
    }

    // ---- PHASE 2: handshake on the WHOLE socket, then transparent decrypted pass-through ----
    // Any client byte sent after the trigger line's `\n` is still in the socket buffer and is consumed
    // ONLY here, by the TLS record layer — never replayed as plaintext/application data.
    let tls = acceptor.accept(socket).await?;
    let (mut tr, mut tw) = tokio::io::split(tls);
    // Decrypted bytes both ways until either side closes. No line discipline past the upgrade.
    tokio::select! {
        r = tokio::io::copy(&mut tr, &mut hw) => { r?; }
        r = tokio::io::copy(&mut hr, &mut tw) => { r?; }
    }
    Ok(())
}

/// Spawn the pump for a STARTTLS connection and return the guest-facing duplex halves to dispatch the
/// guest on, plus the pump's `JoinHandle` (the caller aborts it when the guest dispatch returns). The
/// guest runs byte-identically to a plaintext / implicit-TLS listener — it reads/writes these duplex
/// halves and never learns an upgrade happened. `pub` so the live capability gate can drive the EXACT
/// production pump (not a reimplementation).
pub fn spawn_pump(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    grammar: StarttlsGrammar,
) -> (
    tokio::io::ReadHalf<DuplexStream>,
    tokio::io::WriteHalf<DuplexStream>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let (guest_end, host_end) = tokio::io::duplex(STARTTLS_DUPLEX_BUF);
    let (g_read, g_write) = tokio::io::split(guest_end);
    let handle = tokio::spawn(run_starttls_pump(socket, host_end, acceptor, grammar));
    (g_read, g_write, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(trigger: &str, response: &str, tag_capture: bool) -> StarttlsGrammar {
        StarttlsGrammar {
            trigger: trigger.to_string(),
            response: response.to_string(),
            tag_capture,
        }
    }

    #[test]
    fn match_trigger_untagged_smtp_and_pop3() {
        let smtp = g("STARTTLS", "220 ready", false);
        assert_eq!(match_trigger(b"STARTTLS\r\n", &smtp), Some(None));
        // ASCII-case-insensitive command match.
        assert_eq!(match_trigger(b"starttls\r\n", &smtp), Some(None));
        assert_eq!(match_trigger(b"StartTls\n", &smtp), Some(None)); // bare LF too
        // A different command never matches.
        assert_eq!(match_trigger(b"EHLO host\r\n", &smtp), None);
        // A trailing argument makes it a different (non-matching) line for the untagged form.
        assert_eq!(match_trigger(b"STARTTLS now\r\n", &smtp), None);

        let pop3 = g("STLS", "+OK", false);
        assert_eq!(match_trigger(b"STLS\r\n", &pop3), Some(None));
        assert_eq!(match_trigger(b"stls\r\n", &pop3), Some(None));
    }

    #[test]
    fn match_trigger_tagged_imap_captures_verbatim_tag() {
        let imap = g("STARTTLS", "{tag} OK begin TLS", true);
        assert_eq!(
            match_trigger(b"a001 STARTTLS\r\n", &imap),
            Some(Some("a001".to_string()))
        );
        // Command case-insensitive, tag verbatim (case preserved).
        assert_eq!(
            match_trigger(b"A1 starttls\r\n", &imap),
            Some(Some("A1".to_string()))
        );
        // Extra inter-token spaces tolerated.
        assert_eq!(
            match_trigger(b"xyz   STARTTLS\n", &imap),
            Some(Some("xyz".to_string()))
        );
        // Missing tag ⇒ no match (there is no leading token before the command).
        assert_eq!(match_trigger(b"STARTTLS\r\n", &imap), None);
        // Wrong command after the tag ⇒ no match.
        assert_eq!(match_trigger(b"a1 LOGIN\r\n", &imap), None);
        // Defensive (LOW-1): a tag carrying an embedded control byte (here CR) is refused, so the
        // host-written response stays strictly single-line and control-free. `\n` / space can't be in
        // a tag by construction; `\r`, NUL and other controls are rejected here.
        assert_eq!(match_trigger(b"a\r1 STARTTLS\r\n", &imap), None);
        assert_eq!(match_trigger(b"a\x00 STARTTLS\n", &imap), None);
    }

    #[test]
    fn render_response_substitutes_tag() {
        assert_eq!(
            render_response("{tag} OK begin TLS", Some("a001")),
            "a001 OK begin TLS"
        );
        // No tag ⇒ placeholder becomes empty (used only when tag_capture is false, where a config
        // with a `{tag}` is refused at validation — this is the defensive fallback).
        assert_eq!(render_response("{tag} OK", None), " OK");
        // No placeholder ⇒ verbatim.
        assert_eq!(
            render_response("220 2.0.0 Ready to start TLS", None),
            "220 2.0.0 Ready to start TLS"
        );
    }
}
