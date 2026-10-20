//! Relay-blind E2EE — the async runtime (IU-4).
//!
//! [`establish`] drives the pure handshake ([`boatramp_overlay_proto::e2ee`]) over a bi-stream: it
//! exchanges the length-delimited signed KEM shares, derives the session, and fires the
//! `established` hook with the learned peer identity *before any app byte* (the hook a direct-path
//! promotion later uses to pin the direct link to the session identity, IU-7). [`splice`] then runs
//! the two record-mux pumps that seal application bytes onto the overlay transport and open them
//! back — the relay in between forwards sealed records it cannot read.

use boatramp_overlay_proto::e2ee::{
    E2eeError, HybridInitiator, Opener, Role, Sealer, Session, hybrid_respond, open_signed_share,
    seal_signed_share, transcript,
};
use boatramp_overlay_proto::identity::{OverlayId, OverlaySecret};
use boatramp_overlay_proto::wire;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

/// Application read chunk → one sealed record.
const READ_CHUNK: usize = 16 * 1024;
/// Upper bound on a signed KEM share on the wire (shares are ~1.3 KiB; generous).
const MAX_SHARE: usize = 8 * 1024;
/// Upper bound on a sealed record on the wire (a data chunk + channel tag + AEAD tag).
const MAX_RECORD: usize = READ_CHUNK + 256;

/// A handshake or splice failure.
#[derive(Debug, thiserror::Error)]
pub enum SpliceError {
    #[error(transparent)]
    E2ee(#[from] E2eeError),
    #[error("transport io: {0}")]
    Io(#[from] std::io::Error),
    #[error("framed message too large: {0} bytes")]
    TooLarge(usize),
    #[error("unknown E2EE channel tag {0:#x}")]
    UnknownChannel(u8),
}

/// Write a length-delimited blob (4-byte big-endian length prefix).
pub(crate) async fn write_lp(
    w: &mut (impl AsyncWrite + Unpin),
    buf: &[u8],
) -> Result<(), SpliceError> {
    w.write_all(&(buf.len() as u32).to_be_bytes()).await?;
    w.write_all(buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-delimited blob, bounded by `max`. `Ok(None)` on a clean EOF at a frame boundary.
pub(crate) async fn read_lp(
    r: &mut (impl AsyncRead + Unpin),
    max: usize,
) -> Result<Option<Vec<u8>>, SpliceError> {
    let mut len = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let n = r.read(&mut len[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into())
            };
        }
        filled += n;
    }
    let want = u32::from_be_bytes(len) as usize;
    if want > max {
        return Err(SpliceError::TooLarge(want));
    }
    let mut buf = vec![0u8; want];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Run the identity-signed hybrid-KEM handshake over `(send, recv)` and return the session plus the
/// learned peer identity. The initiator pins the egress (`expect = Some`); the responder learns the
/// initiator (`expect = None`). `established`, if given, is fired with the peer identity the instant
/// the session is ready (before any app byte).
pub async fn establish<S, R>(
    send: &mut S,
    recv: &mut R,
    secret: &OverlaySecret,
    role: Role,
    expect: Option<OverlayId>,
    established: Option<oneshot::Sender<OverlayId>>,
) -> Result<(Session, OverlayId), SpliceError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let (session, peer) = match role {
        Role::Initiator => {
            let initiator = HybridInitiator::generate()?;
            let offer = initiator.offer();
            write_lp(send, &seal_signed_share(&offer, secret).await?).await?;
            let signed_reply = read_lp(recv, MAX_SHARE)
                .await?
                .ok_or(SpliceError::Io(std::io::ErrorKind::UnexpectedEof.into()))?;
            let (reply, peer) = open_signed_share(&signed_reply, expect.as_ref())?;
            let combined = initiator.finish(&reply)?;
            let t = transcript(&offer, &reply, &secret.id(), &peer);
            (Session::new(&combined, &t, role)?, peer)
        }
        Role::Responder => {
            let signed_offer = read_lp(recv, MAX_SHARE)
                .await?
                .ok_or(SpliceError::Io(std::io::ErrorKind::UnexpectedEof.into()))?;
            let (offer, peer) = open_signed_share(&signed_offer, expect.as_ref())?;
            let (reply, combined) = hybrid_respond(&offer)?;
            write_lp(send, &seal_signed_share(&reply, secret).await?).await?;
            let t = transcript(&offer, &reply, &peer, &secret.id());
            (Session::new(&combined, &t, role)?, peer)
        }
    };
    if let Some(tx) = established {
        let _ = tx.send(peer); // receiver may have dropped; the session is still valid
    }
    Ok((session, peer))
}

/// Run the two record-mux pumps of an established session: seal application bytes from `app_r` and
/// control signals from `signaling_out` onto `link_send` ([`wire::CH_DATA`] / [`wire::CH_SIGNAL`]),
/// and open records from `link_recv` back to `app_w` (data) or `signaling_in` (signals). The
/// signaling channel carries the ICE candidate exchange (IU-6) inside the SAME sealed stream — never
/// a side channel, so a relay cannot read or forge it. Delivery to `signaling_in` is non-blocking: a
/// full/closed signaling queue must never stall the data path. A clean EOF on either side
/// half-closes the other.
#[allow(clippy::too_many_arguments)]
pub async fn splice<AR, AW, LS, LR>(
    mut sealer: Sealer,
    mut opener: Opener,
    mut app_r: AR,
    mut app_w: AW,
    mut link_send: LS,
    mut link_recv: LR,
    mut signaling_out: mpsc::Receiver<Vec<u8>>,
    signaling_in: mpsc::Sender<Vec<u8>>,
) -> Result<(), SpliceError>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    LS: AsyncWrite + Unpin,
    LR: AsyncRead + Unpin,
{
    let outbound = async {
        let mut buf = vec![0u8; READ_CHUNK];
        let mut signaling_open = true;
        loop {
            tokio::select! {
                r = app_r.read(&mut buf) => {
                    let n = r?;
                    if n == 0 {
                        link_send.shutdown().await?; // app EOF → clean FIN
                        break;
                    }
                    let mut plaintext = Vec::with_capacity(1 + n);
                    plaintext.push(wire::CH_DATA);
                    plaintext.extend_from_slice(&buf[..n]);
                    write_lp(&mut link_send, &sealer.seal(&plaintext)?).await?;
                }
                msg = signaling_out.recv(), if signaling_open => match msg {
                    Some(m) if m.len() <= wire::MAX_SIGNAL_LEN => {
                        let mut plaintext = Vec::with_capacity(1 + m.len());
                        plaintext.push(wire::CH_SIGNAL);
                        plaintext.extend_from_slice(&m);
                        write_lp(&mut link_send, &sealer.seal(&plaintext)?).await?;
                    }
                    Some(_) => {} // oversized control message — drop, never stall data
                    None => signaling_open = false, // no more signals to send
                },
            }
        }
        Ok::<(), SpliceError>(())
    };

    let inbound = async {
        loop {
            let Some(sealed) = read_lp(&mut link_recv, MAX_RECORD).await? else {
                app_w.shutdown().await?;
                break;
            };
            let record = opener.open(&sealed)?;
            let (&tag, payload) = record
                .split_first()
                .ok_or(SpliceError::E2ee(E2eeError::Aead))?;
            if tag == wire::CH_DATA {
                app_w.write_all(payload).await?;
                app_w.flush().await?;
            } else if tag == wire::CH_SIGNAL {
                // Non-blocking: a full/closed signaling queue must never stall the data path.
                let _ = signaling_in.try_send(payload.to_vec());
            } else {
                return Err(SpliceError::UnknownChannel(tag));
            }
        }
        Ok::<(), SpliceError>(())
    };

    tokio::try_join!(outbound, inbound)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Establish A↔B over a handshake link, then splice application data through the session and
    /// confirm it round-trips and the sealed wire carries no plaintext.
    #[tokio::test]
    async fn establish_then_splice_round_trips_relay_blind() {
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let (a_id, b_id) = (a.id(), b.id());

        // --- handshake over one duplex ---
        let (ha, hb) = tokio::io::duplex(64 * 1024);
        let (mut ha_r, mut ha_w) = tokio::io::split(ha);
        let (mut hb_r, mut hb_w) = tokio::io::split(hb);
        let (tx_est, rx_est) = oneshot::channel();

        let a_task = tokio::spawn(async move {
            establish(
                &mut ha_w,
                &mut ha_r,
                &a,
                Role::Initiator,
                Some(b_id),
                Some(tx_est),
            )
            .await
            .map(|(s, peer)| (s, peer, a))
        });
        let (sess_b, learned_a) = {
            let b_ref = &b;
            establish(&mut hb_w, &mut hb_r, b_ref, Role::Responder, None, None)
                .await
                .unwrap()
        };
        let (sess_a, learned_b, _a_held) = a_task.await.unwrap().unwrap();

        // The responder learned the initiator; the initiator pinned the egress; the hook fired.
        assert_eq!(learned_a, a_id);
        assert_eq!(learned_b, b_id);
        assert_eq!(rx_est.await.unwrap(), b_id);

        // --- splice application data A -> B over a second duplex (the data link) ---
        let (la, lb) = tokio::io::duplex(64 * 1024);
        let (la_r, la_w) = tokio::io::split(la);
        let (lb_r, lb_w) = tokio::io::split(lb);
        // Tap: capture what A seals onto the wire, to assert relay-blindness.
        let (tap_w, mut tap_r) = tokio::io::duplex(64 * 1024);

        let (seal_a, open_a) = sess_a.split();
        let (seal_b, open_b) = sess_b.split();

        // A: app source "hello e2ee overlay" -> seal -> (la_w, tee'd to tap).
        let a_side = tokio::spawn(splice(
            seal_a,
            open_a,
            std::io::Cursor::new(b"hello e2ee overlay".to_vec()),
            tokio::io::sink(),
            TeeWriter {
                inner: la_w,
                tap: tap_w,
            },
            la_r,
            mpsc::channel::<Vec<u8>>(1).1,
            mpsc::channel::<Vec<u8>>(1).0,
        ));
        // B: collect what arrives.
        let (mut collector, coll_pump) = tokio::io::duplex(64 * 1024);
        let b_side = tokio::spawn(splice(
            seal_b,
            open_b,
            tokio::io::empty(),
            coll_pump,
            lb_w,
            lb_r,
            mpsc::channel::<Vec<u8>>(1).1,
            mpsc::channel::<Vec<u8>>(1).0,
        ));

        a_side.await.unwrap().unwrap();
        b_side.await.unwrap().unwrap();

        let mut got = Vec::new();
        collector.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello e2ee overlay");

        // The sealed wire must not contain the plaintext.
        let mut wire_bytes = Vec::new();
        tap_r.read_to_end(&mut wire_bytes).await.unwrap();
        assert!(!wire_bytes.is_empty());
        assert!(
            !wire_bytes.windows(b"hello".len()).any(|w| w == b"hello"),
            "a relay must see only ciphertext"
        );
    }

    /// A `CH_SIGNAL` message (the ICE carrier) muxes through the sealed splice to the peer's
    /// signaling sink, alongside (pending) app data.
    #[tokio::test]
    async fn splice_muxes_signaling_to_the_peer() {
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let b_id = b.id();

        let (ha, hb) = tokio::io::duplex(64 * 1024);
        let (mut ha_r, mut ha_w) = tokio::io::split(ha);
        let (mut hb_r, mut hb_w) = tokio::io::split(hb);
        let a2 = OverlaySecret::from_seed_hex(&a.seed_hex()).unwrap();
        let at = tokio::spawn(async move {
            establish(&mut ha_w, &mut ha_r, &a2, Role::Initiator, Some(b_id), None).await
        });
        let (sess_b, _) = establish(&mut hb_w, &mut hb_r, &b, Role::Responder, None, None)
            .await
            .unwrap();
        let (sess_a, _) = at.await.unwrap().unwrap();

        let (la, lb) = tokio::io::duplex(64 * 1024);
        let (la_r, la_w) = tokio::io::split(la);
        let (lb_r, lb_w) = tokio::io::split(lb);
        let (seal_a, open_a) = sess_a.split();
        let (seal_b, open_b) = sess_b.split();

        // App sources that never EOF (write ends held), so the outbound pumps stay alive to
        // service signaling.
        let (_a_hold, a_app) = tokio::io::duplex(64);
        let (_b_hold, b_app) = tokio::io::duplex(64);
        let (a_app_r, a_app_w) = tokio::io::split(a_app);
        let (b_app_r, b_app_w) = tokio::io::split(b_app);

        let (a_sig_out, a_sig_out_rx) = mpsc::channel::<Vec<u8>>(4);
        let (b_sig_in, mut b_sig_in_rx) = mpsc::channel::<Vec<u8>>(4);

        let _a = tokio::spawn(splice(
            seal_a,
            open_a,
            a_app_r,
            a_app_w,
            la_w,
            la_r,
            a_sig_out_rx,
            mpsc::channel::<Vec<u8>>(1).0,
        ));
        let _b = tokio::spawn(splice(
            seal_b,
            open_b,
            b_app_r,
            b_app_w,
            lb_w,
            lb_r,
            mpsc::channel::<Vec<u8>>(1).1,
            b_sig_in,
        ));

        a_sig_out.send(b"bro-candidate-xyz".to_vec()).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), b_sig_in_rx.recv())
            .await
            .expect("signaling delivered within the timeout")
            .expect("a signal arrived");
        assert_eq!(got, b"bro-candidate-xyz");
    }

    /// A tiny `AsyncWrite` that mirrors everything written into a tap (for the relay-blind check).
    struct TeeWriter<W, T> {
        inner: W,
        tap: T,
    }

    impl<W: AsyncWrite + Unpin, T: AsyncWrite + Unpin> AsyncWrite for TeeWriter<W, T> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let n = std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_write(cx, buf))?;
            // Best-effort tap; ignore tap backpressure/err (it has a large buffer).
            let _ = std::pin::Pin::new(&mut self.tap).poll_write(cx, &buf[..n]);
            std::task::Poll::Ready(Ok(n))
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let _ = std::pin::Pin::new(&mut self.tap).poll_flush(cx);
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let _ = std::pin::Pin::new(&mut self.tap).poll_shutdown(cx);
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}
