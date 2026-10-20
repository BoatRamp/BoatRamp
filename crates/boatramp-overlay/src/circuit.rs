//! Resumable windowed circuit — the async pump (IU-5).
//!
//! [`run_circuit_duplex`] carries a byte stream between a `local` connection and
//! a `link`, framed as [`XgressFrame`]s. It is the subtlest unit in the overlay:
//! a single `select!` loop that, on a link fault, **parks on a rebind channel
//! and retransmits everything still outstanding** onto the next link, so the
//! stream survives a link swap with zero loss or duplication (the peer dedups by
//! offset in its [`RxPortal`]). Mid-flow direct-path promotion (IU-7) reuses this
//! exact mechanism: it simply feeds the direct link's halves to the rebind
//! channel.
//!
//! Framing uses a length-delimited codec because [`FramedRead::next`] is
//! cancellation-safe — the pump's `select!` branches must not lose bytes when a
//! sibling branch wins the race. The [`CircuitRegistry`] that routes a
//! reconnecting stream back to its in-flight pump is **in-memory** runtime state
//! (overlay guardrail 3), never `KvStore`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use boatramp_overlay_proto::OverlayId;
use boatramp_overlay_proto::circuit::{FrameError, RxPortal, TxPortal, XgressFrame};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Instant, sleep_until};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

/// The maximum circuit frame body on the wire (guards the length prefix). A
/// payload frame is `1 + 8 + segment` bytes; this leaves margin.
const MAX_FRAME: usize = boatramp_overlay_proto::circuit::DEFAULT_SEGMENT + 64;

/// The length-delimited codec (4-byte big-endian length prefix by default).
fn codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_FRAME)
        .new_codec()
}

/// The read + write halves of one overlay link (a QUIC bi-stream in production,
/// an in-memory duplex in tests). Boxed so a link can be swapped on rebind.
pub struct LinkHalves {
    read: Box<dyn AsyncRead + Send + Unpin>,
    write: Box<dyn AsyncWrite + Send + Unpin>,
}

impl LinkHalves {
    /// Wrap a read and a write half.
    pub fn new(
        read: impl AsyncRead + Send + Unpin + 'static,
        write: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Self {
        Self {
            read: Box::new(read),
            write: Box::new(write),
        }
    }
}

/// Outcome counters for one circuit run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CircuitStats {
    /// Bytes read from the local side and sent onto the circuit.
    pub bytes_sent: u64,
    /// Bytes delivered from the circuit to the local side.
    pub bytes_recv: u64,
    /// Times the link was swapped (a link fault survived by a rebind).
    pub rebinds: u64,
}

/// A circuit run failure.
#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    /// The link faulted and no rebind arrived within the grace window.
    #[error("link down and no rebind within grace")]
    LinkDown,
    /// The local connection failed.
    #[error("local io: {0}")]
    LocalIo(#[source] std::io::Error),
    /// A peer sent a malformed frame.
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
}

/// Drive a duplex byte stream over a resumable circuit until both sides have
/// cleanly half-closed (both `Fin`s exchanged), or the link is lost past the
/// rebind grace.
///
/// `local_r`/`local_w` are the connection being forwarded; `link` is the first
/// link; `rebind` delivers replacement links (close it to disallow further
/// rebinds). `window` bounds in-flight bytes; `segment` caps one payload frame.
pub async fn run_circuit_duplex<L, W>(
    mut local_r: L,
    mut local_w: W,
    link: LinkHalves,
    mut rebind: mpsc::Receiver<LinkHalves>,
    grace: Duration,
    window: usize,
    segment: usize,
) -> Result<CircuitStats, CircuitError>
where
    L: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut framed_r = FramedRead::new(link.read, codec());
    let mut framed_w = FramedWrite::new(link.write, codec());
    let mut tx = TxPortal::new(window);
    let mut rx = RxPortal::new();
    // Segments sent but not yet cumulatively acked, kept for retransmit on rebind.
    let mut outstanding: BTreeMap<u64, Bytes> = BTreeMap::new();
    let mut live = true;
    let mut rebind_open = true;
    let mut local_eof = false;
    let mut my_fin_sent = false;
    let mut peer_fin = false;
    let mut deadline: Option<Instant> = None;
    let mut stats = CircuitStats::default();
    let mut rbuf = vec![0u8; segment];

    // Encode + send one frame; on error, fault the link and arm the grace timer.
    macro_rules! send_frame {
        ($f:expr) => {{
            let frame: XgressFrame = $f;
            if framed_w.send(Bytes::from(frame.encode())).await.is_err() {
                live = false;
                deadline = Some(Instant::now() + grace);
                false
            } else {
                true
            }
        }};
    }

    loop {
        // Both-way clean half-close: done.
        if my_fin_sent && peer_fin {
            let _ = framed_w.flush().await;
            return Ok(stats);
        }
        // Link gone and no further rebind possible.
        if !live && !rebind_open {
            return Err(CircuitError::LinkDown);
        }
        // Local input exhausted and everything acked → send our Fin.
        if live && local_eof && !my_fin_sent && tx.in_flight() == 0 {
            if send_frame!(XgressFrame::Fin) {
                my_fin_sent = true;
            }
            continue;
        }

        tokio::select! {
            biased;

            // Grace expired on a dead link → give up.
            () = async {
                match deadline {
                    Some(d) => sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            }, if !live => {
                return Err(CircuitError::LinkDown);
            }

            // A replacement link arrived: swap and retransmit everything outstanding.
            swap = rebind.recv(), if rebind_open => match swap {
                Some(next) => {
                    framed_r = FramedRead::new(next.read, codec());
                    framed_w = FramedWrite::new(next.write, codec());
                    live = true;
                    deadline = None;
                    stats.rebinds += 1;
                    let mut ok = true;
                    for (&offset, data) in &outstanding {
                        ok = send_frame!(XgressFrame::Payload { offset, data: data.clone() });
                        if !ok {
                            break;
                        }
                    }
                    // Re-advertise our cumulative ack, and re-assert our Fin if sent.
                    if ok {
                        ok = send_frame!(XgressFrame::Ack { through: rx.ack() });
                    }
                    if ok && my_fin_sent {
                        let _ = send_frame!(XgressFrame::Fin);
                    }
                }
                None => rebind_open = false,
            },

            // Inbound frame from the peer over the current link.
            frame = framed_r.next(), if live => match frame {
                Some(Ok(bytes)) => match XgressFrame::decode(&bytes)? {
                    XgressFrame::Ack { through } => {
                        tx.on_ack(through);
                        outstanding.retain(|&off, data| off + data.len() as u64 > through);
                    }
                    XgressFrame::Payload { offset, data } => {
                        rx.accept(offset, data);
                        for ready in rx.take_ready() {
                            stats.bytes_recv += ready.len() as u64;
                            if let Err(e) = local_w.write_all(&ready).await {
                                return Err(CircuitError::LocalIo(e));
                            }
                        }
                        if let Err(e) = local_w.flush().await {
                            return Err(CircuitError::LocalIo(e));
                        }
                        let _ = send_frame!(XgressFrame::Ack { through: rx.ack() });
                    }
                    XgressFrame::Fin => {
                        peer_fin = true;
                        let _ = local_w.shutdown().await; // half-close the local write side
                    }
                },
                // Link EOF or read error → fault; park for a rebind within grace.
                Some(Err(_)) | None => {
                    live = false;
                    deadline = Some(Instant::now() + grace);
                }
            },

            // Local data to forward, bounded by the send window.
            res = local_r.read(&mut rbuf), if live && !local_eof && tx.available() > 0 => match res {
                Ok(0) => local_eof = true,
                Ok(n) => {
                    let chunk = Bytes::copy_from_slice(&rbuf[..n]);
                    let offset = tx.on_send(n);
                    outstanding.insert(offset, chunk.clone());
                    stats.bytes_sent += n as u64;
                    let _ = send_frame!(XgressFrame::Payload { offset, data: chunk });
                }
                Err(e) => return Err(CircuitError::LocalIo(e)),
            },
        }
    }
}

/// An overlay circuit identifier — opaque, assigned by the dialer and echoed on
/// a resume so a reconnecting stream can be matched to its in-flight pump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CircuitId([u8; 16]);

impl CircuitId {
    /// Wrap 16 raw bytes.
    #[must_use]
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// In-memory map from `(circuit, peer)` to the running pump's rebind sender.
///
/// Runtime state only — never persisted (overlay guardrail 3). A relay/egress
/// registers a circuit's rebind channel while the pump runs, and a reconnecting
/// stream is handed to that pump via [`CircuitRegistry::route_resume`].
#[derive(Clone, Default)]
pub struct CircuitRegistry {
    inner: Arc<RwLock<HashMap<(CircuitId, OverlayId), mpsc::Sender<LinkHalves>>>>,
}

impl CircuitRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the rebind channel of a running circuit pump.
    pub async fn register(&self, id: CircuitId, peer: OverlayId, rebind: mpsc::Sender<LinkHalves>) {
        self.inner.write().await.insert((id, peer), rebind);
    }

    /// Drop a circuit's registration (its pump ended).
    pub async fn deregister(&self, id: CircuitId, peer: OverlayId) {
        self.inner.write().await.remove(&(id, peer));
    }

    /// Route a reconnecting link to the matching in-flight pump. Returns the
    /// halves back when no pump is registered (or its pump has gone) so the
    /// caller can start a fresh circuit instead.
    pub async fn route_resume(
        &self,
        id: CircuitId,
        peer: OverlayId,
        halves: LinkHalves,
    ) -> Option<LinkHalves> {
        let sender = self.inner.read().await.get(&(id, peer)).cloned();
        match sender {
            Some(sender) => match sender.send(halves).await {
                Ok(()) => None,
                Err(returned) => Some(returned.0), // pump gone — hand the link back
            },
            None => Some(halves),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_overlay_proto::OverlaySecret;
    use boatramp_overlay_proto::circuit::{DEFAULT_SEGMENT, DEFAULT_WINDOW};
    use boatramp_overlay_proto::wire::DEFAULT_REBIND_GRACE;

    // --- manual peer helpers (drive the other end of a link by hand) ---------

    async fn put(w: &mut (impl AsyncWrite + Unpin), f: &XgressFrame) {
        let body = f.encode();
        w.write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        w.write_all(&body).await.unwrap();
        w.flush().await.unwrap();
    }

    async fn get(r: &mut (impl AsyncRead + Unpin)) -> Option<XgressFrame> {
        let mut len = [0u8; 4];
        if r.read_exact(&mut len).await.is_err() {
            return None;
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        r.read_exact(&mut body).await.unwrap();
        Some(XgressFrame::decode(&body).unwrap())
    }

    /// Two pumps over one in-memory link: a byte stream forwards end-to-end and
    /// both sides half-close cleanly.
    #[tokio::test]
    async fn two_pumps_forward_a_stream_and_close_cleanly() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let (mut collector, coll_pump) = tokio::io::duplex(64 * 1024);
        let (_dead_tx1, rx1) = mpsc::channel(1);
        let (_dead_tx2, rx2) = mpsc::channel(1);

        let sender = tokio::spawn(run_circuit_duplex(
            std::io::Cursor::new(b"helloworld".to_vec()),
            tokio::io::sink(),
            LinkHalves::new(a_r, a_w),
            rx1,
            DEFAULT_REBIND_GRACE,
            DEFAULT_WINDOW,
            DEFAULT_SEGMENT,
        ));
        let receiver = tokio::spawn(run_circuit_duplex(
            tokio::io::empty(),
            coll_pump,
            LinkHalves::new(b_r, b_w),
            rx2,
            DEFAULT_REBIND_GRACE,
            DEFAULT_WINDOW,
            DEFAULT_SEGMENT,
        ));

        let s = sender.await.unwrap().unwrap();
        let r = receiver.await.unwrap().unwrap();
        let mut got = Vec::new();
        collector.read_to_end(&mut got).await.unwrap();

        assert_eq!(got, b"helloworld");
        assert_eq!(s.bytes_sent, 10);
        assert_eq!(r.bytes_recv, 10);
        assert_eq!(s.rebinds, 0);
    }

    /// The receiver survives a mid-stream link fault: after rebind it re-acks,
    /// drops a retransmitted (already-delivered) segment, and delivers the rest
    /// — no loss, no dup.
    #[tokio::test]
    async fn receiver_survives_a_link_fault_without_loss_or_dup() {
        let (peer1, pump1) = tokio::io::duplex(64 * 1024);
        let (mut p1_r, mut p1_w) = tokio::io::split(peer1);
        let (l1_r, l1_w) = tokio::io::split(pump1);
        let (mut collector, coll_pump) = tokio::io::duplex(64 * 1024);
        let (rebind_tx, rebind_rx) = mpsc::channel::<LinkHalves>(1);

        let receiver = tokio::spawn(run_circuit_duplex(
            tokio::io::empty(),
            coll_pump,
            LinkHalves::new(l1_r, l1_w),
            rebind_rx,
            DEFAULT_REBIND_GRACE,
            DEFAULT_WINDOW,
            DEFAULT_SEGMENT,
        ));

        // Deliver "hello" at offset 0 on link 1; read the cumulative ack.
        put(
            &mut p1_w,
            &XgressFrame::Payload {
                offset: 0,
                data: Bytes::from_static(b"hello"),
            },
        )
        .await;
        assert_eq!(get(&mut p1_r).await, Some(XgressFrame::Ack { through: 5 }));

        // Fault the link: drop our end so the pump's reader hits EOF.
        drop(p1_w);
        drop(p1_r);

        // Rebind the receiver onto link 2.
        let (peer2, pump2) = tokio::io::duplex(64 * 1024);
        let (mut p2_r, mut p2_w) = tokio::io::split(peer2);
        let (l2_r, l2_w) = tokio::io::split(pump2);
        rebind_tx.send(LinkHalves::new(l2_r, l2_w)).await.unwrap();

        // Retransmit the already-delivered "hello" (a dup — must be dropped),
        // then deliver "world".
        put(
            &mut p2_w,
            &XgressFrame::Payload {
                offset: 0,
                data: Bytes::from_static(b"hello"),
            },
        )
        .await;
        put(
            &mut p2_w,
            &XgressFrame::Payload {
                offset: 5,
                data: Bytes::from_static(b"world"),
            },
        )
        .await;

        // Drain frames (a re-ack, an early Fin from the receiver's empty local,
        // the dup's ack) until the cumulative ack reaches 10, then close.
        let mut acked_10 = false;
        while !acked_10 {
            match get(&mut p2_r).await {
                Some(XgressFrame::Ack { through: 10 }) => acked_10 = true,
                Some(XgressFrame::Ack { .. }) | Some(XgressFrame::Fin) => {}
                other => panic!("unexpected frame while draining: {other:?}"),
            }
        }
        put(&mut p2_w, &XgressFrame::Fin).await;

        let stats = receiver.await.unwrap().unwrap();
        assert_eq!(stats.rebinds, 1);
        assert_eq!(stats.bytes_recv, 10, "no byte counted twice");

        let mut got = Vec::new();
        collector.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"helloworld", "no loss, no dup across the rebind");
    }

    #[tokio::test]
    async fn registry_routes_a_resume_to_the_waiting_pump() {
        let reg = CircuitRegistry::new();
        let id = CircuitId::new([7u8; 16]);
        let peer = OverlaySecret::generate().unwrap().id();
        let (tx, mut rx) = mpsc::channel::<LinkHalves>(1);
        reg.register(id, peer, tx).await;

        let (a, _b) = tokio::io::duplex(16);
        let (a_r, a_w) = tokio::io::split(a);
        assert!(
            reg.route_resume(id, peer, LinkHalves::new(a_r, a_w))
                .await
                .is_none(),
            "a registered circuit is routed, not handed back"
        );
        assert!(
            rx.recv().await.is_some(),
            "the pump received the fresh link"
        );

        // An unknown circuit is handed back for a fresh pump.
        let (c, _d) = tokio::io::duplex(16);
        let (c_r, c_w) = tokio::io::split(c);
        assert!(
            reg.route_resume(CircuitId::new([9u8; 16]), peer, LinkHalves::new(c_r, c_w))
                .await
                .is_some()
        );
    }
}
