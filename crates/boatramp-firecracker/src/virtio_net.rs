//! A **virtio-net** device backend for the embedded VMM: the guest's network
//! interface. It implements [`VirtioDevice`] (type 1,
//! a MAC config, RX + TX queues) and bridges frames between the guest's
//! virtqueues and a host tap:
//!
//! * [`transmit`](VirtioNet::transmit) drains the **TX** queue — each chain is a
//!   12-byte `virtio_net_hdr` followed by the Ethernet frame; the header is
//!   stripped and the frame written to the tap.
//! * [`receive`](VirtioNet::receive) delivers one inbound frame into an available
//!   **RX** chain — a zero `virtio_net_hdr` (num_buffers = 1) prepended, then the
//!   frame, written across the writable descriptors.
//!
//! The tap is passed in (a `Write` for TX, the frame bytes for RX) so the queue +
//! framing logic is unit-tested with a `MockSplitQueue` ring + in-memory buffers,
//! no `/dev/kvm`/tap. Owning the real tap fd + polling it for RX is the run-loop
//! (`compute-live`) seam.

use std::io::{Read, Write};

use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_memory::{Bytes, GuestMemoryMmap};

use crate::device_manager::VirtioDeviceOps;
use crate::embedded_vmm::{drain_available, VmmError};
use crate::virtio_mmio::VirtioDevice;

/// virtqueue index of the TX queue (queue 0 = RX, queue 1 = TX).
const TX_QUEUE: u16 = 1;

/// virtio device type id for a network device.
pub const VIRTIO_ID_NET: u32 = 1;
/// `VIRTIO_F_VERSION_1` — modern (1.x) device. Bit 32.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// `VIRTIO_NET_F_MAC` — the device supplies the MAC in config space. Bit 5.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Length of the (modern) `virtio_net_hdr` prefixed to every frame.
pub const VIRTIO_NET_HDR_LEN: usize = 12;
/// Offset of `num_buffers` within `virtio_net_hdr`.
const NET_HDR_NUM_BUFFERS: usize = 10;

/// A virtio-net device with a fixed `mac` over a host `tap` (queue 0 = RX, device
/// → guest; queue 1 = TX, guest → device).
pub struct VirtioNet<T> {
    mac: [u8; 6],
    tap: T,
}

impl<T: Read + Write> VirtioNet<T> {
    /// A device advertising `mac`, bridging to `tap`.
    pub fn new(mac: [u8; 6], tap: T) -> Self {
        Self { mac, tap }
    }

    /// Drain the **TX** queue, writing each frame (with its `virtio_net_hdr`
    /// stripped) to the tap. Called when the guest notifies the TX queue.
    pub fn transmit(&mut self, queue: &mut Queue, mem: &GuestMemoryMmap) -> Result<(), VmmError> {
        let tap = &mut self.tap;
        drain_available(queue, mem, |chain| {
            // Concatenate the readable descriptors → [virtio_net_hdr || frame].
            let mut buf = Vec::new();
            for d in chain {
                if d.is_write_only() {
                    continue;
                }
                let mut seg = vec![0u8; d.len() as usize];
                if mem.read_slice(&mut seg, d.addr()).is_ok() {
                    buf.extend_from_slice(&seg);
                }
            }
            if buf.len() > VIRTIO_NET_HDR_LEN {
                let _ = tap.write_all(&buf[VIRTIO_NET_HDR_LEN..]);
            }
            0 // TX descriptors are read-only; nothing is written back to the guest
        })
    }
}

impl<T: Read + Write> VirtioDevice for VirtioNet<T> {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_NET
    }
    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC
    }
    fn num_queues(&self) -> u16 {
        2 // RX (0) + TX (1)
    }
    fn queue_max_size(&self) -> u16 {
        256
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // `struct virtio_net_config { u8 mac[6]; le16 status; ... }` — expose the
        // MAC at offset 0; the rest reads as zero.
        for (i, b) in data.iter_mut().enumerate() {
            let pos = offset as usize + i;
            *b = self.mac.get(pos).copied().unwrap_or(0);
        }
    }
}

impl<T: Read + Write + Send> VirtioDeviceOps for VirtioNet<T> {
    /// A **TX** notify drains the queue to the tap and returns `true` so the
    /// manager flags the used ring + pulses the IRQ — the guest needs that
    /// completion to reclaim its transmitted buffers (without it the TX ring
    /// fills and transmission stalls). An **RX** notify only means the guest
    /// posted receive buffers; those are consumed by the tap RX poller via
    /// [`receive`](Self::receive), so nothing is serviced here.
    fn service(
        &mut self,
        queue_index: u16,
        queue: &mut Queue,
        mem: &GuestMemoryMmap,
    ) -> Result<bool, VmmError> {
        if queue_index == TX_QUEUE {
            self.transmit(queue, mem)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Deliver one inbound `frame` into an available **RX** chain (prefixed with a
    /// zero `virtio_net_hdr`). Returns `false` if the guest has posted no RX
    /// buffer (the caller drops or re-queues the frame).
    fn receive(
        &mut self,
        queue: &mut Queue,
        mem: &GuestMemoryMmap,
        frame: &[u8],
    ) -> Result<bool, VmmError> {
        let Some(chain) = queue.pop_descriptor_chain(mem) else {
            return Ok(false);
        };
        let head = chain.head_index();
        let written = write_frame_to_chain(chain, mem, frame);
        queue
            .add_used(mem, head, written)
            .map_err(|e| VmmError::Kvm(format!("net add_used: {e}")))?;
        Ok(true)
    }
}

/// Write `[virtio_net_hdr || frame]` across a chain's writable descriptors,
/// returning the number of bytes written (the used-ring `len`).
fn write_frame_to_chain(
    chain: DescriptorChain<&GuestMemoryMmap>,
    mem: &GuestMemoryMmap,
    frame: &[u8],
) -> u32 {
    let mut payload = vec![0u8; VIRTIO_NET_HDR_LEN];
    payload[NET_HDR_NUM_BUFFERS] = 1; // num_buffers = 1 (single-buffer frame)
    payload.extend_from_slice(frame);

    let mut written = 0u32;
    let mut pos = 0usize;
    for d in chain {
        if !d.is_write_only() || pos >= payload.len() {
            continue;
        }
        let n = (d.len() as usize).min(payload.len() - pos);
        if mem.write_slice(&payload[pos..pos + n], d.addr()).is_err() {
            break;
        }
        pos += n;
        written += n as u32;
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use virtio_queue::mock::MockSplitQueue;
    use virtio_queue::{Descriptor, Queue};
    use vm_memory::GuestAddress;

    /// An in-memory stand-in for the host tap (`Read + Write`).
    fn fake_tap() -> Cursor<Vec<u8>> {
        Cursor::new(Vec::new())
    }

    const F_WRITE: u16 = 0x2;
    const HDR_ADDR: u64 = 0x10_0000;
    const FRAME_ADDR: u64 = 0x10_1000;

    fn guest() -> GuestMemoryMmap {
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap()
    }

    #[test]
    fn config_exposes_the_mac_and_features() {
        let mac = [0x02, 0x00, 0x0a, 0x00, 0x00, 0x05];
        let dev = VirtioNet::new(mac, fake_tap());
        assert_eq!(dev.device_type(), VIRTIO_ID_NET);
        assert_eq!(dev.num_queues(), 2);
        assert_eq!(dev.features() & VIRTIO_NET_F_MAC, VIRTIO_NET_F_MAC);
        let mut cfg = [0u8; 6];
        dev.read_config(0, &mut cfg);
        assert_eq!(cfg, mac);
    }

    #[test]
    fn transmit_strips_the_header_and_sends_the_frame_to_the_tap() {
        let mem = guest();
        // Guest TX buffer: [12-byte virtio_net_hdr || frame].
        let frame = *b"hello-ethernet-frame";
        let hdr = [0u8; VIRTIO_NET_HDR_LEN];
        mem.write_slice(&hdr, GuestAddress(HDR_ADDR)).unwrap();
        mem.write_slice(&frame, GuestAddress(FRAME_ADDR)).unwrap();

        let vq = MockSplitQueue::new(&mem, 16);
        let chain = [
            Descriptor::new(HDR_ADDR, VIRTIO_NET_HDR_LEN as u32, 0, 0),
            Descriptor::new(FRAME_ADDR, frame.len() as u32, 0, 0),
        ];
        vq.build_desc_chain(&chain).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let mut dev = VirtioNet::new([0; 6], fake_tap());
        dev.transmit(&mut queue, &mem).unwrap();
        assert_eq!(
            dev.tap.get_ref().as_slice(),
            &frame[..],
            "the tap received exactly the frame, header stripped"
        );
    }

    #[test]
    fn receive_delivers_a_frame_with_a_header_into_the_rx_chain() {
        let mem = guest();
        let vq = MockSplitQueue::new(&mem, 16);
        // One writable RX buffer big enough for the header + frame.
        let chain = [Descriptor::new(FRAME_ADDR, 0x200, F_WRITE, 0)];
        vq.build_desc_chain(&chain).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let frame = *b"inbound-frame-payload";
        let mut dev = VirtioNet::new([0; 6], fake_tap());
        let delivered = dev.receive(&mut queue, &mem, &frame).unwrap();
        assert!(delivered);

        // Guest buffer = 12-byte header (num_buffers=1) then the frame.
        let mut out = [0u8; VIRTIO_NET_HDR_LEN + 21];
        mem.read_slice(&mut out, GuestAddress(FRAME_ADDR)).unwrap();
        assert_eq!(out[NET_HDR_NUM_BUFFERS], 1, "num_buffers = 1");
        assert_eq!(
            &out[VIRTIO_NET_HDR_LEN..],
            &frame,
            "frame follows the header"
        );

        // No RX buffer left → the next frame is not delivered.
        assert!(!dev.receive(&mut queue, &mem, &frame).unwrap());
    }
}
