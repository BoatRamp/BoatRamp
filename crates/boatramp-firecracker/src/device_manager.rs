//! The embedded VMM's **MMIO device manager**: the
//! bus that the vCPU run loop hands its `MmioRead`/`MmioWrite` exits to. It owns
//! the per-device [`MmioTransport`]s + their virtqueues, routes a guest MMIO
//! address to the device whose window contains it ([`route_mmio`]), drives the
//! register protocol, and on a `QueueNotify` services the device's queue and
//! reports the IRQ to raise.
//!
//! The routing + notify → service → IRQ dispatch is unit-tested with a mock
//! device (no `/dev/kvm`); wiring it into the live run loop (calling
//! [`EmbeddedVmm::set_irq`](crate::embedded_vmm::EmbeddedVmm::set_irq) on the
//! returned GSI) + the tap RX poll + vCPU threading is the `compute-live` seam.

use serde::{Deserialize, Serialize};
use virtio_queue::{Queue, QueueT};
use vm_memory::GuestMemoryMmap;

use crate::embedded::{allocate_mmio, route_mmio, MmioDevice};
use crate::embedded_vmm::{build_queue, VmmError};
use crate::virtio_mmio::{MmioState, MmioTransport, QueueConfig, VirtioDevice};

/// The full host-side state of one device for a snapshot (scale-to-zero):
/// the transport registers plus, per virtqueue, the live ring **cursors**
/// (`next_avail`/`next_used`) if the queue has been built. The cursors are the
/// crucial bit — a fresh restore would reset them to 0 and re-pop already-consumed
/// descriptors, corrupting an active queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceState {
    /// Transport registers (status, features, per-queue config).
    pub mmio: MmioState,
    /// Per virtqueue: `Some((next_avail, next_used))` if it was live, else `None`.
    pub cursors: Vec<Option<(u16, u16)>>,
}

/// A virtio device the manager can drive: the register-level [`VirtioDevice`]
/// facts plus the device-specific servicing of a notified queue. The block/net
/// backends implement this (each owning its backing store / tap).
///
/// `Send` so the manager (held behind an `Arc<Mutex<…>>`) can be shared with the
/// virtio-net RX poll thread.
pub trait VirtioDeviceOps: VirtioDevice + Send {
    /// Service the just-notified `queue_index` against `queue` + guest memory;
    /// return whether the used ring advanced (so the manager raises the IRQ).
    fn service(
        &mut self,
        queue_index: u16,
        queue: &mut Queue,
        mem: &GuestMemoryMmap,
    ) -> Result<bool, VmmError>;

    /// Deliver one inbound `frame` into the device's RX queue (virtio-net only;
    /// the default — for devices that never receive, like block — drops it).
    /// Returns whether a used buffer was produced (so the manager raises the IRQ).
    fn receive(
        &mut self,
        _queue: &mut Queue,
        _mem: &GuestMemoryMmap,
        _frame: &[u8],
    ) -> Result<bool, VmmError> {
        Ok(false)
    }
}

// A boxed device is itself a `VirtioDevice` (forward the register facts), so the
// manager can hold heterogeneous devices as `Box<dyn VirtioDeviceOps>`.
impl VirtioDevice for Box<dyn VirtioDeviceOps> {
    fn device_type(&self) -> u32 {
        (**self).device_type()
    }
    fn features(&self) -> u64 {
        (**self).features()
    }
    fn num_queues(&self) -> u16 {
        (**self).num_queues()
    }
    fn queue_max_size(&self) -> u16 {
        (**self).queue_max_size()
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        (**self).read_config(offset, data);
    }
}

/// One device on the bus: its MMIO window, the transport driving its registers,
/// and the rust-vmm `Queue`s. Each queue is built **once** (from the transport's
/// latched [`QueueConfig`]) and then reused — keyed on that config so a driver
/// reset/reconfigure rebuilds it, but a steady stream of notifies keeps the same
/// `Queue` (preserving its `next_avail` cursor; rebuilding per-notify would reset
/// it and re-pop already-consumed descriptors).
struct Slot {
    window: MmioDevice,
    transport: MmioTransport<Box<dyn VirtioDeviceOps>>,
    queues: Vec<Option<(QueueConfig, Queue)>>,
}

impl Slot {
    /// Ensure queue `qpos`'s [`Queue`] is built from the transport's current
    /// latched config, (re)building only when absent or the config changed.
    /// Returns a mutable reference to the live queue, or `None` if `qpos` is out
    /// of range.
    fn ensure_queue(&mut self, qpos: usize) -> Result<Option<&mut Queue>, VmmError> {
        if qpos >= self.queues.len() {
            return Ok(None);
        }
        let cfg = self.transport.queues()[qpos];
        let stale = self.queues[qpos].as_ref().map(|(c, _)| *c) != Some(cfg);
        if stale {
            let max_size = self.transport.device().queue_max_size();
            self.queues[qpos] = Some((cfg, build_queue(&cfg, max_size)?));
        }
        Ok(self.queues[qpos].as_mut().map(|(_, q)| q))
    }
}

/// The virtio-MMIO device bus for one VM.
pub struct DeviceManager {
    slots: Vec<Slot>,
    windows: Vec<MmioDevice>,
}

impl DeviceManager {
    /// Place `devices` on consecutive virtio-MMIO windows (via [`allocate_mmio`]).
    pub fn new(devices: Vec<Box<dyn VirtioDeviceOps>>) -> Result<Self, VmmError> {
        let windows =
            allocate_mmio(devices.len()).map_err(|e| VmmError::Kvm(format!("mmio alloc: {e}")))?;
        let slots = devices
            .into_iter()
            .zip(windows.iter().copied())
            .map(|(d, window)| {
                let nqueues = d.num_queues() as usize;
                Slot {
                    window,
                    transport: MmioTransport::new(d),
                    // `Queue` isn't `Clone`, so build the Vec without `vec![None; n]`.
                    queues: (0..nqueues).map(|_| None).collect(),
                }
            })
            .collect();
        Ok(Self { slots, windows })
    }

    /// The MMIO windows (for building the kernel cmdline `virtio_mmio.device=…`
    /// fragments via [`crate::embedded::mmio_cmdline_arg`]).
    pub fn windows(&self) -> &[MmioDevice] {
        &self.windows
    }

    /// Capture every device's host-side state (transport registers + live queue
    /// cursors) for a snapshot. The device backends themselves are rebuilt
    /// from their launch config on restore — only this guest-invisible state needs
    /// to survive the teardown. Order matches [`new`](Self::new)'s device order.
    pub fn save_device_states(&self) -> Vec<DeviceState> {
        self.slots
            .iter()
            .map(|slot| DeviceState {
                mmio: slot.transport.save_state(),
                cursors: slot
                    .queues
                    .iter()
                    .map(|q| q.as_ref().map(|(_, q)| (q.next_avail(), q.next_used())))
                    .collect(),
            })
            .collect()
    }

    /// Restore device state captured by [`save_device_states`](Self::save_device_states)
    /// onto a freshly built manager (same device order/count). Re-latches the
    /// transport registers, then pre-builds each live queue from its restored
    /// config and re-seats its `next_avail`/`next_used` cursors so the resumed
    /// guest and the host agree on ring progress.
    pub fn restore_device_states(&mut self, states: &[DeviceState]) -> Result<(), VmmError> {
        if states.len() != self.slots.len() {
            return Err(VmmError::Kvm(format!(
                "device state count {} != {} devices",
                states.len(),
                self.slots.len()
            )));
        }
        for (slot, state) in self.slots.iter_mut().zip(states.iter()) {
            slot.transport.restore_state(&state.mmio);
            let max_size = slot.transport.device().queue_max_size();
            for (qpos, cursor) in state.cursors.iter().enumerate() {
                let Some((next_avail, next_used)) = *cursor else {
                    continue; // queue was never built — restored lazily on first notify
                };
                let Some(slot_q) = slot.queues.get_mut(qpos) else {
                    continue;
                };
                let cfg = slot.transport.queues()[qpos];
                let mut queue = build_queue(&cfg, max_size)?;
                queue.set_next_avail(next_avail);
                queue.set_next_used(next_used);
                *slot_q = Some((cfg, queue));
            }
        }
        Ok(())
    }

    /// Handle a guest MMIO **read** at `addr` (a control register or device
    /// config); fills `data` (zero if the address hits no device window).
    pub fn mmio_read(&self, addr: u64, data: &mut [u8]) {
        if let Some((i, offset)) = route_mmio(&self.windows, addr) {
            self.slots[i].transport.read(offset, data);
        } else {
            data.iter_mut().for_each(|b| *b = 0);
        }
    }

    /// Handle a guest MMIO **write** at `addr`. On a `QueueNotify` that advances
    /// the device's used ring, returns the device's GSI for the caller to raise
    /// (`EmbeddedVmm::set_irq`); otherwise `None`.
    pub fn mmio_write(
        &mut self,
        addr: u64,
        data: &[u8],
        mem: &GuestMemoryMmap,
    ) -> Result<Option<u32>, VmmError> {
        let Some((i, offset)) = route_mmio(&self.windows, addr) else {
            return Ok(None);
        };
        let slot = &mut self.slots[i];
        let Some(qidx) = slot.transport.write(offset, data) else {
            return Ok(None);
        };
        let qpos = qidx as usize;
        // Build the queue once (keyed on the latched config), then service it.
        // `service` borrows the queue + the device; split them via raw pieces so
        // both borrows are live at once.
        if slot.ensure_queue(qpos)?.is_none() {
            return Ok(None);
        }
        let (_, queue) = slot.queues[qpos].as_mut().expect("ensured");
        let raised = slot.transport.device_mut().service(qidx, queue, mem)?;
        if raised {
            // Flag the used-ring notification so the guest's ISR finds it set,
            // then tell the caller to pulse the device IRQ line.
            slot.transport.signal_used_ring();
        }
        Ok(raised.then_some(slot.window.irq))
    }

    /// Deliver one inbound `frame` to the device at `index` (its virtio-net RX
    /// queue = queue 0): build/reuse the RX queue and hand the frame to the
    /// device. Returns `Some(gsi)` to pulse when a used buffer was produced (a
    /// guest RX buffer was filled), else `None` (no posted buffer / not a
    /// receiving device / unconfigured RX queue). Called from the tap RX poller.
    pub fn deliver_rx(
        &mut self,
        index: usize,
        frame: &[u8],
        mem: &GuestMemoryMmap,
    ) -> Result<Option<u32>, VmmError> {
        /// virtio-net RX is queue 0 (device → guest).
        const RX_QUEUE: usize = 0;
        let Some(slot) = self.slots.get_mut(index) else {
            return Ok(None);
        };
        // The guest must have posted RX buffers (marked the queue ready) first.
        if !slot
            .transport
            .queues()
            .get(RX_QUEUE)
            .is_some_and(|c| c.ready)
        {
            return Ok(None);
        }
        // Build/reuse the RX queue, then drop that borrow before splitting the
        // queue + device field borrows for `receive`.
        if slot.ensure_queue(RX_QUEUE)?.is_none() {
            return Ok(None);
        }
        let (_, queue) = slot.queues[RX_QUEUE].as_mut().expect("ensured");
        let delivered = slot.transport.device_mut().receive(queue, mem, frame)?;
        if delivered {
            slot.transport.signal_used_ring();
        }
        Ok(delivered.then_some(slot.window.irq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_mmio::{CONFIG_SPACE_OFFSET, MAGIC_VALUE};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use vm_memory::GuestAddress;

    // A fake device recording how many times each queue was serviced.
    struct MockDev {
        serviced: Arc<AtomicU32>,
    }
    impl VirtioDevice for MockDev {
        fn device_type(&self) -> u32 {
            0xabcd
        }
        fn features(&self) -> u64 {
            0
        }
        fn num_queues(&self) -> u16 {
            1
        }
        fn queue_max_size(&self) -> u16 {
            64
        }
        fn read_config(&self, _: u64, data: &mut [u8]) {
            data.iter_mut().for_each(|b| *b = 0x5a);
        }
    }
    impl VirtioDeviceOps for MockDev {
        fn service(
            &mut self,
            _queue_index: u16,
            _queue: &mut Queue,
            _mem: &GuestMemoryMmap,
        ) -> Result<bool, VmmError> {
            self.serviced.fetch_add(1, Ordering::SeqCst);
            Ok(true) // pretend the used ring advanced → raise the IRQ
        }
    }

    fn read32(mgr: &DeviceManager, addr: u64) -> u32 {
        let mut d = [0u8; 4];
        mgr.mmio_read(addr, &mut d);
        u32::from_le_bytes(d)
    }

    #[test]
    fn routes_reads_and_services_notifies_with_the_right_irq() {
        let serviced = Arc::new(AtomicU32::new(0));
        let dev = MockDev {
            serviced: serviced.clone(),
        };
        let mgr_dev: Box<dyn VirtioDeviceOps> = Box::new(dev);
        let mut mgr = DeviceManager::new(vec![mgr_dev]).unwrap();
        let win = mgr.windows()[0];
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // A read of the magic register at the device's window base routes through.
        assert_eq!(read32(&mgr, win.addr), MAGIC_VALUE);
        // Device config (offset 0x100) is delegated to the device.
        let mut cfg = [0u8; 2];
        mgr.mmio_read(win.addr + CONFIG_SPACE_OFFSET, &mut cfg);
        assert_eq!(cfg, [0x5a, 0x5a]);

        // A QueueNotify (register 0x050) of queue 0 → service it + raise the IRQ.
        let raised = mgr
            .mmio_write(win.addr + 0x050, &0u32.to_le_bytes(), &mem)
            .unwrap();
        assert_eq!(raised, Some(win.irq), "notify raises the device's GSI");
        assert_eq!(serviced.load(Ordering::SeqCst), 1);

        // An address outside any window is a no-op (read zeros, write → None).
        assert_eq!(read32(&mgr, win.addr - 1), 0);
        assert_eq!(
            mgr.mmio_write(win.addr - 1, &0u32.to_le_bytes(), &mem)
                .unwrap(),
            None
        );
    }

    #[test]
    fn device_state_captures_and_restores_transport_and_cursors() {
        let serviced = Arc::new(AtomicU32::new(0));
        let dev: Box<dyn VirtioDeviceOps> = Box::new(MockDev {
            serviced: serviced.clone(),
        });
        let mut mgr = DeviceManager::new(vec![dev]).unwrap();
        let win = mgr.windows()[0];
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let write32 = |mgr: &mut DeviceManager, off: u64, val: u32| {
            mgr.mmio_write(win.addr + off, &val.to_le_bytes(), &mem)
                .unwrap()
        };

        // Configure + ready queue 0 the way a driver does, then notify it so the
        // manager builds a live Queue (giving the queue a cursor to capture).
        write32(&mut mgr, 0x030, 0); // QueueSel = 0
        write32(&mut mgr, 0x038, 32); // QueueNum
        write32(&mut mgr, 0x080, 0x100); // QueueDescLow
        write32(&mut mgr, 0x090, 0x200); // QueueDriverLow (avail)
        write32(&mut mgr, 0x0a0, 0x300); // QueueDeviceLow (used)
        write32(&mut mgr, 0x044, 1); // QueueReady
        write32(&mut mgr, 0x070, 0xf); // Status = DRIVER_OK
        write32(&mut mgr, 0x050, 0); // QueueNotify → builds + services queue 0
        assert_eq!(serviced.load(Ordering::SeqCst), 1);

        let states = mgr.save_device_states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].mmio.status, 0xf);
        assert_eq!(states[0].mmio.queues[0].size, 32);
        assert!(states[0].mmio.queues[0].ready);
        assert_eq!(
            states[0].cursors[0],
            Some((0, 0)),
            "the notified queue is live with cursors at 0"
        );

        // Restore onto a fresh manager; saving it again yields identical state.
        let dev2: Box<dyn VirtioDeviceOps> = Box::new(MockDev {
            serviced: Arc::new(AtomicU32::new(0)),
        });
        let mut mgr2 = DeviceManager::new(vec![dev2]).unwrap();
        mgr2.restore_device_states(&states).expect("restore");
        assert_eq!(mgr2.save_device_states(), states, "restore round-trips");

        // Wrong device count is rejected.
        assert!(mgr2.restore_device_states(&[]).is_err());
    }
}
