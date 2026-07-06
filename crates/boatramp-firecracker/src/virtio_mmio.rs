//! The **virtio-MMIO transport** (modern, version 2) register layer for the
//! embedded VMM. This is the pure half: the
//! register map + the driver↔device negotiation state machine (magic/version/
//! device-id, feature negotiation, status, and per-virtqueue configuration),
//! driven by the guest's 32-bit MMIO reads/writes to a device window.
//!
//! It is generic over a [`VirtioDevice`] (the device type, offered features,
//! virtqueue count/size, and config space) so it's unit-tested cross-platform
//! with a fake device — no `/dev/kvm`. The guest-memory virtqueue descriptor
//! processing + the concrete block/net backends are handled separately; a
//! `QueueNotify` write surfaces the notified queue index for the VMM to service.
//!
//! Register offsets + semantics follow the virtio 1.x spec §4.2.2.

use serde::{Deserialize, Serialize};

/// `MagicValue` register content — ASCII `"virt"` little-endian.
pub const MAGIC_VALUE: u32 = 0x7472_6976;
/// `Version` register — `2` for the modern (non-legacy) MMIO transport.
pub const VERSION: u32 = 2;

// Register offsets within a device's MMIO window (virtio 1.x §4.2.2).
const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_VENDOR_ID: u64 = 0x00c;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_INTERRUPT_STATUS: u64 = 0x060;
const REG_INTERRUPT_ACK: u64 = 0x064;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_DESC_HIGH: u64 = 0x084;
const REG_QUEUE_DRIVER_LOW: u64 = 0x090;
const REG_QUEUE_DRIVER_HIGH: u64 = 0x094;
const REG_QUEUE_DEVICE_LOW: u64 = 0x0a0;
const REG_QUEUE_DEVICE_HIGH: u64 = 0x0a4;
const REG_CONFIG_GENERATION: u64 = 0x0fc;
/// Device-specific config space starts here.
pub const CONFIG_SPACE_OFFSET: u64 = 0x100;

/// The `VendorID` boatramp's devices report (`"brmp"` little-endian).
pub const VENDOR_ID: u32 = 0x706d_7262;

/// A virtio device the transport fronts: its type, offered features, virtqueue
/// shape, and config space. The transport handles the register protocol; the
/// device supplies these facts and (later) services queue notifications.
pub trait VirtioDevice {
    /// The virtio device type id (e.g. 2 = block, 1 = net, 3 = console).
    fn device_type(&self) -> u32;
    /// The 64-bit device feature bits offered to the driver.
    fn features(&self) -> u64;
    /// Number of virtqueues this device exposes.
    fn num_queues(&self) -> u16;
    /// Maximum size (entries) of each virtqueue.
    fn queue_max_size(&self) -> u16;
    /// Read `data.len()` bytes of device-specific config at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);
}

/// The guest-programmed configuration of one virtqueue (latched via the MMIO
/// registers; consumed by the VMM when the queue is notified).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueConfig {
    /// Negotiated queue size (entries).
    pub size: u16,
    /// Whether the driver has marked the queue ready.
    pub ready: bool,
    /// Guest physical address of the descriptor table.
    pub desc: u64,
    /// Guest physical address of the available (driver) ring.
    pub avail: u64,
    /// Guest physical address of the used (device) ring.
    pub used: u64,
}

/// The modern virtio-MMIO transport state for one device.
pub struct MmioTransport<D> {
    device: D,
    status: u32,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    queues: Vec<QueueConfig>,
    interrupt_status: u32,
}

/// The host-side transport register state of one device — everything the guest
/// programmed via the MMIO registers (status, negotiated features, per-queue
/// config). It is **not** reconstructable from guest RAM, so a snapshot/restore
/// (scale-to-zero) must carry it across the teardown; the wrapped device
/// itself is rebuilt from its launch config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmioState {
    pub status: u32,
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,
    pub queue_sel: u32,
    pub interrupt_status: u32,
    pub queues: Vec<QueueConfig>,
}

impl<D: VirtioDevice> MmioTransport<D> {
    /// Wrap `device`, sizing the per-queue config table to its queue count.
    pub fn new(device: D) -> Self {
        let n = device.num_queues() as usize;
        Self {
            device,
            status: 0,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: vec![QueueConfig::default(); n],
            interrupt_status: 0,
        }
    }

    /// The negotiated driver feature bits.
    pub fn driver_features(&self) -> u64 {
        self.driver_features
    }

    /// Capture the host-side register state for a snapshot. The wrapped
    /// device is rebuilt separately (from its launch config), so it isn't here.
    pub fn save_state(&self) -> MmioState {
        MmioState {
            status: self.status,
            device_features_sel: self.device_features_sel,
            driver_features: self.driver_features,
            driver_features_sel: self.driver_features_sel,
            queue_sel: self.queue_sel,
            interrupt_status: self.interrupt_status,
            queues: self.queues.clone(),
        }
    }

    /// Restore the host-side register state captured by [`save_state`](Self::save_state)
    /// onto a freshly wrapped device. The queue-config vector keeps its
    /// device-sized length (a malformed snapshot can't grow/shrink it).
    pub fn restore_state(&mut self, state: &MmioState) {
        self.status = state.status;
        self.device_features_sel = state.device_features_sel;
        self.driver_features = state.driver_features;
        self.driver_features_sel = state.driver_features_sel;
        self.queue_sel = state.queue_sel;
        self.interrupt_status = state.interrupt_status;
        for (slot, saved) in self.queues.iter_mut().zip(state.queues.iter()) {
            *slot = *saved;
        }
    }

    /// The device's per-queue configuration (as programmed by the driver).
    pub fn queues(&self) -> &[QueueConfig] {
        &self.queues
    }

    /// The wrapped device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Mutable access to the wrapped device (the device manager services its
    /// queues through this on a `QueueNotify`).
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Flag a used-buffer notification in `InterruptStatus` (`VIRTIO_MMIO_INT_VRING`,
    /// bit 0). The VMM sets this — and pulses the device IRQ — after a queue
    /// advances its used ring; the guest's ISR reads it, services the ring, then
    /// clears it via `InterruptACK`.
    pub fn signal_used_ring(&mut self) {
        self.interrupt_status |= 0x1;
    }

    /// Handle a guest read of the register at `offset`, writing the little-endian
    /// result into `data` (control registers are 32-bit; config space is byte-
    /// addressable and delegated to the device).
    pub fn read(&self, offset: u64, data: &mut [u8]) {
        if offset >= CONFIG_SPACE_OFFSET {
            self.device.read_config(offset - CONFIG_SPACE_OFFSET, data);
            return;
        }
        let q = self.selected_queue();
        let val: u32 = match offset {
            REG_MAGIC => MAGIC_VALUE,
            REG_VERSION => VERSION,
            REG_DEVICE_ID => self.device.device_type(),
            REG_VENDOR_ID => VENDOR_ID,
            REG_DEVICE_FEATURES => {
                let f = self.device.features();
                if self.device_features_sel == 0 {
                    f as u32
                } else {
                    (f >> 32) as u32
                }
            }
            REG_QUEUE_NUM_MAX => u32::from(self.device.queue_max_size()),
            REG_QUEUE_READY => u32::from(q.map(|c| c.ready).unwrap_or(false)),
            REG_INTERRUPT_STATUS => self.interrupt_status,
            REG_STATUS => self.status,
            REG_CONFIG_GENERATION => 0,
            _ => 0,
        };
        write_le(data, val);
    }

    /// Handle a guest write of `data` to the register at `offset`. Returns
    /// `Some(queue_index)` when it is a `QueueNotify` (the VMM should service that
    /// queue), else `None`.
    pub fn write(&mut self, offset: u64, data: &[u8]) -> Option<u16> {
        if offset >= CONFIG_SPACE_OFFSET {
            return None; // device config is read-only through this transport
        }
        let val = read_le(data);
        match offset {
            REG_DEVICE_FEATURES_SEL => self.device_features_sel = val,
            REG_DRIVER_FEATURES_SEL => self.driver_features_sel = val,
            REG_DRIVER_FEATURES => {
                let shift = if self.driver_features_sel == 0 { 0 } else { 32 };
                let mask = 0xffff_ffffu64 << shift;
                self.driver_features = (self.driver_features & !mask) | (u64::from(val) << shift);
            }
            REG_QUEUE_SEL => self.queue_sel = val,
            REG_QUEUE_NUM => self.with_queue(|q| q.size = val as u16),
            REG_QUEUE_READY => self.with_queue(|q| q.ready = val & 1 == 1),
            REG_QUEUE_DESC_LOW => self.with_queue(|q| q.desc = set_low(q.desc, val)),
            REG_QUEUE_DESC_HIGH => self.with_queue(|q| q.desc = set_high(q.desc, val)),
            REG_QUEUE_DRIVER_LOW => self.with_queue(|q| q.avail = set_low(q.avail, val)),
            REG_QUEUE_DRIVER_HIGH => self.with_queue(|q| q.avail = set_high(q.avail, val)),
            REG_QUEUE_DEVICE_LOW => self.with_queue(|q| q.used = set_low(q.used, val)),
            REG_QUEUE_DEVICE_HIGH => self.with_queue(|q| q.used = set_high(q.used, val)),
            REG_INTERRUPT_ACK => self.interrupt_status &= !val,
            REG_STATUS => {
                // Writing 0 resets the device.
                self.status = val;
                if val == 0 {
                    self.reset();
                }
            }
            REG_QUEUE_NOTIFY => return u16::try_from(val).ok(),
            _ => {}
        }
        None
    }

    fn selected_queue(&self) -> Option<&QueueConfig> {
        self.queues.get(self.queue_sel as usize)
    }

    fn with_queue(&mut self, f: impl FnOnce(&mut QueueConfig)) {
        if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
            f(q);
        }
    }

    fn reset(&mut self) {
        self.device_features_sel = 0;
        self.driver_features = 0;
        self.driver_features_sel = 0;
        self.queue_sel = 0;
        self.interrupt_status = 0;
        for q in &mut self.queues {
            *q = QueueConfig::default();
        }
    }
}

/// Replace the low 32 bits of a 64-bit address.
fn set_low(addr: u64, low: u32) -> u64 {
    (addr & 0xffff_ffff_0000_0000) | u64::from(low)
}
/// Replace the high 32 bits of a 64-bit address.
fn set_high(addr: u64, high: u32) -> u64 {
    (addr & 0x0000_0000_ffff_ffff) | (u64::from(high) << 32)
}
/// Write `val` little-endian into the first 4 bytes of `data` (shorter accesses
/// take the low bytes).
fn write_le(data: &mut [u8], val: u32) {
    let bytes = val.to_le_bytes();
    let n = data.len().min(4);
    data[..n].copy_from_slice(&bytes[..n]);
}
/// Read a little-endian u32 from the first up-to-4 bytes of `data`.
fn read_le(data: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = data.len().min(4);
    buf[..n].copy_from_slice(&data[..n]);
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake block-like device: type 2, a couple of feature bits, one queue.
    struct FakeDevice;
    impl VirtioDevice for FakeDevice {
        fn device_type(&self) -> u32 {
            2
        }
        fn features(&self) -> u64 {
            (1 << 0) | (1 << 34) // a low bit + a high (VIRTIO_F_VERSION_1-ish) bit
        }
        fn num_queues(&self) -> u16 {
            1
        }
        fn queue_max_size(&self) -> u16 {
            256
        }
        fn read_config(&self, offset: u64, data: &mut [u8]) {
            // Expose a recognizable config: byte i = offset + i.
            for (i, b) in data.iter_mut().enumerate() {
                *b = (offset as u8).wrapping_add(i as u8);
            }
        }
    }

    fn transport() -> MmioTransport<FakeDevice> {
        MmioTransport::new(FakeDevice)
    }

    fn read32(t: &MmioTransport<FakeDevice>, off: u64) -> u32 {
        let mut d = [0u8; 4];
        t.read(off, &mut d);
        u32::from_le_bytes(d)
    }
    fn write32(t: &mut MmioTransport<FakeDevice>, off: u64, val: u32) -> Option<u16> {
        t.write(off, &val.to_le_bytes())
    }

    #[test]
    fn transport_state_round_trips_for_snapshot() {
        // Program a transport the way a guest driver would: negotiate features,
        // configure + ready queue 0, set DRIVER_OK.
        let mut t = transport();
        write32(&mut t, REG_DRIVER_FEATURES_SEL, 1);
        write32(&mut t, REG_DRIVER_FEATURES, 1 << 2); // high word bit 2 → feature 34
        write32(&mut t, REG_DRIVER_FEATURES_SEL, 0);
        write32(&mut t, REG_DRIVER_FEATURES, 0x1);
        write32(&mut t, REG_QUEUE_SEL, 0);
        write32(&mut t, REG_QUEUE_NUM, 64);
        write32(&mut t, REG_QUEUE_DESC_LOW, 0x1000);
        write32(&mut t, REG_QUEUE_DRIVER_LOW, 0x2000);
        write32(&mut t, REG_QUEUE_DEVICE_LOW, 0x3000);
        write32(&mut t, REG_QUEUE_READY, 1);
        write32(&mut t, REG_STATUS, 0xf); // ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK

        let state = t.save_state();
        // Serialize through JSON too, mirroring the cross-process snapshot path.
        let json = serde_json::to_string(&state).expect("serialize");
        let state2: MmioState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, state2);

        // A fresh transport restored from the state reads back identically.
        let mut restored = transport();
        restored.restore_state(&state2);
        assert_eq!(read32(&restored, REG_STATUS), 0xf);
        assert_eq!(restored.driver_features(), 0x1 | (1 << 34));
        let q = restored.queues()[0];
        assert_eq!(q.size, 64);
        assert!(q.ready);
        assert_eq!(q.desc, 0x1000);
        assert_eq!(q.avail, 0x2000);
        assert_eq!(q.used, 0x3000);
    }

    #[test]
    fn identity_registers_match_the_spec() {
        let t = transport();
        assert_eq!(read32(&t, REG_MAGIC), MAGIC_VALUE);
        assert_eq!(read32(&t, REG_VERSION), 2);
        assert_eq!(read32(&t, REG_DEVICE_ID), 2);
        assert_eq!(read32(&t, REG_VENDOR_ID), VENDOR_ID);
        assert_eq!(read32(&t, REG_QUEUE_NUM_MAX), 256);
    }

    #[test]
    fn device_features_are_paged_by_the_selector() {
        let mut t = transport();
        // Selector 0 → low 32 bits, selector 1 → high 32 bits.
        assert_eq!(read32(&t, REG_DEVICE_FEATURES), 1);
        write32(&mut t, REG_DEVICE_FEATURES_SEL, 1);
        assert_eq!(
            read32(&t, REG_DEVICE_FEATURES),
            1 << 2,
            "bit 34 → high word bit 2"
        );
    }

    #[test]
    fn driver_features_are_assembled_from_both_words() {
        let mut t = transport();
        write32(&mut t, REG_DRIVER_FEATURES_SEL, 0);
        write32(&mut t, REG_DRIVER_FEATURES, 0xaaaa_5555);
        write32(&mut t, REG_DRIVER_FEATURES_SEL, 1);
        write32(&mut t, REG_DRIVER_FEATURES, 0x0000_0003);
        assert_eq!(t.driver_features(), 0x0000_0003_aaaa_5555);
    }

    #[test]
    fn status_is_read_write_and_zero_resets() {
        let mut t = transport();
        write32(&mut t, REG_STATUS, 0x0f);
        assert_eq!(read32(&t, REG_STATUS), 0x0f);
        // Program a queue, then reset via Status=0.
        write32(&mut t, REG_QUEUE_NUM, 64);
        write32(&mut t, REG_QUEUE_READY, 1);
        write32(&mut t, REG_STATUS, 0);
        assert_eq!(read32(&t, REG_STATUS), 0);
        assert_eq!(t.queues()[0], QueueConfig::default(), "reset clears queues");
    }

    #[test]
    fn queue_configuration_latches_the_addresses() {
        let mut t = transport();
        write32(&mut t, REG_QUEUE_SEL, 0);
        write32(&mut t, REG_QUEUE_NUM, 128);
        write32(&mut t, REG_QUEUE_DESC_LOW, 0x1000);
        write32(&mut t, REG_QUEUE_DESC_HIGH, 0x1);
        write32(&mut t, REG_QUEUE_DRIVER_LOW, 0x2000);
        write32(&mut t, REG_QUEUE_DEVICE_LOW, 0x3000);
        write32(&mut t, REG_QUEUE_READY, 1);
        let q = t.queues()[0];
        assert_eq!(q.size, 128);
        assert!(q.ready);
        assert_eq!(q.desc, 0x1_0000_1000, "desc low+high combine");
        assert_eq!(q.avail, 0x2000);
        assert_eq!(q.used, 0x3000);
        assert_eq!(read32(&t, REG_QUEUE_READY), 1);
    }

    #[test]
    fn queue_notify_surfaces_the_queue_index() {
        let mut t = transport();
        assert_eq!(write32(&mut t, REG_QUEUE_NOTIFY, 0), Some(0));
        assert_eq!(write32(&mut t, REG_QUEUE_NOTIFY, 3), Some(3));
        // A non-notify write returns None.
        assert_eq!(write32(&mut t, REG_STATUS, 1), None);
    }

    #[test]
    fn interrupt_ack_clears_status_bits() {
        let mut t = transport();
        t.interrupt_status = 0b11;
        write32(&mut t, REG_INTERRUPT_ACK, 0b01);
        assert_eq!(read32(&t, REG_INTERRUPT_STATUS), 0b10);
    }

    #[test]
    fn config_space_is_delegated_to_the_device() {
        let t = transport();
        let mut d = [0u8; 4];
        t.read(CONFIG_SPACE_OFFSET + 8, &mut d);
        assert_eq!(d, [8, 9, 10, 11], "device config offset 8, bytes 8..12");
    }
}
