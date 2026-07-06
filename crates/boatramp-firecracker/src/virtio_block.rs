//! A **virtio-block** device backend for the embedded VMM: the guest's
//! root/scratch disk. It implements [`VirtioDevice`] (type 2,
//! a capacity config) and services its request queue by parsing each virtio-blk
//! request chain — a 16-byte header (type + sector), one or more data buffers,
//! and a 1-byte status — and performing the read/write against a seekable backing
//! store, writing the status byte and placing the chain on the used ring.
//!
//! Generic over the backing (`Read + Write + Seek`) so the request handling is
//! unit-tested with an in-memory `Cursor` + a `MockSplitQueue` ring (no
//! `/dev/kvm`); production uses a `std::fs::File`. The live wiring into the VMM's
//! MMIO exits is the `compute-live` seam.

use std::io::{Read, Seek, SeekFrom, Write};

use virtio_queue::{DescriptorChain, Queue};
use vm_memory::{Bytes, GuestMemoryMmap};

use crate::device_manager::VirtioDeviceOps;
use crate::embedded_vmm::{drain_available, VmmError};
use crate::virtio_mmio::VirtioDevice;

/// virtio device type id for a block device.
pub const VIRTIO_ID_BLOCK: u32 = 2;
/// `VIRTIO_F_VERSION_1` — modern (1.x) device. Bit 32.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// Logical block (sector) size the virtio-blk protocol addresses in.
pub const SECTOR_SIZE: u64 = 512;

// Request types (the header's `type` field).
const VIRTIO_BLK_T_IN: u32 = 0; // read from device → guest
const VIRTIO_BLK_T_OUT: u32 = 1; // write guest → device
const VIRTIO_BLK_T_FLUSH: u32 = 4;

// Status byte values (written to the request's status descriptor).
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Size of the request header (`type` u32 + `reserved` u32 + `sector` u64).
const HEADER_LEN: usize = 16;

/// A virtio-block device over a seekable `backing` store of `capacity_sectors`
/// 512-byte sectors.
pub struct VirtioBlock<B> {
    backing: B,
    capacity_sectors: u64,
    read_only: bool,
}

impl<B: Read + Write + Seek> VirtioBlock<B> {
    /// Wrap `backing` (its length in 512-byte sectors is `capacity_sectors`).
    pub fn new(backing: B, capacity_sectors: u64, read_only: bool) -> Self {
        Self {
            backing,
            capacity_sectors,
            read_only,
        }
    }

    /// Service every available request on `queue` against guest memory `mem`:
    /// parse each chain, do the I/O, write the status byte, and complete it on the
    /// used ring. Called when the driver notifies the queue.
    pub fn process(&mut self, queue: &mut Queue, mem: &GuestMemoryMmap) -> Result<(), VmmError> {
        let backing = &mut self.backing;
        let read_only = self.read_only;
        drain_available(queue, mem, |chain| {
            service_request(chain, mem, backing, read_only)
        })
    }
}

impl<B: Read + Write + Seek> VirtioDevice for VirtioBlock<B> {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_BLOCK
    }
    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }
    fn num_queues(&self) -> u16 {
        1
    }
    fn queue_max_size(&self) -> u16 {
        256
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // `struct virtio_blk_config { le64 capacity; ... }` — only capacity (the
        // disk size in 512-byte sectors) is meaningful here; the rest is zero.
        let cap = self.capacity_sectors.to_le_bytes();
        for (i, b) in data.iter_mut().enumerate() {
            let pos = offset as usize + i;
            *b = cap.get(pos).copied().unwrap_or(0);
        }
    }
}

impl<B: Read + Write + Seek + Send> VirtioDeviceOps for VirtioBlock<B> {
    /// The block device has a single request queue (index 0); servicing it drains
    /// every available request. Returns `true` so the manager raises the IRQ (a
    /// driver tolerates a spurious one — it re-checks the used ring).
    fn service(
        &mut self,
        _queue_index: u16,
        queue: &mut Queue,
        mem: &GuestMemoryMmap,
    ) -> Result<bool, VmmError> {
        self.process(queue, mem)?;
        Ok(true)
    }
}

/// Service one virtio-blk request chain; returns the number of bytes written into
/// the guest's writable descriptors (the used-ring `len`). Any malformed chain or
/// I/O error is reported via the status byte (and a zero/short length).
fn service_request<B: Read + Write + Seek>(
    chain: DescriptorChain<&GuestMemoryMmap>,
    mem: &GuestMemoryMmap,
    backing: &mut B,
    read_only: bool,
) -> u32 {
    let descs: Vec<_> = chain.collect();
    // Need at least a header + a status descriptor.
    if descs.len() < 2 {
        return 0;
    }
    let header = &descs[0];
    let status = &descs[descs.len() - 1];
    let data = &descs[1..descs.len() - 1];

    // Parse the request header.
    let mut hdr = [0u8; HEADER_LEN];
    if header.len() < HEADER_LEN as u32 || mem.read_slice(&mut hdr, header.addr()).is_err() {
        return write_status(mem, status, VIRTIO_BLK_S_IOERR);
    }
    let req_type = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let sector = u64::from_le_bytes([
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
    ]);

    let (status_byte, written) = match req_type {
        VIRTIO_BLK_T_IN => read_into_guest(mem, data, backing, sector),
        VIRTIO_BLK_T_OUT if read_only => (VIRTIO_BLK_S_IOERR, 0),
        VIRTIO_BLK_T_OUT => write_from_guest(mem, data, backing, sector),
        VIRTIO_BLK_T_FLUSH => (
            if backing.flush().is_ok() {
                VIRTIO_BLK_S_OK
            } else {
                VIRTIO_BLK_S_IOERR
            },
            0,
        ),
        _ => (VIRTIO_BLK_S_UNSUPP, 0),
    };
    written + write_status(mem, status, status_byte)
}

/// Read each data descriptor's worth of sectors from `backing` into guest memory.
fn read_into_guest<B: Read + Seek>(
    mem: &GuestMemoryMmap,
    data: &[virtio_queue::Descriptor],
    backing: &mut B,
    start_sector: u64,
) -> (u8, u32) {
    let mut offset = start_sector * SECTOR_SIZE;
    let mut written = 0u32;
    for d in data {
        let len = d.len() as usize;
        let mut buf = vec![0u8; len];
        if backing.seek(SeekFrom::Start(offset)).is_err() || backing.read_exact(&mut buf).is_err() {
            return (VIRTIO_BLK_S_IOERR, written);
        }
        if mem.write_slice(&buf, d.addr()).is_err() {
            return (VIRTIO_BLK_S_IOERR, written);
        }
        written += d.len();
        offset += len as u64;
    }
    (VIRTIO_BLK_S_OK, written)
}

/// Write each data descriptor's worth of guest memory to `backing`.
fn write_from_guest<B: Write + Seek>(
    mem: &GuestMemoryMmap,
    data: &[virtio_queue::Descriptor],
    backing: &mut B,
    start_sector: u64,
) -> (u8, u32) {
    let mut offset = start_sector * SECTOR_SIZE;
    for d in data {
        let len = d.len() as usize;
        let mut buf = vec![0u8; len];
        if mem.read_slice(&mut buf, d.addr()).is_err() {
            return (VIRTIO_BLK_S_IOERR, 0);
        }
        if backing.seek(SeekFrom::Start(offset)).is_err() || backing.write_all(&buf).is_err() {
            return (VIRTIO_BLK_S_IOERR, 0);
        }
        offset += len as u64;
    }
    (VIRTIO_BLK_S_OK, 0)
}

/// Write the 1-byte status to the request's status descriptor; returns 1 on
/// success (the status byte counts toward the used-ring length), else 0.
fn write_status(mem: &GuestMemoryMmap, status: &virtio_queue::Descriptor, value: u8) -> u32 {
    u32::from(mem.write_slice(&[value], status.addr()).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use virtio_queue::mock::MockSplitQueue;
    use virtio_queue::{Descriptor, Queue};
    use vm_memory::GuestAddress;

    const F_WRITE: u16 = 0x2;

    // Buffer addresses live ≥1 MiB, clear of the mock's ring (written from
    // address 0), per `MockSplitQueue`'s contract.
    const HDR_ADDR: u64 = 0x10_0000;
    const DATA_ADDR: u64 = 0x10_1000;
    const STATUS_ADDR: u64 = 0x10_2000;

    fn guest() -> GuestMemoryMmap {
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x20_0000)]).unwrap()
    }

    #[test]
    fn config_exposes_capacity_in_sectors() {
        let dev = VirtioBlock::new(Cursor::new(vec![0u8; 1024]), 2, false);
        assert_eq!(dev.device_type(), VIRTIO_ID_BLOCK);
        assert_eq!(dev.features() & VIRTIO_F_VERSION_1, VIRTIO_F_VERSION_1);
        let mut cfg = [0u8; 8];
        dev.read_config(0, &mut cfg);
        assert_eq!(u64::from_le_bytes(cfg), 2, "capacity = 2 sectors");
    }

    #[test]
    fn read_request_copies_a_sector_from_backing_into_guest_memory() {
        // Backing disk: sector 0 filled with 0xAB.
        let mut disk = vec![0u8; (SECTOR_SIZE * 2) as usize];
        for b in disk[..SECTOR_SIZE as usize].iter_mut() {
            *b = 0xab;
        }
        let mut dev = VirtioBlock::new(Cursor::new(disk), 2, false);

        let mem = guest();
        let vq = MockSplitQueue::new(&mem, 16);
        // Header (RO, 16B), data (WO, 512B), status (WO, 1B). `build_desc_chain`
        // sets the NEXT links itself; we just supply the addresses + WRITE flags.
        let chain = [
            Descriptor::new(HDR_ADDR, HEADER_LEN as u32, 0, 0),
            Descriptor::new(DATA_ADDR, SECTOR_SIZE as u32, F_WRITE, 0),
            Descriptor::new(STATUS_ADDR, 1, F_WRITE, 0),
        ];
        vq.build_desc_chain(&chain).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        // Write the request header: type = IN (0), sector = 0.
        let mut hdr = [0u8; HEADER_LEN];
        hdr[0..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
        mem.write_slice(&hdr, GuestAddress(HDR_ADDR)).unwrap();

        dev.process(&mut queue, &mem).expect("process");

        // The data descriptor now holds the backing sector; status == OK.
        let mut out = [0u8; SECTOR_SIZE as usize];
        mem.read_slice(&mut out, GuestAddress(DATA_ADDR)).unwrap();
        assert!(out.iter().all(|&b| b == 0xab), "sector copied into guest");
        let mut st = [0u8; 1];
        mem.read_slice(&mut st, GuestAddress(STATUS_ADDR)).unwrap();
        assert_eq!(st[0], VIRTIO_BLK_S_OK);
    }

    #[test]
    fn write_request_persists_guest_data_and_read_only_is_rejected() {
        let mem = guest();
        // Fill the guest data buffer with 0xCD, to be written to the disk.
        mem.write_slice(&[0xcd_u8; SECTOR_SIZE as usize], GuestAddress(DATA_ADDR))
            .unwrap();
        let mut hdr = [0u8; HEADER_LEN];
        hdr[0..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        mem.write_slice(&hdr, GuestAddress(HDR_ADDR)).unwrap();

        let build = |mem: &GuestMemoryMmap| {
            let vq = MockSplitQueue::new(mem, 16);
            let chain = [
                Descriptor::new(HDR_ADDR, HEADER_LEN as u32, 0, 0),
                Descriptor::new(DATA_ADDR, SECTOR_SIZE as u32, 0, 0),
                Descriptor::new(STATUS_ADDR, 1, F_WRITE, 0),
            ];
            vq.build_desc_chain(&chain).unwrap();
            let q: Queue = vq.create_queue().unwrap();
            q
        };

        // Writable device: the sector lands in the backing store.
        let mut rw = VirtioBlock::new(Cursor::new(vec![0u8; (SECTOR_SIZE * 2) as usize]), 2, false);
        let mut q = build(&mem);
        rw.process(&mut q, &mem).unwrap();
        let mut st = [0u8; 1];
        mem.read_slice(&mut st, GuestAddress(STATUS_ADDR)).unwrap();
        assert_eq!(st[0], VIRTIO_BLK_S_OK);
        assert!(rw.backing.get_ref()[..SECTOR_SIZE as usize]
            .iter()
            .all(|&b| b == 0xcd));

        // Read-only device: the write is rejected with an I/O error status.
        let mut ro = VirtioBlock::new(Cursor::new(vec![0u8; (SECTOR_SIZE * 2) as usize]), 2, true);
        let mut q2 = build(&mem);
        ro.process(&mut q2, &mem).unwrap();
        mem.read_slice(&mut st, GuestAddress(STATUS_ADDR)).unwrap();
        assert_eq!(st[0], VIRTIO_BLK_S_IOERR, "read-only rejects writes");
    }
}
