//! The **embedded rust-vmm** VMM: boot the guest in-process under KVM instead
//! of spawning the external `firecracker` binary (the one-binary goal).
//!
//! This module is the **pure x86_64 boot-layout layer** — the foundation every
//! later piece (KVM machine setup, `linux-loader` kernel load, virtio device
//! models, the vCPU run loop) builds on, and the part that is fully
//! unit-testable with no `/dev/kvm`:
//!
//! - the guest **physical memory map** (`ram_regions`): RAM below the 32-bit
//!   MMIO gap, and — for >3.25 GiB guests — a high region past 4 GiB;
//! - the **e820** map handed to the guest via the boot params (`e820_entries`);
//! - **virtio-MMIO** device window + IRQ allocation (`allocate_mmio`) and the
//!   `virtio_mmio.device=…` kernel-cmdline fragments the guest needs to find
//!   them (`mmio_cmdline_arg`).
//!
//! Constants mirror Firecracker's `arch::x86_64::layout`, so the embedded mode
//! and the external mode agree on the guest's view of memory. The KVM ioctls,
//! kernel load, and device emulation are the **`compute-live`** (KVM-host) seam.

/// Start of the Extended BIOS Data Area — the top of the usable first segment of
/// low RAM (everything in `[EBDA_START, HIMEM_START)` is reserved for BIOS/ROM).
pub const EBDA_START: u64 = 0x9_fc00;

/// Where the kernel is loaded (1 MiB) — the start of "high" memory in real-mode
/// terms; also the second usable e820 region's base.
pub const HIMEM_START: u64 = 0x10_0000;

/// Guest physical address of the zero page (the `boot_params` struct).
pub const ZERO_PAGE_START: u64 = 0x7000;

/// Guest physical address the kernel command line is written to.
pub const CMDLINE_START: u64 = 0x2_0000;

/// Maximum kernel command-line length (the reserved cmdline window).
pub const CMDLINE_MAX_SIZE: u64 = 0x1_0000;

/// Base of the 32-bit MMIO gap (3.25 GiB). RAM never occupies
/// `[MMIO_MEM_START, 4 GiB)`; device MMIO windows are carved from here.
pub const MMIO_MEM_START: u64 = 0xd000_0000;

/// First guest physical address past the 32-bit space (4 GiB) — where high RAM
/// resumes for guests larger than [`MMIO_MEM_START`].
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

/// Size of the 32-bit MMIO gap (`[MMIO_MEM_START, 4 GiB)` = 768 MiB).
pub const MMIO_GAP_SIZE: u64 = FIRST_ADDR_PAST_32BITS - MMIO_MEM_START;

/// e820 entry type for usable RAM.
pub const E820_RAM: u32 = 1;

/// First guest IRQ (GSI) available for virtio-MMIO devices (0–4 are legacy).
pub const IRQ_BASE: u32 = 5;

/// Last usable guest IRQ (a single legacy I/O APIC has 24 lines, 0–23).
pub const IRQ_MAX: u32 = 23;

/// Per-device virtio-MMIO window size (one 4 KiB page).
pub const VIRTIO_MMIO_SIZE: u64 = 0x1000;

/// A contiguous guest RAM region: a base guest-physical address + a byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Guest physical start address.
    pub start: u64,
    /// Region length in bytes.
    pub size: u64,
}

/// One e820 map entry (base, length, type) as the guest BIOS/boot-params expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E820Entry {
    /// Guest physical base address.
    pub addr: u64,
    /// Length in bytes.
    pub size: u64,
    /// Entry type ([`E820_RAM`] for usable RAM).
    pub kind: u32,
}

/// A virtio-MMIO device's allocated transport window + IRQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioDevice {
    /// Allocation index (`0..count`).
    pub index: usize,
    /// MMIO window base (guest physical).
    pub addr: u64,
    /// MMIO window size (bytes).
    pub size: u64,
    /// Assigned guest IRQ line.
    pub irq: u32,
}

/// Why a layout could not be built.
#[derive(Debug, PartialEq, Eq)]
pub enum LayoutError {
    /// More virtio-MMIO devices were requested than there are free IRQ lines.
    TooManyDevices {
        /// Devices requested.
        requested: usize,
        /// Devices that fit (IRQs `IRQ_BASE..=IRQ_MAX`).
        max: usize,
    },
    /// More e820 entries than the boot_params table holds.
    TooManyE820Entries {
        /// Entries requested.
        requested: usize,
        /// The boot_params `e820_table` capacity.
        max: usize,
    },
}

impl std::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LayoutError::TooManyDevices { requested, max } => {
                write!(f, "too many MMIO devices: requested {requested}, max {max}")
            }
            LayoutError::TooManyE820Entries { requested, max } => {
                write!(f, "too many e820 entries: requested {requested}, max {max}")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

/// The guest RAM regions for a `mem_bytes`-sized guest. Small guests get one
/// region `[0, mem_bytes)`; guests larger than the MMIO gap get a low region
/// `[0, MMIO_MEM_START)` and a high region past 4 GiB holding the remainder, so
/// no RAM ever overlaps the 32-bit MMIO gap.
pub fn ram_regions(mem_bytes: u64) -> Vec<MemoryRegion> {
    if mem_bytes <= MMIO_MEM_START {
        vec![MemoryRegion {
            start: 0,
            size: mem_bytes,
        }]
    } else {
        vec![
            MemoryRegion {
                start: 0,
                size: MMIO_MEM_START,
            },
            MemoryRegion {
                start: FIRST_ADDR_PAST_32BITS,
                size: mem_bytes - MMIO_MEM_START,
            },
        ]
    }
}

/// The e820 map for a `mem_bytes`-sized guest: the usable RAM ranges the guest
/// sees, with the BIOS/ROM hole `[EBDA_START, HIMEM_START)` and the 32-bit MMIO
/// gap excluded. Mirrors Firecracker's `configure_system`.
pub fn e820_entries(mem_bytes: u64) -> Vec<E820Entry> {
    let mut entries = Vec::with_capacity(3);
    // The first usable segment, up to the EBDA.
    entries.push(E820Entry {
        addr: 0,
        size: mem_bytes.min(EBDA_START),
        kind: E820_RAM,
    });
    // Low RAM from 1 MiB up to the end of low memory (capped at the MMIO gap).
    let low_end = mem_bytes.min(MMIO_MEM_START);
    if low_end > HIMEM_START {
        entries.push(E820Entry {
            addr: HIMEM_START,
            size: low_end - HIMEM_START,
            kind: E820_RAM,
        });
    }
    // High RAM past 4 GiB for guests larger than the MMIO gap.
    if mem_bytes > MMIO_MEM_START {
        entries.push(E820Entry {
            addr: FIRST_ADDR_PAST_32BITS,
            size: mem_bytes - MMIO_MEM_START,
            kind: E820_RAM,
        });
    }
    entries
}

/// Allocate `count` virtio-MMIO device windows: each a [`VIRTIO_MMIO_SIZE`] page
/// stacked from [`MMIO_MEM_START`] upward, with a distinct IRQ from
/// `IRQ_BASE..=IRQ_MAX`. Errors if more devices are requested than IRQ lines.
pub fn allocate_mmio(count: usize) -> Result<Vec<MmioDevice>, LayoutError> {
    let max = (IRQ_MAX - IRQ_BASE) as usize + 1;
    if count > max {
        return Err(LayoutError::TooManyDevices {
            requested: count,
            max,
        });
    }
    Ok((0..count)
        .map(|i| MmioDevice {
            index: i,
            addr: MMIO_MEM_START + (i as u64) * VIRTIO_MMIO_SIZE,
            size: VIRTIO_MMIO_SIZE,
            irq: IRQ_BASE + i as u32,
        })
        .collect())
}

/// Route a guest-physical MMIO `addr` to the virtio-MMIO device window (from
/// [`allocate_mmio`]) that contains it, returning `(device_index, offset)` where
/// `offset` is the access position within that device's register window. `None`
/// if `addr` falls outside every device window. The vCPU run loop uses this to
/// dispatch a `MmioRead`/`MmioWrite` exit to the right device transport.
pub fn route_mmio(devices: &[MmioDevice], addr: u64) -> Option<(usize, u64)> {
    devices.iter().enumerate().find_map(|(i, d)| {
        // Lazy `.then` — only compute the offset for the matching window (a bare
        // subtraction would underflow for addresses below a window).
        (addr >= d.addr && addr < d.addr + d.size).then(|| (i, addr - d.addr))
    })
}

/// The `virtio_mmio.device=<size>@<addr>:<irq>` kernel-cmdline fragment that
/// tells the guest kernel where to find a virtio-MMIO `dev` (Linux parses these
/// to instantiate the transport without device-tree/ACPI enumeration). Size is
/// emitted in KiB with a `K` suffix, matching the kernel's parser.
pub fn mmio_cmdline_arg(dev: &MmioDevice) -> String {
    format!(
        "virtio_mmio.device={}K@0x{:x}:{}",
        dev.size / 1024,
        dev.addr,
        dev.irq
    )
}

/// The role a virtio-MMIO device plays — selects the device model the KVM
/// runtime will instantiate, and what host resource it is backed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRole {
    /// A virtio-block device backed by a host image file (rootfs / scratch /
    /// persistent volume).
    Block {
        /// Host path to the backing image.
        path: String,
        /// Whether the guest sees it read-only.
        read_only: bool,
    },
    /// A virtio-net device backed by a host tap.
    Net {
        /// Host tap device name.
        tap_name: String,
        /// The guest's MAC address.
        guest_mac: String,
    },
}

/// One configured guest device: its role + the MMIO transport it was allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredDevice {
    /// What the device is + its host backing.
    pub role: DeviceRole,
    /// The allocated virtio-MMIO window + IRQ.
    pub transport: MmioDevice,
}

/// The pure boot plan for an embedded-VMM guest — the embedded analog of
/// [`crate::config::FcMachine`]: the memory map, the e820 map, the ordered
/// virtio-MMIO devices, and the fully-assembled kernel command line (the base
/// args plus one `virtio_mmio.device=…` fragment per device). This is what the
/// (later) KVM runtime configures; building it is pure + unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedPlan {
    /// Guest RAM regions.
    pub mem_regions: Vec<MemoryRegion>,
    /// The e820 map handed to the guest.
    pub e820: Vec<E820Entry>,
    /// The ordered virtio-MMIO devices.
    pub devices: Vec<ConfiguredDevice>,
    /// The assembled kernel command line.
    pub cmdline: String,
}

impl EmbeddedPlan {
    /// Assemble the plan: `mem_bytes` of guest RAM, the ordered device `roles`,
    /// and a `cmdline_base` (the caller's `console=`/`root=`/`ip=` args) onto
    /// which the per-device `virtio_mmio.device=…` fragments are appended in
    /// allocation order. Errors if more devices are requested than IRQ lines.
    pub fn build(
        mem_bytes: u64,
        cmdline_base: &str,
        roles: Vec<DeviceRole>,
    ) -> Result<Self, LayoutError> {
        let transports = allocate_mmio(roles.len())?;
        let devices: Vec<ConfiguredDevice> = roles
            .into_iter()
            .zip(transports)
            .map(|(role, transport)| ConfiguredDevice { role, transport })
            .collect();
        let mut cmdline = cmdline_base.trim().to_string();
        for d in &devices {
            cmdline.push(' ');
            cmdline.push_str(&mmio_cmdline_arg(&d.transport));
        }
        Ok(EmbeddedPlan {
            mem_regions: ram_regions(mem_bytes),
            e820: e820_entries(mem_bytes),
            devices,
            cmdline,
        })
    }
}

// ---------------------------------------------------------------------------
// x86_64 long-mode boot protocol (pure)
// ---------------------------------------------------------------------------
//
// The values + tables the guest must have in place before the kernel runs: a
// flat 64-bit GDT, identity page tables for the low 1 GiB (so the kernel's
// early `head_64.S` can run with paging on), and the initial control/general
// registers. Mirrors Firecracker's `arch::x86_64::{gdt,regs}`. All pure — the
// KVM layer (a later slice) copies the GDT + page tables into guest memory and
// loads these register values via `KVM_SET_SREGS`/`KVM_SET_REGS`.

/// Guest physical address the boot GDT is written to.
pub const BOOT_GDT_OFFSET: u64 = 0x500;
/// Guest physical address the (empty) boot IDT is written to.
pub const BOOT_IDT_OFFSET: u64 = 0x520;
/// Guest physical address of the PML4 (top-level page table).
pub const PML4_START: u64 = 0x9000;
/// Guest physical address of the single PDPT.
pub const PDPTE_START: u64 = 0xa000;
/// Guest physical address of the single PD (512 × 2 MiB entries → 1 GiB).
pub const PDE_START: u64 = 0xb000;

/// `CR0.PE` — protected mode enable.
pub const CR0_PE: u64 = 1 << 0;
/// `CR0.PG` — paging enable.
pub const CR0_PG: u64 = 1 << 31;
/// `CR4.PAE` — physical address extension (required for long mode).
pub const CR4_PAE: u64 = 1 << 5;
/// `EFER.LME` — long mode enable.
pub const EFER_LME: u64 = 1 << 8;
/// `EFER.LMA` — long mode active.
pub const EFER_LMA: u64 = 1 << 10;

/// Page-table entry flags: present + writable.
const PT_PRESENT: u64 = 1 << 0;
const PT_RW: u64 = 1 << 1;
/// PDE flag: this entry maps a 2 MiB page (rather than pointing at a PT).
const PDE_PS: u64 = 1 << 7;
/// A 2 MiB huge page.
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
/// 512 entries per 4 KiB page table → one PD covers 1 GiB with 2 MiB pages.
const PT_ENTRIES: u64 = 512;

/// Encode an x86 GDT segment descriptor from a 16-bit access/flags word, a
/// 32-bit `base`, and a 20-bit `limit` (Firecracker's `gdt_entry`).
pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ff) << 40)
        | ((u64::from(limit) & 0x000f_0000) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffff) << 16)
        | (u64::from(limit) & 0x0000_ffff)
}

/// The boot GDT for flat 64-bit long mode: null, a ring-0 code segment
/// (`0xa09b`), and a ring-0 data segment (`0xc093`), each spanning the full
/// 4 GiB. Written at [`BOOT_GDT_OFFSET`]; the segment registers select into it.
pub fn boot_gdt() -> [u64; 3] {
    [
        0,
        gdt_entry(0xa09b, 0, 0xf_ffff),
        gdt_entry(0xc093, 0, 0xf_ffff),
    ]
}

/// One page-table word to write into guest memory at `addr` (little-endian u64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageTableEntry {
    /// Guest physical address to write the entry at.
    pub addr: u64,
    /// The 64-bit entry value.
    pub value: u64,
}

/// Identity page tables mapping the low 1 GiB with 2 MiB huge pages: a PML4
/// pointing at one PDPT pointing at one PD of 512 huge-page entries. Returns the
/// `(addr, value)` words to write at [`PML4_START`]/[`PDPTE_START`]/[`PDE_START`].
pub fn identity_page_tables() -> Vec<PageTableEntry> {
    let mut entries = Vec::with_capacity(2 + PT_ENTRIES as usize);
    // PML4[0] → PDPT, PDPT[0] → PD.
    entries.push(PageTableEntry {
        addr: PML4_START,
        value: PDPTE_START | PT_PRESENT | PT_RW,
    });
    entries.push(PageTableEntry {
        addr: PDPTE_START,
        value: PDE_START | PT_PRESENT | PT_RW,
    });
    // PD[i] maps the i-th 2 MiB page, identity (guest phys == virt).
    for i in 0..PT_ENTRIES {
        entries.push(PageTableEntry {
            addr: PDE_START + i * 8,
            value: (i * HUGE_PAGE_SIZE) | PT_PRESENT | PT_RW | PDE_PS,
        });
    }
    entries
}

/// The initial control + general-purpose register values for booting a 64-bit
/// kernel (long mode, paging on). The KVM layer maps these into `kvm_sregs`
/// (cr0/cr3/cr4/efer + the GDT-selected segments) and `kvm_regs` (rip/rsi/rflags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootRegs {
    /// Instruction pointer — the kernel's 64-bit entry ([`HIMEM_START`]).
    pub rip: u64,
    /// `RSI` — pointer to the `boot_params` zero page ([`ZERO_PAGE_START`]).
    pub rsi: u64,
    /// `RFLAGS` — only the reserved bit 1 set.
    pub rflags: u64,
    /// `CR0` — protected mode + paging.
    pub cr0: u64,
    /// `CR3` — physical address of the PML4.
    pub cr3: u64,
    /// `CR4` — PAE.
    pub cr4: u64,
    /// `EFER` — long mode enabled + active.
    pub efer: u64,
}

/// The boot register state for the 64-bit Linux boot protocol.
pub fn boot_regs() -> BootRegs {
    BootRegs {
        rip: HIMEM_START,
        rsi: ZERO_PAGE_START,
        rflags: 0x2,
        cr0: CR0_PE | CR0_PG,
        cr3: PML4_START,
        cr4: CR4_PAE,
        efer: EFER_LME | EFER_LMA,
    }
}

// ---------------------------------------------------------------------------
// boot_params (the "zero page") — pure serialization at the kernel ABI offsets
// ---------------------------------------------------------------------------
//
// The 64-bit Linux boot protocol takes a 4 KiB `boot_params` struct in RSI. We
// fill the fields a direct vmlinux boot needs: the boot-sector magic, the "HdrS"
// setup-header magic, an undefined loader type, the cmdline pointer/size, and the
// e820 memory map. Offsets are the stable kernel ABI (arch/x86/.../bootparam.h),
// pinned by tests. The KVM layer copies this buffer to [`ZERO_PAGE_START`].

/// Size of the `boot_params` zero page.
pub const ZERO_PAGE_SIZE: usize = 4096;

/// Offset of `boot_params.e820_entries` (count, u8).
const BP_E820_ENTRIES: usize = 0x1e8;
/// Offset of `boot_params.hdr.boot_flag` (u16, `0xaa55`).
const BP_BOOT_FLAG: usize = 0x1fe;
/// Offset of `boot_params.hdr.header` (u32, `"HdrS"`).
const BP_HEADER_MAGIC: usize = 0x202;
/// Offset of `boot_params.hdr.type_of_loader` (u8).
const BP_TYPE_OF_LOADER: usize = 0x210;
/// Offset of `boot_params.hdr.cmd_line_ptr` (u32).
const BP_CMDLINE_PTR: usize = 0x228;
/// Offset of `boot_params.hdr.cmdline_size` (u32, boot protocol ≥ 2.06).
const BP_CMDLINE_SIZE: usize = 0x238;
/// Offset of `boot_params.e820_table` (array of 20-byte entries).
const BP_E820_TABLE: usize = 0x2d0;
/// Size of one packed `boot_e820_entry` (`u64 addr; u64 size; u32 type`).
const E820_ENTRY_BYTES: usize = 20;
/// Capacity of the boot_params `e820_table`.
pub const E820_MAX_ENTRIES: usize = 128;

/// The boot-sector magic (`boot_flag`).
const BOOT_FLAG_MAGIC: u16 = 0xaa55;
/// The setup-header magic, `"HdrS"` little-endian.
const HEADER_MAGIC: u32 = 0x5372_6448;
/// `type_of_loader` value for a loader without an assigned id.
const LOADER_TYPE_UNDEFINED: u8 = 0xff;

/// Build the 4 KiB `boot_params` zero page for a direct 64-bit boot: the boot
/// magics + loader type, the kernel command line pointer (`cmdline_addr`) and
/// `cmdline_size`, and the `e820` memory map. The KVM layer writes the returned
/// bytes to [`ZERO_PAGE_START`] and points `RSI` there. Pure; errors if the e820
/// map exceeds the table capacity.
pub fn build_zero_page(
    e820: &[E820Entry],
    cmdline_addr: u64,
    cmdline_size: u32,
) -> Result<Vec<u8>, LayoutError> {
    if e820.len() > E820_MAX_ENTRIES {
        return Err(LayoutError::TooManyE820Entries {
            requested: e820.len(),
            max: E820_MAX_ENTRIES,
        });
    }
    let mut zp = vec![0u8; ZERO_PAGE_SIZE];
    let put_u16 = |zp: &mut [u8], off: usize, v: u16| {
        zp[off..off + 2].copy_from_slice(&v.to_le_bytes());
    };
    let put_u32 = |zp: &mut [u8], off: usize, v: u32| {
        zp[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put_u64 = |zp: &mut [u8], off: usize, v: u64| {
        zp[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };

    put_u16(&mut zp, BP_BOOT_FLAG, BOOT_FLAG_MAGIC);
    put_u32(&mut zp, BP_HEADER_MAGIC, HEADER_MAGIC);
    zp[BP_TYPE_OF_LOADER] = LOADER_TYPE_UNDEFINED;
    put_u32(&mut zp, BP_CMDLINE_PTR, cmdline_addr as u32);
    put_u32(&mut zp, BP_CMDLINE_SIZE, cmdline_size);

    zp[BP_E820_ENTRIES] = e820.len() as u8;
    for (i, e) in e820.iter().enumerate() {
        let off = BP_E820_TABLE + i * E820_ENTRY_BYTES;
        put_u64(&mut zp, off, e.addr);
        put_u64(&mut zp, off + 8, e.size);
        put_u32(&mut zp, off + 16, e.kind);
    }
    Ok(zp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn small_guest_is_one_region() {
        let regions = ram_regions(512 * MIB);
        assert_eq!(
            regions,
            vec![MemoryRegion {
                start: 0,
                size: 512 * MIB
            }]
        );
    }

    #[test]
    fn large_guest_splits_around_the_mmio_gap() {
        // 4 GiB guest: low region fills up to the gap, the rest goes past 4 GiB.
        let regions = ram_regions(4 * GIB);
        assert_eq!(regions.len(), 2);
        assert_eq!(
            regions[0],
            MemoryRegion {
                start: 0,
                size: MMIO_MEM_START
            }
        );
        assert_eq!(regions[1].start, FIRST_ADDR_PAST_32BITS);
        assert_eq!(regions[1].size, 4 * GIB - MMIO_MEM_START);
        // No RAM overlaps the gap, and total RAM is preserved.
        assert_eq!(regions.iter().map(|r| r.size).sum::<u64>(), 4 * GIB);
        assert!(regions[0].start + regions[0].size <= MMIO_MEM_START);
    }

    #[test]
    fn exactly_at_the_gap_stays_one_region() {
        let regions = ram_regions(MMIO_MEM_START);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].size, MMIO_MEM_START);
    }

    #[test]
    fn e820_excludes_the_bios_hole_and_mmio_gap() {
        let entries = e820_entries(512 * MIB);
        assert_eq!(entries.len(), 2);
        // [0, EBDA) then [1 MiB, 512 MiB).
        assert_eq!(
            entries[0],
            E820Entry {
                addr: 0,
                size: EBDA_START,
                kind: E820_RAM
            }
        );
        assert_eq!(entries[1].addr, HIMEM_START);
        assert_eq!(entries[1].size, 512 * MIB - HIMEM_START);
        // The BIOS hole [EBDA, 1 MiB) is not covered by any entry.
        let covered = |a: u64| entries.iter().any(|e| a >= e.addr && a < e.addr + e.size);
        assert!(!covered(EBDA_START));
        assert!(!covered(HIMEM_START - 1));
        assert!(covered(HIMEM_START));
    }

    #[test]
    fn e820_adds_a_high_entry_for_large_guests() {
        let entries = e820_entries(4 * GIB);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].addr, FIRST_ADDR_PAST_32BITS);
        assert_eq!(entries[2].size, 4 * GIB - MMIO_MEM_START);
        // Usable RAM total = mem - the BIOS/ROM hole [EBDA, 1 MiB).
        let usable: u64 = entries.iter().map(|e| e.size).sum();
        assert_eq!(usable, 4 * GIB - (HIMEM_START - EBDA_START));
    }

    #[test]
    fn mmio_devices_get_distinct_windows_and_irqs() {
        let devs = allocate_mmio(3).unwrap();
        assert_eq!(devs.len(), 3);
        assert_eq!(devs[0].addr, MMIO_MEM_START);
        assert_eq!(devs[0].irq, IRQ_BASE);
        assert_eq!(devs[1].addr, MMIO_MEM_START + VIRTIO_MMIO_SIZE);
        assert_eq!(devs[1].irq, IRQ_BASE + 1);
        assert_eq!(devs[2].irq, IRQ_BASE + 2);
        // Windows are non-overlapping and inside the MMIO gap.
        for w in devs.windows(2) {
            assert!(w[0].addr + w[0].size <= w[1].addr);
        }
        assert!(devs.last().unwrap().addr + VIRTIO_MMIO_SIZE <= FIRST_ADDR_PAST_32BITS);
    }

    #[test]
    fn mmio_allocation_is_bounded_by_irq_lines() {
        let max = (IRQ_MAX - IRQ_BASE) as usize + 1;
        assert!(allocate_mmio(max).is_ok());
        assert_eq!(
            allocate_mmio(max + 1),
            Err(LayoutError::TooManyDevices {
                requested: max + 1,
                max
            })
        );
    }

    #[test]
    fn mmio_cmdline_fragment_matches_the_kernel_parser() {
        let dev = MmioDevice {
            index: 0,
            addr: MMIO_MEM_START,
            size: VIRTIO_MMIO_SIZE,
            irq: IRQ_BASE,
        };
        assert_eq!(mmio_cmdline_arg(&dev), "virtio_mmio.device=4K@0xd0000000:5");
    }

    #[test]
    fn route_mmio_dispatches_addresses_to_device_windows() {
        let devs = allocate_mmio(3).unwrap();
        // Start of window 0.
        assert_eq!(route_mmio(&devs, MMIO_MEM_START), Some((0, 0)));
        // Mid window 1 (offset 0x10).
        assert_eq!(
            route_mmio(&devs, MMIO_MEM_START + VIRTIO_MMIO_SIZE + 0x10),
            Some((1, 0x10))
        );
        // Last byte of window 2.
        assert_eq!(
            route_mmio(&devs, MMIO_MEM_START + 3 * VIRTIO_MMIO_SIZE - 1),
            Some((2, VIRTIO_MMIO_SIZE - 1))
        );
        // Just past the last window → no device.
        assert_eq!(
            route_mmio(&devs, MMIO_MEM_START + 3 * VIRTIO_MMIO_SIZE),
            None
        );
        // Below the first window → no device.
        assert_eq!(route_mmio(&devs, MMIO_MEM_START - 1), None);
    }

    #[test]
    fn embedded_plan_ties_memory_devices_and_cmdline() {
        let roles = vec![
            DeviceRole::Block {
                path: "/img/rootfs.ext4".into(),
                read_only: true,
            },
            DeviceRole::Block {
                path: "/img/scratch.ext4".into(),
                read_only: false,
            },
            DeviceRole::Net {
                tap_name: "tap-web-0".into(),
                guest_mac: "02:00:0a:00:00:05".into(),
            },
        ];
        let plan = EmbeddedPlan::build(512 * MIB, "console=ttyS0 root=/dev/vda ro", roles).unwrap();

        // One MMIO transport per device, distinct windows + sequential IRQs.
        assert_eq!(plan.devices.len(), 3);
        assert_eq!(plan.devices[0].transport.irq, IRQ_BASE);
        assert_eq!(plan.devices[2].transport.irq, IRQ_BASE + 2);
        assert!(matches!(plan.devices[2].role, DeviceRole::Net { .. }));

        // Memory + e820 match the layout helpers.
        assert_eq!(plan.mem_regions, ram_regions(512 * MIB));
        assert_eq!(plan.e820, e820_entries(512 * MIB));

        // The cmdline = base + one fragment per device, in order.
        assert_eq!(
            plan.cmdline,
            "console=ttyS0 root=/dev/vda ro \
             virtio_mmio.device=4K@0xd0000000:5 \
             virtio_mmio.device=4K@0xd0001000:6 \
             virtio_mmio.device=4K@0xd0002000:7"
        );
    }

    #[test]
    fn embedded_plan_rejects_too_many_devices() {
        let max = (IRQ_MAX - IRQ_BASE) as usize + 1;
        let roles = (0..max + 1)
            .map(|i| DeviceRole::Block {
                path: format!("/img/{i}.ext4"),
                read_only: false,
            })
            .collect();
        assert!(matches!(
            EmbeddedPlan::build(MIB, "console=ttyS0", roles),
            Err(LayoutError::TooManyDevices { .. })
        ));
    }

    #[test]
    fn gdt_entries_match_the_known_long_mode_descriptors() {
        // The canonical flat 64-bit ring-0 code/data descriptors.
        assert_eq!(gdt_entry(0xa09b, 0, 0xf_ffff), 0x00af_9b00_0000_ffff);
        assert_eq!(gdt_entry(0xc093, 0, 0xf_ffff), 0x00cf_9300_0000_ffff);
        let gdt = boot_gdt();
        assert_eq!(gdt[0], 0, "entry 0 is the null descriptor");
        assert_eq!(gdt[1], 0x00af_9b00_0000_ffff, "code segment");
        assert_eq!(gdt[2], 0x00cf_9300_0000_ffff, "data segment");
    }

    #[test]
    fn identity_page_tables_map_the_low_1gib() {
        let pt = identity_page_tables();
        // PML4[0] → PDPT, PDPT[0] → PD (present+writable).
        assert_eq!(
            pt[0],
            PageTableEntry {
                addr: PML4_START,
                value: PDPTE_START | 0b11
            }
        );
        assert_eq!(
            pt[1],
            PageTableEntry {
                addr: PDPTE_START,
                value: PDE_START | 0b11
            }
        );
        // 512 PD entries, each a 2 MiB identity huge page (present+rw+PS=0x83).
        let pdes = &pt[2..];
        assert_eq!(pdes.len(), 512);
        assert_eq!(
            pdes[0],
            PageTableEntry {
                addr: PDE_START,
                value: 0x83
            }
        );
        assert_eq!(
            pdes[1],
            PageTableEntry {
                addr: PDE_START + 8,
                value: (2 * MIB) | 0x83
            }
        );
        // Last entry maps the top of the first 1 GiB.
        assert_eq!(pdes[511].value, (511 * 2 * MIB) | 0x83);
        assert_eq!(pdes[511].value & !0xfff, GIB - 2 * MIB);
    }

    #[test]
    fn boot_regs_select_long_mode() {
        let r = boot_regs();
        assert_eq!(r.rip, HIMEM_START, "kernel entry");
        assert_eq!(r.rsi, ZERO_PAGE_START, "boot_params pointer");
        assert_eq!(r.rflags, 0x2);
        assert_eq!(r.cr3, PML4_START, "CR3 points at the PML4");
        assert!(
            r.cr0 & CR0_PE != 0 && r.cr0 & CR0_PG != 0,
            "protected + paging"
        );
        assert!(r.cr4 & CR4_PAE != 0, "PAE for long mode");
        assert!(
            r.efer & EFER_LME != 0 && r.efer & EFER_LMA != 0,
            "long mode"
        );
    }

    fn le_u16(zp: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(zp[off..off + 2].try_into().unwrap())
    }
    fn le_u32(zp: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(zp[off..off + 4].try_into().unwrap())
    }
    fn le_u64(zp: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(zp[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn zero_page_carries_magics_cmdline_and_e820() {
        let e820 = e820_entries(512 * MIB);
        let zp = build_zero_page(&e820, CMDLINE_START, 64).unwrap();
        assert_eq!(zp.len(), ZERO_PAGE_SIZE);
        // Boot magics + loader type.
        assert_eq!(le_u16(&zp, 0x1fe), 0xaa55, "boot_flag");
        assert_eq!(le_u32(&zp, 0x202), 0x5372_6448, "HdrS header magic");
        assert_eq!(zp[0x210], 0xff, "type_of_loader = undefined");
        // Command line.
        assert_eq!(le_u32(&zp, 0x228), CMDLINE_START as u32, "cmd_line_ptr");
        assert_eq!(le_u32(&zp, 0x238), 64, "cmdline_size");
        // e820 count + the first/second entries serialized packed at 0x2d0.
        assert_eq!(zp[0x1e8] as usize, e820.len());
        assert_eq!(le_u64(&zp, 0x2d0), e820[0].addr);
        assert_eq!(le_u64(&zp, 0x2d0 + 8), e820[0].size);
        assert_eq!(le_u32(&zp, 0x2d0 + 16), e820[0].kind);
        let e1 = 0x2d0 + 20;
        assert_eq!(le_u64(&zp, e1), e820[1].addr);
        assert_eq!(le_u64(&zp, e1 + 8), e820[1].size);
    }

    #[test]
    fn zero_page_rejects_an_oversized_e820_map() {
        let many = vec![
            E820Entry {
                addr: 0,
                size: 1,
                kind: E820_RAM,
            };
            E820_MAX_ENTRIES + 1
        ];
        assert_eq!(
            build_zero_page(&many, CMDLINE_START, 0),
            Err(LayoutError::TooManyE820Entries {
                requested: E820_MAX_ENTRIES + 1,
                max: E820_MAX_ENTRIES
            })
        );
        // Exactly the capacity is fine.
        let full = vec![
            E820Entry {
                addr: 0,
                size: 1,
                kind: E820_RAM,
            };
            E820_MAX_ENTRIES
        ];
        assert!(build_zero_page(&full, CMDLINE_START, 0).is_ok());
    }
}
