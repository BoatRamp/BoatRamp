//! A minimal Intel **MP table** for the embedded VMM. Without an MP table (or
//! ACPI), a Linux guest can't discover the
//! interrupt topology — it logs "ACPI MADT or MP tables are not detected", falls
//! back to APIC "virtual wire mode", skips IO-APIC setup, and never receives the
//! scheduler timer interrupt (it hangs at the first idle). Providing an MP table
//! makes the kernel program the IO-APIC and route the legacy IRQs, so the timer
//! (IRQ0) and COM1 (IRQ4) are delivered.
//!
//! This builds the byte image (MP Floating Pointer + MP Configuration Table:
//! per-CPU, ISA bus, IO-APIC, the 16 legacy I/O-interrupt source entries with
//! identity IRQ→pin routing — matching KVM's default IRQ routing — and the
//! LINT0=ExtINT / LINT1=NMI local-interrupt entries), with both checksums.
//! Layout + values mirror Firecracker's `arch::x86_64::mptable`. Pure +
//! unit-tested; the VMM writes it into guest RAM at [`MPTABLE_START`].

/// Guest physical address the MP table is written at — the last KiB of base
/// memory (just below the 640 KiB / EBDA hole), which the kernel scans for the
/// `_MP_` floating-pointer signature.
pub const MPTABLE_START: u64 = 0x9fc00;

const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;
const APIC_VERSION: u8 = 0x14;
const MPC_SPEC: u8 = 4;
/// Highest legacy ISA IRQ (entries built for `0..=GSI_LEGACY_END`).
const GSI_LEGACY_END: u8 = 15;

// MP configuration entry type ids.
const MP_PROCESSOR: u8 = 0;
const MP_BUS: u8 = 1;
const MP_IOAPIC: u8 = 2;
const MP_INTSRC: u8 = 3;
const MP_LINTSRC: u8 = 4;

// Interrupt types.
const MP_INT: u8 = 0;
const MP_NMI: u8 = 1;
const MP_EXTINT: u8 = 3;

// CPU flags + IO-APIC flags.
const CPU_ENABLED: u8 = 1;
const CPU_BOOTPROCESSOR: u8 = 2;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_FLAGS: u32 = 0x200 | 0x001; // APIC | FPU
const MPC_APIC_USABLE: u8 = 1;

/// Build the MP table byte image for `num_cpus` (the `_MP_` floating pointer
/// immediately followed by the `PCMP` configuration table + entries), ready to
/// copy to guest RAM at [`MPTABLE_START`].
pub fn build(num_cpus: u8) -> Vec<u8> {
    let ioapic_id = num_cpus + 1;

    // --- configuration-table entries (after the 44-byte header) ---
    let mut entries: Vec<u8> = Vec::new();
    let mut count: u16 = 0;

    // One processor entry per vCPU (20 bytes each).
    for cpu in 0..num_cpus {
        let mut e = [0u8; 20];
        e[0] = MP_PROCESSOR;
        e[1] = cpu; // local APIC id
        e[2] = APIC_VERSION;
        e[3] = CPU_ENABLED | if cpu == 0 { CPU_BOOTPROCESSOR } else { 0 };
        e[4..8].copy_from_slice(&CPU_STEPPING.to_le_bytes());
        e[8..12].copy_from_slice(&CPU_FEATURE_FLAGS.to_le_bytes());
        entries.extend_from_slice(&e);
        count += 1;
    }

    // ISA bus entry (8 bytes).
    let mut bus = [0u8; 8];
    bus[0] = MP_BUS;
    bus[1] = 0; // bus id
    bus[2..8].copy_from_slice(b"ISA   ");
    entries.extend_from_slice(&bus);
    count += 1;

    // IO-APIC entry (8 bytes).
    let mut ioapic = [0u8; 8];
    ioapic[0] = MP_IOAPIC;
    ioapic[1] = ioapic_id;
    ioapic[2] = APIC_VERSION;
    ioapic[3] = MPC_APIC_USABLE;
    ioapic[4..8].copy_from_slice(&IO_APIC_DEFAULT_PHYS_BASE.to_le_bytes());
    entries.extend_from_slice(&ioapic);
    count += 1;

    // Legacy I/O interrupt source entries (8 bytes each): identity ISA IRQ → IO-
    // APIC pin (matches KVM's default IRQ routing). Covers the timer (IRQ0) and
    // COM1 (IRQ4).
    for irq in 0..=GSI_LEGACY_END {
        let mut e = [0u8; 8];
        e[0] = MP_INTSRC;
        e[1] = MP_INT;
        e[2..4].copy_from_slice(&0u16.to_le_bytes()); // default polarity/trigger
        e[4] = 0; // source bus id (ISA)
        e[5] = irq; // source bus IRQ
        e[6] = ioapic_id; // destination IO-APIC id
        e[7] = irq; // destination IO-APIC pin
        entries.extend_from_slice(&e);
        count += 1;
    }

    // Local interrupt sources: LINT0 = ExtINT (the 8259 path), LINT1 = NMI.
    let mut lint0 = [0u8; 8];
    lint0[0] = MP_LINTSRC;
    lint0[1] = MP_EXTINT;
    lint0[6] = 0; // destination LAPIC id 0
    lint0[7] = 0; // LINT0
    entries.extend_from_slice(&lint0);
    count += 1;

    let mut lint1 = [0u8; 8];
    lint1[0] = MP_LINTSRC;
    lint1[1] = MP_NMI;
    lint1[6] = 0xff; // all LAPICs
    lint1[7] = 1; // LINT1
    entries.extend_from_slice(&lint1);
    count += 1;

    // --- MP configuration table header (44 bytes) ---
    let table_len = 44 + entries.len();
    let mut hdr = [0u8; 44];
    hdr[0..4].copy_from_slice(b"PCMP");
    hdr[4..6].copy_from_slice(&(table_len as u16).to_le_bytes());
    hdr[6] = MPC_SPEC;
    // hdr[7] = checksum (computed below)
    hdr[8..16].copy_from_slice(b"FC      "); // OEM id (8 bytes)
    hdr[16..28].copy_from_slice(b"000000000000"); // product id (12 bytes)
    hdr[34..36].copy_from_slice(&count.to_le_bytes()); // entry count
    hdr[36..40].copy_from_slice(&APIC_DEFAULT_PHYS_BASE.to_le_bytes()); // LAPIC addr

    // Config-table checksum: the 8-bit sum of the header + all entries is 0.
    let mut sum: u8 = 0;
    for &b in hdr.iter().chain(entries.iter()) {
        sum = sum.wrapping_add(b);
    }
    hdr[7] = (!sum).wrapping_add(1);

    // --- MP floating pointer (16 bytes) ---
    let mut mpf = [0u8; 16];
    mpf[0..4].copy_from_slice(b"_MP_");
    mpf[4..8].copy_from_slice(&((MPTABLE_START as u32) + 16).to_le_bytes()); // → config table
    mpf[8] = 1; // length in 16-byte paragraphs
    mpf[9] = MPC_SPEC;
    // mpf[10] = checksum (computed below); mpf[11..16] feature bytes = 0
    let mut s: u8 = 0;
    for &b in mpf.iter() {
        s = s.wrapping_add(b);
    }
    mpf[10] = (!s).wrapping_add(1);

    let mut out = Vec::with_capacity(16 + table_len);
    out.extend_from_slice(&mpf);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&entries);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum8(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b))
    }

    #[test]
    fn signatures_and_checksums_are_valid() {
        let t = build(1);
        // Floating pointer: "_MP_", length 1, spec 4, and the 16-byte sum is 0.
        assert_eq!(&t[0..4], b"_MP_");
        assert_eq!(t[8], 1);
        assert_eq!(t[9], MPC_SPEC);
        assert_eq!(sum8(&t[0..16]), 0, "mpf checksum");
        // physptr points just past the floating pointer.
        let physptr = u32::from_le_bytes(t[4..8].try_into().unwrap());
        assert_eq!(physptr, MPTABLE_START as u32 + 16);

        // Config table: "PCMP" at offset 16, declared length, and (header+entries)
        // sum is 0.
        assert_eq!(&t[16..20], b"PCMP");
        let table_len = u16::from_le_bytes(t[20..22].try_into().unwrap()) as usize;
        assert_eq!(
            table_len,
            t.len() - 16,
            "table length covers header+entries"
        );
        assert_eq!(sum8(&t[16..]), 0, "mpc checksum");
    }

    #[test]
    fn entry_count_and_layout_for_one_cpu() {
        let t = build(1);
        // 1 cpu + 1 bus + 1 ioapic + 16 intsrc + 2 lintsrc = 21 entries.
        let count = u16::from_le_bytes(t[16 + 34..16 + 36].try_into().unwrap());
        assert_eq!(count, 21);
        // Total size: 16 (mpf) + 44 (hdr) + 20 (cpu) + 8 + 8 + 16*8 + 2*8.
        assert_eq!(t.len(), 16 + 44 + 20 + 8 + 8 + 16 * 8 + 2 * 8);
        // The processor entry is enabled + BSP, APIC id 0.
        let cpu = &t[16 + 44..16 + 44 + 20];
        assert_eq!(cpu[0], MP_PROCESSOR);
        assert_eq!(cpu[1], 0);
        assert_eq!(cpu[3], CPU_ENABLED | CPU_BOOTPROCESSOR);
        // LAPIC address in the header.
        let lapic = u32::from_le_bytes(t[16 + 36..16 + 40].try_into().unwrap());
        assert_eq!(lapic, APIC_DEFAULT_PHYS_BASE);
    }

    #[test]
    fn legacy_irqs_route_identity_to_the_ioapic() {
        let t = build(1);
        // Walk to the first INTSRC entry: after mpf(16)+hdr(44)+cpu(20)+bus(8)+ioapic(8).
        let intsrc0 = 16 + 44 + 20 + 8 + 8;
        let ioapic_id = 1 + 1; // num_cpus + 1
        for irq in 0u8..=GSI_LEGACY_END {
            let e = &t[intsrc0 + irq as usize * 8..intsrc0 + irq as usize * 8 + 8];
            assert_eq!(e[0], MP_INTSRC);
            assert_eq!(e[5], irq, "source IRQ");
            assert_eq!(e[6], ioapic_id, "dest IO-APIC");
            assert_eq!(e[7], irq, "identity pin routing");
        }
    }

    #[test]
    fn more_cpus_add_processor_entries() {
        let t = build(4);
        let count = u16::from_le_bytes(t[16 + 34..16 + 36].try_into().unwrap());
        assert_eq!(count, 4 + 1 + 1 + 16 + 2);
        assert_eq!(sum8(&t[0..16]), 0);
        assert_eq!(sum8(&t[16..]), 0);
    }
}
