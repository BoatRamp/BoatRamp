//! Embedded VMM **snapshot/restore** state (scale-to-zero): capture a
//! **paused** microVM's full CPU + chip state so it can
//! be torn down and later reconstructed exactly. The large guest RAM is streamed
//! separately (to a memory file); this module is the small, structured CPU/chip
//! state plus the per-vCPU/VM `KVM_GET_*` capture and `KVM_SET_*` apply.
//!
//! Snapshots are **same-host, same-kernel** (scale-to-zero on one node): the raw
//! KVM structs are kept as-is rather than versioned (Firecracker's cross-version
//! `versionize` is out of scope). Capturing requires the vCPUs to be **paused**
//! (not inside `KVM_RUN`); applying happens on a freshly created VM before its
//! vCPUs run.

use kvm_bindings::{
    kvm_clock_data, kvm_cpuid_entry2, kvm_irqchip, kvm_lapic_state, kvm_mp_state, kvm_msr_entry,
    kvm_pit_state2, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave, CpuId, Msrs,
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

use crate::embedded_vmm::VmmError;

/// One vCPU's captured architectural state.
pub struct VcpuSnapshot {
    pub regs: kvm_regs,
    pub sregs: kvm_sregs,
    pub xsave: kvm_xsave,
    pub xcrs: kvm_xcrs,
    pub mp_state: kvm_mp_state,
    pub vcpu_events: kvm_vcpu_events,
    /// Present only with an in-kernel irqchip (LAPIC state).
    pub lapic: Option<kvm_lapic_state>,
    pub msrs: Vec<kvm_msr_entry>,
    pub cpuid: Vec<kvm_cpuid_entry2>,
}

/// A paused microVM's full CPU + chip state (the guest RAM is streamed alongside).
pub struct VmSnapshot {
    pub mem_bytes: u64,
    pub has_irqchip: bool,
    pub vcpus: Vec<VcpuSnapshot>,
    /// In-kernel irqchip: `[PIC master, PIC slave, IOAPIC]` (irqchip VMs only).
    pub irqchips: Option<[kvm_irqchip; 3]>,
    pub pit: Option<kvm_pit_state2>,
    pub clock: Option<kvm_clock_data>,
}

/// View a POD value as its raw bytes for serialization. `T` must be a fixed-size,
/// pointer-free KVM struct (the only types these helpers are called on) — raw
/// bytes are meaningful only because the snapshot is same-host/same-kernel.
fn pod_bytes<T>(v: &T) -> &[u8] {
    // SAFETY: `T` is a POD KVM struct (no pointers/padding-sensitive content);
    // reading its bytes is sound.
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>()) }
}

fn write_pod<T>(w: &mut dyn std::io::Write, v: &T) -> std::io::Result<()> {
    w.write_all(pod_bytes(v))
}

fn read_pod<T>(r: &mut dyn std::io::Read) -> std::io::Result<T> {
    // SAFETY: zero is a valid bit pattern for these POD structs; we overwrite the
    // full size from the stream.
    let mut v: T = unsafe { std::mem::zeroed() };
    let buf = unsafe {
        std::slice::from_raw_parts_mut((&mut v as *mut T).cast::<u8>(), std::mem::size_of::<T>())
    };
    r.read_exact(buf)?;
    Ok(v)
}

fn write_vec<T>(w: &mut dyn std::io::Write, items: &[T]) -> std::io::Result<()> {
    write_pod(w, &(items.len() as u32))?;
    for it in items {
        write_pod(w, it)?;
    }
    Ok(())
}

fn read_vec<T>(r: &mut dyn std::io::Read) -> std::io::Result<Vec<T>> {
    let n: u32 = read_pod(r)?;
    (0..n).map(|_| read_pod(r)).collect()
}

fn write_opt<T>(w: &mut dyn std::io::Write, v: &Option<T>) -> std::io::Result<()> {
    match v {
        Some(x) => {
            write_pod(w, &1u8)?;
            write_pod(w, x)
        }
        None => write_pod(w, &0u8),
    }
}

fn read_opt<T>(r: &mut dyn std::io::Read) -> std::io::Result<Option<T>> {
    let tag: u8 = read_pod(r)?;
    if tag == 1 {
        Ok(Some(read_pod(r)?))
    } else {
        Ok(None)
    }
}

impl VmSnapshot {
    /// Serialize the CPU/chip state to `w` as raw POD bytes (same-host/same-kernel;
    /// the guest RAM is streamed separately). Format: `mem_bytes`, `has_irqchip`,
    /// per-vCPU state, then the optional irqchip/PIT/clock.
    pub fn write_to(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        write_pod(w, &self.mem_bytes)?;
        write_pod(w, &u8::from(self.has_irqchip))?;
        write_pod(w, &(self.vcpus.len() as u32))?;
        for v in &self.vcpus {
            write_pod(w, &v.regs)?;
            write_pod(w, &v.sregs)?;
            write_pod(w, &v.xsave)?;
            write_pod(w, &v.xcrs)?;
            write_pod(w, &v.mp_state)?;
            write_pod(w, &v.vcpu_events)?;
            write_opt(w, &v.lapic)?;
            write_vec(w, &v.msrs)?;
            write_vec(w, &v.cpuid)?;
        }
        write_opt(w, &self.irqchips)?;
        write_opt(w, &self.pit)?;
        write_opt(w, &self.clock)?;
        Ok(())
    }

    /// Deserialize a snapshot written by [`write_to`](Self::write_to).
    pub fn read_from(r: &mut dyn std::io::Read) -> std::io::Result<Self> {
        let mem_bytes: u64 = read_pod(r)?;
        let has_irqchip: u8 = read_pod(r)?;
        let n: u32 = read_pod(r)?;
        let mut vcpus = Vec::with_capacity(n as usize);
        for _ in 0..n {
            vcpus.push(VcpuSnapshot {
                regs: read_pod(r)?,
                sregs: read_pod(r)?,
                xsave: read_pod(r)?,
                xcrs: read_pod(r)?,
                mp_state: read_pod(r)?,
                vcpu_events: read_pod(r)?,
                lapic: read_opt(r)?,
                msrs: read_vec(r)?,
                cpuid: read_vec(r)?,
            });
        }
        Ok(VmSnapshot {
            mem_bytes,
            has_irqchip: has_irqchip != 0,
            vcpus,
            irqchips: read_opt::<[kvm_irqchip; 3]>(r)?,
            pit: read_opt(r)?,
            clock: read_opt(r)?,
        })
    }
}

/// Read all host-supported MSR values for `vcpu` (the `KVM_GET_MSR_INDEX_LIST` set
/// that `get_msrs` can read), as entries to re-apply on restore.
fn capture_msrs(kvm: &Kvm, vcpu: &VcpuFd) -> Result<Vec<kvm_msr_entry>, VmmError> {
    let index_list = kvm
        .get_msr_index_list()
        .map_err(|e| VmmError::Kvm(format!("get_msr_index_list: {e}")))?;
    let entries: Vec<kvm_msr_entry> = index_list
        .as_slice()
        .iter()
        .map(|&index| kvm_msr_entry {
            index,
            ..Default::default()
        })
        .collect();
    let mut msrs =
        Msrs::from_entries(&entries).map_err(|e| VmmError::Kvm(format!("build msrs: {e:?}")))?;
    let read = vcpu
        .get_msrs(&mut msrs)
        .map_err(|e| VmmError::Kvm(format!("get_msrs: {e}")))?;
    // `get_msrs` reads a prefix of the list; keep what it actually returned.
    Ok(msrs.as_slice()[..read].to_vec())
}

/// Capture one paused `vcpu`'s state. `has_irqchip` gates the LAPIC (only present
/// with an in-kernel irqchip).
pub fn capture_vcpu(kvm: &Kvm, vcpu: &VcpuFd, has_irqchip: bool) -> Result<VcpuSnapshot, VmmError> {
    let map = |what: &str, e: kvm_ioctls::Error| VmmError::Kvm(format!("get {what}: {e}"));
    Ok(VcpuSnapshot {
        regs: vcpu.get_regs().map_err(|e| map("regs", e))?,
        sregs: vcpu.get_sregs().map_err(|e| map("sregs", e))?,
        xsave: vcpu.get_xsave().map_err(|e| map("xsave", e))?,
        xcrs: vcpu.get_xcrs().map_err(|e| map("xcrs", e))?,
        mp_state: vcpu.get_mp_state().map_err(|e| map("mp_state", e))?,
        vcpu_events: vcpu.get_vcpu_events().map_err(|e| map("vcpu_events", e))?,
        lapic: if has_irqchip {
            Some(vcpu.get_lapic().map_err(|e| map("lapic", e))?)
        } else {
            None
        },
        msrs: capture_msrs(kvm, vcpu)?,
        cpuid: vcpu
            .get_cpuid2(KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| map("cpuid", e))?
            .as_slice()
            .to_vec(),
    })
}

/// Apply a captured vCPU state to a freshly created `vcpu` (before it runs).
/// Order matters: CPUID + sregs + MSRs first, then the FPU/extended + GP regs,
/// then the interrupt/mp state.
pub fn apply_vcpu(vcpu: &VcpuFd, snap: &VcpuSnapshot) -> Result<(), VmmError> {
    let map = |what: &str, e: kvm_ioctls::Error| VmmError::Kvm(format!("set {what}: {e}"));

    let cpuid =
        CpuId::from_entries(&snap.cpuid).map_err(|e| VmmError::Kvm(format!("cpuid fam: {e:?}")))?;
    vcpu.set_cpuid2(&cpuid).map_err(|e| map("cpuid", e))?;

    let msrs =
        Msrs::from_entries(&snap.msrs).map_err(|e| VmmError::Kvm(format!("msrs fam: {e:?}")))?;
    // Best-effort: some listed MSRs aren't settable; restore as many as KVM takes.
    let _ = vcpu.set_msrs(&msrs).map_err(|e| map("msrs", e))?;

    vcpu.set_sregs(&snap.sregs).map_err(|e| map("sregs", e))?;
    vcpu.set_xcrs(&snap.xcrs).map_err(|e| map("xcrs", e))?;
    vcpu.set_xsave(&snap.xsave).map_err(|e| map("xsave", e))?;
    if let Some(lapic) = &snap.lapic {
        vcpu.set_lapic(lapic).map_err(|e| map("lapic", e))?;
    }
    vcpu.set_vcpu_events(&snap.vcpu_events)
        .map_err(|e| map("vcpu_events", e))?;
    vcpu.set_mp_state(snap.mp_state)
        .map_err(|e| map("mp_state", e))?;
    vcpu.set_regs(&snap.regs).map_err(|e| map("regs", e))?;
    Ok(())
}

/// Capture the in-kernel chip state (PIC master/slave, IOAPIC) of an irqchip VM.
pub fn capture_irqchips(vm: &VmFd) -> Result<[kvm_irqchip; 3], VmmError> {
    let mut chips = [
        KVM_IRQCHIP_PIC_MASTER,
        KVM_IRQCHIP_PIC_SLAVE,
        KVM_IRQCHIP_IOAPIC,
    ]
    .map(|id| {
        // SAFETY: `kvm_irqchip` is a POD union struct; zero is a valid bit pattern.
        let mut chip: kvm_irqchip = unsafe { std::mem::zeroed() };
        chip.chip_id = id;
        chip
    });
    for chip in &mut chips {
        vm.get_irqchip(chip)
            .map_err(|e| VmmError::Kvm(format!("get_irqchip {}: {e}", chip.chip_id)))?;
    }
    Ok(chips)
}

/// Apply captured irqchip state to a freshly created (irqchip) VM.
pub fn apply_irqchips(vm: &VmFd, chips: &[kvm_irqchip; 3]) -> Result<(), VmmError> {
    for chip in chips {
        vm.set_irqchip(chip)
            .map_err(|e| VmmError::Kvm(format!("set_irqchip {}: {e}", chip.chip_id)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The on-disk snapshot format round-trips every field, including the
    /// variable-length MSR/CPUID vectors and the optional chip state. Pure — the
    /// cross-process restore path (the snapshotting child exits, a fresh child
    /// reloads) depends on this exact byte layout, so it must hold without KVM.
    #[test]
    fn vm_snapshot_round_trips_through_bytes() {
        let regs = kvm_regs {
            rip: 0x0010_0009,
            rsp: 0x0007_f000,
            ..Default::default()
        };
        let sregs = kvm_sregs {
            cr3: 0x0bee_f000,
            ..Default::default()
        };
        let mp_state = kvm_mp_state { mp_state: 7 };

        let mut lapic = kvm_lapic_state::default();
        lapic.regs[3] = 0x42;
        let mut irqchips: [kvm_irqchip; 3] = Default::default();
        for (i, chip) in irqchips.iter_mut().enumerate() {
            chip.chip_id = i as u32;
        }

        let snap = VmSnapshot {
            mem_bytes: 8 * 1024 * 1024,
            has_irqchip: true,
            vcpus: vec![VcpuSnapshot {
                regs,
                sregs,
                xsave: kvm_xsave::default(),
                xcrs: kvm_xcrs::default(),
                mp_state,
                vcpu_events: kvm_vcpu_events::default(),
                lapic: Some(lapic),
                msrs: vec![
                    kvm_msr_entry {
                        index: 0x174,
                        data: 0x1234,
                        ..Default::default()
                    },
                    kvm_msr_entry {
                        index: 0xc000_0080,
                        data: 0xd01,
                        ..Default::default()
                    },
                ],
                cpuid: vec![kvm_cpuid_entry2 {
                    function: 1,
                    eax: 0x600,
                    ..Default::default()
                }],
            }],
            irqchips: Some(irqchips),
            pit: Some(kvm_pit_state2::default()),
            clock: Some(kvm_clock_data::default()),
        };

        let mut buf = Vec::new();
        snap.write_to(&mut buf).expect("write");
        let back = VmSnapshot::read_from(&mut buf.as_slice()).expect("read");

        assert_eq!(back.mem_bytes, snap.mem_bytes);
        assert!(back.has_irqchip);
        assert_eq!(back.vcpus.len(), 1);
        let v = &back.vcpus[0];
        assert_eq!(v.regs.rip, 0x0010_0009);
        assert_eq!(v.regs.rsp, 0x0007_f000);
        assert_eq!(v.sregs.cr3, 0x0bee_f000);
        assert_eq!(v.mp_state.mp_state, 7);
        assert_eq!(v.lapic.as_ref().expect("lapic").regs[3], 0x42);
        assert_eq!(v.msrs.len(), 2);
        assert_eq!(v.msrs[0].index, 0x174);
        assert_eq!(v.msrs[0].data, 0x1234);
        assert_eq!(v.msrs[1].index, 0xc000_0080);
        assert_eq!(v.cpuid.len(), 1);
        assert_eq!(v.cpuid[0].function, 1);
        assert_eq!(v.cpuid[0].eax, 0x600);
        let chips = back.irqchips.as_ref().expect("irqchips");
        assert_eq!(
            [chips[0].chip_id, chips[1].chip_id, chips[2].chip_id],
            [0, 1, 2]
        );
        assert!(back.pit.is_some());
        assert!(back.clock.is_some());
    }
}
