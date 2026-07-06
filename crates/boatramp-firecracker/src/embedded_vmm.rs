//! The embedded VMM **KVM runtime**: bring up an
//! in-process microVM under KVM from the pure [`crate::embedded`] boot layout —
//! the one-binary path that replaces the external `firecracker` process.
//!
//! This module does the **machine setup**: open `/dev/kvm`, create the VM, map
//! guest RAM (from [`crate::embedded::ram_regions`]) and register it with KVM,
//! create the vCPUs, and write the static boot tables (the GDT + identity page
//! tables) into guest memory. Loading the kernel, building the `boot_params`
//! zero page, programming the segment/control registers from the boot layout,
//! and the vCPU run loop + virtio device models build on this setup.
//!
//! Linux + `/dev/kvm` only, behind the `embedded` feature. The pure layout is
//! unit-tested cross-platform; this runtime is exercised by the `compute-live`
//! (KVM-host) seam.

use std::fs::File;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};

use kvm_bindings::{
    kvm_fpu, kvm_msr_entry, kvm_pit_config, kvm_regs, kvm_segment, kvm_userspace_memory_region,
    Msrs, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use linux_loader::loader::{elf::Elf, KernelLoader};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::pthread::{pthread_kill, pthread_self, Pthread};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use virtio_queue::{DescriptorChain, Queue, QueueT};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vm_superio::{Serial, Trigger};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::device_manager::DeviceManager;
use crate::embedded_snapshot::{
    apply_irqchips, apply_vcpu, capture_irqchips, capture_vcpu, VmSnapshot,
};
use crate::tap::Tap;
use crate::virtio_mmio::QueueConfig;

use crate::embedded::{
    boot_gdt, boot_regs, build_zero_page, e820_entries, identity_page_tables, ram_regions,
    BOOT_GDT_OFFSET, CMDLINE_START, HIMEM_START, ZERO_PAGE_START,
};

/// Why bringing up the embedded VMM failed.
#[derive(Debug)]
pub enum VmmError {
    /// A KVM ioctl (`/dev/kvm`, VM, vCPU, or memory-region) failed.
    Kvm(String),
    /// Allocating or writing guest memory failed.
    Memory(String),
}

impl std::fmt::Display for VmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmmError::Kvm(d) => write!(f, "kvm: {d}"),
            VmmError::Memory(d) => write!(f, "guest memory: {d}"),
        }
    }
}

impl std::error::Error for VmmError {}

/// Why the primary vCPU stopped running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExit {
    /// The guest executed `HLT` (idle / clean shutdown via the init).
    Halted,
    /// The guest requested power-off, or triple-faulted into a reset.
    Shutdown,
    /// The host asked the VM to stop ([`interrupt_vcpu`] broke `KVM_RUN` and the
    /// run loop saw the stop flag set) — a clean external teardown.
    Stopped,
}

/// COM1 serial port base (the kernel's `console=ttyS0`); the 8 registers are
/// `[COM1_BASE, COM1_BASE + 8)`.
const COM1_BASE: u16 = 0x3f8;
/// Last COM1 register port.
const COM1_LAST: u16 = COM1_BASE + 7;
/// Legacy COM1 interrupt line (GSI 4) — distinct from the virtio-MMIO range
/// (`IRQ_BASE` = 5 and up), so they never collide.
const COM1_GSI: u32 = 4;

/// Guest physical address for the KVM TSS region (`KVM_SET_TSS_ADDR`) — the
/// conventional spot just below 4 GiB, clear of guest RAM + the MMIO gap.
const TSS_ADDRESS: usize = 0xfffb_d000;

/// Raises the COM1 interrupt (GSI 4) by signalling its KVM irqfd. `None` (the
/// minimal, no-irqchip path) makes triggering a no-op — the guest's 8250 driver
/// then works in polled mode (the serial model always reports the THR empty).
struct Com1Irq(Option<EventFd>);

impl Trigger for Com1Irq {
    type E = std::io::Error;
    fn trigger(&self) -> std::io::Result<()> {
        match &self.0 {
            Some(fd) => fd.write(1),
            None => Ok(()),
        }
    }
}

/// The COM1 16550 model, shared across the vCPU threads (locked per access — the
/// console is on vCPU 0, so cross-vCPU contention is negligible). `Serial::new`
/// uses `NoEvents`, so spell out the three `Serial` generics here.
type SharedSerial =
    Mutex<Serial<Com1Irq, vm_superio::serial::NoEvents, Box<dyn std::io::Write + Send>>>;

/// An in-process KVM microVM: the KVM handle, the VM fd, the guest memory
/// mapping, and the created vCPUs. Dropping it tears the VM down (closes the fds
/// + unmaps guest memory).
pub struct EmbeddedVmm {
    // Held for the VM's lifetime; the VM fd is derived from it.
    _kvm: Kvm,
    // `Arc` so a clone can be shared with the virtio-net RX thread (which injects
    // device IRQs via `set_irq_line` while the vCPU runs on the main thread).
    vm: Arc<VmFd>,
    guest_mem: GuestMemoryMmap,
    vcpus: Vec<VcpuFd>,
    mem_bytes: u64,
    /// COM1 interrupt eventfd (irqfd-registered), when an irqchip is present.
    com1_irq: Option<EventFd>,
}

impl EmbeddedVmm {
    /// Create a VM with `mem_bytes` of guest RAM and `vcpu_count` vCPUs, map +
    /// register guest memory, and write the static boot tables (GDT + identity
    /// page tables) into guest RAM. **No in-kernel irqchip** — so the guest's
    /// `HLT` exits to userspace (`KVM_EXIT_HLT`). Right for a self-contained
    /// payload that halts to signal completion; the device path uses
    /// [`with_irqchip`](Self::with_irqchip). Needs `/dev/kvm`.
    pub fn new(mem_bytes: u64, vcpu_count: u8) -> Result<Self, VmmError> {
        Self::build(mem_bytes, vcpu_count, false)
    }

    /// Like [`new`](Self::new) but with an in-kernel **irqchip** (PIC + IOAPIC +
    /// LAPICs) + PIT, created before the vCPUs (KVM requires that order). Needed
    /// for IRQ delivery to virtio devices ([`set_irq`](Self::set_irq) / the
    /// device-manager run loop).
    ///
    /// ⚠️ With an in-kernel LAPIC the guest's `HLT` does **not** exit to
    /// userspace — the vCPU halts in-kernel until an interrupt arrives. That's
    /// correct for a real guest that idles waiting on device IRQs, but a bare
    /// payload that `hlt`s to finish would block forever (use [`new`](Self::new)
    /// for those).
    pub fn with_irqchip(mem_bytes: u64, vcpu_count: u8) -> Result<Self, VmmError> {
        Self::build(mem_bytes, vcpu_count, true)
    }

    fn build(mem_bytes: u64, vcpu_count: u8, with_irqchip: bool) -> Result<Self, VmmError> {
        let kvm = Kvm::new().map_err(|e| VmmError::Kvm(format!("open /dev/kvm: {e}")))?;
        let vm = kvm
            .create_vm()
            .map_err(|e| VmmError::Kvm(format!("create vm: {e}")))?;

        // In-kernel interrupt setup, before the vCPUs (which need the LAPIC): a
        // TSS region (required on Intel), the in-kernel irqchip (PIC + IOAPIC +
        // LAPICs), and the PIT timer — so the guest kernel boots past interrupt
        // init and virtio devices can raise IRQs. Skipped for the minimal `new`
        // path so a halting payload's `HLT` exits to userspace.
        let mut com1_irq = None;
        if with_irqchip {
            vm.set_tss_address(TSS_ADDRESS)
                .map_err(|e| VmmError::Kvm(format!("set tss: {e}")))?;
            vm.create_irq_chip()
                .map_err(|e| VmmError::Kvm(format!("create irqchip: {e}")))?;
            vm.create_pit2(kvm_pit_config::default())
                .map_err(|e| VmmError::Kvm(format!("create pit: {e}")))?;
            // COM1 interrupt line via an irqfd: signalling the eventfd injects
            // GSI 4 so the guest's interrupt-driven 8250 console driver works.
            let fd = EventFd::new(EFD_NONBLOCK)
                .map_err(|e| VmmError::Kvm(format!("com1 eventfd: {e}")))?;
            vm.register_irqfd(&fd, COM1_GSI)
                .map_err(|e| VmmError::Kvm(format!("register com1 irqfd: {e}")))?;
            com1_irq = Some(fd);
        }

        // Guest RAM laid out by the pure layer, mmap'd + registered with KVM.
        let guest_mem = map_guest_ram(&vm, mem_bytes)?;

        // With an irqchip, give the guest an MP table so it discovers the IO-APIC
        // and routes the legacy IRQs (timer IRQ0, COM1 IRQ4) — without it the
        // kernel falls back to APIC virtual-wire mode, never gets a timer tick,
        // and hangs at its first idle.
        if with_irqchip {
            guest_mem
                .write_slice(
                    &crate::mptable::build(vcpu_count),
                    GuestAddress(crate::mptable::MPTABLE_START),
                )
                .map_err(|e| VmmError::Memory(format!("write mptable: {e}")))?;
        }

        // vCPUs, each seeded with the host's KVM-supported CPUID — a real guest
        // kernel reads CPUID for feature detection and faults early without it (a
        // bare payload doesn't care, but it's harmless there).
        let cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| VmmError::Kvm(format!("get_supported_cpuid: {e}")))?;
        let mut vcpus = Vec::with_capacity(usize::from(vcpu_count));
        for id in 0..vcpu_count {
            let vcpu = vm
                .create_vcpu(u64::from(id))
                .map_err(|e| VmmError::Kvm(format!("create vcpu {id}: {e}")))?;
            // Each vCPU's CPUID must report **its own** local-APIC id, or the guest
            // can't tell the processors apart and SMP bring-up of the APs hangs.
            let mut vcpu_cpuid = cpuid.clone();
            set_cpuid_apic_id(&mut vcpu_cpuid, id);
            vcpu.set_cpuid2(&vcpu_cpuid)
                .map_err(|e| VmmError::Kvm(format!("set_cpuid2 vcpu {id}: {e}")))?;
            // Full guest-boot vCPU init (à la Firecracker): the boot MSRs (incl.
            // MTRR default-type = writeback, so guest RAM is cached, not the
            // glacial uncached default), a clean FPU state, and LINT0=ExtINT /
            // LINT1=NMI on the LAPIC.
            if with_irqchip {
                setup_msrs(&vcpu)?;
                setup_fpu(&vcpu)?;
                set_lint(&vcpu)?;
            }
            vcpus.push(vcpu);
        }

        write_boot_tables(&guest_mem)?;

        Ok(Self {
            _kvm: kvm,
            vm: Arc::new(vm),
            guest_mem,
            vcpus,
            mem_bytes,
            com1_irq,
        })
    }

    /// Program vCPU 0's segment + control registers for the 64-bit boot: the
    /// GDT-selected flat code/data segments, the GDT pointer, CR0/CR3/CR4/EFER
    /// (long mode + paging), `RSI`/`RFLAGS`, and `RIP = entry` — the guest entry
    /// point: [`HIMEM_START`] for a bare payload, or the value returned by
    /// [`load_kernel`](Self::load_kernel) (the kernel's ELF entry) for a real
    /// kernel. Needs `/dev/kvm`.
    pub fn setup_registers(&self, entry: u64) -> Result<(), VmmError> {
        let vcpu = self
            .vcpus
            .first()
            .ok_or_else(|| VmmError::Kvm("no vcpu to configure".into()))?;
        let gdt = boot_gdt();
        let code = segment_from_gdt(gdt[1], 1);
        let data = segment_from_gdt(gdt[2], 2);

        let mut sregs = vcpu
            .get_sregs()
            .map_err(|e| VmmError::Kvm(format!("get_sregs: {e}")))?;
        sregs.cs = code;
        sregs.ds = data;
        sregs.es = data;
        sregs.fs = data;
        sregs.gs = data;
        sregs.ss = data;
        sregs.gdt.base = BOOT_GDT_OFFSET;
        sregs.gdt.limit = (gdt.len() * 8 - 1) as u16;

        let r = boot_regs();
        sregs.cr0 = r.cr0;
        sregs.cr3 = r.cr3;
        sregs.cr4 = r.cr4;
        sregs.efer = r.efer;
        vcpu.set_sregs(&sregs)
            .map_err(|e| VmmError::Kvm(format!("set_sregs: {e}")))?;

        let regs = kvm_regs {
            rip: entry,
            rsi: r.rsi,
            rflags: r.rflags,
            ..Default::default()
        };
        vcpu.set_regs(&regs)
            .map_err(|e| VmmError::Kvm(format!("set_regs: {e}")))?;
        Ok(())
    }

    /// Write the kernel command line (NUL-terminated, at [`CMDLINE_START`]) and
    /// the `boot_params` zero page (at [`ZERO_PAGE_START`]) into guest RAM, with
    /// the e820 map for this VM's memory size. Call before running the vCPUs.
    pub fn write_boot_params(&self, cmdline: &str) -> Result<(), VmmError> {
        let mut cl = cmdline.as_bytes().to_vec();
        cl.push(0); // the kernel expects a NUL-terminated cmdline
        self.guest_mem
            .write_slice(&cl, GuestAddress(CMDLINE_START))
            .map_err(|e| VmmError::Memory(format!("write cmdline: {e}")))?;

        let zp = build_zero_page(
            &e820_entries(self.mem_bytes),
            CMDLINE_START,
            cl.len() as u32,
        )
        .map_err(|e| VmmError::Memory(e.to_string()))?;
        self.guest_mem
            .write_slice(&zp, GuestAddress(ZERO_PAGE_START))
            .map_err(|e| VmmError::Memory(format!("write zero page: {e}")))?;
        Ok(())
    }

    /// Load a `vmlinux` ELF kernel image into guest RAM: its `PT_LOAD` segments
    /// go to their ELF physical addresses (high memory starting at
    /// [`HIMEM_START`]). Returns the guest address the kernel image was loaded at.
    /// The run-loop slice points `RIP` at the kernel's entry. Needs a 64-bit ELF
    /// `vmlinux` (a `bzImage` is the `bzimage` loader, a later addition).
    pub fn load_kernel(&self, kernel_path: &Path) -> Result<GuestAddress, VmmError> {
        let mut image = File::open(kernel_path)
            .map_err(|e| VmmError::Memory(format!("open kernel {}: {e}", kernel_path.display())))?;
        let loaded = Elf::load(
            &self.guest_mem,
            None,
            &mut image,
            Some(GuestAddress(HIMEM_START)),
        )
        .map_err(|e| VmmError::Kvm(format!("load kernel elf: {e}")))?;
        Ok(loaded.kernel_load)
    }

    /// Run the primary vCPU until the guest halts or shuts down. COM1 port I/O is
    /// driven by a full 16550 [`Serial`] model (output to `out`, COM1 IRQ raised
    /// via the irqfd when present — so the kernel's interrupt-driven console
    /// works, not just polled early-boot); virtio-MMIO reads/writes are dispatched
    /// to the device `manager`, with a used-ring-advancing notify pulsing the
    /// device's IRQ line. Needs `/dev/kvm`.
    pub fn run_primary_vcpu(
        &mut self,
        manager: &mut DeviceManager,
        out: &mut dyn std::io::Write,
    ) -> Result<VmExit, VmmError> {
        // The 16550 COM1 model: its IRQ is the irqfd (a no-op trigger on the
        // minimal/no-irqchip path, where the guest uses the UART in polled mode).
        let trigger = Com1Irq(
            self.com1_irq
                .as_ref()
                .map(|fd| fd.try_clone().expect("clone com1 eventfd")),
        );
        let mut serial = Serial::new(trigger, out);

        // Split the borrows: the vCPU (self.vcpus) is driven in the loop while the
        // MMIO handlers touch the disjoint `guest_mem` + `vm` fields.
        let vm = &self.vm;
        let mem = &self.guest_mem;
        let vcpu = self
            .vcpus
            .first_mut()
            .ok_or_else(|| VmmError::Kvm("no vcpu to run".into()))?;
        loop {
            let exit = vcpu
                .run()
                .map_err(|e| VmmError::Kvm(format!("vcpu run: {e}")))?;
            match exit {
                VcpuExit::IoOut(port, data) if (COM1_BASE..=COM1_LAST).contains(&port) => {
                    for &b in data {
                        serial
                            .write((port - COM1_BASE) as u8, b)
                            .map_err(|e| VmmError::Memory(format!("serial write: {e:?}")))?;
                    }
                }
                VcpuExit::IoIn(port, data) if (COM1_BASE..=COM1_LAST).contains(&port) => {
                    let v = serial.read((port - COM1_BASE) as u8);
                    data.iter_mut().for_each(|b| *b = v);
                }
                VcpuExit::IoIn(_, data) => data.iter_mut().for_each(|b| *b = 0), // other PIO in
                VcpuExit::MmioRead(addr, data) => manager.mmio_read(addr, data),
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(gsi) = manager.mmio_write(addr, data, mem)? {
                        // Edge-pulse the device's IRQ line (raise then lower); the
                        // driver wakes, reads the used ring + InterruptStatus, ACKs.
                        vm.set_irq_line(gsi, true)
                            .and_then(|()| vm.set_irq_line(gsi, false))
                            .map_err(|e| VmmError::Kvm(format!("pulse irq {gsi}: {e}")))?;
                    }
                }
                VcpuExit::IoOut(..) => {} // other PIO out
                VcpuExit::Hlt => return Ok(VmExit::Halted),
                VcpuExit::Shutdown => return Ok(VmExit::Shutdown),
                other => return Err(VmmError::Kvm(format!("unexpected vcpu exit: {other:?}"))),
            }
        }
    }

    /// Run **all** vCPUs (one OS thread each) against a **shared** device
    /// `manager` (behind an `Arc<Mutex<…>>`), with optional **virtio-net** + a
    /// clean external **stop**.
    ///
    /// * `net = Some((index, rx_tap))` spawns a thread that `poll`s `rx_tap` for
    ///   inbound frames and delivers them into the net device at `index`'s RX
    ///   queue (pulsing its IRQ); `None` runs without networking.
    /// * `stop` + `vcpu_tid` make it stoppable: vCPU 0's thread id is published
    ///   into `vcpu_tid`, and [`interrupt_vcpu`] (set `stop` first) breaks its
    ///   blocked `KVM_RUN`. When **any** vCPU ends (a guest power-off, an external
    ///   stop, or an error) it sets `stop` + signals the rest, so they all unwind
    ///   and the run returns. The COM1 serial + the device bus are shared (locked
    ///   per access; multi-vCPU contention is rare — the console lives on vCPU 0).
    ///
    /// Needs `/dev/kvm` + an [`with_irqchip`](Self::with_irqchip) VM (for the
    /// device/IRQ path; a bare halting payload uses [`new`](Self::new)).
    pub fn run_with_net(
        &mut self,
        manager: Arc<Mutex<DeviceManager>>,
        net: Option<(usize, Tap)>,
        stop: Arc<AtomicBool>,
        vcpu_tid: Arc<AtomicU64>,
        out: Box<dyn std::io::Write + Send>,
    ) -> Result<VmExit, VmmError> {
        install_vcpu_signal_handler();

        // The shared 16550 COM1 model: one trigger (the irqfd), locked per access.
        let trigger = Com1Irq(
            self.com1_irq
                .as_ref()
                .map(|fd| fd.try_clone().expect("clone com1 eventfd")),
        );
        let serial: Arc<SharedSerial> = Arc::new(Mutex::new(Serial::new(trigger, out)));

        if let Some((net_index, _)) = &net {
            if manager
                .lock()
                .expect("device manager mutex")
                .windows()
                .get(*net_index)
                .is_none()
            {
                return Err(VmmError::Kvm(format!("no device at index {net_index}")));
            }
        }
        let rx_thread = net.map(|(net_index, rx_tap)| {
            // The RX poller shares the manager + a guest-memory clone (same backing
            // mmap) + the VM fd (for IRQ injection) — all `Send`.
            let (rx_mem, rx_vm, rx_mgr, rx_stop) = (
                self.guest_mem.clone(),
                self.vm.clone(),
                manager.clone(),
                stop.clone(),
            );
            std::thread::Builder::new()
                .name("virtio-net-rx".into())
                .spawn(move || rx_poll_loop(rx_tap, &rx_mgr, &rx_mem, &rx_vm, net_index, &rx_stop))
                .expect("spawn rx thread")
        });

        // One thread per vCPU.
        let vcpus = std::mem::take(&mut self.vcpus);
        if vcpus.is_empty() {
            return Err(VmmError::Kvm("no vcpu to run".into()));
        }
        let tids: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::with_capacity(vcpus.len());
        for (i, vcpu) in vcpus.into_iter().enumerate() {
            let (mgr, ser, vm, mem, st, tds, vtid) = (
                manager.clone(),
                serial.clone(),
                self.vm.clone(),
                self.guest_mem.clone(),
                stop.clone(),
                tids.clone(),
                vcpu_tid.clone(),
            );
            let handle = std::thread::Builder::new()
                .name(format!("vcpu-{i}"))
                .spawn(move || {
                    let mut vcpu = vcpu;
                    let tid = pthread_self() as u64;
                    tds.lock().expect("vcpu tids").push(tid);
                    if i == 0 {
                        vtid.store(tid, Ordering::SeqCst);
                    }
                    let r = run_one_vcpu(&mut vcpu, &mgr, &ser, &vm, &mem, &st);
                    if std::env::var_os("BOATRAMP_VMM_SERIAL").is_some() {
                        eprintln!("vmm: vcpu {i} ended: {r:?}");
                    }
                    // This vCPU ended → wind the others (blocked in KVM_RUN) down.
                    st.store(true, Ordering::SeqCst);
                    interrupt_all_vcpus(&tds);
                    // Hand the (now paused) vCPU back so the VM stays snapshottable
                    // after the run loop stops.
                    (i, vcpu, r)
                })
                .map_err(|e| VmmError::Kvm(format!("spawn vcpu {i}: {e}")))?;
            handles.push(handle);
        }

        // Join every vCPU, then the RX poller. The run's outcome is the most
        // informative exit: an error, else a guest halt/shutdown, else Stopped.
        // Reclaim each (paused) vCPU into `self.vcpus`, restoring run order.
        let mut outcome: Result<VmExit, VmmError> = Ok(VmExit::Stopped);
        let mut reclaimed: Vec<(usize, VcpuFd)> = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.join() {
                Ok((i, vcpu, r)) => {
                    reclaimed.push((i, vcpu));
                    outcome = merge_exit(outcome, r);
                }
                Err(_) => {
                    outcome =
                        merge_exit(outcome, Err(VmmError::Kvm("vcpu thread panicked".into())));
                }
            }
        }
        reclaimed.sort_by_key(|(i, _)| *i);
        self.vcpus = reclaimed.into_iter().map(|(_, vcpu)| vcpu).collect();
        stop.store(true, Ordering::Relaxed);
        if let Some(handle) = rx_thread {
            let _ = handle.join();
        }
        outcome
    }

    /// Drive guest IRQ line `gsi` to `active` (the in-kernel irqchip delivers it).
    /// The device-bus raises a virtio device's line after putting buffers on its
    /// used ring, and lowers it once the guest ACKs.
    pub fn set_irq(&self, gsi: u32, active: bool) -> Result<(), VmmError> {
        self.vm
            .set_irq_line(gsi, active)
            .map_err(|e| VmmError::Kvm(format!("set irq line {gsi}: {e}")))
    }

    /// The VM fd (for IRQ chip / device wiring in later slices).
    pub fn vm(&self) -> &VmFd {
        &self.vm
    }

    /// The guest memory mapping (for the kernel load + zero-page write).
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_mem
    }

    /// The created vCPUs (for register setup + the run loop).
    pub fn vcpus(&self) -> &[VcpuFd] {
        &self.vcpus
    }

    /// Capture this **paused** VM's CPU + chip state:
    /// every vCPU's full architectural state + (with an irqchip) the in-kernel
    /// chip state. The vCPUs must not be inside `KVM_RUN` (stop the run loop
    /// first). The guest RAM is streamed separately via [`dump_ram`](Self::dump_ram)
    /// — keeping the small structured state and the large RAM as distinct steps so
    /// a framed snapshot stream can write a header before the RAM.
    pub fn capture_state(&self) -> Result<VmSnapshot, VmmError> {
        let has_irqchip = self.com1_irq.is_some();
        let mut vcpus = Vec::with_capacity(self.vcpus.len());
        for vcpu in &self.vcpus {
            vcpus.push(capture_vcpu(&self._kvm, vcpu, has_irqchip)?);
        }
        let (irqchips, pit, clock) = if has_irqchip {
            (
                Some(capture_irqchips(&self.vm)?),
                Some(
                    self.vm
                        .get_pit2()
                        .map_err(|e| VmmError::Kvm(format!("get_pit2: {e}")))?,
                ),
                Some(
                    self.vm
                        .get_clock()
                        .map_err(|e| VmmError::Kvm(format!("get_clock: {e}")))?,
                ),
            )
        } else {
            (None, None, None)
        };
        Ok(VmSnapshot {
            mem_bytes: self.mem_bytes,
            has_irqchip,
            vcpus,
            irqchips,
            pit,
            clock,
        })
    }

    /// Stream the guest RAM (in layout order) to `out`, for the RAM half of a
    /// snapshot. Pairs with [`capture_state`](Self::capture_state).
    pub fn dump_ram(&self, out: &mut dyn std::io::Write) -> Result<(), VmmError> {
        dump_guest_ram(&self.guest_mem, out)
    }

    /// **Snapshot** this **paused** VM: [`capture_state`](Self::capture_state) plus
    /// the guest RAM streamed to `mem_out`. The returned [`VmSnapshot`] + the
    /// memory stream reconstruct the VM exactly via [`restore`](Self::restore).
    pub fn snapshot(&self, mem_out: &mut dyn std::io::Write) -> Result<VmSnapshot, VmmError> {
        let snap = self.capture_state()?;
        self.dump_ram(mem_out)?;
        Ok(snap)
    }

    /// **Restore** a VM from a [`snapshot`](Self::snapshot) + its `mem_in` memory
    /// stream: create a fresh VM (irqchip + PIT if the snapshot had them), map +
    /// reload the guest RAM, restore the chip + per-vCPU state, and return a VM
    /// ready to **resume** (run its vCPUs — they continue from the captured RIP).
    /// Needs `/dev/kvm`.
    pub fn restore(
        snapshot: &VmSnapshot,
        mem_in: &mut dyn std::io::Read,
    ) -> Result<Self, VmmError> {
        let kvm = Kvm::new().map_err(|e| VmmError::Kvm(format!("open /dev/kvm: {e}")))?;
        let vm = kvm
            .create_vm()
            .map_err(|e| VmmError::Kvm(format!("create vm: {e}")))?;

        let mut com1_irq = None;
        if snapshot.has_irqchip {
            vm.set_tss_address(TSS_ADDRESS)
                .map_err(|e| VmmError::Kvm(format!("set tss: {e}")))?;
            vm.create_irq_chip()
                .map_err(|e| VmmError::Kvm(format!("create irqchip: {e}")))?;
            vm.create_pit2(kvm_pit_config::default())
                .map_err(|e| VmmError::Kvm(format!("create pit: {e}")))?;
            let fd = EventFd::new(EFD_NONBLOCK)
                .map_err(|e| VmmError::Kvm(format!("com1 eventfd: {e}")))?;
            vm.register_irqfd(&fd, COM1_GSI)
                .map_err(|e| VmmError::Kvm(format!("register com1 irqfd: {e}")))?;
            com1_irq = Some(fd);
        }

        // Map guest RAM + reload its contents (incl. the GDT/page-tables/MP-table
        // that were in RAM — the restored sregs point at them, so no re-init).
        let guest_mem = map_guest_ram(&vm, snapshot.mem_bytes)?;
        load_guest_ram(&guest_mem, mem_in)?;

        // Chip state before the vCPUs (KVM requires the irqchip to exist first).
        if snapshot.has_irqchip {
            if let Some(chips) = &snapshot.irqchips {
                apply_irqchips(&vm, chips)?;
            }
            if let Some(pit) = &snapshot.pit {
                vm.set_pit2(pit)
                    .map_err(|e| VmmError::Kvm(format!("set_pit2: {e}")))?;
            }
            if let Some(clock) = &snapshot.clock {
                vm.set_clock(clock)
                    .map_err(|e| VmmError::Kvm(format!("set_clock: {e}")))?;
            }
        }

        let mut vcpus = Vec::with_capacity(snapshot.vcpus.len());
        for (id, snap) in snapshot.vcpus.iter().enumerate() {
            let vcpu = vm
                .create_vcpu(id as u64)
                .map_err(|e| VmmError::Kvm(format!("create vcpu {id}: {e}")))?;
            apply_vcpu(&vcpu, snap)?;
            vcpus.push(vcpu);
        }

        Ok(Self {
            _kvm: kvm,
            vm: Arc::new(vm),
            guest_mem,
            vcpus,
            mem_bytes: snapshot.mem_bytes,
            com1_irq,
        })
    }
}

/// Lay out guest RAM (per [`ram_regions`]) as an mmap and register each region as
/// a KVM memory slot. Shared by [`EmbeddedVmm::build`] and `restore`.
fn map_guest_ram(vm: &VmFd, mem_bytes: u64) -> Result<GuestMemoryMmap, VmmError> {
    let ranges: Vec<(GuestAddress, usize)> = ram_regions(mem_bytes)
        .into_iter()
        .map(|r| (GuestAddress(r.start), r.size as usize))
        .collect();
    let guest_mem = GuestMemoryMmap::from_ranges(&ranges)
        .map_err(|e| VmmError::Memory(format!("map guest memory: {e}")))?;
    for (slot, region) in guest_mem.iter().enumerate() {
        let mr = kvm_userspace_memory_region {
            slot: slot as u32,
            flags: 0,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: region.as_ptr() as u64,
        };
        // SAFETY: `region`'s mapping is owned by `guest_mem` for the VM's whole
        // lifetime, and the slot describes exactly that mapping.
        unsafe { vm.set_user_memory_region(mr) }
            .map_err(|e| VmmError::Kvm(format!("set memory region {slot}: {e}")))?;
    }
    Ok(guest_mem)
}

/// Stream every guest-RAM region (in layout order) to `out` for a snapshot.
fn dump_guest_ram(mem: &GuestMemoryMmap, out: &mut dyn std::io::Write) -> Result<(), VmmError> {
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB chunks
    for region in mem.iter() {
        let len = region.len();
        let mut off = 0u64;
        while off < len {
            let n = ((len - off) as usize).min(buf.len());
            mem.read_slice(&mut buf[..n], region.start_addr().checked_add(off).unwrap())
                .map_err(|e| VmmError::Memory(format!("read guest ram: {e}")))?;
            out.write_all(&buf[..n])
                .map_err(|e| VmmError::Memory(format!("write snapshot ram: {e}")))?;
            off += n as u64;
        }
    }
    Ok(())
}

/// Reload every guest-RAM region (in layout order) from `inp` on restore.
fn load_guest_ram(mem: &GuestMemoryMmap, inp: &mut dyn std::io::Read) -> Result<(), VmmError> {
    let mut buf = vec![0u8; 1 << 20];
    for region in mem.iter() {
        let len = region.len();
        let mut off = 0u64;
        while off < len {
            let n = ((len - off) as usize).min(buf.len());
            inp.read_exact(&mut buf[..n])
                .map_err(|e| VmmError::Memory(format!("read snapshot ram: {e}")))?;
            mem.write_slice(&buf[..n], region.start_addr().checked_add(off).unwrap())
                .map_err(|e| VmmError::Memory(format!("write guest ram: {e}")))?;
            off += n as u64;
        }
    }
    Ok(())
}

/// Fix up a vCPU's CPUID for the VM's (single-socket, no-SMT) topology so the
/// guest can tell the processors apart — required for SMP, else the APs report
/// APIC id 0 like the BSP and bring-up hangs. Sets leaf 1 `EBX[31:24]` = the
/// initial APIC id, and **invalidates the host's x2APIC topology leaves**
/// (`0xB`/`0x1F`, which carry the host's core/thread counts — wrong for the VM)
/// so the guest falls back to the legacy leaf-1 + MP-table topology.
fn set_cpuid_apic_id(cpuid: &mut kvm_bindings::CpuId, apic_id: u8) {
    for entry in cpuid.as_mut_slice() {
        match entry.function {
            1 => entry.ebx = (entry.ebx & 0x00ff_ffff) | (u32::from(apic_id) << 24),
            // EBX = 0 (no logical processors enumerated at this level) makes the
            // guest's extended-topology detection bail out → legacy fallback.
            0xb | 0x1f => {
                entry.eax = 0;
                entry.ebx = 0;
                entry.ecx = entry.index & 0xff;
                entry.edx = u32::from(apic_id);
            }
            _ => {}
        }
    }
}

/// Write the architectural boot MSRs (à la Firecracker's `create_boot_msr_entries`):
/// SYSENTER/SYSCALL bases cleared, TSC = 0, `IA32_MISC_ENABLE` = fast-strings,
/// and `MTRRdefType` = MTRRs-enabled + writeback (so guest RAM is cached).
fn setup_msrs(vcpu: &VcpuFd) -> Result<(), VmmError> {
    const MSR_IA32_SYSENTER_CS: u32 = 0x174;
    const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
    const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
    const MSR_IA32_TSC: u32 = 0x10;
    const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;
    const MSR_MTRR_DEF_TYPE: u32 = 0x2ff;
    const MSR_STAR: u32 = 0xc000_0081;
    const MSR_LSTAR: u32 = 0xc000_0082;
    const MSR_CSTAR: u32 = 0xc000_0083;
    const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
    const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;
    const MISC_ENABLE_FAST_STRING: u64 = 0x1;
    const MTRR_ENABLE_WRITEBACK: u64 = (1 << 11) | 0x6;

    let entry = |index, data| kvm_msr_entry {
        index,
        data,
        ..Default::default()
    };
    let entries = [
        entry(MSR_IA32_SYSENTER_CS, 0),
        entry(MSR_IA32_SYSENTER_ESP, 0),
        entry(MSR_IA32_SYSENTER_EIP, 0),
        entry(MSR_STAR, 0),
        entry(MSR_CSTAR, 0),
        entry(MSR_KERNEL_GS_BASE, 0),
        entry(MSR_SYSCALL_MASK, 0),
        entry(MSR_LSTAR, 0),
        entry(MSR_IA32_TSC, 0),
        entry(MSR_IA32_MISC_ENABLE, MISC_ENABLE_FAST_STRING),
        entry(MSR_MTRR_DEF_TYPE, MTRR_ENABLE_WRITEBACK),
    ];
    let msrs =
        Msrs::from_entries(&entries).map_err(|e| VmmError::Kvm(format!("build msrs: {e:?}")))?;
    let written = vcpu
        .set_msrs(&msrs)
        .map_err(|e| VmmError::Kvm(format!("set_msrs: {e}")))?;
    if written != entries.len() {
        return Err(VmmError::Kvm(format!(
            "set_msrs wrote {written}/{} entries",
            entries.len()
        )));
    }
    Ok(())
}

/// Set a clean x87/SSE FPU state (control word `0x37f`, MXCSR `0x1f80`).
fn setup_fpu(vcpu: &VcpuFd) -> Result<(), VmmError> {
    let fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu)
        .map_err(|e| VmmError::Kvm(format!("set_fpu: {e}")))
}

/// Configure vCPU's local-APIC LINT0/LINT1 delivery modes: LINT0 = ExtINT (so
/// the LAPIC accepts the 8259 PIC's interrupt line — the legacy timer path),
/// LINT1 = NMI. Reads the LAPIC state, rewrites the delivery-mode field (bits
/// 8–10) of the `LVT LINT0` (`0x350`) + `LVT LINT1` (`0x360`) registers, and
/// writes it back. Mirrors Firecracker's `interrupts::set_lint`.
fn set_lint(vcpu: &VcpuFd) -> Result<(), VmmError> {
    const APIC_LVT0: usize = 0x350;
    const APIC_LVT1: usize = 0x360;
    const MODE_EXTINT: u32 = 0x7;
    const MODE_NMI: u32 = 0x4;

    let mut klapic = vcpu
        .get_lapic()
        .map_err(|e| VmmError::Kvm(format!("get_lapic: {e}")))?;
    for (off, mode) in [(APIC_LVT0, MODE_EXTINT), (APIC_LVT1, MODE_NMI)] {
        let cur = u32::from_le_bytes([
            klapic.regs[off] as u8,
            klapic.regs[off + 1] as u8,
            klapic.regs[off + 2] as u8,
            klapic.regs[off + 3] as u8,
        ]);
        let new = (cur & !0x700) | (mode << 8);
        for (i, b) in new.to_le_bytes().into_iter().enumerate() {
            klapic.regs[off + i] = b as i8;
        }
    }
    vcpu.set_lapic(&klapic)
        .map_err(|e| VmmError::Kvm(format!("set_lapic: {e}")))
}

/// Decode a GDT descriptor `entry` (at GDT `table_index`) into the `kvm_segment`
/// the guest's segment register expects — base/limit + the type/flags bits, with
/// the selector = `table_index << 3`. Mirrors Firecracker's `gdt::segment_from_gdt`.
fn segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    let bit = |shift: u64| ((entry >> shift) & 1) as u8;
    let base = ((entry & 0xff00_0000_0000_0000) >> 32)
        | ((entry & 0x0000_00ff_0000_0000) >> 16)
        | ((entry & 0x0000_0000_ffff_0000) >> 16);
    let limit = (((entry & 0x000f_0000_0000_0000) >> 32) | (entry & 0x0000_0000_0000_ffff)) as u32;
    let present = bit(47);
    kvm_segment {
        base,
        limit,
        selector: u16::from(table_index) << 3,
        type_: ((entry >> 40) & 0xf) as u8,
        present,
        dpl: ((entry >> 45) & 0x3) as u8,
        db: bit(54),
        s: bit(44),
        l: bit(53),
        g: bit(55),
        avl: bit(52),
        unusable: u8::from(present == 0),
        padding: 0,
    }
}

/// Build a rust-vmm split [`Queue`] from the transport's latched [`QueueConfig`]
/// (size, ready flag, and the descriptor-table / available-ring / used-ring guest
/// addresses). The device backends call this when the driver marks a queue ready.
pub fn build_queue(cfg: &QueueConfig, max_size: u16) -> Result<Queue, VmmError> {
    let mut q = Queue::new(max_size).map_err(|e| VmmError::Kvm(format!("queue new: {e}")))?;
    q.set_size(cfg.size);
    q.set_desc_table_address(Some(cfg.desc as u32), Some((cfg.desc >> 32) as u32));
    q.set_avail_ring_address(Some(cfg.avail as u32), Some((cfg.avail >> 32) as u32));
    q.set_used_ring_address(Some(cfg.used as u32), Some((cfg.used >> 32) as u32));
    q.set_ready(cfg.ready);
    Ok(q)
}

/// Pop each available descriptor chain on `queue`, hand it to `handle` (the device
/// services the request, filling the guest's writable descriptors, and returns the
/// number of bytes written), then place the chain's head on the used ring. The
/// reusable per-notification loop every virtio device backend (block/net) drives.
pub fn drain_available<'m>(
    queue: &mut Queue,
    mem: &'m GuestMemoryMmap,
    mut handle: impl FnMut(DescriptorChain<&'m GuestMemoryMmap>) -> u32,
) -> Result<(), VmmError> {
    while let Some(chain) = queue.pop_descriptor_chain(mem) {
        let head = chain.head_index();
        let written = handle(chain);
        queue
            .add_used(mem, head, written)
            .map_err(|e| VmmError::Kvm(format!("add_used: {e}")))?;
    }
    Ok(())
}

/// Write the static boot tables into guest RAM: the 3-entry boot GDT (24 bytes
/// at [`BOOT_GDT_OFFSET`]) and the identity page tables (one little-endian u64
/// per [`crate::embedded::PageTableEntry`]).
fn write_boot_tables(mem: &GuestMemoryMmap) -> Result<(), VmmError> {
    let gdt = boot_gdt();
    let mut gdt_bytes = [0u8; 24];
    for (i, entry) in gdt.iter().enumerate() {
        gdt_bytes[i * 8..i * 8 + 8].copy_from_slice(&entry.to_le_bytes());
    }
    mem.write_slice(&gdt_bytes, GuestAddress(BOOT_GDT_OFFSET))
        .map_err(|e| VmmError::Memory(format!("write GDT: {e}")))?;

    for ent in identity_page_tables() {
        mem.write_slice(&ent.value.to_le_bytes(), GuestAddress(ent.addr))
            .map_err(|e| VmmError::Memory(format!("write page table @{:#x}: {e}", ent.addr)))?;
    }
    Ok(())
}

/// The signal used to interrupt a blocked `KVM_RUN` for a clean VM stop. Its
/// handler is installed **without** `SA_RESTART`, so an interrupted `KVM_RUN`
/// surfaces `EINTR` to the run loop instead of auto-restarting.
///
/// `SIGUSR1` is the conventional vCPU-kick signal; embedding the VMM inside a
/// larger process means that process must not also use `SIGUSR1` for its own
/// purposes (a dedicated real-time signal would isolate it — a later refinement).
const VCPU_STOP_SIGNAL: Signal = Signal::SIGUSR1;

static VCPU_SIGNAL_INSTALLED: Once = Once::new();

/// No-op handler — its sole job is to interrupt the `KVM_RUN` syscall.
extern "C" fn vcpu_stop_handler(_: nix::libc::c_int) {}

/// Install the process-wide vCPU-stop signal handler (idempotent).
fn install_vcpu_signal_handler() {
    VCPU_SIGNAL_INSTALLED.call_once(|| {
        let action = SigAction::new(
            SigHandler::Handler(vcpu_stop_handler),
            SaFlags::empty(), // no SA_RESTART → KVM_RUN returns EINTR
            SigSet::empty(),
        );
        // SAFETY: the handler is async-signal-safe (it does nothing).
        unsafe {
            let _ = sigaction(VCPU_STOP_SIGNAL, &action);
        }
    });
}

/// Ask the vCPU thread that published its id into `vcpu_tid` to break out of a
/// blocked `KVM_RUN`, by sending it [`VCPU_STOP_SIGNAL`] (a no-op if no thread
/// has registered yet). Set the run loop's stop flag **before** calling this,
/// and resend in a loop until the VM thread exits — a signal that races
/// `KVM_RUN` entry can be missed, so one shot is not guaranteed to land.
pub fn interrupt_vcpu(vcpu_tid: &AtomicU64) {
    let tid = vcpu_tid.load(Ordering::SeqCst);
    if tid != 0 {
        let _ = pthread_kill(tid as Pthread, VCPU_STOP_SIGNAL);
    }
}

/// Signal **every** registered vCPU thread to break out of `KVM_RUN` (used when
/// one vCPU ends, to unwind the rest, which idle blocked in-kernel on `HLT`).
fn interrupt_all_vcpus(tids: &Mutex<Vec<u64>>) {
    for tid in tids.lock().expect("vcpu tids").iter() {
        let _ = pthread_kill(*tid as Pthread, VCPU_STOP_SIGNAL);
    }
}

/// Combine two vCPU run outcomes into the run's overall result, preferring the
/// most informative: an error, then a guest halt/shutdown, then `Stopped`.
fn merge_exit(
    acc: Result<VmExit, VmmError>,
    next: Result<VmExit, VmmError>,
) -> Result<VmExit, VmmError> {
    match (&acc, &next) {
        (Err(_), _) => acc,
        (_, Err(_)) => next,
        (Ok(VmExit::Stopped), _) => next, // any concrete exit beats Stopped
        _ => acc,
    }
}

/// One vCPU's run loop: drive `KVM_RUN`, dispatching COM1 serial + MMIO exits to
/// the shared `serial`/`manager` and pulsing device IRQs via `vm`. Returns when
/// the guest halts/shuts down, or — on an `EINTR` from [`interrupt_vcpu`] with
/// `stop` set — [`VmExit::Stopped`]. Run on its own thread by
/// [`EmbeddedVmm::run_with_net`]; the signal handler must already be installed.
fn run_one_vcpu(
    vcpu: &mut VcpuFd,
    manager: &Mutex<DeviceManager>,
    serial: &SharedSerial,
    vm: &VmFd,
    mem: &GuestMemoryMmap,
    stop: &AtomicBool,
) -> Result<VmExit, VmmError> {
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(VmExit::Stopped);
        }
        let exit = match vcpu.run() {
            Ok(exit) => exit,
            Err(e) if e.errno() == nix::libc::EINTR => {
                if stop.load(Ordering::Relaxed) {
                    return Ok(VmExit::Stopped);
                }
                continue;
            }
            // `EAGAIN`: this vCPU isn't runnable yet — an AP waiting for the BSP's
            // INIT-SIPI. Yield + retry (not fatal) until the SIPI boots it.
            Err(e) if e.errno() == nix::libc::EAGAIN => {
                if stop.load(Ordering::Relaxed) {
                    return Ok(VmExit::Stopped);
                }
                std::thread::yield_now();
                continue;
            }
            Err(e) => return Err(VmmError::Kvm(format!("vcpu run: {e}"))),
        };
        match exit {
            VcpuExit::IoOut(port, data) if (COM1_BASE..=COM1_LAST).contains(&port) => {
                let mut s = serial.lock().expect("serial");
                for &b in data {
                    s.write((port - COM1_BASE) as u8, b)
                        .map_err(|e| VmmError::Memory(format!("serial write: {e:?}")))?;
                }
            }
            VcpuExit::IoIn(port, data) if (COM1_BASE..=COM1_LAST).contains(&port) => {
                let v = serial
                    .lock()
                    .expect("serial")
                    .read((port - COM1_BASE) as u8);
                data.iter_mut().for_each(|b| *b = v);
            }
            VcpuExit::IoIn(_, data) => data.iter_mut().for_each(|b| *b = 0),
            VcpuExit::MmioRead(addr, data) => {
                manager
                    .lock()
                    .expect("device manager mutex")
                    .mmio_read(addr, data);
            }
            VcpuExit::MmioWrite(addr, data) => {
                let gsi = manager
                    .lock()
                    .expect("device manager mutex")
                    .mmio_write(addr, data, mem)?;
                if let Some(gsi) = gsi {
                    vm.set_irq_line(gsi, true)
                        .and_then(|()| vm.set_irq_line(gsi, false))
                        .map_err(|e| VmmError::Kvm(format!("pulse irq {gsi}: {e}")))?;
                }
            }
            VcpuExit::IoOut(..) => {}
            VcpuExit::Hlt => return Ok(VmExit::Halted),
            VcpuExit::Shutdown => return Ok(VmExit::Shutdown),
            other => return Err(VmmError::Kvm(format!("unexpected vcpu exit: {other:?}"))),
        }
    }
}

/// The virtio-net **RX poll loop**, run on a dedicated thread by
/// [`EmbeddedVmm::run_with_net`]: `poll` the `tap` for readable frames and
/// deliver each into the guest's RX queue (device `net_index`), pulsing the
/// device's IRQ when a guest buffer is filled. Returns when `stop` is set
/// (re-checked every poll timeout) or the tap closes/errors.
fn rx_poll_loop(
    mut tap: Tap,
    manager: &Mutex<DeviceManager>,
    mem: &GuestMemoryMmap,
    vm: &VmFd,
    net_index: usize,
    stop: &AtomicBool,
) {
    // One read returns one frame; size for a standard MTU + Ethernet/virtio slack.
    let mut buf = [0u8; 2048];
    let raw = tap.as_raw_fd();
    while !stop.load(Ordering::Relaxed) {
        // SAFETY: `raw` is `tap`'s fd; `tap` outlives this borrowed view, which is
        // used only for the `poll` call below.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match poll(&mut fds, 200u16) {
            Ok(0) => continue, // timed out — re-check `stop`
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
        let n = match std::io::Read::read(&mut tap, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        };
        // Deliver under the manager lock; pulse the IRQ outside it.
        let pulse =
            manager
                .lock()
                .expect("device manager mutex")
                .deliver_rx(net_index, &buf[..n], mem);
        if let Ok(Some(gsi)) = pulse {
            let _ = vm.set_irq_line(gsi, true);
            let _ = vm.set_irq_line(gsi, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_from_gdt_decodes_the_flat_long_mode_segments() {
        let gdt = boot_gdt();
        // Code segment (GDT index 1): flat, ring-0, 64-bit (L=1), present.
        let cs = segment_from_gdt(gdt[1], 1);
        assert_eq!(cs.base, 0);
        assert_eq!(cs.limit, 0xf_ffff);
        assert_eq!(cs.selector, 0x08, "index 1 → selector 8");
        assert_eq!(cs.present, 1);
        assert_eq!(cs.dpl, 0);
        assert_eq!(cs.s, 1, "code/data (not system) segment");
        assert_eq!(cs.l, 1, "64-bit segment");
        assert_eq!(cs.g, 1, "page-granular limit");
        assert_eq!(cs.type_, 0xb, "execute/read, accessed");
        assert_eq!(cs.unusable, 0);
        // Data segment (GDT index 2): selector 0x10, writable data.
        let ds = segment_from_gdt(gdt[2], 2);
        assert_eq!(ds.selector, 0x10);
        assert_eq!(ds.type_, 0x3, "read/write data, accessed");
        assert_eq!(ds.present, 1);
        assert_eq!(ds.l, 0);
    }

    #[test]
    fn build_queue_latches_the_config() {
        let cfg = QueueConfig {
            size: 64,
            ready: true,
            desc: 0x1_0000_2000,
            avail: 0x3000,
            used: 0x4000,
        };
        let q = build_queue(&cfg, 256).expect("build queue");
        assert_eq!(q.size(), 64);
        assert!(q.ready());
        assert_eq!(q.desc_table(), 0x1_0000_2000);
        assert_eq!(q.avail_ring(), 0x3000);
        assert_eq!(q.used_ring(), 0x4000);
    }

    #[test]
    fn drain_available_services_each_chain_and_advances_the_used_ring() {
        use virtio_queue::mock::MockSplitQueue;
        use virtio_queue::Descriptor;

        // VIRTQ_DESC_F_WRITE — a device-writable descriptor.
        const F_WRITE: u16 = 0x2;

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1_0000)]).unwrap();
        let vq = MockSplitQueue::new(&mem, 16);
        // One writable descriptor (a 256-byte buffer at guest 0x2000).
        let desc = Descriptor::new(0x2000, 0x100, F_WRITE, 0);
        vq.build_desc_chain(&[desc]).unwrap();
        let mut queue: Queue = vq.create_queue().unwrap();

        let mut serviced = 0u32;
        drain_available(&mut queue, &mem, |chain| {
            // The device sees exactly the one writable descriptor it was given.
            let descs: Vec<_> = chain.collect();
            assert_eq!(descs.len(), 1);
            assert!(descs[0].is_write_only());
            assert_eq!(descs[0].len(), 0x100);
            serviced += 1;
            0x100
        })
        .expect("drain");
        assert_eq!(serviced, 1, "the one available chain was serviced");
        // The used ring advanced by one element.
        let used = queue
            .used_idx(&mem, std::sync::atomic::Ordering::Acquire)
            .unwrap();
        assert_eq!(used, std::num::Wrapping(1));
    }

    /// Bring up a real KVM VM + configure its boot state. Ignored by default —
    /// needs `/dev/kvm` (the `compute-live` seam); run with `--ignored` on a KVM
    /// host.
    #[test]
    #[ignore = "creates a real KVM VM; needs /dev/kvm"]
    fn brings_up_a_kvm_vm_and_configures_boot() {
        let vmm = EmbeddedVmm::new(64 * 1024 * 1024, 2).expect("create embedded VM");
        assert_eq!(vmm.vcpus().len(), 2);
        assert!(vmm.guest_memory().iter().count() >= 1);
        vmm.setup_registers(HIMEM_START)
            .expect("program boot registers");
        vmm.write_boot_params("console=ttyS0 reboot=k panic=1")
            .expect("write boot params");
    }

    /// Boot a **real Linux kernel to its root-filesystem mount** on the embedded
    /// VMM. Self-skips unless `BOATRAMP_TEST_KERNEL` points at an uncompressed
    /// x86_64 `vmlinux` (ELF) and `/dev/kvm` is present.
    ///
    /// Proven by this test: the full from-scratch x86_64 boot — `with_irqchip`
    /// machine + CPUID + the boot **MSRs** (incl. MTRR writeback, so guest RAM is
    /// cached) + FPU + LAPIC LINT + the long-mode register state + the ELF kernel
    /// load + `boot_params`/e820 + the **MP table** (IO-APIC / "symmetric I/O
    /// mode") + the 16550 console — boots a real kernel **all the way through init
    /// to the root-device mount**: it runs every initcall and the scheduler (timer
    /// interrupts delivered), then panics `VFS: Unable to mount root fs` because no
    /// disk is attached. (A rootfs is the virtio-block slice.)
    ///
    /// The VM runs on a worker thread; the test polls the captured serial for the
    /// boot to complete (or a deadline) and asserts the markers — so it never
    /// hangs (the process exits and reaps the worker). Dispatch-only
    /// (`compute-live`).
    #[test]
    #[ignore = "boots a real Linux kernel; needs /dev/kvm + BOATRAMP_TEST_KERNEL=vmlinux"]
    fn boots_a_real_kernel_to_serial() {
        if std::env::var("BOATRAMP_TEST_KERNEL").is_err() {
            eprintln!("SKIP: set BOATRAMP_TEST_KERNEL=path/to/uncompressed/vmlinux");
            return;
        }
        if !std::path::Path::new("/dev/kvm").exists() {
            eprintln!("SKIP: /dev/kvm unavailable");
            return;
        }

        // The guest serial, shared with the worker thread. (Everything the worker
        // touches is created inside it, so nothing non-Send crosses the boundary.)
        let serial = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink_buf = serial.clone();
        std::thread::spawn(move || {
            let kernel = std::env::var("BOATRAMP_TEST_KERNEL").unwrap();
            let mut vmm = match EmbeddedVmm::with_irqchip(256 * 1024 * 1024, 1) {
                Ok(vmm) => vmm,
                Err(e) => {
                    eprintln!("worker: KVM unavailable: {e}");
                    return;
                }
            };
            let entry = vmm
                .load_kernel(Path::new(&kernel))
                .expect("load kernel elf");
            vmm.write_boot_params("console=ttyS0 reboot=k panic=1 pci=off")
                .expect("write boot params");
            vmm.setup_registers(entry.raw_value())
                .expect("program boot registers");

            struct SharedSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for SharedSink {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(b);
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut sink = SharedSink(sink_buf);
            let mut devices = DeviceManager::new(vec![]).expect("device manager");
            // Runs until the no-rootfs panic triple-faults into a shutdown.
            let _ = vmm.run_primary_vcpu(&mut devices, &mut sink);
        });

        // Poll the console until the kernel reaches the root-mount panic (boot
        // complete) or a deadline. Returns promptly once the boot finishes.
        let booted = |c: &str| c.contains("Unable to mount root fs");
        let mut console = String::new();
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            console = String::from_utf8_lossy(&serial.lock().unwrap()).into_owned();
            if booted(&console) {
                break;
            }
        }
        eprintln!("=== guest serial ({} bytes) ===\n{console}", console.len());
        assert!(
            console.contains("Linux version"),
            "kernel did not reach its serial console"
        );
        assert!(
            booted(&console),
            "kernel did not boot through to the root-fs mount"
        );
    }

    /// Boot a real Linux kernel **to a mounted root filesystem over virtio-block**.
    /// Self-skips unless `BOATRAMP_TEST_KERNEL` (vmlinux) + `BOATRAMP_TEST_ROOTFS`
    /// (an ext4 disk image) + `/dev/kvm` are present. Attaches the rootfs as a
    /// `virtio-block` device on the device manager, tells the guest about it via
    /// the `virtio_mmio.device=…` cmdline + `root=/dev/vda`, boots, and asserts the
    /// kernel mounts the ext4 root — proving the full virtio-MMIO transport + block
    /// device + IRQ delivery work against a real guest. Dispatch-only.
    #[test]
    #[ignore = "boots Linux on a virtio-block rootfs; needs /dev/kvm + BOATRAMP_TEST_KERNEL + BOATRAMP_TEST_ROOTFS"]
    fn boots_a_real_kernel_with_rootfs() {
        if std::env::var("BOATRAMP_TEST_KERNEL").is_err()
            || std::env::var("BOATRAMP_TEST_ROOTFS").is_err()
            || !std::path::Path::new("/dev/kvm").exists()
        {
            eprintln!("SKIP: need /dev/kvm + BOATRAMP_TEST_KERNEL=vmlinux + BOATRAMP_TEST_ROOTFS=rootfs.ext4");
            return;
        }

        let serial = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink_buf = serial.clone();
        std::thread::spawn(move || {
            use crate::embedded::mmio_cmdline_arg;
            use crate::virtio_block::{VirtioBlock, SECTOR_SIZE};
            let kernel = std::env::var("BOATRAMP_TEST_KERNEL").unwrap();
            let rootfs = std::env::var("BOATRAMP_TEST_ROOTFS").unwrap();

            let mut vmm = EmbeddedVmm::with_irqchip(512 * 1024 * 1024, 1).expect("create vm");
            let entry = vmm.load_kernel(Path::new(&kernel)).expect("load kernel");

            // virtio-block backed by the rootfs image file.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&rootfs)
                .expect("open rootfs");
            let sectors = file.metadata().unwrap().len() / SECTOR_SIZE;
            let block = VirtioBlock::new(file, sectors, false);
            let mut devices = DeviceManager::new(vec![Box::new(block)]).expect("device manager");

            // Tell the guest where the virtio-MMIO device is + which disk is root.
            let mmio: String = devices
                .windows()
                .iter()
                .map(mmio_cmdline_arg)
                .collect::<Vec<_>>()
                .join(" ");
            let cmdline = format!("console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw {mmio}");
            vmm.write_boot_params(&cmdline).expect("boot params");
            vmm.setup_registers(entry.raw_value()).expect("registers");

            struct SharedSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for SharedSink {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(b);
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut sink = SharedSink(sink_buf);
            let _ = vmm.run_primary_vcpu(&mut devices, &mut sink);
        });

        // Poll for the ext4 root mount (or a deadline). "mounted filesystem" is the
        // EXT4 driver confirming it read + mounted the disk over virtio-block.
        let mounted = |c: &str| {
            c.contains("EXT4-fs (vda): mounted filesystem")
                || c.contains("VFS: Mounted root (ext4 filesystem)")
        };
        let mut console = String::new();
        for _ in 0..120 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            console = String::from_utf8_lossy(&serial.lock().unwrap()).into_owned();
            if mounted(&console) || console.contains("Unable to mount root fs") {
                break;
            }
        }
        eprintln!("=== guest serial ({} bytes) ===\n{console}", console.len());
        assert!(
            console.contains("Linux version"),
            "kernel did not reach serial console"
        );
        assert!(
            mounted(&console),
            "kernel did not mount the ext4 root over virtio-block"
        );
    }

    /// Boot a real Linux kernel **SMP with 2 vCPUs** and assert the guest brings
    /// the second processor online — proving the multi-vCPU run loop (one thread
    /// per vCPU, the AP woken by the BSP's INIT-SIPI via the in-kernel LAPIC, the
    /// shared serial/bus, and the cross-vCPU stop). No rootfs: SMP bring-up happens
    /// during early init, before the root-mount panic that ends the run (which
    /// then unwinds both vCPU threads). Self-skips without `/dev/kvm` +
    /// `BOATRAMP_TEST_KERNEL`. Dispatch-only (`compute-live`).
    #[test]
    #[ignore = "boots a 2-vCPU SMP guest; needs /dev/kvm + BOATRAMP_TEST_KERNEL"]
    fn boots_smp_two_vcpus() {
        if std::env::var("BOATRAMP_TEST_KERNEL").is_err()
            || !std::path::Path::new("/dev/kvm").exists()
        {
            eprintln!("SKIP: need /dev/kvm + BOATRAMP_TEST_KERNEL=vmlinux");
            return;
        }
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(30));
            eprintln!("FATAL: boots_smp_two_vcpus exceeded 30s — aborting");
            std::process::exit(124);
        });

        let serial = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink_buf = serial.clone();
        std::thread::spawn(move || {
            let kernel = std::env::var("BOATRAMP_TEST_KERNEL").unwrap();
            // 2 vCPUs ⇒ the MP table advertises 2 processors, so the kernel
            // SMP-boots both.
            let mut vmm = EmbeddedVmm::with_irqchip(512 * 1024 * 1024, 2).expect("create vm");
            let entry = vmm.load_kernel(Path::new(&kernel)).expect("load kernel");
            vmm.write_boot_params("console=ttyS0 reboot=k panic=1 pci=off")
                .expect("boot params");
            vmm.setup_registers(entry.raw_value()).expect("registers");

            struct SharedSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for SharedSink {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(b);
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let manager = Arc::new(Mutex::new(DeviceManager::new(vec![]).expect("dev mgr")));
            let stop = Arc::new(AtomicBool::new(false));
            let tid = Arc::new(AtomicU64::new(0));
            let _ = vmm.run_with_net(manager, None, stop, tid, Box::new(SharedSink(sink_buf)));
        });

        // Poll for the second processor coming online (or the root-mount panic /
        // deadline). The 5.10 kernel logs "smpboot: Booting Node 0 Processor 1" +
        // "smpboot: Total of 2 processors activated".
        let online = |c: &str| c.contains("Total of 2 processors activated");
        let mut console = String::new();
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            console = String::from_utf8_lossy(&serial.lock().unwrap()).into_owned();
            if online(&console) || console.contains("Unable to mount root fs") {
                break;
            }
        }
        eprintln!("=== guest serial ({} bytes) ===\n{console}", console.len());
        assert!(
            console.contains("Linux version"),
            "kernel did not reach serial console"
        );
        assert!(
            online(&console),
            "the second vCPU did not come online (SMP multi-vCPU broken)"
        );
    }

    /// Boot a real Linux kernel with a **virtio-net** interface on a host tap and
    /// prove the datapath end to end: the host pings the guest. Self-skips unless
    /// `BOATRAMP_TEST_KERNEL` (vmlinux) + `BOATRAMP_TEST_ROOTFS` (ext4) + `/dev/kvm`
    /// are present **and** the process can open a tap (`CAP_NET_ADMIN` — run under
    /// `sudo`).
    ///
    /// Wiring: a virtio-block rootfs (so the kernel reaches userspace and stays
    /// alive under `init=/bin/sh`) plus a `virtio-net` device bridged to tap
    /// `brnet-test`; the guest's `eth0` is statically configured by the kernel
    /// `ip=` autoconfig, the host side of the tap gets the gateway IP. A
    /// successful `ping` exercises the full path: host → tap → RX poller →
    /// guest RX queue → guest ARP/ICMP reply → guest TX queue → tap → host. So it
    /// proves the virtio-net transport, the threaded RX poll loop, TX drain, and
    /// IRQ delivery against a real guest. Dispatch-only (`compute-live`).
    #[test]
    #[ignore = "boots Linux with virtio-net + pings it; needs /dev/kvm + CAP_NET_ADMIN + BOATRAMP_TEST_KERNEL + BOATRAMP_TEST_ROOTFS"]
    fn boots_kernel_with_virtio_net_and_pings() {
        use crate::embedded::mmio_cmdline_arg;
        use crate::tap::Tap;
        use crate::virtio_net::VirtioNet;

        if std::env::var("BOATRAMP_TEST_KERNEL").is_err()
            || std::env::var("BOATRAMP_TEST_ROOTFS").is_err()
            || !std::path::Path::new("/dev/kvm").exists()
        {
            eprintln!("SKIP: need /dev/kvm + BOATRAMP_TEST_KERNEL=vmlinux + BOATRAMP_TEST_ROOTFS=rootfs.ext4");
            return;
        }

        // Hard watchdog: bound the whole process in case the ping loop or a boot
        // bug wedges (the VM worker is a daemon thread, never joined).
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(60));
            eprintln!("FATAL: virtio-net test exceeded 60s — aborting");
            std::process::exit(124);
        });

        const TAP: &str = "brnet-test";
        const HOST_IP: &str = "172.31.7.1";
        const GUEST_IP: &str = "172.31.7.2";

        // Open the tap (needs CAP_NET_ADMIN); skip cleanly if unprivileged.
        let tap = match Tap::open(TAP) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("SKIP boots_kernel_with_virtio_net_and_pings: cannot open tap: {e}");
                return;
            }
        };
        // Give the device the TX side and the RX poller the read side.
        let tx_tap = tap.try_clone().expect("clone tap (tx)");
        let rx_tap = tap.try_clone().expect("clone tap (rx)");

        // Configure the host side of the tap (the guest's gateway).
        let ip = |args: &[&str]| {
            std::process::Command::new("ip")
                .args(args)
                .status()
                .expect("run ip")
                .success()
        };
        assert!(
            ip(&["addr", "add", &format!("{HOST_IP}/24"), "dev", TAP]),
            "assign host tap IP"
        );
        assert!(ip(&["link", "set", TAP, "up"]), "bring host tap up");

        // Build the device bus (block rootfs at index 0, net at index 1).
        let rootfs = std::env::var("BOATRAMP_TEST_ROOTFS").unwrap();
        let kernel = std::env::var("BOATRAMP_TEST_KERNEL").unwrap();
        // Mount the root read-only: a ping datapath test needs only a live guest
        // (the kernel's `ip=` autoconfig handles eth0); this also accepts a
        // read-only `squashfs` rootfs, not just a writable ext4.
        let rootfs_file = std::fs::File::open(&rootfs).expect("open rootfs");
        let sectors = rootfs_file.metadata().unwrap().len() / crate::virtio_block::SECTOR_SIZE;
        let block = crate::virtio_block::VirtioBlock::new(rootfs_file, sectors, true);
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        let net = VirtioNet::new(mac, tx_tap);
        let block_dev: Box<dyn crate::device_manager::VirtioDeviceOps> = Box::new(block);
        let net_dev: Box<dyn crate::device_manager::VirtioDeviceOps> = Box::new(net);
        let devices = DeviceManager::new(vec![block_dev, net_dev]).expect("device manager");
        let net_index = 1;

        // virtio-MMIO cmdline fragments for both devices + static guest IP.
        let mmio: String = devices
            .windows()
            .iter()
            .map(mmio_cmdline_arg)
            .collect::<Vec<_>>()
            .join(" ");
        let cmdline = format!(
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/bin/sh \
             ip={GUEST_IP}::{HOST_IP}:255.255.255.0::eth0:off {mmio}"
        );

        let serial = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink_buf = serial.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = stop.clone();

        // Run the guest on a daemon worker; the RX poller is spawned inside
        // `run_with_net`. The worker blocks (the guest runs `/bin/sh` forever), so
        // it is never joined — the process exits at test end and reaps it.
        std::thread::spawn(move || {
            let mut vmm = EmbeddedVmm::with_irqchip(512 * 1024 * 1024, 1).expect("create vm");
            let entry = vmm.load_kernel(Path::new(&kernel)).expect("load kernel");
            vmm.write_boot_params(&cmdline).expect("boot params");
            vmm.setup_registers(entry.raw_value()).expect("registers");

            struct SharedSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for SharedSink {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(b);
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let manager = std::sync::Arc::new(std::sync::Mutex::new(devices));
            let vcpu_tid = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let _ = vmm.run_with_net(
                manager,
                Some((net_index, rx_tap)),
                worker_stop,
                vcpu_tid,
                Box::new(SharedSink(sink_buf)),
            );
        });

        // Poll: ping the guest until it replies (boot + eth0 up takes a few
        // seconds) or a deadline.
        let ping_ok = || {
            std::process::Command::new("ping")
                .args(["-c", "1", "-W", "1", GUEST_IP])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        let mut reachable = false;
        for _ in 0..40 {
            if ping_ok() {
                reachable = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let console = String::from_utf8_lossy(&serial.lock().unwrap()).into_owned();
        eprintln!("=== guest serial ({} bytes) ===\n{console}", console.len());
        assert!(
            console.contains("Linux version"),
            "kernel did not reach serial console"
        );
        assert!(
            reachable,
            "host could not ping the guest over virtio-net (datapath broken)"
        );
    }

    /// End-to-end boot smoke test: a tiny hand-assembled 64-bit long-mode payload
    /// writes `"OK\n"` to COM1 and halts. Proves the whole VMM path under real KVM
    /// — machine + memory, the long-mode GDT/page-tables/CR/EFER register setup,
    /// the vCPU run loop, and serial `IoOut` — with no kernel/rootfs needed.
    /// Ignored by default (the `compute-live` seam); run with `--ignored` on a KVM
    /// host. Self-contained + reproducible.
    #[test]
    #[ignore = "executes guest code under real KVM; needs /dev/kvm"]
    fn boots_a_long_mode_serial_ok_payload() {
        // HARD WATCHDOG (must run on a capacity-1 shared CI runner): `vcpu.run()`
        // blocks indefinitely if the guest spins without an exit (a wrong RIP /
        // bad boot state never reaches the serial `out` or `hlt`). A blocking
        // KVM_RUN ioctl can't be cancelled without immediate_exit + a signal, so
        // we bound the whole *process*: a watchdog thread aborts after a deadline.
        // On a healthy boot the test returns in milliseconds, long before it
        // fires. (Production `run_primary_vcpu`, once it fronts untrusted guests,
        // needs the in-VMM immediate_exit+signal watchdog — tracked for the
        // live-integration phase; this test guard keeps CI safe meanwhile.)
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(15));
            eprintln!(
                "FATAL: embedded VMM boot exceeded 15s — aborting so it can't hang the CI runner"
            );
            std::process::exit(124);
        });

        // mov dx,0x3f8; mov al,'O'; out dx,al; al,'K'; out; al,'\n'; out; hlt.
        // Runs in 64-bit long mode at RIP = HIMEM_START (identity-mapped low 1GiB).
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0x66, 0xba, 0xf8, 0x03, // mov dx, 0x3f8 (COM1)
            0xb0, b'O', 0xee,       // mov al,'O'; out dx,al
            0xb0, b'K', 0xee,       // mov al,'K'; out dx,al
            0xb0, b'\n', 0xee,      // mov al,'\n'; out dx,al
            0xf4,                   // hlt
        ];

        // Self-skip when KVM is unavailable (no /dev/kvm, or nested virt off): the
        // `compute-live` seam runs this anywhere, so an environment without KVM is
        // a skip, not a failure (cf. the `docker_live` pattern). Once a VM is
        // actually created the environment is KVM-capable, so everything after is
        // a hard assertion — a real boot bug fails loudly.
        let mut vmm = match EmbeddedVmm::new(8 * 1024 * 1024, 1) {
            Ok(vmm) => vmm,
            Err(e) => {
                eprintln!("SKIP boots_a_long_mode_serial_ok_payload: KVM unavailable: {e}");
                return;
            }
        };
        vmm.guest_memory()
            .write_slice(payload, GuestAddress(HIMEM_START))
            .expect("write payload");
        vmm.setup_registers(HIMEM_START)
            .expect("program boot registers");

        let mut devices = DeviceManager::new(vec![]).expect("empty device manager");
        let mut out: Vec<u8> = Vec::new();
        let exit = vmm
            .run_primary_vcpu(&mut devices, &mut out)
            .expect("run vcpu");

        assert_eq!(exit, VmExit::Halted, "guest executed HLT");
        assert_eq!(out, b"OK\n", "guest wrote OK to the serial console");
    }

    /// Prove **snapshot → restore → resume** (scale-to-zero): a payload writes
    /// `0x11` to a guest-RAM cell then `HLT`s; we snapshot the halted VM (vCPU
    /// state + RAM), tear it down, restore into a **fresh** VM, and resume — the
    /// vCPU continues from the saved `RIP` and runs the second half (`0x22` + a
    /// final `HLT`). Asserting the cell is `0x11` right after restore and `0x22`
    /// after resume proves the vCPU register state + guest RAM round-trip and that
    /// execution genuinely continues. Needs `/dev/kvm`; dispatch-only.
    #[test]
    #[ignore = "snapshots + restores a VM under real KVM; needs /dev/kvm"]
    fn snapshots_restores_and_resumes() {
        use vm_memory::Bytes;

        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(15));
            eprintln!("FATAL: snapshots_restores_and_resumes exceeded 15s — aborting");
            std::process::exit(124);
        });

        // 64-bit payload at HIMEM_START: mov byte [0x100200],0x11 ; hlt ;
        //                                mov byte [0x100200],0x22 ; hlt
        // (C6 04 25 <abs32> imm8 = mov byte [disp32], imm8.)
        const CELL: u64 = 0x0010_0200;
        #[rustfmt::skip]
        let payload: &[u8] = &[
            0xc6, 0x04, 0x25, 0x00, 0x02, 0x10, 0x00, 0x11, // mov byte [0x100200], 0x11
            0xf4,                                           // hlt
            0xc6, 0x04, 0x25, 0x00, 0x02, 0x10, 0x00, 0x22, // mov byte [0x100200], 0x22
            0xf4,                                           // hlt
        ];

        let mut vmm = match EmbeddedVmm::new(8 * 1024 * 1024, 1) {
            Ok(vmm) => vmm,
            Err(e) => {
                eprintln!("SKIP snapshots_restores_and_resumes: KVM unavailable: {e}");
                return;
            }
        };
        vmm.guest_memory()
            .write_slice(payload, GuestAddress(HIMEM_START))
            .expect("write payload");
        vmm.setup_registers(HIMEM_START).expect("registers");

        // Run to the first HLT: the cell is now 0x11.
        let mut devices = DeviceManager::new(vec![]).expect("device manager");
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            vmm.run_primary_vcpu(&mut devices, &mut out).expect("run 1"),
            VmExit::Halted
        );
        let read_cell = |m: &GuestMemoryMmap| -> u8 { m.read_obj(GuestAddress(CELL)).unwrap() };
        assert_eq!(read_cell(vmm.guest_memory()), 0x11, "first write happened");

        // Snapshot the paused VM (vCPU state + RAM) and tear it down.
        let mut snap_mem: Vec<u8> = Vec::new();
        let snapshot = vmm.snapshot(&mut snap_mem).expect("snapshot");
        drop(vmm);

        // Restore into a fresh VM; the reloaded RAM still holds 0x11.
        let mut restored =
            EmbeddedVmm::restore(&snapshot, &mut std::io::Cursor::new(&snap_mem)).expect("restore");
        assert_eq!(
            read_cell(restored.guest_memory()),
            0x11,
            "restored RAM round-trips"
        );

        // Resume: the vCPU continues from the saved RIP → second write + HLT.
        let mut devices2 = DeviceManager::new(vec![]).expect("device manager");
        let mut out2: Vec<u8> = Vec::new();
        assert_eq!(
            restored
                .run_primary_vcpu(&mut devices2, &mut out2)
                .expect("resume"),
            VmExit::Halted
        );
        assert_eq!(
            read_cell(restored.guest_memory()),
            0x22,
            "resumed from the snapshot RIP and ran the second write"
        );
    }

    /// Prove the **clean external stop**: a guest that spins forever (`jmp $`,
    /// never exiting to userspace) is broken out of `KVM_RUN` by [`interrupt_vcpu`]
    /// and the run loop returns [`VmExit::Stopped`]. This is the mechanism the
    /// compute backend uses to tear a running microVM down (a vCPU blocked in
    /// `KVM_RUN` can only be unblocked by a signal). Needs `/dev/kvm`;
    /// dispatch-only (`compute-live`).
    #[test]
    #[ignore = "spin-loop guest under real KVM, signal-stopped; needs /dev/kvm"]
    fn run_loop_stops_on_signal() {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        use std::sync::{Arc, Mutex};

        // Watchdog: if the stop mechanism fails, bound the whole process so a
        // blocked KVM_RUN can't wedge the runner.
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(15));
            eprintln!("FATAL: run_loop_stops_on_signal exceeded 15s — aborting");
            std::process::exit(124);
        });

        // 64-bit `jmp $` — spins in guest mode forever, no exits.
        let payload: &[u8] = &[0xeb, 0xfe];

        let stop = Arc::new(AtomicBool::new(false));
        let vcpu_tid = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let exit_slot: Arc<Mutex<Option<Result<VmExit, VmmError>>>> = Arc::new(Mutex::new(None));

        let (w_stop, w_tid, w_done, w_exit) = (
            stop.clone(),
            vcpu_tid.clone(),
            done.clone(),
            exit_slot.clone(),
        );
        let worker = std::thread::spawn(move || {
            let mut vmm = match EmbeddedVmm::new(8 * 1024 * 1024, 1) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("SKIP run_loop_stops_on_signal: KVM unavailable: {e}");
                    w_done.store(true, Ordering::SeqCst);
                    return;
                }
            };
            vmm.guest_memory()
                .write_slice(payload, GuestAddress(HIMEM_START))
                .expect("write payload");
            vmm.setup_registers(HIMEM_START).expect("registers");
            let manager = Arc::new(Mutex::new(
                DeviceManager::new(vec![]).expect("device manager"),
            ));
            let exit = vmm.run_with_net(manager, None, w_stop, w_tid, Box::new(std::io::sink()));
            *w_exit.lock().unwrap() = Some(exit);
            w_done.store(true, Ordering::SeqCst);
        });

        // Wait for the vCPU to register its id + start spinning (or bail if KVM
        // was unavailable — the worker then finishes without registering a tid).
        for _ in 0..100 {
            if vcpu_tid.load(Ordering::SeqCst) != 0 || done.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if vcpu_tid.load(Ordering::SeqCst) == 0 {
            let _ = worker.join();
            eprintln!("SKIP run_loop_stops_on_signal: vCPU did not start (KVM unavailable?)");
            return;
        }

        // Let it spin briefly, then request a stop and signal until it exits.
        std::thread::sleep(std::time::Duration::from_millis(100));
        stop.store(true, Ordering::SeqCst);
        for _ in 0..200 {
            interrupt_vcpu(&vcpu_tid);
            if done.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        worker.join().expect("join vm worker");

        let exit = exit_slot.lock().unwrap().take();
        assert!(
            matches!(exit, Some(Ok(VmExit::Stopped))),
            "VM should stop cleanly on signal, got {exit:?}"
        );
    }
}
