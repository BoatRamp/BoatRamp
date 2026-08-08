//! The macOS VM host: build a [`VZVirtualMachineConfiguration`] from a
//! [`WorkerConfig`] and run one Linux microVM to completion. **`target_os =
//! "macos"` + `backend` feature only.**
//!
//! Invoked from the re-exec'd `boatramp __vz-run <json>` child (or the crate's
//! `vz-worker` bin): the child owns the `VZVirtualMachine` on a dedicated serial
//! `DispatchQueue`, starts it, and blocks until the guest stops or the parent
//! closes the control channel (stdin) / signals the process — mirroring the KVM
//! backend's `run_jailed_worker`. Keeping the VM in a child (not the serve
//! process) preserves the single-binary story *and* the per-replica process
//! isolation boundary.
//!
//! All Virtualization.framework calls are `unsafe` (Obj-C message sends); the
//! safety of each is argued at the call site. The device set is: one virtio-blk
//! root (from the staged ext4), one virtio-blk per persistent volume, one
//! virtio-net on the vmnet NAT, and a virtio-console serial captured to stderr
//! for boot debugging.

use std::cell::RefCell;
use std::rc::Rc;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AllocAnyThread;
use objc2_core_foundation::CFRunLoop;
use objc2_foundation::{NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleSerialPortAttachment, VZLinuxBootLoader,
    VZMACAddress, VZNATNetworkDeviceAttachment, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioNetworkDeviceConfiguration,
    VZVirtualMachine, VZVirtualMachineConfiguration,
};

use crate::config::{full_cmdline, WorkerConfig};
use crate::net::mac_for;

/// Build a validated [`VZVirtualMachineConfiguration`] for `cfg`. Assembles the
/// Linux boot loader (kernel + assembled cmdline), the virtio-blk root
/// (read-only unless `writable_root`), one virtio-blk per volume (writable), the
/// virtio-net NAT device (MAC derived from the guest IP), and the serial console.
/// Runs `validateWithError` before returning — a bad config is a launch error,
/// not a boot-time crash.
pub fn build_configuration(
    cfg: &WorkerConfig,
) -> Result<Retained<VZVirtualMachineConfiguration>, String> {
    // SAFETY: every call below is a standard Obj-C alloc/init or setter on a
    // freshly-owned object; arguments are non-null Retained/refs we hold for the
    // duration; no threading constraints apply during configuration assembly
    // (the queue restriction is only on the live VZVirtualMachine).
    unsafe {
        let configuration = VZVirtualMachineConfiguration::new();
        configuration.setCPUCount(cfg.vcpus.max(1) as usize);
        configuration.setMemorySize(u64::from(cfg.mem_mib.max(1)) * 1024 * 1024);

        // Boot loader: kernel + the assembled cmdline (base + env fragment).
        let kernel_url = file_url(&cfg.kernel_path);
        let boot_loader =
            VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url);
        let cmdline = full_cmdline(cfg);
        boot_loader.setCommandLine(&NSString::from_str(&cmdline));
        configuration.setBootLoader(Some(&boot_loader));

        // Storage: the root ext4 (ro unless writable_root), then each volume (rw).
        let mut storage: Vec<Retained<objc2_virtualization::VZStorageDeviceConfiguration>> =
            Vec::with_capacity(1 + cfg.volumes.len());
        storage.push(block_device(&cfg.rootfs_path, !cfg.writable_root)?);
        for vol in &cfg.volumes {
            storage.push(block_device(&vol.image_path, false)?);
        }
        let storage_refs: Vec<&objc2_virtualization::VZStorageDeviceConfiguration> =
            storage.iter().map(AsRef::as_ref).collect();
        configuration.setStorageDevices(&objc2_foundation::NSArray::from_slice(&storage_refs));

        // Network: one virtio-net on the vmnet NAT, MAC derived from the guest IP.
        let net = VZVirtioNetworkDeviceConfiguration::new();
        net.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
        if let Ok(guest_ip) = cfg.guest_ip.parse() {
            let mac_str = NSString::from_str(&mac_for(guest_ip));
            if let Some(mac) = VZMACAddress::initWithString(VZMACAddress::alloc(), &mac_str) {
                net.setMACAddress(&mac);
            }
        }
        let net_up: Retained<objc2_virtualization::VZNetworkDeviceConfiguration> =
            Retained::into_super(net);
        configuration.setNetworkDevices(&objc2_foundation::NSArray::from_slice(&[net_up.as_ref()]));

        // Serial console → this process's stderr (boot logs; gated by
        // BOATRAMP_VMM_SERIAL at the caller, but always wired so a crash is visible).
        let console = VZVirtioConsoleDeviceSerialPortConfiguration::new();
        let stderr = NSFileHandle::fileHandleWithStandardError();
        let attachment =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                None,
                Some(&stderr),
            );
        console.setAttachment(Some(&attachment));
        let console_up: Retained<objc2_virtualization::VZSerialPortConfiguration> =
            Retained::into_super(console);
        configuration.setSerialPorts(&objc2_foundation::NSArray::from_slice(&[
            console_up.as_ref()
        ]));

        configuration
            .validateWithError()
            .map_err(|e| format!("invalid VM configuration: {}", ns_error(&e)))?;
        Ok(configuration)
    }
}

/// A virtio-blk device backed by the RAW disk image at `path` (`read_only`
/// controls the attachment mode), upcast to the storage-device supertype the
/// configuration array wants.
unsafe fn block_device(
    path: &str,
    read_only: bool,
) -> Result<Retained<objc2_virtualization::VZStorageDeviceConfiguration>, String> {
    let url = file_url(path);
    let attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
        VZDiskImageStorageDeviceAttachment::alloc(),
        &url,
        read_only,
    )
    .map_err(|e| format!("attach {path}: {}", ns_error(&e)))?;
    let block = VZVirtioBlockDeviceConfiguration::initWithAttachment(
        VZVirtioBlockDeviceConfiguration::alloc(),
        &attachment,
    );
    Ok(Retained::into_super(block))
}

/// A `file://` [`NSURL`] for a host path.
fn file_url(path: &str) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(path))
}

/// Render an [`NSError`] as a `String` for our error type.
fn ns_error(err: &NSError) -> String {
    err.localizedDescription().to_string()
}

/// Run one VM to completion in **this** process. Called from the `__vz-run`
/// re-exec child.
///
/// The whole VM lifecycle stays on **this one thread** — `VZVirtualMachine` and
/// its owned objects are `!Send`, so they never cross a thread boundary. We use
/// the *main-queue* VM (`initWithConfiguration:`, which drives the VM off the
/// thread's run loop), start it with a completion block, then pump this thread's
/// [`CFRunLoop`] so the framework can deliver the guest's I/O + lifecycle events.
/// A tiny **watcher thread** reads the control channel (stdin) and, on EOF (the
/// parent's `stop` drops it), stops the run loop — after which we request a clean
/// guest halt. Mirrors the KVM worker's "run until the parent tears it down"
/// contract, cooperatively.
///
/// Returns `Ok(())` on a clean run-loop exit; `Err` on a config/start failure.
pub fn run_worker(cfg: WorkerConfig) -> Result<(), String> {
    let configuration = build_configuration(&cfg)?;

    // SAFETY: the main-queue initializer creates a VM driven off this thread's run
    // loop; every subsequent call on `vm` happens on this same thread.
    let vm: Retained<VZVirtualMachine> = unsafe {
        VZVirtualMachine::initWithConfiguration(VZVirtualMachine::alloc(), &configuration)
    };

    // Start; the completion block (run on this thread's run loop) records success.
    let start_result: Rc<RefCell<Option<Result<(), String>>>> = Rc::new(RefCell::new(None));
    {
        let start_result = start_result.clone();
        let handler = RcBlock::new(move |err: *mut NSError| {
            let r = if err.is_null() {
                Ok(())
            } else {
                // SAFETY: a non-null error is owned by the framework for the callback.
                Err(format!("start failed: {}", ns_error(unsafe { &*err })))
            };
            *start_result.borrow_mut() = Some(r);
        });
        // SAFETY: on the VM's thread; the block outlives the async call via RcBlock.
        unsafe { vm.startWithCompletionHandler(&handler) };
    }

    // Watch the control channel on a helper thread; stop the run loop on EOF.
    // `CFRunLoopStop`/`CFRunLoopWakeUp` are documented thread-safe, so we hand the
    // watcher a raw pointer (in a `Send` wrapper) — it never touches the (!Send)
    // VM, only signals the loop. We leak one strong ref to the run loop so the
    // pointer stays valid across `run()` (the loop lives for the process anyway).
    if let Some(run_loop) = CFRunLoop::current() {
        let ptr = objc2_core_foundation::CFRetained::as_ptr(&run_loop);
        spawn_stdin_watcher(RunLoopHandle(ptr.as_ptr()));
        std::mem::forget(run_loop);
    }

    // Pump this thread's run loop until the watcher stops it (parent closed stdin)
    // or the VM stops itself. The framework delivers guest I/O + lifecycle here.
    CFRunLoop::run();

    // Surface a start failure if the completion handler recorded one.
    if let Some(Err(e)) = start_result.borrow().clone() {
        return Err(e);
    }

    // Best-effort clean guest stop on the way out (we're back on the VM's thread).
    // SAFETY: on the VM's thread; `canStop`/`requestStopWithError` are valid here.
    unsafe {
        if vm.canStop() {
            let _ = vm.requestStopWithError();
        }
    }
    Ok(())
}

/// A `Send` wrapper over a raw `CFRunLoop` pointer, so the stdin watcher can
/// signal the loop from another thread. Safe because `CFRunLoopStop`/`WakeUp` are
/// documented thread-safe and [`run_worker`] leaks a strong ref keeping the loop
/// alive for the pointer's lifetime.
struct RunLoopHandle(*mut CFRunLoop);
// SAFETY: the only operations performed through the pointer (`stop`/`wake_up`) are
// documented as thread-safe by Core Foundation.
unsafe impl Send for RunLoopHandle {}

/// Spawn a helper thread that blocks reading the control channel (stdin) and, on
/// EOF — the parent's `stop` drops the child's stdin — stops the run loop so
/// [`run_worker`]'s `CFRunLoop::run()` returns. Never touches the VM.
fn spawn_stdin_watcher(handle: RunLoopHandle) {
    std::thread::Builder::new()
        .name("vz-stdin-watcher".into())
        .spawn(move || {
            use std::io::Read;
            let handle = handle; // move the whole Send wrapper in
            let mut buf = [0u8; 64];
            let stdin = std::io::stdin();
            let mut locked = stdin.lock();
            loop {
                match locked.read(&mut buf) {
                    Ok(0) => break,    // EOF: parent closed the control channel
                    Ok(_) => continue, // ignore any control bytes for now (v1)
                    Err(_) => break,
                }
            }
            // SAFETY: the pointer is kept alive by the leaked strong ref in
            // `run_worker`; `stop`/`wake_up` are thread-safe CF operations.
            unsafe {
                if let Some(run_loop) = handle.0.as_ref() {
                    run_loop.stop();
                    run_loop.wake_up();
                }
            }
        })
        .ok();
}
