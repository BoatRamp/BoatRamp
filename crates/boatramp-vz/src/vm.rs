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
use std::sync::{Arc, Mutex};

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

        // Serial console → this process's stderr (boot logs; always wired so a crash
        // is visible).
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
        // Whether this device model can be paused + saved + restored (scale-to-zero).
        // Not fatal (save/restore is optional) but log the specific reason if not, so
        // an operator can see why a workload won't park.
        if let Err(e) = configuration.validateSaveRestoreSupportWithError() {
            eprintln!(
                "vz: save/restore unsupported for this config: {}",
                ns_error(&e)
            );
        }
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

/// Render an [`NSError`] as a `String` for our error type, appending the failure
/// reason when present (it names the specific incompatible device on a save/restore
/// or configuration error).
fn ns_error(err: &NSError) -> String {
    let desc = err.localizedDescription().to_string();
    match err.localizedFailureReason() {
        Some(reason) => format!("{desc} ({reason})"),
        None => desc,
    }
}

/// Invoke an async `VZVirtualMachine` op (`start`/`restore`/`resume`/`pause`/`save`,
/// each a `…CompletionHandler:` taking `void (^)(NSError *)`) and block **this**
/// thread until its completion fires, by pumping the run loop (the framework
/// delivers the completion there). Must be called on the VM's thread. `Err` carries
/// the op's `NSError`.
fn block_on_vm<F>(invoke: F) -> Result<(), String>
where
    F: FnOnce(&RcBlock<dyn Fn(*mut NSError)>),
{
    let result: Rc<RefCell<Option<Result<(), String>>>> = Rc::new(RefCell::new(None));
    let sink = result.clone();
    let handler = RcBlock::new(move |err: *mut NSError| {
        // SAFETY: a non-null error is owned by the framework for the callback.
        let r = if err.is_null() {
            Ok(())
        } else {
            Err(ns_error(unsafe { &*err }))
        };
        *sink.borrow_mut() = Some(r);
        // Return control to the pumping `CFRunLoop::run()` below.
        if let Some(rl) = CFRunLoop::current() {
            rl.stop();
            rl.wake_up();
        }
    });
    invoke(&handler);
    // The completion handler stops the loop; the guard tolerates a spurious return.
    while result.borrow().is_none() {
        CFRunLoop::run();
    }
    let outcome = result.borrow_mut().take().unwrap_or(Ok(()));
    outcome
}

/// Run one VM to completion in **this** process. Called from the `__vz-run`
/// re-exec child.
///
/// The whole VM lifecycle stays on **this one thread** — `VZVirtualMachine` and its
/// owned objects are `!Send`, so they never cross a thread boundary. We use the
/// *main-queue* VM (`initWithConfiguration:`, driven off the thread's run loop),
/// bring it to Running (a fresh `start`, or `restore` from a saved state file +
/// `resume` for a scale-to-zero wake), then pump the [`CFRunLoop`] so the framework
/// delivers the guest's I/O + lifecycle. A tiny **control watcher** reads one command
/// off stdin — `snapshot <path>` (pause + `saveMachineStateToURL:`, then exit) or EOF
/// (clean stop) — and stops the run loop so we act on it. Mirrors the KVM worker's
/// cooperative "run until the parent tears it down" contract, plus scale-to-zero.
///
/// Returns `Ok(())` on a clean run/stop/snapshot; `Err` on a start/restore/save failure.
pub fn run_worker(cfg: WorkerConfig) -> Result<(), String> {
    let configuration = build_configuration(&cfg)?;

    // SAFETY: the main-queue initializer creates a VM driven off this thread's run
    // loop; every subsequent call on `vm` happens on this same thread.
    let vm: Retained<VZVirtualMachine> = unsafe {
        VZVirtualMachine::initWithConfiguration(VZVirtualMachine::alloc(), &configuration)
    };

    // Bring the VM to Running: restore-from-file + resume (scale-to-zero wake), or a
    // fresh cold boot. Each op is pumped to completion on this thread.
    match &cfg.restore_path {
        Some(path) => {
            let url = file_url(path);
            // SAFETY: on the VM's thread; the block outlives the async call via RcBlock.
            block_on_vm(|h| unsafe { vm.restoreMachineStateFromURL_completionHandler(&url, h) })
                .map_err(|e| format!("restore from {path}: {e}"))?;
            // Restore leaves the VM paused; resume it into the running state.
            block_on_vm(|h| unsafe { vm.resumeWithCompletionHandler(h) })
                .map_err(|e| format!("resume: {e}"))?;
        }
        None => {
            block_on_vm(|h| unsafe { vm.startWithCompletionHandler(h) })
                .map_err(|e| format!("start: {e}"))?;
        }
    }

    // Watch the control channel on a helper thread; it reads one command + stops the
    // run loop. `CFRunLoopStop`/`WakeUp` are documented thread-safe, so we hand it a
    // raw pointer (in a `Send` wrapper) — it never touches the (!Send) VM. We leak one
    // strong ref to the run loop so the pointer stays valid (the loop lives anyway).
    let action: Arc<Mutex<Option<WorkerAction>>> = Arc::new(Mutex::new(None));
    if let Some(run_loop) = CFRunLoop::current() {
        let ptr = objc2_core_foundation::CFRetained::as_ptr(&run_loop);
        spawn_control_watcher(RunLoopHandle(ptr.as_ptr()), action.clone());
        std::mem::forget(run_loop);
    }

    // Serve until the parent asks to stop or snapshot. The framework delivers guest
    // I/O + lifecycle here.
    CFRunLoop::run();

    // Carry out the request back on the VM's thread.
    match action.lock().expect("action mutex").take() {
        Some(WorkerAction::Snapshot(path)) => {
            // Save requires the paused state: pause, write the state file, then exit
            // (process teardown drops the still-paused VM). The state restores via
            // `WorkerConfig::restore_path` on the next wake.
            block_on_vm(|h| unsafe { vm.pauseWithCompletionHandler(h) })
                .map_err(|e| format!("pause: {e}"))?;
            let url = file_url(&path);
            block_on_vm(|h| unsafe { vm.saveMachineStateToURL_completionHandler(&url, h) })
                .map_err(|e| format!("save to {path}: {e}"))?;
        }
        _ => {
            // Best-effort clean guest stop on the way out (back on the VM's thread).
            // SAFETY: on the VM's thread; `canStop`/`requestStopWithError` are valid here.
            unsafe {
                if vm.canStop() {
                    let _ = vm.requestStopWithError();
                }
            }
        }
    }
    Ok(())
}

/// A `Send` wrapper over a raw `CFRunLoop` pointer, so the control watcher can
/// signal the loop from another thread. Safe because `CFRunLoopStop`/`WakeUp` are
/// documented thread-safe and [`run_worker`] leaks a strong ref keeping the loop
/// alive for the pointer's lifetime.
struct RunLoopHandle(*mut CFRunLoop);
// SAFETY: the only operations performed through the pointer (`stop`/`wake_up`) are
// documented as thread-safe by Core Foundation.
unsafe impl Send for RunLoopHandle {}

/// What the parent asked the worker to do, read off the control channel (stdin).
enum WorkerAction {
    /// EOF / unrecognized input: request a clean guest halt, then exit.
    Stop,
    /// `snapshot <path>`: pause + `saveMachineStateToURL:(<path>)`, then exit — the
    /// scale-to-zero park. The state restores via [`WorkerConfig::restore_path`].
    Snapshot(String),
}

/// Spawn a helper thread that reads **one** control command from stdin — `snapshot
/// <path>` (scale-to-zero) or EOF (stop) — records it in `action`, and stops the run
/// loop so [`run_worker`]'s serve `CFRunLoop::run()` returns to act on it. Never
/// touches the (!Send) VM; only signals the loop via the thread-safe handle.
fn spawn_control_watcher(handle: RunLoopHandle, action: Arc<Mutex<Option<WorkerAction>>>) {
    std::thread::Builder::new()
        .name("vz-control".into())
        .spawn(move || {
            use std::io::BufRead;
            let handle = handle; // move the whole Send wrapper in
            let mut line = String::new();
            let act = match std::io::stdin().lock().read_line(&mut line) {
                Ok(0) | Err(_) => WorkerAction::Stop, // EOF or read error
                Ok(_) => match line.trim().strip_prefix("snapshot ") {
                    Some(path) if !path.is_empty() => WorkerAction::Snapshot(path.to_string()),
                    _ => WorkerAction::Stop,
                },
            };
            *action.lock().expect("action mutex") = Some(act);
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
