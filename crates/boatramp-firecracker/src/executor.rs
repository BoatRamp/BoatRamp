//! The microVM executor: launch + stop a Firecracker VM on a KVM host.
//!
//! [`LaunchPlan`] is the **pure** assembly — the exact host commands (tap),
//! process spawn (Firecracker, optionally under the **jailer**), API boot
//! sequence, and teardown — built from an [`FcMachine`] + a [`TapNetwork`].
//! [`Executor`] is the thin runner that applies a plan against a [`Host`],
//! rolling back (kill + tap teardown) on any failure. The plan, the rollback
//! ordering, and the jailer wiring are unit-tested via a recording fake; only
//! the real side effects ([`SystemHost`]) need Linux + `/dev/kvm`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::api::{self, ApiRequest};
use crate::config::FcMachine;
use crate::net::{HostCommand, NodeNetwork, TapNetwork};

/// A spawned process id on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub u32);

/// Why an executor operation failed.
#[derive(Debug)]
pub enum ExecError {
    /// A host command (`ip`/`nft`/`kill`/…) failed to run or exited non-zero.
    Command {
        /// The program that failed.
        program: String,
        /// Failure detail.
        detail: String,
    },
    /// Spawning Firecracker/jailer failed.
    Spawn(String),
    /// The API socket never appeared within the timeout.
    SocketTimeout(PathBuf),
    /// A Firecracker API request failed (transport or non-2xx).
    Api {
        /// The API path.
        path: String,
        /// Failure detail (status + any fault message).
        detail: String,
    },
    /// A generic IO failure.
    Io(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Command { program, detail } => {
                write!(f, "host command `{program}`: {detail}")
            }
            ExecError::Spawn(d) => write!(f, "spawn firecracker: {d}"),
            ExecError::SocketTimeout(p) => write!(f, "API socket {} never appeared", p.display()),
            ExecError::Api { path, detail } => write!(f, "firecracker API {path}: {detail}"),
            ExecError::Io(d) => write!(f, "io: {d}"),
        }
    }
}

impl std::error::Error for ExecError {}

/// Firecracker **jailer** settings: the jailer chroots the VMM,
/// drops it to `uid`/`gid`, and puts it in its own cgroup + network namespace.
/// This is the load-bearing isolation boundary for untrusted multi-tenant VMs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailerConfig {
    /// Path to the `jailer` binary.
    pub jailer_bin: String,
    /// uid the jailed Firecracker drops to.
    pub uid: u32,
    /// gid the jailed Firecracker drops to.
    pub gid: u32,
    /// Base directory the jailer builds each VM's chroot under.
    pub chroot_base: String,
}

/// Executor configuration: the Firecracker binary, optional jailer, where
/// non-jailed API sockets live, and the per-request API timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorConfig {
    /// Path to the `firecracker` binary.
    pub firecracker_bin: String,
    /// Jailer settings (`None` = run Firecracker directly — dev/non-multitenant).
    pub jailer: Option<JailerConfig>,
    /// Directory non-jailed API sockets are created in (must exist).
    pub runtime_dir: PathBuf,
    /// Timeout for waiting on the API socket and for each API request.
    pub api_timeout: Duration,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            firecracker_bin: "firecracker".to_string(),
            jailer: None,
            runtime_dir: PathBuf::from("/run/boatramp"),
            api_timeout: Duration::from_secs(10),
        }
    }
}

impl ExecutorConfig {
    /// The host-visible API socket path for VM `vm_id` — under `runtime_dir`
    /// without the jailer, or inside the jailer's per-VM chroot with it. The one
    /// source of truth for both [`LaunchPlan::build`] (launch) and a later `stop`
    /// that reconstructs the path from the VM id.
    pub fn api_socket(&self, vm_id: &str) -> PathBuf {
        match &self.jailer {
            None => self.runtime_dir.join(format!("fc-{vm_id}.socket")),
            Some(jailer) => {
                let exec_name = Path::new(&self.firecracker_bin)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("firecracker");
                Path::new(&jailer.chroot_base)
                    .join(exec_name)
                    .join(vm_id)
                    .join("root")
                    .join("run")
                    .join("firecracker.socket")
            }
        }
    }
}

/// A process to spawn: a `program` and its `args`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnCommand {
    /// The executable (`firecracker` or `jailer`).
    pub program: String,
    /// Its arguments, in order.
    pub args: Vec<String>,
}

/// The fully-resolved, **pure** plan to launch one VM: tap setup, the VMM spawn,
/// the API boot sequence, and the tap teardown for rollback/stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// Commands to bring up the VM's tap before the VMM starts.
    pub net_setup: Vec<HostCommand>,
    /// The Firecracker (or jailer) process to spawn.
    pub spawn: SpawnCommand,
    /// The host-visible path of the API socket the VMM will create.
    pub api_socket: PathBuf,
    /// The ordered API requests that provision + start the VM.
    pub boot: Vec<ApiRequest>,
    /// Commands to remove the tap (rollback / stop).
    pub net_teardown: Vec<HostCommand>,
}

impl LaunchPlan {
    /// Assemble the launch plan for VM `vm_id` running `machine` on `tap`.
    pub fn build(
        vm_id: &str,
        machine: &FcMachine,
        tap: &TapNetwork,
        config: &ExecutorConfig,
    ) -> Self {
        LaunchPlan {
            net_setup: tap.setup_commands(),
            spawn: spawn_command(vm_id, config),
            api_socket: config.api_socket(vm_id),
            boot: api::boot_sequence(machine),
            net_teardown: tap.teardown_commands(),
        }
    }

    /// Assemble the plan to **restore** VM `vm_id` on `tap`: same tap + spawn +
    /// socket as a fresh launch, but no boot sequence — the snapshot the executor
    /// loads already carries the machine config / drives / boot-source.
    pub fn for_restore(vm_id: &str, tap: &TapNetwork, config: &ExecutorConfig) -> Self {
        LaunchPlan {
            net_setup: tap.setup_commands(),
            spawn: spawn_command(vm_id, config),
            api_socket: config.api_socket(vm_id),
            boot: Vec::new(),
            net_teardown: tap.teardown_commands(),
        }
    }
}

/// Build the VMM spawn command (Firecracker directly, or under the jailer).
fn spawn_command(vm_id: &str, config: &ExecutorConfig) -> SpawnCommand {
    match &config.jailer {
        // Run Firecracker directly; the socket lives under `runtime_dir`.
        None => SpawnCommand {
            program: config.firecracker_bin.clone(),
            args: vec![
                "--id".into(),
                vm_id.to_string(),
                "--api-sock".into(),
                config.api_socket(vm_id).display().to_string(),
            ],
        },
        // Run under the jailer: it chroots to `<base>/<exec-name>/<id>/root`,
        // so the socket it creates (relative to the chroot) maps to
        // `config.api_socket(vm_id)` on the host.
        Some(jailer) => SpawnCommand {
            program: jailer.jailer_bin.clone(),
            args: vec![
                "--id".into(),
                vm_id.to_string(),
                "--uid".into(),
                jailer.uid.to_string(),
                "--gid".into(),
                jailer.gid.to_string(),
                "--exec-file".into(),
                config.firecracker_bin.clone(),
                "--chroot-base-dir".into(),
                jailer.chroot_base.clone(),
                "--".into(),
                "--api-sock".into(),
                "/run/firecracker.socket".into(),
            ],
        },
    }
}

/// A launched VM: its id, the VMM pid, the API socket, and the teardown commands
/// to run when stopping it.
#[derive(Debug, Clone)]
pub struct RunningVm {
    /// The VM id.
    pub id: String,
    /// The Firecracker/jailer process id.
    pub pid: Pid,
    /// The API socket path.
    pub api_socket: PathBuf,
    /// Tap teardown commands (run on stop).
    pub net_teardown: Vec<HostCommand>,
}

/// The side effects the executor needs from the host. The real implementation is
/// [`SystemHost`]; tests use a recording fake, so the launch/rollback logic is
/// verified without a KVM host.
pub trait Host {
    /// Run a one-shot host command (waits for it to exit).
    fn run_command(&self, cmd: &HostCommand) -> Result<(), ExecError>;
    /// Spawn a long-running process (Firecracker/jailer), returning its pid.
    fn spawn(&self, cmd: &SpawnCommand) -> Result<Pid, ExecError>;
    /// Block until `socket` exists, or `timeout` elapses.
    fn wait_for_socket(&self, socket: &Path, timeout: Duration) -> Result<(), ExecError>;
    /// Send one Firecracker API request over `socket`.
    fn api_request(
        &self,
        socket: &Path,
        req: &ApiRequest,
        timeout: Duration,
    ) -> Result<(), ExecError>;
    /// Terminate a spawned process.
    fn kill(&self, pid: Pid) -> Result<(), ExecError>;
}

/// Runs [`LaunchPlan`]s against a [`Host`], with rollback on failure.
#[derive(Debug, Clone)]
pub struct Executor<H: Host> {
    host: H,
    config: ExecutorConfig,
}

impl<H: Host> Executor<H> {
    /// Build an executor over `host` with `config`.
    pub fn new(host: H, config: ExecutorConfig) -> Self {
        Self { host, config }
    }

    /// Access the executor config.
    pub fn config(&self) -> &ExecutorConfig {
        &self.config
    }

    /// Best-effort node networking setup (bridge + egress NAT). Idempotent:
    /// "already exists" failures from re-running are ignored.
    pub fn setup_node(&self, node: &NodeNetwork) {
        for cmd in node.setup_commands() {
            let _ = self.host.run_command(&cmd);
        }
    }

    /// Launch VM `vm_id`: bring up its tap, spawn the VMM, wait for its API
    /// socket, then drive the boot sequence. On any failure the VM is killed (if
    /// spawned) and its tap is torn down before returning the error.
    pub fn launch(
        &self,
        vm_id: &str,
        machine: &FcMachine,
        tap: &TapNetwork,
    ) -> Result<RunningVm, ExecError> {
        let plan = LaunchPlan::build(vm_id, machine, tap, &self.config);
        self.provision(vm_id, &plan, &plan.boot)
    }

    /// Snapshot a **running** VM to `snapshot_path` (state) + `mem_file_path`
    /// (guest RAM): pause → create → resume, so the VM keeps serving afterward.
    /// The snapshot files are left on the host for a later [`restore`](Self::restore).
    /// Pause must succeed; create + resume are then both attempted, surfacing the
    /// create error first so a paused-but-unsnapshotted VM is still resumed.
    pub fn snapshot(
        &self,
        vm: &RunningVm,
        snapshot_path: &str,
        mem_file_path: &str,
    ) -> Result<(), ExecError> {
        let timeout = self.config.api_timeout;
        self.host
            .api_request(&vm.api_socket, &api::pause_request(), timeout)?;
        let created = self.host.api_request(
            &vm.api_socket,
            &api::snapshot_create_request(snapshot_path, mem_file_path),
            timeout,
        );
        let resumed = self
            .host
            .api_request(&vm.api_socket, &api::resume_request(), timeout);
        created?;
        resumed?;
        Ok(())
    }

    /// Restore a snapshot into a fresh VMM for `vm_id` on `tap`: tap up → spawn →
    /// wait socket → load the snapshot (resuming the guest). The snapshot carries
    /// the machine config, so no boot-source/drive/iface calls are sent. Rolls
    /// back the tap/process on failure, like [`launch`](Self::launch).
    pub fn restore(
        &self,
        vm_id: &str,
        tap: &TapNetwork,
        snapshot_path: &str,
        mem_file_path: &str,
    ) -> Result<RunningVm, ExecError> {
        let plan = LaunchPlan::for_restore(vm_id, tap, &self.config);
        let load = api::snapshot_load_request(snapshot_path, mem_file_path, true);
        self.provision(vm_id, &plan, std::slice::from_ref(&load))
    }

    /// Bring up the tap, spawn the VMM, wait for its API socket, then drive
    /// `requests` (the boot sequence for a launch, the snapshot-load for a
    /// restore). On any failure the VM is killed (if spawned) and its tap is torn
    /// down before returning the error.
    fn provision(
        &self,
        vm_id: &str,
        plan: &LaunchPlan,
        requests: &[ApiRequest],
    ) -> Result<RunningVm, ExecError> {
        // 1. Tap networking. On failure, roll back the partial tap.
        for cmd in &plan.net_setup {
            if let Err(err) = self.host.run_command(cmd) {
                self.teardown_net(&plan.net_teardown);
                return Err(err);
            }
        }

        // 2. Spawn the VMM.
        let pid = match self.host.spawn(&plan.spawn) {
            Ok(pid) => pid,
            Err(err) => {
                self.teardown_net(&plan.net_teardown);
                return Err(err);
            }
        };

        // 3. Wait for the API socket, then 4. drive the request sequence. Any
        // failure kills the VMM and tears down the tap.
        if let Err(err) = self
            .host
            .wait_for_socket(&plan.api_socket, self.config.api_timeout)
        {
            self.abort(pid, &plan.net_teardown);
            return Err(err);
        }
        for req in requests {
            if let Err(err) = self
                .host
                .api_request(&plan.api_socket, req, self.config.api_timeout)
            {
                self.abort(pid, &plan.net_teardown);
                return Err(err);
            }
        }

        Ok(RunningVm {
            id: vm_id.to_string(),
            pid,
            api_socket: plan.api_socket.clone(),
            net_teardown: plan.net_teardown.clone(),
        })
    }

    /// Stop a running VM: ask the guest to halt (Ctrl-Alt-Del), then ensure the
    /// VMM process is gone, then tear down its tap. Returns the kill result;
    /// graceful-shutdown and teardown failures are swallowed (best-effort).
    pub fn stop(&self, vm: &RunningVm) -> Result<(), ExecError> {
        let _ = self.host.api_request(
            &vm.api_socket,
            &api::shutdown_request(),
            self.config.api_timeout,
        );
        let killed = self.host.kill(vm.pid);
        self.teardown_net(&vm.net_teardown);
        killed
    }

    /// Kill a spawned VMM and tear down its tap (failure-path cleanup).
    fn abort(&self, pid: Pid, net_teardown: &[HostCommand]) {
        let _ = self.host.kill(pid);
        self.teardown_net(net_teardown);
    }

    /// Run tap teardown commands, ignoring individual failures.
    fn teardown_net(&self, cmds: &[HostCommand]) {
        for cmd in cmds {
            let _ = self.host.run_command(cmd);
        }
    }
}

/// The real host: shells out to `ip`/`nft`/`kill`, spawns Firecracker/jailer,
/// and talks to the API socket. Unix-only; the live behavior needs `/dev/kvm`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemHost;

#[cfg(unix)]
impl Host for SystemHost {
    fn run_command(&self, cmd: &HostCommand) -> Result<(), ExecError> {
        let status = std::process::Command::new(&cmd.program)
            .args(&cmd.args)
            .status()
            .map_err(|e| ExecError::Command {
                program: cmd.program.clone(),
                detail: e.to_string(),
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(ExecError::Command {
                program: cmd.program.clone(),
                detail: format!("exited with {status}"),
            })
        }
    }

    fn spawn(&self, cmd: &SpawnCommand) -> Result<Pid, ExecError> {
        let child = std::process::Command::new(&cmd.program)
            .args(&cmd.args)
            .spawn()
            .map_err(|e| ExecError::Spawn(format!("{}: {e}", cmd.program)))?;
        // Detach: the VM process outlives this call; lifecycle is by pid (`kill`).
        Ok(Pid(child.id()))
    }

    fn wait_for_socket(&self, socket: &Path, timeout: Duration) -> Result<(), ExecError> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if socket.exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err(ExecError::SocketTimeout(socket.to_path_buf()))
    }

    fn api_request(
        &self,
        socket: &Path,
        req: &ApiRequest,
        timeout: Duration,
    ) -> Result<(), ExecError> {
        api::send_over_unix_socket(socket, req, timeout).map_err(|detail| ExecError::Api {
            path: req.path.clone(),
            detail,
        })
    }

    fn kill(&self, pid: Pid) -> Result<(), ExecError> {
        // A non-zero exit (e.g. "no such process") is fine for an idempotent stop.
        match std::process::Command::new("kill")
            .arg(pid.0.to_string())
            .status()
        {
            Ok(_) => Ok(()),
            Err(e) => Err(ExecError::Command {
                program: "kill".to_string(),
                detail: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MachineResources;
    use boatramp_types::compute::{ComputeSpec, RestartPolicy};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn machine() -> FcMachine {
        let spec = ComputeSpec {
            version: 1,
            rootfs: "r".repeat(64),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 128,
            entrypoint: vec!["/app".into()],
            env: BTreeMap::new(),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: boatramp_types::compute::IsolationRequirement::Trusted,
            prefer_backend: None,
        };
        let resources = MachineResources {
            kernel_path: "/k/vmlinux".into(),
            rootfs_path: "/r/app.ext4".into(),
            scratch_path: "/s/vm1.ext4".into(),
            tap_name: "tap-vm1".into(),
            guest_mac: "02:00:0a:00:00:05".into(),
            guest_ip: "10.0.0.5".into(),
        };
        FcMachine::from_spec(&spec, &resources)
    }

    /// A `Host` that records every operation and can force the first op whose
    /// label contains `fail_contains` to fail (to exercise rollback paths).
    struct RecordingHost {
        ops: RefCell<Vec<String>>,
        fail_contains: Option<&'static str>,
    }

    impl RecordingHost {
        fn new(fail_contains: Option<&'static str>) -> Self {
            Self {
                ops: RefCell::new(Vec::new()),
                fail_contains,
            }
        }
        fn record(&self, label: String) -> Result<(), ExecError> {
            let fail = self.fail_contains.is_some_and(|f| label.contains(f));
            self.ops.borrow_mut().push(label.clone());
            if fail {
                Err(ExecError::Io(format!("forced failure at {label}")))
            } else {
                Ok(())
            }
        }
        fn ops(&self) -> Vec<String> {
            self.ops.borrow().clone()
        }
    }

    impl Host for RecordingHost {
        fn run_command(&self, cmd: &HostCommand) -> Result<(), ExecError> {
            self.record(format!("run:{}", cmd.display()))
        }
        fn spawn(&self, cmd: &SpawnCommand) -> Result<Pid, ExecError> {
            self.record(format!("spawn:{}", cmd.program))?;
            Ok(Pid(4242))
        }
        fn wait_for_socket(&self, socket: &Path, _t: Duration) -> Result<(), ExecError> {
            self.record(format!("wait:{}", socket.display()))
        }
        fn api_request(&self, _s: &Path, req: &ApiRequest, _t: Duration) -> Result<(), ExecError> {
            self.record(format!("api:{}", req.path))
        }
        fn kill(&self, pid: Pid) -> Result<(), ExecError> {
            self.record(format!("kill:{}", pid.0))
        }
    }

    fn dev_executor(host: RecordingHost) -> Executor<RecordingHost> {
        Executor::new(host, ExecutorConfig::default())
    }

    fn tap() -> TapNetwork {
        TapNetwork::for_vm("vm1", "br-boatramp")
    }

    #[test]
    fn launch_runs_net_then_spawn_then_wait_then_boot_in_order() {
        let exec = dev_executor(RecordingHost::new(None));
        let vm = exec.launch("vm1", &machine(), &tap()).unwrap();
        assert_eq!(vm.pid, Pid(4242));
        let ops = exec.host.ops();
        // 3 tap commands, then spawn, then wait, then 6 boot requests.
        assert_eq!(ops[0], "run:ip tuntap add tap-vm1 mode tap");
        assert_eq!(ops[3], "spawn:firecracker");
        assert!(ops[4].starts_with("wait:"));
        assert_eq!(
            &ops[5..],
            &[
                "api:/machine-config",
                "api:/boot-source",
                "api:/drives/rootfs",
                "api:/drives/scratch",
                "api:/network-interfaces/eth0",
                "api:/actions",
            ]
        );
        // Happy path: no teardown (no `ip link del`) and no kill.
        assert!(!ops
            .iter()
            .any(|o| o.contains("link del") || o.starts_with("kill:")));
    }

    #[test]
    fn launch_rolls_back_tap_when_spawn_fails() {
        let exec = dev_executor(RecordingHost::new(Some("spawn:")));
        let err = exec.launch("vm1", &machine(), &tap()).unwrap_err();
        assert!(matches!(err, ExecError::Io(_)));
        let ops = exec.host.ops();
        // Tap was set up, spawn failed, tap torn down — and the API was never touched.
        assert_eq!(ops.last().unwrap(), "run:ip link del tap-vm1");
        assert!(!ops.iter().any(|o| o.starts_with("api:")));
        assert!(!ops.iter().any(|o| o.starts_with("kill:")));
    }

    #[test]
    fn launch_kills_and_tears_down_when_socket_times_out() {
        let exec = dev_executor(RecordingHost::new(Some("wait:")));
        assert!(exec.launch("vm1", &machine(), &tap()).is_err());
        let ops = exec.host.ops();
        assert!(ops.iter().any(|o| o == "kill:4242"));
        assert_eq!(ops.last().unwrap(), "run:ip link del tap-vm1");
        assert!(
            !ops.iter().any(|o| o.starts_with("api:")),
            "no boot before the socket is up"
        );
    }

    #[test]
    fn launch_kills_and_tears_down_when_boot_request_fails() {
        let exec = dev_executor(RecordingHost::new(Some("api:/boot-source")));
        assert!(exec.launch("vm1", &machine(), &tap()).is_err());
        let ops = exec.host.ops();
        // machine-config went through; boot-source failed → kill + teardown, and
        // InstanceStart never ran.
        assert!(ops.iter().any(|o| o == "api:/machine-config"));
        assert!(ops.iter().any(|o| o == "kill:4242"));
        assert_eq!(ops.last().unwrap(), "run:ip link del tap-vm1");
        assert!(!ops.iter().any(|o| o == "api:/actions"));
    }

    #[test]
    fn stop_shuts_down_then_kills_then_tears_down() {
        let exec = dev_executor(RecordingHost::new(None));
        let vm = exec.launch("vm1", &machine(), &tap()).unwrap();
        exec.host.ops.borrow_mut().clear();
        exec.stop(&vm).unwrap();
        let ops = exec.host.ops();
        assert_eq!(ops[0], "api:/actions"); // SendCtrlAltDel
        assert!(ops.iter().any(|o| o == "kill:4242"));
        assert_eq!(ops.last().unwrap(), "run:ip link del tap-vm1");
    }

    #[test]
    fn snapshot_pauses_creates_then_resumes() {
        let exec = dev_executor(RecordingHost::new(None));
        let vm = exec.launch("vm1", &machine(), &tap()).unwrap();
        exec.host.ops.borrow_mut().clear();
        exec.snapshot(&vm, "/s/vm1.snap", "/s/vm1.mem").unwrap();
        // pause (/vm), create (/snapshot/create), resume (/vm) — in that order.
        assert_eq!(
            exec.host.ops(),
            vec!["api:/vm", "api:/snapshot/create", "api:/vm"]
        );
    }

    #[test]
    fn snapshot_still_resumes_when_create_fails() {
        let exec = dev_executor(RecordingHost::new(Some("api:/snapshot/create")));
        let vm = RunningVm {
            id: "vm1".into(),
            pid: Pid(4242),
            api_socket: ExecutorConfig::default().api_socket("vm1"),
            net_teardown: tap().teardown_commands(),
        };
        exec.host.ops.borrow_mut().clear();
        let err = exec.snapshot(&vm, "/s/vm1.snap", "/s/vm1.mem").unwrap_err();
        assert!(matches!(err, ExecError::Io(_)));
        // pause, create (fails), resume — the VM is never left paused.
        assert_eq!(
            exec.host.ops(),
            vec!["api:/vm", "api:/snapshot/create", "api:/vm"]
        );
    }

    #[test]
    fn restore_brings_up_tap_spawns_then_loads_snapshot() {
        let exec = dev_executor(RecordingHost::new(None));
        let vm = exec
            .restore("vm1", &tap(), "/s/vm1.snap", "/s/vm1.mem")
            .unwrap();
        assert_eq!(vm.pid, Pid(4242));
        let ops = exec.host.ops();
        // tap up (3), spawn, wait, then exactly the snapshot/load — no boot calls.
        assert_eq!(ops[0], "run:ip tuntap add tap-vm1 mode tap");
        assert_eq!(ops[3], "spawn:firecracker");
        assert!(ops[4].starts_with("wait:"));
        assert_eq!(&ops[5..], &["api:/snapshot/load"]);
        assert!(!ops.iter().any(|o| o == "api:/machine-config"));
    }

    #[test]
    fn restore_rolls_back_when_load_fails() {
        let exec = dev_executor(RecordingHost::new(Some("api:/snapshot/load")));
        assert!(exec
            .restore("vm1", &tap(), "/s/vm1.snap", "/s/vm1.mem")
            .is_err());
        let ops = exec.host.ops();
        assert!(ops.iter().any(|o| o == "kill:4242"));
        assert_eq!(ops.last().unwrap(), "run:ip link del tap-vm1");
    }

    #[test]
    fn restore_plan_has_no_boot_sequence() {
        let plan = LaunchPlan::for_restore("vm1", &tap(), &ExecutorConfig::default());
        assert!(plan.boot.is_empty(), "snapshot carries the machine config");
        assert_eq!(plan.spawn.program, "firecracker");
        assert_eq!(
            plan.api_socket,
            PathBuf::from("/run/boatramp/fc-vm1.socket")
        );
    }

    #[test]
    fn non_jailer_plan_runs_firecracker_directly() {
        let plan = LaunchPlan::build("vm1", &machine(), &tap(), &ExecutorConfig::default());
        assert_eq!(plan.spawn.program, "firecracker");
        assert!(plan.spawn.args.contains(&"--api-sock".to_string()));
        assert_eq!(
            plan.api_socket,
            PathBuf::from("/run/boatramp/fc-vm1.socket")
        );
    }

    #[test]
    fn jailer_plan_wraps_firecracker_and_chroots_the_socket() {
        let config = ExecutorConfig {
            jailer: Some(JailerConfig {
                jailer_bin: "jailer".into(),
                uid: 123,
                gid: 456,
                chroot_base: "/srv/jail".into(),
            }),
            ..ExecutorConfig::default()
        };
        let plan = LaunchPlan::build("vm1", &machine(), &tap(), &config);
        assert_eq!(plan.spawn.program, "jailer");
        let args = plan.spawn.args.join(" ");
        assert!(args.contains("--exec-file firecracker"));
        assert!(args.contains("--uid 123"));
        assert!(args.contains("--chroot-base-dir /srv/jail"));
        assert!(args.contains("-- --api-sock /run/firecracker.socket"));
        // The host-visible socket is inside the per-VM chroot.
        assert_eq!(
            plan.api_socket,
            PathBuf::from("/srv/jail/firecracker/vm1/root/run/firecracker.socket")
        );
    }
}
