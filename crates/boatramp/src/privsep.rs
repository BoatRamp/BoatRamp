//! The privsep root supervisor, feature-instance boot, and the `__root` /
//! `__instance` pre-runtime argv dispatch (privsep Phase 1 — WS-B; design
//! `PLAN-privsep-phase1.md` §2, §4, finding F10). **SECURITY-CRITICAL — this is the
//! minimal TCB floor (the root) + the materialization-by-construction gate.**
//!
//! The root (design §4) is the irreducible, heavily-audited process that resolves the
//! topology, lints the composition fail-closed, and spawns the least-authority
//! instances. It holds BOOTSTRAP AUTHORITY ONLY: it parses no untrusted bytes, opens
//! no pool, unseals no KEK, and materializes no §1.2 authority key input (the
//! secret-blindness guarantee lives in [`boatramp_node::privsep_resolve`], called
//! here before any spawn).
//!
//! WS-B scope (the floor):
//! - **[`classify_argv`] + the `run()` dispatch (F10)** — `__root` / `__instance`
//!   match `argv[1]` EXACTLY, stay OUT of the clap `Command` enum, and engage the
//!   privsep path ONLY when a resolved `[privsep]` section is present. On a
//!   non-privsep node they are a hard refusal; a default (absent-`[privsep]`) boot is
//!   byte-for-byte the unchanged monolith.
//! - **[`plan_root`]** — the pure, fail-closed authorization gate: secret-blind screen
//!   (F1/F11-A) → composition-closure lint (F7, run IN THE ROOT before any spawn) →
//!   the per-instance re-exec spawn spec (argv + the explicitly-minimal, secret-scrubbed
//!   environment, F11-B). A bad composition returns `Err` and NO spawn spec is produced.
//! - **[`MaterializationGate`]** — the per-instance construction gate (design §2.2,
//!   §5 inv1): an authority NOT in the instance's set must never be CONSTRUCTED (no
//!   key unsealed, no pool opened, no listener bound). The full boot path consults
//!   this before building each authority object.
//!
//! WS-C scope (the runtime wiring — this workstream): the root supervisor's
//! [`supervise`] loop (a `socketpair(2)` per `local` link, the privileged public-listener bind +
//! fd-pass, `fork`+`exec` of each `__instance` with its scrubbed env + wired fds, and fail-closed
//! `FailNodeClosed` supervision), and the feature-instance's [`instance_serve`] splice (install the
//! per-capability profile fail-closed `Enforced`, receive the root-wired fds, then accept + splice
//! client fds frontend→backend / receive + serve them). The two HARD WS-C contracts are honored:
//! every path is lexically normalized before derivation
//! ([`boatramp_server::sandbox::lexically_normalize`]), and the composition-layer grant
//! disjointness/coverage is enforced in the root
//! ([`boatramp_server::sandbox::check_grant_disjointness`]).
//!
//! The root's OWN §4.3 self-profile (the TCB floor — the tightest profile on the node) is installed
//! in [`supervise`] AFTER the fork+exec loop + BEFORE the supervise loop (so a child never inherits
//! the root's clamped seccomp/Landlock domain — see the comment at the install site), via the
//! bespoke [`boatramp_server::sandbox::derive_root_profile`] + the shared `install_derived` +
//! `enforce_privsep_status` gate: no network, no key-lock, FS view = the config file + the root's own
//! binary only (`execve` Landlock-pinned to it), everything else `EPERM` / the escape surface killed.
//!
//! Clean seams for later workstreams (fail-closed — never a silent monolith fallback):
//! - **WS-C follow-on** — `tcp`/`overlay` link transports (only `local` is wired here); the other
//!   `listen.*` fd binds beyond the public listener; and the authority-scoped app router (the minimal
//!   backend serve stands in for it).
//! - **WS-D** — the per-capability seccomp/Landlock profile derivation (owned by `sandbox.rs`;
//!   this module CONSUMES it via `derive_profile` + `install_derived` + `enforce_privsep_status`).
//! - **WS-E** — the per-capability authority-API grammar + the re-validated end-principal context
//!   (the link is a BYTE transport here; the grammar layers on [`PrivsepChildFds`]-wired links).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use boatramp_core::privsep::{
    CompositionReport, HostAuthority, InstanceSubstrate, LinkPurpose, PrivsepConfig,
    PrivsepInstanceConfig, check_composition_closure, check_sealed_signer_closure,
    check_vm_secret_blindness_closure,
};
use boatramp_node::privsep_resolve::{self, SecretBlindReport};
use serde::{Deserialize, Serialize};

use crate::config::{self, ServerConfig};
use crate::error::CliError;

// =============================================================================
// Errors
// =============================================================================

/// Any failure of the privsep root / instance path. Fail-closed throughout — the root
/// is the TCB floor, so every one of these refuses to proceed rather than degrading.
#[derive(Debug, thiserror::Error)]
pub enum PrivsepError {
    /// `__root` / `__instance` was invoked (or a serve was routed to the root) on a node
    /// with NO `[privsep]` section (design F10: a node that never composes has no
    /// business re-execing into the root/instance path).
    #[error(
        "privsep entry refused: no [privsep] composition in the config — a non-privsep node \
         boots the monolith and never re-execs `__root`/`__instance`"
    )]
    NotComposed,
    /// The named instance is absent from `[privsep].instances`.
    #[error("privsep instance {0:?} is not defined in [privsep].instances")]
    InstanceNotFound(String),
    /// Loading the server config failed.
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    /// The root's secret-blindness screen refused the config (design F1/F11-A).
    #[error(transparent)]
    SecretBlind(#[from] privsep_resolve::SecretBlindError),
    /// The composition-closure lint refused the composition (design F7). The root fails
    /// the node closed and spawns NOTHING.
    #[error(transparent)]
    Composition(#[from] boatramp_core::privsep::CompositionError),
    /// The composition-layer grant check (WS-C CONTRACT #2) refused: two instances' backend-state
    /// grants overlap, or a hosted backend authority has no state-dir layout entry. Run IN THE
    /// ROOT, fail-closed, before any spawn (what [`boatramp_server::sandbox::derive_profile`]
    /// cannot see from a single instance).
    #[error(transparent)]
    CompositionGrant(#[from] boatramp_server::sandbox::CompositionGrantError),
    /// The `[privsep].per_tenant` scale-to-zero policy is misconfigured (design §Phase-4 WS-C) and
    /// the composition declares a per-tenant template. The root refuses BEFORE any spawn rather
    /// than standing up a template composition that could never instantiate a tenant.
    #[error(transparent)]
    PerTenantPolicy(#[from] boatramp_core::privsep::PerTenantPolicyError),
    /// privsep requires an ENFORCED per-instance sandbox (Linux + the `sandbox` feature). On any
    /// other platform/build the wall cannot be installed, so the root refuses the node closed
    /// rather than spawning instances that would serve without it (design §2 F6).
    #[error(
        "privsep requires a Linux node built with the `sandbox` feature (the per-instance \
         seccomp/Landlock wall is load-bearing + fail-closed) — refusing on this platform/build"
    )]
    UnsupportedPlatform,
    /// A root-supervisor runtime failure (socketpair/link wiring, listener bind, fork+exec, fd
    /// pass, or a supervised child exiting — `FailNodeClosed`). Fail-closed: the root tears the
    /// node down rather than serving degraded.
    #[error("privsep root supervisor: {0}")]
    Supervise(String),
    /// The composition asked the node to SELF-HOST its own serve path under privsep
    /// (`[privsep].node_serve = node-self-host`) — the node's OWN control-plane/admin API, gateway,
    /// handler engine, and managed-DB/KV/blob backends served UNDER the composition, not only guest
    /// workloads — but that serve path is **NOT YET WIRED** (design §Phase-5, pending its own
    /// Security review). Refused fail-closed in the root BEFORE any spawn rather than silently
    /// serving the node's REAL app from a stubbed / under-confined instance (the "no silent
    /// downgrade" invariant). The marker [`NODE_SELF_HOST_UNWIRED_MARKER`] is greppable + invertible:
    /// when the Phase-5 serve path lands it flips from this refusal to a live serve gate.
    #[error(
        "privsep node self-hosting refused: {0} — {marker}. Refusing fail-closed; use the default \
         `node_serve = guest-workloads` composition until the Phase-5 self-host serve path is wired",
        marker = NODE_SELF_HOST_UNWIRED_MARKER
    )]
    NodeSelfHostUnwired(String),
    /// A feature-instance runtime failure (sandbox derive/install, fd receive, or serve). The
    /// instance refuses to serve rather than degrade.
    #[error("privsep instance {label:?}: {reason}")]
    InstanceServe {
        /// The instance label.
        label: String,
        /// What failed.
        reason: String,
    },
}

// =============================================================================
// Pre-runtime argv dispatch (F10)
// =============================================================================

/// The internal argv[1] token that engages the root supervisor.
pub const ROOT_SUBCOMMAND: &str = "__root";
/// The internal argv[1] token that engages a feature-instance.
pub const INSTANCE_SUBCOMMAND: &str = "__instance";

/// What a `boatramp` argv opens into, decided BEFORE clap (design F10). Mirrors the
/// `__sandbox` / `__vmm-run` / `__vz-run` precedent: an exact `argv[1]` match, kept out
/// of the clap `Command` enum entirely (internal, never user-facing / completion /
/// `--help`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvEntry {
    /// `boatramp __root` — engage the root supervisor.
    Root,
    /// `boatramp __instance <label>` — engage that feature-instance.
    Instance(String),
    /// Anything else — the ordinary clap-parsed CLI (the monolith path included).
    Normal,
}

/// Classify a `boatramp` argv for the pre-runtime privsep dispatch (design F10). `argv`
/// is the full process argv (`argv[0]` is the program). An `__instance` with no label
/// still classifies as [`ArgvEntry::Instance`] with an empty label, which
/// [`run_instance`] then refuses loudly.
pub fn classify_argv(argv: &[String]) -> ArgvEntry {
    match argv.get(1).map(String::as_str) {
        Some(ROOT_SUBCOMMAND) => ArgvEntry::Root,
        Some(INSTANCE_SUBCOMMAND) => ArgvEntry::Instance(argv.get(2).cloned().unwrap_or_default()),
        _ => ArgvEntry::Normal,
    }
}

/// Resolve the config-file path from a pre-clap argv: the value after `--config`, else
/// the `boatramp.cfg` serve default (the same default the clap `serve` path uses). Kept
/// minimal because the clap parser is deliberately bypassed for the `__*` entries.
pub fn config_path_from_argv(argv: &[String]) -> PathBuf {
    for (i, a) in argv.iter().enumerate() {
        if let Some(p) = a.strip_prefix("--config=") {
            return PathBuf::from(p);
        }
        if a == "--config"
            && let Some(p) = argv.get(i + 1)
        {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("boatramp.cfg")
}

// =============================================================================
// The root: lint-before-spawn authorization + the re-exec spawn primitive
// =============================================================================

/// One instance's re-exec spawn spec — the SECURITY-CRITICAL primitive the root
/// produces per authorized instance (design §2, §4.1). The actual `.spawn()` + the
/// link/listener fd-pass + supervision are WS-C; this is the fully-formed, tested
/// command + environment the root hands the OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSpawnSpec {
    /// The operator label (the `[privsep].instances` key).
    pub label: String,
    /// The fine-grained authority set this instance materializes.
    pub capabilities: Vec<HostAuthority>,
    /// The ISOLATION SUBSTRATE this instance's spawn backend uses (design §7 "substrate is a spawn
    /// backend"). The supervisor dispatches on it: `OsProcess` is the Phase-1 fork+exec backend,
    /// `Container` the Phase-3 one (the SAME fork+exec, the child additionally unsharing
    /// NS/IPC/UTS/CGROUP in its `pre_exec` — design-note Option C / §8). `Vm` (the scoped first cut —
    /// the root boots the microVM guest + supervises a separate `__vm-relay`) is NOW WIRED: its
    /// supervise-dispatch is live-proven (serve + kill→FailNodeClosed) and Security-reviewed (SHIP), so
    /// `resolve_spawn_backend` DISPATCHES the scoped key-free static-parser frontend shape and refuses
    /// any other VM shape fail-closed.
    pub substrate: InstanceSubstrate,
    /// The re-exec argv TAIL (after `argv[0]`): `["__instance", "<label>", "--config", "<path>"]`.
    pub argv: Vec<String>,
    /// The EXPLICITLY MINIMAL, secret-scrubbed environment for this instance (design
    /// F11-B). The root spawns with `Command::env_clear().envs(this)`, so nothing else is
    /// inherited and no live credential is ever couriered in.
    pub env: BTreeMap<String, String>,
}

impl InstanceSpawnSpec {
    /// Build the ready-to-spawn [`std::process::Command`] (the re-exec): `env_clear` +
    /// the minimal scrubbed env + the `__instance` argv tail. WS-C drives `.spawn()`
    /// and passes the link/listener fds; this is the primitive it calls.
    ///
    /// `#[allow(dead_code)]` carries it as that deliberate WS-C seam (exercised by the
    /// tests) until the supervise loop calls it.
    #[allow(dead_code)]
    pub fn to_command(&self, current_exe: &Path) -> std::process::Command {
        let mut cmd = std::process::Command::new(current_exe);
        cmd.args(&self.argv).env_clear().envs(&self.env);
        cmd
    }
}

/// The root's authorized plan: the composition passed BOTH the secret-blind screen and
/// the composition-closure lint, and every instance has a spawn spec. The presence of
/// this value is the proof that spawning is authorized (design §5 inv4).
#[derive(Debug, Clone)]
pub struct RootPlan {
    /// The spawn specs for the BOOT-FORKED static instances (lifecycle = `Static`) — forked ONCE at
    /// boot by the root supervisor and held for the node's life. Stable order (the
    /// `[privsep].instances` map is sorted). This is the set the supervise loop fork+execs; a
    /// per-tenant template is NOT here (design §Phase-4 WS-C — a template boot-forked once, with no
    /// wired `BOATRAMP_PRIVSEP_TENANT_SCOPE`, would die `Unwired` → `FailNodeClosed`).
    pub static_instances: Vec<InstanceSpawnSpec>,
    /// The spawn specs for the per-tenant TEMPLATE instances (lifecycle = `PerTenantTemplate`) — NOT
    /// forked at boot. The per-tenant router (the frontend) instantiates one copy per active tenant
    /// on demand, wiring each a fresh `BOATRAMP_PRIVSEP_TENANT_SCOPE` + socketpair link
    /// ([`InstanceSpawnSpec`] via the root's own fork+exec primitive). An authorized composition has
    /// at most a handful (the Phase-4 cut wires exactly one wasm template).
    pub templates: Vec<InstanceSpawnSpec>,
    /// The secret-blindness report (the opaque-reference tally).
    pub secret_blind: SecretBlindReport,
    /// The composition-closure report (any non-fatal flags to log).
    pub composition: CompositionReport,
}

impl RootPlan {
    /// Every spawn spec (static + template), for logging the whole authorized plan.
    pub fn all_specs(&self) -> impl Iterator<Item = &InstanceSpawnSpec> {
        self.static_instances.iter().chain(self.templates.iter())
    }
}

/// The greppable, invertible marker the root emits when it refuses node self-hosting because the
/// Phase-5 serve path is not wired (design §Phase-5). It is the counterpart of the live-serve
/// markers the `live gate (privsep)` CI job greps (e.g. `PRIVSEP LIVE OK`): the `#[ignore]`d
/// end-to-end gate asserts THIS marker today, and the SAME gate flips to assert a live serve marker
/// once the self-host serve path + its Security review land — the single, mechanical inversion point.
pub const NODE_SELF_HOST_UNWIRED_MARKER: &str = "PRIVSEP_NODE_SELF_HOST_UNWIRED";

/// The root's fail-closed NODE SELF-HOSTING gate (design §Phase-5). Refuses a composition that asks
/// the node to serve its OWN serve path (control-plane/admin API, gateway, handler engine, the
/// managed-DB/KV/blob backends) UNDER the privsep composition — [`NodeServeMode::NodeSelfHost`] —
/// because that serve path is **NOT YET WIRED** (today a `backend.*` instance serves only the minimal
/// stub; the authority-scoped node app router is the Phase-5 workstream, pending its own Security
/// review). A `None` / [`NodeServeMode::GuestWorkloads`] composition (every pre-Phase-5 node) is a
/// NO-OP, so no running composition changes — this only refuses the not-yet-buildable self-host mode,
/// loud and fail-closed, never a silent downgrade to the stubbed serve.
///
/// Mirrors [`resolve_spawn_backend`]'s substrate gate: keyed on a wired/not-wired vocabulary
/// ([`NodeServeMode::is_wired`]), refusing BEFORE any allocation. Pure (host-testable). When the
/// Phase-5 serve path lands, [`NodeServeMode::is_wired`] flips for `NodeSelfHost` and this gate
/// admits it (and the `#[ignore]`d live gate inverts from the refusal marker to a live serve marker).
fn check_node_self_host_gate(privsep: &PrivsepConfig) -> Result<(), PrivsepError> {
    if privsep.node_serve.is_wired() {
        return Ok(());
    }
    Err(PrivsepError::NodeSelfHostUnwired(format!(
        "composition selects `node_serve = {}`, whose self-host serve path is not wired in this cut",
        privsep.node_serve.tag()
    )))
}

/// Build the root's authorized spawn plan — the PURE, fail-closed authorization gate
/// (design §4.1, §5 inv4/inv6). Runs, in order and all before any spawn:
/// 1. the secret-blind screen (F1/F11-A) over the resolved config;
/// 2. the composition-closure lint (F7) over the `[privsep]` topology;
/// 3. the per-instance re-exec spawn spec (argv + the minimal scrubbed env, F11-B).
///
/// Returns `Err` on an absent `[privsep]`, a secret-blindness violation, or any
/// composition violation — in every case NO spawn spec is produced (a bad composition
/// never spawns). `config_path` is threaded into each instance's `--config` argv;
/// `parent_env` is the root's environment (passed in so this stays pure + testable).
pub fn plan_root<I>(
    cfg: &ServerConfig,
    config_path: &Path,
    parent_env: I,
) -> Result<RootPlan, PrivsepError>
where
    I: IntoIterator<Item = (String, String)> + Clone,
{
    let privsep = cfg.privsep.as_ref().ok_or(PrivsepError::NotComposed)?;

    // 1. Secret-blindness (F1/F11-A) — the root materializes no §1.2 key input.
    let secret_blind = privsep_resolve::screen_secret_blind(cfg)?;

    // 2. Composition-closure (F7) — fail-closed, IN THE ROOT, BEFORE any spawn.
    let composition = check_composition_closure(privsep)?;

    // 2b. Sealed-signer closure (the "signer-key unlock" owner decision): a `[serve.signer]` sealed
    //     key source REQUIRES a `secrets.sealer` reachable from the `token.signer` instance (it
    //     cannot hold the KEK itself), else the key could never be unsealed. Fail-closed, same error
    //     surface as the main lint.
    let sealed_signer = privsep_resolve::sealed_signer_key_ref(cfg).is_some();
    check_sealed_signer_closure(privsep, sealed_signer)?;

    // 2b-vm. VM secret-blindness + scope closure (S2 — `DESIGN-privsep-phase3-vm-derisk.md` §2.3): a
    //     key-material-bearing link (a `secrets.sealer`↔`token.signer` unseal unlock, OR a
    //     serve-designated-to-sealer link — now the FULL `compute_authority_serve_links` shape, not
    //     `AuthorityServe`-only) relayed across a `substrate: Vm` boundary would route KEK-unsealed
    //     plaintext through the SECRET-BLIND root's vsock relay (Tier 1); a VM key holder must be
    //     self-sufficient for its own unlock — co-reside its sealer or hold no key (Tier 2); and a VM
    //     instance must stay WITHIN the approved scope — a key-free listener-only parser frontend (P3)
    //     or a co-located sealer bundle (P1), never a key-free backend/exec/control instance (Tier 3,
    //     the companion scope lint). Structural, fail-closed, same error surface as the main lint. A
    //     no-op on any composition with NO `substrate: Vm` instance (a VM is itself an unwired follow-on
    //     substrate, refused at supervise), so this changes no running composition — it refuses an
    //     unsafe VM topology at the composition gate, before any transport exists.
    check_vm_secret_blindness_closure(privsep, sealed_signer)?;

    // 2c. Per-tenant scale-to-zero policy (design §Phase-4 WS-C): fail-closed BEFORE any spawn when
    //     the composition declares a per-tenant template, so a misconfigured policy (e.g. a 0
    //     concurrency cap that could never serve a tenant) refuses the node closed rather than
    //     standing up a template composition that cannot instantiate. A no-template composition
    //     never reads the policy (byte-compat), so this is gated on template presence.
    let has_per_tenant_template = privsep
        .instances
        .values()
        .any(|i| i.lifecycle.is_per_tenant_template());
    if has_per_tenant_template {
        privsep.per_tenant.validate()?;
    }

    // 2d. NODE SELF-HOSTING gate (design §Phase-5): a composition that asks the node to serve its OWN
    //     serve path (control-plane/admin API, gateway, handler engine, managed-DB/KV/blob backends)
    //     UNDER the privsep composition (`node_serve = node-self-host`) is refused fail-closed — that
    //     serve path is not yet wired (today a backend instance serves only the minimal stub; the
    //     authority-scoped node app router is the Phase-5 workstream, pending its own Security
    //     review). A `guest-workloads` (the default) composition is a no-op here, so no running
    //     composition changes; this only refuses the not-yet-buildable self-host mode, loud and
    //     fail-closed, before any spawn — never a silent downgrade to the stubbed serve.
    check_node_self_host_gate(privsep)?;

    // 3. The per-instance re-exec spawn spec (F11-B minimal env). Reached ONLY after
    //    both gates pass — so a refused composition yields no spawn spec at all.
    let path_str = config_path.to_string_lossy().into_owned();
    // The config-driven secret-env set (Finding 1): env-var names the config declares as
    // secret references (`url_env`/`password_env`/…), scrubbed from every instance's env.
    let declared_secret_env = privsep_resolve::declared_secret_env_var_names(cfg);
    // Partition on lifecycle (design §Phase-4 WS-C): STATIC instances are fork+exec'd once at boot;
    // per-tenant TEMPLATE instances are built as spawnable specs but NOT forked here — the per-tenant
    // router instantiates them on demand, one per tenant, wiring each its own scope + socketpair.
    // The spec (argv + the minimal secret-scrubbed env, F11-B) is built IDENTICALLY for both, so a
    // template's on-demand child inherits NO secret either (the env_clear contract is the same).
    let mut static_instances: Vec<InstanceSpawnSpec> = Vec::new();
    let mut templates: Vec<InstanceSpawnSpec> = Vec::new();
    for (label, inst) in &privsep.instances {
        let argv = vec![
            INSTANCE_SUBCOMMAND.to_string(),
            label.clone(),
            "--config".to_string(),
            path_str.clone(),
        ];
        let env = privsep_resolve::build_instance_env(
            parent_env.clone(),
            &inst.capabilities,
            &declared_secret_env,
        );
        let spec = InstanceSpawnSpec {
            label: label.clone(),
            capabilities: inst.capabilities.clone(),
            substrate: inst.substrate,
            argv,
            env,
        };
        if inst.lifecycle.is_per_tenant_template() {
            templates.push(spec);
        } else {
            static_instances.push(spec);
        }
    }

    Ok(RootPlan {
        static_instances,
        templates,
        secret_blind,
        composition,
    })
}

/// Run the root supervisor for the EXPLICIT `boatramp __root` entry: load the config,
/// then delegate to [`run_root_with_config`]. Refuses a non-privsep node (design F10).
pub fn run_root(config_path: &Path) -> Result<(), CliError> {
    crate::init_tracing();
    let config = ServerConfig::load(config_path, None).map_err(PrivsepError::from)?;
    run_root_with_config(config, config_path)
}

/// Scrub every secret-bearing var from THIS process's OWN environment (design §5
/// inv10: "the root process never holds a live token in its own environ"). The resolved
/// config is already secret-blind by [`plan_root`]'s screen; this additionally clears a
/// live credential the process merely INHERITED (e.g. an operator's `VAULT_TOKEN`) so
/// the root/instance holds none even transiently, and a child built from this environ is
/// clean by inheritance too (belt-and-suspenders beside [`InstanceSpawnSpec::env`]).
///
/// Called once at root/instance entry, in the pre-runtime window — the ONLY sound place
/// to mutate the global environment.
fn scrub_own_environ() {
    let to_remove: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| privsep_resolve::is_secret_bearing_env_var(k))
        .collect();
    for name in &to_remove {
        // SAFETY: edition-2024 `std::env::remove_var` is `unsafe` because a concurrent
        // getenv/setenv on another thread is UB. The privsep entries dispatch in the
        // pre-runtime window (beside the `__sandbox`/`__vmm-run`/`__vz-run` workers,
        // design F10), before the Tokio runtime is built and before any thread is
        // spawned, so no other thread can touch the environment here.
        unsafe { std::env::remove_var(name) };
    }
    if !to_remove.is_empty() {
        tracing::debug!(
            scrubbed = to_remove.len(),
            "[privsep] scrubbed secret-bearing vars from the process's own environ (inv10)"
        );
    }
}

/// Run the root supervisor with an already-resolved config (the IMPLICIT entry: a
/// `boatramp serve` whose config carries a `[privsep]` section). Screens + lints
/// fail-closed, logs the authorized plan, then stops at the WS-C transport seam.
pub fn run_root_with_config(config: ServerConfig, config_path: &Path) -> Result<(), CliError> {
    // Clear any inherited live credential from the root's OWN environ FIRST (inv10), so
    // the root holds none and the per-instance env is built from an already-clean base.
    scrub_own_environ();
    // Collect the root's environment up front: `std::env::Vars` is not `Clone`, and
    // `plan_root` clones the parent env once per instance to build each minimal child env.
    let parent_env: Vec<(String, String)> = std::env::vars().collect();
    let plan = plan_root(&config, config_path, parent_env)?;
    // Present by construction (`plan_root` refused an absent `[privsep]`); re-borrowed for the
    // composition-layer grant check + the supervise wiring below.
    let privsep = config.privsep.as_ref().ok_or(PrivsepError::NotComposed)?;

    // The composition is AUTHORIZED. Log the non-fatal composition flags so an operator
    // sees them (crown-jewel duplication; the F8 backend/exposed co-residency).
    for w in &plan.composition.warnings {
        tracing::warn!(flag = %w, "[privsep] composition flag");
    }
    tracing::info!(
        static_instances = plan.static_instances.len(),
        templates = plan.templates.len(),
        opaque_secret_refs = plan.secret_blind.opaque_reference_count,
        "[privsep] root: composition authorized (secret-blind + closure-lint clean); the root \
         holds bootstrap authority only"
    );
    for spec in plan.all_specs() {
        let per_tenant_template = plan.templates.iter().any(|t| t.label == spec.label);
        tracing::info!(
            instance = %spec.label,
            capabilities = spec.capabilities.len(),
            substrate = spec.substrate.tag(),
            env_vars = spec.env.len(),
            per_tenant_template,
            "[privsep] root: instance authorized ({})",
            if per_tenant_template {
                "per-tenant template — instantiated on demand, NOT boot-forked"
            } else {
                "static — boot-forked, re-exec __instance, minimal scrubbed env"
            }
        );
    }

    // Composition-layer grant check (WS-C CONTRACT #2), run IN THE ROOT, fail-closed, BEFORE any
    // spawn — the companion to the closure lint that `derive_profile` cannot make from a single
    // instance's view: every instance's backend-state grants must be mutually disjoint and the
    // state-dir map must cover every hosted backend authority. Keyed off the SAME normalized
    // data_dir the instances will derive against (both resolve `current_dir()` identically — the
    // children inherit the root's CWD across fork+exec).
    let cwd = std::env::current_dir().map_err(|e| PrivsepError::Supervise(format!("cwd: {e}")))?;
    let data_dir = normalized_data_dir(&config, &cwd);
    let caps_by_instance: BTreeMap<String, BTreeSet<HostAuthority>> = privsep
        .instances
        .iter()
        .map(|(label, inst)| (label.clone(), inst.capabilities.iter().copied().collect()))
        .collect();
    boatramp_server::sandbox::check_grant_disjointness(&caps_by_instance, &data_dir)
        .map_err(PrivsepError::from)?;

    // The composition is fully AUTHORIZED. Create the socketpair(2) link fds, bind + pass the
    // privileged listener fds, fork+exec each `__instance`, and run the supervise loop
    // (crown-jewel FailNodeClosed). The whole live path requires the load-bearing sandbox wall, so
    // it refuses the node closed on any non-Linux / non-`sandbox` build (the children could not
    // install an `Enforced` profile there).
    if !cfg!(all(target_os = "linux", feature = "sandbox")) {
        return Err(PrivsepError::UnsupportedPlatform.into());
    }

    // HIGH-1 (final privsep Security re-review) defense-in-depth #3 — DEFERRED as a `// TODO`, by
    // design. The reviewer suggested asserting `kernel.yama.ptrace_scope >= 1` at root boot as a
    // belt-and-suspenders check against cross-instance `/proc/<pid>/mem` reads. It is intentionally NOT
    // implemented here because: (a) the hole is already closed COMPLETELY and more robustly by the
    // PRIMARY fix — every instance + the relay call `sandbox::set_process_undumpable()`
    // (`PR_SET_DUMPABLE(0)`) post-exec, which makes a target's `/proc/<pid>/mem` root-owned and
    // `ptrace_may_access`-gated INDEPENDENTLY of Yama; and (b) a naive fail-CLOSED assertion would be
    // WRONG — a hardened kernel may ship WITHOUT `CONFIG_SECURITY_YAMA` (the `ptrace_scope` sysctl then
    // does not exist) yet still be fully protected by (a), so refusing to boot on a missing/zero
    // `ptrace_scope` would reject a safe node. A correct version would read
    // `/proc/sys/kernel/yama/ptrace_scope` best-effort and only WARN (never refuse) when Yama is present
    // and 0, and would be gated on a decision about the privsep V5 kernel's Yama config — more than a
    // few lines of careful plumbing for a purely-redundant signal. Tracked as a follow-up, not folded
    // into this HIGH-1 fix.
    // TODO(privsep-high1): best-effort WARN if `/proc/sys/kernel/yama/ptrace_scope` exists and reads 0.

    supervise::run(&config, &plan, config_path).map_err(Into::into)
}

/// The node data dir, made absolute against `cwd` + lexically normalized — the SAME transform
/// [`privsep_resolve::build_instance_sandbox_inputs`] applies, so the root's grant check and each
/// instance's derivation key off an identical path.
fn normalized_data_dir(config: &ServerConfig, cwd: &Path) -> PathBuf {
    let raw = privsep_resolve::resolve_data_dir(config);
    let abs = if raw.is_absolute() {
        raw
    } else {
        cwd.join(raw)
    };
    boatramp_server::sandbox::lexically_normalize(&abs)
}

/// Make `raw` absolute (against `cwd`) + lexically normalized, then `fs::canonicalize` it if it
/// already exists (resolving symlinks) — the SAME transform
/// [`boatramp_server::sandbox::SandboxDerivationInputs::into_normalized`] applies to every instance's
/// grants (WS-C contract #1), so an fd-based Landlock install grants the REAL paths and a
/// `..`/symlink/relative spelling cannot slip a different path past the (lexical) policy.
/// `current_exe()` is already absolute + canonical; a config path (or the vsock UDS path) may be
/// relative. Shared by the root self-profile install ([`supervise`]) and the separate VM relay's
/// profile install ([`run_vm_relay`]) — one normalize helper, not two.
#[cfg(unix)]
fn normalize_for_landlock(raw: &Path, cwd: &Path) -> PathBuf {
    let abs = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    let lexical = boatramp_server::sandbox::lexically_normalize(&abs);
    std::fs::canonicalize(&lexical).unwrap_or(lexical)
}

// =============================================================================
// The feature-instance: the materialization-by-construction gate (§2.2)
// =============================================================================

/// The per-instance materialization-by-construction gate (design §2.2, §5 inv1). An
/// instance holds a fine-grained authority SUBSET; an authority NOT in the set must
/// never be CONSTRUCTED (no key unsealed, no pool opened, no listener bound). The full
/// boot path (WS-C+) consults this gate before building each authority object — the
/// PRIMARY containment layer (caveat 5: inert code), complemented by the WS-D profile
/// wall and the WS-E link mediation.
#[derive(Debug, Clone)]
pub struct MaterializationGate {
    held: BTreeSet<HostAuthority>,
}

/// The gate refused construction of an authority this instance does not hold — a
/// fail-closed bug tripwire (the profile wall + link mediation are the other layers).
///
/// Returned only by [`MaterializationGate::ensure`], whose callers are the
/// per-authority construction sites wired in WS-C; `#[allow(dead_code)]` carries it as
/// that deliberate API seam until then (it is exercised by this module's tests).
#[derive(Debug, Clone, thiserror::Error)]
#[allow(dead_code)]
#[error(
    "privsep: instance must not construct `{0}` — the authority is not in its capability set \
     (materialization-by-construction, design §2.2)"
)]
pub struct DroppedAuthorityError(pub HostAuthority);

impl MaterializationGate {
    /// Build the gate from an instance's capability set (dropping duplicates).
    pub fn new(capabilities: &[HostAuthority]) -> Self {
        Self {
            held: capabilities.iter().copied().collect(),
        }
    }

    /// Whether this instance may MATERIALIZE `authority` (construct its object: unseal
    /// its key / open its pool / bind its listener).
    ///
    /// The WS-C per-authority construction sites are the callers; `#[allow(dead_code)]`
    /// carries this as that deliberate API seam until then (exercised by the tests).
    #[allow(dead_code)]
    pub fn may_materialize(&self, authority: HostAuthority) -> bool {
        self.held.contains(&authority)
    }

    /// Fail-closed guard the construction path calls before building an authority
    /// object: `Ok` if held, else a [`DroppedAuthorityError`] (the object must not exist
    /// in this address space).
    ///
    /// The WS-C per-authority construction sites are the callers; `#[allow(dead_code)]`
    /// carries this as that deliberate API seam until then (exercised by the tests).
    #[allow(dead_code)]
    pub fn ensure(&self, authority: HostAuthority) -> Result<(), DroppedAuthorityError> {
        if self.may_materialize(authority) {
            Ok(())
        } else {
            Err(DroppedAuthorityError(authority))
        }
    }

    /// The authorities this instance holds (sorted).
    pub fn held(&self) -> impl Iterator<Item = HostAuthority> + '_ {
        self.held.iter().copied()
    }

    /// The authorities this instance has DROPPED — everything in the full `all` set it
    /// does not hold (what the WS-D profile must deny materializing).
    pub fn dropped(&self) -> Vec<HostAuthority> {
        HostAuthority::ALL
            .iter()
            .copied()
            .filter(|a| !self.held.contains(a))
            .collect()
    }
}

/// Resolve one instance's on-disk slice (design §2.1 step 1) — the pure refusal gate:
/// a non-privsep node is [`PrivsepError::NotComposed`] (F10), an unknown label is
/// [`PrivsepError::InstanceNotFound`]. Pure (no IO / tracing) so both refusals are
/// unit-testable.
fn resolve_instance_slice<'a>(
    config: &'a ServerConfig,
    label: &str,
) -> Result<&'a PrivsepInstanceConfig, PrivsepError> {
    let privsep = config.privsep.as_ref().ok_or(PrivsepError::NotComposed)?;
    privsep
        .instances
        .get(label)
        .ok_or_else(|| PrivsepError::InstanceNotFound(label.to_string()))
}

/// The namespaces the container substrate unshares + self-checks, in the fixed order of the baseline
/// value (see [`PRIVSEP_CONTAINER_NS_ENV`] / [`read_own_ns_baseline`]).
#[cfg(target_os = "linux")]
const CONTAINER_NS_KINDS: [&str; 4] = ["mnt", "ipc", "uts", "cgroup"];

/// The root's OWN namespace identities, read from `/proc/self/ns/<kind>` for each of
/// [`CONTAINER_NS_KINDS`] and `;`-joined (the magic-symlink targets, e.g. `mnt:[4026531840]`, which
/// contain no `;`). The root never unshares — it stays in the host namespaces — so this is the OUTER
/// baseline a container-substrate instance must have moved OFF of. NON-SECRET (inode identities only),
/// passed to each container instance via [`PRIVSEP_CONTAINER_NS_ENV`]. `None` if a readlink fails
/// (then a container instance gets no baseline and fail-closes its self-check). Linux-only.
#[cfg(target_os = "linux")]
fn read_own_ns_baseline() -> Option<String> {
    let mut parts = Vec::with_capacity(CONTAINER_NS_KINDS.len());
    for ns in CONTAINER_NS_KINDS {
        let link = std::fs::read_link(format!("/proc/self/ns/{ns}")).ok()?;
        parts.push(link.to_string_lossy().into_owned());
    }
    Some(parts.join(";"))
}

/// Fail-closed CONFIRMATION that a `substrate: container` instance really entered the fresh
/// namespaces the root unshared for it in its `pre_exec` (design-note Option C, the SIMPLE model).
///
/// The root did `unshare(CLONE_NEWNS|NEWIPC|NEWUTS|NEWCGROUP)` in THIS child before the re-exec; all
/// four take effect for the CALLING process immediately, so this process's own namespaces must DIFFER
/// from the root supervisor's (which stays in the outer namespaces). We read our OWN
/// `/proc/self/ns/<kind>` magic-symlink targets (the kernel's per-namespace inode identity) and
/// compare them to the root's baseline, which the root PUSHED DOWN via [`PRIVSEP_CONTAINER_NS_ENV`].
/// If any of the four MATCHES the root's, the `unshare` did not take effect (a spawn-dispatch
/// regression that spawned the Container instance like a plain OS process), and we refuse to serve.
///
/// **Why the baseline is pushed down, not read up.** Reading the root's `/proc/<ppid>/ns/*` needs
/// ptrace-read access, and the same-uid rule ALSO requires the caller's capabilities to be a superset
/// of the target's — which this instance (whose caps were fully dropped in `pre_exec`, Finding 2) is
/// NOT, against the full-capability root. Reading our OWN `/proc/self/ns` needs no ptrace, so it works
/// after the cap drop. `pid` is deliberately NOT checked: `CLONE_NEWPID` is excluded on the simple
/// model (see `spawn_wired_instance` + the design note). Linux-only.
#[cfg(target_os = "linux")]
fn verify_container_namespaces_unshared(label: &str) -> Result<(), String> {
    let baseline = std::env::var(PRIVSEP_CONTAINER_NS_ENV).map_err(|_| {
        format!(
            "container-substrate instance {label:?} has no namespace baseline \
             ({PRIVSEP_CONTAINER_NS_ENV} unset) — cannot confirm the unshare; refusing to serve \
             (FailNodeClosed)"
        )
    })?;
    let root_ns: Vec<&str> = baseline.split(';').collect();
    if root_ns.len() != CONTAINER_NS_KINDS.len() {
        return Err(format!(
            "container-substrate instance {label:?}: malformed namespace baseline \
             ({PRIVSEP_CONTAINER_NS_ENV}={baseline:?}) — refusing to serve (FailNodeClosed)"
        ));
    }
    for (ns, root) in CONTAINER_NS_KINDS.iter().zip(root_ns.iter()) {
        let mine = std::fs::read_link(format!("/proc/self/ns/{ns}"))
            .map_err(|e| format!("container substrate: reading /proc/self/ns/{ns}: {e}"))?;
        if mine.to_string_lossy() == *root {
            return Err(format!(
                "container-substrate instance {label:?} shares the root supervisor's {ns} namespace \
                 ({root}) — the unshare did not take effect, so the namespace/cgroup wall is NOT up. \
                 Refusing to serve unconfined (no silent downgrade to an OS process) — FailNodeClosed"
            ));
        }
    }
    Ok(())
}

/// Run a feature-instance (`boatramp __instance <label>`, or the root's spawned child):
/// resolve its slice, build its materialization gate, log the held/dropped authorities,
/// then stop at the WS-C serving seam. Refuses a non-privsep node / an unknown label
/// (design F10, §2).
pub fn run_instance(label: &str, config_path: &Path) -> Result<(), CliError> {
    // Privsep's load-bearing wall is the per-instance Enforced sandbox; on any non-Linux /
    // non-`sandbox` build an instance cannot install it, so refuse to serve rather than run
    // unsandboxed — including the dev-only `Off` posture. The root already refuses off-Linux at
    // spawn; this backstops a manual `boatramp __instance` invocation for consistency (Security
    // re-review INFO), so no privsep instance ever serves unsandboxed on a non-Linux Unix host.
    // Checked FIRST (before `init_tracing` / `scrub_own_environ`) so the HIGH-1 dumpable flip below
    // can be the very first thing a Linux instance does.
    if !cfg!(all(target_os = "linux", feature = "sandbox")) {
        return Err(PrivsepError::UnsupportedPlatform.into());
    }

    // HIGH-1 (final privsep Security re-review) — mark THIS served instance NON-dumpable as the VERY
    // FIRST step (right after the platform gate, BEFORE `init_tracing` + `scrub_own_environ`), so a
    // compromised SAME-UID sibling in the shared host pid namespace cannot
    // `openat("/proc/<our-pid>/mem")` + `pread64` a crown-jewel key out of our mlocked memory, bypassing
    // the ptrace/process_vm_readv seccomp KILL (that VFS read issues no ptrace syscall). With dumpable=0
    // the kernel reparents our `/proc/<pid>/*` to root:root and gates it behind `ptrace_may_access`,
    // which the capless sibling fails (`EPERM`) REGARDLESS of `kernel.yama.ptrace_scope`.
    //
    // Ordered BEFORE `init_tracing` / `scrub_own_environ` on purpose (re-review INFO hardening): on the
    // MANUAL `boatramp __instance` backstop entry (NOT the production root-spawn, which hands over an
    // already-scrubbed minimal env, so it is immune) an inherited env credential sits in a
    // still-dumpable `/proc/<pid>/environ` until `scrub_own_environ` clears it — a sub-ms window a
    // sibling could read. Flipping dumpable=0 FIRST closes that window too (dumpable=0 also walls off
    // `/proc/<pid>/environ`). The flip is `prctl`-only with NO dependencies (needs no tracing, no
    // config), so it is safe to run before everything else; it is still well before any key
    // materialization (keys load later, in `instance_serve::run`), so nothing sensitive precedes it.
    //
    // This MUST live here in the re-exec'd instance — POST-execve — NOT in `spawn_wired_instance`'s
    // pre_exec: a non-setuid execve RESETS dumpable to 1, so a pre_exec value would be clobbered (see
    // `set_process_undumpable`). Load-bearing for HIGH-1 ⇒ fail-closed (refuse to serve if it fails). Own
    // `/proc/self/*` access is unaffected, so the container `/proc/self/ns` self-check + `/proc/self/fd`
    // magic symlinks below keep working. Covers OsProcess + Container instances (and every per-tenant
    // child, which also re-execs through here); the in-guest VM frontend is a separate kernel + out of
    // scope. Linux-only (the whole serving path above is already Linux+`sandbox`-gated).
    #[cfg(target_os = "linux")]
    boatramp_server::sandbox::set_process_undumpable().map_err(|e| PrivsepError::InstanceServe {
        label: label.to_string(),
        reason: format!(
            "marking the instance non-dumpable (HIGH-1 cross-instance /proc/<pid>/mem disclosure): {e}"
        ),
    })?;

    crate::init_tracing();
    // Scrub any inherited live credential from this instance's own environ (inv10). The
    // root already spawns children with an explicitly-minimal scrubbed env, so for a
    // root-spawned child this is a no-op; it backstops the explicit `boatramp __instance`
    // entry, which inherits the full parent environ. (The dumpable flip above already walled
    // `/proc/<pid>/environ` off from a sibling before this runs.)
    scrub_own_environ();

    let config = ServerConfig::load(config_path, None).map_err(PrivsepError::from)?;

    // Step 1 (design §2.1): resolve THIS instance's slice — refuse a non-privsep node
    // (F10) or an unknown label. The instance sees only its own slice; the whole topology
    // stays with the root.
    let inst = resolve_instance_slice(&config, label)?;

    // Step 4 (design §2.1): the materialization-by-construction gate. The full boot path
    // consults it before constructing each authority object.
    let gate = MaterializationGate::new(&inst.capabilities);
    let held: Vec<&str> = gate.held().map(HostAuthority::tag).collect();
    let dropped: Vec<&str> = gate.dropped().iter().map(|a| a.tag()).collect();
    tracing::info!(
        instance = %label,
        held = ?held,
        dropped = ?dropped,
        sandbox = ?inst.sandbox,
        substrate = inst.substrate.tag(),
        "[privsep] instance: slice resolved; materialization gate built (dropped authorities are \
         never constructed)"
    );

    let fail = |reason: String| PrivsepError::InstanceServe {
        label: label.to_string(),
        reason,
    };

    // Phase-3 Container substrate (design-note Option C): if the operator selected
    // `substrate: container` for this instance, CONFIRM — fail-closed, and BEFORE the Landlock wall
    // goes up so `/proc` is still readable — that the root really unshared our mount/ipc/uts/cgroup
    // namespaces in our `pre_exec`. A Container instance that finds itself still in its parent's
    // namespaces (a spawn-dispatch regression that skipped the `unshare`) refuses to serve rather
    // than run unconfined — the "no silent downgrade" invariant, now self-checked by the confined
    // process itself (not merely asserted by the spawner). The namespace/cgroup wall is ADDITIVE: the
    // per-capability seccomp/Landlock profile below is still THE filesystem/syscall wall.
    #[cfg(target_os = "linux")]
    if matches!(inst.substrate, InstanceSubstrate::Container) {
        verify_container_namespaces_unshared(label).map_err(|reason| {
            PrivsepError::InstanceServe {
                label: label.to_string(),
                reason,
            }
        })?;
        tracing::info!(
            instance = %label,
            "[privsep] instance: container substrate CONFIRMED — mount/ipc/uts/cgroup namespaces \
             unshared from the root supervisor (the namespace/cgroup wall is up UNDER the \
             per-capability Landlock FS wall; net namespace deliberately shared for backend egress)"
        );
    }

    // Step 3 (design §2.1): install the per-capability seccomp/Landlock profile BEFORE the
    // runtime, fail-closed `Enforced` fleetwide. Done on THIS single main thread so every Tokio
    // worker thread later inherits the domain via `clone`. The SAME install the VM guest frontend
    // runs ([`run_vm_guest`]), extracted so the two cannot drift (the load-bearing wall).
    install_privsep_instance_profile(
        &config,
        config_path,
        &inst.capabilities,
        inst.sandbox,
        label,
    )
    .map_err(fail)?;

    // Steps 5-6 (design §2.1): open the instance's links over the inherited socketpair fds, then
    // serve its slice. The materialization gate (above) is the construction wall; the link
    // mediation + the profile are the other two defence-in-depth layers.
    let fds = PrivsepChildFds::from_env().map_err(fail)?;
    instance_serve::run(label, &gate, &fds, &config, config_path).map_err(|e| fail(e).into())
}

/// Install THIS instance's per-capability seccomp/Landlock profile, fail-closed `Enforced` fleetwide
/// (design §2 F6 / inv7) — the load-bearing privsep wall. Extracted from [`run_instance`] so the
/// host-side instance ([`run_instance`]) and the VM-guest frontend ([`run_vm_guest`]) install the
/// EXACT same wall from the EXACT same inputs (the "unify, don't parallelize" discipline). Must run on
/// the single main thread BEFORE any Tokio runtime, so every later worker thread inherits the domain
/// via `clone`. Returns the human reason on any refusal (the caller fails the node closed).
fn install_privsep_instance_profile(
    config: &ServerConfig,
    config_path: &Path,
    capabilities: &[HostAuthority],
    sandbox: boatramp_core::privsep::SandboxPosture,
    label: &str,
) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let data_dir = normalized_data_dir(config, &cwd);
    // Pre-create this instance's OWN state subtrees so the derivation's `fs::canonicalize` resolves
    // them (Contract #1): a holder's grant canonicalizes through any symlink before the Landlock
    // wall (which this instance has not yet installed) goes up. Best-effort — a path that cannot be
    // created stays lexical and is still leak-checked lexically.
    let held_set: BTreeSet<HostAuthority> = capabilities.iter().copied().collect();
    for dir in boatramp_server::sandbox::instance_backend_state_grants(&held_set, &data_dir) {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::debug!(?dir, error = %e, "[privsep] could not pre-create own state dir (will stay lexical)");
        }
    }
    // The per-tenant router (`exec.compute`) re-execs THIS binary to fork per-tenant children, so
    // it needs its own executable Landlock read+EXECUTE-pinned — exactly like the root
    // (`sandbox::root_supervisor_policy`). Resolve it the SAME way the root does
    // (`std::env::current_exe()`) and fail CLOSED on a resolve error (the node refuses to serve);
    // a non-`exec.compute` instance needs no execute grant, so it is not resolved and stays `None`.
    let exec_self = if held_set.contains(&HostAuthority::ExecCompute) {
        Some(std::env::current_exe().map_err(|e| format!("resolving current exe: {e}"))?)
    } else {
        None
    };
    let inputs = privsep_resolve::build_instance_sandbox_inputs(
        config,
        capabilities,
        config_path,
        &cwd,
        exec_self.as_deref(),
    );

    let node_allows_unsandboxed = matches!(
        config
            .serve
            .as_ref()
            .and_then(|s| s.sandbox.as_ref())
            .map(|sb| sb.posture)
            .unwrap_or_default(),
        config::SandboxPosture::Off | config::SandboxPosture::Permissive
    );
    let install_plan =
        boatramp_server::sandbox::privsep_install_plan(sandbox, node_allows_unsandboxed)
            .map_err(|e| e.to_string())?;
    match install_plan {
        boatramp_server::sandbox::PrivsepInstallPlan::InstallEnforced(posture) => {
            let profile = boatramp_server::sandbox::derive_profile(&held_set, posture, &inputs)
                .map_err(|e| e.to_string())?;
            let status = boatramp_server::sandbox::install_derived(&profile);
            // Fail-closed FLEETWIDE: anything less than `Enforced` refuses (design §2 F6 / inv7).
            let status = boatramp_server::sandbox::enforce_privsep_status(status)
                .map_err(|e| e.to_string())?;
            tracing::info!(
                instance = %label,
                ?status,
                seccomp_allow = profile.seccomp_allow.len(),
                ro = profile.policy.read_only_paths.len(),
                rw = profile.policy.read_write_paths.len(),
                "[privsep] instance: per-capability profile installed + ENFORCED (the load-bearing wall)"
            );
        }
        boatramp_server::sandbox::PrivsepInstallPlan::SkipDevOff => {
            tracing::warn!(
                instance = %label,
                "[privsep] instance: sandbox posture Off on a dev node — serving WITHOUT a \
                 per-instance profile (dev-only; refused on a non-dev node)"
            );
        }
    }
    Ok(())
}

/// Finding 2 (acpi=off Security review) — PURE assertion of the two guest-kernel-config PRECONDITIONS
/// the `acpi=off` boot silently depends on. `X86_MPPARSE` MUST be OFF (with `acpi=off` ON the kernel
/// hunts for an MPTABLE the firecracker *binary* backend does not emit, so device IRQs never route —
/// the serial `EIO`s and the virtio-vsock probe fails `-22`), and `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES`
/// MUST be `=y` (with ACPI disabled the virtio-mmio devices are discovered off the `virtio_mmio.device=`
/// cmdline). A violation ⇒ `Err` so the caller refuses fail-closed. Split out (no `cfg`) so it is
/// unit-tested without a running kernel. Linux-only (the guest runs on Linux; the parser is dead on a
/// non-Linux build). See [`crate::privsep_vm`]'s `boot_firecracker` for the trace.
#[cfg(target_os = "linux")]
fn check_kernel_config_preconditions(config: &str) -> Result<(), String> {
    if config.lines().any(|l| l.trim() == "CONFIG_X86_MPPARSE=y") {
        return Err(
            "the guest kernel has CONFIG_X86_MPPARSE=y — with `acpi=off` the kernel hunts for an \
             MPTABLE the firecracker binary backend does not emit, so NO device IRQ is routed (the \
             8250 serial TX `EIO`s and the virtio-vsock `request_irq` fails -22, killing the \
             transport). It MUST be OFF. Refusing to serve fail-closed (config drift)"
                .to_string(),
        );
    }
    if !config
        .lines()
        .any(|l| l.trim() == "CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y")
    {
        return Err(
            "the guest kernel is missing CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y — with ACPI disabled \
             (`acpi=off`) the virtio-mmio devices (the vsock transport included) are discovered off \
             the `virtio_mmio.device=` cmdline firecracker appends; without it the vsock device is \
             never found. It MUST be =y. Refusing to serve fail-closed (config drift)"
                .to_string(),
        );
    }
    Ok(())
}

/// Read the RUNNING guest kernel's own config from `/proc/config.gz` (present iff
/// `CONFIG_IKCONFIG_PROC=y`), gunzipped. `None` when absent/unreadable — the guard then cannot assert
/// and WARNs rather than refusing (the positive readiness gate still fails loud on any real
/// degradation). Uses `flate2` (a plain `boatramp` dependency, present in the `fs,sandbox` guest build).
#[cfg(target_os = "linux")]
fn read_proc_config_gz() -> Option<String> {
    use std::io::Read;
    let bytes = std::fs::read("/proc/config.gz").ok()?;
    let mut gz = flate2::read::GzDecoder::new(&bytes[..]);
    let mut out = String::new();
    gz.read_to_string(&mut out).ok()?;
    Some(out)
}

/// Finding 2 (acpi=off Security review) — the guest's BOOT-TIME kernel-config guard. If the running
/// kernel's config is READABLE (`/proc/config.gz`, i.e. `CONFIG_IKCONFIG_PROC=y`) and VIOLATES a
/// precondition, refuse fail-closed (`Err` ⇒ the guest powers off ⇒ the host trips `FailNodeClosed`,
/// LOUD — never a silent boot degradation). If it is ABSENT/unreadable, WARN prominently and proceed:
/// the guard cannot assert, but the relay's POSITIVE readiness gate (Finding 1) still converts any
/// resulting boot degradation (dead IRQs ⇒ no vsock ⇒ no 200) into a loud `FailNodeClosed`.
#[cfg(target_os = "linux")]
fn guest_kernel_config_guard(label: &str) -> Result<(), String> {
    match read_proc_config_gz() {
        Some(config) => {
            check_kernel_config_preconditions(&config)?;
            tracing::info!(
                instance = %label,
                "[privsep] VM guest: kernel-config preconditions OK (X86_MPPARSE off + \
                 VIRTIO_MMIO_CMDLINE_DEVICES=y — the acpi=off boot's device-IRQ routing holds)"
            );
            Ok(())
        }
        None => {
            tracing::warn!(
                instance = %label,
                "[privsep] VM guest: /proc/config.gz is absent (CONFIG_IKCONFIG_PROC off) — CANNOT \
                 assert the X86_MPPARSE-off + VIRTIO_MMIO_CMDLINE_DEVICES=y preconditions at boot. \
                 Relying on the relay's positive readiness gate to fail LOUD if the acpi=off IRQ \
                 routing is broken. Enable CONFIG_IKCONFIG_PROC in the guest kernel to assert here."
            );
            Ok(())
        }
    }
}

/// The scoped privsep VM substrate's IN-GUEST frontend entry (`boatramp __vm-guest`): the static-PIE
/// `boatramp` the non-PIE init shim `execve`d as the microVM guest's PID 1 (own-binary-as-init, O3b).
/// It serves a **static-parser frontend** slice behind the hypervisor wall, carrying ZERO key material
/// (the scoped first cut — `crates/boatramp/DESIGN-privsep-phase3-vm.md`). Flow (the host-model split,
/// self-contained in the guest):
/// 1. read its non-secret descriptor (label + vsock port) from the packed `/privsep-vm-guest.json`;
/// 2. resolve its slice from the packed real config — the SAME [`resolve_instance_slice`] a host-side
///    instance uses — and build the materialization gate;
/// 3. **bind + listen AF_VSOCK BEFORE the wall** (the per-capability profile denies `bind`; the host
///    model has the root bind — inside the guest there is no root, so the guest binds pre-wall and only
///    `accept`s after, self-contained);
/// 4. install its fail-closed `Enforced` profile (S4 — the SAME [`install_privsep_instance_profile`]
///    wall; the guest kernel MUST clear the `MIN_LANDLOCK_ABI` floor or this refuses);
/// 5. serve relayed client connections over vsock with the real HTTP stack (never returns — as PID 1 a
///    fatal error powers the guest off so the host trips `FailNodeClosed`).
#[cfg(target_os = "linux")]
pub fn run_vm_guest() -> Result<(), CliError> {
    crate::init_tracing();
    scrub_own_environ();
    if !cfg!(all(target_os = "linux", feature = "sandbox")) {
        return Err(PrivsepError::UnsupportedPlatform.into());
    }
    let descriptor = crate::privsep_vm::read_guest_descriptor().map_err(|reason| {
        PrivsepError::InstanceServe {
            label: "<vm-guest>".to_string(),
            reason,
        }
    })?;
    let label = descriptor.label;
    let fail = |reason: String| PrivsepError::InstanceServe {
        label: label.clone(),
        reason,
    };

    let config = ServerConfig::load(Path::new(crate::privsep_vm::GUEST_CONFIG_PATH), None)
        .map_err(PrivsepError::from)?;
    let inst = resolve_instance_slice(&config, &label)?;
    // Scope guard (defense in depth behind the root's pre-spawn lint): the guest frontend must be a
    // key-free static-parser frontend (the lint's P3). A guest shipped outside scope refuses rather
    // than serve.
    if !crate::privsep_vm::is_scoped_static_parser_frontend(&inst.capabilities) {
        return Err(fail(
            "the scoped VM substrate serves ONLY a key-free static-parser frontend (a group-C \
             listener-only slice); this slice is out of scope — refusing fail-closed"
                .to_string(),
        )
        .into());
    }
    let _gate = MaterializationGate::new(&inst.capabilities);

    // Finding 2 (acpi=off Security review): assert the guest-kernel-config preconditions the `acpi=off`
    // boot silently depends on (X86_MPPARSE off + VIRTIO_MMIO_CMDLINE_DEVICES=y). Readable-and-wrong ⇒
    // refuse fail-closed (guest powers off ⇒ FailNodeClosed); absent ⇒ WARN (the relay's positive
    // readiness gate still fails loud). Done before binding/serving.
    guest_kernel_config_guard(&label).map_err(fail)?;

    // (3) Bind the vsock listener BEFORE the profile (the profile denies `bind`).
    let listener = crate::privsep_vm::vsock_bind_listen(descriptor.vsock_port)
        .map_err(|e| fail(format!("binding the guest vsock listener: {e}")))?;
    tracing::info!(
        instance = %label,
        port = descriptor.vsock_port,
        "[privsep] VM guest: AF_VSOCK bound + listening (pre-wall); installing the Enforced profile next"
    );

    // (4) Install the fail-closed Enforced profile — the SAME wall a host-side instance installs (S4).
    install_privsep_instance_profile(
        &config,
        Path::new(crate::privsep_vm::GUEST_CONFIG_PATH),
        &inst.capabilities,
        inst.sandbox,
        &label,
    )
    .map_err(fail)?;

    // (5) Serve relayed client connections over vsock, behind the hypervisor + per-capability walls.
    //     Diverges (`!`) — as PID 1 it never returns; it coerces to this fn's `Result` return type.
    crate::privsep_vm::guest_accept_serve_loop(listener, &label)
}

/// The separate least-authority VM client-byte **relay process** entry
/// (`boatramp __vm-relay <label>`) — the owner's S1 placement (2026-11-14): a dedicated process,
/// NOT a widening of the secret-blind root, that accepts each client on the root-bound public TCP
/// listener and splices its bytes to the frontend-in-guest over the firecracker vsock UDS bridge
/// ([`crate::privsep_vm`]). It carries ONLY untrusted client bytes — never key material — so it is
/// itself secret-blind (it scrubs its own environ first). The root→relay contract is
/// [`VmRelayDescriptor`] (over [`PRIVSEP_VM_RELAY_ENV`]) + the inherited pre-bound listener fd (over
/// [`PRIVSEP_FDS_ENV`] / [`PrivsepChildFds`]).
///
/// Flow: read + validate the NON-SECRET contract (the descriptor + the inherited listener fd), then
/// INSTALL the relay's OWN least-authority profile fail-closed [`Enforced`] (no bind/listen/socketpair,
/// no key-lock, `execve`/`fork` hard-killed; FS view = own binary + the ONE vsock UDS —
/// [`boatramp_server::sandbox::derive_relay_profile`]) and, ONLY behind that wall, run the Model-A
/// copy-relay ([`crate::privsep_vm::run_relay`]): accept each client on the root-bound listener and
/// splice OPAQUE bytes both ways to the frontend-in-guest over the vsock UDS. If the profile cannot be
/// installed [`Enforced`] (a build/platform without the Linux seccomp+Landlock wall), it REFUSES to
/// serve — a byte-relay of untrusted client data never runs unprofiled.
///
/// It carries NO authority and NO key material (the secret-blindness invariant + the S2 lint forbid a
/// key-material link crossing here), and scrubs its own environ first (inv10). It is REACHED when an
/// operator selects `substrate: vm` for a scoped key-free static-parser frontend:
/// [`resolve_spawn_backend`] now DISPATCHES that shape (live-proven + Security-reviewed), and the root's
/// supervise loop forks this relay per VM frontend; any other VM shape stays refused fail-closed.
/// The bounded deadline the `__vm-relay` readiness handshake (acpi=off Security review, Finding 1)
/// waits for the frontend-in-guest to serve its first `200` over vsock before the relay accepts any
/// client. Generous — a cold guest boots firecracker, unpacks a ~185 MB initramfs, self-relocates the
/// static-PIE, installs its Enforced profile, and binds vsock before it serves — but FINITE: when it
/// elapses the relay exits and the root trips `FailNodeClosed`, rather than relaying clients to (or
/// waiting forever on) a guest that never positively served.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
const VM_RELAY_READINESS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

pub fn run_vm_relay(label: &str) -> Result<(), CliError> {
    crate::init_tracing();
    // The relay handles untrusted client bytes; scrub any inherited live credential first (inv10).
    scrub_own_environ();
    let fail = |reason: String| PrivsepError::InstanceServe {
        label: label.to_string(),
        reason,
    };
    // Validate the non-secret launch contract the root wired (fail loudly on a broken spawn).
    let descriptor = VmRelayDescriptor::from_env().map_err(fail)?;
    let fds = PrivsepChildFds::from_env().map_err(fail)?;
    let listener_fd = fds.listener.ok_or_else(|| {
        fail(format!(
            "the __vm-relay process needs an inherited pre-bound public listener fd via \
             {PRIVSEP_FDS_ENV}; none was wired"
        ))
    })?;
    tracing::info!(
        instance = %label,
        guest_port = descriptor.guest_port,
        listener_fd,
        "[privsep] __vm-relay: launch contract validated (secret-blind client-byte relay); \
         installing the least-authority profile next, then relaying"
    );

    // The relay splices UNTRUSTED client bytes, so it serves ONLY behind its own Enforced
    // least-authority seccomp/Landlock profile. On a build/platform without the Linux
    // seccomp+Landlock wall the profile cannot install → refuse to serve (fail-closed; never
    // relay a byte unprofiled).
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    let result: Result<(), CliError> =
        run_vm_relay_confined(label, &descriptor, &fds, listener_fd).map_err(|e| fail(e).into());
    #[cfg(not(all(target_os = "linux", feature = "sandbox")))]
    let result: Result<(), CliError> = {
        let _ = (listener_fd, &descriptor);
        Err(fail(
            "the separate-process VM client-byte relay refuses to serve: its Enforced \
             least-authority seccomp/Landlock profile needs Linux + the `sandbox` feature, which \
             this build/platform lacks — a relay of untrusted client bytes never runs unprofiled"
                .to_string(),
        )
        .into())
    };
    result
}

/// Contain the separate relay process, then run the Model-A copy-relay behind the wall (Linux +
/// `sandbox` only). The containment is LAYERED, set up in a fixed order in the pre-serve window:
/// (1) enter a FRESH, EMPTY (loopback-only) network namespace — the PRIMARY IP-egress wall (MED-1),
/// using the CAP_SYS_ADMIN the relay inherits from the root; (2) `pivot_root` into a minimal mount-ns
/// root holding ONLY the own binary + the one vsock-UDS dir, so no host PATHNAME `AF_UNIX` socket path
/// resolves — closing the local-pivot surface the netns cannot (pathname UDS are not netns-scoped, and
/// Landlock does not mediate UDS `connect(2)`) (INFO-1); (3) drop ALL capabilities (empty the bounding
/// set incl. CAP_NET_RAW — INFO); (4) install the relay's OWN least-authority seccomp/Landlock profile
/// fail-closed [`Enforced`] (F1 deny-all-TCP + no bind/listen/socketpair + exec/fork killed). Order is
/// load-bearing: the netns + mount-ns + cap ops need pre-profile state (the profile hard-kills
/// `unshare`/`setns`/`mount`/`pivot_root`), and they need the capability the cap-drop then removes. Any
/// step failing returns `Err` ⇒ the caller fails the node closed (NEVER a relay with a full network /
/// reachable host UDSes / retained caps / no profile).
/// Returns `Err` if the relay loop ever ends — the relay runs for the node's life.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn run_vm_relay_confined(
    label: &str,
    descriptor: &VmRelayDescriptor,
    fds: &PrivsepChildFds,
    listener_fd: i32,
) -> Result<(), String> {
    use std::os::fd::FromRawFd;

    // Nit (a) — foreclose a leaked host DIRECTORY-fd `fchdir`/`openat` escape, STRUCTURALLY. Right after
    // the `__vm-relay` re-exec and BEFORE any namespace/profile step, close EVERY inherited fd except
    // stdio (0/1/2 — tracing) and EXACTLY the fds the root deliberately handed this relay via
    // [`PrivsepChildFds`] (the pre-bound public listener + any link fds — adopted LATER in `run_relay`).
    // CLOEXEC discipline + the re-exec already drop host fds, but this makes "no host dir-fd survives
    // into the relay" a hard `close_range` guarantee rather than a code-analysis assertion: no stray fd
    // can be `fchdir`'d past the minimal mount-ns root below. The kept set is precisely known from the
    // descriptor map, so this preserves it exactly. Fail-closed (never relay a byte with a stray fd open).
    let mut keep_fds: Vec<i32> = fds.links.values().copied().collect();
    if let Some(l) = fds.listener {
        keep_fds.push(l);
    }
    boatramp_server::sandbox::close_inherited_fds_except(&keep_fds).map_err(|e| {
        format!("foreclosing stray inherited fds before the relay confinement (nit a): {e}")
    })?;

    // Contract #1 (WS-C): normalize the own-binary + vsock-UDS paths the Landlock view grants, so the
    // fd-based install grants the REAL paths (a `..`/symlink/relative spelling cannot slip a different
    // path past the lexical policy). The relay holds NO backend authority, so there is no
    // authority-state grant (contract #2 is vacuous) — the view is categorically narrower than any
    // instance's.
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let current_exe = std::env::current_exe().map_err(|e| format!("resolving current exe: {e}"))?;
    let exe_norm = normalize_for_landlock(&current_exe, &cwd);
    let uds_norm = normalize_for_landlock(&descriptor.uds_path, &cwd);

    // MED-1 — PRIMARY egress containment: move the netless relay into a FRESH, EMPTY (loopback-only)
    // network namespace BEFORE the profile install. F1's Landlock `AccessNet` deny-all-TCP wall governs
    // only TCP, so it leaves UDP egress open (the relay's seccomp keeps `socket`/`sendto` for the vsock
    // dial, filtering by name not domain); an empty netns has NO route anywhere, closing UDP + TCP +
    // raw/packet + abstract-UDS egress (and any path to 169.254.169.254) in one move, while the
    // pathname AF_UNIX vsock UDS and the inherited root-netns listener still work (a socket keeps its
    // creation netns). Done HERE, in the pre-profile window, using the CAP_SYS_ADMIN the relay inherits
    // from the privileged root — because the profile hard-KILLS `unshare`/`setns` (KILL_SURFACE) once
    // enforced. Fail-closed: if the netns can't be created/verified-empty, REFUSE (never serve with a
    // full network). The order is: adopt the listener fd (number, already in hand) → unshare netns →
    // drop caps → install the profile → accept()/dial from inside the empty netns.
    boatramp_server::sandbox::enter_empty_netns()
        .map_err(|e| format!("entering the relay's empty network namespace (MED-1): {e}"))?;

    // INFO-1 — PATHNAME-AF_UNIX egress containment, layered OVER the empty netns. The empty netns
    // closes all IP egress + abstract-namespace UDS, but a PATHNAME AF_UNIX socket is NOT netns-scoped,
    // and Landlock's `AccessFs` does not mediate `connect(2)` to a UDS (its dir-grant governs the
    // install's O_PATH opens, not the kernel's `unix_find_other` path walk) — so a compromised relay
    // could still `connect()` a host UDS (`/run/docker.sock`, a dbus/systemd/postgres socket, …) for a
    // local pivot. Enter a private mount namespace + `pivot_root` into a minimal root holding ONLY the
    // own binary (execute-pin) + the one vsock-UDS dir, so no host UDS path resolves. Done HERE, in the
    // pre-profile window (the profile hard-kills `unshare`/`mount`/`pivot_root`), using the CAP_SYS_ADMIN
    // the relay still holds. Fail-closed: if the minimal root can't be built, REFUSE (never serve on the
    // full host mount tree). The vsock dir is the uds's parent — the SAME dir the Landlock view grants.
    let uds_dir = uds_norm
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| uds_norm.clone());
    boatramp_server::sandbox::enter_minimal_mount_ns(&exe_norm, &uds_dir)
        .map_err(|e| format!("building the relay's minimal mount-ns root (INFO-1): {e}"))?;

    // INFO — explicit capability floor, in two steps (AFTER the unshare, which needs CAP_SYS_ADMIN;
    // BEFORE the profile install, so `capset` is not yet seccomp-filtered). Fail-closed on each.
    // (1) prctl securebits (SECBIT_NOROOT) + EMPTY the bounding set (incl. CAP_NET_RAW) + clear ambient
    //     — the SAME sequence every privsep instance's pre_exec performs (one path). This gates cap
    //     RE-acquisition; it needs CAP_SETPCAP, still held here.
    boatramp_server::sandbox::drop_all_capabilities().map_err(|e| {
        format!("dropping the __vm-relay bounding/securebits capabilities (INFO): {e}")
    })?;
    // (2) capset: clear the EFFECTIVE/PERMITTED/INHERITABLE sets IN-PROCESS. An INSTANCE drops its
    //     effective caps via the execve that follows its pre_exec; the relay NEVER execs, so without
    //     this it would serve with its full inherited root caps (CAP_SYS_ADMIN/CAP_NET_RAW). After this
    //     the relay holds ZERO capabilities — the transient CAP_SYS_ADMIN used for the netns unshare is
    //     gone before any client byte is relayed, and no raw/packet socket can be opened.
    boatramp_server::sandbox::clear_current_capabilities()
        .map_err(|e| format!("clearing the __vm-relay effective capabilities (INFO): {e}"))?;

    // HIGH-1 (final privsep Security re-review) — mark the relay NON-dumpable, right AFTER the capability
    // drop and BEFORE the profile install (prctl is not yet seccomp-filtered). The `__vm-relay` runs on
    // the HOST, a same-node-uid process in the SHARED host pid namespace (only the in-guest frontend is on
    // a separate kernel), so a compromised sibling could otherwise `openat`+`pread64` its `/proc/<pid>/mem`
    // the same way it would an instance's; dumpable=0 makes its `/proc/<pid>/*` root-owned ⇒ the capless
    // sibling gets `EPERM` regardless of `yama.ptrace_scope`. Unlike an instance the relay does NOT execve
    // after this point, so there is no reset concern (this call is already post-exec either way). The
    // relay is secret-blind, but it is still a host process and this is the SAME wall every instance gets
    // (one path — `set_process_undumpable`). Load-bearing for HIGH-1 ⇒ fail-closed.
    boatramp_server::sandbox::set_process_undumpable()
        .map_err(|e| format!("marking the __vm-relay non-dumpable (HIGH-1): {e}"))?;

    // Derive + install the relay's bespoke least-authority profile, fail-closed Enforced (the SAME
    // install_derived + enforce_privsep_status machinery the root + every instance uses — one install
    // path, not a second). It is strictly narrower than any instance: no bind/listen/socketpair, no
    // key-lock, execve/execveat + fork/vfork hard-killed; the FS view is the own binary (read+execute)
    // + the ONE vsock UDS. Anything less than Enforced REFUSES (never relay a byte unprofiled).
    let profile = boatramp_server::sandbox::derive_relay_profile(&exe_norm, &uds_norm);
    let status = boatramp_server::sandbox::enforce_privsep_status(
        boatramp_server::sandbox::install_derived(&profile),
    )
    .map_err(|e| format!("installing the __vm-relay least-authority profile: {e}"))?;
    tracing::info!(
        instance = %label,
        ?status,
        seccomp_allow = profile.seccomp_allow.len(),
        seccomp_kill = profile.seccomp_kill.len(),
        ro = profile.policy.read_only_paths.len(),
        "[privsep] __vm-relay: least-authority profile installed + ENFORCED (no \
         bind/listen/socketpair, no key-lock, exec+fork hard-killed; FS view = own binary + the one \
         vsock UDS) — layered OVER the empty-netns IP-egress wall (MED-1) + the minimal mount-ns root \
         (INFO-1) + the dropped capability floor (INFO): UDP/TCP/raw/abstract-UDS egress all closed, \
         no host pathname-UDS path resolves, only the vsock UDS + the inherited listener remain"
    );

    // Adopt the inherited pre-bound public TCP listener (the root bound it + dup2'd it onto this fd —
    // the relay's profile denies `bind`, so the listener MUST arrive pre-bound).
    // SAFETY: `listener_fd` is the fd the root dup'd into this child + named in the fd map; the relay
    // owns it exclusively.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(listener_fd) };
    // Defensive: the relay serves clients with the BLOCKING std `run_relay` (accept + `io::copy`), NOT a
    // tokio reactor, so the inherited public listener MUST be blocking — force it (verified live:
    // `fcntl(F_GETFL)` had no `O_NONBLOCK`, so this is a guard against a future non-blocking source, not
    // a fix for a present one).
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("forcing the inherited public listener blocking: {e}"))?;

    // Finding 1 (acpi=off Security review) — POSITIVE readiness gate, BEHIND the profile + BEFORE the
    // first client. Assert the frontend-in-guest actually SERVES over vsock within a bounded deadline —
    // a LIVENESS check: any valid HTTP response proves the guest is serving (INFO-3; NOT specifically a
    // 200, so a frontend answering `/` non-200 is not false-closed). The UDS merely existing —
    // `boot_firecracker`'s device-up wait — is NOT proof the guest is healthy. Done from the relay (NOT
    // the root), which already holds the `connect`/`read`/`write` socket verbs this needs; the root never
    // crosses the vsock. On timeout this returns `Err` ⇒ the relay exits ⇒ the root's supervise loop
    // trips `FailNodeClosed` — a degraded/non-serving guest is never silently served. The probe
    // connection is just another `Connection: close` client.
    let readiness_deadline = std::time::Instant::now() + VM_RELAY_READINESS_DEADLINE;
    crate::privsep_vm::relay_readiness_probe(&uds_norm, descriptor.guest_port, readiness_deadline)?;
    tracing::info!(
        instance = %label,
        "[privsep] __vm-relay: readiness gate PASSED — the frontend-in-guest returned a valid HTTP \
         response over vsock (liveness proven, any status); now accepting + relaying clients (PRIVSEP \
         VM RELAY READY)"
    );

    // Run the Model-A copy-relay behind the wall: accept each client, dial the frontend-in-guest over
    // the vsock UDS, and splice OPAQUE bytes both ways — NO parse, and NEVER key material (the scoped
    // frontend holds no key; the secret-blindness invariant + the S2 lint forbid a key-material link
    // here, so every byte is treated as opaque). The ONE existing PrivsepChildFds fd-pass carried the
    // listener — no new mechanism. It runs for the node's life; when `accept` ends (the listener
    // closed), it returns and we signal FailNodeClosed.
    crate::privsep_vm::run_relay(label.to_string(), listener, uds_norm, descriptor.guest_port);
    Err(
        "the __vm-relay client-byte relay loop ended — the pre-bound public listener closed; \
         FailNodeClosed (tearing the relay down rather than serving with a dead listener)"
            .to_string(),
    )
}

// =============================================================================
// The root→instance fd-pass contract (WS-C): which inherited fd is which link / listener
// =============================================================================

/// The env var the root sets on each spawned `__instance` to say which inherited fd NUMBER carries
/// which feature-link and (for a `listen.*` instance) its pre-bound listener. The values are fd
/// numbers, NOT secrets — the local-link authority is the root-wired fd TOPOLOGY itself (design
/// §3.3), not any token in the environment — so this var is non-secret and passes the spawn-env
/// allowlist (`BOATRAMP_*`).
pub const PRIVSEP_FDS_ENV: &str = "BOATRAMP_PRIVSEP_FDS";

/// The env var the root sets on each `substrate: container` instance carrying the root's OWN
/// namespace identities (the `;`-joined `/proc/self/ns/{mnt,ipc,uts,cgroup}` magic-symlink targets —
/// see [`read_own_ns_baseline`]). The instance reads its OWN `/proc/self/ns` (no ptrace needed, so it
/// works after the Finding-2 capability drop) and fail-closes unless each DIFFERS from this baseline,
/// confirming it entered fresh namespaces. NON-SECRET (inode identities only), so it passes the
/// `BOATRAMP_*` spawn-env allowlist. Absent for every non-container instance.
pub const PRIVSEP_CONTAINER_NS_ENV: &str = "BOATRAMP_PRIVSEP_CONTAINER_NS";

/// The env var the root sets on a crown-jewel (`secrets.sealer` / `token.signer`) instance naming the
/// feature-links on which it should serve the WS-E **authority-API grammar** (seal/unseal/mint_token)
/// to a relayed end principal. The value is a JSON array of link names — NON-SECRET (names only, like
/// the fd map + the unseal allowlist), so it passes the `BOATRAMP_*` spawn-env allowlist. An absent var
/// ⇒ no authority-serve links ⇒ the crown jewel holds its grammar inert (parks), exactly as before this
/// wave. The root derives the set with [`compute_authority_serve_links`] (secret-blind — names only).
pub const PRIVSEP_AUTHORITY_LINKS_ENV: &str = "BOATRAMP_PRIVSEP_AUTHORITY_LINKS";

/// Parse the WS-E authority-serve link set from the process environment (an absent var ⇒ empty, so a
/// crown jewel serves no grammar unless the root designated links — the pre-this-wave behavior).
fn authority_serve_links_from_env() -> Result<BTreeSet<String>, String> {
    match std::env::var(PRIVSEP_AUTHORITY_LINKS_ENV) {
        Ok(v) => serde_json::from_str(&v)
            .map_err(|e| format!("parsing {PRIVSEP_AUTHORITY_LINKS_ENV}: {e}")),
        Err(std::env::VarError::NotPresent) => Ok(BTreeSet::new()),
        Err(e) => Err(format!("reading {PRIVSEP_AUTHORITY_LINKS_ENV}: {e}")),
    }
}

/// The fd map the root hands ONE instance (serialized into [`PRIVSEP_FDS_ENV`]): each feature-link
/// name → the inherited fd number of this instance's socketpair end, plus the optional pre-bound
/// listener fd. The root `dup2`s each end / listener onto these fixed numbers in the child's
/// `pre_exec` (clearing `CLOEXEC` so they survive the exec); the instance reconstructs its
/// endpoints from them. An absent var ⇒ an empty map (an instance the root wired no fds to).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivsepChildFds {
    /// link name → inherited fd number (this instance's socketpair end).
    pub links: BTreeMap<String, i32>,
    /// The pre-bound listener fd number (a `listen.*` instance only).
    pub listener: Option<i32>,
}

impl PrivsepChildFds {
    /// Serialize for the [`PRIVSEP_FDS_ENV`] value.
    pub fn to_env_value(&self) -> String {
        serde_json::to_string(self).expect("the fd map is always serializable")
    }

    /// Parse the fd map from the process environment (an absent var ⇒ an empty map).
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(PRIVSEP_FDS_ENV) {
            Ok(v) => {
                serde_json::from_str(&v).map_err(|e| format!("parsing {PRIVSEP_FDS_ENV}: {e}"))
            }
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(e) => Err(format!("reading {PRIVSEP_FDS_ENV}: {e}")),
        }
    }
}

/// The public listener address an instance binds, from its capability set + the resolved config
/// (design §4.1: the root binds the privileged listener + passes the fd, so the frontend's profile
/// can deny `bind`). Phase 1 wires the PUBLIC listener (`serve.addr`) for a
/// `listen.public-tls`/`listen.http-parse` holder; the other `listen.*` fd binds (mail / overlay /
/// s3ingress / inbound-tcp / gateway) are a documented follow-on. Pure (host-testable).
fn instance_listener_addr(
    caps: &[HostAuthority],
    config: &ServerConfig,
) -> Option<std::net::SocketAddr> {
    let binds_public = caps.iter().any(|a| {
        matches!(
            a,
            HostAuthority::ListenPublicTls | HostAuthority::ListenHttpParse
        )
    });
    if !binds_public {
        return None;
    }
    config.serve.as_ref().and_then(|s| s.addr)
}

// =============================================================================
// S1: the separate least-authority VM client-byte relay process (`__vm-relay`)
// =============================================================================
//
// The scoped VM substrate (`crate::privsep_vm`) needs a HOST-side client-byte relay: the root binds
// the privileged public TCP listener, and some host process accepts each client and splices its
// bytes to the frontend-in-guest over firecracker's vsock UDS bridge (design §1c, Model A). That
// relay needs `accept4`/`connect`/`read`/`write` — which the secret-blind root's networkless
// TCB-floor self-profile (`sandbox::derive_root_profile` → `ROOT_NET_STRIP`) forbids. The owner
// RESOLVED the placement (S1, 2026-11-14): a SEPARATE least-authority relay process — do NOT widen
// the secret-blind root (a relay bug, parsing untrusted client bytes, stays OUT of the root's TCB
// floor). The relay carries ONLY untrusted client bytes — NEVER key material (a scoped
// static-parser frontend holds no key; `check_vm_secret_blindness_closure` refuses any other VM
// shape before spawn), so the relay is itself secret-blind.
//
// This is the ROOT→relay BOUNDARY CONTRACT (the S1 analog of `InstanceSpawnSpec` for WS-B): the
// fully-formed, host-tested command + environment the root hands the OS for the relay. It is now
// WIRED into the operator supervise dispatch (`supervise::run` → `per_tenant::spawn_vm_relay`): the
// root binds the listener, boots the microVM guest, builds this spec, `fork`+`exec`s the relay, and
// supervises both the firecracker child and the relay child (either's death ⇒ `FailNodeClosed`). The
// relay installs its OWN least-authority seccomp/Landlock profile + enters its egress-contained
// netns/mount-ns BEFORE touching a client byte (`run_vm_relay_confined`), and does a POSITIVE
// readiness handshake to the guest before accepting clients (Finding 1). `substrate: Vm` dispatches
// for the scoped shape ONLY (`resolve_spawn_backend`); any other VM shape is still refused fail-closed
// by the `plan_root` scope lint + the spawn gate.

/// The internal `argv[1]` token that engages the separate VM client-byte relay process. Mirrors the
/// `__root`/`__instance`/`__vm-guest` precedent: an EXACT `argv[1]` match, kept OUT of the clap
/// `Command` enum entirely (internal, never user-facing / completion / `--help`).
pub const VM_RELAY_SUBCOMMAND: &str = "__vm-relay";

/// The env var the root sets on a spawned `__vm-relay` process carrying its NON-SECRET launch
/// descriptor ([`VmRelayDescriptor`] — the frontend label, the firecracker host-side vsock UDS path
/// to dial, and the guest vsock port). Names/paths/a port only — NEVER a secret (the relay is
/// secret-blind: it only splices untrusted client bytes), so it passes the `BOATRAMP_*` spawn-env
/// allowlist exactly like [`PRIVSEP_FDS_ENV`] / [`PRIVSEP_AUTHORITY_LINKS_ENV`]. The pre-bound
/// public TCP listener fd rides the SAME [`PRIVSEP_FDS_ENV`] / [`PrivsepChildFds`] mechanism every
/// instance's listener uses (the root `dup2`s it onto the fixed `listener` fd number) — ONE
/// fd-passing path, not a parallel one.
pub const PRIVSEP_VM_RELAY_ENV: &str = "BOATRAMP_PRIVSEP_VM_RELAY";

/// The non-secret launch descriptor the root hands a `__vm-relay` process (serialized into
/// [`PRIVSEP_VM_RELAY_ENV`]). It carries ONLY names/paths/a port: the relay holds NO
/// [`HostAuthority`] and NO key — its entire authority is the inherited pre-bound listener fd plus
/// the ability to dial the one firecracker vsock UDS named here. The relay accepts each client on
/// the listener and splices its bytes to the guest over a fresh vsock connection to
/// `uds_path` : `guest_port` ([`crate::privsep_vm`]'s `run_relay` is the byte-pipe it runs, once
/// wired behind its own profile).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRelayDescriptor {
    /// The frontend instance label this relay serves (for logging + the `FailNodeClosed` signal).
    pub label: String,
    /// The firecracker host-side vsock UDS the relay dials — the ONLY path into the guest (S1).
    pub uds_path: PathBuf,
    /// The guest vsock port the relay dials over that UDS.
    pub guest_port: u32,
}

impl VmRelayDescriptor {
    /// Serialize for the [`PRIVSEP_VM_RELAY_ENV`] value.
    pub fn to_env_value(&self) -> String {
        serde_json::to_string(self).expect("the VM relay descriptor is always serializable")
    }

    /// Parse from a raw [`PRIVSEP_VM_RELAY_ENV`] value (split out so the contract is unit-testable
    /// without mutating the process environment).
    pub fn from_env_value(value: &str) -> Result<Self, String> {
        serde_json::from_str(value).map_err(|e| format!("parsing {PRIVSEP_VM_RELAY_ENV}: {e}"))
    }

    /// Read + parse the descriptor from the process environment (the relay process's entry reads
    /// this). An ABSENT var is an error — a `__vm-relay` process with no descriptor is a broken
    /// spawn, refused loudly rather than defaulting.
    pub fn from_env() -> Result<Self, String> {
        let value = std::env::var(PRIVSEP_VM_RELAY_ENV)
            .map_err(|e| format!("reading {PRIVSEP_VM_RELAY_ENV}: {e}"))?;
        Self::from_env_value(&value)
    }
}

/// The root→`__vm-relay` re-exec spawn spec — the S1 boundary primitive (the analog of
/// [`InstanceSpawnSpec`] for the separate relay process). It is the fully-formed, tested command +
/// environment the root hands the OS; the supervise dispatch (`supervise::run` →
/// [`per_tenant::spawn_vm_relay`](self)) now builds + spawns it.
///
/// `#[allow(dead_code)]` is kept for the NON-unix build, where the `supervise`/`per_tenant` modules
/// are `#[cfg(unix)]`-gated out and the only remaining reference is the (test-only) unit test — the
/// spec is fully wired on the live unix/Linux path.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRelaySpawnSpec {
    /// The frontend instance label this relay serves.
    pub label: String,
    /// The re-exec argv TAIL (after `argv[0]`): `["__vm-relay", "<label>"]` (mirrors `__instance`).
    pub argv: Vec<String>,
    /// The EXPLICITLY MINIMAL, secret-scrubbed environment (the relay is secret-blind — it splices
    /// untrusted client bytes and MUST carry no credential), PLUS the non-secret
    /// [`PRIVSEP_VM_RELAY_ENV`] descriptor and the [`PRIVSEP_FDS_ENV`] listener-fd map. The root
    /// spawns with `env_clear().envs(this)`, so nothing else is inherited.
    pub env: BTreeMap<String, String>,
}

impl VmRelaySpawnSpec {
    /// Build the ready-to-spawn re-exec [`std::process::Command`]: `env_clear` + the minimal
    /// scrubbed env + the `__vm-relay` argv tail. Called by [`per_tenant::spawn_vm_relay`](self) on the
    /// unix supervise path; `#[allow(dead_code)]` is kept for the non-unix build (supervise cfg'd out).
    #[allow(dead_code)]
    pub fn to_command(&self, current_exe: &Path) -> std::process::Command {
        let mut cmd = std::process::Command::new(current_exe);
        cmd.args(&self.argv).env_clear().envs(&self.env);
        cmd
    }
}

/// Build the root→`__vm-relay` spawn spec for ONE scoped static-parser-frontend VM (S1). PURE +
/// host-testable, so the whole boundary — what crosses to the relay, what is scrubbed, which fd
/// carries the listener — is unit-tested before any live wiring.
///
/// The relay holds NO [`HostAuthority`] (it is a dumb byte pipe), so its environment is
/// `build_instance_env(parent, &[], declared_secret_env)` — the SAME minimal, secret-scrubbed env
/// every capability-less instance gets (so a `_TOKEN`/`_SECRET`/… or config-declared BYO
/// credential var is scrubbed, Finding-1 parity) — plus ONLY the two non-secret wiring vars: the
/// [`PRIVSEP_VM_RELAY_ENV`] descriptor and the [`PRIVSEP_FDS_ENV`] map carrying the pre-bound
/// public TCP listener on `listener_fd` (`links` empty — the relay has no feature-links). Pure
/// (host-testable). `parent_env` is the root's environment; `declared_secret_env` the config-driven
/// secret-env set from [`privsep_resolve::declared_secret_env_var_names`]. Called by the unix
/// supervise dispatch; `#[allow(dead_code)]` is kept for the non-unix build (supervise cfg'd out).
#[allow(dead_code)]
pub fn plan_vm_relay_spec<I>(
    label: &str,
    descriptor: &VmRelayDescriptor,
    listener_fd: i32,
    parent_env: I,
    declared_secret_env: &BTreeSet<String>,
) -> VmRelaySpawnSpec
where
    I: IntoIterator<Item = (String, String)>,
{
    // The relay bears no capability — the minimal capability-less scrub, no secret couriered.
    let mut env = privsep_resolve::build_instance_env(parent_env, &[], declared_secret_env);
    env.insert(PRIVSEP_VM_RELAY_ENV.to_string(), descriptor.to_env_value());
    // The pre-bound public TCP listener rides the one fd-pass mechanism (links empty).
    let fds = PrivsepChildFds {
        links: BTreeMap::new(),
        listener: Some(listener_fd),
    };
    env.insert(PRIVSEP_FDS_ENV.to_string(), fds.to_env_value());
    VmRelaySpawnSpec {
        label: label.to_string(),
        argv: vec![VM_RELAY_SUBCOMMAND.to_string(), label.to_string()],
        env,
    }
}

/// The per-instance SPAWN-BACKEND dispatch for the operator-selectable isolation SUBSTRATE (design §7
/// generalizing seam — "substrate is a spawn backend"). The root calls this for EACH instance BEFORE
/// wiring any links / binding any listener, so a composition that selects an unwired substrate is
/// refused fail-closed before anything is allocated — never spawned part-way, never silently
/// downgraded to an OS process (which would discard the operator's chosen isolation wall).
///
/// **Phase-3 scope.** [`InstanceSubstrate::OsProcess`] is the Phase-1 WIRED backend (the root's
/// `fork`+`exec` over the `local` socketpair, below). [`InstanceSubstrate::Container`] is WIRED too, on
/// the SIMPLE model (design-note Option C, owner-approved): the SAME `fork`+`exec`, with the child
/// additionally unsharing the mount/ipc/uts/cgroup namespaces in its `pre_exec` (no `pivot_root`, no
/// new net/pid/user namespace — the per-capability Landlock profile stays the FS wall, and a
/// `backend.*` instance keeps host-net egress; pid-ns isolation is a deferred increment).
/// [`InstanceSubstrate::Vm`] is NOW WIRED for the owner-greenlit SCOPED first cut — a key-free
/// **static-parser frontend** (a group-C `listen.*`-only slice — the lint's P3;
/// [`crate::privsep_vm::is_scoped_static_parser_frontend`]). A VM has its OWN kernel, so the `local`
/// socketpair cannot cross (unlike Container on one shared kernel — design-note §2a); instead the root
/// binds the privileged listener, boots the microVM guest ([`crate::privsep_vm::boot_frontend_vm`],
/// WITHOUT any in-root relay thread), then `fork`+`exec`s a SEPARATE least-authority relay process
/// (`__vm-relay`) that splices the client's bytes to the frontend-in-guest over the vsock bridge
/// (design §1c Model A), and supervises BOTH the firecracker child and the relay child (either's death
/// ⇒ `FailNodeClosed`). The relay runs the byte-relay — NOT the secret-blind root — because the host
/// client-byte relay needs `accept4`/`connect`/`read`/`write`, which the root's networkless TCB-floor
/// self-profile (`derive_root_profile` — `ROOT_NET_STRIP`) forbids; a relay bug parsing untrusted
/// client bytes stays OUT of the root's TCB floor (S1, owner-resolved 2026-11-14). The relay, not the
/// root, is the host-side vsock endpoint; the root carries no key bytes (a scoped frontend holds no
/// key, enforced by the lint before spawn).
///
/// **SCOPED-WIRED GATE (this cut).** That entire dispatch — [`supervise::run`]'s VM branch +
/// [`per_tenant::spawn_vm_relay`] + the relay-side positive readiness gate ([`run_vm_relay_confined`] →
/// [`crate::privsep_vm::relay_readiness_probe`]) — is BUILT + wired and **LIVE-PROVEN end-to-end on
/// lighthouse**: on a `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y` guest kernel the operator path serves over
/// the SEPARATE confined `__vm-relay` (the readiness gate passes), and killing EITHER the relay child OR
/// the firecracker child trips `FailNodeClosed` (serve + kill-after-serve, the committed
/// `tests/privsep_vm_operator_live.rs`), and the independent Security review returned SHIP. So
/// `is_wired(Vm)` is `true` and this arm DISPATCHES `substrate: vm` for the scoped shape (a key-free
/// static-parser frontend). It still refuses fail-closed for:
/// - Any OTHER VM shape — a co-located sealer bundle (P1, which needs the owner-GATED vsock key-relay,
///   design §3 / S2), a backend, an exec/control instance — outside the approved scope entirely. (The
///   `plan_root` scope lint already refuses these; this is the defence-in-depth spawn-gate companion.)
///
/// Pure (host-testable).
fn resolve_spawn_backend(
    label: &str,
    substrate: InstanceSubstrate,
    capabilities: &[HostAuthority],
) -> Result<(), PrivsepError> {
    // The VM substrate is handled FIRST — its acceptable SCOPE is capability-dependent, so it cannot
    // ride the capability-free `is_wired` shortcut. The operator supervise-dispatch (boot the microVM +
    // fork+supervise a separate least-authority `__vm-relay`, with the relay-side positive readiness
    // gate) is BUILT + wired + LIVE-PROVEN end-to-end on lighthouse (serve + kill→FailNodeClosed), and
    // the independent Security review returned SHIP — so `substrate: vm` now DISPATCHES here for the
    // owner-greenlit scoped shape (a key-free static-parser frontend). Any OTHER VM shape — a co-located
    // sealer bundle / backend / exec/control instance — is outside the approved scope and STILL refused
    // fail-closed (defence-in-depth behind `plan_root`'s `check_vm_secret_blindness_closure` scope lint).
    if matches!(substrate, InstanceSubstrate::Vm) {
        if crate::privsep_vm::is_scoped_static_parser_frontend(capabilities) {
            // The owner-greenlit scoped shape — DISPATCH (the supervise loop boots the guest + forks the
            // separate `__vm-relay`; the relay's positive readiness gate + both-children supervision are
            // live-proven and Security-reviewed).
            return Ok(());
        }
        return Err(PrivsepError::Supervise(format!(
            "instance {label:?} selects the vm substrate but is NOT a key-free static-parser frontend (a \
             group-C `listen.*`-only slice) — it is outside the approved scope entirely: a co-located \
             sealer bundle / backend / exec/control instance in a VM needs the owner-GATED vsock \
             key-relay (design §3 / S2). Refusing fail-closed rather than silently downgrading to an OS \
             process (which would discard the chosen isolation wall); use `substrate: OsProcess` or \
             `substrate: Container`"
        )));
    }
    if substrate.is_wired() {
        return Ok(());
    }
    let backend = substrate.compute_plane_backend().unwrap_or("(none)");
    Err(PrivsepError::Supervise(format!(
        "instance {label:?} selects the {:?} isolation substrate, whose spawn backend is not wired in \
         this cut (it reuses {backend} — a reported follow-on). Refusing fail-closed rather than \
         silently downgrading to an OS process (which would discard the chosen isolation wall); use \
         `substrate: OsProcess` or `substrate: Container`",
        substrate.tag(),
    )))
}

/// Compute the per-instance unseal ALLOWLIST the root wires onto each `secrets.sealer` instance (the
/// "signer-key unlock" containment): for every feature-link that connects a `secrets.sealer` instance
/// to a DIFFERENT `token.signer` instance, the sealer end of that link may unseal ONLY the configured
/// signer `key_ref` over it. The root alone knows the topology; the result is NON-SECRET (names only)
/// and handed to the sealer via [`boatramp_server::privsep_unseal::PRIVSEP_UNSEAL_ALLOW_ENV`], which
/// enforces it fail-closed. Returns a map `instance label → its allowlist` for every sealer instance
/// that has a separately-linked signer (co-resident signer+sealer resolves in-process, needs none).
///
/// Pure (host-testable): derived entirely from the resolved [`ServerConfig`].
fn compute_unseal_allowlists(
    config: &ServerConfig,
) -> BTreeMap<String, boatramp_server::privsep_unseal::UnsealAllowlist> {
    use boatramp_server::privsep_unseal::UnsealAllowlist;
    let mut out: BTreeMap<String, UnsealAllowlist> = BTreeMap::new();
    let Some(privsep) = config.privsep.as_ref() else {
        return out;
    };
    // Only a SEALED signer source needs the sealer-over-link unlock; AwsKms/ambient/absent need none.
    let Some(key_ref) = privsep_resolve::sealed_signer_key_ref(config) else {
        return out;
    };
    // Derive the sealer↔signer unseal edges from the SINGLE shared predicate in `boatramp-types` that
    // the S2 VM secret-blindness lint (`check_vm_secret_blindness_closure` clause 1) ALSO derives from
    // — so the root's allowlist wiring and the lint's key-link edge set can never drift (a widening of
    // the unseal model mirrors into both at once). The SEALER end of each edge may unseal the signer
    // key ref over that link; the signer end is the asker and gets no allowlist. The
    // `unseal_allowlist_and_s2_lint_share_one_edge_set` test locks this lockstep.
    for edge in privsep.sealer_signer_unseal_edges() {
        out.entry(edge.sealer_instance.to_string())
            .or_default()
            .allow(edge.link.to_string(), key_ref.to_string());
    }
    out
}

/// Deterministically select the SEALER (bootstrap-unseal) feature-link a split `token.signer` instance
/// asks its `secrets.sealer` over (signer-key unlock, [`run_signer_unlock`]). **WS-E residual #5.**
///
/// Phase 1 picked `fds.links.next()` — fine while a split signer had exactly ONE link (to its sealer).
/// But a `token.signer` now also gains WS-E **minting-consumer** links (an `AuthorityServe`-marked
/// frontend→signer authority link), so "the first link" is no longer unambiguously the sealer link —
/// a blind `.next()` could grab a minting-consumer link and send the sealed signer-key request down
/// the wrong peer. This selects the bootstrap-unseal link by its PURPOSE in the resolved on-disk
/// topology (restart-class, never control-plane-derived): the UNIQUE link wired to `label` whose PEER
/// holds [`HostAuthority::SecretsSealer`] and which is NOT purpose-marked
/// [`LinkPurpose::AuthorityServe`]/[`LinkPurpose::Relay`] (those are the minting-consumer / serving-splice
/// shapes, never the sealer-unlock link — and the closure lint already forbids marking a two-crown
/// signer↔sealer link `authority-serve`). It is intersected with the links the root actually wired to
/// this instance ([`PrivsepChildFds::links`]), so a topology link with no handed fd is never selected.
///
/// **Fail-closed, mirroring the WS-D per-tenant supervisor's >1-link refusal** (`run_per_tenant_supervisor`):
/// ZERO candidates ⇒ refuse (a sealed-key signer with no sealer link is a broken composition — the
/// closure lint requires one); MORE THAN ONE ⇒ refuse the ambiguous composition rather than silently
/// pick one via `.next()`. Pure (host-testable).
fn select_sealer_link(
    config: &ServerConfig,
    label: &str,
    wired: &BTreeMap<String, i32>,
) -> Result<(String, i32), String> {
    let Some(privsep) = config.privsep.as_ref() else {
        return Err(
            "a sealed-key signer requires a [privsep] composition to locate its secrets.sealer link"
                .to_string(),
        );
    };
    let holds = |lbl: &str, authority: HostAuthority| -> bool {
        privsep
            .instances
            .get(lbl)
            .is_some_and(|i| i.capabilities.contains(&authority))
    };
    let mut candidates: Vec<(String, i32)> = Vec::new();
    for (link_name, link) in &privsep.links {
        if link.from == link.to {
            continue;
        }
        // A minting-consumer (authority-serve) or serving-splice (relay) link is NEVER the
        // sealer-unlock link — exclude them explicitly so the unlock request can only ride the
        // bootstrap-unseal link.
        if link.is_authority_serve() || link.is_relay() {
            continue;
        }
        let peer = if link.from == label {
            &link.to
        } else if link.to == label {
            &link.from
        } else {
            continue;
        };
        if !holds(peer, HostAuthority::SecretsSealer) {
            continue;
        }
        // Only a link the root actually wired an fd for is usable.
        if let Some(&fd) = wired.get(link_name) {
            candidates.push((link_name.clone(), fd));
        }
    }
    match candidates.len() {
        1 => Ok(candidates.remove(0)),
        0 => Err(format!(
            "a sealed-key signer instance {label:?} has no root-wired feature-link to a \
             secrets.sealer (the composition-closure lint requires one); refusing fail-closed"
        )),
        _ => {
            let mut names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
            names.sort_unstable();
            Err(format!(
                "a sealed-key signer instance {label:?} is wired to {} candidate secrets.sealer \
                 links {names:?}, but it expects EXACTLY one (the bootstrap-unseal link); refusing \
                 the ambiguous composition fail-closed rather than picking one via `.next()`",
                candidates.len(),
            ))
        }
    }
}

/// Compute the per-instance WS-E **authority-serve link** designation the root wires onto each
/// crown-jewel (`secrets.sealer` / `token.signer`) instance: the feature-links on which that instance
/// should serve the seal/unseal/mint_token grammar to a relayed end principal. Secret-blind (link
/// names only), handed in via [`PRIVSEP_AUTHORITY_LINKS_ENV`].
///
/// **The designation rule (Phase-3 foundation — the per-link PURPOSE marker now disambiguates).** A
/// link designates WS-E serve on its crown-jewel endpoint `E` when:
/// - it is EXPLICITLY purpose-marked [`LinkPurpose::AuthorityServe`] AND has exactly one crown-jewel
///   endpoint (the closure lint enforces the exactly-one rule — `AuthorityServeLinkNotSingleCrownJewel`);
///   this fires EVEN when the peer is a listener frontend — the design's primary WS-E case (a listener
///   FRONTEND relaying authority calls to an isolated signer), which is link-shape-identical to a
///   client-fd splice and so could not be auto-inferred; or
/// - it is [`LinkPurpose::Unspecified`] (the default — back-compat) AND falls in the conservative,
///   unambiguous inference: EXACTLY ONE crown-jewel endpoint (a crown↔crown link is bootstrap-unseal,
///   handled by [`compute_unseal_allowlists`], excluded) AND the PEER holds NO `listen.*` authority
///   (a listener-frontend link is a client-fd SPLICE / the marker-requiring authority shape — excluded,
///   fail-safe).
///
/// A [`LinkPurpose::Relay`] link is NEVER designated (an explicit serving splice). The Unspecified
/// listener exclusion is why this never fires for the Phase-1 live-gate compositions (both relay
/// through a listener frontend and mark nothing). Pure (host-testable).
///
/// **WIRING-GATE PRECONDITIONS (tracked).** Designating a link here does NOT make the serve LIVE: the
/// stand-up gate [`check_authority_serve_preconditions`] AND-gates the per-link marker (THIS wave)
/// with a configured PoP/`cnf` verifier (the sibling authority layer's half). Until BOTH hold, a
/// designated composition FAILS THE NODE CLOSED at [`run_authority_serve`] rather than serving a
/// PoP-less grammar. The other hard preconditions in
/// [`boatramp_server::privsep_authority::AuthorityServe`]'s doc (the HIGH-1 per-principal `sub` claim +
/// the seal-granularity owner decision, a real limiter + durable audit sink) also remain.
fn compute_authority_serve_links(config: &ServerConfig) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Some(privsep) = config.privsep.as_ref() else {
        return out;
    };
    let caps = |label: &str| -> &[HostAuthority] {
        privsep
            .instances
            .get(label)
            .map_or(&[][..], |i| i.capabilities.as_slice())
    };
    let any_crown = |label: &str| caps(label).iter().any(|a| a.is_crown_jewel());
    let any_listener = |label: &str| caps(label).iter().any(|a| a.is_listener());
    for (link_name, link) in &privsep.links {
        if link.from == link.to {
            continue;
        }
        // An explicit `relay` marker is a serving splice — never an authority-serve link.
        if link.is_relay() {
            continue;
        }
        let from_cj = any_crown(&link.from);
        let to_cj = any_crown(&link.to);
        // Exactly one crown-jewel endpoint (XOR) — a crown↔crown link is bootstrap, excluded. (The
        // lint refuses a crown↔crown / no-crown link that IS marked `authority-serve`, so a marked
        // link that reaches here always has its single crown endpoint.)
        let (holder, peer) = match (from_cj, to_cj) {
            (true, false) => (&link.from, &link.to),
            (false, true) => (&link.to, &link.from),
            _ => continue,
        };
        // EXPLICIT authority-serve marker: designate the crown endpoint EVEN when the peer is a
        // listener frontend (the shape the inference could not safely disambiguate — design §3.4
        // precondition 4). This is the half that, together with the sibling PoP verifier, lets the
        // stand-up gate open.
        if link.is_authority_serve() {
            out.entry(holder.clone())
                .or_default()
                .insert(link_name.clone());
            continue;
        }
        // UNSPECIFIED (the default) — conservative inference: a listener peer is a frontend whose link
        // is a client-fd SPLICE (or the frontend→signer authority shape that NEEDS the explicit marker
        // above), so it is excluded here (fail-safe, never a collision).
        if any_listener(peer) {
            continue;
        }
        out.entry(holder.clone())
            .or_default()
            .insert(link_name.clone());
    }
    out
}

/// The CODE-FAIL-CLOSED stand-up gate for a LIVE authority serve (Security re-review). Standing up a
/// live seal/unseal/**mint_token** grammar on a relay→crown-jewel link is refused unless BOTH Phase-3
/// wiring-gate preconditions hold:
/// 1. a **PoP / `cnf` verifier is configured** — so a relayed context is possession-bound, closing the
///    ACTIVE-principal new-call forgery that the freshness bound + nonce cache (anti-replay (a)+(b)) do
///    NOT close (`mint_token` has no `sub` dependency, so without this it would serve LIVE and the
///    re-mint chain would be reachable);
/// 2. each authority-serve link is **explicitly purpose-marked** as an authority link in the
///    composition (not inferred).
///
/// NEITHER mechanism is representable in the config / composition model until Phase 3, so this ALWAYS
/// refuses today — making the whole authority API code-inert by code (symmetric with the sealer's
/// per-identity fail-closed), not merely convention-inert. When Phase 3 lands the PoP-verifier config
/// and the per-link PURPOSE marker, the two predicates below start returning `true` for a correctly
/// provisioned composition and the gate opens. Pure (host-testable).
fn check_authority_serve_preconditions(config: &ServerConfig) -> Result<(), String> {
    let mut unmet: Vec<&str> = Vec::new();
    if !pop_cnf_verifier_configured(config) {
        unmet.push("a PoP/cnf verifier must be configured (none exists until Phase 3)");
    }
    if !authority_link_purpose_marked(config) {
        unmet.push(
            "the serve-link must be explicitly purpose-marked as an authority link (no per-link \
             PURPOSE marker exists until Phase 3)",
        );
    }
    if unmet.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unmet wiring-gate preconditions (fail-closed): {}",
            unmet.join("; ")
        ))
    }
}

/// Whether a PoP / `cnf` verifier is configured for the authority API (wiring-gate precondition 1).
///
/// **This is the sibling AUTHORITY-LAYER's half of the AND-gate** (the `privsep_authority` / `cose`
/// PoP/`cnf` verifier, out of this agent's Phase-3 lane). No config surface for one exists yet, so it
/// is structurally `false` and the stand-up gate stays CLOSED even once the per-link PURPOSE marker
/// (below) is present — exactly the required invariant: the marker ALONE must never make the serve go
/// live without PoP. The authority layer flips this when its PoP-verifier config lands.
fn pop_cnf_verifier_configured(_config: &ServerConfig) -> bool {
    false
}

/// Whether the composition explicitly PURPOSE-marks at least one authority-serve link (wiring-gate
/// precondition 2 — design §3.4 precondition 4). **Phase-3 foundation (this lane):** the per-link
/// [`LinkPurpose::AuthorityServe`] marker now EXISTS in the composition model, so this returns `true`
/// for a composition that declares one. It is one half of the AND-gate in
/// [`check_authority_serve_preconditions`]; the PoP/`cnf` half ([`pop_cnf_verifier_configured`], the
/// sibling authority layer's) keeps the live serve closed until it too lands, so a marked-but-PoP-less
/// composition still fails the node closed rather than serving. Pure (host-testable).
fn authority_link_purpose_marked(config: &ServerConfig) -> bool {
    config.privsep.as_ref().is_some_and(|p| {
        p.links
            .values()
            .any(|l| matches!(l.purpose, LinkPurpose::AuthorityServe))
    })
}

// =============================================================================
// WS-C runtime: the root's own fork+exec spawn primitive + the live per-tenant registry
// =============================================================================

/// The root's own fork+exec spawn primitive + the LIVE per-tenant instance registry (design
/// §Phase-4 WS-C). Both are the root supervisor's OWN mechanism — per-tenant spawning stays INSIDE
/// the (secret-blind) router via the root's `fork`+`exec`, NOT a `ComputeBackend` trait (owner
/// decision; the compute-plane generalization is Phase 5). Unix-only (needs `socketpair`/`fork`);
/// the whole live path additionally refuses off-Linux / no-`sandbox` at [`super::run_instance`].
#[cfg(unix)]
mod per_tenant {
    use std::collections::BTreeMap;
    use std::os::fd::RawFd;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use boatramp_core::privsep::{PRIVSEP_TENANT_SCOPE_ENV, PerTenantPolicy, TenantScope};
    use boatramp_server::privsep_link::LinkEndpoint;
    use boatramp_server::privsep_tenant::{
        LinkEndpointRelay, PerTenantInstanceRegistry, TenantInstanceLink,
    };

    use super::{
        HostAuthority, InstanceSpawnSpec, InstanceSubstrate, PRIVSEP_FDS_ENV, PrivsepChildFds,
    };

    /// Set `FD_CLOEXEC` on `fd` so a per-tenant child the router fork+exec's never INHERITS it. The
    /// root-passed listener fd is NOT CLOEXEC (it survived the frontend's OWN exec), so without this
    /// it would leak into every per-tenant instance — a violation of F5 (the only fd that ever
    /// crosses to a per-tenant instance is its own socketpair link, then accepted CLIENT fds over
    /// it). The frontend keeps accepting on the listener: `FD_CLOEXEC` only affects `exec`, never the
    /// owning process. (The socketpair ends are already CLOEXEC from [`LinkEndpoint::socketpair`].)
    pub(super) fn set_cloexec(fd: RawFd) -> std::io::Result<()> {
        // SAFETY: F_GETFD/F_SETFD take no pointers; they read/tighten only this fd's own flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// The root supervisor's OWN fork+exec spawn primitive (design §2 / §4.1) — EXTRACTED (WS-C
    /// step 1) from the boot supervisor's spawn loop so the boot supervisor AND the per-tenant router
    /// instantiate an `__instance` the EXACT same way: re-exec the current binary with the spec's
    /// minimal secret-scrubbed env (F11-B `env_clear`), add `extra_env` (the fd map, the tenant
    /// scope), and in the child's `pre_exec` `dup2` each `(src → tgt)` onto its fixed target + clear
    /// `CLOEXEC` so it survives the exec, then `PR_SET_PDEATHSIG(SIGKILL)` (Linux) so a dead parent
    /// takes the child with it (no orphaned authority-holding instance). A `(src, tgt)` with
    /// `src == tgt` clears `CLOEXEC` in place WITHOUT a dup2 — how the router passes a single link fd
    /// at its own number, avoiding a target collision in its crowded fd table. The `dup2`/`fcntl`
    /// machinery is POSIX; only `PR_SET_PDEATHSIG` is Linux-gated.
    ///
    /// **Container substrate (Phase-3 SIMPLE model — design-note Option C).** When
    /// `spec.substrate == Container`, the child additionally `unshare(2)`s the mount, ipc, uts, and
    /// cgroup namespaces at the TOP of its `pre_exec`, BEFORE the (byte-identical) dup / CLOEXEC /
    /// `PR_SET_PDEATHSIG` sequence an OS-process child runs — so a Container child is nothing but an
    /// OS-process child with a namespace/cgroup wall ADDED underneath. Deliberately NOT unshared:
    /// `CLONE_NEWPID` (on the simple model it only retargets `pid_ns_for_children` without moving the
    /// caller, so with no fork-to-pid-1 the first thread the instance spawns fails `EAGAIN` — it
    /// breaks a multithreaded tokio instance and gives the instance process itself no isolation; true
    /// pid-ns isolation needs the pid-ns-init fork model, a deferred increment — design §8),
    /// `CLONE_NEWNET` (a `backend.*` instance must keep host-net egress to its DB/KV/blob — design §5b),
    /// and `CLONE_NEWUSER` (the per-capability Landlock + seccomp wall + the existing privilege drop
    /// already contain it — design §5b). `CLONE_NEWNS` gives a COPY of the mount table (no
    /// `pivot_root`): the per-capability Landlock profile the child installs post-`exec` stays the FS
    /// wall, unchanged (the paths it grants resolve to the same inodes), and the fd-pass is unaffected
    /// — an `AF_UNIX` socketpair end is a plain open fd that crosses any of these namespaces on the one
    /// shared kernel (design §2a). The `unshare` needs `CAP_SYS_ADMIN` (we do NOT add a user namespace),
    /// which the root supervisor holds (it binds privileged listeners); if it FAILS the `pre_exec`
    /// returns `Err` ⇒ `spawn()` fails ⇒ the caller tears the node down (`FailNodeClosed`) — NEVER a
    /// silent downgrade to an unconfined OS process. Linux-only (the CLONE_* flags are Linux); a
    /// Container spec on a non-Linux build is refused below rather than spawned unconfined (the live
    /// path is already Linux+`sandbox`-gated at [`super::run_privsep`] / [`super::run_instance`]).
    ///
    /// **Capability drop (Phase-3 Security re-review, Finding 2 — ALL instances).** When
    /// `drop_privileges` is set AND the child is uid 0 (so it has caps to drop), the `pre_exec` drops
    /// the FULL capability set so a served instance runs as uid 0 with ZERO capabilities — closing
    /// the retained-root primitives seccomp/Landlock don't block (metadata ops on the un-pivoted host
    /// mount table; `kill`/`tgkill` across the shared pid namespace). The BOOT caller passes
    /// `drop_privileges = true` (its children fork from the unconfined root, so they hold the caps to
    /// drop); the per-tenant router passes `false` (its children fork from the ALREADY-capless router
    /// and inherit zero caps — re-dropping would `EPERM`). A non-root node self-skips via `geteuid`.
    /// Done prctl-only (`SECBIT_NOROOT` + bounding-set drop + ambient clear) because `capset` is not
    /// on the seccomp allow-list; a key-material instance's `RLIMIT_MEMLOCK` is raised first so its
    /// best-effort key `mlock` still succeeds without `CAP_IPC_LOCK`.
    pub(super) fn spawn_wired_instance(
        current_exe: &Path,
        spec: &InstanceSpawnSpec,
        dups: Vec<(RawFd, RawFd)>,
        extra_env: &BTreeMap<String, String>,
        drop_privileges: bool,
    ) -> std::io::Result<std::process::Child> {
        let mut cmd = spec.to_command(current_exe);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let container = matches!(spec.substrate, InstanceSubstrate::Container);
        // Whether this instance mlocks key material (a crown jewel's sealing/signing key, or
        // `listen.public-tls`'s live private cert key) — mirrors `boatramp_server::sandbox`'s own
        // `holds_key_material`. Such an instance gets its RLIMIT_MEMLOCK raised before the cap drop so
        // its best-effort mlock still succeeds without CAP_IPC_LOCK (Finding 2 caveat).
        let holds_key_material = spec
            .capabilities
            .iter()
            .any(|a| a.is_crown_jewel() || *a == HostAuthority::ListenPublicTls);
        // The capability-drop + namespace blocks below are Linux-only; keep these inputs "used" on
        // other targets so the OS-process path stays warning-clean everywhere.
        #[cfg(not(target_os = "linux"))]
        let _ = (drop_privileges, holds_key_material);
        // Fail CLOSED rather than spawn a Container instance unconfined on a build where we cannot
        // install the namespace wall (the CLONE_* flags are Linux-only). The live privsep path is
        // already Linux+`sandbox`-gated upstream, so this is a defensive backstop, never a real path.
        #[cfg(not(target_os = "linux"))]
        if container {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the container substrate needs Linux namespaces (CLONE_NEWNS/NEWIPC/NEWUTS/\
                 NEWCGROUP); refusing to spawn it unconfined on a non-Linux build",
            ));
        }
        // SAFETY: `pre_exec` runs post-`fork`/pre-`exec`; `unshare`/`dup2`/`fcntl`/`prctl` are
        // async-signal-safe and touch only this child's namespaces + fd table + death-signal. The
        // caller assigns target fds above every source (boot path) or uses `src == tgt` (per-tenant
        // single link), so no `dup2` clobbers a not-yet-processed source. The `unshare` precedes the
        // fd dups, but none of the unshared namespaces (NS/IPC/UTS/CGROUP — net + pid + user
        // deliberately EXCLUDED) touch the fd table, so the fd-pass is byte-identical to the
        // OS-process path.
        unsafe {
            cmd.pre_exec(move || {
                // Container substrate: add the namespace/cgroup wall FIRST, then run the identical
                // OS-process fd-pass + death-signal sequence below. (No-op for OS-process children.)
                // `CLONE_NEWPID` is DELIBERATELY EXCLUDED on the simple model: `unshare(CLONE_NEWPID)`
                // does not move the caller into the new pid namespace — it only retargets
                // `pid_ns_for_children` — so with no fork-to-pid-1 (Option C never forks a pid-ns
                // init, to keep FailNodeClosed/PDEATHSIG/reaping byte-identical to OS-process), the
                // FIRST thread/process the re-exec'd instance creates fails `EAGAIN` ("can't spawn
                // worker thread"), killing a multithreaded (tokio) instance at startup. Confirmed on
                // the live gate. True pid-namespace isolation needs the pid-ns-init fork model (the
                // container worker's shape) and is a deferred increment — see §8 flag in the design
                // note. The four we unshare take effect for the caller IMMEDIATELY.
                #[cfg(target_os = "linux")]
                if container {
                    let flags = libc::CLONE_NEWNS
                        | libc::CLONE_NEWIPC
                        | libc::CLONE_NEWUTS
                        | libc::CLONE_NEWCGROUP;
                    if libc::unshare(flags) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                for (src, tgt) in &dups {
                    if *src != *tgt && libc::dup2(*src, *tgt) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // Clear CLOEXEC on the target so it survives the exec (dup2 already clears it for
                    // a distinct target; this also covers the src == tgt no-op case).
                    let flags = libc::fcntl(*tgt, libc::F_GETFD);
                    if flags < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(*tgt, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // FailNodeClosed robustness: if the parent dies, the kernel kills this instance (so a
                // crashed parent never leaves authority-holding instances orphaned). Linux only; a
                // best-effort hardening, not the containment itself.
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Phase-3 Security re-review, Finding 2: DROP ALL CAPABILITIES so a served instance
                // runs as uid 0 but with ZERO capabilities — closing the retained-root primitives
                // that neither seccomp nor Landlock blocks (metadata ops — chmod/chown/utimensat — on
                // the un-pivoted host mount table; kill/tgkill against host processes in the shared
                // pid namespace). Applies to EVERY instance (OS-process + Container). Done only where
                // we actually hold caps to drop: a root node's BOOT children fork from the UNCONFINED
                // root (full caps) and drop here; a non-root node's children already have none
                // (skipped via `geteuid`); a per-tenant child forked by the already-capless router
                // inherits zero caps and is called with `drop_privileges == false` (attempting the
                // drop would EPERM). Mechanism is prctl-ONLY — `capset` is NOT on the seccomp
                // allow-list, so a per-tenant child's cap drop under the router's filter would EPERM
                // and break cold-starts. `SECBIT_NOROOT` makes uid 0 gain NO caps at this execve, so
                // for our non-file-caps binary P'(permitted)=P'(effective)=0; the bounding-set drop +
                // ambient clear are belt-and-suspenders and give a clean `CapBnd`. Runs AFTER the
                // container `unshare` (its sole CAP_SYS_ADMIN consumer) and AFTER raising
                // RLIMIT_MEMLOCK for a key-material instance (so its best-effort mlock still locks the
                // key without CAP_IPC_LOCK). The post-exec `/proc/<ppid>/ns` self-check still works
                // (same-uid ptrace-read needs no cap). Setting `SECBIT_NOROOT` is load-bearing ⇒
                // fail-closed on error; the bounding/ambient/rlimit ops are best-effort.
                #[cfg(target_os = "linux")]
                if drop_privileges && libc::geteuid() == 0 {
                    if holds_key_material {
                        // 16 MiB is ample for any realistic key set (keys are KBs) and bounds abuse.
                        let lim = libc::rlimit {
                            rlim_cur: 16 * 1024 * 1024,
                            rlim_max: 16 * 1024 * 1024,
                        };
                        let _ = libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
                    }
                    // Drop ALL capabilities (SECBIT_NOROOT load-bearing + bounding-set drop +
                    // ambient clear) through the ONE shared, async-signal-safe `prctl` path the VM
                    // relay also uses — consolidated so the capability floor can never drift between
                    // the two. `SECBIT` failure ⇒ `Err` (fail-closed, as before); the rest is
                    // best-effort. (The RLIMIT_MEMLOCK raise + the `drop_privileges`/`geteuid` gate
                    // stay here — they are spawn-specific; the relay never holds key material.)
                    boatramp_server::sandbox::drop_all_capabilities()?;
                }
                Ok(())
            });
        }
        cmd.spawn()
    }

    /// The root's fork+exec primitive for the SEPARATE least-authority VM client-byte relay process
    /// (`__vm-relay`) — the S1 companion to [`spawn_wired_instance`], used ONLY by the boot
    /// supervisor's scoped-VM dispatch. It re-execs the current binary with the relay spec's minimal
    /// secret-scrubbed env (already shaped by [`super::plan_vm_relay_spec`] — `env_clear` + the
    /// descriptor + the fd map), and in the child's `pre_exec` `dup2`s the pre-bound public listener
    /// onto its fixed target fd + clears `CLOEXEC`, then `PR_SET_PDEATHSIG(SIGKILL)` so a dead root
    /// takes the relay with it (no orphaned relay).
    ///
    /// Deliberately DIFFERENT from [`spawn_wired_instance`] in two load-bearing ways:
    /// 1. **NO capability drop here.** The relay INHERITS the root's capabilities (incl.
    ///    `CAP_SYS_ADMIN`) and drops them ITSELF, in [`super::run_vm_relay_confined`] — AFTER using
    ///    `CAP_SYS_ADMIN` once to enter its empty netns + minimal mount-ns, and BEFORE installing its
    ///    profile / touching a client byte (`sandbox::drop_all_capabilities` +
    ///    `clear_current_capabilities`). Dropping caps in this `pre_exec` would break those unshares.
    /// 2. **NO namespace unshare here.** Unlike the Container substrate, the relay sets up its OWN
    ///    (net + mount) namespaces post-exec inside `run_vm_relay_confined`.
    ///
    /// The relay re-execs its own binary (the root's execve is Landlock-pinned to it), so this is the
    /// SAME re-exec primitive, minus the instance-specific cap/namespace steps.
    pub(super) fn spawn_vm_relay(
        current_exe: &Path,
        spec: &super::VmRelaySpawnSpec,
        dups: Vec<(RawFd, RawFd)>,
    ) -> std::io::Result<std::process::Child> {
        let mut cmd = spec.to_command(current_exe);
        // SAFETY: `pre_exec` runs post-`fork`/pre-`exec`; `dup2`/`fcntl`/`prctl` are async-signal-safe
        // and touch only this child's fd table + death-signal. The caller assigns the listener target
        // fd ABOVE every source fd, so the `dup2` cannot clobber a not-yet-processed source.
        unsafe {
            cmd.pre_exec(move || {
                for (src, tgt) in &dups {
                    if *src != *tgt && libc::dup2(*src, *tgt) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // Clear CLOEXEC on the target so the listener survives the exec into the relay.
                    let flags = libc::fcntl(*tgt, libc::F_GETFD);
                    if flags < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(*tgt, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                // FailNodeClosed robustness: a dead root takes the relay with it (Linux only).
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // NB: NO capability drop + NO namespace unshare here (see the fn doc) — the relay does
                // both ITSELF, post-exec, in `run_vm_relay_confined`.
                Ok(())
            });
        }
        cmd.spawn()
    }

    /// Why the per-tenant router could not INSTANTIATE a tenant's instance — fail-closed in every
    /// arm (the router refuses the connection rather than serving it from a wrong/absent instance).
    #[derive(Debug, thiserror::Error)]
    pub(super) enum InstantiateError {
        /// Creating the per-tenant `socketpair(2)` link failed.
        #[error("per-tenant instantiate: socketpair for tenant {project:?}: {source}")]
        Socketpair {
            /// The tenant project.
            project: String,
            /// The underlying OS error.
            source: std::io::Error,
        },
        /// The fork+exec of the per-tenant `__instance` failed.
        #[error("per-tenant instantiate: fork+exec for tenant {project:?}: {source}")]
        Spawn {
            /// The tenant project.
            project: String,
            /// The underlying OS error.
            source: std::io::Error,
        },
        /// The tenant's cold start is BACKED OFF: its child failed to instantiate, or died within
        /// the configured min-healthy window, too recently — so the router declines to re-fork it
        /// until the (exponential, capped) backoff elapses, rather than re-forking on every request.
        /// Fail-closed: the connection is refused; it is NEVER served from another tenant's instance,
        /// and the tenant recovers automatically once the window passes.
        #[error(
            "per-tenant instantiate: tenant {project:?} is backed off after a failed/crash-looping \
             cold start (retry in ~{retry_after_ms} ms)"
        )]
        BackedOff {
            /// The tenant project.
            project: String,
            /// Approximately how long until the next cold-start attempt is admitted.
            retry_after_ms: u64,
        },
        /// The NODE-WIDE cold-start rate budget is exhausted: admitting this cold start now would
        /// fork past the operator-tuned cold-start rate, so it is declined to protect already-warm
        /// instances from evict+fork churn under a cross-tenant request spray. Fail-closed: the
        /// connection is refused, never served from another tenant's instance.
        #[error(
            "per-tenant instantiate: node cold-start rate limit reached — declining to fork tenant \
             {project:?} right now (fail-closed)"
        )]
        ColdStartRateLimited {
            /// The tenant project.
            project: String,
        },
    }

    impl InstantiateError {
        /// Whether this is an ADMISSION decline (backoff / rate-limit) — EXPECTED under crash-loop
        /// churn or a cross-tenant spray, so the router logs it at `warn` — vs. a genuine
        /// socketpair/fork failure, logged at `error`. Both refuse the connection fail-closed.
        pub(super) fn is_admission_decline(&self) -> bool {
            matches!(
                self,
                Self::BackedOff { .. } | Self::ColdStartRateLimited { .. }
            )
        }
    }

    /// One live per-tenant instance the router is pooling.
    struct LiveInstance {
        link: TenantInstanceLink,
        child: std::process::Child,
        last_used: Instant,
    }

    /// Per-project cold-start admission + backoff state (WS-C MEDIUM — the cold-start churn / DoS
    /// guard). It dampens two failure shapes WITHOUT ever relaxing isolation: (1) a tenant whose
    /// child fails to fork or dies within the min-healthy window is BACKED OFF (exponential, capped)
    /// so it is not re-forked on every request; (2) a node-wide cold-start TOKEN BUCKET bounds the
    /// global fork rate so a request spray across more tenants than `max_instances` cannot force
    /// continuous SIGKILL+fork churn that evicts warm instances for free. Every decline is
    /// fail-closed: the router refuses the connection (`NotReady`/refusal), NEVER serving it from
    /// another tenant. All state is bounded (pruned) and operator-tunable via [`PerTenantPolicy`].
    #[derive(Debug)]
    struct Admission {
        /// Per-project backoff / crash-loop tracking. Pruned to the set currently backing off or with
        /// an armed crash-loop marker, so the map stays bounded by the recently-active tenant set.
        projects: BTreeMap<String, ProjectAdmission>,
        /// Node-wide cold-start token bucket: `tokens` refills at `cold_start_rate_per_sec` up to
        /// `cold_start_burst`, and each admitted cold start spends one.
        tokens: f64,
        /// When the bucket was last refilled.
        last_refill: Instant,
    }

    /// One project's cold-start admission state.
    #[derive(Debug, Default)]
    struct ProjectAdmission {
        /// When this project's most recent child was forked — arms crash-loop detection: if the
        /// NEXT cold-start attempt finds the instance already gone within the min-healthy window,
        /// the child crash-looped. `None` once consumed / after a healthy reset.
        last_spawn: Option<Instant>,
        /// Consecutive failed / crash-looping cold starts, driving the exponential (capped) backoff.
        consecutive_failures: u32,
        /// The earliest instant the next cold start for this project is admitted (the open backoff
        /// window), or `None` when not backing off.
        retry_after: Option<Instant>,
    }

    impl Admission {
        /// A fresh bucket seeded full (a cold node may wake up to `cold_start_burst` tenants at once).
        fn new(policy: &PerTenantPolicy) -> Self {
            Self {
                projects: BTreeMap::new(),
                tokens: policy.cold_start_burst_capacity(),
                last_refill: Instant::now(),
            }
        }

        /// Decide whether a cold start for `project` is admitted NOW. Called on the COLD path only
        /// (a reuse never forks), under the registry's `live` lock — so exactly one admit decision
        /// runs at a time. Fail-closed: `Err` ⇒ refuse the connection. On `Ok` a rate-limit token has
        /// been spent and the caller proceeds to fork.
        fn admit(
            &mut self,
            project: &str,
            now: Instant,
            policy: &PerTenantPolicy,
        ) -> Result<(), InstantiateError> {
            self.prune(now, policy);
            let min_healthy = policy.cold_start_min_healthy();
            let entry = self.projects.entry(project.to_string()).or_default();
            // Crash-loop: a child forked within the min-healthy window is ALREADY gone (we are on the
            // cold path ⇒ no live instance), so it died too fast — treat as a failed cold start and
            // back off. A zero window disables this (an instance is never "too short-lived").
            if let Some(ls) = entry.last_spawn {
                if !min_healthy.is_zero() && now.duration_since(ls) < min_healthy {
                    entry.last_spawn = None;
                    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                    let delay = policy.cold_start_backoff(entry.consecutive_failures);
                    entry.retry_after = Some(now + delay);
                    return Err(InstantiateError::BackedOff {
                        project: project.to_string(),
                        retry_after_ms: delay.as_millis() as u64,
                    });
                }
                // Lived at least the min-healthy window ⇒ it was healthy (now idle/cap-evicted): the
                // tenant is in good standing again, so clear the failure history.
                entry.last_spawn = None;
                entry.consecutive_failures = 0;
                entry.retry_after = None;
            }
            // An open backoff window (e.g. from a prior FORK failure) still blocks.
            if let Some(ra) = entry.retry_after {
                if now < ra {
                    return Err(InstantiateError::BackedOff {
                        project: project.to_string(),
                        retry_after_ms: ra.saturating_duration_since(now).as_millis() as u64,
                    });
                }
                entry.retry_after = None; // the window elapsed ⇒ half-open: allow one attempt
            }
            // Node-wide cold-start rate limit (protects warm instances from evict+fork churn). A rate
            // of 0 disables it entirely.
            if policy.cold_start_rate_per_sec > 0 {
                self.refill(now, policy);
                if self.tokens < 1.0 {
                    return Err(InstantiateError::ColdStartRateLimited {
                        project: project.to_string(),
                    });
                }
                self.tokens -= 1.0;
            }
            Ok(())
        }

        /// Record that `project`'s child was successfully forked — arms crash-loop detection for the
        /// next cold-start attempt.
        fn record_spawn(&mut self, project: &str, now: Instant) {
            self.projects
                .entry(project.to_string())
                .or_default()
                .last_spawn = Some(now);
        }

        /// Record a FORK failure for `project` (socketpair / fork+exec) — back off before the next
        /// attempt so a persistently-failing tenant is not re-forked on every request.
        fn record_failure(&mut self, project: &str, now: Instant, policy: &PerTenantPolicy) {
            let entry = self.projects.entry(project.to_string()).or_default();
            entry.last_spawn = None;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.retry_after = Some(now + policy.cold_start_backoff(entry.consecutive_failures));
        }

        /// Refill the token bucket for the time elapsed since the last refill, capped at the burst.
        fn refill(&mut self, now: Instant, policy: &PerTenantPolicy) {
            let elapsed = now
                .saturating_duration_since(self.last_refill)
                .as_secs_f64();
            if elapsed > 0.0 {
                let cap = policy.cold_start_burst_capacity();
                self.tokens =
                    (self.tokens + elapsed * f64::from(policy.cold_start_rate_per_sec)).min(cap);
                self.last_refill = now;
            }
        }

        /// Drop entries that carry no live obligation (no open backoff window, no armed crash-loop
        /// marker) so the map stays bounded by the recently-active tenant set.
        fn prune(&mut self, now: Instant, policy: &PerTenantPolicy) {
            let min_healthy = policy.cold_start_min_healthy();
            self.projects.retain(|_, e| {
                let backing_off = e.retry_after.is_some_and(|ra| now < ra);
                let armed = e.last_spawn.is_some_and(|ls| {
                    !min_healthy.is_zero() && now.duration_since(ls) < min_healthy
                });
                backing_off || armed
            });
        }
    }

    /// The LIVE per-tenant instance registry (WS-C step 3) — the real
    /// [`PerTenantInstanceRegistry`] the WS-B frontend router routes against. A `project → live
    /// instance` map the router grows ON DEMAND (one isolated `{exec.wasmtime}` OS process per
    /// tenant), with operator-tunable scale-to-zero ([`PerTenantPolicy`]). Per-tenant spawning stays
    /// INSIDE the (secret-blind) router via the root's own [`spawn_wired_instance`] — NOT a
    /// `ComputeBackend`. Each tenant's socketpair link is created LAZILY at
    /// [`instantiate`](Self::instantiate), never at boot, never shared.
    pub(super) struct ComputePlaneRegistry {
        /// The current binary to re-exec for each per-tenant instance.
        current_exe: PathBuf,
        /// The per-tenant TEMPLATE's spawn spec (argv + the minimal secret-scrubbed env, F11-B) — the
        /// root's authorized template, cloned per tenant with a scope + fd map added.
        template_spec: InstanceSpawnSpec,
        /// The declared frontend→template relay link NAME — the fd-map key under which each
        /// per-tenant child receives its socketpair end.
        link_name: String,
        /// The scale-to-zero policy (idle-eviction window + concurrency cap + cold-start admission).
        policy: PerTenantPolicy,
        /// The live instances, keyed by project. Interior-mutable so `resolve`/`instantiate` take
        /// `&self` (the trait object + the router accept loop share one `&registry`).
        live: Mutex<BTreeMap<String, LiveInstance>>,
        /// Cold-start admission + backoff state (WS-C MEDIUM). A SEPARATE lock from `live`, only ever
        /// taken from `instantiate` while `live` is held (so the lock order is fixed `live → admission`
        /// and there is no cross-path contention). It decides whether a cold start may fork; it never
        /// influences which tenant a connection routes to.
        admission: Mutex<Admission>,
    }

    impl ComputePlaneRegistry {
        /// Build a registry over the authorized template spec + the declared relay link + the policy.
        pub(super) fn new(
            current_exe: PathBuf,
            template_spec: InstanceSpawnSpec,
            link_name: String,
            policy: PerTenantPolicy,
        ) -> Self {
            let admission = Admission::new(&policy);
            Self {
                current_exe,
                template_spec,
                link_name,
                policy,
                live: Mutex::new(BTreeMap::new()),
                admission: Mutex::new(admission),
            }
        }

        /// Instantiate — or return the already-live — per-tenant instance for `scope` (the WS-C
        /// wake / cold-start seam the router drives on a [`RouteOutcome::NotReady`](boatramp_server::privsep_tenant::RouteOutcome::NotReady)).
        /// Lazily creates ONE socketpair for this tenant, forks the template via the root's own
        /// primitive with the scope wired into `BOATRAMP_PRIVSEP_TENANT_SCOPE` + the link fd map, and
        /// registers the live link. Enforces scale-to-zero first: an idle/exited sweep, then — if
        /// still at the concurrency cap — a least-recently-used eviction (never exceeds the cap,
        /// never silently refuses a valid tenant). Fail-closed on a socketpair / fork error.
        pub(super) fn instantiate(
            &self,
            scope: &TenantScope,
        ) -> Result<TenantInstanceLink, InstantiateError> {
            let mut live = self.live.lock().unwrap();
            // A concurrent route may already have instantiated it (cold-start race): reuse it.
            if let Some(inst) = live.get_mut(scope.project()) {
                inst.last_used = Instant::now();
                return Ok(inst.link.clone());
            }
            // Cold-start ADMISSION (WS-C MEDIUM): before forking anything, consult the backoff +
            // node-wide cold-start rate budget. A declined cold start refuses THIS connection
            // fail-closed (it is NEVER served from another tenant) and leaves every warm instance
            // untouched (no fork ⇒ no eviction). Consulted only here on the cold path (a reuse above
            // never forks). The `admission` lock is taken while `live` is held (fixed order), and
            // this critical section contains no `.await` and no fork.
            let now = Instant::now();
            self.admission
                .lock()
                .unwrap()
                .admit(scope.project(), now, &self.policy)?;
            // Scale-to-zero: reap exited + evict idle, then enforce the cap (LRU) BEFORE inserting.
            Self::sweep(&mut live, &self.policy);
            Self::enforce_cap(&mut live, self.policy.max_instances);
            // LAZY per-tenant socketpair (never shared, never at boot). `front` stays with the router
            // (the relay half); `back` is handed to the child at its own fd number. A failure backs the
            // tenant off (so a persistently-failing cold start is not re-forked on every request).
            let (front, back) = match LinkEndpoint::socketpair() {
                Ok(pair) => pair,
                Err(e) => {
                    self.admission.lock().unwrap().record_failure(
                        scope.project(),
                        Instant::now(),
                        &self.policy,
                    );
                    return Err(InstantiateError::Socketpair {
                        project: scope.project().to_string(),
                        source: e,
                    });
                }
            };
            let back_fd = back.as_raw_fd();
            // The per-tenant child's fd map: the one relay link, under its declared name, at `back_fd`.
            let mut fds = PrivsepChildFds::default();
            fds.links.insert(self.link_name.clone(), back_fd);
            let mut extra_env = BTreeMap::new();
            extra_env.insert(PRIVSEP_FDS_ENV.to_string(), fds.to_env_value());
            // The UNFORGEABLE tenant scope — a non-secret BOATRAMP_* name the child RE-VALIDATES.
            extra_env.insert(
                PRIVSEP_TENANT_SCOPE_ENV.to_string(),
                scope.env_value().to_string(),
            );
            // Fork via the root's OWN primitive. `src == tgt == back_fd` clears CLOEXEC in place so
            // the child inherits `back` at its own number WITHOUT a dup2 (no target collision in the
            // router's crowded fd table); `front` + the listener stay CLOEXEC so neither leaks.
            let child = match spawn_wired_instance(
                &self.current_exe,
                &self.template_spec,
                vec![(back_fd, back_fd)],
                &extra_env,
                // The per-tenant router (the parent) has ALREADY dropped all capabilities at ITS own
                // boot spawn, so this cold-start child inherits zero caps + a locked SECBIT_NOROOT.
                // It must NOT re-attempt the drop: the capless child lacks CAP_SETPCAP, so the prctl
                // would EPERM — and `capset` isn't on the router's seccomp allow-list anyway. Zero
                // caps is already guaranteed by inheritance.
                false,
            ) {
                Ok(child) => child,
                Err(e) => {
                    self.admission.lock().unwrap().record_failure(
                        scope.project(),
                        Instant::now(),
                        &self.policy,
                    );
                    return Err(InstantiateError::Spawn {
                        project: scope.project().to_string(),
                        source: e,
                    });
                }
            };
            // A fresh child forked: arm crash-loop detection (a death within the min-healthy window,
            // observed on the NEXT cold start, backs the tenant off).
            self.admission
                .lock()
                .unwrap()
                .record_spawn(scope.project(), Instant::now());
            // The child inherited `back` (fork duplicated the fd table); drop the router's copy so
            // ONLY the child holds its end.
            drop(back);
            let relay = Arc::new(LinkEndpointRelay::new(
                format!("tenant:{}", scope.project()),
                Arc::new(front),
            ));
            let link = TenantInstanceLink::new(scope.clone(), relay);
            tracing::info!(
                project = %scope.project(),
                pid = child.id(),
                live = live.len() + 1,
                "[privsep] per-tenant router: instantiated a tenant instance (lazy socketpair, \
                 scope-wired via env_clear, NO secret inherited)"
            );
            live.insert(
                scope.project().to_string(),
                LiveInstance {
                    link: link.clone(),
                    child,
                    last_used: Instant::now(),
                },
            );
            Ok(link)
        }

        /// Reap exited children + evict instances idle past the policy window (scale-to-zero).
        fn sweep(live: &mut BTreeMap<String, LiveInstance>, policy: &PerTenantPolicy) {
            let idle = policy.idle_eviction();
            let now = Instant::now();
            let evict: Vec<String> = live
                .iter_mut()
                .filter_map(|(p, inst)| {
                    // Reap a child that already exited (crashed/killed) — its link is dead.
                    let exited = matches!(inst.child.try_wait(), Ok(Some(_)));
                    let idle_out = idle.is_some_and(|w| now.duration_since(inst.last_used) >= w);
                    (exited || idle_out).then(|| p.clone())
                })
                .collect();
            for p in evict {
                if let Some(inst) = live.remove(&p) {
                    Self::kill(inst);
                    tracing::info!(project = %p, "[privsep] per-tenant router: evicted an idle/exited tenant instance (scale-to-zero)");
                }
            }
        }

        /// Enforce the concurrency cap: while at/over `max`, evict the LEAST-recently-used instance
        /// (so the subsequent insert never exceeds the cap). `max` is validated ≥ 1 at the root.
        fn enforce_cap(live: &mut BTreeMap<String, LiveInstance>, max: u32) {
            let max = (max as usize).max(1);
            while live.len() >= max {
                let Some(lru) = live
                    .iter()
                    .min_by_key(|(_, i)| i.last_used)
                    .map(|(p, _)| p.clone())
                else {
                    break;
                };
                if let Some(inst) = live.remove(&lru) {
                    Self::kill(inst);
                    tracing::info!(project = %lru, "[privsep] per-tenant router: evicted the LRU tenant instance to honor the concurrency cap");
                }
            }
        }

        /// SIGKILL + reap one per-tenant child (its relay link drops → the socketpair end closes).
        fn kill(mut inst: LiveInstance) {
            let _ = inst.child.kill();
            let _ = inst.child.wait();
        }
    }

    impl PerTenantInstanceRegistry for ComputePlaneRegistry {
        fn resolve(&self, scope: &TenantScope) -> Option<TenantInstanceLink> {
            let mut live = self.live.lock().unwrap();
            let inst = live.get_mut(scope.project())?;
            // A child that has exited has a dead link — reap it and report NOT live, so the router
            // fails over to a fresh NotReady → instantiate rather than relaying onto a dead socket.
            if matches!(inst.child.try_wait(), Ok(Some(_))) {
                if let Some(dead) = live.remove(scope.project()) {
                    Self::kill(dead);
                }
                return None;
            }
            inst.last_used = Instant::now();
            Some(inst.link.clone())
        }
    }

    #[cfg(test)]
    mod admission_tests {
        use std::time::Duration;

        use super::*;

        fn policy() -> PerTenantPolicy {
            PerTenantPolicy {
                cold_start_min_healthy_ms: 1000,
                cold_start_backoff_base_ms: 500,
                cold_start_backoff_max_ms: 30_000,
                cold_start_rate_per_sec: 0, // isolate backoff from the rate limit in these tests
                cold_start_burst: 100,
                ..PerTenantPolicy::default()
            }
        }

        #[test]
        fn first_cold_start_is_admitted_and_a_healthy_reuse_cycle_does_not_back_off() {
            let p = policy();
            let mut adm = Admission::new(&p);
            let t0 = Instant::now();
            // First cold start: admitted; arm the crash-loop marker.
            adm.admit("acme", t0, &p)
                .expect("first cold start admitted");
            adm.record_spawn("acme", t0);
            // The instance lived well past the min-healthy window, then was idle/cap-evicted. The
            // next cold start sees a HEALTHY prior life → admitted, failure history cleared.
            let t1 = t0 + Duration::from_secs(5);
            adm.admit("acme", t1, &p)
                .expect("a cold start after a healthy prior life is admitted");
            assert_eq!(adm.projects["acme"].consecutive_failures, 0);
        }

        #[test]
        fn a_child_dying_within_the_window_backs_the_tenant_off_exponentially() {
            let p = policy();
            let mut adm = Admission::new(&p);
            let t0 = Instant::now();
            adm.admit("acme", t0, &p).unwrap();
            adm.record_spawn("acme", t0);
            // The child died ~200ms later (within the 1s window); the next cold start detects the
            // crash loop and backs off (base 500ms).
            let t1 = t0 + Duration::from_millis(200);
            let err = adm.admit("acme", t1, &p).unwrap_err();
            assert!(err.is_admission_decline());
            assert!(matches!(err, InstantiateError::BackedOff { .. }));
            assert_eq!(adm.projects["acme"].consecutive_failures, 1);
            // Still inside the backoff window ⇒ still declined.
            let err2 = adm
                .admit("acme", t1 + Duration::from_millis(100), &p)
                .unwrap_err();
            assert!(matches!(err2, InstantiateError::BackedOff { .. }));
            // A DIFFERENT tenant is unaffected (per-project — never a foreign tenant's instance).
            adm.admit("globex", t1, &p)
                .expect("an unrelated tenant is not backed off");
        }

        #[test]
        fn a_fork_failure_backs_off_then_recovers_after_the_window() {
            let p = policy();
            let mut adm = Admission::new(&p);
            let t0 = Instant::now();
            adm.admit("acme", t0, &p).unwrap();
            adm.record_failure("acme", t0, &p); // socketpair/fork failed
            // Within the 500ms window: declined.
            assert!(matches!(
                adm.admit("acme", t0 + Duration::from_millis(100), &p),
                Err(InstantiateError::BackedOff { .. })
            ));
            // After the window: half-open, admitted again.
            adm.admit("acme", t0 + Duration::from_millis(600), &p)
                .expect("the backoff window elapsed ⇒ a retry is admitted");
        }

        #[test]
        fn the_node_wide_token_bucket_rate_limits_cold_start_sprays() {
            let p = PerTenantPolicy {
                cold_start_min_healthy_ms: 0, // disable crash-loop backoff; isolate the rate limit
                cold_start_rate_per_sec: 10,
                cold_start_burst: 3,
                ..PerTenantPolicy::default()
            };
            let mut adm = Admission::new(&p);
            let t0 = Instant::now();
            // A spray across distinct tenants: the burst (3) is admitted, the 4th is rate-limited —
            // so warm instances are never evicted to fork a 4th in the same instant.
            for i in 0..3 {
                adm.admit(&format!("t{i}"), t0, &p)
                    .unwrap_or_else(|_| panic!("burst slot {i} admitted"));
            }
            let err = adm.admit("t3", t0, &p).unwrap_err();
            assert!(err.is_admission_decline());
            assert!(matches!(err, InstantiateError::ColdStartRateLimited { .. }));
            // 100ms later the bucket refilled one token (10/s) ⇒ one more admitted.
            adm.admit("t3", t0 + Duration::from_millis(100), &p)
                .expect("a refilled token admits one more cold start");
        }
    }
}

// =============================================================================
// The root supervisor: socketpair wiring + privileged listener bind + fork/exec + supervise
// =============================================================================

#[cfg(unix)]
mod supervise {
    use std::os::fd::{AsRawFd, RawFd};
    use std::path::Path;

    use boatramp_core::privsep::LinkTransport;
    use boatramp_server::privsep_link::LinkEndpoint;

    use super::{PrivsepChildFds, PrivsepError, RootPlan, ServerConfig};

    /// Run the root supervisor over the AUTHORIZED `plan` (design §4): create a `socketpair(2)` per
    /// `local` link, bind the privileged public listeners, `fork`+`exec` one `__instance` per
    /// authorized instance passing it only its own link ends + listener fd, then supervise
    /// fail-closed (`FailNodeClosed` — any child exit tears the node down). The root holds bootstrap
    /// authority only: it parses no bytes, opens no pool, unseals no key.
    pub(super) fn run(
        config: &ServerConfig,
        plan: &RootPlan,
        config_path: &Path,
    ) -> Result<(), PrivsepError> {
        let err = |m: String| PrivsepError::Supervise(m);
        let privsep = config
            .privsep
            .as_ref()
            .ok_or_else(|| err("no [privsep] section at supervise time".to_string()))?;
        let current_exe =
            std::env::current_exe().map_err(|e| err(format!("resolving current exe: {e}")))?;

        // Phase-3 Container substrate: the root's OWN namespace identities, read ONCE here (the root
        // never unshares — it stays in the host namespaces). Pushed down to each container instance so
        // it can self-confirm its fresh namespaces by reading only its OWN /proc/self/ns (a capless
        // instance cannot ptrace-read the full-cap root's /proc/<ppid>/ns — Finding 2). `None` only if
        // a readlink fails, in which case a container instance gets no baseline and fail-closes.
        #[cfg(target_os = "linux")]
        let container_ns_baseline = super::read_own_ns_baseline();

        // Phase-3 spawn-backend dispatch (design §7 "substrate is a spawn backend"): resolve EACH
        // instance's isolation substrate BEFORE wiring/binding/spawning anything. OS-process + the
        // Phase-3 namespace/cgroup Container backend are WIRED; `Vm` is NOW WIRED too for the scoped
        // key-free static-parser frontend shape (live-proven + Security-reviewed SHIP) — the VM branch
        // below boots the microVM guest + forks a separate `__vm-relay` (the host client-byte relay runs
        // in that least-authority relay, NOT the secret-blind root's networkless self-profile; S1). Any
        // OTHER VM shape is refused fail-closed here (see `resolve_spawn_backend`). Container reuses the
        // SAME fork+exec below — it only adds the child-side `unshare` in `spawn_wired_instance`'s
        // `pre_exec` (design-note Option C / §8).
        for (label, inst) in &privsep.instances {
            super::resolve_spawn_backend(label, inst.substrate, &inst.capabilities)?;
        }

        // Phase-4 WS-C: per-tenant TEMPLATE instances are NOT forked at boot and their links are NOT
        // socketpaired at boot — the per-tenant router instantiates a copy (with its own scope +
        // socketpair) per tenant on demand. Collect the template labels so the boot wiring below
        // skips them (a template boot-forked once, with no wired tenant scope, would die `Unwired` →
        // `FailNodeClosed`). A composition with NO template leaves this empty ⇒ byte-unchanged.
        let template_labels: std::collections::BTreeSet<&String> = privsep
            .instances
            .iter()
            .filter(|(_, inst)| inst.lifecycle.is_per_tenant_template())
            .map(|(label, _)| label)
            .collect();
        let touches_template = |link: &boatramp_core::privsep::PrivsepLink| -> bool {
            template_labels.contains(&link.from) || template_labels.contains(&link.to)
        };

        // The per-sealer unseal allowlist (the signer-key-unlock containment): the root wires each
        // `secrets.sealer` instance the exact names each of its links' peers may unseal. NON-SECRET
        // (names only), handed in via an env var alongside the fd map.
        let unseal_allowlists = super::compute_unseal_allowlists(config);
        // The per-crown-jewel WS-E authority-serve link designation (seal/unseal/mint_token grammar).
        // NON-SECRET (link names only); empty for every Phase-1 composition (see the rule).
        let authority_serve_links = super::compute_authority_serve_links(config);

        // 1. A root-created socketpair(2) per `local` link; one end to each endpoint instance.
        //    `tcp`/`overlay` carry their own endpoint arrangement — not wired in the Phase-1 cut
        //    (design §6: local + tcp first; this WS lands the `local` default). Refuse, fail-closed.
        let mut links_by_instance: std::collections::BTreeMap<String, Vec<(String, LinkEndpoint)>> =
            std::collections::BTreeMap::new();
        for (lname, link) in &privsep.links {
            // Defer a link that touches a per-tenant template: its socketpair is created LAZILY, per
            // tenant, by the router at instantiation time — never at boot, never shared (WS-C step 2).
            if touches_template(link) {
                continue;
            }
            match &link.transport {
                LinkTransport::Local => {
                    let (a, b) = LinkEndpoint::socketpair()
                        .map_err(|e| err(format!("socketpair for link {lname:?}: {e}")))?;
                    links_by_instance
                        .entry(link.from.clone())
                        .or_default()
                        .push((lname.clone(), a));
                    links_by_instance
                        .entry(link.to.clone())
                        .or_default()
                        .push((lname.clone(), b));
                }
                other => {
                    return Err(err(format!(
                        "link {lname:?} transport {other:?} is not wired in the Phase-1 cut \
                         (the `local` socketpair transport is; `tcp`/`overlay` are a follow-on)"
                    )));
                }
            }
        }

        // 2. Bind the privileged public listener for each `listen.*` holder (the root binds; the
        //    frontend's profile denies `bind`). Kept owned so the fd stays open across all forks.
        let mut listener_by_instance: std::collections::BTreeMap<String, std::net::TcpListener> =
            std::collections::BTreeMap::new();
        for (label, inst) in &privsep.instances {
            if let Some(addr) = super::instance_listener_addr(&inst.capabilities, config) {
                let listener = std::net::TcpListener::bind(addr)
                    .map_err(|e| err(format!("binding {addr} for instance {label:?}: {e}")))?;
                listener_by_instance.insert(label.clone(), listener);
            }
        }

        // 3. Assign each inherited end/listener a GLOBALLY-UNIQUE target fd number ABOVE every
        //    source fd, so a `pre_exec` `dup2(src → tgt)` can never clobber a not-yet-processed
        //    source (in this child or another's inherited copy). Build each instance's fd map + its
        //    (source, target) dup list.
        let mut sources: Vec<RawFd> = Vec::new();
        for eps in links_by_instance.values() {
            sources.extend(eps.iter().map(|(_, ep)| ep.as_raw_fd()));
        }
        sources.extend(listener_by_instance.values().map(AsRawFd::as_raw_fd));
        let mut next_target = sources.iter().copied().max().unwrap_or(2).max(2) + 1;

        struct ChildWiring {
            label: String,
            fds: PrivsepChildFds,
            dups: Vec<(RawFd, RawFd)>, // (source fd in the parent, target fd in the child)
        }
        let mut wirings: Vec<ChildWiring> = Vec::new();
        for label in privsep.instances.keys() {
            // A per-tenant template is not boot-forked, so it gets no boot fd wiring (WS-C step 2).
            if template_labels.contains(label) {
                continue;
            }
            let mut fds = PrivsepChildFds::default();
            let mut dups = Vec::new();
            if let Some(eps) = links_by_instance.get(label) {
                for (lname, ep) in eps {
                    let target = next_target;
                    next_target += 1;
                    fds.links.insert(lname.clone(), target);
                    dups.push((ep.as_raw_fd(), target));
                }
            }
            if let Some(listener) = listener_by_instance.get(label) {
                let target = next_target;
                next_target += 1;
                fds.listener = Some(target);
                dups.push((listener.as_raw_fd(), target));
            }
            wirings.push(ChildWiring {
                label: label.clone(),
                fds,
                dups,
            });
        }

        // 4. `fork`+`exec` each STATIC `__instance` (NOT the per-tenant templates — WS-C step 2) with
        //    its scrubbed env (already built, F11-B) + the fd map, via the root's own extracted spawn
        //    primitive (`spawn_wired_instance`, WS-C step 1 — the SAME primitive the per-tenant router
        //    reuses). The extra env carries the fd map, plus a sealer's unseal allowlist / a crown
        //    jewel's authority-serve links (names only), exactly as before.
        // Scoped-VM dispatch state (S1). Computed up front; referenced only by the VM branch in the
        // spawn loop (a composition with no `substrate: vm` instance never reads them at runtime —
        // which is fine, the source reference keeps them "used" at compile time):
        // - `declared_secret_env`: the config-declared secret-env set, so the relay's env scrub matches
        //   every instance's (Finding-1 parity — a BYO credential never crosses to the relay);
        // - `vm_work_root`: the per-VM work dir root (initramfs/firecracker.json/console) under the node
        //   data dir — NOT in the relay's Landlock view (the relay dials only the vsock UDS);
        // - `next_guest_cid`: a monotonic guest CID (0/1/2 are reserved; multi-VM topology is a follow-on).
        #[cfg(target_os = "linux")]
        let declared_secret_env =
            boatramp_node::privsep_resolve::declared_secret_env_var_names(config);
        #[cfg(target_os = "linux")]
        let vm_work_root = {
            let cwd = std::env::current_dir().map_err(|e| err(format!("cwd: {e}")))?;
            super::normalized_data_dir(config, &cwd).join("privsep-vm")
        };
        #[cfg(target_os = "linux")]
        let mut next_guest_cid: u32 = 3;

        let mut children: Vec<(String, std::process::Child)> = Vec::new();
        for spec in &plan.static_instances {
            let Some(wiring) = wirings.iter().find(|w| w.label == spec.label) else {
                continue;
            };

            // Scoped-VM substrate dispatch (S1): the VM frontend does NOT take the single-`__instance`
            // fork+exec path below (its own kernel ⇒ the `local` socketpair cannot cross). Instead the
            // root boots the microVM guest ([`boot_frontend_vm`], NO in-root relay thread) and
            // `fork`+`exec`s a SEPARATE least-authority `__vm-relay` process that splices the client's
            // bytes to the frontend-in-guest over the vsock bridge — the relay, NOT the secret-blind
            // root, is the host-side vsock endpoint, and the root carries no key bytes. BOTH children
            // (firecracker + relay) are supervised; either's death ⇒ `FailNodeClosed`.
            if matches!(spec.substrate, super::InstanceSubstrate::Vm) {
                #[cfg(target_os = "linux")]
                {
                    let guest_cid = next_guest_cid;
                    next_guest_cid += 1;
                    // The scoped frontend is a key-free LISTENER-ONLY slice, so it MUST have a
                    // root-bound public listener (assigned a target fd in step 3).
                    let listener_target = match wiring.fds.listener {
                        Some(t) => t,
                        None => {
                            kill_all(&mut children);
                            return Err(err(format!(
                                "scoped VM frontend {:?} has no bound public listener fd — a key-free \
                                 static-parser frontend must bind serve.addr",
                                spec.label
                            )));
                        }
                    };
                    // LOW-1 (Security review, dup-site containment — STRUCTURAL at the source). A scoped
                    // static-parser frontend has NO cross-kernel `local` socketpair links by construction
                    // (its own guest kernel cannot cross a host socketpair — design §2a; the S2 scope lint
                    // admits only a key-free listener-only slice, which holds no feature-links). So any
                    // link fd in this wiring is a MIS-WIRE — refuse fail-closed rather than hand it to the
                    // secret-blind relay. This makes "the relay inherits ONLY the listener" a property of
                    // the SOURCE wiring, not something the downstream `close_inherited_fds_except` has to
                    // scrub after the fact.
                    if !wiring.fds.links.is_empty() {
                        kill_all(&mut children);
                        return Err(err(format!(
                            "scoped VM frontend {:?} was wired {} cross-kernel link fd(s) ({:?}) — a \
                             key-free static-parser frontend has NO socketpair links by construction, so \
                             this is a mis-wire; refusing fail-closed rather than passing a link fd to \
                             the secret-blind __vm-relay",
                            spec.label,
                            wiring.fds.links.len(),
                            wiring.fds.links.keys().collect::<Vec<_>>(),
                        )));
                    }
                    let assets = match crate::privsep_vm::VmAssets::from_env() {
                        Ok(a) => a,
                        Err(e) => {
                            kill_all(&mut children);
                            return Err(err(format!(
                                "the vm substrate for instance {:?} needs its operator-provisioned \
                                 assets: {e}",
                                spec.label
                            )));
                        }
                    };
                    let work_dir = vm_work_root.join(&spec.label);
                    // Boot the microVM guest (NO in-root relay thread — S1). The firecracker child is
                    // spawned here, in the pre-self-profile window (the root's self-profile Landlock-pins
                    // execve to its OWN binary, so firecracker — a different binary — must exec now).
                    let booted = match crate::privsep_vm::boot_frontend_vm(
                        &current_exe,
                        &spec.label,
                        config_path,
                        &assets,
                        &work_dir,
                        guest_cid,
                        crate::privsep_vm::DEFAULT_GUEST_VSOCK_PORT,
                    ) {
                        Ok(b) => b,
                        Err(e) => {
                            kill_all(&mut children);
                            return Err(err(format!(
                                "booting the scoped VM frontend {:?}: {e}",
                                spec.label
                            )));
                        }
                    };
                    // The relay's NON-SECRET descriptor + its secret-blind spawn spec: the pre-bound
                    // public TCP listener rides the ONE existing fd-pass (`PrivsepChildFds`) at
                    // `listener_target`; the env is the minimal capability-less scrub (no credential
                    // crosses) + only the two non-secret wiring vars.
                    let descriptor = super::VmRelayDescriptor {
                        label: spec.label.clone(),
                        uds_path: booted.uds_path.clone(),
                        guest_port: crate::privsep_vm::DEFAULT_GUEST_VSOCK_PORT,
                    };
                    let relay_spec = super::plan_vm_relay_spec(
                        &spec.label,
                        &descriptor,
                        listener_target,
                        std::env::vars(),
                        &declared_secret_env,
                    );
                    // LOW-1 (Security review): hand the relay ONLY the listener dup — the single fd it
                    // legitimately inherits (the pre-bound public TCP listener on `listener_target`). The
                    // links-empty refusal above already proved `wiring.dups` holds no link entries for a
                    // VM frontend, so this filter is belt-and-suspenders that makes the relay's inherited
                    // set EXACTLY {listener} at the source, independent of any future wiring change — no
                    // stray dup can reach the `__vm-relay`'s pre_exec `dup2` loop.
                    let relay_dups: Vec<(RawFd, RawFd)> = wiring
                        .dups
                        .iter()
                        .copied()
                        .filter(|(_, tgt)| *tgt == listener_target)
                        .collect();
                    // fork+exec the SEPARATE least-authority relay process. It INHERITS the root's
                    // capabilities (it drops them ITSELF after entering its netns/mount-ns), so
                    // `spawn_vm_relay` does NO pre_exec cap drop — unlike `spawn_wired_instance`.
                    let relay_child = match super::per_tenant::spawn_vm_relay(
                        &current_exe,
                        &relay_spec,
                        relay_dups,
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            // Tear down the firecracker child we just booted, then everything else.
                            let mut fc = booted.child;
                            let _ = fc.kill();
                            let _ = fc.wait();
                            kill_all(&mut children);
                            return Err(err(format!(
                                "spawning the __vm-relay for instance {:?}: {e}",
                                spec.label
                            )));
                        }
                    };
                    tracing::info!(
                        instance = %spec.label,
                        fc_pid = booted.child.id(),
                        relay_pid = relay_child.id(),
                        guest_cid,
                        console = %booted.console.display(),
                        "[privsep] root: scoped VM frontend dispatched — firecracker guest + separate \
                         __vm-relay process, BOTH supervised (either exit ⇒ FailNodeClosed); the relay \
                         (NOT the secret-blind root) is the host-side vsock endpoint (S1)"
                    );
                    // Supervise BOTH: a guest death (firecracker exit) OR a relay death (incl. a failed
                    // readiness handshake) tears the node down fail-closed.
                    children.push((format!("{} (firecracker guest)", spec.label), booted.child));
                    children.push((format!("{} (vm-relay)", spec.label), relay_child));
                    continue;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    kill_all(&mut children);
                    return Err(err(format!(
                        "instance {:?} selects the vm substrate, which needs Linux + KVM; refusing \
                         fail-closed on this build (never a silent OS-process downgrade)",
                        spec.label
                    )));
                }
            }

            let mut extra_env: std::collections::BTreeMap<String, String> =
                std::collections::BTreeMap::new();
            extra_env.insert(
                super::PRIVSEP_FDS_ENV.to_string(),
                wiring.fds.to_env_value(),
            );
            // A `secrets.sealer` instance also gets its root-wired unseal allowlist (names only).
            if let Some(allow) = unseal_allowlists.get(&spec.label) {
                extra_env.insert(
                    boatramp_server::privsep_unseal::PRIVSEP_UNSEAL_ALLOW_ENV.to_string(),
                    allow.to_env_value(),
                );
            }
            // A crown-jewel instance with designated WS-E authority-serve links gets them (names only).
            if let Some(links) = authority_serve_links.get(&spec.label)
                && !links.is_empty()
            {
                extra_env.insert(
                    super::PRIVSEP_AUTHORITY_LINKS_ENV.to_string(),
                    serde_json::to_string(links).expect("authority-serve link set serializes"),
                );
            }
            // A `substrate: container` instance gets the root's own namespace baseline (names/inodes
            // only) so it can self-confirm — reading only its OWN /proc/self/ns, which works after the
            // capability drop — that it entered fresh namespaces. If the root could not read its own
            // baseline the var is absent and the instance fail-closes its self-check.
            #[cfg(target_os = "linux")]
            if matches!(spec.substrate, super::InstanceSubstrate::Container)
                && let Some(baseline) = &container_ns_baseline
            {
                extra_env.insert(
                    super::PRIVSEP_CONTAINER_NS_ENV.to_string(),
                    baseline.clone(),
                );
            }
            match super::per_tenant::spawn_wired_instance(
                &current_exe,
                spec,
                wiring.dups.clone(),
                &extra_env,
                // Boot spawn: this child forks from the UNCONFINED root (full caps on a root node),
                // so it drops ALL capabilities in its pre_exec (Finding 2). On a non-root node the
                // child already has none and the drop self-skips via `geteuid`.
                true,
            ) {
                Ok(child) => {
                    tracing::info!(
                        instance = %spec.label,
                        pid = child.id(),
                        substrate = spec.substrate.tag(),
                        "[privsep] root: spawned __instance (fds wired, scrubbed env{})",
                        if matches!(spec.substrate, super::InstanceSubstrate::Container) {
                            "; unshared NS/IPC/UTS/CGROUP — net+pid+user shared (simple model)"
                        } else {
                            ""
                        }
                    );
                    children.push((spec.label.clone(), child));
                }
                Err(e) => {
                    kill_all(&mut children);
                    return Err(err(format!("spawning instance {:?}: {e}", spec.label)));
                }
            }
        }

        // Close the parent's copies of the ends it handed out — only the children (via the
        // inherited, dup'd fds) hold them now. (The children have already forked, so their fd
        // tables captured the open sources.)
        drop(links_by_instance);
        drop(listener_by_instance);

        // 5. Install the root's OWN tightest self-profile (design §4.3) — the TCB floor, confining
        //    the supervisor for the rest of its life. Installed HERE, AFTER every instance has been
        //    fork+exec'd (each child forked from an UNCONFINED root and installs its own, broader,
        //    per-capability profile post-exec), because seccomp AND Landlock are both inherited
        //    across fork+exec and STACK as an INTERSECTION — a child can only ever LOSE access a
        //    parent layer dropped, never regain it. Installing this (keyless, networkless,
        //    data_dir-less) profile BEFORE the spawn loop would therefore clamp every child to the
        //    root's own domain (no `connect` for a backend, no `accept4` for a frontend, no `mlock`
        //    for a signer, no `kek_file`/`data_dir` in the Landlock view). The spawn loop parses no
        //    untrusted input, so the one-shot pre-install window carries no attack surface; the
        //    long-lived supervise loop below runs fully confined. The root RETAINS `execve`
        //    (Landlock-pinned to its own binary — see `sandbox::root_supervisor_policy`) so the
        //    re-exec of `boatramp __instance` stays possible; everything else is `EPERM`, and the
        //    escape surface (ptrace/mount/bpf/keyctl/…) is hard-`SIGSYS`-killed. Fail-closed: the
        //    root REFUSES to serve unless the profile reports `Enforced` (same gate as the
        //    instances — `enforce_privsep_status`). The caller already refused a non-Linux/no-
        //    `sandbox` build before reaching here, so on this path the install is a real Linux one.
        let cwd = std::env::current_dir().map_err(|e| err(format!("cwd: {e}")))?;
        let exe_norm = super::normalize_for_landlock(&current_exe, &cwd);
        let config_norm = super::normalize_for_landlock(config_path, &cwd);
        let profile = boatramp_server::sandbox::derive_root_profile(&exe_norm, &config_norm);
        let status = match boatramp_server::sandbox::enforce_privsep_status(
            boatramp_server::sandbox::install_derived(&profile),
        ) {
            Ok(status) => status,
            Err(e) => {
                // Fail closed EXPLICITLY. The instances are already spawned and hold
                // crown-jewel authority; if the root cannot install its OWN confinement
                // (e.g. a kernel below `MIN_LANDLOCK_ABI` ⇒ `NotEnforced`) we tear them
                // down here rather than lean on each child's `PR_SET_PDEATHSIG` — a
                // best-effort hardening, not the containment — as the sole teardown for
                // this path. Mirrors the step-4 spawn-failure + step-6 supervise paths.
                kill_all(&mut children);
                return Err(err(format!("installing the root self-profile: {e}")));
            }
        };
        tracing::info!(
            ?status,
            seccomp_allow = profile.seccomp_allow.len(),
            seccomp_kill = profile.seccomp_kill.len(),
            ro = profile.policy.read_only_paths.len(),
            "[privsep] root: self-profile installed + ENFORCED (TCB floor — no network, no \
             key-lock; execve Landlock-pinned to the root's own binary)"
        );

        // 6. Supervise, fail-closed: any child exit tears the whole node down (crown-jewel
        //    `FailNodeClosed`, the Phase-1 policy — serving with a hole is worse than not serving).
        tracing::info!(
            instances = children.len(),
            "[privsep] root: all instances spawned + wired; supervising (any exit ⇒ FailNodeClosed)"
        );
        loop {
            // Detect the first child that exited (or a wait error) WITHOUT holding a borrow of
            // `children` across the teardown (which also borrows it mutably).
            let mut outcome: Result<Option<String>, (String, String)> = Ok(None);
            for (label, child) in &mut children {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        outcome = Ok(Some(format!("instance {label:?} exited ({status})")));
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        outcome = Err((label.clone(), e.to_string()));
                        break;
                    }
                }
            }
            match outcome {
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(200)),
                Ok(Some(reason)) => {
                    kill_all(&mut children);
                    return Err(err(format!(
                        "{reason} — FailNodeClosed: tearing the node down rather than serving with \
                         a hole"
                    )));
                }
                Err((label, e)) => {
                    kill_all(&mut children);
                    return Err(err(format!("waiting on instance {label:?}: {e}")));
                }
            }
        }
    }

    /// SIGKILL + reap every supervised child (fail-closed teardown).
    fn kill_all(children: &mut [(String, std::process::Child)]) {
        for (_, child) in children.iter_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(not(unix))]
mod supervise {
    use std::path::Path;

    use super::{PrivsepError, RootPlan, ServerConfig};

    pub(super) fn run(
        _config: &ServerConfig,
        _plan: &RootPlan,
        _config_path: &Path,
    ) -> Result<(), PrivsepError> {
        // The root wiring needs `socketpair`/`fork`/`SCM_RIGHTS` (Unix); privsep is Linux-only in
        // Phase 1, and the caller already refused a non-Linux/`sandbox`-less build before reaching
        // here. This stub keeps the crate building on non-Unix.
        Err(PrivsepError::UnsupportedPlatform)
    }
}

// =============================================================================
// The feature-instance serving splice (WS-C): accept + fd-pass (frontend) / recv + serve (backend)
// =============================================================================

#[cfg(unix)]
mod instance_serve {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::SocketAddr;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::sync::Arc;

    use boatramp_core::cose::{Signer, TokenPublicKey};
    use boatramp_core::privsep::HostAuthority;
    use boatramp_server::privsep_authority::{
        AuthorityAudit, AuthorityRateLimiter, AuthorityRegistry, AuthorityServe, ContextVerifier,
        DEFAULT_CONTEXT_MAX_AGE_SECS, DEFAULT_LINK_READ_DEADLINE, DEFAULT_MAX_IN_FLIGHT,
        DurableAudit, FileRevocationList, PreVerifyThrottle, ReplayCache, RevocationCheck,
        SealerHandler, SignerHandler, SourceBucketThrottle, TokenBucketLimiter,
    };
    use boatramp_server::privsep_link::LinkEndpoint;
    use boatramp_server::privsep_tenant::{
        RouteOutcome, WiredTenantIdentity, route_by_host, routing_head, scope_backend_call,
    };
    use boatramp_server::privsep_unseal::{
        EnvelopeSealedFileResolver, SealedKeyResolver, UnsealAllowlist,
    };

    use super::per_tenant::{ComputePlaneRegistry, set_cloexec};
    use super::{
        MaterializationGate, PrivsepChildFds, ServerConfig, authority_serve_links_from_env,
        privsep_resolve,
    };

    /// Serve one instance's slice over its root-wired fds (design §2.1 steps 5-6). The Phase-1
    /// minimal-but-real path. Roles, dispatched from the instance's capability set + its wired fds:
    /// - a SIGNER (`token.signer` with a `[serve.signer] = Sealed` source) UNLOCKS its signing key
    ///   first — it asks the `secrets.sealer` to unseal it over the feature-link (or resolves it
    ///   in-process if it co-resides the sealer), builds the signer, verifies it works, then holds
    ///   it inert (its mint grammar is WS-E). A failed unlock EXITS → `FailNodeClosed`;
    /// - a SEALER (`secrets.sealer` with a root-wired unseal allowlist) SERVES unseal requests on
    ///   each allowlisted link, enforcing the allowlist fail-closed;
    /// - a `listen.*` FRONTEND (has a listener fd) ACCEPTS on the inherited listener and splices each
    ///   accepted CLIENT connection fd to the backend over the local link (`SCM_RIGHTS`);
    /// - a BACKEND (has a client-fd link, no listener) RECEIVES those client fds and serves each with
    ///   the hand-rolled HTTP stack (the full authority-scoped app router is the authority-serve
    ///   follow-on);
    /// - any other instance holds its authorities inert and parks.
    pub(super) fn run(
        label: &str,
        gate: &MaterializationGate,
        fds: &PrivsepChildFds,
        config: &ServerConfig,
        config_path: &Path,
    ) -> Result<(), String> {
        let allowlist = UnsealAllowlist::from_env()?;
        let authority_links = authority_serve_links_from_env()?;
        let signer_key_ref = privsep_resolve::sealed_signer_key_ref(config);
        // Phase-4 WS-C opt-in triggers (derived from the resolved on-disk composition — restart-class):
        //   is_template  ⇒ THIS instance is a per-tenant template the router spawned on demand;
        //   has_template ⇒ the composition defines ANY per-tenant template, so the listener holder is
        //                   the per-tenant ROUTER rather than a plain splice frontend.
        // Both are false for a no-template composition, so every pre-Phase-4 path below is UNCHANGED.
        let privsep = config.privsep.as_ref();
        let is_template = privsep
            .and_then(|p| p.instances.get(label))
            .is_some_and(|i| i.lifecycle.is_per_tenant_template());
        let has_template = privsep.is_some_and(|p| {
            p.instances
                .values()
                .any(|i| i.lifecycle.is_per_tenant_template())
        });
        tracing::info!(
            instance = %label,
            held = gate.held().count(),
            links = fds.links.len(),
            listener = fds.listener.is_some(),
            sealer = gate.may_materialize(HostAuthority::SecretsSealer),
            signer = gate.may_materialize(HostAuthority::TokenSigner),
            unseal_allowlist_links = allowlist.by_link.len(),
            authority_serve_links = authority_links.len(),
            "[privsep] instance: opening its root-wired links + serving its slice"
        );

        // SIGNER-key unlock FIRST (fail-closed): a `token.signer` instance with a sealed source must
        // obtain + verify its key before anything serves. A failure here exits the instance → the
        // root's FailNodeClosed tears the node down rather than serving with a dead signer. The
        // unlocked signer is KEPT if this instance will serve the WS-E mint grammar (below); otherwise
        // it is dropped and the signer holds its authority inert.
        let unlocked_signer: Option<Arc<dyn Signer>> = if gate
            .may_materialize(HostAuthority::TokenSigner)
            && let Some(key_ref) = signer_key_ref
        {
            Some(run_signer_unlock(label, gate, fds, config, key_ref)?)
        } else {
            None
        };

        // WS-E AUTHORITY-API GRAMMAR SERVE (this wave): a crown-jewel instance the root designated
        // authority-serve links for serves seal/unseal (sealer) + mint_token (signer) over those links,
        // re-validating each call's end-principal context. Empty designation (every Phase-1
        // composition) ⇒ this is skipped and the crown jewel holds its grammar inert (parks), exactly
        // as before this wave — so the Phase-1 live tests are unchanged.
        let is_crown = gate.may_materialize(HostAuthority::SecretsSealer)
            || gate.may_materialize(HostAuthority::TokenSigner);
        if is_crown && !authority_links.is_empty() {
            return run_authority_serve(
                label,
                gate,
                fds,
                config,
                &allowlist,
                &authority_links,
                unlocked_signer,
            );
        }

        // A signer that unlocked but serves no WS-E grammar holds its (unlocked) authority inert.
        if unlocked_signer.is_some() {
            tracing::info!(instance = %label, "[privsep] signer: key unlocked + verified; holding it inert (no authority-serve link designated)");
            park();
        }

        // SEALER: serve unseal requests on each allowlisted link, fail-closed.
        if gate.may_materialize(HostAuthority::SecretsSealer) && !allowlist.is_empty() {
            return run_sealer(label, fds, config, &allowlist);
        }

        // PER-TENANT TEMPLATE BACKEND (WS-C step 4): THIS instance was instantiated on demand by the
        // router for one tenant. It establishes its UNFORGEABLE wired tenant identity from the
        // root/router-set `BOATRAMP_PRIVSEP_TENANT_SCOPE` (fail-closed if absent/invalid — an instance
        // that cannot prove its own tenant must not serve) and serves received client fds, scoping
        // every backend call by that identity (never a guest-named tenant). Only fires for a
        // per-tenant template, so a no-template composition never reaches it.
        if is_template {
            return run_per_tenant_backend(label, fds);
        }

        if let Some(listener_fd) = fds.listener {
            let link_fd = *fds.links.values().next().ok_or_else(|| {
                "a listener instance has no feature-link to forward client connections over \
                 (the composition must link it to a backend)"
                    .to_string()
            })?;
            // PER-TENANT PARSER (WS-D Finding-2): when the composition defines a per-tenant template,
            // the public-listener holder is the pure-forward PARSER. It holds NEITHER `backend.kv`
            // NOR `exec.compute` (the composition-closure lint refuses co-locating them on a
            // `listen.http-parse` instance), so it cannot resolve Host→project or fork a tenant
            // itself — it peeks the Host (its job as the http-parse holder) and forwards each accepted
            // client fd + the peeked Host inward to the non-public SUPERVISOR over the link. The
            // resolve + spawn live OFF the public parser (design `DESIGN-wsd.md`). Opt-in: fires ONLY
            // with a template.
            if has_template {
                return run_per_tenant_parser(label, listener_fd, link_fd);
            }
            run_frontend(label, listener_fd, link_fd)
        } else if has_template && gate.may_materialize(HostAuthority::ExecCompute) {
            // PER-TENANT SUPERVISOR (WS-D Finding-2): the non-public backend holding `backend.kv` +
            // `exec.compute`. It binds no listener and parses no raw client bytes; it RECEIVES client
            // fds + the peeked Host over the parser link, re-resolves Host→project against the
            // control-plane KV (authoritative), instantiates / wakes the per-tenant `exec.wasmtime`
            // child (fork), and relays the client fd onward. This is the half the parser's spawn + KV
            // authority was split onto.
            run_per_tenant_supervisor(label, gate, fds, config, config_path)
        } else if let Some((lname, link_fd)) = fds.links.iter().next() {
            run_backend(label, lname, *link_fd)
        } else {
            tracing::info!(
                instance = %label,
                "[privsep] instance: no listener/link to serve in the Phase-1 cut — holding its \
                 authorities inert (its authority-API grammar over the link is WS-E)"
            );
            park()
        }
    }

    /// Park forever (an instance whose authorities are held inert in the Phase-1 cut). Never returns.
    fn park() -> ! {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    /// Build the `secrets.sealer` instance's `[secrets]` KEK envelope (`LocalKek` from `kek_file`, the
    /// only envelope legal under `[privsep]` — the Vault envelope reads a live token the root may not
    /// courier, refused by the secret-blind screen). The kek_file is `[secrets].kek_file` or the
    /// `<data_dir>/secrets/kek` default — in the sealer's Landlock grant (`secrets.sealer` holds it).
    fn build_secrets_envelope(
        config: &ServerConfig,
    ) -> Result<Arc<dyn boatramp_core::envelope::KeyEnvelope>, String> {
        use boatramp_server::envelope::{EnvelopeSpec, build_envelope};
        let data_dir = {
            let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
            super::normalized_data_dir(config, &cwd)
        };
        let kek_file = config
            .secrets
            .as_ref()
            .and_then(|s| s.kek_file.clone())
            .unwrap_or_else(|| data_dir.join("secrets/kek"));
        build_envelope(EnvelopeSpec::Local { kek_file })
            .map_err(|e| format!("building the [secrets] KEK envelope: {e}"))?
            .ok_or_else(|| {
                "the [secrets] KEK envelope resolved to none (expected a local KEK)".to_string()
            })
    }

    /// Build the sealer's [`SealedKeyResolver`] for `key_ref`. Phase-1 cut: a `path:<file>` KEK-sealed
    /// key blob is resolved via the `[secrets]` KEK envelope (the live form). A `boatramp:<name>`
    /// sealed-STORE ref needs the control-plane KV, whose lifecycle belongs to the authority-scoped
    /// backend serve (the follow-on) — building it here would double-open the single-writer store —
    /// so it is refused fail-closed at runtime (the `SecretStoreResolver` is implemented + unit-tested
    /// and wires in with that follow-on).
    fn build_sealer_resolver(
        config: &ServerConfig,
        key_ref: &str,
    ) -> Result<Arc<dyn SealedKeyResolver>, String> {
        if key_ref.starts_with("path:") {
            let envelope = build_secrets_envelope(config)?;
            Ok(Arc::new(EnvelopeSealedFileResolver::new(envelope)))
        } else if key_ref.starts_with("boatramp:") {
            Err(format!(
                "sealed-store signer key {key_ref:?} resolution in the sealer needs the \
                 control-plane KV (owned by the authority-scoped backend serve — a follow-on); use \
                 a `path:<file>` KEK-sealed key under [privsep] Phase 1"
            ))
        } else {
            Err(format!(
                "unsupported sealed signer reference {key_ref:?} (want `boatramp:<name>` or `path:<file>`)"
            ))
        }
    }

    /// A `token.signer` instance: UNLOCK its sealed signing key, then prove it works. If this instance
    /// also holds `secrets.sealer` (co-resident), resolve the key IN-PROCESS (it holds the KEK); else
    /// ask the sealer to unseal it over the single feature-link (`request_unseal`). Then build a
    /// [`boatramp_core::cose::LocalSigner`] and run a sign+verify self-test (the key is live + usable).
    /// Returns the unlocked [`Signer`] so a WS-E `mint_token` grammar can be served off it (the signing
    /// key stays in this instance — it is NEVER representable in any authority response). Fail-closed:
    /// any error returns `Err` → the instance exits → FailNodeClosed.
    fn run_signer_unlock(
        label: &str,
        gate: &MaterializationGate,
        fds: &PrivsepChildFds,
        config: &ServerConfig,
        key_ref: &str,
    ) -> Result<Arc<dyn Signer>, String> {
        use boatramp_core::cose::LocalSigner;

        // Obtain the plaintext key spec (`"<alg>:<hex>"`), held zeroizing (both arms return the
        // `Zeroizing<Vec<u8>>` from the resolver / the unseal client).
        let spec_bytes = if gate.may_materialize(HostAuthority::SecretsSealer) {
            // Co-resident signer+sealer: resolve in-process (it holds the KEK) — no link.
            tracing::info!(instance = %label, "[privsep] signer: co-resident with the sealer — resolving its key in-process");
            let resolver = build_sealer_resolver(config, key_ref)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("building a runtime for in-process unseal: {e}"))?;
            rt.block_on(resolver.resolve(key_ref))?
        } else {
            // Split signer: ask the sealer over its SEALER link, selected EXPLICITLY by purpose (WS-E
            // residual #5) — NEVER a blind `.next()`, now that the signer also gains WS-E
            // minting-consumer links. Fail-closed if absent/ambiguous.
            let (lname, link_fd) = super::select_sealer_link(config, label, &fds.links)?;
            tracing::info!(instance = %label, link = %lname, "[privsep] signer: asking the sealer to unseal its signing key over the explicitly-selected sealer link");
            // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the fd map.
            let link = unsafe { LinkEndpoint::from_inherited_fd(link_fd) };
            boatramp_server::privsep_unseal::request_unseal(&link, key_ref)
                .map_err(|e| format!("unsealing the signing key over the link: {e}"))?
        };

        // The unsealed bytes are a `"<alg>:<hex>"` signer spec.
        let spec = std::str::from_utf8(&spec_bytes).map_err(|_| {
            "the unsealed signer key is not valid UTF-8 (expected `<alg>:<hex>`)".to_string()
        })?;
        // Generic parse error — never interpolate the parser's message: on a malformed-but-
        // KEK-unsealed key (operator error) `from_private_hex`/`split_tagged` can echo a tag or
        // hex fragment of the plaintext key, which must not reach the node log (Security INFO).
        let signer = LocalSigner::from_private_hex(spec).map_err(|_| {
            "the unsealed signing key failed to parse (expected `<alg>:<hex>`)".to_string()
        })?;

        // Self-test: sign + verify a fixed message so a bad/wrong key fails NOW (fail-closed), not at
        // first mint. Proves the unlocked key is live and usable end-to-end.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("building a runtime for the signer self-test: {e}"))?;
        const SELF_TEST: &[u8] = b"privsep signer-key unlock self-test";
        let sig = rt
            .block_on(signer.sign(SELF_TEST))
            .map_err(|e| format!("signing the self-test with the unlocked key: {e}"))?;
        signer.public_key().verify(SELF_TEST, &sig).map_err(|e| {
            format!("verifying the self-test signature (the unlocked key is bad): {e}")
        })?;

        // The marker the live gate greps: only reached after a real unseal + a live sign/verify.
        tracing::info!(instance = %label, "[privsep] PRIVSEP SIGNER UNSEAL OK");
        Ok(Arc::new(signer))
    }

    /// Resolve the PUBLIC control-plane trust root used to re-validate relayed end-principal contexts
    /// (design §3.4 F3 / clarification 4 — a public verifying key, never a secret). Prefers the
    /// explicit `serve.auth_root_public_key`; falls back to the unlocked signer's own public key (a
    /// `token.signer` IS the control-plane auth root, so its public half is the trust anchor). A split
    /// `secrets.sealer` that holds no signer MUST have `auth_root_public_key` configured — else it
    /// cannot verify contexts and refuses to serve the grammar (fail-closed).
    fn resolve_trust_root(
        config: &ServerConfig,
        unlocked_signer: Option<&Arc<dyn Signer>>,
    ) -> Result<TokenPublicKey, String> {
        if let Some(hex) = config
            .serve
            .as_ref()
            .and_then(|s| s.auth_root_public_key.as_ref())
        {
            return TokenPublicKey::from_hex(hex).map_err(|e| {
                format!("parsing serve.auth_root_public_key for the WS-E verifier: {e}")
            });
        }
        if let Some(signer) = unlocked_signer {
            return Ok(signer.public_key());
        }
        Err("no public trust root to re-validate authority-call contexts: set \
             serve.auth_root_public_key (a split secrets.sealer that holds no token.signer needs it)"
            .to_string())
    }

    /// The receiver's wall-clock (Unix seconds) for context freshness + minted-token stamping.
    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Serve the WS-E **authority-API grammar** for a crown-jewel instance on each root-designated
    /// authority-serve link (design §2.1 steps 5-6 / §3.4). Builds the per-capability registry
    /// (`secrets.sealer` ⇒ [`SealerHandler`] over its `[secrets]` KEK envelope; `token.signer` ⇒
    /// [`SignerHandler`] over the unlocked signer), the context verifier (re-validating every relayed
    /// end-principal credential against the public trust root, with the tightened freshness bound), a
    /// shared anti-replay cache + a global in-flight concurrency cap, and serves [`AuthorityServe`] on
    /// one blocking thread per link (the link I/O is blocking). A co-resident `secrets.sealer` that
    /// ALSO has a bootstrap-unseal allowlist serves that too (the two grammars are distinct links/code
    /// paths — the bootstrap unseal is instance-authorized by the root-wired allowlist, the WS-E
    /// grammar is end-principal-authorized by the verified context; both fail-closed). After the serve
    /// threads end (peers gone) the instance parks (its remaining authorities inert). Fail-closed: a
    /// missing trust root / handler / link fd returns `Err` → the instance exits → FailNodeClosed.
    ///
    /// **CODE-FAIL-CLOSED STAND-UP GATE (Security re-review).** Before building ANYTHING, this hard-
    /// refuses to stand up a live authority serve unless the wiring-gate preconditions
    /// ([`check_authority_serve_preconditions`]) are met — a PoP/`cnf` verifier configured AND the
    /// link explicitly purpose-marked. Neither mechanism exists until Phase 3, so today this ALWAYS
    /// refuses: the whole authority API (signer `mint_token` included — it has no `sub` dependency so
    /// it would otherwise serve LIVE without PoP, leaving the re-mint chain reachable) is CODE-inert,
    /// symmetric with the sealer's per-identity fail-closed, not merely convention-inert. A composition
    /// that designates an authority-serve link therefore FAILS THE NODE CLOSED (loud misconfig signal)
    /// rather than serving a PoP-less live grammar. The two Phase-1 compositions designate no link
    /// (empty [`compute_authority_serve_links`]) so they never reach this path.
    fn run_authority_serve(
        label: &str,
        gate: &MaterializationGate,
        fds: &PrivsepChildFds,
        config: &ServerConfig,
        allowlist: &UnsealAllowlist,
        authority_links: &std::collections::BTreeSet<String>,
        unlocked_signer: Option<Arc<dyn Signer>>,
    ) -> Result<(), String> {
        // Hard code gate FIRST — fail closed before building the verifier / registry / any serve.
        super::check_authority_serve_preconditions(config).map_err(|e| {
            format!(
                "[privsep] instance {label:?}: refusing to stand up a live authority serve — {e}"
            )
        })?;
        let trust_root = resolve_trust_root(config, unlocked_signer.as_ref())?;

        // Build the per-capability registry from the held crown jewels.
        let mut registry = AuthorityRegistry::new();
        if gate.may_materialize(HostAuthority::SecretsSealer) {
            let envelope = build_secrets_envelope(config)?;
            registry.register(
                HostAuthority::SecretsSealer,
                Arc::new(SealerHandler::new(envelope)),
            )?;
        }
        if gate.may_materialize(HostAuthority::TokenSigner) {
            let signer = unlocked_signer.ok_or_else(|| {
                "a token.signer WS-E serve needs its unlocked signing key, but none was unlocked \
                 (expected a `[serve.signer] = Sealed` source)"
                    .to_string()
            })?;
            // The handler's context-freshness max-age matches the verifier's default below, so a
            // minted token's TTL binds to the context's REMAINING freshness (MEDIUM-1).
            registry.register(
                HostAuthority::TokenSigner,
                Arc::new(SignerHandler::new(signer, DEFAULT_CONTEXT_MAX_AGE_SECS)),
            )?;
        }
        if registry.is_empty() {
            return Err(
                "a crown-jewel instance was designated WS-E authority-serve links but registered no \
                 handler (no secrets.sealer / token.signer held)"
                    .to_string(),
            );
        }
        let registry = Arc::new(registry);
        let verifier = ContextVerifier::new(trust_root);
        let replay = Arc::new(ReplayCache::with_defaults());
        let max_in_flight = Arc::new(tokio::sync::Semaphore::new(DEFAULT_MAX_IN_FLIGHT));
        // Phase-2 HARDENING (tasks #2/#3): the PRODUCTION limiter + durable audit sink replace the
        // Wave-1 defaults (`Unlimited` / `TracingAudit`). One shared instance per crown jewel, cloned
        // into each link thread. The append-only audit log lives in this instance's OWN data subtree;
        // the composition's sandbox profile must grant the crown jewel WRITE here and deny the relay
        // any access (the sink is write-only from the caller's view). Opening it fails the stand-up
        // closed if the path is not writable (an audit the caller could evade is not an audit).
        let audit: Arc<dyn AuthorityAudit> = {
            let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
            let path = super::normalized_data_dir(config, &cwd)
                .join("privsep")
                .join("authority-audit.jsonl");
            Arc::new(DurableAudit::open(&path).map_err(|e| {
                format!("opening the durable authority audit sink at {path:?}: {e}")
            })?)
        };
        let limiter: Arc<dyn AuthorityRateLimiter> = Arc::new(TokenBucketLimiter::with_defaults());
        // WS-E residual #2: a shared PRE-VERIFY flood throttle keyed on the cheap link/source, checked
        // BEFORE the expensive `cose::verify` so a forged-context flood on one link cannot exhaust CPU
        // (per-source + global token buckets; cloned into each link thread, so the global cap bounds
        // total verify load across all of this crown jewel's authority-serve links).
        let pre_verify: Arc<dyn PreVerifyThrottle> =
            Arc::new(SourceBucketThrottle::with_defaults());
        // WS-E residual #3: the revocation feed. The KV-blind crown jewel reads a PROJECTION of the
        // control-plane `authz/revoked/<cti>` markers from a file in its OWN data subtree (delivered
        // out-of-band — who projects it + the cadence is the owner/ops design, FLAGGED for Security;
        // delivery MUST be atomic). Absent file ⇒ no revocations (matches absent-marker ⇒ not-revoked);
        // present-but-unreadable ⇒ the serve refuses fail-closed. A composition wanting the explicit
        // Phase-1 residual (no feed) can drop a `NoRevocation`; the default wiring is the file feed.
        let revocation: Arc<dyn RevocationCheck> = {
            let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
            let path = super::normalized_data_dir(config, &cwd)
                .join("privsep")
                .join("revoked.json");
            Arc::new(FileRevocationList::at(path))
        };
        tracing::info!(
            instance = %label,
            served = ?registry.served().iter().map(|a| a.tag()).collect::<Vec<_>>(),
            links = authority_links.len(),
            "[privsep] crown jewel: serving the WS-E authority-API grammar (context-re-validated, fail-closed)"
        );

        let mut threads = Vec::new();

        // (a) A co-resident sealer with a bootstrap-unseal allowlist also serves that (distinct links).
        if gate.may_materialize(HostAuthority::SecretsSealer) && !allowlist.is_empty() {
            let any_name = allowlist
                .by_link
                .values()
                .flat_map(|s| s.iter())
                .next()
                .cloned();
            if let Some(any_name) = any_name {
                let resolver = build_sealer_resolver(config, &any_name)?;
                for (link_name, allowed) in &allowlist.by_link {
                    if allowed.is_empty() {
                        continue;
                    }
                    let Some(link_fd) = fds.links.get(link_name).copied() else {
                        return Err(format!(
                            "the unseal allowlist names link {link_name:?}, but the root wired no \
                             such link fd to this instance"
                        ));
                    };
                    let (link_name, allowed, resolver, label) = (
                        link_name.clone(),
                        allowed.clone(),
                        resolver.clone(),
                        label.to_string(),
                    );
                    threads.push(std::thread::spawn(move || {
                        // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the map.
                        let link = unsafe { LinkEndpoint::from_inherited_fd(link_fd) };
                        serve_blocking_unseal(
                            &label,
                            &link_name,
                            &link,
                            &allowed,
                            resolver.as_ref(),
                        );
                    }));
                }
            }
        }

        // (b) The WS-E grammar on each designated authority-serve link (one blocking thread per link).
        for link_name in authority_links {
            let Some(link_fd) = fds.links.get(link_name).copied() else {
                return Err(format!(
                    "the WS-E authority-serve designation names link {link_name:?}, but the root \
                     wired no such link fd to this instance"
                ));
            };
            let (link_name, label) = (link_name.clone(), label.to_string());
            let registry = registry.clone();
            let verifier = verifier.clone();
            let replay = replay.clone();
            let max_in_flight = max_in_flight.clone();
            let limiter = limiter.clone();
            let pre_verify = pre_verify.clone();
            let revocation = revocation.clone();
            let audit = audit.clone();
            threads.push(std::thread::spawn(move || {
                // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the fd map.
                let link = unsafe { LinkEndpoint::from_inherited_fd(link_fd) };
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(instance = %label, link = %link_name, error = %e, "[privsep] authority serve: runtime build failed");
                        return;
                    }
                };
                // Phase-2 HARDENING: the PRODUCTION token-bucket limiter + durable append-only audit
                // sink + the pre-verify flood throttle (all shared across links, cloned in above) —
                // the Wave-1 defaults are gone.
                let serve = AuthorityServe {
                    verifier: &verifier,
                    pre_verify: pre_verify.as_ref(),
                    replay: &replay,
                    revocation: revocation.as_ref(),
                    limiter: limiter.as_ref(),
                    audit: audit.as_ref(),
                    handler: registry.as_ref(),
                    max_in_flight: &max_in_flight,
                    read_deadline: DEFAULT_LINK_READ_DEADLINE,
                };
                if let Err(e) = rt.block_on(serve.serve(&link_name, &link, now_unix)) {
                    tracing::error!(instance = %label, link = %link_name, error = %e, "[privsep] authority serve ended with an error");
                }
            }));
        }

        for t in threads {
            let _ = t.join();
        }
        park()
    }

    /// Drive one bootstrap-unseal serve loop to completion on a current-thread runtime (the helper the
    /// WS-E crown-jewel serve reuses for a co-resident sealer's allowlisted links).
    fn serve_blocking_unseal(
        label: &str,
        link_name: &str,
        link: &LinkEndpoint,
        allowed: &std::collections::BTreeSet<String>,
        resolver: &dyn SealedKeyResolver,
    ) {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(instance = %label, link = %link_name, error = %e, "[privsep] sealer: runtime build failed");
                return;
            }
        };
        tracing::info!(instance = %label, link = %link_name, "[privsep] sealer: serving bootstrap unseal (fail-closed allowlist) alongside the WS-E grammar");
        if let Err(e) = rt.block_on(boatramp_server::privsep_unseal::serve_unseal(
            link_name, link, allowed, resolver,
        )) {
            tracing::error!(instance = %label, link = %link_name, error = %e, "[privsep] sealer: unseal serve ended with an error");
        }
    }

    /// A `secrets.sealer` instance: serve unseal requests on each root-wired allowlisted link,
    /// enforcing the allowlist fail-closed (a request for a name not on a link's allowlist is refused,
    /// logged, no bytes). One blocking serve thread per allowlisted link; after they end (peers gone)
    /// the instance holds its remaining authorities inert and parks.
    fn run_sealer(
        label: &str,
        fds: &PrivsepChildFds,
        config: &ServerConfig,
        allowlist: &UnsealAllowlist,
    ) -> Result<(), String> {
        // One envelope-backed resolver, shared across the per-link serve threads. The resolver is
        // scheme-dispatched per request by `key_ref`; the allowlist has already been built from the
        // signer key ref, so build the resolver for whichever scheme those names use.
        let any_name = allowlist
            .by_link
            .values()
            .flat_map(|s| s.iter())
            .next()
            .cloned()
            .ok_or_else(|| "sealer has an empty unseal allowlist (nothing to serve)".to_string())?;
        let resolver = build_sealer_resolver(config, &any_name)?;

        let mut threads = Vec::new();
        for (link_name, allowed) in &allowlist.by_link {
            if allowed.is_empty() {
                continue;
            }
            let Some(link_fd) = fds.links.get(link_name).copied() else {
                return Err(format!(
                    "the unseal allowlist names link {link_name:?}, but the root wired no such link \
                     fd to this sealer instance"
                ));
            };
            let link_name = link_name.clone();
            let allowed = allowed.clone();
            let resolver = resolver.clone();
            let label = label.to_string();
            threads.push(std::thread::spawn(move || {
                // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the fd map.
                let link = unsafe { LinkEndpoint::from_inherited_fd(link_fd) };
                let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(instance = %label, link = %link_name, error = %e, "[privsep] sealer: runtime build failed");
                        return;
                    }
                };
                tracing::info!(instance = %label, link = %link_name, allowed = ?allowed, "[privsep] sealer: serving unseal requests (fail-closed allowlist)");
                if let Err(e) = rt.block_on(boatramp_server::privsep_unseal::serve_unseal(
                    &link_name, &link, &allowed, resolver.as_ref(),
                )) {
                    tracing::error!(instance = %label, link = %link_name, error = %e, "[privsep] sealer: unseal serve ended with an error");
                }
            }));
        }
        tracing::info!(instance = %label, serve_links = threads.len(), "[privsep] sealer: unseal servers up; holding its other authorities inert");
        for t in threads {
            let _ = t.join();
        }
        // The signer(s) got their key(s) and hold the link(s); the sealer parks (its other authorities
        // are inert in the Phase-1 cut).
        park()
    }

    /// A `listen.*` frontend: accept on the inherited listener fd and splice each accepted client
    /// connection fd to the backend over the local link. Phase-1 raw-splice ⇒ an EMPTY parsed head
    /// (the frontend forwards the raw accepted socket; request-head parsing + the typed grammar are
    /// WS-E). Blocking — the frontend needs no Tokio runtime (it forwards fds, never serves bytes).
    fn run_frontend(label: &str, listener_fd: i32, link_fd: i32) -> Result<(), String> {
        // SAFETY: `listener_fd`/`link_fd` are the fds the root dup'd into this child + named in the
        // fd map; this instance owns them exclusively.
        let listener = unsafe { std::net::TcpListener::from_raw_fd(listener_fd) };
        let link = unsafe { LinkEndpoint::from_inherited_fd(link_fd) };
        tracing::info!(
            instance = %label,
            "[privsep] frontend: accepting on the inherited listener fd; splicing client fds to the \
             backend over the local link (SCM_RIGHTS, unidirectional)"
        );
        loop {
            let (conn, _peer) = listener
                .accept()
                .map_err(|e| format!("accepting on the listener: {e}"))?;
            // Pass the ACCEPTED CLIENT fd to the backend — the ONLY fd that ever crosses a link
            // (never a link/listener/key fd; design F5).
            link.send_client_conn(conn.as_fd(), &[])
                .map_err(|e| format!("splicing a client connection over the link: {e}"))?;
            // Drop our copy (SCM_RIGHTS duplicated the fd) so ONLY the backend serves it.
            drop(conn);
        }
    }

    /// A backend: receive the frontend's spliced client fds over the local link and serve each with
    /// the hand-rolled HTTP stack. The received fd is treated as opaque CLIENT bytes conferring no
    /// authority (design F5). A dedicated blocking thread drains the link (the link I/O is
    /// blocking) and feeds a Tokio consumer that serves each connection.
    fn run_backend(label: &str, link_name: &str, link_fd: i32) -> Result<(), String> {
        // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the fd map.
        let link = unsafe { LinkEndpoint::from_inherited_fd(link_fd) };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("building the Tokio runtime: {e}"))?;
        tracing::info!(
            instance = %label,
            link = %link_name,
            "[privsep] backend: receiving client fds over the local link; serving each with the \
             hand-rolled HTTP stack"
        );
        rt.block_on(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<OwnedFd>(64);
            // Blocking link-drain on a dedicated thread (recv is blocking); it hands each received
            // client fd to the async consumer. EOF/err ends the loop (the frontend went away).
            let drain = std::thread::spawn(move || {
                loop {
                    match link.recv_client_conn() {
                        Ok((fd, _head)) => {
                            if tx.blocking_send(fd).is_err() {
                                break; // the consumer is gone
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "[privsep] backend: link recv ended");
                            break;
                        }
                    }
                }
            });
            while let Some(fd) = rx.recv().await {
                tokio::spawn(serve_client_fd(fd));
            }
            let _ = drain.join();
        });
        Ok(())
    }

    /// Serve one received client connection with the hand-rolled HTTP/1+2 stack (the same
    /// `boatramp_http::serve_connection` the monolith's `serve_router_conn` wraps) + a minimal
    /// handler. The full authority-scoped app router is the self-host serve follow-on: the typed
    /// [`NodeServeHandler`] seam (P5-1, design §Phase-5) is the drop-in that replaces
    /// [`MinimalHandler`] here once P5-2 wires a real surface. Today — behind the unwired self-host
    /// path ([`super::check_node_self_host_gate`] refuses `node-self-host`) — this stays the stub.
    async fn serve_client_fd(fd: OwnedFd) {
        let std_stream = std::net::TcpStream::from(fd);
        if let Err(e) = std_stream.set_nonblocking(true) {
            tracing::debug!(error = %e, "[privsep] backend: set_nonblocking on a client fd");
            return;
        }
        let peer = std_stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let stream = match tokio::net::TcpStream::from_std(std_stream) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "[privsep] backend: adopting a client fd into Tokio");
                return;
            }
        };
        if let Err(e) = boatramp_http::serve_connection(stream, MinimalHandler).await {
            tracing::debug!(%peer, error = %e, "[privsep] backend: connection served with error");
        }
    }

    /// The Phase-1 minimal backend handler: a fixed 200. It proves the end-to-end byte path
    /// (client → frontend listener fd → SCM_RIGHTS splice → backend → hand-rolled HTTP → response)
    /// with the sandbox enforced in both instances. The authority-scoped app router is a follow-on:
    /// the [`NodeServeHandler`] seam (P5-1) is introduced below and swapped in here by P5-2 (it keeps
    /// the identical stub body in the unwired cut, so wiring it changes the serve, not the byte path).
    struct MinimalHandler;

    impl boatramp_http::Handler for MinimalHandler {
        async fn handle(&self, _req: boatramp_http::Request) -> boatramp_http::Response {
            boatramp_http::response(
                200,
                b"boatramp privsep backend instance (Phase 1 minimal serve)\n".to_vec(),
            )
        }
    }

    // =========================================================================
    // P5-1: the authority-scoped node app-router SEAM (design §Phase-5 P5-1)
    // =========================================================================
    //
    // This is the typed seam that REPLACES `MinimalHandler` when a `backend.*` / authority instance
    // serves the node's OWN serve path (`node_serve = node-self-host`). It is introduced BEHIND the
    // still-unwired self-host path: the root gate (`check_node_self_host_gate`) refuses `NodeSelfHost`
    // fail-closed, `NodeServeMode::is_wired(NodeSelfHost)` is still false, and the live
    // `serve_client_fd` above still serves the `MinimalHandler` stub. P5-1 proves the ROUTER SHAPE +
    // the "construct-only-what-you-hold" discipline (design §4 item 5) host-side; P5-2 derives the
    // reachability map from the live link topology, classifies each request into its serve surface,
    // executes each route, and swaps this handler in. NOTHING here runs live.

    /// The routing decision the node app-router makes for one serve surface, identified by the
    /// [`HostAuthority`] that surface needs (design §Phase-5 P5-1, §4 item 5). It encodes the
    /// materialization-by-construction discipline structurally: a surface whose authority this
    /// instance HOLDS is served LOCALLY (the instance may construct that authority object —
    /// [`MaterializationGate::ensure`] passes); every other surface is RELAYED over the instance's
    /// root-wired link to the peer that holds the authority (a crown-jewel WS-E grammar for a group-A
    /// authority, else a typed backend request); a surface whose authority is NEITHER held NOR
    /// reachable over any wired link is REFUSED fail-closed (a composition-closure bug, never a
    /// degraded serve — the node fails closed).
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
    pub(super) enum NodeRoute {
        /// Serve LOCALLY: this instance HOLDS the authority, so it constructs and uses the authority
        /// object in-process (materialization-by-construction — never a dropped authority).
        Local(HostAuthority),
        /// RELAY to a crown-jewel (group A) holder over the named WS-E authority-grammar link: a
        /// bounded `AuthorityCall` with a re-validated end-principal context (results, never keys).
        RelayCrownJewel {
            authority: HostAuthority,
            link: String,
        },
        /// RELAY to a data-holder / control peer over the named backend feature-link: a typed request
        /// the peer serves against its OWN held credential (any non-crown-jewel holder — group B
        /// `backend.*`, group D `exec.*`, group E `control.*`/`acme.*`).
        RelayBackend {
            authority: HostAuthority,
            link: String,
        },
        /// REFUSE fail-closed: the surface's authority is neither HELD nor reachable over any wired
        /// link. The node-self-host composition-closure clause (design §4 item 5) must preclude this,
        /// so a serve-time refusal is a composition bug — it fails the node closed, never degrades.
        Refuse(HostAuthority),
    }

    /// The authority-scoped node app-router (design §Phase-5 P5-1): the typed seam a `backend.*` /
    /// authority instance constructs from its [`MaterializationGate`] to route the node's OWN serve
    /// surfaces. It holds the instance's HELD authority set and the map of which non-held authority is
    /// reachable over which named root-wired link, and makes the [`NodeRoute`] decision for each
    /// surface — routing ONLY to held authorities and relaying everything else (design §4 item 5).
    ///
    /// P5-1 scope is the routing DECISION + the "construct-only-what-you-hold" discipline, host-tested
    /// in isolation. Deriving the reachability map from the live link topology, classifying a real
    /// request into its serve surface, and executing each route (local serve / crown-jewel relay /
    /// backend relay) is P5-2 — this cut takes the map as a constructor input and serves the stub.
    #[derive(Debug, Clone)]
    #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
    pub(super) struct NodeServeRouter {
        /// The authorities this instance holds (from its [`MaterializationGate`]) — the ONLY surfaces
        /// it may serve locally.
        held: BTreeSet<HostAuthority>,
        /// Non-held authority → the named root-wired link that reaches its holder. P5-1 takes this as
        /// a constructor input so the routing decision is host-testable; P5-2 derives it live.
        reachable: BTreeMap<HostAuthority, String>,
    }

    impl NodeServeRouter {
        /// Build the router from an instance's [`MaterializationGate`] (its held authority set) and
        /// the reachability map (non-held authority → the named root-wired link that reaches its
        /// holder). Reversible P5-1 sub-decision (FLAGGED): the reachability map is a constructor
        /// input here so the routing decision is host-testable in isolation; P5-2 derives it from the
        /// live link topology (`fds.links` + the composition's `[privsep.links]` purposes).
        #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
        pub(super) fn new(
            gate: &MaterializationGate,
            reachable: BTreeMap<HostAuthority, String>,
        ) -> Self {
            Self {
                held: gate.held().collect(),
                reachable,
            }
        }

        /// The P5-1 routing decision for a serve surface identified by the [`HostAuthority`] it needs.
        /// HELD ⇒ [`NodeRoute::Local`] (construct-only-what-you-hold); else reachable over a wired
        /// link ⇒ relay ([`NodeRoute::RelayCrownJewel`] for a group-A authority, else
        /// [`NodeRoute::RelayBackend`]); else [`NodeRoute::Refuse`] fail-closed. A HELD authority is
        /// NEVER relayed and a non-held one is NEVER served locally — the structural invariant this
        /// seam exists to prove (design §4 item 5).
        #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
        pub(super) fn route(&self, surface: HostAuthority) -> NodeRoute {
            if self.held.contains(&surface) {
                return NodeRoute::Local(surface);
            }
            match self.reachable.get(&surface) {
                Some(link) if surface.is_crown_jewel() => NodeRoute::RelayCrownJewel {
                    authority: surface,
                    link: link.clone(),
                },
                Some(link) => NodeRoute::RelayBackend {
                    authority: surface,
                    link: link.clone(),
                },
                None => NodeRoute::Refuse(surface),
            }
        }
    }

    /// The P5-1 node app-router HANDLER: the [`boatramp_http::Handler`] drop-in an authority instance
    /// constructs from its [`MaterializationGate`] to replace [`MinimalHandler`] on the self-host
    /// serve path. It holds a [`NodeServeRouter`] ready to route each request's serve surface, but in
    /// THIS unwired cut it still answers the Phase-1 stub 200 — P5-2 adds the request→surface
    /// classifier and executes each [`NodeRoute`] (local serve / relay) against a real surface. Kept
    /// behaviorally identical to the stub so wiring it in P5-2 changes the serve, not the byte path.
    #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
    pub(super) struct NodeServeHandler {
        router: NodeServeRouter,
    }

    impl NodeServeHandler {
        /// Construct the handler around the instance's [`NodeServeRouter`].
        #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
        pub(super) fn new(router: NodeServeRouter) -> Self {
            Self { router }
        }

        /// The router this handler routes each request's serve surface through (consumed by P5-2's
        /// request→surface classifier). Exposed so P5-1 host tests can assert the handler carries the
        /// gate-derived router.
        #[allow(dead_code)] // the P5-1 API seam — exercised by this module's host tests; P5-2 wires it live.
        pub(super) fn router(&self) -> &NodeServeRouter {
            &self.router
        }
    }

    impl boatramp_http::Handler for NodeServeHandler {
        async fn handle(&self, _req: boatramp_http::Request) -> boatramp_http::Response {
            // P5-1 is BEHIND the unwired self-host path: no real serve surface is classified or served
            // yet (that is P5-2), so this answers the SAME Phase-1 stub `MinimalHandler` does. The
            // gate-derived router is held ready; nothing here serves the node's real app.
            boatramp_http::response(
                200,
                b"boatramp privsep backend instance (Phase 1 minimal serve)\n".to_vec(),
            )
        }
    }

    // =========================================================================
    // Phase-4 WS-C: the per-tenant TEMPLATE backend + the per-tenant ROUTER frontend
    // =========================================================================

    /// A PER-TENANT TEMPLATE instance the router instantiated on demand for ONE tenant (WS-C step 4).
    /// It establishes its UNFORGEABLE wired tenant identity from `BOATRAMP_PRIVSEP_TENANT_SCOPE`
    /// (re-validated fail-closed by [`WiredTenantIdentity::from_env`] — an `Unwired`/invalid/unreadable
    /// scope EXITS the instance → the router treats the dead instance as `NotReady` and re-instantiates),
    /// then serves received client fds with EVERY backend call scoped by that identity
    /// ([`scope_backend_call`]) — never a guest-named tenant (artifact #2). Same splice/serve shape as
    /// [`run_backend`], but scope-keyed and identity-fail-closed.
    fn run_per_tenant_backend(label: &str, fds: &PrivsepChildFds) -> Result<(), String> {
        // The UNFORGEABLE wired tenant identity FIRST — fail-closed (an instance that cannot prove its
        // own tenant must not reach a shared backend). Read SOLELY from the router-wired env + RE-VALIDATED.
        let wired = WiredTenantIdentity::from_env().map_err(|e| e.to_string())?;
        let (lname, link_fd) = fds.links.iter().next().ok_or_else(|| {
            "a per-tenant instance has no feature-link to receive client connections over"
                .to_string()
        })?;
        tracing::info!(
            instance = %label,
            project = %wired.scope().project(),
            link = %lname,
            "[privsep] per-tenant backend: wired tenant identity established + re-validated; serving \
             scope-keyed (fail-closed)"
        );
        // The marker the live gate greps — reached ONLY after a VALID wired identity (an Unwired /
        // invalid scope exits above), so it PROVES one isolated per-tenant instance stood up scoped.
        tracing::info!(instance = %label, project = %wired.scope().project(), "[privsep] PRIVSEP PER-TENANT OK");
        // SAFETY: `link_fd` is the fd the router dup'd into this child + named in its fd map.
        let link = unsafe { LinkEndpoint::from_inherited_fd(*link_fd) };
        let wired = Arc::new(wired);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("building the Tokio runtime: {e}"))?;
        rt.block_on(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(OwnedFd, Vec<u8>)>(64);
            // Blocking link-drain on a dedicated thread; hands each received (client fd, routing head)
            // to the async consumer. EOF/err ends the loop (the router went away).
            let drain = std::thread::spawn(move || {
                loop {
                    match link.recv_client_conn() {
                        Ok((fd, head)) => {
                            if tx.blocking_send((fd, head)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "[privsep] per-tenant backend: link recv ended");
                            break;
                        }
                    }
                }
            });
            while let Some((fd, head)) = rx.recv().await {
                tokio::spawn(serve_per_tenant_client_fd(fd, head, wired.clone()));
            }
            let _ = drain.join();
        });
        Ok(())
    }

    /// Serve one received client fd for a per-tenant instance: the frontend's routing marker
    /// ([`routing_head`]) is a defence-in-depth consistency check (did the router splice us the right
    /// tenant's connection?) — a mismatch is logged loudly, but the WIRED identity stays authoritative
    /// (the head NEVER overrides the env). The request is served by a [`PerTenantHandler`] scoped to
    /// the wired identity.
    async fn serve_per_tenant_client_fd(
        fd: OwnedFd,
        head: Vec<u8>,
        wired: Arc<WiredTenantIdentity>,
    ) {
        if !head.is_empty() && !wired.matches_routed(&head) {
            tracing::warn!(
                project = %wired.scope().project(),
                "[privsep] per-tenant backend: routing head did not match the wired scope — serving by \
                 the (authoritative) wired identity, NOT the head"
            );
        }
        let std_stream = std::net::TcpStream::from(fd);
        if let Err(e) = std_stream.set_nonblocking(true) {
            tracing::debug!(error = %e, "[privsep] per-tenant backend: set_nonblocking on a client fd");
            return;
        }
        let peer = std_stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let stream = match tokio::net::TcpStream::from_std(std_stream) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "[privsep] per-tenant backend: adopting a client fd into Tokio");
                return;
            }
        };
        if let Err(e) = boatramp_http::serve_connection(stream, PerTenantHandler { wired }).await {
            tracing::debug!(%peer, error = %e, "[privsep] per-tenant backend: connection served with error");
        }
    }

    /// The per-tenant backend handler: EVERY backend call is scoped by the instance's UNFORGEABLE
    /// wired identity via [`scope_backend_call`] (a guest names no tenant — `None`), so a shared
    /// backend is keyed by the unforgeable scope, never a guest-supplied one (artifact #2). The body
    /// carries the resolved scope so TWO tenants produce TWO DISTINCT responses (the live gate asserts
    /// it). The full authority-scoped app router is the WS-D/WS-E per-tenant backend-call extension.
    struct PerTenantHandler {
        wired: Arc<WiredTenantIdentity>,
    }

    impl boatramp_http::Handler for PerTenantHandler {
        async fn handle(&self, _req: boatramp_http::Request) -> boatramp_http::Response {
            // The normal shape: a guest has NO tenant field, so `None`. The scope is ALWAYS the wired
            // identity; `scope_backend_call` would REFUSE a guest that named a foreign tenant.
            match scope_backend_call(&self.wired, None) {
                Ok(scope) => boatramp_http::response(
                    200,
                    format!(
                        "boatramp privsep per-tenant backend [project={} prefix={}]\n",
                        scope.project(),
                        scope.resource_prefix()
                    )
                    .into_bytes(),
                ),
                Err(e) => boatramp_http::response(403, e.to_string().into_bytes()),
            }
        }
    }

    /// The PER-TENANT PARSER (WS-D Finding-2): the public-listener holder in a per-tenant composition
    /// — `{listen.public-tls, listen.http-parse}`, holding NEITHER `backend.kv` NOR `exec.compute`
    /// (the composition-closure lint refuses co-locating them). It accepts on the inherited listener,
    /// peeks each connection's `Host` (Stage-0 `MSG_PEEK`, consuming NOTHING — its job as the
    /// http-parse holder), and FORWARDS the accepted client fd + the peeked Host inward to the
    /// non-public SUPERVISOR over the link. It resolves no tenant and forks nothing — the supervisor
    /// (which holds KV + spawn, off the public parse surface) does. The accept + peek are
    /// de-serialized (one task per connection) so a slow/silent peer never pins ingress (the slowloris
    /// fix); sends over the single supervisor link are SERIALIZED (the `SCM_RIGHTS` fd-pass + head
    /// frame of two connections must not interleave on one stream).
    fn run_per_tenant_parser(label: &str, listener_fd: i32, link_fd: i32) -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("building the Tokio runtime: {e}"))?;
        rt.block_on(async move {
            // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the fd map. The
            // Mutex serializes the fd-pass across concurrent per-connection tasks.
            let link = Arc::new(std::sync::Mutex::new(unsafe {
                LinkEndpoint::from_inherited_fd(link_fd)
            }));
            // SAFETY: `listener_fd` is the fd the root dup'd into this child + named in the fd map.
            // The parser NEVER forks (it holds no `exec.compute`), so the listener needs no CLOEXEC
            // guard against an inherited child (unlike the pre-WS-D co-located router).
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(listener_fd) };
            std_listener
                .set_nonblocking(true)
                .map_err(|e| format!("set_nonblocking on the listener: {e}"))?;
            let listener = tokio::net::TcpListener::from_std(std_listener)
                .map_err(|e| format!("adopting the listener into Tokio: {e}"))?;
            let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PER_TENANT_ROUTING));
            tracing::info!(
                instance = %label,
                max_inflight = MAX_INFLIGHT_PER_TENANT_ROUTING,
                "[privsep] per-tenant parser: accepting (async, de-serialized) + peeking Host \
                 (Stage-0, MSG_PEEK); forwarding client fds + Host inward to the supervisor (holds \
                 NO backend.kv / exec.compute — WS-D Finding-2)"
            );
            loop {
                let (conn, _peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => return Err::<(), String>(format!("accepting on the listener: {e}")),
                };
                let Ok(permit) = inflight.clone().try_acquire_owned() else {
                    tracing::warn!(
                        cap = MAX_INFLIGHT_PER_TENANT_ROUTING,
                        "[privsep] per-tenant parser: at the in-flight cap — dropping a connection \
                         (fail-closed, no unbounded queue)"
                    );
                    drop(conn);
                    continue;
                };
                let link = link.clone();
                // One task per connection: the host-peek runs OFF the accept loop, so a slow/silent
                // peer pins only its own task until the peek deadline.
                tokio::spawn(async move {
                    let _permit = permit;
                    forward_peeked_connection(conn, &link).await;
                });
            }
        })
    }

    /// Peek the `Host` (deadline-bounded) off ONE accepted connection and forward the raw client fd +
    /// the peeked Host (as the link head) inward to the supervisor. Consumes NOTHING from the client
    /// (`MSG_PEEK`), so the supervisor relays the fd onward and the per-tenant child re-reads the full
    /// request. An unpeekable Host forwards an EMPTY head — the supervisor then refuses it fail-closed
    /// (the resolve policy lives on the KV holder, never the parser). Fail-closed on a transport error
    /// (drop). The send is serialized under `link`'s Mutex so two connections' fd-passes never
    /// interleave on the single supervisor stream.
    async fn forward_peeked_connection(
        conn: tokio::net::TcpStream,
        link: &std::sync::Mutex<LinkEndpoint>,
    ) {
        let host = peek_host_async(&conn, PER_TENANT_PEEK_DEADLINE)
            .await
            .unwrap_or_default();
        let conn = match conn.into_std() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "[privsep] per-tenant parser: reclaiming the client fd from Tokio failed \
                     (dropping the connection, fail-closed)"
                );
                return;
            }
        };
        {
            let guard = link.lock().unwrap();
            if let Err(e) = guard.send_client_conn(conn.as_fd(), host.as_bytes()) {
                tracing::warn!(
                    error = %e,
                    "[privsep] per-tenant parser: forwarding a client fd to the supervisor failed \
                     (dropping the connection, fail-closed)"
                );
            }
        }
        // Our copy: a successful send SCM_RIGHTS-duplicated it to the supervisor; drop closes ours.
        drop(conn);
    }

    /// The PER-TENANT SUPERVISOR (WS-D Finding-2): the non-public backend holding `backend.kv` +
    /// `exec.compute`. It binds NO listener and parses NO raw client bytes. It RECEIVES client fds +
    /// the parser-peeked Host over the parser link, RE-RESOLVES Host→project against the control-plane
    /// KV (authoritative — the parser's Host is only an input, never selects the tenant on its own),
    /// instantiates / wakes the per-tenant `exec.wasmtime` child (lazy socketpair + fork via the
    /// root's own primitive, scale-to-zero pool), and relays the client fd onward to that child. This
    /// is the half the public parser's spawn + KV authority was split onto — the resolve + fork that
    /// the pre-WS-D co-located router performed in the same address space as the parse surface.
    /// Fail-closed throughout (no wildcard / default / fallback tenant).
    fn run_per_tenant_supervisor(
        label: &str,
        gate: &MaterializationGate,
        fds: &PrivsepChildFds,
        config: &ServerConfig,
        config_path: &Path,
    ) -> Result<(), String> {
        // It is the SOLE `backend.kv` holder (so opening the control-plane KV here does not
        // DOUBLE-OPEN the single-writer store) AND holds `exec.compute` (to fork the children). The
        // closure lint guarantees a `listen.http-parse` instance holds neither, so these live here.
        if !gate.may_materialize(HostAuthority::BackendKv) {
            return Err(
                "per-tenant supervisor holds no `backend.kv` — it cannot resolve Host→project to a \
                 tenant (the composition must place `backend.kv` + `exec.compute` on the supervisor)"
                    .to_string(),
            );
        }
        // The supervisor's single boot-wired link is the inbound parser link (the per-tenant relay
        // links to the templates are created LAZILY per tenant, not boot-wired). The supervisor assumes
        // EXACTLY one inbound link, so refuse fail-closed if it was wired more than one (an ambiguous
        // composition the root must reject rather than silently pick one via `.next()`) — F5.
        if fds.links.len() > 1 {
            let mut names: Vec<&String> = fds.links.keys().collect();
            names.sort();
            return Err(format!(
                "a per-tenant supervisor was wired {} inbound feature-links {names:?}, but it expects \
                 EXACTLY one (the parser relay); refusing the ambiguous composition fail-closed",
                fds.links.len(),
            ));
        }
        // Fail-closed if absent.
        let (link_name, inbound_fd) = fds
            .links
            .iter()
            .next()
            .map(|(n, fd)| (n.clone(), *fd))
            .ok_or_else(|| {
                "a per-tenant supervisor has no feature-link to receive client fds from the parser \
                 over (the composition must link the parser to it)"
                    .to_string()
            })?;
        // The supervisor FORKS per-tenant children, so the inbound parser link fd (NOT CLOEXEC — it
        // survived the supervisor's own exec) must be CLOEXEC'd so no per-tenant child inherits it
        // (F5: the only fd that ever reaches a per-tenant child is its own socketpair + client fds).
        set_cloexec(inbound_fd).map_err(|e| format!("CLOEXEC on the parser link fd: {e}"))?;
        // Re-derive the authorized plan IN THE SUPERVISOR so the template's spawn spec is built by the
        // SAME secret-scrubbed contract (F11-B) the root used — a per-tenant child inherits NO secret.
        let parent_env: Vec<(String, String)> = std::env::vars().collect();
        let plan = super::plan_root(config, config_path, parent_env).map_err(|e| e.to_string())?;
        // The supervisor instantiates EXACTLY one per-tenant template. Refuse fail-closed if the
        // composition defines more than one, rather than silently pick one via `.next()` — F5. (The
        // closure lint already constrains every template to be `{exec.wasmtime}`; this guards the
        // supervisor's single-template assumption against a multi-template composition.)
        if plan.templates.len() > 1 {
            let mut labels: Vec<&str> = plan.templates.iter().map(|t| t.label.as_str()).collect();
            labels.sort_unstable();
            return Err(format!(
                "the composition defines {} per-tenant template specs {labels:?}, but a supervisor \
                 instantiates EXACTLY one; refusing the ambiguous composition fail-closed",
                plan.templates.len(),
            ));
        }
        let template_spec = plan.templates.into_iter().next().ok_or_else(|| {
            "the composition defines no per-tenant template spec (a supervisor needs one)"
                .to_string()
        })?;
        let relay_link_name = per_tenant_relay_link_name(config, label, &template_spec.label)?;
        let current_exe =
            std::env::current_exe().map_err(|e| format!("resolving current exe: {e}"))?;
        let policy = config
            .privsep
            .as_ref()
            .map(|p| p.per_tenant)
            .unwrap_or_default();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("building the Tokio runtime: {e}"))?;
        rt.block_on(async move {
            // Bound the control-plane KV open with a fail-loud timeout: if the store open stalls
            // (e.g. a `backend.kv` Landlock-grant/store-path mismatch makes SlateDB's retrying object
            // store spin on EACCES forever), the supervisor EXITS with a clear error → the root's
            // FailNodeClosed tears the node down, rather than hanging up inert. 30s is far beyond a
            // healthy control-plane open (sub-second); it only ever fires on a real stall.
            let deploy = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                build_routing_deploy_store(config),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => {
                    return Err::<(), String>(
                        "per-tenant supervisor: opening the control-plane KV for Host→project \
                         routing timed out after 30s — the store open is stuck. The most likely \
                         cause is that the `backend.kv` Landlock grant does not cover the store's \
                         real path (see `sandbox::backend_state_subdir(BackendKv)` vs \
                         `build_slatedb_kv`'s `data_dir.join(\"kv-slate\")`). Failing closed."
                            .to_string(),
                    );
                }
            };
            let registry = Arc::new(ComputePlaneRegistry::new(
                current_exe,
                template_spec,
                relay_link_name,
                policy,
            ));
            // SAFETY: `inbound_fd` is the fd the root dup'd into this child + named in the fd map; we
            // CLOEXEC'd it above so forked children never inherit it.
            let link = unsafe { LinkEndpoint::from_inherited_fd(inbound_fd) };
            let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PER_TENANT_ROUTING));
            tracing::info!(
                instance = %label,
                link = %link_name,
                idle_evict_secs = policy.idle_eviction_secs,
                max_instances = policy.max_instances,
                max_inflight = MAX_INFLIGHT_PER_TENANT_ROUTING,
                "[privsep] per-tenant supervisor: receiving client fds over the parser link; \
                 resolving Host→project (KV) + instantiating per-tenant instances (fail-closed — no \
                 wildcard / default / fallback tenant); parses NO raw client bytes"
            );
            // Blocking link-drain on a dedicated thread (recv is blocking); it hands each received
            // (client fd, peeked-Host head) to the async consumer. EOF/err ends the loop (parser gone).
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(OwnedFd, Vec<u8>)>(64);
            let drain = std::thread::spawn(move || {
                loop {
                    match link.recv_client_conn() {
                        Ok((fd, head)) => {
                            if tx.blocking_send((fd, head)).is_err() {
                                break; // the consumer is gone
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "[privsep] per-tenant supervisor: parser link recv ended");
                            break;
                        }
                    }
                }
            });
            while let Some((fd, head)) = rx.recv().await {
                let Ok(permit) = inflight.clone().try_acquire_owned() else {
                    tracing::warn!(
                        cap = MAX_INFLIGHT_PER_TENANT_ROUTING,
                        "[privsep] per-tenant supervisor: at the in-flight cap — dropping a \
                         connection (fail-closed, no unbounded queue)"
                    );
                    drop(fd);
                    continue;
                };
                let deploy = deploy.clone();
                let registry = registry.clone();
                // One task per connection: resolve + cold-start + relay run OFF the drain loop, so one
                // tenant's fork never stalls routing for others.
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_supervised_connection(fd, head, &deploy, registry.as_ref()).await;
                });
            }
            let _ = drain.join();
            Ok::<(), String>(())
        })
    }

    /// Hard ceiling on concurrently in-flight per-tenant routing tasks (host-peek + route + relay +
    /// cold-start). Over the cap the router DROPS the connection fail-closed rather than queue
    /// unboundedly or spawn without bound — so a connection spray (including silent slowloris
    /// connections, each otherwise holding its task only until [`PER_TENANT_PEEK_DEADLINE`]) cannot
    /// exhaust memory / task slots.
    const MAX_INFLIGHT_PER_TENANT_ROUTING: usize = 256;

    /// The per-connection host-peek deadline (sub-second). A peer that sends no parseable `Host`
    /// within this window is refused fail-closed. Far shorter than the old inline 5s blocking
    /// `SO_RCVTIMEO`: with the peek now off the accept loop (one task per connection) a stall no
    /// longer pins ingress, and a tight deadline frees the task + its in-flight permit promptly.
    const PER_TENANT_PEEK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

    /// Handle ONE client fd received over the parser link, OFF the drain loop (its own task): the
    /// parser already peeked the `Host` and sent it as the head → the supervisor RE-RESOLVES it
    /// against the KV (authoritative; the parser's Host is only an input) → on `Routed` relay, on
    /// `NotReady` cold-start-then-relay, on refusal drop. Fail-closed throughout — an
    /// unresolved/ambiguous/absent Host, a backed-off/rate-limited or failed cold start, or a relay
    /// error all DROP the connection; none falls back to another tenant. The cold-start `instantiate`
    /// runs HERE (never on the drain loop), so one tenant's fork never stalls routing for others. The
    /// supervisor parses NO raw client bytes: the Host rode in the head, and the client fd is passed
    /// onward opaquely (F5).
    async fn handle_supervised_connection(
        client_fd: OwnedFd,
        host_head: Vec<u8>,
        deploy: &boatramp_core::deploy::DeployStore,
        registry: &ComputePlaneRegistry,
    ) {
        // The Host the parser peeked (an INPUT, never the authority): an empty/invalid head resolves
        // to no tenant and is refused — the resolve policy lives HERE on the KV holder, not the parser.
        let host = String::from_utf8_lossy(&host_head).into_owned();
        // Adopt the received fd into a blocking std stream so the UNCHANGED SCM_RIGHTS relay path can
        // splice it onward; the per-tenant child re-reads the full request (nothing was consumed).
        let conn = std::net::TcpStream::from(client_fd);
        let _ = conn.set_nonblocking(false);
        match route_by_host(deploy, &host, registry).await {
            Ok(RouteOutcome::Routed(link)) => relay_client_to_tenant(&link, &conn),
            Ok(RouteOutcome::NotReady(scope)) => match registry.instantiate(&scope) {
                Ok(link) => relay_client_to_tenant(&link, &conn),
                // A backoff / rate-limit decline is EXPECTED under churn (warn); a socketpair/fork
                // failure is a genuine error. Either way the connection is refused fail-closed.
                Err(e) if e.is_admission_decline() => tracing::warn!(
                    project = %scope.project(),
                    error = %e,
                    "[privsep] per-tenant supervisor: cold-start declined by admission control \
                     (backoff / rate-limit) — refusing the connection (fail-closed)"
                ),
                Err(e) => tracing::error!(
                    project = %scope.project(),
                    error = %e,
                    "[privsep] per-tenant supervisor: cold-start instantiate FAILED — refusing the \
                     connection (fail-closed)"
                ),
            },
            Err(refusal) => tracing::warn!(
                host = %host,
                %refusal,
                "[privsep] per-tenant supervisor: refusing a connection (fail-closed, no fallback \
                 tenant)"
            ),
        }
        // Our copy: a relay SCM_RIGHTS-duplicated it to the tenant; a refusal closes it here.
        drop(conn);
    }

    /// Relay one accepted client fd to a tenant's instance over its wired link, with the
    /// non-authoritative routing marker ([`routing_head`]). Fail-closed on a transport error (the
    /// connection is dropped; the next request for that tenant re-instantiates if the instance died).
    fn relay_client_to_tenant(
        link: &boatramp_server::privsep_tenant::TenantInstanceLink,
        conn: &std::net::TcpStream,
    ) {
        let head = routing_head(link.scope());
        if let Err(e) = link.relay_client(conn.as_raw_fd(), &head) {
            tracing::warn!(
                project = %link.scope().project(),
                error = %e,
                "[privsep] per-tenant router: relaying the client fd to the tenant instance failed \
                 (connection dropped; a dead instance is re-instantiated on the next request)"
            );
        }
    }

    /// The declared relay link NAME between the per-tenant router and the template — the fd-map key
    /// under which each per-tenant child receives its socketpair end. Fail-closed: a composition with
    /// no such link cannot relay to its per-tenant instances.
    fn per_tenant_relay_link_name(
        config: &ServerConfig,
        router_label: &str,
        template_label: &str,
    ) -> Result<String, String> {
        let privsep = config
            .privsep
            .as_ref()
            .ok_or_else(|| "no [privsep] composition at router start".to_string())?;
        privsep
            .links
            .iter()
            .find(|(_, l)| {
                (l.from == router_label && l.to == template_label)
                    || (l.from == template_label && l.to == router_label)
            })
            .map(|(name, _)| name.clone())
            .ok_or_else(|| {
                format!(
                    "the composition declares no link between the per-tenant router {router_label:?} \
                     and the template {template_label:?} — add a `local` relay link so the router can \
                     splice client connections to each per-tenant instance"
                )
            })
    }

    /// Build the routing-only [`DeployStore`](boatramp_core::deploy::DeployStore) the per-tenant
    /// router resolves Host→project against, from the node's control-plane KV (the router is the SOLE
    /// `backend.kv` holder, so opening it here does NOT double-open the single-writer store). The blob
    /// `Storage` is a real FS backend that host resolution NEVER touches (it reads only the KV), so it
    /// is inert here (a KV-only resolve constructor would avoid even constructing it — flagged WS-D).
    /// The KV backend is derived from the resolved `[serve.kv]` (sql ⇒ Sql, else the Slatedb default),
    /// restart-class like the rest of the composition.
    #[cfg(feature = "fs")]
    async fn build_routing_deploy_store(
        config: &ServerConfig,
    ) -> Result<boatramp_core::deploy::DeployStore, String> {
        use boatramp_core::kv::KvOpenPolicy;
        use boatramp_node::backends::{KvBackend, build_kv};
        let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
        let data_dir = super::normalized_data_dir(config, &cwd);
        let sql = config
            .serve
            .as_ref()
            .and_then(|s| s.kv.as_ref())
            .and_then(|k| k.sql.clone());
        let backend = if sql.is_some() {
            KvBackend::Sql
        } else {
            KvBackend::Slatedb
        };
        // A privsep `backend.kv` holder opens the control-plane store UNDER its Landlock sandbox.
        // The store path (`<data_dir>/kv-slate` for Slatedb) MUST sit inside the `backend.kv` rw
        // grant (`sandbox::backend_state_subdir(BackendKv)`); a mismatch EACCES-denies the open and
        // SlateDB's retrying object store spins on it silently. Log the open at `info` so a stall is
        // visible at the default filter (the caller also bounds it with a fail-loud timeout).
        tracing::info!(
            data_dir = %data_dir.display(),
            backend = ?backend,
            "[privsep] per-tenant router: opening the control-plane KV for Host→project routing"
        );
        let kv = build_kv(
            backend,
            &data_dir,
            None,
            KvOpenPolicy::SelfHeal,
            sql.as_ref(),
        )
        .await
        .map_err(|e| format!("opening the control-plane KV for host routing: {e}"))?;
        let storage = Arc::new(boatramp_storage::FsStorage::new(data_dir.join("blobs")));
        Ok(boatramp_core::deploy::DeployStore::new(storage, kv))
    }

    /// Fail-closed fallback when the `fs` feature (the router's blob `Storage` backend) is not built.
    #[cfg(not(feature = "fs"))]
    async fn build_routing_deploy_store(
        _config: &ServerConfig,
    ) -> Result<boatramp_core::deploy::DeployStore, String> {
        Err(
            "per-tenant routing needs the `fs` feature for its blob Storage — build boatramp with \
             default features (fs on)"
                .to_string(),
        )
    }

    /// Async `MSG_PEEK` of the start of an HTTP/1.x request to extract the `Host` header, consuming
    /// NOTHING so the full request still reaches the backend over the spliced fd. Bounded by
    /// `deadline` (a sub-second async timeout) + a header cap. Because each connection is handled in
    /// its OWN task, a slow / silent peer can no longer pin the accept loop at all — the worst it can
    /// do is hold its own task until the deadline, after which it is refused fail-closed. `None` ⇒ no
    /// Host within the bound. HTTP/2 / TLS-SNI host extraction is a WS-D follow-on; the Phase-1 backend
    /// + the live gate use plaintext HTTP/1.1.
    pub(super) async fn peek_host_async(
        conn: &tokio::net::TcpStream,
        deadline: std::time::Duration,
    ) -> Option<String> {
        let scan = async {
            let mut buf = [0u8; 8192];
            let mut last_n = 0usize;
            loop {
                // `peek` awaits readability, then MSG_PEEKs the queued bytes (consumes nothing — the
                // backend still receives the full request over the spliced fd).
                let n = conn.peek(&mut buf).await.ok()?;
                if n == 0 {
                    return None; // peer closed before sending a request
                }
                if let Some(h) = parse_host_header(&buf[..n]) {
                    return Some(h);
                }
                // A complete header block with no Host ⇒ there is no host (refuse).
                if find_subslice(&buf[..n], b"\r\n\r\n").is_some() {
                    return None;
                }
                if n == buf.len() {
                    return None; // header block larger than the cap — refuse fail-closed
                }
                if n == last_n {
                    // No new bytes since the last peek (MSG_PEEK always re-reads from the start, and
                    // the readiness is not cleared by a peek that returns data): yield briefly so a
                    // peer that dribbles its header cannot busy-loop this task. Strictly bounded by
                    // `deadline` (the enclosing timeout), after which the peer is refused.
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                last_n = n;
            }
        };
        tokio::time::timeout(deadline, scan).await.ok().flatten()
    }

    /// Parse the `Host` header value (lowercased, port stripped) from a COMPLETE header line in `buf`
    /// (one terminated by CRLF, so a partial peek never yields a truncated host). Case-insensitive
    /// header name; returns `None` if the end-of-headers is reached without a complete Host line.
    fn parse_host_header(buf: &[u8]) -> Option<String> {
        let mut start = 0usize;
        while let Some(eol) = find_subslice(&buf[start..], b"\r\n") {
            let line = &buf[start..start + eol];
            start += eol + 2;
            if line.is_empty() {
                break; // end of the header block
            }
            if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
                let val = std::str::from_utf8(&line[5..]).ok()?.trim();
                let host = val
                    .split(':')
                    .next()
                    .unwrap_or(val)
                    .trim()
                    .to_ascii_lowercase();
                if host.is_empty() {
                    return None;
                }
                return Some(host);
            }
        }
        None
    }

    /// First index of `needle` in `hay` (small, allocation-free; the peeked header is bounded).
    fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || hay.len() < needle.len() {
            return None;
        }
        hay.windows(needle.len()).position(|w| w == needle)
    }
}

#[cfg(not(unix))]
mod instance_serve {
    use std::path::Path;

    use super::{MaterializationGate, PrivsepChildFds, ServerConfig};

    pub(super) fn run(
        _label: &str,
        _gate: &MaterializationGate,
        _fds: &PrivsepChildFds,
        _config: &ServerConfig,
        _config_path: &Path,
    ) -> Result<(), String> {
        Err(
            "privsep instance serving (socketpair/SCM_RIGHTS) is Unix-only; privsep is Linux-only \
             in Phase 1"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use boatramp_core::privsep::{
        InstanceLifecycle, InstanceSubstrate, LinkPurpose, LinkTransport, NodeServeMode,
        PerTenantPolicy, PrivsepConfig, PrivsepLink, SandboxPosture,
    };

    use super::*;

    // ---- argv dispatch (F10) ----

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().copied().map(String::from).collect()
    }

    #[test]
    fn classify_argv_matches_root_and_instance_exactly() {
        assert_eq!(
            classify_argv(&argv(&["boatramp", "__root"])),
            ArgvEntry::Root
        );
        assert_eq!(
            classify_argv(&argv(&["boatramp", "__instance", "edge"])),
            ArgvEntry::Instance("edge".to_string())
        );
        // An ordinary command is Normal (the monolith path is untouched).
        assert_eq!(
            classify_argv(&argv(&["boatramp", "serve"])),
            ArgvEntry::Normal
        );
        assert_eq!(classify_argv(&argv(&["boatramp"])), ArgvEntry::Normal);
        // A near-miss is NOT the privsep entry (exact match only — the clap enum never
        // sees `__root`/`__instance`, and a lookalike stays a normal, clap-rejected arg).
        assert_eq!(
            classify_argv(&argv(&["boatramp", "__roots"])),
            ArgvEntry::Normal
        );
        assert_eq!(
            classify_argv(&argv(&["boatramp", "root"])),
            ArgvEntry::Normal
        );
    }

    #[test]
    fn config_path_from_argv_reads_flag_or_defaults() {
        assert_eq!(
            config_path_from_argv(&argv(&["boatramp", "__root", "--config", "/etc/br.cfg"])),
            PathBuf::from("/etc/br.cfg")
        );
        assert_eq!(
            config_path_from_argv(&argv(&["boatramp", "__root", "--config=/etc/br.cfg"])),
            PathBuf::from("/etc/br.cfg")
        );
        assert_eq!(
            config_path_from_argv(&argv(&["boatramp", "__root"])),
            PathBuf::from("boatramp.cfg")
        );
    }

    // ---- composition fixtures ----

    fn inst(caps: &[HostAuthority], links: &[&str]) -> PrivsepInstanceConfig {
        PrivsepInstanceConfig {
            capabilities: caps.to_vec(),
            sandbox: SandboxPosture::Derived,
            substrate: InstanceSubstrate::OsProcess,
            links: links.iter().copied().map(String::from).collect(),
            ..Default::default()
        }
    }

    /// A clean least-authority composition whose union == ALL. Restructured for the WIDENED WS-D
    /// Finding-2 lint (a public listener holds no `exec.compute`/`control.admin-api`/`backend.*`):
    /// parser=public-tls+http-parse, edge=the other listeners + `exec.wasmtime` + `acme.dns-control`
    /// (none a forbidden partner), compute=`exec.compute`+`control.admin-api` (off every listener),
    /// data=B, signer=A.
    fn clean_privsep() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        // The public HTTP parse surface on its OWN instance, holding NO spawn/KV (WS-D Finding-2).
        instances.insert(
            "parser".to_string(),
            inst(
                &[
                    HostAuthority::ListenPublicTls,
                    HostAuthority::ListenHttpParse,
                ],
                &[],
            ),
        );
        // The other public listeners. Keep `exec.wasmtime` (the inverted-frontend exception) and
        // `acme.dns-control` (cert issuance) here — neither is a Finding-2 forbidden partner — but NOT
        // `exec.compute`/`control.admin-api` (those move to `compute`, off every untrusted-byte surface).
        instances.insert(
            "edge".to_string(),
            inst(
                &[
                    HostAuthority::ListenMail,
                    HostAuthority::ListenOverlay,
                    HostAuthority::ListenS3Ingress,
                    HostAuthority::ListenInboundTcp,
                    HostAuthority::ListenGateway,
                    HostAuthority::ExecWasmtime,
                    HostAuthority::AcmeDnsControl,
                ],
                &["to-signer"],
            ),
        );
        // The spawn + control plane, off every public listener (WS-D Finding-2, widened): no listener,
        // no backend, no crown ⇒ no violation and no F8 warning.
        instances.insert(
            "compute".to_string(),
            inst(
                &[HostAuthority::ExecCompute, HostAuthority::ControlAdminApi],
                &[],
            ),
        );
        instances.insert(
            "data".to_string(),
            inst(
                &[
                    HostAuthority::BackendKv,
                    HostAuthority::BackendSql,
                    HostAuthority::BackendBlob,
                    HostAuthority::BackendMessaging,
                ],
                &[],
            ),
        );
        instances.insert(
            "signer".to_string(),
            inst(
                &[
                    HostAuthority::SecretsSealer,
                    HostAuthority::TokenSigner,
                    HostAuthority::ImageSigner,
                    HostAuthority::OverlayDialSigner,
                    HostAuthority::S3IngressRoot,
                    HostAuthority::ClusterJoinSigner,
                ],
                &[],
            ),
        );
        let mut links = BTreeMap::new();
        links.insert(
            "to-signer".to_string(),
            PrivsepLink {
                from: "edge".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Unspecified,
            },
        );
        PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        }
    }

    fn cfg_with(privsep: Option<PrivsepConfig>) -> ServerConfig {
        ServerConfig {
            serve: Some(config::ServeConfig::default()),
            privsep,
            ..Default::default()
        }
    }

    fn fake_env() -> Vec<(String, String)> {
        vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("VAULT_TOKEN".to_string(), "s.LIVE".to_string()),
            (
                "BOATRAMP_AUTH_ROOT_PRIVATE_KEY".to_string(),
                "ed25519:LIVE".to_string(),
            ),
        ]
    }

    // ---- plan_root: the lint-before-spawn authorization gate ----

    #[test]
    fn plan_root_refuses_a_non_privsep_node() {
        let cfg = cfg_with(None);
        let err = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env()).unwrap_err();
        assert!(matches!(err, PrivsepError::NotComposed));
    }

    #[test]
    fn plan_root_authorizes_a_clean_composition_with_minimal_env() {
        let cfg = cfg_with(Some(clean_privsep()));
        let plan = plan_root(&cfg, Path::new("/etc/boatramp.cfg"), fake_env())
            .expect("clean composition authorized");
        // clean_privsep has NO per-tenant template, so all five instances are STATIC (boot-forked).
        assert_eq!(plan.static_instances.len(), 5);
        assert!(plan.templates.is_empty());
        for spec in &plan.static_instances {
            // The re-exec argv is the __instance tail with the config path.
            assert_eq!(spec.argv[0], INSTANCE_SUBCOMMAND);
            assert_eq!(&spec.argv[1], &spec.label);
            assert_eq!(spec.argv[2], "--config");
            assert_eq!(spec.argv[3], "/etc/boatramp.cfg");
            // The spawn env is minimal + scrubbed: no live secret is couriered in.
            assert!(!spec.env.contains_key("VAULT_TOKEN"), "{}", spec.label);
            assert!(
                !spec.env.contains_key("BOATRAMP_AUTH_ROOT_PRIVATE_KEY"),
                "{}",
                spec.label
            );
            assert_eq!(spec.env.get("PATH").map(String::as_str), Some("/usr/bin"));
        }
    }

    #[test]
    fn plan_root_refuses_a_bad_composition_before_any_spawn_spec() {
        // Co-reside a crown jewel with a listener → the closure lint REFUSES; no spawn
        // spec is produced (a bad composition never spawns).
        let mut privsep = clean_privsep();
        privsep
            .instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .retain(|a| *a != HostAuthority::ListenHttpParse);
        privsep
            .instances
            .get_mut("signer")
            .unwrap()
            .capabilities
            .push(HostAuthority::ListenHttpParse);
        let cfg = cfg_with(Some(privsep));
        let err = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env()).unwrap_err();
        assert!(
            matches!(err, PrivsepError::Composition(_)),
            "a crown-jewel co-residency is a composition refusal, got {err:?}"
        );
    }

    // ---- Phase-5: the node self-hosting gate (vocabulary + fail-closed refusal) ----

    #[test]
    fn node_self_host_mode_is_refused_fail_closed_before_any_spawn_spec() {
        // The DEFAULT mode (guest-workloads) is the Phase-1..4 wired behavior — the gate is a no-op
        // and a clean composition still authorizes (no running composition changes).
        assert_eq!(NodeServeMode::default(), NodeServeMode::GuestWorkloads);
        assert!(NodeServeMode::GuestWorkloads.is_wired());
        assert!(!NodeServeMode::NodeSelfHost.is_wired());
        assert!(NodeServeMode::NodeSelfHost.is_node_self_host());
        let clean = clean_privsep();
        assert_eq!(clean.node_serve, NodeServeMode::GuestWorkloads);
        check_node_self_host_gate(&clean).expect("the default guest-workloads mode is wired");
        plan_root(
            &cfg_with(Some(clean)),
            Path::new("boatramp.cfg"),
            fake_env(),
        )
        .expect("a clean guest-workloads composition still authorizes");

        // Selecting node self-hosting (the Phase-5 target) is REFUSED fail-closed — the serve path
        // is not wired. The pure gate refuses with the greppable, invertible marker...
        let mut privsep = clean_privsep();
        privsep.node_serve = NodeServeMode::NodeSelfHost;
        let gate_err = check_node_self_host_gate(&privsep)
            .expect_err("node self-hosting must be refused until its serve path is wired");
        assert!(
            matches!(&gate_err, PrivsepError::NodeSelfHostUnwired(_)),
            "node self-hosting is its own fail-closed refusal, got {gate_err:?}"
        );
        assert!(
            gate_err.to_string().contains(NODE_SELF_HOST_UNWIRED_MARKER),
            "the refusal must carry the invertible marker {NODE_SELF_HOST_UNWIRED_MARKER:?}, got: {gate_err}"
        );

        // ...and the gate is WIRED INTO `plan_root`, so the whole root authorization refuses
        // end-to-end BEFORE any spawn spec is produced (a not-yet-buildable self-host composition
        // never spawns — the same posture as the secret-blind / closure refusals above).
        let err = plan_root(
            &cfg_with(Some(privsep)),
            Path::new("boatramp.cfg"),
            fake_env(),
        )
        .expect_err("plan_root must refuse node self-hosting end-to-end before any spawn");
        assert!(
            matches!(err, PrivsepError::NodeSelfHostUnwired(_)),
            "plan_root must surface the self-host refusal, got {err:?}"
        );
    }

    #[test]
    fn plan_root_refuses_an_inline_secret_before_any_spawn_spec() {
        // An inline §1.2 key input (auth_root_private_key) fails the secret-blind screen
        // BEFORE the lint / any spawn spec.
        let mut cfg = cfg_with(Some(clean_privsep()));
        cfg.serve.as_mut().unwrap().auth_root_private_key = Some("ed25519:LIVE".to_string());
        let err = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env()).unwrap_err();
        assert!(
            matches!(err, PrivsepError::SecretBlind(_)),
            "an inline secret is a secret-blindness refusal, got {err:?}"
        );
    }

    #[test]
    fn spawn_spec_to_command_clears_env_and_re_execs() {
        let cfg = cfg_with(Some(clean_privsep()));
        let plan = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env()).unwrap();
        let spec = &plan.static_instances[0];
        let cmd = spec.to_command(Path::new("/usr/local/bin/boatramp"));
        // The program is the current binary (re-exec), args carry the __instance tail.
        assert_eq!(
            cmd.get_program(),
            std::ffi::OsStr::new("/usr/local/bin/boatramp")
        );
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], INSTANCE_SUBCOMMAND);
        // `env_clear()` means the child inherits ONLY the explicitly-built minimal env.
        let env: Vec<_> = cmd.get_envs().collect();
        assert!(
            env.iter()
                .all(|(k, _)| k.to_string_lossy() != "VAULT_TOKEN"),
            "no live secret is couriered to the child"
        );
    }

    // ---- instance-slice resolution: the __instance refusal gate (F10) ----

    #[test]
    fn resolve_instance_slice_refuses_a_non_privsep_node() {
        let cfg = cfg_with(None);
        let err = resolve_instance_slice(&cfg, "edge").unwrap_err();
        assert!(
            matches!(err, PrivsepError::NotComposed),
            "__instance on a non-privsep node is refused, got {err:?}"
        );
    }

    #[test]
    fn resolve_instance_slice_refuses_an_unknown_label() {
        let cfg = cfg_with(Some(clean_privsep()));
        let err = resolve_instance_slice(&cfg, "ghost").unwrap_err();
        assert!(matches!(err, PrivsepError::InstanceNotFound(l) if l == "ghost"));
    }

    #[test]
    fn resolve_instance_slice_returns_the_declared_slice() {
        let cfg = cfg_with(Some(clean_privsep()));
        let inst = resolve_instance_slice(&cfg, "signer").expect("signer slice resolves");
        assert!(inst.capabilities.contains(&HostAuthority::SecretsSealer));
        // The instance's gate holds ONLY its own slice (no listener / exec / control).
        let gate = MaterializationGate::new(&inst.capabilities);
        assert!(!gate.may_materialize(HostAuthority::ListenHttpParse));
        assert!(gate.may_materialize(HostAuthority::TokenSigner));
    }

    // ---- MaterializationGate (§2.2) ----

    #[test]
    fn gate_permits_only_held_authorities() {
        let gate = MaterializationGate::new(&[
            HostAuthority::ListenHttpParse,
            HostAuthority::ExecWasmtime,
        ]);
        assert!(gate.may_materialize(HostAuthority::ListenHttpParse));
        assert!(gate.ensure(HostAuthority::ExecWasmtime).is_ok());
        // A dropped authority must never be constructed.
        assert!(!gate.may_materialize(HostAuthority::SecretsSealer));
        let err = gate.ensure(HostAuthority::SecretsSealer).unwrap_err();
        assert_eq!(err.0, HostAuthority::SecretsSealer);
        // dropped() is exactly ALL minus held.
        let dropped: BTreeSet<_> = gate.dropped().into_iter().collect();
        assert!(dropped.contains(&HostAuthority::SecretsSealer));
        assert!(!dropped.contains(&HostAuthority::ListenHttpParse));
        assert_eq!(dropped.len(), HostAuthority::ALL.len() - 2);
    }

    // ---- signer-key unlock: the root-wired per-link unseal allowlist ----

    /// A split composition: edge=C∪D∪E, data=B, sealer=A∖{token.signer}, signer={token.signer},
    /// with a `to-signer` link between the sealer and the signer.
    fn split_signer_privsep() -> PrivsepConfig {
        let mut p = clean_privsep();
        // Remove the all-A "signer" instance; replace with a split sealer + signer.
        p.instances.remove("signer");
        p.instances.insert(
            "sealer".to_string(),
            inst(
                &[
                    HostAuthority::SecretsSealer,
                    HostAuthority::ImageSigner,
                    HostAuthority::OverlayDialSigner,
                    HostAuthority::S3IngressRoot,
                    HostAuthority::ClusterJoinSigner,
                ],
                &["to-signer"],
            ),
        );
        p.instances.insert(
            "signer".to_string(),
            inst(&[HostAuthority::TokenSigner], &["to-signer"]),
        );
        // edge's `to-signer` link in clean_privsep connected edge→signer; rewire for the split.
        p.instances.get_mut("edge").unwrap().links = vec![];
        p.links.clear();
        p.links.insert(
            "to-signer".to_string(),
            PrivsepLink {
                from: "sealer".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Unspecified,
            },
        );
        p
    }

    #[test]
    fn unseal_allowlist_wires_only_the_sealer_end_of_a_sealer_signer_link() {
        let mut cfg = cfg_with(Some(split_signer_privsep()));
        cfg.serve.as_mut().unwrap().signer = Some(config::AuthSignerConfig::Sealed {
            key_ref: "path:/srv/node/secrets/signer.sealed".to_string(),
        });
        let allow = compute_unseal_allowlists(&cfg);
        // The SEALER end is wired to unseal the signer key ref over `to-signer`.
        let sealer_allow = allow.get("sealer").expect("sealer has an allowlist");
        assert!(sealer_allow.permits("to-signer", "path:/srv/node/secrets/signer.sealed"));
        // The SIGNER end gets NO allowlist (it is the asker, not the sealer).
        assert!(!allow.contains_key("signer"));
        // A name not wired, or the wrong link, is denied.
        assert!(!sealer_allow.permits("to-signer", "boatramp:something-else"));
        assert!(!sealer_allow.permits("to-core", "path:/srv/node/secrets/signer.sealed"));
    }

    #[test]
    fn unseal_allowlist_is_empty_for_a_non_sealed_signer() {
        // No `[serve.signer]` sealed source ⇒ no allowlist wired at all (AwsKms/ambient/absent).
        let cfg = cfg_with(Some(split_signer_privsep()));
        assert!(compute_unseal_allowlists(&cfg).is_empty());
    }

    // ---- WS-E residual #5: the signer selects its SEALER link explicitly (by purpose) ----

    #[test]
    fn select_sealer_link_picks_the_bootstrap_link_for_a_split_signer() {
        let cfg = cfg_with(Some(split_signer_privsep()));
        // The root wired the signer exactly the `to-signer` bootstrap-unseal link (fd 7).
        let mut wired = BTreeMap::new();
        wired.insert("to-signer".to_string(), 7);
        let (name, fd) =
            super::select_sealer_link(&cfg, "signer", &wired).expect("one sealer link");
        assert_eq!(name, "to-signer");
        assert_eq!(fd, 7);
    }

    #[test]
    fn select_sealer_link_ignores_an_authority_serve_minting_link() {
        // The signer gains a WS-E minting-consumer link (frontend→signer, AuthorityServe). The selector
        // must IGNORE it and still pick the bootstrap-unseal link — never send the key request there.
        let mut p = split_signer_privsep();
        p.instances.insert(
            "frontend".to_string(),
            inst(&[HostAuthority::ListenPublicTls], &["to-mint"]),
        );
        p.links.insert(
            "to-mint".to_string(),
            PrivsepLink {
                from: "frontend".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::AuthorityServe,
            },
        );
        let cfg = cfg_with(Some(p));
        let mut wired = BTreeMap::new();
        wired.insert("to-signer".to_string(), 7);
        wired.insert("to-mint".to_string(), 9); // the minting-consumer link is also wired
        let (name, fd) =
            super::select_sealer_link(&cfg, "signer", &wired).expect("one sealer link");
        assert_eq!(
            name, "to-signer",
            "must pick the bootstrap link, not the mint link"
        );
        assert_eq!(fd, 7);
    }

    #[test]
    fn select_sealer_link_refused_when_absent() {
        // A signer with no root-wired link to a secrets.sealer is refused fail-closed.
        let cfg = cfg_with(Some(split_signer_privsep()));
        let wired = BTreeMap::new(); // nothing wired
        let err = super::select_sealer_link(&cfg, "signer", &wired).unwrap_err();
        assert!(err.contains("no root-wired feature-link"), "got {err}");
    }

    #[test]
    fn select_sealer_link_refused_when_ambiguous() {
        // Two sealer-shaped links to the signer ⇒ ambiguous ⇒ refuse rather than `.next()`.
        let mut p = split_signer_privsep();
        // A second, separate sealer instance also linked to the signer (an unusual, ambiguous shape).
        p.instances.insert(
            "sealer2".to_string(),
            inst(&[HostAuthority::SecretsSealer], &["to-sealer2"]),
        );
        p.links.insert(
            "to-sealer2".to_string(),
            PrivsepLink {
                from: "sealer2".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Unspecified,
            },
        );
        let cfg = cfg_with(Some(p));
        let mut wired = BTreeMap::new();
        wired.insert("to-signer".to_string(), 7);
        wired.insert("to-sealer2".to_string(), 8);
        let err = super::select_sealer_link(&cfg, "signer", &wired).unwrap_err();
        assert!(err.contains("ambiguous"), "got {err}");
    }

    #[test]
    fn unseal_allowlist_empty_when_signer_co_resides_the_sealer() {
        // clean_privsep's "signer" holds BOTH secrets.sealer and token.signer → it resolves its key
        // in-process; no cross-instance link, so no allowlist is wired.
        let mut cfg = cfg_with(Some(clean_privsep()));
        cfg.serve.as_mut().unwrap().signer = Some(config::AuthSignerConfig::Sealed {
            key_ref: "path:/srv/node/secrets/signer.sealed".to_string(),
        });
        assert!(
            compute_unseal_allowlists(&cfg).is_empty(),
            "a co-resident signer+sealer needs no root-wired cross-link allowlist"
        );
    }

    #[test]
    fn unseal_allowlist_and_s2_lint_share_one_edge_set() {
        // Obligation (a) LOCKSTEP drift-guard: `compute_unseal_allowlists` (the root's per-link unseal
        // wiring) and the S2 VM secret-blindness lint's clause-1 edge set are BOTH derived from the one
        // shared `PrivsepConfig::sealer_signer_unseal_edges` predicate, so a future widening of the
        // unseal model cannot be mirrored into one but not the other (silently under-refusing in the
        // lint). This asserts they enumerate the SAME set of links on a topology seeded with decoys
        // that MUST be excluded: an `AuthorityServe` minting link (frontend→signer, not a sealer edge)
        // and a `sealer→data` link (data holds no `token.signer`).
        let mut p = split_signer_privsep();
        p.instances.insert(
            "frontend".to_string(),
            inst(&[HostAuthority::ListenPublicTls], &["to-mint"]),
        );
        p.links.insert(
            "to-mint".to_string(),
            PrivsepLink {
                from: "frontend".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::AuthorityServe,
            },
        );
        p.instances
            .get_mut("sealer")
            .unwrap()
            .links
            .push("sealer-data".to_string());
        p.links.insert(
            "sealer-data".to_string(),
            PrivsepLink {
                from: "sealer".to_string(),
                to: "data".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Unspecified,
            },
        );

        let mut cfg = cfg_with(Some(p));
        cfg.serve.as_mut().unwrap().signer = Some(config::AuthSignerConfig::Sealed {
            key_ref: "path:/srv/node/secrets/signer.sealed".to_string(),
        });

        // The shared predicate's edge set — exactly what the S2 lint's clause 1 keys off.
        let predicate_links: BTreeSet<String> = cfg
            .privsep
            .as_ref()
            .unwrap()
            .sealer_signer_unseal_edges()
            .iter()
            .map(|e| e.link.to_string())
            .collect();
        // The set `compute_unseal_allowlists` actually wires onto the sealer end(s).
        let allowlist_links: BTreeSet<String> = compute_unseal_allowlists(&cfg)
            .values()
            .flat_map(|a| a.by_link.keys().cloned())
            .collect();

        assert_eq!(
            predicate_links, allowlist_links,
            "the S2 lint clause-1 edge set and compute_unseal_allowlists must enumerate the SAME links"
        );
        // And it is EXACTLY the real sealer↔signer unseal edge — the decoys are excluded on both sides.
        assert_eq!(
            predicate_links,
            BTreeSet::from(["to-signer".to_string()]),
            "only the real sealer↔signer unseal edge, never the mint/decoy links"
        );
    }

    // ---- WS-C: the root→instance fd-pass contract ----

    #[test]
    fn privsep_child_fds_round_trips_through_env_value() {
        let mut fds = PrivsepChildFds::default();
        fds.links.insert("to-core".to_string(), 3);
        fds.links.insert("to-signer".to_string(), 4);
        fds.listener = Some(5);
        let value = fds.to_env_value();
        let back: PrivsepChildFds = serde_json::from_str(&value).unwrap();
        assert_eq!(back, fds);
        // An empty map (an instance wired no fds) round-trips as the default.
        let empty = PrivsepChildFds::default();
        assert_eq!(
            serde_json::from_str::<PrivsepChildFds>(&empty.to_env_value()).unwrap(),
            empty
        );
    }

    #[test]
    fn instance_listener_addr_only_for_public_listener_holders() {
        let addr: std::net::SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let mut cfg = cfg_with(Some(clean_privsep()));
        cfg.serve.as_mut().unwrap().addr = Some(addr);

        // A public-listener holder (public-tls / http-parse) binds serve.addr.
        assert_eq!(
            instance_listener_addr(&[HostAuthority::ListenHttpParse], &cfg),
            Some(addr)
        );
        assert_eq!(
            instance_listener_addr(&[HostAuthority::ListenPublicTls], &cfg),
            Some(addr)
        );
        // A backend / signer / non-public-listener instance binds nothing here (Phase 1).
        assert_eq!(
            instance_listener_addr(&[HostAuthority::BackendKv], &cfg),
            None
        );
        assert_eq!(
            instance_listener_addr(&[HostAuthority::ListenMail], &cfg),
            None,
            "only the PUBLIC listener is wired in the Phase-1 cut"
        );
        // A public holder with no serve.addr configured binds nothing (nothing to pass).
        cfg.serve.as_mut().unwrap().addr = None;
        assert_eq!(
            instance_listener_addr(&[HostAuthority::ListenHttpParse], &cfg),
            None
        );
    }

    // ---- WS-E: the authority-serve link designation (Phase 2 Wave 1) ----

    #[test]
    fn authority_serve_links_empty_for_the_phase1_compositions() {
        // clean_privsep: the `to-signer` link is edge (a LISTENER frontend) → signer (crown). The
        // listener-peer exclusion drops it (that frontend→signer shape needs the purpose marker —
        // the flagged follow-on), so no WS-E serve is designated — the live test is unchanged.
        assert!(
            compute_authority_serve_links(&cfg_with(Some(clean_privsep()))).is_empty(),
            "a listener-frontend → crown link must not be auto-designated for WS-E"
        );
        // split_signer_privsep: the `to-signer` link is sealer ↔ signer — crown ↔ crown (bootstrap
        // unseal), excluded (not exactly-one crown).
        assert!(
            compute_authority_serve_links(&cfg_with(Some(split_signer_privsep()))).is_empty(),
            "a crown ↔ crown bootstrap link must not be designated for WS-E"
        );
    }

    #[test]
    fn authority_serve_links_designate_a_crown_to_nonlistener_relay() {
        // A crown jewel linked to a NON-listener relay (a control-plane client) is the unambiguous
        // WS-E shape: the crown jewel serves its grammar; the relay is the client.
        let mut instances = BTreeMap::new();
        instances.insert(
            "ctl".to_string(),
            inst(&[HostAuthority::ControlAdminApi], &["to-sign"]),
        );
        instances.insert(
            "signer".to_string(),
            inst(&[HostAuthority::TokenSigner], &["to-sign"]),
        );
        let mut links = BTreeMap::new();
        links.insert(
            "to-sign".to_string(),
            PrivsepLink {
                from: "ctl".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Unspecified,
            },
        );
        let p = PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        };
        let out = compute_authority_serve_links(&cfg_with(Some(p)));
        // The crown-jewel SIGNER end is designated to serve WS-E on `to-sign`.
        assert!(
            out.get("signer").is_some_and(|s| s.contains("to-sign")),
            "the crown jewel must serve WS-E on the link to the relay: {out:?}"
        );
        // The relay is the CLIENT — it serves nothing.
        assert!(
            !out.contains_key("ctl"),
            "the relay must not serve: {out:?}"
        );
    }

    /// Security re-review: even a crown↔(control/exec) link that IS designated for WS-E must NOT stand
    /// up a live serve — the stand-up gate refuses it (code-fail-closed) until the Phase-3 wiring-gate
    /// preconditions (PoP/cnf verifier + per-link PURPOSE marker) exist. And the two Phase-1
    /// compositions designate NOTHING, so they never reach the gate (stand up no authority serve).
    #[test]
    fn authority_serve_stand_up_is_code_fail_closed_until_preconditions_met() {
        // A designated crown↔(control relay) composition...
        let mut instances = BTreeMap::new();
        instances.insert(
            "ctl".to_string(),
            inst(&[HostAuthority::ControlAdminApi], &["to-sign"]),
        );
        instances.insert(
            "signer".to_string(),
            inst(&[HostAuthority::TokenSigner], &["to-sign"]),
        );
        let mut links = BTreeMap::new();
        links.insert(
            "to-sign".to_string(),
            PrivsepLink {
                from: "ctl".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Unspecified,
            },
        );
        let cfg = cfg_with(Some(PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        }));
        // ...IS designated (so the designation is not what stops it)...
        assert!(
            compute_authority_serve_links(&cfg)
                .get("signer")
                .is_some_and(|s| s.contains("to-sign")),
            "the crown↔control link must be designated"
        );
        // ...yet the STAND-UP gate refuses it (fail-closed) — no PoP verifier + no purpose marker.
        assert!(
            check_authority_serve_preconditions(&cfg).is_err(),
            "the stand-up gate must refuse until the Phase-3 preconditions are met"
        );

        // The two Phase-1 compositions designate no authority-serve link at all (never reach the gate).
        assert!(compute_authority_serve_links(&cfg_with(Some(clean_privsep()))).is_empty());
        assert!(compute_authority_serve_links(&cfg_with(Some(split_signer_privsep()))).is_empty());
        // An UNMARKED composition is not purpose-marked; the PoP half is the sibling layer's and
        // remains structurally false (so the gate is closed regardless of the marker half).
        assert!(!pop_cnf_verifier_configured(&cfg));
        assert!(!authority_link_purpose_marked(&cfg));
    }

    // ---- Phase-3 foundation: the per-link PURPOSE marker ----

    /// An EXPLICIT `authority-serve` marker on a listener-FRONTEND → signer link (the design's primary
    /// WS-E shape that the conservative inference refused to auto-designate) IS now designated — yet
    /// the stand-up gate STILL refuses it, because the PoP/`cnf` half of the AND-gate (the sibling
    /// authority layer's) is not configured. This is the required invariant: the marker ALONE never
    /// makes the serve go live without PoP.
    #[test]
    fn authority_serve_marker_designates_but_the_and_gate_stays_closed_without_pop() {
        let mut instances = BTreeMap::new();
        instances.insert(
            "frontend".to_string(),
            inst(
                &[
                    HostAuthority::ListenPublicTls,
                    HostAuthority::ListenHttpParse,
                    HostAuthority::ExecWasmtime,
                ],
                &["to-signer"],
            ),
        );
        instances.insert(
            "signer".to_string(),
            inst(&[HostAuthority::TokenSigner], &["to-signer"]),
        );
        let mut links = BTreeMap::new();
        links.insert(
            "to-signer".to_string(),
            PrivsepLink {
                from: "frontend".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::AuthorityServe,
            },
        );
        let cfg = cfg_with(Some(PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        }));

        // The marker designates the crown-jewel SIGNER to serve on the link EVEN THOUGH the peer is a
        // listener frontend (the shape the inference excluded).
        let designated = compute_authority_serve_links(&cfg);
        assert!(
            designated
                .get("signer")
                .is_some_and(|s| s.contains("to-signer")),
            "an authority-serve-marked listener-frontend → signer link must be designated: {designated:?}"
        );
        assert!(
            !designated.contains_key("frontend"),
            "the frontend relay is the caller — it serves nothing: {designated:?}"
        );

        // The purpose-marker half of the AND-gate is now satisfied...
        assert!(authority_link_purpose_marked(&cfg));
        // ...but the PoP/cnf half (the sibling authority layer's) is not, so the gate stays CLOSED.
        assert!(!pop_cnf_verifier_configured(&cfg));
        let err = check_authority_serve_preconditions(&cfg)
            .expect_err("the stand-up gate must still refuse without a PoP/cnf verifier");
        assert!(
            err.contains("PoP"),
            "the only unmet precondition must be the PoP/cnf verifier, got: {err}"
        );
    }

    // ---- Phase-3: the operator-selectable substrate spawn-backend dispatch ----

    #[test]
    fn resolve_spawn_backend_wires_os_process_container_and_the_scoped_vm_frontend() {
        // OS-process is the Phase-1 wired backend; Container is the Phase-3 wired backend (the SIMPLE
        // model — the SAME fork+exec, with the child unsharing NS/IPC/UTS/CGROUP in its pre_exec).
        resolve_spawn_backend(
            "frontend",
            InstanceSubstrate::OsProcess,
            &[HostAuthority::ListenHttpParse],
        )
        .expect("os-process is a wired spawn backend");
        resolve_spawn_backend(
            "core",
            InstanceSubstrate::Container,
            &[HostAuthority::BackendKv],
        )
        .expect("container is a wired spawn backend (Phase-3 simple model)");
        assert!(InstanceSubstrate::OsProcess.is_wired());
        assert!(InstanceSubstrate::Container.is_wired());
        // `Vm` is NOW WIRED for the owner-greenlit scoped first cut (live-proven serve +
        // kill→FailNodeClosed, Security review SHIP). `is_wired` is capability-free; the per-instance VM
        // SCOPE gate is enforced in `resolve_spawn_backend` itself (below) + the `plan_root` S2 lint.
        assert!(InstanceSubstrate::Vm.is_wired());

        // A VM that IS the owner-greenlit scoped shape — a key-free static-parser frontend (group-C
        // `listen.*`-only) — now DISPATCHES (the supervise loop boots the guest + forks the separate
        // `__vm-relay`). No silent OS-process downgrade: an in-scope VM is served as a VM.
        resolve_spawn_backend(
            "edge-vm",
            InstanceSubstrate::Vm,
            &[HostAuthority::ListenHttpParse],
        )
        .expect("a scoped key-free static-parser VM frontend is now a wired spawn backend");

        // A VM that is NOT a key-free static-parser frontend (it holds a backend credential) is OUTSIDE
        // the approved scope entirely — it needs the owner-GATED vsock key-relay, refused fail-closed
        // (defence-in-depth behind `plan_root`'s scope lint). Never a silent OS-process downgrade.
        let oos =
            resolve_spawn_backend("bad-vm", InstanceSubstrate::Vm, &[HostAuthority::BackendKv])
                .unwrap_err();
        let PrivsepError::Supervise(o) = &oos else {
            panic!("a non-scoped vm must be refused as a Supervise error, got {oos:?}");
        };
        assert!(
            o.contains("key-relay") && o.contains("fail-closed"),
            "the out-of-scope VM refusal must name the owner-gated key-relay + stay fail-closed: {o:?}"
        );
        assert!(
            o.contains("OsProcess") && o.contains("Container"),
            "the refusal must offer the wired OsProcess/Container fallbacks: {o:?}"
        );
        // A VM holding BOTH a listener AND a non-listener authority is NOT key-free — still out of scope.
        let mixed = resolve_spawn_backend(
            "mixed-vm",
            InstanceSubstrate::Vm,
            &[HostAuthority::ListenHttpParse, HostAuthority::BackendKv],
        )
        .unwrap_err();
        assert!(
            matches!(&mixed, PrivsepError::Supervise(m) if m.contains("outside the approved scope")),
            "a VM mixing a listener with a backend credential must stay refused out-of-scope: {mixed:?}"
        );
    }

    // ---- Finding 2 (acpi=off Security review): the guest-kernel-config boot-time guard parser ----

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_config_guard_passes_on_the_shipped_preconditions() {
        // The shape the shipped Landlock-V5 `boatramp-vmlinux` config carries: X86_MPPARSE OFF (as a
        // `# ... is not set` line) + VIRTIO_MMIO_CMDLINE_DEVICES=y.
        let config = "\
CONFIG_SECURITY_LANDLOCK=y
# CONFIG_X86_MPPARSE is not set
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_VIRTIO=y
";
        check_kernel_config_preconditions(config)
            .expect("the shipped X86_MPPARSE-off + CMDLINE_DEVICES=y config must PASS");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_config_guard_refuses_x86_mpparse_on() {
        // Mutation: X86_MPPARSE back ON — with acpi=off the kernel hunts for an MPTABLE firecracker
        // never emits, so device IRQs die (the -22 vsock-probe failure). MUST refuse fail-closed.
        let config = "\
CONFIG_X86_MPPARSE=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
";
        let err =
            check_kernel_config_preconditions(config).expect_err("X86_MPPARSE=y must be refused");
        assert!(
            err.contains("X86_MPPARSE") && err.contains("fail-closed"),
            "the refusal must name X86_MPPARSE + stay fail-closed: {err:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_config_guard_refuses_missing_cmdline_devices() {
        // Mutation: CMDLINE_DEVICES dropped — with ACPI off the virtio-mmio devices (vsock included)
        // are never discovered. MUST refuse fail-closed.
        let config = "\
# CONFIG_X86_MPPARSE is not set
# CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES is not set
";
        let err = check_kernel_config_preconditions(config)
            .expect_err("a missing CMDLINE_DEVICES=y must be refused");
        assert!(
            err.contains("VIRTIO_MMIO_CMDLINE_DEVICES") && err.contains("fail-closed"),
            "the refusal must name VIRTIO_MMIO_CMDLINE_DEVICES + stay fail-closed: {err:?}"
        );
    }

    // ---- S1: the separate least-authority `__vm-relay` process boundary contract ----

    #[test]
    fn vm_relay_descriptor_round_trips_through_its_env_value() {
        let d = VmRelayDescriptor {
            label: "edge-parser".to_string(),
            uds_path: PathBuf::from("/run/brvsk-3-4242.sock"),
            guest_port: crate::privsep_vm::DEFAULT_GUEST_VSOCK_PORT,
        };
        let back = VmRelayDescriptor::from_env_value(&d.to_env_value())
            .expect("the non-secret descriptor round-trips through its env value");
        assert_eq!(d, back);
    }

    #[test]
    fn plan_vm_relay_spec_is_secret_blind_and_wires_the_boundary() {
        // A root environment mixing: a kept non-secret (PATH), a kept non-secret BOATRAMP_* overlay,
        // a name-allowlisted-but-secret BOATRAMP_* (scrubbed by the secret screen), a config-DECLARED
        // BYO credential var (scrubbed by the Finding-1 declared set even though `_URL` is no secret
        // suffix), and a plain cloud credential (dropped by the allowlist). NONE of the three secrets
        // may cross to the relay — it splices untrusted client bytes and must carry no credential.
        let parent = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("BOATRAMP_LOG_FORMAT".to_string(), "json".to_string()),
            ("BOATRAMP_SQL_TOKEN".to_string(), "live-token".to_string()),
            (
                "BOATRAMP_MAIN_DB_URL".to_string(),
                "postgres://u:p@h/db".to_string(),
            ),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "AKIA...".to_string()),
        ];
        let declared: BTreeSet<String> = ["BOATRAMP_MAIN_DB_URL".to_string()].into_iter().collect();
        let descriptor = VmRelayDescriptor {
            label: "edge".to_string(),
            uds_path: PathBuf::from("/run/brvsk-3-7.sock"),
            guest_port: 5201,
        };

        let spec = plan_vm_relay_spec("edge", &descriptor, 7, parent, &declared);

        // argv mirrors `__instance`: the internal token + the label, nothing else.
        assert_eq!(
            spec.argv,
            vec![VM_RELAY_SUBCOMMAND.to_string(), "edge".to_string()]
        );
        assert_eq!(spec.label, "edge");

        // Secret-blind: NOT ONE of the three secret-bearing vars crossed to the relay.
        assert!(
            !spec.env.contains_key("BOATRAMP_SQL_TOKEN"),
            "secret token scrubbed"
        );
        assert!(
            !spec.env.contains_key("BOATRAMP_MAIN_DB_URL"),
            "config-declared BYO credential scrubbed (Finding-1 parity)"
        );
        assert!(
            !spec.env.contains_key("AWS_SECRET_ACCESS_KEY"),
            "cloud credential never crosses"
        );
        // The kept non-secrets are present (the relay resolves the same non-secret config the root saw).
        assert_eq!(spec.env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(
            spec.env.get("BOATRAMP_LOG_FORMAT").map(String::as_str),
            Some("json")
        );

        // The non-secret descriptor rode PRIVSEP_VM_RELAY_ENV, intact.
        let back = VmRelayDescriptor::from_env_value(
            spec.env
                .get(PRIVSEP_VM_RELAY_ENV)
                .expect("the descriptor env var is set"),
        )
        .expect("the descriptor parses back");
        assert_eq!(back, descriptor);

        // The pre-bound public TCP listener rode the ONE fd-pass mechanism: links empty, listener=7.
        let fds: PrivsepChildFds = serde_json::from_str(
            spec.env
                .get(PRIVSEP_FDS_ENV)
                .expect("the fd map env var is set"),
        )
        .expect("the fd map parses back");
        assert_eq!(fds.listener, Some(7));
        assert!(
            fds.links.is_empty(),
            "the relay holds no feature-links — only the listener fd"
        );
    }

    /// The `__vm-relay` process installs a profile derived from ITS launch descriptor's vsock UDS (+
    /// its own binary) and NOTHING else — tying the S1 boundary contract (the descriptor) to the
    /// least-authority wall [`run_vm_relay`] installs. Pure (the live seccomp/Landlock install is the
    /// Linux gate): the FS view is exactly own-binary + the ONE UDS (no config/data_dir/key), and the
    /// seccomp shape is the secret-blind relay shape (accept+dial, but no bind/listen/socketpair, no
    /// key-lock, `execve`/`fork` hard-killed).
    #[test]
    fn vm_relay_descriptor_drives_a_least_authority_secret_blind_profile() {
        let exe = PathBuf::from("/usr/local/bin/boatramp");
        let descriptor = VmRelayDescriptor {
            label: "edge".to_string(),
            uds_path: PathBuf::from("/run/brvsk-3-7.sock"),
            guest_port: crate::privsep_vm::DEFAULT_GUEST_VSOCK_PORT,
        };
        // The EXACT derivation `run_vm_relay` performs (own binary + the descriptor's UDS).
        let profile = boatramp_server::sandbox::derive_relay_profile(&exe, &descriptor.uds_path);

        // FS view = own binary (read+execute) + the DIRECTORY holding the ONE vsock UDS, nothing else
        // (Landlock cannot O_PATH-open a socket inode on static-musl, so the relay grants the uds's
        // dedicated per-VM parent dir, which holds only that socket).
        assert_eq!(
            profile.policy.read_only_paths,
            vec![
                exe.clone(),
                descriptor.uds_path.parent().unwrap().to_path_buf()
            ],
            "the relay sees only its own binary + the dir holding the one vsock UDS — no config/data_dir/key"
        );
        assert_eq!(profile.policy.execute_paths, vec![exe]);
        assert!(profile.policy.read_write_paths.is_empty());
        // F1: the relay walls off ALL TCP (Landlock AccessNet, deny-all) — its one legitimate dial
        // is the AF_UNIX vsock UDS, which AccessNet does not govern.
        assert!(
            profile.policy.deny_all_tcp,
            "the __vm-relay profile must deny all TCP (AccessNet) — it dials only the AF_UNIX vsock"
        );

        let allows = |n: &str| profile.seccomp_allow.iter().any(|x| x == n);
        let kills = |n: &str| profile.seccomp_kill.iter().any(|x| x == n);
        // Accepts clients + dials the guest, but binds/listens/execs nothing and locks no key.
        for keep in ["accept4", "connect", "socket", "shutdown"] {
            assert!(allows(keep), "relay keeps the byte-pipe verb {keep}");
        }
        for deny in [
            "bind",
            "listen",
            "socketpair",
            "mlock",
            "munlock",
            "execve",
            "execveat",
        ] {
            assert!(
                !allows(deny),
                "relay must DENY {deny} (secret-blind least-authority)"
            );
        }
        for kill in ["execve", "execveat", "fork", "vfork"] {
            assert!(kills(kill), "relay must hard-kill {kill}");
        }
    }

    /// An explicit `relay` marker (a serving splice) is NEVER designated for the authority grammar —
    /// even on a crown↔non-listener shape that the UNSPECIFIED inference WOULD designate.
    #[test]
    fn relay_marker_is_never_designated_for_the_authority_grammar() {
        let mut instances = BTreeMap::new();
        instances.insert(
            "ctl".to_string(),
            inst(&[HostAuthority::ControlAdminApi], &["to-sign"]),
        );
        instances.insert(
            "signer".to_string(),
            inst(&[HostAuthority::TokenSigner], &["to-sign"]),
        );
        let link = |purpose| {
            let mut links = BTreeMap::new();
            links.insert(
                "to-sign".to_string(),
                PrivsepLink {
                    from: "ctl".to_string(),
                    to: "signer".to_string(),
                    transport: LinkTransport::Local,
                    purpose,
                },
            );
            links
        };
        // Unspecified: the inference designates the crown↔(non-listener) shape.
        let unspec = cfg_with(Some(PrivsepConfig {
            instances: instances.clone(),
            links: link(LinkPurpose::Unspecified),
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        }));
        assert!(
            compute_authority_serve_links(&unspec)
                .get("signer")
                .is_some_and(|s| s.contains("to-sign"))
        );
        // Relay: the SAME topology is NOT designated (an explicit serving splice).
        let relay = cfg_with(Some(PrivsepConfig {
            instances,
            links: link(LinkPurpose::Relay),
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        }));
        assert!(
            compute_authority_serve_links(&relay).is_empty(),
            "a relay-marked link must never be an authority-serve link"
        );
    }

    // ---- Phase-4 WS-C: the static/template partition + the per-tenant registry ----

    fn template_inst(caps: &[HostAuthority], links: &[&str]) -> PrivsepInstanceConfig {
        PrivsepInstanceConfig {
            capabilities: caps.to_vec(),
            sandbox: SandboxPosture::Derived,
            substrate: InstanceSubstrate::OsProcess,
            lifecycle: InstanceLifecycle::PerTenantTemplate,
            links: links.iter().copied().map(String::from).collect(),
        }
    }

    /// A valid Phase-4 WS-C + WS-D composition (union == ALL), with the public parser DE-COUPLED from
    /// spawn + KV (Finding-2): `parser` = `{listen.public-tls, listen.http-parse}` (the most-exposed
    /// instance, NO spawn/KV) forwards client fds inward; `supervisor` =
    /// `{backend.kv, exec.compute, control.admin-api}` (non-public, binds no listener) resolves
    /// Host→project + forks the per-tenant children and holds the control-plane mutation surface off
    /// every public listener (WIDENED Finding-2); `tenant-wasm` = `{exec.wasmtime}` PER-TENANT
    /// TEMPLATE; `core` = crown jewels + the other backends; `aux` = the other listeners + acme.
    /// `parser-sup` relays client fds parser→supervisor; `to-tenant` relays them supervisor→template.
    fn phase4_privsep() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "parser".to_string(),
            inst(
                &[
                    HostAuthority::ListenPublicTls,
                    HostAuthority::ListenHttpParse,
                ],
                &["parser-sup"],
            ),
        );
        instances.insert(
            "supervisor".to_string(),
            inst(
                &[
                    // The non-public per-tenant SUPERVISOR: `backend.kv` to resolve Host→project and
                    // `exec.compute` to fork the per-tenant `exec.wasmtime` children. It binds no
                    // listener and parses no raw client bytes — it is reached over `parser-sup`
                    // (Finding-2: spawn + KV live OFF the public parser). `control.admin-api` rides
                    // here (off every public listener, per the WIDENED Finding-2), not on `aux`.
                    HostAuthority::BackendKv,
                    HostAuthority::ExecCompute,
                    HostAuthority::ControlAdminApi,
                ],
                &["parser-sup", "to-tenant"],
            ),
        );
        instances.insert(
            "tenant-wasm".to_string(),
            template_inst(&[HostAuthority::ExecWasmtime], &["to-tenant"]),
        );
        instances.insert(
            "core".to_string(),
            inst(
                &[
                    HostAuthority::SecretsSealer,
                    HostAuthority::TokenSigner,
                    HostAuthority::ImageSigner,
                    HostAuthority::OverlayDialSigner,
                    HostAuthority::S3IngressRoot,
                    HostAuthority::ClusterJoinSigner,
                    HostAuthority::BackendSql,
                    HostAuthority::BackendBlob,
                    HostAuthority::BackendMessaging,
                ],
                &[],
            ),
        );
        instances.insert(
            "aux".to_string(),
            inst(
                &[
                    HostAuthority::ListenMail,
                    HostAuthority::ListenOverlay,
                    HostAuthority::ListenS3Ingress,
                    HostAuthority::ListenInboundTcp,
                    HostAuthority::ListenGateway,
                    // `acme.dns-control` (cert issuance) is NOT a Finding-2 forbidden partner, so it
                    // may ride the listener instance; `control.admin-api` moved to `supervisor`.
                    HostAuthority::AcmeDnsControl,
                ],
                &[],
            ),
        );
        let mut links = BTreeMap::new();
        links.insert(
            "parser-sup".to_string(),
            PrivsepLink {
                from: "parser".to_string(),
                to: "supervisor".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Relay,
            },
        );
        links.insert(
            "to-tenant".to_string(),
            PrivsepLink {
                from: "supervisor".to_string(),
                to: "tenant-wasm".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::Relay,
            },
        );
        PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
            node_serve: NodeServeMode::default(),
        }
    }

    #[test]
    fn plan_root_partitions_static_instances_from_on_demand_templates() {
        let cfg = cfg_with(Some(phase4_privsep()));
        let plan = plan_root(&cfg, Path::new("/etc/boatramp.cfg"), fake_env())
            .expect("the Phase-4 WS-C composition is authorized");
        // The per-tenant TEMPLATE is in `templates` (instantiated on demand), NOT in the boot fork
        // set `static_instances` (the bug step 2 fixes: a boot-forked template with no wired scope
        // would die Unwired → FailNodeClosed).
        let template_labels: Vec<&str> = plan.templates.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(template_labels, vec!["tenant-wasm"]);
        let static_labels: std::collections::BTreeSet<&str> = plan
            .static_instances
            .iter()
            .map(|s| s.label.as_str())
            .collect();
        assert!(
            !static_labels.contains("tenant-wasm"),
            "a per-tenant template must NOT be in the boot fork set"
        );
        assert_eq!(
            static_labels,
            ["aux", "core", "parser", "supervisor"]
                .into_iter()
                .collect::<std::collections::BTreeSet<&str>>(),
            "every non-template instance is boot-forked"
        );
        // The template's spec still inherits NO secret (the SAME env_clear/scrub contract).
        let t = &plan.templates[0];
        assert!(!t.env.contains_key("VAULT_TOKEN"));
        assert!(!t.env.contains_key("BOATRAMP_AUTH_ROOT_PRIVATE_KEY"));
    }

    #[test]
    fn plan_root_refuses_a_zero_concurrency_policy_when_a_template_exists() {
        // Fail-closed: a per-tenant template composition with max_instances == 0 could never
        // instantiate any tenant — the root refuses BEFORE any spawn.
        let mut p = phase4_privsep();
        p.per_tenant = PerTenantPolicy {
            idle_eviction_secs: 300,
            max_instances: 0,
            ..PerTenantPolicy::default()
        };
        let cfg = cfg_with(Some(p));
        let err = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env()).unwrap_err();
        assert!(
            matches!(err, PrivsepError::PerTenantPolicy(_)),
            "a 0 concurrency cap with a template is a fail-closed refusal, got {err:?}"
        );
    }

    #[test]
    fn plan_root_ignores_the_per_tenant_policy_without_a_template() {
        // A no-template composition never reads the policy — even a (would-be-invalid) 0 cap passes,
        // so every pre-Phase-4 composition is byte-unchanged.
        let mut p = clean_privsep();
        p.per_tenant = PerTenantPolicy {
            idle_eviction_secs: 0,
            max_instances: 0,
            ..PerTenantPolicy::default()
        };
        let cfg = cfg_with(Some(p));
        let plan = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env())
            .expect("a no-template composition ignores the per_tenant policy");
        assert!(plan.templates.is_empty());
        assert_eq!(plan.static_instances.len(), 5);
    }

    /// An empty [`per_tenant::ComputePlaneRegistry`] resolves EVERY scope to `None` — the WS-C
    /// `NotReady` wake/cold-start seam; a tenant with no live instance is NEVER a fallback for
    /// another. (The live instantiate path forks a real `__instance` and is exercised by the Linux
    /// live gate, not here.)
    #[cfg(unix)]
    #[test]
    fn compute_plane_registry_resolves_an_unseen_tenant_to_not_ready() {
        use boatramp_core::privsep::TenantScope;
        use boatramp_server::privsep_tenant::PerTenantInstanceRegistry;

        let spec = InstanceSpawnSpec {
            label: "tenant-wasm".to_string(),
            capabilities: vec![HostAuthority::ExecWasmtime],
            substrate: InstanceSubstrate::OsProcess,
            argv: vec![
                INSTANCE_SUBCOMMAND.to_string(),
                "tenant-wasm".to_string(),
                "--config".to_string(),
                "boatramp.cfg".to_string(),
            ],
            env: BTreeMap::new(),
        };
        let reg = super::per_tenant::ComputePlaneRegistry::new(
            PathBuf::from("/usr/local/bin/boatramp"),
            spec,
            "to-tenant".to_string(),
            PerTenantPolicy::default(),
        );
        let scope = TenantScope::resolve("acme").expect("valid scope");
        assert!(
            reg.resolve(&scope).is_none(),
            "an empty registry must resolve to NotReady, never a fallback instance"
        );
    }

    /// The HIGH de-serialization property, proven portably (no fork / sandbox / fd wiring needed):
    /// the router accepts in an async loop and handles EACH connection in its OWN task, so a silent
    /// (slowloris) peer pins only its own task until the peek deadline — it NEVER blocks the accept
    /// loop or another connection's host-peek. This mirrors the production accept-loop shape
    /// (`accept → spawn one task per conn → `[`per_tenant::...peek_host_async`]). The full live
    /// serve path (real listener fd + SCM_RIGHTS splice + per-tenant fork under the sandbox) stays
    /// on the `#[ignore]` Linux live gate (`privsep_per_tenant_serves_end_to_end`).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_silent_connection_does_not_block_routing_a_second_connection() {
        use std::time::Duration;

        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral local listener");
        let addr = listener.local_addr().expect("local addr");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<String>>();

        // The de-serialized accept loop: accept two connections, each peeked in its own task.
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (conn, _) = listener.accept().await.expect("accept");
                let tx = tx.clone();
                tokio::spawn(async move {
                    let host =
                        super::instance_serve::peek_host_async(&conn, Duration::from_secs(1)).await;
                    let _ = tx.send(host);
                });
            }
        });

        // A: connect and send NOTHING (slowloris). Held open for the whole test so its peek task
        // stays pinned until the 1s deadline.
        let _silent = tokio::net::TcpStream::connect(addr)
            .await
            .expect("silent peer connects");
        // B: connect and send a real request with a Host.
        let mut real = tokio::net::TcpStream::connect(addr)
            .await
            .expect("real peer connects");
        real.write_all(b"GET / HTTP/1.1\r\nHost: acme.example\r\n\r\n")
            .await
            .expect("write the real request");

        // B's host MUST resolve promptly — well within the 1s peek deadline — even though A is still
        // silent. The silent peer can only ever yield `None`, and only after ~1s (past this window),
        // so the first result delivered here is necessarily B's.
        let got = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("a connection resolves promptly despite the silent peer")
            .expect("the channel delivered a result");
        assert_eq!(
            got.as_deref(),
            Some("acme.example"),
            "the real connection routes while the silent peer is still pinned (de-serialized)"
        );

        server.abort();
    }

    // ---- P5-1: the authority-scoped node app-router seam (design §Phase-5 P5-1) ----
    //
    // These are PURE / host-level tests (no fork, no sandbox, no Linux, no live serve path): they
    // exercise the routing DECISION and the drop-in HANDLER shape in isolation on the host. The full
    // self-host serve path stays REFUSED fail-closed at the root gate and on the `#[ignore]` live gate.

    /// The P5-1 router routes ONLY to held authorities and relays everything else — the
    /// "construct-only-what-you-hold" discipline (design §4 item 5), proven structurally:
    /// - a HELD surface ⇒ `Local` (served in-process);
    /// - a non-held CROWN-JEWEL (group A) reachable over a link ⇒ `RelayCrownJewel` (WS-E grammar);
    /// - any other non-held authority reachable over a link ⇒ `RelayBackend` (typed backend request);
    /// - a non-held, UNREACHABLE surface ⇒ `Refuse` fail-closed (a composition-closure bug).
    #[cfg(unix)]
    #[test]
    fn p5_1_node_router_serves_held_relays_the_rest_refuses_unreachable() {
        use super::instance_serve::{NodeRoute, NodeServeRouter};

        // This instance HOLDS backend.kv only; it can REACH the signer (crown jewel, group A), the
        // blob backend (group B) and the control plane (group E) over named root-wired links.
        let gate = MaterializationGate::new(&[HostAuthority::BackendKv]);
        let reachable = BTreeMap::from([
            (HostAuthority::TokenSigner, "to-signer".to_string()),
            (HostAuthority::BackendBlob, "to-blob".to_string()),
            (HostAuthority::ControlAdminApi, "to-control".to_string()),
        ]);
        let router = NodeServeRouter::new(&gate, reachable);

        // HELD ⇒ served locally; it is NEVER relayed.
        assert_eq!(
            router.route(HostAuthority::BackendKv),
            NodeRoute::Local(HostAuthority::BackendKv),
            "a HELD authority must be served locally (construct-only-what-you-hold)"
        );

        // Non-held crown jewel (group A) reachable over a link ⇒ the WS-E crown-jewel grammar relay.
        assert_eq!(
            router.route(HostAuthority::TokenSigner),
            NodeRoute::RelayCrownJewel {
                authority: HostAuthority::TokenSigner,
                link: "to-signer".to_string(),
            },
            "a non-held crown jewel relays over the WS-E authority grammar, never served locally"
        );

        // Non-held data-holder (group B) reachable over a link ⇒ a typed backend request relay.
        assert_eq!(
            router.route(HostAuthority::BackendBlob),
            NodeRoute::RelayBackend {
                authority: HostAuthority::BackendBlob,
                link: "to-blob".to_string(),
            },
            "a non-held backend relays a typed request over its feature-link"
        );

        // Non-held control-plane (group E) reachable over a link ⇒ a typed backend request relay too
        // (control.admin-api is reached by a typed request, not the crown-jewel grammar).
        assert_eq!(
            router.route(HostAuthority::ControlAdminApi),
            NodeRoute::RelayBackend {
                authority: HostAuthority::ControlAdminApi,
                link: "to-control".to_string(),
            },
            "a non-held, non-crown-jewel surface relays a typed request (group E included)"
        );

        // Non-held AND unreachable ⇒ REFUSE fail-closed (never a silent local serve or degraded path).
        assert_eq!(
            router.route(HostAuthority::BackendSql),
            NodeRoute::Refuse(HostAuthority::BackendSql),
            "a surface neither held nor reachable fails the node closed"
        );
    }

    /// The router NEVER serves a non-held authority locally and NEVER relays a held one — the
    /// structural invariant swept across EVERY `HostAuthority`, for an instance holding a mixed set.
    #[cfg(unix)]
    #[test]
    fn p5_1_node_router_never_serves_a_dropped_authority_nor_relays_a_held_one() {
        use super::instance_serve::{NodeRoute, NodeServeRouter};

        // A mixed instance: holds a crown jewel + a backend; everything else is reachable over one
        // shared link (so no surface is `Refuse` — isolating the hold-vs-relay invariant).
        let held = [HostAuthority::SecretsSealer, HostAuthority::BackendKv];
        let gate = MaterializationGate::new(&held);
        let reachable: BTreeMap<HostAuthority, String> = HostAuthority::ALL
            .iter()
            .copied()
            .filter(|a| !held.contains(a))
            .map(|a| (a, "to-peer".to_string()))
            .collect();
        let router = NodeServeRouter::new(&gate, reachable);

        for &a in HostAuthority::ALL {
            let route = router.route(a);
            if held.contains(&a) {
                assert_eq!(
                    route,
                    NodeRoute::Local(a),
                    "{}: a held authority must serve locally, never relay",
                    a.tag()
                );
            } else {
                assert!(
                    !matches!(route, NodeRoute::Local(_)),
                    "{}: a DROPPED authority must never be served locally (it is not constructed)",
                    a.tag()
                );
                // Non-held ⇒ a relay whose kind follows the authority's group (crown jewel ⇒ WS-E
                // grammar, else a backend request).
                match route {
                    NodeRoute::RelayCrownJewel { authority, .. } => {
                        assert!(
                            authority.is_crown_jewel(),
                            "{}: WS-E relay only for group A",
                            a.tag()
                        );
                    }
                    NodeRoute::RelayBackend { authority, .. } => {
                        assert!(
                            !authority.is_crown_jewel(),
                            "{}: a backend-request relay is never a crown jewel",
                            a.tag()
                        );
                    }
                    other => panic!(
                        "{}: expected a relay for a reachable non-held authority, got {other:?}",
                        a.tag()
                    ),
                }
            }
        }
    }

    /// The P5-1 [`NodeServeHandler`] is a valid `boatramp_http::Handler` drop-in: it serves one real
    /// request end-to-end over an in-process `socketpair` (no listener fd, no SCM_RIGHTS splice, no
    /// sandbox), returning the SAME Phase-1 stub `MinimalHandler` does. This proves the router shape at
    /// the serve boundary while P5-1 stays behind the unwired path (no real surface served yet; P5-2
    /// swaps in the request→surface classifier). Host-testable; the live splice path stays on the
    /// `#[ignore]` Linux gate.
    #[cfg(unix)]
    #[tokio::test]
    async fn p5_1_node_serve_handler_drops_into_serve_connection_and_answers_the_stub() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        use super::instance_serve::{NodeServeHandler, NodeServeRouter};

        // Construct the handler the way an instance would: from its gate-derived router.
        let gate = MaterializationGate::new(&[HostAuthority::BackendKv]);
        let router = NodeServeRouter::new(&gate, BTreeMap::new());
        let handler = NodeServeHandler::new(router);

        // An in-process connected pair stands in for the spliced client fd — no fork / listener /
        // SCM_RIGHTS / sandbox needed.
        let (client, server) = tokio::net::UnixStream::pair().expect("socketpair");

        let serve = tokio::spawn(async move {
            // The exact call `serve_client_fd` makes, minus the TcpStream adoption (generic over IO).
            let _ = boatramp_http::serve_connection(server, handler).await;
        });

        let mut client = client;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: node.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("write the request");

        let mut resp = Vec::new();
        client
            .read_to_end(&mut resp)
            .await
            .expect("read the response");
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.starts_with("HTTP/1.1 200"),
            "the NodeServeHandler drop-in answers the stub 200 (got: {:?})",
            &text[..text.len().min(64)]
        );
        assert!(
            text.contains("Phase 1 minimal serve"),
            "P5-1 is still behind the unwired path — identical stub body to MinimalHandler"
        );

        serve.await.expect("serve task joins");
    }
}
