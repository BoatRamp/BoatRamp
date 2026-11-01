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
//! Clean seams for later workstreams (fail-closed — never a silent monolith fallback):
//! - **WS-C follow-on** — `tcp`/`overlay` link transports (only `local` is wired here); the other
//!   `listen.*` fd binds beyond the public listener; the root's OWN tightest self-profile (design
//!   §4.3); and the authority-scoped app router (the minimal backend serve stands in for it).
//! - **WS-D** — the per-capability seccomp/Landlock profile derivation (owned by `sandbox.rs`;
//!   this module CONSUMES it via `derive_profile` + `install_derived` + `enforce_privsep_status`).
//! - **WS-E** — the per-capability authority-API grammar + the re-validated end-principal context
//!   (the link is a BYTE transport here; the grammar layers on [`PrivsepChildFds`]-wired links).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use boatramp_core::privsep::{
    CompositionReport, HostAuthority, PrivsepInstanceConfig, check_composition_closure,
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
    /// One spawn spec per instance (stable order — the `[privsep].instances` map is sorted).
    pub instances: Vec<InstanceSpawnSpec>,
    /// The secret-blindness report (the opaque-reference tally).
    pub secret_blind: SecretBlindReport,
    /// The composition-closure report (any non-fatal flags to log).
    pub composition: CompositionReport,
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

    // 3. The per-instance re-exec spawn spec (F11-B minimal env). Reached ONLY after
    //    both gates pass — so a refused composition yields no spawn spec at all.
    let path_str = config_path.to_string_lossy().into_owned();
    // The config-driven secret-env set (Finding 1): env-var names the config declares as
    // secret references (`url_env`/`password_env`/…), scrubbed from every instance's env.
    let declared_secret_env = privsep_resolve::declared_secret_env_var_names(cfg);
    let instances = privsep
        .instances
        .iter()
        .map(|(label, inst)| {
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
            InstanceSpawnSpec {
                label: label.clone(),
                capabilities: inst.capabilities.clone(),
                argv,
                env,
            }
        })
        .collect();

    Ok(RootPlan {
        instances,
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
        instances = plan.instances.len(),
        opaque_secret_refs = plan.secret_blind.opaque_reference_count,
        "[privsep] root: composition authorized (secret-blind + closure-lint clean); the root \
         holds bootstrap authority only"
    );
    for spec in &plan.instances {
        tracing::info!(
            instance = %spec.label,
            capabilities = spec.capabilities.len(),
            env_vars = spec.env.len(),
            "[privsep] root: instance authorized to spawn (re-exec __instance, minimal scrubbed env)"
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
    supervise::run(&config, &plan).map_err(Into::into)
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

/// Run a feature-instance (`boatramp __instance <label>`, or the root's spawned child):
/// resolve its slice, build its materialization gate, log the held/dropped authorities,
/// then stop at the WS-C serving seam. Refuses a non-privsep node / an unknown label
/// (design F10, §2).
pub fn run_instance(label: &str, config_path: &Path) -> Result<(), CliError> {
    crate::init_tracing();
    // Scrub any inherited live credential from this instance's own environ (inv10). The
    // root already spawns children with an explicitly-minimal scrubbed env, so for a
    // root-spawned child this is a no-op; it backstops the explicit `boatramp __instance`
    // entry, which inherits the full parent environ.
    scrub_own_environ();

    // Privsep's load-bearing wall is the per-instance Enforced sandbox; on any non-Linux /
    // non-`sandbox` build an instance cannot install it, so refuse to serve rather than run
    // unsandboxed — including the dev-only `Off` posture. The root already refuses off-Linux at
    // spawn; this backstops a manual `boatramp __instance` invocation for consistency (Security
    // re-review INFO), so no privsep instance ever serves unsandboxed on a non-Linux Unix host.
    if !cfg!(all(target_os = "linux", feature = "sandbox")) {
        return Err(PrivsepError::UnsupportedPlatform.into());
    }

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
        "[privsep] instance: slice resolved; materialization gate built (dropped authorities are \
         never constructed)"
    );

    let fail = |reason: String| PrivsepError::InstanceServe {
        label: label.to_string(),
        reason,
    };

    // Step 3 (design §2.1): install the per-capability seccomp/Landlock profile BEFORE the
    // runtime, fail-closed `Enforced` fleetwide. Done on THIS single main thread so every Tokio
    // worker thread later inherits the domain via `clone`.
    let cwd = std::env::current_dir().map_err(|e| fail(format!("cwd: {e}")))?;
    let data_dir = normalized_data_dir(&config, &cwd);
    // Pre-create this instance's OWN state subtrees so the derivation's `fs::canonicalize` resolves
    // them (Contract #1): a holder's grant canonicalizes through any symlink before the Landlock
    // wall (which this instance has not yet installed) goes up. Best-effort — a path that cannot be
    // created stays lexical and is still leak-checked lexically.
    let held_set: BTreeSet<HostAuthority> = inst.capabilities.iter().copied().collect();
    for dir in boatramp_server::sandbox::instance_backend_state_grants(&held_set, &data_dir) {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::debug!(?dir, error = %e, "[privsep] could not pre-create own state dir (will stay lexical)");
        }
    }
    let inputs = privsep_resolve::build_instance_sandbox_inputs(
        &config,
        &inst.capabilities,
        config_path,
        &cwd,
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
        boatramp_server::sandbox::privsep_install_plan(inst.sandbox, node_allows_unsandboxed)
            .map_err(|e| fail(e.to_string()))?;
    match install_plan {
        boatramp_server::sandbox::PrivsepInstallPlan::InstallEnforced(posture) => {
            let profile = boatramp_server::sandbox::derive_profile(&held_set, posture, &inputs)
                .map_err(|e| fail(e.to_string()))?;
            let status = boatramp_server::sandbox::install_derived(&profile);
            // Fail-closed FLEETWIDE: anything less than `Enforced` refuses (design §2 F6 / inv7).
            let status = boatramp_server::sandbox::enforce_privsep_status(status)
                .map_err(|e| fail(e.to_string()))?;
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

    // Steps 5-6 (design §2.1): open the instance's links over the inherited socketpair fds, then
    // serve its slice. The materialization gate (above) is the construction wall; the link
    // mediation + the profile are the other two defence-in-depth layers.
    let fds = PrivsepChildFds::from_env().map_err(&fail)?;
    instance_serve::run(label, &gate, &fds).map_err(|e| fail(e).into())
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
// The root supervisor: socketpair wiring + privileged listener bind + fork/exec + supervise
// =============================================================================

#[cfg(unix)]
mod supervise {
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::process::CommandExt;

    use boatramp_core::privsep::LinkTransport;
    use boatramp_server::privsep_link::LinkEndpoint;

    use super::{PrivsepChildFds, PrivsepError, RootPlan, ServerConfig};

    /// Run the root supervisor over the AUTHORIZED `plan` (design §4): create a `socketpair(2)` per
    /// `local` link, bind the privileged public listeners, `fork`+`exec` one `__instance` per
    /// authorized instance passing it only its own link ends + listener fd, then supervise
    /// fail-closed (`FailNodeClosed` — any child exit tears the node down). The root holds bootstrap
    /// authority only: it parses no bytes, opens no pool, unseals no key.
    pub(super) fn run(config: &ServerConfig, plan: &RootPlan) -> Result<(), PrivsepError> {
        let err = |m: String| PrivsepError::Supervise(m);
        let privsep = config
            .privsep
            .as_ref()
            .ok_or_else(|| err("no [privsep] section at supervise time".to_string()))?;
        let current_exe =
            std::env::current_exe().map_err(|e| err(format!("resolving current exe: {e}")))?;

        // 1. A root-created socketpair(2) per `local` link; one end to each endpoint instance.
        //    `tcp`/`overlay` carry their own endpoint arrangement — not wired in the Phase-1 cut
        //    (design §6: local + tcp first; this WS lands the `local` default). Refuse, fail-closed.
        let mut links_by_instance: std::collections::BTreeMap<String, Vec<(String, LinkEndpoint)>> =
            std::collections::BTreeMap::new();
        for (lname, link) in &privsep.links {
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

        // 4. `fork`+`exec` each `__instance` with its scrubbed env (already built, F11-B) + the fd
        //    map, duping its ends onto the fixed targets in `pre_exec`.
        let mut children: Vec<(String, std::process::Child)> = Vec::new();
        for spec in &plan.instances {
            let Some(wiring) = wirings.iter().find(|w| w.label == spec.label) else {
                continue;
            };
            let mut cmd = spec.to_command(&current_exe);
            cmd.env(super::PRIVSEP_FDS_ENV, wiring.fds.to_env_value());
            let dups = wiring.dups.clone();
            // SAFETY: `pre_exec` runs post-`fork`/pre-`exec`; `dup2`/`fcntl`/`prctl` are
            // async-signal-safe and touch only this child's fd table + death-signal. The target
            // fds are above every source, so no `dup2` clobbers a not-yet-processed source.
            unsafe {
                cmd.pre_exec(move || {
                    for (src, tgt) in &dups {
                        if *src != *tgt && libc::dup2(*src, *tgt) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        // Clear CLOEXEC on the target so it survives the exec (dup2 already clears
                        // it for a distinct target; this also covers the src == tgt no-op case).
                        let flags = libc::fcntl(*tgt, libc::F_GETFD);
                        if flags < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::fcntl(*tgt, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    // FailNodeClosed robustness: if the root dies, the kernel kills this instance
                    // (so a crashed root never leaves authority-holding instances orphaned). Linux
                    // only; a best-effort hardening, not the containment itself.
                    #[cfg(target_os = "linux")]
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            match cmd.spawn() {
                Ok(child) => {
                    tracing::info!(instance = %spec.label, pid = child.id(), "[privsep] root: spawned __instance (fds wired, scrubbed env)");
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

        // 5. Supervise, fail-closed: any child exit tears the whole node down (crown-jewel
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
    use super::{PrivsepError, RootPlan, ServerConfig};

    pub(super) fn run(_config: &ServerConfig, _plan: &RootPlan) -> Result<(), PrivsepError> {
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
    use std::net::SocketAddr;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};

    use boatramp_server::privsep_link::LinkEndpoint;

    use super::{MaterializationGate, PrivsepChildFds};

    /// Serve one instance's slice over its root-wired fds (design §2.1 steps 5-6). The Phase-1
    /// minimal-but-real path demonstrating a 2-instance composition end-to-end:
    /// - a `listen.*` instance (has a listener fd) ACCEPTS on the inherited listener and splices
    ///   each accepted CLIENT connection fd to the backend over the local link (`SCM_RIGHTS`);
    /// - a backend instance (has a link, no listener) RECEIVES those client fds and serves each
    ///   with the hand-rolled HTTP stack (`boatramp_http::serve_connection`) — the SAME serving
    ///   machinery the monolith uses, with a minimal handler (the full authority-scoped app router
    ///   is the authority-serve follow-on);
    /// - any other instance (e.g. a signer awaiting authority calls) holds its authorities inert
    ///   and parks (the per-capability authority-API grammar over the link is WS-E).
    pub(super) fn run(
        label: &str,
        gate: &MaterializationGate,
        fds: &PrivsepChildFds,
    ) -> Result<(), String> {
        tracing::info!(
            instance = %label,
            held = gate.held().count(),
            links = fds.links.len(),
            listener = fds.listener.is_some(),
            "[privsep] instance: opening its root-wired links + serving its slice"
        );
        if let Some(listener_fd) = fds.listener {
            let link_fd = *fds.links.values().next().ok_or_else(|| {
                "a listener instance has no feature-link to forward client connections over \
                 (the composition must link it to a backend)"
                    .to_string()
            })?;
            run_frontend(label, listener_fd, link_fd)
        } else if let Some((lname, link_fd)) = fds.links.iter().next() {
            run_backend(label, lname, *link_fd)
        } else {
            tracing::info!(
                instance = %label,
                "[privsep] instance: no listener/link to serve in the Phase-1 cut — holding its \
                 authorities inert (its authority-API grammar over the link is WS-E)"
            );
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
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
    /// handler. The full authority-scoped app router is the authority-serve follow-on.
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
    /// with the sandbox enforced in both instances. The authority-scoped app router is a follow-on.
    struct MinimalHandler;

    impl boatramp_http::Handler for MinimalHandler {
        async fn handle(&self, _req: boatramp_http::Request) -> boatramp_http::Response {
            boatramp_http::response(
                200,
                b"boatramp privsep backend instance (Phase 1 minimal serve)\n".to_vec(),
            )
        }
    }
}

#[cfg(not(unix))]
mod instance_serve {
    use super::{MaterializationGate, PrivsepChildFds};

    pub(super) fn run(
        _label: &str,
        _gate: &MaterializationGate,
        _fds: &PrivsepChildFds,
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
    use boatramp_core::privsep::{LinkTransport, PrivsepConfig, PrivsepLink, SandboxPosture};

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
            links: links.iter().copied().map(String::from).collect(),
        }
    }

    /// A clean least-authority composition whose union == ALL (edge=C∪D∪E, data=B, signer=A).
    fn clean_privsep() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "edge".to_string(),
            inst(
                &[
                    HostAuthority::ListenPublicTls,
                    HostAuthority::ListenHttpParse,
                    HostAuthority::ListenMail,
                    HostAuthority::ListenOverlay,
                    HostAuthority::ListenS3Ingress,
                    HostAuthority::ListenInboundTcp,
                    HostAuthority::ListenGateway,
                    HostAuthority::ExecWasmtime,
                    HostAuthority::ExecCompute,
                    HostAuthority::ControlAdminApi,
                    HostAuthority::AcmeDnsControl,
                ],
                &["to-signer"],
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
            },
        );
        PrivsepConfig {
            instances,
            links,
            supervisor: None,
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
        assert_eq!(plan.instances.len(), 3);
        for spec in &plan.instances {
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
        let spec = &plan.instances[0];
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
}
