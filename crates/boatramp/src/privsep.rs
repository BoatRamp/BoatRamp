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
    CompositionReport, HostAuthority, InstanceSubstrate, LinkPurpose, PrivsepInstanceConfig,
    check_composition_closure, check_sealed_signer_closure,
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
    /// backend"). The supervisor dispatches on it: `OsProcess` is the wired fork+exec backend;
    /// `Container`/`Vm` are refused fail-closed by [`resolve_spawn_backend`] until their
    /// compute-plane-backend wiring lands (a reported follow-on).
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
        substrate = inst.substrate.tag(),
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
    // The per-tenant router (`exec.compute`) re-execs THIS binary to fork per-tenant children, so
    // it needs its own executable Landlock read+EXECUTE-pinned — exactly like the root
    // (`sandbox::root_supervisor_policy`). Resolve it the SAME way the root does
    // (`std::env::current_exe()`) and fail CLOSED on a resolve error (the node refuses to serve);
    // a non-`exec.compute` instance needs no execute grant, so it is not resolved and stays `None`.
    let exec_self = if held_set.contains(&HostAuthority::ExecCompute) {
        Some(std::env::current_exe().map_err(|e| fail(format!("resolving current exe: {e}")))?)
    } else {
        None
    };
    let inputs = privsep_resolve::build_instance_sandbox_inputs(
        &config,
        &inst.capabilities,
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
    let fds = PrivsepChildFds::from_env().map_err(fail)?;
    instance_serve::run(label, &gate, &fds, &config, config_path).map_err(|e| fail(e).into())
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

/// The per-instance SPAWN-BACKEND dispatch for the operator-selectable isolation SUBSTRATE (design §7
/// generalizing seam — "substrate is a spawn backend"). The root calls this for EACH instance BEFORE
/// wiring any links / binding any listener, so a composition that selects an unwired substrate is
/// refused fail-closed before anything is allocated — never spawned part-way, never silently
/// downgraded to an OS process (which would discard the operator's chosen isolation wall).
///
/// **Phase-3 FOUNDATION scope.** [`InstanceSubstrate::OsProcess`] is the WIRED backend (the root's
/// `fork`+`exec` over the `local` socketpair, below). [`InstanceSubstrate::Container`] and
/// [`InstanceSubstrate::Vm`] are the config vocabulary + this seam: they reuse the
/// `boatramp-container` and `boatramp-firecracker` / `boatramp-vz` compute-plane backends
/// respectively, whose supervisor wiring (the container/VM socketpair-equivalent — a vsock crossing
/// for a VM; see `docs/privsep-substrate-benchmark.md` for the measured cost) is a reported follow-on.
/// Until then this refuses them, naming the backend each reuses. Pure (host-testable).
fn resolve_spawn_backend(label: &str, substrate: InstanceSubstrate) -> Result<(), PrivsepError> {
    if substrate.is_wired() {
        return Ok(());
    }
    let backend = substrate.compute_plane_backend().unwrap_or("(none)");
    Err(PrivsepError::Supervise(format!(
        "instance {label:?} selects the {:?} isolation substrate, whose spawn backend is not wired in \
         the Phase-3 foundation cut (it reuses {backend} — a reported follow-on). Refusing \
         fail-closed rather than silently downgrading to an OS process (which would discard the \
         chosen isolation wall); use `substrate: OsProcess` (the default) until the {} backend lands",
        substrate.tag(),
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
    let holds = |label: &str, authority: HostAuthority| -> bool {
        privsep
            .instances
            .get(label)
            .is_some_and(|i| i.capabilities.contains(&authority))
    };
    for (link_name, link) in &privsep.links {
        // A self-link, or a link between two instances that are the same label, wires nothing.
        if link.from == link.to {
            continue;
        }
        // The SEALER end of a sealer↔(separate)signer link may unseal the signer key ref over it.
        if holds(&link.from, HostAuthority::SecretsSealer)
            && holds(&link.to, HostAuthority::TokenSigner)
        {
            out.entry(link.from.clone())
                .or_default()
                .allow(link_name.clone(), key_ref.to_string());
        }
        if holds(&link.to, HostAuthority::SecretsSealer)
            && holds(&link.from, HostAuthority::TokenSigner)
        {
            out.entry(link.to.clone())
                .or_default()
                .allow(link_name.clone(), key_ref.to_string());
        }
    }
    out
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

    use super::{InstanceSpawnSpec, PRIVSEP_FDS_ENV, PrivsepChildFds};

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

    /// The root supervisor's OWN fork+exec spawn primitive (design §2 / §4.1) — EXTRACTED (WS-C step
    /// 1) from the boot supervisor's spawn loop so the boot supervisor AND the per-tenant router
    /// instantiate an `__instance` the EXACT same way: re-exec the current binary with the spec's
    /// minimal secret-scrubbed env (F11-B `env_clear`), add `extra_env` (the fd map, the tenant
    /// scope), and in the child's `pre_exec` `dup2` each `(src → tgt)` onto its fixed target + clear
    /// `CLOEXEC` so it survives the exec, then `PR_SET_PDEATHSIG(SIGKILL)` (Linux) so a dead parent
    /// takes the child with it (no orphaned authority-holding instance). A `(src, tgt)` with
    /// `src == tgt` clears `CLOEXEC` in place WITHOUT a dup2 — how the router passes a single link fd
    /// at its own number, avoiding a target collision in its crowded fd table. The `dup2`/`fcntl`
    /// machinery is POSIX; only `PR_SET_PDEATHSIG` is Linux-gated.
    pub(super) fn spawn_wired_instance(
        current_exe: &Path,
        spec: &InstanceSpawnSpec,
        dups: Vec<(RawFd, RawFd)>,
        extra_env: &BTreeMap<String, String>,
    ) -> std::io::Result<std::process::Child> {
        let mut cmd = spec.to_command(current_exe);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        // SAFETY: `pre_exec` runs post-`fork`/pre-`exec`; `dup2`/`fcntl`/`prctl` are
        // async-signal-safe and touch only this child's fd table + death-signal. The caller assigns
        // target fds above every source (boot path) or uses `src == tgt` (per-tenant single link),
        // so no `dup2` clobbers a not-yet-processed source.
        unsafe {
            cmd.pre_exec(move || {
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
    }

    /// One live per-tenant instance the router is pooling.
    struct LiveInstance {
        link: TenantInstanceLink,
        child: std::process::Child,
        last_used: Instant,
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
        /// The scale-to-zero policy (idle-eviction window + concurrency cap).
        policy: PerTenantPolicy,
        /// The live instances, keyed by project. Interior-mutable so `resolve`/`instantiate` take
        /// `&self` (the trait object + the router accept loop share one `&registry`).
        live: Mutex<BTreeMap<String, LiveInstance>>,
    }

    impl ComputePlaneRegistry {
        /// Build a registry over the authorized template spec + the declared relay link + the policy.
        pub(super) fn new(
            current_exe: PathBuf,
            template_spec: InstanceSpawnSpec,
            link_name: String,
            policy: PerTenantPolicy,
        ) -> Self {
            Self {
                current_exe,
                template_spec,
                link_name,
                policy,
                live: Mutex::new(BTreeMap::new()),
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
            // Scale-to-zero: reap exited + evict idle, then enforce the cap (LRU) BEFORE inserting.
            Self::sweep(&mut live, &self.policy);
            Self::enforce_cap(&mut live, self.policy.max_instances);
            // LAZY per-tenant socketpair (never shared, never at boot). `front` stays with the router
            // (the relay half); `back` is handed to the child at its own fd number.
            let (front, back) =
                LinkEndpoint::socketpair().map_err(|e| InstantiateError::Socketpair {
                    project: scope.project().to_string(),
                    source: e,
                })?;
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
            let child = spawn_wired_instance(
                &self.current_exe,
                &self.template_spec,
                vec![(back_fd, back_fd)],
                &extra_env,
            )
            .map_err(|e| InstantiateError::Spawn {
                project: scope.project().to_string(),
                source: e,
            })?;
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
            let Some(inst) = live.get_mut(scope.project()) else {
                return None;
            };
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

        // Phase-3 spawn-backend dispatch (design §7 "substrate is a spawn backend"): resolve EACH
        // instance's isolation substrate BEFORE wiring/binding/spawning anything. OS-process is the
        // wired Phase-1 backend; container/VM are refused fail-closed here (never a partial spawn,
        // never a silent downgrade) until their compute-plane-backend wiring lands (a follow-on).
        for (label, inst) in &privsep.instances {
            super::resolve_spawn_backend(label, inst.substrate)?;
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
        let mut children: Vec<(String, std::process::Child)> = Vec::new();
        for spec in &plan.static_instances {
            let Some(wiring) = wirings.iter().find(|w| w.label == spec.label) else {
                continue;
            };
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
            match super::per_tenant::spawn_wired_instance(
                &current_exe,
                spec,
                wiring.dups.clone(),
                &extra_env,
            ) {
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
        let exe_norm = normalize_for_landlock(&current_exe, &cwd);
        let config_norm = normalize_for_landlock(config_path, &cwd);
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

    /// Make `raw` absolute (against `cwd`) + lexically normalized, then `fs::canonicalize` it if it
    /// already exists (resolving symlinks) — the SAME transform
    /// [`boatramp_server::sandbox::SandboxDerivationInputs::into_normalized`] applies to every
    /// instance's grants (WS-C contract #1), so the root's fd-based Landlock install grants the
    /// REAL config-file / own-binary paths and a `..`/symlink/relative spelling cannot slip a
    /// different path past the (lexical) policy. `current_exe()` is already absolute + canonical;
    /// the config path may be relative (the serve default `boatramp.cfg`).
    fn normalize_for_landlock(raw: &Path, cwd: &Path) -> std::path::PathBuf {
        let abs = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            cwd.join(raw)
        };
        let lexical = boatramp_server::sandbox::lexically_normalize(&abs);
        std::fs::canonicalize(&lexical).unwrap_or(lexical)
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
    use std::net::SocketAddr;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::sync::Arc;

    use boatramp_core::cose::{Signer, TokenPublicKey};
    use boatramp_core::privsep::HostAuthority;
    use boatramp_server::privsep_authority::{
        AuthorityAudit, AuthorityRateLimiter, AuthorityRegistry, AuthorityServe, ContextVerifier,
        DEFAULT_CONTEXT_MAX_AGE_SECS, DEFAULT_LINK_READ_DEADLINE, DEFAULT_MAX_IN_FLIGHT,
        DurableAudit, ReplayCache, SealerHandler, SignerHandler, TokenBucketLimiter,
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
            // PER-TENANT ROUTER FRONTEND (WS-C step 5): when the composition defines a per-tenant
            // template, the public-listener holder is the per-tenant ROUTER — it resolves each
            // connection's Host → project (Stage-0), routes to that tenant's instance, instantiating
            // on a NotReady cold-start, and relays the client fd. Opt-in: fires ONLY with a template.
            if has_template {
                return run_per_tenant_frontend(label, gate, listener_fd, config, config_path);
            }
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
            // Split signer: ask the sealer over its single feature-link.
            let (lname, link_fd) = fds.links.iter().next().ok_or_else(|| {
                "a sealed-key signer instance has no feature-link to a secrets.sealer (the \
                     composition-closure lint requires one)"
                    .to_string()
            })?;
            tracing::info!(instance = %label, link = %lname, "[privsep] signer: asking the sealer to unseal its signing key over the link");
            // SAFETY: `link_fd` is the fd the root dup'd into this child + named in the fd map.
            let link = unsafe { LinkEndpoint::from_inherited_fd(*link_fd) };
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
            );
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
            );
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
                // sink (shared across links, cloned in above) — the Wave-1 defaults are gone.
                let serve = AuthorityServe {
                    verifier: &verifier,
                    replay: &replay,
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

    /// The PER-TENANT ROUTER frontend (WS-C step 5): accept on the inherited listener, resolve each
    /// connection's `Host` → project (Stage-0, before any guest byte — via a `MSG_PEEK` that consumes
    /// NOTHING, so the backend re-reads the full request), route to that tenant's instance, and relay
    /// the accepted CLIENT fd. On a [`RouteOutcome::NotReady`] cold-start, INSTANTIATE the tenant's
    /// instance (lazy socketpair + fork via the root's own primitive) then relay. On a `RouteRefusal`,
    /// REFUSE the connection fail-closed — never a wildcard, a default site, or a fallback tenant. The
    /// accepted fd confers no authority (F5); the tenant is taken ONLY from the host resolution, never
    /// a guest field (the router has no parameter by which a guest could name a tenant).
    fn run_per_tenant_frontend(
        label: &str,
        gate: &MaterializationGate,
        listener_fd: i32,
        config: &ServerConfig,
        config_path: &Path,
    ) -> Result<(), String> {
        // The router resolves Host→project via the control-plane KV (the SAME source of truth the
        // monolith uses). WS-C requires the router to be the SOLE `backend.kv` holder so opening the
        // KV here does not DOUBLE-OPEN the single-writer control-plane store. A router that holds no
        // backend.kv cannot resolve hosts → fail-closed (resolving host over a link to a separate
        // backend.kv holder is the WS-D/WS-E per-tenant backend-call extension — flagged, not built).
        if !gate.may_materialize(HostAuthority::BackendKv) {
            return Err(
                "per-tenant router holds no `backend.kv` — it cannot resolve Host→project to a \
                 tenant. Co-locate `backend.kv` on the router (the sole KV opener), or await the \
                 WS-D host-resolution-over-a-link extension"
                    .to_string(),
            );
        }
        // Re-derive the authorized plan IN THE ROUTER so the template's spawn spec is built by the
        // SAME secret-scrubbed contract (F11-B) the root used (the router's own env is already
        // scrubbed, and `build_instance_env` filters further) — a per-tenant child inherits NO secret.
        let parent_env: Vec<(String, String)> = std::env::vars().collect();
        let plan = super::plan_root(config, config_path, parent_env).map_err(|e| e.to_string())?;
        let template_spec = plan.templates.into_iter().next().ok_or_else(|| {
            "the composition defines no per-tenant template spec (a WS-C router needs one)"
                .to_string()
        })?;
        let link_name = per_tenant_relay_link_name(config, label, &template_spec.label)?;
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
            let deploy = build_routing_deploy_store(config).await?;
            let registry =
                ComputePlaneRegistry::new(current_exe, template_spec, link_name, policy);
            // Mark the root-passed listener CLOEXEC so per-tenant children the router forks never
            // INHERIT it (F5 — it is NOT CLOEXEC, having survived the router's own exec).
            set_cloexec(listener_fd).map_err(|e| format!("CLOEXEC on the listener fd: {e}"))?;
            // SAFETY: `listener_fd` is the fd the root dup'd into this child + named in the fd map.
            let listener = unsafe { std::net::TcpListener::from_raw_fd(listener_fd) };
            tracing::info!(
                instance = %label,
                idle_evict_secs = policy.idle_eviction_secs,
                max_instances = policy.max_instances,
                "[privsep] per-tenant router: accepting; resolving Host→project (Stage-0) + routing to \
                 per-tenant instances (fail-closed — no wildcard / default / fallback tenant)"
            );
            loop {
                let (conn, _peer) = listener
                    .accept()
                    .map_err(|e| format!("accepting on the listener: {e}"))?;
                // Stage-0: PEEK (consume NOTHING) just enough to parse the Host, BEFORE any guest byte;
                // the full request still reaches the backend intact over the spliced fd.
                let host = peek_host(&conn).unwrap_or_default();
                match route_by_host(&deploy, &host, &registry).await {
                    Ok(RouteOutcome::Routed(link)) => relay_client_to_tenant(&link, &conn),
                    Ok(RouteOutcome::NotReady(scope)) => match registry.instantiate(&scope) {
                        Ok(link) => relay_client_to_tenant(&link, &conn),
                        Err(e) => tracing::error!(
                            project = %scope.project(),
                            error = %e,
                            "[privsep] per-tenant router: cold-start instantiate FAILED — refusing the \
                             connection (fail-closed)"
                        ),
                    },
                    Err(refusal) => tracing::warn!(
                        host = %host,
                        %refusal,
                        "[privsep] per-tenant router: refusing a connection (fail-closed, no fallback \
                         tenant)"
                    ),
                }
                // Our copy: a relay SCM_RIGHTS-duplicated it to the tenant; a refusal closes it here.
                drop(conn);
            }
        })
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

    /// `MSG_PEEK` the start of an HTTP/1.x request to extract the `Host` header, consuming NOTHING so
    /// the full request still reaches the backend over the spliced fd. Bounded by a read deadline + a
    /// header cap (a slow/short peer cannot pin the accept loop). `None` ⇒ no Host within the bound
    /// (the router then refuses fail-closed). HTTP/2 / TLS-SNI host extraction is a WS-D follow-on; the
    /// Phase-1 backend + the live gate use plaintext HTTP/1.1.
    fn peek_host(conn: &std::net::TcpStream) -> Option<String> {
        // Bound the peek so a stalled peer cannot pin the loop (slowloris). Best-effort.
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut buf = [0u8; 8192];
        for _ in 0..16 {
            let n = conn.peek(&mut buf).ok()?;
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
            // Otherwise more bytes may still be arriving: peek again (it re-reads from the start).
        }
        None
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
        InstanceLifecycle, InstanceSubstrate, LinkPurpose, LinkTransport, PerTenantPolicy,
        PrivsepConfig, PrivsepLink, SandboxPosture,
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
                purpose: LinkPurpose::Unspecified,
            },
        );
        PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
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
        // clean_privsep has NO per-tenant template, so all three instances are STATIC (boot-forked).
        assert_eq!(plan.static_instances.len(), 3);
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

    // ---- Phase-3 foundation: the operator-selectable substrate spawn-backend seam ----

    #[test]
    fn resolve_spawn_backend_wires_os_process_and_refuses_the_follow_on_substrates() {
        // OS-process is the wired Phase-1 backend.
        resolve_spawn_backend("frontend", InstanceSubstrate::OsProcess)
            .expect("os-process is the wired spawn backend");
        // Container + VM are refused fail-closed, naming the compute-plane backend each reuses.
        let c = resolve_spawn_backend("frontend", InstanceSubstrate::Container).unwrap_err();
        assert!(
            matches!(&c, PrivsepError::Supervise(m) if m.contains("boatramp-container") && m.contains("fail-closed")),
            "container must be refused with its reuse backend named, got {c:?}"
        );
        let v = resolve_spawn_backend("frontend", InstanceSubstrate::Vm).unwrap_err();
        assert!(
            matches!(&v, PrivsepError::Supervise(m) if m.contains("firecracker") && m.contains("OsProcess")),
            "vm must be refused with its reuse backend named + the OsProcess fallback, got {v:?}"
        );
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

    /// A valid Phase-4 WS-C composition (union == ALL): `router` = listeners + `backend.kv` (the
    /// per-tenant router + sole KV opener), `tenant-wasm` = `{exec.wasmtime}` PER-TENANT TEMPLATE,
    /// `core` = crown jewels + the other backends, `aux` = the other listeners + exec.compute +
    /// control. A `to-tenant` relay link connects the router and the template.
    fn phase4_privsep() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "router".to_string(),
            inst(
                &[
                    HostAuthority::ListenPublicTls,
                    HostAuthority::ListenHttpParse,
                    HostAuthority::BackendKv,
                    // `exec.compute` = the compute-plane spawn authority: it is what legitimately
                    // grants the router `execve` (the per-capability profile kills `execve` for
                    // every instance EXCEPT the root + `exec.compute` holders) so it can fork the
                    // per-tenant `exec.wasmtime` instances. NOT co-resident with `exec.wasmtime`
                    // (that lives only on the template), so the Phase-4 lint is satisfied.
                    HostAuthority::ExecCompute,
                ],
                &["to-tenant"],
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
                    HostAuthority::ControlAdminApi,
                    HostAuthority::AcmeDnsControl,
                ],
                &[],
            ),
        );
        let mut links = BTreeMap::new();
        links.insert(
            "to-tenant".to_string(),
            PrivsepLink {
                from: "router".to_string(),
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
            ["aux", "core", "router"]
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
        };
        let cfg = cfg_with(Some(p));
        let plan = plan_root(&cfg, Path::new("boatramp.cfg"), fake_env())
            .expect("a no-template composition ignores the per_tenant policy");
        assert!(plan.templates.is_empty());
        assert_eq!(plan.static_instances.len(), 3);
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
}
