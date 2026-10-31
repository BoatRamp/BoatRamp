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
//! Clean seams for later workstreams (fail-closed — never a silent monolith fallback):
//! - **WS-C** — the feature-link transport (`local` socketpair + `SCM_RIGHTS` fd-pass,
//!   `tcp`, `overlay`), the privileged listener-fd bind + pass, and the supervise loop
//!   (restart / health / shutdown). The root logs the AUTHORIZED plan and stops at
//!   this seam; the instance builds its gate and stops at its serving seam.
//! - **WS-D** — the per-capability seccomp/Landlock profile derivation + fail-closed
//!   `Enforced` install (this module does NOT touch `sandbox.rs` or the `SandboxPosture`
//!   types; it only reads WS-A's per-instance `SandboxPosture`).
//! - **WS-E** — the per-capability authority-API grammar + the re-validated
//!   end-principal context.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use boatramp_core::privsep::{
    CompositionReport, HostAuthority, PrivsepInstanceConfig, check_composition_closure,
};
use boatramp_node::privsep_resolve::{self, SecretBlindReport};

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
    /// WS-C seam: the composition is AUTHORIZED, but the feature-link transport +
    /// supervise loop are the next workstream. Fail-closed (never a monolith fallback).
    #[error(
        "privsep root: composition authorized ({instances} instance(s)) — the feature-link \
         transport (socketpair/fd-pass) + listener-fd bind + supervise loop land in WS-C; the \
         root does not yet serve"
    )]
    RootSupervisionNotWired {
        /// The count of authorized instances in the stood-up plan.
        instances: usize,
    },
    /// WS-C seam: the instance resolved its slice + built its materialization gate, but
    /// link-open + the serving splice are the next workstream. Fail-closed.
    #[error(
        "privsep instance {label:?}: gate built ({held} of {total} authorities held) — link-open \
         + the serving splice land in WS-C; the instance does not yet serve"
    )]
    InstanceServingNotWired {
        /// The instance label.
        label: String,
        /// Authorities this instance holds.
        held: usize,
        /// The total authority count (for the operator log).
        total: usize,
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
            let env = privsep_resolve::build_instance_env(parent_env.clone(), &inst.capabilities);
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

    // WS-C: create the socketpair(2) link fds + bind + pass the privileged listener fds,
    // `.spawn()` each `spec.to_command(current_exe)`, then run the supervise loop
    // (restart / health / crown-jewel FailNodeClosed / shutdown fan-out). The spawn
    // SPEC above (argv + the minimal scrubbed env) is the WS-B primitive WS-C drives.
    // TODO(privsep WS-C): wire the transport + supervision here.
    Err(PrivsepError::RootSupervisionNotWired {
        instances: plan.instances.len(),
    }
    .into())
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

    // Step 3 (design §2.1): install the per-capability seccomp/Landlock profile BEFORE
    // the runtime, fail-closed `Enforced` fleetwide.
    // TODO(privsep WS-D): derive + install the per-capability profile (do NOT touch
    // `sandbox.rs` here — WS-D owns the derivation + the `SandboxPosture` handling).

    // Steps 5-6 (design §2.1): open the instance's links over the inherited socketpair
    // fds, build the Tokio runtime, and serve its slice (materializing ONLY its held
    // authorities, each resolving its own secret inputs behind its own Landlock grant).
    // TODO(privsep WS-C): link-open + the serving splice.
    Err(PrivsepError::InstanceServingNotWired {
        label: label.to_string(),
        held: inst.capabilities.len(),
        total: HostAuthority::ALL.len(),
    }
    .into())
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
}
