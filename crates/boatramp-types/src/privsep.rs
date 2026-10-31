//! Privilege-separation composition substrate (privsep Phase 1 — WS-A foundation).
//!
//! This is the **host-INTERNAL** authority vocabulary + the `[privsep]` composition
//! schema + the boot-time, fail-closed composition-closure lint. It is a DIFFERENT
//! axis from [`crate::config`]'s `KNOWN_IMPORTS` (the guest-facing, host⟶guest
//! capability vocabulary): [`HostAuthority`] names what a boatramp *instance* holds
//! INSIDE the trust domain (which keys it unseals, which pools it opens, which
//! untrusted-byte listeners it binds, whether it runs the JIT) — the inner,
//! boatramp⟶boatramp boundary. The two are never conflated: a guest never names a
//! host authority, and an instance's authority set is never guest-supplied.
//!
//! Design: `PLAN-privsep-phase1.md` §1 (the vocabulary), §1.3 (the figment schema),
//! §5 (the invariants + the closure lint). This module is Phase-1 WS-A ONLY — the
//! capability vocabulary, the `[privsep]` config model, and the closure lint. The
//! root supervisor (§4), the feature-instance boot (§2), the feature-link transport
//! (§3), the per-capability profile derivation (§2 F6), and the per-capability
//! authority-API grammar (§3.4) are LATER workstreams (WS-B/WS-C); clean seams are
//! marked `TODO(privsep WS-B)` / `TODO(privsep WS-C)` below.
//!
//! **Default = the monolith, unchanged.** An absent `[privsep]` section
//! ([`crate::config`]'s consumer carries it as `Option<PrivsepConfig>`) is today's
//! turnkey monolith — one process holding every authority — and is NEVER linted (it
//! is the one allowed all-in-one composition; §5.5 default-monolith invariant). Once
//! an operator writes `[privsep]`, the composition is non-default and the closure
//! lint ([`check_composition_closure`]) enforces real separation, fail-closed.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The blast-radius group a [`HostAuthority`] belongs to (design §1.2's A–E grouping).
/// The group — not a free-form flag — is the single source of truth for crown-jewel
/// membership and for the lint's exclusion sets, so the two can never drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityGroup {
    /// **A** — crown-jewel key & sealer authorities. Each must be isolatable ALONE.
    KeySealer,
    /// **B** — backend-credential & data-plane authorities (hold creds, open pools).
    Backend,
    /// **C** — untrusted-byte listener authorities (parse attacker bytes; the riskiest surfaces).
    Listener,
    /// **D** — execution authorities (the JIT; the compute-plane orchestrator).
    Exec,
    /// **E** — control-plane orchestration authorities.
    Control,
}

/// A fine-grained host-INTERNAL authority an instance may or may not **materialize**
/// (design §1.2). This is a **CLOSED, Security-ratified enum** — the host-internal
/// analog of `KNOWN_IMPORTS`: greppable, and a new variant is an explicit, reviewed
/// addition (never a free string, never KV/control-plane-derived). It is a
/// **restart-class** vocabulary: an instance's set is a boot-time, on-disk fact, so no
/// runtime write can grant an authority the on-disk composition did not (design §1.1,
/// §5 F4).
///
/// The wire/config spelling is the stable [`HostAuthority::tag`] string
/// (`"secrets.sealer"`, `"listen.http-parse"`, …); serde serializes to / deserializes
/// from that tag, and an unknown tag is a boot-LOUD refusal
/// ([`ParseHostAuthorityError`]) exactly like an unknown `KNOWN_IMPORTS` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum HostAuthority {
    // ===== Group A — crown-jewel key & sealer authorities (each isolatable alone) =====
    /// `secrets.sealer` — holds and uses the `[secrets]` KEK (local AES-256-GCM `kek_file`,
    /// or Vault Transit) to seal/unseal every per-tenant sealed credential and every sealed
    /// config ref. Materializes the KEK in (mlocked) process memory. Blast radius: every
    /// tenant's secrets across the whole fleet, decryptable at will — the single
    /// highest-value target.
    SecretsSealer,
    /// `token.signer` — holds and uses the control-plane auth root (`auth_root_private_key`,
    /// or the external `[serve.signer]`) to MINT control-plane tokens / OIDC exchanges.
    /// Blast radius: forge authz for ANY principal (incl. `system`/operator) — total
    /// control-plane takeover.
    TokenSigner,
    /// `image.signer` — holds and uses the key-based image-signing key (v0.44.0). Blast
    /// radius: forge a trusted image signature ⟶ supply-chain RCE on every node that pulls.
    ImageSigner,
    /// `overlay.dial-signer` — holds the node `OverlaySecret` (Ed25519 seed → TLS identity,
    /// COSE signer and E2EE) AND the dial-capability minting authority (the trust root and
    /// max dial TTL). The seed is the inline-capable `OverlayServeConfig.identity`, a
    /// crown-jewel key NOT in `SECRET_FIELDS` (design F11-A). Blast radius: impersonate the
    /// node on the fabric; mint holder-bound dial caps reaching any in-cluster service.
    OverlayDialSigner,
    /// `s3ingress.root` — holds the `s3_ingress_secret_file` HKDF root (domain-separated
    /// from the KEK and the signer) used to derive/validate S3-ingress `secret_access_key`s.
    /// Blast radius: forge or validate any S3-ingress upload credential.
    S3IngressRoot,
    /// `cluster.join-signer` — holds the cluster root key; mints/verifies mesh join tokens
    /// (`[cluster]`). Blast radius: admit a rogue node into the mesh (lateral trust).
    ClusterJoinSigner,

    // ===== Group B — backend-credential & data-plane authorities =====
    /// `backend.kv` — opens and holds the control-plane KV store (SlateDB / SQL-KV): the
    /// source of truth (site config, deploy manifests, tokens-at-rest, sealed-creds
    /// ciphertext). Blast radius: read/tamper the whole control plane (ciphertext only
    /// without `secrets.sealer` — the split is the point). Highest-value of group B.
    BackendKv,
    /// `backend.sql` — opens and holds the control-plane SQL pool, the per-project
    /// managed-DB pools and BYO `ExternalDatabaseConfig` creds. Blast radius: read/write all
    /// pooled tenant and control-plane SQL data.
    BackendSql,
    /// `backend.blob` — holds the node base object-store credential (`[serve.s3_credential]`
    /// / `azure_access_key`) and opens the S3/GCS/Azure clients. Blast radius:
    /// read/write/delete all blob data.
    BackendBlob,
    /// `backend.messaging` — opens the messaging / JetStream-parity bus. Blast radius:
    /// inject/drain every topic.
    BackendMessaging,

    // ===== Group C — untrusted-byte listener authorities (parse attacker bytes) =====
    /// `listen.public-tls` — binds the public listener (`serve.addr`) and terminates TLS
    /// (handshake and record layer over untrusted bytes). Materializes the TLS parse surface
    /// and the live private cert key in memory. Isolated, it forwards the decrypted byte
    /// stream inward. Split from `listen.http-parse` (design §6) so the cert key is walled
    /// from the fuzzed parser.
    ListenPublicTls,
    /// `listen.http-parse` — parses the hand-rolled HTTP/2 and HTTP/1 from the (already
    /// TLS-terminated) byte stream. The MOST-exposed, fuzzed surface. Isolated, it can only
    /// forward typed requests inward. The primary Phase-3 inversion target.
    ListenHttpParse,
    /// `listen.mail` — terminates SMTP/IMAP (mailroom); parses untrusted mail-protocol
    /// bytes. Same character as `listen.http-parse`.
    ListenMail,
    /// `listen.overlay` — serves the overlay QUIC relay/egress and parses the circuit
    /// framing (`relay_listen` / `egress_listen`). Blast radius: parse surface on the fabric
    /// edge.
    ListenOverlay,
    /// `listen.s3ingress` — binds the dedicated S3-ingress listener (`s3_ingress_addr`) —
    /// its own SigV4 parse surface. Blast radius: upload-face compromise.
    ListenS3Ingress,
    /// `listen.inbound-tcp` — binds host-owned `[serve.listeners.*]` raw-TCP listeners.
    /// Blast radius: raw-socket parse surface.
    ListenInboundTcp,
    /// `listen.gateway` — serves the reverse-proxy gateway ingress. Blast radius: proxy
    /// parse surface.
    ListenGateway,

    // ===== Group D — execution authorities =====
    /// `exec.wasmtime` — runs the wasmtime JIT (compile and execute guest components). Blast
    /// radius: a wasmtime escape lands in THIS instance's authority set, so what else it
    /// holds is the whole question (Phase 4 shrinks it to one tenant).
    ExecWasmtime,
    /// `exec.compute` — orchestrates the compute plane (firecracker / VZ / container
    /// backends); spawns the `__sandbox` / `__vmm-run` / `__vz-run` re-exec workers. Blast
    /// radius: run arbitrary workloads. The "compute-supervisor" authority the program
    /// sibling-splits OUT of the key-holders: the thing that runs VMs holds no keys.
    ExecCompute,

    // ===== Group E — control-plane orchestration authorities =====
    /// `control.admin-api` — serves the `/api/*` control-plane MUTATION surface (publish,
    /// token mint-request, config set, tenancy apply). Blast radius: drive every
    /// control-plane mutation the caller is authorized for.
    ControlAdminApi,
    /// `acme.dns-control` — holds the ACME account and the DNS-provider credential for cert
    /// issuance (`on_demand_tls`, acme-dns). Blast radius: issue certs / write the operator
    /// zone.
    AcmeDnsControl,
}

impl HostAuthority {
    /// The **full `all` monolith set** — every authority, in group order (A, B, C, D, E).
    /// The DEFAULT instance holds all of these (design §1.2); the closure lint requires the
    /// union of all instances' sets to equal exactly this set (nothing unhosted, §5 F7).
    pub const ALL: &'static [Self] = &[
        // A
        Self::SecretsSealer,
        Self::TokenSigner,
        Self::ImageSigner,
        Self::OverlayDialSigner,
        Self::S3IngressRoot,
        Self::ClusterJoinSigner,
        // B
        Self::BackendKv,
        Self::BackendSql,
        Self::BackendBlob,
        Self::BackendMessaging,
        // C
        Self::ListenPublicTls,
        Self::ListenHttpParse,
        Self::ListenMail,
        Self::ListenOverlay,
        Self::ListenS3Ingress,
        Self::ListenInboundTcp,
        Self::ListenGateway,
        // D
        Self::ExecWasmtime,
        Self::ExecCompute,
        // E
        Self::ControlAdminApi,
        Self::AcmeDnsControl,
    ];

    /// The stable config/wire spelling (the tag). Greppable; the enum↔tag map is the
    /// single source of truth for serde + the error messages.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::SecretsSealer => "secrets.sealer",
            Self::TokenSigner => "token.signer",
            Self::ImageSigner => "image.signer",
            Self::OverlayDialSigner => "overlay.dial-signer",
            Self::S3IngressRoot => "s3ingress.root",
            Self::ClusterJoinSigner => "cluster.join-signer",
            Self::BackendKv => "backend.kv",
            Self::BackendSql => "backend.sql",
            Self::BackendBlob => "backend.blob",
            Self::BackendMessaging => "backend.messaging",
            Self::ListenPublicTls => "listen.public-tls",
            Self::ListenHttpParse => "listen.http-parse",
            Self::ListenMail => "listen.mail",
            Self::ListenOverlay => "listen.overlay",
            Self::ListenS3Ingress => "listen.s3ingress",
            Self::ListenInboundTcp => "listen.inbound-tcp",
            Self::ListenGateway => "listen.gateway",
            Self::ExecWasmtime => "exec.wasmtime",
            Self::ExecCompute => "exec.compute",
            Self::ControlAdminApi => "control.admin-api",
            Self::AcmeDnsControl => "acme.dns-control",
        }
    }

    /// The blast-radius group (design §1.2 A–E).
    pub const fn group(self) -> AuthorityGroup {
        match self {
            Self::SecretsSealer
            | Self::TokenSigner
            | Self::ImageSigner
            | Self::OverlayDialSigner
            | Self::S3IngressRoot
            | Self::ClusterJoinSigner => AuthorityGroup::KeySealer,
            Self::BackendKv | Self::BackendSql | Self::BackendBlob | Self::BackendMessaging => {
                AuthorityGroup::Backend
            }
            Self::ListenPublicTls
            | Self::ListenHttpParse
            | Self::ListenMail
            | Self::ListenOverlay
            | Self::ListenS3Ingress
            | Self::ListenInboundTcp
            | Self::ListenGateway => AuthorityGroup::Listener,
            Self::ExecWasmtime | Self::ExecCompute => AuthorityGroup::Exec,
            Self::ControlAdminApi | Self::AcmeDnsControl => AuthorityGroup::Control,
        }
    }

    /// A crown jewel (group A) — a key/sealer authority that MUST be isolatable alone
    /// (design §1.2 A). Exactly the six: `secrets.sealer`, `token.signer`, `image.signer`,
    /// `overlay.dial-signer`, `s3ingress.root`, `cluster.join-signer`.
    pub const fn is_crown_jewel(self) -> bool {
        matches!(self.group(), AuthorityGroup::KeySealer)
    }

    /// A backend-credential authority (group B).
    pub const fn is_backend(self) -> bool {
        matches!(self.group(), AuthorityGroup::Backend)
    }

    /// An untrusted-byte listener authority (group C).
    pub const fn is_listener(self) -> bool {
        matches!(self.group(), AuthorityGroup::Listener)
    }

    /// An execution authority (group D).
    pub const fn is_exec(self) -> bool {
        matches!(self.group(), AuthorityGroup::Exec)
    }

    /// Whether this authority is part of the **widened crown-jewel exclusion surface**
    /// (design §1.2 / §5 F7): a crown jewel (A) may NEVER co-reside with any of
    /// `{C listeners ∪ exec.wasmtime ∪ exec.compute ∪ control.admin-api ∪ acme.dns-control}`
    /// — i.e. with any group C, D, or E authority. Equivalently, a crown jewel may only
    /// co-reside with other A authorities and with B (backend) authorities.
    pub const fn is_crown_jewel_exclusion_surface(self) -> bool {
        matches!(
            self.group(),
            AuthorityGroup::Listener | AuthorityGroup::Exec | AuthorityGroup::Control
        )
    }

    /// Whether this authority is an **exposed surface** for the §F8 second-tier check: a
    /// group-C listener or a group-D execution authority. `backend.*` SHOULD NOT co-reside
    /// with any of these (warn; deny under a hardened posture — a WS-B knob).
    pub const fn is_f8_exposed_surface(self) -> bool {
        matches!(
            self.group(),
            AuthorityGroup::Listener | AuthorityGroup::Exec
        )
    }

    /// A one-line operator/reviewer description: what it materializes + its blast radius.
    pub const fn doc(self) -> &'static str {
        match self {
            Self::SecretsSealer => {
                "holds the [secrets] KEK (mlocked) to seal/unseal every tenant credential; \
                 RCE ⇒ every secret on the fleet is decryptable — the highest-value target"
            }
            Self::TokenSigner => {
                "holds the control-plane auth root to mint tokens/OIDC exchanges; \
                 RCE ⇒ forge authz for any principal (incl. system) — total takeover"
            }
            Self::ImageSigner => {
                "holds the key-based image-signing key; \
                 RCE ⇒ forge a trusted image signature — supply-chain RCE on every puller"
            }
            Self::OverlayDialSigner => {
                "holds the node overlay seed (TLS+COSE+E2EE) + dial-cap minting authority; \
                 RCE ⇒ impersonate the node on the fabric; mint dial caps to any service"
            }
            Self::S3IngressRoot => {
                "holds the s3-ingress HKDF root; \
                 RCE ⇒ forge or validate any S3-ingress upload credential"
            }
            Self::ClusterJoinSigner => {
                "holds the cluster root key; mints/verifies mesh join tokens; \
                 RCE ⇒ admit a rogue node into the mesh (lateral trust)"
            }
            Self::BackendKv => {
                "opens the control-plane KV source of truth; \
                 RCE ⇒ read/tamper the whole control plane (ciphertext only without the sealer)"
            }
            Self::BackendSql => {
                "opens the control-plane + managed-DB + BYO SQL pools; \
                 RCE ⇒ read/write all pooled tenant + control-plane SQL data"
            }
            Self::BackendBlob => {
                "holds the node object-store credential + clients; \
                 RCE ⇒ read/write/delete all blob data"
            }
            Self::BackendMessaging => {
                "opens the messaging / JetStream-parity bus; RCE ⇒ inject/drain every topic"
            }
            Self::ListenPublicTls => {
                "binds the public listener + terminates TLS over untrusted bytes; \
                 holds the live private cert key; isolated, forwards the decrypted stream inward"
            }
            Self::ListenHttpParse => {
                "parses the hand-rolled HTTP/2+1 (the most-fuzzed surface); \
                 isolated, forwards only typed requests inward — the Phase-3 inversion target"
            }
            Self::ListenMail => {
                "terminates SMTP/IMAP (mailroom) over untrusted bytes; \
                 same character as listen.http-parse"
            }
            Self::ListenOverlay => {
                "serves the overlay QUIC relay/egress + parses the circuit framing; \
                 parse surface on the fabric edge"
            }
            Self::ListenS3Ingress => {
                "binds the dedicated S3-ingress listener (its own SigV4 parse surface); \
                 RCE ⇒ upload-face compromise"
            }
            Self::ListenInboundTcp => {
                "binds host-owned [serve.listeners.*] raw-TCP listeners; \
                 RCE ⇒ raw-socket parse surface"
            }
            Self::ListenGateway => {
                "serves the reverse-proxy gateway ingress; RCE ⇒ proxy parse surface"
            }
            Self::ExecWasmtime => {
                "runs the wasmtime JIT (compile+execute guest components); \
                 a JIT escape lands in this instance's authority set"
            }
            Self::ExecCompute => {
                "orchestrates the compute plane + spawns the re-exec VM/container workers; \
                 the compute-supervisor that must hold no keys"
            }
            Self::ControlAdminApi => {
                "serves the /api/* control-plane mutation surface; \
                 RCE ⇒ drive every control-plane mutation the caller is authorized for"
            }
            Self::AcmeDnsControl => {
                "holds the ACME account + DNS-provider credential for cert issuance; \
                 RCE ⇒ issue certs / write the operator zone"
            }
        }
    }

    /// A comma-separated list of every valid tag — for error messages (the loud-refusal
    /// cure, mirroring `KNOWN_IMPORTS`'s joined-list message).
    fn all_tags_csv() -> String {
        Self::ALL
            .iter()
            .map(|a| a.tag())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// An unrecognized [`HostAuthority`] tag — a boot-LOUD refusal (design §1.3: "a typo is a
/// boot-LOUD refusal, like `KNOWN_IMPORTS`"). Carries the offending tag + the valid set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseHostAuthorityError {
    /// The unrecognized tag as written.
    pub got: String,
}

impl std::fmt::Display for ParseHostAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown host authority {:?}; valid authorities: {}",
            self.got,
            HostAuthority::all_tags_csv()
        )
    }
}

impl std::error::Error for ParseHostAuthorityError {}

impl FromStr for HostAuthority {
    type Err = ParseHostAuthorityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|a| a.tag() == s)
            .ok_or_else(|| ParseHostAuthorityError { got: s.to_string() })
    }
}

impl TryFrom<String> for HostAuthority {
    type Error = ParseHostAuthorityError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<HostAuthority> for String {
    fn from(a: HostAuthority) -> Self {
        a.tag().to_string()
    }
}

impl std::fmt::Display for HostAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

// =============================================================================
// The `[privsep]` figment config model (design §1.3)
// =============================================================================

/// The `[privsep]` section (design §1.3). A map of INSTANCES keyed by arbitrary operator
/// labels (NOT a fixed role menu — decision 2), one logical-link map, and an optional
/// supervisor posture.
///
/// **ABSENT ⇒ the monolith, byte-for-byte unchanged** — the consumer carries this as
/// `Option<PrivsepConfig>`; `None` is today's one-process-holds-everything node and is
/// never linted. `[privsep]` is **restart-class**: it lives in the on-disk config, never
/// in the KV / dynamic daemon config, so a supervised restart re-reads the SAME on-disk
/// topology and no runtime control-plane write can change a resolved composition (design
/// §4, §5 F4).
///
/// TODO(privsep WS-B): the root supervisor reads this on-disk slice, runs
/// [`check_composition_closure`] fail-closed BEFORE any spawn, then spawns one
/// `boatramp __instance <name>` per entry and wires the links. This WS carries + lints the
/// model only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivsepConfig {
    /// The composed instances, keyed by operator label. Each holds a fine-grained SUBSET of
    /// [`HostAuthority`]; the union of every instance's set must equal [`HostAuthority::ALL`]
    /// (§5 F7, enforced by [`check_composition_closure`]).
    pub instances: BTreeMap<String, PrivsepInstanceConfig>,
    /// One logical link per entry, keyed by link name. An instance's
    /// [`PrivsepInstanceConfig::links`] names entries here. The transport
    /// ([`LinkTransport`]) is a config SHAPE behind one API (design §3); WS-A carries it as
    /// a typed placeholder.
    pub links: BTreeMap<String, PrivsepLink>,
    /// Optional supervisor posture (listener-fd ownership + crown-jewel crash policy, design
    /// §4). Carried as a WS-A placeholder; WS-B consumes it.
    pub supervisor: Option<PrivsepSupervisorConfig>,
}

/// One composed instance (design §1.3): the fine-grained authority SUBSET it materializes,
/// its Phase-0 sandbox posture, and the links it opens. The same binary is re-executed into
/// this dropped-authority posture (design §2) — WS-B wiring.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivsepInstanceConfig {
    /// The fine-grained subset this instance MATERIALIZES. Everything NOT listed is never
    /// constructed (no key unsealed, no pool opened, no listener bound) AND is denied by this
    /// instance's per-capability profile (design §2; WS-B).
    pub capabilities: Vec<HostAuthority>,
    /// The Phase-0 sandbox posture to derive/clamp for this instance. Under `[privsep]` the
    /// installed profile is REQUIRED `Enforced` fleetwide (design §2 F6 / §5 F7 inv7); `Off`
    /// is dev-only. WS-A parses + carries this; WS-B derives + installs the profile.
    pub sandbox: SandboxPosture,
    /// The link names (keys of [`PrivsepConfig::links`]) this instance opens.
    pub links: Vec<String>,
}

/// The **per-instance profile-DERIVATION posture** (design §1.3 / §2 F6):
/// `[privsep].instances.<name>.sandbox`. It answers *how THIS instance's per-capability
/// seccomp/Landlock profile is shaped*.
///
/// **Reconciliation with the node posture (WS-D).** This is a DISTINCT axis from the
/// node-wide `[serve.sandbox].posture` (`boatramp_node::config::SandboxPosture` =
/// `Auto|Strict|Permissive|Off`), which is the Phase-0 install-DECISION for the monolith
/// serve path. The two are deliberately NOT merged into one mixed-meaning enum; instead the
/// per-instance posture here DRIVES a Phase-0 install of a DERIVED profile, reusing the
/// Phase-0 machinery (`boatramp_server::sandbox`'s `SandboxPolicy` / `SandboxStatus` /
/// install) — see [`SandboxPosture::enforcement`] and `boatramp_server::sandbox`'s
/// `privsep_install_plan` / `enforce_privsep_status`. Under `[privsep]` enforcement is ALWAYS
/// fail-closed `Enforced` (F6) — not operator-tunable — except `Off`, which is dev-only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxPosture {
    /// Derive the tightest per-capability seccomp/Landlock profile the instance's capability
    /// set needs (the Phase-1 derivation). The default. Fail-closed `Enforced` under `[privsep]`.
    #[default]
    Derived,
    /// Clamp harder than `Derived` (operator-chosen tightening — e.g. drop the shared system
    /// temp dirs from the FS view). Also fail-closed `Enforced` under `[privsep]`.
    Strict,
    /// **Dev-only.** No profile installed. Under `[privsep]` a non-default composition REFUSES
    /// `Off` unless the node `[serve.sandbox].posture` is itself a dev posture (the wall is
    /// load-bearing; design §2 F6). WS-B enforces the refusal via
    /// `boatramp_server::sandbox::privsep_install_plan`.
    Off,
}

impl SandboxPosture {
    /// The enforcement this posture demands of the installed per-instance profile — the
    /// single bridge encoding the F6 fail-closed rule purely from the posture (consumed by
    /// `boatramp_server::sandbox::privsep_install_plan`). `Derived`/`Strict` ⇒
    /// [`ProfileEnforcement::RequireEnforced`] (the profile MUST report `Enforced`, fleetwide);
    /// `Off` ⇒ [`ProfileEnforcement::DevOnlyOff`] (no profile; legal only on a dev node).
    pub const fn enforcement(self) -> ProfileEnforcement {
        match self {
            Self::Derived | Self::Strict => ProfileEnforcement::RequireEnforced,
            Self::Off => ProfileEnforcement::DevOnlyOff,
        }
    }

    /// Whether this posture installs a per-capability profile at all (`true` for
    /// `Derived`/`Strict`; `false` for the dev-only `Off`).
    pub const fn installs_profile(self) -> bool {
        !matches!(self, Self::Off)
    }
}

/// What a [`SandboxPosture`] demands of the installed per-instance profile under `[privsep]`
/// (design §2 F6 / §5 inv7) — the enforcement half of the SandboxPosture reconciliation,
/// kept here in the wasm-clean types layer so both the config model and
/// `boatramp_server::sandbox`'s install path share one source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileEnforcement {
    /// The derived profile MUST install and report `Enforced` — FLEETWIDE, for every instance,
    /// not just crown-jewel ones. A kernel that can deliver only `Partial` refuses privsep
    /// (contrast Phase-0 `auto`, which fails OPEN on `Partial`). The wall is load-bearing.
    RequireEnforced,
    /// No profile is installed (`Off`). Legal ONLY on a dev node (the node
    /// `[serve.sandbox].posture` is `off`/`permissive`); otherwise a real `[privsep]`
    /// composition REFUSES it.
    DevOnlyOff,
}

/// One logical inter-instance link (design §3). WS-A carries `from`/`to`/`transport`; the
/// transport implementation (`local` socketpair / `tcp` / `overlay`) + the authority-API
/// grammar are WS-C.
///
/// TODO(privsep WS-C): wire `LocalLink`/`TcpLink`/`OverlayLink` behind the one `Link` API
/// (design §3.2) and fill the per-capability authority-API grammar (design §3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivsepLink {
    /// The instance label that opens this link (one endpoint).
    pub from: String,
    /// The instance label on the other endpoint.
    pub to: String,
    /// The transport shape behind the one link API.
    pub transport: LinkTransport,
}

/// The link transport — a config SHAPE behind one API (design §3.3). WS-A placeholder.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkTransport {
    /// The fast co-located shape: a root-created `socketpair(2)`, fds passed at spawn (no
    /// named socket, no crypto, no net stack — design §3.3 / F2). The default.
    #[default]
    Local,
    /// A plain TCP socket between the two instance endpoints (same host / trust domain, no
    /// fabric). WS-C carries the endpoint addressing.
    Tcp(SocketAddr),
    /// The existing overlay fabric reused verbatim (relay-blind E2EE, capability-dial). The
    /// value is the overlay service name (`svc/<link>`); design §3.3.
    Overlay(String),
}

/// The supervisor posture (design §4.1 / §4). WS-A placeholder; WS-B consumes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivsepSupervisorConfig {
    /// Whether the root binds the public listener sockets + passes the fds to the
    /// `listen.*`-holding instances (classic privsep; design §4.1 / §6 decision). `None` ⇒
    /// the WS-B default.
    pub bind_public_listeners: Option<bool>,
    /// What happens when a crown-jewel (group A) instance crashes (design §4.1).
    pub crown_jewel_crash: CrownJewelCrashPolicy,
}

/// The crown-jewel crash policy (design §4.1). WS-B placeholder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrownJewelCrashPolicy {
    /// A crashed crown-jewel (A) instance fails the WHOLE node closed rather than serving
    /// with a hole (design §4.1 / §6 — adopted). The default.
    #[default]
    FailNodeClosed,
    /// Restart the crashed instance from the SAME on-disk topology (design §4.1). WS-B owns
    /// the semantics.
    Restart,
}

// =============================================================================
// The composition-closure lint (design §5 F7 + F8; §1.2 crown-jewel exclusion)
// =============================================================================

/// One hard composition-closure violation — a fail-closed REFUSAL (design §5 F7). The root
/// fails the node closed before spawning a single instance if any of these is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionViolation {
    /// An instance holds no capabilities (design §5 F7: "a zero-capability instance").
    ZeroCapabilityInstance {
        /// The offending instance label.
        instance: String,
    },
    /// The union of all instances' capabilities is not the full `all` set — one or more
    /// authorities are UNHOSTED (design §5 F7: "every capability hosted by ≥1 instance").
    UnhostedCapabilities {
        /// The authorities no instance hosts.
        missing: Vec<HostAuthority>,
    },
    /// A crown jewel (group A) co-resides on an instance with an authority in the widened
    /// exclusion surface `{C ∪ exec.* ∪ control.admin-api ∪ acme.dns-control}` (design §1.2 /
    /// §5 F7). The load-bearing refusal.
    CrownJewelCoResident {
        /// The offending instance label.
        instance: String,
        /// The crown jewel(s) held by that instance.
        jewels: Vec<HostAuthority>,
        /// The co-resident exclusion-surface authorities.
        conflicts: Vec<HostAuthority>,
    },
    /// A link's endpoint (`from`/`to`) names an instance that no composition hosts (design
    /// §5 F7: "a `links` entry pointing at an unhosted instance / capability").
    LinkEndpointUnhosted {
        /// The link name.
        link: String,
        /// The endpoint label that is not a hosted instance.
        endpoint: String,
    },
    /// An instance's `links` entry references a link name absent from
    /// [`PrivsepConfig::links`] (the reference does not resolve — design §5 F7's closure
    /// check, instance side).
    InstanceLinkUnknown {
        /// The instance that references the link.
        instance: String,
        /// The unresolved link name.
        link: String,
    },
}

impl std::fmt::Display for CompositionViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapabilityInstance { instance } => {
                write!(
                    f,
                    "instance {instance:?} holds no capabilities (zero-capability instance)"
                )
            }
            Self::UnhostedCapabilities { missing } => {
                write!(f, "no instance hosts these authorities: {}", tags(missing))
            }
            Self::CrownJewelCoResident {
                instance,
                jewels,
                conflicts,
            } => write!(
                f,
                "instance {instance:?} co-resides crown-jewel authorities [{}] with \
                 excluded high-risk surfaces [{}] — a crown jewel must be isolatable alone",
                tags(jewels),
                tags(conflicts)
            ),
            Self::LinkEndpointUnhosted { link, endpoint } => write!(
                f,
                "link {link:?} names endpoint {endpoint:?}, which is not a hosted instance"
            ),
            Self::InstanceLinkUnknown { instance, link } => write!(
                f,
                "instance {instance:?} references link {link:?}, which is not defined in [privsep].links"
            ),
        }
    }
}

/// One non-fatal composition FLAG — surfaced but not refused (design §5 F7 duplication flag
/// and the §5 F8 second tier). The caller logs these; they do not fail the node closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionWarning {
    /// A crown jewel (group A) is held by MORE THAN ONE instance — flagged, not refused:
    /// duplicating a key holder widens the key's exposure (design §5 F7).
    CrownJewelDuplicated {
        /// The duplicated crown-jewel authority.
        authority: HostAuthority,
        /// Every instance that holds it (≥2).
        instances: Vec<String>,
    },
    /// `backend.*` co-resides with `listen.*` / `exec.*` on one instance (design §5 F8
    /// second tier). A warning here; TODO(privsep WS-B): a hardened supervisor posture
    /// PROMOTES this to a hard refusal.
    BackendCoResidentWithExposed {
        /// The offending instance label.
        instance: String,
        /// The backend authorities on that instance.
        backends: Vec<HostAuthority>,
        /// The co-resident listener/exec authorities.
        exposed: Vec<HostAuthority>,
    },
}

impl std::fmt::Display for CompositionWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrownJewelDuplicated {
                authority,
                instances,
            } => write!(
                f,
                "crown-jewel authority {} is held by >1 instance [{}] — duplication widens the key's exposure",
                authority.tag(),
                instances.join(", ")
            ),
            Self::BackendCoResidentWithExposed {
                instance,
                backends,
                exposed,
            } => write!(
                f,
                "instance {instance:?} co-resides backend authorities [{}] with untrusted-byte/exec surfaces [{}] (F8: separate data-plane creds from the exposed surfaces)",
                tags(backends),
                tags(exposed)
            ),
        }
    }
}

/// The result of a clean [`check_composition_closure`] pass: the composition is authorized
/// (no refusals), carrying any non-fatal flags for the caller to log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompositionReport {
    /// Non-fatal flags (crown-jewel duplication; F8 backend co-residency).
    pub warnings: Vec<CompositionWarning>,
}

/// A fail-closed composition REFUSAL: one or more [`CompositionViolation`]s. The root must
/// fail the node closed and spawn nothing (design §5 F7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionError {
    /// Every violation found (the whole picture, so an operator sees all faults at once).
    pub violations: Vec<CompositionViolation>,
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[privsep] composition refused ({} violation(s)): ",
            self.violations.len()
        )?;
        for (i, v) in self.violations.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{v}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CompositionError {}

/// Join authorities' tags for a message.
fn tags(authorities: &[HostAuthority]) -> String {
    authorities
        .iter()
        .map(|a| a.tag())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The **composition-closure lint** (design §5 F7 + §1.2 crown-jewel exclusion + §5 F8) — a
/// PURE function over the parsed `[privsep]` config. It is the **authorization gate**: the
/// root runs it fail-closed, IN THE ROOT, BEFORE any spawn, and refuses (spawns nothing) on
/// any [`CompositionViolation`]. Because `[privsep]` is restart-class disk-only (§5 F4),
/// this lint — not a runtime check — is what authorizes a composition.
///
/// It REFUSES (returns `Err`) on:
/// - a zero-capability instance;
/// - an UNHOSTED capability (the union of all instances' sets must equal
///   [`HostAuthority::ALL`]);
/// - a crown jewel (group A) co-resident with any of
///   `{C listeners ∪ exec.wasmtime ∪ exec.compute ∪ control.admin-api ∪ acme.dns-control}`
///   (the widened exclusion, design §1.2 / §5 F7);
/// - a link endpoint naming an unhosted instance;
/// - an instance `links` entry referencing an undefined link.
///
/// It FLAGS (returns `Ok` with [`CompositionWarning`]s) on:
/// - a crown jewel held by >1 instance (duplication widens exposure);
/// - `backend.*` co-resident with `listen.*` / `exec.*` (design §5 F8 — warn; a hardened
///   posture promotes it to a refusal, WS-B).
///
/// Every violation is collected (not short-circuited) so an operator sees the whole picture.
///
/// NOTE: this is ONLY invoked for an explicitly-present `[privsep]` composition. The absent
/// (monolith) case is never linted — it is the one allowed all-in-one composition (§5.5).
/// TODO(privsep WS-B): the root calls this immediately after resolving the on-disk topology
/// and before the first `fork`+`exec`, failing the node closed on `Err`.
pub fn check_composition_closure(
    cfg: &PrivsepConfig,
) -> Result<CompositionReport, CompositionError> {
    let mut violations = Vec::new();
    let mut warnings = Vec::new();

    // --- Per-instance checks: zero-cap, crown-jewel exclusion, F8 second tier. ---
    for (name, inst) in &cfg.instances {
        if inst.capabilities.is_empty() {
            violations.push(CompositionViolation::ZeroCapabilityInstance {
                instance: name.clone(),
            });
            // A zero-cap instance has nothing further to check for co-residency.
            continue;
        }

        // Deduplicate within an instance so a repeated tag doesn't skew the report.
        let held: BTreeSet<HostAuthority> = inst.capabilities.iter().copied().collect();

        // Crown-jewel exclusion (REFUSE): A × {C ∪ D ∪ E}.
        let jewels: Vec<HostAuthority> = held
            .iter()
            .copied()
            .filter(|a| a.is_crown_jewel())
            .collect();
        if !jewels.is_empty() {
            let conflicts: Vec<HostAuthority> = held
                .iter()
                .copied()
                .filter(|a| a.is_crown_jewel_exclusion_surface())
                .collect();
            if !conflicts.is_empty() {
                violations.push(CompositionViolation::CrownJewelCoResident {
                    instance: name.clone(),
                    jewels,
                    conflicts,
                });
            }
        }

        // F8 second tier (FLAG): backend.* co-resident with listen.* / exec.*.
        let backends: Vec<HostAuthority> =
            held.iter().copied().filter(|a| a.is_backend()).collect();
        if !backends.is_empty() {
            let exposed: Vec<HostAuthority> = held
                .iter()
                .copied()
                .filter(|a| a.is_f8_exposed_surface())
                .collect();
            if !exposed.is_empty() {
                warnings.push(CompositionWarning::BackendCoResidentWithExposed {
                    instance: name.clone(),
                    backends,
                    exposed,
                });
            }
        }
    }

    // --- Closure: every authority hosted by ≥1 instance (union == ALL). ---
    let hosted: BTreeSet<HostAuthority> = cfg
        .instances
        .values()
        .flat_map(|inst| inst.capabilities.iter().copied())
        .collect();
    let missing: Vec<HostAuthority> = HostAuthority::ALL
        .iter()
        .copied()
        .filter(|a| !hosted.contains(a))
        .collect();
    if !missing.is_empty() {
        violations.push(CompositionViolation::UnhostedCapabilities { missing });
    }

    // --- Duplication FLAG: a crown jewel held by >1 instance. ---
    for &jewel in HostAuthority::ALL.iter().filter(|a| a.is_crown_jewel()) {
        let holders: Vec<String> = cfg
            .instances
            .iter()
            .filter(|(_, inst)| inst.capabilities.contains(&jewel))
            .map(|(name, _)| name.clone())
            .collect();
        if holders.len() > 1 {
            warnings.push(CompositionWarning::CrownJewelDuplicated {
                authority: jewel,
                instances: holders,
            });
        }
    }

    // --- Link closure: endpoints name hosted instances; instance refs resolve. ---
    for (link_name, link) in &cfg.links {
        for endpoint in [&link.from, &link.to] {
            if !cfg.instances.contains_key(endpoint) {
                violations.push(CompositionViolation::LinkEndpointUnhosted {
                    link: link_name.clone(),
                    endpoint: endpoint.clone(),
                });
            }
        }
    }
    for (name, inst) in &cfg.instances {
        for link in &inst.links {
            if !cfg.links.contains_key(link) {
                violations.push(CompositionViolation::InstanceLinkUnknown {
                    instance: name.clone(),
                    link: link.clone(),
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(CompositionReport { warnings })
    } else {
        Err(CompositionError { violations })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Vocabulary ----

    #[test]
    fn all_has_every_variant_once_and_tags_round_trip() {
        // 6 A + 4 B + 7 C + 2 D + 2 E = 21 authorities.
        assert_eq!(HostAuthority::ALL.len(), 21);
        let set: BTreeSet<HostAuthority> = HostAuthority::ALL.iter().copied().collect();
        assert_eq!(set.len(), 21, "ALL must contain no duplicates");
        for &a in HostAuthority::ALL {
            // tag → parse round-trip.
            assert_eq!(a.tag().parse::<HostAuthority>().unwrap(), a);
            // serde round-trip through the tag string.
            let json = serde_json::to_string(&a).unwrap();
            assert_eq!(json, format!("{:?}", a.tag()));
            let back: HostAuthority = serde_json::from_str(&json).unwrap();
            assert_eq!(back, a);
        }
        // Tags are unique.
        let tag_set: BTreeSet<&str> = HostAuthority::ALL.iter().map(|a| a.tag()).collect();
        assert_eq!(tag_set.len(), 21);
    }

    #[test]
    fn crown_jewel_set_is_exactly_the_six_group_a() {
        let jewels: BTreeSet<HostAuthority> = HostAuthority::ALL
            .iter()
            .copied()
            .filter(|a| a.is_crown_jewel())
            .collect();
        let expected: BTreeSet<HostAuthority> = [
            HostAuthority::SecretsSealer,
            HostAuthority::TokenSigner,
            HostAuthority::ImageSigner,
            HostAuthority::OverlayDialSigner,
            HostAuthority::S3IngressRoot,
            HostAuthority::ClusterJoinSigner,
        ]
        .into_iter()
        .collect();
        assert_eq!(jewels, expected);
        assert_eq!(jewels.len(), 6);
        // Crown jewels are exactly group A.
        for &a in HostAuthority::ALL {
            assert_eq!(a.is_crown_jewel(), a.group() == AuthorityGroup::KeySealer);
        }
    }

    #[test]
    fn exclusion_surface_is_c_d_e_and_f8_is_c_d() {
        for &a in HostAuthority::ALL {
            let excl = matches!(
                a.group(),
                AuthorityGroup::Listener | AuthorityGroup::Exec | AuthorityGroup::Control
            );
            assert_eq!(a.is_crown_jewel_exclusion_surface(), excl, "{}", a.tag());
            // A crown jewel may co-reside only with A ∪ B.
            assert_eq!(
                a.is_crown_jewel_exclusion_surface(),
                !a.is_crown_jewel() && !a.is_backend(),
                "{}",
                a.tag()
            );
            let f8 = matches!(a.group(), AuthorityGroup::Listener | AuthorityGroup::Exec);
            assert_eq!(a.is_f8_exposed_surface(), f8, "{}", a.tag());
        }
    }

    #[test]
    fn the_tls_http_parse_split_is_present() {
        // The §6 split: public-http → public-tls + http-parse, both group C.
        assert_eq!(
            "listen.public-tls".parse::<HostAuthority>().unwrap(),
            HostAuthority::ListenPublicTls
        );
        assert_eq!(
            "listen.http-parse".parse::<HostAuthority>().unwrap(),
            HostAuthority::ListenHttpParse
        );
        assert_eq!(
            HostAuthority::ListenPublicTls.group(),
            AuthorityGroup::Listener
        );
        assert_eq!(
            HostAuthority::ListenHttpParse.group(),
            AuthorityGroup::Listener
        );
    }

    #[test]
    fn unknown_tag_is_a_loud_refusal() {
        let err = "listen.public-http".parse::<HostAuthority>().unwrap_err();
        assert_eq!(err.got, "listen.public-http");
        let msg = err.to_string();
        assert!(msg.contains("unknown host authority"));
        assert!(msg.contains("listen.public-tls"), "cure lists valid tags");
        // serde deserialize of an unknown tag also fails loudly.
        assert!(serde_json::from_str::<HostAuthority>("\"nope\"").is_err());
    }

    // ---- Lint fixtures ----

    fn inst(caps: &[HostAuthority]) -> PrivsepInstanceConfig {
        PrivsepInstanceConfig {
            capabilities: caps.to_vec(),
            sandbox: SandboxPosture::Derived,
            links: Vec::new(),
        }
    }

    /// A clean, warning-free least-authority composition whose union == ALL:
    /// - `edge`: all listeners + both exec + both control (C ∪ D ∪ E; no A, no B);
    /// - `data`: the four backends (B alone; no listen/exec ⇒ no F8 warning);
    /// - `signer`: the six crown jewels (A alone; co-resides only with A).
    fn clean_composition() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "edge".to_string(),
            inst(&[
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
            ]),
        );
        instances.insert(
            "data".to_string(),
            inst(&[
                HostAuthority::BackendKv,
                HostAuthority::BackendSql,
                HostAuthority::BackendBlob,
                HostAuthority::BackendMessaging,
            ]),
        );
        instances.insert(
            "signer".to_string(),
            inst(&[
                HostAuthority::SecretsSealer,
                HostAuthority::TokenSigner,
                HostAuthority::ImageSigner,
                HostAuthority::OverlayDialSigner,
                HostAuthority::S3IngressRoot,
                HostAuthority::ClusterJoinSigner,
            ]),
        );
        PrivsepConfig {
            instances,
            links: BTreeMap::new(),
            supervisor: None,
        }
    }

    #[test]
    fn valid_least_authority_composition_passes_clean() {
        let report = check_composition_closure(&clean_composition()).expect("valid composition");
        assert!(
            report.warnings.is_empty(),
            "the clean composition must raise no flags, got {:?}",
            report.warnings
        );
    }

    #[test]
    fn refuses_crown_jewel_co_resident_with_a_listener() {
        let mut cfg = clean_composition();
        // Move a listener onto the signer (keeps union == ALL; sole fault).
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .retain(|a| *a != HostAuthority::ListenHttpParse);
        cfg.instances
            .get_mut("signer")
            .unwrap()
            .capabilities
            .push(HostAuthority::ListenHttpParse);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::CrownJewelCoResident { instance, conflicts, .. }
                if instance == "signer" && conflicts.contains(&HostAuthority::ListenHttpParse)
        )));
    }

    #[test]
    fn refuses_crown_jewel_co_resident_with_exec() {
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .retain(|a| *a != HostAuthority::ExecCompute);
        cfg.instances
            .get_mut("signer")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecCompute);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::CrownJewelCoResident { conflicts, .. }
                if conflicts.contains(&HostAuthority::ExecCompute)
        )));
    }

    #[test]
    fn refuses_crown_jewel_co_resident_with_control() {
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .retain(|a| *a != HostAuthority::ControlAdminApi);
        cfg.instances
            .get_mut("signer")
            .unwrap()
            .capabilities
            .push(HostAuthority::ControlAdminApi);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::CrownJewelCoResident { conflicts, .. }
                if conflicts.contains(&HostAuthority::ControlAdminApi)
        )));
    }

    #[test]
    fn refuses_unhosted_capability() {
        let mut cfg = clean_composition();
        // Drop acme.dns-control entirely — no instance hosts it.
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .retain(|a| *a != HostAuthority::AcmeDnsControl);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::UnhostedCapabilities { missing }
                if missing == &vec![HostAuthority::AcmeDnsControl]
        )));
    }

    #[test]
    fn refuses_zero_capability_instance() {
        let mut cfg = clean_composition();
        cfg.instances.insert("ghost".to_string(), inst(&[]));
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::ZeroCapabilityInstance { instance } if instance == "ghost"
        )));
    }

    #[test]
    fn refuses_link_to_unhosted_instance() {
        let mut cfg = clean_composition();
        cfg.links.insert(
            "to-ghost".to_string(),
            PrivsepLink {
                from: "edge".to_string(),
                to: "ghost".to_string(),
                transport: LinkTransport::Local,
            },
        );
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::LinkEndpointUnhosted { endpoint, .. } if endpoint == "ghost"
        )));
    }

    #[test]
    fn refuses_instance_link_referencing_undefined_link() {
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .links
            .push("nope".to_string());
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::InstanceLinkUnknown { instance, link }
                if instance == "edge" && link == "nope"
        )));
    }

    #[test]
    fn flags_crown_jewel_held_by_more_than_one_instance() {
        let mut cfg = clean_composition();
        // A second signer also holds token.signer (union still == ALL; no co-residency).
        cfg.instances
            .insert("signer2".to_string(), inst(&[HostAuthority::TokenSigner]));
        let report = check_composition_closure(&cfg).expect("duplication is a flag, not a refusal");
        assert!(report.warnings.iter().any(|w| matches!(
            w,
            CompositionWarning::CrownJewelDuplicated { authority, instances }
                if *authority == HostAuthority::TokenSigner && instances.len() == 2
        )));
    }

    #[test]
    fn flags_backend_co_resident_with_exposed_surface_f8() {
        // Collapse edge+data: backends now co-reside with listeners/exec → F8 warning, no refusal.
        let mut instances = BTreeMap::new();
        instances.insert(
            "fat-edge".to_string(),
            inst(&[
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
                HostAuthority::BackendKv,
                HostAuthority::BackendSql,
                HostAuthority::BackendBlob,
                HostAuthority::BackendMessaging,
            ]),
        );
        instances.insert(
            "signer".to_string(),
            inst(&[
                HostAuthority::SecretsSealer,
                HostAuthority::TokenSigner,
                HostAuthority::ImageSigner,
                HostAuthority::OverlayDialSigner,
                HostAuthority::S3IngressRoot,
                HostAuthority::ClusterJoinSigner,
            ]),
        );
        let cfg = PrivsepConfig {
            instances,
            links: BTreeMap::new(),
            supervisor: None,
        };
        let report = check_composition_closure(&cfg).expect("F8 is a flag, not a refusal");
        assert!(report.warnings.iter().any(|w| matches!(
            w,
            CompositionWarning::BackendCoResidentWithExposed { instance, .. } if instance == "fat-edge"
        )));
    }

    #[test]
    fn collects_every_violation_at_once() {
        // A zero-cap instance + a bad link → both reported in one error.
        let mut cfg = clean_composition();
        cfg.instances.insert("ghost".to_string(), inst(&[]));
        cfg.links.insert(
            "bad".to_string(),
            PrivsepLink {
                from: "edge".to_string(),
                to: "missing".to_string(),
                transport: LinkTransport::Local,
            },
        );
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(err.violations.len() >= 2);
        assert!(
            err.violations
                .iter()
                .any(|v| matches!(v, CompositionViolation::ZeroCapabilityInstance { .. }))
        );
        assert!(
            err.violations
                .iter()
                .any(|v| matches!(v, CompositionViolation::LinkEndpointUnhosted { .. }))
        );
    }

    // ---- Config (de)serialization shape ----

    #[test]
    fn privsep_config_round_trips_through_ron() {
        let ron = r#"(
            instances: {
                "edge": (
                    capabilities: ["listen.public-tls", "listen.http-parse", "exec.wasmtime"],
                    sandbox: Derived,
                    links: ["to-signer"],
                ),
                "signer": (
                    capabilities: ["secrets.sealer", "token.signer"],
                    links: [],
                ),
            },
            links: {
                "to-signer": (from: "edge", to: "signer", transport: Local),
            },
            supervisor: (bind_public_listeners: true, crown_jewel_crash: FailNodeClosed),
        )"#;
        let cfg: PrivsepConfig = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(ron)
            .expect("parse privsep RON");
        assert_eq!(cfg.instances.len(), 2);
        assert_eq!(
            cfg.instances["edge"].capabilities,
            vec![
                HostAuthority::ListenPublicTls,
                HostAuthority::ListenHttpParse,
                HostAuthority::ExecWasmtime
            ]
        );
        // A missing `sandbox` defaults to Derived.
        assert_eq!(cfg.instances["signer"].sandbox, SandboxPosture::Derived);
        assert_eq!(cfg.links["to-signer"].transport, LinkTransport::Local);
        assert_eq!(
            cfg.supervisor.as_ref().unwrap().crown_jewel_crash,
            CrownJewelCrashPolicy::FailNodeClosed
        );
    }

    #[test]
    fn a_typo_capability_tag_is_refused_at_parse() {
        let ron = r#"(
            instances: { "x": ( capabilities: ["secrets.sealr"] ) },
        )"#;
        let err = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str::<PrivsepConfig>(ron)
            .unwrap_err();
        assert!(
            err.to_string().contains("unknown host authority")
                || err.to_string().contains("secrets.sealr")
        );
    }
}
