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
    /// The per-tenant TEMPLATE scale-to-zero policy (design §Phase-4 WS-C): the idle-eviction
    /// window + the concurrency ceiling the per-tenant router applies to the on-demand
    /// `exec.wasmtime` instances it instantiates. The struct-level `#[serde(default)]` supplies
    /// [`PerTenantPolicy::default`] for a config that omits it, and it is CONSULTED only when the
    /// composition defines a [`InstanceLifecycle::PerTenantTemplate`] (a no-template composition
    /// never reads it), so every pre-Phase-4 composition is byte-unchanged.
    pub per_tenant: PerTenantPolicy,
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
    /// The ISOLATION SUBSTRATE this instance's process runs under (design §Phase-3 / fabric §(b) —
    /// the `in`-axis spectrum). An OPERATOR-SELECTABLE choice (owner: NOT a hard pick —
    /// benchmark-guided), default [`InstanceSubstrate::OsProcess`]. The Phase-3 FOUNDATION cut wires
    /// `OsProcess`; `Container`/`Vm` are the config vocabulary + the supervisor's spawn-backend seam,
    /// refused fail-closed until their compute-plane-backend wiring lands (a reported follow-on). The
    /// struct-level `#[serde(default)]` supplies `OsProcess` for a config that omits it, so every
    /// Phase-1 composition is unchanged.
    pub substrate: InstanceSubstrate,
    /// The instance's LIFECYCLE model (design §Phase-4 WS-A). Default [`InstanceLifecycle::Static`]
    /// — forked ONCE at boot by the root supervisor and held for the node's life (the Phase-1/2/3
    /// behavior; the struct-level `#[serde(default)]` supplies it for a config that omits the field,
    /// so every pre-Phase-4 composition is byte-unchanged). [`InstanceLifecycle::PerTenantTemplate`]
    /// marks this entry a per-tenant **template**: a single on-disk definition the COMPUTE PLANE
    /// instantiates per active tenant (the owner-ratified boundary = **project**), pooled-per-tenant
    /// with scale-to-zero (WS-C) — NOT forked at boot. A template's AUTHORITY set is fixed on-disk
    /// exactly like a static instance (the F4 restart-class invariant): WS-A requires it to be
    /// precisely `{exec.wasmtime}` ([`CompositionViolation::WasmTemplateNotSoleExecWasmtime`]). Only
    /// the per-tenant SCOPE ([`TenantScope`] — the project id) is runtime-derived, and it grants NO
    /// authority; it only narrows which backend namespace the fixed feature-links reach. WS-A carries
    /// and lints the marker; the compute-plane instantiation loop and the Host-header routing that
    /// feed the scope are WS-B/WS-C.
    pub lifecycle: InstanceLifecycle,
    /// The link names (keys of [`PrivsepConfig::links`]) this instance opens.
    pub links: Vec<String>,
}

/// The LIFECYCLE model of a [`PrivsepInstanceConfig`] (design §Phase-4 WS-A). Distinguishes the
/// Phase-1/2/3 **static** instances — forked once at boot — from a Phase-4 per-tenant **template**:
/// a single on-disk definition the compute plane instantiates per active tenant (boundary = project).
///
/// **The F4 restart-class invariant is preserved for a template.** A template's capability set is an
/// on-disk fact, fixed before any spawn, exactly like a static instance's (design §1.1 / §5 F4): no
/// runtime write grants it an authority. The ONLY per-tenant, runtime-derived dimension is the
/// [`TenantScope`] (the project id), which grants NO authority — it narrows the backend namespace the
/// template's fixed feature-links reach, nothing more. The template therefore does NOT add a
/// per-tenant axis to [`HostAuthority`]: "the tenant's grants" is a SCOPE over mediated links, not a
/// capability subset.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum InstanceLifecycle {
    /// Forked ONCE at boot by the root supervisor and held for the node's life — every Phase-1/2/3
    /// instance. The default: a config that omits `lifecycle` is byte-unchanged.
    #[default]
    Static,
    /// A per-tenant TEMPLATE: a single on-disk definition the compute plane INSTANTIATES per active
    /// tenant (boundary = project), pooled-per-tenant with scale-to-zero (WS-C). NOT forked at boot.
    /// Its authority set is fixed on-disk and must be exactly `{exec.wasmtime}`
    /// ([`CompositionViolation::WasmTemplateNotSoleExecWasmtime`]); only its per-tenant
    /// [`TenantScope`] is runtime-derived (and grants no authority).
    PerTenantTemplate,
}

impl InstanceLifecycle {
    /// The stable config/log spelling.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::PerTenantTemplate => "per-tenant-template",
        }
    }

    /// Whether this instance is a per-tenant template the compute plane instantiates per tenant
    /// (rather than a static instance forked once at boot).
    pub const fn is_per_tenant_template(self) -> bool {
        matches!(self, Self::PerTenantTemplate)
    }
}

/// The host-resolved per-tenant **scope** a per-tenant TEMPLATE instance
/// ([`InstanceLifecycle::PerTenantTemplate`]) is instantiated FOR: the **project id** (the
/// owner-ratified tenant boundary). Design §Phase-4 WS-A.
///
/// **It is a non-secret name, carried like the other privsep name-wiring.** A scope is the project
/// slug — the same shape the data plane already keys tenant namespaces by (`project/<id>/…`, see
/// [`crate::project::resource_prefix`]). It is wired into an instantiated template exactly as the
/// fd map / unseal allowlist / authority-serve link set are (design §3.3 / the sibling
/// `compute_unseal_allowlists` + `compute_authority_serve_links`): **names only, never a secret,
/// never taken from a request body** — the root/compute-plane resolves it and sets it over
/// [`PRIVSEP_TENANT_SCOPE_ENV`] (a `BOATRAMP_*` non-secret env, like `BOATRAMP_PRIVSEP_FDS`).
///
/// **It grants NO authority (the F4 invariant).** The template's authority set is fixed on-disk
/// (`{exec.wasmtime}`); the scope only NARROWS which backend namespace the template's fixed
/// feature-links reach. A scope is not a capability and is never a wildcard.
///
/// **WS-A scope.** This type + its **fail-closed** [`resolve`](TenantScope::resolve) validator +
/// the non-secret env (de)serialization ([`env_value`](TenantScope::env_value) /
/// [`from_env_value`](TenantScope::from_env_value)). The Host-header → project resolution that
/// FEEDS `resolve` (the structural keying, mirroring `serve_pipeline::serve_by_host_inner`'s
/// `resolve_site_by_host`) is **WS-B**, and the compute-plane instantiation that consumes the env
/// is **WS-C** — NOT built here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantScope(String);

/// The non-secret env var the root / compute plane sets on an instantiated per-tenant template to
/// carry its resolved [`TenantScope`] (the project id — names only, never a secret, never from a
/// request). A `BOATRAMP_*` name so it passes the spawn-env allowlist, exactly like
/// `BOATRAMP_PRIVSEP_FDS` / `BOATRAMP_PRIVSEP_AUTHORITY_LINKS`. WS-C wires the actual set/read; WS-A
/// defines the name + the fail-closed (de)serialization so both ends share one source of truth.
pub const PRIVSEP_TENANT_SCOPE_ENV: &str = "BOATRAMP_PRIVSEP_TENANT_SCOPE";

/// Why a host-resolved value could not become a [`TenantScope`] — every arm is a **fail-closed
/// REFUSAL** (design §Phase-4 WS-A: an empty/unresolved scope refuses, and a scope is never a
/// wildcard). A template instance is NEVER instantiated against a rejected scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantScopeError {
    /// The host resolved NO tenant scope (the value is empty). Fail-closed: a per-tenant template is
    /// never instantiated with an empty scope — that would leave the per-tenant namespace
    /// unnarrowed. (The Host-header resolution that would produce a scope is WS-B; this is the
    /// representation-layer refusal it funnels into.)
    Unresolved,
    /// The scope is a WILDCARD (`*`, or it contains `*`). Fail-closed: a template scope must name
    /// EXACTLY ONE project — a wildcard would reach every tenant's namespace, defeating the
    /// per-tenant isolation the template exists to draw.
    Wildcard {
        /// The offending value as supplied.
        got: String,
    },
    /// The scope is not a valid project slug (contains `/`, `..`, a path-traversal or non-ASCII
    /// byte, a Unicode homoglyph, or exceeds [`crate::project::MAX_RESOURCE_NAME_LEN`]). Validated
    /// structurally by [`crate::project::is_valid_resource_slug`] — the single source of truth the
    /// data plane already keys tenant namespaces by, so a scope can never be a crafted key.
    Malformed {
        /// The offending value as supplied.
        got: String,
    },
}

impl std::fmt::Display for TenantScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolved => f.write_str(
                "per-tenant template scope is empty/unresolved — refusing fail-closed (a template is \
                 never instantiated without a concrete project id)",
            ),
            Self::Wildcard { got } => write!(
                f,
                "per-tenant template scope {got:?} is a wildcard — refusing fail-closed (a template \
                 scope must name exactly one project, never a wildcard over every tenant)"
            ),
            Self::Malformed { got } => write!(
                f,
                "per-tenant template scope {got:?} is not a valid project slug ({}) — refusing \
                 fail-closed",
                crate::project::INVALID_NAME_REASON
            ),
        }
    }
}

impl std::error::Error for TenantScopeError {}

impl TenantScope {
    /// **Fail-closed** derive-and-validate (design §Phase-4 WS-A). Accepts a host-resolved project
    /// id and returns a scope ONLY when it is a concrete, single, valid project slug. Refuses:
    /// - an EMPTY value ([`TenantScopeError::Unresolved`]) — never a scope over the whole namespace;
    /// - a WILDCARD (`*` / contains `*`) ([`TenantScopeError::Wildcard`]) — never every tenant;
    /// - any non-slug value ([`TenantScopeError::Malformed`]) — validated by
    ///   [`crate::project::is_valid_resource_slug`] (rejects `/`, `..`, path-traversal, non-ASCII
    ///   homoglyphs, over-length), the same rule the data plane keys tenant namespaces by.
    ///
    /// Pure + host-testable; no routing, no env, no request context — the Host-header resolution
    /// that produces the input is WS-B.
    pub fn resolve(project: &str) -> Result<Self, TenantScopeError> {
        if project.is_empty() {
            return Err(TenantScopeError::Unresolved);
        }
        if project.contains('*') {
            return Err(TenantScopeError::Wildcard {
                got: project.to_string(),
            });
        }
        if !crate::project::is_valid_resource_slug(project) {
            return Err(TenantScopeError::Malformed {
                got: project.to_string(),
            });
        }
        Ok(Self(project.to_string()))
    }

    /// The resolved project id (the tenant boundary). Always a valid slug — never empty, never a
    /// wildcard (enforced at [`resolve`](Self::resolve)).
    pub fn project(&self) -> &str {
        &self.0
    }

    /// The backend keyspace prefix this scope narrows the template's fixed feature-links to
    /// (`project/<id>/…`). The scope grants no authority — it only selects this namespace.
    pub fn resource_prefix(&self) -> String {
        crate::project::resource_prefix(&self.0)
    }

    /// The non-secret value to set in [`PRIVSEP_TENANT_SCOPE_ENV`] (the bare project id — names
    /// only, no secret). WS-C sets this on an instantiated template; the symmetric reader is
    /// [`from_env_value`](Self::from_env_value).
    pub fn env_value(&self) -> &str {
        &self.0
    }

    /// Re-derive a scope from a [`PRIVSEP_TENANT_SCOPE_ENV`] value, re-validating fail-closed — so a
    /// tampered or truncated env value refuses exactly as a bad resolution would, rather than being
    /// trusted because it arrived in the environment.
    pub fn from_env_value(value: &str) -> Result<Self, TenantScopeError> {
        Self::resolve(value)
    }
}

/// The ISOLATION SUBSTRATE a feature-instance's process runs under (design §Phase-3; fabric-composition
/// §(b) — the `in`-axis containment spectrum). **Operator-selectable, benchmark-guided (owner decision
/// 2026-11-02 — NOT a hard pick):** the same instance abstraction is substrate-agnostic (design §7 —
/// "substrate is a spawn backend"), so the root supervisor picks the spawn backend per instance,
/// graded by containment strength vs crossing overhead. See `docs/privsep-substrate-benchmark.md` for
/// the measured `local`-shape crossing costs that inform the choice.
///
/// - [`OsProcess`](InstanceSubstrate::OsProcess) — a privilege-dropped OS process wired over the
///   root-created `local` socketpair (the Phase-1 spawn backend, the default). Native speed, shared
///   kernel; the containment is the separate address space + the per-capability seccomp/Landlock wall.
/// - [`Container`](InstanceSubstrate::Container) — the same dropped process under namespace/cgroup
///   confinement, reusing the `boatramp-container` compute-plane backend. Native speed, a namespace
///   wall; excludes kernel-escape from the threat model.
/// - [`Vm`](InstanceSubstrate::Vm) — a hardware-virtualized microVM guest with its own kernel, reusing
///   the `boatramp-firecracker` / `boatramp-vz` compute-plane backends. The strongest wall (survives a
///   guest-kernel RCE); a vsock crossing per request + a boot cost.
///
/// **Phase-3 FOUNDATION scope:** only `OsProcess` is a WIRED spawn backend. `Container`/`Vm` parse +
/// lint as valid composition vocabulary, but the supervisor REFUSES to spawn them fail-closed (naming
/// the compute-plane backend each reuses) rather than silently downgrading to an OS process — a silent
/// downgrade would discard the operator's chosen isolation wall. See [`InstanceSubstrate::is_wired`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum InstanceSubstrate {
    /// A privilege-dropped OS process over the `local` socketpair (the Phase-1 spawn backend). Default.
    #[default]
    OsProcess,
    /// A namespace/cgroup-confined process (reuses the `boatramp-container` backend). Follow-on.
    Container,
    /// A hardware-virtualized microVM guest (reuses `boatramp-firecracker` / `boatramp-vz`). Follow-on.
    Vm,
}

impl InstanceSubstrate {
    /// The stable config/log spelling.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::OsProcess => "os-process",
            Self::Container => "container",
            Self::Vm => "vm",
        }
    }

    /// Whether the Phase-3 FOUNDATION cut wires this substrate's spawn backend. Only `OsProcess` is
    /// wired; `Container`/`Vm` are the reported follow-on (refused fail-closed by the supervisor).
    pub const fn is_wired(self) -> bool {
        matches!(self, Self::OsProcess)
    }

    /// The compute-plane backend crate a NESTING substrate reuses — for the fail-closed follow-on
    /// message. `None` for `OsProcess` (the root's own fork+exec is the backend).
    pub const fn compute_plane_backend(self) -> Option<&'static str> {
        match self {
            Self::OsProcess => None,
            Self::Container => Some("boatramp-container (namespace/cgroup confinement)"),
            Self::Vm => Some("boatramp-firecracker / boatramp-vz (microVM over a vsock crossing)"),
        }
    }
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
/// grammar are WS-C. Phase-3 adds the explicit per-link [`purpose`](PrivsepLink::purpose) marker.
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
    /// The declared PURPOSE of this link (design §3.1 — the two use-shapes over one link; §3.4
    /// precondition 4 — the per-link marker). Default [`LinkPurpose::Unspecified`] ⇒ the role is
    /// INFERRED from the endpoints (the pre-Phase-3 behavior, back-compat). An explicit
    /// [`LinkPurpose::AuthorityServe`] designates the link's crown-jewel endpoint to serve the
    /// authority grammar on it (even when the peer is a listener frontend — the shape the inference
    /// could not safely disambiguate); [`LinkPurpose::Relay`] marks it a serving splice that is
    /// NEVER an authority-serve link. The struct-level `#[serde(default)]` supplies
    /// [`LinkPurpose::Unspecified`] for a config that omits it.
    pub purpose: LinkPurpose,
}

impl PrivsepLink {
    /// Whether this link is EXPLICITLY purpose-marked as an authority-serve link (design §3.4). The
    /// half that — together with the sibling PoP/`cnf` verifier (an AND-gate) — lets the Phase-1
    /// authority-serve stand-up gate open.
    pub const fn is_authority_serve(&self) -> bool {
        matches!(self.purpose, LinkPurpose::AuthorityServe)
    }

    /// Whether this link is EXPLICITLY purpose-marked as a serving-splice relay (frontend→backend).
    pub const fn is_relay(&self) -> bool {
        matches!(self.purpose, LinkPurpose::Relay)
    }
}

/// The declared PURPOSE of a feature-link (design §3.1's two use-shapes, made EXPLICIT per-link in
/// the Phase-3 foundation). A link between a listener FRONTEND and a crown-jewel SIGNER is
/// byte-for-byte the same TOPOLOGY shape as a listener frontend → a serving backend, so the
/// Phase-1 inference ([`crate::privsep`]'s `compute_authority_serve_links`, over in `boatramp`)
/// conservatively refused to auto-designate that shape for the authority grammar. This marker lets
/// the operator state the intent, which is design §3.4 wiring-gate precondition 4 — the half that,
/// together with the sibling PoP/`cnf` verifier (an AND-gate, both required), lets the
/// authority-serve stand-up gate open.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum LinkPurpose {
    /// Unspecified — the link's role is INFERRED from its endpoints' authorities (the pre-Phase-3
    /// behavior, kept for back-compat + the simple splits the Phase-1 live gates use). A crown↔
    /// (non-listener) link is conservatively inferred as an authority-serve link; every other shape
    /// (notably a listener-frontend link) is treated as a serving splice and NEVER auto-designated
    /// for the authority grammar. The default.
    #[default]
    Unspecified,
    /// The frontend→backend SERVING SPLICE relay — the per-request-hot path carrying spliced client
    /// connections (`SCM_RIGHTS` / byte-relay), NOT authority calls. Marking a link `relay` states
    /// explicitly that it is a splice, so it is NEVER designated for the authority grammar even when
    /// an endpoint happens to hold a crown jewel.
    Relay,
    /// An AUTHORITY-SERVE link: the non-crown endpoint (a frontend / control relay) makes typed,
    /// bounded authority calls (seal/unseal/mint_token) to the crown-jewel endpoint, which serves
    /// the WS-E grammar re-validating each call's end-principal context. This explicit marker lets a
    /// listener-FRONTEND→signer authority link be designated WITHOUT colliding with the
    /// link-shape-identical serving splice. It designates the serve but does NOT by itself open the
    /// LIVE serve — the stand-up gate additionally requires the PoP/`cnf` verifier (the AND-gate the
    /// sibling authority layer owns). The composition-closure lint REFUSES an `authority-serve` link
    /// that lacks exactly one crown-jewel endpoint ([`CompositionViolation::AuthorityServeLinkNotSingleCrownJewel`]).
    AuthorityServe,
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

/// The per-tenant TEMPLATE **scale-to-zero policy** (design §Phase-4 WS-C): operator-tunable, with
/// fail-closed defaults. It governs how the per-tenant router (the frontend) POOLS the on-demand
/// `exec.wasmtime` instances it instantiates per tenant — how long an idle instance lives before it
/// is evicted (scale-to-zero), and the hard ceiling on how many may run at once. It lives in the
/// `[privsep]` config (restart-class, like the rest of the composition — §5 F4), and it matters
/// ONLY when the composition declares a [`InstanceLifecycle::PerTenantTemplate`]: a no-template
/// composition never reads it, so the defaults carried for every pre-Phase-4 composition change
/// nothing.
///
/// **Defaults (owner-ratified):** `idle_eviction_secs = 300`, `max_instances = 64`. **Fail-closed:**
/// a misconfigured policy (`max_instances == 0`) is REFUSED at the root's authorization gate before
/// any spawn ([`validate`](PerTenantPolicy::validate)) rather than silently serving no tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PerTenantPolicy {
    /// Idle-eviction window in SECONDS: a per-tenant instance with no routed connection for at
    /// least this long is evicted (its process killed, its link dropped) — the scale-to-zero knob.
    /// Default `300`. `0` DISABLES idle eviction (an instance then lives until the concurrency cap
    /// forces a least-recently-used eviction).
    pub idle_eviction_secs: u64,
    /// The hard ceiling on concurrently-live per-tenant instances. Default `64`. A new tenant beyond
    /// the cap first triggers an idle sweep, then (if still at the cap) evicts the LEAST-recently-used
    /// live instance to make room — it never exceeds the cap and never silently refuses a valid
    /// tenant. Fail-closed: `0` is a misconfiguration ([`PerTenantPolicyError::ZeroMaxInstances`]).
    pub max_instances: u32,
}

impl Default for PerTenantPolicy {
    fn default() -> Self {
        Self {
            idle_eviction_secs: 300,
            max_instances: 64,
        }
    }
}

/// A misconfigured [`PerTenantPolicy`] — a fail-closed REFUSAL the root surfaces before any spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerTenantPolicyError {
    /// `max_instances == 0` — a template composition that could never instantiate any tenant
    /// instance. Fail-closed: refuse rather than silently serve no tenant.
    ZeroMaxInstances,
}

impl std::fmt::Display for PerTenantPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxInstances => f.write_str(
                "[privsep].per_tenant.max_instances is 0 — a per-tenant template composition could \
                 never instantiate any tenant instance; set it to at least 1 (default 64)",
            ),
        }
    }
}

impl std::error::Error for PerTenantPolicyError {}

impl PerTenantPolicy {
    /// Fail-closed validation (design §Phase-4 WS-C) — the root runs it before any spawn when the
    /// composition declares a per-tenant template, refusing a policy that could never serve.
    pub fn validate(&self) -> Result<(), PerTenantPolicyError> {
        if self.max_instances == 0 {
            return Err(PerTenantPolicyError::ZeroMaxInstances);
        }
        Ok(())
    }

    /// The idle-eviction window as a [`std::time::Duration`], or `None` when eviction is disabled
    /// (`idle_eviction_secs == 0`).
    pub fn idle_eviction(&self) -> Option<std::time::Duration> {
        (self.idle_eviction_secs > 0)
            .then(|| std::time::Duration::from_secs(self.idle_eviction_secs))
    }
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
    /// `[serve.signer]` is a SEALED key source (resolved NOT inline — the `token.signer`
    /// instance asks a `secrets.sealer` instance to unseal its key over the feature-link,
    /// per the "signer-key unlock" owner decision), but NO instance in the composition holds
    /// `secrets.sealer` — the signer's key could never be unsealed. Fail-closed
    /// ([`check_sealed_signer_closure`]).
    SealedSignerWithoutSealer {
        /// The instance(s) holding `token.signer` (the signer that could not be unlocked).
        signer_instances: Vec<String>,
    },
    /// A `token.signer` instance with a SEALED key source does NOT itself hold
    /// `secrets.sealer` AND has NO feature-link to any `secrets.sealer` instance — it cannot
    /// ask the sealer to unseal its key. Fail-closed: a sealed signer must either CO-RESIDE
    /// the sealer (resolve in-process) or be LINKED to a sealer instance
    /// ([`check_sealed_signer_closure`]).
    SealedSignerUnlinkedToSealer {
        /// The offending `token.signer` instance.
        signer_instance: String,
    },
    /// A link is explicitly purpose-marked [`LinkPurpose::AuthorityServe`] but does NOT have EXACTLY
    /// ONE crown-jewel (group A) endpoint, so it cannot be an authority-serve link: the authority
    /// grammar (seal/unseal/mint_token) is held only by a crown jewel, so ZERO crown endpoints has
    /// no server, and TWO is the crown↔crown bootstrap-unseal shape (handled by the root-wired
    /// unseal allowlist, not the WS-E grammar). Fail-closed: a misconfigured marker refuses the node
    /// closed rather than standing up an unserveable or ambiguous authority link (design §3.4).
    AuthorityServeLinkNotSingleCrownJewel {
        /// The offending link name.
        link: String,
        /// Its endpoints that hold a crown jewel (0, or ≥2 — never exactly 1, or this would not fire).
        crown_endpoints: Vec<String>,
    },
    /// A per-tenant TEMPLATE instance ([`InstanceLifecycle::PerTenantTemplate`]) holds a capability
    /// set OTHER than exactly `{exec.wasmtime}` (design §Phase-4 WS-A). A template is the guest-JIT
    /// surface the compute plane instantiates per tenant; it must materialize ONLY `exec.wasmtime` so
    /// a wasmtime escape lands in a SINGLE tenant's guest runtime and nothing else — no key, no pool,
    /// no listener, no control surface, and never a crown jewel. Fail-closed: the root refuses the
    /// node closed rather than instantiate a template that would widen a per-tenant escape.
    WasmTemplateNotSoleExecWasmtime {
        /// The offending template instance label.
        instance: String,
        /// Whether it holds `exec.wasmtime` at all (`false` ⇒ it is MISSING the one capability it
        /// must have).
        holds_exec_wasmtime: bool,
        /// The capabilities it holds BEYOND `exec.wasmtime` — the extras to remove (empty when the
        /// sole fault is a missing `exec.wasmtime`). Any crown-jewel key here is doubly disqualifying.
        extra: Vec<HostAuthority>,
    },
    /// One instance co-resides BOTH `exec.compute` and `exec.wasmtime` while the composition defines a
    /// per-tenant TEMPLATE (design §Phase-4 WS-A). The compute-plane SUPERVISOR (`exec.compute`) that
    /// SCHEDULES the per-tenant guest-runtime templates must not ITSELF run guests (`exec.wasmtime`):
    /// co-residency would put a wasmtime escape in the very process that orchestrates every tenant's
    /// instance, re-collapsing the per-tenant boundary Phase-4 exists to draw. Fail-closed.
    ///
    /// **Gated on template presence** (a composition with at least one
    /// [`InstanceLifecycle::PerTenantTemplate`]): without a template, `exec.compute` schedules no
    /// per-tenant instances, so a pre-Phase-4 composition that co-resides the two exec authorities on
    /// one instance (the shipped monolith-equivalent `edge`/`all` compositions, the live-gate
    /// fixtures) is UNCHANGED — the rule fires only once the per-tenant template makes `exec.compute`
    /// the per-tenant scheduler.
    ExecComputeAndWasmtimeCoResident {
        /// The offending instance label.
        instance: String,
    },
    /// A STATIC (non-template) instance holds `exec.wasmtime` WHILE the composition defines a
    /// per-tenant TEMPLATE (design §Phase-4 WS-A). Once a per-tenant template exists, the guest JIT
    /// runs ONLY as a per-tenant instance — one isolated `exec.wasmtime` per tenant — so a shared,
    /// cross-tenant `exec.wasmtime` on ANY static instance re-opens the very boundary the template
    /// draws: a wasmtime escape there would land in a runtime common to every tenant's guests at once.
    /// Fail-closed: once templates exist, `exec.wasmtime` may live ONLY on a per-tenant template.
    ///
    /// This STRICTLY SUBSUMES the `exec.wasmtime`-on-scheduler case of
    /// [`CompositionViolation::ExecComputeAndWasmtimeCoResident`] (that scheduler is a static instance
    /// that holds `exec.wasmtime`), making the "one wasmtime instance per tenant" invariant COMPLETE
    /// and on-disk-provable — not only the exec.compute co-residency shape.
    ///
    /// **Gated on template presence** (at least one [`InstanceLifecycle::PerTenantTemplate`]): without
    /// a template, `exec.wasmtime` on a static instance is the shipped monolith-equivalent runtime and
    /// UNCHANGED — every pre-Phase-4 composition stays byte-compatible.
    ExecWasmtimeOutsidePerTenantTemplate {
        /// The offending static instance label (it holds `exec.wasmtime` but is not a per-tenant
        /// template, while the composition defines at least one template).
        instance: String,
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
            Self::SealedSignerWithoutSealer { signer_instances } => write!(
                f,
                "[serve.signer] is a sealed key source (unsealed by a secrets.sealer over the \
                 feature-link), but no instance holds `secrets.sealer` — the token.signer \
                 instance(s) [{}] could never unlock the signing key; add a `secrets.sealer` \
                 instance (and link it to the signer)",
                signer_instances.join(", ")
            ),
            Self::SealedSignerUnlinkedToSealer { signer_instance } => write!(
                f,
                "token.signer instance {signer_instance:?} has a sealed key source but neither \
                 holds `secrets.sealer` itself nor is linked to a `secrets.sealer` instance — it \
                 cannot ask the sealer to unseal its key; co-reside the sealer or add a link \
                 between them"
            ),
            Self::AuthorityServeLinkNotSingleCrownJewel {
                link,
                crown_endpoints,
            } => write!(
                f,
                "link {link:?} is purpose-marked `authority-serve` but has {} crown-jewel \
                 endpoint(s) [{}] — an authority-serve link must have EXACTLY ONE crown-jewel \
                 endpoint (the server) and one non-crown relay (the caller); a crown↔crown link is \
                 bootstrap-unseal, not an authority serve",
                crown_endpoints.len(),
                crown_endpoints.join(", ")
            ),
            Self::WasmTemplateNotSoleExecWasmtime {
                instance,
                holds_exec_wasmtime,
                extra,
            } => {
                if !*holds_exec_wasmtime {
                    write!(
                        f,
                        "per-tenant template instance {instance:?} does not hold `exec.wasmtime` — a \
                         wasm-runtime template must hold EXACTLY `{{exec.wasmtime}}`{}",
                        if extra.is_empty() {
                            String::new()
                        } else {
                            format!(" (and must drop [{}])", tags(extra))
                        }
                    )
                } else {
                    write!(
                        f,
                        "per-tenant template instance {instance:?} holds [{}] beyond `exec.wasmtime` \
                         — a wasm-runtime template must hold EXACTLY `{{exec.wasmtime}}` (no key, no \
                         pool, no listener, no control surface) so a guest escape is confined to one \
                         tenant",
                        tags(extra)
                    )
                }
            }
            Self::ExecComputeAndWasmtimeCoResident { instance } => write!(
                f,
                "instance {instance:?} co-resides `exec.compute` and `exec.wasmtime` while the \
                 composition defines a per-tenant template — the compute-plane supervisor that \
                 schedules per-tenant instances must not itself run guests; split `exec.wasmtime` \
                 (the per-tenant template) off the `exec.compute` supervisor instance"
            ),
            Self::ExecWasmtimeOutsidePerTenantTemplate { instance } => write!(
                f,
                "instance {instance:?} holds `exec.wasmtime` but is NOT a per-tenant template, while \
                 the composition defines a per-tenant template — once per-tenant templates exist the \
                 guest runtime must run ONLY as a per-tenant instance (one isolated `exec.wasmtime` \
                 per tenant); a shared, cross-tenant `exec.wasmtime` here would defeat the \
                 one-wasmtime-instance-per-tenant guarantee. Move `exec.wasmtime` onto a per-tenant \
                 template instance (lifecycle `per-tenant-template`)"
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
/// - an instance `links` entry referencing an undefined link;
/// - **(Phase-4 WS-A)** a per-tenant TEMPLATE instance whose capability set is not exactly
///   `{exec.wasmtime}` ([`CompositionViolation::WasmTemplateNotSoleExecWasmtime`]);
/// - **(Phase-4 WS-A)** `exec.compute` co-resident with `exec.wasmtime` on one instance WHEN the
///   composition defines a per-tenant template
///   ([`CompositionViolation::ExecComputeAndWasmtimeCoResident`]) — gated on template presence, so
///   every pre-Phase-4 composition is unchanged;
/// - **(Phase-4 WS-A)** `exec.wasmtime` held by a STATIC (non-template) instance WHEN the composition
///   defines a per-tenant template
///   ([`CompositionViolation::ExecWasmtimeOutsidePerTenantTemplate`]) — once templates exist the
///   guest runtime lives ONLY on per-tenant templates, so a shared cross-tenant wasmtime is refused;
///   strictly subsumes the exec.wasmtime-on-scheduler case of the rule above, and likewise gated on
///   template presence (pre-Phase-4 byte-compatible).
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

    // Phase-4 WS-A: does the composition define a per-tenant template at all? The exec.compute ×
    // exec.wasmtime co-residency refusal is gated on this (a composition with no template schedules
    // no per-tenant instances, so `exec.compute` is not yet the per-tenant scheduler — every
    // pre-Phase-4 composition stays unchanged).
    let has_per_tenant_template = cfg
        .instances
        .values()
        .any(|i| i.lifecycle.is_per_tenant_template());

    // --- Per-instance checks: zero-cap, crown-jewel exclusion, F8 second tier, Phase-4 template. ---
    for (name, inst) in &cfg.instances {
        if inst.capabilities.is_empty() {
            violations.push(CompositionViolation::ZeroCapabilityInstance {
                instance: name.clone(),
            });
            // A zero-cap instance has nothing further to check for co-residency. (A zero-cap
            // per-tenant template is reported here; its missing `exec.wasmtime` is the same fault.)
            continue;
        }

        // Deduplicate within an instance so a repeated tag doesn't skew the report.
        let held: BTreeSet<HostAuthority> = inst.capabilities.iter().copied().collect();

        // Phase-4 WS-A rule (a): a per-tenant TEMPLATE must hold EXACTLY `{exec.wasmtime}` — no
        // extra capability, no crown-jewel key. (A crown jewel on a template ALSO trips the
        // crown-jewel exclusion below, since exec.wasmtime is in the exclusion surface; both fire,
        // and this gives the template-specific message.)
        if inst.lifecycle.is_per_tenant_template() {
            let holds_exec_wasmtime = held.contains(&HostAuthority::ExecWasmtime);
            let extra: Vec<HostAuthority> = held
                .iter()
                .copied()
                .filter(|a| *a != HostAuthority::ExecWasmtime)
                .collect();
            if !holds_exec_wasmtime || !extra.is_empty() {
                violations.push(CompositionViolation::WasmTemplateNotSoleExecWasmtime {
                    instance: name.clone(),
                    holds_exec_wasmtime,
                    extra,
                });
            }
        }

        // Phase-4 WS-A rule (b): the compute supervisor must not itself run guests — reject
        // exec.compute co-resident with exec.wasmtime ONCE a per-tenant template exists.
        if has_per_tenant_template
            && held.contains(&HostAuthority::ExecCompute)
            && held.contains(&HostAuthority::ExecWasmtime)
        {
            violations.push(CompositionViolation::ExecComputeAndWasmtimeCoResident {
                instance: name.clone(),
            });
        }

        // Phase-4 WS-A rule (c): once a per-tenant template exists, `exec.wasmtime` may live ONLY on a
        // per-tenant template — a STATIC instance holding it is a shared, cross-tenant guest runtime
        // that re-opens the per-tenant boundary (a wasmtime escape would reach every tenant's guests).
        // This STRICTLY SUBSUMES the exec.wasmtime-on-scheduler case of rule (b) (a static scheduler
        // holding exec.wasmtime trips here too); rule (b) stays as belt-and-suspenders.
        if has_per_tenant_template
            && held.contains(&HostAuthority::ExecWasmtime)
            && !inst.lifecycle.is_per_tenant_template()
        {
            violations.push(CompositionViolation::ExecWasmtimeOutsidePerTenantTemplate {
                instance: name.clone(),
            });
        }

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

    // --- Purpose-marker closure: an `authority-serve` link needs EXACTLY ONE crown-jewel endpoint
    //     (design §3.4). Only meaningful when both endpoints are hosted — an unhosted endpoint is
    //     already a LinkEndpointUnhosted violation above, and this would double-report. ---
    for (link_name, link) in &cfg.links {
        if !link.is_authority_serve() {
            continue;
        }
        let from_hosted = cfg.instances.contains_key(&link.from);
        let to_hosted = cfg.instances.contains_key(&link.to);
        if !(from_hosted && to_hosted) {
            continue;
        }
        let holds_crown = |ep: &str| -> bool {
            cfg.instances
                .get(ep)
                .is_some_and(|i| i.capabilities.iter().any(|a| a.is_crown_jewel()))
        };
        let crown_endpoints: Vec<String> = [&link.from, &link.to]
            .into_iter()
            .filter(|ep| holds_crown(ep))
            .cloned()
            .collect();
        if crown_endpoints.len() != 1 {
            violations.push(
                CompositionViolation::AuthorityServeLinkNotSingleCrownJewel {
                    link: link_name.clone(),
                    crown_endpoints,
                },
            );
        }
    }

    if violations.is_empty() {
        Ok(CompositionReport { warnings })
    } else {
        Err(CompositionError { violations })
    }
}

/// Whether some link in `cfg` DIRECTLY connects instances `a` and `b` (either direction).
fn instances_linked(cfg: &PrivsepConfig, a: &str, b: &str) -> bool {
    cfg.links
        .values()
        .any(|l| (l.from == a && l.to == b) || (l.from == b && l.to == a))
}

/// The **sealed-signer composition-closure rule** (the "signer-key unlock" owner decision):
/// when `[serve.signer]` is a SEALED key source (`sealed_signer == true` — a `boatramp:<name>`
/// or `path:` reference the signer resolves NOT inline), a `token.signer` instance cannot hold
/// the `[secrets]` KEK itself (that would collapse the `secrets.sealer` ↔ `token.signer` split),
/// so it must obtain its key by asking a `secrets.sealer` instance to unseal it over the
/// feature-link. This fail-closed check — run IN THE ROOT, before any spawn, alongside
/// [`check_composition_closure`] — REFUSES a composition where that is impossible:
///
/// - a sealed signer but NO instance holds `secrets.sealer` ([`CompositionViolation::SealedSignerWithoutSealer`]);
/// - a `token.signer` instance that neither CO-RESIDES `secrets.sealer` (resolving its key
///   in-process) nor is LINKED to a `secrets.sealer` instance
///   ([`CompositionViolation::SealedSignerUnlinkedToSealer`]).
///
/// `sealed_signer` is the node-global fact "`[serve.signer]` is the sealed variant" — the caller
/// (the root) derives it from the resolved `ServerConfig`, since this wasm-clean types layer does
/// not see `AuthSignerConfig`. An AwsKms / ambient / absent signer passes `false` and the rule is
/// a no-op (it needs no sealer).
///
/// Kept SEPARATE from [`check_composition_closure`] (whose signature + many callers stay pure over
/// [`PrivsepConfig`] alone): the root runs both and surfaces either refusal identically.
pub fn check_sealed_signer_closure(
    cfg: &PrivsepConfig,
    sealed_signer: bool,
) -> Result<(), CompositionError> {
    if !sealed_signer {
        return Ok(());
    }
    let mut violations = Vec::new();

    let signer_instances: Vec<&String> = cfg
        .instances
        .iter()
        .filter(|(_, inst)| inst.capabilities.contains(&HostAuthority::TokenSigner))
        .map(|(name, _)| name)
        .collect();
    let sealer_instances: Vec<&String> = cfg
        .instances
        .iter()
        .filter(|(_, inst)| inst.capabilities.contains(&HostAuthority::SecretsSealer))
        .map(|(name, _)| name)
        .collect();

    // A sealed signer source with the `token.signer` authority unhosted is already an
    // UnhostedCapabilities refusal from `check_composition_closure`; nothing to add here.
    if signer_instances.is_empty() {
        return Ok(());
    }

    if sealer_instances.is_empty() {
        violations.push(CompositionViolation::SealedSignerWithoutSealer {
            signer_instances: signer_instances.into_iter().cloned().collect(),
        });
        return Err(CompositionError { violations });
    }

    for signer in signer_instances {
        // Co-resident signer+sealer resolves its key in-process (it holds the KEK) — no link
        // needed. This is the less-separated (but valid) composition, e.g. an A∪B "core".
        if sealer_instances.contains(&signer) {
            continue;
        }
        let linked = sealer_instances
            .iter()
            .any(|sealer| instances_linked(cfg, signer, sealer));
        if !linked {
            violations.push(CompositionViolation::SealedSignerUnlinkedToSealer {
                signer_instance: signer.clone(),
            });
        }
    }

    if violations.is_empty() {
        Ok(())
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
            substrate: InstanceSubstrate::OsProcess,
            links: Vec::new(),
            ..Default::default()
        }
    }

    /// A per-tenant TEMPLATE instance holding the given capability set (Phase-4 WS-A fixture).
    fn template(caps: &[HostAuthority]) -> PrivsepInstanceConfig {
        PrivsepInstanceConfig {
            capabilities: caps.to_vec(),
            lifecycle: InstanceLifecycle::PerTenantTemplate,
            ..Default::default()
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
            per_tenant: PerTenantPolicy::default(),
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
                purpose: LinkPurpose::Unspecified,
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
            per_tenant: PerTenantPolicy::default(),
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
                purpose: LinkPurpose::Unspecified,
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

    // ---- sealed-signer closure rule (signer-key unlock) ----

    /// A composition with the signer (`token.signer`) SPLIT onto its own instance, linked to a
    /// separate `secrets.sealer`-holding instance — the intended sealed-signer topology.
    fn split_signer_composition() -> PrivsepConfig {
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
            "core".to_string(),
            inst(&[
                HostAuthority::BackendKv,
                HostAuthority::BackendSql,
                HostAuthority::BackendBlob,
                HostAuthority::BackendMessaging,
            ]),
        );
        // The SEALER: every crown jewel EXCEPT token.signer.
        instances.insert(
            "sealer".to_string(),
            inst(&[
                HostAuthority::SecretsSealer,
                HostAuthority::ImageSigner,
                HostAuthority::OverlayDialSigner,
                HostAuthority::S3IngressRoot,
                HostAuthority::ClusterJoinSigner,
            ]),
        );
        // The SIGNER: token.signer alone.
        instances.insert("signer".to_string(), inst(&[HostAuthority::TokenSigner]));
        let mut links = BTreeMap::new();
        links.insert(
            "to-signer".to_string(),
            PrivsepLink {
                from: "sealer".to_string(),
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

    #[test]
    fn sealed_signer_check_is_a_noop_for_a_non_sealed_signer() {
        // `sealed_signer == false` (AwsKms / ambient / absent) ⇒ the rule never fires, even for
        // a composition that WOULD fail it (no sealer at all).
        let mut cfg = clean_composition();
        // Drop secrets.sealer from the signer instance → no sealer anywhere.
        cfg.instances
            .get_mut("signer")
            .unwrap()
            .capabilities
            .retain(|a| *a != HostAuthority::SecretsSealer);
        // The clean lint would now flag UnhostedCapabilities (sealer unhosted), but the
        // sealed-signer check specifically is a no-op when the signer is not sealed.
        check_sealed_signer_closure(&cfg, false).expect("non-sealed signer skips the rule");
    }

    #[test]
    fn sealed_signer_split_from_a_linked_sealer_is_accepted() {
        check_sealed_signer_closure(&split_signer_composition(), true)
            .expect("a sealed signer linked to a separate sealer is accepted");
    }

    #[test]
    fn sealed_signer_co_resident_with_the_sealer_is_accepted() {
        // The `clean_composition` "signer" instance holds BOTH secrets.sealer and token.signer —
        // it resolves its key in-process (holds the KEK), so no link is required.
        check_sealed_signer_closure(&clean_composition(), true)
            .expect("a signer co-resident with the sealer resolves in-process (no link needed)");
    }

    #[test]
    fn sealed_signer_without_any_sealer_is_refused() {
        let mut cfg = split_signer_composition();
        // Remove secrets.sealer entirely (move its remaining jewels onto the signer so the union
        // still == ALL and this is the SOLE fault the sealed-signer check sees).
        let sealer_caps = cfg.instances.remove("sealer").unwrap().capabilities;
        let keep: Vec<HostAuthority> = sealer_caps
            .into_iter()
            .filter(|a| *a != HostAuthority::SecretsSealer)
            .collect();
        cfg.instances
            .get_mut("signer")
            .unwrap()
            .capabilities
            .extend(keep);
        // Drop the now-dangling link.
        cfg.links.clear();
        let err = check_sealed_signer_closure(&cfg, true).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::SealedSignerWithoutSealer { signer_instances }
                if signer_instances.contains(&"signer".to_string())
        )));
    }

    #[test]
    fn sealed_signer_unlinked_to_the_sealer_is_refused() {
        let mut cfg = split_signer_composition();
        // Keep the separate sealer, but SEVER the signer↔sealer link.
        cfg.links.clear();
        let err = check_sealed_signer_closure(&cfg, true).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            CompositionViolation::SealedSignerUnlinkedToSealer { signer_instance }
                if signer_instance == "signer"
        )));
    }

    // ---- per-link PURPOSE marker (Phase-3 foundation, design §3.4 precondition 4) ----

    #[test]
    fn link_purpose_defaults_to_unspecified_and_round_trips_through_ron() {
        // A config that omits `purpose` defaults to Unspecified (back-compat with every Phase-1 cfg).
        let ron = r#"(
            instances: {
                "edge": ( capabilities: ["listen.http-parse"], links: ["to-sign"] ),
                "signer": ( capabilities: ["token.signer"], links: ["to-sign"] ),
            },
            links: {
                "to-sign": (from: "edge", to: "signer", transport: Local, purpose: AuthorityServe),
                "to-core": (from: "edge", to: "signer", transport: Local),
            },
        )"#;
        let cfg: PrivsepConfig = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(ron)
            .expect("parse privsep RON with a purpose marker");
        assert_eq!(cfg.links["to-sign"].purpose, LinkPurpose::AuthorityServe);
        assert!(cfg.links["to-sign"].is_authority_serve());
        // An omitted `purpose` defaults to Unspecified.
        assert_eq!(cfg.links["to-core"].purpose, LinkPurpose::Unspecified);
        assert!(!cfg.links["to-core"].is_authority_serve());
        assert!(!cfg.links["to-core"].is_relay());
    }

    #[test]
    fn authority_serve_marker_requires_exactly_one_crown_jewel_endpoint() {
        // A crown↔non-crown authority-serve link is accepted (exactly one crown endpoint = the server).
        let mut instances = BTreeMap::new();
        instances.insert("relay".to_string(), inst(&[HostAuthority::ControlAdminApi]));
        instances.insert("signer".to_string(), inst(&[HostAuthority::TokenSigner]));
        // The union of these two is NOT ALL — but the purpose-marker check is orthogonal; we assert
        // ONLY on the AuthorityServeLinkNotSingleCrownJewel variant's presence/absence below.
        let mut links = BTreeMap::new();
        links.insert(
            "to-sign".to_string(),
            PrivsepLink {
                from: "relay".to_string(),
                to: "signer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::AuthorityServe,
            },
        );
        let cfg = PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
        };
        let authorityserve_fault = |cfg: &PrivsepConfig| {
            check_composition_closure(cfg).err().is_some_and(|e| {
                e.violations.iter().any(|v| {
                    matches!(
                        v,
                        CompositionViolation::AuthorityServeLinkNotSingleCrownJewel { .. }
                    )
                })
            })
        };
        assert!(
            !authorityserve_fault(&cfg),
            "a crown↔non-crown authority-serve link must not raise the purpose-marker fault"
        );

        // crown↔crown (bootstrap shape) — two crown endpoints → the fault fires.
        let mut cfg2 = cfg.clone();
        cfg2.instances.get_mut("relay").unwrap().capabilities = vec![HostAuthority::SecretsSealer];
        assert!(
            authorityserve_fault(&cfg2),
            "a crown↔crown authority-serve link must be refused (bootstrap shape, not WS-E)"
        );

        // non-crown↔non-crown — zero crown endpoints → the fault fires.
        let mut cfg3 = cfg.clone();
        cfg3.instances.get_mut("signer").unwrap().capabilities = vec![HostAuthority::BackendKv];
        assert!(
            authorityserve_fault(&cfg3),
            "a non-crown↔non-crown authority-serve link must be refused (no grammar server)"
        );

        // The SAME topology WITHOUT the marker (Unspecified) raises no purpose-marker fault.
        let mut cfg4 = cfg3.clone();
        cfg4.links.get_mut("to-sign").unwrap().purpose = LinkPurpose::Unspecified;
        assert!(
            !authorityserve_fault(&cfg4),
            "an unmarked link is never subject to the authority-serve purpose check"
        );
    }

    // ---- operator-selectable isolation substrate (Phase-3 foundation) ----

    #[test]
    fn instance_substrate_defaults_to_os_process_and_round_trips_through_ron() {
        let ron = r#"(
            instances: {
                "frontend": (
                    capabilities: ["listen.public-tls", "listen.http-parse", "exec.wasmtime"],
                    substrate: OsProcess,
                ),
                "edge-vm": ( capabilities: ["listen.mail"], substrate: Vm ),
                "core": ( capabilities: ["backend.kv"] ),
            },
        )"#;
        let cfg: PrivsepConfig = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(ron)
            .expect("parse privsep RON with substrate markers");
        assert_eq!(
            cfg.instances["frontend"].substrate,
            InstanceSubstrate::OsProcess
        );
        assert_eq!(cfg.instances["edge-vm"].substrate, InstanceSubstrate::Vm);
        // An omitted `substrate` defaults to OsProcess (back-compat: every Phase-1 cfg is unchanged).
        assert_eq!(
            cfg.instances["core"].substrate,
            InstanceSubstrate::OsProcess
        );
        // The foundation cut wires only OsProcess; the nesting substrates name their reuse backend.
        assert!(InstanceSubstrate::OsProcess.is_wired());
        assert!(!InstanceSubstrate::Container.is_wired());
        assert!(!InstanceSubstrate::Vm.is_wired());
        assert!(
            InstanceSubstrate::OsProcess
                .compute_plane_backend()
                .is_none()
        );
        assert!(
            InstanceSubstrate::Vm
                .compute_plane_backend()
                .is_some_and(|b| b.contains("firecracker"))
        );
    }

    // ---- per-tenant wasm-runtime TEMPLATE + lifecycle (Phase-4 WS-A) ----

    /// A valid Phase-4 composition whose union == ALL:
    /// - `tenant-wasm`: a per-tenant TEMPLATE holding ONLY `exec.wasmtime` (the per-tenant guest JIT);
    /// - `edge`: every listener + `exec.compute` + both control (no `exec.wasmtime` — it moved to the
    ///   template; no keys, no backends; `exec.compute` is the per-tenant SCHEDULER, holds no guest);
    /// - `data`: the four backends (B alone);
    /// - `signer`: the six crown jewels (A alone).
    fn phase4_template_composition() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "tenant-wasm".to_string(),
            template(&[HostAuthority::ExecWasmtime]),
        );
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
            per_tenant: PerTenantPolicy::default(),
        }
    }

    fn has_violation(cfg: &PrivsepConfig, pred: impl Fn(&CompositionViolation) -> bool) -> bool {
        check_composition_closure(cfg)
            .err()
            .is_some_and(|e| e.violations.iter().any(pred))
    }

    #[test]
    fn lifecycle_defaults_to_static_and_round_trips_with_a_template_through_ron() {
        let ron = r#"(
            instances: {
                "tenant-wasm": ( capabilities: ["exec.wasmtime"], lifecycle: PerTenantTemplate ),
                "edge": ( capabilities: ["listen.http-parse"] ),
            },
        )"#;
        let cfg: PrivsepConfig = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(ron)
            .expect("parse privsep RON with a lifecycle marker");
        assert_eq!(
            cfg.instances["tenant-wasm"].lifecycle,
            InstanceLifecycle::PerTenantTemplate
        );
        assert!(
            cfg.instances["tenant-wasm"]
                .lifecycle
                .is_per_tenant_template()
        );
        // An omitted `lifecycle` defaults to Static (back-compat: every pre-Phase-4 cfg is unchanged).
        assert_eq!(cfg.instances["edge"].lifecycle, InstanceLifecycle::Static);
        assert!(!cfg.instances["edge"].lifecycle.is_per_tenant_template());
        assert_eq!(InstanceLifecycle::Static.tag(), "static");
        assert_eq!(
            InstanceLifecycle::PerTenantTemplate.tag(),
            "per-tenant-template"
        );
        // serde round-trips value → JSON → value unchanged.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: PrivsepConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn valid_wasm_template_composition_passes_clean() {
        let report =
            check_composition_closure(&phase4_template_composition()).expect("valid composition");
        assert!(
            report.warnings.is_empty(),
            "the valid template composition must raise no flags, got {:?}",
            report.warnings
        );
    }

    #[test]
    fn lint_rejects_template_with_an_extra_capability() {
        let mut cfg = phase4_template_composition();
        // The template now holds a backend credential in addition to exec.wasmtime.
        cfg.instances
            .get_mut("tenant-wasm")
            .unwrap()
            .capabilities
            .push(HostAuthority::BackendKv);
        assert!(has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::WasmTemplateNotSoleExecWasmtime { instance, holds_exec_wasmtime, extra }
                if instance == "tenant-wasm" && *holds_exec_wasmtime && extra.contains(&HostAuthority::BackendKv)
        )));
    }

    #[test]
    fn lint_rejects_template_with_a_crown_jewel_key() {
        let mut cfg = phase4_template_composition();
        // A crown jewel on the template — doubly disqualifying (also trips crown-jewel exclusion).
        cfg.instances
            .get_mut("tenant-wasm")
            .unwrap()
            .capabilities
            .push(HostAuthority::SecretsSealer);
        assert!(has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::WasmTemplateNotSoleExecWasmtime { instance, extra, .. }
                if instance == "tenant-wasm" && extra.contains(&HostAuthority::SecretsSealer)
        )));
    }

    #[test]
    fn lint_rejects_template_missing_exec_wasmtime() {
        // A template that holds something OTHER than exec.wasmtime, and not exec.wasmtime at all.
        let mut cfg = phase4_template_composition();
        *cfg.instances.get_mut("tenant-wasm").unwrap() = template(&[HostAuthority::ExecCompute]);
        // Keep the union == ALL (so the template fault is the clean thing under test): swap the two
        // exec authorities between the template and `edge` — exec.wasmtime onto `edge`, exec.compute
        // onto the template. Dropping exec.compute from `edge` also keeps this focused on rule (a)
        // (otherwise `edge` would co-reside both exec authorities and trip rule (b) as well).
        let edge = &mut cfg.instances.get_mut("edge").unwrap().capabilities;
        edge.push(HostAuthority::ExecWasmtime);
        edge.retain(|a| *a != HostAuthority::ExecCompute);
        assert!(has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::WasmTemplateNotSoleExecWasmtime { instance, holds_exec_wasmtime, extra }
                if instance == "tenant-wasm" && !*holds_exec_wasmtime && extra.contains(&HostAuthority::ExecCompute)
        )));
    }

    #[test]
    fn a_valid_exec_wasmtime_template_passes_rule_a() {
        // A bare `{exec.wasmtime}` template raises NO template fault.
        let cfg = phase4_template_composition();
        assert!(!has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::WasmTemplateNotSoleExecWasmtime { .. }
        )));
    }

    #[test]
    fn lint_rejects_exec_compute_and_wasmtime_co_resident_when_a_template_exists() {
        let mut cfg = phase4_template_composition();
        // Put exec.wasmtime back on the exec.compute-holding `edge` while the template still exists.
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecWasmtime);
        assert!(has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::ExecComputeAndWasmtimeCoResident { instance } if instance == "edge"
        )));
    }

    #[test]
    fn exec_compute_wasmtime_co_residency_rule_is_gated_on_template_presence() {
        // `clean_composition`'s `edge` co-resides exec.compute + exec.wasmtime, but has NO template —
        // a pre-Phase-4 composition. The co-residency rule must NOT fire (it passes clean entirely).
        let cfg = clean_composition();
        assert!(
            !cfg.instances
                .values()
                .any(|i| i.lifecycle.is_per_tenant_template())
        );
        let report = check_composition_closure(&cfg).expect("pre-Phase-4 composition is unchanged");
        assert!(report.warnings.is_empty());
        // Explicitly: no co-residency violation can arise without a template.
        assert!(!has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::ExecComputeAndWasmtimeCoResident { .. }
        )));
    }

    #[test]
    fn lint_rejects_exec_wasmtime_on_a_static_instance_when_a_template_exists() {
        // MEDIUM-1: the canonical Phase-4 composition {template `tenant-wasm`={exec.wasmtime};
        // `edge`={listeners, exec.compute, control, acme}; `data`={backend.*}; `signer`={6 crown
        // jewels}} is authorized — exec.wasmtime lives ONLY on the per-tenant template.
        let mut cfg = phase4_template_composition();
        check_composition_closure(&cfg).expect("the canonical Phase-4 composition is authorized");

        // Now add exec.wasmtime to the STATIC `data` instance. Rule (a) does not apply (data is not a
        // template) and rule (b) does not fire (data holds no exec.compute), yet this stands up a
        // SHARED, cross-tenant wasm runtime alongside the per-tenant template — the MEDIUM-1 gap.
        // Pre-fix this was wrongly ACCEPTED (only an F8 warning); rule (c) must now REFUSE it.
        cfg.instances
            .get_mut("data")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecWasmtime);
        assert!(has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::ExecWasmtimeOutsidePerTenantTemplate { instance }
                if instance == "data"
        )));
    }

    #[test]
    fn exec_wasmtime_outside_template_rule_is_gated_on_template_presence() {
        // With NO per-tenant template, exec.wasmtime on a static instance is the shipped
        // monolith-equivalent runtime — UNCHANGED (pre-Phase-4 byte-compatible). `clean_composition`'s
        // `edge` holds exec.wasmtime and is static, with no template anywhere: it must pass clean and
        // raise NO ExecWasmtimeOutsidePerTenantTemplate violation.
        let cfg = clean_composition();
        assert!(
            !cfg.instances
                .values()
                .any(|i| i.lifecycle.is_per_tenant_template())
        );
        assert!(
            cfg.instances["edge"]
                .capabilities
                .contains(&HostAuthority::ExecWasmtime)
        );
        check_composition_closure(&cfg).expect("a no-template composition is unchanged");
        assert!(!has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::ExecWasmtimeOutsidePerTenantTemplate { .. }
        )));
    }

    // ---- F4 restart-class invariant (Phase-4 WS-A) ----

    #[test]
    fn pre_phase4_compositions_are_unchanged_and_default_to_static() {
        // Every instance of a composition that never mentions `lifecycle` is Static, and the clean
        // Phase-1/2/3 composition still passes exactly as before (no new refusal, no new flag).
        let cfg = clean_composition();
        for inst in cfg.instances.values() {
            assert_eq!(inst.lifecycle, InstanceLifecycle::Static);
        }
        check_composition_closure(&cfg).expect("the pre-Phase-4 clean composition is unchanged");
    }

    #[test]
    fn absent_privsep_monolith_is_byte_unchanged() {
        // The monolith is the ABSENT `[privsep]` section — carried as Option::None by the consumer,
        // never linted. Its representation here (a defaulted PrivsepConfig) has no instances and is
        // byte-stable through a serde round-trip, so adding `lifecycle` cannot perturb the monolith.
        let empty = PrivsepConfig::default();
        assert!(empty.instances.is_empty());
        let json = serde_json::to_string(&empty).unwrap();
        let back: PrivsepConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, empty);
    }

    #[test]
    fn template_authority_is_fixed_on_disk_and_scope_grants_nothing() {
        // The template's AUTHORITY is the on-disk fact `{exec.wasmtime}` — independent of any tenant.
        let t = template(&[HostAuthority::ExecWasmtime]);
        assert_eq!(t.capabilities, vec![HostAuthority::ExecWasmtime]);
        assert!(t.lifecycle.is_per_tenant_template());
        // Resolving DIFFERENT per-tenant scopes changes only the backend NAMESPACE, never the
        // authority set: the scope carries no HostAuthority and selects a `project/<id>/…` prefix.
        let a = TenantScope::resolve("acme").expect("valid scope");
        let b = TenantScope::resolve("globex").expect("valid scope");
        assert_eq!(a.resource_prefix(), "project/acme/");
        assert_eq!(b.resource_prefix(), "project/globex/");
        assert_ne!(a, b);
        // The template definition is identical regardless of which scope it is instantiated for.
        assert_eq!(t.capabilities, vec![HostAuthority::ExecWasmtime]);
    }

    // ---- fail-closed TenantScope (Phase-4 WS-A) ----

    #[test]
    fn tenant_scope_resolves_a_valid_project_slug() {
        let s = TenantScope::resolve("acme-prod").expect("a valid slug resolves");
        assert_eq!(s.project(), "acme-prod");
        assert_eq!(s.env_value(), "acme-prod");
        assert_eq!(s.resource_prefix(), "project/acme-prod/");
        // The reserved default project is itself a valid, scopable tenant.
        assert!(TenantScope::resolve(crate::project::DEFAULT_PROJECT).is_ok());
    }

    #[test]
    fn tenant_scope_is_fail_closed_on_empty_unresolved() {
        assert_eq!(TenantScope::resolve(""), Err(TenantScopeError::Unresolved));
    }

    #[test]
    fn tenant_scope_is_fail_closed_on_a_wildcard() {
        assert!(matches!(
            TenantScope::resolve("*"),
            Err(TenantScopeError::Wildcard { .. })
        ));
        assert!(matches!(
            TenantScope::resolve("acme/*"),
            Err(TenantScopeError::Wildcard { .. })
        ));
        assert!(matches!(
            TenantScope::resolve("ac*me"),
            Err(TenantScopeError::Wildcard { .. })
        ));
    }

    #[test]
    fn tenant_scope_is_fail_closed_on_a_malformed_slug() {
        for bad in [
            "a/b",          // a path segment separator
            "..",           // traversal
            "../x",         // traversal
            "-acme",        // must start alphanumeric
            "acme-",        // must end alphanumeric
            "acme prod",    // space
            "project/acme", // the keyspace prefix is not itself a scope
            "café",         // non-ASCII homoglyph
        ] {
            assert!(
                matches!(
                    TenantScope::resolve(bad),
                    Err(TenantScopeError::Malformed { .. })
                ),
                "{bad:?} must refuse fail-closed as malformed"
            );
        }
        // An over-length slug (> MAX_RESOURCE_NAME_LEN) is malformed.
        let too_long = "a".repeat(crate::project::MAX_RESOURCE_NAME_LEN + 1);
        assert!(matches!(
            TenantScope::resolve(&too_long),
            Err(TenantScopeError::Malformed { .. })
        ));
    }

    #[test]
    fn tenant_scope_from_env_value_re_validates_fail_closed() {
        // A good value round-trips through the env representation.
        let s = TenantScope::resolve("acme").unwrap();
        assert_eq!(TenantScope::from_env_value(s.env_value()), Ok(s));
        // A tampered/empty/wildcard env value refuses exactly as a bad resolution would — it is NOT
        // trusted because it arrived in the environment.
        assert_eq!(
            TenantScope::from_env_value(""),
            Err(TenantScopeError::Unresolved)
        );
        assert!(matches!(
            TenantScope::from_env_value("*"),
            Err(TenantScopeError::Wildcard { .. })
        ));
        assert!(matches!(
            TenantScope::from_env_value("a/b"),
            Err(TenantScopeError::Malformed { .. })
        ));
        // The env var name is the non-secret BOATRAMP_* spelling.
        assert_eq!(PRIVSEP_TENANT_SCOPE_ENV, "BOATRAMP_PRIVSEP_TENANT_SCOPE");
    }

    // ---- per-tenant scale-to-zero policy (Phase-4 WS-C) ----

    #[test]
    fn per_tenant_policy_defaults_are_the_owner_ratified_values() {
        let p = PerTenantPolicy::default();
        assert_eq!(p.idle_eviction_secs, 300);
        assert_eq!(p.max_instances, 64);
        assert_eq!(p.idle_eviction(), Some(std::time::Duration::from_secs(300)));
        // A config that omits `[privsep].per_tenant` gets the defaults (byte-compat).
        assert_eq!(
            PrivsepConfig::default().per_tenant,
            PerTenantPolicy::default()
        );
    }

    #[test]
    fn per_tenant_policy_validate_is_fail_closed_on_zero_max() {
        assert_eq!(PerTenantPolicy::default().validate(), Ok(()));
        let bad = PerTenantPolicy {
            idle_eviction_secs: 300,
            max_instances: 0,
        };
        assert_eq!(
            bad.validate(),
            Err(PerTenantPolicyError::ZeroMaxInstances),
            "a 0 concurrency cap is a fail-closed misconfiguration"
        );
        // idle_eviction_secs == 0 is valid (disables idle eviction).
        let no_evict = PerTenantPolicy {
            idle_eviction_secs: 0,
            max_instances: 8,
        };
        assert_eq!(no_evict.validate(), Ok(()));
        assert_eq!(no_evict.idle_eviction(), None);
    }

    #[test]
    fn per_tenant_policy_round_trips_through_ron_and_defaults_when_omitted() {
        // Explicit policy round-trips.
        let ron = r#"(
            instances: { "tenant-wasm": ( capabilities: ["exec.wasmtime"], lifecycle: PerTenantTemplate ) },
            per_tenant: ( idle_eviction_secs: 120, max_instances: 8 ),
        )"#;
        let cfg: PrivsepConfig = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(ron)
            .expect("parse privsep RON with a per_tenant policy");
        assert_eq!(cfg.per_tenant.idle_eviction_secs, 120);
        assert_eq!(cfg.per_tenant.max_instances, 8);
        // Omitted ⇒ the defaults (byte-compat with pre-WS-C configs).
        let ron2 = r#"( instances: { "edge": ( capabilities: ["listen.http-parse"] ) } )"#;
        let cfg2: PrivsepConfig = ron::Options::default()
            .with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
            .from_str(ron2)
            .expect("parse privsep RON without a per_tenant policy");
        assert_eq!(cfg2.per_tenant, PerTenantPolicy::default());
        // serde value → JSON → value is stable.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: PrivsepConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
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
