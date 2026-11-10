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

    /// Whether this authority is a **public, untrusted-byte listener** — any group-C listener that
    /// parses attacker-controlled bytes (`listen.public-tls`, `listen.http-parse`, `listen.mail`,
    /// `listen.overlay`, `listen.s3ingress`, `listen.inbound-tcp`, `listen.gateway`). This is the
    /// anchor of the Finding-2 hard refusal: an instance holding ANY such listener must hold NO
    /// [`is_public_listener_forbidden_partner`](Self::is_public_listener_forbidden_partner) authority.
    ///
    /// **Widened in WS-D re-review (owner decision 1 — widen the lint).** The finding's named target
    /// was `listen.http-parse` (the most-exposed, fuzzed parser), but every other group-C listener is
    /// the SAME untrusted-byte character, and `listen.public-tls` is in fact SHARPER — it holds the
    /// live private cert key AND parses attacker TLS bytes. A composition that put `exec.compute` +
    /// `backend.kv` on `listen.public-tls`/`mail`/`overlay`/… was lint-clean under the narrow anchor;
    /// it no longer is. Equivalent to [`is_listener`](Self::is_listener) — the anchor IS group C.
    pub const fn is_public_listener(self) -> bool {
        self.is_listener()
    }

    /// Whether this authority is one a **public listener must NOT co-reside** (WS-D Finding-2, widened
    /// in re-review): any authority whose blast radius, reached through a parser RCE on the
    /// untrusted-byte surface, escapes the parser's own address space —
    /// - `exec.compute` (group D): fork/execve of arbitrary workloads — a parser RCE forks the pinned
    ///   binary;
    /// - `control.admin-api` (group E): drives every control-plane mutation (publish, token
    ///   mint-request, config set, tenancy apply) the caller is authorized for;
    /// - **every** `backend.*` (group B): `backend.kv` (rw the control-plane source of truth: site
    ///   config, deploy manifests, tokens-at-rest, sealed-cred ciphertext), `backend.sql` (rw all
    ///   pooled tenant + control-plane SQL), `backend.blob` (rwd all blob data), `backend.messaging`
    ///   (inject/drain every topic). The most-exposed, fuzzed parse surface must hold the LEAST
    ///   authority, so it holds NO data-plane credential and forwards inward over a feature-link.
    ///
    /// **The set is all `backend.*` ∪ `{exec.compute, control.admin-api}`** (re-review decision:
    /// prefer all `backend.*` — no shipped composition co-resides a listener with a backend; both
    /// reference topologies isolate the backends onto a non-public instance, so this over-restricts
    /// nothing). NB `exec.wasmtime` is deliberately NOT here — `listen.http-parse` + `exec.wasmtime`
    /// is the legitimate Phase-3 inverted frontend (the per-tenant child runs the JIT for ONE tenant,
    /// contained by Phase 4); its co-residency is governed by the Phase-4 template rules, not here.
    /// `acme.dns-control` is also NOT here (the re-review named only `control.admin-api`; cert
    /// issuance is not a control-plane mutation, and it legitimately rides a listener frontend).
    pub const fn is_public_listener_forbidden_partner(self) -> bool {
        self.is_backend() || matches!(self, Self::ExecCompute | Self::ControlAdminApi)
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
/// **Phase-3 scope:** `OsProcess` (Phase-1) and `Container` (Phase-3 simple model — the SAME
/// fork+exec, the child unsharing mount/ipc/uts/cgroup namespaces in its `pre_exec`, no
/// `pivot_root`, no new net/pid/user namespace; the per-capability Landlock profile stays the FS wall) are
/// WIRED spawn backends. `Vm` parses + lints as valid composition vocabulary but the supervisor
/// REFUSES to spawn it fail-closed (naming its reuse backend) rather than silently downgrading — a VM
/// has its own kernel, so the `local` socketpair cannot cross and the link transport needs a vsock
/// re-plumb. See [`InstanceSubstrate::is_wired`] and `crates/boatramp/DESIGN-privsep-phase3-container.md`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum InstanceSubstrate {
    /// A privilege-dropped OS process over the `local` socketpair (the Phase-1 spawn backend). Default.
    #[default]
    OsProcess,
    /// A namespace/cgroup-confined process: the SAME fork+exec, the child unsharing
    /// mount/ipc/uts/cgroup namespaces in its `pre_exec` (Phase-3 simple model, WIRED; pid/net/user
    /// namespaces deliberately shared — see the design note).
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

    /// Whether this substrate's spawn backend is WIRED. `OsProcess` is the Phase-1 fork+exec backend;
    /// `Container` is the Phase-3 namespace/cgroup-confined backend (the root unshares
    /// `CLONE_NEWNS|NEWIPC|NEWUTS|NEWCGROUP` in the child's `pre_exec` on the SIMPLE model — no
    /// `pivot_root`, no new net/pid/user namespace, the per-capability Landlock profile stays the FS
    /// wall; see `crates/boatramp/DESIGN-privsep-phase3-container.md`). `Vm` stays the reported follow-on
    /// (its own kernel ⇒ the `local` socketpair cannot cross, so it needs a vsock re-plumb), refused
    /// fail-closed by the supervisor.
    pub const fn is_wired(self) -> bool {
        matches!(self, Self::OsProcess | Self::Container)
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
/// **Defaults (owner-ratified):** `idle_eviction_secs = 300`, `max_instances = 64`. The cold-start
/// admission knobs (`cold_start_*`) default to a generous-but-bounded budget that is a no-op for a
/// healthy node and only dampens crash-loop / cross-tenant-spray fork churn. **Fail-closed:** a
/// misconfigured policy (`max_instances == 0`) is REFUSED at the root's authorization gate before
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
    /// Cold-start crash-loop guard (milliseconds): a per-tenant child that dies within this window
    /// of its fork is treated as a FAILED cold start and its tenant is backed off, so a tenant whose
    /// child keeps crashing is not re-forked on every request. Default `1000`. `0` DISABLES
    /// crash-loop backoff (a fork FAILURE still backs off). Fail-closed: a backed-off tenant is
    /// refused (`NotReady`), never served from another tenant's instance.
    pub cold_start_min_healthy_ms: u64,
    /// The base backoff delay (milliseconds) after the first failed / crash-looping cold start; it
    /// doubles per consecutive failure up to [`cold_start_backoff_max_ms`](Self::cold_start_backoff_max_ms).
    /// Default `500`.
    pub cold_start_backoff_base_ms: u64,
    /// The ceiling (milliseconds) on the exponential cold-start backoff. Default `30000` (30s).
    pub cold_start_backoff_max_ms: u64,
    /// Node-wide cold-start admission rate (forks PER SECOND): the refill rate of the cold-start
    /// token bucket. It bounds how fast NEW per-tenant instances are forked so a request spray across
    /// more tenants than [`max_instances`](Self::max_instances) cannot force continuous evict+fork
    /// churn that evicts warm instances for free. Default `50`. `0` DISABLES cold-start rate limiting.
    pub cold_start_rate_per_sec: u32,
    /// The cold-start token-bucket burst (capacity): how many cold starts may happen back-to-back
    /// before the per-second rate applies (e.g. a cold node waking many tenants at once). Default
    /// `100`. Clamped to at least `1` so a node can always make progress.
    pub cold_start_burst: u32,
}

impl Default for PerTenantPolicy {
    fn default() -> Self {
        Self {
            idle_eviction_secs: 300,
            max_instances: 64,
            cold_start_min_healthy_ms: 1000,
            cold_start_backoff_base_ms: 500,
            cold_start_backoff_max_ms: 30000,
            cold_start_rate_per_sec: 50,
            cold_start_burst: 100,
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

    /// The crash-loop min-healthy window: a child that dies within this of its fork is treated as a
    /// failed cold start (and its tenant backed off). `0` ⇒ zero window ⇒ crash-loop backoff is
    /// disabled (a child is never "too short-lived").
    #[must_use]
    pub fn cold_start_min_healthy(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.cold_start_min_healthy_ms)
    }

    /// The exponential, capped cold-start backoff delay after `failures` consecutive failed /
    /// crash-looping cold starts (`failures >= 1`): `base * 2^(failures - 1)`, clamped to the
    /// configured max. Overflow-safe (the doubling shift is capped).
    #[must_use]
    pub fn cold_start_backoff(&self, failures: u32) -> std::time::Duration {
        let base = self.cold_start_backoff_base_ms.max(1);
        let max = self.cold_start_backoff_max_ms.max(base);
        // Cap the shift so `1 << shift` can never overflow; by ~20 doublings we are already clamped.
        let shift = failures.saturating_sub(1).min(20);
        let delay = base.saturating_mul(1u64 << shift).min(max);
        std::time::Duration::from_millis(delay)
    }

    /// The cold-start token-bucket capacity (burst), always `>= 1` so a node can always cold-start.
    #[must_use]
    pub fn cold_start_burst_capacity(&self) -> f64 {
        f64::from(self.cold_start_burst.max(1))
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
    /// A **public, untrusted-byte listener** (any group-C `listen.*`) co-resides, on one instance, an
    /// authority a parser RCE must not reach — the compute-plane spawn (`exec.compute`), the
    /// control-plane mutation surface (`control.admin-api`), and/or any backend credential
    /// (`backend.*`) — the WS-D Finding-2 refusal (owner decision 2026-11-03, Phase-4 WS-C Security
    /// review; anchor + forbidden set WIDENED in the WS-D re-review, decision 1). Least privilege: the
    /// most-exposed, fuzzed parse surface must hold the LEAST authority, so a parser RCE cannot fork
    /// the pinned binary (`exec.compute`), drive control-plane mutations (`control.admin-api`), or
    /// read/write the data plane (`backend.kv`: site config, deploy manifests, tokens-at-rest,
    /// sealed-cred ciphertext; `backend.sql`: all pooled SQL; `backend.blob`: all blob data;
    /// `backend.messaging`: every topic). A separate non-public instance holds spawn/control/backend,
    /// reached over a feature-link (`DESIGN-wsd.md`). Fail-closed, in the root before any spawn: no
    /// on-disk composition can put them in one address space.
    PublicListenerWithSpawnControlOrBackend {
        /// The offending instance label.
        instance: String,
        /// The public listener(s) it holds — the anchor(s) that must hold the least authority.
        listeners: Vec<HostAuthority>,
        /// The forbidden authorities it co-resides with the listener(s) (a non-empty subset of
        /// `backend.* ∪ {exec.compute, control.admin-api}`) — the ones to move onto a separate
        /// non-public instance reached over a feature-link.
        forbidden: Vec<HostAuthority>,
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
    /// A per-tenant TEMPLATE instance ([`InstanceLifecycle::PerTenantTemplate`]) also selects the
    /// [`InstanceSubstrate::Container`] substrate (Phase-3 Security re-review, Finding 1). The
    /// container substrate's `unshare` runs in the spawned child's `pre_exec`; a boot instance forks
    /// from the UNCONFINED root so that is safe, but a per-tenant instance is cold-start-forked by the
    /// per-tenant ROUTER, which has ALREADY installed its own seccomp filter — and that filter
    /// hard-`SIGSYS`-KILLS `unshare` (only `execve`/`fork` are spared for an `exec.compute` holder).
    /// `std::process::Command::spawn()` returns `Ok` for a `pre_exec` child killed by a signal (the
    /// CLOEXEC error pipe merely EOFs), so the router would register a DEAD instance as live —
    /// defeating `FailNodeClosed` and opening a tenant-wide DoS + corrupt registry. So the combination
    /// is REFUSED fail-closed in the root, at config load, BEFORE any spawn, until the deferred
    /// pid-ns-init container-worker model (which cold-starts differently) lands. `substrate: container`
    /// on a STATIC (boot-forked) instance is unaffected.
    PerTenantTemplateContainerUnsupported {
        /// The offending per-tenant template instance label.
        instance: String,
    },
    /// A **key-material-bearing** link — the `secrets.sealer` ↔ `token.signer` unseal unlock link (the
    /// edge `boatramp::privsep::compute_unseal_allowlists` wires an unseal allowlist onto), or a
    /// [`LinkPurpose::AuthorityServe`] link whose SINGLE crown-jewel endpoint holds `secrets.sealer` —
    /// connects two DIFFERENT instances where AT LEAST ONE is [`InstanceSubstrate::Vm`]. A VM guest has
    /// its OWN kernel, so the `local` fd-passed `socketpair(2)` (the shape the root creates but never
    /// reads) cannot cross the hypervisor boundary; the link must become a vsock byte-relay, and the
    /// natural relay — the one the root runs because it owns the topology — copies the link's bytes
    /// THROUGH the secret-blind root. The KEK-unsealed PLAINTEXT key material would then transit the
    /// root's address space, breaking the "root holds no secret / no key material transits the root"
    /// invariant. Fail-closed ([`check_vm_secret_blindness_closure`], design
    /// `DESIGN-privsep-phase3-vm-derisk.md` §2.3 / S2).
    ///
    /// *Remedy named in the error:* CO-LOCATE `secrets.sealer` and `token.signer` on ONE instance (the
    /// unlock resolves in-process / over an intra-guest socketpair the root never relays — design P1),
    /// keep BOTH endpoints off the VM substrate, or (a later-cut option, not wired in the first cut)
    /// wire the sealer itself as the host-side vsock endpoint so the root wires-but-does-not-relay the
    /// key link (design P2).
    VmKeyMaterialLinkRelayedThroughRoot {
        /// The offending link name.
        link: String,
        /// The endpoint holding `secrets.sealer` (the key-material SOURCE).
        sealer_instance: String,
        /// The other endpoint — the `token.signer` / caller that would RECEIVE the unsealed key
        /// material over the root-relayed link.
        signer_instance: String,
        /// Which endpoint(s) are [`InstanceSubstrate::Vm`] — the boundary the link is relayed across.
        vm_endpoints: Vec<String>,
    },
    /// A [`InstanceSubstrate::Vm`] instance holds a group-A crown-jewel KEY authority but does NOT
    /// co-reside the `secrets.sealer` that would unlock it, so its key unlock could only arrive over a
    /// cross-boundary link the secret-blind root relays — the approved first-cut
    /// "key-free-OR-co-located" VM scope violated directly. Fail-closed, the belt-and-suspenders
    /// companion to [`CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot`]
    /// ([`check_vm_secret_blindness_closure`], design §2.3): a VM instance must either hold NO group-A
    /// key authority (a key-free static parser frontend / compute instance — design P3), or co-reside
    /// the `secrets.sealer` that unlocks it (design P1 — the key conversation never leaves the guest).
    VmKeyHolderNotSelfSufficient {
        /// The offending VM instance label (holds ≥1 group-A crown jewel but not `secrets.sealer`).
        instance: String,
    },
    /// A [`InstanceSubstrate::Vm`] instance falls OUTSIDE the approved first-cut VM scope
    /// ("no-backends-in-VM / static-parser-frontends-or-co-located-sealer-only" — design
    /// `DESIGN-privsep-phase3-vm-derisk.md` §2.3 / S2 companion lint). The approved VM forms are EXACTLY
    /// two:
    /// - **P3 — a key-free static parser FRONTEND:** it holds NO group-A key authority and EVERY
    ///   capability it holds is an untrusted-byte `listen.*` parser surface (its sealer links, if any,
    ///   are listener-peer links a serving splice rides — excluded from serve-designation, so no key
    ///   material crosses to it); or
    /// - **P1 — a co-located sealer BUNDLE:** it holds `secrets.sealer` (so it unlocks its own keys
    ///   in-guest, never over a root-relayed link) and holds ONLY group-A crown-jewel key authorities
    ///   (the sealer + signer + any other key, nothing else).
    ///
    /// Anything else — a key-free **backend/exec/control** instance in a VM (the gap the S2 tiers alone
    /// did not close: they would have ALLOWED it), or a sealer bundle polluted with a non-key authority
    /// — is REFUSED fail-closed. The least-privilege point is that the strongest, highest-overhead wall
    /// (a VM) exists ONLY for the most-exposed parser frontend or the most-valuable key bundle; a data-
    /// plane / spawn / control instance belongs on a lighter substrate reached over a feature-link, not
    /// behind a hypervisor boundary the secret-blind root must relay. (The sibling
    /// [`CompositionViolation::VmKeyHolderNotSelfSufficient`] owns the DISTINCT "a VM holds a crown jewel
    /// but not its sealer" shape, so this variant never double-reports that case.) Run at `plan_root`
    /// before any spawn ([`check_vm_secret_blindness_closure`] Tier 3).
    VmInstanceOutsideApprovedScope {
        /// The offending VM instance label.
        instance: String,
        /// Whether it holds `secrets.sealer` — `true` ⇒ it is a sealer bundle polluted with a
        /// non-key authority (the `disallowed` set); `false` ⇒ it is a key-free instance that is not
        /// listener-only (the `disallowed` set is the non-listener authorities to move off the VM).
        holds_sealer: bool,
        /// The held authorities that place it outside scope: for a sealer bundle, every non-group-A
        /// authority; for a key-free instance, every non-`listen.*` authority (the backend/exec/control
        /// credentials a VM may not hold). Non-empty whenever this fires.
        disallowed: Vec<HostAuthority>,
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
            Self::PublicListenerWithSpawnControlOrBackend {
                instance,
                listeners,
                forbidden,
            } => write!(
                f,
                "instance {instance:?} co-resides public untrusted-byte listener(s) [{}] with \
                 privileged authorities [{}] — a public listener must hold NEITHER spawn \
                 (`exec.compute`) NOR the control-plane mutation surface (`control.admin-api`) NOR \
                 any backend credential (`backend.*`), so a parser RCE cannot fork the pinned binary, \
                 drive control-plane mutations, or read/write the data plane; move spawn/control/\
                 backend onto a separate non-public instance reached over a feature-link (WS-D \
                 Finding-2)",
                tags(listeners),
                tags(forbidden)
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
            Self::PerTenantTemplateContainerUnsupported { instance } => write!(
                f,
                "per-tenant template instance {instance:?} selects `substrate: container`, which is \
                 not supported for a per-tenant template in this cut — the container `unshare` runs \
                 in the cold-start child's pre_exec UNDER the per-tenant router's already-installed \
                 seccomp (which SIGSYS-kills `unshare`), and a pre_exec signal-kill is invisible to \
                 `spawn()`, so the router would register a dead instance as live (tenant-wide DoS, \
                 defeating FailNodeClosed). Use `substrate: os-process` for the template, or keep \
                 `container` only on static (boot-forked) instances, until the deferred pid-ns-init \
                 container-worker model lands"
            ),
            Self::VmKeyMaterialLinkRelayedThroughRoot {
                link,
                sealer_instance,
                signer_instance,
                vm_endpoints,
            } => write!(
                f,
                "link {link:?} carries KEK-unsealed key material (secrets.sealer {sealer_instance:?} \
                 ↔ token.signer {signer_instance:?}) across a VM boundary (vm endpoint(s) [{}]) — a VM \
                 guest has its own kernel, so this link becomes a vsock byte-relay through the \
                 SECRET-BLIND root, and the plaintext key material would transit the root's memory, \
                 breaking the root-holds-no-secret invariant; co-locate `secrets.sealer` and \
                 `token.signer` on ONE instance (intra-guest socketpair, never relayed), keep both off \
                 the VM substrate, or (later cut) wire the sealer as the host-side vsock endpoint",
                vm_endpoints.join(", ")
            ),
            Self::VmKeyHolderNotSelfSufficient { instance } => write!(
                f,
                "VM instance {instance:?} holds a group-A crown-jewel key authority but does not \
                 co-reside the `secrets.sealer` that unlocks it — its key unlock could only arrive \
                 over a cross-boundary link the secret-blind root relays; a VM instance must either \
                 hold NO group-A key authority (a key-free parser frontend / compute instance) or \
                 co-reside its `secrets.sealer` (the key conversation then never leaves the guest)"
            ),
            Self::VmInstanceOutsideApprovedScope {
                instance,
                holds_sealer,
                disallowed,
            } => {
                if *holds_sealer {
                    write!(
                        f,
                        "VM instance {instance:?} is a `secrets.sealer` bundle but also holds \
                         non-key authorities [{}] — a co-located sealer bundle in a VM (P1) may hold \
                         ONLY group-A crown-jewel key authorities (the sealer + signer); move the \
                         backend/exec/control/listener authorities onto a separate non-VM instance \
                         reached over a feature-link",
                        tags(disallowed)
                    )
                } else {
                    write!(
                        f,
                        "VM instance {instance:?} holds [{}] — a key-free VM instance must be a \
                         listener-only parser FRONTEND (P3): the strongest hypervisor wall is for the \
                         most-exposed parser surface or a co-located sealer bundle ONLY, never a \
                         backend/exec/control instance; move these authorities onto a separate non-VM \
                         instance reached over a feature-link, or co-locate `secrets.sealer` if this \
                         is meant to be a key bundle",
                        tags(disallowed)
                    )
                }
            }
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
/// - **(WS-D Finding-2, widened in re-review)** a public untrusted-byte listener (ANY group-C
///   `listen.*`) co-resident with a forbidden partner — `exec.compute` (spawn), `control.admin-api`
///   (control-plane mutation), or ANY `backend.*` credential
///   ([`CompositionViolation::PublicListenerWithSpawnControlOrBackend`]) — the most-exposed, fuzzed
///   parse surface must hold the least authority, so a parser RCE can neither fork the pinned binary,
///   drive control-plane mutations, nor rw the data plane; spawn/control/backend live on a separate
///   non-public instance reached over a link (`exec.wasmtime` is NOT forbidden — the inverted frontend);
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

            // Phase-3 Security re-review, Finding 1: a per-tenant template must NOT use the container
            // substrate. Its cold-start `unshare` would run under the router's seccomp (which
            // SIGSYS-kills `unshare`), and a pre_exec signal-kill is invisible to `spawn()`, so the
            // router would register a dead instance as live (tenant-wide DoS, defeating
            // FailNodeClosed). Refused fail-closed, in the root, before any spawn. (A STATIC instance
            // forks from the unconfined root, so `substrate: container` there is unaffected.)
            if inst.substrate == InstanceSubstrate::Container {
                violations.push(
                    CompositionViolation::PerTenantTemplateContainerUnsupported {
                        instance: name.clone(),
                    },
                );
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

        // WS-D Finding-2 (REFUSE), WIDENED in re-review: a public untrusted-byte listener (ANY group-C
        // `listen.*`) must hold NO forbidden partner — `exec.compute` (spawn), `control.admin-api`
        // (control-plane mutation), or ANY `backend.*` credential. A parser RCE co-resident with any
        // of these escapes the parser's own address space (fork the pinned binary / drive control-plane
        // mutations / rw the data plane) — exactly the blast radius the split removes. `exec.wasmtime`
        // is NOT forbidden (`listen.http-parse` + `exec.wasmtime` is the legitimate Phase-3 inverted
        // frontend; Phase-4 template rules govern it). Collected (not short-circuited) so an operator
        // sees it alongside the others.
        let listeners: Vec<HostAuthority> = held
            .iter()
            .copied()
            .filter(|a| a.is_public_listener())
            .collect();
        if !listeners.is_empty() {
            let forbidden: Vec<HostAuthority> = held
                .iter()
                .copied()
                .filter(|a| a.is_public_listener_forbidden_partner())
                .collect();
            if !forbidden.is_empty() {
                violations.push(
                    CompositionViolation::PublicListenerWithSpawnControlOrBackend {
                        instance: name.clone(),
                        listeners,
                        forbidden,
                    },
                );
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

/// One `secrets.sealer` ↔ `token.signer` **unseal-unlock edge** in a [`PrivsepConfig`]: a feature-link
/// between two DIFFERENT instances, one end holding [`HostAuthority::SecretsSealer`] and the other
/// [`HostAuthority::TokenSigner`] — the link the sealer serves the signer's key unlock over. The
/// [`sealer_instance`](Self::sealer_instance) field names the end that HOLDS the KEK (the key-material
/// source); [`signer_instance`](Self::signer_instance) names the receiving `token.signer` end.
///
/// This is the SINGLE source of truth for "the sealer→signer key link". Both
/// `boatramp::privsep::compute_unseal_allowlists` (the root's per-link unseal-allowlist wiring) and the
/// S2 VM secret-blindness lint ([`check_vm_secret_blindness_closure`] clause 1) DERIVE their edge set
/// from [`PrivsepConfig::sealer_signer_unseal_edges`] — so a future widening of the unseal model is
/// picked up by BOTH automatically and the two can never drift (the lint cannot silently under-refuse a
/// key link the root would wire an unseal allowlist onto). The topological edge ALONE; the node-global
/// "`[serve.signer]` is the sealed variant" (`sealed_signer`) gate — which this wasm-clean types layer
/// cannot see — is applied by each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealerSignerUnsealEdge<'a> {
    /// The link name (a key of [`PrivsepConfig::links`]).
    pub link: &'a str,
    /// The endpoint holding [`HostAuthority::SecretsSealer`] — the KEK-bearing key-material source.
    pub sealer_instance: &'a str,
    /// The other endpoint holding [`HostAuthority::TokenSigner`] — the receiver of the unsealed key.
    pub signer_instance: &'a str,
}

impl PrivsepConfig {
    /// Whether the instance labelled `label` MATERIALIZES `authority` (the shared "does this instance
    /// hold X" predicate the closure checks and the shared edge enumeration below all key off).
    fn instance_holds(&self, label: &str, authority: HostAuthority) -> bool {
        self.instances
            .get(label)
            .is_some_and(|i| i.capabilities.contains(&authority))
    }

    /// Enumerate every `secrets.sealer` ↔ `token.signer` [`SealerSignerUnsealEdge`] in this composition
    /// — the SINGLE shared edge set both `boatramp::privsep::compute_unseal_allowlists` and the S2 VM
    /// secret-blindness lint ([`check_vm_secret_blindness_closure`] clause 1) derive from, so the two
    /// cannot drift from the unseal model (obligation (a)). A self-link (`from == to`) is excluded (it
    /// resolves in-process and wires no cross-instance allowlist); the enumeration mirrors
    /// `compute_unseal_allowlists`'s two INDEPENDENT direction checks exactly, so a (degenerate) link
    /// whose BOTH ends hold sealer+signer yields one edge per matching direction. The node-global
    /// `sealed_signer` gate is NOT applied here (a caller applies it): this is topology alone, pure and
    /// host-testable.
    pub fn sealer_signer_unseal_edges(&self) -> Vec<SealerSignerUnsealEdge<'_>> {
        let mut edges = Vec::new();
        for (link_name, link) in &self.links {
            if link.from == link.to {
                continue;
            }
            if self.instance_holds(&link.from, HostAuthority::SecretsSealer)
                && self.instance_holds(&link.to, HostAuthority::TokenSigner)
            {
                edges.push(SealerSignerUnsealEdge {
                    link: link_name.as_str(),
                    sealer_instance: link.from.as_str(),
                    signer_instance: link.to.as_str(),
                });
            }
            if self.instance_holds(&link.to, HostAuthority::SecretsSealer)
                && self.instance_holds(&link.from, HostAuthority::TokenSigner)
            {
                edges.push(SealerSignerUnsealEdge {
                    link: link_name.as_str(),
                    sealer_instance: link.to.as_str(),
                    signer_instance: link.from.as_str(),
                });
            }
        }
        edges
    }
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

/// The **VM secret-blindness composition-closure rule** (design `DESIGN-privsep-phase3-vm-derisk.md`
/// §2.3 / S2): a fail-closed, STRUCTURAL guard that preserves the secret-blind-root invariant across
/// the [`InstanceSubstrate::Vm`] boundary. Run IN THE ROOT, before any spawn, alongside
/// [`check_composition_closure`] and [`check_sealed_signer_closure`] — the root surfaces either refusal
/// identically.
///
/// A VM guest has its OWN kernel, so the `local` fd-passed `socketpair(2)` the root creates but never
/// reads cannot cross the hypervisor boundary: any link with a VM endpoint must become a vsock
/// byte-relay, and the natural relay — the one the root runs because it owns the topology — copies the
/// link's bytes THROUGH the secret-blind root. A **key-material-bearing** link relayed that way would
/// carry KEK-unsealed PLAINTEXT key material through the root's address space, breaking the "root holds
/// no secret" invariant. This lint REFUSES exactly that, plus (belt-and-suspenders) a VM key holder
/// that is not self-sufficient for its own unlock, plus (the companion scope lint) any VM instance
/// outside the approved first-cut scope:
///
/// - **Tier 1** [`CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot`] — a key-material-bearing
///   link connects two DIFFERENT instances where at least one is [`InstanceSubstrate::Vm`].
///   Key-material-bearing is EITHER: (clause 1) a `secrets.sealer` ↔ `token.signer` unseal-unlock edge
///   — the edge set DERIVED from the shared [`PrivsepConfig::sealer_signer_unseal_edges`] predicate
///   `boatramp::privsep::compute_unseal_allowlists` also derives from, so the two cannot drift
///   (obligation (a)) — gated on `sealed_signer`; OR (clause 2) a SERVE-DESIGNATED link whose sole
///   crown-jewel endpoint holds `secrets.sealer` — GENERALIZED (obligation (c)) to the full
///   `boatramp::privsep::compute_authority_serve_links` designation shape (not a relay, exactly one
///   crown-jewel endpoint holding the sealer, and either `AuthorityServe`-marked OR `Unspecified` with
///   a non-listener peer), so an Unspecified-purpose sealer→VM serve link is caught too.
/// - **Tier 2** [`CompositionViolation::VmKeyHolderNotSelfSufficient`] — a [`InstanceSubstrate::Vm`]
///   instance holds a group-A crown jewel but does not co-reside the `secrets.sealer` that unlocks it.
/// - **Tier 3** [`CompositionViolation::VmInstanceOutsideApprovedScope`] — the companion scope lint
///   (obligation (b)): a VM instance must be EITHER a key-free listener-only parser frontend (P3) OR a
///   co-located sealer bundle holding only group-A keys (P1); a key-free backend/exec/control instance
///   in a VM (which the tiers above alone would ALLOW) is refused fail-closed. The
///   crown-jewel-without-sealer shape is left to Tier 2, so each refuse maps to exactly one variant.
///
/// Two capabilities on the SAME instance share one guest (an intra-guest socketpair the root never
/// relays — design P1), so a co-located `secrets.sealer`+`token.signer` VM is ACCEPTED; a key-free VM
/// parser frontend (design P3) is ACCEPTED. It is a PURE, AST/topology-level predicate over the
/// resolved [`PrivsepConfig`] — never a parse of link traffic or a text marker — reusing only existing
/// predicates ([`HostAuthority::is_crown_jewel`], [`HostAuthority::is_listener`],
/// [`InstanceSubstrate::Vm`], and the shared [`PrivsepConfig::sealer_signer_unseal_edges`] /
/// serve-designation shape the root's `compute_*` helpers also use).
///
/// `sealed_signer` is the same node-global "`[serve.signer]` is the sealed variant" fact
/// [`check_sealed_signer_closure`] takes (the caller derives it from the resolved `ServerConfig`, since
/// this wasm-clean types layer does not see `AuthSignerConfig`). It gates ONLY the
/// `secrets.sealer`↔`token.signer` UNSEAL edge (clause 1 — an AwsKms/ambient/absent signer unseals
/// nothing over a link); the generalized serve-designation clause (clause 2), the Tier-2 key-holder
/// check, and the Tier-3 scope check all stand on the topology ALONE. Kept SEPARATE from
/// [`check_composition_closure`] so its signature and callers stay pure over [`PrivsepConfig`].
pub fn check_vm_secret_blindness_closure(
    cfg: &PrivsepConfig,
    sealed_signer: bool,
) -> Result<(), CompositionError> {
    let mut violations = Vec::new();

    let is_vm = |label: &str| -> bool {
        cfg.instances
            .get(label)
            .is_some_and(|i| i.substrate == InstanceSubstrate::Vm)
    };
    let holds = |label: &str, authority: HostAuthority| -> bool {
        cfg.instances
            .get(label)
            .is_some_and(|i| i.capabilities.contains(&authority))
    };
    let any_listener = |label: &str| -> bool {
        cfg.instances
            .get(label)
            .is_some_and(|i| i.capabilities.iter().any(|a| a.is_listener()))
    };

    // Clause (1)'s edge set — the `secrets.sealer`↔`token.signer` unseal-unlock links — derived from
    // the SINGLE shared predicate [`PrivsepConfig::sealer_signer_unseal_edges`] that the root's
    // `compute_unseal_allowlists` also derives from, so the lint can never drift from (silently
    // under-refuse) the unseal model (obligation (a)). Gated on a SEALED signer source (an
    // inline/AwsKms signer unseals nothing over a link — the gate the types layer cannot see itself).
    let unseal_edge_links: BTreeSet<&str> = if sealed_signer {
        cfg.sealer_signer_unseal_edges()
            .iter()
            .map(|e| e.link)
            .collect()
    } else {
        BTreeSet::new()
    };

    // --- Tier 1 (REFUSE): a key-material-bearing link root-relayed across a VM boundary. ---
    for (link_name, link) in &cfg.links {
        // An unhosted endpoint is already a `LinkEndpointUnhosted` refusal from
        // `check_composition_closure`; skip so we neither double-report nor read a missing instance.
        if !cfg.instances.contains_key(&link.from) || !cfg.instances.contains_key(&link.to) {
            continue;
        }

        // Key-material-bearing? (design §2.3)
        // (i) the `secrets.sealer`↔`token.signer` unseal unlock edge — exactly what
        //     `compute_unseal_allowlists` enumerates, via the shared predicate above.
        let unseal_edge = unseal_edge_links.contains(link_name.as_str());

        // The crown-jewel endpoint(s) of this link. A serve-designated link has EXACTLY one (0/≥2 is
        // already an `AuthorityServeLinkNotSingleCrownJewel` refusal for a marked link).
        let crown_endpoints: Vec<&str> = [link.from.as_str(), link.to.as_str()]
            .into_iter()
            .filter(|ep| {
                cfg.instances
                    .get(*ep)
                    .is_some_and(|i| i.capabilities.iter().any(|a| a.is_crown_jewel()))
            })
            .collect();
        // (ii) a serve-DESIGNATED link whose sole crown jewel is the sealer — GENERALIZED (clause 2,
        //      obligation (c)) from the old `is_authority_serve()`-ONLY shape to the FULL
        //      serve-designation shape `boatramp::privsep::compute_authority_serve_links` uses: NOT a
        //      relay, EXACTLY ONE crown-jewel endpoint which holds `secrets.sealer`, AND either
        //      explicitly `AuthorityServe`-marked OR `Unspecified` with a NON-listener peer (the
        //      conservative inference — a listener peer is a client-fd splice, never an authority
        //      serve). Stands on the topology ALONE (not `sealed_signer`-gated). This now also catches
        //      an UNSPECIFIED-purpose sealer→VM serve link the `AuthorityServe`-only clause missed.
        let serve_designated_sealer = !link.is_relay()
            && crown_endpoints.len() == 1
            && holds(crown_endpoints[0], HostAuthority::SecretsSealer)
            && {
                let peer = if crown_endpoints[0] == link.from.as_str() {
                    link.to.as_str()
                } else {
                    link.from.as_str()
                };
                link.is_authority_serve() || !any_listener(peer)
            };

        if !(unseal_edge || serve_designated_sealer) {
            continue;
        }

        // Root-relayed cross-boundary? Two capabilities on the SAME instance share one guest (an
        // intra-guest socketpair, never relayed); a link between DIFFERENT instances where either is a
        // VM crosses the hypervisor boundary and is relayed by the root.
        let cross_boundary = link.from != link.to && (is_vm(&link.from) || is_vm(&link.to));
        if !cross_boundary {
            continue;
        }

        // Name the sealer SOURCE endpoint and the receiving (signer / caller) endpoint for the remedy.
        let (sealer_instance, signer_instance) = if holds(&link.from, HostAuthority::SecretsSealer)
        {
            (link.from.clone(), link.to.clone())
        } else {
            (link.to.clone(), link.from.clone())
        };
        let mut vm_endpoints: Vec<String> = Vec::new();
        if is_vm(&link.from) {
            vm_endpoints.push(link.from.clone());
        }
        if is_vm(&link.to) {
            vm_endpoints.push(link.to.clone());
        }

        violations.push(CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot {
            link: link_name.clone(),
            sealer_instance,
            signer_instance,
            vm_endpoints,
        });
    }

    // --- Tier 2 (REFUSE): a VM instance must hold NO group-A key authority, OR co-reside the sealer
    //     that unlocks it — the first-cut "key-free-OR-co-located" scope, enforced directly. (A VM
    //     holding ONLY `secrets.sealer` co-resides its own sealer and is self-sufficient; a serve it
    //     makes ACROSS a boundary is caught by Tier 1, not here.) ---
    for (name, inst) in &cfg.instances {
        if inst.substrate != InstanceSubstrate::Vm {
            continue;
        }
        let holds_crown_jewel = inst.capabilities.iter().any(|a| a.is_crown_jewel());
        let co_resides_sealer = inst.capabilities.contains(&HostAuthority::SecretsSealer);
        if holds_crown_jewel && !co_resides_sealer {
            violations.push(CompositionViolation::VmKeyHolderNotSelfSufficient {
                instance: name.clone(),
            });
        }
    }

    // --- Tier 3 (REFUSE, obligation (b)): the approved first-cut VM SCOPE
    //     ("no-backends-in-VM / static-parser-frontends-or-co-located-sealer-only"). The S2 tiers
    //     above alone would ALLOW a key-free backend/exec/control instance in a VM; this companion
    //     scope lint fail-closes that gap. An in-scope VM is EXACTLY one of:
    //       - P3, a key-free parser FRONTEND: holds no crown jewel AND every capability is a `listen.*`
    //         parser surface; or
    //       - P1, a co-located sealer BUNDLE: holds `secrets.sealer` AND holds ONLY group-A crown-jewel
    //         key authorities.
    //     Anything else is refused. The crown-jewel-without-sealer shape is OWNED by Tier 2
    //     (`VmKeyHolderNotSelfSufficient`), so it is excluded here to avoid double-reporting the same
    //     instance — each refuse shape maps to exactly one variant. ---
    for (name, inst) in &cfg.instances {
        if inst.substrate != InstanceSubstrate::Vm {
            continue;
        }
        let held: BTreeSet<HostAuthority> = inst.capabilities.iter().copied().collect();
        let holds_sealer = held.contains(&HostAuthority::SecretsSealer);
        let holds_crown_jewel = held.iter().any(|a| a.is_crown_jewel());
        // Tier 2 owns "a VM crown-jewel holder without its co-located sealer"; don't double-report.
        if holds_crown_jewel && !holds_sealer {
            continue;
        }
        let in_scope = if holds_sealer {
            // P1 — a co-located sealer bundle may hold ONLY group-A crown-jewel key authorities.
            held.iter().all(|a| a.is_crown_jewel())
        } else {
            // P3 — a key-free parser frontend may hold ONLY `listen.*` parser surfaces. (An empty set
            // is a `ZeroCapabilityInstance` refusal from the base lint, not an in-scope VM here.)
            held.iter().all(|a| a.is_listener())
        };
        if !in_scope {
            let disallowed: Vec<HostAuthority> = held
                .iter()
                .copied()
                .filter(|a| {
                    if holds_sealer {
                        !a.is_crown_jewel()
                    } else {
                        !a.is_listener()
                    }
                })
                .collect();
            violations.push(CompositionViolation::VmInstanceOutsideApprovedScope {
                instance: name.clone(),
                holds_sealer,
                disallowed,
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
    fn public_listener_anchor_is_group_c_and_forbidden_set_is_backend_plus_spawn_control() {
        // WS-D re-review (decision 1 — widen the lint): the Finding-2 anchor is EXACTLY every group-C
        // listener, and the forbidden-partner set is ALL `backend.*` ∪ {exec.compute, control.admin-api}.
        for &a in HostAuthority::ALL {
            assert_eq!(
                a.is_public_listener(),
                a.is_listener(),
                "anchor: {}",
                a.tag()
            );
            let forbidden = a.is_backend()
                || matches!(
                    a,
                    HostAuthority::ExecCompute | HostAuthority::ControlAdminApi
                );
            assert_eq!(
                a.is_public_listener_forbidden_partner(),
                forbidden,
                "forbidden: {}",
                a.tag()
            );
        }
        // The inverted-frontend exception: `exec.wasmtime` (listen.http-parse + exec.wasmtime) is NOT
        // forbidden — it is the legitimate per-tenant frontend, governed by the Phase-4 template rules.
        assert!(!HostAuthority::ExecWasmtime.is_public_listener_forbidden_partner());
        // `acme.dns-control` (cert issuance, not a control-plane mutation) is NOT forbidden — only
        // `control.admin-api` is (the re-review named it explicitly).
        assert!(!HostAuthority::AcmeDnsControl.is_public_listener_forbidden_partner());
        // Every backend credential is forbidden (all `backend.*`, not just `backend.kv`).
        for &b in &[
            HostAuthority::BackendKv,
            HostAuthority::BackendSql,
            HostAuthority::BackendBlob,
            HostAuthority::BackendMessaging,
        ] {
            assert!(b.is_public_listener_forbidden_partner(), "{}", b.tag());
        }
        // Every group-C listener is an anchor (not just http-parse).
        for &c in &[
            HostAuthority::ListenPublicTls,
            HostAuthority::ListenHttpParse,
            HostAuthority::ListenMail,
            HostAuthority::ListenOverlay,
            HostAuthority::ListenS3Ingress,
            HostAuthority::ListenInboundTcp,
            HostAuthority::ListenGateway,
        ] {
            assert!(c.is_public_listener(), "{}", c.tag());
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

    /// A clean, warning-free least-authority composition whose union == ALL. Restructured for the
    /// WIDENED WS-D Finding-2 lint: a public listener (ANY group-C) may hold no `exec.compute`,
    /// `control.admin-api`, or `backend.*`, so spawn + control move off the listener instances onto
    /// their own `compute` instance.
    /// - `parser`: the public HTTP parse surface (`listen.public-tls` + `listen.http-parse`) — the
    ///   most-exposed instance, holding NO spawn/control/backend (WS-D Finding-2);
    /// - `edge`: the other listeners + `exec.wasmtime` (the inverted-frontend exception — NOT a
    ///   forbidden partner) + `acme.dns-control` (cert issuance, NOT a forbidden partner);
    /// - `compute`: `exec.compute` + `control.admin-api` (D+E, off every listener — the spawn/control
    ///   plane; no listener, no backend, no crown ⇒ no violation, no F8 warning);
    /// - `data`: the four backends (B alone; no listen/exec ⇒ no F8 warning);
    /// - `signer`: the six crown jewels (A alone; co-resides only with A).
    fn clean_composition() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "parser".to_string(),
            inst(&[
                HostAuthority::ListenPublicTls,
                HostAuthority::ListenHttpParse,
            ]),
        );
        instances.insert(
            "edge".to_string(),
            inst(&[
                HostAuthority::ListenMail,
                HostAuthority::ListenOverlay,
                HostAuthority::ListenS3Ingress,
                HostAuthority::ListenInboundTcp,
                HostAuthority::ListenGateway,
                HostAuthority::ExecWasmtime,
                HostAuthority::AcmeDnsControl,
            ]),
        );
        instances.insert(
            "compute".to_string(),
            inst(&[HostAuthority::ExecCompute, HostAuthority::ControlAdminApi]),
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

    // ---- WS-D Finding-2 (widened in re-review): a public listener (ANY group-C) must hold no
    // forbidden partner — exec.compute (spawn), control.admin-api (control), or any backend.* ----

    #[test]
    fn refuses_public_parser_co_resident_with_exec_compute() {
        // Put `exec.compute` on the public-parser instance — the co-location the finding forbids (a
        // parser RCE could fork the pinned binary). The composition is otherwise closed (exec.compute
        // is also still on `compute`; duplication of a non-crown authority is fine).
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("parser")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecCompute);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::PublicListenerWithSpawnControlOrBackend { instance, forbidden, .. }
                    if instance == "parser" && forbidden.contains(&HostAuthority::ExecCompute)
            )),
            "a public parser co-resident with exec.compute must be refused, got {:?}",
            err.violations
        );
    }

    #[test]
    fn refuses_public_parser_co_resident_with_backend_kv() {
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("parser")
            .unwrap()
            .capabilities
            .push(HostAuthority::BackendKv);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::PublicListenerWithSpawnControlOrBackend { instance, forbidden, .. }
                    if instance == "parser" && forbidden.contains(&HostAuthority::BackendKv)
            )),
            "a public parser co-resident with backend.kv must be refused, got {:?}",
            err.violations
        );
    }

    #[test]
    fn refuses_public_parser_co_resident_with_both_spawn_and_kv() {
        // The exact pre-WS-D per-tenant router shape: listen.http-parse + backend.kv + exec.compute.
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("parser")
            .unwrap()
            .capabilities
            .extend([HostAuthority::BackendKv, HostAuthority::ExecCompute]);
        let err = check_composition_closure(&cfg).unwrap_err();
        let forbidden = err.violations.iter().find_map(|v| match v {
            CompositionViolation::PublicListenerWithSpawnControlOrBackend {
                instance,
                forbidden,
                ..
            } if instance == "parser" => Some(forbidden.clone()),
            _ => None,
        });
        let forbidden = forbidden.expect("the router shape must trip the Finding-2 refusal");
        assert!(forbidden.contains(&HostAuthority::BackendKv));
        assert!(forbidden.contains(&HostAuthority::ExecCompute));
    }

    #[test]
    fn refuses_public_tls_listener_co_resident_with_spawn_and_kv() {
        // WIDENED anchor: the forbidden co-location on `listen.public-tls` (SHARPER than http-parse —
        // it holds the live cert key AND parses attacker TLS bytes) must be refused too, not only on
        // `listen.http-parse`. Build an isolated `{listen.public-tls, exec.compute, backend.kv}`
        // instance (the shape that was lint-CLEAN under the narrow anchor).
        let mut cfg = clean_composition();
        cfg.instances.insert(
            "tls-edge".to_string(),
            inst(&[
                HostAuthority::ListenPublicTls,
                HostAuthority::ExecCompute,
                HostAuthority::BackendKv,
            ]),
        );
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::PublicListenerWithSpawnControlOrBackend { instance, listeners, forbidden }
                    if instance == "tls-edge"
                        && listeners.contains(&HostAuthority::ListenPublicTls)
                        && forbidden.contains(&HostAuthority::ExecCompute)
                        && forbidden.contains(&HostAuthority::BackendKv)
            )),
            "a public-tls listener co-resident with spawn + KV must be refused (widened anchor), got {:?}",
            err.violations
        );
    }

    #[test]
    fn refuses_public_parser_co_resident_with_control_admin_api() {
        // WIDENED forbidden set: `control.admin-api` drives every control-plane mutation; a parser RCE
        // co-resident with it can publish / mint-request / set config / apply tenancy.
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("parser")
            .unwrap()
            .capabilities
            .push(HostAuthority::ControlAdminApi);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::PublicListenerWithSpawnControlOrBackend { instance, forbidden, .. }
                    if instance == "parser" && forbidden.contains(&HostAuthority::ControlAdminApi)
            )),
            "a public parser co-resident with control.admin-api must be refused, got {:?}",
            err.violations
        );
    }

    #[test]
    fn refuses_public_parser_co_resident_with_backend_sql() {
        // WIDENED forbidden set: `backend.sql` (the control-plane + managed-DB SQL pools) is now a hard
        // refusal partner, not only the F8 warning it was before.
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("parser")
            .unwrap()
            .capabilities
            .push(HostAuthority::BackendSql);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::PublicListenerWithSpawnControlOrBackend { instance, forbidden, .. }
                    if instance == "parser" && forbidden.contains(&HostAuthority::BackendSql)
            )),
            "a public parser co-resident with backend.sql must be refused, got {:?}",
            err.violations
        );
    }

    #[test]
    fn refuses_non_http_listener_co_resident_with_a_backend() {
        // WIDENED anchor: a NON-http-parse group-C listener (`listen.mail`) co-resident with a backend
        // credential (`backend.blob`) is now a hard refusal — not merely the F8 warning. Confirms the
        // anchor is every group-C listener, and the forbidden set is ALL `backend.*`.
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("edge")
            .unwrap()
            .capabilities
            .push(HostAuthority::BackendBlob);
        let err = check_composition_closure(&cfg).unwrap_err();
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::PublicListenerWithSpawnControlOrBackend { instance, listeners, forbidden }
                    if instance == "edge"
                        && listeners.contains(&HostAuthority::ListenMail)
                        && forbidden.contains(&HostAuthority::BackendBlob)
            )),
            "a non-http public listener co-resident with backend.blob must be refused, got {:?}",
            err.violations
        );
    }

    #[test]
    fn allows_public_parser_with_exec_wasmtime_the_inverted_frontend() {
        // `listen.http-parse` + `exec.wasmtime` is the LEGITIMATE Phase-3 inverted frontend (no
        // spawn, no control, no backend) — it must NOT trip the Finding-2 refusal, even under the
        // widened set. (No per-tenant template here, so `exec.wasmtime` on a static instance is also
        // unconstrained.)
        let mut cfg = clean_composition();
        cfg.instances
            .get_mut("parser")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecWasmtime);
        let report = check_composition_closure(&cfg).expect(
            "a public parser with exec.wasmtime (no spawn/control/backend) is the allowed inverted frontend",
        );
        // It trips no Finding-2 refusal and raises no F8 flag on the parser either.
        assert!(report.warnings.iter().all(|w| !matches!(
            w,
            CompositionWarning::BackendCoResidentWithExposed { instance, .. } if instance == "parser"
        )));
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
        // exec.compute lives on `compute`; move the sole holder onto the signer (keeps union == ALL).
        cfg.instances
            .get_mut("compute")
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
        // control.admin-api lives on `compute`; move the sole holder onto the signer (union == ALL).
        cfg.instances
            .get_mut("compute")
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
        // The F8 second tier (`backend.* × exec.*`) is a WARNING, not a refusal. Under the WIDENED
        // Finding-2 anchor, a backend co-resident with any LISTENER is now a hard refusal (not an F8
        // warning), so the F8 case must be exercised with a backend co-resident with an EXEC (no
        // listener on the instance) — otherwise the Finding-2 refusal would mask the flag this test
        // asserts. `fat-edge` = the backends + both exec + control.admin-api (NO listener): F8 warns.
        let mut instances = BTreeMap::new();
        instances.insert(
            "parser".to_string(),
            inst(&[
                HostAuthority::ListenPublicTls,
                HostAuthority::ListenHttpParse,
            ]),
        );
        instances.insert(
            "listeners".to_string(),
            inst(&[
                HostAuthority::ListenMail,
                HostAuthority::ListenOverlay,
                HostAuthority::ListenS3Ingress,
                HostAuthority::ListenInboundTcp,
                HostAuthority::ListenGateway,
                HostAuthority::AcmeDnsControl,
            ]),
        );
        instances.insert(
            "fat-edge".to_string(),
            inst(&[
                HostAuthority::ExecWasmtime,
                HostAuthority::ExecCompute,
                HostAuthority::ControlAdminApi,
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
        // Listeners + exec.wasmtime + acme (none a Finding-2 forbidden partner); spawn + control move
        // to `compute`, off every public listener (WIDENED WS-D Finding-2).
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
                HostAuthority::AcmeDnsControl,
            ]),
        );
        instances.insert(
            "compute".to_string(),
            inst(&[HostAuthority::ExecCompute, HostAuthority::ControlAdminApi]),
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
        // `OsProcess` + `Container` (Phase-3 namespace/cgroup simple model) are WIRED backends; `Vm`
        // stays the reported follow-on (its own kernel ⇒ the `local` socketpair cannot cross).
        assert!(InstanceSubstrate::OsProcess.is_wired());
        assert!(InstanceSubstrate::Container.is_wired());
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

    /// A valid Phase-4 composition whose union == ALL (restructured for the WIDENED WS-D Finding-2
    /// lint: a public listener holds no `exec.compute`/`control.admin-api`/`backend.*`):
    /// - `tenant-wasm`: a per-tenant TEMPLATE holding ONLY `exec.wasmtime` (the per-tenant guest JIT);
    /// - `parser`: the public parse surface (`listen.public-tls` + `listen.http-parse`);
    /// - `edge`: the other listeners + `acme.dns-control` (acme is not a Finding-2 forbidden partner;
    ///   no `exec.wasmtime` — it moved to the template; no keys, no backends, no spawn/control);
    /// - `compute`: `exec.compute` (the per-tenant SCHEDULER, holds no guest) + `control.admin-api`,
    ///   off every public listener;
    /// - `data`: the four backends (B alone);
    /// - `signer`: the six crown jewels (A alone).
    fn phase4_template_composition() -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert(
            "tenant-wasm".to_string(),
            template(&[HostAuthority::ExecWasmtime]),
        );
        instances.insert(
            "parser".to_string(),
            inst(&[
                HostAuthority::ListenPublicTls,
                HostAuthority::ListenHttpParse,
            ]),
        );
        instances.insert(
            "edge".to_string(),
            inst(&[
                HostAuthority::ListenMail,
                HostAuthority::ListenOverlay,
                HostAuthority::ListenS3Ingress,
                HostAuthority::ListenInboundTcp,
                HostAuthority::ListenGateway,
                HostAuthority::AcmeDnsControl,
            ]),
        );
        instances.insert(
            "compute".to_string(),
            inst(&[HostAuthority::ExecCompute, HostAuthority::ControlAdminApi]),
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
    fn lint_rejects_per_tenant_template_with_container_substrate() {
        // Phase-3 Security re-review, Finding 1: `lifecycle: per_tenant_template` + `substrate:
        // container` must be refused fail-closed (the cold-start `unshare` would be SIGSYS-killed
        // under the router's seccomp, and the signal-kill is invisible to `spawn()` ⇒ a dead
        // instance registered live). The otherwise-identical composition with the template on
        // `os-process` passes clean, proving the refusal is the substrate's.
        let mut cfg = phase4_template_composition();
        assert!(
            check_composition_closure(&cfg).is_ok(),
            "the template composition is clean on the default os-process substrate"
        );
        cfg.instances.get_mut("tenant-wasm").unwrap().substrate = InstanceSubstrate::Container;
        assert!(
            has_violation(&cfg, |v| matches!(
                v,
                CompositionViolation::PerTenantTemplateContainerUnsupported { instance }
                    if instance == "tenant-wasm"
            )),
            "a per-tenant template on the container substrate must be refused fail-closed"
        );
        // A STATIC instance on the container substrate is UNAFFECTED (it boot-forks from the
        // unconfined root): flipping `data` to container raises no PerTenantTemplate violation.
        let mut ok = phase4_template_composition();
        ok.instances.get_mut("data").unwrap().substrate = InstanceSubstrate::Container;
        assert!(
            !has_violation(&ok, |v| matches!(
                v,
                CompositionViolation::PerTenantTemplateContainerUnsupported { .. }
            )),
            "container on a static (boot-forked) instance must not trip the per-tenant refusal"
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
        // Keep the union == ALL (so the template fault is the thing under test): the template now
        // holds exec.compute, so re-home exec.wasmtime onto the `compute` instance (which already
        // holds exec.compute's sibling authorities). The focus is rule (a) — the template fault;
        // `has_violation` tolerates any secondary flag the re-homing raises.
        cfg.instances
            .get_mut("compute")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecWasmtime);
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
        // Put exec.wasmtime on the exec.compute-holding `compute` instance while the template still
        // exists (the scheduler must not itself run guests).
        cfg.instances
            .get_mut("compute")
            .unwrap()
            .capabilities
            .push(HostAuthority::ExecWasmtime);
        assert!(has_violation(&cfg, |v| matches!(
            v,
            CompositionViolation::ExecComputeAndWasmtimeCoResident { instance } if instance == "compute"
        )));
    }

    #[test]
    fn exec_compute_wasmtime_co_residency_rule_is_gated_on_template_presence() {
        // `clean_composition` has NO per-tenant template (a pre-Phase-4 composition), so the exec.compute
        // × exec.wasmtime co-residency rule must NOT fire — it passes clean entirely. (The rule is gated
        // on template presence; without a template `exec.compute` is not yet the per-tenant scheduler.)
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
        // `parser`={public-tls,http-parse}; `edge`={other listeners, acme}; `compute`={exec.compute,
        // control}; `data`={backend.*}; `signer`={6 crown jewels}} is authorized — exec.wasmtime lives
        // ONLY on the per-tenant template.
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
            ..PerTenantPolicy::default()
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
            ..PerTenantPolicy::default()
        };
        assert_eq!(no_evict.validate(), Ok(()));
        assert_eq!(no_evict.idle_eviction(), None);
    }

    #[test]
    fn cold_start_backoff_is_exponential_and_capped() {
        let p = PerTenantPolicy {
            cold_start_backoff_base_ms: 500,
            cold_start_backoff_max_ms: 30_000,
            ..PerTenantPolicy::default()
        };
        assert_eq!(
            p.cold_start_backoff(1),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            p.cold_start_backoff(2),
            std::time::Duration::from_millis(1000)
        );
        assert_eq!(
            p.cold_start_backoff(3),
            std::time::Duration::from_millis(2000)
        );
        // Climbs geometrically but never exceeds the cap — even for an absurd failure count
        // (the shift is bounded, so there is no overflow / wrap).
        assert_eq!(
            p.cold_start_backoff(100),
            std::time::Duration::from_millis(30_000)
        );
        assert_eq!(p.cold_start_burst_capacity(), 100.0);
        assert_eq!(
            p.cold_start_min_healthy(),
            std::time::Duration::from_millis(1000)
        );
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

    // ---- S2: VM secret-blindness composition-closure lint (`check_vm_secret_blindness_closure`) ----
    //
    // Tier 1 REFUSES a key-material-bearing link (a `secrets.sealer`↔`token.signer` unseal unlock, or
    // an `AuthorityServe` link whose single crown jewel is the sealer) root-relayed across a VM
    // boundary — the KEK-unsealed plaintext would transit the secret-blind root's vsock relay. Tier 2
    // REFUSES a VM instance that holds a group-A key authority without co-residing its sealer (the
    // first-cut "key-free-OR-co-located" scope). Both are PURE over the resolved PrivsepConfig.

    /// Mark one instance's isolation substrate.
    fn set_substrate(cfg: &mut PrivsepConfig, instance: &str, substrate: InstanceSubstrate) {
        cfg.instances.get_mut(instance).unwrap().substrate = substrate;
    }

    #[test]
    fn vm_refuses_sealer_signer_unlock_link_crossing_a_vm_boundary() {
        // `split_signer_composition`: `sealer` (secrets.sealer + 4 other jewels) and `signer`
        // (token.signer alone) on DIFFERENT instances, joined by the `to-signer` unseal link. Put the
        // SEALER in a VM: the sealer co-resides its own KEK so Tier 2 stays silent (clean Tier-1
        // isolation), but the unseal unlock link now crosses the hypervisor boundary → the root would
        // relay KEK-unsealed key material.
        let mut cfg = split_signer_composition();
        set_substrate(&mut cfg, "sealer", InstanceSubstrate::Vm);

        let err = check_vm_secret_blindness_closure(&cfg, true)
            .expect_err("a sealer↔signer unseal link across a VM boundary must refuse");
        assert_eq!(err.violations.len(), 1, "exactly the Tier-1 refusal: {err}");
        match &err.violations[0] {
            CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot {
                link,
                sealer_instance,
                signer_instance,
                vm_endpoints,
            } => {
                assert_eq!(link, "to-signer");
                assert_eq!(sealer_instance, "sealer");
                assert_eq!(signer_instance, "signer");
                assert_eq!(vm_endpoints, &vec!["sealer".to_string()]);
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
    }

    #[test]
    fn vm_unseal_link_refusal_is_gated_on_a_sealed_signer() {
        // The SAME topology (sealer in a VM, linked to a separate signer) is a Tier-1 no-op when the
        // signer is NOT sealed — an AwsKms/ambient/inline signer unseals nothing over the link, so no
        // key material would cross. (The sealer-in-VM self-resides its KEK ⇒ Tier 2 silent too.)
        let mut cfg = split_signer_composition();
        set_substrate(&mut cfg, "sealer", InstanceSubstrate::Vm);
        check_vm_secret_blindness_closure(&cfg, false)
            .expect("a non-sealed signer crosses no key material — the unseal edge is gated");
    }

    #[test]
    fn vm_refuses_an_authority_serve_to_sealer_link_even_when_unsealed() {
        // The design's SECOND key-material-bearing clause: an explicit `AuthorityServe` link whose
        // single crown-jewel endpoint IS the sealer stands on the topology ALONE (NOT gated on
        // `sealed_signer`). `sealer` serves the authority grammar to a key-free `frontend` listener in
        // a VM → the serve response (key material) would cross the root-relayed boundary.
        let mut instances = BTreeMap::new();
        instances.insert(
            "frontend".to_string(),
            inst(&[
                HostAuthority::ListenPublicTls,
                HostAuthority::ListenHttpParse,
            ]),
        );
        // The sole crown-jewel endpoint is `secrets.sealer` (exactly one ⇒ a well-formed authority-serve
        // link, not an `AuthorityServeLinkNotSingleCrownJewel`).
        instances.insert("sealer".to_string(), inst(&[HostAuthority::SecretsSealer]));
        let mut links = BTreeMap::new();
        links.insert(
            "serve".to_string(),
            PrivsepLink {
                from: "frontend".to_string(),
                to: "sealer".to_string(),
                transport: LinkTransport::Local,
                purpose: LinkPurpose::AuthorityServe,
            },
        );
        let mut cfg = PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
        };
        // The VM endpoint is the KEY-FREE frontend (so Tier 2 stays silent — it holds no crown jewel).
        set_substrate(&mut cfg, "frontend", InstanceSubstrate::Vm);

        // `sealed_signer = false`: the authority-serve-to-sealer clause is topology-only.
        let err = check_vm_secret_blindness_closure(&cfg, false)
            .expect_err("an authority-serve-to-sealer link across a VM boundary must refuse");
        assert_eq!(err.violations.len(), 1, "exactly the Tier-1 refusal: {err}");
        match &err.violations[0] {
            CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot {
                link,
                sealer_instance,
                signer_instance,
                vm_endpoints,
            } => {
                assert_eq!(link, "serve");
                assert_eq!(sealer_instance, "sealer");
                assert_eq!(signer_instance, "frontend");
                assert_eq!(vm_endpoints, &vec!["frontend".to_string()]);
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
    }

    #[test]
    fn vm_refuses_a_key_holder_without_its_co_resident_sealer() {
        // Tier 2, ISOLATED: put the key-holding `signer` (token.signer, no secrets.sealer) in a VM and
        // pass `sealed_signer = false` so the Tier-1 unseal edge does NOT fire — proving Tier 2 stands
        // on the topology alone: a VM key holder that does not co-reside its sealer is refused outright
        // (the "key-free-OR-co-located" first-cut scope).
        let mut cfg = split_signer_composition();
        set_substrate(&mut cfg, "signer", InstanceSubstrate::Vm);

        let err = check_vm_secret_blindness_closure(&cfg, false)
            .expect_err("a VM instance holding token.signer without its sealer must refuse");
        assert_eq!(err.violations.len(), 1, "exactly the Tier-2 refusal: {err}");
        match &err.violations[0] {
            CompositionViolation::VmKeyHolderNotSelfSufficient { instance } => {
                assert_eq!(instance, "signer");
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
    }

    #[test]
    fn vm_both_tiers_fire_for_a_sealed_key_holder_in_a_vm() {
        // When the KEY-HOLDING signer is in a VM AND sealed, BOTH tiers fire and compose: Tier 1 (the
        // unseal link crosses to the VM) and Tier 2 (the VM holds token.signer without its sealer).
        let mut cfg = split_signer_composition();
        set_substrate(&mut cfg, "signer", InstanceSubstrate::Vm);
        let err = check_vm_secret_blindness_closure(&cfg, true)
            .expect_err("a sealed key holder in a VM trips both tiers");
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot { signer_instance, .. }
                    if signer_instance == "signer"
            )),
            "Tier 1 (key-material link relayed) must fire: {err}"
        );
        assert!(
            err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::VmKeyHolderNotSelfSufficient { instance }
                    if instance == "signer"
            )),
            "Tier 2 (key holder not self-sufficient) must fire: {err}"
        );
    }

    #[test]
    fn vm_allows_the_p1_co_located_sealer_and_signer_in_one_vm() {
        // P1: secrets.sealer + token.signer (+ every other jewel) co-located on ONE instance — their
        // unlock is an intra-guest socketpair the root never relays. Put that whole crown-jewel
        // instance in a VM: the key conversation never leaves the guest, so the lint ALLOWS it, and the
        // base composition-closure lint still passes (no regression).
        let mut cfg = clean_composition();
        set_substrate(&mut cfg, "signer", InstanceSubstrate::Vm);
        check_vm_secret_blindness_closure(&cfg, true)
            .expect("a co-located sealer+signer in one VM is self-sufficient (P1)");
        check_composition_closure(&cfg).expect("the base composition-closure lint still passes");
    }

    #[test]
    fn vm_allows_a_key_free_vm_parser_frontend() {
        // P3: a key-free VM instance — `parser` holds only group-C listeners (no crown jewel, in no key
        // link), the conservative default. The lint ALLOWS it; the base lint still passes.
        let mut cfg = clean_composition();
        set_substrate(&mut cfg, "parser", InstanceSubstrate::Vm);
        check_vm_secret_blindness_closure(&cfg, true)
            .expect("a key-free VM parser frontend is allowed (P3)");
        check_composition_closure(&cfg).expect("the base composition-closure lint still passes");
    }

    #[test]
    fn vm_lint_is_a_noop_on_existing_non_vm_topologies() {
        // No regression: with NO substrate:Vm instance anywhere, BOTH tiers are a structural no-op —
        // for a sealed signer AND a non-sealed one — across the shipped fixtures.
        for sealed in [false, true] {
            check_vm_secret_blindness_closure(&clean_composition(), sealed).unwrap_or_else(|e| {
                panic!("clean (all OsProcess) must pass (sealed={sealed}): {e}")
            });
            check_vm_secret_blindness_closure(&split_signer_composition(), sealed).unwrap_or_else(
                |e| panic!("split-signer (all OsProcess) must pass (sealed={sealed}): {e}"),
            );
        }
        // The existing closure checks are unmodified and keep passing.
        check_composition_closure(&clean_composition()).expect("base composition lint unchanged");
        check_sealed_signer_closure(&split_signer_composition(), true)
            .expect("sealed-signer lint unchanged");
    }

    // ---- Obligation (a): the shared sealer↔signer unseal-edge predicate (the single source of truth
    // the lint's clause 1 and `compute_unseal_allowlists` both derive from — no drift). ----

    #[test]
    fn sealer_signer_unseal_edges_enumerate_only_cross_instance_sealer_signer_links() {
        // The shared predicate yields exactly the cross-instance sealer↔signer links, naming the sealer
        // SOURCE end and the signer RECEIVER end; it ignores self-links and non-key links.
        let cfg = split_signer_composition();
        let edges = cfg.sealer_signer_unseal_edges();
        assert_eq!(edges.len(), 1, "exactly the `to-signer` edge: {edges:?}");
        assert_eq!(edges[0].link, "to-signer");
        assert_eq!(edges[0].sealer_instance, "sealer");
        assert_eq!(edges[0].signer_instance, "signer");
        // `clean_composition`'s signer holds BOTH sealer+signer (resolves in-process, no cross link),
        // so there is NO cross-instance unseal edge to enumerate.
        assert!(
            clean_composition().sealer_signer_unseal_edges().is_empty(),
            "a co-resident sealer+signer has no cross-instance unseal edge"
        );
    }

    // ---- Obligation (c): clause 2 GENERALIZED from `AuthorityServe`-only to the full
    // serve-designation shape, so an Unspecified-purpose sealer→VM serve link is caught too. ----

    /// A minimal 2-instance VM topology: a `sealer` (VM, holding only `secrets.sealer` → self-sufficient,
    /// so Tiers 2 & 3 stay silent) and a `peer` linked to it with the given purpose + capabilities.
    fn sealer_vm_with_peer(purpose: LinkPurpose, peer_caps: &[HostAuthority]) -> PrivsepConfig {
        let mut instances = BTreeMap::new();
        instances.insert("sealer".to_string(), inst(&[HostAuthority::SecretsSealer]));
        instances.insert("peer".to_string(), inst(peer_caps));
        let mut links = BTreeMap::new();
        links.insert(
            "serve".to_string(),
            PrivsepLink {
                from: "peer".to_string(),
                to: "sealer".to_string(),
                transport: LinkTransport::Local,
                purpose,
            },
        );
        let mut cfg = PrivsepConfig {
            instances,
            links,
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
        };
        set_substrate(&mut cfg, "sealer", InstanceSubstrate::Vm);
        cfg
    }

    #[test]
    fn vm_clause2_refuses_an_unspecified_sealer_serve_link_crossing_a_vm_boundary() {
        // An UNSPECIFIED link whose SOLE crown jewel is the sealer and whose peer is NON-listener is
        // serve-DESIGNATED by `compute_authority_serve_links`' conservative inference — the sealer would
        // serve seal/unseal key material over it, and across a VM boundary the secret-blind root relays
        // that key material. The OLD `is_authority_serve()`-only clause 2 missed this; the generalized
        // clause catches it, standing on the topology ALONE (`sealed_signer = false`).
        let cfg = sealer_vm_with_peer(LinkPurpose::Unspecified, &[HostAuthority::ControlAdminApi]);
        let err = check_vm_secret_blindness_closure(&cfg, false).expect_err(
            "an Unspecified sealer-serve link across a VM boundary must refuse (clause 2)",
        );
        assert_eq!(
            err.violations.len(),
            1,
            "exactly the generalized Tier-1 refusal: {err}"
        );
        match &err.violations[0] {
            CompositionViolation::VmKeyMaterialLinkRelayedThroughRoot {
                link,
                sealer_instance,
                signer_instance,
                vm_endpoints,
            } => {
                assert_eq!(link, "serve");
                assert_eq!(sealer_instance, "sealer");
                assert_eq!(signer_instance, "peer");
                assert_eq!(vm_endpoints, &vec!["sealer".to_string()]);
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
    }

    #[test]
    fn vm_clause2_does_not_over_fire_on_a_relay_or_a_listener_peer() {
        // The generalization faithfully MIRRORS `compute_authority_serve_links` — it must not over-fire:
        // (a) a `Relay`-marked sealer link is a client-fd serving SPLICE, never a key-material serve;
        // (b) an `Unspecified` sealer→LISTENER-frontend link is a client-fd splice too (the inference
        //     excludes a listener peer). Neither carries key material, so both are ACCEPTED even though
        //     they cross the VM boundary.
        check_vm_secret_blindness_closure(
            &sealer_vm_with_peer(LinkPurpose::Relay, &[HostAuthority::ControlAdminApi]),
            false,
        )
        .expect("a relay sealer link is a serving splice, never a key-material serve");
        check_vm_secret_blindness_closure(
            &sealer_vm_with_peer(LinkPurpose::Unspecified, &[HostAuthority::ListenHttpParse]),
            false,
        )
        .expect("an Unspecified sealer→listener-frontend link is a client-fd splice, not a serve");
    }

    // ---- Obligation (b): the companion VM SCOPE lint (Tier 3) — a VM must be a key-free listener-only
    // parser frontend (P3) or a co-located sealer bundle (P1); anything else is refused fail-closed. ----

    #[test]
    fn vm_scope_refuses_a_key_free_backend_in_a_vm() {
        // The gap the S2 Tiers 1+2 alone did NOT close: a key-free BACKEND instance in a VM. The
        // companion scope lint REFUSES it (`clean_composition`'s `data` holds the four backends — no
        // key, no listener). `sealed_signer` is irrelevant (no key link here).
        let mut cfg = clean_composition();
        set_substrate(&mut cfg, "data", InstanceSubstrate::Vm);
        let err = check_vm_secret_blindness_closure(&cfg, false)
            .expect_err("a key-free backend instance in a VM is outside the approved scope");
        assert_eq!(
            err.violations.len(),
            1,
            "exactly the Tier-3 scope refusal: {err}"
        );
        match &err.violations[0] {
            CompositionViolation::VmInstanceOutsideApprovedScope {
                instance,
                holds_sealer,
                disallowed,
            } => {
                assert_eq!(instance, "data");
                assert!(!*holds_sealer, "a backend instance holds no sealer");
                assert!(disallowed.contains(&HostAuthority::BackendKv));
                assert!(
                    disallowed.iter().all(|a| !a.is_listener()),
                    "the disallowed set is the non-listener authorities to move off the VM"
                );
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
        // The base composition-closure lint is unaffected by substrate — still valid (no regression).
        check_composition_closure(&cfg).expect("base composition lint still passes");
    }

    #[test]
    fn vm_scope_refuses_a_key_free_exec_and_control_instance_in_a_vm() {
        // Likewise a key-free exec/control instance in a VM (`clean_composition`'s `compute` holds
        // `exec.compute` + `control.admin-api` — key-free, not listener-only).
        let mut cfg = clean_composition();
        set_substrate(&mut cfg, "compute", InstanceSubstrate::Vm);
        let err = check_vm_secret_blindness_closure(&cfg, false)
            .expect_err("a key-free exec/control instance in a VM is outside the approved scope");
        assert_eq!(err.violations.len(), 1, "{err}");
        match &err.violations[0] {
            CompositionViolation::VmInstanceOutsideApprovedScope {
                instance,
                holds_sealer,
                disallowed,
            } => {
                assert_eq!(instance, "compute");
                assert!(!*holds_sealer);
                assert!(disallowed.contains(&HostAuthority::ExecCompute));
                assert!(disallowed.contains(&HostAuthority::ControlAdminApi));
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
    }

    #[test]
    fn vm_scope_refuses_a_sealer_bundle_polluted_with_a_backend() {
        // P1 is a co-located sealer bundle holding ONLY group-A keys. A sealer VM that ALSO holds a
        // backend credential is outside scope (no-backends-in-VM) — the `holds_sealer` arm of the scope
        // variant (distinct message from the key-free arm).
        let mut instances = BTreeMap::new();
        instances.insert(
            "bundle".to_string(),
            inst(&[
                HostAuthority::SecretsSealer,
                HostAuthority::TokenSigner,
                HostAuthority::BackendKv,
            ]),
        );
        let mut cfg = PrivsepConfig {
            instances,
            links: BTreeMap::new(),
            supervisor: None,
            per_tenant: PerTenantPolicy::default(),
        };
        set_substrate(&mut cfg, "bundle", InstanceSubstrate::Vm);
        let err = check_vm_secret_blindness_closure(&cfg, true)
            .expect_err("a sealer bundle in a VM may not hold a backend credential");
        assert_eq!(err.violations.len(), 1, "{err}");
        match &err.violations[0] {
            CompositionViolation::VmInstanceOutsideApprovedScope {
                instance,
                holds_sealer,
                disallowed,
            } => {
                assert_eq!(instance, "bundle");
                assert!(*holds_sealer, "it IS a sealer bundle (just a polluted one)");
                assert_eq!(disallowed, &vec![HostAuthority::BackendKv]);
            }
            other => panic!("wrong variant / wrong reason: {other:?}"),
        }
    }

    #[test]
    fn vm_scope_leaves_the_non_co_located_key_holder_to_tier2() {
        // Partition proof: a VM holding a crown jewel without its sealer is Tier 2
        // (`VmKeyHolderNotSelfSufficient`); Tier 3 must NOT also report it, so each refuse shape maps to
        // exactly one variant.
        let mut cfg = split_signer_composition();
        set_substrate(&mut cfg, "signer", InstanceSubstrate::Vm);
        let err = check_vm_secret_blindness_closure(&cfg, false)
            .expect_err("a VM key holder without its sealer must refuse");
        assert_eq!(
            err.violations.len(),
            1,
            "exactly the Tier-2 refusal, not also a scope refusal: {err}"
        );
        assert!(
            matches!(
                &err.violations[0],
                CompositionViolation::VmKeyHolderNotSelfSufficient { instance } if instance == "signer"
            ),
            "the key holder is Tier 2's variant: {err}"
        );
        assert!(
            !err.violations.iter().any(|v| matches!(
                v,
                CompositionViolation::VmInstanceOutsideApprovedScope { .. }
            )),
            "Tier 3 must NOT double-report the key-holder shape: {err}"
        );
    }

    #[test]
    fn vm_scope_allows_p1_and_p3_and_every_non_vm_topology() {
        // ALLOW cases, scope-framed: P1 (a co-located sealer+signer bundle in a VM) and P3 (a key-free
        // listener-only parser frontend in a VM) both pass the whole VM lint; and with NO VM instance,
        // Tier 3 is a structural no-op across the shipped fixtures (belt with the existing no-op test).
        let mut p1 = clean_composition(); // `signer` = all six crown jewels (incl. sealer)
        set_substrate(&mut p1, "signer", InstanceSubstrate::Vm);
        check_vm_secret_blindness_closure(&p1, true).expect("P1 co-located sealer bundle in a VM");

        let mut p3 = clean_composition(); // `parser` = listen.public-tls + listen.http-parse only
        set_substrate(&mut p3, "parser", InstanceSubstrate::Vm);
        check_vm_secret_blindness_closure(&p3, true)
            .expect("P3 key-free listener-only VM frontend");

        for sealed in [false, true] {
            check_vm_secret_blindness_closure(&clean_composition(), sealed)
                .expect("no VM ⇒ Tier 3 is a no-op");
            check_vm_secret_blindness_closure(&split_signer_composition(), sealed)
                .expect("no VM ⇒ Tier 3 is a no-op");
        }
    }
}
