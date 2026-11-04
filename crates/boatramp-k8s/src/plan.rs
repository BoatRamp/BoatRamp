//! The **pure** resource planner: a compute spec for a managed database → the typed
//! Kubernetes objects boatramp applies for it (a `StatefulSet` for stable identity, a
//! `Service` named after the workload for the in-cluster DNS the sql-shim/bindings
//! resolve, and a `PersistentVolumeClaim` for the data volume).
//!
//! Everything here is a pure function (spec → objects) with **no I/O** and no cluster
//! contact, so the mapping is fully unit-testable without a cluster — this is where the
//! tests live. The client-side apply/delete/health lives in [`crate`]'s backend impl.

use std::collections::BTreeMap;

use boatramp_core::compute::{ComputeSpec, RootSource, compute_instance_id};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, EnvVar, LocalObjectReference, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, PersistentVolumeClaimVolumeSource, PodSecurityContext, PodSpec,
    PodTemplateSpec, Probe, SeccompProfile, SecurityContext, Service, ServicePort, ServiceSpec,
    TCPSocketAction, TypedLocalObjectReference, Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use serde::{Deserialize, Serialize};

/// The field-manager boatramp applies its compute objects under (server-side apply).
pub const FIELD_MANAGER: &str = "boatramp-compute";

/// Label marking an object as boatramp-managed compute (the stable selector key).
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
/// The label value for [`MANAGED_BY_LABEL`].
pub const MANAGED_BY_VALUE: &str = "boatramp";
/// The per-workload selector label — its value is the (DNS-safe) workload name, so a
/// Service's selector matches exactly its own StatefulSet's pods.
pub const WORKLOAD_LABEL: &str = "boatramp.dev/workload";
/// Annotation recording the owning project (an annotation, not a label, so a project
/// name outside the label charset is still carried without an invalid-value rejection).
pub const PROJECT_ANNOTATION: &str = "boatramp.dev/project";

/// Why building the resource plan failed (pure, no I/O).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The workload (or a derived object) name is not a valid RFC 1123 DNS label, so it
    /// could not be a Kubernetes `Service`/object name. The managed-DB DSN host is the
    /// bare workload name resolved by in-cluster DNS, so the Service MUST carry that exact
    /// name — a name with an underscore or other out-of-charset byte (e.g. a
    /// `sanitize_ident`-derived per-tenant `pg-acme_3f9c…`) is REFUSED here rather than
    /// silently applied as an unreachable Service. Phase 2 adds a DNS-safe name mapping
    /// (with the shim-side host following it).
    #[error(
        "workload name {0:?} is not a valid RFC 1123 DNS label (lowercase alphanumeric or '-', \
         1..=63 chars, starting/ending alphanumeric): it cannot name a Kubernetes Service that \
         in-cluster DNS resolves"
    )]
    InvalidName(String),
    /// The spec's root is not an OCI image reference. The kubelet pulls the operand image,
    /// so the k8s backend requires a [`RootSource::Image`] (an ext4 rootfs / tar is for the
    /// VM / native-container substrates, not a pod).
    #[error("kubernetes backend requires an image reference (RootSource::Image), got {0}")]
    NonImageRoot(&'static str),
    /// A managed database spec must declare exactly one persistent volume (its data
    /// directory). Phase 1 covers the managed-DB stateful case only.
    #[error("managed-database spec must declare exactly one persistent volume, found {0}")]
    VolumeCount(usize),
}

/// The inputs the planner needs beyond the immutable [`ComputeSpec`]: the replica
/// identity and the cluster placement knobs. Keeping these separate from the spec keeps
/// the function a pure `(identity, spec) → objects` mapping.
#[derive(Debug, Clone)]
pub struct PlanContext {
    /// The owning project (carried as an annotation for operator visibility).
    pub project: String,
    /// The workload name — also the Service name + the in-cluster DNS the sql-shim
    /// resolves (`pg-<ident>`). Must be a valid RFC 1123 DNS label.
    pub workload: String,
    /// Replica ordinal (Phase 1 provisions a single-replica StatefulSet, so this is
    /// recorded for identity but the StatefulSet always runs one pod).
    pub replica: u32,
    /// The namespace to place the objects in — the serve pod's OWN namespace.
    pub namespace: String,
    /// The `StorageClass` for the PVC. `None` ⇒ omit `storageClassName` so the cluster's
    /// **default** StorageClass is used (which must itself allow volume expansion — see
    /// [`expandable_storage_class`] for an operator-owned alternative).
    pub storage_class: Option<String>,
    /// The name of a pre-existing k8s `Secret` of type `kubernetes.io/dockerconfigjson`
    /// in this namespace to attach to the pod as an `imagePullSecret`, so the kubelet can
    /// pull the operand image from a PRIVATE registry (Phase 2, item 7). `None` ⇒ an
    /// anonymous/public pull. Operator-configured (`[compute].k8s_image_pull_secret`); the
    /// secret itself is managed outside boatramp (never created here — the backend's RBAC
    /// grants no `secrets` verb).
    pub image_pull_secret: Option<String>,
}

/// The typed Kubernetes objects for one managed database — what the backend applies
/// (server-side) and later deletes.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourcePlan {
    /// Stable identity + the pod running the operand image.
    pub stateful_set: StatefulSet,
    /// The `pg-<ident>` ClusterIP Service — the in-cluster DNS the sql-shim/bindings
    /// resolve to reach the database.
    pub service: Service,
    /// The data volume's claim (on the default / configured StorageClass).
    pub pvc: PersistentVolumeClaim,
}

/// Whether `s` is a valid RFC 1123 DNS label (a Kubernetes object/Service name).
pub fn is_dns1123_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let bytes = s.as_bytes();
    let edge_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !edge_ok(bytes[0]) || !edge_ok(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The standalone PVC name backing a workload's data volume (`<volume>-<workload>`),
/// kept DNS-safe (the volume name in a managed-DB spec is the literal `data`).
pub fn pvc_name(volume: &str, workload: &str) -> String {
    format!("{volume}-{workload}")
}

/// The stable selector labels — the immutable subset a StatefulSet's `spec.selector` and
/// the Service's selector share with the pod template (Kubernetes requires the selector
/// to be a subset of the pod labels).
fn selector_labels(workload: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
        (WORKLOAD_LABEL.to_string(), workload.to_string()),
    ])
}

/// The owning-project annotation set (project + replica ordinal), for operator visibility.
fn annotations(ctx: &PlanContext) -> BTreeMap<String, String> {
    BTreeMap::from([
        (PROJECT_ANNOTATION.to_string(), ctx.project.clone()),
        ("boatramp.dev/replica".to_string(), ctx.replica.to_string()),
    ])
}

/// Metadata shared by every object the plan emits.
fn object_meta(name: String, ctx: &PlanContext) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: Some(ctx.namespace.clone()),
        labels: Some(selector_labels(&ctx.workload)),
        annotations: Some(annotations(ctx)),
        ..Default::default()
    }
}

/// Build the managed-database resource plan from an immutable [`ComputeSpec`] +
/// [`PlanContext`]. Pure: no I/O, so the whole mapping is unit-tested below.
///
/// Maps to a single-replica `StatefulSet` (stable identity) running the operand image,
/// a ClusterIP `Service` named after the workload (the `pg-<ident>` DNS the sql-shim
/// resolves), and a standalone `PersistentVolumeClaim` for the data directory (managed
/// separately so teardown can retain-or-delete it per policy).
pub fn managed_db_plan(ctx: &PlanContext, spec: &ComputeSpec) -> Result<ResourcePlan, PlanError> {
    if !is_dns1123_label(&ctx.workload) {
        return Err(PlanError::InvalidName(ctx.workload.clone()));
    }
    let image = match &spec.root {
        RootSource::Image(reference) => reference.clone(),
        RootSource::Tar(_) => return Err(PlanError::NonImageRoot("tar rootfs")),
        RootSource::Rootfs(_) => return Err(PlanError::NonImageRoot("rootfs image")),
    };
    // Phase 1 = the managed-DB stateful case: exactly one data volume.
    if spec.volumes.len() != 1 {
        return Err(PlanError::VolumeCount(spec.volumes.len()));
    }
    let volume = &spec.volumes[0];
    let claim = pvc_name(&volume.name, &ctx.workload);

    // The PVC: RWO on the configured/default StorageClass, sized from the spec. Resizing
    // is a later `spec.resources.requests.storage` patch, which k8s honors only when the
    // StorageClass has `allowVolumeExpansion` (the cluster default, or an operator-owned
    // `expandable_storage_class`).
    let pvc = PersistentVolumeClaim {
        metadata: object_meta(claim.clone(), ctx),
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_string(),
                    Quantity(format!("{}Mi", volume.size_mib)),
                )])),
                ..Default::default()
            }),
            // `None` ⇒ no `storageClassName` on the wire ⇒ the cluster default SC.
            storage_class_name: ctx.storage_class.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };

    // The container running the operand image. The shared-kernel backends apply the
    // image filesystem, not its OCI config, so the explicit entrypoint from the spec is
    // the argv the pod runs (`command`), with the port + data mount wired through.
    let container = Container {
        name: "db".to_string(),
        image: Some(image.clone()),
        command: (!spec.entrypoint.is_empty()).then(|| spec.entrypoint.clone()),
        env: env_vars(spec),
        ports: Some(vec![ContainerPort {
            container_port: i32::from(spec.port),
            name: Some("db".to_string()),
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }]),
        volume_mounts: Some(vec![VolumeMount {
            name: volume.name.clone(),
            mount_path: volume.mount.clone(),
            ..Default::default()
        }]),
        // A TCP readiness probe on the DB port makes the StatefulSet's `readyReplicas`
        // (what `health` reads) reflect the server actually accepting connections.
        readiness_probe: Some(Probe {
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(i32::from(spec.port)),
                ..Default::default()
            }),
            period_seconds: Some(10),
            ..Default::default()
        }),
        security_context: Some(hardened_security_context(spec)),
        ..Default::default()
    };

    // A numeric `user` (`uid[:gid]`) becomes the pod security context, and `fsGroup`
    // makes the kubelet group-own the mounted PVC to that gid — the k8s-native
    // equivalent of the docker/native pre-chown so a rootless DB can write its data dir.
    let security_context = pod_security_context(spec);

    let pod_volume = Volume {
        name: volume.name.clone(),
        persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
            claim_name: claim,
            read_only: Some(false),
        }),
        ..Default::default()
    };
    let pod = PodSpec {
        containers: vec![container],
        volumes: Some(vec![pod_volume]),
        security_context,
        image_pull_secrets: image_pull_secrets(ctx),
        // A managed-DB pod never calls the k8s API, so do not auto-mount the namespace
        // default ServiceAccount token into it — removing unnecessary apiserver reach from
        // a SQL-reachable operand image (a classic SQL→RCE surface).
        automount_service_account_token: Some(false),
        ..Default::default()
    };

    let stateful_set = StatefulSet {
        metadata: object_meta(ctx.workload.clone(), ctx),
        spec: Some(StatefulSetSpec {
            // Phase 1: one replica (a managed DB is single-writer). Scaling is Phase 2.
            replicas: Some(1),
            // The governing service for stable per-pod DNS; we reuse the workload Service.
            service_name: Some(ctx.workload.clone()),
            selector: LabelSelector {
                match_labels: Some(selector_labels(&ctx.workload)),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(selector_labels(&ctx.workload)),
                    ..Default::default()
                }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let service = Service {
        metadata: object_meta(ctx.workload.clone(), ctx),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_string()),
            selector: Some(selector_labels(&ctx.workload)),
            ports: Some(vec![ServicePort {
                name: Some("db".to_string()),
                port: i32::from(spec.port),
                target_port: Some(IntOrString::Int(i32::from(spec.port))),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(ResourcePlan {
        stateful_set,
        service,
        pvc,
    })
}

/// A boatramp-owned, **expandable** `StorageClass` for managed-database volumes — an
/// operator-applied alternative to relying on the cluster default having
/// `allowVolumeExpansion`. Phase 1 exposes + tests it (so the grow-in-place story is
/// concrete), but the backend does NOT apply it: a `StorageClass` is cluster-scoped and
/// so sits OUTSIDE the namespace-scoped RBAC Role boatramp ships — applying it is an
/// explicit operator step (documented in the chart). `WaitForFirstConsumer` binding
/// defers PV provisioning to the node the pod lands on (correct for a single-attach
/// RWO DB volume).
pub fn expandable_storage_class(name: &str, provisioner: &str) -> StorageClass {
    StorageClass {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([(
                MANAGED_BY_LABEL.to_string(),
                MANAGED_BY_VALUE.to_string(),
            )])),
            ..Default::default()
        },
        provisioner: provisioner.to_string(),
        allow_volume_expansion: Some(true),
        volume_binding_mode: Some("WaitForFirstConsumer".to_string()),
        reclaim_policy: Some("Delete".to_string()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Phase 2: DNS-safe naming
// ---------------------------------------------------------------------------

/// The maximum length of an RFC 1123 DNS **label** — a Kubernetes object/Service name.
pub const DNS_LABEL_MAX: usize = 63;

/// Hex-digit width of the collision-resistant hash suffix appended to a shortened /
/// sanitized name (16 hex = 64 bits of a SHA-256 digest — negligible collision odds for
/// the handful of objects in one namespace, and stable across runs + binary versions
/// since SHA-256 is fixed).
const HASH_SUFFIX_LEN: usize = 16;

/// A stable, collision-resistant short digest of `s` (`HASH_SUFFIX_LEN` lowercase hex
/// chars of its SHA-256), used to disambiguate a shortened / sanitized object name.
fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.as_bytes());
    let mut hex = hex::encode(digest);
    hex.truncate(HASH_SUFFIX_LEN);
    hex
}

/// Coerce `ident` into a valid RFC 1123 DNS label (a Kubernetes object/Service name),
/// **deterministically and injectively**.
///
/// - An `ident` that is ALREADY a valid label is returned **unchanged** (byte-identical
///   on the wire): every derived managed-DB workload name (`bramp-db-<digest>`) and any
///   plain lowercase `[a-z0-9-]` workload passes through untouched, so existing names +
///   their in-cluster DNS do not move.
/// - Otherwise the name is sanitized (lowercased; every out-of-charset byte — `_`, `.`,
///   uppercase, … — folded to `-`; runs of `-` collapsed; trimmed to an alphanumeric
///   edge) AND a [`short_hash`] of the **original** `ident` is appended, so two distinct
///   idents that sanitize to the same body can never collide on one k8s object. An
///   over-long name is truncated to fit the hash within the 63-char label budget.
///
/// Total (never fails) and idempotent on an already-valid label.
pub fn dns_safe_name(ident: &str) -> String {
    if is_dns1123_label(ident) {
        return ident.to_string();
    }
    // Sanitize to the DNS-label charset.
    let mut body = String::with_capacity(ident.len());
    let mut pending_dash = false;
    for ch in ident.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            if pending_dash && !body.is_empty() {
                body.push('-');
            }
            body.push(c);
            pending_dash = false;
        } else {
            // Defer the separator so a leading / trailing run never produces an edge `-`.
            pending_dash = true;
        }
    }
    let suffix = short_hash(ident);
    // Budget the readable body so `<body>-<suffix>` fits a 63-char label.
    let max_body = DNS_LABEL_MAX - suffix.len() - 1;
    let mut body: String = body.chars().take(max_body).collect();
    while body.ends_with('-') {
        body.pop();
    }
    if body.is_empty() {
        // The ident was entirely out-of-charset: a stable alphanumeric-led name.
        format!("x-{suffix}")
    } else {
        format!("{body}-{suffix}")
    }
}

/// The DNS-safe k8s object name for a **generic (stateless) workload** replica — the
/// Deployment + its routing Service share it, and it is the endpoint host the gateway
/// routes to. Derived from the project-qualified [`compute_instance_id`] (so two
/// projects' same-named workloads never collide) through [`dns_safe_name`] (so an
/// underscore / over-long instance id still names a valid object).
pub fn workload_object_name(project: &str, workload: &str, replica: u32) -> String {
    dns_safe_name(&compute_instance_id(project, workload, replica))
}

// ---------------------------------------------------------------------------
// Shared pod-spec helpers
// ---------------------------------------------------------------------------

/// The `imagePullSecrets` for a pod — one [`LocalObjectReference`] naming the configured
/// pull secret, or `None` for a public/anonymous pull.
fn image_pull_secrets(ctx: &PlanContext) -> Option<Vec<LocalObjectReference>> {
    ctx.image_pull_secret
        .as_ref()
        .map(|name| vec![LocalObjectReference { name: name.clone() }])
}

/// The spec's env map as the k8s `EnvVar` list (stable order from the `BTreeMap`).
fn env_vars(spec: &ComputeSpec) -> Option<Vec<EnvVar>> {
    let env: Vec<EnvVar> = spec
        .env
        .iter()
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..Default::default()
        })
        .collect();
    (!env.is_empty()).then_some(env)
}

/// A hardened **container** `SecurityContext` applied to every launched container — the
/// k8s-native equivalent of the docker/container shared-kernel baseline (`boatramp-docker`
/// sets `no-new-privileges:true` + `cap_drop: ALL` + the allowlisted `cap_add`): deny
/// privilege escalation, drop every Linux capability (adding back only the spec's
/// explicitly-allowlisted `cap_add` — honored only under the single-tenant posture, the
/// only posture that ever reaches this shared-kernel backend), and pin the runtime's
/// default seccomp profile. `readOnlyRootFilesystem` is intentionally NOT forced here: a
/// stock DB/operand image writes to its root fs outside the data volume (`/var/run/...`,
/// `/tmp`), so a blanket read-only root would break bring-up without per-image writable
/// `emptyDir` mounts — a documented hardening follow-up, not forced in this cut.
fn hardened_security_context(spec: &ComputeSpec) -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            // Add back only the explicitly-allowlisted caps (empty by default); mirrors
            // the docker backend's `cap_add` escape hatch for the single-tenant posture.
            add: (!spec.cap_add.is_empty()).then(|| spec.cap_add.clone()),
        }),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The pod security context derived from a numeric `spec.user` (`uid[:gid]`), or `None`
/// for an image username / unset (the pod then runs as the image's own user).
fn pod_security_context(spec: &ComputeSpec) -> Option<PodSecurityContext> {
    spec.user
        .as_deref()
        .and_then(parse_uid_gid)
        .map(|(u, g)| PodSecurityContext {
            run_as_user: Some(i64::from(u)),
            run_as_group: Some(i64::from(g)),
            fs_group: Some(i64::from(g)),
            ..Default::default()
        })
}

// ---------------------------------------------------------------------------
// Phase 2: generic stateless Deployment
// ---------------------------------------------------------------------------

/// The typed objects for one **generic (stateless) workload** replica: a `Deployment`
/// (one replica — the boatramp control plane drives per-ordinal launches, same as the
/// docker/container backends run one container per replica) and a ClusterIP `Service`
/// fronting it (a stable name/VIP the gateway routes to, since a Deployment's pod IP is
/// ephemeral). No PVC — a workload that declares volumes takes the stateful
/// ([`managed_db_plan`]) path instead.
#[derive(Debug, Clone, PartialEq)]
pub struct DeploymentPlan {
    /// The one-replica Deployment running the pulled image.
    pub deployment: Deployment,
    /// The ClusterIP Service fronting it (the routable endpoint host).
    pub service: Service,
}

/// Build the generic stateless [`DeploymentPlan`]. `ctx.workload` MUST already be the
/// DNS-safe object name ([`workload_object_name`]). Pure: no I/O. Requires an
/// [`RootSource::Image`] (the kubelet pulls it) and refuses a volume-bearing spec (that
/// is the stateful StatefulSet case).
pub fn deployment_plan(ctx: &PlanContext, spec: &ComputeSpec) -> Result<DeploymentPlan, PlanError> {
    if !is_dns1123_label(&ctx.workload) {
        return Err(PlanError::InvalidName(ctx.workload.clone()));
    }
    match &spec.root {
        RootSource::Image(_) => {}
        RootSource::Tar(_) => return Err(PlanError::NonImageRoot("tar rootfs")),
        RootSource::Rootfs(_) => return Err(PlanError::NonImageRoot("rootfs image")),
    }
    // A stateless Deployment backs no persistent volume — a volume-bearing spec is the
    // stateful case ([`managed_db_plan`]), routed there by the backend.
    if !spec.volumes.is_empty() {
        return Err(PlanError::VolumeCount(spec.volumes.len()));
    }
    let image = spec.root.as_str().to_string();

    let container = Container {
        name: "app".to_string(),
        image: Some(image),
        command: (!spec.entrypoint.is_empty()).then(|| spec.entrypoint.clone()),
        env: env_vars(spec),
        ports: Some(vec![ContainerPort {
            container_port: i32::from(spec.port),
            name: Some("app".to_string()),
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }]),
        // A TCP readiness probe on the app port drives the Deployment's
        // `availableReplicas` (what `health` reads) off the app actually accepting
        // connections, not merely the container starting.
        readiness_probe: Some(Probe {
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(i32::from(spec.port)),
                ..Default::default()
            }),
            period_seconds: Some(10),
            ..Default::default()
        }),
        security_context: Some(hardened_security_context(spec)),
        ..Default::default()
    };

    let pod = PodSpec {
        containers: vec![container],
        security_context: pod_security_context(spec),
        image_pull_secrets: image_pull_secrets(ctx),
        // A generic workload pod never calls the k8s API — do not auto-mount the default
        // ServiceAccount token (no unnecessary apiserver reach from a workload image).
        automount_service_account_token: Some(false),
        ..Default::default()
    };

    let deployment = Deployment {
        metadata: object_meta(ctx.workload.clone(), ctx),
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(selector_labels(&ctx.workload)),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(selector_labels(&ctx.workload)),
                    ..Default::default()
                }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let service = Service {
        metadata: object_meta(ctx.workload.clone(), ctx),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_string()),
            selector: Some(selector_labels(&ctx.workload)),
            ports: Some(vec![ServicePort {
                name: Some("app".to_string()),
                port: i32::from(spec.port),
                target_port: Some(IntOrString::Int(i32::from(spec.port))),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(DeploymentPlan {
        deployment,
        service,
    })
}

// ---------------------------------------------------------------------------
// Phase 2: exec / logs request construction (pure)
// ---------------------------------------------------------------------------

/// The container name every boatramp pod runs its app under — `db` for a stateful
/// managed workload, `app` for a generic one. `exec`/`logs` must target it explicitly,
/// since a pod with a single container still needs the name once sidecars are possible.
pub fn pod_container_name(stateful: bool) -> &'static str {
    if stateful { "db" } else { "app" }
}

/// Build the [`kube::api::AttachParams`] for an `exec` into a workload pod: attach stdout
/// and stderr always, stdin only when there is input to feed, no TTY (so stdout/stderr
/// stay separable), targeting the named container.
pub fn exec_attach_params(container: &str, has_stdin: bool) -> kube::api::AttachParams {
    let mut ap = kube::api::AttachParams::default()
        .container(container)
        .stdin(has_stdin)
        .stdout(true)
        .stderr(true)
        .tty(false);
    // Roomier internal pipes than the 1 KiB default so a chatty command does not stall
    // the ws pump between drains (the caller still drains stdout/stderr concurrently).
    ap.max_stdout_buf_size = Some(64 * 1024);
    ap.max_stderr_buf_size = Some(64 * 1024);
    ap.max_stdin_buf_size = Some(64 * 1024);
    ap
}

/// Build the [`kube::api::LogParams`] for streaming (or tailing) a workload pod's logs,
/// targeting the named container. `tail_lines` bounds the backlog (`None` ⇒ from the
/// container start); `follow` streams new lines as they arrive.
pub fn log_params(container: &str, follow: bool, tail_lines: Option<i64>) -> kube::api::LogParams {
    kube::api::LogParams {
        container: Some(container.to_string()),
        follow,
        tail_lines,
        ..Default::default()
    }
}

/// Extract a command's exit code from the Kubernetes `Status` the exec subresource sends
/// when the remote command finishes (the `k8s-openapi` metav1 `Status` kube's
/// `AttachedProcess::take_status` yields):
/// - a `"Success"` status ⇒ `0`;
/// - a `"Failure"` status carries the real code in a `details.causes[reason="ExitCode"]`
///   whose `message` is the decimal code (the k8s remotecommand convention) ⇒ that code,
///   or `1` for a failure with no explicit `ExitCode` cause;
/// - no status delivered (`None`) ⇒ `0` (the command ran and the channel closed cleanly;
///   mirrors the docker backend defaulting an unknown status to `0`).
pub fn exec_exit_code(
    status: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>,
) -> i32 {
    match status {
        None => 0,
        Some(s) if s.status.as_deref() == Some("Success") => 0,
        Some(s) => s
            .details
            .as_ref()
            .and_then(|d| d.causes.as_ref())
            .and_then(|causes| {
                causes
                    .iter()
                    .find(|c| c.reason.as_deref() == Some("ExitCode"))
            })
            .and_then(|c| c.message.as_deref())
            .and_then(|m| m.parse::<i32>().ok())
            .unwrap_or(1),
    }
}

// ---------------------------------------------------------------------------
// Phase 2: PVC volume management (listing / removal selectors)
// ---------------------------------------------------------------------------

/// The label selector every boatramp-managed object carries
/// (`app.kubernetes.io/managed-by=boatramp`) — the `labelSelector` the backend lists
/// PVCs (and other managed objects) with, so a listing never sweeps in a foreign PVC.
pub fn managed_label_selector() -> String {
    format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}")
}

/// Parse a Kubernetes storage [`Quantity`] (e.g. `"20480Mi"`, `"1Gi"`, `"512M"`,
/// `"1073741824"`) into bytes, for a `list_volumes` size. Supports the binary (`Ki`/`Mi`/
/// `Gi`/`Ti`/`Pi`/`Ei`) and decimal (`k`/`M`/`G`/`T`/`P`/`E`) suffixes k8s uses; an
/// unrecognized form yields `None`. This is the REQUESTED capacity (the PVC's
/// `resources.requests.storage`), not live usage — the core API exposes no per-PVC
/// consumed-bytes figure.
pub fn quantity_to_bytes(q: &str) -> Option<u64> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    let (num, mult): (&str, u128) = if let Some(n) = q.strip_suffix("Ki") {
        (n, 1 << 10)
    } else if let Some(n) = q.strip_suffix("Mi") {
        (n, 1 << 20)
    } else if let Some(n) = q.strip_suffix("Gi") {
        (n, 1 << 30)
    } else if let Some(n) = q.strip_suffix("Ti") {
        (n, 1u128 << 40)
    } else if let Some(n) = q.strip_suffix("Pi") {
        (n, 1u128 << 50)
    } else if let Some(n) = q.strip_suffix("Ei") {
        (n, 1u128 << 60)
    } else if let Some(n) = q.strip_suffix('k') {
        (n, 1_000)
    } else if let Some(n) = q.strip_suffix('M') {
        (n, 1_000_000)
    } else if let Some(n) = q.strip_suffix('G') {
        (n, 1_000_000_000)
    } else if let Some(n) = q.strip_suffix('T') {
        (n, 1_000_000_000_000)
    } else if let Some(n) = q.strip_suffix('P') {
        (n, 1_000_000_000_000_000)
    } else if let Some(n) = q.strip_suffix('E') {
        (n, 1_000_000_000_000_000_000)
    } else {
        (q, 1)
    };
    let value: u128 = num.trim().parse().ok()?;
    u64::try_from(value.saturating_mul(mult)).ok()
}

/// The workload a managed-DB [`compute_volume_scope`](boatramp_core::compute::compute_volume_scope)
/// names, for mapping a reaper `remove_scoped_volume(scope)` back to the PVC
/// (`data-<workload>`). The scope is `<workload>` (default project) or `<project>@<workload>`
/// (the `@` join is injective + outside the resource-slug charset), so the workload is the
/// part after any `@`.
pub fn workload_from_scope(scope: &str) -> &str {
    match scope.split_once('@') {
        Some((_project, workload)) => workload,
        None => scope,
    }
}

// ---------------------------------------------------------------------------
// Phase 2: VolumeSnapshot (CSI) snapshot / restore
// ---------------------------------------------------------------------------

/// The CSI VolumeSnapshot API group boatramp's snapshot/restore objects live in (a CRD,
/// not a built-in `k8s-openapi` type — so the objects are modelled here).
pub const SNAPSHOT_API_GROUP: &str = "snapshot.storage.k8s.io";
/// The CSI VolumeSnapshot API version.
pub const SNAPSHOT_API_VERSION: &str = "v1";

/// A CSI `VolumeSnapshot` (`snapshot.storage.k8s.io/v1`) — modelled here because it is a
/// CRD with no `k8s-openapi` type. Serializes to the exact object the apiserver accepts;
/// the backend applies it (dynamically) ONLY when a `VolumeSnapshotClass` is configured
/// and the StorageClass's CSI driver supports snapshots — else snapshot/restore is a
/// clean "unsupported".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VolumeSnapshot {
    /// `snapshot.storage.k8s.io/v1`.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// `VolumeSnapshot`.
    pub kind: String,
    /// Name + namespace + labels.
    pub metadata: ObjectMeta,
    /// The source PVC + the snapshot class.
    pub spec: VolumeSnapshotSpec,
}

/// A [`VolumeSnapshot`]'s spec: the source PVC and the class to snapshot it under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VolumeSnapshotSpec {
    /// What to snapshot (the PVC backing the workload's data).
    pub source: VolumeSnapshotSource,
    /// The `VolumeSnapshotClass` (selects the CSI driver's snapshot parameters).
    #[serde(
        rename = "volumeSnapshotClassName",
        skip_serializing_if = "Option::is_none"
    )]
    pub volume_snapshot_class_name: Option<String>,
}

/// The source of a [`VolumeSnapshot`] — a PVC in the same namespace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VolumeSnapshotSource {
    /// The name of the PVC to snapshot.
    #[serde(rename = "persistentVolumeClaimName")]
    pub persistent_volume_claim_name: String,
}

/// Build the [`VolumeSnapshot`] object that snapshots `pvc` under `class`, named
/// `snapshot_name`, in the context's namespace + carrying the managed-by label.
pub fn volume_snapshot(
    ctx: &PlanContext,
    snapshot_name: &str,
    pvc: &str,
    class: Option<&str>,
) -> VolumeSnapshot {
    VolumeSnapshot {
        api_version: format!("{SNAPSHOT_API_GROUP}/{SNAPSHOT_API_VERSION}"),
        kind: "VolumeSnapshot".to_string(),
        metadata: object_meta(snapshot_name.to_string(), ctx),
        spec: VolumeSnapshotSpec {
            source: VolumeSnapshotSource {
                persistent_volume_claim_name: pvc.to_string(),
            },
            volume_snapshot_class_name: class.map(str::to_string),
        },
    }
}

/// Build a `PersistentVolumeClaim` **restored from** a [`VolumeSnapshot`]: a new PVC whose
/// `spec.dataSource` references the snapshot (the CSI driver rehydrates its contents on
/// first bind). Sized from `size_mib` (must be ≥ the snapshot's restore size), RWO, on the
/// configured/default StorageClass — the shape a `db restore`/clone-from-backup binds.
pub fn restore_pvc_from_snapshot(
    ctx: &PlanContext,
    pvc_name: &str,
    snapshot_name: &str,
    size_mib: u32,
) -> PersistentVolumeClaim {
    PersistentVolumeClaim {
        metadata: object_meta(pvc_name.to_string(), ctx),
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_string(),
                    Quantity(format!("{size_mib}Mi")),
                )])),
                ..Default::default()
            }),
            storage_class_name: ctx.storage_class.clone(),
            data_source: Some(TypedLocalObjectReference {
                api_group: Some(SNAPSHOT_API_GROUP.to_string()),
                kind: "VolumeSnapshot".to_string(),
                name: snapshot_name.to_string(),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Parse a `ComputeSpec.user` (`"uid"` or `"uid:gid"`, numeric) into `(uid, gid)`,
/// defaulting `gid` to `uid`. `None` for a non-numeric value (an image username) — the
/// pod then runs as the image's own user (no explicit security context). Mirrors the
/// docker backend's `parse_uid_gid`.
fn parse_uid_gid(user: &str) -> Option<(u32, u32)> {
    match user.split_once(':') {
        Some((u, g)) => Some((u.parse().ok()?, g.parse().ok()?)),
        None => {
            let uid: u32 = user.parse().ok()?;
            Some((uid, uid))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::{ManagedDbEngine, managed_db_spec};

    fn ctx(workload: &str) -> PlanContext {
        PlanContext {
            project: "default".to_string(),
            workload: workload.to_string(),
            replica: 0,
            namespace: "boatramp".to_string(),
            storage_class: None,
            image_pull_secret: None,
        }
    }

    #[test]
    fn dns1123_label_validation() {
        assert!(is_dns1123_label("pg"));
        assert!(is_dns1123_label("pg-acme"));
        assert!(is_dns1123_label("pg16-0"));
        // Underscores (a `sanitize_ident` per-tenant name) are NOT valid k8s names.
        assert!(!is_dns1123_label("pg-acme_3f9c"));
        assert!(!is_dns1123_label("-lead"));
        assert!(!is_dns1123_label("trail-"));
        assert!(!is_dns1123_label("UpperCase"));
        assert!(!is_dns1123_label(""));
        assert!(!is_dns1123_label(&"a".repeat(64)));
    }

    #[test]
    fn managed_pg_plan_maps_to_statefulset_service_and_pvc() {
        // The exact spec the auto-registration path builds for a managed Postgres.
        let spec = managed_db_spec(ManagedDbEngine::Postgres, None, 20_480, false);
        let plan = managed_db_plan(&ctx("pg"), &spec).expect("valid plan");

        // --- StatefulSet: stable identity, one replica, the operand image + data mount.
        let sts = &plan.stateful_set;
        assert_eq!(sts.metadata.name.as_deref(), Some("pg"));
        assert_eq!(sts.metadata.namespace.as_deref(), Some("boatramp"));
        let sspec = sts.spec.as_ref().unwrap();
        assert_eq!(sspec.replicas, Some(1));
        assert_eq!(sspec.service_name.as_deref(), Some("pg"));
        // The selector must be the stable boatramp-managed + per-workload labels.
        let sel = sspec.selector.match_labels.as_ref().unwrap();
        assert_eq!(
            sel.get(MANAGED_BY_LABEL).map(String::as_str),
            Some("boatramp")
        );
        assert_eq!(sel.get(WORKLOAD_LABEL).map(String::as_str), Some("pg"));
        // …and the pod template must carry (a superset of) the selector labels.
        let pod_labels = sts
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .as_ref()
            .unwrap();
        assert_eq!(
            pod_labels.get(WORKLOAD_LABEL).map(String::as_str),
            Some("pg")
        );
        let container = &sspec.template.spec.as_ref().unwrap().containers[0];
        // The operand image is the pgvector default (k8s pulls it).
        assert_eq!(container.image.as_deref(), Some("pgvector/pgvector:pg16"));
        // The explicit entrypoint rides through as the pod `command`.
        assert_eq!(
            container
                .command
                .as_ref()
                .unwrap()
                .first()
                .map(String::as_str),
            Some("/usr/local/bin/docker-entrypoint.sh")
        );
        // The data volume is mounted at the engine data dir from a PVC-backed pod volume.
        let mount = &container.volume_mounts.as_ref().unwrap()[0];
        assert_eq!(mount.name, "data");
        assert_eq!(mount.mount_path, "/var/lib/postgresql/data");
        let pod_vol = &sspec
            .template
            .spec
            .as_ref()
            .unwrap()
            .volumes
            .as_ref()
            .unwrap()[0];
        assert_eq!(
            pod_vol.persistent_volume_claim.as_ref().unwrap().claim_name,
            "data-pg"
        );
        // A TCP readiness probe on the DB port drives `readyReplicas`.
        assert_eq!(container.ports.as_ref().unwrap()[0].container_port, 5432);
        assert!(container.readiness_probe.is_some());

        // --- Service: named `pg` (the DNS the sql-shim resolves), ClusterIP, port 5432.
        let svc = &plan.service;
        assert_eq!(svc.metadata.name.as_deref(), Some("pg"));
        let svcspec = svc.spec.as_ref().unwrap();
        assert_eq!(svcspec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(
            svcspec
                .selector
                .as_ref()
                .unwrap()
                .get(WORKLOAD_LABEL)
                .map(String::as_str),
            Some("pg")
        );
        assert_eq!(svcspec.ports.as_ref().unwrap()[0].port, 5432);

        // --- PVC: RWO, sized from the spec, default StorageClass (no name pinned).
        let pvc = &plan.pvc;
        assert_eq!(pvc.metadata.name.as_deref(), Some("data-pg"));
        let pspec = pvc.spec.as_ref().unwrap();
        assert_eq!(
            pspec.access_modes.as_deref(),
            Some(["ReadWriteOnce".to_string()].as_slice())
        );
        assert_eq!(
            pspec
                .resources
                .as_ref()
                .unwrap()
                .requests
                .as_ref()
                .unwrap()
                .get("storage"),
            Some(&Quantity("20480Mi".to_string()))
        );
        assert_eq!(
            pspec.storage_class_name, None,
            "default StorageClass when unset"
        );
    }

    #[test]
    fn pvc_pins_a_configured_storage_class() {
        let spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        let mut c = ctx("pg");
        c.storage_class = Some("fast-ssd".to_string());
        let plan = managed_db_plan(&c, &spec).unwrap();
        assert_eq!(
            plan.pvc.spec.unwrap().storage_class_name.as_deref(),
            Some("fast-ssd")
        );
    }

    #[test]
    fn mysql_plan_uses_its_port_image_and_data_dir() {
        let spec = managed_db_spec(ManagedDbEngine::Mysql, None, 1024, false);
        let plan = managed_db_plan(&ctx("mysql-main"), &spec).unwrap();
        let container = &plan
            .stateful_set
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .containers[0];
        assert_eq!(container.image.as_deref(), Some("mysql:8.0"));
        assert_eq!(
            container.volume_mounts.as_ref().unwrap()[0].mount_path,
            "/var/lib/mysql"
        );
        assert_eq!(plan.service.spec.unwrap().ports.unwrap()[0].port, 3306);
    }

    #[test]
    fn a_custom_operand_image_overrides_the_default() {
        let spec = managed_db_spec(
            ManagedDbEngine::Postgres,
            Some("pgvector/pgvector:pg17"),
            1024,
            false,
        );
        let plan = managed_db_plan(&ctx("pg"), &spec).unwrap();
        let container = &plan
            .stateful_set
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .containers[0];
        assert_eq!(container.image.as_deref(), Some("pgvector/pgvector:pg17"));
    }

    #[test]
    fn a_numeric_user_sets_the_pod_security_context_and_fsgroup() {
        let mut spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        spec.user = Some("999".to_string());
        let plan = managed_db_plan(&ctx("pg"), &spec).unwrap();
        let sc = plan
            .stateful_set
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .security_context
            .expect("numeric user ⇒ pod security context");
        assert_eq!(sc.run_as_user, Some(999));
        assert_eq!(
            sc.fs_group,
            Some(999),
            "fsGroup group-owns the PVC for the rootless DB"
        );
    }

    #[test]
    fn statefulset_pod_is_hardened_and_drops_the_sa_token() {
        // Security-review F2/F3: every launched pod drops privilege escalation + all caps
        // + pins RuntimeDefault seccomp (the docker/container shared-kernel baseline), and
        // does NOT auto-mount the ServiceAccount token (a DB pod never calls the k8s API).
        let spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        let plan = managed_db_plan(&ctx("pg"), &spec).unwrap();
        let pod = plan.stateful_set.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.automount_service_account_token, Some(false));
        let sc = pod.containers[0]
            .security_context
            .as_ref()
            .expect("container security context");
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(
            sc.capabilities.as_ref().unwrap().drop.as_deref(),
            Some(["ALL".to_string()].as_slice())
        );
        assert!(
            sc.capabilities.as_ref().unwrap().add.is_none(),
            "no caps added back by default"
        );
        assert_eq!(
            sc.seccomp_profile.as_ref().unwrap().type_.as_str(),
            "RuntimeDefault"
        );
    }

    #[test]
    fn deployment_pod_is_hardened_and_drops_the_sa_token() {
        let plan = deployment_plan(&ctx("web-0"), &generic_spec()).unwrap();
        let pod = plan.deployment.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.automount_service_account_token, Some(false));
        let sc = pod.containers[0].security_context.as_ref().unwrap();
        assert_eq!(sc.allow_privilege_escalation, Some(false));
        assert_eq!(
            sc.capabilities.as_ref().unwrap().drop.as_deref(),
            Some(["ALL".to_string()].as_slice())
        );
        assert_eq!(
            sc.seccomp_profile.as_ref().unwrap().type_.as_str(),
            "RuntimeDefault"
        );
    }

    #[test]
    fn allowlisted_cap_add_rides_back_onto_the_hardened_container() {
        // The single-tenant posture `cap_add` escape hatch (the only posture that reaches
        // this shared-kernel backend) is honored: dropped-ALL, then the allowlisted caps
        // added back — mirroring the docker backend.
        let mut spec = generic_spec();
        spec.cap_add = vec!["NET_BIND_SERVICE".to_string()];
        let plan = deployment_plan(&ctx("web-0"), &spec).unwrap();
        let sc = plan
            .deployment
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .containers[0]
            .security_context
            .clone()
            .unwrap();
        assert_eq!(
            sc.capabilities.as_ref().unwrap().add.as_deref(),
            Some(["NET_BIND_SERVICE".to_string()].as_slice())
        );
    }

    #[test]
    fn a_non_dns_workload_name_is_refused() {
        // A per-tenant `sanitize_ident` name carries an underscore — invalid as a k8s
        // Service, so the planner fails closed rather than apply an unreachable Service.
        let spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        let err = managed_db_plan(&ctx("pg-acme_3f9c"), &spec).unwrap_err();
        assert!(matches!(err, PlanError::InvalidName(_)));
    }

    #[test]
    fn a_non_image_root_is_refused() {
        let mut spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        spec.root = RootSource::Rootfs("blobhash".to_string());
        assert!(matches!(
            managed_db_plan(&ctx("pg"), &spec).unwrap_err(),
            PlanError::NonImageRoot(_)
        ));
    }

    #[test]
    fn expandable_storage_class_allows_volume_expansion() {
        let sc = expandable_storage_class("boatramp-managed-db", "rancher.io/local-path");
        assert_eq!(sc.metadata.name.as_deref(), Some("boatramp-managed-db"));
        assert_eq!(sc.provisioner, "rancher.io/local-path");
        assert_eq!(sc.allow_volume_expansion, Some(true));
        assert_eq!(
            sc.volume_binding_mode.as_deref(),
            Some("WaitForFirstConsumer")
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2: imagePullSecrets
    // -----------------------------------------------------------------------

    #[test]
    fn a_configured_pull_secret_rides_onto_the_statefulset_pod() {
        let spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        let mut c = ctx("pg");
        c.image_pull_secret = Some("ghcr-cred".to_string());
        let plan = managed_db_plan(&c, &spec).unwrap();
        let secrets = plan
            .stateful_set
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .image_pull_secrets
            .expect("configured pull secret ⇒ imagePullSecrets on the pod");
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "ghcr-cred");
    }

    #[test]
    fn no_pull_secret_leaves_image_pull_secrets_unset() {
        let spec = managed_db_spec(ManagedDbEngine::Postgres, None, 1024, false);
        let plan = managed_db_plan(&ctx("pg"), &spec).unwrap();
        assert!(
            plan.stateful_set
                .spec
                .unwrap()
                .template
                .spec
                .unwrap()
                .image_pull_secrets
                .is_none(),
            "no configured pull secret ⇒ an anonymous pull (no imagePullSecrets)"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2: DNS-safe naming
    // -----------------------------------------------------------------------

    #[test]
    fn dns_safe_name_passes_through_an_already_valid_label() {
        // Already-safe names are byte-identical (stable DNS + no churn).
        for name in [
            "pg",
            "web-0",
            "bramp-db-abcdef0123456789abcdef012",
            "acme-web-0",
        ] {
            assert_eq!(dns_safe_name(name), name, "{name} should pass through");
            assert!(is_dns1123_label(&dns_safe_name(name)));
        }
    }

    #[test]
    fn dns_safe_name_sanitizes_and_hash_disambiguates() {
        // Underscores / uppercase / dots fold to '-', and a hash of the original is
        // appended so the result is a valid label AND injective under sanitization.
        let a = dns_safe_name("Acme_Web.0");
        assert!(is_dns1123_label(&a), "got {a}");
        assert!(a.starts_with("acme-web-0-"), "sanitized body kept: {a}");
        // Two idents that sanitize to the SAME body must NOT collide (the hash differs).
        let x = dns_safe_name("foo_bar");
        let y = dns_safe_name("foo.bar");
        assert_ne!(
            x, y,
            "distinct idents must map to distinct names: {x} vs {y}"
        );
        assert!(is_dns1123_label(&x) && is_dns1123_label(&y));
        // Deterministic across calls (stable object names across relaunch/upgrade).
        assert_eq!(dns_safe_name("foo_bar"), x);
    }

    #[test]
    fn dns_safe_name_shortens_a_long_ident_within_the_label_budget() {
        let long = format!("tenant_{}", "x".repeat(200));
        let name = dns_safe_name(&long);
        assert!(
            name.len() <= DNS_LABEL_MAX,
            "over budget: {} chars",
            name.len()
        );
        assert!(is_dns1123_label(&name), "not a valid label: {name}");
        // Collision-resistant even after truncation: two long idents sharing a 200-char
        // prefix but differing at the tail still map to distinct names.
        let other = format!("tenant_{}y", "x".repeat(199));
        assert_ne!(dns_safe_name(&long), dns_safe_name(&other));
    }

    #[test]
    fn dns_safe_name_handles_an_all_out_of_charset_ident() {
        let name = dns_safe_name("___...");
        assert!(is_dns1123_label(&name), "got {name}");
        assert!(
            name.starts_with("x-"),
            "stable alphanumeric-led fallback: {name}"
        );
    }

    #[test]
    fn workload_object_name_is_dns_safe_and_project_qualified() {
        // Default project keeps the bare instance id (valid label ⇒ unchanged).
        assert_eq!(workload_object_name("default", "web", 0), "web-0");
        // A non-default project qualifies it; an underscore workload still yields a label.
        let n = workload_object_name("acme", "api_v2", 1);
        assert!(is_dns1123_label(&n), "got {n}");
        // Distinct projects never collide on one object name.
        assert_ne!(
            workload_object_name("acme", "web", 0),
            workload_object_name("beta", "web", 0)
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2: generic stateless Deployment
    // -----------------------------------------------------------------------

    fn generic_spec() -> ComputeSpec {
        ComputeSpec {
            version: 1,
            root: RootSource::Image("ghcr.io/acme/app:1.2".to_string()),
            kernel: String::new(),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 256,
            entrypoint: vec!["/app/server".to_string()],
            env: BTreeMap::from([("PORT".to_string(), "8080".to_string())]),
            port: 8080,
            restart: Default::default(),
            startup_grace_secs: 30,
            scale_to_zero: false,
            volumes: Vec::new(),
            writable_root: false,
            cap_add: Vec::new(),
            user: None,
            isolation: Default::default(),
            prefer_backend: None,
            pull_secret: None,
            bindings: Vec::new(),
            post_launch: Vec::new(),
        }
    }

    #[test]
    fn deployment_plan_maps_a_stateless_workload_to_a_deployment_and_service() {
        let mut c = ctx("web-0");
        c.image_pull_secret = Some("ghcr-cred".to_string());
        let plan = deployment_plan(&c, &generic_spec()).expect("valid deployment plan");

        let dep = &plan.deployment;
        assert_eq!(dep.metadata.name.as_deref(), Some("web-0"));
        assert_eq!(dep.metadata.namespace.as_deref(), Some("boatramp"));
        let dspec = dep.spec.as_ref().unwrap();
        assert_eq!(dspec.replicas, Some(1), "one replica per boatramp ordinal");
        assert_eq!(
            dspec
                .selector
                .match_labels
                .as_ref()
                .unwrap()
                .get(WORKLOAD_LABEL)
                .map(String::as_str),
            Some("web-0")
        );
        let pod = dspec.template.spec.as_ref().unwrap();
        let container = &pod.containers[0];
        assert_eq!(container.name, "app");
        assert_eq!(container.image.as_deref(), Some("ghcr.io/acme/app:1.2"));
        assert_eq!(container.command.as_ref().unwrap()[0], "/app/server");
        assert_eq!(container.ports.as_ref().unwrap()[0].container_port, 8080);
        assert!(container.readiness_probe.is_some());
        // The configured pull secret rides onto the generic pod too.
        assert_eq!(
            pod.image_pull_secrets.as_ref().unwrap()[0].name,
            "ghcr-cred"
        );

        // The Service fronts it on the app port (the routable endpoint host).
        let svc = &plan.service;
        assert_eq!(svc.metadata.name.as_deref(), Some("web-0"));
        let svcspec = svc.spec.as_ref().unwrap();
        assert_eq!(svcspec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(svcspec.ports.as_ref().unwrap()[0].port, 8080);
        assert_eq!(
            svcspec
                .selector
                .as_ref()
                .unwrap()
                .get(WORKLOAD_LABEL)
                .map(String::as_str),
            Some("web-0")
        );
    }

    #[test]
    fn deployment_plan_refuses_a_volume_bearing_spec() {
        // A workload that declares a volume is the STATEFUL (StatefulSet) case.
        let mut spec = generic_spec();
        spec.volumes.push(boatramp_core::compute::VolumeRef {
            name: "data".to_string(),
            mount: "/data".to_string(),
            size_mib: 1024,
        });
        assert!(matches!(
            deployment_plan(&ctx("web-0"), &spec).unwrap_err(),
            PlanError::VolumeCount(1)
        ));
    }

    #[test]
    fn deployment_plan_refuses_a_non_image_root() {
        let mut spec = generic_spec();
        spec.root = RootSource::Tar("blob".to_string());
        assert!(matches!(
            deployment_plan(&ctx("web-0"), &spec).unwrap_err(),
            PlanError::NonImageRoot(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Phase 2: exec / logs request construction
    // -----------------------------------------------------------------------

    #[test]
    fn pod_container_name_matches_the_plan() {
        assert_eq!(pod_container_name(true), "db");
        assert_eq!(pod_container_name(false), "app");
    }

    #[test]
    fn exec_attach_params_attach_stdin_only_when_feeding_input() {
        let no_in = exec_attach_params("app", false);
        assert_eq!(no_in.container.as_deref(), Some("app"));
        assert!(!no_in.stdin, "no stdin attach without input");
        assert!(
            no_in.stdout && no_in.stderr,
            "stdout+stderr always attached"
        );
        assert!(!no_in.tty, "no TTY so stdout/stderr stay separable");
        let with_in = exec_attach_params("db", true);
        assert!(with_in.stdin, "stdin attached when input is fed");
    }

    #[test]
    fn log_params_target_the_container_and_tail() {
        let lp = log_params("app", true, Some(200));
        assert_eq!(lp.container.as_deref(), Some("app"));
        assert!(lp.follow);
        assert_eq!(lp.tail_lines, Some(200));
        let all = log_params("db", false, None);
        assert!(!all.follow);
        assert_eq!(all.tail_lines, None, "None ⇒ from the container start");
    }

    #[test]
    fn exec_exit_code_reads_the_remotecommand_status() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Status;
        // Success ⇒ 0.
        let ok: Status = serde_json::from_value(serde_json::json!({
            "status": "Success"
        }))
        .unwrap();
        assert_eq!(exec_exit_code(Some(&ok)), 0);
        // Non-zero exit ⇒ the ExitCode cause's decimal message.
        let fail: Status = serde_json::from_value(serde_json::json!({
            "status": "Failure",
            "reason": "NonZeroExitCode",
            "details": { "causes": [ { "reason": "ExitCode", "message": "3" } ] }
        }))
        .unwrap();
        assert_eq!(exec_exit_code(Some(&fail)), 3);
        // Failure with no ExitCode cause ⇒ 1.
        let bare: Status = serde_json::from_value(serde_json::json!({
            "status": "Failure"
        }))
        .unwrap();
        assert_eq!(exec_exit_code(Some(&bare)), 1);
        // No status delivered ⇒ 0 (command ran, channel closed).
        assert_eq!(exec_exit_code(None), 0);
    }

    // -----------------------------------------------------------------------
    // Phase 2: PVC listing / removal selectors
    // -----------------------------------------------------------------------

    #[test]
    fn managed_label_selector_scopes_to_boatramp() {
        assert_eq!(
            managed_label_selector(),
            "app.kubernetes.io/managed-by=boatramp"
        );
    }

    #[test]
    fn quantity_to_bytes_parses_binary_and_decimal_suffixes() {
        assert_eq!(quantity_to_bytes("20480Mi"), Some(20480 * 1024 * 1024));
        assert_eq!(quantity_to_bytes("1Gi"), Some(1024 * 1024 * 1024));
        assert_eq!(quantity_to_bytes("512M"), Some(512_000_000));
        assert_eq!(quantity_to_bytes("1073741824"), Some(1_073_741_824));
        assert_eq!(quantity_to_bytes("2Ti"), Some(2u64 << 40));
        assert_eq!(quantity_to_bytes("bogus"), None);
        assert_eq!(quantity_to_bytes(""), None);
    }

    #[test]
    fn workload_from_scope_recovers_the_workload() {
        // Default-project scope is the bare workload.
        assert_eq!(workload_from_scope("bramp-db-abc"), "bramp-db-abc");
        // A `<project>@<workload>` scope yields the workload after the injective `@`.
        assert_eq!(workload_from_scope("acme@bramp-db-abc"), "bramp-db-abc");
    }

    // -----------------------------------------------------------------------
    // Phase 2: VolumeSnapshot (CSI)
    // -----------------------------------------------------------------------

    #[test]
    fn volume_snapshot_object_has_the_csi_shape() {
        let snap = volume_snapshot(&ctx("pg"), "pg-backup-1", "data-pg", Some("csi-snapclass"));
        assert_eq!(snap.api_version, "snapshot.storage.k8s.io/v1");
        assert_eq!(snap.kind, "VolumeSnapshot");
        assert_eq!(snap.metadata.name.as_deref(), Some("pg-backup-1"));
        assert_eq!(snap.metadata.namespace.as_deref(), Some("boatramp"));
        assert_eq!(snap.spec.source.persistent_volume_claim_name, "data-pg");
        assert_eq!(
            snap.spec.volume_snapshot_class_name.as_deref(),
            Some("csi-snapclass")
        );
        // It serializes to the exact JSON the apiserver accepts.
        let v = serde_json::to_value(&snap).unwrap();
        assert_eq!(v["apiVersion"], "snapshot.storage.k8s.io/v1");
        assert_eq!(v["spec"]["source"]["persistentVolumeClaimName"], "data-pg");
        assert_eq!(v["spec"]["volumeSnapshotClassName"], "csi-snapclass");
    }

    #[test]
    fn restore_pvc_references_the_snapshot_as_its_datasource() {
        let pvc = restore_pvc_from_snapshot(&ctx("pg"), "data-pg-restored", "pg-backup-1", 20_480);
        let pspec = pvc.spec.unwrap();
        let ds = pspec.data_source.expect("restore PVC has a dataSource");
        assert_eq!(ds.kind, "VolumeSnapshot");
        assert_eq!(ds.api_group.as_deref(), Some("snapshot.storage.k8s.io"));
        assert_eq!(ds.name, "pg-backup-1");
        assert_eq!(
            pspec.resources.unwrap().requests.unwrap().get("storage"),
            Some(&Quantity("20480Mi".to_string()))
        );
    }
}
