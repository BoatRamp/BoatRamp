//! The **pure** resource planner: a compute spec for a managed database → the typed
//! Kubernetes objects boatramp applies for it (a `StatefulSet` for stable identity, a
//! `Service` named after the workload for the in-cluster DNS the sql-shim/bindings
//! resolve, and a `PersistentVolumeClaim` for the data volume).
//!
//! Everything here is a pure function (spec → objects) with **no I/O** and no cluster
//! contact, so the mapping is fully unit-testable without a cluster — this is where the
//! tests live. The client-side apply/delete/health lives in [`crate`]'s backend impl.

use std::collections::BTreeMap;

use boatramp_core::compute::{ComputeSpec, RootSource};
use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvVar, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PersistentVolumeClaimVolumeSource, PodSecurityContext, PodSpec, PodTemplateSpec, Probe,
    Service, ServicePort, ServiceSpec, TCPSocketAction, Volume, VolumeMount,
    VolumeResourceRequirements,
};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

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
    let env: Vec<EnvVar> = spec
        .env
        .iter()
        .map(|(k, v)| EnvVar {
            name: k.clone(),
            value: Some(v.clone()),
            ..Default::default()
        })
        .collect();
    let container = Container {
        name: "db".to_string(),
        image: Some(image.clone()),
        command: (!spec.entrypoint.is_empty()).then(|| spec.entrypoint.clone()),
        env: (!env.is_empty()).then_some(env),
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
        ..Default::default()
    };

    // A numeric `user` (`uid[:gid]`) becomes the pod security context, and `fsGroup`
    // makes the kubelet group-own the mounted PVC to that gid — the k8s-native
    // equivalent of the docker/native pre-chown so a rootless DB can write its data dir.
    let security_context =
        spec.user
            .as_deref()
            .and_then(parse_uid_gid)
            .map(|(u, g)| PodSecurityContext {
                run_as_user: Some(i64::from(u)),
                run_as_group: Some(i64::from(g)),
                fs_group: Some(i64::from(g)),
                ..Default::default()
            });

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
}
