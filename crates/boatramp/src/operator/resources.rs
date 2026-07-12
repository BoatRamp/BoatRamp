//! Desired-workload builders: a [`BoatRampCluster`] spec → the Kubernetes objects
//! the operator owns. Pure functions (spec → object), unit-tested here; the
//! reconciler in `controller.rs` server-side-applies whatever these return.
//!
//! - **cluster mode** → a `StatefulSet` (stable identity + per-node `PVC`) + a
//!   headless `Service` (stable DNS) + a client `Service` + a `ConfigMap` +
//!   a `PodDisruptionBudget`.
//! - **stateless mode** → a `Deployment` + a client `Service` + a `ConfigMap` +
//!   an `HorizontalPodAutoscaler`.
//!
//! K2 stands the workloads up; it does **not** wire Raft membership — cluster-mode
//! pods run as standalone servers until K3 adds the `[cluster]` config + the
//! membership reconciler. That split is deliberate (a StatefulSet alone can't do
//! consensus membership — the whole reason the operator exists).

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, RollingUpdateStatefulSetStrategy, StatefulSet,
    StatefulSetPersistentVolumeClaimRetentionPolicy, StatefulSetSpec, StatefulSetUpdateStrategy,
};
use k8s_openapi::api::autoscaling::v2::{
    HorizontalPodAutoscaler, HorizontalPodAutoscalerSpec, CrossVersionObjectReference,
    MetricSpec, ResourceMetricSource, MetricTarget,
};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EnvVar, EnvVarSource,
    HTTPGetAction, ObjectFieldSelector, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PodSpec, PodTemplateSpec, Probe, Service, ServicePort, ServiceSpec, Volume, VolumeMount,
    VolumeResourceRequirements,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Resource;

use super::crd::BoatRampCluster;

/// The control-plane / serving port every boatramp pod listens on.
const PORT: i32 = 8080;
/// Where the config file is mounted, and the data dir.
const CONFIG_MOUNT: &str = "/etc/boatramp";
const DATA_MOUNT: &str = "/data";
/// The operator's own default image (used when the CR doesn't pin one).
const DEFAULT_IMAGE: &str = "ghcr.io/boatramp/boatramp:latest";

/// Selector/identity labels for a cluster's children.
fn labels(name: &str) -> BTreeMap<String, String> {
    [
        ("app.kubernetes.io/name".to_string(), "boatramp".to_string()),
        ("app.kubernetes.io/instance".to_string(), name.to_string()),
        (
            "app.kubernetes.io/managed-by".to_string(),
            "boatramp-operator".to_string(),
        ),
    ]
    .into()
}

/// `ObjectMeta` for a child object: named, namespaced, labelled, and
/// **owned** by the CR (so `kubectl delete brc` garbage-collects it).
fn child_meta(brc: &BoatRampCluster, name: String) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: brc.metadata.namespace.clone(),
        labels: Some(labels(&instance(brc))),
        owner_references: brc.controller_owner_ref(&()).map(|r| vec![r]),
        ..Default::default()
    }
}

/// The CR's name (the instance every child is keyed to). Also the client
/// Service's name — the DNS the operator's membership executor reaches.
pub fn instance(brc: &BoatRampCluster) -> String {
    brc.metadata.name.clone().unwrap_or_else(|| "boatramp".to_string())
}

fn image(brc: &BoatRampCluster) -> String {
    brc.spec.image.clone().unwrap_or_else(|| DEFAULT_IMAGE.to_string())
}

/// The headless service's DNS name (stable per-pod identity in cluster mode).
fn headless_name(brc: &BoatRampCluster) -> String {
    format!("{}-headless", instance(brc))
}

/// The `boatramp.cfg` (RON) rendered into the ConfigMap: bind, data dir, posture.
/// K2 omits `[cluster]` — K3 adds it along with membership.
fn config_ron(brc: &BoatRampCluster) -> String {
    let posture = brc.spec.posture.as_deref().unwrap_or("multi-tenant");
    format!(
        "(\n  \
           serve: (\n    \
             addr: \"0.0.0.0:{PORT}\",\n    \
             data_dir: \"{DATA_MOUNT}\",\n  \
           ),\n  \
           security: ( profile: \"{posture}\" ),\n\
         )\n"
    )
}

pub fn config_map(brc: &BoatRampCluster) -> ConfigMap {
    ConfigMap {
        metadata: child_meta(brc, format!("{}-config", instance(brc))),
        data: Some([("boatramp.cfg".to_string(), config_ron(brc))].into()),
        ..Default::default()
    }
}

/// The headless Service backing StatefulSet pod DNS (`<pod>.<headless>.<ns>.svc`).
pub fn headless_service(brc: &BoatRampCluster) -> Service {
    Service {
        metadata: child_meta(brc, headless_name(brc)),
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
            selector: Some(labels(&instance(brc))),
            ports: Some(vec![port("http", PORT)]),
            publish_not_ready_addresses: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The client Service (stable ClusterIP) for reaching the API / sites.
pub fn client_service(brc: &BoatRampCluster) -> Service {
    Service {
        metadata: child_meta(brc, instance(brc)),
        spec: Some(ServiceSpec {
            selector: Some(labels(&instance(brc))),
            ports: Some(vec![port("http", PORT)]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn port(name: &str, p: i32) -> ServicePort {
    ServicePort {
        name: Some(name.to_string()),
        port: p,
        target_port: Some(IntOrString::Int(p)),
        ..Default::default()
    }
}

/// The pod's container — shared by the StatefulSet and Deployment. Runs
/// `serve --config <mounted cfg>`, probes `/healthz` (liveness) + `/readyz`
/// (readiness), and learns its own pod name via the downward API (for K3).
fn container(brc: &BoatRampCluster) -> Container {
    Container {
        name: "boatramp".to_string(),
        image: Some(image(brc)),
        // The operator controls the image via the CR's `spec.image` (an explicit
        // version), so image changes roll through a pod-spec change, not a re-pull.
        // Own the field explicitly (`IfNotPresent`): otherwise the apiserver's
        // `:latest`-era `Always` default sticks, and a pinned/loaded image (or a
        // `k3d image import`) is needlessly re-pulled.
        image_pull_policy: Some("IfNotPresent".to_string()),
        // Set the entrypoint explicitly so the pod works regardless of whether the
        // image declares one (`args` alone need an image ENTRYPOINT).
        command: Some(vec!["boatramp".to_string()]),
        args: Some(
            ["serve", "--config", &format!("{CONFIG_MOUNT}/boatramp.cfg")]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        ports: Some(vec![ContainerPort {
            name: Some("http".to_string()),
            container_port: PORT,
            ..Default::default()
        }]),
        env: Some(vec![
            // The pod's own name (downward API): the operator's ordinal-0 pod
            // founds the cluster; every other ordinal joins. The node *identity*
            // is still derived from the mesh key — this only designates the founder.
            EnvVar {
                name: "BOATRAMP_POD_NAME".to_string(),
                value_from: Some(EnvVarSource {
                    field_ref: Some(ObjectFieldSelector {
                        field_path: "metadata.name".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // The single-use join ticket the operator's executor rolls into a
            // Secret for joining pods. Optional: absent for the founder / before
            // the first AddLearner.
            {
                let (secret, key) = super::executor::join_env_source(brc);
                EnvVar {
                    name: "BOATRAMP_CLUSTER_JOIN".to_string(),
                    value_from: Some(EnvVarSource {
                        secret_key_ref: Some(k8s_openapi::api::core::v1::SecretKeySelector {
                            name: secret,
                            key: key.to_string(),
                            optional: Some(true),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            },
        ]),
        liveness_probe: Some(http_probe("/healthz")),
        readiness_probe: Some(http_probe("/readyz")),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "config".to_string(),
                mount_path: CONFIG_MOUNT.to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "data".to_string(),
                mount_path: DATA_MOUNT.to_string(),
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn http_probe(path: &str) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.to_string()),
            port: IntOrString::Int(PORT),
            ..Default::default()
        }),
        period_seconds: Some(10),
        ..Default::default()
    }
}

/// The pod template, minus the `data` volume (the StatefulSet supplies a PVC
/// claim template; the Deployment supplies an `emptyDir`).
fn pod_template(brc: &BoatRampCluster, data_volume: Option<Volume>) -> PodTemplateSpec {
    let mut volumes = vec![Volume {
        name: "config".to_string(),
        config_map: Some(ConfigMapVolumeSource {
            name: format!("{}-config", instance(brc)),
            ..Default::default()
        }),
        ..Default::default()
    }];
    volumes.extend(data_volume);
    PodTemplateSpec {
        metadata: Some(ObjectMeta {
            labels: Some(labels(&instance(brc))),
            ..Default::default()
        }),
        spec: Some(PodSpec {
            containers: vec![container(brc)],
            volumes: Some(volumes),
            ..Default::default()
        }),
    }
}

fn selector(brc: &BoatRampCluster) -> LabelSelector {
    LabelSelector {
        match_labels: Some(labels(&instance(brc))),
        ..Default::default()
    }
}

/// The cluster-mode StatefulSet: stable identity + a per-node data PVC.
///
/// `roll_partition` is the `RollingUpdate` partition the operator controls
/// (quorum-aware upgrades, K4): only pods with an ordinal `>=` the partition are
/// updated, so the operator **pauses** the rollout by setting it to `replicas`
/// when the cluster has no quorum margin, and to `0` to let it proceed one pod at
/// a time (highest ordinal first).
pub fn stateful_set(brc: &BoatRampCluster, roll_partition: i32) -> StatefulSet {
    let storage = brc.spec.storage.clone().unwrap_or_else(|| "10Gi".to_string());
    let pvc = PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some("data".to_string()),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some([("storage".to_string(), Quantity(storage))].into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    StatefulSet {
        metadata: child_meta(brc, instance(brc)),
        spec: Some(StatefulSetSpec {
            replicas: Some(brc.spec.replicas as i32),
            service_name: Some(headless_name(brc)),
            selector: selector(brc),
            // The data volume comes from `volume_claim_templates`, not the pod spec.
            template: pod_template(brc, None),
            volume_claim_templates: Some(vec![pvc]),
            // Quorum-aware rolling upgrade: the operator advances/pauses this
            // partition based on the cluster's roll margin (K4).
            update_strategy: Some(StatefulSetUpdateStrategy {
                type_: Some("RollingUpdate".to_string()),
                rolling_update: Some(RollingUpdateStatefulSetStrategy {
                    partition: Some(roll_partition),
                    ..Default::default()
                }),
            }),
            // **Retain** a node's PVC on scale-down or StatefulSet delete — a Raft
            // voter's durable log/state must never be reclaimed automatically (it
            // would lose the vote + data); reclaiming is an explicit operator step.
            persistent_volume_claim_retention_policy: Some(
                StatefulSetPersistentVolumeClaimRetentionPolicy {
                    when_deleted: Some("Retain".to_string()),
                    when_scaled: Some("Retain".to_string()),
                },
            ),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The stateless-mode Deployment: no per-pod identity, an ephemeral data dir
/// (state lives in the shared/replicated KV).
pub fn deployment(brc: &BoatRampCluster) -> Deployment {
    let data = Volume {
        name: "data".to_string(),
        empty_dir: Some(Default::default()),
        ..Default::default()
    };
    Deployment {
        metadata: child_meta(brc, instance(brc)),
        spec: Some(DeploymentSpec {
            replicas: Some(brc.spec.replicas as i32),
            selector: selector(brc),
            template: pod_template(brc, Some(data)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Keep a majority available during voluntary disruptions (cluster mode).
pub fn pod_disruption_budget(brc: &BoatRampCluster) -> PodDisruptionBudget {
    // Tolerate losing a minority: `min_available = floor(n/2) + 1` keeps quorum.
    let min_available = (brc.spec.replicas / 2) + 1;
    PodDisruptionBudget {
        metadata: child_meta(brc, instance(brc)),
        spec: Some(PodDisruptionBudgetSpec {
            min_available: Some(IntOrString::Int(min_available as i32)),
            selector: Some(selector(brc)),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Autoscale the stateless Deployment on CPU (1..=`replicas`×4, target 75%).
pub fn hpa(brc: &BoatRampCluster) -> HorizontalPodAutoscaler {
    HorizontalPodAutoscaler {
        metadata: child_meta(brc, instance(brc)),
        spec: Some(HorizontalPodAutoscalerSpec {
            scale_target_ref: CrossVersionObjectReference {
                api_version: Some("apps/v1".to_string()),
                kind: "Deployment".to_string(),
                name: instance(brc),
            },
            min_replicas: Some(brc.spec.replicas.max(1) as i32),
            max_replicas: (brc.spec.replicas.max(1) * 4) as i32,
            metrics: Some(vec![MetricSpec {
                type_: "Resource".to_string(),
                resource: Some(ResourceMetricSource {
                    name: "cpu".to_string(),
                    target: MetricTarget {
                        type_: "Utilization".to_string(),
                        average_utilization: Some(75),
                        ..Default::default()
                    },
                }),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::crd::{BoatRampClusterSpec, ClusterMode};

    fn cluster(name: &str, mode: ClusterMode, replicas: u32) -> BoatRampCluster {
        let mut brc = BoatRampCluster::new(
            name,
            BoatRampClusterSpec {
                mode,
                replicas,
                image: None,
                storage: None,
                posture: None,
                admin_token_secret: None,
                root_pubkey: None,
            },
        );
        brc.metadata.namespace = Some("tenant-a".to_string());
        brc.metadata.uid = Some("uid-123".to_string());
        brc
    }

    #[test]
    fn statefulset_has_pvc_stable_dns_probes_and_owner_ref() {
        let brc = cluster("db", ClusterMode::Cluster, 3);
        // A paused rollout (partition == replicas) — the operator's K4 knob.
        let sts = stateful_set(&brc, 3);
        let spec = sts.spec.unwrap();
        assert_eq!(spec.replicas, Some(3));
        assert_eq!(spec.service_name.as_deref(), Some("db-headless"));
        // A per-node PVC (the reason cluster mode is a StatefulSet).
        assert_eq!(spec.volume_claim_templates.as_ref().unwrap().len(), 1);
        // K4: the operator-controlled rolling-upgrade partition.
        assert_eq!(
            spec.update_strategy
                .as_ref()
                .and_then(|u| u.rolling_update.as_ref())
                .and_then(|r| r.partition),
            Some(3)
        );
        // K4: a Raft voter's PVC is never auto-reclaimed (data + vote safety).
        let retain = spec.persistent_volume_claim_retention_policy.as_ref().unwrap();
        assert_eq!(retain.when_deleted.as_deref(), Some("Retain"));
        assert_eq!(retain.when_scaled.as_deref(), Some("Retain"));
        // Probes wired to the real endpoints.
        let c = &spec.template.spec.unwrap().containers[0];
        assert_eq!(
            c.liveness_probe.as_ref().unwrap().http_get.as_ref().unwrap().path.as_deref(),
            Some("/healthz")
        );
        assert_eq!(
            c.readiness_probe.as_ref().unwrap().http_get.as_ref().unwrap().path.as_deref(),
            Some("/readyz")
        );
        // Owned by the CR ⇒ garbage-collected with it.
        let owners = sts.metadata.owner_references.unwrap();
        assert_eq!(owners[0].kind, "BoatRampCluster");
        assert_eq!(owners[0].controller, Some(true));
    }

    #[test]
    fn headless_service_is_headless_and_publishes_not_ready() {
        let svc = headless_service(&cluster("db", ClusterMode::Cluster, 3));
        let spec = svc.spec.unwrap();
        assert_eq!(spec.cluster_ip.as_deref(), Some("None"));
        // Pods must resolve before /readyz passes so peers can find each other.
        assert_eq!(spec.publish_not_ready_addresses, Some(true));
    }

    #[test]
    fn pdb_keeps_a_quorum_majority() {
        // 5 nodes → min_available 3 (tolerate losing 2); 3 → 2; 1 → 1.
        for (n, want) in [(1, 1), (3, 2), (5, 3)] {
            let pdb = pod_disruption_budget(&cluster("db", ClusterMode::Cluster, n));
            let min = pdb.spec.unwrap().min_available.unwrap();
            assert_eq!(min, IntOrString::Int(want), "n={n}");
        }
    }

    #[test]
    fn stateless_mode_is_a_deployment_with_hpa_and_ephemeral_data() {
        let brc = cluster("web", ClusterMode::Stateless, 2);
        let dep = deployment(&brc);
        let tspec = dep.spec.unwrap().template.spec.unwrap();
        // No PVC; data is ephemeral (state is in the shared KV).
        let data_vol = tspec
            .volumes
            .unwrap()
            .into_iter()
            .find(|v| v.name == "data")
            .unwrap();
        assert!(data_vol.empty_dir.is_some());
        let hpa = hpa(&brc);
        let hspec = hpa.spec.unwrap();
        assert_eq!(hspec.scale_target_ref.kind, "Deployment");
        assert_eq!(hspec.min_replicas, Some(2));
        assert_eq!(hspec.max_replicas, 8);
    }

    #[test]
    fn config_map_carries_posture_and_bind() {
        let mut brc = cluster("db", ClusterMode::Cluster, 3);
        brc.spec.posture = Some("single-tenant".to_string());
        let cm = config_map(&brc);
        let cfg = &cm.data.unwrap()["boatramp.cfg"];
        assert!(cfg.contains("profile: \"single-tenant\""));
        assert!(cfg.contains("0.0.0.0:8080"));
    }
}
