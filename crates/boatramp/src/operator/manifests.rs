//! Manifest emitters — `boatramp operator crds` and `operator manifests`.
//!
//! The CRDs are emitted from the Rust types (single-sourced with what the
//! controller reconciles). The install bundle adds the operator's own
//! `ServiceAccount` + a **least-privilege** `ClusterRole`/binding + a `Deployment`
//! that runs *this same binary* as `operator run` — one image, one version. It is
//! the operator-pattern: the bundle installs the operator; the operator does the
//! reconciliation. `operator manifests | kubectl apply -f -` is a helm-less install.

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{Container, PodSpec, PodTemplateSpec, ServiceAccount};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use kube::CustomResourceExt;

use super::crd::{BoatRampCluster, Function, Site};
use super::Result;

/// The operator's default install namespace + `ServiceAccount`/role name.
const NAME: &str = "boatramp-operator";

/// `operator manifests` flags.
#[derive(Debug, clap::Args)]
pub struct ManifestArgs {
    /// Namespace for the operator Deployment + ServiceAccount.
    #[arg(long, default_value = "boatramp-system")]
    namespace: String,
    /// Operator image (the same boatramp image; it runs `operator run`).
    #[arg(long, default_value = "ghcr.io/boatramp/boatramp:latest")]
    image: String,
    /// Operator replicas (leader-elected once K3 lands; 1 is correct until then).
    #[arg(long, default_value_t = 1)]
    replicas: i32,
}

/// Print the three CRDs as YAML, from the Rust definitions.
pub fn print_crds() -> Result<()> {
    for crd in [BoatRampCluster::crd(), Site::crd(), Function::crd()] {
        emit(&crd)?;
    }
    Ok(())
}

/// Print the full install bundle: CRDs + RBAC + operator Deployment.
pub fn print_manifests(args: &ManifestArgs) -> Result<()> {
    print_crds()?;
    emit(&service_account(&args.namespace))?;
    emit(&cluster_role())?;
    emit(&cluster_role_binding(&args.namespace))?;
    emit(&deployment(&args.namespace, &args.image, args.replicas))?;
    Ok(())
}

/// Serialize one object to a YAML document (k8s-openapi emits `apiVersion`/`kind`).
fn emit<T: serde::Serialize>(obj: &T) -> Result<()> {
    println!("---");
    print!("{}", serde_yaml::to_string(obj)?);
    Ok(())
}

/// Common labels for everything the bundle installs.
fn labels() -> std::collections::BTreeMap<String, String> {
    [
        ("app.kubernetes.io/name".to_string(), NAME.to_string()),
        (
            "app.kubernetes.io/managed-by".to_string(),
            "boatramp".to_string(),
        ),
    ]
    .into()
}

fn service_account(namespace: &str) -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels()),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The least-privilege role: full control of the boatramp CRDs + their status, and
/// only the workload/config resources the reconcilers own. **No** cluster-admin.
fn cluster_role() -> ClusterRole {
    let rule = |groups: &[&str], resources: &[&str], verbs: &[&str]| PolicyRule {
        api_groups: Some(
            groups
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        ),
        resources: Some(
            resources
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        ),
        verbs: verbs.iter().map(std::string::ToString::to_string).collect(),
        ..Default::default()
    };
    let all = &[
        "get", "list", "watch", "create", "update", "patch", "delete",
    ];
    ClusterRole {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            labels: Some(labels()),
            ..Default::default()
        },
        rules: Some(vec![
            // The boatramp CRDs + their status subresource.
            rule(
                &["boatramp.dev"],
                &[
                    "boatrampclusters",
                    "boatrampclusters/status",
                    "sites",
                    "sites/status",
                    "functions",
                    "functions/status",
                ],
                all,
            ),
            // The workloads a cluster reconciles into.
            rule(&["apps"], &["statefulsets", "deployments"], all),
            rule(
                &[""],
                &[
                    "services",
                    "configmaps",
                    "secrets",
                    "persistentvolumeclaims",
                ],
                all,
            ),
            rule(&["policy"], &["poddisruptionbudgets"], all),
            // The stateless-mode autoscaler the operator applies.
            rule(&["autoscaling"], &["horizontalpodautoscalers"], all),
            // Read pods (membership/readiness) + emit events.
            rule(&[""], &["pods"], &["get", "list", "watch"]),
            rule(&[""], &["events"], &["create", "patch"]),
        ]),
        ..Default::default()
    }
}

fn cluster_role_binding(namespace: &str) -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            labels: Some(labels()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: NAME.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: NAME.to_string(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    }
}

fn deployment(namespace: &str, image: &str, replicas: i32) -> Deployment {
    Deployment {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(replicas),
            selector: LabelSelector {
                match_labels: Some(labels()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(NAME.to_string()),
                    containers: vec![Container {
                        name: "operator".to_string(),
                        image: Some(image.to_string()),
                        args: Some(vec!["operator".to_string(), "run".to_string()]),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crds_emit_all_three_kinds_as_yaml() {
        // Each CRD serializes with its apiVersion/kind and names its plural — the
        // single-sourced emitter matches the reconciled types.
        for (crd, plural) in [
            (BoatRampCluster::crd(), "boatrampclusters"),
            (Site::crd(), "sites"),
            (Function::crd(), "functions"),
        ] {
            let yaml = serde_yaml::to_string(&crd).unwrap();
            assert!(yaml.contains("kind: CustomResourceDefinition"), "{plural}");
            assert!(yaml.contains("apiextensions.k8s.io/v1"), "{plural}");
            assert!(yaml.contains(plural), "{plural} plural in schema");
            assert!(yaml.contains("boatramp.dev"), "group");
        }
    }

    #[test]
    fn install_bundle_rbac_is_namespaced_and_scoped() {
        let sa = serde_yaml::to_string(&service_account("boatramp-system")).unwrap();
        assert!(sa.contains("kind: ServiceAccount") && sa.contains("boatramp-system"));
        let role = serde_yaml::to_string(&cluster_role()).unwrap();
        assert!(role.contains("boatrampclusters") && role.contains("boatramp.dev"));
        // Least-privilege: never grants the wildcard.
        assert!(!role.contains("'*'") && !role.contains("\"*\""));
        let dep = serde_yaml::to_string(&deployment("boatramp-system", "img:test", 1)).unwrap();
        assert!(dep.contains("kind: Deployment") && dep.contains("img:test"));
        // The operator is the same binary running `operator run`.
        assert!(dep.contains("- operator") && dep.contains("- run"));
    }
}
