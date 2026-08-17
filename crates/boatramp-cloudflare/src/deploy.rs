//! Pure planning for the native Cloudflare deploy: turn resolved inputs (bucket
//! name, D1 id, image ref, regions, the container DO namespace id) into the exact
//! API request shapes — the Worker [`ScriptMetadata`](api::workers::ScriptMetadata)
//! (bindings + DO migration) and the container [`CreateApplicationRequest`]. No
//! I/O, so the whole shape is unit-tested offline; the orchestration in the
//! `boatramp` bin resolves the inputs (ensure resources, build image) then feeds
//! them here.

use crate::api::models::{
    ApplicationConstraints, CreateApplicationRequest, DurableObjectsConfiguration,
    EnvironmentVariable, ModifyApplicationRequest, UserDeploymentConfiguration,
};
use crate::api::workers::{Binding, ContainerRef, Migrations, ScriptMetadata};

/// The DO class the container node runs under (the `Container` = a Durable
/// Object; the Worker's `NODE` binding + the container app both reference it).
pub const NODE_CLASS: &str = "BoatrampNode";
/// The DO class for the edge cache-invalidation coordinator.
pub const CACHE_CLASS: &str = "CacheCoordinator";
/// The Worker script name.
pub const WORKER_NAME: &str = "boatramp";
/// The container application name.
pub const APP_NAME: &str = "boatramp";

/// The Worker bindings for the deploy: R2 (blobs), D1 (`sql`), the two Durable
/// Object namespaces (the container node + the cache coordinator), and the
/// primary-region marker the edge reads. `d1_id` is the database id resolved by
/// ensuring the D1 database. (The control-plane root key is delivered to the
/// container via its app-config environment, not a Worker binding.)
pub fn worker_bindings(r2_bucket: &str, d1_id: &str, primary_region: &str) -> Vec<Binding> {
    vec![
        Binding::R2Bucket {
            name: "BLOBS".into(),
            bucket_name: r2_bucket.into(),
        },
        Binding::D1 {
            name: "SQL".into(),
            id: d1_id.into(),
        },
        Binding::DurableObjectNamespace {
            name: "NODE".into(),
            class_name: NODE_CLASS.into(),
        },
        Binding::DurableObjectNamespace {
            name: "CACHE".into(),
            class_name: CACHE_CLASS.into(),
        },
        Binding::PlainText {
            name: "BOATRAMP_PRIMARY".into(),
            text: primary_region.into(),
        },
    ]
}

/// The Worker script metadata: the given bindings + a first-upload DO migration
/// that creates the node + cache-coordinator DO namespaces (SQLite-backed), under
/// `migration_tag`. `compatibility_date` pins the Workers runtime.
pub fn worker_metadata(
    bindings: Vec<Binding>,
    migration_tag: &str,
    compatibility_date: &str,
) -> ScriptMetadata {
    ScriptMetadata {
        main_module: "shim.mjs".into(),
        bindings,
        // Container-enable the node DO class (the cache coordinator is a plain DO).
        containers: vec![ContainerRef {
            class_name: Some(NODE_CLASS.into()),
            name: None,
        }],
        migrations: Some(Migrations {
            new_tag: migration_tag.into(),
            new_sqlite_classes: vec![NODE_CLASS.into(), CACHE_CLASS.into()],
            ..Default::default()
        }),
        compatibility_date: compatibility_date.into(),
        compatibility_flags: vec![],
    }
}

/// The container-application request: a scale-to-zero app running `image`, capped
/// at `instances`, bound to the node DO namespace `do_namespace_id`, with any
/// per-node config passed as environment (`env`). `instance_type` is the CF
/// instance tier (e.g. `"standard"`). Region placement (`constraints.regions`) is
/// a follow-up — the single instance is placed by the platform.
pub fn application_request(
    image: &str,
    instances: u32,
    instance_type: &str,
    env: Vec<(String, String)>,
    do_namespace_id: &str,
) -> CreateApplicationRequest {
    CreateApplicationRequest {
        name: APP_NAME.into(),
        scheduling_policy: "default".into(),
        // A Durable-Object-backed app scales **on demand per DO id**: the desired
        // `instances` is 0 and `max_instances` caps the total (matches wrangler's
        // apply). `instances` here is the requested cap.
        instances: 0,
        max_instances: Some(instances),
        configuration: UserDeploymentConfiguration {
            image: image.into(),
            instance_type: Some(instance_type.into()),
            environment_variables: env
                .into_iter()
                .map(|(name, value)| EnvironmentVariable { name, value })
                .collect(),
            ..Default::default()
        },
        // `{ tier: 1 }` is the proven-working default — CF places the single
        // instance itself. (Region pinning via `constraints.regions` — upper-cased
        // codes, per wrangler — is a follow-up; the account reported no locations.)
        constraints: Some(ApplicationConstraints {
            tier: Some(1),
            ..Default::default()
        }),
        durable_objects: Some(DurableObjectsConfiguration {
            namespace_id: do_namespace_id.into(),
        }),
    }
}

/// The **modify** body for an existing application, derived from the desired
/// [`CreateApplicationRequest`] — carries the mutable fields (`configuration`,
/// `instances`, `max_instances`, `constraints`, `scheduling_policy`) and drops the
/// create-only ones (`name`, `durable_objects`).
pub fn modify_request(create: &CreateApplicationRequest) -> ModifyApplicationRequest {
    ModifyApplicationRequest {
        instances: create.instances,
        max_instances: create.max_instances,
        configuration: create.configuration.clone(),
        constraints: create.constraints.clone(),
        scheduling_policy: create.scheduling_policy.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_bindings_cover_r2_d1_dos_and_primary() {
        let b = worker_bindings("boatramp-blobs", "d1-uuid", "enam");
        assert_eq!(b.len(), 5);
        assert!(b.contains(&Binding::R2Bucket {
            name: "BLOBS".into(),
            bucket_name: "boatramp-blobs".into()
        }));
        assert!(b.contains(&Binding::D1 {
            name: "SQL".into(),
            id: "d1-uuid".into()
        }));
        assert!(b.contains(&Binding::DurableObjectNamespace {
            name: "NODE".into(),
            class_name: "BoatrampNode".into()
        }));
        assert!(b.contains(&Binding::PlainText {
            name: "BOATRAMP_PRIMARY".into(),
            text: "enam".into()
        }));
    }

    #[test]
    fn metadata_creates_both_do_classes_on_first_upload() {
        let meta = worker_metadata(vec![], "v1", "2025-01-01");
        assert_eq!(meta.main_module, "shim.mjs");
        let m = meta.migrations.unwrap();
        assert!(m.old_tag.is_none(), "first upload has no prior tag");
        assert_eq!(m.new_tag, "v1");
        assert_eq!(m.new_sqlite_classes, vec![NODE_CLASS, CACHE_CLASS]);
    }

    #[test]
    fn application_request_maps_image_instances_regions_env_and_do() {
        let req = application_request(
            "registry.cloudflare.com/acct/boatramp:v1",
            3,
            "standard",
            vec![("BOATRAMP_CLUSTER_INIT".into(), "1".into())],
            "ns-node",
        );
        assert_eq!(req.name, APP_NAME);
        // DO-backed: desired instances 0, cap = the requested count.
        assert_eq!(req.instances, 0);
        assert_eq!(req.max_instances, Some(3));
        assert_eq!(
            req.configuration.image,
            "registry.cloudflare.com/acct/boatramp:v1"
        );
        assert_eq!(req.configuration.instance_type.as_deref(), Some("standard"));
        assert_eq!(req.configuration.environment_variables.len(), 1);
        // The proven-working default constraint is `{ tier: 1 }`.
        assert_eq!(req.constraints.as_ref().unwrap().tier, Some(1));
        assert_eq!(req.durable_objects.unwrap().namespace_id, "ns-node");
    }

    #[test]
    fn modify_request_drops_create_only_fields() {
        let create = application_request("img", 1, "standard", vec![], "ns");
        let modify = modify_request(&create);
        // Modify carries the mutable state, not the create-only DO binding.
        assert_eq!(modify.instances, create.instances);
        assert_eq!(modify.max_instances, create.max_instances);
        assert_eq!(modify.configuration, create.configuration);
        assert_eq!(modify.constraints.unwrap().tier, Some(1));
    }
}
