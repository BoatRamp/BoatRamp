//! Types for the Cloudflare **container ("cloudchamber") API**, hand-ported from
//! wrangler's open-source generated client
//! (`cloudflare/workers-sdk`, `packages/containers-shared/src/client/models`,
//! version `1.0.0`). Only the fields boatramp reads/writes are modeled; serde
//! ignores the rest, so the shapes stay small and forward-tolerant.
//!
//! The API is not (yet) in Cloudflare's public OpenAPI/Terraform surface, so
//! these are pinned to the wrangler client — see the crate docs for the drift
//! guard (`CfApi::probe`).

use serde::{Deserialize, Serialize};

/// A container application (the deployed unit — image + instances + placement,
/// bound to a Durable Object namespace). The response of `GET/POST /applications`.
///
/// Only the fields the reconcile path reads are modeled; unknown fields are
/// ignored by serde.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Application {
    /// The application id (present on responses; absent when constructing a
    /// create request — use [`CreateApplicationRequest`] for that).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The application name (unique within the account) — the reconcile key.
    pub name: String,
    /// Desired instance count.
    pub instances: u32,
    /// Monotonic version, bumped on each modify (drives rollouts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

/// The body of `POST /applications` (create) — the desired container app.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateApplicationRequest {
    /// Application name (unique within the account).
    pub name: String,
    /// How instances are scheduled/placed (e.g. `"default"`, `"regional"`).
    pub scheduling_policy: String,
    /// Desired instance count.
    pub instances: u32,
    /// The per-instance deployment configuration (image, size, env, …).
    pub configuration: UserDeploymentConfiguration,
    /// Region/placement constraints (the primary vs learner regions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ApplicationConstraints>,
    /// The Durable Object namespace this app is bound to (its DO class).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_objects: Option<DurableObjectsConfiguration>,
}

/// The per-instance deployment configuration (`configuration` on an application).
/// Modeled to the fields boatramp sets: the image, the size envelope, and the
/// per-node environment (the cluster node config is passed as env).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UserDeploymentConfiguration {
    /// The OCI image reference the platform pulls.
    pub image: String,
    /// A named instance tier (`"dev"`/`"basic"`/`"standard"`); mutually exclusive
    /// with the explicit `vcpu`/`memory_mib` pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
    /// Explicit vCPU allotment (when not using `instance_type`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpu: Option<f64>,
    /// Explicit memory in MiB (when not using `instance_type`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,
    /// Per-instance environment variables (the boatramp node config).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_variables: Vec<EnvironmentVariable>,
}

/// One container environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentVariable {
    /// Variable name.
    pub name: String,
    /// Variable value.
    pub value: String,
}

/// Region/placement constraints for an application (`constraints`). boatramp uses
/// `regions` for the primary/learner region split.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ApplicationConstraints {
    /// The regions the app may be placed in (CF region codes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    /// Specific cities (finer than regions), if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cities: Vec<String>,
}

/// Binds a container application to a Durable Object namespace (its DO class).
/// The namespace id comes from the Worker's DO migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DurableObjectsConfiguration {
    /// The DO namespace id the container app is bound to.
    pub namespace_id: String,
}

/// A rollout request (`POST /applications/{id}/rollouts`) — applies a new version
/// across the app's instances.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateRolloutRequest {
    /// The application version to roll out to.
    pub target_version: u32,
    /// The rollout strategy (e.g. `"rolling"`).
    pub strategy: String,
    /// Optional human description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Request to mint short-lived image-registry **push** credentials
/// (`POST /registries/{domain}/credentials`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryCredentialsRequest {
    /// Requested permissions (e.g. `["push", "pull"]`).
    pub permissions: Vec<String>,
    /// Credential lifetime in minutes.
    pub expiration_minutes: u32,
}

/// The minted registry credentials (response of the credentials endpoint) — a
/// username/password usable for `docker login` against the CF managed registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryCredentials {
    /// The registry username.
    pub username: String,
    /// The short-lived password/token.
    pub password: String,
}
