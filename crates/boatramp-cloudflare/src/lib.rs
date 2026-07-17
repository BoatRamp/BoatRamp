//! The Cloudflare [`ComputeBackend`].
//!
//! Cloudflare Containers run behind an edge Worker and are deployed
//! **declaratively** (a `wrangler.jsonc` `containers` block: `class_name` +
//! `image` + `instances` + `instance_type`), not launched one replica at a time
//! over an API. That mismatch with the per-replica [`ComputeBackend`] contract
//! (launch/stop one ordinal) is handled out-of-band: the live deploy goes
//! through `boatramp cloudflare` (the wrangler generator) + `wrangler deploy`,
//! not through this trait.
//!
//! So what this crate provides *now*, fully validated:
//!   * [`CfContainer`] — the pure, serializable `ComputeSpec` → CF-Container
//!     mapping (class name, image, instance count, instance tier). This is the
//!     exact shape the wrangler `containers` block needs, unit-tested here.
//!   * [`CloudflareBackend`] — the trait impl. `materialize` (record the image
//!     ref) and `health` (a real HTTPS probe of the edge endpoint) are live;
//!     `launch`/`stop` honestly return an explanatory error rather than a
//!     misleading no-op, while [`CloudflareBackend::deploy_plan`] exposes the
//!     mapping a caller would feed to the declarative deploy.
//!
//! Cross-platform (an HTTP client + pure mapping); no Cloudflare creds live in
//! the spec — they belong to the `wrangler` toolchain / `CLOUDFLARE_API_TOKEN`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use boatramp_core::compute::{
    Artifact, BackendError, Capabilities, ComputeBackend, ComputeSpec, Health, Instance,
    InstanceHandle, IsolationClass, LaunchRequest,
};

/// A Cloudflare Containers instance tier. The vCPU/memory envelope is fixed by
/// the platform; we pick the smallest tier that fits the spec
/// (<https://developers.cloudflare.com/containers/> instance types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceType {
    /// 256 MiB / ~1/16 vCPU.
    Dev,
    /// 1 GiB / ~1/4 vCPU.
    Basic,
    /// 4 GiB / ~1/2 vCPU.
    Standard,
}

impl InstanceType {
    /// The wrangler `instance_type` string.
    pub fn as_str(self) -> &'static str {
        match self {
            InstanceType::Dev => "dev",
            InstanceType::Basic => "basic",
            InstanceType::Standard => "standard",
        }
    }

    /// Memory ceiling (MiB) of this tier.
    pub fn mem_mib(self) -> u32 {
        match self {
            InstanceType::Dev => 256,
            InstanceType::Basic => 1024,
            InstanceType::Standard => 4096,
        }
    }

    /// The smallest tier whose memory envelope holds `mem_mib` (saturating to the
    /// largest tier — the platform rejects an over-large request at deploy, which
    /// is the right place to surface it).
    pub fn for_mem(mem_mib: u32) -> InstanceType {
        if mem_mib <= InstanceType::Dev.mem_mib() {
            InstanceType::Dev
        } else if mem_mib <= InstanceType::Basic.mem_mib() {
            InstanceType::Basic
        } else {
            InstanceType::Standard
        }
    }
}

impl std::fmt::Display for InstanceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Cloudflare Durable-Object **class name** for a workload — PascalCase, ASCII
/// alphanumerics only (CF class names are JS identifiers). `"my-app"` →
/// `"BoatrampMyApp"`; an empty/garbage name falls back to `"BoatrampWorkload"`.
pub fn class_name_for(workload: &str) -> String {
    let mut out = String::from("Boatramp");
    let mut upper_next = true;
    for c in workload.chars() {
        if c.is_ascii_alphanumeric() {
            if upper_next {
                out.push(c.to_ascii_uppercase());
                upper_next = false;
            } else {
                out.push(c);
            }
        } else {
            // Any separator (`-`, `_`, space, …) starts a new PascalCase word.
            upper_next = true;
        }
    }
    if out == "Boatramp" {
        out.push_str("Workload");
    }
    out
}

/// The pure `ComputeSpec` → Cloudflare-Container mapping: exactly the fields a
/// wrangler `containers` entry carries. Serializes to the wrangler JSON shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CfContainer {
    /// The Durable-Object class backing the container.
    pub class_name: String,
    /// The OCI image reference the platform pulls.
    pub image: String,
    /// Desired replica count.
    pub instances: u32,
    /// The platform instance tier (cpu/mem envelope).
    pub instance_type: InstanceType,
}

impl CfContainer {
    /// Map a workload's `spec` (at `instances` replicas) to its CF-Container
    /// entry. The image is the spec's `rootfs` (for the CF/docker backends the
    /// `rootfs` field is an OCI image reference, not a blob hash).
    pub fn for_spec(workload: &str, spec: &ComputeSpec, instances: u32) -> CfContainer {
        CfContainer {
            class_name: class_name_for(workload),
            image: spec.rootfs.clone(),
            instances,
            instance_type: InstanceType::for_mem(spec.mem_mib),
        }
    }
}

/// The Cloudflare compute backend: the published edge domain (for health probes)
/// + a reusable HTTP client.
pub struct CloudflareBackend {
    /// The domain the edge Worker is published on (e.g. `app.example.com`); used
    /// to build the health-probe URL.
    domain: String,
    http: reqwest::Client,
}

impl CloudflareBackend {
    /// A backend probing the Worker published at `domain`.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Wrap a pre-built HTTP client (for tests / custom transports).
    pub fn with_client(domain: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            domain: domain.into(),
            http,
        }
    }

    /// The declarative deploy plan for `workload` at `replicas` — the CF-Container
    /// mapping a caller feeds to `boatramp cloudflare` / `wrangler deploy`. This
    /// is what `launch` *would* do if CF exposed a per-replica API; exposed so
    /// the seam is inspectable, not opaque.
    pub fn deploy_plan(&self, workload: &str, spec: &ComputeSpec, replicas: u32) -> CfContainer {
        CfContainer::for_spec(workload, spec, replicas)
    }

    /// The HTTPS health URL for a replica: the `backend_ref` is treated as the
    /// host to probe (falling back to the configured `domain`), so a replica's
    /// own edge hostname can be recorded at deploy time.
    fn health_url(&self, handle: &InstanceHandle) -> String {
        let host = if handle.backend_ref.is_empty() {
            self.domain.as_str()
        } else {
            handle.backend_ref.as_str()
        };
        format!("https://{host}/")
    }
}

#[async_trait]
impl ComputeBackend for CloudflareBackend {
    fn id(&self) -> &'static str {
        "cloudflare"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // A managed platform: strong (multi-tenant safe), idle-scaling, but no
            // mountable persistent volumes through this path.
            isolation: IsolationClass::Platform,
            scale_to_zero: true,
            persistent_volumes: false,
            max_vcpus: None,
            max_mem_mib: Some(InstanceType::Standard.mem_mib()),
        }
    }

    async fn materialize(&self, spec: &ComputeSpec) -> Result<Artifact, BackendError> {
        // For the CF backend the spec's `rootfs` is an OCI image reference the
        // platform pulls; nothing to stage locally.
        if spec.rootfs.is_empty() {
            return Err(BackendError::Materialize(
                "cloudflare backend needs an OCI image reference in spec.rootfs".into(),
            ));
        }
        Ok(Artifact::Image {
            reference: spec.rootfs.clone(),
        })
    }

    async fn launch(&self, req: &LaunchRequest) -> Result<Instance, BackendError> {
        // Cloudflare Containers are deployed declaratively, not per-replica: the
        // whole `containers` block ships via wrangler. Surface that honestly with
        // the plan that *would* be deployed, instead of a fake Instance.
        let plan = self.deploy_plan(&req.workload, &req.spec, req.replica + 1);
        Err(BackendError::Launch(format!(
            "cloudflare deploy is declarative: \
             run `boatramp cloudflare` to emit wrangler.jsonc + `wrangler deploy`. \
             plan: class_name={} image={} instance_type={}",
            plan.class_name,
            plan.image,
            plan.instance_type.as_str(),
        )))
    }

    async fn stop(&self, _handle: &InstanceHandle) -> Result<(), BackendError> {
        // This backend owns no per-replica resource (it never launched one); the
        // declarative deploy is torn down by lowering `instances` / `wrangler
        // delete`. Idempotent no-op, honest because there's nothing to stop.
        Ok(())
    }

    async fn health(&self, handle: &InstanceHandle) -> Result<Health, BackendError> {
        let url = self.health_url(handle);
        match self.http.get(&url).send().await {
            Ok(resp) => {
                let s = resp.status();
                Ok(if s.is_success() || s.is_redirection() {
                    Health::Healthy
                } else {
                    Health::Unhealthy
                })
            }
            // A transport error is indeterminate (DNS/edge blip), not a hard down.
            Err(_) => Ok(Health::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::compute::{IsolationRequirement, RestartPolicy};
    use std::collections::BTreeMap;

    fn spec(mem_mib: u32, image: &str) -> ComputeSpec {
        ComputeSpec {
            version: 1,
            rootfs: image.into(),
            kernel: String::new(),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib,
            entrypoint: vec![],
            env: BTreeMap::new(),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
        }
    }

    #[test]
    fn instance_type_picks_smallest_fitting_tier() {
        assert_eq!(InstanceType::for_mem(128), InstanceType::Dev);
        assert_eq!(InstanceType::for_mem(256), InstanceType::Dev);
        assert_eq!(InstanceType::for_mem(257), InstanceType::Basic);
        assert_eq!(InstanceType::for_mem(1024), InstanceType::Basic);
        assert_eq!(InstanceType::for_mem(1025), InstanceType::Standard);
        assert_eq!(InstanceType::for_mem(64 * 1024), InstanceType::Standard);
        assert_eq!(InstanceType::Basic.as_str(), "basic");
    }

    #[test]
    fn class_name_is_pascal_case_with_prefix() {
        assert_eq!(class_name_for("web"), "BoatrampWeb");
        assert_eq!(class_name_for("my-app"), "BoatrampMyApp");
        assert_eq!(class_name_for("api_v2 service"), "BoatrampApiV2Service");
        assert_eq!(class_name_for(""), "BoatrampWorkload");
        assert_eq!(class_name_for("---"), "BoatrampWorkload");
        // Result is a valid JS identifier (ASCII alphanumeric, leading letter).
        let n = class_name_for("123-go");
        assert!(n.chars().next().unwrap().is_ascii_alphabetic());
        assert!(n.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn cf_container_maps_spec_and_serializes_to_wrangler_shape() {
        let c = CfContainer::for_spec("web", &spec(512, "registry/app:1.2"), 3);
        assert_eq!(c.class_name, "BoatrampWeb");
        assert_eq!(c.image, "registry/app:1.2");
        assert_eq!(c.instances, 3);
        assert_eq!(c.instance_type, InstanceType::Basic);

        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["class_name"], "BoatrampWeb");
        assert_eq!(json["image"], "registry/app:1.2");
        assert_eq!(json["instances"], 3);
        assert_eq!(json["instance_type"], "basic");
    }

    #[test]
    fn capabilities_are_platform_strong_idle_scaling() {
        let caps = CloudflareBackend::new("example.com").capabilities();
        assert_eq!(caps.isolation, IsolationClass::Platform);
        assert!(
            caps.isolation.is_strong(),
            "platform must satisfy untrusted"
        );
        assert!(caps.scale_to_zero);
        assert!(!caps.persistent_volumes);
        assert_eq!(caps.max_mem_mib, Some(4096));
    }

    #[test]
    fn health_url_prefers_ref_then_domain() {
        let b = CloudflareBackend::new("app.example.com");
        let h = |r: &str| InstanceHandle {
            workload: "w".into(),
            replica: 0,
            backend_ref: r.into(),
        };
        assert_eq!(
            b.health_url(&h("r0.example.com")),
            "https://r0.example.com/"
        );
        assert_eq!(b.health_url(&h("")), "https://app.example.com/");
    }

    #[tokio::test]
    async fn materialize_records_image_and_rejects_empty() {
        let b = CloudflareBackend::new("example.com");
        let art = b.materialize(&spec(256, "registry/app:1")).await.unwrap();
        assert_eq!(
            art,
            Artifact::Image {
                reference: "registry/app:1".into()
            }
        );
        assert!(matches!(
            b.materialize(&spec(256, "")).await,
            Err(BackendError::Materialize(_))
        ));
    }

    #[tokio::test]
    async fn launch_is_declarative_and_stop_is_a_noop() {
        let b = CloudflareBackend::new("example.com");
        let s = spec(2048, "registry/app:1");
        // deploy_plan is inspectable: replica 2 ⇒ at least 3 instances, big tier.
        let plan = b.deploy_plan("web", &s, 3);
        assert_eq!(plan.instance_type, InstanceType::Standard);

        let err = b
            .launch(&LaunchRequest {
                workload: "web".into(),
                replica: 2,
                spec: s,
                artifact: Artifact::Image {
                    reference: "registry/app:1".into(),
                },
            })
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("declarative"), "{msg}");
        assert!(msg.contains("BoatrampWeb"), "{msg}");
        assert!(msg.contains("standard"), "{msg}");

        // stop owns nothing → idempotent Ok.
        b.stop(&InstanceHandle {
            workload: "web".into(),
            replica: 2,
            backend_ref: String::new(),
        })
        .await
        .unwrap();
    }
}
