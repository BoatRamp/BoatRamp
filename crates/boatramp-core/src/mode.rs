//! Deployment mode — the single knob that selects the per-mode coordinator
//! while the guest-facing behavior contract stays identical.
//!
//! Every mode furnishes the same primitive — a **single-writer coordinator** —
//! and that is the *only* thing that fundamentally differs between them:
//!
//! | mode | coordinator | metadata | blobs |
//! | --- | --- | --- | --- |
//! | [`SingleNode`](DeploymentMode::SingleNode) | the process itself | local KV | local fs |
//! | [`Cluster`](DeploymentMode::Cluster) | the Raft leader | embedded Raft | shared s3/R2 |
//! | [`Cloudflare`](DeploymentMode::Cloudflare) | the Raft leader (in Containers) | embedded Raft | R2 |
//!
//! The messaging guarantees (`crate::messaging`) and the `wasi:*` interfaces are
//! identical across all three; a cross-mode conformance suite asserts it.
//! [`Cloudflare`](DeploymentMode::Cloudflare) is **boatramp's cluster mode running
//! on Cloudflare Containers** behind an edge Worker — the same Raft-leader
//! coordinator as self-hosted cluster, not a separate Durable-Object fork — so
//! the only CF-specific piece is the deployment/management layer
//! (see `docs/CLOUDFLARE.md`).

use serde::{Deserialize, Serialize};

/// Which deployment mode a boatramp instance runs in.
///
/// This is config (uniform across targets), not a backend choice: the same
/// commands and manifests apply in every mode, and only the host-side
/// coordinator/backends are selected from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentMode {
    /// The default single binary: zero external dependencies, in-process
    /// everything.
    #[default]
    SingleNode,
    /// N boatramp nodes coordinating among themselves via embedded Raft.
    Cluster,
    /// boatramp's cluster mode running on Cloudflare Containers behind an edge
    /// Worker (same Raft-leader coordinator as [`Cluster`](Self::Cluster)).
    Cloudflare,
}

impl DeploymentMode {
    /// The single-writer coordinator this mode provides — the one piece that
    /// differs across modes. Cloudflare runs the
    /// cluster on Containers, so it shares the cluster's coordinator.
    pub fn coordinator(self) -> &'static str {
        match self {
            Self::SingleNode => "the process itself (in-process mutex)",
            Self::Cluster => "the Raft leader",
            Self::Cloudflare => "the Raft leader (cluster on CF Containers)",
        }
    }

    /// Whether this mode needs boatramp's **managed deployment** layer — a
    /// platform-specific package + orchestration beyond just running the binary.
    /// Single-node and self-hosted cluster are run by starting the boatramp
    /// binary directly; [`Cloudflare`](DeploymentMode::Cloudflare) additionally
    /// needs the container image, the edge Worker, and the CF binding/topology
    /// generation (`boatramp deploy --target cloudflare`). The boatramp binary
    /// itself runs unchanged in either case.
    pub fn needs_managed_deployment(self) -> bool {
        matches!(self, Self::Cloudflare)
    }

    /// The lowercase, kebab-case wire/config name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleNode => "single-node",
            Self::Cluster => "cluster",
            Self::Cloudflare => "cloudflare",
        }
    }
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DeploymentMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "single-node" | "single" => Ok(Self::SingleNode),
            "cluster" => Ok(Self::Cluster),
            "cloudflare" | "cf" => Ok(Self::Cloudflare),
            other => Err(format!(
                "unknown deployment mode `{other}` (expected single-node | cluster | cloudflare)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_str() {
        for mode in [
            DeploymentMode::SingleNode,
            DeploymentMode::Cluster,
            DeploymentMode::Cloudflare,
        ] {
            assert_eq!(mode.as_str().parse::<DeploymentMode>().unwrap(), mode);
        }
    }

    #[test]
    fn default_is_single_node() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::SingleNode);
        assert!(!DeploymentMode::default().needs_managed_deployment());
    }

    #[test]
    fn only_cloudflare_needs_managed_deployment() {
        // Single-node and cluster are run by starting the binary directly;
        // Cloudflare additionally needs the container image + edge Worker + CF
        // bindings (the binary itself runs unchanged, in a Container).
        assert!(!DeploymentMode::SingleNode.needs_managed_deployment());
        assert!(!DeploymentMode::Cluster.needs_managed_deployment());
        assert!(DeploymentMode::Cloudflare.needs_managed_deployment());
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!("kubernetes".parse::<DeploymentMode>().is_err());
    }
}
