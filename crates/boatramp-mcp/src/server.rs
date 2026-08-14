//! The MCP tool surface over the boatramp control plane.
//!
//! Every tool takes an optional `instance` (the registered name from `mcp.toml`);
//! with a single instance it may be omitted. Tools shuttle JSON: read tools return
//! the control plane's JSON verbatim, write tools return its confirmation. The
//! surface is a **complete, enumerated** mirror of the control-plane API — there is
//! no generic passthrough tool; every capability (including the destructive and
//! fleet-admin ones) is a named, described tool so calls are legible and auditable.
//! Authorization remains the token's: a tool only succeeds if the presented token
//! is scoped for that action.

use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{tool, tool_router, RoleServer, ServerHandler};

use crate::client::{ControlPlane, CALLER_BEARER};
use crate::registry::Backend;

/// Percent-encode a host for a URL path segment (mirrors the CLI: a wildcard `*`
/// is the only path-unsafe character in a DNS host).
fn host_segment(host: &str) -> String {
    host.replace('*', "%2A")
}

/// Wrap a JSON value as a successful tool result (pretty-printed for the agent).
fn ok_json(value: &serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    )])
}

/// The MCP server: a tool router over a [`Backend`] (one or many control planes).
#[derive(Clone)]
pub struct BoatrampMcp {
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    backend: Arc<dyn Backend>,
}

// ---- tool parameter structs ------------------------------------------------

/// A tool that only needs to pick an instance.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InstanceOnly {
    /// The registered instance name; omit when only one is configured.
    #[serde(default)]
    pub instance: Option<String>,
}

/// A tool scoped to one site.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SiteParams {
    /// The site name.
    pub site: String,
    /// The registered instance name; omit when only one is configured.
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PutSiteConfigParams {
    /// The site name.
    pub site: String,
    /// The full site-config object to store (replaces the current config).
    pub config: serde_json::Value,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ActivateParams {
    /// The site name.
    pub site: String,
    /// The deployment id to make live.
    pub id: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SetAliasParams {
    /// The site name.
    pub site: String,
    /// The alias name (e.g. `staging`, `preview`).
    pub name: String,
    /// The deployment id the alias should point at.
    pub id: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AliasParams {
    /// The site name.
    pub site: String,
    /// The alias name.
    pub name: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TailLogsParams {
    /// The site name.
    pub site: String,
    /// Maximum number of log lines to return (default server-side).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Return only lines after this cursor/sequence (for polling).
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DomainParams {
    /// The site name.
    pub site: String,
    /// The hostname (e.g. `www.example.com`; `*.example.com` for a wildcard).
    pub host: String,
    /// The verification method (`dns` or `http`); server default if omitted.
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DeploymentParams {
    /// The site name.
    pub site: String,
    /// The deployment id.
    pub id: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InvokeFunctionParams {
    /// The function name.
    pub name: String,
    /// The JSON payload to pass to the invocation (optional).
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NamedParams {
    /// The resource name (e.g. a function name).
    pub name: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DlqParams {
    /// The site name.
    pub site: String,
    /// The consumer topic whose dead-letter queue to operate on.
    pub topic: String,
    /// An optional deployment alias to scope the operation.
    #[serde(default)]
    pub alias: Option<String>,
    /// The action: `purge` or `redrive`.
    pub action: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FunctionRollbackParams {
    /// The function name.
    pub name: String,
    /// The version to roll back to.
    pub to: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FunctionAliasParams {
    /// The function name.
    pub name: String,
    /// The alias label (e.g. `stable`, `canary`).
    pub label: String,
    /// The function version the alias points at.
    pub version: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DefineWorkflowParams {
    /// The workflow name.
    pub name: String,
    /// The full workflow definition object (steps/inputs), per the workflow schema.
    pub spec: serde_json::Value,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StartRunParams {
    /// The workflow name.
    pub name: String,
    /// The JSON input to start the run with (optional).
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct MintTokenParams {
    /// A human label recorded in the token's metadata.
    pub label: String,
    /// The roles to grant (e.g. `["admin"]`, or scoped roles).
    pub roles: Vec<String>,
    /// Time-to-live in seconds (omit for the server default).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// A holder (`cnf`) public key to bind the token to (for DPoP); omit for a
    /// plain bearer.
    #[serde(default)]
    pub holder_pubkey: Option<String>,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct TokenIdParams {
    /// The token id (metadata id) to revoke.
    pub id: String,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct NodeParams {
    /// The Raft node id.
    pub node_id: u64,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct JoinTokenParams {
    /// Time-to-live in seconds for the minted join ticket (omit for the default).
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SetDaemonConfigParams {
    /// The full daemon-config object to apply (see get_daemon_config for the shape).
    pub config: serde_json::Value,
    #[serde(default)]
    pub instance: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InvalidateCacheParams {
    /// Specific cache keys to invalidate; omit or empty to invalidate everything.
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub instance: Option<String>,
}

// ---- tools -----------------------------------------------------------------

#[tool_router]
impl BoatrampMcp {
    /// Build the server over a [`Backend`].
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            backend,
        }
    }

    // ── Instance discovery ──

    #[tool(
        description = "List the registered boatramp instances (name + server URL). Call this \
                          first when unsure which instances exist; pass the 'instance' parameter \
                          on later calls when more than one is registered."
    )]
    async fn list_instances(&self) -> Result<CallToolResult, ErrorData> {
        let list: Vec<serde_json::Value> = self
            .backend
            .list()
            .into_iter()
            .map(|(name, url)| serde_json::json!({ "name": name, "server": url }))
            .collect();
        Ok(ok_json(&serde_json::Value::Array(list)))
    }

    // ── Sites + deployments (read) ──

    #[tool(description = "List all sites on the instance.")]
    async fn list_sites(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/sites").await?))
    }

    #[tool(description = "Get a site's stored configuration (routing, access, handlers, domains).")]
    async fn get_site_config(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/config", p.site)).await?,
        ))
    }

    #[tool(description = "List a site's deployment history (current + past deployments).")]
    async fn list_deployments(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/deployments", p.site))
                .await?,
        ))
    }

    #[tool(description = "Show a site's current live deployment (id, age, size).")]
    async fn current_deployment(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/current", p.site)).await?,
        ))
    }

    #[tool(description = "Fetch a specific deployment's manifest by id.")]
    async fn get_deployment(
        &self,
        Parameters(p): Parameters<DeploymentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/deployments/{}", p.site, p.id))
                .await?,
        ))
    }

    // ── Sites + deployments (write) ──

    #[tool(
        description = "Replace a site's stored configuration with the given object. DESTRUCTIVE: \
                          overwrites the current config — fetch it first with get_site_config and \
                          overlay your changes."
    )]
    async fn put_site_config(
        &self,
        Parameters(p): Parameters<PutSiteConfigParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.put(&format!("/api/sites/{}/config", p.site), &p.config)
                .await?,
        ))
    }

    #[tool(
        description = "Make a specific deployment id the live one for a site (activate / roll \
                          forward or back)."
    )]
    async fn activate_deployment(
        &self,
        Parameters(p): Parameters<ActivateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.post(
                &format!("/api/sites/{}/deployments/{}/activate", p.site, p.id),
                None,
            )
            .await?,
        ))
    }

    // ── Aliases ──

    #[tool(description = "List a site's named aliases (name → deployment id).")]
    async fn list_aliases(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/aliases", p.site)).await?,
        ))
    }

    #[tool(description = "Point a named alias (e.g. staging, preview) at a deployment id.")]
    async fn set_alias(
        &self,
        Parameters(p): Parameters<SetAliasParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let body = serde_json::json!({ "id": p.id });
        Ok(ok_json(
            &cp.put(&format!("/api/sites/{}/aliases/{}", p.site, p.name), &body)
                .await?,
        ))
    }

    #[tool(description = "Remove a named alias from a site.")]
    async fn remove_alias(
        &self,
        Parameters(p): Parameters<AliasParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.delete(&format!("/api/sites/{}/aliases/{}", p.site, p.name))
                .await?,
        ))
    }

    // ── Domains ──

    #[tool(description = "List a site's domain-attachment/verification records.")]
    async fn list_domains(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/domain-verifications", p.site))
                .await?,
        ))
    }

    #[tool(
        description = "Start domain-ownership verification for a host on a site (returns the DNS \
                          TXT / HTTP challenge to satisfy)."
    )]
    async fn start_domain_verification(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let mut path = format!(
            "/api/sites/{}/domains/{}/verification",
            p.site,
            host_segment(&p.host)
        );
        if let Some(method) = &p.method {
            path.push_str(&format!("?method={method}"));
        }
        Ok(ok_json(&cp.post(&path, None).await?))
    }

    #[tool(
        description = "Run the ownership check for a pending host; on success the server attaches \
                          it to the site."
    )]
    async fn check_domain_verification(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.post(
                &format!(
                    "/api/sites/{}/domains/{}/verification/check",
                    p.site,
                    host_segment(&p.host)
                ),
                None,
            )
            .await?,
        ))
    }

    #[tool(description = "Detach a host from a site (remove its verification/attachment).")]
    async fn remove_domain(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.delete(&format!(
                "/api/sites/{}/domains/{}/verification",
                p.site,
                host_segment(&p.host)
            ))
            .await?,
        ))
    }

    // ── Observability ──

    #[tool(description = "Tail a site's captured guest stdout/stderr logs.")]
    async fn tail_logs(
        &self,
        Parameters(p): Parameters<TailLogsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let mut path = format!("/api/sites/{}/_boatramp/logs", p.site);
        let mut q = Vec::new();
        if let Some(limit) = p.limit {
            q.push(format!("limit={limit}"));
        }
        if let Some(after) = &p.after {
            q.push(format!("after={after}"));
        }
        if !q.is_empty() {
            path.push('?');
            path.push_str(&q.join("&"));
        }
        Ok(ok_json(&cp.get(&path).await?))
    }

    #[tool(description = "Show a site's handler invocation stats, consumer lag, and dead letters.")]
    async fn handler_stats(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/sites/{}/_boatramp/handlers", p.site))
                .await?,
        ))
    }

    #[tool(
        description = "Purge or redrive a consumer topic's dead-letter queue. action = 'purge' \
                          or 'redrive'."
    )]
    async fn operate_dlq(
        &self,
        Parameters(p): Parameters<DlqParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let mut body = serde_json::json!({ "topic": p.topic, "action": p.action });
        if let Some(alias) = &p.alias {
            body["alias"] = serde_json::Value::String(alias.clone());
        }
        Ok(ok_json(
            &cp.post(&format!("/api/sites/{}/_boatramp/dlq", p.site), Some(&body))
                .await?,
        ))
    }

    // ── Functions ──

    #[tool(
        description = "List the functions the instance runs (handlers/consumers/crons as functions)."
    )]
    async fn list_functions(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/functions").await?))
    }

    #[tool(
        description = "Invoke a function synchronously with an optional JSON payload; returns its \
                          response."
    )]
    async fn invoke_function(
        &self,
        Parameters(p): Parameters<InvokeFunctionParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.post(
                &format!("/api/functions/{}/invoke", p.name),
                p.payload.as_ref(),
            )
            .await?,
        ))
    }

    #[tool(description = "Show a function's metered usage (invocations, compute).")]
    async fn function_usage(
        &self,
        Parameters(p): Parameters<NamedParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/functions/{}/usage", p.name)).await?,
        ))
    }

    // ── Cluster + fleet ──

    #[tool(description = "List the cluster's Raft membership (voters, learners, leader).")]
    async fn cluster_members(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/cluster/members").await?))
    }

    #[tool(description = "Show cluster-managed certificate status (domain + expiry).")]
    async fn cert_status(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/certs").await?))
    }

    #[tool(
        description = "Report orphan deployments and unreferenced blobs that a prune would remove \
                          (read-only report)."
    )]
    async fn prune_report(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/prune").await?))
    }

    #[tool(description = "Verify every stored blob still hashes to its key (integrity scrub).")]
    async fn scrub_blobs(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.post("/api/scrub", None).await?))
    }

    #[tool(
        description = "Report who the configured token authenticates as (roles + capabilities)."
    )]
    async fn whoami(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/auth/whoami").await?))
    }

    #[tool(
        description = "Delete a site entirely (all deployments + config). DESTRUCTIVE and \
                          irreversible."
    )]
    async fn delete_site(
        &self,
        Parameters(p): Parameters<SiteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.delete(&format!("/api/sites/{}", p.site)).await?,
        ))
    }

    // ── Functions (versioning) ──

    #[tool(description = "Roll a function back to a previous version.")]
    async fn rollback_function(
        &self,
        Parameters(p): Parameters<FunctionRollbackParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let body = serde_json::json!({ "to": p.to });
        Ok(ok_json(
            &cp.post(&format!("/api/functions/{}/rollback", p.name), Some(&body))
                .await?,
        ))
    }

    #[tool(
        description = "Point a function alias label (e.g. stable, canary) at a function version."
    )]
    async fn set_function_alias(
        &self,
        Parameters(p): Parameters<FunctionAliasParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let body = serde_json::json!({ "version": p.version });
        Ok(ok_json(
            &cp.put(
                &format!("/api/functions/{}/aliases/{}", p.name, p.label),
                &body,
            )
            .await?,
        ))
    }

    #[tool(description = "List a function's triggers (crons, queue/blob event sources).")]
    async fn list_triggers(
        &self,
        Parameters(p): Parameters<NamedParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/functions/{}/triggers", p.name))
                .await?,
        ))
    }

    // ── Workflows ──

    #[tool(description = "List the declarative function workflows defined on the instance.")]
    async fn list_workflows(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/workflows").await?))
    }

    #[tool(description = "Get a workflow's definition by name.")]
    async fn get_workflow(
        &self,
        Parameters(p): Parameters<NamedParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.get(&format!("/api/workflows/{}", p.name)).await?,
        ))
    }

    #[tool(description = "Create or replace a workflow definition (the full spec object).")]
    async fn define_workflow(
        &self,
        Parameters(p): Parameters<DefineWorkflowParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.put(&format!("/api/workflows/{}", p.name), &p.spec)
                .await?,
        ))
    }

    #[tool(description = "Delete a workflow definition by name.")]
    async fn delete_workflow(
        &self,
        Parameters(p): Parameters<NamedParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.delete(&format!("/api/workflows/{}", p.name)).await?,
        ))
    }

    #[tool(description = "Start a run of a workflow with an optional JSON input.")]
    async fn start_workflow_run(
        &self,
        Parameters(p): Parameters<StartRunParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.post(&format!("/api/workflows/{}/runs", p.name), p.input.as_ref())
                .await?,
        ))
    }

    // ── Compute + cache ──

    #[tool(description = "List the instance's compute workloads (containers/microVMs).")]
    async fn list_compute(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/compute").await?))
    }

    #[tool(
        description = "Invalidate cached responses: specific keys, or everything when keys is \
                          empty."
    )]
    async fn invalidate_cache(
        &self,
        Parameters(p): Parameters<InvalidateCacheParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let body = serde_json::json!({ "keys": p.keys });
        Ok(ok_json(
            &cp.post("/api/cache/invalidate", Some(&body)).await?,
        ))
    }

    // ── Dynamic daemon config ──

    #[tool(description = "Read the live daemon configuration (operational knobs; no restart).")]
    async fn get_daemon_config(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.get("/api/daemon/config").await?))
    }

    #[tool(
        description = "Apply a new daemon configuration (converges live, no restart). Fetch the \
                          current one with get_daemon_config and overlay your changes."
    )]
    async fn set_daemon_config(
        &self,
        Parameters(p): Parameters<SetDaemonConfigParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.put("/api/daemon/config", &p.config).await?))
    }

    #[tool(description = "Roll the daemon configuration back to the previous generation.")]
    async fn rollback_daemon_config(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(
            &cp.post("/api/daemon/config/rollback", None).await?,
        ))
    }

    // ── Tokens ──

    #[tool(
        description = "Mint a control-plane API token with the given roles. Returned once — \
                          record it. DESTRUCTIVE in the sense that it grants standing access."
    )]
    async fn mint_token(
        &self,
        Parameters(p): Parameters<MintTokenParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let mut body = serde_json::json!({ "label": p.label, "roles": p.roles });
        if let Some(ttl) = p.ttl_secs {
            body["ttl_secs"] = serde_json::json!(ttl);
        }
        if let Some(holder) = &p.holder_pubkey {
            body["holder_pubkey"] = serde_json::json!(holder);
        }
        Ok(ok_json(&cp.post("/api/tokens", Some(&body)).await?))
    }

    #[tool(description = "Revoke a control-plane token by its metadata id.")]
    async fn revoke_token(
        &self,
        Parameters(p): Parameters<TokenIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.delete(&format!("/api/tokens/{}", p.id)).await?))
    }

    // ── Cluster / fleet administration ──

    #[tool(
        description = "Mint a single-use cluster join ticket (for a new node to join the mesh)."
    )]
    async fn create_join_token(
        &self,
        Parameters(p): Parameters<JoinTokenParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let mut body = serde_json::json!({});
        if let Some(ttl) = p.ttl_secs {
            body["ttl_secs"] = serde_json::json!(ttl);
        }
        Ok(ok_json(
            &cp.post("/api/cluster/join-token", Some(&body)).await?,
        ))
    }

    #[tool(
        description = "Promote a caught-up learner node to a voting member. Fleet-admin; changes \
                          quorum."
    )]
    async fn promote_member(
        &self,
        Parameters(p): Parameters<NodeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let body = serde_json::json!({ "node_id": p.node_id });
        Ok(ok_json(
            &cp.post("/api/cluster/promote", Some(&body)).await?,
        ))
    }

    #[tool(
        description = "Remove a node from the cluster's Raft membership. Fleet-admin; DESTRUCTIVE."
    )]
    async fn revoke_member(
        &self,
        Parameters(p): Parameters<NodeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let body = serde_json::json!({ "node_id": p.node_id });
        Ok(ok_json(&cp.post("/api/cluster/revoke", Some(&body)).await?))
    }

    #[tool(description = "Rotate this node's mesh identity key. Fleet-admin.")]
    async fn rotate_mesh_key(
        &self,
        Parameters(p): Parameters<InstanceOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        Ok(ok_json(&cp.post("/api/cluster/rotate-key", None).await?))
    }
}

impl BoatrampMcp {
    /// Resolve the target control plane, mapping resolution errors into the wire
    /// error the agent sees.
    fn cp(&self, instance: Option<&str>) -> Result<&dyn ControlPlane, ErrorData> {
        Ok(self.backend.resolve(instance)?)
    }
}

// The `ServerHandler` is implemented by hand (rather than via `#[tool_handler]`)
// for one reason: `call_tool` receives the `RequestContext` on the SAME task the
// tool then runs on, so it is the one place we can capture the caller's forwarded
// bearer (injected by rmcp's HTTP transport into the request extensions) into a
// task-local the in-process `LocalControlPlane` reads. On stdio there are no HTTP
// parts, so the bearer is `None` and each `HttpControlPlane` uses its own token.
// `list_tools` / `get_tool` mirror what the macro would generate.
impl ServerHandler for BoatrampMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "boatramp MCP server — drive one or more self-hosted boatramp instances (the \
             streaming-first, single-binary Vercel alternative). Call list_instances first; when \
             more than one instance is registered, pass the 'instance' parameter on every tool \
             call. Typed tools cover sites, deployments, aliases, domains, logs, functions, and \
             cluster/fleet ops. The tool set is a complete, enumerated mirror of the control-plane \
             API (no generic passthrough); write, delete, token, and cluster tools can be \
             DESTRUCTIVE. Authorization is enforced by the presented token's scope.",
        )
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        // Capture the caller's bearer from the HTTP request parts rmcp injected into
        // the request extensions (absent on stdio), for the in-process backend.
        let bearer = context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.headers.get(http::header::AUTHORIZATION))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_string);
        let tcc = ToolCallContext::new(self, request, context);
        CALLER_BEARER
            .scope(bearer, self.tool_router.call(tcc))
            .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tool_router.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift guard for the MCP tool surface: the server mirrors the control-plane API as a
    /// fixed set of typed tools, so an accidental removal, rename, or a tool shipped without a
    /// description (an agent relies on the description + schema to choose a tool) is caught here
    /// rather than surfacing as a silently-shrunken agent capability. `tool_router()` is the
    /// macro-generated static, so this needs no backend. Bump the count deliberately when adding
    /// a tool.
    #[test]
    fn tool_surface_is_pinned_and_well_formed() {
        let router = BoatrampMcp::tool_router();
        let tools = router.list_all();

        assert_eq!(
            tools.len(),
            46,
            "MCP tool count changed to {} — update this count intentionally. Tools: {:?}",
            tools.len(),
            tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>()
        );

        // Every tool must carry a non-empty description (an agent selects tools by it).
        for t in &tools {
            assert!(
                t.description.as_ref().is_some_and(|d| !d.is_empty()),
                "MCP tool `{}` has no description",
                t.name
            );
        }

        // A few load-bearing tools must exist by name — a rename is a breaking API change.
        let names: std::collections::BTreeSet<&str> =
            tools.iter().map(|t| t.name.as_ref()).collect();
        for expected in [
            "list_instances",
            "list_sites",
            "get_site_config",
            "put_site_config",
            "activate_deployment",
        ] {
            assert!(
                names.contains(expected),
                "MCP tool `{expected}` is missing (renamed?) — known tools: {names:?}"
            );
        }
    }
}
