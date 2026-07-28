//! The MCP tool surface over the boatramp control plane.
//!
//! Every tool takes an optional `instance` (the registered name from `mcp.toml`);
//! with a single instance it may be omitted. Tools shuttle JSON: read tools return
//! the control plane's JSON verbatim, write tools return its confirmation. The
//! generic [`api_request`](BoatrampMcp::api_request) tool reaches **any**
//! control-plane endpoint — the full-scope escape hatch, including destructive
//! operations the typed tools don't wrap.

use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};

use crate::client::ControlPlane;
use crate::registry::InstanceRegistry;

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

/// The MCP server: a tool router over a registry of boatramp control planes.
#[derive(Clone)]
pub struct BoatrampMcp {
    // Held for the derived `Clone` + the `#[tool_handler]`-generated dispatch; the
    // macro reads it, so the dead-code lint's own note calls this out as ignored.
    #[allow(dead_code)]
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    registry: Arc<InstanceRegistry>,
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
pub struct ApiRequestParams {
    /// HTTP method: GET, POST, PUT, or DELETE.
    pub method: String,
    /// The control-plane path, beginning with `/api/…`.
    pub path: String,
    /// An optional JSON request body (for POST/PUT).
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default)]
    pub instance: Option<String>,
}

// ---- tools -----------------------------------------------------------------

#[tool_router]
impl BoatrampMcp {
    /// Build the server over `registry`.
    pub fn new(registry: Arc<InstanceRegistry>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            registry,
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
            .registry
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

    // ── Full-scope escape hatch ──

    #[tool(
        description = "Call ANY control-plane endpoint directly: method (GET/POST/PUT/DELETE), \
                          path (starting with /api/…), and an optional JSON body. Use this for \
                          operations the typed tools don't cover (tokens, cluster promote/revoke, \
                          daemon config, cache invalidation, …). POWERFUL and can be DESTRUCTIVE — \
                          prefer a typed tool when one exists."
    )]
    async fn api_request(
        &self,
        Parameters(p): Parameters<ApiRequestParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cp = self.cp(p.instance.as_deref())?;
        let method = match p.method.to_ascii_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            other => {
                return Err(crate::Error::Invalid(format!("unsupported method '{other}'")).into())
            }
        };
        if !p.path.starts_with('/') {
            return Err(crate::Error::Invalid("path must start with '/'".into()).into());
        }
        Ok(ok_json(&cp.call(method, &p.path, p.body.as_ref()).await?))
    }
}

impl BoatrampMcp {
    /// Resolve the target control plane, mapping resolution errors into the wire
    /// error the agent sees.
    fn cp(&self, instance: Option<&str>) -> Result<&ControlPlane, ErrorData> {
        Ok(self.registry.resolve(instance)?)
    }
}

#[tool_handler]
impl ServerHandler for BoatrampMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "boatramp MCP server — drive one or more self-hosted boatramp instances (the \
             streaming-first, single-binary Vercel alternative). Call list_instances first; when \
             more than one instance is registered, pass the 'instance' parameter on every tool \
             call. Typed tools cover sites, deployments, aliases, domains, logs, functions, and \
             cluster/fleet ops. For anything not wrapped by a typed tool, use api_request to reach \
             any /api/… endpoint directly. Write and api_request tools can be DESTRUCTIVE.",
        )
    }
}
