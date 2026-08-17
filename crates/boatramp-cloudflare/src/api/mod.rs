//! A native REST client for the Cloudflare deploy — the Workers script-upload
//! API + the container ("cloudchamber") API — so `boatramp deploy --target
//! cloudflare` drives Cloudflare directly, with **no wrangler and no generated
//! artifacts** (matching the S3/GCS/Azure native pattern).
//!
//! Auth + base URL mirror the existing CF clients in boatramp
//! (`boatramp-storage::kv_cloudflare`, `boatramp-acme::cloudflare`): the
//! `client/v4` base with a Bearer API token. Every response is the standard CF
//! envelope (`{ success, errors, result, result_info }`) — including the
//! container API, whose wrangler client models `result`/`result_info` too — so a
//! single [`parse_envelope`] handles all of them.

pub mod models;
pub mod resources;
pub mod workers;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// The Cloudflare v4 API base (same as the other boatramp CF clients).
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A failure talking to the Cloudflare API.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// A transport/HTTP failure (connection, TLS, timeout).
    #[error("cloudflare api network error: {0}")]
    Network(String),
    /// The API returned `success: false` (one or more `{code, message}` errors).
    #[error("cloudflare api error: {0}")]
    Api(String),
    /// The response body could not be decoded to the expected shape.
    #[error("cloudflare api decode error: {0}")]
    Decode(String),
    /// Missing/invalid client configuration (e.g. an unset env var).
    #[error("cloudflare api config error: {0}")]
    Config(String),
}

/// The standard Cloudflare v4 response envelope.
#[derive(serde::Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<EnvelopeError>,
    #[serde(default = "none")]
    result: Option<T>,
}

fn none<T>() -> Option<T> {
    None
}

#[derive(serde::Deserialize)]
struct EnvelopeError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// Parse a Cloudflare v4 envelope into its `result`, or an [`ApiError`]. Pure
/// (no I/O) so the whole success/error/decode contract is unit-tested offline
/// against recorded bodies.
fn parse_envelope<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    let envelope: Envelope<T> = serde_json::from_slice(body).map_err(|e| {
        ApiError::Decode(format!(
            "{e}: {}",
            String::from_utf8_lossy(body)
                .chars()
                .take(400)
                .collect::<String>()
        ))
    })?;
    if !envelope.success {
        let detail = if envelope.errors.is_empty() {
            "success=false with no errors".to_string()
        } else {
            envelope
                .errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; ")
        };
        return Err(ApiError::Api(detail));
    }
    envelope
        .result
        .ok_or_else(|| ApiError::Decode("success=true but no result".into()))
}

/// The reconcile action for a container application: create it, or modify the
/// existing one (identified by id). Pure — decided by matching the desired name
/// against the account's current applications, so the orchestration's
/// create-vs-modify decision is unit-tested without any I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationAction {
    /// No application with this name exists yet — create it.
    Create,
    /// An application with this name exists — modify it (by id) + roll out.
    Modify(String),
}

/// Decide the reconcile action for the desired application `name` given the
/// account's `existing` applications (a redeploy modifies in place; a first
/// deploy creates).
pub fn plan_application(existing: &[models::Application], name: &str) -> ApplicationAction {
    match existing.iter().find(|a| a.name == name) {
        Some(app) => match &app.id {
            Some(id) => ApplicationAction::Modify(id.clone()),
            // An existing app without an id can only be re-created (shouldn't
            // happen — the API always returns an id — but fail safe to create).
            None => ApplicationAction::Create,
        },
        None => ApplicationAction::Create,
    }
}

/// A native Cloudflare API client (Workers + container/cloudchamber API), authed
/// with an account id + API token.
#[derive(Clone)]
pub struct CfApi {
    client: reqwest::Client,
    account_id: String,
    token: String,
}

impl CfApi {
    /// Build a client for the given account id + API token.
    pub fn new(account_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            account_id: account_id.into(),
            token: token.into(),
        }
    }

    /// Build a client from the environment: `CLOUDFLARE_ACCOUNT_ID` +
    /// `CLOUDFLARE_API_TOKEN` (with the legacy `CF_ACCOUNT_ID` / `CF_API_TOKEN`
    /// accepted as fallbacks, matching the KV client).
    pub fn from_env() -> Result<Self, ApiError> {
        let pick = |primary: &str, fallback: &str| {
            std::env::var(primary)
                .or_else(|_| std::env::var(fallback))
                .map_err(|_| ApiError::Config(format!("{primary} (or {fallback}) is not set")))
        };
        Ok(Self::new(
            pick("CLOUDFLARE_ACCOUNT_ID", "CF_ACCOUNT_ID")?,
            pick("CLOUDFLARE_API_TOKEN", "CF_API_TOKEN")?,
        ))
    }

    /// `…/accounts/{account_id}`.
    fn account_base(&self) -> String {
        format!("{API_BASE}/accounts/{}", self.account_id)
    }

    /// `…/accounts/{account_id}/containers` — the container ("cloudchamber") API base.
    fn containers_base(&self) -> String {
        format!("{}/containers", self.account_base())
    }

    /// GET `url` and parse the CF envelope into `T`.
    async fn get<T: DeserializeOwned>(&self, url: String) -> Result<T, ApiError> {
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        let body = resp
            .bytes()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        parse_envelope(&body)
    }

    /// Send `body` as JSON to `url` with `method`, parse the CF envelope into `T`.
    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: String,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .client
            .request(method, &url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        parse_envelope(&bytes)
    }

    // ---- container API: read paths -----------------------------------------

    /// A liveness + **shape probe**: `GET …/containers/me` returns the account's
    /// container defaults/limits. Used to fail loud early if the (pinned,
    /// non-public) container API has drifted or the token lacks the scope.
    pub async fn probe(&self) -> Result<serde_json::Value, ApiError> {
        self.get(format!("{}/me", self.containers_base())).await
    }

    /// List the account's container applications (the reconcile inventory).
    pub async fn list_applications(&self) -> Result<Vec<models::Application>, ApiError> {
        self.get(format!("{}/applications", self.containers_base()))
            .await
    }

    /// Get one container application by id.
    pub async fn get_application(&self, id: &str) -> Result<models::Application, ApiError> {
        self.get(format!("{}/applications/{id}", self.containers_base()))
            .await
    }

    // ---- container API: write paths ----------------------------------------

    /// Create a container application (`POST /applications`).
    pub async fn create_application(
        &self,
        req: &models::CreateApplicationRequest,
    ) -> Result<models::Application, ApiError> {
        self.send(
            reqwest::Method::POST,
            format!("{}/applications", self.containers_base()),
            req,
        )
        .await
    }

    /// Modify an existing container application (`PATCH /applications/{id}`).
    /// Sends the same desired shape as create (name is stable); the platform
    /// applies the diff and bumps the version.
    pub async fn modify_application(
        &self,
        id: &str,
        req: &models::CreateApplicationRequest,
    ) -> Result<models::Application, ApiError> {
        self.send(
            reqwest::Method::PATCH,
            format!("{}/applications/{id}", self.containers_base()),
            req,
        )
        .await
    }

    /// Roll a new version out across an application's instances
    /// (`POST /applications/{id}/rollouts`).
    pub async fn create_rollout(
        &self,
        application_id: &str,
        req: &models::CreateRolloutRequest,
    ) -> Result<serde_json::Value, ApiError> {
        self.send(
            reqwest::Method::POST,
            format!(
                "{}/applications/{application_id}/rollouts",
                self.containers_base()
            ),
            req,
        )
        .await
    }

    /// Mint short-lived image-registry **push** credentials for `domain`
    /// (`POST /registries/{domain}/credentials`) — used to `docker login` +
    /// push the boatramp image to Cloudflare's managed registry.
    pub async fn registry_credentials(
        &self,
        domain: &str,
        req: &models::RegistryCredentialsRequest,
    ) -> Result<models::RegistryCredentials, ApiError> {
        self.send(
            reqwest::Method::POST,
            format!("{}/registries/{domain}/credentials", self.containers_base()),
            req,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_successful_envelope() {
        let body = br#"{"success":true,"errors":[],"messages":[],
            "result":[{"id":"app-1","name":"boatramp","instances":3,"version":2}]}"#;
        let apps: Vec<models::Application> = parse_envelope(body).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id.as_deref(), Some("app-1"));
        assert_eq!(apps[0].name, "boatramp");
        assert_eq!(apps[0].instances, 3);
        assert_eq!(apps[0].version, Some(2));
    }

    #[test]
    fn unknown_fields_are_ignored_forward_tolerant() {
        // The real API returns many more fields; we model only what we read.
        let body = br#"{"success":true,"result":{"id":"a","name":"n","instances":1,
            "created_at":"2026-01-01","scheduling_policy":"default","health":{"x":1}}}"#;
        let app: models::Application = parse_envelope(body).unwrap();
        assert_eq!(app.name, "n");
    }

    #[test]
    fn surfaces_api_errors() {
        let body =
            br#"{"success":false,"errors":[{"code":1000,"message":"bad token"}],"result":null}"#;
        let err = parse_envelope::<Vec<models::Application>>(body).unwrap_err();
        assert!(matches!(err, ApiError::Api(m) if m.contains("1000") && m.contains("bad token")));
    }

    #[test]
    fn success_without_result_is_a_decode_error() {
        let body = br#"{"success":true,"errors":[]}"#;
        let err = parse_envelope::<models::Application>(body).unwrap_err();
        assert!(matches!(err, ApiError::Decode(_)));
    }

    #[test]
    fn non_json_body_is_a_decode_error_with_context() {
        let err =
            parse_envelope::<models::Application>(b"<html>502 Bad Gateway</html>").unwrap_err();
        assert!(matches!(err, ApiError::Decode(m) if m.contains("502")));
    }

    #[test]
    fn reconcile_creates_when_absent_and_modifies_when_present() {
        let existing = vec![
            models::Application {
                id: Some("app-9".into()),
                name: "other".into(),
                instances: 1,
                version: Some(1),
            },
            models::Application {
                id: Some("app-7".into()),
                name: "boatramp".into(),
                instances: 3,
                version: Some(4),
            },
        ];
        assert_eq!(
            plan_application(&existing, "boatramp"),
            ApplicationAction::Modify("app-7".into())
        );
        assert_eq!(
            plan_application(&existing, "brand-new"),
            ApplicationAction::Create
        );
        assert_eq!(plan_application(&[], "boatramp"), ApplicationAction::Create);
    }

    #[test]
    fn create_request_round_trips() {
        let req = models::CreateApplicationRequest {
            name: "boatramp".into(),
            scheduling_policy: "default".into(),
            instances: 1,
            configuration: models::UserDeploymentConfiguration {
                image: "registry.cloudflare.com/acct/boatramp:latest".into(),
                instance_type: Some("standard".into()),
                environment_variables: vec![models::EnvironmentVariable {
                    name: "BOATRAMP_NODE_ID".into(),
                    value: "1".into(),
                }],
                ..Default::default()
            },
            constraints: Some(models::ApplicationConstraints {
                regions: vec!["enam".into()],
                ..Default::default()
            }),
            durable_objects: Some(models::DurableObjectsConfiguration {
                namespace_id: "ns-123".into(),
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        // vcpu/memory omitted (instance_type used); empty cities omitted.
        assert!(!json.contains("vcpu"));
        assert!(!json.contains("cities"));
        assert!(json.contains("\"namespace_id\":\"ns-123\""));
        let back: models::CreateApplicationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }
}
