//! The declarative GraphQL **data connector**: a GraphQL API generated from a managed
//! database.
//!
//! boatramp already runs the site's database as a managed workload and owns the
//! connection, credentials, and per-tenant isolation. This connector turns that database
//! into a GraphQL API with no resolver code: it introspects the schema, generates the
//! GraphQL SDL, and answers each query by compiling it to **one deterministic,
//! parameterized SQL statement** — a *compiler*, never an execution engine. A query it
//! cannot lower is rejected, not partially run; execution happens in the database, which
//! already has correct semantics.
//!
//! It composes with the wasm-resolver model (GraphQL→Wasi) through the federation
//! `SubgraphFetcher` seam, and sits underneath the existing aware-edge (guard, persisted
//! queries, cache). Exposure is deny-by-default and fail-closed — a database-derived API
//! must never leak by default.
//!
//! Landing incrementally: the schema model + SDL generation first, then policy, the query
//! compiler, introspection + serving, relationships, federation, and mutations.
#![allow(dead_code)] // wired into serving by a later landing

pub(crate) mod compile;
pub(crate) mod dialect;
pub(crate) mod introspect;
pub(crate) mod policy;
pub(crate) mod runner;
pub(crate) mod schema;
pub(crate) mod sdl;
/// App-bearer-token claim verification (row_filter claims from a verified app IdP). Needs
/// `oidc` (for `jsonwebtoken`); without it, token claims are simply never sourced (fail-closed).
#[cfg(feature = "oidc")]
pub(crate) mod token;

use boatramp_core::config::HandlerGraphqlDataConfig;
use boatramp_core::sql::SqlValue;
use policy::{Claims, DataPolicy, RowOp, RowPredicate, RowTerm, RowValue, TablePolicy};
use std::collections::BTreeMap;

/// Build the connector's [`DataPolicy`] from a site's `[handlers.graphql.data]` config.
/// Deny-by-default is inherent: only the configured tables/columns become exposed.
pub(crate) fn policy_from_config(cfg: &HandlerGraphqlDataConfig) -> DataPolicy {
    let mut policy = DataPolicy::new();
    for (table, table_cfg) in &cfg.tables {
        let mut table_policy = TablePolicy::columns(table_cfg.columns.iter().cloned());
        if !table_cfg.row_filter.is_empty() {
            table_policy = table_policy.with_rows(RowPredicate {
                terms: table_cfg
                    .row_filter
                    .iter()
                    .map(|term| RowTerm {
                        column: term.column.clone(),
                        op: RowOp::Eq,
                        value: RowValue::Claim(term.claim.clone()),
                    })
                    .collect(),
            });
        }
        for (field, function) in &table_cfg.resolvers {
            table_policy = table_policy.with_resolver(field.clone(), function.clone());
        }
        policy = policy.with_table(table.clone(), table_policy);
    }
    policy
}

/// The request claims a row predicate binds against. The tenant `project` is always available
/// and host-asserted. When the site configures `claims_from_token`, the scalar claims of a
/// **fully verified** application bearer token are merged in beside it — so a `row_filter` can
/// isolate by an app claim (e.g. `tid`). A missing/invalid token contributes nothing (so a
/// filter referencing its claim denies), and the host `project` always wins over any
/// token-supplied `project`, which a token therefore can never spoof.
pub(crate) async fn request_claims(
    project: &str,
    bearer: Option<&str>,
    cfg: &HandlerGraphqlDataConfig,
) -> Claims {
    let mut map = token_claims(cfg, bearer).await;
    map.insert("project".to_string(), SqlValue::Text(project.to_string()));
    Claims::new(map)
}

/// The scalar claims of a verified app token (empty if unconfigured, unverifiable, or the
/// `oidc` feature is off — always fail-closed).
#[cfg(feature = "oidc")]
async fn token_claims(
    cfg: &HandlerGraphqlDataConfig,
    bearer: Option<&str>,
) -> BTreeMap<String, SqlValue> {
    let mut out = BTreeMap::new();
    if let (Some(token_cfg), Some(bearer)) = (&cfg.claims_from_token, bearer) {
        if let Some(claims) = token::verified_claims(token_cfg, bearer).await {
            for (name, value) in &claims {
                if let Some(sql) = scalar_claim(value) {
                    out.insert(name.clone(), sql);
                }
            }
        }
    }
    out
}

#[cfg(not(feature = "oidc"))]
async fn token_claims(
    _cfg: &HandlerGraphqlDataConfig,
    _bearer: Option<&str>,
) -> BTreeMap<String, SqlValue> {
    BTreeMap::new()
}

/// Map a JWT scalar claim to a SQL bind value (arrays/objects/null are not bindable, so a
/// `row_filter` can only bind a scalar claim).
#[cfg(feature = "oidc")]
fn scalar_claim(value: &serde_json::Value) -> Option<SqlValue> {
    match value {
        serde_json::Value::String(s) => Some(SqlValue::Text(s.clone())),
        serde_json::Value::Bool(b) => Some(SqlValue::Boolean(*b)),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(SqlValue::Integer)
            .or_else(|| n.as_f64().map(SqlValue::Real)),
        _ => None,
    }
}

/// Generate the **federation SDL** for a SQL-backed subgraph by introspecting `site`'s
/// managed database and emitting `@key`-typed entities for the exposed tables. Used when
/// registering a SQL subgraph, so an operator never hand-writes SDL.
pub(crate) async fn generate_sql_subgraph_sdl(
    provider: &dyn boatramp_core::sql::SqlBackends,
    project: &str,
    site: &str,
    cfg: &HandlerGraphqlDataConfig,
) -> Result<String, String> {
    let backend = provider
        .database(project, site, &cfg.source)
        .await
        .map_err(|e| format!("opening the `{site}` database: {e}"))?;
    let schema = introspect::introspect_sqlite(backend.as_ref())
        .await
        .map_err(|e| format!("introspecting the `{site}` database: {e}"))?;
    // The SDL exposes only the policy's tables/columns.
    let exposed = policy_from_config(cfg).project_schema(&schema);
    Ok(sdl::generate_federation_sdl(&exposed))
}

#[cfg(all(test, feature = "oidc"))]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn ed_token(key: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = b64url(
            serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid })
                .to_string()
                .as_bytes(),
        );
        let payload = b64url(claims.to_string().as_bytes());
        let signing_input = format!("{header}.{payload}");
        format!(
            "{signing_input}.{}",
            b64url(&key.sign(signing_input.as_bytes()).to_bytes())
        )
    }

    #[tokio::test]
    async fn a_verified_token_claim_merges_but_cannot_spoof_project() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let jwks = serde_json::json!({ "keys": [ {
            "kty": "OKP", "crv": "Ed25519", "kid": "k",
            "x": b64url(key.verifying_key().as_bytes()),
        } ] })
        .to_string();
        std::env::set_var("TEST_GQL_IDP_JWKS_1", &jwks);
        let cfg = HandlerGraphqlDataConfig {
            enabled: true,
            claims_from_token: Some(boatramp_core::config::HandlerGraphqlTokenClaims {
                issuer: "https://idp.test".into(),
                jwks_env: Some("TEST_GQL_IDP_JWKS_1".into()),
                jwks_url: None,
                audience: None,
            }),
            ..Default::default()
        };
        // A token that carries `tid` and *also* tries to claim a different `project`.
        let token = ed_token(
            &key,
            "k",
            serde_json::json!({ "iss": "https://idp.test", "exp": 4_102_444_800_i64, "tid": "acme", "project": "evil" }),
        );
        let claims = request_claims("default", Some(&token), &cfg).await;
        // The app claim merges…
        assert_eq!(claims.get("tid"), Some(&SqlValue::Text("acme".into())));
        // …but the host-asserted project wins — a token can never spoof it.
        assert_eq!(
            claims.get("project"),
            Some(&SqlValue::Text("default".into()))
        );

        // No token → only the host project (fail-closed: `tid` absent, so a filter on it denies).
        let none = request_claims("default", None, &cfg).await;
        assert_eq!(none.get("project"), Some(&SqlValue::Text("default".into())));
        assert_eq!(none.get("tid"), None);

        // An expired token contributes nothing either.
        let expired = ed_token(
            &key,
            "k",
            serde_json::json!({ "iss": "https://idp.test", "exp": 1_000_000_000, "tid": "acme" }),
        );
        assert_eq!(
            request_claims("default", Some(&expired), &cfg)
                .await
                .get("tid"),
            None
        );
    }
}
