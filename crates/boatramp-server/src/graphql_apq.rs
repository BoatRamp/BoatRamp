//! GraphQL Automatic Persisted Queries (APQ) + safelist.
//!
//! A client may send a small **query hash** (`extensions.persistedQuery.sha256Hash`)
//! instead of the full query; the edge resolves the hash to the stored query text and
//! hands the full query to the handler, transparently. On a first miss the client
//! re-sends the query alongside the hash and the edge registers it. In **safelist**
//! mode only pre-registered hashes run — the edge never registers a new one — turning
//! APQ into a query allowlist (a security control).
//!
//! This module is the pure policy: parse the intent, verify the hash, and decide the
//! outcome against the (already-fetched) stored query. The async store read/write and
//! the dispatch wiring live in `handler_dispatch`.

use sha2::{Digest, Sha256};

/// The APQ intent parsed from a request body's `extensions.persistedQuery`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ApqRequest {
    /// No `persistedQuery` extension: an ordinary (full-query) request — not APQ.
    None,
    /// A hash with no query: resolve it from the store.
    Lookup { hash: String },
    /// A hash *and* the query: register it (if the hash matches and policy allows).
    Register { hash: String, query: String },
}

/// Parse the APQ intent from the request body JSON.
pub(crate) fn parse(body: &serde_json::Value) -> ApqRequest {
    let hash = body
        .pointer("/extensions/persistedQuery/sha256Hash")
        .and_then(|h| h.as_str());
    let Some(hash) = hash else {
        return ApqRequest::None;
    };
    match body.get("query").and_then(|q| q.as_str()) {
        Some(query) => ApqRequest::Register {
            hash: hash.to_string(),
            query: query.to_string(),
        },
        None => ApqRequest::Lookup {
            hash: hash.to_string(),
        },
    }
}

/// The resolution of an APQ request against the store + policy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ApqOutcome {
    /// Run this query text. If `store` is `Some`, first persist that `(hash, query)`.
    Run {
        query: String,
        store: Option<(String, String)>,
    },
    /// Return this as a GraphQL error message (`PersistedQueryNotFound`, a hash
    /// mismatch, …) without running the handler.
    Error(String),
}

/// The APQ error a client is expected to react to by re-sending the full query.
pub(crate) const NOT_FOUND: &str = "PersistedQueryNotFound";

/// Decide the outcome for a parsed APQ request, given the query already fetched from
/// the store for its hash (`stored`) and whether safelist mode is on. Pure — the caller
/// performs the async lookup beforehand and the async store afterward.
///
/// `None` means "not an APQ request; leave the request untouched".
pub(crate) fn resolve(
    req: ApqRequest,
    stored: Option<String>,
    safelist: bool,
) -> Option<ApqOutcome> {
    match req {
        ApqRequest::None => None,
        ApqRequest::Lookup { .. } => Some(match stored {
            Some(query) => ApqOutcome::Run { query, store: None },
            None => ApqOutcome::Error(NOT_FOUND.to_string()),
        }),
        ApqRequest::Register { hash, query } => {
            if sha256_hex(&query) != hash {
                return Some(ApqOutcome::Error(
                    "provided sha256Hash does not match the query".to_string(),
                ));
            }
            // Already registered ⇒ run it (idempotent; ignore the resent copy).
            if let Some(existing) = stored {
                return Some(ApqOutcome::Run {
                    query: existing,
                    store: None,
                });
            }
            // Safelist mode never registers a new query.
            if safelist {
                return Some(ApqOutcome::Error(NOT_FOUND.to_string()));
            }
            Some(ApqOutcome::Run {
                query: query.clone(),
                store: Some((hash, query)),
            })
        }
    }
}

/// The lowercase hex sha256 of `s` — the APQ hash of a query.
pub(crate) fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// The kv key for a persisted query: `hapq/{scope}/{hash}` — the same tenant-isolated
/// project-qualified `scope` the response cache uses, so two tenants never collide.
fn apq_key(scope: &str, hash: &str) -> String {
    format!("hapq/{scope}/{hash}")
}

/// The stored (safelisted) query text for `hash` in `scope`, or `None` if not registered.
/// Guest-run operations are **deny-by-default** — only pre-registered operations run,
/// independent of the edge's safelist mode — so this is the guest capability's operation floor.
pub(crate) async fn safelisted(
    kv: &dyn boatramp_core::kv::KvStore,
    scope: &str,
    hash: &str,
) -> Option<String> {
    kv.get(&apq_key(scope, hash))
        .await
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())
}

/// The edge resolution of an APQ request against the kv store.
pub(crate) enum Resolved {
    /// Use this query text (resolved from the store, or the request's own query).
    Query(String),
    /// Return this as a GraphQL error (the client reacts by re-sending the query).
    Error(String),
    /// Not an APQ request; leave the body's `query` untouched.
    Passthrough,
}

/// Resolve the APQ intent in `body` against the store: look the hash up, register it on
/// a hash-verified first miss (unless safelist), and return the effective query — or an
/// error. A store read/write failure degrades gracefully (a read miss ⇒ not-found).
pub(crate) async fn resolve_stored(
    kv: &dyn boatramp_core::kv::KvStore,
    scope: &str,
    body: &serde_json::Value,
    safelist: bool,
) -> Resolved {
    let req = parse(body);
    let hash = match &req {
        ApqRequest::None => return Resolved::Passthrough,
        ApqRequest::Lookup { hash } | ApqRequest::Register { hash, .. } => hash.clone(),
    };
    let stored = kv
        .get(&apq_key(scope, &hash))
        .await
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok());
    match resolve(req, stored, safelist) {
        None => Resolved::Passthrough,
        Some(ApqOutcome::Error(msg)) => Resolved::Error(msg),
        Some(ApqOutcome::Run { query, store }) => {
            if let Some((h, q)) = store {
                let _ = kv.put(&apq_key(scope, &h), q.into_bytes()).await;
            }
            Resolved::Query(query)
        }
    }
}

/// A GraphQL-shaped `200` response carrying an APQ error — the Apollo convention: the
/// client reacts to `PersistedQueryNotFound` by re-sending the full query.
pub(crate) fn error_response(message: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let body = serde_json::json!({ "errors": [ { "message": message } ] }).to_string();
    (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const Q: &str = "{ hello }";

    fn hash_of(q: &str) -> String {
        sha256_hex(q)
    }

    #[test]
    fn parse_distinguishes_plain_lookup_and_register() {
        assert_eq!(parse(&json!({ "query": Q })), ApqRequest::None);
        let ext =
            json!({ "extensions": { "persistedQuery": { "version": 1, "sha256Hash": "abc" } } });
        assert_eq!(parse(&ext), ApqRequest::Lookup { hash: "abc".into() });
        let reg = json!({
            "query": Q,
            "extensions": { "persistedQuery": { "version": 1, "sha256Hash": "abc" } }
        });
        assert_eq!(
            parse(&reg),
            ApqRequest::Register {
                hash: "abc".into(),
                query: Q.into()
            }
        );
    }

    #[test]
    fn lookup_hit_runs_and_miss_reports_not_found() {
        let req = ApqRequest::Lookup { hash: hash_of(Q) };
        assert_eq!(
            resolve(req, Some(Q.to_string()), false),
            Some(ApqOutcome::Run {
                query: Q.into(),
                store: None
            })
        );
        let miss = ApqRequest::Lookup { hash: hash_of(Q) };
        assert_eq!(
            resolve(miss, None, false),
            Some(ApqOutcome::Error(NOT_FOUND.into()))
        );
    }

    #[test]
    fn register_persists_when_hash_matches() {
        let h = hash_of(Q);
        let req = ApqRequest::Register {
            hash: h.clone(),
            query: Q.into(),
        };
        assert_eq!(
            resolve(req, None, false),
            Some(ApqOutcome::Run {
                query: Q.into(),
                store: Some((h, Q.into()))
            })
        );
    }

    #[test]
    fn register_with_wrong_hash_is_rejected() {
        let req = ApqRequest::Register {
            hash: "deadbeef".into(),
            query: Q.into(),
        };
        assert!(matches!(
            resolve(req, None, false),
            Some(ApqOutcome::Error(m)) if m.contains("does not match")
        ));
    }

    #[test]
    fn safelist_never_registers_a_new_query() {
        let h = hash_of(Q);
        // A correct hash+query, but the hash is not already stored: safelist refuses.
        let req = ApqRequest::Register {
            hash: h.clone(),
            query: Q.into(),
        };
        assert_eq!(
            resolve(req, None, true),
            Some(ApqOutcome::Error(NOT_FOUND.into()))
        );
        // A pre-registered hash still runs under safelist (lookup hit).
        assert_eq!(
            resolve(ApqRequest::Lookup { hash: h }, Some(Q.to_string()), true),
            Some(ApqOutcome::Run {
                query: Q.into(),
                store: None
            })
        );
    }

    #[test]
    fn non_apq_request_is_left_alone() {
        assert_eq!(resolve(ApqRequest::None, None, false), None);
    }

    #[tokio::test]
    async fn safelisted_returns_a_registered_op_and_none_otherwise() {
        use boatramp_core::kv::{KvStore, MemoryKv};
        let kv = MemoryKv::new();
        let h = hash_of(Q);
        // Not registered → the guest safelist floor rejects it.
        assert_eq!(safelisted(&kv, "acme", &h).await, None);
        // Registering it (any writer of the APQ store) makes it runnable by a guest.
        kv.put(&apq_key("acme", &h), Q.as_bytes().to_vec())
            .await
            .unwrap();
        assert_eq!(safelisted(&kv, "acme", &h).await, Some(Q.to_string()));
        // Tenant-isolated: another project's guest cannot see it.
        assert_eq!(safelisted(&kv, "other", &h).await, None);
    }
}
