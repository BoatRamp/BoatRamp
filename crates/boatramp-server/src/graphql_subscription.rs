//! GraphQL subscriptions.
//!
//! A subscription is served as a **graphql-sse** event stream (see
//! [`crate::stream::serve_graphql_subscription`]): the subscription's root field names a
//! messaging topic; a mutation (or any producer) publishes an execution result to that
//! topic, and each is framed as a graphql-sse `next` event so a standard graphql-sse
//! client consumes it directly. This module only needs to *detect* a subscription
//! operation and *derive its topic* — the transport (subscribe, `Last-Event-ID` resume,
//! heartbeat, connection caps, graphql-sse framing) is the `stream` module's job.
//!
//! boatramp stays GraphQL-*aware*, not an engine: the payload published to the topic is
//! the subscription result your producer computes; the host just fans it out (framed).

use async_graphql_parser::Positioned;
use async_graphql_parser::types::{
    DocumentOperations, OperationDefinition, OperationType, Selection,
};

/// If `query` is a subscription operation, return the messaging topic it streams from —
/// its single root field's name (a subscription has exactly one root field per the
/// GraphQL spec). Returns `None` for a query/mutation or a malformed subscription.
pub(crate) fn subscription_topic(query: &str) -> Option<String> {
    let doc = async_graphql_parser::parse_query(query).ok()?;
    let ops: Vec<&OperationDefinition> = match &doc.operations {
        DocumentOperations::Single(op) => vec![&op.node],
        DocumentOperations::Multiple(map) => map.values().map(|op| &op.node).collect(),
    };
    ops.into_iter().find_map(|op| {
        if op.ty != OperationType::Subscription {
            return None;
        }
        match op.selection_set.node.items.first() {
            Some(Positioned {
                node: Selection::Field(field),
                ..
            }) => Some(field.node.name.node.to_string()),
            _ => None,
        }
    })
}

/// The run-attach binding P3 derives from a GraphQL subscription whose root field is one of a site's
/// declared `run_subscriptions` fields. See [`subscription_run_binding`].
#[cfg(feature = "run-streaming")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunSubscription {
    /// The root field is a declared run-attach field and a run id was resolved to attach to.
    Attach(String),
    /// The root field is a declared run-attach field, but no usable `id` / `runId` run-id argument
    /// was supplied — a malformed run-attach subscription (a client error, not a topic subscription).
    MissingRunId,
}

/// If `query`'s subscription root field is one of the site's declared run-attach `run_fields`
/// (PLAN-run-streaming P3, D2 Option A), return the run binding — the `run-id` carried in its `id` /
/// `runId` argument (a string literal, or a `$variable` resolved against `variables`), or
/// [`RunSubscription::MissingRunId`] when the field matches but no usable run id is present.
///
/// Returns `None` when the subscription's root field is NOT a declared run-attach field (the caller
/// then takes the ordinary topic-fan-out path, byte-identical to before) or the operation is not a
/// subscription. The guest's own resolver is the AUTHORITY for which run a subscriber may see — it
/// minted + handed out the id at START; here the host only reads the id the client presents (the
/// tenancy fence + the unguessable id are the confinement). boatramp never executes the resolver.
#[cfg(feature = "run-streaming")]
pub(crate) fn subscription_run_binding(
    query: &str,
    run_fields: &[String],
    variables: &serde_json::Value,
) -> Option<RunSubscription> {
    if run_fields.is_empty() {
        return None; // no declared run-attach fields ⇒ never a run subscription
    }
    let doc = async_graphql_parser::parse_query(query).ok()?;
    let ops: Vec<&OperationDefinition> = match &doc.operations {
        DocumentOperations::Single(op) => vec![&op.node],
        DocumentOperations::Multiple(map) => map.values().map(|op| &op.node).collect(),
    };
    for op in ops {
        if op.ty != OperationType::Subscription {
            continue;
        }
        let Some(Positioned {
            node: Selection::Field(field),
            ..
        }) = op.selection_set.node.items.first()
        else {
            continue;
        };
        let field = &field.node;
        if !run_fields.iter().any(|f| f == field.name.node.as_str()) {
            // A subscription, but NOT on a declared run-attach field — the topic-fan-out path owns it.
            return None;
        }
        // A declared run-attach field: resolve the run id from the `id` / `runId` argument.
        let run_id = field
            .arguments
            .iter()
            .find(|(name, _)| matches!(name.node.as_str(), "id" | "runId"))
            .and_then(|(_, value)| run_id_from_value(&value.node, variables));
        return Some(match run_id {
            Some(id) if !id.is_empty() => RunSubscription::Attach(id),
            _ => RunSubscription::MissingRunId,
        });
    }
    None
}

/// Resolve a run-id argument value: a string literal (`id: "…"`), or a `$variable` looked up in the
/// request's `variables` (a JSON object). Any other value shape (number, enum, list, object, absent
/// variable) yields `None` — a malformed run id.
#[cfg(feature = "run-streaming")]
fn run_id_from_value(
    value: &async_graphql_value::Value,
    variables: &serde_json::Value,
) -> Option<String> {
    use async_graphql_value::Value;
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Variable(name) => variables
            .get(name.as_str())
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscription_yields_its_root_field_as_the_topic() {
        assert_eq!(
            subscription_topic("subscription { messageAdded { id body } }"),
            Some("messageAdded".to_string())
        );
        // A named subscription works too.
        assert_eq!(
            subscription_topic("subscription Live { ticks }"),
            Some("ticks".to_string())
        );
    }

    #[test]
    fn a_query_or_mutation_is_not_a_subscription() {
        assert_eq!(subscription_topic("{ me { name } }"), None);
        assert_eq!(subscription_topic("mutation { post(x: 1) }"), None);
        assert_eq!(subscription_topic("query Q { a }"), None);
    }

    #[test]
    fn a_malformed_query_is_not_a_subscription() {
        assert_eq!(subscription_topic("subscription { "), None);
    }

    #[cfg(feature = "run-streaming")]
    mod run_binding {
        use super::super::{RunSubscription, subscription_run_binding};
        use serde_json::json;

        fn no_vars() -> serde_json::Value {
            json!({})
        }

        #[test]
        fn a_declared_run_field_with_a_literal_id_binds_to_that_run() {
            let fields = vec!["watchRun".to_string()];
            assert_eq!(
                subscription_run_binding(
                    r#"subscription { watchRun(id: "0176-abc") { seq } }"#,
                    &fields,
                    &no_vars(),
                ),
                Some(RunSubscription::Attach("0176-abc".to_string()))
            );
            // The `runId` arg name is accepted too.
            assert_eq!(
                subscription_run_binding(
                    r#"subscription { watchRun(runId: "r2") }"#,
                    &fields,
                    &no_vars(),
                ),
                Some(RunSubscription::Attach("r2".to_string()))
            );
        }

        #[test]
        fn a_variable_run_id_resolves_against_the_request_variables() {
            let fields = vec!["watchRun".to_string()];
            let vars = json!({ "rid": "0176-var" });
            assert_eq!(
                subscription_run_binding(
                    "subscription Watch($rid: ID!) { watchRun(id: $rid) }",
                    &fields,
                    &vars,
                ),
                Some(RunSubscription::Attach("0176-var".to_string()))
            );
            // An unbound / non-string variable is a missing run id, not a silent topic fallthrough.
            assert_eq!(
                subscription_run_binding(
                    "subscription Watch($rid: ID!) { watchRun(id: $rid) }",
                    &fields,
                    &json!({ "other": 1 }),
                ),
                Some(RunSubscription::MissingRunId)
            );
        }

        #[test]
        fn a_declared_run_field_without_a_usable_id_is_missing_not_a_topic() {
            let fields = vec!["watchRun".to_string()];
            // No arg at all, an empty id, and a non-string literal all report MissingRunId — a
            // run-attach field must never silently fall through to a topic named after the field.
            for q in [
                "subscription { watchRun }",
                r#"subscription { watchRun(id: "") }"#,
                "subscription { watchRun(id: 42) }",
            ] {
                assert_eq!(
                    subscription_run_binding(q, &fields, &no_vars()),
                    Some(RunSubscription::MissingRunId),
                    "query {q:?} must be MissingRunId"
                );
            }
        }

        #[test]
        fn a_non_declared_field_or_empty_config_is_not_a_run_subscription() {
            // A subscription whose root field is NOT declared ⇒ None (topic path owns it).
            assert_eq!(
                subscription_run_binding(
                    r#"subscription { messageAdded { id } }"#,
                    &["watchRun".to_string()],
                    &no_vars(),
                ),
                None
            );
            // No declared run fields ⇒ never a run subscription, even for a field literally named it.
            assert_eq!(
                subscription_run_binding(r#"subscription { watchRun(id: "x") }"#, &[], &no_vars(),),
                None
            );
            // A query/mutation is never a run subscription.
            assert_eq!(
                subscription_run_binding(
                    r#"query { watchRun(id: "x") }"#,
                    &["watchRun".to_string()],
                    &no_vars(),
                ),
                None
            );
        }
    }
}
