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

use graphql_parser::query::{Definition, OperationDefinition, Selection};

/// If `query` is a subscription operation, return the messaging topic it streams from —
/// its single root field's name (a subscription has exactly one root field per the
/// GraphQL spec). Returns `None` for a query/mutation or a malformed subscription.
pub(crate) fn subscription_topic(query: &str) -> Option<String> {
    let doc = graphql_parser::query::parse_query::<String>(query).ok()?;
    doc.definitions.iter().find_map(|def| {
        let Definition::Operation(OperationDefinition::Subscription(sub)) = def else {
            return None;
        };
        match sub.selection_set.items.first() {
            Some(Selection::Field(field)) => Some(field.name.clone()),
            _ => None,
        }
    })
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
}
