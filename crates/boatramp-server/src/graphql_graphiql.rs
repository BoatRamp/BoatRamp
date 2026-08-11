//! The GraphiQL in-browser explorer, served (when enabled) to a browser `GET` on a
//! GraphQL endpoint. A self-contained HTML page that loads GraphiQL from a CDN and posts
//! queries back to the same URL — a developer convenience, not part of query serving.

use axum::response::{IntoResponse, Response};

/// The GraphiQL page. The fetcher targets the request's own path, so the explorer talks to
/// the same endpoint that served it.
const GRAPHIQL_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>GraphiQL</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="https://unpkg.com/graphiql/graphiql.min.css" />
  </head>
  <body style="margin: 0; height: 100vh;">
    <div id="graphiql" style="height: 100vh;">Loading GraphiQL…</div>
    <script crossorigin src="https://unpkg.com/react/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom/umd/react-dom.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/graphiql/graphiql.min.js"></script>
    <script>
      const fetcher = GraphiQL.createFetcher({ url: window.location.pathname });
      const root = ReactDOM.createRoot(document.getElementById('graphiql'));
      root.render(React.createElement(GraphiQL, { fetcher }));
    </script>
  </body>
</html>
"#;

/// Serve the GraphiQL explorer page.
pub(crate) fn page() -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        GRAPHIQL_HTML,
    )
        .into_response()
}
