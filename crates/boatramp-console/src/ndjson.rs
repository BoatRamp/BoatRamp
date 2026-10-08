//! Fetch-based NDJSON POST streamer for the node-ops progress streams
//! (`POST /api/blob-drain`, `POST /api/blob-purge`).
//!
//! Like [`crate::logstream`], this uses `fetch` so the Bearer token rides along
//! (an `EventSource` can't send one), reads the response body via a
//! `ReadableStream` reader, and splits it on newlines — each line is one NDJSON
//! object. The stream is finite (it ends with a `type:"report"` line), so an
//! `on_end` callback fires exactly once at the end with the terminal outcome.

use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Headers, ReadableStreamDefaultReader, Request, RequestInit, Response, TextDecoder};

/// How an NDJSON stream ended.
pub enum StreamEnd {
    /// The stream completed — every line was delivered via `on_line`.
    Done,
    /// A non-2xx status: the code plus the (small JSON/text) error body the
    /// server returned instead of a stream (e.g. 422 "no blob_fallback", 409).
    Http { status: u16, body: String },
    /// The request never completed or the body failed to decode.
    Transport(String),
}

/// `POST body_json` to `url` (with the Bearer `token`), streaming the NDJSON
/// response. `on_line` fires once per non-empty line (the raw JSON text);
/// `on_end` fires exactly once at the end. Fire-and-forget — the work is
/// spawned and drives itself to completion.
pub fn post_stream(
    url: &str,
    token: &str,
    body_json: String,
    on_line: impl Fn(String) + 'static,
    on_end: impl Fn(StreamEnd) + 'static,
) {
    let url = url.to_string();
    let token = token.to_string();
    spawn_local(async move {
        match pump(&url, &token, body_json, &on_line).await {
            Ok(()) => on_end(StreamEnd::Done),
            Err(end) => on_end(end),
        }
    });
}

/// Drive the fetch + read loop, forwarding each NDJSON line.
async fn pump(
    url: &str,
    token: &str,
    body_json: String,
    on_line: &dyn Fn(String),
) -> Result<(), StreamEnd> {
    let opts = RequestInit::new();
    opts.set_method("POST");
    let headers = Headers::new().map_err(to_end)?;
    headers
        .append("Authorization", &format!("Bearer {token}"))
        .map_err(to_end)?;
    headers
        .append("Content-Type", "application/json")
        .map_err(to_end)?;
    headers
        .append("Accept", "application/x-ndjson")
        .map_err(to_end)?;
    opts.set_headers(&headers);
    opts.set_body(&JsValue::from_str(&body_json));

    let request = Request::new_with_str_and_init(url, &opts).map_err(to_end)?;
    let window = web_sys::window().ok_or_else(|| StreamEnd::Transport("no window".to_string()))?;
    let resp: Response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(to_end)?
        .dyn_into()
        .map_err(to_end)?;

    if !resp.ok() {
        // Error responses are a small body ({"error":"…"} JSON or plain text),
        // not a stream — read it whole for the caller's message.
        let status = resp.status();
        let body = match resp.text() {
            Ok(promise) => JsFuture::from(promise)
                .await
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default(),
            Err(_) => String::new(),
        };
        return Err(StreamEnd::Http { status, body });
    }

    let body = resp
        .body()
        .ok_or_else(|| StreamEnd::Transport("no response body".to_string()))?;
    let reader: ReadableStreamDefaultReader = body.get_reader().dyn_into().map_err(to_end)?;
    let decoder = TextDecoder::new().map_err(to_end)?;

    let mut buf = String::new();
    loop {
        let chunk = JsFuture::from(reader.read()).await.map_err(to_end)?;
        if Reflect::get(&chunk, &JsValue::from_str("done"))
            .map_err(to_end)?
            .as_bool()
            .unwrap_or(true)
        {
            break;
        }
        let bytes: Uint8Array = Reflect::get(&chunk, &JsValue::from_str("value"))
            .map_err(to_end)?
            .dyn_into()
            .map_err(to_end)?;
        let text = decoder
            .decode_with_buffer_source(&bytes.into())
            .map_err(to_end)?;
        buf.push_str(&text);

        // NDJSON: one JSON object per line.
        while let Some(idx) = buf.find('\n') {
            let line: String = buf.drain(..idx + 1).collect();
            let line = line.trim();
            if !line.is_empty() {
                on_line(line.to_string());
            }
        }
    }
    // A final line without a trailing newline.
    let tail = buf.trim();
    if !tail.is_empty() {
        on_line(tail.to_string());
    }
    Ok(())
}

/// Map any JS error into a transport-level [`StreamEnd`].
fn to_end(err: impl Into<JsValue>) -> StreamEnd {
    StreamEnd::Transport(
        err.into()
            .as_string()
            .unwrap_or_else(|| "request failed".to_string()),
    )
}
