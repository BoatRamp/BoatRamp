//! Fetch-based SSE consumer for the live log tail.
//!
//! The browser `EventSource` API can't send an `Authorization` header, but the
//! console authenticates with a Bearer token — so this streams the SSE
//! response with `fetch` (which carries the header), reads the body via a
//! `ReadableStream` reader, and parses `data:` lines itself. An
//! [`web_sys::AbortController`] cancels the stream on pause / unmount.

use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    AbortController, AbortSignal, Headers, ReadableStreamDefaultReader, Request, RequestInit,
    Response, TextDecoder,
};

/// A handle to a running log stream: dropping it aborts the fetch (so a Yew
/// effect cleanup cancels the stream on pause / unmount).
pub struct LogStreamHandle {
    controller: AbortController,
}

impl Drop for LogStreamHandle {
    fn drop(&mut self) {
        self.controller.abort();
    }
}

/// Stream `data:` payloads from the SSE endpoint at `url` (with the Bearer
/// `token`), invoking `on_payload` for each parsed event. Returns a handle whose
/// drop aborts the stream.
pub fn open(
    url: &str,
    token: &str,
    on_payload: impl Fn(String) + 'static,
) -> LogStreamHandle {
    let controller = AbortController::new().expect("AbortController");
    let signal = controller.signal();
    let url = url.to_string();
    let token = token.to_string();
    spawn_local(async move {
        // A user abort surfaces as a JS error too; either way the stream ends.
        let _ = pump(&url, &token, &signal, &on_payload).await;
    });
    LogStreamHandle { controller }
}

/// Drive the fetch + read loop, forwarding each SSE `data:` payload.
async fn pump(
    url: &str,
    token: &str,
    signal: &AbortSignal,
    on_payload: &dyn Fn(String),
) -> Result<(), JsValue> {
    let opts = RequestInit::new();
    opts.set_method("GET");
    let headers = Headers::new()?;
    headers.append("Authorization", &format!("Bearer {token}"))?;
    headers.append("Accept", "text/event-stream")?;
    opts.set_headers(&headers);
    opts.set_signal(Some(signal));

    let request = Request::new_with_str_and_init(url, &opts)?;
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
    let resp: Response = JsFuture::from(window.fetch_with_request(&request))
        .await?
        .dyn_into()?;
    if !resp.ok() {
        return Err(JsValue::from_str(&format!(
            "log stream HTTP {}",
            resp.status()
        )));
    }
    let body = resp
        .body()
        .ok_or_else(|| JsValue::from_str("no response body"))?;
    let reader: ReadableStreamDefaultReader = body.get_reader().dyn_into()?;
    let decoder = TextDecoder::new()?;

    let mut buf = String::new();
    loop {
        let chunk = JsFuture::from(reader.read()).await?;
        if Reflect::get(&chunk, &JsValue::from_str("done"))?
            .as_bool()
            .unwrap_or(true)
        {
            break;
        }
        let bytes: Uint8Array = Reflect::get(&chunk, &JsValue::from_str("value"))?.dyn_into()?;
        let text = decoder.decode_with_buffer_source(&bytes.into())?;
        buf.push_str(&text);

        // SSE frames are separated by a blank line; emit each frame's `data:`.
        while let Some(idx) = buf.find("\n\n") {
            let frame: String = buf.drain(..idx + 2).collect();
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    on_payload(data.trim().to_string());
                }
            }
        }
    }
    Ok(())
}
