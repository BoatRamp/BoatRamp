//! The node **Overlay directory** page: node-global, read-only.
//!
//! Lists the overlay forward-flow service directory (`GET /api/overlay/services`,
//! gated `Overlay·Read`) — the console equivalent of `boatramp overlay ls`. It
//! shows what is joinable: each service name, the relay to dial, the relay +
//! egress overlay **identities** a client pins, and the relay's client-auth
//! posture. "Names, not addresses": an operator reads the directory here instead
//! of hand-assembling topology.
//!
//! The directory is node-global (not project-scoped) and read-only — this is pure
//! presentation; minting a dial capability (`Overlay·Write`) stays the CLI's job
//! (`boatramp forward` / `overlay grant`), so there is no mutating control here.
//!
//! States mirror the other data views: a [`Spinner`] while loading, a clear
//! "you need an overlay role" note on `403` (the token is valid but lacks
//! `Overlay·Read`), an [`ErrorBanner`] with retry on any other failure, a
//! dashed empty card when no services are published, and the table otherwise.

use yew::prelude::*;

use crate::api::ApiError;
use crate::hooks::{Fetch, use_api};
use crate::models::OverlayService;
use crate::widgets::{ErrorBanner, Pill, Section, Spinner, Tone};

/// The Overlay directory page.
#[function_component(OverlayDirectory)]
pub fn overlay_directory() -> Html {
    let services = use_api(|client| async move {
        client
            .get_json::<Vec<OverlayService>>("/api/overlay/services")
            .await
    });

    let body = match &services.state {
        Fetch::Loading => html! { <Spinner label="Loading overlay directory…" /> },
        // A valid token that lacks `Overlay·Read` (the server maps that to 403,
        // see `api.rs`). An expected access posture, not an error to retry — a
        // calm, actionable note instead of the rose error banner.
        Fetch::Failed(ApiError::Forbidden) => forbidden_note(),
        Fetch::Failed(err) => html! {
            <ErrorBanner message={err.to_string()} on_retry={Some(services.reload.clone())} />
        },
        Fetch::Ready(list) if list.is_empty() => empty_note(),
        Fetch::Ready(list) => directory_table(list),
    };

    html! {
        <div class="space-y-8">
            <div>
                <h2 class="text-lg font-semibold text-slate-900">{ "Overlay directory" }</h2>
                <p class="mt-1 max-w-3xl text-sm text-slate-500">
                    { "Services reachable over the overlay fabric — what " }
                    <code class="rounded bg-slate-100 px-1 py-0.5 text-xs">{ "boatramp forward svc/<name>" }</code>
                    { " can dial. Names, not addresses: each row is a service plus the relay and \
                       egress identities a client pins to reach it." }
                </p>
            </div>
            { body }
        </div>
    }
}

/// The directory table (one row per service). Columns mirror `overlay ls` /
/// `resolve`: service, relay (address + pinned identity), egress identity, and
/// the client-auth posture — so the console and CLI agree.
fn directory_table(list: &[OverlayService]) -> Html {
    let count = list.len();
    let count_label = format!("{count} service{}", if count == 1 { "" } else { "s" });
    let action = html! { <span class="text-sm text-slate-500">{ count_label }</span> };
    html! {
        <Section title="Services" action={action}>
            <div class="overflow-x-auto">
                <table class="w-full min-w-[42rem] text-sm">
                    <thead>
                        <tr class="border-b border-slate-200 text-left text-slate-500">
                            <th scope="col" class="py-2 pr-4 font-medium">{ "Service" }</th>
                            <th scope="col" class="py-2 pr-4 font-medium">{ "Relay" }</th>
                            <th scope="col" class="py-2 pr-4 font-medium">{ "Egress identity" }</th>
                            <th scope="col" class="py-2 font-medium">{ "Client auth" }</th>
                        </tr>
                    </thead>
                    <tbody>{ for list.iter().map(service_row) }</tbody>
                </table>
            </div>
            <p class="mt-3 text-xs text-slate-500">
                { "Client auth is the relay's posture: " }
                <span class="font-medium text-slate-600">{ "capability-only" }</span>
                { " accepts any holder of a valid dial capability, while " }
                <span class="font-medium text-slate-600">{ "mutual-pin" }</span>
                { " additionally requires the client identity to be enrolled in the relay's \
                   allow-list." }
            </p>
        </Section>
    }
}

/// One service row. The relay address carries its pinned `relay_id` beneath it
/// (as `overlay resolve` prints `relay (relay_id)`); identities render monospace
/// so a hex key is scannable.
fn service_row(s: &OverlayService) -> Html {
    html! {
        <tr key={s.service.clone()} class="border-b border-slate-100 align-top">
            <td class="py-2.5 pr-4 font-medium text-slate-900">{ &s.service }</td>
            <td class="py-2.5 pr-4">
                <div class="font-mono text-slate-700">{ &s.relay }</div>
                if !s.relay_id.is_empty() {
                    <div class="break-all font-mono text-xs text-slate-500">{ &s.relay_id }</div>
                }
            </td>
            <td class="py-2.5 pr-4 break-all font-mono text-xs text-slate-500">
                { if s.egress_id.is_empty() { "—" } else { &s.egress_id } }
            </td>
            <td class="py-2.5">
                <Pill text={posture_label(&s.client_auth)} tone={Tone::Neutral} />
            </td>
        </tr>
    }
}

/// The client-auth posture label for the pill: the raw posture
/// (`capability-only` | `mutual-pin`) verbatim, or a dash when the server did
/// not send one. Rendered as a neutral tag (a configured posture is a fact, not
/// a good/bad health signal), with the two values explained under the table.
fn posture_label(client_auth: &str) -> AttrValue {
    if client_auth.is_empty() {
        AttrValue::from("—")
    } else {
        AttrValue::from(client_auth.to_string())
    }
}

/// Shown when the token is valid but lacks `Overlay·Read`. Points the operator
/// at the overlay role rather than leaving a bare "forbidden".
fn forbidden_note() -> Html {
    html! {
        <div role="status" aria-live="polite" class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
            <p class="text-sm font-medium text-amber-800">
                { "You need an overlay role to view the directory." }
            </p>
            <p class="mt-1 text-sm text-amber-700">
                { "Your token is valid but lacks the " }
                <code class="rounded bg-amber-100 px-1 py-0.5 text-xs">{ "Overlay·Read" }</code>
                { " right. Ask an admin for an overlay role — e.g. " }
                <code class="rounded bg-amber-100 px-1 py-0.5 text-xs">{ "boatramp token mint --role overlay" }</code>
                { "." }
            </p>
        </div>
    }
}

/// Shown when the directory is empty (no `[overlay] routes` are configured on the
/// node, so there is nothing to forward to yet).
fn empty_note() -> Html {
    html! {
        <div class="rounded-lg border border-dashed border-slate-300 bg-white p-10 text-center">
            <p class="text-slate-500">{ "No services are published to the overlay directory." }</p>
            <p class="mt-1 text-sm text-slate-500">
                { "A node advertises forward-able services under its " }
                <code class="rounded bg-slate-100 px-1.5 py-0.5 text-sm">{ "[overlay]" }</code>
                { " config." }
            </p>
        </div>
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    /// A full directory entry deserializes field-for-field — the drift guard the
    /// console models exist for (if the server renames a field, this fails).
    #[wasm_bindgen_test]
    fn deserializes_directory_entry() {
        let json = r#"[{
            "service": "svc/db",
            "relay": "10.0.0.1:9100",
            "relay_id": "ed25519:aa",
            "egress_id": "ed25519:bb",
            "client_auth": "mutual-pin"
        }]"#;
        let list: Vec<OverlayService> = serde_json::from_str(json).expect("valid directory JSON");
        assert_eq!(list.len(), 1);
        let s = &list[0];
        assert_eq!(s.service, "svc/db");
        assert_eq!(s.relay, "10.0.0.1:9100");
        assert_eq!(s.relay_id, "ed25519:aa");
        assert_eq!(s.egress_id, "ed25519:bb");
        assert_eq!(s.client_auth, "mutual-pin");
    }

    /// `client_auth` is tolerated when absent (matches the CLI mirror), so a node
    /// that predates the posture field still renders.
    #[wasm_bindgen_test]
    fn client_auth_is_optional() {
        let json = r#"[{
            "service": "svc/x",
            "relay": "h:1",
            "relay_id": "ed25519:a",
            "egress_id": "ed25519:b"
        }]"#;
        let list: Vec<OverlayService> =
            serde_json::from_str(json).expect("valid without client_auth");
        assert_eq!(list[0].client_auth, "");
    }

    /// The posture label is shown verbatim (same vocabulary as the CLI), and an
    /// empty posture renders as a dash rather than an empty pill.
    #[wasm_bindgen_test]
    fn posture_label_is_verbatim_or_dash() {
        assert_eq!(posture_label("capability-only").as_str(), "capability-only");
        assert_eq!(posture_label("mutual-pin").as_str(), "mutual-pin");
        assert_eq!(posture_label("").as_str(), "—");
    }
}
