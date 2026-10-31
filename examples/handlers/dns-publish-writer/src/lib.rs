// A wasi:http handler that WRITES DNS records through the boatramp `dns-publish`
// capability (cap-req #24 WS3) and reports, one line per operation, what the host
// gate decided. The guest never holds a zone-write token — it only NAMES records;
// the host performs (or refuses) each mutation through its operator-configured,
// host-held provider credential. Two scenarios, selected by the request path, so a
// single fixture drives every arm of the host gate from a real compiled component:
//
//   * default ("/" or anything not under "/ns"): the main publish sequence —
//       a-in-zone   : upsert an A at an in-zone name            (expect ok)
//       mx-in-zone  : upsert an MX at the zone apex, foreign MX  (expect ok)
//       out-of-zone : upsert an A at a name OUTSIDE the zone     (expect not-authorized)
//       apex-ns     : upsert an NS at the zone apex              (expect apex-refused)
//
//   * "/ns": the sub-zone NS-delegation sequence (Security review MEDIUM-3) —
//       ns-in-list     : upsert a sub-zone NS to an allowlisted nameserver (expect ok under `allowlist`)
//       ns-out-of-list : upsert a sub-zone NS to a NON-allowlisted nameserver (expect not-authorized)
//
// The body is the `key=token` report; the host test also inspects the installed
// ManualDnsProvider's captured records (the real publish through the gate).
wit_bindgen::generate!({
    world: "boatramp:caps-example/handler",
    path: "wit",
    generate_all,
});

use boatramp::handlers::dns_publish;
use boatramp::handlers::dns_publish::{DnsRecord, MxData, PublishError, Rdata};
use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{
    Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, outparam: ResponseOutparam) {
        let path = request.path_with_query().unwrap_or_default();
        let body = if path.starts_with("/ns") {
            ns_sequence()
        } else {
            publish_sequence()
        };
        respond(outparam, 200, body.as_bytes());
    }
}

/// The main publish sequence: one in-zone A, one in-zone (apex) MX, one out-of-zone
/// name, one apex NS. Each line is `key=<outcome-token>`.
fn publish_sequence() -> String {
    let a_in_zone = dns_publish::upsert(&a_record("www.app.example.com", "203.0.113.7"));
    let mx_in_zone = dns_publish::upsert(&mx_record("app.example.com", 10, "mx.mailprovider.net"));
    let out_of_zone = dns_publish::upsert(&a_record("www.evil.example.net", "203.0.113.9"));
    let apex_ns = dns_publish::upsert(&ns_record("app.example.com", "ns1.somewhere.net"));
    [
        format!("a-in-zone={}", token(&a_in_zone)),
        format!("mx-in-zone={}", token(&mx_in_zone)),
        format!("out-of-zone={}", token(&out_of_zone)),
        format!("apex-ns={}", token(&apex_ns)),
    ]
    .join("\n")
}

/// The sub-zone NS-delegation sequence: the SAME (in-zone) owner name in both
/// cases — only the NS rdata TARGET differs — so this isolates the NS-target
/// allowlist from the unchanged own-name allowlist.
fn ns_sequence() -> String {
    let in_list = dns_publish::upsert(&ns_record("deleg.app.example.com", "ns1.ns.app-dns.net"));
    let out_of_list = dns_publish::upsert(&ns_record("deleg.app.example.com", "ns1.attacker.test"));
    [
        format!("ns-in-list={}", token(&in_list)),
        format!("ns-out-of-list={}", token(&out_of_list)),
    ]
    .join("\n")
}

fn a_record(name: &str, ip: &str) -> DnsRecord {
    DnsRecord {
        name: name.to_string(),
        ttl: 300,
        data: Rdata::A(ip.to_string()),
    }
}

fn mx_record(name: &str, preference: u16, exchange: &str) -> DnsRecord {
    DnsRecord {
        name: name.to_string(),
        ttl: 300,
        data: Rdata::Mx(MxData {
            preference,
            exchange: exchange.to_string(),
        }),
    }
}

fn ns_record(name: &str, target: &str) -> DnsRecord {
    DnsRecord {
        name: name.to_string(),
        ttl: 300,
        data: Rdata::Ns(target.to_string()),
    }
}

/// The stable outcome token for one publish result — the host test greps these.
fn token(r: &Result<(), PublishError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(PublishError::AccessDenied) => "access-denied",
        Err(PublishError::NotAuthorized(_)) => "not-authorized",
        Err(PublishError::Unsupported(_)) => "unsupported",
        Err(PublishError::ApexRefused(_)) => "apex-refused",
        Err(PublishError::InvalidRecord(_)) => "invalid-record",
        Err(PublishError::RateLimited) => "rate-limited",
        Err(PublishError::Backend(_)) => "backend",
    }
}

fn respond(outparam: ResponseOutparam, status: u16, message: &[u8]) {
    let resp = OutgoingResponse::new(Fields::new());
    resp.set_status_code(status).unwrap();
    let body = resp.body().unwrap();
    ResponseOutparam::set(outparam, Ok(resp));
    let stream = body.write().unwrap();
    stream.blocking_write_and_flush(message).unwrap();
    drop(stream);
    OutgoingBody::finish(body, None).unwrap();
}

export!(Component);
