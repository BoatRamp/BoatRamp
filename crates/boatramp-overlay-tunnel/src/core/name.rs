//! Name → service normalization (plan §1.3), the R1 subset: both front-ends normalize whatever a
//! consumer typed (a SOCKS in-band hostname today; a TUN synthetic-IP→name reverse lookup in a later
//! release) to the canonical `svc/<name>` the catalog and control plane key on.
//!
//! The DNS-zone form (`db.svc.<cluster>.boatramp.` → `svc/db`) is an R2+ concern (plan §9 open
//! decision 1, gated on the DNS-zone-naming/TLD call) and is deliberately NOT handled here: an
//! unrecognized dotted name normalizes to a service the catalog will not contain, so it fails safely
//! as an unknown service rather than silently guessing a zone-stripping rule.

/// Normalize `input` (whatever a front-end's consumer typed) to the canonical `svc/<name>` form:
/// - already-canonical `svc/<name>` passes through unchanged (case-folded);
/// - the short `svc-<name>` form (handy where a hostname can't contain `/`, e.g. SOCKS) maps to
///   `svc/<name>`;
/// - a bare `<name>` maps to `svc/<name>`.
///
/// Case-folded (ASCII lowercase) since SOCKS/DNS hostnames are conventionally case-insensitive.
/// Does not validate `name` is non-empty or otherwise well-formed — an empty/malformed result simply
/// will not be in the catalog, so it fails as "unknown service", not specially.
#[must_use]
pub fn normalize_name(input: &str) -> String {
    let lower = input.trim().to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("svc/") {
        return format!("svc/{rest}");
    }
    if let Some(rest) = lower.strip_prefix("svc-") {
        return format!("svc/{rest}");
    }
    format!("svc/{lower}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_gets_the_svc_prefix() {
        assert_eq!(normalize_name("db"), "svc/db");
    }

    #[test]
    fn svc_dash_form_normalizes_to_svc_slash() {
        assert_eq!(normalize_name("svc-db"), "svc/db");
    }

    #[test]
    fn already_canonical_passes_through() {
        assert_eq!(normalize_name("svc/db"), "svc/db");
    }

    #[test]
    fn mixed_case_is_folded() {
        assert_eq!(normalize_name("SVC/DB"), "svc/db");
        assert_eq!(normalize_name("DB"), "svc/db");
        assert_eq!(normalize_name("SVC-DB"), "svc/db");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(normalize_name("  db  "), "svc/db");
    }

    #[test]
    fn a_dns_zone_form_is_not_specially_parsed_in_r1() {
        // R2+ concern (plan §9.1); for now it normalizes to a literal service name that will not be
        // in any catalog, so it fails safely as "unknown service" rather than being silently
        // misinterpreted.
        assert_eq!(
            normalize_name("db.svc.cluster.boatramp"),
            "svc/db.svc.cluster.boatramp"
        );
    }
}
