//! The **key-composition choke point** (PLAN-blob-s3-ingress §5 + Security HIGH-2 / Architect HIGH-1,
//! and the M1-review MEDIUM-3 staging-prefix fix).
//!
//! Every object write the local S3 face performs — a single-shot `PutObject`, an assembled
//! multipart Complete, or a staged multipart part — routes through this one module, so a client key
//! can never escape its host-forced scope prefix on **any** backend (the `fs::resolve` traversal
//! backstop is fs-only; cloud backends have no such backstop, so the screen must live at the face).
//!
//! The pipeline is exactly, and only:
//! 1. **percent-decode the wire key ONCE** ([`percent_decode_once`]) — SigV4 signs the encoded form,
//!    storage uses the decoded form; decoding more than once would let `%252e%252e` slip a `..`
//!    past the screen.
//! 2. **screen the decoded key** with [`boatramp_core::project::validate_object_key`] — rejects the
//!    empty key, `..`/`.`, absolute/empty segments, `\`, `*`, control bytes, and (crucially) any
//!    reserved `.boatramp*` segment — which is the namespace multipart staging lives under, so a
//!    client key can never collide with the staging area (M1-review MEDIUM-3).
//! 3. **re-anchor** under the host-forced `hblob/{project-qualified-site}/{container}/` prefix —
//!    the SAME prefix the guest `compat::blob` binding reads, so an uploaded object is guest-readable
//!    with no guest change.
//!
//! The prefix components (`project`, `site`, `container`) come from the SIGNED session-token scope,
//! never from the URL authority or a client header — so cross-container / cross-project is
//! structurally impossible.

use boatramp_core::project::{ProjectRef, validate_object_key};

/// The reserved staging-namespace segment for in-flight multipart uploads. It lives under the
/// case-folded `.boatramp*` namespace that [`validate_object_key`] reserves — so a client object key
/// can NEVER collide with (or read/write into) the staging area. (M1-review MEDIUM-3: the reserved
/// namespace is `.boatramp*`, NOT `.uploads`; staging MUST use this exact prefix.)
pub const STAGING_SEGMENT: &str = ".boatramp-uploads";

/// Percent-decode a wire path/key **exactly once**: each valid `%XX` becomes its byte; an invalid or
/// truncated `%XX` is left verbatim (never a panic on hostile input). This is the single decode the
/// choke point performs — SigV4 verified the *encoded* form, so decoding twice would be a scope-escape
/// vector (`%252e%252e` → `%2e%2e` → `..`). A non-UTF8 result decodes lossily.
pub fn percent_decode_once(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Hex digit value, or `None`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The host-forced object prefix `hblob/{project-qualified-site}/{container}/` — the exact string the
/// guest `compat::blob` binding composes for `(project, site, container)`, so an object written under
/// it is immediately readable by the guest. `project`/`site`/`container` are the host-stamped scope
/// values (never client-supplied); the container is a single validated segment.
pub fn container_prefix(project: &str, site: &str, container: &str) -> String {
    let qualified_site = ProjectRef::new(project).qualified(site);
    format!("hblob/{qualified_site}/{container}/")
}

/// The staging prefix `hblob/{project-qualified-site}/{container}/.boatramp-uploads/{upload_id}/` for
/// a multipart upload's parts. Under the reserved `.boatramp*` namespace, so it can never collide with
/// a (screened) client object key, and the guest binding cannot reach it (`validate_object_key`
/// rejects a guest key naming a `.boatramp*` segment).
pub fn staging_prefix(project: &str, site: &str, container: &str, upload_id: &str) -> String {
    format!(
        "{}{STAGING_SEGMENT}/{upload_id}/",
        container_prefix(project, site, container)
    )
}

/// The storage key for one staged part: `…/.boatramp-uploads/{upload_id}/part-{n:08}`. Zero-padded so
/// a lexicographic `list` returns parts in numeric order (assembly relies on this ordering).
pub fn staging_part_key(
    project: &str,
    site: &str,
    container: &str,
    upload_id: &str,
    part_number: u32,
) -> String {
    format!(
        "{}part-{part_number:08}",
        staging_prefix(project, site, container, upload_id)
    )
}

/// A key-composition rejection. Kept distinct from the storage error so the face maps it to the
/// greppable `BoatrampScopeEscape` S3 error code.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The decoded key failed [`validate_object_key`] (empty, traversal, absolute, reserved
    /// `.boatramp*`, backslash, `*`, or a control byte) — a scope-escape attempt.
    #[error("object key escapes its scoped prefix: {0}")]
    ScopeEscape(String),
}

/// **The choke point.** Given a raw (wire, percent-encoded) object key from the URL and the
/// host-stamped scope, produce the final storage key `hblob/{project-qualified-site}/{container}/{key}`
/// — or reject. Decodes ONCE, screens with [`validate_object_key`], then re-anchors. Every object
/// write in the face MUST obtain its final key here so a key can never escape the scoped prefix.
///
/// Returns `(decoded_key, final_storage_key)`: the decoded key is what the scope-match check compares
/// against the credential's `Key`/`Prefix` target; the storage key is where the object lands.
pub fn compose_object_key(
    project: &str,
    site: &str,
    container: &str,
    raw_wire_key: &str,
) -> Result<(String, String), KeyError> {
    let decoded = percent_decode_once(raw_wire_key);
    validate_object_key(&decoded).map_err(|e| KeyError::ScopeEscape(e.to_string()))?;
    let storage_key = format!("{}{decoded}", container_prefix(project, site, container));
    Ok((decoded, storage_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exactly_once() {
        // A single %XX decode; a double-encoded traversal decodes to the *literal* single-encoded
        // form, NOT to `..` — proving we never double-decode (which would be a scope-escape vector).
        assert_eq!(percent_decode_once("a%2Fb"), "a/b");
        assert_eq!(percent_decode_once("%2e%2e"), "..");
        assert_eq!(percent_decode_once("%252e%252e"), "%2e%2e"); // one decode only
        // A truncated / invalid escape is left verbatim (never a panic).
        assert_eq!(percent_decode_once("a%"), "a%");
        assert_eq!(percent_decode_once("a%zz"), "a%zz");
    }

    #[test]
    fn composes_the_guest_readable_prefix_default_project() {
        // default project ⇒ NO project segment (byte-identical to the pre-project blob layout),
        // matching the guest binding's `hblob/{site}/{container}/`.
        let (decoded, key) =
            compose_object_key("default", "blog", "photos", "avatars/u1/x.jpg").expect("valid key");
        assert_eq!(decoded, "avatars/u1/x.jpg");
        assert_eq!(key, "hblob/blog/photos/avatars/u1/x.jpg");
    }

    #[test]
    fn composes_the_guest_readable_prefix_named_project() {
        // A named project prefixes `"<project>/"` — matching `ProjectRef::qualified`.
        let (_, key) = compose_object_key("acme", "blog", "photos", "x.bin").expect("valid key");
        assert_eq!(key, "hblob/acme/blog/photos/x.bin");
    }

    #[test]
    fn rejects_traversal_via_single_encoding() {
        // `%2e%2e%2f` decodes ONCE to `../` ⇒ a `..` segment ⇒ rejected at the screen.
        let err = compose_object_key("default", "s", "c", "%2e%2e%2fescape").unwrap_err();
        assert!(matches!(err, KeyError::ScopeEscape(_)));
        assert!(compose_object_key("default", "s", "c", "../escape").is_err());
        assert!(compose_object_key("default", "s", "c", "a/../../b").is_err());
    }

    #[test]
    fn rejects_absolute_and_empty_and_dangerous() {
        for bad in [
            "/leading",
            "trailing/",
            "a//b",
            "",
            "star*key",
            "back\\slash",
            "nul\0byte",
        ] {
            assert!(
                compose_object_key("default", "s", "c", bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_client_key_colliding_with_the_staging_prefix() {
        // M1-review MEDIUM-3: a client MUST NOT be able to write into (or read) the multipart staging
        // area. Staging lives under the reserved `.boatramp-uploads` segment; a client key naming that
        // (case-insensitively, at any depth) is rejected by the screen — proving the staging namespace
        // is unreachable via a crafted object key.
        assert!(compose_object_key("default", "s", "c", ".boatramp-uploads/u/part-1").is_err());
        assert!(compose_object_key("default", "s", "c", "a/.boatramp-uploads/u/part-1").is_err());
        assert!(compose_object_key("default", "s", "c", ".BoatRamp-Uploads/u/p").is_err()); // case-fold
        // And the staging-key composer itself lands EXACTLY under that reserved segment.
        let part = staging_part_key("default", "s", "c", "UPLOADID", 3);
        assert_eq!(part, "hblob/s/c/.boatramp-uploads/UPLOADID/part-00000003");
        assert!(part.contains("/.boatramp-uploads/"));
    }

    #[test]
    fn staging_part_keys_sort_in_numeric_order() {
        // Zero-padded part numbers so a lexicographic `list` yields numeric order for assembly.
        let k1 = staging_part_key("default", "s", "c", "u", 1);
        let k2 = staging_part_key("default", "s", "c", "u", 2);
        let k10 = staging_part_key("default", "s", "c", "u", 10);
        let mut v = vec![k10.clone(), k2.clone(), k1.clone()];
        v.sort();
        assert_eq!(v, vec![k1, k2, k10]);
    }
}
