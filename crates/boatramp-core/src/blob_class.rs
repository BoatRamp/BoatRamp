//! Blob-key integrity classification — the ONE place that decides whether a blob object is a
//! re-generable image DERIVATIVE (safe to skip / bless on a declared≠stored mismatch, because it
//! self-heals on next access) or LOAD-BEARING data (a BASELINE or a PRIMARY/original object, which
//! a declared≠stored mismatch must NEVER silently bless).
//!
//! This is the load-bearing security boundary for the clone-robustness + blob-integrity feature
//! set. Three independent features consult it so the "safe only for `der/`" rule lives in exactly
//! one audited function:
//! - the clone/import member-mismatch SKIP ([`crate::project_export`] → the bundle reader): a
//!   mismatched `der/` member is warned + skipped (the target re-derives it); a baseline/primary
//!   member still hard-fails;
//! - the guarded `blob reconcile` (bless the stored bytes): default-scoped to `der/`; a
//!   primary-blob reconcile needs an explicit, audited opt-in;
//! - the targeted legacy-derivative `blob purge`: deletes ONLY `der/` objects of a superseded
//!   image format, NEVER a referenced baseline/primary.
//!
//! ## The convention
//! `der/` and `base/` are GUEST-application path conventions INSIDE a blob container (e.g. the
//! image-serving demo stores a regenerable thumbnail at `…/der/<sha>/<width>.<ext>` and its
//! immutable source at `…/base/<sha>.<ext>`). The host owns no `der/`/`base/` constant, so this
//! classifier recognises them structurally: a path COMPONENT exactly equal to `der`/`base`
//! (never a substring — a key segment `thunder` or `database` is not a derivative).
//!
//! ## The conservative bias (the security property)
//! Misclassifying load-bearing data as a re-generable derivative is the ONLY dangerous error — it
//! would let a truncation/corruption be silently blessed or skipped. Misclassifying a derivative
//! as a baseline/primary is merely conservative (it hard-fails, forcing an explicit decision). So
//! a `base/` component ALWAYS wins: a key carrying both a `base` and a `der` component is a
//! [`Baseline`](BlobClass::Baseline), never a derivative.

use serde::{Deserialize, Serialize};

/// The path component that marks a re-generable derivative tree.
pub const DERIVATIVE_SEGMENT: &str = "der";

/// The path component that marks an immutable baseline tree.
pub const BASELINE_SEGMENT: &str = "base";

/// The integrity class of a blob object, deciding whether a declared≠stored mismatch on it is
/// tolerable. See the module docs for the convention and the conservative bias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobClass {
    /// A re-generable image derivative (`der/` component) — self-heals on next access, so a
    /// declared≠stored mismatch may be skipped/blessed. The ONLY class that is.
    Derivative,
    /// An immutable image baseline (`base/` component) — load-bearing; a mismatch hard-fails.
    Baseline,
    /// Any other blob object (an original/primary/user object) — load-bearing; a mismatch
    /// hard-fails.
    Primary,
}

impl BlobClass {
    /// Whether a declared≠stored mismatch on a blob of this class may be TOLERATED (skipped on a
    /// clone, or blessed by a reconcile) under the DEFAULT, re-generable-derivative-only scope.
    /// `true` ONLY for [`Derivative`](Self::Derivative). A broader action over a baseline/primary
    /// is the louder, explicit opt-in the callers gate separately — it is never this default.
    pub fn is_regenerable(self) -> bool {
        matches!(self, Self::Derivative)
    }

    /// A short, stable label for logs / reports (`"der"`, `"base"`, `"primary"`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Derivative => "der",
            Self::Baseline => "base",
            Self::Primary => "primary",
        }
    }
}

/// Classify a blob storage `key` (e.g. `hblob/acme/blog/images/der/<sha>/512.jpg`, or a key with
/// any leading scope the caller has already stripped). Recognises a `der`/`base` path COMPONENT
/// structurally; a `base` component always wins over a `der` one (the conservative bias — see the
/// module docs). A key with neither is [`Primary`](BlobClass::Primary).
pub fn classify_blob_key(key: &str) -> BlobClass {
    let mut has_der = false;
    let mut has_base = false;
    for seg in key.split('/') {
        match seg {
            DERIVATIVE_SEGMENT => has_der = true,
            BASELINE_SEGMENT => has_base = true,
            _ => {}
        }
    }
    if has_base {
        BlobClass::Baseline
    } else if has_der {
        BlobClass::Derivative
    } else {
        BlobClass::Primary
    }
}

/// Whether `key` is a re-generable [`Derivative`](BlobClass::Derivative) stored in a SUPERSEDED
/// image format — the ONLY objects a targeted legacy-derivative purge may delete. `superseded_ext`
/// is the old format's extension (e.g. `"jpg"` or `".JPG"` — a leading dot and case are
/// normalised); the current format (e.g. WEBP) is never matched. A [`Baseline`](BlobClass::Baseline)
/// or [`Primary`](BlobClass::Primary) object is NEVER superseded-deletable, whatever its extension —
/// the structural guard that keeps a legacy purge off load-bearing data.
pub fn is_superseded_derivative(key: &str, superseded_ext: &str) -> bool {
    if classify_blob_key(key) != BlobClass::Derivative {
        return false;
    }
    key_has_extension(key, superseded_ext)
}

/// Whether the final path component of `key` ends with `.<ext>` (both sides lowercased; a leading
/// dot on `ext` is tolerated). An empty `ext`, or a key whose last component has no extension,
/// yields `false`.
fn key_has_extension(key: &str, ext: &str) -> bool {
    let ext = ext.trim_start_matches('.').to_ascii_lowercase();
    if ext.is_empty() {
        return false;
    }
    let last = key.rsplit('/').next().unwrap_or(key);
    match last.rsplit_once('.') {
        Some((_, got)) => got.eq_ignore_ascii_case(&ext),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_der_base_and_primary() {
        // A `der/` component anywhere in the key is a re-generable derivative.
        assert_eq!(
            classify_blob_key("hblob/acme/blog/images/der/abc123/512.jpg"),
            BlobClass::Derivative
        );
        assert_eq!(
            classify_blob_key("hblob/acme/blog/images/der/abc123/512.webp"),
            BlobClass::Derivative
        );
        // A `base/` component is an immutable baseline.
        assert_eq!(
            classify_blob_key("hblob/acme/blog/images/base/abc123.jpg"),
            BlobClass::Baseline
        );
        // Neither → primary/original.
        assert_eq!(
            classify_blob_key("hblob/acme/blog/uploads/original/photo.png"),
            BlobClass::Primary
        );
        assert_eq!(classify_blob_key("hblob/acme/blog/favicon.ico"), BlobClass::Primary);
    }

    #[test]
    fn der_is_a_whole_component_never_a_substring() {
        // A segment that merely CONTAINS "der"/"base" is NOT a derivative/baseline — the match is
        // on a whole path component, so these are load-bearing primaries (hard-fail, never skip).
        assert_eq!(classify_blob_key("hblob/acme/thunder/x.bin"), BlobClass::Primary);
        assert_eq!(classify_blob_key("hblob/acme/database/x.bin"), BlobClass::Primary);
        assert_eq!(classify_blob_key("hblob/acme/derby/x.bin"), BlobClass::Primary);
    }

    #[test]
    fn base_wins_over_der_the_conservative_bias() {
        // Both components present → Baseline (the SAFE classification). Misclassifying
        // load-bearing data as a skippable derivative is the only dangerous error, so `base` wins.
        assert_eq!(
            classify_blob_key("hblob/acme/blog/base/sha/der/thumb.jpg"),
            BlobClass::Baseline
        );
        assert!(!classify_blob_key("hblob/acme/blog/base/sha/der/thumb.jpg").is_regenerable());
    }

    #[test]
    fn only_derivative_is_regenerable() {
        assert!(BlobClass::Derivative.is_regenerable());
        assert!(!BlobClass::Baseline.is_regenerable());
        assert!(!BlobClass::Primary.is_regenerable());
    }

    #[test]
    fn superseded_derivative_targets_only_legacy_der_objects() {
        // A legacy `.jpg` derivative IS superseded-deletable when the superseded ext is jpg.
        assert!(is_superseded_derivative(
            "hblob/acme/blog/images/der/abc/512.jpg",
            "jpg"
        ));
        // Case + leading-dot normalisation.
        assert!(is_superseded_derivative(
            "hblob/acme/blog/images/der/abc/512.JPG",
            ".jpg"
        ));
        // The CURRENT format (webp) is never a legacy target.
        assert!(!is_superseded_derivative(
            "hblob/acme/blog/images/der/abc/512.webp",
            "jpg"
        ));
        // A baseline `.jpg` is NEVER superseded-deletable (the structural guard) — even though its
        // extension matches. This is the load-bearing assertion: a legacy purge cannot touch a
        // baseline/primary.
        assert!(!is_superseded_derivative(
            "hblob/acme/blog/images/base/abc.jpg",
            "jpg"
        ));
        // A primary `.jpg` is likewise untouchable.
        assert!(!is_superseded_derivative("hblob/acme/blog/photo.jpg", "jpg"));
        // An empty/absent extension never matches.
        assert!(!is_superseded_derivative("hblob/acme/blog/der/abc/noext", "jpg"));
        assert!(!is_superseded_derivative("hblob/acme/blog/der/abc/512.jpg", ""));
    }
}
