//! **Test-only mutation seams** for the `S3 INGRESS SCOPED+SIGV4 OK` live gate (PLAN-blob-s3-ingress
//! §11 / M5). The neutering bodies are behind `#[cfg(feature = "s3-ingress-gate-mutation")]`, a feature
//! set ONLY by the CI gate lane — in every real build the helpers are `false` and the `if` guards at
//! the choke points fold away, so this module adds ZERO production surface.
//!
//! The gate must be *anti-hollow*: every security check it asserts on must FAIL the gate when that
//! check is neutered. A neuter env var flips exactly one product choke point into the broken behaviour
//! a real regression would introduce (skip the scope compare, skip the SigV4 verify, skip the sha256
//! content-address verify, skip the create-only overwrite precondition). The gate test then runs the
//! SAME battery with that env var set and asserts the previously-passing invariant now lets the bad
//! thing through — proving the check is load-bearing, not decorative.
//!
//! Each helper reads its env var live (not cached), so a single test process can toggle one mutation at
//! a time.

/// Whether the SCOPE-confinement check (`authorize_operation`'s container/key compare) should be
/// neutered — a cred for container A would then be able to PUT to B / a sibling / an escaped key
/// (invariant 1). `true` ⇒ the choke point returns `Ok(())` without comparing the request against the
/// signed scope.
#[inline]
pub fn skip_scope_check() -> bool {
    env_flag("BOATRAMP_S3INGRESS_MUTATE_SKIP_SCOPE")
}

/// Whether the SigV4 signature VERIFY should be neutered — a tampered/forged signature would then be
/// accepted (invariant 2). `true` ⇒ `authenticate` treats every signature as valid.
#[inline]
pub fn skip_sigv4_verify() -> bool {
    env_flag("BOATRAMP_S3INGRESS_MUTATE_SKIP_SIGV4")
}

/// Whether the content-addressing sha256 VERIFY should be neutered — bytes whose sha256 ≠ the declared
/// key would then be committed (invariant 4). `true` ⇒ `stream_put` skips the hash compare.
#[inline]
pub fn skip_sha256_verify() -> bool {
    env_flag("BOATRAMP_S3INGRESS_MUTATE_SKIP_SHA256")
}

/// Whether the create-only OVERWRITE precondition should be neutered — a create-only (UGC) credential
/// would then be able to overwrite an existing key (invariant 8). `true` ⇒ the precondition is skipped.
#[inline]
pub fn skip_create_only() -> bool {
    env_flag("BOATRAMP_S3INGRESS_MUTATE_SKIP_CREATE_ONLY")
}

/// Read a mutation env var: present + not `0`/empty ⇒ on. Deliberately permissive on the value (`1`,
/// `true`, anything non-empty-non-`0`) so the CI wiring can just `export VAR=1`. Compiled to a constant
/// `false` outside the gate-mutation feature so the choke-point `if`s vanish in every real build.
#[cfg(feature = "s3-ingress-gate-mutation")]
#[inline]
fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !v.is_empty() && v != "0",
        Err(_) => false,
    }
}

/// Production build: no mutation seam exists — every helper is a constant `false`.
#[cfg(not(feature = "s3-ingress-gate-mutation"))]
#[inline]
fn env_flag(_name: &str) -> bool {
    false
}
