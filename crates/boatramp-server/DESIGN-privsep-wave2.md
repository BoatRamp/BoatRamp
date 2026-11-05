# DESIGN — privsep Phase-2 Wave-2 authority grammars

Status: BUILT on branch `privsep-wave2-grammars` (off `origin/feat/privsep`). TCB-critical;
Security-review gate before fold. This note maps each new grammar to the EXISTING boatramp
authority it wraps, states the typed request/response, the scope key, and every design decision
(numbered, with the safe default chosen). It mirrors the Wave-1 grammars
(`secrets.sealer` seal/unseal, `token.signer` mint_token) in `privsep_authority.rs` exactly.

## What this ships (and what it deliberately does NOT)

Four concrete `AuthorityHandler`s on the existing registry seam, each:
- a new `AuthorityRequest` op variant + a new `AuthorityResponse` RESULT variant (routed through the
  per-variant **compile tripwire** `response_admits_no_key_material`, so Security gates every new
  variant on "does it hand back a key/seed/KEK?" — the answer stays NO);
- `op_name()` + `required_authority()` arms (the four `HostAuthority` variants ALREADY exist:
  `ImageSigner`, `OverlayDialSigner`, `S3IngressRoot`, `ClusterJoinSigner` — no enum change);
- kind-gated (anything but its own op ⇒ `refused_wrong_kind`), fail-closed, scoped SOLELY to the
  re-validated `VerifiedPrincipal` (never a caller-asserted field), audited + rate-limited by the
  shared serve loop;
- unit tests + a `#[cfg(unix)]` socketpair e2e, registered on a real `AuthorityRegistry` and served
  through `AuthorityServe` — exactly as Wave-1's `grammar_round_trips_and_a_replayed_call_is_refused`.

**NOT live-wired (by design, per the task + the Phase-3 gate).** The handlers are NOT registered in
the production composition `boatramp::privsep::run_authority_serve`, and the Phase-3 stand-up gate
`check_authority_serve_preconditions` (always fail-closed pre-Phase-3) is UNTOUCHED. Reasons: (a) the
production key sources for these four authorities are NOT resolved in the privsep instance resolver
(`image_signer_key`/overlay-seed/s3-ingress-root are `None` / unresolved in `privsep_resolve.rs`;
`run_authority_serve` only knows the unlocked auth-root signer), so wiring would require NEW
key-source plumbing — out of scope for building the grammars; (b) the task is explicit: build + test
standalone, do NOT live-wire, keep the monolith + Phases 0–4 untouched. The registration arms +
key-source resolution are the **documented follow-on** (see "Follow-on wiring" below).

## The shared scope model (settled decision applied uniformly)

The crown jewel is control-plane-**policy-blind** (holds no `AuthzPolicy`, no KV) — so a handler can
NOT expand roles→rights. It scopes DIRECTLY on the re-validated token's `GrantedRole`s, exactly as
Wave-1 `scope_of`/`mint_token` do. Settled granularity decision (carried from Wave-1): **scope on
`GrantedRole.target`, fail-closed if targetless.**

Shared helper `scope_target_authorized(principal, requested)`: true iff the principal holds a
`GrantedRole` whose `target` equals `requested`, OR a project role whose bare `<project>` target
covers a `<project>/<site>` `requested` (ProjectWildcard semantics). A principal with NO targeted
role authorizes nothing (fail-closed). Consolidated (one helper), not mirrored per grammar.

---

## Grammar 1 — `image.signer` → `SignImage`

- **Existing authority wrapped.** There is **no in-process Rust image signer today** — real release
  signing is the cosign CLI in CI (`.github/workflows/release.yml`), and the in-tree `image.signer`
  (v0.44.0, `HostAuthority::ImageSigner`, group A) is an INERT privsep key slot (`image_signer_key`
  is `None` in production). So this grammar is built on the **`token.signer`/`cose::Signer`
  template**: it holds a dedicated `Arc<dyn Signer>` (the image-signing key) and produces a detached
  signature. The signing key is NEVER representable in a response (type-foreclosed).
- **Typed request:** `SignImage { digest: String, repo: String }` — `digest` the OCI image/manifest
  digest (`sha256:<64 hex>`); `repo` the repository the image belongs to (the scope).
- **Typed response:** `ImageSigned { signature: String }` — hex of a detached signature over a
  domain-separated, length-framed message `boatramp-image-sign/v1 ‖ len(repo)‖repo ‖ len(digest)‖digest`.
  A RESULT (a signature), never the key.
- **Scope key:** `repo`, matched against the principal's `GrantedRole.target`s
  (`scope_target_authorized`); fail-closed if targetless.
- **Handler:** `ImageSignerHandler { signer }`; `permits_authority == ImageSigner`.

## Grammar 2 — `overlay.dial-signer` → `MintDialCap`

- **Existing authority wrapped.** `cose::mint_overlay_dial(holder, scope, ttl, now, signer)`
  (`KIND_OVERLAY_DIAL`), the holder-bound dial capability minted today by `POST /api/overlay/dial`
  (gated `Overlay·Write`, TTL clamped by `clamp_dial_ttl(req, max_dial_ttl_secs)`, fallback cap
  `DEFAULT_MAX_DIAL_TTL_SECS = 24h`) and `boatramp overlay grant`.
- **Typed request:** `MintDialCap { holder_pubkey: String, scope: String, ttl_secs: u64 }` —
  `holder_pubkey` the DIALING CLIENT's own `ed25519:<hex>` public key (bound into the cap's `cnf`,
  a key the frontend does not hold); `scope` the in-cluster service (e.g. `svc/db`).
- **Typed response:** `DialCapMinted { capability: String }` — the COSE dial cap. A RESULT, never the key.
- **Scope key:** `scope`, matched against the principal's `GrantedRole.target`s; fail-closed if
  targetless. `"*"` wildcard is REFUSED by the grammar (the relayed end-principal path never mints a
  wildcard dial; the offline operator CLI keeps that power). TTL clamped to `max_dial_ttl_secs` ∩
  remaining context freshness.
- **Handler:** `DialSignerHandler { signer, max_dial_ttl_secs, context_max_age_secs }`;
  `permits_authority == OverlayDialSigner`.

## Grammar 3 — `s3ingress.root` → `DeriveS3IngressSecret`

- **Existing authority wrapped.** `S3IngressSecret::derive_secret(access_key_id, session_cti)` — the
  HKDF-SHA256 root loaded from `s3_ingress_secret_file`
  (`crates/boatramp-server/src/s3_ingress/credential.rs`). This is the TRUE `s3ingress.root`
  authority (domain-separated from the KEK and the COSE signer). The scope-bearing `s3-session` COSE
  token is a SEPARATE authority (`token.signer`), so the grammar takes an already-minted session
  token as INPUT and only derives the HMAC secret for it.
- **Typed request:** `DeriveS3IngressSecret { session_token: String, access_key_id: String }` — the
  fleet-signed `s3-session` COSE token + the generated `BRUP…` id.
- **Typed response:** `S3IngressSecretDerived { secret_access_key: String }` — the per-credential
  derived SigV4 HMAC secret (hex). See decision 5: this is the bounded op's RESULT (analogous to
  `mint_token` returning a token), NOT the HKDF ROOT (type-foreclosed).
- **Scope key:** the session token's host-stamped `scope.project` (and `/site`), matched against the
  principal's `GrantedRole.target`s; fail-closed if targetless. The handler holds the fleet PUBLIC
  verify key (non-secret) to `verify_s3_session` the input before deriving.
- **Handler:** `S3IngressRootHandler { secret, session_verify_key }`;
  `permits_authority == S3IngressRoot`.

## Grammar 4 — `cluster.join-signer` → `MintJoinToken`

- **Existing authority wrapped.** `cose::mint_join(ttl, now, signer)` (`KIND_JOIN`) — an UNSCOPED,
  single-use bearer mesh-join token, minted today by `POST /api/cluster/join-token` (admin-gated),
  signed by the auth-root `Issuer`. Single-use is enforced cluster-side (`mesh/join/used/{jti}`).
- **Typed request:** `MintJoinToken { ttl_secs: u64 }`.
- **Typed response:** `JoinTokenMinted { token: String }` — a RESULT, never the key.
- **Scope key (DIFFERENT AXIS — see decision 6):** join is operator-driven NODE bootstrap, not
  per-tenant. The policy-blind crown jewel gates on the principal holding a **global (targetless)
  role whose name == the configured operator role** (default `admin`), fail-closed otherwise. TTL is
  clamped to `max_join_ttl_secs` ∩ remaining context freshness — this also FIXES the standing finding
  that `mint_join` has no server-side TTL max today.
- **Handler:** `JoinSignerHandler { signer, operator_role, max_join_ttl_secs, context_max_age_secs }`;
  `permits_authority == ClusterJoinSigner`.

---

## Design decisions (numbered; safe default chosen) — for Security review

1. **Scope on `GrantedRole.target`, fail-closed if targetless (all resource-scoped grammars).** The
   crown jewel is policy-blind, so it binds the requested resource to the principal's granted
   targets, never expanding roles→rights. Safe default: a principal with no targeted role authorizes
   nothing. **Open for review:** the semantic mapping of each domain resource to a `<project>[/<site>]`
   target (an image `repo`, an overlay service `scope`) is a NAMING CONVENTION the owner/control-plane
   must settle; the grammar matches the strings structurally. Whether the crown jewel should
   ALSO require a specific capability-granting role NAME (which would need a capability marker threaded
   into the end-principal token — the control plane holds the policy, not the crown jewel) is flagged.
   I did NOT gate on role name for grammars 1–3 (policy-blind): the control-plane admin API and the
   context-mint path remain responsible for issuing the principal only the roles/targets it is
   entitled to; the crown jewel enforces target-containment + bounds. This mirrors `mint_token`
   (which checks subset-of-held-roles, not a policy).

2. **image.signer produces a detached signature, not a cosign/OCI artifact.** There is no in-tree
   image-signature VERIFY path (only `cosign verify --key cosign.pub` in CI). Safe default: the
   grammar signs a domain-separated, length-framed `(repo, digest)` message with the dedicated image
   key via `cose::Signer::sign`, returning the raw signature hex. **Open for review:** how this
   detached signature maps onto the cosign/OCI verification path (or whether the privsep image signer
   should emit a cosign-bundle shape) is a verification-path follow-on, out of scope for the SIGN
   grammar. A light `sha256:<hex>` digest-format check is applied (defense-in-depth against signing
   arbitrary bytes framed as a digest).

3. **overlay.dial-signer refuses a `"*"` wildcard scope.** The relayed end-principal grammar mints
   only a concrete, scope-named dial cap; the unbounded-wildcard power stays with the offline
   operator CLI (`boatramp overlay grant`), which the privsep model does not expose over the link.
   Safe default: wildcard ⇒ `Refused`.

4. **overlay.dial-signer's SIGNING key is the control-plane/fleet root, not the overlay seed.** In
   current code the dial cap is signed by the `token.signer` auth-root (`Issuer`) and verified against
   `auth_root_public_key` (exposed as the overlay `trust_root`); the node `OverlaySecret`
   (`OverlayServeConfig.identity`) is only the on-fabric TRANSPORT identity. The `overlay.dial-signer`
   authority doc bundles both, but the minting key today is the root signer. Safe default: the handler
   takes an `Arc<dyn Signer>` (the dial-cap signing key) abstractly — the composition decides which
   key that is. **Open for review:** reconciling the authority's two bundled keys (seed vs. signing
   key) is a composition/key-source decision, flagged, not resolved here.

5. **s3ingress.root returns a DERIVED per-credential secret (not the HKDF ROOT).** The response
   carries the `secret_access_key` HKDF-derived for ONE `(access_key_id, session.cti)` pair, scoped to
   the principal — the bounded op's RESULT, exactly analogous to `mint_token` returning a bearer
   token. The 32-byte HKDF ROOT (`S3IngressSecret.current`) is NEVER representable in any response
   (type-foreclosed). **Flagged explicitly** because a derived credential IS sensitive: the compile
   tripwire arm documents that this is a scoped per-credential result, not the root. The input session
   token's host-stamped scope is additionally bound to the principal's targets, so a frontend RCE can
   only derive secrets for sessions within the principal's authorized project/site.

6. **cluster.join-signer is gated on a global operator role, not a tenant target (axis mismatch).**
   Cluster join is operator-driven node bootstrap with NO tenant/end-principal notion — the F3
   end-principal context model fits it awkwardly. Safe default (conservative, fail-closed): require the
   verified principal to hold a GLOBAL (targetless) `GrantedRole` whose name equals a
   construction-time operator-role constant (default `"admin"`, a node-config value — NOT per-tenant
   policy), and clamp TTL to a `max_join_ttl_secs`. **Open for review:** whether cluster-join belongs
   as an authority-API grammar at all (vs. remaining an operator-only, non-relayed path), and the exact
   operator-role name/mechanism, are flagged for the owner/Security. Also note the authority context is
   hard-pinned to `KIND_ROLE` (`context_pins_kind_to_role`), so a join token can never be relayed back
   as a context — the grammar MINTS join tokens, it never accepts one as authorization.

7. **New TTL max for join (fixes a standing finding).** `mint_join` has NO server-side TTL cap today
   (`[cluster.mesh].join_token_ttl` is dead code) — an admin can mint a near-immortal join token. The
   grammar introduces `max_join_ttl_secs` (default 1h) ∩ context freshness, matching the dial-cap and
   `mint_token` clamps. Surfaced for Security as an improvement over the monolith path.

8. **Code placement.** All four grammars live in `privsep_authority.rs` beside Wave-1 (same shared
   envelope, same compile tripwire, same test module) — the most faithful mirror and the single home
   of the grammar framework. No new module; no visibility widening.

## Follow-on wiring (NOT done here — needs Phase-3 + key sources)

- Register each handler in `boatramp::privsep::run_authority_serve` behind its
  `gate.may_materialize(<authority>)` arm (as `secrets.sealer`/`token.signer` already are), once the
  per-authority key sources are resolved in `privsep_resolve.rs` (image-signer key, overlay dial-cap
  signer, s3-ingress root + fleet verify key, join signer + operator-role config).
- The serve stays inert until the Phase-3 gate (`check_authority_serve_preconditions`: PoP/cnf
  verifier configured AND the link purpose-marked) opens — UNCHANGED by this work.
- Guest-SDK cross-repo follow-on (`boatramp-uchron-shim`): originators must `cnf`-bind + PoP-sign
  these calls (same as Wave-1).
