//! Per-flow access policy for the overlay dial/publish-cap **mint** (overlay follow-up #3).
//!
//! An operator-authored Cedar policy, in its OWN `Overlay` namespace + schema, that gates
//! WHO/WHAT may obtain an overlay **dial** or **publish** capability at the control-plane mint
//! point. It is **separate** from the RBAC authorizer ([`crate::cedar::CompiledCedar`]): the two
//! share **no** entity types, so neither authorizer can satisfy the other, and the flow policy
//! can only ever **deny** a mint the RBAC layer already permitted, or **shrink its TTL** — it
//! never widens authority, never rewrites the minted capability's scope/holder.
//!
//! # Model (the flow schema)
//! - **Principal** `Overlay::Holder` — uid = the holder key (`"<alg>:<hex>"`) the capability will
//!   be bound to. Its attributes `role` / `scope` / `enrolled` are **all optional**: they are
//!   populated ONLY from a verified `overlay-member` credential the caller presents and that is
//!   bound to this holder. A key-only caller (no credential) has **none** of them — an absent
//!   attribute is genuinely absent (not `""`/`false`), so a permit whose `when` reads an absent
//!   attribute simply does not apply (Cedar skips an erroring condition), which is default-deny
//!   safe.
//! - **Action** `Overlay::Action::"dial"` / `"expose"`.
//! - **Resource** `Overlay::Service` — uid = the service name (e.g. `svc/db`); `Service` is a member
//!   of `Overlay::Node` (increment 2 Stage A) — the serving node's overlay identity (the dial
//!   target's `egress_id` / the expose relay's `relay_id`), mint-resolved and threaded in via
//!   [`FlowContext::node`]. A policy may therefore scope a rule to a node
//!   (`resource in Overlay::Node::"<id>"`), a service (`resource == Overlay::Service::"<name>"`), or
//!   both; an unmatched/absent node simply fails to permit (default-deny-safe).
//! - **Context** `{ requestor: String, now: Long, ttl_requested: Long }` — the API principal that
//!   asked (`requestor`), the current time, and the clamped requested TTL. (The owner dropped
//!   source-IP conditions — the fabric reaches services by identity, not IP — so there is no
//!   `src_ip` slot; the grammar has no way to write an IP rule.)
//!
//! # Decision
//! [`FlowPolicy::evaluate`] returns [`Decision::Allow`] (with an optional `ttl_ceiling`) or
//! [`Decision::Deny`]. **Deny-or-shrink-TTL only:** the gate first asks Cedar at the requested
//! TTL; if allowed, there is no shrink (`ttl_ceiling = None`); if denied, it probes a fixed,
//! descending ladder of standard durations **strictly below** the requested TTL and returns the
//! largest one the policy allows (`ttl_ceiling = Some(that)`). Every ceiling it returns is a TTL
//! value that *actually evaluated to Allow* — so a shrink never over-grants, and a policy that
//! denies the flow outright (not just a too-long TTL) still denies at every ladder rung. If no
//! rung is allowed, the flow is denied.
//!
//! # Fail-closed
//! Any construction/evaluation error → [`Decision::Deny`]. Cedar is default-deny within (an empty
//! or permit-less policy denies everything), which is why the *storage* layer treats an absent or
//! empty policy as the feature being **off** (allow) and a stored-but-corrupt policy as deny-all —
//! see [`crate::deploy`] and the server's load path.
//!
//! # Offline non-goals (what this gate is NOT)
//! The gate decides a capability **mint**; the capability it gates is then **offline-verified** by a
//! relay/egress with no control-plane round-trip. So the gate has, by design, **no**:
//! - **real-time revocation** — a tightened or removed policy does not reach already-minted caps;
//!   its effect is bounded by the cap's TTL (set `[overlay] max_dial_ttl_secs` to the longest
//!   revocation latency you can tolerate — that is the knob, not a revocation list);
//! - **rate / quota** — it cannot count or throttle mints (it sees one request at a time);
//! - **concurrent-session** limit — it cannot know how many caps are live for a holder.
//!
//! Consequently the only temporal construct a policy may express is a single `not_after` upper
//! bound (`context.now <= N`) — a hard cutoff after which mints stop. Recurring windows and other
//! complex temporal logic are rejected at store time ([`screen_temporal`]): the gate has no
//! scheduler, and such a rule could not be enforced on a cap already minted inside its window.

#![cfg(feature = "authz")]

use std::collections::{HashMap, HashSet};
use std::error::Error as StdError;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, PolicySet, Request, RestrictedExpression, Schema, ValidationMode, Validator,
};
use serde_json::Value;

/// The Cedar namespace for the flow policy — deliberately distinct from the RBAC namespace
/// (`BR`), so a flow policy can never reference an RBAC entity type and vice versa.
const NS: &str = "Overlay";

/// The flow-policy schema (Cedar schema syntax). All `Holder` attributes are **optional**, so an
/// unpresented attribute is absent (never a defaulted `""`/`false`); `now`/`ttl_requested` are
/// `Long` (seconds) — making `now` a plain scalar means a policy cannot call a datetime extension
/// on it, so the only temporal construct a policy can express is a `context.now` comparison, which
/// the temporal screen further restricts to a single upper bound.
const FLOW_SCHEMA_SRC: &str = r#"
namespace Overlay {
  entity Holder {
    role?: String,
    scope?: String,
    enrolled?: Bool,
  };
  entity Node;
  entity Service in [Node];
  action "dial", "expose" appliesTo {
    principal: [Holder],
    resource: [Service],
    context: {
      requestor: String,
      now: Long,
      ttl_requested: Long,
    }
  };
}
"#;

/// An error compiling/validating an operator-authored flow policy. Surfaced verbatim (status 400)
/// at `PUT /api/overlay/policy` so the operator can fix the text; never reached at evaluate time
/// (a corrupt stored policy fails closed to deny-all at the load path, it is not re-compiled).
#[derive(Debug, thiserror::Error)]
pub enum FlowPolicyError {
    /// The policy text did not parse as a Cedar policy set.
    #[error("policy does not parse: {0}")]
    Parse(String),
    /// The flow schema itself failed to parse — an internal bug (the schema is a constant).
    #[error("internal: flow schema failed to parse: {0}")]
    Schema(String),
    /// The policy parsed but does not type-check against the flow schema (e.g. it references an
    /// unknown entity type — including any RBAC `BR::…` type — or a field not in the schema).
    #[error("policy does not validate against the overlay flow schema: {0}")]
    Validation(String),
    /// The policy uses a temporal (`context.now`) condition that is not a single `not_after`
    /// upper bound (`context.now < N` / `context.now <= N`) — recurring/complex temporal logic is
    /// rejected at store time (REQUIRED #5): the gate has no scheduler, and a policy tightening is
    /// only ever bounded by the capability's TTL, so a recurrence could not be enforced anyway.
    #[error("unsupported temporal condition: {0}")]
    Temporal(String),
}

/// A compiled, validated flow policy — a Cedar [`PolicySet`] plus an [`Authorizer`].
#[derive(Debug)]
pub struct FlowPolicy {
    policies: PolicySet,
    authorizer: Authorizer,
}

/// The holder principal a mint request is evaluated for: the key the capability will be bound to,
/// plus any attributes vouched by a verified, holder-bound `overlay-member` credential. `None`
/// fields are **absent** in the Cedar entity (REQUIRED #3a) — never a defaulted value.
#[derive(Debug, Clone)]
pub struct HolderPrincipal {
    /// The holder key, `"<alg>:<hex>"` — the Cedar `Overlay::Holder` uid.
    pub key: String,
    /// The member role (`node`/`device`/`workload`), from a bound member credential; else absent.
    pub role: Option<String>,
    /// The member service scope, from a bound member credential; else absent.
    pub scope: Option<String>,
    /// Whether a valid, holder-bound member credential was presented (`true`); else absent.
    pub enrolled: Option<bool>,
}

impl HolderPrincipal {
    /// A key-only holder (no member credential): all attributes absent (default-deny safe).
    pub fn key_only(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            role: None,
            scope: None,
            enrolled: None,
        }
    }
}

/// The overlay flow action being gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowAction {
    /// Minting a dial capability (`POST /api/overlay/dial`).
    Dial,
    /// Minting a publish capability (`POST /api/overlay/expose`).
    Expose,
}

impl FlowAction {
    /// The Cedar action id (`Overlay::Action::"<name>"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dial => "dial",
            Self::Expose => "expose",
        }
    }
}

/// The request context (mirrors the schema's `context` record).
#[derive(Debug, Clone)]
pub struct FlowContext {
    /// The API principal that asked for the mint (its subject identity).
    pub requestor: String,
    /// The current time (Unix seconds) — the value a `not_after` bound compares against.
    pub now: u64,
    /// The resolved overlay identity of the node serving the target service — the dial target's
    /// `egress_id` / the expose relay's `relay_id` (increment 2 Stage A). [`FlowPolicy::evaluate`]
    /// attaches it as the `Overlay::Service` entity's ONE parent (`Overlay::Node::"<id>"`), so a
    /// policy may scope a rule to `resource in Overlay::Node::"<id>"`. `None` (e.g. an admin
    /// dry-run preview that supplies no node) ⇒ the Service entity has no parent — a node-scoped
    /// rule then simply never matches (default-deny-safe).
    pub node: Option<String>,
    /// The requested TTL (seconds), already clamped to the server maximum by the caller.
    pub ttl_requested: u64,
}

/// A flow decision: allow (optionally capping the TTL) or deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The mint is permitted. `ttl_ceiling` is `Some(secs)` when the policy pulled the TTL **down**
    /// (deny-at-requested, allow-at-`secs`); `None` when the requested TTL was allowed as-is.
    Allow {
        /// The policy-imposed TTL ceiling (seconds), or `None` for no shrink.
        ttl_ceiling: Option<u64>,
    },
    /// The mint is denied by the flow policy.
    Deny,
}

/// The full outcome of [`FlowPolicy::evaluate`]: the decision plus the deciding policy ids and any
/// evaluation diagnostics. The mint point uses ONLY `decision` (and never surfaces the rest in its
/// 403 — REQUIRED #6); the `POST /api/overlay/policy/test` dry-run surfaces all of it.
#[derive(Debug, Clone)]
pub struct FlowOutcome {
    /// The allow/deny decision (+ any TTL ceiling).
    pub decision: Decision,
    /// The ids of the policies that determined the decision (Cedar's `reason`).
    pub deciding_policies: Vec<String>,
    /// Any evaluation diagnostics (errored conditions, etc.) — NEVER shown in the mint 403.
    pub diagnostics: Vec<String>,
}

/// Parse (but do not type-check) the flow schema. Kept private; only [`FlowPolicy::compile`] needs
/// it. The evaluate path does not use a schema (it builds well-formed entities directly and relies
/// on Cedar's default-deny), mirroring [`crate::cedar`].
fn flow_schema() -> Result<Schema, FlowPolicyError> {
    Schema::from_str(FLOW_SCHEMA_SRC).map_err(|e| FlowPolicyError::Schema(e.to_string()))
}

impl FlowPolicy {
    /// Compile + validate an operator-authored flow policy (`src`, Cedar policy text):
    /// 1. parse it as a [`PolicySet`],
    /// 2. reject recurring/complex temporal conditions (only a single `not_after` upper bound),
    /// 3. type-check it against the flow schema in strict mode.
    ///
    /// Any failure is returned (the `PUT` surfaces it 400); a stored policy is compiled through
    /// this, so a policy that fails here can never reach the gate.
    pub fn compile(src: &str) -> Result<Self, FlowPolicyError> {
        let policies =
            PolicySet::from_str(src).map_err(|e| FlowPolicyError::Parse(e.to_string()))?;
        // REQUIRED #5 — structural (AST/EST) temporal screen, BEFORE type-checking, so a policy
        // with disallowed temporal logic is rejected on its own terms with a clear message.
        screen_temporal(&policies)?;
        let schema = flow_schema()?;
        let result = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        if !result.validation_passed() {
            let errs: Vec<String> = result
                .validation_errors()
                .map(ToString::to_string)
                .collect();
            return Err(FlowPolicyError::Validation(if errs.is_empty() {
                "validation failed".to_string()
            } else {
                errs.join("; ")
            }));
        }
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Evaluate a mint request against the policy: **deny-or-shrink-TTL only**. First decide at the
    /// requested TTL; if allowed, no shrink. If denied, probe the descending TTL ladder below the
    /// requested value and return the largest allowed rung (each rung is re-evaluated, so a
    /// returned ceiling is always a TTL the policy actually allows). Fail-closed throughout.
    pub fn evaluate(
        &self,
        principal: &HolderPrincipal,
        action: FlowAction,
        service: &str,
        ctx: &FlowContext,
    ) -> FlowOutcome {
        let top = self.decide_at(principal, action, service, ctx, ctx.ttl_requested);
        if matches!(top.decision, CedarDecision::Allow) {
            return FlowOutcome {
                decision: Decision::Allow { ttl_ceiling: None },
                deciding_policies: top.reasons,
                diagnostics: top.diags,
            };
        }
        for cand in ttl_ladder(ctx.ttl_requested) {
            let d = self.decide_at(principal, action, service, ctx, cand);
            if matches!(d.decision, CedarDecision::Allow) {
                return FlowOutcome {
                    decision: Decision::Allow {
                        ttl_ceiling: Some(cand),
                    },
                    deciding_policies: d.reasons,
                    diagnostics: d.diags,
                };
            }
        }
        FlowOutcome {
            decision: Decision::Deny,
            deciding_policies: top.reasons,
            diagnostics: top.diags,
        }
    }

    /// One Cedar decision at a concrete TTL. Fail-closed: any construction error yields a `Deny`
    /// decision (with the error recorded as a diagnostic) rather than propagating.
    fn decide_at(
        &self,
        principal: &HolderPrincipal,
        action: FlowAction,
        service: &str,
        ctx: &FlowContext,
        ttl: u64,
    ) -> Decided {
        match self.try_decide(principal, action, service, ctx, ttl) {
            Ok(d) => d,
            Err(e) => Decided {
                decision: CedarDecision::Deny,
                reasons: Vec::new(),
                diags: vec![format!("flow-policy evaluation error: {e}")],
            },
        }
    }

    /// The fallible core of [`decide_at`](Self::decide_at): build the entities + request and run
    /// the authorizer. Kept separate so any construction fault is mapped to a fail-closed deny.
    fn try_decide(
        &self,
        principal: &HolderPrincipal,
        action: FlowAction,
        service: &str,
        ctx: &FlowContext,
        ttl: u64,
    ) -> Result<Decided, Box<dyn StdError>> {
        let principal_uid = uid("Holder", &principal.key);
        let action_uid = uid("Action", action.as_str());
        let resource_uid = uid("Service", service);

        // Optional holder attributes: present ONLY when vouched by a bound member credential; an
        // absent attribute is never inserted, so a `when { principal.<attr> … }` condition errors
        // and the permit does not apply (default-deny safe) — REQUIRED #3a.
        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        if let Some(role) = &principal.role {
            attrs.insert(
                "role".into(),
                RestrictedExpression::new_string(role.clone()),
            );
        }
        if let Some(scope) = &principal.scope {
            attrs.insert(
                "scope".into(),
                RestrictedExpression::new_string(scope.clone()),
            );
        }
        if let Some(enrolled) = principal.enrolled {
            attrs.insert("enrolled".into(), RestrictedExpression::new_bool(enrolled));
        }
        let principal_entity = Entity::new(principal_uid.clone(), attrs, HashSet::new())?;
        // Node-scoping (increment 2 Stage A): when the mint gate resolved a concrete serving node
        // (`ctx.node` — the dial target's `egress_id` / the expose relay's `relay_id`), attach
        // `Overlay::Node::"<id>"` as the Service entity's ONE parent, so a policy can scope a rule
        // with `resource in Overlay::Node::"<id>"` (and still combine with / fall back to a
        // `resource == Overlay::Service::"<name>"` check). Absent ⇒ no parent — a node-scoped rule
        // then simply never matches (composes for free with the gate's default-deny-safe posture).
        let mut resource_parents = HashSet::new();
        let mut node_entity = None;
        if let Some(node_id) = &ctx.node {
            let node_uid = uid("Node", node_id);
            node_entity = Some(Entity::new(
                node_uid.clone(),
                HashMap::new(),
                HashSet::new(),
            )?);
            resource_parents.insert(node_uid);
        }
        let resource_entity = Entity::new(resource_uid.clone(), HashMap::new(), resource_parents)?;
        // Both action entities (no hierarchy) so an `action in [Overlay::Action::"dial", …]` form
        // resolves against known entities as well as the `action == …` form.
        let dial = Entity::new(uid("Action", "dial"), HashMap::new(), HashSet::new())?;
        let expose = Entity::new(uid("Action", "expose"), HashMap::new(), HashSet::new())?;
        let mut all_entities = vec![principal_entity, resource_entity, dial, expose];
        all_entities.extend(node_entity);
        let entities = Entities::from_entities(all_entities, None)?;

        let pairs = vec![
            (
                "requestor".to_string(),
                RestrictedExpression::new_string(ctx.requestor.clone()),
            ),
            (
                "now".to_string(),
                RestrictedExpression::new_long(clamp_i64(ctx.now)),
            ),
            (
                "ttl_requested".to_string(),
                RestrictedExpression::new_long(clamp_i64(ttl)),
            ),
        ];
        let context = Context::from_pairs(pairs)?;

        let request = Request::new(principal_uid, action_uid, resource_uid, context, None)?;
        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);
        let reasons = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        let diags = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        Ok(Decided {
            decision: response.decision(),
            reasons,
            diags,
        })
    }
}

/// The result of one Cedar decision (internal).
struct Decided {
    decision: CedarDecision,
    reasons: Vec<String>,
    diags: Vec<String>,
}

/// The descending TTL ladder probed when the requested TTL is denied: standard durations strictly
/// **below** `requested`, from longest to shortest. A shrink therefore snaps to the nearest
/// standard duration at or below the policy's effective cap — always ≤ requested (never a widen),
/// and every rung is re-evaluated before being returned, so a non-monotonic policy can never yield
/// a ceiling it would actually deny.
fn ttl_ladder(requested: u64) -> impl Iterator<Item = u64> {
    const STEPS: [u64; 17] = [
        86400, 43200, 28800, 21600, 14400, 7200, 3600, 1800, 900, 600, 300, 120, 60, 30, 10, 5, 1,
    ];
    STEPS.into_iter().filter(move |&s| s < requested)
}

/// Clamp a `u64` time/duration to the `i64` Cedar `Long` domain (saturating) — a value past
/// `i64::MAX` is nonsensical here, but we never want an overflow to flip a comparison.
fn clamp_i64(v: u64) -> i64 {
    v.min(i64::MAX as u64) as i64
}

/// Construct an `Overlay::<type>::"<id>"` entity uid.
fn uid(type_name: &str, id: &str) -> EntityUid {
    let tn =
        EntityTypeName::from_str(&format!("{NS}::{type_name}")).expect("static Cedar type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

// ===== Temporal screen (REQUIRED #5) =========================================================

/// Reject any policy whose conditions use a `context.now` term in anything other than a **single**
/// `not_after` upper bound (`context.now < N` or `context.now <= N`, with `N` an integer literal).
/// This is a STRUCTURAL screen over Cedar's EST (the policy AST serialized to JSON) — not a text
/// scan — so it sees the real operators/operands, and it fails **closed**: a `now` term anywhere
/// but the allowed shape, or more than one such bound, is rejected.
///
/// (Datetime *extension* calls are already impossible: the schema types `now` as a `Long`, so
/// the validator rejects a `.offset()`/`durationSince()`-style call on it. This screen closes the
/// remaining door — arithmetic on `now`, lower/equality bounds, and recurrence attempts.)
fn screen_temporal(policies: &PolicySet) -> Result<(), FlowPolicyError> {
    for p in policies.policies() {
        let est = p
            .to_json()
            .map_err(|e| FlowPolicyError::Temporal(format!("cannot inspect policy: {e}")))?;
        let mut bound_count = 0usize;
        if let Some(conds) = est.get("conditions").and_then(Value::as_array) {
            for c in conds {
                if let Some(body) = c.get("body") {
                    walk_temporal(body, &mut bound_count)?;
                }
            }
        }
        if bound_count > 1 {
            return Err(FlowPolicyError::Temporal(format!(
                "policy `{}` has more than one `context.now` bound; only a single `not_after` \
                 upper bound (`context.now < N` or `context.now <= N`) is allowed",
                p.id()
            )));
        }
    }
    Ok(())
}

/// Recursively walk an EST expression. Counts the allowed `context.now <(=) <literal>` bounds; any
/// other appearance of a `context.now` term is a hard reject.
fn walk_temporal(v: &Value, bound_count: &mut usize) -> Result<(), FlowPolicyError> {
    // The ONLY allowed temporal shape: `{"<"|"<=": {"left": context.now, "right": <int literal>}}`.
    for op in ["<", "<="] {
        if let Some(inner) = v.get(op) {
            let left = inner.get("left");
            let right = inner.get("right");
            if left.is_some_and(is_now_attr) && right.is_some_and(is_int_literal) {
                // Defensive: the literal operand must not itself hide a `now` term.
                if right.is_some_and(contains_now) {
                    return Err(temporal_reject());
                }
                *bound_count += 1;
                return Ok(()); // consumed — do not descend into `left` (the single allowed `now`)
            }
        }
    }
    // A `context.now` term outside the allowed upper-bound shape → reject (fail closed).
    if is_now_attr(v) {
        return Err(temporal_reject());
    }
    match v {
        Value::Object(map) => {
            for child in map.values() {
                walk_temporal(child, bound_count)?;
            }
        }
        Value::Array(arr) => {
            for child in arr {
                walk_temporal(child, bound_count)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The standard temporal rejection error.
fn temporal_reject() -> FlowPolicyError {
    FlowPolicyError::Temporal(
        "`context.now` may appear only as a single upper bound (`context.now < N` or \
         `context.now <= N`, N an integer); lower/equality bounds, arithmetic, and multiple \
         bounds are not supported"
            .to_string(),
    )
}

/// Whether an EST node is a `.now` attribute access (`{".": {"left": …, "attr": "now"}}`).
fn is_now_attr(v: &Value) -> bool {
    v.get(".")
        .and_then(|g| g.get("attr"))
        .and_then(Value::as_str)
        == Some("now")
}

/// Whether an EST node is an integer literal (`{"Value": <int>}`).
fn is_int_literal(v: &Value) -> bool {
    v.get("Value")
        .map(|x| x.is_i64() || x.is_u64())
        .unwrap_or(false)
}

/// Whether any `.now` attribute access appears anywhere in the subtree.
fn contains_now(v: &Value) -> bool {
    if is_now_attr(v) {
        return true;
    }
    match v {
        Value::Object(map) => map.values().any(contains_now),
        Value::Array(arr) => arr.iter().any(contains_now),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLDER: &str = "ed25519:aa";

    fn ctx(ttl: u64) -> FlowContext {
        FlowContext {
            requestor: "tok-1".into(),
            now: 1_000_000,
            node: None,
            ttl_requested: ttl,
        }
    }

    fn key_only() -> HolderPrincipal {
        HolderPrincipal::key_only(HOLDER)
    }

    fn with_role(role: &str, scope: &str) -> HolderPrincipal {
        HolderPrincipal {
            key: HOLDER.into(),
            role: Some(role.into()),
            scope: Some(scope.into()),
            enrolled: Some(true),
        }
    }

    #[test]
    fn permit_all_allows_requested_ttl_no_shrink() {
        let fp = FlowPolicy::compile("permit(principal, action, resource);").unwrap();
        let out = fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600));
        assert_eq!(out.decision, Decision::Allow { ttl_ceiling: None });
    }

    #[test]
    fn empty_permit_set_denies_all() {
        // A permit-less set is default-deny within Cedar (the storage layer treats absent/empty as
        // "feature off"; this proves a *stored permit-less* policy denies, not allows).
        let fp = FlowPolicy::compile("forbid(principal, action, resource);").unwrap();
        let out = fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600));
        assert_eq!(out.decision, Decision::Deny);
    }

    #[test]
    fn key_only_cannot_satisfy_a_role_gated_permit() {
        // A permit requiring a role: a key-only holder (role ABSENT) must NOT match (REQUIRED #3a).
        // Optional-attr access is `has`-guarded (strict validation requires it); an absent attr
        // makes `principal has role` false, so the permit does not apply — default-deny safe.
        let src = r#"permit(principal, action, resource)
            when { principal has enrolled && principal.enrolled
                   && principal has role && principal.role == "node" };"#;
        let fp = FlowPolicy::compile(src).unwrap();
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600))
                .decision,
            Decision::Deny,
            "a key-only (no-credential) holder must not satisfy a role-gated permit"
        );
        // The SAME request with a bound member credential (role present) is allowed.
        assert_eq!(
            fp.evaluate(
                &with_role("node", "svc/db"),
                FlowAction::Dial,
                "svc/db",
                &ctx(3600)
            )
            .decision,
            Decision::Allow { ttl_ceiling: None }
        );
    }

    #[test]
    fn absent_attr_condition_is_non_matching_not_defaulted() {
        // REQUIRED #3a — an absent optional attribute is genuinely ABSENT, never a defaulted value.
        // Strict validation enforces this structurally: an UNGUARDED optional-attr access is
        // rejected at compile time, so a policy can never silently read a defaulted `""`/`false`.
        let unguarded = r#"permit(principal, action, resource) when { principal.role == "" };"#;
        assert!(
            matches!(
                FlowPolicy::compile(unguarded),
                Err(FlowPolicyError::Validation(_))
            ),
            "an unguarded optional-attr access must be rejected (forces a `has` guard, so an \
             absent attr is never defaulted)"
        );
        // The GUARDED form is accepted, and a key-only holder (role ABSENT) does not match it.
        let guarded = r#"permit(principal, action, resource) when { principal has role && principal.role == "node" };"#;
        let fp = FlowPolicy::compile(guarded).unwrap();
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600))
                .decision,
            Decision::Deny,
            "an absent attribute must make its `has` guard false (non-matching), never defaulted"
        );
    }

    #[test]
    fn ttl_shrinks_when_requested_exceeds_policy_cap() {
        // Allowed only at ttl <= 300: a 3600s request is pulled DOWN to the 300 ladder rung.
        let src = r#"permit(principal, action, resource) when { context.ttl_requested <= 300 };"#;
        let fp = FlowPolicy::compile(src).unwrap();
        let out = fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600));
        assert_eq!(
            out.decision,
            Decision::Allow {
                ttl_ceiling: Some(300)
            }
        );
        // A request already within the cap is allowed as-is (no shrink).
        let out2 = fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(300));
        assert_eq!(out2.decision, Decision::Allow { ttl_ceiling: None });
    }

    #[test]
    fn hard_deny_is_never_rescued_by_a_shorter_ttl() {
        // A forbid that does not depend on ttl denies at every ladder rung → hard Deny.
        let src = r#"permit(principal, action, resource);
            forbid(principal, action, resource) when { resource == Overlay::Service::"svc/db" };"#;
        let fp = FlowPolicy::compile(src).unwrap();
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600))
                .decision,
            Decision::Deny
        );
        // A different service is still allowed.
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/other", &ctx(3600))
                .decision,
            Decision::Allow { ttl_ceiling: None }
        );
    }

    #[test]
    fn action_and_resource_scope_distinguish_dial_from_expose() {
        let src = r#"permit(principal, action == Overlay::Action::"dial", resource);"#;
        let fp = FlowPolicy::compile(src).unwrap();
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &ctx(3600))
                .decision,
            Decision::Allow { ttl_ceiling: None }
        );
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Expose, "svc/db", &ctx(3600))
                .decision,
            Decision::Deny,
            "a dial-only permit must not authorize an expose mint"
        );
    }

    #[test]
    fn node_scoped_permit_matches_resolved_node() {
        // A policy scoped to node "n-A": a mint whose RESOLVED node IS "n-A" must Allow; a
        // DIFFERENT resolved node ("n-B") must Deny — proving `ctx.node` reaches the Service
        // entity's Cedar parent.
        let src = r#"permit(principal, action, resource in Overlay::Node::"n-A");"#;
        let fp = FlowPolicy::compile(src).unwrap();
        let mut c = ctx(3600);
        c.node = Some("n-A".into());
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &c)
                .decision,
            Decision::Allow { ttl_ceiling: None },
            "a node-scoped permit must match when the resolved node IS the scoped node"
        );
        c.node = Some("n-B".into());
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &c)
                .decision,
            Decision::Deny,
            "a node-scoped permit must NOT match a DIFFERENT resolved node"
        );
    }

    #[test]
    fn rbac_entity_types_do_not_validate_against_the_flow_schema() {
        // A policy referencing the RBAC namespace (`BR::…`) must fail to compile — the two
        // authorizers share no entity types (separate-namespace invariant).
        let err =
            FlowPolicy::compile(r#"permit(principal in BR::Role::"admin", action, resource);"#)
                .unwrap_err();
        assert!(
            matches!(
                err,
                FlowPolicyError::Validation(_) | FlowPolicyError::Parse(_)
            ),
            "an RBAC-namespace policy must not validate against the flow schema, got {err:?}"
        );
    }

    #[test]
    fn node_resource_isolated_from_rbac() {
        // The new `Overlay::Node` resource-group type lives ONLY in the flow schema's own
        // namespace — a policy referencing `BR::Node` (the RBAC namespace) must still fail to
        // validate (two-authorizer isolation extends to the new type, not just Holder/Service).
        let err = FlowPolicy::compile(r#"permit(principal, action, resource in BR::Node::"n-A");"#)
            .unwrap_err();
        assert!(
            matches!(
                err,
                FlowPolicyError::Validation(_) | FlowPolicyError::Parse(_)
            ),
            "a BR::Node-referencing policy must not validate against the flow schema, got {err:?}"
        );
    }

    #[test]
    fn single_not_after_upper_bound_is_allowed() {
        for src in [
            r#"permit(principal, action, resource) when { context.now <= 2000000 };"#,
            r#"permit(principal, action, resource) when { context.now < 2000000 };"#,
        ] {
            assert!(
                FlowPolicy::compile(src).is_ok(),
                "a single not_after upper bound must be accepted: {src}"
            );
        }
    }

    #[test]
    fn complex_or_recurring_temporal_conditions_are_rejected() {
        for src in [
            // A lower bound (not_before).
            r#"permit(principal, action, resource) when { context.now > 1000 };"#,
            // An equality bound.
            r#"permit(principal, action, resource) when { context.now == 1000 };"#,
            // Arithmetic on now (a recurrence attempt).
            r#"permit(principal, action, resource) when { context.now - 1000 < 2000 };"#,
            // Two bounds (a window).
            r#"permit(principal, action, resource) when { context.now <= 2000 && context.now <= 3000 };"#,
            // now compared to a non-literal.
            r#"permit(principal, action, resource) when { context.now < context.ttl_requested };"#,
        ] {
            assert!(
                matches!(FlowPolicy::compile(src), Err(FlowPolicyError::Temporal(_))),
                "a complex/recurring temporal condition must be rejected: {src}"
            );
        }
    }

    #[test]
    fn a_not_after_bound_gates_by_time() {
        let src = r#"permit(principal, action, resource) when { context.now <= 2000000 };"#;
        let fp = FlowPolicy::compile(src).unwrap();
        // Before the cutoff: allowed.
        let mut c = ctx(300);
        c.now = 1_000_000;
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &c)
                .decision,
            Decision::Allow { ttl_ceiling: None }
        );
        // After the cutoff: denied (and no ttl shrink can rescue it — it is time, not ttl).
        c.now = 3_000_000;
        assert_eq!(
            fp.evaluate(&key_only(), FlowAction::Dial, "svc/db", &c)
                .decision,
            Decision::Deny
        );
    }

    #[test]
    fn malformed_policy_fails_to_compile() {
        assert!(matches!(
            FlowPolicy::compile("this is not cedar"),
            Err(FlowPolicyError::Parse(_))
        ));
    }
}
