//! Cedar-based control-plane authorization (the `authz` feature).
//!
//! Generates a Cedar [`PolicySet`] from the operator-editable [`AuthzPolicy`] and
//! decides each request with `Authorizer::is_authorized` over transient,
//! per-request entities, preserving the exact RBAC semantics of [`AuthzPolicy::rights_for`] +
//! [`RightSet::allows`](boatramp_types::authz::RightSet::allows) — enforced by the
//! differential test at the bottom of this module (the faithfulness gate).
//!
//! Model:
//! - **Principal** = `BR::Principal::"self"`, a member of one `BR::Role::"<name>"`
//!   group per granted role, carrying a `<role>_sites : Set<String>` attribute for
//!   every target-scoped role (the raw grant targets — a `"<project>/<site>"` for a
//!   site role, a bare `"<project>"` for a project role; always present, possibly empty).
//! - **Resource** = `BR::<Resource>::"<id>"`. The target-scoped resources carry
//!   attributes the scoping guards read: `BR::Site` a `name` (the full `project/site`)
//!   and a `project` (its project segment); `BR::Project` and `BR::Secrets` a `name`
//!   (the project).
//! - **Action** = `BR::Action::"<action>"` with `read`/`write`/`deploy` parented to
//!   `admin`, so an `admin` grant (`action in [BR::Action::"admin"]`) covers every
//!   action — mirroring `Right::satisfies`' "granted Admin ⇒ any action".
//! - **Target scoping**, mirroring `target_matches`: a `RoleTarget` template guards on
//!   `principal.<role>_sites.contains(resource.name)` (exact `project/site` or project);
//!   a `ProjectWildcard` template (a project role's per-site right) guards on
//!   `…contains(resource.project)`, matching every site whose project segment is granted;
//!   an `AnyTarget` template emits no `when` (a global wildcard).
//!
//! Default-deny throughout: any entity/request construction error yields `false`.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};

use boatramp_types::authz::{Action, AuthzPolicy, GrantedRole, Resource, Right, TargetScope};

/// The Cedar namespace for all boatramp authorization entities.
const NS: &str = "BR";

/// Error compiling an [`AuthzPolicy`] into a Cedar [`PolicySet`].
#[derive(Debug, thiserror::Error)]
pub enum CedarError {
    /// A role name is not a safe Cedar identifier (`[A-Za-z_][A-Za-z0-9_]*`); it
    /// would break the generated policy text (both the `Role::"<name>"` literal and
    /// the `<name>_sites` attribute path). Rejected on compile, deny-safe.
    #[error("unsafe role name: {0:?}")]
    RoleName(String),
    /// The generated policy text failed to parse — an internal generator bug.
    #[error("policy generation failed: {0}")]
    Policy(String),
}

/// A richer authorization outcome than a bare `bool`: the allow/deny decision plus
/// the Cedar diagnostics — which policies *determined* it and any per-policy
/// evaluation errors. Shared by boatramp's own RBAC path ([`CompiledCedar`]) and the
/// generic adoptable entry ([`generic::CompiledPolicySet`]), so both run the one
/// engine and both can surface *why* a request was allowed or denied (U11-4c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzDecision {
    /// Whether the decision is `Allow` (a `Deny`, including the default-deny when no
    /// policy matched, is `false`).
    pub allow: bool,
    /// The ids of the policies that **determined** the decision (Cedar's `reason`
    /// set): the satisfied `permit`s behind an `Allow`, or the `forbid`s behind a
    /// `Deny`. Empty on a default-deny (no policy applied). Sorted for a stable order
    /// (`reason` is an unordered set).
    pub determining_policies: Vec<String>,
    /// Human-readable per-policy evaluation errors (Cedar's `errors`). A policy that
    /// errors mid-evaluation (e.g. a missing attribute) is *skipped* by Cedar rather
    /// than failing the whole request, so these are diagnostics — surfaced so a
    /// consumer can log/alert on a policy that is silently not applying — not a hard
    /// authorization failure.
    pub errors: Vec<String>,
}

impl AuthzDecision {
    /// Project a Cedar `Response` into the crate's decision shape (allow/deny +
    /// determining policies + diagnostics).
    fn from_response(resp: &cedar_policy::Response) -> Self {
        let mut determining_policies: Vec<String> = resp
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        determining_policies.sort();
        let errors: Vec<String> = resp
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        Self {
            allow: matches!(resp.decision(), Decision::Allow),
            determining_policies,
            errors,
        }
    }
}

/// The one Cedar decision engine shared by boatramp's own RBAC authorizer
/// ([`CompiledCedar`]) and the generic adoptable entry
/// ([`generic::CompiledPolicySet`]): a **compile-once** [`PolicySet`] + [`Authorizer`],
/// evaluated many times. Nothing here re-parses or recompiles policy text per call —
/// that is the whole point (U11-4b: boatramp's hot path previously recompiled the
/// `PolicySet` from generated Cedar text on *every* request; see
/// `boatramp-server`'s `AuthInner::policy` cache). Both callers build their
/// per-request [`Request`] + [`Entities`] — the **minimal differing seam**: boatramp
/// projects its fixed RBAC vocabulary into entities, a generic consumer brings its
/// own — and hand them to the SAME [`evaluate`](Self::evaluate), so uchron adopts the
/// exact decision path boatramp runs (U11-4d: one engine, not two parallel copies).
#[derive(Debug)]
struct CedarEngine {
    policies: PolicySet,
    authorizer: Authorizer,
}

impl CedarEngine {
    /// Wrap an already-parsed [`PolicySet`] in a fresh [`Authorizer`]. The expensive
    /// work (parsing/compiling the policy text) happened at the caller's `compile`
    /// step; `Authorizer::new` is cheap and stateless.
    fn new(policies: PolicySet) -> Self {
        Self {
            policies,
            authorizer: Authorizer::new(),
        }
    }

    /// Evaluate one already-built request + entity store against the compiled
    /// policies, returning the rich [`AuthzDecision`]. This is the single line both
    /// the RBAC and generic paths funnel through.
    fn evaluate(&self, request: &Request, entities: &Entities) -> AuthzDecision {
        AuthzDecision::from_response(&self.authorizer.is_authorized(
            request,
            &self.policies,
            entities,
        ))
    }
}

/// A compiled Cedar authorizer generated from an [`AuthzPolicy`].
pub struct CompiledCedar {
    /// The shared, compile-once decision engine (the same type the generic entry
    /// runs on — U11-4d).
    engine: CedarEngine,
    /// Roles carrying at least one target-scoped template — the principal gets a
    /// `<role>_sites` attribute for each (always present, possibly empty), so the
    /// site-scoping `when` guards never hit a missing attribute.
    scoped_roles: Vec<String>,
}

impl CompiledCedar {
    /// Compile an [`AuthzPolicy`] into a Cedar [`PolicySet`].
    ///
    /// Rejects role names that are not safe Cedar identifiers (they would allow
    /// injection into the generated policy text). The generated text is parsed eagerly so a
    /// generator bug surfaces here rather than at authorize time.
    pub fn compile(policy: &AuthzPolicy) -> Result<Self, CedarError> {
        for name in policy.roles.keys() {
            if !is_safe_ident(name) {
                return Err(CedarError::RoleName(name.clone()));
            }
        }
        let text = generate_policy_text(policy);
        let policies = PolicySet::from_str(&text)
            .map_err(|e| CedarError::Policy(format!("{e}\n--- text ---\n{text}")))?;
        let scoped_roles = policy
            .roles
            .iter()
            .filter(|(_, templates)| templates.iter().any(|t| t.scope.is_targeted()))
            .map(|(name, _)| name.clone())
            .collect();
        Ok(Self {
            engine: CedarEngine::new(policies),
            scoped_roles,
        })
    }

    /// Decide whether a principal holding `roles` may perform `required`.
    ///
    /// Default-deny: any entity/request construction error yields `false`.
    pub fn authorize(&self, roles: &[GrantedRole], required: &Right) -> bool {
        self.decide(roles, required).is_ok_and(|d| d.allow)
    }

    /// The fallible core of [`authorize`](Self::authorize): build the per-request
    /// entities + request and run the SHARED [`CedarEngine`]. Kept private but
    /// exercised directly (unwrapped) by the differential test so construction bugs
    /// are loud. Returns the rich [`AuthzDecision`]; `authorize` projects its `allow`.
    fn decide(
        &self,
        roles: &[GrantedRole],
        required: &Right,
    ) -> Result<AuthzDecision, Box<dyn Error>> {
        let principal_uid = uid("Principal", "self");
        let action_uid = uid("Action", required.action.as_str());
        let (resource_uid, resource) = resource_entity(required)?;
        let principal = principal_entity(&principal_uid, roles, &self.scoped_roles)?;

        let mut entities: Vec<Entity> = vec![principal, resource];
        entities.extend(action_entities()?);
        // Empty group entities for each granted role, so `principal in Role::"x"`
        // resolves against a known (leaf) entity rather than a dangling reference.
        for r in roles {
            if is_safe_ident(&r.name) {
                entities.push(Entity::new(
                    uid("Role", &r.name),
                    HashMap::new(),
                    HashSet::new(),
                )?);
            }
        }
        // Schema-free (`None`): boatramp's RBAC vocabulary is generated and internally
        // consistent, so it does not validate requests against a Cedar schema — the
        // generic path (which takes a consumer's own schema) is the one that passes
        // `Some(schema)`. This is the minimal differing seam from the shared engine.
        let entities = Entities::from_entities(entities, None)?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            Context::empty(),
            None,
        )?;
        Ok(self.engine.evaluate(&request, &entities))
    }
}

/// Generate the Cedar policy text for an [`AuthzPolicy`]: one `permit` per role ×
/// right-template. Role names are pre-validated by [`is_safe_ident`], so the
/// `Role::"<name>"` literal and `<name>_sites` attribute path are injection-safe.
fn generate_policy_text(policy: &AuthzPolicy) -> String {
    let mut out = String::new();
    for (role, templates) in &policy.roles {
        for t in templates {
            let action = action_scope(t.action);
            let resource_ty = resource_type(t.resource);
            let guard = match t.scope {
                // Bind the request's target to the role's granted targets, mirroring
                // `target_matches(Some(g), required)`. `Set::contains` is Cedar set
                // membership (`in` is entity-hierarchy membership — wrong here). The
                // granted set holds the raw grant target (a `"<project>/<site>"` for a
                // site role, or a bare `"<project>"` for a project role).
                TargetScope::RoleTarget => {
                    format!(" when {{ principal.{role}_sites.contains(resource.name) }}")
                }
                // A project role's per-site right: match the request's site by its
                // *project* segment against the granted project names, mirroring the
                // `"<project>/*"` wildcard in `target_matches`. Reads the Site
                // resource's `project` attribute (only Site permits use this scope).
                TargetScope::ProjectWildcard => {
                    format!(" when {{ principal.{role}_sites.contains(resource.project) }}")
                }
                // Wildcard grant: matches any resource of that type.
                TargetScope::AnyTarget => String::new(),
            };
            out.push_str(&format!(
                "permit(principal in {NS}::Role::\"{role}\", {action}, resource is {NS}::{resource_ty}){guard};\n"
            ));
        }
    }
    out
}

/// The action clause for a permit. `Admin` is the superuser action: `action in
/// [admin]` matches any request action, because `read`/`write`/`deploy` are
/// parented to `admin` in the per-request action entities — mirroring
/// `Right::satisfies`' "granted Admin ⇒ satisfies any action".
fn action_scope(action: Action) -> String {
    match action {
        Action::Admin => format!("action in [{NS}::Action::\"admin\"]"),
        other => format!("action == {NS}::Action::\"{}\"", other.as_str()),
    }
}

/// The Cedar entity type name (CamelCase) for a [`Resource`].
fn resource_type(resource: Resource) -> &'static str {
    match resource {
        Resource::Site => "Site",
        Resource::Project => "Project",
        Resource::Secrets => "Secrets",
        Resource::Blobs => "Blobs",
        Resource::BlobUpload => "BlobUpload",
        Resource::Tokens => "Tokens",
        Resource::Certs => "Certs",
        Resource::Cache => "Cache",
        Resource::System => "System",
        Resource::Overlay => "Overlay",
        Resource::Messaging => "Messaging",
    }
}

/// Build the principal entity: its `Role::"<name>"` group memberships (parents) and
/// one `<role>_sites` set attribute per target-scoped role in the policy (the site
/// names it holds that role on — always present so the `when` guards never fault).
fn principal_entity(
    principal_uid: &EntityUid,
    roles: &[GrantedRole],
    scoped_roles: &[String],
) -> Result<Entity, Box<dyn Error>> {
    let mut parents: HashSet<EntityUid> = HashSet::new();
    for r in roles {
        if is_safe_ident(&r.name) {
            parents.insert(uid("Role", &r.name));
        }
    }
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
    for role in scoped_roles {
        let sites = roles
            .iter()
            .filter(|r| &r.name == role)
            .filter_map(|r| r.target.as_ref())
            // Fail-closed A8 backstop, mirrored on the Cedar side so the two engines
            // stay faithful: a non-conforming grant target (a pre-v0.7.0 or offline
            // `${PROJECT}`/`*`/… target) never enters the `<role>_sites` set, so no
            // `…_sites.contains(resource.name)` guard can match it — exactly as
            // `target_matches` denies it in the pure oracle.
            .filter(|t| boatramp_types::project::is_conforming_role_target(t))
            .map(|t| RestrictedExpression::new_string(t.clone()));
        attrs.insert(
            format!("{role}_sites"),
            RestrictedExpression::new_set(sites),
        );
    }
    Ok(Entity::new(principal_uid.clone(), attrs, parents)?)
}

/// Build the resource entity for a required right. The target-scoped resources
/// carry attributes the scoping guards read: `Site` is keyed by its full
/// `"<project>/<site>"` target and carries both `name` (the full target, for a site
/// grant) and `project` (its project segment, for a project-wildcard grant); `Project`
/// and `Secrets` are keyed + `name`-attributed by the project. Other resources are
/// global singletons keyed by their type term, needing no attributes.
fn resource_entity(required: &Right) -> Result<(EntityUid, Entity), Box<dyn Error>> {
    let ty = resource_type(required.resource);
    let (id, attrs) = match required.resource {
        // `Site` is keyed by its full `"<project>/<site>"` target with both `name` (for a site
        // grant's `RoleTarget` guard) and `project` (for a project-wildcard grant's guard).
        // `Messaging` is hierarchical the SAME way — its target is the project-qualified topic key
        // `"<project>/<topic>"` (or the project-wildcard `"<project>/*"` for ack/nack) — so it carries
        // the identical `name` + `project` attributes. Today only `admin` grants `Messaging` (an
        // `AnyTarget` permit with no guard), but keying it here means a future project-wildcard
        // `Messaging·Read` grant (a per-project consumer role) authorizes correctly via the
        // `resource.project` guard, exactly as a project role's site-wildcard does.
        Resource::Site | Resource::Messaging => {
            let name = required.target.clone().unwrap_or_default();
            let project = boatramp_types::authz::project_of(&name).to_string();
            let mut a = HashMap::new();
            a.insert(
                "name".to_string(),
                RestrictedExpression::new_string(name.clone()),
            );
            a.insert(
                "project".to_string(),
                RestrictedExpression::new_string(project),
            );
            (name, a)
        }
        // Target-scoped, keyed + `name`-attributed by the raw grant target, so the
        // shared `RoleTarget` guard (`…_sites.contains(resource.name)`) matches:
        // `Project`/`Secrets` by the project `"<project>"`, `BlobUpload` by the
        // container triple `"<project>/<site>/<container>"`. (`BlobUpload` is granted
        // only to `admin` today — an `AnyTarget` template with no guard — but keying
        // it here means a future target-scoped grant of it authorizes correctly.)
        Resource::Project | Resource::Secrets | Resource::BlobUpload => {
            let name = required.target.clone().unwrap_or_default();
            let mut a = HashMap::new();
            a.insert(
                "name".to_string(),
                RestrictedExpression::new_string(name.clone()),
            );
            (name, a)
        }
        other => (other.as_str().to_string(), HashMap::new()),
    };
    let entity_uid = uid(ty, &id);
    let entity = Entity::new(entity_uid.clone(), attrs, HashSet::new())?;
    Ok((entity_uid, entity))
}

/// The four action entities with the superuser hierarchy: `read`/`write`/`deploy`
/// each parent to `admin`, so an `action in [admin]` permit matches them all.
fn action_entities() -> Result<Vec<Entity>, Box<dyn Error>> {
    let admin = uid("Action", "admin");
    let mut out = Vec::with_capacity(4);
    out.push(Entity::new(admin.clone(), HashMap::new(), HashSet::new())?);
    for a in ["read", "write", "deploy"] {
        let parents = HashSet::from([admin.clone()]);
        out.push(Entity::new(uid("Action", a), HashMap::new(), parents)?);
    }
    Ok(out)
}

/// Construct a `BR::<type_name>::"<id>"` entity uid. The type name is a fixed
/// literal (always valid); the id is arbitrary text handled by the infallible
/// [`EntityId::new`].
fn uid(type_name: &str, id: &str) -> EntityUid {
    let tn =
        EntityTypeName::from_str(&format!("{NS}::{type_name}")).expect("static Cedar type name");
    EntityUid::from_type_name_and_id(tn, EntityId::new(id))
}

/// Whether `s` is a safe Cedar identifier (`[A-Za-z_][A-Za-z0-9_]*`). Role names
/// must satisfy this: they appear both as a `Role::"<name>"` string literal and,
/// for scoped roles, as the `<name>_sites` attribute path in generated policy text.
fn is_safe_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Generic Cedar compile / validate / authorize for consumers that bring their
/// **own** Cedar vocabulary (schema + policy text), rather than boatramp's
/// [`AuthzPolicy`] model above.
///
/// The rest of this module hard-codes boatramp's RBAC vocabulary — it *generates*
/// Cedar policy text from an [`AuthzPolicy`]. A downstream product with a different
/// policy model (its own entity types, actions and schema) cannot reuse that
/// generator, and today has to depend on `cedar-policy` directly to parse and
/// validate its own policies. This module lets it drive the identical
/// `cedar-policy` engine — already pulled in by the `cedar` feature — through
/// boatramp-core instead, so it never has to add `cedar-policy` to its own
/// `Cargo.toml` (and never pins a second, possibly divergent, Cedar version).
///
/// Nothing here touches boatramp's own Cedar usage; it is a parallel, additive
/// entry point built on raw Cedar text.
pub mod generic {
    use std::str::FromStr;

    use cedar_policy::{
        Context, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode, Validator,
    };

    use super::{AuthzDecision, CedarEngine};

    /// An error from the [generic](self) Cedar entry points. Each variant carries a
    /// human-readable description of the failing stage (the underlying `cedar-policy`
    /// error rendered to a `String`, so the caller never has to name a `cedar-policy`
    /// type).
    #[derive(Debug, thiserror::Error)]
    pub enum GenericCedarError {
        /// The schema text failed to parse (Cedar schema format).
        #[error("cedar schema parse error: {0}")]
        Schema(String),
        /// The policy text failed to parse.
        #[error("cedar policy parse error: {0}")]
        Policy(String),
        /// The policies parsed but did not type-check against the schema. The string
        /// lists each validation error.
        #[error("cedar policy validation failed: {0}")]
        Validation(String),
        /// A principal/action/resource entity-uid string did not parse.
        #[error("cedar entity-uid parse error: {0}")]
        EntityUid(String),
        /// The entities JSON failed to parse (or did not conform to the schema).
        #[error("cedar entities parse error: {0}")]
        Entities(String),
        /// The context JSON failed to parse.
        #[error("cedar context parse error: {0}")]
        Context(String),
        /// The request did not conform to the schema (bad principal/action/resource
        /// shape for the action's `appliesTo`, or a malformed context).
        #[error("cedar request construction error: {0}")]
        Request(String),
    }

    /// A consumer's own Cedar schema plus a policy set that has been type-checked
    /// against it — ready to authorize caller-supplied requests. Construct one with
    /// [`compile_and_validate`](Self::compile_and_validate) (Cedar-text schema) or
    /// [`compile_and_validate_json_schema`](Self::compile_and_validate_json_schema)
    /// (JSON schema). It owns the parsed [`Schema`] and the SAME compile-once
    /// `CedarEngine` boatramp's own authorizer runs on (U11-4d),
    /// and exposes only a `cedar-policy`-free surface, so the consumer need not depend
    /// on `cedar-policy`.
    ///
    /// **Hot path (U11-4c/4b):** parse the (slowly-changing) entity store and context
    /// ONCE with [`prepare_entities`](Self::prepare_entities) /
    /// [`prepare_context`](Self::prepare_context), then call
    /// [`evaluate`](Self::evaluate) per request — no per-call JSON parse. The
    /// all-in-JSON [`is_authorized_json`](Self::is_authorized_json) remains as a
    /// convenience, implemented over exactly that path.
    #[derive(Debug)]
    pub struct CompiledPolicySet {
        schema: Schema,
        engine: CedarEngine,
    }

    /// A Cedar entity store parsed + validated against a [`CompiledPolicySet`]'s
    /// schema ONCE (via [`prepare_entities`](CompiledPolicySet::prepare_entities)) and
    /// reusable across many [`evaluate`](CompiledPolicySet::evaluate) calls — the
    /// pre-parse that moves the old per-request JSON cost off the hot path. Opaque:
    /// it wraps a `cedar-policy` type so the consumer never names one.
    #[derive(Debug, Clone)]
    pub struct PreparedEntities(Entities);

    /// A Cedar request context parsed ONCE (via
    /// [`prepare_context`](CompiledPolicySet::prepare_context)) and reusable across
    /// evaluations. Opaque, like [`PreparedEntities`].
    #[derive(Debug, Clone)]
    pub struct PreparedContext(Context);

    /// A Cedar entity uid (a principal / action / resource reference) parsed ONCE
    /// (via [`prepare_uid`](CompiledPolicySet::prepare_uid)) and reusable. Opaque,
    /// like [`PreparedEntities`].
    #[derive(Debug, Clone)]
    pub struct PreparedUid(EntityUid);

    impl CompiledPolicySet {
        /// Parse `schema_src` (**Cedar schema format** — the human-readable syntax)
        /// and `policies_src` (Cedar policy text), then **strictly validate** the
        /// policies against the schema. Returns the compiled set on success, or the
        /// first failing stage's error ([schema parse](GenericCedarError::Schema) →
        /// [policy parse](GenericCedarError::Policy) →
        /// [validation](GenericCedarError::Validation)).
        ///
        /// This is the generic analogue of [`CompiledCedar::compile`](super::CompiledCedar::compile),
        /// but driven entirely by the caller's own Cedar text instead of boatramp's
        /// [`AuthzPolicy`](super::AuthzPolicy) vocabulary.
        pub fn compile_and_validate(
            schema_src: &str,
            policies_src: &str,
        ) -> Result<Self, GenericCedarError> {
            let schema = Schema::from_str(schema_src)
                .map_err(|e| GenericCedarError::Schema(e.to_string()))?;
            Self::from_schema(schema, policies_src)
        }

        /// Like [`compile_and_validate`](Self::compile_and_validate), but the schema
        /// is given in Cedar's **JSON schema format** rather than the human-readable
        /// Cedar schema syntax (U11-4c) — for a consumer (uchron) whose policy tooling
        /// emits or stores its schema as JSON. The policies are still Cedar policy
        /// text, and the validation is identical.
        pub fn compile_and_validate_json_schema(
            schema_json: &str,
            policies_src: &str,
        ) -> Result<Self, GenericCedarError> {
            let schema = Schema::from_json_str(schema_json)
                .map_err(|e| GenericCedarError::Schema(e.to_string()))?;
            Self::from_schema(schema, policies_src)
        }

        /// Like [`compile_and_validate_json_schema`](Self::compile_and_validate_json_schema),
        /// but the JSON schema is handed in as an already-parsed
        /// [`serde_json::Value`] rather than a string (U11 fold-up) — so a consumer
        /// (uchron) whose policy tooling already holds the schema as a
        /// `serde_json::Value` need not serialize it back to a string only for this
        /// crate to re-parse it. It goes through `Schema::from_json_value` and then the
        /// SAME strict-validation path (`from_schema`) as the string constructor; the
        /// policies are still Cedar policy text and the validation is identical.
        pub fn compile_and_validate_json_schema_value(
            schema_json: serde_json::Value,
            policies_src: &str,
        ) -> Result<Self, GenericCedarError> {
            let schema = Schema::from_json_value(schema_json)
                .map_err(|e| GenericCedarError::Schema(e.to_string()))?;
            Self::from_schema(schema, policies_src)
        }

        /// Shared tail of the constructors: parse + strictly validate the
        /// policies against an already-parsed `schema`, then build the compile-once
        /// `CedarEngine`.
        fn from_schema(schema: Schema, policies_src: &str) -> Result<Self, GenericCedarError> {
            let policies = PolicySet::from_str(policies_src)
                .map_err(|e| GenericCedarError::Policy(e.to_string()))?;
            let result =
                Validator::new(schema.clone()).validate(&policies, ValidationMode::default());
            if !result.validation_passed() {
                let errs = result
                    .validation_errors()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(GenericCedarError::Validation(errs));
            }
            Ok(Self {
                schema,
                engine: CedarEngine::new(policies),
            })
        }

        /// Parse an entity store (Cedar's [JSON entity format]) against the compiled
        /// schema **once**, returning a reusable [`PreparedEntities`]. Parse the store
        /// that is stable across a batch of requests here, then pass it to many
        /// [`evaluate`](Self::evaluate) calls so none of them re-parses it.
        ///
        /// [JSON entity format]: https://docs.cedarpolicy.com/auth/entities-syntax.html
        pub fn prepare_entities(
            &self,
            entities_json: &str,
        ) -> Result<PreparedEntities, GenericCedarError> {
            Entities::from_json_str(entities_json, Some(&self.schema))
                .map(PreparedEntities)
                .map_err(|e| GenericCedarError::Entities(e.to_string()))
        }

        /// Parse a request context (a JSON object of attributes) **once**, returning a
        /// reusable [`PreparedContext`].
        pub fn prepare_context(
            &self,
            context_json: &str,
        ) -> Result<PreparedContext, GenericCedarError> {
            Context::from_json_str(context_json, None)
                .map(PreparedContext)
                .map_err(|e| GenericCedarError::Context(e.to_string()))
        }

        /// Parse one entity-uid string (e.g. `User::"alice"`) **once**, returning a
        /// reusable [`PreparedUid`] for use as a principal / action / resource.
        pub fn prepare_uid(&self, uid: &str) -> Result<PreparedUid, GenericCedarError> {
            uid.parse()
                .map(PreparedUid)
                .map_err(|e| GenericCedarError::EntityUid(format!("{e}")))
        }

        /// Authorize one request from **pre-parsed** inputs, returning the rich
        /// [`AuthzDecision`](super::AuthzDecision) (allow/deny + the determining
        /// policies + diagnostics) rather than a bare `bool` (U11-4c). The entity
        /// store and context are parsed once (via [`prepare_entities`](Self::prepare_entities)
        /// / [`prepare_context`](Self::prepare_context)) and reused, so this hot path
        /// pays no JSON parse — the per-call cost the old
        /// [`is_authorized_json`](Self::is_authorized_json) incurred. Runs the SAME
        /// `CedarEngine` as boatramp's own authorizer (U11-4d).
        ///
        /// The request is still constructed against the compiled schema, so a request
        /// that does not conform is a loud [`Request`](GenericCedarError::Request)
        /// error rather than a silent deny. No `cedar-policy` type appears in the
        /// signature.
        pub fn evaluate(
            &self,
            principal: &PreparedUid,
            action: &PreparedUid,
            resource: &PreparedUid,
            context: Option<&PreparedContext>,
            entities: &PreparedEntities,
        ) -> Result<AuthzDecision, GenericCedarError> {
            let context = context.map(|c| c.0.clone()).unwrap_or_else(Context::empty);
            let request = Request::new(
                principal.0.clone(),
                action.0.clone(),
                resource.0.clone(),
                context,
                Some(&self.schema),
            )
            .map_err(|e| GenericCedarError::Request(e.to_string()))?;
            Ok(self.engine.evaluate(&request, &entities.0))
        }

        /// Authorize one request entirely from JSON/strings — the convenience form of
        /// [`evaluate`](Self::evaluate). The principal, action and resource are Cedar
        /// entity-uid strings (e.g. `User::"alice"`, `Action::"view"`,
        /// `Photo::"vacation"`); `entities_json` is the entity store in Cedar's
        /// [JSON entity format]; `context_json`, when `Some`, is a JSON object of
        /// context attributes. Everything is parsed per call, so prefer
        /// [`evaluate`](Self::evaluate) with pre-parsed inputs on a hot path.
        ///
        /// Returns `true` iff the decision is `Allow`. No `cedar-policy` type appears
        /// in the signature, so the caller stays free of a direct `cedar-policy`
        /// dependency.
        ///
        /// [JSON entity format]: https://docs.cedarpolicy.com/auth/entities-syntax.html
        pub fn is_authorized_json(
            &self,
            principal: &str,
            action: &str,
            resource: &str,
            context_json: Option<&str>,
            entities_json: &str,
        ) -> Result<bool, GenericCedarError> {
            let principal = self.prepare_uid(principal)?;
            let action = self.prepare_uid(action)?;
            let resource = self.prepare_uid(resource)?;
            let context = context_json.map(|c| self.prepare_context(c)).transpose()?;
            let entities = self.prepare_entities(entities_json)?;
            Ok(self
                .evaluate(&principal, &action, &resource, context.as_ref(), &entities)?
                .allow)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A small NON-boatramp Cedar vocabulary (users viewing photos) — nothing
        /// from boatramp's `BR::` RBAC model.
        const SCHEMA: &str = r#"
            entity User;
            entity Photo;
            action "view" appliesTo { principal: [User], resource: [Photo] };
        "#;

        const POLICY: &str = r#"
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource == Photo::"vacation"
            );
        "#;

        const ENTITIES: &str = r#"[
            { "uid": { "type": "User",  "id": "alice" },    "attrs": {}, "parents": [] },
            { "uid": { "type": "User",  "id": "bob" },      "attrs": {}, "parents": [] },
            { "uid": { "type": "Photo", "id": "vacation" }, "attrs": {}, "parents": [] }
        ]"#;

        #[test]
        fn compiles_and_validates_a_foreign_schema() {
            CompiledPolicySet::compile_and_validate(SCHEMA, POLICY)
                .expect("a well-typed foreign schema + policy must compile and validate");
        }

        #[test]
        fn authorizes_against_a_foreign_schema() {
            let compiled = CompiledPolicySet::compile_and_validate(SCHEMA, POLICY).unwrap();
            // The permitted (principal, resource) pair → Allow.
            assert!(
                compiled
                    .is_authorized_json(
                        r#"User::"alice""#,
                        r#"Action::"view""#,
                        r#"Photo::"vacation""#,
                        None,
                        ENTITIES,
                    )
                    .unwrap()
            );
            // A different principal → Deny (no matching permit).
            assert!(
                !compiled
                    .is_authorized_json(
                        r#"User::"bob""#,
                        r#"Action::"view""#,
                        r#"Photo::"vacation""#,
                        None,
                        ENTITIES,
                    )
                    .unwrap()
            );
        }

        #[test]
        fn validation_rejects_policy_against_undefined_action() {
            // `Action::"delete"` is not in the schema → strict validation must fail
            // (proving we really type-check, not just parse).
            let bad_policy = r#"permit(principal, action == Action::"delete", resource);"#;
            let err = CompiledPolicySet::compile_and_validate(SCHEMA, bad_policy)
                .expect_err("a policy over an undefined action must fail validation");
            assert!(
                matches!(err, GenericCedarError::Validation(_)),
                "expected a Validation error, got {err:?}"
            );
        }

        #[test]
        fn malformed_schema_is_a_schema_error() {
            let err = CompiledPolicySet::compile_and_validate("this is not a schema", POLICY)
                .expect_err("a malformed schema must error");
            assert!(
                matches!(err, GenericCedarError::Schema(_)),
                "expected a Schema error, got {err:?}"
            );
        }

        /// The same vocabulary expressed in Cedar's **JSON schema format** (U11-4c):
        /// `compile_and_validate_json_schema` must compile + validate + authorize
        /// identically to the Cedar-text constructor.
        const JSON_SCHEMA: &str = r#"{
            "": {
                "entityTypes": { "User": {}, "Photo": {} },
                "actions": {
                    "view": {
                        "appliesTo": {
                            "principalTypes": ["User"],
                            "resourceTypes": ["Photo"]
                        }
                    }
                }
            }
        }"#;

        #[test]
        fn compiles_and_authorizes_with_a_json_schema() {
            let compiled = CompiledPolicySet::compile_and_validate_json_schema(JSON_SCHEMA, POLICY)
                .expect("a well-typed JSON schema + policy must compile and validate");
            assert!(
                compiled
                    .is_authorized_json(
                        r#"User::"alice""#,
                        r#"Action::"view""#,
                        r#"Photo::"vacation""#,
                        None,
                        ENTITIES,
                    )
                    .unwrap()
            );
            // A malformed JSON schema is a Schema error, not a panic.
            let err = CompiledPolicySet::compile_and_validate_json_schema("{ not json", POLICY)
                .expect_err("malformed JSON schema must error");
            assert!(matches!(err, GenericCedarError::Schema(_)), "got {err:?}");
        }

        /// (U11 fold-up) The `serde_json::Value` constructor compiles + validates +
        /// authorizes identically to the string JSON-schema constructor — a consumer
        /// that already holds the schema as a parsed `Value` need not re-serialize it.
        #[test]
        fn compiles_and_authorizes_with_a_json_schema_value() {
            let schema_value: serde_json::Value =
                serde_json::from_str(JSON_SCHEMA).expect("JSON_SCHEMA parses to a Value");
            let compiled =
                CompiledPolicySet::compile_and_validate_json_schema_value(schema_value, POLICY)
                    .expect("a well-typed JSON-value schema + policy must compile and validate");
            assert!(
                compiled
                    .is_authorized_json(
                        r#"User::"alice""#,
                        r#"Action::"view""#,
                        r#"Photo::"vacation""#,
                        None,
                        ENTITIES,
                    )
                    .unwrap()
            );
            // A well-formed JSON Value that is not a valid schema is a Schema error,
            // not a panic.
            let err = CompiledPolicySet::compile_and_validate_json_schema_value(
                serde_json::json!({ "": { "entityTypes": 42 } }),
                POLICY,
            )
            .expect_err("a malformed schema Value must error");
            assert!(matches!(err, GenericCedarError::Schema(_)), "got {err:?}");
        }

        /// (U11-4c) The pre-parsed `evaluate` path: prepare the entity store + uids
        /// ONCE, evaluate many times, and get a rich `AuthzDecision` whose `allow`
        /// matches `is_authorized_json` and whose `determining_policies` names the
        /// satisfied permit on an Allow (and is empty on a default-deny).
        #[test]
        fn prepared_evaluate_matches_json_and_reports_diagnostics() {
            let compiled = CompiledPolicySet::compile_and_validate(SCHEMA, POLICY).unwrap();
            let entities = compiled.prepare_entities(ENTITIES).unwrap();
            let view = compiled.prepare_uid(r#"Action::"view""#).unwrap();
            let vacation = compiled.prepare_uid(r#"Photo::"vacation""#).unwrap();
            let alice = compiled.prepare_uid(r#"User::"alice""#).unwrap();
            let bob = compiled.prepare_uid(r#"User::"bob""#).unwrap();

            // Allow: alice → the decision is Allow, names a determining policy, no errors.
            let allow = compiled
                .evaluate(&alice, &view, &vacation, None, &entities)
                .unwrap();
            assert!(allow.allow);
            assert!(
                !allow.determining_policies.is_empty(),
                "an Allow must name the satisfied permit, got {allow:?}"
            );
            assert!(allow.errors.is_empty(), "no evaluation errors: {allow:?}");

            // Deny (default): bob → not allowed, no determining policy.
            let deny = compiled
                .evaluate(&bob, &view, &vacation, None, &entities)
                .unwrap();
            assert!(!deny.allow);
            assert!(
                deny.determining_policies.is_empty(),
                "a default-deny names no policy, got {deny:?}"
            );

            // The prepared path agrees with the all-JSON convenience, which is now
            // implemented over it.
            assert_eq!(
                allow.allow,
                compiled
                    .is_authorized_json(
                        r#"User::"alice""#,
                        r#"Action::"view""#,
                        r#"Photo::"vacation""#,
                        None,
                        ENTITIES,
                    )
                    .unwrap()
            );
        }

        /// LOAD-BEARING-SCHEMA regression gate (authz follow-up 1b).
        ///
        /// `CompiledPolicySet::evaluate` passes `Some(&self.schema)` into
        /// `Request::new`, which rejects a caller-supplied request/context that does
        /// not conform to the schema *before* Cedar evaluates it. This gate proves
        /// that per-request check is **not** redundant with the compile-time
        /// `Validator::validate` (which type-checks only the *policies*) and must not
        /// be dropped: without it a request that omits a **required** context
        /// attribute a `forbid` depends on would silently bypass that `forbid`
        /// (Cedar *skips* a policy that errors mid-evaluation — see
        /// `AuthzDecision::errors`), flipping a Deny into an Allow (fail-open).
        ///
        /// Context is the exposed surface: `prepare_context` parses it schema-free
        /// (`Context::from_json_str(.., None)`) and `prepare_uid` parses uids
        /// schema-free, so `Request::new(.., Some(schema))` is the *only* place the
        /// caller's request shape is validated.
        #[test]
        fn request_schema_check_is_load_bearing_not_redundant_with_validate() {
            // A required `blocked: Bool` context attribute, referenced by a `forbid`.
            const SCHEMA_CTX: &str = r#"
                entity User;
                entity Photo;
                action "view" appliesTo {
                    principal: [User],
                    resource: [Photo],
                    context: { blocked: Bool }
                };
            "#;
            // Broad permit + a conditional forbid that reads the required attribute.
            const POLICY_CTX: &str = r#"
                permit(principal, action == Action::"view", resource);
                forbid(principal, action == Action::"view", resource)
                    when { context.blocked };
            "#;

            // The policies type-check against the schema at compile time — i.e.
            // `Validator::validate` is satisfied. This is the exact premise 1b would
            // lean on; the point is that it is *not sufficient*.
            let compiled = CompiledPolicySet::compile_and_validate(SCHEMA_CTX, POLICY_CTX)
                .expect("permit + context-guarded forbid must validate against the schema");
            let entities = compiled.prepare_entities(ENTITIES).unwrap();
            let view = compiled.prepare_uid(r#"Action::"view""#).unwrap();
            let vacation = compiled.prepare_uid(r#"Photo::"vacation""#).unwrap();
            let alice = compiled.prepare_uid(r#"User::"alice""#).unwrap();

            // (1) FAIL-CLOSED today: a request whose context omits the required
            // `blocked` attribute is rejected by the per-request schema check inside
            // `Request::new(.., Some(schema))` — a loud `Request` error, never an
            // (accidental) Allow. `None` context ⇒ `Context::empty()`.
            let err = compiled
                .evaluate(&alice, &view, &vacation, None, &entities)
                .expect_err("a request missing the required `blocked` context must be rejected");
            assert!(
                matches!(err, GenericCedarError::Request(_)),
                "expected a Request (schema-conformance) error, got {err:?}"
            );

            // A well-formed context (blocked = true) is accepted AND the forbid then
            // applies → Deny. (Proves the forbid is live when its input is present.)
            let ctx_blocked = compiled.prepare_context(r#"{ "blocked": true }"#).unwrap();
            let decided = compiled
                .evaluate(&alice, &view, &vacation, Some(&ctx_blocked), &entities)
                .expect("a schema-conforming request is accepted");
            assert!(!decided.allow, "the forbid must deny when blocked = true");

            // (2) COUNTERFACTUAL — what dropping the schema would do. Build the SAME
            // request schema-free (`Request::new(.., None)`, as the internal path and
            // as 1b proposed) with the empty context and run the shared engine
            // directly. The forbid's `context.blocked` now *errors* (missing attr),
            // so Cedar SKIPS the forbid and the broad permit carries the request to
            // ALLOW — the fail-open the per-request schema check prevents.
            let schemaless_req = Request::new(
                r#"User::"alice""#.parse().unwrap(),
                r#"Action::"view""#.parse().unwrap(),
                r#"Photo::"vacation""#.parse().unwrap(),
                Context::empty(),
                None,
            )
            .expect("a schema-free request is always constructible");
            let raw = compiled.engine.evaluate(&schemaless_req, &entities.0);
            assert!(
                raw.allow,
                "counterfactual: schema-free eval ALLOWS (forbid skipped on the missing \
                 required attr) — this is the fail-open the schema check closes: {raw:?}"
            );
            assert!(
                !raw.errors.is_empty(),
                "the skipped forbid must surface as an evaluation error: {raw:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_types::authz::{RightSet, RightTemplate};
    use std::collections::BTreeMap;

    /// The differential faithfulness gate: for every (roleset, required) pair,
    /// the Cedar decision must equal the pure-Rust oracle
    /// `policy.rights_for(roles).allows(required)`.
    fn assert_faithful(policy: &AuthzPolicy, rolesets: &[Vec<GrantedRole>]) {
        let cedar = CompiledCedar::compile(policy).expect("compile");
        let targets = [
            None,
            Some("blog".to_string()),
            Some("shop".to_string()),
            // Project-qualified site targets + bare project targets (0.2.0), so the
            // gate covers `Resource::Project` and the project-wildcard site scope.
            Some("acme".to_string()),
            Some("acme/blog".to_string()),
            Some("acme/shop".to_string()),
            Some("other/blog".to_string()),
            // A literal `*` target: the wildcard is the *absence* of a target
            // (`None`), so a grant/required of the string `*` must be treated
            // literally by both engines (a resource named `*` can't be created).
            Some("*".to_string()),
            Some("acme/*".to_string()),
            // Non-conforming *required* targets that name the exact string a
            // pre-v0.7.0/offline grant might carry — so the A8 backstop deny is
            // exercised as a match-time pair in the differential gate, and both
            // engines must agree (deny).
            Some("${PROJECT}".to_string()),
            Some("acme/../evil".to_string()),
        ];
        for roles in rolesets {
            let expected_set: RightSet = policy.rights_for(roles);
            for &resource in &Resource::ALL {
                for action in [Action::Read, Action::Write, Action::Deploy, Action::Admin] {
                    for target in &targets {
                        let required = Right::new(resource, target.clone(), action);
                        let oracle = expected_set.allows(&required);
                        // Unwrap `decide` so a construction bug panics loudly with
                        // the offending inputs instead of silently denying.
                        let got = cedar.decide(roles, &required).expect("cedar decide").allow;
                        assert_eq!(
                            got, oracle,
                            "mismatch: roles={roles:?} required={required:?} (cedar={got} oracle={oracle})"
                        );
                    }
                }
            }
        }
    }

    fn default_rolesets() -> Vec<Vec<GrantedRole>> {
        vec![
            vec![],
            vec![GrantedRole::global("admin")],
            vec![GrantedRole::global("operator")],
            // Scoped roles granted globally (no target): RoleTarget templates
            // contribute nothing; only their AnyTarget templates (e.g. Blobs) apply.
            vec![GrantedRole::global("publisher")],
            vec![GrantedRole::global("deployer")],
            vec![GrantedRole::global("viewer")],
            // Scoped roles bound to a site.
            vec![GrantedRole::scoped("publisher", "blog")],
            vec![GrantedRole::scoped("publisher", "shop")],
            vec![GrantedRole::scoped("deployer", "blog")],
            vec![GrantedRole::scoped("viewer", "blog")],
            // Multiple instances of the same scoped role → the site set has 2 members.
            vec![
                GrantedRole::scoped("publisher", "blog"),
                GrantedRole::scoped("publisher", "shop"),
            ],
            // Mixed roles.
            vec![
                GrantedRole::scoped("publisher", "blog"),
                GrantedRole::scoped("viewer", "shop"),
            ],
            vec![
                GrantedRole::scoped("deployer", "blog"),
                GrantedRole::global("operator"),
            ],
            // Unknown role → grants nothing (rights_for skips it).
            vec![GrantedRole::global("ghost")],
            vec![
                GrantedRole::global("ghost"),
                GrantedRole::scoped("viewer", "blog"),
            ],
            // Project roles (0.2.0): the tenant boundary + project-wildcard site scope
            // must match the oracle across every (resource, action, target).
            vec![GrantedRole::scoped("project_admin", "acme")],
            vec![GrantedRole::scoped("project_publisher", "acme")],
            vec![GrantedRole::scoped("project_viewer", "acme")],
            // `messaging_consumer` (0.74.0): the project-wildcard scope on a NON-Site resource
            // (`Messaging·Read` on `"acme/*"`). The differential gate proves the generated Cedar
            // `resource.project` guard authorizes the consume surface (claim/subscribe/ack/nack, which
            // match on the `project` segment) and denies everything else, exactly as the oracle does —
            // confirming the Cedar mapping needs no change for the new role.
            vec![GrantedRole::scoped("messaging_consumer", "acme")],
            vec![GrantedRole::global("project_admin")], // no target → contributes only Blobs
            // A project-qualified site role alongside a project role.
            vec![
                GrantedRole::scoped("publisher", "acme/blog"),
                GrantedRole::scoped("project_viewer", "acme"),
            ],
            // Two projects at once — coverage must stay scoped to each.
            vec![
                GrantedRole::scoped("project_admin", "acme"),
                GrantedRole::scoped("project_viewer", "other"),
            ],
            // A grant target of the literal string `*` is non-conforming (not a valid
            // slug), so the v0.7.0 fail-closed A8 backstop makes it match NOTHING in
            // BOTH engines: the pure oracle drops it in `target_matches`, and the Cedar
            // side never puts it in the `<role>_sites` set. The gate proves the two
            // agree on this deny (a resource can't be named `*` anyway).
            vec![GrantedRole::scoped("publisher", "*")],
            vec![GrantedRole::scoped("project_admin", "*")],
            // A pre-v0.7.0 / offline non-conforming target must also deny in both
            // engines (the load-bearing backstop for already-minted tokens).
            vec![GrantedRole::scoped("publisher", "${PROJECT}")],
            vec![GrantedRole::scoped("project_admin", "acme/../evil")],
        ]
    }

    #[test]
    fn cedar_matches_oracle_default_policy() {
        assert_faithful(&AuthzPolicy::default_policy(), &default_rolesets());
    }

    #[test]
    fn cedar_matches_oracle_custom_policy() {
        // A second, hand-rolled policy to vary the *policy* dimension (not just
        // roles/required): a scoped editor (Site read+write) and a global auditor.
        let mut roles: BTreeMap<String, Vec<RightTemplate>> = BTreeMap::new();
        roles.insert(
            "editor".to_string(),
            vec![
                RightTemplate::scoped(Resource::Site, Action::Read),
                RightTemplate::scoped(Resource::Site, Action::Write),
            ],
        );
        roles.insert(
            "auditor".to_string(),
            vec![
                RightTemplate::any(Resource::System, Action::Read),
                RightTemplate::any(Resource::Tokens, Action::Read),
            ],
        );
        // A role that is BOTH scoped (Site) and global (Certs admin) — exercises a
        // role with mixed template scopes.
        roles.insert(
            "sitelead".to_string(),
            vec![
                RightTemplate::scoped(Resource::Site, Action::Admin),
                RightTemplate::any(Resource::Certs, Action::Admin),
            ],
        );
        let policy = AuthzPolicy {
            version: boatramp_types::SCHEMA_VERSION,
            roles,
        };
        let rolesets = vec![
            vec![],
            vec![GrantedRole::scoped("editor", "blog")],
            vec![GrantedRole::global("editor")], // scoped role, no target → nothing
            vec![GrantedRole::global("auditor")],
            vec![GrantedRole::scoped("sitelead", "blog")],
            vec![GrantedRole::global("sitelead")], // Certs admin applies; Site does not
            vec![
                GrantedRole::scoped("editor", "blog"),
                GrantedRole::global("auditor"),
            ],
            vec![
                GrantedRole::scoped("sitelead", "shop"),
                GrantedRole::scoped("editor", "blog"),
            ],
        ];
        assert_faithful(&policy, &rolesets);
    }

    #[test]
    fn compile_rejects_unsafe_role_name() {
        for bad in [
            "has space",
            "quote\"inject",
            "dash-role",
            "dot.role",
            "",
            "1leading",
        ] {
            let mut roles: BTreeMap<String, Vec<RightTemplate>> = BTreeMap::new();
            roles.insert(
                bad.to_string(),
                vec![RightTemplate::any(Resource::System, Action::Read)],
            );
            let policy = AuthzPolicy {
                version: boatramp_types::SCHEMA_VERSION,
                roles,
            };
            assert!(
                matches!(
                    CompiledCedar::compile(&policy),
                    Err(CedarError::RoleName(_))
                ),
                "expected rejection of role name {bad:?}"
            );
        }
    }

    #[test]
    fn admin_is_superuser_across_actions() {
        let cedar = CompiledCedar::compile(&AuthzPolicy::default_policy()).unwrap();
        let admin = [GrantedRole::global("admin")];
        for &resource in &Resource::ALL {
            for action in [Action::Read, Action::Write, Action::Deploy, Action::Admin] {
                let target = matches!(resource, Resource::Site).then(|| "any-site".to_string());
                let required = Right::new(resource, target, action);
                assert!(
                    cedar.authorize(&admin, &required),
                    "admin denied {required:?}"
                );
            }
        }
    }

    /// (U11-4b benchmark) Measure the per-call parse + Cedar-compile cost that the
    /// authz hot-path cache removes, on the REAL default RBAC policy (multiple roles ×
    /// right-templates → a non-trivial `PolicySet`), exercising the actual
    /// `CompiledCedar::compile` + `authorize` path — not a micro-case. Not a gate; run
    /// explicitly:
    /// `cargo test -p boatramp-core --features authz -- --ignored --nocapture authz_compile_cost`.
    #[test]
    #[ignore = "benchmark: run explicitly with --ignored --nocapture"]
    fn authz_compile_cost_benchmark() {
        use std::time::Instant;

        let policy = AuthzPolicy::default_policy();
        // The exact stored form the hot path deserializes per request today.
        let bytes = serde_json::to_vec(&policy).expect("serialize default policy");
        let roles = [GrantedRole::scoped("publisher", "acme/blog")];
        let required = Right::new(Resource::Site, Some("acme/blog".to_string()), Action::Write);
        let iters = 5_000u32;

        // OLD hot path: deserialize + compile + decide on EVERY call (what boatramp's
        // `AuthInner::policy` did per request before the cache).
        let t0 = Instant::now();
        for _ in 0..iters {
            let p: AuthzPolicy = serde_json::from_slice(&bytes).expect("parse");
            let compiled = CompiledCedar::compile(&p).expect("compile");
            std::hint::black_box(compiled.authorize(&roles, &required));
        }
        let old = t0.elapsed();

        // NEW hot path: compile ONCE (the cache hit), decide on every call.
        let compiled = CompiledCedar::compile(&policy).expect("compile");
        let t1 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(compiled.authorize(&roles, &required));
        }
        let new = t1.elapsed();

        let old_us = old.as_micros() as f64 / f64::from(iters);
        let new_us = new.as_micros() as f64 / f64::from(iters);
        eprintln!(
            "\nU11-4b authz compile-cost benchmark ({iters} iters, default policy):\n  \
             per-request recompile (parse+compile+decide): {old:?} total, {old_us:.2} µs/call\n  \
             cached compile (decide only):                 {new:?} total, {new_us:.2} µs/call\n  \
             parse+compile removed per call:               ~{:.2} µs  ({:.0}x faster)\n",
            old_us - new_us,
            old_us / new_us.max(f64::MIN_POSITIVE),
        );
        // Sanity: the decide-only path must be strictly cheaper than recompiling each call.
        assert!(
            new < old,
            "cached decide must be faster than per-call recompile"
        );
    }

    #[test]
    fn publisher_scoped_to_its_site_only() {
        let cedar = CompiledCedar::compile(&AuthzPolicy::default_policy()).unwrap();
        let roles = [GrantedRole::scoped("publisher", "blog")];
        // Its own site: write allowed.
        assert!(cedar.authorize(
            &roles,
            &Right::new(Resource::Site, Some("blog".into()), Action::Write)
        ));
        // A different site: denied.
        assert!(!cedar.authorize(
            &roles,
            &Right::new(Resource::Site, Some("shop".into()), Action::Write)
        ));
        // Blob deploy (AnyTarget) allowed regardless of site.
        assert!(cedar.authorize(&roles, &Right::new(Resource::Blobs, None, Action::Deploy)));
        // System admin denied.
        assert!(!cedar.authorize(&roles, &Right::new(Resource::System, None, Action::Admin)));
    }
}
