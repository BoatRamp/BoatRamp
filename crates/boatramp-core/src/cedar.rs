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

/// A compiled Cedar authorizer generated from an [`AuthzPolicy`].
pub struct CompiledCedar {
    policies: PolicySet,
    authorizer: Authorizer,
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
            policies,
            authorizer: Authorizer::new(),
            scoped_roles,
        })
    }

    /// Decide whether a principal holding `roles` may perform `required`.
    ///
    /// Default-deny: any entity/request construction error yields `false`.
    pub fn authorize(&self, roles: &[GrantedRole], required: &Right) -> bool {
        matches!(self.decide(roles, required), Ok(Decision::Allow))
    }

    /// The fallible core of [`authorize`](Self::authorize): build the per-request
    /// entities + request and run the authorizer. Kept private but exercised
    /// directly (unwrapped) by the differential test so construction bugs are loud.
    fn decide(&self, roles: &[GrantedRole], required: &Right) -> Result<Decision, Box<dyn Error>> {
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
        let entities = Entities::from_entities(entities, None)?;

        let request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            Context::empty(),
            None,
        )?;
        Ok(self
            .authorizer
            .is_authorized(&request, &self.policies, &entities)
            .decision())
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
        Resource::Site => {
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
        Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
        ValidationMode, Validator,
    };

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
    /// [`compile_and_validate`](Self::compile_and_validate); it owns the parsed
    /// [`Schema`], [`PolicySet`] and an [`Authorizer`] internally and exposes only
    /// `cedar-policy`-free surface, so the consumer need not depend on `cedar-policy`.
    #[derive(Debug)]
    pub struct CompiledPolicySet {
        schema: Schema,
        policies: PolicySet,
        authorizer: Authorizer,
    }

    impl CompiledPolicySet {
        /// Parse `schema_src` (Cedar schema format) and `policies_src` (Cedar policy
        /// text), then **strictly validate** the policies against the schema. Returns
        /// the compiled set on success, or the first failing stage's error
        /// ([schema parse](GenericCedarError::Schema) → [policy
        /// parse](GenericCedarError::Policy) → [validation](GenericCedarError::Validation)).
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
                policies,
                authorizer: Authorizer::new(),
            })
        }

        /// Authorize one request against the compiled policies. The principal,
        /// action and resource are Cedar entity-uid strings (e.g. `User::"alice"`,
        /// `Action::"view"`, `Photo::"vacation"`); `entities_json` is the entity store
        /// in Cedar's [JSON entity format]; `context_json`, when `Some`, is a JSON
        /// object of context attributes. Everything is parsed against the compiled
        /// schema, so a request that does not conform is a loud
        /// [`Request`](GenericCedarError::Request) / [`Entities`](GenericCedarError::Entities)
        /// error rather than a silent deny.
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
            let principal: EntityUid = principal
                .parse()
                .map_err(|e| GenericCedarError::EntityUid(format!("{e}")))?;
            let action: EntityUid = action
                .parse()
                .map_err(|e| GenericCedarError::EntityUid(format!("{e}")))?;
            let resource: EntityUid = resource
                .parse()
                .map_err(|e| GenericCedarError::EntityUid(format!("{e}")))?;
            let context = match context_json {
                Some(c) => Context::from_json_str(c, None)
                    .map_err(|e| GenericCedarError::Context(e.to_string()))?,
                None => Context::empty(),
            };
            let entities = Entities::from_json_str(entities_json, Some(&self.schema))
                .map_err(|e| GenericCedarError::Entities(e.to_string()))?;
            let request = Request::new(principal, action, resource, context, Some(&self.schema))
                .map_err(|e| GenericCedarError::Request(e.to_string()))?;
            let decision = self
                .authorizer
                .is_authorized(&request, &self.policies, &entities)
                .decision();
            Ok(matches!(decision, Decision::Allow))
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
                        let got = cedar.decide(roles, &required).expect("cedar decide")
                            == Decision::Allow;
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
