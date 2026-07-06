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
//!   every target-scoped role (the site names it was granted that role on; always
//!   present, possibly empty).
//! - **Resource** = `BR::<Resource>::"<id>"`; only `BR::Site` carries a `name` attr
//!   (the requested site), which the site-scoping guard reads.
//! - **Action** = `BR::Action::"<action>"` with `read`/`write`/`deploy` parented to
//!   `admin`, so an `admin` grant (`action in [BR::Action::"admin"]`) covers every
//!   action — mirroring `Right::satisfies`' "granted Admin ⇒ any action".
//! - **Site scoping** is `when { principal.<role>_sites.contains(resource.name) }`,
//!   mirroring `target_matches`. `AnyTarget` templates emit no `when` (wildcard).
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
            .filter(|(_, templates)| templates.iter().any(|t| t.scope == TargetScope::RoleTarget))
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
                // Bind the request's site to the roles' granted sites, mirroring
                // `target_matches(Some(g), required)`. `Set::contains` is Cedar set
                // membership (`in` is entity-hierarchy membership — wrong here).
                TargetScope::RoleTarget => {
                    format!(" when {{ principal.{role}_sites.contains(resource.name) }}")
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
        Resource::Blobs => "Blobs",
        Resource::Tokens => "Tokens",
        Resource::Certs => "Certs",
        Resource::Cache => "Cache",
        Resource::System => "System",
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
            .map(|t| RestrictedExpression::new_string(t.clone()));
        attrs.insert(
            format!("{role}_sites"),
            RestrictedExpression::new_set(sites),
        );
    }
    Ok(Entity::new(principal_uid.clone(), attrs, parents)?)
}

/// Build the resource entity for a required right. `Site` is keyed + attributed by
/// the requested site name (read by the scoping guard); other resources are global
/// singletons keyed by their type term, needing no attributes.
fn resource_entity(required: &Right) -> Result<(EntityUid, Entity), Box<dyn Error>> {
    let ty = resource_type(required.resource);
    let (id, attrs) = match required.resource {
        Resource::Site => {
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
        let targets = [None, Some("blog".to_string()), Some("shop".to_string())];
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
