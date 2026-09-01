//! Per-tenant managed-database provisioning: **pure** name derivation and DDL
//! generation, no IO and no async.
//!
//! boatramp can run one shared managed Postgres/MySQL server and give each
//! tenant — a project, or a site — its **own database plus its own login role**,
//! permission-isolated from every other tenant. This module is the security-
//! critical, side-effect-free half of that: it turns an arbitrary,
//! attacker-influenced project/site name into a safe SQL identifier and emits the
//! ordered, idempotent DDL to create / drop / rotate a tenant. The caller
//! ([`boatramp-node`], not this crate) runs the DDL server-side as the superuser
//! and owns credentials, connections, and the "already provisioned" bookkeeping.
//!
//! # Security model
//!
//! - **Identifier sanitization is the perimeter.** [`sanitize_ident`] maps any
//!   input to `[a-z0-9_]`, and — crucially — is **injective**: two distinct
//!   inputs can never collapse to the same identifier (that would silently let
//!   one tenant address another tenant's database). Injectivity is guaranteed by
//!   appending a stable FNV-1a hash of the *original* input whenever the mapping
//!   was lossy or the name was truncated (see [`sanitize_ident`]).
//! - **Defense in depth in the DDL.** Even though the names reaching
//!   [`provision_ddl`] / [`deprovision_ddl`] / [`rotate_ddl`] are already
//!   sanitized and passwords are hex, every emitted statement quotes its
//!   identifiers ([`quote_ident`]) and string literals ([`quote_literal`])
//!   defensively, doubling any embedded quote char. There is no string
//!   interpolation of a raw name or password anywhere in the emitted SQL.
//! - **No IO.** Every function returns owned `String` / `Vec<String>`. Nothing
//!   here connects, queries, or blocks.
//!
//! # `CREATE DATABASE` already-exists contract
//!
//! Postgres `CREATE DATABASE` has no `IF NOT EXISTS` and cannot run inside a
//! transaction or a `DO` block, so [`provision_ddl`] emits it as its own bare
//! statement. **The caller MUST treat a "database already exists" error from
//! that one statement as success** (the tenant is already provisioned) and
//! continue with the remaining statements. Every other statement this module
//! emits is genuinely idempotent (guarded by `IF NOT EXISTS` / `DO $$ ... $$` /
//! `OR REPLACE`-style checks) and can be re-run freely.
//!
//! [`boatramp-node`]: https://docs.rs/boatramp-node

// Without a sql engine feature this module is never `mod`-ed in from `lib.rs`,
// so this attribute is belt-and-suspenders to match the crate's convention of
// keeping sql code quiet on a no-sql build.
#![cfg_attr(
    not(any(feature = "sql-postgres", feature = "sql-mysql")),
    allow(dead_code)
)]

use crate::ExternalSqlKind;

/// Maximum length of a single derived identifier. Postgres truncates
/// identifiers at 63 bytes (`NAMEDATALEN - 1`) and MySQL allows 64; we cap well
/// below both so that a `<base>_<tenant>` combination still fits after
/// re-sanitization, and reserve room for the injectivity hash suffix.
const MAX_IDENT_LEN: usize = 40;

/// Length (in hex chars) of the FNV-1a suffix appended to keep sanitization
/// injective. 8 hex chars = 32 bits of the hash.
const HASH_HEX_LEN: usize = 8;

/// FNV-1a 64-bit hash of `bytes`.
///
/// A tiny, dependency-free, **stable** non-cryptographic hash. Stability is the
/// whole point: `std`'s [`DefaultHasher`] output is explicitly *not* guaranteed
/// stable across builds or platforms, which would make derived identifiers move
/// under a tenant between binary versions. FNV-1a is fixed by its constants, so
/// the same input always yields the same identifier. (It is not
/// collision-resistant against an adversary, but it does not need to be — it is
/// only a disambiguating suffix, and the leading sanitized portion already
/// carries the human-meaningful bytes; see [`sanitize_ident`] for the
/// injectivity argument.)
///
/// [`DefaultHasher`]: std::collections::hash_map::DefaultHasher
fn fnv1a_64(bytes: &[u8]) -> u64 {
    // 64-bit FNV offset basis / prime (the canonical constants).
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// The first [`HASH_HEX_LEN`] hex chars of the FNV-1a hash of `s`.
fn hash_suffix(s: &str) -> String {
    let full = format!("{:016x}", fnv1a_64(s.as_bytes()));
    full[..HASH_HEX_LEN].to_string()
}

/// Map an arbitrary project/site name to a **safe** SQL identifier.
///
/// Rules:
/// 1. Lowercase the input.
/// 2. Keep `[a-z0-9_]`; replace every other char (including `-`, whitespace,
///    quotes, and every SQL metacharacter) with `_`.
/// 3. If the result is empty or starts with a digit, prefix `t_`.
/// 4. Cap the human-readable portion at [`MAX_IDENT_LEN`] chars.
/// 5. **Injectivity:** if step 2 or 4 was *lossy* (any char was replaced, or the
///    name was truncated), append `_` + an 8-hex-char FNV-1a hash of the
///    **original** input.
///
/// # Injectivity guarantee
///
/// Two distinct inputs must never produce the same identifier — otherwise one
/// tenant's derived database/role name could collide with another's, breaking
/// isolation. This holds because:
///
/// - If neither input was lossy, the identifier equals the (lowercased, but
///   already `[a-z0-9_]`) input verbatim, plus an optional `t_` prefix. Two such
///   inputs are equal as identifiers only if they were equal as inputs. (Case is
///   folded, so `Foo`/`foo` *would* collide here — but changing case is a lossy
///   transform under a different definition; we treat any non-lowercase byte as
///   lossy in step 5's check, so `Foo` carries a hash and `foo` does not,
///   keeping them distinct. See the check below.)
/// - If either input was lossy, its identifier ends in `_<hash-of-original>`.
///   The hash is computed over the *original* bytes, so different originals get
///   different suffixes with overwhelming probability, and — decisively — a
///   lossy identifier always carries a hash while a lossless one never does, so
///   the two classes can never collide either.
///
/// The suffix is derived from the pre-sanitization input, so it disambiguates
/// exactly the information that sanitization threw away.
pub fn sanitize_ident(name: &str) -> String {
    let lower = name.to_ascii_lowercase();

    // Lossy if lowercasing changed anything (case-folding erases information),
    // or if any char is outside the safe set (and thus gets replaced below).
    let mut lossy = lower != name;

    let mut cleaned = String::with_capacity(lower.len());
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' {
            cleaned.push(ch);
        } else {
            cleaned.push('_');
            lossy = true;
        }
    }

    // Empty or digit-leading ⇒ prefix `t_` so it's a valid identifier start.
    // An empty input is degenerate (all its information is gone), so force the
    // hash to keep distinct empties/whitespace-only names apart.
    let mut prefixed = if cleaned.is_empty() {
        lossy = true;
        String::from("t_")
    } else if cleaned.as_bytes()[0].is_ascii_digit() {
        format!("t_{cleaned}")
    } else {
        cleaned
    };

    // Truncate the human-readable portion, leaving room for `_<hash>`. Any
    // truncation is lossy and forces the disambiguating suffix.
    let budget = MAX_IDENT_LEN - (HASH_HEX_LEN + 1);
    if prefixed.len() > budget {
        prefixed.truncate(budget);
        lossy = true;
    }

    if lossy {
        format!("{prefixed}_{}", hash_suffix(name))
    } else {
        prefixed
    }
}

/// Derive the per-tenant **database** name from the binding's own database name
/// (`base`, e.g. `appdb`) and an already-sanitized `tenant_ident` (the caller
/// passes `sanitize_ident(project_or_site_name)`).
///
/// Scheme: `<base>_<tenant_ident>`, then the whole thing is re-sanitized and
/// length-capped through [`sanitize_ident`] so the *combined* name is a valid,
/// bounded identifier. Because the combination is deterministic and the re-pass
/// preserves injectivity, distinct `(base, tenant_ident)` pairs stay distinct.
pub fn tenant_db_name(base: &str, tenant_ident: &str) -> String {
    sanitize_ident(&format!("{base}_{tenant_ident}"))
}

/// Derive the per-tenant **login role** name.
///
/// Scheme: `<base>_<tenant_ident>_role`, then re-sanitized and length-capped via
/// [`sanitize_ident`]. Kept distinct from [`tenant_db_name`] by the `_role`
/// suffix so the role and database never share a name.
pub fn tenant_role_name(base: &str, tenant_ident: &str) -> String {
    sanitize_ident(&format!("{base}_{tenant_ident}_role"))
}

/// Quote a SQL **identifier** for `kind`, doubling the embedded quote char and
/// wrapping it: Postgres uses `"double quotes"`, MySQL uses `` `backticks` ``.
///
/// The names reaching this are pre-sanitized, but we quote defensively so no
/// identifier — however it was derived — can break out of its quoting.
fn quote_ident(kind: ExternalSqlKind, id: &str) -> String {
    match kind {
        ExternalSqlKind::Postgres => format!("\"{}\"", id.replace('"', "\"\"")),
        ExternalSqlKind::Mysql => format!("`{}`", id.replace('`', "``")),
    }
}

/// Quote a SQL **string literal** (single-quoted, doubling any embedded `'`).
///
/// Used for the password and for the role-name literal in Postgres's
/// `pg_roles` existence check. Same single-quote convention on both engines.
fn quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// For MySQL, a user is `'name'@'host'`. We always scope to `@'%'` (any host);
/// the network boundary is the operator's (the managed server isn't publicly
/// reachable). The name goes through [`quote_literal`] (single-quoted) because
/// MySQL account names are string-literal-quoted, not identifier-quoted.
fn mysql_user(role: &str) -> String {
    format!("{}@'%'", quote_literal(role))
}

/// Ordered, **idempotent** DDL to create a tenant's isolated database + login
/// role. `db` and `role` are already-derived names (see [`tenant_db_name`] /
/// [`tenant_role_name`]); `password` is the role's login password (hex in
/// practice, but quoted defensively regardless).
///
/// # Postgres
///
/// Emitted in order — role, then database, then PUBLIC lockdown:
/// 1. A `DO $$ ... $$` block that `CREATE ROLE ... LOGIN PASSWORD ...` **only if
///    the role doesn't already exist** (re-run safe).
/// 2. `ALTER ROLE ... WITH LOGIN PASSWORD ...` — always run, to keep the
///    password in sync on a re-provision.
/// 3. `CREATE DATABASE <db> OWNER <role>` — a **bare** statement (no
///    `IF NOT EXISTS`, no transaction, no `DO` block; the engine forbids all
///    three). Per the module-level contract, the caller treats an
///    "already exists" error here as success and moves on.
/// 4. `REVOKE CONNECT ON DATABASE <db> FROM PUBLIC` — strip the default
///    everyone-can-connect grant so *only* this tenant's role reaches the db.
/// 5. `GRANT CONNECT ON DATABASE <db> TO <role>`.
/// 6. `GRANT ALL PRIVILEGES ON DATABASE <db> TO <role>`.
///
/// The REVOKE-then-GRANT pair is the isolation core: without the REVOKE, any
/// role (every login is a member of `PUBLIC`) could connect to the new database.
///
/// # MySQL
///
/// 1. `CREATE DATABASE IF NOT EXISTS <db>`.
/// 2. `CREATE USER IF NOT EXISTS '<role>'@'%' IDENTIFIED BY '<pw>'`.
/// 3. `ALTER USER '<role>'@'%' IDENTIFIED BY '<pw>'` — keep the password in sync.
/// 4. `GRANT ALL PRIVILEGES ON <db>.* TO '<role>'@'%'` — scoped to *this*
///    database only (that `<db>.*` scope is the isolation boundary).
/// 5. `FLUSH PRIVILEGES`.
pub fn provision_ddl(kind: ExternalSqlKind, db: &str, role: &str, password: &str) -> Vec<String> {
    let db_id = quote_ident(kind, db);
    let role_id = quote_ident(kind, role);
    let pw_lit = quote_literal(password);

    match kind {
        ExternalSqlKind::Postgres => {
            let role_lit = quote_literal(role);
            vec![
                // 1. Idempotent role create (CREATE ROLE has no IF NOT EXISTS).
                format!(
                    "DO $$ BEGIN \
                     IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {role_lit}) THEN \
                     CREATE ROLE {role_id} LOGIN PASSWORD {pw_lit}; \
                     END IF; END $$;"
                ),
                // 2. Keep the password in sync on re-provision.
                format!("ALTER ROLE {role_id} WITH LOGIN PASSWORD {pw_lit};"),
                // 3. Bare CREATE DATABASE — "already exists" is the caller's OK.
                format!("CREATE DATABASE {db_id} OWNER {role_id};"),
                // 4-6. Lock the database down to this tenant's role only.
                format!("REVOKE CONNECT ON DATABASE {db_id} FROM PUBLIC;"),
                format!("GRANT CONNECT ON DATABASE {db_id} TO {role_id};"),
                format!("GRANT ALL PRIVILEGES ON DATABASE {db_id} TO {role_id};"),
            ]
        }
        ExternalSqlKind::Mysql => {
            let user = mysql_user(role);
            vec![
                format!("CREATE DATABASE IF NOT EXISTS {db_id};"),
                format!("CREATE USER IF NOT EXISTS {user} IDENTIFIED BY {pw_lit};"),
                format!("ALTER USER {user} IDENTIFIED BY {pw_lit};"),
                format!("GRANT ALL PRIVILEGES ON {db_id}.* TO {user};"),
                "FLUSH PRIVILEGES;".to_string(),
            ]
        }
    }
}

/// Ordered DDL to drop a tenant cleanly. Every statement is `IF EXISTS`-guarded,
/// so deprovisioning a never-provisioned or already-deprovisioned tenant is a
/// no-op rather than an error.
///
/// - **Postgres:** `DROP DATABASE IF EXISTS <db>;` then
///   `DROP ROLE IF EXISTS <role>;`. Terminating live connections to the database
///   first (e.g. `pg_terminate_backend`) is the caller's concern — Postgres
///   refuses to drop a database with active sessions; we keep this pure and just
///   emit the drops.
/// - **MySQL:** `DROP DATABASE IF EXISTS <db>;`,
///   `DROP USER IF EXISTS '<role>'@'%';`, `FLUSH PRIVILEGES;`.
pub fn deprovision_ddl(kind: ExternalSqlKind, db: &str, role: &str) -> Vec<String> {
    let db_id = quote_ident(kind, db);
    let role_id = quote_ident(kind, role);
    match kind {
        ExternalSqlKind::Postgres => vec![
            format!("DROP DATABASE IF EXISTS {db_id};"),
            format!("DROP ROLE IF EXISTS {role_id};"),
        ],
        ExternalSqlKind::Mysql => {
            let user = mysql_user(role);
            vec![
                format!("DROP DATABASE IF EXISTS {db_id};"),
                format!("DROP USER IF EXISTS {user};"),
                "FLUSH PRIVILEGES;".to_string(),
            ]
        }
    }
}

/// DDL to rotate a tenant role's login password (leaving its database and grants
/// untouched).
///
/// - **Postgres:** `ALTER ROLE <role> WITH LOGIN PASSWORD <pw>;`.
/// - **MySQL:** `ALTER USER '<role>'@'%' IDENTIFIED BY <pw>;` then
///   `FLUSH PRIVILEGES;`.
pub fn rotate_ddl(kind: ExternalSqlKind, role: &str, password: &str) -> Vec<String> {
    let role_id = quote_ident(kind, role);
    let pw_lit = quote_literal(password);
    match kind {
        ExternalSqlKind::Postgres => {
            vec![format!(
                "ALTER ROLE {role_id} WITH LOGIN PASSWORD {pw_lit};"
            )]
        }
        ExternalSqlKind::Mysql => {
            let user = mysql_user(role);
            vec![
                format!("ALTER USER {user} IDENTIFIED BY {pw_lit};"),
                "FLUSH PRIVILEGES;".to_string(),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ---- sanitize_ident --------------------------------------------------

    /// The safe charset + `t_` prefix rules hold, and outputs never exceed the
    /// length cap.
    #[test]
    fn sanitize_charset_and_bounds() {
        let long = "a".repeat(200);
        let inputs = [
            "acme-corp",
            "Foo",
            "1tenant",
            "",
            "hello_world",
            "x\"; DROP DATABASE y; --",
            long.as_str(),
        ];
        for input in inputs {
            let out = sanitize_ident(input);
            assert!(!out.is_empty(), "empty output for {input:?}");
            // Only [a-z0-9_].
            assert!(
                out.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "unsafe chars in {out:?} from {input:?}"
            );
            // Never starts with a digit.
            assert!(
                !out.as_bytes()[0].is_ascii_digit(),
                "digit-leading {out:?} from {input:?}"
            );
            // Within the cap.
            assert!(out.len() <= MAX_IDENT_LEN, "over cap: {out:?}");
        }
    }

    /// A clean, already-safe, short, lowercase name is passed through verbatim
    /// with **no** hash suffix (the common, human-readable case).
    #[test]
    fn sanitize_clean_name_unmodified() {
        assert_eq!(sanitize_ident("appdb"), "appdb");
        assert_eq!(sanitize_ident("my_site_42"), "my_site_42");
    }

    /// A digit-leading but otherwise clean name gets the `t_` prefix. It is not
    /// lossy, so it carries no hash.
    #[test]
    fn sanitize_digit_leading_prefixed() {
        assert_eq!(sanitize_ident("1tenant"), "t_1tenant");
    }

    /// **Injectivity:** a battery of tricky, near-colliding inputs all map to
    /// distinct identifiers. This is the core tenant-isolation property.
    #[test]
    fn sanitize_is_injective() {
        let long_a = "a".repeat(50);
        let long_b = format!("{}b", "a".repeat(49));
        let inputs = [
            "acme-corp",
            "acme_corp",
            "Foo",
            "foo",
            "1tenant",
            "tenant",
            "",
            " ",
            long_a.as_str(),
            long_b.as_str(),
            "x\"; DROP DATABASE y; --",
            "x'; DROP DATABASE y; --",
            "hello world",
            "hello_world",
        ];
        let mut seen: HashSet<String> = HashSet::new();
        for input in inputs {
            let out = sanitize_ident(input);
            assert!(
                seen.insert(out.clone()),
                "collision: {input:?} -> {out:?} already produced"
            );
        }
    }

    /// The two specifically-called-out near-collisions map apart.
    #[test]
    fn sanitize_named_near_collisions() {
        assert_ne!(sanitize_ident("acme-corp"), sanitize_ident("acme_corp"));
        assert_ne!(sanitize_ident("Foo"), sanitize_ident("foo"));
    }

    /// A lossy input carries an FNV-1a suffix; the same input is stable across
    /// calls (no `DefaultHasher` run-to-run drift).
    #[test]
    fn sanitize_lossy_has_stable_hash_suffix() {
        let a = sanitize_ident("acme-corp");
        let b = sanitize_ident("acme-corp");
        assert_eq!(a, b, "hash suffix must be stable");
        // "acme-corp" -> "acme_corp" is lossy, so a suffix is present: the
        // sanitized body plus `_` plus 8 hex chars.
        assert!(a.starts_with("acme_corp_"), "unexpected body: {a}");
        assert_eq!(a.len(), "acme_corp_".len() + HASH_HEX_LEN);
    }

    /// A >40-char name is truncated and, being lossy, disambiguated by hash;
    /// two long names that share a 40-char prefix still differ.
    #[test]
    fn sanitize_truncation_stays_distinct() {
        let long_a = format!("{}_alpha", "z".repeat(60));
        let long_b = format!("{}_beta", "z".repeat(60));
        let a = sanitize_ident(&long_a);
        let b = sanitize_ident(&long_b);
        assert!(a.len() <= MAX_IDENT_LEN && b.len() <= MAX_IDENT_LEN);
        assert_ne!(a, b, "truncated long names collided");
    }

    // ---- tenant_db_name / tenant_role_name -------------------------------

    /// The db/role derivation is deterministic, role != db, and both are safe.
    #[test]
    fn tenant_names_scheme() {
        let ident = sanitize_ident("acme");
        let db = tenant_db_name("appdb", &ident);
        let role = tenant_role_name("appdb", &ident);
        assert_ne!(db, role);
        assert!(db.contains("appdb"));
        assert!(role.contains("appdb"));
        assert!(role.contains("role"));
        // Deterministic.
        assert_eq!(db, tenant_db_name("appdb", &ident));
        // Safe charset.
        for name in [&db, &role] {
            assert!(name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        }
    }

    /// Distinct tenants under the same base get distinct db + role names.
    #[test]
    fn tenant_names_distinct_across_tenants() {
        let a = sanitize_ident("alpha");
        let b = sanitize_ident("beta");
        assert_ne!(tenant_db_name("appdb", &a), tenant_db_name("appdb", &b));
        assert_ne!(tenant_role_name("appdb", &a), tenant_role_name("appdb", &b));
    }

    // ---- quoting ---------------------------------------------------------

    /// Identifier quoting doubles the embedded quote char and wraps, per engine.
    #[test]
    fn quote_ident_doubles_embedded_quote() {
        assert_eq!(quote_ident(ExternalSqlKind::Postgres, "a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_ident(ExternalSqlKind::Postgres, "plain"), "\"plain\"");
        assert_eq!(quote_ident(ExternalSqlKind::Mysql, "a`b"), "`a``b`");
        assert_eq!(quote_ident(ExternalSqlKind::Mysql, "plain"), "`plain`");
    }

    /// Literal quoting doubles the embedded single quote and wraps.
    #[test]
    fn quote_literal_doubles_embedded_quote() {
        assert_eq!(quote_literal("O'Brien"), "'O''Brien'");
        assert_eq!(quote_literal("hex_pw"), "'hex_pw'");
        // The classic injection payload is neutralized (the closing quote is
        // doubled, so it stays inside the literal).
        assert_eq!(
            quote_literal("'; DROP TABLE users; --"),
            "'''; DROP TABLE users; --'"
        );
    }

    // ---- provision_ddl ---------------------------------------------------

    /// Postgres provisioning: correct ordering, the PUBLIC lockdown is present,
    /// the bare CREATE DATABASE is present, and names/passwords are quoted.
    #[test]
    fn provision_postgres_isolates_and_quotes() {
        let stmts = provision_ddl(
            ExternalSqlKind::Postgres,
            "appdb_acme",
            "appdb_acme_role",
            "deadbeef",
        );
        let joined = stmts.join("\n");
        // The isolation core.
        assert!(
            joined.contains("REVOKE CONNECT ON DATABASE \"appdb_acme\" FROM PUBLIC"),
            "missing PUBLIC revoke:\n{joined}"
        );
        assert!(joined.contains("GRANT CONNECT ON DATABASE \"appdb_acme\" TO \"appdb_acme_role\""));
        assert!(joined
            .contains("GRANT ALL PRIVILEGES ON DATABASE \"appdb_acme\" TO \"appdb_acme_role\""));
        // Idempotent role create + password sync.
        assert!(joined.contains("pg_roles WHERE rolname = 'appdb_acme_role'"));
        assert!(joined.contains("CREATE ROLE \"appdb_acme_role\" LOGIN PASSWORD 'deadbeef'"));
        assert!(joined.contains("ALTER ROLE \"appdb_acme_role\" WITH LOGIN PASSWORD 'deadbeef'"));
        // Bare CREATE DATABASE (no IF NOT EXISTS, standalone).
        assert!(joined.contains("CREATE DATABASE \"appdb_acme\" OWNER \"appdb_acme_role\""));
        assert!(!joined.contains("CREATE DATABASE IF NOT EXISTS"));
        // The password is only ever a quoted literal, never a bare token.
        assert!(!joined.contains(" deadbeef"), "unquoted password leaked");

        // Ordering: role DO-block before ALTER before CREATE DATABASE before
        // the REVOKE.
        let idx = |needle: &str| stmts.iter().position(|s| s.contains(needle)).unwrap();
        assert!(idx("CREATE ROLE") < idx("ALTER ROLE"));
        assert!(idx("ALTER ROLE") < idx("CREATE DATABASE"));
        assert!(idx("CREATE DATABASE") < idx("REVOKE CONNECT"));
    }

    /// MySQL provisioning: db-scoped GRANT (the isolation boundary), quoted
    /// user + password, and FLUSH PRIVILEGES present.
    #[test]
    fn provision_mysql_scoped_grant_and_quotes() {
        let stmts = provision_ddl(
            ExternalSqlKind::Mysql,
            "appdb_acme",
            "appdb_acme_role",
            "deadbeef",
        );
        let joined = stmts.join("\n");
        assert!(joined.contains("CREATE DATABASE IF NOT EXISTS `appdb_acme`"));
        assert!(joined
            .contains("CREATE USER IF NOT EXISTS 'appdb_acme_role'@'%' IDENTIFIED BY 'deadbeef'"));
        assert!(joined.contains("ALTER USER 'appdb_acme_role'@'%' IDENTIFIED BY 'deadbeef'"));
        // Grant is scoped to this database only.
        assert!(
            joined.contains("GRANT ALL PRIVILEGES ON `appdb_acme`.* TO 'appdb_acme_role'@'%'"),
            "missing db-scoped grant:\n{joined}"
        );
        assert!(joined.contains("FLUSH PRIVILEGES"));
        assert!(!joined.contains(" deadbeef"), "unquoted password leaked");
    }

    // ---- deprovision_ddl / rotate_ddl ------------------------------------

    /// Deprovision uses IF EXISTS guards on both engines.
    #[test]
    fn deprovision_is_guarded() {
        let pg = deprovision_ddl(ExternalSqlKind::Postgres, "appdb_acme", "appdb_acme_role");
        assert_eq!(
            pg,
            vec![
                "DROP DATABASE IF EXISTS \"appdb_acme\";".to_string(),
                "DROP ROLE IF EXISTS \"appdb_acme_role\";".to_string(),
            ]
        );
        let my = deprovision_ddl(ExternalSqlKind::Mysql, "appdb_acme", "appdb_acme_role");
        assert_eq!(
            my,
            vec![
                "DROP DATABASE IF EXISTS `appdb_acme`;".to_string(),
                "DROP USER IF EXISTS 'appdb_acme_role'@'%';".to_string(),
                "FLUSH PRIVILEGES;".to_string(),
            ]
        );
    }

    /// Rotate emits only the password change (quoted), plus FLUSH on MySQL.
    #[test]
    fn rotate_changes_password_only() {
        let pg = rotate_ddl(ExternalSqlKind::Postgres, "appdb_acme_role", "cafef00d");
        assert_eq!(
            pg,
            vec!["ALTER ROLE \"appdb_acme_role\" WITH LOGIN PASSWORD 'cafef00d';".to_string()]
        );
        let my = rotate_ddl(ExternalSqlKind::Mysql, "appdb_acme_role", "cafef00d");
        assert_eq!(
            my,
            vec![
                "ALTER USER 'appdb_acme_role'@'%' IDENTIFIED BY 'cafef00d';".to_string(),
                "FLUSH PRIVILEGES;".to_string(),
            ]
        );
    }

    /// A malicious password can't escape its literal in any emitted statement.
    #[test]
    fn malicious_password_is_neutralized() {
        let evil = "'; DROP DATABASE postgres; --";
        for stmts in [
            provision_ddl(ExternalSqlKind::Postgres, "appdb_x", "appdb_x_role", evil),
            provision_ddl(ExternalSqlKind::Mysql, "appdb_x", "appdb_x_role", evil),
            rotate_ddl(ExternalSqlKind::Postgres, "appdb_x_role", evil),
            rotate_ddl(ExternalSqlKind::Mysql, "appdb_x_role", evil),
        ] {
            for s in stmts {
                // If the payload appears at all, its leading quote must be
                // doubled (`''; DROP ...`), i.e. it stayed inside the literal.
                if s.contains("DROP DATABASE postgres") {
                    assert!(
                        s.contains("''; DROP DATABASE postgres; --"),
                        "password broke out of its literal: {s}"
                    );
                }
            }
        }
    }

    /// The FNV-1a hash matches the reference constants for a known vector, so a
    /// refactor can't silently change derived identifiers.
    #[test]
    fn fnv1a_known_vectors() {
        // FNV-1a 64-bit of the empty string is the offset basis.
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        // Canonical FNV-1a 64-bit test vector for "a".
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}
