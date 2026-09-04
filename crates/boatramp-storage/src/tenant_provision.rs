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
//!   *unconditionally* appending a stable, wide (128-bit) SHA-256 digest of the
//!   *original* input to every identifier — so two distinct originals differ in
//!   the suffix with ~2^-128 (cryptographic) collision probability regardless of
//!   how the human-readable body was folded or truncated (see [`sanitize_ident`]).
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
use boatramp_core::deploy::sha256_hex;

/// Width (chars) of the base-36 digest suffix that keeps sanitization injective:
/// **128 bits** of SHA-256 encoded in base-36 = ⌈128 / log2(36)⌉ = **25 chars**.
/// base-36 (`[0-9a-z]`) is the densest encoding that survives Postgres identifier
/// **case-folding** (an uppercase/base-62 alphabet would collapse to collisions),
/// and 25 chars leaves the *whole* digest inside even MySQL's 32-char user-name
/// limit — plain hex (32 chars) could not. Appended to every identifier so a pair
/// of distinct originals collides only with ~2^-128 probability.
const HASH_B36_LEN: usize = 25;

/// Maximum length of a general derived identifier — a **database** name. Postgres
/// truncates identifiers at 63 bytes (`NAMEDATALEN - 1`); MySQL allows 64 for a
/// schema. Cap at the tighter Postgres limit so it is valid on both.
const MAX_IDENT_LEN: usize = 63;

/// Maximum length of a per-tenant **login role / user** name. MySQL caps a user
/// name at **32** bytes — far tighter than its 64-char schema names or Postgres's
/// 63 — so a role (which may be provisioned on either engine) is capped here to be
/// valid on both. The 25-char base-36 digest still fits: `≤ 6` body + `_` + 25 = 32.
const MAX_ROLE_IDENT_LEN: usize = 32;

/// The leading 128 bits of the SHA-256 digest of `s`, base-36-encoded to
/// [`HASH_B36_LEN`] chars.
///
/// The digest is a **stable** (fixed by the SHA-256 standard, unlike `std`'s
/// [`DefaultHasher`], whose output is explicitly not guaranteed across builds or
/// platforms) and **cryptographically collision-resistant** disambiguator derived
/// from the *original*, pre-sanitization input. Truncating to 128 bits keeps the
/// full-input collision probability at ~2^-128; base-36 encoding (vs hex) is what
/// makes those 128 bits fit a 32-char MySQL user name while leaving room for a
/// human-readable body. Stability matters because a shift here would silently move
/// a tenant's database/role name between binary versions.
///
/// [`DefaultHasher`]: std::collections::hash_map::DefaultHasher
fn hash_suffix(s: &str) -> String {
    // `sha256_hex` yields 64 lowercase hex chars; take the leading 128 bits as a
    // u128 and re-encode in base-36 (denser than hex, case-fold-safe).
    let hex = sha256_hex(s.as_bytes());
    let n = u128::from_str_radix(&hex[..32], 16).expect("32 hex chars are a valid u128");
    to_base36(n)
}

/// Encode a `u128` in base-36 (`[0-9a-z]`), left-padded with `0` to [`HASH_B36_LEN`]
/// chars, so every digest is fixed-width. 128 bits needs at most 25 base-36 digits
/// (36^25 > 2^128), so it always fits.
fn to_base36(mut n: u128) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = [b'0'; HASH_B36_LEN];
    let mut i = HASH_B36_LEN;
    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = DIGITS[(n % 36) as usize];
        n /= 36;
    }
    debug_assert_eq!(n, 0, "128-bit digest overflowed the base-36 width");
    String::from_utf8(buf.to_vec()).expect("base-36 digits are ASCII")
}

/// Map an arbitrary project/site name to a **safe** SQL identifier.
///
/// Rules:
/// 1. Lowercase the input.
/// 2. Keep `[a-z0-9_]`; replace every other char (including `-`, whitespace,
///    quotes, and every SQL metacharacter) with `_`.
/// 3. If the result is empty or starts with a digit, prefix `t_`.
/// 4. Cap the human-readable body so the whole identifier fits `max_len` chars.
/// 5. **Injectivity:** *always* append `_` + a 25-char base-36 (128-bit) SHA-256
///    digest of the **original** input.
///
/// # Injectivity guarantee
///
/// Two distinct inputs must never produce the same identifier — otherwise one
/// tenant's derived database/role name could collide with another's, breaking
/// isolation. Every identifier ends in `_<digest-of-original>`, and the digest is
/// a cryptographic (SHA-256, 128-bit-truncated) hash of the *original* bytes, so:
///
/// - Two distinct originals yield the same 128-bit suffix only with ~2^-128
///   probability — a cryptographically negligible, adversary-resistant chance.
/// - Because the suffix is unconditional, there is no longer a "lossy" vs
///   "lossless" class split whose boundary an attacker could straddle: the body
///   is now purely cosmetic, and *all* disambiguation lives in the full-width
///   digest of the pre-sanitization input.
///
/// The suffix is derived from the pre-sanitization input, so it disambiguates
/// exactly the information that sanitization (case-folding, char replacement,
/// truncation) threw away.
pub fn sanitize_ident(name: &str) -> String {
    sanitize_ident_capped(name, MAX_IDENT_LEN)
}

/// [`sanitize_ident`] with an explicit maximum length, so a role/user name can be
/// held to the tighter [`MAX_ROLE_IDENT_LEN`] (MySQL's 32-char user limit) while a
/// database name uses [`MAX_IDENT_LEN`]. Same guarantees: safe charset, valid start
/// (never digit- or `pg_`-leading), and the full-width [`HASH_B36_LEN`] digest of the
/// original input (so injectivity holds regardless of `max_len` — only the cosmetic
/// body is truncated more aggressively for a tighter cap).
fn sanitize_ident_capped(name: &str, max_len: usize) -> String {
    let lower = name.to_ascii_lowercase();

    let mut cleaned = String::with_capacity(lower.len());
    for ch in lower.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' {
            cleaned.push(ch);
        } else {
            cleaned.push('_');
        }
    }

    // Empty or digit-leading ⇒ prefix `t_` so it's a valid identifier start.
    // Postgres additionally **reserves the `pg_` prefix** for system roles/schemas, so
    // any input that would yield a `pg_`-leading identifier (e.g. a compute workload
    // literally named `pg` — the natural name for a Postgres server, which becomes the
    // per-tenant *role* base) gets the same `t_` guard; otherwise `CREATE ROLE "pg_…"`
    // is rejected with "role name is reserved". Injectivity is unaffected — the digest
    // is of the *original* input, so `pg_x` and `t_pg_x` still get distinct suffixes.
    let reserved_pg = cleaned == "pg" || cleaned.starts_with("pg_");
    let mut body = if cleaned.is_empty() {
        String::from("t_")
    } else if cleaned.as_bytes()[0].is_ascii_digit() || reserved_pg {
        format!("t_{cleaned}")
    } else {
        cleaned
    };

    // Cap the human-readable body, leaving room for the mandatory `_<digest>`.
    // Truncation is harmless to injectivity now that the full-width digest of the
    // *original* input is always appended below.
    body.truncate(max_len.saturating_sub(HASH_B36_LEN + 1));

    // Always append the wide digest of the original input.
    format!("{body}_{}", hash_suffix(name))
}

/// Derive the per-tenant **database** name from the binding's own database name
/// (`base`, e.g. `appdb`) and an already-sanitized `tenant_ident` (the caller
/// passes `sanitize_ident(project_or_site_name)`).
///
/// Scheme: `<base>_<tenant_ident>`, then the whole thing is re-sanitized and
/// length-capped through [`sanitize_ident`] so the *combined* name is a valid,
/// bounded identifier carrying its own always-on digest. Because the combination
/// is deterministic and [`sanitize_ident`] is injective over its (combined)
/// input, distinct `(base, tenant_ident)` pairs stay distinct.
pub fn tenant_db_name(base: &str, tenant_ident: &str) -> String {
    sanitize_ident(&format!("{base}_{tenant_ident}"))
}

/// Derive the per-tenant **login role** name.
///
/// Scheme: `<base>_<tenant_ident>_role`, then re-sanitized and length-capped via
/// [`sanitize_ident`]. Because [`sanitize_ident`] digests the *whole* combined
/// input — including the trailing `_role` — this identifier's 128-bit digest
/// suffix always differs from [`tenant_db_name`]'s (whose input has no `_role`),
/// so the role and database names can never collide even when the human-readable
/// `role` marker is truncated out of the body for a very long tenant. The
/// distinctness is carried by the digest, not by the (cosmetic) marker.
pub fn tenant_role_name(base: &str, tenant_ident: &str) -> String {
    // Capped to MAX_ROLE_IDENT_LEN (32) so it is a valid MySQL *user* name as well as
    // a Postgres role; the full 25-char digest still fits, keeping it injective.
    sanitize_ident_capped(&format!("{base}_{tenant_ident}_role"), MAX_ROLE_IDENT_LEN)
}

/// Quote a SQL **identifier** for `kind`, doubling the embedded quote char and
/// wrapping it: Postgres uses `"double quotes"`, MySQL uses `` `backticks` ``.
///
/// The names reaching this are pre-sanitized, but we quote defensively so no
/// identifier — however it was derived — can break out of its quoting.
///
/// Public so the node-side soft-deprovision path (which composes its own
/// `pg_terminate_backend` / `ALTER DATABASE … RENAME` statements) quotes
/// identifiers through the exact same routine as the pure DDL builders here,
/// rather than hand-rolling a second quoting rule.
pub fn quote_ident(kind: ExternalSqlKind, id: &str) -> String {
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

/// Ordered, **idempotent** DDL granting a tenant's login `role` the everyday
/// application privileges on the objects in its **own** database's `public` schema —
/// run (as the schema-owning superuser, `owner`) *inside the tenant database* after
/// [`provision_ddl`].
///
/// # Why this is needed (Postgres `Shared` only)
///
/// A `Shared` tenant's schema is loaded by the **superuser** (operator `sql exec`
/// connects as the server superuser, since one connection must be able to reach every
/// tenant's database). Those objects are therefore superuser-owned, and Postgres's
/// database-level `GRANT ALL PRIVILEGES ON DATABASE` confers only `CONNECT`/`CREATE`/
/// `TEMP` — **not** table privileges. So the tenant's non-superuser login role (kept
/// non-superuser precisely so the app's row-level security is enforced) can't read or
/// write the tables, and the first guest query fails with `permission denied`. This
/// grants the role the standard app rights and sets `ALTER DEFAULT PRIVILEGES` so
/// objects a later migration creates are covered too — handling either order (provision
/// before or after the schema load). Idempotent: every `GRANT`/`ALTER DEFAULT
/// PRIVILEGES` re-runs harmlessly.
///
/// - **`GRANT … ON ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA public`** — existing objects
///   (a schema already loaded before this ran, or a re-provision).
/// - **`ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA public GRANT …`** — future
///   objects the `owner` (the migration superuser) creates.
///
/// Scoped to the tenant's own database + `public` schema, so it grants nothing
/// cross-tenant (the role can `CONNECT` only to its own database — [`provision_ddl`]'s
/// `REVOKE CONNECT … FROM PUBLIC`), and the role stays non-superuser (RLS still applies).
///
/// # MySQL
///
/// Empty — [`provision_ddl`]'s `GRANT ALL PRIVILEGES ON <db>.*` already covers every
/// current and future table in the tenant's database, so there is no gap.
pub fn grant_app_role_ddl(kind: ExternalSqlKind, role: &str, owner: &str) -> Vec<String> {
    match kind {
        ExternalSqlKind::Postgres => {
            let role_id = quote_ident(kind, role);
            let owner_id = quote_ident(kind, owner);
            vec![
                format!("GRANT USAGE ON SCHEMA public TO {role_id};"),
                format!(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role_id};"
                ),
                format!(
                    "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {role_id};"
                ),
                format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {role_id};"),
                format!(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {owner_id} IN SCHEMA public \
                     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role_id};"
                ),
                format!(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {owner_id} IN SCHEMA public \
                     GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {role_id};"
                ),
                format!(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {owner_id} IN SCHEMA public \
                     GRANT EXECUTE ON FUNCTIONS TO {role_id};"
                ),
            ]
        }
        ExternalSqlKind::Mysql => Vec::new(),
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

/// Ordered, **Postgres-only** DDL to *soft*-delete a tenant: rename its database
/// aside to `renamed` and disable its login role, so the tenant's data survives a
/// grace window (recoverable by [`recover_soft_deprovision_ddl`]) while the
/// **original** database name is freed immediately for a clean same-named re-create,
/// and nothing can reach the renamed-aside data in the meantime.
///
/// This is the recoverable half of the delete matrix — it exists for `Shared`
/// Postgres only, because Postgres can `ALTER DATABASE … RENAME`. MySQL has no
/// database rename, and `Single`'s unit is a whole container/volume, so those cells
/// keep the immediate, irreversible [`deprovision_ddl`] drop.
///
/// Emitted in order:
/// 1. `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname =
///    '<db>'` — evict every live session on the source database (Postgres refuses
///    to rename a database with open connections).
/// 2. `ALTER DATABASE "<db>" RENAME TO "<renamed>"` — move the data aside; this
///    frees `<db>` at once, so a fresh tenant re-created under the same name starts
///    clean and can never alias the renamed-aside data.
/// 3. `ALTER ROLE "<role>" NOLOGIN` — disable the tenant's login role so its sealed
///    credential (kept for recovery) can't reach the renamed database.
///
/// `db`, `renamed`, and `role` are already-derived, sanitized names; every one is
/// quoted through [`quote_ident`] (and the `datname` literal through
/// [`quote_literal`]) defensively.
pub fn soft_deprovision_ddl(db: &str, renamed: &str, role: &str) -> Vec<String> {
    let kind = ExternalSqlKind::Postgres;
    let db_id = quote_ident(kind, db);
    let renamed_id = quote_ident(kind, renamed);
    let role_id = quote_ident(kind, role);
    let db_lit = quote_literal(db);
    vec![
        // 1. Evict live sessions so the RENAME can take the lock.
        format!("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = {db_lit};"),
        // 2. Move the data aside; frees the original name for a clean re-create.
        format!("ALTER DATABASE {db_id} RENAME TO {renamed_id};"),
        // 3. Disable the tenant's login role — nothing reaches the renamed data.
        format!("ALTER ROLE {role_id} NOLOGIN;"),
    ]
}

/// Ordered, **Postgres-only** DDL to *reverse* a [`soft_deprovision_ddl`] within the
/// grace window: rename the aside database `renamed` back to its `original` name and
/// re-enable the tenant's login role. The mirror of the soft delete, so an operator
/// (or a recovery hook) can restore a mistakenly-deleted tenant before the reaper
/// hard-drops it.
///
/// Emitted in order:
/// 1. `ALTER DATABASE "<renamed>" RENAME TO "<original>"` — restore the name.
/// 2. `ALTER ROLE "<role>" LOGIN` — re-enable the login role.
pub fn recover_soft_deprovision_ddl(renamed: &str, original: &str, role: &str) -> Vec<String> {
    let kind = ExternalSqlKind::Postgres;
    let renamed_id = quote_ident(kind, renamed);
    let original_id = quote_ident(kind, original);
    let role_id = quote_ident(kind, role);
    vec![
        format!("ALTER DATABASE {renamed_id} RENAME TO {original_id};"),
        format!("ALTER ROLE {role_id} LOGIN;"),
    ]
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

    /// A clean, already-safe, short, lowercase name keeps its human-readable
    /// body verbatim, but — for injectivity — *always* carries the `_<digest>`
    /// suffix (the digest disambiguator is unconditional now).
    #[test]
    fn sanitize_clean_name_keeps_body_with_suffix() {
        let out = sanitize_ident("appdb");
        assert!(out.starts_with("appdb_"), "unexpected body: {out}");
        assert_eq!(out, format!("appdb_{}", hash_suffix("appdb")));

        let out2 = sanitize_ident("my_site_42");
        assert!(out2.starts_with("my_site_42_"), "unexpected body: {out2}");
        assert_eq!(out2, format!("my_site_42_{}", hash_suffix("my_site_42")));
    }

    /// A digit-leading but otherwise clean name gets the `t_` prefix, then the
    /// mandatory digest suffix.
    #[test]
    fn sanitize_digit_leading_prefixed() {
        assert_eq!(
            sanitize_ident("1tenant"),
            format!("t_1tenant_{}", hash_suffix("1tenant"))
        );
    }

    /// The disambiguating digest suffix is **always present** — even for a clean,
    /// lowercase, already-safe name — and every identifier stays within the
    /// engine cap (Postgres 63 / MySQL 64 bytes).
    #[test]
    fn sanitize_suffix_always_present_and_bounded() {
        for input in [
            "appdb",
            "my_site_42",
            "acme-corp",
            "Foo",
            "1tenant",
            "",
            "a".repeat(200).as_str(),
        ] {
            let out = sanitize_ident(input);
            // Suffix present: ends in `_` + exactly HASH_B36_LEN base-36 chars.
            assert!(out.len() > HASH_B36_LEN + 1, "too short: {out:?}");
            let (body, sep_hash) = out.split_at(out.len() - (HASH_B36_LEN + 1));
            assert!(sep_hash.starts_with('_'), "no `_<hash>` in {out:?}");
            let hash = &sep_hash[1..];
            assert_eq!(hash.len(), HASH_B36_LEN, "wrong hash width in {out:?}");
            assert!(
                hash.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "non-base36 suffix in {out:?}"
            );
            assert_eq!(hash, hash_suffix(input), "suffix must digest the original");
            let _ = body;
            // Within the Postgres cap (and thus MySQL's too).
            assert!(
                out.len() <= MAX_IDENT_LEN,
                "over cap ({}): {out:?}",
                out.len()
            );
        }
        // The cap must fit the tightest engine limit (Postgres NAMEDATALEN-1).
        const { assert!(MAX_IDENT_LEN <= 63) };
    }

    /// **Injectivity:** a battery of tricky, near-colliding inputs all map to
    /// distinct identifiers. This is the core tenant-isolation property. Includes
    /// the two security-review PoC collision classes (see the dedicated tests
    /// below), so a regression to the old 32-bit / conditional-suffix scheme is
    /// caught here too.
    #[test]
    fn sanitize_is_injective() {
        let long_a = "a".repeat(50);
        let long_b = format!("{}b", "a".repeat(49));
        // PoC class B: two 50-char names sharing a 31-char prefix.
        let prefix31 = "a".repeat(31);
        let poc_b1 = format!("{prefix31}{}", "x".repeat(19));
        let poc_b2 = format!("{prefix31}{}", "y".repeat(19));
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
            // PoC class A: two all-metacharacter names that sanitize to the same
            // `______` body.
            "#//$&%",
            ".-!*%,",
            poc_b1.as_str(),
            poc_b2.as_str(),
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

    /// Security-review PoC class A: two distinct all-metacharacter names that both
    /// sanitize to the same `______` body must still map to distinct identifiers,
    /// because the digest is taken over the *original* bytes.
    #[test]
    fn sanitize_poc_metachar_bodies_distinct() {
        assert_ne!(
            sanitize_ident("#//$&%"),
            sanitize_ident(".-!*%,"),
            "distinct metachar-only names collided"
        );
    }

    /// Security-review PoC class B: two distinct names sharing a sanitized prefix
    /// longer than the body budget (so the truncated body is identical) must still
    /// differ, because the always-on digest disambiguates the full original. The
    /// prefix is `MAX_IDENT_LEN` chars — comfortably past any body budget — so this
    /// holds regardless of the digest width.
    #[test]
    fn sanitize_poc_shared_prefix_distinct() {
        let prefix = "a".repeat(MAX_IDENT_LEN);
        let a = format!("{prefix}{}", "b".repeat(20));
        let b = format!("{prefix}{}", "c".repeat(20));
        assert_ne!(a, b);
        let ia = sanitize_ident(&a);
        let ib = sanitize_ident(&b);
        // Bodies are identical after truncation to the body budget…
        let body_a = &ia[..ia.len() - (HASH_B36_LEN + 1)];
        let body_b = &ib[..ib.len() - (HASH_B36_LEN + 1)];
        assert_eq!(body_a, body_b, "truncated bodies should match");
        // …but the identifiers differ in the digest suffix.
        assert_ne!(ia, ib, "shared-prefix long names collided");
    }

    /// The digest suffix is derived from the original input and is stable across
    /// calls (fixed SHA-256, no `DefaultHasher` run-to-run drift).
    #[test]
    fn sanitize_has_stable_digest_suffix() {
        let a = sanitize_ident("acme-corp");
        let b = sanitize_ident("acme-corp");
        assert_eq!(a, b, "digest suffix must be stable");
        // "acme-corp" -> body "acme_corp" plus `_` plus HASH_B36_LEN base-36 chars.
        assert!(a.starts_with("acme_corp_"), "unexpected body: {a}");
        assert_eq!(a.len(), "acme_corp_".len() + HASH_B36_LEN);
    }

    /// A name longer than the body budget is truncated, but two long names that
    /// share a body-length prefix still differ via the always-on digest.
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

    /// The db/role derivation is deterministic, role != db (carried by the
    /// digest, since the role's input has a trailing `_role` the db's lacks),
    /// both stay within the engine cap, and both are safe-charset.
    #[test]
    fn tenant_names_scheme() {
        let ident = sanitize_ident("acme");
        let db = tenant_db_name("appdb", &ident);
        let role = tenant_role_name("appdb", &ident);
        assert_ne!(db, role);
        assert!(db.contains("appdb"));
        assert!(role.contains("appdb"));
        // Both fit the tightest engine identifier limit.
        assert!(db.len() <= MAX_IDENT_LEN, "db over cap: {db}");
        // A role/user must fit the tighter MySQL 32-char user-name limit.
        assert!(role.len() <= MAX_ROLE_IDENT_LEN, "role over cap: {role}");
        // Deterministic.
        assert_eq!(db, tenant_db_name("appdb", &ident));
        // Safe charset.
        for name in [&db, &role] {
            assert!(name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        }
    }

    /// A compute workload named `pg` (the natural name for a Postgres server) is the
    /// role base, so the role must NOT come out `pg_…` — Postgres reserves that prefix
    /// for system roles and rejects `CREATE ROLE "pg_…"`. Regression for the live gate
    /// failure: `sanitize_ident` guards the `pg_` prefix like a digit-leading start.
    #[test]
    fn pg_reserved_prefix_is_guarded() {
        let ident = sanitize_ident("acme");
        let role = tenant_role_name("pg", &ident);
        assert!(
            !role.starts_with("pg_"),
            "role name must not use the Postgres-reserved pg_ prefix: {role}"
        );
        // The chokepoint itself: neither `pg` nor a `pg_`-leading input escapes.
        assert!(!sanitize_ident("pg").starts_with("pg_"));
        assert!(!sanitize_ident("pg_prod").starts_with("pg_"));
        // A non-reserved `pg`-*containing* name (no trailing `_`) is left alone.
        assert!(sanitize_ident("pgbouncer").starts_with("pgbouncer"));
        // Injectivity survives the guard: distinct inputs → distinct names.
        assert_ne!(sanitize_ident("pg_x"), sanitize_ident("t_pg_x"));
    }

    /// A role/user name must fit MySQL's 32-char user-name limit on ANY base +
    /// tenant, even a very long tenant — the digest (25 base-36 chars) still fits,
    /// injectivity holds, and it never digit-/`pg_`-leads. Regression for the live
    /// MySQL gate failure (`my_acme_… is too long for user name (max 32)`).
    #[test]
    fn role_name_fits_mysql_user_limit() {
        let cases = [
            ("my", "acme"),
            ("pg", "acme"),
            ("postgres", &"z".repeat(200) as &str),
            (
                "verylongworkloadname",
                "another-long-tenant-name-with-dashes",
            ),
        ];
        let mut seen = std::collections::HashSet::new();
        for (base, tenant) in cases {
            let role = tenant_role_name(base, &sanitize_ident(tenant));
            assert!(
                role.len() <= MAX_ROLE_IDENT_LEN,
                "role {role:?} ({} chars) exceeds the MySQL user limit {MAX_ROLE_IDENT_LEN}",
                role.len()
            );
            assert!(!role.starts_with("pg_"), "pg_-reserved role: {role}");
            assert!(
                !role.as_bytes()[0].is_ascii_digit(),
                "digit-leading: {role}"
            );
            assert!(seen.insert(role.clone()), "role name collision: {role}");
        }
    }

    /// Distinct tenants under the same base get distinct db + role names — and it
    /// holds for very long tenants too, where the human-readable body truncates
    /// away and only the always-on digest keeps them apart.
    #[test]
    fn tenant_names_distinct_across_tenants() {
        let a = sanitize_ident("alpha");
        let b = sanitize_ident("beta");
        assert_ne!(tenant_db_name("appdb", &a), tenant_db_name("appdb", &b));
        assert_ne!(tenant_role_name("appdb", &a), tenant_role_name("appdb", &b));

        // Long tenants sharing a body prefix stay distinct via the digest, and
        // the db/role of one long tenant never collide with each other.
        let long_a = sanitize_ident(&"z".repeat(80));
        let long_b = sanitize_ident(&format!("{}q", "z".repeat(79)));
        assert_ne!(
            tenant_db_name("appdb", &long_a),
            tenant_db_name("appdb", &long_b)
        );
        assert_ne!(
            tenant_role_name("appdb", &long_a),
            tenant_role_name("appdb", &long_b)
        );
        assert_ne!(
            tenant_db_name("appdb", &long_a),
            tenant_role_name("appdb", &long_a)
        );
        for n in [
            tenant_db_name("appdb", &long_a),
            tenant_role_name("appdb", &long_a),
        ] {
            assert!(n.len() <= MAX_IDENT_LEN, "over cap: {n}");
        }
    }

    // ---- grant_app_role_ddl ----------------------------------------------

    /// Postgres grants the role the app privileges on existing objects AND sets default
    /// privileges (owned by the schema-loading superuser) for future ones — so the
    /// tenant role can use a superuser-loaded schema regardless of provision/load order.
    #[test]
    fn grant_app_role_ddl_postgres_covers_existing_and_future() {
        let stmts = grant_app_role_ddl(ExternalSqlKind::Postgres, "t_pg_acme_role", "pgadmin");
        let all = stmts.join("\n");
        // Every statement targets the tenant role, quoted.
        assert!(stmts.iter().all(|s| s.contains("\"t_pg_acme_role\"")));
        // Existing objects: GRANT ON ALL … IN SCHEMA public.
        assert!(all.contains("GRANT USAGE ON SCHEMA public"));
        assert!(all.contains("ON ALL TABLES IN SCHEMA public"));
        assert!(all.contains("ON ALL SEQUENCES IN SCHEMA public"));
        // Future objects: ALTER DEFAULT PRIVILEGES FOR ROLE <owner>.
        assert!(all.contains("ALTER DEFAULT PRIVILEGES FOR ROLE \"pgadmin\" IN SCHEMA public"));
        // Read+write DML (the reported bug was an INSERT).
        assert!(all.contains("INSERT"));
        assert!(all.contains("UPDATE"));
        assert!(all.contains("DELETE"));
        // Least privilege: no superuser/ownership escalation, no TRUNCATE.
        assert!(!all.to_ascii_uppercase().contains("SUPERUSER"));
        assert!(!all.to_ascii_uppercase().contains("TRUNCATE"));
        assert!(!all.to_ascii_uppercase().contains("OWNER TO"));
    }

    /// MySQL has no gap — `provision_ddl`'s `db.*` grant already covers every current +
    /// future table — so the grant DDL is empty (nothing extra to run).
    #[test]
    fn grant_app_role_ddl_mysql_is_empty() {
        assert!(grant_app_role_ddl(ExternalSqlKind::Mysql, "role", "owner").is_empty());
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

    /// The Postgres soft-delete DDL evicts sessions, renames the database aside
    /// (freeing the original name), and disables the role — in that order, quoted.
    #[test]
    fn soft_deprovision_renames_and_disables_in_order() {
        let stmts = soft_deprovision_ddl(
            "appdb_acme",
            "appdb_acme__deleted_1700000000",
            "appdb_acme_role",
        );
        assert_eq!(
            stmts,
            vec![
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'appdb_acme';".to_string(),
                "ALTER DATABASE \"appdb_acme\" RENAME TO \"appdb_acme__deleted_1700000000\";".to_string(),
                "ALTER ROLE \"appdb_acme_role\" NOLOGIN;".to_string(),
            ]
        );
        let joined = stmts.join("\n");
        // Soft delete NEVER drops — the data survives the grace window.
        assert!(
            !joined.to_ascii_uppercase().contains("DROP DATABASE"),
            "soft delete must not DROP the database:\n{joined}"
        );
        assert!(!joined.to_ascii_uppercase().contains("DROP ROLE"));
    }

    /// Recovery reverses the soft delete: rename back to the original + re-enable
    /// login, in that order.
    #[test]
    fn recover_soft_deprovision_reverses_rename_and_login() {
        let stmts = recover_soft_deprovision_ddl(
            "appdb_acme__deleted_1700000000",
            "appdb_acme",
            "appdb_acme_role",
        );
        assert_eq!(
            stmts,
            vec![
                "ALTER DATABASE \"appdb_acme__deleted_1700000000\" RENAME TO \"appdb_acme\";"
                    .to_string(),
                "ALTER ROLE \"appdb_acme_role\" LOGIN;".to_string(),
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

    /// Pin the derived-identifier digest to a known SHA-256 vector so a refactor
    /// (e.g. swapping the hash or its truncation width) can't silently shift a
    /// tenant's database/role name between binary versions.
    #[test]
    fn digest_suffix_is_pinned() {
        // Full SHA-256("appdb") is
        // 6f6115c972bf4b6e742ac51d4a2329d0d2c2e4d6269400191d88007c48be798b; we keep
        // the leading 128 bits (0x6f6115c972bf4b6e742ac51d4a2329d0) and encode them in
        // base-36, left-padded to 25 chars.
        assert_eq!(hash_suffix("appdb"), "6ldpyd2wfh6vhvqhj6s5o6hg0");
        // Therefore the whole identifier for a clean name is fully determined.
        assert_eq!(sanitize_ident("appdb"), "appdb_6ldpyd2wfh6vhvqhj6s5o6hg0");
    }
}
