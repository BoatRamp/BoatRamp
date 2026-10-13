//! **Credential redaction for log/error strings** — the single choke point the
//! project export/import path (and anything else that touches a DSN) runs a string
//! through before it can land in a `tracing` event, an error message, or a surfaced
//! diagnostic.
//!
//! The non-leak rule (mirroring `boatramp-docker`'s "creds from env, never from the
//! spec"): a database credential rides in a container's **environment**, never in argv
//! and never formatted into a free string. But a DSN is assembled as a string to be
//! handed to a client, and a careless `format!("...: {url}")` on an error path would
//! leak it into a log. [`redact_dsn`] masks the two shapes a credential takes in such a
//! string — the `user:password@` **userinfo** of a `scheme://…` URL, and a
//! `password=` / `PGPASSWORD=` **assignment** — so the choke point is honest even if a
//! caller is careless.
//!
//! Pure + allocation-only (no regex dep), so it is cheap to apply defensively and is
//! unit-mutation-gated in the merge gate (neuter it and a leaked DSN sails through the
//! redaction test).

/// The replacement token substituted for a redacted credential.
pub const REDACTED: &str = "REDACTED";

/// Redact any database credential from `input`, returning a copy safe to log.
///
/// Masks:
/// 1. the `user:password@` (or `user@`) **userinfo** of every `scheme://authority…`
///    occurrence — the whole userinfo is replaced, so a percent-encoded password is
///    masked too; and
/// 2. every `password=…` / `pgpassword=…` **assignment** (query-string or
///    environment-style), value masked up to the next delimiter.
///
/// Everything else is preserved byte-for-byte. Over-redaction is the safe direction, so
/// the matchers lean inclusive; they never under-redact a real credential.
#[must_use]
pub fn redact_dsn(input: &str) -> String {
    redact_kv_passwords(&redact_userinfo(input))
}

/// Replace the `user[:password]@` userinfo of every `scheme://authority…` with
/// [`REDACTED`], leaving the scheme, host, port, path, and query intact.
fn redact_userinfo(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with("://") {
            out.push_str("://");
            i += 3;
            // The authority runs from here to the first path/query/fragment/whitespace
            // delimiter. All delimiters are ASCII, so a byte scan is UTF-8 safe (a
            // multibyte char's bytes are all >= 0x80 and never match a delimiter).
            let auth_start = i;
            let mut j = i;
            while j < input.len() {
                match bytes[j] {
                    b'/' | b'?' | b'#' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' => break,
                    _ => j += 1,
                }
            }
            let authority = &input[auth_start..j];
            // A host never contains '@', so any '@' marks the userinfo separator; the
            // last one is authoritative.
            if let Some(at) = authority.rfind('@') {
                out.push_str(REDACTED);
                out.push_str(&authority[at..]); // "@host[:port]"
            } else {
                out.push_str(authority);
            }
            i = j;
        } else {
            let ch = input[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Mask the value of every `password=` / `pgpassword=` assignment (case-insensitive)
/// up to the next delimiter (`&`, `;`, whitespace, quote, end).
fn redact_kv_passwords(input: &str) -> String {
    // Longer key first so `pgpassword` is matched whole, not as `password` at offset 2.
    const KEYS: &[&str] = &["pgpassword", "password"];
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    'outer: while i < input.len() {
        for key in KEYS {
            if lower[i..].starts_with(key) {
                let after = i + key.len();
                // Optional whitespace, then it must be `=` for this to be an assignment.
                let mut k = after;
                while k < input.len() && matches!(bytes[k], b' ' | b'\t') {
                    k += 1;
                }
                if k < input.len() && bytes[k] == b'=' {
                    out.push_str(&input[i..=k]); // key + optional ws + '='
                    let mut v = k + 1;
                    while v < input.len() {
                        match bytes[v] {
                            b'&' | b';' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' => break,
                            _ => v += 1,
                        }
                    }
                    out.push_str(REDACTED);
                    i = v;
                    continue 'outer;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_url_userinfo_but_keeps_host_and_path() {
        assert_eq!(
            redact_dsn("postgres://alice:s3cr3t@db.host:5432/mydb"),
            "postgres://REDACTED@db.host:5432/mydb"
        );
        // A percent-encoded password (containing an encoded '@') is still fully masked.
        assert_eq!(
            redact_dsn("mysql://u:p%40ss%3Aword@10.0.0.5:3306/app"),
            "mysql://REDACTED@10.0.0.5:3306/app"
        );
        // user-only userinfo is masked too.
        assert_eq!(
            redact_dsn("postgres://alice@db:5432/x"),
            "postgres://REDACTED@db:5432/x"
        );
    }

    #[test]
    fn masks_password_assignments_in_query_and_env_form() {
        assert_eq!(
            redact_dsn("host=db user=alice password=hunter2 sslmode=require"),
            "host=db user=alice password=REDACTED sslmode=require"
        );
        assert_eq!(redact_dsn("PGPASSWORD=hunter2"), "PGPASSWORD=REDACTED");
        // Both shapes at once: userinfo AND a trailing password query param.
        assert_eq!(
            redact_dsn("postgres://u:pw@h:5432/d?sslmode=require&password=foo&x=1"),
            "postgres://REDACTED@h:5432/d?sslmode=require&password=REDACTED&x=1"
        );
    }

    #[test]
    fn leaves_credential_free_strings_untouched() {
        // No userinfo, no password assignment -> byte-identical.
        let s = "pull pgvector/pgvector:pg16: No such image";
        assert_eq!(redact_dsn(s), s);
        let s2 = "create boatramp-ephemeral-123-0: conflict";
        assert_eq!(redact_dsn(s2), s2);
        // An '@' AFTER the authority (in a path) is not userinfo and is preserved.
        assert_eq!(redact_dsn("http://host/path/a@b"), "http://host/path/a@b");
    }

    #[test]
    fn a_leaked_secret_never_survives_redaction() {
        // The anti-hollow property: the secret literal must not appear in the output.
        let secret = "sup3r-s3cret-pw";
        let line = format!("connect postgres://svc:{secret}@db:5432/app failed");
        let red = redact_dsn(&line);
        assert!(
            !red.contains(secret),
            "redaction leaked the password: {red}"
        );
        assert!(red.contains("REDACTED"));
    }
}
