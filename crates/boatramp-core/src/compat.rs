//! Migration shim: parse Netlify/Cloudflare-Pages-style `_redirects` and
//! `_headers` files into boatramp's [`Redirect`]/[`Rewrite`]/[`HeaderRule`]
//! types, so a site moving to boatramp doesn't have to hand-rewrite
//! its routing config in `project.cfg`.
//!
//! Pattern translation: these formats use a trailing `*` as the "splat" (match
//! the rest, including `/`) and `:placeholder` for a segment, with `:splat` in
//! the target. boatramp spells the splat `**` (see [`crate::matcher`]) and also
//! expands `:splat`, so the only rewrite needed is `*` → `**`; `:name`/`:splat`
//! carry over unchanged.

use std::collections::BTreeMap;

use crate::config::{HeaderRule, Redirect, Rewrite};

/// The redirect/rewrite rules parsed from a `_redirects` file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CompatRules {
    /// 3xx redirects (a status `>= 300`, or the default when omitted).
    pub redirects: Vec<Redirect>,
    /// Rewrites/proxies (a `2xx` status — serve `to` without changing the URL).
    pub rewrites: Vec<Rewrite>,
}

/// Translate a `_redirects`/`_headers` path pattern to boatramp's syntax: the
/// `*` splat becomes `**`. `:name`/`:splat` are already compatible.
fn translate_pattern(pattern: &str) -> String {
    pattern.replace('*', "**")
}

/// Parse a `_redirects` file. Unparsable lines, comments (`#`), and blanks are
/// skipped. Conditions and the force (`!`) suffix are ignored (boatramp rewrites
/// are file-losing fallbacks, so `force` has no equivalent) — the status and
/// from/to are honored.
pub fn parse_redirects(text: &str) -> CompatRules {
    let mut out = CompatRules::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(from), Some(to)) = (fields.next(), fields.next()) else {
            continue; // need at least from + to
        };
        // Optional status (may carry a trailing `!` force marker we ignore), and
        // we stop at the first token that isn't a status (conditions follow).
        let status = fields
            .next()
            .map(|tok| tok.trim_end_matches('!'))
            .and_then(|tok| tok.parse::<u16>().ok());
        let from = translate_pattern(from);
        match status {
            // 2xx → a rewrite (serve `to`, keep the URL); also covers proxying
            // when `to` is absolute, which boatramp handles in the rewrite stage.
            Some(code) if (200..300).contains(&code) => out.rewrites.push(Rewrite {
                from,
                to: to.to_string(),
                status: code,
            }),
            // Any other explicit status is a redirect.
            Some(code) => out.redirects.push(Redirect {
                from,
                to: to.to_string(),
                status: code,
            }),
            // No status → a permanent redirect (Netlify defaults to 301).
            None => out.redirects.push(Redirect {
                from,
                to: to.to_string(),
                status: 301,
            }),
        }
    }
    out
}

/// Parse a `_headers` file: a path line (no leading whitespace) followed by
/// indented `Name: value` lines, repeated. A `! Name` line removes a header.
pub fn parse_headers(text: &str) -> Vec<HeaderRule> {
    let mut rules: Vec<HeaderRule> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        let content = line.trim();
        if !indented {
            // A new path block.
            rules.push(HeaderRule {
                matches: translate_pattern(content),
                set: BTreeMap::new(),
                unset: Vec::new(),
            });
            continue;
        }
        let Some(rule) = rules.last_mut() else {
            continue; // an indented line before any path — ignore
        };
        if let Some(name) = content.strip_prefix('!') {
            // `! Header-Name` removes a header.
            let name = name.trim();
            if !name.is_empty() {
                rule.unset.push(name.to_string());
            }
        } else if let Some((name, value)) = content.split_once(':') {
            rule.set
                .insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    // Drop path blocks that ended up with no directives.
    rules.retain(|r| !r.set.is_empty() || !r.unset.is_empty());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_translate_splat_and_status() {
        let rules = parse_redirects(
            "# comment\n\
             /old/:slug   /new/:slug   301\n\
             /api/*       https://api.example.com/:splat   200\n\
             /blog/*      /index.html   200!\n\
             /legacy      /home\n\
             /gone        /            410\n",
        );
        assert_eq!(
            rules.redirects,
            vec![
                Redirect {
                    from: "/old/:slug".into(),
                    to: "/new/:slug".into(),
                    status: 301
                },
                Redirect {
                    from: "/legacy".into(),
                    to: "/home".into(),
                    status: 301
                },
                Redirect {
                    from: "/gone".into(),
                    to: "/".into(),
                    status: 410
                },
            ]
        );
        assert_eq!(
            rules.rewrites,
            vec![
                Rewrite {
                    from: "/api/**".into(),
                    to: "https://api.example.com/:splat".into(),
                    status: 200
                },
                Rewrite {
                    from: "/blog/**".into(),
                    to: "/index.html".into(),
                    status: 200
                },
            ]
        );
    }

    #[test]
    fn spa_fallback_line() {
        let rules = parse_redirects("/*  /index.html  200\n");
        assert_eq!(rules.rewrites.len(), 1);
        assert_eq!(rules.rewrites[0].from, "/**");
        assert_eq!(rules.rewrites[0].to, "/index.html");
    }

    #[test]
    fn headers_blocks_set_and_unset() {
        let rules = parse_headers(
            "/*\n  \
               X-Frame-Options: DENY\n  \
               Referrer-Policy: no-referrer\n\
             /assets/*\n  \
               Cache-Control: max-age=31536000\n  \
               ! X-Powered-By\n\
             /empty\n",
        );
        assert_eq!(rules.len(), 2, "the empty block is dropped");
        assert_eq!(rules[0].matches, "/**");
        assert_eq!(rules[0].set.get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(rules[0].set.get("Referrer-Policy").unwrap(), "no-referrer");
        assert_eq!(rules[1].matches, "/assets/**");
        assert_eq!(
            rules[1].set.get("Cache-Control").unwrap(),
            "max-age=31536000"
        );
        assert_eq!(rules[1].unset, vec!["X-Powered-By".to_string()]);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let rules = parse_redirects("only-one-field\n\n   \n");
        assert!(rules.redirects.is_empty() && rules.rewrites.is_empty());
    }
}
