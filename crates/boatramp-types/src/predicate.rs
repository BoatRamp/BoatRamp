//! A tiny, bounded predicate language for **conditional routing** — the `when`
//! clause on a [`crate::config::Redirect`] / [`crate::config::Rewrite`].
//!
//! The syntax is a **subset of CEL** (Common Expression Language): boolean
//! expressions over a fixed set of request variables and functions. It is
//! deliberately *not* a general CEL runtime — no timestamps, no macros, no regex
//! engine, no user allocation — so it stays trivially bounded, allocation-light,
//! and fast enough to run on every request in the routing hot path. Predicates
//! are **compiled + type-checked at `sync`/`validate`** (a bad expression fails
//! the deploy, like a bad path pattern) and evaluated against a per-request
//! [`RequestContext`]; a small process-wide [compile cache](compile_cached) means
//! a given expression is parsed at most once per process.
//!
//! Grammar (all whitespace-insensitive):
//! ```text
//! expr    := or
//! or      := and ( '||' and )*
//! and     := unary ( '&&' unary )*
//! unary   := '!' unary | compare
//! compare := concat ( ( '==' | '!=' | 'in' ) concat )?
//! concat  := postfix ( '+' postfix )*                 // string concatenation
//! postfix := primary ( '.' IDENT '(' args? ')' )*     // method calls
//! primary := STRING | INT | 'true' | 'false'
//!          | IDENT | IDENT '(' args? ')' | list | '(' expr ')'
//! list    := '[' ( expr ( ',' expr )* )? ']'
//! args    := expr ( ',' expr )*
//! ```
//!
//! Variables: `method`, `host`, `path` (strings).
//! Functions: `header(name)`, `cookie(name)`, `query(name)` → string (name must be
//! a string literal); `file_exists(path)` → bool; `accepts_language(tag)` → bool;
//! `prefers_language([tags])` → the best-matching tag or `""`.
//! String methods: `.startsWith(s)`, `.endsWith(s)`, `.contains(s)` → bool.
//! List method: `.contains(x)` → bool. Operators: `== != in && || ! +`.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use crate::error::ConfigError;

/// A runtime value produced while evaluating a predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Bool(bool),
    Str(String),
    Int(i64),
    List(Vec<Value>),
}

impl Value {
    fn as_bool(&self) -> bool {
        matches!(self, Value::Bool(true))
    }
}

/// The request attributes a predicate can read. Built once per request by the
/// server; header/cookie/query maps use **lower-cased** keys.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    /// Uppercase HTTP method (`GET`).
    pub method: String,
    /// Request host (no port).
    pub host: String,
    /// Request headers, keyed by lower-case name (multi-values joined by `, `).
    pub headers: BTreeMap<String, String>,
    /// Cookies, keyed by name.
    pub cookies: BTreeMap<String, String>,
    /// Query parameters, keyed by name (first value wins).
    pub query: BTreeMap<String, String>,
    /// Accepted language tags, highest quality first, lower-cased (from
    /// `Accept-Language`). Populate with [`RequestContext::parse_accept_language`].
    pub accept_languages: Vec<String>,
}

impl RequestContext {
    /// Parse an `Accept-Language` header value into quality-sorted, lower-cased
    /// tags (`"fr-FR,fr;q=0.9,en;q=0.8"` → `["fr-fr", "fr", "en"]`). Malformed
    /// `q` values default to `1.0`; a `q=0` tag is dropped (explicitly refused).
    pub fn parse_accept_language(header: &str) -> Vec<String> {
        let mut tagged: Vec<(String, f32)> = Vec::new();
        for part in header.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let mut segs = part.split(';');
            let tag = match segs.next() {
                Some(t) if !t.trim().is_empty() => t.trim().to_ascii_lowercase(),
                _ => continue,
            };
            let mut q = 1.0_f32;
            for seg in segs {
                let seg = seg.trim();
                if let Some(v) = seg.strip_prefix("q=") {
                    q = v.trim().parse::<f32>().unwrap_or(1.0);
                }
            }
            if q > 0.0 && tag != "*" {
                tagged.push((tag, q));
            }
        }
        // Stable sort by descending quality (preserves header order within a tier).
        tagged.sort_by(|a, b| b.1.total_cmp(&a.1));
        tagged.into_iter().map(|(t, _)| t).collect()
    }

    /// Whether the request accepts `tag` — an exact match or a primary-subtag
    /// match in either direction (`fr` accepts `fr-CA`; `fr-FR` accepts `fr`).
    fn accepts_language(&self, tag: &str) -> bool {
        let want = tag.to_ascii_lowercase();
        let want_primary = primary_subtag(&want);
        self.accept_languages
            .iter()
            .any(|have| have == &want || primary_subtag(have) == want_primary)
    }

    /// The first `available` tag the request accepts (availability order wins so
    /// the site controls precedence), or `""` if none match.
    fn prefers_language(&self, available: &[String]) -> String {
        available
            .iter()
            .find(|tag| self.accepts_language(tag))
            .cloned()
            .unwrap_or_default()
    }
}

/// The primary language subtag (`fr-CA` → `fr`).
fn primary_subtag(tag: &str) -> &str {
    tag.split('-').next().unwrap_or(tag)
}

/// Everything a predicate evaluation needs: the request + a file-existence probe
/// (closed over the deployment's manifest so `file_exists` is an in-memory lookup).
pub struct EvalEnv<'a> {
    /// The request attributes.
    pub ctx: &'a RequestContext,
    /// The normalized request path being routed (the `path` variable). Supplied
    /// separately from `ctx` because the router is the authority on it.
    pub path: &'a str,
    /// Does `path` exist in the current deployment's file set?
    pub file_exists: &'a dyn Fn(&str) -> bool,
}

/// A compiled `when` predicate: a type-checked expression plus the set of request
/// header dimensions it reads (for the response `Vary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    root: Expr,
    vary: Vec<String>,
}

impl Predicate {
    /// Compile + type-check a predicate expression. Errors (parse errors, unknown
    /// variables/functions, a non-boolean result, a non-literal `header()` name)
    /// surface at `validate`/`sync`, never at request time.
    pub fn compile(src: &str) -> Result<Self, ConfigError> {
        let tokens = lex(src)?;
        let mut parser = Parser::new(tokens);
        let root = parser.parse_expr()?;
        parser.expect_end()?;
        let ty = check(&root)?;
        if ty != Type::Bool {
            return Err(ConfigError::parse(format!(
                "routing `when` must be a boolean expression, got {}: {src:?}",
                ty.name()
            )));
        }
        let mut vary = Vec::new();
        collect_vary(&root, &mut vary);
        vary.sort();
        vary.dedup();
        Ok(Predicate { root, vary })
    }

    /// The header names whose values this predicate depends on — the response
    /// `Vary` set a caching layer must honor so a per-language/-cookie redirect is
    /// not shared across visitors. Empty if the predicate reads only the URL.
    pub fn vary_headers(&self) -> &[String] {
        &self.vary
    }

    /// Evaluate the predicate against a request. Infallible: a compiled predicate
    /// is already type-checked, so evaluation cannot error — a defensive type
    /// mismatch (unreachable) evaluates to `false` (fail closed: the rule is
    /// simply not applied).
    pub fn eval(&self, env: &EvalEnv<'_>) -> bool {
        eval_expr(&self.root, env)
            .map(|v| v.as_bool())
            .unwrap_or(false)
    }
}

/// Compile `src` through a small process-wide cache so a given expression is
/// parsed at most once per process (predicates are validated at deploy, so this
/// only ever caches valid expressions; the hot path is a lock + hash lookup).
/// The cache is capped and cleared wholesale if it grows past the cap — deploy
/// churn can't leak it, and a cleared cache just re-compiles on next use.
pub fn compile_cached(src: &str) -> Result<Arc<Predicate>, ConfigError> {
    /// A conservative cap: real deployments have a handful of distinct predicates.
    const CAP: usize = 1024;
    static CACHE: OnceLock<RwLock<BTreeMap<String, Arc<Predicate>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));

    if let Some(hit) = cache.read().ok().and_then(|c| c.get(src).cloned()) {
        return Ok(hit);
    }
    let compiled = Arc::new(Predicate::compile(src)?);
    if let Ok(mut c) = cache.write() {
        if c.len() >= CAP {
            c.clear();
        }
        c.insert(src.to_string(), compiled.clone());
    }
    Ok(compiled)
}

/// A redirect/rewrite **destination template**: literal text with embedded
/// `${<expr>}` request expressions (each string-typed), evaluated against the
/// request. Lets one rule route to a computed target — e.g.
/// `to: "/${prefers_language(['fr','en'])}/"` sends the visitor to their locale.
/// `${…}` interpolation runs *before* the `:name`/`:splat` capture expansion the
/// router already applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    parts: Vec<TemplatePart>,
    vary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TemplatePart {
    Lit(String),
    Expr(Expr),
}

impl Template {
    /// Whether a destination string needs template compilation (contains `${`).
    /// The router skips [`compile`](Self::compile) + evaluation when this is false.
    pub fn is_template(dest: &str) -> bool {
        dest.contains("${")
    }

    /// Compile a destination template: split on `${…}`, then parse + type-check
    /// each embedded expression (which must be string-typed). Errors surface at
    /// `validate`/`sync`, never at request time.
    pub fn compile(src: &str) -> Result<Template, ConfigError> {
        let mut parts = Vec::new();
        let mut vary = Vec::new();
        let bytes = src.as_bytes();
        let mut i = 0;
        let mut lit_start = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'{') {
                if i > lit_start {
                    parts.push(TemplatePart::Lit(src[lit_start..i].to_string()));
                }
                let (expr_src, next) = scan_interpolation(src, i + 2)?;
                let tokens = lex(&expr_src)?;
                let mut parser = Parser::new(tokens);
                let expr = parser.parse_expr()?;
                parser.expect_end()?;
                let ty = check(&expr)?;
                if ty != Type::Str {
                    return Err(ConfigError::parse(format!(
                        "template `${{…}}` must be a string expression, got {}: {expr_src:?}",
                        ty.name()
                    )));
                }
                collect_vary(&expr, &mut vary);
                parts.push(TemplatePart::Expr(expr));
                i = next;
                lit_start = next;
            } else {
                i += 1;
            }
        }
        if lit_start < src.len() {
            parts.push(TemplatePart::Lit(src[lit_start..].to_string()));
        }
        vary.sort();
        vary.dedup();
        Ok(Template { parts, vary })
    }

    /// Expand the template against a request: interpolate each `${…}` with its
    /// evaluated string value (a defensive non-string, unreachable after
    /// type-check, interpolates empty).
    pub fn expand(&self, env: &EvalEnv<'_>) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                TemplatePart::Lit(s) => out.push_str(s),
                TemplatePart::Expr(e) => {
                    if let Some(Value::Str(s)) = eval_expr(e, env) {
                        out.push_str(&s);
                    }
                }
            }
        }
        out
    }

    /// The response `Vary` header names the interpolated expressions read.
    pub fn vary_headers(&self) -> &[String] {
        &self.vary
    }
}

/// Scan from just after a `${` (at `start`) to the matching `}`, skipping `}`
/// inside string literals, and return the inner expression source + the index
/// just past the `}`.
fn scan_interpolation(src: &str, start: usize) -> Result<(String, usize), ConfigError> {
    let bytes = src.as_bytes();
    let mut i = start;
    let mut in_str: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match in_str {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                i += 1;
            }
            None => match c {
                b'\'' | b'"' => {
                    in_str = Some(c);
                    i += 1;
                }
                b'}' => return Ok((src[start..i].to_string(), i + 1)),
                _ => i += 1,
            },
        }
    }
    Err(ConfigError::parse(
        "unterminated `${…}` in a routing destination template",
    ))
}

/// Compile a destination template through a process-wide cache (mirrors
/// [`compile_cached`] for predicates).
pub fn compile_template_cached(src: &str) -> Result<Arc<Template>, ConfigError> {
    const CAP: usize = 1024;
    static CACHE: OnceLock<RwLock<BTreeMap<String, Arc<Template>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));
    if let Some(hit) = cache.read().ok().and_then(|c| c.get(src).cloned()) {
        return Ok(hit);
    }
    let compiled = Arc::new(Template::compile(src)?);
    if let Ok(mut c) = cache.write() {
        if c.len() >= CAP {
            c.clear();
        }
        c.insert(src.to_string(), compiled.clone());
    }
    Ok(compiled)
}

// ----------------------------------------------------------------------------
// Lexer
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Str(String),
    Int(i64),
    Ident(String),
    // punctuation / operators
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Dot,
    Bang,
    Plus,
    AndAnd,
    OrOr,
    EqEq,
    NotEq,
}

fn lex(src: &str) -> Result<Vec<Token>, ConfigError> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            '[' => {
                out.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Token::RBracket);
                i += 1;
            }
            ',' => {
                out.push(Token::Comma);
                i += 1;
            }
            '.' => {
                out.push(Token::Dot);
                i += 1;
            }
            '+' => {
                out.push(Token::Plus);
                i += 1;
            }
            '!' if bytes.get(i + 1) == Some(&b'=') => {
                out.push(Token::NotEq);
                i += 2;
            }
            '!' => {
                out.push(Token::Bang);
                i += 1;
            }
            '=' if bytes.get(i + 1) == Some(&b'=') => {
                out.push(Token::EqEq);
                i += 2;
            }
            '&' if bytes.get(i + 1) == Some(&b'&') => {
                out.push(Token::AndAnd);
                i += 2;
            }
            '|' if bytes.get(i + 1) == Some(&b'|') => {
                out.push(Token::OrOr);
                i += 2;
            }
            '\'' | '"' => {
                let (s, next) = lex_string(bytes, i, c as u8)?;
                out.push(Token::Str(s));
                i = next;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                    i += 1;
                }
                let n = src[start..i]
                    .parse::<i64>()
                    .map_err(|e| ConfigError::parse(format!("bad integer in `when`: {e}")))?;
                out.push(Token::Int(n));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < bytes.len()
                    && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                out.push(Token::Ident(src[start..i].to_string()));
            }
            other => {
                return Err(ConfigError::parse(format!(
                    "unexpected character {other:?} in routing `when`"
                )))
            }
        }
    }
    Ok(out)
}

fn lex_string(bytes: &[u8], start: usize, quote: u8) -> Result<(String, usize), ConfigError> {
    let mut s = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                let esc = bytes[i + 1];
                s.push(match esc {
                    b'n' => '\n',
                    b't' => '\t',
                    other => other as char, // \' \" \\ and any other → literal
                });
                i += 2;
            }
            q if q == quote => return Ok((s, i + 1)),
            other => {
                s.push(other as char);
                i += 1;
            }
        }
    }
    Err(ConfigError::parse(
        "unterminated string literal in routing `when`".to_string(),
    ))
}

// ----------------------------------------------------------------------------
// AST + parser
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<Expr>),
    /// A bare variable (`path`) or a function call (`header("x")`).
    Var(String),
    Call {
        name: String,
        args: Vec<Expr>,
    },
    Method {
        recv: Box<Expr>,
        name: String,
        args: Vec<Expr>,
    },
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Eq(Box<Expr>, Box<Expr>),
    NotEq(Box<Expr>, Box<Expr>),
    In(Box<Expr>, Box<Expr>),
    Concat(Box<Expr>, Box<Expr>),
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Parser { tokens, pos: 0 }
    }
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, t: &Token) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_end(&self) -> Result<(), ConfigError> {
        if self.pos == self.tokens.len() {
            Ok(())
        } else {
            Err(ConfigError::parse(format!(
                "trailing tokens in routing `when` (near token {})",
                self.pos
            )))
        }
    }

    fn parse_expr(&mut self) -> Result<Expr, ConfigError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, ConfigError> {
        let mut lhs = self.parse_and()?;
        while self.eat(&Token::OrOr) {
            let rhs = self.parse_and()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, ConfigError> {
        let mut lhs = self.parse_unary()?;
        while self.eat(&Token::AndAnd) {
            let rhs = self.parse_unary()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ConfigError> {
        if self.eat(&Token::Bang) {
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_compare()
    }

    fn parse_compare(&mut self) -> Result<Expr, ConfigError> {
        let lhs = self.parse_concat()?;
        if self.eat(&Token::EqEq) {
            return Ok(Expr::Eq(Box::new(lhs), Box::new(self.parse_concat()?)));
        }
        if self.eat(&Token::NotEq) {
            return Ok(Expr::NotEq(Box::new(lhs), Box::new(self.parse_concat()?)));
        }
        if self.peek() == Some(&Token::Ident("in".to_string())) {
            self.pos += 1;
            return Ok(Expr::In(Box::new(lhs), Box::new(self.parse_concat()?)));
        }
        Ok(lhs)
    }

    fn parse_concat(&mut self) -> Result<Expr, ConfigError> {
        let mut lhs = self.parse_postfix()?;
        while self.eat(&Token::Plus) {
            let rhs = self.parse_postfix()?;
            lhs = Expr::Concat(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_postfix(&mut self) -> Result<Expr, ConfigError> {
        let mut e = self.parse_primary()?;
        while self.eat(&Token::Dot) {
            let name = match self.next() {
                Some(Token::Ident(n)) => n,
                _ => return Err(ConfigError::parse("expected method name after `.`")),
            };
            if !self.eat(&Token::LParen) {
                return Err(ConfigError::parse(format!("expected `(` after `.{name}`")));
            }
            let args = self.parse_args()?;
            e = Expr::Method {
                recv: Box::new(e),
                name,
                args,
            };
        }
        Ok(e)
    }

    fn parse_primary(&mut self) -> Result<Expr, ConfigError> {
        match self.next() {
            Some(Token::Str(s)) => Ok(Expr::Str(s)),
            Some(Token::Int(n)) => Ok(Expr::Int(n)),
            Some(Token::LParen) => {
                let e = self.parse_expr()?;
                if !self.eat(&Token::RParen) {
                    return Err(ConfigError::parse("expected `)`"));
                }
                Ok(e)
            }
            Some(Token::LBracket) => {
                let mut items = Vec::new();
                if self.peek() != Some(&Token::RBracket) {
                    loop {
                        items.push(self.parse_expr()?);
                        if !self.eat(&Token::Comma) {
                            break;
                        }
                    }
                }
                if !self.eat(&Token::RBracket) {
                    return Err(ConfigError::parse("expected `]` to close a list"));
                }
                Ok(Expr::List(items))
            }
            Some(Token::Ident(id)) => match id.as_str() {
                "true" => Ok(Expr::Bool(true)),
                "false" => Ok(Expr::Bool(false)),
                _ if self.eat(&Token::LParen) => {
                    let args = self.parse_args()?;
                    Ok(Expr::Call { name: id, args })
                }
                _ => Ok(Expr::Var(id)),
            },
            other => Err(ConfigError::parse(format!(
                "unexpected token {other:?} in routing `when`"
            ))),
        }
    }

    /// Parse a (possibly empty) comma-separated argument list up to the closing
    /// `)` (which this consumes).
    fn parse_args(&mut self) -> Result<Vec<Expr>, ConfigError> {
        let mut args = Vec::new();
        if self.peek() != Some(&Token::RParen) {
            loop {
                args.push(self.parse_expr()?);
                if !self.eat(&Token::Comma) {
                    break;
                }
            }
        }
        if !self.eat(&Token::RParen) {
            return Err(ConfigError::parse("expected `)` to close a call"));
        }
        Ok(args)
    }
}

// ----------------------------------------------------------------------------
// Type check (names, arities, result type) + Vary extraction
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Type {
    Bool,
    Str,
    Int,
    List,
}

impl Type {
    fn name(self) -> &'static str {
        match self {
            Type::Bool => "bool",
            Type::Str => "string",
            Type::Int => "int",
            Type::List => "list",
        }
    }
}

fn check(e: &Expr) -> Result<Type, ConfigError> {
    match e {
        Expr::Str(_) => Ok(Type::Str),
        Expr::Int(_) => Ok(Type::Int),
        Expr::Bool(_) => Ok(Type::Bool),
        Expr::List(items) => {
            for it in items {
                check(it)?;
            }
            Ok(Type::List)
        }
        Expr::Var(name) => match name.as_str() {
            "method" | "host" | "path" => Ok(Type::Str),
            other => Err(ConfigError::parse(format!(
                "unknown variable {other:?} in routing `when` \
                 (known: method, host, path)"
            ))),
        },
        Expr::Call { name, args } => check_call(name, args),
        Expr::Method { recv, name, args } => check_method(recv, name, args),
        Expr::Not(inner) => {
            expect(inner, Type::Bool)?;
            Ok(Type::Bool)
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            expect(a, Type::Bool)?;
            expect(b, Type::Bool)?;
            Ok(Type::Bool)
        }
        Expr::Eq(a, b) | Expr::NotEq(a, b) => {
            let (ta, tb) = (check(a)?, check(b)?);
            if ta != tb {
                return Err(ConfigError::parse(format!(
                    "cannot compare {} to {} in routing `when`",
                    ta.name(),
                    tb.name()
                )));
            }
            Ok(Type::Bool)
        }
        Expr::In(a, b) => {
            check(a)?;
            expect(b, Type::List)?;
            Ok(Type::Bool)
        }
        Expr::Concat(a, b) => {
            expect(a, Type::Str)?;
            expect(b, Type::Str)?;
            Ok(Type::Str)
        }
    }
}

fn expect(e: &Expr, want: Type) -> Result<(), ConfigError> {
    let got = check(e)?;
    if got == want {
        Ok(())
    } else {
        Err(ConfigError::parse(format!(
            "expected {} in routing `when`, got {}",
            want.name(),
            got.name()
        )))
    }
}

fn check_call(name: &str, args: &[Expr]) -> Result<Type, ConfigError> {
    let arity = |n: usize| -> Result<(), ConfigError> {
        if args.len() == n {
            Ok(())
        } else {
            Err(ConfigError::parse(format!(
                "{name}() takes {n} argument(s), got {} in routing `when`",
                args.len()
            )))
        }
    };
    match name {
        "header" | "cookie" | "query" => {
            arity(1)?;
            // The name must be a literal so we can derive the response `Vary`.
            if !matches!(args[0], Expr::Str(_)) {
                return Err(ConfigError::parse(format!(
                    "{name}() needs a string-literal name in routing `when`"
                )));
            }
            Ok(Type::Str)
        }
        "file_exists" => {
            arity(1)?;
            expect(&args[0], Type::Str)?;
            Ok(Type::Bool)
        }
        "accepts_language" => {
            arity(1)?;
            expect(&args[0], Type::Str)?;
            Ok(Type::Bool)
        }
        "prefers_language" => {
            arity(1)?;
            expect(&args[0], Type::List)?;
            Ok(Type::Str)
        }
        other => Err(ConfigError::parse(format!(
            "unknown function {other:?} in routing `when` (known: header, cookie, \
             query, file_exists, accepts_language, prefers_language)"
        ))),
    }
}

fn check_method(recv: &Expr, name: &str, args: &[Expr]) -> Result<Type, ConfigError> {
    match name {
        "startsWith" | "endsWith" | "contains" => {
            if args.len() != 1 {
                return Err(ConfigError::parse(format!(
                    ".{name}() takes 1 argument in routing `when`"
                )));
            }
            let rt = check(recv)?;
            // `.contains` works on strings or lists; the others are string-only.
            if name == "contains" {
                if rt != Type::Str && rt != Type::List {
                    return Err(ConfigError::parse(
                        ".contains() applies to a string or list in routing `when`",
                    ));
                }
            } else if rt != Type::Str {
                return Err(ConfigError::parse(format!(
                    ".{name}() applies to a string in routing `when`"
                )));
            }
            check(&args[0])?;
            Ok(Type::Bool)
        }
        other => Err(ConfigError::parse(format!(
            "unknown method .{other}() in routing `when` (known: startsWith, \
             endsWith, contains)"
        ))),
    }
}

/// Walk the AST collecting the response `Vary` header names the predicate reads.
fn collect_vary(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Call { name, args } => {
            match name.as_str() {
                "header" => {
                    if let Some(Expr::Str(h)) = args.first() {
                        out.push(h.to_ascii_lowercase());
                    }
                }
                "cookie" => out.push("cookie".to_string()),
                "accepts_language" | "prefers_language" => out.push("accept-language".to_string()),
                _ => {}
            }
            for a in args {
                collect_vary(a, out);
            }
        }
        Expr::Method { recv, args, .. } => {
            collect_vary(recv, out);
            for a in args {
                collect_vary(a, out);
            }
        }
        Expr::List(items) => items.iter().for_each(|i| collect_vary(i, out)),
        Expr::Not(a) => collect_vary(a, out),
        Expr::And(a, b)
        | Expr::Or(a, b)
        | Expr::Eq(a, b)
        | Expr::NotEq(a, b)
        | Expr::In(a, b)
        | Expr::Concat(a, b) => {
            collect_vary(a, out);
            collect_vary(b, out);
        }
        Expr::Str(_) | Expr::Int(_) | Expr::Bool(_) | Expr::Var(_) => {}
    }
}

// ----------------------------------------------------------------------------
// Evaluator
// ----------------------------------------------------------------------------

/// Evaluate `e`. Returns `None` only on a type mismatch that the compile-time
/// [`check`] should already have rejected — callers treat `None` as `false`.
fn eval_expr(e: &Expr, env: &EvalEnv<'_>) -> Option<Value> {
    Some(match e {
        Expr::Str(s) => Value::Str(s.clone()),
        Expr::Int(n) => Value::Int(*n),
        Expr::Bool(b) => Value::Bool(*b),
        Expr::List(items) => Value::List(
            items
                .iter()
                .map(|i| eval_expr(i, env))
                .collect::<Option<_>>()?,
        ),
        Expr::Var(name) => Value::Str(match name.as_str() {
            "method" => env.ctx.method.clone(),
            "host" => env.ctx.host.clone(),
            "path" => env.path.to_string(),
            _ => return None,
        }),
        Expr::Call { name, args } => eval_call(name, args, env)?,
        Expr::Method { recv, name, args } => eval_method(recv, name, args, env)?,
        Expr::Not(a) => Value::Bool(!as_bool(eval_expr(a, env)?)?),
        Expr::And(a, b) => {
            // Short-circuit.
            Value::Bool(as_bool(eval_expr(a, env)?)? && as_bool(eval_expr(b, env)?)?)
        }
        Expr::Or(a, b) => Value::Bool(as_bool(eval_expr(a, env)?)? || as_bool(eval_expr(b, env)?)?),
        Expr::Eq(a, b) => Value::Bool(eval_expr(a, env)? == eval_expr(b, env)?),
        Expr::NotEq(a, b) => Value::Bool(eval_expr(a, env)? != eval_expr(b, env)?),
        Expr::In(a, b) => {
            let needle = eval_expr(a, env)?;
            match eval_expr(b, env)? {
                Value::List(items) => Value::Bool(items.contains(&needle)),
                _ => return None,
            }
        }
        Expr::Concat(a, b) => {
            let (x, y) = (eval_expr(a, env)?, eval_expr(b, env)?);
            match (x, y) {
                (Value::Str(x), Value::Str(y)) => Value::Str(x + &y),
                _ => return None,
            }
        }
    })
}

fn as_bool(v: Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(b),
        _ => None,
    }
}
fn as_str(v: Value) -> Option<String> {
    match v {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

fn eval_call(name: &str, args: &[Expr], env: &EvalEnv<'_>) -> Option<Value> {
    match name {
        "header" => {
            let key = as_str(eval_expr(&args[0], env)?)?.to_ascii_lowercase();
            Some(Value::Str(
                env.ctx.headers.get(&key).cloned().unwrap_or_default(),
            ))
        }
        "cookie" => {
            let key = as_str(eval_expr(&args[0], env)?)?;
            Some(Value::Str(
                env.ctx.cookies.get(&key).cloned().unwrap_or_default(),
            ))
        }
        "query" => {
            let key = as_str(eval_expr(&args[0], env)?)?;
            Some(Value::Str(
                env.ctx.query.get(&key).cloned().unwrap_or_default(),
            ))
        }
        "file_exists" => {
            let path = as_str(eval_expr(&args[0], env)?)?;
            Some(Value::Bool((env.file_exists)(&path)))
        }
        "accepts_language" => {
            let tag = as_str(eval_expr(&args[0], env)?)?;
            Some(Value::Bool(env.ctx.accepts_language(&tag)))
        }
        "prefers_language" => {
            let list = match eval_expr(&args[0], env)? {
                Value::List(items) => items.into_iter().map(as_str).collect::<Option<Vec<_>>>()?,
                _ => return None,
            };
            Some(Value::Str(env.ctx.prefers_language(&list)))
        }
        _ => None,
    }
}

fn eval_method(recv: &Expr, name: &str, args: &[Expr], env: &EvalEnv<'_>) -> Option<Value> {
    let recv = eval_expr(recv, env)?;
    let arg = eval_expr(&args[0], env)?;
    let result = match (&recv, name) {
        (Value::Str(s), "startsWith") => s.starts_with(&as_str(arg)?),
        (Value::Str(s), "endsWith") => s.ends_with(&as_str(arg)?),
        (Value::Str(s), "contains") => s.contains(&as_str(arg)?),
        (Value::List(items), "contains") => items.contains(&arg),
        _ => return None,
    };
    Some(Value::Bool(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RequestContext {
        RequestContext {
            method: "GET".into(),
            host: "example.com".into(),
            headers: BTreeMap::from([("x-country".into(), "IT".into())]),
            cookies: BTreeMap::from([("beta".into(), "1".into())]),
            query: BTreeMap::from([("debug".into(), "1".into())]),
            accept_languages: vec!["fr-fr".into(), "fr".into(), "en".into()],
        }
    }

    fn eval(src: &str, files: &[&str]) -> bool {
        let p = Predicate::compile(src).unwrap_or_else(|e| panic!("compile {src:?}: {e}"));
        let c = ctx();
        let exists = |path: &str| files.contains(&path);
        p.eval(&EvalEnv {
            ctx: &c,
            path: "/de/page",
            file_exists: &exists,
        })
    }

    #[test]
    fn accept_language_parses_and_sorts_by_quality() {
        assert_eq!(
            RequestContext::parse_accept_language("fr-FR,fr;q=0.9,en;q=0.8"),
            vec!["fr-fr", "fr", "en"]
        );
        // q=0 is an explicit refusal → dropped; malformed q defaults to 1.0.
        assert_eq!(
            RequestContext::parse_accept_language("de;q=0, en;q=x, es"),
            vec!["en", "es"]
        );
        assert!(RequestContext::parse_accept_language("*").is_empty());
    }

    #[test]
    fn language_negotiation_matches_primary_subtag() {
        // Request accepts fr-fr/fr/en; site offers ['fr','en'] → prefers fr.
        assert!(eval("prefers_language(['fr','en']) == 'fr'", &[]));
        // Availability order decides ties the request is agnostic about.
        assert!(eval("prefers_language(['en','fr']) == 'en'", &[]));
        // accepts_language matches primary subtag either direction.
        assert!(eval("accepts_language('fr-CA')", &[]));
        assert!(eval("accepts_language('en')", &[]));
        assert!(!eval("accepts_language('de')", &[]));
        // No match → empty string.
        assert!(eval("prefers_language(['de','es']) == ''", &[]));
    }

    #[test]
    fn file_exists_and_concat_and_path() {
        assert!(eval("file_exists('/fr/page')", &["/fr/page"]));
        assert!(!eval("file_exists('/fr/page')", &["/en/page"]));
        // The classic locale fallback: no localized file for this path.
        assert!(eval(
            "!file_exists('/fr' + path)",
            &["/de/page"] // '/fr/de/page' absent
        ));
        assert!(!eval("!file_exists('/fr' + path)", &["/fr/de/page"]));
    }

    #[test]
    fn logical_ops_comparisons_membership_and_methods() {
        assert!(eval("method == 'GET' && host == 'example.com'", &[]));
        assert!(eval("method in ['GET','HEAD']", &[]));
        assert!(!eval("method in ['POST']", &[]));
        assert!(eval("path.startsWith('/de')", &[]));
        assert!(eval("path.endsWith('page')", &[]));
        assert!(eval("path.contains('/de/')", &[]));
        assert!(eval("header('x-country') == 'IT'", &[]));
        assert!(eval("cookie('beta') == '1'", &[]));
        assert!(eval("query('debug') == '1'", &[]));
        assert!(eval("!(method == 'POST')", &[]));
        assert!(eval(
            "header('x-country') == 'IT' || header('x-country') == 'FR'",
            &[]
        ));
    }

    #[test]
    fn header_name_is_case_insensitive() {
        // Header lookups fold case; the ctx stores lower-cased keys.
        assert!(eval("header('X-Country') == 'IT'", &[]));
    }

    #[test]
    fn vary_headers_are_derived_for_caching() {
        let p =
            Predicate::compile("prefers_language(['fr']) == 'fr' && header('X-Country') == 'IT'")
                .unwrap();
        assert_eq!(p.vary_headers(), &["accept-language", "x-country"]);
        // Cookie reads vary on Cookie.
        let p = Predicate::compile("cookie('beta') == '1'").unwrap();
        assert_eq!(p.vary_headers(), &["cookie"]);
        // A URL-only predicate varies on nothing.
        let p = Predicate::compile("path.startsWith('/de')").unwrap();
        assert!(p.vary_headers().is_empty());
    }

    #[test]
    fn compile_rejects_bad_predicates() {
        // Non-boolean result.
        assert!(Predicate::compile("path").is_err());
        assert!(Predicate::compile("prefers_language(['fr'])").is_err());
        // Unknown variable / function / method.
        assert!(Predicate::compile("country == 'IT'").is_err());
        assert!(Predicate::compile("geoip('IT')").is_err());
        assert!(Predicate::compile("path.matches('/de.*')").is_err());
        // Type mismatch.
        assert!(Predicate::compile("method == 3").is_err());
        assert!(Predicate::compile("method in 'GET'").is_err());
        // header() needs a literal name (so Vary is derivable).
        assert!(Predicate::compile("header(path) == 'x'").is_err());
        // Syntax errors.
        assert!(Predicate::compile("method ==").is_err());
        assert!(Predicate::compile("(method == 'GET'").is_err());
        assert!(Predicate::compile("'unterminated").is_err());
    }

    #[test]
    fn compile_cache_returns_equal_predicates() {
        let a = compile_cached("method == 'GET'").unwrap();
        let b = compile_cached("method == 'GET'").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(compile_cached("nonsense(").is_err());
    }

    #[test]
    fn template_interpolates_and_reports_vary() {
        assert!(Template::is_template("/${x}/"));
        assert!(!Template::is_template("/static/"));

        // A dynamic destination: send to the negotiated locale (ctx prefers fr).
        let t = Template::compile("/${prefers_language(['fr','en'])}/home").unwrap();
        assert_eq!(t.vary_headers(), &["accept-language"]);
        let c = ctx();
        let exists = |_p: &str| false;
        let env = EvalEnv {
            ctx: &c,
            path: "/",
            file_exists: &exists,
        };
        assert_eq!(t.expand(&env), "/fr/home");

        // Multiple interpolations + literals, including a header read.
        let t = Template::compile("/${header('x-country')}/${prefers_language(['fr'])}").unwrap();
        assert_eq!(t.vary_headers(), &["accept-language", "x-country"]);
        assert_eq!(t.expand(&env), "/IT/fr");

        // A literal-only template expands to itself with no vary.
        let t = Template::compile("/en/home").unwrap();
        assert!(t.vary_headers().is_empty());
        assert_eq!(t.expand(&env), "/en/home");

        // Compile rejects a non-string interpolation and an unterminated `${`.
        assert!(Template::compile("/${file_exists('/x')}/").is_err());
        assert!(Template::compile("/${prefers_language(['fr'])").is_err());
    }
}
