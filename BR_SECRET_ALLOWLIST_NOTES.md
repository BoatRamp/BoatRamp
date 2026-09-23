# Task #492 — per-guest secret allowlist over the per-site `[handlers].secrets` pool

Opt-in, least-privilege scoping of the site secret pool per guest. Absent/empty ⇒ inject the whole
pool (today's behavior, NON-breaking); non-empty ⇒ inject only the named keys.

## Guest-config kinds covered

The site pool (`HandlersSiteConfig.secrets`, `boatramp-types/src/config.rs`) is injected into a
guest's env at exactly ONE choke point: `resolve_env(...)` in
`crates/boatramp-server/src/handler_dispatch.rs`, which passes `&site_handlers.secrets` to
`resolve_secret_env`. `resolve_env` is called only from `build_bindings` (the handler/consumer/cron
binding builder). I traced every `build_bindings` caller and every config kind:

- **HandlerConfig** — gets the site pool via the HTTP-dispatch `build_bindings` call. **COVERED:**
  new `secrets: Vec<String>` field + threaded to `resolve_env`.
- **ConsumerConfig** — gets the site pool via the scheduler's once-per-tick `build_bindings` AND the
  per-message `ConsumerRebuild::bindings_for` (for `signed_context` consumers). **COVERED:** new
  `secrets` field + threaded through both the scheduler call and the `ConsumerRebuild` struct.
- **CronConfig** — NOT a guest itself; a cron resolves to a `HandlerConfig` route via
  `route::match_handler`, and the cron `build_bindings` call passes that matched `handler`. So a cron
  **transitively inherits the matched handler's allowlist** — no field on `CronConfig`. **COVERED
  transitively** (the scheduler cron call passes `&handler.secrets`).
- **StreamConfig** — pure host-side SSE/WebSocket pub/sub fan-out. No guest instantiation, no
  `build_bindings`/`resolve_env`, no secrets injected. **N/A — nothing to do.**
- **SessionConfig** — served through `build_function_bindings` using its own wrapped
  `FunctionConfig.secrets` (a per-guest map), NOT the site pool. The task says functions carry their
  own per-function secrets and must be left untouched; sessions use that path. **OUT OF SCOPE —
  untouched.**

So the two kinds that receive the SITE pool and got the allowlist field are **HandlerConfig** and
**ConsumerConfig**; cron is covered via the matched handler.

## The filter choke point

- One-place helper `filter_site_secrets(pool, allowlist) -> BTreeMap` in `handler_dispatch.rs`:
  empty allowlist ⇒ clone the whole pool; non-empty ⇒ keep only entries whose KEY is in the
  allowlist. Pure projection — it never fabricates a key (an unknown allowlist name is dropped here;
  admission is the enforcement point for typos).
- Applied inside `resolve_env` BEFORE `resolve_secret_env`, so a non-granted secret is never even
  read from the host env / project store for that guest. `allow_env_secret_refs` semantics unchanged
  (the multi-tenant host-env refusal still applies to whatever survives the filter).
- `build_bindings` gained a `secret_allowlist: &[String]` param (mirrors the existing per-guest
  `stats_topics`/`handler_tenancy` threading). Passed as `&handler.secrets` / `&consumer.secrets`
  from all four call sites (HTTP dispatch, scheduler consumer, scheduler cron, ConsumerRebuild).

## Config validation

The site pool lives in the site-scoped `HandlersSiteConfig`, which the deploy manifest's offline
`DeployConfig::check_handlers` cannot see — so the cross-config check lives at ACTIVATION:
`SecurityRuntime::precheck_activation` (`crates/boatramp-server/src/lib.rs`) iterates
`manifest.config.handlers` + `.consumers` and calls the new
`handler_dispatch::admit_secret_allowlist(pool, allowlist, label)`:

- empty allowlist ⇒ OK (inject-all default);
- non-empty allowlist against an EMPTY pool ⇒ hard error (nothing to grant);
- any allowlist name not a key of the pool ⇒ hard error naming the guest (`label` = route+methods /
  consumer topic) + the offending name + the known keys (typo/rot protection).

This mirrors the existing `check_import` unknown-import pattern. (Note: this runs at activation, not
at pure TOML parse, because parse-time has no site pool to check against — the pool is a separate
KV-stored config.)

## Tests

- `boatramp-types` unit `secret_allowlist_field_defaults_empty_and_round_trips`: the field parses,
  defaults empty (inject-all), round-trips, and is elided when empty (byte-identical to pre-#492).
- `boatramp-server` lib `handler_dispatch::secret_allowlist_tests` (6 tests): `filter_site_secrets`
  keeps only declared keys; empty ⇒ full map; drops an unknown name without inventing entries;
  `admit_secret_allowlist` accepts known/empty, rejects an undefined name (naming guest + name), and
  rejects any allowlist against an empty pool.
- `boatramp-server` lib `resolve_env_applies_the_per_guest_secret_allowlist`: drives the REAL
  `resolve_env` choke point — guest A (`["SECRET_A"]`) resolves SECRET_A but NOT SECRET_B; guest B
  (no allowlist) resolves both. (Resolved-env layer; asserts the positive grant the guest can't
  surface.)
- CI-hard gate `boatramp-server` `tests/conformance.rs`
  `handler_secret_allowlist_scopes_the_site_pool_end_to_end` — prints **`SECRET ALLOWLIST SCOPED
  OK`**. Two handlers share an IDENTICAL 2-entry pool; handler A grants only `SECRET_A`, handler B
  grants nothing. Driven end-to-end through the real `router()` → dispatch → `build_bindings` →
  `resolve_env` → engine, serving the committed `http-200` guest's `/env` endpoint (which echoes the
  `GREETING` env var). `GREETING` is the guest-observable proxy for the ungranted secret: A's guest
  reports `greeting=unset` (filtered out), B's reports the injected value.

### Why the gate is non-hollow

I mutation-tested it: replacing the `filter_site_secrets(...)` call in `resolve_env` with the whole
pool makes handler A receive `GREETING` → its guest echoes `greeting=leaked-secret-b` instead of
`greeting=unset` → **the gate FAILS** (verified — both the conformance gate and the `resolve_env`
unit test fail under the mutation, then pass again once reverted). The assertion observes the
ABSENCE of the ungranted secret, which is exactly the property the filter provides.

### Why two SITES rather than two handlers on one site in the gate

The committed `http-200` guest only branches on the exact stripped path `/env`, and two handlers
can't share route `/env` on one site. So the gate mounts the two handlers on `blog-a`/`blog-b` with
an IDENTICAL pool DEFINITION — the difference under test is purely the per-handler allowlist. This
keeps the gate fully end-to-end and observable without rebuilding the wasm fixture (the
`wasm32-wasip2` target is not installed in this environment, and the fixture is a committed binary).

## Finish state

- `cargo clippy --workspace --all-features --all-targets` → clean (EXIT 0). The only two warnings
  anywhere (`boatramp-http` `get_ref`/`sendfile_socket` "never used") PRE-EXIST on the base branch
  (a macOS-only `#[cfg(not(target_os = "linux"))]` dead-code artifact) and are not in this diff —
  verified by stashing my changes and re-running clippy on `boatramp-http`.
- `cargo fmt --all --check` → clean (EXIT 0).
- All new unit tests + the gate → green; all pre-existing resolve/secret/env/desugar tests still
  green (207 boatramp-types tests pass; the existing `handler_env_injected_host_env_not_inherited`
  conformance test still passes).

## Uncertainty / notes

- **Disk pressure (environment, not the change):** the machine's root FS was ~100% full from
  concurrent worktrees' large `target/` dirs. `cargo clippy --workspace --all-features --all-targets`
  (a superset compile that also links every test binary) completed EXIT 0 after I reclaimed space by
  cleaning ONLY this worktree's own `target/` (never another worktree — per instructions). A
  subsequent plain `cargo build` failed ONLY at the final linker write of the large `boatramp` CLI
  binary (errno 28 / "No space left on device") — every source crate compiled and the
  `boatramp-server`/`boatramp-types` libraries linked; this is disk capacity, not a code error (the
  default `cargo build` succeeded EXIT 0 at the start of the session, before the all-features clippy
  filled the disk).
- Validation placement (activation-time `precheck_activation`, not TOML parse) is deliberate and
  documented above — flagging it since the task said "config-parse rejects"; the pure parse layer
  cannot see the site pool, so the cross-config check must be where both configs are in scope.
- Left uncommitted, tree dirty, as instructed.
