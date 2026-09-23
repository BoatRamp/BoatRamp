# Task #493 — per-tenant sealed-secret capability (`boatramp:handlers/tenant-secrets`)

Implemented on branch `tenant-secrets` (worktree `/Users/jwk/Projects/br-tenant-secrets`, v0.5.3
base). Working tree LEFT DIRTY / UNCOMMITTED for the reviewer. FULL guest CRUD + a per-handler name
allowlist, per the owner-approved 3-role panel.

## Files changed

New:
- `crates/boatramp-handlers/src/bindings/tenant_secrets.rs` — the guest host binding.
- `crates/boatramp/src/project_tenant_secrets.rs` — the CLI subcommand.

Modified:
- `crates/boatramp-core/src/deploy.rs` — `keys::tenant_secret` + `tenant_secret_prefix`.
- `crates/boatramp-core/src/secret_store.rs` — `TenantSecretStore`, error variants, caps, `validate_tenant`, unit tests.
- `crates/boatramp-handlers/wit/world.wit` — `tenant-secrets-types`, `tenant-secrets`, `tenant-secrets-host` world.
- `crates/boatramp-handlers/Cargo.toml` — off-by-default `tenant-secrets` feature.
- `crates/boatramp-handlers/src/bindings/mod.rs` — module + `Bindings` field + `with_tenant_secrets` + accessor.
- `crates/boatramp-handlers/src/engine.rs` — linker wiring (feature-gated).
- `crates/boatramp-handlers/src/lib.rs` — re-exports (`TenantSecretsBinding`, `TenantSecretRefused`).
- `crates/boatramp-types/src/config.rs` — `check_import` + `is_named_tenant_secrets_import`, `tenant_secret_names` on `HandlerConfig`/`ConsumerConfig`, tests.
- `crates/boatramp-types/src/function.rs` — `tenant_secret_names` on `FunctionConfig` + both `From` conversions + test literals.
- `crates/boatramp-types/src/route.rs` — test-literal field.
- `crates/boatramp-types/src/authz.rs` — `Some((&"tenant-secrets", _))` arm + table test + mutation-verified role test.
- `crates/boatramp-server/src/project_scope.rs` — `"tenant-secrets"` in `PROJECT_SCOPED_FAMILIES`.
- `crates/boatramp-server/src/control_api.rs` — `set_tenant_secret`/`list_tenant_secrets`/`delete_tenant_secret`.
- `crates/boatramp-server/src/routes.rs` — route registration + extension layer.
- `crates/boatramp-server/src/lib.rs` — `ServerOptions.tenant_secret_store`, inner `OnceLock`, `set_tenant_secret_store`, handler re-imports, test literals.
- `crates/boatramp-server/src/handler_dispatch.rs` — `build_bindings` param + binding wiring + `ConsumerRebuild` field.
- `crates/boatramp-server/src/function_runtime.rs` — top-level-function binding wiring.
- `crates/boatramp-server/src/scheduler.rs` — consumer/cron `build_bindings` + `ConsumerRebuild` call sites.
- `crates/boatramp-server/Cargo.toml` — `boatramp-handlers/tenant-secrets` inside `handlers`.
- `crates/boatramp-server/tests/conformance.rs` — the `TENANT SECRETS SCOPED OK` live gate + bulk test-literal field.
- `crates/boatramp-node/src/node.rs` — build the store, thread into `ServerOptions`, hand the SAME `Arc` to the runtime (handlers-gated).
- `crates/boatramp/src/client.rs` — `TenantSecretMeta` + `tenant_secret_set`/`list`/`delete` `ControlPlane` methods.
- `crates/boatramp/src/handler_validate.rs` — `capability_token` arm + `HOST_HANDLERS_VERSION` → (0,5,0) + policy test.
- `crates/boatramp/src/project.rs`, `main.rs` — wire `project tenant-secrets`.
- `.github/workflows/ci.yml` — `tenant-secrets scoped gate marker (#493)` step.

## How each binding condition is met

- **STORE (1) / Backend C1 / Security HIGH-2, C3, MEDIUM-3, C5:** `TenantSecretStore` in
  `boatramp-core` (NOT handlers-gated), keyed `project/<p>/tenant-secret/<tenant>/<name>` (a DISTINCT
  keyspace from `secret/`). EVERY method validates `tenant` via `validate_resource_name("tenant", …)`
  AND `name` via the shared `validate_name`, fail-closed BEFORE composing the key — so the guest read
  and the control-plane write compose byte-identical segments. `list` keys its prefix on the TENANT
  (`tenant_secret_prefix(project, tenant)`), strip tail is a single `<name>` (no cross-tenant name
  oracle). `MAX_SECRET_VALUE_LEN` (64 KiB) + a per-`(project,tenant)` name-count cap
  (`MAX_TENANT_SECRET_NAMES` = 256; rotation of an existing name is free, only a NEW name counts).
- **WIT (2) / UX C1:** `get -> result<option<list<u8>>, secret-error>` — unset ⇒ `ok(none)`, NOT an
  error. `variant secret-error { access-denied, no-resolved-tenant, not-configured, invalid-name,
  value-too-large, other }` — NO `not-found`. Doc-comments carry: declare-the-import; host supplies
  the resolved tenant / guest never passes one; `get`→none-for-unconfigured; the `all`/anonymous
  always-`no-resolved-tenant` footgun; the two-secret-stores disambiguation. (`list` is a WIT
  keyword, escaped `%list`; the guest imports it as `list`.)
- **BINDING (3) / rights:** `TenantSecretsBinding { store, project, resolved_tenant, allow_names,
  can_read, can_write }`. Deny-by-default (`TenantSecretsHost::new(None)` ⇒ access-denied).
  `resolved_tenant == None` ⇒ `no-resolved-tenant` BEFORE store access. Per-call right re-check
  (get/list → can_read, set/delete → can_write). `allow_names` filters WHICH names (empty ⇒ deny-all;
  not-in-list ⇒ access-denied, before store access). `bindgen!` + `add_to_linker` + `Bindings::
  with_tenant_secrets`; own off-by-default `tenant-secrets` cargo feature gates the binding + linker.
- **GRANTS + CONFIG (4):** `check_import` recognizes `tenant-secrets:read` and `tenant-secrets:admin`
  as two independent grants (via `is_named_tenant_secrets_import`); a bare `tenant-secrets` / wildcard
  / typo fails at deploy. `#[serde(default)] tenant_secret_names: Vec<String>` on Handler/Consumer/
  Function (empty ⇒ deny-all). Neither grant implied by deploy/publish.
- **TENANT RESOLUTION (5):** at handler dispatch + function/consumer/cron dispatch, the binding is
  built with `resolved_tenant = resolved_tenant_string(&caller_tenant)` (the OWN `ScopeAxis::Tenant`
  fact), `can_read`/`can_write` from the two grants, `allow_names` from `tenant_secret_names`.
- **CONTROL-PLANE (6):** `PUT/GET/DELETE /api/projects/{p}/tenant-secrets/{tenant}{,/{name}}` (value
  in JSON body, 64 KiB body limit, 201 + value-free meta / 204 / 404). Reuses
  `no_secret_store_response` (501) + `secret_error_response`. `{tenant}` validated fail-closed → 400.
  One `TenantSecretStore` built at node startup gated on the `[secrets]` envelope; the SAME `Arc` goes
  to `ServerOptions.tenant_secret_store` (routes) AND `runtime.set_tenant_secret_store` (guest).
- **AUTHZ (7) / Security HIGH-1:** explicit `Some((&"tenant-secrets", _))` arm ABOVE the `Some(_)`
  catch-all, gated `Resource::Secrets` (`if get { Read } else { Write }`) — matching `/api/secrets`,
  NOT `Project·Deploy`. `"tenant-secrets"` added to `PROJECT_SCOPED_FAMILIES`. Mutation-verified test
  `tenant_secrets_routes_gate_on_secrets_not_publisher`: a `project_publisher` does NOT satisfy the
  write; `project_admin`/global `admin` do; the tenant boundary holds.
- **CLI (8):** `boatramp project tenant-secrets set/ls/rm/rotate --tenant <t>` nested under `project`,
  reuses the `ValueSource` (--stdin/--file/--value) pattern, value-free `ls`, `rm` reports existence.
  NOT under bare `boatramp secrets`.
- **handler_validate.rs (9):** `capability_token` maps the `tenant-secrets`/`tenant-secrets-types`
  interfaces to the `tenant-secrets` token, satisfied by either declared `tenant-secrets:<right>` via
  the `token:`-prefix match (v0.4.10 lesson — else `boatramp sync` would refuse it).
  `HOST_HANDLERS_VERSION` bumped (0,4,0) → (0,5,0).

## Shim-repo TODO (do NOT do here — separate coordinated change)

The `boatramp-uchron-shim` repo needs a `compat::tenant_secrets` module (mirroring
`compat::messaging_stats`) exposing the new `boatramp:handlers/tenant-secrets` world to guests, and
`"tenant-secrets"` added to the shim's `function` (+ consumer/session per the axis decision) world
dims. This is a guest WIT addition ⇒ a shim rev. The `HOST_HANDLERS_VERSION` bump to (0,5,0) is
already done host-side. Left as a TODO note per instructions.

## What the live gate proves + why it is non-hollow

`crates/boatramp-server/tests/conformance.rs::tenant_secrets_scoped_end_to_end`, marker
`TENANT SECRETS SCOPED OK`, CI step `tenant-secrets scoped gate marker (#493)`. Drives the REAL
`TenantSecretStore` (memory KV + reversible XOR envelope) + the REAL guest binding
(`Bindings::with_tenant_secrets`, the exact `build_bindings` call) + the REAL control-plane router:
1. tenant A `set`s `oauth_secret`, A `get` returns EXACTLY it;
2. **tenant B `get` returns `none`** for the same name over the SAME store (isolation);
3. a no-resolved-tenant invocation is refused `NoResolvedTenant` BEFORE store access, and the failed
   write is proven absent (B still sees nothing);
4. a `/`-bearing resolved tenant (`firm-a/../firm-b`) is refused before store access (no key reshape);
5. a control-plane `PUT tenant=firm-c` is read back by a guest resolving to firm-c (firm-d gets none)
   — the write + read compose byte-identical segments over ONE store; the 201 body never echoes the
   value;
6. a `%2F`-smuggled and a `*`-bearing control-plane `{tenant}` are both `400` before any write;
7. the value never appears in a `list` or the control-plane list body.

**Non-hollow by construction:** every assertion observes the sealed store's ACTUAL bytes (A's value,
B's absence) or the ACTUAL HTTP status — not a printed string. **Mutation-verified (twice, reverted):**
(a) hard-coding the binding's read tenant to `"firm-a"` (ignoring the resolved tenant) FAILS the gate
at the B-isolation assertion; (b) stubbing `validate_tenant` to `Ok(())` FAILS the gate at the
slash-tenant / `%2F`-400 assertion. Runs entirely in-engine with a memory store — **NO live DB**
needed. (At-rest sealing is proven by the core unit test
`secret_store::tests::tenant_set_get_round_trips_and_is_sealed_at_rest`, which reaches the raw KV key
directly — the conformance test can't, since `deploy::keys` is `pub(crate)`.)

## Tests added

- `boatramp-core::secret_store` — 10 new: round-trip+seal, absent=none, rotate, per-tenant list
  isolation (A never sees B), per-project isolation, delete existence, tenant-segment fail-closed
  (empty/`/`/`..`/`.`/`*`/`\`/ws/ctrl/>63B; numeric round-trips), name fail-closed, size cap,
  name-count cap (rotation free).
- `boatramp-handlers::bindings::tenant_secrets` — 10: ungranted=access-denied, set/get round-trip,
  cross-tenant isolation, unset=ok(none), no-resolved-tenant-before-store, read-only-can't-write,
  admin-only-can't-read, allowlist deny, empty-allowlist deny-all, list only allowlisted + no value.
- `boatramp-types::config` — `tenant-secrets:{read,admin}` accepted, bare/wildcard/typo rejected.
- `boatramp-types::authz` — route table cases + mutation-verified publisher-denial test.
- `boatramp::handler_validate` — either-right-satisfies + wrong-token-rejected.
- `boatramp::project_tenant_secrets` — 3 CLI parse tests (--tenant required, value-source exclusivity).

## FINISH checklist

- `cargo build` (default workspace) — OK.
- `cargo build -p boatramp-node` (default, no-handlers) AND `--features handlers` — OK.
- `cargo fmt --all --check` — clean.
- `cargo clippy --workspace --all-features --all-targets` — clean of ALL tenant-secrets findings.
  Fixed en route: `wrong_self_convention` (`to_wit(self)` → `into_wit`), dead `created_at`
  (`#[allow(dead_code)]` on the wire DTO field). Only pre-existing `boatramp-http` dead-code warnings
  remain (present at HEAD, unrelated).
- New unit tests green; full `boatramp-server` conformance suite green (110 tests incl. the new gate).

## Uncertainty / reviewer attention

- **Resolved-tenant axis at the dispatch sites (the panel's GATING item, Backend C2/C7 + Security
  #2):** I wire `resolved_tenant = resolved_tenant_string(&caller_tenant)` at BOTH the handler and the
  top-level-function/consumer/cron dispatch — the OWN `ScopeAxis::Tenant` fact ONLY, per the panel's
  explicit instruction (do NOT fold in `TargetTenant`). This is the SAME value the SQL scope injector
  uses. **The plan flags that construens's load-bearing path is a per-tenant social handler `get` at
  OAuth token-exchange, which MAY run on a `TargetTenant`/capability/anonymous funnel where the
  own-`Tenant` fact isn't populated** — in which case this feature correctly returns
  `no-resolved-tenant` and does NOT unblock. Per the panel condition, construens must validate its
  token-exchange handler carries the own-`Tenant` fact end-to-end; I did NOT widen
  `resolved_tenant_string`. This is the item most worth confirming against a real construens flow.
- **Feature gating of the conformance gate:** the server has no standalone `tenant-secrets` feature;
  it is always enabled inside the server `handlers` feature, so the gate is `#[cfg(feature =
  "handlers")]` (not `all(handlers, tenant-secrets)`, which would silently never run — the first cut
  did exactly that and ran 0 tests; caught + fixed).
- **`InvalidTenant` never surfaced to the guest:** the binding's `refuse()` maps a store
  `InvalidTenant` to a generic `Other("invalid resolved tenant")` (never echoing the tenant). This
  should be unreachable (the host resolves the tenant as a single scalar), but is defense-in-depth.
- **`allow_names` filters `list` too:** a `list` returns only allowlisted names, so a component can't
  enumerate a name it couldn't itself `get`. Deliberate; flagging in case the reviewer wants `list`
  to show all of the tenant's names regardless of the per-component allowlist.
