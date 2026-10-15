# Config resolution rewrite: one `figment` pipeline for every subcommand

Status: **WIP scaffolding landed** behind the off-by-default `config-figment` feature
(`crates/boatramp-node`). The `BOATRAMP_*` environment overlay + its figment provider
are implemented and parity-tested against today's loader; the file + flag layers and the
flip to the default path are the remaining work (below). This doc is the spec the
remainder executes from.

## Why

We keep discovering env vars that "were forgotten along the way" — a knob settable in
`boatramp.cfg` but not via `BOATRAMP_*`, or settable for `serve` but not for the offline
ops. The root cause is **three hand-maintained env loaders that drift**, each covering a
different (overlapping, inconsistent) slice:

| Loader | Where | Runs for | Covers |
| --- | --- | --- | --- |
| **A** | serve clap `#[arg(env = …)]` (`crates/boatramp/src/serve.rs`) | `serve` only | `serve.*` scalars + runtime selectors (kv backend, tls, acme, cluster-action flags) |
| **B** | `ServerConfig::apply_env_overrides` (`crates/boatramp-node/src/config.rs`) | **every** `ServerConfig::load` caller (serve, `blob migrate`, `token`, offline `migrate`) | compute / security / handlers / secrets / cluster + the 3 dynamic maps + `serve.blob_backends` / `listeners` / `s3_ingress_cloud` |
| **C** | ad-hoc `std::env::var` in serve | `serve` / `run_cluster` only | `serve.kv.*` knobs + 2 runtime knobs |

**The core bug:** A and C are serve-only; B is everywhere. So `BOATRAMP_S3_BUCKET`
(Loader A) is honored by `serve` but **not** by `boatramp migrate` / `blob migrate` — the
offline ops that most need to resolve the real blob backend (this is exactly what the
construens v0.34.0 offline finalize tripped over, and what the v0.34.0 targeted stopgap
patched by hand in Loader B).

The fix: **one** resolution pipeline — `defaults → file → env → explicit flags` — built
once and consumed by **every** subcommand.

## Hard requirement: 100% parity (nothing dropped, renamed, or wrongly parsed)

Every input we honor today keeps working. In particular:

- **Current env var names stay verbatim.** figment's generic `Env` provider derives names
  from struct paths, which would *rename* our many irregular ones. We do **not** use
  figment's `Env` provider; we supply a custom overlay (below) that reproduces the exact
  names. A live deployment (construens) depends on these names.
- **Dynamic-keyed maps + lists** keep populating from env.
- **Secret-sourced inputs** stay exactly as they are (never routed through the config
  struct / figment).
- **Precedence** matches today: env overrides file; an explicit flag overrides env.

## Design: emit strings, extract lossy

The overlay (`config::figment_resolve::env_overlay_dict`) builds the env layer as a
`figment::value::Dict`, emitting **every scalar as a string**, lists as arrays, and the
(rare) `rename_all` enums as their lowercased token. Nothing is parsed in the overlay, so
it is infallible. Resolution uses **`Figment::extract_lossy`**, which coerces each string
to the target field's type:

- **bool** fields coerce via figment `Value::to_bool_lossy`, whose accepted spellings
  (`true/yes/1/on` + `false/no/0/off`, case-insensitive) are **exactly**
  `EnvSource::parse_bool`'s — so the bool-spelling parity (risk P4) holds for free.
- **numeric** fields coerce via `to_num_lossy`; a non-numeric value stays a string and
  then fails to deserialize **loudly at extract** — exactly as `apply_env_overrides`
  failed at override time, only deferred.
- **string / enum / path / socket-addr** fields read the string directly. Lossy coercion
  only fires when the *target* is bool/number, so a numeric-looking bucket/region/token in
  a string field is **not** mangled.

This choice means the overlay needs **no per-field type table** — only the small
`LIST_VARS` / `ENUM_VARS` sets (comma-split vs lowercase-token). Everything else is a
plain string.

### Faithful, drift-proof name mapping

The fixed-var overlay is **driven by the same `*_ENV_VARS` const tables** that
`apply_env_overrides` and the forgot-a-knob guard tests already use, deriving each config
path from the var name by the section's rule:

| Section | Env prefix | Config path | Rule (the P1/P2 renames) |
| --- | --- | --- | --- |
| compute | `BOATRAMP_COMPUTE_` | `compute.<field>` | lowercased suffix |
| security | `BOATRAMP_SECURITY_` | `security.profile` / `security.overrides.<field>` | `overrides` dropped from env |
| handlers sql | `BOATRAMP_HANDLERS_SQL_` | `handlers.bindings.sql.<field>` | `bindings` dropped from env |
| handlers jwks/concurrency/hedge | `BOATRAMP_HANDLERS_` | `handlers.<field>` | — |
| s3-ingress | `BOATRAMP_S3_INGRESS_CLOUD_` | `serve.s3_ingress_cloud.<field>` | `serve` dropped from env |
| secrets (+vault) | `BOATRAMP_SECRETS_` | `secrets.<field>` / `secrets.vault.<field>` | nested |
| cluster (+mesh) | `BOATRAMP_CLUSTER_` | `cluster.<field>` / `cluster.mesh.<field>` | nested |
| serve S3 scalars | `BOATRAMP_` | `serve.<field>` (`blobs`, `s3_bucket`, …) | `serve` dropped from env |

Because the overlay iterates the const tables, **a var that exists in a table is handled
by construction** — there is no third hand-maintained list to drift. The drift guard test
`overlay_honors_every_loader_b_fixed_var` asserts exactly that, and chains with the
existing field→var forgot-a-knob guards (field → const var → overlay entry).

### Dynamic maps (risk P0) and the rest

`blob_backends` / `handlers.bindings.sql.databases` / `serve.listeners` are keyed by names
not known ahead of time; the overlay reuses the existing env-scan helpers
(`EnvSource::{blob_backend_projects, sql_database_names, listener_names}`) and emits the
nested dict (including the reserved `DEFAULT` → `"default"` DB-key remap and the flattened
`s3_credential` public ref). Lists (risk P0#4: `kernel_signing_pubkeys`, `…allowed_hashes`,
`migrate_trusted_extensions`, `root_pubkeys`, `seeds`, per-listener `imports`) comma-split
to arrays. File-only structured fields (listener `tls`/`env`/`tenancy`,
`security.profiles`/`projects`, the whole `project.cfg` `DeployConfig` tree) remain
file-only — the env overlay never emits them; the **file layer must still carry them**.

## Precedence via figment merge (verified)

figment's `Value::coalesce` (figment 0.10.19 `src/coalesce.rs`) **deep-merges** two dicts
key-by-key, and a non-dict on either side is replaced wholesale. So:

- `defaults` (lowest) < `file` < `env` < `flags` (highest), each merged in order;
- a section the file set as a dict and env overrides field-by-field **deep-merges** →
  field-level env-over-file precedence (today's behavior) holds;
- a section absent in the file (null/omitted) is **replaced** by the env dict → env can
  materialize a section with no file, as today.

## The flag layer subsumes the `--blobs` probe (risk P3#14)

Today `--blobs` defaults to `fs` in clap, and the file `[serve].blobs` is honored only
when env is unset **and** the flag is still its default — reproduced by a bespoke
`std::env::var_os("BOATRAMP_BLOBS").is_some()` probe. In the figment model this is the
**general rule for the flag layer**: build it from `clap::ArgMatches` filtered to
`ValueSource::CommandLine` (and `EnvValue` goes through the env layer, not here), so a
*defaulted* `--blobs fs` never enters the flag layer and cannot clobber file/env. No
per-flag probe needed — the probe was a one-off of this rule.

## Risk taxonomy → handling

| Risk | What | Handling |
| --- | --- | --- |
| **P0** structural (maps/lists) | dynamic-keyed maps, comma-lists, file-only maps | custom overlay reuses the env-scan helpers; lists → arrays; file-only maps stay in the file layer |
| **P1** name-rename | `serve`/`bindings`/`overrides` dropped from env names | explicit section rules reproduce the names (never path-derive) |
| **P2** split-misnest | multi-`_` field names | explicit full paths (no per-`_` split) |
| **P3** collisions / silent-error | `BOATRAMP_CLUSTER_{INIT,JOIN,ADVERTISE_ADDR}` are Loader-A *actions* not `[cluster]` fields (#12); `BOATRAMP_COMPUTE_{RECONCILE_TICK_MS,NET_DEBUG}` are not `ComputeConfig` fields, and `ComputeConfig` is `deny_unknown_fields` (#13) | overlay is driven by explicit tables → the action flags + non-fields are simply **not** emitted into their section, so no collision and no deny-unknown error; the `--blobs` probe (#14) → the `CommandLine` flag-layer rule |
| **P4** parsing semantics | bool spellings; empty = unset; list trim/drop-empty | `to_bool_lossy` matches `parse_bool`; `EnvSource::get` treats empty as unset (overlay emits nothing); `parse_list` trims/drops |
| **P6** do-not-map | AWS ambient chain, `*_env`/`*_ENV` secret-indirection names, VAULT_TOKEN, `join_token` refs, sealed creds, KEK/root/bootstrap material | the overlay emits the *reference* fields (`token_env`, `password_env`, `s3_credential.secret_access_key` ref) exactly as today, and **never** invents a fixed env mapping for the secret VALUE; the ambient AWS chain + VAULT_TOKEN are resolved downstream, untouched |
| **P7** out-of-scope | client-CLI clap env, guest-shim injected env, cloudflare output env, test/mutation vars | not part of `ServerConfig`; the node overlay never touches them |

## Pre-reqs before the flip (flagged — not done in the scaffold)

1. **File layer without `Serialize`.** The config structs are `Deserialize`-only, so the
   parsed struct can't be fed to figment via `Serialized`, and `figment::value::Value`
   isn't plainly `Deserialize`-targetable (it carries a `Tag`). Two options:
   (a) derive `Serialize` on the config structs (cross-crate: node structs +
   `boatramp_core::security::*`), enabling `Serialized::defaults(parsed)` and a
   `config dump`; or (b) parse the RON/JSON text into `serde_json::Value` and convert to a
   figment `Value`. (a) is preferred (round-trippable config) but larger; decide before
   the flip.
2. **`deny_unknown_fields` structs that lack a struct-level `#[serde(default)]`.**
   `S3CredentialConfig`, `VaultSecretsConfig`, `BlobBackendConfig` (and verify
   `SecurityConfig`) cannot deserialize from a *partial* env sub-dict today — the current
   code builds the full struct then sets fields. Adding `#[serde(default)]` is the clean
   fix **but also loosens file parsing** (a file omitting a field would get the default
   instead of erroring) — a deliberate behavior decision, not a silent change. Each struct
   already derives `Default`, so it is safe where we want it.
3. **Validators on the merged result.** `apply_env_overrides` ends by running
   `validate_sql_db_names` / `validate_blob_backend_projects` / `validate_listeners` on the
   file+env result. The figment path must run these on the extracted config too (it is
   stricter — it also catches a listener/blob/db-name problem introduced purely by the file
   layer, which today is validated only at parse). Confirm this is the same accept/reject
   set, or flag the (safer) divergence.
4. **Loud vs silent cluster-without-listen.** `apply_env_overrides` silently drops an
   env-only `[cluster]` with no `listen`; the figment path fails **loudly** at extract
   (ClusterConfig has no `listen` default). This is arguably better; confirm it's
   acceptable.

## Rollout

1. ✅ Land the overlay + provider + parity tests behind `config-figment` (this commit).
2. Add the file layer + flag layer + the pre-reqs above; implement
   `load_with_figment(path, override, flags)` returning `ServerConfig` (map
   `figment::Error → ConfigError`).
3. Broaden the equivalence battery to the **whole** Loader-B surface + a file+env+flags
   matrix, asserting `load_with_figment == load` (compare `{:?}`), until green across the
   board.
4. Flip: route `ServerConfig::load` (and the offline ops) through `load_with_figment`
   under the feature; run the full CI matrix.
5. Delete Loaders A/B/C and make the feature the default (then drop the feature gate). The
   `*_ENV_VARS` const tables collapse into the overlay's single source of truth; the
   forgot-a-knob guards retarget onto it.

## Test oracle (this commit)

`crates/boatramp-node/src/config.rs`, module `config::figment_resolve::tests`:

- `overlay_honors_every_loader_b_fixed_var` — the drift guard (every Loader-B const var →
  an overlay entry).
- `compute_matches_apply_env_overrides` — full `extract_lossy` vs `apply_env_overrides`
  across str/int/list/enum/bool (ComputeConfig is `#[serde(default)]`).
- `bool_spellings_round_trip_like_parse_bool` — P4.
- `serve_s3_scalars_extract` — the construens finalize concern (enum/str/bool).
- `blob_backends_dynamic_map_shape` / `sql_db_default_token_maps_to_default_key` — P0 maps.
- `empty_value_is_unset` — P4.
