# Config resolution rewrite: one `figment` pipeline for every subcommand

> **Shipped in v0.35.0** — history, not a plan. figment is now the ONLY config path: the
> layered pipeline (defaults/base-seed → **file** → **env** → explicit **CLI flags**) is
> unconditional in `ServerConfig::load`, and the three hand-rolled loaders it replaced
> (serve clap `#[arg(env)]`, `apply_env_overrides`, the ad-hoc `serve.kv.*` env reads) are
> deleted. There is **no `config-figment` feature flag** — it was removed at the cutover.
> User-facing contract: [docs/src/explanation/config-model.md](src/explanation/config-model.md).
> This file is the design/rationale record (why it is shaped this way).

It covers the COMPLETE surface (former Loaders A/B/C): the `serve.*` scalars, the `serve.kv.*`
knobs, the `[security]`/`[compute]`/`[handlers]`/`[secrets]`/`[cluster]` sections, and the three
dynamic-keyed maps. `boatramp config dump` (the Serialize dividend) prints the resolved config
with secrets redacted. The four design decisions below were resolved by the owner; this doc
records the as-built design. (Equivalence with the old loaders was proven by a full-surface
parity battery that was green at the cutover; it has since been replaced by direct
per-section tests, as the old `apply_env_overrides` oracle was deleted with the loaders.)

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
v0.34.0 offline finalize tripped over, and what the v0.34.0 targeted stopgap patched
by hand in Loader B).

The fix: **one** resolution pipeline — `defaults → file → env → explicit flags` — built
once and consumed by **every** subcommand.

## Hard requirement: 100% parity (nothing dropped, renamed, or wrongly parsed)

Every input we honor today keeps working. In particular:

- **Current env var names stay verbatim.** figment's generic `Env` provider derives names
  from struct paths, which would *rename* our many irregular ones. We do **not** use
  figment's `Env` provider; we supply a custom overlay (below) that reproduces the exact
  names. A live deployment depends on these names.
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

## The four decisions, as built

1. **File layer → derived `Serialize`.** `#[derive(Serialize)]` is on the whole `ServerConfig`
   tree (24 node types + `BlobBackend` + `boatramp_core::security::{SecurityConfig,
   ProjectPostureOverride}`). The parsed file serializes straight into a figment layer via
   figment's own serializer (`to_dict`); absent `Option` sections serialize to `Empty` and are
   `prune_empty`-d so they never clobber a lower layer. Also unlocks `config dump`.
2. **Strict file parsing kept** for the `deny_unknown_fields` sub-structs — NO struct-level
   `#[serde(default)]` added. Only two (`VaultSecretsConfig`, `S3CredentialConfig`) have a
   required field; a **base-seed layer below the file** emits their COMPLETE defaults when env
   references them, so a partial env sub-dict never reaches extract — and the file's own fields
   still win (seed < file < env). The file keeps erroring on a missing required field as today.
3. **Validators run on the full merged result** (`validate_sql_db_names` /
   `_blob_backend_projects` / `_listeners`) — stricter than `apply_env_overrides` (also validates
   a file-introduced entry). Intended.
4. **`[cluster]` without `listen` fails LOUDLY** at extract (no `ClusterConfig` `listen`
   default) — not the old silent drop. Intended.

## config dump (the Serialize dividend)

`boatramp config dump [--file boatramp.cfg] [--explain]` resolves the static daemon config
through the pipeline and prints it as JSON with the secret-bearing fields **redacted**
(`auth_root_private_key`, `bootstrap_secret`, `azure_access_key`, `secret_access_key`; secret
*reference* / env-var-NAME fields like `token_env`/`url_env` are left intact). This is necessary
*because* decision 1 made the config `Serialize` — a raw dump would otherwise expose the
control-plane root key. (Client-side, no server; distinct from `config get/set`, the live
dynamic config.)

## Flag layer (as built)

serve parses via `ArgMatches` (`get_matches` + `from_arg_matches`), and `serve_cli_flags` builds
a `{BOATRAMP_<NAME>: raw-value}` map of the args whose `ValueSource == CommandLine` (env name from
each arg's own clap definition). `ServerConfig::load_with_flags` turns that into the TOP figment
layer by **reusing the env overlay** (a flag's name→path mapping equals its env var's). A
defaulted `--blobs fs` is `DefaultValue`, so it's absent — subsuming the old `var_os` probe. serve
still composes `args` over the resolved config; since the flag layer and clap's `args` carry the
same explicit flags, they agree, so the eventual flip (serve consuming only the resolved config)
is correct.

## Cutover (done in v0.35.0)

The owner chose the full cutover over an opt-in flag: figment is the ONLY config path. At the
cut the `config-figment` feature was removed from both crates, `ServerConfig::load` was made
unconditionally figment, and the three legacy loaders were deleted in one change — Loader B
(`apply_env_overrides`, ~664 lines) + its parse helpers, the serve-side Loader-A runtime
duplication (`args.X.or(serve_cfg.X)` combos + the `--blobs` `var_os` probe), and the Loader-C
ad-hoc `serve.kv.*` env reads. serve now consumes only the resolved `ServerConfig` (clap still
PARSES flags — they feed the flag layer + the non-config runtime selectors `--tls`/`--kv`/…).
The `*_ENV_VARS` const tables + `*_FIELD_SUFFIXES` + env-scan helpers stayed — they are the
overlay's single source of truth. A `#[cfg(test)]` adapter routes the pre-figment `env_wires_*`
tests through the pipeline so they remain genuine (non-oracle) figment tests.

## Test oracle

`crates/boatramp-node/src/config.rs`, module `config::figment_resolve::tests` (24 tests):

- `overlay_honors_every_loader_b_fixed_var` / `overlay_honors_every_serve_var` — drift guards
  (every registered env var → an overlay entry).
- `parity_*` (compute / security / handlers-sql / jwks-concurrency-hedge / s3-ingress / secrets
  (+vault, +partial-env) / cluster (+mesh) / sql-databases / blob-backends / listeners / combined)
  — `load_with_figment` == `apply_env_overrides`, pretty-Debug-equal, across the whole Loader-B
  surface + all three maps.
- `serve_scalars_full_extract` / `serve_kv_knobs_full_extract` — Loader A/C fields resolve into
  their ServeConfig path (asserted directly; clap-env can't be driven via `EnvSource::Map`).
- `flag_env_file_precedence` — flag > env > file through the full pipeline.
- `dump_redacts_secrets` — no secret value appears in a dump.
- `bool_spellings_round_trip_like_parse_bool`, `empty_value_is_unset` — P4.

End-to-end (real feature binary): `config dump` with a file + env shows env-over-file, a serve
scalar coerced string→number, the file's `auth_root_private_key` as `<redacted>`, and file-only
values; `serve --help` intact.
- `empty_value_is_unset` — P4.
