# DESIGN: decoupling the two TLS/ACME concepts

Status: implemented on `feat/acme-concept-decouple` (branched off `main`). TCB-adjacent (cert serving);
written for the Security review + the docs-drift pass.

## The two concepts (keep them SEPARATE in code, config, and docs)

**Concept 1 — control-plane cert verification mode.** How the NODE obtains + serves ITS OWN cert for the
`--acme-domain` control-plane domains (served at `:443`). Driven by `--tls <mode>` (`AcmeDns` = DNS-01).
Stored single-node on the filesystem (`./data/acme`), cluster in `KvCertStore` (`cert/<domain>`). The
cert is obtained (and renewed) by the serve loop's refresh pass (`cert_refresh.run` → `obtain_or_load`,
DNS-01) and served through the static SNI tier of the edge resolver (`acme_dns.rs`).

**Concept 2 — on-demand default ACME mode.** How `[serve.on_demand_tls]` issues certs ON-DEMAND for
OTHER domains (tenant catch-all / per-SNI). Its own in-memory `CertCache`, its own challenge
(`OnDemandChallenge`, default `TlsAlpn01`), its own abuse gate (the #02 verified-domain allowlist
`is_host_issuance_authorized`), rate limit, and cluster single-flight. It ISSUES; it is not how the node
gets its own cert.

## The bug

`use_node_cert` (a host-owned TCP listener serving the Concept-1 node cert, cap-req #29) was routed
through the Concept-2 on-demand engine. That engine (a) cannot see the Concept-1 cert, so it re-issued,
and (b) used the wrong challenge and was refused by the tenant-verification gate for a pure control-plane
domain (which is not a tenant attached+verified domain). A pure control-plane FQDN therefore could not be
served on a listener at all.

## FIX A — `use_node_cert` serves the node's control-plane cert directly (Concept 1)

The listener `CompositeResolver` is now three clearly-separated tiers (`acme_dns.rs`):

1. **managed_names tier (Concept 1).** For an SNI matching the listener's `server_names` allowlist (same
   case-insensitive + single-label-wildcard `sni_matches` semantics; the allowlist bounds serving — a
   name outside it is never served the node cert), resolve against the node's CONTROL-PLANE cert source
   and serve it. The on-demand engine is NEVER consulted for a managed name, so no tenant verify/attach
   gate and no issuance trigger apply — a pure control-plane FQDN serves. On a genuine miss (the node
   holds no control-plane cert for the name), fall back to the listener's own static `cert_file` if
   present, else fail the handshake closed. No on-demand (Concept-2) issuance is triggered for a managed
   name.
2. **catch_all_on_demand tier (Concept 2) — UNCHANGED.** For a non-managed SNI, a static (pre-known) cert
   wins; else, only when the listener set `on_demand`, fall through to the on-demand engine's
   project-scoped resolver (verified-domain + project gating intact). A `use_node_cert`-only listener (no
   `on_demand`) does NOT fall through for non-managed names.
3. **static tier.** The listener's own `cert_file`/`key_file`.

The `:443` edge keeps an empty managed tier + `catch_all_on_demand = true` (byte-for-byte its prior
behavior).

### The live/shared node-cert handle (renewal-safe)

`acme_dns::NodeCertSource` wraps `Arc<arc_swap::ArcSwap<SniCertResolver>>` — the same lock-free atomic
`Arc`-swap primitive `ReloadableTls` already uses. The serve path (`serve_acme_dns`) parses the obtained
`--acme-domain` set into ONE `Arc<SniCertResolver>` and:

- builds the `:443` edge config from that SAME resolver (`build_server_config{,s}_maybe_from_resolver`),
- wraps it in a `NodeCertSource` and threads a clone to `spawn_listeners` → the managed tier,
- on every renewal tick, re-parses the fresh set, `NodeCertSource::store`s it (reaching every listener on
  its next handshake), and reloads the edge from the SAME new resolver.

So the edge and the listeners read one source of truth, hot-swapped together — never a stale snapshot. If
the edge resolver had stayed a per-reload snapshot, a `use_node_cert` listener would have served an
expired cert after the first renewal; the shared live handle is what prevents that.

### Behavioral fix preserved

Once a managed name is served from the Concept-1 source, the on-demand `is_host_issuance_authorized`
tenant-verification gate (`deploy.rs`) no longer applies to it: a pure control-plane FQDN now SERVES. The
project-scope gate still applies to the Concept-2 catch-all tier (unchanged).

### Note on `use_node_cert` requiring the engine

The config still requires `[serve.on_demand_tls] enabled = true` for a `use_node_cert` listener, and the
no-engine / non-acme-dns branches still fail closed (kept per the task). The managed tier itself no longer
depends on the engine — it reads `node_certs` — but the requirement and the fail-closed branches are
unchanged by this work. Relaxing the requirement (so `use_node_cert` needs only `--tls acme-dns`, not the
on-demand engine) is a possible follow-up, flagged for the owner, not taken here.

## FIX B — a clean, SETTABLE on-demand challenge (Concept 2)

- **RON + JSON settable.** `OnDemandChallenge` now `(de)serializes as a String`
  (`#[serde(try_from = "String", into = "String")]`) via `FromStr`/`TryFrom<String>` accepting
  `tls-alpn-01` / `dns-01` (plus a few aliases) and `From<_> for String` emitting the kebab token. The
  kebab tokens contain hyphens — invalid RON identifiers — so the previous `rename_all = "kebab-case"`
  unit-variant encoding was unsettable from a RON config file. Now `challenge: "dns-01"` parses from RON
  and `"challenge": "dns-01"` from JSON, equivalently.
- **Env lever.** `[serve.on_demand_tls]` was file-only; an `ON_DEMAND_TLS` alias table maps every scalar
  (incl. `challenge`) to `BOATRAMP_ON_DEMAND_TLS_*` → `["serve","on_demand_tls",<field>]` (the `serve`
  segment dropped, like `alerts`/`s3_ingress_cloud`). A forgot-a-knob parity test asserts every field has
  a mapping.
- **Stale comment retired.** `from_serve_config` already receives the node's ACME DNS provider
  (`serve.rs`), so DNS-01 on-demand works once `challenge` is settable. The refusal branch (correct when a
  provider is genuinely absent) is kept; the comment now reflects reality.

## Tests

- `acme_dns.rs` offline: `use_node_cert` managed name served from the ACTUAL node control-plane source
  WITHOUT pre-seeding the on-demand cache (`use_node_cert_served_from_node_source_with_empty_on_demand_cache`,
  plus the rewritten `use_node_cert_serves_node_source_over_static_and_bounds_to_server_names` and
  `use_node_cert_wildcard_and_mixed_case_route_to_managed`, which seed `node_certs`, not the cache). The
  cross-project project-scope test is reframed onto the Concept-2 catch-all tier where that gate still
  lives (`on_demand_catch_all_listener_refuses_a_cross_project_sni`).
- `config.rs`: `config_json_gate_on_demand_tls_challenge_parses_from_ron_and_json` (RON + JSON + round-trip
  + unknown-token rejection); `serve_on_demand_tls_resolves_from_env`, `every_on_demand_tls_scalar_has_an_env_mapping`,
  `overlay_honors_every_on_demand_tls_var`.
- Pebble `#[ignore]` live gates (run on lighthouse / the mailroom DNS-01 gate — cannot run on darwin):
  `listener_use_node_cert_against_pebble` adjusted to serve a PURE control-plane domain that is NOT
  `attach_verified_domain`'d (obtains it via `obtain_or_load` DNS-01, serves from `node_certs`);
  `on_demand_dns01_from_config_against_pebble` proves `challenge = "dns-01"` SET FROM A RON CONFIG drives
  DNS-01 on-demand end to end.
