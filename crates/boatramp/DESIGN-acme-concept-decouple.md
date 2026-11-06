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

### `use_node_cert` no longer requires the on-demand engine (CHANGE 1)

A `use_node_cert` listener serves the Concept-1 control-plane source DIRECTLY (from `node_certs`); it
never routes through the Concept-2 on-demand engine. So it needs only a `NodeCertSource` — i.e. the node
serving `--tls acme-dns` — NOT `[serve.on_demand_tls] enabled`. `validate_listeners` no longer requires
the engine (the `--tls acme-dns` precondition is a serve-time CLI choice the config file can't see, so it
is enforced fail-closed at serve time). In `serve.rs`, when a `use_node_cert` listener finds no on-demand
engine but the node HAS a control-plane source, it builds the composite from `node_certs` with a DEAD
on-demand resolver + `catch_all_on_demand = false` (the Security-cleared relaxation: a `use_node_cert`-only
listener's catch-all stays OFF, so a non-managed SNI still fails closed). It fails closed only when there
is no control-plane source at all (not `--tls acme-dns`). The non-acme-dns build still fails closed.

## FIX C — per-control-plane-domain challenge (Concept 1, CHANGE 2)

Each `--acme-domain` control-plane domain can be obtained via a DIFFERENT challenge (DNS-01 or
TLS-ALPN-01) — e.g. one domain DNS-01, another TLS-ALPN-01. This is Concept 1 (how the NODE gets its OWN
cert); it is DISTINCT from `[serve.on_demand_tls].challenge` (Concept 2), which is untouched.

- **Config (`[serve.control_plane_tls]`).** A LIST of `{ domain, challenge }` entries, mirroring the
  cap-req #27 `[serve.dns_providers]` per-zone LIST idiom (a `Vec<ControlPlaneDomainTls>`), chosen over a
  bare `{domain → challenge}` map so it is extensible (future per-domain knobs) without a breaking change.
  The flat `--acme-domain`/`BOATRAMP_ACME_DOMAINS` list + `--tls <mode>` stay the DEFAULT; a domain with no
  entry uses the `--tls` default (`acme-dns` ⇒ DNS-01), so an existing flat config is byte-for-byte
  unchanged. File-only (like `dns_providers`). The challenge is a NEW `ControlPlaneChallenge` enum
  (`dns-01` / `tls-alpn-01`), a DISTINCT type from `OnDemandChallenge` so the two concepts stay separate in
  code (the shared *mechanism* — the `CertCache` challenge slot + `TlsAlpn01Solver` — is reused, not the
  config type). **Validation:** the enum's `FromStr` rejects an unsupported method at parse; a TLS-ALPN-01
  override on a WILDCARD domain is refused at config load (only DNS-01 can satisfy a wildcard), as is a
  blank domain.
- **Obtention routing.** `ControlPlaneTls::solver_for(domain)` picks the `ChallengeSolver` per domain
  (override-or-default; a wildcard is ALWAYS DNS-01). `acme_dns::obtain_or_load_with` takes that solver:
  DNS-01 uses the existing convenience (+ the authoritative propagation pre-check + the cap-req #27
  `RoutingDnsProvider`); TLS-ALPN-01 REUSES the on-demand engine's `TlsAlpn01Solver` over a shared
  `CertCache`, against a throwaway account (the DNS-01 convenience's per-call account model — a handful of
  control-plane domains every ~60 days, well under the CA `newAccount` limit). `obtain_or_load` stays as
  the DNS-01 convenience over it. The whole refresh path (`CertRefresh::run` → `obtain_all` /
  `cluster_refresh_certs`) threads the per-domain solver.
- **Edge wiring (how the CA's TLS-ALPN-01 handshake to `:443` is answered).** The acme-dns `:443` edge
  served DNS-01 only, with NO ALPN-challenge slot. CHANGE 2 adds a TIER-0 `node_challenge:
  Option<Arc<CertCache>>` to the edge `CompositeResolver`: on an `acme-tls/1` handshake it serves the
  challenge cert the control-plane solver installed — checked BEFORE the static tier, so a RENEWAL
  validation handshake is answered with the challenge cert even though the domain's REAL cert is already
  in the static tier (serving the real cert would fail validation). The edge config additionally
  advertises `acme-tls/1` in its ALPN (so the CA's validation ALPN negotiates) — ONLY when a control-plane
  TLS-ALPN-01 tier is wired, so the common DNS-01 / on-demand edge is unchanged. Listeners never carry this
  tier (the CA validates against the node's own `:443`, not a listener). The challenge machinery is the
  SAME `CertCache` slot + `TlsAlpn01Solver` the Concept-2 engine uses — reused, not duplicated; the
  control-plane gets its OWN dedicated `CertCache` so it works with the on-demand engine disabled.
- **Init ordering (deferred TLS-ALPN-01 pass).** A TLS-ALPN-01 control-plane domain cannot be obtained
  before `:443` is up (the CA validates by connecting to it), but DNS-01 domains are obtained before
  serving starts (unchanged — no serving gap for the common path). So the initial pass obtains only the
  DNS-01 domains; a single background task waits for the edge to accept (bounded poll-connect), then runs
  the FULL refresh once (DNS-01 from cache, TLS-ALPN-01 obtained against the now-live edge) and swaps, then
  continues as the 6h renewal loop. The deferred pass + renewal share ONE `refresh_and_reload_edge` helper.
  An empty static set is not fatal while a TLS-ALPN-01 domain is pending (it fills in once the edge is up).

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

### CHANGE 1 tests

- `config.rs`: the p–u listener cases updated — `use_node_cert` WITHOUT `[serve.on_demand_tls]` now parses
  (case q flipped), `server_names` is still required independently (case r).
- `acme_dns.rs`: `use_node_cert_no_engine_serves_with_source_and_fails_closed_without` — a `use_node_cert`
  listener serves the node control-plane cert with the on-demand engine DISABLED (the production `dead()`
  resolver + `catch_all = false`), and fails closed when there is no `node_certs` source (not `--tls
  acme-dns`).

### CHANGE 2 tests

- `config.rs`: `control_plane_tls_config_parses_from_ron_and_json` (RON + JSON parse of the per-domain
  override list + the string round-trip + unknown-token rejection); `control_plane_tls_wildcard_tls_alpn01_refused`
  (a wildcard + TLS-ALPN-01 refused, a blank domain refused, the valid shapes parse).
- `acme_dns.rs`: `edge_serves_control_plane_tls_alpn01_challenge` — the `:443` edge serves the control-plane
  TLS-ALPN-01 challenge cert on the `acme-tls/1` handshake BEFORE the real static cert (the renewal-safe
  TIER-0 ordering), advertises `acme-tls/1`, and serves the real cert on a normal handshake.
- `on_demand_tls.rs`: `control_plane_dual_challenge_against_pebble` — `#[ignore]` Pebble live gate obtaining
  TWO control-plane domains via DIFFERENT challenges (one DNS-01 via challtestsrv, one TLS-ALPN-01 validated
  on a locally-bound `:443` edge serving the `node_challenge` tier). Cannot run on darwin — lighthouse only.

### CHANGE 3 (Security INFO fixes)

- `acme_dns.rs` `sni_matches`: the wildcard branch's suffix compare is now case-INSENSITIVE (matching the
  exact branch), with a mixed-case-wildcard test. Hardening only (still fail-closed; never over-serves).
- Comment fixes: `serve.rs` (`node_certs` is passed-but-inert for an on-demand-only listener), `config.rs`
  `validate_listeners` (the decouple — folded into CHANGE 1).
