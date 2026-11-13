# Sync a project between environments

**For: operators**

`project sync` reconciles a **target** project toward a **source** for a **selected set
of pieces** — idempotent (run it twice, same result) and **coherence-preserving** (it
rewrites site configs as it goes, so the target is never left with a dangling pointer or a
broken serve). It is the successor to the one-shot [`project import --clone-from`](./clone-project.md#streaming-clone-pull-from-a-live-source-node)
for keeping a staging / preview / DR copy in step with production: where `--clone-from` is a
single full-or-data copy, `sync` lets you mirror *exactly* the pieces you choose and re-run it
to converge only what changed. (`import --clone-from` is still supported — reach for `sync`
when you want a repeatable, selective mirror.)

Like export/import/clone, `sync` runs against a **running node** and is gated at
**`Project·Admin`** on both the source and the target — never node-global `System·Admin`.

## The dry-run preflight is the default

`sync` **mutates nothing** until you pass `--apply -y`. By default it prints a **preflight
plan**: the destination precondition (exists → excluded pieces preserved; absent → will be
created + provisioned), each selected piece's disposition (carry / rewrite / re-derive /
drop / preserve), and each site/DB classified — including any **incoherent** item that would
be skipped — *before a byte moves*.

```console
$ boatramp project sync acme-staging --from acme --include-pg --include-blobs \
    --server https://cp.acme.com
sync preflight: `acme-staging` ← `acme`
  destination: exists — excluded pieces are preserved verbatim
  identity: fresh | strict: off
pieces:
  [carry    ] pg         managed-DB contents (delta)
  [carry    ] blobs      content-addressed store (integrity/delta)
  [re-derive] routing/tls global routing + TLS re-issued under the target's own identity
items:
  ...
(dry-run preflight — nothing moved; re-run with `--apply -y` to execute this plan)
```

### The preflight classifies each carried DB's restore feasibility

When the selection carries managed-DB contents (`--include-pg`, or a carve that keeps `pg`), the
preflight also classifies **whether each carried database can actually be restored** — so an
unrestorable selection fails in the **plan** (in seconds) rather than part-way through an apply:

- a **managed Postgres** binding — **either tenancy** — carries: it lands via provision + the
  non-superuser atomic **shadow+swap** (a dedicated/single server via the chunked shadow, a
  Shared-tenant server via the sidecar shadow+swap);
- a **managed MySQL** binding — **either tenancy** — carries too: a dedicated/single server via the
  chunked shadow, a Shared-tenant server via the sidecar shadow+swap (mirroring Postgres);
- an **external / bring-your-own-URL** binding is **skipped with a reason** — its data lives on
  *your* server, so boatramp cannot shadow+swap it; replicate it out of band.

A skipped (infeasible) database shows in the plan with its reason and counts toward the **skipped
count** `--strict` refuses on, and a site that binds a skipped database is itself reported
incoherent (its binding would dangle) — all before a byte moves.

A managed **MySQL** database carries its **triggers, stored routines (procedures + functions),
scheduled events, and views** along with its tables, restored safely as a non-privileged user: each
object's `DEFINER` is re-pointed to the destination tenant's own database-scoped role (so a carried
object runs with that tenant's own grants — never a server superuser or another tenant). An object
that would require a privilege the tenant role lacks fails the import fail-closed rather than
escalating. (On a binary-logging managed server this carry needs `log_bin_trust_function_creators=ON`
for the non-superuser `CREATE TRIGGER`/`CREATE FUNCTION`; boatramp's managed-MySQL spec sets it on
automatically — benign under row-format binlog — so a server launched before this release must
relaunch to adopt it.)

> **Why sync can land a managed DB when a plain `--clone-data-only` import cannot.** A data-plane
> clone used to drive the managed-DB restore through the schema-less `--data-only` *overlay*, which
> the import categorically **refuses** for a managed binding (overlaying an untrusted dump onto a
> live schema would run as the bootstrap superuser — an RCE risk). `project sync` instead requests
> a **full dump restored via the non-superuser shadow+swap** — the same safe path a `--force` full
> clone uses — so a managed DB's data lands **without** dragging in the control-plane KV slice. See
> [Managed-database restore is atomic](./clone-project.md#managed-database-restore-is-atomic).

## Choose what to sync

A sync needs an **explicit selection** (naming neither an include nor an exclude is an error —
the conservative default).

- **Allowlist** — any `--include-<piece>` makes the selection *exactly* the named pieces.
  `--include-pg --include-blobs` syncs only managed-DB contents + blobs; everything else is
  left as the target's own.
- **Carve** — using only `--exclude-<piece>` flags starts from the full set and removes the
  named pieces. `--exclude-domains --exclude-secrets` mirrors everything except the domain
  layer and secrets.

The selectable pieces:

| Piece | `--include-`/`--exclude-` | On sync |
| --- | --- | --- |
| managed-DB contents | `pg` | carried (delta) |
| content-addressed blobs | `blobs` | carried (integrity/delta) |
| site configs | `sites` | carried; the `domains` field is **rewritten** (see below) |
| domain layer (domains field + verification/alias records) | `domains` | carried if included, else the target's are preserved |
| imperative project settings | `settings` | carried |
| declarative managed-database bindings | `databases` | carried |
| GraphQL registry + APQ safelist | `graphql` | carried |
| runtime deploy history / current pointers | `history` | carried |
| KEK-sealed secrets | `secrets` | dropped under `--identity fresh`; the target re-provisions its own |

**Excluded pieces are preserved verbatim.** `sync` never reads, writes, or prunes an excluded
piece on the target. This is what makes the staging pattern safe: `--exclude-domains` carries
**zero** source domains, so a staging project cannot accidentally inherit production's live
hostnames.

**Included `sites` with excluded `domains` is a rewrite, not a verbatim copy.** A site's
domains live *inside* its `SiteConfig` body. `--include-sites --exclude-domains` mirrors
everything in each site config **except** the domains field, which it **preserves from the
target** — so the target keeps serving its own hostnames and its domain-ownership proofs are
never touched (no re-authorization on a resync).

### Drop a single item

To drop one specific site or database rather than the whole piece, use the per-item escape
hatches (repeatable):

```console
$ boatramp project sync acme-staging --from acme --include-sites \
    --exclude-site internal-admin --exclude-db scratch --server https://cp.acme.com
```

## Apply it

`--apply` executes the plan and **requires `-y`** (there is no interactive prompt):

```console
$ boatramp project sync acme-staging --from acme --include-pg --include-blobs \
    --apply -y --server https://cp.acme.com
```

Re-run any time — only what changed moves, and any item that was skipped as incoherent
converges once you fix its dependency (the skip set shrinks over runs).

## Sync across nodes

The source can be another node: pass `--from <https-URL>` (it reuses the `--clone-from`
transport; plain-HTTP / private targets are SSRF-refused). The source project defaults to the
target's name; override it with `--from-project`. A cross-node **`--apply`** needs the
**source node's** `Project·Admin` token — via `--clone-source-token-file <path>` or
`BOATRAMP_CLONE_SOURCE_TOKEN` (sent in a header over TLS, never on argv).

Worked example — clone production app data into a fresh/absent A/B environment on a separate
machine, keeping the target's own front door and identity:

```console
$ boatramp project sync construens-preview-a \
    --from https://construens-web.fly.dev --from-project construens-preview \
    --include-pg --include-blobs \
    --clone-source-token-file ./src-admin.token \
    --apply -y --server https://construens-preview-a.fly.dev
```

An absent target is **created and provisioned** (the project + its managed DB) — no
pre-create, no `--force`, no prune. `construens-preview-a` keeps its own domains, its own
sealed secrets / KEK (`--identity fresh`), and brings its control plane via its own
`apply`; only pg + blobs mirror.

## Domain safety (cross-node cutover)

Carrying `--include-domains` from a **cross-node** (URL) source is **refused** on `--apply`
unless you also pass **`--allow-domain-cutover`**. The target's host-uniqueness guard is
same-node only and cannot see whether the remote source still *live-owns* the host, so a blind
carry risks a **second simultaneously-live owner** of the same hostname. Pass
`--allow-domain-cutover` only once the source has yielded the host — a DR failover or a
deliberate blue-green cutover.

## Identity

`--identity fresh` (the default, and the only mode this release) keeps the target's own KEK
and **drops** source-sealed secrets — the target re-provisions its own. (`adopt`, for
same-environment recovery, is a follow-up; for now use
[`project import --identity adopt`](./clone-project.md#import-a-bundle).)

## All-or-nothing

By default `sync` converges every coherent item and *reports* the incoherent ones (a non-zero
skipped count CI can gate on). Pass **`--strict`** to flip skip → refuse-the-whole-run for
automation that wants all-or-nothing.

## Self-heal a prior-failed managed-DB sync

If a previous `project sync --apply` into a Shared-Postgres tenant failed partway, it can leave a
role "tangle" — the tenant's derived roles still owning a stray orphan database, grace tombstones,
and non-DB objects. A subsequent `--apply` now **self-heals** that tangle with zero operator
intervention (no `db drop --orphan`, no manual SQL): it reconciles the derived roles, clears the
orphan data-loss-safely, and reprovisions the tenant fresh so the restore lands clean. A healthy
re-sync is unaffected — the heal fires only on a detected tangle.

By default the heal **preserves** any `__deleted_` grace tombstone: it reassigns the tombstone to
the stable superuser so its grace-recoverable data survives while the derived roles drop cleanly,
and the tombstone is reclaimed on the normal grace schedule (`deprovision_grace_secs`, floored to
the 7-day default for a crash-recovery tombstone so a failed restore stays recoverable). Pass
**`--drop-soft-deleted`** to instead **destroy** those tombstones — a deliberate data-loss opt-in
that has no effect on a healthy sync.

## Known limitations

- **`pg` and `blobs` travel together.** The data-only transport carries managed-DB contents
  and blobs as one unit, so a `pg`-only or `blobs`-only selection is **refused** (it would
  carry the excluded half) — include or exclude **both**.
- **`settings`, `graphql`, and `history` carry over the CLI (since v0.58.0).** The node-side
  selective-sync KV endpoint (`GET`/`POST /api/project-kv-stratum`) lands each slice
  record-by-record, reporting any entries it skips; a dry-run shows them as "carried". (By
  contrast `pg`/`blobs` travel as the single data unit above, and `secrets` re-provision on the
  target — those three are not individually CLI-carryable.)
- **A cross-node managed-DB sync needs v0.59.1+ at both ends.** The `managed_restore` wire field
  that selects the safe shadow+swap restore is **silently ignored by a pre-0.59.1 node**, which
  falls back to the old coupling and refuses the managed member as before. The degradation is
  graceful (never a silent wrong restore), but a managed DB's data only lands when **both** the
  source and target run v0.59.1 or newer — relevant only while a fleet straddles the upgrade.

## See also

- [Export, import & clone a project](./clone-project.md) — the one-shot bundle/stream clone
  (`import --clone-from`) and the transport `sync` reuses.
- [Declare a project with `apply`](./apply.md) — how a target brings its own declarative
  control plane (routing / site config / GraphQL).
- [CLI reference: `boatramp project sync`](../reference/cli-reference.md#boatramp-project-sync) —
  every flag and default.
- [RBAC reference](./../reference/rbac.md) — the `Project·Admin` gate.
