# Export, import & clone a project

A project's state — its managed-database contents, its control-plane KV slice, and its
blobs — can be streamed off a running node as a single portable **BRPROJ bundle**, then
imported into a project on the same node or a different one. This is how you **clone** a
project into another environment (staging → prod, a per-customer copy) or recover one.

Both verbs run against a **running node** and are gated at **`System·Admin`** (the node
operator — a project admin, publisher, or deployer cannot reach them).

## Export a bundle

```console
$ boatramp project export acme --out acme.brproj --server https://cp.acme.com
```

| Flag | Default | Description |
| --- | --- | --- |
| `--out <file>` | — | Write the BRPROJ bundle to this file (required). |
| `--full` | data-only | Export a **full** bundle (schema + data). The default is **data-only**: application data only — no identity, RBAC, or routing. |
| `--include-identity` | off | Include the project KEK (passphrase-wrapped) for a **same-environment recovery**. Implies `--full` and needs a transport key (`--transport-key-file`, else `BOATRAMP_EXPORT_TRANSPORT_KEY`, else an interactive prompt). Local KEK envelopes only. |
| `--transport-key-file <FILE>` | — | File holding the transport passphrase that wraps the identity container. |

Server seam: `POST /api/project-export` (streams the bundle out).

## Import a bundle

Import is a **dry-run plan by default** — it mutates nothing until you pass `--apply`.

```console
$ boatramp project import acme-copy --in acme.brproj --server https://cp.acme.com   # plan only
$ boatramp project import acme-copy --in acme.brproj --apply --server https://cp.acme.com
```

| Flag | Default | Description |
| --- | --- | --- |
| `--in <file>` | — | The bundle file to import (required). |
| `--apply` | dry-run | Execute the import (default: a plan that mutates nothing). |
| `--force` | off | Overlay a **non-empty** control-plane KV destination (the commingle override; only meaningful for a full bundle). |
| `--allow-schema-skew` | off | Proceed despite a Postgres schema-ledger fingerprint mismatch between the bundle and the target. |
| `--identity <fresh\|adopt>` | `fresh` | `fresh` — the target mints its own identity and source-sealed secrets are dropped. `adopt` — install the bundle's KEK for a same-environment recovery (requires a transport key). |
| `--transport-key-file <FILE>` | — | File holding the transport passphrase (for `--identity adopt`). Falls back to `BOATRAMP_EXPORT_TRANSPORT_KEY`, then an interactive prompt. |

Server seam: `POST /api/project-import`.

## Clone a project

There is no single `clone` verb — a clone is an **export followed by an import** into a
new project name:

```console
$ boatramp project export acme --out acme.brproj --server https://cp.acme.com
$ boatramp project import acme-staging --in acme.brproj --apply --server https://cp.acme.com
```

Clone the **data only** (the default bundle) when copying application data into a fresh
project — the target keeps its own identity, RBAC, and routing. For a **same-environment
recovery** of the original project (identity intact), export with `--full
--include-identity` and import with `--identity adopt`.
