# Author configs in RON or JSON

boatramp's config files — the `apply` manifest, `boatramp.cfg`, a site's
`project.cfg` — are written in **RON** (Rusty Object Notation). RON is the native,
primary format: it maps directly onto boatramp's typed Rust schema, supports
comments, and (via the `IMPLICIT_SOME` extension boatramp enables) lets you write
an optional field's value directly instead of wrapping it in `Some(…)`.

As of **v0.6.5**, boatramp *also* accepts **JSON** for the same files — the same
typed schema, just a different surface syntax — so you can generate configs from a
tool that emits JSON (Nickel, Jsonnet, CUE, a script) without a RON code path.

## RON — the native format

RON is what the examples throughout these guides use, and what
[`boatramp config migrate`](../reference/cli.md#boatramp-config) emits. Its
ergonomics matter for hand-authored config:

```ron
(
    project: "acme",
    // Comments are allowed — RON is meant to be read and edited by hand.
    sites: [
        ( name: "www", path: "www/dist", routing: ( clean_urls: true ) ),
    ],
    // IMPLICIT_SOME: write the value directly, no `Some(…)` wrapper.
    functions: [
        ( name: "resize", component: "resize.wasm", runtime: "wasm" ),
    ],
)
```

Prefer RON for anything you edit by hand.

## JSON — for interop and generated configs

JSON deserializes into the **exact same typed schema** as RON. The parser is
selected by file extension — a `.json` file is read as JSON, anything else as RON
— or forced with `--format`:

```console
$ boatramp apply -f apply.json                 # auto-detected: JSON
$ boatramp apply -f manifest.txt --format json # forced JSON regardless of extension
$ boatramp serve -c boatramp.cfg --format ron  # forced RON
```

`--format ron|json` is available on the commands that read a config file
(`apply`, `serve`). Because JSON hits the same typed schema and the same
validators, **everything behaves identically** once parsed:

- **Externally-tagged enums keep their variant names.** A RON `kind: postgres`
  is `"kind": "postgres"` in JSON; a newtype variant like `root: image("…")`
  is `"root": { "image": "…" }`.
- **`deny_unknown_fields` still applies.** A typo'd or misplaced field is
  rejected in JSON exactly as in RON — JSON does not loosen the schema.
- **All semantic validation runs identically** — routing compile-checks, the
  managed-database security contract, resource-name screening, and so on.

### JSON example

The same manifest as the RON above, in JSON:

```json
{
  "project": "acme",
  "sites": [
    { "name": "www", "path": "www/dist", "routing": { "clean_urls": true } }
  ],
  "functions": [
    { "name": "resize", "component": "resize.wasm", "runtime": "wasm" }
  ]
}
```

### JSON is current-schema only

There is **no legacy JSON** — JSON support arrived after config versioning, so
JSON is always parsed against the **current** typed schema. A `version:` field
declaring an **older** schema in a JSON file is an **error**: the loose-parse →
migrate pipeline is a RON-only concern.

If you have an old, versioned RON manifest, upgrade the **RON** source first with
[`boatramp config migrate`](../reference/cli.md#boatramp-config), then (if you
want JSON) regenerate the JSON from the current-schema source. Don't hand-write a
`version:` into JSON expecting a migration — regenerate current-schema JSON
instead.

## Headline use case: generate configs from Nickel

The reason JSON exists as an input: you can author your config in a typed
configuration language and export it to JSON for boatramp to consume. With
[Nickel](https://nickel-lang.org):

```console
$ nickel export --format json manifest.ncl > apply.json
$ boatramp apply -f apply.json
```

Your Nickel source can carry contracts, functions, and shared imports; the
exported JSON is a plain, current-schema manifest that boatramp validates like
any other. The same pattern works with Jsonnet, CUE, or a plain script — anything
that emits current-schema JSON.

Because the parse is auto-detected by the `.json` extension, `boatramp apply -f
apply.json` needs no extra flag; reach for `--format json` only when your
generated file has a non-`.json` name.

## See also

- [`--format` on `apply` / `serve`](../reference/cli.md#boatramp-apply)
- [Declare a project with `apply`](./apply.md)
- [`boatramp config migrate`](../reference/cli.md#boatramp-config)
- [The configuration model](../explanation/config-model.md)
