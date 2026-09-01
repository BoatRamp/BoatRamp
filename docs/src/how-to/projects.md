# Organize sites into a project

A **project** is boatramp's owning + tenant boundary. It groups many sites together
with their functions and compute, and it is the tenant a managed handler's row-level
scope resolves to. Every resource belongs to exactly one project; a reserved
`default` project holds everything that predates projects, so if you never name a
project you keep the single-site experience unchanged.

Use projects when you run more than one site per operator (agencies, monorepos,
multi-tenant SaaS) and want each tenant's sites, functions, and compute isolated —
including their names. Two projects can each own a site called `blog`.

## Before you start

- A boatramp server and an admin token. See
  [Bootstrap authentication & mint tokens](./auth-bootstrap.md).
- On an existing (pre-0.2.0) store, migrate it first — see
  [Upgrade a store to project scoping](./migrate-to-projects.md).

## 1. Create a project

```bash
boatramp project create acme --display "Acme, Inc."
boatramp project ls
```

`create` needs a slug (unique, no `/`); `--display`, `--description`, and `--region`
are optional. `project ls` lists every project; `project show acme` prints the full
record; `project rm acme` deletes an **empty** project. It **refuses** while the project
still owns resources — and the refusal now enumerates exactly what remains, grouped by
resource family — so you know what to delete first. The `default` project can never be
removed.

To tear a project down wholesale, `project rm acme --force` **cascades**: it
deprovisions the project's managed databases, removes its compute workloads and their
volumes, deletes its functions and sites (releasing the sites' global domain claims),
clears its secrets and GraphQL safelist, then removes the project. Preview it first with
`--dry-run` (prints exactly what would be destroyed, changes nothing); a bare `--force`
shows that same plan and asks you to type the project name to confirm, so add `--yes` to
skip the prompt (required when stdin isn't a terminal):

```bash
boatramp project rm acme --dry-run     # what would be destroyed
boatramp project rm acme --force       # cascade, with a typed-name confirmation
boatramp project rm acme --force --yes # cascade, unattended
```

## 2. Target a project

Every site-scoped command takes a `--project` flag; it falls back to
`[publish].project` in `project.cfg`, then the `BOATRAMP_PROJECT` environment
variable, then the `default` project. So these are equivalent:

```bash
boatramp --project acme sync ./dist --site blog
BOATRAMP_PROJECT=acme boatramp sync ./dist --site blog
```

With `--project` omitted you are working in `default`, byte-identical to how boatramp
behaved before projects existed. A site name only has to be unique *within* its
project, so `acme/blog` and `beta/blog` are two different sites that deploy, serve,
and run their background work independently.

## 3. Declare a whole project at once

`boatramp apply` reconciles an entire project from one manifest — see
[Declare a project with `apply`](./apply.md). A minimal `apply.cfg`:

```ron
(
    project: "acme",
    sites: [
        ( name: "www",  path: "www/dist" ),
        ( name: "blog", path: "blog/dist", routing: ( clean_urls: true ) ),
    ],
)
```

```bash
boatramp apply -f apply.cfg
```

## What a project owns

- **Sites** — each with its own deployments, aliases, domains, and background work
  (consumers, crons). Same-named sites in different projects are fully isolated.
- **Functions** — top-level functions and their versions, triggers, invocations, and
  metering.
- **Compute** — container / micro-VM workloads.
- **A tenant identity** — a request routed to one of the project's sites carries the
  project as its host-asserted tenant, which is what a managed handler's
  `Authorized::db()` scopes rows to (nothing guest-supplied).

Content-addressed bodies (blobs, manifests, site and compute config) are shared
across projects and deduplicated — a byte-identical asset uploaded by two projects is
stored once, and it is only garbage-collected when *no* project references it.

## Authorization

Cedar gains a `Project` resource with three project-scoped roles —
`project_admin`, `project_publisher`, `project_viewer` — that govern a project's
sites, functions, compute, and workflows. A token scoped to one project cannot touch
another: a `project_admin:acme` token is refused (403) on project `beta`. Legacy
site-only grants (`publisher:blog`) read as `publisher:default/blog`, so existing
tokens keep working against the `default` project. See
[RBAC roles, actions & resources](../reference/rbac.md).

## See also

- [Declare a project with `apply`](./apply.md)
- [Upgrade a store to project scoping](./migrate-to-projects.md)
- [Core concepts & the deployment model](../explanation/concepts.md)
