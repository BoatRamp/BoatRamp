# Quick Start

Publish a folder and serve it, end to end.

## 1. Run the server

```sh
boatramp serve          # filesystem backend, data in ./data, on 127.0.0.1:8080
```

By default this is plain HTTP with no authentication — fine for local use. For
anything exposed, set up [TLS](../guide/tls.md) and
[authentication](../guide/authentication.md).

## 2. Publish a site

From another terminal, publish a built folder as an immutable deployment and
flip the site to it atomically:

```sh
boatramp sync ./public --server http://127.0.0.1:8080 --site my-site
```

Re-running `sync` on an unchanged tree uploads nothing. Change one file and only
that new blob uploads, then the site flips atomically.

## 3. It's live

```sh
curl http://127.0.0.1:8080/sites/my-site/
```

The explicit `/sites/<name>/` route is always available for admin/testing. In
production you'll attach a domain so the site answers on its own hostname — see
[Domains](../guide/domains.md).

## 4. Inspect, roll back, reclaim

```sh
boatramp status --site my-site        # current deployment: id, age, size
boatramp deployments --site my-site   # history, newest first; * marks live
boatramp rollback --site my-site      # re-activate the previous deployment
boatramp prune --dry-run              # show reclaimable orphans + dead blobs
```

## 5. Save typing with a config file

Drop a `project.cfg` (RON) in your project folder so you don't repeat
`--server` / `--site`:

```ron
(
    publish: (
        server: "http://127.0.0.1:8080",
        site: "my-site",
    ),
    build: (
        command: "npm run build",
        output: "dist",
    ),
)
```

Now `boatramp build && boatramp sync dist` just works. See
[Configuration](../guide/configuration.md).
