# Example project

A minimal boatramp **project folder** — the folder you publish.

```sh
cp project.cfg.example project.cfg     # adjust publish.server / publish.site
boatramp validate                      # check the routing config
boatramp sync                          # publish this folder
```

`project.cfg` (RON) carries everything about *this* project: where to publish
(`publish`), an optional `build`/`bundle` step, and the deploy-scoped `routing`
config (redirects, headers, handlers, …) that is folded into the immutable
deployment manifest. The server's own config lives elsewhere, in
[`boatramp.cfg`](../../boatramp.cfg.example).
