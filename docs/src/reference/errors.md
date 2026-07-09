# Errors & exit codes

## Exit codes

The `boatramp` CLI uses the two standard shell exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Any error. |

On failure the CLI prints the error and its cause chain to stderr, then exits
`1`:

```text
error: failed to publish site "blog"
  caused by: server returned 403 Forbidden
  caused by: token lacks required right site:blog · deploy
```

The top line is the command-level error; each `caused by:` is one link deeper in
the underlying cause, so the root cause is the last line. Scripts should branch on
the exit code (`0` vs non-zero) rather than parse the message text.

(The one place a different code appears is the internal container/VMM sandbox
worker, which propagates the *guest's* exit status — not a surface a user
invokes.)

## API status codes

When the CLI talks to a server, an HTTP error is surfaced in the cause chain
above. The control-plane API uses conventional statuses:

| Status | Meaning | Common cause |
| --- | --- | --- |
| `400` | Bad request | Malformed body, or an invalid [authz policy](./rbac.md#the-policy-document). |
| `401` | Unauthenticated | Missing, malformed, expired, or revoked token. |
| `403` | Forbidden | Valid token without the [required right](./rbac.md#request-to-right-mapping). |
| `404` | Not found | Unknown site, deployment, or alias. |
| `409` | Conflict | State precondition failed (e.g. activating a nonexistent deployment). |
| `413` | Payload too large | Upload exceeds `BOATRAMP_MAX_UPLOAD_BYTES`. |
| `429` | Too many requests | Rate limit or upload-concurrency cap reached. |
| `503` | Unavailable | Upload slots exhausted, or the node is not ready. |

A non-2xx response carries a JSON `{ "error": "..." }` body, which becomes the
deepest `caused by:` line.

## Validation errors

`boatramp validate` (and `sync`, which validates first) reports config problems
against `project.cfg` before anything is published — a bad route pattern, an
unknown handler import, an unparsable cron schedule, or a credential-shaped value
in a handler `env`. These fail at deploy time, not request time:

```text
error: project.cfg: handler /api env var "TOKEN" looks like a secret; move it to
  [handlers].secrets as a reference to a host env var
```

See the [routing schema](./routing.md) for the fields these checks cover.
