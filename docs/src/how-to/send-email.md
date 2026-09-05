# Send email from a function or handler

A function or handler often needs to send mail — a signup-verification link, a
password reset, a receipt. boatramp offers this as a first-class, **per-project**
capability: the guest imports `email` and calls `send`; boatramp holds the SMTP
credentials and delivers the message. The guest **never sees the credentials** and
can't reconfigure the relay — it only *uses* the service. boatramp is the SMTP
**gateway**, not a templating engine: the guest renders its own HTML/plaintext
(with whatever it likes — e.g. the `mrml` MJML crate) and hands boatramp a finished
message.

## Configure a profile

A **profile** is one named SMTP relay: host / port / security / AUTH plus the
default sender. Configure it with `boatramp email` — the password is sealed
**server-side** (the CLI never holds the KEK) and stored per project.

```sh
# STARTTLS submission relay (587), password from stdin (no shell-history trail):
printf '%s' "$SMTP_PASSWORD" \
  | boatramp email set default \
      --host smtp.example.com --security starttls \
      --username apikey --password-stdin \
      --from 'no-reply@example.com'

# a second, named profile (a guest picks it by name):
boatramp email set marketing --host smtp.example.com --security tls \
  --username apikey --password-stdin --from 'hello@example.com' < key.txt
```

`--security` is `starttls` (587), `tls` (implicit TLS, 465), or `plaintext` (a
trusted local relay only); `--port` overrides the conventional port. Omit
`--username`/`--password` for an unauthenticated relay. Add `--durable` to make
this profile's sends default to the durable spool (below).

List and inspect (redacted — **the password is never returned**), and remove:

```sh
boatramp email ls
```
```text
NAME                  HOST                          SECURITY    FROM                          DURABLE
default               smtp.example.com:587          starttls    no-reply@example.com          false
```
```sh
boatramp email show default    # host/port/security/from + whether a password is set
boatramp email rm  marketing
```

All of these are **project-scoped** via the global `--project` flag (default
`default`); managing profiles takes the same right as [secrets](./secrets.md)
(`Secrets·Write`) — a project admin, not a publisher.

## Use it from a guest

Grant the capability by importing `email`, then call `send` with a finished
message. The guest picks a profile by name (`none` ⇒ `default`) and supplies its
own `text` and/or `html`:

```wit
// the host interface your component imports
use boatramp:handlers/email-sender.{send};
use boatramp:handlers/email-types.{email-message};
```

```rust
// inside the guest, having rendered your own bodies
let msg = EmailMessage {
    profile: None,                       // → the project's "default" profile
    to: vec!["dest@example.org".into()],
    cc: vec![], bcc: vec![],
    from: None,                          // → the profile's configured sender
    reply_to: None,
    subject: "Confirm your email".into(),
    text: Some("Visit https://…/verify?t=abc to confirm.".into()),
    html: Some("<p>Visit <a href=\"https://…/verify?t=abc\">confirm</a>.</p>".into()),
    durable: None,                       // → the profile default
};
send(&msg)?;   // Ok = accepted for delivery (spooled), not yet delivered
```

At least one of `text`/`html` is required. A `from` you set must match the
profile's configured sender (a guest can't spoof an arbitrary `From`); omit it to
use the default. `send` returns as soon as the message is **accepted for delivery**
— delivery happens asynchronously off the request path, so a slow relay never
blocks your handler.

Declare the requirement in your function manifest's `requires` so a deploy is
refused on a host that doesn't offer `email`, rather than failing at first send.

## Best-effort vs durable delivery

- **Best-effort** (default): the message is queued in memory and delivered by a
  background task with a few retries. Zero persistence overhead; a node crash
  mid-flight loses the queued message.
- **Durable** (opt-in, per message via `durable: Some(true)`, or per profile via
  `--durable`): the message is persisted onto boatramp's messaging fabric and
  delivered by a worker with lease/retry/dead-letter — it **survives a restart**. A
  message still failing after the max attempts lands in the dead-letter queue,
  where you can inspect and redrive it with [`boatramp dlq`](./background-work.md).
  The durable path needs a messaging backend (always present on a normal node).

## Security posture

Guest email is governed by the `allow_guest_email`
[posture](./security-posture.md) knob: **off under `multi-tenant`** (an untrusted
tenant can't use the shared node's SMTP egress until the operator opts in), **on
under `single-tenant`/`dev`**. When it is off, a handler that imports `email` is
refused at deploy, and a granted `send` returns `access-denied`. The SMTP relay
host is additionally held to the SSRF rule — a relay resolving to a
private/loopback address is refused unless `allow_guest_private_egress` is on — so
a tenant profile can't aim the client at an internal service.

> **Requires a `[secrets]` envelope.** A profile's password is sealed at rest, so
> the `email` commands (and delivery) need a `[secrets]` envelope configured — see
> [Encrypt secrets at rest](./secrets-at-rest.md). Without one the API replies
> `501` with a clear message. In a cluster every node needs the same KEK to
> unwrap, exactly as for secrets and certificate keys.

## See also

- [Give handlers & functions secrets](./secrets.md) — the sealed store the email
  password reuses; the same `Secrets` right manages both.
- [Encrypt secrets at rest](./secrets-at-rest.md) — the envelope that seals the profile.
- [Choose & inspect a security posture](./security-posture.md) — the `allow_guest_email` knob.
- [Run consumers, crons, and streams](./background-work.md) — the fabric + `dlq` the durable spool rides.
