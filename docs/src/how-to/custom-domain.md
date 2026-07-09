# Attach a custom domain

To serve a site on a hostname of your own — `app.example.com` — you attach that
host to the site, and it answers at that host's root. boatramp routes a host only
after you prove you control it, so attaching is a two-step task: start
verification, then verify. For every way a request is matched to a site, see
[How a request reaches your site](../explanation/addressing.md).

## Before you start

- A published site to attach the host to.
- Control of the host: either the ability to serve a file on it (HTTP), or
  access to its DNS zone (DNS TXT).
- For the DNS-TXT method, a server built with the `domain-verify-dns` feature.

## 1. Start verification

Pick the method that matches the access you have, and run `domain add`. It
records the host as pending and prints the challenge to publish:

```sh
boatramp domain add app.example.com --method http
```

```text
domain app.example.com — pending (http)
publish token 7f3c9a2e… at:
  /.well-known/boatramp-domain-verification/7f3c9a2e…
then run: boatramp domain verify app.example.com
```

- **HTTP token** proves you control what the host serves *right now*. Serve the
  printed token under `/.well-known/boatramp-domain-verification/<token>` on the
  host. Works in every build.
- **DNS TXT** proves you control the host's DNS zone, even while the host still
  points somewhere else — the method to use when migrating a live domain. Choose
  it with `--method dns`:

```sh
boatramp domain add app.example.com --method dns
```

```text
domain app.example.com — pending (dns)
publish TXT record:
  _boatramp-verify.app.example.com  TXT  "7f3c9a2e…"
then run: boatramp domain verify app.example.com
```

A pending host does not route and cannot request a certificate until it passes.

## 2. Publish the challenge

Publish exactly what `domain add` printed:

- **HTTP** — make the site (or any server on the host) return the token body at
  the `/.well-known/boatramp-domain-verification/<token>` path.
- **DNS** — add the `_boatramp-verify.<host>` TXT record to the zone and wait
  for it to propagate.

If a managed-DNS provider is configured, skip this step: pass `--auto --provider
<name>` to `domain add` and boatramp publishes the DNS-TXT record and verifies it
for you. See [Automate DNS with a provider](../how-to/auto-dns.md).

## 3. Verify and attach

Run `domain verify`. It checks the challenge and, on success, attaches the host
to the site so it starts routing:

```sh
boatramp domain verify app.example.com
```

```text
domain app.example.com — verified (http), attached to site my-site
```

If the check fails, the host stays pending. Confirm the token file resolves, or
that the TXT record has propagated, then run `domain verify` again.

## 4. Confirm the attachment

List the site's domains to see what routes and what is still pending:

```sh
boatramp domain ls
```

```text
app.example.com   attached   my-site   http
beta.example.com  pending     —        dns
```

## Remove a domain

Detach a host — attached or still pending — with `domain rm`. It stops routing
immediately:

```sh
boatramp domain rm app.example.com
```

```text
domain app.example.com — removed
```

## Next: get a certificate

An attached host is eligible for a certificate but does not have one yet. Issue
one so the domain serves over HTTPS — see
[Get an automatic certificate](../how-to/acme-cert.md).
