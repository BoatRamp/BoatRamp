# The security posture model

The security posture is boatramp's answer to one question: **who do you trust?**
A platform that serves one operator's own sites on a private network can be loose
in ways that a platform hosting untrusted tenants on the public internet must
not. Rather than scatter that judgment across dozens of individual defaults, the
posture makes it one explicit, inspectable decision.

## Why it is operator-only

The hazards a posture governs — running a public bind without auth, upload and
component size caps, whether a site may reach private-network upstreams, whether
compute may share the host kernel — are exactly the ones a **site** must not be
able to relax. So the posture lives only in the operator's `boatramp.cfg` and is
never part of site config. A principal with `site-write` can change routing,
handlers, and content, but cannot widen the trust boundary.

This is why some capabilities are refused by default even though the code
supports them: a site cannot declare a private-IP gateway upstream, and
shared-kernel compute is off, until the operator opts in.

## Knobs are the truth; profiles are sugar

A posture resolves to a set of **knobs** — concrete booleans and byte caps like
`allow_unauthenticated_public_bind`, `max_upload_bytes`, and
`allow_shared_kernel_compute`. Those knobs are what the server actually enforces.

A **profile** is a named bundle of knob values, nothing more:

- `multi-tenant` (the default) assumes untrusted site writers on an untrusted
  network and sets every knob to its strict value.
- `single-tenant` assumes one operator who owns every site and relaxes the knobs
  that only matter between mutually-distrusting tenants.
- `dev` assumes local development and loosens loopback-only conveniences.

Overrides layer individual knobs on top of a profile, so you start from a
coherent baseline and adjust one thing without silently loosening others. Because
the knob is the unit of enforcement, `boatramp security explain` can always show
the resolved value and its source — profile or override.

## The default is strict on purpose

The `multi-tenant` default fails closed: a non-loopback bind refuses to start
without auth, uploads and components are capped, private upstreams and
shared-kernel compute are denied. An operator who wants less must say so
explicitly. That ordering — safe by default, dangerous only on request — is the
whole point of having a posture rather than a pile of independent flags.

To set and inspect one, see
[Choose & inspect a security posture](../how-to/security-posture.md).
