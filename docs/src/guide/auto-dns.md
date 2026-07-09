# Auto-DNS & Custom Domains

boatramp can drive your managed-DNS provider directly, so three things that are
normally manual DNS edits become one command:

- answering **ACME DNS-01** challenges (wildcard + custom-domain certs),
- **pointing a custom domain** at your server (its `A`/`AAAA`/`CNAME`),
- **proving domain ownership** (`domain add --auto` publishes the challenge for
  you).

Every provider uses the same `DnsProvider` seam, so the commands and flags are
identical whichever one you pick — the only per-provider difference is the
credential environment variables.

## Providers

Ten managed-DNS providers are built in, plus `manual` (which just prints the
records to apply by hand — the credential-free fallback, and the answer for
self-hosted BIND/PowerDNS/Knot until RFC 2136 lands; see the roadmap note below).

| `--provider` | Provider | Credential env vars |
|--------------|----------|---------------------|
| `manual` | none (prints records) | — |
| `cloudflare` | Cloudflare | `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_API_TOKEN` |
| `route53` | AWS Route 53 | `ROUTE53_HOSTED_ZONE_ID` + the standard AWS chain |
| `oci` | Oracle Cloud DNS | `OCI_REGION`, `OCI_ZONE`, `OCI_KEY_ID`, `OCI_PRIVATE_KEY_FILE` |
| `digitalocean` (`do`) | DigitalOcean | `DIGITALOCEAN_DOMAIN`, `DIGITALOCEAN_TOKEN` |
| `hetzner` | Hetzner DNS | `HETZNER_ZONE_ID`, `HETZNER_ZONE`, `HETZNER_DNS_TOKEN` |
| `ns1` | NS1 (IBM) | `NS1_ZONE`, `NS1_API_KEY` |
| `dnsimple` | DNSimple | `DNSIMPLE_ACCOUNT_ID`, `DNSIMPLE_ZONE`, `DNSIMPLE_TOKEN` |
| `gcp-dns` (`gcp`) | Google Cloud DNS | `GCP_DNS_PROJECT`, `GCP_DNS_ZONE`, `GCP_ACCESS_TOKEN` |
| `azure-dns` (`azure`) | Azure DNS | `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `AZURE_DNS_ZONE`, `AZURE_ACCESS_TOKEN` |
| `akamai` | Akamai Edge DNS | `AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`, `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN`, `AKAMAI_ZONE` |

Credentials are read from the environment only — never from a config file. The
Google and Azure backends take a short-lived OAuth2 access token in the env var
(mint it with `gcloud`/`az`), matching how the KMS token signers work.

The same names work everywhere: `boatramp dns --provider <name>`, `serve
--acme-dns-provider <name>`, and `domain add --auto --provider <name>`.

## Point a custom domain at your server

Once a domain is **verified** (see below), point it here:

```bash
# apex → address record (a CNAME is invalid at a true apex)
boatramp dns configure-domain example.com --provider cloudflare --target 203.0.113.7

# sub-domain → CNAME (or an address)
boatramp dns configure-domain www.example.com --provider cloudflare --target lb.example.net
```

An IPv4/IPv6 literal becomes an `A`/`AAAA`; anything else becomes a `CNAME`.

Add `--proxied` to route the record through Cloudflare's edge (cache / WAF / edge
TLS). It is Cloudflare-only, chosen **per domain** (not a global switch), applies
only to address/CNAME records, and forces the automatic TTL Cloudflare requires
for proxied records:

```bash
boatramp dns configure-domain docs.example.com \
  --provider cloudflare --target app.fly.dev --proxied
```

## Automate ownership verification

`domain add --auto` closes the DNS-TXT verification loop for you: it publishes the
`_boatramp-verify.<host>` challenge through the provider, polls until it resolves,
attaches the host, then retracts the challenge record.

```bash
boatramp domain add app.example.com --auto --provider cloudflare
#   → publishes the _boatramp-verify TXT, waits for it to resolve, attaches app.example.com
```

Without `--auto` the flow is unchanged: `domain add` prints the record to publish
by hand and you run `domain verify` after (see [Domains & Virtualhosts](./domains.md)).

## Ownership before pointing

`--auto` writes **only** the ownership-proof TXT — never the host's `A`/`CNAME`.
Pointing a domain at your server is always a separate, explicit step
(`dns configure-domain`) that you run *after* ownership is verified. The rule is
deliberate: boatramp never points or serves a hostname you have not proven you
control, which prevents pointing (or accidentally serving) someone else's domain.

## What boatramp remembers

Records boatramp creates on your behalf are tracked in a per-host ledger in the
control plane (`dnsmanaged/<site>/<host>`: the provider + the exact records), so
they can be retracted cleanly when a domain is detached. Challenge TXTs are
retracted automatically once verification succeeds.

## Roadmap note

Today the DNS provider is driven by explicit commands (`dns configure-domain`,
`domain add --auto`) and by the ACME cert path (`serve --tls acme-dns`). A
**leader-only reconcile loop** — which continuously re-asserts each verified
custom domain's `A`/`CNAME` and per-domain certificate from the ledger, and
retracts detached ones — is implemented at the mechanism level (the ledger store
and the reconcile planner) and is being finished behind a `--dns-target` serve
option pending live multi-node validation. **RFC 2136** (TSIG dynamic UPDATE, for
self-hosted authoritative servers) is a planned additional provider; until then
those users can use `manual`.
