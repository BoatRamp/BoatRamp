# DNS providers & credentials

The managed-DNS providers boatramp drives directly, and the `manual` fallback.
Ten providers are built in. Each entry lists the value passed to `--provider`,
any accepted alias, and the exact credential environment variables the provider
reads.

Credentials are read from the environment only — never from a config file. The
same `--provider` names apply in every DNS command surface:
`boatramp dns --provider <name>`, `boatramp serve --acme-dns-provider <name>`,
and `boatramp domain add --provider <name>`.

## Providers

| `--provider` | Alias | Provider | Credential env vars |
|--------------|-------|----------|---------------------|
| `manual` | — | none (prints records) | — |
| `cloudflare` | — | Cloudflare | `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_API_TOKEN` |
| `route53` | — | AWS Route 53 | `ROUTE53_HOSTED_ZONE_ID` + the standard AWS chain |
| `oci` | — | Oracle Cloud DNS | `OCI_REGION`, `OCI_ZONE`, `OCI_KEY_ID`, `OCI_PRIVATE_KEY_FILE` |
| `digitalocean` | `do` | DigitalOcean | `DIGITALOCEAN_DOMAIN`, `DIGITALOCEAN_TOKEN` |
| `hetzner` | — | Hetzner Cloud DNS | `HETZNER_ZONE`, `HETZNER_DNS_TOKEN` |
| `ns1` | — | NS1 (IBM) | `NS1_ZONE`, `NS1_API_KEY` |
| `dnsimple` | — | DNSimple | `DNSIMPLE_ACCOUNT_ID`, `DNSIMPLE_ZONE`, `DNSIMPLE_TOKEN` |
| `gcp-dns` | `gcp` | Google Cloud DNS | `GCP_DNS_PROJECT`, `GCP_DNS_ZONE`, `GCP_ACCESS_TOKEN` |
| `azure-dns` | `azure` | Azure DNS | `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `AZURE_DNS_ZONE`, `AZURE_ACCESS_TOKEN` |
| `akamai` | — | Akamai Edge DNS | `AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`, `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN`, `AKAMAI_ZONE` |

## Notes

- `manual` prints the records to apply by hand and reads no credentials. It is
  the fallback for self-hosted authoritative servers (BIND, PowerDNS, Knot).
- `gcp-dns` and `azure-dns` take a short-lived OAuth2 access token in
  `GCP_ACCESS_TOKEN` / `AZURE_ACCESS_TOKEN`. Mint it with `gcloud` / `az`.
- `route53` reads `ROUTE53_HOSTED_ZONE_ID` for the zone and resolves credentials
  through the standard AWS provider chain (environment, shared config, instance
  role).
- `hetzner` targets the **Hetzner Cloud** DNS API (`api.hetzner.cloud`). The zone
  is addressed by its name, so no numeric zone id is needed (the former
  `HETZNER_ZONE_ID` is no longer read). **Breaking change:** `HETZNER_DNS_TOKEN`
  must now be a Hetzner **Cloud** API token (Bearer auth); the old classic DNS
  API token (`dns.hetzner.com`, `Auth-API-Token`) is decommissioned and no longer
  works. Mint a Cloud API token in the Hetzner Cloud Console
  (project → Security → API tokens). Supported record types include A, AAAA,
  CNAME, TXT, MX, SRV, CAA, NS, PTR, TLSA, and HTTPS/SVCB.

## Multi-zone: a per-zone provider list (`[serve.dns_providers]`)

The `--provider` / `--acme-dns-provider` / `--dns-publish-provider` flags seed **one**
provider from process-global env vars (`CLOUDFLARE_ZONE_ID` + `CLOUDFLARE_API_TOKEN`,
…) — so one `boatramp serve` manages exactly **one** zone. A single-tenant serve that is
authoritative for several domains in **different** zones instead declares a **list** of
per-zone providers in `[serve.dns_providers]`. **Both** consumers — the ACME DNS-01 cert
issuer (`--tls acme-dns`) and the guest `dns-publish` capability — route to the provider
whose `zone_root` is the **longest label-boundary suffix** of the record's / certificate's
owner name (`uranion.link` matches `a.uranion.link` and `uranion.link`, but **not**
`evil-uranion.link`; a nested `b.example.com` wins over `example.com`). No match ⇒
fail-closed. **Empty/absent `dns_providers` ⇒ the single env-seeded path above, unchanged.**

Every identity/credential field is a standard boatramp **`type:value` config pointer**:

- a **bare literal** (`zone_id: "741f56…"`),
- `env:VAR` — the operator's environment (only when the posture's `allow_env_secret_refs`
  is set), or
- `boatramp:NAME` — the sealed `[secrets]` store (resolved under the default project at
  startup; a `boatramp:` ref with no `[secrets]` envelope is a fail-closed **startup error**).

**No secrets in config:** a SECRET field (`token`, `api_key`, `access_token`,
`client_token`, `client_secret`) **must** be a `env:`/`boatramp:` ref — a plaintext literal
is refused at startup (exactly as `[serve.s3_credential].secret_access_key` is). Non-secret
identifiers may be a literal but accept the pointer grammar uniformly. Duplicate `zone_root`s
are refused at startup (longest-suffix can't disambiguate an exact duplicate).

```ron
// Cloudflare, two zones, one serve. Tokens sealed in [secrets]; zone ids are literals.
serve: (
    dns_providers: [
        ( name: "mailroom-pro", kind: "cloudflare", zone_root: "mailroom.pro",
          zone_id: "741f56…",                         // literal (or env:… / boatramp:…)
          token:   "boatramp:CF_TOKEN_MAILROOM_PRO" ), // sealed-store ref (a zone-scoped token)
        ( name: "cariello", kind: "cloudflare", zone_root: "cariello.name",
          zone_id: "a1b2c3…", token: "boatramp:CF_TOKEN_CARIELLO" ),
        // …one entry per served domain/zone
    ],
)
```

`kind` is a **quoted string** using the same grammar + aliases as `--provider` (so a
hyphenated kind like `"gcp-dns"` is expressible — RON enum variants can't contain a hyphen).

### Per-kind config fields

Mirror each provider's env vars, lowercased/namespaced. **Bold** = secret (must be a ref).

| `kind` | config fields (→ mirrors the env vars above) |
|--------|-----------------------------------------------|
| `manual` | *(none)* |
| `cloudflare` | `zone_id`, **`token`**, `proxied` (bool, optional — orange-cloud) |
| `route53` | `hosted_zone_id` (credentials via the AWS provider chain — no token field) |
| `oci` | `region`, `zone`, `key_id`, `private_key_file` (a path; the PEM stays on disk) |
| `digitalocean` | `domain`, **`token`** |
| `hetzner` | `zone`, **`token`** |
| `ns1` | `zone`, **`api_key`** |
| `dnsimple` | `account_id`, `zone`, **`token`** |
| `gcp-dns` | `project`, `zone`, **`access_token`** |
| `azure-dns` | `subscription_id`, `resource_group`, `zone`, **`access_token`** |
| `akamai` | `host`, **`client_token`**, **`client_secret`**, **`access_token`**, `zone` |

For **guest `dns-publish`** over the multi-zone registry, set
`--dns-publish-provider list` (or `[serve.dns_publish].provider = "list"`); the posture
`allow_guest_dns_publish` + the per-handler `dns_publish_zones` allowlist still gate every
write. See [`serve.dns_providers`](boatramp-cfg.md#servedns_providers).

> **Operator caution (multi-zone blast radius).** The registry is **node-global**: a single
> `dns-publish` provider source now serves *every* configured zone, routed by the record's own
> name. So a **wide** per-handler `dns_publish_zones` allowlist (e.g. `**`) exposes **all**
> configured zones to that guest, not just one — a broader reach than the pre-registry single-zone
> model. Keep each grant's `dns_publish_zones` scoped to the exact owner names it needs (the default
> is deny-all); the allowlist, not the registry, is the per-guest least-privilege bound.

## See also

- [Automate DNS with a provider](../how-to/auto-dns.md)
- [Wildcard certs with DNS-01](../how-to/wildcard-dns01.md)
