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
| `hetzner` | — | Hetzner DNS | `HETZNER_ZONE_ID`, `HETZNER_ZONE`, `HETZNER_DNS_TOKEN` |
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

## See also

- [Automate DNS with a provider](../how-to/auto-dns.md)
- [Wildcard certs with DNS-01](../how-to/wildcard-dns01.md)
