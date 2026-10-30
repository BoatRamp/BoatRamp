# Cargo features & platform support

boatramp is one binary of feature-gated crates, but the **default build is
batteries-included**: it enables **every non-conflicting feature**, so a plain
`cargo build`, the Nix/OCI images, and the release binaries all ship the full
capability set — there is no "the server was built without X". This page lists the
cargo features (all default-on) and then which capabilities are Linux-only. To
build a minimal binary instead, see [Build from source](../how-to/build-from-source.md).

## Cargo build features

**Every feature below is on by default.** The whole set composes (there are no
mutually-exclusive features; the runtime `--blobs` / `--kv` / `--tls` selectors
pick among the compiled-in backends), and the nightly `--all-features` gate proves
it. Should a feature ever genuinely *conflict* with another, it would be dropped
from the default and shipped as its own build variant.

For a **minimal build**, opt out and name only what you want:

```sh
cargo build --release -p boatramp --no-default-features --features fs,slatedb
```

Some features imply others: `http3`/`acme-dns` imply `tls`; `cluster` implies
`handlers` + `slatedb`; `operator` implies `cluster`; each `sql-*` and
`orm-subquery` imply `handlers`.

| Feature | Default | Enables |
| --- | --- | --- |
| `fs` | yes | Filesystem blob backend (`--blobs fs`). |
| `slatedb` | yes | The default `--kv slatedb`: a durable transactional LSM over an `object_store` backend. |
| `s3` | yes | S3 blob backend (`--blobs s3`) + its S3→SQS blob-change notification provider. |
| `gcs` | yes | Google Cloud Storage blob backend (`--blobs gcs`) + its GCS→Pub/Sub notification provider. |
| `azure` | yes | Azure Blob Storage backend (`--blobs azure`) + its Event Grid→Storage Queue notification provider. |
| `cloudflare-kv` | yes | Cloudflare KV metadata backend. |
| `tls` | yes | HTTPS: `--tls custom` (operator cert) and `--tls acme` (automatic certs). |
| `acme-dns` | yes | Wildcard TLS via ACME DNS-01 plus the `dns` subcommand (`--tls acme-dns`) and the pluggable DNS-provider clients. Implies `tls`. |
| `http3` | yes | HTTP/3 (QUIC) serving alongside the TLS TCP listener. Implies `tls`. |
| `oidc` | yes | OIDC → token exchange: verify `serve` against an OIDC issuer's JWKS. |
| `signer-aws` | yes | External token signer backed by AWS KMS. |
| `signer-gcp` | yes | External token signer backed by GCP KMS. |
| `signer-azure` | yes | External token signer backed by Azure Key Vault. |
| `signer-vault` | yes | External token signer backed by HashiCorp Vault. |
| `signer-pkcs11` | yes | External token signer backed by a PKCS#11 HSM. |
| `compression` | yes | On-the-fly response compression, opt-in per site. |
| `bundler` | yes | The in-process JS/TS + CSS bundler for `boatramp bundle`. |
| `handlers` | yes | The wasmtime handler engine, component validation at `sync`, and the `sql` handler binding (with the typed [`orm`](../how-to/handler-bindings.md#typed-queries-with-the-orm-builder) query builder over the same databases). |
| `cluster` | yes | Self-hosted Raft cluster mode. Implies `handlers` and `slatedb`. |
| `overlay` | yes | The overlay forward fabric: the `boatramp forward` / `boatramp overlay` / `boatramp tunnel` / `boatramp connect` subcommands and the serve-side `[overlay]` relay/egress roles — relay-blind, capability-gated port forwarding into a cluster. A minimal build re-adds it with `--features overlay`. |
| `tun` | no | The TUN virtual-interface front-end for `boatramp tunnel --tun` (Linux/macOS/Windows) — a real virtual network interface with split-DNS over the `overlay` fabric, so any program reaches in-zone service names transparently. **Opt-in, NOT in the batteries-included default**: the Windows release archive bundles it (with the signed `wintun.dll`); elsewhere build `--features tun` on top of `overlay`. Needs device privilege at run time (`CAP_NET_ADMIN`/root on Linux, root on macOS, Administrator on Windows). |
| `project-export` | yes | The server-side project export/import driver (env-clone) that answers `/api/project-{export,import}`. Implies `sql-postgres` + `fs`. (The `boatramp project export`/`import` client verbs are always built.) |
| `sql-postgres` | yes | External (bring-your-own) PostgreSQL for the handler `sql` binding, opened by name. Implies `handlers`. |
| `sql-mysql` | yes | External (bring-your-own) MySQL/MariaDB for the handler `sql` binding, opened by name. Implies `handlers`. |
| `orm-subquery` | yes | The typed [`orm`](../how-to/handler-bindings.md#typed-queries-with-the-orm-builder) builder's **correlated roll-up** (`related_count`/`related_agg`) and **narrow scalar/`IN` subqueries** — the one scalar-subquery form. Implies `handlers`; drop it to ship a host that refuses correlated subqueries. (pgvector distance and the rest of the `orm` surface are always compiled — not a cargo feature; pgvector is advertised to guests as the experimental `orm-vector` **capability** — a `requires` gate, not a build feature.) |
| `email` | yes | The per-project SMTP email gateway: the `boatramp:handlers/email` guest capability + the `boatramp email` admin subcommand (host-held credentials, durable spool). Implies `handlers`; drop it for a build with no SMTP client. |
| `admin` | yes | The guest project self-config capability `boatramp:handlers/admin` — a guest reconfigures its own project (domains / email / site / secrets) without a token, per-surface and posture-gated. Implies `handlers`; drop it for a build with no guest self-config. |
| `migrate` | yes | Owner-gated schema-migration `function` steps (`boatramp:handlers/migrate-ddl`) — a migration function runs owner-role DDL/DML/verification inside a `Project·Admin` migration run (plain `sql`/`extension` steps work without it). Implies `handlers`. |
| `capability` | yes | The guest capability-minting capability `boatramp:handlers/capability` — a guest mints a fleet-signed, own-project-only target capability (audience host-forced, TTL-clamped, deny-by-default). Implies `handlers`; drop it for a build with no guest capability minting. |
| `session` | yes | The duplex guest session capability `boatramp:handlers/session` — a host-owned SSE-out + POST-in channel with host-managed ordering, resume, and lifetime. Implies `handlers`. |
| `tcp-listener` | yes | Host-owned inbound-TCP listeners (`[serve.listeners.<name>]`): the serve accept loop + the `tcp-connection-host` conn-lane dispatch + per-source-IP connection-rate admission (cap-req 18). Also compiles the `boatramp:handlers/tcp-connection-context` capability (cap-req 16) — a listener guest reads its connection's current wire security (`plaintext`/`tls`/`starttls-pending`, fail-closed), to refuse credentials over plaintext / gate STARTTLS. Implies `handlers`. Runtime-opt-in (posture `allow_guest_tcp_listener` + a declared listener), so compiling it in binds nothing by itself. |
| `tcp-egress` | yes | Host-terminated outbound-TLS egress (`boatramp:handlers/tcp-egress`, mailroom cap-req #15): the OUTBOUND mirror of `tcp-listener` — the host dials the TCP connection and terminates TLS, handing a granted guest only plaintext `wasi:io` streams. Also compiles the `boatramp:handlers/dns-resolve` capability (cap-req 20) — a guest resolves MX / host addresses host-side (`resolve-mx`/`resolve-addr`), SSRF-floored, the DNS half of the egress story. Implies `handlers`. Runtime-opt-in (both gated by the posture `allow_guest_tcp_egress`; `tcp-egress` also needs a non-empty per-handler `egress_allowlist`), so compiling it in grants nothing by itself. |
| `blob-upload` | yes | The guest `boatramp:handlers/blob-upload` capability + the `boatramp blob mint-upload` operator subcommand — mint a short-lived, scoped S3 upload credential for one of a project+site's own blob containers (host-forced scope, TTL/max-bytes clamped, deny-by-default). Implies `handlers`. |
| `blob-upload-cloud` | yes | The **cloud** blob-upload minters (`blob-upload-aws`/`-gcs`/`-azure`): broker a native scoped credential (AWS STS session policy / GCS signed URL + CAB / Azure user-delegation SAS) so a client uploads directly to a cloud-backed blob container. |
| `console` | yes | Bake the web management console (a Wasm SPA) into the binary; serve it at an operator-configured host+path (`[serve.console]`). On in every shipped build (release binaries + Nix/OCI images), which stage the built SPA in; a from-source build embeds a placeholder unless you build the SPA first with `just console`. |
| `mcp` | yes | The [Model Context Protocol](../how-to/mcp.md) server: the `boatramp mcp` stdio subcommand + the HTTP `/mcp` endpoint on `serve`. Also enables `boatramp-server/mcp`. |
| `sandbox` | yes | The whole-process OS sandbox (privsep Phase 0): seccomp-bpf + Landlock, installed on the serving process before it starts serving. **Linux-only** — on another platform this feature compiles only the documented no-op path, so the default build still builds everywhere. Runtime behavior is `[serve.sandbox]`'s `posture` (default `auto`); see the [config reference](./boatramp-cfg.md#servesandbox). |

Two more features are on by default but omitted from the table above:
`domain-verify-dns` (verify a host's `_boatramp-verify` TXT over public DNS) and
`operator` (the in-binary Kubernetes operator; implies `cluster`).

The COSE/CWT + Cedar control-plane auth, the OCI→ext4 rootfs build, and the
container / microVM / remote-docker compute backends are compiled into every
build; they are not behind cargo features. The compute code that needs Linux is
gated at the source level and compiles to no-ops elsewhere.

```sh
# A minimal build (filesystem blobs + embedded KV only).
cargo build --release -p boatramp --no-default-features --features fs,slatedb
```

## Platform support

The publish / serve / handler / TLS / cluster core is cross-platform. The compute
execution backends differ:

| Platform | Compute backends |
| --- | --- |
| Linux `x86_64`, `aarch64` | microVM (needs `/dev/kvm`), native container, remote-docker |
| macOS (Apple silicon, macOS 15+) | native microVM via Virtualization.framework (`vmm-vz`), remote-docker |
| macOS (Intel), Windows | remote-docker only |

The microVM and native-container Linux backends need `/dev/kvm`, namespaces, and
the jailer, so they are Linux-only. Apple-silicon macOS instead gets its own
native microVM backend (`vmm-vz`, boots each replica as a Linux VM via
Virtualization.framework — see [`compute`](./boatramp-cfg.md#compute)); Intel
macOS and Windows have no native backend, so compute there runs through the
remote-docker backend against a Linux Docker host.

## See also

- [Build from source](../how-to/build-from-source.md) — toolchain and selecting
  features at build time.
- [Install boatramp](../how-to/install.md) — prebuilt archives and packages.
