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
`handlers` + `slatedb`; `operator` implies `cluster`; each `sql-*` implies
`handlers`.

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
| `handlers` | yes | The wasmtime handler engine, component validation at `sync`, and the `sql` handler binding. |
| `cluster` | yes | Self-hosted Raft cluster mode. Implies `handlers` and `slatedb`. |
| `sql-postgres` | yes | External (bring-your-own) PostgreSQL for the handler `sql` binding, opened by name. Implies `handlers`. |
| `sql-mysql` | yes | External (bring-your-own) MySQL/MariaDB for the handler `sql` binding, opened by name. Implies `handlers`. |
| `console` | yes | Bake the web management console (a Wasm SPA) into the binary; serve it at an operator-configured host+path (`[serve.console]`). On in every shipped build (release binaries + Nix/OCI images), which stage the built SPA in; a from-source build embeds a placeholder unless you build the SPA first with `just console`. |

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
| macOS, Windows | remote-docker only |

The microVM and native-container backends need `/dev/kvm`, namespaces, and the
jailer, so they are Linux-only; on macOS and Windows that code compiles to
no-ops and compute runs through the remote-docker backend against a Linux Docker
host.

## See also

- [Build from source](../how-to/build-from-source.md) — toolchain and selecting
  features at build time.
- [Install boatramp](../how-to/install.md) — prebuilt archives and packages.
