# Cargo features & platform support

boatramp is one binary of feature-gated crates. The default build is lean; the
heavier capabilities are compiled in with cargo features. This page lists the
cargo features and their default state, then which capabilities are Linux-only.
To turn features on when compiling, see
[Build from source](../how-to/build-from-source.md).

## Cargo build features

The default set is `fs` and `slatedb`; every other feature is off unless named on
the `cargo build` command line. Some features imply others: `http3` implies
`tls`, `acme-dns` implies `tls`, and `cluster` implies `handlers` and `slatedb`.

| Feature | Default | Enables |
| --- | --- | --- |
| `fs` | yes | Filesystem blob backend (`--blobs fs`). |
| `slatedb` | yes | The default `--kv slatedb`: a durable transactional LSM over an `object_store` backend. |
| `s3` | no | S3 blob backend (`--blobs s3`) + its S3→SQS blob-change notification provider. |
| `gcs` | no | Google Cloud Storage blob backend (`--blobs gcs`) + its GCS→Pub/Sub notification provider. |
| `azure` | no | Azure Blob Storage backend (`--blobs azure`) + its Event Grid→Storage Queue notification provider. |
| `cloudflare-kv` | no | Cloudflare KV metadata backend. |
| `tls` | no | HTTPS: `--tls custom` (operator cert) and `--tls acme` (automatic certs). |
| `acme-dns` | no | Wildcard TLS via ACME DNS-01 plus the `dns` subcommand (`--tls acme-dns`) and the pluggable DNS-provider clients. Implies `tls`. |
| `http3` | no | HTTP/3 (QUIC) serving alongside the TLS TCP listener. Implies `tls`. |
| `oidc` | no | OIDC → token exchange: verify `serve` against an OIDC issuer's JWKS. |
| `signer-aws` | no | External token signer backed by AWS KMS. |
| `signer-gcp` | no | External token signer backed by GCP KMS. |
| `signer-azure` | no | External token signer backed by Azure Key Vault. |
| `signer-vault` | no | External token signer backed by HashiCorp Vault. |
| `signer-pkcs11` | no | External token signer backed by a PKCS#11 HSM. |
| `compression` | no | On-the-fly response compression, opt-in per site. |
| `bundler` | no | The in-process JS/TS + CSS bundler for `boatramp bundle`. |
| `handlers` | no | The wasmtime handler engine, component validation at `sync`, and the `sql` handler binding. |
| `cluster` | no | Self-hosted Raft cluster mode. Implies `handlers` and `slatedb`. |

The COSE/CWT + Cedar control-plane auth, the OCI→ext4 rootfs build, and the
container / microVM / remote-docker compute backends are compiled into every
build; they are not behind cargo features. The compute code that needs Linux is
gated at the source level and compiles to no-ops elsewhere.

```sh
# HTTPS, handlers, and wildcard preview certs.
cargo build --release -p boatramp --features tls,handlers,acme-dns
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
