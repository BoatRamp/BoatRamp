# boatramp — common developer tasks. Run `just` to list them.
# https://just.systems

set shell := ["bash", "-cu"]

# Show available recipes.
default:
    @just --list

# Build the workspace (filesystem backend).
build:
    cargo build --workspace

# Build everything, including the S3 backend.
build-all:
    cargo build --workspace --all-features

# Run the HTTP server (filesystem backend).
serve addr="127.0.0.1:8080" data_dir="./data":
    cargo run -- serve --addr {{ addr }} --data-dir {{ data_dir }}

# Run any subcommand, e.g. `just run deployments --site my-site`.
run *args:
    cargo run -- {{ args }}

# Rebuild and restart the server on changes.
watch:
    cargo watch -x 'run -- serve'

# Format Rust, Nix and TOML.
fmt:
    cargo fmt --all
    taplo fmt
    nixfmt flake.nix

# Lint with clippy (default features and all features), denying warnings.
lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run the test suite.
test:
    cargo nextest run --workspace

# Run the full pre-commit hook suite against all files.
check:
    pre-commit run --all-files

# Audit dependencies for advisories, bans and license issues.
deny:
    cargo deny check

# Start a local MinIO (S3-compatible) server for backend testing.
# Console at http://localhost:9001 (default creds minioadmin / minioadmin).
minio data_dir="./.minio":
    mkdir -p {{ data_dir }}
    minio server {{ data_dir }} --address 127.0.0.1:9000 --console-address 127.0.0.1:9001

# Start a local sqld (libsql server) for the `sql` backend test. Serves
# the hrana/HTTP protocol; runs in the foreground (Ctrl-C to stop). Namespaces
# are enabled (the per-site isolation model — one namespace per site) with the
# admin API on `admin_addr` for namespace creation.
sqld data_dir="./.sqld" port="8080" admin_port="9090":
    @echo "sqld on http://localhost:{{ port }} (admin http://localhost:{{ admin_port }}) — run the libsql tests with:"
    @# Use the `localhost` hostname (not 127.0.0.1): with namespaces enabled sqld
    @# routes by the Host subdomain, and a bare `localhost` falls back to the
    @# `default` namespace while `<ns>.localhost` resolves to loopback for the
    @# per-site factory test (you can't subdomain a bare IP).
    @echo "  BOATRAMP_TEST_LIBSQL_URL=http://localhost:{{ port }} \\"
    @echo "  BOATRAMP_TEST_LIBSQL_ADMIN_URL=http://localhost:{{ admin_port }} \\"
    @echo "    cargo test -p boatramp-storage --features sql --test sql_libsql"
    sqld -d "{{ data_dir }}" --http-listen-addr 127.0.0.1:{{ port }} \
      --admin-listen-addr 127.0.0.1:{{ admin_port }} --enable-namespaces

# Run the ACME DNS-01 wildcard-cert end-to-end test against a local Pebble CA.
# The test spawns `pebble` + `pebble-challtestsrv` (provided by `nix develop`),
# mints a throwaway CA, and drives a real `*.deploy.test` wildcard issuance.
acme-dns-e2e:
    cargo test -p boatramp-acme --features acme --test pebble_dns01 -- --ignored --nocapture

# FA-7 `function init` → `function build` round-trip: scaffold the Rust template
# and compile it to a `wasi:http` component (needs the `wasm32-wasip2` target +
# `wasm-tools`, both in `nix develop`). This is the "each template builds to a
# component" gate; run it in CI / the dev shell (it fetches the template's crates,
# so it is not a hermetic flake check).
function-roundtrip:
    cargo test -p boatramp function::tests::init_then_build -- --ignored --nocapture

# Remove build artifacts.
clean:
    cargo clean

# ---- fly.io docs deployment (docs.boatramp.dev) -------------------------------

# Publish the docs to the live boatramp instance + purge the Cloudflare cache.
# Content-only (no image rebuild). Needs `boatramp` on PATH and BOATRAMP_TOKEN in
# the env; CF_ZONE_ID + CF_PURGE_TOKEN enable the purge (skipped if unset).
deploy-docs server="https://docs.boatramp.dev" site="docs":
    #!/usr/bin/env bash
    set -euo pipefail
    mdbook build docs
    boatramp sync docs/book --server "{{ server }}" --site "{{ site }}"
    if [ -n "${CF_ZONE_ID:-}" ] && [ -n "${CF_PURGE_TOKEN:-}" ]; then
      echo "purging Cloudflare cache…"
      curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/purge_cache" \
        -H "Authorization: Bearer ${CF_PURGE_TOKEN}" -H "Content-Type: application/json" \
        --data '{"purge_everything":true}' >/dev/null
      echo "  purged"
    else
      echo "CF_ZONE_ID/CF_PURGE_TOKEN unset — skipping cache purge"
    fi

# Build the base image via Nix + deploy it to the fly app (rare — only when the
# boatramp binary changes; docs content uses `deploy-docs`). Linux-only
# (dockerTools). Needs flyctl + skopeo + FLY_API_TOKEN.
fly-image app="boatramp-docs" tag="latest":
    #!/usr/bin/env bash
    set -euo pipefail
    nix build .#container --out-link image.tar.gz
    skopeo copy docker-archive:image.tar.gz \
      "docker://registry.fly.io/{{ app }}:{{ tag }}" --dest-creds "x:${FLY_API_TOKEN}"
    fly deploy --app "{{ app }}" --image "registry.fly.io/{{ app }}:{{ tag }}"
