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

# Run the GCS backend round-trip against a `fake-gcs-server` emulator (Docker).
# Boots the emulator with a pre-created `boatramp` bucket, then runs the env-gated
# `gcs_emulator` seam. The `gcs` feature toolchain is needed.
gcs-emulator bucket="boatramp":
    #!/usr/bin/env bash
    set -euo pipefail
    docker run -d --name boatramp-fakegcs -p 4443:4443 \
      fsouza/fake-gcs-server -scheme http -public-host localhost:4443 >/dev/null
    trap 'docker rm -f boatramp-fakegcs >/dev/null' EXIT
    sleep 2
    curl -fsS -X POST "http://localhost:4443/storage/v1/b?project=test" \
      -H 'Content-Type: application/json' --data '{"name":"{{ bucket }}"}' >/dev/null
    BOATRAMP_TEST_GCS_ENDPOINT=http://localhost:4443 BOATRAMP_TEST_GCS_BUCKET={{ bucket }} \
      cargo test -p boatramp-storage --features gcs --test gcs_emulator -- --nocapture

# Run the Azure Blob backend round-trip against an Azurite emulator (Docker).
# Boots Azurite, creates the container via the Azure CLI against the well-known
# devstoreaccount1, then runs the env-gated `azure_emulator` seam.
azure-emulator container="boatramp":
    #!/usr/bin/env bash
    set -euo pipefail
    docker run -d --name boatramp-azurite -p 10000:10000 \
      mcr.microsoft.com/azure-storage/azurite azurite-blob --blobHost 0.0.0.0 >/dev/null
    trap 'docker rm -f boatramp-azurite >/dev/null' EXIT
    sleep 2
    CONN='DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;'
    az storage container create --name {{ container }} --connection-string "$CONN" >/dev/null
    BOATRAMP_TEST_AZURE_CONTAINER={{ container }} \
      cargo test -p boatramp-storage --features azure --test azure_emulator -- --nocapture

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

# Start a throwaway PostgreSQL in Docker for the external (bring-your-own) SQL
# backend test. Runs in the foreground (Ctrl-C to stop; the container is removed
# on exit). Prints the URL to run the live round-trip with.
pg port="5432":
    @echo "postgres on localhost:{{ port }} — run the external-SQL test with:"
    @echo "  BOATRAMP_TEST_PG_URL=postgres://boatramp:boatramp@localhost:{{ port }}/boatramp \\"
    @echo "    cargo test -p boatramp-storage --features sql-postgres --test sql_sqlx_live -- --nocapture"
    docker run --rm --name boatramp-pg -p {{ port }}:5432 \
      -e POSTGRES_USER=boatramp -e POSTGRES_PASSWORD=boatramp -e POSTGRES_DB=boatramp \
      postgres:16-alpine

# Start a throwaway MySQL in Docker for the external (bring-your-own) SQL backend
# test. Runs in the foreground (Ctrl-C to stop; the container is removed on exit).
mysql port="3306":
    @echo "mysql on localhost:{{ port }} — run the external-SQL test with:"
    @echo "  BOATRAMP_TEST_MYSQL_URL=mysql://boatramp:boatramp@localhost:{{ port }}/boatramp \\"
    @echo "    cargo test -p boatramp-storage --features sql-mysql --test sql_sqlx_live -- --nocapture"
    docker run --rm --name boatramp-mysql -p {{ port }}:3306 \
      -e MYSQL_USER=boatramp -e MYSQL_PASSWORD=boatramp -e MYSQL_DATABASE=boatramp \
      -e MYSQL_ROOT_PASSWORD=boatramp \
      mysql:8

# Build the embedded web console (Wasm SPA) into crates/boatramp-console/dist,
# which the `console`-featured server binary bakes in (via build.rs). Needs
# trunk + tailwindcss + the wasm32-unknown-unknown target (all in `nix develop`).
# Run this before building/serving with `--features console`.
console:
    cd crates/boatramp-console && trunk build --release

# Rebuild the committed WebAssembly example fixtures the `boatramp-handlers`
# engine tests load (`crates/boatramp-handlers/tests/fixtures/*.wasm`). Compiles
# each guest under `examples/handlers/*` to a `wasi:http` component and copies it
# into place. Needs the `wasm32-wasip2` target (in `nix develop`). Run after
# changing an example guest or a host WIT interface one links against.
build-fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    dest="crates/boatramp-handlers/tests/fixtures"
    for name in http-200 kv-counter sql-counter sql-named event-consumer invoke-caller graphql-accounts graphql-reviews graphql-agent; do
      echo "== building $name =="
      ( cd "examples/handlers/$name" && cargo build --release --target wasm32-wasip2 )
      # The crate emits boatramp_example_<name-with-underscores>.wasm; the fixture
      # keeps the example's hyphenated name.
      out="boatramp_example_${name//-/_}"
      cp "examples/handlers/$name/target/wasm32-wasip2/release/${out}.wasm" "$dest/$name.wasm"
      echo "   -> $dest/$name.wasm"
    done
    # The compose edge/plugin components the `boatramp compose` test loads.
    cdest="crates/boatramp/tests/fixtures"
    for name in edge plugin; do
      echo "== building compose-$name =="
      ( cd "examples/compose/$name" && cargo build --release --target wasm32-wasip2 )
      cp "examples/compose/$name/target/wasm32-wasip2/release/boatramp_compose_${name}.wasm" "$cdest/compose-$name.wasm"
      echo "   -> $cdest/compose-$name.wasm"
    done
    echo "fixtures rebuilt"

# Run the ACME DNS-01 wildcard-cert end-to-end test against a local Pebble CA.
# The test spawns `pebble` + `pebble-challtestsrv` (provided by `nix develop`),
# mints a throwaway CA, and drives a real `*.deploy.test` wildcard issuance.
acme-dns-e2e:
    cargo test -p boatramp-acme --features acme --test pebble_dns01 -- --ignored --nocapture

# FA-7 `function init` → `function build` → local-harness round-trip: scaffold the
# Rust template, compile it to a `wasi:http` component, and run it through the
# in-process harness (needs the `wasm32-wasip2` target + `wasm-tools`, both in
# `nix develop`). The "each template builds to a component and round-trips through
# the local harness" gate; run it in CI / the dev shell (it fetches the template's
# crates, so it is not a hermetic flake check).
function-roundtrip:
    cargo test -p boatramp --features handlers function::tests::harness_runs_a_component_and_asserts
    cargo test -p boatramp function::tests::init_then_build -- --ignored --nocapture

# FA-7 JS round-trip: scaffold the JS template + componentize it with `jco` (via
# `npx`, needs `nodejs` from `nix develop` + network). Separate from the Rust
# recipe since it fetches jco + runs StarlingMonkey (slow).
function-roundtrip-js:
    cargo test -p boatramp function::tests::init_then_build_js -- --ignored --nocapture

# FA-7 Python round-trip: scaffold the Python template + componentize it with
# `componentize-py` (via `uvx`, needs `uv` from `nix develop` + network).
function-roundtrip-py:
    cargo test -p boatramp function::tests::init_then_build_python -- --ignored --nocapture

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
    # docs.boatramp.dev is DNS-only (grey cloud) today, so there is no Cloudflare
    # edge cache to purge and this step is a no-op; it only matters once the record
    # is orange-clouded (`boatramp dns configure-domain … --proxied`). Best-effort
    # regardless: a missing/expired CF token must never fail an otherwise-successful
    # deploy (the docs are already served from the fly origin).
    if [ -n "${CF_ZONE_ID:-}" ] && [ -n "${CF_PURGE_TOKEN:-}" ]; then
      echo "purging Cloudflare cache…"
      code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/purge_cache" \
        -H "Authorization: Bearer ${CF_PURGE_TOKEN}" -H "Content-Type: application/json" \
        --data '{"purge_everything":true}' || echo 000)
      if [ "$code" = 200 ]; then
        echo "  purged"
      else
        echo "  warn: cache purge returned HTTP $code (non-fatal; docs served from the fly origin)"
      fi
    else
      echo "CF_ZONE_ID/CF_PURGE_TOKEN unset — skipping cache purge (docs is DNS-only)"
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

# ---- crates.io release --------------------------------------------------------

# Bump the whole workspace to VERSION in one shot: the `[workspace.package]`
# version every crate inherits, the internal `[workspace.dependencies]` path-dep
# pins (which cargo requires for publishing and cargo-deny requires be non-wildcard
# — so they must track the version, but Cargo has no way to auto-inherit them), the
# workspace-excluded console crate, and the lockfile. Run before tagging a release.
bump-version version:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{ version }}"
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || { echo "not a semver: $v" >&2; exit 1; }
    # The single `[workspace.package]` version line (the only bare `version = "..."`
    # in the root manifest — the dep pins all end in ` }`).
    perl -i -pe 's/^version = "[^"]*"$/version = "'"$v"'"/' Cargo.toml
    # The internal path-dep pins, anchored on the boatramp path so no external dep
    # is touched.
    perl -i -pe 's/(boatramp-[a-z]+ = \{ path = "crates\/boatramp-[a-z]+", )version = "[^"]*"( \})/${1}version = "'"$v"'"${2}/' Cargo.toml
    # The workspace-excluded console crate (its own manifest + lockfile).
    perl -i -pe 's/^version = "[^"]*"$/version = "'"$v"'"/' crates/boatramp-console/Cargo.toml
    # The README's install pins (`cargo install boatramp@X`, `nix run …/vX`,
    # `git checkout vX`) — kept in lockstep so the CI version-pin tripwire passes.
    perl -i -pe 's/(boatramp\@)[0-9]+\.[0-9]+\.[0-9]+/${1}'"$v"'/; s/(BoatRamp\/v)[0-9]+\.[0-9]+\.[0-9]+/${1}'"$v"'/; s/(checkout v)[0-9]+\.[0-9]+\.[0-9]+/${1}'"$v"'/' README.md
    # Refresh the lockfiles' workspace-member versions.
    cargo update --workspace
    ( cd crates/boatramp-console && cargo update --workspace )
    echo "bumped workspace to $v"

# The workspace crates in dependency (publish) order — leaf crates first, so each
# crate's internal deps are already on crates.io by the time it publishes.
crate_order := "boatramp-http boatramp-types boatramp-rpktls boatramp-acme boatramp-core boatramp-storage boatramp-cloudflare boatramp-firecracker boatramp-container boatramp-docker boatramp-vz boatramp-mcp boatramp-cluster boatramp-handlers boatramp-server boatramp-node boatramp"

# Dry-run the release packaging of every workspace crate (no upload). `cargo` can't
# validate a dependent crate until its internal deps are actually on crates.io, so
# those are reported DEFERRED (not a failure — they're validated for real when
# published in order); only a genuine packaging problem is a FAIL. Safe anytime.
publish-dry:
    #!/usr/bin/env bash
    set -uo pipefail
    rc=0
    for c in {{ crate_order }}; do
      if out="$(cargo publish -p "$c" --dry-run --no-verify 2>&1)"; then
        echo "OK       $c"
      elif grep -q "no matching package named" <<<"$out"; then
        echo "DEFERRED $c (internal deps not yet on crates.io)"
      else
        echo "FAIL     $c"; tail -5 <<<"$out"; rc=1
      fi
    done
    exit $rc

# Publish every workspace crate to crates.io, in dependency order. Runs ONLY from
# an exact `vX.Y.Z` tag matching the workspace version (the release discipline),
# and is resumable — already-published versions are skipped, so a rerun after a
# crates.io rate-limit stall picks up where it left off. Authenticate first: run
# `cargo login` locally, or set CARGO_REGISTRY_TOKEN (how the release CI job runs it).
publish:
    #!/usr/bin/env bash
    set -euo pipefail
    tag="$(git describe --exact-match --tags 2>/dev/null || true)"
    if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "refusing to publish: HEAD is not on a vX.Y.Z tag (got '${tag:-none}')." >&2
      echo "tag the release first, e.g.: git tag -a vX.Y.Z -m 'boatramp X.Y.Z' && git checkout vX.Y.Z" >&2
      exit 1
    fi
    ver="${tag#v}"
    wsver="$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)"
    if [[ "$ver" != "$wsver" ]]; then
      echo "refusing to publish: tag $tag does not match the workspace version $wsver." >&2
      exit 1
    fi
    ua="boatramp-publish (info@giacomocariello.com)"
    for c in {{ crate_order }}; do
      code="$(curl -s -A "$ua" -o /dev/null -w '%{http_code}' "https://crates.io/api/v1/crates/$c/$ver" || echo 000)"
      if [[ "$code" == "200" ]]; then
        echo "== skip $c@$ver (already on crates.io) =="
        continue
      fi
      echo "== publish $c@$ver =="
      cargo publish -p "$c"
    done
    echo "published all workspace crates at $ver"
