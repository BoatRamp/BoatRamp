# boatramp — canonical container image.
#
# The Nix-first, reproducible image is `nix build .#container`; this Dockerfile
# is the equivalent for non-Nix users. It builds the single `boatramp` binary
# and runs it on a slim, non-root base.
#
# Default feature set targets Cloudflare Containers: R2 blobs (`s3`) + a
# networked KV for metadata (`cloudflare-kv`). TLS terminates at the edge, so the
# `tls` feature is omitted. Override for other shapes, e.g. the HA/Raft cluster
# image:  docker build --build-arg FEATURES=cluster .
ARG FEATURES=s3,cloudflare-kv

# ---- build -----------------------------------------------------------------
# Pinned to the repo toolchain (rust-toolchain.toml: 1.82) AND by digest, so the
# build is reproducible over time. The `s3` backend pulls aws-lc-rs,
# which needs cmake + clang + a C toolchain at build time.
FROM rust:1.82-slim@sha256:1111c28d995d06a7863ba6cea3b3dcb87bebe65af8ec5517caaf2c8c26f38010 AS build
ARG FEATURES
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev cmake clang \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p boatramp --features "${FEATURES}"

# ---- runtime ---------------------------------------------------------------
# Slim base + CA certificates (the binary reaches R2/Cloudflare over HTTPS).
# Runs as the unprivileged `nobody` user — never root (image hardening).
# Pinned by digest so the runtime image is reproducible; the Nix
# image (`nix build .#container`) remains the canonical reproducible artifact.
FROM debian:stable-slim@sha256:ee12ffb55625b99d62837a72f037d9b2f18fd0c787a89c2b9a4f09666c48776c
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/boatramp /usr/local/bin/boatramp
# Edge terminates TLS; boatramp listens plain on a fixed internal port.
ENV BOATRAMP_ADDR=0.0.0.0:8080
EXPOSE 8080
USER nobody
ENTRYPOINT ["boatramp", "serve"]
