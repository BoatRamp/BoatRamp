# A slim boatramp image for the Kubernetes operator e2e (scripts/e2e-k8s.sh). The
# operator role only needs operator + cluster + tls, so build with
# `--no-default-features`: the shipped default is now batteries-included (all cloud
# SDKs / signers / wasmtime / bundler), whose LTO link is far heavier and OOM-kills
# the in-container build here for no e2e benefit.
FROM rust:1-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      cmake nasm pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p boatramp --no-default-features --features operator,cluster,tls \
    && cp target/release/boatramp /boatramp

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /boatramp /usr/local/bin/boatramp
ENTRYPOINT ["boatramp"]
