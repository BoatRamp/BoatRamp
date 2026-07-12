# A slim boatramp image for the Kubernetes operator e2e (scripts/e2e-k8s.sh).
# Builds the one binary with the operator + cluster + tls features; the operator
# and the server are the same binary.
FROM rust:1-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      cmake nasm pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p boatramp --features operator,cluster,tls \
    && cp target/release/boatramp /boatramp

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /boatramp /usr/local/bin/boatramp
ENTRYPOINT ["boatramp"]
