# Wardstone release image — the image contract pinned in docker/README.md: NO
# entrypoint (compose passes the whole `command: ["wardstone", "ui|api"]`
# list; an ENTRYPOINT here would argv into `wardstone wardstone ui` and
# crash-loop), binary on the container's PATH, non-root user owning
# /var/lib/wardstone/keys. Build from the repo root: docker build -f docker/Dockerfile .
FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# ui/dist is embedded into the ws-web binary at compile time (include_dir);
# it is committed and ships with the source tree.
COPY crates ./crates
COPY ui ./ui
RUN cargo build --release --bin wardstone

FROM debian:bookworm-slim
# curl rides the runtime image for one purpose: the compose healthchecks
# (each process's own /healthz — the ui's over TLS with -k, since the
# setup certificate it first serves is self-signed).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
# Pinned uid/gid 10001 (Task 10, ruling 28d): the relay socket's
# SO_PEERCRED own-uid check and the host-side relay-dir pre-step
# (compose's `install -d -o 10001 -g 10001`) both need the FIXED
# identity — a per-build pick from the system range would make the
# deployment shape nondeterministic.
RUN groupadd -r -g 10001 wardstone \
 && useradd -r -u 10001 -g wardstone -d /var/lib/wardstone -s /usr/sbin/nologin wardstone \
 && mkdir -p /var/lib/wardstone/keys \
 && chown -R wardstone:wardstone /var/lib/wardstone
COPY --from=build /src/target/release/wardstone /usr/local/bin/wardstone
USER wardstone
WORKDIR /var/lib/wardstone
EXPOSE 8443
# Deliberately NO ENTRYPOINT / CMD — the image contract.