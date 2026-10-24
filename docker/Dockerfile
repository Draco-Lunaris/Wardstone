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
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r wardstone \
 && useradd -r -g wardstone -d /var/lib/wardstone -s /usr/sbin/nologin wardstone \
 && mkdir -p /var/lib/wardstone/keys \
 && chown -R wardstone:wardstone /var/lib/wardstone
COPY --from=build /src/target/release/wardstone /usr/local/bin/wardstone
USER wardstone
WORKDIR /var/lib/wardstone
EXPOSE 8443
# Deliberately NO ENTRYPOINT / CMD — the image contract.