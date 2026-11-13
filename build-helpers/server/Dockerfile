# The same immutable multi-platform base and pinned toolchain as desktop Linux builds.
FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
ENV DEBIAN_FRONTEND=noninteractive RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl musl-tools perl pkg-config git \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain 1.97.1 \
    && target="$(uname -m)-unknown-linux-musl" && rustup target add "$target"
WORKDIR /workspace
ENTRYPOINT ["/bin/bash", "/workspace/build-helpers/server/bundle-in-container.sh"]
