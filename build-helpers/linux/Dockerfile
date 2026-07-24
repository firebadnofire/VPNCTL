FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

ARG RUST_TOOLCHAIN=1.97.1
ARG PNPM_VERSION=11.9.0

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        libayatana-appindicator3-dev \
        libssl-dev \
        librsvg2-dev \
        libwebkit2gtk-4.1-dev \
        libxdo-dev \
        patchelf \
        pkg-config \
        wget \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
        https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && rustup component add clippy rustfmt --toolchain "${RUST_TOOLCHAIN}" \
    && chmod -R a+rX "${RUSTUP_HOME}" "${CARGO_HOME}"

RUN corepack enable \
    && corepack prepare "pnpm@${PNPM_VERSION}" --activate \
    && node --version \
    && pnpm --version \
    && rustc --version \
    && cargo --version

WORKDIR /workspace
ENTRYPOINT ["/bin/bash", "/workspace/build-helpers/linux/build-in-container.sh"]
