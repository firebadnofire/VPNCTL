#!/usr/bin/env bash
set -euo pipefail
umask 022
architecture="$(uname -m)"
case "$architecture" in x86_64|aarch64) ;; *) echo 'Unsupported helper architecture' >&2; exit 1;; esac
target="${architecture}-unknown-linux-musl"
# musl and vendored OpenSSL avoid depending on the server's libc/OpenSSL ABI.
export CARGO_TARGET_DIR="/workspace/target/helper-build/${architecture}"
export CARGO_HOME="/workspace/target/helper-cargo/${architecture}"
export RUSTUP_TOOLCHAIN=1.97.1
export CC=musl-gcc
export OPENSSL_STATIC=1
if [[ -n "${VAM_RELEASE_TAG:-}" ]]; then
  node /workspace/build-helpers/release/version.mjs "$VAM_RELEASE_TAG"
  cargo update --workspace
fi
cargo build --locked --release -p vam-server --features bundled-helper --target "$target"
binary="${CARGO_TARGET_DIR}/${target}/release/vam-server"
# Execute in the build container to catch ABI/dependency mistakes before embedding.
reported=$("$binary" self-check)
[ "$reported" = 'vpnctl-helper protocol=2 schema=1 instance_archives_v1 drop_peer_v1 dns_blocking_v1' ]
output="/workspace/target/vam-server-dist/${target}"
mkdir -p "$output"
install -m 0755 "$binary" "$output/vam-server.tmp"
mv -f "$output/vam-server.tmp" "$output/vam-server"
(cd "$output" && sha256sum vam-server > vam-server.sha256.tmp && mv -f vam-server.sha256.tmp vam-server.sha256)
