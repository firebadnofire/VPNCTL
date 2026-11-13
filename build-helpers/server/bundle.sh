#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
command -v docker >/dev/null || { echo 'Docker with amd64/arm64 emulation is required. Alternatively supply matching trusted builds through VAM_HELPER_BUNDLE_DIR.' >&2; exit 1; }
security_args=()
if docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -q 'name=selinux'; then
  security_args=(--security-opt label=disable)
fi
for architecture in ${VAM_HELPER_ARCHITECTURES:-x86_64 aarch64}; do
  case "$architecture" in x86_64) entry=amd64:x86_64;; aarch64) entry=arm64:aarch64;; *) echo "Unsupported helper architecture: $architecture" >&2; exit 1;; esac
  platform="${entry%%:*}"
  architecture="${entry#*:}"
  image="vpnctl-helper-builder:${architecture}-rust1.97.1"
  docker build --platform "linux/${platform}" -f "$root/build-helpers/server/Dockerfile" -t "$image" "$root"
  docker run --rm "${security_args[@]}" --cpus "${VAM_HELPER_BUILD_CPUS:-4}" --memory "${VAM_HELPER_BUILD_MEMORY:-6g}" --env CARGO_BUILD_JOBS=4 --platform "linux/${platform}" --user "$(id -u):$(id -g)" \
    --env HOME=/tmp/helper-builder --volume "$root:/workspace" "$image"
done
