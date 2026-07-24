#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
image_name="${VAM_LINUX_BUILDER_IMAGE:-vpn-appliance-manager-linux-builder:node24.18.0-rust1.97.1}"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: Docker is required for the Linux build helper" >&2
  exit 1
fi

platform_args=()
if [[ -n "${VAM_DOCKER_PLATFORM:-}" ]]; then
  case "${VAM_DOCKER_PLATFORM}" in
    linux/amd64|linux/arm64) ;;
    *)
      echo "error: VAM_DOCKER_PLATFORM must be linux/amd64 or linux/arm64" >&2
      exit 1
      ;;
  esac
  platform_args=(--platform "${VAM_DOCKER_PLATFORM}")
fi

security_args=()
if docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -q 'name=selinux'; then
  security_args=(--security-opt label=disable)
fi

docker build \
  "${platform_args[@]}" \
  --file "${script_dir}/Dockerfile" \
  --tag "${image_name}" \
  "${repo_root}"

docker run --rm \
  "${platform_args[@]}" \
  "${security_args[@]}" \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp/vam-builder \
  --env CARGO_HOME=/workspace/target/.cargo-home \
  --env VAM_SKIP_CHECKS="${VAM_SKIP_CHECKS:-0}" \
  --env SOURCE_DATE_EPOCH="$(git -C "${repo_root}" log -1 --format=%ct 2>/dev/null || printf '0')" \
  --volume "${repo_root}:/workspace" \
  --workdir /workspace \
  "${image_name}"

echo "Linux bundles: ${repo_root}/target/release/bundle"
