#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
image_name="${VAM_LINUX_BUILDER_IMAGE:-vpn-appliance-manager-linux-builder:node24.18.0-rust1.97.1}"

if [[ ! -f "${repo_root}/Cargo.toml" || ! -f "${repo_root}/pnpm-workspace.yaml" ]]; then
  echo "error: refusing to clean an unrecognized repository root" >&2
  exit 1
fi

generated_paths=(
  "${repo_root}/target"
  "${repo_root}/node_modules"
  "${repo_root}/apps/desktop/node_modules"
  "${repo_root}/apps/desktop/dist"
)

for generated_path in "${generated_paths[@]}"; do
  case "${generated_path}" in
    "${repo_root}/"*) rm -rf -- "${generated_path}" ;;
    *)
      echo "error: refusing unsafe clean path: ${generated_path}" >&2
      exit 1
      ;;
  esac
done

if [[ "${VAM_CLEAN_DOCKER_IMAGE:-0}" == "1" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: Docker is required to remove the builder image" >&2
    exit 1
  fi
  docker image rm "${image_name}"
fi

echo "Removed generated Linux build outputs and dependencies."
