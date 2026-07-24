#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

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

echo "Removed generated macOS build outputs and dependencies."
