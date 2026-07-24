#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the macOS helper must run on macOS" >&2
  exit 1
fi

for command in cargo node pnpm rustc; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: required command not found: ${command}" >&2
    exit 1
  fi
done

if [[ "$(node --version)" != "v24.18.0" ]]; then
  echo "error: Node v24.18.0 is required; found $(node --version)" >&2
  exit 1
fi

if [[ "$(pnpm --version)" != "11.9.0" ]]; then
  echo "error: pnpm 11.9.0 is required; found $(pnpm --version)" >&2
  exit 1
fi

cd "${repo_root}"
export CI=true
pnpm install --frozen-lockfile

if [[ "${VAM_SKIP_CHECKS:-0}" != "1" ]]; then
  pnpm verify
fi

tauri_args=(build --bundles app --ci)
if [[ "${VAM_SIGN:-0}" != "1" ]]; then
  tauri_args+=(--no-sign)
fi

pnpm --dir apps/desktop tauri "${tauri_args[@]}"
echo "macOS bundle: ${repo_root}/target/release/bundle/macos/VPN Appliance Manager.app"
