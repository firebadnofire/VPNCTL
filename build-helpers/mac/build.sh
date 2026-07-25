#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
node_version_required="24.18.0"
node_version_required_with_prefix="v${node_version_required}"
pnpm_version_required="11.9.0"

load_nvm() {
  if command -v nvm >/dev/null 2>&1; then
    return
  fi

  local nvm_script=""
  if [[ -n "${NVM_DIR:-}" && -s "${NVM_DIR}/nvm.sh" ]]; then
    nvm_script="${NVM_DIR}/nvm.sh"
  elif [[ -s "${HOME}/.nvm/nvm.sh" ]]; then
    export NVM_DIR="${HOME}/.nvm"
    nvm_script="${NVM_DIR}/nvm.sh"
  elif command -v brew >/dev/null 2>&1; then
    local brew_nvm_prefix
    brew_nvm_prefix="$(brew --prefix nvm 2>/dev/null || true)"
    if [[ -n "${brew_nvm_prefix}" && -s "${brew_nvm_prefix}/nvm.sh" ]]; then
      export NVM_DIR="${NVM_DIR:-${HOME}/.nvm}"
      nvm_script="${brew_nvm_prefix}/nvm.sh"
    fi
  fi

  if [[ -z "${nvm_script}" ]]; then
    echo "error: Node ${node_version_required_with_prefix} is required and nvm was not found." >&2
    echo "Install nvm, then rerun this helper. Common install paths checked: \${NVM_DIR}/nvm.sh, ${HOME}/.nvm/nvm.sh, and Homebrew nvm." >&2
    exit 1
  fi

  # shellcheck source=/dev/null
  . "${nvm_script}"

  if ! command -v nvm >/dev/null 2>&1; then
    echo "error: nvm was loaded from ${nvm_script}, but the nvm command is still unavailable." >&2
    exit 1
  fi
}

ensure_node_version() {
  if command -v node >/dev/null 2>&1 && [[ "$(node --version)" == "${node_version_required_with_prefix}" ]]; then
    return
  fi

  load_nvm
  if ! nvm ls "${node_version_required}" >/dev/null 2>&1; then
    nvm install "${node_version_required}"
  fi
  nvm use "${node_version_required}"
}

ensure_pnpm_version() {
  if command -v pnpm >/dev/null 2>&1 && [[ "$(pnpm --version)" == "${pnpm_version_required}" ]]; then
    return
  fi

  if ! command -v corepack >/dev/null 2>&1; then
    echo "error: corepack is required to activate pnpm ${pnpm_version_required}." >&2
    exit 1
  fi

  corepack enable pnpm
  corepack install --global "pnpm@${pnpm_version_required}"
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the macOS helper must run on macOS" >&2
  exit 1
fi

ensure_node_version
ensure_pnpm_version

for command in cargo node pnpm rustc; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: required command not found: ${command}" >&2
    exit 1
  fi
done

if [[ "$(node --version)" != "${node_version_required_with_prefix}" ]]; then
  echo "error: Node ${node_version_required_with_prefix} is required; found $(node --version)" >&2
  exit 1
fi

if [[ "$(pnpm --version)" != "${pnpm_version_required}" ]]; then
  echo "error: pnpm ${pnpm_version_required} is required; found $(pnpm --version)" >&2
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
