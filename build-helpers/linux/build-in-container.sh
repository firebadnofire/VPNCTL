#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ "$(node --version)" != "v24.18.0" ]]; then
  echo "error: container Node version drifted: $(node --version)" >&2
  exit 1
fi

if [[ "$(pnpm --version)" != "11.9.0" ]]; then
  echo "error: container pnpm version drifted: $(pnpm --version)" >&2
  exit 1
fi

if [[ "$(rustc --version | awk '{print $2}')" != "1.97.1" ]]; then
  echo "error: container Rust version drifted: $(rustc --version)" >&2
  exit 1
fi

mkdir -p "${HOME}" "${CARGO_HOME}"
export CI=true
pnpm install --frozen-lockfile

if [[ "${VAM_SKIP_CHECKS:-0}" != "1" ]]; then
  pnpm verify
fi

pnpm --dir apps/desktop tauri build --bundles deb,appimage --ci
