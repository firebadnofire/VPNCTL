#!/usr/bin/env bash
# Exercise source/artifact transfer and failure cleanup using real Docker, without
# compiling Rust or sharing host checkout paths with build containers.
set -euo pipefail
repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
work=$(mktemp -d)
namespace="vpnctl-bundle-test-$$"
cleanup() {
  status=$?; trap - EXIT
  for architecture in x86_64 aarch64; do
    image="${namespace}-builder:${architecture}-rust1.97.1"
    ids=$(docker ps -aq --filter "ancestor=$image")
    if [[ -n "$ids" ]]; then docker rm -f $ids >/dev/null || status=1; fi
    if docker image inspect "$image" >/dev/null 2>&1; then docker image rm "$image" >/dev/null || status=1; fi
    for kind in cargo build; do
      volume="${namespace}-${kind}-${architecture}-rust1.97.1"
      if docker volume inspect "$volume" >/dev/null 2>&1; then docker volume rm "$volume" >/dev/null || status=1; fi
    done
  done
  rm -rf -- "$work" || status=1
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$work/build-helpers/server"
cp "$repository/build-helpers/server/bundle.sh" "$work/build-helpers/server/bundle.sh"
cat > "$work/build-helpers/server/Dockerfile" <<'DOCKER'
FROM node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
WORKDIR /workspace
ENTRYPOINT ["/bin/bash", "/workspace/build-helpers/server/bundle-in-container.sh"]
DOCKER
cat > "$work/build-helpers/server/bundle-in-container.sh" <<'BUILD'
set -euo pipefail
test "$(cat '/workspace/source with spaces.txt')" = 'tracked source'
test ! -e /workspace/.env.local
test ! -e /workspace/untracked.txt
if [[ -f /workspace/fail-build ]]; then exit 17; fi
output="/workspace/target/vam-server-dist/$(uname -m)-unknown-linux-musl"
mkdir -p "$output"
printf 'fixture output\n' > "$output/vam-server"
(cd "$output" && sha256sum vam-server > vam-server.sha256)
BUILD
printf 'tracked source' > "$work/source with spaces.txt"
printf '.env.local\ntarget/\n' > "$work/.gitignore"
git -C "$work" init -q
git -C "$work" add .
printf 'must not transfer\n' > "$work/.env.local"
printf 'must not transfer\n' > "$work/untracked.txt"
export VAM_HELPER_BUILD_NAMESPACE="$namespace"
export VAM_HELPER_ARCHITECTURES="${VAM_TEST_ARCHITECTURES:-x86_64 aarch64}"
bash "$work/build-helpers/server/bundle.sh"
for architecture in $VAM_HELPER_ARCHITECTURES; do
  output="$work/target/vam-server-dist/${architecture}-unknown-linux-musl"
  test "$(cat "$output/vam-server")" = 'fixture output'
  (cd "$output" && sha256sum -c vam-server.sha256)
done
printf 'PASS: source paths with spaces, tracked-only transfer, both artifact paths and checksums.\n'
printf 'fail\n' > "$work/fail-build"
git -C "$work" add fail-build
if bash "$work/build-helpers/server/bundle.sh"; then echo 'Expected build failure was ignored.' >&2; exit 1; fi
for architecture in $VAM_HELPER_ARCHITECTURES; do
  test "$(cat "$work/target/vam-server-dist/${architecture}-unknown-linux-musl/vam-server")" = 'fixture output'
  test -z "$(docker ps -aq --filter "ancestor=${namespace}-builder:${architecture}-rust1.97.1")"
done
printf 'PASS: failed build is surfaced, stopped containers removed, previous artifacts preserved.\n'
