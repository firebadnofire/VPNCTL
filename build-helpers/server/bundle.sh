#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
for tool in docker git tar sha256sum; do
  command -v "$tool" >/dev/null || { echo "Missing helper bundle tool: $tool" >&2; exit 1; }
done
namespace="${VAM_HELPER_BUILD_NAMESPACE:-vpnctl-helper}"
[[ "$namespace" =~ ^[a-z0-9][a-z0-9_.-]*$ ]] || { echo 'Invalid VAM_HELPER_BUILD_NAMESPACE.' >&2; exit 1; }
container=""
staging=""
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n "$container" ]]; then
    docker rm -f "$container" >/dev/null || { echo "Failed to remove helper build container: $container" >&2; status=1; }
  fi
  if [[ -n "$staging" ]]; then rm -rf -- "$staging" || status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker info >/dev/null
for architecture in ${VAM_HELPER_ARCHITECTURES:-x86_64 aarch64}; do
  case "$architecture" in x86_64) platform=amd64;; aarch64) platform=arm64;; *) echo "Unsupported helper architecture: $architecture" >&2; exit 1;; esac
  target="${architecture}-unknown-linux-musl"
  image="${namespace}-builder:${architecture}-rust1.97.1"
  docker build --platform "linux/${platform}" -t "$image" - < "$root/build-helpers/server/Dockerfile"
  # Stream source and copy artifacts through the Docker API. A job container's
  # checkout path need not exist on the daemon host. Named volumes retain caches
  # without granting the builder a writable bind mount of the checkout.
  container=$(docker create --cpus "${VAM_HELPER_BUILD_CPUS:-4}" --memory "${VAM_HELPER_BUILD_MEMORY:-6g}" \
    --env CARGO_BUILD_JOBS=4 --env VAM_RELEASE_TAG="${VAM_RELEASE_TAG:-}" --platform "linux/${platform}" \
    --mount "type=volume,source=${namespace}-cargo-${architecture}-rust1.97.1,target=/workspace/target/helper-cargo/${architecture}" \
    --mount "type=volume,source=${namespace}-build-${architecture}-rust1.97.1,target=/workspace/target/helper-build/${architecture}" \
    "$image")
  (cd "$root" && git ls-files -z --cached | COPYFILE_DISABLE=1 tar --no-xattrs --null -T - -cf -) | docker cp - "$container:/workspace"
  docker start --attach "$container"
  build_status=$(docker inspect --format '{{.State.ExitCode}}' "$container")
  if [[ "$build_status" != 0 ]]; then echo "Helper build failed for $target (exit $build_status)." >&2; exit 1; fi
  output="$root/target/vam-server-dist/$target"
  mkdir -p "$output"
  staging=$(mktemp -d "$root/target/vam-server-dist/.${architecture}.XXXXXXXXXX")
  docker cp "$container:/workspace/target/vam-server-dist/$target/." "$staging/"
  (cd "$staging" && sha256sum -c vam-server.sha256)
  install -m 0755 "$staging/vam-server" "$output/vam-server.tmp"
  mv -f "$output/vam-server.tmp" "$output/vam-server"
  install -m 0644 "$staging/vam-server.sha256" "$output/vam-server.sha256.tmp"
  mv -f "$output/vam-server.sha256.tmp" "$output/vam-server.sha256"
  rm -rf -- "$staging"
  staging=""
  docker rm "$container" >/dev/null
  container=""
done
