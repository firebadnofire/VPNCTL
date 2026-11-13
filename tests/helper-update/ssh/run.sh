#!/usr/bin/env bash
# Disposable Linux-only acceptance check. No user SSH keys or servers are used.
set -euo pipefail
umask 077
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
fixture="$root/tests/helper-update/ssh"
[[ "$(uname -s)" = Linux && "$(uname -m)" = x86_64 ]] || { echo 'Run this fixture on an x86_64 Linux Docker host.' >&2; exit 1; }
for tool in cargo docker ssh-keygen; do command -v "$tool" >/dev/null || { echo "Missing test tool: $tool" >&2; exit 1; }; done
payload="$root/target/vam-server-dist/x86_64-unknown-linux-musl"
[[ -f "$payload/vam-server" ]] || { echo 'Build the trusted helper first: VAM_HELPER_ARCHITECTURES=x86_64 bash build-helpers/server/bundle.sh' >&2; exit 1; }
work="$(mktemp -d)"
container=""
cleanup() {
 status=$?; trap - EXIT
 if [[ -n "$container" ]]; then
  docker logs "$container" || status=1
  docker rm -f "$container" >/dev/null || status=1
 fi
 rm -rf -- "$work" || status=1
 exit "$status"
}
trap cleanup EXIT
security_args=()
if docker info --format '{{json .SecurityOptions}}' | grep -q 'name=selinux'; then security_args=(--security-opt label=disable); fi
mkdir "$work/public"
ssh-keygen -q -t ed25519 -N '' -f "$work/authentication-key"
cp "$work/authentication-key.pub" "$work/public/authorized_key"
docker build -t vpnctl-helper-ssh-fixture:rust1.97.1 -f "$fixture/Dockerfile" "$fixture"
container=$(docker run -d --name "vpnctl-helper-ssh-validation-$$" "${security_args[@]}" \
 -p 127.0.0.1::22 --volume "$fixture:/fixture:ro" --volume "$work/public:/keys:ro" \
 --volume "$payload:/payload:ro" vpnctl-helper-ssh-fixture:rust1.97.1)
ready=0
for attempt in $(seq 1 40); do
 if docker exec "$container" test -s /run/sshd.pid; then ready=1; break; fi
 sleep 1
done
[[ "$ready" = 1 ]] || { echo 'Disposable SSH fixture did not become ready.' >&2; exit 1; }
mapping=$(docker port "$container" 22/tcp)
export VPNCTL_TEST_PORT="${mapping##*:}"
# Trust the host key through the Docker control plane, never an SSH scan.
docker exec "$container" cat /etc/ssh/ssh_host_ed25519_key.pub > "$work/host-key.pub"
VPNCTL_TEST_FINGERPRINT=$(ssh-keygen -lf "$work/host-key.pub" -E sha256 | awk '{print $2}')
export VPNCTL_TEST_FINGERPRINT
export VPNCTL_TEST_KEY="$work/authentication-key"
export VPNCTL_TEST_PAYLOAD="$payload/vam-server"
export VPNCTL_DISPOSABLE_SSH_TEST=1
cd "$root"
cargo test --locked -p vam-application --test helper_repair_ssh -- --ignored --nocapture
