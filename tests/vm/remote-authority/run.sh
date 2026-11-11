#!/usr/bin/env bash
# Run on the libvirt host. All created resources belong to a unique run name.
set -euo pipefail
umask 077

if [[ $# != 2 ]]; then
  echo "usage: $0 <cloud-init-automation-directory> <linux-vam-server-binary>" >&2
  exit 2
fi
harness="$(realpath -- "$1")"
helper="$(realpath -- "$2")"
suite_source="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
run_name="vpnctl-authority-$(date -u +%Y%m%dT%H%M%S)-${RANDOM}"
suite="$harness/$run_name"
artifacts="${VPNCTL_ARTIFACTS_DIR:-$PWD/vpnctl-acceptance-artifacts}/$run_name"
agent_key="${VPNCTL_AGENT_KEY:-$HOME/.ssh/cgpt/cgpt}"
export CORDS_VM_BASE_DIR="${CORDS_VM_BASE_DIR:-/var/lib/libvirt/ro-images}"
export CORDS_VM_DISK_DIR="/var/lib/libvirt/images/$run_name"
export VM_DISK_ADD=10
started=0
mkdir -p -- "$artifacts"

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ $started == 1 ]]; then
    (cd -- "$harness" && ./copy-log.sh "$run_name") > "$artifacts/extraction.log" 2>&1 || status=1
    if [[ -d "$harness/logs/$run_name" ]]; then cp -a -- "$harness/logs/$run_name/." "$artifacts/"; fi
    if ! (cd -- "$harness" && ./bring-down.sh "$run_name") >> "$artifacts/teardown.log" 2>&1; then
      echo "Teardown failed for $run_name; inspect $artifacts/teardown.log" >&2
      status=1
    fi
  fi
  printf '%s\n' "Artifacts: $artifacts"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

test -x "$helper"
test -f "$agent_key"
test -f "$agent_key.pub"
test -x "$harness/bring-up.sh"
if sudo -n virsh dominfo "$run_name" >/dev/null 2>&1; then
  echo "Refusing to replace existing VM $run_name" >&2
  exit 1
fi
mkdir -- "$suite"
mkdir -- "$suite/include"
cp -- "$helper" "$suite/include/vam-server"
cp -- "$suite_source/include/test.py" "$suite/include/test.py"
python3 - "$suite_source/user-data.template" "$agent_key.pub" "$suite/user-data" <<'PY'
from pathlib import Path
import sys
template, public_key, destination = map(Path, sys.argv[1:])
key = public_key.read_text().strip()
if "\n" in key or not key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
    raise SystemExit("invalid agent public key")
destination.write_text(template.read_text().replace("__AGENT_PUBLIC_KEY__", key))
PY
printf 'instance-id: %s\nlocal-hostname: %s\n' "$run_name" "$run_name" > "$suite/meta-data"
sudo -n install -d -m 0755 -- "$CORDS_VM_DISK_DIR"
started=1
(cd -- "$harness" && ./bring-up.sh --no-console "$run_name") > "$artifacts/bring-up.log" 2>&1

address=""
for attempt in $(seq 1 180); do
  address="$(sudo -n virsh domifaddr "$run_name" --source lease | awk '$3 == "ipv4" {sub(/\/.*/, "", $4); print $4; exit}')"
  if [[ -n "$address" ]]; then break; fi
  sleep 3
done
test -n "$address" || { echo "Guest did not acquire a libvirt-reported address" >&2; exit 1; }

# Obtain host identity through the trusted virtualization control plane, never
# by accepting an unauthenticated SSH scan or disabling host-key validation.
pid=""
for attempt in $(seq 1 180); do
  if reply="$(sudo -n virsh qemu-agent-command "$run_name" '{"execute":"guest-exec","arguments":{"path":"/bin/cat","arg":["/etc/ssh/ssh_host_ed25519_key.pub"],"capture-output":true}}' 2>/dev/null)"; then
    pid="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["return"]["pid"])' <<< "$reply")"
    break
  fi
  sleep 3
done
test -n "$pid" || { echo "Guest agent did not become ready" >&2; exit 1; }
for attempt in $(seq 1 10); do
  reply="$(sudo -n virsh qemu-agent-command "$run_name" "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":$pid}}")"
  if python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["return"].get("exited") else 1)' <<< "$reply"; then break; fi
  sleep 1
done
python3 - "$address" "$artifacts/known_hosts" "$reply" <<'PY'
import base64, json, sys
from pathlib import Path
result = json.loads(sys.argv[3])["return"]
if not result.get("exited") or result.get("exitcode") != 0:
    raise SystemExit("guest host-key retrieval did not finish successfully")
key = base64.b64decode(result["out-data"]).decode().strip().split()
if len(key) < 2 or key[0] != "ssh-ed25519":
    raise SystemExit("unexpected guest host-key format")
Path(sys.argv[2]).write_text(sys.argv[1] + " " + " ".join(key[:2]) + "\n")
PY
ssh_args=(-i "$agent_key" -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$artifacts/known_hosts" -o ConnectTimeout=10)
finished=0
for attempt in $(seq 1 240); do
  if ssh "${ssh_args[@]}" "testuser@$address" 'test -f /var/log/vpnctl-acceptance.exit'; then finished=1; break; fi
  sleep 5
done
test "$finished" = 1 || { echo "Acceptance suite timed out" >&2; exit 1; }
ssh "${ssh_args[@]}" "testuser@$address" 'cat /var/log/vpnctl-acceptance.jsonl' > "$artifacts/results.jsonl"
result="$(ssh "${ssh_args[@]}" "testuser@$address" 'cat /var/log/vpnctl-acceptance.exit')"
test "$result" = 0 || { echo "VPNCTL acceptance failed; inspect $artifacts/results.jsonl" >&2; exit 1; }
if [[ -n "${VPNCTL_CLI:-}" ]]; then
  fingerprint="$(ssh-keygen -lf "$artifacts/known_hosts" -E sha256 | awk '{print $2}')"
  for client in a b; do
    database="$artifacts/client-$client.sqlite"
    "$VPNCTL_CLI" --database "$database" host-add --name "Acceptance server" --hostname "$address" --username testuser --key "$agent_key" > "$artifacts/client-$client-host.json"
    host_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' < "$artifacts/client-$client-host.json")"
    "$VPNCTL_CLI" --database "$database" host-approve "$host_id" --expected-fingerprint "$fingerprint" > "$artifacts/client-$client-trust.json"
    "$VPNCTL_CLI" --database "$database" server "$host_id" list > "$artifacts/client-$client-inventory.json"
  done
  python3 - "$artifacts" <<'PY'
from pathlib import Path
import json, sys
root = Path(sys.argv[1])
a = json.loads((root / "client-a-inventory.json").read_text())
b = json.loads((root / "client-b-inventory.json").read_text())
assert a["identity"]["appliance_id"] == b["identity"]["appliance_id"], "client identity binding differs"
assert len(b["discovery"]["instances"]) >= 1, "fresh CLI client failed to discover the remote instance"
wireguard = next(instance for instance in b["discovery"]["instances"] if instance["configuration"]["instance"]["backend"] == "wireguard")
assert len(wireguard["configuration"]["peers"]) >= 1, "fresh CLI client lost peers"
configuration = wireguard["configuration"]
configuration["instance"]["display_name"] = "Updated by independent CLI client B"
(root / "client-b-edit.json").write_text(json.dumps(configuration))
(root / "client-b-revision").write_text(str(wireguard["revision"]))
PY
  host_b="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' < "$artifacts/client-b-host.json")"
  "$VPNCTL_CLI" --database "$artifacts/client-b.sqlite" server "$host_b" save "$artifacts/client-b-edit.json" --expected-revision "$(cat "$artifacts/client-b-revision")" > "$artifacts/client-b-saved.json"
  saved_revision="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["revision"])' < "$artifacts/client-b-saved.json")"
  instance_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["configuration"]["instance"]["id"])' < "$artifacts/client-b-saved.json")"
  "$VPNCTL_CLI" --database "$artifacts/client-b.sqlite" server "$host_b" preview "$instance_id" --expected-revision "$saved_revision" > "$artifacts/client-b-plan.json"
  plan_hash="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["desired_state_hash"])' < "$artifacts/client-b-plan.json")"
  "$VPNCTL_CLI" --database "$artifacts/client-b.sqlite" server "$host_b" deploy "$instance_id" --expected-revision "$saved_revision" --expected-state-hash "$plan_hash" > "$artifacts/client-b-deployed.json"
  "$VPNCTL_CLI" --database "$artifacts/client-b.sqlite" server "$host_b" clear-cache > "$artifacts/client-b-cache-cleared.json"
  "$VPNCTL_CLI" --database "$artifacts/client-b.sqlite" host-remove "$host_b" > "$artifacts/client-b-profile-removed.json"
  host_a="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' < "$artifacts/client-a-host.json")"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" server "$host_a" list > "$artifacts/client-a-refreshed.json"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" server "$host_a" runtime-history "$instance_id" > "$artifacts/client-a-runtime-history.json"
  python3 - "$artifacts/client-a-refreshed.json" <<'PY'
import json, sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text())
assert any(instance["configuration"]["instance"]["display_name"] == "Updated by independent CLI client B" for instance in state["discovery"]["instances"]), "Client A did not observe Client B's save"
print(json.dumps({"test": "two_native_cli_clients_over_verified_ssh", "success": True}))
PY
  python3 - "$artifacts" <<'PY'
from pathlib import Path
import json, sqlite3, sys, uuid
root = Path(sys.argv[1])
host = json.loads((root / "client-a-host.json").read_text())["id"]
inventory = json.loads((root / "client-a-refreshed.json").read_text())
source = next(item for item in inventory["discovery"]["instances"] if item["configuration"]["instance"]["backend"] == "wireguard")
instance = source["configuration"]["instance"].copy()
instance["id"] = str(uuid.uuid4())
instance["host_id"] = host
instance["display_name"] = "Local legacy migration acceptance"
instance["endpoint"] = {**instance["endpoint"], "port": 59000}
instance["network"] = {**instance["network"], "ipv4_subnet": "10.98.0.0/24", "gateway_ipv4": "10.98.0.1"}
instance["dns"] = {**instance["dns"], "zone": "migration.internal"}
connection = sqlite3.connect(root / "client-a.sqlite")
try:
    connection.execute("INSERT INTO vpn_instances (id, host_id, display_name, backend, endpoint_port, ipv4_subnet, dns_zone, model_json, created_at, updated_at, deleted_at, instance_schema_version, backend_settings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                       (instance["id"], host, instance["display_name"], "wireguard", 59000, "10.98.0.0/24", "migration.internal", json.dumps(instance), instance["created_at"], instance["updated_at"], 2, json.dumps(instance["backend_settings"])))
    connection.execute("INSERT INTO instance_listeners (instance_id, host_id, port, transport, active) VALUES (?, ?, ?, 'udp', 1)", (instance["id"], host, 59000))
    connection.commit()
finally:
    connection.close()
(root / "legacy-instance-id").write_text(instance["id"])
PY
  legacy_id="$(cat "$artifacts/legacy-instance-id")"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" legacy-list > "$artifacts/legacy-before.json"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" legacy-preview "$legacy_id" --host-id "$host_a" > "$artifacts/legacy-preview.json"
  preview_hash="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["expected_preview_hash"])' < "$artifacts/legacy-preview.json")"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" legacy-migrate "$legacy_id" --host-id "$host_a" --expected-preview-hash "$preview_hash" --confirm > "$artifacts/legacy-migrated.json"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" legacy-list > "$artifacts/legacy-after.json"
  "$VPNCTL_CLI" --database "$artifacts/client-a.sqlite" server "$host_a" list > "$artifacts/client-a-after-migration.json"
  python3 - "$artifacts" <<'PY'
from pathlib import Path
import json, sqlite3, sys
root = Path(sys.argv[1])
instance_id = (root / "legacy-instance-id").read_text()
before = json.loads((root / "legacy-before.json").read_text())
after = json.loads((root / "legacy-after.json").read_text())
migrated = json.loads((root / "legacy-migrated.json").read_text())
inventory = json.loads((root / "client-a-after-migration.json").read_text())
assert any(item["instance_id"] == instance_id for item in before), "legacy record was not detected"
assert not any(item["instance_id"] == instance_id for item in after), "completed migration remains eligible"
assert migrated["configuration"]["instance"]["id"] == instance_id, "migration changed instance UUID"
assert any(item["configuration"]["instance"]["id"] == instance_id for item in inventory["discovery"]["instances"]), "server discovery did not verify migration"
with sqlite3.connect(root / "client-a.sqlite") as connection:
    assert connection.execute("SELECT COUNT(*) FROM vpn_instances WHERE id = ?", (instance_id,)).fetchone()[0] == 1, "migration removed local source"
assert (root / "legacy-backups").exists(), "migration did not preserve a local database backup"
print(json.dumps({"test": "real_local_sqlite_migration_preserves_identity_and_source", "success": True}))
PY
fi
cat -- "$artifacts/results.jsonl"
