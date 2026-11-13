#!/usr/bin/env python3
"""Disposable-guest acceptance. Never prints requests, PSKs, or artifacts."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

HELPER = "/usr/local/libexec/vam-server"
COMPATIBILITY = {"protocol_version": 2, "manifest_schema": 1}
ENV = {**os.environ, "SUDO_UID": "0", "SUDO_GID": "0"}
APPLIANCE = None
REDACTIONS = []


def rpc(operation, *, request_id=None, compatibility=None, expect_error=None):
    request_id = request_id or str(uuid.uuid4())
    prepared = subprocess.run([HELPER, "prepare"], env=ENV, check=True, capture_output=True, text=True)
    assert prepared.stdout.strip() == "exchange_uid=0", "unexpected exchange owner"
    root = Path("/var/lib/vpn-appliance-manager/exchange/0")
    request = {"compatibility": compatibility or COMPATIBILITY, "request_id": request_id,
               "appliance_id": APPLIANCE, "operation": operation}
    path = root / "requests" / (request_id + ".json")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(request, stream)
    try:
        result = subprocess.run([HELPER, "manifest-rpc", request_id], env=ENV, check=True, capture_output=True, text=True)
        assert result.stdout.strip() == "response_ready=" + request_id, "helper stdout leaked or status mismatched"
        response = json.loads((root / "responses" / (request_id + ".json")).read_text())
        assert response["request_id"] == request_id, "response correlation failed"
        if expect_error:
            assert response["result"]["Err"]["code"] == expect_error, "unexpected failure code"
            return None
        if "Err" in response["result"]:
            raise RuntimeError("helper refused operation: " + response["result"]["Err"]["message"])
        reply = response["result"]["Ok"]
        if reply["response"] == "operation_failure":
            detail = reply["value"].get("technical_detail") or ""
            for secret in REDACTIONS:
                detail = detail.replace(secret, "[REDACTED]")
            if "PRIVATE KEY" in detail.upper():
                detail = "Private-material diagnostic redacted."
            raise RuntimeError("runtime operation failed: " + reply["value"]["message"] + "; " + detail[:4096])
        return reply
    finally:
        subprocess.run([HELPER, "cleanup", request_id], env=ENV, check=True, capture_output=True)


def archive_restore_roundtrip(instance_id, backend):
    """Only runs inside the disposable guest; retain every runtime identity."""
    current = rpc({"operation": "read", "instance_id": instance_id})["value"]
    rpc({"operation": "stop_instance", "instance_id": instance_id, "expected_revision": current["revision"]})
    runtime = Path("/opt/vpn-appliance-manager/instances") / instance_id
    def contents(path):
        return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in path.rglob("*") if p.is_file() and p.name != ".vpnctl-archive-restore"}
    before = contents(runtime)
    assert before, "runtime snapshot is empty before archive"
    archive_id = str(uuid.uuid4())
    archive_operation = {"operation": "archive_instance", "confirmed": True, "request": {
        "compatibility": COMPATIBILITY, "appliance_id": APPLIANCE,
        "request_id": archive_id, "expected_revision": current["revision"],
        "configuration": current["configuration"], "secrets": {}}}
    archived = rpc(archive_operation, request_id=archive_id)["value"]
    assert rpc(archive_operation, request_id=archive_id)["value"] == archived, "archive retry changed the receipt"
    inventory = rpc({"operation": "discover"})["value"]
    assert any(m["configuration"]["instance"]["id"] == instance_id for m in inventory["archived_instances"]), "archived instance is missing from backups inventory"
    snapshot = Path("/opt/vpn-appliance-manager/backups") / instance_id / ("archive-" + archive_id)
    assert contents(snapshot) == before and not runtime.exists(), "archive did not retain the stopped runtime tree"
    listed_while_archived = rpc({"operation": "list_backups", "instance_id": instance_id})["value"]
    assert any(b["name"] == snapshot.name for b in listed_while_archived), "archived instance snapshots are not listed"
    restore_id = str(uuid.uuid4())
    restore_operation = {"operation": "restore_archived_instance", "instance_id": instance_id,
                         "expected_revision": archived["revision"], "confirmed": True}
    restored = rpc(restore_operation, request_id=restore_id)["value"]
    assert rpc(restore_operation, request_id=restore_id)["value"] == restored, "restore retry changed the receipt"
    assert restored["configuration"] == current["configuration"], "restore changed saved peers or identities"
    assert contents(runtime) == before and contents(snapshot) == before, "restore changed or consumed runtime identity data"
    assert not rpc({"operation": "health", "instance_id": instance_id})["value"]["gateway_running"], "restore unexpectedly started the gateway"
    listed = rpc({"operation": "list_backups", "instance_id": instance_id})["value"]
    assert any(b["name"] == snapshot.name for b in listed), "archive snapshot disappeared after restore"
    health = rpc({"operation": "start_instance", "instance_id": instance_id, "expected_revision": restored["revision"]})["value"]
    assert health["gateway_running"] and health["backend_ready"], "restored backend could not start"
    emit("archive_restore_retains_" + backend + "_runtime_and_identity")


def blocking_roundtrip(instance_id):
    """Real CoreDNS + systemd checks, confined to this disposable guest."""
    import datetime
    import http.server
    import threading
    import time
    payload = {"body": b"0.0.0.0 ads.vpnctl.example\ntrack.vpnctl.example\n", "status": 200, "requests": 0}
    class SourceHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload["requests"] += 1
            body = payload["body"]
            self.send_response(payload["status"])
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), SourceHandler)
    guest_ip = json.loads(subprocess.run(["ip", "-j", "route", "get", "1.1.1.1"], check=True, capture_output=True, text=True).stdout)[0]["prefsrc"]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def blocking(action, request_id=None):
        return rpc({"operation": "blocking", "instance_id": instance_id, "action": action}, request_id=request_id)["value"]
    runtime = Path("/opt/vpn-appliance-manager/instances") / instance_id
    def lookup(domain):
        result = subprocess.run(["docker", "compose", "--project-directory", str(runtime), "exec", "-T", "gateway", "nslookup", domain, "127.0.0.1"], capture_output=True, text=True)
        return result.stdout
    try:
        original = rpc({"operation": "read", "instance_id": instance_id})["value"]
        deployed = rpc({"operation": "discover"})["value"]["deployments"][instance_id]["deployed_revision"]
        draft = copy.deepcopy(original["configuration"])
        draft["instance"]["display_name"] = "Pending VPN edit retained across blocking updates"
        pending = save(draft, original["revision"])["value"]
        policy = blocking({"action": "read"})["state"]["policy"]
        assert policy["interval_days"] == 7 and policy["schedule_enabled"], "default refresh schedule changed"
        policy.update(enabled=True, sources=[{"id": str(uuid.uuid4()), "name": "Guest HTTP source", "url": "http://" + guest_ip + ":" + str(server.server_port) + "/hosts", "enabled": True}])
        request = str(uuid.uuid4())
        action = {"action": "save", "expected_revision": 0, "policy": policy}
        saved = blocking(action, request)
        if saved["state"]["error"]:
            logs = subprocess.run(["docker", "compose", "--project-directory", str(runtime), "logs", "--no-color", "--tail", "10", "dns"], capture_output=True, text=True)
            print(json.dumps({"diagnostic": "blocking_verification", "file_mode": oct((runtime / "dns/hosts/blocklist.hosts").stat().st_mode & 0o777), "test_domain_answer": lookup("ads.vpnctl.example")[:2048], "dns_log": logs.stdout[-4096:]}), flush=True)
        assert not saved["state"]["error"], "blocking apply failed: " + str(saved["state"]["error"])
        assert saved["scheduler_available"] and saved["state"]["sources"][0]["domain_count"] == 2, "source status missing"
        assert "0.0.0.0" in lookup("ads.vpnctl.example"), "CoreDNS did not block the downloaded domain"
        assert "10.88.0.1" in lookup("gateway.vpn.internal"), "blocking broke private-zone DNS"
        assert blocking(action, request) == saved, "blocking retry changed the receipt"
        assert rpc({"operation": "read", "instance_id": instance_id})["value"]["revision"] == pending["revision"], "blocking advanced VPN desired revision"
        assert rpc({"operation": "discover"})["value"]["deployments"][instance_id]["deployed_revision"] == deployed, "blocking deployed pending VPN changes"
        subprocess.run(["systemctl", "is-enabled", "vpnctl-blocking.timer"], check=True, capture_output=True)
        payload["status"] = 503
        failed = blocking({"action": "refresh", "expected_revision": 1})
        assert failed["state"]["error"] and failed["state"]["sources"][0]["stale"], "failed source was not reported stale"
        assert failed["state"]["applied_version"] == saved["state"]["applied_version"], "failed download discarded working data"
        payload.update(status=200, body=b"0.0.0.0 scheduled.vpnctl.example\n")
        state_path = Path("/var/lib/vpn-appliance-manager/control/instances") / instance_id / "blocking/state.json"
        state = json.loads(state_path.read_text())
        state["last_attempt"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=8)).isoformat()
        state_path.write_text(json.dumps(state))
        subprocess.run(["systemctl", "start", "vpnctl-blocking.service"], check=True, capture_output=True, text=True)
        assert "0.0.0.0" in lookup("scheduled.vpnctl.example"), "server-side due refresh did not update DNS"
        latest = blocking({"action": "read"})
        policy = latest["state"]["policy"]
        policy.update(enabled=False, schedule_enabled=False)
        disabled = blocking({"action": "save", "expected_revision": 1, "policy": policy})
        assert not disabled["state"]["error"], "blocking disable failed"
        assert "scheduled.vpnctl.example" not in (runtime / "dns/hosts/blocklist.hosts").read_text(), "disabled blocking retained source rules"
        requests = payload["requests"]
        subprocess.run(["systemctl", "start", "vpnctl-blocking.service"], check=True, capture_output=True, text=True)
        assert payload["requests"] == requests, "disabled schedule still downloaded sources"
        deadline = time.monotonic() + 75
        while "0.0.0.0" in lookup("scheduled.vpnctl.example") and time.monotonic() < deadline:
            time.sleep(3)
        assert "0.0.0.0" not in lookup("scheduled.vpnctl.example"), "disabled blocking did not clear after DNS cache expiry"
        emit("per_instance_blocking_manual_stale_scheduled_disabled_and_vpn_revision_isolation")
    finally:
        server.shutdown()
        server.server_close()


def emit(name):
    print(json.dumps({"test": name, "success": True}), flush=True)


def save(configuration, revision, secrets=None, request_id=None, expect_error=None):
    request_id = request_id or str(uuid.uuid4())
    request = {"compatibility": COMPATIBILITY, "appliance_id": APPLIANCE,
               "request_id": request_id, "expected_revision": revision,
               "configuration": configuration, "secrets": secrets or {}}
    return rpc({"operation": "save", "request": request}, request_id=request_id, expect_error=expect_error)


def run():
    global APPLIANCE
    rpc({"operation": "info"}, compatibility={"protocol_version": 1, "manifest_schema": 1}, expect_error="incompatible")
    assert not Path("/var/lib/vpn-appliance-manager/control").exists(), "unsupported client mutated control state"
    emit("compatibility_refuses_writes_before_initialization")
    info = rpc({"operation": "info"})
    APPLIANCE = info["value"]["appliance_id"]
    assert rpc({"operation": "discover"})["value"]["instances"] == [], "fresh host is not empty"
    emit("fresh_host_discovery")

    instance_id = str(uuid.uuid4())
    peer_id = str(uuid.uuid4())
    secret_id = str(uuid.uuid4())
    private = subprocess.run(["wg", "genkey"], check=True, capture_output=True).stdout.strip()
    public = subprocess.run(["wg", "pubkey"], input=private + b"\n", check=True, capture_output=True).stdout.decode().strip()
    psk = subprocess.run(["wg", "genpsk"], check=True, capture_output=True).stdout.strip()
    REDACTIONS.extend([private.decode(), psk.decode()])
    timestamp = "2026-11-10T12:00:00Z"
    configuration = {
        "instance": {"id": instance_id, "host_id": APPLIANCE, "display_name": "Acceptance WG",
                     "backend": "wireguard", "backend_settings": {"backend": "wireguard", "settings": {"userspace_fallback": False}},
                     "endpoint": {"host": "vpn.test.invalid", "port": 51820},
                     "network": {"ipv4_subnet": "10.88.0.0/24", "gateway_ipv4": "10.88.0.1", "ipv6_subnet": None, "gateway_ipv6": None},
                     "dns": {"zone": "vpn.internal", "soa_serial": 2026111000}, "routing_mode": "split_tunnel",
                     "persistent_keepalive": 25, "created_at": timestamp, "updated_at": timestamp, "deleted_at": None},
        "users": [], "peers": [{"id": peer_id, "user_id": None, "display_name": "Phone", "ipv4_address": "10.88.0.2",
                                 "ipv6_address": None, "dns_name": None, "enabled": True, "created_at": timestamp,
                                 "identity": {"backend": "wireguard", "public_key": public, "preshared_key": secret_id}}],
        "dns_records": [], "dns_blocklist_domains": [],
    }
    save(configuration, 0, expect_error="internal")
    assert not rpc({"operation": "discover"})["value"]["instances"], "manifest committed without its PSK"
    emit("secrets_precede_manifest_commit")
    mutation_id = str(uuid.uuid4())
    secrets = {secret_id: base64.b64encode(psk).decode()}
    first = save(configuration, 0, secrets, mutation_id)
    assert first["value"]["revision"] == 1, "first revision is incorrect"
    assert save(configuration, 0, secrets, mutation_id) == first, "retry duplicated or changed a commit"
    inventory = rpc({"operation": "discover"})["value"]
    encoded = json.dumps(inventory)
    assert private.decode() not in encoded and psk.decode() not in encoded, "discovery exposed secret material"
    assert "private_key_ref" not in encoded, "local credential references leaked into remote metadata"
    assert inventory["instances"][0]["configuration"]["peers"][0]["id"] == peer_id, "peer discovery lost identity"
    emit("independent_exchange_discovery_and_idempotent_retry")
    stale = copy.deepcopy(configuration)
    configuration["instance"]["display_name"] = "Edited by Client B"
    save(configuration, 1)
    save(stale, 1, expect_error="revision_conflict")
    emit("optimistic_concurrency")
    exported = rpc({"operation": "export_peer_psk", "instance_id": instance_id, "peer_id": peer_id, "expected_revision": 2})
    assert base64.b64decode(exported["value"]["value"]) == psk, "scoped export changed PSK"
    emit("explicit_peer_scoped_psk_export")
    root = Path("/var/lib/vpn-appliance-manager/control/instances") / instance_id
    assert (root / "secrets" / secret_id).stat().st_mode & 0o777 == 0o600, "unsafe PSK permissions"
    backup = rpc({"operation": "backup_control", "confirmed": True})["value"]["backup_id"]
    recovery = Path("/var/lib/vpn-appliance-manager/recovery") / backup / "instances" / instance_id
    assert (recovery / "secrets" / secret_id).read_bytes() == psk, "disaster backup lost PSK"
    assert (recovery / "generations/1.json").exists(), "disaster backup lost history"
    emit("protected_control_disaster_backup")

    if os.environ.get("VPNCTL_TEST_DEPLOY", "1") == "1":
        plan = rpc({"operation": "preview_deployment", "instance_id": instance_id, "expected_revision": 2})["value"]
        assert psk.decode() not in json.dumps(plan), "deployment preview exposed PSK"
        deploy_request = str(uuid.uuid4())
        result = rpc({"operation": "apply_deployment", "instance_id": instance_id, "expected_revision": 2,
                      "expected_state_hash": plan["desired_state_hash"]}, request_id=deploy_request)
        assert result["response"] == "deployment_result" and result["value"]["status"] == "succeeded", "deployment did not succeed"
        assert rpc({"operation": "reconcile_runtime", "instance_id": instance_id,
                    "mutation_id": deploy_request})["value"] == "committed", "deployment response was not reconciled"
        assert rpc({"operation": "reconcile_runtime", "instance_id": instance_id,
                    "mutation_id": str(uuid.uuid4())})["value"] == "uncommitted", "unknown operation was not classified"
        configuration["instance"]["display_name"] = "Saved but not deployed"
        save(configuration, 2)
        observed = rpc({"operation": "discover"})["value"]
        assert observed["instances"][0]["revision"] == 3, "desired revision did not advance"
        assert observed["deployments"][instance_id]["deployed_revision"] == 2, "saving incorrectly marked state deployed"
        emit("real_wireguard_deployment_and_pending_revision")
        backup = rpc({"operation": "backup_deployment", "instance_id": instance_id, "expected_revision": 3})["value"]["name"]
        second_private = subprocess.run(["wg", "genkey"], check=True, capture_output=True).stdout.strip()
        REDACTIONS.append(second_private.decode())
        second_public = subprocess.run(["wg", "pubkey"], input=second_private + b"\n", check=True, capture_output=True).stdout.decode().strip()
        second_peer = copy.deepcopy(configuration["peers"][0])
        second_peer.update(id=str(uuid.uuid4()), display_name="Second phone", ipv4_address="10.88.0.3")
        second_peer["identity"] = {"backend": "wireguard", "public_key": second_public, "preshared_key": None}
        configuration["peers"].append(second_peer)
        save(configuration, 3)
        plan = rpc({"operation": "preview_deployment", "instance_id": instance_id, "expected_revision": 4})["value"]
        rpc({"operation": "apply_deployment", "instance_id": instance_id, "expected_revision": 4, "expected_state_hash": plan["desired_state_hash"]})
        configuration["instance"]["display_name"] = "New desired state survives rollback"
        save(configuration, 4)
        preview = rpc({"operation": "preview_restore", "instance_id": instance_id, "expected_revision": 5, "backup_name": backup})["value"]
        rpc({"operation": "restore_deployment", "instance_id": instance_id, "expected_revision": 5, "backup_name": backup,
             "expected_state_hash": preview["expected_state_hash"], "confirmed": True})
        observed = rpc({"operation": "discover"})["value"]
        assert observed["instances"][0]["revision"] == 5, "rollback rewound desired revision"
        assert len(observed["instances"][0]["configuration"]["peers"]) == 2, "rollback discarded newer desired peers"
        assert observed["deployments"][instance_id]["deployed_revision"] == 2, "rollback lost deployed revision tracking"
        assert rpc({"operation": "health", "instance_id": instance_id})["value"]["client_state_matches"], "rollback health was checked against newer desired peers"
        emit("deployment_rollback_preserves_newer_desired_revision_and_peers")
        recovery_id = rpc({"operation": "backup_control", "confirmed": True})["value"]["backup_id"]
        recovery = Path("/var/lib/vpn-appliance-manager/recovery") / recovery_id
        assert (recovery / "deployment-trees" / instance_id / "vpn/server.key").exists(), "complete recovery bundle lost server identity"
        assert (recovery / "deployment-backups" / instance_id / backup / "vpn/server.key").exists(), "complete recovery bundle lost retained runtime backups"
        emit("complete_disaster_recovery_bundle")
        backends = [
            ("amnezia_wg", 55424, {"generation": "awg2", "jc": 5, "jmin": 10, "jmax": 50,
                                  "s1": 64, "s2": 96, "s3": 32, "s4": 8,
                                  "h1": {"min": 5, "max": 999}, "h2": {"min": 1000, "max": 1999},
                                  "h3": {"min": 2000, "max": 2999}, "h4": {"min": 3000, "max": 3999}}),
            ("openvpn", 1194, {"transport": "udp", "cipher": "aes256-gcm", "tls_protection": "tls_crypt", "certificate_lifetime_days": 825}),
            ("ikev2", 500, {"server_identity": "vpn.test.invalid", "certificate_lifetime_days": 825}),
        ]
        for offset, (kind, port, settings) in enumerate(backends, start=89):
            candidate = copy.deepcopy(configuration)
            candidate_id = str(uuid.uuid4())
            candidate["instance"].update(id=candidate_id, display_name="Acceptance " + kind, backend=kind,
                                         backend_settings={"backend": kind, "settings": settings})
            candidate["instance"]["endpoint"]["port"] = port
            candidate["instance"]["network"].update(ipv4_subnet="10." + str(offset) + ".0.0/24", gateway_ipv4="10." + str(offset) + ".0.1")
            candidate["peers"] = []
            save(candidate, 0)
            plan = rpc({"operation": "preview_deployment", "instance_id": candidate_id, "expected_revision": 1})["value"]
            rpc({"operation": "apply_deployment", "instance_id": candidate_id, "expected_revision": 1, "expected_state_hash": plan["desired_state_hash"]})
            health = rpc({"operation": "health", "instance_id": candidate_id})["value"]
            assert health["gateway_running"] and health["backend_ready"], "backend deployment health failed: " + kind
            emit("real_" + kind + "_deployment")
            if kind in ("openvpn", "ikev2"):
                certificate_peer = str(uuid.uuid4())
                identity = "client-" + certificate_peer.replace("-", "")[:12]
                curve = "prime256v1" if kind == "openvpn" else "secp384r1"
                digest = "-sha256" if kind == "openvpn" else "-sha384"
                with tempfile.TemporaryDirectory(prefix="vpnctl-client-") as client_dir:
                    key_file = Path(client_dir) / "client.key"
                    csr_file = Path(client_dir) / "client.csr"
                    subprocess.run(["openssl", "ecparam", "-name", curve, "-genkey", "-noout", "-out", str(key_file)], check=True, capture_output=True)
                    subprocess.run(["openssl", "req", "-new", "-key", str(key_file), digest, "-subj", "/CN=" + identity, "-out", str(csr_file)], check=True, capture_output=True)
                    csr = csr_file.read_text()
                    client_private = key_file.read_text()
                    peer = {"id": certificate_peer, "user_id": None, "display_name": "Certificate client",
                            "ipv4_address": "10." + str(offset) + ".0.2", "ipv6_address": None,
                            "dns_name": None, "enabled": True, "created_at": timestamp,
                            "identity": {"backend": kind, "certificate_serial": None,
                                         ("common_name" if kind == "openvpn" else "identity"): identity}}
                    enrolled = rpc({"operation": "enroll_peer", "instance_id": candidate_id,
                                    "expected_revision": 1, "peer": peer, "csr": csr, "create_dns_record": False})
                    assert enrolled["response"] == "enrollment" and enrolled["value"]["manifest"]["revision"] == 2
                    material = enrolled["value"]["material"]
                    cert = base64.b64decode(material["certificate"])
                    ca = base64.b64decode(material["ca_certificate"])
                    (Path(client_dir) / "client.crt").write_bytes(cert)
                    (Path(client_dir) / "ca.crt").write_bytes(ca)
                    subprocess.run(["openssl", "verify", "-CAfile", str(Path(client_dir) / "ca.crt"), str(Path(client_dir) / "client.crt")], check=True, capture_output=True)
                    discovered = json.dumps(rpc({"operation": "discover"})["value"])
                    assert client_private not in discovered and csr not in discovered and cert.decode() not in discovered, "routine discovery exposed certificate credentials"
                    fetched = rpc({"operation": "export_certificate_material", "instance_id": candidate_id,
                                   "peer_id": certificate_peer, "expected_revision": 2})
                    assert base64.b64decode(fetched["value"]["certificate"]) == cert, "scoped certificate export changed material"
                    revoked = rpc({"operation": "revoke_peer", "instance_id": candidate_id,
                                   "peer_id": certificate_peer, "expected_revision": 2, "confirmed": True})
                    assert revoked["value"]["revision"] == 3 and not revoked["value"]["configuration"]["peers"][0]["enabled"]
                    rpc({"operation": "export_certificate_material", "instance_id": candidate_id,
                         "peer_id": certificate_peer, "expected_revision": 3}, expect_error="invalid_request")
                dropped_peer = copy.deepcopy(peer)
                dropped_peer["id"] = str(uuid.uuid4())
                dropped_peer["display_name"] = "Drop certificate target"
                dropped_peer["ipv4_address"] = "10." + str(offset) + ".0.3"
                dropped_peer["dns_name"] = "drop.vpn.internal"
                new_identity = "drop-" + dropped_peer["id"].replace("-", "")[:12]
                dropped_peer["identity"][("common_name" if kind == "openvpn" else "identity")] = new_identity
                with tempfile.TemporaryDirectory(prefix="vpnctl-drop-client-") as client_dir:
                    key_file = Path(client_dir) / "client.key"
                    csr_file = Path(client_dir) / "client.csr"
                    subprocess.run(["openssl", "ecparam", "-name", curve, "-genkey", "-noout", "-out", str(key_file)], check=True, capture_output=True)
                    subprocess.run(["openssl", "req", "-new", "-key", str(key_file), digest, "-subj", "/CN=" + new_identity, "-out", str(csr_file)], check=True, capture_output=True)
                    rpc({"operation": "enroll_peer", "instance_id": candidate_id, "expected_revision": 3, "peer": dropped_peer, "csr": csr_file.read_text(), "create_dns_record": True})
                    operation = {"operation": "drop_peer", "instance_id": candidate_id, "peer_id": dropped_peer["id"], "expected_revision": 4, "revoke_request_id": str(uuid.uuid4()), "confirmed": True}
                    request = str(uuid.uuid4())
                    removed = rpc(operation, request_id=request)
                    assert removed["value"]["revision"] == 6, "certificate drop skipped revocation revision"
                    assert rpc(operation, request_id=request) == removed, "certificate drop retry changed history"
                    assert len(removed["value"]["configuration"]["peers"]) == 1, "certificate drop removed an unrelated device"
                    assert not removed["value"]["configuration"]["dns_records"], "certificate drop retained linked DNS"
                emit("scoped_" + kind + "_certificate_enrollment_export_and_revocation")
                emit("revoke_then_drop_" + kind + "_device")
            archive_restore_roundtrip(candidate_id, kind)
        runtime_history = rpc({"operation": "runtime_history", "instance_id": instance_id})["value"]
        assert any(item["operation"] == "deploy" and item["succeeded"] for item in runtime_history), "fresh client cannot inspect deployment results"
        assert private.decode() not in json.dumps(runtime_history) and psk.decode() not in json.dumps(runtime_history), "runtime history exposed secret material"
        emit("redacted_remote_runtime_history")
        pending = root / "runtime/pending.json"
        unresolved_request = str(uuid.uuid4())
        pending.write_text(json.dumps(unresolved_request))
        pending.chmod(0o600)
        try:
            assert rpc({"operation": "reconcile_runtime", "instance_id": instance_id,
                        "mutation_id": unresolved_request})["value"] == "unresolved", "interrupted operation was misclassified"
            assert pending.exists(), "unresolved operation was silently cleared"
        finally:
            pending.unlink()
        emit("runtime_request_reconciliation_reports_all_three_outcomes")
        blocking_roundtrip(instance_id)
        current = rpc({"operation": "read", "instance_id": instance_id})["value"]
        target = current["configuration"]["peers"][0]["id"]
        drop_id = str(uuid.uuid4())
        drop = {"operation": "drop_peer", "instance_id": instance_id, "peer_id": target, "expected_revision": current["revision"], "revoke_request_id": str(uuid.uuid4()), "confirmed": True}
        dropped = rpc(drop, request_id=drop_id)
        assert not any(peer["id"] == target for peer in dropped["value"]["configuration"]["peers"]), "drop retained selected device"
        assert rpc(drop, request_id=drop_id) == dropped, "drop retry changed the result"
        assert (root / "secrets" / secret_id).exists(), "drop erased recovery secret material"
        emit("drop_device_preserves_history_secrets_and_is_retryable")
        archive_restore_roundtrip(instance_id, "wireguard")
    print(json.dumps({"suite": "remote-authority", "success": True}), flush=True)


if __name__ == "__main__":
    try:
        run()
    except Exception as failure:
        print(json.dumps({"suite": "remote-authority", "success": False, "error": str(failure)}), flush=True)
        sys.exit(1)
