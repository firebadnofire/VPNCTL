# Disposable VM acceptance

The reproducible remote-authority suite is in `tests/vm/remote-authority`. Run it on `william@live.archuser.org` with `/home/william/codex-cloud-init-automation`, following that harness's `AGENTS.md`. It uses the pinned Debian 13 base image and the host's Rust 1.97.1 toolchain. Preflight Docker/libvirt access, the base image checksum, libvirt network, memory, storage, pinned helper/CLI binaries and required harness environment variables before starting.

The runner creates a uniquely named disposable guest, injects only the orchestration host's SSH public key, discovers its address through libvirt and reads its SSH host public key through the trusted guest agent. Product authentication then uses strict host-key checking. Private SSH keys stay on the orchestration host. The runner collects structured results and redacted harness logs, then removes only its own guest and disks.

From the synced source directory on the libvirt host:

```sh
PATH=/home/william/.cargo/bin:$PATH cargo build -p vam-server -p vam-dev
VPNCTL_CLI="$PWD/target/debug/vam-dev" \
VPNCTL_ARTIFACTS_DIR=/home/william/vpnctl-acceptance-artifacts \
bash tests/vm/remote-authority/run.sh \
  /home/william/codex-cloud-init-automation target/debug/vam-server
```

The guest checks empty discovery, protocol refusal before control initialization, secret-before-manifest commit, idempotent retry, stale revision conflict, scoped PSK export, control disaster backup, actual deployment of all four supported backends, desired-versus-deployed revision, rollback preserving newer desired peers, OpenVPN/IKEv2 certificate enrollment and scoped export/revocation, redacted runtime history, and all three runtime request-reconciliation outcomes. The orchestration host then uses two independent CLI databases over verified SSH to check cross-client discovery, a save/deploy from Client B, Client A refresh, cache deletion and local profile removal. It also seeds a local legacy SQLite instance, previews and confirms migration, verifies remote discovery, and confirms that the original local record and backup remain.

Local gates are `make verify` and the platform desktop packaging workflows. Report macOS, Linux and Windows build results separately; a cross-platform build should never be inferred from a web-only build. Keep VM artifacts redacted and inspect failures before starting another implementation unit.

The suite also checks `drop_peer_v1` and `dns_blocking_v1` behavior: active
OpenVPN/IKEv2 certificate revocation followed by scoped metadata/DNS removal,
repeat-safe device drops, retained recovery secrets, per-instance HTTP hostlists,
actual blocked and private DNS answers, stale-source fallback, and independence
from pending VPN revisions. A guest-local HTTP fixture serves only controlled
test domains. Scheduled refresh is exercised through the installed, hardened
`vpnctl-blocking.service` with an overdue test timestamp; disabling the schedule
must prevent further downloads. Disabling blocking must remove source rules and
stop blocked answers after cache expiry. All changes are confined to the test
appliance and are removed with its guest/disk cleanup.

Local unit tests cover interrupted policy/receipt publication, dataset sharding,
source limits and malformed downloads, unsafe addresses and redirects, private
LAN source support, file rollback, cross-instance isolation, and refusal of runtime
backups that could undo certificate revocation after device metadata removal.
