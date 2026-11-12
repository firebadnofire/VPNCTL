# VPNCTL

VPNCTL manages WireGuard, AmneziaWG, OpenVPN, and IKEv2 appliances on Linux Docker hosts. The Tauri desktop and `vam-dev` CLI use verified SSH to call an on-demand `vam-server` helper. Each appliance owns its saved configuration in versioned JSON manifests. Saving a revision does not deploy it.

The repository retains its historical `dnswg` name. VPNCTL is released under the [MIT License](LICENSE).

## Status and requirements

- Version `0.1.0`; Rust 1.97.1, Node 24.18.0, pnpm 11.9.0.
- Desktop targets: Linux, macOS, and Windows. The helper runs on a compatible Linux host with Docker Engine and Compose v2.
- The remote helper must be installed at `/usr/local/libexec/vam-server` before remote management. Host readiness inspection and the existing explicit package setup workflow remain separate from VPN instance changes.
- Xray is retired from normal creation and management. Existing local Xray records remain available for recovery export; VPNCTL does not mutate their deployments.

## Ownership and safety

The helper stores authoritative public configuration in `/var/lib/vpn-appliance-manager/control/instances/<uuid>`. Immutable generations are selected by an atomically replaced `current.json` pointer. A filesystem lock serializes mutations across helper processes. Clients send expected revisions and request IDs so stale edits fail and lost responses can be reconciled. Only the helper writes authoritative manifests. SFTP transfers bounded protected request and response files.

WireGuard and AmneziaWG peer private keys stay in each client's native credential store. Their server-required PSKs are protected on the appliance and are absent from routine discovery. A complete client export requests only that peer's PSK after the client proves it has the local private key. OpenVPN and IKEv2 client private keys stay local; only public CSRs cross SSH for server signing. The helper retains certificate authorities, issued certificates, CRLs, and server identities. Certificate export explicitly retrieves the selected peer's public certificate and required server material. Routine discovery, previews, plans, and errors are redacted.

The remote appliance UUID is independent of local SSH connection profiles. VPNCTL still verifies the SSH host key before authentication, and detects duplicate appliance identities on cloned hosts. Clients and helper negotiate protocol 2 and manifest schema 1 before authoritative state is opened. Unsupported versions refuse writes.

SQLite on the client stores connection profiles, local credential bindings, drafts, caches, preferences, and legacy migration bookkeeping. A cached view is labeled with its last successful synchronization time and cannot be saved or deployed while offline. Deleting a local connection or cache does not remove remote instances.

Local host removal preserves VPN configurations and original native credential
references separately from active profiles, allowing verified reconnection.
It never deletes SSH key files or exported client configurations and is not
secure erasure. See [host removal implementation status](docs/host-removal.md)
for recovery guarantees and the ownership constraints blocking full drop and
remote Factory Reset. The desktop **Danger Zone** page contains local host
removal, local Factory Reset, instance archiving, and certificate revocation.

## Workflow

1. Add a server connection and verify its SSH host-key fingerprint through an independent trusted channel.
2. Inspect OS, Docker, and Compose readiness. Install the matching helper through the host's trusted administration process.
3. Discover or create an instance under the selected server. Manage peers, DNS, routing, and settings there.
4. Keep unsaved edits as a local draft. **Save to Server** advances desired revision only.
5. **Preview / Deploy** binds the saved revision and observed deployed state. Deployment stages, validates, backs up, activates, and checks health through the helper.
6. Restore a deployment from a remote backup without rewinding saved desired history. **Restore Desired Configuration** creates a new desired revision and requires a separate deployment.
7. Archived instances remain in **Backups → Archived instances**. Restore brings
   back their saved configuration and runtime identities without starting them;
   choose Start or Preview / Deploy afterward. Archive snapshots are retained.

Remote runtime trees are under `/opt/vpn-appliance-manager/instances/<uuid>`. The control directory is outside activation and rollback. Disaster recovery bundles include the control store, active runtime trees, and retained deployment backups. Certificate and server-key restoration is checked against newer saved configuration before it runs.

## CLI

```sh
make cli
target/debug/vam-dev host-add --name lab --hostname 192.0.2.10 --username admin --key "$HOME/.ssh/id_ed25519"
target/debug/vam-dev host-probe <host-uuid>
target/debug/vam-dev host-approve <host-uuid> --expected-fingerprint 'SHA256:verified-value'
target/debug/vam-dev server <host-uuid> list
target/debug/vam-dev server <host-uuid> create --name home --endpoint vpn.example.com --backend wireguard
target/debug/vam-dev server <host-uuid> inspect <instance-uuid>
target/debug/vam-dev server <host-uuid> peer-add <instance-uuid> --name laptop --expected-revision 1
target/debug/vam-dev server <host-uuid> preview <instance-uuid> --expected-revision 2
target/debug/vam-dev server <host-uuid> deploy <instance-uuid> --expected-revision 2 --expected-state-hash <preview-hash>
```

`server --help` lists revision-bound save, peer export/revocation, health, history, backup, deployment restore, desired restore, reconciliation, and local cache removal. The CLI prints public structured JSON; explicit exports write secret-bearing client profiles to a chosen local path.

## Build and validation

```sh
rustup toolchain install 1.97.1
corepack enable
pnpm install
pnpm dev
make verify
```

`make verify` runs formatting, strict Clippy, Rust workspace tests, Svelte checks, Vitest, the web build, and Rust workspace build. Desktop package builds use the platform workflows in [build helpers](build-helpers/README.md). The disposable Debian/libvirt suite is in [tests/vm/remote-authority](tests/vm/remote-authority) and follows the separate `codex-cloud-init-automation` harness instructions. It uses unique guests, verified guest SSH keys, independent client data directories, structured results, and test-owned cleanup.

## Documentation

- [Architecture and migration](docs/architecture.md)
- [Remote format and compatibility](docs/remote-format.md)
- [Deployment and recovery](docs/deployment.md)
- [Security and credential ownership](SECURITY.md)
- [VM testing](docs/testing-vm.md)
