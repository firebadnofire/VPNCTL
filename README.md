<!-- markdownlint-disable MD033 -->

<h1 align="center">VPN Appliance Manager</h1>

<p align="center">
  <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/app-icon.svg" alt="VPN Appliance Manager app icon" width="112">
  <br>
  <strong>Local-first management for self-hosted WireGuard appliances with private DNS.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2f855a"></a>
  <img alt="Rust 1.97.1" src="https://img.shields.io/badge/rust-1.97.1-b7410e">
  <img alt="Tauri 2" src="https://img.shields.io/badge/tauri-2.11-24c8db">
  <img alt="Svelte 5" src="https://img.shields.io/badge/svelte-5-ff3e00">
  <img alt="WireGuard MVP" src="https://img.shields.io/badge/backend-WireGuard-88171a">
</p>

<p align="center">
  <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/instances-screen.png" alt="VPN Appliance Manager instances screen" width="920">
</p>

VPN Appliance Manager is a Tauri 2 desktop application and developer CLI for managing VPN appliances on your own Linux Docker hosts over verified SSH. The current backend is WireGuard. The app keeps desired state locally in SQLite, renders deterministic Docker Compose/CoreDNS/WireGuard configuration, previews remote changes before applying them, creates backups, verifies health, and supports rollback when a deployment mutates remote state.

This repository still uses the historical `dnswg` repo name. The product identity in the app is **VPN Appliance Manager**.

## Current Status

- **Version:** `0.1.0`
- **Desktop package:** `vpn-appliance-manager`
- **Developer CLI:** `vam-dev`
- **Bundle identifier:** `org.archuser.vpnappliancemanager`
- **Remote project name:** `vam-<instance-uuid>`
- **Remote instance root:** `/opt/vpn-appliance-manager/instances/<instance-uuid>`
- **Supported VPN backend today:** WireGuard
- **Secret storage today:** native `KeychainSecretStore`, documented for macOS Keychain; tests use an in-memory store

## What It Manages

- **Docker hosts:** Add SSH targets, probe SSH host keys before authentication, approve exact SHA-256 fingerprints, and inspect Linux/Docker/Compose/WireGuard/firewall readiness.
- **VPN instances:** Create WireGuard appliances with private IPv4 subnets, UDP endpoints, split-tunnel or IPv4 full-tunnel routing, and per-instance private DNS zones.
- **Devices:** Generate local WireGuard identities, optional preshared keys, managed DNS records, enable/disable peers, replace identities, export `.conf` files, and display QR codes.
- **Private DNS:** Manage `A`, `AAAA`, `CNAME`, `TXT`, and `SRV` records inside the instance zone.
- **DNS hostlists:** Add user-managed HTTPS hosts-file sources for DNS blocklists. The app starts with no built-in hostlists.
- **Deployments:** Preview plans by desired-state hash, apply through fixed operations, view redacted logs, run health checks, create backups, and roll back successful snapshots.

## Screenshots

<table>
  <tr>
    <td width="50%">
      <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/hosts-screen.png" alt="Hosts view showing SSH host inspection" width="100%">
      <br><strong>Verified SSH hosts</strong>
    </td>
    <td width="50%">
      <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/device-screen.png" alt="Devices view showing WireGuard device identities" width="100%">
      <br><strong>Device identities and exports</strong>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/dns-records-screen.png" alt="DNS records view" width="100%">
      <br><strong>Private DNS records</strong>
    </td>
    <td width="50%">
      <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/dns-hostlists-screen.png" alt="DNS hostlists view" width="100%">
      <br><strong>HTTPS DNS hostlists</strong>
    </td>
  </tr>
</table>

## Security Model

VPN Appliance Manager is intentionally local-first:

- The UI receives metadata, validation results, plans, health, and redacted events. It does not receive private keys, preshared keys, passphrases, server private keys, or full client configurations.
- SQLite stores desired state, deployment history, public WireGuard metadata, and opaque secret references.
- SSH host-key probing happens before authentication. Unknown and changed host keys block privileged operations until explicitly approved.
- Product code uses `russh` and `russh-sftp`, not the system `ssh` client.
- Rendered secret-bearing files are redacted in the CLI and never returned through Tauri.
- The remote WireGuard server private key is generated and retained on the remote host with mode `0600`; only the public key is returned.
- CoreDNS forwards public queries over DNS-over-TLS to Cloudflare endpoints with certificate-name verification. There is no plaintext DNS fallback in the rendered Corefile.
- Deployment, start, image update, and delete operations manage active UFW or Firewalld rules idempotently with `sudo -n` only where firewall/root bootstrap work requires it.

See [SECURITY.md](SECURITY.md), [architecture](docs/architecture.md), and [remote format](docs/remote-format.md) for the full trust-boundary notes.

## Deployment Flow

```text
Add host
  -> probe SSH host key
  -> approve exact SHA-256 fingerprint
  -> inspect Docker host
  -> create WireGuard instance
  -> add devices, DNS records, and optional hostlists
  -> preview desired-state plan
  -> apply by expected state hash
  -> verify health
```

Before a mutating deployment, the app creates a remote backup. If activation succeeds but health fails, it stops the failed project, moves it to recoverable trash, restores the backup, and reports whether rollback succeeded. Ten remote backups and ten deployment snapshots are retained per instance.

## Quick Start

Install the pinned toolchain and JavaScript dependencies:

```sh
rustup toolchain install 1.97.1
corepack enable
pnpm install
```

Run the desktop app in development:

```sh
pnpm dev
```

Run the browser-only Svelte shell:

```sh
pnpm --dir apps/desktop dev:web
```

Build the desktop package for the current platform:

```sh
pnpm build
```

## Windows Build Helper

From PowerShell:

```powershell
.\build-helpers\windows\build.ps1
```

The Windows helper installs JavaScript dependencies, uses the pinned Rust toolchain, runs verification, and packages the Tauri app. When native tools are missing, it lists the exact action and asks before installing. It supports:

- `-SkipToolInstall` to fail on missing tools without changing the machine
- `-AssumeYes` for preapproved automated setup
- `VAM_SKIP_CHECKS=1` for packaging-only iteration

The helper handles Visual Studio C++ Build Tools, Node.js 24.18.0, Rustup/Rust 1.97.1 with `clippy` and `rustfmt`, WebView2 Runtime, NASM 3.02, NSIS, and pnpm 11.9.0 through Corepack. PATH updates are session-local and deduplicated so reruns remain safe.

Platform-specific build and clean details live in [build-helpers](build-helpers/README.md).

## Developer CLI

`vam-dev` exercises the same application service as the desktop app.

```sh
make cli
target/debug/vam-dev info
target/debug/vam-dev host-add \
  --name lab \
  --hostname 192.0.2.10 \
  --username admin \
  --key "$HOME/.ssh/id_ed25519"
target/debug/vam-dev host-probe <host-uuid>
target/debug/vam-dev host-approve <host-uuid> \
  --expected-fingerprint 'SHA256:verified-value'
target/debug/vam-dev host-inspect <host-uuid>
target/debug/vam-dev instance-add \
  --host-id <host-uuid> \
  --name home \
  --endpoint vpn.example.com
target/debug/vam-dev device-add \
  --instance-id <instance-uuid> \
  --name laptop \
  --dns-name laptop
target/debug/vam-dev dns-add \
  --instance-id <instance-uuid> \
  --name nas \
  --record-type a \
  --value 10.64.0.20
target/debug/vam-dev plan <instance-uuid>
target/debug/vam-dev apply <instance-uuid> \
  --expected-state-hash <hash-from-plan>
target/debug/vam-dev health <instance-uuid>
target/debug/vam-dev backup <instance-uuid>
target/debug/vam-dev rollback <successful-deployment-uuid>
```

`--key` accepts OpenSSH private keys and PuTTY `.ppk` files. Sensitive rendered file contents are redacted in CLI output.

## Verification

```sh
make fmt
make lint
make test
make frontend-check
make frontend-test
make frontend-build
make tauri-build
make verify
```

The repository tests cover model validation, address allocation, DNS rendering, hostlist validation, secret redaction, deterministic rendering, deployment planning, SSH cancellation, host-key decisions, SQLite constraints, snapshot retention, firewall command generation, and desktop API helpers.

## Workspace Map

| Path | Responsibility |
| --- | --- |
| `crates/core` | UUID-backed desired-state models, validation, subnet and address allocation |
| `crates/protocol` | Typed public results, deployment operations, health, progress, structured errors |
| `crates/ssh` | `russh` host-key verification, key-file auth, commands, SFTP, timeout/cancellation |
| `crates/storage` | SQLite migrations, CRUD, snapshots, events, secret-reference retention |
| `crates/deployment` | Deterministic rendering, redacted hashes, drift-aware planning, remote manifests |
| `crates/dns` | DNS validation, Corefile/zone rendering, hostlist parsing, monotonic SOA serials |
| `crates/backend-wireguard` | WireGuard backend trait implementation, peer keys, server/client configuration |
| `crates/secrets` | Native secure secret store and in-memory test store |
| `crates/application` | Shared orchestration, deployment/recovery, export and QR generation |
| `apps/desktop` | Svelte 5 UI and narrow Tauri command boundary |
| `apps/cli` | `vam-dev` developer harness |
| `build-helpers` | Rerun-safe platform build and clean entrypoints |
| `docs` | Architecture, deployment, remote format, and reusable VM testing notes |

## Defaults

New instances use:

- Private IPv4 subnet `10.64.0.0/24`
- Gateway `10.64.0.1`
- UDP port `51820`
- DNS zone `internal`
- Persistent keepalive `25`
- Split-tunnel routing
- Per-device preshared keys by default
- Ten retained backups

IPv4 full-tunnel exports `0.0.0.0/0` and deliberately omits `::/0` unless IPv6 tunnel addressing is implemented.

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Remote filesystem and rendered artifacts](docs/remote-format.md)
- [Deployment, failure, and rollback transitions](docs/deployment.md)
- [Reusable Debian VM testing](docs/testing-vm.md)
- [Security and secret lifecycle](SECURITY.md)

## License

VPN Appliance Manager is released under the [MIT License](LICENSE).
