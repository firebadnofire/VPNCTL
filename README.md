<!-- markdownlint-disable MD033 -->

<h1 align="center">VPN Appliance Manager</h1>

<p align="center">
  <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/app-icon.svg" alt="VPN Appliance Manager app icon" width="112">
  <br>
  <strong>Local-first management for self-hosted WireGuard, AmneziaWG, OpenVPN, IKEv2, and Xray appliances.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2f855a"></a>
  <img alt="Rust 1.97.1" src="https://img.shields.io/badge/rust-1.97.1-b7410e">
  <img alt="Tauri 2" src="https://img.shields.io/badge/tauri-2.11-24c8db">
  <img alt="Svelte 5" src="https://img.shields.io/badge/svelte-5-ff3e00">
  <img alt="VPN backends: 5" src="https://img.shields.io/badge/VPN_backends-5-1769bd">
</p>

<p align="center">
  <img src="https://pubcode.archuser.org/firebadnofire/dnswg/raw/branch/main/assets/instances-screen.png" alt="VPN Appliance Manager instances screen" width="920">
</p>

VPN Appliance Manager is a Tauri 2 desktop application and developer CLI for
managing VPN appliances on Linux Docker hosts over verified SSH. Desired state
stays in local SQLite, secret values stay in the native OS credential store,
and each backend renders deterministic Docker Compose configuration through the
same preview, backup, health, and rollback pipeline.

The repository retains its historical `dnswg` name. The product name is
**VPN Appliance Manager**.

## Current status

- Version `0.1.0`
- Desktop package `vpn-appliance-manager`
- Developer CLI `vam-dev`
- Bundle identifier `org.archuser.vpnappliancemanager`
- Desktop targets: Windows, macOS, and Linux
- Server target: a compatible Linux host with Docker Engine and Compose v2
- Backends: WireGuard, AmneziaWG 2, OpenVPN, IKEv2/IPsec, and Xray/VLESS
- Remote root: `/opt/vpn-appliance-manager/instances/<instance-uuid>`
- Remote Compose project: `vam-<instance-uuid>`

Existing WireGuard-only databases migrate in place. Migration 0002 backfills
WireGuard backend settings and UDP listener rows without rotating instance or
device UUIDs, addresses, public keys, or secret references.

## Backend matrix

| Backend | Server and listeners | Container access | Persistent identity | Device and export |
| --- | --- | --- | --- | --- |
| WireGuard | LinuxServer WireGuard `1.0.20250521-r1-ls109`; configurable UDP host port to container UDP 51820 | `NET_ADMIN`; backend-specific forwarding sysctls; no privileged container or Docker socket | `vpn/server.key` and materialized `wg0.conf` | Local keypair, optional unique per-device PSK, disable/re-enable, replace, revoke, `.conf`, QR |
| AmneziaWG 2 | `amneziavpn/amneziawg-go:2.0.0` by digest; configurable UDP host port to container UDP 55424 | `NET_ADMIN` and `/dev/net/tun`; backend-specific forwarding sysctls | `vpn/server.key`, `awg0.conf`, and AWG J/S/H settings | Local keypair, mandatory unique PSK, disable/re-enable, replace, revoke, `.conf`, QR |
| OpenVPN | Local Alpine build with OpenVPN 2.6.20 and Easy-RSA 3.2.3; configurable UDP or TCP host port to container 1194 | `NET_ADMIN` and `/dev/net/tun`; IPv4 forwarding only | Easy-RSA PKI, requests, CRL, issued certificates, and optional `tls-crypt` key under `vpn/` | Local EC private key and CSR, remote CA signing, CRL revocation, replacement, `.ovpn`; no QR |
| IKEv2 | Local Alpine build with strongSwan 5.9.14; fixed UDP 500 and 4500 | `NET_ADMIN`; IPv4 forwarding; no privileged container | CA/server keys, certificates, CRL, requests, issued and revoked records under `ikev2/` | Local P-384 key and CSR, remote signing, CRL revocation and SA termination, password-protected `.p12`; no QR |
| Xray/VLESS | Local Alpine build with verified Xray v25.8.3 archive; configurable TCP or UDP host port to container 8443 | Non-root UID/GID 10001; no added capabilities, devices, forwarding sysctls, private DNS, or Docker socket | `xray-state/identity` REALITY keys and active structured JSON | Native-stored UUID credential, disable/revoke, regenerate, `.vless.txt`, QR; no tunnel IP or managed private DNS |

All Compose definitions omit `privileged: true`. Pulled images use an explicit
version, AWG uses a digest, local builds pin the Alpine base digest and package
versions, and Xray verifies architecture-specific SHA-256 checksums before
installing its binary. No backend uses a mutable `latest` tag.

Xray's supported desktop creation path is REALITY with TCP or XHTTP. The Rust
backend also validates TLS/mKCP combinations, but the UI intentionally does not
enable TLS until a reviewed native certificate-import path can place PEM
material directly into the secure store.

## What it manages

- **Verified SSH hosts:** pre-authentication key probing, exact SHA-256
  fingerprint approval, changed-key blocking, OpenSSH and PuTTY PPK keys,
  encrypted-key passphrases, fixed commands, SFTP, timeout, and cancellation.
- **Fresh-host setup:** read-only inspection and a separate hash-bound plan for
  apt, dnf, yum, zypper, or pacman; distribution packages only; Docker service
  startup; Compose v2 verification; and explicit Docker-group disclosure.
- **VPN instances:** strongly typed backend settings, typed TCP/UDP listeners,
  deterministic rendered files, custom ports where the protocol permits them,
  and capability-driven routing/DNS behavior.
- **Devices:** backend-specific public identity views over a shared workflow.
  Private keys, PSKs, certificate material, bundle passwords, and complete
  profiles remain behind Rust.
- **Private DNS:** CoreDNS zones with A, AAAA, CNAME, TXT, and SRV records plus
  optional HTTPS hostlists for routed backends. Xray does not pretend to be a
  routed private-DNS VPN.
- **Operations:** preview by desired-state hash, apply, redacted history,
  health, start/stop, image update, manual backup, automatic rollback, and
  retained deployment snapshots.

## Security model

VPN Appliance Manager is intentionally local-first:

- Svelte receives public views, capabilities, plans, health, and redacted
  events. It never receives private keys, PSKs, SSH passphrases, PKCS#12
  passwords, remote server keys, or complete client profiles.
- SQLite stores desired state, public identity metadata, and opaque
  `SecretReference` UUIDs. Secret values use macOS Keychain, Windows Credential
  Manager, or Linux Secret Service through the native keyring backend. There is
  no plaintext fallback.
- SSH host-key probing occurs before authentication. Unknown or changed keys
  block authenticated operations until exact fingerprint approval; replacing a
  changed key is a separate confirmation.
- Product code uses `russh` and `russh-sftp`, never the system `ssh` program.
  Remote process exit status is authoritative. Non-zero inspection, health,
  setup, validation, or deployment commands return structured, redacted error
  detail.
- Client private keys are generated locally. WireGuard/AWG server keys and Xray
  REALITY private keys are generated and retained remotely. Certificate CSRs
  cross SSH, but the corresponding private keys do not.
- Xray VLESS UUIDs are bearer credentials stored in the native credential
  store. SQLite keeps only opaque references, and routine frontend/CLI device
  views expose only the non-secret email/flow label.
- IKEv2 export uses a generated password and a PKCS#12 KDF iteration count of
  600,000; the bundle is written directly by Rust and never serialized to the
  frontend.
- CoreDNS forwards public queries only over DNS-over-TLS to Cloudflare
  endpoints with certificate-name verification; there is no plaintext
  fallback.

See [SECURITY.md](SECURITY.md), [architecture](docs/architecture.md), and
[remote format](docs/remote-format.md).

## Provisioning and deployment flow

```text
Add host
  -> probe SSH host key before authentication
  -> approve exact SHA-256 fingerprint
  -> inspect Linux, package manager, Docker, Compose, and authority
  -> optionally review/apply a separate host setup plan
  -> create a typed VPN instance
  -> create backend-appropriate device identities
  -> preview deterministic desired-state changes
  -> apply only with the reviewed state hash
  -> back up, activate, and verify backend/listener/client/DNS health
  -> automatically restore the complete prior instance tree on failure
```

Normal deployment never installs host packages. Fresh-host setup is its own
explicit workflow. Before a mutating instance deployment, the app copies the
complete instance tree with archive semantics. Rollback therefore restores
configuration and persistent WireGuard/AWG keys, OpenVPN/IKEv2 authorities and
CRLs, or Xray REALITY identity together.

Ten remote backups and ten local successful deployment snapshots are retained
per instance. Secret deletion is deferred while a retained snapshot still
references the secret.

## Quick start

Install the pinned toolchain and JavaScript dependencies:

```sh
rustup toolchain install 1.97.1
corepack enable
pnpm install
```

Run the desktop application:

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

## Windows build helper

From PowerShell:

```powershell
.\build-helpers\windows\build.ps1
```

The rerun-safe helper checks Visual Studio C++ Build Tools, Node.js 24.18.0,
Rust 1.97.1 with Clippy/rustfmt, WebView2, NASM 3.02, NSIS, and pnpm 11.9.0.
It lists missing machine prerequisites and asks before installing them.

- `-SkipToolInstall` fails without changing the machine.
- `-AssumeYes` permits preapproved setup automation.
- `VAM_SKIP_CHECKS=1` is available for packaging-only iteration.

See [build-helpers](build-helpers/README.md) for platform-specific build and
clean entrypoints.

## Developer CLI

`vam-dev` calls the same `ApplicationService` as Tauri:

```sh
make cli
target/debug/vam-dev host-add \
  --name lab \
  --hostname 192.0.2.10 \
  --username admin \
  --key "$HOME/.ssh/id_ed25519"
target/debug/vam-dev host-probe <host-uuid>
target/debug/vam-dev host-approve <host-uuid> \
  --expected-fingerprint 'SHA256:verified-value'
target/debug/vam-dev host-inspect <host-uuid>
target/debug/vam-dev host-provision-plan <host-uuid>
target/debug/vam-dev host-provision-apply <host-uuid> \
  --expected-state-hash <hash-from-host-plan>
target/debug/vam-dev instance-add \
  --host-id <host-uuid> \
  --name home \
  --endpoint vpn.example.com \
  --backend openvpn
target/debug/vam-dev device-add \
  --instance-id <instance-uuid> \
  --name laptop \
  --dns-name laptop
target/debug/vam-dev plan <instance-uuid>
target/debug/vam-dev apply <instance-uuid> \
  --expected-state-hash <hash-from-plan>
target/debug/vam-dev health <instance-uuid>
target/debug/vam-dev backup <instance-uuid>
target/debug/vam-dev rollback <successful-deployment-uuid>
```

Backend values are `wireguard`, `amnezia-wg`, `openvpn`, `ikev2`, and `xray`.
The CLI currently creates each backend with its typed secure defaults; the
desktop exposes conditional advanced settings. `--key` accepts OpenSSH private
keys and PuTTY `.ppk` files. Routine JSON output uses public views. Explicit
export writes the secret-bearing artifact to the chosen local path.

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

The normal suite is local and requires no public VPN infrastructure. It covers
backend dispatch, legacy migration, deterministic rendering, secret redaction,
custom ports, firewall generation, fresh-host plans, credential issue/revoke/
replace, destructive-change classification, persistent-state rollback, SSH
non-zero exits, shell quoting, structured JSON, bounded SFTP, and PPK loading.
Reusable VM acceptance is documented separately.

## Workspace map

| Path | Responsibility |
| --- | --- |
| `crates/core` | UUID desired-state model, strongly typed backend/device settings, validation, addresses, listeners |
| `crates/protocol` | Public plans/results, host provisioning, health, progress, structured errors, secret-safe artifacts |
| `crates/backend` | Shared backend capability, runtime, credential, health, and change-impact contracts |
| `crates/backend-wireguard` | WireGuard server/client rendering and identity behavior |
| `crates/backend-amneziawg` | AWG 2 rendering, obfuscation validation, and identity behavior |
| `crates/backend-openvpn` | OpenVPN/Easy-RSA rendering, issuance, CRL revocation, and `.ovpn` export |
| `crates/backend-ikev2` | strongSwan PKI, fixed listeners, revocation, and protected PKCS#12 export |
| `crates/backend-xray` | Structured VLESS/REALITY/TLS rendering, UUID lifecycle, and profile export |
| `crates/ssh` | `russh` trust, OpenSSH/PPK auth, commands, SFTP, bounded downloads, cancellation |
| `crates/storage` | SQLite migrations, CRUD, listener constraints, snapshots, events, secret retention |
| `crates/deployment` | Shared Compose/CoreDNS rendering, redacted manifests, drift plans |
| `crates/dns` | Zone/Corefile/hostlist validation and deterministic rendering |
| `crates/secrets` | Native credential-store adapter and in-memory test store |
| `crates/application` | Shared orchestration, credentials, host setup, deployment, health, rollback, export |
| `apps/desktop` | Capability-driven Svelte UI and narrow Tauri boundary |
| `apps/cli` | `vam-dev` harness over the same application service |

## Documentation

- [Architecture and trust boundaries](docs/architecture.md)
- [Remote filesystem and backend artifacts](docs/remote-format.md)
- [Deployment, upgrade, failure, and rollback](docs/deployment.md)
- [Reusable multi-backend VM testing](docs/testing-vm.md)
- [Security and secret lifecycle](SECURITY.md)
- [Detailed implementation dissection](dissection.md)
- [Amnezia SSH provisioning reference report](AMNEZIA_CLIENT_SSH_VPN_SERVER_PROVISIONING_REPORT.md)

## License

VPN Appliance Manager is released under the [MIT License](LICENSE).
