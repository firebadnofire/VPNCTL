# VPN Appliance Manager

VPN Appliance Manager is a local-first Tauri 2 desktop application for managing protocol-neutral VPN appliances on Docker hosts over verified SSH. The MVP backend is WireGuard with private CoreDNS zones, deterministic configuration rendering, SQLite desired state, macOS Keychain secrets, deployment plans, remote backups, rollback, health checks, and a developer CLI.

The repository retains the `dnswg` identity. The product identity is:

- Display name: **VPN Appliance Manager**
- Desktop/CLI package: `vpn-appliance-manager` / `vam-dev`
- Bundle identifier: `org.archuser.vpnappliancemanager`
- Remote Compose project: `vam-<instance-uuid>`
- Remote instance root: `/opt/vpn-appliance-manager/instances/<instance-uuid>`

## Quick start

Requirements on macOS:

- Xcode Command Line Tools
- Rust 1.97.1 (pinned by `rust-toolchain.toml`)
- Node.js 24 LTS
- pnpm 11

```sh
rustup toolchain install 1.97.1
corepack enable
pnpm install
make verify
pnpm dev
```

Run the browser-only Svelte shell:

```sh
pnpm --dir apps/desktop dev:web
```

Build an unsigned macOS `.app`:

```sh
pnpm --dir apps/desktop build
```

Reproducible platform packaging and scoped clean helpers live under
[`build-helpers`](build-helpers/README.md). Linux packages are always built
inside Docker:

```sh
make build-macos
make clean-macos
make build-linux
make clean-linux
```

On Windows, run `.\build-helpers\windows\build.ps1` or
`.\build-helpers\windows\clean.ps1` from PowerShell.

## Developer CLI

The CLI uses the same SQLite, Keychain, rendering, SSH, planning, deployment, and rollback service as the desktop app.

```sh
make cli
target/debug/vam-dev info
target/debug/vam-dev host-add \
  --name dnswg-test \
  --hostname 192.168.86.55 \
  --username william \
  --key "$HOME/.ssh/id_ed25519"
target/debug/vam-dev host-list
target/debug/vam-dev host-probe <host-uuid>
target/debug/vam-dev host-approve <host-uuid> \
  --expected-fingerprint 'SHA256:verified-value'
target/debug/vam-dev host-inspect <host-uuid>
target/debug/vam-dev instance-add \
  --host-id <host-uuid> \
  --name lab \
  --endpoint 192.168.86.55
target/debug/vam-dev plan <instance-uuid>
target/debug/vam-dev apply <instance-uuid> \
  --expected-state-hash <hash-from-plan>
target/debug/vam-dev health <instance-uuid>
target/debug/vam-dev backup <instance-uuid>
target/debug/vam-dev rollback <successful-deployment-uuid>
```

`--key` accepts OpenSSH private keys and PuTTY `.ppk` files. `host-approve` always requires the exact probed fingerprint. It never auto-trusts a key. Sensitive rendered file contents are redacted in CLI output.
On macOS, `make cli` applies a stable ad-hoc development signature so Keychain recognizes separate CLI invocations as the same application. Re-run it after rebuilding the CLI.

## Workspace

| Path | Responsibility |
| --- | --- |
| `crates/core` | UUID-backed desired-state models, validation, subnet and address allocation |
| `crates/protocol` | Typed public results, deployment operations, health, progress, structured errors |
| `crates/ssh` | `russh` host-key verification, key-file auth, commands, SFTP, timeout/cancellation |
| `crates/storage` | SQLite migrations, CRUD, snapshots, events, secret-reference retention |
| `crates/deployment` | Deterministic shared rendering, redacted hashes, drift-aware planning |
| `crates/dns` | DNS validation, Corefile/zone rendering, monotonic SOA serials |
| `crates/backend-wireguard` | Backend trait, local peer keys, server/client configuration |
| `crates/secrets` | macOS Keychain and in-memory test stores |
| `crates/application` | Shared orchestration, deployment/recovery, export and QR generation |
| `apps/desktop` | Svelte 5 UI and narrow Tauri command boundary |
| `apps/cli` | `vam-dev` integration harness |

More detail:

- [Architecture and trust boundaries](docs/architecture.md)
- [Remote filesystem and rendered artifacts](docs/remote-format.md)
- [Deployment, failure, and rollback transitions](docs/deployment.md)
- [Reusable Debian VM testing](docs/testing-vm.md)
- [Security and secret lifecycle](SECURITY.md)

## Defaults

New instances use `10.64.0.0/24`, gateway `10.64.0.1`, UDP `51820`, zone `vpn.internal`, keepalive 25 seconds, split tunneling, a per-device preshared key, and ten retained backups. IPv4-only full tunnel exports `0.0.0.0/0` and deliberately omits `::/0`.

## Verification

```sh
make fmt
make lint
make test
make frontend-check
make frontend-test
make frontend-build
make tauri-build
```

Generated configuration is deterministic except deployment timestamps and fresh rollback SOA serials. Tests cover validation, address allocation, DNS, secret redaction, renderer invariants, planning, SSH cancellation, host-key decisions, SQLite constraints, snapshot retention, and the desktop API helpers.
