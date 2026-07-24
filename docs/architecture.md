# Architecture and trust boundaries

## Dependency direction

The desktop and CLI call `ApplicationService`. The service owns orchestration and depends on typed traits rather than UI state:

```text
Svelte UI ── narrow Tauri commands ─┐
                                    ├─ ApplicationService
vam-dev CLI ────────────────────────┘     │
   ├─ Storage (SQLite desired state and deployment history)
   ├─ SecretStore (macOS Keychain; memory only in tests)
   ├─ SshTransport (russh/russh-sftp)
   ├─ DeploymentPlanner / DeploymentExecutor
   ├─ VpnBackend (WireGuard MVP)
   └─ DNS renderer
```

`core` has no transport or UI knowledge. WireGuard is selected through `VpnBackend`; adding another protocol does not change SSH or storage semantics.

## Trust boundaries

### Local UI

The Svelte process receives metadata, validation results, plans, health, and redacted events. It does not receive private keys, preshared keys, passphrases, server private keys, or full client configurations. Rust writes exports directly with mode `0600`; only a generated QR SVG crosses into the view.

### Local persistence

SQLite is canonical desired state. It stores public WireGuard metadata and opaque `SecretReference` UUIDs. Deployment snapshots are secret-free and retain references so an eligible rollback can retrieve Keychain values.

### macOS Keychain

`KeychainSecretStore` uses service `org.archuser.vpnappliancemanager`. There is no plaintext fallback. A missing device secret is irrecoverable: the identity must be replaced and deployed.

### SSH host

Host-key probing occurs before authentication. The user must confirm the exact SHA-256 fingerprint. The exact SSH public-key blob is stored; an unknown or changed key is blocked. Replacing a changed key is a separate explicit operation.

Product code uses `russh` and `russh-sftp`, never the system `ssh` client. Remote commands consist of fixed operations plus POSIX-quoted UUID-derived paths. Authentication supports OpenSSH and PuTTY `.ppk` key files with an optional Keychain passphrase only.

Remote host inspection checks for active UFW and Firewalld. When deployment, start, or image-update operations bring WireGuard up, fixed firewall commands idempotently allow the instance UDP port on active UFW or Firewalld using `sudo -n`; delete attempts to remove the same rule before trashing the instance.

### Remote containers

The images are digest pinned. The server private key is generated inside the remote WireGuard image, remains in a host-only `0600` file, is never returned, and never appears in a process argument. Only its public key is returned.

## Structured errors

`AppError` distinguishes user-facing code and message, affected scope, whether remote mutation occurred, whether automatic rollback succeeded, remediation, and redacted technical detail.

Persisted events never contain private configurations, commands containing secret values, private keys, preshared keys, passphrases, or secret environment values.
