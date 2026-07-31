# Architecture and trust boundaries

## Dependency direction

Both clients call the same Rust application service:

```text
Svelte 5 UI -> narrow Tauri commands --+
                                      |
vam-dev CLI --------------------------+-> ApplicationService
                                           |
                                           +-> BackendRegistry
                                           |    +-> WireGuardBackend
                                           |    +-> AmneziaWgBackend
                                           |    +-> OpenVpnBackend
                                           |    +-> Ikev2Backend
                                           |    `-> XrayBackend
                                           +-> Storage (SQLite)
                                           +-> SecretStore (native OS store)
                                           +-> SshTransport (russh/SFTP)
                                           +-> DeploymentPlanner/Executor
                                           `-> DNS renderer
```

`core` contains UUID-backed desired state and validation, with no UI, SSH,
Docker, or database knowledge. `protocol` contains public result/error types.
`application` owns orchestration and transactions. The UI and CLI do not
implement backend business logic.

## Generic backend boundary

`VpnBackend` owns protocol-specific behavior:

- stable `VpnBackendKind`;
- capability metadata;
- typed settings validation;
- host/container listeners;
- minimum container capabilities, devices, mounts, environment, entrypoint,
  command, and sysctls;
- server identity strategy;
- deterministic server rendering;
- client artifact rendering;
- client secret-reference discovery;
- certificate credential plans where applicable;
- backend validation and health probe types;
- settings-change classification.

`BackendRegistry` is the only application-level lookup. Shared deployment code
consumes a `BackendRuntimeSpec`; it does not carry one Compose template per
protocol. This keeps listener mapping, firewall rules, image preparation,
validation, health, backup, and rollback generic.

Capabilities model real differences:

| Capability | WG/AWG | OpenVPN/IKEv2 | Xray |
| --- | --- | --- | --- |
| Allocated tunnel address | yes | yes | no |
| Managed private DNS | yes | yes | no |
| Quick credential refresh | yes | no | no |
| Reversible identity enable | yes | certificate revocation is irreversible | desired UUID removal requires restart |
| QR export | yes | no | yes |
| Traffic statistics | yes | yes | no |
| Certificate authority | no | yes | no |

The desktop consumes the registry's public capability view to show or suppress
addresses, DNS, PSKs, QR, refresh, and revocation actions. It does not duplicate
protocol rules.

## Desired state and migration

Every instance has:

- UUID identity and host UUID;
- `VpnBackendKind`;
- discriminated `BackendSettings`;
- endpoint and typed listener set;
- routed network/DNS fields retained for a stable storage shape;
- routing mode and lifecycle timestamps.

Every device has a discriminated `DeviceBackendData`:

- WireGuard public key plus local private-key/optional-PSK references;
- AWG public key plus local private-key/mandatory-PSK references;
- OpenVPN Common Name, CSR/certificate/CA/TLS-key references and serial;
- IKEv2 identity, CSR/certificate/CA/bundle-password references and serial;
- Xray UUID credential reference, non-secret email label, and optional flow.

Migration `0002_multi_protocol_model.sql` adds schema versions, backend settings,
device backend discriminators, and a `(host, port, transport)` listener table.
Its defaults backfill existing rows as WireGuard. It replaces the old
UDP-number-only uniqueness index, so TCP and UDP may share a numeric port while
the same host/port/transport combination remains exclusive.

The migration is additive and tested against a schema-0001 database. Existing
WireGuard UUIDs, addresses, JSON, device identities, and secret references
remain valid.

## Trust boundaries

### Svelte/Tauri boundary

Svelte receives:

- public host/instance/device views;
- backend capabilities and typed non-secret settings;
- host/deployment plans;
- health and redacted events;
- public certificates/serials and public keys where needed.

It does not receive:

- SSH key passphrases;
- client or server private keys;
- WireGuard/AWG PSKs;
- certificate private keys or CSRs;
- CA/TLS private material;
- PKCS#12 passwords or bytes;
- Xray client UUID credentials or their opaque references;
- Xray TLS/REALITY private keys;
- complete `.conf`, `.ovpn`, `.p12`, or VLESS artifacts.

Rust writes explicit exports directly to the selected path. QR SVG crosses the
boundary only for backends that declare QR support and is held only in the
current view.

### SQLite and native secret storage

SQLite is canonical desired state and operation history. Secret-bearing fields
hold opaque `SecretReference` UUIDs. The production `KeychainSecretStore`
uses keyring service `org.archuser.vpnappliancemanager`:

- macOS: Keychain;
- Windows: Windows Credential Manager;
- Linux: Secret Service over D-Bus.

The enabled keyring v1 feature selects those platform stores. There is no
plaintext fallback. Tests use `MemorySecretStore`.

Deployment snapshots are secret-free but retain references. Deletion is
deferred while any of the ten retained snapshots still needs a reference. A
missing local secret is not silently regenerated; device identity replacement
is explicit.

### SSH host

Host-key probing performs no authentication. The operator approves the exact
SHA-256 fingerprint, and SQLite stores the exact SSH public-key blob. Unknown
and changed keys block authenticated operations. Replacing a changed key
requires a separate confirmation and re-probe.

Product code uses `russh` and `russh-sftp`, not a system SSH command.
Authentication loads OpenSSH and PuTTY PPK files, including encrypted key
passphrases from the native secret store. Commands and SFTP use the approved
key blob, bounded timeouts/cancellation, and bounded downloads.

Remote exit status is authoritative. Inspection and health may parse structured
key/value stdout only after a zero exit. Errors carry an operation scope,
mutation/rollback flags, remediation, exit status, and redacted stdout/stderr.

Shell strings are fixed templates. UUID-derived paths use POSIX single-quote
escaping, ports/transports come from validated types, JSON comes from
`serde_json`, and protocol configuration uses dedicated renderers.

### Host setup boundary

Inspection is read-only. Package installation is a separate
`HostProvisioningPlan` bound to a SHA-256 hash of the observed host state.
Applying re-inspects first and rejects stale state.

Supported managers are apt, dnf, yum, zypper, and pacman. The setup uses only
distribution repositories and fixed package names/candidates; there is no
downloaded install script or third-party repository bootstrap. It requires
root or `sudo -n`. Adding the SSH user to the Docker group is disclosed as
root-equivalent access. A new verified SSH operation must prove direct Docker
and Compose v2 access afterward.

Normal VPN deployment cannot install packages.

### Remote container boundary

Backends declare their minimum runtime:

- WireGuard: `NET_ADMIN`;
- AWG/OpenVPN: `NET_ADMIN` plus `/dev/net/tun`;
- IKEv2: `NET_ADMIN`;
- Xray: non-root UID/GID 10001 with no added capabilities or devices.

No backend uses privileged mode or mounts the Docker socket. Sysctls are
backend-specific and limited to required forwarding/source-mark settings.
Firewall rules are generated from declared listeners, including custom ports;
the application does not drop host ICMP or apply unrelated global tuning.

Pulled and built software uses explicit versions. AWG and all local Alpine base
images use digests. Xray downloads only during image build with TLS 1.3 and
checks architecture-specific SHA-256 values. Persistent mounts remain under
the UUID instance root and are included in archive-mode backups.

## Certificate and identity transactions

OpenVPN and IKEv2 device creation is a local/remote transaction:

1. Rust generates the client private key and CSR locally.
2. Secret values are staged in the native store.
3. The CSR is uploaded over verified SFTP.
4. A fixed remote CA operation signs it.
5. The certificate/CA material is downloaded with a one-MiB bound.
6. Storage metadata and secret-reference rows commit atomically.

Failure compensates by restoring the authority backup and deleting staged local
secrets. Revocation updates the CRL and reloads the gateway. Replacement issues
new material before revoking the old identity; IKEv2 also terminates the old
connection.

WireGuard/AWG keys are local, with one keypair per device and no shared PSK.
Xray client UUIDs are local bearer credentials: native storage contains the
value, SQLite/snapshots contain only an opaque reference, and routine public
views retain only email/flow metadata. Rust resolves the UUID only while
rendering protected server JSON or an explicit client export.

WireGuard/AWG server keys and Xray REALITY private identity are generated on
the remote host and retained in persistent mounts.

## Structured errors and logs

`AppError` separates:

- stable code and user-facing message;
- affected scope/operation;
- whether remote state may have changed;
- whether automatic rollback succeeded;
- actionable remediation;
- redacted technical detail.

Persisted events contain safe phases and summaries. Commands that could carry
secret values are not persisted. Redaction removes known values and
private-key, preshared-key, password, and passphrase lines before CLI/UI/history
exposure.
