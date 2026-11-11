# Architecture and trust boundaries

## Active architecture

```text
Svelte desktop -> Tauri commands ---+
                                  +-> ApplicationService -> verified SSH/SFTP -> on-demand vam-server
vam-dev CLI -----------------------+         |                                  |
                                            | local SQLite and native secrets    +-> manifest control store
                                            |                                  +-> backend render/deploy/health
                                            +-> local drafts and cache           +-> protected PSKs and runtime PKI
```

The desktop and CLI use the same Rust service. A local connection profile identifies an SSH destination and approved host key. The appliance UUID is stored on the remote host and is independent of that profile. SSH host-key verification always precedes authentication; the appliance UUID cannot override it. A clone with the same appliance UUID at another verified SSH identity is reported as a duplicate.

`vam-server` is invoked over verified SSH per operation. It does not run as a daemon. Requests and responses are bounded files in an owner-restricted exchange directory; SFTP transfers only those files. The helper validates the caller, protocol and schema, request ID, appliance identity, expected revision, paths, configuration, host-wide allocations and listeners before mutation. Authoritative state and managed runtime changes happen only in the helper.

The active remote manifest format is protocol 2, schema 1. Its public configuration contains stable instance and peer UUIDs, backend settings, DNS, routing, listeners, allocations and public secret references. It omits local credential references and private keys. Each instance has immutable desired generations and a synchronized, atomically replaced `current` pointer. An exclusive filesystem lock serializes helper mutations. New PSKs are stored and synchronized before their referencing manifest commits. Retained generations, deployment backups and recovery bundles keep referenced material; no routine garbage collection removes it.

A save advances desired revision and leaves deployed revision unchanged. Deployment previews bind desired revision and observed deployed state; the helper rechecks both before activation. Runtime operation receipts and pending markers are remote. An interrupted operation blocks conflicting mutations until reconciliation. Deployment rollback restores the selected runtime tree and its persistent identity state while preserving newer desired generations. Restoring desired configuration writes a new revision. The control directory is outside deployment-tree moves.

## Client state

Client SQLite stores SSH profiles, local credential bindings, drafts, cached public inventory, preferences and legacy migration status. Routine server inventory always comes from the helper. Failed discovery never becomes an empty server; successful reads carry synchronization timestamps. Offline views are labeled and read-only. A stale local draft remains local until the user reconciles or discards it.

Native credential storage holds each client's SSH passphrase, peer private keys, CSR and export-only material. A fresh second client can discover and manage the same public configuration but cannot claim a complete peer export without that peer's private key. The helper keeps WG/AWG PSKs and certificate authorities/server keys. It returns a selected peer PSK or certificate material only for an explicit scoped export. Svelte receives no secret-bearing artifacts.

The backend registry and existing deterministic renderers still produce WireGuard, AmneziaWG, OpenVPN and IKEv2 deployment artifacts. Xray code remains for decoding and recovering detected legacy records; active creation, helper manifests, normal CLI choices and desktop forms reject it.

## Migration

Older local SQLite instance records are detected by unresolved records, regardless of database age or saved hosts. The migration UI appears only when at least one eligible local legacy instance remains. Preview identifies a destination, configuration and credential requirements. Confirmed migration backs up relevant state, transfers existing server-required PSKs through the helper, commits the public manifest, verifies discovery, and marks the local record archived. It does not restart containers. A different existing remote manifest is a conflict. The local database and credentials remain for recovery. Unsupported Xray records receive recovery export handling rather than a migration action.

The older remote SQLite authority implementation remains in the repository for recovery reads but is not accepted by the helper's active RPC path. There is no automatic import from a remote SQLite authority database into schema 1. See [remote format and upgrades](remote-format.md) for the explicit recovery procedure.
