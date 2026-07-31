# Deployment, upgrade, and recovery

Only one instance deployment may execute at a time. Every Apply recreates the
plan and requires the exact desired-state hash the operator reviewed.

## Fresh-host setup is separate

VPN deployment never installs packages. The host workflow is:

```text
approved SSH key
  -> read-only inspection
  -> typed host setup preview
  -> explicit Apply with observed-state hash
  -> fixed package/service/access operations
  -> fresh verified SSH inspection
```

Inspection detects Linux, architecture, apt/dnf/yum/zypper/pacman, root or
`sudo -n`, Docker CLI, privileged daemon reachability, direct user access,
Docker group membership, Compose version, `/opt` access, WireGuard kernel
availability, UFW, and Firewalld.

Setup installs distribution packages only, enables/starts Docker, optionally
adds the SSH user to the root-equivalent Docker group, and verifies Docker plus
Compose v2. It is guarded for reruns. A stale hash or unsupported/unprivileged
host stops before mutation.

## Instance planning

Planning performs:

1. load and validate typed desired state through the selected backend;
2. resolve required secret references behind Rust;
3. render backend and optional DNS files deterministically;
4. read `state.json` and verify current remote hashes over approved SSH;
5. report drift, uploads, replacements, removals, validation, backup, image,
   activation, restart/reload, and health operations;
6. compare backend settings to the last successful deployment snapshot;
7. hash the complete desired state.

Settings impact is visible in preview:

- `LiveUpdate`: no extra warning;
- `ServiceRestart`: preview states that the gateway must restart;
- `Reinstall`: preview identifies a destructive reinstall-class change and
  tells the operator to review persistent identity impact.

WireGuard/AWG backend-setting changes are restart class. OpenVPN transport,
cipher, and TLS-control changes are restart class. IKEv2 server-identity
rotation and Xray security/identity rotation are reinstall class. Cross-backend
settings are always reinstall class.

The planner also chooses concrete file/runtime work:

- metadata-only changes avoid an unnecessary Compose action;
- DNS-only changes replace zone/hosts data and use the CoreDNS reload path;
- backend mount changes restart the gateway;
- Compose or local Dockerfile changes pull/build and run Compose up;
- a new instance pulls or builds its selected image and creates the project.

## Apply transition

```text
Planned
  -> verify approved SSH key
  -> require Linux + direct Docker + Compose v2
  -> reject stale desired-state hash
  -> reserve every declared host listener
  -> create same-filesystem staging
  -> copy persistent CA/identity state into staging
  -> upload rendered files with declared modes
  -> pull a versioned image or build pinned local input
  -> generate/reuse remote-only WG/AWG or Xray identity
  -> validate backend, optional CoreDNS, and Compose in staging
  -> create archive-mode full-instance backup
  -> atomically activate changed paths
  -> add active UFW/Firewalld rules for declared listeners
  -> reload/restart/recreate the minimum planned services
  -> verify backend, every listener, client set, and optional DNS
  -> persist public discovery data
  -> retain backup and snapshot
  -> Succeeded
```

Listener conflict checks and firewall commands are generated from the backend
listener list. WireGuard, AWG, OpenVPN, and Xray custom ports therefore use the
same checked value in Compose, conflict detection, firewall allowance, and
health. IKEv2 declares fixed UDP 500/4500 and rejects custom ports.

Remote command transport success is not operation success. Every fixed
operation, inspection, and health command checks the remote exit status before
parsing output. A non-zero result becomes a structured error with exit status,
redacted stdout/stderr, scope, mutation state, and remediation.

## Backend validation and health

| Backend | Staging validation | Runtime health |
| --- | --- | --- |
| WireGuard | `wg-quick strip` against materialized `wg0.conf` | project/container, `wg0`, listener, enabled peer count |
| AWG | `awg-quick strip` against materialized `awg0.conf` | project/container, `awg0`, listener, enabled peer count |
| OpenVPN | OpenVPN config/crypto validation in the selected image | process/config, listener, enabled certificate/client count |
| IKEv2 | strongSwan/swanctl availability and staged identity checks | loaded connection/credentials, UDP 500/4500, desired clients |
| Xray | `xray run -test` against materialized `server.json` | Xray test, listener, desired UUID count |

For routed backends, health additionally requires the CoreDNS container,
private-zone resolution, and public DNS-over-TLS forwarding. Xray's health
contract omits DNS honestly.

## Certificate credential transactions

OpenVPN and IKEv2 authority initialization occurs during first deployment and
persists in the instance mount. Device issuance/revocation uses a separate
transaction:

```text
lock instance
  -> verify current deployment and authority
  -> create authority backup
  -> generate/stage local private key + CSR references
  -> upload CSR
  -> sign remotely
  -> bounded-download certificate/CA material
  -> verify serial/material
  -> reload gateway where required
  -> atomically commit device JSON + secret-reference rows
  -> prune temporary remote request files
```

On failure, staged local secrets are removed and the authority backup is
restored. OpenVPN revocation regenerates the CRL and reloads. IKEv2 revocation
regenerates its CRL and terminates the old connection. Replacement issues the
new identity first and then revokes the old one.

## Failure and automatic rollback

Validation before activation leaves active state unchanged. A failure after any
remote mutation is marked accordingly:

```text
Applying -> failure after mutation
  -> stop failed Compose project
  -> move failed tree to recoverable trash
  -> archive-copy complete backup to active instance path
  -> Compose up
  -> backend/listener/client/DNS health
  -> RolledBack | RollbackFailed
```

The full-tree copy includes:

- WireGuard/AWG server private keys;
- OpenVPN CA, server identity, CRL, and `tls-crypt` key;
- IKEv2 CA, server identity, CRL, and revocation records;
- Xray REALITY private/public keys, short ID, and active JSON;
- Compose, listener, DNS, and rendered configuration.

The result reports remote mutation and rollback success independently. A
rollback that restored files but failed health is reported as rollback failure,
not success.

## Manual backup and rollback

Manual backup requires a successful deployed instance. Manual rollback:

1. selects a successful secret-free desired-state snapshot;
2. verifies every referenced local secret still exists;
3. assigns a new monotonic DNS SOA serial;
4. creates another safety backup;
5. renders and applies the snapshot;
6. verifies remote health;
7. replaces SQLite desired state only after success.

Ten remote backups and ten successful deployment snapshots are retained per
instance. Secret references pending deletion survive while any retained
snapshot still refers to them.

## Start, stop, update, delete

- **Start:** checks listeners/firewall, Compose up, then full health.
- **Stop:** Compose stop and a stopped-state result; it does not wait for
  running health.
- **Image update:** creates a backup, pulls or rebuilds the selected explicit
  image, runs Compose up, verifies health, and rolls back on failure.
- **Delete:** tries to remove generated firewall allowances, stops Compose,
  moves the instance tree to timestamped trash, and soft-deletes local state.

Routine Docker operations require direct Docker access and do not silently use
sudo. `sudo -n` is limited to explicit fresh-host setup, application-root
bootstrap, and active host firewall management.
