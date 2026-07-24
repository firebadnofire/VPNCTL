# Deployment and recovery

Only one deployment may execute per instance. A reviewed desired-state hash prevents applying a stale plan.

## Apply transition

```text
Planned
  -> verify approved host key and prerequisites
  -> render + compare remote redacted hashes
  -> upload to same-filesystem staging
  -> pull pinned images
  -> generate/reuse remote-only server key
  -> materialize and validate WireGuard/CoreDNS/Compose
  -> create pre-mutation backup
  -> atomically activate changed files
  -> allow active UFW/Firewalld for the WireGuard UDP port
  -> reload/restart/recreate minimum affected services
  -> full health checks
  -> Succeeded
```

Change classification:

- zone-only: atomically replace zone data and let CoreDNS `auto` reload;
- WireGuard peers/config: restart the gateway path;
- Compose, port, or network: pull and recreate affected services.

Health covers the Compose project, gateway, DNS, `wg0`, published UDP port, expected peers, private DNS, and public DNS forwarding.

## Failure transition

Validation before activation leaves active state unchanged. Any failure after activation is marked as a remote mutation:

```text
Applying -> failure after mutation
  -> stop failed project
  -> move failed state to recoverable trash
  -> restore pre-deployment backup
  -> Compose up
  -> full health checks
  -> RolledBack | RollbackFailed
```

The result reports mutation and rollback independently.

## Manual rollback

Manual rollback selects a successful secret-free snapshot, confirms all referenced Keychain material still exists, assigns a fresh DNS serial, creates another safety backup, renders and applies the snapshot, and verifies it. SQLite desired state is transactionally replaced only after successful remote verification.

Ten remote backups and ten deployment snapshots are retained. Secrets marked for deletion remain in Keychain while referenced by that window.

## Typed lifecycle operations

Start, stop, image update, backup, rollback, and delete are fixed operations. Start, deployment, and image update idempotently allow the WireGuard UDP port when UFW or Firewalld is active; delete attempts to remove that rule before stopping Compose and moving the instance directory to timestamped remote trash, then soft-deletes local state. No routine Docker operation uses sudo. Noninteractive `sudo -n` is used only for the one-time application root bootstrap and active firewall management.
