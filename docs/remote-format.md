# Remote format and compatibility

## Authoritative control store

```text
/var/lib/vpn-appliance-manager/
  control/
    appliance-id
    instances/<instance-uuid>/
      current.json             # committed generation pointer
      generations/<revision>.json
      secrets/<secret-uuid>    # protected WG/AWG PSKs
      runtime/                 # operation receipts and pending runtime state
  recovery/<backup-uuid>/      # control plus active runtime and backups
/opt/vpn-appliance-manager/
  instances/<instance-uuid>/   # active Compose and backend artifacts
  staging/                     # validated deployment candidates
  backups/<instance-uuid>/     # runtime and persistent identity snapshots
  trash/                       # legacy archived runtime trees and retained fragments
```

The control store is outside `/opt/vpn-appliance-manager` so activation and rollback cannot overwrite committed desired state. Control directory entries are owner restricted; secret files are mode `0600`. The helper rejects symlinks, unsafe paths, oversized exchange messages and corrupt metadata. Per-instance discovery errors are returned alongside readable instances; a failed inventory read is never converted to an empty inventory.

Manifest schema 1 holds a version number, appliance UUID, instance UUID, revision, save time, request identity and public `Configuration`. The configuration includes backend settings, peer identities and allocations, DNS records and blocklist domains, routing and endpoint/listener settings. Remote references to PSKs contain only random UUIDs. Client private-key and native credential-store references are not serialized. Desired generations are immutable and the `current.json` pointer selects the committed revision.

A mutation takes an exclusive filesystem lock, validates expected revision and all relevant constraints, writes and synchronizes newly referenced secrets, writes and synchronizes the next immutable generation, atomically replaces `current.json`, then synchronizes the parent directory. An uncommitted generation is not authoritative. Retrying the same request ID and content reconciles the committed generation; reusing an ID for different content is refused. A lost response should be reconciled by request ID before a new mutation is attempted.

## Runtime trees

The existing backend renderers write `compose.yaml`, `.env`, public `instance.json`, deployment `state.json`, DNS zones/hostlists and backend files under the instance runtime root. WireGuard and AmneziaWG use remote `vpn/server.key` and materialized configurations. OpenVPN uses `vpn/pki`, `vpn/requests`, CRL, issued certificates and optional `tls-crypt.key`. IKEv2 uses `ikev2/private`, `x509ca`, `x509`, `x509crl`, requests and issued/revoked records. The server helper resolves protected PSKs and persistent identities during rendering; secret values are absent from public plans and manifests.

Deployment backup and rollback act on runtime trees, not control generations. A recovery bundle includes control generations, protected secrets, active runtime trees and retained runtime backups. Copy recovery bundles into protected storage; they contain server keys and PSKs. Do not restore only the runtime tree when recovering a whole appliance, because it can diverge from authoritative desired state.

## Version and upgrade procedure

Desktop/CLI and helper exchange protocol version 2 and manifest schema version 1. The helper negotiates compatibility before opening or creating authoritative storage. A mismatched client receives `incompatible` and must not write. The schema number is checked when reading every committed generation.

Helper Info also advertises optional capabilities. Restorable instance archive and restore require `instance_archives_v1`; protocol version 2 alone does not imply support. Missing capabilities default to empty for older helpers. The desktop repairs a compatible older helper from its embedded release payload on user-initiated connection/synchronization; CLI users administer upgrades separately. Clients refuse unsupported operations until the helper is updated and freshly verified; they never fall back to legacy removal.

There is no in-place schema upgrader in this version. To move to a future schema: stop mutation traffic, create and verify a complete control/recovery backup, install a helper and clients that explicitly support both source and destination schemas, validate a conversion of every retained generation and secret reference, and atomically publish upgraded generations only after validation. Keep the original backup until discovery, history, deployment observation and recovery have been verified. A version without a reviewed converter must refuse the write and leave control state untouched.

A pre-existing remote SQLite authority database is not automatically imported. Preserve its database, WAL and SHM together, plus any protected secret files, and use the old recovery tooling in an isolated copy to export its public state. Validate identity and content before committing a schema-1 manifest through the helper. Do not delete the old database until independent discovery and recovery backup checks pass. Legacy local SQLite migration is a separate, explicit operation from the desktop or CLI.

## Desktop client enrollment and export

Adding a device saves its credentials and public configuration and clears the
previous local draft without deploying. Review deployment, preview, and explicit
apply remain separate revision/hash-checked steps. Existing unrelated local edits
must be saved or discarded before enrollment. A blank optional DNS name uses the
device name when Add DNS record is enabled.

Retained drafts that exactly match a known committed server generation are obsolete copies and may be discarded; differing edits remain available for explicit reconciliation. Draft writes are drained before enrollment and local cleanup.

WireGuard and AmneziaWG client configurations can be displayed as QR codes. QR rendering shares the file-export renderer, requires the verified appliance and matching locally held private key, and never uploads the client private key. QR codes contain sensitive credentials; they are kept in the current view only and cleared on navigation, editing, or refresh. OpenVPN supports native text copy and private file export; IKEv2 uses private PKCS#12 file export. Oversized configurations report a QR error and must be exported as files.


## Capability-gated device removal and DNS blocking

Protocol 2 and manifest schema 1 are unchanged. `drop_peer_v1` adds the confirmed,
revision-bound `drop_peer` operation with distinct removal and revocation request
IDs. Certificate revocation commits first, then device metadata and linked DNS
records are removed. Each committed step remains in immutable desired history.
Retries validate the original request content; conflicting newer work is refused.

`dns_blocking_v1` adds a per-instance `blocking` operation with `read`, `save`,
`refresh`, and `resume` actions. Saving expects the blocking policy revision,
independent from VPN configuration revisions. Source definitions, statuses,
pending intent, and receipts live under `instances/<uuid>/blocking/` beside the
existing generations/secrets/runtime directories. Public configuration manifests
retain their existing `dns_blocklist_domains` field as baseline rules. Downloaded
source data is stored in immutable UUID directories, indexed into bounded shards;
it is not sent in discovery or inserted into the public manifest.

Blocking read responses include the current policy, source refresh metadata,
compiled/applied dataset versions, errors, pending request ID, and scheduler
availability. Resume resolves the saved original intent rather than accepting a
replacement mutation after a timeout. Unsupported helpers refuse the new
operations; clients must check capabilities before exposing them as available.
The fixed privileged `blocking-refresh` helper subcommand services the optional
systemd timer and accepts no client paths or arbitrary commands.

The fixed `self-check` subcommand reports executable protocol/schema/capabilities
without opening the control store or requiring sudo identity. It is used only to
validate root-owned update candidates. It does not initialize an appliance or
perform a manifest/schema conversion. Automatic repair changes no remote format,
revision, pending-operation marker, blocking policy, or deployed state. See
[deployment and recovery](deployment.md#automatic-helper-repair-and-recovery).
