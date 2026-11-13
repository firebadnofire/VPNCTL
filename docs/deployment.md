# Deployment and recovery

Saving public configuration commits a new desired generation on the appliance. It does not change containers or deployed revision. A deployment preview reports redacted operations and warnings bound to the desired revision and observed runtime state. The helper takes its filesystem lock again before mutation and refuses a stale preview.

The helper reuses backend rendering, staging, validation, Compose activation, health checks and compensation. It resolves protected WG/AWG PSKs and persistent server identities inside the appliance. Redacted runtime operation history, backup-to-revision mapping and pending markers are stored remotely so a fresh client can inspect them. If a process is interrupted with a pending marker, conflicting mutations are refused until the operation is reconciled. A request-ID check reports **committed** when a successful receipt exists, **uncommitted** when no pending operation or successful receipt exists, and **unresolved** when a pending operation has no durable receipt or recovery is required. A completed receipt can finalize pending bookkeeping; an unresolved marker stays in place for operator recovery. Do not repeat a mutation with a new ID until its status is known.

Runtime backups copy the active instance tree, including WireGuard/AWG server keys or OpenVPN/IKEv2 authority, issued certificate and revocation state. A deployment rollback restores the selected deployed tree and its associated persistent state. It preserves all newer desired generations and leaves a pending deployment indication when saved desired revision differs. Restore previews show identity impact; the helper refuses restores that would invalidate newer saved configuration. The authoritative control directory is not part of the runtime move.

**Restore Desired Configuration** selects an older public generation, validates it against current revision and host-wide constraints, and commits it as a new desired revision. It does not rewind history or deploy. Instance removal is separate: it requires confirmation and the current revision, stops and archives the runtime tree, then commits a tombstone while retaining history and secrets for recovery.

**Backups → Archived instances** lists those tombstones, including when there
are no active instances. Archival retains the complete stopped runtime tree as
`backups/<instance-uuid>/archive-<request-uuid>` and records its deployed revision
under the authoritative control store. These archive snapshots are excluded
from routine deployment-backup pruning.

**Restore archived instance** checks the archived revision and host-wide
port/subnet constraints, copies the retained runtime tree without overwriting an
existing deployment, and publishes a new active desired revision with the same
instance, peers, and keys. The instance stays stopped until explicitly started
or deployed. The original archive remains available among its runtime snapshots.
Restoring a never-deployed instance restores its saved configuration only.
Client private keys remain in the original client's native credential store.

Restore uses a durable pending request UUID and committed manifest receipt.
Retries after interruption or a lost response must use that same UUID; the
desktop recovers it from server discovery. Missing or unsafe runtime archives
block restore rather than regenerate server identities. For archives created
by older helpers, a single whole-instance trash tree can be adopted into a
retained snapshot; multiple candidates require explicit server recovery rather
than guessing which identity to restore.

Upgrade the Linux helper alongside the desktop for this workflow. New clients
use the explicit `archive_instance` operation, which older helpers reject before
changing data. The older `remove` operation remains an alias on updated helpers.

A complete disaster-recovery bundle is created through the helper and includes the control directory, active runtime trees and retained backups. It contains secrets and must be stored with restricted permissions. Recovery should restore the bundle as a unit on a compatible host, verify the appliance identity and SSH host key separately, inspect all manifests and runtime state, then resume mutation traffic. Never copy an appliance UUID to a clone and treat it as SSH trust.

The helper must already be installed at `/usr/local/libexec/vam-server` on a new host. Installing or replacing that executable is a trusted host administration step outside the manifest RPC. First installation remains an explicit administration step. The desktop automatically repairs missing supported capabilities on a verified, compatible helper when the user connects or synchronizes; the CLI retains separately administered upgrades. Ensure the installed helper and client support the same protocol and schema before performing writes; incompatible versions refuse them.

Restorable instance archival requires a helper advertising `instance_archives_v1`. The desktop bundles matching Linux x86_64/aarch64 helpers and automatically repairs a compatible older helper on connection. No host is contacted merely by starting the app. If automatic repair fails, expand Technical details and use Refresh / Reconnect after addressing the reported prerequisite (for example passwordless sudo or disk space). A rejected archive request leaves the instance active; do not use legacy removal as a workaround.

## Independent DNS blocking updates

Blocking policy has its own revision and applied dataset hash. Source refresh
never advances the VPN desired or deployed revision. It uses the active deployed
configuration's baseline domains, so unrelated newer desired settings stay
pending. Initial deployment is required before a cached dataset can be applied.

The helper serializes blocking updates with deployments and configuration writes
using the existing authority lock. It stores a durable request intent and pending
marker, copies the current blocking file to a checked recovery path, and atomically
publishes the compiled file. Fresh reserved DNS verification names avoid stale negative-cache answers while
CoreDNS reloads the dataset; DNS readiness is checked independently. Failure restores the
previous file. An incomplete rollback leaves a durable pending journal, blocking
conflicting mutations until the same operation is resumed or recovered.

Normal deployment previews/rendering include the current blocking policy.
Deployment, runtime restore, and instance start verify/reapply that policy rather
than silently retaining an older snapshot's blocking data. Blocking verification
failures are recorded separately with an unknown applied version; a rollback
failure leaves an explicit recovery condition. Reconciliation of a deployment
whose blocking rollback failed retries the DNS-only recovery without applying
another VPN revision. Stop, archive, backups, and certificate revocation remain
available when a source configuration needs correction.

Archive/restore preserves the authoritative policy and cached source datasets in
the control store. Whole-appliance control backups include policy, receipts,
intents, and bounded dataset shards; runtime backups include the operational DNS
file. Do not downgrade to a helper without `dns_blocking_v1` while managed policies
are configured: older helpers cannot enforce this independent policy. Preserve
a complete verified control/runtime backup before changing helper versions.

Device removal does not erase the certificate revocation recorded in desired
history. Runtime restore previews reject backups whose recorded deployed revision
predates a later certificate revocation, including when that device's metadata
has since been dropped. The older snapshot cannot prove it retains the newer
CA/CRL state. This conservative check can also refuse a snapshot taken after a
revocation but before a subsequent VPN deployment; preserve such snapshots for
explicit operator recovery rather than weakening certificate trust.

## Automatic helper repair and recovery

Repair requires the existing protocol 2/schema 1 Info handshake, approved SSH key,
and unchanged appliance/machine identities. It never approves a fingerprint,
converts a schema, deploys desired configuration, or restarts VPN containers.
Helpers already advertising all required capabilities are left untouched.
Unsupported platforms, incompatible schemas, missing build payloads, and changed
identities produce explicit failures instead of an attempted migration.

The desktop contains immutable helper bytes built from the release source. There
is no runtime code download. A private SSH upload is copied to a root-owned
candidate, SHA-256 checked, and executed with `self-check` before installation.
The installer checks ownership, rejects symlinks and writable system directories,
and locks both helper installation and the existing control-store mutation lock.
It rechecks the previous executable checksum under the lock, preserves a concurrently
installed capable helper, and refuses unrecognized concurrent changes. It keeps
`/usr/local/libexec/vam-server.backup-<old-sha256>` and atomically replaces
only the executable. Failed post-install verification restores that backup.
A lost response is resolved by fresh identity/capability discovery on reconnect;
no VPN mutation is replayed. A rollback failure is exposed in Technical details.

Backup helpers remain on the server for operator recovery. To restore one, stop
management traffic, verify its checksum and compatibility, copy it to a
root-owned sibling candidate, and atomically replace the executable under both
locks. Preserve a complete control/runtime recovery backup for any manual helper
version change; executable rollback cannot reverse a schema migration.
