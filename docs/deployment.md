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

The helper must already be installed at `/usr/local/libexec/vam-server` on a new host. Installing or replacing that executable is a trusted host administration step outside the manifest RPC. The current desktop/CLI do not automatically install or upgrade it. Ensure the installed helper and client support the same protocol and schema before performing writes; incompatible versions refuse them.
