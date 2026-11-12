# Host removal implementation status

## Implemented: local recovery preservation

The existing `host-remove` CLI command and `delete_host` application command
now use the shared Rust local cleanup entry point. Local removal performs no
SSH operations. It removes the active connection profile, approved connection
key, cached inventory, and drafts. Legacy local VPN configurations and retained
deployment configurations are copied into `local_host_recovery` before their
active rows are removed. Appliance-scoped peer credential bindings stay in
place, independently of connection profiles.

Private keys are neither moved nor deleted. Native credentials retain their
original references; user-managed SSH key files and exported VPN configuration
files are untouched. Retained recovery references are pinned against the
existing retired-credential cleanup path. Database write exclusion serializes
preservation with native credential retirement across application connections.

Preservation, removal, and the operation receipt commit in one SQLite
transaction with full synchronization. No filesystem or credential-store
mutation is part of local removal, so no cross-store atomic transaction is
assumed. An interrupted transaction leaves the active records intact; an
exact-scope retry after a completed commit returns its durable receipt. A reused
operation identifier with a different scope is rejected. Failed credential
readability checks prevent removal. Late connection-setting writes cannot
recreate a removed profile's drafts or cache.

The Rust cleanup entry point also supports a local reset scope covering all
saved profiles and current preferences. An incomplete reset scope is rejected.
This is not secure erasure: recovery configurations and native credentials
intentionally survive.

The desktop **Danger Zone** navigation page exposes confirmed local host
removal and local Factory Reset. It also centralizes the existing individual
instance archive and certificate revocation actions. Local cleanup works
offline; remote instance/device actions require a live connection and re-read
the authoritative revision before confirmation. A failed local cleanup retains
its original operation ID for retry. Full drop and remote Factory Reset are
shown as unavailable rather than falling back to a different operation.

Reconnection requires fresh SSH verification and agreement with the retained
appliance identity. A new connection to the same verified appliance can export
existing peers using the original client keys. Discovery never recreates absent
remote instances. Retained client material alone cannot replace deleted
server-only secrets.

## Blocked: destructive server cleanup

Full drop, remote Factory Reset, and recovery archive orchestration are not
implemented. No remote cleanup operation or reservation
is exposed. Existing individual instance removal retains its established
behavior.

Repository inspection found two historical ownership gaps that prevent safely
reusing the existing removal path for the approved permanent cleanup:

- Firewall setup adds bare UFW/firewalld port rules without recording whether a
  matching rule already existed. The existing removal command deletes by port
  and protocol, which cannot establish exclusive VPNCTL ownership.
- File replacement retains some files under names such as
  `trash/removed-<timestamp>-<relative-name>`. These names have no instance or
  appliance identity and cannot reliably distinguish material belonging to a
  current managed instance from an unmigrated legacy deployment.

New ownership metadata can protect future resources but cannot reconstruct
missing historical provenance. Permanent cleanup must refuse ambiguous
resources until an explicit ownership/adoption policy resolves them; it must
not guess ownership or delete the entire managed root. Server-authoritative
journals, reservation enforcement, descriptor-relative deletion, consistent
archives, and disposable-server restoration tests remain required before
enabling the remote modes.
