# VPN Appliance Manager multi-protocol refactor dissection

This file is the living implementation record for the refactor of the `dnswg`
repository. It describes the code that existed before the refactor, the design
decisions made during implementation, each completed functional unit, and the
validation evidence collected after every unit.

The repository name remains `dnswg`. The product name remains **VPN Appliance
Manager**.

## Current implementation snapshot (audited 2026-08-19)

This document is a chronological engineering record. Sections that describe an
"initial" architecture, a target, a plan, or a limitation at the start of an
implementation unit are retained as historical context; they are superseded by
the completed units and validation ledger that follow them. The current checkout
is `f92e619` (`docs: record live backend deployment validation`). That commit is
the latest source of this document, and there are no later implementation commits
for the dissection to incorporate.

At this revision, VPN Appliance Manager has one shared Rust application service,
a narrow Tauri bridge, a Svelte 5 desktop client, and a developer CLI. The backend
registry contains functional WireGuard, AmneziaWG 2, OpenVPN, IKEv2, and
Xray/VLESS implementations. The desktop exposes backend-aware creation, settings,
clients, DNS where supported, reviewed deployment, backups, health, and activity
workflows. Sections 12A-12R record the final UI work, live five-backend deployment
matrix, fixes found during live validation, and the last full Windows release
validation.

The current persistence and trust model remains desktop-authoritative:

- `apps/desktop/src-tauri/src/lib.rs` opens `state.sqlite` in the application data
  directory and constructs `ApplicationService` with `KeychainSecretStore`;
- `crates/storage/migrations/0001_initial.sql` through
  `0003_desktop_activity_and_backups.sql` define the local SQLite model for
  hosts, desired state, users, devices, DNS, deployments, backups, activity,
  settings, host-key pins, and opaque secret references;
- desktop-owned secret values are stored in the native OS credential store,
  including integrity-checked chunking for values that exceed platform entry
  limits; backend-owned CA and server identity material can be remote-only;
- the SSH server stores deployed runtime configuration, manifests, protected
  protocol authority/identity state, and remote backups beneath
  `/opt/vpn-appliance-manager`, but it is not the canonical control-state store;
- client artifacts are rendered on demand in Rust from local desired-state
  metadata plus native-store and remote authority material. Raw artifact bytes
  are written to a private local file only after an explicit export; QR-capable
  profiles cross the Tauri boundary only as an SVG whose matrix encodes the
  configuration.

Consequently, a future server-authoritative persistence redesign is not already
implemented by this revision. Moving desired state, client identity material,
profiles, and history to each SSH server would replace—not merely extend—the
SQLite/keychain authority described here. The last runtime and packaging results
in section 12R are evidence from 2026-07-31 and have not been represented as a new
2026-08-19 test run by this documentation-only audit.

## 1. Refactor objective and non-negotiable boundaries

VPN Appliance Manager is being expanded from a WireGuard-specific appliance
manager into a multi-protocol self-hosted VPN manager supporting:

- WireGuard;
- AmneziaWG, with AWG2 as the primary implementation;
- OpenVPN;
- IKEv2;
- Xray/VLESS.

The refactor must preserve the useful security and reliability properties that
already distinguish VPN Appliance Manager from the adjacent Amnezia client:

- the Rust core is the authority for models, validation, secrets, rendering,
  deployment, SSH, backup, rollback, and export;
- the Svelte frontend receives metadata and redacted status only;
- SSH host keys are probed before authentication and require explicit
  fingerprint approval;
- a changed host key blocks all privileged operations unless it is separately
  approved;
- the built-in `russh`/`russh-sftp` transport is used instead of the system SSH
  client;
- remote process exit status is authoritative;
- SQLite is canonical desired state;
- native secure storage contains private material while SQLite stores opaque
  references;
- rendered output is deterministic;
- deployment is previewed before mutation;
- remote changes are staged and validated;
- a backup precedes activation;
- failed activation or health validation triggers rollback;
- persisted logs and frontend payloads are redacted;
- instance files remain under
  `/opt/vpn-appliance-manager/instances/<instance-uuid>`.

The adjacent `../amnezia-client` checkout and
`AMNEZIA_CLIENT_SSH_VPN_SERVER_PROVISIONING_REPORT.md` are protocol-behavior
references, not architecture templates. In particular, this refactor will not
copy Amnezia's missing host-key verification, ignored remote exit status,
privileged-by-default containers, mutable supply-chain inputs, raw string
templating, shared WireGuard PSKs, passwordless PKCS#12 output, or legacy
L2TP/XAuth configuration.

## 2. Runtime and repository constraints

The development checkout is a Windows PowerShell workspace. The Rust workspace
declares Rust 1.97 and edition 2024. The desktop application is Tauri 2.11 with
Svelte 5, Vite, TypeScript, and Vitest. The project uses SQLite through SQLx
migrations.

The initial workspace members are:

| Member | Initial responsibility |
| --- | --- |
| `apps/cli` | `vam-dev` developer/operator CLI |
| `apps/desktop` | Svelte desktop UI and narrow Tauri command layer |
| `crates/application` | orchestration and all remote lifecycle behavior |
| `crates/backend-wireguard` | WireGuard validation and server/client rendering |
| `crates/core` | persisted desired-state domain models and validation |
| `crates/deployment` | shared file rendering, hashing, diff planning |
| `crates/dns` | CoreDNS zone, Corefile, and blocklist rendering |
| `crates/protocol` | UI/CLI-facing operations, health, results, and errors |
| `crates/secrets` | native keyring and in-memory test secret stores |
| `crates/ssh` | verified `russh` execution and SFTP upload |
| `crates/storage` | SQLite CRUD, snapshots, events, and secret retention |

No system packages are required merely to edit or test the initial source. New
Rust dependencies must be justified by protocol requirements and must not
introduce a plaintext secret fallback. Fresh remote Linux host bootstrapping is
a product feature and must be modelled as visible, idempotent deployment
operations rather than performed implicitly during local development.

## 3. Initial architecture trace

### 3.1 Entry points and dependency flow

Both frontends construct the same `ApplicationService`:

```text
Svelte UI -> Tauri commands --+
                              +-> ApplicationService
vam-dev CLI ------------------+
                                   |
                                   +-> Storage
                                   +-> SecretStore
                                   +-> SshTransport
                                   +-> deployment renderer/planner
                                   +-> WireGuard backend
                                   +-> DNS renderer
```

The Tauri layer is narrow and contains no protocol implementation. Its
`render_instance` command clears sensitive file contents before returning
metadata to Svelte. Client exports are written by Rust; only the QR SVG is
returned to the UI. The CLI similarly replaces sensitive rendered contents
with `[REDACTED]`.

This shared-service shape is worth preserving. The problem is not separate UI
and CLI implementations; it is that `ApplicationService` directly selects
WireGuard behavior at nearly every lifecycle boundary.

### 3.2 Persisted core model

`crates/core/src/lib.rs` initially defines:

- `DockerHost` and `SshConnectionConfig`;
- `VpnInstance`, with a `VpnBackendKind` discriminator that contains only
  `WireGuard`;
- common endpoint, IPv4 network, DNS, routing, and keepalive fields;
- `Device`, whose required IPv4 address and `DeviceBackendData::WireGuard`
  payload assume a WireGuard peer;
- users, DNS records, and complete `DesiredState`;
- private-subnet, first-gateway, device-address, subnet-overlap, and duplicate
  UDP-port validation.

The backend enum is therefore only a placeholder. There are no typed backend
settings, capability declarations, transport-aware listener sets, schema
versions, certificate identities, Xray UUID identities, or protocol-specific
validation.

### 3.3 SQLite schema and migration behavior

The initial database has one migration, `0001_initial.sql`. The important
tables are:

- `docker_hosts`;
- `known_host_keys`;
- `vpn_instances`;
- `users`;
- `devices`;
- `dns_records`;
- `deployments` and `deployment_events`;
- `settings`;
- `secret_references`.

`vpn_instances` has indexed columns for host, backend, endpoint port, subnet,
and DNS zone, plus a complete `model_json`. `devices` follows the same pattern:
queryable common columns plus complete `model_json`. Deployment snapshots
serialize `DesiredState`.

The initial `save_instance` implementation always writes the literal
`wireguard` into the indexed backend column, regardless of the model value.
Reads deserialize only `model_json`. This must be corrected before new
backends are introduced.

The active `(host_id, endpoint_port)` unique index assumes one port and does not
distinguish TCP from UDP. That cannot represent OpenVPN transport selection,
IKEv2's fixed UDP 500/4500 pair, or a TCP Xray listener. The migration must add
a listener-reservation representation without dropping or rewriting existing
WireGuard rows destructively.

Existing WireGuard JSON snapshots have no backend-settings or model-schema
fields and serialize the enum as `wire_guard`. Compatibility must be explicit:
old values deserialize to WireGuard with current WireGuard defaults, and new
writes use the canonical backend identity consistently.

Host deletion deliberately uses `ON DELETE RESTRICT` for active instances.
Storage rejects a host that still has active instances and atomically cleans
all dependent rows belonging to already soft-deleted instances. This behavior
must survive all new migrations.

Secret deletion is retention-aware: identities marked pending deletion stay in
the native store while referenced by retained deployment snapshots. The
initial snapshot scan only understands WireGuard private-key and PSK
references, so it must become backend-generic.

### 3.4 Backend and rendering path

`crates/backend-wireguard` initially contains both the nominal `VpnBackend`
trait and its only implementation. The trait supports:

- a string backend ID;
- validation;
- one server file;
- one client artifact.

It does not describe:

- capabilities;
- listener ports and transports;
- container/runtime requirements;
- server identity strategy;
- secret references;
- device creation, revocation, or replacement semantics;
- remote credential issuance;
- health probes;
- quick-update versus reinstall classification.

The WireGuard renderer itself has several sound properties:

- device private keys are generated locally;
- every new device can receive its own PSK;
- active peers are sorted by IPv4 address;
- comments are newline-sanitized;
- client keys never enter server configuration;
- the server private key is represented by a sentinel;
- full-tunnel IPv4 does not advertise an IPv6 default route when no IPv6
  tunnel is configured.

These behaviors become the compatibility baseline for the generic contract.

### 3.5 Shared deployment renderer and planner

`crates/deployment` initially renders:

- a single WireGuard/CoreDNS/Watchtower Compose project;
- `.env` with the WireGuard port;
- `instance.json`;
- CoreDNS configuration, zone, and blocklist files.

Its planner compares a desired manifest to remote hashes and emits typed
operations for file changes, validation, backup, Compose pull/up/restart, DNS
reload, and health checks. DNS-only changes use a DNS reload. Changes beneath
`vpn/` restart the gateway. Other changes pull images and recreate the project.

The plan hash is the SHA-256 of serialized desired state. File hashes redact
lines beginning with `PrivateKey` or `PresharedKey` so the manifest does not
depend on those values. This redaction is too WireGuard-specific for
certificate private keys, PKCS#12 passwords, OpenVPN static keys, and Xray
private Reality material.

The initial image constants use mutable `latest` tags despite documentation
claiming digest pins. Watchtower also deliberately moves deployed images
without a reviewed plan. Both conflict with deterministic, previewed upgrades.

### 3.6 Application orchestration and WireGuard coupling map

`ApplicationService` owns storage, secrets, SSH, per-instance locks, and
deployment cancellation. Its current WireGuard coupling points are:

| Area | Initial WireGuard assumption |
| --- | --- |
| instance creation | always sets `VpnBackendKind::WireGuard` |
| host validation | treats kernel WireGuard availability as the only backend capability |
| device creation | always generates a WireGuard key pair and optional PSK |
| device update | validates through `WireGuardBackend` |
| identity replacement | always rotates WireGuard private/public key and PSK |
| rendering | gathers only WireGuard PSKs and calls `WireGuardBackend` |
| client export | always renders a WireGuard `.conf` |
| QR | assumes every client artifact is QR-suitable |
| deployment | pulls a WireGuard image and materializes `wg0.conf` |
| server identity | generates/reuses `vpn/server.key` with `wg genkey` |
| validation | runs `wg-quick strip` |
| activation | treats `vpn/` as WireGuard credential state |
| health | runs `wg show wg0`, counts peers, and checks one UDP port |
| firewall | always adds/removes one UDP port |
| ownership repair | uses the WireGuard image to chown `vpn/` |
| event text | names WireGuard rather than the selected backend |
| secret retention | knows only WireGuard secret-reference fields |

These are the concrete seams the refactor must replace. Merely adding enum
variants would leave the product non-functional.

### 3.7 Current remote transaction

A mutating deployment currently performs:

1. retrieve the explicitly trusted host key and optional key passphrase;
2. inspect Linux, Docker, Compose, direct Docker access, `/opt` access, sudo,
   WireGuard, UFW, and Firewalld;
3. reject hosts without an already working Docker/Compose installation;
4. create same-filesystem staging and support directories under
   `/opt/vpn-appliance-manager`;
5. reject an occupied UDP listener port unless it belongs to the current
   instance;
6. upload rendered files through SFTP with explicit modes;
7. pull three mutable images;
8. copy or generate the server WireGuard key in staging;
9. materialize the final WireGuard config from the sentinel template;
10. validate WireGuard, CoreDNS, and Compose;
11. copy the current instance as a pre-mutation backup;
12. atomically activate staged file changes;
13. idempotently open UFW/Firewalld for one UDP port;
14. restart/recreate the appropriate services;
15. retry health for up to 30 seconds;
16. normalize `vpn/` ownership after the LinuxServer container has started;
17. restore the backup on activation, service, or health failure;
18. persist the server public key, prune remote backups, and retire secrets no
    longer needed by retained snapshots.

The sequencing of stage, validate, backup, activate, health, and rollback is a
strong foundation. Backend-specific preparation, validation, health, and
credential reconciliation need to become typed inputs to that transaction
instead of duplicating the transaction.

### 3.8 SSH trust and command semantics

`crates/ssh` already provides the required transport boundary:

- host-key probe uses a connection that captures the presented key without
  authenticating;
- normal connections compare the exact public-key blob to the approved value;
- authentication loads an OpenSSH or PuTTY PPK private key through `russh`;
- optional passphrases arrive as zeroizing values from the secret store;
- command stdout, stderr, and exit status are captured separately;
- absence of an exit status is an error;
- operations have cancellation and timeout guards;
- SFTP uploads set only the requested mode and never request chown;
- no product path invokes the system `ssh` executable.

The transport initially lacks a download operation. OpenVPN certificate
retrieval, protected IKEv2 bundles, and backend-generated public material
require a bounded SFTP download method with the same host-key,
authentication, timeout, cancellation, size-limit, and redaction rules.

The application builds fixed remote scripts and quotes variable paths using a
POSIX single-quote helper. That approach is safe only when every data value
either receives context-appropriate validation or travels as an uploaded file.
New backend JSON, configuration, CSRs, certificates, passwords, UUIDs, and SNI
values must not be interpolated into shell commands.

### 3.9 DNS behavior

CoreDNS currently:

- serves an instance-private authoritative zone;
- synthesizes the gateway record;
- renders enabled desired-state records deterministically;
- supports `A`, `AAAA`, `CNAME`, `TXT`, and `SRV`;
- optionally builds a blocklist from user-configured HTTPS hosts files;
- forwards public DNS using DNS-over-TLS with certificate-name verification.

DNS is coupled to the gateway container with
`network_mode: service:gateway`. This is usable for routed tunnel backends but
must be declared as a capability. An instance that cannot route an allocated
private address to CoreDNS must reject managed device DNS and explain why.

The existing separation between VPN credential refresh and DNS refresh is
intentional. Credential refresh uploads only `vpn/`, restarts only `gateway`,
waits for health, and normalizes ownership afterward. DNS refresh uploads only
`dns/` and restarts only `dns`. The generic model must retain these independent
paths where a backend supports them.

### 3.10 UI and CLI

The Svelte UI has pages for Hosts, VPNs, Devices, DNS, Backups, and Logs.
Instance creation is explicitly labelled WireGuard and shows a single UDP port,
private subnet, DNS zone, and routing mode. Instance rows use a hard-coded `WG`
badge. Device actions say “Replace key”, every device exposes QR, export is
labelled WireGuard, and health labels mention the WireGuard interface and UDP
port.

The TypeScript types accept only `backend: "wire_guard"` and one WireGuard
device payload. The Tauri layer mirrors the Rust service but is otherwise
protocol-neutral.

The `vam-dev` CLI uses the same application service but `instance-add` has no
backend/settings arguments. `info` reports only the WireGuard image. Render
output is redacted correctly.

## 4. Target architecture

### 4.1 Dependency rule

Backend implementations will not perform SSH, access SQLite, use the native
secret store, or call UI code. They will implement a common contract using
typed desired state and opaque secret/material maps.

```text
core models + protocol DTOs
            |
            v
      backend contract
       /   / | \   \
     WG  AWG OVPN IKEv2 Xray
       \   \ | /   /
        backend registry
              |
              v
 ApplicationService + deployment transaction
        |          |          |
      SQLite   SecretStore  verified SSH/SFTP
        ^
        |
   Tauri and CLI
```

This preserves one SSH/deployment implementation and prevents backend code from
bypassing host trust, error interpretation, backup, or redaction.

### 4.2 Common backend contract

The contract will expose, at minimum:

- stable backend kind and display name;
- typed capabilities;
- listener ports with TCP/UDP transport;
- validated backend settings;
- deterministic runtime/container specification;
- deterministic server files;
- client-artifact kind and QR eligibility;
- secret references required for server rendering and client export;
- device identity creation/replace/revoke metadata;
- remote credential reconciliation requirements;
- validation command/specification;
- health probe specification;
- classification of a settings change as live update, service restart, or
  reinstall.

Capabilities are behavioral declarations, not UI decoration. They control DNS
availability, address allocation, QR display, quick credential refresh,
certificate issuance/revocation, traffic statistics, fixed/custom ports, and
whether a backend can apply identity changes live.

### 4.3 Typed settings

The core model will use a tagged backend-settings enum. Proposed settings are:

- **WireGuard:** persistent keepalive and optional userspace fallback;
- **AmneziaWG:** generation (`awg2` initially), keepalive, and validated
  obfuscation fields `Jc`, `Jmin`, `Jmax`, `S1`-`S4`, `H1`-`H4`;
- **OpenVPN:** TCP or UDP, subnet, modern cipher/digest policy, TLS mode, and
  certificate lifetime; no arbitrary raw directive field;
- **IKEv2:** address pool, certificate lifetime, server identity, and modern
  IKE/ESP suites; listener ports fixed to UDP 500/4500 and no L2TP/XAuth;
- **Xray:** typed VLESS security and stream settings, including Reality/TLS,
  SNI, fingerprint, raw TCP/XHTTP/mKCP options, and the selected TCP listener.

All values are serialized structurally. JSON is produced with `serde_json`;
configuration lines are rendered from validated enums/numbers/hostnames rather
than raw user fragments.

### 4.4 Generic device identity

The common `Device` record retains ownership, display name, enable state,
optional managed DNS name, and optional allocated addresses. Its tagged backend
payload will describe:

- WireGuard or AWG public key plus local private-key and unique-PSK references;
- OpenVPN certificate common name, local private-key reference, local CSR
  reference, and issued-material state;
- IKEv2 certificate identity plus protected-PKCS#12 password reference and
  issued-material state;
- Xray client-UUID secret reference, email/label metadata, and optional flow
  metadata.

Private keys, PSKs, PKCS#12 passwords, certificate bundles containing private
keys, and equivalent client credentials remain in native secure storage or
explicit `0600` exports. SQLite contains references and public metadata.

Address allocation stays transactional at the application/storage boundary.
Backends that route a private subnet can use the existing allocator. Backends
without a meaningful tunnel address must not receive fabricated WireGuard
fields; managed DNS is disabled unless the capability and identity data provide
a routable address.

### 4.5 Protocol lifecycle expectations

- **WireGuard:** local keypair, unique PSK per peer by default, deterministic
  peer configuration, enable/disable/revoke/replace/export/QR, live peer apply,
  handshake and transfer health/statistics.
- **AWG2:** the WireGuard identity lifecycle plus matching server/client
  obfuscation parameters and AWG-specific validation/health commands.
- **OpenVPN:** local ECDSA P-256 private key and CSR, upload only the CSR for remote CA
  signing, retrieve CA/client certificate and TLS material, assemble `.ovpn`
  locally, list issued identities, revoke through the CA/CRL, replace by a new
  key/CSR, and never persist private keys remotely.
- **IKEv2:** certificate-based IKEv2 only, modern proposals, fixed UDP
  500/4500, protected PKCS#12 export, explicit issuance/list/revoke/replace,
  and no L2TP or XAuth branches.
- **Xray:** native-stored UUID credential plus public metadata, structured
  server JSON, preserve server-only Reality private material,
  reconcile/list/revoke/regenerate clients, export a client configuration, and
  never perform raw textual JSON replacement.

### 4.6 Remote deployment and fresh-host bootstrap

Host inspection will report the detected package manager from:

- `apt`;
- `dnf`;
- `yum`;
- `zypper`;
- `pacman`.

If Docker Engine or Compose is missing, a deployment preview will include typed
bootstrap operations. Apply will use fixed, idempotent package-manager commands
through passwordless sudo, start/enable Docker where appropriate, and reconnect
before normal deployment. Unsupported platforms or missing noninteractive sudo
will fail before instance mutation with remediation.

Images and downloaded artifacts will use fixed versions. Automatic Watchtower
updates are incompatible with reviewed deterministic plans and will be removed
or disabled. Upgrade is an explicit application operation that previews the
new pins. Downloads, if a selected backend requires them, must be verified
against a pinned SHA-256 value before use.

No backend is privileged by default. Runtime specs must request only concrete
capabilities/devices such as `NET_ADMIN` and `/dev/net/tun`. If a backend truly
requires broader privilege on a supported host, the preview and documentation
must identify that exception.

Firewall rules derive solely from each backend's declared listener set. UFW and
Firewalld operations are idempotent and transport-aware. No generated rule may
globally drop ICMP.

### 4.7 Migration strategy

The migration is additive:

1. add schema-version and backend-settings columns with WireGuard-compatible
   defaults;
2. add normalized active listener reservations keyed by instance, port, and
   transport;
3. backfill every existing active instance as WireGuard UDP using its current
   endpoint port;
4. preserve all `model_json`, deployment snapshots, devices, DNS records,
   secret references, and host deletion constraints;
5. teach deserialization to accept old `wire_guard` and absent settings/schema
   fields;
6. rewrite rows only when they are subsequently saved through the current
   model;
7. prove old-database migration and mixed-backend uniqueness with storage
   tests.

### 4.8 Incremental signed commit sequence

Each functional unit is validated, documented here, staged by exact path, and
committed with the configured signing key via `git commit -S`.

1. architecture dissection and Amnezia SSH report;
2. backend contract, core model, migration, and WireGuard compatibility;
3. AWG2 backend;
4. OpenVPN backend;
5. IKEv2 backend;
6. Xray backend;
7. generic application/deployment/SSH lifecycle;
8. CLI, Tauri, and Svelte surfaces;
9. cross-backend security and regression coverage;
10. final user/operator documentation and verification corrections.

## 5. Validation ledger

The ledger is append-only. A failure is recorded and diagnosed before the next
functional unit proceeds.

### Unit 0: architecture and source dissection

Status: complete.

Inspected:

- workspace manifests and crate dependency direction;
- initial SQL migration and storage CRUD/snapshot behavior;
- core desired-state and device models;
- WireGuard backend trait and renderer;
- deployment rendering, manifest hashing, and planning;
- application host, instance, device, DNS, deployment, backup, rollback,
  export, health, firewall, and secret-retention paths;
- `russh`/SFTP trust, authentication, timeout, cancellation, and exit-status
  behavior;
- Tauri command surface, CLI commands, Svelte models/forms/actions;
- current architecture, deployment, security, and README claims;
- adjacent Amnezia protocol behavior and its documented security gaps.

Expected outcome:

- a complete, source-backed map of current coupling points;
- a coherent staged plan that preserves the existing trust/deployment
  invariants;
- no application code modified before that plan is complete.

Observed outcome:

- the architecture and coupling map above is complete;
- the staged plan is fixed;
- no application code has been modified;
- the pre-existing untracked Amnezia report is the output of the immediately
  preceding source-analysis task and is intentionally included in the first
  documentation commit.

Validation:

- `git diff --check -- AMNEZIA_CLIENT_SSH_VPN_SERVER_PROVISIONING_REPORT.md dissection.md`
  passed;
- all 101 adjacent-source references extracted from the Amnezia report resolve
  to files in `../amnezia-client`;
- the dissection contains 25 uniquely named Markdown headings;
- `git status --short` showed only the two intended untracked documentation
  files before staging.

Commit:

- `c10b71b docs: dissect multi-protocol VPN architecture`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 1: backend contract, typed model, migration, and WireGuard compatibility

Status: complete.

#### Common backend crate

Added `crates/backend` as the protocol-independent backend boundary. Its
`VpnBackend` contract now requires each implementation to declare:

- a stable `VpnBackendKind`;
- behavioral `BackendCapabilities`;
- typed TCP/UDP listeners;
- desired-state validation;
- secret references needed for server rendering;
- secret references needed for client rendering;
- deterministic server files;
- deterministic client artifacts;
- client artifact kind;
- settings-change impact as live update, service restart, or reinstall.

`BackendCapabilities` includes allocated tunnel addresses, managed DNS, quick
credential refresh, live identity updates, QR export, traffic statistics, and
certificate-authority behavior. These flags will gate application and UI
features when the remaining backends are registered.

`BackendRegistry` owns trait objects keyed by the typed enum. The application
constructs one registry and uses it for validation, server rendering, client
rendering, and backend secret discovery. At this point the only registered
implementation is WireGuard, so unsupported enum variants fail with the
structured `BackendError::NotRegistered` instead of falling through to
WireGuard.

Backend code remains pure with respect to infrastructure: it has no SSH,
SQLite, keyring, Tauri, or Svelte dependency.

#### Core model

Expanded `VpnBackendKind` to:

- `WireGuard`;
- `AmneziaWg`;
- `OpenVpn`;
- `Ikev2`;
- `Xray`.

Canonical serialized names are `wireguard`, `amnezia_wg`, `openvpn`, `ikev2`,
and `xray`. Aliases accept historical or likely transitional spellings,
including the existing `wire_guard`. Stable `as_str`, display-name, and
default-port methods prevent ad hoc string formatting in storage and UI
adapters.

Added typed `TransportProtocol` and `ListenerPort`. Instance conflict
validation now compares `(port, transport)` listener pairs. TCP and UDP may
therefore share one numeric port on a host, while two active instances may not
claim the same transport and port. Subnet-overlap validation remains unchanged.

Added a tagged `BackendSettings` enum and typed settings structures for all
five target protocols:

- `WireGuardSettings`;
- `AmneziaWgSettings`, including AWG2 generation and the complete numeric
  obfuscation field set;
- `OpenVpnSettings`, with a typed TCP/UDP transport and modern cipher choice;
- `Ikev2Settings`, with server identity and certificate lifetime;
- `XraySettings`, with typed security/transport, SNI, fingerprint, and XHTTP
  path fields.

There is no arbitrary OpenVPN directive string or raw Xray JSON field. More
specific range and hostname validation belongs to each backend implementation.

`VpnInstance.backend_settings` has a serde default of WireGuard settings.
Consequently, old deployment snapshots and old `model_json` rows deserialize
without an eager rewrite.

Added tagged device identity payloads for WireGuard, AmneziaWG, OpenVPN,
IKEv2, and Xray. Each payload exposes its secret references generically for
snapshot retention. The initial Xray implementation stored its UUID inline;
Unit 11's security audit reclassified that bearer credential and replaced the
inline field with a native-store reference before completion.

`Device.ipv4_address` is now optional. Existing JSON address strings
deserialize as `Some(address)`. WireGuard, AWG, OpenVPN, and IKEv2 validation
require an address; Xray can omit one. The allocator ignores addressless
identities and continues reserving addresses held by disabled devices.

#### Additive SQLite migration

Added `0002_multi_protocol_model.sql`. It:

- adds `instance_schema_version` and `backend_settings_json` to
  `vpn_instances`;
- defaults existing rows to schema 1 and WireGuard settings;
- adds `identity_schema_version` and `backend` to `devices`;
- replaces the numeric-port-only unique index with
  `instance_listeners(instance_id, host_id, port, transport, active)`;
- backfills every existing instance listener as UDP using its current endpoint
  port and deletion state;
- enforces active host/port/transport uniqueness;
- retains address uniqueness only for non-empty addresses, allowing multiple
  addressless identities.

The migration does not drop or recreate any desired-state, deployment,
identity, DNS, host-key, or secret-reference row.

`Storage::save_instance` now performs the instance upsert and listener
replacement in one transaction. It writes the actual backend ID, current
schema version, and typed settings JSON instead of the old hard-coded
`wireguard` value. A listener conflict rolls back the entire save.

`replace_desired_state` uses the same current instance metadata and listener
reservation behavior so rollback cannot bypass the multi-protocol constraints.

Device saves now write the identity backend and schema version. An absent IPv4
address is represented by an empty indexed column while the canonical JSON
retains `null`; the partial unique index excludes that empty representation.

Secret-retention scans now call `DeviceBackendData::secret_references` rather
than destructuring WireGuard. Retained OpenVPN and IKEv2 snapshots will
therefore protect their referenced key/CSR/password material without another
storage change.

#### WireGuard adaptation

Moved `VpnBackend` and `BackendError` out of `backend-wireguard`. The
WireGuard crate now implements the common contract and declares:

- allocated tunnel addresses;
- managed DNS;
- quick credential refresh;
- live identity updates;
- QR export;
- traffic statistics;
- no certificate authority.

It declares one UDP listener, reports server-side PSK references separately
from client-side private-key/PSK references, rejects a mismatched backend
instead of relying on an irrefutable enum, and returns a vector of rendered
server files so other backends can own multiple files.

The existing WireGuard configuration content and remote paths are unchanged.
The application now selects WireGuard through `BackendRegistry` for validation,
server rendering, and client rendering. WireGuard creation and remote
deployment remain WireGuard-only until the subsequent backend and generic
orchestration units.

#### Validation and diagnosis

The first storage compile attempt found one stale test call to
`Option<Ipv4Addr>::to_string`. It was corrected to explicitly unwrap the known
WireGuard fixture address, and the same storage test command then passed.

The first workspace check found the expected direct-construction and exhaustive
matching sites in deployment/application code. Each was converted explicitly;
no wildcard branch silently treats a new backend as WireGuard.

The first strict Clippy pass found one unreadable numeric literal in the
legacy-JSON fixture. It was changed to `2_026_073_001_u64`; the identical lint
command then passed.

Passing checks:

- `cargo test -p vam-core -p vam-backend -p vam-backend-wireguard`: 9 tests;
- `cargo test -p vam-storage`: 9 tests;
- `cargo check --workspace --all-targets`;
- `cargo test --workspace`: 47 tests;
- `cargo fmt --all -- --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`.

The new regression coverage proves:

- old `wire_guard` JSON loads as WireGuard with default settings;
- an actual schema-1 database upgraded by the SQL preserves and loads its old
  instance;
- the migration backfills the WireGuard UDP listener;
- SQLite rejects duplicate active host/port/transport reservations;
- SQLite permits TCP and UDP to share a numeric port;
- existing WireGuard key generation, deterministic server rendering,
  full-tunnel IPv4 behavior, secret-free planning, refresh isolation, host-key
  decisions, backup retention, and application flows still pass.

Commit:

- `1882ad4 refactor: add multi-protocol backend model`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 2: AmneziaWG 2 backend

Status: complete as a pure backend implementation. Application registration
and remote deployment are intentionally deferred to the generic orchestration
unit; registering AWG while Compose and activation still assume WireGuard
would advertise a path that cannot yet work end to end.

#### Source behavior inspected

The implementation was derived from the current adjacent Amnezia source rather
than treating AWG as a renamed WireGuard:

- `../amnezia-client/client/core/installers/awgInstaller.cpp` defines the
  current parameter-generation behavior, including `Jc`, `Jmin`, `Jmax`,
  `S1`-`S4`, the AWG2 ranged `H1`-`H4` representation, padding collision
  avoidance, and a monotonically ordered header-range generator;
- `../amnezia-client/client/server_scripts/awg/configure_container.sh` shows
  the complete server-side AWG field set and confirms that those settings live
  in the interface section;
- `../amnezia-client/client/server_scripts/awg/template.conf` confirms that
  the client must receive the same message padding and header values;
- `../amnezia-client/client/server_scripts/awg/Dockerfile`,
  `start.sh`, and `run_container.sh` identify the userspace implementation,
  `awg`/`awg-quick` tools, TUN requirement, interface naming, and current
  container family;
- the official `amnezia-vpn/amneziawg-go` README documents `Jc`'s recommended
  4-12 range, the `Jmin <= Jmax` rule, MTU-fragmentation risk, padding
  semantics, and ranged-header syntax;
- the official `amnezia-vpn/amneziawg-tools` releases identify ranged-header
  support as the AWG 2 tool generation.

The backend targets AWG 2 only. Historical `awg_legacy` scripts were inspected
but were not copied because the task explicitly prioritizes current AWG and
forbids blindly reintroducing obsolete compatibility paths.

#### Runtime contract extension

The common backend contract now describes the infrastructure a backend needs,
not just the text it renders. `BackendRuntimeSpec` declares:

- the immutable container image reference;
- internal listener ports and transports;
- Linux capabilities;
- device mappings;
- config mounts;
- required sysctls;
- server-identity materialization strategy;
- syntax-validation strategy;
- protocol-aware health probe.

The supporting types are closed enums rather than Compose fragments or shell
strings supplied by a backend. This keeps future generic deployment code in
control of quoting and prevents a backend from silently requesting arbitrary
privileges.

The same runtime method was added to WireGuard so all implementations satisfy
one contract. Its current image remains the pre-existing mutable LinuxServer
reference only as a transitional compatibility value. The deployment
generalization unit will replace the old WireGuard-only Compose constants,
remove Watchtower, and pin all managed runtime images together; doing that
partially in this unit would leave two competing image authorities.

#### AWG2 runtime profile

Added `crates/backend-amneziawg`. The runtime profile uses:

- image
  `amneziavpn/amneziawg-go:2.0.0@sha256:7ee1070c9d0131a3825c9ebc134a7ec474ae6c8ec3efcc01428c2610fc1b69b7`;
- UDP container port `55424`, mapped to the instance's selected host endpoint
  port by the future generic Compose renderer;
- only `CAP_NET_ADMIN`;
- only `/dev/net/tun`;
- one writable instance-scoped `vpn` mount at `/etc/amneziawg`;
- IPv4 forwarding and `src_valid_mark` sysctls;
- `awg` for key materialization and health;
- `awg-quick` for configuration validation and interface lifecycle;
- interface name `awg0`.

The image uses both a human-auditable AWG2 tag and Docker Hub's current
multi-platform digest. That prevents a later registry tag update from changing
deployed code invisibly. No host network mode, privileged mode, Docker socket,
global ICMP filtering, or unrelated capability is requested.

The backend renders `vpn/start-awg.sh` as a deterministic executable. It:

1. selects `amneziawg-go` as the userspace implementation;
2. brings `/etc/amneziawg/awg0.conf` up;
3. remains alive as the container's foreground process;
4. traps `INT` and `TERM`;
5. brings the interface down before exiting.

The first draft used `exec awg-quick up`, but `awg-quick up` is a setup command,
not a long-running daemon. That would have made a successfully configured
container exit immediately. The script was corrected before commit and a
regression assertion now rejects that lifecycle form.

#### Typed AWG2 settings and validation

`AmneziaWgSettings` now models `H1`-`H4` as explicit inclusive
`AmneziaWgMagicRange { min, max }` values. A single integer cannot faithfully
represent the current AWG2 `x-y` syntax.

Safe deterministic defaults are:

| Field | Default |
| --- | ---: |
| `Jc` | 5 |
| `Jmin` | 10 |
| `Jmax` | 50 |
| `S1` | 64 |
| `S2` | 96 |
| `S3` | 32 |
| `S4` | 8 |
| `H1` | 5-999 |
| `H2` | 1000-1999 |
| `H3` | 2000-2999 |
| `H4` | 3000-3999 |

Backend validation rejects:

- a settings/backend discriminator mismatch;
- `Jc` outside the official recommended 4-12 range;
- zero junk-packet size, `Jmin > Jmax`, or a junk maximum above the
  conservative 1280-byte non-fragmenting envelope;
- an `S1`-`S4` padding above 1280 bytes;
- duplicate raw padding values;
- padding combinations that make AWG initiation, response, cookie, or
  transport packet sizes collide after accounting for the base message sizes
  148, 92, and 64 bytes;
- a header range below 5, inverted, or above signed 32-bit maximum;
- header ranges that are out of order, overlapping, or share a boundary;
- missing allocated device addresses;
- a non-AWG device identity or nil PSK reference.

The 1280-byte ceiling is intentionally conservative because the official AWG
documentation warns that fragmenting junk or signature packets produces a
suspicious traffic shape. The adjacent Amnezia generator uses much smaller
padding ranges; the application defaults stay inside those observed values.

#### Identity and secret boundary

AWG peer identities follow the secure WireGuard lifecycle where protocol
semantics permit:

- device private/public keypairs are generated locally with cryptographically
  random WireGuard-format material;
- every device gets a separately generated PSK;
- private keys and PSKs are returned as `Zeroizing<String>`;
- the device model stores only the public key and opaque secret references;
- the server renderer asks only for peer PSKs;
- the client renderer asks for that device's private key and PSK;
- the server public key remains under the instance secret reference;
- client private keys never enter the server artifact.

The server configuration contains a backend-specific private-key sentinel.
Generic remote activation will create the server key on the host, derive its
public key, replace the sentinel in the staged file, and preserve the private
key across ordinary updates. This retains the existing server-private-key
boundary rather than generating or storing it in the frontend.

#### Deterministic server and client rendering

The backend renders `vpn/awg0.conf.template` with:

- the instance gateway and prefix;
- fixed internal UDP port `55424`;
- the complete AWG2 numeric obfuscation set;
- narrowly scoped DNS, forwarding, established-return, and instance-subnet NAT
  rules;
- only enabled, non-deleted peers;
- newline-sanitized peer comments;
- stable peer ordering by allocated address;
- each peer's public key, distinct PSK, and `/32` address.

There is no client private key in this output and there is no shared PSK.

Client rendering mirrors all settings that affect the packet format, then adds
the locally retained private key, device address, instance DNS gateway, server
public key, per-device PSK, endpoint, route set, and keepalive. Split-tunnel
profiles receive only the instance subnet. Full-tunnel profiles receive
`0.0.0.0/0` and do not falsely advertise an IPv6 default route for the current
IPv4-only data plane.

AWG client output is a normal text configuration and declares QR export
support. Settings changes are classified as a service restart; unchanged
settings are a live update.

#### Validation and diagnosis

The first focused format check reported only rustfmt layout differences in the
new AWG file and the WireGuard runtime import list. `cargo fmt --all` corrected
them and the identical check then passed.

The first startup script would have exited after interface creation. The
lifecycle analysis above identified the problem before remote orchestration
used the script; it was changed to a signal-aware foreground loop and tested.

The first source-alignment pass also found that the initial validator did not
reject duplicate raw `S1`-`S4` padding values. The adjacent generator avoids
both raw-value duplicates and final packet-size collisions. The missing check
was added. Official upstream documentation was used to retain the recommended
`Jc` range of 4-12 rather than narrowing it to the adjacent client's current
random generator range of 4-6.

The first compile after that tightening found a single `&u16` versus `u16`
comparison. The iterator value is now explicitly dereferenced, and the exact
AWG test target passed on rerun.

Passing checks after the final source-alignment change:

- `cargo fmt --all -- --check`;
- `cargo test -p vam-backend-amneziawg`: 4 tests;
- `cargo check --workspace --all-targets`;
- `cargo test --workspace`: 52 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `git diff --check`.

The new AWG tests prove:

- deterministic server output;
- client/server obfuscation mirroring;
- absence of client private keys from server output;
- per-peer PSK placement;
- split-tunnel routing;
- startup-script foreground and shutdown behavior;
- invalid packet-size collisions are rejected;
- duplicate raw padding values are rejected;
- overlapping header ranges are rejected;
- the image is version-and-digest pinned;
- runtime privilege is limited to `NET_ADMIN` plus TUN;
- generated keypairs and PSKs are unique and use zeroizing private storage.

Commit:

- `3222d12 feat: add AmneziaWG 2 backend`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 3a: certificate credential lifecycle contract

Status: complete. This is the protocol-independent contract and persisted
identity slice needed before the OpenVPN implementation.

#### Why this is a separate unit

WireGuard and AWG can create a usable peer entirely from locally generated
key material plus a deterministic server-config update. OpenVPN and IKEv2
cannot: a remotely retained certificate authority must issue and revoke
certificates, the application must retrieve resulting artifacts, and CRL
changes must be reloaded.

Encoding those operations as backend-supplied shell fragments would move
quoting, path safety, remote exit handling, and secret handling outside the
existing SSH authority. The common backend contract therefore gained a closed,
typed credential plan. The future application/SSH adapter will translate each
variant into fixed commands and will remain responsible for verified-host
execution, exit status, SFTP, cancellation, redaction, and rollback.

#### Typed credential plan

Added `CredentialAction` with:

- authority initialization;
- issue;
- revoke;
- replacement with an explicit previous identity.

Added `CredentialOperation` variants for:

- idempotent OpenVPN CA/server initialization;
- uploading a named secret reference to a relative remote path with an
  explicit file mode;
- importing a CSR;
- signing a client certificate with an explicit lifetime;
- downloading a CA certificate, client certificate, or TLS-crypt key directly
  into a secret reference;
- reading the issued certificate serial;
- revoking a client certificate;
- regenerating the CRL;
- reloading the gateway.

There is deliberately no `RunShell(String)` escape hatch. Relative paths,
common names, lifetimes, secret references, and artifact roles remain
individually inspectable and validateable.

`VpnBackend::plan_credentials` has a fail-closed default that returns
`UnsupportedCredentialOperation`. WireGuard and AWG therefore cannot
accidentally accept a certificate action. OpenVPN implements the complete plan
in Unit 3b, and IKEv2 can extend the closed operation enum with its own explicit
variants later.

#### Pull and local-build runtime images

Changed `BackendRuntimeSpec.image` from a string to `ContainerImage`:

- `Pull` is for an externally built tag-and-digest reference;
- `Build` identifies a deterministic local tag and a rendered Dockerfile.

WireGuard and AWG are explicitly `Pull` runtimes. OpenVPN is `Build`
because no current, official, maintained OpenVPN Community server image with
Easy-RSA was found. Using the adjacent `amneziavpn/openvpn:2.6.3` image would
freeze an OpenVPN release from more than two years ago. A digest-pinned current
Alpine base with version-pinned packages is the smaller and auditable
alternative.

#### OpenVPN secret model

Added typed `OpenVpnTlsProtection` with secure default `TlsCrypt` and an
explicit `None` choice. The latter will be surfaced as a security tradeoff in
the settings UI rather than inferred from a missing string.

`OpenVpnDeviceData` now retains opaque references for:

- the locally generated private key;
- the locally generated CSR;
- the retrieved client certificate;
- the retrieved CA certificate;
- the optional retrieved TLS-crypt key.

The issued certificate serial remains non-secret model metadata and is
initially absent. Secret-retention enumeration includes every new reference,
so rollback snapshots prevent premature native-store deletion of both locally
created and remotely retrieved credential material.

SQLite still receives only the UUID references in `model_json`; this change
does not add a plaintext-key or certificate column and needs no destructive
migration.

#### Validation

Passing checks:

- `cargo fmt --all -- --check`;
- `cargo test -p vam-core -p vam-backend -p vam-backend-wireguard
  -p vam-backend-amneziawg`: 14 tests;
- `cargo check --workspace --all-targets`;
- `cargo test --workspace`: 53 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`.

The new regression test proves that all five OpenVPN secret references are
retention-visible and that TLS-crypt is the default.

Commit:

- `a4bc758 refactor: model certificate credential lifecycle`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 3b: OpenVPN certificate backend

Status: complete at the backend contract boundary. Local identity generation,
deterministic server/client rendering, runtime declaration, typed CA
operations, change classification, and unit coverage are implemented in
`crates/backend-openvpn`. Registration in the application service, translation
of credential operations into verified SSH commands, generic Compose
generation, and fresh-host integration are intentionally later units. This
distinction matters: the crate is functional and tested, but this commit alone
does not claim that the desktop can provision a live OpenVPN instance.

#### Behavioral reference and retained architecture

The adjacent Amnezia client was used as a behavioral map for:

- Easy-RSA authority initialization and persistent PKI storage;
- a locally generated client key followed by CSR import and signing;
- retrieval of the CA, issued certificate, and static TLS material;
- client enumeration by certificate identity;
- revocation, CRL regeneration, and gateway reload;
- UDP/TCP listener selection and inline `.ovpn` output.

The implementation does not copy Amnezia's raw shell-template substitution,
remote client-private-key generation, raw `docker run`, or mutable/old image
choices. Protocol behavior is represented through `VpnBackend`, rendered
files, `BackendRuntimeSpec`, and the typed `CredentialPlan` introduced in Unit
3a. The existing application/SSH/deployment layers remain the sole future
authority for host trust, authentication, transfer, exit status, timeout,
redaction, snapshots, and rollback.

#### New workspace crate and dependency

Added `crates/backend-openvpn` and registered it as a workspace member. The
crate depends only on existing internal contracts plus `rcgen 0.14.8`,
configured without its default features and with the explicit `crypto`, `pem`,
and `ring` features needed for local key and PKCS#10 request generation.

`Cargo.lock` consequently adds `rcgen`, `ring`, `x509-parser`, ASN.1/DER
parsing support, PEM support, and their transitive dependencies. Cargo also
coalesced several permissive existing Windows dependency edges onto the
already-selected `windows-sys 0.61.2`; no application source was changed to
depend on Windows-specific behavior.

The first dependency resolution attempt could not reach crates.io from the
restricted sandbox. It was repeated with the required network approval and
completed normally. No machine-level package was installed.

#### Local client identity generation

`OpenVpnBackend::generate_identity` creates client identity material locally:

- a new ECDSA P-256 key pair per device;
- a PKCS#8 PEM private key retained in `Zeroizing<String>`;
- a PKCS#10 PEM CSR retained in `Zeroizing<String>`;
- `DigitalSignature` key usage;
- `ClientAuth` extended key usage;
- a deterministic common name derived from the display-name slug and UUID.

The private key never becomes part of server rendering or typed credential
operations. The server receives only the CSR through a `SecretReference`.
This preserves the product rule that client private keys do not need to leave
the local application.

The common name is deliberately narrower than an arbitrary X.509 string. It
must be 1-63 lowercase ASCII letters, digits, or hyphens; must start and end
with an alphanumeric character; and must be unique among active identities.
That makes it safe for Easy-RSA arguments, certificate identity matching, and
CCD filenames without relying on last-minute shell escaping.

The initial `rcgen` compile revealed that `CertificateParams` is
`#[non_exhaustive]`. Construction was corrected to use `Default` followed by
explicit field assignment. A subsequent test compile exposed a mutable borrow
held across server rendering; the mutation was scoped before the render call.
Both failures were diagnosed directly and the exact test target passed after
each fix.

#### Runtime and supply-chain declaration

No current official OpenVPN Community server image containing the required
Easy-RSA workflow was available. The adjacent `amneziavpn/openvpn:2.6.3`
image is materially stale. The backend therefore declares a deterministic
local image build:

- local tag:
  `vpn-appliance-manager/openvpn:alpine3.23.5-openvpn2.6.20-r0-easyrsa3.2.3-r0`;
- Dockerfile path: `vpn/Dockerfile`;
- base:
  `alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40`;
- `openvpn=2.6.20-r0`;
- `easy-rsa=3.2.3-r0`;
- `iptables=1.8.11-r1`.

Both the base image identity and installed package versions are fixed. The
image has no mutable `latest` dependency and does not download an unchecked
archive during the build.

The declared runtime uses:

- only `NET_ADMIN`, not `--privileged`;
- only `/dev/net/tun`;
- a writable per-instance `vpn` mount at `/etc/openvpn` so CA, server identity,
  CRL, CCD files, and allocation state survive container replacement;
- only the container-scoped `net.ipv4.ip_forward=1` sysctl;
- internal port 1194 with the configured TCP or UDP transport;
- the configured external listener port declared separately for host
  firewall and Compose publication;
- an OpenVPN-specific config validation and health probe.

`VpnBackend::runtime` now accepts the typed settings and returns
`Result<BackendRuntimeSpec, BackendError>`. That change is necessary because
OpenVPN's container listener protocol is configuration-dependent. WireGuard
and AWG were updated to fail closed on mismatched settings and retain their
existing pinned pull runtimes.

Docker is not installed in this Windows development environment. The rendered
Dockerfile was inspected and asserted in tests, but an actual image build is
not reported as passing. A Linux/Docker integration fixture must build it
before the live-provisioning milestone.

#### Deterministic server artifacts

The server renderer produces:

- `vpn/Dockerfile`, mode `0644`;
- `vpn/server.conf`, mode `0600`;
- `vpn/start-openvpn.sh`, mode `0700`;
- deterministic directory anchors for `vpn/ccd` and `vpn/requests`;
- one mode-`0600` CCD file for every enabled, non-deleted device.

Devices are sorted by validated common name before CCD rendering. Each CCD
contains an `ifconfig-push` for the address allocated by the shared core and
the instance subnet's actual netmask. Disabled and deleted identities are not
admitted by `ccd-exclusive`.

The server configuration uses:

- TUN with `topology subnet`;
- a fixed container port and the selected `udp` or `tcp-server` transport;
- a persistent CA, server certificate/key, CRL, CCD directory, and IP
  allocation file under `/etc/openvpn`;
- `dh none` with `ecdh-curve prime256v1`;
- an explicit TLS-server role;
- required client certificates and client-auth EKU checking;
- TLS 1.3 as the minimum protocol;
- the preferred OpenVPN certificate profile;
- only AES-256-GCM or ChaCha20-Poly1305 as a typed data cipher;
- SHA-256 control-channel authentication;
- compression disabled;
- CRL enforcement;
- `tls-crypt` by default;
- the managed private DNS gateway;
- full-tunnel redirect plus IPv6 blocking, or a subnet-specific split route.

There is no `duplicate-cn`, no password-only authentication, and no
unvalidated custom OpenVPN directive field. Client private keys are absent
from every server artifact.

`tls-crypt` version 1 uses shared group material. It hides and authenticates
the control channel and is materially stronger than an unprotected control
channel, but compromise of one exported profile exposes that shared static
key. It is the current typed default because it matches the requested
retrievable TLS-material lifecycle. A future `tls-crypt-v2` mode would improve
per-client key isolation and should be added as its own typed setting and
credential operations rather than silently changing file semantics.

#### Idempotent container networking

The rendered entrypoint:

- uses `set -eu`;
- checks every iptables rule with `iptables -C` before insertion;
- permits ingress from `tun0`;
- permits only established/related return traffic toward `tun0`;
- masquerades only the configured VPN subnet through `eth0`;
- starts OpenVPN as a tracked foreground child;
- traps normal termination signals;
- removes only the rules it owns on shutdown;
- waits for the actual OpenVPN process and returns its result.

It does not call `killall`, flush a table, alter unrelated host sysctls, or
globally block ICMP. Repeated starts do not accumulate duplicate rules.

#### Client profile export

`.ovpn` profiles are rendered only in Rust and only after all required secret
references have been resolved. Before embedding, the renderer validates and
extracts exactly one expected PEM block for:

- the local PKCS#8 private key;
- the issued client certificate;
- the CA certificate.

When selected, it also validates the exact OpenVPN static-key fence and
hex-only body before emitting an inline `<tls-crypt>` block. Comments or
unexpected data surrounding validated material are discarded. Missing,
mismatched, nil, malformed, or unexpected TLS references fail closed.

Profiles include:

- the configured endpoint host and external port;
- `udp` or `tcp-client`;
- UDP-only `explicit-exit-notify 1`;
- server certificate role verification;
- exact generated server common-name verification;
- TLS 1.3 minimum and the selected modern data cipher;
- `auth-nocache`;
- compression disabled;
- full- or split-tunnel routes;
- the private DNS gateway;
- inline CA, client certificate, local private key, and optional TLS key.

Endpoint hosts are accepted only when they parse as an IP address or pass a
strict DNS-name validator. Newlines, whitespace, shell/config metacharacters,
empty labels, and overlong labels are rejected, preventing a hostname from
injecting additional OpenVPN directives.

The generated profile is returned through the backend's secret-bearing
`ClientArtifact` boundary. It is not a DTO exposed to Svelte. The application
export adapter remains responsible for writing it directly to a user-selected
path.

#### CA, issue, revoke, and replacement plans

Authority initialization declares:

- an instance-derived CA common name;
- an instance-derived server common name;
- a 3,650-day CA lifetime;
- the configured client/server certificate lifetime;
- a 3,650-day CRL lifetime;
- whether a `tls-crypt` key is required.

Client certificate lifetime is validated to 30-825 days. CA and CRL lifetimes
are explicit operation fields rather than hidden Easy-RSA environment
defaults.

Issuance is ordered as:

1. upload the local CSR reference with mode `0600`;
2. import the CSR under the validated common name;
3. sign it as a client certificate for the configured lifetime;
4. download the certificate directly into its secret reference;
5. download the CA certificate directly into its secret reference;
6. when configured, download the static TLS key directly into its reference;
7. read the issued serial as non-secret identity metadata.

Revocation is ordered as certificate revocation, CRL regeneration with the
explicit lifetime, then gateway reload.

Replacement first completes issuance and retrieval of the new identity. Only
then does it revoke the validated previous identity, regenerate the CRL, and
reload. A signing or retrieval failure therefore cannot revoke the currently
working identity first.

The operation list is declarative. No Easy-RSA command string or remote path
derived from unchecked user input enters the backend result. The later SSH
adapter must implement every variant with fixed argument-safe commands, check
the real remote exit code, and perform downloads directly into the native
secret store.

#### Capabilities and update impact

The backend advertises routed address allocation, managed DNS, live identity
updates, traffic statistics, and a certificate authority. It intentionally
does not advertise quick peer refresh or QR export.

Settings change impact is conservative but not destructive:

- unchanged settings and certificate-lifetime-only changes are live-update
  class;
- cipher, transport, and TLS-protection changes require a service restart;
- changing to or from another backend kind is reinstall class.

Transport and TLS-protection changes were initially classified as reinstall.
Review found that neither rotates the CA or requires rebuilding the image.
They were corrected to service restart and covered by a regression test so
the future planner will not present those safe changes as destructive
reinstalls.

#### Validation and failure history

The backend rejects:

- backend/settings/device variant mismatches;
- invalid instance networks or device address allocation;
- certificate lifetimes outside 30-825 days;
- unsafe or duplicate active common names;
- nil secret references;
- missing or unexpected `tls-crypt` references;
- malformed certificate serials;
- endpoint hosts that could inject config;
- missing or malformed client export material.

Development checks deliberately stopped on each failure:

1. the restricted network prevented crates.io resolution; dependency fetching
   was rerun only after approval;
2. `rcgen` non-exhaustive construction failed compilation and was replaced by
   explicit post-default field assignment;
3. a test borrow crossed a render call and was scoped correctly;
4. strict clippy rejected field reassignment after `Default`, so fixtures were
   changed to struct-update construction;
5. the new TCP/full-tunnel test first failed formatting, so the formatter ran
   before any behavioral check continued;
6. strict clippy rejected an implicit test-only `Default` type, so
   `WireGuardSettings::default()` was named explicitly.

Passing checks after the final code change:

- `cargo fmt --all -- --check`;
- `cargo test -p vam-backend-openvpn`: 8 tests;
- `cargo clippy -p vam-backend-openvpn --all-targets -- -D warnings`;
- `cargo check --workspace --all-targets`;
- `cargo test --workspace`: 61 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`.

The OpenVPN tests prove:

- unique local ECDSA keys and PKCS#10 CSRs;
- deterministic server rendering;
- pinned local-build inputs and least container privilege;
- dynamic TCP/UDP runtime declarations;
- fixed CCD address rendering;
- no client private keys in server files;
- modern TLS/cipher/compression policy;
- split-tunnel UDP profiles with TLS protection;
- full-tunnel TCP profiles without TLS protection;
- UDP-only exit notification;
- correct issue/revoke/replacement ordering;
- issue-before-revoke replacement safety;
- injection, common-name, and secret-reference rejection;
- non-destructive transport/TLS change classification.

Remaining validation before OpenVPN can be called provisionable:

- implement typed credential operations in the verified SSH executor;
- teach generic Compose rendering to build this local image and map the
  selected TCP/UDP host listener;
- integrate persistent PKI paths into snapshots, backups, and restore;
- validate Easy-RSA initialization/sign/revoke/CRL commands in a disposable
  Linux Docker fixture;
- build the Dockerfile and run config validation;
- exercise health, statistics, CA persistence, revoke, replacement, image
  upgrade, rollback, custom port, and both transports end to end;
- wire secret-store creation/retrieval and direct export through application,
  CLI, and desktop boundaries.

Commit:

- `96ec7a9 feat: add OpenVPN certificate backend`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 4 plan: IKEv2 certificate backend

Status: implementation plan complete. No IKEv2 code is changed in this planning
unit.

#### Reference findings

The adjacent Amnezia implementation uses a Libreswan-derived mutable
`amneziavpn/ipsec-server:latest` image, starts the container privileged, and
combines three different products in one script:

- certificate-authenticated IKEv2;
- L2TP/IPsec with a shared secret;
- XAuth/PSK.

It generates a 3,072-bit RSA CA, server certificate, and client certificates
inside the container's NSS database. The configurator then exports each client
private key in a PKCS#12 bundle with an empty password. Its proposals include
SHA-1 compatibility branches, its Apple profile disables revocation checking,
and the examined client-management path has no complete certificate revocation
flow.

Only the useful protocol behavior will be retained:

- fixed UDP listeners 500 and 4500;
- a persistent server CA and server certificate;
- certificate-authenticated IKEv2;
- client certificate issue and export;
- address-pool and DNS configuration;
- NAT traversal;
- certificate revocation.

L2TP, XAuth, shared-password authentication, passwordless PKCS#12 export,
mutable images, privileged mode, SHA-1 proposals, and disabled revocation are
explicitly out of scope.

#### Server implementation choice

Use strongSwan with its current `swanctl`/VICI configuration model instead of
Amnezia's Libreswan/NSS script. The planned deterministic local image is:

- the same digest-pinned Alpine 3.23.5 base used by OpenVPN;
- `strongswan=5.9.14-r3` from Alpine 3.23;
- `iptables=1.8.11-r1`;
- no unverified downloads;
- no mutable image tag.

Alpine's strongSwan package includes `charon`, `swanctl`, and `pki`. The image
will run the IKE daemon directly, wait for the VICI socket, load declarative
credentials/connections with `swanctl --load-all --noprompt`, and track the
real foreground daemon. It will not start systemd, OpenRC, or a legacy
`ipsec.conf` starter inside the container.

The runtime should require only:

- `NET_ADMIN`;
- fixed UDP 500 and 4500 publication;
- a writable per-instance `ikev2` mount at `/etc/swanctl`;
- container-scoped IPv4 forwarding.

It should not require `--privileged`, `/dev/ppp`, `/dev/net/tun`, a host
`/lib/modules` mount, IKEv1 kernel modules, or unrelated host sysctls. NAT-T
will be forced so ESP remains encapsulated in UDP 4500 through the Docker
publication boundary.

This is a design assumption until a disposable Linux Docker fixture proves
the complete IKE/XFRM data path. If the fixture demonstrates that a Docker
bridge cannot preserve the required IKEv2/NAT-T behavior on supported hosts,
the correction must be an explicit backend runtime/network mode with a
documented port-conflict model, not a silent move to privileged host
networking.

#### PKI and client identity

Use an online, instance-scoped strongSwan CA retained only in durable remote
storage and covered by backup/rollback. This is a pragmatic appliance design:
an offline root plus online intermediate is stronger, but would require an
external CA workflow beyond this product's self-provisioning scope. The remote
CA key must never enter SQLite, application logs, client exports, or the
frontend.

Use ECDSA P-384 with SHA-384 for:

- the remote CA;
- the remote server certificate;
- locally generated client private keys and CSRs.

P-384 is accepted by current Windows IKEv2 clients and meets strongSwan's
preferred ECDSA strength. Every server certificate must include:

- `serverAuth`;
- the IKE intermediate EKU where supported;
- the configured server identity as a subject alternative name;
- both DNS-name and IP-address SAN forms when the configured identity is an IP
  address, because Windows matches IP endpoints through a DNS SAN while other
  clients use the IP SAN.

Every locally generated client CSR must include:

- a strict instance-unique identity as common name;
- the same value as a DNS SAN so native Windows identity matching succeeds;
- `DigitalSignature`;
- `ClientAuth`.

Client private keys stay local. Only a CSR secret reference is uploaded for
signing. The native secret store retains opaque references for the local
private key and CSR, downloaded client and CA certificates, and the generated
PKCS#12 password. The password-protected bundle itself is generated only for
an explicit export and is held transiently in zeroizing binary memory.

#### Binary secret export boundary

The existing `ClientArtifact.contents: String` can represent WireGuard,
AmneziaWG, and OpenVPN text but cannot safely represent a binary PKCS#12
bundle. Before the backend, change the internal artifact payload into a closed
text-or-binary type:

- text held by `Zeroizing<String>`;
- binary held by `Zeroizing<Vec<u8>>`;
- redacted `Debug`;
- skipped entirely during Serde serialization;
- explicit `as_text` and `as_bytes` accessors.

QR generation must reject binary artifacts even if called incorrectly.
Direct file export must write either variant as bytes with the existing
private-file permissions. The payload and password must never be serialized
through Tauri.

Use the pure-Rust `p12-keystore` crate rather than adding an OpenSSL system
dependency that would differ across Windows, macOS, and Linux. The planned
bundle contains the PKCS#8 P-384 client key, issued client certificate, and CA
certificate. It will use:

- PBES2/PBKDF2-HMAC-SHA-256 with AES-256;
- HMAC-SHA-256 integrity;
- 600,000 encryption KDF iterations;
- 600,000 MAC KDF iterations;
- a non-empty high-entropy generated password.

The iteration count follows the current OWASP PBKDF2-HMAC-SHA-256 work factor
and must be profiled locally. It is an export-time cost, not a server login
cost.

StrongSwan documents that some Apple and Android importers require legacy 3DES
PKCS#12 encryption. The secure default will not silently downgrade for that
compatibility. If testing proves a supported client requires legacy export,
that must become a separately named, explicit compatibility choice with a
warning and test coverage.

The current artifact interface has no safe way to disclose a generated bundle
password to a person without moving it through Svelte. The backend unit will
retain the password only by secret reference and prove protected bundle
generation. The later application/export unit must design an explicit native
export/recovery path—such as a separately confirmed private sidecar or
OS-native secret interaction—before the desktop claims end-to-end IKEv2
export. It must not place the password in a normal DTO or log.

#### Fixed per-device virtual addresses

The common product model assigns a private IPv4 address to routed devices and
uses it for managed DNS. A single dynamic strongSwan pool would break that
invariant because a certificate could receive a different address after
reconnect.

Render one IKEv2 connection and one single-address pool per enabled device:

- remote certificate identity is fixed to the device identity;
- the pool contains exactly the core-allocated device IPv4 address;
- the pool pushes the instance CoreDNS gateway;
- disabled/deleted identities are absent from desired configuration.

This retains deterministic address allocation and per-device DNS without an
additional SQL lease database. The disposable integration fixture must prove
that strongSwan selects the identity-specific connection after certificate
authentication and assigns the one-address pool. If it does not, the
alternative is a typed strongSwan SQL lease store covered by backup—not a
return to untracked dynamic addresses.

#### StrongSwan policy

Render only IKEv2 (`version = 2`) with certificate authentication. Planned
defaults:

- ECDSA SHA-384 authentication;
- AES-256-GCM IKE and ESP proposals with SHA-384 PRF and ECP-384;
- an AES-256/SHA-384/ECP-384 non-AEAD fallback only where the proposal syntax
  requires it;
- no DES, 3DES, RC4, NULL, MD5, SHA-1, MODP-1024, PSK, EAP-password, XAuth,
  or IKEv1;
- PFS for child-SA rekeys;
- fragmentation, MOBIKE, DPD, and forced UDP encapsulation;
- strict local CRL enforcement.

Full tunnel uses `0.0.0.0/0` as local traffic selectors. Split tunnel uses the
instance VPN subnet. IPv6 is not advertised by this first backend and client
metadata must state that IPv6 is not routed.

The entrypoint firewall will add only checked, backend-owned rules for:

- policy-decapsulated traffic from the instance subnet;
- established policy traffic back to the subnet;
- masquerade for subnet traffic not leaving under an IPsec policy.

Every rule will use `iptables -C` before insertion and be removed on shutdown.
The script must not flush tables, append a host-wide final DROP, or alter ICMP.

#### Typed credential lifecycle

Extend `CredentialOperation`, without adding raw shell strings, for:

- idempotent IKEv2 CA/server/empty-CRL initialization;
- signing a validated client CSR;
- revoking a certificate by validated serial while atomically extending the
  retained CRL;
- reloading strongSwan credentials/connections;
- terminating active SAs for a revoked identity.

Issue plan:

1. upload only the CSR reference at mode `0600`;
2. sign it with clientAuth, its identity SAN, P-384/SHA-384, and the configured
   lifetime;
3. download the issued certificate into its secret reference;
4. download the CA certificate into its secret reference;
5. read the certificate serial.

Revoke plan:

1. require an issued certificate serial;
2. extend and atomically replace the CRL;
3. reload credentials/connections;
4. terminate active SAs for the identity after the new CRL is active.

Replacement must issue and retrieve the new credential before revoking the
old serial. `CredentialAction::Replace` therefore needs optional previous
certificate-serial metadata in addition to the previous identity string.
OpenVPN will continue to use only the identity; IKEv2 will require both.

#### Planned validation and functional units

Unit 4a:

- zeroizing binary/text artifact payload;
- QR rejection and byte-safe application export;
- expanded backward-compatible IKEv2 secret-reference model;
- typed IKEv2 credential operations and replacement serial;
- secret-retention and regression tests;
- signed commit.

Unit 4b:

- `crates/backend-ikev2`;
- local P-384 key/CSR and high-entropy password generation;
- deterministic pinned runtime, strongSwan config, fixed pools, firewall
  entrypoint;
- issue/revoke/replace plans;
- protected PKCS#12 creation and wrong-password tests;
- validation/change-impact tests;
- full workspace checks and signed commit.

Later integration units:

- translate every typed IKEv2 operation into fixed verified-SSH execution;
- build/run on a disposable Linux Docker host;
- prove UDP 500/4500, XFRM, NAT-T, custom host constraints, full/split routing,
  fixed address selection, DNS, CRL rejection, active-SA termination,
  persistence, image update, backup, and rollback;
- add explicit password recovery/export UX without exposing it to Svelte;
- add CLI and desktop capability-aware flows.

Commit:

- `8827773 docs: plan secure IKEv2 backend`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 4a: binary artifact and IKEv2 credential contract

Status: complete. This unit changes the secret-bearing export boundary and
credential model required by the IKEv2 backend without implementing strongSwan
behavior.

#### Zeroizing text-or-binary client artifacts

Replaced `ClientArtifact.contents: String` with
`ClientArtifactPayload`, a closed internal enum:

- `Text(Zeroizing<String>)`;
- `Binary(Zeroizing<Vec<u8>>)`.

The payload offers only explicit operations:

- `as_text()` returns `None` for binary data;
- `as_bytes()` supports private file export for both forms;
- `is_binary()` permits capability/error decisions;
- `ClientArtifact::text` and `ClientArtifact::binary` make construction
  explicit at each backend.

Its custom `Debug` implementation reports only payload kind and byte length,
with contents shown as `[REDACTED]`. Serde skips the entire field in both
directions, so text configurations and future PKCS#12 bytes cannot be returned
by a Tauri command merely because an internal artifact is serialized. The
default used when deserializing skipped metadata is an empty zeroizing text
payload.

WireGuard, AWG, and OpenVPN now construct text artifacts through the explicit
constructor. Their tests obtain text through `as_text()` rather than assuming
every future backend is UTF-8.

The application QR path now fails with `qr_not_supported` when it receives a
binary artifact. It does not reinterpret arbitrary certificate bytes as text
or pass them into the QR encoder. The remediation directs the caller to the
private-file export. The direct export path uses `as_bytes()` and retains the
existing private file creation semantics.

`vam-protocol` now depends on the already-pinned workspace `zeroize` crate and
uses the already-present `serde_json` only for its regression test. No new
runtime crypto or platform dependency was introduced in this sub-unit.

The new protocol regression test proves:

- text and binary access are distinct;
- bytes are preserved;
- text and binary secret markers do not appear in debug output;
- neither payload appears in serialized `ClientArtifact` metadata.

#### Backward-compatible IKEv2 device material

Expanded `Ikev2DeviceData` with optional opaque references for:

- the local PKCS#8 client private key;
- the local PKCS#10 CSR;
- the downloaded client certificate;
- the downloaded CA certificate.

The existing required `bundle_password_ref` and optional certificate serial are
retained. Each new field uses `#[serde(default)]`, so device JSON written by the
earlier multi-backend model—with only identity, password reference, and
serial—continues to deserialize. Missing references mean the credential has
not yet been issued; the IKEv2 backend will reject export or credential actions
that require absent material.

`DeviceBackendData::secret_references` now retains the password and every
present IKEv2 key/CSR/certificate reference. SQLite still stores only these
UUID references in `model_json`; no certificate or private material is added
to the database.

The new core regression test proves both:

- old IKEv2 JSON backfills all four new fields to `None`;
- a fully issued identity exposes all five secret references to snapshot
  retention.

#### Typed IKEv2 credential operations

Added `CertificateKeyAlgorithm` with explicit P-256/SHA-256 and
P-384/SHA-384 values. The IKEv2 backend will select only P-384/SHA-384; the
P-256 value makes the contract capable of describing the existing OpenVPN
policy without a future stringly typed algorithm field.

Added closed `CredentialOperation` variants for:

- `InitializeIkev2Authority`, including CA common name, server identity, key
  algorithm, CA/certificate/CRL lifetimes;
- `SignIkev2Client`, including identity, relative CSR path, lifetime, and key
  algorithm;
- `RevokeIkev2Client`, including identity, certificate serial, and CRL
  lifetime;
- `TerminateIkev2Identity`, making active-SA termination part of revocation
  instead of an output-string heuristic.

The existing generic upload, download-to-secret, serial-read, reload, and plan
types remain shared. There is still no arbitrary command or shell-text
operation.

`CredentialAction::Replace` now carries
`previous_certificate_serial: Option<String>` alongside the previous identity.
OpenVPN intentionally ignores the optional serial and retains its common-name
revocation flow. Its replacement regression fixture explicitly supplies
`None`. IKEv2 will require and validate `Some(serial)` before planning a
replacement.

#### Validation

The first focused gate passed without a code or test failure:

- `cargo fmt --all -- --check`;
- `cargo test -p vam-protocol -p vam-core -p vam-backend
  -p vam-backend-wireguard -p vam-backend-amneziawg
  -p vam-backend-openvpn -p vam-application`: 35 tests;
- strict clippy over the same packages and all targets with `-D warnings`.

Full workspace validation also passed:

- `cargo check --workspace --all-targets`;
- `cargo test --workspace`: 63 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo fmt --all -- --check`;
- `git diff --check`.

Staged-patch inspection follows before the signed commit.

Commit:

- `d945f5d refactor: support protected binary client exports`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 4b: secure IKEv2 certificate backend

Status: implementation and local static validation complete. Runtime behavior
on a real Linux Docker host remains an explicit later integration gate.

#### Backend boundary and dependencies

Added `crates/backend-ikev2` as an independent implementation of the shared
`VpnBackend` contract. The crate does not call SSH, Docker, SQLite, Tauri, or
the operating-system keychain. It receives typed desired state and resolved
secret references, validates them, then produces:

- a pinned local image/runtime specification;
- deterministic strongSwan `swanctl` configuration;
- a narrowly scoped idempotent container entrypoint;
- typed CA/client credential-operation plans;
- password-protected binary PKCS#12 client artifacts.

The only new direct runtime dependency is `p12-keystore 0.3.1`. Workspace
configuration sets `default-features = false`, deliberately excluding its
legacy PBES1 feature. PKCS#12 output is configured explicitly for PBES2 with
AES-256, HMAC-SHA-256, and 600,000 derivation iterations for both encryption
and MAC material.

The first dependency-resolution attempt failed because the restricted sandbox
could not reach crates.io. The approved retry downloaded and locked the exact
dependency graph, after which the empty crate and then the complete backend
compiled. This was an environment/network failure, not ignored as a test
failure.

`p12-keystore` redacts its private-key type's `Debug` output, but its internal
key representation owns a normal `Vec<u8>` and does not promise zeroization.
The backend zeroizes decoded PEM/DER buffers and the returned artifact bytes,
and scopes the keystore object to the builder function, but it cannot prove
that the library's internal cloned key buffer is erased before deallocation.
This is a documented residual in-process memory tradeoff. Replacing it would
require a different audited PKCS#12 implementation or an upstream zeroization
change, not an unsafe local workaround.

#### Local client identity generation

`Ikev2Backend::generate_identity` creates client material locally:

- an ECDSA P-384/SHA-384 key in PKCS#8 PEM;
- a PKCS#10 CSR containing the normalized per-device identity as both common
  name and DNS subject-alternative name;
- `digitalSignature` key usage and `clientAuth` extended key usage;
- a nonempty 64-character lowercase hexadecimal bundle password made from two
  independent UUIDv4 values.

The identity includes the device UUID so display-name collisions cannot become
credential collisions. Returned key, CSR, and password values use
`Zeroizing<String>`. Tests generate two identities and prove distinct private
keys, CSRs, identities, and passwords, plus the required P-384 CSR algorithm.

The password contains approximately 244 bits of UUIDv4 randomness. It is never
embedded in model JSON or a client artifact's serializable metadata. The later
application integration must persist it under the existing native
`bundle_password_ref` and provide a deliberate native recovery/export
interaction; it must not expose the password to the Svelte webview.

#### Pinned strongSwan runtime

The backend declares a local image named
`vpn-appliance-manager/ikev2:alpine3.23.5-strongswan5.9.14-r3`. Its rendered
Dockerfile:

- pins the Alpine 3.23.5 base by SHA-256 digest;
- installs exact `strongswan=5.9.14-r3` and `iptables=1.8.11-r1` packages;
- copies only the backend entrypoint;
- exposes UDP 500 and UDP 4500;
- starts through the explicit entrypoint.

The runtime contract requests only `NET_ADMIN`. It does not request
`privileged`, `SYS_MODULE`, `/dev/net/tun`, PPP devices, or host module mounts.
It mounts the backend configuration under `/etc/swanctl`, enables IPv4
forwarding, uses a dedicated restart policy, and describes the CA directory as
durable data requiring backup. The listener set is always exactly UDP 500 and
UDP 4500. Instance endpoint validation rejects a custom IKE port instead of
rendering a configuration that cannot satisfy native client/NAT-T behavior.

This unit does not prove that the pinned image can build or that Alpine's
strongSwan file layout and charon path match the entrypoint: Docker is not
installed in the current Windows environment. Those remain hard Linux fixture
requirements, not inferred successes.

#### Desired-state validation

The backend validates the shared model and IKEv2-specific invariants before
rendering:

- the instance and settings both select IKEv2;
- the instance network and DNS configuration pass core validation;
- endpoint port is exactly 500;
- server identity is a syntactically valid DNS name or IP address;
- client-certificate lifetime is between 30 and 825 days;
- every device uses IKEv2 data and has an allocated IPv4 address;
- every enabled client identity is nonempty, normalized, and unique;
- private-key, CSR, client-certificate, CA-certificate, and bundle-password
  references all exist in issued device data;
- certificate serials, when present, are nonempty hexadecimal strings.

Legacy IKEv2 JSON can still deserialize with absent optional references, but
render/export/credential operations reject such incomplete records until the
application credential bootstrap fills them. This keeps schema migration
compatible without treating missing credentials as usable.

Changing the server identity is classified as `Reinstall`, because it requires
new server certificate material. Changing the client lifetime is classified
as a live configuration update. The test suite fixes both expectations.

#### Deterministic `swanctl` configuration

The renderer sorts enabled devices by UUID, then emits one IKEv2 connection and
one single-address `/32` pool per device. The fixed pool preserves the
application's established invariant that a device's allocated VPN address also
drives its managed DNS records and health expectations. Device connection and
pool names use a collision-resistant UUID prefix rather than display names.

Each connection uses:

- IKEv2 only (`version = 2`);
- ECDSA certificate authentication;
- the configured server certificate and strict CA/CRL trust anchors;
- explicit modern IKE and ESP proposal sets with P-384 ECDH and PFS;
- fragmentation, MOBIKE, DPD, and forced UDP encapsulation;
- the per-device remote identity and fixed pool;
- configured VPN DNS servers;
- either the VPN subnet or `0.0.0.0/0` as the local traffic selector.

No IKEv1, XAuth, EAP-password, PSK, DES/3DES, RC4, NULL, MD5, SHA-1, or weak
MODP proposal is rendered. The backend currently supports IPv4 routing only;
client artifact metadata warns that IPv6 is not routed. Tests compare sorted
output, modern algorithms, strict CRL behavior, fixed pools, split selectors,
and full-tunnel selectors.

The one-connection-per-device selection behavior, virtual-IP assignment, and
client interoperability still require a live strongSwan test. Static rendering
cannot prove how charon chooses otherwise-similar certificate connections.

#### Idempotent entrypoint and firewall scope

The rendered entrypoint:

- fails immediately on command errors;
- adds only backend-owned policy-aware forwarding and masquerade rules;
- checks each rule with `iptables -C` before insertion;
- records which rules it inserted and removes only those rules on exit;
- never flushes tables or installs a host-wide terminal policy;
- launches charon in the foreground and tracks its PID;
- waits for VICI readiness before `swanctl --load-all --noprompt`;
- tears down charon and its own rules if loading fails;
- propagates charon's exit status after cleanup.

The start script intentionally fails when the CA/server certificate/CRL has not
been initialized. The later application planner must execute
`InitializeIkev2Authority` against durable storage before bringing the service
up. It must not mask the missing-credential failure with placeholder files.

Policy matching, XFRM state, Docker bridge forwarding, NAT-T, shutdown signal
handling, and coexistence with an active host firewall remain Linux fixture
tests. The script test proves command shape and absence of broad flush or
privileged behavior, not kernel-level correctness.

#### Typed certificate lifecycle

The backend produces only the closed credential operations added in Unit 4a.
Initialization requests P-384/SHA-384 CA/server material with the configured
server identity, ten-year CA and CRL lifetimes, and the configured client
lifetime.

Issue ordering is:

1. upload the locally generated CSR at mode `0600`;
2. sign it as a P-384/SHA-384 IKEv2 client certificate;
3. download the certificate into its opaque secret reference;
4. download the CA certificate into its opaque secret reference;
5. read and retain the certificate serial;
6. reload strongSwan credentials and connections.

Revoke ordering is:

1. require and validate the issued serial;
2. extend the retained CRL;
3. reload credentials and connections;
4. terminate active SAs for the revoked identity only after the new CRL is
   active.

Replacement issues and retrieves the new credential before revoking the old
serial, then reloads and terminates the old identity. Tests assert operation
types and order for issue, revoke, and replacement. No shell command is carried
inside the plan; the later SSH integration must translate each variant to a
fixed, validated command template.

#### Protected PKCS#12 export

Client export resolves the five opaque secret references, verifies that the
stored password is nonempty, decodes only expected PEM labels, and packages:

- the local PKCS#8 private key;
- the issued leaf certificate;
- the CA certificate, ordered as the root of the chain.

The result is `ClientArtifactPayload::Binary`, suggests a normalized `.p12`
filename, and never becomes a QR payload. The focused regression fixture now
uses an actual CA-signed client certificate. Strict re-import proves that the
private-key chain contains the leaf and CA, and that the correct password
succeeds while a wrong password fails.

This export intentionally refuses the legacy 3DES PKCS#12 fallback sometimes
needed by older Apple/Android importers. Compatibility must become an explicit
future policy with a conspicuous security tradeoff; it will not silently weaken
every exported bundle.

#### Validation

The first focused run stopped after one test failure: strict PKCS#12 re-import
returned a one-certificate chain instead of the expected leaf plus CA. The
implementation was already including both certificates; the fixture had
self-signed the client certificate, so chain construction correctly could not
associate its issuer with the separate CA. The fixture was corrected to have
the CA sign the client certificate, after which all eight backend tests passed.

The next focused run stopped at two clippy findings—an unnecessary raw-string
delimiter and an explicit elidable lifetime. Both were corrected without
changing behavior.

The complete gate then passed:

- `cargo fmt --all` and `cargo fmt --all -- --check`;
- `cargo test -p vam-backend-ikev2`: 8 tests;
- `cargo clippy -p vam-backend-ikev2 --all-targets -- -D warnings`;
- `cargo check --workspace`;
- `cargo test --workspace`: 71 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`.

Still unvalidated because the necessary runtime is unavailable:

- building the pinned IKEv2 image;
- Compose build-context wiring;
- strongSwan startup and `swanctl --load-all`;
- CA/server initialization and persistence;
- real Windows, Apple, Android, and strongSwan-client imports;
- UDP 500/4500 reachability, NAT-T, XFRM, fixed-address selection, DNS,
  full/split routing, CRL enforcement, and active-SA termination;
- backup, restore, image update, rollback, and host-firewall coexistence.

Commit:

- `3975881 feat: add secure IKEv2 certificate backend`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 5 plan: Xray/VLESS backend

Status: implementation plan complete. No Xray model or backend code is changed
in this planning sub-unit.

#### Reference behavior and deliberate differences

The adjacent Amnezia checkout provisions Xray by:

- building a custom Alpine image;
- downloading Xray-core `v25.8.3`;
- running the container privileged with `NET_ADMIN`;
- publishing the selected server TCP port;
- creating a TUN character device even though its VLESS proxy configuration
  does not use a TUN inbound;
- generating one UUID, an X25519 REALITY keypair, and a random short ID inside
  the container;
- writing the server JSON with a shell heredoc;
- reading public REALITY material back over SSH for client export;
- parsing and structurally changing server JSON for user addition/removal, then
  restarting the container.

The current Amnezia configurator is materially better than its original shell
template: Qt JSON objects preserve existing REALITY private material, add or
remove UUID users structurally, build raw/XHTTP/mKCP stream settings, read
public key files, and produce native client JSON/VLESS links. However, the
checked-in image and scripts still contain behaviors this project must not
copy:

- the Xray ZIP is downloaded without digest verification;
- the Alpine base is old and unpinned by digest;
- the image runs privileged even though this VLESS proxy needs neither TUN nor
  network administration;
- container INPUT rules are hard-coded to ports 80 and 443 while Docker may
  publish an arbitrary selected port;
- the entrypoint applies broad DROP policies, kills processes, and tails
  forever instead of making Xray the supervised process;
- unrelated host/container TCP and sysctl tuning is applied;
- initial JSON is composed by unescaped shell interpolation.

VPN Appliance Manager will reuse the useful behavioral model—remote-only
REALITY identity, UUID users, structured JSON, explicit restart, public-material
retrieval—but implement it through deterministic Rust rendering and the
existing verified-SSH/deployment boundaries.

#### Frozen server software and integrity policy

The first backend will deliberately pin the exact Xray-core version used by
the inspected adjacent checkout, `v25.8.3`, rather than silently adopting a
newer protocol/configuration schema during the refactor.

Official GitHub release metadata reports:

- `Xray-linux-64.zip` SHA-256
  `f3f69cdccdf3443f25248f65bec0f621a7bd05c9d6fbbd5d9f064a8fce70f0fc`;
- `Xray-linux-arm64-v8a.zip` SHA-256
  `7bcc35d375398c0df4b53ee004fb5b42402fcc0d331db5f2e6ac86cfc12b6a33`.

The local image will use the already-reviewed Alpine 3.23.5 base digest, select
only `amd64` or `arm64` from Docker's `TARGETARCH`, download the corresponding
asset over HTTPS, verify its fixed SHA-256 before extraction, and reject every
other architecture. Build-only download/extraction packages will be removed
from the final layer. Runtime JSON materialization will use pinned `jq`; it
will not use textual substitution.

This version pin is an intentional compatibility baseline, not an automatic
update channel. A later explicit upgrade operation must change the version and
both digests together, validate the new schema/configuration, and classify
client/server identity impact before apply.

#### Runtime and privilege boundary

The container will listen on a fixed unprivileged internal port, `8443`, with
the configured host listener published to it. This permits custom host ports
without changing an internal firewall and avoids root-only port binding.

The runtime will request:

- no `privileged` mode;
- no Linux capabilities;
- no TUN or other devices;
- no forwarding sysctls;
- one read-only rendered-config mount;
- one writable durable identity/runtime-state mount.

Raw TCP and XHTTP listeners use TCP. mKCP uses UDP. Host firewall rules continue
to derive from the backend listener declaration, so a custom host port and its
actual transport remain aligned.

The image will run as a fixed non-root UID/GID. The generic deployment unit
must create/normalize the durable state directory for that identity before
container start; this is a Linux fixture requirement. Xray itself will be the
final `exec` process, so Docker observes its real exit status and signals it
directly.

#### Supported security/transport matrix

The model retains strongly typed `XraySecurity::{Reality,Tls}` and
`XrayTransport::{Tcp,Xhttp,Mkcp}` values. The backend will enforce:

| Security | raw TCP | XHTTP | mKCP |
| --- | --- | --- | --- |
| REALITY | supported | supported | rejected |
| TLS 1.3 | supported | supported | supported |

Current upstream documentation says REALITY is valid only with RAW, XHTTP, and
gRPC; mKCP is therefore rejected with a structured validation error rather
than producing a configuration that Xray cannot honor. TLS supports all three
selected transports.

VLESS itself uses `decryption: "none"`, so a protective transport-security
layer is mandatory. The backend will not add a plain/`none` security mode.
TLS client configuration will use normal certificate and name validation; it
will never render `allowInsecure`, disable system roots, or bypass certificate
verification. The server will set both minimum and maximum TLS version to 1.3.

`xtls-rprx-vision` flow is supported only with raw TCP plus TLS or REALITY,
matching current upstream flow constraints. XHTTP and mKCP devices must omit
flow. No historical `xtls-rprx-vision-udp443` alias will be accepted.

#### Typed settings extension

`XraySettings` will gain backward-compatible optional fields:

- `reality_public_key`, public base64url metadata retrieved from the remote
  durable identity;
- `reality_short_id`, public client-selection metadata mirrored from remote
  state;
- `tls_certificate_ref`, an opaque native-secret-store reference to a
  PEM certificate/full chain;
- `tls_private_key_ref`, an opaque native-secret-store reference to the
  matching PEM private key.

The REALITY private key is intentionally absent. It exists only in the
instance's remote durable state and backups. The public key and short ID are
not secrets, but they remain behind the Rust application boundary as part of
typed instance state and are emitted only by explicit client export.

TLS secret values remain in native secure storage and explicit sensitive
rendered files. SQLite stores only their UUID references. TLS validation
requires both references together; REALITY rejects TLS references to prevent
stale ambiguous identity state.

The existing server-name, fingerprint, and XHTTP path fields remain. Validation
will restrict them to a real DNS name, an allowlisted browser fingerprint, and
a bounded absolute path without control/query/fragment characters.

#### Remote-only REALITY identity

The rendered server template contains no REALITY private key or short ID.
On startup, a fail-fast script will:

1. set a restrictive umask;
2. inspect the durable identity directory;
3. if all REALITY files are absent, run the pinned `xray x25519`, strictly
   parse and validate one private and one public base64url value, create a
   16-hex-character short ID from the kernel RNG, and atomically install all
   three files at mode `0600`;
4. if only part of the identity exists, fail rather than rotate or guess;
5. use `jq --arg` to inject the private key and short ID into the exact
   structured JSON paths;
6. write the materialized config atomically into durable runtime state;
7. run `xray run -test` against that config;
8. `exec` Xray only after validation succeeds.

Normal restarts and image updates reuse all durable files. The public key and
short ID can be retrieved later through fixed typed SSH discovery, populating
the mirrored settings needed for export. The private key must never be
downloaded, logged, placed in SQLite, or returned to Tauri.

The parser will accept only the pinned release's labeled key lines and the
known later `Password` label as the public/client half, while still validating
the exact base64url shape. It will not assume that any arbitrary second output
line is a key.

#### Structured server rendering

Rust `serde_json` values will render the complete server template. There will
be no raw expert JSON field and no token/string replacement.

The server config will include:

- error-only logs with no access log containing user destinations;
- one VLESS inbound on internal port 8443;
- sorted enabled clients containing UUID, validated email/label, and permitted
  flow only;
- `decryption: "none"`;
- one `freedom` outbound;
- typed stream settings for raw TCP, XHTTP, or mKCP;
- REALITY target/server names and an empty private-key slot for structured
  runtime injection; or
- TLS 1.3 certificate/key file paths and strict SNI rejection.

XHTTP initially renders a bounded path and conservative `auto` mode. The
backend will not expose Amnezia's large unstable XHTTP padding/xmux surface
until each option has a typed model, bounds, client/server parity tests, and an
upstream-version compatibility decision. mKCP initially uses pinned conservative
values rather than raw user strings.

Enabled clients are sorted by UUID, making add, disable, revoke, and regenerate
ordinary desired-state reconciliation. Disabled/revoked UUIDs disappear from
the next server JSON. No remote JSON is read, edited, or used as the source of
truth.

#### Device lifecycle and export

Xray devices remain addressless UUID identities with:

- random UUIDv4 client credential stored behind an opaque local reference;
- bounded validated email/label metadata;
- optional exact `xtls-rprx-vision` flow.

Creation and regeneration happen locally. Disable, revoke, and replacement are
model changes followed by deterministic server render and a validated service
restart. Because no client private key exists, there is no native secret-store
entry for a device. UUIDs are credential-bearing metadata and still must not
appear in ordinary Tauri responses or logs.

The explicit client artifact is a standards-compatible VLESS URI built with a
URL serializer:

- endpoint host and selected host port;
- UUID and `encryption=none`;
- exact security and transport;
- SNI and allowlisted fingerprint;
- REALITY public key and short ID when applicable;
- typed XHTTP/mKCP parameters;
- flow only for raw TCP;
- percent-encoded display label.

The artifact is zeroizing text, QR-capable, and written only by explicit export.
REALITY export fails until verified-SSH discovery has mirrored public material.
TLS export fails unless certificate references exist and configuration
validation has succeeded, although the certificate private key is server-only
and never embedded in the URI.

Xray is a proxy rather than an allocated-IP tunnel. Its capabilities therefore
declare no tunnel address, managed private DNS, peer handshake/transfer
statistics, certificate authority, or quick peer refresh. QR export is
supported. Identity reconciliation requires a service restart until a typed,
authenticated Xray API lifecycle is implemented and tested.

#### Settings-change impact

- unchanged settings: no backend change;
- fingerprint-only change: live client-export metadata update;
- XHTTP path or transport change: service restart and client re-export;
- server-name change: service restart and client re-export;
- security-mode, REALITY key/short-ID mirror, or TLS certificate/key reference
  change: destructive/reinstall-class identity change, surfaced before apply.

Changing images later is an explicit upgrade, not part of settings
classification. Ordinary restart/update must preserve remote REALITY state and
TLS references.

#### Validation and functional split

Unit 5a:

- backward-compatible typed Xray public/TLS settings;
- transport-aware listener reservations;
- TLS secret-reference retention tests;
- signed commit if the model change is nontrivial.

Unit 5b:

- `crates/backend-xray`;
- pinned multi-architecture verified-download Dockerfile;
- non-root/no-capability runtime contract;
- deterministic structured server JSON;
- remote-only REALITY initialization script;
- strict validation/security matrix;
- deterministic VLESS URI client export and QR eligibility;
- add/disable/revoke/regenerate reconciliation tests;
- change-impact tests;
- full workspace checks and signed commit.

Later generic integration:

- register the backend;
- normalize remote state ownership;
- retrieve and validate only public REALITY material over verified SSH;
- persist mirrored public values without exposing them to Svelte;
- ensure initial install is followed by public-material discovery before
  export;
- render/build/publish the selected TCP or UDP listener;
- validate config, restart, health, backup, rollback, and identity persistence
  on a disposable Linux Docker host;
- add backend-aware CLI and desktop workflows.

Runtime claims intentionally deferred until that fixture:

- image build for both architectures;
- pinned ZIP extraction and Xray executable behavior;
- key-output parsing;
- non-root bind-mount ownership;
- `xray run -test`;
- raw TCP, XHTTP, mKCP, REALITY, and TLS interoperability;
- custom listener publishing;
- UUID removal/replacement;
- REALITY identity survival across restart/image update/rollback.

Commit:

- `6009e4d docs: plan secure Xray backend`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 5a: Xray identity metadata, listeners, and server-secret retention

Status: complete. This unit extends the persisted model and secret-retention
boundary without rendering or running Xray.

#### Backward-compatible Xray settings

Added four optional, `#[serde(default)]` fields to `XraySettings`:

- `reality_public_key`;
- `reality_short_id`;
- `tls_certificate_ref`;
- `tls_private_key_ref`.

The first two are non-secret client-verification metadata that will be mirrored
only after the later verified-SSH discovery step. The second two are opaque
native-secret-store references. The model contains no REALITY private-key
field.

Existing Xray JSON containing only security, transport, server name,
fingerprint, and XHTTP path still deserializes with all four fields set to
`None`. `XraySettings::default()` also leaves them absent so creating a
REALITY instance does not fabricate remote public material.

Added `BackendSettings::secret_references()`. It returns Xray's present TLS
certificate/private-key references and an empty set for every backend that
currently keeps server material remote-only or manages secrets per device.
The return values borrow opaque IDs; no secret contents enter core or storage.

#### Transport-aware listener reservation

`VpnInstance::listeners()` now maps:

- Xray raw TCP to TCP;
- Xray XHTTP to TCP;
- Xray mKCP to UDP.

The backend-specific listener method will use the same mapping in Unit 5b.
This fixes both preview/firewall input and SQLite uniqueness before the backend
can be selected operationally. A core test proves a TLS+mKCP instance declares
UDP. A storage test proves it conflicts with an existing WireGuard UDP listener
on the same host/port, while the existing TCP-Xray/UDP-WireGuard sharing test
still passes.

#### Instance-owned secret lifecycle

The pre-refactor secret-reference table supports arbitrary owners, but cleanup
and retained-snapshot discovery considered only device owners. TLS server keys
belong to an instance, not a fabricated device. Storage now treats a candidate
as instance-scoped when its owner is either:

- the instance UUID itself; or
- a device UUID belonging to the instance.

When scanning retained deployment snapshots, it collects both the instance
backend settings' server references and every device backend's references.
This preserves Xray TLS certificate/key secrets for as long as either remains
in the retained desired-state window.

Soft-deleted host cleanup now deletes secret references owned directly by any
of the host's instances in addition to device-owned references. The existing
atomic cleanup test registers a synthetic instance-owned Xray TLS key and
proves no secret-reference row survives host deletion.

The new retention test:

1. creates a TLS Xray instance with two opaque server references;
2. registers both with the instance UUID as owner;
3. marks them pending deletion;
4. records a deployment snapshot that still contains both;
5. proves neither is deletable;
6. records ten newer snapshots after removing both settings references;
7. proves both become deletable after the retention window advances.

No schema migration is needed because `backend_settings_json` and `model_json`
already hold typed JSON and the owner column already accepts instance UUIDs.

#### Validation

The focused gate passed on the first run:

- `cargo fmt --all` and `cargo fmt --all -- --check`;
- `cargo test -p vam-core -p vam-storage`: 20 tests;
- strict clippy for both packages and all targets with `-D warnings`.

The full workspace gate also passed:

- `cargo check --workspace`;
- `cargo test --workspace`: 74 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo fmt --all -- --check`;
- `git diff --check`.

Commit:

- `598f2be refactor: model Xray server identity state`;
- created with `git commit -S`;
- `git verify-commit HEAD` reported a good EDDSA signature from William Jones
  using key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### Unit 5b: Xray/VLESS backend

Status: pure backend implementation and local Rust validation complete. Docker,
POSIX-shell, and live client/server interoperability remain later Linux fixture
gates.

#### Backend and runtime contract

Added `crates/backend-xray` as the fifth implementation of `VpnBackend`. Its
capabilities explicitly describe Xray as an addressless proxy:

- no allocated tunnel addresses;
- no managed private DNS;
- no quick credential refresh;
- no live identity update;
- no WireGuard-style traffic/handshake statistics;
- no certificate authority;
- QR-capable text export.

The backend requests no Linux capabilities, devices, or sysctls. Its runtime
uses:

- fixed internal unprivileged port 8443;
- TCP for raw TCP and XHTTP;
- UDP for mKCP;
- a read-only `/etc/xray` rendered-config mount;
- writable durable `/var/lib/vam-xray` identity/runtime state;
- structured-JSON validation and Xray-specific health declarations.

The local image tag is
`vpn-appliance-manager/xray:alpine3.23.5-v25.8.3`. The Dockerfile uses the
same Alpine 3.23.5 SHA-256 base pin as the other locally built backends and
installs fixed Alpine package versions. It accepts only Docker `TARGETARCH`
values `amd64` and `arm64`, maps each to the official release asset and frozen
digest from the Unit 5 plan, downloads with HTTPS/TLS 1.3, verifies with
`sha256sum -c`, extracts only the Xray executable, and removes its download
dependencies. Unsupported architectures fail the image build.

The image creates fixed UID/GID 10001, declares `USER 10001:10001`, and makes
Xray the final entrypoint process. There is no privileged mode, TUN device,
`NET_ADMIN`, container firewall, host-wide sysctl tuning, process-kill loop,
or keepalive `tail`.

Static tests inspect all of those properties. They do not prove that Alpine
still serves the exact pinned packages, Docker passes the expected architecture
name, the release ZIP layout is unchanged, or the binary executes. Docker is
not installed in this Windows environment.

#### Remote-only REALITY bootstrap

The server template contains empty `privateKey` and `shortIds` fields. The
rendered POSIX entrypoint:

- enables `set -eu` and umask `077`;
- fails if the rendered template is unreadable or structurally incomplete;
- creates a complete identity in a temporary mode-0700 directory only when the
  durable identity directory is entirely absent;
- runs the pinned `xray x25519`;
- extracts values only from explicitly labeled `Private key`, `Public key`, or
  later `Password` lines;
- validates each X25519 value as exactly 43 unpadded base64url characters;
- obtains eight bytes from `/dev/urandom` and validates the resulting 16
  lowercase hex short ID;
- writes all three files at mode `0600`;
- renames the complete temporary directory into place;
- rejects missing, partial, or malformed retained identity instead of rotating
  it;
- injects the private key and short ID into exact JSON paths with `jq`;
- validates the materialized config with `xray run -test`;
- `exec`s the real server only after validation passes.

The security pass changed injection from `jq --arg` to `jq --rawfile`. The
private key therefore does not appear in `jq`'s process arguments or a host
`docker top` view. It is transiently held in the shell only for shape
validation, then read by `jq` from the mode-0600 durable file. Temporary output
is removed by traps. The public key is retained remotely for the later fixed
discovery operation; the backend never renders or requests the private key as a
local secret reference.

The script uses only constant paths and structured JSON operations. It does not
perform `sed` replacement, interpolate user strings into shell source, or
assume an unlabeled second command-output line is safe.

The current machine has neither `sh` nor Docker, so even `sh -n`, image build,
and actual pinned-binary key output are unvalidated. A Linux fixture must check
all three. It must also prove fixed UID 10001 can read the mode-0600 rendered
template/TLS files and write the durable bind mount after generic ownership
normalization.

#### Strict settings and device validation

The backend rejects desired state unless:

- instance/backend/settings tags all select Xray;
- the generic instance/network model is valid;
- endpoint is a syntactically valid DNS name or IP address;
- server name is a bounded ASCII DNS name;
- fingerprint is one of the closed supported browser/random profiles and is
  never `unsafe`;
- XHTTP path is a bounded absolute ASCII path without whitespace, query, or
  fragment;
- REALITY uses only raw TCP or XHTTP;
- REALITY contains neither TLS secret reference;
- REALITY public key and short ID are either both absent during bootstrap or
  both strictly valid;
- TLS contains both certificate and private-key secret references and no
  stale REALITY metadata;
- every undeleted device has Xray data, a unique credential reference, unique
  valid email/label, and no tunnel address or managed DNS name; server rendering
  additionally requires unique, valid resolved UUID credentials;
- flow is absent or exactly `xtls-rprx-vision`;
- Vision flow is used only with raw TCP.

The backend intentionally supplies no unprotected VLESS mode. TLS certificates
and private keys are resolved only during server rendering; absent native
secrets produce a typed missing-secret error. PEM shape is checked and both
rendered files are marked sensitive at mode `0600`. Cryptographic
certificate/private-key matching is not yet performed locally and must be
proved by `xray run -test` in the integration fixture.

#### Deterministic structured JSON

Server JSON is constructed entirely with `serde_json::Value` and serialized by
`serde_json`; there is no raw JSON setting or textual mutation.

Enabled, undeleted clients are sorted by credential UUID. Each contains only
the validated UUID, email/label, level, and permitted flow. The UUID-bearing
template is itself marked sensitive so deployment/log surfaces redact it.
Disabled or removed identities disappear from the next render, and replacement
introduces only the newly generated UUID.

The common server shape contains one VLESS inbound on port 8443,
`decryption: "none"`, error-only logging, and one `freedom` outbound.

REALITY renders:

- typed raw TCP or XHTTP network;
- the validated target/SNI on port 443;
- one server name;
- bounded client/server time difference;
- empty key/short-ID slots for runtime structured injection.

TLS renders:

- typed raw TCP, XHTTP, or mKCP network;
- certificate and key file paths;
- strict SNI rejection;
- explicit TLS minimum and maximum version 1.3;
- `h2` and `http/1.1` ALPN;
- no `allowInsecure` or trust-store bypass.

XHTTP renders conservative `auto` mode plus the typed path. mKCP renders fixed
bounded transport values and an un-obfuscated header. This does not claim that
XHTTP or TLS-over-mKCP works with every client; live parity testing remains
required.

#### UUID lifecycle and VLESS export

`XrayBackend::generate_identity` creates:

- a random UUIDv4 credential;
- a normalized label using the last 12 device UUID digits to avoid collisions
  between deterministic/test UUIDs with common prefixes;
- Vision flow for raw TCP and no flow for XHTTP/mKCP.

The backend does not add any native secret reference for a device. UUID
creation, disable, removal, and replacement are represented by desired state
and deterministic reconciliation; a later application unit will restart and
health-check the service after changes.

Explicit export uses the `url` crate rather than manual query/fragment
concatenation. The VLESS URI includes:

- credential UUID as user information;
- validated endpoint and custom port;
- `encryption=none` under mandatory TLS/REALITY;
- security, SNI, fingerprint, and transport;
- flow only when valid;
- REALITY public key, short ID, and spider path; or TLS ALPN;
- XHTTP path/mode or mKCP header metadata;
- percent-encoded display label.

The result is a zeroizing text payload with a normalized `.vless.txt` filename
and can be rendered as QR by the existing native path. REALITY export fails
until both public metadata values have been retrieved from the remote host.
Tests parse the URI back through `url::Url` and compare fields/query pairs
instead of asserting an unparsed string.

#### Change impact

Backend switches and changes to security mode, REALITY public identity mirror,
or TLS certificate/key references are `Reinstall` class. They can change the
client-authenticated server identity and must be surfaced before apply.

Transport, SNI/target, and XHTTP path changes require `ServiceRestart` and
client re-export. An unchanged setting or fingerprint-only client metadata
change is `LiveUpdate`. Tests pin each classification.

#### Validation ledger

The focused gate was intentionally stopped and corrected at each failure:

1. compilation failed because deterministic sorting retained
   `Result<Uuid, BackendError>` as its key; validation makes mismatched device
   data impossible at that point, so the sort now extracts the proven UUID;
2. test compilation then found the missing test-only `chrono` dependency and
   two overlapping mutable/immutable test borrows; the dependency and borrow
   scopes were corrected;
3. two tests failed because a first-12-digits UUID suffix collided for small
   fixture UUIDs and because the URI test confused the model device UUID with
   its then-inline Xray credential UUID; the suffix now uses the UUID tail.
   Unit 11 later moved that credential behind a secret reference and changed
   the export test to resolve the protected value;
4. URL parsing correctly returned the percent-encoded fragment, so the test was
   corrected to assert `Work%20Laptop`;
5. after all nine tests passed, clippy found one mergeable match arm; it was
   simplified without behavior change.

After the process-argument security correction and deterministic fixture
cleanup, the focused gate passed:

- `cargo fmt --all` and formatting check;
- `cargo test -p vam-backend-xray`: 9 tests;
- strict focused clippy for all targets with `-D warnings`.

The full workspace gate passed:

- `cargo check --workspace`;
- `cargo test --workspace`: 83 tests;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo fmt --all -- --check`;
- `git diff --check`.

Still unvalidated:

- POSIX shell syntax and signal behavior;
- Alpine package availability and image build for amd64/arm64;
- release download, digest verification, ZIP extraction, and Xray invocation;
- actual X25519 output parsing and durable identity initialization;
- non-root read/write ownership on real bind mounts;
- `xray run -test` for every supported matrix entry;
- VLESS/REALITY/TLS client compatibility and TLS certificate-chain behavior;
- XHTTP and mKCP data path;
- custom host port publication and TCP/UDP firewall behavior;
- UUID revocation/replacement after restart;
- public-material discovery;
- backup, restore, rollback, and identity preservation across image updates.

Commit:

- `5835023 feat: add secure Xray VLESS backend`;
- signed with the configured EDDSA signing key
  `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

## Implementation Unit 6: backend-driven deployment rendering

### Plan

This unit is deliberately limited to the shared rendered deployment and its
plan. It does not yet execute backend-specific SSH validation, health, or
credential operations.

1. Make `vam-deployment` consume the selected backend's already-validated
   `BackendRuntimeSpec` and `BackendCapabilities`. Extend that runtime contract
   with explicit non-secret environment values and argv-style entrypoint and
   command fields so the renderer does not identify a protocol from its image
   name. WireGuard retains its required LinuxServer environment, AmneziaWG
   explicitly invokes its rendered startup script, and locally built images
   retain their Dockerfile entrypoints.
2. Render `compose.yaml` from that contract:
   - pulled images use their exact declared reference;
   - locally built images use their exact declared tag and Dockerfile directory;
   - published ports pair desired host listeners with declared container
     listeners and preserve TCP/UDP;
   - capabilities, devices, sysctls, and bind mounts are emitted only when
     requested by the selected backend;
   - CoreDNS is emitted only for backends with managed DNS.
3. Remove Watchtower and its Docker socket mount. Updates must be explicit,
   reviewable apply operations; no container may autonomously replace a pinned
   runtime.
4. Replace the mutable WireGuard/CoreDNS `latest` references:
   - WireGuard is pinned to the upstream LinuxServer release
     `1.0.20250521-r1-ls109`;
   - CoreDNS is pinned to `1.13.1`.
   The locally built OpenVPN, IKEv2, and Xray images and the AmneziaWG image
   were already version/digest pinned by their backend units.
5. Render DNS files and DNS health/reload operations only when the backend
   advertises managed DNS.
6. Generate a server key only for `WireGuardLike` identity strategies. CA and
   structured-identity initialization will be handled by their typed SSH
   operation units.
7. Treat changes under any declared backend mount as gateway configuration
   changes. A fresh or structural deployment will explicitly pull a pinned
   image or build the local image, then recreate the compose project; a
   backend-only file update can restart the gateway.
8. Register all five backends in the application service and supply the
   selected backend runtime/capabilities to shared rendering.
9. Add deterministic unit coverage for WireGuard, AmneziaWG, OpenVPN, IKEv2,
   and Xray compose shapes, including the negative security invariants: no
   `latest`, no Watchtower, no Docker socket, no DNS service for Xray, and no
   undeclared privilege/device.
10. Validate the focused crates first. Stop and diagnose every failure before
    the full workspace gate and signed commit.

### Expected boundaries and security properties

- `vam-deployment` remains backend-agnostic: it renders a typed runtime rather
  than matching protocol names.
- Runtime declarations remain owned and tested by each backend crate.
- Entrypoints and commands are structured argument lists, not shell strings.
- Host paths must remain safe relative rendered paths. Compose rendering must
  reject a listener-count mismatch instead of silently dropping or inventing
  a published port.
- The compose project receives the minimum declared Linux capabilities and
  devices. Xray therefore receives neither `NET_ADMIN` nor `/dev/net/tun`.
- The Docker control socket is never mounted into a managed service.
- This source-only unit cannot prove Docker Compose acceptance or image
  availability because Docker is not installed in the current Windows
  environment. Those limitations will remain explicit in validation.

### Implementation

#### Runtime contract and pinned images

`BackendRuntimeSpec` now carries three additional declarative process fields:

- an ordered non-secret environment mapping;
- an argv-style entrypoint override;
- an argv-style command override.

No shell source is accepted through those fields. The Compose renderer quotes
each YAML scalar. The selected backends use them as follows:

- WireGuard declares only `PUID=0`, `PGID=0`, `TZ=UTC`, and
  `LOG_CONFS=false`;
- AmneziaWG declares `/etc/amneziawg/start-awg.sh` as its entrypoint;
- OpenVPN, IKEv2, and Xray retain the entrypoints baked into their locally
  rendered Dockerfiles.

The WireGuard runtime changed from mutable
`ghcr.io/linuxserver/wireguard:latest` to
`lscr.io/linuxserver/wireguard:1.0.20250521-r1-ls109`. CoreDNS changed from
`docker.io/coredns/coredns:latest` to
`docker.io/coredns/coredns:1.13.1`. The upstream LinuxServer repository listed
the former as its current explicit release during this unit; the current
CoreDNS Helm source referenced 1.13.1. These are version pins rather than
multi-architecture manifest digests and should be refreshed deliberately with
release review.

#### Generic Compose rendering

`vam-deployment` now receives the selected runtime and capability set from the
application rather than owning a WireGuard image/layout.

For each runtime it renders:

- a pulled image reference, or a local image tag plus a safe relative build
  context and Dockerfile;
- the exact backend-declared capability and device lists;
- declared environment, entrypoint, command, and sysctls;
- desired host listeners paired by index with backend container listeners,
  retaining TCP/UDP;
- exact backend bind mounts and read-only flags.

The listener host ports remain in mode-0600 `.env` as
`VAM_LISTENER_<index>_PORT`. The Compose file no longer assumes a single
WireGuard UDP port. A host/container listener-count mismatch or protocol
mismatch is a hard rendering error. Absolute, empty, dot-component, and parent
component backend host/build paths are rejected.

CoreDNS and all DNS files are rendered only when `managed_dns` is true. Xray
therefore receives only `compose.yaml`, `.env`, `instance.json`, and its
backend-rendered files. WireGuard, AmneziaWG, OpenVPN, and IKEv2 retain the
CoreDNS sidecar and deterministic DNS artifacts.

Watchtower was deleted from rendered Compose. There are no update labels and no
Docker socket mount. The old executor's explicit pre-pull step was narrowed to
the pinned WireGuard and CoreDNS images; generic pull/build execution remains
the next integration unit.

#### Backend-aware deployment plans

The planner now receives the runtime and capabilities. It:

- creates a server-key operation only for `WireGuardLike` identities;
- distinguishes pulled from locally built images with explicit
  `ComposePull` and `ComposeBuild` operations;
- treats Compose/Dockerfile changes as structural;
- treats changes under any declared backend mount as gateway changes;
- reloads DNS only for a managed-DNS backend and DNS-only change;
- emits DNS health only for a managed-DNS backend;
- avoids a container action for metadata-only file changes.

This makes a fresh Xray plan build its local image, omit server-key generation,
and omit DNS health. CA and structured identity/credential work is still not
performed in this unit.

#### Application and developer CLI

`ApplicationService` now registers all five concrete backend implementations.
Rendering, planning, applying, and rollback planning ask the selected backend
for its validated runtime and capabilities before calling the shared planner.

The developer CLI no longer reads a WireGuard constant through the deployment
crate. Its `info` output reports each backend's own pulled/local image identity
plus the shared CoreDNS pin.

Important boundary: the remote `DeploymentExecutor`, health parser, firewall
commands, and device lifecycle are still WireGuard-specific at this commit.
The new backends are registered for model/render/plan work, but this unit does
not claim that their plans can yet be safely executed. The next units replace
those SSH assumptions before the CLI/UI can offer non-WireGuard apply.

### Validation ledger

The runtime-field change first passed a focused `cargo check` across the shared
backend crate and all five concrete backend crates.

The deployment renderer then passed 13 unit tests covering:

- deterministic WireGuard Compose;
- version-pin/no-`latest` invariants;
- no Watchtower or Docker socket;
- AmneziaWG image, TUN device, listener, and entrypoint;
- OpenVPN local build and TUN device;
- IKEv2 fixed 500/4500 UDP listeners without a TUN device;
- Xray local build with no DNS, `NET_ADMIN`, TUN device, Watchtower, or Docker
  socket;
- managed/unmanaged DNS file sets;
- listener-count rejection;
- DNS-only plan behavior and drift warning;
- Xray build plan without server-key or DNS health;
- stable redacted sensitive-file hashing.

The application passed its 10 unit tests after all backends were registered,
including the existing strict-host-key, redacted planning, credential refresh,
DNS, firewall, activation, and stop behavior tests.

Strict focused clippy initially stopped on `format_collect` in listener
environment rendering. The implementation was changed to append directly with
`writeln!`; the complete focused gate was rerun and passed:

- `cargo test -p vam-deployment -p vam-application`: 23 tests;
- strict clippy for both crates and all targets with `-D warnings`;
- formatting check;
- `git diff --check`.

The first full-workspace run found the stale developer CLI constant and then
exhausted the Windows volume while creating the desktop archive. The CLI was
corrected. After explicit approval, `cargo clean` removed 74,160 generated
files (38.2 GiB) under this repository's `target` directory only.

The clean full-workspace retry could not rebuild `aws-lc-sys` because NASM is
not installed. A process-local `AWS_LC_SYS_NO_ASM=1` fallback was attempted,
but that fallback also requires CMake, which is not installed. No prerequisite
was installed. Therefore:

- the focused source/test/clippy proof above is valid from before the cache
  cleanup;
- the clean full workspace is blocked by missing NASM (native path) or missing
  CMake (no-assembly fallback);
- Docker Compose/image/runtime validation remains unavailable because Docker
  is not installed;
- native desktop/full-workspace validation must be rerun after the user elects
  to install or provide the documented prerequisites.

Commit:

- `09141ca refactor: render backend-driven deployments`;
- signed with the configured EDDSA signing key
  `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

## Implementation Unit 7: backend-driven verified-SSH deployment

### Plan

This unit generalizes the remote deployment transaction around the backend
runtime contract. Certificate-authority issuance/revocation and the local
device lifecycle remain the next unit.

1. Replace the legacy WireGuard/Watchtower health shape with additive generic
   signals while retaining old fields for serialized/UI compatibility:
   backend readiness, all declared listeners published, desired client set
   present, and whether DNS is required. Watchtower must no longer be required
   for health.
2. Generate the SSH port-conflict probe from every typed listener:
   `ss -ltn` for TCP and `ss -lun` for UDP. A port occupied by the instance's
   existing gateway is allowed; any other collision fails before upload.
3. Generate idempotent UFW/Firewalld allow/remove commands for every exact
   `<port>/<protocol>` tuple. Do not infer UDP from the primary endpoint.
4. Prepare images from `ContainerImage`:
   - pull the exact backend reference for pulled runtimes;
   - build the exact staged Compose gateway for local runtimes;
   - pull pinned CoreDNS only when managed DNS is enabled.
5. Materialize `WireGuardLike` identities from the declared tool, key,
   template, active-config, and sentinel paths. Preserve an existing key,
   generate only when absent, and capture only the public key. This must work
   for both `wg` and `awg`.
6. Build validation commands from `BackendValidation`:
   - WireGuard/AWG quick-strip the staged active config;
   - OpenVPN checks its staged configuration using its built image;
   - IKEv2 performs static strongSwan configuration checks available without
     starting the live service;
   - Xray validates Compose before activation and relies on its fail-closed
     startup self-test for identity materialization.
   CoreDNS validation is capability-gated.
7. Activate all backend-declared identity files rather than hard-coded
   `vpn/wg0.conf`. Pull/build/up/restart commands must follow reviewed plan
   operations, and DNS restarts must be capability-gated.
8. Build health commands from `BackendHealthProbe`:
   WireGuard/AWG interface and peer count; OpenVPN management/process/config
   readiness; strongSwan daemon/loaded connection state; Xray process and
   `run -test` against its active config. Verify every published listener and
   DNS only when required.
9. Retrieve Xray REALITY public key/short ID after healthy startup and persist
   only those public values in desired settings; private identity remains on
   the remote host and is backup/rollback material.
10. Normalize ownership only for declared writable bind mounts and without
    assuming the WireGuard image or `vpn/` path. Staging cleanup must use an
    exact validated instance/plan path and must not rely on an arbitrary
    backend image containing a privileged shell.
11. Keep backup-before-mutation, same-filesystem activation, health-gated
    rollback, bounded retention, redacted events, cancellation, and approved
    host-key verification intact.
12. Add pure command-generation and mocked SSH tests for all listener,
    identity, image, validation, health, activation, and failure boundaries.
    Run focused tests/clippy first; report the already-known NASM/CMake
    full-desktop prerequisite separately.

### Uncertainties resolved conservatively

- OpenVPN and IKEv2 cannot become healthy until their CA/server material exists.
  This unit may prepare their runtime, but a fresh certificate backend apply
  must fail before remote activation with an actionable typed-credential
  prerequisite until Unit 8 initializes the authority transactionally.
- Xray TLS uses Keychain certificate/key material rendered as mode-0600 files.
  REALITY generates and preserves private material remotely. Planning must
  never substitute an invalid fake PEM for TLS; actual secret access remains
  inside the Rust boundary.
- Static validation commands differ in strength. A backend startup self-test
  is part of health and remains rollback-triggering; no weak validation result
  will be presented as full runtime proof.

### Implementation

#### Runtime-owned mount permissions

`ContainerMount` now declares `ContainerMountOwnership` instead of leaving the
application to infer an owner from a hard-coded WireGuard image:

- `HostUser` means that a writable bind mount must be returned to the remote
  SSH user's numeric UID/GID after the container becomes healthy;
- `Numeric { uid, gid }` means that the selected backend image is run once as
  root, with only that exact bind mount attached at `/work`, to create and
  chown its contents before the non-root service starts.

WireGuard, AWG2, OpenVPN, and IKEv2 use `HostUser`. Xray's read-only
configuration mount uses `HostUser`, while its writable identity/state mount
uses UID/GID 10001 to match the explicitly non-root image user. Read-only
mounts are never recursively changed. The command generator attaches only
validated instance-root subpaths, and staging cleanup similarly uses the
selected pinned backend image as root against the exact staging directory.

This keeps the former post-health ownership guarantee without assuming every
backend writes `vpn/` or that every service runs under the LinuxServer image's
user model.

#### Typed listener preflight and firewall management

The SSH transaction now consumes every `ListenerPort` in the backend runtime:

- TCP listeners are checked with `ss -H -ltn`; UDP listeners use
  `ss -H -lun`;
- a matching socket is accepted only when `docker compose port --protocol
  <tcp|udp> gateway <port>` proves that the current instance already owns it;
- any other collision fails before files are uploaded or the firewall is
  changed, and the error names both the transport and port;
- UFW and Firewalld commands enumerate exact `<port>/<transport>` tuples;
- an inactive firewall is left unchanged, and repeated add/remove operations
  remain safe;
- rollback of a failed first installation removes only those declared rules,
  never unrelated host firewall state.

This is necessary for IKEv2's fixed pair of UDP 500 and UDP 4500, OpenVPN's
selected TCP/UDP transport, Xray's selectable transport, and the single UDP
listeners used by WireGuard and AWG2.

#### Backend-selected image preparation

Image preparation follows `ContainerImage` and the reviewed deployment plan:

- pulled backends pull their exact pinned digest/tag;
- locally built OpenVPN, IKEv2, and Xray runtimes build the staged `gateway`
  service through the generated Compose file;
- pinned CoreDNS is pulled only when `managed_dns` is true;
- no generic `docker compose pull` is allowed to silently update a locally
  built or unrelated service;
- explicit image refresh uses the same backend-aware preparation path before
  recreating the services.

Watchtower remains absent. No Docker socket is exposed to a container.

#### Server identity materialization

The former WireGuard-only key command is now generated from
`ServerIdentityStrategy`:

- `WireGuardLike` declares its binary (`wg` or `awg`), private-key path,
  staged template, materialized active configuration, and sentinel;
- an existing private key is copied into the stage when present;
- otherwise the declared tool generates it in the protected stage;
- the private key substitutes the backend-specific sentinel only in the
  server-side active configuration;
- only `<tool> pubkey` output crosses back into the application and is
  persisted as public server metadata;
- the private key remains on the remote host and is covered by backup,
  activation, and rollback.

Host-to-container and container-to-host path mapping requires an exact mount
path or a slash-delimited child. For example, `vpn/awg0.conf` maps through the
`vpn` mount, but `vpn-other/awg0.conf` cannot match it.

Xray REALITY uses its image's fail-closed startup entrypoint to generate its
private X25519 identity and short ID in the 10001-owned state mount. After the
service is healthy, the application reads only the declared public-key and
short-ID files over the already verified SSH connection. It rejects either:

- an invalid public value; or
- a value that differs from a previously approved desired-state value.

Only the public REALITY values are persisted. TLS mode instead resolves the
certificate/private-key references inside the Rust application boundary for
the real render; planning does not fabricate invalid PEM.

#### Backend-specific validation and health

Staged validation is selected by `BackendValidation`:

- WireGuard and AWG2 run their declared quick helper's `strip` operation
  against the mapped staged active configuration;
- OpenVPN checks its staged configuration with the locally built image and
  `openvpn --test-crypto`;
- IKEv2 checks that its generated strongSwan configuration is non-empty and
  that the built image provides `swanctl`; full daemon/connection proof is
  deliberately deferred to health;
- Xray verifies non-empty staged JSON and the built binary before activation;
  its entrypoint performs `xray run -test` on the materialized live
  configuration before executing the server;
- every backend runs `docker compose ... config --quiet`;
- CoreDNS receives its own temporary configuration check only for a backend
  that declares managed DNS. A shell trap removes the temporary verifier.

`InstanceHealth` adds serialized, defaulted generic signals while retaining
the legacy fields for UI/database compatibility:

- `backend_ready`;
- `listeners_ready`;
- `client_state_matches`;
- `dns_required`.

The remote probe always verifies the Compose project and gateway status, then
uses `BackendHealthProbe`:

- WireGuard/AWG2: declared tool can read the interface and observed peer count
  matches enabled desired devices;
- OpenVPN: daemon PID/status files are ready and the rendered client-directory
  count matches desired enabled clients;
- IKEv2: `charon` is alive, `swanctl` can enumerate loaded connections, and
  the rendered secret/connection set matches desired clients;
- Xray: `xray run -test` succeeds against the active materialized JSON and its
  client count matches desired enabled clients.

Every declared Compose port mapping is independently checked. Private/public
DNS probes run only when DNS is managed. Health no longer checks Watchtower.
The transaction accepts a deployment only when the generic signals are all
healthy, then normalizes eligible host-owned mounts. Otherwise it rolls back.

#### Activation, quick refresh, and rollback

Activation moves every backend-declared identity file, not just
`vpn/wg0.conf`, from the same-filesystem stage into the active directory.
Compose actions follow the reviewed plan:

- DNS-only plans restart DNS only;
- gateway restart plans restart the gateway and DNS only when DNS exists;
- create/reinstall plans bring up the complete generated project;
- image pull/build preparation occurs only when the plan contains that
  operation.

Quick credential refresh remains available only when the backend capability
declares it. It now works for both WireGuard and AWG2, uploads only the
backend's credential/config mount, rematerializes the active configuration
with the preserved server private key, validates it, restarts only the
gateway, proves health, and then restores host ownership. DNS files and DNS
restart remain out of this path.

Rollback now distinguishes two cases:

- when a previous current directory existed, restore its backup, recreate the
  previous Compose project, and prove the previous health contract;
- on a first deployment with no backup, bring down the failed project,
  quarantine its current directory under the instance trash path, and remove
  only the new backend's typed firewall rules.

This fixes the former first-install failure path, which attempted to restore a
backup that could not exist. Backup-before-mutation, bounded retention,
redacted events, cancellation propagation, and strict approved-host-key
verification remain in place.

### Validation

The first application test run stopped on a new assertion that expected the
AWG2 host mount to map to the LinuxServer WireGuard container path. Inspection
confirmed that AWG2 deliberately maps `vpn/` to `/etc/amneziawg`; the test
expectation was corrected to the backend contract, and the complete
application gate was rerun.

Passing delivered-source gates:

- formatting with `cargo fmt --all --check`;
- `git diff --check`;
- 45 tests across the backend and deployment crates:
  - AWG2: 4;
  - IKEv2: 8;
  - OpenVPN: 8;
  - WireGuard: 3;
  - Xray: 9;
  - deployment: 13;
- strict clippy with `-D warnings` for those backend/deployment crates and all
  targets.

The application crate was also diagnosed after temporarily selecting russh's
ring provider:

- all 12 application tests passed;
- strict application clippy passed for all targets with `-D warnings`;
- the exact mount-prefix regression covers both accepted children and rejected
  sibling-prefix paths.

That temporary dependency selection was not retained. `Cargo.toml` is back to
`russh = "0.62.3"`, `Cargo.lock` is restored to the AWS-LC graph, and neither
file is part of this change.

Remaining environment-limited validation is explicit:

- a clean native build of the delivered AWS-LC provider is still blocked by
  missing NASM; its documented no-assembly fallback is blocked by missing
  CMake;
- Docker/Compose and a POSIX remote shell are not installed locally, so image
  builds, Compose configuration, entrypoint behavior, and live SSH deployment
  have not been executed;
- OpenVPN and IKEv2 certificate-authority provisioning is the next functional
  unit and is required before those backends can reach live healthy state.

Commit:

- `2b3ecf3 feat: generalize SSH backend deployment`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

## Implementation Unit 8: certificate authority and device transactions

### Plan

This unit connects the already-reviewed `CredentialPlan` operations to the
verified SSH, native secret-store, and SQLite boundaries. It is split into
three independently validated signed checkpoints.

#### 8A: bounded verified-SFTP download

1. Add a `DownloadRequest` to `SshTransport`, using the same approved host key,
   encrypted OpenSSH/PPK key loading, passphrase, cancellation, and operation
   timeout as upload.
2. Read remote artifacts as bytes through SFTP rather than `cat`, output
   parsing, temporary local files, or frontend-visible data.
3. Enforce an application-supplied maximum size while reading so a compromised
   host cannot force unbounded local allocation.
4. Add fake-transport and SSH unit coverage. Preserve the PPK authentication
   code path unchanged.

#### 8B: staged CA bootstrap and persistent activation

1. Extend `ServerIdentityStrategy::CertificateAuthority` with explicit
   persistent host-relative paths. OpenVPN owns its Easy-RSA PKI and optional
   TLS-crypt key; IKEv2 owns its CA, issued certificates, private keys, CRL,
   and serial/index state.
2. Before rendered upload, copy only those declared paths from the existing
   current directory into same-filesystem staging. Reject symlinks and
   incomplete authority state rather than following or regenerating it.
3. After the selected pinned image is prepared, execute the backend-generated
   initialization plan in staging:
   - OpenVPN: Easy-RSA CA, P-256 server certificate, CRL, and optional
     TLS-crypt key;
   - IKEv2: strongSwan `pki` P-384 CA/server keys and certificates, CRL, and a
     protected revocation/serial ledger.
4. Initialization is idempotent only for a complete, validated authority. A
   partial authority fails closed. Normal apply never rotates an existing CA
   or server identity.
5. Validate the complete staged configuration, back up current state, then
   activate the declared persistent identity together with rendered files.
6. Mark the local authority initialized only after Compose health succeeds.
   The marker is not itself trusted: credential operations also verify remote
   authority files.

#### 8C: backend-aware device lifecycle

1. Build each device identity through its backend:
   - WireGuard: local keypair and optional unique PSK;
   - AWG2: local AWG-compatible keypair plus mandatory unique PSK;
   - OpenVPN: local EC private key and PKCS#10 CSR;
   - IKEv2: local P-384 private key/CSR plus a 64-character random protected
     PKCS#12 password;
   - Xray: UUID credential in native storage plus structured non-secret client
     metadata and an opaque reference.
2. Allocate tunnel addresses and managed DNS only when capabilities declare
   those concepts. Xray receives neither a fake tunnel address nor CoreDNS
   record.
3. For certificate devices, require a successfully deployed remote authority,
   upload only the CSR, sign inside the pinned server image, retrieve only
   certificate/CA/public TLS material through bounded SFTP, validate it inside
   the backend, and store it in the native secret store.
4. Persist the new device and all secret-reference rows only after issuance
   succeeds. If local persistence fails, execute a compensating remote
   revocation and remove newly stored local secrets.
5. Revoke remotely and regenerate/load the CRL before disabling or deleting
   certificate devices. Re-enable requires identity replacement because
   certificate revocation is irreversible.
6. Replacement issues and validates the new credential before revoking the
   previous identity, then atomically replaces local device metadata and
   retires old secret references. If local persistence fails, revoke the newly
   issued identity as compensation and report that remote state changed.
7. Xray/WireGuard/AWG identity changes remain desired-state operations and are
   applied through the reviewed deployment/quick-refresh path; no frontend
   receives private material.
8. Serialize all remote credential mutations with the existing per-instance
   lock. Treat every non-zero remote exit as failure; stdout parsing is limited
   to the certificate serial emitted by a command that already exited zero.

### Security/atomicity boundary

SQLite and an OS-native secret store cannot share a true distributed
transaction with a remote CA. The safe ordering is therefore:

1. create private material locally;
2. mutate/validate the remote authority;
3. store returned public credential material locally;
4. commit local metadata;
5. compensate remotely and delete new local secrets if step 4 fails.

For revocation, remote access is removed before local metadata changes. If the
local write then fails, the product reports an explicit remotely-changed
error; it never reports a still-valid revoked credential as safe. Every
authority mutation is backed up or uses an operation-specific rollback copy
before it starts.

### 8A implementation and validation

`SshTransport` now has a byte-oriented `download` operation alongside upload.
`DownloadRequest` carries:

- the same `SshConnectionConfig`;
- the exact approved host public key;
- the optional zeroizing passphrase;
- the exact remote path;
- a caller-selected byte limit;
- the same cancellation token.

`RusshTransport::download` authenticates through the existing
`authenticated()` path. This is important: it preserves russh's native
OpenSSH/PPK loading and compares the presented host key to the approved key
before opening SFTP. It does not invoke the system SSH client or relax host
verification.

The SFTP file is streamed in 16 KiB chunks into `Zeroizing<Vec<u8>>`. The
buffer is also heap-allocated under `Zeroizing`, both to erase certificate
material and to keep the async future small. The read stops with the dedicated
`DownloadTooLarge` error before appending any chunk that would exceed the
limit. Cancellation and the configured operation timeout wrap session setup
and the complete bounded read.

The first strict-clippy run stopped because the initial 16 KiB stack buffer
made the async future exceed the large-future threshold. The buffer was moved
to a zeroizing heap allocation instead of suppressing the lint.

Validation used the temporary ring-provider diagnostic only because the
delivered AWS-LC build remains blocked by missing NASM:

- 4 SSH tests passed, including PPK loading, cancellation, upload metadata, and
  exact-limit/oversize download behavior;
- all 12 application tests passed with its fake transport implementing the new
  trait contract;
- strict clippy passed for both crates and all targets with `-D warnings`;
- formatting and `git diff --check` passed.

`Cargo.toml` and `Cargo.lock` were restored to the delivered AWS-LC graph
before staging.

Commit:

- `2ffc038 feat: add bounded verified SFTP downloads`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### 8B implementation

`ServerIdentityStrategy::CertificateAuthority` now declares its persistent
host-relative paths. The application does not infer these from backend names:

- OpenVPN declares `vpn/pki`, `vpn/requests`, and `vpn/tls-crypt.key`;
- IKEv2 declares its `private`, `x509`, `x509ca`, `x509crl`, `requests`, and
  `issued` directories under `ikev2/`.

Before rendered upload, each existing declared path is copied from `current`
into the unique same-filesystem staging directory. The seed command:

- accepts only a regular file or directory;
- rejects a symlink at the declared root;
- scans directories and rejects any contained symlink;
- requires the staged destination not to exist;
- copies only exact backend-declared paths.

This prevents a compromised persistent directory from redirecting privileged
container writes while retaining the existing CA, server private key, serial
database, issued certificates, and CRL across updates.

After the exact image is pulled/built, `InitializeAuthority` is executed
against staging. A certificate plan must contain exactly one typed
initialization operation at this boundary.

#### OpenVPN Easy-RSA authority

The OpenVPN command runs the pinned local image as root only for the declared
staged `vpn` mount and replaces the service entrypoint with `/bin/sh`. It:

- counts five required non-empty authority/server/CRL files and the optional
  sixth TLS-crypt key;
- treats a complete set as an idempotent validation and verifies the server
  certificate with OpenSSL;
- rejects any partial set, existing empty PKI root, or symlink instead of
  regenerating;
- generates a fresh authority under `.vam-pki-new` with a cleanup trap;
- uses Easy-RSA batch mode, EC `prime256v1`, SHA-256, a 3650-day CA, the
  configured bounded leaf lifetime, and a 3650-day CRL;
- generates the server key remotely and never downloads it;
- generates a unique TLS-crypt key only when the typed settings require it;
- verifies the staged server certificate before atomically renaming the PKI;
- sets private directories/files to 0700/0600 and public certificates/CRL to
  0644.

Client private keys remain local. Easy-RSA is used only for the CA/server key
and to sign locally generated PKCS#10 client requests.

#### IKEv2 strongSwan authority

The IKEv2 command similarly runs only the pinned locally built strongSwan
image against the declared staged `ikev2` mount. It:

- requires a complete CA key/certificate, server key/certificate, and CRL;
- verifies the server chain and parses the CRL on every idempotent reuse;
- rejects partial or symlinked state;
- generates into `.vam-authority-new` with a cleanup trap;
- uses P-384 ECDSA with SHA-384 for both CA and server;
- gives the server certificate the configured validated identity as CN/SAN,
  an explicit `serverAuth` EKU, a fixed initial serial, and the configured
  bounded lifetime;
- creates the initial CRL through `pki --signcrl`;
- validates the new chain and CRL before installing protected files into the
  persistent directories.

The CA and server private keys intentionally remain remote-only and mode 0600.
They are not passphrase-encrypted because unattended certificate issuance
would otherwise require persistently placing the decryption secret beside the
key or repeatedly sending it to an online CA. This is an explicit online-CA
tradeoff: the remote host and backups are within the authority trust boundary.
Client keys and PKCS#12 passwords remain local in the native secret store.

#### Activation and rollback

Certificate persistence is activated as a unit:

- generated/seeded persistent paths move from stage to current only after the
  pre-mutation backup;
- rendered `.keep` files under a persistent directory are not moved a second
  time;
- a previous current path is moved into the instance trash area before the
  staged identity is installed;
- the existing deployment rollback restores the whole backed-up instance,
  including authority, server keys, issued state, and CRL.

The local `certificate_authority_initialized:<instance>` marker is written
only after backend, listener, client-set, and optional DNS health all pass.
No-op applies also write it only after confirming current health. The marker
will be an eligibility hint for device issuance; remote authority validation
remains authoritative.

### 8B validation

Passing gates:

- 29 focused tests: IKEv2 8, OpenVPN 8, deployment 13;
- 14 application tests, including:
  - exact/symlink-safe persistence seeding;
  - OpenVPN EC Easy-RSA, partial-state, verification, and pinned-image command
    generation;
  - IKEv2 P-384/SHA-384, SAN, server EKU, CRL, partial-state, and verification
    command generation;
  - persistent-path activation;
- strict clippy for all affected backend/deployment/application targets with
  `-D warnings`;
- formatting and `git diff --check`.

The first IKEv2 test run stopped because its assertion expected an inner
single-quote representation after the entire script had been quoted as the
single `sh -c` argument. The assertion was corrected to verify the `--san`
flag and validated identity separately. The next clippy run stopped on two
pure helpers returning the large application error type; those helpers now
return small static diagnostics and convert to `AppError` only at the service
boundary.

The application proof again used the temporary ring-provider diagnostic; the
manifest and lockfile are restored to AWS-LC. Docker is unavailable, so the
exact pinned image builds and Easy-RSA/strongSwan command execution remain
unverified locally and are not represented as runtime proof.

Commit:

- `a70ceb0 feat: bootstrap persistent certificate authorities`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### 8C implementation

#### Backend-aware local identities

The application device factory now dispatches through the instance backend:

- WireGuard generates a unique local keypair and an optional per-device PSK;
- AWG2 generates its own local keypair and always creates a unique mandatory
  PSK, even if an old caller sends `preshared_key=false`;
- OpenVPN calls the backend's EC key/PKCS#10 generator, creates opaque
  references for the future certificate, CA certificate, and optional
  TLS-crypt key, and stores only private key/CSR material initially;
- IKEv2 calls the P-384 generator, creates references for certificate/CA
  retrieval, and stores the private key, CSR, and 64-character PKCS#12
  password;
- Xray generates a fresh UUID into native storage and persists structured
  email/flow metadata plus only its opaque secret reference.

Address allocation and managed DNS now follow backend capabilities. Routed
backends reserve the next safe tunnel address. Xray receives `None` for its
address and DNS owner, creates no CoreDNS record even when an old CLI/UI caller
passes its historical default, and writes no secret-reference row.

Identity-bearing fields are immutable through ordinary `update_device`.
Changing a public key, UUID, common name, identity, or secret reference must go
through the explicit replacement workflow.

#### Atomic local metadata

Storage now provides transaction-specific methods instead of composing several
independent writes:

- new device row + every secret-reference row + optional managed DNS row;
- replacement device row + marking every previous reference pending deletion
  + every new reference;
- soft deletion + managed DNS removal + secret retirement.

If any statement fails, SQLite rolls the complete group back. Native secret
values are written before the transaction and deleted if the transaction
fails. Old values are only marked pending and remain recoverable while retained
deployment snapshots reference them.

#### Remote credential transaction

Every certificate issue, revoke, or replacement is serialized by the existing
per-instance lock and requires both:

- the post-health local authority marker; and
- at least one successful deployment snapshot.

The operation still validates the real remote authority. Before the first
mutation it copies the complete active instance into a unique credential
backup under the normal instance backup root. A typed `CredentialPlan` then
executes in order:

Before that copy or any root-container mount, the generic application
preflights every backend-declared persistent path: declared roots may be only
regular files/directories, roots may not be symlinks, and directory trees may
not contain symlinks. This prevents remote drift from redirecting an authority
operation outside the isolated instance root.

1. retrieve the locally generated CSR from native secure storage;
2. upload it through verified SFTP to an exact declared persistent path at
   mode 0600;
3. run signing commands inside the selected pinned backend image;
4. download only the certificate, CA certificate, and optional TLS-crypt key
   through verified SFTP with a 1 MiB per-artifact limit;
5. store those artifacts directly in native secure storage;
6. read the certificate serial using a command that must first exit zero;
7. accept only 1-64 hexadecimal characters and normalize them to uppercase.

Any SSH, SFTP, command-exit, size, serial, or secret-store failure restores the
credential backup through the normal Compose/health/ownership rollback path.
The pending local secrets are then deleted.

After issue, the backend renders the complete client artifact inside Rust as a
validation step before SQLite is touched. OpenVPN must parse all PEM/static-key
blocks. IKEv2 must parse the P-384 private key and certificate chain and build
the password-protected PKCS#12 bundle. Secret-bearing output is discarded; it
does not cross Tauri.

If the later SQLite transaction fails, the same retained backup is restored,
which removes the newly issued identity and restores the old CRL/index. This is
stronger than merely revoking a replacement certificate because replacement
has already revoked the previous identity.

#### OpenVPN operations

OpenVPN operations run Easy-RSA inside the pinned local image with:

- batch mode;
- the fixed `/etc/openvpn/pki` authority;
- `EASYRSA_DN=cn_only`, matching the validated Common Name and the index check;
- caller-independent, backend-generated safe names;
- configured bounded client lifetime;
- OpenSSL chain verification after signing.

Revocation first checks Easy-RSA's tabular index for an existing revoked
subject, making retry a no-op. Otherwise it revokes the exact Common Name,
regenerates and validates the CRL, and restarts only the gateway so OpenVPN
loads the new CRL.

#### IKEv2 operations

The IKEv2 backend paths were corrected to be instance-root-relative
(`ikev2/requests`, `ikev2/issued`, and `ikev2/x509ca`) so the generic
host/container mapper can enforce the mount boundary.

Issuance:

- creates a random 128-bit hexadecimal serial from `/dev/urandom`;
- signs the locally generated PKCS#10 request with P-384/SHA-384 and explicit
  `clientAuth`;
- validates the returned chain before publishing it;
- stores a non-secret serial sidecar for deterministic discovery.

Revocation uses strongSwan `pki --signcrl` with the previous CRL and exact
certificate serial, validates the new CRL before rename, and writes an
idempotency marker under the newly declared persistent `ikev2/revoked`
directory. It then reloads all credentials/connections.

The original credential model asked to terminate an IKE identity, but
`swanctl --terminate --ike` takes an IKE_SA/connection name, not a remote
certificate identity. The operation now carries the backend-generated
`client-<device-uuid>` connection name. It lists that exact SA and terminates
it only when active; a discovery error remains fatal.

This follows the current official strongSwan command contracts:

- <https://docs.strongswan.org/docs/latest/pki/pkiIssue.html>
- <https://docs.strongswan.org/docs/latest/pki/pkiSignCrl.html>
- <https://docs.strongswan.org/docs/latest/swanctl/swanctlTerminate.html>

#### Disable, delete, and replacement

Disabling or deleting a certificate device revokes remotely and reloads the
CRL before committing local disabled/deleted state. A revoked device cannot be
re-enabled because X.509 revocation is irreversible; the application returns
an actionable `certificate_identity_revoked` error directing the caller to
replace identity.

Replacement:

- generates a distinct new local identity (including a new OpenVPN CN/IKEv2
  identity seed);
- issues and validates the new certificate first;
- revokes the old certificate and reloads the gateway;
- terminates the old IKE connection where applicable;
- atomically swaps local metadata and retires old secret references.

WireGuard, AWG2, and Xray replacement uses the same backend-aware local factory
and atomic storage method. Their remote desired-state update remains subject to
the existing reviewed apply/quick-refresh workflow.

### 8C validation

Development failures were stopped and corrected in sequence:

- strict backend clippy found an obsolete `ikev2_device_required` helper after
  credential plans began retaining the complete device; it was removed;
- the first application compile found a wrong `validate_records` argument and
  a moved serial value; the zone is now passed explicitly and the public serial
  is retained with the rollback handle;
- application tests then exposed only an unused duplicated purpose field;
  registration purpose comes from finalized typed backend data, so the
  transient duplicate was removed;
- strict clippy requested two simpler raw-string delimiters and `clone_from`
  for four serial assignments; those no-behavior-change fixes were applied.

Passing gates:

- 36 initial focused core/backend/storage tests;
- 8 IKEv2 tests after the exact connection-termination/path changes;
- 12 storage tests, including the new atomic create/replace/delete and secret
  retirement test;
- 17 application tests, including:
  - five-backend identity generation and secret counts;
  - mandatory AWG2 PSK;
  - certificate command typing, mount quoting, Easy-RSA index idempotence,
    strongSwan CRL/marker behavior, and serial rejection;
  - Xray creation with no tunnel address, DNS record, or secret reference;
  - all prior verified-SSH/deployment behavior;
- strict clippy for all affected targets with `-D warnings`;
- formatting and `git diff --check`.

The application test/clippy gate used the temporary ring-provider diagnostic.
`Cargo.toml` and `Cargo.lock` are restored to the delivered AWS-LC graph.
Docker and a Linux SSH fixture are unavailable, so real Easy-RSA/strongSwan
issue/revoke/restore execution remains an explicit integration-test gap.

Commit:

- `00fb896 feat: add transactional device credentials`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

## Unit 9: Generic application, CLI, and desktop boundary

### Current-state findings

The backend/deployment refactor is not yet reachable through every product
surface:

- `CreateInstanceInput` has no backend field and defaults its port directly to
  WireGuard's 51820;
- `ApplicationService::create_instance` always writes
  `VpnBackendKind::WireGuard` and `BackendSettings::default()`;
- `vam-dev instance-add` has no backend selector and also defaults its port to
  51820;
- the Tauri device commands return and accept the complete core `Device`.
  Consequently, opaque native-secret references and backend identity storage
  metadata are serialized into frontend payloads even though the Svelte UI
  neither needs nor should be allowed to mutate them;
- `vam-dev device-list`, `device-add`, and identity replacement serialize the
  same complete core device, so routine CLI output exposes internal secret
  reference identifiers contrary to the redacted-output contract;
- the Svelte types and forms still describe only a WireGuard instance, require
  a tunnel address for every device, always offer PSK and managed-DNS controls,
  and label all health checks as WireGuard checks.

The core already provides the required strongly typed settings and a single
source of backend defaults through `BackendSettings::defaults_for`. The
backend registry already owns protocol validation and capabilities. Unit 9
will use those boundaries instead of duplicating backend rules in Tauri or the
CLI.

### Unit 9 implementation plan

#### 9A: application and CLI

1. Extend `CreateInstanceInput` with a backend kind, optional typed backend
   settings, and an optional endpoint port. Preserve old callers through Serde
   defaults: an omitted backend remains WireGuard, omitted settings come from
   the selected backend, and an omitted port comes from
   `VpnBackendKind::default_port`.
2. Reject a backend/settings discriminator mismatch before persistence. Build
   an empty desired state and call the selected registered backend's validator
   in addition to generic instance and same-host listener validation.
3. Add a public device view containing only ordinary UI/CLI fields, backend
   kind, and a deliberately public identity label. It must not contain
   `SecretReference`, private material, CSR/certificate storage references, or
   the mutable core `DeviceBackendData`.
4. Add an update input containing only mutable public fields. The application
   must load the existing core device, preserve its instance/address/identity
   metadata, and route the update through the existing transactional
   `update_device` workflow. Provide public-view create/list/replace methods so
   external surfaces never need the core record.
5. Extend `vam-dev instance-add` with a typed backend selector. Let the
   application select the corresponding default port and typed settings unless
   explicitly overridden. Route add/list/enable/replace device commands through
   the public application methods; do not read storage directly or reimplement
   business logic in the CLI.
6. Add parser and application tests for defaults, every backend, mismatch
   rejection, device redaction, and metadata-only mutation.
7. Run formatting, focused application/CLI tests, strict Clippy, patch sanity,
   and the manifest/lock restoration check before a signed commit.

Expected checkpoint: a backend-aware, redacted Rust/CLI boundary without
changing deployment semantics.

#### 9B: Tauri and Svelte

1. Change the Tauri device command signatures to the public application DTOs.
   Retain the thin-command pattern: no storage reads or protocol logic in
   Tauri.
2. Replace WireGuard-only TypeScript declarations with exact discriminated
   unions for backend settings and public device views. Reflect optional
   tunnel addresses and generic health fields.
3. Add protocol selection to instance creation. Present conditional,
   user-relevant settings:
   - WireGuard fallback and routed-network controls;
   - AWG2 obfuscation values with validated defaults;
   - OpenVPN transport, cipher, TLS protection, and certificate lifetime;
   - IKEv2 server identity and certificate lifetime;
   - Xray security, transport, server name, fingerprint, and XHTTP path.
4. Derive the default listener port from the selected backend. Hide
   routed-address/DNS/device PSK controls when capabilities do not apply,
   especially for Xray. Adapt labels and identity details without dumping
   secret-bearing protocol internals into the UI.
5. Generalize health presentation to backend/listener/client-state/DNS
   readiness while retaining legacy fields only for backward-compatible
   deserialization.
6. Run frontend type checking, tests, and production build, then focused Tauri
   Rust tests/Clippy where the local toolchain permits. Stop and document any
   environment-only failure rather than weakening the checks.

Expected checkpoint: all five backends are creatable and manageable through
the existing desktop visual language, while the frontend remains a
non-secret-bearing thin client.

### 9A implementation

`CreateInstanceInput` now carries:

- a backend discriminator that defaults to WireGuard when omitted;
- optional strongly typed `BackendSettings`;
- an optional listener port.

The application trims the endpoint once, derives settings with
`BackendSettings::defaults_for`, and derives the port with the selected
backend's `default_port`. A caller-supplied settings discriminator must match
the selected backend. Before any database write, the service validates both
the generic instance and an empty desired state through the registered backend.
This catches protocol rules such as IKEv2's fixed port and required server
identity at the same boundary used by later render/deploy operations.

The application also exposes a backend catalog for thin clients. Every entry
contains the stable kind, display name, default port, and the registry-owned
capabilities that drive address, DNS, credential, QR, identity-update, and
statistics controls. Tauri and Svelte therefore do not need a second source of
truth for feature availability.

Routine device data now crosses external Rust surfaces as `DeviceView`, not the
storage `Device`. Its discriminated public identity contains only:

- WireGuard public key and whether a PSK exists;
- AWG2 public key;
- OpenVPN Common Name and public certificate serial;
- IKEv2 identity and public certificate serial;
- Xray email label and non-secret flow; the UUID credential and even its opaque
  reference are deliberately absent.

It intentionally has no `SecretReference`, private key/PSK, CSR/certificate
reference, bundle password reference, or mutable `DeviceBackendData`.
`UpdateDeviceInput` contains only the public fields that may be changed.
`update_device_metadata` reloads the authoritative core device, normalizes DNS
only when the registered backend supports managed DNS, preserves the allocated
address and entire backend identity, and delegates to the existing
transactional update/revocation path. A dedicated enable method prevents the
CLI from reading storage or reconstructing the device.

`vam-dev instance-add` accepts `--backend` values `wireguard`, `amnezia-wg`,
`openvpn`, `ikev2`, and `xray`. An omitted selector remains WireGuard-compatible.
An omitted `--port` is deliberately passed as `None`, allowing the application
to choose the backend default rather than teaching the CLI protocol rules.
Device add/list/enable/identity-replace commands now serialize only public
views and contain no direct storage access.

### 9A validation

The first native test attempt stopped before application compilation because
`aws-lc-sys` could not find NASM. No package was installed and the product
dependency was not weakened. The established local diagnostic changed only
the workspace `russh` declaration to its Ring provider while running the
focused gates, then restored the manifest and lockfile.

Passing gates:

- 19 application tests, including:
  - default creation and registered validation for all five backends;
  - legacy JSON input defaulting to WireGuard;
  - backend/settings mismatch rejection;
  - device-view serialization with every opaque secret reference absent;
  - public metadata update with DNS normalization and byte-for-byte unchanged
    backend identity metadata;
- 3 CLI parser tests, including every backend selector, WireGuard compatibility,
  backend-derived port deferral, and explicit device enable/disable values;
- strict Clippy for application and CLI, all targets, with `-D warnings`;
- formatting and `git diff --check`.

After diagnostics, `cargo tree -i aws-lc-rs -e features` confirmed the restored
default russh/AWS-LC graph, and `git diff -- Cargo.toml Cargo.lock` was empty.
The normal native AWS-LC build remains blocked only by the already documented
missing NASM prerequisite.

Commit:

- `3d75741 feat: expose generic backend workflows`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### 9B implementation

#### Secret-free external views

The final boundary review found that returning the core `VpnInstance` could
serialize Xray TLS certificate/private-key references even though the frontend
did not need them. Unit 9B therefore completes the external-view model:

- `BackendSettingsInput` is a strongly typed creation/public-settings enum
  whose Serde representation matches the core backend discriminator but whose
  Xray variant has no TLS secret-reference fields;
- `PublicXraySettings` contains only security/transport, SNI/camouflage host,
  fingerprint, XHTTP path, and REALITY public key/short ID;
- converting public Xray settings to core settings always initializes both TLS
  references to `None`;
- `InstanceView` carries all non-secret instance/network/DNS fields and converts
  core backend settings to the public enum, deliberately dropping any existing
  Xray TLS references;
- Tauri and routine CLI create/list commands use `InstanceView`;
- the unused raw `update_instance(VpnInstance)` Tauri command was removed
  rather than leave a frontend path that could submit internal settings;
- Tauri device commands now accept `UpdateDeviceInput` and return `DeviceView`
  for create/update/list/replacement.

The CLI still exercises the same application service, but its routine JSON
output now uses the same public instance/device views as the desktop. Secret
material remains available only through explicit file export, and opaque
secret reference UUIDs are absent from routine frontend and CLI payloads.

#### Capability-driven desktop

Tauri exposes the application backend catalog through one thin
`backend_options` command. Svelte loads it alongside instances and derives:

- the backend's display name and default listener port;
- whether device addresses and routed controls apply;
- whether managed DNS controls apply;
- whether a quick credential refresh button is valid;
- whether QR export is supported;
- whether disable means reversible identity disable or irreversible
  certificate revocation.

Instance rows now show WG, AWG, OVPN, IKE, or XRAY badges and backend names.
Xray rows omit misleading subnet/private-zone summaries. Device rows show a
public-key, certificate Common Name, IKE identity, or VLESS email label rather
than assuming every device is a WireGuard peer. Disabled certificate
identities are shown as revoked and cannot present a misleading Enable action;
replacement is the recovery workflow already enforced by the application.

Health presentation uses the generic readiness contract:

- Compose project;
- gateway container;
- backend readiness;
- listener readiness;
- client desired-state match;
- DNS container and resolution only when `dns_required` is true.

Legacy WireGuard/watchtower health fields remain in the TypeScript response
shape for compatibility but no longer distort the required-check summary.

#### Conditional instance and device forms

The instance modal retains the existing visual language and exposes:

- WireGuard userspace fallback, routed subnet/DNS, routing mode, endpoint, and
  UDP listener;
- AWG2 routed controls plus collapsible Jc/Jmin/Jmax, S1-S4, and H1-H4
  validated default ranges;
- OpenVPN UDP/TCP transport, custom port, AES-256-GCM or
  ChaCha20-Poly1305, tls-crypt policy, certificate lifetime, routing, and DNS;
- IKEv2 server certificate identity, bounded client certificate lifetime,
  fixed UDP 500/4500 explanation, routing, and DNS;
- Xray REALITY, TCP/XHTTP, custom listener, SNI/camouflage host, browser
  fingerprint, and conditional XHTTP path, without routed-address/DNS fields.

The backend selection handler reads the selected value directly before deriving
the port. Instance toolbar handlers similarly store the selected instance
before refreshing dependent data; this avoids Svelte's event-before-binding
ordering from refreshing the previously selected instance.

Xray TLS/mKCP are displayed as unavailable choices rather than pretending they
can be provisioned securely. The backend supports TLS only with certificate and
private-key references, but no reviewed file-import command currently moves
those secrets directly from local files into the native store. Enabling TLS in
Svelte would either expose PEM material or accept arbitrary reference IDs, so
REALITY is the supported desktop creation path until that separate secure
import workflow exists. REALITY private material is still generated only on
the verified remote host; the UI receives only public discovery values after
deployment.

The device modal follows capabilities:

- WireGuard offers a unique per-device PSK;
- AWG2 explains its mandatory unique PSK;
- OpenVPN/IKEv2 explain local private-key generation plus verified-SSH CSR
  signing;
- Xray explains UUID identity and hides address/DNS/PSK controls;
- managed DNS inputs appear only for routed backends.

Export dialogs select `.conf`, `.ovpn`, protected `.p12`, or `.vless.txt`
according to the public backend kind. QR appears only when the backend declares
that capability. Messages distinguish local desired-state revocation from
immediate certificate revocation.

### 9B validation

Passing exact-current gates:

- 20 application tests, including a synthetic Xray TLS instance proving its
  public JSON contains neither reference field name nor reference UUID;
- 3 CLI tests;
- Tauri library/binary compilation and doc tests;
- strict Clippy for application, CLI, and Tauri, all targets, with
  `-D warnings`;
- `svelte-check`: 0 errors and 0 warnings;
- Vitest: 2/2 tests;
- Vite production build: 113 modules transformed and a complete `dist` bundle;
- formatting and `git diff --check`.

The root pnpm wrapper first stopped at
`ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY`. Direct installed
`svelte-check`, Vitest, and Vite initially encountered sandbox-only `EPERM`
reads of pnpm-linked modules, then passed unchanged outside that restricted
read sandbox. No dependency install or module purge occurred.

The Rust gates again used the temporary Ring diagnostic after the native
AWS-LC path stopped on missing NASM. `Cargo.toml` and `Cargo.lock` are restored;
`cargo tree -i aws-lc-rs -e features` confirms the delivered default
russh/AWS-LC graph.

A localhost production preview was started for visual smoke testing, but the
in-app browser runtime itself exited before navigation with a Windows sandbox
`EPERM` while resolving `C:\Users\william\AppData`. The exact preview process
was stopped. No visual-interaction result is claimed; the successful Svelte
diagnostics and production bundle are the available frontend proof in this
environment.

## Unit 10: Explicit fresh-host prerequisite provisioning

### 10A plan

The final definition-of-done audit found one functional gap: deployment checks
for Linux, direct Docker access, and Docker Compose v2, but it cannot prepare a
fresh supported Linux host. This unit adds that workflow without turning normal
deployment into an implicit package-manager mutation.

The work is split into these independently validated functional steps:

1. Extend the shared protocol with typed package-manager and provisioning-plan
   data. Host inspection will distinguish a missing Docker CLI, an inaccessible
   daemon, a missing Compose v2 plugin, root authority, and noninteractive sudo.
   It will detect apt, dnf, yum, zypper, and pacman in the same order as the
   Amnezia client reference.
2. Add application planning and application methods. Planning is read-only and
   returns a deterministic operation list, security warnings, and a SHA-256
   hash bound to the observed host state. Applying will re-inspect and re-plan,
   reject a stale or altered hash, execute one fixed idempotent script over the
   already verified SSH connection, then open a new verified SSH operation and
   require Linux, direct Docker access, and Compose major version 2 or newer.
3. Expose the workflow through explicit CLI and Tauri commands. No package
   installation will occur during host inspection or instance deployment.
4. Add a host-setup review modal to the desktop. A failed inspection will show
   the detected package manager and authority, let the operator preview each
   operation and warning, and require a separate Apply action.
5. Add focused tests for all five manager scripts, no-op hosts, unsupported or
   unprivileged hosts, stale plans, non-zero SSH exit handling, and secret
   redaction. Then repeat the relevant Rust, Tauri, Svelte, Vitest, production
   bundle, formatting, and patch-sanity gates.

Security and runtime decisions:

- provisioning accepts only a currently approved SSH host key;
- package installation requires root or `sudo -n`; sudo passwords are never
  collected, stored, or placed in a command;
- only distribution package managers are used; there is no `curl | sh`,
  third-party repository bootstrap, or unverified downloaded installer;
- operations use fixed command templates selected from a closed enum, and
  remote host or user data is never interpolated into a shell program;
- Docker service startup uses systemd when present and a conventional service
  fallback otherwise, followed by a hard Docker/Compose verification;
- adding the SSH user to the Docker group is presented as a security-sensitive
  operation because that group grants root-equivalent host control;
- package and service commands are guarded so rerunning the same plan is safe;
- the existing deployment prerequisite gate remains fail-closed, so setup and
  VPN deployment stay separate and understandable.

Expected validation for step 1 is protocol serialization plus application
inspection tests. Expected validation for step 2 is deterministic plans and
scripts, stale-state rejection, non-zero-exit authority, and post-apply
reinspection. Expected validation for steps 3 and 4 is parser/compile checking
and frontend diagnostics. Any failing gate stops the unit for diagnosis before
the next step or signed commit.

### 10A implementation

The shared protocol now treats prerequisite setup as first-class data:

- `PackageManager` is a closed apt/dnf/yum/zypper/pacman enum;
- `HostInspection` reports the detected manager, effective-root status, Docker
  CLI installation, direct Docker access, privileged Docker access, Docker
  group membership, Compose version, and the pre-existing kernel/root/sudo
  checks;
- `HostProvisioningOperation` describes Docker Engine installation, Compose
  plugin installation, service enablement, Docker access grant, and final
  verification;
- `HostProvisioningPlan` binds those operations and security warnings to a
  SHA-256 `expected_state_hash`.

Inspection remains non-mutating. Its fixed shell program reports exit statuses
as key/value data and detects package managers in the reference client's
apt/dnf/yum/zypper/pacman order. It separately asks whether the current SSH
session can use Docker and whether root or `sudo -n` can reach the daemon. That
distinction prevents a stopped service from being mislabeled as only a group
permission problem.

`plan_host_provisioning` enforces these cases:

- a Linux host with direct Docker and Compose v2 produces an empty no-op plan;
- a non-Linux target is rejected with manual-preparation remediation;
- any required mutation without root or noninteractive sudo is rejected;
- package changes without a supported manager are rejected;
- missing Docker plans Engine installation;
- missing or pre-v2 Compose plans a Compose v2 distribution package;
- an unreachable privileged daemon plans service startup;
- a non-root user who lacks direct access and group membership plans an
  explicit Docker-group grant;
- every mutating plan ends with a verification operation.

The plan hash covers the host ID, complete observed inspection, and ordered
operations. `apply_host_provisioning` immediately re-inspects and recreates the
plan, then rejects a mismatched hash before executing setup. A matching plan
selects one closed script template; no host-supplied value is interpolated.
After the command, the application performs another verified-SSH inspection.
Success requires Linux, an installed and directly accessible Docker Engine,
and Compose major version 2 or newer. This new SSH operation is important
because group membership only takes effect for a new login session.

The fixed scripts use:

- apt: `docker.io`, `ca-certificates`, `iproute2`, then
  `docker-compose-v2` or `docker-compose-plugin` only when available;
- dnf/yum: a repository-available `docker` or `moby-engine`, plus
  `ca-certificates`/`iproute`, then a repository-available
  `docker-compose-plugin` or `docker-compose`;
- zypper: `docker`, `ca-certificates`, `iproute2`, then
  `docker-compose` with a plugin-package fallback;
- pacman: `docker`, `ca-certificates`, `iproute2`, and `docker-compose`
  with `--needed`.

All branches guard already-satisfied state, use only the configured
distribution repositories, start Docker through systemd or a conventional
service fallback, and verify privileged Docker plus Compose v2 before returning.
The application then verifies direct unprivileged access separately. A failed
setup is conservatively reported as potentially having changed remote state;
stderr passes through structured secret redaction.

Ordinary VPN deployment still only validates prerequisites. Its remediation
now directs the operator to the separate setup preview rather than silently
installing packages during Apply.

### 10A validation

The first focused test run stopped with 25/26 application tests passing. The
new all-manager invariant found that pacman used `--needed` but did not include
the same explicit `command -v docker` guard as the other four branches. The
branch was corrected, and the exact suite was rerun before any further work.

Passing gates after that correction:

- 26 application tests, including deterministic/no-op planning, all five fixed
  package-manager templates, unsupported-manager and missing-authority errors,
  Docker root-equivalence disclosure, stale-hash rejection, authoritative
  non-zero SSH exit handling with stderr redaction, and successful fresh-session
  reinspection;
- 2 protocol tests;
- strict Clippy for protocol and application, all targets, with `-D warnings`;
- formatting and `git diff --check`.

As in earlier units, native compilation used the temporary Ring diagnostic
because this machine lacks NASM for AWS-LC. The manifest was restored after the
gates, and `cargo tree -i aws-lc-rs -e features` confirms the delivered default
russh/AWS-LC graph. The intentional lockfile change only adds the existing
workspace-pinned `sha2` crate to `vam-application`.

Commit:

- `00933dc feat: provision fresh Docker hosts safely`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### 10B plan

The client exposure remains deliberately thin:

1. Add `host-provision-plan` and `host-provision-apply` developer CLI commands.
   Apply requires `--expected-state-hash`; there is no force or bypass flag.
2. Add matching Tauri commands returning the protocol plan/inspection types,
   and register them in the single invoke handler.
3. Extend TypeScript types with the closed package-manager and operation
   shapes. The frontend will render human descriptions from operation
   discriminators but will never receive or construct a shell script.
4. Add a Review setup action beside host inspection when deployment
   prerequisites are not ready. The action obtains a fresh Rust plan and opens
   a dedicated modal containing manager, ordered operations, warnings,
   root/sudo authority, and the root-equivalent Docker-group warning. Apply
   sends only host ID plus the exact state hash, then replaces the visible
   inspection with the post-apply inspection returned by Rust.
5. Validate CLI parsing/dispatch, Tauri compilation, Svelte diagnostics,
   frontend tests, production bundling, formatting, and patch sanity before a
   separate signed commit.

### 10B implementation

The developer CLI now has two deliberately separate commands:

- `host-provision-plan <host-id>` performs verified inspection and prints the
  typed plan;
- `host-provision-apply <host-id> --expected-state-hash <hash>` re-plans,
  rejects stale state, applies the fixed setup, and prints the post-apply
  inspection.

There is no force switch, raw-command argument, package override, or way to
skip the state hash. Tauri exposes the same two application methods as thin
commands and registers them beside host inspection.

The TypeScript boundary mirrors the protocol's closed package-manager and
operation discriminators. It does not define or receive a script field. The
desktop translates only those discriminators into operator-facing descriptions
such as “Install Docker Compose v2 from the distribution repository.”

Host inspection now presents separate status for:

- Docker CLI/Engine installation;
- direct Docker access by the SSH user;
- privileged Docker daemon access;
- actual Compose v2 readiness rather than any nonempty Compose string;
- detected package manager;
- root or noninteractive-sudo setup authority;
- WireGuard kernel availability and `/opt` bootstrap access.

Selecting another host clears the previous inspection and setup plan, avoiding
an inspection/action mismatch. When prerequisites are incomplete, an explicit
Review setup call asks Rust for a fresh plan. The modal shows package manager,
authority, ordered operations, warnings, and the full observed-state hash. The
Docker-group operation is written as root-equivalent access in both the
application warning and visible operation label.

Apply sends only the plan's host ID and expected state hash. The modal remains
available if Rust rejects or fails the operation; on success, it is replaced by
the post-apply inspection returned after the fresh SSH check. Normal deploy
preview remains a separate workflow and cannot trigger package installation.

### 10B validation

Passing gates:

- 4 CLI parser tests, including rejection of host setup Apply without
  `--expected-state-hash`;
- Tauri library and binary test compilation;
- strict Clippy for CLI and Tauri, all targets, with `-D warnings`;
- `svelte-check`: 0 errors and 0 warnings;
- Vitest: 2/2 tests;
- Vite production build: 113 modules transformed and a complete bundle;
- formatting and `git diff --check`.

The Rust gates used the temporary Ring diagnostic and then restored the
workspace manifest. `cargo tree -i aws-lc-rs -e features` again confirms the
delivered default russh/AWS-LC graph. The frontend tools ran directly from the
installed workspace binaries outside the restricted read sandbox because
pnpm-linked dependencies under the user profile otherwise raise `EPERM`; no
packages were installed or changed.

Commit:

- `7b6de0e feat: review host setup from every client`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

## Unit 11: Definition-of-done audit and current-state documentation

### 11A plan

The closing test inventory maps every requested category to an existing test.
Three semantics are implemented but not named as directly as the specification:
WireGuard and AWG settings-change classification, and full-tree rollback of
backend persistent state. This unit will:

1. add explicit WireGuard/AWG assertions that same settings are live/no-op,
   same-backend changes require only a service restart, and a backend mismatch
   is destructive reinstall class;
2. exercise `restore_backup` with Xray's persistent identity directory and
   assert that rollback copies the complete instance tree, starts Compose,
   performs backend health, and preserves the numeric persistent-mount
   ownership through archive semantics;
3. replace WireGuard-only README, architecture, remote-format, deployment,
   security, and VM-testing claims with checkout-specific multi-backend
   documentation;
4. run the entire Rust workspace suite and strict workspace Clippy through the
   same temporary native-crypto diagnostic, restore AWS-LC, then repeat all
   frontend gates and patch sanity;
5. record exact environmental limits: Docker/POSIX integration and native
   Windows/macOS/Linux package builds are not available in this checkout
   session, and the normal Windows AWS-LC build still requires NASM.

### 11A implementation

The closing audit added direct evidence for behavior that had previously been
implicit:

- WireGuard and AWG settings classifiers now return `LiveUpdate` for equal
  same-backend settings, `ServiceRestart` for a same-backend settings change,
  and `Reinstall` for a cross-backend settings payload. This avoids treating an
  accidental discriminator mismatch as an ordinary restart.
- Deployment planning and Apply both compare the current settings with the last
  successful snapshot. A restart-class change adds an explicit gateway-restart
  warning. A reinstall-class change adds a destructive warning that tells the
  operator to review persistent identity impact before Apply.
- Host inspection and backend health now reject a non-zero remote exit status
  before parsing otherwise plausible stdout. The structured technical detail
  includes the numeric status plus redacted stdout and stderr.
- The full-tree rollback test uses an Xray instance and proves that archive-mode
  copy restores the complete instance directory before Compose and backend
  health. The plan expected a separate numeric-ownership normalization call,
  but the implementation trace showed that `cp -a` preserves Xray's numeric
  UID/GID ownership and that host-user normalization intentionally does not
  apply to numeric mounts. The test was corrected to require the two actual
  operations rather than demand a redundant `chown`.

The security-document reconciliation then exposed a more important modeling
error: the initial Xray implementation treated the VLESS UUID as public device
metadata. A VLESS UUID is bearer authentication material, so an inline UUID in
device JSON violated the repository rule that SQLite holds opaque references
instead of secret values.

The corrected lifecycle is:

1. Rust generates a UUIDv4 and a separate `SecretReference`.
2. The UUID value is staged in the native credential store.
3. `XrayDeviceData` stores only `client_id_ref`, email, and flow.
4. Device creation/replacement registers the reference transactionally as
   `xray_client_id`; failed persistence deletes the staged value.
5. Backend server rendering resolves enabled-device UUIDs inside Rust,
   validates every value as a UUID, rejects duplicate references and duplicate
   resolved values, then serializes the protected client list with
   `serde_json`.
6. Explicit VLESS export resolves only the selected device's reference.
7. `DevicePublicIdentity::Xray` and the TypeScript union contain only email and
   flow. Neither the credential nor its opaque reference crosses Tauri or
   appears in routine CLI JSON.
8. Snapshot retention now sees the Xray reference through the same generic
   `DeviceBackendData::secret_references` path as every other backend.

No legacy-Xray value migration was added. Xray did not exist in the pre-refactor
schema; it was introduced by this same unreleased multi-backend change.
Inventing a conversion for an inline UUID would either leave the bearer value
in SQLite or create a reference with no matching native-store entry. Failing
old development-only inline records is safer than silently manufacturing a
broken credential relationship. The real migration guarantee remains the
specified schema-0001 WireGuard upgrade path.

The current-state security and architecture documents now classify the Xray
UUID explicitly, describe its local/SQLite/remote locations, and distinguish
manifest digests from raw secret bytes. Remote manifests contain one-way
digests; WireGuard/AWG key lines are normalized before hashing, while a changed
high-entropy Xray UUID or imported TLS value may affect only its digest so
credential drift remains detectable.

### 11A focused validation

The first focused application run stopped with 28/29 tests passing. The only
failure was the older identity-generation test asserting that Xray created no
pending secret. Its expectation was updated to require exactly one reference
whose staged value parses as a UUID; the complete focused unit was then rerun.

Passing gates:

- 29 application tests;
- 10 Xray backend tests, including missing, malformed, shared-reference, and
  duplicate resolved UUID rejection;
- 9 core tests;
- strict Clippy for core, application, Xray, WireGuard, and AWG, all targets,
  with `-D warnings`;
- formatting and `git diff --check`.

The focused Rust gates used the temporary Ring diagnostic because this Windows
host lacks NASM for the normal AWS-LC build. The exact manifest line was
restored, `cargo tree -i aws-lc-rs -e features` restored and confirmed the
production AWS-LC graph, and neither `Cargo.toml` nor `Cargo.lock` has a
delivered diff.

Commit:

- `3659281 fix: close multi-backend security gaps`;
- verified good EDDSA signature from William Jones' configured YubiKey-backed
  key `7D6EF134D851C8DA0862D97494F31AF374E2EE3C`.

### 11B current-state documentation and full validation

The closing documentation pass replaced the former WireGuard-only presentation
with checkout-specific descriptions of all five backends. The README, trust
boundaries, remote format, deployment/recovery flow, security matrix, and VM
acceptance guide now each state:

- server implementation and listener transport/port behavior;
- minimum container capabilities/devices/sysctls and Docker-socket exclusion;
- persistent server identity, CA, CRL, or REALITY state;
- local, remote, transient, and reference-only credential locations;
- client identity, export, disable/revoke/replace behavior;
- change-impact, image update, backup, and full-tree rollback behavior;
- fresh-host package-manager setup and the boundary separating it from normal
  deployment;
- backend-appropriate DNS and health semantics;
- current desktop limitation for Xray TLS/mKCP pending a reviewed native PEM
  import path.

Relative Markdown links were resolved across eight principal documents,
including the Amnezia SSH provisioning report. A contradiction search found no
remaining claim that WireGuard is the only backend, no public TypeScript
`client_id`, and no statement that the Xray UUID lacks a secret reference.
`git diff --check` is clean.

Full passing gates:

- `cargo test --workspace`: 117 unit tests across application, five concrete
  backends, core, deployment, CLI, DNS, protocol, secrets, SSH, and storage,
  plus all workspace doc tests;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo fmt --all -- --check`;
- `svelte-check`: 0 errors and 0 warnings;
- Vitest: 1 file and 2/2 tests;
- Vite 7.3.6 production build: 113 modules transformed and a complete bundle.

The first Svelte-check shell invocation used a repository-relative executable
while its working directory was already `apps/desktop`; PowerShell therefore
tried to load `apps` as a module before Svelte started. The command was corrected
to `.\node_modules\.bin\svelte-check.cmd`, after which the gate passed. A
separate documentation-check wrapper initially had an unterminated PowerShell
search string; removing the unnecessary escaped quote allowed all link,
contradiction, and patch-sanity checks to run successfully. Neither invocation
failure changed repository files.

The complete Rust suite used the same temporary Ring-only `russh` diagnostic.
Afterward the exact production dependency declaration was restored and
`cargo tree -i aws-lc-rs -e features` confirmed default AWS-LC resolution.
There is no `Cargo.toml` or `Cargo.lock` diff.

Environment-bounded checks not claimed:

- no live Docker/POSIX backend provisioning, listener, firewall, CA, or
  rollback integration was run against a Linux VM;
- no Windows installer, macOS universal package, or Linux package was built;
- the normal Windows AWS-LC compile remains blocked until NASM is available,
  and no machine prerequisite was installed without approval;
- browser visual interaction remains unverified because the in-app browser
  runtime previously stopped on a Windows sandbox `EPERM` before navigation.

These are environment limitations, not substituted passing evidence. The
reusable, backend-specific VM acceptance procedure is recorded in
`docs/testing-vm.md`.

## 12. Backend-aware desktop UI implementation

### 12A. Authoritative backend presentation metadata

The desktop previously received only seven capability booleans plus the backend
name and default port. That was insufficient to render general screens without
repeating protocol comparisons in Svelte. The backend contract now owns a typed,
public-safe presentation description for every registered implementation:

- short and full names, visible text badge, and creation description;
- routed-tunnel versus proxy behavior, DNS/address/statistics capability, and
  configurable versus fixed-multiple listeners;
- supported client actions and the concrete export format that the backend
  actually renders;
- applicable configuration sections and fields;
- host requirements and a backend-specific identity replacement warning.

The application converts borrowed static backend metadata into an owned
`BackendPresentationView`, nested in each `BackendOptionView`. TypeScript mirrors
the serialized enums. Existing capability booleans remain temporarily available
for compatibility while the screens move to the richer contract. The metadata
does not contain secret references, private key paths, certificate references,
or configuration contents. IKEv2 advertises only its implemented protected
PKCS#12 export; Xray advertises only its implemented VLESS URI/QR representation.
No statistics action is exposed until the application can return real client
statistics.

Validation for this unit:

- `cargo check -p vam-application` passed;
- the five-backend descriptor matrix test passed and asserted capability/action
  consistency, exact badges, implemented exports, Xray proxy/DNS semantics, and
  serialized secret-reference absence;
- strict Clippy passed for `vam-backend`, all five concrete backend crates, and
  `vam-application` with all targets and `-D warnings`;
- `cargo fmt --all -- --check` and `git diff --check` passed;
- Svelte check passed with 0 errors and 0 warnings;
- Vitest passed 2/2 existing frontend tests.

The first focused Rust test attempt confirmed the production AWS-LC build still
cannot find NASM on the ordinary process PATH. The repository helper's existing,
previously installed portable NASM 3.02 was then added to the validation
process's PATH; no installation or machine change was performed, and the same
production AWS-LC dependency graph passed. The normal pnpm wrapper also hit its
known non-interactive modules-directory guard and a blocked registry metadata
request, so the already-installed Svelte/Vitest executables were run directly.
Their first sandboxed launch hit Windows `EPERM`; the approved unsandboxed read
of existing dependencies passed.

Planned signed commit: `feat: expose backend UI metadata`.

### 12B. Presentation-safe instance, client, health, and deployment views

The original Tauri boundary returned persisted instances and devices almost
verbatim, exposed raw health booleans to Svelte, and represented deployment
operations as untyped JSON records. The application layer now constructs four
families of public-safe views while retaining the original internal APIs for
compatibility:

- instance summaries combine the persisted public instance, a backend-aware
  secondary/listener summary, client count, last deployment, and one operational
  state with its evidence source;
- instance details add host name, configured image, applicable non-secret fact
  rows, local desired-state drift, and the last deployment backup name;
- client views contain a Rust-built identity summary, state-specific actions,
  implemented export formats, optional statistics, and no secret identifiers;
- health and deployment-preview views replace backend-specific booleans and raw
  operation JSON with named checks, impact, drift, backup behavior, identity
  effects, and human-readable operations.

List state is deliberately local and honest. A new or locally changed desired
state is `needs_deployment`; applying work is `updating`; failed/rolled-back work
is `error`; and a matching successful deployment is `unknown` until an explicit
live health request returns evidence. Merely opening the Instances screen does
not create SSH connections. Live health produces Healthy, Degraded, Stopped, or
Needs deployment and uses backend-specific readiness labels without inventing a
handshake check. Statistics remain `null` until a real collector exists.

The client-facing Tauri API now offers client-named list commands while the
persisted `Device` model and original commands remain intact. Certificate rows
cannot offer Enable after revocation; they offer Replace identity instead.
Xray rows contain no managed address and no UUID or secret-reference fragment.
Deployment previews preserve the expected desired-state hash used by Apply, but
show sensitive file operations only as redacted labels/path metadata.

Validation for this unit:

- four focused application tests passed for five-backend health labels, local
  state derivation, typed deployment impacts/redaction, and state-aware Xray and
  OpenVPN client views;
- `cargo check -p vam-application` and the Tauri manifest check passed;
- strict application Clippy passed with all targets and `-D warnings` after
  consolidating one duplicate rebuild-impact branch that Clippy identified;
- `cargo fmt --all -- --check` and `git diff --check` passed;
- Svelte check passed with 0 errors and 0 warnings;
- Vitest passed 2/2 existing frontend tests.

Validation used the existing portable NASM 3.02 in the process PATH. No remote
host, Docker appliance, or secret store was contacted. Previous signed commit:
`f7c4ded feat: expose backend UI metadata` (good EDDSA signature).

Planned signed commit: `feat: add desktop presentation views`.

### 12C. Generic host readiness, backup provenance, and activity history

Host inspection formerly collected firewall facts but discarded them and had no
TUN result; the public card therefore had to interpret a WireGuard-only kernel
boolean. The single existing SSH inspection now also reports `/dev/net/tun` and
retains UFW/Firewalld implementation, activity, and management authority. Rust
evaluates every registered backend's declared requirements from that one result.
The resulting view separates trusted SSH, successful connectivity, Docker
readiness, and per-backend Ready, Ready with fallback, Needs setup, or
Unsupported states. No per-backend SSH command or render-time probe was added.

Migration `0003_desktop_activity_and_backups.sql` adds two append-compatible
tables without rewriting instances, devices, deployments, or their JSON:

- `backup_records` stores backend, reason, deployment association, timestamp,
  and whether a snapshot protects identity state;
- `activity_events` stores redacted, filterable operational history with host,
  instance, backend, operation, severity, and optional deployment context.

Manual, pre-deploy, reinstall-class, pre-upgrade, and certificate-credential
backups now receive provenance when created. Legacy remote backup directories
remain visible and are conservatively classified from their existing names.
Image update creates a full pre-upgrade snapshot before changing images.

Backup restore now reviews and targets the exact selected backup name. Names are
strictly constrained to a safe single path component, the preview is guarded by
an expected-state hash, and Apply creates a fresh pre-restore snapshot. A failed
target restore invokes the same full-tree restore/health path against that safety
snapshot and reports whether recovery succeeded. The UI-facing warning states
that server identity and client state are rewound and newer profiles may fail.

The new activity query combines typed activity records with historical
deployment progress and accepts host, instance, backend, operation, and severity
filters. Deployment phases receive readable titles, while technical details
remain separately expandable. Successful host inspections, client lifecycle
operations, exports, start/stop/health operations, backups, and restores now
write sanitized activity records. Existing deployment events remain the source
for deployment history, so no historical event migration is required.

Validation for this unit:

- all 35 application tests and all 13 storage tests passed, including existing
  full-tree restore/health coverage;
- focused readiness tests covered kernel fallback, TUN absence, ready AWG, and
  unsupported architecture;
- storage tests covered backup/activity round trips and all server-side filters;
- the legacy 0001 WireGuard fixture was migrated through 0002 and 0003 without
  instance/listener loss and with empty new history tables;
- unsafe backup path components and activity severity/title mapping were tested;
- strict Clippy passed for protocol, storage, and application with all targets
  and `-D warnings` after replacing one large-error helper with a pure predicate;
- the Tauri manifest check, Rust formatting, and `git diff --check` passed;
- Svelte check passed with 0 errors and 0 warnings; Vitest passed 2/2 tests.

No live host was inspected and no restore was executed against an appliance in
this unit. Validation used the existing portable NASM in the process PATH.
Previous signed commit: `1d7a8b6 feat: add desktop presentation views` (good
EDDSA signature).

Planned signed commit: `feat: add readiness backup and activity views`.

### 12D. Safe backend-aware instance creation and editing (2026-07-31)

The original creation command accepted public backend settings but had no
Rust-owned route for importing Xray TLS material. The only update helper accepted
an entire persisted `VpnInstance`, which would have allowed a future caller to
change the backend, host assignment, IDs, timestamps, or secret references. It
also had no optimistic-concurrency check or non-mutating consequence preview.

Creation now accepts an optional `XrayTlsImportInput` containing certificate and
private-key file paths. Rust reads bounded (maximum 1 MiB), UTF-8 PEM files,
validates both using the Xray backend, generates new opaque secret references,
and places the contents in the native secret store. Only those references enter
the internal `XraySettings`; `InstanceView`, `InstanceDetailView`, update
previews, and TypeScript public settings omit the references, paths, and PEM
contents. REALITY rejects supplied TLS files, TLS requires both files, and
non-Xray backends reject the import field. A failed secure-store write removes
any values written earlier in the same attempt; a subsequent database failure
also removes the newly written values.

Storage now has one shared transactional instance writer. TLS creation or
replacement commits the instance JSON, normalized listener rows, retirement of
the previous instance-owned secret references, and registration of the new
references in one SQLite transaction. Moving from Xray TLS to REALITY retires
the obsolete TLS references even though no new secret is written. Retired values
remain subject to the existing deployment-snapshot retention policy rather than
being deleted while a retained rollback might still need them.

The public update boundary is `UpdateInstanceInput`. It contains the instance ID
and editable desired-state fields, but deliberately has no host ID, backend kind,
persisted timestamps, or secret-reference fields. `preview_instance_update`
loads current state, verifies the caller's current-state SHA-256, validates the
candidate through core, backend, desired-state, and host-listener rules, and
returns typed impact, client re-export consequences, affected-client count, and
warnings without persisting or contacting the host. `update_instance` repeats
the hash and validation under the per-instance lock, then changes local desired
state only. Remote deployment remains a separate plan/apply workflow. The
current hash is returned with `InstanceDetailView` so Settings can make the
optimistic check explicit.

Compatibility is preserved: persisted `VpnInstance`, `Device`, and database
names are unchanged; existing creation payloads deserialize because the TLS
import is optional; the CLI explicitly supplies no import; and all five backend
default creation fixtures continue to pass. Name-only edits have no deployment
impact. Endpoint/listener/network changes report profile re-export impact, DNS
changes report DNS reload, backend settings use each backend's own change
classifier, and reinstall-class updates carry an identity/backup warning.

Files and subsystems changed:

- `crates/backend-xray/src/lib.rs`: public, redaction-safe TLS material validator;
- `crates/storage/src/lib.rs`: atomic instance/listener/secret-reference update;
- `crates/application/src/lib.rs`: safe inputs, TLS import lifecycle, optimistic
  update preview/save, typed impact, redaction, and focused tests;
- `apps/desktop/src-tauri/src/lib.rs`: preview and update Tauri commands;
- `apps/desktop/src/lib/types.ts`: exact public TypeScript contracts;
- `apps/cli/src/main.rs`: explicit compatibility default for TLS import.

Validation for this unit:

- `cargo test -p vam-backend-xray -p vam-storage -p vam-application` passed:
  11 Xray, 14 storage, and 37 application tests;
- focused tests covered PEM acceptance/rejection, transactional reference
  replacement, TLS public-view redaction, backend immutability, stale-update
  rejection, name-only impact, and endpoint client re-export impact;
- the existing five-backend creation matrix and WireGuard workflows remained
  green;
- `cargo clippy -p vam-backend-xray -p vam-storage -p vam-application -p
  vpn-appliance-manager --all-targets -- -D warnings` passed;
- `cargo fmt --all -- --check` and `git diff --check` passed;
- Svelte check passed with 0 errors and 0 warnings;
- Vitest passed 2/2 frontend tests.

The first compile command named the desktop package incorrectly as
`vpn-appliance-manager-desktop`; Cargo stopped before compilation and reported
the package did not exist. The command was corrected to the manifest's actual
package name, `vpn-appliance-manager`, and passed. A later strict Clippy run
stopped on six new style/helper-shape warnings; the helpers were simplified and
the identical impact branches consolidated, after which strict Clippy passed.
No live host, credential store, or remote service was contacted. Tests used
ephemeral UUID-named files under the operating-system temporary directory and
removed them. Rust validation used the existing portable NASM 3.02 by changing
only the command process PATH. Frontend validation used the already-installed
local binaries; no package installation occurred.

Previous signed commit: `cf1146f feat: add readiness backup and activity views`
(good EDDSA signature).

Planned signed commit: `feat: add safe backend-aware instance editing`.

### 12E. Componentized desktop shell and instance workspace (2026-07-31)

The desktop root was a 1,432-line component that combined startup orchestration,
all global screens, every backend form, all dialogs, and presentation helpers.
It loaded raw instances, global hostlists, selected-instance clients/DNS, remote
backup enumeration, and deployment-only logs on startup. The navigation still
called clients “Devices,” and selecting an instance exposed only inline row
actions rather than a persistent management workspace.

The application shell now starts from the presentation boundary introduced in
12B/12C: hosts, `InstanceSummaryView` records, the backend catalog, and unified
local activity. It derives the temporary public `VpnInstance` array from each
summary only for compatibility with workflows not yet migrated. Client and DNS
data load when their global screen or instance tab opens; hostlists load on DNS
entry; remote backups load only on Backups entry. Instance row selection itself
does not issue SSH, health, readiness, or backup calls. The primary navigation
and all newly touched visible labels now use Clients terminology while persisted
`Device` types and commands remain unchanged.

Manage opens a full-content workspace without replacing the navy sidebar. It has
a breadcrumb, instance name, full backend name beside its compact badge, honest
operational state, explicit Refresh health and Review deployment actions, and
Overview, Clients, DNS, Settings, Backups, and Logs tabs. Overview suppresses
network/DNS facts when descriptor capabilities make them meaningless. Xray's
DNS tab explains that managed private DNS is unsupported while still showing
global hostlists. Client, backup, and log renderers are shared by their global
screens and corresponding workspace tabs. Creating an instance now opens its
Overview and foregrounds the separate deployment-review action.

Reusable components introduced in `apps/desktop/src/lib/components` include
backend/state badges, empty state, instance selector, modal heading shell,
shared client/backup/log content, and the instance workspace. Backend-specific
creation controls moved into five isolated form components registered by one
`backendForms` map. Common form state/defaults live in `lib/instance-form.ts`.
The root no longer contains a repeated five-way backend markup chain for the
creation dialog. AWG detail remains collapsed; Xray TLS exposes certificate and
private-key file paths and sends those paths through `xray_tls_import`; PEM
contents are never read by JavaScript or rendered into the DOM.

The component split intentionally introduces no router, state library, or UI
framework. Existing native dialog calls, local state, colors, typography,
density, and plan/apply behavior remain in place. Shared components consume the
Rust descriptor/summary contracts rather than duplicating badge text or state
labels. The current raw client action and legacy backup restore paths remain
visible compatibility surfaces to be replaced by the typed workflows in the
next functional unit; this unit does not claim that those migrations are done.

Files and subsystems changed:

- `apps/desktop/src/App.svelte`: summary/activity startup, lazy entry loading,
  Clients navigation, workspace selection, shared renderers, and form registry;
- `apps/desktop/src/lib/components/*.svelte`: reusable presentation and scoped
  workspace/content components;
- `apps/desktop/src/lib/components/forms/*`: one form per backend plus registry;
- `apps/desktop/src/lib/instance-form.ts`: common wizard state and safe defaults;
- `apps/desktop/src/styles.css`: badge and workspace styles matching the existing
  visual system.

Validation for this unit:

- direct Svelte check passed with 0 errors and 0 warnings after the first
  component pass and again after the backend-form registry;
- Vitest passed 2/2 existing frontend tests;
- the production Vite web build passed (129 modules transformed, 115.02 kB
  JavaScript and 15.00 kB CSS before gzip);
- `git diff --check` passed;
- source inspection confirmed startup no longer invokes `list_instances`,
  `list_dns_hostlists`, `list_backups`, or selected-instance data commands;
  those remote/applicable datasets are reached only through explicit screen/tab
  entry functions.

No host inspection, health request, backup enumeration, deployment, or secret
read was executed during validation. Frontend tools were the already-installed
local binaries; no dependency or machine changes occurred. Full interaction,
responsive, focus, and per-backend fixture coverage is reserved for the later
workflow/accessibility/test units in this plan.

Previous signed commit: `3a5885a feat: add safe backend-aware instance editing`
(good EDDSA signature).

Planned signed commit: `refactor: componentize desktop management UI`.

### 12F. Backend-aware desktop workflows (2026-07-31)

The componentized shell still retained several compatibility surfaces: raw
`InstanceHealth` booleans after Apply and refresh operations, raw `DeviceView`
in client rows, raw `DeploymentOperation` JSON in the preview, deployment-based
rollback rather than exact backup restore, a flat creation form, and a Settings
tab with no editor. Host cards also rendered generic Docker/WireGuard checks
instead of the all-backend readiness evaluation already available in Rust.

The application/Tauri boundary now has presentation-safe wrappers for Apply,
host provisioning, credential refresh, and DNS refresh. Each wrapper reuses the
already obtained result; it does not run a second SSH health or inspection
probe. Svelte no longer imports or indexes `InstanceHealth`. Named checks,
configured image, observation time, and the generic operational state flow into
status notices. Explicit Start, Stop, Health, Apply, Restore, and refresh actions
update the selected summary with live evidence; ordinary rendering remains
local and does not claim a running state.

Instance rows now use the Rust-produced summary/state and keep Manage visible,
with Start, Stop, Refresh health, Preview deployment, Backup, and separately
labelled Delete in a compact action menu. Deployment review calls
`plan_instance_preview`, renders typed impact/backup/server/client consequences,
and shows the redacted human-readable operation label. Technical operation
detail is expandable; Svelte no longer serializes raw operation objects.

Client screens now load `ClientView` and render its identity summary, optional
managed address, state label, exact export formats, and state-specific
`ClientActionView` list. Labels, warnings, destructive designation, QR
availability, certificate revocation/replacement behavior, and statistics
absence therefore come from Rust. Xray has no invented IP or exposed UUID.
Export extension selection follows the advertised export enum (WG/AWG config,
OVPN, protected PKCS#12, or VLESS URI), and QR is callable only when Rust
advertises it. Confirmation dialogs display the backend-provided consequence
warning. User-facing validation/activity language touched in this unit now says
Client while persisted `Device` APIs and storage remain unchanged.

Host Inspect calls the single `inspect_host_view` command. The resulting matrix
separates SSH trust, connectivity, Docker/Compose readiness, and Ready, Ready
with fallback, Needs setup, or Unsupported for all five backends. Applying a
host setup returns the same typed matrix from its final verification result.
Opening or selecting a host still does not inspect automatically.

Backups load `BackupView` with instance/backend/reason metadata. Every Restore
button first calls `preview_backup_restore`, displays identity and affected-client
impact plus the mandatory safety snapshot, then calls `restore_backup_by_name`
with the exact selected name and expected hash. The backend continues to health
verify and automatically recover from the pre-restore snapshot on failure. The
legacy deployment rollback command is no longer reachable from the desktop
backup UI. Logs use `activity_logs` with server-side host, instance, backend,
severity, and operation filters and retain technical detail behind expansion.

Creation is now a five-step wizard: cached host readiness, descriptor-backed VPN
type cards, common basics, isolated backend form, and applicable review facts.
It has only Create; successful creation opens Overview with Review deployment.
AWG advanced defaults remain collapsed, IKEv2 explains its fixed UDP listeners,
and Xray supports REALITY or TLS/mKCP as allowed. Xray TLS certificate and key
paths come from native file pickers. JavaScript never opens the files; Rust reads,
validates, stores, and persists only opaque references.

The workspace Settings tab now opens a safe editor. Backend and host are shown
read-only because `UpdateInstanceInput` omits both. The editor requests a
non-mutating `preview_instance_update`, shows server identity/client re-export
effects, requires explicit acknowledgement for disruptive impacts, and only then
saves local desired state with the current-state hash. Deployment remains a
separate reviewed action. Existing Xray TLS material is retained when both file
paths are blank; replacement requires both paths and is handled by Rust's
transactional secret workflow.

Files and subsystems changed:

- `crates/application/src/lib.rs`: view wrappers that reuse Apply/provisioning/
  refresh results and Client terminology in public errors;
- `apps/desktop/src-tauri/src/lib.rs`: corresponding presentation-safe commands;
- `apps/desktop/src/App.svelte`: typed workflows, wizard, safe Settings preview,
  exact backup restore, server-side logs, and live evidence updates;
- `apps/desktop/src/lib/components`: client action group, deployment impact,
  readiness matrix, instance action menu, and log filters;
- shared client/backup/workspace components and Xray form updated to consume the
  new contracts and native file selection;
- `apps/desktop/src/lib/types.ts` and `styles.css`: exact DTO and visual support.

Validation for this unit:

- all 37 application tests passed, including existing descriptor, health,
  client-state, backup recovery, readiness, redaction, and safe-edit tests;
- strict Clippy passed for `vam-application` and the Tauri desktop package with
  all targets and `-D warnings`;
- Svelte check passed with 0 errors and 0 warnings;
- Vitest passed 2/2 existing frontend tests;
- the Vite production build passed (134 modules, 127.81 kB JavaScript and 18.45
  kB CSS before gzip);
- Rust formatting and `git diff --check` passed.

The first Svelte check correctly stopped on the two remaining raw health types
used by credential and DNS refresh. Presentation wrappers were added and the
check was rerun. A later check stopped on TypeScript's nullable narrowing inside
a Settings descriptor callback; the lookup moved to a typed helper and passed.
No remote host, Docker service, backup, credential store, or certificate file
was accessed during validation. Rust used the existing portable NASM through
the command process PATH, and frontend tools used existing local dependencies.

Previous signed commit: `1296493 refactor: componentize desktop management UI`
(good EDDSA signature).

Planned signed commit: `feat: deliver backend-aware desktop workflows`.

### 12G. Responsive and accessible native UI (2026-07-31)

The desktop shell previously imposed a 900-pixel minimum in both Tauri and
global CSS. Dense panels could consequently force whole-application horizontal
overflow, the sidebar could not contract, workspace/DNS tabs depended on mouse
clicks, the compact instance action menu lacked explicit dismissal behavior,
and modal focus was not contained or restored. These limitations conflicted
with the required 800×600 native baseline even though the established navy,
light-panel, compact control-plane presentation remained appropriate.

The native minimum is now 800×600 while the default remains 1180×760. The
global body minimum width was removed. At narrow desktop widths the sidebar
becomes a 76-pixel icon rail whose real buttons retain accessible names and
native title tooltips; primary content, stat grids, readiness matrices,
toolbars, cards, and forms reflow. Horizontal overflow is limited to panels
that are genuinely tabular. Primary actions remain outside the compact
instance overflow menu.

Global navigation and every operation remain real buttons. A consistent
`:focus-visible` outline was added. Workspace and DNS tabs now implement
`role=tab`, selected state, stable tab/panel IDs, roving tab stops, and
Left/Right keyboard navigation; workspace tabs additionally support Home and
End. The instance overflow menu closes on outside pointer input and Escape,
restoring focus to its summary control. Shared instance selectors have stable
IDs and explicit labels.

The application modal is now labelled, modal to assistive technology, and
focusable. Opening captures the invoking control and moves focus into the
dialog; Tab and Shift+Tab stay within its controls; Escape or a backdrop click
closes it; focus returns to the invoker. Closing also clears QR SVG and pending
Xray certificate/key paths so sensitive or export-derived material is not kept
in ordinary UI state. Busy messages use polite live regions, and destructive
actions continue to carry explicit text such as `Delete instance` and
`Restore this backup`, rather than relying on color.

Files and subsystems changed:

- `apps/desktop/src-tauri/tauri.conf.json`: 800×600 native minimum;
- `apps/desktop/src/App.svelte`: accessible navigation, DNS tabs, modal focus
  lifecycle, live status, and sensitive transient-state clearing;
- `apps/desktop/src/lib/components/InstanceWorkspace.svelte`: keyboard tablist;
- `InstanceActions.svelte`: dismissible, focus-restoring overflow menu;
- `InstanceSelector.svelte`: stable explicit form labelling;
- `apps/desktop/src/styles.css`: rail, local overflow, responsive grids/stacks,
  and visible keyboard focus without changing the established palette.

Validation for this unit:

- Svelte check passed with 0 errors and 0 warnings;
- Vitest passed the existing 2/2 frontend tests;
- the Vite production build passed (134 modules, 131.42 kB JavaScript and
  20.14 kB CSS before gzip);
- `cargo check -p vpn-appliance-manager`, Rust formatting, and strict Clippy for
  the Tauri package with all targets and `-D warnings` passed using the existing
  process-local portable NASM path;
- `git diff --check` passed;
- in-app browser checks at 1180×760, 900×600, and 800×600 found no document
  wider than its viewport; the full sidebar became the compact rail at both
  narrow sizes;
- keyboard checks reached all six global screens, opened the Add SSH host
  dialog, closed it with Escape, and confirmed focus returned to Add host.

The browser validation used the already-running local Vite server. A plain web
page cannot supply Tauri's native `invoke` bridge, so it correctly displayed a
startup error and empty local screens; backend-populated tab and per-backend
fixture behavior is covered in the following component-test unit rather than
being misreported as native runtime proof. No host inspection, SSH connection,
remote operation, dependency installation, or machine change occurred.

Previous signed commit: `f8efa79 feat: deliver backend-aware desktop workflows`
(good EDDSA signature).

Planned signed commit: `fix: improve desktop responsiveness and accessibility`.

### 12H. Automated desktop workflow coverage (2026-07-31)

The frontend previously had only two pure error-formatting tests and no DOM
environment. Capability-driven rendering, lazy command boundaries, keyboard
interaction, restore warnings, and per-backend form isolation therefore lacked
repeatable component-level proof even though the Rust contracts were covered.

Vitest now has an explicit jsdom configuration and resolves Svelte through its
browser condition. Svelte Testing Library supplies semantic DOM queries and
event dispatch. The additions are development-only dependencies; they do not
enter the packaged application bundle or change runtime behavior. A small test
harness owns backend form data as Svelte reactive state so bindable controls are
tested under the same reactivity model as the application rather than producing
non-reactive test-only warnings.

Typed fixtures cover all five public backend descriptors without secrets.
Component coverage verifies badge plus full-name presentation, the implemented
QR matrix, Xray's lack of an invented managed address or exposed identifier,
revoked certificate replacement actions, five-backend readiness, exact backup
metadata, readable activity, typed reinstall consequences, overflow-menu focus
restoration, workspace keyboard navigation, Xray DNS unsupported messaging,
global hostlist independence, and all five isolated backend forms. The AWG2
advanced section is closed by default, IKEv2 documents both fixed listeners and
PKCS#12 export, and Xray REALITY rendering contains neither certificate inputs
nor private-key material.

An application integration fixture mocks only the Tauri command boundary. It
proves startup loads hosts, instance summaries, descriptors, and local activity
without clients, DNS hostlists, backups, inspection, or health. Entering the
relevant screen lazily loads its data. The fixture traverses Instances, Clients,
DNS, Hostlists, Backups, and Logs; it also verifies that an exact backup name is
sent to restore preview and that identity impact, affected clients, the safety
snapshot, and the explicit restore action are shown before mutation.

Files and subsystems changed:

- `apps/desktop/package.json` and `pnpm-lock.yaml`: test-only Svelte Testing
  Library and jsdom dependencies;
- `apps/desktop/vitest.config.ts` and `src/test/setup.ts`: browser-conditioned
  jsdom setup with deterministic cleanup;
- `src/test/fixtures.ts` and `BackendFormHarness.svelte`: typed, non-secret
  backend/application fixtures;
- `src/lib/components/presentation.test.ts`: presentation, capability,
  accessibility, readiness, backup, log, and workspace scenarios;
- `src/lib/components/forms/backend-forms.test.ts`: all backend form surfaces;
- `src/App.integration.test.ts`: mocked-native lazy-loading and cross-screen
  workflows.

Validation for this unit:

- full Vitest passed 24/24 tests across four files;
- Svelte check passed with 0 errors and 0 warnings;
- the production Vite build passed unchanged at 134 modules, 131.42 kB
  JavaScript and 20.14 kB CSS before gzip;
- `git diff --check` passed;
- dependency installation passed the repository's pnpm supply-chain policy
  check; only the desktop development manifest and workspace lockfile changed.

The first test run stopped because Vitest had selected Svelte's server export;
the config now explicitly selects the browser condition. The second run reached
19/20 tests and exposed Testing Library's `events` mount-option collision plus
test-only non-reactive form inputs; an explicit props envelope and reactive
harness corrected both. A subsequent Svelte check stopped on one widened fixture
string and passed after narrowing it to the declared readiness union. No
production behavior was weakened to make a test pass.

No native secret store, file picker, SSH host, backup repository, or remote
service is touched by these tests. Native command behavior remains covered by
Rust tests; this suite verifies the Svelte side of that typed boundary.

Previous signed commit: `62fdc79 fix: improve desktop responsiveness and accessibility`
(good EDDSA signature).

Planned signed commit: `test: add desktop workflow coverage`.

### 12I. Consolidated backend-aware UI validation (2026-07-31)

The completed refactor now has one Rust-owned presentation contract for all five
backends, presentation-safe instance/health/client/deployment views, one-pass
host readiness, exact and recoverable backup restore, unified redacted activity,
safe creation and optimistic settings APIs, a componentized capability-driven
desktop workspace, responsive/keyboard behavior, and DOM-level regression
coverage. Persisted `Device` and `devices` naming remains unchanged while all
ordinary user-facing management surfaces use Client terminology. No render-time
SSH health, backup, or readiness loop was introduced.

Final Windows prerequisite and packaging gate:

- `.\build-helpers\windows\build.ps1 -SkipToolInstall` passed;
- Visual Studio C++ tools, Node 24.18.0, WebView2, NASM 3.02, Rust 1.97.1,
  rustfmt, and Clippy were present;
- its full workspace verification passed and Tauri produced the NSIS installer
  at `target/release/bundle/nsis/VPN Appliance Manager_0.1.0_x64-setup.exe`;
- no missing prerequisite required approval or installation. The helper's
  existing Corepack step nevertheless printed `Installing pnpm@11.9.0` before
  confirming the required version and current lockfile. This did not change a
  source file or install system software, but it is recorded because
  `-SkipToolInstall` is not a completely passive pnpm-version check.

Final repository gates:

- frontend check: 0 errors and 0 warnings;
- frontend test: 24/24 tests passed across four files;
- frontend production build: 134 modules, 131.42 kB JavaScript and 20.14 kB
  CSS before gzip;
- Rust format check passed;
- strict `cargo clippy --workspace --all-targets -- -D warnings` passed;
- `cargo test --workspace` passed 128 tests with no failures;
- `cargo build --workspace` passed;
- root `pnpm verify` passed, repeating formatting, strict Clippy, all Rust tests,
  Svelte check, all frontend tests, and the frontend build;
- `git diff --check` passed after every functional unit and before the final
  documentation commit;
- manual responsive inspection passed at 1180×760, 900×600, and 800×600 with
  no document-level horizontal overflow; all global screens were reachable and
  modal Escape/focus restoration was confirmed.

GNU Make is not installed on this Windows host, so the literal requested
`make frontend-check`, `make frontend-test`, `make frontend-build`, `make test`,
and `make verify` invocations were unavailable. Their exact Makefile commands
were run directly (`pnpm --dir apps/desktop ...`, `cargo test --workspace`,
root `pnpm verify`, and `cargo build --workspace`). The detection-only Windows
helper independently ran the same verification chain and a release package,
providing a second end-to-end result rather than treating command substitution
as unverified equivalence.

No live SSH server or native credential store was available for destructive
manual workflows. Those paths were not simulated as remote-runtime proof:
backend command/render logic, migration, redaction, restore recovery, secret
transactions, and readiness matrices passed Rust tests; the Svelte command
boundary and user presentation passed mocked-native integration tests. No push,
release, host mutation, remote deployment, or remote backup operation occurred.

Signed implementation history, in order:

- `f7c4ded feat: expose backend UI metadata`;
- `1d7a8b6 feat: add desktop presentation views`;
- `cf1146f feat: add readiness backup and activity views`;
- `3a5885a feat: add safe backend-aware instance editing`;
- `1296493 refactor: componentize desktop management UI`;
- `f8efa79 feat: deliver backend-aware desktop workflows`;
- `62fdc79 fix: improve desktop responsiveness and accessibility`;
- `4fbf7e3 test: add desktop workflow coverage`.

Each preceding commit was created with key
`7D6EF134D851C8DA0862D97494F31AF374E2EE3C` and reported a Good EDDSA
signature. No commit was pushed.

Previous signed commit: `4fbf7e3 test: add desktop workflow coverage` (good
EDDSA signature).

Planned signed commit: `docs: record backend-aware UI implementation`.

### 12J. Actionable instance Settings workspace (2026-07-31)

The instance Settings tab previously presented the backend descriptor's section
names as five secondary buttons even though they had no action or navigation
behavior. The rest of the large panel was mostly empty, the local desired-state
purpose was relegated to one low-contrast sentence, and the primary action said
only `Edit desired settings`. This made a safe and useful preview/save workflow
look unfinished.

The panel now leads with its purpose: review the local target configuration,
preview operational impact, save desired state, and separately review a remote
deployment. Its single primary action is `Review and edit settings`. Current
applicable facts show endpoint/listener, routing and managed network, managed
DNS, and the fixed backend/host assignment. These values come from the existing
presentation-safe summary and descriptor, so opening the tab performs no SSH,
health, backup, or readiness operation.

The descriptor's available configuration sections remain authoritative, but
they are now informational cards with plain-language scope instead of inert
buttons. The workflow footer explicitly distinguishes edit/preview, local save,
and later deployment review. Proxy and routed backends continue to receive only
the facts and sections their Rust descriptor advertises. Responsive rules move
the four current facts and editable cards to two columns and eventually stack
the purpose/action and three workflow steps without creating page-wide
horizontal overflow.

Files changed:

- `apps/desktop/src/lib/components/InstanceWorkspace.svelte`: desired-state
  overview, applicable current facts, descriptor section explanations, workflow,
  and clearer action label;
- `apps/desktop/src/styles.css`: compact panel hierarchy and responsive grids;
- `apps/desktop/src/lib/components/presentation.test.ts`: actionable purpose,
  workflow, descriptor content, and absence of inert section buttons.

Validation:

- focused presentation suite passed 20/20 tests;
- full frontend suite passed 25/25 tests across four files;
- Svelte check passed with 0 errors and 0 warnings;
- Vite production build passed (134 modules, 133.91 kB JavaScript and 22.67 kB
  CSS before gzip);
- `git diff --check` passed.

The first focused run stopped because `Review deployment` correctly existed in
both the global action and the new three-step explanation while the test assumed
one match. The assertion was scoped to the two intentional semantic occurrences
and the suite passed; no production behavior changed for that test correction.

Previous signed commit: `3068e0d docs: record backend-aware UI implementation`
(good EDDSA signature).

Planned signed commit: `fix: clarify instance settings workspace`.

### 12K. Visible modal and creation errors (2026-07-31)

Application errors were rendered only in the page content. When a Create
instance request failed, the still-open modal backdrop blurred and obscured that
page alert, leaving the review screen apparently unchanged. Closing the wizard
revealed the error, but the user had no immediate indication that Create failed
or which input needed correction.

Errors produced while a modal is open now render once inside that active dialog.
The creation case is titled `Instance creation failed`, followed by the backend
message, remediation, remote-state warning when applicable, and expandable
technical detail. The assertive alert is programmatically focused after Svelte
renders it, which both announces it and scrolls it into view in a long modal.
The duplicate page alert is suppressed only while a modal owns the error; normal
page errors retain the existing presentation. Opening a fresh creation wizard
clears stale error/detail state, and Back clears the rejected result so corrected
input is not visually associated with an obsolete response.

The real five-step integration test exposed an existing boundary warning: the
root application uses Svelte's legacy reactive mode while backend form children
declared rune-style `$bindable` props. All five isolated form components now use
the compatible exported `form` prop. Their existing object bindings and dynamic
field behavior remain unchanged, while both creation and Settings mount without
`binding_property_non_reactive` warnings.

Files changed:

- `apps/desktop/src/App.svelte`: modal-owned alert, focus, duplicate suppression,
  and clean wizard Back/open state;
- `apps/desktop/src/styles.css`: prominent focused modal alert styling;
- all five `lib/components/forms/*Form.svelte` components: compatible reactive
  prop boundary;
- `apps/desktop/src/App.integration.test.ts`: rejected create request through all
  five wizard steps, in-dialog ownership, focus, message, and remediation.

Validation:

- focused application/form suites passed 4/4 tests with no Svelte runtime
  warnings;
- full frontend suite passed 26/26 tests across four files;
- Svelte check passed with 0 errors and 0 warnings;
- Vite production build passed (134 modules, 135.47 kB JavaScript and 22.91 kB
  CSS before gzip);
- `git diff --check` passed.

The initial patch attempt was rejected atomically because PowerShell's display
of a Unicode close glyph did not match the UTF-8 source context. Smaller
UTF-8-safe hunks were applied instead. No partially applied state remained from
the rejected patch.

Previous signed commit: `71f0b7e fix: clarify instance settings workspace`
(good EDDSA signature).

Planned signed commit: `fix: show creation errors in active dialog`.

### 12L. OpenVPN certificate lifetime policy (2026-07-31)

OpenVPN creation exposed a numeric client-certificate lifetime field with an
HTML maximum of 825 days. The OpenVPN backend independently rejected any value
outside 30-825 days, so removing only the browser constraint would have moved
the same failure into Rust. The screenshot's 1,365-day value could not advance
past native HTML validation and would not have passed application validation.

The OpenVPN-only policy ceiling is removed at both boundaries. The form retains
`min=1` and required validation but has no `max` attribute. Rust now accepts any
positive lifetime representable by the existing persisted `u16` field, including
1,365 days, and rejects zero with `must be at least 1 day`. IKEv2 remains
unchanged because the request and screenshot concern OpenVPN creation.

The form explicitly notes the security tradeoff: longer lifetimes are allowed,
but shorter-lived client certificates reduce exposure when an exported profile
is lost or copied. This is a user-selected credential policy rather than a
silent compatibility relaxation. TLS 1.3 minimums, certificate validation,
revocation behavior, `tls-crypt`, ciphers, private-key storage, and export
protection are unchanged.

Files changed:

- `apps/desktop/src/lib/components/forms/OpenVpnForm.svelte`: remove the 825-day
  maximum and add the lifetime/exposure explanation;
- `crates/backend-openvpn/src/lib.rs`: positive-only validation and a regression
  test for 1,365 days plus zero rejection;
- `apps/desktop/src/lib/components/forms/backend-forms.test.ts`: DOM constraint,
  entered value, and security-note coverage.

Validation:

- focused OpenVPN lifetime test passed;
- complete OpenVPN backend suite passed 9/9 tests;
- strict Clippy for `vam-backend-openvpn` with all targets and `-D warnings`
  passed;
- Rust formatting passed after applying the formatter's one-line return style;
- focused backend-form suite passed 2/2 tests;
- full frontend suite passed 27/27 tests across four files;
- Svelte check passed with 0 errors and 0 warnings;
- Vite production build passed (134 modules, 135.60 kB JavaScript and 22.91 kB
  CSS before gzip);
- `git diff --check` passed.

The first combined gate stopped on the formatter's required line wrapping. No
semantic failure occurred; the mechanical format was applied and every masked
gate was rerun. Concurrent Clippy/test validation briefly waited on Cargo's
normal target-directory lock and then passed.

Previous signed commit: `cff0e8e fix: show creation errors in active dialog`
(good EDDSA signature).

Planned signed commit: `fix: allow longer OpenVPN certificate lifetimes`.

### 12M. Live OpenVPN deployment validation correction (2026-07-31)

The desktop's two failed OpenVPN deployments reached the remote validation
phase after SSH trust verification, upload, pinned image preparation, and
certificate-authority initialization. Both recorded the same OpenVPN 2.6.20
error: `Options error: You must define key file (--secret)`. The backend was
correctly configured for certificate-based TLS with `tls-crypt`; the failure
came from invoking OpenVPN's unrelated static-key `--test-crypto` mode against
the complete server configuration.

The supplied Linode development VM was probed through the application's real
`russh` transport using `key.ppk`. Its ED25519 host key exactly matched the
approved `SHA256:npTb+VUM22DNWCFWU/7USfv3bjQf7MKQFnBXUAjl8po` identity, and the
inspection reported Linux x86_64, Docker 29.6.2, Compose 5.3.1, accessible TUN,
kernel WireGuard support, manageable UFW, and writable application storage.
The separate Windows OpenSSH path also authenticated as `william` using an
ACL-restricted temporary copy of `key.pem`; the original key was not modified,
and the temporary copy was removed after the check.

Adding `--secret /etc/openvpn/tls-crypt.key` was tested and deliberately
rejected because OpenVPN reports that `--server` and static-key `--secret`
cannot be combined. A bounded isolated startup probe was then run against the
failed deployment's staged tree. It mounted only that OpenVPN tree, used the
same `NET_ADMIN` and `/dev/net/tun` privileges required by production, exposed
no host port, reached `Initialization Sequence Completed`, and was forcibly
removed by its cleanup trap.

`validation_command` now generates that startup probe instead of
`--test-crypto`: it starts an unexposed detached container, waits two seconds,
checks the authoritative Docker running state, emits container logs on early
exit, and removes the container on every success, failure, signal, or shell
exit path. The staged OpenVPN mount is writable during the probe because the
real server initializes its persistent pool state there; the directory is
deployment staging and is validated before activation.

A command-contract regression test requires the TUN device, `NET_ADMIN`,
detached lifecycle, running-state inspection, failure logs, cleanup trap, and
writable staged mount, and forbids `--test-crypto` and the former read-only
mount.

Validation so far:

- live PPK/russh fingerprint, authentication, and readiness inspection passed;
- live PEM/OpenSSH strict-host-key authentication passed;
- the original `--test-crypto` failure was reproduced from saved deployment
  events;
- the `--secret` alternative was proven invalid and discarded;
- the isolated live startup probe passed and cleaned up its container;
- `cargo fmt --all -- --check` passed;
- `git diff --check` passed.

The first local rebuild was blocked when C: had only about 0.21 GiB free. The
generated `target/debug/incremental` cache was measured at 12.17 GiB, but it was
not deleted because explicit approval had not been provided. Available space
later rose independently to 5.56 GiB. Single-job focused builds then passed
without deleting any cache or modifying the machine.

Completed local validation:

- the focused OpenVPN validation-command regression passed 1/1;
- both instance-deletion regressions passed 2/2;
- the complete application crate passed 40/40 tests;
- strict Clippy passed for `vam-application` and the Tauri application with all
  targets and `-D warnings`;
- the full frontend suite passed 28/28 tests across four files;
- Svelte check passed with 0 errors and 0 warnings;
- the Vite production build passed (134 modules, 135.84 kB JavaScript and 22.91
  kB CSS before gzip);
- `cargo fmt --all -- --check` and `git diff --check` passed.

Previous signed commit:
`94066c6 fix: allow longer OpenVPN certificate lifetimes` (good EDDSA
signature).

Planned signed commit: `fix: validate OpenVPN deployments with a startup probe`.

### 12N. Local-only deletion for undeployed instances (2026-07-31)

Instance deletion previously assumed every local instance had an activated
remote directory. It removed firewall rules and ran `cd <remote-path>; docker
compose stop` before changing local state. A locally created OpenVPN instance
whose deployments failed during validation therefore produced `no such file or
directory` and remained visible locally.

Deletion is now serialized with the same per-instance lock used by deployment
operations and consults successful deployment history before making any remote
connection. With no successful deployment, it soft-deletes the local instance
immediately. This path works without SSH trust or host connectivity and cannot
alter firewall or Docker state.

For a previously successful deployment, remote teardown remains required, but
the fixed command is idempotent when the managed directory has already been
removed outside the application. It conditionally stops Compose and moves an
existing tree to timestamped recoverable trash, or reports that no remote tree
was present. Rust returns this typed outcome to Tauri and Svelte.

The confirmation now states both possible consequences instead of claiming
that every instance will be backed up remotely. The success notice likewise
distinguishes a stopped/trashed deployment from a local-only undeployed
definition.

Files changed:

- `crates/application/src/lib.rs`: typed deletion result, deployment-aware local
  fast path, per-instance locking, idempotent remote command, and two regression
  tests;
- `apps/desktop/src-tauri/src/lib.rs`: typed command result across the Tauri
  boundary;
- `apps/desktop/src/lib/types.ts`: serialized deletion outcome;
- `apps/desktop/src/App.svelte`: accurate confirmation and result-specific
  notices;
- `apps/desktop/src/App.integration.test.ts`: local-only deletion message and
  invocation coverage.

Validation so far:

- `cargo fmt --all -- --check` passed;
- focused desktop integration suite passed 4/4 tests after correcting the
  jsdom query for the labelled `<summary>` overflow trigger;
- Svelte check passed with 0 errors and 0 warnings.

The root pnpm wrapper again stopped before tests with
`ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY`; direct npm scripts used the
already-installed dependencies and passed. The first frontend test run found
only that jsdom exposes the labelled `<summary>` overflow trigger as a group,
not a button; the query was corrected to use the stable `aria-label` and the
suite passed.

This deletion fix is committed with the OpenVPN deployment probe as one
remote-lifecycle reliability unit because both correct assumptions about remote
state before mutating local desired state.

Planned signed commit:
`fix: harden OpenVPN validation and undeployed deletion`.

### 12O. Certificate-backend ownership and native secret capacity (2026-07-31)

The corrected OpenVPN validation probe exposed two later stages that the former
probe had masked. The first real activation failed while moving
`stage/vpn/pki` into the active tree: Easy-RSA had run in a root container and
left the persistent PKI directory `0700 root:root`, while activation runs as the
managed SSH user. A reversible rename test against the staged tree reproduced
the permission denial. Running a second pinned-image container with only
`chown -R <host uid>:<host gid>` over the authority mount made the same rename
succeed and restore cleanly.

Authority initialization and each later certificate mutation now finish with
that explicit ownership normalization. The host UID and GID are captured from
the authenticated SSH session, the correction runs inside the already-pinned
backend image as root, and the command does not assume passwordless `sudo`.
The implementation is shared by OpenVPN and IKEv2 because both persist a
container-managed certificate authority that the host-side transactional
deployment and SFTP layers must subsequently read or move. It does not change
ownership outside the selected instance's mounted OpenVPN or swanctl authority
root.

With activation fixed, real OpenVPN client issuance reached a second ownership
boundary. Easy-RSA wrote the issued certificate as `0600 root:root`; the CSR
upload and signing succeeded, but the SSH user could not download the
certificate. Applying the same post-operation ownership normalization to every
certificate container command allowed SFTP retrieval without making certificate
files world-readable.

The next retry reached Windows Credential Manager and exposed its 2,560-byte
per-value limit. OpenVPN certificates and IKEv2 PKCS#12 material can exceed that
limit, so the native secret adapter now stores values over 2,048 bytes as
generation-scoped credential chunks. The primary credential contains only a
versioned manifest with generation UUID, chunk count, original byte length, and
SHA-256 digest. Reads require every chunk and verify both length and digest
before returning any reconstructed value. Writes create chunks before atomically
switching the small primary manifest; failed writes clean their uncommitted
generation, and replacement failures attempt to restore the prior manifest.
Deletes remove the referenced chunk generation before removing the manifest.

Existing values at or below the limit remain in their original one-credential
format, and non-manifest legacy values continue to read unchanged. A 4,096-chunk
parser ceiling rejects corrupt or hostile metadata before allocation or lookup.
Credential errors contain operation context and integrity state but never secret
bytes. User-facing error copy now says `native credential store` rather than the
incorrect platform-specific `macOS Keychain` wording.

Live validation used the isolated database at
`C:\Users\william\AppData\Local\Temp\vam-live-matrix-20260731-134342\state.sqlite`
and the user-supplied disposable Linode. The OpenVPN instance used UDP 31194 and
subnet `10.73.0.0/24`, avoiding the host's unrelated managed deployments. No
secret value or exported profile content was printed.

The validated lifecycle was:

1. apply the full 19-operation server plan after the ownership fix;
2. verify Compose, gateway, backend, listener, DNS, and resolver health;
3. generate a real local private key and CSR, sign it with the deployed remote
   authority, retrieve the client and CA certificates plus tls-crypt material,
   and persist the resulting identity;
4. observe the expected client-state drift before deployment;
5. review and apply the exact nine-operation plan with expected-state hash
   `0255ff1bd48ebb080c35983ae2f7416c2f47024e3f582a0359ef0d3eb20cfe4a`;
6. recheck all health fields, including client-state agreement; and
7. export a 2,888-byte `.ovpn` profile by reading the real Windows credential
   store through a fresh process.

The server deployment succeeded as
`d2e67959-c890-40f5-8aeb-5d94bd7647ec`; the client-state deployment succeeded as
`94c6085f-31f2-48c5-85b7-d4df8ca4f231`. The final explicit health check reported
Compose, gateway, OpenVPN backend, listeners, client state, DNS, and both DNS
resolution checks healthy. Watchtower remained intentionally absent for this
test instance and is reported separately rather than weakening backend health.

One apparent `secret_missing` export result was diagnosed as a harness-context
artifact: issuance ran under the real Windows user outside the restricted Codex
sandbox, while the first local-only export process could not see that user's
credential vault. A read-only database check confirmed five active OpenVPN
secret registrations with no retirement markers. Repeating export under the
same Windows identity as the desktop application succeeded. This did not require
a production-code change.

Files changed:

- `crates/application/src/lib.rs`: host-user ownership normalization for
  authority initialization and credential mutation, generic native-store error
  wording, and OpenVPN/IKEv2 command-contract tests;
- `crates/secrets/src/lib.rs`: backward-compatible chunked native credentials,
  integrity validation, transactional replacement/cleanup behavior, and
  manifest parser tests;
- `crates/secrets/Cargo.toml` and `Cargo.lock`: the existing workspace SHA-256
  implementation is now a direct secret-store dependency.

Validation completed before documentation:

- `cargo fmt --all -- --check` passed;
- `cargo clippy -p vam-secrets -p vam-application --all-targets -- -D warnings`
  passed after replacing allocation-heavy digest formatting with a preallocated
  string writer;
- `cargo test -p vam-secrets -p vam-application -j 1` passed: 2/2 secret-store
  tests and 40/40 application tests;
- `cargo build -p vam-dev -j 1` passed using the existing portable NASM path;
- live OpenVPN server apply, client issuance, drift deployment, fresh-process
  export, and explicit health verification all passed.

The first post-fix client attempt was safely rolled back after SFTP reported the
root-owned certificate. The second was safely rolled back when Credential
Manager rejected the oversized value. Neither failed attempt persisted a local
client. Remote credential operations created pre-change backups, and the later
successful attempts preserved the same recovery behavior. No build cache was
deleted and no tool or package was installed.

Previous signed commit:
`ca41f09 fix: harden OpenVPN validation and undeployed deletion` (good EDDSA
signature).

Planned signed commit:
`fix: complete certificate backend deployment lifecycle`.

### 12P. IKEv2 validation, restart safety, and local-image inputs (2026-07-31)

The first live IKEv2 deployment stopped in pre-activation validation even though
its generated authority and configuration were valid. The validator ran
`swanctl --version` in a container without charon. strongSwan 5.9.14 attempts to
connect to its VICI socket for that command, printed the version plus usage, and
exited 2 with `No such file or directory`. Treating that nonzero status as
authoritative was correct; the check itself did not test deployability.

Validation now starts the selected, locally built pinned IKEv2 image as an
isolated detached probe. It publishes no host ports, grants only the runtime's
declared `NET_ADMIN` capability and IPv4-forwarding sysctl, mounts the staged
swanctl authority tree read-only, waits for the container to remain running,
and requires both a charon PID and a successful `swanctl --list-conns`. Early
exit or load failure emits the probe logs, and an exit/signal trap always removes
the container. The exact candidate passed twice against the failed live stage,
including with the authority mount read-only.

The corrected server deployment succeeded, but applying the newly issued client
state exposed a separate restart defect. Health observed the gateway in a
restart loop and automatically restored the pre-client snapshot. The failed
configuration itself remained healthy in an eight-second isolated replay,
loading one pool and one connection, so the generated config and certificate
state were not the cause. An exact `docker compose restart gateway` reproduction
against the otherwise healthy rollback tree produced the same failure and
retained the decisive logs:

- the container writable layer retained `/var/run/charon.vici` across restart;
- the entrypoint saw the stale socket path and treated it as readiness;
- `swanctl --load-all` connected before a new VICI listener existed, received
  `Connection refused`, and exited;
- the `unless-stopped` policy repeated that sequence.

The IKEv2 entrypoint now removes only the stale runtime socket immediately before
starting charon. It does not remove authority data, configuration, certificates,
or other runtime state. The existing bounded wait then observes a socket created
by the new daemon. A full Compose down/up recovery was performed immediately
after the diagnostic reproduction, and explicit application health confirmed
the prior server snapshot was healthy before continuing.

The first plan after changing the entrypoint revealed a third planning issue:
the rendered `start-ikev2.sh` was marked for replacement but only a Compose
restart was planned. The file is a Docker build input copied into the image, so
replacing it on the host cannot affect an existing image. `ContainerImage::Build`
now declares its non-Dockerfile input paths. OpenVPN, IKEv2, and Xray each name
their rendered startup script. The deployment planner treats a change to either
the Dockerfile or any declared build input as structural, adding `ComposeBuild`
and `ComposeUp` rather than `ComposeRestart`. Runtime configuration files in the
same mounted directory do not trigger unnecessary rebuilds unless explicitly
declared as image inputs.

Two identical client-state attempts made before the entrypoint correction both
failed health and both reported successful rollback. After the runtime and
planner fixes, the reviewed plan visibly contained `compose_build` and
`compose_up`. Deployment `cf9e0d9b-6b18-4a6d-be9c-5d81b23c786f` then succeeded.
The final explicit health check reported Compose, gateway, strongSwan readiness,
fixed UDP 500/4500 listeners, client-state agreement, DNS, and private/public DNS
resolution healthy. The real client exported as a protected 1,988-byte PKCS#12
bundle; no bundle contents or password were printed.

Files changed:

- `crates/application/src/lib.rs`: isolated IKEv2 daemon/config validation and
  its command-contract regression test;
- `crates/backend-ikev2/src/lib.rs`: stale VICI socket removal before daemon
  launch, ordering assertion, and declared startup-script build input;
- `crates/backend/src/lib.rs`: typed local-image input-path metadata;
- `crates/deployment/src/lib.rs`: rebuild/recreate classification for declared
  image inputs and a regression test that forbids restart-only handling;
- `crates/backend-openvpn/src/lib.rs` and `crates/backend-xray/src/lib.rs`:
  complete build-input metadata for their existing copied startup scripts.

Validation:

- live old `swanctl --version` failure reproduced with exit 2;
- live replacement validation passed with no published ports and a read-only
  authority mount;
- the focused IKEv2 validation-command test passed;
- deterministic Compose restart-loop reproduction captured `Connection refused`
  and was followed by an automatic scoped full-up recovery;
- `cargo test -p vam-deployment -p vam-backend-ikev2
  -p vam-backend-openvpn -p vam-backend-xray -p vam-application -j 1` passed:
  14 deployment, 8 IKEv2, 9 OpenVPN, 11 Xray, and 41 application tests;
- strict Clippy for those five crates with all targets and `-D warnings` passed;
- the developer harness rebuilt successfully with one Cargo job and the existing
  portable NASM path;
- Rust formatting and `git diff --check` passed;
- live IKEv2 initial deployment, real certificate issuance, corrected
  rebuild/recreate deployment, protected export, and explicit health all passed.

No unrelated containers, ports, or instance paths were modified. Diagnostic
mutations were limited to the test IKEv2 Compose project and were restored before
the successful deployment. No package or prerequisite was installed.

Previous signed commit:
`29be8e7 fix: complete certificate backend deployment lifecycle` (good EDDSA
signature).

Planned signed commit:
`fix: make IKEv2 deployment validation restart-safe`.

### 12Q. Xray protected bootstrap, public identity, and UID-safe backups (2026-07-31)

The first live Xray deployment built its pinned, digest-verified multi-architecture
image but restart-looped immediately. Replaying the exact failed tree without a
published port produced `xray startup: server template is unavailable`.
`server-template.json` is intentionally `0600` because it contains client VLESS
UUIDs once clients exist. The SSH user owns it so staged replacements remain
transactional, while the container was configured to start directly as UID
10001 and could not read that host-owned bind mount. Making it globally readable
would have exposed client authentication material.

The image now performs a narrowly scoped root bootstrap and immediately drops
privilege:

1. the root entrypoint verifies it is in the bootstrap phase;
2. it copies the protected host template into the UID-10001-owned state volume
   as mode `0600`;
3. pinned Alpine `su-exec=0.3-r0` directly execs the same entrypoint as
   `xray:xray`, leaving no root supervisor; and
4. the unprivileged phase verifies UID 10001, generates or validates REALITY
   identity, materializes the active config, self-tests it, and directly execs
   Xray.

The source template remains `0600` owned by the SSH user. Live `docker top`
confirmed the only long-running gateway process is `xray run` as numeric user
10001. Backend health metadata now also requires both the Xray self-test and
client-count query to execute explicitly as `10001:10001`; `docker compose exec`
can no longer default those routine checks to the image's root bootstrap user.

After that fix the server became healthy, but public-identity discovery failed.
The REALITY private key, public key, and short ID were all inside a `0700`
identity directory. The application must read the public key and short ID to
construct client exports and bind future deployments to the approved server
identity, but it must never read or expose the private key. The identity
directory is now `0711` (traversable by a caller that knows an exact filename,
not listable), the private key remains `0600`, and only the distributable public
key and short ID are `0644`. The unprivileged owner reapplies those modes after
validating existing identity, making restarts and earlier state idempotent.

The first post-client plan then found that the empty `xray-state/.keep`
placeholder was mode `0600` after numeric ownership normalization. Host-side
manifest hashing could not read it and its `set -e` output ended early. The
placeholder contains no data and is not sensitive, so it is now rendered
`0644`; the active config, protected template, client UUIDs, and private identity
remain restricted. This one live fixture was created immediately before the
mode correction, so only its empty `.keep` was aligned to `0644` through a
root container before normal planning resumed.

The same plan initially displayed a destructive reinstall warning because the
last successful deployment snapshot preceded post-health REALITY public-material
discovery. Xray settings classification now treats only the first complete
`None -> verified public key and short ID` transition as discovery metadata.
Changing or clearing an already recorded identity remains reinstall-class, as do
security-mode and TLS-secret changes. The corrected client plan contained no
false destructive warning.

Finally, the pre-deploy backup failed before remote mutation because host-side
`cp -a` could not traverse the UID-10001 private state. All full instance-tree
copies—deployment safety backups, manual backups, credential-change backups, and
restores—now use the selected pinned backend image as root with only
`/opt/vpn-appliance-manager` mounted at `/vam`. Both source and destination must
resolve beneath that managed root; external paths are rejected before command
generation. Archive copy preserves numeric ownership without widening private
file modes. This uses the already-authorized Docker boundary and does not grant
the SSH user read access to Xray private state.

Deployment `9b9ff575-8e05-480b-af4c-e14f806bac0a` was the first successful
Xray server activation and persisted the verified public identity. Deployment
`d9679999-20d4-4a89-b9fb-a92060984aea` successfully backed up the numeric state,
restarted with the real client UUID, and passed health. A separate manual backup,
`2026-07-31T19-03-25Z-manual-d9679999-20d4-4a89-b9fb-a92060984aea`, also passed
through the containerized copy path. The client exported as a 260-byte VLESS
URI file; contents and UUID were not printed.

Final Xray health correctly reports Compose, gateway, active-config self-test,
TCP listener, and exact client count as healthy. Managed DNS, DNS containers,
and DNS resolution are deliberately not required or fabricated for this proxy
backend. The client has no invented IPv4/IPv6 address or DNS name.

Files changed:

- `crates/backend-xray/src/lib.rs`: protected template bootstrap, immediate
  privilege drop, sensitivity-specific REALITY permissions, readable empty
  state placeholder, initial-discovery classification, and regression tests;
- `crates/backend/src/lib.rs`: typed health-command user metadata;
- `crates/application/src/lib.rs`: least-privilege Xray health execution,
  managed-root containerized tree copy for backup/restore paths, external-path
  rejection, and command-contract/rollback tests.

Validation:

- reproduced the original `server template is unavailable` failure against the
  exact failed tree without publishing a port;
- verified pinned Alpine package metadata before adding `su-exec=0.3-r0`; no
  host package was installed;
- focused Xray/application/deployment tests passed throughout diagnosis;
- final affected suites passed: 42/42 application tests, 11/11 Xray tests, and
  the backend contract tests;
- strict Clippy for the backend, Xray, and application crates with all targets
  and `-D warnings` passed;
- Rust formatting, one-job developer harness builds, and `git diff --check`
  passed;
- live server deployment, public-identity persistence, VLESS client creation,
  warning-free reviewed plan, UID-safe pre-deploy backup, client deployment,
  manual backup, export, runtime UID check, permission-mode check, and explicit
  UID-10001 health all passed.

Both failed server attempts rolled back successfully. The later backup failure
occurred before remote mutation. No unrelated remote state was modified, and no
secret, UUID, private key, active configuration, or VLESS URI content was logged.

Previous signed commit:
`5de3ab2 fix: make IKEv2 deployment validation restart-safe` (good EDDSA
signature).

Planned signed commit:
`fix: secure Xray deployment state lifecycle`.

### 12R. Consolidated five-backend live deployment and Windows release validation (2026-07-31)

This unit consolidates the evidence for the requested real-host deployment
matrix. The target was the explicitly disposable Linode development VM at
`172.239.63.147`. Its pinned ED25519 host-key identity was verified as
`SHA256:npTb+VUM22DNWCFWU/7USfv3bjQf7MKQFnBXUAjl8po` before privileged work.
The application transport authenticated with the supplied PuTTY PPK through
the same russh path used by the desktop application. The supplied OpenSSH PEM
also authenticated through the system client from an ACL-restricted temporary
copy; the original key was not changed and the temporary copy was removed.

One explicit host inspection produced the shared facts consumed by all backend
readiness evaluations: Linux x86_64, Docker 29.6.2, Compose 5.3.1, directly
accessible Docker, `/dev/net/tun`, WireGuard kernel support, manageable UFW,
writable application root, and sudo bootstrap authority. No render-time probe
or per-backend inspection loop was introduced.

The live matrix used an isolated local database at
`C:\Users\william\AppData\Local\Temp\vam-live-matrix-20260731-134342\state.sqlite`
and distinct ports/subnets so it did not collide with unrelated remote state.
Exports were written only beneath that temporary test directory. Their sizes
and formats were checked, but their private keys, passwords, UUIDs, certificate
contents, and complete URI/configuration text were never printed.

| Backend | Server activation | Real client state | Export | Final explicit health |
| --- | --- | --- | --- | --- |
| WireGuard | `c00b105d-f3c3-41de-bbb7-f062b8be0d13` | `1c432881-b05f-4e27-9507-51d4cea0477b` | 317-byte WireGuard configuration | Compose, gateway, listener, peer set, managed DNS, and resolution passed |
| AmneziaWG 2 | `f3267943-07d9-4563-9a2c-e474e070bcb4` | `ba1c961a-d5c4-4517-a12e-ac2538758f06` | 431-byte AWG configuration | Compose, gateway, listener, peer set, managed DNS, and resolution passed |
| OpenVPN | `d2e67959-c890-40f5-8aeb-5d94bd7647ec` | `94c6085f-31f2-48c5-85b7-d4df8ca4f231` | 2,888-byte `.ovpn` profile | Compose, gateway, OpenVPN configuration, listener, certificate state, managed DNS, and resolution passed |
| IKEv2 | `f4464d73-7737-493a-8535-bad1f4e2507d` | `cf9e0d9b-6b18-4a6d-be9c-5d81b23c786f` | 1,988-byte protected PKCS#12 bundle | Compose, gateway, strongSwan/VICI readiness, UDP 500/4500 listeners, certificate state, managed DNS, and resolution passed |
| Xray | `9b9ff575-8e05-480b-af4c-e14f806bac0a` | `d9679999-20d4-4a89-b9fb-a92060984aea` | 260-byte VLESS URI | Compose, non-root gateway, Xray self-test, TCP listener, and exact client state passed; DNS is correctly not applicable |

The matrix exposed defects that isolated unit tests could not fully reproduce:

- OpenVPN and IKEv2 used unsupported command-line-only validation modes; both
  now use isolated bounded daemon startup probes with no published listeners;
- certificate authority and issued-client artifacts created in root containers
  were not consistently normalized for the application SSH user;
- Windows Credential Manager could not hold larger OpenVPN/PKCS#12 values in a
  single generic credential, so large values now use integrity-checked,
  transactional chunks while retaining legacy reads;
- IKEv2 Compose restarts could consume a stale VICI socket, and changes to
  startup scripts copied into images were incorrectly planned as restarts;
- Xray needed a protected root bootstrap followed by a direct UID-10001 exec,
  sensitivity-specific REALITY permissions, explicit non-root health commands,
  and root-in-container backup copies that preserve numeric ownership; and
- deleting a never-deployed instance incorrectly required SSH and failed while
  changing into a remote directory that could not exist. Undeployed deletion is
  now local-only, while deployed cleanup remains remote and idempotently accepts
  an already absent instance directory.

Every failed live apply either rolled back successfully or failed before remote
mutation. The Xray manual backup
`2026-07-31T19-03-25Z-manual-d9679999-20d4-4a89-b9fb-a92060984aea`
also proved the corrected numeric-ownership copy path. Test deployments remain
on the explicitly disposable VM for inspection; no unrelated instance paths,
containers, or ports were changed, and no remote cleanup was inferred from the
deployment-test request.

Final validation and environment result:

- `.\build-helpers\windows\build.ps1 -SkipToolInstall` completed successfully;
- Visual Studio C++ tools, Node 24.18.0, WebView2, NASM 3.02, Rust 1.97.1 with
  rustfmt/Clippy, pnpm 11.9.0, and NSIS were already available; no missing
  prerequisite or host package installation was required;
- the helper's frozen pnpm install reported the workspace already up to date;
- `pnpm verify` passed `cargo fmt --all -- --check`, strict workspace Clippy for
  all targets, the complete Rust workspace tests, Svelte diagnostics, all 28
  frontend tests, and the production web build;
- the Rust workspace included 42 application, 5 AWG, 8 IKEv2, 9 OpenVPN, 4
  WireGuard, 11 Xray, 9 core, 14 deployment, 4 CLI, 8 DNS, 2 protocol, 2
  secrets, 4 SSH, and 14 storage tests, with the remaining binary/contract and
  documentation targets also passing;
- `svelte-check` reported zero errors and zero warnings;
- Vitest reported 4/4 files and 28/28 tests passing;
- the production Tauri build succeeded and NSIS produced
  `target/release/bundle/nsis/VPN Appliance Manager_0.1.0_x64-setup.exe`
  (6,679,294 bytes);
- GNU Make is not installed in this Windows environment, so the literal
  `make frontend-check`, `make frontend-test`, `make frontend-build`, `make
  test`, and `make verify` wrappers could not run. Their underlying commands
  were all executed successfully by the authoritative Windows helper, and Make
  was not installed solely to add a wrapper layer;
- final `git diff --check`, signed-commit verification, and clean-worktree
  checks are performed immediately after this documentation update.

Signed implementation commits, in order:

- `71f0b7e fix: clarify instance settings workspace`;
- `cff0e8e fix: show creation errors in active dialog`;
- `94066c6 fix: allow longer OpenVPN certificate lifetimes`;
- `ca41f09 fix: harden OpenVPN validation and undeployed deletion`;
- `29be8e7 fix: complete certificate backend deployment lifecycle`;
- `5de3ab2 fix: make IKEv2 deployment validation restart-safe`;
- `06c53b9 fix: secure Xray deployment state lifecycle`.

Each implementation commit was verified with a good EDDSA signature from key
`7D6EF134D851C8DA0862D97494F31AF374E2EE3C`. No commit was pushed.

Previous signed commit:
`06c53b9 fix: secure Xray deployment state lifecycle` (good EDDSA signature).

Planned signed commit:
`docs: record live backend deployment validation`.

## 13. Server-authoritative persistence redesign (2026-08-19)

Status: source audit and implementation plan complete. No authority-model code
has been changed in this planning unit.

### 13.1 Required authority boundary

The new invariant is:

> VPN Appliance Manager keeps only the information necessary to identify and
> securely SSH into an appliance locally; the appliance owns its VPN state and
> credentials, while the desktop retrieves and caches that state as a disposable
> management view.

The approved SSH host key cannot come from the host being authenticated and
therefore remains local. The local connection/trust repository will own only the
appliance UUID binding, friendly name, hostname, port, SSH username, private-key
path, optional native-store passphrase reference, approved host public-key blob
and fingerprint, plus disposable synchronization metadata. Deleting that local
repository may require the operator to re-add and re-approve the appliance, but
must not lose appliance configuration or rotate VPN credentials.

Everything logically owned by a VPN appliance moves to its authority store:
instances and typed settings, listeners, users, devices, tunnel addresses, DNS
records and hostlists, identity metadata, VPN client secret values, imported TLS
material, deployment snapshots and events, activity, backup metadata, and
appliance settings. Existing backend-owned CA, identity, revocation, and runtime
state remains remote and is brought under coherent management-state backup.

The security tradeoff is explicit: privileged compromise of an appliance can
expose the active client credentials managed by that appliance. Restrictive
at-rest storage protects offline copies and accidental disclosure; it does not
protect secrets from an attacker with equivalent root execution on the live
host.

### 13.2 Current ownership inventory

The audit found these present-day coupling points:

| State | Current owner | New owner |
| --- | --- | --- |
| SSH endpoint, private-key path, passphrase reference | local `docker_hosts` plus native credential store | local connection/trust store |
| approved SSH key blob and fingerprint | local `known_host_keys` | local connection/trust store, unchanged |
| instances, listeners, users, devices, DNS | local SQLite | appliance authority database |
| deployment plans, events, snapshots, activity, backup metadata | local SQLite | appliance authority database |
| WG/AWG private keys and PSKs | desktop native credential store | appliance authority secret store |
| OpenVPN/IKEv2 client keys, certificates, CA copies, export passwords | desktop native credential store | appliance authority secret store |
| Xray client UUID and imported TLS material | desktop native credential store | appliance authority secret store |
| backend CA, revocation, server identity, active runtime | protected remote instance tree | protected remote runtime tree, unchanged |
| rendered client artifacts | transient Rust value or explicit local export | reconstructed from appliance state; transient Rust value or explicit local export |
| DNS hostlist cache and UI summaries | local settings/SQLite | appliance settings plus disposable local cache |

`ApplicationService` currently calls concrete `Storage` and `SecretStore`
methods throughout host, instance, device, DNS, deployment, backup, rollback,
health, and export workflows. Device creation and replacement can also mutate a
remote certificate authority before committing local metadata. Deployment and
restore similarly perform remote side effects before final local history/state
updates. Those operations require one server-side concurrency boundary; merely
swapping the `Storage` implementation or copying SQLite files cannot make them
safe.

### 13.3 Remote helper and protocol

Add a small `vam-server` Rust binary under `apps/server` and a shared
`vam-authority` crate. The shared crate owns versioned request/response types,
the normalized authority schema, validation, revision/lease rules, and the
server-side store. The binary remains a thin command dispatcher. It is not an
HTTP service, daemon, frontend, or second orchestration implementation.

The helper protocol will use structured JSON envelopes containing an explicit
protocol version, supported schema range, request UUID, appliance UUID, and a
tagged operation. The minimal operation families are:

- compatibility and current-revision inspection;
- public/cache snapshot retrieval;
- mutation-lease acquire, renew, abort, and transactional commit;
- bounded protected credential retrieval for client rendering/export;
- reviewed legacy migration preview and atomic import;
- coherent management backup creation, listing, verification, and restore.

Application-specific validation, backend rendering, deployment planning, health,
and orchestration remain in `ApplicationService`. Authority commits carry typed
aggregate changes and secret puts/retirements rather than arbitrary SQL or shell
fragments. The helper validates ownership, references, revision, lease token,
schema, and size bounds before one database transaction.

The existing SSH transport has no stdin channel, and secret-bearing JSON must not
appear in a shell argument or routine stdout. Requests and responses will
therefore use per-request UUID files in a restricted exchange directory:

1. VPNCTL uploads a `0600` request with bounded SFTP.
2. VPNCTL executes the fixed helper path with only the validated request UUID.
3. The helper runs through a narrowly installed noninteractive privilege rule,
   validates the request path, writes a bounded `0600` response for the invoking
   SSH UID, and removes the request.
4. VPNCTL downloads the response with the existing bounded SFTP primitive.
5. A helper cleanup operation removes the response; expired exchange files are
   pruned idempotently.

The helper emits only a small non-secret completion status on stdout. Private
keys, PSKs, bearer UUIDs, passwords, imported key material, and complete client
profiles remain inside the protected exchange file and zeroizing Rust buffers.
Malformed envelopes, path escapes, unknown variants, incompatible versions, and
oversized inputs fail closed.

### 13.4 Remote storage and filesystem

Retain `/opt/vpn-appliance-manager/instances/<uuid>` and the existing runtime,
staging, trash, and deployment-backup semantics. Add separate protected roots:

```text
/opt/vpn-appliance-manager/
|-- control/       # root-owned authority database, schema metadata, lock state
|-- exchange/      # bounded per-request files, never durable authority
|-- management-backups/ # coherent disaster-recovery generations
|-- instances/     # existing active backend/runtime trees
|-- backups/       # existing deployment rollback trees
|-- staging/
`-- trash/
```

The authority database is root-owned mode `0600`; protected directories are
`0700`. Secret values use a dedicated BLOB table keyed by the existing opaque
UUID references so state rows and secret writes can commit atomically. Complete
profiles are reconstructed where feasible rather than redundantly persisted.
This also makes the authority database plus required runtime state the coherent
backup unit. No live SQLite, WAL, or shared-memory file is ever transferred to
VPNCTL.

The helper serializes database access and owns migrations. Management backups
are immutable generations: while holding the appliance mutation lease, create a
consistent SQLite snapshot, copy the protected runtime authority trees with the
existing root-container boundary that preserves numeric ownership, write and
verify a digest manifest, then atomically publish the generation. Restore
verifies the complete generation and restores database and protected trees as
one unit. This disaster-recovery flow remains distinct from per-deployment
rollback.

### 13.5 Revision and side-effect concurrency

The authority database has one monotonically increasing appliance revision.
Snapshot responses include it, and the local cache records it. Equal revisions
skip a full refresh. Every successful authority mutation advances the revision
exactly once; validation failures and rolled-back transactions do not advance it.

Optimistic revision checks are paired with a short-lived persisted mutation
lease because deployment, certificate issuance/revocation, runtime backup, and
restore have side effects outside the database transaction. A mutating workflow
is:

1. refresh and obtain revision `N`;
2. acquire a scoped lease only if the authority remains at `N`;
3. execute the existing reviewed application orchestration while renewing the
   lease during long operations;
4. commit metadata and secret changes with the lease token and expected revision
   `N`, advancing atomically to `N + 1`;
5. abort the lease after a pre-commit failure, or run the existing remote rollback
   before abort when side effects occurred.

Another VPNCTL client receives a structured busy or revision-conflict result and
must refresh. Leases have bounded expiry and operation identity so a crashed
desktop cannot lock the appliance forever, while an expired lease cannot be used
to commit. No offline mutation queue is introduced.

### 13.6 Local repositories and application integration

Replace the desktop bootstrap use of `state.sqlite` with explicit local stores:

- `connections.sqlite`: authoritative only for connection and host-trust data;
- `cache.sqlite`: disposable public appliance snapshots, revision, freshness,
  and UI-only state.

The old local-authority database remains readable only by the explicit migration
workflow. New installations do not create its VPN-state tables. Native credential
storage remains for SSH-key passphrases and is removed from ordinary VPN client
identity persistence after successful migration.

Introduce an `AuthorityClient` behind `ApplicationService`. It owns the verified
SSH exchange, compatibility check, revision refresh, lease lifecycle, protected
secret fetch, and typed commits. The application continues to own backend
selection, key/CSR generation, rendering, state-hash review, deployment commands,
rollback, redaction, and public presentation models. Ordinary list/detail views
read synchronized cache data and expose freshness/offline state. Mutations require
a live compatible authority and never report a local queued success.

Client export loads the synchronized state and only the required protected
credential components from the appliance into zeroizing Rust buffers, uses the
existing backend renderer, and writes the explicit private export. QR generation
remains the one tightly scoped Tauri response that encodes a complete supported
profile; normal Svelte models remain secret-free.

### 13.7 Reviewed one-way migration

Migration is explicit and retryable, never an ordinary-startup side effect:

1. detect legacy `state.sqlite` and referenced native secrets;
2. require a reachable appliance with approved local host key and a compatible
   helper;
3. refresh revision and inspect both management and runtime state;
4. build a redacted preview including entities, secret-reference completeness,
   UUID preservation, conflicts, and backup impact;
5. acquire the migration lease and create/verify a management backup;
6. upload one bounded typed import generation containing desired state, history,
   metadata, and required secret values;
7. atomically import only if the expected revision and idempotency key still
   match;
8. re-read and verify entity hashes, secret digests, UUIDs, runtime references,
   and one reconstructible export for every migrated identity/backend;
9. switch the desktop to the synchronized cache;
10. retire old VPN credential entries only after all verification passes, while
    retaining SSH passphrases and a recoverable legacy database backup until the
    operator explicitly completes retirement.

Pre-commit failure leaves legacy authority usable. Repeating a committed import
with the same idempotency key returns the recorded result; it does not duplicate
rows, advance revision again, or rotate credentials.

### 13.8 Functional implementation units

The implementation will proceed in signed, independently validated units:

1. **Authority protocol and store:** add `vam-authority`, remote migrations,
   revision/lease/transaction logic, protected secret BLOBs, snapshot and commit
   validation, compatibility errors, and focused persistence/concurrency tests.
2. **Server helper and secure exchange:** add `vam-server`, filesystem
   initialization, permission enforcement, bounded JSON files, request cleanup,
   managed-root/path validation, helper installation assets, and hostile-input
   tests.
3. **Local connection/cache split:** add the bootstrap/trust repository and
   disposable cache, rename new desktop use to `cache.sqlite`, preserve host-key
   approval invariants, and prove cache destruction/reconstruction.
4. **Application authority client:** integrate verified SSH exchange, revision
   refresh, stale/offline presentation, leases, and typed commit handling while
   retaining backend orchestration in `ApplicationService`.
5. **Identity and export cutover:** move all five backends' client and imported
   TLS secret persistence to appliance authority, re-export from a clean client,
   and remove dead VPN uses of `KeychainSecretStore`.
6. **Migration and disaster recovery:** add review/apply/verify/retire migration,
   coherent management backups, generation restore, idempotent retries, and
   failure recovery.
7. **Desktop/CLI completion:** expose synchronization, freshness, conflicts,
   migration review, management backup/restore, and actionable compatibility
   errors without putting secrets in public models.
8. **Documentation and acceptance:** update README, security, architecture,
   remote format, deployment/backup docs, and this ledger; run the clean-client
   recovery scenario and a create/export/reconnect workflow for all five
   backends.

Each unit must pass formatting, targeted tests, strict Clippy with `-D warnings`,
and all affected workspace/frontend checks before its commit. The final unit runs
the complete workspace verification and the Windows release helper. Live-server
claims require a disposable approved appliance and exact recorded evidence; they
will not be inferred from local tests.

### 13.9 Files expected to change

- `Cargo.toml`, `Cargo.lock`: register the authority library and server binary;
- `crates/authority/`: protocol, schema, store, revision, lease, backup, and
  migration primitives;
- `apps/server/`: thin `vam-server` JSON/file dispatcher;
- `crates/ssh/`: retain verification invariants and add only the exchange support
  that cannot be composed from existing bounded upload/download/execute calls;
- `crates/storage/`: isolate legacy import and disposable-cache responsibilities
  from new appliance authority;
- `crates/secrets/`: retain local SSH-passphrase storage, remove VPN authority
  only after migration verification;
- `crates/application/`: authority client integration and orchestration cutover;
- `apps/cli/`, `apps/desktop/src-tauri/`, `apps/desktop/src/`: explicit sync,
  offline/cache status, conflict handling, migration, and recovery UX;
- `build-helpers/` and host provisioning: build/package/install/version
  `vam-server` without weakening sudo or filesystem permissions;
- `README.md`, `SECURITY.md`, `docs/architecture.md`, `docs/remote-format.md`,
  `docs/deployment.md`, and this file: replace local-first claims and record
  validation evidence.

No unit will copy SQLite/WAL files between client and server, trust a host-supplied
host-key pin, queue offline writes, put secret JSON in shell arguments or logs,
or broaden remote permissions to make the helper convenient.

### 13.10 Authority protocol and transactional store

Status: functional unit 1 complete with local automated validation. The store is
not yet reachable over SSH; helper/exchange integration is the next unit.

Added the `vam-authority` library as the shared client/helper authority boundary.
Its versioned JSON envelope contains a request UUID, optional expected appliance
UUID, exact protocol version, and tagged operation. The first protocol supports
information/compatibility inspection, revision-aware snapshots, mutation lease
acquire/renew/abort, atomic commit, and bounded-reference secret retrieval.
Response failures are structured as invalid request, incompatible, conflict,
busy, invalid lease, missing record, or internal failure. Database/filesystem
errors are reduced to a generic remote message rather than returning sensitive
implementation detail.

The authority schema is separate from the legacy desktop schema. It stores one
stable appliance UUID, monotonic revision, protocol/schema version, and optional
lease; normalized instance, user, device, DNS, deployment, event, backup,
activity, setting, secret, and idempotency tables; and foreign keys that prevent
orphaned appliance aggregates. It intentionally contains no SSH endpoint,
private-key path, passphrase reference, or approved host key.

`AuthorityStore` creates/migrates the database, verifies that a reopened file
belongs to the expected appliance, enables SQLite foreign keys and full
synchronous writes, uses WAL only inside the appliance store, and enforces
`0700` parent-directory plus `0600` database modes on Unix. No SQLite file is an
interchange payload.

Secret values are BLOBs keyed by the existing UUID references. The protocol
serializes them as base64 only inside protected request/response files; custom
`Debug` output always shows `[REDACTED]`, and their byte buffers zeroize on drop.
Snapshots include only secret metadata and never values. Secret inserts/updates
share the same database transaction and revision increment as their owning state
change.

Mutation leases are persisted and conditional on the exact current revision.
Active overlapping leases return a structured busy result; stale revisions
return the expected/current pair. Commit applies the typed change set and clears
the unexpired matching lease only while incrementing the revision. A foreign-key
or other transaction failure rolls back the changes, leaves the revision
unchanged, and preserves the lease so application rollback/retry remains
possible. Reusing a committed lease returns a revision conflict and cannot
advance the revision twice.

Files changed:

- `Cargo.toml` and `Cargo.lock`: register `vam-authority` and its existing
  workspace dependencies;
- `crates/authority/Cargo.toml`: isolated library manifest;
- `crates/authority/migrations/0001_authority.sql`: authority metadata, lease,
  aggregate, protected-secret, and idempotency schema;
- `crates/authority/src/lib.rs`: protocol types, redacted secret buffers,
  compatibility mapping, snapshot reads, lease lifecycle, atomic change-set
  commits, protected secret fetch, permission enforcement, and tests.

Validation and diagnosis:

- the first test build stopped because the current `NetworkConfig` fixture also
  requires explicit optional IPv6 subnet and gateway fields; the fixture was
  corrected without changing the production model;
- strict Clippy stopped on unnecessary `Result` returns in Windows-only no-op
  permission shims; permission calls are now compiled only on Unix and the shims
  were removed;
- strict Clippy then stopped on the size of the commit operation enum variant;
  boxing its change set keeps normal protocol envelopes compact without changing
  JSON;
- six focused authority tests pass, covering disk reopen, appliance identity,
  value-free snapshots, protected secret retrieval, base64 protocol round-trip,
  redacted debug output, exact compatibility, overlapping and stale leases,
  exact-once revision advancement, and failed-transaction rollback;
- `cargo fmt --all -- --check` passes;
- `cargo clippy -p vam-authority --all-targets -- -D warnings` passes;
- `cargo test -p vam-authority` passes 6/6 tests plus doc tests;
- `cargo test --workspace` passed every pre-existing Rust test plus all six
  authority tests and documentation targets;
- `cargo clippy --workspace --all-targets -- -D warnings` passed after the
  authority protocol/store implementation.

No local desktop authority path or remote runtime was changed in this unit.
