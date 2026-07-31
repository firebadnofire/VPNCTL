# VPN Appliance Manager multi-protocol refactor dissection

This file is the living implementation record for the refactor of the `dnswg`
repository. It describes the code that existed before the refactor, the design
decisions made during implementation, each completed functional unit, and the
validation evidence collected after every unit.

The repository name remains `dnswg`. The product name remains **VPN Appliance
Manager**.

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
- Xray client UUID, email/label metadata, and optional flow metadata.

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
- **Xray:** generated UUID plus metadata, structured server JSON, preserve
  server-only Reality private material, reconcile/list/revoke/regenerate
  clients, export a client configuration, and never perform raw textual JSON
  replacement.

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
snapshot retention. Xray has no secret-store reference because its UUID is
itself the client credential and will be treated as sensitive export material.

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

- pending full validation and signed commit.
