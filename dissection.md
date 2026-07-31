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
- **OpenVPN:** local RSA private key and CSR, upload only the CSR for remote CA
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

- pending final diff review, whitespace validation, and signed commit.
