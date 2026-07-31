# Remote filesystem and rendered format

## Root layout

All names are UUID-derived:

```text
/opt/vpn-appliance-manager/
|-- instances/<instance-uuid>/
|   |-- compose.yaml
|   |-- .env
|   |-- instance.json
|   |-- state.json
|   |-- dns/                    # routed backends only
|   |   |-- Corefile
|   |   |-- hosts/blocklist.hosts
|   |   `-- zones/db.<private-zone>
|   |-- vpn/                    # WG, AWG, or OpenVPN
|   |-- ikev2/                  # IKEv2 only
|   |-- xray/                   # Xray read-only config/build input
|   `-- xray-state/             # Xray writable identity/active state
|-- staging/<instance-uuid>-<deployment-uuid>/
|-- backups/<instance-uuid>/<UTC-timestamp-or-manual-name>/
`-- trash/
```

Display names do not participate in remote paths, Compose project names, or
shell arguments. A project is always `vam-<instance-uuid>`.

Staging and active directories share the same filesystem. Validation occurs in
staging; activation moves validated paths into the active tree. Failed active
trees are moved under `trash` rather than silently overwritten.

## Shared files

| File | Mode | Purpose |
| --- | --- | --- |
| `compose.yaml` | `0644` | Backend-generated Compose services, listeners, capabilities, mounts, sysctls |
| `.env` | `0600` | Validated host listener values used by Compose |
| `instance.json` | `0600` | Typed non-secret instance desired state |
| `state.json` | `0600` | Remote manifest: version, content digests with WG/AWG key-line normalization, optional WG/AWG public key, deployment time |
| `dns/Corefile` | `0644` | Private-zone and DNS-over-TLS forwarding policy |
| `dns/zones/db.<zone>` | `0644` | Deterministically sorted A/AAAA/CNAME/TXT/SRV zone |
| `dns/hosts/blocklist.hosts` | `0644` | Deterministically rendered selected hostlists |

Xray declares no managed DNS capability, so none of the `dns/` files or the
CoreDNS service are rendered for Xray.

## Backend directories

### WireGuard

```text
vpn/
|-- server.key             # generated remotely, 0600
|-- wg0.conf.template      # sentinel in place of server private key
`-- wg0.conf               # materialized remotely, 0600
```

The LinuxServer image receives `vpn/` at `/config/wg_confs`. The application
copies an existing `server.key` into staging or generates one inside the
container, prints only `wg pubkey`, and materializes the template without
placing the private key in a process argument.

### AmneziaWG 2

```text
vpn/
|-- server.key
|-- awg0.conf.template
|-- awg0.conf
`-- start-awg.sh
```

`vpn/` mounts at `/etc/amneziawg`. The rendered server and every client contain
the same validated Jc/Jmin/Jmax, S1-S4, and H1-H4 obfuscation values. The
server-key sentinel follows the WireGuard remote-only pattern.

### OpenVPN

```text
vpn/
|-- Dockerfile
|-- server.conf
|-- start-openvpn.sh
|-- tls-crypt.key          # when enabled
|-- ccd/<client-common-name>
|-- requests/
`-- pki/
    |-- private/
    |-- issued/
    |-- revoked/
    |-- crl.pem
    `-- ca.crt
```

`vpn/` mounts read/write at `/etc/openvpn`. `pki`, `requests`, and
`tls-crypt.key` are persistent identity paths: they are copied into staging
before rendering and validated for symlinks/partial authorities. CCD files are
deterministically generated from enabled desired devices.

Client private keys remain in the local credential store. Only CSRs are
uploaded to `requests`; signed certificates and CA/TLS public material are
downloaded through bounded SFTP.

### IKEv2

```text
ikev2/
|-- Dockerfile
|-- swanctl.conf
|-- start-ikev2.sh
|-- private/
|-- x509/
|-- x509ca/
|-- x509crl/
|-- requests/
|-- issued/
`-- revoked/
```

The full directory mounts at `/etc/swanctl`. All listed certificate/authority
directories are persistent identity paths. Local P-384 client CSRs are signed
remotely. Revocation records and CRLs survive restart, image rebuild, upgrade,
backup, and rollback.

### Xray

```text
xray/
|-- Dockerfile
|-- server-template.json
|-- start-xray.sh
`-- tls/
    |-- server.crt         # TLS mode only
    `-- server.key         # TLS mode only
xray-state/
|-- identity/
|   |-- private.key       # REALITY mode, remote only
|   |-- public.key
|   `-- short-id
`-- server.json           # active materialized structured configuration
```

`xray/` is read-only in the runtime container. `xray-state/` is writable and
owned by numeric UID/GID 10001. Startup creates/reuses REALITY identity with
umask 077, materializes the structured template, validates it with
`xray run -test`, and starts Xray as UID/GID 10001.

UUID bearer credentials are resolved from native storage only inside Rust,
validated, inserted through `serde_json`, and sorted deterministically. SQLite
and deployment snapshots contain only opaque references. There is no raw
string replacement. The server template is classified sensitive so its full
client list is redacted from routine CLI/Tauri output.

## Images and build inputs

| Component | Reference strategy |
| --- | --- |
| WireGuard | `lscr.io/linuxserver/wireguard:1.0.20250521-r1-ls109` |
| AmneziaWG | `amneziavpn/amneziawg-go:2.0.0` plus SHA-256 image digest |
| OpenVPN | local tag `vpn-appliance-manager/openvpn:alpine3.23.5-openvpn2.6.20-r0-easyrsa3.2.3-r0`; digest-pinned Alpine base and pinned apk versions |
| IKEv2 | local tag `vpn-appliance-manager/ikev2:alpine3.23.5-strongswan5.9.14-r3`; digest-pinned Alpine base and pinned apk versions |
| Xray | local tag `vpn-appliance-manager/xray:alpine3.23.5-v25.8.3`; digest-pinned Alpine base, pinned apk versions, TLS 1.3 download, per-architecture SHA-256 verification |
| CoreDNS | `docker.io/coredns/coredns:1.13.1` |

No reference ends in `latest`. Local image preparation uses `docker compose
build`; pulled images use `docker compose pull`. The planner surfaces those
operations before apply.

## Manifest, hashing, and drift

`state.json` stores a SHA-256 for each rendered path except itself; it never
stores rendered file bytes. WireGuard/AWG private and preshared-key lines are
normalized to a fixed marker before hashing. Other protected content, including
Xray UUIDs or imported TLS material, can affect only its one-way digest so a
credential change remains visible to drift planning; the manifest never
contains the raw credential or a complete artifact.

Planning:

1. reads and parses the remote manifest;
2. rejects unsafe relative paths;
3. recomputes current remote hashes;
4. marks unexpected differences as drift;
5. compares the remote and locally rendered file sets;
6. emits typed operations and a hash of the complete desired state.

Apply re-renders and rejects a stale desired-state hash. Drift is reported in
the plan and reconciled only through reviewed apply.

## Backup and rollback format

A pre-mutation backup is an archive-mode copy of the complete active instance
tree:

```text
backups/<instance-uuid>/<name>/
  compose.yaml
  .env
  instance.json
  state.json
  <all backend configuration and persistent identity>
  <dns data when present>
```

Rollback stops the failed Compose project, moves the failed tree to `trash`,
copies the entire selected backup back into `instances/<uuid>`, starts Compose,
and runs the selected backend's health contract. This restores protocol keys,
certificate authorities, CRLs, and REALITY identity together with
configuration.

## DNS format

Records sort by owner, type, value, and UUID. Owners must remain inside the
private zone. TTL is limited to 30-86400 seconds. Each change increments a
monotonic `YYYYMMDDNN` SOA serial; rollback creates a new serial.

The Corefile loads the local hosts blocklist before public forwarding. Public
queries go only to `1.1.1.1` and `1.0.0.1` over TLS with
`one.one.one.one` certificate-name verification. There is no plaintext
downgrade.
