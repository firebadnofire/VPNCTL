# Security and secret lifecycle

## Security invariants

- SSH host identity is approved before authentication.
- The Svelte/Tauri boundary contains no secret-bearing model.
- SQLite stores opaque references, never secret values.
- Production secrets use the native OS credential store with no plaintext
  fallback.
- Client private keys are generated locally.
- Remote-only server identity is never returned.
- Remote exit status is authoritative.
- Plans bind review to exact observed/desired-state hashes.
- Containers use backend-declared least privilege and never mount Docker's
  socket.
- A mutating deployment backs up the complete protocol identity tree.

## Secret location matrix

| Material | Local native store | SQLite/frontend | Remote host |
| --- | --- | --- | --- |
| SSH private-key passphrase | yes | opaque reference / never frontend | never |
| WG/AWG client private key | yes | opaque reference / never frontend | never |
| WG client PSK | yes when enabled | opaque reference / never frontend | materialized only in protected server config |
| AWG client PSK | yes, mandatory | opaque reference / never frontend | materialized only in protected server config |
| WG/AWG server private key | never | never | generated/reused under `vpn/server.key`, `0600` |
| OpenVPN client private key | yes | opaque reference / never frontend | never |
| OpenVPN client CSR | yes while identity exists | opaque reference / never frontend | uploaded request file, then pruned |
| OpenVPN client certificate/CA | yes | references plus public serial / never frontend | issued database/CA |
| OpenVPN CA/server key/CRL | never | authority-ready flag only | persistent `vpn/pki` |
| OpenVPN `tls-crypt` key | yes for client export | opaque reference / never frontend | persistent protected file |
| IKEv2 client private key/CSR | yes | opaque references / never frontend | CSR transient; private key never |
| IKEv2 client certificate/CA | yes | references plus public serial / never frontend | issued/CA records |
| IKEv2 PKCS#12 password | yes | opaque reference / never frontend | never |
| IKEv2 CA/server key/CRL | never | authority-ready flag only | persistent `ikev2` directories |
| Xray client UUID credential | yes | opaque reference / never frontend | materialized only in protected active JSON |
| Xray REALITY private key | never | never | generated/reused in `xray-state/identity` |
| Xray REALITY public key/short ID | no secret store needed | public settings only | `xray-state/identity` |
| Xray TLS private key | yes when imported through Rust | opaque reference / never frontend | protected rendered file |
| Complete client artifact | transient Rust memory | never serialized to frontend | never |

`Zeroizing` protects in-memory Rust buffers where practical. It is not a
replacement for OS memory protection, but it reduces lifetime after use.

## Native credential storage

`KeychainSecretStore` uses service
`org.archuser.vpnappliancemanager` and the keyring v1 platform mapping:

- macOS Keychain;
- Windows Credential Manager;
- Linux Secret Service over D-Bus.

The in-memory implementation exists only for tests. A native-store failure is
returned; the application does not fall back to a file, environment variable,
SQLite blob, or frontend state.

Secret references have their own retention table. Deleting/replacing an
identity marks old references pending. Actual native-store deletion waits until
the reference is absent from the ten retained successful deployment snapshots.
This keeps eligible rollbacks usable.

If required local material is missing, rendering/export fails. The application
does not silently rotate an identity. The operator must explicitly replace the
device identity and deploy.

## SSH trust and authentication

The SSH sequence is:

1. open a probe connection without authentication;
2. return algorithm, resolved address, port, exact public key, and SHA-256
   fingerprint;
3. require exact typed fingerprint confirmation;
4. re-probe before saving approval;
5. compare the exact public-key blob on every authenticated operation.

Unknown and changed keys are blocked. Replacing a changed key requires a
separate explicit flag after out-of-band verification.

The product uses `russh`; it never shells out to `ssh`, `scp`, or `sftp`.
OpenSSH and PuTTY PPK private keys are decoded in Rust. Encrypted-key
passphrases are retrieved from native storage. Commands, uploads, and bounded
downloads all receive the approved public-key blob and cancellation token.

Every transported command checks its remote exit status. A non-zero result is
an error even when stdout was successfully received. Technical detail includes
the numeric status and redacted stdout/stderr.

## Host setup authority

Inspection cannot mutate the host. Setup requires an explicit plan and a hash
of the current inspection. Apply re-inspects and refuses stale state.

The installer:

- supports apt, dnf, yum, zypper, and pacman;
- uses distribution repositories only;
- downloads no installer script;
- requires root or noninteractive sudo;
- starts Docker through systemd or a conventional service command;
- verifies privileged Docker/Compose first and direct user access in a fresh
  SSH session;
- warns that Docker-group membership is root-equivalent.

Ordinary instance deployment does not use this package-install authority.

## Server identities

### WireGuard and AWG

The application uploads a sentinel template. A fixed container script creates
or reuses `server.key`, reads it from a file, materializes the active config,
sets `0600`, and prints only the public key. Private keys are not returned,
uploaded from local state, logged, or placed in a process argument.

Every device receives a unique local keypair. WG PSKs are unique when enabled;
AWG PSKs are unique and mandatory. No Amnezia-style shared PSK is used.

### OpenVPN

The persistent Easy-RSA authority uses EC prime256v1 and SHA-256. Client
private keys and PKCS#10 CSRs are generated locally. Only the CSR is uploaded.
The signed certificate, CA certificate, and optional `tls-crypt` material are
downloaded with a one-MiB bound into native storage.

Revocation updates the Easy-RSA index and CRL, verifies the CRL, reloads the
gateway, and retains revocation state in backup/rollback.

### IKEv2

The persistent strongSwan authority and server identity remain remote. Client
private keys and CSRs use P-384/SHA-384 locally. Revocation is serial-bound,
regenerates the CRL, reloads credentials, and terminates the old SA.

Export constructs PKCS#12 in Rust with a generated password stored in the
native credential store. Encryption and MAC KDF iteration counts are 600,000.
No empty-password bundle is produced.

### Xray

Each VLESS UUID is a bearer credential. Rust generates it locally, stores it in
the native credential store, and persists only an opaque reference in SQLite.
Routine CLI/Tauri device views contain only the non-secret email label and flow.
Server rendering and explicit `.vless.txt` export resolve the UUID inside Rust.
Active users are produced with structured JSON serialization, never raw string
replacement. Missing, malformed, shared-reference, or duplicate resolved UUIDs
fail closed.

REALITY private material is generated remotely under umask 077 and never
returned; only the public key and short ID enter desired state.

The Xray container runs as UID/GID 10001 with no added Linux capability,
device, forwarding sysctl, or private DNS service. The downloaded Xray archive
uses HTTPS/TLS 1.3 plus a fixed architecture-specific SHA-256 check.

## Export handling

Exports are explicit:

- WireGuard/AWG: text `.conf`;
- OpenVPN: text `.ovpn`;
- IKEv2: binary password-protected `.p12`;
- Xray: text `.vless.txt`.

Rust materializes the artifact transiently and writes it directly to the
selected path. Unix creation uses mode `0600`. Windows relies on the selected
directory/file's Windows ACL; users should export into their private profile,
not a shared directory. Tauri receives only the resulting path. QR is available
only for text backends that declare it and exists only in the current UI view.

## Containers, network, and supply chain

- No Compose service uses privileged mode.
- No service mounts `/var/run/docker.sock`.
- Capabilities, `/dev/net/tun`, mounts, and sysctls come from the selected
  backend's closed runtime specification.
- Host firewall rules come from validated TCP/UDP listener declarations,
  including custom ports.
- The application does not globally drop ICMP or apply unrelated sysctls.
- No server component uses a mutable `latest` tag.
- AWG and local Alpine bases use digests; apk packages use exact versions;
  Xray archives use fixed hashes.
- CoreDNS public forwarding is DNS-over-TLS only with certificate-name
  verification and no plaintext fallback.

## Logs and error detail

Known secret values and lines containing private-key, preshared-key, password,
or passphrase fields are replaced with `[REDACTED]`. Sensitive rendered files
are cleared before Tauri output and replaced with a marker in CLI output.
Remote manifests contain SHA-256 digests rather than rendered bytes;
WireGuard/AWG private-key and preshared-key lines are normalized to a fixed
marker before hashing. High-entropy Xray UUID and imported TLS material can
affect a one-way remote digest so credential changes remain detectable, but
neither the raw value nor a complete artifact is written to the manifest.

Operational history stores safe phase/message/detail records. It does not store
complete commands containing materialized secrets, complete client profiles,
private keys, PSKs, passphrases, or secret environment values.

## Vulnerability reports

Report vulnerabilities privately to the repository owner. Do not attach real
VPN profiles, private keys, certificates with private material, PPK files, or
passphrases.
