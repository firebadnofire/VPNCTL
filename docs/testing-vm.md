# Reusable Linux VM acceptance

The normal unit suite requires no public VPN infrastructure. This document
defines manual/integration acceptance for a disposable Linux VM on a private
LAN.

The previously prepared Debian clone is named `dnswg-test`. Its recorded
libvirt identity and DHCP address are historical observations, not stable test
inputs:

- libvirt UUID `33863022-461f-49c9-aaf1-8f4b7a7e4485`;
- MAC `52:54:00:cb:de:7c`;
- last observed address `192.168.86.109`;
- last observed Docker `29.6.2`, Compose `5.3.1`.

Always ask the guest agent for the current address.

## Safety and clone invariants

- Clone only from a powered-off template.
- Use a full independent qcow2 image.
- Generate a fresh libvirt UUID, MAC, machine ID, hostname, and SSH host keys.
- Preserve only the intended public `authorized_keys`.
- Remove any copied user private key.
- Use a private/LAN interface whose exposed VPN ports are understood.
- Enable the QEMU guest agent.
- Snapshot or clone before destructive reinstall/rollback tests.
- Never use `--replace`, overwrite an existing disk, or start/modify the
  template.

The reusable `dnswg-test` may retain Docker and `/opt` state for protocol
acceptance. Test automatic fresh-host provisioning on a separate disposable
clone such as `dnswg-fresh-host`.

## Discovery

On the libvirt host:

```sh
ssh server 'sudo virsh domstate debian'
ssh server 'sudo virsh dominfo dnswg-test'
ssh server 'sudo virsh domifaddr dnswg-test --source agent'
```

From the desktop test machine:

```sh
ssh william@<guest-lan-address>
uname -a
docker version
docker compose version
test -w /opt/vpn-appliance-manager
```

Do not bypass the product's SSH trust flow just because manual SSH succeeds.

## Host trust acceptance

1. Add the host with an OpenSSH key and probe without authentication.
2. Verify the SHA-256 fingerprint on the guest through a separate trusted
   channel.
3. Approve the exact fingerprint and inspect successfully.
4. Regenerate guest SSH host keys.
5. Confirm every authenticated operation reports a changed key and is blocked.
6. Verify the replacement fingerprint out of band and use the explicit
   replacement action.
7. Repeat authentication with an unencrypted PuTTY PPK fixture.
8. Repeat with an encrypted supported key and confirm the passphrase is
   retrieved from the native store, not requested by Svelte after save.

## Fresh-host setup acceptance

Use a disposable supported-distro clone with Docker absent:

1. Inspect and verify the correct apt/dnf/yum/zypper/pacman detection.
2. Review the setup plan; confirm no change occurs during inspection/planning.
3. Confirm the modal discloses package operations and Docker-group
   root-equivalent access.
4. Apply using the reviewed observed-state hash.
5. Confirm only distribution packages were used.
6. Confirm Docker is enabled/running and Compose major version is at least 2.
7. Confirm a fresh SSH session has direct Docker access.
8. Re-plan and confirm an empty no-op plan.
9. Change a prerequisite between plan/apply and confirm the stale plan is
   rejected.
10. Repeat on one representative VM from each manager family where resources
    permit.

Do not grant broad passwordless sudo merely for the test. Prefer a root test
account or intentionally reviewed noninteractive rules on a disposable guest.

## Common deployment acceptance

Run for every backend:

1. Create the instance with its default listener.
2. Preview and inspect the typed operations and desired-state hash.
3. Apply and require backend/listener/client/DNS health appropriate to its
   capabilities.
4. Re-plan without changes and confirm no mutation.
5. Create a device and export its expected artifact without viewing secret
   material in the frontend/logs.
6. Disable or revoke the device and verify remote desired state.
7. Replace identity and confirm the old identity is absent/revoked.
8. Create a manual backup.
9. Perform a normal image pull/rebuild and confirm server identity and existing
   clients still work.
10. Force a post-activation health failure and confirm automatic full-tree
    rollback.
11. Restore a successful snapshot manually and confirm a fresh DNS serial for
    routed backends.
12. Search application logs, SQLite, remote manifest, and UI traffic for
    private material.

Use non-default listener ports for WG, AWG, OpenVPN, and Xray. Verify the same
port/protocol in Compose, `ss`, UFW/Firewalld where active, and application
health. Confirm IKEv2 rejects any attempt to replace UDP 500/4500.

## Backend-specific acceptance

### WireGuard

- Verify one unique keypair and PSK per device.
- Import `.conf` and QR into a real client.
- Verify split-tunnel IPv4 and full-tunnel `0.0.0.0/0`.
- Confirm `::/0` is not advertised without IPv6 tunnel support.
- Verify handshake/transfer and enabled-peer count.
- Disable/re-enable without rotating identity.
- Confirm `vpn/server.key` survives image update and rollback.

### AmneziaWG 2

- Verify the selected Jc/Jmin/Jmax, S1-S4, and H1-H4 values match in server and
  exported client.
- Import the `.conf`/QR into an AWG 2-capable client.
- Confirm the server uses `awg0`/`awg-quick`, not plain WireGuard tools.
- Verify the unique mandatory PSK and server key survive update/rollback.

### OpenVPN

- Verify local private-key and CSR generation.
- Confirm only the CSR appears remotely before signing.
- Import the `.ovpn` profile into a real OpenVPN 2.6 client.
- Test UDP and TCP plus both supported data ciphers.
- If `tls-crypt` is enabled, confirm the client embeds the retrieved key.
- Revoke, verify CRL regeneration/reload, and confirm the revoked profile is
  rejected.
- Replace identity and confirm the new profile connects.
- Confirm PKI/index/CRL survive image rebuild and rollback.

### IKEv2

- Verify both UDP 500 and 4500 are published and allowed.
- Confirm the server certificate identity matches the configured endpoint.
- Export `.p12`, retrieve its password through the explicit local workflow, and
  import it into an OS-native IKEv2 client.
- Confirm an empty password does not open the bundle.
- Revoke and verify CRL update plus old-SA termination.
- Replace identity and verify only the new certificate connects.
- Confirm CA/server keys/CRL survive rebuild and rollback.

### Xray

- Use REALITY/TCP, then REALITY/XHTTP.
- Confirm no tunnel address, CoreDNS service, DNS records, forwarding sysctl,
  `NET_ADMIN`, TUN device, or Docker socket.
- Import `.vless.txt` or QR into a compatible client.
- Confirm generated UUIDs are unique and disabled/replaced UUIDs disappear
  from parsed `server.json`.
- Confirm SQLite/device snapshots contain only the UUID's opaque secret
  reference, and routine CLI/Tauri device JSON contains neither the UUID value
  nor its reference.
- Use a custom TCP port and confirm container/host/firewall health matches it.
- Confirm REALITY private key/short ID survive rebuild and rollback.
- Confirm the container runs as UID/GID 10001.

TLS/mKCP requires a reviewed native certificate-import workflow and is not part
of current desktop acceptance.

## DNS acceptance

For WG, AWG, OpenVPN, and IKEv2:

- resolve `gateway.<zone>`;
- resolve a managed device record;
- exercise A, AAAA, CNAME, TXT, and SRV validation;
- add an HTTPS hostlist and verify a selected domain maps to `0.0.0.0`;
- resolve a public name through DNS-over-TLS;
- make a DNS-only change and confirm the DNS reload path;
- verify a monotonic SOA serial after rollback.

For Xray, confirm the UI hides managed DNS and the remote tree contains no
CoreDNS files/service.

## Evidence to retain

Record:

- app commit and signed-commit verification;
- desktop OS/build;
- guest distribution/architecture;
- Docker/Compose versions;
- approved SSH fingerprint;
- backend settings and listener list without secrets;
- plan operations/warnings;
- final health;
- client interoperability result;
- backup/rollback result;
- explicit statement that logs/SQLite/frontend were checked for leakage.

Never retain real private keys, PSKs, PPK files, complete profiles, PKCS#12
passwords, or unredacted error output in test artifacts.
