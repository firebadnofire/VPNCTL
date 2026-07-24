# Debian VM test environment

The reusable integration guest is `dnswg-test`, cloned from the powered-off `debian` template without modifying the template.

The provisioned clone currently has:

- Libvirt UUID `33863022-461f-49c9-aaf1-8f4b7a7e4485`
- MAC address `52:54:00:cb:de:7c`
- DHCP address `192.168.86.109` at the time of acceptance
- Docker Engine `29.6.2` and Compose plugin `5.3.1`

Treat the guest-agent address as authoritative if DHCP later assigns a different address.

## Clone invariants

- Full independent `/var/lib/libvirt/images/dnswg-test.qcow2`
- Fresh libvirt UUID and MAC
- Fresh machine ID, hostname, and SSH host keys
- `/home/william/.ssh/authorized_keys` preserved
- Cloned user private key removed
- Direct `eno1` interface on the `192.168.86.0/24` LAN
- QEMU guest agent enabled
- Docker Engine and Compose plugin enabled
- `william` has direct Docker access
- `/opt/vpn-appliance-manager` owned by `william`

Never use `--replace`, overwrite an existing disk, or start the template. Reuse the clone when its identity and prerequisites are healthy.

## Inspection

On the libvirt host:

```sh
ssh server 'sudo virsh domstate debian'
ssh server 'sudo virsh dominfo dnswg-test'
ssh server 'sudo virsh domifaddr dnswg-test --source agent'
```

From the Mac:

```sh
ssh william@<guest-lan-address>
docker version
docker compose version
test -w /opt/vpn-appliance-manager
```

## Acceptance sequence

1. Probe the fresh unknown host key and approve its exact fingerprint.
2. Regenerate guest SSH host keys and confirm the changed key is blocked.
3. Explicitly replace the verified key.
4. Inspect Linux, architecture, Docker, Compose, WireGuard, UDP port, `/opt`, and sudo bootstrap.
5. Create an instance and deploy it.
6. Add a user and device, then deploy the new peer.
7. Export the client configuration and QR.
8. Resolve `gateway.vpn.internal`, a managed device record, and a public name.
9. Disable/re-enable the peer and verify the peer set.
10. Change only DNS and verify CoreDNS reload behavior.
11. Create a manual backup.
12. Trigger validation failure and verify active state is unchanged.
13. Roll back a successful deployment and confirm a fresh SOA serial.
14. Inspect persisted logs for secret leakage.

Final manual acceptance imports the exported file into the installed macOS WireGuard app and verifies split- and full-tunnel IPv4 routing. The manual client connection is intentionally outside automated test authority.
