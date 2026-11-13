# Helper repair acceptance checks

`installer.sh` exercises atomic installation, idempotence, corrupt/unusable
payloads, rollback, unsafe paths, concurrent replacements, and preservation of
control data. Run it only inside a disposable Linux container with
`VPNCTL_DISPOSABLE_INSTALLER_TEST=1`. `VPNCTL_TEST_HELPER` optionally names a real
built helper inside that container.

For the complete verified SSH/SFTP repair workflow on an x86_64 Linux Docker host:

```sh
VAM_HELPER_ARCHITECTURES=x86_64 bash build-helpers/server/bundle.sh
bash tests/helper-update/ssh/run.sh
```

The second script creates a loopback-only SSH container and a fresh ephemeral
Ed25519 authentication key. The server host key is obtained through the Docker
control plane and approved through the normal application workflow. No user SSH
keys or managed servers are used. The fixture emulates a compatible older helper
by hiding advertised capabilities and refusing `self-check` until the real
application replaces it with the trusted built helper.

The integration test checks automatic replacement, retained backup, capabilities
and appliance identity after rediscovery, repeated discovery using the retained
connection, absence of VPN deployment, and connection shutdown. It is ignored by
the ordinary workspace test run because it requires this disposable fixture;
the script explicitly enables and runs it. Containers and generated keys are
removed on success or failure. The test image is retained as a build cache.
