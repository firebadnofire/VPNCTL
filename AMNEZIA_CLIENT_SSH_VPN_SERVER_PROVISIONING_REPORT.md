# How AmneziaVPN Uses SSH to Provision VPN Servers

## Executive summary

This report describes the self-hosted server provisioning implementation in the
adjacent `amnezia-client` checkout at commit
`30ec46a567b1d5cefd8a1676c4714c58ae5b32d6` (2026-07-29).

AmneziaVPN does **not** carry VPN traffic through SSH. SSH is its remote
administration and provisioning control plane. The application uses an embedded
libssh client to:

1. authenticate to an existing Linux server;
2. verify that the account has non-interactive `sudo`;
3. detect supported package managers and install host prerequisites;
4. install and start Docker when necessary;
5. upload Dockerfiles and generated shell scripts;
6. build, create, configure, and start a protocol-specific container;
7. read server public keys, certificates, and configuration back from the
   container;
8. add, inspect, and revoke VPN clients later; and
9. reconfigure, restart, remove, or rediscover installed containers.

The actual VPN listener is a Docker-published TCP or UDP port. Once
provisioning finishes, ordinary client traffic goes directly to OpenVPN,
WireGuard, AmneziaWG, IPsec/IKEv2, or Xray—not through the SSH connection.

The current provisioning path recognizes five VPN families:

| User-facing VPN | Container identity | Default listener | Server technology |
|---|---|---:|---|
| OpenVPN | `amnezia-openvpn` | UDP 1194 | OpenVPN + Easy-RSA |
| WireGuard | `amnezia-wireguard` | UDP 51820 | WireGuard tools and `wg-quick` |
| AmneziaWG 2 | `amnezia-awg2` | UDP 55424 | `amneziawg-go`, `awg`, and `awg-quick` |
| AmneziaWG legacy | `amnezia-awg` | UDP 55424 | legacy AmneziaWG image with `wg`/`wg-quick` |
| IKEv2 | `amnezia-ipsec` | UDP 500 and 4500 | Libreswan-style IPsec, NSS certificates, and xl2tpd |
| Xray | `amnezia-xray` | TCP 443 | VLESS with Reality by default; raw TCP, XHTTP, or mKCP settings |

The enum still contains Cloak and Shadowsocks/OpenVPN-over-Shadowsocks
containers, but the current code explicitly classifies those two as
unsupported and gives them no script folder or protocol mapping. They are
therefore historical compatibility values, not current SSH provisioning
targets. `SSXray` also appears in protocol/container dispatch, but unlike
`Xray`, it has no script-folder mapping and is not a separately installable
server in the current script registry.

The design is straightforward and mostly centralized, but the source also
exposes material risks:

- the SSH client does not verify the server host key;
- remote shell exit status is not read, so many failing commands can look
  successful unless their text output happens to match a special-case parser;
- all VPN containers are launched `--privileged`, and several also receive
  redundant broad capabilities and host module access;
- some images use mutable `latest` tags, Xray is downloaded without an
  integrity check, and several Dockerfiles start from the old Alpine 3.15 base;
- saved SSH credentials are encrypted on supported non-Linux desktop
  platforms, but encryption is explicitly disabled for desktop Linux;
- the host firewall setup error is discarded by the top-level installer;
- IPsec advertises legacy SHA-1 suites and enables L2TP/XAuth configuration
  branches in addition to IKEv2; and
- Xray allows a custom published port, but its in-container firewall only
  permits TCP 80 and 443.

These findings do not mean SSH itself supplies the VPN. They describe the
trust boundary and operational reliability of the remote installation
mechanism.

## Scope and source map

The report follows the production self-hosted path from the QML setup wizard
through the UI and core controllers, into the SSH abstraction, installer and
configurator classes, and finally the embedded server scripts.

The authoritative type lists are:

- `../amnezia-client/client/core/utils/containerEnum.h:12-31`, which separates
  VPN containers from non-VPN services;
- `../amnezia-client/client/core/utils/protocolEnum.h:20-36`, which lists the
  protocol families; and
- `../amnezia-client/client/core/utils/containers/containerUtils.cpp:211-231`,
  which maps containers to their default protocols.

Protocol script folders are selected in
`../amnezia-client/client/core/utils/selfhosted/scriptsRegistry.cpp:28-45`.
That switch is especially useful for distinguishing live provisioning targets
from enum values retained for compatibility.

This is a static source analysis. No server was modified and no live SSH or VPN
deployment was attempted.

## Architecture: SSH control plane versus VPN data plane

The provisioning path has four layers:

```text
QML setup wizard
    |
    v
InstallUiController
    |
    v
InstallController
    |---- SshSession ---- libssh::Client ---- SSH server
    |                           |
    |                           +-- exec one remote command per channel
    |                           +-- SCP bytes to a host path
    |
    +---- InstallerBase/subclass
    |         generates initial protocol/container settings
    |
    +---- embedded Dockerfiles and shell scripts
    |         build and configure the remote container
    |
    +---- ConfiguratorBase/subclass
              creates a client identity and reads/writes protocol state
```

The application bundles the provisioning scripts as Qt resources. The script
registry maps shared operations such as `install_docker.sh`,
`build_container.sh`, and `setup_host_firewall.sh`, as well as per-protocol
Dockerfiles, run scripts, configuration scripts, startup scripts, and client
templates
(`../amnezia-client/client/core/utils/selfhosted/scriptsRegistry.cpp:48-78`,
`88-114`).

The remote layout is consistently based on:

- host staging/build directory:
  `/opt/amnezia/<container-name>/`;
- container-specific persistent configuration under `/opt/amnezia/...` inside
  the container; and
- a shared Docker bridge named `amnezia-dns-net`, subnet
  `172.29.172.0/24`, with bridge interface `amn0`
  (`../amnezia-client/client/server_scripts/prepare_host.sh:1-8`).

There is no SSH local forwarding, remote forwarding, SOCKS tunnel, agent
forwarding, or persistent control socket in this path. Each VPN container
publishes its own listener with `docker run -p`. SSH remains necessary for
later administrative operations, but not for an already configured client to
carry VPN traffic.

## SSH connection and authentication

### Credential input

The setup wizard asks for:

- `Server IP address [:port]`;
- `SSH Username`; and
- `Password or SSH private key`.

The private-key help text says ED25519 and RSA keys in PEM form are supported
(`../amnezia-client/client/ui/qml/Pages2/PageSetupWizardCredentials.qml:94-98`,
`203-230`).

The internal `ServerCredentials` object contains host, user, secret, and an SSH
port that defaults to 22. A credential set is considered valid only when all
three strings are non-empty and the port is positive
(`../amnezia-client/client/core/utils/commonStructs.h:9-20`).

The UI parses a custom port by looking for any colon and splitting the host on
`:` (`../amnezia-client/client/ui/controllers/selfhosted/installUiController.cpp:568-576`).
That handles a simple `hostname:2222` or IPv4 address and port, but it is not an
IPv6-literal parser: an unbracketed or bracketed IPv6 address contains multiple
colons and cannot be safely interpreted by this logic.

### libssh setup

The project packages libssh 0.11.3 as a static library by default, with OpenSSL
as the default cryptographic backend
(`../amnezia-client/recipes/libssh/conanfile.py:13-35`). The application creates
an `ssh_session`, sets host, port, user, and log verbosity, and runs
`ssh_connect()` on a Qt concurrent worker while a local event loop waits
(`../amnezia-client/client/core/utils/selfhosted/sshClient.cpp:24-65`).

One implementation detail is unusual: `SSH_OPTIONS_USER` receives the string
`<username>@<host>`, while subsequent authentication calls receive just
`<username>` (`sshClient.cpp:41-49`, `67-101`). The report does not infer a
failure from that discrepancy, but it is part of the exact wire-session setup.

No explicit connection timeout, key-exchange policy, cipher policy, MAC policy,
or SSH protocol option is set. The wrapper relies on libssh defaults. It maps a
timeout only by searching the libssh error string for `"Timeout connecting to"`
(`sshClient.cpp:301-318`).

### Password and private-key authentication

Authentication is selected by inspecting the secret text:

- if it contains both `BEGIN` and `PRIVATE KEY`, the code treats it as an
  in-memory private key;
- otherwise, it calls password authentication.

For a private key, the client:

1. imports the base64/PEM text with
   `ssh_pki_import_privkey_base64`;
2. derives a public key;
3. calls `ssh_userauth_try_publickey`; and
4. calls `ssh_userauth_publickey`.

For a password, it calls `ssh_userauth_password`
(`../amnezia-client/client/core/utils/selfhosted/sshClient.cpp:67-105`).

Encrypted private keys are decrypted before the connection test. A callback
blocks on the UI passphrase prompt, libssh imports the protected key, and the
application exports an unencrypted in-memory private key that replaces
`credentials.secretData` for subsequent operations
(`../amnezia-client/client/ui/controllers/selfhosted/installUiController.cpp:588-619`;
`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:1240-1260`;
`../amnezia-client/client/core/utils/selfhosted/sshClient.cpp:334-362`).

### Connection test

The test is minimal: SSH runs `uname -a`, captures stdout and stderr, and treats
the connection as successful when the SSH wrapper returns no libssh error
(`../amnezia-client/client/server_scripts/check_connection.sh:1`;
`../amnezia-client/client/core/utils/selfhosted/sshSession.cpp:212-226`).

### Host identity is not verified

The connection routine never calls libssh's known-host or server-public-key
verification APIs and never asks the user to approve a fingerprint. It
authenticates the client to whatever SSH endpoint answered the requested
address, but it does not authenticate that endpoint to the client. This leaves
first connection and every later administrative session vulnerable to an
active man-in-the-middle attack capable of receiving the SSH credential and
substituting provisioning commands or returned VPN keys.

This conclusion is based on both:

- the complete connection routine, which proceeds directly from
  `ssh_connect()` to user authentication
  (`../amnezia-client/client/core/utils/selfhosted/sshClient.cpp:24-107`); and
- the absence of known-host/server-key verification calls elsewhere in the
  client source.

The separate SFTP-drive mounting feature explicitly disables strict host-key
checking, but that is not the provisioning transport. It reinforces the
project's current host-authentication posture rather than implementing it for
the embedded libssh path.

## Remote command execution and file transfer

### One SSH exec channel per command

`SshSession::runScript()` is not a remote shell-script transaction. It:

1. connects or reuses the current SSH session;
2. removes carriage returns;
3. splits the supplied script into non-empty lines;
4. joins lines ending in `\` into a single logical command;
5. skips logical commands beginning with `#`; and
6. opens a new SSH exec channel for each resulting command.

It stops only when the wrapper itself returns a non-zero `ErrorCode`
(`../amnezia-client/client/core/utils/selfhosted/sshSession.cpp:47-94`).

This execution model has two consequences:

- shell variables only persist within a backslash-joined logical command, which
  explains the heavy use of `;\` in shared scripts; and
- provisioning is not atomic. Earlier commands remain applied if a later
  command fails.

The exec worker requests a command, drains stdout and then stderr in 2 KiB
chunks, invokes optional callbacks, closes the channel, and returns the mapped
libssh transport error (`../amnezia-client/client/core/utils/selfhosted/sshClient.cpp:121-195`).

### Remote process exit status is ignored

The wrapper never calls `ssh_channel_get_exit_status()` or handles an exit
signal. Closing a successfully opened channel normally maps to
`SSH_NO_ERROR`, even when the remote shell command exited non-zero. As a
result, general shell failures do not reliably propagate into `ErrorCode`.

Some installer stages compensate by scraping combined output for known text:

- Docker cgroup and pull-rate errors during build;
- port-allocation errors during `docker run`;
- missing Docker/sudo, unsupported runtimes, old kernels, and package-manager
  locks; and
- missing containers during configuration.

Those checks are in
`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:447-552`
and `746-813`. Any failure with different wording, no output, localized output,
or output not captured by the relevant callback can be reported as success.

### SCP staging

The file-transfer wrapper creates an SCP write session, pushes a file, and
streams a local temporary file in 16 KiB chunks
(`../amnezia-client/client/core/utils/selfhosted/sshClient.cpp:226-290`).
`SshSession::uploadFileToHost()` first writes the supplied bytes to a
`QTemporaryFile`, then SCPs it to the requested host path
(`../amnezia-client/client/core/utils/selfhosted/sshSession.cpp:191-210`).

To write a file inside a container, the code:

1. chooses a random host file such as `/tmp/<random>.tmp`;
2. SCPs the bytes to that host path;
3. runs `docker exec mkdir -p` for the container destination;
4. uses `docker cp` to overwrite the destination, or copies to a temporary
   container path and appends with `cat >>`; and
5. runs `shred -u` on the host temporary file.

See `../amnezia-client/client/core/utils/selfhosted/sshSession.cpp:116-170`.

Cleanup is best-effort and occurs only at the end of the successful path. An
early return after a failed `mkdir`, `docker cp`, or append can leave sensitive
material in `/tmp`. The append path also does not remove the copied temporary
file from inside the container. Examples of data using this path include
OpenVPN certificate requests, WireGuard peer blocks, Xray JSON, startup
scripts, and client metadata.

### Running generated scripts inside a container

For multi-line container configuration, AmneziaVPN uploads a random `.sh` file
under `/opt/amnezia/` in the container, executes it with `bash` (or `sh` for
three non-VPN service containers), and then attempts to delete the script
(`../amnezia-client/client/core/utils/selfhosted/sshSession.cpp:96-114`).

The generated script is transferred rather than embedded in a command line,
which avoids some quoting limits. Variable substitution still happens on the
client with simple string replacement
(`sshSession.cpp:229-236`), so values placed into shell, JSON, or here-document
contexts are not automatically escaped.

## Common provisioning pipeline

`InstallController::setupContainer()` is the central workflow. Every current
VPN family follows these stages
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:102-159`).

### 1. Require a privileged remote account

The installer supports root or a user in the `sudo`/`wheel` groups. It invokes
package-manager commands through `sudo -n`, which requires passwordless,
non-interactive elevation. It detects:

- missing `sudo`;
- a user outside the expected groups;
- inaccessible home directories;
- sudoers denial; and
- a sudo password or interactive authentication requirement.

The checks are implemented in
`../amnezia-client/client/server_scripts/check_user_in_sudo.sh:1-14` and
interpreted by
`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:824-853`.

This means the least-privilege boundary is not a narrow deployment account.
The account must effectively be able to run unrestricted root commands without
interactive confirmation.

### 2. Wait for the package manager

The application detects apt, dnf, yum, zypper, or pacman and checks their lock
or PID state. It polls up to 30 times with 10-second sleeps—roughly five
minutes—and supports a cancellation flag during this phase
(`../amnezia-client/client/server_scripts/check_server_is_busy.sh:1-8`;
`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:856-909`).

Cancellation is not a general remote-command cancellation mechanism. The flag
is checked only in this polling loop.

### 3. Install host prerequisites and Docker

`install_docker.sh` maps the supported package managers to distribution package
names and non-interactive flags. As needed, it installs:

- `sudo`;
- `which`;
- `psmisc`/`fuser`;
- `lsof`;
- the distribution's `docker` or `docker.io` package; and
- AppArmor tooling when AppArmor is enabled.

It rejects a package resolution that would supply Podman, enables/starts the
Docker systemd service, and prints Docker and kernel versions
(`../amnezia-client/client/server_scripts/install_docker.sh:1-34`).

The script is conditionally rerunnable for already installed tools, but it
executes repository metadata updates and package installation directly on the
host. It assumes systemd for Docker activation.

For AmneziaWG 2, the client parses `uname` output and rejects kernels older than
4.14 (`installController.cpp:784-795`).

### 4. Check port availability

For new installations, the client builds an `lsof` pipeline for the desired
port and protocol. IPsec contributes the fixed ports 500 and 4500. OpenVPN can
use TCP, UDP, or both; WireGuard and AWG are UDP; Xray is treated as TCP
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:578-657`;
`../amnezia-client/client/core/utils/containers/containerUtils.cpp:311-316`;
`../amnezia-client/client/core/protocols/protocolUtils.cpp:159-189`).

The comment in the code already marks this for reimplementation with `netstat`.
If `lsof` cannot be installed or produces unexpected output, the check can
degrade because of the general exit-status limitation.

### 5. Prepare shared host state

The client creates `/opt/amnezia/<container-name>`, changes its owner to the SSH
user, and creates the shared Docker bridge if it is absent
(`../amnezia-client/client/server_scripts/prepare_host.sh:1-8`).

### 6. Remove the old container/image

Before a build, the installer executes stop, remove, and image-remove commands
for the target name
(`../amnezia-client/client/server_scripts/remove_container.sh:1-3`).
The top-level setup function does not check this operation's returned error
before continuing (`installController.cpp:133-140`).

For a normal first install, this is intended to clear stale state. For an
update or reinstall, it is destructive replacement rather than in-place
mutation. Unless data is held outside the removed container, protocol keys and
CA state will be regenerated by the subsequent configure script.

### 7. Upload and build the Dockerfile

The client removes the old Dockerfile, SCPs the embedded protocol Dockerfile to
the host directory, substitutes protocol variables into
`docker build --no-cache --pull -t <container-name> <folder>`, and runs it
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:447-487`;
`../amnezia-client/client/server_scripts/build_container.sh:1`).

Every provisioning build therefore bypasses cache and refreshes the base image.
This favors freshness but weakens reproducibility, especially where a
Dockerfile uses a mutable tag.

### 8. Create and attach the container

The per-protocol `run_container.sh` publishes listener ports, grants runtime
privileges, names the container, sets `--restart always`, and then attaches it
to `amnezia-dns-net`.

Every VPN run script uses `--privileged`. OpenVPN and Xray add `NET_ADMIN`;
WireGuard and both AWG variants add `NET_ADMIN`, `SYS_MODULE`, and mount the
host's `/lib/modules`; IPsec is privileged and publishes fixed UDP ports.
Because `--privileged` is already broader than the listed capabilities, the
capability additions do not meaningfully narrow the sandbox.

### 9. Configure the protocol

The client substitutes base and protocol-specific variables into
`configure_container.sh`, uploads the generated script, and runs it inside the
container (`installController.cpp:515-552`).

This stage generates server keys/certificates and writes the server
configuration. Its stdout may also carry values that the client captures for
some non-VPN services.

### 10. Apply host forwarding/firewall tuning

The host script:

- enables IPv4 forwarding for the current runtime;
- drops ICMP echo requests to the host;
- ensures several Docker forwarding rules exist; and
- applies a large set of TCP buffer, backlog, timeout, Fast Open, MTU probing,
  and Hybla congestion-control sysctls.

See `../amnezia-client/client/server_scripts/setup_host_firewall.sh:1-31`.

The `iptables -C ... || iptables -A ...` pattern makes those particular rules
rerun-aware. The changes are runtime commands, not a persistent distribution
firewall configuration. Some sysctls may not exist on modern kernels (for
example `tcp_tw_recycle`), and Hybla may not be available.

Most importantly, `setupContainer()` discards the result of
`setupServerFirewall()` and always proceeds to container startup
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:150-158`).
The UI may therefore report a successful install even if forwarding or
firewall setup failed.

### 11. Install and launch the startup script

If the protocol has `start.sh`, the application uploads it to
`/opt/amnezia/start.sh` in the container and launches it detached with
`docker exec -d`
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:555-575`).

The container images initially contain a placeholder `/opt/amnezia/start.sh`
that tails forever. Docker starts that placeholder as the entry point, giving
the client a live container in which it can install the real script. The
detached real script then configures interfaces/firewall rules, starts the VPN
daemon, and also tails forever.

### 12. Generate an administrative client profile

After container installation, the relevant configurator creates a new client
identity, modifies server state over SSH, retrieves the required public
material, and assembles a local client profile
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:393-444`,
`1129-1187`).

The initial self-hosted record stores both the SSH credentials and generated
container/client configuration so the app can continue administering the
server.

## OpenVPN

### Container build and runtime

OpenVPN is built from `alpine:3.15`. The Dockerfile installs OpenVPN, Easy-RSA,
bash, curl, netcat, `dumb-init`, and RNG tools, upgrades Alpine packages, and
uses the placeholder startup script as its entry point
(`../amnezia-client/client/server_scripts/openvpn/Dockerfile:1-14`, `48-49`).

The run script:

- launches the container privileged;
- disables Docker logging with `--log-driver none`;
- sets `--restart always`;
- publishes the selected port using the selected TCP/UDP transport;
- attaches the DNS bridge;
- creates `/dev/net/tun` when missing; and
- adds a host-address alias inside the container for a server behind NAT.

See `../amnezia-client/client/server_scripts/openvpn/run_container.sh:1-16`.

### Server PKI and configuration

During first configuration, the run script initializes an Easy-RSA PKI,
generates Diffie-Hellman parameters, creates a passwordless CA, generates and
signs the `AmneziaReq` server certificate, creates a static `tls-auth` key, and
generates a CRL
(`openvpn/run_container.sh:18-27`).

`configure_container.sh` writes `server.conf` with:

- a TUN device;
- a configurable subnet, mask, port, and TCP/UDP transport;
- duplicate common names allowed;
- configurable cipher and digest;
- CRL verification;
- `user nobody` and `group nobody`;
- `tls-server`;
- TLS minimum 1.2; and
- optional raw additional server configuration.

The exact template is
`../amnezia-client/client/server_scripts/openvpn/configure_container.sh:1-28`.
Defaults are subnet `10.8.0.0/24`, UDP 1194, AES-256-GCM, SHA-512, and enabled
`tls-auth`
(`../amnezia-client/client/core/utils/constants/protocolConstants.h:15-38`).

TLS 1.2 is allowed; the configuration does not require TLS 1.3. OpenVPN's data
channel is restricted to the configured cipher through both `cipher` and
`data-ciphers`.

### Container networking and daemon startup

The startup script:

- recreates the host-address alias and TUN device;
- permits TUN input/output/forwarding;
- permits VPN-subnet forwarding to either Docker interface;
- adds established/related forwarding;
- adds IPv4 masquerading through `eth0` and `eth1`;
- kills existing OpenVPN processes; and
- starts OpenVPN as a daemon when the CA exists.

See `../amnezia-client/client/server_scripts/openvpn/start.sh:5-30`.

### Client creation over SSH

The application generates a 2048-bit RSA client private key and CSR locally,
using SHA-256 for the request signature
(`../amnezia-client/client/core/configurators/openVpnConfigurator.cpp:238-325`).
The private key therefore does not need to be generated on or downloaded from
the server.

It then:

1. uploads only the CSR to
   `/opt/amnezia/openvpn/clients/<random-id>.req`;
2. runs `easyrsa import-req` and `easyrsa sign-req client` inside the container;
3. reads the CA certificate, signed client certificate, and `tls-auth` key over
   SSH; and
4. inserts those values plus the locally held private key into the embedded
   `.ovpn` template.

This path is implemented in
`../amnezia-client/client/core/configurators/openVpnConfigurator.cpp:41-81`,
`84-149`, and `218-235`. The profile directs traffic to the SSH host name on
the OpenVPN port and, by default, redirects the gateway and configures two DNS
servers
(`../amnezia-client/client/server_scripts/openvpn/template.ovpn:1-37`).

### Client revocation

Later SSH administration lists issued certificates under the Easy-RSA PKI.
Revocation runs `easyrsa revoke`, regenerates the CRL, and copies it into the
active location
(`../amnezia-client/client/core/controllers/selfhosted/usersController.cpp:145-183`,
`492-529`).

## WireGuard

### Container build and runtime

WireGuard is also built from `alpine:3.15`, with `wireguard-tools`, curl, and
`dumb-init`
(`../amnezia-client/client/server_scripts/wireguard/Dockerfile:1-11`).

The container is privileged, adds `NET_ADMIN` and `SYS_MODULE`, bind-mounts
`/lib/modules`, publishes the selected UDP port, enables
`net.ipv4.conf.all.src_valid_mark`, and joins the shared DNS bridge
(`../amnezia-client/client/server_scripts/wireguard/run_container.sh:1-17`).

### Server key generation

The in-container configuration script uses:

- `wg genkey` for a server private key;
- `wg pubkey` for its public key; and
- `wg genpsk` for a preshared key.

It writes those values as files and creates `wg0.conf` with the server private
key, subnet address, and listener port
(`../amnezia-client/client/server_scripts/wireguard/configure_container.sh:1-17`).

Defaults are `10.8.1.0/24` and UDP 51820
(`../amnezia-client/client/core/utils/constants/protocolConstants.h:132-160`).

### Interface and packet forwarding

The startup script uses `wg-quick down` followed by `wg-quick up`, then adds
rules accepting the `wg0` interface, forwarding its subnet to `eth0` or
`eth1`, and masquerading that subnet on both interfaces
(`../amnezia-client/client/server_scripts/wireguard/start.sh:8-28`).

### Client creation over SSH

The client generates an X25519 private/public key pair locally from
`RAND_priv_bytes`
(`../amnezia-client/client/core/configurators/wireguardConfigurator.cpp:49-78`).
It then:

1. reads all existing `AllowedIPs` entries from the server config;
2. chooses the next IPv4 address;
3. reads the server public key and server-generated PSK over SSH;
4. appends a new `[Peer]` block containing the client's public key, the PSK,
   and its `/32` address; and
5. runs `wg syncconf wg0 <(wg-quick strip <config>)` to apply the peer live.

See `wireguardConfigurator.cpp:101-206`.

The generated client config contains the local private key, server public key,
PSK, full-tunnel IPv4 and IPv6 `AllowedIPs`, endpoint, DNS, and a 25-second
keepalive
(`../amnezia-client/client/server_scripts/wireguard/template.conf:1-11`;
`wireguardConfigurator.cpp:209-275`).

The same server PSK is reused in every peer block, rather than generating a
unique PSK for each client. Client public/private key pairs remain unique.

The sequential IP allocation is based on the last parsed `AllowedIPs` entry and
does not provide transactional locking. Two concurrent administrators could
select the same address before either append becomes visible.

### Inspection and revocation

SSH executes `wg show all` to retrieve handshakes, transfer counts, and allowed
IPs. Revocation reads the entire config, removes the section containing the
client public key, uploads the rewritten file, and runs `wg syncconf`
(`../amnezia-client/client/core/controllers/selfhosted/usersController.cpp:74-143`,
`532-604`).

## AmneziaWG

AmneziaWG deliberately reuses most of the WireGuard client-management
implementation. `AwgConfigurator` subclasses `WireguardConfigurator`, converts
the generated WireGuard-style result into AWG-specific client state, and adds
obfuscation parameters
(`../amnezia-client/client/core/configurators/awgConfigurator.cpp:14-108`).

### Two server generations

The source supports:

- `Awg2` / `amnezia-awg2`, using the `awg` script folder, image
  `amneziavpn/amneziawg-go:latest`, `awg`, `awg-quick`, interface `awg0`, and
  `/opt/amnezia/awg/awg0.conf`; and
- legacy `Awg` / `amnezia-awg`, using `awg_legacy`, image
  `amneziavpn/amnezia-wg:latest`, `wg`, `wg-quick`, interface `wg0`, and
  `/opt/amnezia/awg/wg0.conf`.

The mapping is in
`../amnezia-client/client/core/utils/selfhosted/scriptsRegistry.cpp:28-36`;
the image and runtime differences are visible in
`../amnezia-client/client/server_scripts/awg/Dockerfile:1-11`,
`../amnezia-client/client/server_scripts/awg_legacy/Dockerfile:1-11`,
and the two startup scripts.

Both base images use mutable `latest` tags. A reinstall can therefore build
different software without any source change in the desktop client.

### Obfuscation parameters

Before installation, `AwgInstaller` generates randomized packet-junk sizes and
magic headers. AWG 2 uses four ordered numeric ranges for its magic headers;
legacy AWG uses four distinct scalar values. Both receive Jc/Jmin/Jmax, S1/S2,
H1-H4, and special-junk defaults. AWG 2 additionally receives S3 and S4
(`../amnezia-client/client/core/installers/awgInstaller.cpp:28-134`).

The generated server config includes these fields along with the WireGuard-like
private key, address, and listen port
(`../amnezia-client/client/server_scripts/awg/configure_container.sh:1-33`;
`../amnezia-client/client/server_scripts/awg_legacy/configure_container.sh:1-31`).
The client template mirrors the same obfuscation settings so both sides agree
(`../amnezia-client/client/server_scripts/awg/template.conf:1-27`).

The runtime permissions and networking are effectively identical to
WireGuard: privileged container, host module mount, UDP publish, DNS bridge,
interface acceptance/forwarding, and masquerading
(`../amnezia-client/client/server_scripts/awg/run_container.sh:1-17`;
`../amnezia-client/client/server_scripts/awg/start.sh:8-28`).

### Client creation and revocation

Client key generation, IP allocation, server key/PSK retrieval, peer append,
and live `syncconf` are the WireGuard path. The command and interface change to
`awg`/`awg0` for AWG 2; legacy AWG uses `wg`/`wg0`
(`../amnezia-client/client/core/configurators/wireguardConfigurator.cpp:124-206`).

Inspection and revocation make the same distinction
(`../amnezia-client/client/core/controllers/selfhosted/usersController.cpp:88-94`,
`541-600`).

As with WireGuard, every peer receives the same server-generated PSK.

## IKEv2/IPsec

### Container build and fixed ports

The IKEv2 container is built from the mutable image
`amneziavpn/ipsec-server:latest`
(`../amnezia-client/client/server_scripts/ipsec/Dockerfile:1-4`).
It is launched privileged, publishes UDP 500 and 4500, restarts always, and
joins the DNS bridge
(`../amnezia-client/client/server_scripts/ipsec/run_container.sh:1-9`).

Unlike the other main protocols, the UI does not expose an IKEv2 listener port;
the port utility returns `-1`, and container utilities treat 500 and 4500 as
fixed (`../amnezia-client/client/core/protocols/protocolUtils.cpp:120-135`;
`../amnezia-client/client/core/utils/containers/containerUtils.cpp:311-316`).

There is no specialized IKEv2 installer class in
`InstallController::createInstaller()`. It uses the generic base configuration,
while `Ikev2Configurator` supplies client provisioning
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:1008-1023`;
`../amnezia-client/client/core/installers/installerBase.cpp:108-112`).

### What the server script actually configures

The large `configure_container.sh` configures more than certificate-based
IKEv2:

- a shared IPsec connection profile;
- optional L2TP-PSK;
- optional IPsec XAuth-PSK;
- xl2tpd and PPP options;
- IKEv2 certificate authentication;
- per-mode address pools;
- IP forwarding, redirect/rp-filter settings, NAT, forwarding filters, and
  MSS adjustment.

The client always substitutes:

- `IPSEC_VPN_DISABLE_IKEV2=no`;
- `IPSEC_VPN_DISABLE_L2TP=no`; and
- `IPSEC_VPN_DISABLE_XAUTH=no`.

Those defaults are generated in
`../amnezia-client/client/core/utils/selfhosted/scriptsRegistry.cpp:157-168`.
The corresponding server branches are in
`../amnezia-client/client/server_scripts/ipsec/configure_container.sh:22-83`
and `208-259`.

The script creates empty secret/password files with mode 0600, but the
AmneziaVPN client workflow shown here does not populate L2TP or XAuth user
credentials. The generated client profile is IKEv2 certificate-based. Thus the
legacy modes are enabled in server configuration, but they are not the primary
working client path established by this code.

### Cryptography and identity

The script creates:

- a self-signed 3072-bit RSA `"IKEv2 VPN CA"` valid for 120 months;
- a 3072-bit RSA server certificate named after the server IP/host value,
  including IP and DNS SAN entries; and
- an IKEv2 connection requiring client certificates from the same CA.

See `ipsec/configure_container.sh:208-254`.

The proposal lists include AES-GCM and SHA-2 options, but also AES/SHA-1
combinations for IKE and phase 2
(`ipsec/configure_container.sh:43-44`, `248-249`). This is broader and weaker
than a modern-only policy.

The Apple profile uses DH group 14, AES-256/SHA-256 for IKE, AES-128-GCM for
the child SA, but explicitly disables certificate revocation checking and PFS
in the profile
(`../amnezia-client/client/server_scripts/ipsec/mobileconfig.plist:8-39`).

### Client certificate generation over SSH

For each administrative client, the configurator:

1. generates a random 16-character client ID;
2. runs `certutil` inside the container to create a 3072-bit RSA certificate
   with client and server authentication EKUs;
3. exports it with `pk12util` to a `.p12` whose password is the empty string;
4. reads the PKCS#12 and CA certificate bytes over SSH; and
5. stores the client PKCS#12 as base64 in the generated local configuration.

See `../amnezia-client/client/core/configurators/ikev2Configurator.cpp:24-55`
and `58-104`.

The private key is generated in the remote container and exported over the SSH
channel as part of the passwordless PKCS#12. This differs from OpenVPN,
WireGuard, and AWG, whose client private keys are generated locally.

The client-management controller has explicit listing/revocation cases for
OpenVPN, WireGuard/AWG, and Xray, but no IKEv2 case
(`../amnezia-client/client/core/controllers/selfhosted/usersController.cpp:731-750`).
Certificate lifecycle management for IKEv2 is therefore less complete in this
path.

## Xray/VLESS

### Initial image and bootstrap

Xray starts from `alpine:3.15`. The Dockerfile pins the Xray release string to
`v25.8.3`, but downloads its ZIP directly from GitHub with `curl` and performs
no checksum or signature validation
(`../amnezia-client/client/server_scripts/xray/Dockerfile:1-17`).

The container is privileged, adds `NET_ADMIN`, publishes the selected TCP port,
joins the DNS bridge, and creates a TUN device
(`../amnezia-client/client/server_scripts/xray/run_container.sh:1-16`).

The initial configuration script:

- generates a VLESS UUID;
- generates an 8-byte Reality short ID;
- generates an X25519 Reality key pair;
- writes the public/private/short-ID values to files; and
- creates a VLESS inbound with `xtls-rprx-vision`, raw TCP, Reality, and a
  camouflage destination/SNI.

See `../amnezia-client/client/server_scripts/xray/configure_container.sh:1-65`.
Defaults are TCP 443, `www.googletagmanager.com`, Reality, raw transport,
Chrome fingerprint, and `xtls-rprx-vision`
(`../amnezia-client/client/core/utils/constants/protocolConstants.h:49-68`).

### Advanced server configuration is applied later over SSH

The bootstrap JSON is not the end of Xray provisioning. When generating the
administrator profile, `XrayConfigurator` reads the current server JSON,
preserves Reality private material, merges configured stream settings, appends
a new UUID client, uploads the rewritten JSON, and restarts the container
(`../amnezia-client/client/core/configurators/xrayConfigurator.cpp:223-363`).

Supported modelled stream options include:

- raw TCP, XHTTP, and mKCP transport;
- Reality or TLS security;
- SNI, ALPN, and uTLS fingerprint;
- XHTTP mode, host/path/headers, upload method and placement;
- XHTTP ranges, padding, and xmux tuning; and
- mKCP interval, capacities, buffers, and congestion setting.

The JSON construction is in
`../amnezia-client/client/core/configurators/xrayConfigurator.cpp:457-623`.

For Reality, the configurator reads the public key and short ID from the
container, retrying each file up to three times, and embeds those values in the
client config. The private Reality key remains server-side
(`xrayConfigurator.cpp:165-193`, `382-454`).

The generated local Xray config exposes a SOCKS listener at
`127.0.0.1:10808`, then sends VLESS to the server
(`xrayConfigurator.cpp:408-454`). This local SOCKS listener is part of how the
desktop client feeds traffic into Xray; it is not the SSH transport.

Third-party/native Xray profiles are a special case: when already marked as a
third-party config with a client profile, `createConfig()` returns it without
server SSH (`xrayConfigurator.cpp:626-660`).

### Container firewall mismatch for custom ports

Xray's startup script accepts loopback, established traffic, ICMP, and TCP
ports 80 and 443, then changes the container's IPv4 INPUT policy to DROP. It
does the analogous minimal IPv6 filtering and starts Xray
(`../amnezia-client/client/server_scripts/xray/start.sh:8-24`).

The application separately declares Xray's default port changeable
(`../amnezia-client/client/core/protocols/protocolUtils.cpp:139-155`) and
publishes `$XRAY_SERVER_PORT` to the same container port. If a user selects a
TCP port other than 80 or 443, Docker publishes it, but this startup firewall
does not allow it. The likely result is an installed-looking but unreachable
Xray listener.

### Client listing and revocation

SSH reads `server.json`, parses the first inbound's client array, and maintains
a separate `clientsTable` metadata file. Revocation removes the matching UUID,
uploads both updated files, and restarts the container
(`../amnezia-client/client/core/controllers/selfhosted/usersController.cpp:231-291`,
`607-709`).

## Discovery, updates, and repeat runs

### Discovering containers already on a server

Before a new server record is added, the client runs:

```sh
sudo docker ps --format '{{.Names}} {{.Ports}}'
```

It recognizes names matching `amnezia-*`, extracts one published port and
transport, creates a base config, and asks the protocol-specific installer to
read server settings back from the container
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:1428-1507`).

OpenVPN reads and parses `server.conf`; WireGuard/AWG read their interface
configs; Xray parses the first JSON inbound. The application then generates a
new administrator client for supported VPN containers it did not already know
about (`installController.cpp:1079-1126`).

This discovery is convention-based. Renamed containers, containers without a
published port in the expected format, host-networked instances, or materially
different internal layouts will not be reconstructed reliably.

### Update versus reinstall

Server-setting changes can either:

- rerun configuration and startup in the existing container; or
- invoke the full `setupContainer(..., isUpdate=true)` replacement path.

OpenVPN, WireGuard, AWG, and Xray server-setting comparisons determine whether
reinstallation is required
(`../amnezia-client/client/core/controllers/selfhosted/installController.cpp:660-704`).

The distinction matters because full setup removes the container and local
image before rebuilding. Protocol configuration scripts create fresh server
keys, PSKs, CAs, and UUIDs. Without a persistent host volume for these VPN
containers, a full reinstall rotates identity and invalidates previously issued
profiles. The controller clears only its cached administrative profile after a
reinstall (`installController.cpp:193-223`); externally exported client
profiles cannot be automatically updated.

### Rerun safety

The workflow contains several useful rerun guards:

- package installation checks for each prerequisite;
- the shared Docker network is created only when absent;
- host firewall rules use `iptables -C` before append;
- port checks precede new installs;
- already running named containers are discovered; and
- startup uses `down`/kill before bringing a daemon back up.

It is not fully idempotent:

- reinstall is intentionally destructive and regenerates identities;
- old-container removal errors are ignored;
- command exit codes are ignored at the SSH layer;
- container temporary files can remain;
- Xray server rewrites and WireGuard peer appends are read-modify-write
  operations without concurrency control; and
- a partial failure can leave packages, Docker networks, build directories,
  images, containers, or configuration from earlier stages.

## Persistent credentials and secret handling

The self-hosted administrator record serializes the SSH host, user, secret
(field name `password`, even when it contains a private key), and port into the
server JSON
(`../amnezia-client/client/core/models/selfhosted/selfHostedAdminServerConfig.cpp:28-35`,
`83-124`).

`SecureServersRepository` stores the complete server list under
`Servers/serversList`
(`../amnezia-client/client/core/repositories/secureServersRepository.cpp:142-179`).
`SecureQSettings` marks that key for AES-256-CBC encryption and normally stores
the key and IV through Qt Keychain
(`../amnezia-client/client/secureQSettings.cpp:23-37`, `84-101`, `180-195`,
`210-263`).

There are important platform qualifications:

- encryption is enabled by default and the application constructs
  `SecureQSettings` with that default
  (`../amnezia-client/client/secureQSettings.h:16-18`;
  `../amnezia-client/client/amneziaApplication.cpp:58`);
- desktop Linux explicitly returns `false` from `encryptionRequired()` because
  Qt Keychain is considered unreliable, so the server list—including the SSH
  password or decrypted private key—is stored without this encryption layer
  (`../amnezia-client/client/secureQSettings.cpp:198-207`);
- the whole server-list value is cached decrypted in process memory after
  access (`secureQSettings.cpp:40-81`); and
- the AES-CBC storage construction shown here does not add an authentication
  tag in `SecureQSettings`, so confidentiality and tamper detection are not
  equivalent to a modern authenticated-encryption format
  (`../amnezia-client/common/crypto/cryptoUtils.cpp:39-121`).

Generated client profiles also contain sensitive material:

- OpenVPN embeds its locally generated private key;
- WireGuard/AWG embed the client private key and shared PSK;
- IKEv2 embeds a passwordless PKCS#12 containing its private key; and
- Xray embeds client UUID and Reality connection material.

Those profiles live inside the same stored server configuration and inherit
the same platform storage properties.

## Failure handling and observability

The implementation exposes many specific `ErrorCode` values for SSH, package
manager, Docker, port, container, key, and configuration failures. Callers
generally stop a provisioning stage when such a value is returned. That is a
good fail-fast shape at the controller level.

Its effectiveness is limited by the transport abstraction:

- SSH connection/authentication and SCP I/O failures propagate;
- callback-detected failures propagate;
- a selected set of output strings are converted to explicit errors;
- ordinary non-zero remote exit status does not propagate;
- firewall setup is explicitly ignored by the main pipeline; and
- several cleanup calls intentionally ignore errors.

Docker logging is disabled for all five VPN containers with
`--log-driver none`. Protocol daemons also use low/error-only verbosity in
places. That reduces disk consumption and incidental secret exposure, but it
also makes post-failure diagnosis dependent on SSH inspection of live
containers and files.

The application logs each logical command passed to `runScript()`
(`../amnezia-client/client/core/utils/selfhosted/sshSession.cpp:80-86`).
Most large secret-bearing configs are uploaded as files instead of appearing
directly in the command, but any secret substituted into a one-line command
would be exposed to debug logging.

## Security assessment

### Critical trust-boundary issue: no SSH host-key verification

SSH encryption without host authentication does not protect provisioning
against an active intermediary. Because this channel carries a reusable server
password/private key, root-capable commands, VPN server identity, and client
credentials, host-key verification should be treated as the highest-priority
design gap.

A robust design would persist a verified host-key fingerprint per server,
support explicit first-use confirmation, reject changed keys by default, and
provide a deliberate key-rotation flow.

### High reliability issue: remote exit status is discarded

The current success criterion is mainly “libssh transported and closed the
channel without its own error,” not “the remote process exited zero.” This can
create false-positive installs and partial state. The wrapper should retrieve
and return the channel exit status and exit signal, while preserving captured
stdout/stderr for actionable diagnostics.

### High-impact privilege and supply-chain exposure

Provisioning intentionally grants broad root-equivalent authority:

- passwordless sudo on the host;
- Docker daemon control;
- privileged containers;
- host kernel module access for WG/AWG;
- network/firewall mutation; and
- fresh remote image/package downloads.

Mutable `latest` images and an unchecked Xray ZIP mean the executable server
payload is not reproducibly bound to the desktop client's reviewed source.
Digest-pinned base images, checksum/signature verification, and narrower
container capabilities would substantially reduce this exposure.

### Host-wide side effects

The application changes the host, not just an isolated container:

- installs packages;
- enables and starts Docker;
- creates `/opt/amnezia`;
- creates a bridge and interface;
- enables IPv4 forwarding;
- drops ping to the entire host;
- changes global TCP tuning; and
- modifies host forwarding chains.

These actions are visible in the scripts, but there is no transaction or
automatic rollback. Removing containers does not restore packages or sysctls,
and the single-container removal path does not remove the shared network or
host firewall rules.

### Protocol-specific issues

- **OpenVPN:** permits TLS 1.2 rather than requiring TLS 1.3; uses a 2048-bit
  RSA client key; allows duplicate CNs; and accepts arbitrary additional
  client/server configuration text. Defaults otherwise select AES-256-GCM,
  SHA-512, certificate authentication, CRL checking, and `tls-auth`.
- **WireGuard/AWG:** unique client key pairs are strong, but one PSK is shared
  by all peers, IP allocation is not concurrency-safe, and the privileged
  container has host module access.
- **IKEv2/IPsec:** uses 3072-bit RSA certificates but includes SHA-1 proposals,
  creates client PKCS#12 files with an empty password, enables legacy
  L2TP/XAuth branches, and lacks equivalent in-app revocation management.
- **Xray:** Reality private key stays server-side, but the downloaded executable
  is not integrity-checked; custom ports conflict with the startup firewall;
  and TLS mode construction in `buildStreamSettings()` models client-side SNI,
  ALPN, and fingerprint but does not show server certificate/key installation
  in this provisioning path. Reality is the coherent default server setup.

### Input and templating boundary

Script variables are replaced with raw strings. Host names, protocol ports,
sites/SNI values, additional OpenVPN configuration, and advanced Xray fields
eventually enter shell scripts, JSON, or configuration here-documents. UI
models constrain many ordinary choices, but the generic replacement function
does not quote or validate by context. Imported or manipulated configurations
could therefore produce syntax breakage or command/config injection.

Context-aware serialization is preferable:

- construct JSON with `QJsonObject`, never text replacement;
- validate ports as integers and host names/IPs with dedicated parsers;
- shell-quote every argument or avoid shell interpolation;
- model OpenVPN directives as validated fields when possible; and
- deliberately label any raw expert configuration as trusted code.

## Practical lifecycle summary

For a normal first-time self-hosted setup, the complete sequence is:

1. User enters server address, SSH user, and password/private key.
2. App optionally decrypts the private key locally.
3. App connects with libssh and runs `uname -a`.
4. App checks passwordless sudo and package-manager availability.
5. App waits for package-manager locks.
6. App installs missing tools and Docker.
7. App checks the VPN listener port(s).
8. App creates `/opt/amnezia/<container>` and the shared bridge.
9. App removes any same-named old container/image.
10. App uploads the embedded Dockerfile.
11. Server builds the image with `--no-cache --pull`.
12. App runs a privileged named container and publishes VPN ports.
13. App uploads and executes a generated protocol configuration script.
14. App applies host forwarding/firewall/network tuning.
15. App uploads and launches the real container startup script.
16. App creates an administrator VPN identity.
17. App reads the necessary server public material and/or client credential
    back over SSH.
18. App assembles and saves a local client profile.
19. App records the SSH credentials and container/client state for future
    administration.

After that, SSH is used for configuration and lifecycle operations, while VPN
packets use the protocol's published listener directly.

## Conclusions

AmneziaVPN implements a client-driven “bring your own Linux server” appliance
builder. Its distinctive choice is to avoid requiring a preinstalled
Amnezia-specific management daemon: an ordinary SSH service plus
root/passwordless-sudo access is enough for the desktop client to turn the host
into a Docker-based multi-protocol VPN server.

That choice makes the system portable across several Linux package managers
and keeps protocol logic inspectable in bundled scripts. It also puts enormous
trust in the SSH session and the desktop client's error interpretation. The
most important improvements are therefore not new protocols; they are:

1. authenticate the SSH server with persisted host keys;
2. treat remote exit status as authoritative and preserve structured failure
   output;
3. pin and verify every downloaded server artifact;
4. reduce container and host privileges;
5. make credential storage consistently authenticated and encrypted across
   platforms;
6. make firewall behavior protocol/port-aware and validate its success; and
7. make destructive reinstalls, key rotation, and rollback consequences
   explicit to the user.

With those changes, the existing architecture could retain its convenient
SSH-based control plane while becoming substantially more deterministic,
auditable, and resistant to active attack.
