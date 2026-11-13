# Security model

VPNCTL requires verified SSH host keys before authentication. A host key change blocks access until the user verifies and explicitly approves the new fingerprint. The appliance UUID is a remote ownership identifier, not a trust anchor; duplicated UUIDs on cloned hosts are detected separately. The on-demand `vam-server` helper runs only for a request and has no persistent network listener.

## Secret ownership

| Material | Client | Appliance |
| --- | --- | --- |
| SSH key and passphrase | Local SSH/native credential storage | Never copied by VPNCTL |
| WG/AWG peer private key | Native credential store on creating client | Never copied |
| WG/AWG server-required peer PSK | Optional local migration source only | Protected file in control store, resolved by helper |
| WG/AWG server private key | Never copied | Persistent runtime tree and protected recovery backup |
| OpenVPN/IKEv2 client private key | Native credential store on creating client | Never copied |
| Public client CSR | Local native store and explicit signing request | Stored in protected runtime request area |
| CA/server private keys, certificates and CRLs | No private CA/server key | Persistent runtime tree and recovery backup |
| Complete exported client configuration | Written to explicit client path only | Not stored as a public manifest |

Routine discovery, previews, deployment plans, health, errors and logs carry only public or redacted data. Scoped WG/AWG PSK retrieval is available only for explicit selected-peer export; the client first checks that it has the matching private key. Explicit OpenVPN/IKEv2 export retrieves the selected issued certificate and required CA/TLS material, verifies that its public key matches the local CSR, and renders the final profile locally. A second client without a peer private key may manage public configuration but cannot claim a complete export.

Local SQLite contains connection profiles, credential references, drafts, public caches, preferences and legacy bookkeeping. It is not authoritative desired state. Native credential storage uses the OS keyring with no plaintext fallback. The remote public JSON manifest contains no client private-key reference. Newly referenced remote PSKs are written and synchronized before the manifest pointer is committed. Retained desired generations and backups retain referenced secrets; routine garbage collection is disabled.

The helper validates request size, schema and protocol, UUID ownership, expected revision, paths, symlinks, configuration, listener and allocation conflicts. It serializes mutations with a filesystem lock and commits immutable generations with atomic pointer replacement and directory synchronization. Unsupported client versions refuse writes before initializing control state. Exchange files are owner restricted and SFTP is used only for these protected files. The helper never accepts direct SFTP manifest writes.

OpenVPN and IKEv2 issue from verified public CSRs using the retained remote CA. Revocation updates CRLs and desired peer state, and deployment applies the new state. The helper refuses certificate export for a revoked peer. Deployment rollback includes persistent cryptographic state and is rejected if it would invalidate newer saved identities. Disaster-recovery bundles contain PSKs and server private keys; restrict access and retain an independent protected copy before destructive recovery.

CoreDNS forwards public queries over DNS-over-TLS with certificate-name verification. OpenVPN uses TLS 1.3 minimum and current AEAD ciphers. IKEv2 uses the existing strongSwan certificate workflow. No backend requires an unauthenticated VPNCTL management port or Docker socket inside its container. Xray is retired from normal management; legacy recovery remains read-only.

## Operational limits

The helper is currently installed or upgraded through host administration rather than an automated VPNCTL bootstrap. A future manifest schema needs an explicit validated converter and recovery backup; this release supports schema 1 only. Pending runtime operations can block new changes and require request-ID reconciliation or operator recovery; do not clear the marker blindly. See [deployment and recovery](docs/deployment.md) and [remote format](docs/remote-format.md).

## Desktop configuration retrieval

Configuration text copying is an explicit, selected-device native command. Rust
renders the same complete credential-bearing artifact used by file export and
writes it directly to the OS clipboard; the frontend receives only success or a
safe error. Generic frontend clipboard permissions are not enabled. IKEv2 binary
PKCS#12 bundles cannot be copied as text. Clipboard contents may remain in OS
history, sync to other devices through OS features, or be read by other local
applications; VPNCTL does not promise clipboard erasure.

WireGuard and AmneziaWG QR images are generated locally in Rust only after an
explicit request. The image is held in frontend memory while its dialog is open
and cleared on close, navigation, or configuration changes. Late responses cannot
reopen it. No QR generation service, temporary QR file, or configuration-bearing
navigation URL is used. Clearing UI references is not a guarantee of immediate
memory erasure by the webview. Session activity stores curated public operation
summaries, never exported configurations, credential material, or raw errors.

## Blocking source trust and scheduled execution

Blocking sources are server-owned network inputs, not instructions. Downloads
accept only HTTP/HTTPS URLs without embedded credentials or fragments. HTTPS
uses certificate validation and TLS 1.2 or newer; HTTP contents can be altered in
transit and the interface warns about this. The helper does not use environment
proxies. It resolves and validates every initial/redirect destination, then pins
those addresses for the connection while preserving hostname certificate checks.
Loopback, link-local, unspecified, multicast, shared-address metadata ranges,
IPv4-mapped equivalents, and the EC2 IPv6 metadata endpoint are rejected.
Private LAN sources are supported intentionally; administrators should trust
both the source operator and the reachable LAN service. HTTPS-to-HTTP redirects
and more than five redirects are rejected. Download errors omit raw response
bodies and URL-bearing transport diagnostics.

Limits are 30 seconds and 20 MiB per source, four simultaneous downloads,
64 sources per instance, one million unique domains, and 64 MiB of combined
domain names. Domain parsing stops at its unique-domain limit. Existing runtime
files must be regular files within the 256 MiB recovery limit. Downloaded data is
never executed. Datasets are protected and sharded, with unchanged downloads
reusing their previous dataset; old changed datasets and operation receipts are
retained for recovery, so monitor control-store disk usage.

The optional `vpnctl-blocking.timer` starts a root, oneshot helper invocation
without an RPC exchange or network listener. Its owned unit files are clearly
marked; unknown existing units are not overwritten. The service restricts
filesystem writes to VPNCTL control/runtime roots, disables new privileges and
capabilities, and isolates devices, home directories, and temporary files. It
still needs the existing privileged Docker access to verify instance DNS. DNS
probes use an empty, dedicated Docker client configuration under the control
root, so they do not need access to home directories or registry credentials. Only
an explicitly saved policy enables a source or schedule; archived instances are
skipped. Disabling a schedule changes that instance's policy; the shared timer
may remain installed to serve other instances.
