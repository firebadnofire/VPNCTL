# AGENTS.md

Repository-wide guidance for coding agents working on **VPNCTL**. The repository may still use the historical name `dnswg`; do not mistake that for a different project.

## 1. Product contract and decision precedence

**VPNCTL is a user-operated, cross-platform controller for VPN appliances.** It is not the appliance, not a continuously running agent on the server, and not a generative or autonomous configuration engine. A desktop app or CLI connects to a server, inspects what is actually there, and helps the user make deliberate changes. The authoritative configurations live **on the server**, not in the desktop application's database.

The most important design goal is: **make deploying and maintaining a VPN straightforward without hiding disagreements or taking ownership of resources VPNCTL cannot prove it owns.** A clean server should be easy. A previously managed, altered, cloned, or partially failed server must be handled accurately, not optimistically.

When instructions conflict, prefer, in order:

1. The user's explicit instructions for the current task.
2. The user's more recent VPNCTL design decisions, including the decisions recorded in this file.
3. Verified current implementation behavior for claims about what already works.
4. Current architecture, security, deployment, and testing documentation.
5. Older implementation notes, comments, prototypes, and historical behavior.

Do not silently implement an older documented behavior that contradicts the product decisions here. Do not label a proposed feature as shipped merely because it appears in a plan. If source code, documentation, and this file disagree, inspect the code, identify the difference, implement only the requested change, and report what remains inconsistent.

**Explicitly resolved conflict:** Older `docs/remote-format.md` language describes automatic deployment after client enrollment. The current intended user-facing flow is **Add Device saves to the server; Review deployment / Preview / Deploy is a distinct explicit step**. Keep optimistic concurrency checks for both. Do not silently start or redeploy a VPN because a device was added, a configuration was saved, or a DNS source refreshed.

## 2. Design philosophy

- **The software is an agent for the user, not a resident server agent.** It can inspect and reconcile remote state, but it must not invent desired state, silently adopt unexpected configuration, or make generative decisions for the user.
- **Cross-installation continuity matters.** If a second VPNCTL installation connects to a server managed by the first, it should discover the server's existing instances, peers, configuration, revisions, operations, and recoverable history. No desktop installation gets exclusive ownership of an appliance merely because it created it.
- **Remote authority, local convenience.** SSH connection details, credentials, drafts, public caches, and preferences belong locally. Actual VPN instance definitions and operation history belong to the appliance.
- **Simple normal path, explicit exceptional path.** The UI should show a user's goal first (connect, add a VPN, add a device, review and deploy, export a configuration). Expose revision conflicts, interrupted operations, or deployment drift when they matter, with understandable explanations and optional technical detail.
- **Never sacrifice safety to simplify the interface.** A two-click flow is good; a two-click flow that silently clobbers a server is not.
- **Do not add inert UI decoration.** Avoid fictitious metrics, dashboards with no real data source, duplicate status badges, decorative diagrams, fake buttons, and irrelevant internal terminology. An HTML-only prototype may mock actions, but production UI must be backed by real commands and meaningful state.
- **Favor deterministic, inspectable behavior.** Backends, command planning, migration, reconciliation, and deployment must be reviewable and testable. Do not introduce opaque heuristics where explicit validation is possible.

## 3. Architecture and responsibility boundaries

The intended shape is:

```text
Svelte UI -> Tauri commands --------+
                                   +-> Rust ApplicationService -> verified SSH/SFTP
vam-dev CLI ------------------------+                          -> on-demand vam-server
                                      |                             |
                                      +-> local SQLite and          +-> authoritative manifests
                                          native credential store   +-> protected server secrets
                                                                    +-> render/deploy/health/recovery
```

- **Svelte** owns presentation, interaction, local UI state, tooltips, confirmation dialogs, and understandable status messages. It does not own authoritative configuration, cryptographic operations, server-side destructive decisions, or secret-bearing export construction.
- **Tauri/Rust ApplicationService** orchestrates client operations, local state, authentication, reconciliation, secure exports, and desktop/CLI shared behavior. Prefer one shared implementation over a second UI-only implementation.
- **`vam-dev`** is a real client of that same service, not a separate authority or bypass for safety checks.
- **`vam-server`** is the Linux-side authority. It validates and commits manifests, coordinates instance mutations, manages server-owned secrets, renders backends, performs deployments and restores, and records durable remote outcomes. It is invoked per request through verified SSH; do not turn it into an always-on management listener or require a new unauthenticated management port.
- **Docker Engine and Compose v2** are the appliance deployment target. Do not put the Docker socket inside VPN containers as a workaround.
- Keep backend-specific rendering behind consistent interfaces. The current supported backends are **WireGuard, AmneziaWG, OpenVPN, and IKEv2**. **Xray is retired** from normal creation and management, with read-only legacy recovery where needed. SoftEther has been discussed as a possible future backend, not an existing requirement or shipped feature.

Known remote locations (verify in code before changing their use):

```text
/usr/local/libexec/vam-server
/var/lib/vpn-appliance-manager/control/
  appliance-id
  instances/<uuid>/current.json
  instances/<uuid>/generations/<revision>.json
  instances/<uuid>/secrets/<uuid>
  instances/<uuid>/runtime/
/var/lib/vpn-appliance-manager/recovery/
/opt/vpn-appliance-manager/instances/<uuid>/
/opt/vpn-appliance-manager/staging/
/opt/vpn-appliance-manager/backups/<uuid>/
/opt/vpn-appliance-manager/trash/
```

The control store is deliberately outside the runtime activation tree. Never make rollback, Compose replacement, or instance archival overwrite committed desired generations.

Installing or upgrading the remote helper is a separately trusted host-administration operation. Do not imply that simply updating the desktop updates `/usr/local/libexec/vam-server`.

## 4. Server authority, reconciliation, and concurrency

Treat these as different, observable things:

1. **Local draft:** unsaved edits on this installation.
2. **Saved desired state:** authoritative committed server manifest and revision.
3. **Deployed state:** the runtime revision/configuration last successfully activated.
4. **Observed state/health:** what is actually running, including possible out-of-band changes or unknown status.

Do not collapse those into one `configured` boolean. A matching saved and deployed revision is not proof that the service is healthy. An unknown deployment observation is **unknown**, not automatically `needs deployment`.

Required behavior:

- Every connection begins with SSH host-key verification, protocol/capability negotiation, and authoritative discovery before writes. The remote appliance UUID is an ownership identifier, **not** a substitute for SSH host-key trust. Detect duplicate appliance identities on cloned hosts.
- A newly installed desktop must be able to discover an existing appliance without a copy of the other desktop's SQLite database. It may manage public configuration without possessing another client's private export keys.
- Successful server discovery refreshes the public local cache and records synchronization time. A connection failure, unsupported version, corrupt instance, or partial discovery must **never** appear as an empty server. Show partial per-instance errors without erasing readable instances.
- Cached/offline views are visibly stale and read-only for authoritative mutations. Local drafts may remain for later explicit reconciliation.
- Compare each mutation against the **current remote revision**. Use expected-revision checks, server-side locks, stable instance/peer UUIDs, and request IDs. Do not let an old client overwrite another client's saved work.
- Use immutable generations and the atomic `current.json` pointer, with proper synchronization of secrets, generation data, and directories. The helper is the sole writer of authoritative manifests; SFTP must not become a manifest-write API.
- Bind deployment previews to the saved desired revision **and** observed runtime state/hash. Recheck immediately before deployment. Reject stale previews rather than trying to guess intent.
- An SSH timeout after mutation is **not** proof that the mutation failed. Reconcile by original request ID, distinguish committed/uncommitted/unresolved, and do not retry an uncertain mutation with a new ID.
- A durable pending/unresolved operation must block conflicting mutations until reconciled or explicitly recovered. Never clear markers merely to get the UI moving again.
- On a divergent draft, show the original baseline, current local edits, and newest server values. Let the user explicitly discard/reload or deliberately recreate their edits against current state. Do not auto-merge unsafe changes or silently pick the local copy.
- Do not write new desired revisions during mere discovery, login, browsing, refresh, or passive health inspection.

**Cross-client handoff is reconstruction from server authority, not synchronization between laptops.** The new client discovers and understands the remote work, while private credential ownership remains local.

## 5. Saving, deployment, and recovery

- **Save to Server** advances desired configuration only. It does not change containers, routing, firewall, DNS deployment, or listening ports.
- **Review deployment / Preview / Deploy** shows redacted planned differences and warnings, then performs explicit revision-bound activation. Deployments stage, validate, back up, activate, check health, and compensate/roll back when possible.
- Keep user-visible health separate from configuration currency. Health observations need freshness and are invalidated by reconnects or relevant changes; do not display old `healthy` data as current.
- Deployment rollback restores the selected runtime tree and its persistent server identities while preserving newer desired generations. Reject restores that would invalidate more recent peers or cryptographic state.
- **Restore Desired Configuration** validates an older generation and commits it as a **new** desired revision; it does not deploy and does not rewrite history.
- **Archive instance** preserves historical/recovery information, including stopped runtime identity where applicable. Archived instances remain discoverable from Backups even when no active instances exist.
- **Restore archived instance** restores the same identity/keys and desired definition without automatically starting it. Starting or deploying is an explicit separate action. Never silently regenerate keys because an archive is missing or ambiguous.
- Whole-appliance disaster recovery must preserve both the control store and its active/retained runtime identities. Recovery bundles contain secrets; handle them as sensitive backups.
- Protocol version and schema incompatibility must refuse writes before touching authoritative storage. The documented baseline is protocol **2**, manifest schema **1**; check helper capabilities as well as protocol number (for example `instance_archives_v1`). No unreviewed automatic schema conversion.

## 6. Device identity, enrollment, export, and deletion

A **Device** in the UI is a **VPN client identity**, not hardware automatically detected on the network. Avoid implying that VPNCTL scans devices.

- Adding a device creates its credentials and server-side public identity, without automatically deploying it. Preserve local keys if activation later fails. Show the next explicit review/deploy step.
- The default **Add DNS record** option may register the device name in the instance's private DNS zone. A blank optional name means use the device name; advanced settings permit a custom name, and the user can disable DNS enrollment.
- Exports must re-read authoritative server configuration and require the matching locally held private key. Do not claim that another installation can reconstruct private keys it never owned.
- WireGuard and AmneziaWG support locally generated QR configurations; text copy is available for compatible text profiles. OpenVPN may use text/file output as supported; IKEv2 retains its binary PKCS#12 file workflow. Never advertise QR or text import for an incompatible format.
- Keep device **disable**, **revoke**, **remove/drop**, and **archive** semantics distinct. A revoked certificate does not become trusted again merely because its metadata is edited.

### Planned: Drop Device

The recent design calls for a scoped **Drop Device** action in Danger Zone. This is **a planned workflow unless code inspection proves it is implemented**. Do not confuse it with dropping a host or archiving an entire instance.

- Select a managed server/instance first, then a device from that instance, including disabled and revoked identities. Reset the device choice if the instance changes.
- Distinguish empty inventory, offline host, busy operation, and unresolved remote-operation state. Require confirmation naming the host, instance, and selected device.
- Re-read remote state and use fresh expected-revision/request-ID safeguards. Only remove the selected peer and DNS records explicitly linked to that peer (for example through `managed_by_device_id`); preserve unrelated user-created records, other devices, exported files, local private keys, and recovery history.
- For OpenVPN/IKEv2, revoke the device certificate through the existing server-authoritative workflow **before** deleting its managed metadata. If metadata removal fails after revocation, report **"Certificate revoked; device removal incomplete"** and support a safe retry. Do not mask this partial success as a full failure or success.
- Removing a managed identity/DNS record is a desired-state change; explain that deployment is still required to apply access changes to the running appliance.
- Prefer a scoped native helper operation, not ad hoc filesystem deletion or a broad instance delete disguised as device removal.

## 7. DNS and per-instance blocklists

DNS belongs to the managed **instance**, not to a desktop-only settings panel. Preserve clear ownership of generated vs. user-managed records.

The recent product plan also calls for **server-owned, per-instance DNS blocklists** with HTTP/HTTPS source URLs, enable/disable controls, manual refresh, and an **optional seven-day automatic refresh**. Treat this as a target design, not proof that every part has shipped.

- Keep source definitions, enabled state, applicable policy, and refresh metadata authoritative on the server. Two clients must see the same configuration. Do not silently transfer ownership into SQLite.
- Do not conflate a successful source download with a successful DNS deployment. Preserve explicit deployment semantics and report which version/content is currently active.
- Refresh should be transactional and failure-safe: validate content and source, cap bytes/time/domains, reject dangerous/invalid entries, and retain the previously valid blocklist when refresh fails. Report source-specific errors.
- Treat source URLs as untrusted network input. Account for redirects, SSRF to local/metadata addresses, DNS rebinding, oversized files, malformed encoding, and partial downloads. HTTP support is a product requirement, but distinguish it from HTTPS when communicating trust properties.
- The existing remote helper is on-demand, not a daemon. An automatic-refresh implementation must explicitly identify a reliable scheduler/trigger and its ownership; **do not quietly introduce a new always-on listener or pretend a timer runs when no process is running**.
- Changes must be scoped to the selected instance; no blocklist should unexpectedly affect unrelated VPN instances or the host's general DNS service.

## 8. Danger Zone and ownership-safe cleanup

Treat **local removal**, **remote archive**, **device removal**, **full drop**, and **factory reset** as separate operations, not different labels on one deletion command.

Current documented behavior:

- Local host removal and local Factory Reset remove active client-side profiles/caches/drafts/preferences within their scopes, while retaining recovery references, legacy/recovery VPN configurations, and native credential bindings. They do not SSH to the server.
- They do **not** delete user-managed SSH key files, exported client profiles, or generated client private keys; they are **not secure erasure**.
- Reconnecting requires fresh SSH trust verification and matching appliance identity. Local cleanup must not remove remote instances or claim they disappeared.
- Instance removal is archival/restorable with retained runtime identity and history, not an arbitrary `rm -rf` of appliance state.
- **Full drop / remote Factory Reset and recovery-archive orchestration are not implemented** in the supplied docs. Do not expose them as functioning actions or fall back to legacy removal when their capability is absent.

Longer-term remote cleanup design, if explicitly tasked:

- Make each operation's scope and consequences understandable before confirmation. Distinguish local-only cleanup from permanent remote removal, and offer a recovery archive before destructive server cleanup where supported.
- Use server-authoritative journals/receipts, reservations, locking, request-ID idempotency, and repeat-safe resume. Ensure a lost response never leaves the client guessing whether to repeat a destructive action.
- Delete only resources with **proven VPNCTL ownership**. Historical bare UFW/firewalld port rules and ambiguous `trash/removed-*` fragments are not sufficient evidence of ownership. Refuse or quarantine ambiguous cases instead of guessing.
- Never delete the whole managed root just because it is under a VPNCTL-related directory. Preserve unrelated containers, host services, firewall rules, other instance state, recovery material, and user data.
- Require real disposable-server deletion/recovery tests before enabling permanent cleanup. A disabled button is better than a destructive half-implementation.

## 9. Security and secrets

Security boundaries are product behavior, not an optional hardening pass.

- Require independently verified SSH host keys **before authentication**; host-key changes must block until explicitly approved. Appliance UUID equality must never bypass SSH trust.
- Use verified SSH/SFTP for restricted, bounded exchange files. Validate schema, protocol, caller, request identity, revisions, paths/symlinks, listener/port/subnet allocation, and filesystem ownership before mutation.
- Native OS credential stores hold client private keys and SSH passphrases. Do not introduce a plaintext fallback or serialize private-key references into public remote manifests.
- WireGuard/AmneziaWG **peer private keys remain on their creating client**. Appliance-required peer PSKs are protected on the server and returned only for explicit scoped export after proving the client owns the corresponding local private key.
- OpenVPN/IKEv2 **client private keys remain local**; only public CSRs are sent for signing. The appliance retains CA/server keys, issued public certificates, and CRLs. Certificate export is scoped and must match the requesting client's local key/CSR. Revoked peers cannot be exported as valid.
- Routine inventory, previews, plans, errors, logs, notifications, and Activity must be public/redacted. Do not log or store QR payloads, PKCS#12 data, full VPN profiles, private keys, PSKs, or raw secret-bearing responses.
- Build complete export artifacts in Rust, not in Svelte/JavaScript. Native clipboard copy is an explicit user command; acknowledge clipboard history/sync risk, and do not enable generic frontend clipboard access merely to simplify UI code.
- Render WireGuard/AmneziaWG QR codes locally after an explicit request, keep them only in view memory, clear references on close/navigation/config changes, and suppress stale async responses. No external QR service, plaintext temp image, or configuration-bearing URL. Do not promise instant zeroization of webview memory.
- Keep CoreDNS upstream TLS verification, strong backend TLS/cipher requirements, and protected deployment material. Do not add insecure fallback transports for convenience.

## 10. Desktop experience and copy

The old interface exposed too much of the internal state machine. Keep the state machine rigorous **inside the implementation**, but make the UI explain what a person can do next.

- Organize around **Servers/Connections**, **VPN instances**, **Devices**, **DNS/routing**, **Deployment**, **Backups**, and **Danger Zone**, rather than a wall of revisions, hashes, and diagnostic labels.
- Prefer clear actions such as **Add Device**, **Get Configuration**, **Save to Server**, **Review deployment**, **Check VPN health**, and **Review differences**. Avoid ambiguous labels such as an unexplained **State**; add concise tooltips and plain-language context.
- Normal cases should not demand that the user understand generations, receipts, expected revisions, or cryptographic identity. Conflicts, interrupted operations, and advanced diagnostics can expose those details as needed.
- Explain three different conditions accurately: **unsaved edits**, **saved but not deployed**, and **deployed but unhealthy/unknown**. Do not claim a healthy VPN just because revisions match.
- Temporary notifications should dismiss automatically but remain manually dismissible. Current documented targets: success **5 s**, information **7 s**, noncritical warning **10 s**; hover/focus pauses countdown. Persistent connection errors, revision conflicts, and interrupted operations stay visible until resolved.
- **Activity** may retain up to the last **100** curated, public summaries for the session; it is not a durable audit log. **Logs** and authoritative history remain server-sourced. Do not include raw secret-bearing exceptions.
- Show migration UI only when eligible legacy local records were detected. New users should never need to understand the old storage architecture to create their first VPN.
- Clear empty, offline, incompatible-helper, no-private-key, and partial-operation states without silently falling back to an unrelated action.
- Do not add pretend controls in final production UI. Wire actual commands, loading/disabled states, confirmations, errors, and tests.

## 11. Migration and compatibility

- Historical local SQLite instance definitions can be migrated explicitly to server-authoritative manifests. Detect eligible unresolved legacy records, preview destination/requirements/conflicts, create backups, transfer server-required secrets safely, commit through the helper, verify remote discovery, then mark the local record archived.
- Migration **must not** silently deploy or restart containers. Preserve original local records and credentials for recovery.
- If a distinct manifest already exists on the destination, treat it as a conflict, not an invitation to overwrite.
- Xray legacy instances are for recovery/export, not normal migration into active backends.
- Older remote SQLite-authority data is separate from local legacy migration. Do not automatically import it into manifest schema 1; preserve DB/WAL/SHM and secrets and require validated recovery tooling.
- A new manifest schema needs an explicit reviewed converter, verified recovery backup, compatibility handshake, and tests. A version mismatch should refuse writes safely.

## 12. Validation and agent workflow

Before editing:

1. Read the affected Rust/Svelte code, relevant tests, and the current docs. Identify whether the requested behavior is **implemented**, **partially implemented**, or **planned**. Do not infer implementation from prose or mock UI.
2. Trace the operation end to end: UI -> Tauri command -> ApplicationService -> SSH RPC -> remote helper -> authoritative commit/runtime. Fix behavior at the responsible boundary rather than in a UI workaround.
3. Write down failure modes for lost responses, concurrent clients, stale drafts, helper incompatibility, missing client credentials, offline states, and partial remote operations whenever they apply.
4. Make the smallest coherent change that preserves compatibility and security invariants. Avoid unrelated refactors, hidden recovery fallbacks, and new platform/framework dependencies without need.

After editing:

- Honor the repository's pinned toolchain when feasible: Rust **1.97.1**, Node **24.18.0**, pnpm **11.9.0** (confirm pins before updating them). Typical setup is `rustup toolchain install 1.97.1`, `corepack enable`, and `pnpm install`.
- Run `make verify` when feasible. It covers formatting, strict Clippy, Rust workspace tests/build, Svelte checks, Vitest, and the web build. Document which checks actually ran and any failures.
- Treat desktop packaging as **three separate targets**: Linux, macOS, and Windows. A web build is not evidence that native desktop bundles compile.
- For authority, recovery, migration, and destructive workflows, test with two **independent client databases** against one disposable appliance. Ensure a second client discovers saved remote work and cannot overwrite the first client's newer revision.
- Test the negative cases: altered SSH fingerprint, duplicate appliance UUID, unsupported helper/schema, interrupted request, stale preview, failed discovery, export without private key, revocation, ambiguous ownership, and absent archives.
- Use disposable VM acceptance infrastructure in `tests/vm/remote-authority`; its harness is `codex-cloud-init-automation`. Consult `docs/testing-vm.md` and the harness's own `AGENTS.md` before running it. Never assume an external test host or privileged access is available without checking. Preflight SSH trust, Docker/libvirt, guest image checksum, resources, and pinned artifacts. Cleanup must touch only resources created by that test run. Distinguish harness/environment failures from product failures.
- When changing DNS sources, test SSRF/redirect/size limits, malformed records, refresh failure rollback, and cross-instance isolation. When changing deletion, test partial success and exact-scope idempotent retries.
- Verify redaction of logs, operation results, Activity, and test artifacts. Never paste secrets into a report or commit test credentials.
- Keep README, security, compatibility, and recovery docs synchronized with **verified implementation**, especially when an older page contradicts the intended UX.

A useful final engineering report says **what changed, where, what was verified, what remains unimplemented, and any compatibility or recovery concerns**. Never claim tests passed when they were not run.

## 13. Reference documentation

Use these as implementation references, with the precedence described above:

- `README.md`: current overview and user-visible workflows.
- `SECURITY.md`: trust boundaries, secret ownership, export security.
- `docs/architecture.md`: service layering, authority, and migration.
- `docs/remote-format.md`: filesystem layout, protocol/schema, and compatibility; some enrollment UX text is older than the current decision.
- `docs/deployment.md`: deployment, rollback, archives, and disaster recovery.
- `docs/host-removal.md`: implemented local cleanup and explicitly blocked remote destructive cleanup.
- `docs/testing-vm.md`: disposable remote-authority acceptance tests.
- `tests/vm/remote-authority/`: acceptance suite; `build-helpers/README.md`: native build helpers.

**Bottom line:** VPNCTL should be friendly to people without pretending that distributed state, cryptographic identity, or cleanup ownership are simple. Put the complexity in deterministic Rust and the server-authoritative protocol; show it to the user only when they need to make a meaningful choice.
