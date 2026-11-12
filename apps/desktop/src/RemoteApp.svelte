<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { confirm, open, save } from "@tauri-apps/plugin-dialog";
  import { call } from "./lib/api";
  import { newInstanceForm } from "./lib/instance-form";
  import { backendSettingsFromForm, editFormFromInstance } from "./lib/remote-form";
  import { backendForms } from "./lib/components/forms/backend-forms";
  import HostReadinessMatrix from "./lib/components/HostReadinessMatrix.svelte";
  import type { AppError, DockerHost, HostKeyProbe, HostInspectionView, InstanceHealth, VpnBackendKind } from "./lib/types";
  import type { Configuration, LegacyCandidate, Manifest, MigrationPreview, PeerAvailability, RemoteDraft, RemoteInventory, RemotePlan } from "./lib/remote-types";
  import type { RemoteRestorePreview, RuntimeHistoryEntry } from "./lib/remote-types";

  const backends: { kind: VpnBackendKind; name: string; port: number }[] = [
    { kind: "wireguard", name: "WireGuard", port: 51820 }, { kind: "amnezia_wg", name: "AmneziaWG", port: 55424 },
    { kind: "openvpn", name: "OpenVPN", port: 1194 }, { kind: "ikev2", name: "IKEv2/IPsec", port: 500 },
  ];
  const tabs = ["Overview", "Peers / Devices", "DNS and Routing", "Deployment", "Settings"];
  let hosts: DockerHost[] = [];
  let selectedHostId = "";
  let inventory: RemoteInventory | null = null;
  let connection: "disconnected" | "loading" | "connected" | "offline" | "error" = "disconnected";
  let page: "server" | "add-server" | "create-instance" | "migration" = "server";
  let serverTab = "Overview";
  let selected: Manifest | null = null;
  let draft: Configuration | null = null;
  let baseRevision = 0;
  let tab = "Overview";
  let busy = "";
  let initialized = false;
  let error: AppError | null = null;
  let notice = "";
  let inspection: HostInspectionView | null = null;
  let probe: HostKeyProbe | null = null;
  let fingerprint = "";
  let replaceChanged = false;
  let candidates: LegacyCandidate[] = [];
  let migrationPreview: MigrationPreview | null = null;
  let migrationDestination = "";
  let plan: RemotePlan | null = null;
  let history: Manifest[] = [];
  let runtimeHistory: RuntimeHistoryEntry[] = [];
  let availability: PeerAvailability[] = [];
  let health: InstanceHealth | null = null;
  let backups: { name: string; created_at: string }[] = [];
  let restorePreview: RemoteRestorePreview | null = null;
  let instanceForm = newInstanceForm();
  let settingsForm = newInstanceForm();
  let peerName = "";
  let peerDns = "";
  let dnsName = "";
  let dnsValue = "";
  let dnsType = "A";
  let hostForm = { display_name: "", hostname: "", username: "", port: 22, private_key_path: "", passphrase: "" };
  let defaultUsername = "";
  let draftTimer: ReturnType<typeof setTimeout> | undefined;
  let dangerInstanceId = "";
  let dangerPeerId = "";
  let pendingCleanup: { operationId: string; hostIds: string[]; resetPreferences: boolean } | null = null;
  onDestroy(() => clearTimeout(draftTimer));
  function scheduleDraft() { clearTimeout(draftTimer); draftTimer = setTimeout(() => { void retainDraft(); }, 300); }
  $: host = hosts.find((item) => item.id === selectedHostId);
  $: eligibleLocalLegacyInstances = candidates.filter((candidate) => candidate.supported);
  $: showMigrationUI = eligibleLocalLegacyInstances.length > 0;
  $: dirty = Boolean(selected && draft && JSON.stringify(draft) !== JSON.stringify(selected.configuration));
  $: online = connection === "connected" && !inventory?.cached;
  $: observation = selected ? inventory?.discovery.deployments?.[selected.configuration.instance.id] : undefined;
  $: peerCount = inventory?.discovery.instances.reduce((count, item) => count + item.configuration.peers.length, 0) ?? 0;
  $: enabledPeerCount = inventory?.discovery.instances.reduce((count, item) => count + item.configuration.peers.filter((peer) => peer.enabled).length, 0) ?? 0;
  $: dnsRecordCount = inventory?.discovery.instances.reduce((count, item) => count + item.configuration.dns_records.length, 0) ?? 0;
  $: pendingCount = inventory?.discovery.instances.filter((item) => inventory?.discovery.deployments?.[item.configuration.instance.id]?.deployed_revision !== item.revision).length ?? 0;
  $: certificateBackend = draft?.instance.backend === "openvpn" || draft?.instance.backend === "ikev2";
  $: certificateAuthorityReady = !certificateBackend || observation?.deployed_revision != null;
  $: BackendForm = backendForms[instanceForm.backend];
  $: SettingsBackendForm = backendForms[settingsForm.backend];
  $: dangerInstance = inventory?.discovery.instances.find((item) => item.configuration.instance.id === dangerInstanceId) ?? inventory?.discovery.instances[0] ?? null;
  $: dangerPeers = dangerInstance && ["openvpn", "ikev2"].includes(dangerInstance.configuration.instance.backend) ? dangerInstance.configuration.peers.filter((peer) => peer.enabled) : [];
  $: dangerPeer = dangerPeers.find((peer) => peer.id === dangerPeerId) ?? dangerPeers[0] ?? null;
  const copy = <T,>(value: T): T => JSON.parse(JSON.stringify(value));
  const nameOf = (kind: VpnBackendKind) => backends.find((backend) => backend.kind === kind)?.name ?? "Unsupported backend";

  async function task<T>(label: string, action: () => Promise<T>): Promise<T | undefined> {
    busy = label; error = null;
    try { return await action(); }
    catch (cause) { error = cause as AppError; return undefined; }
    finally { busy = ""; }
  }
  onMount(async () => {
    await task("Loading saved servers", async () => {
      const [savedHosts, legacy, info] = await Promise.all([call<DockerHost[]>("list_hosts"), call<LegacyCandidate[]>("legacy_candidates"), call<{ system_username: string }>("app_info")]);
      hosts = savedHosts; candidates = legacy; defaultUsername = info.system_username; hostForm.username = defaultUsername;
    });
    if (hosts.length) await selectServer(hosts[0].id);
    initialized = true;
  });
  async function selectServer(id: string, section = "Overview") {
    if (dirty && !(await retainDraft())) return;
    selectedHostId = id; selected = null; draft = null; inventory = null; inspection = null; probe = null;
    dangerInstanceId = ""; dangerPeerId = "";
    plan = null; health = null; backups = []; restorePreview = null; page = "server"; serverTab = section; await refreshServer();
  }
  async function navigateSection(section: string) {
    if (dirty && !(await retainDraft())) return;
    page = "server"; serverTab = section; selected = null; draft = null;
    if (["Devices", "DNS", "Backups", "Logs"].includes(section) && inventory?.discovery.instances.length) {
      await selectSectionInstance(inventory.discovery.instances[0].configuration.instance.id);
    }
  }
  async function selectSectionInstance(instanceId: string) {
    const manifest = inventory?.discovery.instances.find((item) => item.configuration.instance.id === instanceId);
    if (!manifest) return;
    await openInstance(manifest);
    if (selected?.configuration.instance.id !== instanceId) return;
    tab = serverTab === "Devices" ? "Peers / Devices" : serverTab === "DNS" ? "DNS and Routing" : "Deployment";
    if (serverTab === "Backups") await loadBackups();
    if (serverTab === "Logs") await loadRuntimeHistory();
  }
  async function refreshServer() {
    if (!selectedHostId) return;
    const id = selectedHostId;
    connection = "loading";
    const fresh = await task("Synchronizing server", () => call<RemoteInventory>("discover_remote", { hostId: id }));
    if (selectedHostId !== id) return;
    if (fresh) {
      const hadEdits = dirty;
      inventory = fresh; connection = "connected";
      if (selected) {
        const current = fresh.discovery.instances.find((item) => item.configuration.instance.id === selected?.configuration.instance.id);
        if (current) {
          selected = current;
          if (!hadEdits) {
            draft = copy(current.configuration); baseRevision = current.revision;
            settingsForm = editFormFromInstance(current.configuration.instance);
          }
          plan = null;
        } else if (!fresh.discovery.errors[selected.configuration.instance.id]) {
          selected = null; draft = null; plan = null; health = null; backups = []; restorePreview = null;
        }
      }
    }
    else {
      connection = "error";
      try { inventory = await call<RemoteInventory | null>("cached_remote_inventory", { hostId: id }); if (inventory) connection = "offline"; }
      catch (cause) { error = cause as AppError; }
    }
  }
  async function retainDraft() {
    clearTimeout(draftTimer);
    if (!draft || !selected) return true;
    await task("Keeping local draft", () => call<void>("save_remote_draft", { draft: { host_id: selectedHostId, base_revision: baseRevision, configuration: draft } }));
    return !error;
  }
  async function openInstance(manifest: Manifest) {
    if (dirty && !(await retainDraft())) return;
    if (serverTab === "Overview" || serverTab === "Hosts") serverTab = "Instances";
    selected = manifest; draft = copy(manifest.configuration); baseRevision = manifest.revision;
    plan = null; health = null; backups = []; restorePreview = null;
    tab = serverTab === "Devices" ? "Peers / Devices" : serverTab === "DNS" ? "DNS and Routing" : ["Backups", "Logs"].includes(serverTab) ? "Deployment" : "Overview";
    availability = []; history = []; runtimeHistory = [];
    const local = await task("Loading local draft", () => call<RemoteDraft | null>("load_remote_draft", { hostId: selectedHostId, instanceId: manifest.configuration.instance.id }));
    if (local) { draft = local.configuration; baseRevision = local.base_revision; notice = "Unsaved local edits restored. Saving requires revision validation."; }
    settingsForm = editFormFromInstance(draft!.instance);
    if (online) {
      const result = await task("Checking local export material", () => call<PeerAvailability[]>("remote_peer_availability", { hostId: selectedHostId, instanceId: manifest.configuration.instance.id }));
      if (result) availability = result;
    }
  }
  async function reloadInstance() {
    clearTimeout(draftTimer);
    if (!selected) return;
    if (dirty && !await confirm("Discard this local draft and reload the server configuration?", { title: "Reload configuration", kind: "warning" })) return;
    const fresh = await task("Reading server configuration", () => call<Manifest>("read_remote", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id }));
    if (fresh) {
      await task("Discarding local draft", () => call<void>("discard_remote_draft", { hostId: selectedHostId, instanceId: fresh.configuration.instance.id }));
      if (!error) {
        selected = null; draft = null; notice = "";
        await openInstance(fresh);
      }
    }
  }
  async function saveDraft() {
    if (!draft || !selected || !online) return;
    await retainDraft(); if (error) return;
    const saved = await task("Saving to server", () => call<Manifest>("save_remote_configuration", { input: { host_id: selectedHostId, expected_revision: baseRevision, request_id: crypto.randomUUID(), configuration: draft } }));
    if (saved) {
      await task("Clearing saved draft", () => call<void>("discard_remote_draft", { hostId: selectedHostId, instanceId: saved.configuration.instance.id }));
      if (error) return;
      selected = saved; draft = copy(saved.configuration); baseRevision = saved.revision; plan = null;
      notice = "Saved to server. Preview deployment to apply this revision."; await refreshServer();
    }
  }
  async function createInstance() {
    const created = await task("Creating instance on server", () => call<Manifest>("create_remote_instance", { input: {
      host_id: selectedHostId, display_name: instanceForm.display_name, endpoint_host: instanceForm.endpoint_host,
      backend: instanceForm.backend, backend_settings: backendSettingsFromForm(instanceForm), endpoint_port: instanceForm.endpoint_port,
      ipv4_subnet: instanceForm.ipv4_subnet, dns_zone: instanceForm.dns_zone, routing_mode: instanceForm.routing_mode,
    } }));
    if (created) { page = "server"; await refreshServer(); await openInstance(created); }
  }
  function applySettings() {
    if (!draft) return;
    draft.instance = { ...draft.instance, display_name: settingsForm.display_name,
      endpoint: { host: settingsForm.endpoint_host, port: settingsForm.endpoint_port },
      dns: { ...draft.instance.dns, zone: settingsForm.dns_zone }, routing_mode: settingsForm.routing_mode,
      backend_settings: backendSettingsFromForm(settingsForm) };
    scheduleDraft();
  }
  async function addPeer() {
    if (!selected || dirty) return;
    const saved = await task("Saving new peer to server", () => call<Manifest>("add_remote_peer", { hostId: selectedHostId, expectedRevision: baseRevision,
      input: { instance_id: selected!.configuration.instance.id, display_name: peerName, user_id: null, dns_name: peerDns || null, preshared_key: true, create_dns_record: Boolean(peerDns) } }));
    if (saved) { peerName = ""; peerDns = ""; selected = null; draft = null; await refreshServer(); await openInstance(saved); tab = "Peers / Devices"; }
  }
  async function exportPeer(peerId: string) {
    if (!selected) return;
    const extension = selected.configuration.instance.backend === "openvpn" ? "client.ovpn" : selected.configuration.instance.backend === "ikev2" ? "client.p12" : "client.conf";
    const destination = await save({ title: "Export complete client configuration", defaultPath: extension });
    if (destination) await task("Exporting through native credential storage", () => call<void>("export_remote_peer", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, peerId, destination }));
  }
  async function openDangerZone(instanceId?: string, peerId?: string) {
    await navigateSection("Danger Zone");
    if (serverTab === "Danger Zone") { dangerInstanceId = instanceId ?? ""; dangerPeerId = peerId ?? ""; }
  }
  async function cleanupLocal(resetPreferences: boolean) {
    if (busy || (!resetPreferences && !host)) return;
    if (pendingCleanup && pendingCleanup.resetPreferences !== resetPreferences) return;
    const completed = await task(resetPreferences ? "Resetting local application data" : "Removing local host", async () => {
      const scope = resetPreferences && !pendingCleanup ? await call<{ host_ids: string[] }>("preview_local_factory_reset") : null;
      const target = pendingCleanup ?? { operationId: crypto.randomUUID(), hostIds: scope?.host_ids ?? [selectedHostId], resetPreferences };
      const targetName = hosts.find((item) => item.id === target.hostIds[0])?.display_name ?? "the selected host";
      const message = resetPreferences
        ? `Reset local data for all ${target.hostIds.length} saved hosts and restore application preferences to defaults? Server instances keep running. VPN configurations, client keys, and recovery bindings are preserved. SSH key files and exported VPN configurations are untouched. This is not secure erasure.`
        : `Remove ${targetName} from this machine? Its connection, cache, and drafts will be removed. Server instances keep running. VPN configurations, client keys, and recovery bindings are preserved for verified reconnection. SSH key files and exported VPN configurations are untouched.`;
      if (!await confirm(message, { title: resetPreferences ? "Factory Reset · local data only" : "Local drop", kind: "warning" })) return false;
      clearTimeout(draftTimer);
      pendingCleanup = target;
      await call("cleanup_local", { ...target, confirmed: true });
      pendingCleanup = null;
      hosts = hosts.filter((item) => !target.hostIds.includes(item.id));
      candidates = candidates.filter((item) => !target.hostIds.includes(item.host_id));
      selectedHostId = ""; inventory = null; selected = null; draft = null; inspection = null; probe = null;
      plan = null; health = null; backups = []; restorePreview = null; availability = []; history = []; runtimeHistory = [];
      dangerInstanceId = ""; dangerPeerId = ""; connection = "disconnected";
      if (resetPreferences) {
        instanceForm = newInstanceForm(); settingsForm = newInstanceForm();
        hostForm = { display_name: "", hostname: "", username: defaultUsername, port: 22, private_key_path: "", passphrase: "" };
        peerName = ""; peerDns = ""; dnsName = ""; dnsValue = ""; dnsType = "A";
        fingerprint = ""; replaceChanged = false; migrationPreview = null; migrationDestination = "";
      }
      return true;
    });
    if (completed) {
      notice = resetPreferences ? "Local Factory Reset completed. VPN recovery data is preserved; servers are unchanged." : "Host removed locally. VPN recovery data is preserved; server instances keep running.";
      if (hosts.length) await selectServer(hosts[0].id, "Danger Zone");
    }
  }
  async function archiveDangerInstance() {
    if (busy || !online || !dangerInstance || pendingCleanup) return;
    const hostId = selectedHostId;
    const instanceId = dangerInstance.configuration.instance.id;
    const completed = await task("Archiving instance", async () => {
      const fresh = await call<Manifest>("read_remote", { hostId, instanceId });
      if (!await confirm(`Stop and archive ${fresh.configuration.instance.display_name} on ${host?.display_name}? Connected VPN users will lose service. Saved history, server recovery data, and local client keys are retained. Local drafts are not applied.`, { title: "Archive instance on server", kind: "warning" })) return false;
      await call("remove_remote_configuration", { input: { host_id: hostId, expected_revision: fresh.revision, request_id: crypto.randomUUID(), configuration: fresh.configuration }, confirmed: true });
      return true;
    });
    if (completed) { notice = "Instance archived on server. History and recovery data are retained."; await refreshServer(); }
  }
  async function revokeDangerPeer() {
    if (busy || !online || !dangerInstance || !dangerPeer || pendingCleanup) return;
    const hostId = selectedHostId;
    const instanceId = dangerInstance.configuration.instance.id;
    const peerId = dangerPeer.id;
    const completed = await task("Revoking peer certificate", async () => {
      const fresh = await call<Manifest>("read_remote", { hostId, instanceId });
      const peer = fresh.configuration.peers.find((item) => item.id === peerId && item.enabled);
      if (!peer) throw { code: "peer_changed", message: "This device changed on the server. Refresh before revoking its certificate." };
      if (!await confirm(`Revoke the certificate for ${peer.display_name} in ${fresh.configuration.instance.display_name} on ${host?.display_name}? This cannot be reversed. Deployment is still required to apply the revocation. Local client keys are preserved.`, { title: "Revoke peer certificate", kind: "warning" })) return false;
      await call("revoke_remote_peer", { hostId, instanceId, peerId, expectedRevision: fresh.revision, confirmed: true });
      return true;
    });
    if (completed) { notice = "Certificate revoked in saved configuration. Deploy the instance to apply the revocation."; await refreshServer(); }
  }
  function addDns() {
    if (!draft) return;
    draft.dns_records = [...draft.dns_records, { id: crypto.randomUUID(), instance_id: draft.instance.id, name: dnsName, record_type: dnsType as "A", value: dnsValue, ttl: 300, enabled: true }];
    dnsName = ""; dnsValue = ""; void retainDraft();
  }
  async function previewDeployment() {
    if (!selected) return;
    const result = await task("Previewing saved revision", () => call<RemotePlan>("preview_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision }));
    if (result) plan = result;
  }
  async function deploy() {
    if (!selected || !plan || !await confirm("Deploy saved revision " + baseRevision + " on " + host?.display_name + "?", { title: "Apply deployment", kind: "warning" })) return;
    await task("Deploying saved revision", () => call("apply_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision, expectedStateHash: plan!.desired_state_hash, requestId: crypto.randomUUID() }));
    plan = null; if (!error) { notice = "Deployment completed and health verified."; await refreshServer(); }
  }
  async function loadHistory() {
    if (!selected) return;
    const result = await task("Reading desired-state history", () => call<Manifest[]>("remote_history", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id }));
    if (result) history = result;
  }
  async function loadRuntimeHistory() {
    if (!selected) return;
    const result = await task("Reading deployment history", () => call<RuntimeHistoryEntry[]>("remote_runtime_history", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id }));
    if (result) runtimeHistory = result;
  }
  async function reconcileRuntime() {
    if (!selected || !observation?.pending_operation) return;
    const status = await task("Reconciling interrupted operation", () => call<"committed" | "uncommitted" | "unresolved">("reconcile_remote_runtime", {
      hostId: selectedHostId, instanceId: selected!.configuration.instance.id, mutationId: observation!.pending_operation,
    }));
    if (status) {
      notice = status === "unresolved" ? "The operation outcome is unresolved. Inspect the remote runtime and recovery backup before another mutation." :
        status === "committed" ? "The operation completed; remote state has been reconciled." : "The operation did not commit.";
      await refreshServer();
    }
  }
  async function loadBackups() {
    if (!selected) return;
    const result = await task("Reading runtime backups", () => call<{ name: string; created_at: string }[]>("list_remote_backups", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id }));
    if (result) backups = result;
  }
  async function previewRestore(backupName: string) {
    if (!selected) return;
    const result = await task("Reviewing deployment restore", () => call<RemoteRestorePreview>("preview_remote_restore", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision, backupName }));
    if (result) restorePreview = result;
  }
  async function restoreDeployment() {
    if (!selected || !restorePreview || !await confirm("Restore this deployment and its persistent identity state? Saved desired configuration will be preserved.", { title: "Restore deployment", kind: "warning" })) return;
    const result = await task("Restoring deployed state", () => call<InstanceHealth>("restore_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, preview: restorePreview, confirmed: true }));
    if (result) { health = result; restorePreview = null; notice = "Deployment restored. Saved desired state was preserved."; await refreshServer(); }
  }
  async function restoreDesired(revision: number) {
    if (!selected || dirty || !await confirm("Restore desired revision " + revision + " as a new saved revision? This does not deploy it.", { title: "Restore Desired Configuration", kind: "warning" })) return;
    const result = await task("Restoring desired configuration", () => call<Manifest>("restore_remote_desired", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, revision, expectedRevision: baseRevision, confirmed: true }));
    if (result) { selected = null; draft = null; await refreshServer(); await openInstance(result); tab = "Deployment"; }
  }
  async function inspectServer() {
    const result = await task("Inspecting server", () => call<HostInspectionView>("inspect_host_view", { hostId: selectedHostId }));
    if (result) inspection = result;
  }
  async function probeServer() {
    const result = await task("Probing SSH identity", () => call<HostKeyProbe>("probe_host_key", { hostId: selectedHostId }));
    if (result) { probe = result; fingerprint = ""; replaceChanged = false; }
  }
  async function approveIdentity() {
    if (!probe) return;
    await task("Approving verified SSH identity", () => call("approve_host_key", { hostId: selectedHostId, probed: probe!.key, expectedFingerprint: fingerprint, replaceChangedKey: replaceChanged }));
    if (!error) { probe = null; await refreshServer(); }
  }
  async function addServer() {
    const created = await task("Saving server connection", () => call<DockerHost>("create_host", { input: { ...hostForm, passphrase: hostForm.passphrase || null } }));
    hostForm.passphrase = "";
    if (created) { hosts = [...hosts, created]; await selectServer(created.id); }
  }
  async function previewMigration(id: string) {
    const result = await task("Previewing local legacy migration", () => call<MigrationPreview>("preview_legacy_migration", { instanceId: id, destinationHostId: migrationDestination || selectedHostId }));
    if (result) migrationPreview = result;
  }
  async function migrate() {
    if (!migrationPreview || !await confirm("Back up and migrate this local configuration to the selected server without restarting containers?", { title: "Migrate instance", kind: "warning" })) return;
    await task("Migrating instance", () => call("migrate_legacy_instance", { instanceId: migrationPreview!.instance_id, destinationHostId: migrationPreview!.destination_host_id, expectedPreviewHash: migrationPreview!.expected_preview_hash, confirmed: true }));
    if (!error) {
      candidates = await call<LegacyCandidate[]>("legacy_candidates"); migrationPreview = null;
      if (!candidates.some((candidate) => candidate.supported)) page = "server";
      await refreshServer();
    }
  }
</script>

<svelte:head><title>{host?.display_name ?? "Servers"} · VPNCTL</title></svelte:head>
<div class="shell">
  <aside class="sidebar" aria-label="Primary navigation">
    <div class="brand"><div class="mark" aria-hidden="true">VA</div><div><strong>VPNCTL</strong><span>Appliance Manager</span></div></div>
    <nav aria-label="Control plane"><h2>Control plane</h2>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "Overview"} aria-current={page === "server" && serverTab === "Overview" ? "page" : undefined} onclick={() => navigateSection("Overview")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg><span class="nav-label">Overview</span></button>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "Hosts"} aria-current={page === "server" && serverTab === "Hosts" ? "page" : undefined} onclick={() => navigateSection("Hosts")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M11 7h6M11 17h6"/></svg><span class="nav-label">Hosts</span><span class="nav-count">{hosts.length}</span></button>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "Instances"} aria-label="Instances" aria-current={page === "server" && serverTab === "Instances" ? "page" : undefined} onclick={() => navigateSection("Instances")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg><span class="nav-label">Instances</span><span class="nav-count">{inventory?.discovery.instances.length ?? 0}</span></button>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "Devices"} aria-current={page === "server" && serverTab === "Devices" ? "page" : undefined} onclick={() => navigateSection("Devices")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg><span class="nav-label">Devices</span><span class="nav-count">{peerCount}</span></button>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "DNS"} aria-current={page === "server" && serverTab === "DNS" ? "page" : undefined} onclick={() => navigateSection("DNS")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg><span class="nav-label">DNS</span></button>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "Backups"} aria-current={page === "server" && serverTab === "Backups" ? "page" : undefined} onclick={() => navigateSection("Backups")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg><span class="nav-label">Backups</span></button>
      <button disabled={Boolean(busy)} class:active={page === "server" && serverTab === "Logs"} aria-current={page === "server" && serverTab === "Logs" ? "page" : undefined} onclick={() => navigateSection("Logs")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Z"/><path d="M14 2v6h6M8 13h8M8 17h8"/></svg><span class="nav-label">Logs</span></button>
      <button disabled={Boolean(busy)} class="danger-nav" class:active={page === "server" && serverTab === "Danger Zone"} aria-label="Danger Zone" aria-current={page === "server" && serverTab === "Danger Zone" ? "page" : undefined} onclick={() => navigateSection("Danger Zone")}><svg class="nav-glyph" viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3v1"/></svg><span class="nav-label">Danger Zone</span></button>
    </nav>
    {#if showMigrationUI}<button class="sidebar-migration" disabled={!initialized || Boolean(busy)} onclick={() => { page = "migration"; migrationDestination = selectedHostId; }}>Migrate Instances ({eligibleLocalLegacyInstances.length})</button>{/if}
  </aside>
  <div class="workspace">
    <div class="topbar"><div class="breadcrumbs"><span>Workspace</span><span aria-hidden="true">/</span><strong>{page === "add-server" ? "Add Server" : page === "create-instance" ? "Create Instance" : page === "migration" ? "Migration" : serverTab}</strong></div><div class="topbar-state"><span class="connection-dot" data-state={connection}></span>{host ? `${host.display_name} · ${connection}` : "No server selected"}</div></div>
  <main class="app-main">
    {#if busy}<div class="progress" role="status">{busy}…</div>{/if}
    {#if notice}<div class="notice" role="status"><span>{notice}</span><button aria-label="Dismiss notice" onclick={() => notice = ""}>×</button></div>{/if}
    {#if error}<div class="alert" role="alert"><div><strong>{error.message}</strong>{#if error.remediation}<p>{error.remediation}</p>{/if}{#if error.code === "revision_conflict"}<p>Your local draft is retained. Reload after reviewing the server’s changes.</p>{/if}</div><button aria-label="Dismiss error" onclick={() => error = null}>×</button></div>{/if}
    {#if page === "server" && serverTab === "Danger Zone"}
      <header class="page-head"><div><p class="eyebrow">Workspace / Destructive actions</p><h1>Danger Zone</h1><p class="subtitle">Remove local connections, reset the client, or archive a server instance. Every action requires confirmation.</p></div></header>
      <div class="danger-zone">
        <section class="card danger-preservation"><h2>Recovery data stays protected</h2><p>Local removal and reset preserve VPN configurations, generated client keys, and recovery bindings. SSH key files and exported VPN configurations are never deleted. Factory Reset is not secure erasure.</p></section>
        {#if pendingCleanup}<div class="alert" role="status">A local cleanup needs reconciliation. Retry the same action to check its original operation; its host selection will not change.</div>{/if}
        {#if hosts.length}<section class="card"><label>Danger Zone host<select value={selectedHostId} disabled={Boolean(busy) || Boolean(pendingCleanup)} onchange={(event) => selectServer(event.currentTarget.value, "Danger Zone")}>{#each hosts as server}<option value={server.id}>{server.display_name} · {server.ssh.username}@{server.ssh.hostname}:{server.ssh.port}</option>{/each}</select></label><p>Remote actions affect this host only. Factory Reset applies to all saved hosts.</p></section>{/if}
        <section class="card danger-row"><div><h2>Local drop</h2><p>Remove {host?.display_name ?? "the selected host"} from this machine, including its connection, cache, and drafts. Server instances keep running. Reconnect to the verified appliance to access them again.</p></div><button class="danger-action" disabled={!initialized || !host || Boolean(busy) || (Boolean(pendingCleanup) && pendingCleanup?.resetPreferences !== false)} onclick={() => cleanupLocal(false)}>{pendingCleanup && !pendingCleanup.resetPreferences ? "Retry local drop" : "Remove host locally"}</button></section>
        <section class="card danger-row"><div><h2>Full drop</h2><p>Would permanently remove all current VPNCTL-managed instances from this server, then remove the local connection.</p><p id="full-drop-unavailable">Unavailable: safe server ownership checks and recovery archives are not ready. No full-server deletion will run.</p></div><button class="danger-action" disabled aria-describedby="full-drop-unavailable">Full drop unavailable</button></section>
        <section class="card danger-row"><div><h2>Factory Reset · local data only</h2><p>Remove all saved host profiles, connection state, caches, and drafts, and reset application preferences. You will confirm the full profile count before continuing. Servers remain unchanged; VPN recovery data survives.</p></div><button class="danger-action" disabled={!initialized || Boolean(busy) || (Boolean(pendingCleanup) && pendingCleanup?.resetPreferences !== true)} onclick={() => cleanupLocal(true)}>{pendingCleanup?.resetPreferences ? "Retry local Factory Reset" : "Factory Reset local data"}</button></section>
        <section class="card danger-row"><div><h2>Factory Reset · remove remote data</h2><p>Would clean each distinct verified saved appliance before resetting the client.</p><p id="remote-reset-unavailable">Unavailable for the same server ownership and archive requirements as full drop.</p></div><button class="danger-action" disabled aria-describedby="remote-reset-unavailable">Remote Factory Reset unavailable</button></section>
        <section class="card"><h2>Instance and device actions</h2>
          {#if !host}<p>Add a host to manage its instances.</p>{:else}
            <p>{host.display_name} · {online ? "Live connection" : "Remote actions require a live connection."}</p>
            <button class="secondary" disabled={Boolean(busy) || Boolean(pendingCleanup)} onclick={refreshServer}>Refresh / Reconnect</button>
            {#if inventory?.discovery.instances.length}<label>Managed instance<select value={dangerInstance?.configuration.instance.id ?? ""} disabled={Boolean(busy) || Boolean(pendingCleanup)} onchange={(event) => { dangerInstanceId = event.currentTarget.value; dangerPeerId = ""; }}>{#each inventory.discovery.instances as item}<option value={item.configuration.instance.id}>{item.configuration.instance.display_name}</option>{/each}</select></label>{:else}<p>{online ? "No managed instances available." : "Connect to load the server inventory."}</p>{/if}
            <div class="danger-row"><div><h3>Archive instance on server</h3><p>Stop the selected VPN instance and disconnect its users. Saved history and server recovery data are retained. This does not permanently erase the instance.</p></div><button class="danger-action" disabled={!online || !dangerInstance || Boolean(busy) || Boolean(pendingCleanup)} onclick={archiveDangerInstance}>Archive instance on server</button></div>
            {#if dangerPeers.length}<label>Device certificate<select value={dangerPeer?.id ?? ""} disabled={Boolean(busy) || Boolean(pendingCleanup)} onchange={(event) => dangerPeerId = event.currentTarget.value}>{#each dangerPeers as peer}<option value={peer.id}>{peer.display_name}</option>{/each}</select></label><div class="danger-row"><div><h3>Revoke device certificate</h3><p>Revocation cannot be reversed. Deploy the instance afterward to apply it. Local client keys are preserved.</p></div><button class="danger-action" disabled={!online || !dangerPeer || Boolean(busy) || Boolean(pendingCleanup)} onclick={revokeDangerPeer}>Revoke device certificate</button></div>{/if}
          {/if}
        </section>
      </div>
    {:else if page === "add-server"}
      <header class="page-head"><div><p class="eyebrow">Server connection</p><h1>Add Server</h1><p class="subtitle">Connect a Linux appliance using a verified SSH identity.</p></div></header>
      <form class="card remote-form setup-form" onsubmit={(event) => { event.preventDefault(); void addServer(); }}>
        <label>Server name<input required bind:value={hostForm.display_name} /></label><label>SSH hostname<input required bind:value={hostForm.hostname} /></label>
        <label>SSH username<input required bind:value={hostForm.username} /></label><label>SSH port<input required type="number" min="1" max="65535" bind:value={hostForm.port} /></label>
        <label>Private key path<input required bind:value={hostForm.private_key_path} /></label>
        <button class="secondary" type="button" onclick={async () => { const path = await open({ multiple: false, title: "Choose SSH private key" }); if (typeof path === "string") hostForm.private_key_path = path; }}>Choose key</button>
        <label>Key passphrase<input type="password" autocomplete="off" bind:value={hostForm.passphrase} /></label><button class="primary" disabled={Boolean(busy)}>Add Server</button>
      </form>
    {:else if page === "migration" && showMigrationUI}
      <header class="page-head"><div><p class="eyebrow">Recovery workflow</p><h1>Migrate local instances</h1><p class="subtitle">Review eligible local configuration before saving it to a server.</p></div></header>
      <label>Destination server<select bind:value={migrationDestination}><option value="">Select a server</option>{#each hosts as server}<option value={server.id}>{server.display_name}</option>{/each}</select></label>
      {#each eligibleLocalLegacyInstances as candidate}<section class="card"><h2>{candidate.display_name}</h2><p>{nameOf(candidate.backend)} · {candidate.instance_id}</p><button class="secondary" disabled={!migrationDestination || Boolean(busy)} onclick={() => previewMigration(candidate.instance_id)}>Preview migration</button></section>{/each}
      {#if migrationPreview}<section class="card"><h2>Migration preview</h2><p>{migrationPreview.deployment_present ? "Existing deployment and identities will be preserved." : "Configuration will be saved without deploying containers."}</p>{#each migrationPreview.warnings as warning}<p>{warning}</p>{/each}{#each migrationPreview.issues as issue}<p class="danger">{issue}</p>{/each}<button class="primary" disabled={Boolean(busy) || migrationPreview.issues.length > 0} onclick={migrate}>Back Up and Migrate</button></section>{/if}
    {:else if page === "create-instance"}
      <header class="page-head"><div><p class="eyebrow">New appliance</p><h1>Create Instance on {host?.display_name}</h1><p class="subtitle">Save the configuration first. Preview and deploy it when you are ready.</p></div></header>
      <form class="card remote-form setup-form" onsubmit={(event) => { event.preventDefault(); void createInstance(); }}>
        <label>Instance name<input required bind:value={instanceForm.display_name} /></label>
        <label>Backend<select bind:value={instanceForm.backend} onchange={() => { instanceForm.endpoint_port = backends.find((backend) => backend.kind === instanceForm.backend)!.port; }}>{#each backends as backend}<option value={backend.kind}>{backend.name}</option>{/each}</select></label>
        <label>VPN endpoint<input required bind:value={instanceForm.endpoint_host} /></label><label>Listener port<input type="number" min="1" max="65535" disabled={instanceForm.backend === "ikev2"} bind:value={instanceForm.endpoint_port} /></label>
        <label>IPv4 subnet<input required bind:value={instanceForm.ipv4_subnet} /></label><label>Private DNS zone<input required bind:value={instanceForm.dns_zone} /></label>
        {#if BackendForm}<BackendForm bind:form={instanceForm} />{/if}<button class="primary" disabled={!online || Boolean(busy)}>Save to Server</button>
      </form>
    {:else if !host}
      <header class="page-head"><div><p class="eyebrow">Workspace setup</p><h1>Servers</h1><p class="subtitle">Manage remote VPN appliances from verified SSH connections.</p></div></header><section class="card empty-workspace"><div class="empty-symbol" aria-hidden="true">▣</div><h2>Connect your first VPN server</h2><p>Add a Linux server using a verified SSH connection.</p><button class="primary" onclick={() => page = "add-server"}>Add Server</button></section>
    {:else}
      <header class="page-head"><div><p class="eyebrow">Control plane / {serverTab}</p><h1>{selected && serverTab === "Instances" ? "Instances" : serverTab}</h1><p class="subtitle">{serverTab === "Overview" ? `One workspace for ${host.display_name}, VPN instances, connected devices, and private DNS.` : serverTab === "Hosts" ? "Manage verified SSH connections and inspect remote hosts." : serverTab === "Instances" ? `Provision and manage VPN appliances on ${host.display_name}.` : `Manage ${serverTab.toLowerCase()} for ${host.display_name}.`}</p></div>{#if serverTab === "Overview" || serverTab === "Instances"}<button class="primary" disabled={!online || Boolean(busy)} onclick={() => { instanceForm = newInstanceForm(selectedHostId, host!.ssh.hostname); page = "create-instance"; }}>+ Create instance</button>{:else if serverTab === "Hosts"}<button class="primary" onclick={() => page = "add-server"}>+ Add host</button>{/if}</header>
      {#if inventory?.cached}<div class="alert" role="status">Offline · showing cached information from {new Date(inventory.synchronized_at).toLocaleString()}. Saving and deployment require a live connection.</div>{/if}
      {#if inventory && Object.keys(inventory.discovery.errors).length}<div class="alert" role="alert">Some remote instance metadata could not be read. The server is not empty.<ul>{#each Object.values(inventory.discovery.errors) as problem}<li>{problem}</li>{/each}</ul></div>{/if}
      {#if ["Devices", "DNS", "Backups", "Logs"].includes(serverTab) && inventory?.discovery.instances.length}<section class="card section-selector"><label for="section-instance">Instance</label><select id="section-instance" value={selected?.configuration.instance.id ?? ""} onchange={(event) => selectSectionInstance(event.currentTarget.value)}>{#each inventory.discovery.instances as item}<option value={item.configuration.instance.id}>{item.configuration.instance.display_name}</option>{/each}</select><span>{host.display_name} · {inventory.cached ? "cached" : connection}</span></section>{/if}
      {#if selected && draft}
        {#if serverTab === "Devices"}<div class="metric-grid section-metrics" aria-label="Device summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg></span><strong>{draft.peers.length}</strong><span class="metric-label">Assigned identities</span><small>On {draft.instance.display_name}</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg></span><strong>{draft.peers.filter((peer) => peer.enabled).length}</strong><span class="metric-label">Enabled</span><small>Saved access state</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/></svg></span><strong>{draft.peers.filter((peer) => !peer.enabled).length}</strong><span class="metric-label">Disabled</span><small>Saved access state</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="5"/><path d="m12 11 9-9 2 2-2 2 1 2-3 3-2-2-3 3"/></svg></span><strong>{availability.filter((item) => item.complete_export_available).length}</strong><span class="metric-label">Exportable here</span><small>Complete local credentials</small></div></div>{/if}
        {#if serverTab === "DNS"}<div class="metric-grid section-metrics three" aria-label="DNS summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></span><strong>{draft.dns_records.length}</strong><span class="metric-label">Private DNS records</span><small>Saved configuration</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 22 0 0C6 19 4 16 4 10V5l8-3 8 3v5c0 6-2 9-8 12Z"/><path d="m9 12 2 2 4-4"/></svg></span><strong>{draft.dns_blocklist_domains.length}</strong><span class="metric-label">Blocklist domains</span><small>Saved configuration</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><strong class="metric-date">{draft.instance.dns.zone}</strong><span class="metric-label">Private DNS zone</span><small>On {draft.instance.display_name}</small></div></div>{/if}
        {#if serverTab === "Backups"}<div class="metric-grid section-metrics three" aria-label="Backup summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg></span><strong>{backups.length}</strong><span class="metric-label">Runtime snapshots</span><small>On {draft.instance.display_name}</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></span><strong>{observation?.deployed_revision ?? "—"}</strong><span class="metric-label">Deployed revision</span><small>Current observation</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg></span><strong>{selected.revision}</strong><span class="metric-label">Desired revision</span><small>Saved configuration</small></div></div>{/if}
        {#if serverTab === "Instances"}<div class="metric-grid instance-metrics" aria-label="Instance summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg></span><strong>{inventory?.discovery.instances.length ?? 0}</strong><span class="metric-label">Total instances</span><small>On {host.display_name}</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></span><strong>{inventory?.discovery.instances.filter((item) => inventory?.discovery.deployments?.[item.configuration.instance.id]?.deployed_revision != null).length ?? 0}</strong><span class="metric-label">Deployed</span><small>Deployment revision recorded</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><strong>{pendingCount}</strong><span class="metric-label">Pending deployment</span><small>Saved and deployed revisions differ</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg></span><strong>{peerCount}</strong><span class="metric-label">Assigned devices</span><small>Across this server</small></div></div>{/if}<div class:prototype-split={serverTab === "Instances"} class:instance-split={serverTab === "Instances"}>{#if serverTab === "Instances"}<section class="card instances-panel"><header><h2>Your instances</h2><span class="panel-caption">{inventory?.discovery.instances.length ?? 0} total</span></header><div class="instance-grid">{#each inventory?.discovery.instances ?? [] as instance}<button class="instance-card" class:selected={selected.configuration.instance.id === instance.configuration.instance.id} onclick={() => openInstance(instance)}><span class="instance-symbol" aria-hidden="true">{nameOf(instance.configuration.instance.backend).slice(0, 2).toUpperCase()}</span><span class="instance-card-info"><strong>{instance.configuration.instance.display_name}</strong><small>{instance.configuration.instance.endpoint.host}:{instance.configuration.instance.endpoint.port}</small><small>{nameOf(instance.configuration.instance.backend)} · saved revision {instance.revision}</small></span><span class="instance-chevron" aria-hidden="true">›</span></button>{/each}</div></section>{/if}<div class="instance-detail-column">
        <section class="card instance-workspace" oninput={scheduleDraft}>
          <header class="instance-head"><div><p class="eyebrow">{serverTab === "Instances" ? "Selected appliance" : `Selected instance · ${draft.instance.display_name}`}</p><h2>{serverTab === "Instances" ? draft.instance.display_name : serverTab === "Devices" ? "Device identities" : serverTab === "DNS" ? "Private DNS records" : serverTab === "Backups" ? "Backup inventory" : "Deployment history"}</h2><p>{nameOf(draft.instance.backend)} · saved revision {selected.revision} · {observation?.deployed_revision == null ? "Deployment revision unknown" : "deployed revision " + observation.deployed_revision}</p></div><div class="header-actions"><button class="secondary" disabled={!online || Boolean(busy)} onclick={reloadInstance}>Reload from Server</button><button class="primary" disabled={!dirty || !online || Boolean(busy)} onclick={saveDraft}>Save to Server</button></div></header>
          {#if dirty}<div class="notice status-unsaved" role="status">Unsaved local edits · based on revision {baseRevision}</div>{/if}
          {#if baseRevision !== selected.revision}<div class="alert">This draft is based on an older revision. Reload or reconcile your edits before saving.</div>{/if}
          {#if observation?.deployed_revision !== selected.revision}<div class="notice status-pending" role="status">Pending deployment · saved desired state differs from the deployed revision.</div>{/if}
          {#if observation?.pending_operation}<div class="alert" role="alert">An interrupted runtime operation requires reconciliation before another mutation. <button class="secondary" disabled={!online || Boolean(busy)} onclick={reconcileRuntime}>Check operation outcome</button></div>{/if}
          {#if serverTab === "Instances"}<div class="tabs instance-tabs" role="tablist" aria-label="Instance sections">{#each tabs as item}<button role="tab" aria-label={item} aria-selected={tab === item} class:active={tab === item} onclick={() => tab = item}>{item === "Peers / Devices" ? "Devices" : item === "DNS and Routing" ? "DNS" : item === "Deployment" ? "Deploy" : item}</button>{/each}</div>{/if}
          <div class="instance-content">
          {#if tab === "Overview"}<h3>Remote configuration</h3><dl class="overview-facts"><div><dt>Owning server</dt><dd>{host.display_name}</dd></div><div><dt>Endpoint</dt><dd>{draft.instance.endpoint.host}:{draft.instance.endpoint.port}</dd></div><div><dt>Peers / devices</dt><dd>{draft.peers.length}</dd></div><div><dt>Network</dt><dd>{draft.instance.network.ipv4_subnet}</dd></div><div><dt>Last saved</dt><dd>{new Date(selected.saved_at).toLocaleString()}</dd></div></dl>
          {:else if tab === "Peers / Devices"}
            <div class="table-wrap">
            <table><thead><tr><th>Name</th><th>Address</th><th>State</th><th>Local export</th><th>Action</th></tr></thead><tbody>{#each draft.peers as peer}<tr><td><input aria-label={"Peer name " + peer.display_name} bind:value={peer.display_name} /></td><td>{peer.ipv4_address}</td><td>{#if draft.instance.backend === "openvpn" || draft.instance.backend === "ikev2"}{peer.enabled ? "Active" : "Revoked"}{:else}<input aria-label={"Enable " + peer.display_name} type="checkbox" bind:checked={peer.enabled} />{/if}</td><td><button class="secondary" disabled={!online || dirty || !availability.find((item) => item.peer_id === peer.id)?.complete_export_available} onclick={() => exportPeer(peer.id)}>Export configuration</button>{#if !availability.find((item) => item.peer_id === peer.id)?.complete_export_available}<p>Private material unavailable on this client</p>{/if}</td><td>{#if (draft.instance.backend === "openvpn" || draft.instance.backend === "ikev2") && peer.enabled}<button class="secondary" disabled={Boolean(busy)} onclick={() => openDangerZone(draft!.instance.id, peer.id)}>Revoke in Danger Zone</button>{/if}</td></tr>{/each}</tbody></table>
            </div>
            <form class="remote-form" onsubmit={(event) => { event.preventDefault(); void addPeer(); }}><h3>Add peer / device</h3><label>Peer name<input required bind:value={peerName} /></label><label>DNS name (optional)<input bind:value={peerDns} /></label><p>Save or discard existing edits before creating a peer.</p>{#if !certificateAuthorityReady}<p>Deploy this instance once to establish its certificate authority before enrolling peers.</p>{/if}<button class="primary" disabled={!online || dirty || !certificateAuthorityReady || Boolean(busy)}>Create Peer on Server</button></form>
          {:else if tab === "DNS and Routing"}
            <label>Routing<select bind:value={draft.instance.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel</option></select></label>
            <div class="table-wrap">
            <table><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>Action</th></tr></thead><tbody>{#each draft.dns_records as record}<tr><td>{record.name}</td><td>{record.record_type}</td><td>{record.value}</td><td><button class="secondary" onclick={() => { draft!.dns_records = draft!.dns_records.filter((item) => item.id !== record.id); void retainDraft(); }}>Remove from draft</button></td></tr>{/each}</tbody></table>
            </div>
            <form class="remote-form" onsubmit={(event) => { event.preventDefault(); addDns(); }}><label>DNS record name<input required bind:value={dnsName} /></label><label>Record type<select bind:value={dnsType}>{#each ["A", "AAAA", "CNAME", "TXT", "SRV"] as type}<option>{type}</option>{/each}</select></label><label>Record value<input required bind:value={dnsValue} /></label><button class="secondary">Add to draft</button></form>
          {:else if tab === "Settings"}
            <form class="remote-form" oninput={applySettings} onchange={applySettings} onsubmit={(event) => { event.preventDefault(); applySettings(); }}><label>Instance name<input required bind:value={settingsForm.display_name} /></label><label>VPN endpoint<input required bind:value={settingsForm.endpoint_host} /></label><label>Listener port<input required type="number" min="1" max="65535" disabled={settingsForm.backend === "ikev2"} bind:value={settingsForm.endpoint_port} /></label><label>Private DNS zone<input required bind:value={settingsForm.dns_zone} /></label>{#if SettingsBackendForm}<SettingsBackendForm bind:form={settingsForm} />{/if}<button class="secondary">Keep local draft</button></form>
            <button class="secondary" disabled={Boolean(busy)} onclick={() => openDangerZone(draft!.instance.id)}>Open Danger Zone</button>
          {:else if tab === "Deployment"}
            {#if serverTab === "Logs"}
              <div class="table-wrap"><table><thead><tr><th>Operation</th><th>Desired revision</th><th>Result</th><th>Deployed revision</th><th>Recovery</th></tr></thead><tbody>{#each runtimeHistory as event}<tr><td>{event.operation.replaceAll("_", " ")}</td><td>{event.desired_revision}</td><td><span class="instance-state" data-state={event.succeeded ? "healthy" : "needs_deployment"}>{event.succeeded ? "Succeeded" : "Failed"}</span></td><td>{event.deployed_revision ?? "Unknown"}</td><td>{event.requires_recovery ? "Required" : "None"}</td></tr>{/each}</tbody></table>{#if !runtimeHistory.length}<div class="inventory-empty"><h3>No deployment history</h3><p>Remote operations for this instance will appear here.</p></div>{/if}</div>
            {:else if serverTab === "Backups"}
              <div class="section-toolbar"><h3>Runtime snapshots</h3><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={async () => { await task("Creating runtime backup", () => call("backup_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision })); if (!error) { notice = "Runtime backup created on server."; await loadBackups(); } }}>Create snapshot</button></div>
              <div class="table-wrap"><table><thead><tr><th>Snapshot</th><th>Created</th><th>Action</th></tr></thead><tbody>{#each backups as backup}<tr><td>{backup.name}</td><td>{new Date(backup.created_at).toLocaleString()}</td><td><button class="secondary" disabled={!online || dirty || Boolean(busy)} onclick={() => previewRestore(backup.name)}>Preview restore</button></td></tr>{/each}</tbody></table>{#if !backups.length}<div class="inventory-empty"><h3>No runtime snapshots</h3><p>Create a snapshot of the selected instance to populate this page.</p></div>{/if}</div>
              {#if restorePreview}<section class="alert"><div><h3>Restore deployed revision {restorePreview.deployed_revision ?? "unknown"}</h3><p>{restorePreview.identity_impact}</p><p>Saved desired revision {restorePreview.desired_revision} will remain unchanged.</p><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={restoreDeployment}>Restore Deployment</button></div></section>{/if}
            {:else}
            <div class="header-actions"><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={previewDeployment}>Preview / Deploy</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={async () => { const result = await task("Checking deployment health", () => call<InstanceHealth>("inspect_remote_health", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id })); if (result) health = result; }}>Check health</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={async () => { await task("Creating runtime backup", () => call("backup_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision })); if (!error) notice = "Runtime backup created on server."; }}>Create runtime backup</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadHistory}>View configuration history</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadRuntimeHistory}>View deployment history</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadBackups}>View runtime backups</button></div>
            {#if dirty}<p>Save local edits to the server before previewing deployment.</p>{/if}
            {#if plan}<h3>Deployment preview for saved revision {baseRevision}</h3>{#each plan.warnings as warning}<p class="danger">{warning}</p>{/each}<ul>{#each plan.operations as operation}<li>{operation.operation.replaceAll("_", " ")} {operation.path ?? operation.service ?? ""}</li>{/each}</ul><button class="primary" disabled={Boolean(busy)} onclick={deploy}>Apply saved revision {baseRevision}</button>{/if}
            {#if health}<h3>Deployment health</h3><dl><dt>Gateway</dt><dd>{health.gateway_running ? "Running" : "Stopped / unavailable"}</dd><dt>Backend</dt><dd>{health.backend_ready ? "Ready" : "Needs attention"}</dd><dt>Listeners</dt><dd>{health.listeners_ready ? "Ready" : "Needs attention"}</dd><dt>Deployed peer state</dt><dd>{health.client_state_matches ? "Matches" : "Needs attention"}</dd>{#if health.dns_required}<dt>Private DNS</dt><dd>{health.private_dns_resolves ? "Resolving" : "Needs attention"}</dd><dt>Public DNS</dt><dd>{health.public_dns_resolves ? "Resolving securely" : "Needs attention"}</dd>{/if}</dl>{#if health.details.length}<details><summary>Health details</summary><ul>{#each health.details as detail}<li>{detail}</li>{/each}</ul></details>{/if}{/if}
            {#each backups as backup}<div class="history-row"><span>{backup.name} · {new Date(backup.created_at).toLocaleString()}</span><button class="secondary" disabled={!online || dirty || Boolean(busy)} onclick={() => previewRestore(backup.name)}>Preview deployment restore</button></div>{/each}
            {#if restorePreview}<section class="alert"><div><h3>Restore deployed revision {restorePreview.deployed_revision ?? "unknown"}</h3><p>{restorePreview.identity_impact}</p><p>Saved desired revision {restorePreview.desired_revision} will remain unchanged.</p><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={restoreDeployment}>Restore Deployment</button></div></section>{/if}
            {#each history as revision}<div class="history-row"><span>Desired revision {revision.revision} · {new Date(revision.saved_at).toLocaleString()}</span><button class="secondary" disabled={!online || dirty || revision.revision === selected.revision || Boolean(busy)} onclick={() => restoreDesired(revision.revision)}>Restore Desired Configuration</button></div>{/each}
            {#each runtimeHistory as event}<div class="history-row"><span>{event.operation.replaceAll("_", " ")} · desired revision {event.desired_revision} · {event.succeeded ? "Succeeded" : "Failed"}{event.requires_recovery ? " · Recovery required" : ""}{event.deployed_revision == null ? "" : " · deployed revision " + event.deployed_revision}</span></div>{/each}
            {/if}
          {/if}
          </div>
        </section>
        </div></div>
      {:else}
        {#if serverTab === "Hosts"}<div class="prototype-split"><section class="card host-list-panel"><header><h2>Managed hosts</h2><span>{hosts.length} configured</span></header>{#each hosts as server}<button class:selected={server.id === selectedHostId} onclick={async () => { await selectServer(server.id); serverTab = "Hosts"; }}><span class="instance-symbol" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M11 7h6M11 17h6"/></svg></span><span><strong>{server.display_name}</strong><small>{server.ssh.username}@{server.ssh.hostname}:{server.ssh.port}</small></span><span class="instance-chevron" aria-hidden="true">›</span></button>{/each}</section><section class="card host-detail-panel"><div class="detail-hero"><div><p class="eyebrow">Host details</p><h2>{host.display_name}</h2><p>{host.ssh.username}@{host.ssh.hostname}:{host.ssh.port}</p></div><span class="instance-state" data-state={online ? "healthy" : "needs_deployment"}>{connection}</span></div><div class="host-actions"><button class="secondary" disabled={Boolean(busy)} onclick={refreshServer}>Refresh / Reconnect</button><button class="secondary" onclick={probeServer}>Verify SSH host identity</button><button class="secondary" onclick={inspectServer}>Inspect host readiness</button></div><div class="fact-grid"><div><span>Appliance identity</span><strong>{inventory?.identity.appliance_id ?? "Not synchronized"}</strong></div><div><span>Managed instances</span><strong>{inventory?.discovery.instances.length ?? "Unknown"}</strong></div><div><span>Last synchronized</span><strong>{inventory ? new Date(inventory.synchronized_at).toLocaleString() : "Never"}</strong></div><div><span>Connection</span><strong>{connection}</strong></div></div>{#if probe}<div class="host-verification"><h3>{probe.state === "changed" ? "Changed SSH host key" : "SSH host key"}</h3><p>{probe.key.sha256_fingerprint}</p><p>Verify this fingerprint through an independent trusted channel.</p><label>Exact verified fingerprint<input bind:value={fingerprint} /></label>{#if probe.state === "changed"}<label><input type="checkbox" bind:checked={replaceChanged} /> Explicitly replace the previously approved key</label>{/if}<button class="primary" disabled={fingerprint !== probe.key.sha256_fingerprint || (probe.state === "changed" && !replaceChanged)} onclick={approveIdentity}>Approve SSH identity</button></div>{/if}{#if inspection}<div class="inspection-panel"><p>{inspection.inspection.operating_system} · {inspection.inspection.architecture}</p><p>Docker: {inspection.inspection.docker_version ?? "Unavailable"} · Compose: {inspection.inspection.compose_version ?? "Unavailable"}</p><HostReadinessMatrix view={inspection} /></div>{/if}</section></div>
        {:else}
          {#if serverTab === "Overview"}
            <section class="server-hero"><div><p class="eyebrow">Network status</p><h2>{online ? `${inventory?.discovery.instances.length ?? 0} VPN ${(inventory?.discovery.instances.length ?? 0) === 1 ? "instance" : "instances"} configured` : connection === "offline" ? "Showing saved server data" : connection === "loading" ? "Connecting to server" : "Server needs attention"}</h2><p>{online ? `${inventory?.discovery.instances.length ?? 0} ${(inventory?.discovery.instances.length ?? 0) === 1 ? "instance" : "instances"} on ${host.display_name}. Deployment status and health are shown per instance.` : "Reconnect to read current remote state before saving or deploying changes."}</p></div><button class="hero-action" onclick={() => navigateSection("Instances")}>Manage instances <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg></button></section>
            <div class="metric-grid" aria-label="Server summary">
              <div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M11 7h6M11 17h6"/></svg></span><strong>{hosts.length}</strong><span class="metric-label">Managed hosts</span><small>SSH management targets</small></div>
              <div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg></span><strong>{inventory?.discovery.instances.length ?? "—"}</strong><span class="metric-label">VPN instances</span><small>On {host.display_name}</small></div>
              <div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg></span><strong>{inventory ? enabledPeerCount : "—"}</strong><span class="metric-label">Enabled devices</span><small>{inventory ? `${peerCount} total identities` : "Awaiting discovery"}</small></div>
              <div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></span><strong>{inventory ? dnsRecordCount : "—"}</strong><span class="metric-label">Private DNS records</span><small>Across discovered instances</small></div>
            </div>
            <section class="card activity-panel"><header><h2>Recent activity</h2><button class="activity-link" onclick={() => navigateSection("Logs")}>All logs →</button></header>{#if inventory}<div class="activity-row"><span class="activity-icon" aria-hidden="true">✓</span><div><strong>Server synchronized</strong><p>Remote inventory read from {host.display_name}</p></div><time>{new Date(inventory.synchronized_at).toLocaleTimeString()}</time></div>{:else}<div class="inventory-empty"><h3>No recent activity available</h3><p>Connect to this server to read its current state.</p></div>{/if}</section>
            <section class="quick-actions"><h2>Quick actions</h2><div><button class="card" onclick={() => page = "add-server"}><span class="instance-symbol" aria-hidden="true">+</span><span><strong>Add a host</strong><small>Register another SSH management target</small></span><span aria-hidden="true">›</span></button><button class="card" onclick={() => navigateSection("Devices")}><span class="instance-symbol" aria-hidden="true">▯</span><span><strong>Enroll a device</strong><small>Create a peer on the selected server</small></span><span aria-hidden="true">›</span></button><button class="card" onclick={() => navigateSection("DNS")}><span class="instance-symbol" aria-hidden="true">◎</span><span><strong>Add a DNS record</strong><small>Manage private name resolution</small></span><span aria-hidden="true">›</span></button></div></section>
          {/if}
          {#if serverTab === "Instances"}<div class="metric-grid instance-metrics" aria-label="Instance summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg></span><strong>{inventory?.discovery.instances.length ?? "—"}</strong><span class="metric-label">Total instances</span><small>On {host.display_name}</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></span><strong>{inventory?.discovery.instances.filter((item) => inventory?.discovery.deployments?.[item.configuration.instance.id]?.deployed_revision != null).length ?? "—"}</strong><span class="metric-label">Deployed</span><small>Deployment revision recorded</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><strong>{inventory ? pendingCount : "—"}</strong><span class="metric-label">Pending deployment</span><small>Saved and deployed revisions differ</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg></span><strong>{inventory ? peerCount : "—"}</strong><span class="metric-label">Assigned devices</span><small>Across this server</small></div></div>{/if}
          {#if serverTab === "Overview" || serverTab === "Instances"}<div class:prototype-split={serverTab === "Instances"} class:instance-split={serverTab === "Instances"}><section class="card instances-panel"><header><div>{#if serverTab === "Overview"}<p class="eyebrow">Remote inventory</p>{/if}<h2>{serverTab === "Instances" ? "Your instances" : "Instances"}</h2></div>{#if serverTab === "Overview"}<button class="primary" disabled={!online || Boolean(busy)} onclick={() => { instanceForm = newInstanceForm(selectedHostId, host!.ssh.hostname); page = "create-instance"; }}>Create Instance</button>{:else}<span class="panel-caption">{inventory?.discovery.instances.length ?? 0} total</span>{/if}</header>
            {#if inventory?.discovery.instances.length}<div class="instance-grid">{#each inventory.discovery.instances as instance}<button class="instance-card" onclick={() => openInstance(instance)}><span class="instance-symbol" aria-hidden="true">{nameOf(instance.configuration.instance.backend).slice(0, 2).toUpperCase()}</span><span class="instance-card-info"><strong>{instance.configuration.instance.display_name}</strong><small>{nameOf(instance.configuration.instance.backend)} · {host.display_name}</small><small>{instance.configuration.peers.length} peers · saved revision {instance.revision}</small></span><span class="instance-state" data-state={inventory.discovery.deployments?.[instance.configuration.instance.id]?.deployed_revision === instance.revision ? "healthy" : "needs_deployment"}>{inventory.discovery.deployments?.[instance.configuration.instance.id]?.deployed_revision === instance.revision ? "Revisions match" : inventory.discovery.deployments?.[instance.configuration.instance.id]?.deployed_revision == null ? "Deployment unknown" : "Pending deployment"}</span><span class="instance-chevron" aria-hidden="true">›</span></button>{/each}</div>
            {:else if online && inventory && Object.keys(inventory.discovery.errors).length === 0}<div class="inventory-empty"><span class="empty-symbol" aria-hidden="true">▣</span><h3>No VPN instances configured on this server.</h3><p>Create an instance to save its configuration on this server.</p></div>
            {:else if connection === "loading"}<p class="inventory-message">Discovering remote instances…</p>{:else if !inventory}<p class="inventory-message">Connect and verify this server to discover its instances.</p>{/if}
          </section>{#if serverTab === "Instances"}<section class="card inventory-empty"><span class="empty-symbol" aria-hidden="true">▣</span><h3>Select an instance</h3><p>Its saved configuration and deployment controls appear here.</p></section>{/if}</div>{:else if serverTab !== "Overview"}<section class="card inventory-empty"><span class="empty-symbol" aria-hidden="true">▣</span><h3>No instances available on {host.display_name}</h3><p>Create an instance before managing {serverTab.toLowerCase()}.</p></section>{/if}
        {/if}
      {/if}
    {/if}
    {#each candidates.filter((candidate) => !candidate.supported) as candidate}<section class="card"><h2>Unsupported local configuration: {candidate.display_name}</h2><p>Its source data and remote deployment are preserved. Export recovery metadata before retiring this local record.</p><button class="secondary" onclick={async () => { const destination = await save({ defaultPath: "vpnctl-recovery.json" }); if (destination) await task("Exporting recovery metadata", () => call("export_legacy_recovery", { instanceId: candidate.instance_id, destination })); }}>Export recovery metadata</button></section>{/each}
  </main>
  </div>
</div>

<style>
  aside h2 { font-size: .8rem; color: #9fb3c8; padding: 0 13px; }
  .card { margin-top: 20px; padding: 24px; }
  .remote-form { display: grid; gap: 16px; max-width: 700px; }
  .remote-form label { display: grid; gap: 6px; }
  input, select { padding: 9px; border: 1px solid #bcccdc; border-radius: 6px; max-width: 100%; }
  table { width: 100%; text-align: left; border-collapse: collapse; margin: 20px 0; }
  td, th { padding: 12px 8px; border-bottom: 1px solid #e4e7eb; }
  td p { font-size: 12px; color: #627d98; }
  .instance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
  .instance-card { display: grid; gap: 10px; text-align: left; padding: 20px; border: 1px solid #bcccdc; background: #f8fafc; border-radius: 8px; cursor: pointer; color: #102a43; }
  .instance-card span { font-size: 13px; }
  .history-row { display: flex; justify-content: space-between; gap: 16px; margin-top: 16px; }
  dl { display: grid; grid-template-columns: 160px 1fr; gap: 12px; }
  dd { margin: 0; }
  .tabs { flex-wrap: wrap; }
  @media (max-width: 900px) { header { flex-wrap: wrap; gap: 12px; } .header-actions { flex-wrap: wrap; } table { display: block; overflow-x: auto; } }
</style>
