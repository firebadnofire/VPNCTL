<script lang="ts">
  import { formFeedback } from "./lib/form-feedback";
  import { configurationStatus } from "./lib/configuration-presentation";
  import BlockingContent from "./lib/components/BlockingContent.svelte";
  import ConfigurationReview from "./lib/components/ConfigurationReview.svelte";
  import { createNotifications } from "./lib/notifications";
  import Notifications from "./lib/components/Notifications.svelte";
  import ModalShell from "./lib/components/ModalShell.svelte";
  import Tooltip from "./lib/components/Tooltip.svelte";
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
  type ConnectionState = "disconnected" | "loading" | "connected" | "offline" | "error";
  let connection: ConnectionState = "disconnected";
  let hostSessions: Record<string, { inventory: RemoteInventory | null; connection: ConnectionState; error: AppError | null; errorOperation: string }> = {};
  let connectionTimer: ReturnType<typeof setInterval> | undefined;
  let connectionGeneration = 0;
  function rememberHost() {
    if (selectedHostId) hostSessions = { ...hostSessions, [selectedHostId]: { inventory, connection, error, errorOperation } };
  }
  async function checkConnections() {
    if (busy || !Object.values(hostSessions).some(session => session.connection === "connected")) return;
    const epoch = contextEpoch, generation = connectionGeneration, sessions = hostSessions;
    try {
      const connected = await call<string[]>("connected_hosts");
      if (epoch !== contextEpoch || generation !== connectionGeneration) return;
      for (const [id, session] of Object.entries(sessions)) {
        if (hostSessions[id] !== session) continue;
        if (session.connection === "connected" && !connected.includes(id)) {
          const retained = session.inventory ? { ...session.inventory, cached: true } : null;
          hostSessions = { ...hostSessions, [id]: { ...session, inventory: retained, connection: retained ? "offline" : "disconnected" } };
          if (selectedHostId === id && connection === "connected") { inventory = retained; connection = retained ? "offline" : "disconnected"; closeExport(); }
        }
      }
    } catch (cause) {
      if (epoch === contextEpoch && generation === connectionGeneration && !error) { error = cause as AppError; errorOperation = "Checking SSH connections"; }
    }
  }
  let page: "server" | "add-server" | "create-instance" | "migration" = "server";
  let serverTab = "Overview";
  let blockingDirty = false;
  function blockingChanged(value: boolean) { blockingDirty = value; }
  async function leaveBlocking() {
    if (!blockingDirty) return true;
    if (!await confirm("Discard unsaved blocking settings before leaving this instance? Saved server settings are unchanged.", { title: "Unsaved blocking settings", kind: "warning" })) return false;
    blockingDirty = false; return true;
  }
  let selected: Manifest | null = null;
  let draft: Configuration | null = null;
  let baseRevision = 0;
  let tab = "Overview";
  let busy = "";
  let initialized = false;
  let error: AppError | null = null;
  let errorOperation = "";
  let conflictContexts: string[] = [];
  let lastTaskFailed = false;
  let review: { local: Configuration; server: Configuration; base?: Configuration } | null = null;
  let contextEpoch = 0;
  const notifications = createNotifications();
  const { notify } = notifications;
  const activity = notifications.history;
  let showActivity = false;
  let dialogTrigger: HTMLElement | null = null;
  function openActivity(event: MouseEvent) { dialogTrigger = event.currentTarget as HTMLElement; showActivity = true; }
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
  let observedHealth: Record<string, { value: InstanceHealth; checkedAt: string }> = {};
  function healthReady(value: InstanceHealth) { return value.gateway_running && value.backend_ready && value.listeners_ready && value.client_state_matches && (!value.dns_required || (value.dns_running && value.private_dns_resolves && value.public_dns_resolves)); }
  function healthLabel(instanceId: string) {
    const check = observedHealth[`${selectedHostId}/${instanceId}`];
    return !online || !check ? "Health not checked" : healthReady(check.value) ? "Running · health verified" : "Service needs attention";
  }
  async function checkHealth() {
    if (!selected || !online || busy) return;
    const hostId = selectedHostId, instanceId = selected.configuration.instance.id;
    const result = await task("Checking deployment health", () => call<InstanceHealth>("inspect_remote_health", { hostId, instanceId }));
    if (result) {
      health = result; observedHealth = { ...observedHealth, [`${hostId}/${instanceId}`]: { value: result, checkedAt: new Date().toISOString() } };
      notify(healthReady(result) ? "VPN health verified." : "VPN health check found issues. Review deployment health.", healthReady(result) ? "success" : "warning");
    }
  }
  let backups: { name: string; created_at: string }[] = [];
  let restorePreview: RemoteRestorePreview | null = null;
  let instanceForm = newInstanceForm();
  let settingsForm = newInstanceForm();
  let peerName = "";
  let peerDns = "";
  let peerCreateDns = true;
  let dnsName = "";
  let dnsValue = "";
  let dnsType = "A";
  let hostForm = { display_name: "", hostname: "", username: "", port: 22, private_key_path: "", passphrase: "" };
  let defaultUsername = "";
  let draftWrite: Promise<boolean> = Promise.resolve(true);
  let qrImage = "";
  let exportPeerId = "";
  let exportGeneration = 0;
  let enrolledPeerId = "";
  $: exportDevice = selected?.configuration.peers.find(peer => peer.id === exportPeerId);
  $: exportReason = !online ? "Reconnect to retrieve the current server configuration." : dirty || staleDraft ? "Save or discard your edits and resolve server changes before exporting." : observation?.deployed_revision == null ? "Deploy this instance once to establish its server identity before exporting." : "";
  function closeExport() { exportGeneration++; exportPeerId = ""; qrImage = ""; }
  function openExport(peerId: string, trigger: EventTarget | null) { dialogTrigger = trigger as HTMLElement; closeExport(); exportPeerId = peerId; }
  let draftTimer: ReturnType<typeof setTimeout> | undefined;
  let dangerInstanceId = "";
  let dangerPeerId = "";
  let pendingDrop: { hostId: string; requestId: string; operation: { operation: string; instance_id: string; peer_id: string; expected_revision: number; revoke_request_id: string; confirmed: boolean } } | null = null;
  $: dropPeers = dangerInstance?.configuration.peers ?? [];
  $: dropPeer = dropPeers.find(peer => peer.id === dangerPeerId) ?? dropPeers[0] ?? null;
  $: supportsDropPeer = Boolean(inventory?.identity.capabilities?.includes("drop_peer_v1"));
  let pendingCleanup: { operationId: string; hostIds: string[]; resetPreferences: boolean } | null = null;
  let pendingArchiveRestore: { hostId: string; instanceId: string; expectedRevision: number; requestId: string } | null = null;
  let pendingInstanceArchive: { hostId: string; instanceId: string; input: { host_id: string; expected_revision: number; request_id: string; configuration: Configuration } } | null = null;
  onDestroy(() => {
    clearInterval(connectionTimer); contextEpoch++; closeExport(); clearTimeout(draftTimer); notifications.destroy(); });
  function scheduleDraft() { closeExport(); clearTimeout(draftTimer); draftTimer = setTimeout(() => { void retainDraft(); }, 300); }
  $: host = hosts.find((item) => item.id === selectedHostId);
  $: eligibleLocalLegacyInstances = candidates.filter((candidate) => candidate.supported);
  $: showMigrationUI = eligibleLocalLegacyInstances.length > 0;
  $: staleDraft = Boolean(selected && (baseRevision !== selected.revision || conflictContexts.includes(`${selectedHostId}/${selected.configuration.instance.id}`)));
  $: dirty = Boolean(selected && draft && JSON.stringify(draft) !== JSON.stringify(selected.configuration));
  $: online = connection === "connected" && !inventory?.cached;
  $: supportsInstanceArchives = Boolean(inventory?.identity.capabilities?.includes("instance_archives_v1"));
  $: observation = selected ? inventory?.discovery.deployments?.[selected.configuration.instance.id] : undefined;
  $: peerCount = inventory?.discovery.instances.reduce((count, item) => count + item.configuration.peers.length, 0) ?? 0;
  $: enabledPeerCount = inventory?.discovery.instances.reduce((count, item) => count + item.configuration.peers.filter((peer) => peer.enabled).length, 0) ?? 0;
  $: dnsRecordCount = inventory?.discovery.instances.reduce((count, item) => count + item.configuration.dns_records.length, 0) ?? 0;
  $: pendingCount = inventory?.discovery.instances.filter(item => { const revision = inventory?.discovery.deployments?.[item.configuration.instance.id]?.deployed_revision; return revision != null && revision !== item.revision; }).length ?? 0;
  $: unknownDeploymentCount = inventory?.discovery.instances.filter(item => inventory?.discovery.deployments?.[item.configuration.instance.id]?.deployed_revision == null).length ?? 0;
  $: pendingOperationCount = Object.values(inventory?.discovery.deployments ?? {}).filter(item => item.pending_operation).length;
  $: serviceIssueCount = inventory?.discovery.instances.filter(item => online && observedHealth[`${selectedHostId}/${item.configuration.instance.id}`] && !healthReady(observedHealth[`${selectedHostId}/${item.configuration.instance.id}`].value)).length ?? 0;
  $: connectionLabel = probe?.state === "changed" || error?.code === "host_key_changed" || error?.code === "host_key_changed_during_approval" ? "Host identity changed" : error?.code === "host_key_untrusted" ? "Not yet verified" : error?.code === "ssh_authentication" ? "Authentication required" : connection === "connected" ? "Connected" : connection === "loading" ? "Connecting" : connection === "disconnected" ? "Not connected" : "Connection failed";
  $: certificateBackend = draft?.instance.backend === "openvpn" || draft?.instance.backend === "ikev2";
  $: certificateAuthorityReady = !certificateBackend || observation?.deployed_revision != null;
  $: BackendForm = backendForms[instanceForm.backend];
  $: SettingsBackendForm = backendForms[settingsForm.backend];
  $: dangerInstance = inventory?.discovery.instances.find((item) => item.configuration.instance.id === dangerInstanceId) ?? inventory?.discovery.instances[0] ?? null;
  $: dangerPeers = dangerInstance && ["openvpn", "ikev2"].includes(dangerInstance.configuration.instance.backend) ? dangerInstance.configuration.peers.filter((peer) => peer.enabled) : [];
  $: dangerPeer = dangerPeers.find((peer) => peer.id === dropPeer?.id) ?? null;
  $: archivedInstances = inventory?.discovery.archived_instances ?? [];
  const copy = <T,>(value: T): T => JSON.parse(JSON.stringify(value));
  const nameOf = (kind: VpnBackendKind) => backends.find((backend) => backend.kind === kind)?.name ?? "Unsupported backend";

  async function task<T>(label: string, action: () => Promise<T>): Promise<T | undefined> {
    const epoch = contextEpoch;
    connectionGeneration++;
    busy = label; lastTaskFailed = false;
    try {
      const result = await action();
      if (epoch !== contextEpoch) return undefined;
      if (errorOperation === label) { error = null; errorOperation = ""; }
      return result;
    }
    catch (cause) {
      if (epoch === contextEpoch) {
        error = cause as AppError; errorOperation = label; lastTaskFailed = true;
        notifications.record(`${label} failed.`, "warning");
        if (error.code === "revision_conflict" && label !== "Updating DNS blocking" && selected) {
          const key = `${selectedHostId}/${selected.configuration.instance.id}`;
          conflictContexts = [...new Set([...conflictContexts, key])];
        }
      }
      return undefined;
    }
    finally { if (epoch === contextEpoch) busy = ""; }
  }
  onMount(async () => {
    await task("Loading saved servers", async () => {
      const [savedHosts, legacy, info] = await Promise.all([call<DockerHost[]>("list_hosts"), call<LegacyCandidate[]>("legacy_candidates"), call<{ system_username: string }>("app_info")]);
      hosts = savedHosts; candidates = legacy; defaultUsername = info.system_username; hostForm.username = defaultUsername;
    });
    // Loading profiles is local only. A host click establishes its connection.
    initialized = true;
    connectionTimer = setInterval(checkConnections, 5000);
  });
  async function selectServer(id: string, section = "Overview", connect = true) {
    if (blockingDirty && !await leaveBlocking()) return;
    if (dirty && !(await retainDraft())) return;
    rememberHost();
    closeExport(); enrolledPeerId = "";
    contextEpoch++; busy = ""; review = null; error = null; errorOperation = "";
    selectedHostId = id; selected = null; draft = null; inventory = null; inspection = null; probe = null;
    dangerInstanceId = ""; dangerPeerId = "";
    plan = null; health = null; backups = []; restorePreview = null; page = "server"; serverTab = section;
    const session = hostSessions[id];
    connection = session?.connection ?? "disconnected";
    inventory = session?.inventory ?? null; error = session?.error ?? null; errorOperation = session?.errorOperation ?? "";
    if (connect && connection !== "connected") await refreshServer();
  }
  async function navigateSection(section: string) {
    if (blockingDirty && !await leaveBlocking()) return;
    if (dirty && !(await retainDraft())) return;
    closeExport();
    contextEpoch++; busy = ""; review = null;
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
    const id = selectedHostId, epoch = contextEpoch;
    closeExport();
    connection = "loading";
    // Reconnection invalidates earlier health observations; SSH alone never verifies VPN health.
    observedHealth = {}; health = null;
    const fresh = await task("Synchronizing server and checking helper", () => call<RemoteInventory>("discover_remote", { hostId: id }));
    if (selectedHostId !== id || epoch !== contextEpoch) return;
    if (fresh) {
      const hadEdits = dirty;
      inventory = fresh; connection = "connected"; notifications.record("Server synchronized.");
      if (pendingInstanceArchive && fresh.discovery.archived_instances?.some((item) => item.request_id === pendingInstanceArchive?.input.request_id)) pendingInstanceArchive = null;
      if (selected) {
        const current = fresh.discovery.instances.find((item) => item.configuration.instance.id === selected?.configuration.instance.id);
        if (current) {
          selected = current;
          if (!hadEdits) {
            conflictContexts = conflictContexts.filter(key => key !== `${id}/${current.configuration.instance.id}`);
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
      try { const cached = await call<RemoteInventory | null>("cached_remote_inventory", { hostId: id }); if (epoch !== contextEpoch) return; inventory = cached; if (inventory) connection = "offline"; }
      catch (cause) { if (epoch === contextEpoch) error = cause as AppError; }
    }
    if (epoch === contextEpoch) rememberHost();
  }
  async function retainDraft() {
    clearTimeout(draftTimer);
    if (!draft || !selected || !dirty) return draftWrite;
    const epoch = contextEpoch;
    const retained = { host_id: selectedHostId, base_revision: baseRevision, configuration: copy(draft) };
    draftWrite = draftWrite.then(async () => {
      try { await call<void>("save_remote_draft", { draft: retained }); return true; }
      catch (cause) { if (epoch === contextEpoch) error = cause as AppError; return false; }
    });
    return draftWrite;
  }
  async function openInstance(manifest: Manifest) {
    if (blockingDirty && !await leaveBlocking()) return;
    if (dirty && !(await retainDraft())) return;
    if (serverTab === "Overview" || serverTab === "Hosts") serverTab = "Instances";
    closeExport();
    if (selected?.configuration.instance.id !== manifest.configuration.instance.id) { error = null; errorOperation = ""; enrolledPeerId = ""; }
    contextEpoch++; busy = ""; review = null;
    const epoch = contextEpoch;
    selected = manifest; draft = copy(manifest.configuration); baseRevision = manifest.revision;
    plan = null; health = null; backups = []; restorePreview = null;
    tab = serverTab === "Devices" ? "Peers / Devices" : serverTab === "DNS" ? "DNS and Routing" : ["Backups", "Logs"].includes(serverTab) ? "Deployment" : "Overview";
    availability = []; history = []; runtimeHistory = [];
    let local = await task("Loading local draft", () => call<RemoteDraft | null>("load_remote_draft", { hostId: selectedHostId, instanceId: manifest.configuration.instance.id }));
    if (epoch !== contextEpoch) return;
    if (local && online) {
      let obsoleteCopy = JSON.stringify(local.configuration) === JSON.stringify(manifest.configuration);
      if (!obsoleteCopy && local.base_revision !== manifest.revision) {
        const previous = await task("Checking retained draft", () => call<Manifest[]>("remote_history", { hostId: selectedHostId, instanceId: manifest.configuration.instance.id }));
        if (epoch !== contextEpoch) return;
        if (!previous) { draft = local.configuration; baseRevision = local.base_revision; return; }
        obsoleteCopy = previous.some((item) => item.revision === local!.base_revision && JSON.stringify(item.configuration) === JSON.stringify(local!.configuration));
      }
      if (obsoleteCopy) {
        clearTimeout(draftTimer);
        if (!await draftWrite) return;
        const discarded = await task("Clearing unchanged retained draft", async () => { await call<void>("discard_remote_draft", { hostId: selectedHostId, instanceId: manifest.configuration.instance.id }); return true; });
        if (!discarded || epoch !== contextEpoch) return;
        local = null;
      }
    }
    if (local) { draft = local.configuration; baseRevision = local.base_revision; notify("Unsaved local edits restored. Saving requires revision validation.", "info"); }
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
      await draftWrite;
      draftWrite = Promise.resolve(true);
      await task("Discarding local draft", () => call<void>("discard_remote_draft", { hostId: selectedHostId, instanceId: fresh.configuration.instance.id }));
      if (!lastTaskFailed) {
        error = null; errorOperation = ""; review = null;
        conflictContexts = conflictContexts.filter(key => key !== `${selectedHostId}/${fresh.configuration.instance.id}`);
        selected = null; draft = null;
        await openInstance(fresh);
      }
    }
  }
  async function reviewDifferences(event: MouseEvent) {
    dialogTrigger = event.currentTarget as HTMLElement;
    if (!selected || !draft || !online || busy) return;
    const hostId = selectedHostId, instanceId = selected.configuration.instance.id;
    const local = copy(draft), revision = baseRevision;
    const latest = await task("Reading latest configuration", () => call<Manifest>("read_remote", { hostId, instanceId }));
    if (!latest) return;
    selected = latest; plan = null;
    const versions = await task("Reading original configuration", () => call<Manifest[]>("remote_history", { hostId, instanceId }));
    if (selectedHostId !== hostId || selected?.configuration.instance.id !== instanceId) return;
    review = { local, server: latest.configuration, base: versions?.find(item => item.revision === revision)?.configuration };
  }
  async function saveDraft() {
    if (!draft || !selected || !online || staleDraft || busy) return;
    const controls = document.querySelectorAll<HTMLFormElement | HTMLInputElement>("[data-draft-form], [data-draft-field]");
    for (const control of controls) if (!control.reportValidity()) return;
    if (!await retainDraft()) return;
    const saved = await task("Saving to server", () => call<Manifest>("save_remote_configuration", { input: { host_id: selectedHostId, expected_revision: baseRevision, request_id: crypto.randomUUID(), configuration: draft } }));
    if (saved) {
      await task("Clearing saved draft", () => call<void>("discard_remote_draft", { hostId: selectedHostId, instanceId: saved.configuration.instance.id }));
      if (lastTaskFailed) return;
      selected = saved; draft = copy(saved.configuration); baseRevision = saved.revision; plan = null;
      notify("Saved to server. Preview deployment to apply this revision."); await refreshServer();
    }
  }
  async function createInstance() {
    if (busy || !online) return;
    const created = await task("Creating instance on server", () => call<Manifest>("create_remote_instance", { input: {
      host_id: selectedHostId, display_name: instanceForm.display_name, endpoint_host: instanceForm.endpoint_host,
      backend: instanceForm.backend, backend_settings: backendSettingsFromForm(instanceForm), endpoint_port: instanceForm.endpoint_port,
      ipv4_subnet: instanceForm.ipv4_subnet, dns_zone: instanceForm.dns_zone, routing_mode: instanceForm.routing_mode,
    } }));
    if (created) { notify("Instance saved on the server. Deploy separately when ready."); page = "server"; await refreshServer(); await openInstance(created); }
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
    if (!selected || dirty || staleDraft || busy || !online) return;
    clearTimeout(draftTimer);
    const hostId = selectedHostId;
    const instanceId = selected.configuration.instance.id;
    const existingPeerIds = new Set(selected.configuration.peers.map(peer => peer.id));
    const saved = await task("Adding device", async () => {
      if (!await draftWrite) throw { code: "draft_write_failed", message: "A previous draft could not be saved. Reload from Server before adding a client." };
      return await call<Manifest>("add_remote_peer", { hostId, expectedRevision: selected!.revision,
        input: { instance_id: instanceId, display_name: peerName, user_id: null, dns_name: peerCreateDns ? peerDns.trim() || peerName.trim() : null, preshared_key: true, create_dns_record: peerCreateDns } });
    });
    if (!saved) return;
    peerName = ""; peerDns = ""; peerCreateDns = true;
    selected = saved; draft = copy(saved.configuration); baseRevision = saved.revision; plan = null;
    enrolledPeerId = saved.configuration.peers.find(peer => !existingPeerIds.has(peer.id))?.id ?? "";
    const cleared = await task("Clearing previous client draft", async () => {
      await call<void>("discard_remote_draft", { hostId, instanceId }); return true;
    });
    if (!cleared) { notify("Client saved. Previous local draft could not be cleared; reload before continuing."); return; }
    notify("Device added to the saved configuration. Deploy when you are ready to enable access.");
    await refreshServer();
    const result = await task("Checking configuration availability", () => call<PeerAvailability[]>("remote_peer_availability", { hostId, instanceId }));
    if (result) availability = result;
  }
  async function showPeerQr(peerId: string) {
    if (!selected || exportReason || busy || peerId !== exportPeerId) return;
    const generation = exportGeneration;
    qrImage = "";
    const svg = await task("Preparing private configuration QR code", () => call<string>("remote_peer_qr_svg", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, peerId }));
    if (svg && generation === exportGeneration && peerId === exportPeerId) qrImage = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
  }
  async function copyPeer(peerId: string) {
    if (!selected || exportReason || busy) return;
    const copied = await task("Copying private configuration", async () => {
      await call<void>("copy_remote_peer_configuration", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, peerId }); return true;
    });
    if (copied) notify("Configuration copied. Keep your clipboard private.");
  }
  async function exportPeer(peerId: string) {
    if (!selected || exportReason || busy) return;
    const hostId = selectedHostId, instanceId = selected.configuration.instance.id, epoch = contextEpoch;
    const extension = selected.configuration.instance.backend === "openvpn" ? "client.ovpn" : selected.configuration.instance.backend === "ikev2" ? "client.p12" : "client.conf";
    const exported = await task("Downloading private configuration", async () => {
      const destination = await save({ title: "Download complete device configuration", defaultPath: extension });
      if (!destination || epoch !== contextEpoch) return false;
      await call<void>("export_remote_peer", { hostId, instanceId, peerId, destination }); return true;
    });
    if (exported) notify("Configuration downloaded. Keep the file private.");
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
      await draftWrite;
      await call("cleanup_local", { ...target, confirmed: true });
      pendingCleanup = null;
      hosts = hosts.filter((item) => !target.hostIds.includes(item.id));
      hostSessions = Object.fromEntries(Object.entries(hostSessions).filter(([id]) => !target.hostIds.includes(id)));
      candidates = candidates.filter((item) => !target.hostIds.includes(item.host_id));
      selectedHostId = ""; inventory = null; selected = null; draft = null; inspection = null; probe = null;
      plan = null; health = null; backups = []; restorePreview = null; availability = []; history = []; runtimeHistory = [];
      dangerInstanceId = ""; dangerPeerId = ""; connection = "disconnected";
      if (resetPreferences) {
        instanceForm = newInstanceForm(); settingsForm = newInstanceForm();
        hostForm = { display_name: "", hostname: "", username: defaultUsername, port: 22, private_key_path: "", passphrase: "" };
        peerName = ""; peerDns = ""; peerCreateDns = true; dnsName = ""; dnsValue = ""; dnsType = "A";
        fingerprint = ""; replaceChanged = false; migrationPreview = null; migrationDestination = "";
      }
      return true;
    });
    if (completed) {
      notify(resetPreferences ? "Local Factory Reset completed. VPN recovery data is preserved; servers are unchanged." : "Host removed locally. VPN recovery data is preserved; server instances keep running.");

    }
  }
  async function archiveDangerInstance() {
    if (busy || !online || !supportsInstanceArchives || !dangerInstance || pendingCleanup) return;
    const hostId = selectedHostId;
    const instanceId = dangerInstance.configuration.instance.id;
    if (pendingInstanceArchive && (pendingInstanceArchive.hostId !== hostId || pendingInstanceArchive.instanceId !== instanceId)) return;
    const completed = await task("Archiving instance", async () => {
      const fresh = pendingInstanceArchive ? null : await call<Manifest>("read_remote", { hostId, instanceId });
      const input = pendingInstanceArchive?.input ?? { host_id: hostId, expected_revision: fresh!.revision, request_id: crypto.randomUUID(), configuration: fresh!.configuration };
      if (!await confirm(`Stop and archive ${input.configuration.instance.display_name} on ${host?.display_name}? Connected VPN users will lose service. Saved history, server recovery data, and local client keys are retained. Local drafts are not applied. Restore the instance from Backups.`, { title: "Archive instance on server", kind: "warning" })) return false;
      pendingInstanceArchive = { hostId, instanceId, input };
      await call("remove_remote_configuration", { input, confirmed: true });
      pendingInstanceArchive = null;
      return true;
    });
    if (error?.code === "helper_upgrade_required" && inventory) {
      pendingInstanceArchive = null;
      inventory = { ...inventory, identity: { ...inventory.identity, capabilities: [] } };
    }
    if (completed) { notify("Instance archived on server. History and recovery data are retained."); await refreshServer(); }
  }
  async function checkDropOutcome() {
    if (!pendingDrop || busy || !online || pendingDrop.hostId !== selectedHostId) return;
    const input = pendingDrop;
    const completed = await task("Checking device removal outcome", async () => {
      const committed = await call<Manifest | null>("reconcile_remote_save", { hostId: input.hostId, instanceId: input.operation.instance_id, mutationId: input.requestId });
      if (committed) { pendingDrop = null; return true; }
      if (await confirm("The removal has not committed. A certificate may already have been revoked. Reload current server state and return to device selection? You will confirm any new removal separately.", { title: "Review incomplete removal", kind: "warning" })) { pendingDrop = null; return true; }
      return false;
    });
    if (completed) await refreshServer();
  }
  async function dropDangerPeer() {
    if (busy || !online || !dangerInstance || !dropPeer || !supportsDropPeer || pendingCleanup) return;
    const target = pendingDrop;
    if (target && (target.hostId !== selectedHostId || target.operation.instance_id !== dangerInstance.configuration.instance.id || target.operation.peer_id !== dropPeer.id)) return;
    const completed = await task("Dropping device", async () => {
      let input = target;
      if (!input) {
        const hostId = selectedHostId, instanceId = dangerInstance!.configuration.instance.id, peerId = dropPeer!.id;
        const fresh = await call<Manifest>("read_remote", { hostId, instanceId });
        const device = fresh.configuration.peers.find(peer => peer.id === peerId);
        if (!device) throw { code: "peer_changed", message: "This device changed on the server. Reconnect before removing it." };
        const certificates = ["openvpn", "ikev2"].includes(fresh.configuration.instance.backend);
        if (!await confirm(`Drop ${device.display_name} from ${fresh.configuration.instance.display_name} on ${host?.display_name}? Its managed DNS records will also be removed. ${certificates ? "Its certificate will be revoked first; revocation cannot be reversed. " : ""}Deploy afterward to apply access changes. Local keys, exports, and recovery history are preserved.`, { title: "Drop Device", kind: "warning" })) return false;
        input = { hostId, requestId: crypto.randomUUID(), operation: { operation: "drop_peer", instance_id: instanceId, peer_id: peerId, expected_revision: fresh.revision, revoke_request_id: crypto.randomUUID(), confirmed: true } };
        pendingDrop = input;
      }
      await call<Manifest>("drop_remote_peer", input);
      pendingDrop = null; return true;
    });
    if (completed) { notify("Device dropped from saved configuration. Deploy to apply access changes."); await refreshServer(); }
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
    if (completed) { notify("Certificate revoked in saved configuration. Deploy the instance to apply the revocation."); await refreshServer(); }
  }
  function addDns() {
    if (!draft || !dnsName.trim() || !dnsValue.trim() || staleDraft || busy) return;
    draft.dns_records = [...draft.dns_records, { id: crypto.randomUUID(), instance_id: draft.instance.id, name: dnsName, record_type: dnsType as "A", value: dnsValue, ttl: 300, enabled: true }];
    dnsName = ""; dnsValue = ""; void retainDraft();
  }
  async function previewDeployment() {
    if (!selected || dirty || staleDraft || busy || !online) return;
    const result = await task("Previewing saved revision", () => call<RemotePlan>("preview_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: selected!.revision }));
    if (result) plan = result;
  }
  async function deploy() {
    if (!selected || dirty || busy || !plan || !await confirm("Deploy saved revision " + selected.revision + " on " + host?.display_name + "?", { title: "Apply deployment", kind: "warning" })) return;
    if (!online || staleDraft) return;
    const deployed = await task("Deploying saved revision", async () => {
      const result = await call<{ status: string }>("apply_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: selected!.revision, expectedStateHash: plan!.desired_state_hash, requestId: crypto.randomUUID() });
      if (result.status !== "succeeded") throw { code: "deployment_failed", message: "Deployment did not succeed. Check operation outcome and deployment health before retrying." };
      return true;
    });
    plan = null; if (deployed) { notify("Deployment completed successfully."); enrolledPeerId = ""; await refreshServer(); }
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
      notify(status === "unresolved" ? "The operation outcome is unresolved. Inspect the remote runtime and recovery backup before another mutation." :
        status === "committed" ? "The operation completed; remote state has been reconciled." : "The operation did not commit.", "info");
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
  async function restoreArchivedInstance(archived: Manifest) {
    if (!online || !supportsInstanceArchives || busy || dirty || pendingCleanup) return;
    const instanceId = archived.configuration.instance.id;
    if (pendingArchiveRestore && (pendingArchiveRestore.hostId !== selectedHostId || pendingArchiveRestore.instanceId !== instanceId)) return;
    const pendingId = inventory?.discovery.deployments[instanceId]?.pending_operation;
    const request = pendingArchiveRestore ?? {
      hostId: selectedHostId, instanceId, expectedRevision: archived.revision,
      requestId: pendingId && pendingId !== archived.request_id ? pendingId : crypto.randomUUID(),
    };
    const restored = await task("Restoring archived instance", async () => {
      if (!await confirm(`Restore ${archived.configuration.instance.display_name} on ${host?.display_name}? Its saved configuration and archived runtime identities will be restored. The instance stays stopped until you explicitly start or deploy it. Its recovery snapshot and local client keys are retained.`, { title: "Restore archived instance", kind: "warning" })) return null;
      pendingArchiveRestore = request;
      return await call<Manifest>("restore_archived_instance", { ...request, confirmed: true });
    });
    if (error?.code === "helper_upgrade_required" && inventory) {
      pendingArchiveRestore = null;
      inventory = { ...inventory, identity: { ...inventory.identity, capabilities: [] } };
    }
    if (restored) {
      pendingArchiveRestore = null;
      selected = null; draft = null;
      notify("Archived instance restored. It remains stopped until you start or deploy it. The recovery snapshot is retained.");
      await refreshServer();
      const current = inventory?.discovery.instances.find((item) => item.configuration.instance.id === instanceId);
      if (online && current) { await openInstance(current); await loadBackups(); }
    }
  }
  async function startRestoredInstance() {
    if (!selected || !online || dirty || busy || observation?.deployed_revision == null) return;
    const instanceId = selected.configuration.instance.id;
    const revision = selected.revision;
    const result = await task("Starting instance", async () => {
      if (!await confirm(`Start ${selected!.configuration.instance.display_name} on ${host?.display_name} using its restored deployed state? VPN users may reconnect. Preview / Deploy is still required to apply any newer saved configuration.`, { title: "Start instance", kind: "warning" })) return null;
      return await call<InstanceHealth>("set_remote_running", { hostId: selectedHostId, instanceId, expectedRevision: revision, running: true });
    });
    if (result) { health = result; notify("Instance started using its restored deployed state. Preview / Deploy to apply newer saved configuration."); }
  }
  async function restoreDeployment() {
    if (!selected || !restorePreview || !await confirm("Restore this deployment and its persistent identity state? Saved desired configuration will be preserved.", { title: "Restore deployment", kind: "warning" })) return;
    const result = await task("Restoring deployed state", () => call<InstanceHealth>("restore_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, preview: restorePreview, confirmed: true }));
    if (result) { health = result; restorePreview = null; notify("Deployment restored. Saved desired state was preserved."); await refreshServer(); }
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
    if (!probe || busy) return;
    await task("Approving verified SSH identity", () => call("approve_host_key", { hostId: selectedHostId, probed: probe!.key, expectedFingerprint: fingerprint, replaceChangedKey: replaceChanged }));
    if (!lastTaskFailed) { probe = null; await refreshServer(); }
  }
  async function addServer() {
    if (busy) return;
    const created = await task("Saving server connection", () => call<DockerHost>("create_host", { input: { ...hostForm, passphrase: hostForm.passphrase || null } }));
    hostForm.passphrase = "";
    if (created) { notify("Server connection saved. Verify its SSH identity before connecting.", "info"); hosts = [...hosts, created]; await selectServer(created.id, "Hosts", false); }
  }
  async function previewMigration(id: string) {
    const result = await task("Previewing local legacy migration", () => call<MigrationPreview>("preview_legacy_migration", { instanceId: id, destinationHostId: migrationDestination || selectedHostId }));
    if (result) migrationPreview = result;
  }
  async function migrate() {
    if (!migrationPreview || !await confirm("Back up and migrate this local configuration to the selected server without restarting containers?", { title: "Migrate instance", kind: "warning" })) return;
    await task("Migrating instance", () => call("migrate_legacy_instance", { instanceId: migrationPreview!.instance_id, destinationHostId: migrationPreview!.destination_host_id, expectedPreviewHash: migrationPreview!.expected_preview_hash, confirmed: true }));
    if (!lastTaskFailed) {
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
    <div class="topbar"><div class="breadcrumbs"><span>Workspace</span><span aria-hidden="true">/</span><strong>{page === "add-server" ? "Add Server" : page === "create-instance" ? "Create Instance" : page === "migration" ? "Migration" : serverTab}</strong></div><button class="secondary" onclick={openActivity}>Activity</button><div class="topbar-state"><span class="connection-dot" data-state={connection}></span>{host ? `${host.display_name} · ${connectionLabel}` : "No server selected"}</div></div>
  <main class="app-main">
    {#if busy}<div class="progress" role="status">{busy}…</div>{/if}
    {#if error}<div class="alert" role="alert"><div><strong>{error.message}</strong>{#if error.remediation}<p>{error.remediation}</p>{/if}{#if error.code === "revision_conflict"}<p>Your local draft is retained. Reload after reviewing the server’s changes.</p>{/if}{#if error.technical_detail}<details class="error-details"><summary>Technical details</summary><pre>{error.technical_detail}</pre></details>{/if}</div><button aria-label="Dismiss error" onclick={() => error = null}>×</button></div>{/if}
    {#if page === "server" && serverTab === "Danger Zone"}
      <header class="page-head"><div><p class="eyebrow">Workspace / Destructive actions</p><h1>Danger Zone</h1><p class="subtitle">Remove local connections, reset the client, or archive a server instance. Every action requires confirmation.</p></div></header>
      <div class="danger-zone">
        <section class="card danger-preservation"><h2>Recovery data stays protected</h2><p>Local removal and reset preserve VPN configurations, generated client keys, and recovery bindings. SSH key files and exported VPN configurations are never deleted. Factory Reset is not secure erasure.</p></section>
        {#if pendingCleanup}<div class="alert" role="status">A local cleanup needs reconciliation. Retry the same action to check its original operation; its host selection will not change.</div>{/if}
        {#if hosts.length}<section class="card"><label>Danger Zone host<select value={selectedHostId} disabled={Boolean(busy) || Boolean(pendingCleanup)} onchange={(event) => selectServer(event.currentTarget.value, "Danger Zone")}><option value="" disabled>Choose a host</option>{#each hosts as server}<option value={server.id}>{server.display_name} · {server.ssh.username}@{server.ssh.hostname}:{server.ssh.port}</option>{/each}</select></label><p>Remote actions affect this host only. Factory Reset applies to all saved hosts.</p></section>{/if}
        <section class="card danger-row"><div><h2>Local drop</h2><p>Remove {host?.display_name ?? "the selected host"} from this machine, including its connection, cache, and drafts. Server instances keep running. Reconnect to the verified appliance to access them again.</p></div><button class="danger-action" disabled={!initialized || !host || Boolean(busy) || (Boolean(pendingCleanup) && pendingCleanup?.resetPreferences !== false)} onclick={() => cleanupLocal(false)}>{pendingCleanup && !pendingCleanup.resetPreferences ? "Retry local drop" : "Remove host locally"}</button></section>
        <section class="card danger-row"><div><h2>Full drop</h2><p>Would permanently remove all current VPNCTL-managed instances from this server, then remove the local connection.</p><p id="full-drop-unavailable">Unavailable: safe server ownership checks and recovery archives are not ready. No full-server deletion will run.</p></div><button class="danger-action" disabled aria-describedby="full-drop-unavailable">Full drop unavailable</button></section>
        <section class="card danger-row"><div><h2>Factory Reset · local data only</h2><p>Remove all saved host profiles, connection state, caches, and drafts, and reset application preferences. You will confirm the full profile count before continuing. Servers remain unchanged; VPN recovery data survives.</p></div><button class="danger-action" disabled={!initialized || Boolean(busy) || (Boolean(pendingCleanup) && pendingCleanup?.resetPreferences !== true)} onclick={() => cleanupLocal(true)}>{pendingCleanup?.resetPreferences ? "Retry local Factory Reset" : "Factory Reset local data"}</button></section>
        <section class="card danger-row"><div><h2>Factory Reset · remove remote data</h2><p>Would clean each distinct verified saved appliance before resetting the client.</p><p id="remote-reset-unavailable">Unavailable for the same server ownership and archive requirements as full drop.</p></div><button class="danger-action" disabled aria-describedby="remote-reset-unavailable">Remote Factory Reset unavailable</button></section>
        <section class="card"><h2>Instance and device actions</h2>
          {#if !host}<p>{hosts.length ? "Select a host above to manage its instances." : "Add a host to manage its instances."}</p>{:else}
            <p>{host.display_name} · {online ? "Live connection" : "Remote actions require a live connection."}</p>
            <button class="secondary" disabled={Boolean(busy) || Boolean(pendingCleanup)} onclick={refreshServer}>Refresh / Reconnect</button>
            {#if inventory?.discovery.instances.length}<label>Managed instance<select value={dangerInstance?.configuration.instance.id ?? ""} disabled={Boolean(busy) || Boolean(pendingCleanup) || Boolean(pendingDrop)} onchange={(event) => { dangerInstanceId = event.currentTarget.value; dangerPeerId = ""; }}>{#each inventory.discovery.instances as item}<option value={item.configuration.instance.id}>{item.configuration.instance.display_name}</option>{/each}</select></label>{:else}<p>{online ? "No managed instances available." : "Connect to load the server inventory."}</p>{/if}
            {#if online && !supportsInstanceArchives}<div class="alert" role="status">Automatic helper repair is required. Use Refresh / Reconnect to install the matching bundled helper and check server capabilities. Any repair failure appears above with a retry explanation. The instance remains active unless archival succeeds.</div>{/if}
            <div class="danger-row"><div><h3>Archive instance on server</h3><p>Stop the selected VPN instance and disconnect its users. Saved history and server recovery data are retained. This does not permanently erase the instance.</p></div><button class="danger-action" disabled={!online || !supportsInstanceArchives || !dangerInstance || Boolean(busy) || Boolean(pendingCleanup) || (Boolean(pendingInstanceArchive) && (pendingInstanceArchive?.hostId !== selectedHostId || pendingInstanceArchive?.instanceId !== dangerInstance?.configuration.instance.id))} onclick={archiveDangerInstance}>Archive instance on server</button></div>
            <div class="danger-row"><div><h3>Drop Device</h3><p>Remove a device identity and its managed DNS records from the saved server configuration. Certificate devices are revoked first. Deploy separately to apply access changes.</p>
            {#if dropPeers.length}<label>Device<select value={dropPeer?.id ?? ""} disabled={Boolean(busy) || Boolean(pendingDrop)} onchange={(event) => dangerPeerId = event.currentTarget.value}>{#each dropPeers as peer}<option value={peer.id}>{peer.display_name}{peer.enabled ? "" : " (disabled / revoked)"}</option>{/each}</select></label>{:else}<p>No devices in this instance.</p>{/if}
            {#if !supportsDropPeer}<p>Use Refresh / Reconnect to repair this server’s helper automatically before removing a device.</p>{/if}{#if !online}<p>Reconnect before removing a device.</p>{/if}{#if pendingDrop}<p>A removal outcome is pending for {hosts.find(item => item.id === pendingDrop?.hostId)?.display_name ?? "another host"}. Return to that host and retry the same operation before selecting another device. A certificate may already have been revoked.</p><button class="secondary" disabled={Boolean(busy) || !online || pendingDrop.hostId !== selectedHostId} onclick={checkDropOutcome}>Check removal outcome</button>{/if}
            {#if dangerInstance && inventory?.discovery.deployments?.[dangerInstance.configuration.instance.id]?.pending_operation}<p>Resolve the interrupted operation, or retry this pending device removal, before another mutation.</p>{/if}</div>
            <button class="danger-action" disabled={!online || !supportsDropPeer || !dropPeer || Boolean(busy) || Boolean(pendingCleanup) || (!pendingDrop && Boolean(inventory?.discovery.deployments?.[dangerInstance?.configuration.instance.id ?? ""]?.pending_operation)) || Boolean(pendingDrop && (pendingDrop.hostId !== selectedHostId || pendingDrop.operation.instance_id !== dangerInstance?.configuration.instance.id || pendingDrop.operation.peer_id !== dropPeer.id))} onclick={dropDangerPeer}>{pendingDrop ? "Retry device removal" : "Drop Device"}</button></div>
            {#if dangerPeers.length}<div class="danger-row"><div><h3>Revoke device certificate</h3><p>Revocation cannot be reversed. Deploy the instance afterward to apply it. Local client keys are preserved.</p></div><button class="danger-action" disabled={!online || !dangerPeer || Boolean(busy) || Boolean(pendingCleanup)} onclick={revokeDangerPeer}>Revoke device certificate</button></div>{/if}
          {/if}
        </section>
      </div>
    {:else if page === "add-server"}
      <header class="page-head"><div><p class="eyebrow">Server connection</p><h1>Add Server</h1><p class="subtitle">Connect a Linux appliance using a verified SSH identity. Fields are required unless marked optional.</p></div></header>
      <form use:formFeedback class="card remote-form setup-form" onsubmit={(event) => { event.preventDefault(); void addServer(); }}>
        <label>Server name<input required bind:value={hostForm.display_name} /></label><label>SSH hostname<input placeholder="server.example.com" autocapitalize="none" spellcheck="false" required bind:value={hostForm.hostname} /></label>
        <label>SSH username<input autocomplete="username" required bind:value={hostForm.username} /></label><label>SSH port<input required type="number" min="1" max="65535" bind:value={hostForm.port} /></label>
        <label>Private key path<input required bind:value={hostForm.private_key_path} /></label>
        <button class="secondary" type="button" onclick={async () => { const path = await open({ multiple: false, title: "Choose SSH private key" }); if (typeof path === "string") hostForm.private_key_path = path; }}>Choose key</button>
        <label>Key passphrase (optional)<input type="password" autocomplete="off" bind:value={hostForm.passphrase} /></label><button class="primary" disabled={Boolean(busy)}>Add Server</button>
      </form>
    {:else if page === "migration" && showMigrationUI}
      <header class="page-head"><div><p class="eyebrow">Recovery workflow</p><h1>Migrate local instances</h1><p class="subtitle">Review eligible local configuration before saving it to a server.</p></div></header>
      <label>Destination server<select bind:value={migrationDestination}><option value="">Select a server</option>{#each hosts as server}<option value={server.id}>{server.display_name}</option>{/each}</select></label>
      {#each eligibleLocalLegacyInstances as candidate}<section class="card"><h2>{candidate.display_name}</h2><p>{nameOf(candidate.backend)} · {candidate.instance_id}</p><button class="secondary" disabled={!migrationDestination || Boolean(busy)} onclick={() => previewMigration(candidate.instance_id)}>Preview migration</button></section>{/each}
      {#if migrationPreview}<section class="card"><h2>Migration preview</h2><p>{migrationPreview.deployment_present ? "Existing deployment and identities will be preserved." : "Configuration will be saved without deploying containers."}</p>{#each migrationPreview.warnings as warning}<p>{warning}</p>{/each}{#each migrationPreview.issues as issue}<p class="danger">{issue}</p>{/each}<button class="primary" disabled={Boolean(busy) || migrationPreview.issues.length > 0} onclick={migrate}>Back Up and Migrate</button></section>{/if}
    {:else if page === "create-instance"}
      <header class="page-head"><div><p class="eyebrow">New appliance</p><h1>Create Instance on {host?.display_name}</h1><p class="subtitle">Save the configuration first. Preview and deploy it when you are ready. Fields are required unless marked optional.</p></div></header>
      <form use:formFeedback class="card remote-form setup-form" onsubmit={(event) => { event.preventDefault(); void createInstance(); }}>
        <label>Instance name<input required bind:value={instanceForm.display_name} /></label>
        <label>Backend<select bind:value={instanceForm.backend} onchange={() => { instanceForm.endpoint_port = backends.find((backend) => backend.kind === instanceForm.backend)!.port; }}>{#each backends as backend}<option value={backend.kind}>{backend.name}</option>{/each}</select></label>
        <label>VPN endpoint<input placeholder="vpn.example.com" required bind:value={instanceForm.endpoint_host} /></label><label>Listener port<input type="number" min="1" max="65535" disabled={instanceForm.backend === "ikev2"} bind:value={instanceForm.endpoint_port} /></label>
        <label>IPv4 subnet<input placeholder="10.64.0.0/24" required bind:value={instanceForm.ipv4_subnet} /></label><label>Private DNS zone<input required bind:value={instanceForm.dns_zone} /></label>
        {#if BackendForm}<BackendForm bind:form={instanceForm} />{/if}<button class="primary" disabled={!online || Boolean(busy)}>Save to Server</button>
      </form>
    {:else if !host}
      <header class="page-head"><div><p class="eyebrow">Workspace setup</p><h1>Servers</h1><p class="subtitle">Manage remote VPN appliances from verified SSH connections.</p></div></header><section class="card empty-workspace"><div class="empty-symbol" aria-hidden="true">▣</div>{#if hosts.length}<h2>Choose a host to connect</h2><p>Hosts connect only when selected. Connections stay open while VPNCTL is open and close when the app closes.</p><p>Connecting also repairs compatible outdated server helpers using the bundled version. VPN configuration changes still require deployment.</p>{#each hosts as savedHost}<button class="secondary" disabled={Boolean(busy)} onclick={() => selectServer(savedHost.id)}>{savedHost.display_name}<small>{savedHost.ssh.username}@{savedHost.ssh.hostname}:{savedHost.ssh.port} · {hostSessions[savedHost.id]?.connection === "connected" ? "Connected" : "Not connected"}</small></button>{/each}{:else}<h2>Connect your first VPN server</h2><p>Add a Linux server using a verified SSH connection.</p>{/if}<button class="primary" onclick={() => page = "add-server"}>Add Server</button></section>
    {:else}
      <header class="page-head"><div><p class="eyebrow">Control plane / {serverTab}</p><h1>{selected && serverTab === "Instances" ? "Instances" : serverTab}</h1><p class="subtitle">{serverTab === "Overview" ? `One workspace for ${host.display_name}, VPN instances, connected devices, and private DNS.` : serverTab === "Hosts" ? "Manage verified SSH connections and inspect remote hosts." : serverTab === "Instances" ? `Provision and manage VPN appliances on ${host.display_name}.` : `Manage ${serverTab.toLowerCase()} for ${host.display_name}.`}</p></div>{#if serverTab === "Overview" || serverTab === "Instances"}<button class="primary" disabled={!online || Boolean(busy)} onclick={() => { instanceForm = newInstanceForm(selectedHostId, host!.ssh.hostname); page = "create-instance"; }}>Create Instance</button>{:else if serverTab === "Hosts"}<button class="primary" onclick={() => page = "add-server"}>+ Add host</button>{/if}</header>
      {#if connection !== "connected" && connection !== "loading"}<div class="alert" role="status">{connectionLabel}. Remote saving and deployment require a verified live connection. <button class="secondary" disabled={Boolean(busy)} onclick={refreshServer}>Reconnect</button></div>{/if}
      {#if probe?.state === "changed"}<div class="alert" role="alert">The SSH host identity changed. Access stays blocked until you independently verify and explicitly approve the new fingerprint in Hosts.</div>{/if}
      {#if inventory?.cached}<div class="alert" role="status">Offline · showing cached information from {new Date(inventory.synchronized_at).toLocaleString()}. Saving and deployment require a live connection.</div>{/if}
      {#if inventory && Object.keys(inventory.discovery.errors).length}<div class="alert" role="alert">Some remote instance metadata could not be read. The server is not empty.<ul>{#each Object.values(inventory.discovery.errors) as problem}<li>{problem}</li>{/each}</ul></div>{/if}
      {#if ["Devices", "DNS", "Backups", "Logs"].includes(serverTab) && inventory?.discovery.instances.length}<section class="card section-selector"><label for="section-instance">Instance</label><select disabled={Boolean(busy)} id="section-instance" value={selected?.configuration.instance.id ?? ""} onchange={async (event) => { const selector = event.currentTarget; await selectSectionInstance(selector.value); selector.value = selected?.configuration.instance.id ?? ""; }}>{#each inventory.discovery.instances as item}<option value={item.configuration.instance.id}>{item.configuration.instance.display_name}</option>{/each}</select><span>{host.display_name} · {inventory.cached ? "cached" : connection}</span></section>{/if}
      {#if serverTab === "Backups"}
        <section class="card archived-backups"><header><div><h2>Archived instances</h2><p>Restore saved configuration and retained runtime identities. Restored instances stay stopped until you start or deploy them.</p></div><button class="secondary" disabled={Boolean(busy)} onclick={refreshServer}>Refresh archives</button></header>
          {#if archivedInstances.length}<div class="table-wrap"><table><thead><tr><th>Instance</th><th>Archived</th><th>Saved state</th><th>Action</th></tr></thead><tbody>{#each archivedInstances as archived}<tr><td>{archived.configuration.instance.display_name}<small>{nameOf(archived.configuration.instance.backend)}</small></td><td>{new Date(archived.saved_at).toLocaleString()}</td><td>Archived revision {archived.revision}</td><td><button class="secondary" disabled={!online || !supportsInstanceArchives || dirty || Boolean(busy) || Boolean(pendingCleanup) || (Boolean(pendingArchiveRestore) && pendingArchiveRestore?.instanceId !== archived.configuration.instance.id)} onclick={() => restoreArchivedInstance(archived)}>{pendingArchiveRestore?.instanceId === archived.configuration.instance.id ? "Retry archived instance restore" : "Restore archived instance"}</button></td></tr>{/each}</tbody></table></div>{:else}<div class="inventory-empty"><h3>{online && !supportsInstanceArchives ? "Server helper update required" : inventory ? "No archived instances" : "Archive inventory unavailable"}</h3><p>{online && !supportsInstanceArchives ? "Use Refresh / Reconnect to repair the helper automatically, then list and restore archived instances." : inventory ? "Instances archived on this server will appear here." : "Connect to the server to read its archived instances."}</p></div>{/if}
        </section>
      {/if}
      {#if selected && draft}
        {#if serverTab === "Devices"}<div class="metric-grid section-metrics" aria-label="Device summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg></span><strong>{draft.peers.length}</strong><span class="metric-label">Assigned identities</span><small>On {draft.instance.display_name}</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg></span><strong>{draft.peers.filter((peer) => peer.enabled).length}</strong><span class="metric-label">Enabled</span><small>Saved access state</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/></svg></span><strong>{draft.peers.filter((peer) => !peer.enabled).length}</strong><span class="metric-label">Disabled</span><small>Saved access state</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="5"/><path d="m12 11 9-9 2 2-2 2 1 2-3 3-2-2-3 3"/></svg></span><strong>{availability.filter((item) => item.complete_export_available).length}</strong><span class="metric-label">Exportable here</span><small>Complete local credentials</small></div></div>{/if}
        {#if serverTab === "DNS"}<div class="metric-grid section-metrics three" aria-label="DNS summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></span><strong>{draft.dns_records.length}</strong><span class="metric-label">Private DNS records</span><small>Saved configuration</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 22 0 0C6 19 4 16 4 10V5l8-3 8 3v5c0 6-2 9-8 12Z"/><path d="m9 12 2 2 4-4"/></svg></span><strong>{draft.dns_blocklist_domains.length}</strong><span class="metric-label">Blocklist domains</span><small>Saved configuration</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><strong class="metric-date">{draft.instance.dns.zone}</strong><span class="metric-label">Private DNS zone</span><small>On {draft.instance.display_name}</small></div></div>{/if}
        {#if serverTab === "Backups"}<div class="metric-grid section-metrics three" aria-label="Backup summary"><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></svg></span><strong>{backups.length}</strong><span class="metric-label">Runtime snapshots</span><small>On {draft.instance.display_name}</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></span><strong>{observation?.deployed_revision ?? "—"}</strong><span class="metric-label">Deployed revision</span><small>Current observation</small></div><div class="metric-card"><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg></span><strong>{selected.revision}</strong><span class="metric-label">Desired revision</span><small>Saved configuration</small></div></div>{/if}
        {#if serverTab === "Instances"}<p class="compact-summary">{inventory?.discovery.instances.length ?? 0} instances · {peerCount} devices · {pendingCount} ready to deploy · {unknownDeploymentCount} deployment status unknown</p>{/if}<div class:prototype-split={serverTab === "Instances"} class:instance-split={serverTab === "Instances"}>{#if serverTab === "Instances"}<section class="card instances-panel"><header><h2>Your instances</h2><span class="panel-caption">{inventory?.discovery.instances.length ?? 0} total</span></header><div class="instance-grid">{#each inventory?.discovery.instances ?? [] as instance}<button disabled={Boolean(busy)} class="instance-card" class:selected={selected.configuration.instance.id === instance.configuration.instance.id} onclick={() => openInstance(instance)}><span class="instance-symbol" aria-hidden="true">{nameOf(instance.configuration.instance.backend).slice(0, 2).toUpperCase()}</span><span class="instance-card-info"><strong>{instance.configuration.instance.display_name}</strong><small>{instance.configuration.instance.endpoint.host}:{instance.configuration.instance.endpoint.port}</small><small>{nameOf(instance.configuration.instance.backend)} · {configurationStatus(instance.revision, inventory?.discovery.deployments?.[instance.configuration.instance.id]?.deployed_revision)}</small></span><span class="instance-chevron" aria-hidden="true">›</span></button>{/each}</div></section>{/if}<div class="instance-detail-column">
        <section class="card instance-workspace" oninput={scheduleDraft}>
          <header class="instance-head"><div><p class="eyebrow">{serverTab === "Instances" ? "Selected appliance" : `Selected instance · ${draft.instance.display_name}`}</p><h2>{serverTab === "Instances" ? draft.instance.display_name : serverTab === "Devices" ? "Device identities" : serverTab === "DNS" ? "Private DNS records" : serverTab === "Backups" ? "Backup inventory" : "Deployment history"}</h2><p>{nameOf(draft.instance.backend)} · {host.display_name} · {draft.peers.length} devices</p><p class="status-line">{configurationStatus(selected.revision, observation?.deployed_revision, dirty, staleDraft)}</p><p>{healthLabel(draft.instance.id)}{#if observedHealth[`${selectedHostId}/${draft.instance.id}`]} · checked {new Date(observedHealth[`${selectedHostId}/${draft.instance.id}`].checkedAt).toLocaleTimeString()}{/if}</p></div><div class="header-actions"><button class="secondary" disabled={!online || Boolean(busy)} onclick={reloadInstance}>Reload from Server</button><Tooltip label="About reloading" text="Fetch the latest configuration from the remote server. You will be asked before discarding unsaved local changes." /><button class="primary" disabled={!dirty || staleDraft || !online || Boolean(busy)} onclick={saveDraft}>Save to Server</button><Tooltip label="About saving" text="Save changes on the remote server without applying them to the running VPN. Deploy separately." /></div></header>
          {#if dirty}<div class="notice status-unsaved" role="status">Unsaved changes · Save to Server to keep these edits remotely.</div>{/if}
          {#if staleDraft}<div class="alert" role="alert">The server configuration has changed since you started editing. Your local edits are retained. <button class="secondary" disabled={!online || Boolean(busy)} onclick={reviewDifferences}>Review differences</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={reloadInstance}>Discard local edits and reload</button></div>{/if}
          {#if observation?.deployed_revision != null && observation.deployed_revision !== selected.revision}<div class="notice status-pending" role="status">Changes ready to deploy · saved on the server, not yet applied to the VPN service.</div>{/if}
          <details class="configuration-details"><summary>Configuration details</summary><dl><dt>Draft based on</dt><dd>{baseRevision}</dd><dt>Saved configuration <Tooltip text="The latest configuration saved on the remote server. It may not have been deployed yet." /></dt><dd>{selected.revision}</dd><dt>Deployed configuration <Tooltip text="The version most recently applied to the VPN service. This does not guarantee the service is healthy." /></dt><dd>{observation?.deployed_revision ?? "Unknown"}</dd></dl></details>
          {#if !online || Boolean(busy) || staleDraft || !dirty}<p class="action-help">{!online ? "Reconnect to save or deploy changes." : busy ? `${busy}… Please wait before starting another operation.` : staleDraft ? "Review the server changes and reload before saving." : "No unsaved changes. Save and Deploy are separate operations."}</p>{/if}
          {#if observation?.pending_operation}<div class="alert" role="alert">An interrupted runtime operation requires reconciliation before another mutation. <button class="secondary" disabled={!online || Boolean(busy)} onclick={reconcileRuntime}>Check operation outcome</button></div>{/if}
          {#if serverTab === "Instances"}<div class="tabs instance-tabs" role="tablist" aria-label="Instance sections">{#each tabs as item}<button role="tab" disabled={Boolean(busy)} aria-label={item} aria-selected={tab === item} tabindex={tab === item ? 0 : -1} onkeydown={async (event) => { const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0; if (delta || event.key === "Home" || event.key === "End") { event.preventDefault(); const trigger = event.currentTarget; if (blockingDirty && !await leaveBlocking()) return; const index = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (tabs.indexOf(item) + delta + tabs.length) % tabs.length; tab = tabs[index]; closeExport(); (trigger.parentElement?.querySelectorAll<HTMLButtonElement>("[role=tab]")[index])?.focus(); } }} class:active={tab === item} onclick={async () => { if (blockingDirty && !await leaveBlocking()) return; qrImage = ""; tab = item; }}>{item === "Peers / Devices" ? "Devices" : item === "DNS and Routing" ? "DNS" : item === "Deployment" ? "Deploy" : item}</button>{/each}</div>{/if}
          <fieldset class="instance-content" disabled={Boolean(busy)} aria-label="Instance controls">
          {#if tab === "Overview"}<h3>Remote configuration</h3><div class="header-actions"><button class="secondary" disabled={!online || Boolean(busy)} onclick={checkHealth}>Check VPN health</button><button class="primary" disabled={!online || dirty || staleDraft || Boolean(busy) || Boolean(observation?.pending_operation)} onclick={() => tab = "Deployment"}>Open deployment</button></div><dl class="overview-facts"><div><dt>Owning server</dt><dd>{host.display_name}</dd></div><div><dt>Endpoint</dt><dd>{draft.instance.endpoint.host}:{draft.instance.endpoint.port}</dd></div><div><dt>Peers / devices</dt><dd>{draft.peers.length}</dd></div><div><dt>Network</dt><dd>{draft.instance.network.ipv4_subnet}</dd></div><div><dt>Last saved</dt><dd>{new Date(selected.saved_at).toLocaleString()}</dd></div></dl>
          {:else if tab === "Peers / Devices"}
            <div class="table-wrap">
            {#if !draft.peers.length}<div class="inventory-empty"><h3>No devices yet</h3><p>Add a device below, then deploy to enable its VPN access.</p></div>{/if}
            <table><thead><tr><th>Name</th><th>Address</th><th>Enabled <Tooltip text="Whether this device identity is authorized in the VPN configuration. Changes take effect after saving and deploying. Certificate revocation is managed separately in Danger Zone." /></th><th>Configuration</th><th>Action</th></tr></thead><tbody>{#each draft.peers as peer}<tr><td><input data-draft-field aria-label={"Device name " + peer.display_name} required bind:value={peer.display_name} /></td><td>{peer.ipv4_address ?? "Protocol assigned"}</td><td>{#if draft.instance.backend === "openvpn" || draft.instance.backend === "ikev2"}{peer.enabled ? "Enabled" : "Revoked"}{:else}<input aria-label={"Enable " + peer.display_name} type="checkbox" bind:checked={peer.enabled} />{/if}</td><td><button class="secondary" disabled={Boolean(exportReason) || !peer.enabled || Boolean(busy) || !availability.find((item) => item.peer_id === peer.id)?.complete_export_available} onclick={(event) => openExport(peer.id, event.currentTarget)}>Get Configuration</button>
              {#if !peer.enabled}<p>Disabled or revoked devices cannot export an active configuration.</p>{:else if !availability.find((item) => item.peer_id === peer.id)?.complete_export_available}<p>{availability.find((item) => item.peer_id === peer.id)?.reason ?? "Private material unavailable on this client"}. Retrieve the original configuration from the installation that created this identity, or enroll a new device.</p>{/if}{#if exportReason}<p>{exportReason}</p>{/if}
              </td><td>{#if (draft.instance.backend === "openvpn" || draft.instance.backend === "ikev2") && peer.enabled}<button class="secondary" disabled={Boolean(busy)} onclick={() => openDangerZone(draft!.instance.id, peer.id)}>Revoke in Danger Zone</button>{/if}</td></tr>{/each}</tbody></table>
            </div>
            {#if enrolledPeerId}<section class="notice enrollment-result" role="status"><strong>Device saved on the server</strong><p>Deploy the saved configuration to apply access changes. Configuration retrieval does not activate this device.</p><button class="secondary" disabled={Boolean(busy)} onclick={() => { tab = "Deployment"; serverTab = "Instances"; }}>Review deployment</button><button class="secondary" disabled={Boolean(exportReason) || Boolean(busy) || !availability.find(item => item.peer_id === enrolledPeerId)?.complete_export_available} onclick={(event) => openExport(enrolledPeerId, event.currentTarget)}>Get new device configuration</button>{#if exportReason}<p>{exportReason}</p>{/if}</section>{/if}
            <form use:formFeedback class="remote-form" onsubmit={(event) => { event.preventDefault(); void addPeer(); }}><h3>Add Device</h3><p>A device is a VPN client identity. Create a separate identity for each client installation.</p><label>Device name<input required maxlength="128" bind:value={peerName} /></label><label class="checkbox"><input type="checkbox" bind:checked={peerCreateDns} /> Add DNS record</label><p>Use the device name in the private DNS zone ({draft.instance.dns.zone}) unless you specify a custom DNS name. For example, macbook becomes macbook.{draft.instance.dns.zone}. The record takes effect after deployment.</p><details><summary>Advanced (optional)</summary><label>DNS name (optional)<input disabled={!peerCreateDns} placeholder="Uses device name when blank" bind:value={peerDns} /></label>{#if !peerCreateDns}<p>Enable Add DNS record to specify a DNS name.</p>{/if}</details><p>Adding a device saves it on the server. Deploy separately to apply access changes.</p>{#if dirty || staleDraft}<p>Save or discard existing edits and resolve server changes before adding a device.</p>{/if}{#if !online}<p>Reconnect to add a device.</p>{/if}{#if !certificateAuthorityReady}<p>Deploy this instance once to establish its certificate authority before enrolling devices.</p>{/if}<button class="primary" disabled={!online || dirty || staleDraft || !peerName.trim() || !certificateAuthorityReady || Boolean(busy)}>Add Device</button></form>
          {:else if tab === "DNS and Routing"}
            <label>Routing<select bind:value={draft.instance.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel</option></select></label>
            <div class="table-wrap">
            <table><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>Action</th></tr></thead><tbody>{#each draft.dns_records as record}<tr><td>{record.name}</td><td>{record.record_type}</td><td>{record.value}</td><td><button class="secondary" onclick={() => { draft!.dns_records = draft!.dns_records.filter((item) => item.id !== record.id); void retainDraft(); }}>Remove from draft</button></td></tr>{/each}</tbody></table>
            </div>
            <form use:formFeedback class="remote-form" onsubmit={(event) => { event.preventDefault(); addDns(); }}><label>DNS record name<input placeholder="laptop" required bind:value={dnsName} /></label><label>Record type<select bind:value={dnsType}>{#each ["A", "AAAA", "CNAME", "TXT", "SRV"] as type}<option>{type}</option>{/each}</select></label><label>Record value<input required bind:value={dnsValue} /></label><p>Records are edited locally. Save to Server, then deploy to apply them.</p><button class="secondary" disabled={staleDraft || !dnsName.trim() || !dnsValue.trim()}>Add to draft</button></form>
            {#key `${selectedHostId}/${draft.instance.id}`}<BlockingContent hostId={selectedHostId} instanceId={draft.instance.id} {online} supported={Boolean(inventory?.identity.capabilities?.includes("dns_blocking_v1"))} dirtyChanged={blockingChanged} {busy} run={task} {notify} />{/key}
          {:else if tab === "Settings"}
            <form data-draft-form use:formFeedback class="remote-form" oninput={applySettings} onchange={applySettings} onsubmit={(event) => { event.preventDefault(); applySettings(); }}><label>Instance name<input required bind:value={settingsForm.display_name} /></label><label>VPN endpoint<input placeholder="vpn.example.com" required bind:value={settingsForm.endpoint_host} /></label><label>Listener port<input required type="number" min="1" max="65535" disabled={settingsForm.backend === "ikev2"} bind:value={settingsForm.endpoint_port} /></label><label>Private DNS zone<input required bind:value={settingsForm.dns_zone} /></label>{#if SettingsBackendForm}<SettingsBackendForm bind:form={settingsForm} />{/if}<button class="secondary">Keep local draft</button></form>
            <button class="secondary" disabled={Boolean(busy)} onclick={() => openDangerZone(draft!.instance.id)}>Open Danger Zone</button>
          {:else if tab === "Deployment"}
            {#if serverTab === "Logs"}
              <div class="table-wrap"><table><thead><tr><th>Operation</th><th>Desired revision</th><th>Result</th><th>Deployed revision</th><th>Recovery</th></tr></thead><tbody>{#each runtimeHistory as event}<tr><td>{event.operation.replaceAll("_", " ")}</td><td>{event.desired_revision}</td><td><span class="instance-state" data-state={event.succeeded ? "healthy" : "needs_deployment"}>{event.succeeded ? "Succeeded" : "Failed"}</span></td><td>{event.deployed_revision ?? "Unknown"}</td><td>{event.requires_recovery ? "Required" : "None"}</td></tr>{/each}</tbody></table>{#if !runtimeHistory.length}<div class="inventory-empty"><h3>No deployment history</h3><p>Remote operations for this instance will appear here.</p></div>{/if}</div>
            {:else if serverTab === "Backups"}
              <div class="section-toolbar"><h3>Runtime snapshots <Tooltip text="A snapshot of the remote VPN’s operational configuration that may be used during recovery." /></h3><button class="secondary" disabled={!online || dirty || observation?.deployed_revision == null || Boolean(busy)} onclick={startRestoredInstance}>Start instance</button><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={async () => { await task("Creating runtime backup", () => call("backup_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision })); if (!lastTaskFailed) { notify("Runtime backup created on server."); await loadBackups(); } }}>Create snapshot</button></div>
              <div class="table-wrap"><table><thead><tr><th>Snapshot</th><th>Created</th><th>Action</th></tr></thead><tbody>{#each backups as backup}<tr><td>{backup.name}</td><td>{new Date(backup.created_at).toLocaleString()}</td><td><button class="secondary" disabled={!online || dirty || Boolean(busy)} onclick={() => previewRestore(backup.name)}>Preview restore</button></td></tr>{/each}</tbody></table>{#if !backups.length}<div class="inventory-empty"><h3>No runtime snapshots</h3><p>Create a snapshot of the selected instance to populate this page.</p></div>{/if}</div>
              {#if restorePreview}<section class="alert"><div><h3>Restore deployed revision {restorePreview.deployed_revision ?? "unknown"}</h3><p>{restorePreview.identity_impact}</p><p>Saved desired revision {restorePreview.desired_revision} will remain unchanged.</p><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={restoreDeployment}>Restore Deployment</button></div></section>{/if}
            {:else}
            <div class="header-actions"><button class="primary" disabled={!online || dirty || staleDraft || Boolean(busy) || Boolean(observation?.pending_operation)} onclick={previewDeployment}>Preview / Deploy</button><Tooltip label="About deployment" text="Preview and apply the saved server configuration to the VPN service. Saving alone does not deploy." /><button class="secondary" disabled={!online || Boolean(busy)} onclick={checkHealth}>Check health</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={async () => { await task("Creating runtime backup", () => call("backup_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision })); if (!lastTaskFailed) notify("Runtime backup created on server."); }}>Create runtime backup</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadHistory}>View configuration history</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadRuntimeHistory}>View deployment history</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadBackups}>View runtime backups</button></div>
            {#if dirty}<p>Save local edits to the server before previewing deployment.</p>{/if}
            {#if plan}<h3>Deployment preview for saved revision {selected.revision}</h3>{#each plan.warnings as warning}<p class="danger">{warning}</p>{/each}<ul>{#each plan.operations as operation}<li>{operation.operation.replaceAll("_", " ")} {operation.path ?? operation.service ?? ""}</li>{/each}</ul><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={deploy}>Apply saved revision {selected.revision}</button>{/if}
            {#if health}<h3>Deployment health</h3><dl><dt>Gateway</dt><dd>{health.gateway_running ? "Running" : "Stopped / unavailable"}</dd><dt>Backend</dt><dd>{health.backend_ready ? "Ready" : "Needs attention"}</dd><dt>Listeners</dt><dd>{health.listeners_ready ? "Ready" : "Needs attention"}</dd><dt>Deployed peer state</dt><dd>{health.client_state_matches ? "Matches" : "Needs attention"}</dd>{#if health.dns_required}<dt>Private DNS</dt><dd>{health.private_dns_resolves ? "Resolving" : "Needs attention"}</dd><dt>Public DNS</dt><dd>{health.public_dns_resolves ? "Resolving securely" : "Needs attention"}</dd>{/if}</dl>{#if health.details.length}<details><summary>Health details</summary><ul>{#each health.details as detail}<li>{detail}</li>{/each}</ul></details>{/if}{/if}
            {#each backups as backup}<div class="history-row"><span>{backup.name} · {new Date(backup.created_at).toLocaleString()}</span><button class="secondary" disabled={!online || dirty || Boolean(busy)} onclick={() => previewRestore(backup.name)}>Preview deployment restore</button></div>{/each}
            {#if restorePreview}<section class="alert"><div><h3>Restore deployed revision {restorePreview.deployed_revision ?? "unknown"}</h3><p>{restorePreview.identity_impact}</p><p>Saved desired revision {restorePreview.desired_revision} will remain unchanged.</p><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={restoreDeployment}>Restore Deployment</button></div></section>{/if}
            {#each history as revision}<div class="history-row"><span>Desired revision {revision.revision} · {new Date(revision.saved_at).toLocaleString()}</span><button class="secondary" disabled={!online || dirty || revision.revision === selected.revision || Boolean(busy)} onclick={() => restoreDesired(revision.revision)}>Restore Desired Configuration</button></div>{/each}
            {#each runtimeHistory as event}<div class="history-row"><span>{event.operation.replaceAll("_", " ")} · desired revision {event.desired_revision} · {event.succeeded ? "Succeeded" : "Failed"}{event.requires_recovery ? " · Recovery required" : ""}{event.deployed_revision == null ? "" : " · deployed revision " + event.deployed_revision}</span></div>{/each}
            {/if}
          {/if}
          </fieldset>
        </section>
        </div></div>
      {:else if serverTab === "Backups"}
        <section class="card inventory-empty"><h2>Runtime snapshots</h2><p>Choose an active instance or restore an archived instance above to access its runtime snapshots.</p></section>
      {:else}
        {#if serverTab === "Hosts"}<div class="prototype-split"><section class="card host-list-panel"><header><h2>Managed hosts</h2><span>{hosts.length} configured</span></header>{#each hosts as server}<button disabled={Boolean(busy)} class:selected={server.id === selectedHostId} onclick={async () => { await selectServer(server.id); serverTab = "Hosts"; }}><span class="instance-symbol" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M11 7h6M11 17h6"/></svg></span><span><strong>{server.display_name}</strong><small>{server.ssh.username}@{server.ssh.hostname}:{server.ssh.port} · {hostSessions[server.id]?.connection === "connected" ? "Connected" : "Not connected"}</small></span><span class="instance-chevron" aria-hidden="true">›</span></button>{/each}</section><section class="card host-detail-panel"><div class="detail-hero"><div><p class="eyebrow">Host details</p><h2>{host.display_name}</h2><p>{host.ssh.username}@{host.ssh.hostname}:{host.ssh.port}</p></div><span class="instance-state" data-state={online ? "healthy" : "needs_deployment"}>{connectionLabel}</span></div><p>SSH connectivity is separate from VPN service health.</p><div class="host-actions"><button class="secondary" disabled={Boolean(busy)} onclick={refreshServer}>Reconnect</button><details class="host-tools"><summary>Host Tools</summary><div><button class="secondary" disabled={Boolean(busy)} onclick={probeServer}>Verify SSH host identity</button><Tooltip text="Check the server’s SSH host key to help ensure you are connecting to the expected machine." /><button class="secondary" disabled={Boolean(busy)} onclick={inspectServer}>Check Server Requirements</button><Tooltip text="Check whether the remote server meets the requirements for managing and deploying VPN instances." /></div></details></div><div class="fact-grid"><div><span>Appliance identity</span><strong>{inventory?.identity.appliance_id ?? "Not synchronized"}</strong></div><div><span>Managed instances</span><strong>{inventory?.discovery.instances.length ?? "Unknown"}</strong></div><div><span>Last synchronized</span><strong>{inventory ? new Date(inventory.synchronized_at).toLocaleString() : "Never"}</strong></div><div><span>Connection</span><strong>{connectionLabel}</strong></div></div>{#if probe}<div class="host-verification"><h3>{probe.state === "changed" ? "Changed SSH host key" : "SSH host key"}</h3><p>{probe.key.sha256_fingerprint}</p><p>Verify this fingerprint through an independent trusted channel.</p><p>Approval requires the exact independently verified fingerprint. A changed identity also requires explicit replacement confirmation.</p><label>Exact verified fingerprint<input bind:value={fingerprint} /></label>{#if probe.state === "changed"}<label><input type="checkbox" bind:checked={replaceChanged} /> Explicitly replace the previously approved key</label>{/if}<button class="primary" disabled={Boolean(busy) || fingerprint !== probe.key.sha256_fingerprint || (probe.state === "changed" && !replaceChanged)} onclick={approveIdentity}>Approve SSH identity</button></div>{/if}{#if inspection}<div class="inspection-panel"><p>{inspection.inspection.operating_system} · {inspection.inspection.architecture}</p><p>Docker: {inspection.inspection.docker_version ?? "Unavailable"} · Compose: {inspection.inspection.compose_version ?? "Unavailable"}</p><HostReadinessMatrix view={inspection} /></div>{/if}</section></div>
        {:else}
          {#if serverTab === "Overview"}
            <section class="server-hero"><div><p class="eyebrow">Network status</p><h2>{online ? `${inventory?.discovery.instances.length ?? 0} VPN ${(inventory?.discovery.instances.length ?? 0) === 1 ? "instance" : "instances"} configured` : connection === "offline" ? "Showing saved server data" : connection === "loading" ? "Connecting to server" : "Server needs attention"}</h2><p>{online ? `${inventory?.discovery.instances.length ?? 0} ${(inventory?.discovery.instances.length ?? 0) === 1 ? "instance" : "instances"} on ${host.display_name}. Deployment status and health are shown per instance.` : "Reconnect to read current remote state before saving or deploying changes."}</p></div><button class="hero-action" onclick={() => navigateSection("Instances")}>Manage instances <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h14m-6-6 6 6-6 6"/></svg></button></section>
            <div class="metric-grid" aria-label="Server summary">
              <button class="metric-card metric-link" onclick={() => navigateSection("Hosts")}><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M11 7h6M11 17h6"/></svg></span><strong>{hosts.length}</strong><span class="metric-label">Managed hosts</span><small>SSH management targets</small></button>
              <button class="metric-card metric-link" onclick={() => navigateSection("Instances")}><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="m12 2 8.5 5-8.5 5L3.5 7 12 2ZM3.5 7v10L12 22l8.5-5V7M12 12v10"/></svg></span><strong>{inventory?.discovery.instances.length ?? "—"}</strong><span class="metric-label">VPN instances</span><small>On {host.display_name}</small></button>
              <button class="metric-card metric-link" onclick={() => navigateSection("Devices")}><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg></span><strong>{inventory ? enabledPeerCount : "—"}</strong><span class="metric-label">Enabled devices</span><small>{inventory ? `${peerCount} total identities` : "Awaiting discovery"}</small></button>
              <button class="metric-card metric-link" onclick={() => navigateSection("DNS")}><span class="metric-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></span><strong>{inventory ? dnsRecordCount : "—"}</strong><span class="metric-label">Private DNS records</span><small>Across discovered instances</small></button>
            </div>
            <section class="card attention-panel"><h2>Operational status</h2><p>{online ? "SSH connected. VPN service health requires a separate check." : "Reconnect before making remote changes."}</p><p>{pendingCount} changes ready to deploy · {unknownDeploymentCount} deployment status unknown · {pendingOperationCount} interrupted operations · {serviceIssueCount} verified service issues</p><button class="secondary" onclick={() => navigateSection("Instances")}>Review instances and check health</button></section>
            <section class="card activity-panel"><header><h2>Recent activity</h2><button class="activity-link" onclick={openActivity}>Session activity →</button><button class="activity-link" onclick={() => navigateSection("Logs")}>Deployment logs →</button></header>{#each $activity.slice(0, 3) as item}<div class="activity-row"><div><strong>{item.message}</strong><time>{new Date(item.timestamp).toLocaleTimeString()}</time></div></div>{/each}{#if inventory}<div class="activity-row"><span class="activity-icon" aria-hidden="true">✓</span><div><strong>Server synchronized</strong><p>Remote inventory read from {host.display_name}</p></div><time>{new Date(inventory.synchronized_at).toLocaleTimeString()}</time></div>{:else}<div class="inventory-empty"><h3>No recent activity available</h3><p>Connect to this server to read its current state.</p></div>{/if}</section>
            <section class="quick-actions"><h2>Quick actions</h2><div><button class="card" onclick={() => page = "add-server"}><span class="instance-symbol" aria-hidden="true">+</span><span><strong>Add a host</strong><small>Register another SSH management target</small></span><span aria-hidden="true">›</span></button><button class="card" onclick={() => navigateSection("Devices")}><span class="instance-symbol" aria-hidden="true">▯</span><span><strong>Enroll a device</strong><small>Create a VPN identity, then deploy when ready</small></span><span aria-hidden="true">›</span></button><button class="card" onclick={() => navigateSection("DNS")}><span class="instance-symbol" aria-hidden="true">◎</span><span><strong>Add a DNS record</strong><small>Manage private name resolution</small></span><span aria-hidden="true">›</span></button></div></section>
          {/if}
          {#if serverTab === "Instances"}<p class="compact-summary">{inventory?.discovery.instances.length ?? 0} instances · {peerCount} devices · {pendingCount} ready to deploy · {unknownDeploymentCount} deployment status unknown</p>{/if}
          {#if serverTab === "Overview" || serverTab === "Instances"}<div class:prototype-split={serverTab === "Instances"} class:instance-split={serverTab === "Instances"}><section class="card instances-panel"><header><div>{#if serverTab === "Overview"}<p class="eyebrow">Remote inventory</p>{/if}<h2>{serverTab === "Instances" ? "Your instances" : "Instances"}</h2></div><span class="panel-caption">{inventory?.discovery.instances.length ?? 0} total</span></header>
            {#if inventory?.discovery.instances.length}<div class="instance-grid">{#each inventory.discovery.instances as instance}<button disabled={Boolean(busy)} class="instance-card" onclick={() => openInstance(instance)}><span class="instance-symbol" aria-hidden="true">{nameOf(instance.configuration.instance.backend).slice(0, 2).toUpperCase()}</span><span class="instance-card-info"><strong>{instance.configuration.instance.display_name}</strong><small>{nameOf(instance.configuration.instance.backend)} · {host.display_name}</small><small>{instance.configuration.peers.length} devices · {healthLabel(instance.configuration.instance.id)}</small></span><span class="instance-state" data-state="configuration">{configurationStatus(instance.revision, inventory.discovery.deployments?.[instance.configuration.instance.id]?.deployed_revision)}</span><span class="instance-chevron" aria-hidden="true">›</span></button>{/each}</div>
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
  .error-details { margin-top: 0.75rem; }
  .error-details summary { cursor: pointer; }
  .error-details pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 20rem; overflow: auto; }
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

<Notifications {notifications} />
{#if showActivity}
  <ModalShell returnFocus={dialogTrigger} title="Activity" eyebrow="This session" onclose={() => showActivity = false}>
    <p>Recent operation summaries. Deployment history remains available in Logs.</p>
    <ul class="activity-list">{#each $activity as item}<li>{item.message}<time>{new Date(item.timestamp).toLocaleString()}</time></li>{:else}<li>No activity yet.</li>{/each}</ul>
  </ModalShell>
{/if}

{#if review}
  <ModalShell returnFocus={dialogTrigger} title="Review configuration changes" onclose={() => review = null}>
    <ConfigurationReview local={review.local} server={review.server} base={review.base} />
    <button class="secondary" disabled={!online || Boolean(busy)} onclick={reloadInstance}>Discard local edits and reload</button>
  </ModalShell>
{/if}

{#if exportDevice}
  <ModalShell returnFocus={dialogTrigger} title="Get Configuration" eyebrow={`${exportDevice.display_name} · ${nameOf(selected!.configuration.instance.backend)}`} onclose={closeExport}>
    <p>This configuration contains private VPN credentials. Keep it private and share it only with the intended device.</p>
    {#if error && ["Preparing private configuration QR code", "Copying private configuration", "Downloading private configuration"].includes(errorOperation)}<div class="alert" role="alert">{error.message}</div>{/if}
    {#if exportReason}<p>{exportReason}</p>{/if}
    {#if observation?.deployed_revision !== selected!.revision}<p>Saved changes have not yet been deployed. This configuration may require deployment before it can connect.</p>{/if}
    {#if qrImage}<img class="configuration-qr" src={qrImage} alt="Private VPN client configuration QR code" width="384" height="384" />{/if}
    <div class="export-actions">
      {#if ["wireguard", "amnezia_wg"].includes(selected!.configuration.instance.backend)}<button class="primary" disabled={Boolean(exportReason) || Boolean(busy)} onclick={() => showPeerQr(exportDevice!.id)}>Show QR code</button>{/if}
      <button class="secondary" disabled={Boolean(exportReason) || Boolean(busy)} onclick={() => exportPeer(exportDevice!.id)}>Download configuration file</button>
      {#if selected!.configuration.instance.backend !== "ikev2"}<button class="secondary" disabled={Boolean(exportReason) || Boolean(busy)} onclick={() => copyPeer(exportDevice!.id)}>Copy configuration text</button><p>Copied credentials may remain in system clipboard history or be accessible to other applications.</p>{:else}<p>IKEv2 uses a binary PKCS#12 credential bundle. Import the downloaded file using your VPN client’s certificate workflow; QR and text import are unsupported.</p>{/if}
      {#if selected!.configuration.instance.backend === "openvpn"}<p>Import the downloaded .ovpn file in a compatible OpenVPN client. QR import is unsupported.</p>{/if}
    </div>
    {#if busy}<p role="status">{busy}…</p>{/if}
  </ModalShell>
{/if}
