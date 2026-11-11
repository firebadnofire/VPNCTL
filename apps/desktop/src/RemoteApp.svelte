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
  let draftTimer: ReturnType<typeof setTimeout> | undefined;
  onDestroy(() => clearTimeout(draftTimer));
  function scheduleDraft() { clearTimeout(draftTimer); draftTimer = setTimeout(() => { void retainDraft(); }, 300); }
  $: host = hosts.find((item) => item.id === selectedHostId);
  $: eligibleLocalLegacyInstances = candidates.filter((candidate) => candidate.supported);
  $: showMigrationUI = eligibleLocalLegacyInstances.length > 0;
  $: dirty = Boolean(selected && draft && JSON.stringify(draft) !== JSON.stringify(selected.configuration));
  $: online = connection === "connected" && !inventory?.cached;
  $: observation = selected ? inventory?.discovery.deployments?.[selected.configuration.instance.id] : undefined;
  $: certificateBackend = draft?.instance.backend === "openvpn" || draft?.instance.backend === "ikev2";
  $: certificateAuthorityReady = !certificateBackend || observation?.deployed_revision != null;
  $: BackendForm = backendForms[instanceForm.backend];
  $: SettingsBackendForm = backendForms[settingsForm.backend];
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
      hosts = savedHosts; candidates = legacy; hostForm.username = info.system_username;
    });
    if (hosts.length) await selectServer(hosts[0].id);
    initialized = true;
  });
  async function selectServer(id: string) {
    if (dirty && !(await retainDraft())) return;
    selectedHostId = id; selected = null; draft = null; inventory = null; inspection = null; probe = null;
    plan = null; page = "server"; serverTab = "Overview"; await refreshServer();
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
          selected = null; draft = null; plan = null;
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
    selected = manifest; draft = copy(manifest.configuration); baseRevision = manifest.revision;
    plan = null; tab = "Overview"; availability = []; history = []; runtimeHistory = [];
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
      if (!error) await openInstance(fresh);
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
    if (saved) { peerName = ""; peerDns = ""; await refreshServer(); await openInstance(saved); tab = "Peers / Devices"; }
  }
  async function exportPeer(peerId: string) {
    if (!selected) return;
    const extension = selected.configuration.instance.backend === "openvpn" ? "client.ovpn" : selected.configuration.instance.backend === "ikev2" ? "client.p12" : "client.conf";
    const destination = await save({ title: "Export complete client configuration", defaultPath: extension });
    if (destination) await task("Exporting through native credential storage", () => call<void>("export_remote_peer", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, peerId, destination }));
  }
  async function revokePeer(peerId: string, peerName: string) {
    if (!selected || dirty || !await confirm("Revoke the certificate for " + peerName + "? This cannot be reversed. Deployment is still required to apply the revocation.", { title: "Revoke peer certificate", kind: "warning" })) return;
    const saved = await task("Revoking peer certificate", () => call<Manifest>("revoke_remote_peer", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, peerId, expectedRevision: baseRevision, confirmed: true }));
    if (saved) { await refreshServer(); await openInstance(saved); tab = "Peers / Devices"; }
  }
  async function removeInstance() {
    if (!selected || dirty || !await confirm("Stop and archive this instance on " + host?.display_name + "? Its saved history and recovery backup will be retained.", { title: "Remove instance", kind: "warning" })) return;
    const removed = await task("Archiving instance", () => call<Manifest>("remove_remote_configuration", { input: { host_id: selectedHostId, expected_revision: baseRevision, request_id: crypto.randomUUID(), configuration: selected!.configuration }, confirmed: true }));
    if (removed) { selected = null; draft = null; plan = null; notice = "Instance archived on server."; await refreshServer(); }
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
    if (result) { await refreshServer(); await openInstance(result); tab = "Deployment"; }
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
  <aside>
    <div class="brand"><div class="mark">V</div><div><strong>VPNCTL</strong><span>Remote VPN appliances</span></div></div>
    <nav aria-label="Servers"><h2>Servers</h2>
      {#each hosts as server}<button class:active={selectedHostId === server.id} disabled={Boolean(busy)} onclick={() => selectServer(server.id)}>{server.display_name}</button>{/each}
      <button disabled={!initialized || Boolean(busy)} onclick={() => { page = "add-server"; }}>+ Add Server</button>
      {#if showMigrationUI}<button disabled={!initialized || Boolean(busy)} onclick={() => { page = "migration"; migrationDestination = selectedHostId; }}>Migrate Instances ({eligibleLocalLegacyInstances.length})</button>{/if}
    </nav>
  </aside>
  <main>
    {#if busy}<div class="progress" role="status">{busy}…</div>{/if}
    {#if notice}<div class="notice" role="status"><span>{notice}</span><button aria-label="Dismiss notice" onclick={() => notice = ""}>×</button></div>{/if}
    {#if error}<div class="alert" role="alert"><div><strong>{error.message}</strong>{#if error.remediation}<p>{error.remediation}</p>{/if}{#if error.code === "revision_conflict"}<p>Your local draft is retained. Reload after reviewing the server’s changes.</p>{/if}</div><button aria-label="Dismiss error" onclick={() => error = null}>×</button></div>{/if}
    {#if page === "add-server"}
      <header><h1>Add Server</h1></header>
      <form class="card remote-form" onsubmit={(event) => { event.preventDefault(); void addServer(); }}>
        <label>Server name<input required bind:value={hostForm.display_name} /></label><label>SSH hostname<input required bind:value={hostForm.hostname} /></label>
        <label>SSH username<input required bind:value={hostForm.username} /></label><label>SSH port<input required type="number" min="1" max="65535" bind:value={hostForm.port} /></label>
        <label>Private key path<input required bind:value={hostForm.private_key_path} /></label>
        <button class="secondary" type="button" onclick={async () => { const path = await open({ multiple: false, title: "Choose SSH private key" }); if (typeof path === "string") hostForm.private_key_path = path; }}>Choose key</button>
        <label>Key passphrase<input type="password" autocomplete="off" bind:value={hostForm.passphrase} /></label><button class="primary" disabled={Boolean(busy)}>Add Server</button>
      </form>
    {:else if page === "migration" && showMigrationUI}
      <header><h1>Migrate local instances</h1></header>
      <label>Destination server<select bind:value={migrationDestination}><option value="">Select a server</option>{#each hosts as server}<option value={server.id}>{server.display_name}</option>{/each}</select></label>
      {#each eligibleLocalLegacyInstances as candidate}<section class="card"><h2>{candidate.display_name}</h2><p>{nameOf(candidate.backend)} · {candidate.instance_id}</p><button class="secondary" disabled={!migrationDestination || Boolean(busy)} onclick={() => previewMigration(candidate.instance_id)}>Preview migration</button></section>{/each}
      {#if migrationPreview}<section class="card"><h2>Migration preview</h2><p>{migrationPreview.deployment_present ? "Existing deployment and identities will be preserved." : "Configuration will be saved without deploying containers."}</p>{#each migrationPreview.warnings as warning}<p>{warning}</p>{/each}{#each migrationPreview.issues as issue}<p class="danger">{issue}</p>{/each}<button class="primary" disabled={Boolean(busy) || migrationPreview.issues.length > 0} onclick={migrate}>Back Up and Migrate</button></section>{/if}
    {:else if page === "create-instance"}
      <header><h1>Create Instance on {host?.display_name}</h1></header>
      <form class="card remote-form" onsubmit={(event) => { event.preventDefault(); void createInstance(); }}>
        <label>Instance name<input required bind:value={instanceForm.display_name} /></label>
        <label>Backend<select bind:value={instanceForm.backend} onchange={() => { instanceForm.endpoint_port = backends.find((backend) => backend.kind === instanceForm.backend)!.port; }}>{#each backends as backend}<option value={backend.kind}>{backend.name}</option>{/each}</select></label>
        <label>VPN endpoint<input required bind:value={instanceForm.endpoint_host} /></label><label>Listener port<input type="number" min="1" max="65535" disabled={instanceForm.backend === "ikev2"} bind:value={instanceForm.endpoint_port} /></label>
        <label>IPv4 subnet<input required bind:value={instanceForm.ipv4_subnet} /></label><label>Private DNS zone<input required bind:value={instanceForm.dns_zone} /></label>
        {#if BackendForm}<BackendForm bind:form={instanceForm} />{/if}<button class="primary" disabled={!online || Boolean(busy)}>Save to Server</button>
      </form>
    {:else if !host}
      <header><h1>Servers</h1></header><section class="card"><h2>Connect your first VPN server</h2><p>Add a Linux server using a verified SSH connection.</p><button class="primary" onclick={() => page = "add-server"}>Add Server</button></section>
    {:else}
      <header><div><p class="eyebrow">SERVER · {connection}</p><h1>{host.display_name}</h1><p>{host.ssh.username}@{host.ssh.hostname}:{host.ssh.port}</p></div><button class="secondary" disabled={Boolean(busy)} onclick={refreshServer}>Refresh / Reconnect</button></header>
      {#if inventory?.cached}<div class="alert" role="status">Offline · showing cached information from {new Date(inventory.synchronized_at).toLocaleString()}. Saving and deployment require a live connection.</div>{/if}
      {#if inventory && Object.keys(inventory.discovery.errors).length}<div class="alert" role="alert">Some remote instance metadata could not be read. The server is not empty.<ul>{#each Object.values(inventory.discovery.errors) as problem}<li>{problem}</li>{/each}</ul></div>{/if}
      {#if selected && draft}
        <button class="menu" onclick={async () => { if (!dirty || await retainDraft()) { selected = null; draft = null; } }}>← Server instances</button>
        <section class="card" oninput={scheduleDraft}>
          <header><div><h2>{draft.instance.display_name}</h2><p>{nameOf(draft.instance.backend)} · saved revision {selected.revision} · {observation?.deployed_revision == null ? "Deployment revision unknown" : "deployed revision " + observation.deployed_revision}</p></div><div class="header-actions"><button class="secondary" disabled={!online || Boolean(busy)} onclick={reloadInstance}>Reload from Server</button><button class="primary" disabled={!dirty || !online || Boolean(busy)} onclick={saveDraft}>Save to Server</button></div></header>
          {#if dirty}<div class="notice" role="status">Unsaved local edits · based on revision {baseRevision}</div>{/if}
          {#if baseRevision !== selected.revision}<div class="alert">This draft is based on an older revision. Reload or reconcile your edits before saving.</div>{/if}
          {#if observation?.deployed_revision !== selected.revision}<div class="notice" role="status">Pending deployment · saved desired state differs from the deployed revision.</div>{/if}
          {#if observation?.pending_operation}<div class="alert" role="alert">An interrupted runtime operation requires reconciliation before another mutation. <button class="secondary" disabled={!online || Boolean(busy)} onclick={reconcileRuntime}>Check operation outcome</button></div>{/if}
          <div class="tabs" role="tablist" aria-label="Instance sections">{#each tabs as item}<button role="tab" aria-selected={tab === item} class:active={tab === item} onclick={() => tab = item}>{item}</button>{/each}</div>
          {#if tab === "Overview"}<h3>Remote configuration</h3><dl><dt>Owning server</dt><dd>{host.display_name}</dd><dt>Endpoint</dt><dd>{draft.instance.endpoint.host}:{draft.instance.endpoint.port}</dd><dt>Peers / devices</dt><dd>{draft.peers.length}</dd><dt>Network</dt><dd>{draft.instance.network.ipv4_subnet}</dd><dt>Last saved</dt><dd>{new Date(selected.saved_at).toLocaleString()}</dd></dl>
          {:else if tab === "Peers / Devices"}
            <table><thead><tr><th>Name</th><th>Address</th><th>State</th><th>Local export</th><th>Action</th></tr></thead><tbody>{#each draft.peers as peer}<tr><td><input aria-label={"Peer name " + peer.display_name} bind:value={peer.display_name} /></td><td>{peer.ipv4_address}</td><td>{#if draft.instance.backend === "openvpn" || draft.instance.backend === "ikev2"}{peer.enabled ? "Active" : "Revoked"}{:else}<input aria-label={"Enable " + peer.display_name} type="checkbox" bind:checked={peer.enabled} />{/if}</td><td><button class="secondary" disabled={!online || dirty || !availability.find((item) => item.peer_id === peer.id)?.complete_export_available} onclick={() => exportPeer(peer.id)}>Export configuration</button>{#if !availability.find((item) => item.peer_id === peer.id)?.complete_export_available}<p>Private material unavailable on this client</p>{/if}</td><td>{#if (draft.instance.backend === "openvpn" || draft.instance.backend === "ikev2") && peer.enabled}<button class="secondary" disabled={!online || dirty || Boolean(busy)} onclick={() => revokePeer(peer.id, peer.display_name)}>Revoke certificate</button>{/if}</td></tr>{/each}</tbody></table>
            <form class="remote-form" onsubmit={(event) => { event.preventDefault(); void addPeer(); }}><h3>Add peer / device</h3><label>Peer name<input required bind:value={peerName} /></label><label>DNS name (optional)<input bind:value={peerDns} /></label><p>Save or discard existing edits before creating a peer.</p>{#if !certificateAuthorityReady}<p>Deploy this instance once to establish its certificate authority before enrolling peers.</p>{/if}<button class="primary" disabled={!online || dirty || !certificateAuthorityReady || Boolean(busy)}>Create Peer on Server</button></form>
          {:else if tab === "DNS and Routing"}
            <label>Routing<select bind:value={draft.instance.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel</option></select></label>
            <table><thead><tr><th>Name</th><th>Type</th><th>Value</th><th>Action</th></tr></thead><tbody>{#each draft.dns_records as record}<tr><td>{record.name}</td><td>{record.record_type}</td><td>{record.value}</td><td><button class="secondary" onclick={() => { draft!.dns_records = draft!.dns_records.filter((item) => item.id !== record.id); void retainDraft(); }}>Remove from draft</button></td></tr>{/each}</tbody></table>
            <form class="remote-form" onsubmit={(event) => { event.preventDefault(); addDns(); }}><label>DNS record name<input required bind:value={dnsName} /></label><label>Record type<select bind:value={dnsType}>{#each ["A", "AAAA", "CNAME", "TXT", "SRV"] as type}<option>{type}</option>{/each}</select></label><label>Record value<input required bind:value={dnsValue} /></label><button class="secondary">Add to draft</button></form>
          {:else if tab === "Settings"}
            <form class="remote-form" oninput={applySettings} onchange={applySettings} onsubmit={(event) => { event.preventDefault(); applySettings(); }}><label>Instance name<input required bind:value={settingsForm.display_name} /></label><label>VPN endpoint<input required bind:value={settingsForm.endpoint_host} /></label><label>Listener port<input required type="number" min="1" max="65535" disabled={settingsForm.backend === "ikev2"} bind:value={settingsForm.endpoint_port} /></label><label>Private DNS zone<input required bind:value={settingsForm.dns_zone} /></label>{#if SettingsBackendForm}<SettingsBackendForm bind:form={settingsForm} />{/if}<button class="secondary">Keep local draft</button></form>
            <button class="danger" disabled={!online || dirty || Boolean(busy)} onclick={removeInstance}>Remove instance from server</button>
          {:else if tab === "Deployment"}
            <div class="header-actions"><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={previewDeployment}>Preview / Deploy</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={async () => { const result = await task("Checking deployment health", () => call<InstanceHealth>("inspect_remote_health", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id })); if (result) health = result; }}>Check health</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={async () => { await task("Creating runtime backup", () => call("backup_remote_deployment", { hostId: selectedHostId, instanceId: selected!.configuration.instance.id, expectedRevision: baseRevision })); if (!error) notice = "Runtime backup created on server."; }}>Create runtime backup</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadHistory}>View configuration history</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadRuntimeHistory}>View deployment history</button><button class="secondary" disabled={!online || Boolean(busy)} onclick={loadBackups}>View runtime backups</button></div>
            {#if dirty}<p>Save local edits to the server before previewing deployment.</p>{/if}
            {#if plan}<h3>Deployment preview for saved revision {baseRevision}</h3>{#each plan.warnings as warning}<p class="danger">{warning}</p>{/each}<ul>{#each plan.operations as operation}<li>{operation.operation.replaceAll("_", " ")} {operation.path ?? operation.service ?? ""}</li>{/each}</ul><button class="primary" disabled={Boolean(busy)} onclick={deploy}>Apply saved revision {baseRevision}</button>{/if}
            {#if health}<h3>Deployment health</h3><dl><dt>Gateway</dt><dd>{health.gateway_running ? "Running" : "Stopped / unavailable"}</dd><dt>Backend</dt><dd>{health.backend_ready ? "Ready" : "Needs attention"}</dd><dt>Listeners</dt><dd>{health.listeners_ready ? "Ready" : "Needs attention"}</dd><dt>Deployed peer state</dt><dd>{health.client_state_matches ? "Matches" : "Needs attention"}</dd>{#if health.dns_required}<dt>Private DNS</dt><dd>{health.private_dns_resolves ? "Resolving" : "Needs attention"}</dd><dt>Public DNS</dt><dd>{health.public_dns_resolves ? "Resolving securely" : "Needs attention"}</dd>{/if}</dl>{#if health.details.length}<details><summary>Health details</summary><ul>{#each health.details as detail}<li>{detail}</li>{/each}</ul></details>{/if}{/if}
            {#each backups as backup}<div class="history-row"><span>{backup.name} · {new Date(backup.created_at).toLocaleString()}</span><button class="secondary" disabled={!online || dirty || Boolean(busy)} onclick={() => previewRestore(backup.name)}>Preview deployment restore</button></div>{/each}
            {#if restorePreview}<section class="alert"><div><h3>Restore deployed revision {restorePreview.deployed_revision ?? "unknown"}</h3><p>{restorePreview.identity_impact}</p><p>Saved desired revision {restorePreview.desired_revision} will remain unchanged.</p><button class="primary" disabled={!online || dirty || Boolean(busy)} onclick={restoreDeployment}>Restore Deployment</button></div></section>{/if}
            {#each history as revision}<div class="history-row"><span>Desired revision {revision.revision} · {new Date(revision.saved_at).toLocaleString()}</span><button class="secondary" disabled={!online || dirty || revision.revision === selected.revision || Boolean(busy)} onclick={() => restoreDesired(revision.revision)}>Restore Desired Configuration</button></div>{/each}
            {#each runtimeHistory as event}<div class="history-row"><span>{event.operation.replaceAll("_", " ")} · desired revision {event.desired_revision} · {event.succeeded ? "Succeeded" : "Failed"}{event.requires_recovery ? " · Recovery required" : ""}{event.deployed_revision == null ? "" : " · deployed revision " + event.deployed_revision}</span></div>{/each}
          {/if}
        </section>
      {:else}
        <div class="tabs" role="tablist" aria-label="Server sections">{#each ["Overview", "Instances", "Host Management"] as item}<button role="tab" aria-selected={serverTab === item} class:active={serverTab === item} onclick={() => serverTab = item}>{item}</button>{/each}</div>
        {#if serverTab === "Host Management"}<section class="card"><h2>Host Management</h2><button class="secondary" onclick={probeServer}>Verify SSH host identity</button><button class="secondary" onclick={inspectServer}>Inspect host readiness</button>{#if probe}<h3>{probe.state === "changed" ? "Changed SSH host key" : "SSH host key"}</h3><p>{probe.key.sha256_fingerprint}</p><p>Verify this fingerprint through an independent trusted channel.</p><label>Exact verified fingerprint<input bind:value={fingerprint} /></label>{#if probe.state === "changed"}<label><input type="checkbox" bind:checked={replaceChanged} /> Explicitly replace the previously approved key</label>{/if}<button class="primary" disabled={fingerprint !== probe.key.sha256_fingerprint || (probe.state === "changed" && !replaceChanged)} onclick={approveIdentity}>Approve SSH identity</button>{/if}{#if inspection}<h3>Host readiness</h3><p>{inspection.inspection.operating_system} · {inspection.inspection.architecture}</p><p>Docker: {inspection.inspection.docker_version ?? "Unavailable"} · Compose: {inspection.inspection.compose_version ?? "Unavailable"}</p><HostReadinessMatrix view={inspection} />{/if}</section>
        {:else}
          {#if serverTab === "Overview"}<section class="card"><h2>Server overview</h2><p>Connection: {connection}</p><p>Appliance identity: {inventory?.identity.appliance_id ?? "Not synchronized"}</p><p>Last successful synchronization: {inventory ? new Date(inventory.synchronized_at).toLocaleString() : "Never"}</p><p>Managed instances: {inventory?.discovery.instances.length ?? "Unknown"}</p><button class="secondary" onclick={inspectServer}>Inspect OS, Docker and Compose</button>{#if inspection}<p>{inspection.inspection.operating_system} · {inspection.inspection.architecture}</p><p>Docker: {inspection.inspection.docker_version ?? "Unavailable"} · Compose: {inspection.inspection.compose_version ?? "Unavailable"}</p><HostReadinessMatrix view={inspection} />{/if}</section>{/if}
          <section class="card"><header><h2>Instances</h2><button class="primary" disabled={!online || Boolean(busy)} onclick={() => { instanceForm = newInstanceForm(selectedHostId, host!.ssh.hostname); page = "create-instance"; }}>Create Instance</button></header>
            {#if inventory?.discovery.instances.length}<div class="instance-grid">{#each inventory.discovery.instances as instance}<button class="instance-card" onclick={() => openInstance(instance)}><strong>{instance.configuration.instance.display_name}</strong><span>{nameOf(instance.configuration.instance.backend)} · {host.display_name}</span><span>{instance.configuration.peers.length} peers · saved revision {instance.revision}</span><span>{inventory.discovery.deployments?.[instance.configuration.instance.id]?.deployed_revision === instance.revision ? "Saved and deployed revisions match" : "Pending deployment / deployment revision unknown"}</span></button>{/each}</div>
            {:else if online && inventory && Object.keys(inventory.discovery.errors).length === 0}<h3>No VPN instances configured on this server.</h3><p>Create an instance to save its configuration on this server.</p>
            {:else if connection === "loading"}<p>Discovering remote instances…</p>{:else if !inventory}<p>Connect and verify this server to discover its instances.</p>{/if}
          </section>
        {/if}
      {/if}
    {/if}
    {#each candidates.filter((candidate) => !candidate.supported) as candidate}<section class="card"><h2>Unsupported local configuration: {candidate.display_name}</h2><p>Its source data and remote deployment are preserved. Export recovery metadata before retiring this local record.</p><button class="secondary" onclick={async () => { const destination = await save({ defaultPath: "vpnctl-recovery.json" }); if (destination) await task("Exporting recovery metadata", () => call("export_legacy_recovery", { instanceId: candidate.instance_id, destination })); }}>Export recovery metadata</button></section>{/each}
  </main>
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
