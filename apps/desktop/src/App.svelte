<script lang="ts">
  import { open, save, confirm } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import { call, errorText } from "./lib/api";
  import type {
    AppError,
    AppInfo,
    BackupInfo,
    DeploymentPlan,
    DeploymentProgress,
    Device,
    DnsRecord,
    DnsRecordType,
    DockerHost,
    HostInspection,
    HostKeyProbe,
    InstanceHealth,
    VpnInstance,
  } from "./lib/types";

  type Section = "Hosts" | "Instances" | "Devices" | "DNS" | "Backups" | "Logs";
  type Modal =
    | "host"
    | "trust"
    | "instance"
    | "device"
    | "dns"
    | "plan"
    | "qr"
    | null;

  const sections: Section[] = ["Hosts", "Instances", "Devices", "DNS", "Backups", "Logs"];
  const recordTypes: DnsRecordType[] = ["A", "AAAA", "CNAME", "TXT", "SRV"];
  function shellSingleQuote(value: string) {
    return `'${value.replaceAll("'", "'\"'\"'")}'`;
  }

  function remoteHostKeyCommand(fingerprint: string) {
    return `for key in /etc/ssh/ssh_host_*_key.pub; do test -r "$key" && ssh-keygen -l -E sha256 -f "$key"; done | grep -F ${shellSingleQuote(fingerprint)}`;
  }

  let active: Section = "Hosts";
  let modal: Modal = null;
  let appInfo: AppInfo = {
    name: "VPN Appliance Manager",
    version: "0.1.0",
    status: "starting",
    system_username: "",
  };
  let hosts: DockerHost[] = [];
  let instances: VpnInstance[] = [];
  let devices: Device[] = [];
  let records: DnsRecord[] = [];
  let backups: BackupInfo[] = [];
  let logs: DeploymentProgress[] = [];
  let selectedHostId = "";
  let selectedInstanceId = "";
  let selectedDeviceId = "";
  let busy = "";
  let notice = "";
  let error: AppError | null = null;
  let inspection: HostInspection | null = null;
  let probe: HostKeyProbe | null = null;
  let defaultSshUsername = "";
  let fingerprintConfirmation = "";
  let replaceChangedKey = false;
  let plan: DeploymentPlan | null = null;
  let qrSvg = "";
  let technicalOpen = false;

  let hostForm = {
    display_name: "",
    hostname: "",
    port: 22,
    username: "",
    private_key_path: "",
    passphrase: "",
  };
  let instanceForm = {
    display_name: "",
    host_id: "",
    endpoint_host: "",
    endpoint_port: 51820,
    ipv4_subnet: "10.64.0.0/24",
    dns_zone: "vpn.internal",
    routing_mode: "split_tunnel",
  };
  let deviceForm = {
    instance_id: "",
    display_name: "",
    preshared_key: true,
    create_dns_record: true,
    dns_name: "",
  };
  let dnsForm: {
    instance_id: string;
    name: string;
    record_type: DnsRecordType;
    value: string;
    ttl: number;
  } = { instance_id: "", name: "", record_type: "A", value: "", ttl: 300 };

  $: selectedInstance = instances.find((item) => item.id === selectedInstanceId);
  $: selectedHost = hosts.find((item) => item.id === selectedHostId);
  $: instanceDevices = devices.filter((item) => item.instance_id === selectedInstanceId);
  $: instanceRecords = records.filter((item) => item.instance_id === selectedInstanceId);

  onMount(load);

  async function load() {
    try {
      appInfo = await call<AppInfo>("app_info");
      defaultSshUsername = appInfo.system_username;
      await refresh();
    } catch (cause) {
      setError(cause);
      appInfo.status = "unavailable";
    }
  }

  async function refresh() {
    const [nextHosts, nextInstances, nextLogs] = await Promise.all([
      call<DockerHost[]>("list_hosts"),
      call<VpnInstance[]>("list_instances", { hostId: null }),
      call<DeploymentProgress[]>("logs", { instanceId: null }),
    ]);
    hosts = nextHosts;
    instances = nextInstances;
    logs = nextLogs;
    if (selectedHostId && !hosts.some((host) => host.id === selectedHostId)) selectedHostId = "";
    if (selectedInstanceId && !instances.some((instance) => instance.id === selectedInstanceId)) selectedInstanceId = "";
    if (!selectedHostId && hosts[0]) selectedHostId = hosts[0].id;
    if (!selectedInstanceId && instances[0]) selectedInstanceId = instances[0].id;
    if (selectedInstanceId) await refreshInstanceData();
  }

  async function refreshInstanceData() {
    if (!selectedInstanceId) {
      devices = [];
      records = [];
      backups = [];
      return;
    }
    [devices, records, backups] = await Promise.all([
      call<Device[]>("list_devices", { instanceId: selectedInstanceId }),
      call<DnsRecord[]>("list_dns_records", { instanceId: selectedInstanceId }),
      call<BackupInfo[]>("list_backups", { instanceId: selectedInstanceId }),
    ]);
  }

  async function task<T>(label: string, operation: () => Promise<T>): Promise<T | undefined> {
    busy = label;
    notice = "";
    error = null;
    technicalOpen = false;
    try {
      return await operation();
    } catch (cause) {
      setError(cause);
      return undefined;
    } finally {
      busy = "";
    }
  }

  function setError(cause: unknown) {
    if (typeof cause === "object" && cause !== null && "message" in cause) {
      error = cause as AppError;
    } else {
      error = {
        code: "unexpected",
        message: errorText(cause),
        remote_state_changed: false,
      };
    }
  }

  function openHost() {
    hostForm = {
      display_name: "",
      hostname: "",
      port: 22,
      username: defaultSshUsername,
      private_key_path: "",
      passphrase: "",
    };
    modal = "host";
  }

  async function chooseKey() {
    const result = await open({ multiple: false, directory: false, title: "Choose an SSH private key" });
    if (typeof result === "string") hostForm.private_key_path = result;
  }

  async function saveHost() {
    const created = await task("Saving host", () =>
      call<DockerHost>("create_host", {
        input: {
          ...hostForm,
          passphrase: hostForm.passphrase || null,
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedHostId = created.id;
    await refresh();
    notice = "Host saved. Probe its SSH key before inspection.";
  }

  async function probeHost(host: DockerHost) {
    selectedHostId = host.id;
    const result = await task("Probing SSH host key", () =>
      call<HostKeyProbe>("probe_host_key", { hostId: host.id }),
    );
    if (!result) return;
    probe = result;
    fingerprintConfirmation = "";
    replaceChangedKey = false;
    modal = "trust";
  }

  async function approveKey() {
    if (!probe || !selectedHostId) return;
    const approved = await task("Approving SSH host key", () =>
      call<void>("approve_host_key", {
        hostId: selectedHostId,
        probed: probe?.key,
        expectedFingerprint: fingerprintConfirmation,
        replaceChangedKey,
      }),
    );
    if (approved === undefined && error) return;
    modal = null;
    notice = "SSH host key approved.";
  }

  async function inspect(host: DockerHost) {
    selectedHostId = host.id;
    const result = await task("Inspecting host", () =>
      call<HostInspection>("inspect_host", { hostId: host.id }),
    );
    if (result) inspection = result;
  }

  async function removeHost(host: DockerHost) {
    const accepted = await confirm(
      `Delete "${host.display_name}" from local host management? Existing instances on this host must be deleted first.`,
      { title: "Delete Docker host", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Deleting host", () =>
      call<void>("delete_host", { hostId: host.id }),
    );
    if (result === undefined && error) return;
    if (selectedHostId === host.id) {
      selectedHostId = "";
      inspection = null;
      probe = null;
    }
    await refresh();
    notice = "Host deleted.";
  }

  function openInstance() {
    instanceForm = {
      display_name: "",
      host_id: selectedHostId || hosts[0]?.id || "",
      endpoint_host: hosts.find((host) => host.id === selectedHostId)?.ssh.hostname || "",
      endpoint_port: 51820,
      ipv4_subnet: "10.64.0.0/24",
      dns_zone: "vpn.internal",
      routing_mode: "split_tunnel",
    };
    modal = "instance";
  }

  async function saveInstance() {
    const created = await task("Creating instance", () =>
      call<VpnInstance>("create_instance", { input: instanceForm }),
    );
    if (!created) return;
    modal = null;
    selectedInstanceId = created.id;
    await refresh();
    notice = "Instance created locally. Review its deployment plan to apply it.";
  }

  async function reviewPlan(instance: VpnInstance) {
    selectedInstanceId = instance.id;
    const result = await task("Calculating deployment plan", () =>
      call<DeploymentPlan>("plan_instance", { instanceId: instance.id }),
    );
    if (!result) return;
    plan = result;
    modal = "plan";
  }

  async function applyPlan() {
    if (!plan) return;
    const result = await task("Applying and verifying deployment", () =>
      call<{ status: string }>("apply_instance", {
        instanceId: plan?.instance_id,
        expectedStateHash: plan?.desired_state_hash,
      }),
    );
    if (!result) return;
    modal = null;
    notice = `Deployment ${result.status}.`;
    await refresh();
  }

  async function instanceAction(command: "start_instance" | "stop_instance" | "health", instance: VpnInstance) {
    const result = await task(command.replace("_", " "), () =>
      call<InstanceHealth>(command, { instanceId: instance.id }),
    );
    if (result) {
      notice = healthSummary(result);
    }
  }

  function healthSummary(health: InstanceHealth) {
    const values = Object.entries(health).filter(([key]) => key !== "details");
    const healthy = values.filter(([, value]) => value === true).length;
    return `${healthy}/${values.length} health checks passing.`;
  }

  async function removeInstance(instance: VpnInstance) {
    const accepted = await confirm(
      `Back up, stop, and move "${instance.display_name}" to recoverable remote trash?`,
      { title: "Delete VPN instance", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Deleting instance", () =>
      call<void>("delete_instance", { instanceId: instance.id }),
    );
    if (result === undefined && error) return;
    selectedInstanceId = "";
    await refresh();
    notice = "Instance moved to remote trash and soft-deleted locally.";
  }

  function openDevice() {
    deviceForm = {
      instance_id: selectedInstanceId || instances[0]?.id || "",
      display_name: "",
      preshared_key: true,
      create_dns_record: true,
      dns_name: "",
    };
    modal = "device";
  }

  async function saveDevice() {
    const created = await task("Generating device identity", () =>
      call<Device>("create_device", {
        input: {
          ...deviceForm,
          user_id: null,
          dns_name: deviceForm.dns_name || null,
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedInstanceId = created.instance_id;
    await refreshInstanceData();
    notice = "Device keys were generated locally and saved in Keychain.";
  }

  async function toggleDevice(device: Device) {
    const updated = { ...device, enabled: !device.enabled };
    const result = await task("Updating device", () =>
      call<Device>("update_device", { device: updated }),
    );
    if (result) await refreshInstanceData();
  }

  async function replaceDeviceIdentity(device: Device) {
    const accepted = await confirm(
      `Replace the cryptographic identity for "${device.display_name}"? Its previous configuration will stop working after deployment.`,
      { title: "Replace device identity", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Replacing device identity", () =>
      call<Device>("replace_device_identity", { deviceId: device.id }),
    );
    if (!result) return;
    await refreshInstanceData();
    notice = "A new Keychain identity was created. Deploy before exporting the replacement configuration.";
  }

  async function removeDevice(device: Device) {
    const accepted = await confirm(
      `Remove "${device.display_name}" and its managed DNS record? Its address remains reserved by retained deployment snapshots.`,
      { title: "Remove device", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Removing device", () =>
      call<void>("delete_device", { deviceId: device.id }),
    );
    if (result === undefined && error) return;
    await refreshInstanceData();
    notice = "Device removed locally. Deploy the instance to revoke its peer.";
  }

  async function exportDevice(device: Device) {
    const destination = await save({
      title: "Export WireGuard configuration",
      defaultPath: `${device.display_name.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}.conf`,
      filters: [{ name: "WireGuard configuration", extensions: ["conf"] }],
    });
    if (!destination) return;
    const result = await task("Exporting private configuration", () =>
      call<string>("export_client_configuration", {
        deviceId: device.id,
        destination,
      }),
    );
    if (result) notice = `Configuration exported to ${result} with mode 0600.`;
  }

  async function showQr(device: Device) {
    selectedDeviceId = device.id;
    const result = await task("Generating QR code", () =>
      call<string>("client_qr_svg", { deviceId: device.id }),
    );
    if (!result) return;
    qrSvg = result;
    modal = "qr";
  }

  function openDns() {
    dnsForm = {
      instance_id: selectedInstanceId || instances[0]?.id || "",
      name: "",
      record_type: "A",
      value: "",
      ttl: 300,
    };
    modal = "dns";
  }

  async function saveDns() {
    const result = await task("Validating DNS record", () =>
      call<DnsRecord>("create_dns_record", { input: dnsForm }),
    );
    if (!result) return;
    modal = null;
    selectedInstanceId = result.instance_id;
    await refreshInstanceData();
    notice = "DNS record saved. The instance now has pending desired-state changes.";
  }

  async function removeDns(record: DnsRecord) {
    const accepted = await confirm(`Delete ${record.name} ${record.record_type}?`, {
      title: "Delete DNS record",
      kind: "warning",
    });
    if (!accepted) return;
    const result = await task("Deleting DNS record", () =>
      call<void>("delete_dns_record", {
        recordId: record.id,
        instanceId: record.instance_id,
      }),
    );
    if (result === undefined && error) return;
    await refreshInstanceData();
  }

  async function makeBackup() {
    if (!selectedInstanceId) return;
    const result = await task("Creating remote backup", () =>
      call<BackupInfo>("create_backup", { instanceId: selectedInstanceId }),
    );
    if (!result) return;
    await refreshInstanceData();
    notice = `Backup ${result.name} created.`;
  }

  async function rollbackBackup(backup: BackupInfo) {
    if (!backup.deployment_id) return;
    const accepted = await confirm(
      `Re-render and apply deployment ${backup.deployment_id} with a fresh DNS serial?`,
      { title: "Rollback instance", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Rolling back deployment", () =>
      call<{ status: string }>("rollback", { deploymentId: backup.deployment_id }),
    );
    if (!result) return;
    await refresh();
    notice = `Rollback ${result.status}.`;
  }
</script>

<svelte:head><title>{active} · VPN Appliance Manager</title></svelte:head>

<div class="shell">
  <aside>
    <div class="brand">
      <div class="mark">VA</div>
      <div><strong>VPN Appliance</strong><span>Manager</span></div>
    </div>
    <nav aria-label="Primary">
      {#each sections as section}
        <button class:active={active === section} onclick={() => (active = section)}>
          <span class="nav-dot"></span>{section}
        </button>
      {/each}
    </nav>
  </aside>

  <main>
    <header>
      <div><p class="eyebrow">CONTROL PLANE</p><h1>{active}</h1></div>
      <div class="header-actions">
        {#if active === "Hosts"}<button class="primary" onclick={openHost}>Add host</button>{/if}
        {#if active === "Instances"}<button class="primary" onclick={openInstance} disabled={!hosts.length}>Create instance</button>{/if}
        {#if active === "Devices"}
          <button class="primary" onclick={openDevice} disabled={!instances.length}>Add device</button>
        {/if}
        {#if active === "DNS"}<button class="primary" onclick={openDns} disabled={!instances.length}>Add record</button>{/if}
        {#if active === "Backups"}<button class="primary" onclick={makeBackup} disabled={!selectedInstanceId}>Create backup</button>{/if}
      </div>
    </header>

    {#if busy}<div class="progress"><span></span>{busy}…</div>{/if}
    {#if notice}<div class="notice" role="status">{notice}<button aria-label="Dismiss" onclick={() => (notice = "")}>×</button></div>{/if}
    {#if error}
      <div class="alert" role="alert">
        <div>
          <strong>{error.message}</strong>
          {#if error.remediation}<p>{error.remediation}</p>{/if}
          {#if error.remote_state_changed}
            <p>Remote state changed. Rollback {error.rollback_succeeded ? "succeeded" : "did not succeed"}.</p>
          {/if}
          {#if error.technical_detail}
            <button class="text-button" onclick={() => (technicalOpen = !technicalOpen)}>
              {technicalOpen ? "Hide" : "Show"} technical details
            </button>
            {#if technicalOpen}<pre>{error.technical_detail}</pre>{/if}
          {/if}
        </div>
        <button aria-label="Dismiss" onclick={() => (error = null)}>×</button>
      </div>
    {/if}

    {#if active === "Hosts"}
      {#if hosts.length === 0}
        <section class="hero">
          <div>
            <span class="pill">FIRST RUN</span>
            <h2>Connect your first Docker host</h2>
            <p>Add a Linux server, verify its SSH fingerprint, then inspect Docker and Compose before anything changes remotely.</p>
            <button class="primary" onclick={openHost}>Add SSH host</button>
          </div>
          <div class="checklist">
            <div><b>1</b><span><strong>SSH trust</strong><small>Explicit SHA-256 host-key approval</small></span></div>
            <div><b>2</b><span><strong>Runtime inspection</strong><small>Linux, Docker, Compose, WireGuard</small></span></div>
            <div><b>3</b><span><strong>Desired-state deploy</strong><small>Plan, backup, apply, verify</small></span></div>
          </div>
        </section>
      {/if}
      <section class="panel">
        <div class="panel-head"><h3>Docker hosts</h3><span>{hosts.length} configured</span></div>
        {#if hosts.length}
          <div class="rows">
            {#each hosts as host}
              <article class:selected={host.id === selectedHostId}>
                <div class="status-icon">⌁</div>
                <button class="row-main row-select" onclick={() => (selectedHostId = host.id)}>
                  <strong>{host.display_name}</strong>
                  <small>{host.ssh.username}@{host.ssh.hostname}:{host.ssh.port}</small>
                </button>
                <button class="secondary" onclick={() => probeHost(host)}>Verify key</button>
                <button class="secondary" onclick={() => inspect(host)}>Inspect</button>
                <button class="menu danger" title="Delete" onclick={() => removeHost(host)}>Delete</button>
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><div class="server-icon">⌁</div><h3>No hosts yet</h3><p>Your SSH keys stay on this Mac and host keys are never accepted silently.</p></div>
        {/if}
      </section>
      {#if inspection && selectedHost}
        <section class="panel compact">
          <div class="panel-head"><h3>{selectedHost.display_name} inspection</h3><span>{inspection.operating_system} · {inspection.architecture}</span></div>
          <div class="checks">
            <div class:pass={inspection.docker_accessible}><b>Docker</b><span>{inspection.docker_version || "Not found"}</span></div>
            <div class:pass={Boolean(inspection.compose_version)}><b>Compose plugin</b><span>{inspection.compose_version || "Not found"}</span></div>
            <div class:pass={inspection.wireguard_kernel_available}><b>WireGuard</b><span>{inspection.wireguard_kernel_available ? "Available" : "Userspace fallback via container"}</span></div>
            <div class:pass={inspection.application_root_writable || inspection.sudo_bootstrap_available}><b>/opt bootstrap</b><span>{inspection.application_root_writable ? "Writable" : inspection.sudo_bootstrap_available ? "sudo -n available" : "Blocked"}</span></div>
          </div>
          {#if inspection.warnings.length}
            <div class="warning-list">
              {#each inspection.warnings as warning}<div class="warning">{warning}</div>{/each}
            </div>
          {/if}
        </section>
      {/if}
    {:else if active === "Instances"}
      <section class="stats">
        <article><span>Instances</span><strong>{instances.length}</strong><small>Across all hosts</small></article>
        <article><span>Managed hosts</span><strong class="green">{hosts.length}</strong><small>Explicit SSH trust</small></article>
        <article><span>Selected</span><strong>{selectedInstance ? "1" : "0"}</strong><small>{selectedInstance?.display_name || "None"}</small></article>
      </section>
      <section class="panel">
        {#if instances.length}
          <div class="rows instance-rows">
            {#each instances as instance}
              <article class:selected={instance.id === selectedInstanceId}>
                <div class="status-icon">WG</div>
                <button class="row-main row-select" onclick={() => { selectedInstanceId = instance.id; refreshInstanceData(); }}>
                  <strong>{instance.display_name}</strong>
                  <small>{instance.endpoint.host}:{instance.endpoint.port} · {instance.network.ipv4_subnet} · {instance.dns.zone}</small>
                </button>
                <button class="secondary" onclick={() => instanceAction("start_instance", instance)}>Start</button>
                <button class="secondary" onclick={() => instanceAction("stop_instance", instance)}>Stop</button>
                <button class="secondary" onclick={() => instanceAction("health", instance)}>Health</button>
                <button class="secondary" title="Preview deployment changes before applying them" onclick={() => reviewPlan(instance)}>Preview deploy</button>
                <button class="menu danger" title="Delete" onclick={() => removeInstance(instance)}>Delete</button>
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No VPN instances</h3><p>Create a WireGuard appliance after adding and approving a Docker host.</p></div>
        {/if}
      </section>
    {:else if active === "Devices"}
      <div class="toolbar">
        <label>Instance<select bind:value={selectedInstanceId} onchange={refreshInstanceData}><option value="">Select…</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Device identities</h3><span>{instanceDevices.length} for selected instance</span></div>
        {#if instanceDevices.length}
          <div class="rows">
            {#each instanceDevices as device}
              <article>
                <div class:disabled={!device.enabled} class="status-icon">{device.enabled ? "●" : "○"}</div>
                <div class="row-main"><strong>{device.display_name}</strong><small>{device.ipv4_address}</small></div>
                <button class="secondary" onclick={() => toggleDevice(device)}>{device.enabled ? "Disable" : "Enable"}</button>
                <button class="secondary" onclick={() => replaceDeviceIdentity(device)}>Replace key</button>
                <button class="secondary" onclick={() => showQr(device)}>QR</button>
                <button class="primary small" onclick={() => exportDevice(device)}>Export</button>
                <button class="menu danger" onclick={() => removeDevice(device)}>Remove</button>
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No devices for this instance</h3><p>Private keys are generated locally and remain in the macOS Keychain.</p></div>
        {/if}
      </section>
    {:else if active === "DNS"}
      <div class="toolbar">
        <label>Instance<select bind:value={selectedInstanceId} onchange={refreshInstanceData}><option value="">Select…</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
        {#if selectedInstance}<span>SOA {selectedInstance.dns.soa_serial}</span>{/if}
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Private DNS records</h3><span>A · AAAA · CNAME · TXT · SRV</span></div>
        {#if instanceRecords.length}
          <div class="table">
            <div class="table-head"><span>Name</span><span>Type</span><span>Value</span><span>TTL</span><span></span></div>
            {#each instanceRecords as record}
              <div><span>{record.name}</span><span><b class="type">{record.record_type}</b></span><span>{record.value}</span><span>{record.ttl}</span><span><button class="menu danger" onclick={() => removeDns(record)}>Delete</button></span></div>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No custom records</h3><p>The gateway record is generated automatically. Other queries use DNS-over-TLS.</p></div>
        {/if}
      </section>
    {:else if active === "Backups"}
      <div class="toolbar">
        <label>Instance<select bind:value={selectedInstanceId} onchange={refreshInstanceData}><option value="">Select…</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Deployment backups</h3><span>10 retained per instance</span></div>
        {#if backups.length}
          <div class="rows">
            {#each backups as backup}
              <article>
                <div class="status-icon">↶</div>
                <div class="row-main"><strong>{backup.name}</strong><small>{new Date(backup.created_at).toLocaleString()}</small></div>
                {#if backup.deployment_id}<button class="secondary" onclick={() => rollbackBackup(backup)}>Rollback snapshot</button>{/if}
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No backups yet</h3><p>A timestamped backup is created before every mutating deployment.</p></div>
        {/if}
      </section>
    {:else}
      <section class="panel">
        <div class="panel-head"><h3>Operational history</h3><span>Secrets redacted · {logs.length} events</span></div>
        {#if logs.length}
          <div class="timeline">
            {#each logs as event}
              <article><span></span><div><strong>{event.phase}</strong><p>{event.message}</p><small>{new Date(event.timestamp).toLocaleString()} · {event.deployment_id}</small>{#if event.technical_detail}<details><summary>Technical</summary><pre>{event.technical_detail}</pre></details>{/if}</div></article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No deployment events</h3><p>Progress, health checks, failures, and rollback outcomes will appear here.</p></div>
        {/if}
      </section>
    {/if}

    <footer>{appInfo.name} {appInfo.version} · Local-first management over verified SSH</footer>
  </main>
</div>

{#if modal}
  <div class="modal-backdrop" role="presentation" onclick={(event) => { if (event.target === event.currentTarget) modal = null; }}>
    <section class="modal" role="dialog" aria-modal="true">
      {#if modal === "host"}
        <div class="modal-head"><div><p class="eyebrow">FIRST RUN</p><h2>Add SSH host</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveHost(); }}>
          <label>Display name<input bind:value={hostForm.display_name} required placeholder="Debian lab" /></label>
          <div class="form-grid"><label>Hostname or IP<input bind:value={hostForm.hostname} required placeholder="192.168.86.55" /></label><label>SSH port<input type="number" bind:value={hostForm.port} min="1" max="65535" required /></label></div>
          <label>SSH username<input bind:value={hostForm.username} required placeholder={defaultSshUsername || "username"} /></label>
          <label>SSH private key<div class="path-input"><input bind:value={hostForm.private_key_path} required placeholder="/Users/you/.ssh/id_ed25519 or key.ppk" /><button type="button" class="secondary" onclick={chooseKey}>Choose</button></div></label>
          <label>Key passphrase <span class="optional">optional · saved to Keychain</span><input type="password" bind:value={hostForm.passphrase} autocomplete="new-password" /></label>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" disabled={Boolean(busy)}>Save host</button></div>
        </form>
      {:else if modal === "trust" && probe}
        <div class="modal-head"><div><p class="eyebrow">SSH TRUST</p><h2>{probe.state === "changed" ? "Host key changed" : "Verify host key"}</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <div class:critical={probe.state === "changed"} class="fingerprint-card">
          <span>{probe.key.algorithm} · {probe.key.resolved_address}:{probe.key.port}</span>
          <code>{probe.key.sha256_fingerprint}</code>
          {#if probe.approved_fingerprint}<small>Previously approved: {probe.approved_fingerprint}</small>{/if}
        </div>
        <p class="help">Verify this SHA-256 fingerprint through a trusted channel, then enter it exactly. No authentication occurs during the probe.</p>
        <div class="command-card">
          <span>On the remote server, run:</span>
          <pre>{remoteHostKeyCommand(probe.key.sha256_fingerprint)}</pre>
          <small>Compare the {probe.key.algorithm} line to the fingerprint above.</small>
        </div>
        <label>Fingerprint confirmation<input bind:value={fingerprintConfirmation} spellcheck="false" placeholder="SHA256:…" /></label>
        {#if probe.state === "changed"}<label class="checkbox critical-text"><input type="checkbox" bind:checked={replaceChangedKey} /> I separately verified and intend to replace the approved key.</label>{/if}
        <div class="modal-actions"><button class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" onclick={approveKey} disabled={fingerprintConfirmation !== probe.key.sha256_fingerprint || (probe.state === "changed" && !replaceChangedKey)}>Approve key</button></div>
      {:else if modal === "instance"}
        <div class="modal-head"><div><p class="eyebrow">DESIRED STATE</p><h2>Create WireGuard instance</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveInstance(); }}>
          <label>Display name<input bind:value={instanceForm.display_name} required placeholder="Home VPN" /></label>
          <label>Docker host<select bind:value={instanceForm.host_id} required>{#each hosts as host}<option value={host.id}>{host.display_name}</option>{/each}</select></label>
          <div class="form-grid"><label>Public endpoint<input bind:value={instanceForm.endpoint_host} required placeholder="vpn.example.com" /></label><label>UDP port<input type="number" bind:value={instanceForm.endpoint_port} min="1" max="65535" /></label></div>
          <div class="form-grid"><label>Private IPv4 subnet<input bind:value={instanceForm.ipv4_subnet} required /></label><label>Private DNS zone<input bind:value={instanceForm.dns_zone} required /></label></div>
          <label>Default routing<select bind:value={instanceForm.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel (IPv4)</option></select></label>
          <p class="help">The gateway receives the first usable address. IPv6 is not advertised until an IPv6 tunnel address exists.</p>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">Create instance</button></div>
        </form>
      {:else if modal === "device"}
        <div class="modal-head"><div><p class="eyebrow">LOCAL KEY GENERATION</p><h2>Add device</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveDevice(); }}>
          <label>Instance<select bind:value={deviceForm.instance_id} required>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
          <label>Device name<input bind:value={deviceForm.display_name} required placeholder="William’s MacBook" /></label>
          <label>DNS name <span class="optional">optional</span><input bind:value={deviceForm.dns_name} placeholder="macbook" /></label>
          <label class="checkbox"><input type="checkbox" bind:checked={deviceForm.preshared_key} /> Generate a preshared key (recommended)</label>
          <label class="checkbox"><input type="checkbox" bind:checked={deviceForm.create_dns_record} /> Create a managed DNS A record</label>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">Generate identity</button></div>
        </form>
      {:else if modal === "dns"}
        <div class="modal-head"><div><p class="eyebrow">PRIVATE ZONE</p><h2>Add DNS record</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveDns(); }}>
          <label>Instance<select bind:value={dnsForm.instance_id} required>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
          <div class="form-grid"><label>Owner name<input bind:value={dnsForm.name} required placeholder="service" /></label><label>Record type<select bind:value={dnsForm.record_type}>{#each recordTypes as type}<option value={type}>{type}</option>{/each}</select></label></div>
          <label>Value<input bind:value={dnsForm.value} required placeholder={dnsForm.record_type === "A" ? "10.64.0.10" : "Record value"} /></label>
          <label>TTL<input type="number" bind:value={dnsForm.ttl} min="30" max="86400" required /></label>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">Validate and save</button></div>
        </form>
      {:else if modal === "plan" && plan}
        <div class="modal-head"><div><p class="eyebrow">DEPLOYMENT PREVIEW</p><h2>Preview remote changes</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <p class="help">This preview shows what Apply will change on the verified SSH host. Nothing is changed until you apply it.</p>
        {#if plan.operations.length}
          <ol class="operations">{#each plan.operations as operation}<li><code>{JSON.stringify(operation)}</code></li>{/each}</ol>
        {:else}<div class="empty small-empty"><h3>No changes</h3><p>Remote hashes match desired state.</p></div>{/if}
        {#each plan.warnings as warning}<div class="warning">{warning}</div>{/each}
        <div class="hash">Desired state <code>{plan.desired_state_hash}</code></div>
        <div class="modal-actions"><button class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" onclick={applyPlan} disabled={!plan.operations.length}>Apply these changes</button></div>
      {:else if modal === "qr"}
        <div class="modal-head"><div><p class="eyebrow">PRIVATE CONFIGURATION</p><h2>WireGuard QR code</h2></div><button onclick={() => { modal = null; qrSvg = ""; }}>×</button></div>
        <div class="qr">{@html qrSvg}</div>
        <p class="help centered">This SVG exists only in the current desktop view. Close it when the device has imported the configuration.</p>
      {/if}
    </section>
  </div>
{/if}
