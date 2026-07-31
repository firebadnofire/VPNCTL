<script lang="ts">
  import { tick } from "svelte";
  import type {
    BackendOption,
    BackupView,
    Client,
    ClientActionView,
    ConfigurationSection,
    DnsHostlist,
    DnsRecord,
    InstanceSummary,
    LogEvent,
  } from "../types";
  import BackendBadge from "./BackendBadge.svelte";
  import BackupsContent from "./BackupsContent.svelte";
  import ClientsContent from "./ClientsContent.svelte";
  import EmptyState from "./EmptyState.svelte";
  import StateBadge from "./StateBadge.svelte";
  import LogsContent from "./LogsContent.svelte";

  export type WorkspaceTab = "Overview" | "Clients" | "DNS" | "Settings" | "Backups" | "Logs";

  let {
    summary,
    options,
    tab,
    devices,
    records,
    hostlists,
    backups,
    logs,
    onback,
    ontabchange,
    onhealth,
    onplan,
    onaddclient,
    onclientaction,
    onbackup,
    onrestore,
    oneditsettings,
  }: {
    summary: InstanceSummary;
    options: BackendOption[];
    tab: WorkspaceTab;
    devices: Client[];
    records: DnsRecord[];
    hostlists: DnsHostlist[];
    backups: BackupView[];
    logs: LogEvent[];
    onback: () => void;
    ontabchange: (tab: WorkspaceTab) => void;
    onhealth: () => void;
    onplan: () => void;
    onaddclient: () => void;
    onclientaction: (client: Client, action: ClientActionView) => void;
    onbackup: () => void;
    onrestore: (backup: BackupView) => void;
    oneditsettings: () => void;
  } = $props();

  const tabs: WorkspaceTab[] = ["Overview", "Clients", "DNS", "Settings", "Backups", "Logs"];
  const configurationSectionCopy: Record<ConfigurationSection, { label: string; description: string }> = {
    general: { label: "General", description: "Instance name and public endpoint." },
    network: { label: "Network", description: "Listener, private addressing, and routing policy." },
    protocol: { label: "Protocol", description: "Backend-specific transport and security controls." },
    dns: { label: "DNS", description: "Private zone and managed DNS behavior." },
    advanced: { label: "Advanced", description: "Specialized backend and compatibility options." },
  };
  let backend = $derived(options.find((option) => option.kind === summary.instance.backend));
  let instanceLogs = $derived(logs.filter((event) => event.instance_id === summary.instance.id));
  async function tabKeydown(event: KeyboardEvent, current: WorkspaceTab) {
    const index = tabs.indexOf(current);
    const next = event.key === "ArrowRight" ? tabs[(index + 1) % tabs.length] : event.key === "ArrowLeft" ? tabs[(index - 1 + tabs.length) % tabs.length] : event.key === "Home" ? tabs[0] : event.key === "End" ? tabs.at(-1)! : null;
    if (!next) return;
    event.preventDefault();
    ontabchange(next);
    await tick();
    document.getElementById(`instance-tab-${summary.instance.id}-${next}`)?.focus();
  }
</script>

<section class="workspace">
  <button class="text-button breadcrumb" type="button" onclick={onback}>← Instances</button>
  <div class="workspace-title">
    <div>
      <h1>{summary.instance.display_name}</h1>
      <div class="workspace-identity">
        <BackendBadge backend={summary.instance.backend} {options} />
        <StateBadge state={summary.state} />
      </div>
    </div>
    <div class="header-actions">
      <button class="secondary" type="button" onclick={onhealth}>Refresh health</button>
      <button class="primary" type="button" onclick={onplan}>Review deployment</button>
    </div>
  </div>
  <div class="tabs workspace-tabs" role="tablist" aria-label="Instance management">
    {#each tabs as item}
      <button
        type="button"
        role="tab"
        id={`instance-tab-${summary.instance.id}-${item}`}
        aria-controls={`instance-panel-${summary.instance.id}`}
        aria-selected={tab === item}
        tabindex={tab === item ? 0 : -1}
        class:active={tab === item}
        onkeydown={(event) => tabKeydown(event, item)}
        onclick={() => ontabchange(item)}>{item}</button
      >
    {/each}
  </div>

  <div role="tabpanel" id={`instance-panel-${summary.instance.id}`} aria-labelledby={`instance-tab-${summary.instance.id}-${tab}`} tabindex="0">
  {#if tab === "Overview"}
    <div class="stats">
      <article><span>Backend</span><strong>{backend?.display_name ?? summary.instance.backend}</strong><small>{backend?.presentation.description}</small></article>
      <article><span>Listener</span><strong>{summary.listener_summary}</strong><small>{summary.instance.endpoint.host}</small></article>
      <article><span>Clients</span><strong>{summary.client_count}</strong><small>Configured desired state</small></article>
    </div>
    <div class="panel workspace-facts">
      <div><span>Routing</span><strong>{backend?.presentation.routing === "proxy" ? "Proxy" : summary.instance.routing_mode.replace("_", " ")}</strong></div>
      {#if backend?.presentation.client_addresses === "allocated"}<div><span>Network</span><strong>{summary.instance.network.ipv4_subnet}</strong></div>{/if}
      {#if backend?.presentation.dns === "managed_private_dns"}<div><span>Managed DNS</span><strong>{summary.instance.dns.zone}</strong></div>{/if}
      <div><span>Evidence</span><strong>{summary.state_evidence.replaceAll("_", " ")}</strong></div>
    </div>
  {:else if tab === "Clients"}
    <div class="workspace-toolbar"><div><h2>Clients</h2><p>Identity actions and exports for this instance.</p></div><button class="primary" type="button" onclick={onaddclient}>Add client</button></div>
    <div class="panel"><ClientsContent clients={devices} onaction={onclientaction} /></div>
  {:else if tab === "DNS"}
    {#if backend?.presentation.dns === "unsupported"}
      <EmptyState title="Managed private DNS is not supported" description={`${backend.display_name} does not allocate routed client addresses. Global hostlists remain available below.`} />
    {:else}
      <div class="panel"><div class="panel-head"><h3>Managed records</h3><span>{records.length}</span></div>{#each records as record}<div class="workspace-record"><strong>{record.name}</strong><span>{record.record_type}</span><code>{record.value}</code></div>{/each}</div>
    {/if}
    <div class="panel"><div class="panel-head"><h3>Global hostlists</h3><span>{hostlists.length}</span></div>{#if hostlists.length}{#each hostlists as hostlist}<div class="workspace-record"><strong>{hostlist.name}</strong><span>{hostlist.coverage || "Custom"}</span><code>{hostlist.url}</code></div>{/each}{:else}<p class="help">No global hostlists are configured.</p>{/if}</div>
  {:else if tab === "Settings"}
    <div class="panel settings-panel">
      <div class="settings-purpose">
        <div>
          <p class="eyebrow">DESIRED CONFIGURATION</p>
          <h2>Control how this instance should run</h2>
          <p>Review the local target configuration, preview the operational impact of changes, and save it for a separate deployment review.</p>
        </div>
        <button class="primary" type="button" onclick={oneditsettings}>Review and edit settings</button>
      </div>
      <div class="settings-current-facts" aria-label="Current desired configuration">
        <div><span>Public endpoint</span><strong>{summary.instance.endpoint.host}:{summary.instance.endpoint.port}</strong><small>{summary.listener_summary}</small></div>
        <div><span>Routing model</span><strong>{backend?.presentation.routing === "proxy" ? "Proxy" : summary.instance.routing_mode.replace("_", " ")}</strong><small>{backend?.presentation.client_addresses === "allocated" ? summary.instance.network.ipv4_subnet : "No managed client subnet"}</small></div>
        <div><span>Managed DNS</span><strong>{backend?.presentation.dns === "managed_private_dns" ? summary.instance.dns.zone : "Not provided"}</strong><small>{backend?.presentation.dns === "managed_private_dns" ? "Private zone is part of desired state" : "This backend does not publish a private zone"}</small></div>
        <div><span>Fixed assignment</span><strong>{backend?.display_name ?? summary.instance.backend}</strong><small>Backend and host cannot be changed from this screen</small></div>
      </div>
      <div class="settings-editable">
        <div class="settings-section-heading"><div><h3>What you can edit</h3><p>Only sections supported by this backend are shown.</p></div><span>{backend?.presentation.configuration_sections.length ?? 0} sections</span></div>
        <div class="settings-section-grid">
          {#each backend?.presentation.configuration_sections ?? [] as section}
            <article><strong>{configurationSectionCopy[section].label}</strong><span>{configurationSectionCopy[section].description}</span></article>
          {/each}
        </div>
      </div>
      <div class="settings-workflow">
        <div><b>1</b><span><strong>Edit and preview</strong><small>Validation calculates restart, rebuild, or identity impact before save.</small></span></div>
        <div><b>2</b><span><strong>Save desired state</strong><small>This updates local configuration only; it does not contact the host.</small></span></div>
        <div><b>3</b><span><strong>Review deployment</strong><small>Apply the remote change later from the reviewed deployment plan.</small></span></div>
      </div>
    </div>
  {:else if tab === "Backups"}
    <div class="workspace-toolbar"><div><h2>Backups</h2><p>Remote snapshots for this instance.</p></div><button class="primary" type="button" onclick={onbackup}>Create backup</button></div>
    <div class="panel"><BackupsContent {backups} onrestore={onrestore} /></div>
  {:else}
    <div class="panel"><div class="panel-head"><h3>Instance activity</h3><span>{instanceLogs.length} events</span></div><LogsContent events={instanceLogs} /></div>
  {/if}
  </div>
</section>
