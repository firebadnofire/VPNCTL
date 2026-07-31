<script lang="ts">
  import type {
    BackendOption,
    BackupView,
    Client,
    ClientActionView,
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
  let backend = $derived(options.find((option) => option.kind === summary.instance.backend));
  let instanceLogs = $derived(logs.filter((event) => event.instance_id === summary.instance.id));
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
        aria-selected={tab === item}
        class:active={tab === item}
        onclick={() => ontabchange(item)}>{item}</button
      >
    {/each}
  </div>

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
    <div class="panel">
      <div class="panel-head"><h3>Configuration sections</h3><span>Host and backend are immutable here</span></div>
      <div class="settings-sections">
        {#each backend?.presentation.configuration_sections ?? [] as section}<button class="secondary" type="button">{section[0].toUpperCase() + section.slice(1)}</button>{/each}
      </div>
      <p class="help">Settings are saved to local desired state after a typed impact preview. Deployment remains a separate reviewed action.</p>
      <div class="panel-actions"><button class="primary" type="button" onclick={oneditsettings}>Edit desired settings</button></div>
    </div>
  {:else if tab === "Backups"}
    <div class="workspace-toolbar"><div><h2>Backups</h2><p>Remote snapshots for this instance.</p></div><button class="primary" type="button" onclick={onbackup}>Create backup</button></div>
    <div class="panel"><BackupsContent {backups} onrestore={onrestore} /></div>
  {:else}
    <div class="panel"><div class="panel-head"><h3>Instance activity</h3><span>{instanceLogs.length} events</span></div><LogsContent events={instanceLogs} /></div>
  {/if}
</section>
