<script lang="ts">
  import type { ActivityFilter, DockerHost, VpnBackendKind, VpnInstance } from "../types";
  let { value, hosts, instances, onchange }: { value: ActivityFilter; hosts: DockerHost[]; instances: VpnInstance[]; onchange: (value: ActivityFilter) => void } = $props();
  const backends: VpnBackendKind[] = ["wireguard", "amnezia_wg", "openvpn", "ikev2", "xray"];
  function update(field: keyof ActivityFilter, next: string) { onchange({ ...value, [field]: next || null }); }
</script>
<div class="log-filters">
  <label>Host<select value={value.host_id ?? ""} onchange={(event) => update("host_id", event.currentTarget.value)}><option value="">All hosts</option>{#each hosts as host}<option value={host.id}>{host.display_name}</option>{/each}</select></label>
  <label>Instance<select value={value.instance_id ?? ""} onchange={(event) => update("instance_id", event.currentTarget.value)}><option value="">All instances</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
  <label>Backend<select value={value.backend ?? ""} onchange={(event) => update("backend", event.currentTarget.value)}><option value="">All backends</option>{#each backends as backend}<option value={backend}>{backend}</option>{/each}</select></label>
  <label>Severity<select value={value.severity ?? ""} onchange={(event) => update("severity", event.currentTarget.value)}><option value="">All severities</option><option value="info">Info</option><option value="warning">Warning</option><option value="error">Error</option></select></label>
  <label>Operation<input value={value.operation ?? ""} onchange={(event) => update("operation", event.currentTarget.value)} placeholder="e.g. client_created" /></label>
</div>
