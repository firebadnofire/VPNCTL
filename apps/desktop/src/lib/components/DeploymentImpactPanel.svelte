<script lang="ts">
  import type { DeploymentPreview } from "../types";
  let { preview }: { preview: DeploymentPreview } = $props();
  let disruptive = $derived(preview.impact === "reinstall" || preview.impact === "rebuild" || preview.impact === "service_restart");
</script>
<div class:critical={preview.impact === "reinstall"} class="impact-panel">
  <div class="impact-title"><span>Expected impact</span><strong>{preview.impact.replaceAll("_", " ")}</strong></div>
  <div class="impact-facts"><div><span>Backup</span><strong>{preview.creates_backup ? "Created before change" : "No backup operation"}</strong></div><div><span>Affected clients</span><strong>{preview.affected_clients}</strong></div></div>
  <p>{preview.server_identity_effect}</p><p>{preview.client_effect}</p>
  {#if disruptive}<strong class="impact-warning">Review this disruptive change before applying it.</strong>{/if}
</div>
