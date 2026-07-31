<script lang="ts">
  import type { Client, ClientActionView } from "../types";
  let { client, onaction }: { client: Client; onaction: (client: Client, action: ClientActionView) => void } = $props();
</script>
<div class="client-actions" aria-label={`Actions for ${client.display_name}`}>
  {#each client.actions as action}
    <button class:danger={action.destructive} class:primary={action.action === "export"} class:secondary={action.action !== "export" && !action.destructive} class="small" type="button" onclick={() => onaction(client, action)}>{action.label}</button>
  {/each}
</div>
