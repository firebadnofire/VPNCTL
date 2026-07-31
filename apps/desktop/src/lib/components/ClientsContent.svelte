<script lang="ts">
  import type { Client, ClientActionView } from "../types";
  import ClientActionGroup from "./ClientActionGroup.svelte";
  import EmptyState from "./EmptyState.svelte";

  let {
    clients,
    onaction,
  }: {
    clients: Client[];
    onaction: (client: Client, action: ClientActionView) => void;
  } = $props();
</script>

{#if clients.length}
  <div class="rows">
    {#each clients as client}
      <article>
        <div class:disabled={!client.enabled} class="status-icon">{client.enabled ? "●" : "○"}</div>
        <div class="row-main"><strong>{client.display_name}</strong><small>{client.ipv4_address ? `${client.ipv4_address} · ` : ""}{client.identity_summary}</small></div>
        <span class:revoked={client.state_label === "Revoked"} class="client-state">{client.state_label}</span>
        <ClientActionGroup {client} {onaction} />
      </article>
    {/each}
  </div>
{:else}<EmptyState title="No clients for this instance" description="Client identities are generated in Rust; private material remains in the native credential store." />{/if}
