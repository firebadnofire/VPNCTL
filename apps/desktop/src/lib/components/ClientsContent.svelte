<script lang="ts">
  import type { BackendOption, Device } from "../types";
  import EmptyState from "./EmptyState.svelte";

  let {
    clients,
    backendOptions,
    ontoggle,
    onreplace,
    onqr,
    onexport,
    onremove,
  }: {
    clients: Device[];
    backendOptions: BackendOption[];
    ontoggle: (client: Device) => void;
    onreplace: (client: Device) => void;
    onqr: (client: Device) => void;
    onexport: (client: Device) => void;
    onremove: (client: Device) => void;
  } = $props();

  function capabilities(client: Device) {
    return backendOptions.find((option) => option.kind === client.backend)?.capabilities;
  }

  function identity(client: Device) {
    switch (client.public_identity.backend) {
      case "wireguard":
      case "amnezia_wg": return `${client.public_identity.identity.public_key.slice(0, 12)}…`;
      case "openvpn": return client.public_identity.identity.common_name;
      case "ikev2": return client.public_identity.identity.identity;
      case "xray": return client.public_identity.identity.email;
    }
  }
</script>

{#if clients.length}
  <div class="rows">
    {#each clients as client}
      <article>
        <div class:disabled={!client.enabled} class="status-icon">{client.enabled ? "●" : "○"}</div>
        <div class="row-main"><strong>{client.display_name}</strong><small>{client.ipv4_address ? `${client.ipv4_address} · ` : ""}{identity(client)}</small></div>
        {#if capabilities(client)?.certificate_authority && !client.enabled}
          <span class="revoked">Revoked</span>
        {:else}<button class="secondary" type="button" onclick={() => ontoggle(client)}>{capabilities(client)?.certificate_authority ? "Revoke" : client.enabled ? "Disable" : "Enable"}</button>{/if}
        <button class="secondary" type="button" onclick={() => onreplace(client)}>Replace identity</button>
        {#if capabilities(client)?.qr_export}<button class="secondary" type="button" onclick={() => onqr(client)}>QR</button>{/if}
        <button class="primary small" type="button" onclick={() => onexport(client)}>Export</button>
        <button class="menu danger" type="button" onclick={() => onremove(client)}>Remove</button>
      </article>
    {/each}
  </div>
{:else}<EmptyState title="No clients for this instance" description="Client identities are generated in Rust; private material remains in the native credential store." />{/if}
