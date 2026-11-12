<script lang="ts">
  import ModalShell from "../lib/components/ModalShell.svelte";
  import Tooltip from "../lib/components/Tooltip.svelte";
  let open = false;
</script>
<button onclick={() => open = true}>Open dialog</button>
<Tooltip text="Saved on the remote server." label="About saving" />
{#if open}<ModalShell title="Test dialog" onclose={() => open = false}><button>Inside dialog</button></ModalShell>{/if}
