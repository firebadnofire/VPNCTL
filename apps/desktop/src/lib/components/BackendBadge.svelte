<script lang="ts">
  import type { BackendOption, VpnBackendKind } from "../types";

  let {
    backend,
    options,
    showName = true,
  }: { backend: VpnBackendKind; options: BackendOption[]; showName?: boolean } = $props();

  let descriptor = $derived(options.find((option) => option.kind === backend));
</script>

<span class="backend-badge" data-backend={backend}>
  <b>{descriptor?.presentation.badge ?? backend.toUpperCase()}</b>
  {#if showName}<span>{descriptor?.display_name ?? backend}</span>{/if}
</span>
