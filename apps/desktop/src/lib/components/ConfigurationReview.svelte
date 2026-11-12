<script lang="ts">
  import type { Configuration } from "../remote-types";
  import { configurationDifferences } from "../configuration-presentation";
  export let local: Configuration;
  export let server: Configuration;
  export let base: Configuration | undefined = undefined;
  $: differences = configurationDifferences(local, server, base);
</script>
<p>Review your edits and the latest saved server configuration. Reload discards local edits; reapply any changes you want to keep afterward. Nothing is saved or deployed by this review.</p>
{#if !base}<p class="notice">The original configuration is unavailable. Showing local and server values only.</p>{/if}
<div class="table-wrap"><table><thead><tr><th>Setting</th>{#if base}<th>Original</th>{/if}<th>Your draft</th><th>Server</th></tr></thead><tbody>
{#each differences as difference}<tr><th>{difference.section}<small>{difference.field}</small></th>{#if base}<td>{difference.base}</td>{/if}<td>{difference.local}</td><td>{difference.server}</td></tr>{:else}<tr><td colspan={base ? 4 : 3}>No configuration differences.</td></tr>{/each}
</tbody></table></div>
