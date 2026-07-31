<script lang="ts">
  import type { Snippet } from "svelte";

  let {
    title,
    eyebrow,
    onclose,
    children,
  }: { title: string; eyebrow: string; onclose: () => void; children: Snippet } = $props();
</script>

<div class="modal-head">
  <div><p class="eyebrow">{eyebrow}</p><h2>{title}</h2></div>
  <button type="button" aria-label={`Close ${title}`} onclick={onclose}>×</button>
</div>
{@render children()}
