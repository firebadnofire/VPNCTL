<script lang="ts">
  let { text, label = "More information" }: { text: string; label?: string } = $props();
  const id = $props.id();
  let open = $state(false);
  let wrapper: HTMLSpanElement;
</script>
<svelte:window onpointerdown={(event) => { if (open && wrapper && !wrapper.contains(event.target as Node)) open = false; }} />
<span bind:this={wrapper} role="group" class="tooltip-wrap" onmouseleave={() => open = false}>
  <button class="help-trigger" type="button" aria-label={label} aria-describedby={id} aria-expanded={open}
    onmouseenter={() => open = true} onfocus={() => open = true} onblur={() => open = false}
    onclick={() => open = true} onkeydown={(event) => { if (event.key === "Escape") { open = false; event.stopPropagation(); } }}>?</button>
  <span id={id} role="tooltip" class="tooltip-content" hidden={!open}>{text}</span>
</span>
