<script lang="ts">
  import { fly } from "svelte/transition";
  import { onMount } from "svelte";
  import type { Notifications } from "../notifications";
  export let notifications: Notifications;
  const { visible } = notifications;
  let reducedMotion = true;
  onMount(() => {
    const media = matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => reducedMotion = media.matches;
    update(); media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  });
</script>
<div class="toast-region" aria-label="Notifications" aria-live="polite" aria-relevant="additions">
  {#each $visible as item (item.id)}
    <section class="toast" data-kind={item.kind} aria-label={item.kind}
      onmouseenter={() => notifications.pause(item.id, "hover")} onmouseleave={() => notifications.resume(item.id, "hover")}
      onfocusin={() => notifications.pause(item.id, "focus")} onfocusout={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) notifications.resume(item.id, "focus"); }}
      transition:fly={{ y: 8, duration: reducedMotion ? 0 : 140 }}>
      <span>{item.message}</span><button type="button" aria-label="Dismiss notification" onclick={() => notifications.dismiss(item.id)}>×</button>
    </section>
  {/each}
</div>
