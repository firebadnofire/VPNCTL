<script lang="ts">
  import { onMount, type Snippet } from "svelte";
  let { title, eyebrow = "", onclose, children, returnFocus }: { title: string; eyebrow?: string; onclose: () => void; children: Snippet; returnFocus?: HTMLElement | null } = $props();
  const id = $props.id();
  let dialog: HTMLDialogElement;
  onMount(() => {
    const previous = returnFocus ?? document.activeElement as HTMLElement | null;
    // Native dialogs provide focus containment and make the surrounding UI inert.
    dialog.showModal();
    return () => { dialog.close(); previous?.focus(); };
  });
</script>
<dialog bind:this={dialog} class="modal" aria-labelledby={id} oncancel={(event) => { event.preventDefault(); onclose(); }}>
  <div class="modal-head">
    <div>{#if eyebrow}<p class="eyebrow">{eyebrow}</p>{/if}<h2 id={id}>{title}</h2></div>
    <button type="button" aria-label={`Close ${title}`} onclick={onclose}>×</button>
  </div>
  {@render children()}
</dialog>
