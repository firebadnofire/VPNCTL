<script lang="ts">
  import { onMount } from "svelte";
  import type { VpnInstance } from "../types";
  let { instance, onstart, onstop, onhealth, onplan, onbackup, ondelete }: { instance: VpnInstance; onstart: (instance: VpnInstance) => void; onstop: (instance: VpnInstance) => void; onhealth: (instance: VpnInstance) => void; onplan: (instance: VpnInstance) => void; onbackup: (instance: VpnInstance) => void; ondelete: (instance: VpnInstance) => void } = $props();
  let menu: HTMLDetailsElement;
  let trigger: HTMLElement;
  function close(restore = false) { menu.open = false; if (restore) trigger.focus(); }
  function keydown(event: KeyboardEvent) { if (event.key === "Escape" && menu.open) { event.preventDefault(); close(true); } }
  onMount(() => { const outside = (event: PointerEvent) => { if (menu.open && !menu.contains(event.target as Node)) close(); }; document.addEventListener("pointerdown", outside); return () => document.removeEventListener("pointerdown", outside); });
</script>
<details class="overflow-menu" bind:this={menu}><summary bind:this={trigger} aria-label={`More actions for ${instance.display_name}`} onkeydown={keydown}>More</summary><div role="menu" tabindex="-1" onkeydown={keydown}><button role="menuitem" type="button" onclick={() => { close(); onstart(instance); }}>Start</button><button role="menuitem" type="button" onclick={() => { close(); onstop(instance); }}>Stop</button><button role="menuitem" type="button" onclick={() => { close(); onhealth(instance); }}>Refresh health</button><button role="menuitem" type="button" onclick={() => { close(); onplan(instance); }}>Preview deployment</button><button role="menuitem" type="button" onclick={() => { close(); onbackup(instance); }}>Create backup</button><hr /><button role="menuitem" class="danger" type="button" onclick={() => { close(); ondelete(instance); }}>Delete instance</button></div></details>
