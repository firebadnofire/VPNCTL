<script lang="ts">
  import type { VpnInstance } from "../types";

  let {
    instances,
    value,
    onchange,
    label = "Instance",
  }: {
    instances: VpnInstance[];
    value: string;
    onchange: (value: string) => void;
    label?: string;
  } = $props();
</script>

<label class="instance-selector">
  {label}
  <select value={value} onchange={(event) => onchange(event.currentTarget.value)}>
    <option value="">Select…</option>
    {#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}
  </select>
</label>
