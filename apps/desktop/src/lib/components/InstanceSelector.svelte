<script lang="ts">
  import type { VpnInstance } from "../types";

  let {
    instances,
    value,
    onchange,
    label = "Instance",
    id = "instance-selector",
  }: {
    instances: VpnInstance[];
    value: string;
    onchange: (value: string) => void;
    label?: string;
    id?: string;
  } = $props();
</script>

<label class="instance-selector" for={id}>
  {label}
  <select {id} value={value} onchange={(event) => onchange(event.currentTarget.value)}>
    <option value="">Select…</option>
    {#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}
  </select>
</label>
