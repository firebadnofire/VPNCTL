<script lang="ts">import type { InstanceForm } from "../../instance-form"; let { form = $bindable() }: { form: InstanceForm } = $props();</script>
<label class="checkbox"><input type="checkbox" bind:checked={form.wireguard_userspace_fallback} /> Allow userspace fallback when the host kernel module is unavailable</label>
