<script lang="ts">import type { InstanceForm } from "../../instance-form"; export let form: InstanceForm;</script>
<label class="checkbox"><input type="checkbox" bind:checked={form.wireguard_userspace_fallback} /> Allow userspace fallback when the host kernel module is unavailable</label>
