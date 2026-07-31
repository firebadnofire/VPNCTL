<script lang="ts">
  import type { InstanceOperationalState } from "../types";

  let { state }: { state: InstanceOperationalState } = $props();
  const labels: Record<InstanceOperationalState, string> = {
    healthy: "Healthy",
    degraded: "Degraded",
    stopped: "Stopped",
    unknown: "Unknown",
    needs_deployment: "Needs deployment",
    updating: "Updating",
    error: "Error",
  };
</script>

<span class="state-badge" data-state={state}>{labels[state]}</span>
