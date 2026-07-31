<script lang="ts">
  import type { HostInspectionView } from "../types";
  let { view }: { view: HostInspectionView } = $props();
  const labels = { ready: "Ready", ready_with_fallback: "Ready with fallback", needs_setup: "Needs setup", unsupported: "Unsupported" };
</script>
<div class="readiness-summary"><div><span>SSH trust</span><strong>{view.ssh_trust}</strong></div><div><span>Connectivity</span><strong>{view.connectivity}</strong></div><div><span>Docker and Compose</span><strong>{view.docker_ready ? "Ready" : "Needs setup"}</strong></div></div>
<div class="readiness-matrix">{#each view.backend_readiness as backend}<article data-readiness={backend.status}><div><strong>{backend.display_name}</strong><span>{labels[backend.status]}</span></div>{#each backend.details as detail}<small>{detail}</small>{/each}</article>{/each}</div>
