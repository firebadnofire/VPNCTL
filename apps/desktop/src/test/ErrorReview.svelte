<script lang="ts">
  import ErrorFeedback from "../lib/components/ErrorFeedback.svelte";
  import { formFeedback } from "../lib/form-feedback";
  import type { AppError } from "../lib/types";
  const scenarios: Record<string, AppError> = {
    Backup: { code: "validation", message: "Deploy the instance successfully before creating a restorable manual backup.", remediation: "Correct the highlighted values and try again.", remote_state_changed: false },
    Deployment: { code: "remote_command", message: "A command on the server failed.", scope: "compose_build", remediation: "Review the command output below and check the server requirements before retrying.", remote_state_changed: true, rollback_succeeded: false, technical_detail: "exit_status=1\nstderr:\nTest fixture: image build failed because the configured image could not be retrieved.\nNo production server was contacted." },
    Conflict: { code: "revision_conflict", message: "The server configuration changed while this draft was being edited.", remote_state_changed: false },
    Connection: { code: "ssh_transport", message: "The SSH connection was interrupted.", remediation: "Reconnect to the host and check the operation status before retrying a change.", remote_state_changed: true },
    Validation: { code: "validation", message: "The VPN network must be a valid IPv4 network.", remote_state_changed: false },
  };
  let scenario = $state("Backup");
  let visible = $state(true);
  let width = $state("800px");
  let destination = $state("");
</script>
<main style={`--review-width: ${width}`}>
  <h1>Error feedback review</h1>
  <p>Disposable UI fixtures. No native commands or server connections.</p>
  <label>Scenario<select bind:value={scenario} onchange={() => { visible = true; destination = ""; }}>{#each Object.keys(scenarios) as item}<option>{item}</option>{/each}</select></label>
  <label>Review width<select bind:value={width}><option value="1200px">Desktop</option><option value="800px">800 pixels</option><option value="360px">360 pixels</option></select></label>
  <div class="review">
    {#if visible}{#key scenario}<ErrorFeedback error={scenarios[scenario]} operation={scenario === "Backup" ? "Creating runtime backup" : scenario} context="Home VPN / Special" ondismiss={() => visible = false} ondeployment={() => destination = "Deployment opened. Preview and deploy remain explicit actions."} />{/key}{/if}
    {#if destination}<p role="status">{destination}</p>{/if}
    <form use:formFeedback onsubmit={(event) => event.preventDefault()}>
      <label>Device name (required)<input required name="device" /></label>
      <button class="primary">Validate form</button>
    </form>
  </div>
</main>
<style>
  main { padding: 24px; }
  .review { width: min(100%, var(--review-width)); margin-top: 24px; }
</style>
