<script lang="ts">
  import type { AppError } from "../types";

  let { error, operation = "", context = "", ondismiss, ondeployment }: {
    error: AppError;
    operation?: string;
    context?: string;
    ondismiss?: () => void;
    ondeployment?: () => void;
  } = $props();

  // Older helpers return the backup requirement as a generic validation error.
  const backupRequirement = $derived(error.code === "backup_requires_deployment" || error.message === "Deploy the instance successfully before creating a restorable manual backup.");
  const remediation = $derived(backupRequirement
    ? "Open Deployment, preview the saved configuration, and deploy it successfully. Then create the runtime backup."
    : error.remediation === "Correct the highlighted values and try again." ? undefined : error.remediation);
  const message = $derived(error.message === "A fixed remote operation failed." ? "A command on the server failed." : error.message);
</script>

<div class="alert error-feedback" role="alert">
  <div class="error-body">
    {#if operation}<p class="error-context">{[operation, context].filter(Boolean).join(" · ")}</p>{/if}
    <strong>{message}</strong>
    {#if remediation}<p>{remediation}</p>{/if}
    {#if error.code === "revision_conflict"}<p>Your local draft is retained. Review the server’s changes before discarding and reloading.</p>{/if}
    {#if error.remote_state_changed}
      <p>{error.rollback_succeeded === true ? "Recovery restored the previous runtime state. Check its health before continuing." : "The server may have changed. Reconnect and review the operation’s status before retrying a change."}</p>
    {/if}
    {#if error.rollback_succeeded === false}<p>Automatic recovery did not complete. Review deployment history and recovery information before continuing.</p>{/if}
    {#if backupRequirement && ondeployment}<button class="secondary" onclick={ondeployment}>Open Deployment</button>{/if}
    <details class="error-details">
      <summary>Technical details</summary>
      <dl>
        <dt>Error code</dt><dd>{error.code || "unknown"}</dd>
        {#if operation}<dt>Action</dt><dd>{operation}</dd>{/if}
        {#if context}<dt>Context</dt><dd>{context}</dd>{/if}
        {#if error.scope}<dt>Stage</dt><dd>{error.scope}</dd>{/if}
      </dl>
      {#if error.technical_detail}<pre>{error.technical_detail}</pre>{:else}<p>No additional diagnostics were supplied.</p>{/if}
    </details>
  </div>
  {#if ondismiss}<button class="dismiss-error" aria-label="Dismiss error" onclick={ondismiss}>×</button>{/if}
</div>

<style>
  .error-feedback { align-items: flex-start; }
  .error-body { min-width: 0; flex: 1; overflow-wrap: anywhere; }
  .error-context { margin-top: 0; font-weight: 600; }
  .error-details { margin-top: 0.75rem; }
  summary { cursor: pointer; min-height: 2.75rem; display: list-item; align-content: center; }
  dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 0.35rem 1rem; }
  dd { margin: 0; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 20rem; overflow: auto; }
  .dismiss-error { min-width: 2.75rem; min-height: 2.75rem; }
</style>
