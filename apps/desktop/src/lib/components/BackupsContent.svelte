<script lang="ts">
  import type { BackupInfo } from "../types";
  import EmptyState from "./EmptyState.svelte";
  let { backups, onrestore }: { backups: BackupInfo[]; onrestore: (backup: BackupInfo) => void } = $props();
</script>
{#if backups.length}<div class="rows">{#each backups as backup}<article><div class="status-icon">↶</div><div class="row-main"><strong>{backup.name}</strong><small>{new Date(backup.created_at).toLocaleString()}</small></div>{#if backup.deployment_id}<button class="secondary" type="button" onclick={() => onrestore(backup)}>Review restore</button>{/if}</article>{/each}</div>{:else}<EmptyState title="No backups yet" description="Backups load only when this screen opens; mutating deployments create a protected snapshot." />{/if}
