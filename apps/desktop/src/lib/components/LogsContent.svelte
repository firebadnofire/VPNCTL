<script lang="ts">
  import type { LogEvent } from "../types";
  import EmptyState from "./EmptyState.svelte";
  let { events }: { events: LogEvent[] } = $props();
</script>
{#if events.length}<div class="timeline">{#each events as event}<article><span></span><div><strong>{event.title}</strong><p>{event.message}</p><small>{new Date(event.timestamp).toLocaleString()} · {event.severity}{event.deployment_id ? ` · ${event.deployment_id}` : ""}</small>{#if event.technical_detail}<details><summary>Technical</summary><pre>{event.technical_detail}</pre></details>{/if}</div></article>{/each}</div>{:else}<EmptyState title="No activity" description="Progress, health checks, failures, and rollback outcomes will appear here." />{/if}
