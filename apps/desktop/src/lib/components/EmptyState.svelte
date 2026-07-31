<script lang="ts">
  let {
    title,
    description,
    actionLabel = "",
    onaction = () => {},
  }: {
    title: string;
    description: string;
    actionLabel?: string;
    onaction?: () => void;
  } = $props();
</script>

<div class="empty">
  <h3>{title}</h3>
  <p>{description}</p>
  {#if actionLabel}<button class="primary" type="button" onclick={onaction}>{actionLabel}</button>{/if}
</div>
