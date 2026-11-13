<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { confirm } from "@tauri-apps/plugin-dialog";
  import { call } from "../api";
  import { formFeedback } from "../form-feedback";
  import type { BlockingAction, BlockingPolicy, BlockingView } from "../remote-types";
  export let hostId: string;
  export let instanceId: string;
  export let online: boolean;
  export let supported: boolean;
  export let busy: string;
  export let run: (label: string, action: () => Promise<BlockingView>) => Promise<BlockingView | undefined>;
  export let dirtyChanged: (dirty: boolean) => void = () => {};
  export let notify: (message: string, kind?: "success" | "info" | "warning") => void;
  let current: BlockingView | null = null;
  let policy: BlockingPolicy = { revision: 0, enabled: false, schedule_enabled: true, interval_days: 7, sources: [] };
  let pending: { requestId: string; action: BlockingAction } | null = null;
  let loading = false;
  let alive = true;
  let mounted = false;
  let attempted = false;
  $: dirty = Boolean(current && JSON.stringify(policy) !== JSON.stringify(current.state.policy));
  $: dirtyChanged(dirty);
  $: httpSources = policy.sources.some(source => source.enabled && source.url.trim().startsWith("http://"));
  const date = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : "Never";
  onDestroy(() => { alive = false; dirtyChanged(false); });
  onMount(() => { mounted = true; });
  $: if (mounted && online && supported && !busy && !current && !loading && !attempted) { attempted = true; void load(); }
  async function load() {
    if (loading || busy || !online || !supported) return;
    if (dirty && !await confirm("Discard unsaved blocking settings and reload the server policy?", { title: "Reload blocking settings", kind: "warning" })) return;
    loading = true;
    const result = await run("Reading DNS blocking", () => call<BlockingView>("remote_blocking", { hostId, instanceId, requestId: crypto.randomUUID(), action: { action: "read" } }));
    if (alive && result) { current = result; policy = structuredClone(result.state.policy); pending = result.state.pending_request ? { requestId: result.state.pending_request, action: { action: "resume" } } : null; }
    if (alive) loading = false;
  }
  async function execute(action?: BlockingAction) {
    if (!current || loading || busy || !online) return;
    const target = pending ?? { requestId: crypto.randomUUID(), action: action! };
    pending = target; loading = true;
    const result = await run("Updating DNS blocking", () => call<BlockingView>("remote_blocking", { hostId, instanceId, ...target }));
    if (alive && result) {
      current = result; policy = structuredClone(result.state.policy);
      pending = result.state.pending_request ? { requestId: result.state.pending_request, action: { action: "resume" } } : null;
      notify(result.state.error ? "Blocking update needs attention. Review its status." : "DNS blocking rules updated independently of VPN deployment.", result.state.error ? "warning" : "success");
    }
    if (alive) loading = false;
  }
  function addSource() {
    policy = { ...policy, enabled: policy.sources.length === 0 ? true : policy.enabled, sources: [...policy.sources, { id: crypto.randomUUID(), name: "", url: "", enabled: true }] };
  }
  async function removeSource(id: string) {
    const source = policy.sources.find(item => item.id === id);
    if (source && await confirm(`Remove blocking source ${source.name || "Untitled source"}? Save blocking settings to apply removal.`, { title: "Remove blocking source", kind: "warning" })) policy = { ...policy, sources: policy.sources.filter(item => item.id !== id) };
  }
</script>
<section class="blocking-panel" aria-label="DNS blocking">
  <header class="section-toolbar"><div><h3>Blocking</h3><p>Lists belong to this instance and are shared across VPNCTL installations. Blocking updates do not deploy pending VPN changes.</p></div></header>
  {#if !supported}<p>Update this server’s VPNCTL helper to enable per-instance DNS blocking.</p>
  {:else if !online}<p>Reconnect to read and manage blocking. Saved server schedules continue while VPNCTL is closed.</p>
  {:else}
    <button class="secondary" type="button" disabled={loading || Boolean(busy)} onclick={load}>Reload blocking settings</button>
    {#if current}
      {#if current.state.error}<div class="alert" role="status">{current.state.error}</div>{/if}
      {#if pending}<p role="status">An update outcome is pending. Retry the same operation or reload server status before making another change.</p><button class="secondary" type="button" disabled={loading || Boolean(busy)} onclick={() => execute()}>Retry blocking update</button>{/if}
      <form use:formFeedback class="remote-form" onsubmit={(event) => { event.preventDefault(); void execute({ action: "save", expected_revision: current!.state.policy.revision, policy }); }}>
        <fieldset disabled={loading || Boolean(busy) || Boolean(pending)}>
          <label class="checkbox"><input type="checkbox" bind:checked={policy.enabled} /> Enable DNS blocking</label>
          <p>Turning blocking off preserves sources and downloaded data. Existing manually saved blocked domains are preserved and included when blocking is enabled.</p>
          {#if httpSources}<p class="notice">HTTP sources are not authenticated or encrypted in transit. Prefer HTTPS when available.</p>{/if}
          <div class="table-wrap"><table><thead><tr><th>Enabled</th><th>Source</th><th>Refresh status</th><th>Action</th></tr></thead><tbody>
            {#each policy.sources as source, index (source.id)}
              {@const status = current.state.sources.find(item => item.id === source.id && item.url === source.url)}
              <tr><td><input type="checkbox" aria-label={`Enable source ${index + 1}`} bind:checked={source.enabled} /></td><td><label>Name<input required maxlength="128" aria-label={`Source ${index + 1} name`} bind:value={source.name} /></label><label>HTTP/HTTPS URL<input required type="url" pattern="https?://.*" maxlength="2048" aria-label={`Source ${index + 1} URL`} placeholder="https://example.com/hosts" bind:value={source.url} /></label></td>
              <td><p>{status?.domain_count ?? 0} domains{status?.stale ? " · Stale data" : ""}</p><p>Last attempt: {date(status?.last_attempt)}</p><p>Last success: {date(status?.last_success)}</p>{#if status?.error}<p class="danger">{status.error}</p>{/if}</td>
              <td><button class="secondary" type="button" onclick={() => removeSource(source.id)}>Remove source</button></td></tr>
            {:else}<tr><td colspan="4">No blocking sources configured. Add a hosts-file or domain-list URL to start.</td></tr>{/each}
          </tbody></table></div>
          <button class="secondary" type="button" disabled={policy.sources.length >= 64} onclick={addSource}>Add blocking source</button>
          <label class="checkbox"><input type="checkbox" bind:checked={policy.schedule_enabled} /> Refresh automatically</label>
          <label>Refresh interval (days)<input type="number" min="1" max="365" step="1" required disabled={!policy.schedule_enabled} bind:value={policy.interval_days} /></label>
          <p>{policy.schedule_enabled ? "The server checks due refreshes hourly, even when VPNCTL is closed." : "Scheduling is disabled. Use Refresh now for manual updates."}</p>
          {#if !current.scheduler_available}<p class="notice">Automatic scheduling requires systemd on this host. Settings can be saved; use manual refresh on this host.</p>{/if}
          <p>{dirty ? "Unsaved blocking settings" : "Blocking settings match the server"}. Saving downloads enabled sources and applies only DNS blocking rules.</p>
          <button class="primary" disabled={!dirty}>Save blocking settings</button>
        </fieldset>
      </form>
      <button class="secondary" type="button" disabled={loading || Boolean(busy) || dirty || Boolean(pending) || !current.state.policy.enabled} onclick={() => execute({ action: "refresh", expected_revision: current!.state.policy.revision })}>Refresh now</button>
      {#if dirty}<p>Save or reload blocking settings before refreshing.</p>{:else if !current.state.policy.enabled}<p>Enable and save blocking settings before refreshing sources.</p>{/if}
      <dl class="blocking-status"><dt>Last complete refresh</dt><dd>{date(current.state.last_success)}</dd><dt>Last applied</dt><dd>{date(current.state.applied_at)}</dd><dt>Applied dataset</dt><dd>{current.state.applied_version?.slice(0, 12) ?? "Not applied"}</dd></dl>
      <p>Source limit: 64 sources, 20 MiB each. Combined limit: one million unique domains and 64 MiB of domain names. Hosts and plain domain lists are supported.</p>
    {/if}
    {#if loading}<p role="status">Updating blocking status… Downloads and DNS verification may take a moment.</p>{/if}
  {/if}
</section>
