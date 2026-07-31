<script lang="ts">
  import { backendForms } from "../lib/components/forms/backend-forms";
  import { newInstanceForm } from "../lib/instance-form";
  import type { VpnBackendKind } from "../lib/types";

  let { kind }: { kind: VpnBackendKind } = $props();
  let form = $state(newInstanceForm("host-1", "vpn.example.com"));
  let BackendForm = $derived(backendForms[kind]);
</script>

<BackendForm bind:form />
