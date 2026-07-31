<script lang="ts">
  import { open, save, confirm } from "@tauri-apps/plugin-dialog";
  import { onMount, tick } from "svelte";
  import { call, errorText } from "./lib/api";
  import BackendBadge from "./lib/components/BackendBadge.svelte";
  import BackupsContent from "./lib/components/BackupsContent.svelte";
  import ClientsContent from "./lib/components/ClientsContent.svelte";
  import DeploymentImpactPanel from "./lib/components/DeploymentImpactPanel.svelte";
  import EmptyState from "./lib/components/EmptyState.svelte";
  import InstanceSelector from "./lib/components/InstanceSelector.svelte";
  import InstanceActions from "./lib/components/InstanceActions.svelte";
  import InstanceWorkspace, { type WorkspaceTab } from "./lib/components/InstanceWorkspace.svelte";
  import ModalShell from "./lib/components/ModalShell.svelte";
  import LogsContent from "./lib/components/LogsContent.svelte";
  import HostReadinessMatrix from "./lib/components/HostReadinessMatrix.svelte";
  import LogFilters from "./lib/components/LogFilters.svelte";
  import StateBadge from "./lib/components/StateBadge.svelte";
  import { backendForms } from "./lib/components/forms/backend-forms";
  import { newInstanceForm, type InstanceForm } from "./lib/instance-form";
  import type {
    AppError,
    AppInfo,
    ActivityFilter,
    BackendOption,
    BackendSettings,
    BackupInfo,
    BackupRestorePreview,
    BackupView,
    Client,
    ClientActionView,
    DeploymentPreview,
    DeploymentResultView,
    DnsHostlist,
    DnsRecord,
    DnsRecordType,
    DockerHost,
    HostInspectionView,
    HostKeyProbe,
    HostProvisioningOperation,
    HostProvisioningPlan,
    InstanceHealthView,
    InstanceDetail,
    InstanceSummary,
    InstanceUpdatePreview,
    LogEvent,
    UpdateDeviceInput,
    VpnBackendKind,
    VpnInstance,
  } from "./lib/types";

  type Section = "Hosts" | "Instances" | "Clients" | "DNS" | "Backups" | "Logs";
  type DnsPanel = "Records" | "Hostlists";
  type Modal =
    | "host"
    | "trust"
    | "instance"
    | "device"
    | "dns"
    | "hostlist"
    | "host-setup"
    | "plan"
    | "restore"
    | "settings"
    | "qr"
    | null;

  const sections: Section[] = ["Hosts", "Instances", "Clients", "DNS", "Backups", "Logs"];
  const dnsPanels: DnsPanel[] = ["Records", "Hostlists"];
  const recordTypes: DnsRecordType[] = ["A", "AAAA", "CNAME", "TXT", "SRV"];

  function shellSingleQuote(value: string) {
    return `'${value.replaceAll("'", "'\"'\"'")}'`;
  }

  function remoteHostKeyCommand(fingerprint: string) {
    return `for key in /etc/ssh/ssh_host_*_key.pub; do test -r "$key" && ssh-keygen -l -E sha256 -f "$key"; done | grep -F ${shellSingleQuote(fingerprint)}`;
  }

  let active: Section = "Hosts";
  let activeDnsPanel: DnsPanel = "Records";
  let modal: Modal = null;
  let appInfo: AppInfo = {
    name: "VPN Appliance Manager",
    version: "0.1.0",
    status: "starting",
    system_username: "",
  };
  let hosts: DockerHost[] = [];
  let instances: VpnInstance[] = [];
  let instanceSummaries: InstanceSummary[] = [];
  let backendOptions: BackendOption[] = [];
  let clients: Client[] = [];
  let records: DnsRecord[] = [];
  let hostlists: DnsHostlist[] = [];
  let backups: BackupView[] = [];
  let logs: LogEvent[] = [];
  let activityFilter: ActivityFilter = {};
  let selectedHostId = "";
  let selectedInstanceId = "";
  let selectedDeviceId = "";
  let workspaceInstanceId = "";
  let workspaceTab: WorkspaceTab = "Overview";
  let busy = "";
  let notice = "";
  let noticeHealth: InstanceHealthView | null = null;
  let error: AppError | null = null;
  let inspection: HostInspectionView | null = null;
  let hostSetupPlan: HostProvisioningPlan | null = null;
  let probe: HostKeyProbe | null = null;
  let defaultSshUsername = "";
  let fingerprintConfirmation = "";
  let replaceChangedKey = false;
  let plan: DeploymentPreview | null = null;
  let restorePreview: BackupRestorePreview | null = null;
  let settingsDetail: InstanceDetail | null = null;
  let settingsForm: InstanceForm | null = null;
  let settingsPreview: InstanceUpdatePreview | null = null;
  let settingsImpactAcknowledged = false;
  let wizardStep = 1;
  let previousModal: Modal = null;
  let focusReturn: HTMLElement | null = null;
  let qrSvg = "";
  let technicalOpen = false;

  let hostForm = {
    display_name: "",
    hostname: "",
    port: 22,
    username: "",
    private_key_path: "",
    passphrase: "",
  };
  let instanceForm = newInstanceForm();
  let deviceForm = {
    instance_id: "",
    display_name: "",
    preshared_key: true,
    create_dns_record: true,
    dns_name: "",
  };
  let dnsForm: {
    instance_id: string;
    name: string;
    record_type: DnsRecordType;
    value: string;
    ttl: number;
  } = { instance_id: "", name: "", record_type: "A", value: "", ttl: 300 };
  let hostlistForm = {
    id: "",
    name: "",
    url: "",
    coverage: "",
  };

  $: selectedInstance = instances.find((item) => item.id === selectedInstanceId);
  $: selectedSummary = instanceSummaries.find((item) => item.instance.id === selectedInstanceId);
  $: selectedHost = hosts.find((item) => item.id === selectedHostId);
  $: instanceFormBackend = backendOptions.find((item) => item.kind === instanceForm.backend);
  $: BackendForm = backendForms[instanceForm.backend];
  $: instanceClients = clients.filter((item) => item.instance_id === selectedInstanceId);
  $: instanceRecords = records.filter((item) => item.instance_id === selectedInstanceId);
  $: dnsFormInstance = instances.find((item) => item.id === dnsForm.instance_id);
  $: deviceFormInstance = instances.find((item) => item.id === deviceForm.instance_id);
  $: deviceFormBackend = backendOptions.find((item) => item.kind === deviceFormInstance?.backend);
  $: selectedBackend = backendOptions.find((item) => item.kind === selectedInstance?.backend);
  $: deviceDnsPreview = deviceDnsNamePreview(deviceForm.dns_name, deviceFormInstance?.dns.zone || "");
  $: if (modal !== previousModal) {
    handleModalTransition(previousModal, modal);
    previousModal = modal;
  }

  onMount(load);

  async function load() {
    try {
      appInfo = await call<AppInfo>("app_info");
      defaultSshUsername = appInfo.system_username;
      await refresh();
    } catch (cause) {
      setError(cause);
      appInfo.status = "unavailable";
    }
  }

  async function refresh() {
    const [nextHosts, nextSummaries, nextBackends, nextLogs] = await Promise.all([
      call<DockerHost[]>("list_hosts"),
      call<InstanceSummary[]>("list_instance_summaries", { hostId: null }),
      call<BackendOption[]>("backend_options"),
      call<LogEvent[]>("activity_logs", { filter: {} }),
    ]);
    hosts = nextHosts;
    instanceSummaries = nextSummaries;
    instances = nextSummaries.map((summary) => summary.instance);
    backendOptions = nextBackends;
    logs = nextLogs;
    if (selectedHostId && !hosts.some((host) => host.id === selectedHostId)) selectedHostId = "";
    if (selectedInstanceId && !instances.some((instance) => instance.id === selectedInstanceId)) selectedInstanceId = "";
    if (!selectedHostId && hosts[0]) selectedHostId = hosts[0].id;
    if (!selectedInstanceId && instances[0]) selectedInstanceId = instances[0].id;
  }

  async function refreshClientAndDnsData() {
    if (!selectedInstanceId) {
      clients = [];
      records = [];
      return;
    }
    [clients, records] = await Promise.all([
      call<Client[]>("list_clients", { instanceId: selectedInstanceId }),
      call<DnsRecord[]>("list_dns_records", { instanceId: selectedInstanceId }),
    ]);
  }

  async function refreshBackups() {
    backups = selectedInstanceId
      ? await call<BackupView[]>("list_backup_views", { instanceId: selectedInstanceId })
      : [];
  }

  async function updateActivityFilter(filter: ActivityFilter) {
    activityFilter = filter;
    logs = await call<LogEvent[]>("activity_logs", { filter });
  }

  async function selectSection(section: Section) {
    workspaceInstanceId = "";
    active = section;
    if (section === "Clients" || section === "DNS") await refreshClientAndDnsData();
    if (section === "DNS" && hostlists.length === 0) await refreshHostlists();
    if (section === "Backups") await refreshBackups();
  }

  async function selectedInstanceChanged(value: string) {
    selectedInstanceId = value;
    if (active === "Clients" || active === "DNS") await refreshClientAndDnsData();
    if (active === "Backups") await refreshBackups();
  }

  function dnsTabKeydown(event: KeyboardEvent, panel: DnsPanel) {
    const index = dnsPanels.indexOf(panel);
    const next = event.key === "ArrowRight" ? dnsPanels[(index + 1) % dnsPanels.length] : event.key === "ArrowLeft" ? dnsPanels[(index - 1 + dnsPanels.length) % dnsPanels.length] : null;
    if (!next) return;
    event.preventDefault();
    activeDnsPanel = next;
    document.getElementById(`dns-tab-${next}`)?.focus();
  }

  async function manageInstance(instanceId: string) {
    selectedInstanceId = instanceId;
    workspaceInstanceId = instanceId;
    workspaceTab = "Overview";
  }

  async function selectWorkspaceTab(tab: WorkspaceTab) {
    workspaceTab = tab;
    if (tab === "Clients" || tab === "DNS") await refreshClientAndDnsData();
    if (tab === "DNS" && hostlists.length === 0) await refreshHostlists();
    if (tab === "Backups") await refreshBackups();
  }

  function closeWorkspace() {
    workspaceInstanceId = "";
    active = "Instances";
  }

  async function task<T>(label: string, operation: () => Promise<T>): Promise<T | undefined> {
    busy = label;
    notice = "";
    noticeHealth = null;
    error = null;
    technicalOpen = false;
    try {
      return await operation();
    } catch (cause) {
      setError(cause);
      return undefined;
    } finally {
      busy = "";
    }
  }

  function setError(cause: unknown) {
    if (typeof cause === "object" && cause !== null && "message" in cause) {
      error = cause as AppError;
    } else {
      error = {
        code: "unexpected",
        message: errorText(cause),
        remote_state_changed: false,
      };
    }
  }

  function setNotice(message: string, health: InstanceHealthView | null = null) {
    notice = message;
    noticeHealth = health;
  }

  function clearNotice() {
    notice = "";
    noticeHealth = null;
  }

  async function handleModalTransition(previous: Modal, next: Modal) {
    if (!previous && next) {
      focusReturn = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      await tick();
      document.querySelector<HTMLElement>(".modal")?.focus();
    } else if (previous && !next) {
      qrSvg = "";
      restorePreview = null;
      instanceForm.xray_certificate_path = "";
      instanceForm.xray_private_key_path = "";
      if (settingsForm) {
        settingsForm.xray_certificate_path = "";
        settingsForm.xray_private_key_path = "";
      }
      await tick();
      focusReturn?.focus();
      focusReturn = null;
    }
  }

  function closeModal() {
    modal = null;
  }

  function modalKeydown(event: KeyboardEvent) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeModal();
      return;
    }
    if (event.key !== "Tab") return;
    const dialog = event.currentTarget as HTMLElement;
    const controls = [...dialog.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])")];
    if (!controls.length) return;
    const first = controls[0];
    const last = controls.at(-1)!;
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }

  function modalLabel(value: Exclude<Modal, null>) {
    return {
      host: "Add SSH host", trust: "Verify SSH host key", instance: "Create VPN instance",
      device: "Add client", dns: "Add DNS record", hostlist: "Edit DNS hostlist",
      "host-setup": "Review host setup", plan: "Review deployment", restore: "Review backup restore",
      settings: "Edit instance settings", qr: "Client QR code",
    }[value];
  }

  function applyLiveHealth(instanceId: string, health: InstanceHealthView) {
    instanceSummaries = instanceSummaries.map((summary) =>
      summary.instance.id === instanceId
        ? { ...summary, state: health.state, state_evidence: "live_health", observed_at: health.observed_at }
        : summary,
    );
  }

  function openHost() {
    hostForm = {
      display_name: "",
      hostname: "",
      port: 22,
      username: defaultSshUsername,
      private_key_path: "",
      passphrase: "",
    };
    modal = "host";
  }

  async function chooseKey() {
    const result = await open({ multiple: false, directory: false, title: "Choose an SSH private key" });
    if (typeof result === "string") hostForm.private_key_path = result;
  }

  async function saveHost() {
    const created = await task("Saving host", () =>
      call<DockerHost>("create_host", {
        input: {
          ...hostForm,
          passphrase: hostForm.passphrase || null,
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedHostId = created.id;
    await refresh();
    notice = "Host saved. Probe its SSH key before inspection.";
  }

  async function probeHost(host: DockerHost) {
    selectedHostId = host.id;
    const result = await task("Probing SSH host key", () =>
      call<HostKeyProbe>("probe_host_key", { hostId: host.id }),
    );
    if (!result) return;
    probe = result;
    fingerprintConfirmation = "";
    replaceChangedKey = false;
    modal = "trust";
  }

  async function approveKey() {
    if (!probe || !selectedHostId) return;
    const approved = await task("Approving SSH host key", () =>
      call<void>("approve_host_key", {
        hostId: selectedHostId,
        probed: probe?.key,
        expectedFingerprint: fingerprintConfirmation,
        replaceChangedKey,
      }),
    );
    if (approved === undefined && error) return;
    modal = null;
    notice = "SSH host key approved.";
  }

  async function inspect(host: DockerHost) {
    selectedHostId = host.id;
    inspection = null;
    hostSetupPlan = null;
    const result = await task("Inspecting host", () =>
      call<HostInspectionView>("inspect_host_view", { hostId: host.id }),
    );
    if (result) inspection = result;
  }

  function hostSetupOperationLabel(operation: HostProvisioningOperation) {
    switch (operation.operation) {
      case "install_docker_engine":
        return "Install Docker Engine from the distribution repository";
      case "install_compose_plugin":
        return "Install Docker Compose v2 from the distribution repository";
      case "enable_docker_service":
        return "Enable and start the Docker service";
      case "grant_docker_access":
        return "Add the SSH user to the Docker group (root-equivalent access)";
      case "verify_prerequisites":
        return "Reconnect and verify direct Docker and Compose v2 access";
    }
  }

  async function reviewHostSetup(host: DockerHost) {
    selectedHostId = host.id;
    const result = await task("Calculating host setup plan", () =>
      call<HostProvisioningPlan>("plan_host_provisioning", { hostId: host.id }),
    );
    if (!result) return;
    hostSetupPlan = result;
    modal = "host-setup";
  }

  async function applyHostSetup() {
    if (!hostSetupPlan) return;
    const pendingPlan = hostSetupPlan;
    const result = await task("Applying and verifying host setup", () =>
      call<HostInspectionView>("apply_host_provisioning_view", {
        hostId: pendingPlan.host_id,
        expectedStateHash: pendingPlan.expected_state_hash,
      }),
    );
    if (!result) return;
    inspection = result;
    hostSetupPlan = null;
    modal = null;
    notice = "Host setup succeeded. Docker and Compose v2 are directly accessible over a fresh verified SSH session.";
  }

  async function removeHost(host: DockerHost) {
    const accepted = await confirm(
      `Delete "${host.display_name}" from local host management? Existing instances on this host must be deleted first.`,
      { title: "Delete Docker host", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Deleting host", () =>
      call<void>("delete_host", { hostId: host.id }),
    );
    if (result === undefined && error) return;
    if (selectedHostId === host.id) {
      selectedHostId = "";
      inspection = null;
      hostSetupPlan = null;
      probe = null;
    }
    await refresh();
    notice = "Host deleted.";
  }

  function openInstance() {
    const hostId = selectedHostId || hosts[0]?.id || "";
    const endpointHost = hosts.find((host) => host.id === hostId)?.ssh.hostname || "";
    instanceForm = newInstanceForm(hostId, endpointHost);
    wizardStep = 1;
    modal = "instance";
  }

  function backendChanged(backend: VpnBackendKind) {
    instanceForm.backend = backend;
    const option = backendOptions.find((item) => item.kind === instanceForm.backend);
    if (option) instanceForm.endpoint_port = option.default_port;
    if (instanceForm.backend === "ikev2" && !instanceForm.ikev2_server_identity) {
      instanceForm.ikev2_server_identity = instanceForm.endpoint_host;
    }
  }

  function backendSettingsFromForm(form: InstanceForm = instanceForm): BackendSettings {
    switch (form.backend) {
      case "wireguard":
        return {
          backend: "wireguard",
          settings: { userspace_fallback: form.wireguard_userspace_fallback },
        };
      case "amnezia_wg":
        return {
          backend: "amnezia_wg",
          settings: {
            generation: "awg2",
            jc: form.awg_jc,
            jmin: form.awg_jmin,
            jmax: form.awg_jmax,
            s1: form.awg_s1,
            s2: form.awg_s2,
            s3: form.awg_s3,
            s4: form.awg_s4,
            h1: { min: form.awg_h1_min, max: form.awg_h1_max },
            h2: { min: form.awg_h2_min, max: form.awg_h2_max },
            h3: { min: form.awg_h3_min, max: form.awg_h3_max },
            h4: { min: form.awg_h4_min, max: form.awg_h4_max },
          },
        };
      case "openvpn":
        return {
          backend: "openvpn",
          settings: {
            transport: form.openvpn_transport,
            cipher: form.openvpn_cipher,
            tls_protection: form.openvpn_tls_protection,
            certificate_lifetime_days: form.openvpn_certificate_lifetime_days,
          },
        };
      case "ikev2":
        return {
          backend: "ikev2",
          settings: {
            server_identity:
              form.ikev2_server_identity.trim() || form.endpoint_host.trim(),
            certificate_lifetime_days: form.ikev2_certificate_lifetime_days,
          },
        };
      case "xray":
        return {
          backend: "xray",
          settings: {
            security: form.xray_security,
            transport: form.xray_transport,
            server_name: form.xray_server_name,
            fingerprint: form.xray_fingerprint,
            xhttp_path: form.xray_xhttp_path,
            reality_public_key: null,
            reality_short_id: null,
          },
        };
    }
  }

  function editFormFromInstance(instance: VpnInstance) {
    const form = newInstanceForm(instance.host_id, instance.endpoint.host);
    Object.assign(form, {
      display_name: instance.display_name,
      backend: instance.backend,
      endpoint_port: instance.endpoint.port,
      ipv4_subnet: instance.network.ipv4_subnet,
      dns_zone: instance.dns.zone,
      routing_mode: instance.routing_mode,
    });
    const settings = instance.backend_settings;
    switch (settings.backend) {
      case "wireguard": form.wireguard_userspace_fallback = settings.settings.userspace_fallback; break;
      case "amnezia_wg": Object.assign(form, {
        awg_jc: settings.settings.jc, awg_jmin: settings.settings.jmin, awg_jmax: settings.settings.jmax,
        awg_s1: settings.settings.s1, awg_s2: settings.settings.s2, awg_s3: settings.settings.s3, awg_s4: settings.settings.s4,
        awg_h1_min: settings.settings.h1.min, awg_h1_max: settings.settings.h1.max,
        awg_h2_min: settings.settings.h2.min, awg_h2_max: settings.settings.h2.max,
        awg_h3_min: settings.settings.h3.min, awg_h3_max: settings.settings.h3.max,
        awg_h4_min: settings.settings.h4.min, awg_h4_max: settings.settings.h4.max,
      }); break;
      case "openvpn": Object.assign(form, {
        openvpn_transport: settings.settings.transport,
        openvpn_cipher: settings.settings.cipher,
        openvpn_tls_protection: settings.settings.tls_protection,
        openvpn_certificate_lifetime_days: settings.settings.certificate_lifetime_days,
      }); break;
      case "ikev2": Object.assign(form, {
        ikev2_server_identity: settings.settings.server_identity,
        ikev2_certificate_lifetime_days: settings.settings.certificate_lifetime_days,
      }); break;
      case "xray": Object.assign(form, {
        xray_security: settings.settings.security,
        xray_transport: settings.settings.transport,
        xray_server_name: settings.settings.server_name,
        xray_fingerprint: settings.settings.fingerprint,
        xray_xhttp_path: settings.settings.xhttp_path,
      }); break;
    }
    return form;
  }

  function settingsUpdateInput() {
    if (!settingsDetail || !settingsForm) return null;
    if (Boolean(settingsForm.xray_certificate_path) !== Boolean(settingsForm.xray_private_key_path)) {
      error = { code: "validation", message: "Choose both Xray TLS files, or leave both blank to retain existing material.", remote_state_changed: false };
      return null;
    }
    const backendSettings = backendSettingsFromForm(settingsForm);
    return {
      id: settingsDetail.summary.instance.id,
      display_name: settingsForm.display_name,
      endpoint_host: settingsForm.endpoint_host,
      endpoint_port: settingsForm.endpoint_port,
      ipv4_subnet: settingsForm.ipv4_subnet,
      dns_zone: settingsForm.dns_zone,
      routing_mode: settingsForm.routing_mode,
      persistent_keepalive: settingsDetail.summary.instance.persistent_keepalive,
      backend_settings: backendSettings,
      expected_current_state_hash: settingsDetail.current_state_hash,
      xray_tls_import:
        settingsForm.backend === "xray" && settingsForm.xray_security === "tls" && settingsForm.xray_certificate_path && settingsForm.xray_private_key_path
          ? { certificate_path: settingsForm.xray_certificate_path, private_key_path: settingsForm.xray_private_key_path }
          : null,
    };
  }

  async function openInstanceSettings() {
    if (!selectedInstanceId) return;
    const detail = await task("Loading instance settings", () =>
      call<InstanceDetail>("instance_detail", { instanceId: selectedInstanceId }),
    );
    if (!detail) return;
    settingsDetail = detail;
    settingsForm = editFormFromInstance(detail.summary.instance);
    settingsPreview = null;
    settingsImpactAcknowledged = false;
    modal = "settings";
  }

  async function previewSettingsUpdate() {
    const input = settingsUpdateInput();
    if (!input) return;
    settingsPreview = await task("Previewing settings impact", () =>
      call<InstanceUpdatePreview>("preview_instance_update", { input }),
    ) ?? null;
    settingsImpactAcknowledged = false;
  }

  async function saveSettingsUpdate() {
    const input = settingsUpdateInput();
    if (!input || !settingsPreview) return;
    const disruptive = settingsPreview.impact !== "no_changes" && settingsPreview.impact !== "live_reload";
    if (disruptive && !settingsImpactAcknowledged) return;
    const result = await task("Saving desired settings", () => call<VpnInstance>("update_instance", { input }));
    if (!result) return;
    modal = null;
    settingsDetail = null;
    settingsForm = null;
    settingsPreview = null;
    await refresh();
    notice = "Desired settings saved locally. Review the deployment before applying remote changes.";
  }

  async function saveInstance() {
    const created = await task("Creating instance", () =>
      call<VpnInstance>("create_instance", {
        input: {
          host_id: instanceForm.host_id,
          display_name: instanceForm.display_name,
          backend: instanceForm.backend,
          backend_settings: backendSettingsFromForm(),
          endpoint_host: instanceForm.endpoint_host,
          endpoint_port: instanceForm.endpoint_port,
          ipv4_subnet: instanceForm.ipv4_subnet,
          dns_zone: instanceForm.dns_zone,
          routing_mode: instanceForm.routing_mode,
          xray_tls_import:
            instanceForm.backend === "xray" && instanceForm.xray_security === "tls"
              ? {
                  certificate_path: instanceForm.xray_certificate_path,
                  private_key_path: instanceForm.xray_private_key_path,
                }
              : null,
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedInstanceId = created.id;
    await refresh();
    workspaceInstanceId = created.id;
    workspaceTab = "Overview";
    notice = "Instance created locally. Review its deployment plan to apply it.";
  }

  async function reviewPlan(instance: VpnInstance) {
    selectedInstanceId = instance.id;
    const result = await task("Calculating deployment plan", () =>
      call<DeploymentPreview>("plan_instance_preview", { instanceId: instance.id }),
    );
    if (!result) return;
    plan = result;
    modal = "plan";
  }

  async function applyPlan() {
    if (!plan) return;
    const pendingPlan = plan;
    modal = null;
    plan = null;
    const result = await task("Applying and verifying deployment", () =>
      call<DeploymentResultView>("apply_instance_view", {
        instanceId: pendingPlan.instance_id,
        expectedStateHash: pendingPlan.desired_state_hash,
      }),
    );
    if (!result) return;
    await refresh();
    applyLiveHealth(pendingPlan.instance_id, result.health);
    setNotice(`Deployment ${result.status}. ${healthSummary(result.health)}`, result.health);
  }

  async function instanceAction(command: "start_instance" | "stop_instance" | "health", instance: VpnInstance) {
    const viewCommand = {
      start_instance: "start_instance_view",
      stop_instance: "stop_instance_view",
      health: "health_view",
    }[command];
    const result = await task(command.replace("_", " "), () =>
      call<InstanceHealthView>(viewCommand, { instanceId: instance.id }),
    );
    if (result) {
      applyLiveHealth(instance.id, result);
      setNotice(healthSummary(result), result);
    }
  }

  function healthSummary(health: InstanceHealthView) {
    const passing = health.checks.filter((check) => check.passing).length;
    return `${health.state.replace("_", " ")}: ${passing}/${health.checks.length} checks passing.`;
  }

  async function removeInstance(instance: VpnInstance) {
    const accepted = await confirm(
      `Back up, stop, and move "${instance.display_name}" to recoverable remote trash?`,
      { title: "Delete VPN instance", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Deleting instance", () =>
      call<void>("delete_instance", { instanceId: instance.id }),
    );
    if (result === undefined && error) return;
    selectedInstanceId = "";
    await refresh();
    notice = "Instance moved to remote trash and soft-deleted locally.";
  }

  function openDevice() {
    const instanceId = selectedInstanceId || instances[0]?.id || "";
    const instance = instances.find((item) => item.id === instanceId);
    const capabilities = backendOptions.find((item) => item.kind === instance?.backend)?.capabilities;
    deviceForm = {
      instance_id: instanceId,
      display_name: "",
      preshared_key: true,
      create_dns_record: capabilities?.managed_dns ?? true,
      dns_name: "",
    };
    modal = "device";
  }

  async function saveDevice() {
    const dnsNameError = deviceFormBackend?.capabilities.managed_dns
      ? deviceDnsNameZoneError(deviceForm.dns_name, deviceFormInstance?.dns.zone || "")
      : null;
    if (dnsNameError) {
      error = {
        code: "validation",
        message: dnsNameError,
        remote_state_changed: false,
      };
      return;
    }
    const created = await task("Generating client identity", () =>
      call<unknown>("create_device", {
        input: {
          ...deviceForm,
          user_id: null,
          dns_name: deviceForm.dns_name || null,
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedInstanceId = deviceForm.instance_id;
    await refreshClientAndDnsData();
    const backend = deviceFormInstance?.backend;
    notice =
      backend === "xray"
        ? "Xray client UUID created locally. Review and deploy the instance before export."
        : backend === "openvpn" || backend === "ikev2"
          ? "Client key generated locally and certificate issued through the verified SSH authority."
          : "Client keys were generated locally and saved in the native credential store.";
  }

  async function toggleDevice(device: Client) {
    const input: UpdateDeviceInput = {
      id: device.id,
      user_id: device.user_id ?? null,
      display_name: device.display_name,
      dns_name: device.dns_name ?? null,
      enabled: !device.enabled,
    };
    const result = await task("Updating client", () =>
      call<unknown>("update_device", { input }),
    );
    if (result) await refreshClientAndDnsData();
  }

  async function replaceDeviceIdentity(device: Client) {
    const result = await task("Replacing client identity", () =>
      call<unknown>("replace_device_identity", { deviceId: device.id }),
    );
    if (!result) return;
    await refreshClientAndDnsData();
    notice = "A new client identity was created in the native credential store. Review and deploy before exporting it.";
  }

  async function removeDevice(device: Client) {
    const result = await task("Removing client", () =>
      call<void>("delete_device", { deviceId: device.id }),
    );
    if (result === undefined && error) return;
    await refreshClientAndDnsData();
    notice =
      device.backend === "openvpn" || device.backend === "ikev2"
        ? "Client certificate revoked and client removed."
        : "Client removed locally. Review and deploy the instance to revoke its identity.";
  }

  async function exportDevice(device: Client) {
    const format = device.export_formats[0];
    const exportInfo = {
      wire_guard_configuration: { suffix: "conf", filterExtension: "conf", name: "WireGuard configuration" },
      amnezia_wg_configuration: { suffix: "conf", filterExtension: "conf", name: "AWG configuration" },
      open_vpn_profile: { suffix: "ovpn", filterExtension: "ovpn", name: "OpenVPN profile" },
      protected_pkcs12: { suffix: "p12", filterExtension: "p12", name: "Protected PKCS#12 credential" },
      vless_uri: { suffix: "vless.txt", filterExtension: "txt", name: "VLESS URI" },
    }[format];
    if (!exportInfo) {
      error = { code: "unsupported_export", message: "This client has no implemented export format.", remote_state_changed: false };
      return;
    }
    const destination = await save({
      title: `Export ${exportInfo.name}`,
      defaultPath: `${device.display_name.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}.${exportInfo.suffix}`,
      filters: [{ name: exportInfo.name, extensions: [exportInfo.filterExtension] }],
    });
    if (!destination) return;
    const result = await task("Exporting private configuration", () =>
      call<string>("export_client_configuration", {
        deviceId: device.id,
        destination,
      }),
    );
    if (result) notice = `Configuration exported to ${result} with mode 0600.`;
  }

  async function showQr(device: Client) {
    selectedDeviceId = device.id;
    const result = await task("Generating QR code", () =>
      call<string>("client_qr_svg", { deviceId: device.id }),
    );
    if (!result) return;
    qrSvg = result;
    modal = "qr";
  }

  async function handleClientAction(client: Client, action: ClientActionView) {
    if (action.warning) {
      const accepted = await confirm(action.warning, {
        title: `${action.label}: ${client.display_name}`,
        kind: action.destructive ? "warning" : "info",
      });
      if (!accepted) return;
    }
    switch (action.action) {
      case "enable":
      case "disable":
      case "revoke":
        await toggleDevice(client);
        break;
      case "rotate_identity":
      case "replace_identity":
        await replaceDeviceIdentity(client);
        break;
      case "export":
        await exportDevice(client);
        break;
      case "qr_export":
        await showQr(client);
        break;
      case "remove":
        await removeDevice(client);
        break;
      case "inspect_statistics":
        notice = "Statistics are not available until the backend returns observed client data.";
        break;
    }
  }

  function backendDisplayName(kind: VpnBackendKind) {
    return backendOptions.find((option) => option.kind === kind)?.display_name ?? kind;
  }

  function backendOption(kind: VpnBackendKind) {
    return backendOptions.find((option) => option.kind === kind);
  }

  function openDns() {
    dnsForm = {
      instance_id: selectedInstanceId || instances[0]?.id || "",
      name: "",
      record_type: "A",
      value: "",
      ttl: 300,
    };
    modal = "dns";
  }

  async function saveDns() {
    const ownerError = dnsOwnerZoneError(dnsForm.name, dnsFormInstance?.dns.zone || "");
    if (ownerError) {
      error = {
        code: "validation",
        message: ownerError,
        remote_state_changed: false,
      };
      return;
    }
    const result = await task("Validating DNS record", () =>
      call<DnsRecord>("create_dns_record", { input: dnsForm }),
    );
    if (!result) return;
    modal = null;
    selectedInstanceId = result.instance_id;
    await refreshClientAndDnsData();
    notice = "DNS record saved. The instance now has pending desired-state changes.";
  }

  function dnsOwnerZoneError(name: string, zone: string) {
    if (!zone) return null;
    const owner = name.trim().replace(/\.$/, "").toLowerCase();
    const normalizedZone = zone.trim().replace(/\.$/, "").toLowerCase();
    if (!owner || owner === "@" || !owner.includes(".")) return null;
    if (owner === normalizedZone || owner.endsWith(`.${normalizedZone}`)) return null;
    return `DNS owner names must be short names inside ${zone}, or fully-qualified names ending in .${zone}.`;
  }

  function deviceDnsNamePreview(name: string, zone: string) {
    const owner = name.trim().replace(/\.$/, "").toLowerCase();
    const normalizedZone = zone.trim().replace(/\.$/, "").toLowerCase();
    if (!owner || !normalizedZone) return "";
    if (owner === normalizedZone || owner.endsWith(`.${normalizedZone}`)) return owner;
    if (owner.includes(".")) return "";
    return `${owner}.${normalizedZone}`;
  }

  function deviceDnsNameZoneError(name: string, zone: string) {
    if (!zone) return null;
    const owner = name.trim().replace(/\.$/, "").toLowerCase();
    const normalizedZone = zone.trim().replace(/\.$/, "").toLowerCase();
    if (!owner || !owner.includes(".")) return null;
    if (owner === normalizedZone || owner.endsWith(`.${normalizedZone}`)) return null;
    return `Device DNS names must be short names inside ${zone}, or fully-qualified names ending in .${zone}.`;
  }

  async function removeDns(record: DnsRecord) {
    const accepted = await confirm(`Delete ${record.name} ${record.record_type}?`, {
      title: "Delete DNS record",
      kind: "warning",
    });
    if (!accepted) return;
    const result = await task("Deleting DNS record", () =>
      call<void>("delete_dns_record", {
        recordId: record.id,
        instanceId: record.instance_id,
      }),
    );
    if (result === undefined && error) return;
    await refreshClientAndDnsData();
  }

  function openHostlist(hostlist: DnsHostlist | null = null) {
    hostlistForm = hostlist
      ? {
          id: hostlist.id,
          name: hostlist.name,
          url: hostlist.url,
          coverage: hostlist.coverage,
        }
      : {
          id: "",
          name: "",
          url: "",
          coverage: "",
        };
    modal = "hostlist";
  }

  async function refreshHostlists() {
    hostlists = await call<DnsHostlist[]>("list_dns_hostlists");
  }

  async function saveHostlist() {
    const payload = {
      name: hostlistForm.name,
      url: hostlistForm.url,
      coverage: hostlistForm.coverage,
    };
    const result = hostlistForm.id
      ? await task("Saving hostlist", () =>
          call<DnsHostlist>("update_dns_hostlist", {
            hostlist: { id: hostlistForm.id, ...payload },
          }),
        )
      : await task("Adding hostlist", () =>
          call<DnsHostlist>("create_dns_hostlist", { input: payload }),
        );
    if (!result) return;
    modal = null;
    await refreshHostlists();
    notice = "Hostlist saved. Deploy or refresh DNS to apply the updated blocklist.";
  }

  async function removeHostlist(hostlist: DnsHostlist) {
    const accepted = await confirm(`Delete ${hostlist.name}?`, {
      title: "Delete hostlist",
      kind: "warning",
    });
    if (!accepted) return;
    const result = await task("Deleting hostlist", () =>
      call<void>("delete_dns_hostlist", { hostlistId: hostlist.id }),
    );
    if (result === undefined && error) return;
    await refreshHostlists();
    notice = "Hostlist deleted. Deploy or refresh DNS to apply the updated blocklist.";
  }

  async function makeBackup(instanceId = selectedInstanceId) {
    if (!instanceId) return;
    const result = await task("Creating remote backup", () =>
      call<BackupInfo>("create_backup", { instanceId }),
    );
    if (!result) return;
    await refreshBackups();
    notice = `Backup ${result.name} created.`;
  }

  async function backupInstance(instance: VpnInstance) {
    selectedInstanceId = instance.id;
    await makeBackup(instance.id);
  }

  async function refreshRemoteCredentials() {
    if (!selectedInstanceId) return;
    const result = await task("Refreshing remote credential store", () =>
      call<InstanceHealthView>("refresh_remote_credentials_view", { instanceId: selectedInstanceId }),
    );
    if (!result) return;
    applyLiveHealth(selectedInstanceId, result);
    setNotice(`Credential store refreshed. ${healthSummary(result)}`, result);
  }

  async function refreshRemoteDnsStore() {
    if (!selectedInstanceId) return;
    const result = await task("Refreshing remote DNS store", () =>
      call<InstanceHealthView>("refresh_remote_dns_store_view", { instanceId: selectedInstanceId }),
    );
    if (!result) return;
    applyLiveHealth(selectedInstanceId, result);
    setNotice(`DNS store refreshed. ${healthSummary(result)}`, result);
  }

  async function reviewBackupRestore(backup: BackupView) {
    const preview = await task("Reviewing backup restore", () =>
      call<BackupRestorePreview>("preview_backup_restore", {
        instanceId: backup.instance_id,
        backupName: backup.name,
      }),
    );
    if (!preview) return;
    restorePreview = preview;
    modal = "restore";
  }

  async function applyBackupRestore() {
    if (!restorePreview) return;
    const pending = restorePreview;
    modal = null;
    restorePreview = null;
    const health = await task("Restoring and verifying backup", () =>
      call<InstanceHealthView>("restore_backup_by_name", {
        instanceId: pending.instance_id,
        backupName: pending.backup_name,
        expectedStateHash: pending.expected_state_hash,
      }),
    );
    if (!health) return;
    await refreshBackups();
    applyLiveHealth(pending.instance_id, health);
    setNotice(`Backup ${pending.backup_name} restored and verified.`, health);
  }
</script>

<svelte:head><title>{active} · VPN Appliance Manager</title></svelte:head>

<div class="shell">
  <aside>
    <div class="brand">
      <div class="mark">VA</div>
      <div><strong>VPN Appliance</strong><span>Manager</span></div>
    </div>
    <nav aria-label="Primary">
      {#each sections as section}
        <button class:active={active === section} title={section} aria-label={section} onclick={() => selectSection(section)}>
          <span class="nav-icon" aria-hidden="true">{{ Hosts: "H", Instances: "I", Clients: "C", DNS: "D", Backups: "B", Logs: "L" }[section]}</span><span class="nav-label">{section}</span>
        </button>
      {/each}
    </nav>
  </aside>

  <main>
    {#if workspaceInstanceId && selectedSummary}
      {#if busy}<div class="progress" role="status" aria-live="polite"><span></span>{busy}…</div>{/if}
      {#if notice}<div class="notice" role="status"><span>{notice}</span><button aria-label="Dismiss" onclick={clearNotice}>×</button></div>{/if}
      {#if error}<div class="alert" role="alert"><div><strong>{error.message}</strong>{#if error.remediation}<p>{error.remediation}</p>{/if}</div><button aria-label="Dismiss" onclick={() => (error = null)}>×</button></div>{/if}
      <InstanceWorkspace
        summary={selectedSummary}
        options={backendOptions}
        tab={workspaceTab}
        devices={clients}
        {records}
        {hostlists}
        {backups}
        {logs}
        onback={closeWorkspace}
        ontabchange={selectWorkspaceTab}
        onhealth={() => instanceAction("health", selectedSummary.instance)}
        onplan={() => reviewPlan(selectedSummary.instance)}
        onaddclient={openDevice}
        onclientaction={handleClientAction}
        onbackup={() => backupInstance(selectedSummary.instance)}
        onrestore={reviewBackupRestore}
        oneditsettings={openInstanceSettings}
      />
      <footer>{appInfo.name} {appInfo.version} · Local-first management over verified SSH</footer>
    {:else}
    <header>
      <div><p class="eyebrow">CONTROL PLANE</p><h1>{active}</h1></div>
      <div class="header-actions">
        {#if active === "Hosts"}<button class="primary" onclick={openHost}>Add host</button>{/if}
        {#if active === "Instances"}<button class="primary" onclick={openInstance} disabled={!hosts.length}>Create instance</button>{/if}
        {#if active === "Clients"}
          {#if selectedBackend?.capabilities.quick_credential_refresh}
            <button class="secondary" onclick={refreshRemoteCredentials} disabled={!selectedInstanceId}>Refresh identities</button>
          {/if}
          <button class="primary" onclick={openDevice} disabled={!instances.length}>Add client</button>
        {/if}
        {#if active === "DNS"}
          {#if activeDnsPanel === "Records"}
            <button class="secondary" onclick={refreshRemoteDnsStore} disabled={!selectedInstanceId || !selectedBackend?.capabilities.managed_dns}>Refresh DNS store</button>
            <button class="primary" onclick={openDns} disabled={!instances.length || !selectedBackend?.capabilities.managed_dns}>Add record</button>
          {/if}
        {/if}
        {#if active === "Backups"}<button class="primary" onclick={() => makeBackup()} disabled={!selectedInstanceId}>Create backup</button>{/if}
      </div>
    </header>

    {#if busy}<div class="progress" role="status" aria-live="polite"><span></span>{busy}…</div>{/if}
    {#if notice}
      <div class="notice" role="status">
        <div class="notice-body">
          <span>{notice}</span>
          {#if noticeHealth}
            <details class="check-log">
              <summary>Checks</summary>
              <div class="check-log-list">
                {#each noticeHealth.checks as check}
                  <div class:pass={check.passing} class:fail={!check.passing}>
                    <b>{check.passing ? "Pass" : "Fail"}</b><span>{check.label}</span>
                  </div>
                {/each}
                {#if noticeHealth.details.length}
                  <div class="check-details">
                    {#each noticeHealth.details as detail}<span>{detail}</span>{/each}
                  </div>
                {/if}
              </div>
            </details>
          {/if}
        </div>
        <button aria-label="Dismiss" onclick={clearNotice}>×</button>
      </div>
    {/if}
    {#if error}
      <div class="alert" role="alert">
        <div>
          <strong>{error.message}</strong>
          {#if error.remediation}<p>{error.remediation}</p>{/if}
          {#if error.remote_state_changed}
            <p>Remote state changed. Rollback {error.rollback_succeeded ? "succeeded" : "did not succeed"}.</p>
          {/if}
          {#if error.technical_detail}
            <button class="text-button" onclick={() => (technicalOpen = !technicalOpen)}>
              {technicalOpen ? "Hide" : "Show"} technical details
            </button>
            {#if technicalOpen}<pre>{error.technical_detail}</pre>{/if}
          {/if}
        </div>
        <button aria-label="Dismiss" onclick={() => (error = null)}>×</button>
      </div>
    {/if}

    {#if active === "Hosts"}
      {#if hosts.length === 0}
        <section class="hero">
          <div>
            <span class="pill">FIRST RUN</span>
            <h2>Connect your first Docker host</h2>
            <p>Add a Linux server, verify its SSH fingerprint, then inspect Docker and Compose before anything changes remotely.</p>
            <button class="primary" onclick={openHost}>Add SSH host</button>
          </div>
          <div class="checklist">
            <div><b>1</b><span><strong>SSH trust</strong><small>Explicit SHA-256 host-key approval</small></span></div>
            <div><b>2</b><span><strong>Runtime inspection</strong><small>Linux, Docker, Compose, kernel support</small></span></div>
            <div><b>3</b><span><strong>Desired-state deploy</strong><small>Plan, backup, apply, verify</small></span></div>
          </div>
        </section>
      {/if}
      <section class="panel">
        <div class="panel-head"><h3>Docker hosts</h3><span>{hosts.length} configured</span></div>
        {#if hosts.length}
          <div class="rows">
            {#each hosts as host}
              <article class:selected={host.id === selectedHostId}>
                <div class="status-icon">⌁</div>
                <button class="row-main row-select" onclick={() => { selectedHostId = host.id; inspection = null; hostSetupPlan = null; }}>
                  <strong>{host.display_name}</strong>
                  <small>{host.ssh.username}@{host.ssh.hostname}:{host.ssh.port}</small>
                </button>
                <button class="secondary" onclick={() => probeHost(host)}>Verify key</button>
                <button class="secondary" onclick={() => inspect(host)}>Inspect</button>
                <button class="menu danger" title="Delete" onclick={() => removeHost(host)}>Delete</button>
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><div class="server-icon">⌁</div><h3>No hosts yet</h3><p>Your SSH keys stay on this Mac and host keys are never accepted silently.</p></div>
        {/if}
      </section>
      {#if inspection && selectedHost}
        <section class="panel compact">
          <div class="panel-head"><h3>{selectedHost.display_name} readiness</h3><span>{inspection.inspection.operating_system} · {inspection.inspection.architecture}</span></div>
          <HostReadinessMatrix view={inspection} />
          {#if inspection.inspection.warnings.length}
            <div class="warning-list">
              {#each inspection.inspection.warnings as warning}<div class="warning">{warning}</div>{/each}
            </div>
          {/if}
          {#if !inspection.docker_ready}
            <div class="host-setup-cta">
              <div><strong>Prerequisites need attention</strong><span>Review the exact package, service, and access changes before anything is installed.</span></div>
              <button class="primary" onclick={() => reviewHostSetup(selectedHost)}>Review setup</button>
            </div>
          {/if}
        </section>
      {/if}
    {:else if active === "Instances"}
      <section class="stats">
        <article><span>Instances</span><strong>{instances.length}</strong><small>Across all hosts</small></article>
        <article><span>Managed hosts</span><strong class="green">{hosts.length}</strong><small>Explicit SSH trust</small></article>
        <article><span>Selected</span><strong>{selectedInstance ? "1" : "0"}</strong><small>{selectedInstance?.display_name || "None"}</small></article>
      </section>
      <section class="panel instance-list-panel">
        {#if instances.length}
          <div class="rows instance-rows">
            {#each instanceSummaries as summary}
              <article class:selected={summary.instance.id === selectedInstanceId}>
                <BackendBadge backend={summary.instance.backend} options={backendOptions} />
                <button class="row-main row-select" onclick={() => { selectedInstanceId = summary.instance.id; }}>
                  <strong>{summary.instance.display_name}</strong>
                  <small>{summary.secondary_summary} · {summary.listener_summary}</small>
                </button>
                <StateBadge state={summary.state} />
                <button class="primary small" onclick={() => manageInstance(summary.instance.id)}>Manage</button>
                <InstanceActions instance={summary.instance} onstart={(instance) => instanceAction("start_instance", instance)} onstop={(instance) => instanceAction("stop_instance", instance)} onhealth={(instance) => instanceAction("health", instance)} onplan={reviewPlan} onbackup={backupInstance} ondelete={removeInstance} />
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No VPN instances</h3><p>Create a WireGuard, AWG2, OpenVPN, IKEv2, or Xray appliance after approving a Docker host.</p></div>
        {/if}
      </section>
    {:else if active === "Clients"}
      <div class="toolbar">
        <InstanceSelector {instances} value={selectedInstanceId} onchange={selectedInstanceChanged} />
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Client identities</h3><span>{instanceClients.length} for selected instance</span></div>
        <ClientsContent clients={instanceClients} onaction={handleClientAction} />
      </section>
    {:else if active === "DNS"}
      <div class="toolbar">
        <InstanceSelector {instances} value={selectedInstanceId} onchange={selectedInstanceChanged} />
        {#if selectedInstance}
          <span>{selectedBackend?.capabilities.managed_dns ? `Zone ${selectedInstance.dns.zone} - SOA ${selectedInstance.dns.soa_serial}` : `${backendDisplayName(selectedInstance.backend)} does not provide a routed private DNS zone`}</span>
        {/if}
      </div>
      <div class="tabs" role="tablist" aria-label="DNS panels">
        {#each dnsPanels as panel}
          <button type="button" role="tab" id={`dns-tab-${panel}`} aria-controls="dns-panel" aria-selected={activeDnsPanel === panel} tabindex={activeDnsPanel === panel ? 0 : -1} class:active={activeDnsPanel === panel} onclick={() => (activeDnsPanel = panel)} onkeydown={(event) => dnsTabKeydown(event, panel)}>{panel}</button>
        {/each}
      </div>
      <div id="dns-panel" role="tabpanel" aria-labelledby={`dns-tab-${activeDnsPanel}`} tabindex="0">
      {#if activeDnsPanel === "Records"}
      <section class="panel">
        <div class="panel-head"><h3>Private DNS records</h3><span>A · AAAA · CNAME · TXT · SRV</span></div>
        {#if selectedInstance && !selectedBackend?.capabilities.managed_dns}
          <div class="empty"><h3>Private DNS is not applicable</h3><p>{backendDisplayName(selectedInstance.backend)} is a proxy backend and does not allocate routed client addresses or publish this private zone.</p></div>
        {:else if instanceRecords.length}
          <div class="table">
            <div class="table-head"><span>Name</span><span>Type</span><span>Value</span><span>TTL</span><span></span></div>
            {#each instanceRecords as record}
              <div><span>{record.name}</span><span><b class="type">{record.record_type}</b></span><span>{record.value}</span><span>{record.ttl}</span><span><button class="menu danger" onclick={() => removeDns(record)}>Delete</button></span></div>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No custom records</h3><p>The gateway record is generated automatically. Other queries use DNS-over-TLS.</p></div>
        {/if}
      </section>
      {:else}
        <section class="panel">
          <div class="panel-head">
            <h3>Hostlists</h3>
            <div class="panel-head-actions">
              <span>{hostlists.length} HTTPS sources</span>
              <button class="primary small" onclick={() => openHostlist()}>Add</button>
            </div>
          </div>
          {#if hostlists.length}
            <div class="hostlist-table">
              <div class="hostlist-head"><span>Name</span><span>URL</span><span>Coverage</span><span></span></div>
              {#each hostlists as hostlist}
                <div>
                  <strong>{hostlist.name}</strong>
                  <a href={hostlist.url} target="_blank" rel="noreferrer" aria-label={`Open ${hostlist.name}`}>{hostlist.url}</a>
                  <span>{hostlist.coverage || "Custom hosts source"}</span>
                  <span class="row-actions"><button class="secondary" onclick={() => openHostlist(hostlist)}>Edit</button><button class="menu danger" onclick={() => removeHostlist(hostlist)}>Delete</button></span>
                </div>
              {/each}
            </div>
          {:else}
            <div class="empty"><h3>No hostlists</h3><p>Add HTTPS hosts files to build the DNS blocklist used by future deployments.</p></div>
          {/if}
        </section>
      {/if}
      </div>
    {:else if active === "Backups"}
      <div class="toolbar">
        <InstanceSelector {instances} value={selectedInstanceId} onchange={selectedInstanceChanged} />
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Deployment backups</h3><span>10 retained per instance</span></div>
        <BackupsContent {backups} onrestore={reviewBackupRestore} />
      </section>
    {:else}
      <section class="panel">
        <div class="panel-head"><h3>Operational history</h3><span>Secrets redacted · {logs.length} events</span></div>
        <LogFilters value={activityFilter} {hosts} {instances} onchange={updateActivityFilter} />
        <LogsContent events={logs} />
      </section>
    {/if}

    <footer>{appInfo.name} {appInfo.version} · Local-first management over verified SSH</footer>
    {/if}
  </main>
</div>

{#if modal}
  <div class="modal-backdrop" role="presentation" onclick={(event) => { if (event.target === event.currentTarget) closeModal(); }}>
    <div class="modal" role="dialog" aria-modal="true" aria-label={modalLabel(modal)} tabindex="-1" onkeydown={modalKeydown}>
      {#if modal === "host"}
        <ModalShell title="Add SSH host" eyebrow="FIRST RUN" onclose={() => (modal = null)}>
          <form onsubmit={(event) => { event.preventDefault(); saveHost(); }}>
            <label>Display name<input bind:value={hostForm.display_name} required placeholder="Debian lab" /></label>
            <div class="form-grid"><label>Hostname or IP<input bind:value={hostForm.hostname} required placeholder="192.168.86.55" /></label><label>SSH port<input type="number" bind:value={hostForm.port} min="1" max="65535" required /></label></div>
            <label>SSH username<input bind:value={hostForm.username} required placeholder={defaultSshUsername || "username"} /></label>
            <label>SSH private key<div class="path-input"><input bind:value={hostForm.private_key_path} required placeholder="/Users/you/.ssh/id_ed25519 or key.ppk" /><button type="button" class="secondary" onclick={chooseKey}>Choose</button></div></label>
            <label>Key passphrase <span class="optional">optional · saved to Keychain</span><input type="password" bind:value={hostForm.passphrase} autocomplete="new-password" /></label>
            <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" disabled={Boolean(busy)}>Save host</button></div>
          </form>
        </ModalShell>
      {:else if modal === "trust" && probe}
        <div class="modal-head"><div><p class="eyebrow">SSH TRUST</p><h2>{probe.state === "changed" ? "Host key changed" : "Verify host key"}</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <div class:critical={probe.state === "changed"} class="fingerprint-card">
          <span>{probe.key.algorithm} · {probe.key.resolved_address}:{probe.key.port}</span>
          <code>{probe.key.sha256_fingerprint}</code>
          {#if probe.approved_fingerprint}<small>Previously approved: {probe.approved_fingerprint}</small>{/if}
        </div>
        <p class="help">Verify this SHA-256 fingerprint through a trusted channel, then enter it exactly. No authentication occurs during the probe.</p>
        <div class="command-card">
          <span>On the remote server, run:</span>
          <pre>{remoteHostKeyCommand(probe.key.sha256_fingerprint)}</pre>
          <small>Compare the {probe.key.algorithm} line to the fingerprint above.</small>
        </div>
        <label>Fingerprint confirmation<input bind:value={fingerprintConfirmation} spellcheck="false" placeholder="SHA256:…" /></label>
        {#if probe.state === "changed"}<label class="checkbox critical-text"><input type="checkbox" bind:checked={replaceChangedKey} /> I separately verified and intend to replace the approved key.</label>{/if}
        <div class="modal-actions"><button class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" onclick={approveKey} disabled={fingerprintConfirmation !== probe.key.sha256_fingerprint || (probe.state === "changed" && !replaceChangedKey)}>Approve key</button></div>
      {:else if modal === "instance"}
        <div class="modal-head"><div><p class="eyebrow">STEP {wizardStep} OF 5</p><h2>Create VPN instance</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <div class="wizard-steps" aria-label="Creation progress"><span class:active={wizardStep >= 1}>Host</span><span class:active={wizardStep >= 2}>Type</span><span class:active={wizardStep >= 3}>Basics</span><span class:active={wizardStep >= 4}>Backend</span><span class:active={wizardStep >= 5}>Review</span></div>
        <form onsubmit={(event) => { event.preventDefault(); if (wizardStep < 5) wizardStep += 1; else saveInstance(); }}>
          {#if wizardStep === 1}
            <label>Docker host<select bind:value={instanceForm.host_id} required>{#each hosts as host}<option value={host.id}>{host.display_name}</option>{/each}</select></label>
            {#if inspection && selectedHostId === instanceForm.host_id}<HostReadinessMatrix view={inspection} />{:else}<div class="empty small-empty"><h3>Readiness not cached</h3><p>Finish or cancel this wizard, then use Inspect on the Hosts screen. Opening the wizard never probes SSH automatically.</p></div>{/if}
          {:else if wizardStep === 2}
            <div class="backend-cards">{#each backendOptions as option}<button type="button" class:selected={instanceForm.backend === option.kind} onclick={() => backendChanged(option.kind)}><BackendBadge backend={option.kind} options={backendOptions} /><span>{option.presentation.description}</span></button>{/each}</div>
          {:else if wizardStep === 3}
            <label>Display name<input bind:value={instanceForm.display_name} required placeholder="Home VPN" /></label>
            <div class="form-grid"><label>Public endpoint<input bind:value={instanceForm.endpoint_host} required placeholder="vpn.example.com" /></label><label>Listener port<input type="number" bind:value={instanceForm.endpoint_port} min="1" max="65535" disabled={instanceForm.backend === "ikev2"} required /></label></div>
            {#if instanceFormBackend?.presentation.client_addresses === "allocated"}<div class="form-grid"><label>Private IPv4 subnet<input bind:value={instanceForm.ipv4_subnet} required /></label><label>Private DNS zone<input bind:value={instanceForm.dns_zone} required /></label></div><label>Default routing<select bind:value={instanceForm.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel (IPv4)</option></select></label>{/if}
          {:else if wizardStep === 4}
            <BackendForm bind:form={instanceForm} />
          {:else}
            <div class="review-facts"><div><span>Host</span><strong>{hosts.find((host) => host.id === instanceForm.host_id)?.display_name}</strong></div><div><span>Backend</span><strong>{instanceFormBackend?.display_name}</strong></div><div><span>Endpoint</span><strong>{instanceForm.endpoint_host}:{instanceForm.endpoint_port}</strong></div>{#if instanceFormBackend?.presentation.client_addresses === "allocated"}<div><span>Network</span><strong>{instanceForm.ipv4_subnet}</strong></div><div><span>DNS</span><strong>{instanceForm.dns_zone}</strong></div>{/if}</div>
            <p class="help">Create saves local desired state only. After creation, review the typed deployment impact before changing the host.</p>
          {/if}
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button>{#if wizardStep > 1}<button type="button" class="secondary" onclick={() => (wizardStep -= 1)}>Back</button>{/if}<button class="primary">{wizardStep === 5 ? "Create" : "Continue"}</button></div>
        </form>
      {:else if modal === "device"}
        <div class="modal-head"><div><p class="eyebrow">CLIENT IDENTITY</p><h2>Add client</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveDevice(); }}>
          <label>Instance<select bind:value={deviceForm.instance_id} required>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
          <label>Client name<input bind:value={deviceForm.display_name} required placeholder="Main PC" /></label>
          {#if deviceFormBackend?.capabilities.managed_dns}
            <label>DNS name <span class="optional">optional</span><input bind:value={deviceForm.dns_name} placeholder="mainpc" /></label>
            {#if deviceFormInstance}
              <p class="help">Enter a short name like mainpc; it will be saved as {deviceDnsPreview || `mainpc.${deviceFormInstance.dns.zone}`}.</p>
            {/if}
            <label class="checkbox"><input type="checkbox" bind:checked={deviceForm.create_dns_record} /> Create a managed DNS A record</label>
          {/if}
          {#if deviceFormInstance?.backend === "wireguard"}
            <label class="checkbox"><input type="checkbox" bind:checked={deviceForm.preshared_key} /> Generate a unique preshared key (recommended)</label>
          {:else if deviceFormInstance?.backend === "amnezia_wg"}
            <p class="help">AWG2 always generates a unique mandatory preshared key for this device.</p>
          {:else if deviceFormInstance?.backend === "openvpn" || deviceFormInstance?.backend === "ikev2"}
            <p class="help">The private key is generated locally. The CSR is signed by this instance's remote authority over verified SSH; private key material never leaves the native credential store.</p>
          {:else if deviceFormInstance?.backend === "xray"}
            <p class="help">A unique VLESS UUID and label will be generated. Xray identities do not receive tunnel IP or private DNS records.</p>
          {/if}
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">Generate identity</button></div>
        </form>
      {:else if modal === "dns"}
        <div class="modal-head"><div><p class="eyebrow">PRIVATE ZONE</p><h2>Add DNS record</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveDns(); }}>
          <label>Instance<select bind:value={dnsForm.instance_id} required>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
          <div class="form-grid"><label>Owner name<input bind:value={dnsForm.name} required placeholder="mainpc" /></label><label>Record type<select bind:value={dnsForm.record_type}>{#each recordTypes as type}<option value={type}>{type}</option>{/each}</select></label></div>
          {#if dnsFormInstance}
            <p class="help">Use a short name like mainpc, or a full name ending in .{dnsFormInstance.dns.zone}. Names outside this zone will not resolve here.</p>
          {/if}
          <label>Value<input bind:value={dnsForm.value} required placeholder={dnsForm.record_type === "A" ? "10.64.0.10" : "Record value"} /></label>
          <label>TTL<input type="number" bind:value={dnsForm.ttl} min="30" max="86400" required /></label>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">Validate and save</button></div>
        </form>
      {:else if modal === "hostlist"}
        <div class="modal-head"><div><p class="eyebrow">DNS BLOCKLIST</p><h2>{hostlistForm.id ? "Edit hostlist" : "Add hostlist"}</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveHostlist(); }}>
          <label>Name<input bind:value={hostlistForm.name} required placeholder="Malware hosts" /></label>
          <label>HTTPS URL<input type="url" bind:value={hostlistForm.url} required placeholder="https://example.com/hosts" /></label>
          <label>Coverage <span class="optional">optional</span><input bind:value={hostlistForm.coverage} placeholder="Adware, malware, telemetry" /></label>
          <p class="help">Saved hostlists are fetched over HTTPS while rendering deployments. The app starts with no built-in hostlists.</p>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">{hostlistForm.id ? "Save changes" : "Add hostlist"}</button></div>
        </form>
      {:else if modal === "host-setup" && hostSetupPlan}
        <div class="modal-head"><div><p class="eyebrow">HOST SETUP PREVIEW</p><h2>Prepare Docker prerequisites</h2></div><button onclick={() => (modal = null)}>Close</button></div>
        <p class="help">This preview is bound to the current verified inspection. Apply will re-inspect first and stop if the host state or plan has changed.</p>
        <div class="setup-facts">
          <div><span>Package manager</span><strong>{hostSetupPlan.package_manager?.toUpperCase() || "Not required"}</strong></div>
          <div><span>Authority</span><strong>{inspection?.inspection.effective_user_is_root ? "Root session" : inspection?.inspection.sudo_bootstrap_available ? "Noninteractive sudo" : "Unavailable"}</strong></div>
        </div>
        {#if hostSetupPlan.operations.length}
          <ol class="operations">
            {#each hostSetupPlan.operations as operation}<li>{hostSetupOperationLabel(operation)}</li>{/each}
          </ol>
        {:else}
          <div class="empty small-empty"><h3>No setup changes</h3><p>Docker and Compose v2 are already ready.</p></div>
        {/if}
        {#each hostSetupPlan.warnings as warning}<div class="warning">{warning}</div>{/each}
        <div class="hash">Observed host state <code>{hostSetupPlan.expected_state_hash}</code></div>
        <div class="modal-actions"><button class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" onclick={applyHostSetup} disabled={!hostSetupPlan.operations.length || Boolean(busy)}>Apply host setup</button></div>
      {:else if modal === "plan" && plan}
        <div class="modal-head"><div><p class="eyebrow">DEPLOYMENT PREVIEW</p><h2>Preview remote changes</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <p class="help">This preview shows what Apply will change on the verified SSH host. Nothing is changed until you apply it.</p>
        <DeploymentImpactPanel preview={plan} />
        {#if plan.operations.length}
          <ol class="operations">{#each plan.operations as operation}<li>{operation.label}{#if operation.technical_detail}<details><summary>Technical detail</summary><code>{operation.technical_detail}</code></details>{/if}</li>{/each}</ol>
        {:else}<div class="empty small-empty"><h3>No changes</h3><p>Remote hashes match desired state.</p></div>{/if}
        {#each plan.warnings as warning}<div class="warning">{warning}</div>{/each}
        <div class="hash">Desired state <code>{plan.desired_state_hash}</code></div>
        <div class="modal-actions"><button class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" onclick={applyPlan} disabled={!plan.operations.length}>Apply these changes</button></div>
      {:else if modal === "settings" && settingsForm && settingsDetail}
        {@const SettingsBackendForm = backendForms[settingsForm.backend]}
        {@const settingsDescriptor = backendOption(settingsForm.backend)}
        <div class="modal-head"><div><p class="eyebrow">LOCAL DESIRED STATE</p><h2>Edit {settingsDetail.summary.instance.display_name}</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); previewSettingsUpdate(); }}>
          <div class="form-grid equal"><label>Backend<input value={settingsDescriptor?.display_name ?? settingsForm.backend} readonly /></label><label>Host<input value={settingsDetail.host_display_name} readonly /></label></div>
          <label>Display name<input bind:value={settingsForm.display_name} required /></label>
          <div class="form-grid"><label>Public endpoint<input bind:value={settingsForm.endpoint_host} required /></label><label>Listener port<input type="number" bind:value={settingsForm.endpoint_port} min="1" max="65535" required /></label></div>
          {#if settingsDescriptor?.presentation.client_addresses === "allocated"}<div class="form-grid equal"><label>Private IPv4 subnet<input bind:value={settingsForm.ipv4_subnet} required /></label><label>DNS zone<input bind:value={settingsForm.dns_zone} required /></label></div><label>Routing<select bind:value={settingsForm.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel</option></select></label>{/if}
          <SettingsBackendForm form={settingsForm} />
          {#if settingsPreview}
            <div class:critical={settingsPreview.impact === "reinstall"} class="impact-panel"><div class="impact-title"><span>Expected impact</span><strong>{settingsPreview.impact.replaceAll("_", " ")}</strong></div><p>{settingsPreview.server_identity_effect}</p><p>{settingsPreview.client_effect}</p>{#each settingsPreview.warnings as warning}<div class="warning">{warning}</div>{/each}</div>
            {#if settingsPreview.impact !== "no_changes" && settingsPreview.impact !== "live_reload"}<label class="checkbox critical-text"><input type="checkbox" bind:checked={settingsImpactAcknowledged} /> I reviewed and acknowledge this disruptive deployment impact.</label>{/if}
          {/if}
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button type="submit" class="secondary">Preview impact</button><button type="button" class="primary" onclick={saveSettingsUpdate} disabled={!settingsPreview || (settingsPreview.impact !== "no_changes" && settingsPreview.impact !== "live_reload" && !settingsImpactAcknowledged)}>Save desired settings</button></div>
        </form>
      {:else if modal === "restore" && restorePreview}
        <div class="modal-head"><div><p class="eyebrow">RESTORE PREVIEW</p><h2>Restore {restorePreview.backup_name}</h2></div><button onclick={() => { modal = null; restorePreview = null; }}>×</button></div>
        <div class="warning">{restorePreview.identity_impact}</div>
        <div class="setup-facts">
          <div><span>Affected clients</span><strong>{restorePreview.affected_clients}</strong></div>
          <div><span>Safety backup</span><strong>{restorePreview.creates_safety_backup ? "Created before restore" : "Not available"}</strong></div>
        </div>
        <p class="help">The selected backup name is validated exactly. Health is checked after restore; a failed target automatically recovers from the new pre-restore snapshot.</p>
        <div class="modal-actions"><button class="secondary" onclick={() => { modal = null; restorePreview = null; }}>Cancel</button><button class="primary danger-action" onclick={applyBackupRestore}>Restore this backup</button></div>
      {:else if modal === "qr"}
        <div class="modal-head"><div><p class="eyebrow">PRIVATE CONFIGURATION</p><h2>{selectedInstance ? backendDisplayName(selectedInstance.backend) : "Client"} QR code</h2></div><button onclick={() => { modal = null; qrSvg = ""; }}>×</button></div>
        <div class="qr">{@html qrSvg}</div>
        <p class="help centered">This SVG exists only in the current desktop view. Close it when the device has imported the configuration.</p>
      {/if}
    </div>
  </div>
{/if}
