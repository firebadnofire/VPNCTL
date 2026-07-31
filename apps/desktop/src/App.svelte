<script lang="ts">
  import { open, save, confirm } from "@tauri-apps/plugin-dialog";
  import { onMount } from "svelte";
  import { call, errorText } from "./lib/api";
  import type {
    AppError,
    AppInfo,
    BackendOption,
    BackendSettings,
    BackupInfo,
    DeploymentPlan,
    DeploymentProgress,
    DeploymentResult,
    Device,
    DnsHostlist,
    DnsRecord,
    DnsRecordType,
    DockerHost,
    HostInspection,
    HostKeyProbe,
    HostProvisioningOperation,
    HostProvisioningPlan,
    InstanceHealth,
    UpdateDeviceInput,
    VpnBackendKind,
    VpnInstance,
  } from "./lib/types";

  type Section = "Hosts" | "Instances" | "Devices" | "DNS" | "Backups" | "Logs";
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
    | "qr"
    | null;

  const sections: Section[] = ["Hosts", "Instances", "Devices", "DNS", "Backups", "Logs"];
  const dnsPanels: DnsPanel[] = ["Records", "Hostlists"];
  const recordTypes: DnsRecordType[] = ["A", "AAAA", "CNAME", "TXT", "SRV"];
  const healthCheckLabels: Array<[keyof InstanceHealth, string]> = [
    ["compose_project_exists", "Compose project exists"],
    ["gateway_running", "Gateway container running"],
    ["backend_ready", "VPN backend is ready"],
    ["listeners_ready", "Required listeners are published"],
    ["client_state_matches", "Client identities match desired state"],
  ];

  interface InstanceForm {
    display_name: string;
    host_id: string;
    backend: VpnBackendKind;
    endpoint_host: string;
    endpoint_port: number;
    ipv4_subnet: string;
    dns_zone: string;
    routing_mode: "full_tunnel" | "split_tunnel";
    wireguard_userspace_fallback: boolean;
    awg_jc: number;
    awg_jmin: number;
    awg_jmax: number;
    awg_s1: number;
    awg_s2: number;
    awg_s3: number;
    awg_s4: number;
    awg_h1_min: number;
    awg_h1_max: number;
    awg_h2_min: number;
    awg_h2_max: number;
    awg_h3_min: number;
    awg_h3_max: number;
    awg_h4_min: number;
    awg_h4_max: number;
    openvpn_transport: "tcp" | "udp";
    openvpn_cipher: "aes256-gcm" | "chacha20-poly1305";
    openvpn_tls_protection: "tls_crypt" | "none";
    openvpn_certificate_lifetime_days: number;
    ikev2_server_identity: string;
    ikev2_certificate_lifetime_days: number;
    xray_security: "reality";
    xray_transport: "tcp" | "xhttp" | "mkcp";
    xray_server_name: string;
    xray_fingerprint: string;
    xray_xhttp_path: string;
  }

  function newInstanceForm(hostId = "", endpointHost = ""): InstanceForm {
    return {
      display_name: "",
      host_id: hostId,
      backend: "wireguard",
      endpoint_host: endpointHost,
      endpoint_port: 51820,
      ipv4_subnet: "10.64.0.0/24",
      dns_zone: "internal",
      routing_mode: "split_tunnel",
      wireguard_userspace_fallback: false,
      awg_jc: 5,
      awg_jmin: 10,
      awg_jmax: 50,
      awg_s1: 64,
      awg_s2: 96,
      awg_s3: 32,
      awg_s4: 8,
      awg_h1_min: 5,
      awg_h1_max: 999,
      awg_h2_min: 1000,
      awg_h2_max: 1999,
      awg_h3_min: 2000,
      awg_h3_max: 2999,
      awg_h4_min: 3000,
      awg_h4_max: 3999,
      openvpn_transport: "udp",
      openvpn_cipher: "aes256-gcm",
      openvpn_tls_protection: "tls_crypt",
      openvpn_certificate_lifetime_days: 825,
      ikev2_server_identity: endpointHost,
      ikev2_certificate_lifetime_days: 825,
      xray_security: "reality",
      xray_transport: "tcp",
      xray_server_name: "www.cloudflare.com",
      xray_fingerprint: "chrome",
      xray_xhttp_path: "/",
    };
  }
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
  let backendOptions: BackendOption[] = [];
  let devices: Device[] = [];
  let records: DnsRecord[] = [];
  let hostlists: DnsHostlist[] = [];
  let backups: BackupInfo[] = [];
  let logs: DeploymentProgress[] = [];
  let selectedHostId = "";
  let selectedInstanceId = "";
  let selectedDeviceId = "";
  let busy = "";
  let notice = "";
  let noticeHealth: InstanceHealth | null = null;
  let error: AppError | null = null;
  let inspection: HostInspection | null = null;
  let hostSetupPlan: HostProvisioningPlan | null = null;
  let probe: HostKeyProbe | null = null;
  let defaultSshUsername = "";
  let fingerprintConfirmation = "";
  let replaceChangedKey = false;
  let plan: DeploymentPlan | null = null;
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
  $: selectedHost = hosts.find((item) => item.id === selectedHostId);
  $: instanceFormBackend = backendOptions.find((item) => item.kind === instanceForm.backend);
  $: instanceDevices = devices.filter((item) => item.instance_id === selectedInstanceId);
  $: instanceRecords = records.filter((item) => item.instance_id === selectedInstanceId);
  $: dnsFormInstance = instances.find((item) => item.id === dnsForm.instance_id);
  $: deviceFormInstance = instances.find((item) => item.id === deviceForm.instance_id);
  $: deviceFormBackend = backendOptions.find((item) => item.kind === deviceFormInstance?.backend);
  $: selectedBackend = backendOptions.find((item) => item.kind === selectedInstance?.backend);
  $: deviceDnsPreview = deviceDnsNamePreview(deviceForm.dns_name, deviceFormInstance?.dns.zone || "");

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
    const [nextHosts, nextInstances, nextBackends, nextHostlists, nextLogs] = await Promise.all([
      call<DockerHost[]>("list_hosts"),
      call<VpnInstance[]>("list_instances", { hostId: null }),
      call<BackendOption[]>("backend_options"),
      call<DnsHostlist[]>("list_dns_hostlists"),
      call<DeploymentProgress[]>("logs", { instanceId: null }),
    ]);
    hosts = nextHosts;
    instances = nextInstances;
    backendOptions = nextBackends;
    hostlists = nextHostlists;
    logs = nextLogs;
    if (selectedHostId && !hosts.some((host) => host.id === selectedHostId)) selectedHostId = "";
    if (selectedInstanceId && !instances.some((instance) => instance.id === selectedInstanceId)) selectedInstanceId = "";
    if (!selectedHostId && hosts[0]) selectedHostId = hosts[0].id;
    if (!selectedInstanceId && instances[0]) selectedInstanceId = instances[0].id;
    if (selectedInstanceId) await refreshInstanceData();
  }

  async function refreshInstanceData() {
    if (!selectedInstanceId) {
      devices = [];
      records = [];
      backups = [];
      return;
    }
    [devices, records, backups] = await Promise.all([
      call<Device[]>("list_devices", { instanceId: selectedInstanceId }),
      call<DnsRecord[]>("list_dns_records", { instanceId: selectedInstanceId }),
      call<BackupInfo[]>("list_backups", { instanceId: selectedInstanceId }),
    ]);
  }

  async function selectedInstanceChanged(event: Event) {
    selectedInstanceId = (event.currentTarget as HTMLSelectElement).value;
    await refreshInstanceData();
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

  function setNotice(message: string, health: InstanceHealth | null = null) {
    notice = message;
    noticeHealth = health;
  }

  function clearNotice() {
    notice = "";
    noticeHealth = null;
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
      call<HostInspection>("inspect_host", { hostId: host.id }),
    );
    if (result) inspection = result;
  }

  function composeV2Available(value?: string) {
    const major = value?.trim().replace(/^v/, "").split(".")[0];
    return Boolean(major && Number.parseInt(major, 10) >= 2);
  }

  function hostPrerequisitesReady(value: HostInspection) {
    return (
      value.operating_system === "Linux" &&
      value.docker_installed &&
      value.docker_accessible &&
      composeV2Available(value.compose_version)
    );
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
      call<HostInspection>("apply_host_provisioning", {
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

  function backendSettingsFromForm(): BackendSettings {
    switch (instanceForm.backend) {
      case "wireguard":
        return {
          backend: "wireguard",
          settings: { userspace_fallback: instanceForm.wireguard_userspace_fallback },
        };
      case "amnezia_wg":
        return {
          backend: "amnezia_wg",
          settings: {
            generation: "awg2",
            jc: instanceForm.awg_jc,
            jmin: instanceForm.awg_jmin,
            jmax: instanceForm.awg_jmax,
            s1: instanceForm.awg_s1,
            s2: instanceForm.awg_s2,
            s3: instanceForm.awg_s3,
            s4: instanceForm.awg_s4,
            h1: { min: instanceForm.awg_h1_min, max: instanceForm.awg_h1_max },
            h2: { min: instanceForm.awg_h2_min, max: instanceForm.awg_h2_max },
            h3: { min: instanceForm.awg_h3_min, max: instanceForm.awg_h3_max },
            h4: { min: instanceForm.awg_h4_min, max: instanceForm.awg_h4_max },
          },
        };
      case "openvpn":
        return {
          backend: "openvpn",
          settings: {
            transport: instanceForm.openvpn_transport,
            cipher: instanceForm.openvpn_cipher,
            tls_protection: instanceForm.openvpn_tls_protection,
            certificate_lifetime_days: instanceForm.openvpn_certificate_lifetime_days,
          },
        };
      case "ikev2":
        return {
          backend: "ikev2",
          settings: {
            server_identity:
              instanceForm.ikev2_server_identity.trim() || instanceForm.endpoint_host.trim(),
            certificate_lifetime_days: instanceForm.ikev2_certificate_lifetime_days,
          },
        };
      case "xray":
        return {
          backend: "xray",
          settings: {
            security: instanceForm.xray_security,
            transport: instanceForm.xray_transport,
            server_name: instanceForm.xray_server_name,
            fingerprint: instanceForm.xray_fingerprint,
            xhttp_path: instanceForm.xray_xhttp_path,
            reality_public_key: null,
            reality_short_id: null,
          },
        };
    }
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
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedInstanceId = created.id;
    await refresh();
    notice = "Instance created locally. Review its deployment plan to apply it.";
  }

  async function reviewPlan(instance: VpnInstance) {
    selectedInstanceId = instance.id;
    const result = await task("Calculating deployment plan", () =>
      call<DeploymentPlan>("plan_instance", { instanceId: instance.id }),
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
      call<DeploymentResult>("apply_instance", {
        instanceId: pendingPlan.instance_id,
        expectedStateHash: pendingPlan.desired_state_hash,
      }),
    );
    if (!result) return;
    setNotice(`Deployment ${result.status}. ${healthSummary(result.health)}`, result.health);
    await refresh();
  }

  async function instanceAction(command: "start_instance" | "stop_instance" | "health", instance: VpnInstance) {
    const result = await task(command.replace("_", " "), () =>
      call<InstanceHealth>(command, { instanceId: instance.id }),
    );
    if (result) {
      setNotice(healthSummary(result), result);
    }
  }

  function healthSummary(health: InstanceHealth) {
    const checks = healthChecks(health);
    const healthy = checks.filter((check) => check.passing).length;
    return `${healthy}/${checks.length} required health checks passing.`;
  }

  function healthChecks(health: InstanceHealth) {
    const checks = healthCheckLabels.map(([key, label]) => ({
      label,
      passing: Boolean(health[key]),
    }));
    if (health.dns_required) {
      checks.push(
        { label: "DNS container running", passing: health.dns_running },
        { label: "Private DNS resolves", passing: health.private_dns_resolves },
        { label: "Public DNS resolves", passing: health.public_dns_resolves },
      );
    }
    return checks;
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
    const created = await task("Generating device identity", () =>
      call<Device>("create_device", {
        input: {
          ...deviceForm,
          user_id: null,
          dns_name: deviceForm.dns_name || null,
        },
      }),
    );
    if (!created) return;
    modal = null;
    selectedInstanceId = created.instance_id;
    await refreshInstanceData();
    notice =
      created.backend === "xray"
        ? "Xray client UUID created locally. Review and deploy the instance before export."
        : created.backend === "openvpn" || created.backend === "ikev2"
          ? "Client key generated locally and certificate issued through the verified SSH authority."
          : "Device keys were generated locally and saved in the native credential store.";
  }

  async function toggleDevice(device: Device) {
    const input: UpdateDeviceInput = {
      id: device.id,
      user_id: device.user_id ?? null,
      display_name: device.display_name,
      dns_name: device.dns_name ?? null,
      enabled: !device.enabled,
    };
    const result = await task("Updating device", () =>
      call<Device>("update_device", { input }),
    );
    if (result) await refreshInstanceData();
  }

  async function replaceDeviceIdentity(device: Device) {
    const accepted = await confirm(
      `Replace the cryptographic identity for "${device.display_name}"? Its previous configuration will stop working after deployment.`,
      { title: "Replace device identity", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Replacing device identity", () =>
      call<Device>("replace_device_identity", { deviceId: device.id }),
    );
    if (!result) return;
    await refreshInstanceData();
    notice = "A new client identity was created in the native credential store. Review and deploy before exporting it.";
  }

  async function removeDevice(device: Device) {
    const accepted = await confirm(
      `Remove "${device.display_name}" and its managed DNS record? Its address remains reserved by retained deployment snapshots.`,
      { title: "Remove device", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Removing device", () =>
      call<void>("delete_device", { deviceId: device.id }),
    );
    if (result === undefined && error) return;
    await refreshInstanceData();
    notice =
      device.backend === "openvpn" || device.backend === "ikev2"
        ? "Client certificate revoked and device removed."
        : "Device removed locally. Review and deploy the instance to revoke its identity.";
  }

  async function exportDevice(device: Device) {
    const exportInfo =
      device.backend === "openvpn"
        ? { suffix: "ovpn", filterExtension: "ovpn", name: "OpenVPN profile" }
        : device.backend === "ikev2"
          ? { suffix: "p12", filterExtension: "p12", name: "Protected PKCS#12 credential" }
          : device.backend === "xray"
            ? { suffix: "vless.txt", filterExtension: "txt", name: "VLESS URI" }
            : { suffix: "conf", filterExtension: "conf", name: `${backendDisplayName(device.backend)} configuration` };
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

  async function showQr(device: Device) {
    selectedDeviceId = device.id;
    const result = await task("Generating QR code", () =>
      call<string>("client_qr_svg", { deviceId: device.id }),
    );
    if (!result) return;
    qrSvg = result;
    modal = "qr";
  }

  function backendDisplayName(kind: VpnBackendKind) {
    return backendOptions.find((option) => option.kind === kind)?.display_name ?? kind;
  }

  function backendBadge(kind: VpnBackendKind) {
    return {
      wireguard: "WG",
      amnezia_wg: "AWG",
      openvpn: "OVPN",
      ikev2: "IKE",
      xray: "XRAY",
    }[kind];
  }

  function deviceIdentitySummary(device: Device) {
    switch (device.public_identity.backend) {
      case "wireguard":
        return `WireGuard public key ${device.public_identity.identity.public_key}`;
      case "amnezia_wg":
        return `AWG2 public key ${device.public_identity.identity.public_key}`;
      case "openvpn":
        return `OpenVPN certificate ${device.public_identity.identity.common_name}`;
      case "ikev2":
        return `IKEv2 identity ${device.public_identity.identity.identity}`;
      case "xray":
        return `VLESS client ${device.public_identity.identity.email}`;
    }
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
    await refreshInstanceData();
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
    await refreshInstanceData();
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
    await refreshInstanceData();
    notice = `Backup ${result.name} created.`;
  }

  async function backupInstance(instance: VpnInstance) {
    selectedInstanceId = instance.id;
    await makeBackup(instance.id);
  }

  async function refreshRemoteCredentials() {
    if (!selectedInstanceId) return;
    const result = await task("Refreshing remote credential store", () =>
      call<InstanceHealth>("refresh_remote_credentials", { instanceId: selectedInstanceId }),
    );
    if (!result) return;
    setNotice(`Credential store refreshed. ${healthSummary(result)}`, result);
  }

  async function refreshRemoteDnsStore() {
    if (!selectedInstanceId) return;
    const result = await task("Refreshing remote DNS store", () =>
      call<InstanceHealth>("refresh_remote_dns_store", { instanceId: selectedInstanceId }),
    );
    if (!result) return;
    setNotice(`DNS store refreshed. ${healthSummary(result)}`, result);
  }

  async function rollbackBackup(backup: BackupInfo) {
    if (!backup.deployment_id) return;
    const accepted = await confirm(
      `Re-render and apply deployment ${backup.deployment_id} with a fresh DNS serial?`,
      { title: "Rollback instance", kind: "warning" },
    );
    if (!accepted) return;
    const result = await task("Rolling back deployment", () =>
      call<{ status: string }>("rollback", { deploymentId: backup.deployment_id }),
    );
    if (!result) return;
    await refresh();
    notice = `Rollback ${result.status}.`;
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
        <button class:active={active === section} onclick={() => (active = section)}>
          <span class="nav-dot"></span>{section}
        </button>
      {/each}
    </nav>
  </aside>

  <main>
    <header>
      <div><p class="eyebrow">CONTROL PLANE</p><h1>{active}</h1></div>
      <div class="header-actions">
        {#if active === "Hosts"}<button class="primary" onclick={openHost}>Add host</button>{/if}
        {#if active === "Instances"}<button class="primary" onclick={openInstance} disabled={!hosts.length}>Create instance</button>{/if}
        {#if active === "Devices"}
          {#if selectedBackend?.capabilities.quick_credential_refresh}
            <button class="secondary" onclick={refreshRemoteCredentials} disabled={!selectedInstanceId}>Refresh identities</button>
          {/if}
          <button class="primary" onclick={openDevice} disabled={!instances.length}>Add device</button>
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

    {#if busy}<div class="progress"><span></span>{busy}…</div>{/if}
    {#if notice}
      <div class="notice" role="status">
        <div class="notice-body">
          <span>{notice}</span>
          {#if noticeHealth}
            <details class="check-log">
              <summary>Checks</summary>
              <div class="check-log-list">
                {#each healthChecks(noticeHealth) as check}
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
          <div class="panel-head"><h3>{selectedHost.display_name} inspection</h3><span>{inspection.operating_system} · {inspection.architecture}</span></div>
          <div class="checks">
            <div class:pass={inspection.docker_installed}><b>Docker Engine</b><span>{inspection.docker_version || (inspection.docker_installed ? "Installed; daemon unavailable" : "Not found")}</span></div>
            <div class:pass={inspection.docker_accessible}><b>Direct Docker access</b><span>{inspection.docker_accessible ? "Available" : inspection.docker_privileged_accessible ? "Privilege works; user access blocked" : "Daemon unavailable"}</span></div>
            <div class:pass={composeV2Available(inspection.compose_version)}><b>Compose v2</b><span>{inspection.compose_version || "Not found"}</span></div>
            <div class:pass={Boolean(inspection.package_manager) || hostPrerequisitesReady(inspection)}><b>Package manager</b><span>{inspection.package_manager?.toUpperCase() || (hostPrerequisitesReady(inspection) ? "Not needed" : "Unsupported")}</span></div>
            <div class:pass={inspection.wireguard_kernel_available}><b>WireGuard</b><span>{inspection.wireguard_kernel_available ? "Available" : "Userspace fallback via container"}</span></div>
            <div class:pass={inspection.effective_user_is_root || inspection.sudo_bootstrap_available}><b>Setup authority</b><span>{inspection.effective_user_is_root ? "Root session" : inspection.sudo_bootstrap_available ? "sudo -n available" : "Manual setup required"}</span></div>
            <div class:pass={inspection.application_root_writable || inspection.sudo_bootstrap_available}><b>/opt bootstrap</b><span>{inspection.application_root_writable ? "Writable" : inspection.sudo_bootstrap_available ? "sudo -n available" : "Blocked"}</span></div>
          </div>
          {#if inspection.warnings.length}
            <div class="warning-list">
              {#each inspection.warnings as warning}<div class="warning">{warning}</div>{/each}
            </div>
          {/if}
          {#if !hostPrerequisitesReady(inspection)}
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
      <section class="panel">
        {#if instances.length}
          <div class="rows instance-rows">
            {#each instances as instance}
              <article class:selected={instance.id === selectedInstanceId}>
                <div class="status-icon">{backendBadge(instance.backend)}</div>
                <button class="row-main row-select" onclick={() => { selectedInstanceId = instance.id; refreshInstanceData(); }}>
                  <strong>{instance.display_name}</strong>
                  <small>{backendDisplayName(instance.backend)} · {instance.endpoint.host}:{instance.endpoint.port}{instance.backend === "xray" ? "" : ` · ${instance.network.ipv4_subnet} · ${instance.dns.zone}`}</small>
                </button>
                <button class="secondary" onclick={() => instanceAction("start_instance", instance)}>Start</button>
                <button class="secondary" onclick={() => instanceAction("stop_instance", instance)}>Stop</button>
                <button class="secondary" onclick={() => instanceAction("health", instance)}>Health</button>
                <button class="secondary" title="Preview deployment changes before applying them" onclick={() => reviewPlan(instance)}>Preview deploy</button>
                <button class="secondary" title="Back up this instance, including its credential and DNS stores" onclick={() => backupInstance(instance)}>Backup</button>
                <button class="menu danger" title="Delete" onclick={() => removeInstance(instance)}>Delete</button>
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No VPN instances</h3><p>Create a WireGuard, AWG2, OpenVPN, IKEv2, or Xray appliance after approving a Docker host.</p></div>
        {/if}
      </section>
    {:else if active === "Devices"}
      <div class="toolbar">
        <label>Instance<select value={selectedInstanceId} onchange={selectedInstanceChanged}><option value="">Select…</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Device identities</h3><span>{instanceDevices.length} for selected instance</span></div>
        {#if instanceDevices.length}
          <div class="rows">
            {#each instanceDevices as device}
              <article>
                <div class:disabled={!device.enabled} class="status-icon">{device.enabled ? "●" : "○"}</div>
                <div class="row-main"><strong>{device.display_name}</strong><small>{device.ipv4_address ? `${device.ipv4_address} · ` : ""}{deviceIdentitySummary(device)}</small></div>
                {#if backendOptions.find((option) => option.kind === device.backend)?.capabilities.certificate_authority && !device.enabled}
                  <span class="revoked">Revoked</span>
                {:else}
                  <button class="secondary" onclick={() => toggleDevice(device)}>{backendOptions.find((option) => option.kind === device.backend)?.capabilities.certificate_authority ? "Revoke" : device.enabled ? "Disable" : "Enable"}</button>
                {/if}
                <button class="secondary" onclick={() => replaceDeviceIdentity(device)}>Replace identity</button>
                {#if backendOptions.find((option) => option.kind === device.backend)?.capabilities.qr_export}
                  <button class="secondary" onclick={() => showQr(device)}>QR</button>
                {/if}
                <button class="primary small" onclick={() => exportDevice(device)}>Export</button>
                <button class="menu danger" onclick={() => removeDevice(device)}>Remove</button>
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No devices for this instance</h3><p>Client identities are generated in Rust; private material remains in the native credential store.</p></div>
        {/if}
      </section>
    {:else if active === "DNS"}
      <div class="toolbar">
        <label>Instance<select value={selectedInstanceId} onchange={selectedInstanceChanged}><option value="">Select…</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
        {#if selectedInstance}
          <span>{selectedBackend?.capabilities.managed_dns ? `Zone ${selectedInstance.dns.zone} - SOA ${selectedInstance.dns.soa_serial}` : `${backendDisplayName(selectedInstance.backend)} does not provide a routed private DNS zone`}</span>
        {/if}
      </div>
      <div class="tabs" role="tablist" aria-label="DNS panels">
        {#each dnsPanels as panel}
          <button type="button" role="tab" aria-selected={activeDnsPanel === panel} class:active={activeDnsPanel === panel} onclick={() => (activeDnsPanel = panel)}>{panel}</button>
        {/each}
      </div>
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
    {:else if active === "Backups"}
      <div class="toolbar">
        <label>Instance<select value={selectedInstanceId} onchange={selectedInstanceChanged}><option value="">Select…</option>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
      </div>
      <section class="panel">
        <div class="panel-head"><h3>Deployment backups</h3><span>10 retained per instance</span></div>
        {#if backups.length}
          <div class="rows">
            {#each backups as backup}
              <article>
                <div class="status-icon">↶</div>
                <div class="row-main"><strong>{backup.name}</strong><small>{new Date(backup.created_at).toLocaleString()}</small></div>
                {#if backup.deployment_id}<button class="secondary" onclick={() => rollbackBackup(backup)}>Rollback snapshot</button>{/if}
              </article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No backups yet</h3><p>A timestamped backup is created before every mutating deployment.</p></div>
        {/if}
      </section>
    {:else}
      <section class="panel">
        <div class="panel-head"><h3>Operational history</h3><span>Secrets redacted · {logs.length} events</span></div>
        {#if logs.length}
          <div class="timeline">
            {#each logs as event}
              <article><span></span><div><strong>{event.phase}</strong><p>{event.message}</p><small>{new Date(event.timestamp).toLocaleString()} · {event.deployment_id}</small>{#if event.technical_detail}<details><summary>Technical</summary><pre>{event.technical_detail}</pre></details>{/if}</div></article>
            {/each}
          </div>
        {:else}
          <div class="empty"><h3>No deployment events</h3><p>Progress, health checks, failures, and rollback outcomes will appear here.</p></div>
        {/if}
      </section>
    {/if}

    <footer>{appInfo.name} {appInfo.version} · Local-first management over verified SSH</footer>
  </main>
</div>

{#if modal}
  <div class="modal-backdrop" role="presentation" onclick={(event) => { if (event.target === event.currentTarget) modal = null; }}>
    <section class="modal" role="dialog" aria-modal="true">
      {#if modal === "host"}
        <div class="modal-head"><div><p class="eyebrow">FIRST RUN</p><h2>Add SSH host</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveHost(); }}>
          <label>Display name<input bind:value={hostForm.display_name} required placeholder="Debian lab" /></label>
          <div class="form-grid"><label>Hostname or IP<input bind:value={hostForm.hostname} required placeholder="192.168.86.55" /></label><label>SSH port<input type="number" bind:value={hostForm.port} min="1" max="65535" required /></label></div>
          <label>SSH username<input bind:value={hostForm.username} required placeholder={defaultSshUsername || "username"} /></label>
          <label>SSH private key<div class="path-input"><input bind:value={hostForm.private_key_path} required placeholder="/Users/you/.ssh/id_ed25519 or key.ppk" /><button type="button" class="secondary" onclick={chooseKey}>Choose</button></div></label>
          <label>Key passphrase <span class="optional">optional · saved to Keychain</span><input type="password" bind:value={hostForm.passphrase} autocomplete="new-password" /></label>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" disabled={Boolean(busy)}>Save host</button></div>
        </form>
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
        <div class="modal-head"><div><p class="eyebrow">DESIRED STATE</p><h2>Create VPN instance</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveInstance(); }}>
          <label>Display name<input bind:value={instanceForm.display_name} required placeholder="Home VPN" /></label>
          <label>Docker host<select bind:value={instanceForm.host_id} required>{#each hosts as host}<option value={host.id}>{host.display_name}</option>{/each}</select></label>
          <label>Protocol
            <select value={instanceForm.backend} onchange={(event) => backendChanged((event.currentTarget as HTMLSelectElement).value as VpnBackendKind)}>
              {#each backendOptions as option}<option value={option.kind}>{option.display_name}</option>{/each}
            </select>
          </label>
          <div class="form-grid">
            <label>Public endpoint<input bind:value={instanceForm.endpoint_host} required placeholder="vpn.example.com" /></label>
            <label>{instanceForm.backend === "openvpn" ? instanceForm.openvpn_transport.toUpperCase() : instanceForm.backend === "xray" && instanceForm.xray_transport === "mkcp" ? "UDP" : instanceForm.backend === "xray" ? "TCP" : "UDP"} port
              <input type="number" bind:value={instanceForm.endpoint_port} min="1" max="65535" disabled={instanceForm.backend === "ikev2"} required />
            </label>
          </div>
          {#if instanceFormBackend?.capabilities.allocated_tunnel_addresses}
            <div class="form-grid"><label>Private IPv4 subnet<input bind:value={instanceForm.ipv4_subnet} required /></label><label>Private DNS zone<input bind:value={instanceForm.dns_zone} required /></label></div>
            <label>Default routing<select bind:value={instanceForm.routing_mode}><option value="split_tunnel">Split tunnel</option><option value="full_tunnel">Full tunnel (IPv4)</option></select></label>
          {/if}

          {#if instanceForm.backend === "wireguard"}
            <label class="checkbox"><input type="checkbox" bind:checked={instanceForm.wireguard_userspace_fallback} /> Allow userspace fallback when the host kernel module is unavailable</label>
          {:else if instanceForm.backend === "amnezia_wg"}
            <details class="advanced-settings">
              <summary>AWG2 obfuscation settings</summary>
              <p class="help">Validated AWG2 defaults are prefilled. Change these only when every client will receive the matching profile.</p>
              <div class="parameter-grid">
                <label>Jc<input type="number" bind:value={instanceForm.awg_jc} min="0" max="128" required /></label>
                <label>Jmin<input type="number" bind:value={instanceForm.awg_jmin} min="0" max="1280" required /></label>
                <label>Jmax<input type="number" bind:value={instanceForm.awg_jmax} min="0" max="1280" required /></label>
                <label>S1<input type="number" bind:value={instanceForm.awg_s1} min="0" max="65535" required /></label>
                <label>S2<input type="number" bind:value={instanceForm.awg_s2} min="0" max="65535" required /></label>
                <label>S3<input type="number" bind:value={instanceForm.awg_s3} min="0" max="65535" required /></label>
                <label>S4<input type="number" bind:value={instanceForm.awg_s4} min="0" max="65535" required /></label>
              </div>
              <div class="range-grid">
                <span>Magic header</span><span>Minimum</span><span>Maximum</span>
                <b>H1</b><input aria-label="H1 minimum" type="number" bind:value={instanceForm.awg_h1_min} required /><input aria-label="H1 maximum" type="number" bind:value={instanceForm.awg_h1_max} required />
                <b>H2</b><input aria-label="H2 minimum" type="number" bind:value={instanceForm.awg_h2_min} required /><input aria-label="H2 maximum" type="number" bind:value={instanceForm.awg_h2_max} required />
                <b>H3</b><input aria-label="H3 minimum" type="number" bind:value={instanceForm.awg_h3_min} required /><input aria-label="H3 maximum" type="number" bind:value={instanceForm.awg_h3_max} required />
                <b>H4</b><input aria-label="H4 minimum" type="number" bind:value={instanceForm.awg_h4_min} required /><input aria-label="H4 maximum" type="number" bind:value={instanceForm.awg_h4_max} required />
              </div>
            </details>
          {:else if instanceForm.backend === "openvpn"}
            <div class="form-grid equal">
              <label>Transport<select bind:value={instanceForm.openvpn_transport}><option value="udp">UDP</option><option value="tcp">TCP</option></select></label>
              <label>Data cipher<select bind:value={instanceForm.openvpn_cipher}><option value="aes256-gcm">AES-256-GCM</option><option value="chacha20-poly1305">ChaCha20-Poly1305</option></select></label>
            </div>
            <div class="form-grid equal">
              <label>TLS control protection<select bind:value={instanceForm.openvpn_tls_protection}><option value="tls_crypt">tls-crypt</option><option value="none">None</option></select></label>
              <label>Client certificate lifetime (days)<input type="number" bind:value={instanceForm.openvpn_certificate_lifetime_days} min="1" max="825" required /></label>
            </div>
          {:else if instanceForm.backend === "ikev2"}
            <div class="form-grid equal">
              <label>Server certificate identity<input bind:value={instanceForm.ikev2_server_identity} required placeholder={instanceForm.endpoint_host || "vpn.example.com"} /></label>
              <label>Client certificate lifetime (days)<input type="number" bind:value={instanceForm.ikev2_certificate_lifetime_days} min="1" max="825" required /></label>
            </div>
            <p class="help">IKEv2 always reserves UDP 500 and 4500. Client exports are password-protected PKCS#12 credentials.</p>
          {:else if instanceForm.backend === "xray"}
            <div class="form-grid equal">
              <label>Security<select bind:value={instanceForm.xray_security}><option value="reality">REALITY</option><option disabled>TLS requires certificate import</option></select></label>
              <label>Transport<select bind:value={instanceForm.xray_transport}><option value="tcp">TCP</option><option value="xhttp">XHTTP</option><option disabled>mKCP requires TLS</option></select></label>
            </div>
            <div class="form-grid equal">
              <label>SNI / camouflage host<input bind:value={instanceForm.xray_server_name} required placeholder="www.example.com" /></label>
              <label>Client fingerprint<select bind:value={instanceForm.xray_fingerprint}><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="safari">Safari</option><option value="edge">Edge</option><option value="randomized">Randomized</option></select></label>
            </div>
            {#if instanceForm.xray_transport === "xhttp"}<label>XHTTP path<input bind:value={instanceForm.xray_xhttp_path} required placeholder="/" /></label>{/if}
            <p class="help">REALITY private material is generated remotely during verified deployment. Only its public key and short ID are retained in desired state.</p>
          {/if}

          <p class="help">{instanceForm.backend === "xray" ? "Xray creates VLESS proxy identities without tunnel addresses or managed private DNS." : "The gateway receives the first usable address. IPv6 is not advertised until an IPv6 tunnel address exists."}</p>
          <div class="modal-actions"><button type="button" class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary">Create instance</button></div>
        </form>
      {:else if modal === "device"}
        <div class="modal-head"><div><p class="eyebrow">CLIENT IDENTITY</p><h2>Add device</h2></div><button onclick={() => (modal = null)}>×</button></div>
        <form onsubmit={(event) => { event.preventDefault(); saveDevice(); }}>
          <label>Instance<select bind:value={deviceForm.instance_id} required>{#each instances as instance}<option value={instance.id}>{instance.display_name}</option>{/each}</select></label>
          <label>Device name<input bind:value={deviceForm.display_name} required placeholder="Main PC" /></label>
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
        <div class="modal-head"><div><p class="eyebrow">DNS BLOCKLIST</p><h2>{hostlistForm.id ? "Edit hostlist" : "Add hostlist"}</h2></div><button onclick={() => (modal = null)}>Ã—</button></div>
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
          <div><span>Authority</span><strong>{inspection?.effective_user_is_root ? "Root session" : inspection?.sudo_bootstrap_available ? "Noninteractive sudo" : "Unavailable"}</strong></div>
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
        {#if plan.operations.length}
          <ol class="operations">{#each plan.operations as operation}<li><code>{JSON.stringify(operation)}</code></li>{/each}</ol>
        {:else}<div class="empty small-empty"><h3>No changes</h3><p>Remote hashes match desired state.</p></div>{/if}
        {#each plan.warnings as warning}<div class="warning">{warning}</div>{/each}
        <div class="hash">Desired state <code>{plan.desired_state_hash}</code></div>
        <div class="modal-actions"><button class="secondary" onclick={() => (modal = null)}>Cancel</button><button class="primary" onclick={applyPlan} disabled={!plan.operations.length}>Apply these changes</button></div>
      {:else if modal === "qr"}
        <div class="modal-head"><div><p class="eyebrow">PRIVATE CONFIGURATION</p><h2>{selectedInstance ? backendDisplayName(selectedInstance.backend) : "Client"} QR code</h2></div><button onclick={() => { modal = null; qrSvg = ""; }}>×</button></div>
        <div class="qr">{@html qrSvg}</div>
        <p class="help centered">This SVG exists only in the current desktop view. Close it when the device has imported the configuration.</p>
      {/if}
    </section>
  </div>
{/if}
