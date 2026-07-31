export type UUID = string;

export interface AppInfo {
  name: string;
  version: string;
  status: string;
  system_username: string;
}

export interface AppError {
  code: string;
  message: string;
  scope?: string;
  remote_state_changed: boolean;
  rollback_succeeded?: boolean;
  remediation?: string;
  technical_detail?: string;
}

export interface DockerHost {
  id: UUID;
  display_name: string;
  ssh: {
    hostname: string;
    port: number;
    username: string;
    private_key_path: string;
    passphrase_ref?: UUID | null;
  };
  created_at: string;
  updated_at: string;
}

export type VpnBackendKind =
  | "wireguard"
  | "amnezia_wg"
  | "openvpn"
  | "ikev2"
  | "xray";

export type BackendSettings =
  | {
      backend: "wireguard";
      settings: { userspace_fallback: boolean };
    }
  | {
      backend: "amnezia_wg";
      settings: {
        generation: "awg2";
        jc: number;
        jmin: number;
        jmax: number;
        s1: number;
        s2: number;
        s3: number;
        s4: number;
        h1: { min: number; max: number };
        h2: { min: number; max: number };
        h3: { min: number; max: number };
        h4: { min: number; max: number };
      };
    }
  | {
      backend: "openvpn";
      settings: {
        transport: "tcp" | "udp";
        cipher: "aes256-gcm" | "chacha20-poly1305";
        tls_protection: "tls_crypt" | "none";
        certificate_lifetime_days: number;
      };
    }
  | {
      backend: "ikev2";
      settings: {
        server_identity: string;
        certificate_lifetime_days: number;
      };
    }
  | {
      backend: "xray";
      settings: {
        security: "tls" | "reality";
        transport: "tcp" | "xhttp" | "mkcp";
        server_name: string;
        fingerprint: string;
        xhttp_path: string;
        reality_public_key?: string | null;
        reality_short_id?: string | null;
      };
    };

export interface BackendCapabilities {
  allocated_tunnel_addresses: boolean;
  managed_dns: boolean;
  quick_credential_refresh: boolean;
  live_identity_updates: boolean;
  qr_export: boolean;
  traffic_statistics: boolean;
  certificate_authority: boolean;
}

export interface BackendOption {
  kind: VpnBackendKind;
  display_name: string;
  default_port: number;
  capabilities: BackendCapabilities;
  presentation: BackendPresentation;
}

export type ClientAction =
  | "enable"
  | "disable"
  | "rotate_identity"
  | "replace_identity"
  | "revoke"
  | "export"
  | "qr_export"
  | "remove"
  | "inspect_statistics";

export type ClientExportFormat =
  | "wire_guard_configuration"
  | "amnezia_wg_configuration"
  | "open_vpn_profile"
  | "protected_pkcs12"
  | "vless_uri";

export type ConfigurationSection = "general" | "network" | "protocol" | "dns" | "advanced";

export type ConfigurationField =
  | "endpoint"
  | "listener_port"
  | "address_pool"
  | "routing_mode"
  | "managed_dns"
  | "persistent_keepalive"
  | "userspace_fallback"
  | "amnezia_obfuscation"
  | "open_vpn_transport"
  | "open_vpn_cipher"
  | "open_vpn_tls_protection"
  | "certificate_lifetime"
  | "ikev2_server_identity"
  | "xray_security"
  | "xray_transport"
  | "xray_server_name"
  | "xray_camouflage_target"
  | "xray_http_path"
  | "xray_tls_material";

export type BackendHostRequirement =
  | "linux"
  | "supported_architecture"
  | "docker_engine"
  | "compose_v2"
  | "docker_access"
  | "tun_device"
  | "wire_guard_kernel_or_userspace";

export interface BackendPresentation {
  short_name: string;
  badge: string;
  description: string;
  routing: "routed_tunnel" | "proxy";
  dns: "managed_private_dns" | "unsupported";
  client_addresses: "allocated" | "none";
  statistics: "backend_supported" | "unavailable";
  listener_model: "configurable" | "fixed_multiple";
  client_identity_name: string;
  client_actions: ClientAction[];
  export_formats: ClientExportFormat[];
  configuration_sections: ConfigurationSection[];
  configuration_fields: ConfigurationField[];
  host_requirements: BackendHostRequirement[];
  identity_replacement_warning: string;
}

export interface VpnInstance {
  id: UUID;
  host_id: UUID;
  display_name: string;
  backend: VpnBackendKind;
  backend_settings: BackendSettings;
  endpoint: { host: string; port: number };
  network: {
    ipv4_subnet: string;
    gateway_ipv4: string;
    ipv6_subnet?: string;
    gateway_ipv6?: string;
  };
  dns: { zone: string; soa_serial: number };
  routing_mode: "full_tunnel" | "split_tunnel";
  persistent_keepalive: number;
  created_at: string;
  updated_at: string;
}

export type InstanceOperationalState =
  | "healthy"
  | "degraded"
  | "stopped"
  | "unknown"
  | "needs_deployment"
  | "updating"
  | "error";

export type DriftState = "not_checked" | "up_to_date" | "desired_changes" | "remote_drift";

export interface InstanceSummary {
  instance: VpnInstance;
  secondary_summary: string;
  listener_summary: string;
  client_count: number;
  state: InstanceOperationalState;
  state_evidence: "local_desired_state" | "deployment_history" | "live_health";
  observed_at?: string | null;
  last_deployment?: DeploymentSummary | null;
}

export interface PresentationFact {
  label: string;
  value: string;
}

export interface InstanceDetail {
  summary: InstanceSummary;
  current_state_hash: string;
  host_display_name: string;
  configured_image: string;
  drift: DriftState;
  last_backup_name?: string | null;
  facts: PresentationFact[];
}

export interface XrayTlsImportInput {
  certificate_path: string;
  private_key_path: string;
}

export interface CreateInstanceInput {
  host_id: UUID;
  display_name: string;
  endpoint_host: string;
  backend: VpnBackendKind;
  backend_settings?: BackendSettings | null;
  endpoint_port?: number | null;
  ipv4_subnet: string;
  dns_zone: string;
  routing_mode?: "full_tunnel" | "split_tunnel" | null;
  xray_tls_import?: XrayTlsImportInput | null;
}

export interface UpdateInstanceInput {
  id: UUID;
  display_name: string;
  endpoint_host: string;
  endpoint_port: number;
  ipv4_subnet: string;
  dns_zone: string;
  routing_mode: "full_tunnel" | "split_tunnel";
  persistent_keepalive: number;
  backend_settings: BackendSettings;
  expected_current_state_hash: string;
  xray_tls_import?: XrayTlsImportInput | null;
}

export interface User {
  id: UUID;
  display_name: string;
  created_at: string;
}

export interface Device {
  id: UUID;
  instance_id: UUID;
  user_id?: UUID;
  display_name: string;
  ipv4_address?: string | null;
  ipv6_address?: string;
  dns_name?: string;
  enabled: boolean;
  backend: VpnBackendKind;
  public_identity:
    | {
        backend: "wireguard";
        identity: { public_key: string; preshared_key: boolean };
      }
    | {
        backend: "amnezia_wg";
        identity: { public_key: string };
      }
    | {
        backend: "openvpn";
        identity: { common_name: string; certificate_serial?: string | null };
      }
    | {
        backend: "ikev2";
        identity: { identity: string; certificate_serial?: string | null };
      }
    | {
        backend: "xray";
        identity: { email: string; flow?: string | null };
      };
  created_at: string;
}

export interface ClientActionView {
  action: ClientAction;
  label: string;
  warning?: string | null;
  destructive: boolean;
}

export interface ClientStatistics {
  last_activity?: string | null;
  received_bytes?: number | null;
  transmitted_bytes?: number | null;
}

export interface Client {
  id: UUID;
  instance_id: UUID;
  user_id?: UUID | null;
  display_name: string;
  ipv4_address?: string | null;
  ipv6_address?: string | null;
  dns_name?: string | null;
  enabled: boolean;
  backend: VpnBackendKind;
  identity_summary: string;
  state_label: string;
  actions: ClientActionView[];
  export_formats: ClientExportFormat[];
  statistics?: ClientStatistics | null;
  created_at: string;
}

export interface UpdateDeviceInput {
  id: UUID;
  user_id?: UUID | null;
  display_name: string;
  dns_name?: string | null;
  enabled: boolean;
}

export type DnsRecordType = "A" | "AAAA" | "CNAME" | "TXT" | "SRV";

export interface DnsRecord {
  id: UUID;
  instance_id: UUID;
  name: string;
  record_type: DnsRecordType;
  value: string;
  ttl: number;
  enabled: boolean;
  managed_by_device_id?: UUID;
}

export interface DnsHostlist {
  id: UUID;
  name: string;
  url: string;
  coverage: string;
}

export interface HostKeyInfo {
  hostname: string;
  resolved_address: string;
  port: number;
  algorithm: string;
  sha256_fingerprint: string;
  public_key_base64: string;
}

export interface HostKeyProbe {
  key: HostKeyInfo;
  state: "unknown" | "trusted" | "changed";
  approved_fingerprint?: string;
}

export interface HostInspection {
  operating_system: string;
  architecture: string;
  package_manager?: "apt" | "dnf" | "yum" | "zypper" | "pacman";
  effective_user_is_root: boolean;
  docker_installed: boolean;
  docker_version?: string;
  compose_version?: string;
  docker_accessible: boolean;
  docker_privileged_accessible: boolean;
  docker_group_member: boolean;
  wireguard_kernel_available: boolean;
  tun_device_available: boolean;
  firewall: {
    implementation?: string | null;
    active?: boolean | null;
    manageable: boolean;
  };
  application_root_writable: boolean;
  sudo_bootstrap_available: boolean;
  warnings: string[];
}

export interface HostInspectionView {
  inspection: HostInspection;
  ssh_trust: string;
  connectivity: string;
  docker_ready: boolean;
  backend_readiness: Array<{
    backend: VpnBackendKind;
    display_name: string;
    status: "ready" | "ready_with_fallback" | "needs_setup" | "unsupported";
    details: string[];
  }>;
}

export type HostProvisioningOperation = {
  operation:
    | "install_docker_engine"
    | "install_compose_plugin"
    | "enable_docker_service"
    | "grant_docker_access"
    | "verify_prerequisites";
};

export interface HostProvisioningPlan {
  host_id: UUID;
  package_manager?: "apt" | "dnf" | "yum" | "zypper" | "pacman";
  operations: HostProvisioningOperation[];
  warnings: string[];
  expected_state_hash: string;
}

export interface DeploymentPlan {
  id: UUID;
  instance_id: UUID;
  operations: Array<Record<string, unknown>>;
  warnings: string[];
  desired_state_hash: string;
}

export interface InstanceHealth {
  compose_project_exists: boolean;
  gateway_running: boolean;
  backend_ready: boolean;
  listeners_ready: boolean;
  client_state_matches: boolean;
  dns_required: boolean;
  dns_running: boolean;
  watchtower_running: boolean;
  private_dns_resolves: boolean;
  public_dns_resolves: boolean;
  wireguard_interface_exists: boolean;
  listen_port_matches: boolean;
  expected_peers_present: boolean;
  details: string[];
}

export interface InstanceHealthView {
  state: InstanceOperationalState;
  observed_at: string;
  configured_image: string;
  checks: Array<{ label: string; passing: boolean }>;
  details: string[];
}

export interface DeploymentSummary {
  id: UUID;
  instance_id: UUID;
  status: string;
  backup_name?: string;
  started_at: string;
  finished_at?: string;
}

export interface DeploymentResult {
  deployment_id: UUID;
  status: string;
  remote_state_changed: boolean;
  rollback_succeeded?: boolean;
  backup_name?: string;
  health: InstanceHealth;
}

export interface DeploymentResultView {
  deployment_id: UUID;
  status: string;
  remote_state_changed: boolean;
  rollback_succeeded?: boolean | null;
  backup_name?: string | null;
  health: InstanceHealthView;
}

export interface BackupInfo {
  name: string;
  created_at: string;
  deployment_id?: UUID;
}

export type BackupReason =
  | "manual"
  | "pre_deploy"
  | "pre_upgrade"
  | "pre_reinstall"
  | "credential_change"
  | "legacy_unknown";

export interface BackupView {
  instance_id: UUID;
  instance_name: string;
  backend: VpnBackendKind;
  backend_name: string;
  name: string;
  created_at: string;
  deployment_id?: UUID | null;
  reason: BackupReason;
  protects_identity: boolean;
  restore_warning: string;
}

export interface BackupRestorePreview {
  instance_id: UUID;
  backup_name: string;
  reason: BackupReason;
  affected_clients: number;
  identity_impact: string;
  creates_safety_backup: boolean;
  expected_state_hash: string;
}

export interface DeploymentProgress {
  deployment_id: UUID;
  sequence: number;
  timestamp: string;
  phase: string;
  message: string;
  technical_detail?: string;
}

export interface ActivityFilter {
  host_id?: UUID | null;
  instance_id?: UUID | null;
  backend?: VpnBackendKind | null;
  operation?: string | null;
  severity?: string | null;
}

export interface LogEvent {
  id: UUID;
  sequence: number;
  timestamp: string;
  severity: string;
  operation: string;
  title: string;
  message: string;
  technical_detail?: string | null;
  host_id?: UUID | null;
  instance_id?: UUID | null;
  backend?: VpnBackendKind | null;
  deployment_id?: UUID | null;
}

export type DeploymentImpact =
  | "no_changes"
  | "dns_reload"
  | "live_reload"
  | "service_restart"
  | "rebuild"
  | "reinstall";

export interface DeploymentPreview {
  id: UUID;
  instance_id: UUID;
  operations: Array<{
    label: string;
    technical_detail?: string | null;
    sensitive: boolean;
  }>;
  impact: DeploymentImpact;
  creates_backup: boolean;
  server_identity_effect: string;
  client_effect: string;
  affected_clients: number;
  drift: DriftState;
  warnings: string[];
  desired_state_hash: string;
}

export interface InstanceUpdatePreview {
  instance_id: UUID;
  current_state_hash: string;
  impact: DeploymentImpact;
  affected_client_count: number;
  requires_client_reexport: boolean;
  client_effect: string;
  server_identity_effect: string;
  warnings: string[];
}
