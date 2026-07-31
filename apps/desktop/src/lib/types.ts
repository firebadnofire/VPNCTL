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
        identity: { client_id: UUID; email: string; flow?: string | null };
      };
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
  application_root_writable: boolean;
  sudo_bootstrap_available: boolean;
  warnings: string[];
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

export interface BackupInfo {
  name: string;
  created_at: string;
  deployment_id?: UUID;
}

export interface DeploymentProgress {
  deployment_id: UUID;
  sequence: number;
  timestamp: string;
  phase: string;
  message: string;
  technical_detail?: string;
}
