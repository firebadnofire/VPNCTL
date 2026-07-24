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

export interface VpnInstance {
  id: UUID;
  host_id: UUID;
  display_name: string;
  backend: "wire_guard";
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
  ipv4_address: string;
  ipv6_address?: string;
  dns_name?: string;
  enabled: boolean;
  backend_data: {
    backend: "wire_guard";
    data: {
      public_key: string;
      private_key_ref: UUID;
      preshared_key_ref?: UUID | null;
    };
  };
  created_at: string;
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
  docker_version?: string;
  compose_version?: string;
  docker_accessible: boolean;
  wireguard_kernel_available: boolean;
  application_root_writable: boolean;
  sudo_bootstrap_available: boolean;
  warnings: string[];
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
  dns_running: boolean;
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
