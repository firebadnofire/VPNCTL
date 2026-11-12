import type { VpnInstance, DnsRecord, VpnBackendKind } from "./types";

export interface RemotePeer {
  id: string; user_id: string | null; display_name: string; ipv4_address: string | null;
  ipv6_address: string | null; dns_name: string | null; enabled: boolean; created_at: string;
  identity: { backend: string; public_key?: string; preshared_key?: string | null; common_name?: string; identity?: string; certificate_serial?: string | null };
}
export interface Configuration {
  instance: VpnInstance; users: { id: string; display_name: string; created_at: string }[];
  peers: RemotePeer[]; dns_records: DnsRecord[]; dns_blocklist_domains: string[];
}
export interface Manifest {
  schema_version: number; appliance_id: string; revision: number; request_id: string;
  request_digest: string; saved_at: string; removed: boolean; configuration: Configuration;
}
export interface RemoteInventory {
  host_id: string; identity: { appliance_id: string; machine_fingerprint: string; ssh_public_key: string };
  synchronized_at: string; cached: boolean;
  discovery: { instances: Manifest[]; archived_instances?: Manifest[]; errors: Record<string, string>; deployments: Record<string, { deployed_revision: number | null; pending_operation: string | null }> };
}
export interface RemoteDraft { host_id: string; base_revision: number; configuration: Configuration }
export interface PeerAvailability { peer_id: string; complete_export_available: boolean; reason: string | null }
export interface LegacyCandidate { instance_id: string; host_id: string; display_name: string; backend: VpnBackendKind; supported: boolean; status: string }
export interface MigrationPreview {
  instance_id: string; destination_host_id: string; configuration: Configuration;
  deployment_present: boolean; remote_metadata_digest: string; already_persisted: boolean;
  issues: string[]; warnings: string[]; expected_preview_hash: string;
}
export interface RemotePlan { id: string; instance_id: string; operations: { operation: string; path?: string; service?: string; name?: string }[]; warnings: string[]; desired_state_hash: string }
export interface RemoteRestorePreview { backup_name: string; expected_state_hash: string; identity_impact: string; desired_revision: number; deployed_revision: number | null }
export interface RuntimeHistoryEntry { request_id: string; desired_revision: number; operation: string; succeeded: boolean; requires_recovery: boolean; deployed_revision: number | null }
