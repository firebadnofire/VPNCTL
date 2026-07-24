use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use ipnet::Ipv4Net;
use qrcode::{QrCode, render::svg};
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, time::sleep};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_backend_wireguard::{VpnBackend, WireGuardBackend};
use vam_core::{
    DEFAULT_DNS_ZONE, DEFAULT_KEEPALIVE, DEFAULT_PORT, DEFAULT_SUBNET, DesiredState, Device,
    DeviceBackendData, DnsConfig, DnsRecord, DnsRecordType, DockerHost, EndpointConfig,
    NetworkConfig, RoutingMode, SecretReference, SshConnectionConfig, User, VpnBackendKind,
    VpnInstance, WireGuardDeviceData, allocate_next_ipv4, first_usable, validate_host_instances,
    validate_instance,
};
use vam_deployment::{
    COREDNS_IMAGE, DeploymentExecutor, DeploymentPlanner, RemoteManifest, WIREGUARD_IMAGE,
    build_manifest, shell_quote,
};
use vam_dns::{next_soa_serial, validate_records};
use vam_protocol::{
    AppError, BackupInfo, ClientArtifact, DeploymentOperation, DeploymentPlan, DeploymentProgress,
    DeploymentResult, DeploymentStatus, DeploymentSummary, HostInspection, HostKeyInfo,
    HostKeyProbe, HostKeyState, InstanceHealth, RenderedFile, redact,
};
use vam_secrets::{SecretStore, SecretStoreError};
use vam_ssh::{CommandResult, RusshTransport, SshError, SshTransport, UploadRequest};
use vam_storage::{Storage, StorageError};
use zeroize::Zeroizing;

const APP_ROOT: &str = "/opt/vpn-appliance-manager";
const BACKUP_RETENTION: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHostInput {
    pub display_name: String,
    pub hostname: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub username: String,
    pub private_key_path: PathBuf,
    pub passphrase: Option<String>,
}

const fn default_ssh_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInstanceInput {
    pub host_id: Uuid,
    pub display_name: String,
    pub endpoint_host: String,
    #[serde(default = "default_vpn_port")]
    pub endpoint_port: u16,
    #[serde(default = "default_subnet")]
    pub ipv4_subnet: String,
    #[serde(default = "default_zone")]
    pub dns_zone: String,
    #[serde(default)]
    pub routing_mode: Option<RoutingMode>,
}

const fn default_vpn_port() -> u16 {
    DEFAULT_PORT
}

fn default_subnet() -> String {
    DEFAULT_SUBNET.into()
}

fn default_zone() -> String {
    DEFAULT_DNS_ZONE.into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDeviceInput {
    pub instance_id: Uuid,
    pub user_id: Option<Uuid>,
    pub display_name: String,
    #[serde(default = "default_true")]
    pub preshared_key: bool,
    #[serde(default = "default_true")]
    pub create_dns_record: bool,
    pub dns_name: Option<String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDnsRecordInput {
    pub instance_id: Uuid,
    pub name: String,
    pub record_type: DnsRecordType,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

const fn default_ttl() -> u32 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedConfiguration {
    pub files: Vec<RenderedFile>,
    pub plan: Option<DeploymentPlan>,
}

#[derive(Clone)]
pub struct ApplicationService {
    pub storage: Storage,
    pub secrets: Arc<dyn SecretStore>,
    transport: Arc<dyn SshTransport>,
    instance_locks: Arc<Mutex<HashMap<Uuid, Arc<Mutex<()>>>>>,
    cancellations: Arc<Mutex<HashMap<Uuid, CancellationToken>>>,
}

impl ApplicationService {
    #[must_use]
    pub fn new(storage: Storage, secrets: Arc<dyn SecretStore>) -> Self {
        Self::with_transport(storage, secrets, Arc::new(RusshTransport::default()))
    }

    #[must_use]
    pub fn with_transport(
        storage: Storage,
        secrets: Arc<dyn SecretStore>,
        transport: Arc<dyn SshTransport>,
    ) -> Self {
        Self {
            storage,
            secrets,
            transport,
            instance_locks: Arc::default(),
            cancellations: Arc::default(),
        }
    }

    pub async fn create_host(&self, input: CreateHostInput) -> Result<DockerHost, AppError> {
        if input.display_name.trim().is_empty()
            || input.hostname.trim().is_empty()
            || input.username.trim().is_empty()
        {
            return Err(validation_error(
                "Host name, address, and SSH user are required.",
            ));
        }
        if input.port == 0 {
            return Err(validation_error("SSH port must be between 1 and 65535."));
        }
        let passphrase_ref = if let Some(passphrase) = input.passphrase {
            let reference = SecretReference(Uuid::new_v4());
            self.secrets
                .put(&reference, passphrase.as_bytes())
                .await
                .map_err(secret_error)?;
            self.storage
                .register_secret_reference(reference.0, "ssh_key_passphrase", reference.0)
                .await
                .map_err(storage_error)?;
            Some(reference)
        } else {
            None
        };
        let now = Utc::now();
        let host = DockerHost {
            id: Uuid::new_v4(),
            display_name: input.display_name.trim().into(),
            ssh: SshConnectionConfig {
                hostname: input.hostname.trim().into(),
                port: input.port,
                username: input.username.trim().into(),
                private_key_path: input.private_key_path,
                passphrase_ref,
            },
            created_at: now,
            updated_at: now,
        };
        self.storage.save_host(&host).await.map_err(storage_error)?;
        Ok(host)
    }

    pub async fn update_host(&self, host: DockerHost) -> Result<DockerHost, AppError> {
        if host.display_name.trim().is_empty() || host.ssh.hostname.trim().is_empty() {
            return Err(validation_error("Host name and address are required."));
        }
        self.storage.save_host(&host).await.map_err(storage_error)?;
        Ok(host)
    }

    pub async fn list_hosts(&self) -> Result<Vec<DockerHost>, AppError> {
        self.storage.list_hosts().await.map_err(storage_error)
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<(), AppError> {
        self.storage.delete_host(id).await.map_err(storage_error)
    }

    pub async fn probe_host_key(&self, host_id: Uuid) -> Result<HostKeyProbe, AppError> {
        let host = self
            .storage
            .get_host(host_id)
            .await
            .map_err(storage_error)?;
        let cancellation = CancellationToken::new();
        let key = self
            .transport
            .probe_host_key(&host.ssh, &cancellation)
            .await
            .map_err(ssh_error)?;
        let approved = self
            .storage
            .known_host_key(host_id)
            .await
            .map_err(storage_error)?;
        let state = match &approved {
            None => HostKeyState::Unknown,
            Some(approved) if approved.public_key_base64 == key.public_key_base64 => {
                HostKeyState::Trusted
            }
            Some(_) => HostKeyState::Changed,
        };
        Ok(HostKeyProbe {
            key,
            state,
            approved_fingerprint: approved.map(|value| value.sha256_fingerprint),
        })
    }

    pub async fn approve_host_key(
        &self,
        host_id: Uuid,
        probed: HostKeyInfo,
        expected_fingerprint: &str,
        replace_changed_key: bool,
    ) -> Result<(), AppError> {
        if probed.sha256_fingerprint != expected_fingerprint {
            return Err(AppError {
                code: "fingerprint_confirmation_mismatch".into(),
                message: "The typed fingerprint does not match the probed SSH host key.".into(),
                scope: Some(host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Re-check and enter the complete SHA-256 fingerprint.".into()),
                technical_detail: None,
            });
        }
        let current = self.probe_host_key(host_id).await?;
        if current.key.public_key_base64 != probed.public_key_base64 {
            return Err(AppError {
                code: "host_key_changed_during_approval".into(),
                message: "The SSH host key changed while it was being approved.".into(),
                scope: Some(host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Probe the host again and investigate the change.".into()),
                technical_detail: None,
            });
        }
        if current.state == HostKeyState::Changed && !replace_changed_key {
            return Err(AppError {
                code: "host_key_changed".into(),
                message: "The host key differs from the approved key.".into(),
                scope: Some(host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some(
                    "Use the separate replace-key confirmation after verifying the server.".into(),
                ),
                technical_detail: None,
            });
        }
        self.storage
            .approve_host_key(host_id, &current.key, replace_changed_key)
            .await
            .map_err(storage_error)
    }

    pub async fn inspect_host(&self, host_id: Uuid) -> Result<HostInspection, AppError> {
        let (host, trusted, passphrase) = self.trusted_host(host_id).await?;
        let command = r#"set +e
printf 'operating_system='; uname -s
printf 'architecture='; uname -m
if command -v docker >/dev/null 2>&1; then
  printf 'docker_version='; docker version --format '{{.Server.Version}}' 2>/dev/null
  docker info >/dev/null 2>&1; printf 'docker_accessible=%s\n' "$?"
  printf 'compose_version='; docker compose version --short 2>/dev/null
else
  printf 'docker_version=\ncompose_version=\ndocker_accessible=127\n'
fi
test -e /sys/module/wireguard || command -v wg >/dev/null 2>&1
printf 'wireguard=%s\n' "$?"
test -w /opt || test -w /opt/vpn-appliance-manager
printf 'root_writable=%s\n' "$?"
sudo -n true >/dev/null 2>&1
printf 'sudo_bootstrap=%s\n' "$?"
if command -v ufw >/dev/null 2>&1; then
  if sudo -n ufw status 2>/dev/null | grep -q '^Status: active'; then
    printf 'ufw=active\n'
  elif sudo -n ufw status >/dev/null 2>&1; then
    printf 'ufw=inactive\n'
  else
    printf 'ufw=unavailable\n'
  fi
else
  printf 'ufw=missing\n'
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  if firewall-cmd --state >/dev/null 2>&1; then
    printf 'firewalld=active\n'
  else
    printf 'firewalld=inactive\n'
  fi
else
  printf 'firewalld=missing\n'
fi
"#;
        let result = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase.as_ref(),
                command,
                &CancellationToken::new(),
            )
            .await
            .map_err(ssh_error)?;
        let values = parse_key_values(&result.stdout_text().map_err(ssh_error)?);
        let docker_version = nonempty(values.get("docker_version"));
        let compose_version = nonempty(values.get("compose_version"));
        let docker_accessible = values
            .get("docker_accessible")
            .is_some_and(|value| value == "0");
        let operating_system = values.get("operating_system").cloned().unwrap_or_default();
        let mut warnings = Vec::new();
        if operating_system != "Linux" {
            warnings.push("The target is not Linux.".into());
        }
        if docker_version.is_none() {
            warnings.push("Docker Engine was not detected.".into());
        }
        if compose_version.is_none() {
            warnings.push("The Docker Compose plugin was not detected.".into());
        }
        if !docker_accessible {
            warnings.push("The SSH user cannot access Docker directly.".into());
        }
        let sudo_available = values
            .get("sudo_bootstrap")
            .is_some_and(|value| value == "0");
        match values.get("ufw").map(String::as_str) {
            Some("active") if !sudo_available => warnings.push(
                "UFW is active, but noninteractive sudo is unavailable for firewall changes."
                    .into(),
            ),
            Some("unavailable") => warnings
                .push("UFW is installed, but its status could not be checked over SSH.".into()),
            _ => {}
        }
        if matches!(values.get("firewalld").map(String::as_str), Some("active")) && !sudo_available
        {
            warnings.push(
                "Firewalld is active, but noninteractive sudo is unavailable for firewall changes."
                    .into(),
            );
        }
        Ok(HostInspection {
            operating_system,
            architecture: values.get("architecture").cloned().unwrap_or_default(),
            docker_version,
            compose_version,
            docker_accessible,
            wireguard_kernel_available: values.get("wireguard").is_some_and(|value| value == "0"),
            application_root_writable: values
                .get("root_writable")
                .is_some_and(|value| value == "0"),
            sudo_bootstrap_available: sudo_available,
            warnings,
        })
    }

    pub async fn create_instance(
        &self,
        input: CreateInstanceInput,
    ) -> Result<VpnInstance, AppError> {
        self.storage
            .get_host(input.host_id)
            .await
            .map_err(storage_error)?;
        let subnet: Ipv4Net = input
            .ipv4_subnet
            .parse()
            .map_err(|_| validation_error("The IPv4 subnet is invalid."))?;
        let gateway = first_usable(subnet).map_err(|error| validation_error(&error.to_string()))?;
        let now = Utc::now();
        let instance = VpnInstance {
            id: Uuid::new_v4(),
            host_id: input.host_id,
            display_name: input.display_name.trim().into(),
            backend: VpnBackendKind::WireGuard,
            endpoint: EndpointConfig {
                host: input.endpoint_host.trim().into(),
                port: input.endpoint_port,
            },
            network: NetworkConfig {
                ipv4_subnet: subnet,
                gateway_ipv4: gateway,
                ipv6_subnet: None,
                gateway_ipv6: None,
            },
            dns: DnsConfig {
                zone: input
                    .dns_zone
                    .trim()
                    .trim_end_matches('.')
                    .to_ascii_lowercase(),
                soa_serial: next_soa_serial(0, Utc::now().date_naive())
                    .map_err(|error| validation_error(&error.to_string()))?,
            },
            routing_mode: input.routing_mode.unwrap_or(RoutingMode::SplitTunnel),
            persistent_keepalive: DEFAULT_KEEPALIVE,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        validate_instance(&instance).map_err(|error| validation_error(&error.to_string()))?;
        let mut instances = self
            .storage
            .list_instances(Some(input.host_id))
            .await
            .map_err(storage_error)?;
        instances.push(instance.clone());
        validate_host_instances(&instances)
            .map_err(|error| validation_error(&error.to_string()))?;
        self.storage
            .save_instance(&instance)
            .await
            .map_err(storage_error)?;
        Ok(instance)
    }

    pub async fn update_instance(
        &self,
        mut instance: VpnInstance,
    ) -> Result<VpnInstance, AppError> {
        instance.updated_at = Utc::now();
        validate_instance(&instance).map_err(|error| validation_error(&error.to_string()))?;
        let mut instances = self
            .storage
            .list_instances(Some(instance.host_id))
            .await
            .map_err(storage_error)?;
        instances.retain(|existing| existing.id != instance.id);
        instances.push(instance.clone());
        validate_host_instances(&instances)
            .map_err(|error| validation_error(&error.to_string()))?;
        self.storage
            .save_instance(&instance)
            .await
            .map_err(storage_error)?;
        Ok(instance)
    }

    pub async fn list_instances(
        &self,
        host_id: Option<Uuid>,
    ) -> Result<Vec<VpnInstance>, AppError> {
        self.storage
            .list_instances(host_id)
            .await
            .map_err(storage_error)
    }

    pub async fn desired_state(&self, instance_id: Uuid) -> Result<DesiredState, AppError> {
        self.storage
            .desired_state(instance_id)
            .await
            .map_err(storage_error)
    }

    pub async fn create_user(&self, display_name: &str) -> Result<User, AppError> {
        if display_name.trim().is_empty() {
            return Err(validation_error("User name is required."));
        }
        let user = User {
            id: Uuid::new_v4(),
            display_name: display_name.trim().into(),
            created_at: Utc::now(),
        };
        self.storage.save_user(&user).await.map_err(storage_error)?;
        Ok(user)
    }

    pub async fn list_users(&self) -> Result<Vec<User>, AppError> {
        self.storage.list_users().await.map_err(storage_error)
    }

    pub async fn delete_user(&self, id: Uuid) -> Result<(), AppError> {
        self.storage.delete_user(id).await.map_err(storage_error)
    }

    pub async fn create_device(&self, input: CreateDeviceInput) -> Result<Device, AppError> {
        if input.display_name.trim().is_empty() {
            return Err(validation_error("Device name is required."));
        }
        let instance = self
            .storage
            .get_instance(input.instance_id)
            .await
            .map_err(storage_error)?;
        let devices = self
            .storage
            .list_devices(input.instance_id)
            .await
            .map_err(storage_error)?;
        let address = allocate_next_ipv4(
            instance.network.ipv4_subnet,
            instance.network.gateway_ipv4,
            &devices,
        )
        .map_err(|error| validation_error(&error.to_string()))?;
        let (private, public) = WireGuardBackend::generate_device_keys();
        let private_ref = SecretReference(Uuid::new_v4());
        self.secrets
            .put(&private_ref, private.as_bytes())
            .await
            .map_err(secret_error)?;
        let psk_ref = if input.preshared_key {
            let reference = SecretReference(Uuid::new_v4());
            let psk = WireGuardBackend::generate_preshared_key();
            self.secrets
                .put(&reference, psk.as_bytes())
                .await
                .map_err(secret_error)?;
            Some(reference)
        } else {
            None
        };
        let device = Device {
            id: Uuid::new_v4(),
            instance_id: input.instance_id,
            user_id: input.user_id,
            display_name: input.display_name.trim().into(),
            ipv4_address: address,
            ipv6_address: None,
            dns_name: input
                .dns_name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            enabled: true,
            backend_data: DeviceBackendData::WireGuard(WireGuardDeviceData {
                public_key: public,
                private_key_ref: private_ref.clone(),
                preshared_key_ref: psk_ref.clone(),
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        self.storage
            .save_device(&device)
            .await
            .map_err(storage_error)?;
        self.storage
            .register_secret_reference(private_ref.0, "wireguard_private_key", device.id)
            .await
            .map_err(storage_error)?;
        if let Some(reference) = psk_ref {
            self.storage
                .register_secret_reference(reference.0, "wireguard_preshared_key", device.id)
                .await
                .map_err(storage_error)?;
        }
        if input.create_dns_record {
            let name = device
                .dns_name
                .clone()
                .unwrap_or_else(|| slug(&device.display_name));
            let record = DnsRecord {
                id: Uuid::new_v4(),
                instance_id: input.instance_id,
                name,
                record_type: DnsRecordType::A,
                value: device.ipv4_address.to_string(),
                ttl: 300,
                enabled: true,
                managed_by_device_id: Some(device.id),
            };
            self.validate_and_save_record(record).await?;
        }
        Ok(device)
    }

    pub async fn update_device(&self, device: Device) -> Result<Device, AppError> {
        let mut state = self.desired_state(device.instance_id).await?;
        state.devices.retain(|existing| existing.id != device.id);
        state.devices.push(device.clone());
        WireGuardBackend
            .validate(&state)
            .map_err(|error| validation_error(&error.to_string()))?;
        let dns_changed = self
            .storage
            .save_device_and_sync_managed_dns(&device)
            .await
            .map_err(storage_error)?;
        if dns_changed {
            self.bump_soa(device.instance_id).await?;
        }
        Ok(device)
    }

    pub async fn delete_device(&self, id: Uuid) -> Result<(), AppError> {
        let device = self.storage.get_device(id).await.map_err(storage_error)?;
        let now = Utc::now();
        self.storage
            .soft_delete_device(id, now)
            .await
            .map_err(storage_error)?;
        self.storage
            .mark_secrets_pending_delete(id)
            .await
            .map_err(storage_error)?;
        self.bump_soa(device.instance_id).await
    }

    pub async fn replace_device_identity(&self, id: Uuid) -> Result<Device, AppError> {
        let mut device = self.storage.get_device(id).await.map_err(storage_error)?;
        let (private, public) = WireGuardBackend::generate_device_keys();
        let private_ref = SecretReference(Uuid::new_v4());
        let psk_ref = SecretReference(Uuid::new_v4());
        let psk = WireGuardBackend::generate_preshared_key();
        self.secrets
            .put(&private_ref, private.as_bytes())
            .await
            .map_err(secret_error)?;
        self.secrets
            .put(&psk_ref, psk.as_bytes())
            .await
            .map_err(secret_error)?;
        device.backend_data = DeviceBackendData::WireGuard(WireGuardDeviceData {
            public_key: public,
            private_key_ref: private_ref.clone(),
            preshared_key_ref: Some(psk_ref.clone()),
        });
        self.storage
            .save_device(&device)
            .await
            .map_err(storage_error)?;
        self.storage
            .mark_secrets_pending_delete(device.id)
            .await
            .map_err(storage_error)?;
        for (reference, purpose) in [
            (private_ref, "wireguard_private_key"),
            (psk_ref, "wireguard_preshared_key"),
        ] {
            self.storage
                .register_secret_reference(reference.0, purpose, device.id)
                .await
                .map_err(storage_error)?;
        }
        Ok(device)
    }

    pub async fn list_devices(&self, instance_id: Uuid) -> Result<Vec<Device>, AppError> {
        self.storage
            .list_devices(instance_id)
            .await
            .map_err(storage_error)
    }

    pub async fn create_dns_record(
        &self,
        input: CreateDnsRecordInput,
    ) -> Result<DnsRecord, AppError> {
        let record = DnsRecord {
            id: Uuid::new_v4(),
            instance_id: input.instance_id,
            name: input.name,
            record_type: input.record_type,
            value: input.value,
            ttl: input.ttl,
            enabled: true,
            managed_by_device_id: None,
        };
        self.validate_and_save_record(record).await
    }

    pub async fn update_dns_record(&self, record: DnsRecord) -> Result<DnsRecord, AppError> {
        self.validate_and_save_record(record).await
    }

    async fn validate_and_save_record(&self, record: DnsRecord) -> Result<DnsRecord, AppError> {
        let instance = self
            .storage
            .get_instance(record.instance_id)
            .await
            .map_err(storage_error)?;
        let mut records = self
            .storage
            .list_dns_records(record.instance_id)
            .await
            .map_err(storage_error)?;
        records.retain(|existing| existing.id != record.id);
        records.push(record.clone());
        validate_records(&instance.dns.zone, &records)
            .map_err(|error| validation_error(&error.to_string()))?;
        self.storage
            .save_dns_record(&record)
            .await
            .map_err(storage_error)?;
        self.bump_soa(record.instance_id).await?;
        Ok(record)
    }

    async fn bump_soa(&self, instance_id: Uuid) -> Result<(), AppError> {
        let mut instance = self
            .storage
            .get_instance(instance_id)
            .await
            .map_err(storage_error)?;
        instance.dns.soa_serial = next_soa_serial(instance.dns.soa_serial, Utc::now().date_naive())
            .map_err(|error| validation_error(&error.to_string()))?;
        instance.updated_at = Utc::now();
        self.storage
            .save_instance(&instance)
            .await
            .map_err(storage_error)
    }

    pub async fn list_dns_records(&self, instance_id: Uuid) -> Result<Vec<DnsRecord>, AppError> {
        self.storage
            .list_dns_records(instance_id)
            .await
            .map_err(storage_error)
    }

    pub async fn delete_dns_record(&self, id: Uuid, instance_id: Uuid) -> Result<(), AppError> {
        self.storage
            .delete_dns_record(id)
            .await
            .map_err(storage_error)?;
        self.bump_soa(instance_id).await
    }

    pub async fn render_instance(&self, instance_id: Uuid) -> Result<Vec<RenderedFile>, AppError> {
        let state = self.desired_state(instance_id).await?;
        self.render_state(&state).await
    }

    pub async fn plan_instance(&self, instance_id: Uuid) -> Result<DeploymentPlan, AppError> {
        let state = self.desired_state(instance_id).await?;
        let files = self.render_state_for_plan(&state).await?;
        let remote = self.remote_manifest(&state.instance).await?;
        vam_deployment::DefaultDeploymentPlanner
            .calculate(&state, &files, remote.as_ref())
            .map_err(deployment_error)
    }

    pub async fn apply_instance(
        &self,
        instance_id: Uuid,
        expected_state_hash: &str,
    ) -> Result<DeploymentResult, AppError> {
        let lock = self.instance_lock(instance_id).await;
        let _guard = lock.lock().await;
        let state = self.desired_state(instance_id).await?;
        let files = self.render_state(&state).await?;
        let remote = self.remote_manifest(&state.instance).await?;
        let plan = vam_deployment::DefaultDeploymentPlanner
            .calculate(&state, &files, remote.as_ref())
            .map_err(deployment_error)?;
        if plan.desired_state_hash != expected_state_hash {
            return Err(AppError {
                code: "stale_deployment_plan".into(),
                message: "Desired state changed after the deployment plan was reviewed.".into(),
                scope: Some(instance_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Review and confirm a fresh deployment plan.".into()),
                technical_detail: None,
            });
        }
        self.storage
            .record_deployment(&plan, &state, DeploymentStatus::Planned)
            .await
            .map_err(storage_error)?;
        if plan.operations.is_empty() {
            if let Some(public) = remote
                .as_ref()
                .and_then(|manifest| manifest.server_public_key.as_ref())
            {
                self.storage
                    .set_setting(&server_public_key_setting(instance_id), public)
                    .await
                    .map_err(storage_error)?;
            }
            let health = self.health(instance_id).await?;
            if !health_is_healthy(&health) {
                self.storage
                    .finish_deployment(plan.id, DeploymentStatus::Failed, None)
                    .await
                    .map_err(storage_error)?;
                return Err(AppError {
                    code: "health_check_failed".into(),
                    message: "The unchanged remote configuration is not healthy.".into(),
                    scope: Some(instance_id.to_string()),
                    remote_state_changed: false,
                    rollback_succeeded: None,
                    remediation: Some("Review the health details and remote logs.".into()),
                    technical_detail: Some(format!("{health:?}")),
                });
            }
            self.storage
                .finish_deployment(plan.id, DeploymentStatus::Succeeded, None)
                .await
                .map_err(storage_error)?;
            return Ok(DeploymentResult {
                deployment_id: plan.id,
                status: DeploymentStatus::Succeeded,
                remote_state_changed: false,
                rollback_succeeded: None,
                backup_name: None,
                health,
            });
        }
        let cancellation = CancellationToken::new();
        self.cancellations
            .lock()
            .await
            .insert(plan.id, cancellation.clone());
        let result = self.execute(&state, &files, &plan, &cancellation).await;
        self.cancellations.lock().await.remove(&plan.id);
        if let Err(failure) = &result {
            if let Ok(stored) = self.storage.get_deployment(plan.id).await
                && matches!(
                    stored.summary.status,
                    DeploymentStatus::Planned | DeploymentStatus::Applying
                )
            {
                let _ = self
                    .storage
                    .finish_deployment(plan.id, DeploymentStatus::Failed, None)
                    .await;
            }
            let mut sequence = self
                .storage
                .list_deployment_events(Some(instance_id))
                .await
                .map(|events| {
                    events
                        .into_iter()
                        .filter(|event| event.deployment_id == plan.id)
                        .map(|event| event.sequence)
                        .max()
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            let _ = self
                .record_event(
                    plan.id,
                    &mut sequence,
                    "failed",
                    &failure.message,
                    failure.technical_detail.clone(),
                    "error",
                )
                .await;
        }
        result
    }

    pub async fn cancel_deployment(&self, deployment_id: Uuid) -> bool {
        if let Some(token) = self.cancellations.lock().await.get(&deployment_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    pub async fn health(&self, instance_id: Uuid) -> Result<InstanceHealth, AppError> {
        let state = self.desired_state(instance_id).await?;
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        self.remote_health(
            &state,
            &host,
            &trusted,
            passphrase.as_ref(),
            &CancellationToken::new(),
        )
        .await
    }

    pub async fn start_instance(&self, instance_id: Uuid) -> Result<InstanceHealth, AppError> {
        self.compose_operation(instance_id, "up -d", true).await
    }

    pub async fn stop_instance(&self, instance_id: Uuid) -> Result<InstanceHealth, AppError> {
        self.compose_operation(instance_id, "stop", false).await
    }

    pub async fn update_images(&self, instance_id: Uuid) -> Result<InstanceHealth, AppError> {
        self.compose_operation(instance_id, "pull && docker compose up -d", true)
            .await
    }

    async fn compose_operation(
        &self,
        instance_id: Uuid,
        operation: &str,
        expect_running: bool,
    ) -> Result<InstanceHealth, AppError> {
        let state = self.desired_state(instance_id).await?;
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        let cancellation = CancellationToken::new();
        if expect_running {
            self.ensure_firewall_allows(
                &state.instance,
                &host,
                &trusted,
                passphrase.as_ref(),
                &cancellation,
            )
            .await?;
        }
        let command = format!(
            "set -eu; cd {}; docker compose {operation}",
            shell_quote(&state.instance.remote_path())
        );
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &command,
            &cancellation,
        )
        .await?;
        if !expect_running {
            return self
                .remote_health(&state, &host, &trusted, passphrase.as_ref(), &cancellation)
                .await;
        }
        let health = self
            .wait_for_healthy(&state, &host, &trusted, passphrase.as_ref(), &cancellation)
            .await?;
        if health_is_healthy(&health) {
            self.normalize_vpn_ownership(
                &state,
                &host,
                &trusted,
                passphrase.as_ref(),
                &cancellation,
            )
            .await?;
        }
        Ok(health)
    }

    pub async fn create_backup(&self, instance_id: Uuid) -> Result<BackupInfo, AppError> {
        let instance = self
            .storage
            .get_instance(instance_id)
            .await
            .map_err(storage_error)?;
        let deployment = self
            .storage
            .last_successful_deployment(instance_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                validation_error(
                    "Deploy the instance successfully before creating a restorable manual backup.",
                )
            })?;
        let (host, trusted, passphrase) = self.trusted_host(instance.host_id).await?;
        let name = format!(
            "{}-manual-{}",
            Utc::now().format("%Y-%m-%dT%H-%M-%SZ"),
            deployment.summary.id
        );
        let backup_path = backup_path(instance.id, &name);
        let command = format!(
            "set -eu; test -d {current}; install -d {parent}; cp -a {current} {backup}",
            current = shell_quote(&instance.remote_path()),
            parent = shell_quote(&format!("{APP_ROOT}/backups/{}", instance.id)),
            backup = shell_quote(&backup_path),
        );
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &command,
            &CancellationToken::new(),
        )
        .await?;
        Ok(BackupInfo {
            name,
            created_at: Utc::now(),
            deployment_id: Some(deployment.summary.id),
        })
    }

    pub async fn list_backups(&self, instance_id: Uuid) -> Result<Vec<BackupInfo>, AppError> {
        let instance = self
            .storage
            .get_instance(instance_id)
            .await
            .map_err(storage_error)?;
        let (host, trusted, passphrase) = self.trusted_host(instance.host_id).await?;
        let deployments = self
            .storage
            .list_deployments(instance_id)
            .await
            .map_err(storage_error)?;
        let deployment_ids: HashMap<_, _> = deployments
            .into_iter()
            .filter_map(|deployment| deployment.backup_name.map(|name| (name, deployment.id)))
            .collect();
        let root = format!("{APP_ROOT}/backups/{instance_id}");
        let command = format!(
            "if test -d {root}; then find {root} -mindepth 1 -maxdepth 1 -type d -printf '%f|%T@\\n' | sort -t '|' -k2,2nr; fi",
            root = shell_quote(&root),
        );
        let result = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &command,
                &CancellationToken::new(),
            )
            .await?;
        let mut backups = Vec::new();
        for line in result.stdout_text().map_err(ssh_error)?.lines() {
            let Some((name, timestamp)) = line.rsplit_once('|') else {
                continue;
            };
            let Some(created_at) = parse_find_timestamp(timestamp) else {
                continue;
            };
            backups.push(BackupInfo {
                name: name.into(),
                created_at,
                deployment_id: deployment_ids.get(name).copied().or_else(|| {
                    name.rsplit_once("-manual-")
                        .and_then(|(_, id)| Uuid::parse_str(id).ok())
                }),
            });
        }
        Ok(backups)
    }

    pub async fn rollback(&self, deployment_id: Uuid) -> Result<DeploymentResult, AppError> {
        let snapshot = self
            .storage
            .get_deployment(deployment_id)
            .await
            .map_err(storage_error)?;
        if snapshot.summary.status != DeploymentStatus::Succeeded {
            return Err(validation_error(
                "Only a successful deployment can be selected for rollback.",
            ));
        }
        let instance_id = snapshot.summary.instance_id;
        let lock = self.instance_lock(instance_id).await;
        let _guard = lock.lock().await;
        let mut state = snapshot.desired_state;
        state.instance.dns.soa_serial = next_soa_serial(
            self.storage
                .get_instance(instance_id)
                .await
                .map_err(storage_error)?
                .dns
                .soa_serial,
            Utc::now().date_naive(),
        )
        .map_err(|error| validation_error(&error.to_string()))?;
        state.instance.updated_at = Utc::now();
        let files = self.render_state(&state).await?;
        let remote = self.remote_manifest(&state.instance).await?;
        let plan = vam_deployment::DefaultDeploymentPlanner
            .calculate(&state, &files, remote.as_ref())
            .map_err(deployment_error)?;
        self.storage
            .record_deployment(&plan, &state, DeploymentStatus::Planned)
            .await
            .map_err(storage_error)?;
        let cancellation = CancellationToken::new();
        let result = self.execute(&state, &files, &plan, &cancellation).await?;
        self.storage
            .replace_desired_state(&state)
            .await
            .map_err(storage_error)?;
        Ok(result)
    }

    pub async fn delete_instance(&self, instance_id: Uuid) -> Result<(), AppError> {
        let instance = self
            .storage
            .get_instance(instance_id)
            .await
            .map_err(storage_error)?;
        let (host, trusted, passphrase) = self.trusted_host(instance.host_id).await?;
        let trash = format!(
            "{APP_ROOT}/trash/{}-{}",
            instance.id,
            Utc::now().format("%Y%m%dT%H%M%SZ")
        );
        let command = format!(
            "set -eu; cd {current}; docker compose stop; install -d {trash_parent}; mv {current} {trash}",
            current = shell_quote(&instance.remote_path()),
            trash_parent = shell_quote(&format!("{APP_ROOT}/trash")),
            trash = shell_quote(&trash),
        );
        let cancellation = CancellationToken::new();
        self.remove_firewall_allow(
            &instance,
            &host,
            &trusted,
            passphrase.as_ref(),
            &cancellation,
        )
        .await?;
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &command,
            &cancellation,
        )
        .await?;
        self.storage
            .soft_delete_instance(instance_id, Utc::now())
            .await
            .map_err(storage_error)
    }

    pub async fn client_configuration(&self, device_id: Uuid) -> Result<ClientArtifact, AppError> {
        let device = self
            .storage
            .get_device(device_id)
            .await
            .map_err(storage_error)?;
        let state = self.desired_state(device.instance_id).await?;
        let secrets = self.device_secret_map(&state, &device).await?;
        WireGuardBackend
            .render_client(&state, &device, &secrets)
            .map_err(backend_error)
    }

    pub async fn client_qr_svg(&self, device_id: Uuid) -> Result<String, AppError> {
        let artifact = self.client_configuration(device_id).await?;
        let code = QrCode::new(artifact.contents.as_bytes()).map_err(|error| AppError {
            code: "qr_generation_failed".into(),
            message: "The client configuration is too large for a QR code.".into(),
            scope: Some(device_id.to_string()),
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: Some("Export the configuration as a file instead.".into()),
            technical_detail: Some(error.to_string()),
        })?;
        Ok(code
            .render::<svg::Color>()
            .min_dimensions(384, 384)
            .dark_color(svg::Color("#102a43"))
            .light_color(svg::Color("#ffffff"))
            .build())
    }

    pub async fn export_client_configuration(
        &self,
        device_id: Uuid,
        destination: &Path,
    ) -> Result<PathBuf, AppError> {
        let artifact = self.client_configuration(device_id).await?;
        let destination = if destination.is_dir() {
            destination.join(&artifact.suggested_filename)
        } else {
            destination.to_owned()
        };
        write_private_file(&destination, artifact.contents.as_bytes()).await?;
        Ok(destination)
    }

    pub async fn list_deployments(
        &self,
        instance_id: Uuid,
    ) -> Result<Vec<DeploymentSummary>, AppError> {
        self.storage
            .list_deployments(instance_id)
            .await
            .map_err(storage_error)
    }

    pub async fn logs(
        &self,
        instance_id: Option<Uuid>,
    ) -> Result<Vec<DeploymentProgress>, AppError> {
        self.storage
            .list_deployment_events(instance_id)
            .await
            .map_err(storage_error)
    }

    async fn render_state(&self, state: &DesiredState) -> Result<Vec<RenderedFile>, AppError> {
        let mut secrets = HashMap::new();
        for device in &state.devices {
            let DeviceBackendData::WireGuard(data) = &device.backend_data;
            if let Some(reference) = &data.preshared_key_ref {
                secrets.insert(reference.clone(), self.secret_text(reference).await?);
            }
        }
        self.render_state_with_secrets(state, &secrets).await
    }

    async fn render_state_for_plan(
        &self,
        state: &DesiredState,
    ) -> Result<Vec<RenderedFile>, AppError> {
        let placeholder =
            Zeroizing::new(String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        let secrets = state
            .devices
            .iter()
            .filter_map(|device| {
                let DeviceBackendData::WireGuard(data) = &device.backend_data;
                data.preshared_key_ref
                    .as_ref()
                    .map(|reference| (reference.clone(), placeholder.clone()))
            })
            .collect();
        self.render_state_with_secrets(state, &secrets).await
    }

    async fn render_state_with_secrets(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, AppError> {
        WireGuardBackend.validate(state).map_err(backend_error)?;
        let mut files = vam_deployment::DefaultDeploymentPlanner
            .render(state)
            .map_err(deployment_error)?;
        files.push(
            WireGuardBackend
                .render_server(state, secrets)
                .map_err(backend_error)?,
        );
        let mut manifest = build_manifest(&files);
        if let Some(public) = self
            .storage
            .get_setting::<String>(&server_public_key_setting(state.instance.id))
            .await
            .map_err(storage_error)?
        {
            manifest.server_public_key = Some(public);
        }
        files.push(RenderedFile {
            path: "state.json".into(),
            contents: format!(
                "{}\n",
                serde_json::to_string_pretty(&manifest).map_err(serialization_error)?
            ),
            mode: 0o600,
            sensitive: false,
        });
        Ok(files)
    }

    async fn remote_manifest(
        &self,
        instance: &VpnInstance,
    ) -> Result<Option<RemoteManifest>, AppError> {
        let (host, trusted, passphrase) = self.trusted_host(instance.host_id).await?;
        let path = format!("{}/state.json", instance.remote_path());
        let command = format!(
            "if test -r {path}; then cat {path}; fi",
            path = shell_quote(&path)
        );
        let result = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase.as_ref(),
                &command,
                &CancellationToken::new(),
            )
            .await
            .map_err(ssh_error)?;
        if result.exit_status != 0 {
            return Err(command_error("read_remote_manifest", &result, false));
        }
        let text = result.stdout_text().map_err(ssh_error)?;
        if text.trim().is_empty() {
            return Ok(None);
        }
        let mut manifest: RemoteManifest =
            serde_json::from_str(&text).map_err(serialization_error)?;
        let paths: Vec<_> = manifest.files.keys().cloned().collect();
        if paths.iter().any(|path| !safe_relative_path(path)) {
            return Err(AppError {
                code: "remote_manifest_unsafe".into(),
                message: "The remote manifest contains an unsafe path.".into(),
                scope: Some(instance.id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Inspect the remote state.json before deploying.".into()),
                technical_detail: None,
            });
        }
        let mut hash_command = String::from("set -eu");
        for path in &paths {
            let remote_path = format!("{}/{}", instance.remote_path(), path);
            let quoted = shell_quote(&remote_path);
            if path == "vpn/wg0.conf.template" {
                hash_command.push_str(&format!(
                    "; if test -f {quoted}; then sed -E 's/^[[:space:]]*(PrivateKey|PresharedKey)[[:space:]]*=.*/secret = [REDACTED]/' {quoted} | sha256sum | cut -d ' ' -f 1; else printf 'missing\\n'; fi"
                ));
            } else {
                hash_command.push_str(&format!(
                    "; if test -f {quoted}; then sha256sum {quoted} | cut -d ' ' -f 1; else printf 'missing\\n'; fi"
                ));
            }
        }
        let actual = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase.as_ref(),
                &hash_command,
                &CancellationToken::new(),
            )
            .await
            .map_err(ssh_error)?;
        if actual.exit_status != 0 {
            return Err(command_error("verify_remote_hashes", &actual, false));
        }
        let hashes: Vec<_> = actual
            .stdout_text()
            .map_err(ssh_error)?
            .lines()
            .map(str::to_owned)
            .collect();
        if hashes.len() != paths.len() {
            return Err(AppError {
                code: "remote_hash_output_invalid".into(),
                message: "The remote file hash response was incomplete.".into(),
                scope: Some(instance.id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Verify sha256sum and core utilities on the host.".into()),
                technical_detail: None,
            });
        }
        for (path, actual_hash) in paths.into_iter().zip(hashes) {
            if manifest.files.get(&path) != Some(&actual_hash) {
                manifest.drifted_files.push(path.clone());
                manifest.files.insert(path, actual_hash);
            }
        }
        Ok(Some(manifest))
    }

    async fn trusted_host(
        &self,
        host_id: Uuid,
    ) -> Result<
        (
            DockerHost,
            vam_storage::KnownHostKey,
            Option<Zeroizing<String>>,
        ),
        AppError,
    > {
        let host = self
            .storage
            .get_host(host_id)
            .await
            .map_err(storage_error)?;
        let trusted = self
            .storage
            .known_host_key(host_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| AppError {
                code: "host_key_untrusted".into(),
                message: "The SSH host key has not been approved.".into(),
                scope: Some(host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Probe and explicitly approve the SHA-256 fingerprint.".into()),
                technical_detail: None,
            })?;
        let passphrase = match &host.ssh.passphrase_ref {
            Some(reference) => Some(self.secret_text(reference).await?),
            None => None,
        };
        Ok((host, trusted, passphrase))
    }

    async fn secret_text(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<String>, AppError> {
        let bytes = self.secrets.get(reference).await.map_err(secret_error)?;
        String::from_utf8(bytes.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| AppError {
                code: "secret_invalid".into(),
                message: "A secure-store value is not valid UTF-8.".into(),
                scope: Some(reference.0.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Replace the affected identity or credential.".into()),
                technical_detail: None,
            })
    }

    async fn device_secret_map(
        &self,
        state: &DesiredState,
        device: &Device,
    ) -> Result<HashMap<SecretReference, Zeroizing<String>>, AppError> {
        let DeviceBackendData::WireGuard(data) = &device.backend_data;
        let mut secrets = HashMap::new();
        secrets.insert(
            data.private_key_ref.clone(),
            self.secret_text(&data.private_key_ref).await?,
        );
        if let Some(reference) = &data.preshared_key_ref {
            secrets.insert(reference.clone(), self.secret_text(reference).await?);
        }
        let server_reference = SecretReference(state.instance.id);
        let server_public = self
            .storage
            .get_setting::<String>(&server_public_key_setting(state.instance.id))
            .await
            .map_err(storage_error)?
            .ok_or_else(|| AppError {
                code: "server_public_key_missing".into(),
                message: "The server public key is unavailable; deploy the instance first.".into(),
                scope: Some(state.instance.id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Apply the instance, then export the client.".into()),
                technical_detail: None,
            })?;
        secrets.insert(server_reference.clone(), Zeroizing::new(server_public));
        Ok(secrets)
    }

    async fn checked_execute(
        &self,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        command: &str,
        cancellation: &CancellationToken,
    ) -> Result<CommandResult, AppError> {
        let result = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase,
                command,
                cancellation,
            )
            .await
            .map_err(ssh_error)?;
        if result.exit_status != 0 {
            return Err(command_error("remote_operation", &result, false));
        }
        Ok(result)
    }

    async fn ensure_firewall_allows(
        &self,
        instance: &VpnInstance,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let command = firewall_allow_command(instance.endpoint.port);
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await
            .map(|_| ())
            .map_err(|mut error| {
                error.code = "remote_firewall".into();
                error.message = format!(
                    "The remote firewall could not be opened for UDP port {}.",
                    instance.endpoint.port
                );
                error.scope = Some(instance.id.to_string());
                error.remediation = Some(
                    "Ensure UFW or Firewalld is inactive, or grant noninteractive sudo for firewall management."
                        .into(),
                );
                error
            })
    }

    async fn remove_firewall_allow(
        &self,
        instance: &VpnInstance,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let command = firewall_remove_command(instance.endpoint.port);
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await
            .map(|_| ())
            .map_err(|mut error| {
                error.code = "remote_firewall".into();
                error.message = format!(
                    "The remote firewall rule for UDP port {} could not be removed.",
                    instance.endpoint.port
                );
                error.scope = Some(instance.id.to_string());
                error.remediation = Some(
                    "Ensure UFW or Firewalld is inactive, or grant noninteractive sudo for firewall management."
                        .into(),
                );
                error
            })
    }

    async fn instance_lock(&self, instance_id: Uuid) -> Arc<Mutex<()>> {
        self.instance_locks
            .lock()
            .await
            .entry(instance_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn record_event(
        &self,
        deployment_id: Uuid,
        sequence: &mut u64,
        phase: &str,
        message: &str,
        technical_detail: Option<String>,
        level: &str,
    ) -> Result<(), AppError> {
        *sequence += 1;
        self.storage
            .record_deployment_event(
                &DeploymentProgress {
                    deployment_id,
                    sequence: *sequence,
                    timestamp: Utc::now(),
                    phase: phase.into(),
                    message: message.into(),
                    technical_detail: technical_detail.map(|value| redact(&value, &[])),
                },
                level,
            )
            .await
            .map_err(storage_error)
    }

    async fn remote_health(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<InstanceHealth, AppError> {
        let expected_peers = state
            .devices
            .iter()
            .filter(|device| device.enabled && device.deleted_at.is_none())
            .count();
        let command = format!(
            r#"set +e
cd {path} || exit 0
services="$(docker compose ps --status running --services 2>/dev/null)"
printf 'project=1\n'
printf 'gateway=%s\n' "$(printf '%s\n' "$services" | grep -qx gateway; echo $?)"
printf 'dns=%s\n' "$(printf '%s\n' "$services" | grep -qx dns; echo $?)"
docker compose exec -T gateway wg show wg0 >/dev/null 2>&1
printf 'wireguard=%s\n' "$?"
peer_count="$(docker compose exec -T gateway wg show wg0 peers 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
printf 'peer_count=%s\n' "$peer_count"
docker compose port --protocol udp gateway 51820 2>/dev/null | grep -Eq ':{port}$'
printf 'port=%s\n' "$?"
docker compose exec -T gateway nslookup gateway.{zone} 127.0.0.1 >/dev/null 2>&1
printf 'private_dns=%s\n' "$?"
docker compose exec -T gateway nslookup example.com 127.0.0.1 >/dev/null 2>&1
printf 'public_dns=%s\n' "$?"
"#,
            path = shell_quote(&state.instance.remote_path()),
            zone = state.instance.dns.zone,
            port = state.instance.endpoint.port,
        );
        let result = self
            .transport
            .execute(
                &host.ssh,
                &trusted.public_key_base64,
                passphrase,
                &command,
                cancellation,
            )
            .await
            .map_err(ssh_error)?;
        let text = result.stdout_text().map_err(ssh_error)?;
        let values = parse_key_values(&text);
        let zero = |key: &str| values.get(key).is_some_and(|value| value == "0");
        let peer_count = values
            .get("peer_count")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        Ok(InstanceHealth {
            compose_project_exists: values.get("project").is_some_and(|value| value == "1"),
            gateway_running: zero("gateway"),
            dns_running: zero("dns"),
            private_dns_resolves: zero("private_dns"),
            public_dns_resolves: zero("public_dns"),
            wireguard_interface_exists: zero("wireguard"),
            listen_port_matches: zero("port"),
            expected_peers_present: peer_count == expected_peers,
            details: vec![
                format!("Expected peers: {expected_peers}"),
                format!("Observed peers: {peer_count}"),
            ],
        })
    }

    async fn normalize_vpn_ownership(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let command = format!(
            r#"set -eu
docker run --rm --entrypoint sh \
  -e VAM_UID="$(id -u)" -e VAM_GID="$(id -g)" \
  -v {vpn_mount} {image} \
  -c 'chown -R "$VAM_UID:$VAM_GID" /work'
"#,
            vpn_mount = shell_quote(&format!("{}/vpn:/work", state.instance.remote_path())),
            image = shell_quote(WIREGUARD_IMAGE),
        );
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await
            .map(|_| ())
    }

    async fn wait_for_healthy(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<InstanceHealth, AppError> {
        const ATTEMPTS: usize = 30;
        for attempt in 0..ATTEMPTS {
            let health = self
                .remote_health(state, host, trusted, passphrase, cancellation)
                .await?;
            if health_is_healthy(&health) || attempt + 1 == ATTEMPTS {
                return Ok(health);
            }
            tokio::select! {
                () = cancellation.cancelled() => return Err(ssh_error(SshError::Cancelled)),
                () = sleep(Duration::from_secs(1)) => {}
            }
        }
        unreachable!("the bounded health loop always returns")
    }
}

#[async_trait::async_trait]
impl DeploymentExecutor for ApplicationService {
    async fn execute(
        &self,
        state: &DesiredState,
        files: &[RenderedFile],
        plan: &DeploymentPlan,
        cancellation: &CancellationToken,
    ) -> Result<DeploymentResult, AppError> {
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        let rollback_state = self
            .storage
            .last_successful_deployment(state.instance.id)
            .await
            .map_err(storage_error)?
            .map(|deployment| deployment.desired_state);
        let rollback_health_state = rollback_state.as_ref().unwrap_or(state);
        let mut sequence = 0;
        self.record_event(
            plan.id,
            &mut sequence,
            "verify",
            "Verified the approved SSH host key.",
            None,
            "info",
        )
        .await?;
        let inspection = self.inspect_host(state.instance.host_id).await?;
        if inspection.operating_system != "Linux"
            || !inspection.docker_accessible
            || inspection.compose_version.is_none()
            || inspection
                .compose_version
                .as_deref()
                .and_then(version_major)
                .is_none_or(|major| major < 2)
        {
            let error = AppError {
                code: "host_prerequisites_failed".into(),
                message: "The host does not meet deployment prerequisites.".into(),
                scope: Some(state.instance.host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some(
                    "Provide Linux, direct Docker access, and the Docker Compose plugin.".into(),
                ),
                technical_detail: Some(inspection.warnings.join("; ")),
            };
            self.storage
                .finish_deployment(plan.id, DeploymentStatus::Failed, None)
                .await
                .map_err(storage_error)?;
            return Err(error);
        }
        let stage = format!("{APP_ROOT}/staging/{}-{}", state.instance.id, plan.id);
        let backup_name = plan
            .operations
            .iter()
            .find_map(|operation| match operation {
                DeploymentOperation::CreateBackup { name } => Some(name.clone()),
                _ => None,
            })
            .unwrap_or_else(|| format!("{}-{}", Utc::now().format("%Y-%m-%dT%H-%M-%SZ"), plan.id));
        let backup = backup_path(state.instance.id, &backup_name);
        let bootstrap = format!(
            r#"set -eu
if test ! -w {root}; then
  if test ! -e {root} && test -w /opt; then
    install -d -m 0750 {root}
  else
    sudo -n install -d -m 0750 -o "$USER" -g "$(id -gn)" {root}
  fi
fi
test -w {root}
install -d {instances} {staging_root} {backups} {trash} {stage}
"#,
            root = shell_quote(APP_ROOT),
            instances = shell_quote(&format!("{APP_ROOT}/instances")),
            staging_root = shell_quote(&format!("{APP_ROOT}/staging")),
            backups = shell_quote(&format!("{APP_ROOT}/backups/{}", state.instance.id)),
            trash = shell_quote(&format!("{APP_ROOT}/trash")),
            stage = shell_quote(&stage),
        );
        if let Err(mut error) = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &bootstrap,
                cancellation,
            )
            .await
        {
            error.scope = Some(state.instance.id.to_string());
            self.storage
                .finish_deployment(plan.id, DeploymentStatus::Failed, None)
                .await
                .map_err(storage_error)?;
            return Err(error);
        }
        let port_check = format!(
            r#"set -eu
if ss -H -lun | awk -v port=':{port}' '$5 ~ (port "$") {{ found=1 }} END {{ exit !found }}'; then
  if test ! -d {current} || test -z "$(cd {current} && docker compose ps -q gateway 2>/dev/null)"; then
    printf 'UDP port {port} is already in use\n' >&2
    exit 42
  fi
fi
"#,
            port = state.instance.endpoint.port,
            current = shell_quote(&state.instance.remote_path()),
        );
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &port_check,
            cancellation,
        )
        .await
        .map_err(|mut error| {
            error.code = "udp_port_conflict".into();
            error.message = format!(
                "UDP port {} is already in use on the host.",
                state.instance.endpoint.port
            );
            error.remediation =
                Some("Choose an unused UDP port or stop the conflicting service.".into());
            error
        })?;
        let directories = rendered_directories(files);
        let mut prepare_dirs = format!("set -eu; install -d {}", shell_quote(&stage));
        for directory in directories {
            prepare_dirs.push_str(&format!(
                "; install -d {}",
                shell_quote(&format!("{stage}/{directory}"))
            ));
        }
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &prepare_dirs,
            cancellation,
        )
        .await?;
        self.record_event(
            plan.id,
            &mut sequence,
            "upload",
            "Uploading the rendered configuration to same-filesystem staging.",
            None,
            "info",
        )
        .await?;
        for file in files {
            self.transport
                .upload(UploadRequest {
                    config: &host.ssh,
                    trusted_key_base64: &trusted.public_key_base64,
                    passphrase: passphrase.as_ref(),
                    remote_path: &format!("{stage}/{}", file.path),
                    contents: file.contents.as_bytes(),
                    mode: file.mode,
                    cancellation,
                })
                .await
                .map_err(ssh_error)?;
        }
        self.record_event(
            plan.id,
            &mut sequence,
            "images",
            "Pulling the pinned WireGuard and CoreDNS images.",
            None,
            "info",
        )
        .await?;
        let pull = format!(
            "set -eu; docker pull {}; docker pull {}",
            shell_quote(WIREGUARD_IMAGE),
            shell_quote(COREDNS_IMAGE)
        );
        self.checked_execute(&host, &trusted, passphrase.as_ref(), &pull, cancellation)
            .await?;
        let key_command = format!(
            r#"set -eu
if test -r {current_key}; then cp {current_key} {stage_key}; fi
docker run --rm --entrypoint sh -v {vpn_mount} {image} -c 'set -eu; umask 077; test -s /work/server.key || wg genkey > /work/server.key; wg pubkey < /work/server.key; awk '"'"'{{ if ($0 == "PrivateKey = __VAM_SERVER_PRIVATE_KEY__") {{ getline key < "/work/server.key"; print "PrivateKey = " key }} else print }}'"'"' /work/wg0.conf.template > /work/wg0.conf; chmod 0600 /work/server.key /work/wg0.conf'
"#,
            current_key = shell_quote(&format!("{}/vpn/server.key", state.instance.remote_path())),
            stage_key = shell_quote(&format!("{stage}/vpn/server.key")),
            vpn_mount = shell_quote(&format!("{stage}/vpn:/work")),
            image = shell_quote(WIREGUARD_IMAGE),
        );
        let public_result = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &key_command,
                cancellation,
            )
            .await?;
        let server_public = public_result.stdout_text().map_err(ssh_error)?;
        let server_public = server_public.trim();
        if server_public.len() != 44 {
            self.storage
                .finish_deployment(plan.id, DeploymentStatus::Failed, None)
                .await
                .map_err(storage_error)?;
            return Err(AppError {
                code: "server_key_generation_failed".into(),
                message: "The remote WireGuard image did not return a valid public key.".into(),
                scope: Some(state.instance.id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Inspect Docker and the pinned WireGuard image.".into()),
                technical_detail: None,
            });
        }
        let mut manifest = build_manifest(files);
        manifest.server_public_key = Some(server_public.into());
        manifest.deployed_at = Some(Utc::now().to_rfc3339());
        let state_json = format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).map_err(serialization_error)?
        );
        self.transport
            .upload(UploadRequest {
                config: &host.ssh,
                trusted_key_base64: &trusted.public_key_base64,
                passphrase: passphrase.as_ref(),
                remote_path: &format!("{stage}/state.json"),
                contents: state_json.as_bytes(),
                mode: 0o600,
                cancellation,
            })
            .await
            .map_err(ssh_error)?;
        self.record_event(
            plan.id,
            &mut sequence,
            "validate",
            "Validating WireGuard, CoreDNS, and Compose configuration.",
            None,
            "info",
        )
        .await?;
        let validate = format!(
            r#"set -eu
docker run --rm --entrypoint sh -v {vpn_mount} {wg_image} -c 'wg-quick strip /work/wg0.conf >/dev/null'
cid="$(docker run -d --rm -v {dns_mount} {dns_image} -conf /etc/coredns/Corefile)"
sleep 1
test "$(docker inspect -f '{{{{.State.Running}}}}' "$cid")" = true
docker rm -f "$cid" >/dev/null
cd {stage}
docker compose --env-file .env config --quiet
"#,
            vpn_mount = shell_quote(&format!("{stage}/vpn:/work:ro")),
            wg_image = shell_quote(WIREGUARD_IMAGE),
            dns_mount = shell_quote(&format!("{stage}/dns:/etc/coredns:ro")),
            dns_image = shell_quote(COREDNS_IMAGE),
            stage = shell_quote(&stage),
        );
        if let Err(error) = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &validate,
                cancellation,
            )
            .await
        {
            self.storage
                .finish_deployment(plan.id, DeploymentStatus::Failed, None)
                .await
                .map_err(storage_error)?;
            return Err(error);
        }
        let current = state.instance.remote_path();
        let backup_command = format!(
            "set -eu; if test -d {current}; then install -d {backup_parent}; cp -a {current} {backup}; fi",
            current = shell_quote(&current),
            backup_parent = shell_quote(&format!("{APP_ROOT}/backups/{}", state.instance.id)),
            backup = shell_quote(&backup),
        );
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &backup_command,
            cancellation,
        )
        .await?;
        self.record_event(
            plan.id,
            &mut sequence,
            "backup",
            "Created the pre-mutation backup.",
            Some(backup_name.clone()),
            "info",
        )
        .await?;
        let activate = activation_command(&current, &stage, files, plan);
        let activation_result = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &activate,
                cancellation,
            )
            .await;
        if let Err(mut error) = activation_result {
            error.remote_state_changed = true;
            let rollback_ok = self
                .restore_backup(
                    rollback_health_state,
                    &host,
                    &trusted,
                    passphrase.as_ref(),
                    &backup,
                    cancellation,
                )
                .await
                .is_ok();
            error.rollback_succeeded = Some(rollback_ok);
            let status = if rollback_ok {
                DeploymentStatus::RolledBack
            } else {
                DeploymentStatus::RollbackFailed
            };
            self.storage
                .finish_deployment(plan.id, status, Some(&backup_name))
                .await
                .map_err(storage_error)?;
            return Err(error);
        }
        self.record_event(
            plan.id,
            &mut sequence,
            "apply",
            "Activated the staged configuration.",
            None,
            "info",
        )
        .await?;
        self.record_event(
            plan.id,
            &mut sequence,
            "firewall",
            "Ensuring active host firewalls allow the WireGuard UDP port.",
            None,
            "info",
        )
        .await?;
        if let Err(mut error) = self
            .ensure_firewall_allows(
                &state.instance,
                &host,
                &trusted,
                passphrase.as_ref(),
                cancellation,
            )
            .await
        {
            error.remote_state_changed = true;
            let rollback_ok = self
                .restore_backup(
                    rollback_health_state,
                    &host,
                    &trusted,
                    passphrase.as_ref(),
                    &backup,
                    cancellation,
                )
                .await
                .is_ok();
            error.rollback_succeeded = Some(rollback_ok);
            let status = if rollback_ok {
                DeploymentStatus::RolledBack
            } else {
                DeploymentStatus::RollbackFailed
            };
            self.storage
                .finish_deployment(plan.id, status, Some(&backup_name))
                .await
                .map_err(storage_error)?;
            return Err(error);
        }
        let compose_command = if plan
            .operations
            .iter()
            .any(|operation| matches!(operation, DeploymentOperation::ReloadDns))
        {
            "true"
        } else if plan.operations.iter().any(|operation| {
            matches!(
                operation,
                DeploymentOperation::ComposeRestart { service } if service == "gateway"
            )
        }) {
            "docker compose restart gateway && docker compose restart dns"
        } else {
            "docker compose pull && docker compose up -d --remove-orphans"
        };
        let compose = format!("set -eu; cd {}; {compose_command}", shell_quote(&current));
        let compose_result = self
            .checked_execute(&host, &trusted, passphrase.as_ref(), &compose, cancellation)
            .await;
        let health = if compose_result.is_ok() {
            match self
                .wait_for_healthy(state, &host, &trusted, passphrase.as_ref(), cancellation)
                .await
            {
                Ok(health) if health_is_healthy(&health) => self
                    .normalize_vpn_ownership(
                        rollback_health_state,
                        &host,
                        &trusted,
                        passphrase.as_ref(),
                        cancellation,
                    )
                    .await
                    .map(|()| health),
                result => result,
            }
        } else {
            Err(compose_result.expect_err("checked above"))
        };
        let health = match health {
            Ok(health) if health_is_healthy(&health) => health,
            Ok(health) => {
                let rollback_ok = self
                    .restore_backup(
                        rollback_health_state,
                        &host,
                        &trusted,
                        passphrase.as_ref(),
                        &backup,
                        cancellation,
                    )
                    .await
                    .is_ok();
                let status = if rollback_ok {
                    DeploymentStatus::RolledBack
                } else {
                    DeploymentStatus::RollbackFailed
                };
                self.storage
                    .finish_deployment(plan.id, status, Some(&backup_name))
                    .await
                    .map_err(storage_error)?;
                return Err(AppError {
                    code: "health_check_failed".into(),
                    message: "The deployment activated, but one or more health checks failed."
                        .into(),
                    scope: Some(state.instance.id.to_string()),
                    remote_state_changed: true,
                    rollback_succeeded: Some(rollback_ok),
                    remediation: Some("Review the health details and deployment log.".into()),
                    technical_detail: Some(format!("{health:?}")),
                });
            }
            Err(mut error) => {
                let rollback_ok = self
                    .restore_backup(
                        rollback_health_state,
                        &host,
                        &trusted,
                        passphrase.as_ref(),
                        &backup,
                        cancellation,
                    )
                    .await
                    .is_ok();
                error.remote_state_changed = true;
                error.rollback_succeeded = Some(rollback_ok);
                let status = if rollback_ok {
                    DeploymentStatus::RolledBack
                } else {
                    DeploymentStatus::RollbackFailed
                };
                self.storage
                    .finish_deployment(plan.id, status, Some(&backup_name))
                    .await
                    .map_err(storage_error)?;
                return Err(error);
            }
        };
        self.storage
            .set_setting(
                &server_public_key_setting(state.instance.id),
                &server_public,
            )
            .await
            .map_err(storage_error)?;
        let cleanup_stage = format!(
            "docker run --rm --entrypoint sh -v {root_mount} {image} -c {script}",
            root_mount = shell_quote(&format!("{APP_ROOT}:/vam")),
            image = shell_quote(WIREGUARD_IMAGE),
            script = shell_quote(&format!(
                "rm -rf -- /vam/staging/{}-{}",
                state.instance.id, plan.id
            )),
        );
        if let Err(error) = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &cleanup_stage,
                cancellation,
            )
            .await
        {
            let _ = self
                .record_event(
                    plan.id,
                    &mut sequence,
                    "cleanup",
                    "The consumed staging directory could not be removed.",
                    error.technical_detail,
                    "warning",
                )
                .await;
        }
        let prune = prune_command(state.instance.id, BACKUP_RETENTION);
        let _ = self
            .checked_execute(&host, &trusted, passphrase.as_ref(), &prune, cancellation)
            .await;
        self.storage
            .finish_deployment(plan.id, DeploymentStatus::Succeeded, Some(&backup_name))
            .await
            .map_err(storage_error)?;
        for reference in self
            .storage
            .deletable_secret_references(state.instance.id, BACKUP_RETENTION)
            .await
            .map_err(storage_error)?
        {
            let reference = SecretReference(reference);
            if let Err(error) = self.secrets.delete(&reference).await {
                let _ = self
                    .record_event(
                        plan.id,
                        &mut sequence,
                        "secret_retention",
                        "A retired Keychain item could not be removed and will be retried.",
                        Some(error.to_string()),
                        "warning",
                    )
                    .await;
                continue;
            }
            if let Err(error) = self.storage.remove_secret_reference(reference.0).await {
                let _ = self
                    .record_event(
                        plan.id,
                        &mut sequence,
                        "secret_retention",
                        "A retired secret-reference row could not be removed and will be retried.",
                        Some(error.to_string()),
                        "warning",
                    )
                    .await;
            }
        }
        self.record_event(
            plan.id,
            &mut sequence,
            "complete",
            "Deployment verified successfully.",
            None,
            "info",
        )
        .await?;
        Ok(DeploymentResult {
            deployment_id: plan.id,
            status: DeploymentStatus::Succeeded,
            remote_state_changed: true,
            rollback_succeeded: None,
            backup_name: Some(backup_name),
            health,
        })
    }
}

impl ApplicationService {
    async fn restore_backup(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        backup: &str,
        cancellation: &CancellationToken,
    ) -> Result<InstanceHealth, AppError> {
        let current = state.instance.remote_path();
        let failed = format!(
            "{APP_ROOT}/trash/{}-failed-{}",
            state.instance.id,
            Utc::now().format("%Y%m%dT%H%M%SZ")
        );
        let command = format!(
            "set -eu; if test -d {current}; then cd {current}; docker compose down || true; cd /; mv {current} {failed}; fi; cp -a {backup} {current}; cd {current}; docker compose up -d",
            current = shell_quote(&current),
            failed = shell_quote(&failed),
            backup = shell_quote(backup),
        );
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await?;
        let health = self
            .wait_for_healthy(state, host, trusted, passphrase, cancellation)
            .await?;
        if !health_is_healthy(&health) {
            return Err(AppError {
                code: "rollback_health_failed".into(),
                message: "The backup was restored but failed health checks.".into(),
                scope: Some(state.instance.id.to_string()),
                remote_state_changed: true,
                rollback_succeeded: Some(false),
                remediation: Some("Inspect the restored Compose project on the host.".into()),
                technical_detail: Some(format!("{health:?}")),
            });
        }
        self.normalize_vpn_ownership(state, host, trusted, passphrase, cancellation)
            .await?;
        Ok(health)
    }
}

fn rendered_directories(files: &[RenderedFile]) -> Vec<String> {
    let mut directories = Vec::new();
    for file in files {
        let mut path = Path::new(&file.path).parent();
        while let Some(directory) = path {
            let text = directory.to_string_lossy();
            if !text.is_empty() && !directories.iter().any(|item| item == text.as_ref()) {
                directories.push(text.into_owned());
            }
            path = directory.parent();
        }
    }
    directories.sort();
    directories
}

fn safe_relative_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path.is_empty()
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn activation_command(
    current: &str,
    stage: &str,
    files: &[RenderedFile],
    plan: &DeploymentPlan,
) -> String {
    let mut command = format!("set -eu; install -d {}", shell_quote(current));
    for directory in rendered_directories(files) {
        command.push_str(&format!(
            "; install -d {}",
            shell_quote(&format!("{current}/{directory}"))
        ));
    }
    let changed: Vec<_> = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            DeploymentOperation::UploadFile { path, .. }
            | DeploymentOperation::ReplaceFile { path, .. } => Some(path),
            _ => None,
        })
        .collect();
    for path in changed {
        command.push_str(&format!(
            "; mv {} {}",
            shell_quote(&format!("{stage}/{path}")),
            shell_quote(&format!("{current}/{path}"))
        ));
    }
    if plan
        .operations
        .iter()
        .any(|operation| matches!(operation, DeploymentOperation::GenerateServerKey))
        || plan.operations.iter().any(|operation| {
            matches!(
                operation,
                DeploymentOperation::UploadFile { path, .. }
                    | DeploymentOperation::ReplaceFile { path, .. }
                    if path == "vpn/wg0.conf.template"
            )
        })
    {
        for path in ["vpn/server.key", "vpn/wg0.conf"] {
            command.push_str(&format!(
                "; mv {} {}",
                shell_quote(&format!("{stage}/{path}")),
                shell_quote(&format!("{current}/{path}"))
            ));
        }
    }
    for path in plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            DeploymentOperation::RemoveFile { path } => Some(path),
            _ => None,
        })
    {
        let trash = format!(
            "{APP_ROOT}/trash/removed-{}-{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            path.replace('/', "_")
        );
        command.push_str(&format!(
            "; if test -e {source}; then mv {source} {trash}; fi",
            source = shell_quote(&format!("{current}/{path}")),
            trash = shell_quote(&trash)
        ));
    }
    command
}

fn prune_command(instance_id: Uuid, retention: usize) -> String {
    let root = format!("{APP_ROOT}/backups/{instance_id}");
    format!(
        "set -eu; if test -d {root}; then find {root} -mindepth 1 -maxdepth 1 -type d -print | sort -r | tail -n +{start} | xargs -r rm -rf --; fi",
        root = shell_quote(&root),
        start = retention + 1,
    )
}

fn firewall_allow_command(port: u16) -> String {
    format!(
        r#"set -eu
if command -v ufw >/dev/null 2>&1; then
  if sudo -n ufw status 2>/dev/null | grep -q '^Status: active'; then
    sudo -n ufw allow {port}/udp >/dev/null
  elif ! sudo -n ufw status >/dev/null 2>&1; then
    printf 'UFW is installed, but its status could not be checked with sudo -n.\n' >&2
    exit 43
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  sudo -n firewall-cmd --permanent --add-port={port}/udp >/dev/null
  sudo -n firewall-cmd --reload >/dev/null
fi
"#
    )
}

fn firewall_remove_command(port: u16) -> String {
    format!(
        r#"set -eu
if command -v ufw >/dev/null 2>&1; then
  if sudo -n ufw status 2>/dev/null | grep -q '^Status: active'; then
    sudo -n ufw delete allow {port}/udp >/dev/null 2>&1 || true
  elif ! sudo -n ufw status >/dev/null 2>&1; then
    printf 'UFW is installed, but its status could not be checked with sudo -n.\n' >&2
    exit 43
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  sudo -n firewall-cmd --permanent --remove-port={port}/udp >/dev/null 2>&1 || true
  sudo -n firewall-cmd --reload >/dev/null
fi
"#
    )
}

fn backup_path(instance_id: Uuid, name: &str) -> String {
    format!("{APP_ROOT}/backups/{instance_id}/{name}")
}

fn server_public_key_setting(instance_id: Uuid) -> String {
    format!("wireguard_server_public_key:{instance_id}")
}

fn parse_find_timestamp(value: &str) -> Option<chrono::DateTime<Utc>> {
    let (seconds, fractional) = value.split_once('.')?;
    let seconds = seconds.parse().ok()?;
    let mut nanos = fractional.chars().take(9).collect::<String>();
    while nanos.len() < 9 {
        nanos.push('0');
    }
    chrono::DateTime::from_timestamp(seconds, nanos.parse().ok()?)
}

fn health_is_healthy(health: &InstanceHealth) -> bool {
    health.compose_project_exists
        && health.gateway_running
        && health.dns_running
        && health.private_dns_resolves
        && health.public_dns_resolves
        && health.wireguard_interface_exists
        && health.listen_port_matches
        && health.expected_peers_present
}

fn parse_key_values(output: &str) -> HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().into(), value.trim().into()))
        .collect()
}

fn nonempty(value: Option<&String>) -> Option<String> {
    value.filter(|value| !value.is_empty()).cloned()
}

fn version_major(value: &str) -> Option<u64> {
    value
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()
}

fn slug(value: &str) -> String {
    let value: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    value.trim_matches('-').into()
}

async fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use tokio::{fs::OpenOptions, io::AsyncWriteExt};
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .await
            .map_err(io_error)?;
        file.write_all(contents).await.map_err(io_error)?;
        file.sync_all().await.map_err(io_error)?;
    }
    #[cfg(not(unix))]
    {
        tokio::fs::write(path, contents).await.map_err(io_error)?;
    }
    Ok(())
}

fn validation_error(message: &str) -> AppError {
    AppError {
        code: "validation".into(),
        message: message.into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Correct the highlighted values and try again.".into()),
        technical_detail: None,
    }
}

fn storage_error(error: StorageError) -> AppError {
    AppError {
        code: "storage".into(),
        message: match error {
            StorageError::NotFound => "The requested record was not found.".into(),
            StorageError::HostKeyChanged => "The SSH host key changed.".into(),
            _ => "Local persistence failed.".into(),
        },
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Check the local database and retry.".into()),
        technical_detail: Some(error.to_string()),
    }
}

fn secret_error(error: SecretStoreError) -> AppError {
    AppError {
        code: if matches!(error, SecretStoreError::NotFound) {
            "secret_missing"
        } else {
            "secret_store"
        }
        .into(),
        message: if matches!(error, SecretStoreError::NotFound) {
            "Required private material is missing from the macOS Keychain."
        } else {
            "The macOS Keychain operation failed."
        }
        .into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some(
            "Replace the affected device identity if the secret cannot be recovered.".into(),
        ),
        technical_detail: match error {
            SecretStoreError::NotFound => None,
            _ => Some(error.to_string()),
        },
    }
}

fn ssh_error(error: SshError) -> AppError {
    let code = match error {
        SshError::Cancelled => "cancelled",
        SshError::Timeout => "ssh_timeout",
        SshError::HostKeyUntrusted => "host_key_untrusted",
        SshError::HostKeyChanged => "host_key_changed",
        SshError::Authentication => "ssh_authentication",
        _ => "ssh",
    };
    AppError {
        code: code.into(),
        message: error.to_string(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Verify the host, approved key, SSH key file, and network.".into()),
        technical_detail: None,
    }
}

fn deployment_error(error: vam_deployment::DeploymentError) -> AppError {
    AppError {
        code: "deployment_render".into(),
        message: "The desired configuration could not be rendered.".into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Correct the invalid instance or DNS values.".into()),
        technical_detail: Some(error.to_string()),
    }
}

fn backend_error(error: vam_backend_wireguard::BackendError) -> AppError {
    AppError {
        code: "wireguard".into(),
        message: error.to_string(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Correct the WireGuard device data or replace missing secrets.".into()),
        technical_detail: None,
    }
}

fn serialization_error(error: serde_json::Error) -> AppError {
    AppError {
        code: "serialization".into(),
        message: "Structured state could not be encoded or decoded.".into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Inspect the local database and remote state manifest.".into()),
        technical_detail: Some(error.to_string()),
    }
}

fn command_error(scope: &str, result: &CommandResult, changed: bool) -> AppError {
    let stderr = String::from_utf8_lossy(&result.stderr);
    AppError {
        code: "remote_command".into(),
        message: "A fixed remote operation failed.".into(),
        scope: Some(scope.into()),
        remote_state_changed: changed,
        rollback_succeeded: None,
        remediation: Some("Expand the technical details and inspect the remote host.".into()),
        technical_detail: Some(redact(&stderr, &[])),
    }
}

fn io_error(error: std::io::Error) -> AppError {
    AppError {
        code: "file_export".into(),
        message: "The private configuration could not be exported.".into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Choose a writable destination and retry.".into()),
        technical_detail: Some(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;
    use vam_secrets::MemorySecretStore;

    struct FakeTransport {
        key: RwLock<HostKeyInfo>,
        commands: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl SshTransport for FakeTransport {
        async fn probe_host_key(
            &self,
            _config: &SshConnectionConfig,
            _cancellation: &CancellationToken,
        ) -> Result<HostKeyInfo, SshError> {
            Ok(self.key.read().expect("test lock").clone())
        }

        async fn execute(
            &self,
            _config: &SshConnectionConfig,
            trusted_key_base64: &str,
            _passphrase: Option<&Zeroizing<String>>,
            command: &str,
            _cancellation: &CancellationToken,
        ) -> Result<CommandResult, SshError> {
            if trusted_key_base64 != self.key.read().expect("test lock").public_key_base64 {
                return Err(SshError::HostKeyChanged);
            }
            self.commands
                .lock()
                .expect("test command lock")
                .push(command.to_owned());
            Ok(CommandResult {
                stdout: b"operating_system=Linux\narchitecture=x86_64\ndocker_version=29.0.0\ndocker_accessible=0\ncompose_version=5.3.1\nwireguard=0\nroot_writable=0\nsudo_bootstrap=1\n".to_vec(),
                stderr: Vec::new(),
                exit_status: 0,
            })
        }

        async fn upload(&self, _request: UploadRequest<'_>) -> Result<(), SshError> {
            Ok(())
        }
    }

    #[test]
    fn activation_paths_are_shell_quoted() {
        let plan = DeploymentPlan {
            id: Uuid::nil(),
            instance_id: Uuid::nil(),
            operations: vec![DeploymentOperation::UploadFile {
                path: "dns/zones/db.vpn.internal".into(),
                sensitive: false,
            }],
            warnings: vec![],
            desired_state_hash: "hash".into(),
        };
        let files = vec![RenderedFile {
            path: "dns/zones/db.vpn.internal".into(),
            contents: String::new(),
            mode: 0o644,
            sensitive: false,
        }];
        let command = activation_command("/safe/current", "/safe/stage", &files, &plan);
        assert!(command.contains("'/safe/stage/dns/zones/db.vpn.internal'"));
        assert!(!command.contains("$(bad)"));
    }

    #[test]
    fn firewall_commands_manage_active_ufw_and_firewalld_idempotently() {
        let allow = firewall_allow_command(51_820);
        assert!(allow.contains("sudo -n ufw status"));
        assert!(allow.contains("sudo -n ufw allow 51820/udp"));
        assert!(allow.contains("firewall-cmd --state"));
        assert!(allow.contains("sudo -n firewall-cmd --permanent --add-port=51820/udp"));
        assert!(allow.contains("sudo -n firewall-cmd --reload"));

        let remove = firewall_remove_command(51_820);
        assert!(remove.contains("sudo -n ufw delete allow 51820/udp"));
        assert!(remove.contains("|| true"));
        assert!(remove.contains("sudo -n firewall-cmd --permanent --remove-port=51820/udp"));
    }

    #[tokio::test]
    async fn service_round_trips_local_models() {
        let storage = Storage::in_memory().await.unwrap();
        let service = ApplicationService::with_transport(
            storage,
            Arc::new(MemorySecretStore::default()),
            Arc::new(RusshTransport::default()),
        );
        let host = service
            .create_host(CreateHostInput {
                display_name: "lab".into(),
                hostname: "192.0.2.1".into(),
                port: 22,
                username: "tester".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase: None,
            })
            .await
            .unwrap();
        let instance = service
            .create_instance(CreateInstanceInput {
                host_id: host.id,
                display_name: "private".into(),
                endpoint_host: "vpn.example.test".into(),
                endpoint_port: DEFAULT_PORT,
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: DEFAULT_DNS_ZONE.into(),
                routing_mode: None,
            })
            .await
            .unwrap();
        assert_eq!(service.list_instances(None).await.unwrap(), vec![instance]);
    }

    #[tokio::test]
    async fn redacted_planning_render_does_not_read_device_secrets() {
        let storage = Storage::in_memory().await.unwrap();
        let secrets = Arc::new(MemorySecretStore::default());
        let service = ApplicationService::with_transport(
            storage,
            secrets.clone(),
            Arc::new(RusshTransport::default()),
        );
        let host = service
            .create_host(CreateHostInput {
                display_name: "lab".into(),
                hostname: "192.0.2.1".into(),
                port: 22,
                username: "tester".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase: None,
            })
            .await
            .unwrap();
        let instance = service
            .create_instance(CreateInstanceInput {
                host_id: host.id,
                display_name: "private".into(),
                endpoint_host: "vpn.example.test".into(),
                endpoint_port: DEFAULT_PORT,
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: DEFAULT_DNS_ZONE.into(),
                routing_mode: None,
            })
            .await
            .unwrap();
        let device = service
            .create_device(CreateDeviceInput {
                instance_id: instance.id,
                user_id: None,
                display_name: "laptop".into(),
                preshared_key: true,
                create_dns_record: false,
                dns_name: None,
            })
            .await
            .unwrap();
        let DeviceBackendData::WireGuard(data) = &device.backend_data;
        secrets.delete(&data.private_key_ref).await.unwrap();
        secrets
            .delete(data.preshared_key_ref.as_ref().unwrap())
            .await
            .unwrap();

        let state = service.desired_state(instance.id).await.unwrap();
        assert_eq!(
            service.render_state(&state).await.unwrap_err().code,
            "secret_missing"
        );
        let files = service.render_state_for_plan(&state).await.unwrap();
        assert!(
            files
                .iter()
                .any(|file| file.path == "vpn/wg0.conf.template")
        );
    }

    #[tokio::test]
    async fn host_key_requires_approval_and_changed_key_is_distinct() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = Arc::new(FakeTransport {
            key: RwLock::new(HostKeyInfo {
                hostname: "lab".into(),
                resolved_address: "192.0.2.1".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                sha256_fingerprint: "SHA256:first".into(),
                public_key_base64: "first-key".into(),
            }),
            commands: std::sync::Mutex::new(Vec::new()),
        });
        let service = ApplicationService::with_transport(
            storage,
            Arc::new(MemorySecretStore::default()),
            fake.clone(),
        );
        let host = service
            .create_host(CreateHostInput {
                display_name: "lab".into(),
                hostname: "lab".into(),
                port: 22,
                username: "tester".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase: None,
            })
            .await
            .unwrap();
        assert_eq!(
            service.probe_host_key(host.id).await.unwrap().state,
            HostKeyState::Unknown
        );
        assert_eq!(
            service.inspect_host(host.id).await.unwrap_err().code,
            "host_key_untrusted"
        );
        let probe = service.probe_host_key(host.id).await.unwrap();
        service
            .approve_host_key(host.id, probe.key, "SHA256:first", false)
            .await
            .unwrap();
        assert!(
            service
                .inspect_host(host.id)
                .await
                .unwrap()
                .docker_accessible
        );

        *fake.key.write().expect("test lock") = HostKeyInfo {
            hostname: "lab".into(),
            resolved_address: "192.0.2.1".into(),
            port: 22,
            algorithm: "ssh-ed25519".into(),
            sha256_fingerprint: "SHA256:replacement".into(),
            public_key_base64: "replacement-key".into(),
        };
        assert_eq!(
            service.probe_host_key(host.id).await.unwrap().state,
            HostKeyState::Changed
        );
        assert_eq!(
            service.inspect_host(host.id).await.unwrap_err().code,
            "host_key_changed"
        );
    }

    #[tokio::test]
    async fn stop_reports_stopped_state_without_waiting_for_running_health() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = Arc::new(FakeTransport {
            key: RwLock::new(HostKeyInfo {
                hostname: "lab".into(),
                resolved_address: "192.0.2.1".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                sha256_fingerprint: "SHA256:first".into(),
                public_key_base64: "first-key".into(),
            }),
            commands: std::sync::Mutex::new(Vec::new()),
        });
        let service = ApplicationService::with_transport(
            storage,
            Arc::new(MemorySecretStore::default()),
            fake.clone(),
        );
        let host = service
            .create_host(CreateHostInput {
                display_name: "lab".into(),
                hostname: "lab".into(),
                port: 22,
                username: "tester".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase: None,
            })
            .await
            .unwrap();
        let probe = service.probe_host_key(host.id).await.unwrap();
        service
            .approve_host_key(host.id, probe.key, "SHA256:first", false)
            .await
            .unwrap();
        let instance = service
            .create_instance(CreateInstanceInput {
                host_id: host.id,
                display_name: "private".into(),
                endpoint_host: "vpn.example.test".into(),
                endpoint_port: DEFAULT_PORT,
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: DEFAULT_DNS_ZONE.into(),
                routing_mode: None,
            })
            .await
            .unwrap();

        let health = service.stop_instance(instance.id).await.unwrap();
        assert!(!health.gateway_running);
        let commands = fake.commands.lock().expect("test command lock");
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("docker compose stop"));
        assert!(commands[1].contains("docker compose ps --status running"));
    }
}
