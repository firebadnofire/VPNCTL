#[cfg(not(test))]
use std::collections::BTreeSet;
use std::{
    collections::HashMap,
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use qrcode::{QrCode, render::svg};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(not(test))]
use tokio::time::timeout;
use tokio::{sync::Mutex, time::sleep};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_backend::{
    BackendError, BackendHealthProbe, BackendRegistry, BackendRuntimeSpec, BackendValidation,
    ChangeImpact, ContainerImage, ContainerMountOwnership, CredentialAction, CredentialOperation,
    ServerIdentityStrategy, VpnBackend,
};
use vam_backend_amneziawg::AmneziaWgBackend;
use vam_backend_ikev2::Ikev2Backend;
use vam_backend_openvpn::OpenVpnBackend;
use vam_backend_wireguard::WireGuardBackend;
use vam_backend_xray::{REALITY_PUBLIC_KEY_PATH, REALITY_SHORT_ID_PATH, XrayBackend};
#[cfg(test)]
use vam_core::DEFAULT_PORT;
use vam_core::{
    AmneziaWgDeviceData, AmneziaWgSettings, BackendSettings, DEFAULT_DNS_ZONE, DEFAULT_KEEPALIVE,
    DEFAULT_SUBNET, DesiredState, Device, DeviceBackendData, DnsConfig, DnsRecord, DnsRecordType,
    DockerHost, EndpointConfig, Ikev2DeviceData, Ikev2Settings, ListenerPort, NetworkConfig,
    OpenVpnDeviceData, OpenVpnSettings, OpenVpnTlsProtection, RoutingMode, SecretReference,
    SshConnectionConfig, TransportProtocol, User, VpnBackendKind, VpnInstance, WireGuardDeviceData,
    WireGuardSettings, XraySecurity, XrayTransport, allocate_next_ipv4, first_usable,
    validate_host_instances, validate_instance,
};
use vam_deployment::{
    COREDNS_IMAGE, DeploymentExecutor, DeploymentPlanner, RemoteManifest, build_manifest,
    shell_quote,
};
#[cfg(not(test))]
use vam_dns::parse_hostslist_domains;
use vam_dns::{next_soa_serial, validate_records};
use vam_protocol::{
    AppError, BackupInfo, ClientArtifact, DeploymentOperation, DeploymentPlan, DeploymentProgress,
    DeploymentResult, DeploymentStatus, DeploymentSummary, HostInspection, HostKeyInfo,
    HostKeyProbe, HostKeyState, HostProvisioningOperation, HostProvisioningPlan, InstanceHealth,
    PackageManager, RenderedFile, redact,
};
use vam_secrets::{SecretStore, SecretStoreError};
#[cfg(test)]
use vam_ssh::DownloadRequest;
use vam_ssh::{CommandResult, RusshTransport, SshError, SshTransport, UploadRequest};
use vam_storage::{Storage, StorageError};
use zeroize::Zeroizing;

const APP_ROOT: &str = "/opt/vpn-appliance-manager";
const BACKUP_RETENTION: usize = 10;
const DNS_HOSTLISTS_SETTING: &str = "dns_hostlists";
#[cfg(not(test))]
const HOSTLIST_CACHE_MAX_AGE: Duration = Duration::from_hours(24);
#[cfg(not(test))]
const HOSTLIST_FETCH_TIMEOUT: Duration = Duration::from_secs(8);

#[cfg(not(test))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedHostlist {
    url: String,
    fetched_at: chrono::DateTime<Utc>,
    domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsHostlist {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub coverage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDnsHostlistInput {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub coverage: String,
}

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
    #[serde(default = "default_backend")]
    pub backend: VpnBackendKind,
    #[serde(default)]
    pub backend_settings: Option<BackendSettingsInput>,
    #[serde(default)]
    pub endpoint_port: Option<u16>,
    #[serde(default = "default_subnet")]
    pub ipv4_subnet: String,
    #[serde(default = "default_zone")]
    pub dns_zone: String,
    #[serde(default)]
    pub routing_mode: Option<RoutingMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", content = "settings")]
pub enum BackendSettingsInput {
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardSettings),
    #[serde(rename = "amnezia_wg")]
    AmneziaWg(AmneziaWgSettings),
    #[serde(rename = "openvpn")]
    OpenVpn(OpenVpnSettings),
    #[serde(rename = "ikev2")]
    Ikev2(Ikev2Settings),
    #[serde(rename = "xray")]
    Xray(PublicXraySettings),
}

impl BackendSettingsInput {
    #[must_use]
    pub const fn kind(&self) -> VpnBackendKind {
        match self {
            Self::WireGuard(_) => VpnBackendKind::WireGuard,
            Self::AmneziaWg(_) => VpnBackendKind::AmneziaWg,
            Self::OpenVpn(_) => VpnBackendKind::OpenVpn,
            Self::Ikev2(_) => VpnBackendKind::Ikev2,
            Self::Xray(_) => VpnBackendKind::Xray,
        }
    }

    #[must_use]
    pub fn into_backend_settings(self) -> BackendSettings {
        match self {
            Self::WireGuard(settings) => BackendSettings::WireGuard(settings),
            Self::AmneziaWg(settings) => BackendSettings::AmneziaWg(settings),
            Self::OpenVpn(settings) => BackendSettings::OpenVpn(settings),
            Self::Ikev2(settings) => BackendSettings::Ikev2(settings),
            Self::Xray(settings) => BackendSettings::Xray(settings.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicXraySettings {
    pub security: XraySecurity,
    pub transport: XrayTransport,
    pub server_name: String,
    pub fingerprint: String,
    pub xhttp_path: String,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
}

impl From<PublicXraySettings> for vam_core::XraySettings {
    fn from(settings: PublicXraySettings) -> Self {
        Self {
            security: settings.security,
            transport: settings.transport,
            server_name: settings.server_name,
            fingerprint: settings.fingerprint,
            xhttp_path: settings.xhttp_path,
            reality_public_key: settings.reality_public_key,
            reality_short_id: settings.reality_short_id,
            tls_certificate_ref: None,
            tls_private_key_ref: None,
        }
    }
}

impl From<&BackendSettings> for BackendSettingsInput {
    fn from(settings: &BackendSettings) -> Self {
        match settings {
            BackendSettings::WireGuard(settings) => Self::WireGuard(*settings),
            BackendSettings::AmneziaWg(settings) => Self::AmneziaWg(settings.clone()),
            BackendSettings::OpenVpn(settings) => Self::OpenVpn(settings.clone()),
            BackendSettings::Ikev2(settings) => Self::Ikev2(settings.clone()),
            BackendSettings::Xray(settings) => Self::Xray(PublicXraySettings {
                security: settings.security,
                transport: settings.transport,
                server_name: settings.server_name.clone(),
                fingerprint: settings.fingerprint.clone(),
                xhttp_path: settings.xhttp_path.clone(),
                reality_public_key: settings.reality_public_key.clone(),
                reality_short_id: settings.reality_short_id.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceView {
    pub id: Uuid,
    pub host_id: Uuid,
    pub display_name: String,
    pub backend: VpnBackendKind,
    pub backend_settings: BackendSettingsInput,
    pub endpoint: EndpointConfig,
    pub network: NetworkConfig,
    pub dns: DnsConfig,
    pub routing_mode: RoutingMode,
    pub persistent_keepalive: u16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&VpnInstance> for InstanceView {
    fn from(instance: &VpnInstance) -> Self {
        Self {
            id: instance.id,
            host_id: instance.host_id,
            display_name: instance.display_name.clone(),
            backend: instance.backend,
            backend_settings: BackendSettingsInput::from(&instance.backend_settings),
            endpoint: instance.endpoint.clone(),
            network: instance.network.clone(),
            dns: instance.dns.clone(),
            routing_mode: instance.routing_mode,
            persistent_keepalive: instance.persistent_keepalive,
            created_at: instance.created_at,
            updated_at: instance.updated_at,
        }
    }
}

const fn default_backend() -> VpnBackendKind {
    VpnBackendKind::WireGuard
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", content = "identity")]
pub enum DevicePublicIdentity {
    #[serde(rename = "wireguard")]
    WireGuard {
        public_key: String,
        preshared_key: bool,
    },
    #[serde(rename = "amnezia_wg")]
    AmneziaWg { public_key: String },
    #[serde(rename = "openvpn")]
    OpenVpn {
        common_name: String,
        certificate_serial: Option<String>,
    },
    #[serde(rename = "ikev2")]
    Ikev2 {
        identity: String,
        certificate_serial: Option<String>,
    },
    #[serde(rename = "xray")]
    Xray { email: String, flow: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceView {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub user_id: Option<Uuid>,
    pub display_name: String,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub dns_name: Option<String>,
    pub enabled: bool,
    pub backend: VpnBackendKind,
    pub public_identity: DevicePublicIdentity,
    pub created_at: DateTime<Utc>,
}

impl From<&Device> for DeviceView {
    fn from(device: &Device) -> Self {
        let public_identity = match &device.backend_data {
            DeviceBackendData::WireGuard(data) => DevicePublicIdentity::WireGuard {
                public_key: data.public_key.clone(),
                preshared_key: data.preshared_key_ref.is_some(),
            },
            DeviceBackendData::AmneziaWg(data) => DevicePublicIdentity::AmneziaWg {
                public_key: data.public_key.clone(),
            },
            DeviceBackendData::OpenVpn(data) => DevicePublicIdentity::OpenVpn {
                common_name: data.common_name.clone(),
                certificate_serial: data.certificate_serial.clone(),
            },
            DeviceBackendData::Ikev2(data) => DevicePublicIdentity::Ikev2 {
                identity: data.identity.clone(),
                certificate_serial: data.certificate_serial.clone(),
            },
            DeviceBackendData::Xray(data) => DevicePublicIdentity::Xray {
                email: data.email.clone(),
                flow: data.flow.clone(),
            },
        };
        Self {
            id: device.id,
            instance_id: device.instance_id,
            user_id: device.user_id,
            display_name: device.display_name.clone(),
            ipv4_address: device.ipv4_address,
            ipv6_address: device.ipv6_address,
            dns_name: device.dns_name.clone(),
            enabled: device.enabled,
            backend: device.backend_data.kind(),
            public_identity,
            created_at: device.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDeviceInput {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub display_name: String,
    pub dns_name: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendCapabilitiesView {
    pub allocated_tunnel_addresses: bool,
    pub managed_dns: bool,
    pub quick_credential_refresh: bool,
    pub live_identity_updates: bool,
    pub qr_export: bool,
    pub traffic_statistics: bool,
    pub certificate_authority: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendOptionView {
    pub kind: VpnBackendKind,
    pub display_name: String,
    pub default_port: u16,
    pub capabilities: BackendCapabilitiesView,
}

struct PendingSecret {
    reference: SecretReference,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct CredentialExecutionOutcome {
    certificate_serial: Option<String>,
    backup_path: Option<String>,
}

const fn default_true() -> bool {
    true
}

fn pending_text_secret(reference: SecretReference, value: &Zeroizing<String>) -> PendingSecret {
    PendingSecret {
        reference,
        value: Zeroizing::new(value.as_bytes().to_vec()),
    }
}

fn generate_device_identity(
    instance: &VpnInstance,
    display_name: &str,
    device_id: Uuid,
    preshared_key: bool,
) -> Result<(DeviceBackendData, Vec<PendingSecret>), BackendError> {
    match instance.backend {
        VpnBackendKind::WireGuard => {
            let (private, public) = WireGuardBackend::generate_device_keys();
            let private_key_ref = SecretReference(Uuid::new_v4());
            let mut secrets = vec![pending_text_secret(private_key_ref.clone(), &private)];
            let preshared_key_ref = if preshared_key {
                let reference = SecretReference(Uuid::new_v4());
                let psk = WireGuardBackend::generate_preshared_key();
                secrets.push(pending_text_secret(reference.clone(), &psk));
                Some(reference)
            } else {
                None
            };
            Ok((
                DeviceBackendData::WireGuard(WireGuardDeviceData {
                    public_key: public,
                    private_key_ref,
                    preshared_key_ref,
                }),
                secrets,
            ))
        }
        VpnBackendKind::AmneziaWg => {
            let (private, public) = AmneziaWgBackend::generate_device_keys();
            let private_key_ref = SecretReference(Uuid::new_v4());
            let preshared_key_ref = SecretReference(Uuid::new_v4());
            let psk = AmneziaWgBackend::generate_preshared_key();
            Ok((
                DeviceBackendData::AmneziaWg(AmneziaWgDeviceData {
                    public_key: public,
                    private_key_ref: private_key_ref.clone(),
                    preshared_key_ref: preshared_key_ref.clone(),
                }),
                vec![
                    pending_text_secret(private_key_ref, &private),
                    pending_text_secret(preshared_key_ref, &psk),
                ],
            ))
        }
        VpnBackendKind::OpenVpn => {
            let generated = OpenVpnBackend::generate_identity(display_name, device_id)?;
            let private_key_ref = SecretReference(Uuid::new_v4());
            let csr_ref = SecretReference(Uuid::new_v4());
            let certificate_ref = SecretReference(Uuid::new_v4());
            let ca_certificate_ref = SecretReference(Uuid::new_v4());
            let tls_crypt_key_ref = match &instance.backend_settings {
                BackendSettings::OpenVpn(settings)
                    if settings.tls_protection == OpenVpnTlsProtection::TlsCrypt =>
                {
                    Some(SecretReference(Uuid::new_v4()))
                }
                BackendSettings::OpenVpn(_) => None,
                _ => return Err(BackendError::BackendMismatch(instance.backend)),
            };
            Ok((
                DeviceBackendData::OpenVpn(OpenVpnDeviceData {
                    common_name: generated.common_name,
                    private_key_ref: private_key_ref.clone(),
                    csr_ref: csr_ref.clone(),
                    certificate_ref,
                    ca_certificate_ref,
                    tls_crypt_key_ref,
                    certificate_serial: None,
                }),
                vec![
                    pending_text_secret(private_key_ref, &generated.private_key),
                    pending_text_secret(csr_ref, &generated.csr),
                ],
            ))
        }
        VpnBackendKind::Ikev2 => {
            let generated = Ikev2Backend::generate_identity(display_name, device_id)?;
            let private_key_ref = SecretReference(Uuid::new_v4());
            let csr_ref = SecretReference(Uuid::new_v4());
            let certificate_ref = SecretReference(Uuid::new_v4());
            let ca_certificate_ref = SecretReference(Uuid::new_v4());
            let bundle_password_ref = SecretReference(Uuid::new_v4());
            Ok((
                DeviceBackendData::Ikev2(Ikev2DeviceData {
                    identity: generated.identity,
                    private_key_ref: Some(private_key_ref.clone()),
                    csr_ref: Some(csr_ref.clone()),
                    certificate_ref: Some(certificate_ref),
                    ca_certificate_ref: Some(ca_certificate_ref),
                    bundle_password_ref: bundle_password_ref.clone(),
                    certificate_serial: None,
                }),
                vec![
                    pending_text_secret(private_key_ref, &generated.private_key),
                    pending_text_secret(csr_ref, &generated.csr),
                    pending_text_secret(bundle_password_ref, &generated.bundle_password),
                ],
            ))
        }
        VpnBackendKind::Xray => {
            let BackendSettings::Xray(settings) = &instance.backend_settings else {
                return Err(BackendError::BackendMismatch(instance.backend));
            };
            let client_id_ref = SecretReference(Uuid::new_v4());
            let client_id = Zeroizing::new(Uuid::new_v4().to_string());
            Ok((
                DeviceBackendData::Xray(XrayBackend::generate_identity(
                    display_name,
                    device_id,
                    settings.transport,
                    client_id_ref.clone(),
                )),
                vec![pending_text_secret(client_id_ref, &client_id)],
            ))
        }
    }
}

fn device_secret_registrations(device: &Device) -> Vec<(Uuid, String)> {
    match &device.backend_data {
        DeviceBackendData::WireGuard(data) => {
            let mut values = vec![(data.private_key_ref.0, "wireguard_private_key".to_owned())];
            values.extend(
                data.preshared_key_ref
                    .iter()
                    .map(|reference| (reference.0, "wireguard_preshared_key".to_owned())),
            );
            values
        }
        DeviceBackendData::AmneziaWg(data) => vec![
            (data.private_key_ref.0, "amneziawg_private_key".to_owned()),
            (
                data.preshared_key_ref.0,
                "amneziawg_preshared_key".to_owned(),
            ),
        ],
        DeviceBackendData::OpenVpn(data) => {
            let mut values = vec![
                (data.private_key_ref.0, "openvpn_private_key".to_owned()),
                (data.csr_ref.0, "openvpn_csr".to_owned()),
                (data.certificate_ref.0, "openvpn_certificate".to_owned()),
                (
                    data.ca_certificate_ref.0,
                    "openvpn_ca_certificate".to_owned(),
                ),
            ];
            values.extend(
                data.tls_crypt_key_ref
                    .iter()
                    .map(|reference| (reference.0, "openvpn_tls_crypt_key".to_owned())),
            );
            values
        }
        DeviceBackendData::Ikev2(data) => {
            let mut values = vec![(
                data.bundle_password_ref.0,
                "ikev2_pkcs12_password".to_owned(),
            )];
            values.extend(
                data.private_key_ref
                    .iter()
                    .map(|reference| (reference.0, "ikev2_private_key".to_owned())),
            );
            values.extend(
                data.csr_ref
                    .iter()
                    .map(|reference| (reference.0, "ikev2_csr".to_owned())),
            );
            values.extend(
                data.certificate_ref
                    .iter()
                    .map(|reference| (reference.0, "ikev2_certificate".to_owned())),
            );
            values.extend(
                data.ca_certificate_ref
                    .iter()
                    .map(|reference| (reference.0, "ikev2_ca_certificate".to_owned())),
            );
            values
        }
        DeviceBackendData::Xray(data) => {
            vec![(data.client_id_ref.0, "xray_client_id".to_owned())]
        }
    }
}

fn certificate_identity_metadata(
    device: &Device,
) -> Result<(String, Option<String>), BackendError> {
    match &device.backend_data {
        DeviceBackendData::OpenVpn(data) => {
            Ok((data.common_name.clone(), data.certificate_serial.clone()))
        }
        DeviceBackendData::Ikev2(data) => {
            Ok((data.identity.clone(), data.certificate_serial.clone()))
        }
        data => Err(BackendError::BackendMismatch(data.kind())),
    }
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
    backends: Arc<BackendRegistry>,
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
        let backends: [Arc<dyn VpnBackend>; 5] = [
            Arc::new(WireGuardBackend),
            Arc::new(AmneziaWgBackend),
            Arc::new(OpenVpnBackend),
            Arc::new(Ikev2Backend),
            Arc::new(XrayBackend),
        ];
        Self {
            storage,
            secrets,
            transport,
            backends: Arc::new(BackendRegistry::new(backends)),
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
if command -v apt-get >/dev/null 2>&1; then
  printf 'package_manager=apt\n'
elif command -v dnf >/dev/null 2>&1; then
  printf 'package_manager=dnf\n'
elif command -v yum >/dev/null 2>&1; then
  printf 'package_manager=yum\n'
elif command -v zypper >/dev/null 2>&1; then
  printf 'package_manager=zypper\n'
elif command -v pacman >/dev/null 2>&1; then
  printf 'package_manager=pacman\n'
else
  printf 'package_manager=\n'
fi
test "$(id -u)" -eq 0
printf 'effective_user_is_root=%s\n' "$?"
id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker
printf 'docker_group_member=%s\n' "$?"
if command -v docker >/dev/null 2>&1; then
  printf 'docker_installed=0\n'
  printf 'docker_version='; docker version --format '{{.Server.Version}}' 2>/dev/null
  docker info >/dev/null 2>&1; printf 'docker_accessible=%s\n' "$?"
  printf 'compose_version='; docker compose version --short 2>/dev/null
else
  printf 'docker_installed=127\ndocker_version=\ncompose_version=\ndocker_accessible=127\n'
fi
if test "$(id -u)" -eq 0; then
  docker info >/dev/null 2>&1
  printf 'docker_privileged_accessible=%s\n' "$?"
elif sudo -n true >/dev/null 2>&1; then
  sudo -n docker info >/dev/null 2>&1
  printf 'docker_privileged_accessible=%s\n' "$?"
else
  printf 'docker_privileged_accessible=127\n'
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
        if result.exit_status != 0 {
            return Err(command_error("inspect_host", &result, false));
        }
        let values = parse_key_values(&result.stdout_text().map_err(ssh_error)?);
        let docker_version = nonempty(values.get("docker_version"));
        let compose_version = nonempty(values.get("compose_version"));
        let docker_installed = values
            .get("docker_installed")
            .is_some_and(|value| value == "0");
        let docker_accessible = values
            .get("docker_accessible")
            .is_some_and(|value| value == "0");
        let package_manager = match values.get("package_manager").map(String::as_str) {
            Some("apt") => Some(PackageManager::Apt),
            Some("dnf") => Some(PackageManager::Dnf),
            Some("yum") => Some(PackageManager::Yum),
            Some("zypper") => Some(PackageManager::Zypper),
            Some("pacman") => Some(PackageManager::Pacman),
            _ => None,
        };
        let operating_system = values.get("operating_system").cloned().unwrap_or_default();
        let mut warnings = Vec::new();
        if operating_system != "Linux" {
            warnings.push("The target is not Linux.".into());
        }
        if !docker_installed {
            warnings.push("Docker Engine was not detected.".into());
        } else if docker_version.is_none() {
            warnings
                .push("Docker Engine is installed, but its server version is unavailable.".into());
        }
        if compose_version.is_none() {
            warnings.push("The Docker Compose plugin was not detected.".into());
        }
        if !docker_accessible {
            warnings.push("The SSH user cannot access Docker directly.".into());
        }
        if operating_system == "Linux" && package_manager.is_none() {
            warnings.push(
                "No supported package manager (apt, dnf, yum, zypper, or pacman) was detected."
                    .into(),
            );
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
            package_manager,
            effective_user_is_root: values
                .get("effective_user_is_root")
                .is_some_and(|value| value == "0"),
            docker_installed,
            docker_version,
            compose_version,
            docker_accessible,
            docker_privileged_accessible: values
                .get("docker_privileged_accessible")
                .is_some_and(|value| value == "0"),
            docker_group_member: values
                .get("docker_group_member")
                .is_some_and(|value| value == "0"),
            wireguard_kernel_available: values.get("wireguard").is_some_and(|value| value == "0"),
            application_root_writable: values
                .get("root_writable")
                .is_some_and(|value| value == "0"),
            sudo_bootstrap_available: sudo_available,
            warnings,
        })
    }

    pub async fn plan_host_provisioning(
        &self,
        host_id: Uuid,
    ) -> Result<HostProvisioningPlan, AppError> {
        let inspection = self.inspect_host(host_id).await?;
        build_host_provisioning_plan(host_id, &inspection)
            .map_err(|error| host_provisioning_error(host_id, error))
    }

    pub async fn apply_host_provisioning(
        &self,
        host_id: Uuid,
        expected_state_hash: &str,
    ) -> Result<HostInspection, AppError> {
        let plan = self.plan_host_provisioning(host_id).await?;
        if plan.expected_state_hash != expected_state_hash {
            return Err(AppError {
                code: "host_provisioning_plan_stale".into(),
                message: "The host prerequisite state changed after the setup preview.".into(),
                scope: Some(host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Inspect the host and review a new setup plan.".into()),
                technical_detail: None,
            });
        }
        if plan.operations.is_empty() {
            return self.inspect_host(host_id).await;
        }

        let command = host_provisioning_script(plan.package_manager, &plan.operations)
            .map_err(|error| host_provisioning_error(host_id, error))?;
        let (host, trusted, passphrase) = self.trusted_host(host_id).await?;
        if let Err(mut error) = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &command,
                &CancellationToken::new(),
            )
            .await
        {
            error.scope = Some(host_id.to_string());
            error.remote_state_changed = true;
            error.remediation = Some(
                "Inspect the remote package-manager and Docker service logs, then create a new setup preview."
                    .into(),
            );
            return Err(error);
        }

        let inspection = self.inspect_host(host_id).await?;
        if !host_deployment_prerequisites_ready(&inspection) {
            return Err(AppError {
                code: "host_provisioning_verification_failed".into(),
                message: "Host setup completed, but a fresh SSH check still failed prerequisites."
                    .into(),
                scope: Some(host_id.to_string()),
                remote_state_changed: true,
                rollback_succeeded: None,
                remediation: Some(
                    "Reconnect manually and verify Docker group membership, the Docker service, and Docker Compose v2."
                        .into(),
                ),
                technical_detail: Some(inspection.warnings.join("; ")),
            });
        }
        Ok(inspection)
    }

    pub async fn create_instance(
        &self,
        input: CreateInstanceInput,
    ) -> Result<VpnInstance, AppError> {
        self.storage
            .get_host(input.host_id)
            .await
            .map_err(storage_error)?;
        let endpoint_host = input.endpoint_host.trim().to_owned();
        let backend_settings = match input.backend_settings {
            Some(settings) if settings.kind() == input.backend => settings.into_backend_settings(),
            Some(_) => {
                return Err(validation_error(
                    "Backend settings do not match the selected backend.",
                ));
            }
            None => BackendSettings::defaults_for(input.backend, &endpoint_host),
        };
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
            backend: input.backend,
            backend_settings,
            endpoint: EndpointConfig {
                host: endpoint_host,
                port: input
                    .endpoint_port
                    .unwrap_or_else(|| input.backend.default_port()),
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
        self.backends
            .get(instance.backend)
            .map_err(backend_error)?
            .validate(&DesiredState {
                instance: instance.clone(),
                users: Vec::new(),
                devices: Vec::new(),
                dns_records: Vec::new(),
                dns_blocklist_domains: Vec::new(),
            })
            .map_err(backend_error)?;
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

    pub async fn create_instance_view(
        &self,
        input: CreateInstanceInput,
    ) -> Result<InstanceView, AppError> {
        let instance = self.create_instance(input).await?;
        Ok(InstanceView::from(&instance))
    }

    pub async fn list_instance_views(
        &self,
        host_id: Option<Uuid>,
    ) -> Result<Vec<InstanceView>, AppError> {
        Ok(self
            .list_instances(host_id)
            .await?
            .iter()
            .map(InstanceView::from)
            .collect())
    }

    pub fn backend_options(&self) -> Vec<BackendOptionView> {
        [
            VpnBackendKind::WireGuard,
            VpnBackendKind::AmneziaWg,
            VpnBackendKind::OpenVpn,
            VpnBackendKind::Ikev2,
            VpnBackendKind::Xray,
        ]
        .into_iter()
        .filter_map(|kind| {
            self.backends
                .capabilities(kind)
                .map(|capabilities| BackendOptionView {
                    kind,
                    display_name: kind.display_name().into(),
                    default_port: kind.default_port(),
                    capabilities: BackendCapabilitiesView {
                        allocated_tunnel_addresses: capabilities.allocated_tunnel_addresses,
                        managed_dns: capabilities.managed_dns,
                        quick_credential_refresh: capabilities.quick_credential_refresh,
                        live_identity_updates: capabilities.live_identity_updates,
                        qr_export: capabilities.qr_export,
                        traffic_statistics: capabilities.traffic_statistics,
                        certificate_authority: capabilities.certificate_authority,
                    },
                })
        })
        .collect()
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
        let lock = self.instance_lock(input.instance_id).await;
        let _guard = lock.lock().await;
        let instance = self
            .storage
            .get_instance(input.instance_id)
            .await
            .map_err(storage_error)?;
        let backend = self.backends.get(instance.backend).map_err(backend_error)?;
        let capabilities = backend.capabilities();
        let devices = self
            .storage
            .list_devices(input.instance_id)
            .await
            .map_err(storage_error)?;
        let address = if capabilities.allocated_tunnel_addresses {
            Some(
                allocate_next_ipv4(
                    instance.network.ipv4_subnet,
                    instance.network.gateway_ipv4,
                    &devices,
                )
                .map_err(|error| validation_error(&error.to_string()))?,
            )
        } else {
            None
        };
        let dns_name = if capabilities.managed_dns {
            input
                .dns_name
                .as_deref()
                .map(|value| normalize_dns_owner(value, &instance.dns.zone))
                .transpose()
                .map_err(|error| validation_error(&error))?
                .flatten()
        } else {
            None
        };
        let device_id = Uuid::new_v4();
        let (backend_data, pending_secrets) = generate_device_identity(
            &instance,
            input.display_name.trim(),
            device_id,
            input.preshared_key,
        )
        .map_err(backend_error)?;
        let mut device = Device {
            id: device_id,
            instance_id: input.instance_id,
            user_id: input.user_id,
            display_name: input.display_name.trim().into(),
            ipv4_address: address,
            ipv6_address: None,
            dns_name,
            enabled: true,
            backend_data,
            created_at: Utc::now(),
            deleted_at: None,
        };
        let mut candidate_state = self.desired_state(instance.id).await?;
        candidate_state.devices.push(device.clone());
        backend.validate(&candidate_state).map_err(backend_error)?;
        self.store_pending_secrets(&pending_secrets).await?;
        let credential_outcome = if capabilities.certificate_authority {
            let outcome = match self
                .issue_certificate_device(&candidate_state, &mut device)
                .await
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.delete_device_secrets(&device).await;
                    return Err(error);
                }
            };
            candidate_state.devices.pop();
            candidate_state.devices.push(device.clone());
            if let Err(error) = self
                .validate_certificate_client(&candidate_state, &device)
                .await
            {
                let _ = self
                    .restore_credential_outcome(&candidate_state, &outcome)
                    .await;
                self.delete_device_secrets(&device).await;
                return Err(error);
            }
            Some(outcome)
        } else {
            None
        };
        let dns_record = if input.create_dns_record && capabilities.managed_dns {
            let address = device.ipv4_address.ok_or_else(|| {
                validation_error("This backend cannot create a managed tunnel-address record.")
            })?;
            let name = device
                .dns_name
                .clone()
                .unwrap_or_else(|| format!("{}.{}", slug(&device.display_name), instance.dns.zone));
            let record = DnsRecord {
                id: Uuid::new_v4(),
                instance_id: input.instance_id,
                name,
                record_type: DnsRecordType::A,
                value: address.to_string(),
                ttl: 300,
                enabled: true,
                managed_by_device_id: Some(device.id),
            };
            let mut records = candidate_state.dns_records.clone();
            records.push(record.clone());
            validate_records(&instance.dns.zone, &records)
                .map_err(|error| validation_error(&error.to_string()))?;
            Some(record)
        } else {
            None
        };
        let registrations = device_secret_registrations(&device);
        if let Err(error) = self
            .storage
            .save_new_device_with_secret_references(&device, &registrations, dns_record.as_ref())
            .await
        {
            let mut app_error = storage_error(error);
            if let Some(outcome) = &credential_outcome {
                app_error.remote_state_changed = true;
                app_error.rollback_succeeded = Some(
                    self.restore_credential_outcome(&candidate_state, outcome)
                        .await
                        .is_ok(),
                );
            }
            self.delete_device_secrets(&device).await;
            return Err(app_error);
        }
        if dns_record.is_some() {
            self.bump_soa(device.instance_id).await?;
        }
        Ok(device)
    }

    pub async fn update_device(&self, device: Device) -> Result<Device, AppError> {
        let lock = self.instance_lock(device.instance_id).await;
        let _guard = lock.lock().await;
        let previous = self
            .storage
            .get_device(device.id)
            .await
            .map_err(storage_error)?;
        if previous.instance_id != device.instance_id
            || previous.backend_data != device.backend_data
        {
            return Err(validation_error(
                "Device identity metadata is immutable; use Replace identity.",
            ));
        }
        let mut state = self.desired_state(device.instance_id).await?;
        state.devices.retain(|existing| existing.id != device.id);
        state.devices.push(device.clone());
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        backend
            .validate(&state)
            .map_err(|error| validation_error(&error.to_string()))?;
        let credential_outcome = if backend.capabilities().certificate_authority {
            match (previous.enabled, device.enabled) {
                (true, false) => Some(
                    self.execute_device_credential_action(
                        &state,
                        &previous,
                        CredentialAction::Revoke,
                    )
                    .await?,
                ),
                (false, true) => {
                    return Err(AppError {
                        code: "certificate_identity_revoked".into(),
                        message:
                            "A revoked certificate device cannot be re-enabled with the same identity."
                                .into(),
                        scope: Some(device.id.to_string()),
                        remote_state_changed: false,
                        rollback_succeeded: None,
                        remediation: Some(
                            "Replace the device identity to issue a new certificate.".into(),
                        ),
                        technical_detail: None,
                    });
                }
                _ => None,
            }
        } else {
            None
        };
        let dns_changed = self.storage.save_device_and_sync_managed_dns(&device).await;
        let dns_changed = match dns_changed {
            Ok(changed) => changed,
            Err(error) => {
                let mut error = storage_error(error);
                if let Some(outcome) = &credential_outcome {
                    error.remote_state_changed = true;
                    error.rollback_succeeded = Some(
                        self.restore_credential_outcome(&state, outcome)
                            .await
                            .is_ok(),
                    );
                }
                return Err(error);
            }
        };
        if dns_changed {
            self.bump_soa(device.instance_id).await?;
        }
        Ok(device)
    }

    pub async fn delete_device(&self, id: Uuid) -> Result<(), AppError> {
        let device = self.storage.get_device(id).await.map_err(storage_error)?;
        let lock = self.instance_lock(device.instance_id).await;
        let _guard = lock.lock().await;
        let device = self.storage.get_device(id).await.map_err(storage_error)?;
        let state = self.desired_state(device.instance_id).await?;
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let credential_outcome = if backend.capabilities().certificate_authority {
            Some(
                self.execute_device_credential_action(&state, &device, CredentialAction::Revoke)
                    .await?,
            )
        } else {
            None
        };
        let now = Utc::now();
        if let Err(error) = self.storage.soft_delete_device(id, now).await {
            let mut error = storage_error(error);
            if let Some(outcome) = &credential_outcome {
                error.remote_state_changed = true;
                error.rollback_succeeded = Some(
                    self.restore_credential_outcome(&state, outcome)
                        .await
                        .is_ok(),
                );
            }
            return Err(error);
        }
        self.bump_soa(device.instance_id).await
    }

    pub async fn replace_device_identity(&self, id: Uuid) -> Result<Device, AppError> {
        let mut device = self.storage.get_device(id).await.map_err(storage_error)?;
        let lock = self.instance_lock(device.instance_id).await;
        let _guard = lock.lock().await;
        device = self.storage.get_device(id).await.map_err(storage_error)?;
        let previous = device.clone();
        let mut state = self.desired_state(device.instance_id).await?;
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let (backend_data, pending_secrets) =
            generate_device_identity(&state.instance, &device.display_name, Uuid::new_v4(), true)
                .map_err(backend_error)?;
        device.backend_data = backend_data;
        device.enabled = true;
        state.devices.retain(|candidate| candidate.id != device.id);
        state.devices.push(device.clone());
        backend.validate(&state).map_err(backend_error)?;
        self.store_pending_secrets(&pending_secrets).await?;
        let credential_outcome = if backend.capabilities().certificate_authority {
            let (previous_identity, previous_certificate_serial) =
                certificate_identity_metadata(&previous).map_err(backend_error)?;
            let outcome = match self
                .execute_device_credential_action(
                    &state,
                    &device,
                    CredentialAction::Replace {
                        previous_identity,
                        previous_certificate_serial,
                    },
                )
                .await
            {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.delete_device_secrets(&device).await;
                    return Err(error);
                }
            };
            match &mut device.backend_data {
                DeviceBackendData::OpenVpn(data) => {
                    data.certificate_serial
                        .clone_from(&outcome.certificate_serial);
                }
                DeviceBackendData::Ikev2(data) => {
                    data.certificate_serial
                        .clone_from(&outcome.certificate_serial);
                }
                _ => unreachable!("capability identifies certificate backends"),
            }
            if outcome.certificate_serial.is_none() {
                let rollback_succeeded = self
                    .restore_credential_outcome(&state, &outcome)
                    .await
                    .is_ok();
                self.delete_device_secrets(&device).await;
                return Err(AppError {
                    code: "certificate_serial_missing".into(),
                    message: "The replacement certificate has no valid serial.".into(),
                    scope: Some(device.id.to_string()),
                    remote_state_changed: true,
                    rollback_succeeded: Some(rollback_succeeded),
                    remediation: Some("Inspect the remote certificate authority state.".into()),
                    technical_detail: None,
                });
            }
            state.devices.pop();
            state.devices.push(device.clone());
            if let Err(error) = self.validate_certificate_client(&state, &device).await {
                let _ = self.restore_credential_outcome(&state, &outcome).await;
                self.delete_device_secrets(&device).await;
                return Err(error);
            }
            Some(outcome)
        } else {
            None
        };
        let registrations = device_secret_registrations(&device);
        if let Err(error) = self
            .storage
            .replace_device_identity_and_retire_secrets(&device, &registrations)
            .await
        {
            let mut error = storage_error(error);
            if let Some(outcome) = &credential_outcome {
                error.remote_state_changed = true;
                error.rollback_succeeded = Some(
                    self.restore_credential_outcome(&state, outcome)
                        .await
                        .is_ok(),
                );
            }
            self.delete_device_secrets(&device).await;
            return Err(error);
        }
        Ok(device)
    }

    pub async fn list_devices(&self, instance_id: Uuid) -> Result<Vec<Device>, AppError> {
        self.storage
            .list_devices(instance_id)
            .await
            .map_err(storage_error)
    }

    pub async fn create_device_view(
        &self,
        input: CreateDeviceInput,
    ) -> Result<DeviceView, AppError> {
        let device = self.create_device(input).await?;
        Ok(DeviceView::from(&device))
    }

    pub async fn update_device_metadata(
        &self,
        input: UpdateDeviceInput,
    ) -> Result<DeviceView, AppError> {
        if input.display_name.trim().is_empty() {
            return Err(validation_error("Device name is required."));
        }
        let mut device = self
            .storage
            .get_device(input.id)
            .await
            .map_err(storage_error)?;
        let instance = self
            .storage
            .get_instance(device.instance_id)
            .await
            .map_err(storage_error)?;
        let backend = self.backends.get(instance.backend).map_err(backend_error)?;
        device.user_id = input.user_id;
        device.display_name = input.display_name.trim().into();
        device.dns_name = if backend.capabilities().managed_dns {
            input
                .dns_name
                .as_deref()
                .map(|value| normalize_dns_owner(value, &instance.dns.zone))
                .transpose()
                .map_err(|error| validation_error(&error))?
                .flatten()
        } else {
            None
        };
        device.enabled = input.enabled;
        let device = self.update_device(device).await?;
        Ok(DeviceView::from(&device))
    }

    pub async fn set_device_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<DeviceView, AppError> {
        let device = self.storage.get_device(id).await.map_err(storage_error)?;
        self.update_device_metadata(UpdateDeviceInput {
            id,
            user_id: device.user_id,
            display_name: device.display_name,
            dns_name: device.dns_name,
            enabled,
        })
        .await
    }

    pub async fn list_device_views(&self, instance_id: Uuid) -> Result<Vec<DeviceView>, AppError> {
        Ok(self
            .list_devices(instance_id)
            .await?
            .iter()
            .map(DeviceView::from)
            .collect())
    }

    pub async fn replace_device_identity_view(&self, id: Uuid) -> Result<DeviceView, AppError> {
        let device = self.replace_device_identity(id).await?;
        Ok(DeviceView::from(&device))
    }

    async fn store_pending_secrets(&self, secrets: &[PendingSecret]) -> Result<(), AppError> {
        let mut stored = Vec::new();
        for secret in secrets {
            if let Err(error) = self
                .secrets
                .put(&secret.reference, secret.value.as_slice())
                .await
            {
                for reference in stored {
                    let _ = self.secrets.delete(&reference).await;
                }
                return Err(secret_error(error));
            }
            stored.push(secret.reference.clone());
        }
        Ok(())
    }

    async fn delete_device_secrets(&self, device: &Device) {
        for reference in device.backend_data.secret_references() {
            let _ = self.secrets.delete(reference).await;
        }
    }

    async fn validate_certificate_client(
        &self,
        state: &DesiredState,
        device: &Device,
    ) -> Result<(), AppError> {
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let secrets = self.device_secret_map(state, device).await?;
        backend
            .render_client(state, device, &secrets)
            .map(|_| ())
            .map_err(backend_error)
    }

    async fn issue_certificate_device(
        &self,
        state: &DesiredState,
        device: &mut Device,
    ) -> Result<CredentialExecutionOutcome, AppError> {
        let initialized = self
            .storage
            .get_setting::<bool>(&certificate_authority_setting(state.instance.id))
            .await
            .map_err(storage_error)?
            .unwrap_or(false);
        let deployed = self
            .storage
            .last_successful_deployment(state.instance.id)
            .await
            .map_err(storage_error)?
            .is_some();
        if !initialized || !deployed {
            return Err(AppError {
                code: "certificate_authority_not_deployed".into(),
                message: format!(
                    "Deploy the {} instance successfully before issuing client certificates.",
                    state.instance.backend
                ),
                scope: Some(state.instance.id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some(
                    "Review and apply the instance plan to initialize its persistent authority."
                        .into(),
                ),
                technical_detail: None,
            });
        }
        let outcome = self
            .execute_device_credential_action(state, device, CredentialAction::Issue)
            .await?;
        match &mut device.backend_data {
            DeviceBackendData::OpenVpn(data) => {
                data.certificate_serial
                    .clone_from(&outcome.certificate_serial);
            }
            DeviceBackendData::Ikev2(data) => {
                data.certificate_serial
                    .clone_from(&outcome.certificate_serial);
            }
            _ => {
                return Err(validation_error(
                    "Only certificate backends can issue a certificate device.",
                ));
            }
        }
        if matches!(
            &device.backend_data,
            DeviceBackendData::OpenVpn(OpenVpnDeviceData {
                certificate_serial: None,
                ..
            }) | DeviceBackendData::Ikev2(Ikev2DeviceData {
                certificate_serial: None,
                ..
            })
        ) {
            let rollback_succeeded = self
                .restore_credential_outcome(state, &outcome)
                .await
                .is_ok();
            return Err(AppError {
                code: "certificate_serial_missing".into(),
                message: "The remote authority did not return an issued certificate serial.".into(),
                scope: Some(device.id.to_string()),
                remote_state_changed: true,
                rollback_succeeded: Some(rollback_succeeded),
                remediation: Some("Inspect the remote certificate authority state.".into()),
                technical_detail: None,
            });
        }
        Ok(outcome)
    }

    async fn execute_device_credential_action(
        &self,
        state: &DesiredState,
        device: &Device,
        action: CredentialAction,
    ) -> Result<CredentialExecutionOutcome, AppError> {
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        if !backend.capabilities().certificate_authority {
            return Err(validation_error(
                "This backend does not use certificate credential operations.",
            ));
        }
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let plan = backend
            .plan_credentials(state, Some(device), action)
            .map_err(backend_error)?;
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        let cancellation = CancellationToken::new();
        let current = state.instance.remote_path();
        let backup_name = format!(
            "{}-credential-{}",
            Utc::now().format("%Y-%m-%dT%H-%M-%SZ"),
            Uuid::new_v4()
        );
        let backup = backup_path(state.instance.id, &backup_name);
        let validate_identity = validate_persistent_identity_command(&current, &runtime)
            .ok_or_else(|| {
                validation_error(
                    "The certificate backend has no persistent identity validation command.",
                )
            })?;
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &validate_identity,
            &cancellation,
        )
        .await?;
        let backup_command = format!(
            "set -eu; test -d {current}; install -d {parent}; test ! -e {backup} && test ! -L {backup}; cp -a -- {current} {backup}",
            current = shell_quote(&current),
            parent = shell_quote(&format!("{APP_ROOT}/backups/{}", state.instance.id)),
            backup = shell_quote(&backup),
        );
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &backup_command,
            &cancellation,
        )
        .await?;

        let mut outcome = CredentialExecutionOutcome::default();
        let operation_result = async {
            for operation in &plan.operations {
                match operation {
                    CredentialOperation::UploadSecret {
                        reference,
                        relative_path,
                        mode,
                    } => {
                        if !safe_relative_path(relative_path)
                            || !certificate_identity_paths(&runtime)
                                .iter()
                                .any(|path| path_is_within(relative_path, path))
                        {
                            return Err(validation_error(
                                "The credential plan attempted an unsafe upload path.",
                            ));
                        }
                        let value = self.secrets.get(reference).await.map_err(secret_error)?;
                        self.transport
                            .upload(UploadRequest {
                                config: &host.ssh,
                                trusted_key_base64: &trusted.public_key_base64,
                                passphrase: passphrase.as_ref(),
                                remote_path: &format!("{current}/{relative_path}"),
                                contents: value.as_slice(),
                                mode: *mode,
                                cancellation: &cancellation,
                            })
                            .await
                            .map_err(ssh_error)?;
                    }
                    CredentialOperation::DownloadToSecret {
                        relative_path,
                        reference,
                        ..
                    } => {
                        if !safe_relative_path(relative_path)
                            || !certificate_identity_paths(&runtime)
                                .iter()
                                .any(|path| path_is_within(relative_path, path))
                        {
                            return Err(validation_error(
                                "The credential plan attempted an unsafe download path.",
                            ));
                        }
                        let value = self
                            .transport
                            .download(vam_ssh::DownloadRequest {
                                config: &host.ssh,
                                trusted_key_base64: &trusted.public_key_base64,
                                passphrase: passphrase.as_ref(),
                                remote_path: &format!("{current}/{relative_path}"),
                                max_bytes: 1024 * 1024,
                                cancellation: &cancellation,
                            })
                            .await
                            .map_err(ssh_error)?;
                        self.secrets
                            .put(reference, value.as_slice())
                            .await
                            .map_err(secret_error)?;
                    }
                    CredentialOperation::ReadCertificateSerial { .. } => {
                        let command = credential_operation_command(
                            &current,
                            &runtime,
                            state.instance.backend,
                            operation,
                        )
                        .map_err(validation_error)?
                        .ok_or_else(|| {
                            validation_error(
                                "The certificate serial operation produced no command.",
                            )
                        })?;
                        let result = self
                            .checked_execute(
                                &host,
                                &trusted,
                                passphrase.as_ref(),
                                &command,
                                &cancellation,
                            )
                            .await?;
                        outcome.certificate_serial =
                            parse_certificate_serial(&result.stdout_text().map_err(ssh_error)?);
                        if outcome.certificate_serial.is_none() {
                            return Err(AppError {
                                code: "certificate_serial_invalid".into(),
                                message: "The remote authority returned an invalid serial.".into(),
                                scope: Some(device.id.to_string()),
                                remote_state_changed: true,
                                rollback_succeeded: None,
                                remediation: Some(
                                    "Inspect the issued certificate and authority database.".into(),
                                ),
                                technical_detail: None,
                            });
                        }
                    }
                    CredentialOperation::InitializeOpenVpnAuthority { .. }
                    | CredentialOperation::InitializeIkev2Authority { .. } => {
                        return Err(validation_error(
                            "Authority initialization is not a device credential operation.",
                        ));
                    }
                    _ => {
                        let command = credential_operation_command(
                            &current,
                            &runtime,
                            state.instance.backend,
                            operation,
                        )
                        .map_err(validation_error)?
                        .ok_or_else(|| {
                            validation_error(
                                "The credential plan operation produced no remote command.",
                            )
                        })?;
                        self.checked_execute(
                            &host,
                            &trusted,
                            passphrase.as_ref(),
                            &command,
                            &cancellation,
                        )
                        .await?;
                    }
                }
            }
            Ok::<(), AppError>(())
        }
        .await;

        if let Err(mut error) = operation_result {
            error.remote_state_changed = true;
            error.rollback_succeeded = Some(
                self.restore_backup(
                    state,
                    &host,
                    &trusted,
                    passphrase.as_ref(),
                    Some(&backup),
                    &cancellation,
                )
                .await
                .is_ok(),
            );
            return Err(error);
        }
        let prune = prune_command(state.instance.id, BACKUP_RETENTION);
        let _ = self
            .checked_execute(&host, &trusted, passphrase.as_ref(), &prune, &cancellation)
            .await;
        outcome.backup_path = Some(backup);
        Ok(outcome)
    }

    async fn restore_credential_outcome(
        &self,
        state: &DesiredState,
        outcome: &CredentialExecutionOutcome,
    ) -> Result<(), AppError> {
        let backup = outcome.backup_path.as_deref().ok_or_else(|| {
            validation_error("The credential operation has no restorable authority backup.")
        })?;
        let rollback_state = self
            .storage
            .last_successful_deployment(state.instance.id)
            .await
            .map_err(storage_error)?
            .map_or_else(|| state.clone(), |deployment| deployment.desired_state);
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        self.restore_backup(
            &rollback_state,
            &host,
            &trusted,
            passphrase.as_ref(),
            Some(backup),
            &CancellationToken::new(),
        )
        .await
        .map(|_| ())
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

    pub async fn list_dns_hostlists(&self) -> Result<Vec<DnsHostlist>, AppError> {
        self.storage
            .get_setting::<Vec<DnsHostlist>>(DNS_HOSTLISTS_SETTING)
            .await
            .map_err(storage_error)
            .map(Option::unwrap_or_default)
    }

    pub async fn create_dns_hostlist(
        &self,
        input: CreateDnsHostlistInput,
    ) -> Result<DnsHostlist, AppError> {
        let hostlist =
            validate_dns_hostlist(Uuid::new_v4(), &input.name, &input.url, &input.coverage)
                .map_err(|message| validation_error(&message))?;
        let mut hostlists = self.list_dns_hostlists().await?;
        if hostlists.iter().any(|item| item.url == hostlist.url) {
            return Err(validation_error("A hostlist with this URL already exists."));
        }
        hostlists.push(hostlist.clone());
        self.save_dns_hostlists(&hostlists).await?;
        Ok(hostlist)
    }

    pub async fn update_dns_hostlist(
        &self,
        hostlist: DnsHostlist,
    ) -> Result<DnsHostlist, AppError> {
        let hostlist = validate_dns_hostlist(
            hostlist.id,
            &hostlist.name,
            &hostlist.url,
            &hostlist.coverage,
        )
        .map_err(|message| validation_error(&message))?;
        let mut hostlists = self.list_dns_hostlists().await?;
        let position = hostlists
            .iter()
            .position(|item| item.id == hostlist.id)
            .ok_or_else(|| storage_error(StorageError::NotFound))?;
        if hostlists
            .iter()
            .any(|item| item.id != hostlist.id && item.url == hostlist.url)
        {
            return Err(validation_error("A hostlist with this URL already exists."));
        }
        hostlists[position] = hostlist.clone();
        self.save_dns_hostlists(&hostlists).await?;
        Ok(hostlist)
    }

    pub async fn delete_dns_hostlist(&self, id: Uuid) -> Result<(), AppError> {
        let mut hostlists = self.list_dns_hostlists().await?;
        hostlists.retain(|item| item.id != id);
        self.save_dns_hostlists(&hostlists).await
    }

    async fn save_dns_hostlists(&self, hostlists: &[DnsHostlist]) -> Result<(), AppError> {
        self.storage
            .set_setting(DNS_HOSTLISTS_SETTING, &hostlists)
            .await
            .map_err(storage_error)
    }

    pub async fn render_instance(&self, instance_id: Uuid) -> Result<Vec<RenderedFile>, AppError> {
        let state = self.desired_state(instance_id).await?;
        self.render_state(&state).await
    }

    pub async fn plan_instance(&self, instance_id: Uuid) -> Result<DeploymentPlan, AppError> {
        let state = self.desired_state(instance_id).await?;
        let files = self.render_state(&state).await?;
        let remote = self.remote_manifest(&state.instance).await?;
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let mut plan = vam_deployment::DefaultDeploymentPlanner
            .calculate(
                &state,
                &runtime,
                backend.capabilities(),
                &files,
                remote.as_ref(),
            )
            .map_err(deployment_error)?;
        self.annotate_settings_change(&state, backend.as_ref(), &mut plan)
            .await?;
        Ok(plan)
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
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let mut plan = vam_deployment::DefaultDeploymentPlanner
            .calculate(
                &state,
                &runtime,
                backend.capabilities(),
                &files,
                remote.as_ref(),
            )
            .map_err(deployment_error)?;
        self.annotate_settings_change(&state, backend.as_ref(), &mut plan)
            .await?;
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
            if backend.capabilities().certificate_authority {
                self.storage
                    .set_setting(&certificate_authority_setting(instance_id), &true)
                    .await
                    .map_err(storage_error)?;
            }
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
        self.compose_operation(instance_id, "refresh_images", true)
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
        let command = if operation == "refresh_images" {
            let backend = self
                .backends
                .get(state.instance.backend)
                .map_err(backend_error)?;
            let runtime = backend
                .runtime(&state.instance.backend_settings)
                .map_err(backend_error)?;
            format!(
                "{}; cd {}; docker compose up -d --remove-orphans",
                image_prepare_command(
                    &state.instance.remote_path(),
                    &runtime,
                    backend.capabilities().managed_dns,
                ),
                shell_quote(&state.instance.remote_path()),
            )
        } else {
            format!(
                "set -eu; cd {}; docker compose {operation}",
                shell_quote(&state.instance.remote_path())
            )
        };
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

    pub async fn refresh_remote_credentials(
        &self,
        instance_id: Uuid,
    ) -> Result<InstanceHealth, AppError> {
        let state = self.desired_state(instance_id).await?;
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        if !backend.capabilities().quick_credential_refresh {
            return Err(validation_error(&format!(
                "{} credentials require the typed issue/revoke workflow.",
                state.instance.backend
            )));
        }
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        if !matches!(
            runtime.identity,
            ServerIdentityStrategy::WireGuardLike { .. }
        ) {
            return Err(validation_error(
                "Quick credential refresh requires a WireGuard-like backend identity.",
            ));
        }
        let files = self.render_state(&state).await?;
        let device_store_files: Vec<_> = files
            .iter()
            .filter(|file| {
                runtime.mounts.iter().any(|mount| {
                    file.path == mount.host_path
                        || file
                            .path
                            .strip_prefix(mount.host_path)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
            })
            .collect();
        if device_store_files.is_empty() {
            return Err(validation_error(
                "There are no rendered remote credential files for this instance.",
            ));
        }
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        let cancellation = CancellationToken::new();
        self.upload_rendered_files(
            &state.instance,
            &host,
            &trusted,
            passphrase.as_ref(),
            &device_store_files,
            &cancellation,
        )
        .await?;
        let current = state.instance.remote_path();
        let identity_command = materialize_server_identity_command(&current, &current, &runtime)
            .expect("quick-refresh backends have WireGuard-like identity");
        let validate = validation_command(&current, &runtime, backend.capabilities().managed_dns);
        let command = format!(
            "{identity_command}; {validate}; cd {}; docker compose restart gateway",
            shell_quote(&current)
        );
        let result = match self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &command,
                &cancellation,
            )
            .await
        {
            Ok(result) => result,
            Err(mut error) => {
                error.remote_state_changed = true;
                error.scope = Some(state.instance.id.to_string());
                error.remediation = Some(
                    "Deploy the instance if the server key is missing, then retry the credential refresh."
                        .into(),
                );
                return Err(error);
            }
        };
        if let Some(public) = parse_key_values(&result.stdout_text().map_err(ssh_error)?)
            .get("server_public_key")
            .filter(|value| value.len() == 44)
        {
            self.storage
                .set_setting(&server_public_key_setting(instance_id), public)
                .await
                .map_err(storage_error)?;
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

    pub async fn refresh_remote_dns_store(
        &self,
        instance_id: Uuid,
    ) -> Result<InstanceHealth, AppError> {
        let state = self.desired_state(instance_id).await?;
        let files = self.render_state_for_plan(&state).await?;
        let dns_files: Vec<_> = files
            .iter()
            .filter(|file| file.path.starts_with("dns/"))
            .collect();
        if dns_files.is_empty() {
            return Err(validation_error(
                "There are no rendered remote DNS files for this instance.",
            ));
        }
        let (host, trusted, passphrase) = self.trusted_host(state.instance.host_id).await?;
        let cancellation = CancellationToken::new();
        self.upload_rendered_files(
            &state.instance,
            &host,
            &trusted,
            passphrase.as_ref(),
            &dns_files,
            &cancellation,
        )
        .await?;
        let command = format!(
            "set -eu; cd {}; docker compose restart dns",
            shell_quote(&state.instance.remote_path())
        );
        if let Err(mut error) = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &command,
                &cancellation,
            )
            .await
        {
            error.remote_state_changed = true;
            error.scope = Some(state.instance.id.to_string());
            return Err(error);
        }
        self.wait_for_healthy(&state, &host, &trusted, passphrase.as_ref(), &cancellation)
            .await
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
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let plan = vam_deployment::DefaultDeploymentPlanner
            .calculate(
                &state,
                &runtime,
                backend.capabilities(),
                &files,
                remote.as_ref(),
            )
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
        self.backends
            .get(state.instance.backend)
            .map_err(backend_error)?
            .render_client(&state, &device, &secrets)
            .map_err(backend_error)
    }

    pub async fn client_qr_svg(&self, device_id: Uuid) -> Result<String, AppError> {
        let artifact = self.client_configuration(device_id).await?;
        let contents = artifact.contents.as_text().ok_or_else(|| AppError {
            code: "qr_not_supported".into(),
            message: "This backend exports a binary client credential that cannot be encoded as a QR code.".into(),
            scope: Some(device_id.to_string()),
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: Some("Export the client credential as a private file instead.".into()),
            technical_detail: None,
        })?;
        let code = QrCode::new(contents.as_bytes()).map_err(|error| AppError {
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

    async fn selected_dns_blocklist_domains(
        &self,
        _instance_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let hostlists = self.list_dns_hostlists().await?;

        #[cfg(test)]
        {
            let _ = hostlists;
            tokio::task::yield_now().await;
            Ok(Vec::new())
        }

        #[cfg(not(test))]
        {
            let mut tasks = Vec::new();
            for source in hostlists {
                let service = self.clone();
                tasks.push(tokio::spawn(async move {
                    service.cached_hostlist_domains(source).await
                }));
            }

            let mut domains = BTreeSet::new();
            for task in tasks {
                let source_domains = task.await.map_err(|error| AppError {
                    code: "hostlist_task".into(),
                    message: "A DNS hostlist refresh task failed.".into(),
                    scope: None,
                    remote_state_changed: false,
                    rollback_succeeded: None,
                    remediation: Some("Retry DNS refresh.".into()),
                    technical_detail: Some(error.to_string()),
                })??;
                domains.extend(source_domains);
            }
            Ok(domains.into_iter().collect())
        }
    }

    #[cfg(not(test))]
    async fn cached_hostlist_domains(&self, source: DnsHostlist) -> Result<Vec<String>, AppError> {
        let setting = hostlist_cache_setting(source.id);
        let cached = self
            .storage
            .get_setting::<CachedHostlist>(&setting)
            .await
            .map_err(storage_error)?;
        if let Some(cache) = cached.as_ref() {
            let age = Utc::now()
                .signed_duration_since(cache.fetched_at)
                .to_std()
                .unwrap_or(Duration::MAX);
            if cache.url == source.url && age <= HOSTLIST_CACHE_MAX_AGE {
                return Ok(cache.domains.clone());
            }
        }

        match self.fetch_hostlist_domains(source.clone()).await {
            Ok(domains) => {
                let cache = CachedHostlist {
                    url: source.url,
                    fetched_at: Utc::now(),
                    domains: domains.clone(),
                };
                self.storage
                    .set_setting(&setting, &cache)
                    .await
                    .map_err(storage_error)?;
                Ok(domains)
            }
            Err(_error) if cached.is_some() => Ok(cached.expect("checked is_some").domains),
            Err(error) => Err(error),
        }
    }

    #[cfg(not(test))]
    async fn fetch_hostlist_domains(&self, source: DnsHostlist) -> Result<Vec<String>, AppError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(HOSTLIST_FETCH_TIMEOUT)
            .user_agent("vpn-appliance-manager/0.1 hostlist-refresh")
            .build()
            .map_err(hostlist_error)?;
        let response = timeout(HOSTLIST_FETCH_TIMEOUT, client.get(&source.url).send())
            .await
            .map_err(|_| hostlist_timeout_error(&source))?
            .map_err(hostlist_error)?
            .error_for_status()
            .map_err(hostlist_error)?;
        let contents = timeout(HOSTLIST_FETCH_TIMEOUT, response.text())
            .await
            .map_err(|_| hostlist_timeout_error(&source))?
            .map_err(hostlist_error)?;
        let mut domains = parse_hostslist_domains(&contents);
        if domains.is_empty() {
            return Err(AppError {
                code: "hostlist_empty".into(),
                message: format!("{} did not contain any usable DNS hosts.", source.name),
                scope: None,
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some("Disable the source or retry after checking its URL.".into()),
                technical_detail: Some(source.url),
            });
        }
        domains.sort();
        Ok(domains)
    }

    async fn render_state(&self, state: &DesiredState) -> Result<Vec<RenderedFile>, AppError> {
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let mut secrets = HashMap::new();
        for reference in backend.server_secret_references(state) {
            secrets.insert(reference.clone(), self.secret_text(&reference).await?);
        }
        self.render_state_with_secrets(state, &secrets).await
    }

    async fn render_state_for_plan(
        &self,
        state: &DesiredState,
    ) -> Result<Vec<RenderedFile>, AppError> {
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let placeholder =
            Zeroizing::new(String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        let mut secrets = HashMap::new();
        for reference in backend.server_secret_references(state) {
            let value = if state.instance.backend == VpnBackendKind::Xray {
                self.secret_text(&reference).await?
            } else {
                placeholder.clone()
            };
            secrets.insert(reference, value);
        }
        self.render_state_with_secrets(state, &secrets).await
    }

    async fn render_state_with_secrets(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, AppError> {
        let mut render_state = state.clone();
        render_state.dns_blocklist_domains = self
            .selected_dns_blocklist_domains(render_state.instance.id)
            .await?;
        let backend = self
            .backends
            .get(render_state.instance.backend)
            .map_err(backend_error)?;
        backend.validate(&render_state).map_err(backend_error)?;
        let runtime = backend
            .runtime(&render_state.instance.backend_settings)
            .map_err(backend_error)?;
        let mut files = vam_deployment::DefaultDeploymentPlanner
            .render(&render_state, &runtime, backend.capabilities())
            .map_err(deployment_error)?;
        files.extend(
            backend
                .render_server(&render_state, secrets)
                .map_err(backend_error)?,
        );
        let mut manifest = build_manifest(&files);
        if let Some(public) = self
            .storage
            .get_setting::<String>(&server_public_key_setting(render_state.instance.id))
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
        let mut secrets = HashMap::new();
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        for reference in backend
            .client_secret_references(device)
            .map_err(backend_error)?
        {
            secrets.insert(reference.clone(), self.secret_text(&reference).await?);
        }
        if matches!(
            state.instance.backend,
            VpnBackendKind::WireGuard | VpnBackendKind::AmneziaWg
        ) {
            let server_reference = SecretReference(state.instance.id);
            let server_public = self
                .storage
                .get_setting::<String>(&server_public_key_setting(state.instance.id))
                .await
                .map_err(storage_error)?
                .ok_or_else(|| AppError {
                    code: "server_public_key_missing".into(),
                    message: "The server public key is unavailable; deploy the instance first."
                        .into(),
                    scope: Some(state.instance.id.to_string()),
                    remote_state_changed: false,
                    rollback_succeeded: None,
                    remediation: Some("Apply the instance, then export the client.".into()),
                    technical_detail: None,
                })?;
            secrets.insert(server_reference, Zeroizing::new(server_public));
        }
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

    async fn upload_rendered_files(
        &self,
        instance: &VpnInstance,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        files: &[&RenderedFile],
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut prepare = format!("set -eu; test -d {}", shell_quote(&instance.remote_path()));
        for directory in
            rendered_directories_from_paths(files.iter().map(|file| file.path.as_str()))
        {
            prepare.push_str(&format!(
                "; install -d {}",
                shell_quote(&format!("{}/{directory}", instance.remote_path()))
            ));
        }
        self.checked_execute(host, trusted, passphrase, &prepare, cancellation)
            .await?;
        let mut changed = false;
        for file in files {
            self.transport
                .upload(UploadRequest {
                    config: &host.ssh,
                    trusted_key_base64: &trusted.public_key_base64,
                    passphrase,
                    remote_path: &format!("{}/{}", instance.remote_path(), file.path),
                    contents: file.contents.as_bytes(),
                    mode: file.mode,
                    cancellation,
                })
                .await
                .map_err(|error| {
                    let mut app_error = ssh_error(error);
                    app_error.scope = Some(instance.id.to_string());
                    app_error.remote_state_changed = changed;
                    app_error
                })?;
            changed = true;
        }
        Ok(())
    }

    async fn ensure_firewall_allows(
        &self,
        instance: &VpnInstance,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let listeners = instance.listeners();
        let command = firewall_allow_command(&listeners);
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await
            .map(|_| ())
            .map_err(|mut error| {
                error.code = "remote_firewall".into();
                error.message = format!(
                    "The remote firewall could not be opened for {}.",
                    listener_summary(&listeners)
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
        let listeners = instance.listeners();
        let command = firewall_remove_command(&listeners);
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await
            .map(|_| ())
            .map_err(|mut error| {
                error.code = "remote_firewall".into();
                error.message = format!(
                    "The remote firewall rules for {} could not be removed.",
                    listener_summary(&listeners)
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
        let expected_clients = state
            .devices
            .iter()
            .filter(|device| device.enabled && device.deleted_at.is_none())
            .count();
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let capabilities = backend.capabilities();
        let command = remote_health_command(state, &runtime, capabilities.managed_dns);
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
        if result.exit_status != 0 {
            return Err(command_error("health", &result, false));
        }
        let text = result.stdout_text().map_err(ssh_error)?;
        let values = parse_key_values(&text);
        let zero = |key: &str| values.get(key).is_some_and(|value| value == "0");
        let client_count = values
            .get("client_count")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let listeners_ready = state
            .instance
            .listeners()
            .iter()
            .enumerate()
            .all(|(index, _)| zero(&format!("listener_{index}")));
        let backend_ready = zero("backend");
        let client_state_matches = client_count == expected_clients;
        let mut details = Vec::new();
        for (label, key) in [
            ("Gateway status", "gateway_status"),
            ("DNS status", "dns_status"),
            ("Backend probe", "backend_status"),
        ] {
            if let Some(status) = values.get(key).filter(|value| !value.is_empty()) {
                details.push(format!("{label}: {status}"));
            }
        }
        Ok(InstanceHealth {
            compose_project_exists: values.get("project").is_some_and(|value| value == "1"),
            gateway_running: zero("gateway"),
            backend_ready,
            listeners_ready,
            client_state_matches,
            dns_required: capabilities.managed_dns,
            dns_running: zero("dns"),
            watchtower_running: false,
            private_dns_resolves: zero("private_dns"),
            public_dns_resolves: zero("public_dns"),
            wireguard_interface_exists: matches!(
                runtime.health,
                BackendHealthProbe::WireGuardLike { .. }
            ) && backend_ready,
            listen_port_matches: listeners_ready,
            expected_peers_present: client_state_matches,
            details,
        })
    }

    async fn persist_discovered_public_identity(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let BackendSettings::Xray(settings) = &state.instance.backend_settings else {
            return Ok(());
        };
        if settings.security != XraySecurity::Reality {
            return Ok(());
        }
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let public_relative = runtime_host_path(&runtime, REALITY_PUBLIC_KEY_PATH)
            .ok_or_else(|| validation_error("Xray public identity path is not mounted."))?;
        let short_id_relative = runtime_host_path(&runtime, REALITY_SHORT_ID_PATH)
            .ok_or_else(|| validation_error("Xray short-ID path is not mounted."))?;
        let public_path = format!("{}/{}", state.instance.remote_path(), public_relative);
        let short_id_path = format!("{}/{}", state.instance.remote_path(), short_id_relative);
        let command = format!(
            "set -eu; test -s {public}; test -s {short}; printf 'reality_public_key='; tr -d '\\r\\n' < {public}; printf '\\nreality_short_id='; tr -d '\\r\\n' < {short}; printf '\\n'",
            public = shell_quote(&public_path),
            short = shell_quote(&short_id_path),
        );
        let result = self
            .checked_execute(host, trusted, passphrase, &command, cancellation)
            .await?;
        let values = parse_key_values(&result.stdout_text().map_err(ssh_error)?);
        let public_key = values
            .get("reality_public_key")
            .cloned()
            .ok_or_else(|| validation_error("Xray did not expose its REALITY public key."))?;
        let short_id = values
            .get("reality_short_id")
            .cloned()
            .ok_or_else(|| validation_error("Xray did not expose its REALITY short ID."))?;
        if let (Some(previous_key), Some(previous_short_id)) = (
            settings.reality_public_key.as_ref(),
            settings.reality_short_id.as_ref(),
        ) && (previous_key != &public_key || previous_short_id != &short_id)
        {
            return Err(AppError {
                code: "xray_public_identity_changed".into(),
                message:
                    "The remote Xray REALITY identity differs from the approved public identity."
                        .into(),
                scope: Some(state.instance.id.to_string()),
                remote_state_changed: true,
                rollback_succeeded: None,
                remediation: Some(
                    "Restore the expected backup or explicitly replace the Xray server identity."
                        .into(),
                ),
                technical_detail: None,
            });
        }
        if settings.reality_public_key.as_ref() == Some(&public_key)
            && settings.reality_short_id.as_ref() == Some(&short_id)
        {
            return Ok(());
        }
        let mut discovered = state.clone();
        let BackendSettings::Xray(settings) = &mut discovered.instance.backend_settings else {
            unreachable!("the cloned settings retain their backend")
        };
        settings.reality_public_key = Some(public_key);
        settings.reality_short_id = Some(short_id);
        backend.validate(&discovered).map_err(backend_error)?;
        discovered.instance.updated_at = Utc::now();
        self.storage
            .save_instance(&discovered.instance)
            .await
            .map_err(storage_error)
    }

    async fn normalize_vpn_ownership(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        cancellation: &CancellationToken,
    ) -> Result<(), AppError> {
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let Some(command) =
            normalize_host_mount_ownership_command(&state.instance.remote_path(), &runtime)
        else {
            return Ok(());
        };
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
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let runtime = backend
            .runtime(&state.instance.backend_settings)
            .map_err(backend_error)?;
        let capabilities = backend.capabilities();
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
        if !host_deployment_prerequisites_ready(&inspection) {
            let error = AppError {
                code: "host_prerequisites_failed".into(),
                message: "The host does not meet deployment prerequisites.".into(),
                scope: Some(state.instance.host_id.to_string()),
                remote_state_changed: false,
                rollback_succeeded: None,
                remediation: Some(
                    "Review and apply the separate host setup plan, or provide Linux, direct Docker access, and Docker Compose v2 manually."
                        .into(),
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
        let listeners = state.instance.listeners();
        let port_check = port_conflict_command(&state.instance, &runtime);
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &port_check,
            cancellation,
        )
        .await
        .map_err(|mut error| {
            error.code = "listener_port_conflict".into();
            error.message = format!(
                "One or more required listeners ({}) are already in use on the host.",
                listener_summary(&listeners)
            );
            error.remediation =
                Some("Choose unused listener ports or stop the conflicting host service.".into());
            error
        })?;
        if let Some(seed_identity) =
            seed_persistent_identity_command(&state.instance.remote_path(), &stage, &runtime)
        {
            self.record_event(
                plan.id,
                &mut sequence,
                "identity",
                "Copying the existing persistent certificate authority into protected staging.",
                None,
                "info",
            )
            .await?;
            self.checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &seed_identity,
                cancellation,
            )
            .await?;
        }
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
            "Preparing the selected pinned backend image and optional DNS image.",
            None,
            "info",
        )
        .await?;
        let prepare_images = if plan.operations.iter().any(|operation| {
            matches!(
                operation,
                DeploymentOperation::ComposePull | DeploymentOperation::ComposeBuild
            )
        }) {
            image_prepare_command(&stage, &runtime, capabilities.managed_dns)
        } else {
            "true".into()
        };
        self.checked_execute(
            &host,
            &trusted,
            passphrase.as_ref(),
            &prepare_images,
            cancellation,
        )
        .await?;
        if capabilities.certificate_authority {
            let credential_plan = backend
                .plan_credentials(state, None, CredentialAction::InitializeAuthority)
                .map_err(backend_error)?;
            let [operation] = credential_plan.operations.as_slice() else {
                return Err(validation_error(
                    "Certificate authority initialization must contain exactly one operation.",
                ));
            };
            self.record_event(
                plan.id,
                &mut sequence,
                "identity",
                "Validating or initializing the staged certificate authority.",
                None,
                "info",
            )
            .await?;
            let initialize =
                certificate_authority_initialization_command(&stage, &runtime, operation)
                    .map_err(validation_error)?;
            self.checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &initialize,
                cancellation,
            )
            .await?;
        }
        let server_public = if let Some(identity_command) =
            materialize_server_identity_command(&state.instance.remote_path(), &stage, &runtime)
        {
            let result = self
                .checked_execute(
                    &host,
                    &trusted,
                    passphrase.as_ref(),
                    &identity_command,
                    cancellation,
                )
                .await?;
            let values = parse_key_values(&result.stdout_text().map_err(ssh_error)?);
            let public = values
                .get("server_public_key")
                .filter(|value| value.len() == 44)
                .cloned()
                .ok_or_else(|| AppError {
                    code: "server_key_generation_failed".into(),
                    message: format!(
                        "The remote {} runtime did not return a valid public key.",
                        state.instance.backend
                    ),
                    scope: Some(state.instance.id.to_string()),
                    remote_state_changed: false,
                    rollback_succeeded: None,
                    remediation: Some(
                        "Inspect Docker and the selected pinned backend image.".into(),
                    ),
                    technical_detail: None,
                })?;
            Some(public)
        } else {
            None
        };
        let mut manifest = build_manifest(files);
        manifest.server_public_key.clone_from(&server_public);
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
            "Validating the selected backend, optional DNS, and Compose configuration.",
            None,
            "info",
        )
        .await?;
        let validate = validation_command(&stage, &runtime, capabilities.managed_dns);
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
        let activate = activation_command(&current, &stage, files, plan, &runtime);
        let mut activation_result = self
            .checked_execute(
                &host,
                &trusted,
                passphrase.as_ref(),
                &activate,
                cancellation,
            )
            .await;
        if activation_result.is_ok()
            && let Some(command) = prepare_numeric_mount_ownership_command(&current, &runtime)
        {
            activation_result = self
                .checked_execute(&host, &trusted, passphrase.as_ref(), &command, cancellation)
                .await;
        }
        if let Err(mut error) = activation_result {
            error.remote_state_changed = true;
            let rollback_ok = self
                .restore_backup(
                    rollback_health_state,
                    &host,
                    &trusted,
                    passphrase.as_ref(),
                    rollback_state.as_ref().map(|_| backup.as_str()),
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
            "Ensuring active host firewalls allow every declared backend listener.",
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
                    rollback_state.as_ref().map(|_| backup.as_str()),
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
        let compose = compose_activation_command(&current, plan, capabilities.managed_dns);
        let compose_result = self
            .checked_execute(&host, &trusted, passphrase.as_ref(), &compose, cancellation)
            .await;
        let health = if compose_result.is_ok() {
            match self
                .wait_for_healthy(state, &host, &trusted, passphrase.as_ref(), cancellation)
                .await
            {
                Ok(health) if health_is_healthy(&health) => {
                    match self
                        .persist_discovered_public_identity(
                            state,
                            &host,
                            &trusted,
                            passphrase.as_ref(),
                            cancellation,
                        )
                        .await
                    {
                        Ok(()) => self
                            .normalize_vpn_ownership(
                                state,
                                &host,
                                &trusted,
                                passphrase.as_ref(),
                                cancellation,
                            )
                            .await
                            .map(|()| health),
                        Err(error) => Err(error),
                    }
                }
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
                        rollback_state.as_ref().map(|_| backup.as_str()),
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
                        rollback_state.as_ref().map(|_| backup.as_str()),
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
        if let Some(server_public) = &server_public {
            self.storage
                .set_setting(&server_public_key_setting(state.instance.id), server_public)
                .await
                .map_err(storage_error)?;
        }
        if capabilities.certificate_authority {
            self.storage
                .set_setting(&certificate_authority_setting(state.instance.id), &true)
                .await
                .map_err(storage_error)?;
        }
        let cleanup_stage = format!(
            "docker run --rm --user 0:0 --entrypoint sh -v {root_mount} {image} -c {script}",
            root_mount = shell_quote(&format!("{APP_ROOT}:/vam")),
            image = shell_quote(runtime_image_reference(&runtime)),
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
    async fn annotate_settings_change(
        &self,
        state: &DesiredState,
        backend: &dyn VpnBackend,
        plan: &mut DeploymentPlan,
    ) -> Result<(), AppError> {
        if plan.operations.is_empty() {
            return Ok(());
        }
        let Some(previous) = self
            .storage
            .last_successful_deployment(state.instance.id)
            .await
            .map_err(storage_error)?
        else {
            return Ok(());
        };
        let impact = backend.classify_settings_change(
            &previous.desired_state.instance.backend_settings,
            &state.instance.backend_settings,
        );
        if let Some(warning) = settings_change_warning(impact) {
            plan.warnings.push(warning.into());
        }
        Ok(())
    }

    async fn restore_backup(
        &self,
        state: &DesiredState,
        host: &DockerHost,
        trusted: &vam_storage::KnownHostKey,
        passphrase: Option<&Zeroizing<String>>,
        backup: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<InstanceHealth, AppError> {
        let current = state.instance.remote_path();
        let failed = format!(
            "{APP_ROOT}/trash/{}-failed-{}",
            state.instance.id,
            Utc::now().format("%Y%m%dT%H%M%SZ")
        );
        let command = if let Some(backup) = backup {
            format!(
                "set -eu; test -d {backup}; if test -d {current}; then cd {current}; docker compose down || true; cd /; mv {current} {failed}; fi; cp -a {backup} {current}; cd {current}; docker compose up -d",
                current = shell_quote(&current),
                failed = shell_quote(&failed),
                backup = shell_quote(backup),
            )
        } else {
            format!(
                "set -eu; if test -d {current}; then cd {current}; docker compose down || true; cd /; mv {current} {failed}; fi",
                current = shell_quote(&current),
                failed = shell_quote(&failed),
            )
        };
        self.checked_execute(host, trusted, passphrase, &command, cancellation)
            .await?;
        if backup.is_none() {
            self.remove_firewall_allow(&state.instance, host, trusted, passphrase, cancellation)
                .await?;
            return Ok(InstanceHealth::default());
        }
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
    rendered_directories_from_paths(files.iter().map(|file| file.path.as_str()))
}

fn rendered_directories_from_paths<'a>(paths: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut directories = Vec::new();
    for file_path in paths {
        let mut path = Path::new(file_path).parent();
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

fn certificate_identity_paths(runtime: &BackendRuntimeSpec) -> &'static [&'static str] {
    match runtime.identity {
        ServerIdentityStrategy::CertificateAuthority { persistent_paths } => persistent_paths,
        _ => &[],
    }
}

fn path_is_within(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn seed_persistent_identity_command(
    current: &str,
    stage: &str,
    runtime: &BackendRuntimeSpec,
) -> Option<String> {
    let paths = certificate_identity_paths(runtime);
    if paths.is_empty() {
        return None;
    }
    let mut command = String::from("set -eu");
    for path in paths {
        debug_assert!(safe_relative_path(path));
        let source = format!("{current}/{path}");
        let destination = format!("{stage}/{path}");
        let parent = Path::new(&destination)
            .parent()
            .expect("declared identity paths have a parent")
            .to_string_lossy();
        command.push_str(&format!(
            r#"; if test -e {source} || test -L {source}; then
  test ! -L {source}
  if test -d {source}; then
    if find {source} -type l -print -quit | grep -q .; then
      echo "persistent identity contains a symbolic link: {label}" >&2
      exit 1
    fi
  else
    test -f {source}
  fi
  test ! -e {destination} && test ! -L {destination}
  install -d {parent}
  cp -a -- {source} {destination}
fi"#,
            source = shell_quote(&source),
            destination = shell_quote(&destination),
            parent = shell_quote(&parent),
            label = path,
        ));
    }
    Some(command)
}

fn validate_persistent_identity_command(
    current: &str,
    runtime: &BackendRuntimeSpec,
) -> Option<String> {
    let paths = certificate_identity_paths(runtime);
    if paths.is_empty() {
        return None;
    }
    let mut command = String::from("set -eu");
    for path in paths {
        debug_assert!(safe_relative_path(path));
        let source = format!("{current}/{path}");
        command.push_str(&format!(
            r#"; if test -e {source} || test -L {source}; then
  test ! -L {source}
  if test -d {source}; then
    if find {source} -type l -print -quit | grep -q .; then
      echo "persistent identity contains a symbolic link: {label}" >&2
      exit 1
    fi
  else
    test -f {source}
  fi
fi"#,
            source = shell_quote(&source),
            label = path,
        ));
    }
    Some(command)
}

fn authority_mount<'a>(
    stage: &str,
    runtime: &'a BackendRuntimeSpec,
) -> Result<(String, &'a str), &'static str> {
    let first_path = certificate_identity_paths(runtime)
        .first()
        .ok_or("The backend has no certificate authority paths.")?;
    let mount = runtime
        .mounts
        .iter()
        .find(|mount| path_is_within(first_path, mount.host_path) && !mount.read_only)
        .ok_or("The certificate backend has no writable mount for its persistent authority.")?;
    Ok((
        format!("{stage}/{}:{}", mount.host_path, mount.container_path),
        mount.container_path,
    ))
}

fn certificate_authority_initialization_command(
    stage: &str,
    runtime: &BackendRuntimeSpec,
    operation: &CredentialOperation,
) -> Result<String, &'static str> {
    let image = shell_quote(runtime_image_reference(runtime));
    let (mount, root) = authority_mount(stage, runtime)?;
    let script = match operation {
        CredentialOperation::InitializeOpenVpnAuthority {
            ca_common_name,
            server_common_name,
            ca_lifetime_days,
            certificate_lifetime_days,
            crl_lifetime_days,
            tls_crypt,
        } => {
            let tls_required = if *tls_crypt { "1" } else { "0" };
            format!(
                r#"set -eu
umask 077
root={root}
pki="$root/pki"
tls_key="$root/tls-crypt.key"
present=0
required=5
for file in "$pki/ca.crt" "$pki/private/ca.key" "$pki/issued/{server_common_name}.crt" "$pki/private/{server_common_name}.key" "$pki/crl.pem"; do
  if test -s "$file"; then present=$((present + 1)); fi
done
if test {tls_required} -eq 1; then
  required=$((required + 1))
  if test -s "$tls_key"; then present=$((present + 1)); fi
fi
if test "$present" -eq "$required"; then
  test ! -L "$pki"
  if find "$pki" -type l -print -quit | grep -q .; then
    echo "OpenVPN authority contains a symbolic link" >&2
    exit 1
  fi
  openssl verify -CAfile "$pki/ca.crt" "$pki/issued/{server_common_name}.crt"
  exit 0
fi
if test "$present" -ne 0 || test -e "$pki" || test -L "$pki"; then
  echo "OpenVPN authority is partial; refusing to regenerate it" >&2
  exit 1
fi
new="$root/.vam-pki-new"
test ! -L "$new"
rm -rf -- "$new"
cleanup() {{ rm -rf -- "$new"; }}
trap cleanup EXIT INT TERM HUP
export EASYRSA=/usr/share/easy-rsa
export EASYRSA_BATCH=1
export EASYRSA_PKI="$new"
export EASYRSA_DN=cn_only
export EASYRSA_ALGO=ec
export EASYRSA_CURVE=prime256v1
export EASYRSA_DIGEST=sha256
EASYRSA_REQ_CN={ca_common_name} EASYRSA_CA_EXPIRE={ca_lifetime_days} easyrsa init-pki
EASYRSA_REQ_CN={ca_common_name} EASYRSA_CA_EXPIRE={ca_lifetime_days} easyrsa build-ca nopass
EASYRSA_CERT_EXPIRE={certificate_lifetime_days} easyrsa build-server-full {server_common_name} nopass
EASYRSA_CRL_DAYS={crl_lifetime_days} easyrsa gen-crl
openssl verify -CAfile "$new/ca.crt" "$new/issued/{server_common_name}.crt"
mv "$new" "$pki"
if test {tls_required} -eq 1; then
  openvpn --genkey secret "$root/.vam-tls-crypt-new"
  chmod 0600 "$root/.vam-tls-crypt-new"
  mv "$root/.vam-tls-crypt-new" "$tls_key"
fi
chmod 0700 "$pki/private"
find "$pki/private" -type f -exec chmod 0600 {{}} +
chmod 0644 "$pki/ca.crt" "$pki/issued/{server_common_name}.crt" "$pki/crl.pem"
trap - EXIT INT TERM HUP"#,
                root = shell_quote(root),
                ca_common_name = shell_quote(ca_common_name),
                server_common_name = server_common_name,
                ca_lifetime_days = ca_lifetime_days,
                certificate_lifetime_days = certificate_lifetime_days,
                crl_lifetime_days = crl_lifetime_days,
            )
        }
        CredentialOperation::InitializeIkev2Authority {
            ca_common_name,
            server_identity,
            key_algorithm,
            ca_lifetime_days,
            certificate_lifetime_days,
            crl_lifetime_days,
        } => {
            let (size, digest) = match key_algorithm {
                vam_backend::CertificateKeyAlgorithm::EcdsaP256Sha256 => (256, "sha256"),
                vam_backend::CertificateKeyAlgorithm::EcdsaP384Sha384 => (384, "sha384"),
            };
            format!(
                r#"set -eu
umask 077
root={root}
ca_key="$root/private/vam-ca-key.pem"
ca_cert="$root/x509ca/vam-ca.pem"
server_key="$root/private/vam-server-key.pem"
server_cert="$root/x509/vam-server.pem"
crl="$root/x509crl/vam-crl.pem"
present=0
for file in "$ca_key" "$ca_cert" "$server_key" "$server_cert" "$crl"; do
  if test -s "$file"; then present=$((present + 1)); fi
done
if test "$present" -eq 5; then
  for directory in private x509 x509ca x509crl; do
    test ! -L "$root/$directory"
    if find "$root/$directory" -type l -print -quit | grep -q .; then
      echo "IKEv2 authority contains a symbolic link" >&2
      exit 1
    fi
  done
  pki --verify --in "$server_cert" --cacert "$ca_cert"
  pki --print --type crl --in "$crl" >/dev/null
  exit 0
fi
if test "$present" -ne 0; then
  echo "IKEv2 authority is partial; refusing to regenerate it" >&2
  exit 1
fi
new="$root/.vam-authority-new"
test ! -L "$new"
rm -rf -- "$new"
install -d -m 0700 "$new/private" "$new/x509" "$new/x509ca" "$new/x509crl"
cleanup() {{ rm -rf -- "$new"; }}
trap cleanup EXIT INT TERM HUP
pki --gen --type ecdsa --size {size} --outform pem > "$new/private/vam-ca-key.pem"
pki --self --ca --in "$new/private/vam-ca-key.pem" --type ecdsa --dn {ca_dn} --lifetime {ca_lifetime_days} --digest {digest} --outform pem > "$new/x509ca/vam-ca.pem"
pki --gen --type ecdsa --size {size} --outform pem > "$new/private/vam-server-key.pem"
pki --issue --in "$new/private/vam-server-key.pem" --type priv --cacert "$new/x509ca/vam-ca.pem" --cakey "$new/private/vam-ca-key.pem" --dn {server_dn} --san {server_identity} --flag serverAuth --serial 01 --lifetime {certificate_lifetime_days} --digest {digest} --outform pem > "$new/x509/vam-server.pem"
pki --signcrl --cacert "$new/x509ca/vam-ca.pem" --cakey "$new/private/vam-ca-key.pem" --lifetime {crl_lifetime_days} --digest {digest} --outform pem > "$new/x509crl/vam-crl.pem"
pki --verify --in "$new/x509/vam-server.pem" --cacert "$new/x509ca/vam-ca.pem"
pki --print --type crl --in "$new/x509crl/vam-crl.pem" >/dev/null
install -m 0600 "$new/private/vam-ca-key.pem" "$ca_key"
install -m 0600 "$new/private/vam-server-key.pem" "$server_key"
install -m 0644 "$new/x509ca/vam-ca.pem" "$ca_cert"
install -m 0644 "$new/x509/vam-server.pem" "$server_cert"
install -m 0644 "$new/x509crl/vam-crl.pem" "$crl"
trap - EXIT INT TERM HUP
rm -rf -- "$new""#,
                root = shell_quote(root),
                size = size,
                ca_dn = shell_quote(&format!("CN={ca_common_name}")),
                server_dn = shell_quote(&format!("CN={server_identity}")),
                server_identity = shell_quote(server_identity),
                ca_lifetime_days = ca_lifetime_days,
                certificate_lifetime_days = certificate_lifetime_days,
                crl_lifetime_days = crl_lifetime_days,
            )
        }
        _ => {
            return Err(
                "The backend returned an invalid certificate-authority initialization plan.",
            );
        }
    };
    Ok(format!(
        "docker run --rm --user 0:0 --entrypoint /bin/sh -v {mount} {image} -c {script}",
        mount = shell_quote(&mount),
        script = shell_quote(&script),
    ))
}

fn credential_container_command(
    current: &str,
    runtime: &BackendRuntimeSpec,
    script: &str,
) -> Result<String, &'static str> {
    let (mount, _) = authority_mount(current, runtime)?;
    Ok(format!(
        "docker run --rm --user 0:0 --entrypoint /bin/sh -v {mount} {image} -c {script}",
        mount = shell_quote(&mount),
        image = shell_quote(runtime_image_reference(runtime)),
        script = shell_quote(script),
    ))
}

fn credential_operation_command(
    current: &str,
    runtime: &BackendRuntimeSpec,
    backend: VpnBackendKind,
    operation: &CredentialOperation,
) -> Result<Option<String>, &'static str> {
    let command = match operation {
        CredentialOperation::ImportOpenVpnCsr {
            common_name,
            relative_path,
        } => {
            if backend != VpnBackendKind::OpenVpn {
                return Err("An OpenVPN credential operation was assigned to another backend.");
            }
            let request = runtime_container_path(runtime, relative_path)
                .ok_or("The OpenVPN request path is outside its declared mount.")?;
            let script = format!(
                r"set -eu
export EASYRSA=/usr/share/easy-rsa
export EASYRSA_BATCH=1
export EASYRSA_PKI=/etc/openvpn/pki
export EASYRSA_DN=cn_only
easyrsa import-req {request} {common_name}",
                request = shell_quote(&request),
                common_name = shell_quote(common_name),
            );
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::SignOpenVpnClient {
            common_name,
            certificate_lifetime_days,
        } => {
            if backend != VpnBackendKind::OpenVpn {
                return Err("An OpenVPN credential operation was assigned to another backend.");
            }
            let script = format!(
                r"set -eu
export EASYRSA=/usr/share/easy-rsa
export EASYRSA_BATCH=1
export EASYRSA_PKI=/etc/openvpn/pki
export EASYRSA_DN=cn_only
EASYRSA_CERT_EXPIRE={certificate_lifetime_days} easyrsa sign-req client {common_name}
openssl verify -CAfile /etc/openvpn/pki/ca.crt /etc/openvpn/pki/issued/{common_name}.crt",
                common_name = shell_quote(common_name),
            );
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::RevokeOpenVpnClient { common_name } => {
            if backend != VpnBackendKind::OpenVpn {
                return Err("An OpenVPN credential operation was assigned to another backend.");
            }
            let script = format!(
                r#"set -eu
export EASYRSA=/usr/share/easy-rsa
export EASYRSA_BATCH=1
export EASYRSA_PKI=/etc/openvpn/pki
export EASYRSA_DN=cn_only
common_name={common_name}
if awk -F '	' -v subject="/CN=$common_name" '$1 == "R" && $6 == subject {{ found=1 }} END {{ exit !found }}' "$EASYRSA_PKI/index.txt"; then
  :
else
  easyrsa revoke "$common_name"
fi"#,
                common_name = shell_quote(common_name),
            );
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::RegenerateOpenVpnCrl { lifetime_days } => {
            if backend != VpnBackendKind::OpenVpn {
                return Err("An OpenVPN credential operation was assigned to another backend.");
            }
            let script = format!(
                r#"set -eu
export EASYRSA=/usr/share/easy-rsa
export EASYRSA_BATCH=1
export EASYRSA_PKI=/etc/openvpn/pki
export EASYRSA_DN=cn_only
EASYRSA_CRL_DAYS={lifetime_days} easyrsa gen-crl
openssl crl -in "$EASYRSA_PKI/crl.pem" -noout"#,
            );
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::SignIkev2Client {
            identity,
            relative_path,
            certificate_lifetime_days,
            key_algorithm,
        } => {
            if backend != VpnBackendKind::Ikev2 {
                return Err("An IKEv2 credential operation was assigned to another backend.");
            }
            let request = runtime_container_path(runtime, relative_path)
                .ok_or("The IKEv2 request path is outside its declared mount.")?;
            let certificate_relative = format!("ikev2/issued/{identity}.pem");
            let certificate = runtime_container_path(runtime, &certificate_relative)
                .ok_or("The IKEv2 certificate path is outside its declared mount.")?;
            let digest = match key_algorithm {
                vam_backend::CertificateKeyAlgorithm::EcdsaP256Sha256 => "sha256",
                vam_backend::CertificateKeyAlgorithm::EcdsaP384Sha384 => "sha384",
            };
            let script = format!(
                r#"set -eu
umask 077
request={request}
certificate={certificate}
serial_file="$certificate.serial"
serial="$(od -An -N16 -tx1 /dev/urandom | tr -d '[:space:]')"
test "${{#serial}}" -eq 32
test ! -e "$certificate" && test ! -L "$certificate"
pki --issue --in "$request" --type pkcs10 --cacert /etc/swanctl/x509ca/vam-ca.pem --cakey /etc/swanctl/private/vam-ca-key.pem --flag clientAuth --serial "$serial" --lifetime {certificate_lifetime_days} --digest {digest} --outform pem > "$certificate"
pki --verify --in "$certificate" --cacert /etc/swanctl/x509ca/vam-ca.pem
printf '%s\n' "$serial" > "$serial_file"
chmod 0644 "$certificate" "$serial_file""#,
                request = shell_quote(&request),
                certificate = shell_quote(&certificate),
            );
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::RevokeIkev2Client {
            certificate_serial,
            crl_lifetime_days,
            ..
        } => {
            if backend != VpnBackendKind::Ikev2 {
                return Err("An IKEv2 credential operation was assigned to another backend.");
            }
            let script = format!(
                r#"set -eu
umask 077
crl=/etc/swanctl/x509crl/vam-crl.pem
new="$crl.vam-new"
marker=/etc/swanctl/revoked/{certificate_serial}
test -s "$crl"
if test -f "$marker" && test ! -L "$marker"; then
  exit 0
fi
test ! -e "$marker" && test ! -L "$marker"
rm -f -- "$new"
pki --signcrl --cacert /etc/swanctl/x509ca/vam-ca.pem --cakey /etc/swanctl/private/vam-ca-key.pem --lastcrl "$crl" --serial {certificate_serial} --reason superseded --lifetime {crl_lifetime_days} --digest sha384 --outform pem > "$new"
pki --print --type crl --in "$new" >/dev/null
chmod 0644 "$new"
mv "$new" "$crl"
install -m 0644 /dev/null "$marker""#,
                certificate_serial = shell_quote(certificate_serial),
            );
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::ReloadGateway => Some(match backend {
            VpnBackendKind::OpenVpn => format!(
                "set -eu; cd {}; docker compose restart gateway",
                shell_quote(current)
            ),
            VpnBackendKind::Ikev2 => format!(
                "set -eu; cd {}; docker compose exec -T gateway swanctl --load-all --noprompt",
                shell_quote(current)
            ),
            _ => return Err("Only certificate backends can reload credential state."),
        }),
        CredentialOperation::TerminateIkev2Connection { connection_name } => {
            if backend != VpnBackendKind::Ikev2 {
                return Err("An IKEv2 credential operation was assigned to another backend.");
            }
            let script = format!(
                r#"set -eu
sas="$(swanctl --list-sas --ike {connection_name} --raw)"
if test -n "$sas"; then
  swanctl --terminate --ike {connection_name} --timeout 10
fi"#,
                connection_name = shell_quote(connection_name),
            );
            Some(format!(
                "set -eu; cd {}; docker compose exec -T gateway /bin/sh -c {}",
                shell_quote(current),
                shell_quote(&script)
            ))
        }
        CredentialOperation::ReadCertificateSerial { relative_path } => {
            let certificate = runtime_container_path(runtime, relative_path)
                .ok_or("The certificate path is outside its declared mount.")?;
            let script = match backend {
                VpnBackendKind::OpenVpn => format!(
                    "set -eu; serial=\"$(openssl x509 -in {} -noout -serial | sed 's/^serial=//;s/^Serial=//')\"; printf 'certificate_serial=%s\\n' \"$serial\"",
                    shell_quote(&certificate)
                ),
                VpnBackendKind::Ikev2 => format!(
                    "set -eu; serial=\"$(cat {}.serial)\"; printf 'certificate_serial=%s\\n' \"$serial\"",
                    shell_quote(&certificate)
                ),
                _ => return Err("Only certificate backends can read certificate serials."),
            };
            Some(credential_container_command(current, runtime, &script)?)
        }
        CredentialOperation::UploadSecret { .. }
        | CredentialOperation::DownloadToSecret { .. }
        | CredentialOperation::InitializeOpenVpnAuthority { .. }
        | CredentialOperation::InitializeIkev2Authority { .. } => None,
    };
    Ok(command)
}

fn parse_certificate_serial(output: &str) -> Option<String> {
    let values = parse_key_values(output);
    values.get("certificate_serial").and_then(|serial| {
        let normalized = serial.trim().to_ascii_uppercase();
        (!normalized.is_empty()
            && normalized.len() <= 64
            && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
    })
}

fn activation_command(
    current: &str,
    stage: &str,
    files: &[RenderedFile],
    plan: &DeploymentPlan,
    runtime: &BackendRuntimeSpec,
) -> String {
    let mut command = format!("set -eu; install -d {}", shell_quote(current));
    for directory in rendered_directories(files) {
        command.push_str(&format!(
            "; install -d {}",
            shell_quote(&format!("{current}/{directory}"))
        ));
    }
    let persistent_paths = certificate_identity_paths(runtime);
    for path in persistent_paths {
        let source = format!("{stage}/{path}");
        let destination = format!("{current}/{path}");
        let parent = Path::new(&destination)
            .parent()
            .expect("declared identity paths have a parent")
            .to_string_lossy();
        let trash = format!(
            "{APP_ROOT}/trash/identity-{}-{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            path.replace('/', "_")
        );
        command.push_str(&format!(
            "; if test -e {source} || test -L {source}; then test ! -L {source}; install -d {parent}; if test -e {destination} || test -L {destination}; then mv {destination} {trash}; fi; mv {source} {destination}; fi",
            source = shell_quote(&source),
            parent = shell_quote(&parent),
            destination = shell_quote(&destination),
            trash = shell_quote(&trash),
        ));
    }
    let changed: Vec<_> = plan
        .operations
        .iter()
        .filter_map(|operation| match operation {
            DeploymentOperation::UploadFile { path, .. }
            | DeploymentOperation::ReplaceFile { path, .. }
                if !persistent_paths
                    .iter()
                    .any(|persistent| path_is_within(path, persistent)) =>
            {
                Some(path)
            }
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
    if let ServerIdentityStrategy::WireGuardLike {
        private_key_path,
        template_path,
        materialized_path,
        ..
    } = runtime.identity
        && (plan
            .operations
            .iter()
            .any(|operation| matches!(operation, DeploymentOperation::GenerateServerKey))
            || plan.operations.iter().any(|operation| {
                matches!(
                    operation,
                    DeploymentOperation::UploadFile { path, .. }
                        | DeploymentOperation::ReplaceFile { path, .. }
                        if path == template_path
                )
            }))
    {
        for path in [private_key_path, materialized_path] {
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

fn remote_health_command(
    state: &DesiredState,
    runtime: &BackendRuntimeSpec,
    managed_dns: bool,
) -> String {
    let mut command = format!(
        r#"set +e
cd {path} || exit 0
services="$(docker compose ps --status running --services 2>/dev/null)"
statuses="$(docker compose ps --all --format '{{{{.Service}}}}|{{{{.State}}}}|{{{{.Health}}}}|{{{{.Status}}}}' 2>/dev/null)"
status_for() {{
  printf '%s\n' "$statuses" | awk -F'|' -v service="$1" '$1 == service {{ health = ($3 == "" ? "none" : $3); print $2 "/" health " " $4; exit }}'
}}
printf 'project=1\n'
printf 'gateway=%s\n' "$(printf '%s\n' "$services" | grep -qx gateway; echo $?)"
printf 'dns=%s\n' "$(printf '%s\n' "$services" | grep -qx dns; echo $?)"
printf 'gateway_status=%s\n' "$(status_for gateway)"
printf 'dns_status=%s\n' "$(status_for dns)"
"#,
        path = shell_quote(&state.instance.remote_path()),
    );
    match runtime.health {
        BackendHealthProbe::WireGuardLike { tool, interface } => {
            write!(
                command,
                r#"
docker compose exec -T gateway {tool} show {interface} >/dev/null 2>&1
printf 'backend=%s\n' "$?"
client_count="$(docker compose exec -T gateway {tool} show {interface} peers 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"
printf 'client_count=%s\n' "$client_count"
printf 'backend_status={tool} interface {interface}\n'
"#
            )
            .expect("writing to a String cannot fail");
        }
        BackendHealthProbe::OpenVpn => {
            command.push_str(
                r#"
docker compose exec -T gateway sh -c 'pidof openvpn >/dev/null && test -s /run/openvpn/status.log' >/dev/null 2>&1
printf 'backend=%s\n' "$?"
client_count="$(docker compose exec -T gateway sh -c 'find /etc/openvpn/ccd -maxdepth 1 -type f ! -name .keep -print 2>/dev/null | wc -l' | tr -d ' ')"
printf 'client_count=%s\n' "$client_count"
printf 'backend_status=OpenVPN process and status file\n'
"#,
            );
        }
        BackendHealthProbe::Ikev2 => {
            command.push_str(
                r#"
docker compose exec -T gateway sh -c 'pidof charon >/dev/null && swanctl --list-conns >/dev/null' >/dev/null 2>&1
printf 'backend=%s\n' "$?"
client_count="$(docker compose exec -T gateway sh -c "swanctl --list-conns 2>/dev/null | grep -Ec '^client-[0-9a-f]{32}:'" | tr -d ' ')"
printf 'client_count=%s\n' "$client_count"
printf 'backend_status=strongSwan daemon and loaded connections\n'
"#,
            );
        }
        BackendHealthProbe::Xray => {
            let BackendValidation::Xray { config_path } = runtime.validation else {
                unreachable!("Xray health requires Xray validation metadata")
            };
            writeln!(
                command,
                r#"
docker compose exec -T gateway xray run -test -c {config_path} >/dev/null 2>&1
printf 'backend=%s\n' "$?"
client_count="$(docker compose exec -T gateway jq -r '.inbounds[0].settings.clients | length' {config_path} 2>/dev/null | tr -d ' ')"
printf 'client_count=%s\n' "$client_count"
printf 'backend_status=Xray active configuration self-test\n'"#,
                config_path = shell_quote(config_path),
            )
            .expect("writing to a String cannot fail");
        }
    }
    for (index, (host, container)) in state
        .instance
        .listeners()
        .iter()
        .zip(&runtime.container_listeners)
        .enumerate()
    {
        writeln!(
            command,
            r#"docker compose port --protocol {protocol} gateway {container_port} 2>/dev/null | grep -Eq ':{host_port}$'
printf 'listener_{index}=%s\n' "$?""#,
            protocol = host.protocol,
            container_port = container.port,
            host_port = host.port,
        )
        .expect("writing to a String cannot fail");
    }
    if managed_dns {
        writeln!(
            command,
            r#"docker compose exec -T gateway nslookup gateway.{zone} 127.0.0.1 >/dev/null 2>&1
printf 'private_dns=%s\n' "$?"
docker compose exec -T gateway nslookup example.com 127.0.0.1 >/dev/null 2>&1
printf 'public_dns=%s\n' "$?""#,
            zone = state.instance.dns.zone,
        )
        .expect("writing to a String cannot fail");
    } else {
        command.push_str("printf 'private_dns=1\\npublic_dns=1\\n'\n");
    }
    command
}

fn port_conflict_command(instance: &VpnInstance, runtime: &BackendRuntimeSpec) -> String {
    let mut command = String::from("set -eu\n");
    let current = shell_quote(&instance.remote_path());
    for (host, container) in instance
        .listeners()
        .iter()
        .zip(&runtime.container_listeners)
    {
        let ss_mode = match host.protocol {
            TransportProtocol::Tcp => "-ltn",
            TransportProtocol::Udp => "-lun",
        };
        writeln!(
            command,
            r"if ss -H {ss_mode} | awk '{{print $5}}' | grep -Eq ':{host_port}$'; then
  if test ! -d {current} || ! (cd {current} && docker compose port --protocol {protocol} gateway {container_port} 2>/dev/null | grep -Eq ':{host_port}$'); then
    printf '{protocol_upper} port {host_port} is already in use\n' >&2
    exit 42
  fi
fi",
            host_port = host.port,
            protocol = host.protocol,
            protocol_upper = host.protocol.as_str().to_ascii_uppercase(),
            container_port = container.port,
        )
        .expect("writing to a String cannot fail");
    }
    command
}

fn image_prepare_command(stage: &str, runtime: &BackendRuntimeSpec, managed_dns: bool) -> String {
    let mut command = String::from("set -eu");
    match runtime.image {
        ContainerImage::Pull(reference) => {
            write!(command, "; docker pull {}", shell_quote(reference))
                .expect("writing to a String cannot fail");
        }
        ContainerImage::Build { .. } => {
            write!(
                command,
                "; cd {}; docker compose --env-file .env build gateway",
                shell_quote(stage)
            )
            .expect("writing to a String cannot fail");
        }
    }
    if managed_dns {
        write!(command, "; docker pull {}", shell_quote(COREDNS_IMAGE))
            .expect("writing to a String cannot fail");
    }
    command
}

fn compose_activation_command(current: &str, plan: &DeploymentPlan, managed_dns: bool) -> String {
    let operation = if plan
        .operations
        .iter()
        .any(|operation| matches!(operation, DeploymentOperation::ReloadDns))
    {
        "docker compose restart dns".to_owned()
    } else if plan.operations.iter().any(|operation| {
        matches!(
            operation,
            DeploymentOperation::ComposeRestart { service } if service == "gateway"
        )
    }) {
        if managed_dns {
            "docker compose restart gateway && docker compose restart dns".into()
        } else {
            "docker compose restart gateway".into()
        }
    } else if plan
        .operations
        .iter()
        .any(|operation| matches!(operation, DeploymentOperation::ComposeUp))
    {
        "docker compose up -d --remove-orphans".into()
    } else {
        "true".into()
    };
    format!("set -eu; cd {}; {operation}", shell_quote(current))
}

fn runtime_image_reference(runtime: &BackendRuntimeSpec) -> &'static str {
    match runtime.image {
        ContainerImage::Pull(reference) => reference,
        ContainerImage::Build { tag, .. } => tag,
    }
}

fn prepare_numeric_mount_ownership_command(
    current: &str,
    runtime: &BackendRuntimeSpec,
) -> Option<String> {
    let mut command = String::from("set -eu");
    let mut changed = false;
    for mount in runtime.mounts.iter().filter(|mount| {
        !mount.read_only && matches!(mount.ownership, ContainerMountOwnership::Numeric { .. })
    }) {
        let ContainerMountOwnership::Numeric { uid, gid } = mount.ownership else {
            unreachable!("the iterator retains only numeric ownership")
        };
        let bind = format!("{current}/{}:/work", mount.host_path);
        write!(
            command,
            "; docker run --rm --user 0:0 --entrypoint sh -v {} {} -c {}",
            shell_quote(&bind),
            shell_quote(runtime_image_reference(runtime)),
            shell_quote(&format!("chown -R {uid}:{gid} /work"))
        )
        .expect("writing to a String cannot fail");
        changed = true;
    }
    changed.then_some(command)
}

fn normalize_host_mount_ownership_command(
    current: &str,
    runtime: &BackendRuntimeSpec,
) -> Option<String> {
    let mut command = String::from("set -eu");
    let mut changed = false;
    for mount in runtime
        .mounts
        .iter()
        .filter(|mount| !mount.read_only && mount.ownership == ContainerMountOwnership::HostUser)
    {
        let bind = format!("{current}/{}:/work", mount.host_path);
        write!(
            command,
            "; docker run --rm --user 0:0 --entrypoint sh -e VAM_UID=\"$(id -u)\" -e VAM_GID=\"$(id -g)\" -v {} {} -c {}",
            shell_quote(&bind),
            shell_quote(runtime_image_reference(runtime)),
            shell_quote("chown -R \"$VAM_UID:$VAM_GID\" /work"),
        )
        .expect("writing to a String cannot fail");
        changed = true;
    }
    changed.then_some(command)
}

fn materialize_server_identity_command(
    current: &str,
    stage: &str,
    runtime: &BackendRuntimeSpec,
) -> Option<String> {
    let ServerIdentityStrategy::WireGuardLike {
        tool,
        private_key_path,
        template_path,
        materialized_path,
        sentinel,
    } = runtime.identity
    else {
        return None;
    };
    let current_key = format!("{current}/{private_key_path}");
    let stage_key = format!("{stage}/{private_key_path}");
    let private_in_container = format!("/work/{private_key_path}");
    let template_in_container = format!("/work/{template_path}");
    let materialized_in_container = format!("/work/{materialized_path}");
    let script = format!(
        r#"set -eu
umask 077
private_key={private_key}
template={template}
materialized={materialized}
test -s "$private_key" || {tool} genkey > "$private_key"
public_key="$({tool} pubkey < "$private_key")"
awk -v sentinel={sentinel} -v key_file="$private_key" '
  $0 == "PrivateKey = " sentinel {{
    if ((getline key < key_file) <= 0) exit 42
    print "PrivateKey = " key
    next
  }}
  {{ print }}
' "$template" > "$materialized"
chmod 0600 "$private_key" "$materialized"
printf 'server_public_key=%s\n' "$public_key"
"#,
        private_key = shell_quote(&private_in_container),
        template = shell_quote(&template_in_container),
        materialized = shell_quote(&materialized_in_container),
        sentinel = shell_quote(sentinel),
    );
    let preserve = if current == stage {
        String::new()
    } else {
        format!(
            "if test -r {current_key}; then cp {current_key} {stage_key}; fi; ",
            current_key = shell_quote(&current_key),
            stage_key = shell_quote(&stage_key),
        )
    };
    Some(format!(
        "set -eu; {preserve}docker run --rm --entrypoint sh -v {stage_mount} {image} -c {script}",
        stage_mount = shell_quote(&format!("{stage}:/work")),
        image = shell_quote(runtime_image_reference(runtime)),
        script = shell_quote(&script),
    ))
}

fn runtime_container_path(runtime: &BackendRuntimeSpec, relative_path: &str) -> Option<String> {
    runtime.mounts.iter().find_map(|mount| {
        let suffix = if relative_path == mount.host_path {
            Some("")
        } else {
            relative_path.strip_prefix(&format!("{}/", mount.host_path))
        }?;
        Some(if suffix.is_empty() {
            mount.container_path.into()
        } else {
            format!("{}/{suffix}", mount.container_path.trim_end_matches('/'))
        })
    })
}

fn runtime_host_path(runtime: &BackendRuntimeSpec, container_path: &str) -> Option<String> {
    runtime.mounts.iter().find_map(|mount| {
        let suffix = if container_path == mount.container_path {
            Some("")
        } else {
            container_path.strip_prefix(&format!("{}/", mount.container_path.trim_end_matches('/')))
        }?;
        Some(if suffix.is_empty() {
            mount.host_path.into()
        } else {
            format!("{}/{suffix}", mount.host_path.trim_end_matches('/'))
        })
    })
}

fn validation_command(stage: &str, runtime: &BackendRuntimeSpec, managed_dns: bool) -> String {
    let image = shell_quote(runtime_image_reference(runtime));
    let mut command = String::from("set -eu");
    match runtime.validation {
        BackendValidation::WireGuardQuick { tool, config_path } => {
            let container_config = runtime_container_path(runtime, config_path)
                .expect("backend validation path must be under a declared mount");
            let mount = runtime
                .mounts
                .iter()
                .find(|mount| config_path.starts_with(mount.host_path))
                .expect("backend validation path must be under a declared mount");
            let mount_value = format!("{stage}/{}:{}:ro", mount.host_path, mount.container_path);
            let script = format!(
                "{} strip {} >/dev/null",
                tool,
                shell_quote(&container_config)
            );
            write!(
                command,
                "; docker run --rm --entrypoint sh -v {} {} -c {}",
                shell_quote(&mount_value),
                image,
                shell_quote(&script)
            )
            .expect("writing to a String cannot fail");
        }
        BackendValidation::OpenVpn { config_path } => {
            let container_config = runtime_container_path(runtime, config_path)
                .expect("backend validation path must be under a declared mount");
            let mount = runtime
                .mounts
                .iter()
                .find(|mount| config_path.starts_with(mount.host_path))
                .expect("backend validation path must be under a declared mount");
            let mount_value = format!("{stage}/{}:{}:ro", mount.host_path, mount.container_path);
            write!(
                command,
                "; docker run --rm --entrypoint openvpn -v {} {} --config {} --test-crypto",
                shell_quote(&mount_value),
                image,
                shell_quote(&container_config)
            )
            .expect("writing to a String cannot fail");
        }
        BackendValidation::Ikev2 => {
            write!(
                command,
                "; test -s {}; docker run --rm --entrypoint swanctl {} --version >/dev/null",
                shell_quote(&format!("{stage}/ikev2/swanctl.conf")),
                image
            )
            .expect("writing to a String cannot fail");
        }
        BackendValidation::Xray { .. } => {
            write!(
                command,
                "; test -s {}; docker run --rm --entrypoint xray {} version >/dev/null",
                shell_quote(&format!("{stage}/xray/server-template.json")),
                image
            )
            .expect("writing to a String cannot fail");
        }
    }
    if managed_dns {
        let dns_mount = format!("{stage}/dns:/etc/coredns:ro");
        write!(
            command,
            r#"; cid="$(docker run -d --rm -v {dns_mount} {dns_image} -conf /etc/coredns/Corefile)"; trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT HUP INT TERM; sleep 1; test "$(docker inspect -f '{{{{.State.Running}}}}' "$cid")" = true; docker rm -f "$cid" >/dev/null; cid=; trap - EXIT HUP INT TERM"#,
            dns_mount = shell_quote(&dns_mount),
            dns_image = shell_quote(COREDNS_IMAGE),
        )
        .expect("writing to a String cannot fail");
    }
    write!(
        command,
        "; cd {}; docker compose --env-file .env config --quiet",
        shell_quote(stage)
    )
    .expect("writing to a String cannot fail");
    command
}

fn firewall_allow_command(listeners: &[ListenerPort]) -> String {
    let mut ufw_rules = String::new();
    let mut firewalld_rules = String::new();
    for listener in listeners {
        writeln!(
            ufw_rules,
            "    sudo -n ufw allow {}/{} >/dev/null",
            listener.port, listener.protocol
        )
        .expect("writing to a String cannot fail");
        writeln!(
            firewalld_rules,
            "  sudo -n firewall-cmd --permanent --add-port={}/{} >/dev/null",
            listener.port, listener.protocol
        )
        .expect("writing to a String cannot fail");
    }
    format!(
        r"set -eu
if command -v ufw >/dev/null 2>&1; then
  if sudo -n ufw status 2>/dev/null | grep -q '^Status: active'; then
{ufw_rules}\
  elif ! sudo -n ufw status >/dev/null 2>&1; then
    printf 'UFW is installed, but its status could not be checked with sudo -n.\n' >&2
    exit 43
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
{firewalld_rules}\
  sudo -n firewall-cmd --reload >/dev/null
fi
"
    )
}

fn firewall_remove_command(listeners: &[ListenerPort]) -> String {
    let mut ufw_rules = String::new();
    let mut firewalld_rules = String::new();
    for listener in listeners {
        writeln!(
            ufw_rules,
            "    sudo -n ufw delete allow {}/{} >/dev/null 2>&1 || true",
            listener.port, listener.protocol
        )
        .expect("writing to a String cannot fail");
        writeln!(
            firewalld_rules,
            "  sudo -n firewall-cmd --permanent --remove-port={}/{} >/dev/null 2>&1 || true",
            listener.port, listener.protocol
        )
        .expect("writing to a String cannot fail");
    }
    format!(
        r"set -eu
if command -v ufw >/dev/null 2>&1; then
  if sudo -n ufw status 2>/dev/null | grep -q '^Status: active'; then
{ufw_rules}\
  elif ! sudo -n ufw status >/dev/null 2>&1; then
    printf 'UFW is installed, but its status could not be checked with sudo -n.\n' >&2
    exit 43
  fi
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
{firewalld_rules}\
  sudo -n firewall-cmd --reload >/dev/null
fi
"
    )
}

fn listener_summary(listeners: &[ListenerPort]) -> String {
    listeners
        .iter()
        .enumerate()
        .fold(String::new(), |mut output, (index, listener)| {
            if index > 0 {
                output.push_str(", ");
            }
            write!(output, "{}/{}", listener.port, listener.protocol)
                .expect("writing to a String cannot fail");
            output
        })
}

fn backup_path(instance_id: Uuid, name: &str) -> String {
    format!("{APP_ROOT}/backups/{instance_id}/{name}")
}

fn server_public_key_setting(instance_id: Uuid) -> String {
    format!("wireguard_server_public_key:{instance_id}")
}

fn certificate_authority_setting(instance_id: Uuid) -> String {
    format!("certificate_authority_initialized:{instance_id}")
}

#[cfg(not(test))]
fn hostlist_cache_setting(source_id: Uuid) -> String {
    format!("dns_hostlist_cache:{source_id}")
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
        && health.backend_ready
        && health.listeners_ready
        && health.client_state_matches
        && (!health.dns_required
            || (health.dns_running && health.private_dns_resolves && health.public_dns_resolves))
}

fn settings_change_warning(impact: ChangeImpact) -> Option<&'static str> {
    match impact {
        ChangeImpact::LiveUpdate => None,
        ChangeImpact::ServiceRestart => {
            Some("Backend settings changed; the gateway service must restart.")
        }
        ChangeImpact::Reinstall => Some(
            "Destructive reinstall-class backend settings change detected. Review the persistent identity impact before Apply; the complete instance tree will be backed up first.",
        ),
    }
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

#[derive(Debug, PartialEq, Eq)]
enum HostProvisioningError {
    UnsupportedOperatingSystem(String),
    AuthorityRequired,
    PackageManagerUnsupported,
    Serialization(String),
}

fn host_provisioning_error(host_id: Uuid, error: HostProvisioningError) -> AppError {
    match error {
        HostProvisioningError::UnsupportedOperatingSystem(operating_system) => AppError {
            code: "host_provisioning_unsupported_os".into(),
            message: "Automatic host setup supports Linux targets only.".into(),
            scope: Some(host_id.to_string()),
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: Some("Prepare Docker Engine and Docker Compose v2 manually.".into()),
            technical_detail: Some(format!("Detected operating system: {operating_system}")),
        },
        HostProvisioningError::AuthorityRequired => AppError {
            code: "host_provisioning_authority_required".into(),
            message: "Host setup requires root or noninteractive sudo.".into(),
            scope: Some(host_id.to_string()),
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: Some(
                "Connect as root, configure narrowly scoped passwordless sudo, or install Docker and Compose manually."
                    .into(),
            ),
            technical_detail: None,
        },
        HostProvisioningError::PackageManagerUnsupported => AppError {
            code: "host_provisioning_package_manager_unsupported".into(),
            message: "No supported Linux package manager was detected.".into(),
            scope: Some(host_id.to_string()),
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: Some(
                "Install Docker Engine and Docker Compose v2 manually, then inspect the host again."
                    .into(),
            ),
            technical_detail: Some("Supported managers: apt, dnf, yum, zypper, pacman.".into()),
        },
        HostProvisioningError::Serialization(detail) => AppError {
            code: "serialization".into(),
            message: "The host setup plan could not be encoded.".into(),
            scope: Some(host_id.to_string()),
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: Some("Inspect the host and create a new setup plan.".into()),
            technical_detail: Some(detail),
        },
    }
}

fn build_host_provisioning_plan(
    host_id: Uuid,
    inspection: &HostInspection,
) -> Result<HostProvisioningPlan, HostProvisioningError> {
    if inspection.operating_system != "Linux" {
        return Err(HostProvisioningError::UnsupportedOperatingSystem(
            inspection.operating_system.clone(),
        ));
    }

    let compose_ready = inspection
        .compose_version
        .as_deref()
        .and_then(version_major)
        .is_some_and(|major| major >= 2);
    if inspection.docker_accessible && compose_ready {
        return host_provisioning_plan(host_id, inspection, Vec::new(), Vec::new());
    }

    if !inspection.effective_user_is_root && !inspection.sudo_bootstrap_available {
        return Err(HostProvisioningError::AuthorityRequired);
    }

    let package_changes_required = !inspection.docker_installed || !compose_ready;
    if package_changes_required && inspection.package_manager.is_none() {
        return Err(HostProvisioningError::PackageManagerUnsupported);
    }

    let mut operations = Vec::new();
    if !inspection.docker_installed {
        operations.push(HostProvisioningOperation::InstallDockerEngine);
    }
    if !compose_ready {
        operations.push(HostProvisioningOperation::InstallComposePlugin);
    }
    if !inspection.docker_privileged_accessible {
        operations.push(HostProvisioningOperation::EnableDockerService);
    }
    if !inspection.effective_user_is_root
        && !inspection.docker_accessible
        && !inspection.docker_group_member
    {
        operations.push(HostProvisioningOperation::GrantDockerAccess);
    }
    operations.push(HostProvisioningOperation::VerifyPrerequisites);

    let mut warnings = Vec::new();
    if package_changes_required {
        warnings.push(
            "Setup installs only distribution-provided packages; package versions are controlled by the host repositories."
                .into(),
        );
    }
    if operations.contains(&HostProvisioningOperation::GrantDockerAccess) {
        warnings.push(
            "Adding the SSH user to the Docker group grants root-equivalent control of this host."
                .into(),
        );
    }
    host_provisioning_plan(host_id, inspection, operations, warnings)
}

fn host_provisioning_plan(
    host_id: Uuid,
    inspection: &HostInspection,
    operations: Vec<HostProvisioningOperation>,
    warnings: Vec<String>,
) -> Result<HostProvisioningPlan, HostProvisioningError> {
    let encoded = serde_json::to_vec(&(host_id, inspection, &operations))
        .map_err(|error| HostProvisioningError::Serialization(error.to_string()))?;
    let expected_state_hash = format!("{:x}", Sha256::digest(encoded));
    Ok(HostProvisioningPlan {
        host_id,
        package_manager: inspection.package_manager,
        operations,
        warnings,
        expected_state_hash,
    })
}

fn host_deployment_prerequisites_ready(inspection: &HostInspection) -> bool {
    inspection.operating_system == "Linux"
        && inspection.docker_installed
        && inspection.docker_accessible
        && inspection
            .compose_version
            .as_deref()
            .and_then(version_major)
            .is_some_and(|major| major >= 2)
}

fn host_provisioning_script(
    package_manager: Option<PackageManager>,
    operations: &[HostProvisioningOperation],
) -> Result<String, HostProvisioningError> {
    let install_docker = operations.contains(&HostProvisioningOperation::InstallDockerEngine);
    let install_compose = operations.contains(&HostProvisioningOperation::InstallComposePlugin);
    let enable_docker = operations.contains(&HostProvisioningOperation::EnableDockerService);
    let grant_docker = operations.contains(&HostProvisioningOperation::GrantDockerAccess);
    if (install_docker || install_compose) && package_manager.is_none() {
        return Err(HostProvisioningError::PackageManagerUnsupported);
    }

    let mut script = format!(
        "set -eu\nINSTALL_DOCKER={}\nINSTALL_COMPOSE={}\nENABLE_DOCKER={}\nGRANT_DOCKER={}\n",
        u8::from(install_docker),
        u8::from(install_compose),
        u8::from(enable_docker),
        u8::from(grant_docker),
    );
    script.push_str(
        r#"if test "$(id -u)" -eq 0; then
  SUDO=
else
  command -v sudo >/dev/null 2>&1
  sudo -n true
  SUDO='sudo -n'
fi
"#,
    );

    let package_commands = match package_manager {
        Some(PackageManager::Apt) => {
            r#"if test "$INSTALL_DOCKER" = 1 || test "$INSTALL_COMPOSE" = 1; then
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get -q update
fi
if test "$INSTALL_DOCKER" = 1 && ! command -v docker >/dev/null 2>&1; then
  $SUDO apt-get -yq install --install-recommends docker.io ca-certificates iproute2
fi
if test "$INSTALL_COMPOSE" = 1 && ! docker compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'; then
  if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    $SUDO apt-get -yq install docker-compose-v2
  elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    $SUDO apt-get -yq install docker-compose-plugin
  else
    printf 'No distribution-provided Docker Compose v2 package was found.\n' >&2
    exit 46
  fi
fi
"#
        }
        Some(PackageManager::Dnf) => {
            r#"if test "$INSTALL_DOCKER" = 1 || test "$INSTALL_COMPOSE" = 1; then
  $SUDO dnf -y makecache
fi
if test "$INSTALL_DOCKER" = 1 && ! command -v docker >/dev/null 2>&1; then
  if dnf -q list --available docker >/dev/null 2>&1 || rpm -q docker >/dev/null 2>&1; then
    docker_package=docker
  elif dnf -q list --available moby-engine >/dev/null 2>&1 || rpm -q moby-engine >/dev/null 2>&1; then
    docker_package=moby-engine
  else
    printf 'No distribution-provided Docker Engine package was found.\n' >&2
    exit 45
  fi
  $SUDO dnf -y install "$docker_package" ca-certificates iproute
fi
if test "$INSTALL_COMPOSE" = 1 && ! docker compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'; then
  if dnf -q list --available docker-compose-plugin >/dev/null 2>&1 || rpm -q docker-compose-plugin >/dev/null 2>&1; then
    compose_package=docker-compose-plugin
  elif dnf -q list --available docker-compose >/dev/null 2>&1 || rpm -q docker-compose >/dev/null 2>&1; then
    compose_package=docker-compose
  else
    printf 'No distribution-provided Docker Compose v2 package was found.\n' >&2
    exit 46
  fi
  $SUDO dnf -y install "$compose_package"
fi
"#
        }
        Some(PackageManager::Yum) => {
            r#"if test "$INSTALL_DOCKER" = 1 || test "$INSTALL_COMPOSE" = 1; then
  $SUDO yum -y makecache
fi
if test "$INSTALL_DOCKER" = 1 && ! command -v docker >/dev/null 2>&1; then
  if yum -q list available docker >/dev/null 2>&1 || rpm -q docker >/dev/null 2>&1; then
    docker_package=docker
  elif yum -q list available moby-engine >/dev/null 2>&1 || rpm -q moby-engine >/dev/null 2>&1; then
    docker_package=moby-engine
  else
    printf 'No distribution-provided Docker Engine package was found.\n' >&2
    exit 45
  fi
  $SUDO yum -y -q install "$docker_package" ca-certificates iproute
fi
if test "$INSTALL_COMPOSE" = 1 && ! docker compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'; then
  if yum -q list available docker-compose-plugin >/dev/null 2>&1 || rpm -q docker-compose-plugin >/dev/null 2>&1; then
    compose_package=docker-compose-plugin
  elif yum -q list available docker-compose >/dev/null 2>&1 || rpm -q docker-compose >/dev/null 2>&1; then
    compose_package=docker-compose
  else
    printf 'No distribution-provided Docker Compose v2 package was found.\n' >&2
    exit 46
  fi
  $SUDO yum -y -q install "$compose_package"
fi
"#
        }
        Some(PackageManager::Zypper) => {
            r#"if test "$INSTALL_DOCKER" = 1 || test "$INSTALL_COMPOSE" = 1; then
  $SUDO zypper -nq refresh
fi
if test "$INSTALL_DOCKER" = 1 && ! command -v docker >/dev/null 2>&1; then
  $SUDO zypper -nq install docker ca-certificates iproute2
fi
if test "$INSTALL_COMPOSE" = 1 && ! docker compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'; then
  if ! $SUDO zypper -nq install docker-compose; then
    $SUDO zypper -nq install docker-compose-plugin
  fi
fi
"#
        }
        Some(PackageManager::Pacman) => {
            r#"if test "$INSTALL_DOCKER" = 1 && ! command -v docker >/dev/null 2>&1; then
  $SUDO pacman -Sy --needed --noconfirm docker ca-certificates iproute2
elif test "$INSTALL_COMPOSE" = 1; then
  $SUDO pacman -Sy
fi
if test "$INSTALL_COMPOSE" = 1 && ! docker compose version --short 2>/dev/null | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'; then
  $SUDO pacman -S --needed --noconfirm docker-compose
fi
"#
        }
        None => "",
    };
    script.push_str(package_commands);
    script.push_str(
        r#"if test "$ENABLE_DOCKER" = 1; then
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable --now docker
  elif command -v service >/dev/null 2>&1; then
    $SUDO service docker start
  else
    printf 'No supported service manager was found for Docker.\n' >&2
    exit 47
  fi
fi
if test "$GRANT_DOCKER" = 1 && ! id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
  getent group docker >/dev/null 2>&1 || $SUDO groupadd --system docker
  $SUDO usermod -aG docker "$(id -un)"
fi
$SUDO docker info >/dev/null
$SUDO docker compose version --short | grep -Eq '^v?([2-9]|[1-9][0-9]+)\.'
"#,
    );
    Ok(script)
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

fn normalize_dns_owner(value: &str, zone: &str) -> Result<Option<String>, String> {
    let owner = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if owner.is_empty() {
        return Ok(None);
    }
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if owner == zone || owner.ends_with(&format!(".{zone}")) {
        return Ok(Some(owner));
    }
    if owner.contains('.') {
        return Err(format!(
            "DNS names must be short names inside {zone}, or fully-qualified names ending in .{zone}."
        ));
    }
    Ok(Some(format!("{owner}.{zone}")))
}

fn validate_dns_hostlist(
    id: Uuid,
    name: &str,
    url: &str,
    coverage: &str,
) -> Result<DnsHostlist, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Hostlist name is required.".into());
    }
    let parsed = reqwest::Url::parse(url.trim())
        .map_err(|_| "Hostlist URL must be a valid HTTPS URL.".to_owned())?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err("Hostlist URL must use HTTPS.".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Hostlist URLs must not include credentials.".into());
    }
    Ok(DnsHostlist {
        id,
        name: name.into(),
        url: parsed.to_string(),
        coverage: coverage.trim().into(),
    })
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

#[cfg(not(test))]
fn hostlist_error(error: reqwest::Error) -> AppError {
    AppError {
        code: "hostlist_fetch".into(),
        message: "A selected DNS hostlist could not be refreshed.".into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Retry DNS refresh or use the cached hostlist if one exists.".into()),
        technical_detail: Some(error.to_string()),
    }
}

#[cfg(not(test))]
fn hostlist_timeout_error(source: &DnsHostlist) -> AppError {
    AppError {
        code: "hostlist_timeout".into(),
        message: format!("{} took too long to refresh.", source.name),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Retry DNS refresh; cached domains are used when available.".into()),
        technical_detail: Some(source.url.clone()),
    }
}

fn storage_error(error: StorageError) -> AppError {
    let (message, remediation) = match &error {
        StorageError::NotFound => (
            "The requested record was not found.",
            "Refresh the view and try again.",
        ),
        StorageError::HostHasActiveInstances => (
            "Delete this host's VPN instances before removing the Docker host.",
            "Open Instances, delete every instance on this host, then retry host deletion.",
        ),
        StorageError::HostKeyChanged => (
            "The SSH host key changed.",
            "Verify the host identity before approving the new key.",
        ),
        _ => (
            "Local persistence failed.",
            "Check the local database and retry.",
        ),
    };
    AppError {
        code: "storage".into(),
        message: message.into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some(remediation.into()),
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

fn backend_error(error: BackendError) -> AppError {
    AppError {
        code: "backend".into(),
        message: error.to_string(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some(
            "Correct the backend settings or replace missing identity material.".into(),
        ),
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
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let detail = format!(
        "exit_status={}\nstdout:\n{}\nstderr:\n{}",
        result.exit_status, stdout, stderr
    );
    AppError {
        code: "remote_command".into(),
        message: "A fixed remote operation failed.".into(),
        scope: Some(scope.into()),
        remote_state_changed: changed,
        rollback_succeeded: None,
        remediation: Some("Expand the technical details and inspect the remote host.".into()),
        technical_detail: Some(redact(&detail, &[])),
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
    use std::collections::VecDeque;
    use std::sync::RwLock;
    use vam_secrets::MemorySecretStore;

    struct FakeTransport {
        key: RwLock<HostKeyInfo>,
        commands: std::sync::Mutex<Vec<String>>,
        uploads: std::sync::Mutex<Vec<(String, String)>>,
        responses: std::sync::Mutex<VecDeque<CommandResult>>,
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
            let mut commands = self.commands.lock().expect("test command lock");
            let after_stop = commands
                .last()
                .is_some_and(|previous| previous.contains("docker compose stop"));
            commands.push(command.to_owned());
            if let Some(result) = self
                .responses
                .lock()
                .expect("test response lock")
                .pop_front()
            {
                return Ok(result);
            }
            if command.contains("services=\"$(docker compose ps --status running --services") {
                let stdout = if after_stop {
                    b"project=1\ngateway=1\ndns=1\ngateway_status=exited/none Exited (0)\ndns_status=exited/none Exited (0)\nbackend=1\nclient_count=0\nbackend_status=stopped\nlistener_0=1\nprivate_dns=1\npublic_dns=1\n".to_vec()
                } else {
                    b"project=1\ngateway=0\ndns=0\ngateway_status=running/none Up 1 second\ndns_status=running/none Up 1 second\nbackend=0\nclient_count=1\nbackend_status=ready\nlistener_0=0\nprivate_dns=0\npublic_dns=0\n".to_vec()
                };
                return Ok(CommandResult {
                    stdout,
                    stderr: Vec::new(),
                    exit_status: 0,
                });
            }
            Ok(CommandResult {
                stdout: b"operating_system=Linux\narchitecture=x86_64\npackage_manager=apt\neffective_user_is_root=1\ndocker_group_member=0\ndocker_installed=0\ndocker_version=29.0.0\ndocker_accessible=0\ncompose_version=5.3.1\ndocker_privileged_accessible=0\nwireguard=0\nroot_writable=0\nsudo_bootstrap=1\n".to_vec(),
                stderr: Vec::new(),
                exit_status: 0,
            })
        }

        async fn upload(&self, request: UploadRequest<'_>) -> Result<(), SshError> {
            self.uploads.lock().expect("test upload lock").push((
                request.remote_path.to_owned(),
                String::from_utf8_lossy(request.contents).into_owned(),
            ));
            Ok(())
        }

        async fn download(
            &self,
            _request: DownloadRequest<'_>,
        ) -> Result<Zeroizing<Vec<u8>>, SshError> {
            Err(SshError::Protocol(
                "the fake transport has no requested download".into(),
            ))
        }
    }

    fn fake_transport() -> Arc<FakeTransport> {
        Arc::new(FakeTransport {
            key: RwLock::new(HostKeyInfo {
                hostname: "lab".into(),
                resolved_address: "192.0.2.1".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                sha256_fingerprint: "SHA256:first".into(),
                public_key_base64: "first-key".into(),
            }),
            commands: std::sync::Mutex::new(Vec::new()),
            uploads: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::new()),
        })
    }

    fn command_state(kind: VpnBackendKind) -> DesiredState {
        let now = Utc::now();
        DesiredState {
            instance: VpnInstance {
                id: Uuid::nil(),
                host_id: Uuid::from_u128(1),
                display_name: "Command Test".into(),
                backend: kind,
                backend_settings: BackendSettings::defaults_for(kind, "vpn.example.test"),
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: kind.default_port(),
                },
                network: NetworkConfig {
                    ipv4_subnet: "10.64.0.0/24".parse().unwrap(),
                    gateway_ipv4: "10.64.0.1".parse().unwrap(),
                    ipv6_subnet: None,
                    gateway_ipv6: None,
                },
                dns: DnsConfig {
                    zone: "internal".into(),
                    soa_serial: 2_026_073_001,
                },
                routing_mode: RoutingMode::SplitTunnel,
                persistent_keepalive: DEFAULT_KEEPALIVE,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            },
            users: Vec::new(),
            devices: Vec::new(),
            dns_records: Vec::new(),
            dns_blocklist_domains: Vec::new(),
        }
    }

    fn host_inspection(package_manager: Option<PackageManager>) -> HostInspection {
        HostInspection {
            operating_system: "Linux".into(),
            architecture: "x86_64".into(),
            package_manager,
            effective_user_is_root: true,
            docker_installed: false,
            docker_version: None,
            compose_version: None,
            docker_accessible: false,
            docker_privileged_accessible: false,
            docker_group_member: false,
            wireguard_kernel_available: false,
            application_root_writable: false,
            sudo_bootstrap_available: false,
            warnings: vec![],
        }
    }

    fn queued_result(stdout: &str, stderr: &str, exit_status: u32) -> CommandResult {
        CommandResult {
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            exit_status,
        }
    }

    const FRESH_APT_HOST: &str = "operating_system=Linux\narchitecture=x86_64\npackage_manager=apt\neffective_user_is_root=1\ndocker_group_member=1\ndocker_installed=127\ndocker_version=\ndocker_accessible=127\ncompose_version=\ndocker_privileged_accessible=127\nwireguard=1\nroot_writable=1\nsudo_bootstrap=0\n";
    const READY_APT_HOST: &str = "operating_system=Linux\narchitecture=x86_64\npackage_manager=apt\neffective_user_is_root=1\ndocker_group_member=0\ndocker_installed=0\ndocker_version=29.0.0\ndocker_accessible=0\ncompose_version=2.40.0\ndocker_privileged_accessible=0\nwireguard=1\nroot_writable=1\nsudo_bootstrap=0\n";
    const HEALTHY_XRAY: &str = "project=1\ngateway=0\ndns=1\ngateway_status=running/none Up 1 second\ndns_status=absent\nbackend=0\nclient_count=0\nbackend_status=ready\nlistener_0=0\nprivate_dns=1\npublic_dns=1\n";

    #[test]
    fn host_setup_plans_are_deterministic_and_noop_when_ready() {
        let host_id = Uuid::from_u128(42);
        let mut ready = host_inspection(Some(PackageManager::Apt));
        ready.docker_installed = true;
        ready.docker_version = Some("29.0.0".into());
        ready.compose_version = Some("v2.40.0".into());
        ready.docker_accessible = true;
        ready.docker_privileged_accessible = true;

        let first = build_host_provisioning_plan(host_id, &ready).unwrap();
        let second = build_host_provisioning_plan(host_id, &ready).unwrap();
        assert!(first.operations.is_empty());
        assert_eq!(first.expected_state_hash, second.expected_state_hash);
        assert_eq!(first.expected_state_hash.len(), 64);
    }

    #[test]
    fn host_setup_uses_fixed_idempotent_scripts_for_every_supported_manager() {
        let managers = [
            (PackageManager::Apt, "apt-get -yq install"),
            (PackageManager::Dnf, "dnf -y install"),
            (PackageManager::Yum, "yum -y -q install"),
            (PackageManager::Zypper, "zypper -nq install"),
            (PackageManager::Pacman, "pacman -Sy --needed"),
        ];
        for (manager, expected_command) in managers {
            let inspection = host_inspection(Some(manager));
            let plan = build_host_provisioning_plan(Uuid::from_u128(7), &inspection).unwrap();
            assert_eq!(
                plan.operations,
                vec![
                    HostProvisioningOperation::InstallDockerEngine,
                    HostProvisioningOperation::InstallComposePlugin,
                    HostProvisioningOperation::EnableDockerService,
                    HostProvisioningOperation::VerifyPrerequisites,
                ]
            );
            let script = host_provisioning_script(plan.package_manager, &plan.operations).unwrap();
            assert!(script.contains(expected_command));
            assert!(script.contains("systemctl enable --now docker"));
            assert!(script.contains("docker compose version --short"));
            assert!(script.contains("command -v docker"));
            assert!(!script.contains("curl"));
            assert!(!script.contains("wget"));
            assert!(!script.contains("http://"));
            assert!(!script.contains("https://"));
        }
    }

    #[test]
    fn host_setup_requires_authority_and_supported_package_management() {
        let mut unprivileged = host_inspection(Some(PackageManager::Apt));
        unprivileged.effective_user_is_root = false;
        assert_eq!(
            build_host_provisioning_plan(Uuid::nil(), &unprivileged).unwrap_err(),
            HostProvisioningError::AuthorityRequired
        );

        let unsupported = host_inspection(None);
        assert_eq!(
            build_host_provisioning_plan(Uuid::nil(), &unsupported).unwrap_err(),
            HostProvisioningError::PackageManagerUnsupported
        );
    }

    #[test]
    fn host_setup_discloses_root_equivalent_docker_group_access() {
        let mut inspection = host_inspection(Some(PackageManager::Apt));
        inspection.effective_user_is_root = false;
        inspection.sudo_bootstrap_available = true;
        let plan = build_host_provisioning_plan(Uuid::nil(), &inspection).unwrap();
        assert!(
            plan.operations
                .contains(&HostProvisioningOperation::GrantDockerAccess)
        );
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("root-equivalent"))
        );
        let script = host_provisioning_script(plan.package_manager, &plan.operations).unwrap();
        assert!(script.contains("usermod -aG docker"));
        assert!(script.contains("sudo -n true"));
    }

    #[test]
    fn deployment_preview_discloses_restart_and_destructive_reinstall_impact() {
        assert!(settings_change_warning(ChangeImpact::LiveUpdate).is_none());
        assert!(
            settings_change_warning(ChangeImpact::ServiceRestart)
                .is_some_and(|warning| warning.contains("must restart"))
        );
        assert!(
            settings_change_warning(ChangeImpact::Reinstall)
                .is_some_and(|warning| warning.contains("Destructive reinstall-class"))
        );
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
        let runtime = WireGuardBackend
            .runtime(&BackendSettings::default())
            .expect("WireGuard runtime");
        let command = activation_command("/safe/current", "/safe/stage", &files, &plan, &runtime);
        assert!(command.contains("'/safe/stage/dns/zones/db.vpn.internal'"));
        assert!(!command.contains("$(bad)"));
    }

    #[test]
    fn firewall_commands_manage_active_ufw_and_firewalld_idempotently() {
        let listeners = [
            ListenerPort {
                port: 443,
                protocol: TransportProtocol::Tcp,
            },
            ListenerPort {
                port: 4_500,
                protocol: TransportProtocol::Udp,
            },
        ];
        let allow = firewall_allow_command(&listeners);
        assert!(allow.contains("sudo -n ufw status"));
        assert!(allow.contains("sudo -n ufw allow 443/tcp"));
        assert!(allow.contains("sudo -n ufw allow 4500/udp"));
        assert!(allow.contains("firewall-cmd --state"));
        assert!(allow.contains("sudo -n firewall-cmd --permanent --add-port=443/tcp"));
        assert!(allow.contains("sudo -n firewall-cmd --permanent --add-port=4500/udp"));
        assert!(allow.contains("sudo -n firewall-cmd --reload"));

        let remove = firewall_remove_command(&listeners);
        assert!(remove.contains("sudo -n ufw delete allow 443/tcp"));
        assert!(remove.contains("sudo -n ufw delete allow 4500/udp"));
        assert!(remove.contains("|| true"));
        assert!(remove.contains("sudo -n firewall-cmd --permanent --remove-port=443/tcp"));
        assert!(remove.contains("sudo -n firewall-cmd --permanent --remove-port=4500/udp"));
    }

    #[test]
    fn ssh_commands_follow_backend_runtime_contracts() {
        let ikev2 = command_state(VpnBackendKind::Ikev2);
        let ikev2_runtime = Ikev2Backend
            .runtime(&ikev2.instance.backend_settings)
            .unwrap();
        let ports = port_conflict_command(&ikev2.instance, &ikev2_runtime);
        assert_eq!(ports.matches("ss -H -lun").count(), 2);
        assert!(ports.contains("--protocol udp gateway 500"));
        assert!(ports.contains("--protocol udp gateway 4500"));
        assert!(ports.contains("UDP port 4500 is already in use"));

        let xray = command_state(VpnBackendKind::Xray);
        let xray_runtime = XrayBackend
            .runtime(&xray.instance.backend_settings)
            .unwrap();
        let images = image_prepare_command("/safe/stage", &xray_runtime, false);
        assert!(images.contains("docker compose --env-file .env build gateway"));
        assert!(!images.contains(COREDNS_IMAGE));
        let health = remote_health_command(&xray, &xray_runtime, false);
        assert!(health.contains("xray run -test"));
        assert!(health.contains("--protocol tcp gateway 8443"));
        assert!(!health.contains("nslookup"));
        let ownership =
            prepare_numeric_mount_ownership_command("/safe/current", &xray_runtime).unwrap();
        assert!(ownership.contains("chown -R 10001:10001 /work"));
        assert!(ownership.contains("'/safe/current/xray-state:/work'"));
    }

    #[test]
    fn certificate_authorities_are_staged_idempotently_and_activated_as_persistent_state() {
        let openvpn = command_state(VpnBackendKind::OpenVpn);
        let openvpn_backend = OpenVpnBackend;
        let openvpn_runtime = openvpn_backend
            .runtime(&openvpn.instance.backend_settings)
            .unwrap();
        let seed =
            seed_persistent_identity_command("/safe/current", "/safe/stage", &openvpn_runtime)
                .unwrap();
        assert!(seed.contains("test ! -L '/safe/current/vpn/pki'"));
        assert!(seed.contains("find '/safe/current/vpn/pki' -type l"));
        assert!(seed.contains("cp -a -- '/safe/current/vpn/pki' '/safe/stage/vpn/pki'"));

        let credential_plan = openvpn_backend
            .plan_credentials(&openvpn, None, CredentialAction::InitializeAuthority)
            .unwrap();
        let initialize = certificate_authority_initialization_command(
            "/safe/stage",
            &openvpn_runtime,
            &credential_plan.operations[0],
        )
        .unwrap();
        assert!(initialize.contains("vpn-appliance-manager/openvpn:"));
        assert!(initialize.contains("OpenVPN authority is partial"));
        assert!(initialize.contains("EASYRSA_ALGO=ec"));
        assert!(initialize.contains("EASYRSA_CURVE=prime256v1"));
        assert!(initialize.contains("easyrsa build-ca nopass"));
        assert!(initialize.contains("openssl verify"));
        assert!(!initialize.contains("latest"));

        let files = openvpn_backend
            .render_server(&openvpn, &HashMap::new())
            .unwrap();
        let plan = DeploymentPlan {
            id: Uuid::nil(),
            instance_id: openvpn.instance.id,
            operations: files
                .iter()
                .map(|file| DeploymentOperation::UploadFile {
                    path: file.path.clone(),
                    sensitive: file.sensitive,
                })
                .collect(),
            warnings: Vec::new(),
            desired_state_hash: "hash".into(),
        };
        let activation = activation_command(
            "/safe/current",
            "/safe/stage",
            &files,
            &plan,
            &openvpn_runtime,
        );
        assert!(activation.contains("mv '/safe/stage/vpn/pki' '/safe/current/vpn/pki'"));
    }

    #[test]
    fn ikev2_authority_uses_p384_server_identity_and_crl_validation() {
        let state = command_state(VpnBackendKind::Ikev2);
        let backend = Ikev2Backend;
        let runtime = backend.runtime(&state.instance.backend_settings).unwrap();
        let plan = backend
            .plan_credentials(&state, None, CredentialAction::InitializeAuthority)
            .unwrap();
        let command = certificate_authority_initialization_command(
            "/safe/stage",
            &runtime,
            &plan.operations[0],
        )
        .unwrap();
        assert!(command.contains("--type ecdsa --size 384"));
        assert!(command.contains("--digest sha384"));
        assert!(command.contains("--flag serverAuth"));
        assert!(command.contains("--san"));
        assert!(command.contains("vpn.example.test"));
        assert!(command.contains("pki --signcrl"));
        assert!(command.contains("pki --verify"));
        assert!(command.contains("IKEv2 authority is partial"));
        assert!(!command.contains("--type rsa"));
    }

    #[test]
    fn backend_device_identity_generation_matches_capabilities() {
        let wireguard = command_state(VpnBackendKind::WireGuard);
        let (data, secrets) =
            generate_device_identity(&wireguard.instance, "Laptop", Uuid::from_u128(10), false)
                .unwrap();
        assert!(matches!(
            data,
            DeviceBackendData::WireGuard(WireGuardDeviceData {
                preshared_key_ref: None,
                ..
            })
        ));
        assert_eq!(secrets.len(), 1);

        let awg = command_state(VpnBackendKind::AmneziaWg);
        let (data, secrets) =
            generate_device_identity(&awg.instance, "Laptop", Uuid::from_u128(11), false).unwrap();
        assert!(matches!(data, DeviceBackendData::AmneziaWg(_)));
        assert_eq!(secrets.len(), 2);

        let openvpn = command_state(VpnBackendKind::OpenVpn);
        let (data, secrets) =
            generate_device_identity(&openvpn.instance, "Laptop", Uuid::from_u128(12), true)
                .unwrap();
        let DeviceBackendData::OpenVpn(data) = data else {
            panic!("expected OpenVPN identity");
        };
        assert!(data.certificate_serial.is_none());
        assert!(data.tls_crypt_key_ref.is_some());
        assert_eq!(secrets.len(), 2);

        let ikev2 = command_state(VpnBackendKind::Ikev2);
        let (data, secrets) =
            generate_device_identity(&ikev2.instance, "Laptop", Uuid::from_u128(13), true).unwrap();
        let DeviceBackendData::Ikev2(data) = data else {
            panic!("expected IKEv2 identity");
        };
        assert!(data.private_key_ref.is_some());
        assert!(data.certificate_ref.is_some());
        assert_eq!(secrets.len(), 3);

        let xray = command_state(VpnBackendKind::Xray);
        let (data, secrets) =
            generate_device_identity(&xray.instance, "Laptop", Uuid::from_u128(14), true).unwrap();
        let DeviceBackendData::Xray(data) = data else {
            panic!("expected Xray identity");
        };
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].reference, data.client_id_ref);
        Uuid::parse_str(std::str::from_utf8(secrets[0].value.as_slice()).unwrap()).unwrap();
    }

    #[test]
    fn certificate_device_commands_are_typed_quoted_and_idempotent() {
        let openvpn = command_state(VpnBackendKind::OpenVpn);
        let runtime = OpenVpnBackend
            .runtime(&openvpn.instance.backend_settings)
            .unwrap();
        let import = CredentialOperation::ImportOpenVpnCsr {
            common_name: "laptop-1234".into(),
            relative_path: "vpn/requests/laptop-1234.req".into(),
        };
        let command = credential_operation_command(
            "/safe/current",
            &runtime,
            VpnBackendKind::OpenVpn,
            &import,
        )
        .unwrap()
        .unwrap();
        assert!(command.contains("easyrsa import-req"));
        assert!(command.contains("EASYRSA_DN=cn_only"));
        assert!(command.contains("'/safe/current/vpn:/etc/openvpn'"));

        let revoke = CredentialOperation::RevokeOpenVpnClient {
            common_name: "laptop-1234".into(),
        };
        let command = credential_operation_command(
            "/safe/current",
            &runtime,
            VpnBackendKind::OpenVpn,
            &revoke,
        )
        .unwrap()
        .unwrap();
        assert!(command.contains("index.txt"));
        assert!(command.contains("easyrsa revoke"));

        let ikev2 = command_state(VpnBackendKind::Ikev2);
        let runtime = Ikev2Backend
            .runtime(&ikev2.instance.backend_settings)
            .unwrap();
        let revoke = CredentialOperation::RevokeIkev2Client {
            identity: "laptop-1234".into(),
            certificate_serial: "A1B2C3".into(),
            crl_lifetime_days: 3650,
        };
        let command =
            credential_operation_command("/safe/current", &runtime, VpnBackendKind::Ikev2, &revoke)
                .unwrap()
                .unwrap();
        assert!(command.contains("--lastcrl"));
        assert!(command.contains("--serial"));
        assert!(command.contains("revoked"));
        assert!(command.contains("test -f"));
        assert_eq!(
            parse_certificate_serial("certificate_serial=00a1b2\n").as_deref(),
            Some("00A1B2")
        );
        assert!(parse_certificate_serial("certificate_serial=../../bad").is_none());
    }

    #[test]
    fn wireguard_like_identity_and_validation_are_backend_declared() {
        let state = command_state(VpnBackendKind::AmneziaWg);
        let runtime = AmneziaWgBackend
            .runtime(&state.instance.backend_settings)
            .unwrap();
        assert_eq!(
            runtime_container_path(&runtime, "vpn/awg0.conf.template").as_deref(),
            Some("/etc/amneziawg/awg0.conf.template")
        );
        assert_eq!(
            runtime_container_path(&runtime, "vpn-other/awg0.conf"),
            None
        );
        assert_eq!(
            runtime_host_path(&runtime, "/etc/amneziawg/awg0.conf").as_deref(),
            Some("vpn/awg0.conf")
        );
        assert_eq!(
            runtime_host_path(&runtime, "/etc/amneziawg-other/awg0.conf"),
            None
        );
        let identity =
            materialize_server_identity_command("/safe/current", "/safe/stage", &runtime).unwrap();
        assert!(identity.contains("awg genkey"));
        assert!(identity.contains("awg pubkey"));
        assert!(identity.contains("/work/vpn/awg0.conf.template"));
        assert!(identity.contains("__VAM_AWG_SERVER_PRIVATE_KEY__"));

        let validation = validation_command("/safe/stage", &runtime, true);
        assert!(validation.contains("awg-quick"));
        assert!(validation.contains("/etc/amneziawg/awg0.conf"));
        assert!(validation.contains(COREDNS_IMAGE));
        assert!(validation.contains("docker compose --env-file .env config --quiet"));
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: Some(DEFAULT_PORT),
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: DEFAULT_DNS_ZONE.into(),
                routing_mode: None,
            })
            .await
            .unwrap();
        assert_eq!(service.list_instances(None).await.unwrap(), vec![instance]);
    }

    #[tokio::test]
    async fn instance_creation_dispatches_defaults_and_validation_for_every_backend() {
        let storage = Storage::in_memory().await.unwrap();
        let service = ApplicationService::with_transport(
            storage,
            Arc::new(MemorySecretStore::default()),
            Arc::new(RusshTransport::default()),
        );
        let backends = [
            VpnBackendKind::WireGuard,
            VpnBackendKind::AmneziaWg,
            VpnBackendKind::OpenVpn,
            VpnBackendKind::Ikev2,
            VpnBackendKind::Xray,
        ];
        let options = service.backend_options();
        assert_eq!(options.len(), backends.len());
        assert!(
            options
                .iter()
                .all(|option| option.default_port == option.kind.default_port())
        );
        for (index, backend) in backends.into_iter().enumerate() {
            let host = service
                .create_host(CreateHostInput {
                    display_name: format!("lab-{index}"),
                    hostname: format!("192.0.2.{}", index + 1),
                    port: 22,
                    username: "tester".into(),
                    private_key_path: PathBuf::from("/tmp/key"),
                    passphrase: None,
                })
                .await
                .unwrap();
            let endpoint_host = format!("vpn-{index}.example.test");
            let instance = service
                .create_instance(CreateInstanceInput {
                    host_id: host.id,
                    display_name: backend.display_name().into(),
                    endpoint_host: endpoint_host.clone(),
                    backend,
                    backend_settings: None,
                    endpoint_port: None,
                    ipv4_subnet: format!("10.64.{index}.0/24"),
                    dns_zone: format!("backend-{index}.internal"),
                    routing_mode: None,
                })
                .await
                .unwrap();
            assert_eq!(instance.backend, backend);
            assert_eq!(instance.backend_settings.kind(), backend);
            assert_eq!(instance.endpoint.port, backend.default_port());
            if let BackendSettings::Ikev2(settings) = &instance.backend_settings {
                assert_eq!(settings.server_identity, endpoint_host);
            }
        }

        let old_input: CreateInstanceInput = serde_json::from_value(serde_json::json!({
            "host_id": Uuid::nil(),
            "display_name": "legacy",
            "endpoint_host": "legacy.example.test"
        }))
        .unwrap();
        assert_eq!(old_input.backend, VpnBackendKind::WireGuard);
        assert_eq!(old_input.endpoint_port, None);

        let host = service
            .create_host(CreateHostInput {
                display_name: "mismatch".into(),
                hostname: "192.0.2.100".into(),
                port: 22,
                username: "tester".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase: None,
            })
            .await
            .unwrap();
        let error = service
            .create_instance(CreateInstanceInput {
                host_id: host.id,
                display_name: "mismatch".into(),
                endpoint_host: "vpn.example.test".into(),
                backend: VpnBackendKind::OpenVpn,
                backend_settings: Some(BackendSettingsInput::WireGuard(
                    WireGuardSettings::default(),
                )),
                endpoint_port: None,
                ipv4_subnet: "10.65.0.0/24".into(),
                dns_zone: "mismatch.internal".into(),
                routing_mode: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "validation");
        assert!(error.message.contains("do not match"));
    }

    #[tokio::test]
    async fn public_device_workflow_redacts_references_and_preserves_identity_metadata() {
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: None,
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: "test.internal".into(),
                routing_mode: None,
            })
            .await
            .unwrap();
        let view = service
            .create_device_view(CreateDeviceInput {
                instance_id: instance.id,
                user_id: None,
                display_name: "Laptop".into(),
                preshared_key: true,
                create_dns_record: true,
                dns_name: Some("laptop".into()),
            })
            .await
            .unwrap();
        let raw = service.storage.get_device(view.id).await.unwrap();
        let references: Vec<_> = raw
            .backend_data
            .secret_references()
            .into_iter()
            .map(|reference| reference.0.to_string())
            .collect();
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("private_key_ref"));
        assert!(!json.contains("preshared_key_ref"));
        assert!(
            references
                .iter()
                .all(|reference| !json.contains(reference.as_str()))
        );

        let updated = service
            .update_device_metadata(UpdateDeviceInput {
                id: view.id,
                user_id: None,
                display_name: " Travel Laptop ".into(),
                dns_name: Some("travel".into()),
                enabled: false,
            })
            .await
            .unwrap();
        assert_eq!(updated.display_name, "Travel Laptop");
        assert_eq!(updated.dns_name.as_deref(), Some("travel.test.internal"));
        assert!(!updated.enabled);
        assert_eq!(
            service.list_device_views(instance.id).await.unwrap(),
            vec![updated.clone()]
        );
        let after = service.storage.get_device(view.id).await.unwrap();
        assert_eq!(after.backend_data, raw.backend_data);
    }

    #[test]
    fn public_instance_view_omits_xray_tls_secret_references() {
        let mut instance = command_state(VpnBackendKind::Xray).instance;
        let certificate_ref = SecretReference(Uuid::new_v4());
        let private_key_ref = SecretReference(Uuid::new_v4());
        let BackendSettings::Xray(settings) = &mut instance.backend_settings else {
            panic!("expected Xray settings");
        };
        settings.security = XraySecurity::Tls;
        settings.reality_public_key = None;
        settings.reality_short_id = None;
        settings.tls_certificate_ref = Some(certificate_ref.clone());
        settings.tls_private_key_ref = Some(private_key_ref.clone());

        let json = serde_json::to_string(&InstanceView::from(&instance)).unwrap();
        assert!(!json.contains("tls_certificate_ref"));
        assert!(!json.contains("tls_private_key_ref"));
        assert!(!json.contains(&certificate_ref.0.to_string()));
        assert!(!json.contains(&private_key_ref.0.to_string()));
    }

    #[tokio::test]
    async fn xray_device_creation_keeps_client_credential_out_of_public_view() {
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
        let mut instance = command_state(VpnBackendKind::Xray).instance;
        instance.id = Uuid::new_v4();
        instance.host_id = host.id;
        service.storage.save_instance(&instance).await.unwrap();

        let device = service
            .create_device(CreateDeviceInput {
                instance_id: instance.id,
                user_id: None,
                display_name: "Browser".into(),
                preshared_key: true,
                create_dns_record: true,
                dns_name: Some("browser".into()),
            })
            .await
            .unwrap();
        assert!(device.ipv4_address.is_none());
        assert!(device.dns_name.is_none());
        assert!(matches!(device.backend_data, DeviceBackendData::Xray(_)));
        assert!(
            service
                .list_dns_records(instance.id)
                .await
                .unwrap()
                .is_empty()
        );
        let DeviceBackendData::Xray(data) = &device.backend_data else {
            panic!("expected Xray device metadata");
        };
        assert_eq!(
            device_secret_registrations(&device),
            vec![(data.client_id_ref.0, "xray_client_id".to_owned())]
        );
        let stored = secrets.get(&data.client_id_ref).await.unwrap();
        let client_id = std::str::from_utf8(stored.as_slice()).unwrap();
        Uuid::parse_str(client_id).unwrap();

        let persisted_json = serde_json::to_string(&device.backend_data).unwrap();
        assert!(!persisted_json.contains(client_id));
        assert!(persisted_json.contains(&data.client_id_ref.0.to_string()));
        let public_json = serde_json::to_string(&DeviceView::from(&device)).unwrap();
        assert!(!public_json.contains("client_id"));
        assert!(!public_json.contains(&data.client_id_ref.0.to_string()));
        assert!(!public_json.contains(client_id));
    }

    #[tokio::test]
    async fn dns_hostlists_start_empty_and_are_user_managed() {
        let storage = Storage::in_memory().await.unwrap();
        let service = ApplicationService::with_transport(
            storage,
            Arc::new(MemorySecretStore::default()),
            Arc::new(RusshTransport::default()),
        );
        assert!(service.list_dns_hostlists().await.unwrap().is_empty());

        let invalid = service
            .create_dns_hostlist(CreateDnsHostlistInput {
                name: "Plain HTTP".into(),
                url: "http://example.test/hosts".into(),
                coverage: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(invalid.code, "validation");

        let hostlist = service
            .create_dns_hostlist(CreateDnsHostlistInput {
                name: " Malware hosts ".into(),
                url: "https://example.test/hosts".into(),
                coverage: " malware ".into(),
            })
            .await
            .unwrap();
        assert_eq!(hostlist.name, "Malware hosts");
        assert_eq!(hostlist.coverage, "malware");
        assert_eq!(
            service.list_dns_hostlists().await.unwrap(),
            vec![hostlist.clone()]
        );

        let duplicate = service
            .create_dns_hostlist(CreateDnsHostlistInput {
                name: "Duplicate".into(),
                url: hostlist.url.clone(),
                coverage: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(duplicate.code, "validation");

        let updated = service
            .update_dns_hostlist(DnsHostlist {
                name: "Threat feeds".into(),
                coverage: "threat domains".into(),
                ..hostlist.clone()
            })
            .await
            .unwrap();
        assert_eq!(updated.name, "Threat feeds");

        service.delete_dns_hostlist(updated.id).await.unwrap();
        assert!(service.list_dns_hostlists().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rendered_blocklist_is_empty_until_hostlists_are_added() {
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: Some(DEFAULT_PORT),
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: DEFAULT_DNS_ZONE.into(),
                routing_mode: None,
            })
            .await
            .unwrap();
        let state = service.desired_state(instance.id).await.unwrap();
        let files = service.render_state_for_plan(&state).await.unwrap();
        let hosts = files
            .iter()
            .find(|file| file.path == "dns/hosts/blocklist.hosts")
            .expect("blocklist hosts file");
        assert!(!hosts.contents.contains("ads.google.com"));
    }

    #[tokio::test]
    async fn device_dns_names_are_normalized_into_instance_zone() {
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: Some(DEFAULT_PORT),
                ipv4_subnet: DEFAULT_SUBNET.into(),
                dns_zone: "test.internal".into(),
                routing_mode: None,
            })
            .await
            .unwrap();

        let device = service
            .create_device(CreateDeviceInput {
                instance_id: instance.id,
                user_id: None,
                display_name: "vm1".into(),
                preshared_key: true,
                create_dns_record: true,
                dns_name: Some("vm1".into()),
            })
            .await
            .unwrap();
        assert_eq!(device.dns_name.as_deref(), Some("vm1.test.internal"));
        let records = service.list_dns_records(instance.id).await.unwrap();
        assert_eq!(records[0].name, "vm1.test.internal");
        assert_eq!(
            records[0].value,
            device
                .ipv4_address
                .expect("WireGuard device has an address")
                .to_string()
        );

        let invalid = service
            .create_device(CreateDeviceInput {
                instance_id: instance.id,
                user_id: None,
                display_name: "bad".into(),
                preshared_key: true,
                create_dns_record: true,
                dns_name: Some("vm1.internal".into()),
            })
            .await
            .unwrap_err();
        assert_eq!(invalid.code, "validation");
        assert!(invalid.message.contains("test.internal"));
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: Some(DEFAULT_PORT),
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
        let DeviceBackendData::WireGuard(data) = &device.backend_data else {
            panic!("expected WireGuard device");
        };
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
    async fn host_setup_rejects_stale_plans_and_treats_nonzero_exit_as_authoritative() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = fake_transport();
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

        fake.responses
            .lock()
            .expect("test response lock")
            .push_back(queued_result(FRESH_APT_HOST, "", 0));
        let plan = service.plan_host_provisioning(host.id).await.unwrap();
        assert!(!plan.operations.is_empty());

        fake.responses.lock().expect("test response lock").extend([
            queued_result(FRESH_APT_HOST, "", 0),
            queued_result("", "password=hunter2", 23),
        ]);
        let error = service
            .apply_host_provisioning(host.id, &plan.expected_state_hash)
            .await
            .unwrap_err();
        assert_eq!(error.code, "remote_command");
        assert!(error.remote_state_changed);
        let detail = error.technical_detail.unwrap();
        assert!(!detail.contains("hunter2"));
        assert!(detail.contains("[REDACTED]"));
        assert!(detail.contains("exit_status=23"));

        let command_count = fake.commands.lock().expect("test command lock").len();
        let error = service
            .apply_host_provisioning(host.id, "stale-state")
            .await
            .unwrap_err();
        assert_eq!(error.code, "host_provisioning_plan_stale");
        assert_eq!(
            fake.commands.lock().expect("test command lock").len(),
            command_count + 1,
            "stale apply may inspect but must not execute setup"
        );
    }

    #[tokio::test]
    async fn host_setup_reinspects_after_apply_and_requires_direct_access() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = fake_transport();
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

        fake.responses
            .lock()
            .expect("test response lock")
            .push_back(queued_result(FRESH_APT_HOST, "", 0));
        let plan = service.plan_host_provisioning(host.id).await.unwrap();
        fake.responses.lock().expect("test response lock").extend([
            queued_result(FRESH_APT_HOST, "", 0),
            queued_result("", "", 0),
            queued_result(READY_APT_HOST, "", 0),
        ]);
        let inspection = service
            .apply_host_provisioning(host.id, &plan.expected_state_hash)
            .await
            .unwrap();
        assert!(host_deployment_prerequisites_ready(&inspection));
        assert!(
            fake.commands
                .lock()
                .expect("test command lock")
                .iter()
                .any(|command| command.contains("usermod -aG docker"))
        );
    }

    #[tokio::test]
    async fn rollback_restores_the_complete_backend_identity_tree_before_health() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = fake_transport();
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
        let mut state = command_state(VpnBackendKind::Xray);
        state.instance.host_id = host.id;
        let (host, trusted, passphrase) = service.trusted_host(host.id).await.unwrap();
        fake.responses.lock().expect("test response lock").extend([
            queued_result("", "", 0),
            queued_result(HEALTHY_XRAY, "", 0),
            queued_result("", "", 0),
        ]);

        let backup = format!("{APP_ROOT}/backups/{}/reviewed-snapshot", state.instance.id);
        let health = service
            .restore_backup(
                &state,
                &host,
                &trusted,
                passphrase.as_ref(),
                Some(&backup),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(health_is_healthy(&health));

        let commands = fake.commands.lock().expect("test command lock");
        let restore = commands
            .iter()
            .find(|command| command.contains("reviewed-snapshot"))
            .expect("rollback copy command");
        assert!(restore.contains(&format!("cp -a '{backup}'")));
        assert!(restore.contains(&format!("'{APP_ROOT}/instances/{}'", state.instance.id)));
        assert!(restore.contains("docker compose up -d"));
        assert!(
            commands
                .iter()
                .any(|command| command.contains("xray run -test"))
        );
        assert_eq!(
            commands.len(),
            2,
            "archive-mode full-tree restore preserves Xray's numeric identity ownership"
        );
    }

    #[tokio::test]
    async fn inspection_and_health_treat_remote_exit_status_as_authoritative() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = fake_transport();
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

        fake.responses
            .lock()
            .expect("test response lock")
            .push_back(queued_result(
                "operating_system=Linux\n",
                "inspect failed",
                17,
            ));
        let inspection_error = service.inspect_host(host.id).await.unwrap_err();
        assert_eq!(inspection_error.code, "remote_command");
        assert!(
            inspection_error
                .technical_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("exit_status=17"))
        );

        let mut state = command_state(VpnBackendKind::Xray);
        state.instance.host_id = host.id;
        let (host, trusted, passphrase) = service.trusted_host(host.id).await.unwrap();
        fake.responses
            .lock()
            .expect("test response lock")
            .push_back(queued_result(HEALTHY_XRAY, "health failed", 19));
        let health_error = service
            .remote_health(
                &state,
                &host,
                &trusted,
                passphrase.as_ref(),
                &CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(health_error.code, "remote_command");
        assert_eq!(health_error.scope.as_deref(), Some("health"));
        assert!(
            health_error
                .technical_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("exit_status=19"))
        );
    }

    #[tokio::test]
    async fn host_key_requires_approval_and_changed_key_is_distinct() {
        let storage = Storage::in_memory().await.unwrap();
        let fake = fake_transport();
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
        let fake = fake_transport();
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: Some(DEFAULT_PORT),
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

    #[tokio::test]
    async fn refresh_remote_credentials_uploads_real_device_keys_without_dns_restart() {
        let storage = Storage::in_memory().await.unwrap();
        let secrets = Arc::new(MemorySecretStore::default());
        let fake = fake_transport();
        let service = ApplicationService::with_transport(storage, secrets.clone(), fake.clone());
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
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: Some(DEFAULT_PORT),
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
                display_name: "vm1".into(),
                preshared_key: true,
                create_dns_record: true,
                dns_name: Some("vm1".into()),
            })
            .await
            .unwrap();
        let DeviceBackendData::WireGuard(data) = &device.backend_data else {
            panic!("expected WireGuard device");
        };
        let psk = secrets
            .get(data.preshared_key_ref.as_ref().unwrap())
            .await
            .unwrap();
        let psk = String::from_utf8(psk.to_vec()).unwrap();

        service
            .refresh_remote_credentials(instance.id)
            .await
            .unwrap();

        let uploads = fake.uploads.lock().expect("test upload lock");
        let template = uploads
            .iter()
            .find(|(path, _)| path.ends_with("/vpn/wg0.conf.template"))
            .map(|(_, contents)| contents)
            .expect("uploaded wireguard template");
        assert!(template.contains(&data.public_key));
        assert!(template.contains(&psk));
        assert!(!template.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!uploads.iter().any(|(path, _)| path.contains("/dns/")));
        drop(uploads);

        let commands = fake.commands.lock().expect("test command lock");
        assert!(
            commands
                .iter()
                .any(|command| command.contains("docker compose restart gateway"))
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.contains("docker compose restart dns"))
        );
        assert!(commands.iter().any(|command| command.contains("chown -R")));
    }
}
