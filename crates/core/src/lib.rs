use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_SUBNET: &str = "10.64.0.0/24";
pub const DEFAULT_DNS_ZONE: &str = "internal";
pub const DEFAULT_PORT: u16 = 51_820;
pub const DEFAULT_AMNEZIAWG_PORT: u16 = 55_424;
pub const DEFAULT_OPENVPN_PORT: u16 = 1_194;
pub const DEFAULT_IKEV2_PORT: u16 = 500;
pub const DEFAULT_XRAY_PORT: u16 = 443;
pub const DEFAULT_KEEPALIVE: u16 = 25;
pub const CURRENT_INSTANCE_SCHEMA_VERSION: u32 = 2;
pub const CURRENT_DEVICE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerHost {
    pub id: Uuid,
    pub display_name: String,
    pub ssh: SshConnectionConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshConnectionConfig {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub private_key_path: PathBuf,
    pub passphrase_ref: Option<SecretReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SecretReference(pub Uuid);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VpnBackendKind {
    #[serde(rename = "wireguard", alias = "wire_guard")]
    WireGuard,
    #[serde(rename = "amnezia_wg", alias = "amneziawg", alias = "awg2")]
    AmneziaWg,
    #[serde(rename = "openvpn", alias = "open_vpn")]
    OpenVpn,
    #[serde(rename = "ikev2", alias = "ike_v2")]
    Ikev2,
    #[serde(rename = "xray")]
    Xray,
}

impl VpnBackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::AmneziaWg => "amnezia_wg",
            Self::OpenVpn => "openvpn",
            Self::Ikev2 => "ikev2",
            Self::Xray => "xray",
        }
    }

    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::WireGuard => "WireGuard",
            Self::AmneziaWg => "AmneziaWG 2",
            Self::OpenVpn => "OpenVPN",
            Self::Ikev2 => "IKEv2",
            Self::Xray => "Xray",
        }
    }

    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::WireGuard => DEFAULT_PORT,
            Self::AmneziaWg => DEFAULT_AMNEZIAWG_PORT,
            Self::OpenVpn => DEFAULT_OPENVPN_PORT,
            Self::Ikev2 => DEFAULT_IKEV2_PORT,
            Self::Xray => DEFAULT_XRAY_PORT,
        }
    }
}

impl std::fmt::Display for VpnBackendKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.display_name())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerPort {
    pub port: u16,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct WireGuardSettings {
    #[serde(default)]
    pub userspace_fallback: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AmneziaWgGeneration {
    #[default]
    Awg2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmneziaWgMagicRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmneziaWgSettings {
    #[serde(default)]
    pub generation: AmneziaWgGeneration,
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub s3: u16,
    pub s4: u16,
    pub h1: AmneziaWgMagicRange,
    pub h2: AmneziaWgMagicRange,
    pub h3: AmneziaWgMagicRange,
    pub h4: AmneziaWgMagicRange,
}

impl Default for AmneziaWgSettings {
    fn default() -> Self {
        Self {
            generation: AmneziaWgGeneration::Awg2,
            jc: 5,
            jmin: 10,
            jmax: 50,
            s1: 64,
            s2: 96,
            s3: 32,
            s4: 8,
            h1: AmneziaWgMagicRange { min: 5, max: 999 },
            h2: AmneziaWgMagicRange {
                min: 1_000,
                max: 1_999,
            },
            h3: AmneziaWgMagicRange {
                min: 2_000,
                max: 2_999,
            },
            h4: AmneziaWgMagicRange {
                min: 3_000,
                max: 3_999,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnTransport {
    Tcp,
    #[default]
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OpenVpnCipher {
    #[default]
    Aes256Gcm,
    Chacha20Poly1305,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpenVpnTlsProtection {
    #[default]
    TlsCrypt,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenVpnSettings {
    #[serde(default)]
    pub transport: OpenVpnTransport,
    #[serde(default)]
    pub cipher: OpenVpnCipher,
    #[serde(default)]
    pub tls_protection: OpenVpnTlsProtection,
    pub certificate_lifetime_days: u16,
}

impl Default for OpenVpnSettings {
    fn default() -> Self {
        Self {
            transport: OpenVpnTransport::Udp,
            cipher: OpenVpnCipher::Aes256Gcm,
            tls_protection: OpenVpnTlsProtection::TlsCrypt,
            certificate_lifetime_days: 825,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ikev2Settings {
    pub server_identity: String,
    pub certificate_lifetime_days: u16,
}

impl Default for Ikev2Settings {
    fn default() -> Self {
        Self {
            server_identity: String::new(),
            certificate_lifetime_days: 825,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum XraySecurity {
    Tls,
    #[default]
    Reality,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum XrayTransport {
    #[default]
    Tcp,
    Xhttp,
    Mkcp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XraySettings {
    #[serde(default)]
    pub security: XraySecurity,
    #[serde(default)]
    pub transport: XrayTransport,
    pub server_name: String,
    pub fingerprint: String,
    pub xhttp_path: String,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub tls_certificate_ref: Option<SecretReference>,
    #[serde(default)]
    pub tls_private_key_ref: Option<SecretReference>,
}

impl Default for XraySettings {
    fn default() -> Self {
        Self {
            security: XraySecurity::Reality,
            transport: XrayTransport::Tcp,
            server_name: "www.cloudflare.com".into(),
            fingerprint: "chrome".into(),
            xhttp_path: "/".into(),
            reality_public_key: None,
            reality_short_id: None,
            tls_certificate_ref: None,
            tls_private_key_ref: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", content = "settings")]
pub enum BackendSettings {
    #[serde(rename = "wireguard", alias = "wire_guard")]
    WireGuard(WireGuardSettings),
    #[serde(rename = "amnezia_wg", alias = "amneziawg", alias = "awg2")]
    AmneziaWg(AmneziaWgSettings),
    #[serde(rename = "openvpn", alias = "open_vpn")]
    OpenVpn(OpenVpnSettings),
    #[serde(rename = "ikev2", alias = "ike_v2")]
    Ikev2(Ikev2Settings),
    #[serde(rename = "xray")]
    Xray(XraySettings),
}

impl Default for BackendSettings {
    fn default() -> Self {
        Self::WireGuard(WireGuardSettings::default())
    }
}

impl BackendSettings {
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
    pub fn secret_references(&self) -> Vec<&SecretReference> {
        match self {
            Self::Xray(settings) => {
                let mut references = Vec::new();
                references.extend(settings.tls_certificate_ref.iter());
                references.extend(settings.tls_private_key_ref.iter());
                references
            }
            Self::WireGuard(_) | Self::AmneziaWg(_) | Self::OpenVpn(_) | Self::Ikev2(_) => {
                Vec::new()
            }
        }
    }

    #[must_use]
    pub fn defaults_for(kind: VpnBackendKind, endpoint_host: &str) -> Self {
        match kind {
            VpnBackendKind::WireGuard => Self::default(),
            VpnBackendKind::AmneziaWg => Self::AmneziaWg(AmneziaWgSettings::default()),
            VpnBackendKind::OpenVpn => Self::OpenVpn(OpenVpnSettings::default()),
            VpnBackendKind::Ikev2 => Self::Ikev2(Ikev2Settings {
                server_identity: endpoint_host.into(),
                ..Ikev2Settings::default()
            }),
            VpnBackendKind::Xray => Self::Xray(XraySettings::default()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    FullTunnel,
    SplitTunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub ipv4_subnet: Ipv4Net,
    pub gateway_ipv4: Ipv4Addr,
    pub ipv6_subnet: Option<String>,
    pub gateway_ipv6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsConfig {
    pub zone: String,
    pub soa_serial: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnInstance {
    pub id: Uuid,
    pub host_id: Uuid,
    pub display_name: String,
    pub backend: VpnBackendKind,
    #[serde(default)]
    pub backend_settings: BackendSettings,
    pub endpoint: EndpointConfig,
    pub network: NetworkConfig,
    pub dns: DnsConfig,
    pub routing_mode: RoutingMode,
    pub persistent_keepalive: u16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

impl VpnInstance {
    #[must_use]
    pub fn remote_path(&self) -> String {
        format!("/opt/vpn-appliance-manager/instances/{}", self.id)
    }

    #[must_use]
    pub fn compose_project(&self) -> String {
        format!("vam-{}", self.id)
    }

    #[must_use]
    pub fn listeners(&self) -> Vec<ListenerPort> {
        match &self.backend_settings {
            BackendSettings::WireGuard(_) | BackendSettings::AmneziaWg(_) => vec![ListenerPort {
                port: self.endpoint.port,
                protocol: TransportProtocol::Udp,
            }],
            BackendSettings::OpenVpn(settings) => vec![ListenerPort {
                port: self.endpoint.port,
                protocol: match settings.transport {
                    OpenVpnTransport::Tcp => TransportProtocol::Tcp,
                    OpenVpnTransport::Udp => TransportProtocol::Udp,
                },
            }],
            BackendSettings::Ikev2(_) => vec![
                ListenerPort {
                    port: 500,
                    protocol: TransportProtocol::Udp,
                },
                ListenerPort {
                    port: 4_500,
                    protocol: TransportProtocol::Udp,
                },
            ],
            BackendSettings::Xray(settings) => vec![ListenerPort {
                port: self.endpoint.port,
                protocol: match settings.transport {
                    XrayTransport::Tcp | XrayTransport::Xhttp => TransportProtocol::Tcp,
                    XrayTransport::Mkcp => TransportProtocol::Udp,
                },
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireGuardDeviceData {
    pub public_key: String,
    pub private_key_ref: SecretReference,
    pub preshared_key_ref: Option<SecretReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmneziaWgDeviceData {
    pub public_key: String,
    pub private_key_ref: SecretReference,
    pub preshared_key_ref: SecretReference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenVpnDeviceData {
    pub common_name: String,
    pub private_key_ref: SecretReference,
    pub csr_ref: SecretReference,
    pub certificate_ref: SecretReference,
    pub ca_certificate_ref: SecretReference,
    pub tls_crypt_key_ref: Option<SecretReference>,
    pub certificate_serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ikev2DeviceData {
    pub identity: String,
    #[serde(default)]
    pub private_key_ref: Option<SecretReference>,
    #[serde(default)]
    pub csr_ref: Option<SecretReference>,
    #[serde(default)]
    pub certificate_ref: Option<SecretReference>,
    #[serde(default)]
    pub ca_certificate_ref: Option<SecretReference>,
    pub bundle_password_ref: SecretReference,
    pub certificate_serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XrayDeviceData {
    pub client_id_ref: SecretReference,
    pub email: String,
    pub flow: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", content = "data", rename_all = "snake_case")]
pub enum DeviceBackendData {
    WireGuard(WireGuardDeviceData),
    AmneziaWg(AmneziaWgDeviceData),
    OpenVpn(OpenVpnDeviceData),
    Ikev2(Ikev2DeviceData),
    Xray(XrayDeviceData),
}

impl DeviceBackendData {
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
    pub fn secret_references(&self) -> Vec<&SecretReference> {
        match self {
            Self::WireGuard(data) => {
                let mut references = vec![&data.private_key_ref];
                references.extend(data.preshared_key_ref.as_ref());
                references
            }
            Self::AmneziaWg(data) => {
                vec![&data.private_key_ref, &data.preshared_key_ref]
            }
            Self::OpenVpn(data) => {
                let mut references = vec![
                    &data.private_key_ref,
                    &data.csr_ref,
                    &data.certificate_ref,
                    &data.ca_certificate_ref,
                ];
                references.extend(data.tls_crypt_key_ref.as_ref());
                references
            }
            Self::Ikev2(data) => {
                let mut references = vec![&data.bundle_password_ref];
                references.extend(data.private_key_ref.iter());
                references.extend(data.csr_ref.iter());
                references.extend(data.certificate_ref.iter());
                references.extend(data.ca_certificate_ref.iter());
                references
            }
            Self::Xray(data) => vec![&data.client_id_ref],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub user_id: Option<Uuid>,
    pub display_name: String,
    #[serde(default)]
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub dns_name: Option<String>,
    pub enabled: bool,
    pub backend_data: DeviceBackendData,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
    Srv,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub name: String,
    pub record_type: DnsRecordType,
    pub value: String,
    pub ttl: u32,
    pub enabled: bool,
    pub managed_by_device_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesiredState {
    pub instance: VpnInstance,
    pub users: Vec<User>,
    pub devices: Vec<Device>,
    pub dns_records: Vec<DnsRecord>,
    #[serde(default)]
    pub dns_blocklist_domains: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("{field} is required")]
    Required { field: &'static str },
    #[error("VPN subnet must be contained in RFC1918 private address space")]
    NonPrivateSubnet,
    #[error("gateway must be the first usable address in the VPN subnet")]
    InvalidGateway,
    #[error("no device address is available in the VPN subnet")]
    AddressPoolExhausted,
    #[error("address {0} is outside the VPN subnet or is reserved")]
    InvalidDeviceAddress(Ipv4Addr),
    #[error("duplicate device address {0}")]
    DuplicateDeviceAddress(Ipv4Addr),
    #[error("{0} devices require an allocated IPv4 tunnel address")]
    MissingDeviceAddress(VpnBackendKind),
    #[error("device backend {device} does not match instance backend {instance}")]
    DeviceBackendMismatch {
        instance: VpnBackendKind,
        device: VpnBackendKind,
    },
    #[error("backend settings do not match instance backend {0}")]
    BackendSettingsMismatch(VpnBackendKind),
    #[error("VPN listener port must be between 1 and 65535")]
    InvalidPort,
    #[error("instance subnets overlap")]
    OverlappingSubnet,
    #[error("instances on one host cannot share {protocol} port {port}")]
    DuplicatePort {
        port: u16,
        protocol: TransportProtocol,
    },
}

pub fn validate_instance(instance: &VpnInstance) -> Result<(), ValidationError> {
    if instance.display_name.trim().is_empty() {
        return Err(ValidationError::Required {
            field: "display_name",
        });
    }
    if instance.endpoint.host.trim().is_empty() {
        return Err(ValidationError::Required { field: "endpoint" });
    }
    if instance.endpoint.port == 0 {
        return Err(ValidationError::InvalidPort);
    }
    if instance.backend_settings.kind() != instance.backend {
        return Err(ValidationError::BackendSettingsMismatch(instance.backend));
    }
    if !is_private_subnet(instance.network.ipv4_subnet) {
        return Err(ValidationError::NonPrivateSubnet);
    }
    if instance.network.gateway_ipv4 != first_usable(instance.network.ipv4_subnet)? {
        return Err(ValidationError::InvalidGateway);
    }
    Ok(())
}

pub fn validate_device_addresses(
    instance: &VpnInstance,
    devices: &[Device],
) -> Result<(), ValidationError> {
    let mut seen = HashSet::new();
    for device in devices.iter().filter(|device| device.deleted_at.is_none()) {
        if device.backend_data.kind() != instance.backend {
            return Err(ValidationError::DeviceBackendMismatch {
                instance: instance.backend,
                device: device.backend_data.kind(),
            });
        }
        let Some(address) = device.ipv4_address else {
            if instance.backend != VpnBackendKind::Xray {
                return Err(ValidationError::MissingDeviceAddress(instance.backend));
            }
            continue;
        };
        if !instance.network.ipv4_subnet.contains(&address)
            || address == instance.network.ipv4_subnet.network()
            || address == instance.network.ipv4_subnet.broadcast()
            || address == instance.network.gateway_ipv4
        {
            return Err(ValidationError::InvalidDeviceAddress(address));
        }
        if !seen.insert(address) {
            return Err(ValidationError::DuplicateDeviceAddress(address));
        }
    }
    Ok(())
}

pub fn validate_host_instances(instances: &[VpnInstance]) -> Result<(), ValidationError> {
    for (index, left) in instances.iter().enumerate() {
        for right in &instances[index + 1..] {
            if left.host_id != right.host_id
                || left.deleted_at.is_some()
                || right.deleted_at.is_some()
            {
                continue;
            }
            let right_listeners: HashSet<_> = right.listeners().into_iter().collect();
            if let Some(listener) = left
                .listeners()
                .into_iter()
                .find(|listener| right_listeners.contains(listener))
            {
                return Err(ValidationError::DuplicatePort {
                    port: listener.port,
                    protocol: listener.protocol,
                });
            }
            if left
                .network
                .ipv4_subnet
                .contains(&right.network.ipv4_subnet.network())
                || right
                    .network
                    .ipv4_subnet
                    .contains(&left.network.ipv4_subnet.network())
            {
                return Err(ValidationError::OverlappingSubnet);
            }
        }
    }
    Ok(())
}

pub fn allocate_next_ipv4(
    subnet: Ipv4Net,
    gateway: Ipv4Addr,
    devices: &[Device],
) -> Result<Ipv4Addr, ValidationError> {
    let used: HashSet<_> = devices
        .iter()
        .filter(|device| device.deleted_at.is_none())
        .filter_map(|device| device.ipv4_address)
        .collect();
    subnet
        .hosts()
        .filter(|address| *address != gateway)
        .find(|address| !used.contains(address))
        .ok_or(ValidationError::AddressPoolExhausted)
}

pub fn first_usable(subnet: Ipv4Net) -> Result<Ipv4Addr, ValidationError> {
    subnet
        .hosts()
        .next()
        .ok_or(ValidationError::AddressPoolExhausted)
}

fn is_private_subnet(subnet: Ipv4Net) -> bool {
    let private_ranges = [
        "10.0.0.0/8".parse::<Ipv4Net>().expect("constant is valid"),
        "172.16.0.0/12".parse().expect("constant is valid"),
        "192.168.0.0/16".parse().expect("constant is valid"),
    ];
    private_ranges
        .iter()
        .any(|private| private.contains(&subnet.network()) && private.contains(&subnet.broadcast()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(host_id: Uuid, subnet: &str, port: u16) -> VpnInstance {
        let subnet: Ipv4Net = subnet.parse().unwrap();
        VpnInstance {
            id: Uuid::new_v4(),
            host_id,
            display_name: "test".into(),
            backend: VpnBackendKind::WireGuard,
            backend_settings: BackendSettings::default(),
            endpoint: EndpointConfig {
                host: "vpn.example.test".into(),
                port,
            },
            network: NetworkConfig {
                ipv4_subnet: subnet,
                gateway_ipv4: first_usable(subnet).unwrap(),
                ipv6_subnet: None,
                gateway_ipv6: None,
            },
            dns: DnsConfig {
                zone: DEFAULT_DNS_ZONE.into(),
                soa_serial: 2_026_072_301,
            },
            routing_mode: RoutingMode::SplitTunnel,
            persistent_keepalive: DEFAULT_KEEPALIVE,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    #[test]
    fn allocates_after_gateway_and_reserves_disabled_devices() {
        let subnet: Ipv4Net = "10.64.0.0/29".parse().unwrap();
        let gateway = "10.64.0.1".parse().unwrap();
        let device = Device {
            id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            user_id: None,
            display_name: "old".into(),
            ipv4_address: Some("10.64.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: None,
            enabled: false,
            backend_data: DeviceBackendData::WireGuard(WireGuardDeviceData {
                public_key: "public".into(),
                private_key_ref: SecretReference(Uuid::new_v4()),
                preshared_key_ref: None,
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        assert_eq!(
            allocate_next_ipv4(subnet, gateway, &[device]).unwrap(),
            "10.64.0.3".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn rejects_public_subnet() {
        let subnet: Ipv4Net = "8.8.8.0/24".parse().unwrap();
        assert!(!is_private_subnet(subnet));
    }

    #[test]
    fn rejects_overlapping_subnets_and_duplicate_host_ports() {
        let host_id = Uuid::new_v4();
        let left = instance(host_id, "10.64.0.0/24", 51_820);
        let overlapping = instance(host_id, "10.64.0.128/25", 51_821);
        assert_eq!(
            validate_host_instances(&[left.clone(), overlapping]).unwrap_err(),
            ValidationError::OverlappingSubnet
        );
        let duplicate_port = instance(host_id, "10.65.0.0/24", 51_820);
        assert_eq!(
            validate_host_instances(&[left, duplicate_port]).unwrap_err(),
            ValidationError::DuplicatePort {
                port: 51_820,
                protocol: TransportProtocol::Udp,
            }
        );
    }

    #[test]
    fn tcp_and_udp_listeners_can_share_a_numeric_port() {
        let host_id = Uuid::new_v4();
        let udp = instance(host_id, "10.64.0.0/24", 443);
        let mut tcp = instance(host_id, "10.65.0.0/24", 443);
        tcp.backend = VpnBackendKind::Xray;
        tcp.backend_settings = BackendSettings::Xray(XraySettings::default());

        validate_host_instances(&[udp, tcp]).unwrap();
    }

    #[test]
    fn xray_settings_backfill_public_and_tls_metadata_and_reserve_transport() {
        let legacy: XraySettings = serde_json::from_value(serde_json::json!({
            "security": "reality",
            "transport": "tcp",
            "server_name": "www.example.test",
            "fingerprint": "chrome",
            "xhttp_path": "/"
        }))
        .unwrap();
        assert!(legacy.reality_public_key.is_none());
        assert!(legacy.reality_short_id.is_none());
        assert!(legacy.tls_certificate_ref.is_none());
        assert!(legacy.tls_private_key_ref.is_none());
        assert!(BackendSettings::Xray(legacy).secret_references().is_empty());

        let certificate_ref = SecretReference(Uuid::from_u128(1));
        let private_key_ref = SecretReference(Uuid::from_u128(2));
        let settings = XraySettings {
            security: XraySecurity::Tls,
            transport: XrayTransport::Mkcp,
            tls_certificate_ref: Some(certificate_ref.clone()),
            tls_private_key_ref: Some(private_key_ref.clone()),
            ..XraySettings::default()
        };
        assert_eq!(
            BackendSettings::Xray(settings.clone()).secret_references(),
            vec![&certificate_ref, &private_key_ref]
        );

        let mut xray = instance(Uuid::new_v4(), "10.64.0.0/24", 443);
        xray.backend = VpnBackendKind::Xray;
        xray.backend_settings = BackendSettings::Xray(settings);
        assert_eq!(
            xray.listeners(),
            vec![ListenerPort {
                port: 443,
                protocol: TransportProtocol::Udp,
            }]
        );
    }

    #[test]
    fn legacy_wire_guard_json_deserializes_with_current_defaults() {
        let value = serde_json::json!({
            "id": Uuid::nil(),
            "host_id": Uuid::from_u128(1),
            "display_name": "legacy",
            "backend": "wire_guard",
            "endpoint": {"host": "vpn.example.test", "port": 51820},
            "network": {
                "ipv4_subnet": "10.64.0.0/24",
                "gateway_ipv4": "10.64.0.1",
                "ipv6_subnet": null,
                "gateway_ipv6": null
            },
            "dns": {"zone": "vpn.internal", "soa_serial": 2_026_073_001_u64},
            "routing_mode": "split_tunnel",
            "persistent_keepalive": 25,
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
            "deleted_at": null
        });
        let decoded: VpnInstance = serde_json::from_value(value).unwrap();

        assert_eq!(decoded.backend, VpnBackendKind::WireGuard);
        assert_eq!(decoded.backend_settings, BackendSettings::default());
        assert_eq!(
            decoded.listeners(),
            vec![ListenerPort {
                port: 51_820,
                protocol: TransportProtocol::Udp,
            }]
        );
    }

    #[test]
    fn openvpn_identity_retains_all_local_and_retrieved_material() {
        let private_key_ref = SecretReference(Uuid::from_u128(1));
        let csr_ref = SecretReference(Uuid::from_u128(2));
        let certificate_ref = SecretReference(Uuid::from_u128(3));
        let ca_certificate_ref = SecretReference(Uuid::from_u128(4));
        let tls_crypt_key_ref = SecretReference(Uuid::from_u128(5));
        let data = DeviceBackendData::OpenVpn(OpenVpnDeviceData {
            common_name: "client-01".into(),
            private_key_ref: private_key_ref.clone(),
            csr_ref: csr_ref.clone(),
            certificate_ref: certificate_ref.clone(),
            ca_certificate_ref: ca_certificate_ref.clone(),
            tls_crypt_key_ref: Some(tls_crypt_key_ref.clone()),
            certificate_serial: None,
        });

        assert_eq!(
            data.secret_references(),
            vec![
                &private_key_ref,
                &csr_ref,
                &certificate_ref,
                &ca_certificate_ref,
                &tls_crypt_key_ref,
            ]
        );
        assert_eq!(
            OpenVpnSettings::default().tls_protection,
            OpenVpnTlsProtection::TlsCrypt
        );
    }

    #[test]
    fn ikev2_identity_backfills_optional_material_and_retains_all_new_references() {
        let bundle_password_ref = SecretReference(Uuid::from_u128(1));
        let legacy: Ikev2DeviceData = serde_json::from_value(serde_json::json!({
            "identity": "client-01",
            "bundle_password_ref": bundle_password_ref,
            "certificate_serial": null
        }))
        .unwrap();
        assert!(legacy.private_key_ref.is_none());
        assert!(legacy.csr_ref.is_none());
        assert!(legacy.certificate_ref.is_none());
        assert!(legacy.ca_certificate_ref.is_none());

        let private_key_ref = SecretReference(Uuid::from_u128(2));
        let csr_ref = SecretReference(Uuid::from_u128(3));
        let certificate_ref = SecretReference(Uuid::from_u128(4));
        let ca_certificate_ref = SecretReference(Uuid::from_u128(5));
        let data = DeviceBackendData::Ikev2(Ikev2DeviceData {
            identity: "client-01".into(),
            private_key_ref: Some(private_key_ref.clone()),
            csr_ref: Some(csr_ref.clone()),
            certificate_ref: Some(certificate_ref.clone()),
            ca_certificate_ref: Some(ca_certificate_ref.clone()),
            bundle_password_ref: bundle_password_ref.clone(),
            certificate_serial: None,
        });

        assert_eq!(
            data.secret_references(),
            vec![
                &bundle_password_ref,
                &private_key_ref,
                &csr_ref,
                &certificate_ref,
                &ca_certificate_ref,
            ]
        );
    }

    #[test]
    fn exhausted_pool_is_reported() {
        let instance = instance(Uuid::new_v4(), "10.64.0.0/30", 51_820);
        let device = Device {
            id: Uuid::new_v4(),
            instance_id: instance.id,
            user_id: None,
            display_name: "only peer".into(),
            ipv4_address: Some("10.64.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: None,
            enabled: false,
            backend_data: DeviceBackendData::WireGuard(WireGuardDeviceData {
                public_key: "public".into(),
                private_key_ref: SecretReference(Uuid::new_v4()),
                preshared_key_ref: None,
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        assert_eq!(
            allocate_next_ipv4(
                instance.network.ipv4_subnet,
                instance.network.gateway_ipv4,
                &[device]
            )
            .unwrap_err(),
            ValidationError::AddressPoolExhausted
        );
    }
}
