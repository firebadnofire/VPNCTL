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
pub const DEFAULT_KEEPALIVE: u16 = 25;

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VpnBackendKind {
    WireGuard,
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
#[serde(tag = "backend", content = "data", rename_all = "snake_case")]
pub enum DeviceBackendData {
    WireGuard(WireGuardDeviceData),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub user_id: Option<Uuid>,
    pub display_name: String,
    pub ipv4_address: Ipv4Addr,
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
    #[error("instance subnets overlap")]
    OverlappingSubnet,
    #[error("instances on one host cannot share UDP port {0}")]
    DuplicatePort(u16),
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
        let address = device.ipv4_address;
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
            if left.endpoint.port == right.endpoint.port {
                return Err(ValidationError::DuplicatePort(left.endpoint.port));
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
        .map(|device| device.ipv4_address)
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
            ipv4_address: "10.64.0.2".parse().unwrap(),
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
            ValidationError::DuplicatePort(51_820)
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
            ipv4_address: "10.64.0.2".parse().unwrap(),
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
