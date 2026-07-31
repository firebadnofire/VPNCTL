use std::{collections::HashMap, fmt::Write as _};

use vam_backend::{
    BackendCapabilities, BackendError, BackendHealthProbe, BackendRuntimeSpec, BackendValidation,
    ChangeImpact, ClientArtifactKind, ContainerCapability, ContainerDevice, ContainerMount,
    ServerIdentityStrategy, VpnBackend,
};
use vam_core::{
    AmneziaWgMagicRange, AmneziaWgSettings, BackendSettings, DesiredState, Device,
    DeviceBackendData, ListenerPort, RoutingMode, SecretReference, TransportProtocol,
    ValidationError, VpnBackendKind, validate_device_addresses, validate_instance,
};
use vam_protocol::{ClientArtifact, RenderedFile};
use wireguard_conf::{PresharedKey, PrivateKey, PublicKey};
use zeroize::Zeroizing;

pub const SERVER_PRIVATE_KEY_SENTINEL: &str = "__VAM_AWG_SERVER_PRIVATE_KEY__";
pub const AMNEZIAWG_IMAGE: &str = concat!(
    "amneziavpn/amneziawg-go:2.0.0@",
    "sha256:7ee1070c9d0131a3825c9ebc134a7ec474ae6c8ec3efcc01428c2610fc1b69b7"
);
pub const AWG_CONTAINER_PORT: u16 = 55_424;

const MESSAGE_INITIATION_SIZE: u16 = 148;
const MESSAGE_RESPONSE_SIZE: u16 = 92;
const MESSAGE_COOKIE_REPLY_SIZE: u16 = 64;
const AWG_START_SCRIPT: &str = r#"#!/bin/sh
set -eu
export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go

cleanup() {
    awg-quick down /etc/amneziawg/awg0.conf || true
}

trap 'cleanup; exit 0' INT TERM
awg-quick up /etc/amneziawg/awg0.conf
while :; do
    sleep 3600 &
    wait "$!" || true
done
"#;

#[derive(Debug, Default)]
pub struct AmneziaWgBackend;

impl AmneziaWgBackend {
    #[must_use]
    pub fn generate_device_keys() -> (Zeroizing<String>, String) {
        let private = PrivateKey::random();
        let public = PublicKey::from(&private);
        (Zeroizing::new(private.to_string()), public.to_string())
    }

    #[must_use]
    pub fn generate_preshared_key() -> Zeroizing<String> {
        Zeroizing::new(PresharedKey::random().to_string())
    }
}

impl VpnBackend for AmneziaWgBackend {
    fn kind(&self) -> VpnBackendKind {
        VpnBackendKind::AmneziaWg
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            allocated_tunnel_addresses: true,
            managed_dns: true,
            quick_credential_refresh: true,
            live_identity_updates: true,
            qr_export: true,
            traffic_statistics: true,
            certificate_authority: false,
        }
    }

    fn runtime(&self) -> BackendRuntimeSpec {
        BackendRuntimeSpec {
            image: AMNEZIAWG_IMAGE,
            container_listeners: vec![ListenerPort {
                port: AWG_CONTAINER_PORT,
                protocol: TransportProtocol::Udp,
            }],
            capabilities: vec![ContainerCapability::NetAdmin],
            devices: vec![ContainerDevice::Tun],
            mounts: vec![ContainerMount {
                host_path: "vpn",
                container_path: "/etc/amneziawg",
                read_only: false,
            }],
            sysctls: vec![
                ("net.ipv4.ip_forward", "1"),
                ("net.ipv4.conf.all.src_valid_mark", "1"),
            ],
            identity: ServerIdentityStrategy::WireGuardLike {
                tool: "awg",
                private_key_path: "vpn/server.key",
                template_path: "vpn/awg0.conf.template",
                materialized_path: "vpn/awg0.conf",
                sentinel: SERVER_PRIVATE_KEY_SENTINEL,
            },
            validation: BackendValidation::WireGuardQuick {
                tool: "awg-quick",
                config_path: "vpn/awg0.conf",
            },
            health: BackendHealthProbe::WireGuardLike {
                tool: "awg",
                interface: "awg0",
            },
        }
    }

    fn listeners(&self, settings: &BackendSettings, endpoint_port: u16) -> Vec<ListenerPort> {
        if !matches!(settings, BackendSettings::AmneziaWg(_)) {
            return Vec::new();
        }
        vec![ListenerPort {
            port: endpoint_port,
            protocol: TransportProtocol::Udp,
        }]
    }

    fn validate(&self, state: &DesiredState) -> Result<(), BackendError> {
        if state.instance.backend != self.kind() {
            return Err(BackendError::BackendMismatch(self.kind()));
        }
        let BackendSettings::AmneziaWg(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        validate_instance(&state.instance)?;
        validate_device_addresses(&state.instance, &state.devices)?;
        validate_settings(settings)?;
        for device in &state.devices {
            let DeviceBackendData::AmneziaWg(data) = &device.backend_data else {
                return Err(BackendError::BackendMismatch(self.kind()));
            };
            if data.preshared_key_ref.0.is_nil() {
                return Err(BackendError::InvalidKeyMaterial(self.kind()));
            }
        }
        Ok(())
    }

    fn server_secret_references(&self, state: &DesiredState) -> Vec<SecretReference> {
        state
            .devices
            .iter()
            .filter_map(|device| match &device.backend_data {
                DeviceBackendData::AmneziaWg(data) => Some(data.preshared_key_ref.clone()),
                _ => None,
            })
            .collect()
    }

    fn client_secret_references(
        &self,
        device: &Device,
    ) -> Result<Vec<SecretReference>, BackendError> {
        let DeviceBackendData::AmneziaWg(data) = &device.backend_data else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        Ok(vec![
            data.private_key_ref.clone(),
            data.preshared_key_ref.clone(),
        ])
    }

    fn render_server(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, BackendError> {
        self.validate(state)?;
        let BackendSettings::AmneziaWg(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let subnet = state.instance.network.ipv4_subnet;
        let gateway = state.instance.network.gateway_ipv4;
        let mut output = format!(
            "[Interface]\nPrivateKey = {SERVER_PRIVATE_KEY_SENTINEL}\nAddress = {gateway}/{}\nListenPort = {AWG_CONTAINER_PORT}\n{}\nPostUp = iptables -A INPUT -i %i -p udp --dport 53 -j ACCEPT; iptables -A INPUT -i %i -p tcp --dport 53 -j ACCEPT; iptables -A FORWARD -i %i -o %i -j ACCEPT; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -j MASQUERADE\nPreDown = iptables -D INPUT -i %i -p udp --dport 53 -j ACCEPT; iptables -D INPUT -i %i -p tcp --dport 53 -j ACCEPT; iptables -D FORWARD -i %i -o %i -j ACCEPT; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet} -o eth0 -j MASQUERADE\n",
            subnet.prefix_len(),
            render_obfuscation(settings),
        );
        let mut devices: Vec<_> = state
            .devices
            .iter()
            .filter(|device| device.enabled && device.deleted_at.is_none())
            .collect();
        devices.sort_by_key(|device| device.ipv4_address);
        for device in devices {
            let DeviceBackendData::AmneziaWg(data) = &device.backend_data else {
                return Err(BackendError::BackendMismatch(self.kind()));
            };
            let psk = secrets.get(&data.preshared_key_ref).ok_or_else(|| {
                BackendError::MissingSecret {
                    backend: self.kind(),
                    reference: data.preshared_key_ref.clone(),
                }
            })?;
            let address = device.ipv4_address.ok_or(BackendError::Validation(
                ValidationError::MissingDeviceAddress(self.kind()),
            ))?;
            write!(
                output,
                "\n# {} ({})\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {address}/32\n",
                sanitize_comment(&device.display_name),
                device.id,
                data.public_key,
                psk.as_str(),
            )
            .expect("writing to a String cannot fail");
        }
        Ok(vec![
            RenderedFile {
                path: "vpn/awg0.conf.template".into(),
                contents: output,
                mode: 0o600,
                sensitive: true,
            },
            RenderedFile {
                path: "vpn/start-awg.sh".into(),
                contents: AWG_START_SCRIPT.into(),
                mode: 0o700,
                sensitive: false,
            },
        ])
    }

    fn render_client(
        &self,
        state: &DesiredState,
        device: &Device,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<ClientArtifact, BackendError> {
        self.validate(state)?;
        let BackendSettings::AmneziaWg(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let DeviceBackendData::AmneziaWg(data) = &device.backend_data else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let private =
            secrets
                .get(&data.private_key_ref)
                .ok_or_else(|| BackendError::MissingSecret {
                    backend: self.kind(),
                    reference: data.private_key_ref.clone(),
                })?;
        let psk =
            secrets
                .get(&data.preshared_key_ref)
                .ok_or_else(|| BackendError::MissingSecret {
                    backend: self.kind(),
                    reference: data.preshared_key_ref.clone(),
                })?;
        let server_public = secrets
            .get(&SecretReference(state.instance.id))
            .ok_or_else(|| BackendError::MissingSecret {
                backend: self.kind(),
                reference: SecretReference(state.instance.id),
            })?;
        let address = device.ipv4_address.ok_or(BackendError::Validation(
            ValidationError::MissingDeviceAddress(self.kind()),
        ))?;
        let allowed = match state.instance.routing_mode {
            RoutingMode::FullTunnel => "0.0.0.0/0".to_owned(),
            RoutingMode::SplitTunnel => state.instance.network.ipv4_subnet.to_string(),
        };
        let output = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {address}/32\nDNS = {}\n{}\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = {}:{}\nAllowedIPs = {allowed}\nPersistentKeepalive = {}\n",
            private.as_str(),
            state.instance.network.gateway_ipv4,
            render_obfuscation(settings),
            server_public.as_str(),
            psk.as_str(),
            state.instance.endpoint.host,
            state.instance.endpoint.port,
            state.instance.persistent_keepalive,
        );
        Ok(ClientArtifact {
            suggested_filename: format!("{}.conf", slug(&device.display_name)),
            contents: output,
            ipv6_warning: state
                .instance
                .network
                .ipv6_subnet
                .is_none()
                .then(|| "IPv6 is not routed by this IPv4-only instance.".into()),
        })
    }

    fn client_artifact_kind(&self) -> ClientArtifactKind {
        ClientArtifactKind::TextConfiguration
    }

    fn classify_settings_change(
        &self,
        previous: &BackendSettings,
        next: &BackendSettings,
    ) -> ChangeImpact {
        if previous == next {
            ChangeImpact::LiveUpdate
        } else {
            ChangeImpact::ServiceRestart
        }
    }
}

fn validate_settings(settings: &AmneziaWgSettings) -> Result<(), BackendError> {
    if !(4..=12).contains(&settings.jc) {
        return invalid("jc", "must be between 4 and 12");
    }
    if settings.jmin == 0 || settings.jmin > settings.jmax || settings.jmax > 1_280 {
        return invalid("jmin/jmax", "must satisfy 1 <= Jmin <= Jmax <= 1280");
    }
    let paddings = [settings.s1, settings.s2, settings.s3, settings.s4];
    if paddings.iter().any(|value| *value > 1_280) {
        return invalid("s1-s4", "padding must be at most 1280 bytes");
    }
    if paddings
        .iter()
        .enumerate()
        .any(|(index, value)| paddings[index + 1..].contains(value))
    {
        return invalid("s1-s4", "padding values must be distinct");
    }
    let packet_sizes = [
        settings.s1.saturating_add(MESSAGE_INITIATION_SIZE),
        settings.s2.saturating_add(MESSAGE_RESPONSE_SIZE),
        settings.s3.saturating_add(MESSAGE_COOKIE_REPLY_SIZE),
        settings.s4,
    ];
    if packet_sizes
        .iter()
        .enumerate()
        .any(|(index, value)| packet_sizes[index + 1..].contains(value))
    {
        return invalid("s1-s4", "resulting AWG packet sizes must be distinct");
    }
    let ranges = [&settings.h1, &settings.h2, &settings.h3, &settings.h4];
    for range in &ranges {
        validate_magic_range(range)?;
    }
    if ranges.windows(2).any(|pair| pair[0].max >= pair[1].min) {
        return invalid("h1-h4", "magic-header ranges must be ordered and disjoint");
    }
    Ok(())
}

fn validate_magic_range(range: &AmneziaWgMagicRange) -> Result<(), BackendError> {
    if range.min < 5 || range.min > range.max || range.max > i32::MAX as u32 {
        return invalid(
            "h1-h4",
            "each range must satisfy 5 <= min <= max <= 2147483647",
        );
    }
    Ok(())
}

fn invalid<T>(field: &'static str, message: &str) -> Result<T, BackendError> {
    Err(BackendError::InvalidSetting {
        backend: VpnBackendKind::AmneziaWg,
        field,
        message: message.into(),
    })
}

fn render_obfuscation(settings: &AmneziaWgSettings) -> String {
    format!(
        "Jc = {}\nJmin = {}\nJmax = {}\nS1 = {}\nS2 = {}\nS3 = {}\nS4 = {}\nH1 = {}-{}\nH2 = {}-{}\nH3 = {}-{}\nH4 = {}-{}",
        settings.jc,
        settings.jmin,
        settings.jmax,
        settings.s1,
        settings.s2,
        settings.s3,
        settings.s4,
        settings.h1.min,
        settings.h1.max,
        settings.h2.min,
        settings.h2.max,
        settings.h3.min,
        settings.h3.max,
        settings.h4.min,
        settings.h4.max,
    )
}

fn sanitize_comment(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

fn slug(value: &str) -> String {
    let slug: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    slug.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use vam_core::{AmneziaWgDeviceData, DnsConfig, EndpointConfig, NetworkConfig, VpnInstance};

    fn fixture() -> (
        DesiredState,
        Device,
        HashMap<SecretReference, Zeroizing<String>>,
    ) {
        let instance_id = Uuid::nil();
        let private_ref = SecretReference(Uuid::from_u128(2));
        let psk_ref = SecretReference(Uuid::from_u128(3));
        let device = Device {
            id: Uuid::from_u128(4),
            instance_id,
            user_id: None,
            display_name: "Laptop\nSafe".into(),
            ipv4_address: Some("10.64.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: Some("laptop.vpn.internal".into()),
            enabled: true,
            backend_data: DeviceBackendData::AmneziaWg(AmneziaWgDeviceData {
                public_key: "client-public".into(),
                private_key_ref: private_ref.clone(),
                preshared_key_ref: psk_ref.clone(),
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        let subnet = "10.64.0.0/24".parse().unwrap();
        let state = DesiredState {
            instance: VpnInstance {
                id: instance_id,
                host_id: Uuid::from_u128(1),
                display_name: "AWG".into(),
                backend: VpnBackendKind::AmneziaWg,
                backend_settings: BackendSettings::AmneziaWg(AmneziaWgSettings::default()),
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: AWG_CONTAINER_PORT,
                },
                network: NetworkConfig {
                    ipv4_subnet: subnet,
                    gateway_ipv4: "10.64.0.1".parse().unwrap(),
                    ipv6_subnet: None,
                    gateway_ipv6: None,
                },
                dns: DnsConfig {
                    zone: "vpn.internal".into(),
                    soa_serial: 2_026_073_001,
                },
                routing_mode: RoutingMode::SplitTunnel,
                persistent_keepalive: 25,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
            users: Vec::new(),
            devices: vec![device.clone()],
            dns_records: Vec::new(),
            dns_blocklist_domains: Vec::new(),
        };
        let secrets = HashMap::from([
            (private_ref, Zeroizing::new("client-private".into())),
            (psk_ref, Zeroizing::new("unique-peer-psk".into())),
            (
                SecretReference(instance_id),
                Zeroizing::new("server-public".into()),
            ),
        ]);
        (state, device, secrets)
    }

    #[test]
    fn awg2_render_is_deterministic_and_mirrors_obfuscation() {
        let (state, device, secrets) = fixture();
        let first = AmneziaWgBackend.render_server(&state, &secrets).unwrap();
        let second = AmneziaWgBackend.render_server(&state, &secrets).unwrap();
        assert_eq!(first, second);
        let server = first
            .iter()
            .find(|file| file.path == "vpn/awg0.conf.template")
            .unwrap();
        let client = AmneziaWgBackend
            .render_client(&state, &device, &secrets)
            .unwrap();
        for expected in [
            "Jc = 5",
            "S3 = 32",
            "S4 = 8",
            "H1 = 5-999",
            "H4 = 3000-3999",
        ] {
            assert!(server.contents.contains(expected));
            assert!(client.contents.contains(expected));
        }
        assert!(server.contents.contains("PresharedKey = unique-peer-psk"));
        assert!(!server.contents.contains("client-private"));
        assert!(client.contents.contains("AllowedIPs = 10.64.0.0/24"));
        let start_script = first
            .iter()
            .find(|file| file.path == "vpn/start-awg.sh")
            .unwrap();
        assert!(start_script.contents.contains("awg-quick up"));
        assert!(start_script.contents.contains("awg-quick down"));
        assert!(start_script.contents.contains("while :"));
        assert!(!start_script.contents.contains("exec awg-quick up"));
    }

    #[test]
    fn invalid_packet_collisions_and_header_overlap_are_rejected() {
        let (mut state, _, secrets) = fixture();
        if let BackendSettings::AmneziaWg(settings) = &mut state.instance.backend_settings {
            settings.s2 = settings.s1 + MESSAGE_INITIATION_SIZE - MESSAGE_RESPONSE_SIZE;
        }
        assert!(AmneziaWgBackend.render_server(&state, &secrets).is_err());

        if let BackendSettings::AmneziaWg(settings) = &mut state.instance.backend_settings {
            settings.s2 = 96;
            settings.s3 = settings.s4;
        }
        assert!(AmneziaWgBackend.render_server(&state, &secrets).is_err());

        if let BackendSettings::AmneziaWg(settings) = &mut state.instance.backend_settings {
            settings.s3 = 32;
            settings.h2.min = settings.h1.max;
        }
        assert!(AmneziaWgBackend.render_server(&state, &secrets).is_err());
    }

    #[test]
    fn runtime_is_awg2_specific_pinned_and_least_privilege() {
        let runtime = AmneziaWgBackend.runtime();
        assert!(runtime.image.contains(":2.0.0@sha256:"));
        assert_eq!(runtime.capabilities, vec![ContainerCapability::NetAdmin]);
        assert_eq!(runtime.devices, vec![ContainerDevice::Tun]);
        assert!(matches!(
            runtime.health,
            BackendHealthProbe::WireGuardLike {
                tool: "awg",
                interface: "awg0"
            }
        ));
    }

    #[test]
    fn generated_identity_material_is_unique_and_zeroizable() {
        let (first_private, first_public) = AmneziaWgBackend::generate_device_keys();
        let (second_private, second_public) = AmneziaWgBackend::generate_device_keys();
        let first_psk = AmneziaWgBackend::generate_preshared_key();
        let second_psk = AmneziaWgBackend::generate_preshared_key();
        assert_ne!(first_private.as_str(), second_private.as_str());
        assert_ne!(first_public, second_public);
        assert_ne!(first_psk.as_str(), second_psk.as_str());
        assert_eq!(first_private.len(), 44);
        assert_eq!(first_psk.len(), 44);
    }
}
