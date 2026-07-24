use std::{collections::HashMap, fmt::Write as _};

use async_trait::async_trait;
use thiserror::Error;
use vam_core::{
    DesiredState, Device, DeviceBackendData, RoutingMode, SecretReference, ValidationError,
    validate_device_addresses, validate_instance,
};
use vam_protocol::{ClientArtifact, RenderedFile};
use wireguard_conf::{PresharedKey, PrivateKey, PublicKey};
use zeroize::Zeroizing;

pub const SERVER_PRIVATE_KEY_SENTINEL: &str = "__VAM_SERVER_PRIVATE_KEY__";

#[derive(Debug, Error)]
pub enum BackendError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("WireGuard secret {0:?} is unavailable")]
    MissingSecret(SecretReference),
    #[error("device backend does not match the instance backend")]
    BackendMismatch,
    #[error("WireGuard key is invalid")]
    InvalidKey,
}

#[async_trait]
pub trait VpnBackend: Send + Sync {
    fn backend_id(&self) -> &'static str;
    fn validate(&self, state: &DesiredState) -> Result<(), BackendError>;
    fn render_server(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<RenderedFile, BackendError>;
    fn render_client(
        &self,
        state: &DesiredState,
        device: &Device,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<ClientArtifact, BackendError>;
}

#[derive(Debug, Default)]
pub struct WireGuardBackend;

impl WireGuardBackend {
    #[must_use]
    pub fn generate_device_keys() -> (Zeroizing<String>, String) {
        let private = PrivateKey::random();
        let public = PublicKey::from(&private);
        let private_text = Zeroizing::new(private.to_string());
        (private_text, public.to_string())
    }

    #[must_use]
    pub fn generate_preshared_key() -> Zeroizing<String> {
        Zeroizing::new(PresharedKey::random().to_string())
    }
}

#[async_trait]
impl VpnBackend for WireGuardBackend {
    fn backend_id(&self) -> &'static str {
        "wireguard"
    }

    fn validate(&self, state: &DesiredState) -> Result<(), BackendError> {
        validate_instance(&state.instance)?;
        validate_device_addresses(&state.instance, &state.devices)?;
        Ok(())
    }

    fn render_server(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<RenderedFile, BackendError> {
        self.validate(state)?;
        let subnet = state.instance.network.ipv4_subnet;
        let gateway = state.instance.network.gateway_ipv4;
        let mut output = format!(
            "[Interface]\nPrivateKey = {SERVER_PRIVATE_KEY_SENTINEL}\nAddress = {gateway}/{}\nListenPort = 51820\nPostUp = iptables -A FORWARD -i %i -o %i -j ACCEPT; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -j MASQUERADE\nPreDown = iptables -D FORWARD -i %i -o %i -j ACCEPT; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet} -o eth0 -j MASQUERADE\n",
            subnet.prefix_len()
        );
        let mut devices: Vec<_> = state
            .devices
            .iter()
            .filter(|device| device.enabled && device.deleted_at.is_none())
            .collect();
        devices.sort_by_key(|device| device.ipv4_address);
        for device in devices {
            let DeviceBackendData::WireGuard(data) = &device.backend_data;
            write!(
                output,
                "\n# {} ({})\n[Peer]\nPublicKey = {}\n",
                sanitize_comment(&device.display_name),
                device.id,
                data.public_key
            )
            .expect("writing to a String cannot fail");
            if let Some(reference) = &data.preshared_key_ref {
                let key = secrets
                    .get(reference)
                    .ok_or_else(|| BackendError::MissingSecret(reference.clone()))?;
                writeln!(output, "PresharedKey = {}", key.as_str())
                    .expect("writing to a String cannot fail");
            }
            writeln!(output, "AllowedIPs = {}/32", device.ipv4_address)
                .expect("writing to a String cannot fail");
        }
        Ok(RenderedFile {
            path: "vpn/wg0.conf.template".into(),
            contents: output,
            mode: 0o600,
            sensitive: true,
        })
    }

    fn render_client(
        &self,
        state: &DesiredState,
        device: &Device,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<ClientArtifact, BackendError> {
        let DeviceBackendData::WireGuard(data) = &device.backend_data;
        let private = secrets
            .get(&data.private_key_ref)
            .ok_or_else(|| BackendError::MissingSecret(data.private_key_ref.clone()))?;
        let server_public = secrets
            .iter()
            .find_map(|(reference, value)| {
                (reference.0 == state.instance.id).then_some(value.as_str())
            })
            .ok_or(BackendError::MissingSecret(SecretReference(
                state.instance.id,
            )))?;
        let allowed = match state.instance.routing_mode {
            RoutingMode::FullTunnel => "0.0.0.0/0".to_owned(),
            RoutingMode::SplitTunnel => state.instance.network.ipv4_subnet.to_string(),
        };
        let mut output = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32\nDNS = {}\n\n[Peer]\nPublicKey = {server_public}\n",
            private.as_str(),
            device.ipv4_address,
            state.instance.network.gateway_ipv4
        );
        if let Some(reference) = &data.preshared_key_ref {
            let key = secrets
                .get(reference)
                .ok_or_else(|| BackendError::MissingSecret(reference.clone()))?;
            writeln!(output, "PresharedKey = {}", key.as_str())
                .expect("writing to a String cannot fail");
        }
        write!(
            output,
            "Endpoint = {}:{}\nAllowedIPs = {allowed}\nPersistentKeepalive = {}\n",
            state.instance.endpoint.host,
            state.instance.endpoint.port,
            state.instance.persistent_keepalive
        )
        .expect("writing to a String cannot fail");
        let filename = format!("{}.conf", slug(&device.display_name));
        Ok(ClientArtifact {
            suggested_filename: filename,
            contents: output,
            ipv6_warning: state
                .instance
                .network
                .ipv6_subnet
                .is_none()
                .then(|| "IPv6 is not routed by this IPv4-only instance.".into()),
        })
    }
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
    use vam_core::{
        DEFAULT_KEEPALIVE, DnsConfig, EndpointConfig, NetworkConfig, VpnBackendKind, VpnInstance,
        WireGuardDeviceData,
    };
    use zeroize::Zeroize;

    fn fixture(
        mode: RoutingMode,
    ) -> (
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
            display_name: "MacBook\nInjected".into(),
            ipv4_address: "10.64.0.2".parse().unwrap(),
            ipv6_address: None,
            dns_name: Some("macbook".into()),
            enabled: true,
            backend_data: DeviceBackendData::WireGuard(WireGuardDeviceData {
                public_key: "device-public-key".into(),
                private_key_ref: private_ref.clone(),
                preshared_key_ref: Some(psk_ref.clone()),
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        let subnet = "10.64.0.0/24".parse().unwrap();
        let state = DesiredState {
            instance: VpnInstance {
                id: instance_id,
                host_id: Uuid::from_u128(1),
                display_name: "VPN".into(),
                backend: VpnBackendKind::WireGuard,
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: 51_820,
                },
                network: NetworkConfig {
                    ipv4_subnet: subnet,
                    gateway_ipv4: "10.64.0.1".parse().unwrap(),
                    ipv6_subnet: None,
                    gateway_ipv6: None,
                },
                dns: DnsConfig {
                    zone: "vpn.internal".into(),
                    soa_serial: 2_026_072_301,
                },
                routing_mode: mode,
                persistent_keepalive: DEFAULT_KEEPALIVE,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
            users: Vec::new(),
            devices: vec![device.clone()],
            dns_records: Vec::new(),
        };
        let secrets = HashMap::from([
            (private_ref, Zeroizing::new("client-private".into())),
            (psk_ref, Zeroizing::new("peer-psk".into())),
            (
                SecretReference(instance_id),
                Zeroizing::new("server-public".into()),
            ),
        ]);
        (state, device, secrets)
    }

    #[test]
    fn generated_keys_are_wireguard_base64_and_zeroizable() {
        let (mut private, public) = WireGuardBackend::generate_device_keys();
        assert_eq!(private.len(), 44);
        assert_eq!(public.len(), 44);
        private.zeroize();
        assert!(private.is_empty() || private.chars().all(|character| character == '\0'));
    }

    #[test]
    fn server_template_is_deterministic_and_contains_no_client_private_key() {
        let (state, _, secrets) = fixture(RoutingMode::SplitTunnel);
        let rendered = WireGuardBackend.render_server(&state, &secrets).unwrap();
        assert!(rendered.contents.contains(SERVER_PRIVATE_KEY_SENTINEL));
        assert!(rendered.contents.contains("PresharedKey = peer-psk"));
        assert!(rendered.contents.contains("AllowedIPs = 10.64.0.2/32"));
        assert!(
            rendered
                .contents
                .contains("iptables -A FORWARD -i %i -o %i -j ACCEPT")
        );
        assert!(
            rendered
                .contents
                .contains("iptables -D FORWARD -i %i -o %i -j ACCEPT")
        );
        assert!(!rendered.contents.contains("client-private"));
        assert!(!rendered.contents.contains('\r'));
    }

    #[test]
    fn ipv4_full_tunnel_never_advertises_ipv6_default_route() {
        let (state, device, secrets) = fixture(RoutingMode::FullTunnel);
        let artifact = WireGuardBackend
            .render_client(&state, &device, &secrets)
            .unwrap();
        assert!(artifact.contents.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!artifact.contents.contains("::/0"));
        assert!(artifact.ipv6_warning.is_some());
        assert_eq!(artifact.suggested_filename, "macbook-injected.conf");
    }
}
