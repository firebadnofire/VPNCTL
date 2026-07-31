use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use uuid::Uuid;
use vam_backend::{
    BackendCapabilities, BackendError, BackendHealthProbe, BackendHostRequirement,
    BackendPresentation, BackendRuntimeSpec, BackendValidation, ChangeImpact, ClientAction,
    ClientAddressCapability, ClientArtifactKind, ClientExportFormat, ConfigurationField,
    ConfigurationSection, ContainerCapability, ContainerDevice, ContainerImage, ContainerMount,
    ContainerMountOwnership, CredentialAction, CredentialArtifact, CredentialOperation,
    CredentialPlan, DnsCapability, ListenerModel, RoutingCapability, ServerIdentityStrategy,
    StatisticsCapability, VpnBackend,
};
use vam_core::{
    BackendSettings, DesiredState, Device, DeviceBackendData, ListenerPort, OpenVpnCipher,
    OpenVpnDeviceData, OpenVpnSettings, OpenVpnTlsProtection, OpenVpnTransport, RoutingMode,
    SecretReference, TransportProtocol, VpnBackendKind, validate_device_addresses,
    validate_instance,
};
use vam_protocol::{ClientArtifact, RenderedFile};
use zeroize::Zeroizing;

pub const OPENVPN_CONTAINER_PORT: u16 = 1_194;
pub const OPENVPN_LOCAL_IMAGE: &str =
    "vpn-appliance-manager/openvpn:alpine3.23.5-openvpn2.6.20-r0-easyrsa3.2.3-r0";
pub const OPENVPN_DOCKERFILE_PATH: &str = "vpn/Dockerfile";

const CA_LIFETIME_DAYS: u16 = 3_650;
const CRL_LIFETIME_DAYS: u16 = 3_650;
const OPENVPN_DOCKERFILE: &str = r#"FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache \
        easy-rsa=3.2.3-r0 \
        iptables=1.8.11-r1 \
        openvpn=2.6.20-r0 \
    && ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa \
    && mkdir -p /run/openvpn
ENV EASYRSA=/usr/share/easy-rsa
ENV EASYRSA_BATCH=1
ENV EASYRSA_PKI=/etc/openvpn/pki
COPY start-openvpn.sh /usr/local/sbin/start-openvpn
RUN chmod 0755 /usr/local/sbin/start-openvpn
ENTRYPOINT ["/usr/local/sbin/start-openvpn"]
"#;

#[derive(Debug)]
pub struct GeneratedOpenVpnIdentity {
    pub common_name: String,
    pub private_key: Zeroizing<String>,
    pub csr: Zeroizing<String>,
}

#[derive(Debug, Default)]
pub struct OpenVpnBackend;

impl OpenVpnBackend {
    pub fn generate_identity(
        display_name: &str,
        device_id: Uuid,
    ) -> Result<GeneratedOpenVpnIdentity, BackendError> {
        let common_name = common_name(display_name, device_id);
        validate_common_name(&common_name)?;

        let key_pair = KeyPair::generate()
            .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name.as_str());
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr = params
            .serialize_request(&key_pair)
            .and_then(|request| request.pem())
            .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn))?;

        Ok(GeneratedOpenVpnIdentity {
            common_name,
            private_key: Zeroizing::new(key_pair.serialize_pem()),
            csr: Zeroizing::new(csr),
        })
    }
}

impl VpnBackend for OpenVpnBackend {
    fn kind(&self) -> VpnBackendKind {
        VpnBackendKind::OpenVpn
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            allocated_tunnel_addresses: true,
            managed_dns: true,
            quick_credential_refresh: false,
            live_identity_updates: true,
            qr_export: false,
            traffic_statistics: true,
            certificate_authority: true,
        }
    }

    fn presentation(&self) -> BackendPresentation {
        BackendPresentation {
            short_name: "OVPN",
            badge: "OVPN",
            description: "TLS-based VPN with broad client compatibility",
            routing: RoutingCapability::RoutedTunnel,
            dns: DnsCapability::ManagedPrivateDns,
            client_addresses: ClientAddressCapability::Allocated,
            statistics: StatisticsCapability::BackendSupported,
            listener_model: ListenerModel::Configurable,
            client_identity_name: "certificate identity",
            client_actions: &[
                ClientAction::Revoke,
                ClientAction::ReplaceIdentity,
                ClientAction::Export,
                ClientAction::Remove,
            ],
            export_formats: &[ClientExportFormat::OpenVpnProfile],
            configuration_sections: &[
                ConfigurationSection::General,
                ConfigurationSection::Network,
                ConfigurationSection::Protocol,
                ConfigurationSection::Dns,
                ConfigurationSection::Advanced,
            ],
            configuration_fields: &[
                ConfigurationField::Endpoint,
                ConfigurationField::ListenerPort,
                ConfigurationField::AddressPool,
                ConfigurationField::RoutingMode,
                ConfigurationField::ManagedDns,
                ConfigurationField::OpenVpnTransport,
                ConfigurationField::OpenVpnCipher,
                ConfigurationField::OpenVpnTlsProtection,
                ConfigurationField::CertificateLifetime,
            ],
            host_requirements: &[
                BackendHostRequirement::Linux,
                BackendHostRequirement::SupportedArchitecture,
                BackendHostRequirement::DockerEngine,
                BackendHostRequirement::ComposeV2,
                BackendHostRequirement::DockerAccess,
                BackendHostRequirement::TunDevice,
            ],
            identity_replacement_warning: "Revokes the current certificate and issues a new client identity. Existing exported profiles will stop working.",
        }
    }

    fn runtime(&self, settings: &BackendSettings) -> Result<BackendRuntimeSpec, BackendError> {
        let BackendSettings::OpenVpn(settings) = settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        Ok(BackendRuntimeSpec {
            image: ContainerImage::Build {
                tag: OPENVPN_LOCAL_IMAGE,
                dockerfile_path: OPENVPN_DOCKERFILE_PATH,
                input_paths: &["vpn/start-openvpn.sh"],
            },
            container_listeners: vec![ListenerPort {
                port: OPENVPN_CONTAINER_PORT,
                protocol: transport_protocol(settings.transport),
            }],
            capabilities: vec![ContainerCapability::NetAdmin],
            devices: vec![ContainerDevice::Tun],
            mounts: vec![ContainerMount {
                host_path: "vpn",
                container_path: "/etc/openvpn",
                read_only: false,
                ownership: ContainerMountOwnership::HostUser,
            }],
            environment: Vec::new(),
            entrypoint: Vec::new(),
            command: Vec::new(),
            sysctls: vec![("net.ipv4.ip_forward", "1")],
            identity: ServerIdentityStrategy::CertificateAuthority {
                persistent_paths: &["vpn/pki", "vpn/requests", "vpn/tls-crypt.key"],
            },
            validation: BackendValidation::OpenVpn {
                config_path: "vpn/server.conf",
            },
            health: BackendHealthProbe::OpenVpn,
        })
    }

    fn listeners(&self, settings: &BackendSettings, endpoint_port: u16) -> Vec<ListenerPort> {
        let BackendSettings::OpenVpn(settings) = settings else {
            return Vec::new();
        };
        vec![ListenerPort {
            port: endpoint_port,
            protocol: transport_protocol(settings.transport),
        }]
    }

    fn validate(&self, state: &DesiredState) -> Result<(), BackendError> {
        if state.instance.backend != self.kind() {
            return Err(BackendError::BackendMismatch(self.kind()));
        }
        let BackendSettings::OpenVpn(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        validate_instance(&state.instance)?;
        validate_device_addresses(&state.instance, &state.devices)?;
        validate_settings(settings)?;
        validate_endpoint_host(&state.instance.endpoint.host)?;

        let mut common_names = HashSet::new();
        for device in state
            .devices
            .iter()
            .filter(|device| device.deleted_at.is_none())
        {
            let DeviceBackendData::OpenVpn(data) = &device.backend_data else {
                return Err(BackendError::BackendMismatch(self.kind()));
            };
            validate_common_name(&data.common_name)?;
            validate_device_material(settings, data)?;
            if !common_names.insert(data.common_name.as_str()) {
                return invalid("common_name", "active client common names must be unique");
            }
        }
        Ok(())
    }

    fn server_secret_references(&self, _state: &DesiredState) -> Vec<SecretReference> {
        Vec::new()
    }

    fn client_secret_references(
        &self,
        device: &Device,
    ) -> Result<Vec<SecretReference>, BackendError> {
        let DeviceBackendData::OpenVpn(data) = &device.backend_data else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let mut references = vec![
            data.private_key_ref.clone(),
            data.certificate_ref.clone(),
            data.ca_certificate_ref.clone(),
        ];
        references.extend(data.tls_crypt_key_ref.iter().cloned());
        Ok(references)
    }

    fn render_server(
        &self,
        state: &DesiredState,
        _secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, BackendError> {
        self.validate(state)?;
        let BackendSettings::OpenVpn(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };

        let mut files = vec![
            RenderedFile {
                path: OPENVPN_DOCKERFILE_PATH.into(),
                contents: OPENVPN_DOCKERFILE.into(),
                mode: 0o644,
                sensitive: false,
            },
            RenderedFile {
                path: "vpn/server.conf".into(),
                contents: render_server_config(state, settings),
                mode: 0o600,
                sensitive: false,
            },
            RenderedFile {
                path: "vpn/start-openvpn.sh".into(),
                contents: render_start_script(state),
                mode: 0o700,
                sensitive: false,
            },
            RenderedFile {
                path: "vpn/ccd/.keep".into(),
                contents: String::new(),
                mode: 0o600,
                sensitive: false,
            },
            RenderedFile {
                path: "vpn/requests/.keep".into(),
                contents: String::new(),
                mode: 0o600,
                sensitive: false,
            },
        ];

        let netmask = state.instance.network.ipv4_subnet.netmask();
        let mut devices: Vec<_> = state
            .devices
            .iter()
            .filter(|device| device.enabled && device.deleted_at.is_none())
            .collect();
        devices.sort_by(|left, right| {
            let DeviceBackendData::OpenVpn(left) = &left.backend_data else {
                unreachable!("validation rejects mismatched device backends")
            };
            let DeviceBackendData::OpenVpn(right) = &right.backend_data else {
                unreachable!("validation rejects mismatched device backends")
            };
            left.common_name.cmp(&right.common_name)
        });
        for device in devices {
            let DeviceBackendData::OpenVpn(data) = &device.backend_data else {
                unreachable!("validation rejects mismatched device backends")
            };
            let address = device
                .ipv4_address
                .expect("validation requires OpenVPN device addresses");
            files.push(RenderedFile {
                path: format!("vpn/ccd/{}", data.common_name),
                contents: format!("ifconfig-push {address} {netmask}\n"),
                mode: 0o600,
                sensitive: false,
            });
        }
        Ok(files)
    }

    fn render_client(
        &self,
        state: &DesiredState,
        device: &Device,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<ClientArtifact, BackendError> {
        self.validate(state)?;
        let BackendSettings::OpenVpn(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let DeviceBackendData::OpenVpn(data) = &device.backend_data else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };

        let private_key = required_secret(secrets, &data.private_key_ref)?;
        let certificate = required_secret(secrets, &data.certificate_ref)?;
        let ca_certificate = required_secret(secrets, &data.ca_certificate_ref)?;
        let private_key = extract_pem(
            private_key.as_str(),
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
        )?;
        let certificate = extract_pem(
            certificate.as_str(),
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----",
        )?;
        let ca_certificate = extract_pem(
            ca_certificate.as_str(),
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----",
        )?;

        let mut config = format!(
            "client\ndev tun\nproto {}\nremote {} {}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\npull\nremote-cert-tls server\nverify-x509-name {} name\ntls-version-min 1.3\ntls-cert-profile preferred\ndata-ciphers {}\nauth SHA256\nauth-nocache\nallow-compression no\nverb 3\n",
            client_transport(settings.transport),
            state.instance.endpoint.host,
            state.instance.endpoint.port,
            server_common_name(state.instance.id),
            cipher_name(settings.cipher),
        );
        if settings.transport == OpenVpnTransport::Udp {
            config.push_str("explicit-exit-notify 1\n");
        }
        match state.instance.routing_mode {
            RoutingMode::FullTunnel => {
                config.push_str("redirect-gateway def1 bypass-dhcp\nblock-ipv6\n");
            }
            RoutingMode::SplitTunnel => {
                config.push_str(&format!(
                    "route {} {}\n",
                    state.instance.network.ipv4_subnet.network(),
                    state.instance.network.ipv4_subnet.netmask()
                ));
            }
        }
        config.push_str(&format!(
            "dhcp-option DNS {}\n\n<ca>\n{ca_certificate}\n</ca>\n<cert>\n{certificate}\n</cert>\n<key>\n{private_key}\n</key>\n",
            state.instance.network.gateway_ipv4,
        ));
        if settings.tls_protection == OpenVpnTlsProtection::TlsCrypt {
            let reference = data
                .tls_crypt_key_ref
                .as_ref()
                .ok_or(BackendError::InvalidKeyMaterial(self.kind()))?;
            let key = required_secret(secrets, reference)?;
            let key = extract_static_key(key.as_str())?;
            config.push_str(&format!("<tls-crypt>\n{key}\n</tls-crypt>\n"));
        }

        Ok(ClientArtifact::text(
            format!("{}.ovpn", slug(&device.display_name)),
            config,
            state
                .instance
                .network
                .ipv6_subnet
                .is_none()
                .then(|| "IPv6 is blocked because this OpenVPN instance routes IPv4 only.".into()),
        ))
    }

    fn client_artifact_kind(&self) -> ClientArtifactKind {
        ClientArtifactKind::TextConfiguration
    }

    fn plan_credentials(
        &self,
        state: &DesiredState,
        device: Option<&Device>,
        action: CredentialAction,
    ) -> Result<CredentialPlan, BackendError> {
        self.validate(state)?;
        let BackendSettings::OpenVpn(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let operations = match action {
            CredentialAction::InitializeAuthority => {
                vec![CredentialOperation::InitializeOpenVpnAuthority {
                    ca_common_name: ca_common_name(state.instance.id),
                    server_common_name: server_common_name(state.instance.id),
                    ca_lifetime_days: CA_LIFETIME_DAYS,
                    certificate_lifetime_days: settings.certificate_lifetime_days,
                    crl_lifetime_days: CRL_LIFETIME_DAYS,
                    tls_crypt: settings.tls_protection == OpenVpnTlsProtection::TlsCrypt,
                }]
            }
            CredentialAction::Issue => {
                let data = openvpn_device(device, self.kind())?;
                issue_operations(settings, data)
            }
            CredentialAction::Revoke => {
                let data = openvpn_device(device, self.kind())?;
                vec![
                    CredentialOperation::RevokeOpenVpnClient {
                        common_name: data.common_name.clone(),
                    },
                    CredentialOperation::RegenerateOpenVpnCrl {
                        lifetime_days: CRL_LIFETIME_DAYS,
                    },
                    CredentialOperation::ReloadGateway,
                ]
            }
            CredentialAction::Replace {
                previous_identity, ..
            } => {
                validate_common_name(&previous_identity)?;
                let data = openvpn_device(device, self.kind())?;
                let mut operations = issue_operations(settings, data);
                operations.extend([
                    CredentialOperation::RevokeOpenVpnClient {
                        common_name: previous_identity,
                    },
                    CredentialOperation::RegenerateOpenVpnCrl {
                        lifetime_days: CRL_LIFETIME_DAYS,
                    },
                    CredentialOperation::ReloadGateway,
                ]);
                operations
            }
        };
        Ok(CredentialPlan { operations })
    }

    fn classify_settings_change(
        &self,
        previous: &BackendSettings,
        next: &BackendSettings,
    ) -> ChangeImpact {
        match (previous, next) {
            (BackendSettings::OpenVpn(previous), BackendSettings::OpenVpn(next))
                if previous == next =>
            {
                ChangeImpact::LiveUpdate
            }
            (BackendSettings::OpenVpn(previous), BackendSettings::OpenVpn(next))
                if previous.transport != next.transport
                    || previous.tls_protection != next.tls_protection =>
            {
                ChangeImpact::ServiceRestart
            }
            (BackendSettings::OpenVpn(previous), BackendSettings::OpenVpn(next))
                if previous.cipher != next.cipher =>
            {
                ChangeImpact::ServiceRestart
            }
            (BackendSettings::OpenVpn(_), BackendSettings::OpenVpn(_)) => ChangeImpact::LiveUpdate,
            _ => ChangeImpact::Reinstall,
        }
    }
}

fn validate_settings(settings: &OpenVpnSettings) -> Result<(), BackendError> {
    if settings.certificate_lifetime_days == 0 {
        return invalid("certificate_lifetime_days", "must be at least 1 day");
    }
    Ok(())
}

fn validate_device_material(
    settings: &OpenVpnSettings,
    data: &OpenVpnDeviceData,
) -> Result<(), BackendError> {
    let mut references = vec![
        &data.private_key_ref,
        &data.csr_ref,
        &data.certificate_ref,
        &data.ca_certificate_ref,
    ];
    references.extend(data.tls_crypt_key_ref.as_ref());
    if references.iter().any(|reference| reference.0.is_nil()) {
        return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn));
    }
    match (settings.tls_protection, data.tls_crypt_key_ref.is_some()) {
        (OpenVpnTlsProtection::TlsCrypt, false) | (OpenVpnTlsProtection::None, true) => {
            return invalid(
                "tls_protection",
                "device TLS key reference must match the instance TLS mode",
            );
        }
        _ => {}
    }
    if let Some(serial) = &data.certificate_serial
        && (serial.is_empty() || !serial.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return invalid("certificate_serial", "must be hexadecimal");
    }
    Ok(())
}

fn validate_common_name(common_name: &str) -> Result<(), BackendError> {
    let bytes = common_name.as_bytes();
    let valid = (1..=63).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if !valid {
        return invalid(
            "common_name",
            "must be 1-63 lowercase ASCII letters, digits, or hyphens and start/end alphanumeric",
        );
    }
    Ok(())
}

fn validate_endpoint_host(host: &str) -> Result<(), BackendError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        });
    if !valid {
        return invalid("endpoint.host", "must be an IP address or a valid DNS name");
    }
    Ok(())
}

fn invalid<T>(field: &'static str, message: &str) -> Result<T, BackendError> {
    Err(BackendError::InvalidSetting {
        backend: VpnBackendKind::OpenVpn,
        field,
        message: message.into(),
    })
}

fn required_secret<'a>(
    secrets: &'a HashMap<SecretReference, Zeroizing<String>>,
    reference: &SecretReference,
) -> Result<&'a Zeroizing<String>, BackendError> {
    secrets
        .get(reference)
        .ok_or_else(|| BackendError::MissingSecret {
            backend: VpnBackendKind::OpenVpn,
            reference: reference.clone(),
        })
}

fn openvpn_device(
    device: Option<&Device>,
    backend: VpnBackendKind,
) -> Result<&OpenVpnDeviceData, BackendError> {
    let device = device.ok_or(BackendError::MissingCredentialDevice(backend))?;
    let DeviceBackendData::OpenVpn(data) = &device.backend_data else {
        return Err(BackendError::BackendMismatch(backend));
    };
    Ok(data)
}

fn issue_operations(
    settings: &OpenVpnSettings,
    data: &OpenVpnDeviceData,
) -> Vec<CredentialOperation> {
    let request_path = format!("vpn/requests/{}.req", data.common_name);
    let certificate_path = format!("vpn/pki/issued/{}.crt", data.common_name);
    let mut operations = vec![
        CredentialOperation::UploadSecret {
            reference: data.csr_ref.clone(),
            relative_path: request_path.clone(),
            mode: 0o600,
        },
        CredentialOperation::ImportOpenVpnCsr {
            common_name: data.common_name.clone(),
            relative_path: request_path,
        },
        CredentialOperation::SignOpenVpnClient {
            common_name: data.common_name.clone(),
            certificate_lifetime_days: settings.certificate_lifetime_days,
        },
        CredentialOperation::DownloadToSecret {
            relative_path: certificate_path.clone(),
            reference: data.certificate_ref.clone(),
            artifact: CredentialArtifact::ClientCertificate,
        },
        CredentialOperation::DownloadToSecret {
            relative_path: "vpn/pki/ca.crt".into(),
            reference: data.ca_certificate_ref.clone(),
            artifact: CredentialArtifact::CaCertificate,
        },
    ];
    if let Some(reference) = &data.tls_crypt_key_ref {
        operations.push(CredentialOperation::DownloadToSecret {
            relative_path: "vpn/tls-crypt.key".into(),
            reference: reference.clone(),
            artifact: CredentialArtifact::TlsCryptKey,
        });
    }
    operations.push(CredentialOperation::ReadCertificateSerial {
        relative_path: certificate_path,
    });
    operations
}

fn render_server_config(state: &DesiredState, settings: &OpenVpnSettings) -> String {
    let subnet = state.instance.network.ipv4_subnet;
    let mut config = format!(
        "port {OPENVPN_CONTAINER_PORT}\nproto {}\ndev tun\ntopology subnet\nca /etc/openvpn/pki/ca.crt\ncert /etc/openvpn/pki/issued/{}.crt\nkey /etc/openvpn/pki/private/{}.key\ndh none\necdh-curve prime256v1\nserver {} {}\ntls-server\nifconfig-pool-persist /etc/openvpn/ipp.txt\nclient-config-dir /etc/openvpn/ccd\nccd-exclusive\nclient-to-client\nkeepalive 10 120\npersist-key\npersist-tun\nuser nobody\ngroup nobody\ncrl-verify /etc/openvpn/pki/crl.pem\nstatus /run/openvpn/status.log 10\nstatus-version 3\nverify-client-cert require\nremote-cert-tls client\ntls-version-min 1.3\ntls-cert-profile preferred\ndata-ciphers {}\nauth SHA256\nallow-compression no\nverb 3\n",
        server_transport(settings.transport),
        server_common_name(state.instance.id),
        server_common_name(state.instance.id),
        subnet.network(),
        subnet.netmask(),
        cipher_name(settings.cipher),
    );
    if settings.tls_protection == OpenVpnTlsProtection::TlsCrypt {
        config.push_str("tls-crypt /etc/openvpn/tls-crypt.key\n");
    }
    config.push_str(&format!(
        "push \"dhcp-option DNS {}\"\n",
        state.instance.network.gateway_ipv4
    ));
    match state.instance.routing_mode {
        RoutingMode::FullTunnel => {
            config.push_str("push \"redirect-gateway def1 bypass-dhcp\"\npush \"block-ipv6\"\n");
        }
        RoutingMode::SplitTunnel => {
            config.push_str(&format!(
                "push \"route {} {}\"\n",
                subnet.network(),
                subnet.netmask()
            ));
        }
    }
    config
}

fn render_start_script(state: &DesiredState) -> String {
    let subnet = state.instance.network.ipv4_subnet;
    format!(
        r#"#!/bin/sh
set -eu

add_rules() {{
    iptables -C FORWARD -i tun0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i tun0 -j ACCEPT
    iptables -C FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s {subnet} -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -j MASQUERADE
}}

delete_rules() {{
    iptables -C FORWARD -i tun0 -j ACCEPT 2>/dev/null && iptables -D FORWARD -i tun0 -j ACCEPT || true
    iptables -C FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && iptables -D FORWARD -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true
    iptables -t nat -C POSTROUTING -s {subnet} -o eth0 -j MASQUERADE 2>/dev/null && iptables -t nat -D POSTROUTING -s {subnet} -o eth0 -j MASQUERADE || true
}}

child=
cleanup() {{
    if [ -n "$child" ]; then
        kill -TERM "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    delete_rules
}}

trap 'cleanup; exit 0' INT TERM
add_rules
openvpn --config /etc/openvpn/server.conf &
child=$!
if wait "$child"; then
    status=0
else
    status=$?
fi
child=
delete_rules
exit "$status"
"#,
    )
}

fn extract_pem<'a>(value: &'a str, begin: &str, end: &str) -> Result<&'a str, BackendError> {
    let start = value
        .find(begin)
        .ok_or(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn))?;
    let tail = &value[start..];
    let finish = tail
        .find(end)
        .map(|index| index + end.len())
        .ok_or(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn))?;
    let block = &tail[..finish];
    let body = block
        .strip_prefix(begin)
        .and_then(|body| body.strip_suffix(end))
        .ok_or(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn))?;
    let mut has_content = false;
    for character in body
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
    {
        has_content = true;
        if !(character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')) {
            return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn));
        }
    }
    if !has_content {
        return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn));
    }
    Ok(block)
}

fn extract_static_key(value: &str) -> Result<&str, BackendError> {
    const BEGIN: &str = "-----BEGIN OpenVPN Static key V1-----";
    const END: &str = "-----END OpenVPN Static key V1-----";
    let block = extract_pem(value, BEGIN, END)?;
    let body = block
        .strip_prefix(BEGIN)
        .and_then(|body| body.strip_suffix(END))
        .ok_or(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn))?;
    if body
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .any(|character| !character.is_ascii_hexdigit())
    {
        return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::OpenVpn));
    }
    Ok(block)
}

fn transport_protocol(transport: OpenVpnTransport) -> TransportProtocol {
    match transport {
        OpenVpnTransport::Tcp => TransportProtocol::Tcp,
        OpenVpnTransport::Udp => TransportProtocol::Udp,
    }
}

fn server_transport(transport: OpenVpnTransport) -> &'static str {
    match transport {
        OpenVpnTransport::Tcp => "tcp-server",
        OpenVpnTransport::Udp => "udp",
    }
}

fn client_transport(transport: OpenVpnTransport) -> &'static str {
    match transport {
        OpenVpnTransport::Tcp => "tcp-client",
        OpenVpnTransport::Udp => "udp",
    }
}

fn cipher_name(cipher: OpenVpnCipher) -> &'static str {
    match cipher {
        OpenVpnCipher::Aes256Gcm => "AES-256-GCM",
        OpenVpnCipher::Chacha20Poly1305 => "CHACHA20-POLY1305",
    }
}

fn ca_common_name(instance_id: Uuid) -> String {
    format!("vam-ca-{}", instance_id.simple())
}

fn server_common_name(instance_id: Uuid) -> String {
    format!("vam-server-{}", instance_id.simple())
}

fn common_name(display_name: &str, device_id: Uuid) -> String {
    let display = slug(display_name);
    let display = display.trim_matches('-');
    let display = if display.is_empty() {
        "client"
    } else {
        &display[..display.len().min(20)]
    };
    format!("{display}-{}", &device_id.simple().to_string()[..12])
        .trim_matches('-')
        .to_owned()
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
    use vam_core::{DnsConfig, EndpointConfig, NetworkConfig, VpnInstance, first_usable};

    fn fixture() -> (
        DesiredState,
        Device,
        HashMap<SecretReference, Zeroizing<String>>,
    ) {
        let instance_id = Uuid::from_u128(1);
        let private_key_ref = SecretReference(Uuid::from_u128(2));
        let csr_ref = SecretReference(Uuid::from_u128(3));
        let certificate_ref = SecretReference(Uuid::from_u128(4));
        let ca_certificate_ref = SecretReference(Uuid::from_u128(5));
        let tls_crypt_key_ref = SecretReference(Uuid::from_u128(6));
        let subnet = "10.88.0.0/24".parse().unwrap();
        let device = Device {
            id: Uuid::from_u128(7),
            instance_id,
            user_id: None,
            display_name: "Work Laptop".into(),
            ipv4_address: Some("10.88.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: Some("work-laptop.vpn.internal".into()),
            enabled: true,
            backend_data: DeviceBackendData::OpenVpn(OpenVpnDeviceData {
                common_name: "work-laptop-000000000007".into(),
                private_key_ref: private_key_ref.clone(),
                csr_ref,
                certificate_ref: certificate_ref.clone(),
                ca_certificate_ref: ca_certificate_ref.clone(),
                tls_crypt_key_ref: Some(tls_crypt_key_ref.clone()),
                certificate_serial: Some("A1B2C3".into()),
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        let state = DesiredState {
            instance: VpnInstance {
                id: instance_id,
                host_id: Uuid::from_u128(8),
                display_name: "OpenVPN".into(),
                backend: VpnBackendKind::OpenVpn,
                backend_settings: BackendSettings::OpenVpn(OpenVpnSettings::default()),
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: 1_194,
                },
                network: NetworkConfig {
                    ipv4_subnet: subnet,
                    gateway_ipv4: first_usable(subnet).unwrap(),
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
            (
                private_key_ref,
                Zeroizing::new(
                    "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----".into(),
                ),
            ),
            (
                certificate_ref,
                Zeroizing::new(
                    "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----".into(),
                ),
            ),
            (
                ca_certificate_ref,
                Zeroizing::new(
                    "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----".into(),
                ),
            ),
            (
                tls_crypt_key_ref,
                Zeroizing::new(
                    "# generated\n-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----\n"
                        .into(),
                ),
            ),
        ]);
        (state, device, secrets)
    }

    #[test]
    fn local_identity_generation_uses_unique_ec_private_keys_and_pkcs10_csrs() {
        let first =
            OpenVpnBackend::generate_identity("Laptop ../ Unsafe", Uuid::from_u128(10)).unwrap();
        let second =
            OpenVpnBackend::generate_identity("Laptop ../ Unsafe", Uuid::from_u128(11)).unwrap();

        assert_eq!(first.common_name, "laptop-----unsafe-000000000000");
        assert_ne!(first.private_key.as_str(), second.private_key.as_str());
        assert_ne!(first.csr.as_str(), second.csr.as_str());
        assert!(first.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(first.csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(!first.csr.contains(first.private_key.as_str()));
    }

    #[test]
    fn server_render_is_deterministic_modern_and_contains_no_client_private_key() {
        let (state, _, secrets) = fixture();
        let first = OpenVpnBackend.render_server(&state, &secrets).unwrap();
        let second = OpenVpnBackend.render_server(&state, &secrets).unwrap();
        assert_eq!(first, second);

        let server = first
            .iter()
            .find(|file| file.path == "vpn/server.conf")
            .unwrap();
        assert!(server.contents.contains("tls-version-min 1.3"));
        assert!(
            server
                .contents
                .contains("tls-crypt /etc/openvpn/tls-crypt.key")
        );
        assert!(server.contents.contains("data-ciphers AES-256-GCM"));
        assert!(server.contents.contains("ccd-exclusive"));
        assert!(!server.contents.contains("duplicate-cn"));
        assert!(!server.contents.contains("client-private"));
        assert!(!server.contents.contains("comp-lzo"));
        let ccd = first
            .iter()
            .find(|file| file.path == "vpn/ccd/work-laptop-000000000007")
            .unwrap();
        assert_eq!(ccd.contents, "ifconfig-push 10.88.0.2 255.255.255.0\n");
        let start = first
            .iter()
            .find(|file| file.path == "vpn/start-openvpn.sh")
            .unwrap();
        assert!(start.contents.contains("iptables -C"));
        assert!(start.contents.contains("delete_rules"));
        assert!(!start.contents.contains("killall"));
    }

    #[test]
    fn client_export_embeds_only_validated_material_and_split_route() {
        let (state, device, secrets) = fixture();
        let artifact = OpenVpnBackend
            .render_client(&state, &device, &secrets)
            .unwrap();

        assert_eq!(artifact.suggested_filename, "work-laptop.ovpn");
        let contents = artifact.contents.as_text().unwrap();
        assert!(contents.contains("proto udp"));
        assert!(contents.contains("explicit-exit-notify 1"));
        assert!(contents.contains("tls-version-min 1.3"));
        assert!(contents.contains("verify-x509-name vam-server-"));
        assert!(contents.contains("route 10.88.0.0 255.255.255.0"));
        assert!(contents.contains("<tls-crypt>"));
        assert!(!contents.contains("# generated"));
        assert!(!contents.contains("redirect-gateway"));
    }

    #[test]
    fn tcp_full_tunnel_without_tls_crypt_renders_only_selected_features() {
        let (mut state, mut device, secrets) = fixture();
        state.instance.backend_settings = BackendSettings::OpenVpn(OpenVpnSettings {
            transport: OpenVpnTransport::Tcp,
            tls_protection: OpenVpnTlsProtection::None,
            ..OpenVpnSettings::default()
        });
        state.instance.routing_mode = RoutingMode::FullTunnel;
        if let DeviceBackendData::OpenVpn(data) = &mut device.backend_data {
            data.tls_crypt_key_ref = None;
        }
        state.devices = vec![device.clone()];

        let server_files = OpenVpnBackend.render_server(&state, &secrets).unwrap();
        let server = server_files
            .iter()
            .find(|file| file.path == "vpn/server.conf")
            .unwrap();
        assert!(server.contents.contains("proto tcp-server"));
        assert!(
            server
                .contents
                .contains("push \"redirect-gateway def1 bypass-dhcp\"")
        );
        assert!(!server.contents.contains("tls-crypt "));
        assert!(!server.contents.contains("explicit-exit-notify"));

        let client = OpenVpnBackend
            .render_client(&state, &device, &secrets)
            .unwrap();
        let client_contents = client.contents.as_text().unwrap();
        assert!(client_contents.contains("proto tcp-client"));
        assert!(client_contents.contains("redirect-gateway def1 bypass-dhcp"));
        assert!(client_contents.contains("block-ipv6"));
        assert!(!client_contents.contains("<tls-crypt>"));
        assert!(!client_contents.contains("explicit-exit-notify"));
    }

    #[test]
    fn issue_revoke_and_replace_plans_are_ordered_and_secret_referenced() {
        let (state, device, _) = fixture();
        let issue = OpenVpnBackend
            .plan_credentials(&state, Some(&device), CredentialAction::Issue)
            .unwrap();
        assert!(matches!(
            issue.operations.first(),
            Some(CredentialOperation::UploadSecret { mode: 0o600, .. })
        ));
        assert!(matches!(
            issue.operations.last(),
            Some(CredentialOperation::ReadCertificateSerial { .. })
        ));

        let revoke = OpenVpnBackend
            .plan_credentials(&state, Some(&device), CredentialAction::Revoke)
            .unwrap();
        assert_eq!(
            revoke.operations,
            vec![
                CredentialOperation::RevokeOpenVpnClient {
                    common_name: "work-laptop-000000000007".into(),
                },
                CredentialOperation::RegenerateOpenVpnCrl {
                    lifetime_days: CRL_LIFETIME_DAYS,
                },
                CredentialOperation::ReloadGateway,
            ]
        );

        let replacement = OpenVpnBackend
            .plan_credentials(
                &state,
                Some(&device),
                CredentialAction::Replace {
                    previous_identity: "retired-client-01".into(),
                    previous_certificate_serial: None,
                },
            )
            .unwrap();
        let sign_index = replacement
            .operations
            .iter()
            .position(|operation| {
                matches!(operation, CredentialOperation::SignOpenVpnClient { .. })
            })
            .unwrap();
        let revoke_index = replacement
            .operations
            .iter()
            .position(|operation| {
                matches!(operation, CredentialOperation::RevokeOpenVpnClient { .. })
            })
            .unwrap();
        assert!(sign_index < revoke_index);
    }

    #[test]
    fn runtime_is_a_pinned_local_build_and_tracks_transport() {
        let udp = OpenVpnBackend
            .runtime(&BackendSettings::OpenVpn(OpenVpnSettings::default()))
            .unwrap();
        assert_eq!(
            udp.image,
            ContainerImage::Build {
                tag: OPENVPN_LOCAL_IMAGE,
                dockerfile_path: OPENVPN_DOCKERFILE_PATH,
                input_paths: &["vpn/start-openvpn.sh"],
            }
        );
        assert_eq!(
            udp.container_listeners,
            vec![ListenerPort {
                port: OPENVPN_CONTAINER_PORT,
                protocol: TransportProtocol::Udp,
            }]
        );
        assert!(OPENVPN_DOCKERFILE.contains("alpine:3.23.5@sha256:"));
        assert!(OPENVPN_DOCKERFILE.contains("openvpn=2.6.20-r0"));
        assert_eq!(udp.capabilities, vec![ContainerCapability::NetAdmin]);
        assert_eq!(udp.devices, vec![ContainerDevice::Tun]);

        let tcp_settings = OpenVpnSettings {
            transport: OpenVpnTransport::Tcp,
            ..OpenVpnSettings::default()
        };
        let tcp = OpenVpnBackend
            .runtime(&BackendSettings::OpenVpn(tcp_settings))
            .unwrap();
        assert_eq!(tcp.container_listeners[0].protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn settings_changes_do_not_classify_listener_or_tls_updates_as_reinstalls() {
        let baseline = BackendSettings::OpenVpn(OpenVpnSettings::default());
        assert_eq!(
            OpenVpnBackend.classify_settings_change(&baseline, &baseline),
            ChangeImpact::LiveUpdate
        );

        let transport = BackendSettings::OpenVpn(OpenVpnSettings {
            transport: OpenVpnTransport::Tcp,
            ..OpenVpnSettings::default()
        });
        assert_eq!(
            OpenVpnBackend.classify_settings_change(&baseline, &transport),
            ChangeImpact::ServiceRestart
        );

        let tls = BackendSettings::OpenVpn(OpenVpnSettings {
            tls_protection: OpenVpnTlsProtection::None,
            ..OpenVpnSettings::default()
        });
        assert_eq!(
            OpenVpnBackend.classify_settings_change(&baseline, &tls),
            ChangeImpact::ServiceRestart
        );

        assert_eq!(
            OpenVpnBackend.classify_settings_change(
                &baseline,
                &BackendSettings::WireGuard(vam_core::WireGuardSettings::default())
            ),
            ChangeImpact::Reinstall
        );
    }

    #[test]
    fn certificate_lifetime_has_no_825_day_ceiling_but_rejects_zero() {
        let (mut state, _, secrets) = fixture();
        let BackendSettings::OpenVpn(settings) = &mut state.instance.backend_settings else {
            panic!("fixture must use OpenVPN settings");
        };
        settings.certificate_lifetime_days = 1365;
        assert!(OpenVpnBackend.render_server(&state, &secrets).is_ok());

        let BackendSettings::OpenVpn(settings) = &mut state.instance.backend_settings else {
            unreachable!();
        };
        settings.certificate_lifetime_days = 0;
        let error = OpenVpnBackend.render_server(&state, &secrets).unwrap_err();
        assert!(error.to_string().contains("must be at least 1 day"));
    }

    #[test]
    fn unsafe_common_names_and_tls_reference_mismatches_are_rejected() {
        let (mut state, _, secrets) = fixture();
        if let DeviceBackendData::OpenVpn(data) = &mut state.devices[0].backend_data {
            data.common_name = "../escape".into();
        }
        assert!(OpenVpnBackend.render_server(&state, &secrets).is_err());

        if let DeviceBackendData::OpenVpn(data) = &mut state.devices[0].backend_data {
            data.common_name = "safe-client".into();
            data.tls_crypt_key_ref = None;
        }
        assert!(OpenVpnBackend.render_server(&state, &secrets).is_err());

        if let DeviceBackendData::OpenVpn(data) = &mut state.devices[0].backend_data {
            data.tls_crypt_key_ref = Some(SecretReference(Uuid::from_u128(6)));
        }
        state.instance.endpoint.host = "vpn.example.test\nverb 9".into();
        assert!(OpenVpnBackend.render_server(&state, &secrets).is_err());
    }
}
