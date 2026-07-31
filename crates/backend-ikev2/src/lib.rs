use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, PrivateKey,
    PrivateKeyChain,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
};
use uuid::Uuid;
use vam_backend::{
    BackendCapabilities, BackendError, BackendHealthProbe, BackendHostRequirement,
    BackendPresentation, BackendRuntimeSpec, BackendValidation, CertificateKeyAlgorithm,
    ChangeImpact, ClientAction, ClientAddressCapability, ClientArtifactKind, ClientExportFormat,
    ConfigurationField, ConfigurationSection, ContainerCapability, ContainerImage, ContainerMount,
    ContainerMountOwnership, CredentialAction, CredentialArtifact, CredentialOperation,
    CredentialPlan, DnsCapability, ListenerModel, RoutingCapability, ServerIdentityStrategy,
    StatisticsCapability, VpnBackend,
};
use vam_core::{
    BackendSettings, DEFAULT_IKEV2_PORT, DesiredState, Device, DeviceBackendData, Ikev2DeviceData,
    Ikev2Settings, ListenerPort, RoutingMode, SecretReference, TransportProtocol, VpnBackendKind,
    validate_device_addresses, validate_instance,
};
use vam_protocol::{ClientArtifact, RenderedFile};
use zeroize::Zeroizing;

pub const IKEV2_IKE_PORT: u16 = 500;
pub const IKEV2_NATT_PORT: u16 = 4_500;
pub const IKEV2_LOCAL_IMAGE: &str = "vpn-appliance-manager/ikev2:alpine3.23.5-strongswan5.9.14-r3";
pub const IKEV2_DOCKERFILE_PATH: &str = "ikev2/Dockerfile";
pub const PKCS12_KDF_ITERATIONS: u32 = 600_000;

const CA_LIFETIME_DAYS: u16 = 3_650;
const CRL_LIFETIME_DAYS: u16 = 3_650;
const CA_CERTIFICATE_PATH: &str = "ikev2/x509ca/vam-ca.pem";
const CLIENT_KEY_ALGORITHM: CertificateKeyAlgorithm = CertificateKeyAlgorithm::EcdsaP384Sha384;
const IKEV2_DOCKERFILE: &str = r#"FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
RUN apk add --no-cache \
        iptables=1.8.11-r1 \
        strongswan=5.9.14-r3 \
    && mkdir -p /run/charon
COPY start-ikev2.sh /usr/local/sbin/start-ikev2
RUN chmod 0755 /usr/local/sbin/start-ikev2
ENTRYPOINT ["/usr/local/sbin/start-ikev2"]
"#;

#[derive(Debug)]
pub struct GeneratedIkev2Identity {
    pub identity: String,
    pub private_key: Zeroizing<String>,
    pub csr: Zeroizing<String>,
    pub bundle_password: Zeroizing<String>,
}

#[derive(Debug, Default)]
pub struct Ikev2Backend;

impl Ikev2Backend {
    pub fn generate_identity(
        display_name: &str,
        device_id: Uuid,
    ) -> Result<GeneratedIkev2Identity, BackendError> {
        let identity = client_identity(display_name, device_id);
        validate_client_identity(&identity)?;

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
            .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;
        let mut params = CertificateParams::new(vec![identity.clone()])
            .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, identity.as_str());
        params.distinguished_name = distinguished_name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr = params
            .serialize_request(&key_pair)
            .and_then(|request| request.pem())
            .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;

        Ok(GeneratedIkev2Identity {
            identity,
            private_key: Zeroizing::new(key_pair.serialize_pem()),
            csr: Zeroizing::new(csr),
            bundle_password: generate_bundle_password(),
        })
    }
}

impl VpnBackend for Ikev2Backend {
    fn kind(&self) -> VpnBackendKind {
        VpnBackendKind::Ikev2
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
            short_name: "IKE",
            badge: "IKE",
            description: "Native IPsec VPN supported by major operating systems",
            routing: RoutingCapability::RoutedTunnel,
            dns: DnsCapability::ManagedPrivateDns,
            client_addresses: ClientAddressCapability::Allocated,
            statistics: StatisticsCapability::BackendSupported,
            listener_model: ListenerModel::FixedMultiple,
            client_identity_name: "certificate profile",
            client_actions: &[
                ClientAction::Revoke,
                ClientAction::ReplaceIdentity,
                ClientAction::Export,
                ClientAction::Remove,
            ],
            export_formats: &[ClientExportFormat::ProtectedPkcs12],
            configuration_sections: &[
                ConfigurationSection::General,
                ConfigurationSection::Network,
                ConfigurationSection::Protocol,
                ConfigurationSection::Dns,
                ConfigurationSection::Advanced,
            ],
            configuration_fields: &[
                ConfigurationField::Endpoint,
                ConfigurationField::AddressPool,
                ConfigurationField::RoutingMode,
                ConfigurationField::ManagedDns,
                ConfigurationField::Ikev2ServerIdentity,
                ConfigurationField::CertificateLifetime,
            ],
            host_requirements: &[
                BackendHostRequirement::Linux,
                BackendHostRequirement::SupportedArchitecture,
                BackendHostRequirement::DockerEngine,
                BackendHostRequirement::ComposeV2,
                BackendHostRequirement::DockerAccess,
            ],
            identity_replacement_warning: "Revokes the current certificate and issues a new client profile. Existing exported profiles will stop working.",
        }
    }

    fn runtime(&self, settings: &BackendSettings) -> Result<BackendRuntimeSpec, BackendError> {
        if !matches!(settings, BackendSettings::Ikev2(_)) {
            return Err(BackendError::BackendMismatch(self.kind()));
        }
        Ok(BackendRuntimeSpec {
            image: ContainerImage::Build {
                tag: IKEV2_LOCAL_IMAGE,
                dockerfile_path: IKEV2_DOCKERFILE_PATH,
                input_paths: &["ikev2/start-ikev2.sh"],
            },
            container_listeners: ikev2_listeners(),
            capabilities: vec![ContainerCapability::NetAdmin],
            devices: Vec::new(),
            mounts: vec![ContainerMount {
                host_path: "ikev2",
                container_path: "/etc/swanctl",
                read_only: false,
                ownership: ContainerMountOwnership::HostUser,
            }],
            environment: Vec::new(),
            entrypoint: Vec::new(),
            command: Vec::new(),
            sysctls: vec![("net.ipv4.ip_forward", "1")],
            identity: ServerIdentityStrategy::CertificateAuthority {
                persistent_paths: &[
                    "ikev2/private",
                    "ikev2/x509",
                    "ikev2/x509ca",
                    "ikev2/x509crl",
                    "ikev2/requests",
                    "ikev2/issued",
                    "ikev2/revoked",
                ],
            },
            validation: BackendValidation::Ikev2,
            health: BackendHealthProbe::Ikev2,
        })
    }

    fn listeners(&self, settings: &BackendSettings, _endpoint_port: u16) -> Vec<ListenerPort> {
        if matches!(settings, BackendSettings::Ikev2(_)) {
            ikev2_listeners()
        } else {
            Vec::new()
        }
    }

    fn validate(&self, state: &DesiredState) -> Result<(), BackendError> {
        if state.instance.backend != self.kind() {
            return Err(BackendError::BackendMismatch(self.kind()));
        }
        let BackendSettings::Ikev2(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        validate_instance(&state.instance)?;
        validate_device_addresses(&state.instance, &state.devices)?;
        if state.instance.endpoint.port != DEFAULT_IKEV2_PORT {
            return invalid(
                "endpoint.port",
                "IKEv2 uses fixed UDP listeners 500 and 4500",
            );
        }
        validate_server_identity(&settings.server_identity)?;
        validate_certificate_lifetime(settings.certificate_lifetime_days)?;

        let mut identities = HashSet::new();
        for device in state
            .devices
            .iter()
            .filter(|device| device.deleted_at.is_none())
        {
            let DeviceBackendData::Ikev2(data) = &device.backend_data else {
                return Err(BackendError::BackendMismatch(self.kind()));
            };
            validate_client_identity(&data.identity)?;
            validate_device_material(data)?;
            if let Some(serial) = &data.certificate_serial {
                validate_certificate_serial(serial)?;
            }
            if !identities.insert(data.identity.as_str()) {
                return invalid("identity", "active IKEv2 identities must be unique");
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
        let data = ikev2_device(device, self.kind())?;
        Ok(vec![
            required_reference(data.private_key_ref.as_ref(), self.kind())?.clone(),
            required_reference(data.certificate_ref.as_ref(), self.kind())?.clone(),
            required_reference(data.ca_certificate_ref.as_ref(), self.kind())?.clone(),
            data.bundle_password_ref.clone(),
        ])
    }

    fn render_server(
        &self,
        state: &DesiredState,
        _secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, BackendError> {
        self.validate(state)?;
        let mut files = vec![
            RenderedFile {
                path: IKEV2_DOCKERFILE_PATH.into(),
                contents: IKEV2_DOCKERFILE.into(),
                mode: 0o644,
                sensitive: false,
            },
            RenderedFile {
                path: "ikev2/swanctl.conf".into(),
                contents: render_swanctl_config(state),
                mode: 0o600,
                sensitive: false,
            },
            RenderedFile {
                path: "ikev2/start-ikev2.sh".into(),
                contents: render_start_script(state),
                mode: 0o700,
                sensitive: false,
            },
        ];
        for directory in [
            "private", "x509", "x509ca", "x509crl", "requests", "issued", "revoked",
        ] {
            files.push(RenderedFile {
                path: format!("ikev2/{directory}/.keep"),
                contents: String::new(),
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
        if !state
            .devices
            .iter()
            .any(|candidate| candidate.id == device.id && candidate.enabled)
        {
            return invalid("device", "IKEv2 export requires an enabled desired device");
        }
        let data = ikev2_device(device, self.kind())?;
        let private_key_ref = required_reference(data.private_key_ref.as_ref(), self.kind())?;
        let certificate_ref = required_reference(data.certificate_ref.as_ref(), self.kind())?;
        let ca_certificate_ref = required_reference(data.ca_certificate_ref.as_ref(), self.kind())?;
        let private_key = required_secret(secrets, private_key_ref, self.kind())?;
        let certificate = required_secret(secrets, certificate_ref, self.kind())?;
        let ca_certificate = required_secret(secrets, ca_certificate_ref, self.kind())?;
        let password = required_secret(secrets, &data.bundle_password_ref, self.kind())?;
        validate_bundle_password(password.as_str())?;

        let bundle = build_pkcs12(
            &data.identity,
            device.id,
            private_key.as_str(),
            certificate.as_str(),
            ca_certificate.as_str(),
            password.as_str(),
        )?;
        Ok(ClientArtifact::binary(
            format!("{}.p12", slug(&device.display_name)),
            bundle,
            state
                .instance
                .network
                .ipv6_subnet
                .is_none()
                .then(|| "IPv6 is not routed by this IKEv2 instance.".into()),
        ))
    }

    fn client_artifact_kind(&self) -> ClientArtifactKind {
        ClientArtifactKind::ProtectedPkcs12
    }

    fn plan_credentials(
        &self,
        state: &DesiredState,
        device: Option<&Device>,
        action: CredentialAction,
    ) -> Result<CredentialPlan, BackendError> {
        self.validate(state)?;
        let BackendSettings::Ikev2(settings) = &state.instance.backend_settings else {
            return Err(BackendError::BackendMismatch(self.kind()));
        };
        let operations = match action {
            CredentialAction::InitializeAuthority => {
                vec![CredentialOperation::InitializeIkev2Authority {
                    ca_common_name: ca_common_name(state.instance.id),
                    server_identity: settings.server_identity.clone(),
                    key_algorithm: CLIENT_KEY_ALGORITHM,
                    ca_lifetime_days: CA_LIFETIME_DAYS,
                    certificate_lifetime_days: settings.certificate_lifetime_days,
                    crl_lifetime_days: CRL_LIFETIME_DAYS,
                }]
            }
            CredentialAction::Issue => {
                let device = device.ok_or(BackendError::MissingCredentialDevice(self.kind()))?;
                let data = ikev2_device(device, self.kind())?;
                issue_operations(settings, data)?
            }
            CredentialAction::Revoke => {
                let device = device.ok_or(BackendError::MissingCredentialDevice(self.kind()))?;
                let data = ikev2_device(device, self.kind())?;
                revoke_operations(device, data)?
            }
            CredentialAction::Replace {
                previous_identity,
                previous_certificate_serial,
            } => {
                validate_client_identity(&previous_identity)?;
                let previous_certificate_serial =
                    previous_certificate_serial.ok_or_else(|| BackendError::InvalidSetting {
                        backend: self.kind(),
                        field: "previous_certificate_serial",
                        message: "IKEv2 replacement requires the previous certificate serial"
                            .into(),
                    })?;
                validate_certificate_serial(&previous_certificate_serial)?;
                let device = device.ok_or(BackendError::MissingCredentialDevice(self.kind()))?;
                let data = ikev2_device(device, self.kind())?;
                let mut operations = issue_operations(settings, data)?;
                operations.extend([
                    CredentialOperation::RevokeIkev2Client {
                        identity: previous_identity.clone(),
                        certificate_serial: previous_certificate_serial,
                        crl_lifetime_days: CRL_LIFETIME_DAYS,
                    },
                    CredentialOperation::ReloadGateway,
                    CredentialOperation::TerminateIkev2Connection {
                        connection_name: connection_name(device),
                    },
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
            (BackendSettings::Ikev2(previous), BackendSettings::Ikev2(next))
                if previous == next =>
            {
                ChangeImpact::LiveUpdate
            }
            (BackendSettings::Ikev2(previous), BackendSettings::Ikev2(next))
                if previous.server_identity != next.server_identity =>
            {
                ChangeImpact::Reinstall
            }
            (BackendSettings::Ikev2(_), BackendSettings::Ikev2(_)) => ChangeImpact::LiveUpdate,
            _ => ChangeImpact::Reinstall,
        }
    }
}

fn ikev2_listeners() -> Vec<ListenerPort> {
    vec![
        ListenerPort {
            port: IKEV2_IKE_PORT,
            protocol: TransportProtocol::Udp,
        },
        ListenerPort {
            port: IKEV2_NATT_PORT,
            protocol: TransportProtocol::Udp,
        },
    ]
}

fn validate_certificate_lifetime(lifetime_days: u16) -> Result<(), BackendError> {
    if !(30..=825).contains(&lifetime_days) {
        return invalid(
            "certificate_lifetime_days",
            "must be between 30 and 825 days",
        );
    }
    Ok(())
}

fn validate_server_identity(identity: &str) -> Result<(), BackendError> {
    if identity.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    validate_dns_name(identity, "server_identity")
}

fn validate_dns_name(value: &str, field: &'static str) -> Result<(), BackendError> {
    if value.is_empty() || value.len() > 253 || value.trim_end_matches('.') != value {
        return invalid(field, "must be a non-empty DNS name without a trailing dot");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return invalid(field, "contains an invalid DNS label");
        }
    }
    Ok(())
}

fn validate_client_identity(identity: &str) -> Result<(), BackendError> {
    if identity.is_empty()
        || identity.len() > 63
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !identity
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !identity
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return invalid(
            "identity",
            "must be 1-63 lowercase letters, digits, or hyphens and start/end alphanumeric",
        );
    }
    Ok(())
}

fn validate_certificate_serial(serial: &str) -> Result<(), BackendError> {
    if serial.is_empty()
        || serial.len() > 64
        || !serial.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return invalid("certificate_serial", "must be 1-64 hexadecimal characters");
    }
    Ok(())
}

fn validate_device_material(data: &Ikev2DeviceData) -> Result<(), BackendError> {
    for reference in [
        data.private_key_ref.as_ref(),
        data.csr_ref.as_ref(),
        data.certificate_ref.as_ref(),
        data.ca_certificate_ref.as_ref(),
        Some(&data.bundle_password_ref),
    ] {
        let reference = required_reference(reference, VpnBackendKind::Ikev2)?;
        if reference.0.is_nil() {
            return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2));
        }
    }
    Ok(())
}

fn validate_bundle_password(password: &str) -> Result<(), BackendError> {
    if !(20..=128).contains(&password.len())
        || !password
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
    {
        return invalid(
            "bundle_password",
            "must be 20-128 printable non-whitespace ASCII characters",
        );
    }
    Ok(())
}

fn invalid<T>(field: &'static str, message: &str) -> Result<T, BackendError> {
    Err(BackendError::InvalidSetting {
        backend: VpnBackendKind::Ikev2,
        field,
        message: message.into(),
    })
}

fn required_reference(
    reference: Option<&SecretReference>,
    backend: VpnBackendKind,
) -> Result<&SecretReference, BackendError> {
    reference.ok_or(BackendError::InvalidKeyMaterial(backend))
}

fn required_secret<'a>(
    secrets: &'a HashMap<SecretReference, Zeroizing<String>>,
    reference: &SecretReference,
    backend: VpnBackendKind,
) -> Result<&'a Zeroizing<String>, BackendError> {
    secrets
        .get(reference)
        .ok_or_else(|| BackendError::MissingSecret {
            backend,
            reference: reference.clone(),
        })
}

fn ikev2_device(
    device: &Device,
    backend: VpnBackendKind,
) -> Result<&Ikev2DeviceData, BackendError> {
    let DeviceBackendData::Ikev2(data) = &device.backend_data else {
        return Err(BackendError::BackendMismatch(backend));
    };
    Ok(data)
}

fn issue_operations(
    settings: &Ikev2Settings,
    data: &Ikev2DeviceData,
) -> Result<Vec<CredentialOperation>, BackendError> {
    let csr_ref = required_reference(data.csr_ref.as_ref(), VpnBackendKind::Ikev2)?;
    let certificate_ref = required_reference(data.certificate_ref.as_ref(), VpnBackendKind::Ikev2)?;
    let ca_certificate_ref =
        required_reference(data.ca_certificate_ref.as_ref(), VpnBackendKind::Ikev2)?;
    let request_path = format!("ikev2/requests/{}.pem", data.identity);
    let certificate_path = format!("ikev2/issued/{}.pem", data.identity);
    Ok(vec![
        CredentialOperation::UploadSecret {
            reference: csr_ref.clone(),
            relative_path: request_path.clone(),
            mode: 0o600,
        },
        CredentialOperation::SignIkev2Client {
            identity: data.identity.clone(),
            relative_path: request_path,
            certificate_lifetime_days: settings.certificate_lifetime_days,
            key_algorithm: CLIENT_KEY_ALGORITHM,
        },
        CredentialOperation::DownloadToSecret {
            relative_path: certificate_path.clone(),
            reference: certificate_ref.clone(),
            artifact: CredentialArtifact::ClientCertificate,
        },
        CredentialOperation::DownloadToSecret {
            relative_path: CA_CERTIFICATE_PATH.into(),
            reference: ca_certificate_ref.clone(),
            artifact: CredentialArtifact::CaCertificate,
        },
        CredentialOperation::ReadCertificateSerial {
            relative_path: certificate_path,
        },
    ])
}

fn revoke_operations(
    device: &Device,
    data: &Ikev2DeviceData,
) -> Result<Vec<CredentialOperation>, BackendError> {
    let serial = data
        .certificate_serial
        .as_ref()
        .ok_or_else(|| BackendError::InvalidSetting {
            backend: VpnBackendKind::Ikev2,
            field: "certificate_serial",
            message: "IKEv2 revocation requires an issued certificate serial".into(),
        })?;
    validate_certificate_serial(serial)?;
    Ok(vec![
        CredentialOperation::RevokeIkev2Client {
            identity: data.identity.clone(),
            certificate_serial: serial.clone(),
            crl_lifetime_days: CRL_LIFETIME_DAYS,
        },
        CredentialOperation::ReloadGateway,
        CredentialOperation::TerminateIkev2Connection {
            connection_name: connection_name(device),
        },
    ])
}

fn connection_name(device: &Device) -> String {
    format!("client-{}", device.id.simple())
}

fn render_swanctl_config(state: &DesiredState) -> String {
    let BackendSettings::Ikev2(settings) = &state.instance.backend_settings else {
        unreachable!("validation rejects mismatched IKEv2 settings")
    };
    let local_ts = match state.instance.routing_mode {
        RoutingMode::FullTunnel => "0.0.0.0/0".to_owned(),
        RoutingMode::SplitTunnel => state.instance.network.ipv4_subnet.to_string(),
    };
    let mut devices: Vec<_> = state
        .devices
        .iter()
        .filter(|device| device.enabled && device.deleted_at.is_none())
        .collect();
    devices.sort_by(|left, right| {
        let DeviceBackendData::Ikev2(left) = &left.backend_data else {
            unreachable!("validation rejects mismatched IKEv2 devices")
        };
        let DeviceBackendData::Ikev2(right) = &right.backend_data else {
            unreachable!("validation rejects mismatched IKEv2 devices")
        };
        left.identity.cmp(&right.identity)
    });

    let mut output = String::from("connections {\n");
    for device in &devices {
        let DeviceBackendData::Ikev2(data) = &device.backend_data else {
            unreachable!("validation rejects mismatched IKEv2 devices")
        };
        let suffix = device.id.simple();
        writeln!(
            output,
            r"  client-{suffix} {{
    version = 2
    local_addrs = 0.0.0.0
    pools = pool-{suffix}
    proposals = aes256gcm16-prfsha384-ecp384,aes256-sha384-prfsha384-ecp384
    send_cert = always
    send_certreq = yes
    fragmentation = yes
    mobike = yes
    encap = yes
    dpd_delay = 30s
    reauth_time = 0s
    local {{
      auth = ecdsa-sha384
      certs = vam-server.pem
      id = {}
    }}
    remote {{
      auth = ecdsa-sha384
      id = {}
      cacerts = vam-ca.pem
      revocation = strict
    }}
    children {{
      protected {{
        mode = tunnel
        local_ts = {local_ts}
        esp_proposals = aes256gcm16-ecp384,aes256-sha384-ecp384
        start_action = none
        close_action = clear
        dpd_action = clear
        rekey_time = 1h
      }}
    }}
  }}",
            settings.server_identity, data.identity
        )
        .expect("writing to a String cannot fail");
    }
    output.push_str("}\n\npools {\n");
    for device in devices {
        let address = device
            .ipv4_address
            .expect("validation requires an IKEv2 device address");
        let suffix = device.id.simple();
        writeln!(
            output,
            "  pool-{suffix} {{\n    addrs = {address}/32\n    dns = {}\n  }}",
            state.instance.network.gateway_ipv4
        )
        .expect("writing to a String cannot fail");
    }
    output.push_str("}\n");
    output
}

fn render_start_script(state: &DesiredState) -> String {
    let subnet = state.instance.network.ipv4_subnet;
    format!(
        r#"#!/bin/sh
set -eu

add_rules() {{
    iptables -C FORWARD -s {subnet} -m policy --dir in --pol ipsec -j ACCEPT 2>/dev/null || iptables -A FORWARD -s {subnet} -m policy --dir in --pol ipsec -j ACCEPT
    iptables -C FORWARD -d {subnet} -m policy --dir out --pol ipsec -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -d {subnet} -m policy --dir out --pol ipsec -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -C POSTROUTING -s {subnet} -o eth0 -m policy --dir out --pol none -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s {subnet} -o eth0 -m policy --dir out --pol none -j MASQUERADE
}}

delete_rules() {{
    iptables -D FORWARD -s {subnet} -m policy --dir in --pol ipsec -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d {subnet} -m policy --dir out --pol ipsec -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s {subnet} -o eth0 -m policy --dir out --pol none -j MASQUERADE 2>/dev/null || true
}}

daemon_pid=
shutdown() {{
    if [ -n "$daemon_pid" ]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    delete_rules
    exit 0
}}
trap shutdown INT TERM HUP

add_rules
rm -f /var/run/charon.vici
/usr/lib/strongswan/charon &
daemon_pid=$!

attempt=0
while [ "$attempt" -lt 100 ]; do
    if [ -S /var/run/charon.vici ]; then
        break
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        wait "$daemon_pid"
        exit $?
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

if [ ! -S /var/run/charon.vici ]; then
    echo "charon VICI socket did not become ready" >&2
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    delete_rules
    exit 1
fi

if ! swanctl --load-all --noprompt; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    delete_rules
    exit 1
fi

if wait "$daemon_pid"; then
    status=0
else
    status=$?
fi
daemon_pid=
delete_rules
exit "$status"
"#
    )
}

fn build_pkcs12(
    identity: &str,
    device_id: Uuid,
    private_key_pem: &str,
    certificate_pem: &str,
    ca_certificate_pem: &str,
    password: &str,
) -> Result<Vec<u8>, BackendError> {
    let private_key_der = decode_pem(private_key_pem, "PRIVATE KEY")?;
    let certificate_der = decode_pem(certificate_pem, "CERTIFICATE")?;
    let ca_certificate_der = decode_pem(ca_certificate_pem, "CERTIFICATE")?;
    let private_key = PrivateKey::from_der(private_key_der.as_slice())
        .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;
    let certificate = Certificate::from_der(certificate_der.as_slice())
        .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;
    let ca_certificate = Certificate::from_der(ca_certificate_der.as_slice())
        .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;
    let chain = PrivateKeyChain::new(
        device_id.as_bytes().as_slice(),
        private_key,
        [certificate, ca_certificate],
    );
    let mut keystore = KeyStore::new();
    keystore.add_entry(identity, KeyStoreEntry::PrivateKeyChain(chain));
    keystore
        .writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .encryption_iterations(PKCS12_KDF_ITERATIONS)
        .mac_algorithm(MacAlgorithm::HmacSha256)
        .mac_iterations(PKCS12_KDF_ITERATIONS)
        .write()
        .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))
}

fn decode_pem(value: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let trimmed = value.trim();
    let body = trimmed
        .strip_prefix(&begin)
        .and_then(|value| value.strip_suffix(&end))
        .ok_or(BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))?;
    let encoded = Zeroizing::new(
        body.chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>(),
    );
    if encoded.is_empty()
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2));
    }
    STANDARD
        .decode(encoded.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| BackendError::InvalidKeyMaterial(VpnBackendKind::Ikev2))
}

fn ca_common_name(instance_id: Uuid) -> String {
    format!("vam-ikev2-ca-{}", &instance_id.simple().to_string()[..12])
}

fn client_identity(display_name: &str, device_id: Uuid) -> String {
    let mut base = String::new();
    let mut last_was_hyphen = false;
    for character in display_name.chars() {
        let next = if character.is_ascii_alphanumeric() {
            Some(character.to_ascii_lowercase())
        } else {
            Some('-')
        };
        if let Some(next) = next {
            if next == '-' {
                if base.is_empty() || last_was_hyphen {
                    continue;
                }
                last_was_hyphen = true;
            } else {
                last_was_hyphen = false;
            }
            base.push(next);
            if base.len() == 42 {
                break;
            }
        }
    }
    let base = base.trim_matches('-');
    let base = if base.is_empty() { "device" } else { base };
    format!("{base}-{}", &device_id.simple().to_string()[..12])
}

fn generate_bundle_password() -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ))
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
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "ikev2-client".into()
    } else {
        slug.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
    use rcgen::{BasicConstraints, IsCa, Issuer};
    use vam_core::{DnsConfig, EndpointConfig, NetworkConfig, VpnInstance, first_usable};

    fn fixture() -> (
        DesiredState,
        Device,
        HashMap<SecretReference, Zeroizing<String>>,
        String,
    ) {
        let instance_id = Uuid::from_u128(1);
        let device_id = Uuid::from_u128(2);
        let generated = Ikev2Backend::generate_identity("Work Laptop", device_id).unwrap();
        let private_key_ref = SecretReference(Uuid::from_u128(3));
        let csr_ref = SecretReference(Uuid::from_u128(4));
        let certificate_ref = SecretReference(Uuid::from_u128(5));
        let ca_certificate_ref = SecretReference(Uuid::from_u128(6));
        let password_ref = SecretReference(Uuid::from_u128(7));

        let client_key = KeyPair::from_pem(generated.private_key.as_str()).unwrap();
        let mut client_params = CertificateParams::new(vec![generated.identity.clone()]).unwrap();
        let mut client_dn = DistinguishedName::new();
        client_dn.push(DnType::CommonName, generated.identity.as_str());
        client_params.distinguished_name = client_dn;
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "Test IKEv2 CA");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap().pem();
        let ca_issuer = Issuer::new(ca_params, ca_key);
        let client_certificate = client_params
            .signed_by(&client_key, &ca_issuer)
            .unwrap()
            .pem();

        let device = Device {
            id: device_id,
            instance_id,
            user_id: None,
            display_name: "Work Laptop".into(),
            ipv4_address: Some("10.89.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: Some("work-laptop.vpn.internal".into()),
            enabled: true,
            backend_data: DeviceBackendData::Ikev2(Ikev2DeviceData {
                identity: generated.identity.clone(),
                private_key_ref: Some(private_key_ref.clone()),
                csr_ref: Some(csr_ref.clone()),
                certificate_ref: Some(certificate_ref.clone()),
                ca_certificate_ref: Some(ca_certificate_ref.clone()),
                bundle_password_ref: password_ref.clone(),
                certificate_serial: Some("A1B2C3".into()),
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        let subnet = "10.89.0.0/24".parse().unwrap();
        let state = DesiredState {
            instance: VpnInstance {
                id: instance_id,
                host_id: Uuid::from_u128(8),
                display_name: "IKEv2".into(),
                backend: VpnBackendKind::Ikev2,
                backend_settings: BackendSettings::Ikev2(Ikev2Settings {
                    server_identity: "vpn.example.test".into(),
                    certificate_lifetime_days: 825,
                }),
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: DEFAULT_IKEV2_PORT,
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
        let password = generated.bundle_password.to_string();
        let secrets = HashMap::from([
            (private_key_ref, generated.private_key),
            (csr_ref, generated.csr),
            (certificate_ref, Zeroizing::new(client_certificate)),
            (ca_certificate_ref, Zeroizing::new(ca_certificate)),
            (
                password_ref,
                Zeroizing::new(generated.bundle_password.to_string()),
            ),
        ]);
        (state, device, secrets, password)
    }

    #[test]
    fn local_identity_generation_uses_unique_p384_material_and_passwords() {
        let first =
            Ikev2Backend::generate_identity("Laptop ../ Unsafe", Uuid::from_u128(10)).unwrap();
        let second =
            Ikev2Backend::generate_identity("Laptop ../ Unsafe", Uuid::from_u128(11)).unwrap();

        assert_eq!(first.identity, "laptop-unsafe-000000000000");
        assert_ne!(first.private_key.as_str(), second.private_key.as_str());
        assert_ne!(first.csr.as_str(), second.csr.as_str());
        assert_ne!(
            first.bundle_password.as_str(),
            second.bundle_password.as_str()
        );
        assert_eq!(first.bundle_password.len(), 64);
        assert!(first.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(first.csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    }

    #[test]
    fn runtime_is_pinned_fixed_port_and_least_privilege() {
        let runtime = Ikev2Backend
            .runtime(&BackendSettings::Ikev2(Ikev2Settings::default()))
            .unwrap();
        assert_eq!(
            runtime.image,
            ContainerImage::Build {
                tag: IKEV2_LOCAL_IMAGE,
                dockerfile_path: IKEV2_DOCKERFILE_PATH,
                input_paths: &["ikev2/start-ikev2.sh"],
            }
        );
        assert_eq!(runtime.container_listeners, ikev2_listeners());
        assert_eq!(runtime.capabilities, vec![ContainerCapability::NetAdmin]);
        assert!(runtime.devices.is_empty());
        assert!(IKEV2_DOCKERFILE.contains("alpine:3.23.5@sha256:"));
        assert!(IKEV2_DOCKERFILE.contains("strongswan=5.9.14-r3"));
        assert!(!IKEV2_DOCKERFILE.contains("latest"));
    }

    #[test]
    fn server_render_is_deterministic_modern_and_assigns_fixed_pool() {
        let (state, _, secrets, _) = fixture();
        let first = Ikev2Backend.render_server(&state, &secrets).unwrap();
        let second = Ikev2Backend.render_server(&state, &secrets).unwrap();
        assert_eq!(first, second);
        let config = first
            .iter()
            .find(|file| file.path == "ikev2/swanctl.conf")
            .unwrap();
        assert!(config.contents.contains("version = 2"));
        assert!(config.contents.contains("auth = ecdsa-sha384"));
        assert!(config.contents.contains("aes256gcm16-prfsha384-ecp384"));
        assert!(config.contents.contains("revocation = strict"));
        assert!(config.contents.contains("addrs = 10.89.0.2/32"));
        assert!(config.contents.contains("dns = 10.89.0.1"));
        assert!(config.contents.contains("local_ts = 10.89.0.0/24"));
        for forbidden in ["sha1", "3des", "xauth", "l2tp", "auth = psk", "version = 1"] {
            assert!(!config.contents.to_ascii_lowercase().contains(forbidden));
        }
        let start = first
            .iter()
            .find(|file| file.path == "ikev2/start-ikev2.sh")
            .unwrap();
        assert!(start.contents.contains("iptables -C"));
        assert!(start.contents.contains("--pol ipsec"));
        assert!(start.contents.contains("delete_rules"));
        assert!(start.contents.contains("swanctl --load-all --noprompt"));
        let stale_socket_cleanup = start
            .contents
            .find("rm -f /var/run/charon.vici")
            .expect("the restart path must remove a stale VICI socket");
        let daemon_start = start
            .contents
            .find("/usr/lib/strongswan/charon &")
            .expect("the startup script must launch charon");
        assert!(stale_socket_cleanup < daemon_start);
        assert!(!start.contents.contains("iptables -F"));
        assert!(!start.contents.contains("--privileged"));
    }

    #[test]
    fn full_tunnel_changes_only_the_traffic_selector() {
        let (mut state, _, secrets, _) = fixture();
        state.instance.routing_mode = RoutingMode::FullTunnel;
        let files = Ikev2Backend.render_server(&state, &secrets).unwrap();
        let config = files
            .iter()
            .find(|file| file.path == "ikev2/swanctl.conf")
            .unwrap();
        assert!(config.contents.contains("local_ts = 0.0.0.0/0"));
        assert!(!config.contents.contains("local_ts = 10.89.0.0/24"));
    }

    #[test]
    fn protected_pkcs12_export_is_binary_and_rejects_wrong_password() {
        let (state, device, secrets, password) = fixture();
        let artifact = Ikev2Backend
            .render_client(&state, &device, &secrets)
            .unwrap();
        assert_eq!(artifact.suggested_filename, "work-laptop.p12");
        assert!(artifact.contents.is_binary());
        assert!(artifact.contents.as_text().is_none());
        let store = KeyStore::from_pkcs12(
            artifact.contents.as_bytes(),
            &password,
            Pkcs12ImportPolicy::Strict,
        )
        .unwrap();
        let (alias, chain) = store.private_key_chain().unwrap();
        assert_eq!(alias, "work-laptop-000000000000");
        assert_eq!(chain.certs().len(), 2);
        assert!(
            KeyStore::from_pkcs12(
                artifact.contents.as_bytes(),
                "definitely-the-wrong-password",
                Pkcs12ImportPolicy::Strict,
            )
            .is_err()
        );
    }

    #[test]
    fn issue_revoke_and_replace_plans_are_ordered_and_terminate_old_sas() {
        let (state, device, _, _) = fixture();
        let issue = Ikev2Backend
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

        let revoke = Ikev2Backend
            .plan_credentials(&state, Some(&device), CredentialAction::Revoke)
            .unwrap();
        assert!(matches!(
            revoke.operations.as_slice(),
            [
                CredentialOperation::RevokeIkev2Client { .. },
                CredentialOperation::ReloadGateway,
                CredentialOperation::TerminateIkev2Connection { .. }
            ]
        ));

        let replacement = Ikev2Backend
            .plan_credentials(
                &state,
                Some(&device),
                CredentialAction::Replace {
                    previous_identity: "retired-client-01".into(),
                    previous_certificate_serial: Some("DEADBEEF".into()),
                },
            )
            .unwrap();
        let sign_index = replacement
            .operations
            .iter()
            .position(|operation| matches!(operation, CredentialOperation::SignIkev2Client { .. }))
            .unwrap();
        let revoke_index = replacement
            .operations
            .iter()
            .position(|operation| {
                matches!(operation, CredentialOperation::RevokeIkev2Client { .. })
            })
            .unwrap();
        assert!(sign_index < revoke_index);
        assert!(matches!(
            replacement.operations.last(),
            Some(CredentialOperation::TerminateIkev2Connection { connection_name })
                if connection_name.starts_with("client-")
        ));
    }

    #[test]
    fn unsafe_identity_missing_material_and_custom_port_are_rejected() {
        let (mut state, _, secrets, _) = fixture();
        if let DeviceBackendData::Ikev2(data) = &mut state.devices[0].backend_data {
            data.identity = "../escape".into();
        }
        assert!(Ikev2Backend.render_server(&state, &secrets).is_err());

        if let DeviceBackendData::Ikev2(data) = &mut state.devices[0].backend_data {
            data.identity = "safe-client".into();
            data.private_key_ref = None;
        }
        assert!(Ikev2Backend.render_server(&state, &secrets).is_err());

        if let DeviceBackendData::Ikev2(data) = &mut state.devices[0].backend_data {
            data.private_key_ref = Some(SecretReference(Uuid::from_u128(3)));
        }
        state.instance.endpoint.port = 5_000;
        assert!(Ikev2Backend.render_server(&state, &secrets).is_err());
    }

    #[test]
    fn server_identity_rotation_is_explicitly_reinstall_class() {
        let baseline = BackendSettings::Ikev2(Ikev2Settings {
            server_identity: "vpn.example.test".into(),
            certificate_lifetime_days: 825,
        });
        let lifetime = BackendSettings::Ikev2(Ikev2Settings {
            server_identity: "vpn.example.test".into(),
            certificate_lifetime_days: 365,
        });
        assert_eq!(
            Ikev2Backend.classify_settings_change(&baseline, &lifetime),
            ChangeImpact::LiveUpdate
        );
        let identity = BackendSettings::Ikev2(Ikev2Settings {
            server_identity: "new.example.test".into(),
            certificate_lifetime_days: 825,
        });
        assert_eq!(
            Ikev2Backend.classify_settings_change(&baseline, &identity),
            ChangeImpact::Reinstall
        );
    }
}
