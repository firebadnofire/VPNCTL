use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_authority::manifest::{
    Compatibility, Configuration, Discovery, Manifest, Operation, Reply, Request, SaveRequest,
};
use vam_authority_client::AuthoritySshSession;

use super::{
    AppError, ApplicationService, CreateInstanceInput, VpnBackendKind, storage_error,
    validation_error,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerIdentity {
    pub appliance_id: Uuid,
    pub machine_fingerprint: String,
    pub ssh_public_key: String,
    /// Negotiated helper features; never used as an appliance trust anchor.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteInventory {
    pub host_id: Uuid,
    pub identity: ServerIdentity,
    pub synchronized_at: DateTime<Utc>,
    pub cached: bool,
    pub discovery: Discovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSaveInput {
    pub host_id: Uuid,
    pub expected_revision: u64,
    pub request_id: Uuid,
    pub configuration: Configuration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDraft {
    pub host_id: Uuid,
    pub base_revision: u64,
    pub configuration: Configuration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAvailability {
    pub peer_id: Uuid,
    pub complete_export_available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRestorePreview {
    pub backup_name: String,
    pub expected_state_hash: String,
    pub identity_impact: String,
    pub desired_revision: u64,
    pub deployed_revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCandidate {
    pub instance_id: Uuid,
    pub host_id: Uuid,
    pub display_name: String,
    pub backend: VpnBackendKind,
    pub supported: bool,
    pub status: String,
}

fn identity_key(host_id: Uuid) -> String {
    format!("remote_identity:{host_id}")
}
fn cache_key(host_id: Uuid) -> String {
    format!("remote_inventory_cache:{host_id}")
}

#[allow(clippy::result_large_err)]
pub fn validate_remote_configuration(configuration: &Configuration) -> Result<(), AppError> {
    use vam_backend::VpnBackend;
    configuration
        .validate(configuration.instance.host_id)
        .map_err(|error| validation_error(&error.to_string()))?;
    let state = configuration.runtime_state();
    let result = match state.instance.backend {
        VpnBackendKind::WireGuard => super::WireGuardBackend.validate(&state),
        VpnBackendKind::AmneziaWg => super::AmneziaWgBackend.validate(&state),
        VpnBackendKind::OpenVpn => super::OpenVpnBackend.validate(&state),
        VpnBackendKind::Ikev2 => super::Ikev2Backend.validate(&state),
        VpnBackendKind::Xray => {
            return Err(validation_error(
                "Unsupported backend; preserve legacy data for recovery.",
            ));
        }
    };
    result.map_err(super::backend_error)
}
pub(super) fn migration_key(instance_id: Uuid) -> String {
    format!("legacy_resolution:{instance_id}")
}

impl ApplicationService {
    pub async fn list_remote_backups(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<Vec<vam_protocol::BackupInfo>, AppError> {
        match self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::ListBackups { instance_id },
            )
            .await?
        {
            Reply::Backups(backups) => Ok(backups),
            _ => Err(validation_error("Unexpected backup inventory response.")),
        }
    }

    pub async fn preview_remote_restore(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        expected_revision: u64,
        backup_name: String,
    ) -> Result<RemoteRestorePreview, AppError> {
        match self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::PreviewRestore {
                    instance_id,
                    expected_revision,
                    backup_name,
                },
            )
            .await?
        {
            Reply::RestorePreview {
                backup_name,
                expected_state_hash,
                identity_impact,
                desired_revision,
                deployed_revision,
            } => Ok(RemoteRestorePreview {
                backup_name,
                expected_state_hash,
                identity_impact,
                desired_revision,
                deployed_revision,
            }),
            _ => Err(validation_error("Unexpected restore preview response.")),
        }
    }

    pub async fn restore_remote_deployment(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        preview: RemoteRestorePreview,
        confirmed: bool,
    ) -> Result<vam_protocol::InstanceHealth, AppError> {
        match self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::RestoreDeployment {
                    instance_id,
                    expected_revision: preview.desired_revision,
                    backup_name: preview.backup_name,
                    expected_state_hash: preview.expected_state_hash,
                    confirmed,
                },
            )
            .await?
        {
            Reply::Health(health) => Ok(health),
            _ => Err(validation_error("Unexpected restore result.")),
        }
    }

    pub async fn set_remote_running(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        expected_revision: u64,
        running: bool,
    ) -> Result<vam_protocol::InstanceHealth, AppError> {
        let operation = if running {
            Operation::StartInstance {
                instance_id,
                expected_revision,
            }
        } else {
            Operation::StopInstance {
                instance_id,
                expected_revision,
            }
        };
        match self
            .remote_operation(host_id, Uuid::new_v4(), operation)
            .await?
        {
            Reply::Health(health) => Ok(health),
            _ => Err(validation_error("Unexpected runtime state response.")),
        }
    }
    pub async fn save_remote_draft(&self, draft: RemoteDraft) -> Result<(), AppError> {
        let _guard = self.cleanup_guard.read().await;
        self.storage
            .set_setting(
                &format!(
                    "remote_draft:{}:{}",
                    draft.host_id, draft.configuration.instance.id
                ),
                &Some(draft),
            )
            .await
            .map_err(storage_error)
    }

    pub async fn load_remote_draft(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<Option<RemoteDraft>, AppError> {
        self.storage
            .get_setting::<Option<RemoteDraft>>(&format!("remote_draft:{host_id}:{instance_id}"))
            .await
            .map_err(storage_error)
            .map(Option::flatten)
    }

    pub async fn discard_remote_draft(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<(), AppError> {
        self.storage
            .set_setting(
                &format!("remote_draft:{host_id}:{instance_id}"),
                &Option::<RemoteDraft>::None,
            )
            .await
            .map_err(storage_error)
    }

    pub async fn remote_peer_availability(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<Vec<PeerAvailability>, AppError> {
        let manifest = self.read_remote(host_id, instance_id).await?;
        let mut availability = Vec::new();
        for peer in &manifest.configuration.peers {
            let binding = self
                .storage
                .get_setting::<vam_core::DeviceBackendData>(&peer_binding_key(
                    manifest.appliance_id,
                    instance_id,
                    peer.id,
                ))
                .await
                .map_err(storage_error)?;
            let private_ref = match binding.as_ref() {
                Some(vam_core::DeviceBackendData::WireGuard(data)) => Some(&data.private_key_ref),
                Some(vam_core::DeviceBackendData::AmneziaWg(data)) => Some(&data.private_key_ref),
                Some(vam_core::DeviceBackendData::OpenVpn(data)) => Some(&data.private_key_ref),
                Some(vam_core::DeviceBackendData::Ikev2(data)) => data.private_key_ref.as_ref(),
                _ => None,
            };
            let identity_matches = match (&peer.identity, binding.as_ref()) {
                (
                    vam_authority::manifest::PublicIdentity::Wireguard { public_key, .. },
                    Some(vam_core::DeviceBackendData::WireGuard(data)),
                ) => public_key == &data.public_key,
                (
                    vam_authority::manifest::PublicIdentity::AmneziaWg { public_key, .. },
                    Some(vam_core::DeviceBackendData::AmneziaWg(data)),
                ) => public_key == &data.public_key,
                (
                    vam_authority::manifest::PublicIdentity::Openvpn {
                        common_name,
                        certificate_serial,
                    },
                    Some(vam_core::DeviceBackendData::OpenVpn(data)),
                ) => {
                    common_name == &data.common_name
                        && certificate_serial == &data.certificate_serial
                }
                (
                    vam_authority::manifest::PublicIdentity::Ikev2 {
                        identity,
                        certificate_serial,
                    },
                    Some(vam_core::DeviceBackendData::Ikev2(data)),
                ) => identity == &data.identity && certificate_serial == &data.certificate_serial,
                _ => false,
            };
            let available = if let Some(reference) = private_ref {
                match self.secrets.get(reference).await {
                    Ok(_) => identity_matches && peer.enabled,
                    Err(vam_secrets::SecretStoreError::NotFound) => false,
                    Err(error) => return Err(super::secret_error(error)),
                }
            } else {
                false
            };
            availability.push(PeerAvailability {
                peer_id: peer.id,
                complete_export_available: available,
                reason: (!available).then(|| {
                    "Complete export requires peer private material available on this client."
                        .into()
                }),
            });
        }
        Ok(availability)
    }
    pub async fn remote_blocking(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        request_id: Uuid,
        action: vam_authority::manifest::blocking::Action,
    ) -> Result<vam_authority::manifest::blocking::View, AppError> {
        let identity = self.remote_identity(host_id).await?;
        if !identity
            .capabilities
            .iter()
            .any(|value| value == vam_authority::manifest::blocking::CAPABILITY)
        {
            return Err(validation_error(
                "Update the server helper to manage per-instance DNS blocking.",
            ));
        }
        match self
            .remote_operation(
                host_id,
                request_id,
                Operation::Blocking {
                    instance_id,
                    action,
                },
            )
            .await.map_err(|mut error| {
                if error.code == "revision_conflict" {
                    error.code = "blocking_revision_conflict".into();
                    error.message = "Blocking settings changed on the server. Reload blocking settings before saving again.".into();
                    error.remediation = Some("Your unsaved blocking edits remain in this view. Review them before confirming a reload.".into());
                }
                error
            })?
        {
            Reply::Blocking(view) => Ok(*view),
            _ => Err(validation_error("Unexpected DNS blocking response.")),
        }
    }

    pub async fn drop_remote_peer(
        &self,
        host_id: Uuid,
        request_id: Uuid,
        operation: vam_authority::manifest::Operation,
    ) -> Result<Manifest, AppError> {
        if !matches!(
            operation,
            Operation::DropPeer {
                confirmed: true,
                ..
            }
        ) {
            return Err(validation_error("Confirmed device removal is required."));
        }
        let identity = self.remote_identity(host_id).await?;
        if !identity
            .capabilities
            .contains(&vam_authority::manifest::DROP_PEER_CAPABILITY.to_owned())
        {
            return Err(validation_error(
                "Update the server helper to support device removal.",
            ));
        }
        manifest_reply(
            self.remote_operation(host_id, request_id, operation)
                .await?,
        )
    }

    pub async fn add_remote_peer(
        &self,
        host_id: Uuid,
        expected_revision: u64,
        input: super::CreateDeviceInput,
    ) -> Result<Manifest, AppError> {
        use vam_core::{Device, DeviceBackendData, allocate_next_ipv4};
        let manifest = self.read_remote(host_id, input.instance_id).await?;
        if manifest.revision != expected_revision {
            return Err(validation_error(
                "Remote revision changed; reload before creating a peer.",
            ));
        }
        if input.display_name.trim().is_empty() {
            return Err(validation_error("Peer name is required."));
        }
        let mut state = manifest.configuration.runtime_state();
        let id = Uuid::new_v4();
        let address = allocate_next_ipv4(
            state.instance.network.ipv4_subnet,
            state.instance.network.gateway_ipv4,
            &state.devices,
        )
        .map_err(|error| validation_error(&error.to_string()))?;
        let (backend_data, pending) = super::generate_device_identity(
            &state.instance,
            &input.display_name,
            id,
            input.preshared_key,
        )
        .map_err(super::backend_error)?;
        let psk_ref = match &backend_data {
            DeviceBackendData::WireGuard(data) => data.preshared_key_ref.as_ref(),
            DeviceBackendData::AmneziaWg(data) => Some(&data.preshared_key_ref),
            _ => None,
        };
        let mut remote_secrets = BTreeMap::new();
        for secret in &pending {
            if Some(&secret.reference) == psk_ref {
                remote_secrets.insert(
                    secret.reference.0,
                    vam_authority::SecretValue::new(secret.value.to_vec()),
                );
            }
        }
        let dns_name = input
            .dns_name
            .as_deref()
            .map(|name| super::normalize_dns_owner(name, &state.instance.dns.zone))
            .transpose()
            .map_err(|error| validation_error(&error))?
            .flatten();
        state.devices.push(Device {
            id,
            instance_id: input.instance_id,
            user_id: input.user_id,
            display_name: input.display_name.trim().into(),
            ipv4_address: Some(address),
            ipv6_address: None,
            dns_name: dns_name.clone(),
            enabled: true,
            backend_data: backend_data.clone(),
            created_at: Utc::now(),
            deleted_at: None,
        });
        if input.create_dns_record
            && let Some(name) = dns_name
        {
            state.dns_records.push(vam_core::DnsRecord {
                id: Uuid::new_v4(),
                instance_id: input.instance_id,
                name,
                record_type: vam_core::DnsRecordType::A,
                value: address.to_string(),
                ttl: 300,
                enabled: true,
                managed_by_device_id: Some(id),
            });
        }
        let configuration = Configuration::from_legacy(&state, manifest.appliance_id)
            .map_err(|error| validation_error(&error.to_string()))?;
        // Preserve local keys if a response is lost; reconcile the mutation UUID.
        self.store_pending_secrets(&pending).await?;
        self.storage
            .set_setting(
                &peer_binding_key(manifest.appliance_id, input.instance_id, id),
                &backend_data,
            )
            .await
            .map_err(storage_error)?;
        let request_id = Uuid::new_v4();
        if matches!(
            backend_data,
            DeviceBackendData::OpenVpn(_) | DeviceBackendData::Ikev2(_)
        ) {
            let peer = configuration
                .peers
                .iter()
                .find(|peer| peer.id == id)
                .cloned()
                .ok_or_else(|| validation_error("New peer projection is unavailable."))?;
            let csr_ref = match &backend_data {
                DeviceBackendData::OpenVpn(data) => &data.csr_ref,
                DeviceBackendData::Ikev2(data) => data
                    .csr_ref
                    .as_ref()
                    .ok_or_else(|| validation_error("Local CSR reference is unavailable."))?,
                _ => unreachable!(),
            };
            let csr = self.secret_text(csr_ref).await?;
            let reply = self
                .remote_operation(
                    host_id,
                    request_id,
                    Operation::EnrollPeer {
                        instance_id: input.instance_id,
                        expected_revision,
                        peer,
                        csr: csr.to_string(),
                        create_dns_record: input.create_dns_record,
                    },
                )
                .await?;
            let Reply::Enrollment {
                manifest: saved,
                material,
            } = reply
            else {
                return Err(validation_error(
                    "Unexpected certificate enrollment response.",
                ));
            };
            self.store_certificate_material(
                saved.appliance_id,
                input.instance_id,
                id,
                backend_data,
                &saved.configuration,
                material,
            )
            .await?;
            return Ok(*saved);
        }
        manifest_reply(
            self.remote_operation(
                host_id,
                request_id,
                Operation::Save {
                    request: Box::new(SaveRequest {
                        compatibility: Compatibility::default(),
                        appliance_id: manifest.appliance_id,
                        request_id,
                        expected_revision,
                        configuration,
                        secrets: remote_secrets,
                    }),
                },
            )
            .await?,
        )
    }

    pub async fn export_remote_peer(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        peer_id: Uuid,
        destination: &std::path::Path,
    ) -> Result<(), AppError> {
        let artifact = self
            .remote_peer_export_artifact(host_id, instance_id, peer_id)
            .await?;
        super::write_private_file(destination, artifact.contents.as_bytes()).await
    }

    /// Explicit export only. Never serialize this secret-bearing artifact into UI state or logs.
    pub async fn remote_peer_export_artifact(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        peer_id: Uuid,
    ) -> Result<vam_protocol::ClientArtifact, AppError> {
        use vam_core::DeviceBackendData;
        let manifest = self.read_remote(host_id, instance_id).await?;
        let binding = self.storage.get_setting::<DeviceBackendData>(&peer_binding_key(manifest.appliance_id, instance_id, peer_id)).await.map_err(storage_error)?
            .ok_or_else(|| AppError::new("missing_local_private_key", "This client does not possess the device private key and cannot export a complete configuration."))?;
        if matches!(
            binding,
            DeviceBackendData::OpenVpn(_) | DeviceBackendData::Ikev2(_)
        ) {
            self.remote_certificate_artifact(host_id, &manifest, peer_id, binding)
                .await
        } else {
            self.remote_peer_configuration(host_id, &manifest, peer_id, binding)
                .await
        }
    }

    /// Explicit text export for the native clipboard; binary credential bundles are not text.
    pub async fn remote_peer_configuration_text(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        peer_id: Uuid,
    ) -> Result<zeroize::Zeroizing<String>, AppError> {
        let artifact = self
            .remote_peer_export_artifact(host_id, instance_id, peer_id)
            .await?;
        if artifact.contents.is_binary() {
            return Err(AppError::new(
                "text_export_not_supported",
                "This device uses a binary credential bundle. Download the configuration file instead.",
            ));
        }
        Ok(zeroize::Zeroizing::new(
            artifact
                .contents
                .as_text()
                .ok_or_else(|| validation_error("Configuration text is unavailable."))?
                .to_owned(),
        ))
    }

    /// Render only for the verified appliance and the locally held matching key.
    async fn remote_peer_configuration(
        &self,
        host_id: Uuid,
        manifest: &Manifest,
        peer_id: Uuid,
        binding: vam_core::DeviceBackendData,
    ) -> Result<vam_protocol::ClientArtifact, AppError> {
        use vam_core::{DeviceBackendData, SecretReference};
        let instance_id = manifest.configuration.instance.id;
        let mut state = manifest.configuration.runtime_state();
        let device = state
            .devices
            .iter_mut()
            .find(|device| device.id == peer_id)
            .ok_or_else(|| validation_error("Peer no longer exists."))?;
        if !device.enabled {
            return Err(validation_error(
                "Disabled peers cannot be exported as active configurations.",
            ));
        }
        let (private_ref, psk_ref, identity_matches) = match (&device.backend_data, &binding) {
            (DeviceBackendData::WireGuard(remote), DeviceBackendData::WireGuard(local)) => (
                &local.private_key_ref,
                remote.preshared_key_ref.as_ref(),
                remote.public_key == local.public_key,
            ),
            (DeviceBackendData::AmneziaWg(remote), DeviceBackendData::AmneziaWg(local)) => (
                &local.private_key_ref,
                Some(&remote.preshared_key_ref),
                remote.public_key == local.public_key,
            ),
            _ => {
                return Err(validation_error(
                    "Certificate exports require the certificate-authority workflow.",
                ));
            }
        };
        if !identity_matches {
            return Err(validation_error(
                "Local credential belongs to an earlier peer identity.",
            ));
        }
        let private = self.secret_text(private_ref).await?;
        let mut secrets = std::collections::HashMap::new();
        secrets.insert(private_ref.clone(), private);
        let psk_ref = psk_ref.cloned();
        device.backend_data = binding;
        match &mut device.backend_data {
            DeviceBackendData::WireGuard(data) => data.preshared_key_ref.clone_from(&psk_ref),
            DeviceBackendData::AmneziaWg(data) => {
                data.preshared_key_ref = psk_ref
                    .clone()
                    .ok_or_else(|| validation_error("Missing server PSK reference."))?;
            }
            _ => {}
        }
        let device = device.clone();
        let Reply::PeerPsk {
            value,
            server_public_key,
        } = self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::ExportPeerPsk {
                    instance_id,
                    peer_id,
                    expected_revision: manifest.revision,
                },
            )
            .await?
        else {
            return Err(validation_error("Unexpected peer export response."));
        };
        if let Some(reference) = psk_ref {
            let value = value.ok_or_else(|| validation_error("Server PSK is unavailable."))?;
            let text = String::from_utf8(value.as_bytes().to_vec())
                .map_err(|_| validation_error("Invalid server PSK encoding."))?;
            secrets.insert(reference, zeroize::Zeroizing::new(text));
        }
        secrets.insert(
            SecretReference(instance_id),
            zeroize::Zeroizing::new(server_public_key.ok_or_else(|| {
                validation_error(
                    "Deploy the instance before exporting a complete client configuration.",
                )
            })?),
        );
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(super::backend_error)?;
        let artifact = backend
            .render_client(&state, &device, &secrets)
            .map_err(super::backend_error)?;
        Ok(artifact)
    }

    pub async fn remote_peer_qr_svg(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        peer_id: Uuid,
    ) -> Result<String, AppError> {
        let manifest = self.read_remote(host_id, instance_id).await?;
        if !matches!(
            manifest.configuration.instance.backend,
            VpnBackendKind::WireGuard | VpnBackendKind::AmneziaWg
        ) {
            return Err(AppError::new(
                "qr_not_supported",
                "Use file export for this backend's client credentials.",
            ));
        }
        let binding = self
            .storage
            .get_setting(&peer_binding_key(
                manifest.appliance_id,
                instance_id,
                peer_id,
            ))
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                AppError::new(
                    "missing_local_private_key",
                    "This client does not possess the peer private key.",
                )
            })?;
        let artifact = self
            .remote_peer_configuration(host_id, &manifest, peer_id, binding)
            .await?;
        let code = qrcode::QrCode::new(artifact.contents.as_bytes()).map_err(|_| AppError::new("qr_generation_failed", "The configuration is too large for a QR code. Export it as a private file instead."))?;
        Ok(code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(384, 384)
            .build())
    }
    /// SSH trust is checked before any use of the appliance UUID. The latter
    /// is an ownership identifier, never an authentication credential.
    pub(super) async fn remote_identity(&self, host_id: Uuid) -> Result<ServerIdentity, AppError> {
        let lock = self.instance_lock(Uuid::nil()).await;
        let _guard = lock.lock().await;
        let (host, trusted, passphrase) = self.trusted_host(host_id).await?;
        let response = self
            .manifest_exchange
            .exchange_manifest(
                &AuthoritySshSession {
                    config: &host.ssh,
                    trusted_key_base64: &trusted.public_key_base64,
                    passphrase: passphrase.as_ref(),
                },
                &Request {
                    compatibility: Compatibility::default(),
                    request_id: Uuid::new_v4(),
                    appliance_id: None,
                    operation: Operation::Info,
                },
                &CancellationToken::new(),
            )
            .await
            .map_err(|error| remote_transport_error(&error))?;
        let Reply::Info {
            appliance_id,
            machine_fingerprint,
            capabilities,
            ..
        } = response.result.map_err(remote_failure)?
        else {
            return Err(validation_error(
                "The helper returned an unexpected identity response.",
            ));
        };
        let identity = ServerIdentity {
            appliance_id,
            machine_fingerprint,
            ssh_public_key: trusted.public_key_base64,
            capabilities,
        };
        if let Some(previous) = self
            .storage
            .get_setting::<ServerIdentity>(&identity_key(host_id))
            .await
            .map_err(storage_error)?
            && (previous.appliance_id != identity.appliance_id
                || previous.machine_fingerprint != identity.machine_fingerprint)
        {
            return Err(validation_error(
                "The server appliance or machine identity changed. Inspect the host and recover or recreate its local connection profile.",
            ));
        }
        for other in self.list_hosts().await? {
            if other.id == host_id {
                continue;
            }
            if let Some(previous) = self
                .storage
                .get_setting::<ServerIdentity>(&identity_key(other.id))
                .await
                .map_err(storage_error)?
                && previous.appliance_id == identity.appliance_id
                && (previous.machine_fingerprint != identity.machine_fingerprint
                    || previous.ssh_public_key != identity.ssh_public_key)
            {
                return Err(AppError {
                    code: "duplicate_appliance_identity".into(), message: "Two SSH hosts report the same appliance UUID with different machine or host-key identities.".into(),
                    scope: Some(host_id.to_string()), remote_state_changed: false, rollback_succeeded: None,
                    remediation: Some("Keep both hosts unchanged and resolve the cloned appliance identity before managing either copy.".into()), technical_detail: None,
                });
            }
        }
        for previous in self
            .storage
            .recovered_appliance_identities()
            .await
            .map_err(storage_error)?
        {
            let previous: ServerIdentity = serde_json::from_value(previous).map_err(|_| validation_error("Retained appliance identity is invalid; inspect local recovery data before reconnecting."))?;
            if previous.appliance_id == identity.appliance_id
                && (previous.machine_fingerprint != identity.machine_fingerprint
                    || previous.ssh_public_key != identity.ssh_public_key)
            {
                return Err(validation_error(
                    "This appliance UUID conflicts with a retained recovery identity. Resolve the machine or SSH identity change before reusing local credentials.",
                ));
            }
        }
        self.storage
            .set_setting(&identity_key(host_id), &identity)
            .await
            .map_err(storage_error)?;
        Ok(identity)
    }

    pub(super) async fn remote_operation(
        &self,
        host_id: Uuid,
        request_id: Uuid,
        operation: Operation,
    ) -> Result<Reply, AppError> {
        let _guard = self.cleanup_guard.read().await;
        let identity = self.remote_identity(host_id).await?;
        let (host, trusted, passphrase) = self.trusted_host(host_id).await?;
        let response = self
            .manifest_exchange
            .exchange_manifest(
                &AuthoritySshSession {
                    config: &host.ssh,
                    trusted_key_base64: &trusted.public_key_base64,
                    passphrase: passphrase.as_ref(),
                },
                &Request {
                    compatibility: Compatibility::default(),
                    request_id,
                    appliance_id: Some(identity.appliance_id),
                    operation,
                },
                &CancellationToken::new(),
            )
            .await
            .map_err(|error| remote_transport_error(&error))?;
        match response.result.map_err(remote_failure)? {
            Reply::OperationFailure(error) => Err(error),
            reply => Ok(reply),
        }
    }

    pub async fn discover_remote(&self, host_id: Uuid) -> Result<RemoteInventory, AppError> {
        self.ensure_remote_helper(host_id).await?;
        let Reply::Discovery(discovery) = self
            .remote_operation(host_id, Uuid::new_v4(), Operation::Discover)
            .await?
        else {
            return Err(validation_error(
                "The helper returned an unexpected discovery response.",
            ));
        };
        let identity = self
            .storage
            .get_setting(&identity_key(host_id))
            .await
            .map_err(storage_error)?
            .ok_or_else(|| validation_error("Server identity is unavailable."))?;
        let inventory = RemoteInventory {
            host_id,
            identity,
            synchronized_at: Utc::now(),
            cached: false,
            discovery,
        };
        self.storage
            .set_setting(&cache_key(host_id), &inventory)
            .await
            .map_err(storage_error)?;
        Ok(inventory)
    }

    /// An explicit offline-view operation: failures from `discover_remote` are
    /// never swallowed or converted into an apparently successful empty list.
    pub async fn cached_remote_inventory(
        &self,
        host_id: Uuid,
    ) -> Result<Option<RemoteInventory>, AppError> {
        let mut cached = self
            .storage
            .get_setting::<Option<RemoteInventory>>(&cache_key(host_id))
            .await
            .map_err(storage_error)?
            .flatten();
        if let Some(inventory) = &mut cached {
            inventory.cached = true;
        }
        Ok(cached)
    }

    pub async fn clear_remote_cache(&self, host_id: Uuid) -> Result<(), AppError> {
        self.storage
            .set_setting(&cache_key(host_id), &Option::<RemoteInventory>::None)
            .await
            .map_err(storage_error)
    }

    pub async fn read_remote(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<Manifest, AppError> {
        manifest_reply(
            self.remote_operation(host_id, Uuid::new_v4(), Operation::Read { instance_id })
                .await?,
        )
    }

    pub async fn save_remote(&self, input: RemoteSaveInput) -> Result<Manifest, AppError> {
        validate_remote_configuration(&input.configuration)?;
        let appliance_id = self.remote_identity(input.host_id).await?.appliance_id;
        if input.configuration.instance.host_id != appliance_id {
            return Err(validation_error(
                "Configuration belongs to a different server.",
            ));
        }
        manifest_reply(
            self.remote_operation(
                input.host_id,
                input.request_id,
                Operation::Save {
                    request: Box::new(SaveRequest {
                        compatibility: Compatibility::default(),
                        appliance_id,
                        request_id: input.request_id,
                        expected_revision: input.expected_revision,
                        configuration: input.configuration,
                        secrets: BTreeMap::new(),
                    }),
                },
            )
            .await?,
        )
    }

    pub async fn create_remote_instance(
        &self,
        input: CreateInstanceInput,
    ) -> Result<Manifest, AppError> {
        use vam_core::{
            BackendSettings, DnsConfig, EndpointConfig, NetworkConfig, RoutingMode, VpnInstance,
            first_usable,
        };
        if input.backend == VpnBackendKind::Xray {
            return Err(validation_error(
                "Xray is unsupported. Existing legacy data remains available for recovery.",
            ));
        }
        let identity = self.remote_identity(input.host_id).await?;
        let subnet = input
            .ipv4_subnet
            .parse()
            .map_err(|_| validation_error("The IPv4 subnet is invalid."))?;
        let gateway = first_usable(subnet).map_err(|error| validation_error(&error.to_string()))?;
        let settings = match input.backend_settings {
            Some(settings) if settings.kind() == input.backend => settings.into_backend_settings(),
            Some(_) => {
                return Err(validation_error(
                    "Backend settings do not match the selected backend.",
                ));
            }
            None => BackendSettings::defaults_for(input.backend, &input.endpoint_host),
        };
        let now = Utc::now();
        let configuration = Configuration {
            instance: VpnInstance {
                id: Uuid::new_v4(),
                host_id: identity.appliance_id,
                display_name: input.display_name.trim().into(),
                backend: input.backend,
                backend_settings: settings,
                endpoint: EndpointConfig {
                    host: input.endpoint_host.trim().into(),
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
                    soa_serial: vam_dns::next_soa_serial(0, now.date_naive())
                        .map_err(|error| validation_error(&error.to_string()))?,
                },
                routing_mode: input.routing_mode.unwrap_or(RoutingMode::SplitTunnel),
                persistent_keepalive: vam_core::DEFAULT_KEEPALIVE,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            },
            users: Vec::new(),
            peers: Vec::new(),
            dns_records: Vec::new(),
            dns_blocklist_domains: Vec::new(),
        };
        self.save_remote(RemoteSaveInput {
            host_id: input.host_id,
            expected_revision: 0,
            request_id: Uuid::new_v4(),
            configuration,
        })
        .await
    }

    pub async fn remote_history(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<Vec<Manifest>, AppError> {
        let Reply::History(history) = self
            .remote_operation(host_id, Uuid::new_v4(), Operation::History { instance_id })
            .await?
        else {
            return Err(validation_error(
                "The helper returned an unexpected history response.",
            ));
        };
        Ok(history)
    }

    pub async fn remote_runtime_history(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<Vec<vam_authority::manifest::RuntimeHistoryEntry>, AppError> {
        let Reply::RuntimeHistory(history) = self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::RuntimeHistory { instance_id },
            )
            .await?
        else {
            return Err(validation_error(
                "The helper returned an unexpected runtime history response.",
            ));
        };
        Ok(history)
    }

    pub async fn reconcile_remote_runtime(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        mutation_id: Uuid,
    ) -> Result<vam_authority::manifest::RuntimeReconciliation, AppError> {
        let Reply::RuntimeReconciled(status) = self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::ReconcileRuntime {
                    instance_id,
                    mutation_id,
                },
            )
            .await?
        else {
            return Err(validation_error(
                "The helper returned an unexpected runtime reconciliation response.",
            ));
        };
        Ok(status)
    }

    pub async fn preview_remote_deployment(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        expected_revision: u64,
    ) -> Result<vam_protocol::DeploymentPlan, AppError> {
        match self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::PreviewDeployment {
                    instance_id,
                    expected_revision,
                },
            )
            .await?
        {
            Reply::DeploymentPlan(plan) => Ok(plan),
            _ => Err(validation_error("Unexpected deployment preview response.")),
        }
    }

    pub async fn apply_remote_deployment(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        expected_revision: u64,
        expected_state_hash: String,
        request_id: Uuid,
    ) -> Result<vam_protocol::DeploymentResult, AppError> {
        match self
            .remote_operation(
                host_id,
                request_id,
                Operation::ApplyDeployment {
                    instance_id,
                    expected_revision,
                    expected_state_hash,
                },
            )
            .await?
        {
            Reply::DeploymentResult(result) => Ok(result),
            _ => Err(validation_error("Unexpected deployment response.")),
        }
    }

    pub async fn inspect_remote_health(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
    ) -> Result<vam_protocol::InstanceHealth, AppError> {
        match self
            .remote_operation(host_id, Uuid::new_v4(), Operation::Health { instance_id })
            .await?
        {
            Reply::Health(health) => Ok(health),
            _ => Err(validation_error("Unexpected deployment health response.")),
        }
    }

    pub async fn backup_remote_deployment(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        expected_revision: u64,
    ) -> Result<vam_protocol::BackupInfo, AppError> {
        match self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::BackupDeployment {
                    instance_id,
                    expected_revision,
                },
            )
            .await?
        {
            Reply::Backup(backup) => Ok(backup),
            _ => Err(validation_error("Unexpected deployment backup response.")),
        }
    }

    pub async fn reconcile_remote_save(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        mutation_id: Uuid,
    ) -> Result<Option<Manifest>, AppError> {
        match self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::Reconcile {
                    instance_id,
                    mutation_id,
                },
            )
            .await?
        {
            Reply::Reconciled(manifest) => Ok(manifest.map(|manifest| *manifest)),
            _ => Err(validation_error("Unexpected reconciliation response.")),
        }
    }

    pub async fn restore_remote_desired(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        revision: u64,
        expected_revision: u64,
        confirmed: bool,
    ) -> Result<Manifest, AppError> {
        manifest_reply(
            self.remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::RestoreDesired {
                    instance_id,
                    revision,
                    expected_revision,
                    confirmed,
                },
            )
            .await?,
        )
    }

    pub async fn remove_remote_configuration(
        &self,
        input: RemoteSaveInput,
        confirmed: bool,
    ) -> Result<Manifest, AppError> {
        let identity = self.remote_identity(input.host_id).await?;
        if !supports_archives(&identity) {
            return Err(archive_upgrade_required());
        }
        manifest_reply(
            self.remote_operation(
                input.host_id,
                input.request_id,
                Operation::ArchiveInstance {
                    request: Box::new(SaveRequest {
                        compatibility: Compatibility::default(),
                        appliance_id: identity.appliance_id,
                        request_id: input.request_id,
                        expected_revision: input.expected_revision,
                        configuration: input.configuration,
                        secrets: BTreeMap::new(),
                    }),
                    confirmed,
                },
            )
            .await
            .map_err(archive_operation_error)?,
        )
    }

    pub async fn restore_archived_instance(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        expected_revision: u64,
        request_id: Uuid,
        confirmed: bool,
    ) -> Result<Manifest, AppError> {
        if !supports_archives(&self.remote_identity(host_id).await?) {
            return Err(archive_upgrade_required());
        }
        manifest_reply(
            self.remote_operation(
                host_id,
                request_id,
                Operation::RestoreArchivedInstance {
                    instance_id,
                    expected_revision,
                    confirmed,
                },
            )
            .await
            .map_err(archive_operation_error)?,
        )
    }

    pub async fn legacy_candidates(&self) -> Result<Vec<LegacyCandidate>, AppError> {
        let mut candidates = Vec::new();
        for instance in self
            .storage
            .list_instances(None)
            .await
            .map_err(storage_error)?
        {
            if self
                .storage
                .get_setting::<String>(&migration_key(instance.id))
                .await
                .map_err(storage_error)?
                .is_some()
            {
                continue;
            }
            candidates.push(LegacyCandidate {
                instance_id: instance.id,
                host_id: instance.host_id,
                display_name: instance.display_name,
                backend: instance.backend,
                supported: instance.backend != VpnBackendKind::Xray,
                status: if instance.backend == VpnBackendKind::Xray {
                    "unsupported_recovery_only"
                } else {
                    "requires_preview"
                }
                .into(),
            });
        }
        Ok(candidates)
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn manifest_reply(reply: Reply) -> Result<Manifest, AppError> {
    if let Reply::Manifest(manifest) = reply {
        Ok(*manifest)
    } else {
        Err(validation_error(
            "The helper returned an unexpected manifest response.",
        ))
    }
}

pub(super) fn peer_binding_key(appliance_id: Uuid, instance_id: Uuid, peer_id: Uuid) -> String {
    format!("local_peer_binding:{appliance_id}:{instance_id}:{peer_id}")
}

fn remote_failure(failure: vam_authority::AuthorityFailure) -> AppError {
    use vam_authority::AuthorityFailureCode;
    AppError {
        code: match failure.code { AuthorityFailureCode::RevisionConflict => "revision_conflict", AuthorityFailureCode::Incompatible => "incompatible_helper", _ => "remote_authority" }.into(),
        message: failure.message, scope: None, remote_state_changed: false, rollback_succeeded: None,
        remediation: Some("Refresh the server configuration and retain your draft before retrying. Incompatible helpers require a validated upgrade.".into()), technical_detail: None,
    }
}

fn archive_upgrade_required() -> AppError {
    let mut error = AppError::new(
        "helper_upgrade_required",
        "The server helper does not support restorable archives. The archive or restore operation has not run.",
    );
    error.remediation = Some("Use Refresh / Reconnect in the desktop to repair a compatible older helper automatically. CLI users must install a validated helper at /usr/local/libexec/vam-server. The desktop app and server helper must both support archived-instance recovery.".into());
    error
}

fn supports_archives(identity: &ServerIdentity) -> bool {
    identity
        .capabilities
        .iter()
        .any(|feature| feature == vam_authority::manifest::INSTANCE_ARCHIVE_CAPABILITY)
}

fn archive_operation_error(error: AppError) -> AppError {
    // A helper downgrade between negotiation and execution still fails closed.
    // Never retry using the older removal operation: it lacks restore metadata.
    if error.code == "remote_authority" && error.message.contains("invalid manifest request") {
        let mut failure = archive_upgrade_required();
        failure.technical_detail = Some(error.message);
        failure
    } else {
        error
    }
}

fn remote_transport_error(error: &vam_authority_client::AuthorityClientError) -> AppError {
    AppError { code: "remote_exchange_failed".into(), message: error.to_string(), scope: None,
        remote_state_changed: true, rollback_succeeded: None,
        remediation: Some("Reconnect and reconcile the mutation request UUID before retrying a write. The existing local draft and remote cache remain available.".into()), technical_detail: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use vam_authority::manifest::{ManifestStore, Response};
    use vam_authority_client::{AuthorityClientError, ManifestExchange};
    use vam_core::DockerHost;
    use vam_secrets::MemorySecretStore;
    use vam_storage::Storage;

    struct Helper {
        store: ManifestStore,
        appliance_id: Uuid,
        offline: AtomicBool,
        calls: AtomicUsize,
        supports_archives: AtomicBool,
    }

    #[async_trait]
    impl ManifestExchange for Helper {
        async fn exchange_manifest(
            &self,
            session: &AuthoritySshSession<'_>,
            request: &Request,
            _: &CancellationToken,
        ) -> Result<Response, AuthorityClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.offline.load(Ordering::SeqCst) {
                return Err(AuthorityClientError::Ssh(vam_ssh::SshError::Timeout));
            }
            assert_eq!(session.trusted_key_base64, "approved-key");
            let result = match &request.operation {
                Operation::Info => Ok(Reply::Info {
                    appliance_id: self.appliance_id,
                    machine_fingerprint: session.config.hostname.clone(),
                    software_version: "test".into(),
                    capabilities: if self.supports_archives.load(Ordering::SeqCst) {
                        vec![vam_authority::manifest::INSTANCE_ARCHIVE_CAPABILITY.into()]
                    } else {
                        vec![]
                    },
                }),
                Operation::Discover => self.store.discover().map(Reply::Discovery),
                Operation::Read { instance_id } => self
                    .store
                    .read(*instance_id)
                    .and_then(|manifest| manifest.ok_or(vam_authority::AuthorityError::NotFound))
                    .map(|manifest| Reply::Manifest(Box::new(manifest))),
                Operation::Save { request } => self
                    .store
                    .save(request)
                    .map(|manifest| Reply::Manifest(Box::new(manifest))),
                Operation::ArchiveInstance { request, confirmed } => self
                    .store
                    .remove(request, *confirmed)
                    .map(|manifest| Reply::Manifest(Box::new(manifest))),
                Operation::RestoreArchivedInstance {
                    instance_id,
                    expected_revision,
                    confirmed,
                } => {
                    if !confirmed {
                        Err(vam_authority::AuthorityError::InvalidState(
                            "restore requires confirmation".into(),
                        ))
                    } else if let Some(manifest) = self
                        .store
                        .reconciled_archive_restore(
                            *instance_id,
                            *expected_revision,
                            request.request_id,
                        )
                        .unwrap()
                    {
                        Ok(Reply::Manifest(Box::new(manifest)))
                    } else {
                        let context = self
                            .store
                            .archived_runtime_context(*instance_id, *expected_revision)
                            .unwrap();
                        context.begin_or_resume_removal(request.request_id).unwrap();
                        let manifest = context.commit_archive_restore(request.request_id).unwrap();
                        context.finish_mutation().unwrap();
                        Ok(Reply::Manifest(Box::new(manifest)))
                    }
                }
                Operation::ExportPeerPsk {
                    instance_id,
                    peer_id,
                    expected_revision,
                } => self
                    .store
                    .export_peer_psk(*instance_id, *peer_id, *expected_revision)
                    .map(|value| Reply::PeerPsk {
                        value,
                        server_public_key: Some(
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                        ),
                    }),
                Operation::InspectLegacy { .. } => Ok(Reply::LegacyInspection {
                    deployment_present: false,
                    instance: None,
                    metadata_digest: "empty".into(),
                }),
                Operation::BackupControl { .. } => Ok(Reply::ControlBackup {
                    backup_id: request.request_id,
                }),
                Operation::Migrate { request, .. } => self
                    .store
                    .save(request)
                    .map(|manifest| Reply::Manifest(Box::new(manifest))),
                _ => panic!("unexpected operation"),
            };
            Ok(Response {
                compatibility: Compatibility::default(),
                request_id: request.request_id,
                result: result.map_err(|error| error.failure()),
            })
        }
    }

    async fn client(
        helper: Arc<Helper>,
        hostname: &str,
        trusted: bool,
    ) -> (ApplicationService, DockerHost) {
        let service = ApplicationService::new(
            Storage::in_memory().await.unwrap(),
            Arc::new(MemorySecretStore::default()),
        )
        .with_manifest_exchange(helper);
        let host = service
            .create_host(super::super::CreateHostInput {
                display_name: hostname.into(),
                hostname: hostname.into(),
                port: 22,
                username: "test".into(),
                private_key_path: "/unused".into(),
                passphrase: None,
            })
            .await
            .unwrap();
        if trusted {
            approve(&service, &host).await;
        }
        (service, host)
    }

    async fn approve(service: &ApplicationService, host: &DockerHost) {
        service
            .storage
            .approve_host_key(
                host.id,
                &vam_protocol::HostKeyInfo {
                    hostname: host.ssh.hostname.clone(),
                    resolved_address: "127.0.0.1".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    sha256_fingerprint: "SHA256:approved".into(),
                    public_key_base64: "approved-key".into(),
                },
                false,
            )
            .await
            .unwrap();
    }

    fn helper(path: &std::path::Path) -> Arc<Helper> {
        let appliance_id = Uuid::new_v4();
        Arc::new(Helper {
            store: ManifestStore::open(path, appliance_id).unwrap(),
            appliance_id,
            offline: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
            supports_archives: AtomicBool::new(true),
        })
    }

    #[tokio::test]
    async fn fresh_clients_share_remote_state_without_creating_legacy_rows() {
        let dir = tempfile::tempdir().unwrap();
        let helper = helper(dir.path());
        let (a, host_a) = client(helper.clone(), "server", true).await;
        let (b, host_b) = client(helper.clone(), "server", true).await;
        assert!(
            a.discover_remote(host_a.id)
                .await
                .unwrap()
                .discovery
                .instances
                .is_empty()
        );
        let created = a
            .create_remote_instance(CreateInstanceInput {
                host_id: host_a.id,
                display_name: "primary".into(),
                endpoint_host: "vpn.example.com".into(),
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: None,
                ipv4_subnet: "10.88.0.0/24".into(),
                dns_zone: "vpn.internal".into(),
                routing_mode: None,
                xray_tls_import: None,
            })
            .await
            .unwrap();
        assert_eq!(created.configuration.instance.host_id, helper.appliance_id);
        let discovered = b.discover_remote(host_b.id).await.unwrap();
        assert_eq!(discovered.discovery.instances[0], created);
        let mut configuration = created.configuration.clone();
        configuration.instance.display_name = "from B".into();
        b.save_remote(RemoteSaveInput {
            host_id: host_b.id,
            expected_revision: 1,
            request_id: Uuid::new_v4(),
            configuration,
        })
        .await
        .unwrap();
        let error = a
            .save_remote(RemoteSaveInput {
                host_id: host_a.id,
                expected_revision: 1,
                request_id: Uuid::new_v4(),
                configuration: created.configuration,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, "revision_conflict");
        assert_eq!(
            a.discover_remote(host_a.id)
                .await
                .unwrap()
                .discovery
                .instances[0]
                .revision,
            2
        );
        assert!(a.storage.list_instances(None).await.unwrap().is_empty());
        assert!(b.legacy_candidates().await.unwrap().is_empty());
        b.delete_host(host_b.id).await.unwrap();
        assert_eq!(helper.store.discover().unwrap().instances.len(), 1);
    }

    #[tokio::test]
    async fn outdated_helper_blocks_archival_until_support_is_negotiated() {
        let directory = tempfile::tempdir().unwrap();
        let helper = helper(directory.path());
        helper.supports_archives.store(false, Ordering::SeqCst);
        let (service, host) = client(helper.clone(), "server", true).await;
        let created = service
            .create_remote_instance(CreateInstanceInput {
                host_id: host.id,
                display_name: "Still active".into(),
                endpoint_host: "vpn.example.test".into(),
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: None,
                ipv4_subnet: "10.88.0.0/24".into(),
                dns_zone: "vpn.internal".into(),
                routing_mode: None,
                xray_tls_import: None,
            })
            .await
            .unwrap();
        let input = RemoteSaveInput {
            host_id: host.id,
            expected_revision: created.revision,
            request_id: Uuid::new_v4(),
            configuration: created.configuration.clone(),
        };
        let error = service
            .remove_remote_configuration(input.clone(), true)
            .await
            .unwrap_err();
        assert_eq!(error.code, "helper_upgrade_required");
        assert!(!error.remote_state_changed);
        assert!(
            error
                .remediation
                .unwrap()
                .contains("/usr/local/libexec/vam-server")
        );
        assert_eq!(
            helper.store.discover().unwrap().instances,
            vec![created.clone()]
        );
        assert!(
            service
                .restore_archived_instance(
                    host.id,
                    created.configuration.instance.id,
                    2,
                    Uuid::new_v4(),
                    true
                )
                .await
                .is_err()
        );
        helper.supports_archives.store(true, Ordering::SeqCst);
        assert!(
            service
                .remove_remote_configuration(input, true)
                .await
                .unwrap()
                .removed
        );
        assert!(helper.store.discover().unwrap().instances.is_empty());
    }

    #[test]
    fn legacy_info_and_cache_do_not_imply_archive_support() {
        let response: Reply = serde_json::from_value(serde_json::json!({"response":"info", "value": {
            "appliance_id": Uuid::new_v4(), "machine_fingerprint":"machine", "software_version":"0.1.0"
        }})).unwrap();
        assert!(matches!(response, Reply::Info { capabilities, .. } if capabilities.is_empty()));
        let identity: ServerIdentity = serde_json::from_value(serde_json::json!({
            "appliance_id": Uuid::new_v4(), "machine_fingerprint":"machine", "ssh_public_key":"approved"
        })).unwrap();
        assert!(!supports_archives(&identity));
        let mapped = archive_operation_error(AppError::new(
            "remote_authority",
            "authority state is invalid: invalid manifest request",
        ));
        assert_eq!(mapped.code, "helper_upgrade_required");
        assert!(!mapped.remote_state_changed);
    }

    #[tokio::test]
    async fn fresh_clients_can_discover_and_restore_archived_instances() {
        let directory = tempfile::tempdir().unwrap();
        let helper = helper(directory.path());
        let (a, host_a) = client(helper.clone(), "server", true).await;
        let created = a
            .create_remote_instance(CreateInstanceInput {
                host_id: host_a.id,
                display_name: "recoverable".into(),
                endpoint_host: "vpn.example.test".into(),
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: None,
                ipv4_subnet: "10.88.0.0/24".into(),
                dns_zone: "vpn.internal".into(),
                routing_mode: None,
                xray_tls_import: None,
            })
            .await
            .unwrap();
        let archived = a
            .remove_remote_configuration(
                RemoteSaveInput {
                    host_id: host_a.id,
                    expected_revision: created.revision,
                    request_id: Uuid::new_v4(),
                    configuration: created.configuration.clone(),
                },
                true,
            )
            .await
            .unwrap();
        let (b, host_b) = client(helper, "server", true).await;
        let discovery = b.discover_remote(host_b.id).await.unwrap().discovery;
        assert!(discovery.instances.is_empty());
        assert_eq!(discovery.archived_instances, vec![archived.clone()]);
        let operation = Uuid::new_v4();
        let id = created.configuration.instance.id;
        assert!(
            b.restore_archived_instance(host_b.id, id, archived.revision, operation, false)
                .await
                .is_err()
        );
        let restored = b
            .restore_archived_instance(host_b.id, id, archived.revision, operation, true)
            .await
            .unwrap();
        assert_eq!(
            b.restore_archived_instance(host_b.id, id, archived.revision, operation, true)
                .await
                .unwrap(),
            restored
        );
        assert_eq!(restored.configuration, created.configuration);
        assert_eq!(
            a.discover_remote(host_a.id)
                .await
                .unwrap()
                .discovery
                .instances,
            vec![restored]
        );
    }

    #[tokio::test]
    async fn trust_precedes_identity_and_offline_cache_is_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let helper = helper(dir.path());
        let (service, host) = client(helper.clone(), "server", false).await;
        assert!(service.discover_remote(host.id).await.is_err());
        assert_eq!(helper.calls.load(Ordering::SeqCst), 0);
        approve(&service, &host).await;
        assert!(!service.discover_remote(host.id).await.unwrap().cached);
        helper.offline.store(true, Ordering::SeqCst);
        assert!(service.discover_remote(host.id).await.is_err());
        assert!(
            service
                .cached_remote_inventory(host.id)
                .await
                .unwrap()
                .unwrap()
                .cached
        );
        assert!(service.legacy_candidates().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn peers_remain_visible_without_local_private_keys_and_only_original_client_exports() {
        for backend in [VpnBackendKind::WireGuard, VpnBackendKind::AmneziaWg] {
            let dir = tempfile::tempdir().unwrap();
            let helper = helper(&dir.path().join("remote"));
            let (a, host_a) = client(helper.clone(), "server", true).await;
            let (b, host_b) = client(helper.clone(), "server", true).await;
            let created = a
                .create_remote_instance(CreateInstanceInput {
                    host_id: host_a.id,
                    display_name: "primary".into(),
                    endpoint_host: "vpn.example.com".into(),
                    backend,
                    backend_settings: None,
                    endpoint_port: None,
                    ipv4_subnet: "10.88.0.0/24".into(),
                    dns_zone: "vpn.internal".into(),
                    routing_mode: None,
                    xray_tls_import: None,
                })
                .await
                .unwrap();
            let id = created.configuration.instance.id;
            let saved = a
                .add_remote_peer(
                    host_a.id,
                    1,
                    super::super::CreateDeviceInput {
                        instance_id: id,
                        user_id: None,
                        display_name: "phone".into(),
                        preshared_key: true,
                        create_dns_record: true,
                        dns_name: Some("phone".into()),
                    },
                )
                .await
                .unwrap();
            let peer = saved.configuration.peers[0].id;
            assert_eq!(
                b.read_remote(host_b.id, id)
                    .await
                    .unwrap()
                    .configuration
                    .peers
                    .len(),
                1
            );
            let destination = dir.path().join("phone.conf");
            let error = b
                .export_remote_peer(host_b.id, id, peer, &destination)
                .await
                .unwrap_err();
            assert_eq!(error.code, "missing_local_private_key");
            assert!(!destination.exists());
            a.export_remote_peer(host_a.id, id, peer, &destination)
                .await
                .unwrap();
            let contents = std::fs::read_to_string(&destination).unwrap();
            assert!(contents.contains("PrivateKey = "));
            assert!(contents.contains("PresharedKey = "));
            let text = a
                .remote_peer_configuration_text(host_a.id, id, peer)
                .await
                .unwrap();
            assert_eq!(text.as_str(), contents);
            assert_eq!(
                b.remote_peer_configuration_text(host_b.id, id, peer)
                    .await
                    .unwrap_err()
                    .code,
                "missing_local_private_key"
            );
            assert_eq!(
                b.remote_peer_qr_svg(host_b.id, id, peer)
                    .await
                    .unwrap_err()
                    .code,
                "missing_local_private_key"
            );
            let qr = a.remote_peer_qr_svg(host_a.id, id, peer).await.unwrap();
            assert!(qr.contains("<svg"));
            assert!(qr.contains("<path"));
            let expected_qr = qrcode::QrCode::new(contents.as_bytes())
                .unwrap()
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(384, 384)
                .build();
            assert_eq!(qr, expected_qr);
            assert_eq!(
                saved.configuration.dns_records[0].managed_by_device_id,
                Some(peer)
            );
            a.discover_remote(host_a.id).await.unwrap();
            a.delete_host(host_a.id).await.unwrap();
            assert_eq!(std::fs::read_to_string(&destination).unwrap(), contents);
            let reconnected = DockerHost {
                id: Uuid::new_v4(),
                ..host_a
            };
            a.storage.save_host(&reconnected).await.unwrap();
            approve(&a, &reconnected).await;
            assert_eq!(
                a.discover_remote(reconnected.id)
                    .await
                    .unwrap()
                    .discovery
                    .instances
                    .len(),
                1
            );
            assert!(
                a.remote_peer_availability(reconnected.id, id)
                    .await
                    .unwrap()[0]
                    .complete_export_available
            );
            a.export_remote_peer(
                reconnected.id,
                id,
                peer,
                &dir.path().join("reconnected.conf"),
            )
            .await
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.path().join("reconnected.conf")).unwrap(),
                contents
            );
            helper
                .store
                .remove(
                    &SaveRequest {
                        compatibility: Compatibility::default(),
                        appliance_id: helper.appliance_id,
                        request_id: Uuid::new_v4(),
                        expected_revision: saved.revision,
                        configuration: saved.configuration,
                        secrets: BTreeMap::new(),
                    },
                    true,
                )
                .unwrap();
            assert!(
                a.discover_remote(reconnected.id)
                    .await
                    .unwrap()
                    .discovery
                    .instances
                    .is_empty()
            );
            assert!(helper.store.discover().unwrap().instances.is_empty());
        }
    }

    #[tokio::test]
    async fn cloned_appliance_identity_is_not_accepted_as_ssh_trust() {
        let dir = tempfile::tempdir().unwrap();
        let helper = helper(dir.path());
        let (service, host) = client(helper.clone(), "server", true).await;
        service.discover_remote(host.id).await.unwrap();
        let clone = service
            .create_host(super::super::CreateHostInput {
                display_name: "clone".into(),
                hostname: "clone".into(),
                port: 22,
                username: "test".into(),
                private_key_path: "/unused".into(),
                passphrase: None,
            })
            .await
            .unwrap();
        approve(&service, &clone).await;
        assert_eq!(
            service.discover_remote(clone.id).await.unwrap_err().code,
            "duplicate_appliance_identity"
        );
        service.delete_host(host.id).await.unwrap();
        let error = service.discover_remote(clone.id).await.unwrap_err();
        assert!(error.message.contains("retained recovery identity"));
    }

    #[tokio::test]
    async fn migration_is_conditional_preserves_peers_and_keeps_the_source_database() {
        let dir = tempfile::tempdir().unwrap();
        let helper = helper(&dir.path().join("remote"));
        let (mut a, host) = client(helper.clone(), "server", true).await;
        a.storage = Storage::open(&dir.path().join("legacy.sqlite"))
            .await
            .unwrap();
        a.storage.save_host(&host).await.unwrap();
        approve(&a, &host).await;
        assert!(a.legacy_candidates().await.unwrap().is_empty());
        let legacy = a
            .create_instance(CreateInstanceInput {
                host_id: host.id,
                display_name: "legacy".into(),
                endpoint_host: "vpn.example.com".into(),
                backend: VpnBackendKind::WireGuard,
                backend_settings: None,
                endpoint_port: None,
                ipv4_subnet: "10.88.0.0/24".into(),
                dns_zone: "vpn.internal".into(),
                routing_mode: None,
                xray_tls_import: None,
            })
            .await
            .unwrap();
        let peer = a
            .create_device(super::super::CreateDeviceInput {
                instance_id: legacy.id,
                user_id: None,
                display_name: "phone".into(),
                preshared_key: true,
                create_dns_record: false,
                dns_name: None,
            })
            .await
            .unwrap();
        assert_eq!(a.legacy_candidates().await.unwrap().len(), 1);
        let preview = a
            .preview_legacy_migration(legacy.id, host.id)
            .await
            .unwrap();
        assert!(preview.issues.is_empty(), "{:?}", preview.issues);
        assert!(
            a.migrate_legacy_instance(legacy.id, host.id, &preview.expected_preview_hash, false)
                .await
                .is_err()
        );
        let migrated = a
            .migrate_legacy_instance(legacy.id, host.id, &preview.expected_preview_hash, true)
            .await
            .unwrap();
        assert_eq!(migrated.configuration.instance.id, legacy.id);
        assert_eq!(migrated.configuration.peers[0].id, peer.id);
        assert!(a.legacy_candidates().await.unwrap().is_empty());
        assert_eq!(a.storage.get_instance(legacy.id).await.unwrap(), legacy);
        assert!(dir.path().join("legacy-backups").exists());
        assert!(
            a.migrate_legacy_instance(legacy.id, host.id, &preview.expected_preview_hash, true)
                .await
                .is_err()
        );
        assert_eq!(helper.store.discover().unwrap().instances.len(), 1);
        let (b, host_b) = client(helper, "server", true).await;
        assert_eq!(
            b.discover_remote(host_b.id)
                .await
                .unwrap()
                .discovery
                .instances
                .len(),
            1
        );
        assert!(b.legacy_candidates().await.unwrap().is_empty());
    }
}
