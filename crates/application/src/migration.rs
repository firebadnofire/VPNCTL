use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;
use vam_authority::{
    SecretValue,
    manifest::{Compatibility, Configuration, Manifest, Operation, Reply, SaveRequest},
};
use vam_core::{DeviceBackendData, SecretReference};

use super::remote::{manifest_reply, migration_key, peer_binding_key};
use super::{AppError, ApplicationService, storage_error, validation_error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyMigrationPreview {
    pub instance_id: Uuid,
    pub destination_host_id: Uuid,
    pub configuration: Configuration,
    pub deployment_present: bool,
    pub remote_metadata_digest: String,
    pub already_persisted: bool,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
    pub expected_preview_hash: String,
}

impl ApplicationService {
    pub async fn preview_legacy_migration(
        &self,
        instance_id: Uuid,
        destination_host_id: Uuid,
    ) -> Result<LegacyMigrationPreview, AppError> {
        if !self
            .legacy_candidates()
            .await?
            .iter()
            .any(|candidate| candidate.instance_id == instance_id && candidate.supported)
        {
            return Err(validation_error(
                "No matching eligible local legacy configuration was detected.",
            ));
        }
        let state = self
            .storage
            .desired_state(instance_id)
            .await
            .map_err(storage_error)?;
        let identity = self.remote_identity(destination_host_id).await?;
        let configuration = Configuration::from_legacy(&state, identity.appliance_id)
            .map_err(|error| validation_error(&error.to_string()))?;
        let inventory = self.discover_remote(destination_host_id).await?;
        let existing = inventory
            .discovery
            .instances
            .iter()
            .find(|manifest| manifest.configuration.instance.id == instance_id);
        let mut issues: Vec<String> = inventory.discovery.errors.values().cloned().collect();
        if existing.is_some_and(|manifest| manifest.configuration != configuration) {
            issues.push("An authoritative configuration with this UUID already exists and differs from the local source. It will not be overwritten.".into());
        }
        if let Err(error) = configuration.validate(identity.appliance_id) {
            issues.push(error.to_string());
        }
        let Reply::LegacyInspection {
            deployment_present,
            instance,
            metadata_digest,
        } = self
            .remote_operation(
                destination_host_id,
                Uuid::new_v4(),
                Operation::InspectLegacy { instance_id },
            )
            .await?
        else {
            return Err(validation_error("Unexpected legacy inspection response."));
        };
        if let Some(mut remote_instance) = instance {
            remote_instance.host_id = identity.appliance_id;
            remote_instance.created_at = configuration.instance.created_at;
            remote_instance.updated_at = configuration.instance.updated_at;
            if *remote_instance != configuration.instance {
                issues.push("Legacy deployment settings differ from the local source. Resolve that difference before migration.".into());
            }
        } else if deployment_present {
            issues.push("The legacy deployment lacks readable instance metadata; recover it before migration.".into());
        }
        for reference in server_psk_references(&state.devices) {
            if self.secrets.get(&reference).await.is_err() {
                issues.push(
                    "A required legacy server PSK is unavailable in the native credential store."
                        .into(),
                );
            }
        }
        let warnings = vec!["Migration saves configuration without restarting containers or rotating identities. Local source data and credentials are retained.".into()];
        let source = serde_json::to_vec(&state).map_err(super::serialization_error)?;
        let expected_preview_hash = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    &source,
                    destination_host_id,
                    &identity,
                    &configuration,
                    &metadata_digest,
                    existing.map(|manifest| manifest.revision),
                    &issues
                ))
                .map_err(super::serialization_error)?
            )
        );
        Ok(LegacyMigrationPreview {
            instance_id,
            destination_host_id,
            configuration,
            deployment_present,
            remote_metadata_digest: metadata_digest,
            already_persisted: existing.is_some(),
            issues,
            warnings,
            expected_preview_hash,
        })
    }

    pub async fn migrate_legacy_instance(
        &self,
        instance_id: Uuid,
        destination_host_id: Uuid,
        expected_preview_hash: &str,
        confirmed: bool,
    ) -> Result<Manifest, AppError> {
        if !confirmed {
            return Err(validation_error(
                "Legacy migration requires a reviewed preview and confirmation.",
            ));
        }
        let preview = self
            .preview_legacy_migration(instance_id, destination_host_id)
            .await?;
        if preview.expected_preview_hash != expected_preview_hash {
            return Err(validation_error(
                "Migration preview changed; inspect a fresh preview before proceeding.",
            ));
        }
        if !preview.issues.is_empty() {
            return Err(validation_error(&preview.issues.join(" ")));
        }
        let state = self
            .storage
            .desired_state(instance_id)
            .await
            .map_err(storage_error)?;
        self.storage
            .backup_legacy_database(Uuid::new_v4())
            .await
            .map_err(storage_error)?;
        self.remote_operation(
            destination_host_id,
            Uuid::new_v4(),
            Operation::BackupControl { confirmed: true },
        )
        .await?;
        if preview.deployment_present {
            self.remote_operation(
                destination_host_id,
                Uuid::new_v4(),
                Operation::BackupLegacy {
                    instance_id,
                    confirmed: true,
                },
            )
            .await?;
        }
        for device in &state.devices {
            self.storage
                .set_setting(
                    &peer_binding_key(
                        preview.configuration.instance.host_id,
                        instance_id,
                        device.id,
                    ),
                    &device.backend_data,
                )
                .await
                .map_err(storage_error)?;
        }
        let manifest = if preview.already_persisted {
            self.read_remote(destination_host_id, instance_id).await?
        } else {
            let mut secrets = BTreeMap::new();
            for reference in server_psk_references(&state.devices) {
                let value = self
                    .secrets
                    .get(&reference)
                    .await
                    .map_err(super::secret_error)?;
                secrets.insert(reference.0, SecretValue::new(value.to_vec()));
            }
            let request_id = Uuid::new_v4();
            manifest_reply(
                self.remote_operation(
                    destination_host_id,
                    request_id,
                    Operation::Migrate {
                        request: Box::new(SaveRequest {
                            compatibility: Compatibility::default(),
                            appliance_id: preview.configuration.instance.host_id,
                            request_id,
                            expected_revision: 0,
                            configuration: preview.configuration.clone(),
                            secrets,
                        }),
                        expected_legacy_digest: preview.remote_metadata_digest,
                    },
                )
                .await?,
            )?
        };
        let discovered = self.discover_remote(destination_host_id).await?;
        if !discovered.discovery.instances.iter().any(|remote| {
            remote.configuration == manifest.configuration && remote.revision >= manifest.revision
        }) {
            return Err(validation_error(
                "Remote migration persistence could not be verified; the local source remains active for recovery.",
            ));
        }
        self.storage
            .set_setting(&migration_key(instance_id), &"migrated")
            .await
            .map_err(storage_error)?;
        Ok(manifest)
    }

    pub async fn retire_legacy_instance(
        &self,
        instance_id: Uuid,
        confirmed: bool,
    ) -> Result<(), AppError> {
        if !confirmed {
            return Err(validation_error(
                "Archiving a legacy migration candidate requires confirmation.",
            ));
        }
        if !self
            .legacy_candidates()
            .await?
            .iter()
            .any(|candidate| candidate.instance_id == instance_id)
        {
            return Err(validation_error(
                "No matching local legacy configuration was detected.",
            ));
        }
        self.storage
            .backup_legacy_database(Uuid::new_v4())
            .await
            .map_err(storage_error)?;
        self.storage
            .set_setting(&migration_key(instance_id), &"retired")
            .await
            .map_err(storage_error)
    }

    pub async fn export_legacy_recovery(
        &self,
        instance_id: Uuid,
        destination: &std::path::Path,
    ) -> Result<(), AppError> {
        let state = self
            .storage
            .desired_state(instance_id)
            .await
            .map_err(storage_error)?;
        // This protected source export retains credential references; native
        // credential values and existing remote deployments are never changed.
        let bytes = serde_json::to_vec_pretty(&state).map_err(super::serialization_error)?;
        super::write_private_file(destination, &bytes).await
    }
}

fn server_psk_references(devices: &[vam_core::Device]) -> Vec<SecretReference> {
    devices
        .iter()
        .filter(|device| device.deleted_at.is_none())
        .filter_map(|device| match &device.backend_data {
            DeviceBackendData::WireGuard(data) => data.preshared_key_ref.clone(),
            DeviceBackendData::AmneziaWg(data) => Some(data.preshared_key_ref.clone()),
            DeviceBackendData::OpenVpn(_)
            | DeviceBackendData::Ikev2(_)
            | DeviceBackendData::Xray(_) => None,
        })
        .collect()
}
