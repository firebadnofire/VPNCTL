//! Shared desktop/CLI cleanup entry points. Local cleanup never performs SSH
//! or rewrites native credentials; its only mutation is a durable `SQLite` commit.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vam_storage::LocalCleanupScope;

use super::{AppError, ApplicationService, storage_error, validation_error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCleanupResult {
    pub operation_id: Uuid,
    pub removed_profile_ids: Vec<Uuid>,
    pub preferences_reset: bool,
    pub recovery_preserved: bool,
}

impl ApplicationService {
    pub async fn cleanup_local(
        &self,
        operation_id: Uuid,
        mut scope: LocalCleanupScope,
    ) -> Result<LocalCleanupResult, AppError> {
        let _guard = self.cleanup_guard.write().await;
        scope.host_ids.sort_unstable();
        scope.host_ids.dedup();
        // Existing legacy deployment/credential mutations use these locks.
        // Drain them before validating or pinning any recovery references.
        let mut instance_ids = Vec::new();
        for host_id in &scope.host_ids {
            instance_ids.extend(
                self.storage
                    .list_instances(Some(*host_id))
                    .await
                    .map_err(storage_error)?
                    .into_iter()
                    .map(|instance| instance.id),
            );
        }
        instance_ids.sort_unstable();
        instance_ids.dedup();
        let mut instance_guards = Vec::new();
        for instance_id in instance_ids {
            instance_guards.push(self.instance_lock(instance_id).await.lock_owned().await);
        }
        if let Some(previous) = self
            .storage
            .local_cleanup_scope(operation_id)
            .await
            .map_err(storage_error)?
        {
            if previous != scope {
                return Err(validation_error(
                    "Cleanup operation ID was reused with a different scope.",
                ));
            }
        } else {
            self.storage
                .cleanup_local_profiles_checked(operation_id, scope.clone(), |references| {
                    let secrets = self.secrets.clone();
                    async move {
                        for reference in references {
                            secrets.get(&reference).await.map_err(|error| vam_storage::StorageError::InvalidData(format!("Recovery credential {} is unavailable; local removal stopped: {error}", reference.0)))?;
                        }
                        Ok(())
                    }
                })
                .await
                .map_err(storage_error)?;
        }
        Ok(LocalCleanupResult {
            operation_id,
            removed_profile_ids: scope.host_ids,
            preferences_reset: scope.reset_preferences,
            recovery_preserved: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vam_core::{DockerHost, SecretReference, SshConnectionConfig};
    use vam_secrets::{MemorySecretStore, SecretStore};
    use vam_storage::Storage;

    #[tokio::test]
    async fn local_cleanup_preserves_native_credentials_and_user_files() {
        let storage = Storage::in_memory().await.unwrap();
        let secrets = Arc::new(MemorySecretStore::default());
        let reference = SecretReference(Uuid::new_v4());
        secrets.put(&reference, b"passphrase").await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("id_ed25519");
        let exported = directory.path().join("phone.conf");
        std::fs::write(&key, b"user-managed SSH key").unwrap();
        std::fs::write(&exported, b"user-exported VPN configuration").unwrap();
        let host = DockerHost {
            id: Uuid::new_v4(),
            display_name: "offline host".into(),
            ssh: SshConnectionConfig {
                hostname: "unreachable.invalid".into(),
                port: 22,
                username: "test".into(),
                private_key_path: key.clone(),
                passphrase_ref: Some(reference.clone()),
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        storage.save_host(&host).await.unwrap();
        let service = ApplicationService::new(storage, secrets.clone());
        let operation_id = Uuid::new_v4();
        let scope = LocalCleanupScope {
            host_ids: vec![host.id],
            reset_preferences: true,
        };
        service
            .cleanup_local(operation_id, scope.clone())
            .await
            .unwrap();
        service.cleanup_local(operation_id, scope).await.unwrap();
        assert_eq!(
            secrets.get(&reference).await.unwrap().as_slice(),
            b"passphrase"
        );
        assert_eq!(std::fs::read(key).unwrap(), b"user-managed SSH key");
        assert_eq!(
            std::fs::read(exported).unwrap(),
            b"user-exported VPN configuration"
        );
        assert_eq!(
            service
                .storage
                .local_host_recovery(host.id)
                .await
                .unwrap()
                .unwrap()
                .ssh_passphrase_reference,
            Some(reference)
        );
        assert!(
            service
                .storage
                .set_setting(
                    &format!("remote_draft:{}:{}", host.id, Uuid::new_v4()),
                    &"late write"
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unavailable_recovery_credential_blocks_removal() {
        let service = ApplicationService::new(
            Storage::in_memory().await.unwrap(),
            Arc::new(MemorySecretStore::default()),
        );
        let host = service
            .create_host(super::super::CreateHostInput {
                display_name: "offline".into(),
                hostname: "unreachable.invalid".into(),
                port: 22,
                username: "test".into(),
                private_key_path: "/not-touched".into(),
                passphrase: None,
            })
            .await
            .unwrap();
        let mut host = host;
        host.ssh.passphrase_ref = Some(SecretReference(Uuid::new_v4()));
        service.storage.save_host(&host).await.unwrap();
        assert!(service.delete_host(host.id).await.is_err());
        assert_eq!(service.storage.get_host(host.id).await.unwrap(), host);
        assert!(
            service
                .storage
                .local_host_recovery(host.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
