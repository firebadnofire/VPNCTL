//! Local cleanup never writes or deletes native credentials or user files.
//! Preservation and removal therefore share one `SQLite` commit, rather than
//! pretending that the keyring can participate in a database transaction.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;
use vam_core::{Device, DnsRecord, User, VpnInstance};

use crate::{Storage, StorageError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalCleanupScope {
    pub host_ids: Vec<Uuid>,
    pub reset_preferences: bool,
}

/// Public configuration and references only; private keys remain in the
/// existing native store under their original references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostRecovery {
    pub identity: Option<serde_json::Value>,
    pub inventory: Option<serde_json::Value>,
    pub instances: Vec<VpnInstance>,
    pub devices: Vec<Device>,
    pub users: Vec<User>,
    pub dns_records: Vec<DnsRecord>,
    pub deployment_configurations: Vec<vam_core::DesiredState>,
    pub ssh_passphrase_reference: Option<vam_core::SecretReference>,
}

/// Serializes native retirement with recovery preservation across processes.
/// Dropping this guard rolls back the registry change; the caller must retain
/// it until the native deletion has completed or failed.
pub struct SecretRetirement {
    transaction: Transaction<'static, Sqlite>,
    reference: Uuid,
}

impl SecretRetirement {
    pub async fn finish(mut self) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM secret_references WHERE id=?")
            .bind(self.reference.to_string())
            .execute(&mut *self.transaction)
            .await?;
        self.transaction.commit().await?;
        Ok(())
    }
}

impl Storage {
    pub async fn begin_secret_retirement(
        &self,
        reference: Uuid,
    ) -> Result<Option<SecretRetirement>, StorageError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("UPDATE local_cleanup_operations SET id=id WHERE 0")
            .execute(&mut *transaction)
            .await?;
        let eligible: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM secret_references s WHERE s.id=? AND s.pending_delete_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM local_recovery_secret_references r WHERE r.id=s.id))")
            .bind(reference.to_string()).fetch_one(&mut *transaction).await?;
        if !eligible {
            return Ok(None);
        }
        Ok(Some(SecretRetirement {
            transaction,
            reference,
        }))
    }
    pub async fn recovered_appliance_identities(
        &self,
    ) -> Result<Vec<serde_json::Value>, StorageError> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT identity_json FROM local_host_recovery WHERE identity_json IS NOT NULL ORDER BY host_id")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|row| serde_json::from_str(&row).map_err(Into::into))
            .collect()
    }

    pub async fn local_cleanup_scope(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<LocalCleanupScope>, StorageError> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT scope_json FROM local_cleanup_operations WHERE id=?")
                .bind(operation_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        value
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    pub async fn local_host_recovery(
        &self,
        host_id: Uuid,
    ) -> Result<Option<LocalHostRecovery>, StorageError> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT recovery_json FROM local_host_recovery WHERE host_id=?")
                .bind(host_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        value
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    /// Exact-scope retries return the original completion. A transaction either
    /// preserves all recovery bindings and removes profiles, or changes nothing.
    /// No credential reference is discarded or marked for garbage collection.
    pub async fn cleanup_local_profiles(
        &self,
        operation_id: Uuid,
        scope: LocalCleanupScope,
    ) -> Result<(), StorageError> {
        self.cleanup_local_profiles_checked(operation_id, scope, |_| async { Ok(()) })
            .await
    }

    /// Read native credentials while holding the same database write exclusion
    /// used by retirement. The callback must not mutate credentials or query
    /// this database through another connection.
    pub async fn cleanup_local_profiles_checked<F, Fut>(
        &self,
        operation_id: Uuid,
        mut scope: LocalCleanupScope,
        mut verify: F,
    ) -> Result<(), StorageError>
    where
        F: FnMut(Vec<vam_core::SecretReference>) -> Fut,
        Fut: std::future::Future<Output = Result<(), StorageError>>,
    {
        scope.host_ids.sort_unstable();
        scope.host_ids.dedup();
        let encoded_scope = serde_json::to_string(&scope)?;
        let mut tx = self.pool.begin().await?;
        // Acquire the write lock before reading the scope or recovery sources.
        sqlx::query("UPDATE local_cleanup_operations SET id=id WHERE 0")
            .execute(&mut *tx)
            .await?;
        let previous: Option<String> =
            sqlx::query_scalar("SELECT scope_json FROM local_cleanup_operations WHERE id=?")
                .bind(operation_id.to_string())
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(previous) = previous {
            return if previous == encoded_scope {
                Ok(())
            } else {
                Err(StorageError::InvalidData(
                    "cleanup operation ID reused with a different scope".into(),
                ))
            };
        }
        if scope.reset_preferences {
            let mut current: Vec<String> = sqlx::query_scalar("SELECT id FROM docker_hosts")
                .fetch_all(&mut *tx)
                .await?;
            current.sort_unstable();
            let mut requested: Vec<String> =
                scope.host_ids.iter().map(ToString::to_string).collect();
            requested.sort_unstable();
            if current != requested {
                return Err(StorageError::InvalidData(
                    "local Factory Reset must include all saved profiles; refresh the reset scope"
                        .into(),
                ));
            }
        }
        for id in &scope.host_ids {
            let host_json: String =
                sqlx::query_scalar("SELECT model_json FROM docker_hosts WHERE id=?")
                    .bind(id.to_string())
                    .fetch_optional(&mut *tx)
                    .await?
                    .ok_or(StorageError::NotFound)?;
            let host: vam_core::DockerHost = serde_json::from_str(&host_json)?;
            let recovery = LocalHostRecovery {
                identity: setting(&mut tx, &format!("remote_identity:{id}")).await?,
                inventory: setting(&mut tx, &format!("remote_inventory_cache:{id}")).await?,
                instances: models(&mut tx, "SELECT model_json FROM vpn_instances WHERE host_id=?", *id).await?,
                devices: models(&mut tx, "SELECT model_json FROM devices WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)", *id).await?,
                users: models(&mut tx, "SELECT model_json FROM users WHERE id IN (SELECT user_id FROM devices WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?))", *id).await?,
                dns_records: models(&mut tx, "SELECT model_json FROM dns_records WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)", *id).await?,
                deployment_configurations: sqlx::query_scalar::<_, String>("SELECT desired_state_json FROM deployments WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)")
                    .bind(id.to_string()).fetch_all(&mut *tx).await?.into_iter()
                    .map(|value| serde_json::from_str(&value)).collect::<Result<_, _>>()?,
                ssh_passphrase_reference: host.ssh.passphrase_ref,
            };
            let mut required = std::collections::BTreeSet::new();
            if let Some(reference) = &recovery.ssh_passphrase_reference {
                required.insert(reference.0);
            }
            for instance in recovery
                .instances
                .iter()
                .filter(|instance| instance.deleted_at.is_none())
            {
                required.extend(
                    instance
                        .backend_settings
                        .secret_references()
                        .iter()
                        .map(|reference| reference.0),
                );
            }
            for device in recovery
                .devices
                .iter()
                .filter(|device| device.deleted_at.is_none())
            {
                required.extend(
                    device
                        .backend_data
                        .secret_references()
                        .iter()
                        .map(|reference| reference.0),
                );
            }
            if let Some(appliance_id) = recovery
                .identity
                .as_ref()
                .and_then(|identity| identity.get("appliance_id"))
                .and_then(serde_json::Value::as_str)
            {
                let prefix = format!("local_peer_binding:{appliance_id}:");
                let bindings: Vec<String> =
                    sqlx::query_scalar("SELECT value_json FROM settings WHERE instr(key, ?) = 1")
                        .bind(prefix)
                        .fetch_all(&mut *tx)
                        .await?;
                for binding in bindings {
                    let binding: vam_core::DeviceBackendData = serde_json::from_str(&binding)?;
                    required.extend(
                        binding
                            .secret_references()
                            .iter()
                            .map(|reference| reference.0)
                            .filter(|id| !id.is_nil()),
                    );
                }
            }
            verify(
                required
                    .into_iter()
                    .map(vam_core::SecretReference)
                    .collect(),
            )
            .await?;
            // Refuse to overwrite an earlier recovery bundle. Host UUIDs are
            // immutable; a collision must be inspected rather than lose data.
            sqlx::query("INSERT INTO local_host_recovery (host_id, identity_json, recovery_json, preserved_at) VALUES (?, ?, ?, ?)")
                .bind(id.to_string()).bind(recovery.identity.as_ref().map(serde_json::to_string).transpose()?).bind(serde_json::to_string(&recovery)?).bind(Utc::now().to_rfc3339())
                .execute(&mut *tx).await?;
            sqlx::query("INSERT INTO local_recovery_secret_references (id, host_id) SELECT id, ? FROM secret_references WHERE owner_id IN (SELECT id FROM vpn_instances WHERE host_id=? UNION SELECT id FROM devices WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)) ON CONFLICT(id) DO NOTHING")
                .bind(id.to_string()).bind(id.to_string()).bind(id.to_string()).execute(&mut *tx).await?;
            if let Some(reference) = &recovery.ssh_passphrase_reference {
                sqlx::query("INSERT INTO local_recovery_secret_references (id, host_id) VALUES (?, ?) ON CONFLICT(id) DO NOTHING")
                    .bind(reference.0.to_string()).bind(id.to_string()).execute(&mut *tx).await?;
            }
            // Pin references even if older data never registered them in the
            // secret registry. Keep all retained deployment identities too.
            let mut references = std::collections::BTreeSet::new();
            for instance in &recovery.instances {
                references.extend(
                    instance
                        .backend_settings
                        .secret_references()
                        .iter()
                        .map(|reference| reference.0),
                );
            }
            for device in &recovery.devices {
                references.extend(
                    device
                        .backend_data
                        .secret_references()
                        .iter()
                        .map(|reference| reference.0),
                );
            }
            for state in &recovery.deployment_configurations {
                references.extend(
                    state
                        .instance
                        .backend_settings
                        .secret_references()
                        .iter()
                        .map(|reference| reference.0),
                );
                for device in &state.devices {
                    references.extend(
                        device
                            .backend_data
                            .secret_references()
                            .iter()
                            .map(|reference| reference.0),
                    );
                }
            }
            for reference in references {
                sqlx::query("INSERT INTO local_recovery_secret_references (id, host_id) VALUES (?, ?) ON CONFLICT(id) DO NOTHING")
                    .bind(reference.to_string()).bind(id.to_string()).execute(&mut *tx).await?;
            }
            for statement in [
                "DELETE FROM deployment_events WHERE deployment_id IN (SELECT id FROM deployments WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?))",
                "DELETE FROM backup_records WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)",
                "DELETE FROM deployments WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)",
                "DELETE FROM dns_records WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)",
                "DELETE FROM devices WHERE instance_id IN (SELECT id FROM vpn_instances WHERE host_id=?)",
                "DELETE FROM vpn_instances WHERE host_id=?",
                "DELETE FROM docker_hosts WHERE id=?",
            ] {
                sqlx::query(statement)
                    .bind(id.to_string())
                    .execute(&mut *tx)
                    .await?;
            }
            // UUID-delimited matching, not SQL LIKE (whose '_' is a wildcard).
            for prefix in [
                "remote_identity:",
                "remote_inventory_cache:",
                "archived_host_profile:",
            ] {
                sqlx::query("DELETE FROM settings WHERE key=?")
                    .bind(format!("{prefix}{id}"))
                    .execute(&mut *tx)
                    .await?;
            }
            let draft_prefix = format!("remote_draft:{id}:");
            sqlx::query("DELETE FROM settings WHERE instr(key, ?) = 1")
                .bind(draft_prefix)
                .execute(&mut *tx)
                .await?;
        }
        if scope.reset_preferences {
            // This is the current application preference. Do not indiscriminately
            // clear settings: peer bindings and legacy recovery metadata live here.
            sqlx::query("DELETE FROM settings WHERE key='dns_hostlists' OR substr(key, 1, 19)='dns_hostlist_cache:'")
                .execute(&mut *tx).await?;
        }
        sqlx::query(
            "INSERT INTO local_cleanup_operations (id, scope_json, completed_at) VALUES (?, ?, ?)",
        )
        .bind(operation_id.to_string())
        .bind(encoded_scope)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn models<T: serde::de::DeserializeOwned>(
    tx: &mut Transaction<'_, Sqlite>,
    query: &str,
    host_id: Uuid,
) -> Result<Vec<T>, StorageError> {
    sqlx::query(query)
        .bind(host_id.to_string())
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|row| serde_json::from_str(row.get("model_json")).map_err(Into::into))
        .collect()
}

async fn setting(
    tx: &mut Transaction<'_, Sqlite>,
    key: &str,
) -> Result<Option<serde_json::Value>, StorageError> {
    let value: Option<String> = sqlx::query_scalar("SELECT value_json FROM settings WHERE key=?")
        .bind(key)
        .fetch_optional(&mut **tx)
        .await?;
    value
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(Into::into)
}
