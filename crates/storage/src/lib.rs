use std::{collections::HashSet, path::Path, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use thiserror::Error;
use uuid::Uuid;
use vam_core::{DesiredState, Device, DeviceBackendData, DnsRecord, DockerHost, User, VpnInstance};
use vam_protocol::{
    DeploymentPlan, DeploymentProgress, DeploymentStatus, DeploymentSummary, HostKeyInfo,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("record was not found")]
    NotFound,
    #[error("the SSH host key differs from the approved key")]
    HostKeyChanged,
    #[error("stored data is invalid: {0}")]
    InvalidData(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownHostKey {
    pub host_id: Uuid,
    pub algorithm: String,
    pub public_key_base64: String,
    pub sha256_fingerprint: String,
    pub approved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDeployment {
    pub summary: DeploymentSummary,
    pub desired_state: DesiredState,
    pub plan: DeploymentPlan,
}

#[derive(Clone, Debug)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn in_memory() -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn save_host(&self, host: &DockerHost) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO docker_hosts
             (id, display_name, hostname, ssh_port, username, private_key_path,
              passphrase_secret_ref, model_json, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
              display_name=excluded.display_name, hostname=excluded.hostname,
              ssh_port=excluded.ssh_port, username=excluded.username,
              private_key_path=excluded.private_key_path,
              passphrase_secret_ref=excluded.passphrase_secret_ref,
              model_json=excluded.model_json, updated_at=excluded.updated_at",
        )
        .bind(host.id.to_string())
        .bind(&host.display_name)
        .bind(&host.ssh.hostname)
        .bind(i64::from(host.ssh.port))
        .bind(&host.ssh.username)
        .bind(host.ssh.private_key_path.to_string_lossy().as_ref())
        .bind(
            host.ssh
                .passphrase_ref
                .as_ref()
                .map(|value| value.0.to_string()),
        )
        .bind(serde_json::to_string(host)?)
        .bind(host.created_at.to_rfc3339())
        .bind(host.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_hosts(&self) -> Result<Vec<DockerHost>, StorageError> {
        let rows = sqlx::query("SELECT model_json FROM docker_hosts ORDER BY display_name")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| serde_json::from_str(row.get("model_json")).map_err(StorageError::from))
            .collect()
    }

    pub async fn get_host(&self, id: Uuid) -> Result<DockerHost, StorageError> {
        let row = sqlx::query("SELECT model_json FROM docker_hosts WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::NotFound)?;
        Ok(serde_json::from_str(row.get("model_json"))?)
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM docker_hosts WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub async fn known_host_key(
        &self,
        host_id: Uuid,
    ) -> Result<Option<KnownHostKey>, StorageError> {
        let row = sqlx::query(
            "SELECT algorithm, public_key_base64, sha256_fingerprint, approved_at
             FROM known_host_keys WHERE host_id = ? ORDER BY approved_at DESC LIMIT 1",
        )
        .bind(host_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(KnownHostKey {
                host_id,
                algorithm: row.get("algorithm"),
                public_key_base64: row.get("public_key_base64"),
                sha256_fingerprint: row.get("sha256_fingerprint"),
                approved_at: parse_datetime(row.get("approved_at"))?,
            })
        })
        .transpose()
    }

    pub async fn approve_host_key(
        &self,
        host_id: Uuid,
        key: &HostKeyInfo,
        replace: bool,
    ) -> Result<(), StorageError> {
        if let Some(approved) = self.known_host_key(host_id).await?
            && approved.public_key_base64 != key.public_key_base64
            && !replace
        {
            return Err(StorageError::HostKeyChanged);
        }
        let mut transaction = self.pool.begin().await?;
        if replace {
            sqlx::query("DELETE FROM known_host_keys WHERE host_id = ?")
                .bind(host_id.to_string())
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query(
            "INSERT INTO known_host_keys
             (host_id, algorithm, public_key_base64, sha256_fingerprint, approved_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(host_id, algorithm) DO UPDATE SET
               public_key_base64=excluded.public_key_base64,
               sha256_fingerprint=excluded.sha256_fingerprint,
               approved_at=excluded.approved_at",
        )
        .bind(host_id.to_string())
        .bind(&key.algorithm)
        .bind(&key.public_key_base64)
        .bind(&key.sha256_fingerprint)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn save_instance(&self, instance: &VpnInstance) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO vpn_instances
             (id, host_id, display_name, backend, endpoint_port, ipv4_subnet, dns_zone,
              model_json, created_at, updated_at, deleted_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,
              endpoint_port=excluded.endpoint_port, ipv4_subnet=excluded.ipv4_subnet,
              dns_zone=excluded.dns_zone, model_json=excluded.model_json,
              updated_at=excluded.updated_at, deleted_at=excluded.deleted_at",
        )
        .bind(instance.id.to_string())
        .bind(instance.host_id.to_string())
        .bind(&instance.display_name)
        .bind("wireguard")
        .bind(i64::from(instance.endpoint.port))
        .bind(instance.network.ipv4_subnet.to_string())
        .bind(&instance.dns.zone)
        .bind(serde_json::to_string(instance)?)
        .bind(instance.created_at.to_rfc3339())
        .bind(instance.updated_at.to_rfc3339())
        .bind(instance.deleted_at.map(|value| value.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn soft_delete_instance(
        &self,
        id: Uuid,
        deleted_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let mut instance = self.get_instance(id).await?;
        instance.deleted_at = Some(deleted_at);
        instance.updated_at = deleted_at;
        self.save_instance(&instance).await
    }

    pub async fn list_instances(
        &self,
        host_id: Option<Uuid>,
    ) -> Result<Vec<VpnInstance>, StorageError> {
        let rows = if let Some(host_id) = host_id {
            sqlx::query(
                "SELECT model_json FROM vpn_instances
                 WHERE host_id = ? AND deleted_at IS NULL ORDER BY display_name",
            )
            .bind(host_id.to_string())
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT model_json FROM vpn_instances
                 WHERE deleted_at IS NULL ORDER BY display_name",
            )
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter()
            .map(|row| serde_json::from_str(row.get("model_json")).map_err(StorageError::from))
            .collect()
    }

    pub async fn get_instance(&self, id: Uuid) -> Result<VpnInstance, StorageError> {
        let row =
            sqlx::query("SELECT model_json FROM vpn_instances WHERE id = ? AND deleted_at IS NULL")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StorageError::NotFound)?;
        Ok(serde_json::from_str(row.get("model_json"))?)
    }

    pub async fn save_user(&self, user: &User) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO users (id, display_name, model_json, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               display_name=excluded.display_name, model_json=excluded.model_json",
        )
        .bind(user.id.to_string())
        .bind(&user.display_name)
        .bind(serde_json::to_string(user)?)
        .bind(user.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<User>, StorageError> {
        json_rows(
            sqlx::query("SELECT model_json FROM users ORDER BY display_name")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn delete_user(&self, id: Uuid) -> Result<(), StorageError> {
        let mut devices: Vec<Device> = json_rows(
            sqlx::query("SELECT model_json FROM devices WHERE user_id = ? AND deleted_at IS NULL")
                .bind(id.to_string())
                .fetch_all(&self.pool)
                .await?,
        )?;
        for device in &mut devices {
            device.user_id = None;
        }

        let mut transaction = self.pool.begin().await?;
        for device in devices {
            sqlx::query("UPDATE devices SET user_id=NULL, model_json=? WHERE id=?")
                .bind(serde_json::to_string(&device)?)
                .bind(device.id.to_string())
                .execute(&mut *transaction)
                .await?;
        }
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.to_string())
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn save_device(&self, device: &Device) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO devices
             (id, instance_id, user_id, display_name, ipv4_address, enabled,
              model_json, created_at, deleted_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               user_id=excluded.user_id, display_name=excluded.display_name,
               ipv4_address=excluded.ipv4_address, enabled=excluded.enabled,
               model_json=excluded.model_json, deleted_at=excluded.deleted_at",
        )
        .bind(device.id.to_string())
        .bind(device.instance_id.to_string())
        .bind(device.user_id.map(|id| id.to_string()))
        .bind(&device.display_name)
        .bind(device.ipv4_address.to_string())
        .bind(device.enabled)
        .bind(serde_json::to_string(device)?)
        .bind(device.created_at.to_rfc3339())
        .bind(device.deleted_at.map(|value| value.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn save_device_and_sync_managed_dns(
        &self,
        device: &Device,
    ) -> Result<bool, StorageError> {
        let mut managed_records: Vec<DnsRecord> = json_rows(
            sqlx::query(
                "SELECT model_json FROM dns_records
                 WHERE managed_by_device_id=?",
            )
            .bind(device.id.to_string())
            .fetch_all(&self.pool)
            .await?,
        )?;
        let dns_changed = managed_records
            .iter()
            .any(|record| record.enabled != device.enabled);
        for record in &mut managed_records {
            record.enabled = device.enabled;
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO devices
             (id, instance_id, user_id, display_name, ipv4_address, enabled,
              model_json, created_at, deleted_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               user_id=excluded.user_id, display_name=excluded.display_name,
               ipv4_address=excluded.ipv4_address, enabled=excluded.enabled,
               model_json=excluded.model_json, deleted_at=excluded.deleted_at",
        )
        .bind(device.id.to_string())
        .bind(device.instance_id.to_string())
        .bind(device.user_id.map(|id| id.to_string()))
        .bind(&device.display_name)
        .bind(device.ipv4_address.to_string())
        .bind(device.enabled)
        .bind(serde_json::to_string(device)?)
        .bind(device.created_at.to_rfc3339())
        .bind(device.deleted_at.map(|value| value.to_rfc3339()))
        .execute(&mut *transaction)
        .await?;
        for record in managed_records {
            sqlx::query("UPDATE dns_records SET enabled=?, model_json=? WHERE id=?")
                .bind(record.enabled)
                .bind(serde_json::to_string(&record)?)
                .bind(record.id.to_string())
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(dns_changed)
    }

    pub async fn soft_delete_device(
        &self,
        id: Uuid,
        deleted_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let mut device = self.get_device(id).await?;
        device.deleted_at = Some(deleted_at);
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "UPDATE devices SET model_json=?, deleted_at=?
             WHERE id=? AND deleted_at IS NULL",
        )
        .bind(serde_json::to_string(&device)?)
        .bind(deleted_at.to_rfc3339())
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM dns_records WHERE managed_by_device_id=?")
            .bind(id.to_string())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get_device(&self, id: Uuid) -> Result<Device, StorageError> {
        let row = sqlx::query("SELECT model_json FROM devices WHERE id = ? AND deleted_at IS NULL")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::NotFound)?;
        Ok(serde_json::from_str(row.get("model_json"))?)
    }

    pub async fn list_devices(&self, instance_id: Uuid) -> Result<Vec<Device>, StorageError> {
        json_rows(
            sqlx::query(
                "SELECT model_json FROM devices
                 WHERE instance_id = ? AND deleted_at IS NULL
                 ORDER BY ipv4_address",
            )
            .bind(instance_id.to_string())
            .fetch_all(&self.pool)
            .await?,
        )
    }

    pub async fn save_dns_record(&self, record: &DnsRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO dns_records
             (id, instance_id, name, record_type, value, ttl, enabled,
              managed_by_device_id, model_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               name=excluded.name, record_type=excluded.record_type,
               value=excluded.value, ttl=excluded.ttl, enabled=excluded.enabled,
               managed_by_device_id=excluded.managed_by_device_id,
               model_json=excluded.model_json",
        )
        .bind(record.id.to_string())
        .bind(record.instance_id.to_string())
        .bind(&record.name)
        .bind(format!("{:?}", record.record_type).to_ascii_uppercase())
        .bind(&record.value)
        .bind(i64::from(record.ttl))
        .bind(record.enabled)
        .bind(record.managed_by_device_id.map(|id| id.to_string()))
        .bind(serde_json::to_string(record)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_dns_records(
        &self,
        instance_id: Uuid,
    ) -> Result<Vec<DnsRecord>, StorageError> {
        json_rows(
            sqlx::query(
                "SELECT model_json FROM dns_records
                 WHERE instance_id = ? ORDER BY name, record_type, value",
            )
            .bind(instance_id.to_string())
            .fetch_all(&self.pool)
            .await?,
        )
    }

    pub async fn delete_dns_record(&self, id: Uuid) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM dns_records WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub async fn desired_state(&self, instance_id: Uuid) -> Result<DesiredState, StorageError> {
        let instance = self.get_instance(instance_id).await?;
        let devices = self.list_devices(instance_id).await?;
        let user_ids: HashSet<_> = devices.iter().filter_map(|device| device.user_id).collect();
        let users = self
            .list_users()
            .await?
            .into_iter()
            .filter(|user| user_ids.contains(&user.id))
            .collect();
        let dns_records = self.list_dns_records(instance_id).await?;
        Ok(DesiredState {
            instance,
            users,
            devices,
            dns_records,
        })
    }

    pub async fn record_deployment(
        &self,
        plan: &DeploymentPlan,
        state: &DesiredState,
        status: DeploymentStatus,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO deployments
             (id, instance_id, status, desired_state_json, plan_json, started_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(plan.id.to_string())
        .bind(plan.instance_id.to_string())
        .bind(format!("{status:?}").to_ascii_lowercase())
        .bind(serde_json::to_string(state)?)
        .bind(serde_json::to_string(plan)?)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_deployment_event(
        &self,
        event: &DeploymentProgress,
        level: &str,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO deployment_events
             (deployment_id, sequence, timestamp, level, phase, message, technical_detail)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.deployment_id.to_string())
        .bind(i64::try_from(event.sequence).unwrap_or(i64::MAX))
        .bind(event.timestamp.to_rfc3339())
        .bind(level)
        .bind(&event.phase)
        .bind(&event.message)
        .bind(&event.technical_detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn finish_deployment(
        &self,
        id: Uuid,
        status: DeploymentStatus,
        backup_name: Option<&str>,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE deployments SET status = ?, backup_name = ?, finished_at = ? WHERE id = ?",
        )
        .bind(status_name(status))
        .bind(backup_name)
        .bind(Utc::now().to_rfc3339())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub async fn list_deployments(
        &self,
        instance_id: Uuid,
    ) -> Result<Vec<DeploymentSummary>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, instance_id, status, backup_name, started_at, finished_at
             FROM deployments WHERE instance_id = ? ORDER BY started_at DESC",
        )
        .bind(instance_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| deployment_summary(&row))
            .collect()
    }

    pub async fn get_deployment(&self, id: Uuid) -> Result<StoredDeployment, StorageError> {
        let row = sqlx::query(
            "SELECT id, instance_id, status, backup_name, started_at, finished_at,
                    desired_state_json, plan_json
             FROM deployments WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StorageError::NotFound)?;
        Ok(StoredDeployment {
            summary: deployment_summary(&row)?,
            desired_state: serde_json::from_str(row.get("desired_state_json"))?,
            plan: serde_json::from_str(row.get("plan_json"))?,
        })
    }

    pub async fn last_successful_deployment(
        &self,
        instance_id: Uuid,
    ) -> Result<Option<StoredDeployment>, StorageError> {
        let row = sqlx::query(
            "SELECT id FROM deployments
             WHERE instance_id = ? AND status = 'succeeded'
             ORDER BY finished_at DESC LIMIT 1",
        )
        .bind(instance_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => self
                .get_deployment(parse_uuid(row.get("id"))?)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    pub async fn list_deployment_events(
        &self,
        instance_id: Option<Uuid>,
    ) -> Result<Vec<DeploymentProgress>, StorageError> {
        let rows = if let Some(instance_id) = instance_id {
            sqlx::query(
                "SELECT e.deployment_id, e.sequence, e.timestamp, e.phase,
                        e.message, e.technical_detail
                 FROM deployment_events e JOIN deployments d ON d.id=e.deployment_id
                 WHERE d.instance_id = ?
                 ORDER BY e.timestamp DESC, e.sequence DESC LIMIT 500",
            )
            .bind(instance_id.to_string())
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT deployment_id, sequence, timestamp, phase, message, technical_detail
                 FROM deployment_events
                 ORDER BY timestamp DESC, sequence DESC LIMIT 500",
            )
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter()
            .map(|row| {
                Ok(DeploymentProgress {
                    deployment_id: parse_uuid(row.get("deployment_id"))?,
                    sequence: u64::try_from(row.get::<i64, _>("sequence"))
                        .map_err(|error| StorageError::InvalidData(error.to_string()))?,
                    timestamp: parse_datetime(row.get("timestamp"))?,
                    phase: row.get("phase"),
                    message: row.get("message"),
                    technical_detail: row.get("technical_detail"),
                })
            })
            .collect()
    }

    pub async fn replace_desired_state(&self, state: &DesiredState) -> Result<(), StorageError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "UPDATE vpn_instances SET display_name=?, endpoint_port=?, ipv4_subnet=?,
             dns_zone=?, model_json=?, updated_at=?, deleted_at=? WHERE id=?",
        )
        .bind(&state.instance.display_name)
        .bind(i64::from(state.instance.endpoint.port))
        .bind(state.instance.network.ipv4_subnet.to_string())
        .bind(&state.instance.dns.zone)
        .bind(serde_json::to_string(&state.instance)?)
        .bind(state.instance.updated_at.to_rfc3339())
        .bind(state.instance.deleted_at.map(|value| value.to_rfc3339()))
        .bind(state.instance.id.to_string())
        .execute(&mut *transaction)
        .await?;
        for user in &state.users {
            sqlx::query(
                "INSERT INTO users (id, display_name, model_json, created_at)
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET
                   display_name=excluded.display_name, model_json=excluded.model_json",
            )
            .bind(user.id.to_string())
            .bind(&user.display_name)
            .bind(serde_json::to_string(user)?)
            .bind(user.created_at.to_rfc3339())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE devices SET deleted_at=?
             WHERE instance_id=? AND deleted_at IS NULL",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(state.instance.id.to_string())
        .execute(&mut *transaction)
        .await?;
        for device in &state.devices {
            sqlx::query(
                "INSERT INTO devices
                 (id, instance_id, user_id, display_name, ipv4_address, enabled,
                  model_json, created_at, deleted_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET
                   user_id=excluded.user_id, display_name=excluded.display_name,
                   ipv4_address=excluded.ipv4_address, enabled=excluded.enabled,
                   model_json=excluded.model_json, deleted_at=excluded.deleted_at",
            )
            .bind(device.id.to_string())
            .bind(device.instance_id.to_string())
            .bind(device.user_id.map(|id| id.to_string()))
            .bind(&device.display_name)
            .bind(device.ipv4_address.to_string())
            .bind(device.enabled)
            .bind(serde_json::to_string(device)?)
            .bind(device.created_at.to_rfc3339())
            .bind(device.deleted_at.map(|value| value.to_rfc3339()))
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query("DELETE FROM dns_records WHERE instance_id=?")
            .bind(state.instance.id.to_string())
            .execute(&mut *transaction)
            .await?;
        for record in &state.dns_records {
            sqlx::query(
                "INSERT INTO dns_records
                 (id, instance_id, name, record_type, value, ttl, enabled,
                  managed_by_device_id, model_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(record.id.to_string())
            .bind(record.instance_id.to_string())
            .bind(&record.name)
            .bind(format!("{:?}", record.record_type).to_ascii_uppercase())
            .bind(&record.value)
            .bind(i64::from(record.ttl))
            .bind(record.enabled)
            .bind(record.managed_by_device_id.map(|id| id.to_string()))
            .bind(serde_json::to_string(record)?)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn register_secret_reference(
        &self,
        id: Uuid,
        purpose: &str,
        owner_id: Uuid,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO secret_references (id, purpose, owner_id, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               purpose=excluded.purpose, owner_id=excluded.owner_id,
               pending_delete_at=NULL",
        )
        .bind(id.to_string())
        .bind(purpose)
        .bind(owner_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_setting<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO settings (key, value_json) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
        )
        .bind(key)
        .bind(serde_json::to_string(value)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_setting<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StorageError> {
        let value = sqlx::query("SELECT value_json FROM settings WHERE key=?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        value
            .map(|row| serde_json::from_str(row.get("value_json")))
            .transpose()
            .map_err(StorageError::from)
    }

    pub async fn mark_secrets_pending_delete(&self, owner_id: Uuid) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE secret_references SET pending_delete_at=?
             WHERE owner_id=? AND pending_delete_at IS NULL",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(owner_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn deletable_secret_references(
        &self,
        instance_id: Uuid,
        retained_deployments: usize,
    ) -> Result<Vec<Uuid>, StorageError> {
        let rows = sqlx::query(
            "SELECT s.id
             FROM secret_references s JOIN devices d ON d.id=s.owner_id
             WHERE d.instance_id=? AND s.pending_delete_at IS NOT NULL",
        )
        .bind(instance_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let candidates: Vec<Uuid> = rows
            .into_iter()
            .map(|row| parse_uuid(row.get("id")))
            .collect::<Result<_, _>>()?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let snapshots = sqlx::query(
            "SELECT desired_state_json FROM deployments
             WHERE instance_id=? ORDER BY started_at DESC LIMIT ?",
        )
        .bind(instance_id.to_string())
        .bind(i64::try_from(retained_deployments).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await?;
        let mut retained = HashSet::new();
        for row in snapshots {
            let state: DesiredState = serde_json::from_str(row.get("desired_state_json"))?;
            for device in state.devices {
                let DeviceBackendData::WireGuard(data) = device.backend_data;
                retained.insert(data.private_key_ref.0);
                retained.extend(data.preshared_key_ref.map(|reference| reference.0));
            }
        }
        Ok(candidates
            .into_iter()
            .filter(|id| !retained.contains(id))
            .collect())
    }

    pub async fn remove_secret_reference(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM secret_references WHERE id=?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn json_rows<T>(rows: Vec<sqlx::sqlite::SqliteRow>) -> Result<Vec<T>, StorageError>
where
    T: serde::de::DeserializeOwned,
{
    rows.into_iter()
        .map(|row| serde_json::from_str(row.get("model_json")).map_err(StorageError::from))
        .collect()
}

fn parse_uuid(value: &str) -> Result<Uuid, StorageError> {
    Uuid::parse_str(value).map_err(|error| StorageError::InvalidData(error.to_string()))
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| StorageError::InvalidData(error.to_string()))
}

fn status_name(status: DeploymentStatus) -> &'static str {
    match status {
        DeploymentStatus::Planned => "planned",
        DeploymentStatus::Applying => "applying",
        DeploymentStatus::Succeeded => "succeeded",
        DeploymentStatus::Failed => "failed",
        DeploymentStatus::RolledBack => "rolledback",
        DeploymentStatus::RollbackFailed => "rollbackfailed",
    }
}

fn parse_status(value: &str) -> Result<DeploymentStatus, StorageError> {
    match value {
        "planned" => Ok(DeploymentStatus::Planned),
        "applying" => Ok(DeploymentStatus::Applying),
        "succeeded" => Ok(DeploymentStatus::Succeeded),
        "failed" => Ok(DeploymentStatus::Failed),
        "rolledback" => Ok(DeploymentStatus::RolledBack),
        "rollbackfailed" => Ok(DeploymentStatus::RollbackFailed),
        other => Err(StorageError::InvalidData(format!(
            "unknown deployment status {other}"
        ))),
    }
}

fn deployment_summary(row: &sqlx::sqlite::SqliteRow) -> Result<DeploymentSummary, StorageError> {
    let finished: Option<&str> = row.get("finished_at");
    Ok(DeploymentSummary {
        id: parse_uuid(row.get("id"))?,
        instance_id: parse_uuid(row.get("instance_id"))?,
        status: parse_status(row.get("status"))?,
        backup_name: row.get("backup_name"),
        started_at: parse_datetime(row.get("started_at"))?,
        finished_at: finished.map(parse_datetime).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::path::PathBuf;
    use vam_core::{
        DEFAULT_KEEPALIVE, DeviceBackendData, DnsConfig, EndpointConfig, NetworkConfig,
        RoutingMode, SecretReference, SshConnectionConfig, VpnBackendKind, WireGuardDeviceData,
    };
    use vam_protocol::DeploymentPlan;

    #[tokio::test]
    async fn migrates_and_round_trips_host() {
        let storage = Storage::in_memory().await.unwrap();
        let host = DockerHost {
            id: Uuid::new_v4(),
            display_name: "test".into(),
            ssh: SshConnectionConfig {
                hostname: "example.test".into(),
                port: 22,
                username: "william".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase_ref: None,
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        storage.save_host(&host).await.unwrap();
        assert_eq!(storage.get_host(host.id).await.unwrap(), host);
    }

    #[tokio::test]
    async fn settings_are_typed_and_upserted() {
        let storage = Storage::in_memory().await.unwrap();
        storage
            .set_setting("server-public", &"first")
            .await
            .unwrap();
        storage
            .set_setting("server-public", &"second")
            .await
            .unwrap();
        assert_eq!(
            storage
                .get_setting::<String>("server-public")
                .await
                .unwrap(),
            Some("second".into())
        );
    }

    fn instance(host_id: Uuid, id: Uuid, port: u16) -> VpnInstance {
        VpnInstance {
            id,
            host_id,
            display_name: format!("instance-{id}"),
            backend: VpnBackendKind::WireGuard,
            endpoint: EndpointConfig {
                host: "vpn.example.test".into(),
                port,
            },
            network: NetworkConfig {
                ipv4_subnet: "10.64.0.0/24".parse().unwrap(),
                gateway_ipv4: "10.64.0.1".parse().unwrap(),
                ipv6_subnet: None,
                gateway_ipv6: None,
            },
            dns: DnsConfig {
                zone: "vpn.internal".into(),
                soa_serial: 2_026_072_301,
            },
            routing_mode: RoutingMode::SplitTunnel,
            persistent_keepalive: DEFAULT_KEEPALIVE,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    fn host() -> DockerHost {
        DockerHost {
            id: Uuid::new_v4(),
            display_name: "test".into(),
            ssh: SshConnectionConfig {
                hostname: "example.test".into(),
                port: 22,
                username: "william".into(),
                private_key_path: PathBuf::from("/tmp/key"),
                passphrase_ref: None,
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn database_enforces_active_host_port_uniqueness() {
        let storage = Storage::in_memory().await.unwrap();
        let host = host();
        storage.save_host(&host).await.unwrap();
        storage
            .save_instance(&instance(host.id, Uuid::new_v4(), 51_820))
            .await
            .unwrap();
        assert!(matches!(
            storage
                .save_instance(&instance(host.id, Uuid::new_v4(), 51_820))
                .await,
            Err(StorageError::Database(_))
        ));
    }

    #[tokio::test]
    async fn delete_user_clears_device_json_ownership() {
        let storage = Storage::in_memory().await.unwrap();
        let host = host();
        storage.save_host(&host).await.unwrap();
        let instance = instance(host.id, Uuid::new_v4(), 51_820);
        storage.save_instance(&instance).await.unwrap();
        let user = User {
            id: Uuid::new_v4(),
            display_name: "operator".into(),
            created_at: Utc::now(),
        };
        storage.save_user(&user).await.unwrap();
        let device = Device {
            id: Uuid::new_v4(),
            instance_id: instance.id,
            user_id: Some(user.id),
            display_name: "peer".into(),
            ipv4_address: "10.64.0.2".parse().unwrap(),
            ipv6_address: None,
            dns_name: None,
            enabled: true,
            backend_data: DeviceBackendData::WireGuard(WireGuardDeviceData {
                public_key: "public".into(),
                private_key_ref: SecretReference(Uuid::new_v4()),
                preshared_key_ref: None,
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        storage.save_device(&device).await.unwrap();

        storage.delete_user(user.id).await.unwrap();

        let updated = storage.get_device(device.id).await.unwrap();
        assert_eq!(updated.user_id, None);
    }

    #[tokio::test]
    async fn pending_secrets_survive_ten_deployment_snapshots() {
        let storage = Storage::in_memory().await.unwrap();
        let host = host();
        storage.save_host(&host).await.unwrap();
        let instance = instance(host.id, Uuid::new_v4(), 51_820);
        storage.save_instance(&instance).await.unwrap();
        let secret = SecretReference(Uuid::new_v4());
        let device = Device {
            id: Uuid::new_v4(),
            instance_id: instance.id,
            user_id: None,
            display_name: "peer".into(),
            ipv4_address: "10.64.0.2".parse().unwrap(),
            ipv6_address: None,
            dns_name: None,
            enabled: true,
            backend_data: DeviceBackendData::WireGuard(WireGuardDeviceData {
                public_key: "public".into(),
                private_key_ref: secret.clone(),
                preshared_key_ref: None,
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        storage.save_device(&device).await.unwrap();
        storage
            .register_secret_reference(secret.0, "wireguard_private_key", device.id)
            .await
            .unwrap();
        storage
            .mark_secrets_pending_delete(device.id)
            .await
            .unwrap();
        let state_with_device = DesiredState {
            instance: instance.clone(),
            users: Vec::new(),
            devices: vec![device],
            dns_records: Vec::new(),
        };
        let first_plan = DeploymentPlan {
            id: Uuid::new_v4(),
            instance_id: instance.id,
            operations: Vec::new(),
            warnings: Vec::new(),
            desired_state_hash: "first".into(),
        };
        storage
            .record_deployment(&first_plan, &state_with_device, DeploymentStatus::Succeeded)
            .await
            .unwrap();
        assert!(
            storage
                .deletable_secret_references(instance.id, 10)
                .await
                .unwrap()
                .is_empty()
        );
        let state_without_device = DesiredState {
            instance: instance.clone(),
            users: Vec::new(),
            devices: Vec::new(),
            dns_records: Vec::new(),
        };
        for index in 0..10 {
            let plan = DeploymentPlan {
                id: Uuid::new_v4(),
                instance_id: instance.id,
                operations: Vec::new(),
                warnings: Vec::new(),
                desired_state_hash: index.to_string(),
            };
            storage
                .record_deployment(&plan, &state_without_device, DeploymentStatus::Succeeded)
                .await
                .unwrap();
        }
        assert_eq!(
            storage
                .deletable_secret_references(instance.id, 10)
                .await
                .unwrap(),
            vec![secret.0]
        );
    }
}
