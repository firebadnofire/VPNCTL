use std::{path::Path, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use uuid::Uuid;
use vam_authority::AuthoritySnapshot;
use vam_core::DockerHost;
use vam_protocol::HostKeyInfo;

use crate::{KnownHostKey, StorageError};

static CONNECTION_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/connections");
static CACHE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/cache");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionRecord {
    pub connection_id: Uuid,
    pub appliance_id: Option<Uuid>,
    pub host: DockerHost,
}

#[derive(Clone, Debug)]
pub struct ConnectionStore {
    pool: SqlitePool,
}

impl ConnectionStore {
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        let pool = open_database(path).await?;
        CONNECTION_MIGRATOR.run(&pool).await?;
        #[cfg(unix)]
        protect_local_database(path)?;
        Ok(Self { pool })
    }

    pub async fn in_memory() -> Result<Self, StorageError> {
        let pool = open_memory_database().await?;
        CONNECTION_MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn save(&self, record: &ConnectionRecord) -> Result<(), StorageError> {
        if record.connection_id != record.host.id {
            return Err(StorageError::InvalidData(
                "connection ID and host model ID differ".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO connections
             (id, appliance_id, display_name, hostname, ssh_port, username,
              private_key_path, passphrase_secret_ref, model_json, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               appliance_id=excluded.appliance_id,
               display_name=excluded.display_name,
               hostname=excluded.hostname,
               ssh_port=excluded.ssh_port,
               username=excluded.username,
               private_key_path=excluded.private_key_path,
               passphrase_secret_ref=excluded.passphrase_secret_ref,
               model_json=excluded.model_json,
               updated_at=excluded.updated_at",
        )
        .bind(record.connection_id.to_string())
        .bind(record.appliance_id.map(|id| id.to_string()))
        .bind(&record.host.display_name)
        .bind(&record.host.ssh.hostname)
        .bind(i64::from(record.host.ssh.port))
        .bind(&record.host.ssh.username)
        .bind(record.host.ssh.private_key_path.to_string_lossy())
        .bind(
            record
                .host
                .ssh
                .passphrase_ref
                .as_ref()
                .map(|reference| reference.0.to_string()),
        )
        .bind(serde_json::to_string(&record.host)?)
        .bind(record.host.created_at.to_rfc3339())
        .bind(record.host.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, connection_id: Uuid) -> Result<ConnectionRecord, StorageError> {
        let row = sqlx::query("SELECT appliance_id, model_json FROM connections WHERE id=?")
            .bind(connection_id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::NotFound)?;
        connection_record(connection_id, &row)
    }

    pub async fn list(&self) -> Result<Vec<ConnectionRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, appliance_id, model_json FROM connections ORDER BY display_name, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let id = parse_uuid(row.get("id"), "connection ID")?;
                connection_record(id, &row)
            })
            .collect()
    }

    pub async fn bind_appliance(
        &self,
        connection_id: Uuid,
        appliance_id: Uuid,
    ) -> Result<(), StorageError> {
        let changed = sqlx::query("UPDATE connections SET appliance_id=? WHERE id=?")
            .bind(appliance_id.to_string())
            .bind(connection_id.to_string())
            .execute(&self.pool)
            .await?
            .rows_affected();
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub async fn delete(&self, connection_id: Uuid) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM connections WHERE id=?")
            .bind(connection_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn approved_host_key(
        &self,
        connection_id: Uuid,
    ) -> Result<Option<KnownHostKey>, StorageError> {
        let row = sqlx::query(
            "SELECT algorithm, public_key_base64, sha256_fingerprint, approved_at
             FROM approved_host_keys WHERE connection_id=?
             ORDER BY approved_at DESC LIMIT 1",
        )
        .bind(connection_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(KnownHostKey {
                host_id: connection_id,
                algorithm: row.get("algorithm"),
                public_key_base64: row.get("public_key_base64"),
                sha256_fingerprint: row.get("sha256_fingerprint"),
                approved_at: parse_timestamp(row.get("approved_at"), "approval timestamp")?,
            })
        })
        .transpose()
    }

    pub async fn approve_host_key(
        &self,
        connection_id: Uuid,
        key: &HostKeyInfo,
        replace_changed_key: bool,
    ) -> Result<(), StorageError> {
        if self.get(connection_id).await?.host.ssh.hostname != key.hostname {
            return Err(StorageError::InvalidData(
                "host-key hostname does not match the connection".into(),
            ));
        }
        if let Some(approved) = self.approved_host_key(connection_id).await?
            && (approved.algorithm != key.algorithm
                || approved.public_key_base64 != key.public_key_base64)
            && !replace_changed_key
        {
            return Err(StorageError::HostKeyChanged);
        }
        let mut transaction = self.pool.begin().await?;
        if replace_changed_key {
            sqlx::query("DELETE FROM approved_host_keys WHERE connection_id=?")
                .bind(connection_id.to_string())
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query(
            "INSERT INTO approved_host_keys
             (connection_id, algorithm, public_key_base64, sha256_fingerprint, approved_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(connection_id, algorithm) DO UPDATE SET
               public_key_base64=excluded.public_key_base64,
               sha256_fingerprint=excluded.sha256_fingerprint,
               approved_at=excluded.approved_at",
        )
        .bind(connection_id.to_string())
        .bind(&key.algorithm)
        .bind(&key.public_key_base64)
        .bind(&key.sha256_fingerprint)
        .bind(Utc::now().to_rfc3339())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedAuthoritySnapshot {
    pub synchronized_at: DateTime<Utc>,
    pub snapshot: AuthoritySnapshot,
}

#[derive(Clone, Debug)]
pub struct AuthorityCache {
    pool: SqlitePool,
}

impl AuthorityCache {
    pub async fn open(path: &Path) -> Result<Self, StorageError> {
        let pool = open_database(path).await?;
        CACHE_MIGRATOR.run(&pool).await?;
        #[cfg(unix)]
        protect_local_database(path)?;
        Ok(Self { pool })
    }

    pub async fn in_memory() -> Result<Self, StorageError> {
        let pool = open_memory_database().await?;
        CACHE_MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn replace(
        &self,
        snapshot: &AuthoritySnapshot,
        synchronized_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        snapshot
            .info
            .ensure_compatible()
            .map_err(|error| StorageError::InvalidData(error.to_string()))?;
        let revision = i64::try_from(snapshot.info.revision)
            .map_err(|_| StorageError::InvalidData("authority revision is too large".into()))?;
        let changed = sqlx::query(
            "INSERT INTO authority_snapshots
             (appliance_id, revision, protocol_version, schema_version,
              software_version, synchronized_at, snapshot_json)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(appliance_id) DO UPDATE SET
               revision=excluded.revision,
               protocol_version=excluded.protocol_version,
               schema_version=excluded.schema_version,
               software_version=excluded.software_version,
               synchronized_at=excluded.synchronized_at,
               snapshot_json=excluded.snapshot_json
             WHERE excluded.revision >= authority_snapshots.revision",
        )
        .bind(snapshot.info.appliance_id.to_string())
        .bind(revision)
        .bind(i64::from(snapshot.info.protocol_version))
        .bind(i64::from(snapshot.info.schema_version))
        .bind(&snapshot.info.software_version)
        .bind(synchronized_at.to_rfc3339())
        .bind(serde_json::to_string(snapshot)?)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(StorageError::InvalidData(
                "an older authority revision cannot replace a newer cached generation".into(),
            ));
        }
        Ok(())
    }

    pub async fn get(
        &self,
        appliance_id: Uuid,
    ) -> Result<Option<CachedAuthoritySnapshot>, StorageError> {
        let row = sqlx::query(
            "SELECT synchronized_at, snapshot_json FROM authority_snapshots WHERE appliance_id=?",
        )
        .bind(appliance_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let snapshot: AuthoritySnapshot = serde_json::from_str(row.get("snapshot_json"))?;
            if snapshot.info.appliance_id != appliance_id {
                return Err(StorageError::InvalidData(
                    "cached snapshot appliance identity does not match its key".into(),
                ));
            }
            Ok(CachedAuthoritySnapshot {
                synchronized_at: parse_timestamp(
                    row.get("synchronized_at"),
                    "cache synchronization timestamp",
                )?,
                snapshot,
            })
        })
        .transpose()
    }

    pub async fn remove(&self, appliance_id: Uuid) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM authority_snapshots WHERE appliance_id=?")
            .bind(appliance_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear(&self) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM authority_snapshots")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

async fn open_database(path: &Path) -> Result<SqlitePool, StorageError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
    }
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
        .create_if_missing(true)
        .foreign_keys(true);
    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?)
}

async fn open_memory_database() -> Result<SqlitePool, StorageError> {
    let options = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
    Ok(SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?)
}

fn connection_record(
    connection_id: Uuid,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ConnectionRecord, StorageError> {
    let host: DockerHost = serde_json::from_str(row.get("model_json"))?;
    if host.id != connection_id {
        return Err(StorageError::InvalidData(
            "stored connection model ID does not match its key".into(),
        ));
    }
    let appliance_id = row
        .get::<Option<&str>, _>("appliance_id")
        .map(|value| parse_uuid(value, "appliance ID"))
        .transpose()?;
    Ok(ConnectionRecord {
        connection_id,
        appliance_id,
        host,
    })
}

fn parse_uuid(value: &str, label: &str) -> Result<Uuid, StorageError> {
    Uuid::parse_str(value).map_err(|_| StorageError::InvalidData(format!("invalid {label}")))
}

fn parse_timestamp(value: &str, label: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| StorageError::InvalidData(format!("invalid {label}")))
}

#[cfg(unix)]
fn protect_local_database(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(sqlx::Error::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use vam_authority::{AUTHORITY_PROTOCOL_VERSION, AUTHORITY_SCHEMA_VERSION, AuthorityInfo};
    use vam_core::SshConnectionConfig;

    use super::*;

    fn host(id: Uuid) -> DockerHost {
        let now = Utc::now();
        DockerHost {
            id,
            display_name: "Primary appliance".into(),
            ssh: SshConnectionConfig {
                hostname: "vpn.example.test".into(),
                port: 22,
                username: "operator".into(),
                private_key_path: PathBuf::from("operator-key"),
                passphrase_ref: None,
            },
            created_at: now,
            updated_at: now,
        }
    }

    fn snapshot(appliance_id: Uuid, revision: u64) -> AuthoritySnapshot {
        AuthoritySnapshot {
            info: AuthorityInfo {
                appliance_id,
                revision,
                protocol_version: AUTHORITY_PROTOCOL_VERSION,
                schema_version: AUTHORITY_SCHEMA_VERSION,
                software_version: "test".into(),
            },
            instances: Vec::new(),
            users: Vec::new(),
            devices: Vec::new(),
            dns_records: Vec::new(),
            settings: BTreeMap::default(),
            deployments: Vec::new(),
            deployment_events: Vec::new(),
            backups: Vec::new(),
            activity: Vec::new(),
            secrets: Vec::new(),
        }
    }

    #[tokio::test]
    async fn connections_bind_appliances_and_keep_host_trust_local() {
        let store = ConnectionStore::in_memory().await.unwrap();
        let connection_id = Uuid::new_v4();
        let appliance_id = Uuid::new_v4();
        let host = host(connection_id);
        store
            .save(&ConnectionRecord {
                connection_id,
                appliance_id: None,
                host: host.clone(),
            })
            .await
            .unwrap();
        store
            .bind_appliance(connection_id, appliance_id)
            .await
            .unwrap();
        store
            .approve_host_key(
                connection_id,
                &HostKeyInfo {
                    hostname: host.ssh.hostname.clone(),
                    resolved_address: "192.0.2.10".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    sha256_fingerprint: "SHA256:approved".into(),
                    public_key_base64: "approved-key".into(),
                },
                false,
            )
            .await
            .unwrap();

        let restored = store.get(connection_id).await.unwrap();
        assert_eq!(restored.appliance_id, Some(appliance_id));
        assert_eq!(restored.host, host);
        assert_eq!(
            store
                .approved_host_key(connection_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_base64,
            "approved-key"
        );
    }

    #[tokio::test]
    async fn appliance_binding_is_unique_across_local_connections() {
        let store = ConnectionStore::in_memory().await.unwrap();
        let appliance_id = Uuid::new_v4();
        for id in [Uuid::new_v4(), Uuid::new_v4()] {
            store
                .save(&ConnectionRecord {
                    connection_id: id,
                    appliance_id: None,
                    host: host(id),
                })
                .await
                .unwrap();
        }
        let connections = store.list().await.unwrap();
        store
            .bind_appliance(connections[0].connection_id, appliance_id)
            .await
            .unwrap();
        assert!(matches!(
            store
                .bind_appliance(connections[1].connection_id, appliance_id)
                .await,
            Err(StorageError::Database(_))
        ));
    }

    #[tokio::test]
    async fn cache_file_is_disposable_and_reconstructible_without_connection_loss() {
        let directory = tempfile::tempdir().unwrap();
        let connections_path = directory.path().join("connections.sqlite");
        let cache_path = directory.path().join("cache.sqlite");
        let connection_id = Uuid::new_v4();
        let appliance_id = Uuid::new_v4();

        let connections = ConnectionStore::open(&connections_path).await.unwrap();
        connections
            .save(&ConnectionRecord {
                connection_id,
                appliance_id: Some(appliance_id),
                host: host(connection_id),
            })
            .await
            .unwrap();
        let cache = AuthorityCache::open(&cache_path).await.unwrap();
        cache
            .replace(&snapshot(appliance_id, 7), Utc::now())
            .await
            .unwrap();
        assert_eq!(
            cache
                .get(appliance_id)
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .info
                .revision,
            7
        );

        cache.close().await;
        drop(cache);
        std::fs::remove_file(&cache_path).unwrap();
        let rebuilt = AuthorityCache::open(&cache_path).await.unwrap();
        assert!(rebuilt.get(appliance_id).await.unwrap().is_none());
        rebuilt
            .replace(&snapshot(appliance_id, 8), Utc::now())
            .await
            .unwrap();
        assert_eq!(
            rebuilt
                .get(appliance_id)
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .info
                .revision,
            8
        );
        assert_eq!(
            connections.get(connection_id).await.unwrap().appliance_id,
            Some(appliance_id)
        );
    }

    #[tokio::test]
    async fn cache_rejects_incompatible_generations() {
        let cache = AuthorityCache::in_memory().await.unwrap();
        let mut incompatible = snapshot(Uuid::new_v4(), 1);
        incompatible.info.protocol_version += 1;
        assert!(matches!(
            cache.replace(&incompatible, Utc::now()).await,
            Err(StorageError::InvalidData(_))
        ));
    }

    #[tokio::test]
    async fn cache_never_regresses_an_appliance_revision() {
        let cache = AuthorityCache::in_memory().await.unwrap();
        let appliance_id = Uuid::new_v4();
        cache
            .replace(&snapshot(appliance_id, 4), Utc::now())
            .await
            .unwrap();
        assert!(matches!(
            cache.replace(&snapshot(appliance_id, 3), Utc::now()).await,
            Err(StorageError::InvalidData(_))
        ));
        assert_eq!(
            cache
                .get(appliance_id)
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .info
                .revision,
            4
        );
    }
}
