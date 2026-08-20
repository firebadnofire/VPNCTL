use std::{collections::BTreeMap, fmt, path::Path, str::FromStr, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{
    Row, SqlitePool, Transaction,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use thiserror::Error;
use uuid::Uuid;
use vam_core::{DesiredState, Device, DnsRecord, User, VpnInstance};
use vam_protocol::{DeploymentPlan, DeploymentProgress, DeploymentStatus, DeploymentSummary};
use zeroize::Zeroize;

pub const AUTHORITY_PROTOCOL_VERSION: u32 = 1;
pub const AUTHORITY_SCHEMA_VERSION: u32 = 1;
pub const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LEASE_SECONDS: u64 = 15 * 60;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("authority filesystem operation failed: {0}")]
    Filesystem(#[from] std::io::Error),
    #[error("authority revision conflict: expected {expected}, current {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("authority is busy with {scope} until {expires_at}")]
    Busy {
        scope: String,
        expires_at: DateTime<Utc>,
    },
    #[error("authority mutation lease is invalid or expired")]
    InvalidLease,
    #[error("authority record was not found")]
    NotFound,
    #[error("authority state is invalid: {0}")]
    InvalidState(String),
    #[error(
        "authority protocol {remote_protocol} / schema {remote_schema} is incompatible with client protocol {local_protocol} / schema {local_schema}"
    )]
    Incompatible {
        local_protocol: u32,
        local_schema: u32,
        remote_protocol: u32,
        remote_schema: u32,
    },
}

impl AuthorityError {
    #[must_use]
    pub fn failure(&self) -> AuthorityFailure {
        match self {
            Self::RevisionConflict { expected, actual } => AuthorityFailure {
                code: AuthorityFailureCode::RevisionConflict,
                message: self.to_string(),
                expected_revision: Some(*expected),
                current_revision: Some(*actual),
                lease_expires_at: None,
            },
            Self::Busy { expires_at, .. } => AuthorityFailure {
                code: AuthorityFailureCode::Busy,
                message: self.to_string(),
                expected_revision: None,
                current_revision: None,
                lease_expires_at: Some(*expires_at),
            },
            Self::InvalidLease => {
                AuthorityFailure::new(AuthorityFailureCode::InvalidLease, self.to_string())
            }
            Self::NotFound => {
                AuthorityFailure::new(AuthorityFailureCode::NotFound, self.to_string())
            }
            Self::InvalidState(_) => {
                AuthorityFailure::new(AuthorityFailureCode::InvalidRequest, self.to_string())
            }
            Self::Incompatible { .. } => {
                AuthorityFailure::new(AuthorityFailureCode::Incompatible, self.to_string())
            }
            Self::Database(_) | Self::Migration(_) | Self::Filesystem(_) => AuthorityFailure::new(
                AuthorityFailureCode::Internal,
                "The appliance authority operation failed.",
            ),
            Self::Serialization(_) => AuthorityFailure::new(
                AuthorityFailureCode::InvalidRequest,
                "The authority request or stored state is invalid.",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityFailureCode {
    InvalidRequest,
    Incompatible,
    RevisionConflict,
    Busy,
    InvalidLease,
    NotFound,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityFailure {
    pub code: AuthorityFailureCode,
    pub message: String,
    pub expected_revision: Option<u64>,
    pub current_revision: Option<u64>,
    pub lease_expires_at: Option<DateTime<Utc>>,
}

impl AuthorityFailure {
    fn new(code: AuthorityFailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            expected_revision: None,
            current_revision: None,
            lease_expires_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityRequestEnvelope {
    pub protocol_version: u32,
    pub request_id: Uuid,
    pub appliance_id: Option<Uuid>,
    pub operation: AuthorityOperation,
}

impl AuthorityRequestEnvelope {
    pub fn validate_protocol(&self) -> Result<(), AuthorityError> {
        if self.protocol_version != AUTHORITY_PROTOCOL_VERSION {
            return Err(AuthorityError::Incompatible {
                local_protocol: AUTHORITY_PROTOCOL_VERSION,
                local_schema: AUTHORITY_SCHEMA_VERSION,
                remote_protocol: self.protocol_version,
                remote_schema: AUTHORITY_SCHEMA_VERSION,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum AuthorityOperation {
    Info,
    Snapshot {
        known_revision: Option<u64>,
    },
    AcquireLease {
        expected_revision: u64,
        owner: Uuid,
        scope: String,
        ttl_seconds: u64,
    },
    RenewLease {
        lease: MutationLease,
        ttl_seconds: u64,
    },
    AbortLease {
        lease: MutationLease,
    },
    Commit {
        lease: MutationLease,
        changes: Box<AuthorityChangeSet>,
    },
    GetSecrets {
        ids: Vec<Uuid>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityResponseEnvelope {
    pub protocol_version: u32,
    pub request_id: Uuid,
    pub result: Result<AuthorityResponse, AuthorityFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum AuthorityResponse {
    Info(AuthorityInfo),
    NotModified(AuthorityInfo),
    Snapshot(Box<AuthoritySnapshot>),
    Lease(MutationLease),
    LeaseAborted,
    Committed(CommitResult),
    Secrets { values: Vec<SecretPut> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityInfo {
    pub appliance_id: Uuid,
    pub revision: u64,
    pub protocol_version: u32,
    pub schema_version: u32,
}

impl AuthorityInfo {
    pub fn ensure_compatible(&self) -> Result<(), AuthorityError> {
        if self.protocol_version != AUTHORITY_PROTOCOL_VERSION
            || self.schema_version != AUTHORITY_SCHEMA_VERSION
        {
            return Err(AuthorityError::Incompatible {
                local_protocol: AUTHORITY_PROTOCOL_VERSION,
                local_schema: AUTHORITY_SCHEMA_VERSION,
                remote_protocol: self.protocol_version,
                remote_schema: self.schema_version,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationLease {
    pub token: Uuid,
    pub owner: Uuid,
    pub scope: String,
    pub base_revision: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretValue(#[serde(with = "base64_value")] Vec<u8>);

impl SecretValue {
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn sha256_hex(&self) -> String {
        digest_hex(&Sha256::digest(&self.0).into())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretValue")
            .field("bytes", &self.0.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

mod base64_value {
    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64.encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        BASE64.decode(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretPut {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub value: SecretValue,
}

impl fmt::Debug for SecretPut {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretPut")
            .field("id", &self.id)
            .field("owner_id", &self.owner_id)
            .field("purpose", &self.purpose)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDeployment {
    pub summary: DeploymentSummary,
    pub desired_state: DesiredState,
    pub plan: DeploymentPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredDeploymentEvent {
    pub progress: DeploymentProgress,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupRecord {
    pub instance_id: Uuid,
    pub name: String,
    pub backend: String,
    pub reason: String,
    pub protects_identity: bool,
    pub deployment_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityRecord {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub operation: String,
    pub title: String,
    pub message: String,
    pub technical_detail: Option<String>,
    pub instance_id: Option<Uuid>,
    pub backend: Option<String>,
    pub deployment_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthoritySnapshot {
    pub info: AuthorityInfo,
    pub instances: Vec<VpnInstance>,
    pub users: Vec<User>,
    pub devices: Vec<Device>,
    pub dns_records: Vec<DnsRecord>,
    pub settings: BTreeMap<String, serde_json::Value>,
    pub deployments: Vec<StoredDeployment>,
    pub deployment_events: Vec<StoredDeploymentEvent>,
    pub backups: Vec<BackupRecord>,
    pub activity: Vec<ActivityRecord>,
    pub secrets: Vec<SecretMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuthorityChangeSet {
    #[serde(default)]
    pub upsert_instances: Vec<VpnInstance>,
    #[serde(default)]
    pub delete_instances: Vec<Uuid>,
    #[serde(default)]
    pub upsert_users: Vec<User>,
    #[serde(default)]
    pub delete_users: Vec<Uuid>,
    #[serde(default)]
    pub upsert_devices: Vec<Device>,
    #[serde(default)]
    pub delete_devices: Vec<Uuid>,
    #[serde(default)]
    pub upsert_dns_records: Vec<DnsRecord>,
    #[serde(default)]
    pub delete_dns_records: Vec<Uuid>,
    #[serde(default)]
    pub upsert_settings: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    pub delete_settings: Vec<String>,
    #[serde(default)]
    pub upsert_deployments: Vec<StoredDeployment>,
    #[serde(default)]
    pub upsert_deployment_events: Vec<StoredDeploymentEvent>,
    #[serde(default)]
    pub upsert_backups: Vec<BackupRecord>,
    #[serde(default)]
    pub upsert_activity: Vec<ActivityRecord>,
    #[serde(default)]
    pub put_secrets: Vec<SecretPut>,
    #[serde(default)]
    pub delete_secrets: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitResult {
    pub previous_revision: u64,
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub struct AuthorityStore {
    pool: SqlitePool,
}

impl AuthorityStore {
    pub async fn open(path: &Path, appliance_id: Uuid) -> Result<Self, AuthorityError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            set_directory_permissions(parent)?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        let store = Self { pool };
        store.initialize(appliance_id).await?;
        #[cfg(unix)]
        set_file_permissions(path)?;
        Ok(store)
    }

    pub async fn in_memory(appliance_id: Uuid) -> Result<Self, AuthorityError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        let store = Self { pool };
        store.initialize(appliance_id).await?;
        Ok(store)
    }

    async fn initialize(&self, appliance_id: Uuid) -> Result<(), AuthorityError> {
        sqlx::query(
            "INSERT INTO authority_meta
             (singleton, appliance_id, revision, protocol_version, schema_version)
             VALUES (1, ?, 0, ?, ?)
             ON CONFLICT(singleton) DO NOTHING",
        )
        .bind(appliance_id.to_string())
        .bind(i64::from(AUTHORITY_PROTOCOL_VERSION))
        .bind(i64::from(AUTHORITY_SCHEMA_VERSION))
        .execute(&self.pool)
        .await?;
        let info = self.info().await?;
        if info.appliance_id != appliance_id {
            return Err(AuthorityError::InvalidState(format!(
                "database belongs to appliance {}, not {appliance_id}",
                info.appliance_id
            )));
        }
        Ok(())
    }

    pub async fn info(&self) -> Result<AuthorityInfo, AuthorityError> {
        let row = sqlx::query(
            "SELECT appliance_id, revision, protocol_version, schema_version
             FROM authority_meta WHERE singleton = 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuthorityError::NotFound)?;
        authority_info(&row)
    }

    pub async fn snapshot(&self) -> Result<AuthoritySnapshot, AuthorityError> {
        let info = self.info().await?;
        info.ensure_compatible()?;
        let instances = json_models(
            sqlx::query("SELECT model_json FROM vpn_instances ORDER BY id")
                .fetch_all(&self.pool)
                .await?,
        )?;
        let users = json_models(
            sqlx::query("SELECT model_json FROM users ORDER BY id")
                .fetch_all(&self.pool)
                .await?,
        )?;
        let devices = json_models(
            sqlx::query("SELECT model_json FROM devices ORDER BY id")
                .fetch_all(&self.pool)
                .await?,
        )?;
        let dns_records = json_models(
            sqlx::query("SELECT model_json FROM dns_records ORDER BY id")
                .fetch_all(&self.pool)
                .await?,
        )?;
        let setting_rows = sqlx::query("SELECT key, value_json FROM settings ORDER BY key")
            .fetch_all(&self.pool)
            .await?;
        let settings = setting_rows
            .into_iter()
            .map(|row| Ok((row.get("key"), serde_json::from_str(row.get("value_json"))?)))
            .collect::<Result<_, AuthorityError>>()?;
        let deployments = deployment_rows(&self.pool).await?;
        let deployment_events = deployment_event_rows(&self.pool).await?;
        let backups = backup_rows(&self.pool).await?;
        let activity = activity_rows(&self.pool).await?;
        let secrets = secret_metadata_rows(&self.pool).await?;
        Ok(AuthoritySnapshot {
            info,
            instances,
            users,
            devices,
            dns_records,
            settings,
            deployments,
            deployment_events,
            backups,
            activity,
            secrets,
        })
    }

    pub async fn acquire_lease(
        &self,
        expected_revision: u64,
        owner: Uuid,
        scope: &str,
        ttl: Duration,
    ) -> Result<MutationLease, AuthorityError> {
        if scope.trim().is_empty() {
            return Err(AuthorityError::InvalidState(
                "mutation lease scope is required".into(),
            ));
        }
        let ttl_seconds = ttl.as_secs();
        if ttl_seconds == 0 || ttl_seconds > MAX_LEASE_SECONDS {
            return Err(AuthorityError::InvalidState(format!(
                "mutation lease duration must be between 1 and {MAX_LEASE_SECONDS} seconds"
            )));
        }
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::seconds(i64::try_from(ttl_seconds).map_err(|error| {
                AuthorityError::InvalidState(format!("lease duration is invalid: {error}"))
            })?);
        let lease = MutationLease {
            token: Uuid::new_v4(),
            owner,
            scope: scope.trim().to_owned(),
            base_revision: expected_revision,
            expires_at,
        };
        let result = sqlx::query(
            "UPDATE authority_meta
             SET lease_token=?, lease_owner=?, lease_scope=?, lease_base_revision=?,
                 lease_expires_at=?
             WHERE singleton=1 AND revision=?
               AND (lease_token IS NULL OR lease_expires_at <= ?)",
        )
        .bind(lease.token.to_string())
        .bind(lease.owner.to_string())
        .bind(&lease.scope)
        .bind(to_i64(expected_revision, "revision")?)
        .bind(lease.expires_at.to_rfc3339())
        .bind(to_i64(expected_revision, "revision")?)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(lease);
        }
        self.lease_failure(expected_revision, now).await
    }

    async fn lease_failure<T>(
        &self,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<T, AuthorityError> {
        let row = sqlx::query(
            "SELECT revision, lease_scope, lease_expires_at
             FROM authority_meta WHERE singleton=1",
        )
        .fetch_one(&self.pool)
        .await?;
        let actual = to_u64(row.get("revision"), "revision")?;
        if actual != expected_revision {
            return Err(AuthorityError::RevisionConflict {
                expected: expected_revision,
                actual,
            });
        }
        let scope: Option<String> = row.get("lease_scope");
        let expires_at: Option<String> = row.get("lease_expires_at");
        if let (Some(scope), Some(expires_at)) = (scope, expires_at) {
            let expires_at = parse_datetime(&expires_at)?;
            if expires_at > now {
                return Err(AuthorityError::Busy { scope, expires_at });
            }
        }
        Err(AuthorityError::InvalidLease)
    }

    pub async fn renew_lease(
        &self,
        lease: &MutationLease,
        ttl: Duration,
    ) -> Result<MutationLease, AuthorityError> {
        let ttl_seconds = ttl.as_secs();
        if ttl_seconds == 0 || ttl_seconds > MAX_LEASE_SECONDS {
            return Err(AuthorityError::InvalidState(format!(
                "mutation lease duration must be between 1 and {MAX_LEASE_SECONDS} seconds"
            )));
        }
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::seconds(i64::try_from(ttl_seconds).map_err(|error| {
                AuthorityError::InvalidState(format!("lease duration is invalid: {error}"))
            })?);
        let result = sqlx::query(
            "UPDATE authority_meta SET lease_expires_at=?
             WHERE singleton=1 AND revision=? AND lease_token=? AND lease_owner=?
               AND lease_base_revision=? AND lease_expires_at>?",
        )
        .bind(expires_at.to_rfc3339())
        .bind(to_i64(lease.base_revision, "revision")?)
        .bind(lease.token.to_string())
        .bind(lease.owner.to_string())
        .bind(to_i64(lease.base_revision, "revision")?)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AuthorityError::InvalidLease);
        }
        Ok(MutationLease {
            expires_at,
            ..lease.clone()
        })
    }

    pub async fn abort_lease(&self, lease: &MutationLease) -> Result<(), AuthorityError> {
        let result = sqlx::query(
            "UPDATE authority_meta
             SET lease_token=NULL, lease_owner=NULL, lease_scope=NULL,
                 lease_base_revision=NULL, lease_expires_at=NULL
             WHERE singleton=1 AND lease_token=? AND lease_owner=?",
        )
        .bind(lease.token.to_string())
        .bind(lease.owner.to_string())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AuthorityError::InvalidLease);
        }
        Ok(())
    }

    pub async fn commit(
        &self,
        lease: &MutationLease,
        changes: &AuthorityChangeSet,
    ) -> Result<CommitResult, AuthorityError> {
        self.validate_changes(changes).await?;
        let mut transaction = self.pool.begin().await?;
        apply_changes(&mut transaction, changes).await?;
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE authority_meta
             SET revision=revision+1, lease_token=NULL, lease_owner=NULL,
                 lease_scope=NULL, lease_base_revision=NULL, lease_expires_at=NULL
             WHERE singleton=1 AND revision=? AND lease_token=? AND lease_owner=?
               AND lease_base_revision=? AND lease_expires_at>?",
        )
        .bind(to_i64(lease.base_revision, "revision")?)
        .bind(lease.token.to_string())
        .bind(lease.owner.to_string())
        .bind(to_i64(lease.base_revision, "revision")?)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            transaction.rollback().await?;
            let actual = self.info().await?.revision;
            if actual != lease.base_revision {
                return Err(AuthorityError::RevisionConflict {
                    expected: lease.base_revision,
                    actual,
                });
            }
            return Err(AuthorityError::InvalidLease);
        }
        transaction.commit().await?;
        Ok(CommitResult {
            previous_revision: lease.base_revision,
            revision: lease.base_revision + 1,
        })
    }

    async fn validate_changes(&self, changes: &AuthorityChangeSet) -> Result<(), AuthorityError> {
        let appliance_id = self.info().await?.appliance_id;
        for instance in &changes.upsert_instances {
            if instance.host_id != appliance_id {
                return Err(AuthorityError::InvalidState(format!(
                    "instance {} belongs to host {}, not appliance {appliance_id}",
                    instance.id, instance.host_id
                )));
            }
        }
        for deployment in &changes.upsert_deployments {
            if deployment.summary.instance_id != deployment.desired_state.instance.id
                || deployment.plan.instance_id != deployment.summary.instance_id
            {
                return Err(AuthorityError::InvalidState(format!(
                    "deployment {} has inconsistent instance identity",
                    deployment.summary.id
                )));
            }
        }
        for secret in &changes.put_secrets {
            if secret.purpose.trim().is_empty() {
                return Err(AuthorityError::InvalidState(format!(
                    "secret {} has no purpose",
                    secret.id
                )));
            }
            if secret.value.as_bytes().is_empty()
                || secret.value.as_bytes().len() > MAX_SECRET_BYTES
            {
                return Err(AuthorityError::InvalidState(format!(
                    "secret {} must contain between 1 and {MAX_SECRET_BYTES} bytes",
                    secret.id
                )));
            }
        }
        if changes
            .upsert_settings
            .keys()
            .chain(&changes.delete_settings)
            .any(|key| key.trim().is_empty())
        {
            return Err(AuthorityError::InvalidState(
                "authority setting key is required".into(),
            ));
        }
        Ok(())
    }

    pub async fn get_secrets(&self, ids: &[Uuid]) -> Result<Vec<SecretPut>, AuthorityError> {
        let mut secrets = Vec::with_capacity(ids.len());
        for id in ids {
            let row = sqlx::query("SELECT id, owner_id, purpose, value FROM secrets WHERE id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?
                .ok_or(AuthorityError::NotFound)?;
            secrets.push(SecretPut {
                id: parse_uuid(row.get("id"))?,
                owner_id: parse_uuid(row.get("owner_id"))?,
                purpose: row.get("purpose"),
                value: SecretValue::new(row.get("value")),
            });
        }
        Ok(secrets)
    }

    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

async fn apply_changes(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    changes: &AuthorityChangeSet,
) -> Result<(), AuthorityError> {
    for id in &changes.delete_dns_records {
        sqlx::query("DELETE FROM dns_records WHERE id=?")
            .bind(id.to_string())
            .execute(&mut **transaction)
            .await?;
    }
    for id in &changes.delete_devices {
        sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(id.to_string())
            .execute(&mut **transaction)
            .await?;
    }
    for id in &changes.delete_instances {
        sqlx::query("DELETE FROM vpn_instances WHERE id=?")
            .bind(id.to_string())
            .execute(&mut **transaction)
            .await?;
    }
    for id in &changes.delete_users {
        sqlx::query("DELETE FROM users WHERE id=?")
            .bind(id.to_string())
            .execute(&mut **transaction)
            .await?;
    }
    for key in &changes.delete_settings {
        sqlx::query("DELETE FROM settings WHERE key=?")
            .bind(key)
            .execute(&mut **transaction)
            .await?;
    }
    for id in &changes.delete_secrets {
        sqlx::query("DELETE FROM secrets WHERE id=?")
            .bind(id.to_string())
            .execute(&mut **transaction)
            .await?;
    }
    for instance in &changes.upsert_instances {
        sqlx::query(
            "INSERT INTO vpn_instances (id, model_json, deleted_at) VALUES (?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               model_json=excluded.model_json, deleted_at=excluded.deleted_at",
        )
        .bind(instance.id.to_string())
        .bind(serde_json::to_string(instance)?)
        .bind(instance.deleted_at.map(|value| value.to_rfc3339()))
        .execute(&mut **transaction)
        .await?;
    }
    for user in &changes.upsert_users {
        sqlx::query(
            "INSERT INTO users (id, model_json) VALUES (?, ?)
             ON CONFLICT(id) DO UPDATE SET model_json=excluded.model_json",
        )
        .bind(user.id.to_string())
        .bind(serde_json::to_string(user)?)
        .execute(&mut **transaction)
        .await?;
    }
    for device in &changes.upsert_devices {
        sqlx::query(
            "INSERT INTO devices (id, instance_id, model_json, deleted_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,
               model_json=excluded.model_json, deleted_at=excluded.deleted_at",
        )
        .bind(device.id.to_string())
        .bind(device.instance_id.to_string())
        .bind(serde_json::to_string(device)?)
        .bind(device.deleted_at.map(|value| value.to_rfc3339()))
        .execute(&mut **transaction)
        .await?;
    }
    for record in &changes.upsert_dns_records {
        sqlx::query(
            "INSERT INTO dns_records (id, instance_id, model_json) VALUES (?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET instance_id=excluded.instance_id,
               model_json=excluded.model_json",
        )
        .bind(record.id.to_string())
        .bind(record.instance_id.to_string())
        .bind(serde_json::to_string(record)?)
        .execute(&mut **transaction)
        .await?;
    }
    for (key, value) in &changes.upsert_settings {
        sqlx::query(
            "INSERT INTO settings (key, value_json) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
        )
        .bind(key)
        .bind(serde_json::to_string(value)?)
        .execute(&mut **transaction)
        .await?;
    }
    for deployment in &changes.upsert_deployments {
        let summary = &deployment.summary;
        sqlx::query(
            "INSERT INTO deployments
             (id, instance_id, status, desired_state_json, plan_json, backup_name,
              started_at, finished_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET status=excluded.status,
               desired_state_json=excluded.desired_state_json,
               plan_json=excluded.plan_json, backup_name=excluded.backup_name,
               started_at=excluded.started_at, finished_at=excluded.finished_at",
        )
        .bind(summary.id.to_string())
        .bind(summary.instance_id.to_string())
        .bind(status_name(summary.status))
        .bind(serde_json::to_string(&deployment.desired_state)?)
        .bind(serde_json::to_string(&deployment.plan)?)
        .bind(&summary.backup_name)
        .bind(summary.started_at.to_rfc3339())
        .bind(summary.finished_at.map(|value| value.to_rfc3339()))
        .execute(&mut **transaction)
        .await?;
    }
    for event in &changes.upsert_deployment_events {
        let progress = &event.progress;
        sqlx::query(
            "INSERT INTO deployment_events
             (deployment_id, sequence, timestamp, level, phase, message, technical_detail)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(deployment_id, sequence) DO UPDATE SET
               timestamp=excluded.timestamp, level=excluded.level, phase=excluded.phase,
               message=excluded.message, technical_detail=excluded.technical_detail",
        )
        .bind(progress.deployment_id.to_string())
        .bind(to_i64(progress.sequence, "deployment event sequence")?)
        .bind(progress.timestamp.to_rfc3339())
        .bind(&event.level)
        .bind(&progress.phase)
        .bind(&progress.message)
        .bind(&progress.technical_detail)
        .execute(&mut **transaction)
        .await?;
    }
    for backup in &changes.upsert_backups {
        sqlx::query(
            "INSERT INTO backup_records
             (instance_id, name, backend, reason, protects_identity, deployment_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(instance_id, name) DO UPDATE SET backend=excluded.backend,
               reason=excluded.reason, protects_identity=excluded.protects_identity,
               deployment_id=excluded.deployment_id, created_at=excluded.created_at",
        )
        .bind(backup.instance_id.to_string())
        .bind(&backup.name)
        .bind(&backup.backend)
        .bind(&backup.reason)
        .bind(backup.protects_identity)
        .bind(backup.deployment_id.map(|id| id.to_string()))
        .bind(backup.created_at.to_rfc3339())
        .execute(&mut **transaction)
        .await?;
    }
    for activity in &changes.upsert_activity {
        sqlx::query(
            "INSERT INTO activity_events
             (id, timestamp, severity, operation, title, message, technical_detail,
              instance_id, backend, deployment_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET timestamp=excluded.timestamp,
               severity=excluded.severity, operation=excluded.operation,
               title=excluded.title, message=excluded.message,
               technical_detail=excluded.technical_detail,
               instance_id=excluded.instance_id, backend=excluded.backend,
               deployment_id=excluded.deployment_id",
        )
        .bind(activity.id.to_string())
        .bind(activity.timestamp.to_rfc3339())
        .bind(&activity.severity)
        .bind(&activity.operation)
        .bind(&activity.title)
        .bind(&activity.message)
        .bind(&activity.technical_detail)
        .bind(activity.instance_id.map(|id| id.to_string()))
        .bind(&activity.backend)
        .bind(activity.deployment_id.map(|id| id.to_string()))
        .execute(&mut **transaction)
        .await?;
    }
    let now = Utc::now().to_rfc3339();
    for secret in &changes.put_secrets {
        sqlx::query(
            "INSERT INTO secrets (id, owner_id, purpose, value, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET owner_id=excluded.owner_id,
               purpose=excluded.purpose, value=excluded.value,
               updated_at=excluded.updated_at",
        )
        .bind(secret.id.to_string())
        .bind(secret.owner_id.to_string())
        .bind(&secret.purpose)
        .bind(secret.value.as_bytes())
        .bind(&now)
        .bind(&now)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn deployment_rows(pool: &SqlitePool) -> Result<Vec<StoredDeployment>, AuthorityError> {
    let rows = sqlx::query(
        "SELECT id, instance_id, status, desired_state_json, plan_json,
                backup_name, started_at, finished_at
         FROM deployments ORDER BY started_at, id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let finished_at: Option<String> = row.get("finished_at");
            Ok(StoredDeployment {
                summary: DeploymentSummary {
                    id: parse_uuid(row.get("id"))?,
                    instance_id: parse_uuid(row.get("instance_id"))?,
                    status: parse_status(row.get("status"))?,
                    backup_name: row.get("backup_name"),
                    started_at: parse_datetime(row.get("started_at"))?,
                    finished_at: finished_at.as_deref().map(parse_datetime).transpose()?,
                },
                desired_state: serde_json::from_str(row.get("desired_state_json"))?,
                plan: serde_json::from_str(row.get("plan_json"))?,
            })
        })
        .collect()
}

async fn deployment_event_rows(
    pool: &SqlitePool,
) -> Result<Vec<StoredDeploymentEvent>, AuthorityError> {
    let rows = sqlx::query(
        "SELECT deployment_id, sequence, timestamp, level, phase, message, technical_detail
         FROM deployment_events ORDER BY timestamp, deployment_id, sequence",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(StoredDeploymentEvent {
                progress: DeploymentProgress {
                    deployment_id: parse_uuid(row.get("deployment_id"))?,
                    sequence: to_u64(row.get("sequence"), "deployment event sequence")?,
                    timestamp: parse_datetime(row.get("timestamp"))?,
                    phase: row.get("phase"),
                    message: row.get("message"),
                    technical_detail: row.get("technical_detail"),
                },
                level: row.get("level"),
            })
        })
        .collect()
}

async fn backup_rows(pool: &SqlitePool) -> Result<Vec<BackupRecord>, AuthorityError> {
    let rows = sqlx::query(
        "SELECT instance_id, name, backend, reason, protects_identity,
                deployment_id, created_at
         FROM backup_records ORDER BY created_at, instance_id, name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let deployment_id: Option<String> = row.get("deployment_id");
            Ok(BackupRecord {
                instance_id: parse_uuid(row.get("instance_id"))?,
                name: row.get("name"),
                backend: row.get("backend"),
                reason: row.get("reason"),
                protects_identity: row.get("protects_identity"),
                deployment_id: deployment_id.as_deref().map(parse_uuid).transpose()?,
                created_at: parse_datetime(row.get("created_at"))?,
            })
        })
        .collect()
}

async fn activity_rows(pool: &SqlitePool) -> Result<Vec<ActivityRecord>, AuthorityError> {
    let rows = sqlx::query(
        "SELECT id, timestamp, severity, operation, title, message, technical_detail,
                instance_id, backend, deployment_id
         FROM activity_events ORDER BY timestamp, id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let instance_id: Option<String> = row.get("instance_id");
            let deployment_id: Option<String> = row.get("deployment_id");
            Ok(ActivityRecord {
                id: parse_uuid(row.get("id"))?,
                timestamp: parse_datetime(row.get("timestamp"))?,
                severity: row.get("severity"),
                operation: row.get("operation"),
                title: row.get("title"),
                message: row.get("message"),
                technical_detail: row.get("technical_detail"),
                instance_id: instance_id.as_deref().map(parse_uuid).transpose()?,
                backend: row.get("backend"),
                deployment_id: deployment_id.as_deref().map(parse_uuid).transpose()?,
            })
        })
        .collect()
}

async fn secret_metadata_rows(pool: &SqlitePool) -> Result<Vec<SecretMetadata>, AuthorityError> {
    let rows = sqlx::query(
        "SELECT id, owner_id, purpose, created_at, updated_at FROM secrets ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(SecretMetadata {
                id: parse_uuid(row.get("id"))?,
                owner_id: parse_uuid(row.get("owner_id"))?,
                purpose: row.get("purpose"),
                created_at: parse_datetime(row.get("created_at"))?,
                updated_at: parse_datetime(row.get("updated_at"))?,
            })
        })
        .collect()
}

fn authority_info(row: &sqlx::sqlite::SqliteRow) -> Result<AuthorityInfo, AuthorityError> {
    Ok(AuthorityInfo {
        appliance_id: parse_uuid(row.get("appliance_id"))?,
        revision: to_u64(row.get("revision"), "revision")?,
        protocol_version: to_u32(row.get("protocol_version"), "protocol version")?,
        schema_version: to_u32(row.get("schema_version"), "schema version")?,
    })
}

fn json_models<T: DeserializeOwned>(
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Vec<T>, AuthorityError> {
    rows.into_iter()
        .map(|row| serde_json::from_str(row.get("model_json")).map_err(AuthorityError::from))
        .collect()
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

fn parse_status(value: &str) -> Result<DeploymentStatus, AuthorityError> {
    match value {
        "planned" => Ok(DeploymentStatus::Planned),
        "applying" => Ok(DeploymentStatus::Applying),
        "succeeded" => Ok(DeploymentStatus::Succeeded),
        "failed" => Ok(DeploymentStatus::Failed),
        "rolledback" => Ok(DeploymentStatus::RolledBack),
        "rollbackfailed" => Ok(DeploymentStatus::RollbackFailed),
        other => Err(AuthorityError::InvalidState(format!(
            "unknown deployment status {other}"
        ))),
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, AuthorityError> {
    Uuid::parse_str(value).map_err(|error| AuthorityError::InvalidState(error.to_string()))
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>, AuthorityError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| AuthorityError::InvalidState(error.to_string()))
}

fn to_u64(value: i64, field: &str) -> Result<u64, AuthorityError> {
    u64::try_from(value)
        .map_err(|error| AuthorityError::InvalidState(format!("invalid {field}: {error}")))
}

fn to_u32(value: i64, field: &str) -> Result<u32, AuthorityError> {
    u32::try_from(value)
        .map_err(|error| AuthorityError::InvalidState(format!("invalid {field}: {error}")))
}

fn to_i64(value: u64, field: &str) -> Result<i64, AuthorityError> {
    i64::try_from(value)
        .map_err(|error| AuthorityError::InvalidState(format!("invalid {field}: {error}")))
}

fn digest_hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use vam_core::{
        BackendSettings, DnsConfig, EndpointConfig, NetworkConfig, RoutingMode, VpnBackendKind,
    };

    fn instance(appliance_id: Uuid, instance_id: Uuid) -> VpnInstance {
        let now = Utc::now();
        VpnInstance {
            id: instance_id,
            host_id: appliance_id,
            display_name: "primary".into(),
            backend: VpnBackendKind::WireGuard,
            backend_settings: BackendSettings::default(),
            endpoint: EndpointConfig {
                host: "vpn.example.com".into(),
                port: 51_820,
            },
            network: NetworkConfig {
                ipv4_subnet: "10.88.0.0/24".parse().unwrap(),
                gateway_ipv4: Ipv4Addr::new(10, 88, 0, 1),
                ipv6_subnet: None,
                gateway_ipv6: None,
            },
            dns: DnsConfig {
                zone: "vpn.internal".into(),
                soa_serial: 1,
            },
            routing_mode: RoutingMode::SplitTunnel,
            persistent_keepalive: 25,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn authority_survives_reopen_and_secret_values_are_not_in_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.sqlite");
        let appliance_id = Uuid::new_v4();
        let instance_id = Uuid::new_v4();
        let secret_id = Uuid::new_v4();
        let store = AuthorityStore::open(&path, appliance_id).await.unwrap();
        let lease = store
            .acquire_lease(0, Uuid::new_v4(), "test", Duration::from_secs(30))
            .await
            .unwrap();
        let changes = AuthorityChangeSet {
            upsert_instances: vec![instance(appliance_id, instance_id)],
            put_secrets: vec![SecretPut {
                id: secret_id,
                owner_id: instance_id,
                purpose: "wireguard_private_key".into(),
                value: SecretValue::new(b"private-value".to_vec()),
            }],
            ..AuthorityChangeSet::default()
        };
        assert_eq!(store.commit(&lease, &changes).await.unwrap().revision, 1);
        drop(store);

        let reopened = AuthorityStore::open(&path, appliance_id).await.unwrap();
        let snapshot = reopened.snapshot().await.unwrap();
        assert_eq!(snapshot.info.revision, 1);
        assert_eq!(snapshot.instances.len(), 1);
        assert_eq!(snapshot.secrets.len(), 1);
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("private-value"));
        let secrets = reopened.get_secrets(&[secret_id]).await.unwrap();
        assert_eq!(secrets[0].value.as_bytes(), b"private-value");
    }

    #[tokio::test]
    async fn revisions_and_leases_reject_stale_or_overlapping_mutations() {
        let store = AuthorityStore::in_memory(Uuid::new_v4()).await.unwrap();
        let first = store
            .acquire_lease(0, Uuid::new_v4(), "first", Duration::from_secs(30))
            .await
            .unwrap();
        let busy = store
            .acquire_lease(0, Uuid::new_v4(), "second", Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(matches!(busy, AuthorityError::Busy { .. }));
        let committed = store
            .commit(&first, &AuthorityChangeSet::default())
            .await
            .unwrap();
        assert_eq!(committed.previous_revision, 0);
        assert_eq!(committed.revision, 1);
        let stale = store
            .acquire_lease(0, Uuid::new_v4(), "stale", Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(matches!(
            stale,
            AuthorityError::RevisionConflict {
                expected: 0,
                actual: 1
            }
        ));
        assert!(matches!(
            store.commit(&first, &AuthorityChangeSet::default()).await,
            Err(AuthorityError::RevisionConflict {
                expected: 0,
                actual: 1
            })
        ));
    }

    #[tokio::test]
    async fn failed_transaction_does_not_advance_revision_or_consume_lease() {
        let appliance_id = Uuid::new_v4();
        let store = AuthorityStore::in_memory(appliance_id).await.unwrap();
        let lease = store
            .acquire_lease(0, Uuid::new_v4(), "invalid", Duration::from_secs(30))
            .await
            .unwrap();
        let missing_instance_device = Device {
            id: Uuid::new_v4(),
            instance_id: Uuid::new_v4(),
            user_id: None,
            display_name: "orphan".into(),
            ipv4_address: None,
            ipv6_address: None,
            dns_name: None,
            enabled: true,
            backend_data: vam_core::DeviceBackendData::Xray(vam_core::XrayDeviceData {
                client_id_ref: vam_core::SecretReference(Uuid::new_v4()),
                email: "orphan@example.com".into(),
                flow: None,
            }),
            created_at: Utc::now(),
            deleted_at: None,
        };
        let result = store
            .commit(
                &lease,
                &AuthorityChangeSet {
                    upsert_devices: vec![missing_instance_device],
                    ..AuthorityChangeSet::default()
                },
            )
            .await;
        assert!(matches!(result, Err(AuthorityError::Database(_))));
        assert_eq!(store.info().await.unwrap().revision, 0);
        store
            .commit(&lease, &AuthorityChangeSet::default())
            .await
            .unwrap();
        assert_eq!(store.info().await.unwrap().revision, 1);
    }

    #[test]
    fn secret_protocol_values_are_base64_and_debug_redacted() {
        let put = SecretPut {
            id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            purpose: "test".into(),
            value: SecretValue::new(b"do-not-log".to_vec()),
        };
        let debug = format!("{put:?}");
        assert!(!debug.contains("do-not-log"));
        let json = serde_json::to_string(&put).unwrap();
        assert!(!json.contains("do-not-log"));
        let decoded: SecretPut = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.value.as_bytes(), b"do-not-log");
    }

    #[test]
    fn request_envelope_round_trips_without_plaintext_debug_output() {
        let lease = MutationLease {
            token: Uuid::new_v4(),
            owner: Uuid::new_v4(),
            scope: "client-create".into(),
            base_revision: 7,
            expires_at: Utc::now() + chrono::Duration::seconds(30),
        };
        let request = AuthorityRequestEnvelope {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            appliance_id: Some(Uuid::new_v4()),
            operation: AuthorityOperation::Commit {
                lease,
                changes: Box::new(AuthorityChangeSet {
                    put_secrets: vec![SecretPut {
                        id: Uuid::new_v4(),
                        owner_id: Uuid::new_v4(),
                        purpose: "wireguard_private_key".into(),
                        value: SecretValue::new(b"envelope-secret".to_vec()),
                    }],
                    ..AuthorityChangeSet::default()
                }),
            },
        };
        assert!(!format!("{request:?}").contains("envelope-secret"));
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("envelope-secret"));
        let decoded: AuthorityRequestEnvelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);
        decoded.validate_protocol().unwrap();
    }

    #[test]
    fn compatibility_is_exact_and_fails_closed() {
        AuthorityInfo {
            appliance_id: Uuid::new_v4(),
            revision: 0,
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            schema_version: AUTHORITY_SCHEMA_VERSION,
        }
        .ensure_compatible()
        .unwrap();
        let error = AuthorityInfo {
            appliance_id: Uuid::new_v4(),
            revision: 0,
            protocol_version: AUTHORITY_PROTOCOL_VERSION + 1,
            schema_version: AUTHORITY_SCHEMA_VERSION,
        }
        .ensure_compatible()
        .unwrap_err();
        assert!(matches!(error, AuthorityError::Incompatible { .. }));
    }
}
