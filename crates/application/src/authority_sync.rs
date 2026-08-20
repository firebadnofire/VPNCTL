use std::sync::Arc;

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_authority::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityFailureCode, AuthorityOperation, AuthorityRequestEnvelope,
    AuthorityResponse,
};
use vam_authority_client::{AuthorityClientError, AuthorityExchange, AuthoritySshSession};
use vam_secrets::{SecretStore, SecretStoreError};
use vam_storage::{AuthorityCache, ConnectionStore, StorageError};
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum AuthoritySyncError {
    #[error("the local appliance connection was not found")]
    ConnectionNotFound,
    #[error("the appliance SSH host key has not been approved locally")]
    HostKeyUntrusted,
    #[error("the stored SSH passphrase is not valid UTF-8")]
    InvalidPassphrase,
    #[error("the contacted appliance identity differs from this local connection")]
    ApplianceChanged,
    #[error("the appliance returned an unexpected response")]
    UnexpectedResponse,
    #[error("the appliance authority rejected synchronization: {0:?}")]
    Remote(AuthorityFailureCode),
    #[error(transparent)]
    Exchange(#[from] AuthorityClientError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Secret(#[from] SecretStoreError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynchronizationResult {
    pub appliance_id: Uuid,
    pub revision: u64,
    pub synchronized_at: DateTime<Utc>,
    pub cache_updated: bool,
}

#[derive(Clone)]
pub struct AuthoritySynchronizer {
    connections: ConnectionStore,
    cache: AuthorityCache,
    secrets: Arc<dyn SecretStore>,
    exchange: Arc<dyn AuthorityExchange>,
}

impl AuthoritySynchronizer {
    #[must_use]
    pub fn new(
        connections: ConnectionStore,
        cache: AuthorityCache,
        secrets: Arc<dyn SecretStore>,
        exchange: Arc<dyn AuthorityExchange>,
    ) -> Self {
        Self {
            connections,
            cache,
            secrets,
            exchange,
        }
    }

    pub async fn synchronize(
        &self,
        connection_id: Uuid,
        cancellation: &CancellationToken,
    ) -> Result<SynchronizationResult, AuthoritySyncError> {
        let connection =
            self.connections
                .get(connection_id)
                .await
                .map_err(|error| match error {
                    StorageError::NotFound => AuthoritySyncError::ConnectionNotFound,
                    error => AuthoritySyncError::Storage(error),
                })?;
        let trusted = self
            .connections
            .approved_host_key(connection_id)
            .await?
            .ok_or(AuthoritySyncError::HostKeyUntrusted)?;
        let passphrase = match &connection.host.ssh.passphrase_ref {
            Some(reference) => {
                let bytes = self.secrets.get(reference).await?;
                Some(Zeroizing::new(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| AuthoritySyncError::InvalidPassphrase)?,
                ))
            }
            None => None,
        };
        let session = AuthoritySshSession {
            config: &connection.host.ssh,
            trusted_key_base64: &trusted.public_key_base64,
            passphrase: passphrase.as_ref(),
        };

        let info = self
            .exchange_operation(&session, None, AuthorityOperation::Info, cancellation)
            .await?;
        let AuthorityResponse::Info(info) = info else {
            return Err(AuthoritySyncError::UnexpectedResponse);
        };
        info.ensure_compatible()
            .map_err(|_| AuthoritySyncError::UnexpectedResponse)?;
        if connection
            .appliance_id
            .is_some_and(|expected| expected != info.appliance_id)
        {
            return Err(AuthoritySyncError::ApplianceChanged);
        }
        if connection.appliance_id.is_none() {
            self.connections
                .bind_appliance(connection_id, info.appliance_id)
                .await?;
        }
        let known_revision = self
            .cache
            .get(info.appliance_id)
            .await?
            .map(|cached| cached.snapshot.info.revision);
        let response = self
            .exchange_operation(
                &session,
                Some(info.appliance_id),
                AuthorityOperation::Snapshot { known_revision },
                cancellation,
            )
            .await?;
        let synchronized_at = Utc::now();
        match response {
            AuthorityResponse::NotModified(current)
                if current.appliance_id == info.appliance_id
                    && Some(current.revision) == known_revision =>
            {
                Ok(SynchronizationResult {
                    appliance_id: current.appliance_id,
                    revision: current.revision,
                    synchronized_at,
                    cache_updated: false,
                })
            }
            AuthorityResponse::Snapshot(snapshot)
                if snapshot.info.appliance_id == info.appliance_id =>
            {
                self.cache.replace(&snapshot, synchronized_at).await?;
                Ok(SynchronizationResult {
                    appliance_id: snapshot.info.appliance_id,
                    revision: snapshot.info.revision,
                    synchronized_at,
                    cache_updated: true,
                })
            }
            _ => Err(AuthoritySyncError::UnexpectedResponse),
        }
    }

    async fn exchange_operation(
        &self,
        session: &AuthoritySshSession<'_>,
        appliance_id: Option<Uuid>,
        operation: AuthorityOperation,
        cancellation: &CancellationToken,
    ) -> Result<AuthorityResponse, AuthoritySyncError> {
        let response = self
            .exchange
            .exchange(
                session,
                &AuthorityRequestEnvelope {
                    protocol_version: AUTHORITY_PROTOCOL_VERSION,
                    request_id: Uuid::new_v4(),
                    appliance_id,
                    operation,
                },
                cancellation,
            )
            .await?;
        response
            .result
            .map_err(|failure| AuthoritySyncError::Remote(failure.code))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        path::PathBuf,
        sync::Mutex,
    };

    use async_trait::async_trait;
    use vam_authority::{
        AUTHORITY_SCHEMA_VERSION, AuthorityInfo, AuthorityResponseEnvelope, AuthoritySnapshot,
    };
    use vam_authority_client::AuthorityClientError;
    use vam_core::{DockerHost, SshConnectionConfig};
    use vam_protocol::HostKeyInfo;
    use vam_secrets::MemorySecretStore;
    use vam_storage::ConnectionRecord;

    use super::*;

    struct ScriptedExchange {
        responses: Mutex<VecDeque<AuthorityResponse>>,
        requests: Mutex<Vec<AuthorityRequestEnvelope>>,
    }

    #[async_trait]
    impl AuthorityExchange for ScriptedExchange {
        async fn exchange(
            &self,
            session: &AuthoritySshSession<'_>,
            request: &AuthorityRequestEnvelope,
            _cancellation: &CancellationToken,
        ) -> Result<AuthorityResponseEnvelope, AuthorityClientError> {
            assert_eq!(session.trusted_key_base64, "approved-key");
            self.requests.lock().unwrap().push(request.clone());
            Ok(AuthorityResponseEnvelope {
                protocol_version: AUTHORITY_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: Ok(self.responses.lock().unwrap().pop_front().unwrap()),
            })
        }
    }

    fn info(appliance_id: Uuid, revision: u64) -> AuthorityInfo {
        AuthorityInfo {
            appliance_id,
            revision,
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            schema_version: AUTHORITY_SCHEMA_VERSION,
            software_version: "test".into(),
        }
    }

    fn snapshot(appliance_id: Uuid, revision: u64) -> AuthoritySnapshot {
        AuthoritySnapshot {
            info: info(appliance_id, revision),
            instances: Vec::new(),
            users: Vec::new(),
            devices: Vec::new(),
            dns_records: Vec::new(),
            settings: BTreeMap::new(),
            deployments: Vec::new(),
            deployment_events: Vec::new(),
            backups: Vec::new(),
            activity: Vec::new(),
            secrets: Vec::new(),
        }
    }

    async fn stores(appliance_id: Option<Uuid>) -> (ConnectionStore, AuthorityCache, Uuid) {
        let connections = ConnectionStore::in_memory().await.unwrap();
        let cache = AuthorityCache::in_memory().await.unwrap();
        let connection_id = Uuid::new_v4();
        let now = Utc::now();
        connections
            .save(&ConnectionRecord {
                connection_id,
                appliance_id,
                host: DockerHost {
                    id: connection_id,
                    display_name: "appliance".into(),
                    ssh: SshConnectionConfig {
                        hostname: "vpn.example.test".into(),
                        port: 22,
                        username: "operator".into(),
                        private_key_path: PathBuf::from("operator-key"),
                        passphrase_ref: None,
                    },
                    created_at: now,
                    updated_at: now,
                },
            })
            .await
            .unwrap();
        connections
            .approve_host_key(
                connection_id,
                &HostKeyInfo {
                    hostname: "vpn.example.test".into(),
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
        (connections, cache, connection_id)
    }

    #[tokio::test]
    async fn first_sync_binds_appliance_and_replaces_disposable_cache() {
        let appliance_id = Uuid::new_v4();
        let (connections, cache, connection_id) = stores(None).await;
        let exchange = Arc::new(ScriptedExchange {
            responses: Mutex::new(VecDeque::from([
                AuthorityResponse::Info(info(appliance_id, 3)),
                AuthorityResponse::Snapshot(Box::new(snapshot(appliance_id, 3))),
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let synchronizer = AuthoritySynchronizer::new(
            connections.clone(),
            cache.clone(),
            Arc::new(MemorySecretStore::default()),
            exchange.clone(),
        );

        let result = synchronizer
            .synchronize(connection_id, &CancellationToken::new())
            .await
            .unwrap();
        assert!(result.cache_updated);
        assert_eq!(result.revision, 3);
        assert_eq!(
            connections.get(connection_id).await.unwrap().appliance_id,
            Some(appliance_id)
        );
        assert_eq!(
            cache
                .get(appliance_id)
                .await
                .unwrap()
                .unwrap()
                .snapshot
                .info
                .revision,
            3
        );
        let requests = exchange.requests.lock().unwrap();
        assert!(matches!(requests[0].operation, AuthorityOperation::Info));
        assert!(matches!(
            requests[1].operation,
            AuthorityOperation::Snapshot {
                known_revision: None
            }
        ));
    }

    #[tokio::test]
    async fn equal_revision_skips_snapshot_replacement() {
        let appliance_id = Uuid::new_v4();
        let (connections, cache, connection_id) = stores(Some(appliance_id)).await;
        cache
            .replace(&snapshot(appliance_id, 8), Utc::now())
            .await
            .unwrap();
        let exchange = Arc::new(ScriptedExchange {
            responses: Mutex::new(VecDeque::from([
                AuthorityResponse::Info(info(appliance_id, 8)),
                AuthorityResponse::NotModified(info(appliance_id, 8)),
            ])),
            requests: Mutex::new(Vec::new()),
        });
        let result = AuthoritySynchronizer::new(
            connections,
            cache,
            Arc::new(MemorySecretStore::default()),
            exchange.clone(),
        )
        .synchronize(connection_id, &CancellationToken::new())
        .await
        .unwrap();
        assert!(!result.cache_updated);
        assert!(matches!(
            exchange.requests.lock().unwrap()[1].operation,
            AuthorityOperation::Snapshot {
                known_revision: Some(8)
            }
        ));
    }

    #[tokio::test]
    async fn changed_appliance_identity_blocks_snapshot_access() {
        let expected = Uuid::new_v4();
        let contacted = Uuid::new_v4();
        let (connections, cache, connection_id) = stores(Some(expected)).await;
        let exchange = Arc::new(ScriptedExchange {
            responses: Mutex::new(VecDeque::from([AuthorityResponse::Info(info(
                contacted, 1,
            ))])),
            requests: Mutex::new(Vec::new()),
        });
        let result = AuthoritySynchronizer::new(
            connections,
            cache,
            Arc::new(MemorySecretStore::default()),
            exchange.clone(),
        )
        .synchronize(connection_id, &CancellationToken::new())
        .await;
        assert!(matches!(result, Err(AuthoritySyncError::ApplianceChanged)));
        assert_eq!(exchange.requests.lock().unwrap().len(), 1);
    }
}
