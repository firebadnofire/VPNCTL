use std::{collections::HashMap, sync::RwLock};

use async_trait::async_trait;
use thiserror::Error;
use vam_core::SecretReference;
use zeroize::Zeroizing;

const SERVICE: &str = "org.archuser.vpnappliancemanager";

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret was not found")]
    NotFound,
    #[error("native secure storage failed: {0}")]
    Native(String),
    #[error("secret store lock is poisoned")]
    Lock,
}

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn put(&self, reference: &SecretReference, value: &[u8]) -> Result<(), SecretStoreError>;
    async fn get(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStoreError>;
    async fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError>;
}

#[derive(Debug, Default)]
pub struct MemorySecretStore {
    values: RwLock<HashMap<SecretReference, Zeroizing<Vec<u8>>>>,
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn put(&self, reference: &SecretReference, value: &[u8]) -> Result<(), SecretStoreError> {
        self.values
            .write()
            .map_err(|_| SecretStoreError::Lock)?
            .insert(reference.clone(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    async fn get(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        self.values
            .read()
            .map_err(|_| SecretStoreError::Lock)?
            .get(reference)
            .cloned()
            .ok_or(SecretStoreError::NotFound)
    }

    async fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError> {
        self.values
            .write()
            .map_err(|_| SecretStoreError::Lock)?
            .remove(reference);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct KeychainSecretStore;

#[async_trait]
impl SecretStore for KeychainSecretStore {
    async fn put(&self, reference: &SecretReference, value: &[u8]) -> Result<(), SecretStoreError> {
        let account = reference.0.to_string();
        let value = Zeroizing::new(value.to_vec());
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(SERVICE, &account)
                .map_err(|error| SecretStoreError::Native(error.to_string()))?;
            entry
                .set_secret(&value)
                .map_err(|error| SecretStoreError::Native(error.to_string()))
        })
        .await
        .map_err(|error| SecretStoreError::Native(error.to_string()))?
    }

    async fn get(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        let account = reference.0.to_string();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(SERVICE, &account)
                .map_err(|error| SecretStoreError::Native(error.to_string()))?;
            entry
                .get_secret()
                .map(Zeroizing::new)
                .map_err(|error| match error {
                    keyring::Error::NoEntry => SecretStoreError::NotFound,
                    other => SecretStoreError::Native(other.to_string()),
                })
        })
        .await
        .map_err(|error| SecretStoreError::Native(error.to_string()))?
    }

    async fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError> {
        let account = reference.0.to_string();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(SERVICE, &account)
                .map_err(|error| SecretStoreError::Native(error.to_string()))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(SecretStoreError::Native(error.to_string())),
            }
        })
        .await
        .map_err(|error| SecretStoreError::Native(error.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn memory_store_round_trip() {
        let store = MemorySecretStore::default();
        let reference = SecretReference(Uuid::new_v4());
        store.put(&reference, b"secret").await.unwrap();
        assert_eq!(store.get(&reference).await.unwrap().as_slice(), b"secret");
        store.delete(&reference).await.unwrap();
        assert!(matches!(
            store.get(&reference).await,
            Err(SecretStoreError::NotFound)
        ));
    }
}
