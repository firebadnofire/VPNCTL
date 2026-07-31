use std::{collections::HashMap, fmt::Write as _, sync::RwLock};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use vam_core::SecretReference;
use zeroize::Zeroizing;

const SERVICE: &str = "org.archuser.vpnappliancemanager";
const CHUNK_SIZE: usize = 2_048;
const MANIFEST_PREFIX: &str = "vam-chunked-secret-v1";
const MAX_CHUNKS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChunkManifest {
    generation: Uuid,
    chunk_count: usize,
    value_length: usize,
    sha256: [u8; 32],
}

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

fn native_error(context: &str, error: impl std::fmt::Display) -> SecretStoreError {
    SecretStoreError::Native(format!("{context}: {error}"))
}

fn native_entry(account: &str) -> Result<keyring::Entry, SecretStoreError> {
    keyring::Entry::new(SERVICE, account)
        .map_err(|error| native_error("credential entry could not be opened", error))
}

fn read_native(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretStoreError> {
    match native_entry(account)?.get_secret() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(native_error("credential could not be read", error)),
    }
}

fn write_native(account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
    native_entry(account)?
        .set_secret(value)
        .map_err(|error| native_error("credential could not be written", error))
}

fn delete_native(account: &str) -> Result<(), SecretStoreError> {
    match native_entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(native_error("credential could not be deleted", error)),
    }
}

fn digest_hex(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn parse_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn encode_manifest(manifest: &ChunkManifest) -> Vec<u8> {
    format!(
        "{MANIFEST_PREFIX}:{}:{}:{}:{}",
        manifest.generation,
        manifest.chunk_count,
        manifest.value_length,
        digest_hex(&manifest.sha256)
    )
    .into_bytes()
}

fn parse_manifest(value: &[u8]) -> Result<Option<ChunkManifest>, SecretStoreError> {
    let Ok(text) = std::str::from_utf8(value) else {
        return Ok(None);
    };
    if !text.starts_with(MANIFEST_PREFIX) {
        return Ok(None);
    }
    let mut fields = text.split(':');
    let valid = fields.next() == Some(MANIFEST_PREFIX);
    let generation = fields.next().and_then(|value| Uuid::parse_str(value).ok());
    let chunk_count = fields.next().and_then(|value| value.parse::<usize>().ok());
    let value_length = fields.next().and_then(|value| value.parse::<usize>().ok());
    let sha256 = fields.next().and_then(parse_digest);
    if !valid
        || fields.next().is_some()
        || generation.is_none()
        || chunk_count.is_none_or(|count| count == 0 || count > MAX_CHUNKS)
        || value_length.is_none()
        || sha256.is_none()
    {
        return Err(SecretStoreError::Native(
            "stored chunk manifest is invalid".into(),
        ));
    }
    Ok(Some(ChunkManifest {
        generation: generation.expect("checked above"),
        chunk_count: chunk_count.expect("checked above"),
        value_length: value_length.expect("checked above"),
        sha256: sha256.expect("checked above"),
    }))
}

fn chunk_account(account: &str, generation: Uuid, index: usize) -> String {
    format!("{account}.chunk.{generation}.{index}")
}

fn delete_chunk_generation(
    account: &str,
    manifest: &ChunkManifest,
) -> Result<(), SecretStoreError> {
    let mut first_error = None;
    for index in 0..manifest.chunk_count {
        if let Err(error) = delete_native(&chunk_account(account, manifest.generation, index))
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn put_native_secret(
    account: &str,
    value: &[u8],
    generation: Uuid,
) -> Result<(), SecretStoreError> {
    let previous = read_native(account)?;
    let previous_manifest = previous
        .as_deref()
        .map(|value| parse_manifest(value.as_slice()))
        .transpose()?
        .flatten();
    let mut new_manifest = None;
    if value.len() > CHUNK_SIZE {
        let manifest = ChunkManifest {
            generation,
            chunk_count: value.len().div_ceil(CHUNK_SIZE),
            value_length: value.len(),
            sha256: Sha256::digest(value).into(),
        };
        for (index, chunk) in value.chunks(CHUNK_SIZE).enumerate() {
            if let Err(error) = write_native(&chunk_account(account, generation, index), chunk) {
                let cleanup = delete_chunk_generation(account, &manifest);
                return Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup_error) => SecretStoreError::Native(format!(
                        "{error}; partial chunk cleanup also failed: {cleanup_error}"
                    )),
                });
            }
        }
        if let Err(error) = write_native(account, &encode_manifest(&manifest)) {
            let cleanup = delete_chunk_generation(account, &manifest);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => SecretStoreError::Native(format!(
                    "{error}; uncommitted chunk cleanup also failed: {cleanup_error}"
                )),
            });
        }
        new_manifest = Some(manifest);
    } else {
        write_native(account, value)?;
    }

    if let Some(previous_manifest) = previous_manifest
        && let Err(error) = delete_chunk_generation(account, &previous_manifest)
    {
        let restore = previous
            .as_deref()
            .ok_or_else(|| SecretStoreError::Native("previous credential disappeared".into()))
            .and_then(|previous| write_native(account, previous));
        let cleanup = new_manifest.as_ref().map_or(Ok(()), |manifest| {
            delete_chunk_generation(account, manifest)
        });
        return Err(SecretStoreError::Native(format!(
            "previous credential chunks could not be retired: {error}; rollback: {}; new chunk cleanup: {}",
            restore.map_or_else(
                |restore_error| restore_error.to_string(),
                |()| "restored".into()
            ),
            cleanup.map_or_else(
                |cleanup_error| cleanup_error.to_string(),
                |()| "complete".into()
            )
        )));
    }
    Ok(())
}

fn get_native_secret(account: &str) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
    let primary = read_native(account)?.ok_or(SecretStoreError::NotFound)?;
    let Some(manifest) = parse_manifest(primary.as_slice())? else {
        return Ok(primary);
    };
    let mut value = Zeroizing::new(Vec::with_capacity(manifest.value_length));
    for index in 0..manifest.chunk_count {
        let chunk = read_native(&chunk_account(account, manifest.generation, index))?
            .ok_or_else(|| SecretStoreError::Native("stored secret chunk is missing".into()))?;
        value.extend_from_slice(chunk.as_slice());
    }
    let sha256: [u8; 32] = Sha256::digest(value.as_slice()).into();
    if value.len() != manifest.value_length || sha256 != manifest.sha256 {
        return Err(SecretStoreError::Native(
            "stored secret chunks failed integrity validation".into(),
        ));
    }
    Ok(value)
}

fn delete_native_secret(account: &str) -> Result<(), SecretStoreError> {
    let primary = read_native(account)?;
    if let Some(manifest) = primary
        .as_deref()
        .map(|value| parse_manifest(value.as_slice()))
        .transpose()?
        .flatten()
    {
        delete_chunk_generation(account, &manifest)?;
    }
    delete_native(account)
}

#[async_trait]
impl SecretStore for KeychainSecretStore {
    async fn put(&self, reference: &SecretReference, value: &[u8]) -> Result<(), SecretStoreError> {
        let account = reference.0.to_string();
        let value = Zeroizing::new(value.to_vec());
        let generation = Uuid::new_v4();
        tokio::task::spawn_blocking(move || put_native_secret(&account, &value, generation))
            .await
            .map_err(|error| SecretStoreError::Native(error.to_string()))?
    }

    async fn get(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<Vec<u8>>, SecretStoreError> {
        let account = reference.0.to_string();
        tokio::task::spawn_blocking(move || get_native_secret(&account))
            .await
            .map_err(|error| SecretStoreError::Native(error.to_string()))?
    }

    async fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError> {
        let account = reference.0.to_string();
        tokio::task::spawn_blocking(move || delete_native_secret(&account))
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

    #[test]
    fn chunk_manifest_round_trips_and_detects_malformed_metadata() {
        let value = vec![0x5a; CHUNK_SIZE * 2 + 17];
        let manifest = ChunkManifest {
            generation: Uuid::from_u128(7),
            chunk_count: value.len().div_ceil(CHUNK_SIZE),
            value_length: value.len(),
            sha256: Sha256::digest(&value).into(),
        };
        assert_eq!(
            parse_manifest(&encode_manifest(&manifest)).unwrap(),
            Some(manifest)
        );
        assert!(parse_manifest(b"ordinary legacy secret").unwrap().is_none());
        assert!(parse_manifest(b"vam-chunked-secret-v1:broken").is_err());
    }
}
