//! Helper-owned, immutable JSON desired-state generations.
//!
//! A single, host-wide filesystem lock serializes validation and publication.
//! Protected secrets are durable before the current-generation pointer changes.
//! No secret or generation is deleted: retained backups may reference either.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vam_core::{
    DesiredState, DeviceBackendData, DnsRecord, User, VpnBackendKind, VpnInstance,
    validate_host_instances, validate_instance,
};
use zeroize::Zeroizing;

use crate::{AuthorityError, SecretValue};

pub const PROTOCOL_VERSION: u32 = 2;
pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub protocol_version: u32,
    pub manifest_schema: u32,
}

impl Default for Compatibility {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            manifest_schema: SCHEMA_VERSION,
        }
    }
}

impl Compatibility {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self != &Self::default() {
            return Err(AuthorityError::Incompatible {
                local_protocol: PROTOCOL_VERSION,
                local_schema: SCHEMA_VERSION,
                remote_protocol: self.protocol_version,
                remote_schema: self.manifest_schema,
            });
        }
        Ok(())
    }
}

/// Public identity data. Local private-key and credential-store references are
/// deliberately absent from this wire/storage model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicIdentity {
    Wireguard {
        public_key: String,
        preshared_key: Option<Uuid>,
    },
    AmneziaWg {
        public_key: String,
        preshared_key: Uuid,
    },
    Openvpn {
        common_name: String,
        certificate_serial: Option<String>,
    },
    Ikev2 {
        identity: String,
        certificate_serial: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub display_name: String,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<Ipv6Addr>,
    pub dns_name: Option<String>,
    pub enabled: bool,
    pub identity: PublicIdentity,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// `host_id` is the stable appliance UUID, never a local connection UUID.
    pub instance: VpnInstance,
    pub users: Vec<User>,
    pub peers: Vec<Peer>,
    pub dns_records: Vec<DnsRecord>,
    pub dns_blocklist_domains: Vec<String>,
}

impl Configuration {
    /// Runtime projection only. Nil credential references represent unavailable
    /// local material and must never be used to generate replacement keys.
    pub fn runtime_state(&self) -> DesiredState {
        use vam_core::{
            AmneziaWgDeviceData, Device, Ikev2DeviceData, OpenVpnDeviceData, SecretReference,
            WireGuardDeviceData,
        };
        let unavailable = || SecretReference(Uuid::nil());
        let devices = self.peers.iter().map(|peer| {
            let backend_data = match &peer.identity {
                PublicIdentity::Wireguard { public_key, preshared_key } => DeviceBackendData::WireGuard(WireGuardDeviceData {
                    public_key: public_key.clone(), private_key_ref: unavailable(), preshared_key_ref: preshared_key.map(SecretReference),
                }),
                PublicIdentity::AmneziaWg { public_key, preshared_key } => DeviceBackendData::AmneziaWg(AmneziaWgDeviceData {
                    public_key: public_key.clone(), private_key_ref: unavailable(), preshared_key_ref: SecretReference(*preshared_key),
                }),
                PublicIdentity::Openvpn { common_name, certificate_serial } => DeviceBackendData::OpenVpn(OpenVpnDeviceData {
                    common_name: common_name.clone(), private_key_ref: unavailable(), csr_ref: unavailable(),
                    certificate_ref: unavailable(), ca_certificate_ref: unavailable(), tls_crypt_key_ref: if matches!(&self.instance.backend_settings,
                        vam_core::BackendSettings::OpenVpn(settings) if settings.tls_protection == vam_core::OpenVpnTlsProtection::TlsCrypt) { Some(unavailable()) } else { None },
                    certificate_serial: certificate_serial.clone(),
                }),
                PublicIdentity::Ikev2 { identity, certificate_serial } => DeviceBackendData::Ikev2(Ikev2DeviceData {
                    identity: identity.clone(), private_key_ref: Some(unavailable()), csr_ref: Some(unavailable()),
                    certificate_ref: Some(unavailable()), ca_certificate_ref: Some(unavailable()),
                    bundle_password_ref: unavailable(), certificate_serial: certificate_serial.clone(),
                }),
            };
            Device { id: peer.id, instance_id: self.instance.id, user_id: peer.user_id, display_name: peer.display_name.clone(),
                ipv4_address: peer.ipv4_address, ipv6_address: peer.ipv6_address, dns_name: peer.dns_name.clone(),
                enabled: peer.enabled, backend_data, created_at: peer.created_at, deleted_at: None }
        }).collect();
        DesiredState {
            instance: self.instance.clone(),
            users: self.users.clone(),
            devices,
            dns_records: self.dns_records.clone(),
            dns_blocklist_domains: self.dns_blocklist_domains.clone(),
        }
    }
    pub fn from_legacy(state: &DesiredState, appliance_id: Uuid) -> Result<Self, AuthorityError> {
        let mut instance = state.instance.clone();
        instance.host_id = appliance_id;
        let peers = state
            .devices
            .iter()
            .filter(|device| device.deleted_at.is_none())
            .map(|device| {
                let identity = match &device.backend_data {
                    DeviceBackendData::WireGuard(data) => PublicIdentity::Wireguard {
                        public_key: data.public_key.clone(),
                        preshared_key: data.preshared_key_ref.as_ref().map(|reference| reference.0),
                    },
                    DeviceBackendData::AmneziaWg(data) => PublicIdentity::AmneziaWg {
                        public_key: data.public_key.clone(),
                        preshared_key: data.preshared_key_ref.0,
                    },
                    DeviceBackendData::OpenVpn(data) => PublicIdentity::Openvpn {
                        common_name: data.common_name.clone(),
                        certificate_serial: data.certificate_serial.clone(),
                    },
                    DeviceBackendData::Ikev2(data) => PublicIdentity::Ikev2 {
                        identity: data.identity.clone(),
                        certificate_serial: data.certificate_serial.clone(),
                    },
                    DeviceBackendData::Xray(_) => {
                        return Err(invalid(
                            "Xray is unsupported; preserve the legacy configuration for recovery",
                        ));
                    }
                };
                Ok(Peer {
                    id: device.id,
                    user_id: device.user_id,
                    display_name: device.display_name.clone(),
                    ipv4_address: device.ipv4_address,
                    ipv6_address: device.ipv6_address,
                    dns_name: device.dns_name.clone(),
                    enabled: device.enabled,
                    identity,
                    created_at: device.created_at,
                })
            })
            .collect::<Result<_, AuthorityError>>()?;
        Ok(Self {
            instance,
            users: state.users.clone(),
            peers,
            dns_records: state.dns_records.clone(),
            dns_blocklist_domains: state.dns_blocklist_domains.clone(),
        })
    }

    fn secret_ids(&self) -> BTreeSet<Uuid> {
        self.peers
            .iter()
            .filter_map(|peer| match peer.identity {
                PublicIdentity::Wireguard { preshared_key, .. } => preshared_key,
                PublicIdentity::AmneziaWg { preshared_key, .. } => Some(preshared_key),
                _ => None,
            })
            .collect()
    }

    pub fn validate(&self, appliance_id: Uuid) -> Result<(), AuthorityError> {
        validate_instance(&self.instance).map_err(|error| invalid(&error.to_string()))?;
        if self.instance.host_id != appliance_id
            || self.instance.backend == VpnBackendKind::Xray
            || self.instance.deleted_at.is_some()
        {
            return Err(invalid(
                "invalid appliance ownership or unsupported instance",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let users: BTreeSet<_> = self.users.iter().map(|user| user.id).collect();
        if users.len() != self.users.len() {
            return Err(invalid("duplicate user identity"));
        }
        for peer in &self.peers {
            let (kind, public_key) = match &peer.identity {
                PublicIdentity::Wireguard { public_key, .. } => {
                    (VpnBackendKind::WireGuard, Some(public_key))
                }
                PublicIdentity::AmneziaWg { public_key, .. } => {
                    (VpnBackendKind::AmneziaWg, Some(public_key))
                }
                PublicIdentity::Openvpn { common_name, .. } => {
                    if common_name.is_empty() {
                        return Err(invalid("missing certificate common name"));
                    }
                    (VpnBackendKind::OpenVpn, None)
                }
                PublicIdentity::Ikev2 { identity, .. } => {
                    if identity.is_empty() {
                        return Err(invalid("missing certificate identity"));
                    }
                    (VpnBackendKind::Ikev2, None)
                }
            };
            if kind != self.instance.backend
                || !ids.insert(peer.id)
                || peer.display_name.trim().is_empty()
                || peer.user_id.is_some_and(|id| !users.contains(&id))
            {
                return Err(invalid(
                    "invalid peer identity, backend, or user association",
                ));
            }
            if let Some(key) = public_key
                && BASE64.decode(key).map_or(true, |bytes| bytes.len() != 32)
            {
                return Err(invalid("invalid peer public key"));
            }
            let address = peer
                .ipv4_address
                .ok_or_else(|| invalid("missing peer address"))?;
            let network = &self.instance.network;
            if !network.ipv4_subnet.contains(&address)
                || address == network.gateway_ipv4
                || address == network.ipv4_subnet.network()
                || address == network.ipv4_subnet.broadcast()
                || !addresses.insert(address)
            {
                return Err(invalid("invalid or duplicate peer address"));
            }
        }
        let mut record_ids = BTreeSet::new();
        for record in &self.dns_records {
            if record.instance_id != self.instance.id
                || !record_ids.insert(record.id)
                || record
                    .managed_by_device_id
                    .is_some_and(|id| !ids.contains(&id))
            {
                return Err(invalid("invalid DNS record ownership"));
            }
        }
        vam_dns::validate_records(&self.instance.dns.zone, &self.dns_records)
            .map_err(|error| invalid(&error.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub appliance_id: Uuid,
    pub revision: u64,
    pub request_id: Uuid,
    pub request_digest: String,
    pub saved_at: DateTime<Utc>,
    pub removed: bool,
    pub configuration: Configuration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub instances: Vec<Manifest>,
    pub errors: BTreeMap<String, String>,
    pub deployments: BTreeMap<Uuid, DeploymentObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentObservation {
    pub deployed_revision: Option<u64>,
    pub pending_operation: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub compatibility: Compatibility,
    pub request_id: Uuid,
    pub appliance_id: Option<Uuid>,
    pub operation: Operation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    ReconcileRuntime {
        instance_id: Uuid,
        mutation_id: Uuid,
    },
    RuntimeHistory {
        instance_id: Uuid,
    },
    EnrollPeer {
        instance_id: Uuid,
        expected_revision: u64,
        peer: Peer,
        csr: String,
        create_dns_record: bool,
    },
    ExportCertificateMaterial {
        instance_id: Uuid,
        peer_id: Uuid,
        expected_revision: u64,
    },
    RevokePeer {
        instance_id: Uuid,
        peer_id: Uuid,
        expected_revision: u64,
        confirmed: bool,
    },
    Info,
    Discover,
    Read {
        instance_id: Uuid,
    },
    Save {
        request: Box<SaveRequest>,
    },
    History {
        instance_id: Uuid,
    },
    Reconcile {
        instance_id: Uuid,
        mutation_id: Uuid,
    },
    Remove {
        request: Box<SaveRequest>,
        confirmed: bool,
    },
    RestoreDesired {
        instance_id: Uuid,
        revision: u64,
        expected_revision: u64,
        confirmed: bool,
    },
    ExportPeerPsk {
        instance_id: Uuid,
        peer_id: Uuid,
        expected_revision: u64,
    },
    BackupControl {
        confirmed: bool,
    },
    PreviewDeployment {
        instance_id: Uuid,
        expected_revision: u64,
    },
    ApplyDeployment {
        instance_id: Uuid,
        expected_revision: u64,
        expected_state_hash: String,
    },
    Health {
        instance_id: Uuid,
    },
    BackupDeployment {
        instance_id: Uuid,
        expected_revision: u64,
    },
    ListBackups {
        instance_id: Uuid,
    },
    PreviewRestore {
        instance_id: Uuid,
        expected_revision: u64,
        backup_name: String,
    },
    RestoreDeployment {
        instance_id: Uuid,
        expected_revision: u64,
        backup_name: String,
        expected_state_hash: String,
        confirmed: bool,
    },
    StartInstance {
        instance_id: Uuid,
        expected_revision: u64,
    },
    StopInstance {
        instance_id: Uuid,
        expected_revision: u64,
    },
    InspectLegacy {
        instance_id: Uuid,
    },
    BackupLegacy {
        instance_id: Uuid,
        confirmed: bool,
    },
    Migrate {
        request: Box<SaveRequest>,
        expected_legacy_digest: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub compatibility: Compatibility,
    pub request_id: Uuid,
    pub result: Result<Reply, crate::AuthorityFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", content = "value", rename_all = "snake_case")]
pub enum Reply {
    RuntimeReconciled(RuntimeReconciliation),
    RuntimeHistory(Vec<RuntimeHistoryEntry>),
    Enrollment {
        manifest: Box<Manifest>,
        material: CertificateMaterial,
    },
    CertificateMaterial(CertificateMaterial),
    Info {
        appliance_id: Uuid,
        machine_fingerprint: String,
        software_version: String,
    },
    Discovery(Discovery),
    Manifest(Box<Manifest>),
    History(Vec<Manifest>),
    /// None means the mutation is not in committed history. Transport failures
    /// or corrupt history remain errors, never an uncommitted assertion.
    Reconciled(Option<Box<Manifest>>),
    PeerPsk {
        value: Option<SecretValue>,
        server_public_key: Option<String>,
    },
    ControlBackup {
        backup_id: Uuid,
    },
    DeploymentPlan(vam_protocol::DeploymentPlan),
    DeploymentResult(vam_protocol::DeploymentResult),
    Health(vam_protocol::InstanceHealth),
    Backup(vam_protocol::BackupInfo),
    Backups(Vec<vam_protocol::BackupInfo>),
    RestorePreview {
        backup_name: String,
        expected_state_hash: String,
        identity_impact: String,
        desired_revision: u64,
        deployed_revision: Option<u64>,
    },
    OperationFailure(vam_protocol::AppError),
    LegacyInspection {
        deployment_present: bool,
        instance: Option<Box<VpnInstance>>,
        metadata_digest: String,
    },
    LegacyBackup {
        backup_name: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeHistoryEntry {
    pub request_id: Uuid,
    pub desired_revision: u64,
    pub operation: String,
    pub succeeded: bool,
    pub requires_recovery: bool,
    pub deployed_revision: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReconciliation {
    Committed,
    Uncommitted,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMaterial {
    pub peer_id: Uuid,
    pub certificate: SecretValue,
    pub ca_certificate: SecretValue,
    pub tls_crypt: Option<SecretValue>,
}

/// Held throughout a helper runtime operation, excluding competing desired
/// commits and deployments from every process on this host.
pub struct RuntimeContext {
    _lock: File,
    pub manifest: Manifest,
    pub secrets: BTreeMap<Uuid, SecretValue>,
    directory: PathBuf,
    store: ManifestStore,
}

impl RuntimeContext {
    pub fn committed_request(
        &self,
        request_id: Uuid,
        hash: &str,
    ) -> Result<Option<Manifest>, AuthorityError> {
        let current = self
            .store
            .read_locked(self.manifest.configuration.instance.id)?
            .ok_or(AuthorityError::NotFound)?;
        for revision in 1..=current.revision {
            let manifest = self
                .store
                .generation(current.configuration.instance.id, revision)?;
            if manifest.request_id == request_id {
                if manifest.request_digest != hash {
                    return Err(invalid(
                        "request identity was reused with different content",
                    ));
                }
                return Ok(Some(manifest));
            }
        }
        Ok(None)
    }

    pub fn commit_configuration(
        &self,
        configuration: Configuration,
        request_id: Uuid,
        hash: &str,
    ) -> Result<Manifest, AuthorityError> {
        configuration.validate(self.manifest.appliance_id)?;
        let request = SaveRequest {
            compatibility: Compatibility::default(),
            appliance_id: self.manifest.appliance_id,
            request_id,
            expected_revision: self.manifest.revision,
            configuration,
            secrets: BTreeMap::new(),
        };
        let result = self.store.commit_locked(&request, hash, false, true);
        match result {
            Ok(manifest) => Ok(manifest),
            Err(error) => {
                if let Some(manifest) = self.committed_request(request_id, hash)? {
                    sync_directory(&self.store.instance_dir(manifest.configuration.instance.id))?;
                    Ok(manifest)
                } else {
                    Err(error)
                }
            }
        }
    }
    pub fn commit_removal(&self, request: &SaveRequest) -> Result<Manifest, AuthorityError> {
        request.compatibility.validate()?;
        if request.appliance_id != self.manifest.appliance_id
            || request.configuration != self.manifest.configuration
            || request.expected_revision != self.manifest.revision
            || !request.secrets.is_empty()
        {
            return Err(invalid(
                "removal no longer matches the locked authoritative revision",
            ));
        }
        let hash = digest(&Zeroizing::new(serde_json::to_vec(&(request, "remove"))?));
        self.store.commit_locked(request, &hash, true, true)
    }

    /// Only resume an idempotent removal with the same request identity.
    pub fn begin_or_resume_removal(&self, id: Uuid) -> Result<(), AuthorityError> {
        match self.pending_operation()? {
            Some(pending) if pending == id => Ok(()),
            Some(_) => Err(invalid(
                "another interrupted operation requires reconciliation",
            )),
            None => self.begin_mutation(id),
        }
    }
    pub fn remember_backup(&self, name: &str, revision: Option<u64>) -> Result<(), AuthorityError> {
        private_directory(&self.directory)?;
        let path = self.directory.join("backup-revisions.json");
        let mut revisions: BTreeMap<String, Option<u64>> =
            optional_json(&path)?.unwrap_or_default();
        revisions.insert(name.into(), revision);
        replace_json(&path, &revisions)
    }

    pub fn backup_revision(&self, name: &str) -> Result<Option<u64>, AuthorityError> {
        let revisions: BTreeMap<String, Option<u64>> =
            optional_json(&self.directory.join("backup-revisions.json"))?.unwrap_or_default();
        Ok(revisions.get(name).copied().flatten())
    }

    pub fn historical_configuration(&self, revision: u64) -> Result<Configuration, AuthorityError> {
        let path = self
            .directory
            .parent()
            .ok_or_else(|| invalid("missing instance control parent"))?
            .join("generations")
            .join(format!("{revision}.json"));
        let manifest: Manifest = read_json(&path)?;
        if manifest.configuration.instance.id != self.manifest.configuration.instance.id
            || manifest.appliance_id != self.manifest.appliance_id
            || manifest.schema_version != SCHEMA_VERSION
        {
            return Err(invalid("invalid backup configuration generation"));
        }
        Ok(manifest.configuration)
    }
    pub fn read_record<T: DeserializeOwned>(&self, id: Uuid) -> Result<Option<T>, AuthorityError> {
        let path = self.directory.join(format!("{id}.json"));
        if !path.try_exists()? {
            return Ok(None);
        }
        read_json(&path).map(Some)
    }

    pub fn record_ids(&self) -> Result<Vec<Uuid>, AuthorityError> {
        if !self.directory.try_exists()? {
            return Ok(Vec::new());
        }
        reject_symlink(&self.directory)?;
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let path = entry?.path();
            reject_symlink(&path)?;
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("json")
                && let Some(stem) = path.file_stem().and_then(std::ffi::OsStr::to_str)
                && let Ok(id) = Uuid::parse_str(stem)
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    pub fn begin_mutation(&self, id: Uuid) -> Result<(), AuthorityError> {
        private_directory(&self.directory)?;
        let path = self.directory.join("pending.json");
        reject_symlink(&path)?;
        if path.try_exists()? {
            return Err(invalid(
                "an interrupted runtime operation requires reconciliation before another mutation",
            ));
        }
        replace_json(&path, &id)
    }

    pub fn finish_mutation(&self) -> Result<(), AuthorityError> {
        std::fs::remove_file(self.directory.join("pending.json"))?;
        sync_directory(&self.directory)
    }

    pub fn pending_operation(&self) -> Result<Option<Uuid>, AuthorityError> {
        optional_json(&self.directory.join("pending.json"))
    }
    pub fn record(&self, name: Uuid, value: &impl Serialize) -> Result<(), AuthorityError> {
        private_directory(&self.directory)?;
        replace_json(&self.directory.join(format!("{name}.json")), value)
    }

    pub fn deployed(&self) -> Result<Option<u64>, AuthorityError> {
        let path = self.directory.join("deployed.json");
        if !path.try_exists()? {
            return Ok(None);
        }
        read_json(&path).map(Some)
    }

    pub fn mark_deployed(&self) -> Result<(), AuthorityError> {
        self.set_deployed_revision(Some(self.manifest.revision))
    }

    pub fn set_deployed_revision(&self, revision: Option<u64>) -> Result<(), AuthorityError> {
        private_directory(&self.directory)?;
        let path = self.directory.join("deployed.json");
        if let Some(revision) = revision {
            replace_json(&path, &revision)
        } else {
            reject_symlink(&path)?;
            match std::fs::remove_file(path) {
                Ok(()) => sync_directory(&self.directory),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveRequest {
    pub compatibility: Compatibility,
    pub appliance_id: Uuid,
    pub request_id: Uuid,
    /// Zero means create, otherwise this must equal the current revision.
    pub expected_revision: u64,
    pub configuration: Configuration,
    pub secrets: BTreeMap<Uuid, SecretValue>,
}

/// This root is the protected control tree, separate from runtime deployment
/// trees. It must be included in disaster-recovery backups in its entirety.
#[derive(Debug, Clone)]
pub struct ManifestStore {
    root: PathBuf,
    appliance_id: Uuid,
}

impl ManifestStore {
    pub fn maintenance_lock(&self) -> Result<File, AuthorityError> {
        self.lock()
    }
    pub fn runtime_context(
        &self,
        id: Uuid,
        expected_revision: Option<u64>,
    ) -> Result<RuntimeContext, AuthorityError> {
        let lock = self.lock()?;
        let manifest = self.read_locked(id)?.ok_or(AuthorityError::NotFound)?;
        if manifest.removed {
            return Err(AuthorityError::NotFound);
        }
        if let Some(expected) = expected_revision
            && expected != manifest.revision
        {
            return Err(AuthorityError::RevisionConflict {
                expected,
                actual: manifest.revision,
            });
        }
        let secrets = manifest
            .configuration
            .secret_ids()
            .into_iter()
            .map(|id| {
                let value = read_bytes(
                    &self
                        .instance_dir(manifest.configuration.instance.id)
                        .join("secrets")
                        .join(id.to_string()),
                )?;
                Ok((id, SecretValue::new(value)))
            })
            .collect::<Result<_, AuthorityError>>()?;
        Ok(RuntimeContext {
            _lock: lock,
            directory: self.instance_dir(id).join("runtime"),
            manifest,
            secrets,
            store: self.clone(),
        })
    }
    pub fn open(root: &Path, appliance_id: Uuid) -> Result<Self, AuthorityError> {
        private_directory(root)?;
        private_directory(&root.join("instances"))?;
        let store = Self {
            root: root.into(),
            appliance_id,
        };
        let _lock = store.lock()?;
        let identity_path = root.join("identity.json");
        if identity_path.try_exists()? {
            if read_json::<Uuid>(&identity_path)? != appliance_id {
                return Err(invalid("control tree belongs to another appliance"));
            }
        } else {
            write_immutable(&identity_path, &serde_json::to_vec(&appliance_id)?)?;
        }
        Ok(store)
    }

    fn lock(&self) -> Result<File, AuthorityError> {
        let path = self.root.join("mutation.lock");
        reject_symlink(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.lock()?;
        Ok(file)
    }

    fn instance_dir(&self, id: Uuid) -> PathBuf {
        self.root.join("instances").join(id.to_string())
    }

    pub fn discover(&self) -> Result<Discovery, AuthorityError> {
        let _lock = self.lock()?;
        self.discover_locked()
    }

    fn discover_locked(&self) -> Result<Discovery, AuthorityError> {
        let mut result = Discovery {
            instances: Vec::new(),
            errors: BTreeMap::new(),
            deployments: BTreeMap::new(),
        };
        for entry in std::fs::read_dir(self.root.join("instances"))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let read = Uuid::parse_str(&name)
                .map_err(|_| invalid("invalid instance directory"))
                .and_then(|id| self.read_locked(id));
            match read {
                Ok(Some(manifest)) if !manifest.removed => {
                    let id = manifest.configuration.instance.id;
                    let runtime = self.instance_dir(id).join("runtime");
                    let observation = (|| {
                        Ok::<_, AuthorityError>(DeploymentObservation {
                            deployed_revision: optional_json(&runtime.join("deployed.json"))?,
                            pending_operation: optional_json(&runtime.join("pending.json"))?,
                        })
                    })();
                    match observation {
                        Ok(observation) => {
                            result.deployments.insert(id, observation);
                        }
                        Err(error) => {
                            result
                                .errors
                                .insert(format!("{id}/runtime"), error.to_string());
                        }
                    }
                    result.instances.push(manifest);
                }
                Ok(_) => {}
                Err(error) => {
                    result.errors.insert(name, error.to_string());
                }
            }
        }
        result
            .instances
            .sort_by_key(|manifest| manifest.configuration.instance.id);
        Ok(result)
    }

    pub fn read(&self, id: Uuid) -> Result<Option<Manifest>, AuthorityError> {
        let _lock = self.lock()?;
        self.read_locked(id)
    }

    fn read_locked(&self, id: Uuid) -> Result<Option<Manifest>, AuthorityError> {
        let dir = self.instance_dir(id);
        reject_symlink(&dir)?;
        let pointer = dir.join("current.json");
        reject_symlink(&pointer)?;
        if !pointer.try_exists()? {
            return Ok(None);
        }
        let revision: u64 = read_json(&pointer)?;
        self.generation(id, revision).map(Some)
    }

    fn generation(&self, id: Uuid, revision: u64) -> Result<Manifest, AuthorityError> {
        let dir = self.instance_dir(id);
        reject_symlink(&dir)?;
        reject_symlink(&dir.join("generations"))?;
        let manifest: Manifest =
            read_json(&dir.join("generations").join(format!("{revision}.json")))?;
        if manifest.schema_version != SCHEMA_VERSION {
            return Err(AuthorityError::Incompatible {
                local_protocol: PROTOCOL_VERSION,
                local_schema: SCHEMA_VERSION,
                remote_protocol: PROTOCOL_VERSION,
                remote_schema: manifest.schema_version,
            });
        }
        if manifest.revision != revision
            || manifest.configuration.instance.id != id
            || manifest.appliance_id != self.appliance_id
        {
            return Err(invalid("manifest identity or revision mismatch"));
        }
        manifest.configuration.validate(self.appliance_id)?;
        Ok(manifest)
    }

    pub fn save(&self, request: &SaveRequest) -> Result<Manifest, AuthorityError> {
        self.save_validated(request, || Ok(()), false)
    }

    pub fn save_checked(
        &self,
        request: &SaveRequest,
        check: impl FnOnce() -> Result<(), AuthorityError>,
    ) -> Result<Manifest, AuthorityError> {
        if request.expected_revision != 0 {
            return Err(invalid("legacy import requires a create revision"));
        }
        self.save_validated(request, check, true)
    }

    fn save_validated(
        &self,
        request: &SaveRequest,
        check: impl FnOnce() -> Result<(), AuthorityError>,
        credential_mutation: bool,
    ) -> Result<Manifest, AuthorityError> {
        request.compatibility.validate()?;
        request.configuration.validate(self.appliance_id)?;
        if request.appliance_id != self.appliance_id {
            return Err(invalid("appliance identity mismatch"));
        }
        let digest = digest(&Zeroizing::new(serde_json::to_vec(request)?));
        let _lock = self.lock()?;
        check()?;
        self.commit_locked(request, &digest, false, credential_mutation)
    }

    fn commit_locked(
        &self,
        request: &SaveRequest,
        request_digest: &str,
        removed: bool,
        owned_runtime: bool,
    ) -> Result<Manifest, AuthorityError> {
        let id = request.configuration.instance.id;
        let current = self.read_locked(id)?;
        let actual = current.as_ref().map_or(0, |manifest| manifest.revision);
        // Search only committed history. A request that persisted a generation
        // but never published its pointer has not committed.
        for revision in 1..=actual {
            let manifest = self.generation(id, revision)?;
            if manifest.request_id == request.request_id {
                if manifest.request_digest != request_digest {
                    return Err(invalid("request UUID was reused with different content"));
                }
                return Ok(manifest);
            }
        }
        if actual != request.expected_revision {
            return Err(AuthorityError::RevisionConflict {
                expected: request.expected_revision,
                actual,
            });
        }
        if !removed {
            for peer in &request.configuration.peers {
                if matches!(
                    peer.identity,
                    PublicIdentity::Openvpn { .. } | PublicIdentity::Ikev2 { .. }
                ) {
                    let previous = current.as_ref().and_then(|manifest| {
                        manifest
                            .configuration
                            .peers
                            .iter()
                            .find(|old| old.id == peer.id)
                    });
                    if !owned_runtime && previous.is_none() {
                        return Err(invalid("certificate peers require explicit CSR enrollment"));
                    }
                    if let Some(previous) = previous {
                        if previous.identity != peer.identity {
                            return Err(invalid(
                                "certificate identity changes require explicit replacement enrollment",
                            ));
                        }
                        if !previous.enabled && peer.enabled {
                            return Err(invalid("revoked certificate peers cannot be re-enabled"));
                        }
                        if previous.enabled && !peer.enabled && !owned_runtime {
                            return Err(invalid("certificate peers must be explicitly revoked"));
                        }
                    }
                }
            }
            if !owned_runtime
                && current.as_ref().is_some_and(|manifest| {
                    manifest.configuration.peers.iter().any(|old| {
                        old.enabled
                            && matches!(
                                old.identity,
                                PublicIdentity::Openvpn { .. } | PublicIdentity::Ikev2 { .. }
                            )
                            && !request
                                .configuration
                                .peers
                                .iter()
                                .any(|peer| peer.id == old.id)
                    })
                })
            {
                return Err(invalid(
                    "revoke certificate peers before removing their metadata",
                ));
            }
        }
        if current.as_ref().is_some_and(|manifest| manifest.removed) {
            return Err(invalid("removed instance cannot be overwritten"));
        }
        if current.as_ref().is_some_and(|manifest| {
            manifest.configuration.instance.backend != request.configuration.instance.backend
        }) {
            return Err(invalid(
                "an instance backend is immutable; create a separate instance instead",
            ));
        }
        let pending = optional_json::<Uuid>(&self.instance_dir(id).join("runtime/pending.json"))?;
        if pending.is_some() && !(owned_runtime && pending == Some(request.request_id)) {
            return Err(invalid(
                "reconcile the interrupted runtime operation before saving configuration",
            ));
        }
        let discovery = self.discover_locked()?;
        if !discovery.errors.is_empty() {
            return Err(invalid(
                "repair unreadable instance metadata before mutating this host",
            ));
        }
        let mut instances: Vec<_> = discovery
            .instances
            .into_iter()
            .filter(|manifest| manifest.configuration.instance.id != id)
            .map(|manifest| manifest.configuration.instance)
            .collect();
        instances.push(request.configuration.instance.clone());
        validate_host_instances(&instances).map_err(|error| invalid(&error.to_string()))?;
        let dir = self.instance_dir(id);
        private_directory(&dir)?;
        private_directory(&dir.join("generations"))?;
        private_directory(&dir.join("secrets"))?;
        let required = request.configuration.secret_ids();
        if request.secrets.keys().any(|id| !required.contains(id)) {
            return Err(invalid("only referenced server PSKs may be persisted"));
        }
        // Secrets are immutable. Rotation uses a new reference, preserving old
        // desired revisions, running deployments, and backups.
        for secret_id in required {
            let path = dir.join("secrets").join(secret_id.to_string());
            reject_symlink(&path)?;
            if let Some(value) = request.secrets.get(&secret_id) {
                if BASE64
                    .decode(value.as_bytes())
                    .map_or(true, |bytes| bytes.len() != 32)
                {
                    return Err(invalid("server PSK must encode 32 bytes"));
                }
                if path.try_exists()? {
                    if Zeroizing::new(read_bytes(&path)?).as_slice() != value.as_bytes() {
                        return Err(invalid("existing PSK reference cannot change value"));
                    }
                } else {
                    replace_bytes(&path, value.as_bytes())?;
                }
            }
            let persisted = Zeroizing::new(read_bytes(&path)?);
            if BASE64
                .decode(&persisted)
                .map_or(true, |bytes| bytes.len() != 32)
            {
                return Err(invalid("missing or corrupt server PSK"));
            }
        }
        let revision = actual
            .checked_add(1)
            .ok_or_else(|| invalid("revision limit reached"))?;
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            appliance_id: self.appliance_id,
            revision,
            request_id: request.request_id,
            request_digest: request_digest.into(),
            saved_at: Utc::now(),
            removed,
            configuration: request.configuration.clone(),
        };
        let generation_path = dir.join("generations").join(format!("{revision}.json"));
        // An uncommitted orphan may occupy the next revision after a crash.
        // Preserve it for inspection; it was never authoritative.
        reject_symlink(&generation_path)?;
        if generation_path.try_exists()? {
            std::fs::rename(
                &generation_path,
                dir.join("generations")
                    .join(format!("orphan-{}.json", Uuid::new_v4())),
            )?;
            sync_directory(&dir.join("generations"))?;
        }
        write_immutable(&generation_path, &serde_json::to_vec_pretty(&manifest)?)?;
        replace_json(&dir.join("current.json"), &revision)?;
        Ok(manifest)
    }

    pub fn history(&self, id: Uuid) -> Result<Vec<Manifest>, AuthorityError> {
        let _lock = self.lock()?;
        let current = self.read_locked(id)?.ok_or(AuthorityError::NotFound)?;
        (1..=current.revision)
            .map(|revision| self.generation(id, revision))
            .collect()
    }

    pub fn restore_desired(
        &self,
        id: Uuid,
        revision: u64,
        expected_revision: u64,
        request_id: Uuid,
        confirmed: bool,
    ) -> Result<Manifest, AuthorityError> {
        if !confirmed {
            return Err(invalid(
                "restoring desired configuration requires confirmation",
            ));
        }
        let _lock = self.lock()?;
        let current = self.read_locked(id)?.ok_or(AuthorityError::NotFound)?;
        if revision > current.revision {
            return Err(AuthorityError::NotFound);
        }
        let previous = self.generation(id, revision)?;
        if previous.removed {
            return Err(invalid("cannot restore a removed desired configuration"));
        }
        let request = SaveRequest {
            compatibility: Compatibility::default(),
            appliance_id: self.appliance_id,
            request_id,
            expected_revision,
            configuration: previous.configuration,
            secrets: BTreeMap::new(),
        };
        let digest = digest(&serde_json::to_vec(&(
            &request,
            "restore_desired",
            revision,
        ))?);
        self.commit_locked(&request, &digest, false, false)
    }

    /// Copy the complete protected control tree, including every retained
    /// generation and secret. Runtime-only backups are not disaster recovery.
    pub fn backup_control(&self, destination: &Path) -> Result<(), AuthorityError> {
        self.backup_control_with(destination, |_| Ok(()))
    }

    /// Include runtime identity trees under the same host mutation lock when
    /// the helper creates a complete disaster-recovery bundle.
    pub fn backup_control_with(
        &self,
        destination: &Path,
        copy_runtime: impl FnOnce(&Path) -> Result<(), AuthorityError>,
    ) -> Result<(), AuthorityError> {
        if destination.starts_with(&self.root) || destination.try_exists()? {
            return Err(invalid(
                "control backup requires a new destination outside the control tree",
            ));
        }
        let _lock = self.lock()?;
        let inventory = self.discover_locked()?;
        if !inventory.errors.is_empty() {
            return Err(invalid(
                "control backup requires readable committed manifests",
            ));
        }
        copy_private_tree(&self.root, destination)?;
        copy_runtime(destination)?;
        let backup = Self::open(destination, self.appliance_id)?;
        if serde_json::to_vec(&backup.discover()?.instances)?
            != serde_json::to_vec(&inventory.instances)?
        {
            return Err(invalid("control backup verification failed"));
        }
        Ok(())
    }

    pub fn remove(
        &self,
        request: &SaveRequest,
        confirmed: bool,
    ) -> Result<Manifest, AuthorityError> {
        if !confirmed {
            return Err(invalid("instance removal requires confirmation"));
        }
        request.compatibility.validate()?;
        if request.appliance_id != self.appliance_id {
            return Err(invalid("appliance identity mismatch"));
        }
        request.configuration.validate(self.appliance_id)?;
        let digest = digest(&serde_json::to_vec(&(request, "remove"))?);
        let _lock = self.lock()?;
        let current = self
            .read_locked(request.configuration.instance.id)?
            .ok_or(AuthorityError::NotFound)?;
        if current.configuration != request.configuration {
            return Err(invalid("removal preview no longer matches instance"));
        }
        self.commit_locked(request, &digest, true, false)
    }

    /// Explicit export only; normal discovery never returns secret values.
    pub fn export_peer_psk(
        &self,
        id: Uuid,
        peer_id: Uuid,
        expected_revision: u64,
    ) -> Result<Option<SecretValue>, AuthorityError> {
        let _lock = self.lock()?;
        let manifest = self.read_locked(id)?.ok_or(AuthorityError::NotFound)?;
        if manifest.removed {
            return Err(AuthorityError::NotFound);
        }
        if manifest.revision != expected_revision {
            return Err(AuthorityError::RevisionConflict {
                expected: expected_revision,
                actual: manifest.revision,
            });
        }
        let peer = manifest
            .configuration
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .ok_or(AuthorityError::NotFound)?;
        let reference = match peer.identity {
            PublicIdentity::Wireguard { preshared_key, .. } => preshared_key,
            PublicIdentity::AmneziaWg { preshared_key, .. } => Some(preshared_key),
            _ => {
                return Err(invalid(
                    "PSK export is supported only for WireGuard and AmneziaWG",
                ));
            }
        };
        reference
            .map(|reference| {
                read_bytes(
                    &self
                        .instance_dir(id)
                        .join("secrets")
                        .join(reference.to_string()),
                )
                .map(SecretValue::new)
            })
            .transpose()
    }
}

fn invalid(message: &str) -> AuthorityError {
    AuthorityError::InvalidState(message.into())
}

fn copy_private_tree(source: &Path, destination: &Path) -> Result<(), AuthorityError> {
    private_directory(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if entry.file_name() == "mutation.lock" {
            continue;
        }
        if kind.is_dir() {
            copy_private_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            write_immutable(&target, &read_bytes(&entry.path())?)?;
        } else {
            return Err(invalid("unsafe file in control backup"));
        }
    }
    sync_directory(destination)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn reject_symlink(path: &Path) -> Result<(), AuthorityError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(invalid("symlinks are forbidden in authoritative storage"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn private_directory(path: &Path) -> Result<(), AuthorityError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.try_exists()? {
            private_directory(parent)?;
        }
        reject_symlink(parent)?;
    }
    reject_symlink(path)?;
    if !path.try_exists()? {
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        reject_symlink(path)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, AuthorityError> {
    reject_symlink(path)?;
    let file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_DOCUMENT_BYTES {
        return Err(invalid("invalid or oversized authoritative file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(invalid("oversized authoritative file"));
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, AuthorityError> {
    serde_json::from_slice(&read_bytes(path)?).map_err(|_| invalid("invalid authoritative JSON"))
}

fn optional_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, AuthorityError> {
    if let Some(parent) = path.parent() {
        reject_symlink(parent)?;
    }
    reject_symlink(path)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    read_json(path).map(Some)
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<(), AuthorityError> {
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(invalid("authoritative file exceeds size limit"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_directory(
        path.parent()
            .ok_or_else(|| invalid("missing storage parent"))?,
    )?;
    Ok(())
}

fn replace_json(path: &Path, value: &impl Serialize) -> Result<(), AuthorityError> {
    replace_bytes(path, &serde_json::to_vec(value)?)
}

fn replace_bytes(path: &Path, bytes: &[u8]) -> Result<(), AuthorityError> {
    reject_symlink(path)?;
    let temporary = path.with_file_name(format!(".pending-{}", Uuid::new_v4()));
    write_immutable(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| invalid("missing storage parent"))?,
    )
}

fn sync_directory(path: &Path) -> Result<(), AuthorityError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vam_core::{BackendSettings, DnsConfig, EndpointConfig, NetworkConfig, RoutingMode};

    fn request(appliance_id: Uuid) -> SaveRequest {
        let now = Utc::now();
        SaveRequest {
            compatibility: Compatibility::default(),
            appliance_id,
            request_id: Uuid::new_v4(),
            expected_revision: 0,
            secrets: BTreeMap::new(),
            configuration: Configuration {
                instance: VpnInstance {
                    id: Uuid::new_v4(),
                    host_id: appliance_id,
                    display_name: "primary".into(),
                    backend: VpnBackendKind::WireGuard,
                    backend_settings: BackendSettings::default(),
                    endpoint: EndpointConfig {
                        host: "vpn.example.com".into(),
                        port: 51820,
                    },
                    network: NetworkConfig {
                        ipv4_subnet: "10.88.0.0/24".parse().unwrap(),
                        gateway_ipv4: "10.88.0.1".parse().unwrap(),
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
                },
                users: Vec::new(),
                peers: Vec::new(),
                dns_records: Vec::new(),
                dns_blocklist_domains: Vec::new(),
            },
        }
    }

    fn add_psk(request: &mut SaveRequest) -> (Uuid, Uuid, String) {
        let id = Uuid::new_v4();
        let peer_id = Uuid::new_v4();
        let value = BASE64.encode([7; 32]);
        request.configuration.peers.push(Peer {
            id: peer_id,
            user_id: None,
            display_name: "phone".into(),
            ipv4_address: Some("10.88.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: None,
            enabled: true,
            identity: PublicIdentity::Wireguard {
                public_key: BASE64.encode([8; 32]),
                preshared_key: Some(id),
            },
            created_at: Utc::now(),
        });
        request
            .secrets
            .insert(id, SecretValue::new(value.clone().into_bytes()));
        (id, peer_id, value)
    }

    #[test]
    fn independent_clients_discover_and_conflicts_do_not_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let client_a = ManifestStore::open(dir.path(), appliance).unwrap();
        let client_b = ManifestStore::open(dir.path(), appliance).unwrap();
        assert!(client_b.discover().unwrap().instances.is_empty());
        let mut edit_a = request(appliance);
        let saved = client_a.save(&edit_a).unwrap();
        assert_eq!(
            client_b.read(saved.configuration.instance.id).unwrap(),
            Some(saved)
        );
        edit_a.expected_revision = 1;
        edit_a.request_id = Uuid::new_v4();
        let mut edit_b = edit_a.clone();
        edit_a.configuration.instance.display_name = "A".into();
        client_a.save(&edit_a).unwrap();
        edit_b.request_id = Uuid::new_v4();
        edit_b.configuration.instance.display_name = "B".into();
        assert!(matches!(
            client_b.save(&edit_b),
            Err(AuthorityError::RevisionConflict {
                expected: 1,
                actual: 2
            })
        ));
        assert_eq!(
            client_b.discover().unwrap().instances[0]
                .configuration
                .instance
                .display_name,
            "A"
        );
    }

    #[test]
    fn secrets_are_durable_before_publication_and_never_in_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let mut request = request(appliance);
        let (secret, peer, value) = add_psk(&mut request);
        let pending = request.secrets.remove(&secret).unwrap();
        assert!(store.save(&request).is_err());
        assert!(store.discover().unwrap().instances.is_empty());
        request.secrets.insert(secret, pending);
        store.save(&request).unwrap();
        let reopened = ManifestStore::open(dir.path(), appliance).unwrap();
        let public = serde_json::to_string(&reopened.discover().unwrap()).unwrap();
        assert!(!public.contains(&value));
        assert!(!public.contains("private_key_ref"));
        assert_eq!(
            reopened
                .export_peer_psk(request.configuration.instance.id, peer, 1)
                .unwrap()
                .unwrap()
                .as_bytes(),
            value.as_bytes()
        );
        assert!(
            reopened
                .export_peer_psk(request.configuration.instance.id, Uuid::new_v4(), 1)
                .is_err()
        );
        assert!(
            reopened
                .export_peer_psk(request.configuration.instance.id, peer, 0)
                .is_err()
        );
        request.expected_revision = 1;
        request.request_id = Uuid::new_v4();
        request.secrets.insert(
            secret,
            SecretValue::new(BASE64.encode([9; 32]).into_bytes()),
        );
        assert!(store.save(&request).is_err());
        assert_eq!(
            store
                .read(request.configuration.instance.id)
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }

    #[test]
    fn retries_reconcile_committed_history_and_reject_changed_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let mut first = request(appliance);
        let original = store.save(&first).unwrap();
        assert_eq!(store.save(&first).unwrap(), original);
        let mut next = first.clone();
        next.request_id = Uuid::new_v4();
        next.expected_revision = 1;
        next.configuration.instance.display_name = "newer".into();
        store.save(&next).unwrap();
        assert_eq!(store.save(&first).unwrap(), original);
        first.configuration.instance.display_name = "changed retry".into();
        assert!(store.save(&first).is_err());
        assert_eq!(
            store.history(next.configuration.instance.id).unwrap().len(),
            2
        );
    }

    #[test]
    fn uncommitted_generations_are_invisible_and_preserved_on_retry() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let mut request = request(appliance);
        store.save(&request).unwrap();
        let path = store
            .instance_dir(request.configuration.instance.id)
            .join("generations/2.json");
        write_immutable(&path, b"partial generation from interrupted operation").unwrap();
        assert_eq!(store.discover().unwrap().instances[0].revision, 1);
        request.expected_revision = 1;
        request.request_id = Uuid::new_v4();
        assert_eq!(store.save(&request).unwrap().revision, 2);
        assert!(
            std::fs::read_dir(path.parent().unwrap())
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("orphan-"))
        );
    }

    #[test]
    fn removal_is_confirmed_and_retains_history_and_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let mut request = request(appliance);
        let (secret, _, _) = add_psk(&mut request);
        store.save(&request).unwrap();
        request.expected_revision = 1;
        request.request_id = Uuid::new_v4();
        assert!(store.remove(&request, false).is_err());
        let removed = store.remove(&request, true).unwrap();
        assert!(removed.removed);
        assert_eq!(store.remove(&request, true).unwrap(), removed);
        assert!(store.discover().unwrap().instances.is_empty());
        assert_eq!(
            store
                .history(request.configuration.instance.id)
                .unwrap()
                .len(),
            2
        );
        assert!(
            store
                .instance_dir(request.configuration.instance.id)
                .join("secrets")
                .join(secret.to_string())
                .exists()
        );
    }

    #[test]
    fn concurrent_writers_serialize_across_independent_store_handles() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let mut request = request(appliance);
        store.save(&request).unwrap();
        request.expected_revision = 1;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let writers: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                let mut request = request.clone();
                request.request_id = Uuid::new_v4();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.save(&request)
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(AuthorityError::RevisionConflict { .. })))
                .count(),
            1
        );
    }

    #[test]
    fn incompatible_clients_do_not_create_instance_state() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let mut request = request(appliance);
        request.compatibility.protocol_version = 1;
        assert!(matches!(
            store.save(&request),
            Err(AuthorityError::Incompatible { .. })
        ));
        assert!(
            !store
                .instance_dir(request.configuration.instance.id)
                .exists()
        );
        assert!(ManifestStore::open(dir.path(), Uuid::new_v4()).is_err());
    }

    #[test]
    fn future_manifest_schema_refuses_reads_and_writes_without_republishing_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let first = request(appliance);
        let id = first.configuration.instance.id;
        store.save(&first).unwrap();
        let pointer = store.instance_dir(id).join("current.json");
        let original_pointer = std::fs::read(&pointer).unwrap();
        let generation = store.instance_dir(id).join("generations/1.json");
        let mut future: Manifest = read_json(&generation).unwrap();
        future.schema_version = SCHEMA_VERSION + 1;
        replace_json(&generation, &future).unwrap();
        assert!(matches!(
            store.read(id),
            Err(AuthorityError::Incompatible {
                remote_schema: 2,
                ..
            })
        ));
        let mut next = first;
        next.expected_revision = 1;
        next.request_id = Uuid::new_v4();
        assert!(matches!(
            store.save(&next),
            Err(AuthorityError::Incompatible {
                remote_schema: 2,
                ..
            })
        ));
        assert_eq!(std::fs::read(pointer).unwrap(), original_pointer);
    }

    #[test]
    fn desired_restore_creates_revision_and_disaster_backup_retains_psks() {
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(&dir.path().join("control"), appliance).unwrap();
        let mut first = request(appliance);
        let (_, peer, value) = add_psk(&mut first);
        store.save(&first).unwrap();
        let mut next = first.clone();
        next.expected_revision = 1;
        next.request_id = Uuid::new_v4();
        next.configuration.instance.display_name = "newer".into();
        store.save(&next).unwrap();
        let id = first.configuration.instance.id;
        assert!(
            store
                .restore_desired(id, 1, 1, Uuid::new_v4(), true)
                .is_err()
        );
        let restored = store
            .restore_desired(id, 1, 2, Uuid::new_v4(), true)
            .unwrap();
        assert_eq!(restored.revision, 3);
        assert_eq!(restored.configuration, first.configuration);
        let backup_path = dir.path().join("backup");
        store.backup_control(&backup_path).unwrap();
        let backup = ManifestStore::open(&backup_path, appliance).unwrap();
        assert_eq!(backup.history(id).unwrap().len(), 3);
        assert_eq!(
            backup
                .export_peer_psk(id, peer, 3)
                .unwrap()
                .unwrap()
                .as_bytes(),
            value.as_bytes()
        );
        assert!(store.backup_control(&backup_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_and_symlinked_metadata_are_errors_not_empty_inventory() {
        use std::os::unix::{fs::PermissionsExt, fs::symlink};
        let dir = tempfile::tempdir().unwrap();
        let appliance = Uuid::new_v4();
        let store = ManifestStore::open(dir.path(), appliance).unwrap();
        let request = request(appliance);
        store.save(&request).unwrap();
        let instance = store.instance_dir(request.configuration.instance.id);
        assert_eq!(
            std::fs::metadata(instance.join("current.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(instance.join("secrets"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::remove_file(instance.join("current.json")).unwrap();
        symlink("/etc/passwd", instance.join("current.json")).unwrap();
        let result = store.discover().unwrap();
        assert!(result.instances.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(store.save(&request).is_err());
    }
}
