use sha2::{Digest, Sha256};
use vam_authority::manifest::{Compatibility, ManifestStore, Operation, Reply, Request, Response};

use super::{
    AuthorityError, CallerIdentity, ServerError, ServerRuntime, load_or_create_appliance_id,
    read_bounded, validate_request_file, write_response,
};
use uuid::Uuid;

impl ServerRuntime {
    pub async fn process_manifest_request(
        &self,
        caller: CallerIdentity,
        request_id: Uuid,
    ) -> Result<std::path::PathBuf, ServerError> {
        self.prepare_exchange(caller)?;
        let path = self.paths.request(caller, request_id);
        validate_request_file(&path, caller)?;
        let bytes = zeroize::Zeroizing::new(read_bounded(&path, self.max_request_bytes)?);
        std::fs::remove_file(path)?;
        let parsed = serde_json::from_slice::<Request>(&bytes)
            .map_err(|_| AuthorityError::InvalidState("invalid manifest request".into()))
            .and_then(|request| {
                // Negotiation must precede opening or creating authoritative
                // storage. Unsupported clients cannot initialize or upgrade it.
                request.compatibility.validate()?;
                if request.request_id != request_id {
                    return Err(AuthorityError::InvalidState(
                        "request identity mismatch".into(),
                    ));
                }
                Ok(request)
            });
        let result = match parsed {
            Ok(request) => self.dispatch_manifest(request).await,
            Err(error) => Err(error),
        };
        let response = Response {
            compatibility: Compatibility::default(),
            request_id,
            result: result.map_err(|error| error.failure()),
        };
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&response)?);
        if bytes.len() > self.max_response_bytes {
            return Err(ServerError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
            });
        }
        let path = self.paths.response(caller, request_id);
        write_response(&path, &bytes, caller)?;
        Ok(path)
    }

    async fn dispatch_manifest(&self, request: Request) -> Result<Reply, AuthorityError> {
        let appliance_id = load_or_create_appliance_id(&self.paths).map_err(|_| {
            AuthorityError::InvalidState("unable to read appliance identity".into())
        })?;
        if !matches!(request.operation, Operation::Info)
            && request.appliance_id != Some(appliance_id)
        {
            return Err(AuthorityError::InvalidState(
                "appliance identity mismatch".into(),
            ));
        }
        let machine_fingerprint = bind_machine_identity(&self.paths, &read_machine_identity()?)?;
        if matches!(request.operation, Operation::Info) {
            return Ok(Reply::Info {
                appliance_id,
                machine_fingerprint,
                software_version: env!("CARGO_PKG_VERSION").into(),
            });
        }
        let store = ManifestStore::open(&self.paths.control_dir(), appliance_id)?;
        match request.operation {
            operation @ (Operation::EnrollPeer { .. } | Operation::RevokePeer { .. }) => {
                crate::enrollment::mutate(&store, request.request_id, operation).await
            }
            Operation::ExportCertificateMaterial {
                instance_id,
                peer_id,
                expected_revision,
            } => crate::enrollment::export(&store, instance_id, peer_id, expected_revision),
            Operation::Info => unreachable!("handled before opening authoritative storage"),
            Operation::Discover => Ok(Reply::Discovery(store.discover()?)),
            Operation::Read { instance_id } => Ok(Reply::Manifest(Box::new(
                store.read(instance_id)?.ok_or(AuthorityError::NotFound)?,
            ))),
            Operation::Save { request: save } => {
                vam_application::validate_remote_configuration(&save.configuration)
                    .map_err(|error| AuthorityError::InvalidState(error.message))?;
                if save.request_id != request.request_id || save.appliance_id != appliance_id {
                    return Err(AuthorityError::InvalidState(
                        "mutation identity mismatch".into(),
                    ));
                }
                Ok(Reply::Manifest(Box::new(store.save(&save)?)))
            }
            Operation::Remove {
                request: save,
                confirmed,
            }
            | Operation::ArchiveInstance {
                request: save,
                confirmed,
            } => {
                if save.request_id != request.request_id || save.appliance_id != appliance_id {
                    return Err(AuthorityError::InvalidState(
                        "mutation identity mismatch".into(),
                    ));
                }
                crate::runtime::remove_instance(&store, &save, confirmed).await
            }
            Operation::RestoreArchivedInstance {
                instance_id,
                expected_revision,
                confirmed,
            } => crate::archive::restore(
                &store,
                std::path::Path::new("/opt/vpn-appliance-manager"),
                instance_id,
                expected_revision,
                request.request_id,
                confirmed,
            ),
            Operation::History { instance_id } => Ok(Reply::History(store.history(instance_id)?)),
            Operation::RuntimeHistory { instance_id } => {
                crate::runtime::history(&store, instance_id)
            }
            Operation::ReconcileRuntime {
                instance_id,
                mutation_id,
            } => crate::runtime::reconcile(&store, instance_id, mutation_id),
            Operation::Reconcile {
                instance_id,
                mutation_id,
            } => {
                let result = if store.read(instance_id)?.is_some() {
                    store
                        .history(instance_id)?
                        .into_iter()
                        .find(|generation| generation.request_id == mutation_id)
                        .map(Box::new)
                } else {
                    None
                };
                Ok(Reply::Reconciled(result))
            }
            Operation::RestoreDesired {
                instance_id,
                revision,
                expected_revision,
                confirmed,
            } => Ok(Reply::Manifest(Box::new(store.restore_desired(
                instance_id,
                revision,
                expected_revision,
                request.request_id,
                confirmed,
            )?))),
            Operation::ExportPeerPsk {
                instance_id,
                peer_id,
                expected_revision,
            } => {
                let value = store.export_peer_psk(instance_id, peer_id, expected_revision)?;
                let path = format!("/opt/vpn-appliance-manager/instances/{instance_id}/state.json");
                crate::runtime::validate_runtime_path(&path).map_err(|_| {
                    AuthorityError::InvalidState("unsafe deployment metadata path".into())
                })?;
                let server_public_key = if std::path::Path::new(&path).try_exists()? {
                    let bytes =
                        read_bounded(std::path::Path::new(&path), 1024 * 1024).map_err(|_| {
                            AuthorityError::InvalidState("unreadable deployment metadata".into())
                        })?;
                    let state: serde_json::Value = serde_json::from_slice(&bytes)?;
                    state
                        .get("server_public_key")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                } else {
                    None
                };
                Ok(Reply::PeerPsk {
                    value,
                    server_public_key,
                })
            }
            Operation::BackupControl { confirmed } => {
                if !confirmed {
                    return Err(AuthorityError::InvalidState(
                        "control backup requires confirmation".into(),
                    ));
                }
                let backup_id = request.request_id;
                store.backup_control_with(
                    &self.paths.root.join("recovery").join(backup_id.to_string()),
                    |destination| {
                        for (source, target) in [("instances", "deployment-trees"), ("backups", "deployment-backups")] {
                            let source = format!("/opt/vpn-appliance-manager/{source}");
                            crate::runtime::validate_runtime_path(&source).map_err(|_| AuthorityError::InvalidState("unsafe disaster-recovery source".into()))?;
                            if std::path::Path::new(&source).try_exists()? {
                                let result = std::process::Command::new("/bin/cp").env_clear().args(["-a", "--"]).arg(&source).arg(destination.join(target)).output()?;
                                if !result.status.success() { return Err(AuthorityError::InvalidState("runtime identity backup failed; incomplete bundle must not be restored".into())); }
                            }
                        }
                        let result = std::process::Command::new("/bin/sync").env_clear().arg("-f").arg(destination).output()?;
                        if !result.status.success() { return Err(AuthorityError::InvalidState("disaster-recovery bundle synchronization failed".into())); }
                        Ok(())
                    },
                )?;
                Ok(Reply::ControlBackup { backup_id })
            }
            Operation::InspectLegacy { instance_id } => {
                let _lock = store.maintenance_lock()?;
                inspect_legacy(instance_id)
            }
            Operation::Migrate {
                request: save,
                expected_legacy_digest,
            } => {
                vam_application::validate_remote_configuration(&save.configuration)
                    .map_err(|error| AuthorityError::InvalidState(error.message))?;
                if save.request_id != request.request_id
                    || save.appliance_id != appliance_id
                    || save.expected_revision != 0
                {
                    return Err(AuthorityError::InvalidState(
                        "invalid migration identity or create revision".into(),
                    ));
                }
                let manifest = store.save_checked(&save, || {
                    let Reply::LegacyInspection {
                        metadata_digest, ..
                    } = inspect_legacy(save.configuration.instance.id)?
                    else {
                        unreachable!()
                    };
                    if metadata_digest != expected_legacy_digest {
                        return Err(AuthorityError::InvalidState(
                            "legacy deployment changed after migration preview".into(),
                        ));
                    }
                    Ok(())
                })?;
                Ok(Reply::Manifest(Box::new(manifest)))
            }
            Operation::BackupLegacy {
                instance_id,
                confirmed,
            } => {
                let _lock = store.maintenance_lock()?;
                if !confirmed {
                    return Err(AuthorityError::InvalidState(
                        "legacy backup requires confirmation".into(),
                    ));
                }
                let source = format!("/opt/vpn-appliance-manager/instances/{instance_id}");
                crate::runtime::validate_runtime_path(&source).map_err(|_| {
                    AuthorityError::InvalidState("unsafe legacy runtime path".into())
                })?;
                if !std::path::Path::new(&source).try_exists()? {
                    return Ok(Reply::LegacyBackup { backup_name: None });
                }
                let backup_name = format!("migration-{}", request.request_id);
                let parent = format!("/opt/vpn-appliance-manager/backups/{instance_id}");
                crate::runtime::validate_runtime_path(&parent).map_err(|_| {
                    AuthorityError::InvalidState("unsafe legacy backup path".into())
                })?;
                std::fs::create_dir_all(&parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
                }
                let destination = format!("{parent}/{backup_name}");
                if std::path::Path::new(&destination).try_exists()? {
                    return Err(AuthorityError::InvalidState(
                        "legacy backup destination already exists; inspect it before retrying"
                            .into(),
                    ));
                }
                let status = tokio::process::Command::new("/bin/cp")
                    .env_clear()
                    .args(["-a", "--", &source, &destination])
                    .status()
                    .await?;
                if !status.success() {
                    return Err(AuthorityError::InvalidState(
                        "legacy runtime backup failed".into(),
                    ));
                }
                Ok(Reply::LegacyBackup {
                    backup_name: Some(backup_name),
                })
            }
            operation @ (Operation::PreviewDeployment { .. }
            | Operation::ApplyDeployment { .. }
            | Operation::Health { .. }
            | Operation::BackupDeployment { .. }
            | Operation::ListBackups { .. }
            | Operation::PreviewRestore { .. }
            | Operation::RestoreDeployment { .. }
            | Operation::StartInstance { .. }
            | Operation::StopInstance { .. }) => {
                crate::runtime::execute(&store, request.request_id, operation).await
            }
        }
    }
}

fn read_machine_identity() -> Result<String, AuthorityError> {
    let machine = std::path::Path::new("/etc/machine-id");
    match read_bounded(machine, 128) {
        Ok(bytes) if bytes.len() >= 16 => return Ok(format!("{:x}", Sha256::digest(bytes))),
        Ok(_) => {
            return Err(AuthorityError::InvalidState(
                "host machine identity is uninitialized".into(),
            ));
        }
        Err(ServerError::Filesystem(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(AuthorityError::InvalidState(
                "cannot read host machine identity".into(),
            ));
        }
    }
    // Non-systemd hosts still have persistent SSH public identity. Only public
    // key fields participate; changing a comment does not change the binding.
    for path in [
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/etc/ssh/ssh_host_rsa_key.pub",
    ] {
        match read_bounded(std::path::Path::new(path), 4096) {
            Ok(bytes) => {
                let key = std::str::from_utf8(&bytes)
                    .map_err(|_| {
                        AuthorityError::InvalidState("invalid host public key encoding".into())
                    })?
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>();
                if key.len() != 2 {
                    return Err(AuthorityError::InvalidState(
                        "invalid host public key".into(),
                    ));
                }
                return Ok(format!("{:x}", Sha256::digest(key.join(" "))));
            }
            Err(ServerError::Filesystem(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            }
            Err(_) => {
                return Err(AuthorityError::InvalidState(
                    "cannot read host public identity".into(),
                ));
            }
        }
    }
    Err(AuthorityError::InvalidState(
        "persistent host identity is unavailable; initialize machine-id or host SSH keys".into(),
    ))
}

fn bind_machine_identity(
    paths: &super::ServerPaths,
    fingerprint: &str,
) -> Result<String, AuthorityError> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(paths.control_dir().join("identity.lock"))?;
    lock.lock()?;
    let binding = paths.control_dir().join("machine-fingerprint");
    match std::fs::symlink_metadata(&binding) {
        Ok(_) => {
            super::validate_request_file(&binding, super::effective_identity()).map_err(|_| {
                AuthorityError::InvalidState("unsafe machine identity binding".into())
            })?;
            if read_bounded(&binding, 128).map_err(|_| {
                AuthorityError::InvalidState("unreadable machine identity binding".into())
            })? != fingerprint.as_bytes()
            {
                return Err(AuthorityError::InvalidState("cloned appliance identity detected; explicit disaster-recovery identity review is required".into()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let temporary = paths
                .control_dir()
                .join(format!(".machine-{}", Uuid::new_v4()));
            super::create_private_file(&temporary, fingerprint.as_bytes())?;
            std::fs::rename(temporary, binding)?;
            std::fs::File::open(paths.control_dir())?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(fingerprint.into())
}

fn inspect_legacy(instance_id: Uuid) -> Result<Reply, AuthorityError> {
    let root = format!("/opt/vpn-appliance-manager/instances/{instance_id}");
    crate::runtime::validate_runtime_path(&root)
        .map_err(|_| AuthorityError::InvalidState("unsafe legacy runtime path".into()))?;
    let mut digest = Sha256::new();
    let mut instance = None;
    for name in ["instance.json", "state.json", "compose.yaml"] {
        let path = std::path::Path::new(&root).join(name);
        crate::runtime::validate_runtime_path(
            path.to_str()
                .ok_or_else(|| AuthorityError::InvalidState("invalid runtime path".into()))?,
        )
        .map_err(|_| AuthorityError::InvalidState("unsafe legacy metadata path".into()))?;
        if path.try_exists()? {
            let bytes = read_bounded(&path, 1024 * 1024).map_err(|_| {
                AuthorityError::InvalidState("legacy metadata is unreadable or oversized".into())
            })?;
            digest.update(name.as_bytes());
            digest.update(&bytes);
            if name == "instance.json" {
                instance = Some(Box::new(serde_json::from_slice(&bytes)?));
            }
        }
    }
    Ok(Reply::LegacyInspection {
        deployment_present: std::path::Path::new(&root)
            .join("compose.yaml")
            .try_exists()?,
        instance,
        metadata_digest: format!("{:x}", digest.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exchange(runtime: &ServerRuntime, request: &Request) -> Response {
        let caller = crate::effective_identity();
        runtime.prepare_exchange(caller).unwrap();
        crate::create_private_file(
            &runtime.paths.request(caller, request.request_id),
            &serde_json::to_vec(request).unwrap(),
        )
        .unwrap();
        let path = runtime
            .process_manifest_request(caller, request.request_id)
            .await
            .unwrap();
        let response = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        runtime
            .cleanup_exchange(caller, request.request_id)
            .unwrap();
        response
    }

    #[tokio::test]
    async fn negotiation_rejects_old_protocol_without_authority_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::new(dir.path());
        let request = Request {
            compatibility: Compatibility {
                protocol_version: 1,
                manifest_schema: 1,
            },
            request_id: Uuid::new_v4(),
            appliance_id: None,
            operation: Operation::Info,
        };
        assert_eq!(
            exchange(&runtime, &request).await.result.unwrap_err().code,
            vam_authority::AuthorityFailureCode::Incompatible
        );
        assert!(!runtime.paths.control_dir().exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn discovery_is_empty_only_after_verified_appliance_identity() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::new(dir.path());
        let appliance_id = crate::load_or_create_appliance_id(runtime.paths()).unwrap();
        let mut request = Request {
            compatibility: Compatibility::default(),
            request_id: Uuid::new_v4(),
            appliance_id: Some(Uuid::new_v4()),
            operation: Operation::Discover,
        };
        assert!(exchange(&runtime, &request).await.result.is_err());
        assert!(!runtime.paths.control_dir().join("instances").exists());
        request.appliance_id = Some(appliance_id);
        request.request_id = Uuid::new_v4();
        let Reply::Discovery(discovery) = exchange(&runtime, &request).await.result.unwrap() else {
            panic!("expected discovery");
        };
        assert!(discovery.instances.is_empty());
        assert!(discovery.errors.is_empty());
    }

    #[test]
    fn cloned_machine_binding_is_rejected_and_original_identity_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = ServerRuntime::new(dir.path());
        let identity = super::super::load_or_create_appliance_id(runtime.paths()).unwrap();
        bind_machine_identity(runtime.paths(), "machine-A").unwrap();
        assert!(bind_machine_identity(runtime.paths(), "machine-B").is_err());
        assert_eq!(
            super::super::read_appliance_id(&runtime.paths.appliance_id()).unwrap(),
            identity
        );
        assert_eq!(
            std::fs::read_to_string(runtime.paths.control_dir().join("machine-fingerprint"))
                .unwrap(),
            "machine-A"
        );
    }
}
