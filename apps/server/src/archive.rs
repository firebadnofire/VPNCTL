//! Retained instance snapshots and stopped restores. All paths originate from
//! authoritative instance/operation UUIDs, never client-supplied paths.

use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use vam_authority::{
    AuthorityError,
    manifest::{InstanceArchive, ManifestStore, Reply},
};

fn invalid(message: &str) -> AuthorityError {
    AuthorityError::InvalidState(message.into())
}

pub(crate) fn checked_path(root: &Path, path: &Path) -> Result<(), AuthorityError> {
    if !path.starts_with(root)
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid("archive path escapes the managed runtime root"));
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid("symlink in archive path"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(crate) fn backup_path(
    root: &Path,
    archive: &InstanceArchive,
) -> Result<Option<PathBuf>, AuthorityError> {
    let Some(name) = &archive.backup_name else {
        return Ok(None);
    };
    if name != &format!("archive-{}", archive.request_id) {
        return Err(invalid("invalid archive backup identity"));
    }
    let path = root
        .join("backups")
        .join(archive.instance_id.to_string())
        .join(name);
    checked_path(root, &path)?;
    Ok(Some(path))
}

pub(crate) fn validate_snapshot(path: &Path) -> Result<(), AuthorityError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("instance archive is not a real directory"));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(invalid("symlink or special file in instance archive"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != fs::symlink_metadata(path)?.dev()
                || (metadata.is_file() && metadata.nlink() != 1)
            {
                return Err(invalid("mount or hard link in instance archive"));
            }
        }
        if metadata.is_dir() {
            validate_snapshot(&entry.path())?;
        }
    }
    Ok(())
}

pub(crate) fn restore(
    store: &ManifestStore,
    root: &Path,
    instance_id: Uuid,
    expected_revision: u64,
    request_id: Uuid,
    confirmed: bool,
) -> Result<Reply, AuthorityError> {
    if !confirmed {
        return Err(invalid(
            "restoring an archived instance requires confirmation",
        ));
    }
    if let Some(manifest) =
        store.reconciled_archive_restore(instance_id, expected_revision, request_id)?
    {
        return Ok(Reply::Manifest(Box::new(manifest)));
    }
    let context = store.archived_runtime_context(instance_id, expected_revision)?;
    context.validate_archive_restore()?;
    if context.pending_operation()? == Some(context.manifest.request_id) {
        // Archival committed before its process lost the completion response.
        context.finish_mutation()?;
    }
    // Port/subnet conflicts are rejected before any runtime files are changed.
    context.begin_or_resume_removal(request_id)?;
    let result = (|| {
        let archive = if let Some(archive) = context.archive()? {
            archive
        } else {
            // Older helpers retained complete runtime trees in trash. Adopt
            // only an unambiguous whole-instance tree; never guess by mtime.
            let trash = root.join("trash");
            checked_path(root, &trash)?;
            let prefix = format!("{instance_id}-");
            let mut candidates = Vec::new();
            if trash.try_exists()? {
                for entry in fs::read_dir(&trash)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(timestamp) = name.strip_prefix(&prefix)
                        && chrono::NaiveDateTime::parse_from_str(timestamp, "%Y%m%dT%H%M%SZ")
                            .is_ok()
                    {
                        checked_path(root, &entry.path())?;
                        if !entry.file_type()?.is_dir() {
                            return Err(invalid("legacy instance archive is not a directory"));
                        }
                        candidates.push(entry.path());
                    }
                }
            }
            if candidates.len() > 1 {
                return Err(invalid(
                    "multiple legacy runtime archives exist; explicit server recovery is required to choose the correct snapshot",
                ));
            }
            let archive = InstanceArchive {
                instance_id,
                request_id: context.manifest.request_id,
                desired_revision: context.manifest.revision - 1,
                deployed_revision: context.deployed()?,
                backup_name: candidates
                    .first()
                    .map(|_| format!("archive-{}", context.manifest.request_id)),
            };
            if let (Some(source), Some(destination)) =
                (candidates.first(), backup_path(root, &archive)?)
            {
                publish_snapshot(root, source, &destination, request_id)?;
            } else if archive.deployed_revision.is_some() {
                return Err(invalid(
                    "the archived deployment files are missing; restore refused to avoid replacing server identities",
                ));
            }
            context.remember_archive(&archive)?;
            archive
        };
        if archive.instance_id != instance_id
            || archive.request_id != context.manifest.request_id
            || archive.desired_revision + 1 != context.manifest.revision
        {
            return Err(invalid(
                "archive metadata does not match the authoritative archived revision",
            ));
        }
        if let Some(source) = backup_path(root, &archive)? {
            publish_snapshot(
                root,
                &source,
                &root.join("instances").join(instance_id.to_string()),
                request_id,
            )?;
            if let Some(name) = &archive.backup_name {
                context.remember_backup(name, archive.deployed_revision)?;
            }
        } else if archive.deployed_revision.is_some() {
            return Err(invalid("deployed instance archive has no runtime snapshot"));
        }
        let manifest = context.commit_archive_restore(request_id)?;
        context.finish_mutation()?;
        Ok(Reply::Manifest(Box::new(manifest)))
    })();
    match result {
        Ok(reply) => Ok(reply),
        Err(error) => {
            let mut failure =
                vam_protocol::AppError::new("archive_restore_failed", error.to_string());
            failure.scope = Some(request_id.to_string());
            failure.remote_state_changed = true;
            failure.remediation = Some("The archive is retained. Retry this restore with the same request UUID; do not deploy or regenerate instance keys.".into());
            Ok(Reply::OperationFailure(failure))
        }
    }
}

/// Keep the original snapshot. Publication never overwrites an active tree.
fn publish_snapshot(
    root: &Path,
    source: &Path,
    destination: &Path,
    operation: Uuid,
) -> Result<(), AuthorityError> {
    use std::io::Write;
    checked_path(root, source)?;
    checked_path(root, destination)?;
    let marker = ".vpnctl-archive-restore";
    if destination.try_exists()? {
        checked_path(root, &destination.join(marker))?;
        return if fs::read_to_string(destination.join(marker))? == operation.to_string() {
            Ok(())
        } else {
            Err(invalid("restore would overwrite an existing runtime tree"))
        };
    }
    let staging = root.join("staging").join(format!(
        "archive-restore-{operation}-{}",
        destination
            .file_name()
            .ok_or_else(|| invalid("missing restore destination"))?
            .to_string_lossy()
    ));
    checked_path(root, &staging)?;
    fs::create_dir_all(
        staging
            .parent()
            .ok_or_else(|| invalid("missing staging parent"))?,
    )?;
    copy_tree(source, &staging)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(staging.join(marker))?;
    file.write_all(operation.to_string().as_bytes())?;
    file.sync_all()?;
    fs::File::open(&staging)?.sync_all()?;
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("missing archive parent"))?;
    fs::create_dir_all(parent)?;
    checked_path(root, parent)?;
    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;
        use rustix::fs::{RenameFlags, renameat_with};
        let from = open(
            staging
                .parent()
                .ok_or_else(|| invalid("missing staging parent"))?,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let to = open(
            parent,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        renameat_with(
            &from,
            staging
                .file_name()
                .ok_or_else(|| invalid("missing staging name"))?,
            &to,
            destination
                .file_name()
                .ok_or_else(|| invalid("missing destination name"))?,
            RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
    }
    #[cfg(not(target_os = "linux"))]
    publish_on_test_host(&staging, destination)?;
    fs::File::open(parent)?.sync_all()?;
    fs::File::open(
        staging
            .parent()
            .ok_or_else(|| invalid("missing staging parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn publish_on_test_host(source: &Path, destination: &Path) -> Result<(), AuthorityError> {
    // Production helpers run on Linux; desktop tests use exclusive roots.
    if cfg!(test) {
        fs::rename(source, destination)?;
        Ok(())
    } else {
        Err(invalid(
            "runtime archive publication requires the Linux helper",
        ))
    }
}

#[cfg(unix)]
fn copy_tree(source: &Path, destination: &Path) -> Result<(), AuthorityError> {
    use nix::{
        fcntl::{AtFlags, OFlag, open, openat},
        sys::stat::{Mode, SFlag, fchmod, fstat, fstatat, mkdirat},
    };
    use std::os::fd::OwnedFd;
    fn io(error: nix::errno::Errno) -> AuthorityError {
        std::io::Error::from(error).into()
    }
    fn copy(
        source: &OwnedFd,
        dest: &OwnedFd,
        device: nix::libc::dev_t,
    ) -> Result<(), AuthorityError> {
        let mut dir = nix::dir::Dir::from_fd(source.try_clone()?).map_err(io)?;
        for entry in dir.iter() {
            let entry = entry.map_err(io)?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            let stat = fstatat(source, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io)?;
            if stat.st_dev != device {
                return Err(invalid("mount boundary in runtime archive"));
            }
            let mode = Mode::from_bits_truncate(stat.st_mode) & Mode::from_bits_truncate(0o777);
            match SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT {
                SFlag::S_IFDIR => {
                    match mkdirat(dest, name, Mode::from_bits_truncate(0o700)) {
                        Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
                        Err(error) => return Err(io(error)),
                    }
                    let from = openat(
                        source,
                        name,
                        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(io)?;
                    let to = openat(
                        dest,
                        name,
                        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(io)?;
                    copy(&from, &to, device)?;
                    fchmod(&to, mode).map_err(io)?;
                    fs::File::from(to).sync_all()?;
                }
                SFlag::S_IFREG => {
                    if stat.st_nlink != 1 {
                        return Err(invalid("hard-linked file in runtime archive"));
                    }
                    let from = openat(
                        source,
                        name,
                        OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(io)?;
                    let actual = fstat(&from).map_err(io)?;
                    if actual.st_ino != stat.st_ino || actual.st_dev != stat.st_dev {
                        return Err(invalid("runtime archive changed during restore"));
                    }
                    let to = openat(
                        dest,
                        name,
                        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC | OFlag::O_NOFOLLOW,
                        Mode::from_bits_truncate(0o600),
                    )
                    .map_err(io)?;
                    let mut from = fs::File::from(from);
                    let mut to = fs::File::from(to);
                    std::io::copy(&mut from, &mut to)?;
                    fchmod(&to, mode).map_err(io)?;
                    to.sync_all()?;
                }
                _ => return Err(invalid("symlink or special file in runtime archive")),
            }
        }
        Ok(())
    }
    let from = open(
        source,
        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io)?;
    match fs::create_dir(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let to = open(
        destination,
        OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io)?;
    fchmod(&to, Mode::from_bits_truncate(0o700)).map_err(io)?;
    let device = fstat(&from).map_err(io)?.st_dev;
    copy(&from, &to, device)
}

#[cfg(not(unix))]
fn copy_tree(_source: &Path, _destination: &Path) -> Result<(), AuthorityError> {
    Err(invalid("archive recovery requires the Linux helper"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn archived_fixture(root: &Path, legacy: bool) -> (ManifestStore, Uuid, u64, PathBuf) {
        use vam_authority::manifest::{Compatibility, Configuration, SaveRequest};
        use vam_core::{
            BackendSettings, DnsConfig, EndpointConfig, NetworkConfig, RoutingMode, VpnBackendKind,
            VpnInstance,
        };
        let appliance = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let store = ManifestStore::open(&root.join("control"), appliance).unwrap();
        let mut input = SaveRequest {
            compatibility: Compatibility::default(),
            appliance_id: appliance,
            request_id: Uuid::new_v4(),
            expected_revision: 0,
            secrets: std::collections::BTreeMap::default(),
            configuration: Configuration {
                instance: VpnInstance {
                    id,
                    host_id: appliance,
                    display_name: "Archived VPN".into(),
                    backend: VpnBackendKind::WireGuard,
                    backend_settings: BackendSettings::default(),
                    endpoint: EndpointConfig {
                        host: "vpn.example.test".into(),
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
                users: vec![],
                peers: vec![],
                dns_records: vec![],
                dns_blocklist_domains: vec![],
            },
        };
        store.save(&input).unwrap();
        input.request_id = Uuid::new_v4();
        input.expected_revision = 1;
        let source = if legacy {
            root.join("trash").join(format!("{id}-20261112T100000Z"))
        } else {
            root.join("backups")
                .join(id.to_string())
                .join(format!("archive-{}", input.request_id))
        };
        fs::create_dir_all(source.join("vpn")).unwrap();
        fs::write(
            source.join("vpn/server.key"),
            b"persistent server private key",
        )
        .unwrap();
        fs::write(source.join("compose.yaml"), b"name: archived-vpn\n").unwrap();
        {
            let context = store.runtime_context(id, Some(1)).unwrap();
            context.set_deployed_revision(Some(1)).unwrap();
            if !legacy {
                context
                    .remember_archive(&InstanceArchive {
                        instance_id: id,
                        request_id: input.request_id,
                        desired_revision: 1,
                        deployed_revision: Some(1),
                        backup_name: Some(format!("archive-{}", input.request_id)),
                    })
                    .unwrap();
            }
        }
        let archived = store.remove(&input, true).unwrap();
        (store, id, archived.revision, source)
    }

    #[test]
    fn helper_restores_new_and_legacy_archives_without_starting_or_consuming_snapshots() {
        for legacy in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            let (store, id, revision, source) = archived_fixture(&root, legacy);
            let request = Uuid::new_v4();
            assert!(restore(&store, &root, id, revision, request, false).is_err());
            let Reply::Manifest(restored) =
                restore(&store, &root, id, revision, request, true).unwrap()
            else {
                panic!("restore failed");
            };
            assert!(!restored.removed);
            assert_eq!(restored.revision, revision + 1);
            assert_eq!(
                fs::read(
                    root.join("instances")
                        .join(id.to_string())
                        .join("vpn/server.key")
                )
                .unwrap(),
                b"persistent server private key"
            );
            assert!(source.join("vpn/server.key").exists());
            let Reply::Manifest(retried) =
                restore(&store, &root, id, revision, request, true).unwrap()
            else {
                panic!("retry failed");
            };
            assert_eq!(retried, restored);
            assert!(store.discover().unwrap().archived_instances.is_empty());
            assert_eq!(
                store.runtime_context(id, None).unwrap().deployed().unwrap(),
                Some(1)
            );
        }
    }

    #[test]
    fn missing_runtime_archive_never_creates_a_replacement_identity() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let (store, id, revision, source) = archived_fixture(&root, false);
        fs::remove_dir_all(&source).unwrap();
        let request = Uuid::new_v4();
        assert!(matches!(
            restore(&store, &root, id, revision, request, true).unwrap(),
            Reply::OperationFailure(_)
        ));
        assert!(store.read(id).unwrap().unwrap().removed);
        assert!(!root.join("instances").join(id.to_string()).exists());
        assert_eq!(
            store.discover().unwrap().deployments[&id].pending_operation,
            Some(request)
        );
    }
    #[test]
    fn retained_runtime_snapshot_restores_keys_and_is_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let source = root.join("backups/instance/archive-operation");
        fs::create_dir_all(source.join("vpn")).unwrap();
        fs::write(source.join("vpn/server.key"), b"original server identity").unwrap();
        fs::write(source.join("compose.yaml"), b"name: test-instance\n").unwrap();
        let target = root.join("instances/instance");
        let operation = Uuid::new_v4();
        publish_snapshot(&root, &source, &target, operation).unwrap();
        publish_snapshot(&root, &source, &target, operation).unwrap();
        assert_eq!(
            fs::read(target.join("vpn/server.key")).unwrap(),
            b"original server identity"
        );
        assert!(source.join("vpn/server.key").exists());
        assert!(publish_snapshot(&root, &source, &target, Uuid::new_v4()).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn restore_refuses_symlinks_and_keeps_original_archive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let source = root.join("backups/source");
        fs::create_dir_all(&source).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", source.join("unexpected")).unwrap();
        assert!(
            publish_snapshot(
                &root,
                &source,
                &root.join("instances/instance"),
                Uuid::new_v4()
            )
            .is_err()
        );
        assert!(!root.join("instances/instance").exists());
        assert!(
            fs::symlink_metadata(source.join("unexpected"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
