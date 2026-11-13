//! Reuse the established deployment executor inside the privileged helper.
//! Its `SQLite` index is ephemeral and is reconstructed from the locked JSON
//! revision. No client controls commands, upload paths, or runtime credentials.

use std::{io::Write, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_application::ApplicationService;
use vam_authority::{
    AuthorityError,
    manifest::{
        ManifestStore, Operation, Reply, RuntimeContext, RuntimeHistoryEntry, RuntimeReconciliation,
    },
};
use vam_core::{DockerHost, SecretReference, SshConnectionConfig};
use vam_protocol::{AppError, HostKeyInfo};
use vam_secrets::{MemorySecretStore, SecretStore};
use vam_ssh::{CommandResult, DownloadRequest, SshError, SshTransport, UploadRequest};
use vam_storage::Storage;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct Receipt {
    operation_hash: String,
    #[serde(default)]
    operation: String,
    desired_revision: u64,
    reply: Reply,
    #[serde(default)]
    updates_deployment: bool,
    #[serde(default)]
    deployed_revision: Option<u64>,
    #[serde(default)]
    requires_recovery: bool,
}

pub fn history(store: &ManifestStore, instance_id: Uuid) -> Result<Reply, AuthorityError> {
    let context = store.runtime_context(instance_id, None)?;
    let mut entries = Vec::new();
    for id in context.record_ids()? {
        let value: serde_json::Value = context
            .read_record(id)?
            .ok_or_else(|| AuthorityError::InvalidState("missing runtime receipt".into()))?;
        if value.get("request_hash").is_some() {
            // Certificate receipts have a separate public manifest revision.
            continue;
        }
        if value.get("operation_hash").is_none() {
            return Err(AuthorityError::InvalidState(
                "unknown runtime receipt format".into(),
            ));
        }
        let receipt: Receipt = serde_json::from_value(value)?;
        entries.push(RuntimeHistoryEntry {
            request_id: id,
            desired_revision: receipt.desired_revision,
            operation: if receipt.operation.is_empty() {
                "runtime".into()
            } else {
                receipt.operation
            },
            succeeded: !matches!(receipt.reply, Reply::OperationFailure(_)),
            requires_recovery: receipt.requires_recovery,
            deployed_revision: receipt
                .updates_deployment
                .then_some(receipt.deployed_revision)
                .flatten(),
        });
    }
    Ok(Reply::RuntimeHistory(entries))
}

pub async fn reconcile(
    store: &ManifestStore,
    instance_id: Uuid,
    mutation_id: Uuid,
) -> Result<Reply, AuthorityError> {
    let context = store.runtime_context(instance_id, None)?;
    let pending = context.pending_operation()?;
    let status = if let Some(mut receipt) = context.read_record::<Receipt>(mutation_id)? {
        if receipt.requires_recovery
            && matches!(&receipt.reply, Reply::OperationFailure(error) if error.code == "dns_blocking_apply_failed")
        {
            let revision = receipt.deployed_revision.ok_or_else(|| {
                AuthorityError::InvalidState("Missing active revision for DNS recovery.".into())
            })?;
            let configuration = context.historical_configuration(revision)?;
            crate::blocking::apply_cached(
                &context,
                &configuration,
                Path::new("/opt/vpn-appliance-manager"),
            )
            .await?;
            let service = project_configuration(&context, &configuration)
                .await
                .map_err(|error| AuthorityError::InvalidState(error.message))?;
            receipt.reply = Reply::Health(
                service
                    .health(instance_id)
                    .await
                    .map_err(|error| AuthorityError::InvalidState(error.message))?,
            );
            receipt.requires_recovery = false;
            context.record(mutation_id, &receipt)?;
        }
        if receipt.requires_recovery {
            RuntimeReconciliation::Unresolved
        } else {
            if pending == Some(mutation_id) {
                if receipt.updates_deployment {
                    context.set_deployed_revision(receipt.deployed_revision)?;
                }
                context.finish_mutation()?;
            }
            if matches!(receipt.reply, Reply::OperationFailure(_)) {
                RuntimeReconciliation::Uncommitted
            } else {
                RuntimeReconciliation::Committed
            }
        }
    } else if pending == Some(mutation_id) {
        RuntimeReconciliation::Unresolved
    } else {
        RuntimeReconciliation::Uncommitted
    };
    Ok(Reply::RuntimeReconciled(status))
}

pub async fn remove_instance(
    store: &ManifestStore,
    request: &vam_authority::manifest::SaveRequest,
    confirmed: bool,
) -> Result<Reply, AuthorityError> {
    request.compatibility.validate()?;
    if !confirmed {
        return Err(AuthorityError::InvalidState(
            "instance removal requires confirmation".into(),
        ));
    }
    let current = store
        .read(request.configuration.instance.id)?
        .ok_or(AuthorityError::NotFound)?;
    if current.removed {
        return store
            .remove(request, true)
            .map(|manifest| Reply::Manifest(Box::new(manifest)));
    }
    let context = store.runtime_context(
        request.configuration.instance.id,
        Some(request.expected_revision),
    )?;
    if context.manifest.configuration != request.configuration || !request.secrets.is_empty() {
        return Err(AuthorityError::InvalidState(
            "removal preview no longer matches the instance".into(),
        ));
    }
    let root = Path::new("/opt/vpn-appliance-manager");
    let current_path = root
        .join("instances")
        .join(request.configuration.instance.id.to_string());
    crate::archive::checked_path(root, &current_path)?;
    let backup_name = format!("archive-{}", request.request_id);
    let backup = root
        .join("backups")
        .join(request.configuration.instance.id.to_string())
        .join(&backup_name);
    crate::archive::checked_path(root, &backup)?;
    let runtime_present = current_path.try_exists()? || backup.try_exists()?;
    if current_path.try_exists()? {
        crate::archive::validate_snapshot(&current_path)?;
    }
    if backup.try_exists()? {
        crate::archive::validate_snapshot(&backup)?;
    }
    let deployed_revision = context.deployed()?;
    if deployed_revision.is_some() && !runtime_present {
        return Err(AuthorityError::InvalidState("The deployed runtime tree is missing; archive refused because a restorable snapshot cannot be retained.".into()));
    }
    let service = project_configuration(&context, &context.manifest.configuration)
        .await
        .map_err(|error| AuthorityError::InvalidState(error.message))?;
    context.begin_or_resume_removal(request.request_id)?;
    context.remember_archive(&vam_authority::manifest::InstanceArchive {
        instance_id: request.configuration.instance.id,
        request_id: request.request_id,
        desired_revision: context.manifest.revision,
        deployed_revision,
        backup_name: runtime_present.then_some(backup_name.clone()),
    })?;
    match service
        .archive_instance_for_recovery(request.configuration.instance.id, request.request_id)
        .await
    {
        Ok(result) => {
            if runtime_present && !result.remote_content_moved {
                return Err(AuthorityError::InvalidState("The runtime snapshot disappeared during archival; the instance remains pending recovery.".into()));
            }
            if runtime_present {
                context.remember_backup(&backup_name, deployed_revision)?;
            }
            let manifest = context.commit_removal(request)?;
            context.finish_mutation()?;
            Ok(Reply::Manifest(Box::new(manifest)))
        }
        Err(mut error) => {
            error.remote_state_changed = true;
            error.scope = Some(request.request_id.to_string());
            error.remediation = Some("Inspect the archived runtime tree and retry this confirmed removal with the same request UUID.".into());
            Ok(Reply::OperationFailure(error))
        }
    }
}

pub async fn execute(
    store: &ManifestStore,
    request_id: Uuid,
    operation: Operation,
) -> Result<Reply, AuthorityError> {
    let (instance_id, revision, mutating) = match &operation {
        Operation::PreviewDeployment {
            instance_id,
            expected_revision,
        }
        | Operation::PreviewRestore {
            instance_id,
            expected_revision,
            ..
        } => (*instance_id, Some(*expected_revision), false),
        Operation::ApplyDeployment {
            instance_id,
            expected_revision,
            ..
        }
        | Operation::BackupDeployment {
            instance_id,
            expected_revision,
        }
        | Operation::StartInstance {
            instance_id,
            expected_revision,
        }
        | Operation::StopInstance {
            instance_id,
            expected_revision,
        }
        | Operation::RestoreDeployment {
            instance_id,
            expected_revision,
            ..
        } => (*instance_id, Some(*expected_revision), true),
        Operation::Health { instance_id } | Operation::ListBackups { instance_id } => {
            (*instance_id, None, false)
        }
        _ => {
            return Err(AuthorityError::InvalidState(
                "unsupported runtime operation".into(),
            ));
        }
    };
    let context = if matches!(operation, Operation::ListBackups { .. })
        && let Some(manifest) = store.read(instance_id)?
        && manifest.removed
    {
        store.archived_runtime_context(instance_id, manifest.revision)?
    } else {
        store.runtime_context(instance_id, revision)?
    };
    let operation_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&operation)?));
    let operation_kind = match &operation {
        Operation::ApplyDeployment { .. } => "deploy",
        Operation::BackupDeployment { .. } => "backup",
        Operation::StartInstance { .. } => "start",
        Operation::StopInstance { .. } => "stop",
        Operation::RestoreDeployment { .. } => "restore_deployment",
        _ => "runtime",
    };
    if mutating && let Some(receipt) = context.read_record::<Receipt>(request_id)? {
        if receipt.operation_hash != operation_hash {
            return Err(AuthorityError::InvalidState(
                "runtime request UUID reused with different operation".into(),
            ));
        }
        if context.pending_operation()? == Some(request_id) {
            if receipt.updates_deployment {
                context.set_deployed_revision(receipt.deployed_revision)?;
            }
            if !receipt.requires_recovery {
                context.finish_mutation()?;
            }
        }
        return Ok(receipt.reply);
    }
    let restore = match &operation {
        Operation::PreviewRestore { backup_name, .. }
        | Operation::RestoreDeployment { backup_name, .. } => Some(backup_name.clone()),
        _ => None,
    };
    let restored_revision = restore
        .as_ref()
        .map(|name| context.backup_revision(name))
        .transpose()?
        .flatten();
    let restore_configuration = if restore.is_some() {
        let revision = restored_revision.ok_or_else(|| AuthorityError::InvalidState("This backup lacks a verified configuration revision. Preserve it and use the documented legacy recovery procedure.".into()))?;
        context.validate_certificate_backup_revision(revision)?;
        let configuration = context.historical_configuration(revision)?;
        if matches!(
            configuration.instance.backend,
            vam_core::VpnBackendKind::OpenVpn | vam_core::VpnBackendKind::Ikev2
        ) && context.manifest.configuration.peers.iter().any(|peer| {
            !configuration
                .peers
                .iter()
                .any(|old| old.id == peer.id && old.identity == peer.identity)
        }) {
            return Err(AuthorityError::InvalidState("Restoring this certificate state could invalidate identities required by newer desired state; restore refused.".into()));
        }
        Some(configuration)
    } else if matches!(
        &operation,
        Operation::Health { .. } | Operation::StartInstance { .. } | Operation::StopInstance { .. }
    ) {
        context
            .deployed()?
            .map(|revision| context.historical_configuration(revision))
            .transpose()?
    } else {
        None
    };
    let blocking_after = matches!(
        &operation,
        Operation::ApplyDeployment { .. }
            | Operation::RestoreDeployment { .. }
            | Operation::StartInstance { .. }
    );
    let blocking_configuration = restore_configuration
        .as_ref()
        .unwrap_or(&context.manifest.configuration)
        .clone();
    let mut projection = restore_configuration
        .as_ref()
        .unwrap_or(&context.manifest.configuration)
        .clone();
    if matches!(
        &operation,
        Operation::PreviewDeployment { .. } | Operation::ApplyDeployment { .. }
    ) {
        let blocking = context.blocking_state()?;
        projection.dns_blocklist_domains = crate::blocking::effective_domains(
            &context,
            &blocking.policy,
            &blocking.sources,
            &projection.dns_blocklist_domains,
        )?;
    }
    let service = project_configuration(&context, &projection)
        .await
        .map_err(|error| AuthorityError::InvalidState(error.message))?;
    let prior_deployed_revision = context.deployed()?;
    if mutating {
        context.begin_mutation(request_id)?;
    }
    let previous_backups = if mutating {
        service
            .list_backups(instance_id)
            .await
            .map_err(|error| AuthorityError::InvalidState(error.message))?
            .into_iter()
            .map(|backup| backup.name)
            .collect::<std::collections::BTreeSet<_>>()
    } else {
        std::collections::BTreeSet::new()
    };
    let result = match operation {
        Operation::PreviewDeployment { .. } => match service.plan_instance(instance_id).await {
            Ok(mut plan) => match service.deployment_evidence_hash(instance_id).await {
                Ok(evidence) => {
                    plan.desired_state_hash = bound_plan_hash(
                        &plan.desired_state_hash,
                        &evidence,
                        context.manifest.revision,
                    );
                    Ok(Reply::DeploymentPlan(plan))
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        Operation::ApplyDeployment {
            expected_state_hash,
            ..
        } => match service.plan_instance(instance_id).await {
            Ok(plan) => match service.deployment_evidence_hash(instance_id).await {
                Ok(evidence)
                    if bound_plan_hash(
                        &plan.desired_state_hash,
                        &evidence,
                        context.manifest.revision,
                    ) == expected_state_hash =>
                {
                    service
                        .apply_instance(instance_id, &plan.desired_state_hash)
                        .await
                        .map(Reply::DeploymentResult)
                }
                Ok(_) => Err(AppError::new(
                    "stale_deployment_plan",
                    "Desired revision or deployment evidence changed; review a new preview.",
                )),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        Operation::Health { .. } => service.health(instance_id).await.map(Reply::Health),
        Operation::ListBackups { .. } => {
            service.list_backups(instance_id).await.map(Reply::Backups)
        }
        Operation::StartInstance { .. } => {
            service.start_instance(instance_id).await.map(Reply::Health)
        }
        Operation::StopInstance { .. } => {
            service.stop_instance(instance_id).await.map(Reply::Health)
        }
        Operation::PreviewRestore { backup_name, .. } => {
            match service
                .preview_backup_restore(instance_id, &backup_name)
                .await
            {
                Ok(preview) => match service.deployment_evidence_hash(instance_id).await {
                    Ok(evidence) => Ok(Reply::RestorePreview {
                        backup_name,
                        expected_state_hash: bound_plan_hash(
                            &preview.expected_state_hash,
                            &evidence,
                            context.manifest.revision,
                        ),
                        identity_impact: preview.identity_impact,
                        desired_revision: context.manifest.revision,
                        deployed_revision: restored_revision,
                    }),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            }
        }
        Operation::RestoreDeployment {
            backup_name,
            expected_state_hash,
            confirmed,
            ..
        } => {
            if confirmed {
                match service
                    .preview_backup_restore(instance_id, &backup_name)
                    .await
                {
                    Ok(preview) => match service.deployment_evidence_hash(instance_id).await {
                        Ok(evidence)
                            if bound_plan_hash(
                                &preview.expected_state_hash,
                                &evidence,
                                context.manifest.revision,
                            ) == expected_state_hash =>
                        {
                            match service
                                .restore_backup_by_name(
                                    instance_id,
                                    &backup_name,
                                    &preview.expected_state_hash,
                                )
                                .await
                            {
                                Ok(_) => service.health(instance_id).await.map(Reply::Health),
                                Err(error) => Err(error),
                            }
                        }
                        Ok(_) => Err(AppError::new(
                            "stale_restore_preview",
                            "Deployment or desired configuration changed after the restore preview.",
                        )),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            } else {
                Err(AppError::new(
                    "confirmation_required",
                    "Restoring a deployment requires a reviewed preview and confirmation.",
                ))
            }
        }
        Operation::BackupDeployment { .. } => {
            service.create_backup(instance_id).await.map(Reply::Backup)
        }
        _ => unreachable!("operation checked before acquiring runtime lock"),
    };
    let mut reply = match result {
        Ok(reply) => reply,
        Err(error) => Reply::OperationFailure(error),
    };
    let activated_before_blocking = matches!(&reply, Reply::DeploymentResult(result) if result.status == vam_protocol::DeploymentStatus::Succeeded)
        || (restore.is_some() && matches!(&reply, Reply::Health(_)));
    if blocking_after
        && !matches!(reply, Reply::OperationFailure(_))
        && !matches!(&reply, Reply::DeploymentResult(result) if result.status != vam_protocol::DeploymentStatus::Succeeded)
        && let Err(error) = crate::blocking::apply_cached(
            &context,
            &blocking_configuration,
            Path::new("/opt/vpn-appliance-manager"),
        )
        .await
    {
        if context.blocking_state()?.apply_journal.is_some() {
            let mut failure = AppError::new("dns_blocking_apply_failed", error.to_string());
            failure.remote_state_changed = true;
            failure.rollback_succeeded = Some(false);
            reply = Reply::OperationFailure(failure);
        } else {
            let message = format!("DNS blocking needs attention: {error}");
            match &mut reply {
                Reply::DeploymentResult(result) => result.health.details.push(message),
                Reply::Health(health) => health.details.push(message),
                _ => {}
            }
        }
    }
    if mutating {
        for backup in service
            .list_backups(instance_id)
            .await
            .map_err(|error| AuthorityError::InvalidState(error.message))?
        {
            if !previous_backups.contains(&backup.name) {
                context.remember_backup(&backup.name, prior_deployed_revision)?;
            }
        }
        let requires_recovery = matches!(&reply, Reply::OperationFailure(error) if error.remote_state_changed && error.rollback_succeeded != Some(true));
        let updates_deployment = activated_before_blocking
            || matches!(&reply, Reply::DeploymentResult(result) if result.status == vam_protocol::DeploymentStatus::Succeeded)
            || (restore.is_some() && matches!(&reply, Reply::Health(_)));
        let deployed_revision = if operation_kind == "start" {
            prior_deployed_revision
        } else if restore.is_some() {
            restored_revision
        } else {
            Some(context.manifest.revision)
        };
        match &reply {
            Reply::Backup(backup) => {
                context.remember_backup(&backup.name, prior_deployed_revision)?;
            }
            Reply::DeploymentResult(result) => {
                if let Some(name) = &result.backup_name {
                    context.remember_backup(name, prior_deployed_revision)?;
                }
            }
            _ => {}
        }
        context.record(
            request_id,
            &Receipt {
                operation_hash,
                operation: operation_kind.into(),
                desired_revision: context.manifest.revision,
                reply: reply.clone(),
                updates_deployment,
                deployed_revision,
                requires_recovery,
            },
        )?;
        if updates_deployment {
            context.set_deployed_revision(deployed_revision)?;
        }
        if !requires_recovery {
            context.finish_mutation()?;
        }
    }
    Ok(reply)
}

fn bound_plan_hash(desired: &str, evidence: &str, revision: u64) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{desired}|{evidence}|{revision}"))
    )
}

pub(crate) async fn project_configuration(
    context: &RuntimeContext,
    configuration: &vam_authority::manifest::Configuration,
) -> Result<ApplicationService, AppError> {
    let storage = Storage::in_memory().await.map_err(project_error)?;
    let state = configuration.runtime_state();
    let now = Utc::now();
    let host = DockerHost {
        id: context.manifest.appliance_id,
        display_name: "helper execution context".into(),
        ssh: SshConnectionConfig {
            hostname: "helper-local".into(),
            port: 22,
            username: "root".into(),
            private_key_path: "/unused-helper-local".into(),
            passphrase_ref: None,
        },
        created_at: now,
        updated_at: now,
    };
    storage.save_host(&host).await.map_err(project_error)?;
    storage
        .approve_host_key(
            host.id,
            &HostKeyInfo {
                hostname: "helper-local".into(),
                resolved_address: "helper-local".into(),
                port: 22,
                algorithm: "helper-local".into(),
                sha256_fingerprint: "helper-local".into(),
                public_key_base64: "helper-local".into(),
            },
            false,
        )
        .await
        .map_err(project_error)?;
    storage
        .save_instance(&state.instance)
        .await
        .map_err(project_error)?;
    for user in &state.users {
        storage.save_user(user).await.map_err(project_error)?;
    }
    for device in &state.devices {
        storage.save_device(device).await.map_err(project_error)?;
    }
    for record in &state.dns_records {
        storage
            .save_dns_record(record)
            .await
            .map_err(project_error)?;
    }
    // Reconstruct the last verified deployed snapshot so the existing executor
    // can classify changes and validate automatic rollback against that older
    // deployment rather than against a newer saved desired revision.
    if let Some(revision) = context.deployed().map_err(project_error)? {
        let deployed = context
            .historical_configuration(revision)
            .map_err(project_error)?
            .runtime_state();
        let plan = vam_protocol::DeploymentPlan {
            id: Uuid::new_v4(),
            instance_id: deployed.instance.id,
            operations: Vec::new(),
            warnings: Vec::new(),
            desired_state_hash: format!("verified-deployed-revision-{revision}"),
        };
        storage
            .record_deployment(&plan, &deployed, vam_protocol::DeploymentStatus::Succeeded)
            .await
            .map_err(project_error)?;
        storage
            .finish_deployment(plan.id, vam_protocol::DeploymentStatus::Succeeded, None)
            .await
            .map_err(project_error)?;
    }
    let secrets = Arc::new(MemorySecretStore::default());
    for (id, value) in &context.secrets {
        secrets
            .put(&SecretReference(*id), value.as_bytes())
            .await
            .map_err(project_error)?;
    }
    Ok(
        ApplicationService::with_transport(storage, secrets, Arc::new(HelperLocalExecution))
            .with_runtime_projection(state),
    )
}

fn project_error(error: impl std::fmt::Display) -> AppError {
    AppError {
        code: "helper_execution_index".into(),
        message: "Unable to reconstruct the helper execution index.".into(),
        scope: None,
        remote_state_changed: false,
        rollback_succeeded: None,
        remediation: Some("Inspect the authoritative manifest and helper dependencies.".into()),
        technical_detail: Some(error.to_string()),
    }
}

/// This adapter is private to the helper. It executes only commands generated
/// by the existing Rust deployment engine; no raw-command RPC exists.
struct HelperLocalExecution;

#[async_trait]
impl SshTransport for HelperLocalExecution {
    async fn probe_host_key(
        &self,
        _: &SshConnectionConfig,
        _: &CancellationToken,
    ) -> Result<HostKeyInfo, SshError> {
        Err(SshError::Protocol(
            "SSH probing is unavailable inside helper execution".into(),
        ))
    }

    async fn execute(
        &self,
        _: &SshConnectionConfig,
        _: &str,
        _: Option<&Zeroizing<String>>,
        command: &str,
        cancellation: &CancellationToken,
    ) -> Result<CommandResult, SshError> {
        let mut child = tokio::process::Command::new("/bin/sh");
        child
            .arg("-c")
            .arg(command)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/root")
            .env("USER", "root")
            .env("LC_ALL", "C")
            .kill_on_drop(true);
        let output = tokio::select! {
            () = cancellation.cancelled() => return Err(SshError::Cancelled),
            result = tokio::time::timeout(Duration::from_mins(10), child.output()) => {
                result.map_err(|_| SshError::Timeout)?.map_err(|error| SshError::Protocol(error.to_string()))?
            }
        };
        if output.stdout.len() + output.stderr.len() > 16 * 1024 * 1024 {
            return Err(SshError::Protocol(
                "helper command output exceeded the safety limit".into(),
            ));
        }
        Ok(CommandResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_status: u32::try_from(output.status.code().ok_or(SshError::MissingExitStatus)?)
                .map_err(|_| SshError::MissingExitStatus)?,
        })
    }

    async fn upload(&self, request: UploadRequest<'_>) -> Result<(), SshError> {
        validate_runtime_path(request.remote_path)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(request.mode);
        }
        let mut file = options.open(request.remote_path).map_err(local_io)?;
        file.write_all(request.contents).map_err(local_io)?;
        file.sync_all().map_err(local_io)
    }

    async fn download(&self, request: DownloadRequest<'_>) -> Result<Zeroizing<Vec<u8>>, SshError> {
        use std::io::Read;
        validate_runtime_path(request.remote_path)?;
        let file = std::fs::File::open(request.remote_path).map_err(local_io)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(request.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(local_io)?;
        if bytes.len() > request.max_bytes {
            return Err(SshError::DownloadTooLarge {
                max_bytes: request.max_bytes,
            });
        }
        Ok(bytes)
    }
}

pub(crate) fn validate_runtime_path(path: &str) -> Result<(), SshError> {
    let path = Path::new(path);
    if !path.starts_with("/opt/vpn-appliance-manager")
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SshError::Protocol("unsafe helper runtime file path".into()));
    }
    for parent in path.ancestors() {
        match std::fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SshError::Protocol("symlink in helper runtime path".into()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(local_io(error)),
        }
    }
    Ok(())
}

fn local_io(error: std::io::Error) -> SshError {
    SshError::Protocol(format!("helper filesystem operation failed: {error}"))
}
