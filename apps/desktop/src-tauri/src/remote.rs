use super::AppState;

#[tauri::command]
pub async fn restore_archived_instance(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    expected_revision: u64,
    request_id: Uuid,
    confirmed: bool,
) -> Result<Manifest, AppError> {
    state
        .0
        .restore_archived_instance(
            host_id,
            instance_id,
            expected_revision,
            request_id,
            confirmed,
        )
        .await
}

#[tauri::command]
pub async fn list_remote_backups(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<Vec<BackupInfo>, AppError> {
    state.0.list_remote_backups(host_id, instance_id).await
}
#[tauri::command]
pub async fn preview_remote_restore(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    expected_revision: u64,
    backup_name: String,
) -> Result<vam_application::RemoteRestorePreview, AppError> {
    state
        .0
        .preview_remote_restore(host_id, instance_id, expected_revision, backup_name)
        .await
}
#[tauri::command]
pub async fn restore_remote_deployment(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    preview: vam_application::RemoteRestorePreview,
    confirmed: bool,
) -> Result<InstanceHealth, AppError> {
    state
        .0
        .restore_remote_deployment(host_id, instance_id, preview, confirmed)
        .await
}
#[tauri::command]
pub async fn set_remote_running(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    expected_revision: u64,
    running: bool,
) -> Result<InstanceHealth, AppError> {
    state
        .0
        .set_remote_running(host_id, instance_id, expected_revision, running)
        .await
}
use std::path::PathBuf;
use tauri::State;
use uuid::Uuid;
use vam_application::{
    CreateDeviceInput, CreateInstanceInput, LegacyCandidate, LegacyMigrationPreview,
    PeerAvailability, RemoteDraft, RemoteInventory, RemoteSaveInput,
};
use vam_authority::manifest::Manifest;
use vam_protocol::{AppError, BackupInfo, DeploymentPlan, DeploymentResult, InstanceHealth};

#[tauri::command]
pub async fn discover_remote(
    state: State<'_, AppState>,
    host_id: Uuid,
) -> Result<RemoteInventory, AppError> {
    state.0.discover_remote(host_id).await
}
#[tauri::command]
pub async fn cached_remote_inventory(
    state: State<'_, AppState>,
    host_id: Uuid,
) -> Result<Option<RemoteInventory>, AppError> {
    state.0.cached_remote_inventory(host_id).await
}
#[tauri::command]
pub async fn read_remote(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<Manifest, AppError> {
    state.0.read_remote(host_id, instance_id).await
}
#[tauri::command]
pub async fn create_remote_instance(
    state: State<'_, AppState>,
    input: CreateInstanceInput,
) -> Result<Manifest, AppError> {
    state.0.create_remote_instance(input).await
}
#[tauri::command]
pub async fn save_remote_configuration(
    state: State<'_, AppState>,
    input: RemoteSaveInput,
) -> Result<Manifest, AppError> {
    state.0.save_remote(input).await
}
#[tauri::command]
pub async fn add_remote_peer(
    state: State<'_, AppState>,
    host_id: Uuid,
    expected_revision: u64,
    input: CreateDeviceInput,
) -> Result<Manifest, AppError> {
    state
        .0
        .add_remote_peer(host_id, expected_revision, input)
        .await
}
#[tauri::command]
pub async fn remote_peer_availability(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<Vec<PeerAvailability>, AppError> {
    state.0.remote_peer_availability(host_id, instance_id).await
}
#[tauri::command]
pub async fn export_remote_peer(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    peer_id: Uuid,
    destination: PathBuf,
) -> Result<(), AppError> {
    state
        .0
        .export_remote_peer(host_id, instance_id, peer_id, &destination)
        .await
}
#[tauri::command]
pub async fn revoke_remote_peer(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    peer_id: Uuid,
    expected_revision: u64,
    confirmed: bool,
) -> Result<Manifest, AppError> {
    state
        .0
        .revoke_remote_peer(host_id, instance_id, peer_id, expected_revision, confirmed)
        .await
}
#[tauri::command]
pub async fn remove_remote_configuration(
    state: State<'_, AppState>,
    input: RemoteSaveInput,
    confirmed: bool,
) -> Result<Manifest, AppError> {
    state.0.remove_remote_configuration(input, confirmed).await
}
#[tauri::command]
pub async fn preview_remote_deployment(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    expected_revision: u64,
) -> Result<DeploymentPlan, AppError> {
    state
        .0
        .preview_remote_deployment(host_id, instance_id, expected_revision)
        .await
}
#[tauri::command]
pub async fn apply_remote_deployment(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    expected_revision: u64,
    expected_state_hash: String,
    request_id: Uuid,
) -> Result<DeploymentResult, AppError> {
    state
        .0
        .apply_remote_deployment(
            host_id,
            instance_id,
            expected_revision,
            expected_state_hash,
            request_id,
        )
        .await
}
#[tauri::command]
pub async fn inspect_remote_health(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.inspect_remote_health(host_id, instance_id).await
}
#[tauri::command]
pub async fn backup_remote_deployment(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    expected_revision: u64,
) -> Result<BackupInfo, AppError> {
    state
        .0
        .backup_remote_deployment(host_id, instance_id, expected_revision)
        .await
}
#[tauri::command]
pub async fn remote_history(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<Vec<Manifest>, AppError> {
    state.0.remote_history(host_id, instance_id).await
}
#[tauri::command]
pub async fn remote_runtime_history(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<Vec<vam_authority::manifest::RuntimeHistoryEntry>, AppError> {
    state.0.remote_runtime_history(host_id, instance_id).await
}
#[tauri::command]
pub async fn reconcile_remote_runtime(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    mutation_id: Uuid,
) -> Result<vam_authority::manifest::RuntimeReconciliation, AppError> {
    state
        .0
        .reconcile_remote_runtime(host_id, instance_id, mutation_id)
        .await
}
#[tauri::command]
pub async fn restore_remote_desired(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    revision: u64,
    expected_revision: u64,
    confirmed: bool,
) -> Result<Manifest, AppError> {
    state
        .0
        .restore_remote_desired(host_id, instance_id, revision, expected_revision, confirmed)
        .await
}
#[tauri::command]
pub async fn legacy_candidates(
    state: State<'_, AppState>,
) -> Result<Vec<LegacyCandidate>, AppError> {
    state.0.legacy_candidates().await
}
#[tauri::command]
pub async fn preview_legacy_migration(
    state: State<'_, AppState>,
    instance_id: Uuid,
    destination_host_id: Uuid,
) -> Result<LegacyMigrationPreview, AppError> {
    state
        .0
        .preview_legacy_migration(instance_id, destination_host_id)
        .await
}
#[tauri::command]
pub async fn migrate_legacy_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
    destination_host_id: Uuid,
    expected_preview_hash: String,
    confirmed: bool,
) -> Result<Manifest, AppError> {
    state
        .0
        .migrate_legacy_instance(
            instance_id,
            destination_host_id,
            &expected_preview_hash,
            confirmed,
        )
        .await
}
#[tauri::command]
pub async fn retire_legacy_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
    confirmed: bool,
) -> Result<(), AppError> {
    state.0.retire_legacy_instance(instance_id, confirmed).await
}
#[tauri::command]
pub async fn export_legacy_recovery(
    state: State<'_, AppState>,
    instance_id: Uuid,
    destination: PathBuf,
) -> Result<(), AppError> {
    state
        .0
        .export_legacy_recovery(instance_id, &destination)
        .await
}
#[tauri::command]
pub async fn save_remote_draft(
    state: State<'_, AppState>,
    draft: RemoteDraft,
) -> Result<(), AppError> {
    state.0.save_remote_draft(draft).await
}
#[tauri::command]
pub async fn load_remote_draft(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<Option<RemoteDraft>, AppError> {
    state.0.load_remote_draft(host_id, instance_id).await
}
#[tauri::command]
pub async fn discard_remote_draft(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
) -> Result<(), AppError> {
    state.0.discard_remote_draft(host_id, instance_id).await
}

#[tauri::command]
pub async fn remote_peer_qr_svg(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    peer_id: Uuid,
) -> Result<String, AppError> {
    state
        .0
        .remote_peer_qr_svg(host_id, instance_id, peer_id)
        .await
}

/// Copy through the native bridge without returning credentials to JavaScript.
#[tauri::command]
pub async fn copy_remote_peer_configuration(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    peer_id: Uuid,
) -> Result<(), AppError> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    let text = state
        .0
        .remote_peer_configuration_text(host_id, instance_id, peer_id)
        .await?;
    app.clipboard().write_text(text.as_str()).map_err(|_| AppError::new(
        "clipboard_unavailable",
        "Could not copy the configuration to the system clipboard. Download the configuration file instead.",
    ))
}

#[tauri::command]
pub async fn drop_remote_peer(
    state: State<'_, AppState>,
    host_id: Uuid,
    request_id: Uuid,
    operation: vam_authority::manifest::Operation,
) -> Result<Manifest, AppError> {
    state
        .0
        .drop_remote_peer(host_id, request_id, operation)
        .await
}

#[tauri::command]
pub async fn remote_blocking(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    request_id: Uuid,
    action: vam_authority::manifest::blocking::Action,
) -> Result<vam_authority::manifest::blocking::View, AppError> {
    state
        .0
        .remote_blocking(host_id, instance_id, request_id, action)
        .await
}

#[tauri::command]
pub async fn reconcile_remote_save(
    state: State<'_, AppState>,
    host_id: Uuid,
    instance_id: Uuid,
    mutation_id: Uuid,
) -> Result<Option<Manifest>, AppError> {
    state
        .0
        .reconcile_remote_save(host_id, instance_id, mutation_id)
        .await
}
