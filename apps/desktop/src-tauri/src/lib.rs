use std::sync::Arc;
use tauri::{Manager, State};
use uuid::Uuid;
use vam_application::{ApplicationService, CreateHostInput, HostInspectionView};
use vam_core::DockerHost;
use vam_protocol::{AppError, HostInspection, HostKeyInfo, HostKeyProbe, HostProvisioningPlan};
use vam_secrets::KeychainSecretStore;
use vam_storage::Storage;
mod remote;

#[derive(Clone)]
struct AppState(Arc<ApplicationService>);

#[tauri::command]
fn app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "VPNCTL",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "ready",
        "system_username": system_username()
    })
}

fn system_username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

#[tauri::command]
async fn create_host(
    state: State<'_, AppState>,
    input: CreateHostInput,
) -> Result<DockerHost, AppError> {
    state.0.create_host(input).await
}

#[tauri::command]
async fn update_host(state: State<'_, AppState>, host: DockerHost) -> Result<DockerHost, AppError> {
    state.0.update_host(host).await
}

#[tauri::command]
async fn list_hosts(state: State<'_, AppState>) -> Result<Vec<DockerHost>, AppError> {
    state.0.list_hosts().await
}

#[tauri::command]
async fn delete_host(state: State<'_, AppState>, host_id: Uuid) -> Result<(), AppError> {
    state.0.delete_host(host_id).await
}

#[tauri::command]
async fn probe_host_key(
    state: State<'_, AppState>,
    host_id: Uuid,
) -> Result<HostKeyProbe, AppError> {
    state.0.probe_host_key(host_id).await
}

#[tauri::command]
async fn approve_host_key(
    state: State<'_, AppState>,
    host_id: Uuid,
    probed: HostKeyInfo,
    expected_fingerprint: String,
    replace_changed_key: bool,
) -> Result<(), AppError> {
    state
        .0
        .approve_host_key(host_id, probed, &expected_fingerprint, replace_changed_key)
        .await
}

#[tauri::command]
async fn inspect_host(
    state: State<'_, AppState>,
    host_id: Uuid,
) -> Result<HostInspection, AppError> {
    state.0.inspect_host(host_id).await
}

#[tauri::command]
async fn inspect_host_view(
    state: State<'_, AppState>,
    host_id: Uuid,
) -> Result<HostInspectionView, AppError> {
    state.0.inspect_host_view(host_id).await
}

#[tauri::command]
async fn plan_host_provisioning(
    state: State<'_, AppState>,
    host_id: Uuid,
) -> Result<HostProvisioningPlan, AppError> {
    state.0.plan_host_provisioning(host_id).await
}

#[tauri::command]
async fn apply_host_provisioning(
    state: State<'_, AppState>,
    host_id: Uuid,
    expected_state_hash: String,
) -> Result<HostInspection, AppError> {
    state
        .0
        .apply_host_provisioning(host_id, &expected_state_hash)
        .await
}

#[tauri::command]
async fn apply_host_provisioning_view(
    state: State<'_, AppState>,
    host_id: Uuid,
    expected_state_hash: String,
) -> Result<HostInspectionView, AppError> {
    state
        .0
        .apply_host_provisioning_view(host_id, &expected_state_hash)
        .await
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let storage =
                tauri::async_runtime::block_on(Storage::open(&data_dir.join("state.sqlite")))
                    .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })?;
            app.manage(AppState(Arc::new(ApplicationService::new(
                storage,
                Arc::new(KeychainSecretStore),
            ))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            remote::discover_remote,
            remote::cached_remote_inventory,
            remote::read_remote,
            remote::create_remote_instance,
            remote::save_remote_configuration,
            remote::add_remote_peer,
            remote::remote_peer_availability,
            remote::export_remote_peer,
            remote::revoke_remote_peer,
            remote::remove_remote_configuration,
            remote::preview_remote_deployment,
            remote::apply_remote_deployment,
            remote::inspect_remote_health,
            remote::backup_remote_deployment,
            remote::list_remote_backups,
            remote::preview_remote_restore,
            remote::restore_remote_deployment,
            remote::set_remote_running,
            remote::remote_history,
            remote::remote_runtime_history,
            remote::reconcile_remote_runtime,
            remote::restore_remote_desired,
            remote::legacy_candidates,
            remote::preview_legacy_migration,
            remote::migrate_legacy_instance,
            remote::retire_legacy_instance,
            remote::export_legacy_recovery,
            remote::save_remote_draft,
            remote::load_remote_draft,
            remote::discard_remote_draft,
            app_info,
            create_host,
            update_host,
            list_hosts,
            delete_host,
            probe_host_key,
            approve_host_key,
            inspect_host,
            inspect_host_view,
            plan_host_provisioning,
            apply_host_provisioning,
            apply_host_provisioning_view,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VPNCTL");
}
