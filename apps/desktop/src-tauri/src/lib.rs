use std::{path::PathBuf, sync::Arc};

use tauri::{Manager, State};
use uuid::Uuid;
use vam_application::{
    ApplicationService, CreateDeviceInput, CreateDnsRecordInput, CreateHostInput,
    CreateInstanceInput,
};
use vam_core::{Device, DnsRecord, DockerHost, User, VpnInstance};
use vam_protocol::{
    AppError, BackupInfo, DeploymentPlan, DeploymentProgress, DeploymentResult, DeploymentSummary,
    HostInspection, HostKeyInfo, HostKeyProbe, InstanceHealth, RenderedFile,
};
use vam_secrets::KeychainSecretStore;
use vam_storage::Storage;

#[derive(Clone)]
struct AppState(Arc<ApplicationService>);

#[tauri::command]
fn app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "VPN Appliance Manager",
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
async fn create_instance(
    state: State<'_, AppState>,
    input: CreateInstanceInput,
) -> Result<VpnInstance, AppError> {
    state.0.create_instance(input).await
}

#[tauri::command]
async fn update_instance(
    state: State<'_, AppState>,
    instance: VpnInstance,
) -> Result<VpnInstance, AppError> {
    state.0.update_instance(instance).await
}

#[tauri::command]
async fn list_instances(
    state: State<'_, AppState>,
    host_id: Option<Uuid>,
) -> Result<Vec<VpnInstance>, AppError> {
    state.0.list_instances(host_id).await
}

#[tauri::command]
async fn render_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<RenderedFile>, AppError> {
    let mut files = state.0.render_instance(instance_id).await?;
    for file in &mut files {
        if file.sensitive {
            file.contents.clear();
        }
    }
    Ok(files)
}

#[tauri::command]
async fn plan_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<DeploymentPlan, AppError> {
    state.0.plan_instance(instance_id).await
}

#[tauri::command]
async fn apply_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
    expected_state_hash: String,
) -> Result<DeploymentResult, AppError> {
    state
        .0
        .apply_instance(instance_id, &expected_state_hash)
        .await
}

#[tauri::command]
async fn start_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.start_instance(instance_id).await
}

#[tauri::command]
async fn stop_instance(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.stop_instance(instance_id).await
}

#[tauri::command]
async fn update_images(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.update_images(instance_id).await
}

#[tauri::command]
async fn delete_instance(state: State<'_, AppState>, instance_id: Uuid) -> Result<(), AppError> {
    state.0.delete_instance(instance_id).await
}

#[tauri::command]
async fn create_user(state: State<'_, AppState>, display_name: String) -> Result<User, AppError> {
    state.0.create_user(&display_name).await
}

#[tauri::command]
async fn list_users(state: State<'_, AppState>) -> Result<Vec<User>, AppError> {
    state.0.list_users().await
}

#[tauri::command]
async fn delete_user(state: State<'_, AppState>, user_id: Uuid) -> Result<(), AppError> {
    state.0.delete_user(user_id).await
}

#[tauri::command]
async fn create_device(
    state: State<'_, AppState>,
    input: CreateDeviceInput,
) -> Result<Device, AppError> {
    state.0.create_device(input).await
}

#[tauri::command]
async fn update_device(state: State<'_, AppState>, device: Device) -> Result<Device, AppError> {
    state.0.update_device(device).await
}

#[tauri::command]
async fn list_devices(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<Device>, AppError> {
    state.0.list_devices(instance_id).await
}

#[tauri::command]
async fn delete_device(state: State<'_, AppState>, device_id: Uuid) -> Result<(), AppError> {
    state.0.delete_device(device_id).await
}

#[tauri::command]
async fn replace_device_identity(
    state: State<'_, AppState>,
    device_id: Uuid,
) -> Result<Device, AppError> {
    state.0.replace_device_identity(device_id).await
}

#[tauri::command]
async fn create_dns_record(
    state: State<'_, AppState>,
    input: CreateDnsRecordInput,
) -> Result<DnsRecord, AppError> {
    state.0.create_dns_record(input).await
}

#[tauri::command]
async fn update_dns_record(
    state: State<'_, AppState>,
    record: DnsRecord,
) -> Result<DnsRecord, AppError> {
    state.0.update_dns_record(record).await
}

#[tauri::command]
async fn list_dns_records(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<DnsRecord>, AppError> {
    state.0.list_dns_records(instance_id).await
}

#[tauri::command]
async fn delete_dns_record(
    state: State<'_, AppState>,
    record_id: Uuid,
    instance_id: Uuid,
) -> Result<(), AppError> {
    state.0.delete_dns_record(record_id, instance_id).await
}

#[tauri::command]
async fn create_backup(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<BackupInfo, AppError> {
    state.0.create_backup(instance_id).await
}

#[tauri::command]
async fn refresh_remote_credentials(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.refresh_remote_credentials(instance_id).await
}

#[tauri::command]
async fn refresh_remote_dns_store(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.refresh_remote_dns_store(instance_id).await
}

#[tauri::command]
async fn list_backups(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<BackupInfo>, AppError> {
    state.0.list_backups(instance_id).await
}

#[tauri::command]
async fn rollback(
    state: State<'_, AppState>,
    deployment_id: Uuid,
) -> Result<DeploymentResult, AppError> {
    state.0.rollback(deployment_id).await
}

#[tauri::command]
async fn health(state: State<'_, AppState>, instance_id: Uuid) -> Result<InstanceHealth, AppError> {
    state.0.health(instance_id).await
}

#[tauri::command]
async fn list_deployments(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<DeploymentSummary>, AppError> {
    state.0.list_deployments(instance_id).await
}

#[tauri::command]
async fn logs(
    state: State<'_, AppState>,
    instance_id: Option<Uuid>,
) -> Result<Vec<DeploymentProgress>, AppError> {
    state.0.logs(instance_id).await
}

#[tauri::command]
async fn cancel_deployment(
    state: State<'_, AppState>,
    deployment_id: Uuid,
) -> Result<bool, AppError> {
    Ok(state.0.cancel_deployment(deployment_id).await)
}

#[tauri::command]
async fn export_client_configuration(
    state: State<'_, AppState>,
    device_id: Uuid,
    destination: PathBuf,
) -> Result<PathBuf, AppError> {
    state
        .0
        .export_client_configuration(device_id, &destination)
        .await
}

#[tauri::command]
async fn client_qr_svg(state: State<'_, AppState>, device_id: Uuid) -> Result<String, AppError> {
    state.0.client_qr_svg(device_id).await
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
            app_info,
            create_host,
            update_host,
            list_hosts,
            delete_host,
            probe_host_key,
            approve_host_key,
            inspect_host,
            create_instance,
            update_instance,
            list_instances,
            render_instance,
            plan_instance,
            apply_instance,
            start_instance,
            stop_instance,
            update_images,
            delete_instance,
            create_user,
            list_users,
            delete_user,
            create_device,
            update_device,
            list_devices,
            delete_device,
            replace_device_identity,
            create_dns_record,
            update_dns_record,
            list_dns_records,
            delete_dns_record,
            create_backup,
            refresh_remote_credentials,
            refresh_remote_dns_store,
            list_backups,
            rollback,
            health,
            list_deployments,
            logs,
            cancel_deployment,
            export_client_configuration,
            client_qr_svg,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VPN Appliance Manager");
}
