use std::{path::PathBuf, sync::Arc};

use tauri::{Manager, State};
use uuid::Uuid;
use vam_application::{
    ActivityFilter, ApplicationService, BackendOptionView, BackupRestorePreview, BackupView,
    ClientView, CreateDeviceInput, CreateDnsHostlistInput, CreateDnsRecordInput, CreateHostInput,
    CreateInstanceInput, DeploymentPreviewView, DeploymentResultView, DeviceView, DnsHostlist,
    HostInspectionView, InstanceDetailView, InstanceHealthView, InstanceSummaryView,
    InstanceUpdatePreview, InstanceView, LogEventView, UpdateDeviceInput, UpdateInstanceInput,
};
use vam_core::{DnsRecord, DockerHost, User};
use vam_protocol::{
    AppError, BackupInfo, DeploymentPlan, DeploymentProgress, DeploymentResult, DeploymentSummary,
    HostInspection, HostKeyInfo, HostKeyProbe, HostProvisioningPlan, InstanceHealth, RenderedFile,
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

#[tauri::command]
async fn create_instance(
    state: State<'_, AppState>,
    input: CreateInstanceInput,
) -> Result<InstanceView, AppError> {
    state.0.create_instance_view(input).await
}

#[tauri::command]
async fn preview_instance_update(
    state: State<'_, AppState>,
    input: UpdateInstanceInput,
) -> Result<InstanceUpdatePreview, AppError> {
    state.0.preview_instance_update(input).await
}

#[tauri::command]
async fn update_instance(
    state: State<'_, AppState>,
    input: UpdateInstanceInput,
) -> Result<InstanceView, AppError> {
    state.0.update_instance_view(input).await
}

#[tauri::command]
async fn list_instances(
    state: State<'_, AppState>,
    host_id: Option<Uuid>,
) -> Result<Vec<InstanceView>, AppError> {
    state.0.list_instance_views(host_id).await
}

#[tauri::command]
async fn list_instance_summaries(
    state: State<'_, AppState>,
    host_id: Option<Uuid>,
) -> Result<Vec<InstanceSummaryView>, AppError> {
    state.0.list_instance_summary_views(host_id).await
}

#[tauri::command]
async fn instance_detail(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceDetailView, AppError> {
    state.0.instance_detail_view(instance_id).await
}

#[tauri::command]
fn backend_options(state: State<'_, AppState>) -> Vec<BackendOptionView> {
    state.0.backend_options()
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
async fn plan_instance_preview(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<DeploymentPreviewView, AppError> {
    state.0.plan_instance_view(instance_id).await
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
async fn apply_instance_view(
    state: State<'_, AppState>,
    instance_id: Uuid,
    expected_state_hash: String,
) -> Result<DeploymentResultView, AppError> {
    state
        .0
        .apply_instance_view(instance_id, &expected_state_hash)
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
async fn start_instance_view(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealthView, AppError> {
    state.0.start_instance_view(instance_id).await
}

#[tauri::command]
async fn stop_instance_view(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealthView, AppError> {
    state.0.stop_instance_view(instance_id).await
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
) -> Result<DeviceView, AppError> {
    state.0.create_device_view(input).await
}

#[tauri::command]
async fn update_device(
    state: State<'_, AppState>,
    input: UpdateDeviceInput,
) -> Result<DeviceView, AppError> {
    state.0.update_device_metadata(input).await
}

#[tauri::command]
async fn list_devices(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<DeviceView>, AppError> {
    state.0.list_device_views(instance_id).await
}

#[tauri::command]
async fn list_clients(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<ClientView>, AppError> {
    state.0.list_client_views(instance_id).await
}

#[tauri::command]
async fn delete_device(state: State<'_, AppState>, device_id: Uuid) -> Result<(), AppError> {
    state.0.delete_device(device_id).await
}

#[tauri::command]
async fn replace_device_identity(
    state: State<'_, AppState>,
    device_id: Uuid,
) -> Result<DeviceView, AppError> {
    state.0.replace_device_identity_view(device_id).await
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
async fn list_dns_hostlists(state: State<'_, AppState>) -> Result<Vec<DnsHostlist>, AppError> {
    state.0.list_dns_hostlists().await
}

#[tauri::command]
async fn create_dns_hostlist(
    state: State<'_, AppState>,
    input: CreateDnsHostlistInput,
) -> Result<DnsHostlist, AppError> {
    state.0.create_dns_hostlist(input).await
}

#[tauri::command]
async fn update_dns_hostlist(
    state: State<'_, AppState>,
    hostlist: DnsHostlist,
) -> Result<DnsHostlist, AppError> {
    state.0.update_dns_hostlist(hostlist).await
}

#[tauri::command]
async fn delete_dns_hostlist(
    state: State<'_, AppState>,
    hostlist_id: Uuid,
) -> Result<(), AppError> {
    state.0.delete_dns_hostlist(hostlist_id).await
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
async fn refresh_remote_credentials_view(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealthView, AppError> {
    state.0.refresh_remote_credentials_view(instance_id).await
}

#[tauri::command]
async fn refresh_remote_dns_store(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealth, AppError> {
    state.0.refresh_remote_dns_store(instance_id).await
}

#[tauri::command]
async fn refresh_remote_dns_store_view(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealthView, AppError> {
    state.0.refresh_remote_dns_store_view(instance_id).await
}

#[tauri::command]
async fn list_backups(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<BackupInfo>, AppError> {
    state.0.list_backups(instance_id).await
}

#[tauri::command]
async fn list_backup_views(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<Vec<BackupView>, AppError> {
    state.0.list_backup_views(instance_id).await
}

#[tauri::command]
async fn preview_backup_restore(
    state: State<'_, AppState>,
    instance_id: Uuid,
    backup_name: String,
) -> Result<BackupRestorePreview, AppError> {
    state
        .0
        .preview_backup_restore(instance_id, &backup_name)
        .await
}

#[tauri::command]
async fn restore_backup_by_name(
    state: State<'_, AppState>,
    instance_id: Uuid,
    backup_name: String,
    expected_state_hash: String,
) -> Result<InstanceHealthView, AppError> {
    state
        .0
        .restore_backup_by_name(instance_id, &backup_name, &expected_state_hash)
        .await
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
async fn health_view(
    state: State<'_, AppState>,
    instance_id: Uuid,
) -> Result<InstanceHealthView, AppError> {
    state.0.health_view(instance_id).await
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
async fn activity_logs(
    state: State<'_, AppState>,
    filter: ActivityFilter,
) -> Result<Vec<LogEventView>, AppError> {
    state.0.activity_logs(filter).await
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
            inspect_host_view,
            plan_host_provisioning,
            apply_host_provisioning,
            apply_host_provisioning_view,
            create_instance,
            preview_instance_update,
            update_instance,
            list_instances,
            list_instance_summaries,
            instance_detail,
            backend_options,
            render_instance,
            plan_instance,
            plan_instance_preview,
            apply_instance,
            apply_instance_view,
            start_instance,
            stop_instance,
            start_instance_view,
            stop_instance_view,
            update_images,
            delete_instance,
            create_user,
            list_users,
            delete_user,
            create_device,
            update_device,
            list_devices,
            list_clients,
            delete_device,
            replace_device_identity,
            create_dns_record,
            update_dns_record,
            list_dns_records,
            delete_dns_record,
            list_dns_hostlists,
            create_dns_hostlist,
            update_dns_hostlist,
            delete_dns_hostlist,
            create_backup,
            refresh_remote_credentials,
            refresh_remote_credentials_view,
            refresh_remote_dns_store,
            refresh_remote_dns_store_view,
            list_backups,
            list_backup_views,
            preview_backup_restore,
            restore_backup_by_name,
            rollback,
            health,
            health_view,
            list_deployments,
            logs,
            activity_logs,
            cancel_deployment,
            export_client_configuration,
            client_qr_svg,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VPN Appliance Manager");
}
