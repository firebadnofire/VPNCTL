use super::{BackendChoice, print_json};
use clap::Subcommand;
use std::path::PathBuf;
use uuid::Uuid;
use vam_application::{
    ApplicationService, CreateDeviceInput, CreateInstanceInput, RemoteSaveInput,
};
use vam_authority::manifest::Configuration;

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    ClearCache,
    Backups {
        instance_id: Uuid,
    },
    RestorePreview {
        instance_id: Uuid,
        backup_name: String,
        #[arg(long)]
        expected_revision: u64,
    },
    RestoreDeployment {
        instance_id: Uuid,
        preview: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
    Start {
        instance_id: Uuid,
        #[arg(long)]
        expected_revision: u64,
    },
    Stop {
        instance_id: Uuid,
        #[arg(long)]
        expected_revision: u64,
    },
    List,
    Cached,
    Inspect {
        instance_id: Uuid,
    },
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long, value_enum, default_value = "wireguard")]
        backend: BackendChoice,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value = "10.64.0.0/24")]
        subnet: String,
        #[arg(long, default_value = "internal")]
        zone: String,
    },
    /// Save a complete public Configuration JSON document, without deployment.
    Save {
        configuration: PathBuf,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    PeerAdd {
        instance_id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        dns_name: Option<String>,
        #[arg(long)]
        expected_revision: u64,
    },
    PeerExport {
        instance_id: Uuid,
        peer_id: Uuid,
        destination: PathBuf,
    },
    PeerRevoke {
        instance_id: Uuid,
        peer_id: Uuid,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        confirm: bool,
    },
    Remove {
        configuration: PathBuf,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Preview {
        instance_id: Uuid,
        #[arg(long)]
        expected_revision: u64,
    },
    Deploy {
        instance_id: Uuid,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        expected_state_hash: String,
        #[arg(long)]
        request_id: Option<Uuid>,
    },
    Health {
        instance_id: Uuid,
    },
    Backup {
        instance_id: Uuid,
        #[arg(long)]
        expected_revision: u64,
    },
    History {
        instance_id: Uuid,
    },
    RuntimeHistory {
        instance_id: Uuid,
    },
    ReconcileRuntime {
        instance_id: Uuid,
        mutation_id: Uuid,
    },
    RestoreDesired {
        instance_id: Uuid,
        revision: u64,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        confirm: bool,
    },
    Reconcile {
        instance_id: Uuid,
        mutation_id: Uuid,
    },
}

pub async fn run(
    service: &ApplicationService,
    host_id: Uuid,
    operation: ServerCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    match operation {
        ServerCommand::ClearCache => {
            service.clear_remote_cache(host_id).await?;
            print_json(&serde_json::json!({ "cleared_local_cache": host_id }))?;
        }
        ServerCommand::Backups { instance_id } => {
            print_json(&service.list_remote_backups(host_id, instance_id).await?)?;
        }
        ServerCommand::RestorePreview {
            instance_id,
            backup_name,
            expected_revision,
        } => print_json(
            &service
                .preview_remote_restore(host_id, instance_id, expected_revision, backup_name)
                .await?,
        )?,
        ServerCommand::RestoreDeployment {
            instance_id,
            preview,
            confirm,
        } => {
            let preview = serde_json::from_slice(&std::fs::read(preview)?)?;
            print_json(
                &service
                    .restore_remote_deployment(host_id, instance_id, preview, confirm)
                    .await?,
            )?;
        }
        ServerCommand::Start {
            instance_id,
            expected_revision,
        } => print_json(
            &service
                .set_remote_running(host_id, instance_id, expected_revision, true)
                .await?,
        )?,
        ServerCommand::Stop {
            instance_id,
            expected_revision,
        } => print_json(
            &service
                .set_remote_running(host_id, instance_id, expected_revision, false)
                .await?,
        )?,
        ServerCommand::List => print_json(&service.discover_remote(host_id).await?)?,
        ServerCommand::Cached => print_json(&service.cached_remote_inventory(host_id).await?)?,
        ServerCommand::Inspect { instance_id } => {
            print_json(&service.read_remote(host_id, instance_id).await?)?;
        }
        ServerCommand::Create {
            name,
            endpoint,
            backend,
            port,
            subnet,
            zone,
        } => print_json(
            &service
                .create_remote_instance(CreateInstanceInput {
                    host_id,
                    display_name: name,
                    endpoint_host: endpoint,
                    backend: backend.into(),
                    backend_settings: None,
                    endpoint_port: port,
                    ipv4_subnet: subnet,
                    dns_zone: zone,
                    routing_mode: None,
                    xray_tls_import: None,
                })
                .await?,
        )?,
        ServerCommand::Save {
            configuration,
            expected_revision,
            request_id,
        } => {
            let bytes = std::fs::read(configuration)?;
            let configuration: Configuration = serde_json::from_slice(&bytes)?;
            print_json(
                &service
                    .save_remote(RemoteSaveInput {
                        host_id,
                        expected_revision,
                        request_id: request_id.unwrap_or_else(Uuid::new_v4),
                        configuration,
                    })
                    .await?,
            )?;
        }
        ServerCommand::PeerAdd {
            instance_id,
            name,
            dns_name,
            expected_revision,
        } => print_json(
            &service
                .add_remote_peer(
                    host_id,
                    expected_revision,
                    CreateDeviceInput {
                        instance_id,
                        user_id: None,
                        display_name: name,
                        preshared_key: true,
                        create_dns_record: dns_name.is_some(),
                        dns_name,
                    },
                )
                .await?,
        )?,
        ServerCommand::PeerExport {
            instance_id,
            peer_id,
            destination,
        } => {
            service
                .export_remote_peer(host_id, instance_id, peer_id, &destination)
                .await?;
            print_json(&serde_json::json!({ "exported": destination }))?;
        }
        ServerCommand::PeerRevoke {
            instance_id,
            peer_id,
            expected_revision,
            confirm,
        } => print_json(
            &service
                .revoke_remote_peer(host_id, instance_id, peer_id, expected_revision, confirm)
                .await?,
        )?,
        ServerCommand::Remove {
            configuration,
            expected_revision,
            confirm,
            request_id,
        } => {
            let configuration: Configuration =
                serde_json::from_slice(&std::fs::read(configuration)?)?;
            print_json(
                &service
                    .remove_remote_configuration(
                        RemoteSaveInput {
                            host_id,
                            expected_revision,
                            request_id: request_id.unwrap_or_else(Uuid::new_v4),
                            configuration,
                        },
                        confirm,
                    )
                    .await?,
            )?;
        }
        ServerCommand::Preview {
            instance_id,
            expected_revision,
        } => print_json(
            &service
                .preview_remote_deployment(host_id, instance_id, expected_revision)
                .await?,
        )?,
        ServerCommand::Deploy {
            instance_id,
            expected_revision,
            expected_state_hash,
            request_id,
        } => print_json(
            &service
                .apply_remote_deployment(
                    host_id,
                    instance_id,
                    expected_revision,
                    expected_state_hash,
                    request_id.unwrap_or_else(Uuid::new_v4),
                )
                .await?,
        )?,
        ServerCommand::Health { instance_id } => {
            print_json(&service.inspect_remote_health(host_id, instance_id).await?)?;
        }
        ServerCommand::Backup {
            instance_id,
            expected_revision,
        } => print_json(
            &service
                .backup_remote_deployment(host_id, instance_id, expected_revision)
                .await?,
        )?,
        ServerCommand::History { instance_id } => {
            print_json(&service.remote_history(host_id, instance_id).await?)?;
        }
        ServerCommand::RuntimeHistory { instance_id } => {
            print_json(&service.remote_runtime_history(host_id, instance_id).await?)?;
        }
        ServerCommand::ReconcileRuntime {
            instance_id,
            mutation_id,
        } => {
            print_json(
                &service
                    .reconcile_remote_runtime(host_id, instance_id, mutation_id)
                    .await?,
            )?;
        }
        ServerCommand::RestoreDesired {
            instance_id,
            revision,
            expected_revision,
            confirm,
        } => print_json(
            &service
                .restore_remote_desired(host_id, instance_id, revision, expected_revision, confirm)
                .await?,
        )?,
        ServerCommand::Reconcile {
            instance_id,
            mutation_id,
        } => print_json(
            &service
                .reconcile_remote_save(host_id, instance_id, mutation_id)
                .await?,
        )?,
    }
    Ok(())
}
