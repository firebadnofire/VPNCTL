use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::{path::PathBuf, process::ExitCode, sync::Arc};
use uuid::Uuid;
use vam_application::{ApplicationService, CreateHostInput, CreateInstanceInput};
use vam_core::{DEFAULT_DNS_ZONE, DEFAULT_SUBNET, VpnBackendKind};
use vam_secrets::KeychainSecretStore;

mod server;

#[derive(Debug, Parser)]
#[command(
    name = "vam-dev",
    about = "Manage remote VPN appliances over verified SSH"
)]
struct Cli {
    #[arg(long, default_value = "vam-dev.sqlite")]
    database: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Info,
    HostAdd(HostAdd),
    HostList,
    HostRemove {
        host_id: Uuid,
    },
    HostProbe {
        host_id: Uuid,
    },
    HostApprove {
        host_id: Uuid,
        #[arg(long)]
        expected_fingerprint: String,
        #[arg(long)]
        replace_changed_key: bool,
    },
    HostInspect {
        host_id: Uuid,
    },
    HostProvisionPlan {
        host_id: Uuid,
    },
    HostProvisionApply {
        host_id: Uuid,
        #[arg(long)]
        expected_state_hash: String,
    },
    Server {
        host_id: Uuid,
        #[command(subcommand)]
        operation: server::ServerCommand,
    },
    /// Compatibility alias; creates desired state remotely, never locally.
    InstanceAdd(InstanceAdd),
    /// Compatibility alias; reads authoritative state from the specified host.
    InstanceList {
        #[arg(long)]
        host_id: Uuid,
    },
    LegacyList,
    LegacyPreview {
        instance_id: Uuid,
        #[arg(long)]
        host_id: Uuid,
    },
    LegacyMigrate {
        instance_id: Uuid,
        #[arg(long)]
        host_id: Uuid,
        #[arg(long)]
        expected_preview_hash: String,
        #[arg(long)]
        confirm: bool,
    },
    LegacyExport {
        instance_id: Uuid,
        destination: PathBuf,
    },
    LegacyRetire {
        instance_id: Uuid,
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Args)]
struct HostAdd {
    #[arg(long)]
    name: String,
    #[arg(long)]
    hostname: String,
    #[arg(long, default_value_t = 22)]
    port: u16,
    #[arg(long)]
    username: String,
    #[arg(long)]
    key: PathBuf,
}

#[derive(Debug, Args)]
struct InstanceAdd {
    #[arg(long)]
    host_id: Uuid,
    #[arg(long)]
    name: String,
    #[arg(long)]
    endpoint: String,
    #[arg(long, value_enum, default_value = "wireguard")]
    backend: BackendChoice,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long, default_value = DEFAULT_SUBNET)]
    subnet: String,
    #[arg(long, default_value = DEFAULT_DNS_ZONE)]
    zone: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendChoice {
    Wireguard,
    AmneziaWg,
    Openvpn,
    Ikev2,
}

impl From<BackendChoice> for VpnBackendKind {
    fn from(value: BackendChoice) -> Self {
        match value {
            BackendChoice::Wireguard => Self::WireGuard,
            BackendChoice::AmneziaWg => Self::AmneziaWg,
            BackendChoice::Openvpn => Self::OpenVpn,
            BackendChoice::Ikev2 => Self::Ikev2,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(application_error) = error.downcast_ref::<vam_protocol::AppError>() {
                eprintln!("{}", serde_json::json!({ "error": application_error }));
            } else {
                eprintln!(
                    "{}",
                    serde_json::json!({ "error": { "code": "cli_operation_failed", "message": error.to_string() } })
                );
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let storage = vam_storage::Storage::open(&cli.database).await?;
    let service = ApplicationService::new(storage, Arc::new(KeychainSecretStore));
    match cli.command {
        Command::Info => print_json(
            &serde_json::json!({ "name": "VPNCTL", "version": env!("CARGO_PKG_VERSION"),
            "authority_protocol": vam_authority::manifest::PROTOCOL_VERSION, "manifest_schema": vam_authority::manifest::SCHEMA_VERSION,
            "backends": ["wireguard", "amnezia_wg", "openvpn", "ikev2"] }),
        )?,
        Command::HostAdd(args) => print_json(
            &service
                .create_host(CreateHostInput {
                    display_name: args.name,
                    hostname: args.hostname,
                    port: args.port,
                    username: args.username,
                    private_key_path: args.key,
                    passphrase: None,
                })
                .await?,
        )?,
        Command::HostList => print_json(&service.list_hosts().await?)?,
        Command::HostRemove { host_id } => {
            service.delete_host(host_id).await?;
            print_json(&serde_json::json!({ "removed_local_profile": host_id }))?;
        }
        Command::HostProbe { host_id } => print_json(&service.probe_host_key(host_id).await?)?,
        Command::HostApprove {
            host_id,
            expected_fingerprint,
            replace_changed_key,
        } => {
            let probe = service.probe_host_key(host_id).await?;
            service
                .approve_host_key(
                    host_id,
                    probe.key,
                    &expected_fingerprint,
                    replace_changed_key,
                )
                .await?;
            print_json(&serde_json::json!({ "approved_host": host_id }))?;
        }
        Command::HostInspect { host_id } => print_json(&service.inspect_host_view(host_id).await?)?,
        Command::HostProvisionPlan { host_id } => {
            print_json(&service.plan_host_provisioning(host_id).await?)?;
        }
        Command::HostProvisionApply {
            host_id,
            expected_state_hash,
        } => print_json(
            &service
                .apply_host_provisioning_view(host_id, &expected_state_hash)
                .await?,
        )?,
        Command::Server { host_id, operation } => server::run(&service, host_id, operation).await?,
        Command::InstanceAdd(args) => print_json(
            &service
                .create_remote_instance(CreateInstanceInput {
                    host_id: args.host_id,
                    display_name: args.name,
                    endpoint_host: args.endpoint,
                    backend: args.backend.into(),
                    backend_settings: None,
                    endpoint_port: args.port,
                    ipv4_subnet: args.subnet,
                    dns_zone: args.zone,
                    routing_mode: None,
                    xray_tls_import: None,
                })
                .await?,
        )?,
        Command::InstanceList { host_id } => print_json(&service.discover_remote(host_id).await?)?,
        Command::LegacyList => print_json(&service.legacy_candidates().await?)?,
        Command::LegacyPreview {
            instance_id,
            host_id,
        } => print_json(
            &service
                .preview_legacy_migration(instance_id, host_id)
                .await?,
        )?,
        Command::LegacyMigrate {
            instance_id,
            host_id,
            expected_preview_hash,
            confirm,
        } => print_json(
            &service
                .migrate_legacy_instance(instance_id, host_id, &expected_preview_hash, confirm)
                .await?,
        )?,
        Command::LegacyExport {
            instance_id,
            destination,
        } => {
            service
                .export_legacy_recovery(instance_id, &destination)
                .await?;
            print_json(&serde_json::json!({ "exported": destination }))?;
        }
        Command::LegacyRetire {
            instance_id,
            confirm,
        } => {
            service.retire_legacy_instance(instance_id, confirm).await?;
            print_json(&serde_json::json!({ "retired_local_record": instance_id }))?;
        }
    }
    Ok(())
}

fn print_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_instance_operations_require_server_scope_and_revisions() {
        let id = Uuid::new_v4().to_string();
        assert!(Cli::try_parse_from(["vam-dev", "instance-list"]).is_err());
        assert!(Cli::try_parse_from(["vam-dev", "server", &id, "deploy", &id]).is_err());
        assert!(Cli::try_parse_from(["vam-dev", "server", &id, "save", "config.json"]).is_err());
        assert!(Cli::try_parse_from(["vam-dev", "host-provision-apply", &id]).is_err());
    }
    #[test]
    fn creation_alias_is_wireguard_by_default_and_rejects_xray() {
        let id = Uuid::new_v4().to_string();
        let args = [
            "vam-dev",
            "instance-add",
            "--host-id",
            &id,
            "--name",
            "primary",
            "--endpoint",
            "vpn.example.com",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let Command::InstanceAdd(instance) = cli.command else {
            panic!("expected creation alias");
        };
        assert_eq!(
            VpnBackendKind::from(instance.backend),
            VpnBackendKind::WireGuard
        );
        assert!(Cli::try_parse_from(args.into_iter().chain(["--backend", "xray"])).is_err());
    }
}
