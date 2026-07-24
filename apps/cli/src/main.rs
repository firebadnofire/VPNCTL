use std::{path::PathBuf, sync::Arc};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use uuid::Uuid;
use vam_application::{
    ApplicationService, CreateDeviceInput, CreateDnsRecordInput, CreateHostInput,
    CreateInstanceInput,
};
use vam_core::{DEFAULT_DNS_ZONE, DEFAULT_PORT, DEFAULT_SUBNET, DnsRecordType};
use vam_secrets::KeychainSecretStore;

#[derive(Debug, Parser)]
#[command(name = "vam-dev", about = "VPN Appliance Manager developer harness")]
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
    InstanceAdd(InstanceAdd),
    InstanceList {
        #[arg(long)]
        host_id: Option<Uuid>,
    },
    Render {
        instance_id: Uuid,
    },
    Plan {
        instance_id: Uuid,
    },
    Apply {
        instance_id: Uuid,
        #[arg(long)]
        expected_state_hash: String,
    },
    Health {
        instance_id: Uuid,
    },
    Start {
        instance_id: Uuid,
    },
    Stop {
        instance_id: Uuid,
    },
    Backup {
        instance_id: Uuid,
    },
    Rollback {
        deployment_id: Uuid,
    },
    UserAdd {
        name: String,
    },
    UserList,
    DeviceAdd(DeviceAdd),
    DeviceList {
        instance_id: Uuid,
    },
    DeviceEnable {
        device_id: Uuid,
        #[arg(action = clap::ArgAction::Set)]
        enabled: bool,
    },
    DeviceDelete {
        device_id: Uuid,
    },
    DeviceReplaceIdentity {
        device_id: Uuid,
    },
    DnsAdd(DnsAdd),
    DnsList {
        instance_id: Uuid,
    },
    Export {
        device_id: Uuid,
        destination: PathBuf,
    },
    DeploymentList {
        instance_id: Uuid,
    },
    Logs {
        #[arg(long)]
        instance_id: Option<Uuid>,
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
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    #[arg(long, default_value = DEFAULT_SUBNET)]
    subnet: String,
    #[arg(long, default_value = DEFAULT_DNS_ZONE)]
    zone: String,
}

#[derive(Debug, Args)]
struct DeviceAdd {
    #[arg(long)]
    instance_id: Uuid,
    #[arg(long)]
    name: String,
    #[arg(long)]
    user_id: Option<Uuid>,
    #[arg(long)]
    dns_name: Option<String>,
    #[arg(long, default_value_t = true)]
    preshared_key: bool,
    #[arg(long, default_value_t = true)]
    create_dns_record: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RecordKind {
    A,
    Aaaa,
    Cname,
    Txt,
    Srv,
}

impl From<RecordKind> for DnsRecordType {
    fn from(value: RecordKind) -> Self {
        match value {
            RecordKind::A => Self::A,
            RecordKind::Aaaa => Self::Aaaa,
            RecordKind::Cname => Self::Cname,
            RecordKind::Txt => Self::Txt,
            RecordKind::Srv => Self::Srv,
        }
    }
}

#[derive(Debug, Args)]
struct DnsAdd {
    #[arg(long)]
    instance_id: Uuid,
    #[arg(long)]
    name: String,
    #[arg(long, value_enum)]
    record_type: RecordKind,
    #[arg(long)]
    value: String,
    #[arg(long, default_value_t = 300)]
    ttl: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let storage = vam_storage::Storage::open(&cli.database).await?;
    let service = ApplicationService::new(storage, Arc::new(KeychainSecretStore));
    match cli.command {
        Command::Info => {
            println!("VPN Appliance Manager developer harness");
            println!("database: {}", cli.database.display());
            println!("WireGuard image: {}", vam_deployment::WIREGUARD_IMAGE);
            println!("CoreDNS image: {}", vam_deployment::COREDNS_IMAGE);
        }
        Command::HostAdd(args) => {
            print_json(
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
            )?;
        }
        Command::HostList => print_json(&service.list_hosts().await?)?,
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
            println!("Host key approved.");
        }
        Command::HostInspect { host_id } => print_json(&service.inspect_host(host_id).await?)?,
        Command::InstanceAdd(args) => {
            print_json(
                &service
                    .create_instance(CreateInstanceInput {
                        host_id: args.host_id,
                        display_name: args.name,
                        endpoint_host: args.endpoint,
                        endpoint_port: args.port,
                        ipv4_subnet: args.subnet,
                        dns_zone: args.zone,
                        routing_mode: None,
                    })
                    .await?,
            )?;
        }
        Command::InstanceList { host_id } => {
            print_json(&service.list_instances(host_id).await?)?;
        }
        Command::Render { instance_id } => {
            let mut files = service.render_instance(instance_id).await?;
            for file in &mut files {
                if file.sensitive {
                    file.contents = "[REDACTED]\n".into();
                }
            }
            print_json(&files)?;
        }
        Command::Plan { instance_id } => {
            print_json(&service.plan_instance(instance_id).await?)?;
        }
        Command::Apply {
            instance_id,
            expected_state_hash,
        } => {
            print_json(
                &service
                    .apply_instance(instance_id, &expected_state_hash)
                    .await?,
            )?;
        }
        Command::Health { instance_id } => print_json(&service.health(instance_id).await?)?,
        Command::Start { instance_id } => {
            print_json(&service.start_instance(instance_id).await?)?;
        }
        Command::Stop { instance_id } => {
            print_json(&service.stop_instance(instance_id).await?)?;
        }
        Command::Backup { instance_id } => {
            print_json(&service.create_backup(instance_id).await?)?;
        }
        Command::Rollback { deployment_id } => {
            print_json(&service.rollback(deployment_id).await?)?;
        }
        Command::UserAdd { name } => print_json(&service.create_user(&name).await?)?,
        Command::UserList => print_json(&service.list_users().await?)?,
        Command::DeviceAdd(args) => {
            print_json(
                &service
                    .create_device(CreateDeviceInput {
                        instance_id: args.instance_id,
                        user_id: args.user_id,
                        display_name: args.name,
                        preshared_key: args.preshared_key,
                        create_dns_record: args.create_dns_record,
                        dns_name: args.dns_name,
                    })
                    .await?,
            )?;
        }
        Command::DeviceList { instance_id } => {
            print_json(&service.list_devices(instance_id).await?)?;
        }
        Command::DeviceEnable { device_id, enabled } => {
            let mut selected = service.storage.get_device(device_id).await?;
            selected.enabled = enabled;
            print_json(&service.update_device(selected).await?)?;
        }
        Command::DeviceDelete { device_id } => {
            service.delete_device(device_id).await?;
            println!("Device soft-deleted.");
        }
        Command::DeviceReplaceIdentity { device_id } => {
            print_json(&service.replace_device_identity(device_id).await?)?;
        }
        Command::DnsAdd(args) => {
            print_json(
                &service
                    .create_dns_record(CreateDnsRecordInput {
                        instance_id: args.instance_id,
                        name: args.name,
                        record_type: args.record_type.into(),
                        value: args.value,
                        ttl: args.ttl,
                    })
                    .await?,
            )?;
        }
        Command::DnsList { instance_id } => {
            print_json(&service.list_dns_records(instance_id).await?)?;
        }
        Command::Export {
            device_id,
            destination,
        } => {
            println!(
                "{}",
                service
                    .export_client_configuration(device_id, &destination)
                    .await?
                    .display()
            );
        }
        Command::DeploymentList { instance_id } => {
            print_json(&service.list_deployments(instance_id).await?)?;
        }
        Command::Logs { instance_id } => {
            print_json(&service.logs(instance_id).await?)?;
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
    fn device_enable_accepts_explicit_boolean_values() {
        let id = Uuid::nil();
        let id = id.to_string();
        for value in ["true", "false"] {
            let cli = Cli::try_parse_from(["vam-dev", "device-enable", &id, value])
                .expect("boolean device state should parse");
            assert!(matches!(cli.command, Command::DeviceEnable { .. }));
        }
    }
}
