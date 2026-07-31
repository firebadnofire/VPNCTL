use std::{path::PathBuf, sync::Arc};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use uuid::Uuid;
use vam_application::{
    ApplicationService, CreateDeviceInput, CreateDnsRecordInput, CreateHostInput,
    CreateInstanceInput,
};
use vam_core::{DEFAULT_DNS_ZONE, DEFAULT_SUBNET, DnsRecordType, VpnBackendKind};
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
    HostProvisionPlan {
        host_id: Uuid,
    },
    HostProvisionApply {
        host_id: Uuid,
        #[arg(long)]
        expected_state_hash: String,
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
    Xray,
}

impl From<BackendChoice> for VpnBackendKind {
    fn from(value: BackendChoice) -> Self {
        match value {
            BackendChoice::Wireguard => Self::WireGuard,
            BackendChoice::AmneziaWg => Self::AmneziaWg,
            BackendChoice::Openvpn => Self::OpenVpn,
            BackendChoice::Ikev2 => Self::Ikev2,
            BackendChoice::Xray => Self::Xray,
        }
    }
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
            println!(
                "WireGuard image: {}",
                vam_backend_wireguard::WIREGUARD_IMAGE
            );
            println!(
                "AmneziaWG image: {}",
                vam_backend_amneziawg::AMNEZIAWG_IMAGE
            );
            println!(
                "OpenVPN image: {}",
                vam_backend_openvpn::OPENVPN_LOCAL_IMAGE
            );
            println!("IKEv2 image: {}", vam_backend_ikev2::IKEV2_LOCAL_IMAGE);
            println!("Xray image: {}", vam_backend_xray::XRAY_LOCAL_IMAGE);
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
        Command::HostProvisionPlan { host_id } => {
            print_json(&service.plan_host_provisioning(host_id).await?)?;
        }
        Command::HostProvisionApply {
            host_id,
            expected_state_hash,
        } => {
            print_json(
                &service
                    .apply_host_provisioning(host_id, &expected_state_hash)
                    .await?,
            )?;
        }
        Command::InstanceAdd(args) => {
            print_json(
                &service
                    .create_instance_view(CreateInstanceInput {
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
            )?;
        }
        Command::InstanceList { host_id } => {
            print_json(&service.list_instance_views(host_id).await?)?;
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
                    .create_device_view(CreateDeviceInput {
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
            print_json(&service.list_device_views(instance_id).await?)?;
        }
        Command::DeviceEnable { device_id, enabled } => {
            print_json(&service.set_device_enabled(device_id, enabled).await?)?;
        }
        Command::DeviceDelete { device_id } => {
            service.delete_device(device_id).await?;
            println!("Device soft-deleted.");
        }
        Command::DeviceReplaceIdentity { device_id } => {
            print_json(&service.replace_device_identity_view(device_id).await?)?;
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

    #[test]
    fn instance_add_accepts_every_backend_and_defers_the_default_port() {
        let host_id = Uuid::nil().to_string();
        let cases = [
            ("wireguard", VpnBackendKind::WireGuard),
            ("amnezia-wg", VpnBackendKind::AmneziaWg),
            ("openvpn", VpnBackendKind::OpenVpn),
            ("ikev2", VpnBackendKind::Ikev2),
            ("xray", VpnBackendKind::Xray),
        ];
        for (argument, expected) in cases {
            let cli = Cli::try_parse_from([
                "vam-dev",
                "instance-add",
                "--host-id",
                &host_id,
                "--name",
                "test",
                "--endpoint",
                "vpn.example.test",
                "--backend",
                argument,
            ])
            .expect("backend should parse");
            let Command::InstanceAdd(args) = cli.command else {
                panic!("expected instance-add");
            };
            assert_eq!(VpnBackendKind::from(args.backend), expected);
            assert_eq!(args.port, None);
        }
    }

    #[test]
    fn instance_add_remains_wireguard_compatible_by_default() {
        let host_id = Uuid::nil().to_string();
        let cli = Cli::try_parse_from([
            "vam-dev",
            "instance-add",
            "--host-id",
            &host_id,
            "--name",
            "test",
            "--endpoint",
            "vpn.example.test",
        ])
        .expect("legacy instance-add should parse");
        let Command::InstanceAdd(args) = cli.command else {
            panic!("expected instance-add");
        };
        assert_eq!(
            VpnBackendKind::from(args.backend),
            VpnBackendKind::WireGuard
        );
        assert_eq!(args.port, None);
    }

    #[test]
    fn host_provision_apply_requires_an_expected_state_hash() {
        let host_id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["vam-dev", "host-provision-apply", &host_id]).is_err());
        let cli = Cli::try_parse_from([
            "vam-dev",
            "host-provision-apply",
            &host_id,
            "--expected-state-hash",
            "reviewed-hash",
        ])
        .expect("hash-bound host provisioning should parse");
        let Command::HostProvisionApply {
            expected_state_hash,
            ..
        } = cli.command
        else {
            panic!("expected host-provision-apply");
        };
        assert_eq!(expected_state_hash, "reviewed-hash");
    }
}
