use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_backend::{
    BackendCapabilities, BackendRuntimeSpec, ContainerCapability, ContainerDevice, ContainerImage,
    ServerIdentityStrategy,
};
use vam_core::{DesiredState, VpnInstance};
use vam_dns::{DnsError, render_blocklist_hosts, render_corefile, render_zone};
use vam_protocol::{AppError, DeploymentOperation, DeploymentPlan, DeploymentResult, RenderedFile};

pub const COREDNS_IMAGE: &str = "docker.io/coredns/coredns:1.13.1";

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error(transparent)]
    Dns(#[from] DnsError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("rendered path is unsafe")]
    UnsafePath,
    #[error(
        "backend declares {container} container listener(s), but desired state declares {host} host listener(s)"
    )]
    ListenerCountMismatch { host: usize, container: usize },
    #[error("host listener {index} uses {host}, but its container listener uses {container}")]
    ListenerProtocolMismatch {
        index: usize,
        host: vam_core::TransportProtocol,
        container: vam_core::TransportProtocol,
    },
    #[error("backend runtime path is unsafe: {0}")]
    UnsafeRuntimePath(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RemoteManifest {
    pub version: u32,
    pub files: BTreeMap<String, String>,
    pub server_public_key: Option<String>,
    pub deployed_at: Option<String>,
    #[serde(default)]
    pub drifted_files: Vec<String>,
}

pub trait DeploymentPlanner: Send + Sync {
    fn render(
        &self,
        state: &DesiredState,
        runtime: &BackendRuntimeSpec,
        capabilities: BackendCapabilities,
    ) -> Result<Vec<RenderedFile>, DeploymentError>;
    fn calculate(
        &self,
        state: &DesiredState,
        runtime: &BackendRuntimeSpec,
        capabilities: BackendCapabilities,
        files: &[RenderedFile],
        remote: Option<&RemoteManifest>,
    ) -> Result<DeploymentPlan, DeploymentError>;
}

#[derive(Debug, Default)]
pub struct DefaultDeploymentPlanner;

impl DeploymentPlanner for DefaultDeploymentPlanner {
    fn render(
        &self,
        state: &DesiredState,
        runtime: &BackendRuntimeSpec,
        capabilities: BackendCapabilities,
    ) -> Result<Vec<RenderedFile>, DeploymentError> {
        render_shared_files(state, runtime, capabilities)
    }

    fn calculate(
        &self,
        state: &DesiredState,
        runtime: &BackendRuntimeSpec,
        capabilities: BackendCapabilities,
        files: &[RenderedFile],
        remote: Option<&RemoteManifest>,
    ) -> Result<DeploymentPlan, DeploymentError> {
        plan(state, runtime, capabilities, files, remote)
    }
}

#[async_trait]
pub trait DeploymentExecutor: Send + Sync {
    async fn execute(
        &self,
        state: &DesiredState,
        files: &[RenderedFile],
        plan: &DeploymentPlan,
        cancellation: &CancellationToken,
    ) -> Result<DeploymentResult, AppError>;
}

pub fn render_shared_files(
    state: &DesiredState,
    runtime: &BackendRuntimeSpec,
    capabilities: BackendCapabilities,
) -> Result<Vec<RenderedFile>, DeploymentError> {
    let instance = &state.instance;
    let compose = render_compose(state, runtime, capabilities)?;
    let instance_json = serde_json::to_string_pretty(instance)?;
    let mut files = vec![
        file("compose.yaml", compose, 0o644, false)?,
        file(".env", render_listener_environment(instance), 0o600, false)?,
        file("instance.json", format!("{instance_json}\n"), 0o600, false)?,
    ];
    if capabilities.managed_dns {
        let corefile = render_corefile(&instance.dns.zone)?;
        let zone = render_zone(
            &instance.dns.zone,
            instance.network.gateway_ipv4,
            instance.dns.soa_serial,
            &state.dns_records,
        )?;
        files.extend([
            file("dns/Corefile", corefile, 0o644, false)?,
            file(
                "dns/hosts/blocklist.hosts",
                render_blocklist_hosts(&state.dns_blocklist_domains),
                0o644,
                false,
            )?,
            file(
                &format!("dns/zones/db.{}", instance.dns.zone),
                zone,
                0o644,
                false,
            )?,
        ]);
    }
    Ok(files)
}

pub fn render_compose(
    state: &DesiredState,
    runtime: &BackendRuntimeSpec,
    capabilities: BackendCapabilities,
) -> Result<String, DeploymentError> {
    let host_listeners = state.instance.listeners();
    if host_listeners.len() != runtime.container_listeners.len() {
        return Err(DeploymentError::ListenerCountMismatch {
            host: host_listeners.len(),
            container: runtime.container_listeners.len(),
        });
    }
    for mount in &runtime.mounts {
        ensure_safe_relative_path(mount.host_path)?;
        if !mount.container_path.starts_with('/') {
            return Err(DeploymentError::UnsafeRuntimePath(
                mount.container_path.into(),
            ));
        }
    }

    let mut output = format!(
        r#"name: "{}"
services:
  gateway:
    image: "{}"
    restart: unless-stopped
"#,
        yaml_escape(&state.instance.compose_project()),
        yaml_escape(runtime_image(runtime.image)),
    );
    if let ContainerImage::Build {
        dockerfile_path, ..
    } = runtime.image
    {
        ensure_safe_relative_path(dockerfile_path)?;
        let (context, dockerfile) = dockerfile_path
            .rsplit_once('/')
            .ok_or_else(|| DeploymentError::UnsafeRuntimePath(dockerfile_path.into()))?;
        writeln!(
            output,
            "    build:\n      context: \"./{}\"\n      dockerfile: \"{}\"",
            yaml_escape(context),
            yaml_escape(dockerfile)
        )
        .expect("writing to a String cannot fail");
    }
    render_runtime_sequence(
        &mut output,
        "cap_add",
        runtime
            .capabilities
            .iter()
            .map(|capability| match capability {
                ContainerCapability::NetAdmin => "NET_ADMIN",
            }),
    );
    render_runtime_sequence(
        &mut output,
        "devices",
        runtime.devices.iter().map(|device| match device {
            ContainerDevice::Tun => "/dev/net/tun:/dev/net/tun",
        }),
    );
    render_runtime_mapping(
        &mut output,
        "environment",
        runtime.environment.iter().copied(),
    );
    render_runtime_inline_sequence(&mut output, "entrypoint", &runtime.entrypoint);
    render_runtime_inline_sequence(&mut output, "command", &runtime.command);
    render_runtime_mapping(&mut output, "sysctls", runtime.sysctls.iter().copied());

    if !host_listeners.is_empty() {
        output.push_str("    ports:\n");
        for (index, (host, container)) in host_listeners
            .iter()
            .zip(&runtime.container_listeners)
            .enumerate()
        {
            if host.protocol != container.protocol {
                return Err(DeploymentError::ListenerProtocolMismatch {
                    index,
                    host: host.protocol,
                    container: container.protocol,
                });
            }
            writeln!(
                output,
                "      - \"${{VAM_LISTENER_{index}_PORT}}:{}/{}\"",
                container.port, container.protocol
            )
            .expect("writing to a String cannot fail");
        }
    }
    if !runtime.mounts.is_empty() {
        output.push_str("    volumes:\n");
        for mount in &runtime.mounts {
            let read_only = if mount.read_only { ":ro" } else { "" };
            writeln!(
                output,
                "      - \"./{}:{}{}\"",
                yaml_escape(mount.host_path),
                yaml_escape(mount.container_path),
                read_only
            )
            .expect("writing to a String cannot fail");
        }
    }
    if capabilities.managed_dns {
        write!(
            output,
            r#"  dns:
    image: "{COREDNS_IMAGE}"
    restart: unless-stopped
    network_mode: service:gateway
    depends_on:
      - gateway
    volumes:
      - "./dns/Corefile:/etc/coredns/Corefile:ro"
      - "./dns/zones:/etc/coredns/zones:ro"
      - "./dns/hosts:/etc/coredns/hosts:ro"
    command:
      - "-conf"
      - "/etc/coredns/Corefile"
"#
        )
        .expect("writing to a String cannot fail");
    }
    Ok(output)
}

fn runtime_image(image: ContainerImage) -> &'static str {
    match image {
        ContainerImage::Pull(reference) => reference,
        ContainerImage::Build { tag, .. } => tag,
    }
}

fn render_listener_environment(instance: &VpnInstance) -> String {
    instance
        .listeners()
        .iter()
        .enumerate()
        .fold(String::new(), |mut output, (index, listener)| {
            writeln!(output, "VAM_LISTENER_{index}_PORT={}", listener.port)
                .expect("writing to a String cannot fail");
            output
        })
}

fn render_runtime_sequence<'a>(
    output: &mut String,
    name: &str,
    values: impl Iterator<Item = &'a str>,
) {
    let values: Vec<_> = values.collect();
    if values.is_empty() {
        return;
    }
    writeln!(output, "    {name}:").expect("writing to a String cannot fail");
    for value in values {
        writeln!(output, "      - \"{}\"", yaml_escape(value))
            .expect("writing to a String cannot fail");
    }
}

fn render_runtime_inline_sequence(output: &mut String, name: &str, values: &[&str]) {
    if values.is_empty() {
        return;
    }
    let values = values
        .iter()
        .map(|value| format!("\"{}\"", yaml_escape(value)))
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(output, "    {name}: [{values}]").expect("writing to a String cannot fail");
}

fn render_runtime_mapping<'a>(
    output: &mut String,
    name: &str,
    values: impl Iterator<Item = (&'a str, &'a str)>,
) {
    let values: Vec<_> = values.collect();
    if values.is_empty() {
        return;
    }
    writeln!(output, "    {name}:").expect("writing to a String cannot fail");
    for (key, value) in values {
        writeln!(
            output,
            "      \"{}\": \"{}\"",
            yaml_escape(key),
            yaml_escape(value)
        )
        .expect("writing to a String cannot fail");
    }
}

fn yaml_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn ensure_safe_relative_path(path: &str) -> Result<(), DeploymentError> {
    if path.starts_with('/')
        || path.is_empty()
        || path
            .split('/')
            .any(|part| part == ".." || part == "." || part.is_empty())
    {
        return Err(DeploymentError::UnsafeRuntimePath(path.into()));
    }
    Ok(())
}

pub fn build_manifest(files: &[RenderedFile]) -> RemoteManifest {
    RemoteManifest {
        version: 1,
        files: files
            .iter()
            .filter(|file| file.path != "state.json")
            .map(|file| (file.path.clone(), hash_rendered_file(file)))
            .collect(),
        server_public_key: None,
        deployed_at: None,
        drifted_files: Vec::new(),
    }
}

pub fn plan(
    state: &DesiredState,
    runtime: &BackendRuntimeSpec,
    capabilities: BackendCapabilities,
    desired_files: &[RenderedFile],
    remote: Option<&RemoteManifest>,
) -> Result<DeploymentPlan, DeploymentError> {
    let plan_id = Uuid::new_v4();
    let desired = build_manifest(desired_files);
    let remote_files = remote.map_or_else(BTreeMap::new, |manifest| manifest.files.clone());
    let mut operations = Vec::new();
    if remote.is_none() {
        operations.push(DeploymentOperation::CreateDirectory {
            path: state.instance.remote_path(),
        });
        if matches!(
            runtime.identity,
            ServerIdentityStrategy::WireGuardLike { .. }
        ) {
            operations.push(DeploymentOperation::GenerateServerKey);
        }
    }
    for file in desired_files {
        if file.path == "state.json" {
            continue;
        }
        let operation = if remote_files.contains_key(&file.path) {
            if remote_files.get(&file.path) == desired.files.get(&file.path) {
                continue;
            }
            DeploymentOperation::ReplaceFile {
                path: file.path.clone(),
                sensitive: file.sensitive,
            }
        } else {
            DeploymentOperation::UploadFile {
                path: file.path.clone(),
                sensitive: file.sensitive,
            }
        };
        operations.push(operation);
    }
    let desired_paths: BTreeSet<_> = desired.files.keys().collect();
    for path in remote_files.keys() {
        if !desired_paths.contains(path) {
            operations.push(DeploymentOperation::RemoveFile { path: path.clone() });
        }
    }
    if !operations.is_empty()
        && let Some(state_file) = desired_files.iter().find(|file| file.path == "state.json")
    {
        operations.push(if remote.is_some() {
            DeploymentOperation::ReplaceFile {
                path: state_file.path.clone(),
                sensitive: state_file.sensitive,
            }
        } else {
            DeploymentOperation::UploadFile {
                path: state_file.path.clone(),
                sensitive: state_file.sensitive,
            }
        });
    }
    if !operations.is_empty() {
        let changed_paths: Vec<_> = operations
            .iter()
            .filter_map(|operation| match operation {
                DeploymentOperation::UploadFile { path, .. }
                | DeploymentOperation::ReplaceFile { path, .. }
                | DeploymentOperation::RemoveFile { path } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        let metadata_only = !changed_paths.is_empty()
            && changed_paths
                .iter()
                .all(|path| *path == "instance.json" || *path == "state.json");
        let dns_only = capabilities.managed_dns
            && !changed_paths.is_empty()
            && changed_paths.iter().all(|path| {
                path.starts_with("dns/") || *path == "instance.json" || *path == "state.json"
            });
        let backend_changed = changed_paths.iter().any(|path| {
            runtime.mounts.iter().any(|mount| {
                *path == mount.host_path
                    || path
                        .strip_prefix(mount.host_path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        });
        let dockerfile_changed = match runtime.image {
            ContainerImage::Build {
                dockerfile_path, ..
            } => changed_paths.contains(&dockerfile_path),
            ContainerImage::Pull(_) => false,
        };
        let structural_change =
            remote.is_none() || changed_paths.contains(&"compose.yaml") || dockerfile_changed;
        operations.extend([
            DeploymentOperation::ValidateConfiguration,
            DeploymentOperation::CreateBackup {
                name: format!("{}-{plan_id}", Utc::now().format("%Y-%m-%dT%H-%M-%SZ")),
            },
        ]);
        if structural_change {
            operations.push(match runtime.image {
                ContainerImage::Pull(_) => DeploymentOperation::ComposePull,
                ContainerImage::Build { .. } => DeploymentOperation::ComposeBuild,
            });
            operations.push(DeploymentOperation::ComposeUp);
        } else if dns_only {
            operations.push(DeploymentOperation::ReloadDns);
        } else if backend_changed {
            operations.push(DeploymentOperation::ComposeRestart {
                service: "gateway".into(),
            });
        } else if !metadata_only {
            operations.push(match runtime.image {
                ContainerImage::Pull(_) => DeploymentOperation::ComposePull,
                ContainerImage::Build { .. } => DeploymentOperation::ComposeBuild,
            });
            operations.push(DeploymentOperation::ComposeUp);
        }
        operations.push(DeploymentOperation::HealthCheck {
            service: "gateway".into(),
        });
        if capabilities.managed_dns {
            operations.push(DeploymentOperation::HealthCheck {
                service: "dns".into(),
            });
        }
    }
    let desired_state_hash = hex_hash(&serde_json::to_vec(state)?);
    Ok(DeploymentPlan {
        id: plan_id,
        instance_id: state.instance.id,
        operations,
        warnings: remote.map_or_else(Vec::new, |manifest| {
            manifest
                .drifted_files
                .iter()
                .map(|path| format!("Remote drift detected in {path}; the file will be replaced."))
                .collect()
        }),
        desired_state_hash,
    })
}

#[must_use]
pub fn shell_quote(argument: &str) -> String {
    if argument.is_empty() {
        return "''".into();
    }
    format!("'{}'", argument.replace('\'', "'\"'\"'"))
}

fn file(
    path: &str,
    contents: String,
    mode: u32,
    sensitive: bool,
) -> Result<RenderedFile, DeploymentError> {
    if path.starts_with('/') || path.split('/').any(|part| part == ".." || part.is_empty()) {
        return Err(DeploymentError::UnsafePath);
    }
    Ok(RenderedFile {
        path: path.into(),
        contents,
        mode,
        sensitive,
    })
}

#[must_use]
pub fn hash_rendered_file(file: &RenderedFile) -> String {
    let mut contents = file
        .contents
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("PrivateKey =")
                || line.trim_start().starts_with("PresharedKey =")
            {
                "secret = [REDACTED]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if file.contents.ends_with('\n') {
        contents.push('\n');
    }
    hex_hash(contents.as_bytes())
}

fn hex_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vam_backend::VpnBackend;
    use vam_backend_amneziawg::AmneziaWgBackend;
    use vam_backend_ikev2::Ikev2Backend;
    use vam_backend_openvpn::OpenVpnBackend;
    use vam_backend_wireguard::{WIREGUARD_IMAGE, WireGuardBackend};
    use vam_backend_xray::XrayBackend;
    use vam_core::{
        BackendSettings, DEFAULT_KEEPALIVE, Device, DnsConfig, EndpointConfig, NetworkConfig,
        RoutingMode, VpnBackendKind, VpnInstance,
    };

    fn state() -> DesiredState {
        state_for(VpnBackendKind::WireGuard)
    }

    fn state_for(kind: VpnBackendKind) -> DesiredState {
        let subnet = "10.64.0.0/24".parse().unwrap();
        let endpoint_host = "vpn.example.test";
        DesiredState {
            instance: VpnInstance {
                id: Uuid::nil(),
                host_id: Uuid::from_u128(1),
                display_name: "Test VPN".into(),
                backend: kind,
                backend_settings: BackendSettings::defaults_for(kind, endpoint_host),
                endpoint: EndpointConfig {
                    host: endpoint_host.into(),
                    port: kind.default_port(),
                },
                network: NetworkConfig {
                    ipv4_subnet: subnet,
                    gateway_ipv4: "10.64.0.1".parse().unwrap(),
                    ipv6_subnet: None,
                    gateway_ipv6: None,
                },
                dns: DnsConfig {
                    zone: "vpn.internal".into(),
                    soa_serial: 2_026_072_301,
                },
                routing_mode: RoutingMode::SplitTunnel,
                persistent_keepalive: DEFAULT_KEEPALIVE,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
            users: Vec::new(),
            devices: Vec::<Device>::new(),
            dns_records: Vec::new(),
            dns_blocklist_domains: vec!["ads.google.com".into()],
        }
    }

    fn runtime_for<B: VpnBackend>(backend: &B, state: &DesiredState) -> BackendRuntimeSpec {
        backend
            .runtime(&state.instance.backend_settings)
            .expect("backend runtime")
    }

    fn compose_for<B: VpnBackend>(backend: &B, state: &DesiredState) -> String {
        render_compose(state, &runtime_for(backend, state), backend.capabilities())
            .expect("compose")
    }

    #[test]
    fn quotes_hostile_shell_arguments() {
        assert_eq!(shell_quote("a'b;$(bad)"), "'a'\"'\"'b;$(bad)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shared_images_are_version_pinned() {
        assert!(!WIREGUARD_IMAGE.ends_with(":latest"));
        assert!(!COREDNS_IMAGE.ends_with(":latest"));
        assert!(WIREGUARD_IMAGE.contains("1.0.20250521-r1-ls109"));
        assert!(COREDNS_IMAGE.ends_with(":1.13.1"));
    }

    #[test]
    fn wireguard_compose_is_deterministic_and_least_privilege() {
        let state = state();
        let first = compose_for(&WireGuardBackend, &state);
        let second = compose_for(&WireGuardBackend, &state);
        assert_eq!(first, second);
        assert!(first.contains(WIREGUARD_IMAGE));
        assert!(first.contains(COREDNS_IMAGE));
        assert!(first.contains("network_mode: service:gateway"));
        assert!(first.contains("\"./dns/hosts:/etc/coredns/hosts:ro\""));
        assert!(first.contains("\"LOG_CONFS\": \"false\""));
        assert!(first.contains("\"${VAM_LISTENER_0_PORT}:51820/udp\""));
        assert!(first.contains("NET_ADMIN"));
        assert!(!first.contains("/dev/net/tun"));
        assert!(!first.contains("PEERS:"));
        assert!(!first.contains("SERVERURL:"));
        assert!(!first.contains("watchtower"));
        assert!(!first.contains("/var/run/docker.sock"));
        assert!(!first.contains(":latest"));
    }

    #[test]
    fn amneziawg_compose_uses_pinned_image_tun_and_explicit_entrypoint() {
        let state = state_for(VpnBackendKind::AmneziaWg);
        let compose = compose_for(&AmneziaWgBackend, &state);
        assert!(compose.contains("amneziavpn/amneziawg-go:2.0.0@sha256:"));
        assert!(compose.contains("\"${VAM_LISTENER_0_PORT}:55424/udp\""));
        assert!(compose.contains("\"/dev/net/tun:/dev/net/tun\""));
        assert!(compose.contains("entrypoint: [\"/etc/amneziawg/start-awg.sh\"]"));
        assert!(compose.contains("NET_ADMIN"));
        assert!(compose.contains("  dns:"));
    }

    #[test]
    fn openvpn_compose_builds_the_pinned_local_image() {
        let state = state_for(VpnBackendKind::OpenVpn);
        let compose = compose_for(&OpenVpnBackend, &state);
        assert!(compose.contains("vpn-appliance-manager/openvpn:alpine3.23.5"));
        assert!(compose.contains("context: \"./vpn\""));
        assert!(compose.contains("dockerfile: \"Dockerfile\""));
        assert!(compose.contains("\"${VAM_LISTENER_0_PORT}:1194/udp\""));
        assert!(compose.contains("\"/dev/net/tun:/dev/net/tun\""));
        assert!(compose.contains("NET_ADMIN"));
    }

    #[test]
    fn ikev2_compose_publishes_both_fixed_udp_listeners_without_tun_device() {
        let state = state_for(VpnBackendKind::Ikev2);
        let compose = compose_for(&Ikev2Backend, &state);
        assert!(compose.contains("context: \"./ikev2\""));
        assert!(compose.contains("\"${VAM_LISTENER_0_PORT}:500/udp\""));
        assert!(compose.contains("\"${VAM_LISTENER_1_PORT}:4500/udp\""));
        assert!(compose.contains("NET_ADMIN"));
        assert!(!compose.contains("/dev/net/tun"));
    }

    #[test]
    fn xray_compose_has_no_dns_network_privilege_or_docker_socket() {
        let state = state_for(VpnBackendKind::Xray);
        let compose = compose_for(&XrayBackend, &state);
        assert!(compose.contains("context: \"./xray\""));
        assert!(compose.contains("\"${VAM_LISTENER_0_PORT}:8443/tcp\""));
        assert!(!compose.contains("  dns:"));
        assert!(!compose.contains("NET_ADMIN"));
        assert!(!compose.contains("/dev/net/tun"));
        assert!(!compose.contains("/var/run/docker.sock"));
        assert!(!compose.contains("watchtower"));
    }

    #[test]
    fn shared_files_include_coredns_hosts_blocklist() {
        let state = state();
        let backend = WireGuardBackend;
        let files = render_shared_files(
            &state,
            &runtime_for(&backend, &state),
            backend.capabilities(),
        )
        .unwrap();
        let hosts = files
            .iter()
            .find(|file| file.path == "dns/hosts/blocklist.hosts")
            .expect("blocklist hosts file");
        assert!(hosts.contents.contains("0.0.0.0 ads.google.com\n"));
        assert!(hosts.contents.contains(":: ads.google.com\n"));

        let corefile = files
            .iter()
            .find(|file| file.path == "dns/Corefile")
            .expect("Corefile");
        assert!(
            corefile
                .contents
                .contains("hosts /etc/coredns/hosts/blocklist.hosts")
        );
    }

    #[test]
    fn unmanaged_dns_backend_omits_all_dns_files() {
        let state = state_for(VpnBackendKind::Xray);
        let backend = XrayBackend;
        let files = render_shared_files(
            &state,
            &runtime_for(&backend, &state),
            backend.capabilities(),
        )
        .unwrap();
        assert!(files.iter().all(|file| !file.path.starts_with("dns/")));
        assert_eq!(
            files
                .iter()
                .find(|file| file.path == ".env")
                .expect("listener environment")
                .contents,
            "VAM_LISTENER_0_PORT=443\n"
        );
    }

    #[test]
    fn listener_mismatch_is_rejected() {
        let state = state_for(VpnBackendKind::Ikev2);
        let backend = Ikev2Backend;
        let mut runtime = runtime_for(&backend, &state);
        runtime.container_listeners.pop();
        assert!(matches!(
            render_compose(&state, &runtime, backend.capabilities()),
            Err(DeploymentError::ListenerCountMismatch {
                host: 2,
                container: 1
            })
        ));
    }

    #[test]
    fn dns_only_diff_uses_reload_and_reports_drift() {
        let state = state();
        let files = vec![
            RenderedFile {
                path: "instance.json".into(),
                contents: "new metadata\n".into(),
                mode: 0o600,
                sensitive: false,
            },
            RenderedFile {
                path: "dns/zones/db.vpn.internal".into(),
                contents: "new zone\n".into(),
                mode: 0o644,
                sensitive: false,
            },
        ];
        let mut remote = build_manifest(&files);
        remote
            .files
            .insert("dns/zones/db.vpn.internal".into(), "drift".into());
        remote
            .drifted_files
            .push("dns/zones/db.vpn.internal".into());
        let backend = WireGuardBackend;
        let plan = plan(
            &state,
            &runtime_for(&backend, &state),
            backend.capabilities(),
            &files,
            Some(&remote),
        )
        .unwrap();
        assert!(plan.operations.iter().any(|operation| {
            matches!(
                operation,
                DeploymentOperation::ReplaceFile { path, .. }
                    if path == "dns/zones/db.vpn.internal"
            )
        }));
        assert!(
            plan.operations
                .iter()
                .any(|operation| matches!(operation, DeploymentOperation::ReloadDns))
        );
        assert!(plan.operations.iter().any(|operation| {
            matches!(
                operation,
                DeploymentOperation::CreateBackup { name }
                    if name.ends_with(&plan.id.to_string())
            )
        }));
        assert_eq!(plan.warnings.len(), 1);
    }

    #[test]
    fn new_xray_plan_builds_without_server_key_or_dns_health() {
        let state = state_for(VpnBackendKind::Xray);
        let backend = XrayBackend;
        let runtime = runtime_for(&backend, &state);
        let files =
            render_shared_files(&state, &runtime, backend.capabilities()).expect("shared files");
        let plan = plan(&state, &runtime, backend.capabilities(), &files, None).expect("plan");
        assert!(
            plan.operations
                .iter()
                .any(|operation| matches!(operation, DeploymentOperation::ComposeBuild))
        );
        assert!(
            !plan
                .operations
                .iter()
                .any(|operation| { matches!(operation, DeploymentOperation::GenerateServerKey) })
        );
        assert!(!plan.operations.iter().any(|operation| {
            matches!(
                operation,
                DeploymentOperation::HealthCheck { service } if service == "dns"
            )
        }));
    }

    #[test]
    fn sensitive_hash_never_contains_or_depends_on_secret_values() {
        let left = RenderedFile {
            path: "vpn/wg0.conf.template".into(),
            contents: "PrivateKey = first\nPresharedKey = alpha\n".into(),
            mode: 0o600,
            sensitive: true,
        };
        let right = RenderedFile {
            contents: "PrivateKey = second\nPresharedKey = beta\n".into(),
            ..left.clone()
        };
        assert_eq!(hash_rendered_file(&left), hash_rendered_file(&right));
        assert!(!hash_rendered_file(&left).contains("first"));
    }
}
