use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use vam_core::DesiredState;
use vam_dns::{DnsError, render_corefile, render_zone};
use vam_protocol::{AppError, DeploymentOperation, DeploymentPlan, DeploymentResult, RenderedFile};

pub const WIREGUARD_IMAGE: &str = "ghcr.io/linuxserver/wireguard:latest";
pub const COREDNS_IMAGE: &str = "docker.io/coredns/coredns:latest";
pub const WATCHTOWER_IMAGE: &str = "docker.io/containrrr/watchtower:latest";

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error(transparent)]
    Dns(#[from] DnsError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("rendered path is unsafe")]
    UnsafePath,
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
    fn render(&self, state: &DesiredState) -> Result<Vec<RenderedFile>, DeploymentError>;
    fn calculate(
        &self,
        state: &DesiredState,
        files: &[RenderedFile],
        remote: Option<&RemoteManifest>,
    ) -> Result<DeploymentPlan, DeploymentError>;
}

#[derive(Debug, Default)]
pub struct DefaultDeploymentPlanner;

impl DeploymentPlanner for DefaultDeploymentPlanner {
    fn render(&self, state: &DesiredState) -> Result<Vec<RenderedFile>, DeploymentError> {
        render_shared_files(state)
    }

    fn calculate(
        &self,
        state: &DesiredState,
        files: &[RenderedFile],
        remote: Option<&RemoteManifest>,
    ) -> Result<DeploymentPlan, DeploymentError> {
        plan(state, files, remote)
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

pub fn render_shared_files(state: &DesiredState) -> Result<Vec<RenderedFile>, DeploymentError> {
    let instance = &state.instance;
    let compose = render_compose(state);
    let corefile = render_corefile(&instance.dns.zone)?;
    let zone = render_zone(
        &instance.dns.zone,
        instance.network.gateway_ipv4,
        instance.dns.soa_serial,
        &state.dns_records,
    )?;
    let instance_json = serde_json::to_string_pretty(instance)?;
    Ok(vec![
        file("compose.yaml", compose, 0o644, false)?,
        file(
            ".env",
            format!("WIREGUARD_PORT={}\n", instance.endpoint.port),
            0o600,
            false,
        )?,
        file("instance.json", format!("{instance_json}\n"), 0o600, false)?,
        file("dns/Corefile", corefile, 0o644, false)?,
        file(
            &format!("dns/zones/db.{}", instance.dns.zone),
            zone,
            0o644,
            false,
        )?,
    ])
}

#[must_use]
pub fn render_compose(state: &DesiredState) -> String {
    let scope = state.instance.id;
    format!(
        "name: {}\nservices:\n  gateway:\n    image: {}\n    restart: unless-stopped\n    labels:\n      com.centurylinklabs.watchtower.enable: \"true\"\n      com.centurylinklabs.watchtower.scope: \"{scope}\"\n    cap_add:\n      - NET_ADMIN\n    environment:\n      PUID: \"0\"\n      PGID: \"0\"\n      TZ: UTC\n      LOG_CONFS: \"false\"\n    sysctls:\n      net.ipv4.ip_forward: \"1\"\n      net.ipv4.conf.all.src_valid_mark: \"1\"\n    ports:\n      - \"${{WIREGUARD_PORT}}:51820/udp\"\n    volumes:\n      - ./vpn:/config/wg_confs\n      - ./state:/var/lib/vpn-appliance-manager\n  dns:\n    image: {}\n    restart: unless-stopped\n    labels:\n      com.centurylinklabs.watchtower.enable: \"true\"\n      com.centurylinklabs.watchtower.scope: \"{scope}\"\n    network_mode: service:gateway\n    depends_on:\n      - gateway\n    volumes:\n      - ./dns/Corefile:/etc/coredns/Corefile:ro\n      - ./dns/zones:/etc/coredns/zones:ro\n    command:\n      - -conf\n      - /etc/coredns/Corefile\n  watchtower:\n    image: {}\n    restart: unless-stopped\n    labels:\n      com.centurylinklabs.watchtower.enable: \"true\"\n      com.centurylinklabs.watchtower.scope: \"{scope}\"\n    environment:\n      WATCHTOWER_LABEL_ENABLE: \"true\"\n      WATCHTOWER_SCOPE: \"{scope}\"\n      WATCHTOWER_CLEANUP: \"true\"\n      WATCHTOWER_SCHEDULE: \"0 0 4 * * *\"\n      WATCHTOWER_NO_STARTUP_MESSAGE: \"true\"\n      WATCHTOWER_ROLLING_RESTART: \"true\"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        state.instance.compose_project(),
        WIREGUARD_IMAGE,
        COREDNS_IMAGE,
        WATCHTOWER_IMAGE,
    )
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
        operations.push(DeploymentOperation::GenerateServerKey);
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
        let dns_only = !changed_paths.is_empty()
            && changed_paths.iter().all(|path| {
                path.starts_with("dns/") || *path == "instance.json" || *path == "state.json"
            });
        let wireguard_changed = changed_paths.iter().any(|path| path.starts_with("vpn/"));
        operations.extend([
            DeploymentOperation::ValidateConfiguration,
            DeploymentOperation::CreateBackup {
                name: format!("{}-{plan_id}", Utc::now().format("%Y-%m-%dT%H-%M-%SZ")),
            },
        ]);
        if dns_only {
            operations.push(DeploymentOperation::ReloadDns);
        } else if wireguard_changed && remote.is_some() {
            operations.push(DeploymentOperation::ComposeRestart {
                service: "gateway".into(),
            });
        } else {
            operations.push(DeploymentOperation::ComposePull);
            operations.push(DeploymentOperation::ComposeUp);
        }
        operations.extend([
            DeploymentOperation::HealthCheck {
                service: "gateway".into(),
            },
            DeploymentOperation::HealthCheck {
                service: "dns".into(),
            },
        ]);
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
    use vam_core::{
        DEFAULT_KEEPALIVE, Device, DnsConfig, EndpointConfig, NetworkConfig, RoutingMode,
        VpnBackendKind, VpnInstance,
    };

    fn state() -> DesiredState {
        let subnet = "10.64.0.0/24".parse().unwrap();
        DesiredState {
            instance: VpnInstance {
                id: Uuid::nil(),
                host_id: Uuid::from_u128(1),
                display_name: "Test VPN".into(),
                backend: VpnBackendKind::WireGuard,
                endpoint: EndpointConfig {
                    host: "vpn.example.test".into(),
                    port: 51_820,
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
        }
    }

    #[test]
    fn quotes_hostile_shell_arguments() {
        assert_eq!(shell_quote("a'b;$(bad)"), "'a'\"'\"'b;$(bad)'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn managed_images_use_watchtower_update_channels() {
        assert!(WIREGUARD_IMAGE.ends_with(":latest"));
        assert!(COREDNS_IMAGE.ends_with(":latest"));
        assert!(WATCHTOWER_IMAGE.ends_with(":latest"));
        assert!(!WIREGUARD_IMAGE.contains("@sha256:"));
        assert!(!COREDNS_IMAGE.contains("@sha256:"));
        assert!(!WATCHTOWER_IMAGE.contains("@sha256:"));
    }

    #[test]
    fn compose_is_deterministic_and_does_not_generate_peers() {
        let state = state();
        let first = render_compose(&state);
        let second = render_compose(&state);
        assert_eq!(first, second);
        assert!(first.contains(WIREGUARD_IMAGE));
        assert!(first.contains(COREDNS_IMAGE));
        assert!(first.contains(WATCHTOWER_IMAGE));
        assert!(first.contains("network_mode: service:gateway"));
        assert!(first.contains("LOG_CONFS: \"false\""));
        assert!(first.contains("WATCHTOWER_LABEL_ENABLE: \"true\""));
        assert!(first.contains("WATCHTOWER_CLEANUP: \"true\""));
        assert!(first.contains("WATCHTOWER_SCHEDULE: \"0 0 4 * * *\""));
        assert!(first.contains(
            "com.centurylinklabs.watchtower.scope: \"00000000-0000-0000-0000-000000000000\""
        ));
        assert!(!first.contains("PEERS:"));
        assert!(!first.contains("SERVERURL:"));
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
        let plan = plan(&state, &files, Some(&remote)).unwrap();
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
