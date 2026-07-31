use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderedFile {
    pub path: String,
    pub contents: String,
    pub mode: u32,
    pub sensitive: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ClientArtifactPayload {
    Text(Zeroizing<String>),
    Binary(Zeroizing<Vec<u8>>),
}

impl ClientArtifactPayload {
    pub fn text(contents: impl Into<String>) -> Self {
        Self::Text(Zeroizing::new(contents.into()))
    }

    pub fn binary(contents: Vec<u8>) -> Self {
        Self::Binary(Zeroizing::new(contents))
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(contents) => Some(contents.as_str()),
            Self::Binary(_) => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(contents) => contents.as_bytes(),
            Self::Binary(contents) => contents.as_slice(),
        }
    }

    pub const fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_))
    }
}

impl Default for ClientArtifactPayload {
    fn default() -> Self {
        Self::text(String::new())
    }
}

impl fmt::Debug for ClientArtifactPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_binary() { "binary" } else { "text" };
        formatter
            .debug_struct("ClientArtifactPayload")
            .field("kind", &kind)
            .field("bytes", &self.as_bytes().len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientArtifact {
    pub suggested_filename: String,
    #[serde(skip)]
    pub contents: ClientArtifactPayload,
    pub ipv6_warning: Option<String>,
}

impl ClientArtifact {
    pub fn text(
        suggested_filename: impl Into<String>,
        contents: impl Into<String>,
        ipv6_warning: Option<String>,
    ) -> Self {
        Self {
            suggested_filename: suggested_filename.into(),
            contents: ClientArtifactPayload::text(contents),
            ipv6_warning,
        }
    }

    pub fn binary(
        suggested_filename: impl Into<String>,
        contents: Vec<u8>,
        ipv6_warning: Option<String>,
    ) -> Self {
        Self {
            suggested_filename: suggested_filename.into(),
            contents: ClientArtifactPayload::binary(contents),
            ipv6_warning,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostKeyInfo {
    pub hostname: String,
    pub resolved_address: String,
    pub port: u16,
    pub algorithm: String,
    pub sha256_fingerprint: String,
    pub public_key_base64: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyState {
    Unknown,
    Trusted,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostKeyProbe {
    pub key: HostKeyInfo,
    pub state: HostKeyState,
    pub approved_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostInspection {
    pub operating_system: String,
    pub architecture: String,
    pub docker_version: Option<String>,
    pub compose_version: Option<String>,
    pub docker_accessible: bool,
    pub wireguard_kernel_available: bool,
    pub application_root_writable: bool,
    pub sudo_bootstrap_available: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum DeploymentOperation {
    CreateDirectory { path: String },
    GenerateServerKey,
    UploadFile { path: String, sensitive: bool },
    ReplaceFile { path: String, sensitive: bool },
    RemoveFile { path: String },
    ValidateConfiguration,
    CreateBackup { name: String },
    ComposePull,
    ComposeBuild,
    ComposeUp,
    ComposeRestart { service: String },
    ReloadDns,
    HealthCheck { service: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub operations: Vec<DeploymentOperation>,
    pub warnings: Vec<String>,
    pub desired_state_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Planned,
    Applying,
    Succeeded,
    Failed,
    RolledBack,
    RollbackFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentProgress {
    pub deployment_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub phase: String,
    pub message: String,
    pub technical_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InstanceHealth {
    pub compose_project_exists: bool,
    pub gateway_running: bool,
    #[serde(default)]
    pub backend_ready: bool,
    #[serde(default)]
    pub listeners_ready: bool,
    #[serde(default)]
    pub client_state_matches: bool,
    #[serde(default)]
    pub dns_required: bool,
    pub dns_running: bool,
    pub watchtower_running: bool,
    pub private_dns_resolves: bool,
    pub public_dns_resolves: bool,
    pub wireguard_interface_exists: bool,
    pub listen_port_matches: bool,
    pub expected_peers_present: bool,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentResult {
    pub deployment_id: Uuid,
    pub status: DeploymentStatus,
    pub remote_state_changed: bool,
    pub rollback_succeeded: Option<bool>,
    pub backup_name: Option<String>,
    pub health: InstanceHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentSummary {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub status: DeploymentStatus,
    pub backup_name: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupInfo {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deployment_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct AppError {
    pub code: String,
    pub message: String,
    pub scope: Option<String>,
    pub remote_state_changed: bool,
    pub rollback_succeeded: Option<bool>,
    pub remediation: Option<String>,
    pub technical_detail: Option<String>,
}

impl AppError {
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            scope: None,
            remote_state_changed: false,
            rollback_succeeded: None,
            remediation: None,
            technical_detail: None,
        }
    }
}

#[must_use]
pub fn redact(input: &str, known_secrets: &[&str]) -> String {
    let mut output = input.to_owned();
    for secret in known_secrets.iter().filter(|secret| !secret.is_empty()) {
        output = output.replace(secret, "[REDACTED]");
    }
    output
        .lines()
        .map(|line| {
            let lowered = line.to_ascii_lowercase();
            if ["privatekey", "presharedkey", "password", "passphrase"]
                .iter()
                .any(|needle| lowered.contains(needle))
            {
                format!(
                    "{} = [REDACTED]",
                    line.split('=').next().unwrap_or("secret")
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_and_structured_secrets() {
        let value = "token=abc\nPrivateKey = secret\nsafe=yes";
        let redacted = redact(value, &["abc"]);
        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("secret"));
        assert!(redacted.contains("safe=yes"));
    }

    #[test]
    fn client_artifact_payload_supports_text_and_binary_without_serializing_secrets() {
        let text = ClientArtifact::text("client.conf", "text-secret", None);
        assert_eq!(text.contents.as_text(), Some("text-secret"));
        assert_eq!(text.contents.as_bytes(), b"text-secret");
        assert!(!format!("{:?}", text.contents).contains("text-secret"));
        assert!(
            !serde_json::to_string(&text)
                .unwrap()
                .contains("text-secret")
        );

        let binary = ClientArtifact::binary("client.p12", b"binary-secret".to_vec(), None);
        assert!(binary.contents.is_binary());
        assert_eq!(binary.contents.as_text(), None);
        assert_eq!(binary.contents.as_bytes(), b"binary-secret");
        assert!(!format!("{:?}", binary.contents).contains("binary-secret"));
        assert!(
            !serde_json::to_string(&binary)
                .unwrap()
                .contains("binary-secret")
        );
    }
}
