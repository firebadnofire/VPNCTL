use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use vam_core::{
    BackendSettings, DesiredState, Device, ListenerPort, SecretReference, ValidationError,
    VpnBackendKind,
};
use vam_protocol::{ClientArtifact, RenderedFile};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub allocated_tunnel_addresses: bool,
    pub managed_dns: bool,
    pub quick_credential_refresh: bool,
    pub live_identity_updates: bool,
    pub qr_export: bool,
    pub traffic_statistics: bool,
    pub certificate_authority: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeImpact {
    LiveUpdate,
    ServiceRestart,
    Reinstall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientArtifactKind {
    TextConfiguration,
    ProtectedPkcs12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerImage {
    Pull(&'static str),
    Build {
        tag: &'static str,
        dockerfile_path: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerCapability {
    NetAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerDevice {
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerMount {
    pub host_path: &'static str,
    pub container_path: &'static str,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerIdentityStrategy {
    WireGuardLike {
        tool: &'static str,
        private_key_path: &'static str,
        template_path: &'static str,
        materialized_path: &'static str,
        sentinel: &'static str,
    },
    CertificateAuthority,
    StructuredJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendValidation {
    WireGuardQuick {
        tool: &'static str,
        config_path: &'static str,
    },
    OpenVpn {
        config_path: &'static str,
    },
    Ikev2,
    Xray {
        config_path: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealthProbe {
    WireGuardLike {
        tool: &'static str,
        interface: &'static str,
    },
    OpenVpn,
    Ikev2,
    Xray,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRuntimeSpec {
    pub image: ContainerImage,
    pub container_listeners: Vec<ListenerPort>,
    pub capabilities: Vec<ContainerCapability>,
    pub devices: Vec<ContainerDevice>,
    pub mounts: Vec<ContainerMount>,
    pub sysctls: Vec<(&'static str, &'static str)>,
    pub identity: ServerIdentityStrategy,
    pub validation: BackendValidation,
    pub health: BackendHealthProbe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialAction {
    InitializeAuthority,
    Issue,
    Revoke,
    Replace { previous_identity: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialArtifact {
    CaCertificate,
    ClientCertificate,
    TlsCryptKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOperation {
    InitializeOpenVpnAuthority {
        ca_common_name: String,
        server_common_name: String,
        ca_lifetime_days: u16,
        certificate_lifetime_days: u16,
        crl_lifetime_days: u16,
        tls_crypt: bool,
    },
    UploadSecret {
        reference: SecretReference,
        relative_path: String,
        mode: u32,
    },
    ImportOpenVpnCsr {
        common_name: String,
        relative_path: String,
    },
    SignOpenVpnClient {
        common_name: String,
        certificate_lifetime_days: u16,
    },
    DownloadToSecret {
        relative_path: String,
        reference: SecretReference,
        artifact: CredentialArtifact,
    },
    ReadCertificateSerial {
        relative_path: String,
    },
    RevokeOpenVpnClient {
        common_name: String,
    },
    RegenerateOpenVpnCrl {
        lifetime_days: u16,
    },
    ReloadGateway,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPlan {
    pub operations: Vec<CredentialOperation>,
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("{backend} secret {reference:?} is unavailable")]
    MissingSecret {
        backend: VpnBackendKind,
        reference: SecretReference,
    },
    #[error("device backend does not match the {0} instance backend")]
    BackendMismatch(VpnBackendKind),
    #[error("{0} key or certificate material is invalid")]
    InvalidKeyMaterial(VpnBackendKind),
    #[error("{backend} setting {field} is invalid: {message}")]
    InvalidSetting {
        backend: VpnBackendKind,
        field: &'static str,
        message: String,
    },
    #[error("backend {0} is not registered")]
    NotRegistered(VpnBackendKind),
    #[error("backend {backend} does not support credential operation {operation}")]
    UnsupportedCredentialOperation {
        backend: VpnBackendKind,
        operation: &'static str,
    },
    #[error("backend {0} credential operation requires a device identity")]
    MissingCredentialDevice(VpnBackendKind),
}

pub trait VpnBackend: Send + Sync {
    fn kind(&self) -> VpnBackendKind;
    fn capabilities(&self) -> BackendCapabilities;
    fn runtime(&self, settings: &BackendSettings) -> Result<BackendRuntimeSpec, BackendError>;
    fn listeners(&self, settings: &BackendSettings, endpoint_port: u16) -> Vec<ListenerPort>;
    fn validate(&self, state: &DesiredState) -> Result<(), BackendError>;
    fn server_secret_references(&self, state: &DesiredState) -> Vec<SecretReference>;
    fn client_secret_references(
        &self,
        device: &Device,
    ) -> Result<Vec<SecretReference>, BackendError>;
    fn render_server(
        &self,
        state: &DesiredState,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<Vec<RenderedFile>, BackendError>;
    fn render_client(
        &self,
        state: &DesiredState,
        device: &Device,
        secrets: &HashMap<SecretReference, Zeroizing<String>>,
    ) -> Result<ClientArtifact, BackendError>;
    fn client_artifact_kind(&self) -> ClientArtifactKind {
        ClientArtifactKind::TextConfiguration
    }
    fn plan_credentials(
        &self,
        _state: &DesiredState,
        _device: Option<&Device>,
        action: CredentialAction,
    ) -> Result<CredentialPlan, BackendError> {
        let operation = match action {
            CredentialAction::InitializeAuthority => "initialize authority",
            CredentialAction::Issue => "issue",
            CredentialAction::Revoke => "revoke",
            CredentialAction::Replace { .. } => "replace",
        };
        Err(BackendError::UnsupportedCredentialOperation {
            backend: self.kind(),
            operation,
        })
    }
    fn classify_settings_change(
        &self,
        previous: &BackendSettings,
        next: &BackendSettings,
    ) -> ChangeImpact;
}

#[derive(Default)]
pub struct BackendRegistry {
    backends: HashMap<VpnBackendKind, Arc<dyn VpnBackend>>,
}

impl BackendRegistry {
    #[must_use]
    pub fn new(backends: impl IntoIterator<Item = Arc<dyn VpnBackend>>) -> Self {
        let backends = backends
            .into_iter()
            .map(|backend| (backend.kind(), backend))
            .collect();
        Self { backends }
    }

    pub fn get(&self, kind: VpnBackendKind) -> Result<&Arc<dyn VpnBackend>, BackendError> {
        self.backends
            .get(&kind)
            .ok_or(BackendError::NotRegistered(kind))
    }

    #[must_use]
    pub fn capabilities(&self, kind: VpnBackendKind) -> Option<BackendCapabilities> {
        self.backends
            .get(&kind)
            .map(|backend| backend.capabilities())
    }

    #[must_use]
    pub fn kinds(&self) -> Vec<VpnBackendKind> {
        let mut kinds: Vec<_> = self.backends.keys().copied().collect();
        kinds.sort();
        kinds
    }
}
