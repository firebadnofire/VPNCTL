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
    #[error("backend {0} is not registered")]
    NotRegistered(VpnBackendKind),
}

pub trait VpnBackend: Send + Sync {
    fn kind(&self) -> VpnBackendKind;
    fn capabilities(&self) -> BackendCapabilities;
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
