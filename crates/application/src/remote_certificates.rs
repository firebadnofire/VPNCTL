use std::collections::HashMap;
use uuid::Uuid;
use vam_authority::manifest::{
    CertificateMaterial, Configuration, Manifest, Operation, PublicIdentity, Reply,
};
use vam_core::{BackendSettings, DeviceBackendData, OpenVpnTlsProtection, SecretReference};
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use super::remote::{manifest_reply, peer_binding_key};
use super::{
    AppError, ApplicationService, backend_error, secret_error, storage_error, validation_error,
};

impl ApplicationService {
    pub(super) async fn store_certificate_material(
        &self,
        appliance_id: Uuid,
        instance_id: Uuid,
        peer_id: Uuid,
        mut binding: DeviceBackendData,
        configuration: &Configuration,
        material: CertificateMaterial,
    ) -> Result<(), AppError> {
        if material.peer_id != peer_id {
            return Err(validation_error(
                "Certificate response belongs to another peer.",
            ));
        }
        let public = configuration
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .ok_or_else(|| validation_error("Issued peer is absent from saved configuration."))?;
        let (csr_ref, certificate_ref, ca_ref, tls_ref) = match (&mut binding, &public.identity) {
            (
                DeviceBackendData::OpenVpn(local),
                PublicIdentity::Openvpn {
                    common_name,
                    certificate_serial,
                },
            ) if &local.common_name == common_name => {
                local.certificate_serial.clone_from(certificate_serial);
                if let BackendSettings::OpenVpn(settings) = &configuration.instance.backend_settings
                {
                    if settings.tls_protection == OpenVpnTlsProtection::TlsCrypt
                        && local.tls_crypt_key_ref.is_none()
                    {
                        local.tls_crypt_key_ref = Some(SecretReference(Uuid::new_v4()));
                    }
                    if settings.tls_protection == OpenVpnTlsProtection::None {
                        local.tls_crypt_key_ref = None;
                    }
                }
                (
                    local.csr_ref.clone(),
                    local.certificate_ref.clone(),
                    local.ca_certificate_ref.clone(),
                    local.tls_crypt_key_ref.clone(),
                )
            }
            (
                DeviceBackendData::Ikev2(local),
                PublicIdentity::Ikev2 {
                    identity,
                    certificate_serial,
                },
            ) if &local.identity == identity => {
                local.certificate_serial.clone_from(certificate_serial);
                (
                    local
                        .csr_ref
                        .clone()
                        .ok_or_else(|| validation_error("Local CSR is unavailable."))?,
                    local.certificate_ref.clone().ok_or_else(|| {
                        validation_error("Local certificate reference is unavailable.")
                    })?,
                    local
                        .ca_certificate_ref
                        .clone()
                        .ok_or_else(|| validation_error("Local CA reference is unavailable."))?,
                    None,
                )
            }
            _ => {
                return Err(validation_error(
                    "Certificate identity does not match this client's local credentials.",
                ));
            }
        };
        let csr = self.secrets.get(&csr_ref).await.map_err(secret_error)?;
        let (_, csr_pem) = x509_parser::pem::parse_x509_pem(&csr).map_err(|_| {
            validation_error("Local CSR is invalid; private credentials were not regenerated.")
        })?;
        let (_, request) = x509_parser::certification_request::X509CertificationRequest::from_der(
            &csr_pem.contents,
        )
        .map_err(|_| validation_error("Local CSR is invalid."))?;
        let (_, certificate_pem) =
            x509_parser::pem::parse_x509_pem(material.certificate.as_bytes())
                .map_err(|_| validation_error("Returned certificate is invalid."))?;
        let certificate = certificate_pem
            .parse_x509()
            .map_err(|_| validation_error("Returned certificate is invalid."))?;
        if certificate.public_key().raw != request.certification_request_info.subject_pki.raw {
            return Err(validation_error(
                "Issued certificate does not match the locally generated identity.",
            ));
        }
        let store = async {
            self.secrets
                .put(&certificate_ref, material.certificate.as_bytes())
                .await
                .map_err(secret_error)?;
            self.secrets
                .put(&ca_ref, material.ca_certificate.as_bytes())
                .await
                .map_err(secret_error)?;
            if let Some(reference) = tls_ref {
                let value = material.tls_crypt.ok_or_else(|| {
                    validation_error("Server TLS protection material is unavailable.")
                })?;
                self.secrets
                    .put(&reference, value.as_bytes())
                    .await
                    .map_err(secret_error)?;
            }
            self.storage
                .set_setting(
                    &peer_binding_key(appliance_id, instance_id, peer_id),
                    &binding,
                )
                .await
                .map_err(storage_error)
        }
        .await;
        store.map_err(|mut error: AppError| {
            error.remote_state_changed = true;
            error.remediation = Some("The peer remains saved on the server. Retry an explicit export on this client to recover public certificate material; its private key remains local.".into());
            error
        })
    }

    pub(super) async fn remote_certificate_artifact(
        &self,
        host_id: Uuid,
        manifest: &Manifest,
        peer_id: Uuid,
        binding: DeviceBackendData,
    ) -> Result<vam_protocol::ClientArtifact, AppError> {
        let peer = manifest
            .configuration
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .ok_or_else(|| validation_error("Peer no longer exists."))?;
        if !peer.enabled {
            return Err(validation_error(
                "Revoked certificate credentials cannot be exported as an active configuration.",
            ));
        }
        let private_ref = match &binding {
            DeviceBackendData::OpenVpn(data) => &data.private_key_ref,
            DeviceBackendData::Ikev2(data) => data.private_key_ref.as_ref().ok_or_else(|| {
                AppError::new(
                    "missing_local_private_key",
                    "This client lacks the peer private key.",
                )
            })?,
            _ => {
                return Err(validation_error(
                    "Peer does not use certificate credentials.",
                ));
            }
        };
        // Prove local possession before requesting even scoped server material.
        self.secrets.get(private_ref).await.map_err(secret_error)?;
        let Reply::CertificateMaterial(material) = self
            .remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::ExportCertificateMaterial {
                    instance_id: manifest.configuration.instance.id,
                    peer_id,
                    expected_revision: manifest.revision,
                },
            )
            .await?
        else {
            return Err(validation_error("Unexpected certificate export response."));
        };
        self.store_certificate_material(
            manifest.appliance_id,
            manifest.configuration.instance.id,
            peer_id,
            binding,
            &manifest.configuration,
            material,
        )
        .await?;
        let binding = self
            .storage
            .get_setting::<DeviceBackendData>(&peer_binding_key(
                manifest.appliance_id,
                manifest.configuration.instance.id,
                peer_id,
            ))
            .await
            .map_err(storage_error)?
            .ok_or_else(|| validation_error("Local credential binding is unavailable."))?;
        let mut state = manifest.configuration.runtime_state();
        let device = state
            .devices
            .iter_mut()
            .find(|device| device.id == peer_id)
            .ok_or_else(|| validation_error("Peer projection is unavailable."))?;
        device.backend_data = binding;
        let device = device.clone();
        let backend = self
            .backends
            .get(state.instance.backend)
            .map_err(backend_error)?;
        let mut secrets: HashMap<SecretReference, Zeroizing<String>> = HashMap::new();
        for reference in backend
            .client_secret_references(&device)
            .map_err(backend_error)?
        {
            secrets.insert(reference.clone(), self.secret_text(&reference).await?);
        }
        let artifact = backend
            .render_client(&state, &device, &secrets)
            .map_err(backend_error)?;
        Ok(artifact)
    }

    pub async fn revoke_remote_peer(
        &self,
        host_id: Uuid,
        instance_id: Uuid,
        peer_id: Uuid,
        expected_revision: u64,
        confirmed: bool,
    ) -> Result<Manifest, AppError> {
        manifest_reply(
            self.remote_operation(
                host_id,
                Uuid::new_v4(),
                Operation::RevokePeer {
                    instance_id,
                    peer_id,
                    expected_revision,
                    confirmed,
                },
            )
            .await?,
        )
    }
}
