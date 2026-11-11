//! Certificate operations accept public CSRs only. Client private keys and
//! client credential-store references never cross this boundary.
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vam_authority::{
    AuthorityError, SecretValue,
    manifest::{
        CertificateMaterial, Manifest, ManifestStore, Operation, Peer, PublicIdentity, Reply,
    },
};
use vam_core::{Device, DeviceBackendData, DnsRecord, DnsRecordType, SecretReference};
use vam_protocol::AppError;
use x509_parser::prelude::FromDer;

#[derive(Serialize, Deserialize)]
struct CredentialReceipt {
    request_hash: String,
    reply: Reply,
}

pub async fn mutate(
    store: &ManifestStore,
    request_id: Uuid,
    operation: Operation,
) -> Result<Reply, AuthorityError> {
    let (instance_id, expected_revision) = match &operation {
        Operation::EnrollPeer {
            instance_id,
            expected_revision,
            ..
        }
        | Operation::RevokePeer {
            instance_id,
            expected_revision,
            confirmed: true,
            ..
        } => (*instance_id, *expected_revision),
        _ => {
            return Err(invalid(
                "certificate operation requires explicit confirmation",
            ));
        }
    };
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&operation)?));
    let context = store.runtime_context(instance_id, None)?;
    if let Some(receipt) = context.read_record::<CredentialReceipt>(request_id)? {
        if receipt.request_hash != hash {
            return Err(invalid(
                "credential request UUID reused with different content",
            ));
        }
        if context.pending_operation()? == Some(request_id) {
            context.finish_mutation()?;
        }
        return Ok(receipt.reply);
    }
    if let Some(committed) = context.committed_request(request_id, &hash)? {
        let reply = if matches!(&operation, Operation::EnrollPeer { .. }) {
            let Operation::EnrollPeer { peer, .. } = &operation else {
                unreachable!()
            };
            let material = read_material(&committed, peer.id)?;
            Reply::Enrollment {
                manifest: Box::new(committed),
                material,
            }
        } else {
            Reply::Manifest(Box::new(committed))
        };
        context.record(
            request_id,
            &CredentialReceipt {
                request_hash: hash,
                reply: reply.clone(),
            },
        )?;
        if context.pending_operation()? == Some(request_id) {
            context.finish_mutation()?;
        }
        return Ok(reply);
    }
    if context.manifest.revision != expected_revision {
        return Err(AuthorityError::RevisionConflict {
            expected: expected_revision,
            actual: context.manifest.revision,
        });
    }
    if context.deployed()?.is_none() {
        return Err(invalid(
            "deploy and verify this certificate authority before managing certificates",
        ));
    }
    let mut configuration = context.manifest.configuration.clone();
    let (mut device, enroll, csr) = match operation {
        Operation::EnrollPeer {
            peer,
            csr,
            create_dns_record,
            ..
        } => {
            if configuration.peers.iter().any(|old| old.id == peer.id) {
                return Err(invalid(
                    "peer already exists; discovery must never replace its identity",
                ));
            }
            validate_csr(&peer, &csr)?;
            configuration.peers.push(peer.clone());
            if create_dns_record && let Some(name) = &peer.dns_name {
                configuration.dns_records.push(DnsRecord {
                    id: Uuid::new_v4(),
                    instance_id,
                    name: name.clone(),
                    record_type: DnsRecordType::A,
                    value: peer
                        .ipv4_address
                        .ok_or_else(|| invalid("peer address is required"))?
                        .to_string(),
                    ttl: 300,
                    enabled: true,
                    managed_by_device_id: Some(peer.id),
                });
            }
            vam_application::validate_remote_configuration(&configuration)
                .map_err(|error| invalid(&error.message))?;
            let mut device = configuration
                .runtime_state()
                .devices
                .into_iter()
                .find(|device| device.id == peer.id)
                .ok_or_else(|| invalid("new peer projection is unavailable"))?;
            assign_temporary_references(&mut device)?;
            (device, true, Some(csr))
        }
        Operation::RevokePeer { peer_id, .. } => {
            let peer = configuration
                .peers
                .iter()
                .find(|peer| peer.id == peer_id)
                .ok_or(AuthorityError::NotFound)?;
            if !matches!(
                peer.identity,
                PublicIdentity::Openvpn { .. } | PublicIdentity::Ikev2 { .. }
            ) {
                return Err(invalid("peer does not use certificates"));
            }
            if !peer.enabled {
                return Ok(Reply::Manifest(Box::new(context.manifest.clone())));
            }
            let device = configuration
                .runtime_state()
                .devices
                .into_iter()
                .find(|device| device.id == peer_id)
                .ok_or(AuthorityError::NotFound)?;
            (device, false, None)
        }
        _ => unreachable!("operation validated above"),
    };
    let service = crate::runtime::project_configuration(&context, &context.manifest.configuration)
        .await
        .map_err(|error| invalid(&error.message))?;
    if let Some(csr) = csr {
        let reference = match &device.backend_data {
            DeviceBackendData::OpenVpn(data) => &data.csr_ref,
            DeviceBackendData::Ikev2(data) => data
                .csr_ref
                .as_ref()
                .ok_or_else(|| invalid("CSR reference is missing"))?,
            _ => return Err(invalid("unsupported certificate backend")),
        };
        service
            .secrets
            .put(reference, csr.as_bytes())
            .await
            .map_err(|_| invalid("unable to stage public CSR"))?;
    }
    context.begin_mutation(request_id)?;
    let outcome = if enroll {
        service.issue_projected_certificate(&mut device).await
    } else {
        service.revoke_projected_certificate(&device).await
    };
    let backup = match outcome {
        Ok(backup) => backup,
        Err(mut error) => {
            if error.rollback_succeeded == Some(true) || !error.remote_state_changed {
                context.finish_mutation()?;
            }
            error.scope = Some(request_id.to_string());
            return Ok(Reply::OperationFailure(error));
        }
    };
    if let Some(name) = Path::new(&backup)
        .file_name()
        .and_then(|name| name.to_str())
    {
        context.remember_backup(name, context.deployed()?)?;
    }
    let peer = configuration
        .peers
        .iter_mut()
        .find(|peer| peer.id == device.id)
        .ok_or(AuthorityError::NotFound)?;
    if enroll {
        match (&mut peer.identity, &device.backend_data) {
            (
                PublicIdentity::Openvpn {
                    certificate_serial, ..
                },
                DeviceBackendData::OpenVpn(data),
            ) => certificate_serial.clone_from(&data.certificate_serial),
            (
                PublicIdentity::Ikev2 {
                    certificate_serial, ..
                },
                DeviceBackendData::Ikev2(data),
            ) => certificate_serial.clone_from(&data.certificate_serial),
            _ => return Err(invalid("certificate backend changed unexpectedly")),
        }
    } else {
        peer.enabled = false;
        for record in &mut configuration.dns_records {
            if record.managed_by_device_id == Some(peer.id) {
                record.enabled = false;
            }
        }
    }
    let synchronized = std::process::Command::new("/bin/sync")
        .env_clear()
        .arg("-f")
        .arg(context.manifest.configuration.instance.remote_path())
        .output()?;
    if !synchronized.status.success() {
        return Err(invalid(
            "certificate state could not be synchronized; reconcile the pending operation",
        ));
    }
    let committed = match context.commit_configuration(configuration, request_id, &hash) {
        Ok(manifest) => manifest,
        Err(error) => {
            // A failed directory sync after pointer replacement is ambiguous.
            // Never compensate cryptographic state if the commit may exist.
            match context.committed_request(request_id, &hash) {
                Ok(None) => {
                    let recovered = service
                        .compensate_projected_certificate(instance_id, backup)
                        .await
                        .is_ok();
                    if recovered {
                        context.finish_mutation()?;
                    }
                    let mut failure = AppError::new(
                        "credential_manifest_commit",
                        "Certificate metadata could not be committed.",
                    );
                    failure.remote_state_changed = true;
                    failure.rollback_succeeded = Some(recovered);
                    failure.scope = Some(request_id.to_string());
                    return Ok(Reply::OperationFailure(failure));
                }
                _ => return Err(error),
            }
        }
    };
    let reply = if enroll {
        let material = read_material(&committed, device.id)?;
        Reply::Enrollment {
            manifest: Box::new(committed),
            material,
        }
    } else {
        Reply::Manifest(Box::new(committed))
    };
    context.record(
        request_id,
        &CredentialReceipt {
            request_hash: hash,
            reply: reply.clone(),
        },
    )?;
    context.finish_mutation()?;
    Ok(reply)
}

pub fn export(
    store: &ManifestStore,
    instance_id: Uuid,
    peer_id: Uuid,
    expected_revision: u64,
) -> Result<Reply, AuthorityError> {
    let context = store.runtime_context(instance_id, Some(expected_revision))?;
    Ok(Reply::CertificateMaterial(read_material(
        &context.manifest,
        peer_id,
    )?))
}

fn read_material(
    manifest: &Manifest,
    peer_id: Uuid,
) -> Result<CertificateMaterial, AuthorityError> {
    vam_application::validate_remote_configuration(&manifest.configuration)
        .map_err(|error| invalid(&error.message))?;
    let peer = manifest
        .configuration
        .peers
        .iter()
        .find(|peer| peer.id == peer_id)
        .ok_or(AuthorityError::NotFound)?;
    if !peer.enabled {
        return Err(invalid("revoked peer certificate cannot be exported"));
    }
    let (certificate, ca, tls, identity, serial) = match &peer.identity {
        PublicIdentity::Openvpn {
            common_name,
            certificate_serial,
        } => (
            format!("vpn/pki/issued/{common_name}.crt"),
            "vpn/pki/ca.crt",
            true,
            common_name,
            certificate_serial,
        ),
        PublicIdentity::Ikev2 {
            identity,
            certificate_serial,
        } => (
            format!("ikev2/issued/{identity}.pem"),
            "ikev2/x509ca/vam-ca.pem",
            false,
            identity,
            certificate_serial,
        ),
        _ => return Err(invalid("peer does not use certificates")),
    };
    let read = |relative: &str| -> Result<SecretValue, AuthorityError> {
        let path = format!(
            "{}/{relative}",
            manifest.configuration.instance.remote_path()
        );
        crate::runtime::validate_runtime_path(&path)
            .map_err(|_| invalid("unsafe certificate material path"))?;
        super::read_bounded(Path::new(&path), 1024 * 1024)
            .map(SecretValue::new)
            .map_err(|_| invalid("certificate material is unavailable"))
    };
    let certificate = read(&certificate)?;
    let ca_certificate = read(ca)?;
    verify_certificate(
        &certificate,
        &ca_certificate,
        identity,
        serial
            .as_deref()
            .ok_or_else(|| invalid("peer has no issued certificate serial"))?,
    )?;
    let tls_crypt = if tls
        && matches!(&manifest.configuration.instance.backend_settings,
        vam_core::BackendSettings::OpenVpn(settings) if settings.tls_protection == vam_core::OpenVpnTlsProtection::TlsCrypt)
    {
        Some(read("vpn/tls-crypt.key")?)
    } else {
        None
    };
    Ok(CertificateMaterial {
        peer_id,
        certificate,
        ca_certificate,
        tls_crypt,
    })
}

fn verify_certificate(
    certificate: &SecretValue,
    ca: &SecretValue,
    identity: &str,
    serial: &str,
) -> Result<(), AuthorityError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate.as_bytes())
        .map_err(|_| invalid("invalid issued certificate PEM"))?;
    let (_, ca_pem) = x509_parser::pem::parse_x509_pem(ca.as_bytes())
        .map_err(|_| invalid("invalid CA certificate PEM"))?;
    let cert = pem
        .parse_x509()
        .map_err(|_| invalid("invalid issued certificate"))?;
    let authority = ca_pem
        .parse_x509()
        .map_err(|_| invalid("invalid CA certificate"))?;
    let name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok());
    if name != Some(identity)
        || !cert
            .raw_serial_as_string()
            .replace(':', "")
            .trim_start_matches('0')
            .eq_ignore_ascii_case(serial.trim_start_matches('0'))
    {
        return Err(invalid(
            "issued certificate does not match the peer public identity",
        ));
    }
    cert.verify_signature(Some(authority.public_key()))
        .map_err(|_| invalid("issued certificate does not verify against the server CA"))?;
    if !cert.validity().is_valid() || !authority.validity().is_valid() {
        return Err(invalid(
            "certificate or CA has expired; explicit credential renewal is required",
        ));
    }
    Ok(())
}

fn assign_temporary_references(device: &mut Device) -> Result<(), AuthorityError> {
    let reference = || SecretReference(Uuid::new_v4());
    match &mut device.backend_data {
        DeviceBackendData::OpenVpn(data) => {
            data.private_key_ref = reference();
            data.csr_ref = reference();
            data.certificate_ref = reference();
            data.ca_certificate_ref = reference();
            if data.tls_crypt_key_ref.is_some() {
                data.tls_crypt_key_ref = Some(reference());
            }
        }
        DeviceBackendData::Ikev2(data) => {
            data.private_key_ref = Some(reference());
            data.csr_ref = Some(reference());
            data.certificate_ref = Some(reference());
            data.ca_certificate_ref = Some(reference());
            data.bundle_password_ref = reference();
        }
        _ => return Err(invalid("unsupported certificate backend")),
    }
    Ok(())
}

fn validate_csr(peer: &Peer, csr: &str) -> Result<(), AuthorityError> {
    let csr = csr.trim();
    if csr.len() > 65536
        || !csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        || !csr.ends_with("-----END CERTIFICATE REQUEST-----")
        || csr.contains("PRIVATE KEY")
    {
        return Err(invalid(
            "only a bounded public certificate signing request is accepted",
        ));
    }
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(csr.as_bytes()).map_err(|_| invalid("invalid CSR PEM"))?;
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .map_err(|_| invalid("invalid CSR DER"))?;
    request
        .verify_signature()
        .map_err(|_| invalid("CSR signature verification failed"))?;
    let (identity, signature, curve) = match &peer.identity {
        PublicIdentity::Openvpn {
            common_name,
            certificate_serial: None,
        } => (common_name, "1.2.840.10045.4.3.2", "1.2.840.10045.3.1.7"),
        PublicIdentity::Ikev2 {
            identity,
            certificate_serial: None,
        } => (identity, "1.2.840.10045.4.3.3", "1.3.132.0.34"),
        _ => {
            return Err(invalid(
                "new certificate peers must enroll without an existing serial",
            ));
        }
    };
    let names = request
        .certification_request_info
        .subject
        .iter_common_name()
        .map(x509_parser::prelude::AttributeTypeAndValue::as_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("invalid CSR subject"))?;
    let parameters = request
        .certification_request_info
        .subject_pki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
        .map(|oid| oid.to_id_string());
    if names != [identity.as_str()]
        || request.signature_algorithm.algorithm.to_id_string() != signature
        || parameters.as_deref() != Some(curve)
    {
        return Err(invalid(
            "CSR identity or cryptographic algorithm does not match the requested peer",
        ));
    }
    if let Some(extensions) = request.requested_extensions() {
        for extension in extensions {
            use x509_parser::extensions::{GeneralName, ParsedExtension};
            match extension {
                ParsedExtension::BasicConstraints(constraints) if !constraints.ca => {}
                ParsedExtension::KeyUsage(usage)
                    if usage.digital_signature() && usage.flags.is_power_of_two() => {}
                ParsedExtension::ExtendedKeyUsage(usage)
                    if usage.client_auth
                        && !usage.any
                        && !usage.server_auth
                        && !usage.code_signing
                        && !usage.email_protection
                        && !usage.time_stamping
                        && !usage.ocsp_signing
                        && usage.other.is_empty() => {}
                ParsedExtension::SubjectAlternativeName(names)
                    if matches!(peer.identity, PublicIdentity::Ikev2 { .. })
                        && names.general_names.iter().all(
                            |name| matches!(name, GeneralName::DNSName(name) if *name == identity),
                        ) => {}
                _ => {
                    return Err(invalid(
                        "CSR extensions must be limited to this peer's client identity and signing usage",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn invalid(message: &str) -> AuthorityError {
    AuthorityError::InvalidState(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(identity: PublicIdentity) -> Peer {
        Peer {
            id: Uuid::new_v4(),
            user_id: None,
            display_name: "phone".into(),
            ipv4_address: Some("10.88.0.2".parse().unwrap()),
            ipv6_address: None,
            dns_name: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            identity,
        }
    }

    #[test]
    fn existing_client_generators_produce_verified_identity_bound_csrs() {
        let generated =
            vam_backend_openvpn::OpenVpnBackend::generate_identity("phone", Uuid::new_v4())
                .unwrap();
        let mut public = peer(PublicIdentity::Openvpn {
            common_name: generated.common_name,
            certificate_serial: None,
        });
        validate_csr(&public, &generated.csr).unwrap();
        assert!(validate_csr(&public, &generated.private_key).is_err());
        if let PublicIdentity::Openvpn { common_name, .. } = &mut public.identity {
            *common_name = "someone-else".into();
        }
        assert!(validate_csr(&public, &generated.csr).is_err());
        let generated =
            vam_backend_ikev2::Ikev2Backend::generate_identity("phone", Uuid::new_v4()).unwrap();
        let public = peer(PublicIdentity::Ikev2 {
            identity: generated.identity,
            certificate_serial: None,
        });
        validate_csr(&public, &generated.csr).unwrap();
        assert!(validate_csr(&public, &generated.private_key).is_err());
    }
}
